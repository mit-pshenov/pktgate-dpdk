// src/ctl/reload.cpp
//
// M8 C1 — ReloadManager implementation.
//
// See reload.h for the module contract + C1 scope. This TU holds:
//   * the module-local ReloadManager singleton (state below)
//   * deploy() that runs parse → validate → compile → build →
//     populate_ruleset_eal and atomic-exchanges g_active
//   * deploy_prebuilt() test shim
//   * shutdown() that drops g_active (C1 stub — C4 adds RCU offline
//     + bounded synchronize)
//
// All writes to `g_active` (including init / shutdown) go through
// `g_.g_active.exchange(...)` so the ONE atomic (D1 exception) is
// the single source of truth. Workers load it with memory_order_acquire.

#include "src/ctl/reload.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

#include <variant>

#include "src/compiler/compiler.h"
#include "src/compiler/object_compiler.h"
#include "src/config/model.h"
#include "src/config/parser.h"
#include "src/config/sizing.h"
#include "src/config/validator.h"
#include "src/ruleset/builder.h"
#include "src/ruleset/builder_eal.h"
#include "src/ruleset/ruleset.h"

namespace pktgate::ctl::reload {

namespace {

// -------------------------------------------------------------------------
// ReloadManager — module-local singleton.
//
// Single instance lives inside an anonymous namespace; exposed to the
// outside world only through the free functions declared in reload.h.
// That keeps the DPDK-aware storage out of the public header and makes
// C2/C3/C4 additions (token, deadline, pending_free) additive without
// API churn.
//
// The `g_active` atomic IS the process-wide pointer (D9). It is the
// ONE atomic the project owns (D1 exception). Never add more.
struct ReloadManager {
  std::mutex                                reload_mutex;
  std::atomic<ruleset::Ruleset*>            g_active{nullptr};

  // Bookkeeping — only touched under reload_mutex.
  bool            initialised = false;
  InitParams      params{};
  std::uint64_t   generation_counter = 0;  // monotonic, feeds name_prefix

  ReloadCounters  counters{};
};

ReloadManager g_{};

// -------------------------------------------------------------------------
// Helpers used only by this TU.

// Build a unique DPDK-object name_prefix per deploy. rte_hash / rte_fib
// enforce global name uniqueness; collisions between successive
// reloads produce EEXIST. Embedding the generation counter guarantees
// uniqueness across the lifetime of the process.
std::string compose_name_prefix(const std::string& base,
                                std::uint64_t gen) {
  return base + "_g" + std::to_string(gen);
}

// Free a previous Ruleset — C1 immediate free. C2/C3 swap this for
// RCU-synchronized pending_free drain. Localised behind a single
// helper so the GC sequencing change in later cycles only touches one
// call site.
void free_previous_ruleset(ruleset::Ruleset* rs_old) {
  // NOTE(M8 C2): replace with `rte_rcu_qsbr_start(qs)` + deadline poll
  // over `rte_rcu_qsbr_check(qs, token, false)`. For C1 there is no
  // real QSBR registration yet, so immediate free is safe (integration
  // tests exercise this path on a fresh fixture — no worker threads
  // holding references).
  delete rs_old;
}

// Internal deploy body — caller already holds reload_mutex.
// Runs parse / validate / compile / build / populate, then exchanges.
DeployResult deploy_locked(std::string_view config_json) {
  DeployResult out{};

  if (!g_.initialised) {
    out.ok = false;
    out.kind = DeployError::kInternal;
    out.error = "reload: not initialised";
    ++g_.counters.internal_error;
    return out;
  }

  // ---- 1. Parse --------------------------------------------------------
  config::ParseResult pr = config::parse(config_json);
  if (!config::is_ok(pr)) {
    const auto& err = config::get_err(pr);
    out.ok = false;
    out.kind = DeployError::kParse;
    out.error = "parse: " + err.message;
    ++g_.counters.parse_error;
    return out;
  }
  // validate() takes Config& (may default-fill fields per C7 U2.18)
  // so grab the variant member as a non-const reference rather than
  // via `config::get_ok` which returns const.
  config::Config& cfg = std::get<config::Config>(pr);

  // ---- 2. Validate -----------------------------------------------------
  config::ValidateResult vr = config::validate(cfg);
  if (std::holds_alternative<config::ValidateError>(vr)) {
    const auto& err = std::get<config::ValidateError>(vr);
    out.ok = false;
    out.kind = DeployError::kValidate;
    out.error = "validate: " + err.message;
    ++g_.counters.validate_error;
    return out;
  }

  // ---- 3. Compile ------------------------------------------------------
  compiler::CompileResult cr = compiler::compile(cfg);
  if (cr.error) {
    out.ok = false;
    out.kind = DeployError::kCompile;
    out.error = "compile: " + cr.error->message;
    ++g_.counters.compile_error;
    return out;
  }

  // ---- 4. Build Ruleset (pure-C++ arenas) ------------------------------
  auto rs_new = std::make_unique<ruleset::Ruleset>(
      ruleset::build_ruleset(cr, cfg.sizing, g_.params.num_lcores));

  // ---- 5. Populate EAL compound tables --------------------------------
  //
  // Unique name_prefix per deploy so successive reloads don't collide
  // in the rte_hash / rte_fib global namespace. See compose_name_prefix.
  const std::uint64_t gen = ++g_.generation_counter;
  rs_new->generation = gen;

  ruleset::EalPopulateParams ep;
  ep.name_prefix = compose_name_prefix(g_.params.name_prefix, gen);
  ep.socket_id   = g_.params.socket_id;
  ep.max_entries = g_.params.max_entries;

  auto ep_res = ruleset::populate_ruleset_eal(*rs_new, cr, ep);
  if (!ep_res.ok) {
    out.ok = false;
    out.kind = DeployError::kBuildEal;
    out.error = "build_eal: " + ep_res.error;
    ++g_.counters.build_eal_error;
    return out;
  }

  // ---- 6. Publish (atomic_exchange) -----------------------------------
  //
  // Release semantics on the store half so every write made to
  // *rs_new during build/populate is visible to any worker that
  // subsequently acquire-loads g_active and sees the new pointer.
  ruleset::Ruleset* rs_old =
      g_.g_active.exchange(rs_new.release(), std::memory_order_acq_rel);

  // ---- 7. Free previous --------------------------------------------
  free_previous_ruleset(rs_old);

  // ---- 8. Bookkeeping ---------------------------------------------
  ++g_.counters.success;
  out.ok = true;
  out.kind = DeployError::kOk;
  out.generation = gen;
  return out;
}

}  // namespace

// -----------------------------------------------------------------------
// Public API.

void init(const InitParams& params) {
  std::lock_guard<std::mutex> lock(g_.reload_mutex);
  if (g_.initialised) {
    // Idempotent under the same InitParams — tests repeat init() per
    // fixture setup. Overwriting params would surprise callers; keep
    // first-wins semantics.
    return;
  }
  g_.params = params;
  g_.initialised = true;
}

void shutdown() {
  std::lock_guard<std::mutex> lock(g_.reload_mutex);
  // C1 STUB: free g_active immediately. C4 will add
  //   1. signal workers to stop
  //   2. rte_rcu_qsbr_thread_offline + _thread_unregister per worker
  //   3. rte_rcu_qsbr_synchronize with bounded deadline
  //   4. then exchange g_active → nullptr and free
  ruleset::Ruleset* rs_old =
      g_.g_active.exchange(nullptr, std::memory_order_acq_rel);
  if (rs_old) {
    free_previous_ruleset(rs_old);
  }
  g_.initialised = false;
  g_.params = {};
  g_.generation_counter = 0;
  g_.counters = {};
}

bool is_initialised() {
  std::lock_guard<std::mutex> lock(g_.reload_mutex);
  return g_.initialised;
}

DeployResult deploy(std::string_view config_json) {
  std::lock_guard<std::mutex> lock(g_.reload_mutex);
  return deploy_locked(config_json);
}

DeployResult deploy_prebuilt(std::unique_ptr<ruleset::Ruleset> rs) {
  DeployResult out{};
  if (!rs) {
    out.ok = false;
    out.kind = DeployError::kInternal;
    out.error = "deploy_prebuilt: null Ruleset";
    std::lock_guard<std::mutex> lock(g_.reload_mutex);
    ++g_.counters.internal_error;
    return out;
  }

  std::lock_guard<std::mutex> lock(g_.reload_mutex);
  if (!g_.initialised) {
    out.ok = false;
    out.kind = DeployError::kInternal;
    out.error = "deploy_prebuilt: not initialised";
    ++g_.counters.internal_error;
    return out;
  }

  const std::uint64_t gen = ++g_.generation_counter;
  rs->generation = gen;

  ruleset::Ruleset* rs_old =
      g_.g_active.exchange(rs.release(), std::memory_order_acq_rel);

  free_previous_ruleset(rs_old);

  ++g_.counters.success;
  out.ok = true;
  out.kind = DeployError::kOk;
  out.generation = gen;
  return out;
}

ruleset::Ruleset* active_ruleset() {
  return g_.g_active.load(std::memory_order_acquire);
}

ReloadCounters counters_snapshot() {
  std::lock_guard<std::mutex> lock(g_.reload_mutex);
  return g_.counters;  // copy by value
}

std::atomic<ruleset::Ruleset*>* g_active_ptr() {
  return &g_.g_active;
}

}  // namespace pktgate::ctl::reload
