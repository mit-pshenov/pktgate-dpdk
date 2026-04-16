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

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

#include <variant>

#include <rte_rcu_qsbr.h>

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

  // C2 — scalar stash for rs_old pointers whose RCU synchronize timed
  // out. In C3 this is replaced by a K_PENDING=8 array + drain
  // discipline. For C2 we just keep the pointer LIVE-REACHABLE so
  // LeakSanitizer doesn't flag the intentional leak; shutdown() drops
  // it with `delete` (no quiescent guarantee — fine for test
  // teardown, where workers are being joined anyway).
  //
  // Not a real pending_free queue: single slot, last-writer-wins,
  // older timed-out pointers ARE leaked if two timeouts land in a row
  // (vanishingly rare; C3 is the real fix).
  ruleset::Ruleset* c2_pending_leak = nullptr;
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

// Actually delete the old ruleset and bump the `freed_total`
// counter. Caller must hold `reload_mutex`. Kept as a single helper
// so C3's pending_free drain has one call site to swap over.
void do_free_ruleset_locked(ruleset::Ruleset* rs_old) {
  if (rs_old == nullptr) return;
  delete rs_old;
  ++g_.counters.freed_total;
}

// C2 — bounded RCU synchronize.
//
// Take a start token, then poll rte_rcu_qsbr_check(wait=false) against
// a steady_clock deadline. Returns:
//   *  1 — all registered readers have reported quiescent; safe to free.
//   *  0 — deadline expired; caller must NOT free (C2: leak; C3: push
//         onto pending_free queue with the TOKEN we took here).
//
// NB: the token MUST be taken AFTER the atomic_exchange; taking it
// before races the grace period and can let a worker still holding
// the old pointer pass a quiescent checkpoint before the publish.
//
// `wait` is a BOOL (NOT a timeout, NOT a TSC delta — D30).
// `wait=false` makes rte_rcu_qsbr_check non-blocking so we can layer
// our own steady_clock deadline without blocking indefinitely in DPDK.
int wait_for_quiescent(struct rte_rcu_qsbr* qs,
                       uint64_t token,
                       std::chrono::steady_clock::time_point deadline,
                       std::chrono::microseconds poll_interval) {
  if (qs == nullptr) {
    // C2 — no-QSBR mode: fall back to the C1 immediate-free contract.
    return 1;
  }
  for (;;) {
    int r = rte_rcu_qsbr_check(qs, token, /*wait=*/false);
    if (r == 1) return 1;
    if (std::chrono::steady_clock::now() >= deadline) {
      return 0;  // timeout
    }
    std::this_thread::sleep_for(poll_interval);
  }
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

  // ---- 7. Bounded RCU synchronize --------------------------------
  //
  // Take the token AFTER the exchange (D30). Poll with wait=false
  // against a monotonic deadline; if the deadline expires, bail out
  // with kReloadTimeout. C2 intentionally LEAKS rs_old on timeout —
  // C3 adds pending_free[] with the token we took here.
  const uint64_t token = (g_.params.qs != nullptr)
                             ? rte_rcu_qsbr_start(g_.params.qs)
                             : 0u;
  const auto deadline =
      std::chrono::steady_clock::now() + g_.params.reload_timeout;

  const int sync_ok = wait_for_quiescent(g_.params.qs, token, deadline,
                                         g_.params.poll_interval);
  if (sync_ok != 1) {
    // TODO(M8 C3): push {rs_old, token} onto K_PENDING=8 pending_free
    // queue instead of stashing in a single-slot leak holder. For C2,
    // we intentionally keep rs_old live-reachable via `c2_pending_leak`
    // so LeakSanitizer doesn't flag the deliberate leak; the sentinel
    // test (X1.4) observes `freed_total` unchanged.
    if (g_.c2_pending_leak != nullptr) {
      // Second back-to-back timeout: the older pointer IS actually
      // leaked in C2 (last-writer-wins). C3's K_PENDING=8 slots fix
      // this; for the single-slot C2 stash this is documented.
    }
    g_.c2_pending_leak = rs_old;
    ++g_.counters.timeout;
    out.ok = false;
    out.kind = DeployError::kReloadTimeout;
    out.error = "reload: synchronize deadline expired";
    // Generation still reports the publish — the new ruleset is
    // live, we just couldn't free the old one yet.
    out.generation = gen;
    return out;
  }

  // ---- 8. Free previous (quiescent) -----------------------------
  do_free_ruleset_locked(rs_old);

  // ---- 9. Bookkeeping -------------------------------------------
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
  //
  // For C2 we keep the immediate free in shutdown: the fixture path
  // either has already joined its fake workers (so QSBR is idle) or
  // is tearing down an EAL that never had real workers. C4 owns the
  // real shutdown-sequence fix (D12).
  ruleset::Ruleset* rs_old =
      g_.g_active.exchange(nullptr, std::memory_order_acq_rel);
  if (rs_old) {
    do_free_ruleset_locked(rs_old);
  }
  // Drain C2's single-slot pending_free stash. In production C4 would
  // run a final bounded synchronize first; for tests the fixture has
  // already joined its fake workers by the time shutdown() is called.
  if (g_.c2_pending_leak != nullptr) {
    do_free_ruleset_locked(g_.c2_pending_leak);
    g_.c2_pending_leak = nullptr;
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

  // Bounded synchronize — same contract as deploy_locked above.
  const uint64_t token = (g_.params.qs != nullptr)
                             ? rte_rcu_qsbr_start(g_.params.qs)
                             : 0u;
  const auto deadline =
      std::chrono::steady_clock::now() + g_.params.reload_timeout;
  const int sync_ok = wait_for_quiescent(g_.params.qs, token, deadline,
                                         g_.params.poll_interval);
  if (sync_ok != 1) {
    // TODO(M8 C3): push {rs_old, token} onto K_PENDING=8 pending_free.
    // C2 stashes in a single slot — LSAN stays happy, freed_total
    // stays unchanged, test harness can observe both invariants.
    g_.c2_pending_leak = rs_old;
    ++g_.counters.timeout;
    out.ok = false;
    out.kind = DeployError::kReloadTimeout;
    out.error = "deploy_prebuilt: synchronize deadline expired";
    out.generation = gen;
    return out;
  }

  do_free_ruleset_locked(rs_old);

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
