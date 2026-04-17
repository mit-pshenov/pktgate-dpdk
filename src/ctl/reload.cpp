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

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <variant>

#include <rte_rcu_qsbr.h>

#include "src/compiler/compiler.h"
#include "src/compiler/object_compiler.h"
#include "src/config/model.h"
#include "src/config/parser.h"
#include "src/config/sizing.h"
#include "src/config/validator.h"
#include "src/rl_arena/arena.h"
#include "src/runtime/arena_gc.h"
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
// -------------------------------------------------------------------------
// Default hugepage-budget probe — reports a very large availability
// so the common case (no tests / production with real hugepages) never
// hits the gate by accident. Tests that need the gate injected poke a
// custom probe via `set_budget_probe_for_test`.
config::HugepageProbe make_default_budget_probe() {
  return [] {
    return config::HugepageInfo{/*available_bytes=*/static_cast<std::size_t>(1)
                                << 40};  // 1 TiB — effectively unlimited.
  };
}

// PendingEntry — one {ruleset, token} pair on the pending_free queue.
// The token was produced by `rte_rcu_qsbr_start(qs)` AFTER the publish
// exchange (§9.2 D30); each drain attempt polls
// `rte_rcu_qsbr_check(qs, token, wait=false)` and frees the ruleset on
// success.
struct PendingEntry {
  ruleset::Ruleset* rs    = nullptr;
  std::uint64_t     token = 0;
};

// K_PENDING=8 is FIXED per design §9.2 — "each entry is ~bytes; 8 is
// plenty for plausible stuck-worker scenarios before the watchdog
// escalates". Not configurable; see review-notes.md D36.
static constexpr std::size_t kPendingMax = 8;

struct ReloadManager {
  std::mutex                                reload_mutex;
  std::atomic<ruleset::Ruleset*>            g_active{nullptr};

  // Bookkeeping — only touched under reload_mutex.
  bool            initialised = false;
  InitParams      params{};
  std::uint64_t   generation_counter = 0;  // monotonic, feeds name_prefix

  // C4 — D37 budget probe injection point. The integration tests need
  // to drive the hugepage-budget gate deterministically (the real
  // /proc-hugepages reader reports whatever the host has at test time,
  // which is not controllable). Tests poke a lambda here via the
  // internal test helper below; production and other tests fall back
  // to the default "bottomless" probe.
  config::HugepageProbe budget_probe{};

  ReloadCounters  counters{};

  // C3 — D36 pending_free queue. Fixed-size array (§9.2 K_PENDING=8).
  // `pending_depth` is the live occupancy; all slots `[depth..max)`
  // are undefined. Every mutation happens under `reload_mutex`.
  std::array<PendingEntry, kPendingMax> pending_free{};
  std::size_t                           pending_depth = 0;

  // Throttling state for the "reload_pending_full dataplane_wedged"
  // ERROR log. The invariant: at most ONE log line is emitted per
  // overflow event. An "overflow event" STARTS when an overflow
  // happens and the flag is false → we log and flip the flag to true.
  // An "event ENDS" when a drain actually frees a slot → flag resets
  // to false. Subsequent overflows within the same event do NOT log.
  //
  // This matches X1.5's "exactly once per overflow (not once per
  // subsequent retry)" assertion and design §9.2 / D36 Q5 cadence.
  bool overflow_event_logged = false;

  // Overflow retention. Design spec says "intentionally leak rs_old"
  // on overflow, but LeakSanitizer must stay clean for dev-asan runs.
  // Retaining the pointer in a live-reachable unique_ptr container is
  // functionally equivalent (process is wedged; operator escalation
  // will restart). Never drained — by design.
  std::vector<std::unique_ptr<ruleset::Ruleset>> overflow_holder{};
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
// counter. Caller must hold `reload_mutex`. Also used by the
// pending_free drain to free entries whose grace period has elapsed.
void do_free_ruleset_locked(ruleset::Ruleset* rs_old) {
  if (rs_old == nullptr) return;
  delete rs_old;
  ++g_.counters.freed_total;
}

// C3 — D36 drain. Called at the TOP of every deploy() (before any
// ruleset-pointer manipulation) so a successful drain happens under
// the same lock that will take the next token. For each entry, poll
// `rte_rcu_qsbr_check(qs, entry.token, wait=false)` once; if it
// returns 1 the grace period has elapsed and the ruleset can be
// freed. Entries that are not yet quiescent are compacted back to
// the head of the array.
//
// If the drain frees AT LEAST ONE slot the overflow-log throttle is
// cleared — a future overflow starts a fresh event and WILL log.
//
// Caller must hold `reload_mutex`.
void drain_pending_free_locked() {
  if (g_.pending_depth == 0) return;
  // Without a QSBR handle there is no quiescent state to poll — fall
  // back to immediate drain (matches the no-qs mode elsewhere).
  struct rte_rcu_qsbr* const qs = g_.params.qs;
  std::size_t dst = 0;
  bool freed_any = false;
  for (std::size_t src = 0; src < g_.pending_depth; ++src) {
    PendingEntry& e = g_.pending_free[src];
    const int ok = (qs == nullptr)
                       ? 1
                       : rte_rcu_qsbr_check(qs, e.token, /*wait=*/false);
    if (ok == 1) {
      // D11 arena GC fires after the grace period has elapsed for
      // THIS entry — the whole point of the pending_free queue is
      // that we arrive here AFTER rte_rcu_qsbr_check confirms the
      // readers have all reported quiescent.
      if (e.rs != nullptr) pktgate::runtime::rl_arena_gc(e.rs);
      do_free_ruleset_locked(e.rs);
      freed_any = true;
      // drop the slot (do not copy forward)
    } else {
      if (dst != src) {
        g_.pending_free[dst] = e;
      }
      ++dst;
    }
  }
  // Zero-out the tail to avoid dangling ruleset* in unused slots.
  for (std::size_t i = dst; i < g_.pending_depth; ++i) {
    g_.pending_free[i] = PendingEntry{};
  }
  g_.pending_depth = dst;
  g_.counters.pending_depth = static_cast<std::uint64_t>(dst);
  if (freed_any) {
    // End-of-event: the next overflow starts a fresh throttle cycle.
    g_.overflow_event_logged = false;
  }
}

// C3 — handle a reload-timeout: either push {rs_old, token} onto
// pending_free, or declare overflow. On overflow, bump the counter
// and (throttled) emit the ERROR log + retain the ruleset in
// overflow_holder so LSAN stays clean.
//
// Caller must hold `reload_mutex`.
void handle_timeout_locked(ruleset::Ruleset* rs_old, std::uint64_t token) {
  if (rs_old == nullptr) return;

  if (g_.pending_depth < kPendingMax) {
    g_.pending_free[g_.pending_depth++] = PendingEntry{rs_old, token};
    g_.counters.pending_depth = static_cast<std::uint64_t>(g_.pending_depth);
    return;
  }

  // Overflow path.
  ++g_.counters.pending_full;
  if (!g_.overflow_event_logged) {
    // One ERROR line per overflow EVENT (§9.2 Q5 cadence, X1.5 spec).
    // Structured-ish format; main.cpp's log_json helper is TU-local,
    // so keep this self-contained here.
    std::fprintf(stderr,
                 "{\"level\":\"error\",\"event\":\"reload_pending_full\","
                 "\"reason\":\"dataplane_wedged\",\"pending_depth\":%zu}\n",
                 g_.pending_depth);
    ++g_.counters.overflow_log_total;
    g_.overflow_event_logged = true;
  }
  // Live-reachable retention: LSAN clean, semantically a leak (never
  // drained — by design, process is wedged).
  g_.overflow_holder.emplace_back(rs_old);
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

  // ---- 0. Drain pending_free (D36) -------------------------------------
  //
  // Happens BEFORE any new publish/synchronize so:
  //   * freed_total bumps before the new token is in play
  //   * a successful drain resets the overflow-log throttle BEFORE we
  //     possibly hit overflow again on this deploy
  drain_pending_free_locked();

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

  // ---- 2b. D37 validator memory-budget pre-flight (C4) -----------------
  //
  // Runs AFTER validate() succeeds but BEFORE compile / build /
  // populate — the whole point is to catch the "this config cannot
  // fit" case before we touch hugepages. Three gates, literal reason
  // strings per §9.2:
  //
  //   * expansion_per_rule — one rule expands past kDefaultPerRuleCeiling
  //   * aggregate          — sum of L4 expansions exceeds sizing cap
  //   * hugepage_budget    — estimated footprint > available hugepages
  //
  // A reject bumps the appropriate sub-reason counter and returns
  // kValidatorBudget with `budget_reason` populated; `active_ruleset()`
  // and `active_generation` are UNCHANGED.
  {
    // Manager-held budget probe. Defaults to "essentially unlimited"
    // so the C1/C2/C3 tests that never configured a probe keep their
    // happy-path semantics. Production would inject a real /proc
    // reader (C5 / M10 scope); the tests fit everything they need via
    // inline sizing values.
    config::HugepageProbe probe = g_.budget_probe
                                      ? g_.budget_probe
                                      : make_default_budget_probe();

    config::ValidateResult br = config::validate_budget(cfg, probe);
    if (std::holds_alternative<config::ValidateError>(br)) {
      const auto& berr = std::get<config::ValidateError>(br);
      out.ok = false;
      out.kind = DeployError::kValidatorBudget;
      out.error = "validator_budget: " + berr.message;
      switch (berr.kind) {
        case config::ValidateError::kBudgetPerRuleExceeded:
          out.budget_reason = ValidatorBudgetReason::kExpansionPerRule;
          ++g_.counters.validate_budget_expansion_per_rule;
          break;
        case config::ValidateError::kBudgetAggregateExceeded:
          out.budget_reason = ValidatorBudgetReason::kAggregate;
          ++g_.counters.validate_budget_aggregate;
          break;
        case config::ValidateError::kBudgetHugepage:
          out.budget_reason = ValidatorBudgetReason::kHugepageBudget;
          ++g_.counters.validate_budget_hugepage;
          break;
        // validate_budget contract (src/config/validator.h §D37): only
        // the three kBudget* kinds above are emitted. The remaining
        // enumerators belong to validate() proper and cannot appear
        // here. Listed explicitly for -Wswitch-enum; fall through to
        // the safe default classification.
        case config::ValidateError::kUnresolvedObject:
        case config::ValidateError::kUnresolvedInterfaceRef:
        case config::ValidateError::kDuplicateRuleId:
        case config::ValidateError::kKeyCollision:
        case config::ValidateError::kInvalidLayerTransition:
        case config::ValidateError::kUnresolvedTargetPort:
          out.budget_reason = ValidatorBudgetReason::kAggregate;
          ++g_.counters.validate_budget_aggregate;
          break;
      }
      return out;
    }
  }

  // ---- 3. Compile ------------------------------------------------------
  //
  // M9 C3 (D10, D24, D41): wire the process-wide RateLimit arena's
  // slot allocator into the compiler. Every kRateLimit rule gets a
  // stable slot (survives reload) recorded in CompiledAction.rl_slot;
  // the builder below copies it into RuleAction.rl_index AND
  // Ruleset::rl_actions[slot]. The allocator captures
  // `rl_arena_global()` by reference; deploy_locked is called under
  // `reload_mutex` (D35) so concurrent alloc_slot calls are impossible.
  compiler::RlSlotAllocator rl_alloc =
      [&](std::uint64_t rule_id) -> std::uint16_t {
    return rl_arena::rl_arena_global().alloc_slot(rule_id);
  };
  compiler::CompileResult cr = compiler::compile(cfg, /*opts=*/{}, rl_alloc);
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
    // C3 D36 — push {rs_old, token} onto pending_free. Overflow path
    // (queue was already full) retains rs_old in overflow_holder and
    // bumps pending_full + emits throttled ERROR log.
    handle_timeout_locked(rs_old, token);
    ++g_.counters.timeout;
    out.ok = false;
    out.kind = DeployError::kReloadTimeout;
    out.error = "reload: synchronize deadline expired";
    // Generation still reports the publish — the new ruleset is
    // live, we just couldn't free the old one yet.
    out.generation = gen;
    return out;
  }

  // ---- 8. Arena GC (D11) + free previous (quiescent) -----------
  //
  // D11 ordering invariant: synchronize has confirmed every worker
  // that observed rs_old has reported quiescent, so it is now safe
  // to walk rs_old's arena slots / zero counter rows / push slot
  // indices back on the free list. M8 body is a no-op stub; M9 C5
  // fills it. See src/runtime/arena_gc.h.
  //
  // Null-guard: first-ever deploy has no predecessor; nothing to GC.
  if (rs_old != nullptr) pktgate::runtime::rl_arena_gc(rs_old);
  do_free_ruleset_locked(rs_old);

  // ---- 9. Bookkeeping -------------------------------------------
  ++g_.counters.success;
  g_.counters.active_generation = gen;
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
  // C4 — D12 proper shutdown sequence.
  //
  // Sequencing assumption: the CALLER has already signalled workers
  // to stop and joined them (rte_eal_mp_wait_lcore in main.cpp, or
  // the test fixture's worker.join()). Each worker thread must have
  // called rte_rcu_qsbr_thread_offline + _thread_unregister for
  // itself at the bottom of its loop (see src/dataplane/worker.cpp).
  // Under those preconditions, rte_rcu_qsbr_check returns 1 as soon
  // as we ask.
  //
  // The sync here exists to give TSAN the happens-before edge it
  // cannot observe from rte_eal_mp_wait_lcore (DPDK's lcore join
  // uses internal sync that TSan's interceptors don't see). After
  // a successful rte_rcu_qsbr_check the sync fences in the DPDK
  // primitive are sufficient for TSAN to conclude "the worker's
  // read happened-before our delete". This closes the M4-M7
  // parked baseline race on every functional binary-runner.
  //
  // If the QSBR handle is nullptr (no workers, or unit-style fixture
  // that bypassed the lifecycle) we fall through to the C1 immediate
  // free — there is nothing to synchronize against.
  struct rte_rcu_qsbr* const qs = g_.params.qs;
  const auto deadline =
      std::chrono::steady_clock::now() + g_.params.shutdown_timeout;

  ruleset::Ruleset* rs_old =
      g_.g_active.exchange(nullptr, std::memory_order_acq_rel);

  if (rs_old != nullptr) {
    if (qs != nullptr) {
      const uint64_t tok = rte_rcu_qsbr_start(qs);
      const int ok = wait_for_quiescent(qs, tok, deadline,
                                        g_.params.poll_interval);
      if (ok == 1) {
        // D11 arena GC (stub; M9 fills). See deploy_locked step 8.
        if (rs_old != nullptr) pktgate::runtime::rl_arena_gc(rs_old);
        do_free_ruleset_locked(rs_old);
      } else {
        // Deadline expired (worker died mid-flight, or somebody forgot
        // to offline+unregister). Retain in overflow_holder so LSAN
        // stays clean. WARN, not ERROR — shutdown is best-effort.
        std::fprintf(stderr,
                     "{\"level\":\"warn\",\"event\":\"shutdown_sync_timeout\","
                     "\"note\":\"ruleset retained in overflow_holder\"}\n");
        g_.overflow_holder.emplace_back(rs_old);
      }
    } else {
      // No QSBR — caller guarantees no concurrent readers.
      // D11 arena GC fires regardless of the synchronize path.
      if (rs_old != nullptr) pktgate::runtime::rl_arena_gc(rs_old);
      do_free_ruleset_locked(rs_old);
    }
  }

  // C3 D36 — drain pending_free entries. After the synchronize above
  // every previously-queued token has necessarily expired (grace
  // period is cumulative), so we can free unconditionally.
  for (std::size_t i = 0; i < g_.pending_depth; ++i) {
    auto* p = g_.pending_free[i].rs;
    if (p != nullptr) pktgate::runtime::rl_arena_gc(p);
    do_free_ruleset_locked(p);
    g_.pending_free[i] = PendingEntry{};
  }
  g_.pending_depth = 0;
  // overflow_holder: unique_ptr destructors free the retained
  // rulesets. Bump freed_total for test visibility.
  for (auto& up : g_.overflow_holder) {
    if (up) ++g_.counters.freed_total;
  }
  g_.overflow_holder.clear();
  g_.overflow_event_logged = false;

  g_.initialised = false;
  g_.params = {};
  g_.generation_counter = 0;
  g_.counters = {};
  g_.budget_probe = {};
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

  // C3 — drain pending_free before this publish, same as deploy().
  drain_pending_free_locked();

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
    // C3 D36 — pending_free push + overflow handling (see deploy_locked).
    handle_timeout_locked(rs_old, token);
    ++g_.counters.timeout;
    out.ok = false;
    out.kind = DeployError::kReloadTimeout;
    out.error = "deploy_prebuilt: synchronize deadline expired";
    out.generation = gen;
    return out;
  }

  // D11 arena GC (stub; M9 fills). See deploy_locked step 8.
  // Null-guard: first-ever deploy has no predecessor and there is
  // nothing to GC; do_free_ruleset_locked tolerates nullptr too.
  if (rs_old != nullptr) pktgate::runtime::rl_arena_gc(rs_old);
  do_free_ruleset_locked(rs_old);

  ++g_.counters.success;
  g_.counters.active_generation = gen;
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

void set_budget_probe_for_test(config::HugepageProbe probe) {
  std::lock_guard<std::mutex> lock(g_.reload_mutex);
  g_.budget_probe = std::move(probe);
}

// -------------------------------------------------------------------------
// C5 — functional-test simulate helpers.

void simulate_timeout_for_test() {
  std::lock_guard<std::mutex> lock(g_.reload_mutex);
  // Fabricate a "stuck" old ruleset: the real pending_free contract
  // only cares that the pointer is delete-safe. A default-constructed
  // Ruleset satisfies that (no EAL handles owned). We use dummy token
  // 0 because simulate_drain will run with qs==nullptr which treats
  // every entry as quiescent.
  auto* rs_dummy = new ruleset::Ruleset{};
  handle_timeout_locked(rs_dummy, /*token=*/0u);
  ++g_.counters.timeout;
}

void simulate_drain_for_test() {
  std::lock_guard<std::mutex> lock(g_.reload_mutex);
  // Temporarily neutralise the QSBR handle so drain_pending_free_locked
  // treats every entry as quiescent and frees it. Restore on exit.
  struct rte_rcu_qsbr* const saved_qs = g_.params.qs;
  g_.params.qs = nullptr;
  drain_pending_free_locked();
  g_.params.qs = saved_qs;
}

}  // namespace pktgate::ctl::reload
