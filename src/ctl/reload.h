// src/ctl/reload.h
//
// M8 C1 — ReloadManager: single-funnel hot-reload pipeline.
//
// Owns the single process-wide `g_active` pointer (D9) and the single
// `reload_mutex` (D35) that serialises every reload entry point
// (cmd_socket UDS in M8; inotify in M11). Every publish of a new
// Ruleset goes through `deploy()`, which parses the incoming config
// JSON, runs it through validate / compile / build / populate, and
// atomically exchanges `g_active` under the mutex.
//
// C1 scope (this file):
//   * move g_active ownership out of main.cpp (D9 structural)
//   * wire a minimal `deploy(json)` that runs the full pipeline
//     (parse → validate → compile → build → populate_ruleset_eal)
//     under reload_mutex and atomic-exchanges g_active
//   * expose a worker-facing accessor `active_ruleset()`
//   * publish a small ReloadCounters struct so tests / later cycles
//     can observe success / error buckets
//
// C2 scope (this file):
//   * take a `rte_rcu_qsbr*` handle in InitParams (optional — nullptr
//     reverts to the C1 immediate-free path for unit-style tests)
//   * bounded synchronize: after atomic_exchange, `rte_rcu_qsbr_start`
//     to take a TOKEN, then poll `rte_rcu_qsbr_check(qs, token,
//     wait=false)` against a `steady_clock` deadline
//   * on deadline expiry: return DeployError::kReloadTimeout, bump the
//     `timeout` counter, and INTENTIONALLY LEAK the old ruleset
//     (C3 adds pending_free; for C2 a TODO marks the leak)
//   * configurable `reload_timeout` (default 500 ms, tests may shrink
//     to 50 ms so X1.4 doesn't stall)
//   * `freed_total` counter so tests can assert "old ruleset freed"
//     without UAF-reading the raw pointer
//
// C3 scope (this file):
//   * K_PENDING=8 pending_free queue (§9.2, D36). Each deploy() starts
//     by attempting to drain every entry via rte_rcu_qsbr_check(wait=0)
//     using the token stored with each entry. Drained rulesets are
//     freed (freed_total bumps); un-drained entries are compacted back
//     into the queue head.
//   * On a timeout, the old ruleset is pushed onto pending_free with
//     the token taken AFTER the publish exchange. The C2 single-slot
//     `c2_pending_leak` bridge is REMOVED.
//   * On overflow (9th stuck entry), `pending_full` counter bumps per
//     overflow, `overflow_log_total` bumps once per overflow EVENT
//     (throttled by `overflow_event_logged` flag that resets whenever
//     a drain actually frees a slot). The overflowing ruleset is
//     retained in `overflow_holder` so ASAN/LSAN stay clean — design
//     spec is "leak rs_old" semantically, but live-reachable retention
//     keeps the sanitisers quiet.
//
// D30 compliance — SIGNATURES verified against DPDK 25.11 on 2026-04-16:
//   * /home/mit/Dev/dpdk-25.11/lib/rcu/rte_rcu_qsbr.h (live header)
//   * doc.dpdk.org/api-25.11/rte__rcu__qsbr_8h.html
//     - `uint64_t rte_rcu_qsbr_start(struct rte_rcu_qsbr *v)`
//       returns a TOKEN (not a TSC delta).
//     - `int rte_rcu_qsbr_check(struct rte_rcu_qsbr *v, uint64_t t,
//        bool wait)` — `t` is a token; `wait` is a BLOCKING FLAG
//       (bool), not a timeout. Returns 1 when all registered readers
//       have reported quiescent since `t` was issued; 0 otherwise.
//     - We pass `wait=false` and manage our own deadline via
//       `std::chrono::steady_clock`.
//
// Later cycles extend this module:
//   * C3 — pending_free[K_PENDING=8] queue + drain + overflow alert
//   * C4 — shutdown sequence (offline+unregister+synchronize) + D37
//          validator memory-budget pre-flight
//   * C5 — telemetry reload channel (/pktgate/reload) + REFACTOR
//
// Design anchors:
//   * design.md §4.5 — ControlPlaneState, g_active, reload_mutex
//   * design.md §9.2 — deploy() pipeline (parse/validate/compile/
//                       build/publish/synchronize/GC)
//   * review-notes.md D9  — single process-wide g_active (overrides
//                            per-worker ownership)
//   * review-notes.md D35 — single reload_mutex funnel

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

#include "src/config/validator.h"  // HugepageProbe type for test helper
#include "src/ruleset/ruleset.h"

// Opaque forward declaration — we take a `rte_rcu_qsbr*` but do not
// pull the DPDK RCU header into every C++ TU that includes reload.h.
// The actual struct lives in `lib/rcu/rte_rcu_qsbr.h`; the reload TU
// includes it locally.
struct rte_rcu_qsbr;

namespace pktgate::ctl::reload {

// -------------------------------------------------------------------------
// DeployError — classify why a deploy() call failed.
//
// Maps roughly to `reload_total{result=…}` labels in the telemetry
// model (design.md §9.2). C5 will surface these as Prometheus labels.
enum class DeployError {
  kOk = 0,
  kParse,              // JSON syntax or schema mismatch
  kValidate,           // semantic validation failed
  kValidatorBudget,    // C4 — D37 memory-budget pre-flight rejected the config
  kCompile,            // compiler rejected the ruleset
  kBuildEal,           // EAL table population failed (rte_hash/fib)
  kReloadTimeout,      // C2 — RCU synchronize deadline expired (D30/D12)
  kInternal,           // programmer error / not-initialized
};

// D37 reject reasons — spec literal strings (design §9.2).
// Carried on DeployResult when `kind == kValidatorBudget` so the caller
// can route to the correct sub-reason telemetry counter and emit an
// operator-visible log line.
enum class ValidatorBudgetReason {
  kNone = 0,
  kExpansionPerRule,  // "expansion_per_rule" — one rule exceeds the per-rule ceiling
  kAggregate,         // "aggregate"          — sum of expanded entries exceeds total cap
  kHugepageBudget,    // "hugepage_budget"    — projected arena size > available hugepages
};

// DeployResult — one deploy() outcome.
//
// Success => `ok=true`, `error` empty, `generation` set to the new
// Ruleset's generation. Failure => `ok=false`, `error` human-readable,
// `kind` tagging which stage failed.
struct DeployResult {
  bool ok = false;
  DeployError kind = DeployError::kInternal;
  std::string error;
  std::uint64_t generation = 0;
  // C4 — populated when kind == kValidatorBudget. `kNone` otherwise.
  ValidatorBudgetReason budget_reason = ValidatorBudgetReason::kNone;
};

// -------------------------------------------------------------------------
// ReloadCounters — per-process reload statistics.
//
// Plain u64 fields (D1: zero-atomics except g_active). `counters_snapshot()`
// returns a copy taken under `reload_mutex`, so there's no torn-read
// concern on the caller side. The storm test (X1.2) samples this after
// 1000 UDS reloads to assert `success == 1000`.
struct ReloadCounters {
  std::uint64_t success = 0;
  std::uint64_t parse_error = 0;
  std::uint64_t validate_error = 0;
  std::uint64_t compile_error = 0;
  std::uint64_t build_eal_error = 0;
  std::uint64_t timeout = 0;        // C2 — reload synchronize deadline expired
  std::uint64_t internal_error = 0;
  // Side-channel for tests: counts ruleset frees that actually ran
  // (i.e. reached `delete rs_old` after QSBR said quiescent). Lets
  // the X1.4 sentinel assert "old ruleset NOT freed on timeout"
  // without UAF-reading the stale pointer. C3: pending_free drain also
  // bumps this counter (one bump per entry freed).
  std::uint64_t freed_total = 0;
  // C3 — D36 pending_free observables.
  //
  // `pending_depth` is a GAUGE (current queue occupancy, 0..K_PENDING).
  // `pending_full` is a COUNTER (bumps once per reload that overflowed
  //                              because the queue was already full).
  // `overflow_log_total` is a COUNTER that tests inspect: it counts
  //                              ERROR log emissions "reload_pending_full
  //                              dataplane_wedged". Throttled to ONE
  //                              per overflow event (a new event starts
  //                              the next time a drain actually frees a
  //                              slot), NOT one per overflow retry.
  std::uint64_t pending_depth = 0;
  std::uint64_t pending_full = 0;
  std::uint64_t overflow_log_total = 0;

  // C4 — D37 validator budget pre-flight sub-reason counters. Each
  // bumps exactly once per deploy() that rejects on its respective
  // gate. On a validator-budget reject the publish exchange DOES NOT
  // happen — `active_ruleset()` is unchanged, `active_generation`
  // stays put.
  std::uint64_t validate_budget_expansion_per_rule = 0;
  std::uint64_t validate_budget_aggregate          = 0;
  std::uint64_t validate_budget_hugepage           = 0;

  // C4 — monotonic "generation of currently published ruleset". Only
  // bumps on a SUCCESSFUL exchange; sticky across validator rejects,
  // parse errors, timeouts (timeout still publishes, so the publish
  // generation is the one that advances — but `success` is the
  // contract visible in tests). X1.6/X1.7 check this as the
  // "active_generation unchanged on reject" invariant.
  std::uint64_t active_generation = 0;
};

// -------------------------------------------------------------------------
// InitParams — construction-time configuration of the reload manager.
//
// Carries the knobs that populate_ruleset_eal() needs (socket id,
// entries per compound table) and the per-lcore counter-row sizing
// that build_ruleset() uses (num_lcores).
//
// `name_prefix` is composed with the per-deploy generation counter
// to produce unique rte_hash / rte_fib names (DPDK's global registry
// forbids duplicates). Prefix defaults to "pktgate_reload" for tests.
struct InitParams {
  int           socket_id   = 0;
  unsigned      num_lcores  = 1;
  std::uint32_t max_entries = 1024;
  std::string   name_prefix = "pktgate_reload";

  // C2 — RCU-QSBR bounded synchronize.
  //
  // `qs` is borrowed — the caller (main.cpp in production, the
  // integration fixture in tests) owns the QSBR storage and the
  // thread_register/online lifecycle. When `qs == nullptr` the reload
  // manager falls back to the C1 immediate-free path (unit-style
  // tests that don't care about quiescent-state sequencing).
  //
  // `reload_timeout` is the upper bound on how long `deploy()` is
  // willing to poll `rte_rcu_qsbr_check` after publish. Production
  // default is 500 ms per design §9.2; X1.4 shrinks this to 50 ms so
  // the sentinel doesn't stall the test wall-clock.
  //
  // `poll_interval` is the quantum between check() calls. 100 µs
  // keeps the busy-loop off the CPU without adding meaningful
  // latency to the common (fast) quiescent path.
  struct rte_rcu_qsbr*      qs              = nullptr;
  std::chrono::milliseconds reload_timeout  = std::chrono::milliseconds(500);
  std::chrono::microseconds poll_interval   = std::chrono::microseconds(100);

  // C4 — upper bound on how long shutdown() is willing to poll
  // rte_rcu_qsbr_check after the caller has already joined its
  // workers. Well under this in practice (workers offline +
  // unregistered => check returns 1 immediately). A deadline exists
  // only so we don't block indefinitely if a worker died mid-flight
  // without cleanly un-registering.
  std::chrono::milliseconds shutdown_timeout =
      std::chrono::milliseconds(2000);
};

// Initialise the reload manager. Must be called once per process
// before any deploy() / active_ruleset() call. Thread-safe (idempotent
// under the same InitParams; subsequent calls are no-ops so the
// integration fixture can call it per test without duplicating state).
void init(const InitParams& params);

// Shutdown the reload manager. Frees the current g_active (if any)
// and resets all internal state.
//
// C4 — D12 shutdown sequence.
//   1. CALLER responsibility: signal workers to stop and JOIN them
//      (rte_eal_mp_wait_lcore / std::thread::join). Workers MUST
//      have called rte_rcu_qsbr_thread_offline +
//      rte_rcu_qsbr_thread_unregister for themselves before exit
//      (see src/dataplane/worker.cpp).
//   2. shutdown() takes a start-token and polls
//      rte_rcu_qsbr_check(qs, token, wait=false) against a bounded
//      deadline (`shutdown_timeout`, default 2 s) so any straggling
//      grace period drains before we delete the currently-published
//      ruleset. If the deadline expires, the ruleset is pushed onto
//      `overflow_holder` (LSAN-clean retention) and a single WARN log
//      is emitted. Not blocking indefinitely is a design invariant.
//   3. atomic_exchange(g_active, nullptr) + delete if drained; push
//      onto overflow_holder otherwise.
//   4. Drain pending_free the same way; anything still pending after
//      the deadline joins overflow_holder.
//
// After shutdown() returns, the caller may destroy the QSBR storage
// (only the caller knows when it allocated it).
void shutdown();

// Return true if the manager has been initialised (for defensive
// guards in integration helpers and the U6.43b check).
bool is_initialised();

// -------------------------------------------------------------------------
// deploy() — the single publish entry point.
//
// Steps (C1 body):
//   1. Acquire reload_mutex (D35).
//   2. Parse the JSON payload → config::Config.
//   3. Validate the config.
//   4. Compile the config → CompileResult.
//   5. build_ruleset() + populate_ruleset_eal() — produce a fully
//      populated ruleset::Ruleset.
//   6. atomic_exchange(g_active, new_rs) — publish.
//   7. Free the previous ruleset (C1: immediate; C2/C3 wire RCU
//      synchronize + pending_free).
//   8. Bump success counter, return DeployResult{ok=true}.
//
// On any failure, bump the appropriate counter and return
// DeployResult{ok=false, kind=…} — g_active is NOT exchanged.
DeployResult deploy(std::string_view config_json);

// -------------------------------------------------------------------------
// active_ruleset() — worker-facing accessor.
//
// Returns the live Ruleset* with acquire-load semantics (D9). Every
// worker reads this at the top of its burst and holds the local
// pointer for the duration of the burst. RCU-QSBR (C2) will add the
// quiescent-state reporting; C1 only exposes the atomic load.
ruleset::Ruleset* active_ruleset();

// Snapshot the current reload counters. Taken under reload_mutex so
// no torn reads; caller gets a stable copy.
ReloadCounters counters_snapshot();

// -------------------------------------------------------------------------
// Test helpers (internal — not part of the stable API).
//
// `deploy_prebuilt()` accepts a fully-populated Ruleset and publishes
// it without running the parse/validate/compile/build pipeline. Used
// by the X1.2 cmd_socket storm test to avoid allocating 1000 FIBs /
// hash tables (each rte_fib_create pins ~128 MB of tbl24, and DPDK
// name uniqueness forces per-call name churn). Tests own the Ruleset
// construction; the manager just owns the publish + free.
DeployResult deploy_prebuilt(std::unique_ptr<ruleset::Ruleset> rs);

// Internal accessor for the structural U6.43b test (the test checks
// that this symbol exists and is reachable).
std::atomic<ruleset::Ruleset*>* g_active_ptr();

// C4 — test helper: inject a deterministic HugepageProbe lambda for
// the D37 gate-3 tests (X1.6.HugepageBudget, X1.7.HugepageBudget).
// Passing an empty std::function resets the probe to the default
// "bottomless" probe used in production.
void set_budget_probe_for_test(config::HugepageProbe probe);

// C5 — test helpers for the F5.12/F5.13/F5.14 functional tests.
//
// These bypass the worker hot path entirely: instead of freezing a
// real QSBR thread (which requires test-only worker state and would
// add a D1-class branch), we directly drive the post-synchronize
// accounting paths under reload_mutex. The functional tests assert
// only that the reload-counter family in stats-on-exit reflects the
// simulated events; the INTEGRATION tier (X1.4/X1.5) covers the
// real-QSBR behaviour end-to-end.
//
// simulate_timeout_for_test — push a dummy {ruleset, token} pair onto
// pending_free (or overflow if already full), bump `timeout`, and
// possibly emit the throttled ERROR log. The "dummy ruleset" is a
// default-constructed Ruleset (deleted by the drain path, or retained
// in overflow_holder on overflow — LSAN-clean either way).
void simulate_timeout_for_test();

// simulate_drain_for_test — run drain_pending_free_locked() with
// qs==nullptr (immediate-drain semantics) so every entry on
// pending_free is freed and `freed_total` bumps accordingly.
// Resets the overflow-log throttle on any successful drain.
void simulate_drain_for_test();

}  // namespace pktgate::ctl::reload
