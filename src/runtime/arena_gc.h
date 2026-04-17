// src/runtime/arena_gc.h
//
// M8 C5 — D11 arena GC hook-point. M9 C4 fills the body.
//
// The reload manager calls `rl_arena_gc(rs_old, rs_new)` AFTER the
// bounded `rte_rcu_qsbr_check` has confirmed quiescent and BEFORE
// freeing the old ruleset. The M9 C4 body computes the rule-id set
// diff `removed = rs_old.rl_rule_ids \ rs_new.rl_rule_ids`, zeroes
// the RL TokenBucket row for every removed slot (§9.4 step 5b — safe
// because no reader can reach `rs_old` any more), then calls
// `RateLimitArena::free_slot(rule_id)` for each (D24 — slot release,
// row memory stays allocated for later reuse).
//
// The ordering invariant that matters is:
//   publish(rs_new) → synchronize(qs, token, deadline)
//     → rl_arena_gc(rs_old, rs_new)      ← C4 body
//     → delete rs_old
// Any reader that observed rs_old's rl_arena slot index has by this
// point reported quiescent, so it is safe to zero the row / free the
// slot. This invariant is pinned by the 5 call sites in
// src/ctl/reload.cpp (M8 C5 wired them; M9 C4 only updates the
// argument list).
//
// The hook is declared noexcept so callers under reload_mutex don't
// need exception plumbing.
//
// Nullable arguments:
//   * `rs_old == nullptr` — no predecessor (first-ever deploy). No-op.
//   * `rs_new == nullptr` — no successor (shutdown / drain path after
//                           timeout). Treat as empty rule-id set — every
//                           rule_id in rs_old is "removed".
//
// Test hook: `set_arena_gc_hook_for_test` swaps the concrete function
// pointer for a lambda so the `ArenaGcHookCalled` integration test
// can verify reload.cpp actually invokes it at the right point
// without coupling to the real arena's state.
//
// Design anchors:
//   * review-notes.md §D11 — "arena GC ordering after synchronize"
//   * review-notes.md §D24 — "rl_arena slot lifecycle: free slot, not free row"
//   * review-notes.md §D33 — "counter consistency invariant" (eager zero
//                             keeps stats-on-exit aligned with §10.3)
//   * design.md §9.4 step 5b — eager counter-row zeroing
//   * implementation-plan.md §M9 C4

#pragma once

#include <functional>

#include "src/ruleset/ruleset.h"

namespace pktgate::runtime {

// Run arena GC on a ruleset that has just exited the quiescent grace
// period and is about to be freed. Called from reload::deploy_locked
// (and the 4 other pre-wired sites) AFTER
// `rte_rcu_qsbr_check(qs, token, …) == 1` (or on a non-concurrent
// shutdown / drain path) and BEFORE the actual delete.
//
// Thread safety: caller holds reload_mutex (D35). No atomics required.
// Body reads `rs_old->rl_actions` + `rs_new->rl_actions` and mutates
// the process-wide `rl_arena::rl_arena_global()` singleton; the mutex
// funnel keeps this single-writer.
void rl_arena_gc(ruleset::Ruleset* rs_old,
                 ruleset::Ruleset* rs_new) noexcept;

// Test-only hook. Passing a non-empty std::function replaces the
// default body; passing an empty std::function restores the default.
// Tests use this to assert the hook is actually invoked by
// reload::deploy() at the right point without driving a real arena.
using ArenaGcHook =
    std::function<void(ruleset::Ruleset* rs_old, ruleset::Ruleset* rs_new)>;
void set_arena_gc_hook_for_test(ArenaGcHook hook);

}  // namespace pktgate::runtime
