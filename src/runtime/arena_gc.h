// src/runtime/arena_gc.h
//
// M8 C5 — D11 arena GC hook (stub).
//
// The reload manager calls `rl_arena_gc(rs_old)` AFTER the bounded
// `rte_rcu_qsbr_check` has confirmed quiescent and BEFORE freeing the
// old ruleset. M8 ships only the hook-point: the body is empty.
// M9 C5 fills the real rl_arena slot lifecycle per D11 + D24 (walk
// removed rules, zero counter rows, free arena slot indices).
//
// The ordering invariant that matters NOW is:
//   publish(rs_new) → synchronize(qs, token, deadline) → rl_arena_gc(rs_old)
//   → delete rs_old
// Any reader that observed rs_old's rl_arena slot index has by this
// point reported quiescent, so it is safe to zero the row. This
// invariant is what the M8 hook pins; body is M9.
//
// The hook is declared noexcept so callers under reload_mutex don't
// need to add exception plumbing. `rs` may legitimately be nullptr
// (first-ever reload has no predecessor) — M9 C5 must no-op on null.
//
// Test hook: `set_arena_gc_hook_for_test` swaps the concrete function
// pointer for a lambda so the `ArenaGcHookCalled` integration test
// can verify reload.cpp actually invokes it at the right point
// without waiting for the M9 body to land.
//
// Design anchors:
//   * review-notes.md §D11 — "arena GC ordering after synchronize"
//   * review-notes.md §D24 — "rl_arena slot lifecycle: free slot, not free row"
//   * design.md §11       — arena GC hook point
//   * implementation-plan.md §M8 GREEN impl bullet 4

#pragma once

#include <functional>

#include "src/ruleset/ruleset.h"

namespace pktgate::runtime {

// Run arena GC on a ruleset that has just exited the quiescent grace
// period and is about to be freed. Called from reload::deploy_locked
// AFTER `rte_rcu_qsbr_check(qs, token, …) == 1` and BEFORE the actual
// delete. M8 body is empty; M9 C5 fills per D11 + D24.
//
// Thread safety: caller holds reload_mutex. No atomics required.
void rl_arena_gc(ruleset::Ruleset* rs) noexcept;

// Test-only hook. Passing a non-empty std::function replaces the
// default stub body; passing an empty std::function restores the
// default. Tests use this to assert the hook is actually invoked
// by reload::deploy() at the right point.
using ArenaGcHook = std::function<void(ruleset::Ruleset*)>;
void set_arena_gc_hook_for_test(ArenaGcHook hook);

}  // namespace pktgate::runtime
