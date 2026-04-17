// src/runtime/arena_gc.cpp
//
// M9 C4 — D11 arena GC body. See arena_gc.h for the contract.
//
// Walk `rs_old->rl_actions[0 .. n_rl_actions]`; for each rule_id NOT
// present in `rs_new->rl_actions`, eagerly zero the associated per-lcore
// TokenBucket row in the rl_arena singleton (§9.4 step 5b — keeps
// stats-on-exit consistent with §10.3, D33) and then call
// `arena.free_slot(rule_id)` (D24 — slot released, row storage stays).
//
// Ordering invariant (D11): the caller in src/ctl/reload.cpp has
// already verified `rte_rcu_qsbr_check(qs, token, …) == 1` (or runs on
// a non-concurrent shutdown/drain path). No reader can observe the
// removed slots any more, so eager row zeroing is race-free.
//
// Complexity: O(n_old × n_new). Control-plane only; typical n < 100.
// Not worth a set/hash map allocation.

#include "src/runtime/arena_gc.h"

#include <cstdint>
#include <cstring>
#include <mutex>
#include <utility>

#include "src/rl_arena/arena.h"
#include "src/rl_arena/rl_arena.h"
#include "src/ruleset/ruleset.h"

namespace pktgate::runtime {

namespace {

// Hook override + mutex. Small lock contention footprint: the hook is
// called once per successful reload, long after the hot path. Tests
// swap the function under the same lock so the override is visible
// the next time deploy() runs.
std::mutex  g_hook_mutex;
ArenaGcHook g_hook;

// Linear membership check in `rs_new->rl_actions`. Returns true when
// `rule_id` is carried into the successor ruleset (and must therefore
// be KEPT in the arena). `rs_new == nullptr` means "no successor" —
// equivalent to an empty rule-id set — every rule is "removed".
bool rule_id_kept_in_new(const ruleset::Ruleset* rs_new,
                         std::uint64_t rule_id) noexcept {
  if (rs_new == nullptr || rs_new->rl_actions == nullptr) return false;
  const std::uint32_t n = rs_new->n_rl_actions;
  for (std::uint32_t j = 0; j < n; ++j) {
    if (rs_new->rl_actions[j].rule_id == rule_id) return true;
  }
  return false;
}

// Default GC body — the real implementation. Kept as a free function
// so the test-hook override can short-circuit it cleanly.
void default_gc_body(ruleset::Ruleset* rs_old,
                     ruleset::Ruleset* rs_new) noexcept {
  if (rs_old == nullptr || rs_old->rl_actions == nullptr) return;
  if (rs_old->n_rl_actions == 0) return;

  auto& arena = rl_arena::rl_arena_global();

  const std::uint32_t n_old = rs_old->n_rl_actions;
  for (std::uint32_t i = 0; i < n_old; ++i) {
    const std::uint64_t rid = rs_old->rl_actions[i].rule_id;

    // A zero rule_id is a sentinel — `RlAction` value-initialises with
    // rule_id == 0, so any padding slot in a partially-populated
    // rl_actions array would otherwise trigger spurious free_slot(0).
    // The compiler should never emit rule_id == 0 for a real RL rule
    // (config validation + D41 roundtrip tests guard the positive
    // range), but the defensive guard is cheap.
    if (rid == 0) continue;

    if (rule_id_kept_in_new(rs_new, rid)) continue;

    // Rule removed. Resolve its slot; if the arena no longer knows
    // about it (idempotency path — GC ran earlier or this rule_id
    // never got a slot) the lookup returns nullopt and we skip both
    // steps silently.
    const auto slot_opt = arena.lookup_slot(rid);
    if (!slot_opt) continue;

    // §9.4 step 5b — eager zero of the per-lcore TokenBucket row.
    // Must precede free_slot so a concurrent reader that observed the
    // slot through `rs_old` sees zeroes (RCU has confirmed quiescent,
    // so strictly this is belt-and-braces; the real win is D33 —
    // stats-on-exit can't leak old bucket state into a freshly
    // re-allocated rule_id). Zeroes tokens, last_refill_tsc, dropped,
    // and any padding on every lcore slot in the row.
    rl_arena::RlRow& row = arena.get_row(*slot_opt);
    std::memset(&row, 0, sizeof(rl_arena::RlRow));

    // D24 — release the slot index. Row memory stays allocated; the
    // bitmap bit goes free; id_to_slot entry is dropped.
    arena.free_slot(rid);
  }
}

}  // namespace

void rl_arena_gc(ruleset::Ruleset* rs_old,
                 ruleset::Ruleset* rs_new) noexcept {
  // Snapshot hook under lock so a concurrent test-swap does not race
  // the call. std::function copy is allocation-free for small lambdas.
  ArenaGcHook local;
  {
    std::lock_guard<std::mutex> lk(g_hook_mutex);
    local = g_hook;
  }
  if (local) {
    // Test hook present — invoke it. noexcept on the function is a
    // promise to the reload caller that we won't propagate exceptions,
    // so wrap the std::function call in a try/catch-all.
    try {
      local(rs_old, rs_new);
    } catch (...) {
      // Swallow — tests must not throw out of the hook.
    }
    return;
  }

  default_gc_body(rs_old, rs_new);
}

void set_arena_gc_hook_for_test(ArenaGcHook hook) {
  std::lock_guard<std::mutex> lk(g_hook_mutex);
  g_hook = std::move(hook);
}

}  // namespace pktgate::runtime
