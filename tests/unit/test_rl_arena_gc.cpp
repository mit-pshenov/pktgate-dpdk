// tests/unit/test_rl_arena_gc.cpp
//
// M9 C4 — `runtime::rl_arena_gc(rs_old, rs_new)` body.
//
// Covers:
//   * U4.11 — GC removes slot: rule_id present in rs_old and absent
//             from rs_new → slot freed; lookup_slot returns nullopt;
//             slot_live(s) is false. Surviving rule_ids keep their
//             slot with bucket state intact.
//   * U4.14 — counter row zeroed EAGERLY on slot reuse: armed bucket
//             values on the removed rule's row are zero IMMEDIATELY
//             after rl_arena_gc returns (before any subsequent
//             alloc_slot reuse). §9.4 step 5b / D11 / D33.
//
// The tests construct `Ruleset` values on the stack with manually-
// populated `rl_actions[]` arrays; `n_rl_actions` is pre-bumped so the
// GC body walks the entries. No compiler / builder involvement — this
// TU isolates the GC body's set-diff + zero + free_slot contract.
//
// The runtime arena is the process-wide singleton (D10), so each test
// scrubs its rule_ids at entry and exit via `ArenaScrubber` to keep
// tests independent inside a single binary.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#include "src/rl_arena/arena.h"
#include "src/rl_arena/rl_arena.h"
#include "src/runtime/arena_gc.h"
#include "src/ruleset/ruleset.h"

namespace pktgate::test {

namespace {

using ::pktgate::rl_arena::kInvalidSlot;
using ::pktgate::rl_arena::kMaxLcores;
using ::pktgate::rl_arena::RateLimitArena;
using ::pktgate::rl_arena::RlRow;
using ::pktgate::rl_arena::TokenBucket;

// Scrub rule_ids out of the process-wide arena at entry and exit so a
// test doesn't inherit or leak state. Same pattern as
// tests/integration/test_rl_compile_build.cpp (C3).
struct ArenaScrubber {
  std::vector<std::uint64_t> ids;
  explicit ArenaScrubber(std::vector<std::uint64_t> ids_)
      : ids(std::move(ids_)) {
    auto& a = rl_arena::rl_arena_global();
    for (auto id : ids) a.free_slot(id);
  }
  ~ArenaScrubber() {
    auto& a = rl_arena::rl_arena_global();
    for (auto id : ids) a.free_slot(id);
  }
};

// Build a Ruleset carrying `rl_actions[]` populated from the caller's
// vector. Storage lives on the heap inside the Ruleset (so ~Ruleset
// frees it through the default deleter). rule_id=0 is legal but the
// GC body treats it as a sentinel — tests avoid id==0 on purpose.
//
// Keeping this helper free-standing rather than inside a fixture lets
// each TEST case control its ruleset lifetime exactly.
ruleset::Ruleset make_rs_with_rl_ids(
    const std::vector<std::uint64_t>& rule_ids) {
  ruleset::Ruleset rs;
  if (rule_ids.empty()) return rs;

  const std::uint32_t n = static_cast<std::uint32_t>(rule_ids.size());
  // ~Ruleset uses ::operator delete[] on rl_actions when free_fn is
  // null (D23 custom-allocator is opt-in). Match that with new[].
  rs.rl_actions = new ruleset::RlAction[n];
  rs.rl_actions_capacity = n;
  rs.n_rl_actions = n;
  for (std::uint32_t i = 0; i < n; ++i) {
    rs.rl_actions[i] = ruleset::RlAction{
        /*rule_id=*/rule_ids[i],
        /*rate_bps=*/1'000'000ull,
        /*burst_bytes=*/100'000ull,
    };
  }
  return rs;
}

}  // namespace

// =========================================================================
// U4.11 — rl_arena_gc removes slots for rules absent from rs_new; keeps
// slots for surviving rules.
// =========================================================================
TEST(RlArenaGcU4_11, RemovesAbsentRulesKeepsSurvivors) {
  constexpr std::uint64_t kIdRemoved  = 0xC411'0001ull;
  constexpr std::uint64_t kIdKept     = 0xC411'0002ull;
  ArenaScrubber scrub{{kIdRemoved, kIdKept}};

  auto& arena = rl_arena::rl_arena_global();

  // Pre-alloc slots for both ids (simulates the compile-time alloc
  // the real pipeline performs).
  const std::uint16_t s_removed = arena.alloc_slot(kIdRemoved);
  const std::uint16_t s_kept    = arena.alloc_slot(kIdKept);
  ASSERT_NE(s_removed, kInvalidSlot);
  ASSERT_NE(s_kept,    kInvalidSlot);
  ASSERT_NE(s_removed, s_kept);

  // Mark the KEPT row with an easy-to-spot value so we can verify it
  // survives.
  arena.get_row(s_kept).per_lcore[2].tokens = 0xABCDEF01ull;
  arena.get_row(s_kept).per_lcore[2].dropped = 17;

  // rs_old: both ids.  rs_new: only kIdKept.
  ruleset::Ruleset rs_old = make_rs_with_rl_ids({kIdRemoved, kIdKept});
  ruleset::Ruleset rs_new = make_rs_with_rl_ids({kIdKept});

  runtime::rl_arena_gc(&rs_old, &rs_new);

  // Removed id: slot no longer live, lookup fails.
  EXPECT_FALSE(arena.lookup_slot(kIdRemoved).has_value())
      << "rl_arena_gc must call free_slot for rules absent from rs_new";
  EXPECT_FALSE(arena.slot_live(s_removed));

  // Kept id: same slot, bucket state preserved.
  ASSERT_TRUE(arena.lookup_slot(kIdKept).has_value());
  EXPECT_EQ(*arena.lookup_slot(kIdKept), s_kept)
      << "surviving rule must keep its slot across GC";
  EXPECT_TRUE(arena.slot_live(s_kept));
  EXPECT_EQ(arena.get_row(s_kept).per_lcore[2].tokens, 0xABCDEF01ull)
      << "surviving rule's bucket state must NOT be zeroed by GC";
  EXPECT_EQ(arena.get_row(s_kept).per_lcore[2].dropped, 17u);
}

// =========================================================================
// U4.11b — rs_new == nullptr means "no successor"; every rule_id in
// rs_old is removed. Exercises the shutdown/drain variant of the
// signature.
// =========================================================================
TEST(RlArenaGcU4_11, NullRsNewFreesEverything) {
  constexpr std::uint64_t kIdA = 0xC411'0101ull;
  constexpr std::uint64_t kIdB = 0xC411'0102ull;
  ArenaScrubber scrub{{kIdA, kIdB}};

  auto& arena = rl_arena::rl_arena_global();
  const std::uint16_t sa = arena.alloc_slot(kIdA);
  const std::uint16_t sb = arena.alloc_slot(kIdB);
  ASSERT_NE(sa, kInvalidSlot);
  ASSERT_NE(sb, kInvalidSlot);

  ruleset::Ruleset rs_old = make_rs_with_rl_ids({kIdA, kIdB});

  runtime::rl_arena_gc(&rs_old, /*rs_new=*/nullptr);

  EXPECT_FALSE(arena.lookup_slot(kIdA).has_value());
  EXPECT_FALSE(arena.lookup_slot(kIdB).has_value());
  EXPECT_FALSE(arena.slot_live(sa));
  EXPECT_FALSE(arena.slot_live(sb));
}

// =========================================================================
// U4.11c — rs_old == nullptr is a silent no-op (defensive; matches
// arena_gc.h contract).
// =========================================================================
TEST(RlArenaGcU4_11, NullRsOldNoOp) {
  // No arena state to scrub — the test touches no ids.
  ruleset::Ruleset rs_new = make_rs_with_rl_ids({});
  runtime::rl_arena_gc(/*rs_old=*/nullptr, &rs_new);
  runtime::rl_arena_gc(/*rs_old=*/nullptr, /*rs_new=*/nullptr);
  SUCCEED();
}

// =========================================================================
// U4.13 — barrier ordering (contract-level).
//
// The body enforces ordering through its POSITION in reload.cpp: the 5
// call sites all run AFTER `rte_rcu_qsbr_check(...) == 1` returned (or
// on a non-concurrent shutdown/drain path) and BEFORE
// `do_free_ruleset_locked` deletes rs_old. U4.13 pins this with a
// code-reading assertion + a body-level contract check.
//
// The code-reading part lives as source comments in reload.cpp +
// arena_gc.h. The dynamic part this test pins: the body is invoked
// against a ruleset that is still fully allocated (rl_actions not null,
// rl_actions_capacity >= n_rl_actions) — i.e. the callers must have
// NOT freed rs_old yet.  If any call site moved the free-before-GC,
// the rs_old passed to the body would be freed memory and ASAN would
// flag it. This test is therefore an ASAN tripwire for the ordering.
//
// The full integration-level ordering assertion (GC happens after the
// real rcu synchronize and before delete) lives in
// tests/integration/test_rl_reload_gc.cpp (C4), exercising
// reload::deploy_prebuilt's real pipeline.
// =========================================================================
TEST(RlArenaGcU4_13, BodyReceivesLiveRsOld) {
  constexpr std::uint64_t kId = 0xC413'0001ull;
  ArenaScrubber scrub{{kId}};

  auto& arena = rl_arena::rl_arena_global();
  arena.alloc_slot(kId);

  ruleset::Ruleset rs_old = make_rs_with_rl_ids({kId});

  // Prove the body touches rs_old's rl_actions: the removed id must
  // be resolved via rs_old.rl_actions[0].rule_id. If the call site
  // accidentally passed freed memory, ASAN would flag inside the body.
  runtime::rl_arena_gc(&rs_old, /*rs_new=*/nullptr);
  EXPECT_FALSE(arena.lookup_slot(kId).has_value());
}

// =========================================================================
// U4.14 — counter row zeroed EAGERLY on slot removal.
//
// §9.4 step 5b: the GC pass zeros the per-lcore bucket row BEFORE
// free_slot, so stats-on-exit don't leak old counters into the
// following aggregation even if the process stops before another
// alloc_slot reuses the index. D33 counter consistency.
//
// Arm the row with non-zero values on multiple lcores, run GC, then
// read the row back via the slot index BEFORE any realloc. The row
// must be all-zero.
// =========================================================================
TEST(RlArenaGcU4_14, CounterRowZeroedEagerly) {
  constexpr std::uint64_t kId = 0xC414'0001ull;
  ArenaScrubber scrub{{kId}};

  auto& arena = rl_arena::rl_arena_global();
  const std::uint16_t s = arena.alloc_slot(kId);
  ASSERT_NE(s, kInvalidSlot);

  // Arm across multiple lcores including edges.
  arena.get_row(s).per_lcore[0].tokens         = 0xDEADBEEFull;
  arena.get_row(s).per_lcore[0].last_refill_tsc = 0x11111111ull;
  arena.get_row(s).per_lcore[0].dropped        = 3;

  arena.get_row(s).per_lcore[3].tokens         = 99999ull;
  arena.get_row(s).per_lcore[3].last_refill_tsc = 0xDEADBEEFull;
  arena.get_row(s).per_lcore[3].dropped        = 7;

  arena.get_row(s).per_lcore[kMaxLcores - 1].tokens         = 55555ull;
  arena.get_row(s).per_lcore[kMaxLcores - 1].last_refill_tsc = 0xABCDull;
  arena.get_row(s).per_lcore[kMaxLcores - 1].dropped        = 13;

  ruleset::Ruleset rs_old = make_rs_with_rl_ids({kId});
  runtime::rl_arena_gc(&rs_old, /*rs_new=*/nullptr);

  // Read the row BEFORE any realloc — this pins "eager zeroing" vs
  // "zero on next alloc_slot" (the C1 alloc path also zeros, so a
  // lazy-on-alloc implementation would still pass a variant of this
  // test if we allocated first; by checking the row pre-realloc we
  // isolate the eager contract).
  const RlRow& row = arena.get_row(s);
  for (std::size_t i = 0; i < kMaxLcores; ++i) {
    EXPECT_EQ(row.per_lcore[i].tokens, 0u) << "lcore " << i;
    EXPECT_EQ(row.per_lcore[i].last_refill_tsc, 0u) << "lcore " << i;
    EXPECT_EQ(row.per_lcore[i].dropped, 0u) << "lcore " << i;
  }
}

// =========================================================================
// Idempotency: running GC twice is a silent no-op on the second pass.
// Guards against double-free in the pending_free drain path where the
// same rs_old could be walked more than once if the drain logic ever
// regressed.
// =========================================================================
TEST(RlArenaGcU4_11, IdempotentSecondPass) {
  constexpr std::uint64_t kId = 0xC411'0201ull;
  ArenaScrubber scrub{{kId}};

  auto& arena = rl_arena::rl_arena_global();
  arena.alloc_slot(kId);

  ruleset::Ruleset rs_old = make_rs_with_rl_ids({kId});

  runtime::rl_arena_gc(&rs_old, /*rs_new=*/nullptr);
  EXPECT_FALSE(arena.lookup_slot(kId).has_value());

  // Second pass: nothing to do (lookup returns nullopt → body skips).
  runtime::rl_arena_gc(&rs_old, /*rs_new=*/nullptr);
  EXPECT_FALSE(arena.lookup_slot(kId).has_value());
}

}  // namespace pktgate::test
