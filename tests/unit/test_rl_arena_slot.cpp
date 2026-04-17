// tests/unit/test_rl_arena_slot.cpp
//
// M9 C1 — RateLimitArena slot lifecycle (D24).
//
// Scope:
//   * U4.9    — first publish: alloc_slot picks a free index, marks it
//               live, row is zero-initialised, lookup returns same slot.
//   * U4.9b   — exhaustion sentinel: once max_rules slots are live, the
//               next alloc returns `kInvalidSlot` (0xFFFF); existing ids
//               still lookup to their slots.
//   * U4.10   — rule survives reload: alloc_slot(42), mutate bucket
//               state, alloc_slot(42) again — same slot, tokens preserved
//               (NOT re-zeroed).
//   * U4.11   — rule removed: alloc_slot(42), free_slot(42); slot no
//               longer live, id_to_slot no longer contains 42, lookup
//               returns nullopt; row storage vector still has
//               size()==max_rules (row memory NOT deallocated — D24).
//   * U4.12   — slot reuse clears row: alloc, mutate per_lcore buckets,
//               free, alloc a new id — the returned slot's row is
//               all-zero across every lcore (tokens, last_refill_tsc,
//               dropped).
//
// This TU links against pktgate_rl_ctl (control-plane arena — separate
// library from pktgate_rl math). That separation is load-bearing: U5.9
// asserts `unordered_map` / `id_to_slot` symbols are absent from the
// bucket-math archive `libpktgate_rl.a`. The arena's std::unordered_map
// must live in a different archive.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <optional>

#include "src/rl_arena/arena.h"
#include "src/rl_arena/rl_arena.h"

namespace {

using ::pktgate::rl_arena::kInvalidSlot;
using ::pktgate::rl_arena::kMaxLcores;
using ::pktgate::rl_arena::RateLimitArena;
using ::pktgate::rl_arena::RlRow;
using ::pktgate::rl_arena::TokenBucket;

// U4.9 — first publish: empty arena, alloc(42) returns a valid slot,
// lookup returns the same slot, slot_live is set, and the row is
// zero-initialised.
TEST(RlArenaSlotU4_9, FirstPublishAllocatesAndZeros) {
  RateLimitArena arena(/*max_rules=*/256);

  const std::uint16_t s = arena.alloc_slot(/*rule_id=*/42);
  ASSERT_NE(s, kInvalidSlot);
  EXPECT_LT(s, 256u);

  // lookup returns the same slot.
  const auto look = arena.lookup_slot(42);
  ASSERT_TRUE(look.has_value());
  EXPECT_EQ(*look, s);

  // slot_live bit is on.
  EXPECT_TRUE(arena.slot_live(s));

  // Row is zero-initialised across every lcore slot.
  const RlRow& row = arena.get_row(s);
  for (std::size_t i = 0; i < kMaxLcores; ++i) {
    EXPECT_EQ(row.per_lcore[i].tokens, 0u) << "lcore " << i;
    EXPECT_EQ(row.per_lcore[i].last_refill_tsc, 0u) << "lcore " << i;
    EXPECT_EQ(row.per_lcore[i].dropped, 0u) << "lcore " << i;
  }
}

// U4.9b — exhaustion: fill every slot, next alloc returns kInvalidSlot;
// previously allocated ids still lookup correctly.
TEST(RlArenaSlotU4_9b, ExhaustionReturnsInvalidSentinel) {
  constexpr std::uint16_t kMax = 8;
  RateLimitArena arena(kMax);

  for (std::uint64_t i = 0; i < kMax; ++i) {
    const std::uint16_t s = arena.alloc_slot(/*rule_id=*/100 + i);
    ASSERT_NE(s, kInvalidSlot) << "alloc #" << i << " unexpectedly failed";
  }
  // One more should fail.
  const std::uint16_t overflow = arena.alloc_slot(/*rule_id=*/999);
  EXPECT_EQ(overflow, kInvalidSlot);

  // Existing ids still resolve.
  for (std::uint64_t i = 0; i < kMax; ++i) {
    EXPECT_TRUE(arena.lookup_slot(100 + i).has_value())
        << "rule_id " << (100 + i) << " lost after exhaustion";
  }
  // Unknown id (the one that failed to alloc) must NOT be mapped.
  EXPECT_FALSE(arena.lookup_slot(999).has_value());
}

// U4.10 — rule survives reload: calling alloc_slot for an already-live
// rule_id returns the SAME slot and does NOT clear the bucket state.
// Tokens mutated between the two calls must still be there afterwards.
TEST(RlArenaSlotU4_10, SurvivesReloadTokensPreserved) {
  RateLimitArena arena(/*max_rules=*/256);

  const std::uint16_t s1 = arena.alloc_slot(/*rule_id=*/42);
  ASSERT_NE(s1, kInvalidSlot);

  // Simulate bucket activity on lcore index 3.
  arena.get_row(s1).per_lcore[3].tokens = 12345;
  arena.get_row(s1).per_lcore[3].last_refill_tsc = 9'999'999ULL;
  arena.get_row(s1).per_lcore[3].dropped = 7;

  // Second publish with same rule_id — the arena MUST return the same
  // slot and MUST NOT zero the row.
  const std::uint16_t s2 = arena.alloc_slot(/*rule_id=*/42);
  EXPECT_EQ(s2, s1);

  const RlRow& row = arena.get_row(s2);
  EXPECT_EQ(row.per_lcore[3].tokens, 12345u);
  EXPECT_EQ(row.per_lcore[3].last_refill_tsc, 9'999'999ULL);
  EXPECT_EQ(row.per_lcore[3].dropped, 7u);

  // Still just one entry in id_to_slot (observable via lookup).
  EXPECT_TRUE(arena.lookup_slot(42).has_value());
  EXPECT_TRUE(arena.slot_live(s1));
}

// U4.11 — rule removed: free_slot releases the slot index and drops
// id_to_slot entry; lookup returns nullopt; slot_live(s) is false;
// but the row storage vector still has size()==max_rules (D24: free
// slot, NOT free row).
TEST(RlArenaSlotU4_11, FreeSlotNotFreeRow) {
  RateLimitArena arena(/*max_rules=*/256);

  const std::uint16_t s = arena.alloc_slot(/*rule_id=*/42);
  ASSERT_NE(s, kInvalidSlot);

  // Mutate bucket so "row memory still allocated" is observable.
  arena.get_row(s).per_lcore[0].tokens = 42;

  arena.free_slot(/*rule_id=*/42);

  // Slot no longer live.
  EXPECT_FALSE(arena.slot_live(s));
  // id_to_slot no longer contains 42.
  EXPECT_FALSE(arena.lookup_slot(42).has_value());

  // Row vector still full size (D24 — free_slot, NOT free_row).
  EXPECT_EQ(arena.row_vector_size(), 256u);

  // Freeing an unknown id is a silent no-op — covers idempotency
  // expected by the GC path.
  arena.free_slot(/*rule_id=*/42);  // double-free must not crash
  arena.free_slot(/*rule_id=*/999);  // never allocated

  EXPECT_FALSE(arena.slot_live(s));
  EXPECT_EQ(arena.row_vector_size(), 256u);
}

// U4.12 — slot reuse clears row. alloc → mutate → free → alloc a fresh
// rule_id: the row at the returned slot must be fully zero on every
// lcore bucket. (The policy is "lowest-free-index" so the freed slot
// will be reused for the next alloc in this single-slot case.)
TEST(RlArenaSlotU4_12, SlotReuseClearsRow) {
  RateLimitArena arena(/*max_rules=*/256);

  const std::uint16_t s1 = arena.alloc_slot(/*rule_id=*/42);
  ASSERT_NE(s1, kInvalidSlot);

  // Scribble across multiple lcores.
  arena.get_row(s1).per_lcore[3].tokens = 99999;
  arena.get_row(s1).per_lcore[3].dropped = 7;
  arena.get_row(s1).per_lcore[3].last_refill_tsc = 123456789ULL;
  arena.get_row(s1).per_lcore[kMaxLcores - 1].tokens = 55555;
  arena.get_row(s1).per_lcore[kMaxLcores - 1].dropped = 3;

  arena.free_slot(/*rule_id=*/42);

  // Alloc a NEW rule_id. With lowest-free-index policy and only one
  // free slot (the one we just freed), the returned slot equals s1.
  // We don't assert the specific slot value — we assert the row at
  // the returned slot is all-zero.
  const std::uint16_t s2 = arena.alloc_slot(/*rule_id=*/777);
  ASSERT_NE(s2, kInvalidSlot);

  const RlRow& row = arena.get_row(s2);
  for (std::size_t i = 0; i < kMaxLcores; ++i) {
    EXPECT_EQ(row.per_lcore[i].tokens, 0u) << "lcore " << i;
    EXPECT_EQ(row.per_lcore[i].last_refill_tsc, 0u) << "lcore " << i;
    EXPECT_EQ(row.per_lcore[i].dropped, 0u) << "lcore " << i;
  }

  // And the old rule_id (42) is gone; 777 is present.
  EXPECT_FALSE(arena.lookup_slot(42).has_value());
  EXPECT_TRUE(arena.lookup_slot(777).has_value());
}

}  // namespace
