// tests/unit/test_rl_arena_tsan.cpp
//
// M9 C2 — extended U5.8 TSAN zero-atomic / zero-race assertion.
//
// The C0 U5.8 test body greps `libpktgate_rl.a` for banned symbols
// (std::atomic, fetch_add, lock cmpxchg, etc.). That's necessary but
// not sufficient: a future change could introduce a RACE without
// adding any of those symbols (plain non-atomic shared writes across
// threads). C2 extends the invariant with a runtime TSAN harness.
//
// Harness: two std::thread workers, each calling `rl_consume` against
// its own `per_lcore[]` slot of the SAME RlRow. If a bug made the
// bucket row itself shared (or a future change introduced a
// control-plane reference that workers dereferenced), TSAN would
// report a race. The test passes iff ThreadSanitizer's runtime
// observes zero races across the whole body — the dev-tsan ctest
// preset surfaces any race as a test failure via TSAN_OPTIONS
// `halt_on_error=1` (set globally in CMakePresets.json).
//
// This TU is EAL-free (pure C++ + pthreads), so it links against
// pktgate_rl_ctl and runs under the standard unit target. Under
// dev-asan this is a sanity check on the math; under dev-tsan it is
// the D1 runtime gate.

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <thread>

#include "src/rl_arena/arena.h"
#include "src/rl_arena/rl_arena.h"

namespace {

using ::pktgate::rl_arena::kInvalidSlot;
using ::pktgate::rl_arena::kMaxLcores;
using ::pktgate::rl_arena::RateLimitArena;
using ::pktgate::rl_arena::rl_consume;
using ::pktgate::rl_arena::RlRow;
using ::pktgate::rl_arena::TokenBucket;

// Deterministic fake TSC: monotonic per thread, no syscall. Injecting
// a plain counter keeps the test portable + independent of the host
// TSC frequency.
constexpr std::uint64_t kFakeTscHz = 2'000'000'000ULL;

// U5.8-extended — two std::threads mutating disjoint per_lcore[]
// slots of the same RlRow concurrently. D1 per-lcore isolation
// guarantees this is race-free; TSAN observes the invariant at
// runtime.
TEST(RlArenaTsanU5_8Ext, PerLcoreConcurrentConsumeNoRace) {
  RateLimitArena arena(/*max_rules=*/16);
  const std::uint16_t slot = arena.alloc_slot(/*rule_id=*/7);
  ASSERT_NE(slot, kInvalidSlot);

  auto& row = arena.get_row(slot);

  constexpr std::uint32_t kIters = 50'000;
  const std::uint64_t rate = 1'000'000'000ULL;
  const std::uint64_t burst = 10'000'000ULL;

  auto worker = [&](std::size_t lcore_slot, std::uint64_t tsc_start) {
    TokenBucket& bucket = row.per_lcore[lcore_slot];
    std::uint64_t now = tsc_start;
    for (std::uint32_t i = 0; i < kIters; ++i) {
      now += 1'000;  // 1 µs/pkt at the fake 2 GHz TSC
      (void)rl_consume(bucket, now, kFakeTscHz, /*pkt_len=*/100, rate,
                       burst, /*n_lcores=*/2);
    }
  };

  std::thread t0(worker, 0u, 1ULL);
  std::thread t1(worker, 1u, 1ULL);
  t0.join();
  t1.join();

  // Non-race observables: both per-lcore slots got real writes.
  EXPECT_NE(row.per_lcore[0].last_refill_tsc, 0u);
  EXPECT_NE(row.per_lcore[1].last_refill_tsc, 0u);
  // All other slots untouched.
  for (std::size_t i = 2; i < kMaxLcores; ++i) {
    EXPECT_EQ(row.per_lcore[i].last_refill_tsc, 0u) << "lcore slot " << i;
    EXPECT_EQ(row.per_lcore[i].tokens, 0u) << "lcore slot " << i;
    EXPECT_EQ(row.per_lcore[i].dropped, 0u) << "lcore slot " << i;
  }
}

}  // namespace
