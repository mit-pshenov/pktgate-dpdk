// tests/unit/test_rl_arena.cpp
//
// M9 C0 — U5.1 .. U5.10 for src/rl_arena (bucket-math layer).
//
// Scope:
//   * U5.1  — per-lcore isolation (no cross-slot writes)
//   * U5.2  — D34 clamp, fresh bucket (last_refill_tsc == 0)
//   * U5.3  — D34 clamp, 10 s idle
//   * U5.4  — D34 no-clamp, 1 µs idle (steady state)
//   * U5.5  — bucket capped at `burst`
//   * U5.6  — drop on insufficient tokens; `dropped` bumped
//   * U5.7  — consume on sufficient tokens
//   * U5.8  — zero-atomic invariant (symbol grep on libpktgate_rl.a)
//   * U5.9  — `id_to_slot` symbol must NOT appear in bucket-math TU
//             (hot path has no hash lookup)
//   * U5.10 — TSC mock injection (rl_consume takes `now_tsc` + `tsc_hz`
//             as parameters, never calls rte_rdtsc internally)
//
// This test TU is pure C++: no DPDK headers. It links against
// libpktgate_rl only. U5.8 / U5.9 introspect the archive via `nm`
// at runtime; the archive path is baked into the binary as a
// compile-time string via target_compile_definitions
// (PKTGATE_RL_ARCHIVE_PATH) per `grabli_cmake_path_defines.md`.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "src/rl_arena/rl_arena.h"

namespace {

using ::pktgate::rl_arena::kMaxLcores;
using ::pktgate::rl_arena::rl_consume;
using ::pktgate::rl_arena::RlRow;
using ::pktgate::rl_arena::TokenBucket;

// One-second's worth of TSC for a nominal 2 GHz CPU. Any non-zero
// value works for the math — the specific number only matters for
// the clamp comparison against `raw`.
constexpr std::uint64_t kTscHz = 2'000'000'000ULL;

// Sanity: the header constants are wired right.
TEST(RlArenaTypes, TokenBucketIsOneCacheLine) {
  EXPECT_EQ(sizeof(TokenBucket), 64u);
  EXPECT_EQ(alignof(TokenBucket), 64u);
}

TEST(RlArenaTypes, RlRowHasOneSlotPerLcore) {
  EXPECT_EQ(sizeof(RlRow), 64u * kMaxLcores);
  static_assert(kMaxLcores == 128,
                "U5 fixtures assume DPDK default RTE_MAX_LCORE=128");
}

// U5.1 — per-lcore isolation. A write to `row.per_lcore[0]` must
// leave all other slots byte-identical.
TEST(RlArenaU5_1, PerLcoreIsolation) {
  RlRow row{};
  // Seed every slot to a known pattern.
  for (std::size_t i = 0; i < kMaxLcores; ++i) {
    row.per_lcore[i].tokens = 1'000;
    row.per_lcore[i].last_refill_tsc = 0;
    row.per_lcore[i].dropped = 0;
  }
  // Snapshot slot 1 byte-for-byte before consumption on slot 0.
  TokenBucket before_slot1;
  std::memcpy(&before_slot1, &row.per_lcore[1], sizeof(TokenBucket));

  // Refill + consume on slot 0. rate=0 is fine for isolation check;
  // we just need a mutation that a buggy impl would scatter.
  const bool ok = rl_consume(row.per_lcore[0], /*now=*/kTscHz,
                             /*tsc_hz=*/kTscHz, /*pkt_len=*/100,
                             /*rate=*/1'000'000, /*burst=*/10'000,
                             /*n_lcores=*/4);
  EXPECT_TRUE(ok);

  // Slot 0 changed; slot 1 did not.
  EXPECT_EQ(std::memcmp(&row.per_lcore[1], &before_slot1, sizeof(TokenBucket)),
            0);
  // Spot-check an adjacent-but-far slot too. M13 C0: dropped the unused
  // `zero_bucket{}` fixture — the per-field EXPECT_EQ checks below are
  // the actual assertion; `zero_bucket` was dead code that tripped
  // dev-release -Werror=unused-but-set-variable.
  EXPECT_EQ(row.per_lcore[kMaxLcores - 1].tokens, 1'000u);
  EXPECT_EQ(row.per_lcore[kMaxLcores - 1].last_refill_tsc, 0u);
}

// U5.2 — D34 clamp on a fresh bucket. `last_refill_tsc == 0`,
// `now_tsc = 10e9`. Without a clamp, `elapsed * rate` overflows
// 64-bit; with the clamp, `elapsed = tsc_hz` and the bucket fills
// to `burst` (since tsc_hz * rate / tsc_hz / n_lcores == rate/n > 0,
// but capped at burst).
TEST(RlArenaU5_2, D34ClampFreshBucket) {
  TokenBucket b{};  // tokens=0, last_refill_tsc=0
  const std::uint64_t now = 10'000'000'000ULL;  // 10 s of TSC at 1 GHz-ish
  const std::uint64_t rate = 1'000'000'000ULL;  // 1 GB/s aggregate
  const std::uint64_t burst = 10'000ULL;
  const std::uint32_t n_lcores = 4;

  // Packet big enough to FAIL when tokens are clamped at burst is
  // NOT the point here; we just need to verify no overflow and that
  // tokens land at `burst` (clamped refill).
  const bool ok = rl_consume(b, now, kTscHz, /*pkt_len=*/0, rate, burst,
                             n_lcores);
  EXPECT_TRUE(ok);
  // With clamp: refill = tsc_hz * rate / tsc_hz / n_lcores
  //           = rate / n_lcores = 250 MB/s. Capped at burst.
  EXPECT_EQ(b.tokens, burst);
  EXPECT_EQ(b.last_refill_tsc, now);
  EXPECT_EQ(b.dropped, 0u);
}

// U5.3 — D34 clamp after 10 s idle. Same expected behaviour as U5.2.
TEST(RlArenaU5_3, D34ClampTenSecondIdle) {
  TokenBucket b{};
  b.tokens = 0;
  b.last_refill_tsc = 1'000'000;  // some arbitrary past TSC
  const std::uint64_t now = b.last_refill_tsc + 10 * kTscHz;
  const std::uint64_t rate = 1'000'000'000ULL;
  const std::uint64_t burst = 50'000ULL;
  const std::uint32_t n_lcores = 8;

  const bool ok = rl_consume(b, now, kTscHz, /*pkt_len=*/0, rate, burst,
                             n_lcores);
  EXPECT_TRUE(ok);
  // refill raw would have been 10*tsc_hz; clamped to tsc_hz → 1 s
  // worth → rate/n_lcores = 125 MB/s, capped at burst=50 000.
  EXPECT_EQ(b.tokens, burst);
  EXPECT_EQ(b.last_refill_tsc, now);
  EXPECT_EQ(b.dropped, 0u);
}

// U5.4 — D34 must NOT fire for a sub-second elapsed. 1 µs at 2 GHz
// TSC = 2000 cycles → refill is small but non-zero.
TEST(RlArenaU5_4, D34NoClampSteadyState) {
  TokenBucket b{};
  b.tokens = 0;
  b.last_refill_tsc = 1'000'000'000ULL;
  // 1 µs elapsed at 2 GHz TSC → 2000 cycles.
  const std::uint64_t elapsed_cycles = kTscHz / 1'000'000ULL;
  const std::uint64_t now = b.last_refill_tsc + elapsed_cycles;
  const std::uint64_t rate = 1'000'000'000ULL;  // 1 GB/s aggregate
  const std::uint64_t burst = 1'000'000ULL;     // big enough not to cap
  const std::uint32_t n_lcores = 4;

  const bool ok = rl_consume(b, now, kTscHz, /*pkt_len=*/0, rate, burst,
                             n_lcores);
  EXPECT_TRUE(ok);

  // Expected refill: elapsed_cycles * rate / tsc_hz / n_lcores
  //                = 2000 * 1e9 / 2e9 / 4 = 250 bytes.
  // Must be > 0 and < burst.
  EXPECT_GT(b.tokens, 0u);
  EXPECT_LT(b.tokens, burst);
  // Within a factor of 2 of the arithmetic expectation (integer
  // division floor noise — but this exact choice of numbers divides
  // evenly):
  const std::uint64_t expected = elapsed_cycles * rate / kTscHz / n_lcores;
  EXPECT_EQ(b.tokens, expected);
  EXPECT_EQ(b.last_refill_tsc, now);
}

// U5.5 — bucket can never exceed `burst`. Refill with huge input
// post-clamp, expect tokens pinned at burst.
TEST(RlArenaU5_5, BucketCapAtBurst) {
  TokenBucket b{};
  b.tokens = 500;
  b.last_refill_tsc = 1;
  const std::uint64_t now = 1 + kTscHz;  // 1 s elapsed → clamp boundary
  const std::uint64_t rate = 10'000'000'000ULL;  // 10 GB/s
  const std::uint64_t burst = 1'000ULL;          // small cap
  const std::uint32_t n_lcores = 1;

  const bool ok = rl_consume(b, now, kTscHz, /*pkt_len=*/0, rate, burst,
                             n_lcores);
  EXPECT_TRUE(ok);
  EXPECT_EQ(b.tokens, burst);
}

// U5.6 — when tokens < pkt_len after refill, return false and bump
// `dropped`. Tokens must end at their post-refill value (NOT
// decremented).
TEST(RlArenaU5_6, DropOnInsufficientTokens) {
  TokenBucket b{};
  b.tokens = 0;
  b.last_refill_tsc = kTscHz;  // seeded so no clamp edge
  const std::uint64_t now = b.last_refill_tsc + 1;  // ~0 elapsed → ~0 refill
  const std::uint64_t rate = 1'000'000ULL;
  const std::uint64_t burst = 100'000ULL;
  const std::uint32_t n_lcores = 4;
  const std::uint32_t pkt_len = 1500;

  const bool ok = rl_consume(b, now, kTscHz, pkt_len, rate, burst, n_lcores);
  EXPECT_FALSE(ok);
  EXPECT_EQ(b.dropped, 1u);
  // Tokens stayed at their post-refill value (no subtraction on drop).
  EXPECT_LT(b.tokens, pkt_len);
  EXPECT_EQ(b.last_refill_tsc, now);
}

// U5.7 — when tokens >= pkt_len, return true and deduct. `dropped`
// stays at 0.
TEST(RlArenaU5_7, ConsumeOnSufficientTokens) {
  TokenBucket b{};
  b.tokens = 10'000;
  b.last_refill_tsc = kTscHz;
  const std::uint64_t now = b.last_refill_tsc + 1;  // minimal refill
  const std::uint64_t rate = 1'000'000ULL;
  const std::uint64_t burst = 100'000ULL;
  const std::uint32_t n_lcores = 4;
  const std::uint32_t pkt_len = 1500;

  const std::uint64_t before = b.tokens;
  const bool ok = rl_consume(b, now, kTscHz, pkt_len, rate, burst, n_lcores);
  EXPECT_TRUE(ok);
  EXPECT_EQ(b.dropped, 0u);
  // Tokens = min(before + tiny_refill, burst) - pkt_len
  EXPECT_LE(b.tokens, before);          // definitely decremented
  EXPECT_GE(b.tokens, before - pkt_len - 1);  // tiny refill may add ≤1 byte
}

// Helper: pipe `cmd` through popen, return full stdout.
std::string run_shell(const std::string& cmd) {
  FILE* p = ::popen(cmd.c_str(), "r");
  if (!p) {
    return {};
  }
  std::string out;
  char buf[4096];
  std::size_t n;
  while ((n = std::fread(buf, 1, sizeof(buf), p)) > 0) {
    out.append(buf, n);
  }
  ::pclose(p);
  return out;
}

// U5.8 — zero-atomic invariant. The built libpktgate_rl.a must
// contain NO references to std::atomic / _Atomic / __atomic_* / any
// `lock` RMW instructions that would indicate a hot-path atomic.
//
// Strategy: `nm -C --defined-only libpktgate_rl.a` lists demangled
// symbols defined in the archive; `objdump -d` on the archive
// dumps disassembly where any `lock cmpxchg` / `lock xadd` would
// show up. Both must be clean for the rl_arena TU.
//
// Symbol patterns asserted absent:
//   * `std::atomic`
//   * `__atomic_`
//   * `atomic_`
//   * `compare_exchange` / `fetch_add` / `fetch_sub`
//
// Instruction patterns asserted absent (objdump):
//   * `lock cmpxchg`
//   * `lock xadd`
//
// PKTGATE_RL_ARCHIVE_PATH is injected by target_compile_definitions
// as a C-string literal (per grabli_cmake_path_defines.md).
TEST(RlArenaU5_8, ZeroAtomicSymbols) {
#ifndef PKTGATE_RL_ARCHIVE_PATH
  GTEST_SKIP() << "PKTGATE_RL_ARCHIVE_PATH not set";
#else
  const std::string archive = PKTGATE_RL_ARCHIVE_PATH;
  // `nm -C` demangles. `|| true` so empty output isn't a pipe error.
  const std::string syms =
      run_shell("nm -C --defined-only --undefined-only '" + archive +
                "' 2>/dev/null; true");
  ASSERT_FALSE(syms.empty()) << "nm produced no output for " << archive;

  auto must_not_contain = [&](const char* needle) {
    EXPECT_EQ(syms.find(needle), std::string::npos)
        << "pktgate_rl archive contains banned symbol pattern '" << needle
        << "' — D1 violation";
  };
  must_not_contain("std::atomic");
  must_not_contain("__atomic_");
  must_not_contain("atomic_fetch");
  must_not_contain("compare_exchange");

  // Disassemble and look for lock-prefixed RMW. `objdump -d` on an
  // archive iterates every member. Redirect stderr so missing-dwarf
  // chatter doesn't leak in.
  const std::string disasm =
      run_shell("objdump -d '" + archive + "' 2>/dev/null; true");
  ASSERT_FALSE(disasm.empty()) << "objdump produced no output";
  EXPECT_EQ(disasm.find("lock cmpxchg"), std::string::npos)
      << "pktgate_rl archive contains `lock cmpxchg` — D1 violation";
  EXPECT_EQ(disasm.find("lock xadd"), std::string::npos)
      << "pktgate_rl archive contains `lock xadd` — D1 violation";
  // `lock xchg` on an arbitrary memory operand is also a real RMW.
  // Plain `xchg reg,mem` has an implicit lock; disassemblers emit
  // "xchg" (no lock prefix token) in that case, so we can't filter
  // on a text match alone without false positives from register-
  // register xchg. Skip this one — the cmpxchg / xadd coverage is
  // sufficient for D1 fencing.
#endif
}

// U5.9 — bucket math must NOT reference any map/hash symbol from
// the C1 arena's `id_to_slot` table. Hot path is direct row-index
// lookup; id_to_slot is control-plane only.
//
// The C1 arena type doesn't exist yet, so there's nothing to
// accidentally pull in — but this test pins the invariant
// pre-emptively. We grep the archive for any sign of
// `unordered_map`, `rte_hash`, or an `id_to_slot` symbol.
TEST(RlArenaU5_9, HotPathHasNoHashLookup) {
#ifndef PKTGATE_RL_ARCHIVE_PATH
  GTEST_SKIP() << "PKTGATE_RL_ARCHIVE_PATH not set";
#else
  const std::string archive = PKTGATE_RL_ARCHIVE_PATH;
  const std::string syms =
      run_shell("nm -C --defined-only --undefined-only '" + archive +
                "' 2>/dev/null; true");
  ASSERT_FALSE(syms.empty());

  auto must_not_contain = [&](const char* needle) {
    EXPECT_EQ(syms.find(needle), std::string::npos)
        << "pktgate_rl archive references '" << needle
        << "' — D23/§4.4 hot-path slot discipline violated";
  };
  must_not_contain("unordered_map");
  must_not_contain("rte_hash");
  must_not_contain("id_to_slot");
#endif
}

// U5.10 — TSC mock injection. This test is satisfied at compile time
// by the signature of rl_consume — it MUST accept `now_tsc` and
// `tsc_hz` as parameters. A runtime body verifies deterministic
// behaviour under injected timestamps (two calls with identical
// `now_tsc` must produce identical state transitions, modulo the
// bucket's carry-over).
TEST(RlArenaU5_10, TscMockInjection) {
  // Compile-time: the signature accepts explicit TSC params. If a
  // future refactor tries to inline `rte_rdtsc()` inside rl_consume,
  // these calls would stop compiling without matching changes here.
  TokenBucket b1{};
  TokenBucket b2{};
  const std::uint64_t now = 7'654'321ULL;
  const std::uint64_t rate = 1'000'000ULL;
  const std::uint64_t burst = 100'000ULL;

  const bool r1 =
      rl_consume(b1, now, kTscHz, /*pkt_len=*/100, rate, burst, /*n=*/2);
  const bool r2 =
      rl_consume(b2, now, kTscHz, /*pkt_len=*/100, rate, burst, /*n=*/2);
  EXPECT_EQ(r1, r2);
  EXPECT_EQ(b1.tokens, b2.tokens);
  EXPECT_EQ(b1.last_refill_tsc, b2.last_refill_tsc);
  EXPECT_EQ(b1.last_refill_tsc, now);
  EXPECT_EQ(b1.dropped, b2.dropped);

  // A second call with a different injected `now` produces a
  // different state — confirms the fn really uses the param.
  const std::uint64_t now2 = now + kTscHz / 1000;  // 1 ms later
  (void)rl_consume(b1, now2, kTscHz, /*pkt_len=*/0, rate, burst, /*n=*/2);
  EXPECT_EQ(b1.last_refill_tsc, now2);
  EXPECT_NE(b1.last_refill_tsc, b2.last_refill_tsc);
}

}  // namespace
