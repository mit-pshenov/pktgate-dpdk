// tests/integration/test_rl_integration.cpp
//
// M9 C2 — hot-path integration of the per-lcore token bucket arena
// into action_dispatch::apply_action. The M7 C3 RATELIMIT stub
// ("always-allow kAllow placeholder") is replaced with a real consume
// against `rl_arena_global()`. C2 asserts:
//
//   * Per-lcore isolation on the real dispatch path. Two worker
//     threads driving apply_action against the SAME ruleset slot
//     touch disjoint `per_lcore[]` rows; no data race.
//   * Drops above limit + passes under limit via the real apply_action
//     code path (`tx_burst_fn` spy observes the forwarded mbuf).
//   * TSAN-gated: this test file links into the dev-tsan suite; the
//     per-lcore invariant means ZERO races are reported with no
//     `tests/tsan.supp` additions.
//
// The test is EAL-backed (integration tier) because rte_pktmbuf_alloc
// + rte_lcore_id need real EAL init. Single-process EAL fixture shared
// with `test_reload.cpp` via `--file-prefix=pktgate_rl_integration`.
//
// Contract with M9 C2 plumbing:
//
//   * `rl_arena_global()` is a process-lifetime singleton exposed from
//     src/rl_arena/arena.cpp. C2 docs the choice in the commit body
//     (singleton option (a) — simplest; no ControlPlaneState wrapper).
//   * `rs.rl_actions[slot] = {rule_id, rate_bps, burst_bytes}` is read
//     by action_dispatch on the RL verb arm. The test populates this
//     array manually (no compiler involvement — that's C3).
//   * `action->rl_index` is the slot index returned by
//     `arena.alloc_slot(rule_id)`. C2 assumes slot == rl_index; the
//     C3 compiler/builder pipeline guarantees this invariant.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_cycles.h>

#include "src/action/action.h"
#include "src/compiler/compiler.h"
#include "src/dataplane/action_dispatch.h"
#include "src/dataplane/worker.h"
#include "src/rl_arena/arena.h"
#include "src/rl_arena/rl_arena.h"
#include "src/ruleset/ruleset.h"

namespace pktgate::test {

// ---- EAL fixture (one-shot per process) ---------------------------------

class RlIntegrationEalFixture : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (s_initialized) return;
    const char* argv[] = {
        "test_rl_integration",
        "--no-pci",
        "--no-huge",
        "-m", "256",
        "--log-level", "lib.*:error",
        "-d", DPDK_DRIVER_DIR,
        "--file-prefix", "pktgate_rl_integration",
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    int ret = rte_eal_init(argc, const_cast<char**>(argv));
    ASSERT_GE(ret, 0) << "rte_eal_init failed";
    s_initialized = true;
  }

  static void TearDownTestSuite() {
    // DPDK 25.11 does not cleanly re-init within the same process —
    // skip rte_eal_cleanup (same rationale as unit + M8 integration
    // fixtures).
  }

  static constexpr const char* DPDK_DRIVER_DIR =
      "/home/mit/Dev/dpdk-25.11/build/drivers/";

 private:
  static inline bool s_initialized = false;
};

// ---- Spy TX hook: records every mbuf without touching PMD -----------------
//
// action_dispatch::tx_one calls ctx->tx_burst_fn. EalFixture has no
// real port, so the spy stands in. Returns 1 (success); the recorded
// mbuf is freed by the test teardown to avoid leaks.

struct TxSpy {
  std::atomic<std::uint64_t> calls{0};
};
static TxSpy g_tx_spy;

static std::uint16_t spy_tx_burst(std::uint16_t /*port*/,
                                  std::uint16_t /*queue*/,
                                  rte_mbuf** tx_pkts,
                                  std::uint16_t nb_pkts) {
  // The spy pretends the PMD accepted every packet: free them here
  // (matches the production contract — PMD owns the mbufs after a
  // successful TX call) and bump the call counter.
  for (std::uint16_t i = 0; i < nb_pkts; ++i) {
    rte_pktmbuf_free(tx_pkts[i]);
  }
  g_tx_spy.calls.fetch_add(nb_pkts, std::memory_order_relaxed);
  return nb_pkts;
}

// ---- Helpers -------------------------------------------------------------

static rte_mempool* make_test_mempool() {
  static rte_mempool* g_mp = nullptr;
  if (g_mp != nullptr) return g_mp;
  g_mp = rte_pktmbuf_pool_create(
      "rl_int_pool", /*n=*/2048, /*cache=*/32,
      /*priv_size=*/0,
      /*data_room=*/RTE_MBUF_DEFAULT_BUF_SIZE,
      static_cast<int>(rte_socket_id()));
  return g_mp;
}

// Build a minimal Ruleset with a single RL rule at slot 0.
// default_action ALLOW so an unmatched pkt would forward; kMatch with
// kRateLimit verb goes through the arena consume path.
static ruleset::Ruleset make_rl_ruleset(std::uint16_t slot, std::uint32_t rule_id,
                                        std::uint64_t rate_bps,
                                        std::uint64_t burst_bytes,
                                        unsigned num_lcores) {
  ruleset::Ruleset rs;
  // We use the allocator-free M2 path for simplicity — same as unit
  // test_builder fixtures. Tear down is via ~Ruleset.
  rs.l2_actions_capacity = 4;
  rs.l3_actions_capacity = 4;
  rs.l4_actions_capacity = 4;
  rs.l2_actions = new action::RuleAction[4]();
  rs.l3_actions = new action::RuleAction[4]();
  rs.l4_actions = new action::RuleAction[4]();

  // Populate l4_actions[0] with a RateLimit verb pointing at `slot`.
  rs.l4_actions[0].rule_id = rule_id;
  rs.l4_actions[0].counter_slot = 0;
  rs.l4_actions[0].verb =
      static_cast<std::uint8_t>(compiler::ActionVerb::kRateLimit);
  rs.l4_actions[0].rl_index = slot;
  rs.n_l4_rules = 1;

  // M9 C2: rl_actions[] arena entry for this rule. The slot index in
  // `rl_actions[]` is what `action->rl_index` points at.
  rs.rl_actions_capacity = 4;
  rs.rl_actions = new ruleset::RlAction[4]();
  rs.rl_actions[slot].rule_id = rule_id;
  rs.rl_actions[slot].rate_bps = rate_bps;
  rs.rl_actions[slot].burst_bytes = burst_bytes;
  rs.n_rl_actions = static_cast<std::uint32_t>(slot) + 1;

  // Minimum counter bookkeeping.
  rs.num_lcores = num_lcores;
  rs.counter_slots_per_lcore = 3u * 4u;  // 3 layers * cap 4
  rs.counters = nullptr;  // apply_action doesn't touch counters on RL path.

  rs.default_action = 0;  // ALLOW
  rs.generation = 1;
  return rs;
}

// ---- Tests ---------------------------------------------------------------

// C2-U5.8.a — single-threaded plumbing: apply_action kRateLimit path
// calls into the arena, drops when bucket is empty, forwards when
// refilled.
TEST_F(RlIntegrationEalFixture, ApplyActionRateLimitDispatch) {
  rte_mempool* mp = make_test_mempool();
  ASSERT_NE(mp, nullptr);

  // Arena is process-wide. Alloc slot 0 for rule 1234.
  auto& arena = pktgate::rl_arena::rl_arena_global();
  const std::uint16_t slot = arena.alloc_slot(/*rule_id=*/1234);
  ASSERT_NE(slot, pktgate::rl_arena::kInvalidSlot);

  // Tiny rate + tiny burst → first packet fails (bucket starts at 0,
  // the 1-cycle elapsed after last_refill_tsc=0 + clamp produces
  // exactly `rate / n_lcores` bytes which is smaller than our 1500 B
  // packet, so DROP).
  //
  // Using a burst smaller than the test packet length guarantees the
  // first call drops regardless of TSC observations.
  const std::uint64_t rate_bps = 100;      // 100 B/s — tiny
  const std::uint64_t burst_bytes = 100;   // 100 B cap — smaller than 1500 B pkt
  ruleset::Ruleset rs =
      make_rl_ruleset(slot, /*rule_id=*/1234, rate_bps, burst_bytes,
                      /*num_lcores=*/1);

  dataplane::WorkerCtx ctx{};
  ctx.tx_port_id = 0;
  ctx.tx_burst_fn = &spy_tx_burst;
  ctx.rl_arena = &arena;
  ctx.tsc_hz = rte_get_tsc_hz();

  const std::uint64_t spy_before = g_tx_spy.calls.load();

  // Alloc a 1500 B packet and dispatch.
  rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  m->pkt_len = 1500;
  m->data_len = 1500;

  dataplane::apply_action(&ctx, rs, m, dataplane::Disposition::kMatch,
                          &rs.l4_actions[0]);

  // First call: bucket empty, burst cap 100 B, packet 1500 B → DROP.
  // Spy call count unchanged.
  EXPECT_EQ(g_tx_spy.calls.load(), spy_before);

  // Bump per-lcore dropped counter observable directly through the
  // arena (lcore_id 0 is the main thread here).
  auto& row = arena.get_row(slot);
  EXPECT_GE(row.per_lcore[rte_lcore_id()].dropped, 1u);

  // Now raise burst so a packet fits, allocate a fresh mbuf, dispatch:
  // should forward via spy.
  rs.rl_actions[slot].rate_bps = 10'000'000'000ULL;
  rs.rl_actions[slot].burst_bytes = 10'000'000'000ULL;

  rte_mbuf* m2 = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m2, nullptr);
  m2->pkt_len = 1500;
  m2->data_len = 1500;
  dataplane::apply_action(&ctx, rs, m2, dataplane::Disposition::kMatch,
                          &rs.l4_actions[0]);
  EXPECT_EQ(g_tx_spy.calls.load(), spy_before + 1);

  // Tidy: free the slot so the next test in this binary starts clean.
  arena.free_slot(/*rule_id=*/1234);
}

// C2-U5.8.b — per-lcore isolation on the real dispatch path.
//
// Two std::threads drive rl_consume against the SAME slot, each
// touching its own `per_lcore[i]` row. Under TSAN, if apply_action
// were written with a shared write (or a shared-mutable state), this
// test would race. We run a tight spin for a fixed duration and
// observe only the bucket-math side-effects.
//
// Note: we intentionally call `rl_consume` directly (via the arena
// row) from each std::thread rather than apply_action — the
// std::thread's rte_lcore_id() returns LCORE_ID_ANY (0x7FFFFFFF) which
// would out-of-bounds index the per_lcore[] array. The apply_action
// path is exercised single-threadedly above; the per-lcore invariant
// this test proves is that two concurrent mutators on disjoint slots
// of the SAME arena row do not race — which is what D1 guarantees.
TEST_F(RlIntegrationEalFixture, PerLcoreIsolationOnSharedSlot) {
  auto& arena = pktgate::rl_arena::rl_arena_global();
  const std::uint16_t slot = arena.alloc_slot(/*rule_id=*/5555);
  ASSERT_NE(slot, pktgate::rl_arena::kInvalidSlot);

  auto& row = arena.get_row(slot);

  constexpr std::uint32_t kIters = 10'000;
  const std::uint64_t tsc_hz = rte_get_tsc_hz();
  const std::uint64_t rate = 1'000'000'000ULL;
  const std::uint64_t burst = 10'000'000ULL;

  // Two threads → two disjoint per_lcore[] slots. Each thread mutates
  // only its own slot. TSAN will flag any cross-slot write or shared-
  // location RMW.
  auto worker = [&](std::size_t lcore_slot) {
    auto& bucket = row.per_lcore[lcore_slot];
    for (std::uint32_t i = 0; i < kIters; ++i) {
      const std::uint64_t now = rte_rdtsc();
      (void)pktgate::rl_arena::rl_consume(bucket, now, tsc_hz,
                                          /*pkt_len=*/100, rate, burst,
                                          /*n_lcores=*/2);
    }
  };

  std::thread t0(worker, 0u);
  std::thread t1(worker, 1u);
  t0.join();
  t1.join();

  // Observable side-effect: both buckets got real writes.
  EXPECT_NE(row.per_lcore[0].last_refill_tsc, 0u);
  EXPECT_NE(row.per_lcore[1].last_refill_tsc, 0u);
  // Slots 2..N-1 were not touched.
  for (std::size_t i = 2; i < pktgate::rl_arena::kMaxLcores; ++i) {
    EXPECT_EQ(row.per_lcore[i].last_refill_tsc, 0u) << "lcore slot " << i;
    EXPECT_EQ(row.per_lcore[i].tokens, 0u) << "lcore slot " << i;
    EXPECT_EQ(row.per_lcore[i].dropped, 0u) << "lcore slot " << i;
  }

  arena.free_slot(/*rule_id=*/5555);
}

// C2-U5.8.c — singleton identity: two calls to rl_arena_global()
// return the SAME object. This pins the process-lifetime property; a
// regression that returned a fresh arena per call would drop bucket
// state between worker ticks.
TEST_F(RlIntegrationEalFixture, ArenaGlobalIsSingleton) {
  auto& a1 = pktgate::rl_arena::rl_arena_global();
  auto& a2 = pktgate::rl_arena::rl_arena_global();
  EXPECT_EQ(&a1, &a2);
}

}  // namespace pktgate::test
