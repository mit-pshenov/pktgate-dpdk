// tests/unit/test_snapshot_sum.cpp
//
// M10 C1 — unit tests for the `build_snapshot` aggregation function.
//
// RED → GREEN coverage:
//   * U7.1 snapshot sum — single lcore.
//   * U7.2 snapshot sum — N=4 lcores.
//   * U7.6 per-port counter wrapping — rte_eth_stats mapping.
//
// Pure C++; no DPDK, no EAL. Tests construct fake LcoreCounterViews
// pointing at local uint64_t variables and fake PortStats inline.
// The TU links against `pktgate_telemetry` (DPDK-free lib per
// `grabli_m4c0_dpdk_free_core_library.md`).

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "src/ruleset/ruleset.h"
#include "src/telemetry/snapshot.h"

namespace {

using ::pktgate::ruleset::RuleCounter;
using ::pktgate::telemetry::build_snapshot;
using ::pktgate::telemetry::LcoreCounterView;
using ::pktgate::telemetry::PortStats;
using ::pktgate::telemetry::RuleIdent;
using ::pktgate::telemetry::Snapshot;

// ---------------------------------------------------------------
// U7.1 — Snapshot sum, single lcore.
//
// One lcore with per-rule row[0] = {matched=10, bytes=1500, drops=0,
// rl_drops=0} + two scalar WorkerCtx counters. build_snapshot must
// surface the values verbatim (single lcore -> no sum needed).
// ---------------------------------------------------------------

TEST(SnapshotSum, U7_1_SingleLcoreBasic) {
  // Allocate a counter row with 4 slots (matches a tiny ruleset).
  std::array<RuleCounter, 4> row{};
  row[0].matched_packets = 10;
  row[0].matched_bytes   = 1500;
  row[0].drops           = 0;
  row[0].rl_drops        = 0;

  std::uint64_t multiseg_drop = 3;
  std::uint64_t qinq_outer    = 7;

  LcoreCounterView view{
      .pkt_multiseg_drop_total = &multiseg_drop,
      .qinq_outer_only_total   = &qinq_outer,
      .counter_row             = row.data(),
      .n_slots                 = static_cast<std::uint32_t>(row.size()),
  };

  std::array<LcoreCounterView, 1> views{view};

  std::array<RuleIdent, 1> rules{RuleIdent{
      .rule_id      = 2001,
      .counter_slot = 0,
      .layer        = 3,
  }};

  Snapshot snap = build_snapshot(/*generation=*/1, views, rules, {});

  EXPECT_EQ(snap.generation, 1u);
  EXPECT_EQ(snap.pkt_multiseg_drop_total, 3u);
  EXPECT_EQ(snap.qinq_outer_only_total, 7u);

  ASSERT_EQ(snap.per_rule.size(), 1u);
  EXPECT_EQ(snap.per_rule[0].rule_id, 2001u);
  EXPECT_EQ(snap.per_rule[0].layer, 3u);
  EXPECT_EQ(snap.per_rule[0].matched_packets, 10u);
  EXPECT_EQ(snap.per_rule[0].matched_bytes, 1500u);
  EXPECT_EQ(snap.per_rule[0].drops, 0u);
  EXPECT_EQ(snap.per_rule[0].rl_drops, 0u);
}

// ---------------------------------------------------------------
// U7.2 — Snapshot sum, N=4 lcores.
//
// Four lcores, each with distinct per-rule values. Snapshot must
// produce element-wise sums.
// ---------------------------------------------------------------

TEST(SnapshotSum, U7_2_FourLcoresElementwiseSum) {
  constexpr std::size_t kNLcores = 4;
  constexpr std::uint32_t kSlots = 2;

  // Per-lcore row storage.
  std::array<std::array<RuleCounter, kSlots>, kNLcores> rows{};
  std::array<std::uint64_t, kNLcores> multiseg{};
  std::array<std::uint64_t, kNLcores> qinq{};

  // Populate: lcore i has matched_packets=(i+1)*10 on slot 0 and
  // matched_packets=(i+1)*100 on slot 1, drops=(i+1) on slot 0.
  // Scalar counters: multiseg=(i+1)*2, qinq=(i+1)*3.
  for (std::size_t i = 0; i < kNLcores; ++i) {
    rows[i][0].matched_packets = (i + 1) * 10;
    rows[i][0].matched_bytes   = (i + 1) * 1000;
    rows[i][0].drops           = (i + 1);
    rows[i][0].rl_drops        = 0;
    rows[i][1].matched_packets = (i + 1) * 100;
    rows[i][1].matched_bytes   = (i + 1) * 10'000;
    rows[i][1].drops           = 0;
    rows[i][1].rl_drops        = (i + 1) * 5;
    multiseg[i] = (i + 1) * 2;
    qinq[i]     = (i + 1) * 3;
  }

  std::array<LcoreCounterView, kNLcores> views{};
  for (std::size_t i = 0; i < kNLcores; ++i) {
    views[i] = LcoreCounterView{
        .pkt_multiseg_drop_total = &multiseg[i],
        .qinq_outer_only_total   = &qinq[i],
        .counter_row             = rows[i].data(),
        .n_slots                 = kSlots,
    };
  }

  std::array<RuleIdent, 2> rules{
      RuleIdent{.rule_id = 100, .counter_slot = 0, .layer = 2},
      RuleIdent{.rule_id = 200, .counter_slot = 1, .layer = 4},
  };

  Snapshot snap = build_snapshot(/*generation=*/42, views, rules, {});

  EXPECT_EQ(snap.generation, 42u);

  // 1+2+3+4 = 10 → *2 = 20 for multiseg, *3 = 30 for qinq.
  EXPECT_EQ(snap.pkt_multiseg_drop_total, 20u);
  EXPECT_EQ(snap.qinq_outer_only_total, 30u);

  ASSERT_EQ(snap.per_rule.size(), 2u);

  // Rule 100 (slot 0): matched_packets = sum (i+1)*10 = 10*10 = 100,
  // matched_bytes = sum (i+1)*1000 = 10*1000 = 10'000, drops = 1+2+3+4=10.
  const auto& r0 = snap.per_rule[0];
  EXPECT_EQ(r0.rule_id, 100u);
  EXPECT_EQ(r0.layer, 2u);
  EXPECT_EQ(r0.matched_packets, 100u);
  EXPECT_EQ(r0.matched_bytes, 10'000u);
  EXPECT_EQ(r0.drops, 10u);
  EXPECT_EQ(r0.rl_drops, 0u);

  // Rule 200 (slot 1): matched_packets = 10*100 = 1000,
  // matched_bytes = 10*10000 = 100'000, rl_drops = 10*5 = 50.
  const auto& r1 = snap.per_rule[1];
  EXPECT_EQ(r1.rule_id, 200u);
  EXPECT_EQ(r1.layer, 4u);
  EXPECT_EQ(r1.matched_packets, 1000u);
  EXPECT_EQ(r1.matched_bytes, 100'000u);
  EXPECT_EQ(r1.drops, 0u);
  EXPECT_EQ(r1.rl_drops, 50u);
}

// ---------------------------------------------------------------
// U7.2 corollary — rule with zero traffic across all lcores is
// omitted from `per_rule` (mirrors stats_on_exit convention at
// main.cpp:588 — no point in emitting zero-valued counter lines,
// keeps /metrics cardinality bounded to rules that actually hit).
// ---------------------------------------------------------------

TEST(SnapshotSum, U7_2_ZeroTrafficRuleOmitted) {
  std::array<RuleCounter, 2> row{};  // all zeros
  std::uint64_t multiseg = 0;
  std::uint64_t qinq = 0;

  LcoreCounterView view{
      .pkt_multiseg_drop_total = &multiseg,
      .qinq_outer_only_total   = &qinq,
      .counter_row             = row.data(),
      .n_slots                 = 2,
  };
  std::array<LcoreCounterView, 1> views{view};

  std::array<RuleIdent, 2> rules{
      RuleIdent{.rule_id = 1, .counter_slot = 0, .layer = 2},
      RuleIdent{.rule_id = 2, .counter_slot = 1, .layer = 3},
  };

  Snapshot snap = build_snapshot(/*generation=*/5, views, rules, {});

  EXPECT_EQ(snap.per_rule.size(), 0u)
      << "Rules with zero counters must be omitted (per main.cpp:588).";
}

// ---------------------------------------------------------------
// U7.6 — Per-port counter wrapping via PortStats.
//
// build_snapshot copies the caller-supplied PortStats array into
// `Snapshot::per_port`. The caller is responsible for translating
// rte_eth_stats → PortStats (DPDK-aware adapter, lives in the
// publisher); this test exercises the aggregation seam with a
// fake-populated array, matching the real production wiring.
// ---------------------------------------------------------------

TEST(SnapshotSum, U7_6_PerPortStatsWrappedAndCopied) {
  std::array<PortStats, 2> ports{};
  ports[0].ipackets  = 1'000'000;
  ports[0].opackets  = 999'900;
  ports[0].ibytes    = 1'500'000'000;
  ports[0].obytes    = 1'499'000'000;
  ports[0].imissed   = 42;
  ports[0].ierrors   = 7;
  ports[0].oerrors   = 1;
  ports[0].rx_nombuf = 13;

  ports[1].ipackets  = 123;
  ports[1].opackets  = 456;
  ports[1].ibytes    = 789'000;
  ports[1].obytes    = 654'000;
  ports[1].imissed   = 0;
  ports[1].ierrors   = 0;
  ports[1].oerrors   = 0;
  ports[1].rx_nombuf = 0;

  Snapshot snap = build_snapshot(/*generation=*/99,
                                 /*lcore_views=*/{},
                                 /*per_rule_ids=*/{},
                                 ports);

  ASSERT_EQ(snap.per_port.size(), 2u);
  EXPECT_EQ(snap.per_port[0].ipackets, 1'000'000u);
  EXPECT_EQ(snap.per_port[0].opackets, 999'900u);
  EXPECT_EQ(snap.per_port[0].ibytes, 1'500'000'000u);
  EXPECT_EQ(snap.per_port[0].obytes, 1'499'000'000u);
  EXPECT_EQ(snap.per_port[0].imissed, 42u);
  EXPECT_EQ(snap.per_port[0].ierrors, 7u);
  EXPECT_EQ(snap.per_port[0].oerrors, 1u);
  EXPECT_EQ(snap.per_port[0].rx_nombuf, 13u);

  EXPECT_EQ(snap.per_port[1].ipackets, 123u);
  EXPECT_EQ(snap.per_port[1].opackets, 456u);
  EXPECT_EQ(snap.per_port[1].ibytes, 789'000u);
  EXPECT_EQ(snap.per_port[1].obytes, 654'000u);
}

// ---------------------------------------------------------------
// U7.6 corollary — empty per-port array produces empty per_port.
// Avoids a future regression where the writer unconditionally pushes
// a sentinel entry.
// ---------------------------------------------------------------

TEST(SnapshotSum, U7_6_EmptyPortArrayProducesEmpty) {
  Snapshot snap = build_snapshot(/*generation=*/1,
                                 /*lcore_views=*/{},
                                 /*per_rule_ids=*/{},
                                 /*port_stats=*/{});
  EXPECT_EQ(snap.per_port.size(), 0u);
  EXPECT_EQ(snap.per_rule.size(), 0u);
  EXPECT_EQ(snap.pkt_multiseg_drop_total, 0u);
  EXPECT_EQ(snap.qinq_outer_only_total, 0u);
}

// ---------------------------------------------------------------
// Defensive — null pointers inside LcoreCounterView are tolerated
// (relaxed_load_u64 returns 0). A future WorkerCtx field rename
// that leaves the view pointer nullptr should not crash or race;
// it should silently contribute 0.
// ---------------------------------------------------------------

TEST(SnapshotSum, NullViewPointersTolerated) {
  LcoreCounterView view{};  // all nullptr
  std::array<LcoreCounterView, 1> views{view};

  Snapshot snap = build_snapshot(/*generation=*/1, views, {}, {});
  EXPECT_EQ(snap.pkt_multiseg_drop_total, 0u);
  EXPECT_EQ(snap.qinq_outer_only_total, 0u);
  EXPECT_EQ(snap.per_rule.size(), 0u);
}

// ---------------------------------------------------------------
// M14 C3 — D43 per-port backpressure counters.
//
// The per-port counter families `pktgate_tx_dropped_total{port}` and
// `pktgate_tx_burst_short_total{port}` are bumped by pktgate's own
// `tx_one()` / `redirect_drain()` wrappers in src/dataplane/
// action_dispatch.h. They are per-lcore scalars indexed by port_id,
// aggregated across lcores at publisher tick.
//
// U14.6 — tx_dropped_per_port round-trips through build_snapshot:
//         LcoreCounterView exposes a pointer+count; Snapshot has a
//         parallel std::vector<uint64_t> filled by element-wise sum.
// U14.7 — same contract for tx_burst_short_per_port.
// ---------------------------------------------------------------

TEST(SnapshotSum, U14_6_TxDroppedPerPortAggregated) {
  // Two lcores, four ports each. Per-lcore storage mimics the
  // std::array<uint64_t, RTE_MAX_ETHPORTS> field the WorkerCtx will
  // own in GREEN. Tests use a narrower 4-slot view to keep the
  // aggregate arithmetic easy to read.
  constexpr std::uint32_t kPorts = 4;

  std::array<std::uint64_t, kPorts> tx_dropped_lcore0{0, 5, 0, 10};
  std::array<std::uint64_t, kPorts> tx_dropped_lcore1{1, 0, 3, 20};

  LcoreCounterView v0{};
  v0.tx_dropped_per_port       = tx_dropped_lcore0.data();
  v0.tx_dropped_per_port_count = kPorts;

  LcoreCounterView v1{};
  v1.tx_dropped_per_port       = tx_dropped_lcore1.data();
  v1.tx_dropped_per_port_count = kPorts;

  std::array<LcoreCounterView, 2> views{v0, v1};

  Snapshot snap =
      build_snapshot(/*generation=*/7, views, /*per_rule_ids=*/{},
                     /*port_stats=*/{});

  ASSERT_EQ(snap.tx_dropped_per_port.size(), kPorts)
      << "Snapshot must expose a parallel tx_dropped_per_port vector";
  EXPECT_EQ(snap.tx_dropped_per_port[0], 1u);   // 0 + 1
  EXPECT_EQ(snap.tx_dropped_per_port[1], 5u);   // 5 + 0
  EXPECT_EQ(snap.tx_dropped_per_port[2], 3u);   // 0 + 3
  EXPECT_EQ(snap.tx_dropped_per_port[3], 30u);  // 10 + 20
}

TEST(SnapshotSum, U14_7_TxBurstShortPerPortAggregated) {
  constexpr std::uint32_t kPorts = 3;

  std::array<std::uint64_t, kPorts> burst_short_lcore0{2, 0, 7};
  std::array<std::uint64_t, kPorts> burst_short_lcore1{3, 4, 0};

  LcoreCounterView v0{};
  v0.tx_burst_short_per_port       = burst_short_lcore0.data();
  v0.tx_burst_short_per_port_count = kPorts;

  LcoreCounterView v1{};
  v1.tx_burst_short_per_port       = burst_short_lcore1.data();
  v1.tx_burst_short_per_port_count = kPorts;

  std::array<LcoreCounterView, 2> views{v0, v1};

  Snapshot snap =
      build_snapshot(/*generation=*/8, views, /*per_rule_ids=*/{},
                     /*port_stats=*/{});

  ASSERT_EQ(snap.tx_burst_short_per_port.size(), kPorts);
  EXPECT_EQ(snap.tx_burst_short_per_port[0], 5u);   // 2 + 3
  EXPECT_EQ(snap.tx_burst_short_per_port[1], 4u);   // 0 + 4
  EXPECT_EQ(snap.tx_burst_short_per_port[2], 7u);   // 7 + 0
}

// Defensive — null pointer on the new view fields contributes zero
// without growing the aggregate vector past counts actually seen.
TEST(SnapshotSum, U14_6_7_NullTxPerPortToleratedAndSurfaceNames) {
  LcoreCounterView view{};  // all nullptr
  std::array<LcoreCounterView, 1> views{view};

  Snapshot snap = build_snapshot(/*generation=*/1, views, {}, {});

  // Zero-sized when no view exposes per-port counter pointers.
  EXPECT_EQ(snap.tx_dropped_per_port.size(), 0u);
  EXPECT_EQ(snap.tx_burst_short_per_port.size(), 0u);

  // Base names must still surface through snapshot_metric_names() so
  // D33 routes them even with zero-valued ports.
  auto names = ::pktgate::telemetry::snapshot_metric_names(snap);
  EXPECT_TRUE(names.count("pktgate_tx_dropped_total") > 0)
      << "pktgate_tx_dropped_total missing from snapshot_metric_names";
  EXPECT_TRUE(names.count("pktgate_tx_burst_short_total") > 0)
      << "pktgate_tx_burst_short_total missing from snapshot_metric_names";
}

}  // namespace
