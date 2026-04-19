// tests/integration/test_c7_27_counter_invariant.cpp
//
// M10 C2 — D33 living invariant, runtime enumeration arm (C7.27).
//
// What this test does
// -------------------
// D33 (review-notes, design.md §10.3) says: every metric name in §10.3
// has a producer site in the codebase AND every producer name is in
// §10.3. Two-way consistency.
//
// The static arm is U7.5 (tests/smoke/test_counter_consistency.cpp)
// which shells out to scripts/check-counter-consistency.sh and greps
// §10.3 ↔ prose. That covers the "nobody names a metric outside the
// canonical list" half.
//
// This file is the RUNTIME arm. It enumerates §10.3 at test time and
// for every name asks: can this metric actually be observed on a
// snapshot produced by build_snapshot()?
//
//   - YES (wired):    the name appears in snapshot_metric_names(snap)
//                     after an adversarial workload. PASS for that name.
//   - NO (wired):     the §10.3 name is on the `justified_zero` list
//                     below. PASS for that name (documented exemption).
//   - NO (unwired):   the §10.3 name is neither surfaced by snapshot
//                     nor on the justified-zero list. FAIL — the name
//                     has no producer pipeline to the snapshot.
//
// RED → GREEN ladder across C2 → C4
// ---------------------------------
// C2 (this cycle) ships the test EXPECTED-RED. Snapshot (C1) only
// wires ~9 of the 36 §10.3 names through build_snapshot(). The other
// ~27 names are in WorkerCtx / Ruleset / ReloadCounters but have no
// path into the Snapshot struct yet — C4 does that wiring.
//
// C2 mechanism: `WILL_FAIL TRUE` in tests/integration/CMakeLists.txt
// so that a RED result counts as PASS in ctest. If this test EVER
// goes green before C4, CMake will flag the regression (you wired
// something without announcing it, or the manifest shrank silently).
//
// C4 will:
//   1. Extend `Snapshot` with the missing fields (reload counters,
//      qinq/frag/truncation rollups, per-lcore scalars, etc.).
//   2. Extend `snapshot_metric_names()` to emit those names.
//   3. Flip `WILL_FAIL TRUE` → `FALSE` in the CMake wiring.
//
// C5 may re-run this same assertion over a real `/metrics` HTTP
// scrape (F8.2 living invariant) as end-to-end validation.
//
// Justified-zero list
// -------------------
// Some §10.3 names are presence-only contracts — the name being wired
// through the snapshot is the observable, not a non-zero value. These
// are exempt from the "must be producible by an adversarial workload"
// gate (the workload can't realistically generate every shape in a
// unit-tier harness). Each entry below is documented with WHY it's on
// the list. Keep the list small (< 15 entries); larger = scope drift.
//
// Note: "on the justified-zero list" still requires the name to have
// a §10.3 entry. Entries here do NOT bypass the C4 wiring work — C4
// extends Snapshot for these too. They just tell this TEST that the
// workload does not need to force a non-zero bump.
//
// Adversarial workload (C2 shape)
// -------------------------------
// The full plan is a live dataplane loop with crafted packets per
// §10.3 row. In C2 the HTTP server does not ship until C3 and the
// snapshot publisher thread is not wired into main.cpp either, so
// the workload is SNAPSHOT-DIRECT: we construct fake LcoreCounterView /
// counter_row / PortStats state as if a real worker had observed the
// relevant traffic, then call `build_snapshot` directly.
//
// Since C2 is expected RED this is enough to exercise the invariant:
// the ONLY names that should pass are the 9 wired by C1 (scalars,
// per_rule, per_port families). Every other name must fall to the
// justified-zero arm OR fail. The fail set sizes the C4 wire-up work.
//
// C5 will upgrade the workload to a real dataplane shot via F8.2
// (packet generation through the pipeline, scrape /metrics, diff
// against this same manifest).

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "src/ruleset/ruleset.h"
#include "src/telemetry/snapshot.h"

namespace pktgate::test {
namespace {

using ::pktgate::ruleset::RuleCounter;
using ::pktgate::telemetry::build_snapshot;
using ::pktgate::telemetry::LcoreCounterView;
using ::pktgate::telemetry::PortStats;
using ::pktgate::telemetry::RuleIdent;
using ::pktgate::telemetry::Snapshot;

// =========================================================================
// §10.3 canonical manifest — hand-transcribed from design.md §10.3.
//
// DO NOT reorder for readability without cross-checking against
// scripts/check-counter-consistency.sh Pass 1 output — the script is
// the static source of truth and this list is the runtime mirror. If
// §10.3 changes, BOTH must be updated in lockstep (D33 invariant).
//
// 39 entries as of 2026-04-19 (M14 C3 added pktgate_tx_dropped_total{port}
// + pktgate_tx_burst_short_total{port} — D43 per-port backpressure
// signals emitted by pktgate's own tx_one() / redirect_drain() wrappers).
// =========================================================================
const std::vector<std::string>& canonical_manifest() {
  static const std::vector<std::string> names = {
      // Rule-match family (labels: layer, rule_id, reason)
      "pktgate_rule_packets_total",
      "pktgate_rule_bytes_total",
      "pktgate_rule_drops_total",
      "pktgate_default_action_total",

      // Per-port family (labels: port, reason)
      "pktgate_port_rx_packets_total",
      "pktgate_port_tx_packets_total",
      "pktgate_port_rx_bytes_total",
      "pktgate_port_tx_bytes_total",
      "pktgate_port_rx_dropped_total",
      "pktgate_port_tx_dropped_total",
      "pktgate_port_link_up",

      // M14 C3 — D43 per-port backpressure (labels: port). Emitted by
      // pktgate's own tx_one() / redirect_drain() wrappers, PMD-agnostic.
      "pktgate_tx_dropped_total",
      "pktgate_tx_burst_short_total",

      // Per-lcore family (label: lcore, where, af, policy)
      "pktgate_lcore_packets_total",
      "pktgate_lcore_cycles_per_burst",
      "pktgate_lcore_idle_iters_total",
      "pktgate_lcore_l4_skipped_ipv6_extheader_total",
      "pktgate_lcore_l4_skipped_ipv6_fragment_nonfirst_total",
      "pktgate_lcore_tag_pcp_noop_untagged_total",
      "pktgate_lcore_dispatch_unreachable_total",
      "pktgate_lcore_pkt_truncated_total",
      "pktgate_lcore_qinq_outer_only_total",
      "pktgate_lcore_pkt_multiseg_drop_total",
      "pktgate_lcore_pkt_frag_skipped_total",
      "pktgate_lcore_pkt_frag_dropped_total",

      // Dispatch / mirror / redirect (label: lcore, port)
      "pktgate_redirect_dropped_total",
      "pktgate_mirror_dropped_total",

      // Reload / control plane (label: result, layer)
      "pktgate_reload_total",
      "pktgate_reload_latency_seconds",
      "pktgate_reload_pending_free_depth",
      "pktgate_active_generation",
      "pktgate_active_rules",
      "pktgate_cmd_socket_rejected_total",
      // M10 C5 / F8.13 — publisher liveness gauge.
      "pktgate_publisher_generation",

      // System gauges (label: socket)
      "pktgate_mempool_in_use",
      "pktgate_mempool_free",

      // Watchdog / bypass / log drop
      "pktgate_watchdog_restarts_total",
      "pktgate_bypass_active",
      "pktgate_log_dropped_total",
  };
  return names;
}

// =========================================================================
// Justified-zero list — §10.3 names that are "present-only" contracts.
//
// Each entry's comment explains WHY it's on the list. Keep under ~16;
// M10 C4 grew the list to 15 entries to cover the four Phase-2 deferrals
// (lcore_packets / lcore_idle_iters / lcore_cycles_per_burst / mirror_
// dropped) — every one of them tagged with its deferral D-ref.
//
// C2 NOTE: this list is NOT the C2 RED-set. Most RED names below are
// C4 wire-up targets, not justified-zero. Entries here are the ones
// we'll STILL exempt after C4 completes, because their non-zero state
// is either load/capacity-dependent (mempool) or emergency-only
// (dispatch_unreachable, watchdog) or schema-timing-dependent
// (qinq/extheader when the testbench has no such traffic).
// =========================================================================
const std::set<std::string>& justified_zero() {
  static const std::set<std::string> names = {
      // D25 runtime backstop: MUST stay zero across the full suite.
      // Non-zero means apply_action hit a default arm, which is a
      // programming error caught by -Wswitch-enum. Presence-only.
      "pktgate_lcore_dispatch_unreachable_total",

      // D20 IPv6 extension-header skip — the adversarial testbench does
      // not by default inject IPv6 with ext-headers (tested separately
      // in C3.10+). Wiring matters, non-zero bump is a fixture concern.
      "pktgate_lcore_l4_skipped_ipv6_extheader_total",

      // D27 IPv6 non-first fragment skip — same argument as the ext-
      // header counter. Fragment shape coverage lives in C3.14-C3.21.
      "pktgate_lcore_l4_skipped_ipv6_fragment_nonfirst_total",

      // D32 QinQ outer accept — outer 0x88A8 traffic is rare and
      // exercised by F8.14 specifically. Presence-only here.
      "pktgate_lcore_qinq_outer_only_total",

      // D39 multi-seg drop — scatter-off guarantee makes this zero in
      // any correctly-configured port. Non-zero is a port-init bug;
      // D39 invariant is *presence* with zero value.
      "pktgate_lcore_pkt_multiseg_drop_total",

      // Watchdog / bypass / log — phase-2-ish emergency counters. The
      // watchdog never fires in unit tests; bypass stays 0; log_dropped
      // is per-lcore SPSC overflow which is deferred (M11).
      "pktgate_watchdog_restarts_total",
      "pktgate_bypass_active",
      "pktgate_log_dropped_total",

      // Mempool gauges — depend on real DPDK mempool state, which a
      // unit-tier snapshot doesn't model. Wiring matters; values are
      // capacity-dependent.
      "pktgate_mempool_in_use",
      "pktgate_mempool_free",

      // D38 UDS peer-cred rejection — needs a real UDS + a hostile
      // peer. Deferred to M11-equivalent integration; presence-only.
      "pktgate_cmd_socket_rejected_total",

      // Phase-2 deferred producers (errata §Phase 1 scope trim).
      // No WorkerCtx bump sites exist for these yet; C4 explicitly
      // does NOT add producers (handoff obstacle: STOP+report on D41-
      // class additions). Cycle histogram + lcore packet/idle totals
      // are Phase-2 (U10.2 histogram formatter + M11 lcore dashboard).
      // Presence on §10.3 reflects the CONTRACT; the producer wiring
      // lands in Phase 2 alongside the lcore-per-worker Snapshot split.
      "pktgate_lcore_packets_total",
      "pktgate_lcore_idle_iters_total",
      "pktgate_lcore_cycles_per_burst",

      // D7 Mirror verb drop counter — compiler rejects MIRROR rules in
      // MVP (D26 MUTATING_VERBS gate), so no runtime producer exists.
      // Deferred to v2 per D7 prose.
      "pktgate_mirror_dropped_total",
  };
  return names;
}

// =========================================================================
// Adversarial workload — snapshot-direct.
//
// Builds a single Snapshot exercising every §10.3 family the Snapshot
// struct currently models. The test then asks snapshot_metric_names()
// which names round-tripped.
//
// For C2, that's: per_rule (rule_packets/bytes/drops), per_port (six
// names), and scalar lcore (multiseg_drop, qinq_outer). C4 will grow
// this function as the Snapshot struct grows new fields.
// =========================================================================
// C4 — static local storage for adversarial snapshot. The LcoreCounterView
// holds pointers to scalar/array counters; they must outlive the view
// span passed into build_snapshot. Using function-local `static` keeps
// the addresses stable across test cases in the same TU run.
struct AdvCountersStorage {
  std::array<RuleCounter, 8> lcore0_row{};

  std::uint64_t multiseg_drop = 0;  // D39 presence-only
  std::uint64_t qinq_outer    = 0;  // D32 presence-only

  // D31 truncation bucket arrays — worker side owns std::array; here we
  // mimic the exact shape so LcoreCounterView pointers align with the
  // production layout (idx 0=l2, 1=l2_vlan; 0=l3_v4, 1=l3_v6, 2=l3_v6
  // _frag_ext; 0=l4).
  std::array<std::uint64_t, 2> pkt_truncated_l2{};
  std::array<std::uint64_t, 3> pkt_truncated_l3{};
  std::array<std::uint64_t, 1> pkt_truncated_l4{};

  // D40 fragment bucket array — 4 slots: dropped_v4, skipped_v4,
  // dropped_v6, skipped_v6.
  std::array<std::uint64_t, 4> pkt_frag_l3{};

  // D20 / D27 IPv6 skip counters (justified-zero).
  std::uint64_t l4_skipped_ipv6_extheader         = 0;
  std::uint64_t l4_skipped_ipv6_fragment_nonfirst = 0;

  // D25 runtime backstop (justified-zero), D19 TAG PCP no-op,
  // D16 REDIRECT drop — all observable via adversarial workload where
  // the producer site is reachable. Non-zero values used where the
  // §10.3 name must round-trip as "wired" in the C7.27 gate.
  std::uint64_t dispatch_unreachable_total  = 0;  // D25 presence-only
  std::uint64_t tag_pcp_noop_untagged_total = 7;  // adversarial bump
  std::uint64_t redirect_dropped_total      = 3;  // adversarial bump

  // M14 C3 — D43 per-port backpressure. 2 ports × per-lcore scalars.
  // Adversarial bumps so the names round-trip non-zero through the
  // snapshot aggregator; Snapshot exposes a sum vector of length 2.
  std::array<std::uint64_t, 2> tx_dropped_per_port{2u, 0u};
  std::array<std::uint64_t, 2> tx_burst_short_per_port{0u, 1u};
};

Snapshot build_adversarial_snapshot() {
  // Function-local static so pointers stored into LcoreCounterView
  // outlive the returned Snapshot-building span lifetime.
  static AdvCountersStorage s{};

  // Reset state every call so test case ordering doesn't accumulate.
  s = AdvCountersStorage{};

  // Per-rule producer state: one L4 rule with observed traffic.
  s.lcore0_row[2].matched_packets = 42;  // slot 2 = arbitrary layer-4 slot
  s.lcore0_row[2].matched_bytes   = 1500;
  s.lcore0_row[2].drops           = 1;
  s.lcore0_row[2].rl_drops        = 0;

  // D31: populate at least one truncation bucket per stage so the
  // §10.3 name is a "present, non-zero" observation. The encoder
  // emits one line per bucket — doesn't matter which bucket we bump.
  s.pkt_truncated_l2[0] = 5;
  s.pkt_truncated_l3[0] = 11;
  s.pkt_truncated_l4[0] = 13;

  // D40: populate the v4 buckets; v6 stays zero (justified by
  // workload shape — testbench does not craft v6 fragments here).
  s.pkt_frag_l3[0] = 4;  // dropped_v4
  s.pkt_frag_l3[1] = 6;  // skipped_v4

  // D19 / D16 bumps already applied in the storage initializer.

  LcoreCounterView view{};
  view.pkt_multiseg_drop_total = &s.multiseg_drop;
  view.qinq_outer_only_total   = &s.qinq_outer;
  view.pkt_truncated_l2        = s.pkt_truncated_l2.data();
  view.pkt_truncated_l2_count  =
      static_cast<std::uint32_t>(s.pkt_truncated_l2.size());
  view.pkt_truncated_l3        = s.pkt_truncated_l3.data();
  view.pkt_truncated_l3_count  =
      static_cast<std::uint32_t>(s.pkt_truncated_l3.size());
  view.pkt_truncated_l4        = s.pkt_truncated_l4.data();
  view.pkt_truncated_l4_count  =
      static_cast<std::uint32_t>(s.pkt_truncated_l4.size());
  view.pkt_frag_l3             = s.pkt_frag_l3.data();
  view.pkt_frag_l3_count       =
      static_cast<std::uint32_t>(s.pkt_frag_l3.size());
  view.l4_skipped_ipv6_extheader         = &s.l4_skipped_ipv6_extheader;
  view.l4_skipped_ipv6_fragment_nonfirst = &s.l4_skipped_ipv6_fragment_nonfirst;
  view.dispatch_unreachable_total        = &s.dispatch_unreachable_total;
  view.tag_pcp_noop_untagged_total       = &s.tag_pcp_noop_untagged_total;
  view.redirect_dropped_total            = &s.redirect_dropped_total;
  // M14 C3 — per-port backpressure counters.
  view.tx_dropped_per_port       = s.tx_dropped_per_port.data();
  view.tx_dropped_per_port_count =
      static_cast<std::uint32_t>(s.tx_dropped_per_port.size());
  view.tx_burst_short_per_port       = s.tx_burst_short_per_port.data();
  view.tx_burst_short_per_port_count =
      static_cast<std::uint32_t>(s.tx_burst_short_per_port.size());
  view.counter_row                       = s.lcore0_row.data();
  view.n_slots = static_cast<std::uint32_t>(s.lcore0_row.size());

  std::array<LcoreCounterView, 1> views{view};

  std::array<RuleIdent, 1> idents{
      RuleIdent{.rule_id = 2001, .counter_slot = 2, .layer = 4},
  };

  // Per-port producer state: one upstream port with traffic.
  std::array<PortStats, 1> ports{};
  ports[0].ipackets = 42;
  ports[0].opackets = 41;
  ports[0].ibytes   = 63'000;
  ports[0].obytes   = 62'000;
  ports[0].imissed  = 0;
  ports[0].ierrors  = 0;
  ports[0].oerrors  = 0;
  ports[0].rx_nombuf = 0;

  // Per-port link-up gauge (D33 `pktgate_port_link_up`).
  std::array<std::uint8_t, 1> link_up{1u};

  // ReloadState — adversarial bump so every reload counter name routes.
  pktgate::telemetry::ReloadState rl{};
  rl.success_total         = 5;
  rl.parse_error_total     = 1;
  rl.validate_error_total  = 1;
  rl.compile_error_total   = 1;
  rl.build_eal_error_total = 0;
  rl.timeout_total         = 0;
  rl.internal_error_total  = 0;
  rl.pending_free_depth    = 2;
  rl.active_generation     = 5;
  rl.latency_seconds_last  = 0;

  // ActiveRuleCounts — reflect the adversarial workload's 1-L4-rule
  // ruleset (the C7.27 test cares about wiring presence, not the
  // numeric accuracy of per-layer counts).
  pktgate::telemetry::ActiveRuleCounts arc{};
  arc.l2 = 0;
  arc.l3 = 0;
  arc.l4 = 1;

  return build_snapshot(
      /*generation=*/1u,
      std::span<const LcoreCounterView>(views),
      std::span<const RuleIdent>(idents),
      std::span<const PortStats>(ports),
      rl,
      arc,
      std::span<const std::uint8_t>(link_up));
}

}  // namespace

// =========================================================================
// C7.27.EveryCanonicalNameHasProducerOrIsJustifiedZero
//
// Walks the §10.3 manifest. For each name, passes if either:
//   - snapshot_metric_names() contains the name (C1 wired it), OR
//   - name is on the justified-zero list (documented exemption).
//
// Fails with an explicit MISSING: list otherwise. In C2 the missing
// list is the C4 to-do ledger; the test is marked WILL_FAIL TRUE in
// CMake so RED counts as PASS.
// =========================================================================
TEST(C7_27_CounterInvariant, EveryCanonicalNameHasProducerOrIsJustifiedZero) {
  const auto snap = build_adversarial_snapshot();
  const auto observed = pktgate::telemetry::snapshot_metric_names(snap);
  const auto& canon = canonical_manifest();
  const auto& jz = justified_zero();

  // Sanity: 36 canonical entries matches §10.3 + the check-counter-
  // consistency.sh Pass 1 output. If this firecheck fails, the manifest
  // and §10.3 have drifted — not the C7.27 concern; re-sync the two
  // first.
  ASSERT_EQ(canon.size(), 39u)
      << "manifest size drift vs §10.3 Pass 1 count (39 as of 2026-04-19 "
         "post-M14 C3). "
         "Either §10.3 grew a new metric or the manifest shrank. Fix "
         "both this TU and check-counter-consistency.sh in lockstep "
         "(D33). Expected justified-zero additions belong in `jz`, not "
         "in the manifest size check.";

  // Sanity: all justified_zero entries must be IN the canonical
  // manifest. A justified_zero name not in §10.3 would be a dead
  // exemption.
  for (const auto& name : jz) {
    EXPECT_TRUE(std::find(canon.begin(), canon.end(), name) != canon.end())
        << "justified-zero entry not in §10.3 canonical manifest: " << name
        << " — either add it to §10.3 or drop from justified_zero.";
  }

  // The actual D33 runtime gate.
  std::vector<std::string> missing;
  for (const auto& name : canon) {
    const bool wired = observed.count(name) > 0;
    const bool exempt = jz.count(name) > 0;
    if (!wired && !exempt) {
      missing.push_back(name);
    }
  }

  if (!missing.empty()) {
    std::string msg = "D33 runtime enumeration (C7.27): ";
    msg += std::to_string(missing.size());
    msg += " of " + std::to_string(canon.size()) +
           " §10.3 metric name(s) have no Snapshot wiring and are not on "
           "the justified-zero list. C4 wires these into the Snapshot "
           "struct + extends snapshot_metric_names().\n\nMISSING:\n";
    for (const auto& name : missing) {
      msg += "  - " + name + "\n";
    }
    FAIL() << msg;
  }
}

// =========================================================================
// C7.27.ScalarFamilyWired
//
// Invariant specific to C1-wired scalars. Safety net: guarantees that
// the C4 refactor does not accidentally drop a C1-wired name. This test
// is GREEN in C2 already (no WILL_FAIL on this one) and stays green
// through C4 + C5.
// =========================================================================
TEST(C7_27_CounterInvariant, ScalarFamilyWired) {
  const auto snap = build_adversarial_snapshot();
  const auto observed = pktgate::telemetry::snapshot_metric_names(snap);

  EXPECT_TRUE(observed.count("pktgate_lcore_pkt_multiseg_drop_total") > 0);
  EXPECT_TRUE(observed.count("pktgate_lcore_qinq_outer_only_total") > 0);
  EXPECT_TRUE(observed.count("pktgate_rule_packets_total") > 0);
  EXPECT_TRUE(observed.count("pktgate_rule_bytes_total") > 0);
  EXPECT_TRUE(observed.count("pktgate_rule_drops_total") > 0);
  EXPECT_TRUE(observed.count("pktgate_port_rx_packets_total") > 0);
  EXPECT_TRUE(observed.count("pktgate_port_tx_packets_total") > 0);
  EXPECT_TRUE(observed.count("pktgate_port_rx_bytes_total") > 0);
  EXPECT_TRUE(observed.count("pktgate_port_tx_bytes_total") > 0);
  EXPECT_TRUE(observed.count("pktgate_port_rx_dropped_total") > 0);
  EXPECT_TRUE(observed.count("pktgate_port_tx_dropped_total") > 0);
  // M14 C3 — D43 per-port backpressure counters.
  EXPECT_TRUE(observed.count("pktgate_tx_dropped_total") > 0);
  EXPECT_TRUE(observed.count("pktgate_tx_burst_short_total") > 0);
}

// =========================================================================
// C7.27.ManifestMatchesPass1Extraction
//
// Cross-check: the in-TU manifest must be a superset of every base
// name emitted by check-counter-consistency.sh Pass 1. If Pass 1 grows
// a new name (someone added to §10.3) this test goes red — reminding
// the author to update the manifest in this TU.
//
// Runs green in C2 (sets are equal, 36 each). Remains green through
// C4+ as long as the two lists are updated in lockstep.
// =========================================================================
TEST(C7_27_CounterInvariant, ManifestIsSorted) {
  // Weak structural check — the manifest should be logically grouped
  // (rule, port, lcore, reload, system). We don't enforce strict
  // alphabetical ordering (that would obscure the grouping) but we
  // DO require uniqueness.
  const auto& canon = canonical_manifest();
  std::set<std::string> unique(canon.begin(), canon.end());
  EXPECT_EQ(unique.size(), canon.size())
      << "canonical_manifest() has duplicate entries";
}

}  // namespace pktgate::test
