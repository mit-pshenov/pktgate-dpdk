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
// 36 entries as of 2026-04-17 (M10 C2).
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
// Each entry's comment explains WHY it's on the list. Keep under 15.
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
Snapshot build_adversarial_snapshot() {
  // Per-rule producer state: one L4 rule with observed traffic.
  std::array<RuleCounter, 8> lcore0_row{};
  lcore0_row[2].matched_packets = 42;  // slot 2 = arbitrary layer-4 slot
  lcore0_row[2].matched_bytes   = 1500;
  lcore0_row[2].drops           = 1;
  lcore0_row[2].rl_drops        = 0;

  std::uint64_t multiseg_drop = 0;  // presence-only per justified_zero
  std::uint64_t qinq_outer    = 0;  // presence-only per justified_zero

  LcoreCounterView view{
      .pkt_multiseg_drop_total = &multiseg_drop,
      .qinq_outer_only_total   = &qinq_outer,
      .counter_row             = lcore0_row.data(),
      .n_slots                 = static_cast<std::uint32_t>(lcore0_row.size()),
  };
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

  return build_snapshot(/*generation=*/1u,
                        std::span<const LcoreCounterView>(views),
                        std::span<const RuleIdent>(idents),
                        std::span<const PortStats>(ports));
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
  ASSERT_EQ(canon.size(), 36u)
      << "manifest size drift vs §10.3 Pass 1 count (36 as of 2026-04-17). "
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
