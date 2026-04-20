// src/telemetry/counter_names.h
//
// M10 C5 REFACTOR — canonical §10.3 counter-name constants + typed
// CounterName struct carrying each name together with its metric type.
//
// Context
// -------
// The plan for M10 REFACTOR (implementation-plan.md §M10 lines 571-573)
// asks for a `CounterName` type carrying its §10.3 row reference so the
// D33 grep becomes structurally unnecessary over time. This file is the
// minimal-safe cut: we EXTRACT the raw name string literals that
// previously lived inline at every emit site into a single header that
// declares them once, along with a typed struct (name + metric type).
// Callers (src/main.cpp BodyFn; src/telemetry/snapshot.cpp
// snapshot_metric_names(); tests/integration/test_c7_27_counter_
// invariant.cpp canonical_manifest()) dereference the same constants.
//
// Why minimal-safe
// ----------------
// Collapsing the emit pipeline wholesale (encoder rewrite, snapshot
// field-descriptor table, reflection) would touch main.cpp, encoder.h,
// snapshot.h, and four test TUs simultaneously — D41-class risk on the
// just-landed C4 F8.2 pipeline. This cut changes NO signatures, NO
// snapshot fields, NO encoder API. It replaces string literals with
// constant references; a successful compilation over all call sites is
// the load-bearing assertion.
//
// Belt-and-suspenders
// -------------------
// `scripts/check-counter-consistency.sh` stays operational (D33 grep
// arm). This header does NOT replace it. The grep arm scans design.md
// and review-notes.md for prose drift; this header only extracts the
// SOURCE references from C++ code, which the grep never scanned.
// Future work (Phase 2) can migrate the grep to a consteval table of
// these constants, but that is out of M10 scope.
//
// D-refs: D3 (counting model), D33 (consistency invariant), D42
// (hand-rolled HTTP + minimalism in the telemetry surface).

#pragma once

#include <array>
#include <string_view>

#include "src/telemetry/prom_encoder.h"

namespace pktgate::telemetry::names {

// ---------------------------------------------------------------------
// CounterName — typed reference carrying a §10.3 name + its metric type.
//
// `name` is a constant `std::string_view` pointing into this TU's
// string table (string-literal lifetime). `type` is the canonical
// MetricType from prom_encoder.h; consumers wanting to emit via
// format_counter / format_gauge dispatch on it.
//
// Equality / ordering operate on `name` only — `type` is metadata.
struct CounterName {
  std::string_view name;
  MetricType       type;

  constexpr friend bool operator==(CounterName a, CounterName b) {
    return a.name == b.name;
  }
  constexpr friend bool operator!=(CounterName a, CounterName b) {
    return !(a == b);
  }
};

// ---------------------------------------------------------------------
// Canonical §10.3 name constants.
//
// Grouped by family (rule, port, lcore, dispatch, reload, system).
// Keep alphabetically-ordered WITHIN each family for grep stability.
//
// Every name here has a matching row in design.md §10.3 and, when
// surfaced by the Phase 1 pipeline, a producer site in src/. Names
// documented as presence-only (justified-zero in C7.27) still live
// here — the typed reference carries the §10.3 identity regardless of
// the value being observed.
//
// When §10.3 grows a new name:
//   1. Add the prose row to design.md §10.3.
//   2. Add a constexpr CounterName instance below.
//   3. Extend tests/integration/test_c7_27_counter_invariant.cpp
//      canonical_manifest() and (if an exposition path is wired)
//      snapshot_metric_names() in snapshot.cpp + emit in
//      src/main.cpp BodyFn.
//   4. Run `scripts/check-counter-consistency.sh` — it reads §10.3
//      and will fold the new name into its Pass 1 set automatically.

// --- Rule-match family ------------------------------------------------
inline constexpr CounterName kRulePacketsTotal{
    "pktgate_rule_packets_total", MetricType::Counter};
inline constexpr CounterName kRuleBytesTotal{
    "pktgate_rule_bytes_total", MetricType::Counter};
inline constexpr CounterName kRuleDropsTotal{
    "pktgate_rule_drops_total", MetricType::Counter};
inline constexpr CounterName kDefaultActionTotal{
    "pktgate_default_action_total", MetricType::Counter};

// --- Per-port family --------------------------------------------------
inline constexpr CounterName kPortRxPacketsTotal{
    "pktgate_port_rx_packets_total", MetricType::Counter};
inline constexpr CounterName kPortTxPacketsTotal{
    "pktgate_port_tx_packets_total", MetricType::Counter};
inline constexpr CounterName kPortRxBytesTotal{
    "pktgate_port_rx_bytes_total", MetricType::Counter};
inline constexpr CounterName kPortTxBytesTotal{
    "pktgate_port_tx_bytes_total", MetricType::Counter};
inline constexpr CounterName kPortRxDroppedTotal{
    "pktgate_port_rx_dropped_total", MetricType::Counter};
inline constexpr CounterName kPortTxDroppedTotal{
    "pktgate_port_tx_dropped_total", MetricType::Counter};
inline constexpr CounterName kPortLinkUp{
    "pktgate_port_link_up", MetricType::Gauge};
// M14 C3 — D43 per-port backpressure counters emitted by pktgate's
// own tx_one() / redirect_drain() wrappers. PMD-agnostic. D1-clean:
// per-lcore bumps via relaxed_bump aggregated at publisher tick.
inline constexpr CounterName kTxDroppedTotal{
    "pktgate_tx_dropped_total", MetricType::Counter};
inline constexpr CounterName kTxBurstShortTotal{
    "pktgate_tx_burst_short_total", MetricType::Counter};

// --- Per-lcore family -------------------------------------------------
inline constexpr CounterName kLcorePacketsTotal{
    "pktgate_lcore_packets_total", MetricType::Counter};
inline constexpr CounterName kLcoreCyclesPerBurst{
    "pktgate_lcore_cycles_per_burst", MetricType::Histogram};
inline constexpr CounterName kLcoreIdleItersTotal{
    "pktgate_lcore_idle_iters_total", MetricType::Counter};
inline constexpr CounterName kLcoreL4SkippedIpv6ExtheaderTotal{
    "pktgate_lcore_l4_skipped_ipv6_extheader_total",
    MetricType::Counter};
inline constexpr CounterName kLcoreL4SkippedIpv6FragmentNonfirstTotal{
    "pktgate_lcore_l4_skipped_ipv6_fragment_nonfirst_total",
    MetricType::Counter};
inline constexpr CounterName kLcoreTagPcpNoopUntaggedTotal{
    "pktgate_lcore_tag_pcp_noop_untagged_total", MetricType::Counter};
inline constexpr CounterName kLcoreDispatchUnreachableTotal{
    "pktgate_lcore_dispatch_unreachable_total", MetricType::Counter};
inline constexpr CounterName kLcorePktTruncatedTotal{
    "pktgate_lcore_pkt_truncated_total", MetricType::Counter};
inline constexpr CounterName kLcoreQinqOuterOnlyTotal{
    "pktgate_lcore_qinq_outer_only_total", MetricType::Counter};
inline constexpr CounterName kLcorePktMultisegDropTotal{
    "pktgate_lcore_pkt_multiseg_drop_total", MetricType::Counter};
inline constexpr CounterName kLcorePktFragSkippedTotal{
    "pktgate_lcore_pkt_frag_skipped_total", MetricType::Counter};
inline constexpr CounterName kLcorePktFragDroppedTotal{
    "pktgate_lcore_pkt_frag_dropped_total", MetricType::Counter};

// --- Dispatch / mirror / redirect ------------------------------------
inline constexpr CounterName kRedirectDroppedTotal{
    "pktgate_redirect_dropped_total", MetricType::Counter};
// M16 C2 — D7 mirror dispatch counter triplet.
//   mirror_sent_total         — clone staged into mirror_tx[port]
//                               (success at STAGE time; a stage-full
//                               drop does not count here).
//   mirror_clone_failed_total — rte_pktmbuf_copy returned null;
//                               original still forwards, no clone.
//   mirror_dropped_total      — clone staged but unsent at drain
//                               time (short rte_eth_tx_burst) OR
//                               stage-time buffer-full drop.
inline constexpr CounterName kMirrorSentTotal{
    "pktgate_mirror_sent_total", MetricType::Counter};
inline constexpr CounterName kMirrorCloneFailedTotal{
    "pktgate_mirror_clone_failed_total", MetricType::Counter};
inline constexpr CounterName kMirrorDroppedTotal{
    "pktgate_mirror_dropped_total", MetricType::Counter};

// --- Reload / control plane -------------------------------------------
inline constexpr CounterName kReloadTotal{
    "pktgate_reload_total", MetricType::Counter};
inline constexpr CounterName kReloadLatencySeconds{
    "pktgate_reload_latency_seconds", MetricType::Histogram};
inline constexpr CounterName kReloadPendingFreeDepth{
    "pktgate_reload_pending_free_depth", MetricType::Gauge};
inline constexpr CounterName kActiveGeneration{
    "pktgate_active_generation", MetricType::Gauge};
inline constexpr CounterName kActiveRules{
    "pktgate_active_rules", MetricType::Gauge};
inline constexpr CounterName kCmdSocketRejectedTotal{
    "pktgate_cmd_socket_rejected_total", MetricType::Counter};
// C5 / F8.13 — publisher liveness gauge (new §10.3 row).
inline constexpr CounterName kPublisherGeneration{
    "pktgate_publisher_generation", MetricType::Gauge};

// --- System gauges ----------------------------------------------------
inline constexpr CounterName kMempoolInUse{
    "pktgate_mempool_in_use", MetricType::Gauge};
inline constexpr CounterName kMempoolFree{
    "pktgate_mempool_free", MetricType::Gauge};

// --- Watchdog / bypass / log ring ------------------------------------
inline constexpr CounterName kWatchdogRestartsTotal{
    "pktgate_watchdog_restarts_total", MetricType::Counter};
inline constexpr CounterName kBypassActive{
    "pktgate_bypass_active", MetricType::Gauge};
inline constexpr CounterName kLogDroppedTotal{
    "pktgate_log_dropped_total", MetricType::Counter};

// ---------------------------------------------------------------------
// kAllCounterNames — flat array of every CounterName declared above.
//
// Consumers that need to enumerate the full §10.3 set (the D33 runtime
// gate in tests/integration/test_c7_27_counter_invariant.cpp, any
// future encoder-side dispatch table) iterate this array. Size MUST
// match the §10.3 canonical count — a mismatch here is the D33 drift
// signal picked up by the C7.27 ASSERT_EQ on canonical_manifest().
//
// Order is exposition-stable (mirrors §10.3 prose order). Grepping for
// a name in source returns a single hit in this header.
inline constexpr std::array<CounterName, 41> kAllCounterNames{
    // Rule-match family
    kRulePacketsTotal,
    kRuleBytesTotal,
    kRuleDropsTotal,
    kDefaultActionTotal,
    // Per-port family
    kPortRxPacketsTotal,
    kPortTxPacketsTotal,
    kPortRxBytesTotal,
    kPortTxBytesTotal,
    kPortRxDroppedTotal,
    kPortTxDroppedTotal,
    kPortLinkUp,
    // M14 C3 — D43 per-port backpressure (pktgate's own tx wrappers).
    kTxDroppedTotal,
    kTxBurstShortTotal,
    // Per-lcore family
    kLcorePacketsTotal,
    kLcoreCyclesPerBurst,
    kLcoreIdleItersTotal,
    kLcoreL4SkippedIpv6ExtheaderTotal,
    kLcoreL4SkippedIpv6FragmentNonfirstTotal,
    kLcoreTagPcpNoopUntaggedTotal,
    kLcoreDispatchUnreachableTotal,
    kLcorePktTruncatedTotal,
    kLcoreQinqOuterOnlyTotal,
    kLcorePktMultisegDropTotal,
    kLcorePktFragSkippedTotal,
    kLcorePktFragDroppedTotal,
    // Dispatch / mirror / redirect
    kRedirectDroppedTotal,
    kMirrorSentTotal,
    kMirrorCloneFailedTotal,
    kMirrorDroppedTotal,
    // Reload / control plane
    kReloadTotal,
    kReloadLatencySeconds,
    kReloadPendingFreeDepth,
    kActiveGeneration,
    kActiveRules,
    kCmdSocketRejectedTotal,
    kPublisherGeneration,
    // System gauges
    kMempoolInUse,
    kMempoolFree,
    // Watchdog / bypass / log
    kWatchdogRestartsTotal,
    kBypassActive,
    kLogDroppedTotal,
};

}  // namespace pktgate::telemetry::names
