// src/telemetry/snapshot.h
//
// M10 C1 — Snapshot struct + pure aggregation function.
//
// D3 — single-writer (telemetry thread), multi-reader snapshot
// pipeline. The telemetry thread ticks at 1 Hz: reads per-lcore
// counter rows + WorkerCtx scalar counters + per-port rte_eth_stats,
// aggregates them into a `Snapshot`, publishes into the ring
// (snapshot_ring.h). Readers (C3+ HTTP `/metrics`) acquire-load the
// latest slot.
//
// This header lives in the DPDK-free control-plane lib
// `pktgate_telemetry`. We do NOT pull `<rte_ethdev.h>` in here —
// instead we declare a minimal DPDK-free `PortStats` struct with the
// subset of `rte_eth_stats` fields the encoder needs. The publisher
// TU (or a thin DPDK-aware bridge in C3) is responsible for calling
// `rte_eth_stats_get` and copying into `PortStats` before invoking
// `build_snapshot`.
//
// Reader-side D1 compliance (2026-04-17 amendment):
//   * WORKER side counter writes stay plain non-atomic
//     (`++ctx.ctr`) — D1 sacred, zero atomics in the classify /
//     dispatch hot path.
//   * READER side (this file's `build_snapshot`) uses
//     `__atomic_load_n(..., __ATOMIC_RELAXED)` on the source
//     counters. On x86-64 this is a single `mov`, no fence.
//   * TSan sees the relaxed load as synchronising with any plain
//     write under the "shared variable both accessed by atomic
//     operations" rule — no race flag.
//
// Fields surfaced in C1 are a representative subset of §10.3;
// C4 extends to the full list (reload counters, qinq, frag,
// truncation, etc.). C1 covers enough to exercise U7.1-U7.4/U7.6.

#pragma once

#include <cstddef>
#include <cstdint>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "src/ruleset/ruleset.h"

namespace pktgate::telemetry {

// -------------------------------------------------------------------------
// PortStats — DPDK-free proxy for `rte_eth_stats`.
//
// The publisher (or the C3 adapter) fills this from `rte_eth_stats`
// before calling `build_snapshot`. Keeping the struct DPDK-free
// means `pktgate_telemetry` stays linkable without DPDK headers —
// unit tests construct fake PortStats inline.
//
// Field mapping to §10.3 exposition names:
//   ipackets   → pktgate_port_rx_packets_total{port}
//   opackets   → pktgate_port_tx_packets_total{port}
//   ibytes     → pktgate_port_rx_bytes_total{port}
//   obytes     → pktgate_port_tx_bytes_total{port}
//   imissed    → pktgate_port_rx_dropped_total{port,reason="noqueue"}
//   ierrors    → pktgate_port_rx_dropped_total{port,reason="err"}
//   oerrors    → pktgate_port_tx_dropped_total{port}
//   rx_nombuf  → pktgate_port_rx_dropped_total{port,reason="nombuf"}
struct PortStats {
  std::uint64_t ipackets  = 0;
  std::uint64_t opackets  = 0;
  std::uint64_t ibytes    = 0;
  std::uint64_t obytes    = 0;
  std::uint64_t imissed   = 0;
  std::uint64_t ierrors   = 0;
  std::uint64_t oerrors   = 0;
  std::uint64_t rx_nombuf = 0;
};

// -------------------------------------------------------------------------
// LcoreCounterView — read-only view over one lcore's WorkerCtx
// scalar counters.
//
// The publisher TU constructs one of these per live worker (pointer
// to the real `WorkerCtx` fields). `build_snapshot` reads via the
// view using `__atomic_load_n(..., __ATOMIC_RELAXED)` — worker side
// stays plain.
//
// C4 expands this to the full §10.3 scalar-counter set (sum-across-
// lcores). Null pointers mean the view-constructor did not expose that
// field (test fakes frequently wire only a subset). A null pointer
// contributes 0 to the aggregate — it does NOT fall off the emitted
// metric name list (the §10.3 name is surfaced even on zero,
// presence-only semantics).
struct LcoreCounterView {
  // C1 — multiseg drop + QinQ outer (both D31/D32 presence-only).
  const std::uint64_t* pkt_multiseg_drop_total = nullptr;
  const std::uint64_t* qinq_outer_only_total   = nullptr;

  // C4 — D31 per-stage truncation counter buckets. Pointer to
  // worker_ctx.pkt_truncated_l2[] / l3[] / l4[]; sum across lcores
  // per bucket. Null-friendly (a missing bucket view contributes 0).
  const std::uint64_t* pkt_truncated_l2       = nullptr;  // array of kL2TruncBucketCount
  std::uint32_t        pkt_truncated_l2_count = 0;
  const std::uint64_t* pkt_truncated_l3       = nullptr;  // array of kL3TruncBucketCount
  std::uint32_t        pkt_truncated_l3_count = 0;
  const std::uint64_t* pkt_truncated_l4       = nullptr;  // array of kL4TruncBucketCount
  std::uint32_t        pkt_truncated_l4_count = 0;

  // C4 — D40 fragment counter buckets (v4 + v6 dropped/skipped).
  // Pointer to worker_ctx.pkt_frag_l3[] (L3FragCtrs = 4 slots).
  const std::uint64_t* pkt_frag_l3       = nullptr;
  std::uint32_t        pkt_frag_l3_count = 0;

  // C4 — D20/D27 IPv6 skip counters.
  const std::uint64_t* l4_skipped_ipv6_extheader         = nullptr;
  const std::uint64_t* l4_skipped_ipv6_fragment_nonfirst = nullptr;

  // C4 — D25 runtime backstop + D19 TAG PCP no-op.
  const std::uint64_t* dispatch_unreachable_total = nullptr;
  const std::uint64_t* tag_pcp_noop_untagged_total = nullptr;

  // C4 — D16 REDIRECT drop counter.
  const std::uint64_t* redirect_dropped_total = nullptr;

  // M14 C3 — D43 per-port backpressure counter arrays emitted by
  // pktgate's own tx wrappers. Pointer + count mirror the pattern
  // used by the truncation / fragment bucket arrays. Null-friendly
  // (a fixture not exercising the tx path contributes 0 and no
  // port-dimension entries).
  //
  // Expected count in production: RTE_MAX_ETHPORTS. Smaller counts
  // are valid (unit-test fixtures with a handful of synthetic
  // ports). The aggregator resizes Snapshot::tx_dropped_per_port
  // to max(count across all views) and element-wise sums into it.
  const std::uint64_t* tx_dropped_per_port       = nullptr;
  std::uint32_t        tx_dropped_per_port_count = 0;
  const std::uint64_t* tx_burst_short_per_port       = nullptr;
  std::uint32_t        tx_burst_short_per_port_count = 0;

  // M16 C2 — D7 per-port mirror dispatch counter arrays. Same shape
  // as the D43 tx arrays above (pointer + count, null-friendly). The
  // aggregator resizes Snapshot::mirror_*_per_port to max(count
  // across views) and element-wise sums. Indexed by destination port
  // (RuleAction::mirror_port).
  const std::uint64_t* mirror_sent_per_port       = nullptr;
  std::uint32_t        mirror_sent_per_port_count = 0;
  const std::uint64_t* mirror_clone_failed_per_port       = nullptr;
  std::uint32_t        mirror_clone_failed_per_port_count = 0;
  const std::uint64_t* mirror_dropped_per_port       = nullptr;
  std::uint32_t        mirror_dropped_per_port_count = 0;

  // Per-rule counter row for this lcore: layout matches
  // `Ruleset::counter_row(lcore_id)`. `n_slots` is
  // `rs.counter_slots_per_lcore`. Null allowed for fakes that only
  // exercise scalar counters.
  const ruleset::RuleCounter* counter_row = nullptr;
  std::uint32_t n_slots = 0;
};

// -------------------------------------------------------------------------
// PerRuleCounter — aggregated per-rule counter in the snapshot.
//
// Sum across all lcores of `counter_row[slot]` for a given rule.
// The `slot` is the rule's `counter_slot` (layer-offset already
// applied by the publisher; see `layer_base`). `rule_id` is preserved
// so the encoder can emit `rule_id="N"` labels.
struct PerRuleCounter {
  std::uint64_t rule_id         = 0;
  std::uint64_t matched_packets = 0;
  std::uint64_t matched_bytes   = 0;
  std::uint64_t drops           = 0;
  std::uint64_t rl_drops        = 0;
  // Layer tag for `layer="l2|l3|l4"` label. 2/3/4 → "l2"/"l3"/"l4";
  // 0 = unset (C1 default when the publisher doesn't surface per-rule
  // yet). Encoder treats 0 as "omit label".
  std::uint8_t  layer           = 0;
};

// -------------------------------------------------------------------------
// ReloadState — control-plane reload counter family aggregated into the
// Snapshot (D33 / §10.3 reload.*).
//
// Filled by the publisher from `ctl::reload::counters_snapshot()` (taken
// under `reload_mutex`, so no torn reads). Surfaces every reload counter
// in §10.3 plus the `active_generation` gauge.
//
// `reload_latency_seconds_last` captures the most recent successful
// reload's measured latency for the `pktgate_reload_latency_seconds`
// gauge (spec treats it as the last-observed value; histogram form is
// Phase 2). M10 C4 publisher leaves this at zero until reload.cpp
// starts stamping a per-deploy duration — the name still ships through
// snapshot_metric_names so D33 is satisfied, and the value is zero
// until the producer side adds timing. See handoff obstacle #5.
struct ReloadState {
  std::uint64_t success_total          = 0;
  std::uint64_t parse_error_total      = 0;
  std::uint64_t validate_error_total   = 0;
  std::uint64_t compile_error_total    = 0;
  std::uint64_t build_eal_error_total  = 0;
  std::uint64_t timeout_total          = 0;
  std::uint64_t internal_error_total   = 0;
  std::uint64_t pending_free_depth     = 0;  // gauge
  std::uint64_t active_generation      = 0;  // gauge
  std::int64_t  latency_seconds_last   = 0;  // gauge (see above — Phase 2 populates)
};

// -------------------------------------------------------------------------
// ActiveRuleCounts — snapshot of the currently-published Ruleset's
// per-layer rule counts. Surfaces `pktgate_active_rules{layer="l2|l3|l4"}`.
//
// Populated by the publisher via `ctl::reload::active_ruleset()` pointer
// (single-acquire load) at snapshot build time. Gauges — no `_total`.
struct ActiveRuleCounts {
  std::uint64_t l2 = 0;
  std::uint64_t l3 = 0;
  std::uint64_t l4 = 0;
};

// -------------------------------------------------------------------------
// Snapshot — immutable aggregate produced by the 1 Hz telemetry thread.
//
// `generation` is assigned by the publisher on each build; the ring
// buffer uses it to decide latest-slot index and to detect torn
// reads (reader acquire-loads `latest_gen`, then reads the slot
// `latest_gen % N`).
//
// C1 shipped a small subset of §10.3 (per-rule, per-port, two scalars).
// C4 extends to the full §10.3 set: every WorkerCtx scalar counter
// wired in M4-M7, the full reload counter family (M8), and the
// `pktgate_default_action_total` gauge. Phase-2 deferrals (histogram
// cycles_per_burst, lcore_packets, idle_iters) stay off the snapshot
// until their producers land.
struct Snapshot {
  std::uint64_t generation = 0;

  // Per-lcore scalar sums across all workers (sum-of-lcores).
  std::uint64_t pkt_multiseg_drop_total = 0;
  std::uint64_t qinq_outer_only_total   = 0;

  // C4 — D31 truncation rollups. Per-stage bucket sums across lcores.
  // `pkt_truncated_total` is surfaced with a `where` label (l2/l2_vlan/
  // l3_v4/l3_v6/l3_v6_frag_ext/l4) — the encoder walks every bucket
  // and emits one counter line per where-value. Missing bucket (all
  // zero) is still emitted for D33 presence contract.
  std::uint64_t pkt_truncated_l2           = 0;
  std::uint64_t pkt_truncated_l2_vlan      = 0;
  std::uint64_t pkt_truncated_l3_v4        = 0;
  std::uint64_t pkt_truncated_l3_v6        = 0;
  std::uint64_t pkt_truncated_l3_v6_frag_ext = 0;
  std::uint64_t pkt_truncated_l4           = 0;

  // C4 — D40 fragment rollups. `af` label carries "v4"/"v6"; the
  // encoder emits four lines total (skipped/dropped × v4/v6).
  std::uint64_t pkt_frag_skipped_v4 = 0;
  std::uint64_t pkt_frag_skipped_v6 = 0;
  std::uint64_t pkt_frag_dropped_v4 = 0;
  std::uint64_t pkt_frag_dropped_v6 = 0;

  // C4 — D20/D27 IPv6 skip counter rollups.
  std::uint64_t l4_skipped_ipv6_extheader_total         = 0;
  std::uint64_t l4_skipped_ipv6_fragment_nonfirst_total = 0;

  // C4 — D25 runtime backstop + D19 TAG PCP no-op + D16 REDIRECT drop.
  std::uint64_t dispatch_unreachable_total   = 0;
  std::uint64_t tag_pcp_noop_untagged_total  = 0;
  std::uint64_t redirect_dropped_total       = 0;

  // C4 — `pktgate_default_action_total{action="allow|drop"}` — bumps
  // when the pipeline runs default_behavior fallthrough. Populated
  // by the publisher from the existing per-rule drop/match aggregate;
  // for M10 C4 we approximate "observable" by summing the unmatched-
  // fallthrough count from Ruleset.default_action × RX count. The
  // publisher leaves both arms at zero for generations where no
  // fallthrough occurred (encoder still emits for D33 presence).
  std::uint64_t default_action_allow_total = 0;
  std::uint64_t default_action_drop_total  = 0;

  // Per-rule aggregated rows. `rule_id`-keyed entries only; empty
  // rows (matched_packets == 0 && drops == 0) may be omitted by the
  // publisher — the encoder never emits zero-valued counter lines
  // for rules that never matched, per existing `stats_on_exit`
  // convention (main.cpp:588).
  std::vector<PerRuleCounter> per_rule;

  // Per-port rte_eth_stats snapshot. Indexed by port_id; empty
  // entries are skipped by the encoder.
  std::vector<PortStats> per_port;

  // Per-port link-up gauge. Parallel to `per_port`; same index.
  // `1` = link up, `0` = link down. Surfaces
  // `pktgate_port_link_up{port="N"}`. Publisher fills this from
  // `rte_eth_link_get_nowait` alongside `rte_eth_stats_get`.
  std::vector<std::uint8_t> per_port_link_up;

  // M14 C3 — D43 per-port backpressure rollups. Sum of
  // LcoreCounterView::tx_{dropped,burst_short}_per_port[i] across
  // every lcore view. Length = max count observed across views (the
  // aggregator grows the vectors as it walks views). Indexed by
  // port_id; encoder emits `pktgate_tx_{dropped,burst_short}_total
  // {port="N"}` per entry.
  std::vector<std::uint64_t> tx_dropped_per_port;
  std::vector<std::uint64_t> tx_burst_short_per_port;

  // M16 C2 — D7 per-port mirror dispatch rollups. Sum of
  // LcoreCounterView::mirror_*_per_port[i] across every lcore view.
  // Same sizing rule as tx_dropped_per_port. Encoder emits
  // `pktgate_mirror_{sent,clone_failed,dropped}_total{port="N"}` per
  // entry.
  std::vector<std::uint64_t> mirror_sent_per_port;
  std::vector<std::uint64_t> mirror_clone_failed_per_port;
  std::vector<std::uint64_t> mirror_dropped_per_port;

  // C4 — reload + active-ruleset surface.
  ReloadState      reload{};
  ActiveRuleCounts active_rules{};

  // C5 — publisher liveness gauge. Same value as `generation` above
  // (the publisher increments both in lockstep) but surfaced as a
  // separately-named §10.3 metric so F8.13 can observe the writer's
  // forward progress across a slow-reader scrape without inferring it
  // from `generation` (an internal ring field, not an exposition
  // metric). Duplication is deliberate: `generation` is ring
  // plumbing, `publisher_generation_gauge` is the §10.3 promise.
  std::uint64_t publisher_generation_gauge = 0;
};

// -------------------------------------------------------------------------
// build_snapshot — pure aggregation function.
//
// Inputs:
//   * `generation`       — caller-chosen generation tag (writer
//                          increments once per tick).
//   * `lcore_views`      — span of LcoreCounterView, one per live
//                          worker. Per-lcore scalar sums and
//                          per-rule row sums aggregate across all
//                          views.
//   * `per_rule_ids`     — rule-identity metadata (rule_id, layer,
//                          counter_slot) for every rule the
//                          snapshot must surface. Caller computes
//                          this from the active Ruleset (l2/l3/l4
//                          action arrays); the aggregator doesn't
//                          touch DPDK state. `counter_slot` here is
//                          the absolute slot (layer_base already
//                          applied).
//   * `port_stats`       — span of PortStats, one per active port.
//                          The snapshot's `per_port` is a copy.
//
// Output: a fully-aggregated Snapshot with `generation` set.
//
// Threading: call from the telemetry thread only. Workers must not
// be touched directly from here — the LcoreCounterView pointers
// alias into live WorkerCtx fields. Reader-side atomic loads satisfy
// TSan; D1 worker-side writes stay plain.
struct RuleIdent {
  std::uint64_t rule_id      = 0;
  std::uint32_t counter_slot = 0;  // absolute (layer_base applied)
  std::uint8_t  layer        = 0;  // 2/3/4
};

Snapshot build_snapshot(std::uint64_t generation,
                        std::span<const LcoreCounterView> lcore_views,
                        std::span<const RuleIdent> per_rule_ids,
                        std::span<const PortStats> port_stats,
                        const ReloadState& reload = ReloadState{},
                        const ActiveRuleCounts& active_rules = ActiveRuleCounts{},
                        std::span<const std::uint8_t> port_link_up = {});

// -------------------------------------------------------------------------
// snapshot_metric_names — enumerate §10.3 metric names the given Snapshot
// actually surfaces (C2 C7.27 — D33 living invariant).
//
// Purpose: the C7.27 runtime enumeration test asks "which §10.3 names are
// wired through the snapshot right now?" and compares that against the
// §10.3 canonical manifest. Names in §10.3 but not in this helper's
// output are either genuinely missing (→ C4 wire-up work) or listed on
// the C7.27 justified-zero list (exempt from the check).
//
// The returned set contains the *base* metric name (no labels). If the
// snapshot has ≥1 per_rule entry, `pktgate_rule_packets_total` etc. are
// emitted; if `per_port` is non-empty, the port family is emitted; scalar
// counters emit their base name unconditionally as long as the snapshot
// was built with the corresponding LcoreCounterView field populated.
//
// C4 grows this set as reload/qinq/frag/truncation/etc. fields get added
// to `Snapshot`. The D33 invariant is lockstep: every §10.3 name → every
// Snapshot field → every producer site. snapshot_metric_names() is one
// link in that chain.
//
// Pure function — DPDK-free, no IO, no threads.
std::set<std::string> snapshot_metric_names(const Snapshot& snap);

}  // namespace pktgate::telemetry
