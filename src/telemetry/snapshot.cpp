// src/telemetry/snapshot.cpp
//
// M10 C1   — build_snapshot impl.
// M10 C4   — extended to aggregate every §10.3 name via LcoreCounterView
//            pointer fields (D31 truncation, D40 fragments, D20/D27 IPv6
//            skip, D25 backstop, D19 TAG no-op, D16 redirect drop) plus
//            ReloadState + ActiveRuleCounts + per_port_link_up.
// M11 C1.5 — writer side corrected: per-lcore counters are bumped by
//            the worker via dataplane::relaxed_bump (RELAXED
//            load+store pair) so the access is atomic on both ends.
//
// Pure aggregation — no DPDK, no threads, no IO.
//
// Concurrency model (D1 amendment §telemetry counter clause, 2026-04-17):
//
//   * WRITER: the owning worker lcore, at packet-rate. Uses
//     dataplane::relaxed_bump(p) = __atomic_store_n(p,
//     __atomic_load_n(p, RELAXED) + 1, RELAXED). On x86-64 this lowers
//     to plain `mov; inc; mov` — no `lock` prefix, no bus fence, no
//     cache-line ownership transfer. Functionally indistinguishable
//     from a plain `++(*p)` on the single-writer CPU; the load+store
//     pair is the TSan synchronisation annotation, not an inter-CPU
//     fence. D1 hot-path philosophy preserved.
//
//   * READER: this file. `__atomic_load_n(p, RELAXED)` — single `mov`
//     on x86-64.
//
//   * Pairing: the C++ memory model requires BOTH sides of a
//     concurrent access to be atomic operations on the same storage
//     for TSan to treat the pair as synchronising. Before M11 C1.5
//     the writer used a plain `++(*p)` RMW — that is a data race
//     against the atomic load here, reported every time (seen at M10
//     C5 in classify_l3.h bumps against relaxed_load_u64). The fix
//     makes the writer side atomic as well; codegen is unchanged on
//     x86-64 because single-writer means no LOCK is required for
//     correctness, only for cross-CPU RMW ordering that we explicitly
//     do not need here.

#include "src/telemetry/snapshot.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <span>
#include <string>

namespace pktgate::telemetry {

namespace {

// Reader-side relaxed load — single `mov` on x86-64, no fence.
// Pairs with dataplane::relaxed_bump / relaxed_add on the worker side
// (M11 C1.5). Both sides atomic is required by the C++ memory model
// for TSan to treat the pair as synchronising; see the file header.
inline std::uint64_t relaxed_load_u64(const std::uint64_t* p) {
  if (p == nullptr) return 0;
  return __atomic_load_n(p, __ATOMIC_RELAXED);
}

// Array-bucket relaxed load: sums (p[0..n)) via per-slot relaxed loads.
// Returns zero if p is null. Used for the L2/L3/L4 truncation and the
// L3 fragment bucket arrays — each slot is its own scalar counter.
// Writer-side pair is dataplane::relaxed_bump_bucket.
inline std::uint64_t relaxed_load_bucket(const std::uint64_t* p,
                                         std::uint32_t idx) {
  if (p == nullptr) return 0;
  return __atomic_load_n(p + idx, __ATOMIC_RELAXED);
}

}  // namespace

Snapshot build_snapshot(std::uint64_t generation,
                        std::span<const LcoreCounterView> lcore_views,
                        std::span<const RuleIdent> per_rule_ids,
                        std::span<const PortStats> port_stats,
                        const ReloadState& reload,
                        const ActiveRuleCounts& active_rules,
                        std::span<const std::uint8_t> port_link_up) {
  Snapshot out;
  out.generation = generation;

  // -- Per-lcore scalar sums --------------------------------------
  // Sum each WorkerCtx scalar across all live lcores. Relaxed loads
  // on the source; worker side stays plain non-atomic.
  //
  // C4 — every LcoreCounterView pointer field gets a relaxed load.
  // Null pointers contribute 0 (fixtures may wire only a subset).
  for (const auto& view : lcore_views) {
    out.pkt_multiseg_drop_total +=
        relaxed_load_u64(view.pkt_multiseg_drop_total);
    out.qinq_outer_only_total +=
        relaxed_load_u64(view.qinq_outer_only_total);

    // D31 truncation buckets. The worker owns a std::array<uint64_t,
    // kL{2,3,4}TruncBucketCount>; we sum each bucket across lcores
    // into the corresponding Snapshot scalar. Buckets mapped to the
    // §10.3 `where` label: l2, l2_vlan, l3_v4, l3_v6, l3_v6_frag_ext,
    // l4 — six names in total after the encoder splits by where.
    if (view.pkt_truncated_l2 != nullptr) {
      if (view.pkt_truncated_l2_count >= 1) {
        out.pkt_truncated_l2 +=
            relaxed_load_bucket(view.pkt_truncated_l2, 0);
      }
      if (view.pkt_truncated_l2_count >= 2) {
        out.pkt_truncated_l2_vlan +=
            relaxed_load_bucket(view.pkt_truncated_l2, 1);
      }
    }
    if (view.pkt_truncated_l3 != nullptr) {
      if (view.pkt_truncated_l3_count >= 1) {
        out.pkt_truncated_l3_v4 +=
            relaxed_load_bucket(view.pkt_truncated_l3, 0);
      }
      if (view.pkt_truncated_l3_count >= 2) {
        out.pkt_truncated_l3_v6 +=
            relaxed_load_bucket(view.pkt_truncated_l3, 1);
      }
      if (view.pkt_truncated_l3_count >= 3) {
        out.pkt_truncated_l3_v6_frag_ext +=
            relaxed_load_bucket(view.pkt_truncated_l3, 2);
      }
    }
    if (view.pkt_truncated_l4 != nullptr &&
        view.pkt_truncated_l4_count >= 1) {
      out.pkt_truncated_l4 +=
          relaxed_load_bucket(view.pkt_truncated_l4, 0);
    }

    // D40 fragment buckets. 4 slots:
    //   0 = kL3FragDroppedV4, 1 = kL3FragSkippedV4,
    //   2 = kL3FragDroppedV6, 3 = kL3FragSkippedV6
    if (view.pkt_frag_l3 != nullptr) {
      if (view.pkt_frag_l3_count >= 1) {
        out.pkt_frag_dropped_v4 +=
            relaxed_load_bucket(view.pkt_frag_l3, 0);
      }
      if (view.pkt_frag_l3_count >= 2) {
        out.pkt_frag_skipped_v4 +=
            relaxed_load_bucket(view.pkt_frag_l3, 1);
      }
      if (view.pkt_frag_l3_count >= 3) {
        out.pkt_frag_dropped_v6 +=
            relaxed_load_bucket(view.pkt_frag_l3, 2);
      }
      if (view.pkt_frag_l3_count >= 4) {
        out.pkt_frag_skipped_v6 +=
            relaxed_load_bucket(view.pkt_frag_l3, 3);
      }
    }

    // D20 / D27 / D25 / D19 / D16 — scalar lcore counters.
    out.l4_skipped_ipv6_extheader_total +=
        relaxed_load_u64(view.l4_skipped_ipv6_extheader);
    out.l4_skipped_ipv6_fragment_nonfirst_total +=
        relaxed_load_u64(view.l4_skipped_ipv6_fragment_nonfirst);
    out.dispatch_unreachable_total +=
        relaxed_load_u64(view.dispatch_unreachable_total);
    out.tag_pcp_noop_untagged_total +=
        relaxed_load_u64(view.tag_pcp_noop_untagged_total);
    out.redirect_dropped_total +=
        relaxed_load_u64(view.redirect_dropped_total);

    // M14 C3 — D43 per-port backpressure. Grow the rollup vectors to
    // the max count seen across views and element-wise sum each
    // port's counter. Null pointer contributes 0 (count-guarded).
    if (view.tx_dropped_per_port != nullptr &&
        view.tx_dropped_per_port_count > 0) {
      if (out.tx_dropped_per_port.size() < view.tx_dropped_per_port_count) {
        out.tx_dropped_per_port.resize(view.tx_dropped_per_port_count, 0u);
      }
      for (std::uint32_t i = 0; i < view.tx_dropped_per_port_count; ++i) {
        out.tx_dropped_per_port[i] +=
            relaxed_load_bucket(view.tx_dropped_per_port, i);
      }
    }
    if (view.tx_burst_short_per_port != nullptr &&
        view.tx_burst_short_per_port_count > 0) {
      if (out.tx_burst_short_per_port.size() <
          view.tx_burst_short_per_port_count) {
        out.tx_burst_short_per_port.resize(
            view.tx_burst_short_per_port_count, 0u);
      }
      for (std::uint32_t i = 0; i < view.tx_burst_short_per_port_count;
           ++i) {
        out.tx_burst_short_per_port[i] +=
            relaxed_load_bucket(view.tx_burst_short_per_port, i);
      }
    }

    // M16 C2 — D7 per-port mirror dispatch. Same pattern as the D43
    // tx arrays above: grow the rollup vectors, element-wise sum.
    if (view.mirror_sent_per_port != nullptr &&
        view.mirror_sent_per_port_count > 0) {
      if (out.mirror_sent_per_port.size() <
          view.mirror_sent_per_port_count) {
        out.mirror_sent_per_port.resize(
            view.mirror_sent_per_port_count, 0u);
      }
      for (std::uint32_t i = 0; i < view.mirror_sent_per_port_count; ++i) {
        out.mirror_sent_per_port[i] +=
            relaxed_load_bucket(view.mirror_sent_per_port, i);
      }
    }
    if (view.mirror_clone_failed_per_port != nullptr &&
        view.mirror_clone_failed_per_port_count > 0) {
      if (out.mirror_clone_failed_per_port.size() <
          view.mirror_clone_failed_per_port_count) {
        out.mirror_clone_failed_per_port.resize(
            view.mirror_clone_failed_per_port_count, 0u);
      }
      for (std::uint32_t i = 0;
           i < view.mirror_clone_failed_per_port_count; ++i) {
        out.mirror_clone_failed_per_port[i] +=
            relaxed_load_bucket(view.mirror_clone_failed_per_port, i);
      }
    }
    if (view.mirror_dropped_per_port != nullptr &&
        view.mirror_dropped_per_port_count > 0) {
      if (out.mirror_dropped_per_port.size() <
          view.mirror_dropped_per_port_count) {
        out.mirror_dropped_per_port.resize(
            view.mirror_dropped_per_port_count, 0u);
      }
      for (std::uint32_t i = 0; i < view.mirror_dropped_per_port_count;
           ++i) {
        out.mirror_dropped_per_port[i] +=
            relaxed_load_bucket(view.mirror_dropped_per_port, i);
      }
    }
  }

  // -- Per-rule sums ----------------------------------------------
  // For each rule, sum the RuleCounter row across all lcores at the
  // rule's counter_slot. Rules with zero traffic across all lcores
  // are omitted (mirrors main.cpp:588 stats_on_exit convention —
  // no wire-protocol value in emitting zero counter lines, and it
  // keeps /metrics cardinality bounded to rules that actually hit).
  out.per_rule.reserve(per_rule_ids.size());
  for (const auto& ident : per_rule_ids) {
    PerRuleCounter agg;
    agg.rule_id = ident.rule_id;
    agg.layer   = ident.layer;

    for (const auto& view : lcore_views) {
      if (view.counter_row == nullptr) continue;
      if (ident.counter_slot >= view.n_slots) continue;
      const auto& row = view.counter_row[ident.counter_slot];
      // RuleCounter fields are plain uint64_t written by the owning
      // lcore. Reader-side relaxed load on each — takes the address
      // of each field explicitly so __atomic_load_n sees a scalar.
      agg.matched_packets += relaxed_load_u64(&row.matched_packets);
      agg.matched_bytes   += relaxed_load_u64(&row.matched_bytes);
      agg.drops           += relaxed_load_u64(&row.drops);
      agg.rl_drops        += relaxed_load_u64(&row.rl_drops);
    }

    // Skip rules with no observed traffic at all — same rule as
    // stats_on_exit.
    if (agg.matched_packets == 0 && agg.matched_bytes == 0 &&
        agg.drops == 0 && agg.rl_drops == 0) {
      continue;
    }
    out.per_rule.push_back(agg);
  }

  // -- Per-port stats ---------------------------------------------
  // Straight copy — the caller has already populated PortStats from
  // rte_eth_stats_get (or a test fake). The ports are not
  // cross-thread shared state; this is just a value-copy.
  out.per_port.assign(port_stats.begin(), port_stats.end());

  // -- Per-port link-up gauge -------------------------------------
  // Parallel to per_port; indices align. If port_link_up is shorter
  // than port_stats, missing tail is padded with zero (link-down
  // default). Caller may pass empty span to skip the gauge entirely.
  out.per_port_link_up.assign(port_link_up.begin(), port_link_up.end());
  if (out.per_port_link_up.size() < out.per_port.size()) {
    out.per_port_link_up.resize(out.per_port.size(), 0u);
  }

  // -- Reload state + active ruleset counts ------------------------
  // Copied from caller — the publisher takes reload::counters_snapshot()
  // under reload_mutex (D35) so there's no torn read on the source
  // side. ActiveRuleCounts is filled from active_ruleset()->n_l{2,3,4}_rules.
  out.reload       = reload;
  out.active_rules = active_rules;

  // -- Publisher liveness gauge -----------------------------------
  // Mirror the writer-assigned generation into the exposition field.
  // F8.13 observes this across a slow-reader scrape to prove the
  // 1 Hz writer is not blocked by a stalled scraper.
  out.publisher_generation_gauge = generation;

  return out;
}

// -------------------------------------------------------------------------
// snapshot_metric_names — see header. Emits §10.3 base names for every
// Snapshot field the current struct surfaces. C4 grew this to the full
// §10.3 non-Phase-2 set.
std::set<std::string> snapshot_metric_names(const Snapshot& snap) {
  std::set<std::string> names;

  // Per-rule family — emitted whenever the snapshot carries >= 1 rule
  // row. Zero rules means no L2/L3/L4 traffic observed; the encoder
  // convention is "no counter line emitted" (mirrors stats_on_exit
  // at main.cpp:588). For D33 purposes the family is still considered
  // "wired" as long as the aggregation path exists — the test feeds
  // at least one rule to exercise all three names in the same call.
  if (!snap.per_rule.empty()) {
    names.insert("pktgate_rule_packets_total");
    names.insert("pktgate_rule_bytes_total");
    names.insert("pktgate_rule_drops_total");
  }

  // Per-port family — emitted whenever the publisher surfaced any
  // PortStats. Single port is enough to prove the 6-metric family is
  // routed.
  if (!snap.per_port.empty()) {
    names.insert("pktgate_port_rx_packets_total");
    names.insert("pktgate_port_tx_packets_total");
    names.insert("pktgate_port_rx_bytes_total");
    names.insert("pktgate_port_tx_bytes_total");
    names.insert("pktgate_port_rx_dropped_total");
    names.insert("pktgate_port_tx_dropped_total");
  }

  // C4 — port link-up gauge. Surfaces whenever the publisher populated
  // per_port_link_up (or it was auto-padded from per_port).
  if (!snap.per_port_link_up.empty()) {
    names.insert("pktgate_port_link_up");
  }

  // Scalar lcore counters wired in M10 C1 — always surfaced (a zero
  // Snapshot value is still a valid observation; the field exists on
  // Snapshot and round-trips through the encoder).
  names.insert("pktgate_lcore_pkt_multiseg_drop_total");
  names.insert("pktgate_lcore_qinq_outer_only_total");

  // C4 — D31 truncation rollup. One §10.3 name with a `where` label;
  // the encoder splits by bucket. Snapshot surfaces all six buckets
  // as separate scalar fields, but the base metric name is single.
  names.insert("pktgate_lcore_pkt_truncated_total");

  // C4 — D40 fragment rollups. Two §10.3 names with `af` label.
  names.insert("pktgate_lcore_pkt_frag_skipped_total");
  names.insert("pktgate_lcore_pkt_frag_dropped_total");

  // C4 — D20 / D27 IPv6 skip counters.
  names.insert("pktgate_lcore_l4_skipped_ipv6_extheader_total");
  names.insert("pktgate_lcore_l4_skipped_ipv6_fragment_nonfirst_total");

  // C4 — D25 runtime backstop + D19 TAG PCP no-op + D16 REDIRECT drop.
  names.insert("pktgate_lcore_dispatch_unreachable_total");
  names.insert("pktgate_lcore_tag_pcp_noop_untagged_total");
  names.insert("pktgate_redirect_dropped_total");

  // C4 — default-action fallthrough counter. Surfaced with the
  // `action="allow|drop"` label; single base name.
  names.insert("pktgate_default_action_total");

  // C4 — reload family. The ReloadState sub-struct always contributes
  // these names (values may be zero at boot; presence still routes).
  names.insert("pktgate_reload_total");
  names.insert("pktgate_reload_latency_seconds");
  names.insert("pktgate_reload_pending_free_depth");
  names.insert("pktgate_active_generation");

  // C4 — active ruleset rule counts by layer.
  names.insert("pktgate_active_rules");

  // C5 — publisher liveness gauge (F8.13 / D3). Always surfaced; the
  // publisher always stamps `publisher_generation_gauge = generation`.
  names.insert("pktgate_publisher_generation");

  // M14 C3 — D43 per-port backpressure counter families. Always
  // surfaced as base names (presence contract — per-port label
  // cardinality is 0 when no view exposes the arrays; a zero-width
  // snapshot still routes the name through D33). Mirrors the
  // handling of port_link_up / lcore scalar counters above.
  names.insert("pktgate_tx_dropped_total");
  names.insert("pktgate_tx_burst_short_total");

  // M16 C2 — D7 mirror dispatch counter triplet. Always surfaced
  // (presence contract, same as D43 tx counters above). Per-port
  // label cardinality is 0 when no view exposes the arrays.
  names.insert("pktgate_mirror_sent_total");
  names.insert("pktgate_mirror_clone_failed_total");
  names.insert("pktgate_mirror_dropped_total");

  return names;
}

}  // namespace pktgate::telemetry
