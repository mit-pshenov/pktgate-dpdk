// src/telemetry/snapshot.cpp
//
// M10 C1 — build_snapshot impl.
//
// Pure aggregation — no DPDK, no threads, no IO. The reader-side
// relaxed-atomic load on WorkerCtx counter sources satisfies TSan
// without forcing worker-side atomics (D1 amendment 2026-04-17).

#include "src/telemetry/snapshot.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <span>
#include <string>

namespace pktgate::telemetry {

namespace {

// Reader-side relaxed load — single `mov` on x86-64, no fence.
// Paired with plain worker-side writes (D1 sacred: worker side stays
// non-atomic; reader side uses __atomic_load_n to make TSan see the
// access as synchronising).
inline std::uint64_t relaxed_load_u64(const std::uint64_t* p) {
  if (p == nullptr) return 0;
  return __atomic_load_n(p, __ATOMIC_RELAXED);
}

}  // namespace

Snapshot build_snapshot(std::uint64_t generation,
                        std::span<const LcoreCounterView> lcore_views,
                        std::span<const RuleIdent> per_rule_ids,
                        std::span<const PortStats> port_stats) {
  Snapshot out;
  out.generation = generation;

  // -- Per-lcore scalar sums --------------------------------------
  // Sum each WorkerCtx scalar across all live lcores. Relaxed loads
  // on the source; worker side stays plain non-atomic.
  for (const auto& view : lcore_views) {
    out.pkt_multiseg_drop_total +=
        relaxed_load_u64(view.pkt_multiseg_drop_total);
    out.qinq_outer_only_total +=
        relaxed_load_u64(view.qinq_outer_only_total);
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

  return out;
}

// -------------------------------------------------------------------------
// snapshot_metric_names — see header. Emits §10.3 base names for every
// Snapshot field the current (M10 C1) struct surfaces. C4 extends this
// as reload/qinq/frag/truncation/etc. fields get wired.
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

  // Scalar lcore counters wired in M10 C1. Unconditionally surfaced
  // (a zero snapshot value is still a valid observation — the field
  // exists on Snapshot and round-trips through the encoder).
  names.insert("pktgate_lcore_pkt_multiseg_drop_total");
  names.insert("pktgate_lcore_qinq_outer_only_total");

  return names;
}

}  // namespace pktgate::telemetry
