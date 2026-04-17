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
#include <span>
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
// Only a representative subset of WorkerCtx counters is surfaced in
// C1; C4 expands this to the full §10.3 set. The field pointers may
// be null if the worker doesn't expose that particular counter (test
// fakes frequently only wire a subset).
struct LcoreCounterView {
  const std::uint64_t* pkt_multiseg_drop_total = nullptr;
  const std::uint64_t* qinq_outer_only_total   = nullptr;
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
// Snapshot — immutable aggregate produced by the 1 Hz telemetry thread.
//
// `generation` is assigned by the publisher on each build; the ring
// buffer uses it to decide latest-slot index and to detect torn
// reads (reader acquire-loads `latest_gen`, then reads the slot
// `latest_gen % N`).
//
// Field set is intentionally small in C1: enough to exercise
// U7.1-U7.4/U7.6. C4 wires the full §10.3 set.
struct Snapshot {
  std::uint64_t generation = 0;

  // Per-lcore scalar sums across all workers (sum-of-lcores).
  std::uint64_t pkt_multiseg_drop_total = 0;
  std::uint64_t qinq_outer_only_total   = 0;

  // Per-rule aggregated rows. `rule_id`-keyed entries only; empty
  // rows (matched_packets == 0 && drops == 0) may be omitted by the
  // publisher — the encoder never emits zero-valued counter lines
  // for rules that never matched, per existing `stats_on_exit`
  // convention (main.cpp:588).
  std::vector<PerRuleCounter> per_rule;

  // Per-port rte_eth_stats snapshot. Indexed by port_id; empty
  // entries are skipped by the encoder.
  std::vector<PortStats> per_port;
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
                        std::span<const PortStats> port_stats);

}  // namespace pktgate::telemetry
