// src/dataplane/classify_l2.h
//
// M4 C1 — classify_l2 skeleton: plumbing + empty-ruleset early exit.
//
// Implements the L2 classification entry point per §5.2.  Full body
// is built incrementally across M4 cycles:
//
//   C1 (this file) — function signature, verdict enum, empty-ruleset
//                    NEXT_L3 short-circuit, wired into worker RX loop.
//   C2             — L2 src_mac / dst_mac compound hash lookup (D15).
//   C3             — first-match-wins + VLAN l3_offset write (D13).
//   C4             — QinQ outer 0x88A8 accept + counter (D32).
//   C5             — truncation length guards (D31).
//
// Design anchors:
//   * §5.2  — classify_l2 full spec
//   * §5.1  — dynfield layout (PktgateDynfield)
//   * D13   — l3_offset per-VLAN-level byte offset
//   * D15   — compound primary + filter_mask
//   * D31   — per-stage truncation sentinels
//   * D32   — QinQ outer 0x88A8 acceptance
//   * D39   — headers-in-first-seg invariant (nb_segs == 1 precondition)
//   * D41   — classify_l2 is the top-level entry point for unit tests C2+

#pragma once

#include <rte_mbuf.h>

#include "src/eal/dynfield.h"
#include "src/ruleset/ruleset.h"

namespace pktgate::dataplane {

// -------------------------------------------------------------------------
// ClassifyL2Verdict — result of classify_l2.
//
// Minimal set for C1.  C2-C5 do not add new verdicts; DROP is here so
// the worker can distinguish final-drop from pass-through.
// TERMINAL_DROP is kept in sync with eal::kTerminalDrop for the dynfield,
// but this enum is the caller-facing return type (no dynfield write in C1).

enum class ClassifyL2Verdict : std::uint8_t {
  kNextL3 = 0,  // L2 pass — proceed to L3 pipeline
  kDrop   = 1,  // terminal drop
};

// -------------------------------------------------------------------------
// classify_l2 — top-level L2 classification entry point (§5.2).
//
// Preconditions (enforced by caller / worker.cpp D39 guard):
//   m->nb_segs == 1   (headers-in-first-seg invariant)
//
// C1 body: if the ruleset has no L2 compound entries, return kNextL3.
// This is the "empty ruleset" short-circuit — no rules means every
// packet passes through L2 and proceeds to L3.
//
// TODO C2: compound hash lookup via rte_hash_lookup / filter_mask check.
// TODO C3: VLAN parsing + l3_offset write into dynfield (D13).
// TODO C4: QinQ outer 0x88A8 accept + qinq_outer_only_total bump (D32).
// TODO C5: D31 truncation length guards at l2 / l2_vlan buckets.

inline ClassifyL2Verdict classify_l2(struct rte_mbuf* m,
                                     const ruleset::Ruleset& rs) {
  // D39: caller is responsible for ensuring nb_segs == 1 before calling.
  // In release builds with C9+ the guard will be promoted to a shared
  // classify_entry helper; for C1 we trust the worker's pre-check.

  // m is unused in the C1 skeleton (no packet parsing yet).
  // C2+ will read eth header fields from m.
  (void)m;

  // Empty-ruleset short-circuit: if no L2 compound entries are loaded,
  // every packet falls through to L3 (no rules = no L2 constraints).
  if (rs.l2_compound_count == 0) {
    return ClassifyL2Verdict::kNextL3;
  }

  // TODO C2: rte_hash_lookup(rs.l2_compound_hash, &primary_key)
  //          + filter_mask secondary validation.
  // For now, any non-empty ruleset also returns NEXT_L3 (miss path).
  // This placeholder is replaced in C2.
  return ClassifyL2Verdict::kNextL3;
}

}  // namespace pktgate::dataplane
