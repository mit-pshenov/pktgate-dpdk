// src/dataplane/classify_l2.h
//
// M4 C1 — classify_l2 skeleton: plumbing + empty-ruleset early exit.
// M4 C2 — compound hash lookup: src_mac/dst_mac/vlan/ethertype/pcp
//          primary probes in selectivity order + filter_mask check (D15).
// M4 C3 — first-match-wins audit (already correct from C2) +
//          VLAN l3_offset dynfield write per D13: l3_offset=14 (untagged)
//          or l3_offset=18 (single 0x8100 VLAN tag); parsed_vlan and
//          parsed_ethertype written to dynfield before dispatch.
// Implements the L2 classification entry point per §5.2.  Full body
// is built incrementally across M4 cycles:
//
//   C1 (see git) — function signature, verdict enum, empty-ruleset
//                  NEXT_L3 short-circuit, wired into worker RX loop.
//   C2 (see git) — compound hash lookup via rte_hash_lookup_data,
//                 selectivity-ordered probing, filter_mask secondary check,
//                 verdict dispatch, dynfield verdict_action_idx write.
//                 Minimal VLAN extraction for selectivity probing (vlan
//                 primary key only); l3_offset dynfield write deferred C3.
//   C3 (this)   — first-match-wins audit (C2 already returns on first hit,
//                 no structural change needed).  D13 dynfield write added:
//                 l3_offset, parsed_vlan, parsed_ethertype written to mbuf
//                 dynfield before the selectivity probes, so classify_l3
//                 (M5) can read the correct byte offset.
//                 Single-VLAN (0x8100) only; QinQ (0x88A8) deferred C4.
//   C4           — QinQ outer 0x88A8 accept + counter (D32).
//   C5           — truncation length guards (D31).
//
// Design anchors:
//   * §5.2  — classify_l2 full spec
//   * §5.1  — dynfield layout (PktgateDynfield)
//   * D13   — l3_offset per-VLAN-level byte offset (C3)
//   * D15   — compound primary + filter_mask
//   * D31   — per-stage truncation sentinels (C5)
//   * D32   — QinQ outer 0x88A8 acceptance (C4)
//   * D39   — headers-in-first-seg invariant (nb_segs == 1 precondition)
//   * D41   — classify_l2 is the top-level entry point for unit tests C2+

#pragma once

#include <cstdint>
#include <cstring>

#include <rte_hash.h>
#include <rte_mbuf.h>

#include "src/action/action.h"
#include "src/compiler/rule_compiler.h"   // l2_mask:: constants
#include "src/eal/dynfield.h"
#include "src/ruleset/ruleset.h"
#include "src/ruleset/types.h"

namespace pktgate::dataplane {

// -------------------------------------------------------------------------
// ClassifyL2Verdict — result of classify_l2.
//
// kNextL3: L2 pass — proceed to L3 (empty ruleset miss OR ALLOW action).
// kDrop:   terminal drop — L2 rule with DROP action matched.

enum class ClassifyL2Verdict : std::uint8_t {
  kNextL3 = 0,  // L2 pass — proceed to L3 pipeline
  kDrop   = 1,  // terminal drop
};

// -------------------------------------------------------------------------
// Internal helpers (anonymous namespace in a header — inline-only hot path).

namespace detail {

// Pack a 6-byte MAC (bytes[0..5]) into a uint64_t with bytes in memory
// order (low byte = bytes[0]), high 2 bytes zero. Matches mac_to_u64 in
// rule_compiler.cpp exactly so hash key packing is consistent.
inline std::uint64_t mac_to_u64(const std::uint8_t* b) {
  std::uint64_t v = 0;
  std::memcpy(&v, b, 6);  // little-endian: b[0] → byte 0 of v
  return v;
}

// Check all filter_mask secondary fields against the packet.
//
// Parameters mirror the packet fields extracted in classify_l2:
//   e           — the compound entry (filter_mask + want_* fields)
//   other_mac   — the "other" MAC (dst if primary was src, and vice versa)
//   pkt_vlan    — parsed vlan id (0xFFFF if untagged)
//   pkt_etype   — ethertype (inner after VLAN strip, if tagged; outer if not)
//   pkt_pcp     — PCP bits (0 if untagged)
//
// Returns true if all secondary constraints pass (or the filter_mask bit
// for that field is not set).
inline bool l2_filter_ok(const ruleset::L2CompoundEntry* e,
                         std::uint64_t other_mac,
                         std::uint16_t pkt_vlan,
                         std::uint16_t pkt_etype,
                         std::uint8_t  pkt_pcp) {
  using namespace compiler::l2_mask;

  if ((e->filter_mask & kDstMac) || (e->filter_mask & kSrcMac)) {
    // want_mac holds the other-MAC constraint when both src and dst
    // are in the rule. Compare as u64 (same pack as mac_to_u64).
    std::uint64_t want = 0;
    std::memcpy(&want, e->want_mac, 6);
    if (other_mac != want) return false;
  }
  if (e->filter_mask & kVlan) {
    if (pkt_vlan != e->want_vlan) return false;
  }
  if (e->filter_mask & kEthertype) {
    if (pkt_etype != e->want_ethertype) return false;
  }
  if (e->filter_mask & kPcp) {
    if (pkt_pcp != e->want_pcp) return false;
  }
  return true;
}

// Dispatch a matched L2 compound entry: write dynfield verdict_action_idx,
// return the appropriate ClassifyL2Verdict based on action verb.
inline ClassifyL2Verdict l2_dispatch(struct rte_mbuf* m,
                                     const ruleset::Ruleset& rs,
                                     const ruleset::L2CompoundEntry* e) {
  const std::uint16_t idx = e->action_idx;
  auto* dyn = eal::mbuf_dynfield(m);
  dyn->verdict_action_idx = idx;

  // Guard: if l2_actions is nullptr (no builder ran), default to drop.
  if (!rs.l2_actions || idx >= rs.n_l2_rules) {
    return ClassifyL2Verdict::kDrop;
  }

  const auto verb = static_cast<compiler::ActionVerb>(
      rs.l2_actions[idx].verb);
  switch (verb) {
    case compiler::ActionVerb::kAllow:
      return ClassifyL2Verdict::kNextL3;
    case compiler::ActionVerb::kDrop:
      return ClassifyL2Verdict::kDrop;
    case compiler::ActionVerb::kMirror:
    case compiler::ActionVerb::kRateLimit:
    case compiler::ActionVerb::kTag:
    case compiler::ActionVerb::kRedirect:
      // Mirror/RL/Tag/Redirect in L2 context: pass to L3 for now.
      // Full dispatch for these verbs lands in later cycles.
      return ClassifyL2Verdict::kNextL3;
  }
  return ClassifyL2Verdict::kNextL3;  // unreachable
}

// Try a single hash probe: lookup `key` in `hash`, on hit validate
// filter_mask and dispatch. Returns nullopt if miss or filter fails.
inline ClassifyL2Verdict l2_try_probe(struct rte_mbuf* m,
                                      const ruleset::Ruleset& rs,
                                      struct rte_hash* hash,
                                      std::uint64_t key,
                                      std::uint64_t other_mac,
                                      std::uint16_t pkt_vlan,
                                      std::uint16_t pkt_etype,
                                      std::uint8_t  pkt_pcp,
                                      bool& hit) {
  void* data = nullptr;
  int ret = rte_hash_lookup_data(hash, &key, &data);
  if (ret < 0 || !data) {
    hit = false;
    return ClassifyL2Verdict::kNextL3;
  }
  const auto* e = static_cast<const ruleset::L2CompoundEntry*>(data);
  if (!l2_filter_ok(e, other_mac, pkt_vlan, pkt_etype, pkt_pcp)) {
    hit = false;
    return ClassifyL2Verdict::kNextL3;
  }
  hit = true;
  return l2_dispatch(m, rs, e);
}

}  // namespace detail

// -------------------------------------------------------------------------
// classify_l2 — top-level L2 classification entry point (§5.2).
//
// Preconditions (enforced by caller / worker.cpp D39 guard):
//   m->nb_segs == 1   (headers-in-first-seg invariant)
//
// C3 body (full, includes C1/C2 steps):
//   1. Empty-ruleset short-circuit (from C1).
//   2. Parse Ethernet header: src_mac, dst_mac, outer ethertype.
//   3. If outer ethertype == 0x8100 (single VLAN): extract vlan_id and
//      pcp from the 802.1Q TCI; inner ethertype is at offset 16.
//      QinQ (0x88A8) outer detection is deferred to C4.
//   4. D13 dynfield write: l3_offset=14 (untagged) or 18 (single VLAN),
//      parsed_vlan, parsed_ethertype — written before any probe so
//      classify_l3 (M5) always reads the correct byte offset.
//   5. Probe in selectivity order (§5.2, D15, first-match-wins): src_mac
//      → dst_mac → vlan → ethertype → pcp. Each probe:
//      rte_hash_lookup_data, filter_mask check, dispatch on first match.
//   6. Miss: return kNextL3.
//
// TODO C4: QinQ outer 0x88A8 accept + qinq_outer_only_total bump (D32).
// TODO C5: D31 truncation length guards at l2 / l2_vlan buckets.

inline ClassifyL2Verdict classify_l2(struct rte_mbuf* m,
                                     const ruleset::Ruleset& rs) {
  // D39: caller is responsible for ensuring nb_segs == 1 before calling.

  // Empty-ruleset short-circuit (C1).
  if (rs.l2_compound_count == 0 || !rs.l2_compound_hash) {
    return ClassifyL2Verdict::kNextL3;
  }

  // ---- Parse Ethernet header ------------------------------------------------
  // Frame layout (untagged):
  //   [0..5]   dst_mac
  //   [6..11]  src_mac
  //   [12..13] ethertype
  //
  // Frame layout (802.1Q tagged, outer ethertype == 0x8100):
  //   [0..5]   dst_mac
  //   [6..11]  src_mac
  //   [12..13] outer ethertype = 0x8100
  //   [14..15] TCI (pcp[15:13] + cfi[12] + vid[11:0])
  //   [16..17] inner ethertype

  const auto* raw = rte_pktmbuf_mtod(m, const std::uint8_t*);

  const std::uint64_t src_key = detail::mac_to_u64(raw + 6);
  const std::uint64_t dst_key = detail::mac_to_u64(raw + 0);

  const std::uint16_t outer_etype =
      static_cast<std::uint16_t>((raw[12] << 8) | raw[13]);

  // VLAN extraction: fills local variables used for both the D13 dynfield
  // write and the D15 selectivity probe key.
  std::uint16_t pkt_vlan = 0xFFFFu;   // sentinel: untagged
  std::uint16_t pkt_etype = outer_etype;
  std::uint8_t  pkt_pcp   = 0;

  if (outer_etype == 0x8100u) {
    const std::uint16_t tci =
        static_cast<std::uint16_t>((raw[14] << 8) | raw[15]);
    pkt_vlan  = tci & 0x0FFFu;          // vid: bits [11:0]
    pkt_pcp   = static_cast<std::uint8_t>((tci >> 13) & 0x07u);
    pkt_etype = static_cast<std::uint16_t>((raw[16] << 8) | raw[17]);
  }
  // QinQ 0x88A8 outer — C4 territory. No additional parsing here.

  // ---- D13: write l3_offset, parsed_vlan, parsed_ethertype to dynfield ----
  // Write before the selectivity probes so classify_l3 (M5) always reads
  // the correct byte offset regardless of which probe (if any) hits.
  //
  // Untagged:       l3_offset = 14, parsed_vlan = 0xFFFF
  // Single VLAN:    l3_offset = 18, parsed_vlan = vid (12 lower bits of TCI)
  // QinQ (C4):      l3_offset = 22 (deferred — C4 writes this)
  {
    auto* dyn = eal::mbuf_dynfield(m);
    dyn->l3_offset        = (pkt_vlan != 0xFFFFu) ? 18u : 14u;
    dyn->parsed_vlan      = pkt_vlan;
    dyn->parsed_ethertype = pkt_etype;
  }

  // ---- Selectivity-ordered probing (§5.2, D15) ----------------------------
  // Order: src_mac > dst_mac > vlan > ethertype > pcp.
  // All primaries live in the same l2_compound_hash; we probe with
  // different key values per slot. A hit returns an L2CompoundEntry*
  // whose filter_mask describes secondary constraints to verify.

  struct rte_hash* h = rs.l2_compound_hash;
  bool hit = false;
  ClassifyL2Verdict v;

  // 1. src_mac probe (key = packed src MAC, other = packed dst MAC).
  v = detail::l2_try_probe(m, rs, h, src_key, dst_key,
                           pkt_vlan, pkt_etype, pkt_pcp, hit);
  if (hit) return v;

  // 2. dst_mac probe (key = packed dst MAC, other = packed src MAC).
  v = detail::l2_try_probe(m, rs, h, dst_key, src_key,
                           pkt_vlan, pkt_etype, pkt_pcp, hit);
  if (hit) return v;

  // 3. vlan probe (key = vlan_id zero-extended to u64).
  if (pkt_vlan != 0xFFFFu) {
    const std::uint64_t vlan_key = static_cast<std::uint64_t>(pkt_vlan);
    v = detail::l2_try_probe(m, rs, h, vlan_key, 0,
                             pkt_vlan, pkt_etype, pkt_pcp, hit);
    if (hit) return v;
  }

  // 4. ethertype probe (key = ethertype zero-extended to u64).
  {
    const std::uint64_t etype_key = static_cast<std::uint64_t>(pkt_etype);
    v = detail::l2_try_probe(m, rs, h, etype_key, 0,
                             pkt_vlan, pkt_etype, pkt_pcp, hit);
    if (hit) return v;
  }

  // 5. pcp probe (key = pcp zero-extended to u64).
  {
    const std::uint64_t pcp_key = static_cast<std::uint64_t>(pkt_pcp);
    v = detail::l2_try_probe(m, rs, h, pcp_key, 0,
                             pkt_vlan, pkt_etype, pkt_pcp, hit);
    if (hit) return v;
  }

  // Miss: no L2 rule matched. Proceed to L3.
  return ClassifyL2Verdict::kNextL3;
}

}  // namespace pktgate::dataplane
