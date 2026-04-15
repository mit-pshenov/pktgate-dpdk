// src/dataplane/classify_l2.h
//
// M4 C1 — classify_l2 skeleton: plumbing + empty-ruleset early exit.
// M4 C2 — compound hash lookup: src_mac/dst_mac/vlan/ethertype/pcp
//          primary probes in selectivity order + filter_mask check (D15).
// M4 C3 — first-match-wins audit (already correct from C2) +
//          VLAN l3_offset dynfield write per D13: l3_offset=14 (untagged)
//          or l3_offset=18 (single 0x8100 VLAN tag); parsed_vlan and
//          parsed_ethertype written to dynfield before dispatch.
// M4 C4 — QinQ outer 0x88A8 accept + qinq_outer_only_total bump (D32).
// M4 C5 — D31 truncation length guards: l2 (< 14 B) and l2_vlan
//          (VLAN TPID at offset 12 but pkt_len < 18). Both bump
//          pkt_truncated_total[where] and return kDrop.
//
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
//   C5           — D31 truncation length guards (l2 / l2_vlan buckets).
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

#include <array>
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
// kDrop:   terminal drop — L2 rule with DROP action matched, or D31 guard.

enum class ClassifyL2Verdict : std::uint8_t {
  kNextL3 = 0,  // L2 pass — proceed to L3 pipeline
  kDrop   = 1,  // terminal drop (rule match or D31 truncation guard)
};

// -------------------------------------------------------------------------
// L2TruncBucket — D31 per-stage truncation counter buckets for classify_l2.
//
// kL2      — frame shorter than minimal Ethernet header (< 14 B).
// kL2Vlan  — frame has a VLAN TPID (0x8100 / 0x88A8) at offset 12 but
//             pkt_len < 18 (no room for the 4-byte VLAN tag to reach the
//             inner ethertype).
//
// Indexed into a std::array<uint64_t, kL2TruncBucketCount> counter storage.
// L3/L4 buckets (l3_v4, l3_v6, l3_v6_frag_ext, l4) land in M5/M6.

enum class L2TruncBucket : std::size_t {
  kL2     = 0,
  kL2Vlan = 1,
};
inline constexpr std::size_t kL2TruncBucketCount = 2;

// Convenience alias used by WorkerCtx and test code.
using L2TruncCtrs = std::array<std::uint64_t, kL2TruncBucketCount>;

// -------------------------------------------------------------------------
// Internal helpers (anonymous namespace in a header — inline-only hot path).

namespace detail {

// D32: returns true if `etype` is a VLAN TPID (0x8100 C-tag or 0x88A8 S-tag).
// Used at the outer ethertype check (offset 12) and at the inner ethertype
// check (offset 16 after one walked tag) to detect true QinQ stacks.
inline bool is_vlan_tpid(std::uint16_t etype) noexcept {
  return etype == 0x8100u || etype == 0x88A8u;
}

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
// Preconditions (enforced by caller via classify_entry_ok, M4 C9):
//   m->nb_segs == 1   (headers-in-first-seg invariant, D39)
//   See src/dataplane/classify_entry.h — shared across L2/L3/L4 stages.
//
// C5 body (full, includes C1/C2/C3/C4 steps):
//   0. D31 guard #1: if pkt_len < 14, bump trunc_ctrs[kL2], return kDrop.
//   1. Empty-ruleset short-circuit (from C1).
//   2. Parse Ethernet header: src_mac, dst_mac, outer ethertype.
//   3. D31 guard #2: if outer ethertype ∈ VLAN TPID AND pkt_len < 18,
//      bump trunc_ctrs[kL2Vlan], return kDrop.
//   4. If outer ethertype ∈ {0x8100, 0x88A8} (VLAN TPID, D32): extract
//      vlan_id and pcp from the 802.1Q TCI; inner ethertype is at offset 16.
//      D32: walk ONE tag only. If the inner ethertype is itself a VLAN TPID
//      (true QinQ stack), bump *qinq_ctr (if non-null) but do NOT drill
//      further. l3_offset stays 18, not 22.
//   5. D13 dynfield write: l3_offset=14 (untagged) or 18 (VLAN/QinQ-outer),
//      parsed_vlan, parsed_ethertype — written before any probe so
//      classify_l3 (M5) always reads the correct byte offset.
//   6. Probe in selectivity order (§5.2, D15, first-match-wins): src_mac
//      → dst_mac → vlan → ethertype → pcp. Each probe:
//      rte_hash_lookup_data, filter_mask check, dispatch on first match.
//   7. Miss: return kNextL3.
//
// qinq_ctr (optional, D32):
//   Pointer to a per-lcore uint64_t counter for QinQ outer-only events.
//   Pass nullptr to skip the bump (backward-compatible default).
//   Worker passes &ctx->qinq_outer_only_total.
//
// trunc_ctrs (optional, D31):
//   Pointer to a L2TruncCtrs array (std::array<uint64_t, 2> indexed by
//   L2TruncBucket). Pass nullptr to skip the bump (backward-compatible).
//   Worker passes &ctx->pkt_truncated_l2.

inline ClassifyL2Verdict classify_l2(struct rte_mbuf* m,
                                     const ruleset::Ruleset& rs,
                                     std::uint64_t* qinq_ctr = nullptr,
                                     L2TruncCtrs*  trunc_ctrs = nullptr) {
  // D39: caller (worker.cpp) has already run classify_entry_ok which
  // enforces nb_segs == 1.  See src/dataplane/classify_entry.h.

  // ---- D31 Guard #1: l2 bucket — frame shorter than minimal Ethernet -------
  // Minimal Ethernet header: dst_mac(6) + src_mac(6) + ethertype(2) = 14 B.
  // Any frame shorter than this cannot be parsed at all.  Fires before any
  // other logic — including empty-ruleset bail and header parse.
  if (rte_pktmbuf_pkt_len(m) < 14u) {
    if (trunc_ctrs) {
      ++(*trunc_ctrs)[static_cast<std::size_t>(L2TruncBucket::kL2)];
    }
    return ClassifyL2Verdict::kDrop;
  }

  // ---- Parse outer ethertype (pkt_len >= 14 guaranteed by guard #1) --------
  // Frame layout:
  //   [0..5]   dst_mac
  //   [6..11]  src_mac
  //   [12..13] ethertype (outer; may be a VLAN TPID)
  //   (further fields only valid if pkt_len >= 18 — guard #2 below)

  const auto* raw = rte_pktmbuf_mtod(m, const std::uint8_t*);

  const std::uint16_t outer_etype =
      static_cast<std::uint16_t>((raw[12] << 8) | raw[13]);

  // ---- D31 Guard #2: l2_vlan bucket — VLAN header truncated ---------------
  // Must fire before the empty-ruleset bail so truncated VLAN frames are
  // always dropped regardless of ruleset state.  After guard #1 we know
  // pkt_len >= 14, so reading raw[12..13] above was safe; but raw[14..17]
  // (VLAN TCI + inner ethertype) is only present when pkt_len >= 18.
  if (detail::is_vlan_tpid(outer_etype) && rte_pktmbuf_pkt_len(m) < 18u) {
    if (trunc_ctrs) {
      ++(*trunc_ctrs)[static_cast<std::size_t>(L2TruncBucket::kL2Vlan)];
    }
    return ClassifyL2Verdict::kDrop;
  }

  // ---- Parse src/dst MACs (pkt_len >= 14 guaranteed, safe) ----------------
  const std::uint64_t src_key = detail::mac_to_u64(raw + 6);
  const std::uint64_t dst_key = detail::mac_to_u64(raw + 0);

  // VLAN extraction: fills local variables used for both the D13 dynfield
  // write and the D15 selectivity probe key.
  std::uint16_t pkt_vlan = 0xFFFFu;   // sentinel: untagged
  std::uint16_t pkt_etype = outer_etype;
  std::uint8_t  pkt_pcp   = 0;

  // D32: both 0x8100 (C-tag) and 0x88A8 (S-tag) are VLAN TPIDs.
  // Walk ONE tag regardless of which TPID is outer.
  if (detail::is_vlan_tpid(outer_etype)) {
    const std::uint16_t tci =
        static_cast<std::uint16_t>((raw[14] << 8) | raw[15]);
    pkt_vlan  = tci & 0x0FFFu;          // vid: bits [11:0]
    pkt_pcp   = static_cast<std::uint8_t>((tci >> 13) & 0x07u);
    pkt_etype = static_cast<std::uint16_t>((raw[16] << 8) | raw[17]);

    // D32: if the inner ethertype is itself a VLAN TPID, this is a true
    // QinQ stack. Bump the counter. We do NOT drill further — l3_offset
    // stays 18, full QinQ is v2 per D32 prose.
    //
    // NOTE: counter bump happens BEFORE the empty-ruleset short-circuit
    // so observability is independent of rule presence (C7 fix).
    if (detail::is_vlan_tpid(pkt_etype) && qinq_ctr != nullptr) {
      ++(*qinq_ctr);
    }
  }

  // ---- D13: write l3_offset, parsed_vlan, parsed_ethertype to dynfield ----
  // Write BEFORE the empty-ruleset short-circuit so classify_l3 (M5) always
  // reads the correct byte offset even when no L2 rules exist (C7 fix —
  // original C1 placement ran the short-circuit before parse, leaving
  // dynfield zero-initialised for empty rulesets).
  //
  // Untagged:       l3_offset = 14, parsed_vlan = 0xFFFF
  // Single VLAN:    l3_offset = 18, parsed_vlan = vid (12 lower bits of TCI)
  // QinQ outer:     l3_offset = 18 (ONE tag walked, inner not drilled, D32)
  {
    auto* dyn = eal::mbuf_dynfield(m);
    dyn->l3_offset        = (pkt_vlan != 0xFFFFu) ? 18u : 14u;
    dyn->parsed_vlan      = pkt_vlan;
    dyn->parsed_ethertype = pkt_etype;
  }

  // Empty-ruleset short-circuit (C1, re-placed by C7 fix).
  // Moved AFTER parse + dynfield write + qinq counter bump so that:
  //   (a) truncation guards still fire first (memory safety)
  //   (b) downstream classify_l3 reads a correct l3_offset
  //   (c) qinq_outer_only_total observability is independent of rule state
  // The short-circuit still skips the selectivity probes, which is the
  // only part that actually needs l2_compound_hash to be populated.
  if (rs.l2_compound_count == 0 || !rs.l2_compound_hash) {
    return ClassifyL2Verdict::kNextL3;
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
