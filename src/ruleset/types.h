// src/ruleset/types.h
//
// M2 C2 — runtime compound entry types for the Ruleset arenas.
//
// These are the *runtime* representations stored in the Ruleset's
// compound entry arenas. The compiler (rule_compiler, C3-C5) produces
// these; the hot path (M4-M6) reads them during classification.
//
// Design anchors:
//   * D15 — compound primary + filter_mask pattern
//   * D29 — ICMP type->dport, code->sport unification (no separate ICMP field)
//   * §4.1 — struct layouts and sizing invariants

#pragma once

#include <cstdint>

namespace pktgate::ruleset {

// L2CompoundEntry — value stored in L2 primary hash.
//
// Primary hash keys: src_mac or dst_mac (most-selective exact key).
// filter_mask bits cover the secondary L2 constraints checked after
// primary hash hit.
struct L2CompoundEntry {
  std::uint8_t  filter_mask;      // bits: ETHERTYPE|VLAN|PCP|DST_MAC|SRC_MAC
  std::uint8_t  want_pcp;
  std::uint16_t want_ethertype;   // network byte order
  std::uint16_t want_vlan;        // host order
  std::uint8_t  want_mac[6];      // the *other* MAC if both src and dst constrained
  std::uint16_t action_idx;       // index into l2_actions[]
  std::uint16_t _tail_pad;        // hold sizeof at 16 B (matches §4.3 table)
};

static_assert(sizeof(L2CompoundEntry) == 16, "L2CompoundEntry layout drift");

// L4CompoundEntry — value stored in L4 primary hash.
//
// D29 — ICMP unification: §5.4 packs ICMP type into the dport slot
// and ICMP code into the sport slot. Rules that match on ICMP code
// reuse want_src_port for the expected code — no separate ICMP field.
// The SRC_PORT filter_mask bit means "verify the sport slot", whether
// the underlying L4 protocol is TCP/UDP (real source port) or ICMP
// (packed code value).
//
// NOTE: design.md §4.1 comments this as "12 bytes" but the fields
// sum to 10. Sizing invariant deferred to C4 (L4 compound construction)
// where the correct size will be verified. If it needs to be 12,
// _pad2 must become uint32_t or a second pad field is needed.
struct L4CompoundEntry {
  std::uint8_t  filter_mask;      // bits: SRC_PORT|TCP_FLAGS|VRF
  std::uint8_t  tcp_flags_want;
  std::uint8_t  tcp_flags_mask;
  std::uint8_t  _pad;
  std::uint16_t want_src_port;    // host order; ICMP: reused as code slot
  std::uint16_t action_idx;
  std::uint16_t _pad2;            // keeps sizeof a multiple of 4
};

}  // namespace pktgate::ruleset
