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

// L3CompoundEntry — value stored in the L3 FIB next_hop slot.
//
// M4 C0 retrofit (D41). Primary key is the destination prefix stored
// directly in the rte_fib / rte_fib6 table; this entry holds the
// action index plus any secondary filter bits (src prefix / vrf).
// The FIB's next_hop slot is a 64-bit opaque value — we pack
// action_idx + filter_mask + valid_tag into the low 32 bits and leave
// the high 32 bits reserved (either unused or an arena index in a
// later cycle when filter_mask grows).
//
// Keep the on-wire layout stable at 8 bytes so it fits the FIB
// next_hop slot with `nh_sz = RTE_FIB_DIR24_8_8B`.
//
// -------------------------------------------------------------------------
// M5 C1b retrofit (2026-04-15) — `valid_tag` disambiguates FIB miss from
// a zero-packed valid entry.
//
// `builder_eal.cpp` creates the v4/v6 FIBs with `rte_fib_conf.default_nh
// = 0`, which is the miss sentinel returned by `rte_fib_lookup_bulk`
// when no prefix matches the queried address. Before C1b a real hit at
// `action_idx = 0, filter_mask = 0` packed byte-for-byte identically to
// the miss sentinel, so `classify_l3` could not tell "rule 0 matched"
// from "no match" and silently leaked `action_idx = 0` drop rules as
// `kNextL4` fall-through.
//
// C1b reuses the former `_pad0` byte as `valid_tag`, stamped with the
// constant `L3_ENTRY_VALID_TAG = 0xA5` on every arena-resident entry.
// `classify_l3` unpacks the next-hop slot and checks the tag; any slot
// with `valid_tag != 0xA5` is treated as a FIB miss (including literal
// `nh == 0`, since 0x00 != 0xA5). Size / alignment / `nh_sz` unchanged
// — the retrofit is pure byte-level, one of the four previously-padding
// bytes repurposed with an explicit meaning.
//
// **Invariant.** Every L3 arena slot MUST be constructed through
// `ruleset::make_l3_entry(...)` (or through a path that copies from an
// already-stamped entry). Raw `L3CompoundEntry{...}` aggregate
// initialisation bypasses the stamp and is a bug. `builder_eal.cpp`
// `populate_ruleset_eal` is the single authoritative fill site in the
// hot-path data structures and funnels every compiled L3 rule through
// the helper.
//
// Closes memory grabli `rte_fib_default_nh_aliases_action_idx_0`.
// -------------------------------------------------------------------------
struct L3CompoundEntry {
  std::uint8_t  filter_mask;      // reserved for secondary (src_prefix, vrf)
  std::uint8_t  valid_tag;        // M5 C1b: 0xA5 on valid entries, 0 on miss
  std::uint16_t action_idx;       // index into l3_actions[]
  std::uint32_t _pad1;            // reserved (e.g., src_prefix arena idx)
};

static_assert(sizeof(L3CompoundEntry) == 8, "L3CompoundEntry layout drift");

// Sentinel value stamped into `L3CompoundEntry.valid_tag` by
// `make_l3_entry`. Chosen as 0xA5 (0b10100101) — a non-zero, non-trivial
// bit pattern unlikely to collide with accidental zero-initialised or
// all-ones memory. See the C1b retrofit note on `L3CompoundEntry` above.
inline constexpr std::uint8_t L3_ENTRY_VALID_TAG = 0xA5;

// make_l3_entry — the single authoritative constructor for arena-resident
// L3 compound entries (M5 C1b).
//
// Every L3 arena slot MUST go through this helper so the `valid_tag`
// byte is stamped and `classify_l3` can distinguish a real match at
// `action_idx = 0, filter_mask = 0` from a `rte_fib` miss (the built-in
// miss sentinel is `default_nh = 0`, which would otherwise be byte-
// identical to a zero-packed valid entry).
//
// `filter_mask` defaults to 0 because M5 C1 only ships the primary
// dst-prefix match; later cycles that grow secondary constraints can
// pass an explicit mask.
constexpr L3CompoundEntry make_l3_entry(
    std::uint16_t action_idx,
    std::uint8_t filter_mask = 0) noexcept {
  return L3CompoundEntry{
      /*.filter_mask =*/ filter_mask,
      /*.valid_tag   =*/ L3_ENTRY_VALID_TAG,
      /*.action_idx  =*/ action_idx,
      /*._pad1       =*/ 0u,
  };
}

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
