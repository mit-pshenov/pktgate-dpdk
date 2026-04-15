// src/dataplane/classify_l3.h
//
// M5 C0 — classify_l3 skeleton: plumbing + pass-through pipeline hook.
//
// The classify_l3 stage consumes `dyn->l3_offset` and
// `dyn->parsed_ethertype` (both written by classify_l2 per D13) and
// dispatches on ethertype into the IPv4 or IPv6 branch. The full body
// is built incrementally across M5 cycles:
//
//   C0 (this)   — function signature, verdict enum, empty pass-through
//                 body that unconditionally returns kNextL4 so the
//                 worker can wire the L2 → L3 → L4 chain end-to-end
//                 before any real header parsing lands.
//   C1           — IPv4 branch: dst-prefix primary FIB lookup via
//                  rte_fib_lookup_bulk(n=1), D14 IHL reject, D31 l3_v4
//                  truncation guard, dispatch on match.
//   C2           — IPv4 src-prefix secondary + compound L3.
//   C3           — IPv4 fragment handling (D17 fragment_policy) + D40
//                  pkt_frag_{dropped,skipped}_total{v4} counters.
//   C4           — IPv6 branch: dst-prefix primary FIB lookup via
//                  rte_fib6_lookup_bulk(n=1), D31 l3_v6 truncation guard.
//   C5           — IPv6 first-protocol-only ext-header handling per D20
//                  (SKIP_L4 + l4_skipped_ipv6_extheader bump).
//   C6           — IPv6 Fragment ext (next_header=44) per D27 first-vs-
//                  non-first split, D31 l3_v6_frag_ext guard, D40 alias
//                  invariant (both D27 named counter and D40 family
//                  fire at the same site).
//
// Design anchors:
//   * §5.3 classify_l3 (design.md lines 1108-1360) — full target spec
//   * §5.1 dynfield layout (PktgateDynfield)
//   * D14  — IPv4 IHL reject (L4 offset formula itself is M6 territory)
//   * D17  — fragment_policy (drop / l3_only / allow), default l3_only
//   * D20  — IPv6 first-protocol-only ext-header scope
//   * D27  — IPv6 Fragment ext first-vs-non-first differentiation
//   * D30  — rte_fib_lookup_bulk(n=1) per-packet form is the default
//   * D31  — per-stage truncation sentinels (l3_v4 / l3_v6 / l3_v6_frag_ext)
//   * D39  — headers-in-first-seg invariant (enforced by the shared
//            classify_entry_ok gate in the worker; do NOT re-guard here)
//   * D40  — fragment counter family (v4/v6 × drop/skip)
//   * D41  — classify_l3 is a top-level pipeline stage reachable from
//            the worker kNextL3 arm; pipeline smoke invariant applies
//
// Layer hygiene: classify_l3 reads the dynfield written by classify_l2
// and does NOT reparse the L2 header. The worker's shared
// classify_entry_ok (src/dataplane/classify_entry.h) already enforces
// `nb_segs == 1` for the whole RX loop — no duplication here.

#pragma once

#include <cstdint>

#include <rte_mbuf.h>

#include "src/eal/dynfield.h"
#include "src/ruleset/ruleset.h"

namespace pktgate::dataplane {

// -------------------------------------------------------------------------
// ClassifyL3Verdict — result of classify_l3.
//
// Mirrors §5.3 `verdict_layer` values (design.md):
//   kNextL4       — L3 pass, continue to L4 classification.
//   kTerminalPass — final allow (e.g. fragment with FRAG_ALLOW policy,
//                   or non-first fragment under FRAG_L3_ONLY that has
//                   already run through L3 matching).
//   kTerminalDrop — final drop (truncation sentinel, IHL reject,
//                   fragment drop, or L3 rule with DROP action).
//
// Rule-driven terminal verdicts (match with ALLOW/DROP action) land
// in C1/C2 with additional variants as needed; C0 only ships the
// three §5.3 baseline values. The enum is fixed-width (std::uint8_t)
// to stay ABI-stable for the dynfield `verdict_layer` field.

enum class ClassifyL3Verdict : std::uint8_t {
  kNextL4       = 0,  // L3 pass — proceed to L4 pipeline
  kTerminalPass = 1,  // final allow at L3
  kTerminalDrop = 2,  // final drop at L3
};

// -------------------------------------------------------------------------
// classify_l3 — top-level L3 classification entry point (§5.3).
//
// Preconditions (enforced by the caller via classify_entry_ok, M4 C9):
//   m->nb_segs == 1   — headers-in-first-seg invariant (D39)
//
// Dynfield contract (written by classify_l2, read here):
//   dyn->l3_offset        — byte offset from frame start to L3 header
//                           (14 untagged, 18 single VLAN / QinQ-outer)
//   dyn->parsed_ethertype — inner ethertype after VLAN strip
//
// C0 body — pass-through skeleton:
//   Unconditionally returns ClassifyL3Verdict::kNextL4 so the worker
//   kNextL3 arm can be wired to call classify_l3 + switch on the inner
//   verdict. IPv4 body lands in C1 (dst FIB + D14 IHL + D31 l3_v4).
//   IPv6 body lands in C4 (dst FIB6 + D31 l3_v6). The dynfield reads
//   below are plumbed (but unused in C0) so that when C1 adds the
//   first `if (et == RTE_BE16(RTE_ETHER_TYPE_IPV4))` branch, the
//   helper variables are already in scope — no signature churn.
//
// The function is `noexcept`: like classify_l2 it runs on the hot
// path and must not throw. All DPDK calls it will eventually make
// (rte_fib_lookup_bulk / rte_fib6_lookup_bulk / rte_hash_lookup_data)
// are C APIs that return error codes, not exceptions.

inline ClassifyL3Verdict classify_l3(struct rte_mbuf* m,
                                     const ruleset::Ruleset& rs) noexcept {
  // Dynfield reads plumbed for C1+. In C0 they are unused by the body;
  // we still bind them to surface type mismatches / missing field names
  // at compile time now, not when C1 adds the IPv4 branch.
  [[maybe_unused]] const auto* dyn = eal::mbuf_dynfield(m);
  [[maybe_unused]] const std::uint8_t  l3_off = dyn->l3_offset;
  [[maybe_unused]] const std::uint16_t et     = dyn->parsed_ethertype;
  [[maybe_unused]] const auto&         rs_ref = rs;

  // TODO M5 C1: IPv4 branch —
  //   if (et == RTE_BE16(RTE_ETHER_TYPE_IPV4)) {
  //     D31 l3_v4 truncation guard (pkt_len < l3_off + sizeof(rte_ipv4_hdr))
  //     D14 IHL reject ((version_ihl & 0x0F) < 5)
  //     rte_fib_lookup_bulk(rs.l3_v4_fib, &da, &nh, 1);
  //     ...
  //   }
  //
  // TODO M5 C4: IPv6 branch —
  //   if (et == RTE_BE16(RTE_ETHER_TYPE_IPV6)) {
  //     D31 l3_v6 truncation guard (pkt_len < l3_off + sizeof(rte_ipv6_hdr))
  //     rte_fib6_lookup_bulk(rs.l3_v6_fib, &dst, &nh, 1);
  //     ...
  //   }
  //
  // TODO M5 C3/C6: D17 fragment_policy handling + D40 counter family.
  // TODO M5 C5:    D20 IPv6 first-protocol-only ext-header scope.
  // TODO M5 C6:    D27 IPv6 Fragment ext first-vs-non-first split.

  return ClassifyL3Verdict::kNextL4;
}

}  // namespace pktgate::dataplane
