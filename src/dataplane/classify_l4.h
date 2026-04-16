// src/dataplane/classify_l4.h
//
// M6 C0 — classify_l4 skeleton: SKIP_L4 guard, D14 L4 offset, D31
//         l4 truncation sentinel, miss → TERMINAL_PASS.
//
// Built incrementally across M6 cycles:
//
//   C0 (this) — function signature, verdict enum, SKIP_L4 entry guard,
//               D14 L4 offset computation (IPv4 IHL, IPv6 fixed 40 +
//               l4_extra), D31 `l4` truncation guard, miss path →
//               kTerminalPass.  No hash lookups — those land in C1/C2.
//   C1        — TCP/UDP/SCTP port parsing + ICMP D29 packing +
//               proto_dport primary hash probe.
//   C2        — proto_sport + proto_only + filter_mask + selectivity.
//
// Design anchors:
//   * §5.4 classify_l4 (design.md lines 1358-1442)
//   * §5.1 dynfield layout (PktgateDynfield)
//   * D14  — L4 offset: IPv4 = l3_offset + (IHL << 2),
//            IPv6 = l3_offset + 40 + l4_extra
//   * D15  — compound primary + filter_mask + selectivity order
//   * D21  — SKIP_L4 entry guard: if set, kTerminalPass immediately
//   * D29  — ICMP type→dport, code→sport packing (C1 scope)
//   * D31  — per-stage truncation sentinel: `l4` bucket
//            (TCP/UDP/SCTP need 4 B, ICMP/ICMPv6 need 2 B, other 0)
//   * D39  — headers-in-first-seg invariant (enforced by the shared
//            classify_entry_ok gate in the worker; do NOT re-guard here)
//   * D41  — classify_l4 is a top-level pipeline stage reachable from
//            the worker kNextL4 arm; pipeline smoke invariant applies
//
// Layer hygiene: classify_l4 reads the dynfield written by classify_l2
// (l3_offset, parsed_ethertype) and classify_l3 (parsed_l3_proto,
// flags/SKIP_L4, l4_extra) and does NOT reparse L2/L3 headers.
//
// **Ethertype byte-order**: classify_l2 writes `parsed_ethertype` in
// HOST byte order (0x0800 / 0x86DD). Compare against RTE_ETHER_TYPE_*
// constants directly — do NOT wrap in RTE_BE16(). See grabli
// `grabli_classify_l3_ethertype_byte_order.md`.

#pragma once

#include <array>
#include <cstdint>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include "src/eal/dynfield.h"
#include "src/ruleset/ruleset.h"
#include "src/ruleset/types.h"

namespace pktgate::dataplane {

// -------------------------------------------------------------------------
// L4TruncBucket — D31 per-stage truncation counter bucket for classify_l4.
//
// kL4 — L4 header truncated. TCP/UDP/SCTP need >=4 B at l4off,
//        ICMP/ICMPv6 need >=2 B, other protos need 0 (no truncation
//        check). Only one bucket because §5.4 has a single truncation
//        site; the proto is already discriminated by parsed_l3_proto.

enum class L4TruncBucket : std::size_t {
  kL4 = 0,
};
inline constexpr std::size_t kL4TruncBucketCount = 1;

// Convenience alias used by WorkerCtx and test code.
using L4TruncCtrs = std::array<std::uint64_t, kL4TruncBucketCount>;

// -------------------------------------------------------------------------
// ClassifyL4Verdict — result of classify_l4.
//
// Mirrors §5.4 outcomes:
//   kTerminalPass — default: L4 miss, SKIP_L4, or an L4 rule with ALLOW
//                   action. The packet is accepted by the pipeline.
//   kTerminalDrop — D31 l4 truncation sentinel, or an L4 rule with DROP
//                   action.
//   kMatch        — L4 compound entry matched. C1+ returns this; C0
//                   always returns kTerminalPass or kTerminalDrop.

enum class ClassifyL4Verdict : std::uint8_t {
  kTerminalPass = 0,
  kTerminalDrop = 1,
  kMatch        = 2,
};

// -------------------------------------------------------------------------
// classify_l4 — Layer 4 classifier (§5.4).
//
// Called from the worker kNextL4 arm after classify_l3 has written the
// dynfield (parsed_l3_proto, flags, l4_extra). Returns a verdict that
// the worker dispatches on.
//
// Parameters:
//   m          — the mbuf (single-segment, guaranteed by classify_entry_ok).
//   rs         — compiled ruleset (L4 hash tables, compound entries, actions).
//   trunc_ctrs — optional D31 truncation counter array. Pass nullptr to
//                skip the bump (backward-compatible). Worker passes
//                &ctx->pkt_truncated_l4.
//
// Hot path — must be inline, noexcept, no allocation. Same contract as
// classify_l2 / classify_l3.

inline ClassifyL4Verdict classify_l4(struct rte_mbuf* m,
                                     const ruleset::Ruleset& /*rs*/,
                                     L4TruncCtrs* trunc_ctrs = nullptr) noexcept {
  auto* dyn = eal::mbuf_dynfield(m);

  // ---- D21 SKIP_L4 entry guard (U6.39) ----------------------------------
  //
  // If classify_l3 set SKIP_L4 (non-first fragment under L3_ONLY,
  // extension header, etc.) we must not touch the L4 header at all.
  // Terminal pass — the packet was already accepted at L3 scope and
  // the default action will be applied by the worker's apply_action
  // stage (M7).
  if (dyn->flags & eal::kSkipL4) {
    return ClassifyL4Verdict::kTerminalPass;
  }

  const std::uint8_t proto  = dyn->parsed_l3_proto;
  const std::uint8_t l3_off = dyn->l3_offset;
  const std::uint16_t et    = dyn->parsed_ethertype;

  // ---- D14: L4 header offset --------------------------------------------
  //
  // IPv4: l3_offset + (IHL << 2) — IHL from the actual header, not
  //        assumed 5. This handles options correctly (U6.19: IHL=6 → 24 B).
  // IPv6: l3_offset + 40 (fixed header) + l4_extra (D27 fragment ext
  //        header extra — 8 B for first IPv6 fragments under L3_ONLY,
  //        0 otherwise).
  // Non-IP: should not reach here (classify_l3 returns kTerminalPass for
  //        non-IP ethertype), but guard defensively.
  std::uint16_t l4off;
  if (et == RTE_ETHER_TYPE_IPV4) {
    auto* ip = rte_pktmbuf_mtod_offset(m, const struct rte_ipv4_hdr*, l3_off);
    l4off = static_cast<std::uint16_t>(l3_off) +
            static_cast<std::uint16_t>((ip->version_ihl & 0x0F) << 2);
  } else if (et == RTE_ETHER_TYPE_IPV6) {
    l4off = static_cast<std::uint16_t>(l3_off) + 40u + dyn->l4_extra;
  } else {
    // Non-IP — should never arrive here per the pipeline invariant,
    // but if it does, terminal pass (don't leak, don't crash).
    return ClassifyL4Verdict::kTerminalPass;
  }

  // ---- D31 l4 truncation guard (U6.16) ----------------------------------
  //
  // Minimum bytes we need to read at l4off:
  //   TCP/UDP/SCTP: 4 B (src+dst port pair — unified compound key shape)
  //   ICMP/ICMPv6:  2 B (type+code)
  //   other proto:  0 (no L4 header read; skip truncation check)
  std::uint16_t need = 0;
  if (proto == IPPROTO_TCP || proto == IPPROTO_UDP ||
      proto == IPPROTO_SCTP) {
    need = 4;
  } else if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6) {
    need = 2;
  }

  if (need && m->pkt_len < static_cast<std::uint32_t>(l4off) + need) {
    if (trunc_ctrs) {
      ++(*trunc_ctrs)[static_cast<std::size_t>(L4TruncBucket::kL4)];
    }
    return ClassifyL4Verdict::kTerminalDrop;
  }

  // ---- C0 skeleton: no hash lookups yet (C1/C2 scope) -------------------
  //
  // L4 miss → TERMINAL_PASS. The packet was not matched by any L4 rule
  // and the worker will apply the default action (M7).
  return ClassifyL4Verdict::kTerminalPass;
}

}  // namespace pktgate::dataplane
