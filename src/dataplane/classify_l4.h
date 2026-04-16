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
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

#include "src/compiler/rule_compiler.h"
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
// l4_filter_ok — filter_mask secondary check for an L4 compound entry.
//
// `alt_port` is the "other" port — for a proto_dport primary, it's sport;
// for a proto_sport primary, it's dport; for proto_only, it's sport.
// The entry's filter_mask bits determine which secondary constraints to
// check:
//   kSrcPort:  want_src_port must match alt_port (D29: also ICMP code).
//   kTcpFlags: TODO — reserved for a later cycle.
//   kVrf:      TODO — reserved for a later cycle.

inline bool l4_filter_ok(const ruleset::L4CompoundEntry* e,
                          std::uint16_t alt_port) noexcept {
  if (e->filter_mask & compiler::l4_mask::kSrcPort) {
    if (e->want_src_port != alt_port) {
      return false;
    }
  }
  // TODO: add kTcpFlags and kVrf checks here.
  return true;
}

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
                                     const ruleset::Ruleset& rs,
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
    l4off = static_cast<std::uint16_t>(
                static_cast<unsigned>(l3_off) + ((ip->version_ihl & 0x0Fu) << 2));
  } else if (et == RTE_ETHER_TYPE_IPV6) {
    l4off = static_cast<std::uint16_t>(static_cast<unsigned>(l3_off) + 40u + dyn->l4_extra);
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

  // ---- C1: Port parsing + D29 ICMP packing ------------------------------
  //
  // TCP/UDP/SCTP: read big-endian sport/dport from the first 4 bytes.
  // ICMP/ICMPv6 (D29): type → dport slot, code → sport slot.
  //   This unifies the compound key shape: a rule matching ICMP type=8
  //   stores `dport=8` in the primary key, and `code` in want_src_port
  //   with the SRC_PORT filter_mask bit.
  // Other protos: sport=0, dport=0 (no port to key on).
  std::uint16_t sport = 0;
  std::uint16_t dport = 0;
  if (proto == IPPROTO_TCP || proto == IPPROTO_UDP ||
      proto == IPPROTO_SCTP) {
    auto* l4 = rte_pktmbuf_mtod_offset(m, const struct rte_udp_hdr*, l4off);
    sport = rte_be_to_cpu_16(l4->src_port);
    dport = rte_be_to_cpu_16(l4->dst_port);
  } else if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6) {
    auto* icmp = rte_pktmbuf_mtod_offset(m, const std::uint8_t*, l4off);
    dport = icmp[0];  // type → dport slot
    sport = icmp[1];  // code → sport slot
  }

  // Write parsed ports to dynfield for observability / later stages.
  dyn->parsed_l4_sport = sport;
  dyn->parsed_l4_dport = dport;

  // ---- D15 selectivity-ordered probing (C1+C2) --------------------------
  //
  // Three tiers against the single l4_compound_hash, keyed with
  // l4_key helpers (tag byte in bits 24-31 prevents collisions):
  //   1. proto_dport  — most selective
  //   2. proto_sport  — mid selective
  //   3. proto_only   — least selective (catch-all)
  //
  // First hit with passing filter_mask wins → dispatch.
  if (rs.l4_compound_hash) {
    // Tier 1: proto_dport — key = (proto << 16) | dport
    {
      const std::uint32_t key_pd = compiler::l4_key::proto_dport(proto, dport);
      void* data = nullptr;
      int ret = rte_hash_lookup_data(rs.l4_compound_hash, &key_pd, &data);
      if (ret >= 0 && data) {
        const auto* e = static_cast<const ruleset::L4CompoundEntry*>(data);
        if (l4_filter_ok(e, sport)) {
          dyn->verdict_action_idx = e->action_idx;
          return ClassifyL4Verdict::kMatch;
        }
      }
    }
    // Tier 2: proto_sport — key = (1<<24) | (proto << 16) | sport
    {
      const std::uint32_t key_ps = compiler::l4_key::proto_sport(proto, sport);
      void* data = nullptr;
      int ret = rte_hash_lookup_data(rs.l4_compound_hash, &key_ps, &data);
      if (ret >= 0 && data) {
        const auto* e = static_cast<const ruleset::L4CompoundEntry*>(data);
        // For proto_sport primary, the sport is already matched by the
        // hash key — no SRC_PORT secondary needed. filter_mask may still
        // have TCP_FLAGS or VRF bits for secondary checks.
        if (l4_filter_ok(e, dport)) {
          dyn->verdict_action_idx = e->action_idx;
          return ClassifyL4Verdict::kMatch;
        }
      }
    }
    // Tier 3: proto_only — key = (2<<24) | proto
    {
      const std::uint32_t key_po = compiler::l4_key::proto_only(proto);
      void* data = nullptr;
      int ret = rte_hash_lookup_data(rs.l4_compound_hash, &key_po, &data);
      if (ret >= 0 && data) {
        const auto* e = static_cast<const ruleset::L4CompoundEntry*>(data);
        if (l4_filter_ok(e, sport)) {
          dyn->verdict_action_idx = e->action_idx;
          return ClassifyL4Verdict::kMatch;
        }
      }
    }
  }

  // ---- L4 miss → TERMINAL_PASS -----------------------------------------
  //
  // The packet was not matched by any L4 rule. The worker will apply the
  // default action (M7).
  return ClassifyL4Verdict::kTerminalPass;
}

}  // namespace pktgate::dataplane
