// src/dataplane/action_dispatch.h
//
// M7 C0 — apply_action skeleton + ALLOW/DROP + TERMINAL_PASS/DROP
// (D16 REDIRECT staging, D19 TAG semantics land in C1/C2).
//
// Design anchors:
//   * §5.5   — apply_action (lines 1454-1651)
//   * D22    — RuleAction 20 B + alignas(4)
//   * D25    — default arms on BOTH switches + -Wswitch-enum (enforced
//              globally in cmake/Warnings.cmake). `dispatch_unreachable_total`
//              is the runtime backstop counter (bumped when the
//              default arm fires — design says it stays 0 across the
//              full suite). Checked per-build in X2.9.
//   * D26    — Mirror refcnt zero-copy compile-time gate (not exercised
//              in M7; compiler rejects MIRROR verb — D7).
//
// Design choice (handoff §"M7-specific guidance" option c):
//
// The worker dispatches apply_action inline at the match site with a
// `Disposition` enum that captures *only* the outcome apply_action cares
// about (kMatch needs a valid RuleAction*; kTerminalPass needs the
// ruleset's default_action; kTerminalDrop → free). The design §5.5
// `verdict_layer` switch is replaced by a smaller `disposition` switch
// here + the existing per-layer switches in worker.cpp. No
// verdict_layer field is added to the dynfield; per-layer counter
// bumps live in the worker (bump_l2_counter / bump_l4_counter) which
// already know the matching layer.
//
// Both switches use exhaustive `case` coverage with an explicit
// `default:` arm that bumps `ctx->dispatch_unreachable_total` and
// frees the mbuf (D25 runtime backstop). The -Wswitch-enum flag
// catches missing cases at build time; the default arm is the belt.
//
// TX path in unit tests:
//   EalFixture has no real ports, so we inject a spy TX hook. The
//   hook is a function pointer `ctx->tx_burst_fn` that defaults to
//   rte_eth_tx_burst. Unit tests overwrite it with a spy that
//   records the mbuf and returns 1 (success) without touching
//   hardware. If the hook returns 0 (TX failed), apply_action frees
//   the mbuf — same as production behaviour.

#pragma once

#include <cstdint>

#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "src/action/action.h"
#include "src/compiler/compiler.h"
#include "src/dataplane/worker.h"
#include "src/ruleset/ruleset.h"

namespace pktgate::dataplane {

// -------------------------------------------------------------------------
// apply_dscp_pcp — D19 TAG semantics (M7 C1).
//
// Rewrites DSCP (IPv4 ToS / IPv6 TC high 6 bits) and VLAN PCP (TCI
// high 3 bits) in place on the mbuf.  Design §5.5 TAG case:
//
//   * DSCP: IPv4 ToS byte = (dscp << 2) | preserved_ECN_2_bits.
//           IPv6 TC field (8 bits straddling version_tc_flow[0] low
//           nibble and version_tc_flow[1] high nibble) similarly.
//   * IPv4 cksum invariant: zero the existing hdr_checksum and set
//           RTE_MBUF_F_TX_IP_CKSUM + RTE_MBUF_F_TX_IPV4 so the NIC
//           recomputes on TX.  NO SW cksum fallback in C1 (handoff
//           §Potential obstacles #3 — dev VM e1000 lacks HW ip-cksum,
//           F3.8 deferred to M13 lab).
//   * IPv6 has no L3 checksum, so TC byte rewrite is free (no flag).
//   * PCP: rewrite bits [7:5] of TCI byte 0 (frame offset 14 when the
//           outer TPID is at 12).  Applies ONLY to tagged frames.
//   * PCP on untagged: no-op + bump `ctx->tag_pcp_noop_untagged_total`
//           (D19 — do NOT insert a VLAN tag on the operator's behalf).
//
// VLAN detection: outer ethertype bytes 12-13 read as host-order u16.
// 0x8100 (C-tag) or 0x88A8 (S-tag) => tagged.  Self-contained — does
// NOT require classify_l2 to have populated the dynfield (apply_action
// must work even when unit tests bypass classify).  Matches
// `dataplane::detail::is_vlan_tpid` in classify_l2.h (D32).
//
// `dscp == 0` AND `pcp == 0` is a degenerate TAG — apply_dscp_pcp is
// still called but neither rewrite fires (DSCP write would preserve
// the ToS/TC low 2 ECN bits unchanged; we short-circuit for clarity
// and to avoid gratuitous cksum invalidation).

inline void apply_dscp_pcp(WorkerCtx* ctx, rte_mbuf* m,
                           std::uint8_t dscp, std::uint8_t pcp) {
  // Degenerate TAG (no fields to rewrite): nothing to do.
  if (dscp == 0 && pcp == 0) {
    return;
  }

  // Bounds guard: need at least 14 B to read the outer ethertype.
  // classify_l2 would have dropped anything shorter (D31 l2 bucket),
  // but apply_action is callable from unit tests bypassing classify,
  // so we re-check cheaply.
  if (rte_pktmbuf_pkt_len(m) < 14u) {
    return;
  }

  auto* p = rte_pktmbuf_mtod(m, std::uint8_t*);
  const std::uint16_t outer_etype =
      static_cast<std::uint16_t>((p[12] << 8) | p[13]);
  const bool tagged = (outer_etype == 0x8100u || outer_etype == 0x88A8u);

  // L3 starts at 14 (untagged) or 18 (one VLAN tag walked, matches D13
  // / D32 — QinQ stops at ONE tag in MVP).
  const std::size_t l3_off = tagged ? 18u : 14u;
  // Effective L3 ethertype: after VLAN if tagged, else the outer.
  std::uint16_t l3_etype = outer_etype;
  if (tagged) {
    // Need bytes 16-17 for inner ethertype; guard pkt_len.
    if (rte_pktmbuf_pkt_len(m) < 18u) {
      // Truncated VLAN — classify_l2 would have dropped.  Be defensive:
      // skip L3 rewrite, still handle PCP below since TCI at 14-15
      // is readable once we have >= 16 bytes.
      l3_etype = 0;
    } else {
      l3_etype = static_cast<std::uint16_t>((p[16] << 8) | p[17]);
    }
  }

  // --- DSCP rewrite -------------------------------------------------------
  if (dscp != 0) {
    if (l3_etype == 0x0800u /* IPv4 */ &&
        rte_pktmbuf_pkt_len(m) >= l3_off + 20u) {
      // ToS at l3_off + 1. Preserve ECN low 2 bits.
      const std::uint8_t tos_old = p[l3_off + 1];
      const std::uint8_t ecn = tos_old & 0x03u;
      p[l3_off + 1] = static_cast<std::uint8_t>((dscp << 2) | ecn);
      // Invalidate existing IPv4 header checksum — NIC recomputes on TX.
      p[l3_off + 10] = 0;
      p[l3_off + 11] = 0;
      m->ol_flags |= (RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4);
    } else if (l3_etype == 0x86DDu /* IPv6 */ &&
               rte_pktmbuf_pkt_len(m) >= l3_off + 40u) {
      // TC field: 8 bits straddling version_tc_flow byte 0 low nibble
      // and byte 1 high nibble.  Layout (on-wire BE):
      //   byte 0 = version(4) << 4 | TC_high(4)
      //   byte 1 = TC_low(4) << 4  | FL_high(4)
      // New TC = (dscp << 2) | ecn_2_bits; preserve version nibble in
      // byte 0 high and FL nibble in byte 1 low.
      const std::uint8_t b0 = p[l3_off + 0];
      const std::uint8_t b1 = p[l3_off + 1];
      const std::uint8_t version_nib = b0 & 0xF0u;
      const std::uint8_t fl_nib      = b1 & 0x0Fu;
      const std::uint8_t ecn =
          static_cast<std::uint8_t>(((b0 & 0x0Fu) << 4 |
                                     (b1 & 0xF0u) >> 4) & 0x03u);
      const std::uint8_t tc_new = static_cast<std::uint8_t>((dscp << 2) | ecn);
      p[l3_off + 0] = static_cast<std::uint8_t>(version_nib | (tc_new >> 4));
      p[l3_off + 1] = static_cast<std::uint8_t>(
          ((tc_new & 0x0Fu) << 4) | fl_nib);
      // No cksum flag for IPv6 (no L3 cksum).
    }
    // Other ethertypes (ARP, LLDP, ...) silently skipped — no L3 header
    // to rewrite.  Compiler should not emit TAG rules for non-IP L2
    // flows in practice.
  }

  // --- PCP rewrite --------------------------------------------------------
  if (pcp != 0) {
    if (tagged) {
      // TCI at frame bytes 14 (high) and 15 (low) on-wire BE.
      // PCP = bits [15:13] of the 16-bit TCI = bits [7:5] of byte 14.
      // DEI = bit 12 = bit 4 of byte 14.  VID high nibble = bits [11:8]
      // = bits [3:0] of byte 14.
      const std::uint8_t tci_hi = p[14];
      const std::uint8_t preserved = tci_hi & 0x1Fu;  // DEI + VID hi nibble
      p[14] = static_cast<std::uint8_t>(((pcp & 0x07u) << 5) | preserved);
      // byte 15 (VID low 8 bits) unchanged.
    } else {
      // D19: untagged + PCP = no-op + counter bump, do NOT insert a tag.
      if (ctx != nullptr) {
        ctx->tag_pcp_noop_untagged_total++;
      }
    }
  }
}

// -------------------------------------------------------------------------
// Disposition — what the classify pipeline decided for this mbuf.
//
// The worker already knows the verdict layer (via the switch chain it
// runs over kNextL{2,3,4} / kTerminal*). apply_action takes only the
// minimal information it needs: which end state we're in.
//
// * kMatch        — a classifier hit a rule; `action` must be non-null
//                   and point into the ruleset's per-layer action arena.
// * kTerminalPass — the classifier reached the end of the pipeline
//                   without a matching DROP/ALLOW rule; apply_action
//                   resolves this via `rs.default_action`.
// * kTerminalDrop — the classifier decided to drop (truncation guard,
//                   D17 fragment drop, L3 DROP rule with no L4 follow-up).
//                   apply_action frees the mbuf.
//
// Any other numeric value reaching apply_action hits the D25 outer
// default arm and bumps `dispatch_unreachable_total`. U6.44 injects a
// forged value to assert this backstop works.

enum class Disposition : std::uint8_t {
  kMatch        = 0,
  kTerminalPass = 1,
  kTerminalDrop = 2,
};

// -------------------------------------------------------------------------
// tx_one — single-mbuf TX via the ctx hook (spy-friendly). Returns the
// number of mbufs transmitted (0 or 1). Callers must free the mbuf
// when the return value is 0.

inline std::uint16_t tx_one(WorkerCtx* ctx, std::uint16_t port_id,
                            rte_mbuf* m) {
  // ctx->tx_burst_fn lets unit tests inject a spy without reaching
  // the PMD. Production sets it to rte_eth_tx_burst at init time.
  if (ctx->tx_burst_fn == nullptr) {
    return 0;  // defensive — treat as TX failure, caller frees.
  }
  return ctx->tx_burst_fn(port_id, ctx->queue_id, &m, 1);
}

// -------------------------------------------------------------------------
// apply_terminal_pass — resolve TERMINAL_PASS via rs.default_action.
//
// `default_action` is 0 = ALLOW, 1 = DROP (matches
// config::DefaultBehavior::{kAllow, kDrop} numeric encoding).
// Anything else falls through to free (belt-and-braces, though the
// config parser / validator never emits outside {0, 1}).

inline void apply_terminal_pass(WorkerCtx* ctx, const ruleset::Ruleset& rs,
                                rte_mbuf* m) {
  if (rs.default_action == 0 /* ALLOW */) {
    const std::uint16_t sent = tx_one(ctx, ctx->tx_port_id, m);
    if (sent == 0) {
      rte_pktmbuf_free(m);
    }
    return;
  }
  // default_action == 1 (DROP) or any unexpected value → free.
  rte_pktmbuf_free(m);
}

// -------------------------------------------------------------------------
// apply_action — route an mbuf to its terminal destination.
//
// `disp` picks which high-level outcome we're dispatching. When
// `disp == kMatch`, `action` MUST be non-null and point at a
// RuleAction in the ruleset's l{2,3,4}_actions arena. For the other
// dispositions `action` is ignored.
//
// Returns nothing — the mbuf is either transmitted (spy/PMD keeps
// ownership on success) or freed. The caller must NOT touch the mbuf
// after this call.

inline void apply_action(WorkerCtx* ctx, const ruleset::Ruleset& rs,
                         rte_mbuf* m, Disposition disp,
                         const action::RuleAction* action) {
  // Outer switch: disposition. D25 default arm fires if a future
  // Disposition variant is added without updating this switch (the
  // -Wswitch-enum flag catches it at compile time; this runtime
  // backstop protects release builds where the warning was somehow
  // bypassed, and handles forged inputs like U6.44).
  switch (disp) {
    case Disposition::kTerminalPass:
      apply_terminal_pass(ctx, rs, m);
      return;

    case Disposition::kTerminalDrop:
      rte_pktmbuf_free(m);
      return;

    case Disposition::kMatch:
      // Fall through to the inner verb switch below. Handled outside
      // the outer `case` so that adding a new Disposition value
      // doesn't accidentally skip the verb dispatch.
      break;

    default:
      // D25 runtime backstop: unknown disposition. Bump counter,
      // free mbuf, return. U6.44 covers this branch.
      ctx->dispatch_unreachable_total++;
      rte_pktmbuf_free(m);
      return;
  }

  // kMatch path — `action` must be non-null.
  if (action == nullptr) {
    // Defensive: caller passed kMatch + nullptr. Treat as
    // dispatch_unreachable — this is a state-machine bug. (Not
    // covered by a dedicated test; the worker never passes nullptr
    // for kMatch.)
    ctx->dispatch_unreachable_total++;
    rte_pktmbuf_free(m);
    return;
  }

  // Inner switch: verb. D25 default arm fires if a future ActionVerb
  // is added without updating this switch. U6.45 covers this by
  // injecting verb=99.
  switch (static_cast<compiler::ActionVerb>(action->verb)) {
    case compiler::ActionVerb::kAllow: {
      const std::uint16_t sent = tx_one(ctx, ctx->tx_port_id, m);
      if (sent == 0) {
        rte_pktmbuf_free(m);
      }
      return;
    }

    case compiler::ActionVerb::kDrop:
      rte_pktmbuf_free(m);
      return;

    case compiler::ActionVerb::kRateLimit:
      // M9 plugs the real per-lcore token bucket. MVP stub = always
      // allow, so the packet flows through to TX. §M7 plan line
      // "RL stub → treat as ALLOW for MVP".
      {
        const std::uint16_t sent = tx_one(ctx, ctx->tx_port_id, m);
        if (sent == 0) {
          rte_pktmbuf_free(m);
        }
      }
      return;

    case compiler::ActionVerb::kTag:
      // M7 C1 — D19 TAG semantics. Rewrite DSCP / PCP, then fall through
      // to ALLOW-style TX. `apply_dscp_pcp` handles the untagged-PCP
      // no-op counter internally.
      apply_dscp_pcp(ctx, m, action->dscp, action->pcp);
      {
        const std::uint16_t sent = tx_one(ctx, ctx->tx_port_id, m);
        if (sent == 0) {
          rte_pktmbuf_free(m);
        }
      }
      return;

    case compiler::ActionVerb::kRedirect:
      // C2 fills the REDIRECT body (D16 staging + burst-end flush).
      // For C0: free. The compiler does NOT currently reject
      // REDIRECT, so a config with REDIRECT would hit this branch.
      // This matches the pre-C2 behaviour of the worker (which was
      // freeing everything); C2 replaces it with staging.
      rte_pktmbuf_free(m);
      return;

    case compiler::ActionVerb::kMirror:
      // D7 — compiler rejects MIRROR at publish time. Reaching here
      // means the compiler-reject path was bypassed; treat as
      // unreachable and free.
      ctx->dispatch_unreachable_total++;
      rte_pktmbuf_free(m);
      return;

    default:
      // D25 runtime backstop: unknown verb. U6.45 covers this
      // branch by forging action->verb = 99.
      ctx->dispatch_unreachable_total++;
      rte_pktmbuf_free(m);
      return;
  }
}

}  // namespace pktgate::dataplane
