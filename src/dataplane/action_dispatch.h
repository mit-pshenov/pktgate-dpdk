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

#include <rte_config.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include "src/action/action.h"
#include "src/compiler/compiler.h"
#include "src/dataplane/lcore_counter.h"  // M11 C1.5 — relaxed_bump helpers
#include "src/dataplane/worker.h"
#include "src/rl_arena/arena.h"
#include "src/rl_arena/rl_arena.h"
#include "src/ruleset/ruleset.h"

namespace pktgate::dataplane {

// -------------------------------------------------------------------------
// M7 C2 — D16 REDIRECT staging + burst-end drain.
//
// stage_redirect enqueues the mbuf into ctx->redirect_tx[port].pkts; the
// actual TX is deferred until end-of-burst in redirect_drain(), which
// calls tx_burst_fn once per non-empty staged port.  Unsent mbufs are
// freed and redirect_dropped_total bumped (D16 fix for the naive-inline
// TX mbuf leak described in review-notes).
//
// Buffer-full policy: drop the new mbuf (free + counter bump).  See
// worker.h kRedirectBurstMax comment for rationale.

inline void stage_redirect(WorkerCtx* ctx, std::uint16_t port,
                           rte_mbuf* m) {
  // Defensive: unknown port index — count as drop.  RTE_MAX_ETHPORTS
  // is the array size; port_id == 0xFFFF (RuleAction "no port" sentinel)
  // and any forged oversized index lands here.
  if (port >= RTE_MAX_ETHPORTS) {
    relaxed_bump(&ctx->redirect_dropped_total);
    rte_pktmbuf_free(m);
    return;
  }
  auto& s = ctx->redirect_tx[port];
  if (s.count >= kRedirectBurstMax) {
    // Buffer full — drop the new arrival, keep the staged packets
    // (they are closer to being drained).  No OOB write.
    relaxed_bump(&ctx->redirect_dropped_total);
    rte_pktmbuf_free(m);
    return;
  }
  s.pkts[s.count++] = m;
}

inline void redirect_drain(WorkerCtx* ctx) {
  for (std::uint16_t p = 0; p < RTE_MAX_ETHPORTS; ++p) {
    auto& s = ctx->redirect_tx[p];
    if (s.count == 0) continue;
    std::uint16_t sent = 0;
    if (ctx->tx_burst_fn != nullptr) {
      sent = ctx->tx_burst_fn(p, ctx->queue_id, s.pkts, s.count);
    }
    if (sent < s.count) {
      // Free unsent mbufs and bump the drop counter (D16).
      for (std::uint16_t i = sent; i < s.count; ++i) {
        rte_pktmbuf_free(s.pkts[i]);
      }
      const std::uint64_t unsent =
          static_cast<std::uint64_t>(s.count - sent);
      relaxed_add(&ctx->redirect_dropped_total, unsent);
      // M14 C3 — D43 per-port backpressure. Every unsent mbuf counts
      // against the destination port; redirect_drain's dst port is
      // `p` regardless of ctx->tx_port_id. Bump tx_dropped by the
      // whole unsent count; bump tx_burst_short only if the burst
      // was PARTIALLY accepted (sent > 0) — a fully-rejected burst
      // looks to the operator like a hard outage, not short-burst
      // backpressure.
      relaxed_add(&ctx->tx_dropped_per_port[p], unsent);
      if (sent > 0) {
        relaxed_bump_bucket(ctx->tx_burst_short_per_port, p);
      }
    }
    s.count = 0;
  }
}

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
        relaxed_bump(&ctx->tag_pcp_noop_untagged_total);
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
    // M14 C3 — D43: even the defensive no-hook path counts as a port
    // drop for the caller-requested destination. Guard port_id
    // against stray RuleAction sentinels (0xFFFF) + belt-and-braces
    // bounds check on the fixed-size bucket array.
    if (port_id < RTE_MAX_ETHPORTS) {
      relaxed_bump_bucket(ctx->tx_dropped_per_port, port_id);
    }
    return 0;  // defensive — treat as TX failure, caller frees.
  }
  const std::uint16_t sent =
      ctx->tx_burst_fn(port_id, ctx->queue_id, &m, 1);
  if (sent == 0 && port_id < RTE_MAX_ETHPORTS) {
    // M14 C3 — D43 per-port backpressure: single-packet send failed.
    // tx_burst_short is NOT bumped here (short-burst needs sent > 0,
    // by definition nb_pkts == 1 → sent ∈ {0, 1}; zero is a full
    // drop, not a short burst).
    relaxed_bump_bucket(ctx->tx_dropped_per_port, port_id);
  }
  return sent;
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
      relaxed_bump(&ctx->dispatch_unreachable_total);
      rte_pktmbuf_free(m);
      return;
  }

  // kMatch path — `action` must be non-null.
  if (action == nullptr) {
    // Defensive: caller passed kMatch + nullptr. Treat as
    // dispatch_unreachable — this is a state-machine bug. (Not
    // covered by a dedicated test; the worker never passes nullptr
    // for kMatch.)
    relaxed_bump(&ctx->dispatch_unreachable_total);
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

    case compiler::ActionVerb::kRateLimit: {
      // M9 C2 — real per-lcore token bucket consume.
      //
      // Contract:
      //   * ctx->rl_arena is the process-lifetime arena singleton
      //     (src/rl_arena/arena.cpp rl_arena_global()). Null in
      //     test fixtures that don't exercise RL — fall through to a
      //     defensive drop + dispatch_unreachable bump.
      //   * action->rl_index is the slot index assigned at build
      //     time (C3 wires this — C2 assumes `rl_index == slot` and
      //     relies on the integration test to populate manually).
      //   * rs.rl_actions[rl_index] carries {rule_id, rate, burst}.
      //     Bounds guard: rl_index < rs.rl_actions_capacity AND
      //     rs.rl_actions != nullptr. A misconfigured build that
      //     left either invariant broken dispatches as unreachable.
      //   * Hot path: NO control-plane lookup (no lookup_slot call,
      //     no unordered_map read). Direct `rl_arena->get_row(slot)`
      //     is a bounds-checked vector access (control-plane only
      //     field `id_to_slot` is never touched).
      //   * D1 sacred: `rl_consume` mutates a single per-lcore slot
      //     `row.per_lcore[lcore_id]`. Zero atomics, zero RMW.
      //   * D34: the math layer clamps `elapsed` at `tsc_hz` before
      //     the multiply (see src/rl_arena/rl_arena.cpp) — worker
      //     passes the cached `ctx->tsc_hz` populated at init.
      //
      // TODO(M9 C3): guarantee `rl_index == arena.alloc_slot(rule_id)`
      // invariant from the compiler/builder. C2 test populates
      // rl_actions manually and assumes the invariant holds.
      if (ctx->rl_arena == nullptr ||
          action->rl_index >= rs.rl_actions_capacity ||
          rs.rl_actions == nullptr) {
        relaxed_bump(&ctx->dispatch_unreachable_total);
        rte_pktmbuf_free(m);
        return;
      }

      const auto& rl = rs.rl_actions[action->rl_index];
      auto& row = ctx->rl_arena->get_row(action->rl_index);
      const unsigned lcore_id = rte_lcore_id();
      // `rte_lcore_id()` returns LCORE_ID_ANY (0x7FFFFFFF) for threads
      // not registered with EAL — any such caller (e.g. a mis-written
      // test thread) would out-of-bounds index the per-lcore array.
      // Drop defensively.
      if (lcore_id >= rl_arena::kMaxLcores) {
        relaxed_bump(&ctx->dispatch_unreachable_total);
        rte_pktmbuf_free(m);
        return;
      }

      // Divisor: active-lcore count from the Ruleset. Clamp to 1 so
      // a degenerate `num_lcores == 0` (test fixtures) does not
      // divide-by-zero. Production paths always have num_lcores >= 1.
      const unsigned n_active = (rs.num_lcores == 0) ? 1u : rs.num_lcores;

      const bool pass = rl_arena::rl_consume(
          row.per_lcore[lcore_id],
          /*now_tsc=*/rte_rdtsc(),
          /*tsc_hz=*/ctx->tsc_hz,
          /*pkt_len=*/rte_pktmbuf_pkt_len(m),
          /*rate=*/rl.rate_bps,
          /*burst=*/rl.burst_bytes,
          /*n_lcores=*/n_active);

      if (pass) {
        const std::uint16_t sent = tx_one(ctx, ctx->tx_port_id, m);
        if (sent == 0) {
          rte_pktmbuf_free(m);
        }
      } else {
        rte_pktmbuf_free(m);
      }
      return;
    }

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
      // M7 C2 — D16: stage into per-port buffer, drained at burst end
      // via redirect_drain(ctx).  stage_redirect handles the buffer-
      // full drop + counter internally.
      stage_redirect(ctx, action->redirect_port, m);
      return;

    case compiler::ActionVerb::kMirror:
      // M16 C1 placeholder arm (review-notes §D7 amendment 2026-04-20).
      // The compile-path reject is removed in C1 — a mirror rule now
      // lowers a resolved `action->mirror_port` through the builder
      // and reaches here. C2 replaces this body with stage_mirror +
      // stage_tx (original forward) + mirror_drain at burst end. In
      // C1 no hot-path code lands yet: if a live packet hits a mirror
      // rule (unit/EAL tests do not inject packets into this arm), we
      // fall back to the unreachable-counter + free behaviour so the
      // hot path remains provably safe. `-Wswitch-enum` keeps us
      // honest when C2 rewrites this arm.
      relaxed_bump(&ctx->dispatch_unreachable_total);
      rte_pktmbuf_free(m);
      return;

    default:
      // D25 runtime backstop: unknown verb. U6.45 covers this
      // branch by forging action->verb = 99.
      relaxed_bump(&ctx->dispatch_unreachable_total);
      rte_pktmbuf_free(m);
      return;
  }
}

}  // namespace pktgate::dataplane
