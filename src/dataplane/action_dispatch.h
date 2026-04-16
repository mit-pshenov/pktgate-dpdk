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
      // C1 fills the TAG body (D19 DSCP/PCP semantics). For C0 this
      // is a pass-through to TX so a TAG rule that slipped past the
      // compiler doesn't silently swallow the packet.
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
