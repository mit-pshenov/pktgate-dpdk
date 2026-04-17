// src/dataplane/worker.cpp
//
// M3 C1/C5 — worker skeleton: RX loop with D39 multi-seg drop.
// M4 C1      — classify_l2 call site wired in.
// M4 C8      — per-rule counter bump after classify_l2 match.
// M4 C9      — D39 guard moved into shared classify_entry helper.
// M6 C0      — classify_l4 call site wired in (kNextL4 arm).
//
// The worker polls a single RX queue, drops multi-segment mbufs
// (D39: headers-in-first-seg invariant — now handled by
// classify_entry_ok), calls classify_l2 on each surviving mbuf, and
// dispatches on the verdict. L3 classification (classify_l3) chains
// from the kNextL3 arm; L4 (classify_l4) chains from L3's kNextL4 arm.
// All stages share the same classify_entry_ok gate.

#include "src/dataplane/worker.h"

#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_rcu_qsbr.h>  // M8 C4 — D12 lifecycle

#include "src/action/action.h"
#include "src/ctl/reload.h"  // M8 C5 — acquire-load g_active per burst
#include "src/dataplane/action_dispatch.h"
#include "src/dataplane/classify_entry.h"
#include "src/dataplane/classify_l2.h"
#include "src/dataplane/classify_l3.h"
#include "src/dataplane/classify_l4.h"
#include "src/dataplane/lcore_counter.h"  // M11 C1.5 — relaxed_bump helpers
#include "src/eal/dynfield.h"
#include "src/ruleset/ruleset.h"

namespace pktgate::dataplane {

namespace {

constexpr std::uint16_t kBurstSize = 32;

// M4 C8 — verdict_action_idx sentinel.
//
// classify_l2 writes `dyn->verdict_action_idx = idx` on a match and leaves
// the field untouched on a miss.  The worker needs to distinguish
// "matched action slot 0" from "no match", so we pre-initialise the
// dynfield to a reserved sentinel before every classify_l2 call. 0xFFFF is
// outside every valid action_idx range (rules_per_layer_max is bounded
// well below 65535 by sizing), so it cannot collide with a real match.
constexpr std::uint16_t kNoMatchSentinel = 0xFFFFu;

// bump_l4_counter — M6 C5: post-classify_l4 per-rule counter increment.
//
// Symmetric to bump_l2_counter but applies the L4 layer_base offset
// to avoid aliasing with L2/L3 counter slots in the same flat row.
// counter_slot is dense [0..N) per layer; the flat row layout is
// [L2: 0..cap) [L3: cap..2*cap) [L4: 2*cap..3*cap) where cap =
// l2_actions_capacity (= rules_per_layer_max).
inline void bump_l4_counter(const ruleset::Ruleset& rs,
                            std::uint16_t action_idx,
                            unsigned lcore_id) {
  if (action_idx >= rs.n_l4_rules || !rs.l4_actions || !rs.counters) return;

  const auto& act = rs.l4_actions[action_idx];
  // Apply L4 layer_base offset: 2 * rules_per_layer_max.
  const auto slot = static_cast<std::uint32_t>(act.counter_slot) +
                    2u * rs.l2_actions_capacity;

  ruleset::RuleCounter* row = rs.counter_row(lcore_id);
  if (!row || slot >= rs.counter_slots_per_lcore) return;

  ruleset::RuleCounter& ctr = row[slot];
  // M11 C1.5: RELAXED load+store pair — paired with publisher-side
  // __atomic_load_n(&row.matched_packets/.drops/..., RELAXED). Worker
  // is the single writer for this lcore's slot; publisher reads under
  // RCU read-side (acquire-load of g_active) on the SnapshotPublisher
  // thread.
  relaxed_bump(&ctr.matched_packets);
  // classify_l4 returns kMatch for all matched rules regardless of
  // action verb. Check the action verb directly to bump drops.
  if (static_cast<compiler::ActionVerb>(act.verb) ==
      compiler::ActionVerb::kDrop) {
    relaxed_bump(&ctr.drops);
  }
}

// bump_l2_counter — M4 C8: post-classify_l2 per-rule counter increment.
//
// Reads the matched action slot from the ruleset action arena and
// increments the corresponding RuleCounter row for this lcore.  Runs on
// the worker lcore — zero atomics per D1 (RuleCounter writes are
// single-writer per lcore; telemetry aggregates in M10).
//
// Guards against misconfigured ruleset (nullptr action/counters, slot
// out-of-range) so a compile/build failure on the side path cannot
// corrupt RX processing.
inline void bump_l2_counter(const ruleset::Ruleset& rs,
                            std::uint16_t action_idx,
                            ClassifyL2Verdict verdict,
                            unsigned lcore_id) {
  if (action_idx >= rs.n_l2_rules || !rs.l2_actions || !rs.counters) return;

  const auto& act = rs.l2_actions[action_idx];
  const auto slot = static_cast<std::uint32_t>(act.counter_slot);

  ruleset::RuleCounter* row = rs.counter_row(lcore_id);
  if (!row || slot >= rs.counter_slots_per_lcore) return;

  ruleset::RuleCounter& ctr = row[slot];
  // M11 C1.5: RELAXED load+store pair (see bump_l4_counter rationale).
  relaxed_bump(&ctr.matched_packets);
  if (verdict == ClassifyL2Verdict::kDrop) {
    relaxed_bump(&ctr.drops);
  }
}

}  // namespace

int worker_main(void* arg) {
  auto* ctx = static_cast<WorkerCtx*>(arg);
  struct rte_mbuf* bufs[kBurstSize];

  // M4 C8: lcore id for per-rule counter indexing (§4.3 D3).  Captured
  // once at entry — lcore affinity does not change for the lifetime of
  // a worker thread.
  const unsigned lcore_id = rte_lcore_id();

  // M8 C4 — D12 RCU QSBR lifecycle. When `qs == nullptr` we skip all
  // of this and the caller is responsible for sequencing shutdown (the
  // C1 immediate-free path). Production + integration always pass qs.
  if (ctx->qs != nullptr) {
    rte_rcu_qsbr_thread_register(ctx->qs, ctx->qsbr_thread_id);
    rte_rcu_qsbr_thread_online(ctx->qs, ctx->qsbr_thread_id);
  }

  // D19/Q7: worker stays "online" at all times — no offline transition
  // on idle. M8 C4: worker now reports quiescent between every burst
  // so the reload manager's synchronize path drains promptly.

  while (ctx->running->load(std::memory_order_relaxed)) {
    // M8 C5 — D9/RCU acquire-load per burst.
    //
    // The previous ruleset pointer in ctx->ruleset is a cached
    // pointer that MUST be refreshed from g_active on every burst.
    // Between the refresh here and the rte_rcu_qsbr_quiescent call
    // below, the worker holds a local stable pointer; any concurrent
    // reload that exchanges g_active waits for this thread's
    // quiescent report before the reload manager frees the old
    // pointer (D11 + D30 + D36 pending_free queue). Without this
    // per-burst refresh, the worker pins the initial pointer for
    // its lifetime and a reload's free_ruleset races the worker's
    // classify_l{2,3,4} dereferences.
    ctx->ruleset = ctl::reload::active_ruleset();
    if (ctx->ruleset == nullptr) {
      // No active ruleset (pre-publish or mid-shutdown). Skip the
      // burst and report quiescent so any pending reload/shutdown
      // synchronize unblocks.
      if (ctx->qs != nullptr) {
        rte_rcu_qsbr_quiescent(ctx->qs, ctx->qsbr_thread_id);
      }
      continue;
    }

    const std::uint16_t nb_rx =
        rte_eth_rx_burst(ctx->port_id, ctx->queue_id, bufs, kBurstSize);

    if (nb_rx == 0) {
      // D19: idle path — no offline transition.
      // M8 C5: report quiescent even on idle so RCU synchronize
      // is not starved by a worker that happens to see zero RX.
      if (ctx->qs != nullptr) {
        rte_rcu_qsbr_quiescent(ctx->qs, ctx->qsbr_thread_id);
      }
      continue;
    }

    for (std::uint16_t i = 0; i < nb_rx; ++i) {
      // D39 pre-classify entry gate (M4 C9): headers-in-first-seg
      // invariant check + debug assert + release-build counter bump.
      // Promoted out of classify_l2 into classify_entry_ok so L3/L4
      // (M5/M6) reuse the same gate.  Port validator (C3) ensures
      // scatter is OFF and mempool fits max_rx_pkt_len, so a multi-seg
      // mbuf reaching here means a PMD lied — the helper drops it.
      if (!classify_entry_ok(bufs[i], &ctx->pkt_multiseg_drop_total)) {
        rte_pktmbuf_free(bufs[i]);
        continue;
      }

      // M4 C8: pre-init verdict_action_idx to the no-match sentinel so
      // bump_l2_counter can reliably distinguish "matched slot 0" from
      // "no match".  classify_l2::l2_dispatch writes the real action_idx
      // on hit; a miss leaves this sentinel in place.
      auto* dyn = eal::mbuf_dynfield(bufs[i]);
      dyn->verdict_action_idx = kNoMatchSentinel;
      // M6 C5: zero the flags field so stale SKIP_L4 bits from a
      // previous mbuf reuse cycle don't leak into classify_l4.
      // classify_l3 writes SKIP_L4 on the non-first fragment / ext-header
      // path; without this reset, a recycled mbuf that previously carried
      // a fragmented or ext-header packet would skip L4 on its next life.
      dyn->flags = 0;
      // M6 C5: zero l4_extra so IPv6 first-fragment's +8 offset from a
      // previous mbuf does not bleed into a plain IPv4/IPv6 packet.
      dyn->l4_extra = 0;

      // M4 C1: L2 classification. classify_l2 returns kNextL3 on
      // empty ruleset or hash miss, kDrop on L2 rule drop action.
      // M5 will extend the kNextL3 branch to call classify_l3.
      // D32: pass per-lcore qinq counter so the hot path can bump it.
      // D31: pass per-lcore truncation counter array (l2 / l2_vlan buckets).
      // TODO M5: call classify_l3 on kNextL3 verdict.
      const ClassifyL2Verdict l2v =
          classify_l2(bufs[i], *ctx->ruleset,
                      &ctx->qinq_outer_only_total,
                      &ctx->pkt_truncated_l2);

      // M4 C8: bump the per-rule counter if classify_l2 matched a rule.
      // A miss leaves verdict_action_idx == kNoMatchSentinel (pre-init).
      const std::uint16_t act_idx = dyn->verdict_action_idx;
      if (act_idx != kNoMatchSentinel) {
        bump_l2_counter(*ctx->ruleset, act_idx, l2v, lcore_id);
      }

      switch (l2v) {
        case ClassifyL2Verdict::kNextL3: {
          // M5 C0: L2 pass → call classify_l3. C0 shipped a pass-through
          // body; C1 added the IPv4 branch (D31 l3_v4 truncation guard,
          // D14 IHL reject, dst-prefix FIB lookup); C3 added the D17
          // fragment-policy branch + D40 v4 fragment counters. The inner
          // verdict switch was wired in C0 so later cycles only extend
          // the enum + body without touching worker.cpp.
          //
          // D31: pass per-lcore L3 truncation counter array
          // (pkt_truncated_l3[l3_v4]) — optional-counter pattern symmetric
          // to classify_l2's pkt_truncated_l2.
          // D40: pass per-lcore L3 fragment counter array
          // (pkt_frag_l3[{dropped_v4, skipped_v4}]) — same pattern.
          const ClassifyL3Verdict l3v =
              classify_l3(bufs[i], *ctx->ruleset,
                          &ctx->pkt_truncated_l3,
                          &ctx->pkt_frag_l3,
                          &ctx->l4_skipped_ipv6_extheader,
                          &ctx->l4_skipped_ipv6_fragment_nonfirst);
          switch (l3v) {
            case ClassifyL3Verdict::kNextL4: {
              // M6 C0: L3 pass → call classify_l4.
              // D31: pass per-lcore L4 truncation counter array.
              const ClassifyL4Verdict l4v =
                  classify_l4(bufs[i], *ctx->ruleset,
                              &ctx->pkt_truncated_l4);
              switch (l4v) {
                case ClassifyL4Verdict::kTerminalPass:
                  // L4 miss or SKIP_L4 or ALLOW rule. M7 C0: dispatch
                  // via default_action (ALLOW → TX, DROP → free).
                  apply_action(ctx, *ctx->ruleset, bufs[i],
                               Disposition::kTerminalPass, nullptr);
                  break;
                case ClassifyL4Verdict::kTerminalDrop:
                  // D31 l4 truncation or L4 DROP rule.
                  apply_action(ctx, *ctx->ruleset, bufs[i],
                               Disposition::kTerminalDrop, nullptr);
                  break;
                case ClassifyL4Verdict::kMatch: {
                  // L4 compound entry matched. M6 C5: bump L4
                  // per-rule counter. M7 C0: dispatch via apply_action
                  // with the matched RuleAction*.
                  const std::uint16_t l4_act_idx = dyn->verdict_action_idx;
                  const action::RuleAction* act = nullptr;
                  if (l4_act_idx != kNoMatchSentinel) {
                    bump_l4_counter(*ctx->ruleset, l4_act_idx, lcore_id);
                    if (ctx->ruleset->l4_actions &&
                        l4_act_idx < ctx->ruleset->n_l4_rules) {
                      act = &ctx->ruleset->l4_actions[l4_act_idx];
                    }
                  }
                  if (act != nullptr) {
                    apply_action(ctx, *ctx->ruleset, bufs[i],
                                 Disposition::kMatch, act);
                  } else {
                    // Defensive: kMatch without a resolvable action.
                    apply_action(ctx, *ctx->ruleset, bufs[i],
                                 Disposition::kTerminalDrop, nullptr);
                  }
                  break;
                }
              }
              break;
            }
            case ClassifyL3Verdict::kTerminalPass:
              // Final allow at L3 (e.g. FRAG_ALLOW in C3, L3 allow
              // rule with no L4 follow-up). M7 C0: dispatch via
              // default_action (ALLOW → TX, DROP → free).
              apply_action(ctx, *ctx->ruleset, bufs[i],
                           Disposition::kTerminalPass, nullptr);
              break;
            case ClassifyL3Verdict::kTerminalDrop:
              // Final drop at L3 (truncation sentinel, IHL reject,
              // fragment drop, L3 DROP rule).
              apply_action(ctx, *ctx->ruleset, bufs[i],
                           Disposition::kTerminalDrop, nullptr);
              break;
          }
          break;
        }
        case ClassifyL2Verdict::kDrop:
          // M7 C0: L2 DROP is a terminal drop disposition.
          apply_action(ctx, *ctx->ruleset, bufs[i],
                       Disposition::kTerminalDrop, nullptr);
          break;
      }
    }

    // M7 C2 — D16: drain any REDIRECT-staged mbufs at end of burst.
    // One batched rte_eth_tx_burst per non-empty target port; unsent
    // mbufs freed and redirect_dropped_total bumped.
    redirect_drain(ctx);

    // M8 C4 — D12: report quiescent at end of every burst so the
    // reload manager's synchronize path drains promptly. The fence
    // inside rte_rcu_qsbr_quiescent gives TSAN the happens-before
    // edge that closes the M4-M7 baseline race (main's `delete` at
    // shutdown must see the worker's last read as prior).
    if (ctx->qs != nullptr) {
      rte_rcu_qsbr_quiescent(ctx->qs, ctx->qsbr_thread_id);
    }
  }

  // M8 C4 — D12 worker exit: offline + unregister. Must happen BEFORE
  // returning so the reload manager's shutdown-time synchronize() can
  // conclude the grace period without stalling on us. The offline call
  // emits a store-release fence; unregister follows so rte_rcu_qsbr_check
  // stops waiting for our thread id.
  if (ctx->qs != nullptr) {
    rte_rcu_qsbr_thread_offline(ctx->qs, ctx->qsbr_thread_id);
    rte_rcu_qsbr_thread_unregister(ctx->qs, ctx->qsbr_thread_id);
  }

  // M8 C4 — D12 TSAN-visible handshake. Release store pairs with the
  // acquire load in main.cpp's stats_on_exit path. See worker.h's
  // `worker_done` doc for rationale. MUST be the LAST instrumented
  // write on this thread so every prior worker write (per-lcore
  // counter rows + WorkerCtx scalars) is visible to the reader.
  ctx->worker_done.store(true, std::memory_order_release);

  return 0;
}

}  // namespace pktgate::dataplane
