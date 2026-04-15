// src/dataplane/worker.cpp
//
// M3 C1/C5 — worker skeleton: RX loop with D39 multi-seg drop.
// M4 C1      — classify_l2 call site wired in.
// M4 C8      — per-rule counter bump after classify_l2 match.
// M4 C9      — D39 guard moved into shared classify_entry helper.
//
// The worker polls a single RX queue, drops multi-segment mbufs
// (D39: headers-in-first-seg invariant — now handled by
// classify_entry_ok), calls classify_l2 on each surviving mbuf, and
// dispatches on the verdict. Classification for L3/L4
// (classify_l3/classify_l4) arrives in M5-M6 and will share the same
// classify_entry_ok gate.

#include "src/dataplane/worker.h"

#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include "src/action/action.h"
#include "src/dataplane/classify_entry.h"
#include "src/dataplane/classify_l2.h"
#include "src/dataplane/classify_l3.h"
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
  ++ctr.matched_packets;
  if (verdict == ClassifyL2Verdict::kDrop) {
    ++ctr.drops;
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

  // D19/Q7: worker stays "online" at all times — no offline transition
  // on idle. Real RCU register/online/offline/unregister lands in M8.

  while (ctx->running->load(std::memory_order_relaxed)) {
    const std::uint16_t nb_rx =
        rte_eth_rx_burst(ctx->port_id, ctx->queue_id, bufs, kBurstSize);

    if (nb_rx == 0) {
      // D19: idle path — no offline transition.
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
                          &ctx->pkt_frag_l3);
          switch (l3v) {
            case ClassifyL3Verdict::kNextL4:
              // TODO M6: call classify_l4 on kNextL4 verdict.
              // For now, free (same as the old M4 kNextL3 free arm).
              rte_pktmbuf_free(bufs[i]);
              break;
            case ClassifyL3Verdict::kTerminalPass:
              // Final allow at L3 (e.g. FRAG_ALLOW in C3). TX path
              // lands in a later milestone; for now, free.
              rte_pktmbuf_free(bufs[i]);
              break;
            case ClassifyL3Verdict::kTerminalDrop:
              // Final drop at L3 (truncation sentinel, IHL reject,
              // fragment drop, L3 DROP rule). Free the mbuf.
              rte_pktmbuf_free(bufs[i]);
              break;
          }
          break;
        }
        case ClassifyL2Verdict::kDrop:
          rte_pktmbuf_free(bufs[i]);
          break;
      }
    }
  }

  return 0;
}

}  // namespace pktgate::dataplane
