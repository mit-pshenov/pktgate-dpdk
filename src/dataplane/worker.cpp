// src/dataplane/worker.cpp
//
// M3 C1/C5 — worker skeleton: RX loop with D39 multi-seg drop.
// M4 C1      — classify_l2 call site wired in.
//
// The worker polls a single RX queue, drops multi-segment mbufs
// (D39: headers-in-first-seg invariant), calls classify_l2 on each
// surviving mbuf, and dispatches on the verdict. Classification for
// L3/L4 (classify_l3/classify_l4) arrives in M5-M6.

#include "src/dataplane/worker.h"

#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "src/dataplane/classify_l2.h"

namespace pktgate::dataplane {

namespace {
constexpr std::uint16_t kBurstSize = 32;
}  // namespace

int worker_main(void* arg) {
  auto* ctx = static_cast<WorkerCtx*>(arg);
  struct rte_mbuf* bufs[kBurstSize];

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
      // D39: drop multi-segment mbufs. Port validator (C3) ensures
      // scatter is OFF and mempool fits max_rx_pkt_len, so multi-seg
      // should never arrive in practice. This is the safety net.
      if (!is_single_segment(bufs[i])) {
        ++ctx->pkt_multiseg_drop_total;
        rte_pktmbuf_free(bufs[i]);
        continue;
      }

      // D39 debug assert: after passing the check, nb_segs MUST be 1.
      RTE_ASSERT(bufs[i]->nb_segs == 1);

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

      switch (l2v) {
        case ClassifyL2Verdict::kNextL3:
          // L2 pass — proceed to L3 (M5 hook).  For now, free.
          rte_pktmbuf_free(bufs[i]);
          break;
        case ClassifyL2Verdict::kDrop:
          rte_pktmbuf_free(bufs[i]);
          break;
      }
    }
  }

  return 0;
}

}  // namespace pktgate::dataplane
