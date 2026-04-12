// src/dataplane/worker.cpp
//
// M3 C1/C5 — worker skeleton: RX loop with D39 multi-seg drop.
//
// The worker polls a single RX queue, drops multi-segment mbufs
// (D39: headers-in-first-seg invariant), frees remaining mbufs, and
// exits when the global running flag is cleared. Classification
// (classify_l2/l3/l4) arrives in M4-M6.

#include "src/dataplane/worker.h"

#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

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

      // M3: no classification, just free. M4+ adds classify_l2/l3/l4.
      rte_pktmbuf_free(bufs[i]);
    }
  }

  return 0;
}

}  // namespace pktgate::dataplane
