// src/dataplane/worker.cpp
//
// M3 C1 — worker skeleton: RX + free (no classification).
//
// The worker polls a single RX queue, frees all received mbufs, and
// exits when the global running flag is cleared. Classification
// (classify_l2/l3/l4) arrives in M4-M6.

#include "src/dataplane/worker.h"

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

    // M3: no classification, just free. M4+ adds classify_l2/l3/l4.
    for (std::uint16_t i = 0; i < nb_rx; ++i) {
      rte_pktmbuf_free(bufs[i]);
    }
  }

  return 0;
}

}  // namespace pktgate::dataplane
