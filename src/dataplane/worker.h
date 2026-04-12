// src/dataplane/worker.h
//
// M3 C1 — worker skeleton: RX loop that polls and drops.
//
// Design anchors:
//   * §5.1 — burst loop skeleton
//   * D9   — g_active global (scaffold; real QSBR is M8)
//   * D19  — worker stays RCU-online at idle (Q7)
//   * D39  — nb_segs != 1 drop (C5 adds the check)

#pragma once

#include <cstdint>
#include <atomic>

#include "src/ruleset/ruleset.h"

namespace pktgate::dataplane {

// Worker context passed to each lcore via rte_eal_remote_launch.
struct WorkerCtx {
  std::uint16_t port_id;       // port to RX from
  std::uint16_t queue_id;      // RX queue assigned to this worker
  std::atomic<bool>* running;  // global stop flag (ctl::g_running)
};

// Worker entry point. Launched via rte_eal_remote_launch.
// Signature matches rte_eal_remote_launch callback: int (*)(void*).
int worker_main(void* arg);

}  // namespace pktgate::dataplane
