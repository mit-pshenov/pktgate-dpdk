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

#include <rte_mbuf.h>

#include "src/ruleset/ruleset.h"

namespace pktgate::dataplane {

// Worker context passed to each lcore via rte_eal_remote_launch.
struct WorkerCtx {
  std::uint16_t port_id;       // port to RX from
  std::uint16_t queue_id;      // RX queue assigned to this worker
  std::atomic<bool>* running;  // global stop flag (ctl::g_running)

  // M4 C1: active Ruleset pointer. Set by the control plane before
  // launching the worker. Hot-reload (M8) will update this under RCU.
  // Non-owning — lifetime managed by g_active (D9).
  const ruleset::Ruleset* ruleset = nullptr;

  // Per-worker counters (D3: per-lcore, zero atomics).
  std::uint64_t pkt_multiseg_drop_total = 0;  // D39: nb_segs != 1
  std::uint64_t qinq_outer_only_total   = 0;  // D32: outer S-tag, inner is VLAN TPID
};

// D39: check if an mbuf is single-segment. If not, it must be dropped.
// This is the pre-classify check; the actual classify_l2/l3/l4 is M4+.
inline bool is_single_segment(const struct rte_mbuf* m) {
  return m->nb_segs == 1;
}

// Worker entry point. Launched via rte_eal_remote_launch.
// Signature matches rte_eal_remote_launch callback: int (*)(void*).
int worker_main(void* arg);

}  // namespace pktgate::dataplane
