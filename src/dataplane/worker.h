// src/dataplane/worker.h
//
// M3 C1 — worker skeleton: RX loop that polls and drops.
//
// Design anchors:
//   * §5.1 — burst loop skeleton
//   * D9   — g_active global (scaffold; real QSBR is M8)
//   * D19  — worker stays RCU-online at idle (Q7)
//   * D39  — nb_segs != 1 drop (C5 adds the check)
//   * D31  — truncation sentinels (M4 C5): pkt_truncated_l2 counter array

#pragma once

#include <cstdint>
#include <atomic>

#include <rte_mbuf.h>

#include "src/dataplane/classify_l2.h"  // L2TruncCtrs, L2TruncBucket
#include "src/dataplane/classify_l3.h"  // ClassifyL3Verdict (M5 C0)
#include "src/dataplane/classify_l4.h"  // ClassifyL4Verdict, L4TruncCtrs (M6 C0)
#include "src/ruleset/ruleset.h"

namespace pktgate::dataplane {

// M7 C0: TX burst hook signature. Matches rte_eth_tx_burst so the
// production path stores `&rte_eth_tx_burst` directly. Unit tests
// override the hook with a spy (the EalFixture has no real ports,
// so a direct rte_eth_tx_burst call would hit RTE_MAX_ETHPORTS).
using TxBurstFn = std::uint16_t (*)(std::uint16_t port_id,
                                    std::uint16_t queue_id,
                                    rte_mbuf** tx_pkts,
                                    std::uint16_t nb_pkts);

// Worker context passed to each lcore via rte_eal_remote_launch.
struct WorkerCtx {
  std::uint16_t port_id;       // port to RX from
  std::uint16_t queue_id;      // RX queue assigned to this worker
  // M7 C0: egress port for ALLOW / TAG / RL-stub / TERMINAL_PASS-allow.
  // main.cpp sets this to port_ids[1] (downstream); REDIRECT uses a
  // per-rule port from RuleAction.redirect_port (M7 C2).
  std::uint16_t tx_port_id = 0;
  std::atomic<bool>* running;  // global stop flag (ctl::g_running)

  // M4 C1: active Ruleset pointer. Set by the control plane before
  // launching the worker. Hot-reload (M8) will update this under RCU.
  // Non-owning — lifetime managed by g_active (D9).
  const ruleset::Ruleset* ruleset = nullptr;

  // M7 C0: TX hook. Defaults to nullptr; main.cpp wires it to
  // rte_eth_tx_burst before launching the worker. Unit tests
  // overwrite it with a spy that records the mbuf without calling
  // into the PMD.
  TxBurstFn tx_burst_fn = nullptr;

  // Per-worker counters (D3: per-lcore, zero atomics).
  std::uint64_t pkt_multiseg_drop_total = 0;  // D39: nb_segs != 1
  std::uint64_t qinq_outer_only_total   = 0;  // D32: outer S-tag, inner is VLAN TPID
  L2TruncCtrs   pkt_truncated_l2{};           // D31: l2 / l2_vlan truncation buckets
  L3TruncCtrs   pkt_truncated_l3{};           // D31: l3_v4 (M5 C1) + l3_v6 (M5 C4) truncation buckets
  L3FragCtrs    pkt_frag_l3{};                // D40: fragment drop/skip buckets (M5 C3 v4;
                                              //       C6 adds v6 slots to the same array)
  std::uint64_t l4_skipped_ipv6_extheader = 0;  // D20: IPv6 non-fragment ext-header → SKIP_L4 (M5 C5)
  std::uint64_t l4_skipped_ipv6_fragment_nonfirst = 0;  // D27: non-first v6 fragment → SKIP_L4 (M5 C6)
  L4TruncCtrs   pkt_truncated_l4{};           // D31: l4 truncation bucket (M6 C0)
  // M7 C0: D25 runtime backstop. Bumped from apply_action's default
  // arms (outer disposition switch + inner verb switch). MUST stay 0
  // across the full suite (X2.9 simplified form).
  std::uint64_t dispatch_unreachable_total = 0;
};

// D39: check if an mbuf is single-segment.  M3 C5 primitive retained
// for U6.2a unit test back-compat; the production RX loop now goes
// through classify_entry_ok (src/dataplane/classify_entry.h, M4 C9)
// which bundles this check with the per-lcore drop counter bump and a
// debug RTE_ASSERT.
inline bool is_single_segment(const struct rte_mbuf* m) {
  return m->nb_segs == 1;
}

// Worker entry point. Launched via rte_eal_remote_launch.
// Signature matches rte_eal_remote_launch callback: int (*)(void*).
int worker_main(void* arg);

}  // namespace pktgate::dataplane
