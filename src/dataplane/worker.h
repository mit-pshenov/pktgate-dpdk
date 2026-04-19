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

#include <rte_config.h>                   // RTE_MAX_ETHPORTS
#include <rte_mbuf.h>

#include "src/dataplane/classify_l2.h"  // L2TruncCtrs, L2TruncBucket

// Forward-declare the DPDK QSBR handle — worker.cpp includes the real
// header. Keeping this opaque in worker.h avoids pulling rte_rcu_qsbr
// into every TU that includes WorkerCtx.
struct rte_rcu_qsbr;
#include "src/dataplane/classify_l3.h"  // ClassifyL3Verdict (M5 C0)
#include "src/dataplane/classify_l4.h"  // ClassifyL4Verdict, L4TruncCtrs (M6 C0)
#include "src/ruleset/ruleset.h"

// M9 C2 — forward-declare the rate-limit arena class. The full
// definition lives in src/rl_arena/arena.h (libpktgate_rl_ctl). Worker
// keeps a pointer; action_dispatch dereferences it when handling the
// kRateLimit verb. Pointer is stable for the process lifetime (arena
// outlives every Ruleset — D10) so no per-burst refresh is needed.
namespace pktgate::rl_arena {
class RateLimitArena;
}

namespace pktgate::dataplane {

// M7 C0: TX burst hook signature. Matches rte_eth_tx_burst so the
// production path stores `&rte_eth_tx_burst` directly. Unit tests
// override the hook with a spy (the EalFixture has no real ports,
// so a direct rte_eth_tx_burst call would hit RTE_MAX_ETHPORTS).
using TxBurstFn = std::uint16_t (*)(std::uint16_t port_id,
                                    std::uint16_t queue_id,
                                    rte_mbuf** tx_pkts,
                                    std::uint16_t nb_pkts);

// M7 C2 — D16 REDIRECT staging buffer.
//
// REDIRECT stages packets into a per-target-port buffer; actual TX
// happens at end of burst in redirect_drain().  This fixes the mbuf
// leak on TX-full in the naive inline-TX design (review-notes D16):
// unsent mbufs are explicitly freed + counted at drain time.
//
// Buffer size: kRedirectBurstMax = 32.  Matches the RX burst size so
// even a full burst of REDIRECT hits fits; small constant keeps the
// per-worker memory footprint bounded (32 * RTE_MAX_ETHPORTS * 8 B ~
// 8 KB of staging pointers per worker for RTE_MAX_ETHPORTS = 32).
//
// Buffer-full policy: drop the NEW incoming packet at stage time
// (bump redirect_dropped_total, free the mbuf).  Rationale: the
// packets already staged are closer to being drained; dropping the
// new arrival keeps head-of-line semantics and avoids an O(N) shift.
// This is a defensive guard — the buffer should never fill in
// practice because drain runs at end of every RX burst.
constexpr std::uint16_t kRedirectBurstMax = 32;

struct RedirectBuf {
  std::uint16_t count = 0;
  rte_mbuf*     pkts[kRedirectBurstMax] = {};
};

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

  // M8 C4 — D12 RCU QSBR lifecycle.
  //
  // `qs` is the process-wide QSBR handle owned by the reload manager's
  // caller (main.cpp in production, the integration fixture in tests).
  // `qsbr_thread_id` is assigned by main.cpp from a monotonic
  // per-worker counter (0..num_workers-1) and MUST be unique across
  // concurrently-registered workers.
  //
  // Worker contract (see src/dataplane/worker.cpp):
  //   * on entry: rte_rcu_qsbr_thread_register(qs, tid) +
  //                rte_rcu_qsbr_thread_online(qs, tid)
  //   * in loop: rte_rcu_qsbr_quiescent(qs, tid) between bursts so
  //               the reload manager's synchronize path drains
  //   * on exit: rte_rcu_qsbr_thread_offline(qs, tid) +
  //                rte_rcu_qsbr_thread_unregister(qs, tid)
  //
  // When `qs == nullptr` the lifecycle is skipped — D12 falls back to
  // "caller joins workers then immediate free" (unit tests that don't
  // configure QSBR). Production always sets this.
  struct rte_rcu_qsbr* qs            = nullptr;
  unsigned int         qsbr_thread_id = 0;

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
  // M7 C1: D19 TAG semantics. Bumped when apply_action handles a TAG
  // verb with pcp != 0 against an untagged frame — the PCP rewrite
  // is a no-op (design §5.5 TAG case: we MUST NOT insert a VLAN tag
  // on behalf of the operator). stats_on_exit surfacing in C3 per
  // handoff plan.
  std::uint64_t tag_pcp_noop_untagged_total = 0;

  // M7 C2 — D16 REDIRECT staging.
  //
  // One per-target-port staging buffer.  Indexed by the action's
  // redirect_port field; sized RTE_MAX_ETHPORTS for MVP (the array is
  // sparse — only ports actually targeted by REDIRECT rules ever see
  // non-zero counts).  Drained at end of every RX burst via
  // redirect_drain() in worker.cpp; unsent mbufs freed + counted.
  RedirectBuf redirect_tx[RTE_MAX_ETHPORTS] = {};

  // M7 C2: D16 REDIRECT drop counter.  Bumped on:
  //   (a) drain partial send — (s.count - sent) unsent mbufs freed;
  //   (b) stage-time buffer full — new mbuf dropped, one increment.
  // Single counter covers both cases per unit.md U6.54/U6.55 wording
  // ("redirect_dropped_total += (s.n - sent)" for drain; U6.55 notes
  // implementation MAY use a different counter but spec allows the
  // shared counter so long as no overflow occurs).
  std::uint64_t redirect_dropped_total = 0;

  // M14 C3 — D43 per-port backpressure counters emitted by pktgate's
  // own tx wrappers (tx_one() + redirect_drain() in action_dispatch.h).
  // PMD-agnostic: these see every TX drop the driver returns on ANY
  // backend (pci / TAP / vhost / memif), where per-driver xstats
  // differ wildly.
  //
  //   tx_dropped_per_port[p]       — bumped whenever rte_eth_tx_burst
  //                                  (or the unit-test spy) returns
  //                                  fewer packets than requested.
  //                                  tx_one: +1 when sent == 0.
  //                                  redirect_drain: += (count - sent).
  //   tx_burst_short_per_port[p]   — bumped once per redirect_drain
  //                                  call that was partially accepted
  //                                  (sent > 0 && sent < count). This
  //                                  is the "short burst" signal the
  //                                  operator uses to detect
  //                                  backpressure onset (a single
  //                                  dropped packet should not by
  //                                  itself trip an alert).
  //
  // Per-lcore, indexed by dst port_id. RTE_MAX_ETHPORTS slots keeps
  // the array addressable by any legal port id without a bounds
  // branch per bump; sparse in practice (only ports actually targeted
  // by ALLOW/TAG/REDIRECT ever see non-zero counts). Memory cost:
  // 32 × 8 B × 2 arrays = 512 B per WorkerCtx.
  //
  // D1 hot-path invariant: bumped via relaxed_bump_bucket / relaxed_add
  // helpers in src/dataplane/lcore_counter.h; lowers to mov/inc/mov
  // on x86-64 with no `lock` prefix. Single-writer per lcore; no
  // cross-CPU RMW, so D1 zero-atomics is preserved.
  std::uint64_t tx_dropped_per_port[RTE_MAX_ETHPORTS]     = {};
  std::uint64_t tx_burst_short_per_port[RTE_MAX_ETHPORTS] = {};

  // M9 C2 — rate-limit arena handle. Stable pointer for the entire
  // worker lifetime; the arena lives outside the Ruleset (D10) and
  // outlives every reload. action_dispatch reads
  // `rl_arena->get_row(action->rl_index).per_lcore[lcore_id]` on the
  // kRateLimit verb arm — per-lcore isolation guarantees D1 zero-
  // atomics with no cross-thread sharing of bucket state.
  //
  // Null in unit-test WorkerCtx fixtures that do not exercise the
  // RL path; action_dispatch guards the pointer and falls through to
  // a defensive drop if the RL verb fires without an arena configured.
  pktgate::rl_arena::RateLimitArena* rl_arena = nullptr;

  // M9 C2 — cached TSC frequency. Populated once at worker init from
  // `rte_get_tsc_hz()`; re-read per packet would be wasteful (some
  // kernels implement the DPDK helper over a kernel call the first
  // time). Used by action_dispatch::rl_consume.
  std::uint64_t tsc_hz = 0;

  // M8 C4 — D12 TSAN-visible handshake.
  //
  // `rte_eal_mp_wait_lcore()` pthread_join's every worker and that IS
  // a real happens-before edge — BUT ThreadSanitizer is blind to it:
  // librte_eal.so isn't instrumented so TSan can't observe DPDK's
  // internal sync. All of the worker's counter bumps (per-rule
  // counter rows, WorkerCtx scalar fields) are then read by the main
  // thread's stats_on_exit emitter, which TSan correctly flags as a
  // race against the worker's last write.
  //
  // `worker_done` closes that gap. The worker issues a release store
  // as its last instrumented action before returning; the main
  // thread spin-waits on an acquire load after rte_eal_mp_wait_lcore
  // before touching any per-lcore counter. The store-release /
  // load-acquire pair is instrumented (both sides live in this TU,
  // not in a DPDK .so) so TSan sees the HB edge.
  //
  // This is NOT a hot-path atomic (grabli_tsan_hotpath_atomic_antipattern):
  // it's ONE store per worker lifetime + ONE load per worker lifetime
  // at shutdown. Zero atomics in the classify/dispatch path per D1.
  std::atomic<bool> worker_done{false};
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
