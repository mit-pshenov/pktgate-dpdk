// src/dataplane/classify_entry.h
//
// M4 C9 — shared pre-classify entry gate.
//
// Promotes the D39 "headers-in-first-seg" invariant check out of
// classify_l2 so classify_l3 / classify_l4 (M5/M6) can reuse the same
// entry gate without duplicating the logic.  Before C9 the check lived
// inline in `worker.cpp` (runtime guard) with a comment in classify_l2.h
// stating the precondition; the refactor is a pure lift, no behaviour
// change for classify_l2.
//
// Design anchors:
//   * D39 — headers-in-first-seg invariant (nb_segs == 1 precondition for
//           every classifier stage; port init enforces scatter-off +
//           mempool-fit, this helper is the second-line safety net).
//   * §5.1 preamble — "Headers-in-first-seg invariant" paragraph
//   * implementation-plan.md §M4 REFACTOR (lines 344-347) — the cycle body.
//
// Release builds: `if (unlikely(m->nb_segs != 1))` path that bumps a
// per-lcore counter and returns false.  Debug builds: RTE_ASSERT first
// so UB shows up as an immediate abort under test, not a silent counter
// bump.
//
// The helper is header-only and `inline` so the hot path stays leaf-call
// free; the bump site uses a raw `uint64_t*` (no atomics, D1) matching
// the WorkerCtx per-lcore counter field directly.

#pragma once

#include <cstdint>

#include <rte_branch_prediction.h>
#include <rte_debug.h>
#include <rte_mbuf.h>

namespace pktgate::dataplane {

// -------------------------------------------------------------------------
// classify_entry_ok — D39 pre-classify gate.
//
// Returns true iff the mbuf satisfies the headers-in-first-seg invariant
// (nb_segs == 1).  On a violation:
//   * bumps `*multiseg_drop_ctr` if non-null (per-lcore counter, no atomics)
//   * returns false (caller must free the mbuf and advance to the next one)
//
// Debug builds additionally RTE_ASSERT — a multi-seg mbuf reaching here
// means either port validator D39 check was bypassed or a PMD lied about
// scatter capability; both are bugs worth an immediate abort during
// development.
//
// Usage pattern (worker.cpp):
//
//     if (!classify_entry_ok(bufs[i], &ctx->pkt_multiseg_drop_total)) {
//       rte_pktmbuf_free(bufs[i]);
//       continue;
//     }
//     // proceed with classify_l2 / classify_l3 / classify_l4 ...
//
// The optional counter pointer mirrors the
// `grabli_classify_l2_optional_counter_pattern.md` convention: callers
// that do not own per-lcore storage (unit tests) pass nullptr.

inline bool classify_entry_ok(const struct rte_mbuf* m,
                              std::uint64_t* multiseg_drop_ctr = nullptr) noexcept {
  if (unlikely(m->nb_segs != 1)) {
    if (multiseg_drop_ctr != nullptr) {
      ++(*multiseg_drop_ctr);
    }
    return false;
  }
  // Debug-only: after the release-build check passed, assert the
  // invariant holds.  Any PMD misbehaviour that sneaks a chain past the
  // check trips the assert under dev-debug / dev-asan.
  RTE_ASSERT(m->nb_segs == 1);
  return true;
}

}  // namespace pktgate::dataplane
