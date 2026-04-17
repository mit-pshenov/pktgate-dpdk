// src/dataplane/lcore_counter.h
//
// M11 C1.5 — per-lcore telemetry counter bump helpers.
//
// Context: every per-lcore telemetry counter in this codebase is a
// single-writer / multi-reader scalar.
//   * Writer: the owning worker lcore, at packet-rate.
//   * Reader: the SnapshotPublisher thread (`relaxed_load_u64` /
//     `relaxed_load_bucket` in src/telemetry/snapshot.cpp).
//
// Before M11 C1.5 the writer side used a plain `++(*p)` RMW and the
// reader side used `__atomic_load_n(p, __ATOMIC_RELAXED)`. That pairing
// is a data race under the C++ memory model: TSan needs **both** sides
// to be atomic operations for the access to be treated as synchronising
// (plain write + atomic load = race, reported every time).
//
// The fix below keeps the D1 hot-path philosophy intact:
//
//   * The helper compiles to `mov; inc; mov` (or `mov; add; mov` for
//     the `+= delta` variant) on x86-64 — **no `lock` prefix, no bus
//     fence, no cache-line ownership transfer**.  This is functionally
//     indistinguishable from the previous plain `++(*p)` on the single-
//     writer side; single-writer means no other CPU is racing to RMW
//     the same cache line, so the lack of LOCK is correct.
//
//   * It is NOT `__atomic_fetch_add(p, 1, __ATOMIC_RELAXED)`: that
//     lowers to `lock xadd` on x86-64, which IS a contention fence at
//     Mpps and directly violates D1 ("per-lcore token bucket, zero
//     atomic RMW on the packet-rate hot path"). Same for
//     `std::atomic<uint64_t>::fetch_add`. See
//     grabli_tsan_hotpath_atomic_antipattern.md.
//
//   * The load + store pair is what the C++ memory model calls an
//     "atomic operation" on `p` (the compiler treats the pointed-to
//     storage as atomic-accessed), so the publisher's
//     `__atomic_load_n(p, __ATOMIC_RELAXED)` forms a proper
//     well-defined pair. TSan no longer reports a race on the access.
//     This is a TSAN synchronisation annotation on the writer, not an
//     inter-CPU fence — the semantics differ sharply from `fetch_add`.
//
// D1 amendment scope (review-notes §D1 telemetry clause, 2026-04-17):
//   RELAXED load+store pairs for single-writer per-lcore telemetry
//   counters are explicitly permitted.  The D1 prohibition targets
//   `lock xadd` / CAS / atomic RMW that coordinates across CPUs; this
//   helper is structurally none of those.
//
// Codegen check (to verify the invariant holds after a toolchain bump):
//   objdump -d <worker.cpp.o> | grep -A 3 'relaxed_bump' | head -20
//   → expect mov/inc/mov; NO `lock` prefix anywhere.
//
// Usage:
//   if (ctr) relaxed_bump(ctr);
//   if (bucket) relaxed_bump_bucket(bucket, slot_idx);
//   if (row) relaxed_add(&row->matched_bytes, pkt_len);

#pragma once

#include <cstddef>
#include <cstdint>

namespace pktgate::dataplane {

// Relaxed atomic RMW-increment for a single-writer per-lcore counter.
// Paired with snapshot.cpp relaxed_load_u64() on the publisher thread.
//
// Codegen on x86-64 (gcc/clang, any optimisation level): plain
// mov; inc; mov — no `lock` prefix, no bus fence. Indistinguishable
// from `++(*p)` on the writer CPU while giving TSan the annotation it
// needs to treat the publisher's relaxed load as a matched pair.
inline void relaxed_bump(std::uint64_t* p) noexcept {
  __atomic_store_n(p,
                   __atomic_load_n(p, __ATOMIC_RELAXED) + 1u,
                   __ATOMIC_RELAXED);
}

// Bucket-array variant: bump arr[idx] under the same pairing.
inline void relaxed_bump_bucket(std::uint64_t* arr,
                                std::size_t idx) noexcept {
  relaxed_bump(arr + idx);
}

// Relaxed add-delta variant — used for `matched_bytes += pkt_len` and
// `redirect_dropped_total += (s.count - sent)` where we add more than
// one unit at a time. Same codegen story (mov; add; mov); same TSan
// annotation semantics as relaxed_bump.
inline void relaxed_add(std::uint64_t* p, std::uint64_t delta) noexcept {
  __atomic_store_n(p,
                   __atomic_load_n(p, __ATOMIC_RELAXED) + delta,
                   __ATOMIC_RELAXED);
}

}  // namespace pktgate::dataplane
