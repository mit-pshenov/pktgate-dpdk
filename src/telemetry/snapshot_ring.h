// src/telemetry/snapshot_ring.h
//
// M10 C1 — Single-writer / multi-reader Snapshot ring buffer.
//
// D3 — the ring decouples the 1 Hz snapshot writer from the Prom
// `/metrics` reader (only reader in Phase 1, contract allows N).
// The N=4 slack means a slow scraper doesn't stall the writer
// (F8.13 — verified end-to-end in M10 C5).
//
// Contract:
//   * `publish()` is called by a SINGLE writer thread (the telemetry
//     publisher). Concurrent publishers are a contract violation —
//     not guarded here.
//   * `read_latest()` is called by any number of reader threads.
//     Readers see the latest fully-published generation; a reader
//     scheduled mid-publish sees the previous generation.
//
// Synchronisation (TSan-clean design):
//
//   * `latest_gen_` (std::atomic<uint64_t>) tracks the most recently
//     published slot's generation. Acquire-load on read, release-
//     store on publish — pairs with the slot copy so readers that
//     observe `gen >= G` see the slot write for G.
//   * Per-slot `std::shared_mutex`: the writer takes a unique lock
//     on the target slot while doing the move-assign; readers take
//     a shared lock while copying the slot out. At 1 Hz writer
//     cadence + N=4 slots the contention is minimal — a reader
//     rarely races the writer on the SAME slot (they're working on
//     different slots `gen % N`). When they do, the writer waits
//     for the reader's scrape — the worker thread keeps running
//     irrespective (the whole point of the N-slot ring is that the
//     dataplane never blocks on telemetry).
//
// TSan: the per-slot mutex teaches TSan the happens-before edges.
// No race flagged on slot reads/writes even though `Snapshot`
// contains `std::vector` internals. The single-writer contract is
// enforced by convention (not checked); concurrent publishers would
// race on the slot-index selection but the mutex would still make
// each individual slot assignment HB-ordered.
//
// D1 note: these atomics / mutexes are control-plane only. The
// hot path (classify/dispatch) never touches this structure; only
// the 1 Hz telemetry publisher and the HTTP `/metrics` server
// interact with it. D1 forbids atomics on the packet-rate hot
// path, not on the control plane. Reader-side relaxed loads on
// WorkerCtx counter sources (snapshot.cpp) are D1-permitted per
// the 2026-04-17 amendment.

#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <shared_mutex>

#include "src/telemetry/snapshot.h"

namespace pktgate::telemetry {

// N=4 is the production value per D3 (§10.1 snapshot publisher).
// Template on N to keep the test harness flexible; the canonical
// alias below pins the production size.
template <std::size_t N>
class SnapshotRing {
  static_assert(N >= 2, "Ring must have at least 2 slots");

 public:
  SnapshotRing() = default;

  // Non-copyable, non-movable — the atomic member has no copy/move,
  // and the class holds cross-thread state anyway.
  SnapshotRing(const SnapshotRing&) = delete;
  SnapshotRing& operator=(const SnapshotRing&) = delete;
  SnapshotRing(SnapshotRing&&) = delete;
  SnapshotRing& operator=(SnapshotRing&&) = delete;

  // Publish a new snapshot. SINGLE-WRITER contract — concurrent
  // publishers would race on the slot-index selection.
  //
  // `snap.generation` is the writer-assigned generation number. The
  // ring trusts the caller to supply a monotonically-increasing
  // value (the publisher ticks a counter). The slot index is
  // `snap.generation % N`.
  //
  // Implementation: take the slot's unique lock, move the snapshot
  // into the slot, release the lock, then release-store the new
  // generation. The mutex HB-order plus the release-store pair
  // ensures any reader observing `gen >= snap.generation` via
  // acquire-load sees the fully-written slot.
  void publish(Snapshot snap) {
    const std::uint64_t gen = snap.generation;
    const std::size_t idx = static_cast<std::size_t>(gen % N);
    {
      std::unique_lock<std::shared_mutex> lock(slot_mtx_[idx]);
      slots_[idx] = std::move(snap);
    }
    // Release-store after the slot is fully written + the slot
    // mutex released. Readers that acquire-load `latest_gen_ >= gen`
    // and then take the slot's shared lock see the write.
    latest_gen_.store(gen, std::memory_order_release);
  }

  // Read the latest fully-published snapshot.
  //
  // Returns nullopt iff no snapshot has ever been published
  // (`latest_gen_ == 0`). The publisher's first publish MUST use
  // generation >= 1 so readers can disambiguate "nothing yet" from
  // "slot 0 is valid".
  //
  // Returns by value (copy) — the caller owns an independent
  // Snapshot. Reader takes a shared lock on the slot while copying;
  // concurrent writers to the SAME slot wait (rare: writer is on
  // `gen % N`, reader is on `latest % N` which is the same slot
  // only during the contended narrow window). At 1 Hz writer
  // cadence, reader contention is effectively zero.
  std::optional<Snapshot> read_latest() const {
    const std::uint64_t gen = latest_gen_.load(std::memory_order_acquire);
    if (gen == 0) {
      return std::nullopt;
    }
    const std::size_t idx = static_cast<std::size_t>(gen % N);
    std::shared_lock<std::shared_mutex> lock(slot_mtx_[idx]);
    // Copy under shared lock — TSan-clean. The writer's unique-lock
    // publish HB-orders this read.
    return slots_[idx];
  }

  // Observability for tests: peek the current latest generation
  // without copying the slot. Useful for U7.3.
  std::uint64_t latest_generation() const {
    return latest_gen_.load(std::memory_order_acquire);
  }

  static constexpr std::size_t capacity() { return N; }

 private:
  // Slot storage. Default-constructed Snapshots have generation = 0.
  std::array<Snapshot, N> slots_{};
  // Per-slot shared_mutex: writer takes unique_lock, readers take
  // shared_lock. mutable because read_latest is const. At 1 Hz +
  // N=4 the contention is negligible; the mutex exists to make TSan
  // see the happens-before edge on `Snapshot` bytes (including
  // std::vector internals) without requiring seqlock annotations.
  mutable std::array<std::shared_mutex, N> slot_mtx_{};
  // Monotonic generation of the latest fully-published slot. Zero
  // means "no publish yet".
  std::atomic<std::uint64_t> latest_gen_{0};
};

// Production alias — the D3-specified N=4.
using ProdSnapshotRing = SnapshotRing<4>;

}  // namespace pktgate::telemetry
