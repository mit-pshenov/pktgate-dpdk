// src/telemetry/snapshot_publisher.h
//
// M10 C3 — snapshot publisher thread wrapper (deferred from C1).
//
// D3 — single 1 Hz writer that aggregates per-lcore counters + port
// stats into a Snapshot and publishes into the SnapshotRing. Runs on
// its own std::thread; lifecycle controlled by a caller-owned
// `std::atomic<bool>` "running" flag (the main process ties this to
// `pktgate::ctl::g_running` so SIGTERM flips both the workers and
// the publisher in one go).
//
// DPDK-free: the caller passes a `build_fn` callback. Unit tests
// supply a pure fake; `main.cpp` supplies a lambda that reads
// `rte_eth_stats_get` + walks the live Ruleset counter rows and
// invokes `build_snapshot(...)` from snapshot.h. This is the same
// layering seam `pktgate_rl` / `pktgate_rl_ctl` established — the
// telemetry lib owns NO `rte_*` symbols.
//
// Shutdown contract: the publisher loop wakes every 100 ms
// (`kWakeIntervalMs`) and checks `running->load(acquire)`. When the
// flag flips false, the loop exits promptly. U7.X2 pins the join
// latency at <200 ms — guards against the naive `sleep(1000 ms)`
// cadence that would make SIGTERM stall up to a second.
//
// Cadence note: the loop emits one snapshot per `kPublishIntervalMs`
// (default 1000 ms). Between publishes it sleeps in
// `kWakeIntervalMs` slices so shutdown stays responsive. A longer
// publish cadence does NOT make shutdown slower.

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <thread>

#include "src/telemetry/snapshot.h"
#include "src/telemetry/snapshot_ring.h"

namespace pktgate::telemetry {

// Publisher config + control-plane lifecycle. Not thread-safe on its
// own — the caller constructs it on one thread, `start()` spawns the
// internal worker, `stop()` joins it. Move / copy forbidden.
class SnapshotPublisher {
 public:
  // Signature of the snapshot-builder callback. Receives the next
  // generation number (already assigned by the publisher) and
  // returns the fully-built Snapshot. Callback runs on the
  // publisher's own thread, must be thread-safe w.r.t. the live
  // WorkerCtx counters it reads (reader-side relaxed atomic loads
  // — see snapshot.cpp).
  using BuildFn = std::function<Snapshot(std::uint64_t generation)>;

  // Default publish interval. 1 Hz per D3 §10.1.
  static constexpr unsigned kPublishIntervalMs = 1000;
  // Wake interval inside the sleep loop. 100 ms guarantees clean
  // shutdown within 200 ms of `running=false`. See U7.X2.
  static constexpr unsigned kWakeIntervalMs = 100;

  SnapshotPublisher() = default;
  SnapshotPublisher(const SnapshotPublisher&) = delete;
  SnapshotPublisher& operator=(const SnapshotPublisher&) = delete;
  SnapshotPublisher(SnapshotPublisher&&) = delete;
  SnapshotPublisher& operator=(SnapshotPublisher&&) = delete;
  ~SnapshotPublisher() { stop(); }

  // Spawn the publisher thread. `ring` and `running` must outlive
  // the publisher (stop()/join is driven by `*running == false`).
  // `build_fn` is invoked from the publisher thread; copied into
  // the std::function member.
  //
  // Calling start() twice without an intervening stop() is a
  // programmer error (the method silently returns on the second
  // call to avoid corrupting the std::thread).
  void start(ProdSnapshotRing& ring,
             std::atomic<bool>& running,
             BuildFn build_fn,
             unsigned publish_interval_ms = kPublishIntervalMs);

  // Join the publisher thread. Safe to call multiple times; safe to
  // call without a prior start(). Does NOT flip `running` — the
  // caller owns that flag.
  void stop();

  // Observability: current generation counter (monotonically
  // increased on each publish). Useful for tests that need to
  // assert "publisher looped at least N times".
  std::uint64_t generation() const {
    return generation_.load(std::memory_order_acquire);
  }

 private:
  void run_loop(ProdSnapshotRing* ring,
                std::atomic<bool>* running,
                BuildFn build_fn,
                unsigned publish_interval_ms);

  std::thread thread_;
  // Monotonic publish-generation counter. Writer-side; read by
  // `generation()` for test observability.
  std::atomic<std::uint64_t> generation_{0};
  // Tracks whether start() has been called; prevents double-start
  // from corrupting `thread_`.
  bool started_{false};
};

}  // namespace pktgate::telemetry
