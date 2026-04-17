// src/telemetry/snapshot_publisher.cpp
//
// M10 C3 — publisher thread implementation. See snapshot_publisher.h.

#include "src/telemetry/snapshot_publisher.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>
#include <utility>

namespace pktgate::telemetry {

void SnapshotPublisher::start(ProdSnapshotRing& ring,
                              std::atomic<bool>& running,
                              BuildFn build_fn,
                              unsigned publish_interval_ms) {
  if (started_) {
    // Double-start — silent no-op to preserve thread_.
    return;
  }
  started_ = true;
  thread_ = std::thread(&SnapshotPublisher::run_loop, this, &ring,
                        &running, std::move(build_fn),
                        publish_interval_ms);
}

void SnapshotPublisher::stop() {
  if (thread_.joinable()) {
    thread_.join();
  }
  // Leave started_ = true so a post-stop start() stays a no-op
  // (publisher is one-shot by contract).
}

void SnapshotPublisher::run_loop(ProdSnapshotRing* ring,
                                 std::atomic<bool>* running,
                                 BuildFn build_fn,
                                 unsigned publish_interval_ms) {
  using namespace std::chrono;

  // Publish generation 1 immediately on entry so the scrape path
  // has a valid snapshot as soon as start() returns. U7.X3 pins
  // this contract.
  while (running->load(std::memory_order_acquire)) {
    const std::uint64_t gen =
        generation_.fetch_add(1, std::memory_order_relaxed) + 1;
    Snapshot snap = build_fn(gen);
    // Ensure generation matches what the ring expects (caller may
    // have overwritten it; we canonicalise here).
    snap.generation = gen;
    ring->publish(std::move(snap));

    // Sleep in kWakeIntervalMs slices so shutdown stays responsive.
    // Total slept across this publish interval = publish_interval_ms.
    unsigned remaining = publish_interval_ms;
    while (remaining > 0 &&
           running->load(std::memory_order_acquire)) {
      const unsigned slice =
          remaining < kWakeIntervalMs ? remaining : kWakeIntervalMs;
      std::this_thread::sleep_for(milliseconds(slice));
      remaining -= slice;
    }
  }
}

}  // namespace pktgate::telemetry
