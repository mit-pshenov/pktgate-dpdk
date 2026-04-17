// tests/unit/test_snapshot_publisher.cpp
//
// M10 C3 — unit tests for the SnapshotPublisher thread wrapper.
//
// RED → GREEN coverage:
//   * U7.X1 — publisher loops. generation() increases by >= 1 across
//             a 1.5 s wall-clock window. Guards against a broken loop
//             body that publishes once and falls out.
//   * U7.X2 — shutdown latency. running=false → thread join within
//             200 ms. Guards against the naive `sleep(1000)` cadence
//             that would leave SIGTERM stalled up to a second (D1
//             amendment 2026-04-17: lifecycle atomics are OK,
//             control-plane only).
//   * U7.X3 — first publish happens before stop(). Ordering contract
//             for the scrape path (HttpServer must see at least one
//             snapshot on first scrape — either by waiting for
//             publisher or by returning an empty-but-valid body; the
//             C3 main.cpp wires publisher-start BEFORE HTTP accept
//             thread so empty-scrape is a real-world rare edge).
//
// Pure C++, no DPDK. Links pktgate_telemetry.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>

#include "src/telemetry/snapshot.h"
#include "src/telemetry/snapshot_publisher.h"
#include "src/telemetry/snapshot_ring.h"

namespace {

using ::pktgate::telemetry::ProdSnapshotRing;
using ::pktgate::telemetry::Snapshot;
using ::pktgate::telemetry::SnapshotPublisher;

// Small build fn: returns a Snapshot with the generation number
// stamped into `pkt_multiseg_drop_total` so the test can verify
// round-trip identity. Pure, no side effects.
Snapshot test_build(std::uint64_t gen) {
  Snapshot s;
  s.generation = gen;
  s.pkt_multiseg_drop_total = gen * 10u;
  return s;
}

// ------------------------------------------------------------------
// U7.X1 — publisher actually loops + publishes more than once.
// ------------------------------------------------------------------
TEST(SnapshotPublisher, U7_X1_PublisherLoopsAtExpectedCadence) {
  ProdSnapshotRing ring;
  std::atomic<bool> running{true};
  SnapshotPublisher pub;

  // Use a short publish interval (100 ms) so the test wall-clock
  // stays under 2 s. The production cadence is 1 s; the loop logic
  // is identical either way.
  pub.start(ring, running, test_build, /*publish_interval_ms=*/100);

  std::this_thread::sleep_for(std::chrono::milliseconds(500));

  // We slept 500 ms, publisher ticks every 100 ms → we must have
  // seen at least 2 generations (conservative lower bound: CI
  // scheduler jitter can eat up to ~300 ms on a busy runner).
  const std::uint64_t gen_after_sleep = pub.generation();
  EXPECT_GE(gen_after_sleep, 2u)
      << "Publisher should have looped at least twice in 500 ms "
         "(observed generation=" << gen_after_sleep << ")";

  running.store(false, std::memory_order_release);
  pub.stop();

  // Final latest snapshot must match the last publish.
  auto latest = ring.read_latest();
  ASSERT_TRUE(latest.has_value());
  EXPECT_EQ(latest->generation, latest->pkt_multiseg_drop_total / 10u);
  EXPECT_GE(latest->generation, gen_after_sleep);
}

// ------------------------------------------------------------------
// U7.X2 — shutdown latency bound. Guards against `sleep(1000)` style
// cadences that block the entire shutdown on a full sleep slice.
// ------------------------------------------------------------------
TEST(SnapshotPublisher, U7_X2_ShutdownJoinsWithin200Ms) {
  ProdSnapshotRing ring;
  std::atomic<bool> running{true};
  SnapshotPublisher pub;

  // Production cadence (1 s publish interval). The loop body MUST
  // use a shorter wake interval (100 ms) or the join will stall up
  // to the publish interval. This is the whole point of the test.
  pub.start(ring, running, test_build, /*publish_interval_ms=*/1000);

  // Let the publisher enter its sleep phase so the shutdown has to
  // interrupt a sleep, not catch the thread mid-build.
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  const auto t0 = std::chrono::steady_clock::now();
  running.store(false, std::memory_order_release);
  pub.stop();
  const auto elapsed = std::chrono::steady_clock::now() - t0;

  const auto elapsed_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(elapsed)
          .count();
  EXPECT_LT(elapsed_ms, 200)
      << "Publisher stop() took " << elapsed_ms
      << " ms; cadence regressed to sleep-whole-interval";
}

// ------------------------------------------------------------------
// U7.X3 — first publish before stop. A started-then-immediately-
// stopped publisher must still publish at least once (the `run_loop`
// builds a snapshot on entry, before its first sleep). The scrape
// path relies on this: HttpServer::start() happens right after
// SnapshotPublisher::start(), and we want the first scrape to see a
// valid ring.
// ------------------------------------------------------------------
TEST(SnapshotPublisher, U7_X3_FirstPublishBeforeStop) {
  ProdSnapshotRing ring;
  std::atomic<bool> running{true};
  SnapshotPublisher pub;

  pub.start(ring, running, test_build, /*publish_interval_ms=*/1000);

  // Give the thread a brief window to publish its first snapshot.
  // 50 ms is plenty — the build fn is a no-op and the first publish
  // happens before the loop's first sleep.
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  auto latest = ring.read_latest();
  EXPECT_TRUE(latest.has_value())
      << "Publisher did not publish any snapshot within 50 ms of "
         "start; scrape-vs-publish ordering contract broken";
  if (latest) {
    EXPECT_EQ(latest->generation, 1u)
        << "First publish must use generation=1 (0 reserved as "
           "SnapshotRing sentinel)";
  }

  running.store(false, std::memory_order_release);
  pub.stop();
}

}  // namespace
