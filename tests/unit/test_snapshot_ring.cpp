// tests/unit/test_snapshot_ring.cpp
//
// M10 C1 — unit tests for the SnapshotRing single-writer /
// multi-reader ring buffer.
//
// RED → GREEN coverage:
//   * U7.3 ring buffer N=4 — publish 6 snapshots, reader acquire-
//          loads latest, sees gen=6; oldest 2 overwritten. Single-
//          writer TSAN race-free (dev-tsan gate).
//   * U7.4 slot reuse zero-init — writer overwriting an old slot
//          produces a snapshot with ONLY the current values, no
//          carryover from the wrapped-over slot. Protects against
//          a future "partial update" refactor.
//
// The TSAN harness (U7.3) spins a single writer thread + a single
// reader thread that both pound the ring. The structure of publish
// (plain slot store + release gen store) vs read (acquire gen load
// + plain slot read, via copy-return) MUST be race-free under
// ThreadSanitizer. dev-tsan preset runs with TSAN_OPTIONS
// `halt_on_error=1` (CMakePresets.json) so any race fails the test.
//
// Pure C++, no DPDK. Links `pktgate_telemetry`.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <thread>
#include <vector>

#include "src/telemetry/snapshot.h"
#include "src/telemetry/snapshot_ring.h"

namespace {

using ::pktgate::telemetry::ProdSnapshotRing;
using ::pktgate::telemetry::Snapshot;
using ::pktgate::telemetry::SnapshotRing;

// ---------------------------------------------------------------
// U7.3 — Ring buffer N=4.
//
// Publish 6 snapshots with monotonic generation 1..6. Reader
// read_latest() must return the snapshot with generation == 6. The
// ring holds only 4 slots so generations 1 and 2 have been
// overwritten (by 5 and 6 respectively), but the reader contract
// only promises "latest" — slots 3/4/5/6 are still present, the
// latest is 6.
// ---------------------------------------------------------------

TEST(SnapshotRing, U7_3_PublishSixSeesLatestGen) {
  ProdSnapshotRing ring;

  for (std::uint64_t g = 1; g <= 6; ++g) {
    Snapshot snap;
    snap.generation = g;
    snap.pkt_multiseg_drop_total = g * 10;
    snap.qinq_outer_only_total   = g * 100;
    ring.publish(std::move(snap));
  }

  auto latest = ring.read_latest();
  ASSERT_TRUE(latest.has_value());
  EXPECT_EQ(latest->generation, 6u);
  EXPECT_EQ(latest->pkt_multiseg_drop_total, 60u);
  EXPECT_EQ(latest->qinq_outer_only_total, 600u);

  EXPECT_EQ(ring.latest_generation(), 6u);
  EXPECT_EQ(ring.capacity(), 4u);
}

// ---------------------------------------------------------------
// U7.3 corollary — before any publish, read_latest returns nullopt.
// The publisher's first generation MUST be >= 1; generation 0 is
// reserved as the "no snapshot yet" sentinel.
// ---------------------------------------------------------------

TEST(SnapshotRing, U7_3_InitialReadReturnsNullopt) {
  ProdSnapshotRing ring;
  EXPECT_FALSE(ring.read_latest().has_value());
  EXPECT_EQ(ring.latest_generation(), 0u);
}

// ---------------------------------------------------------------
// U7.3 TSAN — single-writer + single-reader concurrent harness.
//
// Writer publishes monotonically-increasing generations; reader
// acquire-loads latest and verifies INTERNAL CONSISTENCY of every
// observed snapshot. With the mutex-protected slot design, each
// Snapshot returned by read_latest() must be self-consistent — the
// writer sets `pkt_multiseg_drop_total = g` and `qinq_outer = g*2`
// at publish time, so any observed snapshot with `generation == G`
// must have both scalar fields matching G's pattern.
//
// We do NOT assert monotonicity across consecutive reader calls:
// between the `latest_gen_.load()` and the shared-lock acquire, the
// writer may have rewritten a *different* slot with a lower-mod
// index, so two consecutive reads can surface gen=N then gen<N for
// the slot the reader happened to pick. That's acceptable — the
// Prom scraper takes the latest snapshot at one point in time, not
// a streaming delta.
//
// Under dev-tsan: TSAN_OPTIONS halt_on_error=1 means any race
// observed on the slot bytes OR the std::vector internals fails
// the test at runtime.
// ---------------------------------------------------------------

TEST(SnapshotRing, U7_3_TsanSingleWriterSingleReaderRaceFree) {
  ProdSnapshotRing ring;
  std::atomic<bool> stop{false};

  constexpr std::uint64_t kIters = 1000;

  std::thread writer([&] {
    for (std::uint64_t g = 1; g <= kIters; ++g) {
      Snapshot snap;
      snap.generation = g;
      snap.pkt_multiseg_drop_total = g;
      snap.qinq_outer_only_total   = g * 2;
      ring.publish(std::move(snap));
    }
    stop.store(true, std::memory_order_release);
  });

  std::thread reader([&] {
    std::uint64_t max_seen = 0;
    while (!stop.load(std::memory_order_acquire)) {
      auto snap = ring.read_latest();
      if (!snap.has_value()) continue;
      // Internal consistency: if we saw gen=g, the embedded fields
      // must match the writer's pattern for gen g (writer assigns
      // pkt_multiseg_drop_total = g, qinq = g*2 before publishing).
      // Any torn read would fail this check.
      EXPECT_EQ(snap->pkt_multiseg_drop_total, snap->generation);
      EXPECT_EQ(snap->qinq_outer_only_total, snap->generation * 2u);
      if (snap->generation > max_seen) max_seen = snap->generation;
    }
    // One final read after stop, to pick up the last publish.
    auto snap = ring.read_latest();
    ASSERT_TRUE(snap.has_value());
    EXPECT_EQ(snap->pkt_multiseg_drop_total, snap->generation);
    EXPECT_EQ(snap->qinq_outer_only_total, snap->generation * 2u);
  });

  writer.join();
  reader.join();

  // After both threads have joined, the writer's last publish is
  // fully ordered before this read (thread join is an HB edge). The
  // final `latest_gen` MUST be kIters.
  auto final_snap = ring.read_latest();
  ASSERT_TRUE(final_snap.has_value());
  EXPECT_EQ(final_snap->generation, kIters);
  EXPECT_EQ(ring.latest_generation(), kIters);
}

// ---------------------------------------------------------------
// U7.4 — Zero-init on slot reuse.
//
// Publish generation 1 with non-trivial fields. Publish generation
// 5 (which reuses slot index `5 % 4 == 1`) with DIFFERENT field
// values. Read back gen=5: every field must reflect the gen=5
// publish, NONE of the gen=1 carryover.
//
// The current impl moves a freshly-constructed Snapshot into the
// slot (`slots_[idx] = std::move(snap)`), so this is inherently
// true. The test protects against a future "partial update"
// refactor that tried to memcpy only non-zero fields, or reused
// scratch buffers without clearing — either would fail here.
// ---------------------------------------------------------------

TEST(SnapshotRing, U7_4_SlotReuseZeroInitOnOverwrite) {
  ProdSnapshotRing ring;

  // First publish: generation 1 with non-trivial state.
  {
    Snapshot snap;
    snap.generation = 1;
    snap.pkt_multiseg_drop_total = 777;
    snap.qinq_outer_only_total   = 555;
    snap.per_rule.push_back({.rule_id         = 999,
                             .matched_packets = 100,
                             .matched_bytes   = 10'000,
                             .drops           = 10,
                             .rl_drops        = 1,
                             .layer           = 3});
    snap.per_port.push_back({.ipackets = 123'456});
    ring.publish(std::move(snap));
  }

  // Publish gens 2, 3, 4 with minimal state to advance the writer
  // past the first slot.
  for (std::uint64_t g = 2; g <= 4; ++g) {
    Snapshot snap;
    snap.generation = g;
    ring.publish(std::move(snap));
  }

  // Generation 5 reuses slot index 5 % 4 == 1, same slot as gen 1.
  // The new snapshot has distinct non-zero values in a subset of
  // fields; all OTHER fields must be zero / empty.
  {
    Snapshot snap;
    snap.generation = 5;
    snap.pkt_multiseg_drop_total = 42;
    // Deliberately leave qinq_outer_only_total = 0, per_rule empty,
    // per_port empty — these must NOT carry over from gen 1.
    ring.publish(std::move(snap));
  }

  auto latest = ring.read_latest();
  ASSERT_TRUE(latest.has_value());
  EXPECT_EQ(latest->generation, 5u);
  EXPECT_EQ(latest->pkt_multiseg_drop_total, 42u);

  // These MUST be zero/empty — the gen 1 payload must not leak
  // through the shared slot.
  EXPECT_EQ(latest->qinq_outer_only_total, 0u)
      << "Gen 1 value 555 leaked through slot reuse.";
  EXPECT_EQ(latest->per_rule.size(), 0u)
      << "Gen 1 per_rule leaked through slot reuse.";
  EXPECT_EQ(latest->per_port.size(), 0u)
      << "Gen 1 per_port leaked through slot reuse.";
}

// ---------------------------------------------------------------
// U7.4 corollary — explicit slot-indexing round trip for N=2. With
// a smaller ring the slot-reuse wrap is immediate (gen 2 reuses
// slot 0). Verifies the modulo math and that reader observes the
// new payload, not the old.
// ---------------------------------------------------------------

TEST(SnapshotRing, U7_4_SmallRingImmediateWrap) {
  SnapshotRing<2> ring;
  {
    Snapshot s;
    s.generation = 1;
    s.pkt_multiseg_drop_total = 111;
    ring.publish(std::move(s));
  }
  {
    Snapshot s;
    s.generation = 2;
    s.pkt_multiseg_drop_total = 222;
    ring.publish(std::move(s));
  }
  {
    Snapshot s;
    s.generation = 3;  // wraps back to slot 1
    s.pkt_multiseg_drop_total = 333;
    ring.publish(std::move(s));
  }
  auto latest = ring.read_latest();
  ASSERT_TRUE(latest.has_value());
  EXPECT_EQ(latest->generation, 3u);
  EXPECT_EQ(latest->pkt_multiseg_drop_total, 333u);
}

}  // namespace
