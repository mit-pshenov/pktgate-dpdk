// tests/integration/test_reload.cpp
//
// M8 C0 — integration tier scaffold + QSBR bring-up fixture.
//
// This is the FIRST integration binary. Scope for C0 is deliberately
// minimal: prove the tier compiles, EAL initialises, and a real
// rte_rcu_qsbr state machine can be driven by fake worker threads.
// Later cycles (C1-C5) grow deploy() / reload_mutex / pending_free /
// shutdown sequencing on top of this same fixture.
//
// M8 plan anchors (implementation-plan.md §M8 + scratch/m8-supervisor-
// handoff.md):
//   D9   — single process-wide g_active (U6.42/U6.43 live in test_eal_unit)
//   D11  — arena GC ordering after synchronize (stub; M9 fills)
//   D12  — RCU shutdown offline/unregister + bounded synchronize (C2/C4)
//   D30  — rte_rcu_qsbr_check(qs, token, wait=0) + deadline (C2)
//   D35  — single reload_mutex funnel (C1)
//   D36  — pending_free[K_PENDING=8] queue (C3)
//   D37  — validator memory-budget pre-flight (C4)
//
// The fixture (IntegrationEalFixture) mirrors tests/unit/eal_fixture.h
// but uses its own --file-prefix so it can coexist with test_eal_unit
// in a single ctest invocation on the same machine. The RCU smoke
// spawns N=2 fake worker threads; each registers + goes online + loops
// reporting quiescent state. Main thread drives a synchronize call
// and verifies it returns cleanly.
//
// CRITICAL: the DPDK RCU API signature (D30) is:
//   int  rte_rcu_qsbr_check(struct rte_rcu_qsbr*, uint64_t token, bool wait);
//   void rte_rcu_qsbr_synchronize(struct rte_rcu_qsbr*, unsigned int thread_id);
// `token` is a start-token from rte_rcu_qsbr_start(), NOT a TSC delta.
// The 4th review caught this misreading in the design. Verified
// against DPDK 25.11 lib/rcu/rte_rcu_qsbr.h for this cycle.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <thread>
#include <vector>

#include <rte_eal.h>
#include <rte_rcu_qsbr.h>

namespace pktgate::test {

// -------------------------------------------------------------------------
// Integration-tier EAL fixture.
//
// Same contract as tests/unit/eal_fixture.h (rte_eal_init once,
// --no-pci --no-huge -m 512). Uses a DIFFERENT --file-prefix so the
// unit-tier and integration-tier binaries can run in the same ctest
// pass without colliding on /run/dpdk/rte_config. DPDK EAL may only
// be initialized once per process; TearDownTestSuite intentionally
// skips rte_eal_cleanup (same rationale as the unit fixture).
// -------------------------------------------------------------------------
class IntegrationEalFixture : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (s_initialized) return;

    const char* argv[] = {
        "test_reload",
        "--no-pci",
        "--no-huge",
        "-m", "512",
        "--log-level", "lib.*:error",
        "-d", DPDK_DRIVER_DIR,
        "--file-prefix", "pktgate_integration",
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    int ret = rte_eal_init(argc, const_cast<char**>(argv));
    ASSERT_GE(ret, 0) << "rte_eal_init failed";

    s_initialized = true;
  }

  static void TearDownTestSuite() {
    // rte_eal_cleanup() intentionally skipped — DPDK 25.11 does not
    // cleanly support re-init within the same process.
  }

  static constexpr const char* DPDK_DRIVER_DIR =
      "/home/mit/Dev/dpdk-25.11/build/drivers/";

 private:
  static inline bool s_initialized = false;
};

// -------------------------------------------------------------------------
// QSBR bring-up smoke.
//
// Spawns N=2 fake worker threads. Each:
//   (1) rte_rcu_qsbr_thread_register(qs, id)
//   (2) rte_rcu_qsbr_thread_online(qs, id)
//   (3) loop: rte_rcu_qsbr_quiescent(qs, id) + short sleep, while keep_going
//   (4) rte_rcu_qsbr_thread_offline(qs, id)
//   (5) rte_rcu_qsbr_thread_unregister(qs, id)
//
// Main thread calls rte_rcu_qsbr_synchronize(qs, RTE_QSBR_THRID_INVALID)
// while workers are active — it must return within a short wall-clock
// window (workers report quiescent ~1 kHz). This proves the fixture can
// drive a real QSBR state machine, which is the pre-requisite for every
// D30/D35/D36 test shipping in C1-C5.
//
// We intentionally DO NOT exercise rte_rcu_qsbr_check(qs, token, wait=0)
// polling against a deadline here — that belongs in C2 where the
// real reload manager supplies the deadline. C0 only proves synchronize
// works at all, i.e. the fixture is wired correctly.
// -------------------------------------------------------------------------
class ReloadSmokeTest : public IntegrationEalFixture {};

namespace {

constexpr std::uint32_t kMaxThreads = 4;   // headroom for C1+ growth
constexpr unsigned      kNumWorkers = 2;   // C0 smoke count

struct QsbrHarness {
  struct rte_rcu_qsbr* qs = nullptr;
  std::atomic<bool>    keep_going{true};
  // Worker thread ids, one per spawned worker. 0 and 1 for C0.
  std::vector<unsigned int> thread_ids;
};

void worker_loop(QsbrHarness* h, unsigned int thread_id) {
  // Bring the thread online so rte_rcu_qsbr_check waits for it.
  rte_rcu_qsbr_thread_register(h->qs, thread_id);
  rte_rcu_qsbr_thread_online(h->qs, thread_id);

  // Tight-ish loop reporting quiescent every ~1 ms. Higher-frequency
  // reporting keeps synchronize latency bounded when main thread
  // fires it without warning.
  while (h->keep_going.load(std::memory_order_acquire)) {
    rte_rcu_qsbr_quiescent(h->qs, thread_id);
    std::this_thread::sleep_for(std::chrono::microseconds(200));
  }

  // Graceful exit: offline + unregister. This is the D12 shutdown
  // pattern that C4 will replicate in the real worker shutdown path.
  rte_rcu_qsbr_thread_offline(h->qs, thread_id);
  rte_rcu_qsbr_thread_unregister(h->qs, thread_id);
}

}  // namespace

TEST_F(ReloadSmokeTest, QsbrBringUpAndSynchronize) {
  // Allocate the QSBR variable. rte_rcu_qsbr_get_memsize tells us
  // how large the opaque struct is for max_threads readers.
  size_t sz = rte_rcu_qsbr_get_memsize(kMaxThreads);
  ASSERT_GT(sz, 0u) << "rte_rcu_qsbr_get_memsize returned 0";

  // Plain malloc is fine here — the QSBR variable is not on the hot
  // path, just a test-scope allocation. Align to 8 bytes to satisfy
  // the 64-bit atomic fields inside.
  void* raw = std::aligned_alloc(alignof(std::max_align_t), sz);
  ASSERT_NE(raw, nullptr) << "aligned_alloc failed";
  auto* qs = static_cast<struct rte_rcu_qsbr*>(raw);

  ASSERT_EQ(rte_rcu_qsbr_init(qs, kMaxThreads), 0) << "rte_rcu_qsbr_init failed";

  QsbrHarness h;
  h.qs = qs;
  h.thread_ids = {0u, 1u};

  // Spawn workers.
  std::vector<std::thread> workers;
  workers.reserve(kNumWorkers);
  for (unsigned int tid : h.thread_ids) {
    workers.emplace_back(worker_loop, &h, tid);
  }

  // Give workers a beat to register + go online. A tiny sleep is
  // enough here because worker_loop does register→online as the
  // very first two calls.
  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  // Drive a synchronize — must return cleanly. Bound the observed
  // latency loosely (100 ms); workers report quiescent every 200 µs
  // so this should complete in single-digit milliseconds.
  auto t0 = std::chrono::steady_clock::now();
  rte_rcu_qsbr_synchronize(qs, RTE_QSBR_THRID_INVALID);
  auto t1 = std::chrono::steady_clock::now();
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
  EXPECT_LT(ms, 100) << "synchronize took too long: " << ms << " ms";

  // Drive a start/check pair while workers are still reporting. This
  // is the kernel of what C2's deploy() will do (minus the deadline
  // loop). Expect rte_rcu_qsbr_check to succeed within a few
  // worker quiescent cycles.
  uint64_t token = rte_rcu_qsbr_start(qs);
  int check_ret = 0;
  for (int i = 0; i < 1000 && check_ret == 0; ++i) {
    // wait=false: non-blocking poll. Same pattern as D30 deadline loop.
    check_ret = rte_rcu_qsbr_check(qs, token, /*wait=*/false);
    if (check_ret == 0) {
      std::this_thread::sleep_for(std::chrono::microseconds(500));
    }
  }
  EXPECT_EQ(check_ret, 1) << "rte_rcu_qsbr_check never saw token " << token;

  // Stop workers, join, free.
  h.keep_going.store(false, std::memory_order_release);
  for (auto& w : workers) {
    w.join();
  }
  std::free(raw);
}

}  // namespace pktgate::test
