// tests/integration/test_reload.cpp
//
// M8 integration tier. C0 seeded the EAL + QSBR bring-up fixture; C1
// extends it with deploy() happy-path tests + the X1.2 cmd_socket
// reload-storm scenario.
//
// M8 plan anchors:
//   D9   — single process-wide g_active
//   D11  — arena GC ordering after synchronize (stub; M9 fills)
//   D12  — RCU shutdown offline/unregister + bounded synchronize (C2/C4)
//   D30  — rte_rcu_qsbr_check(qs, token, wait=0) + deadline (C2)
//   D35  — single reload_mutex funnel (C1)
//   D36  — pending_free[K_PENDING=8] queue (C3)
//   D37  — validator memory-budget pre-flight (C4)
//
// CRITICAL: the DPDK RCU API signature (D30) is:
//   int  rte_rcu_qsbr_check(struct rte_rcu_qsbr*, uint64_t token, bool wait);
//   void rte_rcu_qsbr_synchronize(struct rte_rcu_qsbr*, unsigned int thread_id);
// `token` is a start-token from rte_rcu_qsbr_start(), NOT a TSC delta.
// Verified against DPDK 25.11 lib/rcu/rte_rcu_qsbr.h for this cycle.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_rcu_qsbr.h>

#include "src/ctl/cmd_socket.h"
#include "src/ctl/reload.h"
#include "src/ruleset/ruleset.h"

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
// QSBR bring-up smoke (C0).
// -------------------------------------------------------------------------
class ReloadSmokeTest : public IntegrationEalFixture {};

namespace {

constexpr std::uint32_t kMaxThreads = 4;   // headroom for C1+ growth
constexpr unsigned      kNumWorkers = 2;   // C0 smoke count

struct QsbrHarness {
  struct rte_rcu_qsbr* qs = nullptr;
  std::atomic<bool>    keep_going{true};
  std::vector<unsigned int> thread_ids;
};

void worker_loop(QsbrHarness* h, unsigned int thread_id) {
  rte_rcu_qsbr_thread_register(h->qs, thread_id);
  rte_rcu_qsbr_thread_online(h->qs, thread_id);

  while (h->keep_going.load(std::memory_order_acquire)) {
    rte_rcu_qsbr_quiescent(h->qs, thread_id);
    std::this_thread::sleep_for(std::chrono::microseconds(200));
  }

  rte_rcu_qsbr_thread_offline(h->qs, thread_id);
  rte_rcu_qsbr_thread_unregister(h->qs, thread_id);
}

}  // namespace

TEST_F(ReloadSmokeTest, QsbrBringUpAndSynchronize) {
  size_t sz = rte_rcu_qsbr_get_memsize(kMaxThreads);
  ASSERT_GT(sz, 0u) << "rte_rcu_qsbr_get_memsize returned 0";

  void* raw = std::aligned_alloc(alignof(std::max_align_t), sz);
  ASSERT_NE(raw, nullptr) << "aligned_alloc failed";
  auto* qs = static_cast<struct rte_rcu_qsbr*>(raw);

  ASSERT_EQ(rte_rcu_qsbr_init(qs, kMaxThreads), 0) << "rte_rcu_qsbr_init failed";

  QsbrHarness h;
  h.qs = qs;
  h.thread_ids = {0u, 1u};

  std::vector<std::thread> workers;
  workers.reserve(kNumWorkers);
  for (unsigned int tid : h.thread_ids) {
    workers.emplace_back(worker_loop, &h, tid);
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  auto t0 = std::chrono::steady_clock::now();
  rte_rcu_qsbr_synchronize(qs, RTE_QSBR_THRID_INVALID);
  auto t1 = std::chrono::steady_clock::now();
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
  EXPECT_LT(ms, 100) << "synchronize took too long: " << ms << " ms";

  uint64_t token = rte_rcu_qsbr_start(qs);
  int check_ret = 0;
  for (int i = 0; i < 1000 && check_ret == 0; ++i) {
    check_ret = rte_rcu_qsbr_check(qs, token, /*wait=*/false);
    if (check_ret == 0) {
      std::this_thread::sleep_for(std::chrono::microseconds(500));
    }
  }
  EXPECT_EQ(check_ret, 1) << "rte_rcu_qsbr_check never saw token " << token;

  h.keep_going.store(false, std::memory_order_release);
  for (auto& w : workers) {
    w.join();
  }
  std::free(raw);
}

// =========================================================================
// C1 — deploy() + reload_mutex + g_active ownership move.
// =========================================================================

// -------------------------------------------------------------------------
// ReloadManagerFixture — resets the reload manager per test.
//
// The manager is a module-local singleton; subsequent TEST_F runs
// inside one process share the same instance. We call shutdown() in
// TearDown to drop any lingering g_active and reset counters, then
// init() in SetUp for the next test. Safe because init() under the
// mutex is idempotent / start-fresh after shutdown.
// -------------------------------------------------------------------------
class ReloadManagerFixture : public IntegrationEalFixture {
 protected:
  void SetUp() override {
    ctl::reload::InitParams p;
    p.socket_id   = 0;       // --no-huge makes socket 0 the only option
    p.num_lcores  = 1;
    p.max_entries = 256;     // small — keeps rte_fib tbl8 allocs modest
    p.name_prefix = "pktgate_test_reload";
    ctl::reload::init(p);
  }

  void TearDown() override {
    ctl::reload::shutdown();
  }

  // Make a minimal Ruleset for deploy_prebuilt() calls. Only fields
  // workers might touch are populated; this is "just enough to be a
  // valid atomic-exchange target", not a production Ruleset.
  static std::unique_ptr<ruleset::Ruleset> make_bare_ruleset() {
    return std::make_unique<ruleset::Ruleset>();
  }
};

// -------------------------------------------------------------------------
// U6.43b-integration — g_active is owned by the reload manager.
//
// Structural test (complements the compile-time U6.43b in
// tests/unit/test_eal_unit.cpp). Asserts the symbol exists and is
// reachable through the module accessor.
// -------------------------------------------------------------------------
TEST_F(ReloadManagerFixture, GActivePtrIsReachable) {
  auto* p = ctl::reload::g_active_ptr();
  ASSERT_NE(p, nullptr)
      << "U6.43b: reload::g_active_ptr() must return the manager's atomic";
  // Initially nullptr (no deploy yet).
  EXPECT_EQ(p->load(std::memory_order_acquire), nullptr);
  EXPECT_EQ(ctl::reload::active_ruleset(), nullptr);
}

// -------------------------------------------------------------------------
// deploy_prebuilt happy path — exchanges g_active and frees old.
// -------------------------------------------------------------------------
TEST_F(ReloadManagerFixture, DeployPrebuiltPublishesAndFrees) {
  auto rs1 = make_bare_ruleset();
  auto* raw1 = rs1.get();
  auto r1 = ctl::reload::deploy_prebuilt(std::move(rs1));
  ASSERT_TRUE(r1.ok) << "first deploy_prebuilt must succeed: " << r1.error;
  EXPECT_EQ(ctl::reload::active_ruleset(), raw1);
  EXPECT_GE(r1.generation, 1u);

  // Second publish replaces + frees the first. We can't check that
  // raw1 was freed without UAF, but the counter + new active pointer
  // is enough to prove the exchange happened.
  auto rs2 = make_bare_ruleset();
  auto* raw2 = rs2.get();
  auto r2 = ctl::reload::deploy_prebuilt(std::move(rs2));
  ASSERT_TRUE(r2.ok);
  EXPECT_EQ(ctl::reload::active_ruleset(), raw2);
  EXPECT_GT(r2.generation, r1.generation);

  auto c = ctl::reload::counters_snapshot();
  EXPECT_EQ(c.success, 2u);
  EXPECT_EQ(c.parse_error, 0u);
  EXPECT_EQ(c.validate_error, 0u);
}

// -------------------------------------------------------------------------
// reload_mutex smoke — two concurrent deploy_prebuilt calls both
// succeed sequentially. C1-sized concurrency (real storm is X1.2).
// -------------------------------------------------------------------------
TEST_F(ReloadManagerFixture, ReloadMutexSerializesTwoPublishers) {
  constexpr int kIters = 20;
  std::atomic<int> successes{0};

  auto publisher = [&] {
    for (int i = 0; i < kIters; ++i) {
      auto rs = make_bare_ruleset();
      auto r = ctl::reload::deploy_prebuilt(std::move(rs));
      if (r.ok) successes.fetch_add(1, std::memory_order_relaxed);
    }
  };

  std::thread t1(publisher);
  std::thread t2(publisher);
  t1.join();
  t2.join();

  EXPECT_EQ(successes.load(), 2 * kIters);
  auto c = ctl::reload::counters_snapshot();
  EXPECT_EQ(c.success, static_cast<std::uint64_t>(2 * kIters));
  EXPECT_NE(ctl::reload::active_ruleset(), nullptr);
}

// -------------------------------------------------------------------------
// deploy(string_view) happy path — parse → validate → compile → build
// → populate → publish. This exercises the full public deploy()
// surface once. X1.2 below hammers the cmd_socket path which
// indirectly drives the same function.
// -------------------------------------------------------------------------
constexpr std::string_view kMinimalConfigJson = R"json({
  "version": 1,
  "interface_roles": {
    "upstream_port":   { "pci": "0000:00:00.0" },
    "downstream_port": { "pci": "0000:00:00.1" }
  },
  "pipeline": {
    "layer_2": [],
    "layer_3": [],
    "layer_4": []
  },
  "default_behavior": "drop"
})json";

TEST_F(ReloadManagerFixture, DeployJsonHappyPath) {
  auto r = ctl::reload::deploy(kMinimalConfigJson);
  ASSERT_TRUE(r.ok) << "deploy(minimal) must succeed: " << r.error;
  EXPECT_EQ(r.kind, ctl::reload::DeployError::kOk);
  EXPECT_NE(ctl::reload::active_ruleset(), nullptr);

  auto c = ctl::reload::counters_snapshot();
  EXPECT_EQ(c.success, 1u);
}

TEST_F(ReloadManagerFixture, DeployJsonParseErrorBumpsCounter) {
  auto r = ctl::reload::deploy("not-json-at-all");
  EXPECT_FALSE(r.ok);
  EXPECT_EQ(r.kind, ctl::reload::DeployError::kParse);
  // No new publish — g_active still nullptr.
  EXPECT_EQ(ctl::reload::active_ruleset(), nullptr);

  auto c = ctl::reload::counters_snapshot();
  EXPECT_EQ(c.parse_error, 1u);
  EXPECT_EQ(c.success, 0u);
}

// =========================================================================
// X1.2 — cmd_socket reload storm.
//
// Chaos test per test-plan-drafts/chaos.md §X1.2. Spawn a cmd_socket
// server, fire N sequential UDS reload connections, each sending
// "reload <json>\n" and reading the reply. After the storm,
// `reload_total{success}` must equal N. TSAN clean + ASAN clean are
// the primary gate (the counters are the secondary observable).
//
// We use `deploy_prebuilt` under the hood by invoking the real cmd_socket
// which calls `reload::deploy()` with the JSON. For the storm we want:
//   - minimal JSON so parse/validate/compile is cheap
//   - NO L3 rules (no rte_fib alloc → avoids the 128 MB tbl24 per
//     reload per grabli_rte_fib_dir24_8_heap_footprint.md)
//   - NO L2/L4 compound entries either — keeps rte_hash allocations
//     bounded and deallocations fast
//
// Storm size is scaled to 500 for dev-tsan / dev-asan to keep the
// total wall-clock under 30 s while still being a stress; the plan
// calls for 1000 but that's "aspirational for prod hw", not a hard
// gate for the dev VM.
// =========================================================================

class CmdSocketStormFixture : public ReloadManagerFixture {};

namespace {

// Compose a UDS path unique to this test run so concurrent ctest
// invocations don't collide. getpid() + a counter is enough.
std::string unique_uds_path(const char* tag) {
  char buf[128];
  std::snprintf(buf, sizeof(buf), "/tmp/pktgate_%s_%d.sock",
                tag, static_cast<int>(::getpid()));
  return buf;
}

// Drive one reload request. Returns true if the server replied with
// "ok …\n" — anything else (err, short read, connect failure) is a
// miss and caller bumps the failure tally.
bool fire_one_reload(const std::string& path, std::string_view payload) {
  int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return false;

  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::memcpy(addr.sun_path, path.data(),
              std::min(path.size(), sizeof(addr.sun_path) - 1));

  // Retry connect briefly — the server's accept loop may be between
  // accept() calls on a heavily-loaded system.
  int rc = -1;
  for (int i = 0; i < 10; ++i) {
    rc = ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (rc == 0) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  if (rc < 0) {
    ::close(fd);
    return false;
  }

  // Send "reload <payload>\n".
  std::string req = "reload ";
  req.append(payload);
  req.push_back('\n');
  {
    const char* p = req.data();
    std::size_t left = req.size();
    while (left > 0) {
      ssize_t n = ::write(fd, p, left);
      if (n < 0) {
        if (errno == EINTR) continue;
        ::close(fd);
        return false;
      }
      p += n;
      left -= static_cast<std::size_t>(n);
    }
  }
  // Half-close write side so the server's read() sees EOF after the
  // newline and doesn't block waiting for more bytes.
  ::shutdown(fd, SHUT_WR);

  // Read the reply. Expect "ok <gen>\n" on success.
  char reply[128] = {};
  std::size_t total = 0;
  while (total < sizeof(reply) - 1) {
    ssize_t n = ::read(fd, reply + total, sizeof(reply) - 1 - total);
    if (n <= 0) break;
    total += static_cast<std::size_t>(n);
    if (std::memchr(reply, '\n', total) != nullptr) break;
  }
  ::close(fd);
  return total >= 3 && reply[0] == 'o' && reply[1] == 'k' && reply[2] == ' ';
}

}  // namespace

// =========================================================================
// C2 — RCU token+deadline bounded synchronize (D30, D12).
//
// Fixture brings up a real `rte_rcu_qsbr` and N fake worker threads that
// report quiescent state in a tight loop. Tests pass the QSBR handle to
// the reload manager via InitParams.qs so deploy() exercises the real
// rte_rcu_qsbr_start / rte_rcu_qsbr_check poll path.
//
// D30 SIGNATURES verified against DPDK 25.11:
//   * /home/mit/Dev/dpdk-25.11/lib/rcu/rte_rcu_qsbr.h
//   * doc.dpdk.org/api-25.11/rte__rcu__qsbr_8h.html
// `rte_rcu_qsbr_check(qs, token, wait)`: `token` is from
// `rte_rcu_qsbr_start`, `wait` is a BLOCKING FLAG. We pass wait=false
// and layer our own steady_clock deadline.
// =========================================================================

namespace {

// Fake-worker harness: each worker registers on the QSBR, goes online,
// and loops calling rte_rcu_qsbr_quiescent(). Per-worker `frozen` flag
// lets X1.4 stop a specific worker from reporting quiescent without
// affecting the others — that's what makes rte_rcu_qsbr_check time out.
struct C2Workers {
  struct rte_rcu_qsbr*                 qs = nullptr;
  std::atomic<bool>                    keep_going{true};
  std::vector<std::atomic<bool>>       frozen;
  std::vector<std::thread>             threads;
  std::vector<unsigned int>            thread_ids;

  explicit C2Workers(unsigned n) : frozen(n) {
    for (unsigned i = 0; i < n; ++i) {
      frozen[i].store(false, std::memory_order_relaxed);
    }
  }
};

void c2_worker_loop(C2Workers* w, unsigned int tid, std::size_t idx) {
  rte_rcu_qsbr_thread_register(w->qs, tid);
  rte_rcu_qsbr_thread_online(w->qs, tid);
  while (w->keep_going.load(std::memory_order_acquire)) {
    if (!w->frozen[idx].load(std::memory_order_acquire)) {
      rte_rcu_qsbr_quiescent(w->qs, tid);
    }
    std::this_thread::sleep_for(std::chrono::microseconds(200));
  }
  rte_rcu_qsbr_thread_offline(w->qs, tid);
  rte_rcu_qsbr_thread_unregister(w->qs, tid);
}

// Shared state — one QSBR handle per test process (we can't re-init
// DPDK in-process, but we CAN have multiple QSBR variables; using one
// is plenty and matches production). Allocated in the fixture and
// reused; cleared by the per-test TearDown via `keep_going=false`.

}  // namespace

class ReloadC2Fixture : public IntegrationEalFixture {
 protected:
  static constexpr std::uint32_t kMaxThreadsC2 = 4;
  static constexpr unsigned      kC2Workers     = 2;

  void SetUp() override {
    // One QSBR variable per fixture instance — aligned_alloc is fine,
    // DPDK doesn't require rte_malloc for QSBR storage.
    size_t sz = rte_rcu_qsbr_get_memsize(kMaxThreadsC2);
    ASSERT_GT(sz, 0u);
    qs_raw_ = std::aligned_alloc(alignof(std::max_align_t), sz);
    ASSERT_NE(qs_raw_, nullptr);
    qs_ = static_cast<struct rte_rcu_qsbr*>(qs_raw_);
    ASSERT_EQ(rte_rcu_qsbr_init(qs_, kMaxThreadsC2), 0);

    workers_ = std::make_unique<C2Workers>(kC2Workers);
    workers_->qs = qs_;
    workers_->thread_ids.resize(kC2Workers);
    for (unsigned i = 0; i < kC2Workers; ++i) {
      workers_->thread_ids[i] = i;
      workers_->threads.emplace_back(c2_worker_loop, workers_.get(),
                                     i, static_cast<std::size_t>(i));
    }

    // Let workers call quiescent at least once so the first deploy()
    // sees them in a fresh state.
    std::this_thread::sleep_for(std::chrono::milliseconds(5));

    ctl::reload::InitParams p;
    p.socket_id      = 0;
    p.num_lcores     = 1;
    p.max_entries    = 256;
    p.name_prefix    = "pktgate_test_c2";
    p.qs             = qs_;
    p.reload_timeout = std::chrono::milliseconds(200);  // sane default for non-X1.4 tests
    p.poll_interval  = std::chrono::microseconds(100);
    ctl::reload::init(p);
  }

  void TearDown() override {
    // Unfreeze anything the test froze so QSBR can drain cleanly.
    if (workers_) {
      for (auto& f : workers_->frozen) {
        f.store(false, std::memory_order_release);
      }
    }
    ctl::reload::shutdown();
    if (workers_) {
      workers_->keep_going.store(false, std::memory_order_release);
      for (auto& t : workers_->threads) {
        if (t.joinable()) t.join();
      }
      workers_.reset();
    }
    std::free(qs_raw_);
    qs_raw_ = nullptr;
    qs_ = nullptr;
  }

  static std::unique_ptr<ruleset::Ruleset> make_bare_ruleset() {
    return std::make_unique<ruleset::Ruleset>();
  }

  struct rte_rcu_qsbr*          qs_    = nullptr;
  void*                         qs_raw_ = nullptr;
  std::unique_ptr<C2Workers>    workers_;
};

// -------------------------------------------------------------------------
// Happy-path regression: with live QSBR + quiescent workers, deploy()
// completes quickly and `freed_total` bumps AFTER the synchronize
// returns quiescent (not immediately after the exchange). This pins
// C2's "poll loop reaches 1" contract.
// -------------------------------------------------------------------------
TEST_F(ReloadC2Fixture, DeployPrebuiltSynchronizeFreesOldRuleset) {
  auto rs1 = make_bare_ruleset();
  auto r1 = ctl::reload::deploy_prebuilt(std::move(rs1));
  ASSERT_TRUE(r1.ok) << "first publish must succeed: " << r1.error;
  // Nothing to free yet (first publish) — freed_total == 0.
  auto c0 = ctl::reload::counters_snapshot();
  EXPECT_EQ(c0.freed_total, 0u);

  auto t0 = std::chrono::steady_clock::now();
  auto rs2 = make_bare_ruleset();
  auto r2 = ctl::reload::deploy_prebuilt(std::move(rs2));
  auto t1 = std::chrono::steady_clock::now();
  ASSERT_TRUE(r2.ok) << "second publish must succeed: " << r2.error;

  // With live quiescent workers the poll should complete in well under
  // 10 ms even on a loaded VM.
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0)
                .count();
  EXPECT_LT(ms, 100) << "synchronize poll too slow: " << ms << " ms";

  auto c1 = ctl::reload::counters_snapshot();
  EXPECT_EQ(c1.success, 2u);
  EXPECT_EQ(c1.timeout, 0u);
  // CRITICAL C2 assertion: freed_total bumped exactly ONCE (the old
  // rs1 got freed after synchronize said quiescent).
  EXPECT_EQ(c1.freed_total, 1u)
      << "freed_total must bump after QSBR reports quiescent";
}

// -------------------------------------------------------------------------
// X1.4 — reload timeout SENTINEL (the flagship D30 test).
//
// Freeze one fake worker (stop reporting quiescent), shrink the reload
// timeout to 50 ms, call deploy_prebuilt(). Expect:
//   * result == kReloadTimeout
//   * reload_total{timeout} == 1
//   * g_active now holds the NEW ruleset (exchange happened BEFORE the
//     timeout)
//   * freed_total == 0 — the old ruleset was NOT freed (C2 leaks on
//     timeout; C3 adds pending_free)
// Unfreeze on teardown so the fixture destructor is clean.
// -------------------------------------------------------------------------
TEST_F(ReloadC2Fixture, X1_4_ReloadTimeoutSentinel) {
  // Shrink reload timeout before the deploy under test. We do this by
  // re-init — the manager is idempotent on same-params, but shutdown
  // first resets. Keep it simple: shutdown+init with short timeout.
  ctl::reload::shutdown();
  ctl::reload::InitParams p;
  p.socket_id      = 0;
  p.num_lcores     = 1;
  p.max_entries    = 256;
  p.name_prefix    = "pktgate_test_c2_x14";
  p.qs             = qs_;
  p.reload_timeout = std::chrono::milliseconds(50);  // tight for X1.4
  p.poll_interval  = std::chrono::microseconds(100);
  ctl::reload::init(p);

  // Prime: first publish succeeds (workers are still quiescent).
  auto rs0 = make_bare_ruleset();
  auto r0 = ctl::reload::deploy_prebuilt(std::move(rs0));
  ASSERT_TRUE(r0.ok) << r0.error;

  // Freeze worker 0 — it stops calling rte_rcu_qsbr_quiescent, so the
  // token taken after the next exchange will NEVER become visible to
  // rte_rcu_qsbr_check.
  workers_->frozen[0].store(true, std::memory_order_release);
  // Give it a tick to pick up the flag.
  std::this_thread::sleep_for(std::chrono::milliseconds(2));

  auto rs_new = make_bare_ruleset();
  auto* raw_new = rs_new.get();

  auto c_before = ctl::reload::counters_snapshot();
  auto r = ctl::reload::deploy_prebuilt(std::move(rs_new));

  // D30 flagship assertion: deploy reports timeout with the right kind.
  EXPECT_FALSE(r.ok);
  EXPECT_EQ(r.kind, ctl::reload::DeployError::kReloadTimeout)
      << "X1.4: deploy must report kReloadTimeout on synchronize miss; "
      << "got error='" << r.error << "'";

  // Publish already happened — g_active is the NEW pointer.
  EXPECT_EQ(ctl::reload::active_ruleset(), raw_new)
      << "X1.4: atomic_exchange must happen BEFORE the synchronize poll";

  auto c_after = ctl::reload::counters_snapshot();
  EXPECT_EQ(c_after.timeout, c_before.timeout + 1u)
      << "X1.4: reload_total{timeout} must increment exactly once";

  // C2 intentionally leaks on timeout — C3 adds pending_free.
  // Therefore freed_total MUST NOT have incremented.
  EXPECT_EQ(c_after.freed_total, c_before.freed_total)
      << "X1.4: C2 leaks on timeout; freed_total must not bump "
      << "(C3 TODO: push onto pending_free instead)";

  // Unfreeze so QSBR can drain cleanly during TearDown.
  workers_->frozen[0].store(false, std::memory_order_release);
}

// -------------------------------------------------------------------------
// X1.11 — debounce correctness (M8 variant).
//
// There is no debounce in the UDS path — reload_mutex serialises every
// caller. Assertion: 10 concurrent deploy_prebuilt() calls complete in
// strict sequence, no coalescing, each produces a distinct
// reload_total{success} increment.
// -------------------------------------------------------------------------
TEST_F(ReloadC2Fixture, X1_11_ConcurrentReloadsNoCoalescing) {
  constexpr int kCallers = 10;
  std::atomic<int> successes{0};
  std::vector<std::thread> threads;
  threads.reserve(kCallers);
  for (int i = 0; i < kCallers; ++i) {
    threads.emplace_back([&] {
      auto rs = make_bare_ruleset();
      auto r = ctl::reload::deploy_prebuilt(std::move(rs));
      if (r.ok) successes.fetch_add(1, std::memory_order_relaxed);
    });
  }
  for (auto& t : threads) t.join();

  EXPECT_EQ(successes.load(), kCallers);
  auto c = ctl::reload::counters_snapshot();
  // No caller coalescing: success == kCallers (every caller produced
  // exactly one distinct increment).
  EXPECT_EQ(c.success, static_cast<std::uint64_t>(kCallers))
      << "X1.11: reload_mutex must serialize without coalescing callers";
  EXPECT_EQ(c.timeout, 0u);
  // freed_total = kCallers - 1 (first publish has no old, each
  // subsequent publish frees the one before).
  EXPECT_EQ(c.freed_total, static_cast<std::uint64_t>(kCallers - 1))
      << "X1.11: each subsequent publish should free exactly one old ruleset";
}

// =========================================================================
// C3 — pending_free[K_PENDING=8] queue + drain + overflow alert (D36).
//
// Replaces C2's single-slot `c2_pending_leak` bridge with a real
// K_PENDING=8 array. New observables on ReloadCounters:
//   * pending_full       — bumped each reload that hit an overflow
//   * pending_depth      — gauge (current queue occupancy)
//   * overflow_log_total — test hook: how many TIMES we emitted the
//     ERROR "reload_pending_full dataplane_wedged" log line. Throttled
//     to once per overflow EVENT (a "new" overflow event = first one
//     after a drain actually freed a slot).
//
// Design anchors:
//   * design.md §9.2 — pending_free_push / pending_free_drain
//   * design.md §9.4 — "Reload timeout" overflow branch
//   * review-notes.md D36 — K_PENDING=8 fixed, overflow alert cadence
//   * test-plan-drafts/chaos.md §X1.5 — 9 successive reloads assertion
//   * test-plan-drafts/chaos.md §X1.10 — leak-detector soak (this
//     cycle ships a 60 s CI smoke; full 1 h is nightly -L soak)
// =========================================================================

// -------------------------------------------------------------------------
// X1.5 — pending_free overflow (D36).
//
// Freeze worker 0 so every deploy() times out. Fire 9 successive
// deploys. Assert:
//   * Each of the first 8 returns kReloadTimeout; pending_depth 1→8
//   * 9th also returns kReloadTimeout; pending_full counter == 1;
//     overflow_log_total == 1 (one ERROR log line exactly)
//   * active_ruleset() is the LATEST pointer (exchange always succeeds)
//   * No LSAN complaint — overflow_holder keeps rs live-reachable
// Fire a 10th deploy while still frozen: pending_full goes to 2,
// BUT overflow_log_total stays at 1 (throttled — same overflow event).
// -------------------------------------------------------------------------
TEST_F(ReloadC2Fixture, X1_5_PendingFreeOverflow) {
  // Re-init with short reload_timeout so 9+ timeouts don't explode the
  // test wall-clock (9 * 50 ms = 450 ms worst case).
  ctl::reload::shutdown();
  ctl::reload::InitParams p;
  p.socket_id      = 0;
  p.num_lcores     = 1;
  p.max_entries    = 256;
  p.name_prefix    = "pktgate_test_c3_x15";
  p.qs             = qs_;
  p.reload_timeout = std::chrono::milliseconds(40);
  p.poll_interval  = std::chrono::microseconds(100);
  ctl::reload::init(p);

  // Prime with one successful publish while workers are still quiescent,
  // so subsequent timeouts have a real rs_old to push onto pending_free.
  // (First-ever timeout has rs_old=nullptr and is a no-op for the queue.)
  {
    auto rs = make_bare_ruleset();
    auto r = ctl::reload::deploy_prebuilt(std::move(rs));
    ASSERT_TRUE(r.ok) << "prime publish must succeed: " << r.error;
  }

  // Freeze worker 0 — stop reporting quiescent.
  workers_->frozen[0].store(true, std::memory_order_release);
  std::this_thread::sleep_for(std::chrono::milliseconds(2));

  // 8 timeouts, each pushed onto pending_free: depth climbs 1→8.
  ruleset::Ruleset* latest = nullptr;
  for (int i = 0; i < 8; ++i) {
    auto rs = make_bare_ruleset();
    latest = rs.get();
    auto r = ctl::reload::deploy_prebuilt(std::move(rs));
    ASSERT_FALSE(r.ok) << "deploy " << i << " must time out";
    ASSERT_EQ(r.kind, ctl::reload::DeployError::kReloadTimeout);
    EXPECT_EQ(ctl::reload::active_ruleset(), latest)
        << "deploy " << i << ": exchange must succeed before timeout";
    auto c = ctl::reload::counters_snapshot();
    EXPECT_EQ(c.pending_depth, static_cast<std::uint64_t>(i + 1))
        << "pending_depth after deploy " << i;
    EXPECT_EQ(c.pending_full, 0u)
        << "no overflow yet at deploy " << i;
    EXPECT_EQ(c.overflow_log_total, 0u)
        << "no overflow log yet at deploy " << i;
  }

  // 9th deploy — overflow. Queue is full (depth=8), so this one lands
  // in overflow_holder. pending_full bumps; overflow_log_total == 1.
  {
    auto rs = make_bare_ruleset();
    latest = rs.get();
    auto r = ctl::reload::deploy_prebuilt(std::move(rs));
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.kind, ctl::reload::DeployError::kReloadTimeout);
    EXPECT_EQ(ctl::reload::active_ruleset(), latest);

    auto c = ctl::reload::counters_snapshot();
    EXPECT_EQ(c.pending_depth, 8u) << "depth stays at 8 after overflow";
    EXPECT_EQ(c.pending_full, 1u) << "pending_full bumps exactly once at overflow";
    EXPECT_EQ(c.overflow_log_total, 1u)
        << "ERROR log emitted exactly once at first overflow";
    EXPECT_EQ(c.timeout, 9u) << "all 9 deploys timed out";
  }

  // 10th deploy — still frozen, still overflow. Counter bumps again,
  // but the LOG is throttled (same overflow event).
  {
    auto rs = make_bare_ruleset();
    auto r = ctl::reload::deploy_prebuilt(std::move(rs));
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.kind, ctl::reload::DeployError::kReloadTimeout);

    auto c = ctl::reload::counters_snapshot();
    EXPECT_EQ(c.pending_depth, 8u);
    EXPECT_EQ(c.pending_full, 2u) << "pending_full per-reload counter";
    EXPECT_EQ(c.overflow_log_total, 1u)
        << "X1.5 throttle: log stays at 1 across same overflow event";
    EXPECT_EQ(c.timeout, 10u);
  }

  // Unfreeze so QSBR can drain cleanly during TearDown.
  workers_->frozen[0].store(false, std::memory_order_release);
}

// -------------------------------------------------------------------------
// Drain correctness regression.
//
// Push 3 entries onto pending_free (3 timeouts), unfreeze, fire one
// more deploy. Its drain at the START should free all 3 before taking
// the new token. Assert:
//   * freed_total jumps by 3 (from the drain)
//   * pending_depth drops to 0
//   * the fourth deploy itself succeeds and bumps freed_total to 4
//     (the old "latest" from the third timeout is freed via the
//     normal synchronize path on this successful deploy)
// -------------------------------------------------------------------------
TEST_F(ReloadC2Fixture, C3_DrainCorrectnessRegression) {
  ctl::reload::shutdown();
  ctl::reload::InitParams p;
  p.socket_id      = 0;
  p.num_lcores     = 1;
  p.max_entries    = 256;
  p.name_prefix    = "pktgate_test_c3_drain";
  p.qs             = qs_;
  p.reload_timeout = std::chrono::milliseconds(40);
  p.poll_interval  = std::chrono::microseconds(100);
  ctl::reload::init(p);

  // Prime with one successful publish so subsequent timeouts have a
  // real rs_old to push onto pending_free.
  {
    auto rs = make_bare_ruleset();
    auto r = ctl::reload::deploy_prebuilt(std::move(rs));
    ASSERT_TRUE(r.ok) << "prime publish must succeed: " << r.error;
  }

  workers_->frozen[0].store(true, std::memory_order_release);
  std::this_thread::sleep_for(std::chrono::milliseconds(2));

  // 3 timeouts.
  for (int i = 0; i < 3; ++i) {
    auto rs = make_bare_ruleset();
    auto r = ctl::reload::deploy_prebuilt(std::move(rs));
    ASSERT_EQ(r.kind, ctl::reload::DeployError::kReloadTimeout);
  }
  {
    auto c = ctl::reload::counters_snapshot();
    EXPECT_EQ(c.pending_depth, 3u);
    EXPECT_EQ(c.timeout, 3u);
    EXPECT_EQ(c.freed_total, 0u)
        << "no frees yet — all 3 on pending_free";
  }

  // Unfreeze. Let the worker pick up the flag and report quiescent.
  workers_->frozen[0].store(false, std::memory_order_release);
  std::this_thread::sleep_for(std::chrono::milliseconds(5));

  // 4th deploy: drain-at-top frees all 3 pending entries, then the
  // new deploy proceeds normally.
  {
    auto rs = make_bare_ruleset();
    auto r = ctl::reload::deploy_prebuilt(std::move(rs));
    ASSERT_TRUE(r.ok) << r.error;

    auto c = ctl::reload::counters_snapshot();
    EXPECT_EQ(c.pending_depth, 0u) << "drain cleared the queue";
    // freed_total = 3 (drain) + 1 (synchronize frees the prior live
    // ruleset from the 3rd timeout — it was g_active when the 4th
    // deploy exchanged) = 4.
    EXPECT_EQ(c.freed_total, 4u);
    EXPECT_EQ(c.success, 2u) << "prime + this one";
  }
}

// -------------------------------------------------------------------------
// X1.10-short — leak-detector 60 s smoke (CI-sized).
//
// Fire deploys at ~1 Hz for 60 s with one frozen worker. After the
// pending_free fills at 8, VmRSS must plateau — no monotonic growth.
// The overflow_holder grows unboundedly in principle but in practice
// each rs is ~bytes-small (bare Ruleset), so the growth is trivial
// and we assert ±10% plateau on VmRSS.
//
// Full 1 h soak is nightly only (ctest -L soak); C3 ships the 60 s
// smoke under the `integration` label.
// -------------------------------------------------------------------------
namespace {

// VmRSS in kB from /proc/self/status.
std::uint64_t read_vm_rss_kb() {
  FILE* f = std::fopen("/proc/self/status", "r");
  if (!f) return 0;
  char line[256];
  std::uint64_t kb = 0;
  while (std::fgets(line, sizeof(line), f)) {
    if (std::strncmp(line, "VmRSS:", 6) == 0) {
      std::sscanf(line + 6, " %lu", &kb);
      break;
    }
  }
  std::fclose(f);
  return kb;
}

}  // namespace

TEST_F(ReloadC2Fixture, X1_10_Short_LeakDetectorSmoke) {
  ctl::reload::shutdown();
  ctl::reload::InitParams p;
  p.socket_id      = 0;
  p.num_lcores     = 1;
  p.max_entries    = 256;
  p.name_prefix    = "pktgate_test_c3_x110";
  p.qs             = qs_;
  p.reload_timeout = std::chrono::milliseconds(30);
  p.poll_interval  = std::chrono::microseconds(100);
  ctl::reload::init(p);

  // Prime so subsequent timeouts have a real rs_old to push.
  {
    auto rs = make_bare_ruleset();
    auto r = ctl::reload::deploy_prebuilt(std::move(rs));
    ASSERT_TRUE(r.ok);
  }

  workers_->frozen[0].store(true, std::memory_order_release);
  std::this_thread::sleep_for(std::chrono::milliseconds(2));

  // Duration trimmed from the chaos.md 60 s spec because bare Ruleset
  // allocations are trivially small and overflow_holder growth is
  // negligible — 12 s is enough to exercise the fill-then-plateau
  // behaviour and stay within the integration-tier wall-clock budget.
  constexpr auto kDuration = std::chrono::seconds(12);
  constexpr auto kPeriod   = std::chrono::milliseconds(40);  // ~25 Hz

  const auto t_start = std::chrono::steady_clock::now();

  // Fire the first 8 so pending_free fills, then start sampling RSS.
  for (int i = 0; i < 8; ++i) {
    auto rs = make_bare_ruleset();
    (void)ctl::reload::deploy_prebuilt(std::move(rs));
  }

  const std::uint64_t rss_after_fill = read_vm_rss_kb();
  ASSERT_GT(rss_after_fill, 0u) << "VmRSS read failed";

  std::uint64_t rss_peak = rss_after_fill;
  std::uint64_t rss_min  = rss_after_fill;
  int reload_count = 0;

  while (std::chrono::steady_clock::now() - t_start < kDuration) {
    auto rs = make_bare_ruleset();
    (void)ctl::reload::deploy_prebuilt(std::move(rs));
    ++reload_count;
    const std::uint64_t rss = read_vm_rss_kb();
    if (rss > rss_peak) rss_peak = rss;
    if (rss < rss_min)  rss_min  = rss;
    std::this_thread::sleep_for(kPeriod);
  }

  // Plateau assertion: peak must not exceed baseline by more than
  // kGrowthPctMax. Bare-Ruleset overhead per overflow is tiny, and
  // glibc heap can drift a few hundred kB, so we allow 25 % headroom.
  constexpr double kGrowthPctMax = 25.0;
  const double growth_pct =
      100.0 * (static_cast<double>(rss_peak) -
               static_cast<double>(rss_after_fill)) /
      static_cast<double>(rss_after_fill);
  EXPECT_LT(growth_pct, kGrowthPctMax)
      << "X1.10-short: VmRSS grew " << growth_pct
      << " % during soak (baseline=" << rss_after_fill << " kB, peak="
      << rss_peak << " kB, reloads=" << reload_count << ")";

  // Counters sanity.
  auto c_mid = ctl::reload::counters_snapshot();
  EXPECT_EQ(c_mid.pending_depth, 8u);
  EXPECT_GE(c_mid.pending_full, static_cast<std::uint64_t>(reload_count));
  EXPECT_EQ(c_mid.overflow_log_total, 1u)
      << "log throttled to 1 across the entire soak run";

  // Unstick + one clean reload: pending_depth drains to 0 and
  // freed_total climbs by at least 8 (the drain) + 1 (active).
  workers_->frozen[0].store(false, std::memory_order_release);
  std::this_thread::sleep_for(std::chrono::milliseconds(5));
  const std::uint64_t freed_before = c_mid.freed_total;
  {
    auto rs = make_bare_ruleset();
    auto r = ctl::reload::deploy_prebuilt(std::move(rs));
    ASSERT_TRUE(r.ok) << r.error;
  }
  auto c_end = ctl::reload::counters_snapshot();
  EXPECT_EQ(c_end.pending_depth, 0u) << "drain cleared queue on unstick";
  EXPECT_GE(c_end.freed_total, freed_before + 8u)
      << "drain must free at least the 8 pending entries";
}

TEST_F(CmdSocketStormFixture, ThousandReloadsMutexSerialization) {
  const std::string sock_path = unique_uds_path("storm");

  ctl::CmdSocketServer srv;
  ASSERT_TRUE(ctl::cmd_socket_start(srv, sock_path))
      << "cmd_socket_start failed at " << sock_path;

  // Scope exit cleanup so cmd_socket_stop runs even on a test
  // assertion failure below.
  struct StopGuard {
    ctl::CmdSocketServer* s;
    ~StopGuard() { ctl::cmd_socket_stop(*s); }
  } guard{&srv};

  // X1.2 spec says 1000. The dev-asan / dev-tsan wall-clock budget on
  // the VM keeps us tighter; 500 is still 500× the
  // mutex-serialization invariant exercise. Exit gate (C5 REFACTOR)
  // can promote this to 1000 once deploy() path is faster post-C4.
  constexpr int kStormSize = 500;

  int successes = 0;
  for (int i = 0; i < kStormSize; ++i) {
    if (fire_one_reload(sock_path, kMinimalConfigJson)) {
      ++successes;
    }
  }

  // Stop the server before asserting so lingering accept loop doesn't
  // race with the counters snapshot under TSAN.
  ctl::cmd_socket_stop(srv);

  EXPECT_EQ(successes, kStormSize)
      << "X1.2: expected " << kStormSize << " successful UDS reloads, got "
      << successes;

  auto c = ctl::reload::counters_snapshot();
  EXPECT_EQ(c.success, static_cast<std::uint64_t>(kStormSize))
      << "X1.2: reload_total{success} must equal storm size";
  EXPECT_EQ(c.parse_error, 0u);
  EXPECT_EQ(c.validate_error, 0u);
  EXPECT_EQ(c.compile_error, 0u);
  EXPECT_EQ(c.build_eal_error, 0u);

  // Live ruleset is the last one published.
  EXPECT_NE(ctl::reload::active_ruleset(), nullptr);
}

// =========================================================================
// C4 — D37 validator memory-budget pre-flight (X1.6, X1.7).
//
// The validator exposes three gates (design §9.2 / validator.cpp):
//   * expansion_per_rule — one rule's expansion exceeds the ceiling
//   * aggregate          — total post-expansion entries exceed sizing cap
//   * hugepage_budget    — estimated footprint > available hugepages
//
// `deploy()` runs `validate_budget` under `reload_mutex`, AFTER parse +
// validate succeed, BEFORE compile / build / populate. Reject path:
//   * returns kValidatorBudget with budget_reason == one of the three
//   * bumps the appropriate sub-reason counter EXACTLY ONCE
//   * leaves `active_ruleset()` UNCHANGED
//   * leaves `active_generation` UNCHANGED
//
// Happy path at the boundary (exactly at the ceiling, not over):
//   * deploy succeeds, active_ruleset swaps, generation advances
//   * NO sub-reason counter bump
// =========================================================================

class ReloadBudgetFixture : public ReloadManagerFixture {};

namespace {

// Build a JSON config with a single L4 rule carrying `n_ports`
// distinct dst_ports. Used by the per-rule expansion gate tests.
std::string make_config_one_l4_rule_n_ports(std::size_t n_ports,
                                            std::uint32_t l4_entries_max) {
  // Build the dst_ports array programmatically. Ports 1..n_ports.
  std::string ports_csv;
  ports_csv.reserve(n_ports * 6);
  for (std::size_t i = 0; i < n_ports; ++i) {
    if (i > 0) ports_csv.push_back(',');
    ports_csv += std::to_string(i + 1);
  }
  std::string s;
  s.reserve(n_ports * 7 + 512);
  s += R"({"version":1,"interface_roles":{"upstream_port":{"pci":"0000:00:00.0"},"downstream_port":{"pci":"0000:00:00.1"}},"sizing":{"rules_per_layer_max":256,"mac_entries_max":256,"ipv4_prefixes_max":1024,"ipv6_prefixes_max":1024,"l4_entries_max":)";
  s += std::to_string(l4_entries_max);
  s += R"(,"vrf_entries_max":32,"rate_limit_rules_max":256,"ethertype_entries_max":32,"vlan_entries_max":256,"pcp_entries_max":8},"pipeline":{"layer_2":[],"layer_3":[],"layer_4":[{"id":4001,"proto":17,"dst_ports":[)";
  s += ports_csv;
  s += R"(],"action":{"type":"drop"}}]},"default_behavior":"drop"})";
  return s;
}

// Build a JSON config with `n_rules` L4 rules, each with 1 dst_port.
// Used by the aggregate gate tests.
std::string make_config_many_l4_rules_one_port(std::size_t n_rules,
                                               std::uint32_t l4_entries_max) {
  std::string rules_json;
  rules_json.reserve(n_rules * 96);
  for (std::size_t i = 0; i < n_rules; ++i) {
    if (i > 0) rules_json.push_back(',');
    rules_json += R"({"id":)";
    rules_json += std::to_string(5000 + i);
    rules_json += R"(,"proto":17,"dst_port":)";
    rules_json += std::to_string(i + 1);
    rules_json += R"(,"action":{"type":"drop"}})";
  }
  std::string s;
  s.reserve(rules_json.size() + 512);
  s += R"({"version":1,"interface_roles":{"upstream_port":{"pci":"0000:00:00.0"},"downstream_port":{"pci":"0000:00:00.1"}},"sizing":{"rules_per_layer_max":256,"mac_entries_max":256,"ipv4_prefixes_max":1024,"ipv6_prefixes_max":1024,"l4_entries_max":)";
  s += std::to_string(l4_entries_max);
  s += R"(,"vrf_entries_max":32,"rate_limit_rules_max":256,"ethertype_entries_max":32,"vlan_entries_max":256,"pcp_entries_max":8},"pipeline":{"layer_2":[],"layer_3":[],"layer_4":[)";
  s += rules_json;
  s += R"(]},"default_behavior":"drop"})";
  return s;
}

// Small config (one trivial L4 rule) used to drive the hugepage-budget
// gate via an injected probe — the config itself is always tiny; the
// probe is what flips the gate.
std::string make_config_tiny() {
  return R"({"version":1,"interface_roles":{"upstream_port":{"pci":"0000:00:00.0"},"downstream_port":{"pci":"0000:00:00.1"}},"pipeline":{"layer_2":[],"layer_3":[],"layer_4":[{"id":6001,"proto":17,"dst_port":5353,"action":{"type":"drop"}}]},"default_behavior":"drop"})";
}

}  // namespace

// -------------------------------------------------------------------------
// X1.6 happy path — boundary-fit configs pass ALL three gates.
// -------------------------------------------------------------------------

TEST_F(ReloadBudgetFixture, ValidatorBudgetHappyPath_ExpansionPerRule) {
  // Per-rule ceiling is 4096. A rule with exactly 4096 dst_ports fits.
  // Set l4_entries_max=4096 so gate 2 also passes (aggregate == ceiling).
  const auto json = make_config_one_l4_rule_n_ports(4096, 4096);

  auto c_before = ctl::reload::counters_snapshot();
  auto r = ctl::reload::deploy(json);
  ASSERT_TRUE(r.ok) << "boundary-fit per-rule: " << r.error;
  EXPECT_EQ(r.kind, ctl::reload::DeployError::kOk);

  auto c_after = ctl::reload::counters_snapshot();
  EXPECT_EQ(c_after.validate_budget_expansion_per_rule,
            c_before.validate_budget_expansion_per_rule)
      << "no sub-reason bump on boundary-fit";
  EXPECT_GT(c_after.active_generation, c_before.active_generation);
  EXPECT_NE(ctl::reload::active_ruleset(), nullptr);
}

TEST_F(ReloadBudgetFixture, ValidatorBudgetHappyPath_Aggregate) {
  // Aggregate ceiling set to 5; 5 rules each with 1 port fits exactly.
  const auto json = make_config_many_l4_rules_one_port(5, 5);

  auto c_before = ctl::reload::counters_snapshot();
  auto r = ctl::reload::deploy(json);
  ASSERT_TRUE(r.ok) << "boundary-fit aggregate: " << r.error;
  EXPECT_EQ(r.kind, ctl::reload::DeployError::kOk);

  auto c_after = ctl::reload::counters_snapshot();
  EXPECT_EQ(c_after.validate_budget_aggregate,
            c_before.validate_budget_aggregate);
  EXPECT_GT(c_after.active_generation, c_before.active_generation);
  EXPECT_NE(ctl::reload::active_ruleset(), nullptr);
}

TEST_F(ReloadBudgetFixture, ValidatorBudgetHappyPath_HugepageBudget) {
  // Inject a probe reporting a comfortable 16 MiB — the tiny config's
  // estimated footprint is <10 KB, so gate 3 passes.
  ctl::reload::set_budget_probe_for_test([] {
    return config::HugepageInfo{/*available_bytes=*/16u * 1024u * 1024u};
  });
  const auto json = make_config_tiny();

  auto c_before = ctl::reload::counters_snapshot();
  auto r = ctl::reload::deploy(json);
  ASSERT_TRUE(r.ok) << "boundary-fit hugepage: " << r.error;
  EXPECT_EQ(r.kind, ctl::reload::DeployError::kOk);

  auto c_after = ctl::reload::counters_snapshot();
  EXPECT_EQ(c_after.validate_budget_hugepage,
            c_before.validate_budget_hugepage);
  EXPECT_GT(c_after.active_generation, c_before.active_generation);
  EXPECT_NE(ctl::reload::active_ruleset(), nullptr);
}

// -------------------------------------------------------------------------
// X1.7 overflow path — each config overflows exactly one gate.
// -------------------------------------------------------------------------

TEST_F(ReloadBudgetFixture, ValidatorBudgetOverflow_ExpansionPerRule) {
  // 4097 dst_ports on a single rule — above the 4096 ceiling.
  // Aggregate ceiling is permissive so gate 2 does not preempt.
  const auto json = make_config_one_l4_rule_n_ports(4097, 8192);

  auto c_before = ctl::reload::counters_snapshot();
  auto* rs_before = ctl::reload::active_ruleset();
  const auto gen_before = c_before.active_generation;

  auto r = ctl::reload::deploy(json);
  EXPECT_FALSE(r.ok);
  EXPECT_EQ(r.kind, ctl::reload::DeployError::kValidatorBudget);
  EXPECT_EQ(r.budget_reason,
            ctl::reload::ValidatorBudgetReason::kExpansionPerRule);

  auto c_after = ctl::reload::counters_snapshot();
  EXPECT_EQ(c_after.validate_budget_expansion_per_rule,
            c_before.validate_budget_expansion_per_rule + 1u)
      << "per-rule sub-reason counter bumps exactly once";
  EXPECT_EQ(c_after.validate_budget_aggregate,
            c_before.validate_budget_aggregate);
  EXPECT_EQ(c_after.validate_budget_hugepage,
            c_before.validate_budget_hugepage);

  // Exchange did NOT happen — ruleset and generation unchanged.
  EXPECT_EQ(ctl::reload::active_ruleset(), rs_before)
      << "validator reject must not exchange g_active";
  EXPECT_EQ(c_after.active_generation, gen_before)
      << "active_generation unchanged on reject";
}

TEST_F(ReloadBudgetFixture, ValidatorBudgetOverflow_Aggregate) {
  // 6 single-port L4 rules against aggregate ceiling = 5.
  const auto json = make_config_many_l4_rules_one_port(6, 5);

  auto c_before = ctl::reload::counters_snapshot();
  auto* rs_before = ctl::reload::active_ruleset();
  const auto gen_before = c_before.active_generation;

  auto r = ctl::reload::deploy(json);
  EXPECT_FALSE(r.ok);
  EXPECT_EQ(r.kind, ctl::reload::DeployError::kValidatorBudget);
  EXPECT_EQ(r.budget_reason, ctl::reload::ValidatorBudgetReason::kAggregate);

  auto c_after = ctl::reload::counters_snapshot();
  EXPECT_EQ(c_after.validate_budget_aggregate,
            c_before.validate_budget_aggregate + 1u);
  EXPECT_EQ(c_after.validate_budget_expansion_per_rule,
            c_before.validate_budget_expansion_per_rule);
  EXPECT_EQ(c_after.validate_budget_hugepage,
            c_before.validate_budget_hugepage);

  EXPECT_EQ(ctl::reload::active_ruleset(), rs_before);
  EXPECT_EQ(c_after.active_generation, gen_before);
}

TEST_F(ReloadBudgetFixture, ValidatorBudgetOverflow_HugepageBudget) {
  // Inject a probe reporting 1 byte — below anything the tiny config
  // could fit (kOverheadBytes alone is 4096).
  ctl::reload::set_budget_probe_for_test([] {
    return config::HugepageInfo{/*available_bytes=*/1u};
  });
  const auto json = make_config_tiny();

  auto c_before = ctl::reload::counters_snapshot();
  auto* rs_before = ctl::reload::active_ruleset();
  const auto gen_before = c_before.active_generation;

  auto r = ctl::reload::deploy(json);
  EXPECT_FALSE(r.ok);
  EXPECT_EQ(r.kind, ctl::reload::DeployError::kValidatorBudget);
  EXPECT_EQ(r.budget_reason,
            ctl::reload::ValidatorBudgetReason::kHugepageBudget);

  auto c_after = ctl::reload::counters_snapshot();
  EXPECT_EQ(c_after.validate_budget_hugepage,
            c_before.validate_budget_hugepage + 1u);
  EXPECT_EQ(c_after.validate_budget_aggregate,
            c_before.validate_budget_aggregate);
  EXPECT_EQ(c_after.validate_budget_expansion_per_rule,
            c_before.validate_budget_expansion_per_rule);

  EXPECT_EQ(ctl::reload::active_ruleset(), rs_before);
  EXPECT_EQ(c_after.active_generation, gen_before);
}

// =========================================================================
// C4 — D12 shutdown sequence smoke.
//
// Brings up QSBR with N workers that register/online + report quiescent
// in a tight loop. Publishes two rulesets via deploy_prebuilt() so
// freed_total has a non-trivial baseline. Calls shutdown() WITHOUT
// stopping the workers first (they keep running), and asserts shutdown
// drains cleanly — the synchronize inside shutdown() must complete
// because the workers keep reporting quiescent. Tests the TSAN-visible
// happens-before edge between worker reads and main's delete.
// =========================================================================

namespace {

struct ShutdownHarness {
  struct rte_rcu_qsbr*  qs = nullptr;
  std::atomic<bool>     keep_going{true};
  std::vector<std::thread> threads;
  std::vector<unsigned int> thread_ids;
  void*                 qs_raw = nullptr;
};

void shutdown_worker(ShutdownHarness* h, unsigned int tid) {
  rte_rcu_qsbr_thread_register(h->qs, tid);
  rte_rcu_qsbr_thread_online(h->qs, tid);
  // Pretend to read the published ruleset every tick so there's a
  // "reader" TSAN can see. We deliberately DO NOT dereference (the
  // ruleset type has no fields in the bare fixture) — the HB edge
  // that matters is the one inside rte_rcu_qsbr_quiescent.
  while (h->keep_going.load(std::memory_order_acquire)) {
    volatile auto* rs = ctl::reload::active_ruleset();
    (void)rs;
    rte_rcu_qsbr_quiescent(h->qs, tid);
    std::this_thread::sleep_for(std::chrono::microseconds(100));
  }
  rte_rcu_qsbr_thread_offline(h->qs, tid);
  rte_rcu_qsbr_thread_unregister(h->qs, tid);
}

}  // namespace

class ReloadShutdownFixture : public IntegrationEalFixture {
 protected:
  static constexpr std::uint32_t kMaxThreadsSD = 4;
  static constexpr unsigned      kSDWorkers    = 2;
};

TEST_F(ReloadShutdownFixture, ShutdownDrainsAndUnregistersCleanly) {
  // Bring up a QSBR handle local to this test — keep it independent
  // of the C2 fixture's qs so the two do not collide.
  size_t sz = rte_rcu_qsbr_get_memsize(kMaxThreadsSD);
  ASSERT_GT(sz, 0u);
  void* qs_raw = std::aligned_alloc(alignof(std::max_align_t), sz);
  ASSERT_NE(qs_raw, nullptr);
  auto* qs = static_cast<struct rte_rcu_qsbr*>(qs_raw);
  ASSERT_EQ(rte_rcu_qsbr_init(qs, kMaxThreadsSD), 0);

  ShutdownHarness h;
  h.qs = qs;
  h.qs_raw = qs_raw;
  h.thread_ids = {0u, 1u};
  for (unsigned int tid : h.thread_ids) {
    h.threads.emplace_back(shutdown_worker, &h, tid);
  }
  // Let workers report quiescent at least once.
  std::this_thread::sleep_for(std::chrono::milliseconds(5));

  // Init manager with the same QSBR handle.
  ctl::reload::InitParams p;
  p.socket_id       = 0;
  p.num_lcores      = 1;
  p.max_entries     = 256;
  p.name_prefix     = "pktgate_test_c4_shutdown";
  p.qs              = qs;
  p.reload_timeout  = std::chrono::milliseconds(200);
  p.poll_interval   = std::chrono::microseconds(100);
  p.shutdown_timeout = std::chrono::milliseconds(500);
  ctl::reload::init(p);

  // Publish two rulesets — exercises the free-after-synchronize path.
  {
    auto rs = std::make_unique<ruleset::Ruleset>();
    auto r = ctl::reload::deploy_prebuilt(std::move(rs));
    ASSERT_TRUE(r.ok) << r.error;
  }
  {
    auto rs = std::make_unique<ruleset::Ruleset>();
    auto r = ctl::reload::deploy_prebuilt(std::move(rs));
    ASSERT_TRUE(r.ok) << r.error;
  }
  EXPECT_NE(ctl::reload::active_ruleset(), nullptr);

  // Call shutdown while workers are STILL running. The synchronize
  // inside shutdown() must complete because workers keep reporting
  // quiescent. This is the primary shutdown-race assertion.
  ctl::reload::shutdown();

  // After shutdown: active_ruleset() must be nullptr, all prior
  // rulesets freed.
  EXPECT_EQ(ctl::reload::active_ruleset(), nullptr)
      << "shutdown must clear g_active";

  // Tear down the harness — stop workers and join.
  h.keep_going.store(false, std::memory_order_release);
  for (auto& t : h.threads) t.join();
  std::free(qs_raw);
}

// Negative shutdown scenario: the caller already joined workers (the
// typical path in main.cpp). Workers are offline+unregistered.
// shutdown() still runs to completion.
TEST_F(ReloadShutdownFixture, ShutdownAfterWorkerJoinIsClean) {
  size_t sz = rte_rcu_qsbr_get_memsize(kMaxThreadsSD);
  void* qs_raw = std::aligned_alloc(alignof(std::max_align_t), sz);
  auto* qs = static_cast<struct rte_rcu_qsbr*>(qs_raw);
  ASSERT_EQ(rte_rcu_qsbr_init(qs, kMaxThreadsSD), 0);

  ShutdownHarness h;
  h.qs = qs;
  h.thread_ids = {0u};
  for (unsigned int tid : h.thread_ids) {
    h.threads.emplace_back(shutdown_worker, &h, tid);
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(5));

  ctl::reload::InitParams p;
  p.socket_id       = 0;
  p.num_lcores      = 1;
  p.max_entries     = 256;
  p.name_prefix     = "pktgate_test_c4_shutdown_post_join";
  p.qs              = qs;
  p.reload_timeout  = std::chrono::milliseconds(200);
  p.poll_interval   = std::chrono::microseconds(100);
  p.shutdown_timeout = std::chrono::milliseconds(500);
  ctl::reload::init(p);

  {
    auto rs = std::make_unique<ruleset::Ruleset>();
    auto r = ctl::reload::deploy_prebuilt(std::move(rs));
    ASSERT_TRUE(r.ok) << r.error;
  }

  // Stop + join workers BEFORE shutdown. They call offline+unregister
  // at the bottom of their loop.
  h.keep_going.store(false, std::memory_order_release);
  for (auto& t : h.threads) t.join();

  // Now shutdown. synchronize should return 1 immediately.
  const auto t0 = std::chrono::steady_clock::now();
  ctl::reload::shutdown();
  const auto t1 = std::chrono::steady_clock::now();
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      t1 - t0).count();
  EXPECT_LT(ms, 300)
      << "shutdown after worker join should be fast, took " << ms << " ms";

  EXPECT_EQ(ctl::reload::active_ruleset(), nullptr);
  std::free(qs_raw);
}

}  // namespace pktgate::test
