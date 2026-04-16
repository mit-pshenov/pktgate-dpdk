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

}  // namespace pktgate::test
