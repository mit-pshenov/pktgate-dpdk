// tests/unit/eal_fixture.h
//
// M3 C4 — singleton gtest fixture that calls rte_eal_init() once.
//
// DPDK EAL can only be initialized once per process. All EAL-needing
// unit tests share this fixture in the same binary.

#pragma once

#include <gtest/gtest.h>

#include <rte_eal.h>
#include <rte_mbuf.h>

namespace pktgate::test {

class EalFixture : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (s_initialized) return;

    // Minimal EAL for unit tests: no PCI, no hugepages. Memory bumped
    // to 512 MB in M4 C0 — the rte_fib DIR24_8 table allocates a flat
    // 16Mi-entry tbl24 (128 MB with 8-byte next_hops), so the previous
    // 64 MB budget failed rte_fib_create with rte_errno=12 (ENOMEM)
    // as soon as U4.2 tried to open an L3 FIB. 512 MB is cheap on the
    // dev VM and leaves plenty of headroom for sanitizer presets.
    const char* argv[] = {
        "test_eal_unit",
        "--no-pci",
        "--no-huge",
        "-m", "512",
        "--log-level", "lib.*:error",
        "-d", DPDK_DRIVER_DIR,
        "--vdev", "net_null0",
        "--file-prefix", "pktgate_eal_unit",
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    int ret = rte_eal_init(argc, const_cast<char**>(argv));
    ASSERT_GE(ret, 0) << "rte_eal_init failed";

    s_initialized = true;
  }

  static void TearDownTestSuite() {
    // rte_eal_cleanup() can only be called once and DPDK 25.11
    // may not fully support it in test contexts. Skip cleanup.
  }

  // Default DPDK driver directory for the dev VM.
  static constexpr const char* DPDK_DRIVER_DIR =
      "/home/mit/Dev/dpdk-25.11/build/drivers/";

 private:
  static inline bool s_initialized = false;
};

}  // namespace pktgate::test
