// tests/unit/eal_fixture.h
//
// M3 C4 — singleton gtest fixture that calls rte_eal_init() once.
//
// DPDK EAL can only be initialized once per process. All EAL-needing
// unit tests share this fixture in the same binary.

#pragma once

#include <cstdlib>
#include <vector>

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
    //
    // EAL `-d <path>` is **opt-in** via PKTGATE_DPDK_DRIVER_DIR: the dev
    // VM's ldconfig already exposes the build-tree PMDs and passing `-d`
    // on top hits EAL's tailq double-registration panic on the dual
    // install (memory `vm_dpdk_layout.md`, 2026-04-19 infra fixup).
    std::vector<const char*> argv{
        "test_eal_unit",
        "--no-pci",
        "--no-huge",
        "-m", "512",
        "--log-level", "lib.*:error",
    };
    const char* drv = std::getenv("PKTGATE_DPDK_DRIVER_DIR");
    if (drv != nullptr && drv[0] != '\0') {
      argv.push_back("-d");
      argv.push_back(drv);
    }
    argv.push_back("--vdev");
    argv.push_back("net_null0");
    argv.push_back("--file-prefix");
    argv.push_back("pktgate_eal_unit");

    int argc = static_cast<int>(argv.size());
    int ret = rte_eal_init(argc, const_cast<char**>(argv.data()));
    ASSERT_GE(ret, 0) << "rte_eal_init failed";

    s_initialized = true;
  }

  static void TearDownTestSuite() {
    // rte_eal_cleanup() can only be called once and DPDK 25.11
    // may not fully support it in test contexts. Skip cleanup.
  }

 private:
  static inline bool s_initialized = false;
};

}  // namespace pktgate::test
