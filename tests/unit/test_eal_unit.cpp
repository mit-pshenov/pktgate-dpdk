// tests/unit/test_eal_unit.cpp
//
// M3 C4 — EAL-needing unit tests.
//
// This binary has its own main() that calls rte_eal_init() once
// via the EalFixture, then runs all gtest tests. Separate from
// the pure-C++ unit tests that don't need EAL.

#include "tests/unit/eal_fixture.h"

#include <gtest/gtest.h>

#include <rte_mbuf.h>

#include "src/eal/dynfield.h"

namespace pktgate::test {

// =========================================================================
// U6.1 — dynfield registration and writability
//
// After EAL boot, register the dynfield, verify offset is valid,
// allocate an mbuf, write to the dynfield, read back.
// =========================================================================

class DynfieldTest : public EalFixture {};

TEST_F(DynfieldTest, U6_1_DynfieldRegistrationAndWritable) {
  // Register dynfield.
  int offset = eal::register_dynfield();
  ASSERT_GE(offset, 0) << "dynfield registration failed";
  EXPECT_EQ(eal::dynfield_offset(), offset);

  // Offset must be within mbuf bounds. DPDK reserves space within the
  // rte_mbuf struct itself for dynamic fields (the dynfield1[] area).
  // The offset is typically < sizeof(rte_mbuf).
  EXPECT_GT(offset, 0);
  EXPECT_LT(offset, static_cast<int>(sizeof(struct rte_mbuf)));

  // Create a tiny mempool for the test.
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "test_dynfield_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr) << "mempool creation failed";

  // Allocate an mbuf and write to the dynfield.
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr) << "mbuf alloc failed";

  auto* dyn = eal::mbuf_dynfield(m);
  ASSERT_NE(dyn, nullptr);

  // Write known values.
  dyn->verdict_layer = eal::kNextL3;
  dyn->l3_offset = 14;  // standard Ethernet header
  dyn->parsed_l3_proto = 0x04;  // IPv4
  dyn->flags = 0;
  dyn->l4_extra = 0;
  dyn->parsed_l4_dport = 443;
  dyn->parsed_l4_sport = 12345;
  dyn->parsed_vlan = 0xFFFF;  // untagged
  dyn->parsed_ethertype = 0x0800;  // IPv4

  // Read back and verify.
  const auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(m));
  EXPECT_EQ(cdyn->verdict_layer, eal::kNextL3);
  EXPECT_EQ(cdyn->l3_offset, 14);
  EXPECT_EQ(cdyn->parsed_l3_proto, 0x04);
  EXPECT_EQ(cdyn->flags, 0);
  EXPECT_EQ(cdyn->l4_extra, 0);
  EXPECT_EQ(cdyn->parsed_l4_dport, 443);
  EXPECT_EQ(cdyn->parsed_l4_sport, 12345);
  EXPECT_EQ(cdyn->parsed_vlan, 0xFFFF);
  EXPECT_EQ(cdyn->parsed_ethertype, 0x0800);

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

}  // namespace pktgate::test
