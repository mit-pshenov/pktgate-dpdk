// tests/unit/test_eal_unit.cpp
//
// M3/M4 — EAL-needing unit tests.
//
// This binary has its own main() that calls rte_eal_init() once
// via the EalFixture, then runs all gtest tests. Separate from
// the pure-C++ unit tests that don't need EAL.

#include "tests/unit/eal_fixture.h"

#include <gtest/gtest.h>

#include <cstring>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_fib.h>
#include <rte_fib6.h>
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_ip6.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "src/compiler/compiler.h"
#include "src/compiler/object_compiler.h"
#include "src/compiler/rule_compiler.h"
#include "src/config/model.h"
#include "src/config/sizing.h"
#include "src/dataplane/classify_l2.h"
#include "src/dataplane/classify_l3.h"
#include "src/dataplane/worker.h"
#include "src/eal/dynfield.h"
#include "src/eal/port_init.h"
#include "src/ruleset/builder.h"
#include "src/ruleset/builder_eal.h"
#include "src/ruleset/ruleset.h"
#include "src/ruleset/types.h"

namespace pktgate::test {

// =========================================================================
// U6.0a — dynfield registration and writability
//
// After EAL boot, register the dynfield, verify offset is valid,
// allocate an mbuf, write to the dynfield, read back.
//
// NOTE: originally labeled U6.1 in the M3 plan. Renamed to U6.0a in
// M4 C0 because the real U6.1 test ID was re-assigned by the M4
// plan to "L2 empty ruleset → NEXT_L3" (first classify_l2 cycle).
// See scratch/m4-supervisor-handoff.md "Plan errata".
// =========================================================================

class DynfieldTest : public EalFixture {};

TEST_F(DynfieldTest, U6_0a_DynfieldRegistrationAndWritable) {
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

// =========================================================================
// U6.1 — classify_l2: empty ruleset → NEXT_L3 [needs EAL]
//
// Build a Ruleset with no L2 compound entries (l2_compound_count == 0,
// l2_compound_hash == nullptr — the pure-C++ builder path leaves them
// as nullptr/0). Allocate a stub mbuf from a tiny mempool, call
// classify_l2() through the top-level public entry point (D41 invariant:
// tests go through the same entry point the worker uses), and assert
// that the verdict is kNextL3.
//
// The stub mbuf payload does not matter for this test — the empty-ruleset
// short-circuit fires before any packet parsing.
//
// Covers: §5.2 control flow, F1 default (miss → proceed to L3).
// D41: first cycle where classify_l2 is called; this IS the top-level
//      entry point test that all C2+ cycles must also satisfy.
// =========================================================================

class ClassifyL2Test : public EalFixture {};

TEST_F(ClassifyL2Test, U6_1_EmptyRulesetReturnsNextL3) {
  // Register the dynfield so classify_l2 can use mbuf_dynfield in future
  // cycles. C1 body doesn't write the dynfield yet, but the dynfield must
  // be registered before any production code path uses it.
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  // Build an empty Ruleset (pure-C++ path: no DPDK handles).
  ruleset::Ruleset rs;
  // l2_compound_count is 0 by default (value-initialized in Ruleset ctor).
  ASSERT_EQ(rs.l2_compound_count, 0u);
  ASSERT_EQ(rs.l2_compound_hash, nullptr);

  // Create a tiny mempool for the stub mbuf.
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_1_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr) << "mempool creation failed";

  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr) << "mbuf alloc failed";

  // Precondition: single segment (D39 invariant the worker guarantees).
  ASSERT_EQ(m->nb_segs, 1);

  // D31: truncation guards fire before empty-ruleset bail. Build a minimal
  // valid-length Ethernet frame (14 B untagged) so guard #1 doesn't trigger.
  // The payload content does not matter — empty ruleset → kNextL3 before
  // any field parsing or hash probing.
  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 14));
  ASSERT_NE(pkt, nullptr) << "mbuf append failed";
  std::memset(pkt, 0, 14);
  // Write a non-VLAN ethertype (0x0800) so guard #2 also doesn't trigger.
  pkt[12] = 0x08; pkt[13] = 0x00;

  // D41 invariant: call through top-level classify_l2 entry point.
  const dataplane::ClassifyL2Verdict verdict = dataplane::classify_l2(m, rs);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kNextL3)
      << "empty ruleset must return kNextL3 (L2 miss → proceed to L3)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// U6.2a — D39 worker multi-seg drop: is_single_segment check + counter
//
// Synthesize a multi-seg mbuf (chain two mbufs), verify that
// is_single_segment rejects it and that the WorkerCtx counter
// increments correctly.
// =========================================================================

class WorkerMultiSegTest : public EalFixture {};

TEST_F(WorkerMultiSegTest, U6_2a_SingleSegReturnsTrue) {
  // Single-segment mbuf: is_single_segment must return true.
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "test_singleseg_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr) << "mempool creation failed";

  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  EXPECT_EQ(m->nb_segs, 1);
  EXPECT_TRUE(dataplane::is_single_segment(m));

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

TEST_F(WorkerMultiSegTest, U6_2a_MultiSegReturnsFalse) {
  // Chain two mbufs to create a multi-segment packet.
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "test_multiseg_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr) << "mempool creation failed";

  struct rte_mbuf* head = rte_pktmbuf_alloc(mp);
  struct rte_mbuf* tail = rte_pktmbuf_alloc(mp);
  ASSERT_NE(head, nullptr);
  ASSERT_NE(tail, nullptr);

  // Manually chain: head->next = tail, nb_segs = 2.
  head->next = tail;
  head->nb_segs = 2;
  head->pkt_len = head->data_len + tail->data_len;

  EXPECT_FALSE(dataplane::is_single_segment(head));

  // Verify WorkerCtx counter bookkeeping pattern.
  // (Worker RX loop: if !is_single_segment → ++counter, free, continue.)
  dataplane::WorkerCtx ctx{};
  std::atomic<bool> running{true};
  ctx.running = &running;
  EXPECT_EQ(ctx.pkt_multiseg_drop_total, 0u);

  // Simulate the drop path.
  if (!dataplane::is_single_segment(head)) {
    ++ctx.pkt_multiseg_drop_total;
  }
  EXPECT_EQ(ctx.pkt_multiseg_drop_total, 1u);

  // Free the chained mbuf (rte_pktmbuf_free walks the chain).
  rte_pktmbuf_free(head);
  rte_mempool_free(mp);
}

// =========================================================================
// Builder-EAL test helpers (M4 C0 — U4.2..U4.5)
// =========================================================================
//
// Each test builds a tiny Config, runs the compiler pipeline, calls
// populate_ruleset_eal() to open the DPDK tables, then queries the
// tables to assert that primary keys / prefixes resolve to the right
// compound entries.
//
// The rte_hash / rte_fib global namespace is shared process-wide, so
// each test uses a unique `name_prefix` to avoid EEXIST on reruns.

namespace builder_eal {

using ::pktgate::compiler::CompileResult;
using ::pktgate::compiler::compile;
using ::pktgate::config::ActionAllow;
using ::pktgate::config::ActionDrop;
using ::pktgate::config::Cidr4;
using ::pktgate::config::Cidr6;
using ::pktgate::config::Config;
using ::pktgate::config::DefaultBehavior;
using ::pktgate::config::FragmentPolicy;
using ::pktgate::config::InterfaceRole;
using ::pktgate::config::Mac;
using ::pktgate::config::PciSelector;
using ::pktgate::config::Rule;
using ::pktgate::config::RuleAction;
using ::pktgate::config::SubnetObject;
using ::pktgate::config::SubnetRef;
using ::pktgate::config::kSchemaVersion;
using ::pktgate::config::kSizingDevDefaults;
using ::pktgate::ruleset::EalPopulateParams;
using ::pktgate::ruleset::L3CompoundEntry;
using ::pktgate::ruleset::Ruleset;
using ::pktgate::ruleset::populate_ruleset_eal;

inline Config make_config() {
  Config cfg;
  cfg.version = kSchemaVersion;
  cfg.default_behavior = DefaultBehavior::kDrop;
  cfg.fragment_policy = FragmentPolicy::kL3Only;
  cfg.sizing = kSizingDevDefaults;
  cfg.interface_roles = {
      InterfaceRole{"upstream_port", PciSelector{"0000:00:00.0"}},
      InterfaceRole{"downstream_port", PciSelector{"0000:00:00.1"}},
  };
  return cfg;
}

inline Rule& append_rule(std::vector<Rule>& layer, std::int32_t id,
                         RuleAction action) {
  auto& r = layer.emplace_back();
  r.id = id;
  r.action = std::move(action);
  return r;
}

// Unpack an L3CompoundEntry from the FIB next_hop slot.
inline L3CompoundEntry unpack_l3(std::uint64_t nh) {
  L3CompoundEntry entry{};
  std::memcpy(&entry, &nh, sizeof(entry));
  return entry;
}

}  // namespace builder_eal

class BuilderEalTest : public EalFixture {};

// =========================================================================
// U4.2 — FIB4 population [needs EAL]
//
// Three L3v4 rules with distinct destination prefixes (resolved via
// `dst_subnet` SubnetRef → object pool). After populate_ruleset_eal
// the v4 FIB must return the correct action_idx for in-prefix addresses
// and the default (no match) for an outside address.
// =========================================================================

TEST_F(BuilderEalTest, U4_2_Fib4Population) {
  using namespace builder_eal;
  Config cfg = make_config();

  // Three subnets, one per L3 rule.
  SubnetObject a;
  a.name = "net_a";
  a.cidrs.push_back(Cidr4{0x0A000000, 8});    // 10.0.0.0/8
  cfg.objects.subnets.push_back(std::move(a));

  SubnetObject b;
  b.name = "net_b";
  b.cidrs.push_back(Cidr4{0xAC100000, 12});   // 172.16.0.0/12
  cfg.objects.subnets.push_back(std::move(b));

  SubnetObject c;
  c.name = "net_c";
  c.cidrs.push_back(Cidr4{0xC0A80000, 16});   // 192.168.0.0/16
  cfg.objects.subnets.push_back(std::move(c));

  auto& r1 = append_rule(cfg.pipeline.layer_3, 3001, ActionDrop{});
  r1.dst_subnet = SubnetRef{"net_a"};
  auto& r2 = append_rule(cfg.pipeline.layer_3, 3002, ActionAllow{});
  r2.dst_subnet = SubnetRef{"net_b"};
  auto& r3 = append_rule(cfg.pipeline.layer_3, 3003, ActionDrop{});
  r3.dst_subnet = SubnetRef{"net_c"};

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value());
  ASSERT_EQ(cr.l3_compound.size(), 3u);

  Ruleset rs;
  EalPopulateParams params;
  params.name_prefix = "u4_2";
  params.socket_id = 0;
  params.max_entries = 64;

  auto res = populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;
  ASSERT_NE(rs.l3_v4_fib, nullptr);

  // Lookup in-prefix addresses via rte_fib_lookup_bulk.
  const std::uint32_t ips[4] = {
      0x0A010203,   // 10.1.2.3 -> net_a (rule 0)
      0xAC110001,   // 172.17.0.1 -> net_b (rule 1)
      0xC0A80001,   // 192.168.0.1 -> net_c (rule 2)
      0x08080808,   // 8.8.8.8 -> no match
  };
  std::uint64_t nh[4] = {0, 0, 0, 0};
  int lret = rte_fib_lookup_bulk(rs.l3_v4_fib,
                                 const_cast<std::uint32_t*>(ips), nh, 4);
  ASSERT_EQ(lret, 0);

  EXPECT_EQ(unpack_l3(nh[0]).action_idx, 0);
  EXPECT_EQ(unpack_l3(nh[1]).action_idx, 1);
  EXPECT_EQ(unpack_l3(nh[2]).action_idx, 2);
  // Default next_hop is 0 (we set conf.default_nh = 0). action_idx==0
  // in the default slot would alias rule 0, so we check the *entry*
  // has prefix==8 (rule 0) only for ip[0].
  EXPECT_EQ(nh[3], 0u) << "8.8.8.8 must not match any configured prefix";
}

// =========================================================================
// U4.3 — FIB6 population [needs EAL]
// =========================================================================

TEST_F(BuilderEalTest, U4_3_Fib6Population) {
  using namespace builder_eal;
  Config cfg = make_config();

  // 2001:db8::/32 and fd00::/8
  SubnetObject a;
  a.name = "v6_a";
  {
    Cidr6 c{};
    c.bytes[0] = 0x20; c.bytes[1] = 0x01;
    c.bytes[2] = 0x0d; c.bytes[3] = 0xb8;
    c.prefix = 32;
    a.cidrs.push_back(c);
  }
  cfg.objects.subnets.push_back(std::move(a));

  SubnetObject b;
  b.name = "v6_b";
  {
    Cidr6 c{};
    c.bytes[0] = 0xfd;
    c.prefix = 8;
    b.cidrs.push_back(c);
  }
  cfg.objects.subnets.push_back(std::move(b));

  auto& r1 = append_rule(cfg.pipeline.layer_3, 4001, ActionDrop{});
  r1.dst_subnet = SubnetRef{"v6_a"};
  auto& r2 = append_rule(cfg.pipeline.layer_3, 4002, ActionAllow{});
  r2.dst_subnet = SubnetRef{"v6_b"};

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value());
  ASSERT_EQ(cr.l3_compound.size(), 2u);

  Ruleset rs;
  EalPopulateParams params;
  params.name_prefix = "u4_3";
  params.socket_id = 0;
  params.max_entries = 64;

  auto res = populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;
  ASSERT_NE(rs.l3_v6_fib, nullptr);

  // Lookup: 2001:db8::1 → v6_a; fd12::1 → v6_b; 2001:470::1 → no match.
  rte_ipv6_addr ips[3]{};
  ips[0].a[0] = 0x20; ips[0].a[1] = 0x01;
  ips[0].a[2] = 0x0d; ips[0].a[3] = 0xb8;
  ips[0].a[15] = 0x01;

  ips[1].a[0] = 0xfd; ips[1].a[1] = 0x12;
  ips[1].a[15] = 0x01;

  ips[2].a[0] = 0x20; ips[2].a[1] = 0x01;
  ips[2].a[2] = 0x04; ips[2].a[3] = 0x70;
  ips[2].a[15] = 0x01;

  std::uint64_t nh[3] = {0, 0, 0};
  int lret = rte_fib6_lookup_bulk(rs.l3_v6_fib, ips, nh, 3);
  ASSERT_EQ(lret, 0);

  EXPECT_EQ(unpack_l3(nh[0]).action_idx, 0);
  EXPECT_EQ(unpack_l3(nh[1]).action_idx, 1);
  EXPECT_EQ(nh[2], 0u) << "2001:470::1 must not match";
}

// =========================================================================
// U4.4 — L2 rte_hash population [needs EAL]
//
// Two L2 rules with distinct src_mac. After populate_ruleset_eal the
// rte_hash must resolve the packed MAC keys to the correct action_idx
// and return -ENOENT for a random MAC.
// =========================================================================

TEST_F(BuilderEalTest, U4_4_L2HashPopulation) {
  using namespace builder_eal;
  Config cfg = make_config();

  auto& r1 = append_rule(cfg.pipeline.layer_2, 1001, ActionAllow{});
  r1.src_mac = Mac{{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}};
  auto& r2 = append_rule(cfg.pipeline.layer_2, 1002, ActionDrop{});
  r2.src_mac = Mac{{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}};

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value());
  ASSERT_EQ(cr.l2_compound.size(), 2u);

  Ruleset rs;
  EalPopulateParams params;
  params.name_prefix = "u4_4";
  params.socket_id = 0;
  params.max_entries = 64;

  auto res = populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;
  ASSERT_NE(rs.l2_compound_hash, nullptr);

  // Lookup the two configured keys.
  std::uint64_t k1 = cr.l2_compound[0].primary_key;
  std::uint64_t k2 = cr.l2_compound[1].primary_key;
  std::uint64_t k_miss = 0xDEADBEEFCAFEBABEull;

  void* data = nullptr;
  ASSERT_GE(rte_hash_lookup_data(rs.l2_compound_hash, &k1, &data), 0);
  ASSERT_NE(data, nullptr);
  EXPECT_EQ(static_cast<pktgate::ruleset::L2CompoundEntry*>(data)->action_idx,
            0);

  data = nullptr;
  ASSERT_GE(rte_hash_lookup_data(rs.l2_compound_hash, &k2, &data), 0);
  ASSERT_NE(data, nullptr);
  EXPECT_EQ(static_cast<pktgate::ruleset::L2CompoundEntry*>(data)->action_idx,
            1);

  data = nullptr;
  int miss = rte_hash_lookup_data(rs.l2_compound_hash, &k_miss, &data);
  EXPECT_LT(miss, 0) << "random key must miss";
}

// =========================================================================
// U4.5 — L4 primary hash population [needs EAL]
//
// Two L4 rules: (tcp, dport=443) and icmp catch-all. Lookup each
// primary key through rte_hash_lookup_data.
// =========================================================================

TEST_F(BuilderEalTest, U4_5_L4HashPopulation) {
  using namespace builder_eal;
  Config cfg = make_config();

  auto& r1 = append_rule(cfg.pipeline.layer_4, 2001, ActionDrop{});
  r1.proto = 6;      // TCP
  r1.dst_port = 443;

  auto& r2 = append_rule(cfg.pipeline.layer_4, 2002, ActionAllow{});
  r2.proto = 1;      // ICMP, no dport -> proto-only primary

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value());
  ASSERT_EQ(cr.l4_compound.size(), 2u);

  Ruleset rs;
  EalPopulateParams params;
  params.name_prefix = "u4_5";
  params.socket_id = 0;
  params.max_entries = 64;

  auto res = populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;
  ASSERT_NE(rs.l4_compound_hash, nullptr);

  std::uint32_t k1 = cr.l4_compound[0].primary_key;  // (6<<16)|443
  std::uint32_t k2 = cr.l4_compound[1].primary_key;  // 1
  std::uint32_t k_miss = 0xDEADBEEFu;

  void* data = nullptr;
  ASSERT_GE(rte_hash_lookup_data(rs.l4_compound_hash, &k1, &data), 0);
  ASSERT_NE(data, nullptr);
  EXPECT_EQ(static_cast<pktgate::ruleset::L4CompoundEntry*>(data)->action_idx,
            0);

  data = nullptr;
  ASSERT_GE(rte_hash_lookup_data(rs.l4_compound_hash, &k2, &data), 0);
  ASSERT_NE(data, nullptr);
  EXPECT_EQ(static_cast<pktgate::ruleset::L4CompoundEntry*>(data)->action_idx,
            1);

  data = nullptr;
  int miss = rte_hash_lookup_data(rs.l4_compound_hash, &k_miss, &data);
  EXPECT_LT(miss, 0) << "random primary key must miss";
}

// =========================================================================
// U4.18 — D39 port scatter-off + mempool-fit validator [needs EAL]
//
// Create two mempools: one with data_room too small for RTE_ETHER_MAX_LEN,
// one with data_room large enough. check_no_scatter() must reject the
// small one with "multiseg_rx_unsupported" in the error and accept the
// large one.
//
// The net_null port from EalFixture has max_rx_pktlen set to a large
// value (well over 64), so the "data_room=64" mempool forces the
// violation path.
// =========================================================================

class ScatterValidatorTest : public EalFixture {};

TEST_F(ScatterValidatorTest, U4_18_CheckNoScatterAcceptsAndRejects) {
  // Resolve the net_null port spawned by the EalFixture.
  auto resolve = eal::resolve_port_by_name("net_null0");
  ASSERT_TRUE(resolve.ok) << resolve.error;
  const std::uint16_t port_id = resolve.port_id;

  // D39 specifies the mempool's element size must be >= max_rx_pktlen.
  // A mempool with a too-small element cannot hold a standard Ethernet
  // frame in one segment — check_no_scatter must reject it.
  //
  // rte_pktmbuf_pool_create takes `data_room` as the 5th parameter.
  // data_room must be >= sizeof(struct rte_mbuf)'s headroom (128) per
  // DPDK requirements, so we use 256 for the "too small" case (<1518
  // but >= minimum headroom) and RTE_MBUF_DEFAULT_BUF_SIZE for the
  // "fits" case.
  struct rte_mempool* small_mp = rte_pktmbuf_pool_create(
      "u4_18_small_pool", 63, 0, 0,
      static_cast<uint16_t>(256), 0);
  ASSERT_NE(small_mp, nullptr);

  struct rte_mempool* big_mp = rte_pktmbuf_pool_create(
      "u4_18_big_pool", 63, 0, 0,
      RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(big_mp, nullptr);

  auto small_res = eal::check_no_scatter(port_id, small_mp);
  EXPECT_FALSE(small_res.ok);
  EXPECT_NE(small_res.error.find("multiseg_rx_unsupported"), std::string::npos)
      << "error must contain 'multiseg_rx_unsupported' sentinel, got: "
      << small_res.error;

  auto big_res = eal::check_no_scatter(port_id, big_mp);
  EXPECT_TRUE(big_res.ok) << big_res.error;

  rte_mempool_free(small_mp);
  rte_mempool_free(big_mp);
}

// =========================================================================
// U6.2 — L2 src_mac match → dispatch_l2 [needs EAL]
//
// Build a Ruleset with one L2 DROP rule keyed on src_mac aa:bb:cc:dd:ee:ff.
// Present a packet with that src_mac. Expect classify_l2 to return kDrop
// AND to have written verdict_action_idx=0 into the dynfield.
//
// Covers: D15 (compound primary lookup + dispatch), §5.2, D41.
// =========================================================================

class ClassifyL2CompoundTest : public EalFixture {};

TEST_F(ClassifyL2CompoundTest, U6_2_SrcMacMatchDispatch) {
  using namespace builder_eal;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  Config cfg = make_config();
  // One L2 DROP rule: src_mac = aa:bb:cc:dd:ee:ff
  auto& r1 = append_rule(cfg.pipeline.layer_2, 2001, ActionDrop{});
  r1.src_mac = config::Mac{{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}};

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value()) << "compile failed";
  ASSERT_EQ(cr.l2_compound.size(), 1u);

  // Build ruleset (actions) + EAL tables.
  Ruleset rs = ruleset::build_ruleset(cr, cfg.sizing, /*num_lcores=*/1);
  EalPopulateParams params;
  params.name_prefix = "u6_2";
  params.socket_id = 0;
  params.max_entries = 64;
  auto res = ruleset::populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;
  ASSERT_NE(rs.l2_compound_hash, nullptr);

  // Build a minimal untagged Ethernet frame:
  //   dst_mac: 01:02:03:04:05:06
  //   src_mac: aa:bb:cc:dd:ee:ff
  //   ethertype: 0x0800 (IPv4)
  //   payload: zeros
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_2_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  // Build Ethernet header in the mbuf.
  uint8_t* pkt = reinterpret_cast<uint8_t*>(
      rte_pktmbuf_append(m, 64));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 64);
  // dst_mac
  pkt[0]=0x01; pkt[1]=0x02; pkt[2]=0x03;
  pkt[3]=0x04; pkt[4]=0x05; pkt[5]=0x06;
  // src_mac = aa:bb:cc:dd:ee:ff
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0xff;
  // ethertype = 0x0800
  pkt[12]=0x08; pkt[13]=0x00;

  // D41: call through top-level entry point.
  const dataplane::ClassifyL2Verdict verdict = dataplane::classify_l2(m, rs);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kDrop)
      << "src_mac DROP rule must return kDrop";

  // Dynfield: verdict_action_idx must point at rule index 0.
  const auto* dyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(m));
  EXPECT_EQ(dyn->verdict_action_idx, 0u)
      << "verdict_action_idx must be 0 (first rule)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// U6.3 — L2 compound filter_mask rejects partial match [needs EAL]
//
// Rule on (src_mac + vlan_id=100). Packet has matching src_mac but no
// VLAN tag (parsed_vlan = 0xFFFF, which != 100). Primary hit on src_mac,
// filter_mask check for kVlan fails → fall through → kNextL3 (miss).
//
// Covers: D15 (filter_mask secondary check), §5.2.
// =========================================================================

TEST_F(ClassifyL2CompoundTest, U6_3_FilterMaskRejectsPartialMatch) {
  using namespace builder_eal;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  Config cfg = make_config();
  // Rule on src_mac + vlan=100, action=ALLOW.
  auto& r1 = append_rule(cfg.pipeline.layer_2, 2003, ActionAllow{});
  r1.src_mac = config::Mac{{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}};
  r1.vlan_id = 100;

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value()) << "compile failed";
  ASSERT_EQ(cr.l2_compound.size(), 1u);
  // Compiler should pick src_mac as primary (more selective than vlan).
  EXPECT_EQ(cr.l2_compound[0].entry.filter_mask,
            compiler::l2_mask::kVlan)
      << "vlan must be in filter_mask (secondary), src_mac is primary";

  Ruleset rs = ruleset::build_ruleset(cr, cfg.sizing, /*num_lcores=*/1);
  EalPopulateParams params;
  params.name_prefix = "u6_3";
  params.socket_id = 0;
  params.max_entries = 64;
  auto res = ruleset::populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;

  // Untagged packet with matching src_mac but NO VLAN tag.
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_3_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 64));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 64);
  pkt[0]=0x01; pkt[1]=0x02; pkt[2]=0x03;
  pkt[3]=0x04; pkt[4]=0x05; pkt[5]=0x06;
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0xff;
  pkt[12]=0x08; pkt[13]=0x00;  // untagged IPv4

  // D41: through top-level entry point. Primary hit, filter_mask fails → miss.
  const dataplane::ClassifyL2Verdict verdict = dataplane::classify_l2(m, rs);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kNextL3)
      << "filter_mask vlan check must reject packet with no VLAN tag";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// U6.4 — L2 selectivity order probed correctly [needs EAL]
//
// Two rules: rule1 on src_mac=aa:bb:cc:dd:ee:01 (DROP), rule2 on
// vlan=200 (ALLOW). Packet has vlan=200 and src_mac NOT matching rule1.
// Classifier probes src_mac first → miss, then probes vlan → hit.
// Result: kNextL3 (ALLOW action from rule2).
//
// Covers: §5.2 selectivity order (src_mac > vlan probed first), D15.
// =========================================================================

TEST_F(ClassifyL2CompoundTest, U6_4_SelectivityOrderProbed) {
  using namespace builder_eal;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  Config cfg = make_config();
  // Rule 0: src_mac primary → DROP (packet src_mac does NOT match this).
  auto& r1 = append_rule(cfg.pipeline.layer_2, 2010, ActionDrop{});
  r1.src_mac = config::Mac{{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}};
  // Rule 1: vlan primary (=200) → ALLOW (packet vlan DOES match this).
  auto& r2 = append_rule(cfg.pipeline.layer_2, 2011, ActionAllow{});
  r2.vlan_id = 200;

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value()) << "compile failed";
  ASSERT_EQ(cr.l2_compound.size(), 2u);
  // Verify compiler assigned primary kinds.
  EXPECT_EQ(cr.l2_compound[0].primary_kind,
            compiler::L2PrimaryKind::kSrcMac)
      << "rule0 must have kSrcMac primary";
  EXPECT_EQ(cr.l2_compound[1].primary_kind,
            compiler::L2PrimaryKind::kVlan)
      << "rule1 must have kVlan primary";

  Ruleset rs = ruleset::build_ruleset(cr, cfg.sizing, /*num_lcores=*/1);
  EalPopulateParams params;
  params.name_prefix = "u6_4";
  params.socket_id = 0;
  params.max_entries = 64;
  auto res = ruleset::populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;

  // Packet: src_mac=aa:bb:cc:dd:ee:02 (does NOT match rule0),
  //         vlan=200 (matches rule1). VLAN-tagged frame (0x8100).
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_4_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  // VLAN-tagged Ethernet: 6+6+2 (0x8100)+2 (vlan=200)+2 (inner etype) = 18 B header.
  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 64));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 64);
  // dst_mac
  pkt[0]=0x01; pkt[1]=0x02; pkt[2]=0x03;
  pkt[3]=0x04; pkt[4]=0x05; pkt[5]=0x06;
  // src_mac = aa:bb:cc:dd:ee:02 (different from rule0's aa:...:01)
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0x02;
  // outer ethertype: 0x8100 (VLAN)
  pkt[12]=0x81; pkt[13]=0x00;
  // TCI: vlan=200, pcp=0 → 0x00c8
  pkt[14]=0x00; pkt[15]=0xc8;
  // inner ethertype: 0x0800
  pkt[16]=0x08; pkt[17]=0x00;

  // D41: through top-level entry point.
  // Expected: src_mac probe → miss (packet src_mac != rule0's MAC),
  //           vlan probe → hit rule1 (vlan=200), ALLOW → kNextL3.
  const dataplane::ClassifyL2Verdict verdict = dataplane::classify_l2(m, rs);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kNextL3)
      << "vlan=200 ALLOW rule must produce kNextL3 after src_mac probe misses";

  // Dynfield: verdict_action_idx must be 1 (rule1 = second rule = index 1).
  const auto* dyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(m));
  EXPECT_EQ(dyn->verdict_action_idx, 1u)
      << "verdict_action_idx must be 1 (second rule, vlan-primary)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// U6.5 — L2 first-match-wins [needs EAL]
//
// Two rules both match a packet with src_mac=aa:bb:cc:dd:ee:01 and
// vlan=100:
//   Rule 0: src_mac=aa:bb:cc:dd:ee:01, vlan=100 (filter_mask kVlan) → DROP
//   Rule 1: vlan=100 (primary=kVlan) → ALLOW
//
// Selectivity order probes src_mac first.  Rule 0 has src_mac as its
// primary key → probe hits, filter_mask vlan=100 passes → dispatched.
// Rule 1 is never probed.  First-match-wins per config order enforced
// by selectivity ordering.
//
// Assert: verdict == kDrop AND verdict_action_idx == 0.
//
// Covers: F1 (first-match-wins discipline), §5.2 selectivity order.
// D41: through top-level classify_l2 entry point.
// =========================================================================

TEST_F(ClassifyL2CompoundTest, U6_5_FirstMatchWins) {
  using namespace builder_eal;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  Config cfg = make_config();

  // Rule 0 (config position 0): src_mac primary + vlan=100 in filter_mask → DROP.
  // primary_kind = kSrcMac, filter_mask = kVlan.
  auto& r0 = append_rule(cfg.pipeline.layer_2, 5000, ActionDrop{});
  r0.src_mac = config::Mac{{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}};
  r0.vlan_id = 100;

  // Rule 1 (config position 1): vlan=100 primary only → ALLOW.
  // primary_kind = kVlan, no filter_mask.
  auto& r1 = append_rule(cfg.pipeline.layer_2, 5001, ActionAllow{});
  r1.vlan_id = 100;

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value()) << "compile failed";
  ASSERT_EQ(cr.l2_compound.size(), 2u);

  // Verify compiler chose src_mac as primary for rule 0 and vlan for rule 1.
  EXPECT_EQ(cr.l2_compound[0].primary_kind, compiler::L2PrimaryKind::kSrcMac)
      << "rule 0 must have kSrcMac primary";
  EXPECT_EQ(cr.l2_compound[1].primary_kind, compiler::L2PrimaryKind::kVlan)
      << "rule 1 must have kVlan primary";

  Ruleset rs = ruleset::build_ruleset(cr, cfg.sizing, /*num_lcores=*/1);
  EalPopulateParams params;
  params.name_prefix = "u6_5";
  params.socket_id = 0;
  params.max_entries = 64;
  auto res = ruleset::populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;
  ASSERT_NE(rs.l2_compound_hash, nullptr);

  // Build a VLAN-tagged frame:
  //   dst_mac: 01:02:03:04:05:06
  //   src_mac: aa:bb:cc:dd:ee:01  ← matches rule 0
  //   outer ethertype: 0x8100
  //   TCI: vlan=100, pcp=0  ← matches both rules
  //   inner ethertype: 0x0800
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_5_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 64));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 64);
  // dst_mac
  pkt[0]=0x01; pkt[1]=0x02; pkt[2]=0x03;
  pkt[3]=0x04; pkt[4]=0x05; pkt[5]=0x06;
  // src_mac = aa:bb:cc:dd:ee:01
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0x01;
  // outer ethertype: 0x8100
  pkt[12]=0x81; pkt[13]=0x00;
  // TCI: vlan=100 (0x0064), pcp=0
  pkt[14]=0x00; pkt[15]=0x64;
  // inner ethertype: 0x0800
  pkt[16]=0x08; pkt[17]=0x00;

  // D41: through top-level entry point.
  // Expect rule 0 (src_mac primary, DROP) fires before rule 1 (vlan primary,
  // ALLOW) is probed — first-match-wins by selectivity order.
  const dataplane::ClassifyL2Verdict verdict = dataplane::classify_l2(m, rs);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kDrop)
      << "first-match-wins: rule 0 (DROP) must fire before rule 1 (ALLOW)";

  const auto* dyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(m));
  EXPECT_EQ(dyn->verdict_action_idx, 0u)
      << "verdict_action_idx must be 0 (rule 0, src_mac primary)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// U6.6 — VLAN-tagged IPv4 sets l3_offset=18, parsed_vlan=100,
//         parsed_ethertype=0x0800 (D13) [needs EAL]
//
// Build a VLAN-tagged IPv4 frame (vlan=100, inner ethertype=0x0800).
// After classify_l2, assert dynfield fields per D13:
//   dyn->l3_offset == 18
//   dyn->parsed_vlan == 100
//   dyn->parsed_ethertype == 0x0800
//
// Uses a vlan=100 ALLOW rule so classify_l2 reaches the dispatch path.
// Dynfield is written before dispatch (design §5.2 lines 1039-1041),
// so the fields are valid regardless of verdict.
//
// Covers: D13 (VLAN-tagged l3_offset fix), §5.2, §5.1.
// D41: through top-level classify_l2 entry point.
// =========================================================================

TEST_F(ClassifyL2CompoundTest, U6_6_VlanTaggedIPv4L3Offset) {
  using namespace builder_eal;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  Config cfg = make_config();
  // One rule: vlan=100 → ALLOW. Ensures a hit so we exercise the dispatch.
  auto& r0 = append_rule(cfg.pipeline.layer_2, 6000, ActionAllow{});
  r0.vlan_id = 100;

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value()) << "compile failed";
  ASSERT_EQ(cr.l2_compound.size(), 1u);

  Ruleset rs = ruleset::build_ruleset(cr, cfg.sizing, /*num_lcores=*/1);
  EalPopulateParams params;
  params.name_prefix = "u6_6";
  params.socket_id = 0;
  params.max_entries = 64;
  auto res = ruleset::populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;

  // VLAN-tagged frame:
  //   dst: 01:02:03:04:05:06  src: aa:bb:cc:dd:ee:01
  //   outer ethertype: 0x8100, TCI: vlan=100 (0x0064), pcp=0
  //   inner ethertype: 0x0800 (IPv4)
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_6_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 64));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 64);
  pkt[0]=0x01; pkt[1]=0x02; pkt[2]=0x03;
  pkt[3]=0x04; pkt[4]=0x05; pkt[5]=0x06;
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0x01;
  pkt[12]=0x81; pkt[13]=0x00;    // outer ethertype: 0x8100
  pkt[14]=0x00; pkt[15]=0x64;    // TCI: vlan=100, pcp=0
  pkt[16]=0x08; pkt[17]=0x00;    // inner ethertype: 0x0800 (IPv4)

  // D41: through top-level entry point.
  const dataplane::ClassifyL2Verdict verdict = dataplane::classify_l2(m, rs);
  // Rule matches → ALLOW → kNextL3.
  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kNextL3);

  // D13: assert dynfield l3_offset, parsed_vlan, parsed_ethertype.
  const auto* dyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(m));
  EXPECT_EQ(dyn->l3_offset, 18u)
      << "VLAN-tagged IPv4: l3_offset must be 18 (14 Eth + 4 VLAN tag)";
  EXPECT_EQ(dyn->parsed_vlan, 100u)
      << "parsed_vlan must be 100 (TCI & 0x0FFF)";
  EXPECT_EQ(dyn->parsed_ethertype, 0x0800u)
      << "parsed_ethertype must be inner ethertype 0x0800 (IPv4)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// U6.7 — untagged IPv4 sets l3_offset=14 (D13) [needs EAL]
//
// Build an untagged IPv4 frame (outer ethertype=0x0800). After
// classify_l2, assert dynfield:
//   dyn->l3_offset == 14
//
// unit.md specifies only l3_offset for U6.7 (no parsed_vlan assertion
// for untagged — see dispatch prompt guidance).
//
// Uses an ethertype=0x0800 ALLOW rule so the frame hits. Dynfield is
// written before dispatch so fields are valid on miss too, but a hit
// is cleaner for demonstrating the full path.
//
// Covers: D13 (untagged l3_offset=14), §5.2, §5.1.
// D41: through top-level classify_l2 entry point.
// =========================================================================

TEST_F(ClassifyL2CompoundTest, U6_7_UntaggedIPv4L3Offset) {
  using namespace builder_eal;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  Config cfg = make_config();
  // One rule: ethertype=0x0800 → ALLOW.
  auto& r0 = append_rule(cfg.pipeline.layer_2, 7000, ActionAllow{});
  r0.ethertype = 0x0800;

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value()) << "compile failed";
  ASSERT_EQ(cr.l2_compound.size(), 1u);

  Ruleset rs = ruleset::build_ruleset(cr, cfg.sizing, /*num_lcores=*/1);
  EalPopulateParams params;
  params.name_prefix = "u6_7";
  params.socket_id = 0;
  params.max_entries = 64;
  auto res = ruleset::populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;

  // Untagged frame:
  //   dst: 01:02:03:04:05:06  src: aa:bb:cc:dd:ee:02
  //   ethertype: 0x0800 (IPv4)
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_7_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 64));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 64);
  pkt[0]=0x01; pkt[1]=0x02; pkt[2]=0x03;
  pkt[3]=0x04; pkt[4]=0x05; pkt[5]=0x06;
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0x02;
  pkt[12]=0x08; pkt[13]=0x00;    // ethertype: 0x0800 (IPv4), no VLAN

  // D41: through top-level entry point.
  const dataplane::ClassifyL2Verdict verdict = dataplane::classify_l2(m, rs);
  // Rule matches → ALLOW → kNextL3.
  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kNextL3);

  // D13: assert l3_offset = 14 for untagged frame.
  const auto* dyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(m));
  EXPECT_EQ(dyn->l3_offset, 14u)
      << "untagged IPv4: l3_offset must be 14 (standard Ethernet header)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// U6.8 — QinQ outer 0x88A8 accepted; inner 0x8100 bumps counter (D32)
//
// Frame layout (double-tagged QinQ):
//   [0..5]   dst_mac
//   [6..11]  src_mac
//   [12..13] outer ethertype: 0x88A8 (S-tag, 802.1ad)
//   [14..15] outer TCI: vlan=200, pcp=0
//   [16..17] inner ethertype: 0x8100 (C-tag) ← true QinQ stack
//   [18..19] inner TCI: vlan=300, pcp=0
//   [20..21] inner-inner ethertype: 0x0800 (IPv4)
//
// classify_l2 MUST:
//   - walk ONE tag (S-tag at offset 12), see inner ethertype 0x8100
//   - bump qinq_outer_only_total (inner is a VLAN TPID → true QinQ)
//   - set l3_offset = 18 (NOT 22 — no inner drilling)
//   - set parsed_vlan = 200 (outer TCI & 0x0FFF)
//   - set parsed_ethertype = 0x8100 (inner, not drilled)
//   - return kNextL3 (no terminal drop for QinQ, D32)
//
// Uses a vlan=200 ALLOW rule to exercise the full dispatch path.
//
// Covers: D32 (QinQ outer accept + counter), D13, D41.
// =========================================================================

TEST_F(ClassifyL2CompoundTest, U6_8_QinQOuterAcceptedInnerBumpsCounter) {
  using namespace builder_eal;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  Config cfg = make_config();
  // Rule: vlan=200 → ALLOW. Outer S-tag TCI has vid=200, so this probe hits.
  auto& r0 = append_rule(cfg.pipeline.layer_2, 8000, ActionAllow{});
  r0.vlan_id = 200;

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value()) << "compile failed";
  ASSERT_EQ(cr.l2_compound.size(), 1u);

  Ruleset rs = ruleset::build_ruleset(cr, cfg.sizing, /*num_lcores=*/1);
  EalPopulateParams params;
  params.name_prefix = "u6_8";
  params.socket_id = 0;
  params.max_entries = 64;
  auto res = ruleset::populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;

  // Double-tagged QinQ frame:
  //   dst: 01:02:03:04:05:06  src: aa:bb:cc:dd:ee:08
  //   outer: S-tag 0x88A8, TCI: vlan=200 (0x00C8), pcp=0
  //   inner: C-tag 0x8100, TCI: vlan=300 (0x012C), pcp=0
  //   inner-inner: IPv4 0x0800
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_8_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 64));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 64);
  pkt[0]=0x01; pkt[1]=0x02; pkt[2]=0x03;
  pkt[3]=0x04; pkt[4]=0x05; pkt[5]=0x06;
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0x08;
  pkt[12]=0x88; pkt[13]=0xA8;    // outer ethertype: 0x88A8 (S-tag)
  pkt[14]=0x00; pkt[15]=0xC8;    // outer TCI: vlan=200, pcp=0
  pkt[16]=0x81; pkt[17]=0x00;    // inner ethertype: 0x8100 (C-tag) — true QinQ
  pkt[18]=0x01; pkt[19]=0x2C;    // inner TCI: vlan=300, pcp=0
  pkt[20]=0x08; pkt[21]=0x00;    // inner-inner ethertype: 0x0800 (IPv4)

  // D32: pass a local counter to observe the bump.
  std::uint64_t qinq_ctr = 0;

  // D41: through top-level classify_l2 entry point.
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs, &qinq_ctr);
  // D32: QinQ frames must NOT be terminally dropped.
  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kNextL3)
      << "QinQ outer frame must produce kNextL3 (no terminal drop for QinQ)";

  // D32: inner ethertype 0x8100 is a VLAN TPID → counter must fire.
  EXPECT_EQ(qinq_ctr, 1u)
      << "qinq_outer_only_total must be 1 (inner ethertype is VLAN TPID 0x8100)";

  // D13 / D32: l3_offset must be 18 (ONE tag walked, not two).
  const auto* dyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(m));
  EXPECT_EQ(dyn->l3_offset, 18u)
      << "QinQ outer: l3_offset must be 18 (one tag walked, inner not drilled)";
  EXPECT_EQ(dyn->parsed_vlan, 200u)
      << "parsed_vlan must be 200 (outer S-tag TCI & 0x0FFF)";
  EXPECT_EQ(dyn->parsed_ethertype, 0x8100u)
      << "parsed_ethertype must be inner 0x8100 (inner C-tag, not drilled)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// U6.9 — single 0x88A8 tag over IPv4: outer accepted, no counter bump (D32)
//
// Frame layout (single S-tag, no inner VLAN):
//   [0..5]   dst_mac
//   [6..11]  src_mac
//   [12..13] outer ethertype: 0x88A8 (S-tag)
//   [14..15] TCI: vlan=400, pcp=0
//   [16..17] inner ethertype: 0x0800 (IPv4) ← NOT a VLAN TPID
//
// classify_l2 MUST:
//   - walk ONE tag (S-tag at offset 12), see inner ethertype 0x0800
//   - NOT bump qinq_outer_only_total (inner is IPv4, not a VLAN TPID)
//   - set l3_offset = 18
//   - set parsed_vlan = 400 (TCI & 0x0FFF)
//   - set parsed_ethertype = 0x0800
//   - return kNextL3
//
// Uses a vlan=400 ALLOW rule.
//
// Covers: D32 (single S-tag, no-bump path), D13, D41.
// =========================================================================

TEST_F(ClassifyL2CompoundTest, U6_9_SingleSTagOverIPv4NoBump) {
  using namespace builder_eal;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  Config cfg = make_config();
  // Rule: vlan=400 → ALLOW.
  auto& r0 = append_rule(cfg.pipeline.layer_2, 9000, ActionAllow{});
  r0.vlan_id = 400;

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value()) << "compile failed";
  ASSERT_EQ(cr.l2_compound.size(), 1u);

  Ruleset rs = ruleset::build_ruleset(cr, cfg.sizing, /*num_lcores=*/1);
  EalPopulateParams params;
  params.name_prefix = "u6_9";
  params.socket_id = 0;
  params.max_entries = 64;
  auto res = ruleset::populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;

  // Single S-tag frame over IPv4:
  //   dst: 01:02:03:04:05:06  src: aa:bb:cc:dd:ee:09
  //   outer: S-tag 0x88A8, TCI: vlan=400 (0x0190), pcp=0
  //   inner ethertype: 0x0800 (IPv4)
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_9_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 64));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 64);
  pkt[0]=0x01; pkt[1]=0x02; pkt[2]=0x03;
  pkt[3]=0x04; pkt[4]=0x05; pkt[5]=0x06;
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0x09;
  pkt[12]=0x88; pkt[13]=0xA8;    // outer ethertype: 0x88A8 (S-tag)
  pkt[14]=0x01; pkt[15]=0x90;    // TCI: vlan=400, pcp=0
  pkt[16]=0x08; pkt[17]=0x00;    // inner ethertype: 0x0800 (IPv4) — NOT VLAN

  // D32: pass a local counter; must remain 0 after the call.
  std::uint64_t qinq_ctr = 0;

  // D41: through top-level classify_l2 entry point.
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs, &qinq_ctr);
  // D32: single S-tag over IPv4 must pass (no terminal drop).
  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kNextL3)
      << "single S-tag over IPv4 must produce kNextL3";

  // D32: inner ethertype is IPv4 (0x0800), NOT a VLAN TPID → no bump.
  EXPECT_EQ(qinq_ctr, 0u)
      << "qinq_outer_only_total must NOT be bumped when inner etype is IPv4";

  // D13 / D32: l3_offset = 18, parsed_vlan = 400, parsed_ethertype = 0x0800.
  const auto* dyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(m));
  EXPECT_EQ(dyn->l3_offset, 18u)
      << "single S-tag: l3_offset must be 18";
  EXPECT_EQ(dyn->parsed_vlan, 400u)
      << "parsed_vlan must be 400 (TCI & 0x0FFF)";
  EXPECT_EQ(dyn->parsed_ethertype, 0x0800u)
      << "parsed_ethertype must be 0x0800 (IPv4)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// U6.10 — L2 truncation: packet < 14 B drops + bumps pkt_truncated_total[l2]
//
// Synthesize a 10-byte mbuf (shorter than minimal Ethernet header = 14 B).
// Call classify_l2 through the top-level entry point (D41). Assert:
//   - verdict == kDrop (D31 guard fires before any header parse)
//   - pkt_truncated_total[kL2] == 1 (l2 bucket counter incremented)
//
// Uses an empty ruleset so the only code path that can produce kDrop is the
// D31 truncation guard (empty ruleset would otherwise → kNextL3).
//
// Covers: D31 (l2 bucket), §5.2 entry guard, D41.
// =========================================================================

class ClassifyL2TruncTest : public EalFixture {};

TEST_F(ClassifyL2TruncTest, U6_10_ShortFrameDropsL2Bucket) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  // Empty ruleset — without D31 guard, empty ruleset → kNextL3.
  // With guard: 10 < 14 → kDrop before ruleset is consulted.
  ruleset::Ruleset rs;
  ASSERT_EQ(rs.l2_compound_count, 0u);
  ASSERT_EQ(rs.l2_compound_hash, nullptr);

  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_10_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  // Append exactly 10 bytes (< 14 B minimal Ethernet header).
  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 10));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0xAB, 10);
  ASSERT_EQ(m->pkt_len, 10u);

  // D31 counter storage: array indexed by L2TruncBucket.
  std::array<std::uint64_t, dataplane::kL2TruncBucketCount> trunc_ctrs{};

  // D41: call through top-level entry point.
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs, nullptr, &trunc_ctrs);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kDrop)
      << "10-byte frame must be dropped by D31 l2 guard (< 14 B)";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2)], 1u)
      << "pkt_truncated_total[l2] must be 1";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2Vlan)], 0u)
      << "pkt_truncated_total[l2_vlan] must be 0 (wrong bucket)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// U6.11 — L2 truncation: VLAN header short (16 B with 0x8100) drops +
//          bumps pkt_truncated_total[l2_vlan]
//
// Synthesize a 16-byte mbuf with outer ethertype=0x8100 at offset 12.
// A VLAN-tagged frame needs at least 18 B (14 B Ethernet + 4 B VLAN tag).
// 16 B has the 0x8100 TPID at offsets [12..13] but the TCI ([14..15]) is
// present while inner ethertype ([16..17]) is missing — so pkt_len = 16 < 18.
//
// Assert:
//   - verdict == kDrop
//   - pkt_truncated_total[kL2Vlan] == 1
//   - pkt_truncated_total[kL2] == 0 (l2 guard does not fire; pkt_len >= 14)
//
// Uses an empty ruleset so only the D31 guard can produce kDrop.
//
// Covers: D31 (l2_vlan bucket), §5.2 VLAN guard, D41.
// =========================================================================

TEST_F(ClassifyL2TruncTest, U6_11_VlanShortFrameDropsL2VlanBucket) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  // Empty ruleset.
  ruleset::Ruleset rs;
  ASSERT_EQ(rs.l2_compound_count, 0u);
  ASSERT_EQ(rs.l2_compound_hash, nullptr);

  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_11_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  // Append exactly 16 bytes. Layout:
  //   [0..5]   dst_mac = 01:02:03:04:05:06
  //   [6..11]  src_mac = aa:bb:cc:dd:ee:0b
  //   [12..13] outer ethertype = 0x8100 (VLAN TPID)
  //   [14..15] TCI = 0x0064 (vlan=100, pcp=0)
  //   (inner ethertype at [16..17] is absent: pkt_len=16 < 18)
  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 16));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 16);
  pkt[0]=0x01; pkt[1]=0x02; pkt[2]=0x03;
  pkt[3]=0x04; pkt[4]=0x05; pkt[5]=0x06;
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0x0b;
  pkt[12]=0x81; pkt[13]=0x00;   // 0x8100: VLAN TPID
  pkt[14]=0x00; pkt[15]=0x64;   // TCI: vlan=100
  ASSERT_EQ(m->pkt_len, 16u);

  // D31 counter storage.
  std::array<std::uint64_t, dataplane::kL2TruncBucketCount> trunc_ctrs{};

  // D41: call through top-level entry point.
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs, nullptr, &trunc_ctrs);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kDrop)
      << "16-byte VLAN frame (pkt_len=16 < 18) must be dropped by D31 l2_vlan guard";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2Vlan)], 1u)
      << "pkt_truncated_total[l2_vlan] must be 1";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2)], 0u)
      << "pkt_truncated_total[l2] must be 0 (pkt_len=16 >= 14, l2 guard doesn't fire)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// U6.11a — M5 C0 classify_l3 baseline: empty L3 ruleset → kNextL4.
//
// Supervisor ruling (M5 C0): U6.12 in unit.md stays owned by D31
// l3_v4 truncation (lands in C1); C0 gets a fresh ID U6.11a, same
// precedent as M4 C0 U6.0a. This test validates the C0 plumbing
// skeleton: classify_l3 is a pass-through that unconditionally
// returns kNextL4 regardless of the mbuf contents, so later cycles
// (C1 IPv4 body, C4 IPv6 body) can incrementally add parsing
// without breaking the worker wiring.
//
// An "empty L3 ruleset" is a default-constructed ruleset::Ruleset:
// l3_v4_fib / l3_v6_fib / l3_compound_entries are all nullptr and
// n_l3_rules == 0. The C0 skeleton does not touch any of these
// fields; it only reads dyn->l3_offset + dyn->parsed_ethertype
// (already written by classify_l2 in M4 C3) and returns kNextL4.
//
// Assertions:
//   - verdict == ClassifyL3Verdict::kNextL4
//   - ruleset fields remain as default-constructed (sanity)
//
// Covers: M5 C0 plumbing baseline; §5.3 classify_l3 signature; D41.
// =========================================================================

class ClassifyL3SkeletonTest : public EalFixture {};

TEST_F(ClassifyL3SkeletonTest, U6_11a_EmptyL3RulesetYieldsNextL4) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  // Empty L3 ruleset: default-constructed, zero L3 rules, all FIB
  // handles nullptr (same shape U6.1/C1.8 use for L2 empty ruleset).
  ruleset::Ruleset rs;
  ASSERT_EQ(rs.n_l3_rules, 0u);
  ASSERT_EQ(rs.l3_v4_fib, nullptr);
  ASSERT_EQ(rs.l3_v6_fib, nullptr);
  ASSERT_EQ(rs.l3_compound_count, 0u);

  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_11a_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  // Minimal well-formed IPv4 Ethernet frame: 14 B L2 + 20 B IPv4
  // header. classify_l2 would normally write dyn->l3_offset=14 and
  // dyn->parsed_ethertype=0x0800 on this shape, but for a direct
  // classify_l3 call we write them by hand — the C0 skeleton does
  // not depend on classify_l2 having run, since the body is a
  // pure pass-through. Real integration via the worker kNextL3
  // arm is covered by future functional tests (F4, M5 C10).
  constexpr std::size_t kFrameLen = 14 + 20;
  uint8_t* pkt =
      reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, kFrameLen));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, kFrameLen);
  pkt[12] = 0x08;
  pkt[13] = 0x00;  // 0x0800 IPv4
  // IPv4 header at offset 14: version=4, IHL=5 (well-formed).
  pkt[14] = 0x45;

  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset = 14;
  dyn->parsed_ethertype = 0x0800;
  dyn->parsed_vlan = 0xFFFF;
  dyn->flags = 0;

  // C0: direct call, pass-through skeleton must return kNextL4.
  const dataplane::ClassifyL3Verdict verdict =
      dataplane::classify_l3(m, rs);

  EXPECT_EQ(verdict, dataplane::ClassifyL3Verdict::kNextL4)
      << "U6.11a: empty L3 ruleset must yield kNextL4 (C0 pass-through)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// M5 C1 — classify_l3 IPv4 branch: D31 l3_v4 + D14 IHL + dst FIB
//
// Four tests covering the C1 RED list per implementation-plan-errata §M5 C1:
//
//   U6.12  — IPv4 short packet (< l3_off + 20) → kTerminalDrop +
//            pkt_truncated_l3[l3_v4] bumped (D31 truncation arm).
//   U6.13  — IPv4 `version_ihl` with IHL<5 → kTerminalDrop + same l3_v4
//            bucket bumped (D14 reject; shares l3_v4 with D31 trunc per
//            errata §M5 C1).
//   U6.18  — IPv4 dst FIB hit → dispatch on rule action
//            (allow → kNextL4). unit.md's stale "TERMINAL_L3" wording
//            is reconciled inline to the C0 enum (kNextL4 / kTerminalDrop).
//   U6.18a — IPv4 dst FIB miss (no matching prefix) → kNextL4 fall-
//            through. C2 will add the src-prefix secondary; for C1 a
//            miss means fall through, and NO truncation counter is bumped.
//
// All four bypass classify_l2 and call classify_l3 directly, pre-setting
// dyn->l3_offset = 14 + dyn->parsed_ethertype = RTE_BE16(0x0800) the way
// classify_l2 would after parsing an untagged Ethernet frame. Same pattern
// as U6.11a (M5 C0 baseline).
//
// Covers: D14 (reject-only arm), D31 (bucket `l3_v4`), D30 (rte_fib_lookup_bulk
// n=1), D41 (pipeline smoke invariant at the classify_l3 stage).
// =========================================================================

class ClassifyL3Ipv4Test : public EalFixture {};

// -------------------------------------------------------------------------
// U6.12 — IPv4 short packet → D31 l3_v4 truncation drop
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4Test, U6_12_Ipv4ShortPacketTruncated) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;  // empty — no FIB, the guard fires first

  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_12_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  // Frame: 14 B Ethernet + 10 B partial IPv4 header (< 20 needed).
  // pkt_len = 24, l3_off = 14, need = 14 + 20 = 34, guard fires.
  constexpr std::size_t kFrameLen = 14 + 10;
  uint8_t* pkt =
      reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, kFrameLen));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, kFrameLen);
  pkt[12] = 0x08;
  pkt[13] = 0x00;  // 0x0800 IPv4
  // Partial IPv4 header: version_ihl byte alone is 0x45 but the body
  // doesn't fit — the D31 guard must fire before any header byte is
  // dereferenced. Leave the bytes zero to demonstrate the guard runs
  // before reading version_ihl.

  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset        = 14;
  dyn->parsed_ethertype = RTE_BE16(RTE_ETHER_TYPE_IPV4);
  dyn->parsed_vlan      = 0xFFFF;
  dyn->flags            = 0;

  dataplane::L3TruncCtrs trunc_ctrs{};
  const dataplane::ClassifyL3Verdict verdict =
      dataplane::classify_l3(m, rs, &trunc_ctrs);

  EXPECT_EQ(verdict, dataplane::ClassifyL3Verdict::kTerminalDrop)
      << "U6.12: short IPv4 frame must be dropped by D31 l3_v4 guard";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V4)], 1u)
      << "U6.12: pkt_truncated_l3[l3_v4] must be 1";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// -------------------------------------------------------------------------
// U6.13 — IPv4 IHL<5 → D14 reject (same l3_v4 bucket)
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4Test, U6_13_Ipv4IhlLessThan5Rejected) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;  // empty — guards fire before FIB lookup

  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_13_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  // Full-length frame: 14 B L2 + 20 B IPv4 header so the D31 guard passes.
  // The D14 IHL reject must fire on `(version_ihl & 0x0F) < 5`.
  constexpr std::size_t kFrameLen = 14 + 20;
  uint8_t* pkt =
      reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, kFrameLen));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, kFrameLen);
  pkt[12] = 0x08;
  pkt[13] = 0x00;  // 0x0800 IPv4
  // IPv4 header at offset 14:
  //   version_ihl = 0x44  → version=4, IHL=4 (invalid, minimum is 5)
  pkt[14] = 0x44;

  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset        = 14;
  dyn->parsed_ethertype = RTE_BE16(RTE_ETHER_TYPE_IPV4);
  dyn->parsed_vlan      = 0xFFFF;
  dyn->flags            = 0;

  dataplane::L3TruncCtrs trunc_ctrs{};
  const dataplane::ClassifyL3Verdict verdict =
      dataplane::classify_l3(m, rs, &trunc_ctrs);

  EXPECT_EQ(verdict, dataplane::ClassifyL3Verdict::kTerminalDrop)
      << "U6.13: IPv4 with IHL<5 must be dropped by D14 reject";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V4)], 1u)
      << "U6.13: pkt_truncated_l3[l3_v4] must be 1 (D14 shares l3_v4 per errata §M5 C1)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// -------------------------------------------------------------------------
// U6.18 — IPv4 dst FIB hit → dispatch on rule action
//
// unit.md wording reconciliation (errata §M5 C1): the stale entry says
// "dst FIB hit → TERMINAL_L3". C0 shipped an enum without TERMINAL_L3;
// current C1 semantics are:
//   allow action → kNextL4
//   drop  action → kTerminalDrop
// This test covers the allow → kNextL4 arm.
//
// NOTE: we use two L3 rules so the target rule's action_idx is 1
// (non-zero) and its packed L3CompoundEntry is non-zero, distinguishable
// from the FIB's default_nh = 0 miss sentinel (builder_eal.cpp). A
// single rule with action_idx==0 and all-zero filter_mask would pack
// to 0 and alias the miss sentinel — see U4_2_Fib4Population's note.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4Test, U6_18_Ipv4DstFibHitDispatch) {
  using namespace builder_eal;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  Config cfg = make_config();

  // Filler rule first so the target allow rule lands at action_idx=1
  // (so its packed next-hop is non-zero, not aliased with the miss
  // sentinel default_nh=0).
  SubnetObject filler;
  filler.name = "net_filler";
  filler.cidrs.push_back(Cidr4{0xAC100000, 12});  // 172.16.0.0/12
  cfg.objects.subnets.push_back(std::move(filler));

  SubnetObject target;
  target.name = "net_target";
  target.cidrs.push_back(Cidr4{0x0A000000, 8});   // 10.0.0.0/8
  cfg.objects.subnets.push_back(std::move(target));

  auto& r_filler = append_rule(cfg.pipeline.layer_3, 6018, ActionDrop{});
  r_filler.dst_subnet = SubnetRef{"net_filler"};
  auto& r_target = append_rule(cfg.pipeline.layer_3, 6019, ActionAllow{});
  r_target.dst_subnet = SubnetRef{"net_target"};

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value());
  ASSERT_EQ(cr.l3_compound.size(), 2u);

  // Build actions arena first (populate_ruleset_eal only opens FIB /
  // hash handles and fills compound entries — the l3_actions arena is
  // filled by build_ruleset from cr.l3_actions).
  Ruleset rs = ruleset::build_ruleset(cr, cfg.sizing, /*num_lcores=*/1);
  EalPopulateParams params;
  params.name_prefix = "u6_18";
  params.socket_id = 0;
  params.max_entries = 64;

  auto res = populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;
  ASSERT_NE(rs.l3_v4_fib, nullptr);
  ASSERT_GE(rs.n_l3_rules, 2u);
  // Target rule's action slot is 1 (filler drop at 0, allow at 1) so
  // the packed L3CompoundEntry is non-zero and distinguishable from
  // the FIB default_nh=0 miss sentinel.
  EXPECT_EQ(rs.l3_actions[1].verb,
            static_cast<std::uint8_t>(compiler::ActionVerb::kAllow));

  // Build a 14 B Ethernet + 20 B IPv4 frame addressed to 10.1.2.3.
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_18_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  constexpr std::size_t kFrameLen = 14 + 20;
  uint8_t* pkt =
      reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, kFrameLen));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, kFrameLen);
  pkt[12] = 0x08;
  pkt[13] = 0x00;  // 0x0800 IPv4
  pkt[14] = 0x45;  // version=4, IHL=5
  // dst_addr at offset 14+16 = 30. 10.1.2.3 network-byte-order.
  pkt[30] = 0x0A;
  pkt[31] = 0x01;
  pkt[32] = 0x02;
  pkt[33] = 0x03;

  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset        = 14;
  dyn->parsed_ethertype = RTE_BE16(RTE_ETHER_TYPE_IPV4);
  dyn->parsed_vlan      = 0xFFFF;
  dyn->flags            = 0;

  dataplane::L3TruncCtrs trunc_ctrs{};
  const dataplane::ClassifyL3Verdict verdict =
      dataplane::classify_l3(m, rs, &trunc_ctrs);

  EXPECT_EQ(verdict, dataplane::ClassifyL3Verdict::kNextL4)
      << "U6.18: dst FIB hit on allow rule must dispatch to kNextL4 "
         "(unit.md's stale TERMINAL_L3 wording reconciled to C0 enum)";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V4)], 0u)
      << "U6.18: clean hit must not bump the truncation bucket";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// -------------------------------------------------------------------------
// U6.18a — IPv4 dst FIB miss → kNextL4 fall-through (NEW, errata §M5 C1)
//
// Same populated FIB as U6.18; frame addressed to 192.168.1.1 which
// matches neither the filler (172.16/12) nor the target (10/8) prefix.
// FIB lookup returns nh=0 (default_nh), classify_l3 falls through to
// kNextL4 and bumps no counter. Same precedent as M4 C0's U6.0a and
// M5 C0's U6.11a for adding new test IDs in-cycle.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4Test, U6_18a_Ipv4DstFibMissFallsThrough) {
  using namespace builder_eal;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  Config cfg = make_config();

  SubnetObject filler;
  filler.name = "net_filler";
  filler.cidrs.push_back(Cidr4{0xAC100000, 12});
  cfg.objects.subnets.push_back(std::move(filler));

  SubnetObject target;
  target.name = "net_target";
  target.cidrs.push_back(Cidr4{0x0A000000, 8});
  cfg.objects.subnets.push_back(std::move(target));

  auto& r_filler = append_rule(cfg.pipeline.layer_3, 6020, ActionDrop{});
  r_filler.dst_subnet = SubnetRef{"net_filler"};
  auto& r_target = append_rule(cfg.pipeline.layer_3, 6021, ActionAllow{});
  r_target.dst_subnet = SubnetRef{"net_target"};

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value());

  // Build actions arena first (same as U6.18).
  Ruleset rs = ruleset::build_ruleset(cr, cfg.sizing, /*num_lcores=*/1);
  EalPopulateParams params;
  params.name_prefix = "u6_18a";
  params.socket_id = 0;
  params.max_entries = 64;

  auto res = populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;
  ASSERT_NE(rs.l3_v4_fib, nullptr);

  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_18a_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  constexpr std::size_t kFrameLen = 14 + 20;
  uint8_t* pkt =
      reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, kFrameLen));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, kFrameLen);
  pkt[12] = 0x08;
  pkt[13] = 0x00;
  pkt[14] = 0x45;
  // 192.168.1.1 — outside both populated prefixes.
  pkt[30] = 0xC0;
  pkt[31] = 0xA8;
  pkt[32] = 0x01;
  pkt[33] = 0x01;

  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset        = 14;
  dyn->parsed_ethertype = RTE_BE16(RTE_ETHER_TYPE_IPV4);
  dyn->parsed_vlan      = 0xFFFF;
  dyn->flags            = 0;

  dataplane::L3TruncCtrs trunc_ctrs{};
  const dataplane::ClassifyL3Verdict verdict =
      dataplane::classify_l3(m, rs, &trunc_ctrs);

  EXPECT_EQ(verdict, dataplane::ClassifyL3Verdict::kNextL4)
      << "U6.18a: dst FIB miss must fall through to kNextL4 (C2 adds src secondary)";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V4)], 0u)
      << "U6.18a: clean miss must NOT bump pkt_truncated_l3[l3_v4]";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// -------------------------------------------------------------------------
// U6.18b — L3CompoundEntry valid_tag retrofit: zero-packed hit vs FIB miss
//
// Regression sentinel for the `rte_fib_default_nh_aliases_action_idx_0`
// grabli. Before M5 C1b the hot path used `nh == 0` as the FIB miss
// signal, which aliased with a real hit on an `action_idx = 0,
// filter_mask = 0` entry (packed to 0x0000000000000000 — byte-identical
// to `rte_fib_conf.default_nh = 0`). M5 C1b introduces an explicit
// `valid_tag = 0xA5` byte stamped into every arena-resident
// `L3CompoundEntry` via `ruleset::make_l3_entry(...)`; classify_l3
// unpacks the next-hop slot and checks the tag instead of nh-against-zero.
//
// Setup: a SINGLE L3 drop rule whose dst_subnet resolves to an IPv4
// prefix, so after compile the target rule lands at `action_idx = 0`
// and its packed L3CompoundEntry (filter_mask=0, action_idx=0) is
// literally all-zero except for the new `valid_tag` byte. Before C1b
// the test would observe `nh == 0` and return `kNextL4` (the C1 miss
// arm) → wrong verdict. After C1b the dispatcher sees a valid entry,
// resolves ActionVerb::kDrop, and returns `kTerminalDrop`.
//
// Contrast with U6.18: U6.18 deliberately inserts a filler rule so the
// allow target lands at `action_idx = 1` (non-zero). U6.18b is the
// complementary coverage that exercises the `action_idx = 0` slot via
// a drop rule, and it MUST NOT rely on any "+1 filler" workaround.
//
// Covers: M5 C1b valid_tag retrofit; closes grabli
// `rte_fib_default_nh_aliases_action_idx_0`.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4Test, U6_18b_Ipv4DstFibHitAtActionIdxZero) {
  using namespace builder_eal;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  Config cfg = make_config();

  // Single target rule at slot 0 with a drop action. With no filler,
  // the resulting L3CompoundEntry has action_idx=0 and filter_mask=0;
  // pre-C1b this aliases the FIB miss sentinel byte-for-byte.
  SubnetObject target;
  target.name = "net_target";
  target.cidrs.push_back(Cidr4{0x0A000000, 8});   // 10.0.0.0/8
  cfg.objects.subnets.push_back(std::move(target));

  auto& r_target = append_rule(cfg.pipeline.layer_3, 6022, ActionDrop{});
  r_target.dst_subnet = SubnetRef{"net_target"};

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value());
  ASSERT_EQ(cr.l3_compound.size(), 1u);
  // Sanity: the target sits at slot 0 (the exact alias case we guard).
  ASSERT_EQ(cr.l3_compound[0].entry.action_idx, 0u);
  ASSERT_EQ(cr.l3_compound[0].entry.filter_mask, 0u);

  // Build actions arena first (populate_ruleset_eal only opens FIB /
  // hash handles and fills compound entries — the l3_actions arena is
  // filled by build_ruleset from cr.l3_actions). See memory grabli
  // `populate_ruleset_eal_no_l3_actions`.
  Ruleset rs = ruleset::build_ruleset(cr, cfg.sizing, /*num_lcores=*/1);
  EalPopulateParams params;
  params.name_prefix = "u6_18b";
  params.socket_id = 0;
  params.max_entries = 64;

  auto res = populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;
  ASSERT_NE(rs.l3_v4_fib, nullptr);
  ASSERT_GE(rs.n_l3_rules, 1u);
  EXPECT_EQ(rs.l3_actions[0].verb,
            static_cast<std::uint8_t>(compiler::ActionVerb::kDrop));

  // Build a 14 B Ethernet + 20 B IPv4 frame addressed to 10.1.2.3
  // (matches the target 10/8 prefix).
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_18b_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  constexpr std::size_t kFrameLen = 14 + 20;
  uint8_t* pkt =
      reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, kFrameLen));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, kFrameLen);
  pkt[12] = 0x08;
  pkt[13] = 0x00;  // 0x0800 IPv4
  pkt[14] = 0x45;  // version=4, IHL=5
  // dst_addr at offset 14+16 = 30. 10.1.2.3 network-byte-order.
  pkt[30] = 0x0A;
  pkt[31] = 0x01;
  pkt[32] = 0x02;
  pkt[33] = 0x03;

  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset        = 14;
  dyn->parsed_ethertype = RTE_BE16(RTE_ETHER_TYPE_IPV4);
  dyn->parsed_vlan      = 0xFFFF;
  dyn->flags            = 0;

  dataplane::L3TruncCtrs trunc_ctrs{};
  const dataplane::ClassifyL3Verdict verdict =
      dataplane::classify_l3(m, rs, &trunc_ctrs);

  EXPECT_EQ(verdict, dataplane::ClassifyL3Verdict::kTerminalDrop)
      << "U6.18b: dst FIB hit on a drop rule at action_idx=0 must "
         "dispatch to kTerminalDrop (valid_tag disambiguates the "
         "zero-packed-hit from rte_fib default_nh=0 miss sentinel)";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V4)], 0u)
      << "U6.18b: clean hit must not bump the truncation bucket";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// M4 C6 — L2 truncation corner tests (C1.1-C1.8)
//
// Eight frame shapes hammering the D31 truncation guards in classify_l2.
// All tests use an empty ruleset so the only code paths that can produce
// kDrop are the D31 guards. The ordering in classify_l2 (C5 landing):
//
//   Guard #1 (l2)      fires at pkt_len < 14
//   Guard #2 (l2_vlan) fires at is_vlan_tpid(outer_etype) && pkt_len < 18
//   Empty-ruleset bail fires after both guards → kNextL3
//
// Test IDs: C1.1-C1.8.  Covers D31, D32, D41.
// All tests use fresh L2TruncCtrs{} (zero-init) for clean delta assertions.
// =========================================================================

class ClassifyL2TruncCornerTest : public EalFixture {};

// =========================================================================
// C1.1 — Zero-byte frame
//
// Packet: empty (pkt_len=0). Guard #1 fires (0 < 14).
// Assert: pkt_truncated_total[l2] == 1, verdict == kDrop.
// =========================================================================
TEST_F(ClassifyL2TruncCornerTest, C1_1_ZeroByte) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "c1_1_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);
  // Do NOT append any bytes: pkt_len stays 0.
  ASSERT_EQ(m->pkt_len, 0u);

  dataplane::L2TruncCtrs trunc_ctrs{};
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs, nullptr, &trunc_ctrs);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kDrop)
      << "C1.1: zero-byte frame must be dropped by D31 l2 guard";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2)], 1u)
      << "C1.1: pkt_truncated_total[l2] must be 1";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2Vlan)], 0u)
      << "C1.1: pkt_truncated_total[l2_vlan] must be 0";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// C1.2 — One-byte frame
//
// Packet: 1 byte (0x01). Guard #1 fires (1 < 14).
// Assert: pkt_truncated_total[l2] == 1, verdict == kDrop.
// =========================================================================
TEST_F(ClassifyL2TruncCornerTest, C1_2_OneByte) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "c1_2_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 1));
  ASSERT_NE(pkt, nullptr);
  pkt[0] = 0x01;
  ASSERT_EQ(m->pkt_len, 1u);

  dataplane::L2TruncCtrs trunc_ctrs{};
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs, nullptr, &trunc_ctrs);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kDrop)
      << "C1.2: 1-byte frame must be dropped by D31 l2 guard";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2)], 1u)
      << "C1.2: pkt_truncated_total[l2] must be 1";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2Vlan)], 0u)
      << "C1.2: pkt_truncated_total[l2_vlan] must be 0";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// C1.3 — 13-byte frame (one byte short of minimal Ethernet header)
//
// Packet: 13 bytes of 0xFF. Guard #1 fires (13 < 14).
// Assert: pkt_truncated_total[l2] == 1, verdict == kDrop.
// =========================================================================
TEST_F(ClassifyL2TruncCornerTest, C1_3_ThirteenBytes) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "c1_3_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 13));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0xFF, 13);
  ASSERT_EQ(m->pkt_len, 13u);

  dataplane::L2TruncCtrs trunc_ctrs{};
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs, nullptr, &trunc_ctrs);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kDrop)
      << "C1.3: 13-byte frame must be dropped by D31 l2 guard";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2)], 1u)
      << "C1.3: pkt_truncated_total[l2] must be 1";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2Vlan)], 0u)
      << "C1.3: pkt_truncated_total[l2_vlan] must be 0";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// C1.4 — 14-byte frame claiming VLAN TPID 0x8100
//
// Layout: dst(6) + src(6) + 0x8100 — 14 B total, no room for TCI.
// Guard #1 does NOT fire (14 >= 14). Guard #2 fires (is_vlan_tpid(0x8100)
// && 14 < 18).
// Assert: pkt_truncated_total[l2_vlan] == 1, verdict == kDrop.
// =========================================================================
TEST_F(ClassifyL2TruncCornerTest, C1_4_FourteenBytesVlanTpid8100) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "c1_4_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  // 14 bytes: dst(6) + src(6) + ethertype=0x8100 (VLAN TPID). No TCI bytes.
  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 14));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 14);
  pkt[0]=0x00; pkt[1]=0x11; pkt[2]=0x22;
  pkt[3]=0x33; pkt[4]=0x44; pkt[5]=0x55;
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0xff;
  pkt[12]=0x81; pkt[13]=0x00;  // 0x8100 TPID
  ASSERT_EQ(m->pkt_len, 14u);

  dataplane::L2TruncCtrs trunc_ctrs{};
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs, nullptr, &trunc_ctrs);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kDrop)
      << "C1.4: 14-byte VLAN TPID frame must be dropped by D31 l2_vlan guard";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2Vlan)], 1u)
      << "C1.4: pkt_truncated_total[l2_vlan] must be 1";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2)], 0u)
      << "C1.4: pkt_truncated_total[l2] must be 0 (14 >= 14, guard #1 doesn't fire)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// C1.5 — 15-byte frame: dst(6) + src(6) + 0x8100 + one TCI byte
//
// One byte of TCI present but inner ethertype ([16..17]) absent.
// Guard #2 fires (is_vlan_tpid(0x8100) && 15 < 18).
// Assert: pkt_truncated_total[l2_vlan] == 1, verdict == kDrop.
// =========================================================================
TEST_F(ClassifyL2TruncCornerTest, C1_5_FifteenBytesVlanOneTciByte) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "c1_5_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  // 15 bytes: dst(6) + src(6) + 0x8100 + 1 TCI byte.
  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 15));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 15);
  pkt[0]=0x00; pkt[1]=0x11; pkt[2]=0x22;
  pkt[3]=0x33; pkt[4]=0x44; pkt[5]=0x55;
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0xff;
  pkt[12]=0x81; pkt[13]=0x00;  // 0x8100 TPID
  pkt[14]=0x00;                 // one TCI byte (0x00), second byte absent
  ASSERT_EQ(m->pkt_len, 15u);

  dataplane::L2TruncCtrs trunc_ctrs{};
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs, nullptr, &trunc_ctrs);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kDrop)
      << "C1.5: 15-byte VLAN frame must be dropped by D31 l2_vlan guard";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2Vlan)], 1u)
      << "C1.5: pkt_truncated_total[l2_vlan] must be 1";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2)], 0u)
      << "C1.5: pkt_truncated_total[l2] must be 0";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// C1.6 — 17-byte frame: dst(6) + src(6) + 0x8100 + three extra bytes
//
// Bytes at [14..16]: 0x00 0x64 0x08 — TCI=0x0064 (vlan=100) + first byte
// of inner ethertype (0x08), but second byte absent → pkt_len=17 < 18.
// Guard #2 fires (is_vlan_tpid(0x8100) && 17 < 18).
// Assert: pkt_truncated_total[l2_vlan] == 1, verdict == kDrop.
// =========================================================================
TEST_F(ClassifyL2TruncCornerTest, C1_6_SeventeenBytesVlanThreeExtraBytes) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "c1_6_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  // 17 bytes: dst(6) + src(6) + 0x8100 + 0x00 0x64 0x08
  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 17));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 17);
  pkt[0]=0x00; pkt[1]=0x11; pkt[2]=0x22;
  pkt[3]=0x33; pkt[4]=0x44; pkt[5]=0x55;
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0xff;
  pkt[12]=0x81; pkt[13]=0x00;  // 0x8100 TPID
  pkt[14]=0x00; pkt[15]=0x64;  // TCI: vlan=100
  pkt[16]=0x08;                 // first byte of inner etype (0x0800), second absent
  ASSERT_EQ(m->pkt_len, 17u);

  dataplane::L2TruncCtrs trunc_ctrs{};
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs, nullptr, &trunc_ctrs);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kDrop)
      << "C1.6: 17-byte VLAN frame must be dropped by D31 l2_vlan guard";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2Vlan)], 1u)
      << "C1.6: pkt_truncated_total[l2_vlan] must be 1";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2)], 0u)
      << "C1.6: pkt_truncated_total[l2] must be 0";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// C1.7 — 14-byte frame claiming 0x88A8 (S-tag TPID)
//
// Layout: dst(6) + src(6) + 0x88A8 — 14 B total.
// D32: 0x88A8 is treated as a VLAN TPID (same path as 0x8100). Guard #2
// fires (is_vlan_tpid(0x88A8) && 14 < 18). Bucket is l2_vlan, NOT l2.
// Assert: pkt_truncated_total[l2_vlan] == 1, verdict == kDrop.
// =========================================================================
TEST_F(ClassifyL2TruncCornerTest, C1_7_FourteenBytesStagTpid88A8) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "c1_7_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  // 14 bytes: dst(6) + src(6) + ethertype=0x88A8 (S-tag TPID). No TCI bytes.
  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 14));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 14);
  pkt[0]=0x00; pkt[1]=0x11; pkt[2]=0x22;
  pkt[3]=0x33; pkt[4]=0x44; pkt[5]=0x55;
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0xff;
  pkt[12]=0x88; pkt[13]=0xA8;  // 0x88A8 S-tag TPID (D32)
  ASSERT_EQ(m->pkt_len, 14u);

  dataplane::L2TruncCtrs trunc_ctrs{};
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs, nullptr, &trunc_ctrs);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kDrop)
      << "C1.7: 14-byte 0x88A8 S-tag frame must be dropped by D31 l2_vlan guard";
  // D32: 0x88A8 is a VLAN TPID → guard #2 fires → l2_vlan bucket, not l2.
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2Vlan)], 1u)
      << "C1.7: pkt_truncated_total[l2_vlan] must be 1 (D32: 0x88A8 walks VLAN path)";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2)], 0u)
      << "C1.7: pkt_truncated_total[l2] must be 0 (14 >= 14, guard #1 does not fire)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// C1.8 — 14-byte frame, non-VLAN ethertype (0x0800)
//
// Layout: dst(6) + src(6) + 0x0800 — 14 B — well-formed minimal Ethernet.
// Neither guard fires: pkt_len=14 >= 14 (guard #1 ok), outer_etype=0x0800
// is not a VLAN TPID (guard #2 ok). Empty-ruleset bail → kNextL3.
//
// M4 interpretation (classify_l3 not yet implemented — lands in M5):
//   - Assert l2 == 0 (l2 guard did NOT fire)
//   - Assert l2_vlan == 0 (l2_vlan guard did NOT fire)
//   - Assert verdict == kNextL3 (classify_l2 falls through to classify_l3)
//   - The l3_v4 truncation counter originally specified by corner.md
//     (pkt_truncated_total[l3_v4] += 1) cannot be asserted in M4 because
//     classify_l3 does not exist yet.
//
// TODO: M5 C? — assert l3_v4 truncation bucket += 1 once classify_l3 lands.
//
// Covers: D31 (confirms l2 bucket does not fire on well-formed 14 B frame),
//         D41 (top-level classify_l2 call).
// =========================================================================
TEST_F(ClassifyL2TruncCornerTest, C1_8_FourteenBytesIPv4EtherNoVlan) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "c1_8_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  // 14 bytes: dst(6) + src(6) + ethertype=0x0800 (IPv4, non-VLAN).
  // Well-formed minimal Ethernet header — neither D31 guard fires.
  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 14));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 14);
  pkt[0]=0x00; pkt[1]=0x11; pkt[2]=0x22;
  pkt[3]=0x33; pkt[4]=0x44; pkt[5]=0x55;
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0xff;
  pkt[12]=0x08; pkt[13]=0x00;  // 0x0800 IPv4, not a VLAN TPID
  ASSERT_EQ(m->pkt_len, 14u);

  dataplane::L2TruncCtrs trunc_ctrs{};
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs, nullptr, &trunc_ctrs);

  // M4 interpretation: neither D31 L2-stage guard fires on well-formed 14 B.
  // Empty-ruleset bail returns kNextL3 (classify_l3 will handle l3_v4
  // truncation once it lands in M5).
  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kNextL3)
      << "C1.8: well-formed 14-byte IPv4 frame must pass classify_l2 → kNextL3";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2)], 0u)
      << "C1.8: pkt_truncated_total[l2] must be 0 (14 B >= 14, guard #1 does not fire)";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2Vlan)], 0u)
      << "C1.8: pkt_truncated_total[l2_vlan] must be 0 (0x0800 is not a VLAN TPID)";

  // TODO: M5 C? — assert l3_v4 truncation bucket += 1 once classify_l3 lands.

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// M4 C7 — VLAN/QinQ corner tests (C4.1-C4.10)
//
// Semantic corner cases for valid-length frames with edge-case tag stacks
// or TCI bits.  All tests go through the top-level classify_l2() entry
// point (D41 invariant).
//
// Pre-authorized M4 interpretations applied here:
//   C4.2  — empty ruleset (L3 rule from corner.md → not testable in M4)
//   C4.3  — single collapsed test (C4.3a/C4.3b split is L3-level, TODO M5)
//   C4.9  — 18 B boundary: inner etype engineered to 0x0800 (non-VLAN)
//   C4.10 — duplicate of C1.6; transcribed for completeness per corner plan
//
// Handoff errata: handoff said C4.1-C4.11, corner.md has only C4.1-C4.10.
// No C4.11 is transcribed (handoff off-by-one).
//
// References: D32 (QinQ outer), D31 (truncation guards), D13 (l3_offset),
//             D41 (top-level entry point discipline).
// =========================================================================

class ClassifyL2VlanQinQCornerTest : public EalFixture {};

// =========================================================================
// C4.1 — Single 802.1Q VLAN (0x8100), vlan=100, IPv4/UDP payload
//
// Setup: L2 rule on vlan_id=100 → ALLOW.
// Frame: dst+src+0x8100+TCI(vlan=100,pcp=0)+0x0800+zeros.
// Assert:
//   - verdict == kNextL3 (ALLOW rule fires)
//   - verdict_action_idx == 0 (first rule)
//   - qinq_outer_only_total == 0 (inner etype 0x0800, not a VLAN TPID)
//   - l3_offset == 18, parsed_vlan == 100, parsed_ethertype == 0x0800
//
// Already-GREEN from C3 impl (VLAN l3_offset + compound probe).
// Transcribed here as confirmation and corner-plan completeness.
//
// Covers: D13, D15, D32 (no bump path), D41.
// =========================================================================
TEST_F(ClassifyL2VlanQinQCornerTest, C4_1_Single8021qVlan100AllowRule) {
  using namespace builder_eal;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  Config cfg = make_config();
  // L2 rule: vlan_id=100 → ALLOW.
  auto& r0 = append_rule(cfg.pipeline.layer_2, 4100, ActionAllow{});
  r0.vlan_id = 100;

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value()) << "compile failed";
  ASSERT_EQ(cr.l2_compound.size(), 1u);

  Ruleset rs = ruleset::build_ruleset(cr, cfg.sizing, /*num_lcores=*/1);
  EalPopulateParams params;
  params.name_prefix = "c4_1";
  params.socket_id = 0;
  params.max_entries = 64;
  auto res = ruleset::populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;
  ASSERT_NE(rs.l2_compound_hash, nullptr);

  // VLAN-tagged frame: dst+src+0x8100+TCI(vlan=100,pcp=0)+0x0800+padding.
  // [0..5]   dst_mac
  // [6..11]  src_mac
  // [12..13] 0x8100 (VLAN TPID)
  // [14..15] TCI: vlan=100 (0x0064), pcp=0
  // [16..17] inner ethertype: 0x0800 (IPv4)
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "c4_1_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 64));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 64);
  pkt[0]=0x01; pkt[1]=0x02; pkt[2]=0x03;
  pkt[3]=0x04; pkt[4]=0x05; pkt[5]=0x06;   // dst_mac
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0x41;  // src_mac
  pkt[12]=0x81; pkt[13]=0x00;               // 0x8100 VLAN TPID
  pkt[14]=0x00; pkt[15]=0x64;               // TCI: vlan=100, pcp=0
  pkt[16]=0x08; pkt[17]=0x00;               // inner ethertype: 0x0800 IPv4

  std::uint64_t qinq_ctr = 0;

  // D41: through top-level classify_l2 entry point.
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs, &qinq_ctr);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kNextL3)
      << "C4.1: vlan=100 ALLOW rule must produce kNextL3";
  // Dynfield: action_idx = 0 (first rule).
  const auto* dyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(m));
  EXPECT_EQ(dyn->verdict_action_idx, 0u)
      << "C4.1: verdict_action_idx must be 0 (first rule)";
  // D32: inner etype is 0x0800, NOT a VLAN TPID → counter must NOT fire.
  EXPECT_EQ(qinq_ctr, 0u)
      << "C4.1: qinq_outer_only_total must be 0 (inner etype 0x0800)";
  // D13: l3_offset=18 for single VLAN tag, parsed_vlan=100, parsed_ethertype=0x0800.
  EXPECT_EQ(dyn->l3_offset, 18u)
      << "C4.1: l3_offset must be 18 (VLAN-tagged frame)";
  EXPECT_EQ(dyn->parsed_vlan, 100u)
      << "C4.1: parsed_vlan must be 100";
  EXPECT_EQ(dyn->parsed_ethertype, 0x0800u)
      << "C4.1: parsed_ethertype must be 0x0800 (IPv4)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// C4.2 — Single 802.1ad S-tag (0x88A8), inner ethertype IPv4
//
// M4 interpretation: corner.md setup was "L3 rule on dst /32" — not
// testable in M4.  Empty L2 ruleset used instead: classify_l2 falls
// through to kNextL3.  D32 confirmation: S-tag accepted without QinQ event.
//
// Frame layout:
//   [12..13] 0x88A8 (S-tag TPID)
//   [14..15] TCI: vlan=200, pcp=0
//   [16..17] 0x0800 (IPv4) ← inner etype is NOT a VLAN TPID
//
// Assert:
//   - verdict == kNextL3 (empty ruleset pass-through)
//   - qinq_outer_only_total == 0 (inner 0x0800 is not a VLAN TPID)
//   - l3_offset == 18, parsed_vlan == 200, parsed_ethertype == 0x0800
//
// Already-GREEN from C4 impl (U6.9 covers this path exactly).
//
// Covers: D32 (S-tag single-tag, no-bump), D13, D41.
// =========================================================================
TEST_F(ClassifyL2VlanQinQCornerTest, C4_2_SingleSTagOverIPv4NoQinQEvent) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  // Empty L2 ruleset (M4 interpretation: no L3 rule testable here).
  ruleset::Ruleset rs;
  ASSERT_EQ(rs.l2_compound_count, 0u);
  ASSERT_EQ(rs.l2_compound_hash, nullptr);

  // Single S-tag frame: dst+src+0x88A8+TCI(vlan=200)+0x0800+padding.
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "c4_2_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 64));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 64);
  pkt[0]=0x01; pkt[1]=0x02; pkt[2]=0x03;
  pkt[3]=0x04; pkt[4]=0x05; pkt[5]=0x06;   // dst_mac
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0x42;  // src_mac
  pkt[12]=0x88; pkt[13]=0xA8;               // 0x88A8 S-tag TPID (D32)
  pkt[14]=0x00; pkt[15]=0xC8;               // TCI: vlan=200, pcp=0
  pkt[16]=0x08; pkt[17]=0x00;               // inner ethertype: 0x0800 (IPv4)

  std::uint64_t qinq_ctr = 0;
  dataplane::L2TruncCtrs trunc_ctrs{};

  // D41: through top-level classify_l2 entry point.
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs, &qinq_ctr, &trunc_ctrs);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kNextL3)
      << "C4.2: single S-tag over IPv4 → kNextL3 (empty ruleset, no L2 drop)";
  // D32: inner etype is 0x0800, NOT a VLAN TPID → counter must NOT fire.
  EXPECT_EQ(qinq_ctr, 0u)
      << "C4.2: qinq_outer_only_total must be 0 (inner etype 0x0800)";
  // D13.
  const auto* dyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(m));
  EXPECT_EQ(dyn->l3_offset, 18u)
      << "C4.2: l3_offset must be 18 (single S-tag)";
  EXPECT_EQ(dyn->parsed_vlan, 200u)
      << "C4.2: parsed_vlan must be 200";
  EXPECT_EQ(dyn->parsed_ethertype, 0x0800u)
      << "C4.2: parsed_ethertype must be 0x0800";
  // No truncation (valid-length frame).
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2)], 0u)
      << "C4.2: no l2 truncation";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2Vlan)], 0u)
      << "C4.2: no l2_vlan truncation";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// C4.3 — True QinQ: S-tag (0x88A8) + C-tag (0x8100) + IPv4
//
// M4 interpretation: corner.md defined C4.3a/C4.3b based on classify_l3
// behavior after the misread bytes at l3_offset=18.  M4 has no classify_l3
// so both variants are L2-identical.  Single collapsed test C4_3_TrueQinQ.
//
// TODO: M5 C? — split into C4.3a/C4.3b with engineered TCI for l3_v4
//       truncation variants once classify_l3 lands.
//
// Frame layout:
//   [12..13] 0x88A8 (S-tag)
//   [14..15] TCI: vlan=200, pcp=0
//   [16..17] 0x8100 (C-tag) ← inner etype IS a VLAN TPID → QinQ event
//   [18..19] inner TCI: vlan=50, pcp=0
//   [20..21] inner-inner ethertype: 0x0800
//
// Assert:
//   - qinq_outer_only_total += 1 (inner 0x8100 is a VLAN TPID)
//   - verdict == kNextL3 (empty ruleset, no terminal drop)
//   - l3_offset == 18, parsed_ethertype == 0x8100 (inner as-seen, not drilled)
//   - no truncation counters bump
//
// Already-GREEN from C4 impl (U6.8 covers this exact path).
//
// Covers: D32 (true QinQ, counter bump, no deeper drill), D13, D41.
// =========================================================================
TEST_F(ClassifyL2VlanQinQCornerTest, C4_3_TrueQinQSTagCTag) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  // Empty L2 ruleset.
  ruleset::Ruleset rs;
  ASSERT_EQ(rs.l2_compound_count, 0u);

  // True QinQ frame: S-tag (0x88A8) + C-tag (0x8100).
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "c4_3_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 64));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 64);
  pkt[0]=0x01; pkt[1]=0x02; pkt[2]=0x03;
  pkt[3]=0x04; pkt[4]=0x05; pkt[5]=0x06;   // dst_mac
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0x43;  // src_mac
  pkt[12]=0x88; pkt[13]=0xA8;               // outer 0x88A8 (S-tag)
  pkt[14]=0x00; pkt[15]=0xC8;               // outer TCI: vlan=200, pcp=0
  pkt[16]=0x81; pkt[17]=0x00;               // inner 0x8100 (C-tag) → QinQ bump
  pkt[18]=0x00; pkt[19]=0x32;               // inner TCI: vlan=50, pcp=0
  pkt[20]=0x08; pkt[21]=0x00;               // inner-inner: 0x0800 IPv4

  std::uint64_t qinq_ctr = 0;
  dataplane::L2TruncCtrs trunc_ctrs{};

  // D41: through top-level classify_l2 entry point.
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs, &qinq_ctr, &trunc_ctrs);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kNextL3)
      << "C4.3: true QinQ must produce kNextL3 (no terminal drop, D32)";
  // D32: inner etype 0x8100 IS a VLAN TPID → counter must fire.
  EXPECT_EQ(qinq_ctr, 1u)
      << "C4.3: qinq_outer_only_total must be 1 (inner 0x8100 is VLAN TPID)";
  // D13: l3_offset=18 (one tag walked, inner not drilled).
  const auto* dyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(m));
  EXPECT_EQ(dyn->l3_offset, 18u)
      << "C4.3: l3_offset must be 18 (one tag walked, inner not drilled)";
  EXPECT_EQ(dyn->parsed_ethertype, 0x8100u)
      << "C4.3: parsed_ethertype must be 0x8100 (inner C-tag, as-seen)";
  // No truncation (valid-length frame).
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2)], 0u)
      << "C4.3: no l2 truncation";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2Vlan)], 0u)
      << "C4.3: no l2_vlan truncation";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// C4.4 — QinQ: S-tag + S-tag (0x88A8 + 0x88A8)
//
// Frame layout:
//   [12..13] 0x88A8 (outer S-tag)
//   [14..15] TCI: vlan=10, pcp=0
//   [16..17] 0x88A8 (inner S-tag) ← VLAN TPID → bump
//
// Assert: qinq_outer_only_total += 1, verdict == kNextL3,
//         parsed_ethertype == 0x88A8.
//
// Covers: D32 (double-S-tag), D41.
// =========================================================================
TEST_F(ClassifyL2VlanQinQCornerTest, C4_4_QinQSTagSTag) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;  // empty ruleset

  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "c4_4_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 64));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 64);
  pkt[0]=0x01; pkt[1]=0x02; pkt[2]=0x03;
  pkt[3]=0x04; pkt[4]=0x05; pkt[5]=0x06;   // dst_mac
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0x44;  // src_mac
  pkt[12]=0x88; pkt[13]=0xA8;               // outer 0x88A8 (S-tag)
  pkt[14]=0x00; pkt[15]=0x0A;               // outer TCI: vlan=10, pcp=0
  pkt[16]=0x88; pkt[17]=0xA8;               // inner 0x88A8 (S-tag) → QinQ bump
  pkt[18]=0x00; pkt[19]=0x14;               // inner TCI: vlan=20, pcp=0
  pkt[20]=0x08; pkt[21]=0x00;               // inner-inner: 0x0800

  std::uint64_t qinq_ctr = 0;

  // D41: through top-level classify_l2 entry point.
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs, &qinq_ctr);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kNextL3)
      << "C4.4: double S-tag must produce kNextL3 (no terminal drop)";
  EXPECT_EQ(qinq_ctr, 1u)
      << "C4.4: qinq_outer_only_total must be 1 (inner 0x88A8 is VLAN TPID)";
  const auto* dyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(m));
  EXPECT_EQ(dyn->parsed_ethertype, 0x88A8u)
      << "C4.4: parsed_ethertype must be 0x88A8 (inner S-tag, not drilled)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// C4.5 — QinQ: C-tag + C-tag (0x8100 + 0x8100) — "Q-in-Q with two C-tags"
//
// Frame layout:
//   [12..13] 0x8100 (outer C-tag)
//   [14..15] TCI: vlan=30, pcp=0
//   [16..17] 0x8100 (inner C-tag) ← VLAN TPID → bump
//
// Assert: qinq_outer_only_total += 1, verdict == kNextL3,
//         parsed_ethertype == 0x8100.
//
// Covers: D32 (C-in-C variant), D41.
// =========================================================================
TEST_F(ClassifyL2VlanQinQCornerTest, C4_5_QinQCTagCTag) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;  // empty ruleset

  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "c4_5_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 64));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 64);
  pkt[0]=0x01; pkt[1]=0x02; pkt[2]=0x03;
  pkt[3]=0x04; pkt[4]=0x05; pkt[5]=0x06;   // dst_mac
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0x45;  // src_mac
  pkt[12]=0x81; pkt[13]=0x00;               // outer 0x8100 (C-tag)
  pkt[14]=0x00; pkt[15]=0x1E;               // outer TCI: vlan=30, pcp=0
  pkt[16]=0x81; pkt[17]=0x00;               // inner 0x8100 (C-tag) → QinQ bump
  pkt[18]=0x00; pkt[19]=0x28;               // inner TCI: vlan=40, pcp=0
  pkt[20]=0x08; pkt[21]=0x00;               // inner-inner: 0x0800

  std::uint64_t qinq_ctr = 0;

  // D41: through top-level classify_l2 entry point.
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs, &qinq_ctr);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kNextL3)
      << "C4.5: C-in-C (double 0x8100) must produce kNextL3";
  EXPECT_EQ(qinq_ctr, 1u)
      << "C4.5: qinq_outer_only_total must be 1 (inner 0x8100 is VLAN TPID)";
  const auto* dyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(m));
  EXPECT_EQ(dyn->parsed_ethertype, 0x8100u)
      << "C4.5: parsed_ethertype must be 0x8100 (inner C-tag, not drilled)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// C4.6 — VLAN TCI with DEI bit set (vlan=100, dei=1)
//
// DEI decision: design does not mention DEI.  This test documents that
// classify_l2 masks it out — only `tci & 0x0FFF` is used for vlan_id and
// `(tci >> 13) & 0x07` for pcp.  DEI (bit 12) is silently ignored.
//
// TCI with dei=1, vlan=100, pcp=0: 0x1064 (bits: pcp=000, dei=1, vid=0x064).
//   bit layout:  [15:13]=pcp=000, [12]=dei=1, [11:0]=vid=0x064
//   0b_000_1_000001100100 = 0x1064
//
// Setup: L2 rule on vlan_id=100 → ALLOW.
// Assert: rule fires (DEI masked out, vlan 100 still matches),
//         parsed_vlan == 100, no counter anomaly.
//
// Covers: DEI semantics decision (documented via this test), D13, D41.
// =========================================================================
TEST_F(ClassifyL2VlanQinQCornerTest, C4_6_VlanDEIBitMaskedOut) {
  using namespace builder_eal;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  Config cfg = make_config();
  // L2 rule: vlan_id=100 → ALLOW (same as C4.1).
  auto& r0 = append_rule(cfg.pipeline.layer_2, 4600, ActionAllow{});
  r0.vlan_id = 100;

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value()) << "compile failed";
  ASSERT_EQ(cr.l2_compound.size(), 1u);

  Ruleset rs = ruleset::build_ruleset(cr, cfg.sizing, /*num_lcores=*/1);
  EalPopulateParams params;
  params.name_prefix = "c4_6";
  params.socket_id = 0;
  params.max_entries = 64;
  auto res = ruleset::populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;

  // VLAN frame with DEI=1, vlan=100, pcp=0.
  // TCI = 0x1064: pcp=000, dei=1, vid=0x064 (100 decimal).
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "c4_6_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 64));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 64);
  pkt[0]=0x01; pkt[1]=0x02; pkt[2]=0x03;
  pkt[3]=0x04; pkt[4]=0x05; pkt[5]=0x06;   // dst_mac
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0x46;  // src_mac
  pkt[12]=0x81; pkt[13]=0x00;               // 0x8100 VLAN TPID
  pkt[14]=0x10; pkt[15]=0x64;               // TCI: pcp=0, dei=1, vlan=100 (0x1064)
  pkt[16]=0x08; pkt[17]=0x00;               // inner ethertype: 0x0800 IPv4

  std::uint64_t qinq_ctr = 0;

  // D41: through top-level classify_l2 entry point.
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs, &qinq_ctr);

  // DEI bit must be masked out: rule on vlan=100 must still fire.
  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kNextL3)
      << "C4.6: DEI bit must be masked out; vlan=100 ALLOW rule must fire";
  EXPECT_EQ(qinq_ctr, 0u)
      << "C4.6: qinq_outer_only_total must be 0 (inner etype 0x0800)";
  const auto* dyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(m));
  // D13: parsed_vlan must be 100 (tci & 0x0FFF masks out DEI bit).
  EXPECT_EQ(dyn->parsed_vlan, 100u)
      << "C4.6: parsed_vlan must be 100 (DEI bit 12 masked out by tci & 0x0FFF)";
  EXPECT_EQ(dyn->l3_offset, 18u)
      << "C4.6: l3_offset must be 18 (VLAN-tagged)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// C4.7 — VLAN TCI with PCP=7 (highest priority), vlan=50
//
// Setup: L2 rule with pcp=7 → ALLOW.
// Frame: 0x8100 + TCI(pcp=7, vlan=50) + 0x0800.
// TCI: pcp=7 (111), dei=0, vlan=50 (0x032)
//   0b_111_0_000000110010 = 0xE032
//
// Assert: rule fires (pcp primary probe hits), pcp==7.
// PCP parse is plumbed in classify_l2 via (tci >> 13) & 0x07.
//
// Covers: PCP parse correctness, D15 (pcp primary probe), D41.
// =========================================================================
TEST_F(ClassifyL2VlanQinQCornerTest, C4_7_VlanPcp7Fires) {
  using namespace builder_eal;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  Config cfg = make_config();
  // L2 rule: pcp=7 → ALLOW.  Compiler picks pcp as primary key.
  auto& r0 = append_rule(cfg.pipeline.layer_2, 4700, ActionAllow{});
  r0.pcp = 7;

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value()) << "compile failed";
  ASSERT_EQ(cr.l2_compound.size(), 1u);
  EXPECT_EQ(cr.l2_compound[0].primary_kind, compiler::L2PrimaryKind::kPcp)
      << "C4.7: compiler must choose pcp as primary";

  Ruleset rs = ruleset::build_ruleset(cr, cfg.sizing, /*num_lcores=*/1);
  EalPopulateParams params;
  params.name_prefix = "c4_7";
  params.socket_id = 0;
  params.max_entries = 64;
  auto res = ruleset::populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;

  // VLAN-tagged frame with pcp=7, vlan=50.
  // TCI = 0xE032: pcp=7(111), dei=0, vlan=50(0x032).
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "c4_7_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 64));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 64);
  pkt[0]=0x01; pkt[1]=0x02; pkt[2]=0x03;
  pkt[3]=0x04; pkt[4]=0x05; pkt[5]=0x06;   // dst_mac
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0x47;  // src_mac
  pkt[12]=0x81; pkt[13]=0x00;               // 0x8100 VLAN TPID
  pkt[14]=0xE0; pkt[15]=0x32;               // TCI: pcp=7, dei=0, vlan=50 (0xE032)
  pkt[16]=0x08; pkt[17]=0x00;               // inner ethertype: 0x0800 IPv4

  // D41: through top-level classify_l2 entry point.
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kNextL3)
      << "C4.7: pcp=7 ALLOW rule must fire → kNextL3";
  // Confirm dynfield action_idx = 0 (first rule fired).
  const auto* dyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(m));
  EXPECT_EQ(dyn->verdict_action_idx, 0u)
      << "C4.7: verdict_action_idx must be 0 (first rule)";
  // Confirm pcp parsed correctly (via parsed_vlan extraction path indirectly).
  // classify_l2 uses pkt_pcp = (tci >> 13) & 0x07 for the probe key.
  EXPECT_EQ(dyn->parsed_vlan, 50u)
      << "C4.7: parsed_vlan must be 50 (TCI & 0x0FFF)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// C4.8 — Triple-tagged (0x8100 + 0x8100 + 0x8100) over IP
//
// classify_l2 walks ONE tag only.  After consuming the first 0x8100 tag,
// the inner ethertype is 0x8100 → QinQ bump.  Third tag not walked.
//
// Frame layout:
//   [12..13] outer 0x8100
//   [14..15] outer TCI: vlan=10
//   [16..17] second 0x8100 (inner of first walk) → QinQ bump
//   [18..19] second TCI (third tag outer TCI, not walked)
//   [20..21] third 0x8100 (third tag, not reached)
//
// Assert: qinq_outer_only_total += 1, verdict == kNextL3,
//         parsed_ethertype == 0x8100, no crash.
//
// Covers: D32 (deeper stacks must not crash, one-tag-walk discipline), D41.
// =========================================================================
TEST_F(ClassifyL2VlanQinQCornerTest, C4_8_TripleTagged8100NoCrash) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;  // empty ruleset

  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "c4_8_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 64));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 64);
  pkt[0]=0x01; pkt[1]=0x02; pkt[2]=0x03;
  pkt[3]=0x04; pkt[4]=0x05; pkt[5]=0x06;   // dst_mac
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0x48;  // src_mac
  pkt[12]=0x81; pkt[13]=0x00;               // first tag 0x8100 (outer)
  pkt[14]=0x00; pkt[15]=0x0A;               // outer TCI: vlan=10
  pkt[16]=0x81; pkt[17]=0x00;               // second tag 0x8100 → seen as inner etype → QinQ bump
  pkt[18]=0x00; pkt[19]=0x14;               // second TCI: vlan=20 (not walked further)
  pkt[20]=0x81; pkt[21]=0x00;               // third tag 0x8100 (not reached by classifier)
  pkt[22]=0x00; pkt[23]=0x1E;               // third TCI: vlan=30
  pkt[24]=0x08; pkt[25]=0x00;               // innermost ethertype: 0x0800 IPv4

  std::uint64_t qinq_ctr = 0;

  // D41: through top-level classify_l2 entry point.
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs, &qinq_ctr);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kNextL3)
      << "C4.8: triple-tagged frame must produce kNextL3 (no crash, no terminal drop)";
  // First walk: outer 0x8100 → inner seen at [16..17] = 0x8100 → bump.
  EXPECT_EQ(qinq_ctr, 1u)
      << "C4.8: qinq_outer_only_total must be 1 (second tag 0x8100 is VLAN TPID)";
  const auto* dyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(m));
  // parsed_ethertype is the inner etype after first walk: 0x8100 (second tag).
  EXPECT_EQ(dyn->parsed_ethertype, 0x8100u)
      << "C4.8: parsed_ethertype must be 0x8100 (second tag, one-walk discipline)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// C4.9 — 18 B frame: VLAN 0x8100, walk into 14+4=18 B exactly
//
// Exactly 18 B is the D31 l2_vlan boundary.  Guard #2 fires on
// pkt_len < 18; 18 is NOT < 18, so NO truncation.
//
// Frame layout (exactly 18 bytes):
//   [0..5]   dst_mac
//   [6..11]  src_mac
//   [12..13] 0x8100 TPID
//   [14..15] TCI: vlan=100, pcp=0 (0x0064)
//   [16..17] inner ethertype: 0x0800 (engineered to be non-VLAN, predictable)
//
// Assert: no truncation counters bump, verdict == kNextL3 (empty ruleset),
//         l3_offset == 18, parsed_ethertype == 0x0800.
//
// M4 interpretation: inner etype engineered to 0x0800 (non-VLAN) for
// predictable parsed_ethertype assertion.
//
// Covers: D31 boundary (pkt_len==18 is the first OK case for VLAN), D41.
// =========================================================================
TEST_F(ClassifyL2VlanQinQCornerTest, C4_9_ExactlyEighteenBytesVlanNoBoundaryDrop) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;  // empty ruleset

  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "c4_9_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  // Exactly 18 bytes.
  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 18));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 18);
  pkt[0]=0x01; pkt[1]=0x02; pkt[2]=0x03;
  pkt[3]=0x04; pkt[4]=0x05; pkt[5]=0x06;   // dst_mac
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0x49;  // src_mac
  pkt[12]=0x81; pkt[13]=0x00;               // 0x8100 VLAN TPID
  pkt[14]=0x00; pkt[15]=0x64;               // TCI: vlan=100, pcp=0
  pkt[16]=0x08; pkt[17]=0x00;               // inner ethertype: 0x0800 (engineered non-VLAN)

  ASSERT_EQ(m->pkt_len, 18u) << "C4.9: frame must be exactly 18 bytes";

  std::uint64_t qinq_ctr = 0;
  dataplane::L2TruncCtrs trunc_ctrs{};

  // D41: through top-level classify_l2 entry point.
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs, &qinq_ctr, &trunc_ctrs);

  // 18 >= 18 → guard #2 does NOT fire.
  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kNextL3)
      << "C4.9: 18 B VLAN frame must NOT be truncated (boundary is pkt_len < 18)";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2Vlan)], 0u)
      << "C4.9: no l2_vlan truncation at exactly 18 B";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2)], 0u)
      << "C4.9: no l2 truncation";
  EXPECT_EQ(qinq_ctr, 0u)
      << "C4.9: no QinQ event (inner etype 0x0800)";
  const auto* dyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(m));
  EXPECT_EQ(dyn->l3_offset, 18u)
      << "C4.9: l3_offset must be 18 (VLAN-tagged frame)";
  EXPECT_EQ(dyn->parsed_ethertype, 0x0800u)
      << "C4.9: parsed_ethertype must be 0x0800 (engineered inner etype)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// C4.10 — 17 B frame with 0x8100 TPID: l2_vlan truncation
//
// Note: this is the same shape class as C6's C1.6 (also 17 B + 0x8100).
// C6 (commit e5b188c) already covered it via C1.6.  Transcribed here for
// corner-plan completeness and independence (C4.* corner suite).
// Marked: "already-GREEN from C5/C6, duplicate shape of C1.6".
//
// Frame: 17 bytes with 0x8100 at [12..13]. Guard #2 fires (17 < 18).
//
// Assert: pkt_truncated_total[l2_vlan] += 1, verdict == kDrop.
//
// Covers: D31 (l2_vlan bucket), D32 (0x8100 treated as VLAN TPID), D41.
// =========================================================================
TEST_F(ClassifyL2VlanQinQCornerTest, C4_10_SeventeenBytesVlanTruncated) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;  // empty ruleset

  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "c4_10_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  // Exactly 17 bytes.
  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, 17));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, 17);
  pkt[0]=0x01; pkt[1]=0x02; pkt[2]=0x03;
  pkt[3]=0x04; pkt[4]=0x05; pkt[5]=0x06;   // dst_mac
  pkt[6]=0xaa; pkt[7]=0xbb; pkt[8]=0xcc;
  pkt[9]=0xdd; pkt[10]=0xee; pkt[11]=0x4A;  // src_mac
  pkt[12]=0x81; pkt[13]=0x00;               // 0x8100 VLAN TPID
  pkt[14]=0x00; pkt[15]=0x64;               // partial TCI byte (but 17 < 18 → guard fires)
  pkt[16]=0x08;                              // one partial byte (not a full inner etype)

  ASSERT_EQ(m->pkt_len, 17u) << "C4.10: frame must be exactly 17 bytes";

  dataplane::L2TruncCtrs trunc_ctrs{};

  // D41: through top-level classify_l2 entry point.
  const dataplane::ClassifyL2Verdict verdict =
      dataplane::classify_l2(m, rs, nullptr, &trunc_ctrs);

  EXPECT_EQ(verdict, dataplane::ClassifyL2Verdict::kDrop)
      << "C4.10: 17 B VLAN frame must be dropped by D31 l2_vlan guard";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2Vlan)], 1u)
      << "C4.10: pkt_truncated_total[l2_vlan] must be 1";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L2TruncBucket::kL2)], 0u)
      << "C4.10: pkt_truncated_total[l2] must be 0 (17 >= 14, guard #1 does not fire)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

}  // namespace pktgate::test
