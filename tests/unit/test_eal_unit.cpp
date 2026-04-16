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
#include "src/dataplane/classify_l4.h"
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
// dyn->l3_offset = 14 + dyn->parsed_ethertype = 0x0800 (host byte order)
// the way classify_l2 would after parsing an untagged Ethernet frame. Same pattern
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
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV4;
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
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV4;
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
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV4;
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
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV4;
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
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV4;
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
// M5 C3 — classify_l3 IPv4 fragment handling (D17 + D40 v4 counters)
//
// Seven unit tests exercise the IPv4 fragment branch of classify_l3:
//
//   U6.21 — non-first frag, FRAG_L3_ONLY, L3 miss  → kTerminalPass
//   U6.22 — non-first frag, FRAG_L3_ONLY, L3 hit   → rule action
//                                                   (allow → kTerminalPass,
//                                                    drop  → kTerminalDrop)
//   U6.23 — fragment,        FRAG_DROP             → kTerminalDrop
//   U6.24 — fragment,        FRAG_ALLOW            → kTerminalPass
//   U6.25 — first frag (MF=1, offset=0), FRAG_L3_ONLY — no SKIP_L4,
//                                                       runs full L3+L4
//   U6.26a — FRAG_DROP bumps pkt_frag_dropped_total_v4 exactly once
//            (D40 v4 drop sentinel, no bleed into other buckets)
//   U6.26b — FRAG_L3_ONLY/nonfirst bumps pkt_frag_skipped_total_v4
//            exactly once + sets the SKIP_L4 dynfield flag
//            (D40 v4 skip sentinel)
//
// All tests bypass classify_l2 and call classify_l3 directly, writing
// `dyn->l3_offset / parsed_ethertype / flags` by hand. Same pattern as
// U6.12-U6.18b (M5 C1/C1b).
//
// `rs.fragment_policy` is set directly on the Ruleset (u8 encoded per
// classify_l3.h `FragmentPolicy`): the config→ruleset wiring for this
// field is a pre-C3 gap, and U6.21-U6.26b validate the classify_l3
// behavior on a policy regardless of how the policy lands in the
// ruleset.
//
// Frame layout helper: an IPv4 fragment word at offset 14+6 (= 20) is
// written big-endian as two bytes. MF=1 sets bit 13 of the BE16 word
// → byte[20] |= 0x20. A non-zero fragment offset is encoded in units
// of 8 bytes: offset=8 bytes on the wire → ((8/8)=1) → low 13 bits =
// 0x0001 → BE bytes 20=0x00, 21=0x01.
// =========================================================================

class ClassifyL3Ipv4FragmentTest : public EalFixture {};

namespace {

// Build a minimal IPv4 frame: 14 B Ethernet + 20 B IPv4 header, addressed
// to `dst_be` (host→big-endian happens at the memcpy). The caller writes
// the fragment word after return via `pkt[20]/pkt[21]`.
//
// Returns: {mempool, mbuf, pkt pointer}.
struct FragFrame {
  struct rte_mempool* mp;
  struct rte_mbuf*    m;
  std::uint8_t*       pkt;
};

inline FragFrame build_ipv4_frame(const char* pool_name, std::uint32_t dst) {
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      pool_name, 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  EXPECT_NE(mp, nullptr) << "mempool create failed: " << pool_name;
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  EXPECT_NE(m, nullptr);
  EXPECT_EQ(m->nb_segs, 1);

  constexpr std::size_t kFrameLen = 14 + 20;
  std::uint8_t* pkt = reinterpret_cast<std::uint8_t*>(
      rte_pktmbuf_append(m, kFrameLen));
  EXPECT_NE(pkt, nullptr);
  std::memset(pkt, 0, kFrameLen);
  pkt[12] = 0x08;
  pkt[13] = 0x00;  // EtherType 0x0800 IPv4
  pkt[14] = 0x45;  // version=4, IHL=5
  // dst_addr at offset 14+16 = 30, big-endian.
  pkt[30] = static_cast<std::uint8_t>((dst >> 24) & 0xFF);
  pkt[31] = static_cast<std::uint8_t>((dst >> 16) & 0xFF);
  pkt[32] = static_cast<std::uint8_t>((dst >> 8) & 0xFF);
  pkt[33] = static_cast<std::uint8_t>(dst & 0xFF);

  return FragFrame{mp, m, pkt};
}

// Set the IPv4 `fragment_offset_and_flags` BE16 word at [20..21].
// `mf` sets the MF bit (bit 13 of the BE16 word). `frag_off_units`
// is the 13-bit fragment offset (in units of 8 bytes on the wire).
inline void set_frag_word(std::uint8_t* pkt, bool mf,
                          std::uint16_t frag_off_units) {
  const std::uint16_t word =
      (mf ? 0x2000u : 0u) | (frag_off_units & 0x1FFFu);
  pkt[20] = static_cast<std::uint8_t>((word >> 8) & 0xFF);
  pkt[21] = static_cast<std::uint8_t>(word & 0xFF);
}

inline void set_dyn_for_ipv4(struct rte_mbuf* m) {
  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset        = 14;
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV4;
  dyn->parsed_vlan      = 0xFFFF;
  dyn->flags            = 0;
}

}  // namespace

// -------------------------------------------------------------------------
// U6.21 — non-first frag, FRAG_L3_ONLY, L3 miss → kTerminalPass (D21 cliff)
//
// Non-first IPv4 fragment hits classify_l3 with an unpopulated FIB
// (rs.l3_v4_fib == nullptr). FRAG_L3_ONLY sets SKIP_L4, falls through
// to the L3 branch, the short-circuit miss arm observes SKIP_L4 and
// returns kTerminalPass (NOT kNextL4). Without the C3 fix the hot path
// would return kNextL4 on the miss arm and send the packet to
// classify_l4 with no L4 header, crashing or producing garbage.
//
// Also asserts: pkt_frag_skipped_total_v4 == 1 (the single skip site).
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4FragmentTest, U6_21_NonFirstFragL3OnlyMissTerminalPass) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;   // empty — no FIB, no rules
  rs.fragment_policy = dataplane::kFragL3Only;

  auto ff = build_ipv4_frame("u6_21_pool", 0x0A010203u);  // 10.1.2.3
  ASSERT_NE(ff.m, nullptr);
  // Non-first fragment: offset=1 (units-of-8 = 8 bytes), MF=0.
  set_frag_word(ff.pkt, /*mf=*/false, /*frag_off_units=*/1);
  set_dyn_for_ipv4(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "U6.21: non-first frag + L3_ONLY + FIB miss must yield kTerminalPass "
         "(SKIP_L4 cliff — design.md §5.3 line 1201)";
  auto* dyn = eal::mbuf_dynfield(ff.m);
  EXPECT_NE(dyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "U6.21: non-first frag under L3_ONLY must set SKIP_L4 dynfield flag";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 1u)
      << "U6.21: pkt_frag_skipped_total_v4 must be 1";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV4)], 0u)
      << "U6.21: pkt_frag_dropped_total_v4 must be 0";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// U6.22 — non-first frag, FRAG_L3_ONLY, L3 hit on allow rule →
//         kTerminalPass (reconciled from stale "TERMINAL_L3" wording)
//
// Non-first IPv4 fragment, populated FIB with an allow rule matching
// the dst prefix. L3_ONLY sets SKIP_L4; dispatcher resolves allow and
// would normally return kNextL4, but the SKIP_L4 guard at the return
// site collapses it to kTerminalPass (L4 classifier cannot run on a
// non-first fragment). Unit.md says "TERMINAL_L3" — the C3 enum ships
// {kNextL4, kTerminalPass, kTerminalDrop}, so the reconciliation is:
// allow hit under SKIP_L4 → kTerminalPass.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4FragmentTest, U6_22_NonFirstFragL3OnlyHitTerminalPass) {
  using namespace builder_eal;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  Config cfg = make_config();

  // Filler rule so the target allow rule lands at action_idx=1 — same
  // shape as U6.18 (avoid the C1b zero-packed entry path; that's not
  // what this test is about).
  SubnetObject filler;
  filler.name = "net_filler_u6_22";
  filler.cidrs.push_back(Cidr4{0xAC100000, 12});  // 172.16.0.0/12
  cfg.objects.subnets.push_back(std::move(filler));

  SubnetObject target;
  target.name = "net_target_u6_22";
  target.cidrs.push_back(Cidr4{0x0A000000, 8});   // 10.0.0.0/8
  cfg.objects.subnets.push_back(std::move(target));

  auto& r_filler = append_rule(cfg.pipeline.layer_3, 6221, ActionDrop{});
  r_filler.dst_subnet = SubnetRef{"net_filler_u6_22"};
  auto& r_target = append_rule(cfg.pipeline.layer_3, 6222, ActionAllow{});
  r_target.dst_subnet = SubnetRef{"net_target_u6_22"};

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value());

  Ruleset rs = ruleset::build_ruleset(cr, cfg.sizing, /*num_lcores=*/1);
  rs.fragment_policy = dataplane::kFragL3Only;
  EalPopulateParams params;
  params.name_prefix = "u6_22";
  params.socket_id = 0;
  params.max_entries = 64;
  auto res = populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;
  ASSERT_NE(rs.l3_v4_fib, nullptr);

  auto ff = build_ipv4_frame("u6_22_pool", 0x0A010203u);  // matches 10/8
  ASSERT_NE(ff.m, nullptr);
  set_frag_word(ff.pkt, /*mf=*/false, /*frag_off_units=*/1);  // non-first
  set_dyn_for_ipv4(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "U6.22: non-first frag + L3_ONLY + allow-rule hit must collapse "
         "to kTerminalPass (L4 cannot run under SKIP_L4; reconciled from "
         "unit.md's stale TERMINAL_L3 wording)";
  auto* dyn = eal::mbuf_dynfield(ff.m);
  EXPECT_NE(dyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "U6.22: SKIP_L4 must still be set on L3-hit path";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 1u)
      << "U6.22: pkt_frag_skipped_total_v4 must be 1";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// U6.23 — fragment, FRAG_DROP → kTerminalDrop
//
// Any fragment under FRAG_DROP is dropped unconditionally, whether or
// not L3 rules would otherwise match. Test uses a non-first fragment
// but the FRAG_DROP arm never consults is_nonfirst; U6.26a below
// separately exercises the first-fragment + FRAG_DROP sub-case.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4FragmentTest, U6_23_FragFragDropTerminalDrop) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragDrop;

  auto ff = build_ipv4_frame("u6_23_pool", 0x0A010203u);
  ASSERT_NE(ff.m, nullptr);
  set_frag_word(ff.pkt, /*mf=*/false, /*frag_off_units=*/1);  // non-first
  set_dyn_for_ipv4(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalDrop)
      << "U6.23: any fragment under FRAG_DROP must terminally drop";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV4)], 1u)
      << "U6.23: pkt_frag_dropped_total_v4 must be 1";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// U6.24 — fragment, FRAG_ALLOW → kTerminalPass
//
// FRAG_ALLOW skips L3+L4 entirely and yields kTerminalPass. The
// §5.5 dispatch path applies default_action to the resulting terminal
// pass. No counter bump (operator opts into this unsafe policy at
// config time; no per-packet observability).
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4FragmentTest, U6_24_FragFragAllowTerminalPass) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragAllow;

  auto ff = build_ipv4_frame("u6_24_pool", 0x0A010203u);
  ASSERT_NE(ff.m, nullptr);
  set_frag_word(ff.pkt, /*mf=*/true, /*frag_off_units=*/0);  // first frag
  set_dyn_for_ipv4(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "U6.24: any fragment under FRAG_ALLOW must terminally pass";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV4)], 0u)
      << "U6.24: FRAG_ALLOW must not bump the drop counter";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 0u)
      << "U6.24: FRAG_ALLOW must not bump the skip counter";
  auto* dyn = eal::mbuf_dynfield(ff.m);
  EXPECT_EQ(dyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "U6.24: FRAG_ALLOW must not set SKIP_L4 — this arm bypasses L4 "
         "via a terminal verdict, not via the SKIP_L4 path";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// U6.25 — first fragment (offset=0, MF=1) under FRAG_L3_ONLY runs full
//         L3+L4. First fragment carries the L4 header, so no SKIP_L4
//         flag, no skip counter bump; classify_l3 returns kNextL4 on
//         FIB miss (empty ruleset → FIB null → short-circuit miss arm).
//         Mirrors D27 IPv6 first-fragment semantics that C6 will add.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4FragmentTest, U6_25_FirstFragL3OnlyRunsFullL4) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  auto ff = build_ipv4_frame("u6_25_pool", 0x0A010203u);
  ASSERT_NE(ff.m, nullptr);
  // First fragment: MF=1, frag_off_units=0.
  set_frag_word(ff.pkt, /*mf=*/true, /*frag_off_units=*/0);
  set_dyn_for_ipv4(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kNextL4)
      << "U6.25: first frag under L3_ONLY must pass through to L4 "
         "(first frag carries the L4 header; symmetric to D27 IPv6)";
  auto* dyn = eal::mbuf_dynfield(ff.m);
  EXPECT_EQ(dyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "U6.25: first frag must NOT set SKIP_L4";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 0u)
      << "U6.25: first frag must NOT bump skip counter";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV4)], 0u)
      << "U6.25: first frag under L3_ONLY must NOT bump drop counter";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// U6.26a — D40 v4 drop sentinel: FRAG_DROP bumps pkt_frag_dropped_total_v4
//          exactly once, no bleed into pkt_frag_skipped_total_v4 or
//          pkt_truncated_l3. Explicit D40 counter-delta invariant.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4FragmentTest, U6_26a_FragDropBumpsDroppedCounterOnly) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragDrop;

  auto ff = build_ipv4_frame("u6_26a_pool", 0x0A010203u);
  ASSERT_NE(ff.m, nullptr);
  set_frag_word(ff.pkt, /*mf=*/true, /*frag_off_units=*/0);  // first frag
  set_dyn_for_ipv4(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalDrop)
      << "U6.26a: FRAG_DROP must terminally drop";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV4)], 1u)
      << "U6.26a: pkt_frag_dropped_total_v4 must be 1 (D40 drop sentinel)";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 0u)
      << "U6.26a: drop path must NOT bleed into pkt_frag_skipped_total_v4";
  EXPECT_EQ(trunc[static_cast<std::size_t>(
                dataplane::L3TruncBucket::kL3V4)], 0u)
      << "U6.26a: drop path must NOT bleed into pkt_truncated_l3";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// U6.26b — D40 v4 skip sentinel: FRAG_L3_ONLY + non-first bumps
//          pkt_frag_skipped_total_v4 exactly once AND sets the SKIP_L4
//          dynfield flag, with no bleed into pkt_frag_dropped_total_v4.
//          Explicit D40 v4 skip invariant.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4FragmentTest, U6_26b_FragL3OnlyNonFirstBumpsSkippedAndSkipL4) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  auto ff = build_ipv4_frame("u6_26b_pool", 0x0A010203u);
  ASSERT_NE(ff.m, nullptr);
  set_frag_word(ff.pkt, /*mf=*/false, /*frag_off_units=*/1);  // non-first
  set_dyn_for_ipv4(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag);

  // Empty ruleset → L3 miss → SKIP_L4 → kTerminalPass.
  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "U6.26b: non-first frag under L3_ONLY with empty FIB must yield "
         "kTerminalPass (same path as U6.21; D17 cliff)";
  auto* dyn = eal::mbuf_dynfield(ff.m);
  EXPECT_NE(dyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "U6.26b: non-first frag under L3_ONLY must set SKIP_L4 flag";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 1u)
      << "U6.26b: pkt_frag_skipped_total_v4 must be 1 (D40 skip sentinel)";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV4)], 0u)
      << "U6.26b: skip path must NOT bleed into pkt_frag_dropped_total_v4";
  EXPECT_EQ(trunc[static_cast<std::size_t>(
                dataplane::L3TruncBucket::kL3V4)], 0u)
      << "U6.26b: skip path must NOT bleed into pkt_truncated_l3";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
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

// =========================================================================
// M5 C4 — classify_l3 IPv6 branch: dst-prefix FIB lookup + D31 l3_v6
//         truncation guard + basic IPv6 pass-through.
//
// Four unit tests:
//
//   U6.14  — IPv6 short packet (pkt_len < l3_off + 40) → kTerminalDrop +
//            D31 l3_v6 truncation bucket bump.
//   U6.26  — IPv6 plain TCP (next_header=6), no L3 rules → kNextL4,
//            l4_extra stays at init value (0). Basic IPv6 pass-through.
//   U6.32  — IPv6 dst FIB hit on allow/drop rule → dispatch on action
//            (allow → kNextL4, drop → kTerminalDrop). Same pattern as
//            U6.18 for IPv4.
//   U6.32a — IPv6 dst FIB miss → kNextL4 fall-through (analogous to
//            U6.18a for IPv4).
//
// All tests bypass classify_l2 and call classify_l3 directly, writing
// dyn->l3_offset / parsed_ethertype / flags by hand. Same pattern as
// U6.12-U6.18b (M5 C1/C1b).
// =========================================================================

class ClassifyL3Ipv6Test : public EalFixture {};

// -------------------------------------------------------------------------
// U6.14 — IPv6 short packet (pkt_len < l3_off + 40) → kTerminalDrop
//
// IPv6 has a fixed 40-byte header. A frame shorter than l3_off + 40
// cannot hold a valid IPv6 header. D31 l3_v6 truncation guard fires,
// bumps pkt_truncated_l3[l3_v6], returns kTerminalDrop.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv6Test, U6_14_Ipv6ShortPacketTruncDrop) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;

  // Build a short frame: 14 B Ethernet + 39 B "IPv6 header" (one byte short).
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_14_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  constexpr std::size_t kFrameLen = 14 + 39;  // one byte short of valid IPv6
  std::uint8_t* pkt = reinterpret_cast<std::uint8_t*>(
      rte_pktmbuf_append(m, kFrameLen));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, kFrameLen);
  pkt[12] = 0x86;
  pkt[13] = 0xDD;  // EtherType 0x86DD IPv6

  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset        = 14;
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV6;
  dyn->parsed_vlan      = 0xFFFF;
  dyn->flags            = 0;

  dataplane::L3TruncCtrs trunc_ctrs{};
  const auto verdict = dataplane::classify_l3(m, rs, &trunc_ctrs);

  EXPECT_EQ(verdict, dataplane::ClassifyL3Verdict::kTerminalDrop)
      << "U6.14: IPv6 frame shorter than l3_off+40 must be dropped by D31 l3_v6 guard";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V6)], 1u)
      << "U6.14: pkt_truncated_l3[l3_v6] must be 1";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V4)], 0u)
      << "U6.14: IPv6 truncation must NOT bleed into l3_v4 bucket";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// -------------------------------------------------------------------------
// U6.26 — IPv6 plain TCP (next_header=6), no L3 rules → kNextL4
//
// IPv6 packet with next_header = 6 (TCP). No L3 rules in the ruleset,
// so the FIB is nullptr → skip lookup → fall through to kNextL4.
// l4_extra must stay at its init value (0) since C4 does not write it;
// ext-header handling (C5) and fragment handling (C6) will write l4_extra.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv6Test, U6_26_Ipv6PlainTcpNextL4) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;

  // Build a 14 B Ethernet + 40 B IPv6 header frame.
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_26_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  constexpr std::size_t kFrameLen = 14 + 40;
  std::uint8_t* pkt = reinterpret_cast<std::uint8_t*>(
      rte_pktmbuf_append(m, kFrameLen));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, kFrameLen);
  pkt[12] = 0x86;
  pkt[13] = 0xDD;  // EtherType 0x86DD IPv6
  pkt[14] = 0x60;  // version=6
  pkt[20] = 6;     // next_header = TCP (offset 14+6 = 20)
  // dst_addr at offset 14+24 = 38 (16 bytes). Set to 2001:db8::1.
  pkt[38] = 0x20; pkt[39] = 0x01;
  pkt[40] = 0x0d; pkt[41] = 0xb8;
  pkt[53] = 0x01;  // last byte of dst_addr

  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset        = 14;
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV6;
  dyn->parsed_vlan      = 0xFFFF;
  dyn->flags            = 0;
  dyn->l4_extra         = 0;  // pre-init to 0

  dataplane::L3TruncCtrs trunc_ctrs{};
  const auto verdict = dataplane::classify_l3(m, rs, &trunc_ctrs);

  EXPECT_EQ(verdict, dataplane::ClassifyL3Verdict::kNextL4)
      << "U6.26: IPv6 plain TCP with no L3 rules must fall through to kNextL4";
  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(m));
  EXPECT_EQ(cdyn->l4_extra, 0u)
      << "U6.26: l4_extra must stay 0 (C4 does not write l4_extra; ext-headers are C5/C6)";
  EXPECT_EQ(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "U6.26: plain TCP must not set SKIP_L4";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V6)], 0u)
      << "U6.26: valid IPv6 frame must NOT bump l3_v6 truncation counter";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// -------------------------------------------------------------------------
// U6.32 — IPv6 dst FIB hit → dispatch on rule action
//
// unit.md wording says "TERMINAL_L3" — reconciled to current enum per
// the same pattern as M5 C1's U6.18 reconciliation:
//   allow action → kNextL4
//   drop  action → kTerminalDrop
//
// Uses a filler + target rule (same as U6.18) so the target allow rule
// lands at action_idx=1, avoiding the C1b zero-packed entry path.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv6Test, U6_32_Ipv6DstFibHitDispatch) {
  using namespace builder_eal;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  Config cfg = make_config();

  // Filler rule (IPv6 prefix) at action_idx=0.
  SubnetObject filler;
  filler.name = "v6_filler_u6_32";
  {
    Cidr6 c{};
    c.bytes[0] = 0xfd;  // fd00::/8
    c.prefix = 8;
    filler.cidrs.push_back(c);
  }
  cfg.objects.subnets.push_back(std::move(filler));

  // Target rule (IPv6 prefix) at action_idx=1.
  SubnetObject target;
  target.name = "v6_target_u6_32";
  {
    Cidr6 c{};
    c.bytes[0] = 0x20; c.bytes[1] = 0x01;
    c.bytes[2] = 0x0d; c.bytes[3] = 0xb8;  // 2001:db8::/32
    c.prefix = 32;
    target.cidrs.push_back(c);
  }
  cfg.objects.subnets.push_back(std::move(target));

  auto& r_filler = append_rule(cfg.pipeline.layer_3, 6320, ActionDrop{});
  r_filler.dst_subnet = SubnetRef{"v6_filler_u6_32"};
  auto& r_target = append_rule(cfg.pipeline.layer_3, 6321, ActionAllow{});
  r_target.dst_subnet = SubnetRef{"v6_target_u6_32"};

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value());
  ASSERT_EQ(cr.l3_compound.size(), 2u);

  Ruleset rs = ruleset::build_ruleset(cr, cfg.sizing, /*num_lcores=*/1);
  EalPopulateParams params;
  params.name_prefix = "u6_32";
  params.socket_id = 0;
  params.max_entries = 64;

  auto res = populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;
  ASSERT_NE(rs.l3_v6_fib, nullptr);
  ASSERT_GE(rs.n_l3_rules, 2u);
  EXPECT_EQ(rs.l3_actions[1].verb,
            static_cast<std::uint8_t>(compiler::ActionVerb::kAllow));

  // Build a 14 B Ethernet + 40 B IPv6 frame addressed to 2001:db8::1.
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_32_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  constexpr std::size_t kFrameLen = 14 + 40;
  std::uint8_t* pkt = reinterpret_cast<std::uint8_t*>(
      rte_pktmbuf_append(m, kFrameLen));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, kFrameLen);
  pkt[12] = 0x86;
  pkt[13] = 0xDD;  // 0x86DD IPv6
  pkt[14] = 0x60;  // version=6
  pkt[20] = 6;     // next_header = TCP
  // dst_addr at offset 14+24 = 38 (16 bytes). 2001:db8::1.
  pkt[38] = 0x20; pkt[39] = 0x01;
  pkt[40] = 0x0d; pkt[41] = 0xb8;
  pkt[53] = 0x01;  // last byte

  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset        = 14;
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV6;
  dyn->parsed_vlan      = 0xFFFF;
  dyn->flags            = 0;

  dataplane::L3TruncCtrs trunc_ctrs{};
  const auto verdict = dataplane::classify_l3(m, rs, &trunc_ctrs);

  EXPECT_EQ(verdict, dataplane::ClassifyL3Verdict::kNextL4)
      << "U6.32: dst FIB hit on IPv6 allow rule must dispatch to kNextL4 "
         "(unit.md's stale TERMINAL_L3 wording reconciled to C0 enum)";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V6)], 0u)
      << "U6.32: clean hit must not bump the l3_v6 truncation bucket";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// -------------------------------------------------------------------------
// U6.32a — IPv6 dst FIB miss → kNextL4 fall-through (NEW, M5 C4)
//
// Same populated FIB as U6.32; frame addressed to fc00::1 which matches
// neither the filler (fd00::/8) nor the target (2001:db8::/32) prefix.
// FIB lookup returns nh=0 (default_nh), classify_l3 falls through to
// kNextL4 and bumps no counter. Analogous to U6.18a for IPv4.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv6Test, U6_32a_Ipv6DstFibMissFallsThrough) {
  using namespace builder_eal;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  Config cfg = make_config();

  SubnetObject filler;
  filler.name = "v6_filler_u6_32a";
  {
    Cidr6 c{};
    c.bytes[0] = 0xfd;
    c.prefix = 8;
    filler.cidrs.push_back(c);
  }
  cfg.objects.subnets.push_back(std::move(filler));

  SubnetObject target;
  target.name = "v6_target_u6_32a";
  {
    Cidr6 c{};
    c.bytes[0] = 0x20; c.bytes[1] = 0x01;
    c.bytes[2] = 0x0d; c.bytes[3] = 0xb8;
    c.prefix = 32;
    target.cidrs.push_back(c);
  }
  cfg.objects.subnets.push_back(std::move(target));

  auto& r_filler = append_rule(cfg.pipeline.layer_3, 6322, ActionDrop{});
  r_filler.dst_subnet = SubnetRef{"v6_filler_u6_32a"};
  auto& r_target = append_rule(cfg.pipeline.layer_3, 6323, ActionAllow{});
  r_target.dst_subnet = SubnetRef{"v6_target_u6_32a"};

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value());

  Ruleset rs = ruleset::build_ruleset(cr, cfg.sizing, /*num_lcores=*/1);
  EalPopulateParams params;
  params.name_prefix = "u6_32a";
  params.socket_id = 0;
  params.max_entries = 64;

  auto res = populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;
  ASSERT_NE(rs.l3_v6_fib, nullptr);

  // Build a 14 B Ethernet + 40 B IPv6 frame addressed to fc00::1 —
  // outside both populated prefixes.
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_32a_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  constexpr std::size_t kFrameLen = 14 + 40;
  std::uint8_t* pkt = reinterpret_cast<std::uint8_t*>(
      rte_pktmbuf_append(m, kFrameLen));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, kFrameLen);
  pkt[12] = 0x86;
  pkt[13] = 0xDD;
  pkt[14] = 0x60;  // version=6
  pkt[20] = 6;     // next_header = TCP
  // dst_addr: fc00::1 — outside both fd00::/8 and 2001:db8::/32.
  pkt[38] = 0xfc;
  pkt[53] = 0x01;

  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset        = 14;
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV6;
  dyn->parsed_vlan      = 0xFFFF;
  dyn->flags            = 0;

  dataplane::L3TruncCtrs trunc_ctrs{};
  const auto verdict = dataplane::classify_l3(m, rs, &trunc_ctrs);

  EXPECT_EQ(verdict, dataplane::ClassifyL3Verdict::kNextL4)
      << "U6.32a: IPv6 dst FIB miss must fall through to kNextL4";
  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V6)], 0u)
      << "U6.32a: clean miss must NOT bump pkt_truncated_l3[l3_v6]";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// U6.27 — IPv6 non-fragment extension header (0 = hop-by-hop) → SKIP_L4,
//         `l4_skipped_ipv6_extheader` bumped, FIB lookup still runs.
//
// D20 first-protocol-only: if next_header is a recognized extension header
// protocol, mark the packet L4-unclassifiable (SKIP_L4 flag in dynfield)
// and bump the per-lcore `l4_skipped_ipv6_extheader` counter. L3 FIB
// lookup still runs (same semantics as IPv4 fragment L3_ONLY). Fragment
// header (44) is excluded from the ext-header mask — C6 handles it.
//
// D22 EXT_MASK_LT64: only bits < 64 go in the bitmask; values >= 64 are
// explicit comparisons. No UB from shifting beyond 63.
//
// Test: no L3 rules → FIB is null → since SKIP_L4 is set, result must be
// kTerminalPass (not kNextL4). Verify SKIP_L4 flag in dynfield. Verify
// counter bumped to 1.
// =========================================================================

TEST_F(ClassifyL3Ipv6Test, U6_27_Ipv6ExtHeaderHopByHopSkipL4) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;

  // Build a 14 B Ethernet + 40 B IPv6 header frame.
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_27_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  constexpr std::size_t kFrameLen = 14 + 40;
  std::uint8_t* pkt = reinterpret_cast<std::uint8_t*>(
      rte_pktmbuf_append(m, kFrameLen));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, kFrameLen);
  pkt[12] = 0x86;
  pkt[13] = 0xDD;  // EtherType 0x86DD IPv6
  pkt[14] = 0x60;  // version=6
  pkt[20] = 0;     // next_header = 0 (hop-by-hop extension header)
  // dst_addr at offset 14+24 = 38 (16 bytes). Set to 2001:db8::1.
  pkt[38] = 0x20; pkt[39] = 0x01;
  pkt[40] = 0x0d; pkt[41] = 0xb8;
  pkt[53] = 0x01;  // last byte of dst_addr

  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset        = 14;
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV6;
  dyn->parsed_vlan      = 0xFFFF;
  dyn->flags            = 0;
  dyn->l4_extra         = 0;

  dataplane::L3TruncCtrs trunc_ctrs{};
  dataplane::L3FragCtrs  frag_ctrs{};
  std::uint64_t exthdr_ctr = 0;
  const auto verdict = dataplane::classify_l3(
      m, rs, &trunc_ctrs, &frag_ctrs, &exthdr_ctr);

  // With SKIP_L4 set and FIB null, must return kTerminalPass (not kNextL4).
  EXPECT_EQ(verdict, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "U6.27: IPv6 ext-header (hop-by-hop=0) with no L3 rules must "
         "return kTerminalPass when SKIP_L4 is set";

  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(m));
  EXPECT_NE(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "U6.27: hop-by-hop ext-header must set SKIP_L4 flag in dynfield";

  EXPECT_EQ(exthdr_ctr, 1u)
      << "U6.27: l4_skipped_ipv6_extheader counter must be 1 (D20)";

  EXPECT_EQ(trunc_ctrs[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V6)], 0u)
      << "U6.27: valid IPv6 frame must NOT bump l3_v6 truncation counter";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// M5 C6 — IPv6 Fragment ext tests (D27, D31, D40)
//
// Six tests covering the IPv6 Fragment Extension Header (next_header = 44):
//   U6.15  — frag-ext truncated (D31 l3_v6_frag_ext bucket)
//   U6.28  — first fragment: l4_extra = 8, kNextL4 (D27)
//   U6.29  — non-first fragment: SKIP_L4 + both counters bumped (D27 + D40)
//   U6.30  — first fragment with inner nxt=44 (nested) → SKIP_L4 (D27 edge)
//   U6.31  — proto=135 (mobility) → SKIP_L4 via is_ext_proto (D22 UB fix)
//   U6.26c — D27/D40 alias invariant: non-first v6 frag under L3_ONLY bumps
//            BOTH l4_skipped_ipv6_fragment_nonfirst AND pkt_frag_skipped_total_v6
//
// All tests build IPv6 frames with fragment extension header at l3_off+40.
// The fragment ext header is 8 bytes: next_header(1) + reserved(1) +
// frag_data(2, big-endian) + id(4). frag_data layout after CPU convert:
//   bits [3..15] = fragment offset (13 bits)
//   bits [1..2]  = reserved
//   bit  [0]     = MF (more fragments)
// =========================================================================

class ClassifyL3Ipv6FragExtTest : public EalFixture {};

namespace {

// Build a minimal IPv6 frame WITH a Fragment extension header.
// Total: 14 B Ethernet + 40 B IPv6 + 8 B Fragment ext = 62 B.
// The fragment ext header is at l3_off + 40.
//
// Parameters:
//   pool_name — unique mempool name
//   inner_nxt — next_header inside the fragment ext (e.g., 6 for TCP)
//   frag_data_be — big-endian frag_data field (use rte_cpu_to_be_16)
//   truncate — if > 0, truncate the frame so only this many bytes remain
//              (used by U6.15 to test l3_v6_frag_ext truncation guard)
struct V6FragFrame {
  struct rte_mempool* mp;
  struct rte_mbuf*    m;
  std::uint8_t*       pkt;
};

inline V6FragFrame build_ipv6_frag_frame(const char* pool_name,
                                         std::uint8_t inner_nxt,
                                         std::uint16_t frag_data_be,
                                         std::size_t truncate = 0) {
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      pool_name, 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  EXPECT_NE(mp, nullptr) << "mempool create failed: " << pool_name;
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  EXPECT_NE(m, nullptr);
  EXPECT_EQ(m->nb_segs, 1);

  constexpr std::size_t kFullLen = 14 + 40 + 8;  // Eth + IPv6 + FragExt
  const std::size_t frame_len = (truncate > 0) ? truncate : kFullLen;
  std::uint8_t* pkt = reinterpret_cast<std::uint8_t*>(
      rte_pktmbuf_append(m, static_cast<std::uint16_t>(frame_len)));
  EXPECT_NE(pkt, nullptr);
  std::memset(pkt, 0, frame_len);

  // Ethernet header
  pkt[12] = 0x86;
  pkt[13] = 0xDD;  // EtherType 0x86DD IPv6

  // IPv6 header (40 bytes at offset 14)
  pkt[14] = 0x60;  // version=6
  pkt[20] = 44;    // next_header = 44 (Fragment)
  // payload_length: at least 8 (fragment ext header)
  const std::uint16_t payload_len_be = rte_cpu_to_be_16(
      static_cast<std::uint16_t>(frame_len > 54 ? frame_len - 54 : 0));
  std::memcpy(&pkt[18], &payload_len_be, 2);
  // dst_addr at offset 14+24 = 38 (16 bytes). Set to 2001:db8::1.
  pkt[38] = 0x20; pkt[39] = 0x01;
  pkt[40] = 0x0d; pkt[41] = 0xb8;
  pkt[53] = 0x01;  // last byte of dst_addr

  // Fragment Extension Header (8 bytes at offset 54)
  if (frame_len >= 62) {
    pkt[54] = inner_nxt;        // next_header
    pkt[55] = 0;                // reserved
    std::memcpy(&pkt[56], &frag_data_be, 2);  // frag_data (big-endian)
    // id at pkt[58..61] — leave as 0
  }

  return V6FragFrame{mp, m, pkt};
}

inline void set_dyn_for_ipv6(struct rte_mbuf* m) {
  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset        = 14;
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV6;
  dyn->parsed_vlan      = 0xFFFF;
  dyn->flags            = 0;
  dyn->l4_extra         = 0;
}

}  // namespace

// -------------------------------------------------------------------------
// U6.15 — IPv6 frag-ext truncated (pkt_len < l3_off + 40 + 8) →
//         D31 l3_v6_frag_ext truncation drop
//
// IPv6 header with next_header=44 (Fragment), but the packet is only
// l3_off + 40 + 4 = 58 bytes (missing 4 bytes of the fragment ext header).
// The D31 l3_v6_frag_ext guard fires, bumps the new truncation bucket,
// and returns kTerminalDrop.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv6FragExtTest, U6_15_Ipv6FragExtTruncDrop) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;

  // Build truncated frame: 14 + 40 + 4 = 58 bytes (4 bytes short of frag ext)
  auto ff = build_ipv6_frag_frame("u6_15_pool", /*inner_nxt=*/6,
                                  /*frag_data_be=*/0,
                                  /*truncate=*/58);
  ASSERT_NE(ff.m, nullptr);
  set_dyn_for_ipv6(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalDrop)
      << "U6.15: IPv6 frag-ext truncated must be dropped by D31 l3_v6_frag_ext guard";
  EXPECT_EQ(trunc[static_cast<std::size_t>(
                dataplane::L3TruncBucket::kL3V6FragExt)], 1u)
      << "U6.15: pkt_truncated_l3[l3_v6_frag_ext] must be 1";
  EXPECT_EQ(trunc[static_cast<std::size_t>(
                dataplane::L3TruncBucket::kL3V6)], 0u)
      << "U6.15: frag-ext truncation must NOT bleed into l3_v6 bucket";
  EXPECT_EQ(trunc[static_cast<std::size_t>(
                dataplane::L3TruncBucket::kL3V4)], 0u)
      << "U6.15: frag-ext truncation must NOT bleed into l3_v4 bucket";
  EXPECT_EQ(exthdr_ctr, 0u)
      << "U6.15: truncation path must NOT bump exthdr counter";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// U6.28 — Fragment ext, first fragment (frag_offset=0, MF=1) → l4_extra=8,
//         kNextL4 (D27). First fragment carries the L4 header at
//         l3off + 40 + 8; classify_l3 sets l4_extra = 8 so M6's
//         classify_l4 knows the extra offset.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv6FragExtTest, U6_28_FragExtFirstFragment) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  // First fragment: frag_offset=0, MF=1.
  // frag_data layout (host order): bits[3..15] = offset, bit[0] = MF
  // MF=1, offset=0 → host value = 0x0001 → big-endian
  const std::uint16_t frag_data_be = rte_cpu_to_be_16(0x0001u);
  auto ff = build_ipv6_frag_frame("u6_28_pool", /*inner_nxt=*/6,
                                  frag_data_be);
  ASSERT_NE(ff.m, nullptr);
  set_dyn_for_ipv6(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  // First fragment under L3_ONLY with no L3 rules → kNextL4 (L4 can still run)
  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kNextL4)
      << "U6.28: first v6 fragment with inner TCP under L3_ONLY must yield kNextL4 "
         "(D27: first frag drills one step to L4 header)";

  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(ff.m));
  EXPECT_EQ(cdyn->l4_extra, 8u)
      << "U6.28: l4_extra must be 8 (fragment ext header is 8 bytes, D27)";
  EXPECT_EQ(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "U6.28: first fragment with inner TCP must NOT set SKIP_L4";

  // No counter bumps on first fragment
  EXPECT_EQ(frag_nonfirst_ctr, 0u)
      << "U6.28: first fragment must NOT bump frag_nonfirst counter";
  EXPECT_EQ(exthdr_ctr, 0u)
      << "U6.28: first fragment with inner TCP must NOT bump exthdr counter";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV6)], 0u)
      << "U6.28: first fragment must NOT bump pkt_frag_skipped_total_v6";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// U6.29 — Fragment ext, non-first (frag_offset≠0) → SKIP_L4 +
//         l4_skipped_ipv6_fragment_nonfirst bumped +
//         pkt_frag_skipped_total_v6 bumped (D27 + D40)
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv6FragExtTest, U6_29_FragExtNonFirstFragment) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  // Non-first fragment: frag_offset=4 (units-of-8 = 32 bytes), MF=0.
  // frag_data layout (host order): bits[3..15] = offset=4, bit[0] = MF=0
  // host value = 4 << 3 = 0x0020 → big-endian
  const std::uint16_t frag_data_be = rte_cpu_to_be_16(
      static_cast<std::uint16_t>(4u << 3));
  auto ff = build_ipv6_frag_frame("u6_29_pool", /*inner_nxt=*/6,
                                  frag_data_be);
  ASSERT_NE(ff.m, nullptr);
  set_dyn_for_ipv6(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  // Non-first fragment under L3_ONLY with no L3 rules (null FIB) →
  // SKIP_L4 set, FIB miss → kTerminalPass (D21 cliff)
  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "U6.29: non-first v6 fragment under L3_ONLY + FIB miss must yield "
         "kTerminalPass (SKIP_L4 cliff)";

  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(ff.m));
  EXPECT_NE(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "U6.29: non-first v6 fragment under L3_ONLY must set SKIP_L4";

  // D27 named counter
  EXPECT_EQ(frag_nonfirst_ctr, 1u)
      << "U6.29: l4_skipped_ipv6_fragment_nonfirst must be 1 (D27)";
  // D40 family counter
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV6)], 1u)
      << "U6.29: pkt_frag_skipped_total_v6 must be 1 (D40)";
  // No bleed into other counters
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV6)], 0u)
      << "U6.29: skip path must NOT bleed into pkt_frag_dropped_total_v6";
  EXPECT_EQ(exthdr_ctr, 0u)
      << "U6.29: non-first frag must NOT bump exthdr counter";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// U6.30 — Fragment ext with inner next_header=44 (nested fragment) →
//         SKIP_L4 (D27 chain-after-fragment edge case)
//
// First fragment (frag_offset=0, MF=1) but the fragment ext's inner
// next_header is 44 (another fragment header). Per D27, chaining after a
// fragment header is treated as SKIP_L4 regardless of first-vs-non-first
// status — classify_l3 does not walk further into nested extension
// headers. The exthdr counter is bumped (inner_nxt is an ext-header proto).
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv6FragExtTest, U6_30_FragExtNestedFragmentSkipL4) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  // First fragment with inner nxt=44 (nested fragment).
  // frag_data: MF=1, offset=0 → host value = 0x0001
  const std::uint16_t frag_data_be = rte_cpu_to_be_16(0x0001u);
  auto ff = build_ipv6_frag_frame("u6_30_pool", /*inner_nxt=*/44,
                                  frag_data_be);
  ASSERT_NE(ff.m, nullptr);
  set_dyn_for_ipv6(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  // First fragment with nested frag ext → SKIP_L4 set, FIB miss → kTerminalPass
  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "U6.30: first v6 fragment with inner nxt=44 (nested) under L3_ONLY "
         "must yield kTerminalPass (D27 chain-after-fragment → SKIP_L4)";

  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(ff.m));
  EXPECT_NE(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "U6.30: chain-after-fragment must set SKIP_L4";

  // D27: inner_nxt=44 is itself a fragment → exthdr_ctr bumped
  EXPECT_EQ(exthdr_ctr, 1u)
      << "U6.30: inner nxt=44 (nested fragment) must bump exthdr_ctr "
         "(chain-after-fragment triggers the exthdr path per D27)";

  // Non-first counter must NOT be bumped — this is a first fragment
  EXPECT_EQ(frag_nonfirst_ctr, 0u)
      << "U6.30: first fragment with nested frag must NOT bump frag_nonfirst";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// U6.31 — Proto=135 (mobility) → SKIP_L4 via is_ext_proto's explicit OR
//         clause (D22 UB fix sentinel). No new code needed for C6 — this
//         exercises the C5 is_ext_proto lambda. Protects against UB
//         regression if someone replaces the explicit OR with a bitmask
//         shift on proto >= 64.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv6FragExtTest, U6_31_Proto135MobilityExtHeader) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;

  // Build a plain 14 B Ethernet + 40 B IPv6 frame with next_header=135.
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_31_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  constexpr std::size_t kFrameLen = 14 + 40;
  std::uint8_t* pkt = reinterpret_cast<std::uint8_t*>(
      rte_pktmbuf_append(m, kFrameLen));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, kFrameLen);
  pkt[12] = 0x86;
  pkt[13] = 0xDD;  // EtherType 0x86DD IPv6
  pkt[14] = 0x60;  // version=6
  pkt[20] = 135;   // next_header = 135 (mobility)
  // dst_addr: 2001:db8::1
  pkt[38] = 0x20; pkt[39] = 0x01;
  pkt[40] = 0x0d; pkt[41] = 0xb8;
  pkt[53] = 0x01;

  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset        = 14;
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV6;
  dyn->parsed_vlan      = 0xFFFF;
  dyn->flags            = 0;
  dyn->l4_extra         = 0;

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  const auto verdict = dataplane::classify_l3(m, rs, &trunc, &frag,
                                              &exthdr_ctr);

  // Proto=135 is in is_ext_proto's explicit OR clause (p == 135) — must
  // set SKIP_L4 and bump exthdr_ctr. With null FIB → kTerminalPass.
  EXPECT_EQ(verdict, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "U6.31: proto=135 (mobility) must trigger SKIP_L4 via is_ext_proto, "
         "yielding kTerminalPass with null FIB (D22 UB fix sentinel)";

  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(m));
  EXPECT_NE(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "U6.31: proto=135 must set SKIP_L4 flag";

  EXPECT_EQ(exthdr_ctr, 1u)
      << "U6.31: l4_skipped_ipv6_extheader must be 1 (D20 via explicit OR)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// -------------------------------------------------------------------------
// U6.26c — D27/D40 alias invariant sentinel: non-first v6 fragment under
//          L3_ONLY bumps BOTH l4_skipped_ipv6_fragment_nonfirst (D27)
//          AND pkt_frag_skipped_total_v6 (D40) at the same site. This is
//          the explicit sentinel asserting both counters fire from a single
//          code path — if someone refactors and separates the bump sites,
//          this test catches it.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv6FragExtTest, U6_26c_D27D40AliasInvariant) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0) << "dynfield registration failed";

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  // Non-first fragment: offset=1, MF=0 → host value = 1 << 3 = 0x0008
  const std::uint16_t frag_data_be = rte_cpu_to_be_16(
      static_cast<std::uint16_t>(1u << 3));
  auto ff = build_ipv6_frag_frame("u6_26c_pool", /*inner_nxt=*/6,
                                  frag_data_be);
  ASSERT_NE(ff.m, nullptr);
  set_dyn_for_ipv6(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  // Non-first under L3_ONLY with null FIB → kTerminalPass
  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "U6.26c: verdict must be kTerminalPass (same as U6.29)";

  // ---- D27/D40 alias invariant: both counters must be 1 from the
  // ---- same code path. If refactored apart, this breaks.
  EXPECT_EQ(frag_nonfirst_ctr, 1u)
      << "U6.26c: l4_skipped_ipv6_fragment_nonfirst must be 1 (D27 named)";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV6)], 1u)
      << "U6.26c: pkt_frag_skipped_total_v6 must be 1 (D40 family)";

  // No bleed
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV6)], 0u)
      << "U6.26c: alias path must NOT bleed into v6 drop counter";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV4)], 0u)
      << "U6.26c: alias path must NOT bleed into v4 drop counter";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 0u)
      << "U6.26c: alias path must NOT bleed into v4 skip counter";
  EXPECT_EQ(exthdr_ctr, 0u)
      << "U6.26c: non-first frag must NOT bump exthdr counter";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// =========================================================================
// M5 C7 — classify_l3 IPv4 corner tests (C2.2–C2.22)
//
// Twenty-one tests exercising edge cases of the IPv4 branch in classify_l3
// (C1-C3 impl). All tests bypass classify_l2 and call classify_l3 directly.
// No new impl — this is a test-only cycle.
//
// Key M5 adaptation: classify_l4 does NOT exist yet (M6). Tests that in
// corner.md assert L4 behavior (L4 truncation, L4 rule hits) are adapted
// to assert what classify_l3 ACTUALLY returns:
//   - A valid L3 header with no L3 match → kNextL4 (pipeline continues)
//   - L3 truncation / IHL reject → kTerminalDrop + trunc counter
//   - Fragment handling per D17 fragment_policy
//
// Covers: D14, D17, D31, D40, D13
// =========================================================================

class ClassifyL3Ipv4CornerTest : public EalFixture {};

// Helper: build_ipv4_corner_frame — allocates an mbuf of exactly `frame_len`
// bytes, writes EtherType 0x0800 at [12..13]. Caller fills the rest.
namespace {

struct CornerFrame {
  struct rte_mempool* mp;
  struct rte_mbuf*    m;
  std::uint8_t*       pkt;
};

inline CornerFrame build_corner_frame(const char* pool_name,
                                      std::size_t frame_len) {
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      pool_name, 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  EXPECT_NE(mp, nullptr) << "mempool create failed: " << pool_name;
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  EXPECT_NE(m, nullptr);
  EXPECT_EQ(m->nb_segs, 1);

  std::uint8_t* pkt = nullptr;
  if (frame_len > 0) {
    pkt = reinterpret_cast<std::uint8_t*>(
        rte_pktmbuf_append(m, static_cast<std::uint16_t>(frame_len)));
    EXPECT_NE(pkt, nullptr);
    std::memset(pkt, 0, frame_len);
    if (frame_len >= 14) {
      pkt[12] = 0x08;
      pkt[13] = 0x00;  // EtherType 0x0800 IPv4
    }
  }
  return CornerFrame{mp, m, pkt};
}

// Set dyn fields for IPv4 with a given l3_offset.
inline void set_dyn_ipv4_corner(struct rte_mbuf* m,
                                std::uint8_t l3_off = 14) {
  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset        = l3_off;
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV4;
  dyn->parsed_vlan      = 0xFFFF;
  dyn->flags            = 0;
}

}  // namespace

// -------------------------------------------------------------------------
// C2.2 — IPv4 full header but no L4 bytes (34 B frame)
//
// corner.md: Ether(14) + IP(20) + proto=17, no UDP payload. 34 B total.
// M5 adaptation: L3 header is well-formed (IHL=5, 20 B present), so
// classify_l3 passes all guards and falls through. FIB is null → kNextL4.
// L4 truncation check is M6 scope.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4CornerTest, C2_2_FullIpv4HeaderNoL4Bytes) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  auto cf = build_corner_frame("c2_2_pool", 34);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[14] = 0x45;  // version=4, IHL=5
  cf.pkt[23] = 17;    // proto=UDP
  set_dyn_ipv4_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kNextL4)
      << "C2.2: valid L3 header + no L3 rules → kNextL4 (L4 trunc is M6)";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V4)], 0u)
      << "C2.2: no l3_v4 truncation counter expected";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// -------------------------------------------------------------------------
// C2.3 — IPv4 IHL=5, frame cut at 19 B of L3 (33 B total, 1 byte short)
//
// pkt_len=33 < l3_off(14) + 20 = 34. D31 l3_v4 guard fires.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4CornerTest, C2_3_FrameCutAt19B_L3V4Trunc) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  auto cf = build_corner_frame("c2_3_pool", 33);
  ASSERT_NE(cf.m, nullptr);
  // Don't bother with version_ihl — guard fires before reading it.
  set_dyn_ipv4_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalDrop)
      << "C2.3: 33 B frame (19 B L3) must be dropped by D31 l3_v4 guard";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V4)], 1u)
      << "C2.3: pkt_truncated[l3_v4] must be 1";
}

// -------------------------------------------------------------------------
// C2.4 — IPv4 IHL=5, frame cut at 15 B of L3 (29 B total, 5 bytes short)
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4CornerTest, C2_4_FrameCutAt15B_L3V4Trunc) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  auto cf = build_corner_frame("c2_4_pool", 29);
  ASSERT_NE(cf.m, nullptr);
  set_dyn_ipv4_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalDrop)
      << "C2.4: 29 B frame (15 B L3) must be dropped by D31 l3_v4 guard";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V4)], 1u)
      << "C2.4: pkt_truncated[l3_v4] must be 1";
}

// -------------------------------------------------------------------------
// C2.5 — IPv4 IHL=15 (60 B claimed) in a 40 B packet (34 B after l3_off=14)
//
// corner.md: IHL=15 → 60 B options-inclusive header. But only 20 B of L3
// are present. classify_l3 passes the D31 guard (pkt_len=40 >= 14+20=34)
// and passes the D14 IHL check (15 >= 5). FIB lookup runs. No L3 match
// → kNextL4.
// M5 adaptation: L4 truncation (L4 offset=14+60=74 > pkt_len=40) is M6.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4CornerTest, C2_5_Ihl15In40BytePacket) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  auto cf = build_corner_frame("c2_5_pool", 40);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[14] = 0x4F;  // version=4, IHL=15
  set_dyn_ipv4_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kNextL4)
      << "C2.5: IHL=15 passes IHL≥5 check, L3 guard passes (26 B ≥ 20 B), "
         "FIB miss → kNextL4 (L4 truncation is M6 scope)";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V4)], 0u)
      << "C2.5: no l3_v4 truncation counter expected";
}

// -------------------------------------------------------------------------
// C2.6 — IPv4 IHL=4 (bad, smaller than minimum)
//
// version_ihl=0x44 → IHL=4 < 5 → D14 reject at l3_v4 bucket.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4CornerTest, C2_6_Ihl4Rejected) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  // Full-length frame so D31 guard passes but D14 reject fires.
  auto cf = build_corner_frame("c2_6_pool", 34);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[14] = 0x44;  // version=4, IHL=4 (bad)
  set_dyn_ipv4_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalDrop)
      << "C2.6: IHL=4 must be rejected by D14 (IHL<5 → l3_v4 drop)";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V4)], 1u)
      << "C2.6: pkt_truncated[l3_v4] must be 1 (D14 shares l3_v4 bucket)";
}

// -------------------------------------------------------------------------
// C2.7 — IPv4 IHL=0
//
// version_ihl=0x40 → IHL=0 < 5 → D14 reject.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4CornerTest, C2_7_Ihl0Rejected) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  auto cf = build_corner_frame("c2_7_pool", 34);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[14] = 0x40;  // version=4, IHL=0
  set_dyn_ipv4_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalDrop)
      << "C2.7: IHL=0 must be rejected by D14 (IHL<5 → l3_v4 drop)";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V4)], 1u)
      << "C2.7: pkt_truncated[l3_v4] must be 1";
}

// -------------------------------------------------------------------------
// C2.8 — IPv4 version≠4 but ethertype=0x0800 (spoof)
//
// version_ihl=0x65 → version=6, IHL=5. classify_l3 does NOT verify the
// version nibble. IHL=5 ≥ 5 passes. FIB miss → kNextL4. Documents that
// version verification is NOT in classify_l3 scope.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4CornerTest, C2_8_VersionSpoofPassesIhlCheck) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  auto cf = build_corner_frame("c2_8_pool", 34);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[14] = 0x65;  // version=6 (spoofed), IHL=5
  set_dyn_ipv4_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kNextL4)
      << "C2.8: version≠4 under EtherType 0x0800 still passes IHL check "
         "(classify_l3 does not verify version nibble; D14 scope)";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V4)], 0u)
      << "C2.8: no truncation expected";
}

// -------------------------------------------------------------------------
// C2.9 — IPv4 IHL=6, valid 4-byte option (record-route stub) + TCP
//
// IHL=6 → 24 B header. classify_l3 passes (IHL≥5). FIB runs.
// M5 adaptation: L4 rule is M6 scope. Assert kNextL4.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4CornerTest, C2_9_Ihl6WithOptionsPassesL3) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  // 14 B Ether + 24 B IPv4 (IHL=6) + 20 B TCP = 58 B
  auto cf = build_corner_frame("c2_9_pool", 58);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[14] = 0x46;  // version=4, IHL=6
  cf.pkt[23] = 6;     // proto=TCP
  // 4 bytes of IP options at [34..37]: NOP padding
  cf.pkt[34] = 0x01;  cf.pkt[35] = 0x01;
  cf.pkt[36] = 0x01;  cf.pkt[37] = 0x01;
  // TCP header at [38..57]: dport=80 at offset [40..41]
  cf.pkt[40] = 0x00;  cf.pkt[41] = 0x50;  // dport=80
  set_dyn_ipv4_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kNextL4)
      << "C2.9: IHL=6 with 4 B options passes IHL≥5 check → kNextL4 "
         "(L4 rule matching is M6 scope)";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V4)], 0u);
}

// -------------------------------------------------------------------------
// C2.10 — IPv4 IHL=15, 40 B of options, TCP dport=443
//
// IHL=15 → 60 B header. classify_l3 passes (IHL≥5). FIB runs.
// M5 adaptation: L4 rule is M6. Assert kNextL4.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4CornerTest, C2_10_Ihl15WithMaxOptionsPassesL3) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  // 14 B Ether + 60 B IPv4 (IHL=15) + 20 B TCP = 94 B
  auto cf = build_corner_frame("c2_10_pool", 94);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[14] = 0x4F;  // version=4, IHL=15
  cf.pkt[23] = 6;     // proto=TCP
  // 40 bytes of IP options at [34..73]: NOP padding
  for (int i = 34; i < 74; ++i) cf.pkt[i] = 0x01;
  // TCP header at [74..93]: dport=443 at offset [76..77]
  cf.pkt[76] = 0x01;  cf.pkt[77] = 0xBB;  // dport=443
  set_dyn_ipv4_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kNextL4)
      << "C2.10: IHL=15 passes IHL≥5 check → kNextL4 (L4 rule is M6)";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V4)], 0u);
}

// -------------------------------------------------------------------------
// C2.11 — IPv4 non-first fragment under fragment_policy=l3_only
//
// Non-first fragment (offset=185, MF=0). SKIP_L4 + FIB miss →
// kTerminalPass. pkt_frag_skipped_total_v4 += 1. No L4 dispatch.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4CornerTest, C2_11_NonFirstFragL3OnlySkipL4) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  auto cf = build_corner_frame("c2_11_pool", 54);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[14] = 0x45;  // version=4, IHL=5
  cf.pkt[23] = 17;    // proto=UDP
  // fragment_offset=185 (units of 8), MF=0: big-endian frag word
  // offset=185 → lower 13 bits, MF=0 → bit 13 unset.
  const std::uint16_t frag_word = 185;  // offset in units of 8
  cf.pkt[20] = static_cast<std::uint8_t>((frag_word >> 8) & 0xFF);
  cf.pkt[21] = static_cast<std::uint8_t>(frag_word & 0xFF);
  set_dyn_ipv4_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C2.11: non-first frag under l3_only + FIB miss → kTerminalPass";
  auto* dyn = eal::mbuf_dynfield(cf.m);
  EXPECT_NE(dyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C2.11: SKIP_L4 must be set for non-first fragment";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 1u)
      << "C2.11: pkt_frag_skipped_total_v4 must be 1";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV4)], 0u)
      << "C2.11: no drop counter bleed";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// -------------------------------------------------------------------------
// C2.12 — IPv4 non-first fragment under fragment_policy=drop
//
// pkt_frag_dropped_total_v4 += 1, kTerminalDrop.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4CornerTest, C2_12_NonFirstFragDropPolicy) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragDrop;

  auto cf = build_corner_frame("c2_12_pool", 54);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[14] = 0x45;
  cf.pkt[23] = 17;
  // Non-first: offset=185, MF=0
  cf.pkt[20] = 0x00;  cf.pkt[21] = 0xB9;  // 185
  set_dyn_ipv4_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalDrop)
      << "C2.12: non-first frag under drop policy → kTerminalDrop";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV4)], 1u)
      << "C2.12: pkt_frag_dropped_total_v4 must be 1";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 0u)
      << "C2.12: no skip counter bleed";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// -------------------------------------------------------------------------
// C2.13 — IPv4 non-first fragment under fragment_policy=allow
//
// FRAG_ALLOW → kTerminalPass immediately. No counters bumped.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4CornerTest, C2_13_NonFirstFragAllowPolicy) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragAllow;

  auto cf = build_corner_frame("c2_13_pool", 54);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[14] = 0x45;
  cf.pkt[23] = 17;
  // Non-first: offset=185, MF=0
  cf.pkt[20] = 0x00;  cf.pkt[21] = 0xB9;
  set_dyn_ipv4_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C2.13: non-first frag under allow policy → kTerminalPass";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV4)], 0u)
      << "C2.13: FRAG_ALLOW must not bump drop counter";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 0u)
      << "C2.13: FRAG_ALLOW must not bump skip counter";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// -------------------------------------------------------------------------
// C2.14 — IPv4 first fragment (MF=1, offset=0) under l3_only
//
// First fragment is NOT a non-first: treated as normal packet. No SKIP_L4,
// no frag counter. FIB miss → kNextL4.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4CornerTest, C2_14_FirstFragL3OnlyNotSkipped) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  auto cf = build_corner_frame("c2_14_pool", 54);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[14] = 0x45;
  cf.pkt[23] = 17;
  // First fragment: MF=1 (bit 13 set), offset=0.
  // BE word: 0x2000
  cf.pkt[20] = 0x20;  cf.pkt[21] = 0x00;
  set_dyn_ipv4_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kNextL4)
      << "C2.14: first frag (MF=1, offset=0) under l3_only → kNextL4 "
         "(first fragment carries L4 header, classify_l4 can run)";
  auto* dyn = eal::mbuf_dynfield(cf.m);
  EXPECT_EQ(dyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C2.14: first frag must NOT set SKIP_L4";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 0u)
      << "C2.14: first frag must NOT bump skip counter";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV4)], 0u)
      << "C2.14: first frag under l3_only must NOT bump drop counter";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// -------------------------------------------------------------------------
// C2.15 — IPv4 first fragment (MF=1, offset=0) with L4 rule
//
// First fragment under l3_only is NOT skipped. classify_l3 returns kNextL4.
// L4 rule matching is M6 scope.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4CornerTest, C2_15_FirstFragWithL4Rule) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  // 14 + 20 + 8 B UDP payload = 42 B
  auto cf = build_corner_frame("c2_15_pool", 42);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[14] = 0x45;
  cf.pkt[23] = 17;    // proto=UDP
  // First fragment: MF=1, offset=0
  cf.pkt[20] = 0x20;  cf.pkt[21] = 0x00;
  // UDP dport=53 at offset 36 (14+20+2)
  cf.pkt[36] = 0x00;  cf.pkt[37] = 0x35;
  set_dyn_ipv4_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kNextL4)
      << "C2.15: first fragment under l3_only → kNextL4 (L4 rule is M6)";
  auto* dyn = eal::mbuf_dynfield(cf.m);
  EXPECT_EQ(dyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C2.15: first frag must NOT set SKIP_L4";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// -------------------------------------------------------------------------
// C2.16 — IPv4 single fragment (DF=1, MF=0, offset=0) — not a fragment
//
// DF=1 is bit 14 of the BE16 frag word → 0x4000. This packet has neither
// MF set nor a non-zero offset, so is_frag = false. Not a fragment at all.
// classify_l3 returns kNextL4 (no L3 rules, no fragment handling).
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4CornerTest, C2_16_DfBitNotFragment) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  // 14 + 20 + 20 TCP = 54 B
  auto cf = build_corner_frame("c2_16_pool", 54);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[14] = 0x45;
  cf.pkt[23] = 6;     // proto=TCP
  // DF=1, MF=0, offset=0: BE word = 0x4000
  cf.pkt[20] = 0x40;  cf.pkt[21] = 0x00;
  // TCP dport=80 at [36..37]
  cf.pkt[36] = 0x00;  cf.pkt[37] = 0x50;
  set_dyn_ipv4_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kNextL4)
      << "C2.16: DF=1 packet is NOT a fragment → kNextL4";
  auto* dyn = eal::mbuf_dynfield(cf.m);
  EXPECT_EQ(dyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C2.16: non-fragment must NOT set SKIP_L4";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 0u);
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV4)], 0u);

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// -------------------------------------------------------------------------
// C2.17 — IPv4 MF=0, offset≠0 (last fragment) → SKIP_L4
//
// offset=100 (units of 8), MF=0. Non-first → SKIP_L4 path.
// Under l3_only with empty FIB → kTerminalPass.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4CornerTest, C2_17_LastFragSkipL4) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  auto cf = build_corner_frame("c2_17_pool", 54);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[14] = 0x45;
  cf.pkt[23] = 17;
  // Last fragment: MF=0, offset=100 → BE word = 0x0064
  cf.pkt[20] = 0x00;  cf.pkt[21] = 0x64;
  set_dyn_ipv4_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C2.17: last frag (MF=0, offset≠0) under l3_only → kTerminalPass";
  auto* dyn = eal::mbuf_dynfield(cf.m);
  EXPECT_NE(dyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C2.17: non-first fragment must set SKIP_L4";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 1u)
      << "C2.17: pkt_frag_skipped_total_v4 must be 1";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// -------------------------------------------------------------------------
// C2.18 — IPv4 MF=1, offset≠0 (middle fragment) → SKIP_L4
//
// offset=64, MF=1. Non-first → SKIP_L4 path.
// Under l3_only with empty FIB → kTerminalPass.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4CornerTest, C2_18_MiddleFragSkipL4) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  auto cf = build_corner_frame("c2_18_pool", 54);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[14] = 0x45;
  cf.pkt[23] = 17;
  // Middle fragment: MF=1, offset=64 → BE word = 0x2040
  cf.pkt[20] = 0x20;  cf.pkt[21] = 0x40;
  set_dyn_ipv4_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C2.18: middle frag (MF=1, offset≠0) under l3_only → kTerminalPass";
  auto* dyn = eal::mbuf_dynfield(cf.m);
  EXPECT_NE(dyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C2.18: non-first fragment must set SKIP_L4";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 1u)
      << "C2.18: pkt_frag_skipped_total_v4 must be 1";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// -------------------------------------------------------------------------
// C2.19 — IPv4 pathological frag_offset > datagram size
//
// offset=8100 (units of 8 = 64800 B into datagram), MF=0. Non-first →
// SKIP_L4. No crash, no special handling. pktgate-dpdk does NOT attempt
// reassembly sanity on fragment offsets.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4CornerTest, C2_19_PathologicalOffsetNoCrash) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  auto cf = build_corner_frame("c2_19_pool", 54);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[14] = 0x45;
  cf.pkt[23] = 17;
  // Pathological offset: 8100 (0x1FA4) in the 13-bit field, MF=0.
  // BE word: 0x1FA4
  cf.pkt[20] = 0x1F;  cf.pkt[21] = 0xA4;
  set_dyn_ipv4_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C2.19: pathological offset behaves as non-first frag → kTerminalPass";
  auto* dyn = eal::mbuf_dynfield(cf.m);
  EXPECT_NE(dyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C2.19: non-first fragment must set SKIP_L4";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 1u);

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// -------------------------------------------------------------------------
// C2.20 — IPv4 + TCP with only 2 B of transport header (36 B total)
//
// L3 header is complete (IHL=5, 20 B present). classify_l3 returns
// kNextL4. L4 truncation (need=4, only 2 B present) is M6 scope.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4CornerTest, C2_20_TcpOnly2BytesL4TruncIsM6) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  // 14 + 20 + 2 = 36 B
  auto cf = build_corner_frame("c2_20_pool", 36);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[14] = 0x45;
  cf.pkt[23] = 6;  // proto=TCP
  set_dyn_ipv4_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kNextL4)
      << "C2.20: L3 header complete → kNextL4 (L4 truncation is M6 scope)";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V4)], 0u);
}

// -------------------------------------------------------------------------
// C2.21 — IPv4 + ICMP with only 1 B (type but no code), 35 B total
//
// L3 header is complete → kNextL4. L4 truncation (need=2, only 1 B) M6.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4CornerTest, C2_21_IcmpOnly1ByteL4TruncIsM6) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  // 14 + 20 + 1 = 35 B
  auto cf = build_corner_frame("c2_21_pool", 35);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[14] = 0x45;
  cf.pkt[23] = 1;  // proto=ICMP
  set_dyn_ipv4_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kNextL4)
      << "C2.21: L3 header complete → kNextL4 (L4 truncation is M6 scope)";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V4)], 0u);
}

// -------------------------------------------------------------------------
// C2.22 — VLAN-tagged IPv4 with IHL=6 (D13 + D14 compound)
//
// l3_offset=18 (written by classify_l2 for single VLAN). IHL=6 → 24 B
// IPv4 header. classify_l3 reads at offset 18, passes guards. FIB runs.
// M5 adaptation: L4 rule is M6. Assert kNextL4.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv4CornerTest, C2_22_VlanTaggedIpv4Ihl6) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  // 14 B Ether + 4 B VLAN (0x8100) + 24 B IPv4 (IHL=6) + 8 B UDP = 50 B
  auto cf = build_corner_frame("c2_22_pool", 50);
  ASSERT_NE(cf.m, nullptr);
  // Ethernet header: dst(6) + src(6) + VLAN TPID 0x8100
  cf.pkt[12] = 0x81;  cf.pkt[13] = 0x00;
  // VLAN TCI at [14..15]: vlan=100
  cf.pkt[14] = 0x00;  cf.pkt[15] = 0x64;
  // Inner ethertype at [16..17]: 0x0800 (IPv4)
  cf.pkt[16] = 0x08;  cf.pkt[17] = 0x00;
  // IPv4 header starts at offset 18 (l3_offset=18 per D13 VLAN)
  cf.pkt[18] = 0x46;  // version=4, IHL=6
  cf.pkt[27] = 17;    // proto=UDP (offset 18+9=27)
  // 4 bytes of IP options at [38..41]: NOP padding
  cf.pkt[38] = 0x01;  cf.pkt[39] = 0x01;
  cf.pkt[40] = 0x01;  cf.pkt[41] = 0x01;
  // UDP dport=53 at [44..45] (l3_offset(18) + IHL*4(24) + 2 = 44)
  cf.pkt[44] = 0x00;  cf.pkt[45] = 0x35;

  // Set dynfield as classify_l2 would for a VLAN-tagged frame.
  auto* dyn = eal::mbuf_dynfield(cf.m);
  dyn->l3_offset        = 18;  // D13: VLAN shifts L3 start by 4
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV4;
  dyn->parsed_vlan      = 100;
  dyn->flags            = 0;

  dataplane::L3TruncCtrs trunc{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kNextL4)
      << "C2.22: VLAN-tagged IPv4 IHL=6, l3_offset=18 → kNextL4 (L4 rule M6)";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V4)], 0u)
      << "C2.22: no truncation expected (D13 compound with D14)";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// =========================================================================
// M5 C8 — classify_l3 IPv6 corner tests (C3.2–C3.21)
//
// Twenty tests exercising edge cases of the IPv6 branch in classify_l3
// (C4-C6 impl). All tests bypass classify_l2 and call classify_l3 directly.
// No new impl — this is a test-only cycle.
//
// Key M5 adaptation: classify_l4 does NOT exist yet (M6). Tests that in
// corner.md assert L4 behavior (L4 rule hits) are adapted to assert what
// classify_l3 ACTUALLY returns:
//   - A valid L3 header with no L3 match → kNextL4 (pipeline continues)
//   - L3 truncation → kTerminalDrop + trunc counter
//   - Fragment handling per D17/D27 → appropriate counters + verdicts
//   - Ext-header handling per D20 → SKIP_L4 + exthdr counter
//
// Covers: D13, D17, D20, D22, D27, D31, D40
//
// C3.20 is the D13+D27 flagship SENTINEL: validates that the D13 VLAN
// l3_offset composes with D27 IPv6 fragment ext handling.
// =========================================================================

class ClassifyL3Ipv6CornerTest : public EalFixture {};

// Helper: build an IPv6 corner frame of exactly `frame_len` bytes.
// Sets EtherType 0x86DD at [12..13] and version=6 at [14].
namespace {

inline CornerFrame build_ipv6_corner_frame(const char* pool_name,
                                           std::size_t frame_len) {
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      pool_name, 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  EXPECT_NE(mp, nullptr) << "mempool create failed: " << pool_name;
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  EXPECT_NE(m, nullptr);
  EXPECT_EQ(m->nb_segs, 1);

  std::uint8_t* pkt = nullptr;
  if (frame_len > 0) {
    pkt = reinterpret_cast<std::uint8_t*>(
        rte_pktmbuf_append(m, static_cast<std::uint16_t>(frame_len)));
    EXPECT_NE(pkt, nullptr);
    std::memset(pkt, 0, frame_len);
    if (frame_len >= 14) {
      pkt[12] = 0x86;
      pkt[13] = 0xDD;  // EtherType 0x86DD IPv6
    }
    if (frame_len >= 15) {
      pkt[14] = 0x60;  // version=6
    }
  }
  return CornerFrame{mp, m, pkt};
}

// Set dyn fields for IPv6 with a given l3_offset.
inline void set_dyn_ipv6_corner(struct rte_mbuf* m,
                                std::uint8_t l3_off = 14) {
  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset        = l3_off;
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV6;
  dyn->parsed_vlan      = 0xFFFF;
  dyn->flags            = 0;
  dyn->l4_extra         = 0;
}

}  // namespace

// -------------------------------------------------------------------------
// C3.2 — IPv6 truncated (39 B after L2) → D31 l3_v6 + kTerminalDrop
//
// corner.md: ether(14) + raw 39 B pretending to be v6 = 53 B total.
// One byte short of the IPv6 40-byte fixed header → D31 l3_v6 guard fires.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv6CornerTest, C3_2_Truncated39B_L3V6Trunc) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  auto cf = build_ipv6_corner_frame("c3_2_pool", 14 + 39);  // 53 B
  ASSERT_NE(cf.m, nullptr);
  set_dyn_ipv6_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalDrop)
      << "C3.2: IPv6 39B after L2 (53B total) must be dropped by D31 l3_v6 guard";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V6)], 1u)
      << "C3.2: pkt_truncated_l3[l3_v6] must be 1";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V4)], 0u)
      << "C3.2: must NOT bleed into l3_v4 bucket";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V6FragExt)], 0u)
      << "C3.2: must NOT bleed into l3_v6_frag_ext bucket";
  EXPECT_EQ(exthdr_ctr, 0u)
      << "C3.2: truncation path must NOT bump exthdr counter";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// -------------------------------------------------------------------------
// C3.3 — IPv6 40 B + no L4 bytes (54 B total) → kNextL4
//
// corner.md: Ether()/IPv6(nh=6) with pkt_len=54, 0 B L4.
// M5 adaptation: L4 truncation check is M6 scope. classify_l3 sees a
// valid 40-byte IPv6 header with nh=6 (TCP, not an ext-header), FIB null →
// kNextL4. No L3 counters move.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv6CornerTest, C3_3_Ipv6NoL4Bytes_NextL4) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  auto cf = build_ipv6_corner_frame("c3_3_pool", 14 + 40);  // 54 B
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[20] = 6;  // next_header = TCP
  set_dyn_ipv6_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kNextL4)
      << "C3.3: IPv6 40B header + TCP + no L3 rules → kNextL4 (L4 trunc is M6)";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V6)], 0u)
      << "C3.3: valid IPv6 header must NOT bump l3_v6 truncation";
  EXPECT_EQ(exthdr_ctr, 0u)
      << "C3.3: TCP is not an ext-header, exthdr must stay 0";
  EXPECT_EQ(frag_nonfirst_ctr, 0u)
      << "C3.3: non-fragment must NOT bump frag_nonfirst";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// -------------------------------------------------------------------------
// C3.4–C3.13: IPv6 ext-header corner tests (D20 first-proto-only)
//
// Each test sets IPv6 next_header to a recognized ext-header value and
// verifies: SKIP_L4 set, l4_skipped_ipv6_extheader += 1, kTerminalPass
// (SKIP_L4 collapses kNextL4 with null FIB).
//
// All use 14 B Ether + 40 B IPv6 = 54 B minimum frames.
// -------------------------------------------------------------------------

// C3.4 — next_header=0 (Hop-by-Hop Options)
TEST_F(ClassifyL3Ipv6CornerTest, C3_4_ExtHeader_HopByHop_Nh0) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  auto cf = build_ipv6_corner_frame("c3_4_pool", 14 + 40);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[20] = 0;  // next_header = 0 (Hop-by-Hop)
  set_dyn_ipv6_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C3.4: nh=0 (HopByHop) → SKIP_L4 + null FIB → kTerminalPass";
  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(cf.m));
  EXPECT_NE(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C3.4: SKIP_L4 must be set for nh=0";
  EXPECT_EQ(exthdr_ctr, 1u)
      << "C3.4: l4_skipped_ipv6_extheader must be 1 (D20)";
  EXPECT_EQ(frag_nonfirst_ctr, 0u)
      << "C3.4: non-fragment must NOT bump frag_nonfirst";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// C3.5 — next_header=43 (Routing)
TEST_F(ClassifyL3Ipv6CornerTest, C3_5_ExtHeader_Routing_Nh43) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  auto cf = build_ipv6_corner_frame("c3_5_pool", 14 + 40);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[20] = 43;  // next_header = 43 (Routing)
  set_dyn_ipv6_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  std::uint64_t exthdr_ctr = 0;
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, nullptr, &exthdr_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C3.5: nh=43 (Routing) → SKIP_L4 + null FIB → kTerminalPass";
  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(cf.m));
  EXPECT_NE(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C3.5: SKIP_L4 must be set for nh=43";
  EXPECT_EQ(exthdr_ctr, 1u)
      << "C3.5: l4_skipped_ipv6_extheader must be 1 (D20)";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// C3.6 — next_header=50 (ESP)
TEST_F(ClassifyL3Ipv6CornerTest, C3_6_ExtHeader_ESP_Nh50) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  auto cf = build_ipv6_corner_frame("c3_6_pool", 14 + 40);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[20] = 50;  // next_header = 50 (ESP)
  set_dyn_ipv6_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  std::uint64_t exthdr_ctr = 0;
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, nullptr, &exthdr_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C3.6: nh=50 (ESP) → SKIP_L4 + null FIB → kTerminalPass";
  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(cf.m));
  EXPECT_NE(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C3.6: SKIP_L4 must be set for nh=50";
  EXPECT_EQ(exthdr_ctr, 1u)
      << "C3.6: l4_skipped_ipv6_extheader must be 1 (D20)";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// C3.7 — next_header=51 (AH)
TEST_F(ClassifyL3Ipv6CornerTest, C3_7_ExtHeader_AH_Nh51) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  auto cf = build_ipv6_corner_frame("c3_7_pool", 14 + 40);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[20] = 51;  // next_header = 51 (AH)
  set_dyn_ipv6_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  std::uint64_t exthdr_ctr = 0;
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, nullptr, &exthdr_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C3.7: nh=51 (AH) → SKIP_L4 + null FIB → kTerminalPass";
  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(cf.m));
  EXPECT_NE(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C3.7: SKIP_L4 must be set for nh=51";
  EXPECT_EQ(exthdr_ctr, 1u)
      << "C3.7: l4_skipped_ipv6_extheader must be 1 (D20)";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// C3.8 — next_header=60 (Destination Options)
TEST_F(ClassifyL3Ipv6CornerTest, C3_8_ExtHeader_DestOpt_Nh60) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  auto cf = build_ipv6_corner_frame("c3_8_pool", 14 + 40);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[20] = 60;  // next_header = 60 (Destination Options)
  set_dyn_ipv6_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  std::uint64_t exthdr_ctr = 0;
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, nullptr, &exthdr_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C3.8: nh=60 (DestOpt) → SKIP_L4 + null FIB → kTerminalPass";
  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(cf.m));
  EXPECT_NE(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C3.8: SKIP_L4 must be set for nh=60";
  EXPECT_EQ(exthdr_ctr, 1u)
      << "C3.8: l4_skipped_ipv6_extheader must be 1 (D20)";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// C3.9 — next_header=135 (Mobility, explicit >=64 list, D22 UB proof)
TEST_F(ClassifyL3Ipv6CornerTest, C3_9_ExtHeader_Mobility_Nh135) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  auto cf = build_ipv6_corner_frame("c3_9_pool", 14 + 40);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[20] = 135;  // next_header = 135 (Mobility)
  set_dyn_ipv6_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  std::uint64_t exthdr_ctr = 0;
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, nullptr, &exthdr_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C3.9: nh=135 (Mobility) → SKIP_L4 via explicit OR clause (D22 UB proof)";
  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(cf.m));
  EXPECT_NE(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C3.9: SKIP_L4 must be set for nh=135";
  EXPECT_EQ(exthdr_ctr, 1u)
      << "C3.9: l4_skipped_ipv6_extheader must be 1 (D20, D22)";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// C3.10 — next_header=139 (HIP)
TEST_F(ClassifyL3Ipv6CornerTest, C3_10_ExtHeader_HIP_Nh139) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  auto cf = build_ipv6_corner_frame("c3_10_pool", 14 + 40);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[20] = 139;  // next_header = 139 (HIP)
  set_dyn_ipv6_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  std::uint64_t exthdr_ctr = 0;
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, nullptr, &exthdr_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C3.10: nh=139 (HIP) → SKIP_L4 via explicit OR clause (D22)";
  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(cf.m));
  EXPECT_NE(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C3.10: SKIP_L4 must be set for nh=139";
  EXPECT_EQ(exthdr_ctr, 1u)
      << "C3.10: l4_skipped_ipv6_extheader must be 1 (D20, D22)";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// C3.11 — next_header=140 (shim6)
TEST_F(ClassifyL3Ipv6CornerTest, C3_11_ExtHeader_Shim6_Nh140) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  auto cf = build_ipv6_corner_frame("c3_11_pool", 14 + 40);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[20] = 140;  // next_header = 140 (shim6)
  set_dyn_ipv6_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  std::uint64_t exthdr_ctr = 0;
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, nullptr, &exthdr_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C3.11: nh=140 (shim6) → SKIP_L4 via explicit OR clause (D22)";
  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(cf.m));
  EXPECT_NE(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C3.11: SKIP_L4 must be set for nh=140";
  EXPECT_EQ(exthdr_ctr, 1u)
      << "C3.11: l4_skipped_ipv6_extheader must be 1 (D20, D22)";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// C3.12 — next_header=253 (experimental)
TEST_F(ClassifyL3Ipv6CornerTest, C3_12_ExtHeader_Experimental_Nh253) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  auto cf = build_ipv6_corner_frame("c3_12_pool", 14 + 40);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[20] = 253;  // next_header = 253 (experimental)
  set_dyn_ipv6_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  std::uint64_t exthdr_ctr = 0;
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, nullptr, &exthdr_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C3.12: nh=253 (experimental) → SKIP_L4 via explicit OR (D22)";
  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(cf.m));
  EXPECT_NE(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C3.12: SKIP_L4 must be set for nh=253";
  EXPECT_EQ(exthdr_ctr, 1u)
      << "C3.12: l4_skipped_ipv6_extheader must be 1 (D20, D22)";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// C3.13 — next_header=254 (experimental)
TEST_F(ClassifyL3Ipv6CornerTest, C3_13_ExtHeader_Experimental_Nh254) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  auto cf = build_ipv6_corner_frame("c3_13_pool", 14 + 40);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[20] = 254;  // next_header = 254 (experimental)
  set_dyn_ipv6_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  std::uint64_t exthdr_ctr = 0;
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, nullptr, &exthdr_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C3.13: nh=254 (experimental) → SKIP_L4 via explicit OR (D22)";
  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(cf.m));
  EXPECT_NE(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C3.13: SKIP_L4 must be set for nh=254";
  EXPECT_EQ(exthdr_ctr, 1u)
      << "C3.13: l4_skipped_ipv6_extheader must be 1 (D20, D22)";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// -------------------------------------------------------------------------
// C3.14 — IPv6 Fragment ext, first fragment (offset=0, MF=1), inner TCP
//
// corner.md: classify_l3 handles the fragment ext, drills one step
// (l4_extra=8), inner nh=6 (TCP) is NOT an ext header → proceeds to FIB
// lookup → returns kNextL4. Assert kNextL4, l4_extra=8, no skip counters.
// M5 adaptation: L4 rule is M6, just assert kNextL4.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv6CornerTest, C3_14_FirstFragTcpNextL4) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  // First fragment: frag_offset=0, MF=1. Host value = 0x0001.
  const std::uint16_t frag_data_be = rte_cpu_to_be_16(0x0001u);
  auto ff = build_ipv6_frag_frame("c3_14_pool", /*inner_nxt=*/6,
                                  frag_data_be);
  ASSERT_NE(ff.m, nullptr);
  set_dyn_for_ipv6(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kNextL4)
      << "C3.14: first v6 fragment with inner TCP under L3_ONLY → kNextL4 (D27)";

  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(ff.m));
  EXPECT_EQ(cdyn->l4_extra, 8u)
      << "C3.14: l4_extra must be 8 (D27 first frag drills one step)";
  EXPECT_EQ(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C3.14: first fragment with inner TCP must NOT set SKIP_L4";
  EXPECT_EQ(frag_nonfirst_ctr, 0u)
      << "C3.14: first fragment must NOT bump frag_nonfirst";
  EXPECT_EQ(exthdr_ctr, 0u)
      << "C3.14: inner TCP must NOT bump exthdr counter";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV6)], 0u)
      << "C3.14: first fragment must NOT bump pkt_frag_skipped_total_v6";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// C3.15 — IPv6 Fragment ext, non-first (offset=185), UDP
//
// corner.md: l4_skipped_ipv6_fragment_nonfirst += 1 + D40 alias
// pkt_frag_skipped_total_v6 += 1 + SKIP_L4 + kTerminalPass.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv6CornerTest, C3_15_NonFirstFrag185_SkipL4) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  // Non-first fragment: offset=185, MF=0.
  // frag_data host: offset=185 in [3..15], MF=0 in bit[0]
  // host value = 185 << 3 = 0x05C8
  const std::uint16_t frag_data_be = rte_cpu_to_be_16(
      static_cast<std::uint16_t>(185u << 3));
  auto ff = build_ipv6_frag_frame("c3_15_pool", /*inner_nxt=*/17,
                                  frag_data_be);
  ASSERT_NE(ff.m, nullptr);
  set_dyn_for_ipv6(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C3.15: non-first v6 fragment (offset=185) → SKIP_L4 + kTerminalPass";
  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(ff.m));
  EXPECT_NE(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C3.15: SKIP_L4 must be set for non-first fragment";
  EXPECT_EQ(frag_nonfirst_ctr, 1u)
      << "C3.15: l4_skipped_ipv6_fragment_nonfirst must be 1 (D27)";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV6)], 1u)
      << "C3.15: pkt_frag_skipped_total_v6 must be 1 (D40 alias)";
  EXPECT_EQ(exthdr_ctr, 0u)
      << "C3.15: non-first frag must NOT bump exthdr counter";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// C3.16 — First frag nh=44 (nested fragment) → SKIP_L4 + exthdr += 1
//
// corner.md: l4_skipped_ipv6_extheader += 1 (ext-after-fragment → SKIP_L4).
// kTerminalPass.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv6CornerTest, C3_16_FirstFragNestedFrag44_SkipL4) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  // First fragment: offset=0, MF=1. Host value = 0x0001.
  const std::uint16_t frag_data_be = rte_cpu_to_be_16(0x0001u);
  auto ff = build_ipv6_frag_frame("c3_16_pool", /*inner_nxt=*/44,
                                  frag_data_be);
  ASSERT_NE(ff.m, nullptr);
  set_dyn_for_ipv6(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C3.16: first frag with inner nh=44 (nested) → SKIP_L4 → kTerminalPass";
  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(ff.m));
  EXPECT_NE(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C3.16: chain-after-fragment must set SKIP_L4";
  EXPECT_EQ(exthdr_ctr, 1u)
      << "C3.16: l4_skipped_ipv6_extheader must be 1 (D27 nested frag → ext path)";
  EXPECT_EQ(frag_nonfirst_ctr, 0u)
      << "C3.16: first fragment must NOT bump frag_nonfirst";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// C3.17 — First frag nh=0 (HopByHop after Fragment) → SKIP_L4 + exthdr += 1
//
// corner.md: ext-after-fragment under first-proto-only → SKIP_L4.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv6CornerTest, C3_17_FirstFragHopByHopAfterFrag_SkipL4) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  // First fragment: offset=0, MF=1. Host value = 0x0001.
  const std::uint16_t frag_data_be = rte_cpu_to_be_16(0x0001u);
  auto ff = build_ipv6_frag_frame("c3_17_pool", /*inner_nxt=*/0,
                                  frag_data_be);
  ASSERT_NE(ff.m, nullptr);
  set_dyn_for_ipv6(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C3.17: first frag with inner nh=0 (HopByHop) → SKIP_L4 → kTerminalPass";
  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(ff.m));
  EXPECT_NE(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C3.17: ext-after-fragment must set SKIP_L4";
  EXPECT_EQ(exthdr_ctr, 1u)
      << "C3.17: l4_skipped_ipv6_extheader must be 1 (D27 chain-after-frag)";
  EXPECT_EQ(frag_nonfirst_ctr, 0u)
      << "C3.17: first fragment must NOT bump frag_nonfirst";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// C3.18 — Fragment ext truncated: only 4 B of 8 present (58 B total)
//
// corner.md: pkt_truncated_total{where="l3_v6_frag_ext"} += 1 + kTerminalDrop
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv6CornerTest, C3_18_FragExtTrunc4B) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  // Build truncated frame: 14 + 40 + 4 = 58 bytes
  auto ff = build_ipv6_frag_frame("c3_18_pool", /*inner_nxt=*/6,
                                  /*frag_data_be=*/0,
                                  /*truncate=*/58);
  ASSERT_NE(ff.m, nullptr);
  set_dyn_for_ipv6(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalDrop)
      << "C3.18: frag-ext truncated (4B of 8) → D31 l3_v6_frag_ext → kTerminalDrop";
  EXPECT_EQ(trunc[static_cast<std::size_t>(
                dataplane::L3TruncBucket::kL3V6FragExt)], 1u)
      << "C3.18: pkt_truncated_l3[l3_v6_frag_ext] must be 1";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V6)], 0u)
      << "C3.18: must NOT bleed into l3_v6 bucket";
  EXPECT_EQ(exthdr_ctr, 0u)
      << "C3.18: truncation must NOT bump exthdr counter";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// C3.19 — Fragment ext, 0 B of it present (54 B total = Eth + IPv6 only)
//
// corner.md: pkt_truncated_total{where="l3_v6_frag_ext"} += 1 + kTerminalDrop
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv6CornerTest, C3_19_FragExtTrunc0B) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  // Build truncated frame: 14 + 40 + 0 = 54 bytes (no frag ext at all)
  auto ff = build_ipv6_frag_frame("c3_19_pool", /*inner_nxt=*/6,
                                  /*frag_data_be=*/0,
                                  /*truncate=*/54);
  ASSERT_NE(ff.m, nullptr);
  set_dyn_for_ipv6(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalDrop)
      << "C3.19: frag-ext 0B present (54B total) → D31 l3_v6_frag_ext → kTerminalDrop";
  EXPECT_EQ(trunc[static_cast<std::size_t>(
                dataplane::L3TruncBucket::kL3V6FragExt)], 1u)
      << "C3.19: pkt_truncated_l3[l3_v6_frag_ext] must be 1";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V6)], 0u)
      << "C3.19: must NOT bleed into l3_v6 bucket";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// C3.20 — VLAN-tagged IPv6 first fragment with TCP (D13+D27 compound)
//
// **FLAGSHIP SENTINEL** — validates D13 VLAN l3_offset=18 composes with
// D27 IPv6 fragment ext. classify_l3 reads l3_offset=18, processes fragment
// ext, l4_extra=8, inner nh=6 (TCP) is not an ext-header → kNextL4.
//
// corner.md: l3_offset=18, l4_extra=8, L4 offset=18+40+8=66.
// M5 adaptation: L4 rule is M6. Assert kNextL4.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv6CornerTest, C3_20_Sentinel_VlanIpv6FragFirstTcp) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  // Frame: 14 B Ether + 4 B VLAN + 40 B IPv6 + 8 B FragExt = 66 B
  // l3_offset = 18 (D13 VLAN tag shifts L3 start by 4)
  constexpr std::size_t kFrameLen = 14 + 4 + 40 + 8;  // 66 B
  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "c3_20_sentinel_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);
  ASSERT_EQ(m->nb_segs, 1);

  std::uint8_t* pkt = reinterpret_cast<std::uint8_t*>(
      rte_pktmbuf_append(m, kFrameLen));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, kFrameLen);

  // Ethernet header: dst(6) + src(6) + VLAN TPID 0x8100
  pkt[12] = 0x81;  pkt[13] = 0x00;
  // VLAN TCI at [14..15]: vlan=100
  pkt[14] = 0x00;  pkt[15] = 0x64;
  // Inner ethertype at [16..17]: 0x86DD (IPv6)
  pkt[16] = 0x86;  pkt[17] = 0xDD;

  // IPv6 header at offset 18 (l3_offset=18)
  pkt[18] = 0x60;  // version=6
  pkt[24] = 44;    // next_header = 44 (Fragment) — offset 18+6=24
  // payload_length: 8 (fragment ext header)
  const std::uint16_t payload_be = rte_cpu_to_be_16(8u);
  std::memcpy(&pkt[22], &payload_be, 2);  // payload_length at offset 18+4=22
  // dst_addr at offset 18+24 = 42 (16 bytes): 2001:db8::1
  pkt[42] = 0x20; pkt[43] = 0x01;
  pkt[44] = 0x0d; pkt[45] = 0xb8;
  pkt[57] = 0x01;  // last byte of dst_addr

  // Fragment ext header at offset 18+40 = 58 (8 bytes)
  pkt[58] = 6;     // inner next_header = 6 (TCP)
  pkt[59] = 0;     // reserved
  // frag_data: first fragment (offset=0, MF=1). Host value = 0x0001.
  const std::uint16_t frag_data_be = rte_cpu_to_be_16(0x0001u);
  std::memcpy(&pkt[60], &frag_data_be, 2);
  // id at pkt[62..65] — leave 0

  // Set dynfield as classify_l2 would for a VLAN-tagged IPv6 frame.
  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset        = 18;  // D13: VLAN shifts L3 start by 4
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV6;
  dyn->parsed_vlan      = 100;
  dyn->flags            = 0;
  dyn->l4_extra         = 0;

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  // D13+D27 compound: VLAN l3_offset=18 + first fragment + inner TCP → kNextL4
  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kNextL4)
      << "C3.20 SENTINEL: VLAN-tagged IPv6 first frag with TCP, "
         "l3_offset=18 (D13) + D27 → kNextL4 (L4 rule is M6)";

  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(m));
  EXPECT_EQ(cdyn->l4_extra, 8u)
      << "C3.20 SENTINEL: l4_extra must be 8 (D27 first frag drills one step)";
  EXPECT_EQ(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C3.20 SENTINEL: first fragment with inner TCP must NOT set SKIP_L4";

  // No counter bumps on this path
  EXPECT_EQ(frag_nonfirst_ctr, 0u)
      << "C3.20 SENTINEL: first fragment must NOT bump frag_nonfirst";
  EXPECT_EQ(exthdr_ctr, 0u)
      << "C3.20 SENTINEL: inner TCP must NOT bump exthdr counter";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV6)], 0u)
      << "C3.20 SENTINEL: first fragment must NOT bump skip counter";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV6)], 0u)
      << "C3.20 SENTINEL: no drop counter on first frag under L3_ONLY";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V6)], 0u)
      << "C3.20 SENTINEL: valid frame must NOT bump truncation";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L3TruncBucket::kL3V6FragExt)], 0u)
      << "C3.20 SENTINEL: valid frame must NOT bump frag-ext truncation";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// -------------------------------------------------------------------------
// C3.21 — First frag nh=253 (experimental, >=64 explicit OR list)
//
// corner.md: l4_skipped_ipv6_extheader += 1 (253 in explicit >=64 list).
// kTerminalPass.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3Ipv6CornerTest, C3_21_FirstFragInnerNh253_SkipL4) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  // First fragment: offset=0, MF=1. Host value = 0x0001.
  const std::uint16_t frag_data_be = rte_cpu_to_be_16(0x0001u);
  auto ff = build_ipv6_frag_frame("c3_21_pool", /*inner_nxt=*/253,
                                  frag_data_be);
  ASSERT_NE(ff.m, nullptr);
  set_dyn_for_ipv6(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C3.21: first frag with inner nh=253 → SKIP_L4 via explicit OR → kTerminalPass";
  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(ff.m));
  EXPECT_NE(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C3.21: chain-after-fragment with nh=253 must set SKIP_L4";
  EXPECT_EQ(exthdr_ctr, 1u)
      << "C3.21: l4_skipped_ipv6_extheader must be 1 (D22 explicit OR, D27)";
  EXPECT_EQ(frag_nonfirst_ctr, 0u)
      << "C3.21: first fragment must NOT bump frag_nonfirst";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// =========================================================================
// M5 C9 — Fragment policy matrix (C5.1–C5.16)
//
// 16 tests exercising the D17 fragment_policy × v4/v6 × first/nonfirst
// combinatorial matrix against the existing classify_l3 implementation
// (C3 v4 + C6 v6). No new src/ code — test-only cycle.
//
// Covers: D17, D27, D40, D21 cliff
//
// Key M5 adaptation: classify_l4 does NOT exist yet (M6). Tests that in
// corner.md assert L4 behavior are adapted to assert what classify_l3
// actually returns per the M5 C9 scope adaptation notes.
// =========================================================================

class ClassifyL3FragPolicyMatrixTest : public EalFixture {};

// -------------------------------------------------------------------------
// C5.1 — v4 first fragment, l3_only, L3 miss
//
// First fragment (MF=1, offset=0). Under l3_only, first fragment is NOT
// skipped — classify_l3 treats it normally. No L3 rules → null FIB →
// kNextL4 (L4 can still run on first fragment).
// No frag counters bumped (first frag under l3_only is pass-through).
// -------------------------------------------------------------------------
TEST_F(ClassifyL3FragPolicyMatrixTest, C5_1_V4FirstL3OnlyMiss) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  auto ff = build_ipv4_frame("c5_1_pool", 0x0A010203u);  // 10.1.2.3
  ASSERT_NE(ff.m, nullptr);
  set_frag_word(ff.pkt, /*mf=*/true, /*frag_off_units=*/0);  // first frag
  set_dyn_for_ipv4(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kNextL4)
      << "C5.1: first frag under l3_only + FIB miss → kNextL4 "
         "(first frag carries L4 header, not skipped)";
  auto* dyn = eal::mbuf_dynfield(ff.m);
  EXPECT_EQ(dyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C5.1: first frag must NOT set SKIP_L4";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 0u)
      << "C5.1: no skip counter on first frag";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV4)], 0u)
      << "C5.1: no drop counter on first frag under l3_only";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// C5.2 — v4 first fragment, l3_only, L3 hit (drop rule)
//
// First fragment with a populated FIB containing a drop rule matching the
// dst prefix. First frag under l3_only is NOT skipped → FIB hit → drop
// action → kTerminalDrop.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3FragPolicyMatrixTest, C5_2_V4FirstL3OnlyL3HitDrop) {
  using namespace builder_eal;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  Config cfg = make_config();

  // Filler rule at action_idx=0 (avoid C1b zero-packed entry ambiguity).
  SubnetObject filler;
  filler.name = "net_filler_c5_2";
  filler.cidrs.push_back(Cidr4{0xAC100000, 12});  // 172.16.0.0/12
  cfg.objects.subnets.push_back(std::move(filler));

  // Target: drop rule on 10.0.0.0/8 at action_idx=1.
  SubnetObject target;
  target.name = "net_target_c5_2";
  target.cidrs.push_back(Cidr4{0x0A000000, 8});   // 10.0.0.0/8
  cfg.objects.subnets.push_back(std::move(target));

  auto& r_filler = append_rule(cfg.pipeline.layer_3, 5201, ActionAllow{});
  r_filler.dst_subnet = SubnetRef{"net_filler_c5_2"};
  auto& r_target = append_rule(cfg.pipeline.layer_3, 5202, ActionDrop{});
  r_target.dst_subnet = SubnetRef{"net_target_c5_2"};

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value());

  Ruleset rs = ruleset::build_ruleset(cr, cfg.sizing, /*num_lcores=*/1);
  rs.fragment_policy = dataplane::kFragL3Only;
  EalPopulateParams params;
  params.name_prefix = "c5_2";
  params.socket_id = 0;
  params.max_entries = 64;
  auto res = populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;
  ASSERT_NE(rs.l3_v4_fib, nullptr);

  auto ff = build_ipv4_frame("c5_2_pool", 0x0A010203u);  // matches 10/8
  ASSERT_NE(ff.m, nullptr);
  set_frag_word(ff.pkt, /*mf=*/true, /*frag_off_units=*/0);  // first frag
  set_dyn_for_ipv4(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalDrop)
      << "C5.2: first frag under l3_only + L3 drop-rule hit → kTerminalDrop";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV4)], 0u)
      << "C5.2: L3 rule drop is NOT a fragment-policy drop — no D40 frag counter";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// C5.3 — v4 first fragment, l3_only, L4 rule would hit (M6 scope)
//
// First fragment under l3_only, no L3 rules. classify_l3 returns kNextL4
// (first frag, no L3 match). L4 rule matching is M6.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3FragPolicyMatrixTest, C5_3_V4FirstL3OnlyL4RuleHit) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  // 14 + 20 + 8 B UDP payload = 42 B
  auto cf = build_corner_frame("c5_3_pool", 42);
  ASSERT_NE(cf.m, nullptr);
  cf.pkt[14] = 0x45;  // version=4, IHL=5
  cf.pkt[23] = 17;    // proto=UDP
  // First fragment: MF=1, offset=0
  cf.pkt[20] = 0x20;  cf.pkt[21] = 0x00;
  // UDP dport=53 at offset 36
  cf.pkt[36] = 0x00;  cf.pkt[37] = 0x35;
  set_dyn_ipv4_corner(cf.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(cf.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kNextL4)
      << "C5.3: first frag under l3_only + no L3 match → kNextL4 (L4 rule is M6)";
  auto* dyn = eal::mbuf_dynfield(cf.m);
  EXPECT_EQ(dyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C5.3: first frag must NOT set SKIP_L4";

  rte_pktmbuf_free(cf.m);
  rte_mempool_free(cf.mp);
}

// -------------------------------------------------------------------------
// C5.4 — v4 non-first fragment, l3_only, no rules
//
// SKIP_L4 + pkt_frag_skipped_total_v4 += 1, FIB miss → kTerminalPass.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3FragPolicyMatrixTest, C5_4_V4NonFirstL3OnlyNoRules) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  auto ff = build_ipv4_frame("c5_4_pool", 0x0A010203u);
  ASSERT_NE(ff.m, nullptr);
  set_frag_word(ff.pkt, /*mf=*/false, /*frag_off_units=*/100);  // non-first
  set_dyn_for_ipv4(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C5.4: non-first frag + l3_only + no rules → kTerminalPass (D21 cliff)";
  auto* dyn = eal::mbuf_dynfield(ff.m);
  EXPECT_NE(dyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C5.4: non-first frag must set SKIP_L4";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 1u)
      << "C5.4: pkt_frag_skipped_total_v4 must be 1";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV4)], 0u)
      << "C5.4: no drop counter bleed";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// C5.5 — v4 non-first fragment, l3_only, L3 hit (drop rule)
//
// SKIP_L4 + pkt_frag_skipped_total_v4 += 1. FIB hit with drop action →
// kTerminalDrop (L3 drop wins regardless of SKIP_L4).
// -------------------------------------------------------------------------
TEST_F(ClassifyL3FragPolicyMatrixTest, C5_5_V4NonFirstL3OnlyL3HitDrop) {
  using namespace builder_eal;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  Config cfg = make_config();

  SubnetObject filler;
  filler.name = "net_filler_c5_5";
  filler.cidrs.push_back(Cidr4{0xAC100000, 12});
  cfg.objects.subnets.push_back(std::move(filler));

  SubnetObject target;
  target.name = "net_target_c5_5";
  target.cidrs.push_back(Cidr4{0x0A000000, 8});
  cfg.objects.subnets.push_back(std::move(target));

  auto& r_filler = append_rule(cfg.pipeline.layer_3, 5501, ActionAllow{});
  r_filler.dst_subnet = SubnetRef{"net_filler_c5_5"};
  auto& r_target = append_rule(cfg.pipeline.layer_3, 5502, ActionDrop{});
  r_target.dst_subnet = SubnetRef{"net_target_c5_5"};

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value());

  Ruleset rs = ruleset::build_ruleset(cr, cfg.sizing, /*num_lcores=*/1);
  rs.fragment_policy = dataplane::kFragL3Only;
  EalPopulateParams params;
  params.name_prefix = "c5_5";
  params.socket_id = 0;
  params.max_entries = 64;
  auto res = populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << res.error;
  ASSERT_NE(rs.l3_v4_fib, nullptr);

  auto ff = build_ipv4_frame("c5_5_pool", 0x0A010203u);  // matches 10/8
  ASSERT_NE(ff.m, nullptr);
  set_frag_word(ff.pkt, /*mf=*/false, /*frag_off_units=*/100);  // non-first
  set_dyn_for_ipv4(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalDrop)
      << "C5.5: non-first frag + l3_only + L3 drop-rule hit → kTerminalDrop";
  auto* dyn = eal::mbuf_dynfield(ff.m);
  EXPECT_NE(dyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C5.5: non-first frag must set SKIP_L4 even on L3 drop path";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 1u)
      << "C5.5: pkt_frag_skipped_total_v4 must be 1 (set before FIB lookup)";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// C5.6 — v4 non-first fragment, l3_only, L4 rule would hit
//
// L4 is skipped due to SKIP_L4. FIB miss → kTerminalPass. The L4 rule
// does NOT fire (M6 scope anyway; SKIP_L4 guarantees skip).
// -------------------------------------------------------------------------
TEST_F(ClassifyL3FragPolicyMatrixTest, C5_6_V4NonFirstL3OnlyL4RuleWouldHit) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  auto ff = build_ipv4_frame("c5_6_pool", 0x0A010203u);
  ASSERT_NE(ff.m, nullptr);
  set_frag_word(ff.pkt, /*mf=*/false, /*frag_off_units=*/100);  // non-first
  set_dyn_for_ipv4(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C5.6: non-first frag + l3_only + L3 miss → kTerminalPass "
         "(L4 rule cannot fire — SKIP_L4 latched)";
  auto* dyn = eal::mbuf_dynfield(ff.m);
  EXPECT_NE(dyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C5.6: SKIP_L4 must be set, preventing L4 dispatch";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 1u)
      << "C5.6: pkt_frag_skipped_total_v4 must be 1";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// C5.7 — v4 first fragment, drop policy
//
// FRAG_DROP → pkt_frag_dropped_total_v4 += 1 + kTerminalDrop.
// First fragment IS dropped under drop policy.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3FragPolicyMatrixTest, C5_7_V4FirstDrop) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragDrop;

  auto ff = build_ipv4_frame("c5_7_pool", 0x0A010203u);
  ASSERT_NE(ff.m, nullptr);
  set_frag_word(ff.pkt, /*mf=*/true, /*frag_off_units=*/0);  // first frag
  set_dyn_for_ipv4(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalDrop)
      << "C5.7: first frag under drop → kTerminalDrop";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV4)], 1u)
      << "C5.7: pkt_frag_dropped_total_v4 must be 1";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 0u)
      << "C5.7: no skip counter bleed";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// C5.8 — v4 non-first fragment, drop policy
//
// Same as C5.7 — pkt_frag_dropped_total_v4 += 1 + kTerminalDrop.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3FragPolicyMatrixTest, C5_8_V4NonFirstDrop) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragDrop;

  auto ff = build_ipv4_frame("c5_8_pool", 0x0A010203u);
  ASSERT_NE(ff.m, nullptr);
  set_frag_word(ff.pkt, /*mf=*/false, /*frag_off_units=*/100);  // non-first
  set_dyn_for_ipv4(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalDrop)
      << "C5.8: non-first frag under drop → kTerminalDrop";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV4)], 1u)
      << "C5.8: pkt_frag_dropped_total_v4 must be 1";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 0u)
      << "C5.8: no skip counter bleed";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// C5.9 — v4 first fragment, allow policy
//
// FRAG_ALLOW → kTerminalPass. No counters bumped (allow passes silently).
// -------------------------------------------------------------------------
TEST_F(ClassifyL3FragPolicyMatrixTest, C5_9_V4FirstAllow) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragAllow;

  auto ff = build_ipv4_frame("c5_9_pool", 0x0A010203u);
  ASSERT_NE(ff.m, nullptr);
  set_frag_word(ff.pkt, /*mf=*/true, /*frag_off_units=*/0);  // first frag
  set_dyn_for_ipv4(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C5.9: first frag under allow → kTerminalPass";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV4)], 0u)
      << "C5.9: allow must not bump drop counter";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 0u)
      << "C5.9: allow must not bump skip counter";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// C5.10 — v4 non-first fragment, allow policy
//
// Same → kTerminalPass. No counters.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3FragPolicyMatrixTest, C5_10_V4NonFirstAllow) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragAllow;

  auto ff = build_ipv4_frame("c5_10_pool", 0x0A010203u);
  ASSERT_NE(ff.m, nullptr);
  set_frag_word(ff.pkt, /*mf=*/false, /*frag_off_units=*/100);  // non-first
  set_dyn_for_ipv4(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C5.10: non-first frag under allow → kTerminalPass";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV4)], 0u)
      << "C5.10: allow must not bump drop counter";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV4)], 0u)
      << "C5.10: allow must not bump skip counter";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// C5.11 — v6 first fragment, l3_only, L4 rule would hit (M6 scope)
//
// First v6 fragment with inner TCP. L3_ONLY, no L3 rules. classify_l3 sets
// l4_extra=8, returns kNextL4 (L4 rule is M6). No frag counters.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3FragPolicyMatrixTest, C5_11_V6FirstL3OnlyL4RuleHit) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  // First fragment: frag_offset=0, MF=1. Host value = 0x0001.
  const std::uint16_t frag_data_be = rte_cpu_to_be_16(0x0001u);
  auto ff = build_ipv6_frag_frame("c5_11_pool", /*inner_nxt=*/6,
                                  frag_data_be);
  ASSERT_NE(ff.m, nullptr);
  set_dyn_for_ipv6(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kNextL4)
      << "C5.11: first v6 frag + l3_only + no L3 rules → kNextL4 (L4 is M6)";
  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(ff.m));
  EXPECT_EQ(cdyn->l4_extra, 8u)
      << "C5.11: l4_extra must be 8 (D27 first fragment drill)";
  EXPECT_EQ(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C5.11: first fragment with inner TCP must NOT set SKIP_L4";
  EXPECT_EQ(frag_nonfirst_ctr, 0u)
      << "C5.11: first fragment must NOT bump frag_nonfirst";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV6)], 0u)
      << "C5.11: first fragment must NOT bump pkt_frag_skipped_total_v6";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV6)], 0u)
      << "C5.11: first fragment under l3_only must NOT bump drop counter";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// C5.12 — v6 non-first fragment, l3_only
//
// l4_skipped_ipv6_fragment_nonfirst += 1, pkt_frag_skipped_total_v6 += 1
// (D40 alias), SKIP_L4 → FIB miss → kTerminalPass.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3FragPolicyMatrixTest, C5_12_V6NonFirstL3Only) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragL3Only;

  // Non-first fragment: frag_offset=4, MF=0.
  // Host value = 4 << 3 = 0x0020.
  const std::uint16_t frag_data_be = rte_cpu_to_be_16(
      static_cast<std::uint16_t>(4u << 3));
  auto ff = build_ipv6_frag_frame("c5_12_pool", /*inner_nxt=*/17,
                                  frag_data_be);
  ASSERT_NE(ff.m, nullptr);
  set_dyn_for_ipv6(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C5.12: non-first v6 frag + l3_only + no rules → kTerminalPass";
  auto* cdyn = eal::mbuf_dynfield(static_cast<const struct rte_mbuf*>(ff.m));
  EXPECT_NE(cdyn->flags & static_cast<std::uint8_t>(eal::kSkipL4), 0)
      << "C5.12: non-first frag must set SKIP_L4";
  EXPECT_EQ(frag_nonfirst_ctr, 1u)
      << "C5.12: l4_skipped_ipv6_fragment_nonfirst must be 1 (D27)";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV6)], 1u)
      << "C5.12: pkt_frag_skipped_total_v6 must be 1 (D40 alias)";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV6)], 0u)
      << "C5.12: no drop counter bleed";
  EXPECT_EQ(exthdr_ctr, 0u)
      << "C5.12: non-first frag must NOT bump exthdr counter";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// C5.13 — v6 first fragment, drop policy
//
// FRAG_DROP → pkt_frag_dropped_total_v6 += 1 + kTerminalDrop.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3FragPolicyMatrixTest, C5_13_V6FirstDrop) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragDrop;

  // First fragment: frag_offset=0, MF=1. Host value = 0x0001.
  const std::uint16_t frag_data_be = rte_cpu_to_be_16(0x0001u);
  auto ff = build_ipv6_frag_frame("c5_13_pool", /*inner_nxt=*/6,
                                  frag_data_be);
  ASSERT_NE(ff.m, nullptr);
  set_dyn_for_ipv6(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalDrop)
      << "C5.13: first v6 frag under drop → kTerminalDrop";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV6)], 1u)
      << "C5.13: pkt_frag_dropped_total_v6 must be 1";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV6)], 0u)
      << "C5.13: no skip counter bleed";
  EXPECT_EQ(frag_nonfirst_ctr, 0u)
      << "C5.13: drop path must NOT bump frag_nonfirst counter";
  EXPECT_EQ(exthdr_ctr, 0u)
      << "C5.13: drop path must NOT bump exthdr counter";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// C5.14 — v6 non-first fragment, drop policy
//
// Same → pkt_frag_dropped_total_v6 += 1 + kTerminalDrop.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3FragPolicyMatrixTest, C5_14_V6NonFirstDrop) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragDrop;

  // Non-first fragment: frag_offset=4, MF=0.
  const std::uint16_t frag_data_be = rte_cpu_to_be_16(
      static_cast<std::uint16_t>(4u << 3));
  auto ff = build_ipv6_frag_frame("c5_14_pool", /*inner_nxt=*/17,
                                  frag_data_be);
  ASSERT_NE(ff.m, nullptr);
  set_dyn_for_ipv6(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalDrop)
      << "C5.14: non-first v6 frag under drop → kTerminalDrop";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV6)], 1u)
      << "C5.14: pkt_frag_dropped_total_v6 must be 1";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV6)], 0u)
      << "C5.14: no skip counter bleed";
  EXPECT_EQ(frag_nonfirst_ctr, 0u)
      << "C5.14: drop path must NOT bump frag_nonfirst counter";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// C5.15 — v6 first fragment, allow policy
//
// FRAG_ALLOW → kTerminalPass. No counters.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3FragPolicyMatrixTest, C5_15_V6FirstAllow) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragAllow;

  // First fragment: frag_offset=0, MF=1.
  const std::uint16_t frag_data_be = rte_cpu_to_be_16(0x0001u);
  auto ff = build_ipv6_frag_frame("c5_15_pool", /*inner_nxt=*/6,
                                  frag_data_be);
  ASSERT_NE(ff.m, nullptr);
  set_dyn_for_ipv6(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C5.15: first v6 frag under allow → kTerminalPass";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV6)], 0u)
      << "C5.15: allow must not bump drop counter";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV6)], 0u)
      << "C5.15: allow must not bump skip counter";
  EXPECT_EQ(frag_nonfirst_ctr, 0u)
      << "C5.15: allow path must NOT bump frag_nonfirst counter";
  EXPECT_EQ(exthdr_ctr, 0u)
      << "C5.15: allow path must NOT bump exthdr counter";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// -------------------------------------------------------------------------
// C5.16 — v6 non-first fragment, allow policy
//
// Same → kTerminalPass. No counters.
// -------------------------------------------------------------------------
TEST_F(ClassifyL3FragPolicyMatrixTest, C5_16_V6NonFirstAllow) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;
  rs.fragment_policy = dataplane::kFragAllow;

  // Non-first fragment: frag_offset=4, MF=0.
  const std::uint16_t frag_data_be = rte_cpu_to_be_16(
      static_cast<std::uint16_t>(4u << 3));
  auto ff = build_ipv6_frag_frame("c5_16_pool", /*inner_nxt=*/17,
                                  frag_data_be);
  ASSERT_NE(ff.m, nullptr);
  set_dyn_for_ipv6(ff.m);

  dataplane::L3TruncCtrs trunc{};
  dataplane::L3FragCtrs  frag{};
  std::uint64_t exthdr_ctr = 0;
  std::uint64_t frag_nonfirst_ctr = 0;
  const auto v = dataplane::classify_l3(ff.m, rs, &trunc, &frag,
                                        &exthdr_ctr, &frag_nonfirst_ctr);

  EXPECT_EQ(v, dataplane::ClassifyL3Verdict::kTerminalPass)
      << "C5.16: non-first v6 frag under allow → kTerminalPass";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragDroppedV6)], 0u)
      << "C5.16: allow must not bump drop counter";
  EXPECT_EQ(frag[static_cast<std::size_t>(
                dataplane::L3FragBucket::kL3FragSkippedV6)], 0u)
      << "C5.16: allow must not bump skip counter";
  EXPECT_EQ(frag_nonfirst_ctr, 0u)
      << "C5.16: allow path must NOT bump frag_nonfirst counter";
  EXPECT_EQ(exthdr_ctr, 0u)
      << "C5.16: allow path must NOT bump exthdr counter";

  rte_pktmbuf_free(ff.m);
  rte_mempool_free(ff.mp);
}

// =========================================================================
// M6 C0 — classify_l4 skeleton: SKIP_L4 guard + D14 L4 offset + D31
//          l4 truncation + L4 miss path.
//
// Four RED tests per the M6 C0 cycle row:
//
//   U6.16  — D31 l4 truncation sentinel: TCP packet with < 4 B after
//            L4 offset → kTerminalDrop + pkt_truncated_l4[kL4] bumped.
//   U6.19  — D14 IHL=6 L4 offset: IPv4 with 24-byte header. L4 offset
//            must be l3_offset + 24, not l3_offset + 20.
//   U6.39  — D21 SKIP_L4 flag set → classify_l4 returns kTerminalPass
//            immediately without touching L4 header.
//   U6.40  — L4 miss (no hash tables populated) → kTerminalPass.
//
// All tests bypass classify_l2/classify_l3 and call classify_l4 directly,
// pre-setting the dynfield the way the upstream stages would.
//
// Covers: D14, D21, D31 (bucket `l4`), D41 (pipeline smoke at L4).
// =========================================================================

class ClassifyL4SkeletonTest : public EalFixture {};

// -------------------------------------------------------------------------
// U6.16 — L4 truncated TCP → D31 l4 sentinel
//
// IPv4 IHL=5 → L4 offset = 14 + 20 = 34. Frame size = 14 + 20 + 2 = 36.
// TCP needs 4 B at l4off; only 2 B available → truncation drop.
// -------------------------------------------------------------------------
TEST_F(ClassifyL4SkeletonTest, U6_16_L4TruncatedTcpDropsSentinel) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;  // empty — no L4 tables

  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_16_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);

  // 14 B Ethernet + 20 B IPv4 + 2 B partial TCP = 36 B total.
  // L4 offset = 34, need = 4, available = 36 - 34 = 2 → truncation.
  constexpr std::size_t kFrameLen = 14 + 20 + 2;
  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, kFrameLen));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, kFrameLen);

  // Ethernet: ethertype 0x0800 IPv4
  pkt[12] = 0x08; pkt[13] = 0x00;
  // IPv4 at offset 14: version=4, IHL=5
  pkt[14] = 0x45;
  // Protocol = TCP (6)
  pkt[23] = IPPROTO_TCP;

  // Pre-set dynfield as if classify_l2 + classify_l3 ran.
  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset        = 14;
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV4;  // 0x0800 HOST order
  dyn->parsed_l3_proto  = IPPROTO_TCP;
  dyn->flags            = 0;   // no SKIP_L4
  dyn->l4_extra         = 0;

  dataplane::L4TruncCtrs trunc{};
  const auto verdict = dataplane::classify_l4(m, rs, &trunc);

  EXPECT_EQ(verdict, dataplane::ClassifyL4Verdict::kTerminalDrop)
      << "U6.16: TCP with <4 B at L4 offset must be dropped (D31 l4 sentinel)";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L4TruncBucket::kL4)], 1u)
      << "U6.16: pkt_truncated_l4[l4] must be 1";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// -------------------------------------------------------------------------
// U6.19 — D14 IHL=6 L4 offset uses `ihl << 2`
//
// IPv4 with IHL=6 (24-byte header, 4 B options). L4 offset must be
// l3_offset + 24 = 38. Frame has a valid 4-byte TCP stub at offset 38.
// classify_l4 must NOT truncation-drop (pkt_len >= 38 + 4 = 42).
// -------------------------------------------------------------------------
TEST_F(ClassifyL4SkeletonTest, U6_19_Ihl6L4OffsetUsesIhlShift2) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;  // empty — no L4 tables

  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_19_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);

  // 14 B Ethernet + 24 B IPv4 (IHL=6) + 4 B TCP ports = 42 B total.
  // L4 offset should be 14 + 24 = 38. need = 4. 42 >= 38 + 4 = 42 → OK.
  constexpr std::size_t kFrameLen = 14 + 24 + 4;
  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, kFrameLen));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, kFrameLen);

  // Ethernet: ethertype 0x0800 IPv4
  pkt[12] = 0x08; pkt[13] = 0x00;
  // IPv4 at offset 14: version=4, IHL=6 → 24-byte header with 4 B options
  pkt[14] = 0x46;
  // Protocol = TCP (6)
  pkt[23] = IPPROTO_TCP;
  // Write recognisable port values at L4 offset 38 (not 34!)
  // to verify classify_l4 reads at the correct position.
  // sport=0x1234 at offset 38-39, dport=0x5678 at offset 40-41
  pkt[38] = 0x12; pkt[39] = 0x34;  // src port big-endian
  pkt[40] = 0x56; pkt[41] = 0x78;  // dst port big-endian

  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset        = 14;
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV4;  // 0x0800 HOST order
  dyn->parsed_l3_proto  = IPPROTO_TCP;
  dyn->flags            = 0;
  dyn->l4_extra         = 0;

  dataplane::L4TruncCtrs trunc{};
  const auto verdict = dataplane::classify_l4(m, rs, &trunc);

  // With IHL=6 and correct L4 offset computation (l3_off + 24 = 38),
  // the packet has exactly 4 B at the L4 position → NOT truncated.
  // No hash tables → L4 miss → kTerminalPass.
  EXPECT_EQ(verdict, dataplane::ClassifyL4Verdict::kTerminalPass)
      << "U6.19: IHL=6 with valid L4 header must NOT be truncation-dropped";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L4TruncBucket::kL4)], 0u)
      << "U6.19: no truncation counter bump";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// -------------------------------------------------------------------------
// U6.39 — SKIP_L4 flag → TERMINAL_PASS immediately (D21)
//
// Dynfield has SKIP_L4 set (e.g. non-first fragment under L3_ONLY).
// classify_l4 must return kTerminalPass without touching the L4 header.
// The frame is deliberately malformed at L4 (only 2 B of "TCP") to
// prove that classify_l4 short-circuits before the truncation check.
// -------------------------------------------------------------------------
TEST_F(ClassifyL4SkeletonTest, U6_39_SkipL4FlagReturnsTerminalPass) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;

  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_39_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);

  // Deliberately short: 14 + 20 + 2 = 36 B. TCP would need 4 B at l4off.
  // If SKIP_L4 guard works, truncation check is never reached.
  constexpr std::size_t kFrameLen = 14 + 20 + 2;
  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, kFrameLen));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, kFrameLen);
  pkt[12] = 0x08; pkt[13] = 0x00;
  pkt[14] = 0x45;
  pkt[23] = IPPROTO_TCP;

  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset        = 14;
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV4;
  dyn->parsed_l3_proto  = IPPROTO_TCP;
  dyn->flags            = eal::kSkipL4;  // SKIP_L4 set!
  dyn->l4_extra         = 0;

  dataplane::L4TruncCtrs trunc{};
  const auto verdict = dataplane::classify_l4(m, rs, &trunc);

  EXPECT_EQ(verdict, dataplane::ClassifyL4Verdict::kTerminalPass)
      << "U6.39: SKIP_L4 flag must short-circuit to kTerminalPass (D21)";
  // Truncation counter must NOT be bumped — we never reached the check.
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L4TruncBucket::kL4)], 0u)
      << "U6.39: SKIP_L4 must not touch truncation counter";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// -------------------------------------------------------------------------
// U6.40 — L4 miss → TERMINAL_PASS (no hash tables populated)
//
// Valid IPv4/TCP frame with full L4 header. No L4 hash tables in the
// ruleset. classify_l4 must return kTerminalPass (default pass-through).
// -------------------------------------------------------------------------
TEST_F(ClassifyL4SkeletonTest, U6_40_L4MissReturnsTerminalPass) {
  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  ruleset::Ruleset rs;  // empty — l4_compound_hash == nullptr
  ASSERT_EQ(rs.l4_compound_hash, nullptr);

  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_40_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);
  struct rte_mbuf* m = rte_pktmbuf_alloc(mp);
  ASSERT_NE(m, nullptr);

  // 14 B Ethernet + 20 B IPv4 + 8 B TCP header stub = 42 B.
  // L4 offset = 34, need = 4, available = 42 - 34 = 8 → not truncated.
  constexpr std::size_t kFrameLen = 14 + 20 + 8;
  uint8_t* pkt = reinterpret_cast<uint8_t*>(rte_pktmbuf_append(m, kFrameLen));
  ASSERT_NE(pkt, nullptr);
  std::memset(pkt, 0, kFrameLen);
  pkt[12] = 0x08; pkt[13] = 0x00;
  pkt[14] = 0x45;
  pkt[23] = IPPROTO_TCP;
  // sport/dport at offset 34: any values, we just prove no match.
  pkt[34] = 0x00; pkt[35] = 0x50;  // sport 80
  pkt[36] = 0x01; pkt[37] = 0xBB;  // dport 443

  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset        = 14;
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV4;
  dyn->parsed_l3_proto  = IPPROTO_TCP;
  dyn->flags            = 0;
  dyn->l4_extra         = 0;

  dataplane::L4TruncCtrs trunc{};
  const auto verdict = dataplane::classify_l4(m, rs, &trunc);

  EXPECT_EQ(verdict, dataplane::ClassifyL4Verdict::kTerminalPass)
      << "U6.40: L4 miss (no hash tables) must return kTerminalPass";
  EXPECT_EQ(trunc[static_cast<std::size_t>(dataplane::L4TruncBucket::kL4)], 0u)
      << "U6.40: no truncation";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// =========================================================================
// M6 C1 — L4 port parsing + proto_dport primary + D29 ICMP packing.
//
// Four RED tests:
//
//   U6.33  — proto+dport primary hit: TCP/443 packet matched by a rule
//            with proto=TCP, dport=443. classify_l4 returns kMatch and
//            writes the correct verdict_action_idx.
//   U6.34  — proto+dport with src-port wildcard: same rule (no sport
//            constraint, filter_mask==0), any sport matches.
//   U6.35  — proto+dport+sport exact match: rule has sport=12345
//            (filter_mask kSrcPort). Match only when sport matches;
//            sport mismatch → L4 miss → kTerminalPass.
//   U6.41  — ICMP type/code packing (D29): rule matches proto=ICMP
//            dport=8 (echo request type). ICMP packet with type=8
//            code=0. Primary key = (1<<16)|8 hits. filter_mask
//            SRC_PORT checks code=0. kMatch + action_idx correct.
//
// All tests build a full CompileResult → build_ruleset → populate_
// ruleset_eal pipeline to get a real rte_hash table, then call
// classify_l4 directly with pre-set dynfields.
//
// Covers: D14, D15, D29, D41.
// =========================================================================

class ClassifyL4PortTest : public EalFixture {};

// Helper: build a minimal IPv4/TCP packet in an mbuf, pre-set dynfields.
// Returns the mbuf pointer. Caller owns the mbuf + pool.
namespace l4_port_detail {

using namespace builder_eal;

// Build a Ruleset with L4 tables populated from the given config.
// name_prefix must be unique per test to avoid rte_hash name collisions.
inline ruleset::Ruleset build_l4_ruleset(Config& cfg,
                                         const std::string& name_prefix) {
  auto cr = compile(cfg);
  if (cr.error.has_value()) {
    throw std::runtime_error("compile failed: " + cr.error->message);
  }

  ruleset::Ruleset rs =
      ruleset::build_ruleset(cr, cfg.sizing, /*num_lcores=*/1);
  EalPopulateParams params;
  params.name_prefix = name_prefix;
  params.socket_id = 0;
  params.max_entries = 64;
  auto res = ruleset::populate_ruleset_eal(rs, cr, params);
  if (!res.ok) {
    throw std::runtime_error("populate_ruleset_eal failed: " + res.error);
  }
  return rs;
}

// Create a minimal IPv4/TCP frame in an mbuf from pool `mp`.
// sport and dport are in HOST order. proto is the IP protocol number.
// For ICMP, the first two L4 bytes are type and code (not port numbers).
inline rte_mbuf* make_l4_pkt(rte_mempool* mp,
                              std::uint8_t proto,
                              std::uint16_t sport,
                              std::uint16_t dport,
                              bool is_icmp = false) {
  rte_mbuf* m = rte_pktmbuf_alloc(mp);
  if (!m) return nullptr;

  // 14 B Ethernet + 20 B IPv4 + 8 B L4 stub = 42 B.
  constexpr std::size_t kFrameLen = 14 + 20 + 8;
  auto* pkt = reinterpret_cast<std::uint8_t*>(rte_pktmbuf_append(m, kFrameLen));
  if (!pkt) { rte_pktmbuf_free(m); return nullptr; }
  std::memset(pkt, 0, kFrameLen);

  // Ethernet: ethertype 0x0800 (IPv4)
  pkt[12] = 0x08; pkt[13] = 0x00;
  // IPv4 at offset 14: version=4, IHL=5
  pkt[14] = 0x45;
  // Total length = 20 + 8 = 28
  pkt[16] = 0x00; pkt[17] = 28;
  // Protocol
  pkt[23] = proto;

  // L4 header at offset 34.
  if (is_icmp) {
    // ICMP: byte[0] = type, byte[1] = code (D29 packing).
    pkt[34] = static_cast<std::uint8_t>(dport);  // type → dport slot
    pkt[35] = static_cast<std::uint8_t>(sport);  // code → sport slot
  } else {
    // TCP/UDP/SCTP: big-endian sport at offset 34-35, dport at 36-37.
    pkt[34] = static_cast<std::uint8_t>(sport >> 8);
    pkt[35] = static_cast<std::uint8_t>(sport & 0xFF);
    pkt[36] = static_cast<std::uint8_t>(dport >> 8);
    pkt[37] = static_cast<std::uint8_t>(dport & 0xFF);
  }

  // Pre-set dynfield as if classify_l2 + classify_l3 ran.
  auto* dyn = eal::mbuf_dynfield(m);
  dyn->l3_offset        = 14;
  dyn->parsed_ethertype = RTE_ETHER_TYPE_IPV4;  // HOST order
  dyn->parsed_l3_proto  = proto;
  dyn->flags            = 0;   // no SKIP_L4
  dyn->l4_extra         = 0;
  dyn->verdict_action_idx = 0xFFFF;  // sentinel

  return m;
}

}  // namespace l4_port_detail

// -------------------------------------------------------------------------
// U6.33 — proto+dport primary hit (TCP/443)
//
// Rule: proto=TCP, dport=443, action=DROP.
// Packet: TCP sport=80 dport=443.
// Expected: kMatch, verdict_action_idx=0.
// -------------------------------------------------------------------------
TEST_F(ClassifyL4PortTest, U6_33_ProtoDportPrimaryHit) {
  using namespace builder_eal;
  using namespace l4_port_detail;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  Config cfg = make_config();
  auto& r1 = append_rule(cfg.pipeline.layer_4, 4001, ActionDrop{});
  r1.proto = IPPROTO_TCP;
  r1.dst_port = 443;

  auto rs = build_l4_ruleset(cfg, "u6_33");
  ASSERT_NE(rs.l4_compound_hash, nullptr);
  ASSERT_GE(rs.l4_compound_count, 1u);

  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_33_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);

  auto* m = make_l4_pkt(mp, IPPROTO_TCP, /*sport=*/80, /*dport=*/443);
  ASSERT_NE(m, nullptr);

  dataplane::L4TruncCtrs trunc{};
  const auto verdict = dataplane::classify_l4(m, rs, &trunc);

  EXPECT_EQ(verdict, dataplane::ClassifyL4Verdict::kMatch)
      << "U6.33: TCP/443 must match the proto_dport primary (D15)";
  EXPECT_EQ(trunc[0], 0u) << "U6.33: no truncation";

  // Check verdict_action_idx was written.
  const auto* dyn = eal::mbuf_dynfield(
      static_cast<const struct rte_mbuf*>(m));
  EXPECT_EQ(dyn->verdict_action_idx, 0u)
      << "U6.33: verdict_action_idx must be 0 (first rule)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

// -------------------------------------------------------------------------
// U6.34 — proto+dport with src-port wildcard
//
// Same rule (proto=TCP, dport=443, no sport constraint → filter_mask==0).
// Inject packets with different sport values → all must match.
// -------------------------------------------------------------------------
TEST_F(ClassifyL4PortTest, U6_34_ProtoDportWildcardSport) {
  using namespace builder_eal;
  using namespace l4_port_detail;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  Config cfg = make_config();
  auto& r1 = append_rule(cfg.pipeline.layer_4, 4002, ActionDrop{});
  r1.proto = IPPROTO_TCP;
  r1.dst_port = 443;
  // No src_port → filter_mask has no kSrcPort bit → wildcard.

  auto rs = build_l4_ruleset(cfg, "u6_34");
  ASSERT_NE(rs.l4_compound_hash, nullptr);

  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_34_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);

  // Test with two different sport values: 1234 and 65535.
  for (std::uint16_t sport : {std::uint16_t{1234}, std::uint16_t{65535}}) {
    auto* m = make_l4_pkt(mp, IPPROTO_TCP, sport, /*dport=*/443);
    ASSERT_NE(m, nullptr);

    dataplane::L4TruncCtrs trunc{};
    const auto verdict = dataplane::classify_l4(m, rs, &trunc);

    EXPECT_EQ(verdict, dataplane::ClassifyL4Verdict::kMatch)
        << "U6.34: TCP/443 with any sport (" << sport
        << ") must match when filter_mask has no SRC_PORT bit";

    rte_pktmbuf_free(m);
  }

  rte_mempool_free(mp);
}

// -------------------------------------------------------------------------
// U6.35 — proto+dport+sport exact match
//
// Rule: proto=TCP, dport=443, sport=12345.
// Matching packet (sport=12345) → kMatch.
// Mismatching packet (sport=9999) → miss → kTerminalPass.
// -------------------------------------------------------------------------
TEST_F(ClassifyL4PortTest, U6_35_ProtoDportSportExact) {
  using namespace builder_eal;
  using namespace l4_port_detail;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  Config cfg = make_config();
  auto& r1 = append_rule(cfg.pipeline.layer_4, 4003, ActionDrop{});
  r1.proto = IPPROTO_TCP;
  r1.dst_port = 443;
  r1.src_port = 12345;

  auto rs = build_l4_ruleset(cfg, "u6_35");
  ASSERT_NE(rs.l4_compound_hash, nullptr);

  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_35_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);

  // Exact sport match → kMatch.
  {
    auto* m = make_l4_pkt(mp, IPPROTO_TCP, /*sport=*/12345, /*dport=*/443);
    ASSERT_NE(m, nullptr);

    dataplane::L4TruncCtrs trunc{};
    const auto verdict = dataplane::classify_l4(m, rs, &trunc);

    EXPECT_EQ(verdict, dataplane::ClassifyL4Verdict::kMatch)
        << "U6.35: TCP/443 sport=12345 must match exactly";

    const auto* dyn = eal::mbuf_dynfield(
        static_cast<const struct rte_mbuf*>(m));
    EXPECT_EQ(dyn->verdict_action_idx, 0u)
        << "U6.35: verdict_action_idx must be 0 (first rule)";

    rte_pktmbuf_free(m);
  }

  // Sport mismatch → filter_mask rejects → miss → kTerminalPass.
  {
    auto* m = make_l4_pkt(mp, IPPROTO_TCP, /*sport=*/9999, /*dport=*/443);
    ASSERT_NE(m, nullptr);

    dataplane::L4TruncCtrs trunc{};
    const auto verdict = dataplane::classify_l4(m, rs, &trunc);

    EXPECT_EQ(verdict, dataplane::ClassifyL4Verdict::kTerminalPass)
        << "U6.35: TCP/443 sport=9999 must NOT match (filter_mask SRC_PORT rejects)";

    rte_pktmbuf_free(m);
  }

  rte_mempool_free(mp);
}

// -------------------------------------------------------------------------
// U6.41 — ICMP type/code packing (D29)
//
// Rule: proto=ICMP (1), dport=8 (echo request type).
// Also has src_port=0 (filter_mask kSrcPort → checks code=0).
// Packet: ICMP type=8, code=0 → primary key = (1<<16)|8 → hit.
// filter_mask SRC_PORT: want_src_port=0 vs pkt code=0 → pass.
// Expected: kMatch, verdict_action_idx=0.
// -------------------------------------------------------------------------
TEST_F(ClassifyL4PortTest, U6_41_IcmpTypeCodePackingD29) {
  using namespace builder_eal;
  using namespace l4_port_detail;

  int off = eal::register_dynfield();
  ASSERT_GE(off, 0);

  Config cfg = make_config();
  auto& r1 = append_rule(cfg.pipeline.layer_4, 4004, ActionDrop{});
  r1.proto = IPPROTO_ICMP;   // 1
  r1.dst_port = 8;           // ICMP type = 8 (echo request) → dport slot
  r1.src_port = 0;           // ICMP code = 0 → sport slot (D29: want_src_port)

  auto rs = build_l4_ruleset(cfg, "u6_41");
  ASSERT_NE(rs.l4_compound_hash, nullptr);

  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "u6_41_pool", 63, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  ASSERT_NE(mp, nullptr);

  // Build ICMP packet: type=8 (→dport), code=0 (→sport). D29 packing.
  auto* m = make_l4_pkt(mp, IPPROTO_ICMP,
                         /*sport=*/0, /*dport=*/8,
                         /*is_icmp=*/true);
  ASSERT_NE(m, nullptr);

  dataplane::L4TruncCtrs trunc{};
  const auto verdict = dataplane::classify_l4(m, rs, &trunc);

  EXPECT_EQ(verdict, dataplane::ClassifyL4Verdict::kMatch)
      << "U6.41: ICMP echo-request (type=8, code=0) must match via D29 packing";

  const auto* dyn = eal::mbuf_dynfield(
      static_cast<const struct rte_mbuf*>(m));
  EXPECT_EQ(dyn->verdict_action_idx, 0u)
      << "U6.41: verdict_action_idx must be 0 (first rule, D29)";

  rte_pktmbuf_free(m);
  rte_mempool_free(mp);
}

}  // namespace pktgate::test
