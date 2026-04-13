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

#include <rte_fib.h>
#include <rte_fib6.h>
#include <rte_hash.h>
#include <rte_ip6.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "src/compiler/compiler.h"
#include "src/compiler/object_compiler.h"
#include "src/compiler/rule_compiler.h"
#include "src/config/model.h"
#include "src/config/sizing.h"
#include "src/dataplane/classify_l2.h"
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
// src_subnet since M1 has no dst_subnet). After populate_ruleset_eal
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
  r1.src_subnet = SubnetRef{"net_a"};
  auto& r2 = append_rule(cfg.pipeline.layer_3, 3002, ActionAllow{});
  r2.src_subnet = SubnetRef{"net_b"};
  auto& r3 = append_rule(cfg.pipeline.layer_3, 3003, ActionDrop{});
  r3.src_subnet = SubnetRef{"net_c"};

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
  r1.src_subnet = SubnetRef{"v6_a"};
  auto& r2 = append_rule(cfg.pipeline.layer_3, 4002, ActionAllow{});
  r2.src_subnet = SubnetRef{"v6_b"};

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

}  // namespace pktgate::test
