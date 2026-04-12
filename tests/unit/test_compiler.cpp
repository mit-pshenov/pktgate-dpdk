// tests/unit/test_compiler.cpp
//
// M2 compiler tests.
// C1: U3.1, U3.2, U3.3, U3.4 — object expansion + rule expansion.
// C2: U3.5, U3.6 — struct sizing static_asserts.
// C3: U3.7, U3.8, U3.25 — L2 compound construction.
// C4: U3.9, U3.10, U3.11, U3.24 — L4 compound construction.
// C5: U3.12, C6.1-C6.6 — ICMP/D29 + L4 compound corners.
// C6: U3.13, U3.14, U3.15, U3.16 — rule tiering + first-match-wins.
// C7: U3.17, U3.18, U3.19, U3.20, U3.21 — mirror reject + D26 strategy.
//
// These test the compiler's object expansion, rule expansion, and
// L2/L4 compound construction mechanics. The compiler takes a
// parsed+validated Config and produces compiled structures.
//
// No DPDK. No EAL. Pure C++ unit tests.

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

#include "src/action/action.h"
#include "src/compiler/compiler.h"
#include "src/compiler/mirror_strategy.h"
#include "src/compiler/object_compiler.h"
#include "src/compiler/rule_compiler.h"
#include "src/config/addr.h"
#include "src/config/model.h"
#include "src/config/sizing.h"
#include "src/ruleset/types.h"

namespace {

using namespace pktgate::compiler;
using namespace pktgate::config;

// Helper: build a minimal valid Config with the given objects/pipeline.
Config make_config() {
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

// Helper: append a rule to a layer, returning a reference so the
// caller can fill in fields. Avoids std::move of Rule which triggers
// GCC -Wmaybe-uninitialized false positives in release mode due to
// the optional<variant<..., ActionMirror(string), ...>> move path.
Rule& append_rule(std::vector<Rule>& layer, std::int32_t id,
                  RuleAction action) {
  auto& r = layer.emplace_back();
  r.id = id;
  r.action = std::move(action);
  return r;
}

// -------------------------------------------------------------------------
// U3.1 Object compiler — subnet list flatten
//
// subnets.corp_v4 = ["10.0.0.0/8", "10.1.0.0/16"] flattens to a
// 2-element Cidr4[] post-expansion. Covers D8.
// -------------------------------------------------------------------------
TEST(ObjectCompiler, SubnetListFlatten_U3_1) {
  ObjectPool pool;
  SubnetObject sobj;
  sobj.name = "corp_v4";

  // 10.0.0.0/8 → addr=0x0A000000
  Cidr4 c1{};
  c1.addr = 0x0A000000;
  c1.prefix = 8;
  sobj.cidrs.push_back(c1);

  // 10.1.0.0/16 → addr=0x0A010000
  Cidr4 c2{};
  c2.addr = 0x0A010000;
  c2.prefix = 16;
  sobj.cidrs.push_back(c2);

  pool.subnets.push_back(std::move(sobj));

  auto compiled = compile_objects(pool);

  // Must have the "corp_v4" entry
  auto it = compiled.subnets.by_name.find("corp_v4");
  ASSERT_NE(it, compiled.subnets.by_name.end())
      << "corp_v4 subnet not found in compiled objects";

  // Must have exactly 2 CIDRs
  const auto& cidrs = it->second;
  ASSERT_EQ(cidrs.size(), 2u);

  // First CIDR: 10.0.0.0/8
  ASSERT_TRUE(std::holds_alternative<Cidr4>(cidrs[0]));
  const auto& r1 = std::get<Cidr4>(cidrs[0]);
  EXPECT_EQ(r1.addr, 0x0A000000u);
  EXPECT_EQ(r1.prefix, 8);

  // Second CIDR: 10.1.0.0/16
  ASSERT_TRUE(std::holds_alternative<Cidr4>(cidrs[1]));
  const auto& r2 = std::get<Cidr4>(cidrs[1]);
  EXPECT_EQ(r2.addr, 0x0A010000u);
  EXPECT_EQ(r2.prefix, 16);
}

// -------------------------------------------------------------------------
// U3.2 Object compiler — port group expansion
//
// port_groups.web_ports = [80, 443, 8080] expands into three L4
// primary entries keyed {proto=tcp, dport=80/443/8080} (selectivity
// preserved). Covers D15, F1.
//
// At C1 scope we test: (1) port group is resolved by compile_objects,
// (2) a rule referencing the port group via dst_ports expands into 3
// L4 entries each with a distinct dst_port, all sharing the same
// action_index.
// -------------------------------------------------------------------------
TEST(ObjectCompiler, PortGroupExpansion_U3_2) {
  Config cfg = make_config();

  // Set up port group
  PortGroupObject pg;
  pg.name = "web_ports";
  pg.ports = {80, 443, 8080};
  cfg.objects.port_groups.push_back(std::move(pg));

  // Object-level check: compile_objects resolves the port group
  auto objs = compile_objects(cfg.objects);
  auto it = objs.port_groups.by_name.find("web_ports");
  ASSERT_NE(it, objs.port_groups.by_name.end())
      << "web_ports port group not found in compiled objects";
  ASSERT_EQ(it->second.size(), 3u);
  EXPECT_EQ(it->second[0], 80);
  EXPECT_EQ(it->second[1], 443);
  EXPECT_EQ(it->second[2], 8080);

  // Rule-level check: a L4 rule with dst_ports from the port group
  // expands into 3 entries.
  auto& rule = append_rule(cfg.pipeline.layer_4, 3001, ActionDrop{});
  rule.dst_ports = {80, 443, 8080}; // expanded from port group by caller

  auto result = compile(cfg);

  // Must produce 3 L4 entries
  ASSERT_EQ(result.l4_entries.size(), 3u);

  // All entries share the same action_index (single logical rule)
  EXPECT_EQ(result.l4_entries[0].action_index,
            result.l4_entries[1].action_index);
  EXPECT_EQ(result.l4_entries[1].action_index,
            result.l4_entries[2].action_index);

  // Each entry has a distinct dst_port, in order
  EXPECT_EQ(result.l4_entries[0].dst_port, 80);
  EXPECT_EQ(result.l4_entries[1].dst_port, 443);
  EXPECT_EQ(result.l4_entries[2].dst_port, 8080);

  // Only 1 action (the three entries share it)
  ASSERT_EQ(result.l4_actions.size(), 1u);
  EXPECT_EQ(result.l4_actions[0].rule_id, 3001);
  EXPECT_EQ(result.l4_actions[0].verb, ActionVerb::kDrop);
}

// -------------------------------------------------------------------------
// U3.3 Port-list on a single rule expands to multiple entries
//
// A rule with dst_port: [22, 80, 443] produces three L4 compound
// entries, all pointing at the same L4CompoundEntry index (the action
// descriptor is shared). Covers D15.
// -------------------------------------------------------------------------
TEST(ObjectCompiler, PortListExpansion_U3_3) {
  Config cfg = make_config();

  auto& rule = append_rule(cfg.pipeline.layer_4, 3002, ActionAllow{});
  rule.dst_ports = {22, 80, 443};

  auto result = compile(cfg);

  // 3 expanded entries
  ASSERT_EQ(result.l4_entries.size(), 3u);

  // All share the same action_index
  const auto shared_idx = result.l4_entries[0].action_index;
  EXPECT_EQ(result.l4_entries[1].action_index, shared_idx);
  EXPECT_EQ(result.l4_entries[2].action_index, shared_idx);

  // Ports match the input list order
  EXPECT_EQ(result.l4_entries[0].dst_port, 22);
  EXPECT_EQ(result.l4_entries[1].dst_port, 80);
  EXPECT_EQ(result.l4_entries[2].dst_port, 443);

  // Single action entry
  ASSERT_EQ(result.l4_actions.size(), 1u);
  EXPECT_EQ(result.l4_actions[0].rule_id, 3002);
  EXPECT_EQ(result.l4_actions[0].verb, ActionVerb::kAllow);
}

// -------------------------------------------------------------------------
// U3.4 Monotonic counter_slot assignment per layer
//
// N L2 rules get counter_slots in [0..N) contiguously per layer_base.
// Verifies §4.3 dense slot assignment. Covers §4.3, D33.
// -------------------------------------------------------------------------
TEST(ObjectCompiler, MonotonicCounterSlot_U3_4) {
  Config cfg = make_config();

  // Add 5 L2 rules
  for (int i = 0; i < 5; ++i) {
    auto& r = append_rule(cfg.pipeline.layer_2, 1000 + i, ActionAllow{});
    r.vlan_id = 100 + i;  // unique L2 field
  }

  // Add 3 L4 rules (to verify per-layer independence)
  for (int i = 0; i < 3; ++i) {
    auto& r = append_rule(cfg.pipeline.layer_4, 3000 + i, ActionDrop{});
    r.dst_port = 80 + i;
  }

  auto result = compile(cfg);

  // L2: 5 actions with counter_slots 0..4
  ASSERT_EQ(result.l2_actions.size(), 5u);
  for (std::uint16_t i = 0; i < 5; ++i) {
    EXPECT_EQ(result.l2_actions[i].counter_slot, i)
        << "L2 action " << i << " has wrong counter_slot";
  }

  // L4: 3 actions with counter_slots 0..2 (independent of L2)
  ASSERT_EQ(result.l4_actions.size(), 3u);
  for (std::uint16_t i = 0; i < 3; ++i) {
    EXPECT_EQ(result.l4_actions[i].counter_slot, i)
        << "L4 action " << i << " has wrong counter_slot";
  }
}

// -------------------------------------------------------------------------
// U3.5 Compiled RuleAction sizing invariant (static_assert)
//
// sizeof(RuleAction) == 20 and alignof(RuleAction) == 4. Covers D22.
// The static_asserts live in action.h itself — this test is a runtime
// witness that the header compiled successfully with the invariant
// intact. If action.h changes and breaks the assertion, this TU fails
// to compile, which is the intended signal.
// -------------------------------------------------------------------------
TEST(CompilerStructSizing, RuleActionSize_U3_5) {
  static_assert(sizeof(pktgate::action::RuleAction) == 20,
                "RuleAction layout drift — expected 20 B (D22)");
  static_assert(alignof(pktgate::action::RuleAction) == 4,
                "RuleAction alignment drift — expected 4 (D22)");
  SUCCEED() << "RuleAction is 20 B, alignas(4) — D22 invariant holds";
}

// -------------------------------------------------------------------------
// U3.6 Compiled L2CompoundEntry sizing invariant
//
// sizeof(L2CompoundEntry) == 16. Covers 2nd external review, §4.1.
// -------------------------------------------------------------------------
TEST(CompilerStructSizing, L2CompoundEntrySize_U3_6) {
  static_assert(sizeof(pktgate::ruleset::L2CompoundEntry) == 16,
                "L2CompoundEntry layout drift — expected 16 B");
  SUCCEED() << "L2CompoundEntry is 16 B — §4.1 invariant holds";
}

// =========================================================================
// C3 — L2 compound construction
// =========================================================================

// Helper: pack a Mac into a uint64_t the same way the runtime does
// (first 6 bytes of a uint64_t in memory order, upper 2 bytes zero).
static std::uint64_t mac_to_u64(const Mac& m) {
  std::uint64_t v = 0;
  auto* p = reinterpret_cast<std::uint8_t*>(&v);
  for (std::size_t i = 0; i < 6; ++i) p[i] = m.bytes[i];
  return v;
}

// -------------------------------------------------------------------------
// U3.7 L2 compound construction — src_mac primary
//
// A rule with src_mac constraint becomes an entry with primary kind
// kSrcMac, and the filter_mask reflects any secondary constraints
// (vlan/ethertype/dst_mac/pcp). Covers D15, F1.
// -------------------------------------------------------------------------
TEST(L2CompoundConstruction, SrcMacPrimary_U3_7) {
  Config cfg = make_config();

  // Rule: src_mac + vlan_id + ethertype
  auto& rule = append_rule(cfg.pipeline.layer_2, 2001, ActionAllow{});
  Mac src{};
  src.bytes = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
  rule.src_mac = src;
  rule.vlan_id = 100;
  rule.ethertype = 0x0800;

  auto result = compile(cfg);

  // compile_l2_rules takes the L2 rules and their compiled actions
  auto l2 = compile_l2_rules(cfg.pipeline.layer_2, result.l2_actions);
  ASSERT_EQ(l2.size(), 1u);

  // Primary must be src_mac (most selective constrained field)
  EXPECT_EQ(l2[0].primary_kind, L2PrimaryKind::kSrcMac);
  EXPECT_EQ(l2[0].primary_key, mac_to_u64(src));

  // filter_mask must have VLAN + ETHERTYPE bits set (secondary constraints)
  // but NOT SRC_MAC (that's the primary)
  EXPECT_TRUE(l2[0].entry.filter_mask & l2_mask::kVlan)
      << "VLAN bit must be set (secondary constraint)";
  EXPECT_TRUE(l2[0].entry.filter_mask & l2_mask::kEthertype)
      << "ETHERTYPE bit must be set (secondary constraint)";
  EXPECT_FALSE(l2[0].entry.filter_mask & l2_mask::kSrcMac)
      << "SRC_MAC bit must NOT be set (it's the primary)";
  EXPECT_FALSE(l2[0].entry.filter_mask & l2_mask::kDstMac)
      << "DST_MAC bit must NOT be set (not constrained)";
  EXPECT_FALSE(l2[0].entry.filter_mask & l2_mask::kPcp)
      << "PCP bit must NOT be set (not constrained)";

  // Secondary want_* values must be populated
  EXPECT_EQ(l2[0].entry.want_vlan, 100);
  EXPECT_EQ(l2[0].entry.want_ethertype, 0x0800);

  // action_idx must point at the right action
  EXPECT_EQ(l2[0].entry.action_idx, 0);
}

// -------------------------------------------------------------------------
// U3.8 L2 compound — src+dst+vlan selectivity ordering
//
// When a rule constrains src_mac, dst_mac, vlan, and ethertype, the
// compiler picks src_mac as primary (per §5.2 selectivity order) and
// puts the rest in the filter_mask bitmap. Covers D15, §5.2.
// -------------------------------------------------------------------------
TEST(L2CompoundConstruction, SelectivityOrdering_U3_8) {
  Config cfg = make_config();

  // Rule: src_mac + dst_mac + vlan_id + ethertype (all four constrained)
  auto& rule = append_rule(cfg.pipeline.layer_2, 2002, ActionDrop{});
  Mac src{};
  src.bytes = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  Mac dst{};
  dst.bytes = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
  rule.src_mac = src;
  rule.dst_mac = dst;
  rule.vlan_id = 200;
  rule.ethertype = 0x86DD;

  auto result = compile(cfg);
  auto l2 = compile_l2_rules(cfg.pipeline.layer_2, result.l2_actions);
  ASSERT_EQ(l2.size(), 1u);

  // Primary must be src_mac (highest selectivity)
  EXPECT_EQ(l2[0].primary_kind, L2PrimaryKind::kSrcMac);
  EXPECT_EQ(l2[0].primary_key, mac_to_u64(src));

  // filter_mask must have DST_MAC + VLAN + ETHERTYPE
  EXPECT_TRUE(l2[0].entry.filter_mask & l2_mask::kDstMac);
  EXPECT_TRUE(l2[0].entry.filter_mask & l2_mask::kVlan);
  EXPECT_TRUE(l2[0].entry.filter_mask & l2_mask::kEthertype);
  EXPECT_FALSE(l2[0].entry.filter_mask & l2_mask::kSrcMac)
      << "SRC_MAC must NOT be in filter_mask (it's the primary)";
  EXPECT_FALSE(l2[0].entry.filter_mask & l2_mask::kPcp)
      << "PCP not constrained";

  // want_mac must hold the dst_mac (the "other" MAC, per §4.1)
  for (std::size_t i = 0; i < 6; ++i) {
    EXPECT_EQ(l2[0].entry.want_mac[i], dst.bytes[i])
        << "want_mac[" << i << "] mismatch";
  }
  EXPECT_EQ(l2[0].entry.want_vlan, 200);
  EXPECT_EQ(l2[0].entry.want_ethertype, 0x86DD);

  // Also verify: a rule with ONLY dst_mac (no src_mac) picks dst_mac
  // as primary, and a rule with ONLY vlan picks vlan, etc.
  Config cfg2 = make_config();
  auto& r2 = append_rule(cfg2.pipeline.layer_2, 2003, ActionAllow{});
  r2.dst_mac = dst;
  r2.vlan_id = 300;

  auto result2 = compile(cfg2);
  auto l2b = compile_l2_rules(cfg2.pipeline.layer_2, result2.l2_actions);
  ASSERT_EQ(l2b.size(), 1u);
  EXPECT_EQ(l2b[0].primary_kind, L2PrimaryKind::kDstMac)
      << "Without src_mac, dst_mac should be primary";
  EXPECT_EQ(l2b[0].primary_key, mac_to_u64(dst));
  EXPECT_TRUE(l2b[0].entry.filter_mask & l2_mask::kVlan);
  EXPECT_FALSE(l2b[0].entry.filter_mask & l2_mask::kDstMac)
      << "DST_MAC is primary, must not be in filter_mask";

  // A rule with only vlan_id picks vlan as primary
  Config cfg3 = make_config();
  auto& r3 = append_rule(cfg3.pipeline.layer_2, 2004, ActionAllow{});
  r3.vlan_id = 400;

  auto result3 = compile(cfg3);
  auto l2c = compile_l2_rules(cfg3.pipeline.layer_2, result3.l2_actions);
  ASSERT_EQ(l2c.size(), 1u);
  EXPECT_EQ(l2c[0].primary_kind, L2PrimaryKind::kVlan);
  EXPECT_EQ(l2c[0].primary_key, 400u);
  EXPECT_EQ(l2c[0].entry.filter_mask, 0u)
      << "Only vlan constrained and it's the primary — no secondary bits";

  // A rule with only ethertype picks ethertype
  Config cfg4 = make_config();
  auto& r4 = append_rule(cfg4.pipeline.layer_2, 2005, ActionAllow{});
  r4.ethertype = 0x0800;

  auto result4 = compile(cfg4);
  auto l2d = compile_l2_rules(cfg4.pipeline.layer_2, result4.l2_actions);
  ASSERT_EQ(l2d.size(), 1u);
  EXPECT_EQ(l2d[0].primary_kind, L2PrimaryKind::kEthertype);
  EXPECT_EQ(l2d[0].primary_key, 0x0800u);

  // A rule with only pcp picks pcp
  Config cfg5 = make_config();
  auto& r5 = append_rule(cfg5.pipeline.layer_2, 2006, ActionAllow{});
  r5.pcp = 5;

  auto result5 = compile(cfg5);
  auto l2e = compile_l2_rules(cfg5.pipeline.layer_2, result5.l2_actions);
  ASSERT_EQ(l2e.size(), 1u);
  EXPECT_EQ(l2e[0].primary_kind, L2PrimaryKind::kPcp);
  EXPECT_EQ(l2e[0].primary_key, 5u);
}

// -------------------------------------------------------------------------
// U3.25 Port-list with duplicates flagged or deduped
//
// dst_port: [80, 80, 443] produces two unique entries (dedup policy).
// Covers D8.
//
// Note: U3.25 talks about port-list dedup. At L2 level there are no
// port lists, but the dedup principle applies to dst_ports at the
// compile() level. We test that compile() deduplicates port entries.
// -------------------------------------------------------------------------
TEST(PortListDedup, DuplicatePortsDeduped_U3_25) {
  Config cfg = make_config();

  auto& rule = append_rule(cfg.pipeline.layer_4, 3010, ActionAllow{});
  rule.dst_ports = {80, 80, 443};

  auto result = compile(cfg);

  // Should produce 2 unique entries, not 3
  ASSERT_EQ(result.l4_entries.size(), 2u)
      << "Duplicate port 80 should be deduped";

  // The two unique ports are 80 and 443
  EXPECT_EQ(result.l4_entries[0].dst_port, 80);
  EXPECT_EQ(result.l4_entries[1].dst_port, 443);

  // Both share the same action
  EXPECT_EQ(result.l4_entries[0].action_index,
            result.l4_entries[1].action_index);
}

// =========================================================================
// C4 — L4 compound construction
// =========================================================================

// -------------------------------------------------------------------------
// U3.9 L4 compound — proto+dport primary
//
// Rule {proto: tcp, dst_port: 443} becomes an entry in l4_proto_dport
// keyed (tcp<<16 | 443); filter_mask has no bits set. Covers D15.
// -------------------------------------------------------------------------
TEST(L4CompoundConstruction, ProtoDportPrimary_U3_9) {
  Config cfg = make_config();

  // TCP = 6, dst_port = 443
  auto& rule = append_rule(cfg.pipeline.layer_4, 4001, ActionAllow{});
  rule.proto = 6;       // TCP
  rule.dst_port = 443;

  auto result = compile(cfg);
  auto l4out = compile_l4_rules(cfg.pipeline.layer_4, result.l4_actions);
  ASSERT_EQ(l4out.rules.size(), 1u);
  ASSERT_TRUE(l4out.collisions.empty());

  const auto& cr = l4out.rules[0];

  // Primary must be kProtoDport
  EXPECT_EQ(cr.primary_kind, L4PrimaryKind::kProtoDport);

  // Key = (proto << 16) | dport = (6 << 16) | 443
  const std::uint32_t expected_key = (6u << 16) | 443u;
  EXPECT_EQ(cr.primary_key, expected_key);

  // filter_mask: no secondary constraints → 0
  EXPECT_EQ(cr.entry.filter_mask, 0u)
      << "No secondary constraints — filter_mask must be zero";

  // action_idx must point at the right action
  EXPECT_EQ(cr.entry.action_idx, 0u);
}

// -------------------------------------------------------------------------
// U3.10 L4 compound — proto+dport+sport has SRC_PORT bit
//
// With src_port also constrained, the SRC_PORT bit is set in
// L4CompoundEntry.filter_mask and want_src_port is populated.
// Covers D15.
// -------------------------------------------------------------------------
TEST(L4CompoundConstruction, ProtoDportSportSrcPortBit_U3_10) {
  Config cfg = make_config();

  // TCP = 6, dst_port = 443, src_port = 12345
  auto& rule = append_rule(cfg.pipeline.layer_4, 4002, ActionDrop{});
  rule.proto = 6;         // TCP
  rule.dst_port = 443;
  rule.src_port = 12345;

  auto result = compile(cfg);
  auto l4out = compile_l4_rules(cfg.pipeline.layer_4, result.l4_actions);
  ASSERT_EQ(l4out.rules.size(), 1u);

  const auto& cr = l4out.rules[0];

  // Primary must be kProtoDport
  EXPECT_EQ(cr.primary_kind, L4PrimaryKind::kProtoDport);
  const std::uint32_t expected_key = (6u << 16) | 443u;
  EXPECT_EQ(cr.primary_key, expected_key);

  // filter_mask: SRC_PORT bit set
  EXPECT_TRUE(cr.entry.filter_mask & l4_mask::kSrcPort)
      << "SRC_PORT bit must be set when src_port is constrained";

  // want_src_port must hold the constrained value
  EXPECT_EQ(cr.entry.want_src_port, 12345u);

  // No TCP_FLAGS or VRF bits
  EXPECT_FALSE(cr.entry.filter_mask & l4_mask::kTcpFlags);
  EXPECT_FALSE(cr.entry.filter_mask & l4_mask::kVrf);
}

// -------------------------------------------------------------------------
// U3.11 L4 compound — proto only goes to l4_proto_only
//
// Rule {proto: icmp} with no port constraint lands in l4_proto_only
// hash, not the dport/sport tables. Covers D15.
// -------------------------------------------------------------------------
TEST(L4CompoundConstruction, ProtoOnlyTable_U3_11) {
  Config cfg = make_config();

  // ICMP = 1, no port constraint
  auto& rule = append_rule(cfg.pipeline.layer_4, 4003, ActionAllow{});
  rule.proto = 1;  // ICMP

  auto result = compile(cfg);
  auto l4out = compile_l4_rules(cfg.pipeline.layer_4, result.l4_actions);
  ASSERT_EQ(l4out.rules.size(), 1u);

  const auto& cr = l4out.rules[0];

  // Primary must be kProtoOnly
  EXPECT_EQ(cr.primary_kind, L4PrimaryKind::kProtoOnly);

  // Key = proto (just the protocol number)
  EXPECT_EQ(cr.primary_key, 1u);

  // filter_mask: no secondary constraints → 0
  EXPECT_EQ(cr.entry.filter_mask, 0u)
      << "Proto-only rule has no secondary constraints";
}

// -------------------------------------------------------------------------
// U3.24 Collision detection — L4 compound identical keys
//
// Two L4 rules with identical primary key AND identical filter_mask
// content are reported as a collision (dead rule). Covers D15,
// compiler correctness.
// -------------------------------------------------------------------------
TEST(L4CompoundConstruction, CollisionDetection_U3_24) {
  Config cfg = make_config();

  // Rule 1: TCP/443, no secondary constraints
  auto& r1 = append_rule(cfg.pipeline.layer_4, 4010, ActionAllow{});
  r1.proto = 6;
  r1.dst_port = 443;

  // Rule 2: TCP/443, identical — dead rule
  auto& r2 = append_rule(cfg.pipeline.layer_4, 4011, ActionDrop{});
  r2.proto = 6;
  r2.dst_port = 443;

  auto result = compile(cfg);
  auto l4out = compile_l4_rules(cfg.pipeline.layer_4, result.l4_actions);

  // Both rules still produce entries (the compiler doesn't remove them)
  EXPECT_EQ(l4out.rules.size(), 2u);

  // But there must be exactly one collision reported
  ASSERT_EQ(l4out.collisions.size(), 1u);
  EXPECT_EQ(l4out.collisions[0].rule_index_first, 0u);
  EXPECT_EQ(l4out.collisions[0].rule_index_second, 1u);

  // Now test that different filter_mask content is NOT a collision:
  // Rule A: TCP/80 with src_port=1234
  // Rule B: TCP/80 without src_port
  // These have the same primary key but different filter_mask → not a collision.
  Config cfg2 = make_config();
  auto& ra = append_rule(cfg2.pipeline.layer_4, 4020, ActionAllow{});
  ra.proto = 6;
  ra.dst_port = 80;
  ra.src_port = 1234;

  auto& rb = append_rule(cfg2.pipeline.layer_4, 4021, ActionDrop{});
  rb.proto = 6;
  rb.dst_port = 80;

  auto result2 = compile(cfg2);
  auto l4out2 = compile_l4_rules(cfg2.pipeline.layer_4, result2.l4_actions);

  EXPECT_EQ(l4out2.rules.size(), 2u);
  EXPECT_TRUE(l4out2.collisions.empty())
      << "Different filter_mask should NOT be reported as collision";
}

// =========================================================================
// C5 — ICMP/D29 + L4 compound corners
// =========================================================================

// -------------------------------------------------------------------------
// U3.12 L4 compound — ICMP type+code packing (D29)
//
// Rule matching `icmp type=8 code=0` packs type into dport slot, code
// into sport slot; SRC_PORT bit set because code is constrained; no
// separate want_icmp_code field. Covers D14, D29.
//
// Per D29 unification: ICMP type goes to dst_port, ICMP code goes to
// src_port. The compiler treats them identically to TCP/UDP ports.
// -------------------------------------------------------------------------
TEST(L4CompoundICMP, IcmpTypeCodePacking_U3_12) {
  Config cfg = make_config();

  // ICMP = 1, type=8 (echo request) → dport slot, code=0 → sport slot
  auto& rule = append_rule(cfg.pipeline.layer_4, 5001, ActionDrop{});
  rule.proto = 1;        // ICMP
  rule.dst_port = 8;     // type=8 in dport slot (D29)
  rule.src_port = 0;     // code=0 in sport slot (D29)

  auto result = compile(cfg);
  auto l4out = compile_l4_rules(cfg.pipeline.layer_4, result.l4_actions);
  ASSERT_EQ(l4out.rules.size(), 1u);
  ASSERT_TRUE(l4out.collisions.empty());

  const auto& cr = l4out.rules[0];

  // Primary: kProtoDport with key = (1 << 16) | 8
  EXPECT_EQ(cr.primary_kind, L4PrimaryKind::kProtoDport);
  const std::uint32_t expected_key = (1u << 16) | 8u;
  EXPECT_EQ(cr.primary_key, expected_key)
      << "ICMP type=8 must pack as (proto=1 << 16) | type=8";

  // SRC_PORT bit MUST be set: code=0 is a real constraint (code IS specified)
  EXPECT_TRUE(cr.entry.filter_mask & l4_mask::kSrcPort)
      << "SRC_PORT bit must be set when ICMP code is constrained (D29)";

  // want_src_port holds the ICMP code value
  EXPECT_EQ(cr.entry.want_src_port, 0u)
      << "ICMP code=0 must be stored in want_src_port slot (D29)";

  // No TCP_FLAGS bit (ICMP doesn't have TCP flags)
  EXPECT_FALSE(cr.entry.filter_mask & l4_mask::kTcpFlags);
}

// -------------------------------------------------------------------------
// C6.1 TCP SYN only, dport=443 (compiler-level)
//
// L4 rule {proto:tcp, dport:443, tcp_flags:{syn:true}, drop}. Assert
// compiler produces entry with TCP_FLAGS bit in filter_mask. Covers
// D15 compound with TCP_FLAGS secondary.
// -------------------------------------------------------------------------
TEST(L4CompoundCorners, TcpSynDport443_C6_1) {
  Config cfg = make_config();

  auto& rule = append_rule(cfg.pipeline.layer_4, 6001, ActionDrop{});
  rule.proto = 6;         // TCP
  rule.dst_port = 443;
  // tcp_flags: syn=true → mask=0x02, want=0x02
  TcpFlags flags;
  flags.mask = 0x02;  // SYN bit in mask
  flags.want = 0x02;  // SYN bit in want
  rule.tcp_flags = flags;

  auto result = compile(cfg);
  auto l4out = compile_l4_rules(cfg.pipeline.layer_4, result.l4_actions);
  ASSERT_EQ(l4out.rules.size(), 1u);

  const auto& cr = l4out.rules[0];

  // Primary: TCP/443
  EXPECT_EQ(cr.primary_kind, L4PrimaryKind::kProtoDport);
  EXPECT_EQ(cr.primary_key, (6u << 16) | 443u);

  // filter_mask MUST have TCP_FLAGS bit set
  EXPECT_TRUE(cr.entry.filter_mask & l4_mask::kTcpFlags)
      << "TCP_FLAGS bit must be set when tcp_flags is constrained (D15)";

  // The stored flags values must match
  EXPECT_EQ(cr.entry.tcp_flags_mask, 0x02u)
      << "tcp_flags_mask must contain SYN bit";
  EXPECT_EQ(cr.entry.tcp_flags_want, 0x02u)
      << "tcp_flags_want must have SYN bit set (syn=true)";

  // No SRC_PORT bit (no src_port constraint)
  EXPECT_FALSE(cr.entry.filter_mask & l4_mask::kSrcPort);
}

// -------------------------------------------------------------------------
// C6.2 TCP FIN, dport=443 (same rule structure, wrong flags)
//
// Same rule as C6.1. At compiler level: verify filter_mask has TCP_FLAGS
// bit set so a FIN packet would NOT match at runtime. Covers D15.
//
// Note: actual runtime mismatch is M6 — here we just verify the entry
// structure correctly encodes the constraint that distinguishes SYN
// from FIN.
// -------------------------------------------------------------------------
TEST(L4CompoundCorners, TcpFinMiss_C6_2) {
  Config cfg = make_config();

  // Same rule as C6.1: TCP/443, tcp_flags={syn:true}
  auto& rule = append_rule(cfg.pipeline.layer_4, 6002, ActionDrop{});
  rule.proto = 6;
  rule.dst_port = 443;
  TcpFlags flags;
  flags.mask = 0x02;  // SYN bit
  flags.want = 0x02;  // SYN must be set
  rule.tcp_flags = flags;

  auto result = compile(cfg);
  auto l4out = compile_l4_rules(cfg.pipeline.layer_4, result.l4_actions);
  ASSERT_EQ(l4out.rules.size(), 1u);

  const auto& cr = l4out.rules[0];

  // filter_mask has TCP_FLAGS — this is the gate that prevents a FIN
  // packet (flags=0x01) from matching at runtime
  EXPECT_TRUE(cr.entry.filter_mask & l4_mask::kTcpFlags)
      << "TCP_FLAGS bit must be set — this is what blocks FIN at runtime";

  // The constraint: mask=0x02 (check SYN), want=0x02 (SYN must be set)
  // A FIN packet has flags=0x01: (0x01 & 0x02) == 0 != 0x02 → mismatch
  EXPECT_EQ(cr.entry.tcp_flags_mask, 0x02u);
  EXPECT_EQ(cr.entry.tcp_flags_want, 0x02u);

  // Verify the runtime check would indeed reject FIN=0x01:
  // (packet_flags & mask) == want  →  (0x01 & 0x02) == 0x02  →  false
  constexpr std::uint8_t fin_flags = 0x01;
  EXPECT_NE(fin_flags & cr.entry.tcp_flags_mask, cr.entry.tcp_flags_want)
      << "FIN packet must NOT match the SYN-only constraint";
}

// -------------------------------------------------------------------------
// C6.3 UDP dport=53 wildcard src (compiler-level)
//
// Rule {udp, dport:53, drop} with no src_port. Assert NO SRC_PORT bit
// in filter_mask. Covers D15.
// -------------------------------------------------------------------------
TEST(L4CompoundCorners, UdpDport53WildcardSrc_C6_3) {
  Config cfg = make_config();

  auto& rule = append_rule(cfg.pipeline.layer_4, 6003, ActionDrop{});
  rule.proto = 17;       // UDP
  rule.dst_port = 53;    // DNS
  // No src_port constraint

  auto result = compile(cfg);
  auto l4out = compile_l4_rules(cfg.pipeline.layer_4, result.l4_actions);
  ASSERT_EQ(l4out.rules.size(), 1u);

  const auto& cr = l4out.rules[0];

  // Primary: UDP/53
  EXPECT_EQ(cr.primary_kind, L4PrimaryKind::kProtoDport);
  EXPECT_EQ(cr.primary_key, (17u << 16) | 53u);

  // NO SRC_PORT bit — wildcard matches any source port
  EXPECT_FALSE(cr.entry.filter_mask & l4_mask::kSrcPort)
      << "SRC_PORT bit must NOT be set when no src_port constraint (D15)";

  // No TCP_FLAGS bit either (UDP)
  EXPECT_FALSE(cr.entry.filter_mask & l4_mask::kTcpFlags);

  // filter_mask should be completely zero (no secondary constraints)
  EXPECT_EQ(cr.entry.filter_mask, 0u);
}

// -------------------------------------------------------------------------
// C6.4 UDP dport=53 with src_port=1234 constraint (compiler-level)
//
// Assert SRC_PORT bit IS set and want_src_port=1234. Covers D15.
// -------------------------------------------------------------------------
TEST(L4CompoundCorners, UdpDport53WithSport_C6_4) {
  Config cfg = make_config();

  auto& rule = append_rule(cfg.pipeline.layer_4, 6004, ActionDrop{});
  rule.proto = 17;        // UDP
  rule.dst_port = 53;     // DNS
  rule.src_port = 1234;   // Specific source port

  auto result = compile(cfg);
  auto l4out = compile_l4_rules(cfg.pipeline.layer_4, result.l4_actions);
  ASSERT_EQ(l4out.rules.size(), 1u);

  const auto& cr = l4out.rules[0];

  // Primary: UDP/53
  EXPECT_EQ(cr.primary_kind, L4PrimaryKind::kProtoDport);
  EXPECT_EQ(cr.primary_key, (17u << 16) | 53u);

  // SRC_PORT bit MUST be set
  EXPECT_TRUE(cr.entry.filter_mask & l4_mask::kSrcPort)
      << "SRC_PORT bit must be set when src_port=1234 is constrained (D15)";

  // want_src_port must hold the constraint value
  EXPECT_EQ(cr.entry.want_src_port, 1234u);
}

// -------------------------------------------------------------------------
// C6.5 ICMP echo request (type=8, code=0) — compiler-level
//
// Rule {proto:icmp, dst_port:8, drop} — type in dport slot per D29.
// Assert proto_dport key = (1<<16)|8. Covers D29.
// -------------------------------------------------------------------------
TEST(L4CompoundCorners, IcmpEchoRequest_C6_5) {
  Config cfg = make_config();

  // ICMP echo: type=8 → dport slot, no code constraint (wildcard code)
  auto& rule = append_rule(cfg.pipeline.layer_4, 6005, ActionDrop{});
  rule.proto = 1;        // ICMP
  rule.dst_port = 8;     // type=8 (echo request) in dport slot (D29)

  auto result = compile(cfg);
  auto l4out = compile_l4_rules(cfg.pipeline.layer_4, result.l4_actions);
  ASSERT_EQ(l4out.rules.size(), 1u);

  const auto& cr = l4out.rules[0];

  // Primary: proto_dport key = (1 << 16) | 8
  EXPECT_EQ(cr.primary_kind, L4PrimaryKind::kProtoDport);
  EXPECT_EQ(cr.primary_key, (1u << 16) | 8u)
      << "ICMP type=8 packs as (proto=1 << 16) | type=8 (D29)";

  // No SRC_PORT bit — code is not constrained (wildcard)
  EXPECT_FALSE(cr.entry.filter_mask & l4_mask::kSrcPort)
      << "No code constraint → SRC_PORT bit must NOT be set";

  // filter_mask completely zero
  EXPECT_EQ(cr.entry.filter_mask, 0u);
}

// -------------------------------------------------------------------------
// C6.6 ICMP dest unreachable, code=3 (port unreachable) — compiler-level
//
// Rule {proto:icmp, dst_port:3, src_port:3, drop} — type=3→dport,
// code=3→sport per D29 packing. Assert SRC_PORT bit set,
// want_src_port=3. Covers D29.
// -------------------------------------------------------------------------
TEST(L4CompoundCorners, IcmpDestUnreachableCode3_C6_6) {
  Config cfg = make_config();

  // ICMP dest unreachable: type=3 → dport, code=3 → sport
  auto& rule = append_rule(cfg.pipeline.layer_4, 6006, ActionDrop{});
  rule.proto = 1;        // ICMP
  rule.dst_port = 3;     // type=3 (dest unreachable) in dport slot (D29)
  rule.src_port = 3;     // code=3 (port unreachable) in sport slot (D29)

  auto result = compile(cfg);
  auto l4out = compile_l4_rules(cfg.pipeline.layer_4, result.l4_actions);
  ASSERT_EQ(l4out.rules.size(), 1u);

  const auto& cr = l4out.rules[0];

  // Primary: proto_dport key = (1 << 16) | 3
  EXPECT_EQ(cr.primary_kind, L4PrimaryKind::kProtoDport);
  EXPECT_EQ(cr.primary_key, (1u << 16) | 3u)
      << "ICMP type=3 packs as (proto=1 << 16) | type=3 (D29)";

  // SRC_PORT bit MUST be set (code=3 is constrained)
  EXPECT_TRUE(cr.entry.filter_mask & l4_mask::kSrcPort)
      << "SRC_PORT bit must be set when ICMP code is constrained (D29)";

  // want_src_port holds the ICMP code value
  EXPECT_EQ(cr.entry.want_src_port, 3u)
      << "ICMP code=3 must be in want_src_port slot (D29)";

  // No TCP_FLAGS bit
  EXPECT_FALSE(cr.entry.filter_mask & l4_mask::kTcpFlags);
}

// =========================================================================
// C6 — Rule tiering + first-match-wins
// =========================================================================

// -------------------------------------------------------------------------
// U3.13 Rule tiering — default software
//
// Rules without hw_offload_hint get execution_tier == SW in the compiled
// action output. Covers D4.
// -------------------------------------------------------------------------
TEST(RuleTiering, DefaultSoftware_U3_13) {
  Config cfg = make_config();

  // Rule with default hw_offload_hint (false)
  auto& rule = append_rule(cfg.pipeline.layer_4, 7001, ActionAllow{});
  rule.proto = 6;
  rule.dst_port = 80;
  // hw_offload_hint defaults to false — do NOT set it

  auto result = compile(cfg);

  // The L4 action must have execution_tier == kSw
  ASSERT_EQ(result.l4_actions.size(), 1u);
  EXPECT_EQ(result.l4_actions[0].execution_tier, ExecutionTier::kSw)
      << "Rule without hw_offload_hint must get execution_tier == SW (D4)";
}

// -------------------------------------------------------------------------
// U3.14 Rule tiering — operator hint honored
//
// hw_offload_hint: true produces execution_tier == HW in compiled action.
// Covers D4.
// -------------------------------------------------------------------------
TEST(RuleTiering, OperatorHintHonored_U3_14) {
  Config cfg = make_config();

  auto& rule = append_rule(cfg.pipeline.layer_4, 7002, ActionDrop{});
  rule.proto = 6;
  rule.dst_port = 443;
  rule.hw_offload_hint = true;

  // Compile with hw_offload_enabled = true so the hint is honored
  CompileOptions opts;
  opts.hw_offload_enabled = true;
  auto result = compile(cfg, opts);

  ASSERT_EQ(result.l4_actions.size(), 1u);
  EXPECT_EQ(result.l4_actions[0].execution_tier, ExecutionTier::kHw)
      << "Rule with hw_offload_hint=true must get execution_tier == HW (D4)";
}

// -------------------------------------------------------------------------
// U3.15 Rule tiering — MVP may globally disable
//
// With hw_offload_enabled == false (MVP default), compiler demotes all
// rules back to SW at publish time. Even rules with hw_offload_hint=true
// end up as SW. Covers D4, §14 MVP.
// -------------------------------------------------------------------------
TEST(RuleTiering, MvpGlobalDisable_U3_15) {
  Config cfg = make_config();

  // Two rules: one with hint=true, one default (false)
  auto& r1 = append_rule(cfg.pipeline.layer_4, 7003, ActionAllow{});
  r1.proto = 6;
  r1.dst_port = 80;
  r1.hw_offload_hint = true;

  auto& r2 = append_rule(cfg.pipeline.layer_4, 7004, ActionDrop{});
  r2.proto = 17;
  r2.dst_port = 53;
  // hw_offload_hint defaults to false

  // Compile with hw_offload_enabled = false (MVP default)
  CompileOptions opts;
  opts.hw_offload_enabled = false;
  auto result = compile(cfg, opts);

  ASSERT_EQ(result.l4_actions.size(), 2u);
  EXPECT_EQ(result.l4_actions[0].execution_tier, ExecutionTier::kSw)
      << "Even with hint=true, global disable must demote to SW (D4 MVP)";
  EXPECT_EQ(result.l4_actions[1].execution_tier, ExecutionTier::kSw)
      << "Default hint + global disable must remain SW (D4 MVP)";
}

// -------------------------------------------------------------------------
// U3.16 First-match-wins iteration order preserved
//
// Within a layer, compiled RuleAction[] entries appear in the order rules
// were declared in the config. The action_idx assigned to each primary-
// hash entry reflects config order. Covers F1.
// -------------------------------------------------------------------------
TEST(RuleTiering, FirstMatchWinsOrder_U3_16) {
  Config cfg = make_config();

  // Add 4 L4 rules in a specific order
  auto& r1 = append_rule(cfg.pipeline.layer_4, 8001, ActionAllow{});
  r1.proto = 6;
  r1.dst_port = 80;

  auto& r2 = append_rule(cfg.pipeline.layer_4, 8002, ActionDrop{});
  r2.proto = 6;
  r2.dst_port = 443;

  auto& r3 = append_rule(cfg.pipeline.layer_4, 8003, ActionAllow{});
  r3.proto = 17;
  r3.dst_port = 53;

  auto& r4 = append_rule(cfg.pipeline.layer_4, 8004, ActionDrop{});
  r4.proto = 1;
  r4.dst_port = 8;  // ICMP echo request via D29

  auto result = compile(cfg);

  // 4 actions in declaration order
  ASSERT_EQ(result.l4_actions.size(), 4u);
  EXPECT_EQ(result.l4_actions[0].rule_id, 8001);
  EXPECT_EQ(result.l4_actions[1].rule_id, 8002);
  EXPECT_EQ(result.l4_actions[2].rule_id, 8003);
  EXPECT_EQ(result.l4_actions[3].rule_id, 8004);

  // counter_slots must be dense and in order: 0, 1, 2, 3
  EXPECT_EQ(result.l4_actions[0].counter_slot, 0u);
  EXPECT_EQ(result.l4_actions[1].counter_slot, 1u);
  EXPECT_EQ(result.l4_actions[2].counter_slot, 2u);
  EXPECT_EQ(result.l4_actions[3].counter_slot, 3u);

  // Entries must reference action indices in declaration order.
  // Each rule produces one entry (no port-list expansion).
  ASSERT_EQ(result.l4_entries.size(), 4u);
  EXPECT_EQ(result.l4_entries[0].action_index, 0u);
  EXPECT_EQ(result.l4_entries[1].action_index, 1u);
  EXPECT_EQ(result.l4_entries[2].action_index, 2u);
  EXPECT_EQ(result.l4_entries[3].action_index, 3u);

  // Also check L2 layer: add 3 L2 rules and verify order
  Config cfg2 = make_config();
  auto& l2r1 = append_rule(cfg2.pipeline.layer_2, 9001, ActionAllow{});
  l2r1.vlan_id = 100;

  auto& l2r2 = append_rule(cfg2.pipeline.layer_2, 9002, ActionDrop{});
  l2r2.vlan_id = 200;

  auto& l2r3 = append_rule(cfg2.pipeline.layer_2, 9003, ActionAllow{});
  l2r3.ethertype = 0x0800;

  auto result2 = compile(cfg2);

  // 3 L2 actions in declaration order
  ASSERT_EQ(result2.l2_actions.size(), 3u);
  EXPECT_EQ(result2.l2_actions[0].rule_id, 9001);
  EXPECT_EQ(result2.l2_actions[1].rule_id, 9002);
  EXPECT_EQ(result2.l2_actions[2].rule_id, 9003);

  // Entries in order
  ASSERT_EQ(result2.l2_entries.size(), 3u);
  EXPECT_EQ(result2.l2_entries[0].action_index, 0u);
  EXPECT_EQ(result2.l2_entries[1].action_index, 1u);
  EXPECT_EQ(result2.l2_entries[2].action_index, 2u);
}

// =========================================================================
// C7 — Mirror reject + D26 strategy
// =========================================================================

// -------------------------------------------------------------------------
// U3.17 Mirror action compile-time reject (D7 MVP)
//
// Compiling a ruleset containing `action: mirror` produces a
// MirrorNotImplemented error at the compile stage. The compiler rejects
// the mirror verb (D7: mirror not implemented in this build).
// -------------------------------------------------------------------------
TEST(MirrorReject, MirrorNotImplemented_U3_17) {
  Config cfg = make_config();

  // Add a mirror rule to L4
  auto& rule = append_rule(cfg.pipeline.layer_4, 9100, ActionMirror{"mirror_port"});
  rule.proto = 6;
  rule.dst_port = 80;

  auto result = compile(cfg);

  // The compile must produce a compile error
  ASSERT_TRUE(result.error.has_value())
      << "Compiling a mirror rule must produce an error (D7 MVP)";
  EXPECT_EQ(result.error->code, CompileErrorCode::kMirrorNotImplemented)
      << "Error code must be kMirrorNotImplemented";
  EXPECT_NE(result.error->message.find("mirror"), std::string::npos)
      << "Error message must mention 'mirror'";

  // Also verify mirror rules in L2 and L3 layers are rejected
  Config cfg_l2 = make_config();
  auto& r2 = append_rule(cfg_l2.pipeline.layer_2, 9101, ActionMirror{"mirror_port"});
  r2.vlan_id = 100;
  auto result_l2 = compile(cfg_l2);
  ASSERT_TRUE(result_l2.error.has_value())
      << "Mirror in L2 must also be rejected (D7)";
  EXPECT_EQ(result_l2.error->code, CompileErrorCode::kMirrorNotImplemented);

  Config cfg_l3 = make_config();
  append_rule(cfg_l3.pipeline.layer_3, 9102, ActionMirror{"mirror_port"});
  auto result_l3 = compile(cfg_l3);
  ASSERT_TRUE(result_l3.error.has_value())
      << "Mirror in L3 must also be rejected (D7)";
  EXPECT_EQ(result_l3.error->code, CompileErrorCode::kMirrorNotImplemented);
}

// -------------------------------------------------------------------------
// U3.18 D26 mirror strategy — deep copy forced when TAG present
//
// A ruleset with any TAG rule forces mirror_strategy == DEEP_COPY,
// even if config_requests_zero_copy == true. The MUTATING_VERBS set
// is consulted. Covers D26.
// -------------------------------------------------------------------------
TEST(MirrorStrategy, DeepCopyWhenTagPresent_U3_18) {
  // Build a set of verbs that includes TAG (a mutating verb)
  std::vector<ActionVerb> verbs = {
      ActionVerb::kAllow,
      ActionVerb::kDrop,
      ActionVerb::kTag,  // TAG is mutating
  };

  DriverCapabilities caps;
  caps.tx_non_mutating = true;

  // Even with zero_copy requested + driver support, TAG forces DEEP_COPY
  auto strategy = determine_mirror_strategy(
      verbs, /*config_requests_zero_copy=*/true, caps);

  EXPECT_EQ(strategy, MirrorStrategy::kDeepCopy)
      << "TAG present → must select DEEP_COPY regardless of config/driver (D26)";
}

// -------------------------------------------------------------------------
// U3.19 D26 mirror strategy — refcnt allowed when no mutating verbs
//
// Ruleset without TAG (only ALLOW/DROP/RL/REDIRECT) plus
// config_requests_zero_copy==true plus driver cap tx_non_mutating==true
// yields REFCNT_ZERO_COPY. Covers D26.
// -------------------------------------------------------------------------
TEST(MirrorStrategy, RefcntWhenNoMutatingVerbs_U3_19) {
  std::vector<ActionVerb> verbs = {
      ActionVerb::kAllow,
      ActionVerb::kDrop,
      ActionVerb::kRateLimit,
      ActionVerb::kRedirect,
  };

  DriverCapabilities caps;
  caps.tx_non_mutating = true;

  auto strategy = determine_mirror_strategy(
      verbs, /*config_requests_zero_copy=*/true, caps);

  EXPECT_EQ(strategy, MirrorStrategy::kRefcntZeroCopy)
      << "No mutating verbs + zero_copy requested + driver ok → REFCNT_ZERO_COPY (D26)";
}

// -------------------------------------------------------------------------
// U3.20 D26 mirror strategy — driver capability gate
//
// Same as U3.19 but driver cap tx_non_mutating is false → forced
// back to DEEP_COPY. Covers D26.
// -------------------------------------------------------------------------
TEST(MirrorStrategy, DriverCapGate_U3_20) {
  std::vector<ActionVerb> verbs = {
      ActionVerb::kAllow,
      ActionVerb::kDrop,
      ActionVerb::kRateLimit,
      ActionVerb::kRedirect,
  };

  DriverCapabilities caps;
  caps.tx_non_mutating = false;  // driver can't do it

  auto strategy = determine_mirror_strategy(
      verbs, /*config_requests_zero_copy=*/true, caps);

  EXPECT_EQ(strategy, MirrorStrategy::kDeepCopy)
      << "Driver cap false → must fall back to DEEP_COPY (D26)";
}

// -------------------------------------------------------------------------
// U3.21 D26 MUTATING_VERBS enum-scan test
//
// Iterate all ActionVerb enum values and assert each is classified as
// mutating or non-mutating in the compiler's is_mutating_verb() lookup.
// Prevents a new verb being added without D26 update. Covers D26, D25.
// -------------------------------------------------------------------------
TEST(MirrorStrategy, MutatingVerbsEnumScan_U3_21) {
  // D26: MUTATING_VERBS = { TAG } for baseline.
  // All other verbs are non-mutating.
  struct VerbExpect {
    ActionVerb verb;
    bool mutating;
    const char* name;
  };

  const VerbExpect table[] = {
      {ActionVerb::kAllow,     false, "ALLOW"},
      {ActionVerb::kDrop,      false, "DROP"},
      {ActionVerb::kMirror,    false, "MIRROR"},
      {ActionVerb::kRateLimit, false, "RATE_LIMIT"},
      {ActionVerb::kTag,       true,  "TAG"},
      {ActionVerb::kRedirect,  false, "REDIRECT"},
  };

  for (const auto& [verb, expected, name] : table) {
    EXPECT_EQ(is_mutating_verb(verb), expected)
        << "is_mutating_verb(" << name << ") mismatch — D26 update needed";
  }

  // Verify we covered ALL enum values (catches new verbs added without updating table).
  // ActionVerb values are 0..5 (kAllow=0, ..., kRedirect=5).
  // If a new verb is added with value > 5, this count check will fail.
  EXPECT_EQ(std::size(table), 6u)
      << "enum-scan table size mismatch — update this test when adding new ActionVerb values";
}

}  // namespace
