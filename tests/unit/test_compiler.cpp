// tests/unit/test_compiler.cpp
//
// M2 compiler tests.
// C1: U3.1, U3.2, U3.3, U3.4 — object expansion + rule expansion.
// C2: U3.5, U3.6 — struct sizing static_asserts.
// C3: U3.7, U3.8, U3.25 — L2 compound construction.
//
// These test the compiler's object expansion, rule expansion, and
// L2 compound construction mechanics. The compiler takes a
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

}  // namespace
