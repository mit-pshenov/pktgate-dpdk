// tests/unit/test_compiler.cpp
//
// M2 C1 — compiler scaffold + object compiler.
// RED tests: U3.1, U3.2, U3.3, U3.4.
//
// These test the compiler's object expansion and rule expansion
// mechanics. The compiler takes a parsed+validated Config and
// produces compiled structures.
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

}  // namespace
