// tests/unit/test_builder.cpp
//
// M2 builder-scope tests.
// C2: U4.8 — struct sizing static_asserts.
// C9: U4.1, U4.6, U4.17 — arena sizing, counter layout, generation.
//
// No DPDK. No EAL. Pure C++ unit tests.

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>

#include "src/action/action.h"
#include "src/compiler/compiler.h"
#include "src/compiler/object_compiler.h"
#include "src/config/model.h"
#include "src/config/sizing.h"
#include "src/ruleset/builder.h"
#include "src/ruleset/ruleset.h"

namespace {

using namespace pktgate::compiler;
using namespace pktgate::config;
using namespace pktgate::ruleset;

// -------------------------------------------------------------------------
// U4.8 RuleAction 20 B / alignas(4) static_assert in builder
//
// Compile-time assertion that the builder's declaration of RuleAction
// still matches the layout invariant. If someone ever adds a field the
// build breaks. Covers D22.
// -------------------------------------------------------------------------
TEST(BuilderStructSizing, RuleActionLayout_U4_8) {
  static_assert(sizeof(pktgate::action::RuleAction) == 20,
                "RuleAction layout drift — expected 20 B (D22)");
  static_assert(alignof(pktgate::action::RuleAction) == 4,
                "RuleAction alignment drift — expected 4 (D22)");
  SUCCEED() << "RuleAction 20 B / alignas(4) — D22 builder invariant holds";
}

// -------------------------------------------------------------------------
// U4.6 RuleCounter is 64 B / alignas(64) — compile-time check.
// -------------------------------------------------------------------------
TEST(BuilderStructSizing, RuleCounterLayout_U4_6_static) {
  static_assert(sizeof(RuleCounter) == 64,
                "RuleCounter must be exactly 64 B (one cache line)");
  static_assert(alignof(RuleCounter) == 64,
                "RuleCounter must be 64 B aligned");
  SUCCEED() << "RuleCounter 64 B / alignas(64) — §4.3 invariant holds";
}

// Helper: build a minimal valid Config.
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

// Helper: append a rule.
Rule& append_rule(std::vector<Rule>& layer, std::int32_t id,
                  RuleAction action) {
  auto& r = layer.emplace_back();
  r.id = id;
  r.action = std::move(action);
  return r;
}

// =========================================================================
// U4.1 Arena sizing from `sizing` config
//
// Builder reads sizing.rules_per_layer_max and allocates action arrays
// of exactly that size per layer, and by_rule counter rows per lcore of
// 3 * rules_per_layer_max. No hardcoded constants. Allocation sizes
// verified against expected byte counts. Covers D6.
// =========================================================================
TEST(RulesetBuilder, ArenaSizingFromConfig_U4_1) {
  // Use a custom sizing to ensure nothing is hardcoded.
  Config cfg = make_config();
  cfg.sizing.rules_per_layer_max = 1024;

  // Populate one rule per layer so compile succeeds.
  auto& r2 = append_rule(cfg.pipeline.layer_2, 100, ActionAllow{});
  r2.src_mac = Mac{{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};

  append_rule(cfg.pipeline.layer_3, 200, ActionDrop{});
  // L3 rules need at least src_subnet or dst_subnet — but the compiler
  // doesn't enforce this at M2 level (no FIB). A bare rule is fine for
  // action array sizing.

  auto& r4 = append_rule(cfg.pipeline.layer_4, 300, ActionAllow{});
  r4.proto = 6;
  r4.dst_port = 80;

  auto cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value()) << "compile must succeed";

  // Build the ruleset.
  constexpr unsigned kNumLcores = 4;
  auto rs = build_ruleset(cr, cfg.sizing, kNumLcores);

  // Action arena capacity must equal rules_per_layer_max.
  EXPECT_EQ(rs.l2_actions_capacity, 1024u)
      << "l2_actions capacity must come from sizing, not hardcoded";
  EXPECT_EQ(rs.l3_actions_capacity, 1024u)
      << "l3_actions capacity must come from sizing, not hardcoded";
  EXPECT_EQ(rs.l4_actions_capacity, 1024u)
      << "l4_actions capacity must come from sizing, not hardcoded";

  // Action arrays must be allocated (non-null) even with only 1 rule each.
  EXPECT_NE(rs.l2_actions, nullptr);
  EXPECT_NE(rs.l3_actions, nullptr);
  EXPECT_NE(rs.l4_actions, nullptr);

  // Verify actual allocated byte counts.
  const std::size_t expected_action_bytes =
      1024 * sizeof(pktgate::action::RuleAction);
  EXPECT_EQ(rs.l2_actions_capacity * sizeof(pktgate::action::RuleAction),
            expected_action_bytes)
      << "l2_actions byte count must be 1024 * 20 = 20480";
  EXPECT_EQ(rs.l3_actions_capacity * sizeof(pktgate::action::RuleAction),
            expected_action_bytes);
  EXPECT_EQ(rs.l4_actions_capacity * sizeof(pktgate::action::RuleAction),
            expected_action_bytes);

  // Counter rows: 3 * rules_per_layer_max = 3072 per lcore.
  const std::uint32_t expected_total_slots = 3 * 1024;
  EXPECT_EQ(rs.counter_slots_per_lcore, expected_total_slots)
      << "counter_slots_per_lcore must be 3 * rules_per_layer_max";

  // Counter memory allocated for kNumLcores lcores.
  EXPECT_EQ(rs.num_lcores, kNumLcores);
  EXPECT_NE(rs.counters, nullptr);

  // Verify different sizing produces different capacities (no hardcode).
  Config cfg2 = make_config();
  cfg2.sizing.rules_per_layer_max = 512;

  auto& s2 = append_rule(cfg2.pipeline.layer_4, 400, ActionAllow{});
  s2.proto = 17;
  s2.dst_port = 53;

  auto cr2 = compile(cfg2);
  auto rs2 = build_ruleset(cr2, cfg2.sizing, kNumLcores);

  EXPECT_EQ(rs2.l2_actions_capacity, 512u)
      << "Different sizing must produce different capacity";
  EXPECT_EQ(rs2.l4_actions_capacity, 512u);
  EXPECT_EQ(rs2.counter_slots_per_lcore, 3u * 512u);
}

// =========================================================================
// U4.6 Per-lcore counter row layout
//
// PerLcoreCounters laid out [lcore_id][layer_base + counter_slot].
// Each RuleCounter is 64B aligned. No row straddles cache lines.
// Pointer arithmetic checks + static_assert. Covers D3, §4.3.
// =========================================================================
TEST(RulesetBuilder, PerLcoreCounterLayout_U4_6) {
  Config cfg = make_config();
  cfg.sizing.rules_per_layer_max = 128;

  auto& r = append_rule(cfg.pipeline.layer_4, 500, ActionAllow{});
  r.proto = 6;
  r.dst_port = 443;

  auto cr = compile(cfg);
  constexpr unsigned kNumLcores = 4;
  auto rs = build_ruleset(cr, cfg.sizing, kNumLcores);

  const std::uint32_t M = cfg.sizing.rules_per_layer_max;  // 128
  const std::uint32_t total_slots = 3 * M;                 // 384

  // Verify layer_base math: L2=0, L3=M, L4=2M.
  EXPECT_EQ(layer_base(Layer::kL2, M), 0u);
  EXPECT_EQ(layer_base(Layer::kL3, M), M);
  EXPECT_EQ(layer_base(Layer::kL4, M), 2 * M);

  // Each lcore's counter row must be independently addressable.
  for (unsigned lcore = 0; lcore < kNumLcores; ++lcore) {
    RuleCounter* row = rs.counter_row(lcore);
    ASSERT_NE(row, nullptr) << "lcore " << lcore << " counter row is null";

    // The row pointer must be 64B-aligned (cache-line aligned).
    auto addr = reinterpret_cast<std::uintptr_t>(row);
    EXPECT_EQ(addr % 64, 0u)
        << "lcore " << lcore << " counter row not 64B-aligned";

    // Each individual RuleCounter within the row must be 64B-aligned.
    for (std::uint32_t slot = 0; slot < total_slots; ++slot) {
      auto slot_addr = reinterpret_cast<std::uintptr_t>(&row[slot]);
      EXPECT_EQ(slot_addr % 64, 0u)
          << "lcore " << lcore << " slot " << slot << " not 64B-aligned";
    }

    // No row straddles into a different lcore's territory.
    if (lcore + 1 < kNumLcores) {
      RuleCounter* next_row = rs.counter_row(lcore + 1);
      auto gap = reinterpret_cast<std::uintptr_t>(next_row) -
                 reinterpret_cast<std::uintptr_t>(row);
      EXPECT_EQ(gap, total_slots * sizeof(RuleCounter))
          << "Gap between lcore " << lcore << " and " << (lcore + 1)
          << " must be exactly total_slots * 64";
    }
  }

  // Specific index check: layer_base(L4) + counter_slot of our rule.
  // The rule got counter_slot=0 (first L4 rule).
  ASSERT_GE(cr.l4_actions.size(), 1u);
  std::uint16_t slot = cr.l4_actions[0].counter_slot;
  std::uint32_t idx = layer_base(Layer::kL4, M) + slot;
  EXPECT_LT(idx, total_slots) << "Counter index must be in bounds";

  // The counter at that index must be zero-initialized.
  RuleCounter* row0 = rs.counter_row(0);
  EXPECT_EQ(row0[idx].matched_packets, 0u);
  EXPECT_EQ(row0[idx].matched_bytes, 0u);
  EXPECT_EQ(row0[idx].drops, 0u);
  EXPECT_EQ(row0[idx].rl_drops, 0u);
}

// =========================================================================
// U4.17 Generation counter increments monotonically
//
// Each successful build increments ruleset.generation exactly once.
// Covers D12 polish, §4.1 metadata.
// =========================================================================
TEST(RulesetBuilder, GenerationMonotonic_U4_17) {
  Config cfg = make_config();

  auto& r = append_rule(cfg.pipeline.layer_4, 600, ActionAllow{});
  r.proto = 6;
  r.dst_port = 80;

  auto cr = compile(cfg);

  constexpr unsigned kNumLcores = 2;

  // Build three rulesets. Generation is a process-wide counter —
  // we can't assume absolute values because other tests may have
  // called build_ruleset first. But the contract is:
  //   (a) generation > 0
  //   (b) each successive build increments by exactly 1
  auto rs1 = build_ruleset(cr, cfg.sizing, kNumLcores);
  EXPECT_GT(rs1.generation, 0u) << "generation must be positive";

  auto rs2 = build_ruleset(cr, cfg.sizing, kNumLcores);
  EXPECT_EQ(rs2.generation, rs1.generation + 1)
      << "Second build must increment generation by exactly 1";

  auto rs3 = build_ruleset(cr, cfg.sizing, kNumLcores);
  EXPECT_EQ(rs3.generation, rs2.generation + 1)
      << "Third build must increment generation by exactly 1";

  // Monotonicity: each > previous.
  EXPECT_GT(rs2.generation, rs1.generation);
  EXPECT_GT(rs3.generation, rs2.generation);
}

}  // namespace
