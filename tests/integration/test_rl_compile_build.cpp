// tests/integration/test_rl_compile_build.cpp
//
// M9 C3 — compile → build roundtrip for rate-limit rules.
//
// D41 watch (review-notes §M8 RCU reader gap; M7 C2b
// dscp/pcp/redirect_port silent-lowering): the RL slot identity must
// travel through three independent pipelines without silent loss:
//
//   1. config::ActionRateLimit.{bytes_per_sec, burst_bytes} + rule.id
//      → CompiledAction.{rl_slot, rl_rate_bps, rl_burst_bytes}
//      (compiler TU, via the `RlSlotAllocator` bridging to the arena)
//   2. CompiledAction.rl_slot → action::RuleAction.rl_index (builder)
//   3. {rule_id, rate, burst} snapshot → Ruleset::rl_actions[slot]
//      + n_rl_actions bump (builder, same pass)
//
// A 3-way roundtrip assertion is the whole point of the test: the
// C0/C1/C2 unit tests each covered one layer, but each of those layers
// can lie about the others. Only config → compile → build → runtime-
// struct inspection catches the M7 C2b / M8 C5 class of silent loss.
//
// The U4.10 "survives reload" contract (D24) is also exercised: compile
// and build with the same config twice, arm the bucket state between
// the two builds, and assert slot + row state survive. Functional F3.14
// (full packet-plane reload roundtrip) lands in C5.
//
// No EAL. build_ruleset (M2 zero-arg) is DPDK-free; the arena is a
// static singleton with its own storage. This test links
// pktgate_core + pktgate_rl_ctl and does NOT require rte_eal_init —
// which keeps the roundtrip cheap enough to run under dev-tsan.

#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <vector>

#include "src/action/action.h"
#include "src/compiler/compiler.h"
#include "src/compiler/object_compiler.h"
#include "src/config/model.h"
#include "src/config/sizing.h"
#include "src/rl_arena/arena.h"
#include "src/rl_arena/rl_arena.h"
#include "src/ruleset/builder.h"
#include "src/ruleset/ruleset.h"

namespace pktgate::test {

namespace {

// Minimal Config helper — same pattern as tests/unit/test_builder.cpp.
config::Config make_rl_config(std::int32_t rule_id_a,
                              std::uint64_t rate_a,
                              std::uint64_t burst_a,
                              std::int32_t rule_id_b,
                              std::uint64_t rate_b,
                              std::uint64_t burst_b) {
  config::Config cfg;
  cfg.version = config::kSchemaVersion;
  cfg.default_behavior = config::DefaultBehavior::kDrop;
  cfg.fragment_policy = config::FragmentPolicy::kL3Only;
  cfg.sizing = config::kSizingDevDefaults;
  cfg.interface_roles = {
      config::InterfaceRole{"upstream_port",
                            config::PciSelector{"0000:00:00.0"}},
      config::InterfaceRole{"downstream_port",
                            config::PciSelector{"0000:00:00.1"}},
  };

  // Two L4 rules with RateLimit. Distinct rule_ids so the arena hands
  // out two distinct slots.
  auto& r_a = cfg.pipeline.layer_4.emplace_back();
  r_a.id = rule_id_a;
  r_a.proto = 6;        // TCP
  r_a.dst_port = 80;
  r_a.action = config::ActionRateLimit{rate_a, burst_a};

  auto& r_b = cfg.pipeline.layer_4.emplace_back();
  r_b.id = rule_id_b;
  r_b.proto = 17;       // UDP
  r_b.dst_port = 53;
  r_b.action = config::ActionRateLimit{rate_b, burst_b};

  return cfg;
}

// RAII helper: clean the global arena's slots for a set of rule_ids at
// test entry + exit so the module-local singleton doesn't leak state
// across TEST_F boundaries. The arena is process-wide by design (D10,
// survives reload) so without explicit cleanup the second test in this
// TU would see slots from the first.
struct ArenaScrubber {
  std::vector<std::uint64_t> ids;
  explicit ArenaScrubber(std::vector<std::uint64_t> ids_)
      : ids(std::move(ids_)) {
    auto& a = rl_arena::rl_arena_global();
    for (auto id : ids) a.free_slot(id);
  }
  ~ArenaScrubber() {
    auto& a = rl_arena::rl_arena_global();
    for (auto id : ids) a.free_slot(id);
  }
};

}  // namespace

// =========================================================================
// C3-Roundtrip.TwoRulesThreeStagesLockstep
//
// Build a config with two kRateLimit L4 rules, run compile → build,
// and assert all three stages of the RL pipeline carry the same slot
// + rule_id + rate + burst data:
//
//   stage 1: CompiledAction.rl_slot is a valid (non-sentinel) slot
//            returned by the arena for each rule_id.
//   stage 2: RuleAction.rl_index equals CompiledAction.rl_slot.
//   stage 3: Ruleset::rl_actions[slot] carries the config's rate + burst.
//   stage 3b: n_rl_actions is at least max(slot)+1.
//
// If ANY of the three stages silently drops a field, exactly one of
// these assertions fails — and the error message points at the exact
// boundary (same D41 "silent pipeline gap" pattern as M7 C2b and M8 C5).
// =========================================================================
TEST(RlCompileBuildRoundtrip, TwoRulesThreeStagesLockstep) {
  constexpr std::int32_t kIdA = 4201;
  constexpr std::int32_t kIdB = 4202;
  constexpr std::uint64_t kRateA = 1'000'000ull;
  constexpr std::uint64_t kBurstA = 100'000ull;
  constexpr std::uint64_t kRateB = 2'000'000ull;
  constexpr std::uint64_t kBurstB = 200'000ull;

  ArenaScrubber scrub{{static_cast<std::uint64_t>(kIdA),
                       static_cast<std::uint64_t>(kIdB)}};

  config::Config cfg =
      make_rl_config(kIdA, kRateA, kBurstA, kIdB, kRateB, kBurstB);

  // Wire the real arena allocator into compile().
  auto& arena = rl_arena::rl_arena_global();
  compiler::RlSlotAllocator rl_alloc =
      [&arena](std::uint64_t rid) { return arena.alloc_slot(rid); };

  auto cr = compiler::compile(cfg, /*opts=*/{}, rl_alloc);
  ASSERT_FALSE(cr.error.has_value()) << "compile must succeed";
  ASSERT_EQ(cr.l4_actions.size(), 2u);

  // Stage 1 — CompiledAction.rl_slot populated for both rules.
  const auto& ca_a = cr.l4_actions[0];
  const auto& ca_b = cr.l4_actions[1];
  EXPECT_EQ(ca_a.verb, compiler::ActionVerb::kRateLimit);
  EXPECT_EQ(ca_b.verb, compiler::ActionVerb::kRateLimit);
  EXPECT_NE(ca_a.rl_slot, rl_arena::kInvalidSlot)
      << "CompiledAction.rl_slot must be a real slot (stage 1)";
  EXPECT_NE(ca_b.rl_slot, rl_arena::kInvalidSlot)
      << "CompiledAction.rl_slot must be a real slot (stage 1)";
  EXPECT_NE(ca_a.rl_slot, ca_b.rl_slot)
      << "distinct rule_ids must get distinct slots";
  EXPECT_EQ(ca_a.rl_rate_bps, kRateA);
  EXPECT_EQ(ca_a.rl_burst_bytes, kBurstA);
  EXPECT_EQ(ca_b.rl_rate_bps, kRateB);
  EXPECT_EQ(ca_b.rl_burst_bytes, kBurstB);

  // Cross-check with arena: the arena also sees these rule_ids at the
  // same slots.
  EXPECT_EQ(arena.lookup_slot(static_cast<std::uint64_t>(kIdA)),
            std::optional<std::uint16_t>{ca_a.rl_slot});
  EXPECT_EQ(arena.lookup_slot(static_cast<std::uint64_t>(kIdB)),
            std::optional<std::uint16_t>{ca_b.rl_slot});

  // Build the Ruleset (zero-arg M2 path, DPDK-free).
  constexpr unsigned kNumLcores = 4;
  auto rs = ruleset::build_ruleset(cr, cfg.sizing, kNumLcores);

  ASSERT_EQ(rs.n_l4_rules, 2u);
  ASSERT_NE(rs.l4_actions, nullptr);
  ASSERT_NE(rs.rl_actions, nullptr);

  // Stage 2 — RuleAction.rl_index matches CompiledAction.rl_slot.
  EXPECT_EQ(rs.l4_actions[0].rl_index, ca_a.rl_slot)
      << "RuleAction.rl_index must equal CompiledAction.rl_slot (stage 2)";
  EXPECT_EQ(rs.l4_actions[1].rl_index, ca_b.rl_slot)
      << "RuleAction.rl_index must equal CompiledAction.rl_slot (stage 2)";
  EXPECT_EQ(rs.l4_actions[0].verb,
            static_cast<std::uint8_t>(compiler::ActionVerb::kRateLimit));
  EXPECT_EQ(rs.l4_actions[1].verb,
            static_cast<std::uint8_t>(compiler::ActionVerb::kRateLimit));

  // Stage 3 — Ruleset::rl_actions[slot] carries the rate + burst.
  const auto& rl_a = rs.rl_actions[ca_a.rl_slot];
  EXPECT_EQ(rl_a.rule_id, static_cast<std::uint64_t>(kIdA))
      << "Ruleset::rl_actions[slot].rule_id (stage 3)";
  EXPECT_EQ(rl_a.rate_bps, kRateA)
      << "Ruleset::rl_actions[slot].rate_bps (stage 3)";
  EXPECT_EQ(rl_a.burst_bytes, kBurstA)
      << "Ruleset::rl_actions[slot].burst_bytes (stage 3)";

  const auto& rl_b = rs.rl_actions[ca_b.rl_slot];
  EXPECT_EQ(rl_b.rule_id, static_cast<std::uint64_t>(kIdB));
  EXPECT_EQ(rl_b.rate_bps, kRateB);
  EXPECT_EQ(rl_b.burst_bytes, kBurstB);

  // Stage 3b — n_rl_actions covers the highest live slot.
  const std::uint16_t max_slot =
      ca_a.rl_slot > ca_b.rl_slot ? ca_a.rl_slot : ca_b.rl_slot;
  EXPECT_GE(rs.n_rl_actions, static_cast<std::uint32_t>(max_slot) + 1u)
      << "n_rl_actions must include the highest live RL slot (stage 3b)";
}

// =========================================================================
// C3-Roundtrip.SurvivesReloadU4_10
//
// U4.10 extended to the compile → build path (was arena-only in C1).
// Contract (D24): same rule_id across two compile→build cycles returns
// the SAME slot, and the TokenBucket state for that slot is preserved
// across the second build.
//
// Sequence:
//   1. compile + build once → record slot s for rule_id 42.
//   2. Arm per-lcore bucket state on arena row rows_[s].
//   3. compile + build again with the same Config (emulates reload).
//   4. Assert same slot + arena row state still carries the arm.
//
// The arm writes `tokens = 0xCAFE` on an inactive lcore slot; we read
// back through the arena (which survives ~Ruleset by design, D10).
// =========================================================================
TEST(RlCompileBuildRoundtrip, SurvivesReloadU4_10) {
  constexpr std::int32_t kId = 42;
  constexpr std::uint64_t kRate = 1'500'000ull;
  constexpr std::uint64_t kBurst = 150'000ull;

  ArenaScrubber scrub{{static_cast<std::uint64_t>(kId), 9999ull}};

  // Second id just to force rule_id=42 to not necessarily land at slot 0.
  config::Config cfg =
      make_rl_config(9999, 123456ull, 12345ull, kId, kRate, kBurst);

  auto& arena = rl_arena::rl_arena_global();
  compiler::RlSlotAllocator rl_alloc =
      [&arena](std::uint64_t rid) { return arena.alloc_slot(rid); };

  // ---- First compile + build ----
  auto cr1 = compiler::compile(cfg, /*opts=*/{}, rl_alloc);
  ASSERT_FALSE(cr1.error.has_value());
  ASSERT_EQ(cr1.l4_actions.size(), 2u);
  const std::uint16_t s1 = cr1.l4_actions[1].rl_slot;
  ASSERT_NE(s1, rl_arena::kInvalidSlot);

  {
    auto rs1 =
        ruleset::build_ruleset(cr1, cfg.sizing, /*num_lcores=*/4);
    EXPECT_EQ(rs1.l4_actions[1].rl_index, s1);
    EXPECT_EQ(rs1.rl_actions[s1].rule_id,
              static_cast<std::uint64_t>(kId));
    EXPECT_EQ(rs1.rl_actions[s1].rate_bps, kRate);

    // Arm bucket state on lcore slot 3 — picked so a potential drop
    // race on the hot path can't overwrite it between builds.
    auto& row = arena.get_row(s1);
    row.per_lcore[3].tokens = 0xCAFEull;
    row.per_lcore[3].last_refill_tsc = 0x1234ull;
    row.per_lcore[3].dropped = 7ull;
  }  // rs1 destroyed here

  // ---- Second compile + build: same config (emulates reload) ----
  auto cr2 = compiler::compile(cfg, /*opts=*/{}, rl_alloc);
  ASSERT_FALSE(cr2.error.has_value());
  ASSERT_EQ(cr2.l4_actions.size(), 2u);
  const std::uint16_t s2 = cr2.l4_actions[1].rl_slot;
  EXPECT_EQ(s2, s1) << "survives-reload: same rule_id must get same slot (U4.10)";

  auto rs2 = ruleset::build_ruleset(cr2, cfg.sizing, /*num_lcores=*/4);
  EXPECT_EQ(rs2.l4_actions[1].rl_index, s2);
  EXPECT_EQ(rs2.rl_actions[s2].rule_id, static_cast<std::uint64_t>(kId));
  EXPECT_EQ(rs2.rl_actions[s2].rate_bps, kRate);
  EXPECT_EQ(rs2.rl_actions[s2].burst_bytes, kBurst);

  // Arena row state survives the build — D24 "free slot, not free row".
  const auto& row2 = arena.get_row(s2);
  EXPECT_EQ(row2.per_lcore[3].tokens, 0xCAFEull)
      << "bucket tokens lost across reload (D24 violation)";
  EXPECT_EQ(row2.per_lcore[3].last_refill_tsc, 0x1234ull);
  EXPECT_EQ(row2.per_lcore[3].dropped, 7ull);
}

// =========================================================================
// C3-Roundtrip.NonRlVerbsStayAtSentinel
//
// Non-kRateLimit verbs must carry rl_index == kInvalidSlot through the
// compile→build pipeline. This guards against a reverse D41 — silently
// allocating slots for verbs that never needed one.
// =========================================================================
TEST(RlCompileBuildRoundtrip, NonRlVerbsStayAtSentinel) {
  config::Config cfg;
  cfg.version = config::kSchemaVersion;
  cfg.default_behavior = config::DefaultBehavior::kDrop;
  cfg.fragment_policy = config::FragmentPolicy::kL3Only;
  cfg.sizing = config::kSizingDevDefaults;
  cfg.interface_roles = {
      config::InterfaceRole{"p0", config::PciSelector{"0000:00:00.0"}},
      config::InterfaceRole{"p1", config::PciSelector{"0000:00:00.1"}},
  };

  auto& r_allow = cfg.pipeline.layer_4.emplace_back();
  r_allow.id = 100;
  r_allow.proto = 6;
  r_allow.dst_port = 22;
  r_allow.action = config::ActionAllow{};

  auto& r_drop = cfg.pipeline.layer_4.emplace_back();
  r_drop.id = 101;
  r_drop.proto = 17;
  r_drop.dst_port = 1900;
  r_drop.action = config::ActionDrop{};

  auto& arena = rl_arena::rl_arena_global();
  compiler::RlSlotAllocator rl_alloc =
      [&arena](std::uint64_t rid) { return arena.alloc_slot(rid); };

  auto cr = compiler::compile(cfg, /*opts=*/{}, rl_alloc);
  ASSERT_FALSE(cr.error.has_value());
  ASSERT_EQ(cr.l4_actions.size(), 2u);

  EXPECT_EQ(cr.l4_actions[0].rl_slot, rl_arena::kInvalidSlot);
  EXPECT_EQ(cr.l4_actions[1].rl_slot, rl_arena::kInvalidSlot);

  auto rs = ruleset::build_ruleset(cr, cfg.sizing, /*num_lcores=*/2);
  EXPECT_EQ(rs.l4_actions[0].rl_index, rl_arena::kInvalidSlot);
  EXPECT_EQ(rs.l4_actions[1].rl_index, rl_arena::kInvalidSlot);
  // No live RL slots → n_rl_actions stays 0.
  EXPECT_EQ(rs.n_rl_actions, 0u);

  // Arena never saw allocations for these ids.
  EXPECT_FALSE(arena.lookup_slot(100).has_value());
  EXPECT_FALSE(arena.lookup_slot(101).has_value());
}

}  // namespace pktgate::test
