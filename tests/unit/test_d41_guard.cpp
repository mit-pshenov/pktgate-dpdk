// tests/unit/test_d41_guard.cpp
//
// D41 C1 — runtime half of the observable-field guard.
//
// The static_assert pair in src/ruleset/builder.cpp catches the
// "projection desync" subclass of D41 drift (field count / type shape
// between action::observable_fields and compiler::observable_fields).
// The failure mode the static guard CANNOT see is "both projections
// were updated in lockstep but the builder's copy_actions lambda
// forgot to lower the new field" — that's pure wiring drift. This
// file is the runtime half: build a real config touching every
// observable field, run parse -> validate -> compile -> build (no EAL),
// then compare the two projections element-wise via EXPECT_EQ.
//
// D41 C1 invariant: static_assert + runtime roundtrip ship in the same
// atomic commit. Supervisor handoff §C1 explicitly rejects
// "static now, runtime later" splits.
//
// Scope (explicitly kept narrow):
//
//   * No EAL. No populate_ruleset_eal. The zero-arg build_ruleset
//     overload in src/ruleset/builder.cpp (line 26) works on plain
//     operator new and is DPDK-free. This keeps the guard fast enough
//     to run under dev-tsan without an EAL fixture.
//
//   * Per-rule + per-layer coverage: every verb exercised at least
//     once, and at least one rule carries non-sentinel values for
//     every observable field (rule_id != 0, counter_slot != 0 for
//     the second rule in a layer, verb varies, execution_tier stays
//     kSw per MVP, redirect_port resolves to a non-zero non-sentinel
//     role_idx, dscp and pcp non-zero for TAG, rl_index non-sentinel
//     for RATELIMIT).
//
//   * Future-proofing tested: a mutation smoke (CompiledAction copy,
//     flip one field, verify projection no longer matches) pins the
//     "guard notices changes" semantics.
//
// Out of scope (tracked separately):
//
//   * Main.cpp call-graph orphans (M4 C0b + M9 C5 runtime-surface
//     gaps) -> D41 C2 (EAL-fixture smoke).
//   * config::RuleAction variant-arm growth in resolve_action
//     (Caveat 2 from discovery report) -> D41 C1b.

#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <tuple>
#include <vector>

#include "src/action/action.h"
#include "src/compiler/compiler.h"
#include "src/compiler/object_compiler.h"
#include "src/config/addr.h"
#include "src/config/model.h"
#include "src/config/sizing.h"
#include "src/rl_arena/arena.h"
#include "src/rl_arena/rl_arena.h"
#include "src/ruleset/builder.h"
#include "src/ruleset/ruleset.h"

namespace {

using namespace pktgate::compiler;
using namespace pktgate::config;
using namespace pktgate::ruleset;

// Helper: minimal Config with two interface roles so REDIRECT can
// resolve a non-zero role idx (downstream_port -> 1).
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

Rule& append_rule(std::vector<Rule>& layer, std::int32_t id,
                  RuleAction action) {
  auto& r = layer.emplace_back();
  r.id = id;
  r.action = std::move(action);
  return r;
}

// RAII arena cleanup for RL rules — mirrors tests/integration/
// test_rl_compile_build.cpp: the global arena is process-wide so slot
// allocations leak across tests unless scrubbed. Frees the slot at
// both entry and exit so retries stay idempotent.
struct ArenaScrubber {
  std::vector<std::uint64_t> ids;
  explicit ArenaScrubber(std::vector<std::uint64_t> ids_)
      : ids(std::move(ids_)) {
    auto& a = pktgate::rl_arena::rl_arena_global();
    for (auto id : ids) a.free_slot(id);
  }
  ~ArenaScrubber() {
    auto& a = pktgate::rl_arena::rl_arena_global();
    for (auto id : ids) a.free_slot(id);
  }
};

// =========================================================================
// ProjectionRoundtrip.AllVerbsPerLayer
//
// Every observable-field projection round-trips through
// compile -> build_ruleset without loss or mutation, on every layer
// that the compiler populates. The canonical failure mode this test
// prevents: a worker adds a new field to both observable_fields()
// tuples (static_assert still green), but forgets the lowering line
// in copy_actions — one EXPECT_EQ below starts failing with a clear
// "lhs vs rhs projection mismatch" at the exact layer/index.
//
// Coverage per layer:
//   L2: ActionTag (dscp/pcp non-zero) + ActionTargetPort (REDIRECT).
//   L3: ActionAllow + ActionDrop (covers verb + counter_slot only).
//   L4: ActionRateLimit (rl_slot non-sentinel, rate/burst non-zero)
//       + ActionDrop fallback.
// =========================================================================
TEST(D41GuardRuntimeRoundtrip, AllVerbsPerLayer) {
  constexpr std::int32_t kL4RlId = 7701;

  ArenaScrubber scrub{{static_cast<std::uint64_t>(kL4RlId)}};

  Config cfg = make_config();

  // ---- L2: TAG (dscp=46, pcp=5) + REDIRECT(downstream_port). ----
  ActionTag tag;
  tag.dscp = 46;
  tag.pcp = 5;
  auto& l2_tag = append_rule(cfg.pipeline.layer_2, 1101, tag);
  l2_tag.src_mac = Mac{{0x02, 0x00, 0x00, 0x00, 0x00, 0x11}};

  ActionTargetPort redir;
  redir.role_name = "downstream_port";
  auto& l2_redir = append_rule(cfg.pipeline.layer_2, 1102, redir);
  l2_redir.src_mac = Mac{{0x02, 0x00, 0x00, 0x00, 0x00, 0x12}};

  // ---- L3: ALLOW + DROP (compiler still populates l3_actions). ----
  append_rule(cfg.pipeline.layer_3, 2201, ActionAllow{});
  append_rule(cfg.pipeline.layer_3, 2202, ActionDrop{});

  // ---- L4: RATELIMIT + DROP. ----
  auto& l4_rl = append_rule(cfg.pipeline.layer_4, kL4RlId,
                            ActionRateLimit{10'000'000ull, 125'000ull});
  l4_rl.proto = 6;
  l4_rl.dst_port = 443;

  auto& l4_drop = append_rule(cfg.pipeline.layer_4, 7702, ActionDrop{});
  l4_drop.proto = 17;
  l4_drop.dst_port = 53;

  // Wire the real arena allocator so rl_slot is a valid slot, not
  // kInvalidSlot. Mirrors pktgate_dpdk main.cpp bootstrap.
  auto& arena = pktgate::rl_arena::rl_arena_global();
  RlSlotAllocator rl_alloc =
      [&arena](std::uint64_t rid) { return arena.alloc_slot(rid); };

  auto cr = compile(cfg, /*opts=*/{}, rl_alloc);
  ASSERT_FALSE(cr.error.has_value()) << "compile must succeed";

  constexpr unsigned kNumLcores = 2;
  auto rs = build_ruleset(cr, cfg.sizing, kNumLcores);

  // ---- Per-layer projection compare. ----
  //
  // The tuples are `std::tuple<...>` with identical element types
  // (enforced by the static_assert in builder.cpp). operator== on
  // std::tuple compares element-by-element; gtest's EXPECT_EQ prints
  // "which field diverged" only at tuple granularity, so we also
  // break out per-field EXPECT_EQs below for readable diagnostics.
  auto compare_layer =
      [](const char* layer_name,
         const std::vector<CompiledAction>& src,
         const pktgate::action::RuleAction* dst,
         std::uint32_t n_rules) {
        ASSERT_EQ(src.size(), n_rules)
            << layer_name << ": CompiledAction count drift";
        for (std::uint32_t i = 0; i < n_rules; ++i) {
          const auto ca_proj =
              pktgate::compiler::observable_fields(src[i]);
          const auto ra_proj =
              pktgate::action::observable_fields(dst[i]);
          EXPECT_EQ(ca_proj, ra_proj)
              << layer_name << " rule index " << i
              << ": projection mismatch (D41 drift)";
          EXPECT_EQ(std::get<0>(ca_proj), std::get<0>(ra_proj))
              << layer_name << "[" << i << "] rule_id";
          EXPECT_EQ(std::get<1>(ca_proj), std::get<1>(ra_proj))
              << layer_name << "[" << i << "] counter_slot";
          EXPECT_EQ(std::get<2>(ca_proj), std::get<2>(ra_proj))
              << layer_name << "[" << i << "] verb";
          EXPECT_EQ(std::get<3>(ca_proj), std::get<3>(ra_proj))
              << layer_name << "[" << i << "] execution_tier";
          EXPECT_EQ(std::get<4>(ca_proj), std::get<4>(ra_proj))
              << layer_name << "[" << i << "] redirect_port";
          EXPECT_EQ(std::get<5>(ca_proj), std::get<5>(ra_proj))
              << layer_name << "[" << i << "] dscp";
          EXPECT_EQ(std::get<6>(ca_proj), std::get<6>(ra_proj))
              << layer_name << "[" << i << "] pcp";
          EXPECT_EQ(std::get<7>(ca_proj), std::get<7>(ra_proj))
              << layer_name << "[" << i << "] rl_index/rl_slot";
        }
      };

  compare_layer("L2", cr.l2_actions, rs.l2_actions, rs.n_l2_rules);
  compare_layer("L3", cr.l3_actions, rs.l3_actions, rs.n_l3_rules);
  compare_layer("L4", cr.l4_actions, rs.l4_actions, rs.n_l4_rules);

  // ---- Positive-value checks: every observable field is non-sentinel
  // on at least one rule so a "stay at default" bug (like the pre-M7
  // C2b hardcoded redirect_port=0xFFFF) is catchable. ----
  ASSERT_GE(rs.n_l2_rules, 2u);
  ASSERT_GE(rs.n_l3_rules, 2u);
  ASSERT_GE(rs.n_l4_rules, 2u);

  // TAG carries non-zero dscp/pcp.
  EXPECT_EQ(rs.l2_actions[0].dscp, 46u) << "TAG dscp lowered";
  EXPECT_EQ(rs.l2_actions[0].pcp, 5u) << "TAG pcp lowered";

  // REDIRECT resolved role_idx -> 1 (downstream_port).
  EXPECT_EQ(rs.l2_actions[1].redirect_port, 1u) << "REDIRECT role idx";

  // counter_slot is dense per layer: second rule has slot 1.
  EXPECT_EQ(rs.l2_actions[1].counter_slot, 1u);
  EXPECT_EQ(rs.l3_actions[1].counter_slot, 1u);
  EXPECT_EQ(rs.l4_actions[1].counter_slot, 1u);

  // RATELIMIT got a valid slot (not kInvalidSlot).
  EXPECT_NE(rs.l4_actions[0].rl_index, 0xFFFFu)
      << "RL slot allocator must hand out a real slot";

  // execution_tier stays kSw (MVP: hw_offload_enabled=false).
  for (std::uint32_t i = 0; i < rs.n_l4_rules; ++i) {
    EXPECT_EQ(rs.l4_actions[i].execution_tier,
              static_cast<std::uint8_t>(ExecutionTier::kSw));
  }
}

// =========================================================================
// ProjectionRoundtrip.MutationDetected
//
// Meta-test: proves that observable_fields() actually observes field
// values, not structural identity. Take a compiled action, build a
// ruleset, then mutate a single RuleAction field in the arena and
// confirm the projection pair no longer compares equal. Without this
// the whole guard could be lying (returning e.g. tuple<int,int,...>{}
// — trivially equal to anything).
// =========================================================================
TEST(D41GuardRuntimeRoundtrip, MutationDetected) {
  Config cfg = make_config();
  auto& r = append_rule(cfg.pipeline.layer_4, 8801, ActionAllow{});
  r.proto = 6;
  r.dst_port = 22;

  auto cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value());
  ASSERT_EQ(cr.l4_actions.size(), 1u);

  constexpr unsigned kNumLcores = 1;
  auto rs = build_ruleset(cr, cfg.sizing, kNumLcores);
  ASSERT_GE(rs.n_l4_rules, 1u);

  const auto ca_proj =
      pktgate::compiler::observable_fields(cr.l4_actions[0]);
  auto ra_proj_before =
      pktgate::action::observable_fields(rs.l4_actions[0]);
  EXPECT_EQ(ca_proj, ra_proj_before)
      << "baseline projection must match after build";

  // Mutate counter_slot in the runtime arena. This is a deliberate
  // out-of-band write that a real bug (forgotten lowering) would
  // naturally leave the arena slot at zero; we simulate the reverse
  // direction to prove the comparison actually reads the field.
  rs.l4_actions[0].counter_slot =
      static_cast<std::uint16_t>(rs.l4_actions[0].counter_slot + 1);
  auto ra_proj_after =
      pktgate::action::observable_fields(rs.l4_actions[0]);
  EXPECT_NE(ca_proj, ra_proj_after)
      << "projection must diverge after out-of-band mutation "
         "(if this passes, observable_fields() is not actually "
         "observing the field it claims to)";
}

}  // namespace
