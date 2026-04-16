// tests/unit/test_builder.cpp
//
// M2 builder-scope tests.
// C2: U4.8 — struct sizing static_asserts.
// C9: U4.1, U4.6, U4.17 — arena sizing, counter layout, generation.
// C10: U4.7, U4.15, U4.16 — NUMA socket propagation, locality, D28.
//
// No DPDK. No EAL. Pure C++ unit tests.

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

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
  // L3 rules need at least dst_subnet — but the compiler
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

// =========================================================================
// Allocator spy for D23 NUMA tests (C10).
//
// Records every allocation with {size, alignment, socket_id, ptr}.
// Uses std::aligned_alloc under the hood — no DPDK dependency.
// =========================================================================

struct AllocRecord {
  std::size_t size;
  std::size_t alignment;
  int socket_id;
  void* ptr;
};

struct AllocSpy {
  std::vector<AllocRecord> records;
  std::vector<void*> allocated;  // for cleanup

  static void* alloc_fn(std::size_t size, std::size_t alignment,
                         int socket_id, void* ctx) {
    auto* spy = static_cast<AllocSpy*>(ctx);
    // std::aligned_alloc requires size to be a multiple of alignment.
    std::size_t alloc_size = size;
    if (alloc_size % alignment != 0) {
      alloc_size += alignment - (alloc_size % alignment);
    }
    void* ptr = std::aligned_alloc(alignment, alloc_size);
    if (ptr) {
      std::memset(ptr, 0, alloc_size);
      spy->records.push_back({size, alignment, socket_id, ptr});
      spy->allocated.push_back(ptr);
    }
    return ptr;
  }

  static void free_fn(void* ptr, void* /*ctx*/) {
    // The spy tracks allocations; free individually.
    std::free(ptr);
  }

  RulesetAllocator make_allocator() {
    return RulesetAllocator{&AllocSpy::alloc_fn, &AllocSpy::free_fn, this};
  }
};

// =========================================================================
// U4.7 NUMA socket_id propagation (D23)
//
// Builder invoked with socket_id=1 allocates ALL Ruleset arrays on
// socket 1. Verified via allocator spy that records each call's
// socket_id. Covers D23.
// =========================================================================
TEST(RulesetBuilder, NumaSocketPropagation_U4_7) {
  Config cfg = make_config();
  cfg.sizing.rules_per_layer_max = 64;

  auto& r = append_rule(cfg.pipeline.layer_4, 700, ActionAllow{});
  r.proto = 6;
  r.dst_port = 80;

  auto cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value()) << "compile must succeed";

  constexpr unsigned kNumLcores = 2;
  constexpr int kTargetSocket = 1;

  AllocSpy spy;
  auto alloc = spy.make_allocator();
  auto rs = build_ruleset(cr, cfg.sizing, kNumLcores, alloc, kTargetSocket);

  // Must have recorded at least 4 allocations (l2, l3, l4 actions + counters).
  ASSERT_GE(spy.records.size(), 4u)
      << "Expected at least 4 allocations (3 action arenas + counters)";

  // Every allocation must carry the declared socket_id.
  for (std::size_t i = 0; i < spy.records.size(); ++i) {
    EXPECT_EQ(spy.records[i].socket_id, kTargetSocket)
        << "Allocation " << i << " (size=" << spy.records[i].size
        << ") used wrong socket_id: " << spy.records[i].socket_id
        << " (expected " << kTargetSocket << ")";
  }
}

// =========================================================================
// U4.15 Ruleset NUMA locality — every major pointer on expected socket
//
// After build, every major arena pointer in the Ruleset is on the
// declared socket. Verified via allocator spy: each pointer in the
// Ruleset matches one of the spy's recorded allocations, all of which
// carry the declared socket_id. Covers D23.
// =========================================================================
TEST(RulesetBuilder, NumaLocality_U4_15) {
  Config cfg = make_config();
  cfg.sizing.rules_per_layer_max = 128;

  auto& r2 = append_rule(cfg.pipeline.layer_2, 800, ActionAllow{});
  r2.src_mac = Mac{{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};

  append_rule(cfg.pipeline.layer_3, 801, ActionDrop{});

  auto& r4 = append_rule(cfg.pipeline.layer_4, 802, ActionAllow{});
  r4.proto = 17;
  r4.dst_port = 53;

  auto cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value()) << "compile must succeed";

  constexpr unsigned kNumLcores = 4;
  constexpr int kTargetSocket = 1;

  AllocSpy spy;
  auto alloc = spy.make_allocator();
  auto rs = build_ruleset(cr, cfg.sizing, kNumLcores, alloc, kTargetSocket);

  // Collect all recorded pointers into a set for lookup.
  auto ptr_on_socket = [&](void* p) -> bool {
    for (const auto& rec : spy.records) {
      if (rec.ptr == p) {
        return rec.socket_id == kTargetSocket;
      }
    }
    return false;  // not found in spy — not allocated through it
  };

  // Every major arena pointer must be in the spy's records, on the
  // correct socket.
  EXPECT_NE(rs.l2_actions, nullptr);
  EXPECT_TRUE(ptr_on_socket(rs.l2_actions))
      << "l2_actions not allocated on socket " << kTargetSocket;

  EXPECT_NE(rs.l3_actions, nullptr);
  EXPECT_TRUE(ptr_on_socket(rs.l3_actions))
      << "l3_actions not allocated on socket " << kTargetSocket;

  EXPECT_NE(rs.l4_actions, nullptr);
  EXPECT_TRUE(ptr_on_socket(rs.l4_actions))
      << "l4_actions not allocated on socket " << kTargetSocket;

  EXPECT_NE(rs.counters, nullptr);
  EXPECT_TRUE(ptr_on_socket(rs.counters))
      << "counters not allocated on socket " << kTargetSocket;
}

// =========================================================================
// U4.16 Port TX-queue symmetry pre-check (D28)
//
// check_port_tx_symmetry(roles, n_workers, dev_info_mock) rejects any
// role whose mocked max_tx_queues < n_workers. Pure C++ with fake
// EthDevInfo struct (no EAL). Covers D28.
// =========================================================================
TEST(RulesetBuilder, TxQueueSymmetry_U4_16) {
  // Two roles: upstream and downstream.
  std::vector<InterfaceRole> roles = {
      InterfaceRole{"upstream_port", PciSelector{"0000:00:03.0"}},
      InterfaceRole{"downstream_port", PciSelector{"0000:00:04.0"}},
  };

  // Mock dev info — upstream has enough queues, downstream does not.
  std::unordered_map<std::string, EthDevInfo> dev_info;
  dev_info["upstream_port"] = EthDevInfo{.max_tx_queues = 8};
  dev_info["downstream_port"] = EthDevInfo{.max_tx_queues = 2};

  constexpr unsigned kWorkers = 4;

  // With 4 workers, downstream (max=2) must fail.
  auto errors = check_port_tx_symmetry(roles, kWorkers, dev_info);
  ASSERT_EQ(errors.size(), 1u)
      << "Expected exactly 1 error (downstream_port)";
  EXPECT_EQ(errors[0].role_name, "downstream_port");
  EXPECT_EQ(errors[0].max_tx_queues, 2u);
  EXPECT_EQ(errors[0].n_workers, kWorkers);

  // With 2 workers, both pass.
  auto errors2 = check_port_tx_symmetry(roles, 2, dev_info);
  EXPECT_TRUE(errors2.empty())
      << "Both ports have >=2 TX queues; expected no errors";

  // Missing role in dev_info map — should report as error (0 queues).
  std::vector<InterfaceRole> roles3 = {
      InterfaceRole{"mirror_port", PciSelector{"0000:00:05.0"}},
  };
  auto errors3 = check_port_tx_symmetry(roles3, 1, dev_info);
  ASSERT_EQ(errors3.size(), 1u)
      << "Missing port in dev_info map must be an error";
  EXPECT_EQ(errors3[0].role_name, "mirror_port");
  EXPECT_EQ(errors3[0].max_tx_queues, 0u);
}

// =========================================================================
// U6.22 Config fragment_policy → Ruleset.fragment_policy wiring
//
// Config with fragment_policy = kDrop (value 1) goes through compile() →
// build_ruleset(). The resulting Ruleset.fragment_policy must be 1
// (kFragDrop). Today nothing copies the value, so rs.fragment_policy
// stays 0 (kFragL3Only by POD-init luck) → FAIL. Covers D17, errata
// §M5 C3 silent gap.
// =========================================================================
TEST(RulesetBuilder, FragmentPolicyWired_U6_22) {
  Config cfg = make_config();
  cfg.fragment_policy = FragmentPolicy::kDrop;  // value 1

  // Need at least one L3 rule so compile is non-trivial.
  append_rule(cfg.pipeline.layer_3, 900, ActionDrop{});

  auto cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value()) << "compile must succeed";

  constexpr unsigned kNumLcores = 2;
  auto rs = build_ruleset(cr, cfg.sizing, kNumLcores);

  // fragment_policy must be 1 (kFragDrop), NOT 0 (kFragL3Only).
  EXPECT_EQ(rs.fragment_policy, 1u)
      << "fragment_policy must propagate from Config through CompileResult "
         "to Ruleset; got " << static_cast<unsigned>(rs.fragment_policy)
      << " (expected 1 = kFragDrop)";

  // Also verify the kAllow path.
  Config cfg2 = make_config();
  cfg2.fragment_policy = FragmentPolicy::kAllow;  // value 2
  append_rule(cfg2.pipeline.layer_3, 901, ActionAllow{});

  auto cr2 = compile(cfg2);
  ASSERT_FALSE(cr2.error.has_value());

  auto rs2 = build_ruleset(cr2, cfg2.sizing, kNumLcores);
  EXPECT_EQ(rs2.fragment_policy, 2u)
      << "fragment_policy kAllow (2) must propagate; got "
      << static_cast<unsigned>(rs2.fragment_policy);

  // And the default kL3Only — this one passes today by luck (POD=0).
  Config cfg3 = make_config();
  append_rule(cfg3.pipeline.layer_3, 902, ActionDrop{});

  auto cr3 = compile(cfg3);
  ASSERT_FALSE(cr3.error.has_value());

  auto rs3 = build_ruleset(cr3, cfg3.sizing, kNumLcores);
  EXPECT_EQ(rs3.fragment_policy, 0u)
      << "fragment_policy kL3Only (0) must propagate (default)";
}

// =========================================================================
// U3.Smoke2 — TAG action lowering: dscp/pcp propagate to RuleAction
//
// Config with a TAG rule (dscp=46, pcp=5) goes through compile() →
// build_ruleset(). The resulting action::RuleAction slot must carry the
// same dscp/pcp and verb=kTag. Before C2b retrofit, the compiler's
// CompiledAction carries only the verb enum — dscp/pcp are silently
// dropped and builder::copy_actions hardcodes zeros. Covers D41 retrofit,
// D19 TAG payload. Errata §M7 C2b.
// =========================================================================
TEST(RulesetBuilder, TagActionLowered_U3_Smoke2) {
  Config cfg = make_config();

  // Single L2 rule carrying a TAG action with non-zero DSCP and PCP.
  ActionTag tag;
  tag.dscp = 46;  // EF (expedited forwarding)
  tag.pcp = 5;    // voice class
  auto& r = append_rule(cfg.pipeline.layer_2, 1001, tag);
  r.src_mac = Mac{{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}};

  auto cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value()) << "compile must succeed";
  ASSERT_EQ(cr.l2_actions.size(), 1u);

  // CompiledAction must carry the dscp/pcp payload — this is the
  // compiler-side half of the retrofit.
  EXPECT_EQ(cr.l2_actions[0].verb, ActionVerb::kTag)
      << "CompiledAction.verb must reflect the tag action";
  EXPECT_EQ(cr.l2_actions[0].dscp, 46u)
      << "CompiledAction.dscp must carry config::ActionTag.dscp (D41 retrofit)";
  EXPECT_EQ(cr.l2_actions[0].pcp, 5u)
      << "CompiledAction.pcp must carry config::ActionTag.pcp (D41 retrofit)";

  constexpr unsigned kNumLcores = 2;
  auto rs = build_ruleset(cr, cfg.sizing, kNumLcores);

  ASSERT_GE(rs.n_l2_rules, 1u);
  ASSERT_NE(rs.l2_actions, nullptr);

  const auto& ra = rs.l2_actions[0];
  EXPECT_EQ(static_cast<unsigned>(ra.verb),
            static_cast<unsigned>(ActionVerb::kTag))
      << "RuleAction.verb must equal kTag after lowering";
  EXPECT_EQ(static_cast<unsigned>(ra.dscp), 46u)
      << "RuleAction.dscp must equal config dscp=46 after builder copy "
         "(hardcoded 0 before retrofit)";
  EXPECT_EQ(static_cast<unsigned>(ra.pcp), 5u)
      << "RuleAction.pcp must equal config pcp=5 after builder copy";
}

// =========================================================================
// U3.Smoke3 — REDIRECT action lowering: role_name resolves to port_idx
//
// Config with a REDIRECT rule targeting "downstream_port" (second role in
// interface_roles) goes through compile() → build_ruleset(). The
// RuleAction slot must carry redirect_port = 1 (index of the matching
// role) and verb = kRedirect. Before C2b retrofit, builder hardcodes
// redirect_port = 0xFFFF, which apply_redirect treats as a drop.
// Covers D41 retrofit, D16 REDIRECT port. Errata §M7 C2b.
// =========================================================================
TEST(RulesetBuilder, RedirectActionLowered_U3_Smoke3) {
  Config cfg = make_config();
  // make_config() pre-populates two roles: upstream_port (idx 0),
  // downstream_port (idx 1). Target downstream_port so the expected
  // index is 1 (distinct from the 0xFFFF sentinel and 0).

  ActionTargetPort redir;
  redir.role_name = "downstream_port";
  auto& r = append_rule(cfg.pipeline.layer_2, 2001, redir);
  r.src_mac = Mac{{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}};

  auto cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value()) << "compile must succeed";
  ASSERT_EQ(cr.l2_actions.size(), 1u);

  EXPECT_EQ(cr.l2_actions[0].verb, ActionVerb::kRedirect)
      << "CompiledAction.verb must reflect the redirect action";
  EXPECT_EQ(cr.l2_actions[0].redirect_port, 1u)
      << "CompiledAction.redirect_port must carry resolved role idx "
         "(downstream_port = 1)";

  constexpr unsigned kNumLcores = 2;
  auto rs = build_ruleset(cr, cfg.sizing, kNumLcores);

  ASSERT_GE(rs.n_l2_rules, 1u);
  ASSERT_NE(rs.l2_actions, nullptr);

  const auto& ra = rs.l2_actions[0];
  EXPECT_EQ(static_cast<unsigned>(ra.verb),
            static_cast<unsigned>(ActionVerb::kRedirect))
      << "RuleAction.verb must equal kRedirect after lowering";
  EXPECT_EQ(ra.redirect_port, 1u)
      << "RuleAction.redirect_port must equal resolved port_idx = 1 "
         "(hardcoded 0xFFFF before retrofit)";
}

// =========================================================================
// U3.Smoke4 — default_behavior lowering: Config → Ruleset.default_action
//
// Config with default_behavior=kDrop must produce Ruleset.default_action=1;
// default_behavior=kAllow must produce 0. Before C2b retrofit, neither
// the compiler nor the builder read cfg.default_behavior and
// rs.default_action stays at its POD-default 0 regardless of config.
// Covers D7 (default arm), D41 retrofit. Errata §M7 C2b.
// =========================================================================
TEST(RulesetBuilder, DefaultActionLowered_U3_Smoke4) {
  // Case 1: default_behavior = kDrop → rs.default_action == 1.
  Config cfg_drop = make_config();
  cfg_drop.default_behavior = DefaultBehavior::kDrop;
  append_rule(cfg_drop.pipeline.layer_4, 3001, ActionAllow{});

  auto cr_drop = compile(cfg_drop);
  ASSERT_FALSE(cr_drop.error.has_value());

  constexpr unsigned kNumLcores = 2;
  auto rs_drop = build_ruleset(cr_drop, cfg_drop.sizing, kNumLcores);
  EXPECT_EQ(static_cast<unsigned>(rs_drop.default_action), 1u)
      << "default_behavior=kDrop must lower to rs.default_action=1 "
         "(stays 0 before retrofit)";

  // Case 2: default_behavior = kAllow → rs.default_action == 0.
  Config cfg_allow = make_config();
  cfg_allow.default_behavior = DefaultBehavior::kAllow;
  append_rule(cfg_allow.pipeline.layer_4, 3002, ActionAllow{});

  auto cr_allow = compile(cfg_allow);
  ASSERT_FALSE(cr_allow.error.has_value());

  auto rs_allow = build_ruleset(cr_allow, cfg_allow.sizing, kNumLcores);
  EXPECT_EQ(static_cast<unsigned>(rs_allow.default_action), 0u)
      << "default_behavior=kAllow must lower to rs.default_action=0";
}

}  // namespace
