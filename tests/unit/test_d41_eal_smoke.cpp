// tests/unit/test_d41_eal_smoke.cpp
//
// D41 C2 — boot-path smoke (Candidate D from the D41 discovery report).
//
// Complement to C1 (tuple-projection static_assert + runtime roundtrip)
// and C1b (resolve_action visitor exhaustiveness). This cycle covers a
// runtime-surface subclass that compile-time guards structurally cannot
// catch: `main.cpp` call-graph orphans. The canonical precedents are
//
//   * M4 C0b — `populate_ruleset_eal` existed but was never called from
//     main.cpp, so every DPDK table handle stayed nullptr while every
//     unit test pass green; only the F2.* functional tier noticed.
//   * M9 C5 — RlSlotAllocator was defined but not wired into main.cpp's
//     compile() invocation, so every RL rule shipped with kInvalidSlot
//     and the dataplane silently failed RL dispatch.
//
// A compile-time projection sees only the type relationships between
// CompiledAction and RuleAction; it cannot reason about which entry
// points are actually called at boot. The C2 smoke closes that gap by
// running the full boot pipeline --- parse/synthetic-AST -> compile ->
// build_ruleset -> populate_ruleset_eal --- on a minimal config that
// touches every observable verb and asserting the D41 invariants hold
// on the resulting Ruleset.
//
// Scope (strict):
//
//   * Inline EalFixture with unique file-prefix=pktgate_d41_smoke so
//     this binary does not collide with the process-wide singleton
//     EalFixture in test_eal_unit. Separate /run/dpdk namespace.
//   * 2 L2 + 2 L3 + 2 L4 rules, one per MVP-supported verb. Non-zero
//     dscp/pcp/redirect/rate/burst so sentinel-drop bugs show up.
//   * Per-rule projection roundtrip: observable_fields(RuleAction) must
//     equal observable_fields(CompiledAction) post-populate (proves
//     populate_ruleset_eal does not silently overwrite the action arena).
//   * Positive-value checks (TAG dscp/pcp, REDIRECT role_idx=1,
//     RATELIMIT slot != kInvalidSlot).
//   * Q6 runtime assertion (the key C2 addition): rs.rl_actions[slot]
//     carries {rule_id, rate_bps, burst_bytes} matching the compiler
//     output. This is the D41 lockstep invariant defended by
//     src/ruleset/builder.cpp:101-112,268-279. If a future copy-paste
//     regression drops the rl_actions[] populate step, this test fails
//     even though the static_asserts stay green and C1's runtime
//     roundtrip (RuleAction-side only) stays green.
//
// Out of scope:
//
//   * next_layer / flags / mirror_port --- dead carriers, excluded
//     from observable_fields() by D41 C1. See action.h for the
//     allowlist rationale.
//   * fragment_policy / default_action ruleset-level --- covered by
//     M5 C3b (U6.22) and M7 C2b (U3.Smoke2/3/4) smoke tests already.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <tuple>
#include <vector>

#include <rte_eal.h>

#include "src/action/action.h"
#include "src/compiler/compiler.h"
#include "src/compiler/object_compiler.h"
#include "src/config/addr.h"
#include "src/config/model.h"
#include "src/config/sizing.h"
#include "src/rl_arena/arena.h"
#include "src/rl_arena/rl_arena.h"
#include "src/ruleset/builder.h"
#include "src/ruleset/builder_eal.h"
#include "src/ruleset/ruleset.h"

namespace {

using namespace pktgate::compiler;
using namespace pktgate::config;
using namespace pktgate::ruleset;

// -------------------------------------------------------------------------
// Inline EAL fixture with a unique file-prefix so this binary does not
// share /run/dpdk/<prefix>/ state with test_eal_unit's singleton. EAL
// can still only be initialised once per process, but this process
// carries only D41 C2 tests, so one SetUpTestSuite is sufficient.
//
// The pattern mirrors tests/unit/eal_fixture.h (M3 C4) --- copy-paste
// is intentional per handoff: avoid cross-binary /run/dpdk/ collisions
// that plagued earlier cycles (memory: grabli_run_dpdk_tmpfs_leak).
// -------------------------------------------------------------------------
class D41EalSmokeFixture : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (s_initialized) return;

    // EAL `-d <path>` is opt-in via PKTGATE_DPDK_DRIVER_DIR --- same
    // dual-install rationale as tests/unit/eal_fixture.h (2026-04-19
    // infra fixup, memory `vm_dpdk_layout.md`).
    std::vector<const char*> argv{
        "test_d41_eal_smoke",
        "--no-pci",
        "--no-huge",
        "-m", "512",
        "--log-level", "lib.*:error",
    };
    const char* drv = std::getenv("PKTGATE_DPDK_DRIVER_DIR");
    if (drv != nullptr && drv[0] != '\0') {
      argv.push_back("-d");
      argv.push_back(drv);
    }
    argv.push_back("--vdev");
    argv.push_back("net_null0");
    argv.push_back("--file-prefix");
    argv.push_back("pktgate_d41_smoke");

    int argc = static_cast<int>(argv.size());
    int ret = rte_eal_init(argc, const_cast<char**>(argv.data()));
    ASSERT_GE(ret, 0) << "rte_eal_init failed";

    s_initialized = true;
  }

  static void TearDownTestSuite() {
    // rte_eal_cleanup() is not fully supported in test contexts on
    // DPDK 25.11 --- skip cleanup, same as eal_fixture.h.
  }

 private:
  static inline bool s_initialized = false;
};

// -------------------------------------------------------------------------
// Helpers (same shape as test_d41_guard.cpp + test_eal_unit.cpp).
// -------------------------------------------------------------------------
Config make_config() {
  Config cfg;
  cfg.version = kSchemaVersion;
  cfg.default_behavior = DefaultBehavior::kDrop;
  cfg.fragment_policy = FragmentPolicy::kDrop;
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

// RAII scrubber for the process-wide RL arena singleton. Idempotent on
// both entry and exit so reruns under ctest retries stay clean.
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
// D41EalSmoke.AllObservableFieldsRoundtripThroughEal
//
// Full boot pipeline on a minimal config with every observable verb.
// Asserts the three D41 invariants that only a runtime EAL-fixture
// smoke can observe:
//
//   1. Per-layer per-rule observable_fields() roundtrip survives
//      populate_ruleset_eal (covers future regressions that might
//      overwrite the action arena from the EAL-side populate path).
//   2. Positive-value checks: TAG lowered dscp/pcp, REDIRECT role_idx
//      resolved, RATELIMIT slot non-sentinel. Catches the M7 C2b
//      class of silent-zero-default bugs.
//   3. Q6 runtime assertion: rs.rl_actions[slot] contents match the
//      CompiledAction's rate/burst/rule_id fields. Covers the
//      builder.cpp:101-112,268-279 lockstep populate --- if a future
//      copy-paste drops the `rs.rl_actions[s.rl_slot] = ...` line,
//      this test fails even when C1's RuleAction-side roundtrip
//      stays green.
// =========================================================================
TEST_F(D41EalSmokeFixture, AllObservableFieldsRoundtripThroughEal) {
  // ---- Config ----------------------------------------------------------
  // IDs chosen so no layer collides: 1xxx = L2, 2xxx = L3, 3xxx = L4.
  constexpr std::int32_t kL2TagId       = 1001;
  constexpr std::int32_t kL2RedirectId  = 1002;
  constexpr std::int32_t kL2MirrorId    = 1003;
  constexpr std::int32_t kL3AllowId     = 2001;
  constexpr std::int32_t kL3DropId      = 2002;
  constexpr std::int32_t kL4RateLimitId = 3001;
  constexpr std::int32_t kL4DropId      = 3002;

  constexpr std::uint64_t kRateBps    = 1'000'000ull;
  constexpr std::uint64_t kBurstBytes = 10'000ull;

  ArenaScrubber scrub{{static_cast<std::uint64_t>(kL4RateLimitId)}};

  Config cfg = make_config();

  // ---- L2: TAG (dscp=46, pcp=5) + REDIRECT(downstream_port) ------------
  ActionTag tag;
  tag.dscp = 46;
  tag.pcp = 5;
  auto& l2_tag = append_rule(cfg.pipeline.layer_2, kL2TagId, tag);
  l2_tag.src_mac = Mac{{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}};

  ActionTargetPort redir;
  redir.role_name = "downstream_port";
  auto& l2_redir = append_rule(cfg.pipeline.layer_2, kL2RedirectId, redir);
  l2_redir.src_mac = Mac{{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01}};

  // M16 C1 (D7 unlock, D41 #7): MIRROR rule. Exercises the new
  // `mirror_port` field end-to-end through parse -> compile ->
  // build_ruleset -> populate_ruleset_eal and pins the D41 guard
  // extension at the EAL boot-path smoke tier. Before M16 C1 this
  // config would have compile-errored with kMirrorNotImplemented;
  // post-C1 it compiles and lowers the resolved role_idx to
  // action::RuleAction.mirror_port via builder::copy_actions.
  ActionMirror mirror;
  mirror.role_name = "downstream_port";
  auto& l2_mirror = append_rule(cfg.pipeline.layer_2, kL2MirrorId, mirror);
  l2_mirror.src_mac = Mac{{0xCA, 0xFE, 0xBE, 0xEF, 0xF0, 0x01}};

  // ---- L3: ALLOW (10.0.0.0/24) + DROP (192.168.1.0/24) -----------------
  //
  // SubnetRef needs a matching SubnetObject in cfg.objects.subnets (the
  // compiler resolves by name). No overlap so the compound L3 compiler
  // is satisfied.
  SubnetObject allow_net;
  allow_net.name = "net_allow";
  allow_net.cidrs.push_back(Cidr4{0x0A000000u, 24});   // 10.0.0.0/24
  cfg.objects.subnets.push_back(std::move(allow_net));

  SubnetObject drop_net;
  drop_net.name = "net_drop";
  drop_net.cidrs.push_back(Cidr4{0xC0A80100u, 24});    // 192.168.1.0/24
  cfg.objects.subnets.push_back(std::move(drop_net));

  auto& l3_allow = append_rule(cfg.pipeline.layer_3, kL3AllowId, ActionAllow{});
  l3_allow.dst_subnet = SubnetRef{"net_allow"};
  auto& l3_drop = append_rule(cfg.pipeline.layer_3, kL3DropId, ActionDrop{});
  l3_drop.dst_subnet = SubnetRef{"net_drop"};

  // ---- L4: RATELIMIT (tcp/443) + DROP (udp/53) -------------------------
  ActionRateLimit rl;
  rl.bytes_per_sec = kRateBps;
  rl.burst_bytes   = kBurstBytes;
  auto& l4_rl = append_rule(cfg.pipeline.layer_4, kL4RateLimitId, rl);
  l4_rl.proto = 6;
  l4_rl.dst_port = 443;

  auto& l4_drop = append_rule(cfg.pipeline.layer_4, kL4DropId, ActionDrop{});
  l4_drop.proto = 17;
  l4_drop.dst_port = 53;

  // ---- Compile ---------------------------------------------------------
  // Real RlSlotAllocator against the process-wide arena singleton ---
  // same wiring as test_d41_guard.cpp and production main.cpp.
  auto& arena = pktgate::rl_arena::rl_arena_global();
  RlSlotAllocator rl_alloc =
      [&arena](std::uint64_t rid) { return arena.alloc_slot(rid); };

  CompileResult cr = compile(cfg, /*opts=*/{}, rl_alloc);
  ASSERT_FALSE(cr.error.has_value()) << "compile must succeed";
  ASSERT_EQ(cr.l2_actions.size(), 3u)
      << "L2: TAG + REDIRECT + MIRROR (M16 C1 D7 unlock)";
  ASSERT_EQ(cr.l3_actions.size(), 2u);
  ASSERT_EQ(cr.l4_actions.size(), 2u);

  // Per memory grabli_populate_ruleset_eal_no_l3_actions: build_ruleset
  // MUST run before populate_ruleset_eal; otherwise l*_actions arenas
  // stay null and the Ruleset is only half-populated.
  constexpr unsigned kNumLcores = 1;
  Ruleset rs = build_ruleset(cr, cfg.sizing, kNumLcores);
  ASSERT_GE(rs.n_l2_rules, 3u);
  ASSERT_GE(rs.n_l3_rules, 2u);
  ASSERT_GE(rs.n_l4_rules, 2u);

  // ---- populate_ruleset_eal (the step that M4 C0b's main.cpp was
  // missing; this test would have caught that gap) --------------------
  EalPopulateParams params;
  params.name_prefix = "d41_c2_smoke";
  params.socket_id = 0;
  params.max_entries = 64;

  auto res = populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << "populate_ruleset_eal failed: " << res.error;

  // ---- Invariant 1: per-rule observable-field roundtrip (post-EAL).
  //
  // Same shape as test_d41_guard.cpp but run AFTER populate_ruleset_eal
  // to catch any future regression where EAL-side population overwrites
  // the action arena. Today populate_ruleset_eal only touches the
  // compound handles (rte_hash / rte_fib), not the action arena, but
  // this assertion pins that contract.
  auto compare_layer =
      [](const char* layer_name,
         const std::vector<CompiledAction>& src,
         const pktgate::action::RuleAction* dst,
         std::uint32_t n_rules) {
        ASSERT_EQ(src.size(), n_rules)
            << layer_name << ": CompiledAction count drift (post-EAL)";
        for (std::uint32_t i = 0; i < n_rules; ++i) {
          const auto ca_proj =
              pktgate::compiler::observable_fields(src[i]);
          const auto ra_proj =
              pktgate::action::observable_fields(dst[i]);
          EXPECT_EQ(ca_proj, ra_proj)
              << layer_name << " rule index " << i
              << ": D41 projection mismatch post populate_ruleset_eal";
        }
      };

  compare_layer("L2", cr.l2_actions, rs.l2_actions, rs.n_l2_rules);
  compare_layer("L3", cr.l3_actions, rs.l3_actions, rs.n_l3_rules);
  compare_layer("L4", cr.l4_actions, rs.l4_actions, rs.n_l4_rules);

  // ---- Invariant 2: positive-value checks. --------------------------
  // TAG lowered dscp/pcp --- the M7 C2b regression class.
  EXPECT_EQ(rs.l2_actions[0].dscp, 46u) << "TAG dscp lowered";
  EXPECT_EQ(rs.l2_actions[0].pcp, 5u) << "TAG pcp lowered";

  // REDIRECT role_idx resolves to downstream_port == 1.
  EXPECT_EQ(rs.l2_actions[1].redirect_port, 1u)
      << "REDIRECT downstream_port role idx";

  // M16 C1 (D41 #7): MIRROR verb lowers mirror_port to downstream_port
  // role_idx (1). The first two L2 rules (TAG + REDIRECT) keep the
  // 0xFFFF sentinel — catches any future regression that copies
  // mirror_port from the wrong arm of resolve_action.
  EXPECT_EQ(rs.l2_actions[2].verb,
            static_cast<std::uint8_t>(ActionVerb::kMirror));
  EXPECT_EQ(rs.l2_actions[2].mirror_port, 1u)
      << "MIRROR downstream_port role idx lowered through EAL boot";
  EXPECT_EQ(rs.l2_actions[0].mirror_port, 0xFFFFu)
      << "TAG verb must keep mirror_port sentinel";
  EXPECT_EQ(rs.l2_actions[1].mirror_port, 0xFFFFu)
      << "REDIRECT verb must keep mirror_port sentinel";

  // L3 verbs land right verb bytes.
  EXPECT_EQ(rs.l3_actions[0].verb,
            static_cast<std::uint8_t>(ActionVerb::kAllow));
  EXPECT_EQ(rs.l3_actions[1].verb,
            static_cast<std::uint8_t>(ActionVerb::kDrop));

  // L4 RATELIMIT lands a real slot (not kInvalidSlot 0xFFFF) and the
  // second L4 DROP rule leaves the sentinel intact.
  EXPECT_EQ(rs.l4_actions[0].verb,
            static_cast<std::uint8_t>(ActionVerb::kRateLimit));
  EXPECT_EQ(rs.l4_actions[1].verb,
            static_cast<std::uint8_t>(ActionVerb::kDrop));
  EXPECT_NE(rs.l4_actions[0].rl_index, 0xFFFFu)
      << "RL slot allocator must hand out a real slot";
  EXPECT_EQ(rs.l4_actions[1].rl_index, 0xFFFFu)
      << "non-RL verb must keep the kInvalidSlot sentinel";

  // ---- Invariant 3 (Q6 runtime): rs.rl_actions[slot] matches the
  // CompiledAction contents. This is the D41 lockstep invariant
  // defended by src/ruleset/builder.cpp:101-112,268-279 --- if a
  // future overload refactor drops the `rs.rl_actions[s.rl_slot] =
  // {...}` populate line, this EXPECT_EQ chain fails even when the
  // static_assert pair and the C1 projection roundtrip stay green.
  ASSERT_GT(rs.n_rl_actions, 0u)
      << "populate_ruleset_eal must not clear the rl_actions arena";

  const auto slot = cr.l4_actions[0].rl_slot;
  ASSERT_NE(slot, 0xFFFFu) << "CompiledAction.rl_slot must be allocated";
  ASSERT_LT(slot, rs.rl_actions_capacity)
      << "slot must fit the rl_actions arena";

  EXPECT_EQ(rs.rl_actions[slot].rule_id,
            static_cast<std::uint64_t>(kL4RateLimitId))
      << "rl_actions[slot].rule_id tracks CompiledAction rule_id";
  EXPECT_EQ(rs.rl_actions[slot].rate_bps, cr.l4_actions[0].rl_rate_bps)
      << "rl_actions[slot].rate_bps tracks CompiledAction.rl_rate_bps";
  EXPECT_EQ(rs.rl_actions[slot].burst_bytes,
            cr.l4_actions[0].rl_burst_bytes)
      << "rl_actions[slot].burst_bytes tracks CompiledAction.rl_burst_bytes";

  // Also assert the raw values end up what the config asked for ---
  // belt-and-suspenders covering the compile() side of the pipeline.
  EXPECT_EQ(rs.rl_actions[slot].rate_bps, kRateBps);
  EXPECT_EQ(rs.rl_actions[slot].burst_bytes, kBurstBytes);
}

}  // namespace
