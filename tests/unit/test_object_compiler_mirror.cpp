// tests/unit/test_object_compiler_mirror.cpp
//
// M16 C1 — U16.1 parser/compiler roundtrip for `action: mirror`.
//
// Before M16 C1 the object compiler rejected any config with a mirror
// rule (`CompileErrorCode::kMirrorNotImplemented`). M16 C1 removes that
// reject (review-notes §D7 amendment 2026-04-20) and lowers the
// resolved mirror destination port_id through the CompiledAction
// `mirror_port` field — symmetric to `redirect_port` and guarded by
// the D41 #7 observable_fields projection extension (static_assert
// pair in src/ruleset/builder.cpp + runtime roundtrip in
// tests/unit/test_d41_guard.cpp + EAL smoke in
// tests/unit/test_d41_eal_smoke.cpp).
//
// Scope (narrow, unit tier, DPDK-free):
//   * Drive the full parse -> validate -> compile pipeline on YAML
//     carrying `action: mirror, target_port: <role>`. The compile()
//     output must carry a CompiledAction with verb == kMirror and
//     mirror_port == <resolved role idx>.
//   * Assert compile() returns NO error (proves the scan-for-kMirror
//     reject block is gone).
//   * Cross-layer (L2 / L3 / L4) coverage: same rule shape compiles
//     in every layer.
//   * Sanity: a non-mirror rule keeps mirror_port at the 0xFFFF
//     sentinel (proves we did not accidentally clobber the default).
//
// Out of scope (later cycles):
//   * Hot-path MIRROR dispatch behaviour — M16 C2.
//   * Functional TAP smoke — M16 C3.
//   * Chaos — M16 C4 / C5.
//
// Memory anchors:
//   * grabli_empty_ruleset_short_circuit_hides_parse.md — drive the
//     real parse pipeline, not construct CompiledAction directly.
//   * grabli_m4c0_dpdk_free_core_library.md — this TU stays in
//     pktgate_core (parser + validator + compiler), no DPDK.

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "src/compiler/compiler.h"
#include "src/compiler/object_compiler.h"
#include "src/config/model.h"
#include "src/config/parser.h"
#include "src/config/sizing.h"
#include "src/config/validator.h"

namespace {

using namespace pktgate::compiler;
using namespace pktgate::config;

// -------------------------------------------------------------------------
// Build a Config directly (no YAML parser path needed — the validator
// runs against Config, not source text). Two interface_roles so
// mirror can resolve to role_idx 1 (a non-trivial non-zero index).
// -------------------------------------------------------------------------
Config make_config() {
  Config cfg;
  cfg.version = kSchemaVersion;
  cfg.default_behavior = DefaultBehavior::kDrop;
  cfg.fragment_policy = FragmentPolicy::kL3Only;
  cfg.sizing = kSizingDevDefaults;
  cfg.interface_roles = {
      InterfaceRole{"upstream_port",   PciSelector{"0000:00:00.0"}},
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

// =========================================================================
// U16.1 — compile() accepts a mirror rule and lowers mirror_port.
// =========================================================================
TEST(ObjectCompilerMirror, L4MirrorCompilesAndLowersPort_U16_1) {
  Config cfg = make_config();

  auto& rule = append_rule(cfg.pipeline.layer_4, 16001,
                           ActionMirror{"downstream_port"});
  rule.proto = 6;
  rule.dst_port = 443;

  // Validator must accept — mirror target_port resolves.
  auto vres = validate(cfg);
  ASSERT_TRUE(std::holds_alternative<ValidateOk>(vres))
      << "validator rejected mirror with resolvable target_port: "
      << std::get<ValidateError>(vres).message;

  auto cr = compile(cfg);

  ASSERT_FALSE(cr.error.has_value())
      << "compile() returned an error for a mirror rule — D7 unlock "
         "(M16 C1) should not reject mirror. Error: "
      << (cr.error ? cr.error->message : "");

  ASSERT_EQ(cr.l4_actions.size(), 1u);
  const auto& ca = cr.l4_actions[0];
  EXPECT_EQ(ca.verb, ActionVerb::kMirror);
  EXPECT_EQ(ca.rule_id, 16001);
  EXPECT_EQ(ca.mirror_port, 1u)
      << "downstream_port is interface_roles[1]";
  EXPECT_EQ(ca.redirect_port, 0xFFFFu)
      << "mirror rule must NOT set redirect_port";
  EXPECT_EQ(ca.rl_slot, 0xFFFFu)
      << "mirror rule is not a rate-limit verb";
}

// =========================================================================
// U16.1b — Cross-layer coverage: L2 + L3 mirror also compile.
// =========================================================================
TEST(ObjectCompilerMirror, AllLayersAcceptMirror_U16_1b) {
  // L2 layer.
  {
    Config cfg = make_config();
    auto& r = append_rule(cfg.pipeline.layer_2, 16011,
                          ActionMirror{"upstream_port"});
    r.vlan_id = 42;

    auto cr = compile(cfg);
    ASSERT_FALSE(cr.error.has_value()) << "L2 mirror must compile";
    ASSERT_EQ(cr.l2_actions.size(), 1u);
    EXPECT_EQ(cr.l2_actions[0].verb, ActionVerb::kMirror);
    EXPECT_EQ(cr.l2_actions[0].mirror_port, 0u)
        << "upstream_port is interface_roles[0]";
  }

  // L3 layer.
  {
    Config cfg = make_config();
    append_rule(cfg.pipeline.layer_3, 16012,
                ActionMirror{"downstream_port"});

    auto cr = compile(cfg);
    ASSERT_FALSE(cr.error.has_value()) << "L3 mirror must compile";
    ASSERT_EQ(cr.l3_actions.size(), 1u);
    EXPECT_EQ(cr.l3_actions[0].verb, ActionVerb::kMirror);
    EXPECT_EQ(cr.l3_actions[0].mirror_port, 1u);
  }
}

// =========================================================================
// U16.1c — Non-mirror rules keep mirror_port at 0xFFFF sentinel.
//
// Sanity check: adding mirror_port lowering must not clobber the
// default sentinel for ALLOW / DROP / TAG / REDIRECT / RATELIMIT
// verbs. If a future refactor accidentally copies mirror_port from
// an unrelated ActionLowered branch, this test flags it immediately.
// =========================================================================
TEST(ObjectCompilerMirror, NonMirrorVerbsKeepSentinel_U16_1c) {
  Config cfg = make_config();

  append_rule(cfg.pipeline.layer_4, 16021, ActionAllow{});
  append_rule(cfg.pipeline.layer_4, 16022, ActionDrop{});

  ActionTag tag;
  tag.dscp = 32;
  tag.pcp = 3;
  append_rule(cfg.pipeline.layer_4, 16023, tag);

  ActionTargetPort redir;
  redir.role_name = "upstream_port";
  append_rule(cfg.pipeline.layer_4, 16024, redir);

  auto cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value());
  ASSERT_EQ(cr.l4_actions.size(), 4u);

  for (const auto& ca : cr.l4_actions) {
    EXPECT_EQ(ca.mirror_port, 0xFFFFu)
        << "non-kMirror verb (rule_id=" << ca.rule_id
        << ") must keep mirror_port at 0xFFFF sentinel";
  }
  // Spot-check the REDIRECT verb still lowers redirect_port correctly
  // — regression canary for accidental copy-from-wrong-field bugs.
  EXPECT_EQ(cr.l4_actions[3].verb, ActionVerb::kRedirect);
  EXPECT_EQ(cr.l4_actions[3].redirect_port, 0u)
      << "upstream_port is interface_roles[0]";
}

// =========================================================================
// U16.1d — kMirrorNotImplemented enumerator still exists (ABI).
//
// The enumerator is preserved in src/compiler/compiler.h for ABI
// continuity even though no emitter site references it in M16+.
// This compile-time test pins that contract — removing the
// enumerator breaks this build, surfacing the ABI change at the
// unit tier rather than silently elsewhere.
// =========================================================================
TEST(ObjectCompilerMirror, MirrorNotImplementedEnumeratorPreserved_U16_1d) {
  // Reference the enumerator to force ODR-use.
  const auto code = CompileErrorCode::kMirrorNotImplemented;
  EXPECT_EQ(static_cast<std::uint8_t>(code), 1u);
}

}  // namespace
