// tests/unit/test_role_idx_port_id_translation.cpp
//
// M16 C3.5 RED — U16.12 + U16.13.
//
// Pins a pre-existing M7 regression class surfaced by M16 C3 worker:
// `RuleAction.{redirect_port, mirror_port}` today carry the compiler-side
// `role_idx` (declaration-rank of the role name within
// `interface_roles`) — but the hot path passes those bytes straight to
// `rte_eth_tx_burst(port, ...)` which expects a DPDK port_id. Works on
// every existing test only because the role names happen to sort /
// enumerate the same way DPDK vdevs do. M16 C3 had to rename its mirror
// role `zz_mirror_port` to keep the lex-rank coincident with the DPDK
// port_id (2). Memory `grabli_role_idx_as_port_id_bug.md`.
//
// RED strategy (this cycle):
//   * Construct `interface_roles` whose declaration-rank (== role_idx)
//     DIVERGES from the DPDK vdev enumeration order, using NameSelector
//     entries that point at `net_null[0..2]` vdevs booted in a cmdline
//     order that does NOT match the declaration-rank of the roles.
//   * Drive the full parse-free pipeline compile() -> build_ruleset() ->
//     populate_ruleset_eal() with one redirect rule + one mirror rule.
//   * Assert RuleAction.redirect_port / .mirror_port contain the
//     RESOLVED DPDK port_id (what the hot path will feed
//     rte_eth_tx_burst), NOT the compiler role_idx.
//
// Current tree: populate_ruleset_eal never touches rs.l*_actions —
// role_idx flows through unchanged, assertions fail by 0 vs >=1.
// GREEN cycle (M16 C3.5) lands the translation step in
// src/ruleset/builder_eal.cpp and flips these to pass.
//
// Non-lex role layout:
//
//   role_name / declaration_rank / vdev_name     / DPDK port_id
//   ------------------------------------------------------------
//   "zulu"   / 0                  / net_null1    / 1
//   "alpha"  / 1                  / net_null2    / 2
//   "mike"   / 2                  / net_null0    / 0
//
// Every role has `role_idx != port_id`. Divergence held by construction
// (not inadvertent coincidence).
//
// Why NameSelector: simplest DPDK name→port_id path. The resolver and
// EAL-side rte_eth_dev_get_port_by_name both accept the raw `net_null*`
// spelling, no vdev spec parsing needed.
//
// Out of scope: compile-path unit semantics are owned by
// test_object_compiler_mirror.cpp (M16 C1). This TU covers ONLY the
// populate-time translation invariant — it is the RED twin of the C3.5
// GREEN commit's populate_ruleset_eal diff. Runtime roundtrip D41 guard
// (test_d41_guard.cpp) and EAL boot-path smoke (test_d41_eal_smoke.cpp)
// continue to assert role_idx semantics at CompiledAction level; the
// population-time translation is a new, post-D41 step.
//
// Layering: LABELS unit;needs-eal (like test_d41_eal_smoke.cpp) because
// rte_eth_dev_get_port_by_name requires EAL initialisation. Links
// pktgate_dp so the EAL-aware populate path is reachable.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include <rte_eal.h>
#include <rte_ethdev.h>

#include "src/action/action.h"
#include "src/compiler/compiler.h"
#include "src/compiler/object_compiler.h"
#include "src/config/model.h"
#include "src/config/sizing.h"
#include "src/ruleset/builder.h"
#include "src/ruleset/builder_eal.h"
#include "src/ruleset/ruleset.h"

namespace {

using namespace pktgate::compiler;
using namespace pktgate::config;
using namespace pktgate::ruleset;

// -------------------------------------------------------------------------
// Inline EAL fixture — unique `--file-prefix=pktgate_role_port_xlate` so
// this binary does not share /run/dpdk/<prefix>/ state with either
// test_eal_unit (pktgate_eal_unit) or test_d41_eal_smoke
// (pktgate_d41_smoke). EAL can only be initialised once per process; the
// singleton runs once on first test, tears down as a no-op at program
// exit.
//
// vdev cmdline order: net_null0, net_null1, net_null2 ->
// DPDK port_ids: 0, 1, 2 (DPDK assigns in --vdev cmdline order).
// -------------------------------------------------------------------------
class RolePortXlateFixture : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (s_initialized) return;

    std::vector<const char*> argv{
        "test_role_idx_port_id_translation",
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
    // Three vdevs — DPDK assigns port_ids in cmdline order, so
    // net_null0 -> 0, net_null1 -> 1, net_null2 -> 2.
    argv.push_back("--vdev");
    argv.push_back("net_null0");
    argv.push_back("--vdev");
    argv.push_back("net_null1");
    argv.push_back("--vdev");
    argv.push_back("net_null2");
    argv.push_back("--file-prefix");
    argv.push_back("pktgate_role_port_xlate");

    int argc = static_cast<int>(argv.size());
    int ret = rte_eal_init(argc, const_cast<char**>(argv.data()));
    ASSERT_GE(ret, 0) << "rte_eal_init failed";

    s_initialized = true;
  }

  static void TearDownTestSuite() {
    // Same caveat as eal_fixture.h: rte_eal_cleanup() is not safe under
    // DPDK 25.11 in test contexts. Let the process exit.
  }

  // Resolve a vdev name to its runtime DPDK port_id. The test's "expected"
  // column — the value RuleAction.{redirect,mirror}_port should contain
  // POST-populate for the translation step to land correctly. Any value
  // that isn't this (e.g. the compiler role_idx) is the bug.
  static std::uint16_t port_id_of(const char* name) {
    std::uint16_t pid = 0xFFFFu;
    int ret = rte_eth_dev_get_port_by_name(name, &pid);
    EXPECT_EQ(ret, 0) << "rte_eth_dev_get_port_by_name(" << name
                      << ") failed with ret=" << ret;
    return pid;
  }

 private:
  static inline bool s_initialized = false;
};

// -------------------------------------------------------------------------
// Helper: minimal Config with THREE interface_roles in a declaration
// order whose ranks diverge from the DPDK port_id each role's vdev
// maps to.
//
// Declaration rank (== role_idx emitted by resolve_role_idx):
//   zulu  -> 0
//   alpha -> 1
//   mike  -> 2
//
// vdev cmdline assignment (set up by the fixture):
//   net_null0 -> port_id 0
//   net_null1 -> port_id 1
//   net_null2 -> port_id 2
//
// Role -> vdev binding (chosen so role_idx != port_id for every role):
//   zulu  -> NameSelector{"net_null1"}  -> port_id 1  (role_idx 0)
//   alpha -> NameSelector{"net_null2"}  -> port_id 2  (role_idx 1)
//   mike  -> NameSelector{"net_null0"}  -> port_id 0  (role_idx 2)
// -------------------------------------------------------------------------
Config make_nonlex_config() {
  Config cfg;
  cfg.version = kSchemaVersion;
  cfg.default_behavior = DefaultBehavior::kDrop;
  cfg.fragment_policy = FragmentPolicy::kL3Only;
  cfg.sizing = kSizingDevDefaults;
  // Vector order = resolve_role_idx output. The divergence is by
  // construction: every (role_idx, port_id) pair is different.
  cfg.interface_roles = {
      InterfaceRole{"zulu",  NameSelector{"net_null1"}},
      InterfaceRole{"alpha", NameSelector{"net_null2"}},
      InterfaceRole{"mike",  NameSelector{"net_null0"}},
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
// U16.12 — after compile()+build_ruleset()+populate_ruleset_eal(), the
// `RuleAction.redirect_port` AND `RuleAction.mirror_port` fields carry
// the resolved DPDK port_id of the target role, NOT the compiler-side
// role_idx (declaration-rank).
//
// Setup: non-lex interface_roles (see make_nonlex_config).
//
// Rules:
//   * L4 rule 16012 — action: redirect -> "alpha"
//     Expected post-populate: redirect_port == port_id_of("net_null2") == 2.
//     Current tree: 1 (role_idx of "alpha").
//   * L4 rule 16013 — action: mirror -> "mike"
//     Expected post-populate: mirror_port == port_id_of("net_null0") == 0.
//     Current tree: 2 (role_idx of "mike").
//
// Sanity assertions nail the drift in both directions — test would not
// exercise the bug if the three DPDK ports happened to be enumerated in
// the same order as the role declaration.
// =========================================================================
TEST_F(RolePortXlateFixture, RedirectAndMirrorTranslate_U16_12) {
  const std::uint16_t port_zulu  = port_id_of("net_null1");
  const std::uint16_t port_alpha = port_id_of("net_null2");
  const std::uint16_t port_mike  = port_id_of("net_null0");

  // Sanity: the divergence is actually present in the live fixture.
  // If DPDK ever enumerated vdevs in a different order (dpdk_dev_list
  // quirk, vfio reshuffle, etc.), this test would still be RED because
  // the assertion is built off port_id_of, but the ASSERTs here make
  // it obvious that the test IS exercising the drift and not passing
  // by lex-enumeration coincidence.
  ASSERT_NE(port_zulu, 0u)
      << "role `zulu` role_idx=0 must not coincide with its port_id";
  ASSERT_NE(port_alpha, 1u)
      << "role `alpha` role_idx=1 must not coincide with its port_id";
  ASSERT_NE(port_mike, 2u)
      << "role `mike` role_idx=2 must not coincide with its port_id";

  Config cfg = make_nonlex_config();

  // redirect -> alpha (role_idx=1, DPDK port_id=port_alpha=2).
  ActionTargetPort redir;
  redir.role_name = "alpha";
  auto& l4_redir = append_rule(cfg.pipeline.layer_4, 16012, redir);
  l4_redir.proto = 17;       // UDP
  l4_redir.dst_port = 4242;

  // mirror -> mike (role_idx=2, DPDK port_id=port_mike=0).
  ActionMirror mirror;
  mirror.role_name = "mike";
  auto& l4_mirror = append_rule(cfg.pipeline.layer_4, 16013, mirror);
  l4_mirror.proto = 17;
  l4_mirror.dst_port = 4243;

  // Compile pipeline. No RL slot allocator needed — neither rule is a
  // rate-limit verb. Same idiom as test_d41_guard.cpp's unit-path for
  // non-RL coverage.
  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value())
      << "compile() must accept redirect + mirror with resolvable roles";
  ASSERT_EQ(cr.l4_actions.size(), 2u);

  // Pre-populate sanity: CompiledAction still carries role_idx (the
  // semantic the compiler + D41 guard document and defend).
  ASSERT_EQ(cr.l4_actions[0].verb, ActionVerb::kRedirect);
  ASSERT_EQ(cr.l4_actions[1].verb, ActionVerb::kMirror);
  EXPECT_EQ(cr.l4_actions[0].redirect_port, 1u)
      << "compile() lowers role_idx to CompiledAction.redirect_port; "
         "`alpha` is declaration rank 1";
  EXPECT_EQ(cr.l4_actions[1].mirror_port, 2u)
      << "compile() lowers role_idx to CompiledAction.mirror_port; "
         "`mike` is declaration rank 2";

  // Build + populate.
  constexpr unsigned kNumLcores = 1;
  Ruleset rs = build_ruleset(cr, cfg.sizing, kNumLcores);
  ASSERT_GE(rs.n_l4_rules, 2u);

  EalPopulateParams params;
  params.name_prefix = "c3_5_u16_12";
  params.socket_id = 0;
  params.max_entries = 64;

  auto res = populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << "populate_ruleset_eal failed: " << res.error;

  // THE CORE RED ASSERTIONS — these flip GREEN once M16 C3.5 lands the
  // translation step in populate_ruleset_eal.
  //
  // On current tree both fail — populate_ruleset_eal does NOT walk
  // rs.l4_actions; RuleAction.redirect_port / mirror_port still carry
  // the pre-populate CompiledAction role_idx (1 and 2 respectively),
  // not the resolved DPDK port_ids (port_alpha=2 and port_mike=0).
  EXPECT_EQ(rs.l4_actions[0].redirect_port, port_alpha)
      << "post-populate redirect_port must hold the resolved DPDK "
         "port_id (rte_eth_tx_burst consumer), not the compiler "
         "role_idx. C3.5 fix: translate inside populate_ruleset_eal.";
  EXPECT_EQ(rs.l4_actions[1].mirror_port, port_mike)
      << "post-populate mirror_port must hold the resolved DPDK "
         "port_id (stage_mirror / rte_eth_tx_burst consumer), not "
         "the compiler role_idx. C3.5 fix: translate inside "
         "populate_ruleset_eal.";

  // Twin sentinel-preservation checks. These are belt-and-braces: a
  // buggy fix that clobbers the OTHER port field on a single-verb rule
  // would survive the core assertions above but break hot-path
  // dispatch elsewhere.
  EXPECT_EQ(rs.l4_actions[0].mirror_port, 0xFFFFu)
      << "redirect rule must keep mirror_port sentinel";
  EXPECT_EQ(rs.l4_actions[1].redirect_port, 0xFFFFu)
      << "mirror rule must keep redirect_port sentinel";
}

// =========================================================================
// U16.13 — redirect-only twin. Pins the M7 side of the regression
// independently of the mirror verb, so a GREEN-cycle fix that
// accidentally skips the redirect arm of the translation helper fails
// loudly. Same non-lex role layout; one REDIRECT rule to a role whose
// role_idx != port_id.
// =========================================================================
TEST_F(RolePortXlateFixture, RedirectOnlyTranslates_U16_13) {
  const std::uint16_t port_zulu  = port_id_of("net_null1");
  // Pin divergence for the one role this test uses.
  ASSERT_NE(port_zulu, 0u)
      << "role `zulu` role_idx=0 must not coincide with its port_id";

  Config cfg = make_nonlex_config();

  // redirect -> zulu (role_idx=0, DPDK port_id=port_zulu=1).
  ActionTargetPort redir;
  redir.role_name = "zulu";
  auto& l4_redir = append_rule(cfg.pipeline.layer_4, 16014, redir);
  l4_redir.proto = 6;        // TCP
  l4_redir.dst_port = 8080;

  CompileResult cr = compile(cfg);
  ASSERT_FALSE(cr.error.has_value());
  ASSERT_EQ(cr.l4_actions.size(), 1u);
  ASSERT_EQ(cr.l4_actions[0].verb, ActionVerb::kRedirect);
  EXPECT_EQ(cr.l4_actions[0].redirect_port, 0u)
      << "CompiledAction.redirect_port carries role_idx of `zulu` (0)";

  constexpr unsigned kNumLcores = 1;
  Ruleset rs = build_ruleset(cr, cfg.sizing, kNumLcores);
  ASSERT_GE(rs.n_l4_rules, 1u);

  EalPopulateParams params;
  params.name_prefix = "c3_5_u16_13";
  params.socket_id = 0;
  params.max_entries = 64;

  auto res = populate_ruleset_eal(rs, cr, params);
  ASSERT_TRUE(res.ok) << "populate_ruleset_eal failed: " << res.error;

  // Core RED assertion — fails on current tree (redirect_port == 0 =
  // role_idx), passes post-C3.5 (redirect_port == port_zulu == 1).
  EXPECT_EQ(rs.l4_actions[0].redirect_port, port_zulu)
      << "post-populate redirect_port must hold the resolved DPDK "
         "port_id. M7 regression class — precedent pre-dates mirror "
         "landing, surfaced by M16 C3.";
  EXPECT_EQ(rs.l4_actions[0].mirror_port, 0xFFFFu)
      << "REDIRECT verb must keep mirror_port sentinel unchanged by "
         "the translation step";
}

}  // namespace
