// tests/unit/test_budget_corners.cpp
//
// M1 C11 — D37 budget pre-flight corner cases (boundary conditions).
//
// Six tests: C7.4..C7.9 from corner.md. These exercise the exact
// boundary (just-fits vs overflows-by-one) for all three D37 gates:
//
//   Gate 1 — per-rule expansion ceiling (kDefaultPerRuleCeiling = 4096)
//   Gate 2 — aggregate L4 expansion vs sizing.l4_entries_max
//   Gate 3 — expected_ruleset_bytes vs HugepageProbe available_bytes
//
// These are unit-tier tests (no telemetry, no reload wiring — that's
// M10). The label is BOTH `unit` AND `corner` so that `ctest -L corner`
// picks them up alongside future scapy-pytest corner tests.
//
// Target: `libpktgate_core.a` → `pktgate::config::validate_budget`.
// No EAL, no mempool, no DPDK includes — strictly pure-C++.
//
// Covers: D37.

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <variant>
#include <vector>

#include "src/config/model.h"
#include "src/config/sizing.h"
#include "src/config/validator.h"

namespace {

using ::pktgate::config::Config;
using ::pktgate::config::HugepageInfo;
using ::pktgate::config::HugepageProbe;
using ::pktgate::config::kDefaultPerRuleCeiling;
using ::pktgate::config::ValidateError;
using ::pktgate::config::ValidateOk;
using ::pktgate::config::ValidateResult;
using ::pktgate::config::expected_ruleset_bytes;
using ::pktgate::config::validate_budget;

inline bool v_is_ok(const ValidateResult& r) noexcept {
  return std::holds_alternative<ValidateOk>(r);
}
inline const ValidateError& v_get_err(const ValidateResult& r) {
  return std::get<ValidateError>(r);
}

// Build a Config with N L4 rules, each having `ports_per_rule` entries
// in dst_ports. Reuses the same pattern as C10's make_budget_config_l4.
Config make_budget_config_l4(std::size_t n_rules,
                             std::size_t ports_per_rule,
                             ::pktgate::config::Sizing sizing) {
  Config cfg;
  cfg.version = ::pktgate::config::kSchemaVersion;
  cfg.default_behavior = ::pktgate::config::DefaultBehavior::kDrop;
  cfg.sizing = sizing;

  cfg.interface_roles.push_back(
      {"upstream_port", ::pktgate::config::PciSelector{"0000:00:00.0"}});
  cfg.interface_roles.push_back(
      {"downstream_port", ::pktgate::config::PciSelector{"0000:00:00.1"}});

  for (std::size_t i = 0; i < n_rules; ++i) {
    ::pktgate::config::Rule r;
    r.id = static_cast<std::int32_t>(i + 1);
    r.dst_ports.reserve(ports_per_rule);
    for (std::size_t p = 0; p < ports_per_rule; ++p) {
      r.dst_ports.push_back(static_cast<std::int32_t>(p));
    }
    cfg.pipeline.layer_4.push_back(std::move(r));
  }
  return cfg;
}

// Build a Config with heterogeneous L4 rules (different per-rule port counts).
Config make_budget_config_l4_heterogeneous(
    const std::vector<std::size_t>& ports_per_rule,
    ::pktgate::config::Sizing sizing) {
  Config cfg;
  cfg.version = ::pktgate::config::kSchemaVersion;
  cfg.default_behavior = ::pktgate::config::DefaultBehavior::kDrop;
  cfg.sizing = sizing;

  cfg.interface_roles.push_back(
      {"upstream_port", ::pktgate::config::PciSelector{"0000:00:00.0"}});
  cfg.interface_roles.push_back(
      {"downstream_port", ::pktgate::config::PciSelector{"0000:00:00.1"}});

  for (std::size_t i = 0; i < ports_per_rule.size(); ++i) {
    ::pktgate::config::Rule r;
    r.id = static_cast<std::int32_t>(i + 1);
    r.dst_ports.reserve(ports_per_rule[i]);
    for (std::size_t p = 0; p < ports_per_rule[i]; ++p) {
      r.dst_ports.push_back(static_cast<std::int32_t>(p));
    }
    cfg.pipeline.layer_4.push_back(std::move(r));
  }
  return cfg;
}

// Generous hugepage probe that never triggers gate 3.
HugepageProbe generous_probe() {
  return [] { return HugepageInfo{1024ULL * 1024 * 1024}; };  // 1 GiB
}

// Exact hugepage probe for gate 3 boundary testing.
HugepageProbe exact_probe(std::size_t bytes) {
  return [bytes] { return HugepageInfo{bytes}; };
}

// =========================================================================
// C7.4 — D37 per-rule ceiling just-fits.
//
// Config: one L4 rule with `dst_port` expanding to exactly 4096
// entries (== kDefaultPerRuleCeiling). Gate 1 uses a strict `>` check,
// so exactly-at-ceiling must pass.
//
// Assert: validate_budget() returns success.
// Covers: D37.
// =========================================================================

TEST(BudgetCornerC7_4, PerRuleCeilingJustFits) {
  auto sizing = ::pktgate::config::kSizingProdDefaults;
  // Aggregate ceiling must be >= per-rule to avoid gate 2 firing.
  sizing.l4_entries_max = static_cast<std::uint32_t>(kDefaultPerRuleCeiling);

  const Config cfg = make_budget_config_l4(/*n_rules=*/1,
                                           /*ports_per_rule=*/kDefaultPerRuleCeiling,
                                           sizing);
  const ValidateResult vr = validate_budget(cfg, generous_probe());

  ASSERT_TRUE(v_is_ok(vr))
      << "validate_budget rejected a rule expanding to exactly "
      << kDefaultPerRuleCeiling
      << " entries (ceiling boundary — must pass); kind="
      << static_cast<int>(v_get_err(vr).kind)
      << " msg=" << v_get_err(vr).message;
}

// =========================================================================
// C7.5 — D37 per-rule ceiling overflows.
//
// Config: one L4 rule expanding to 4097 entries (one above ceiling).
// Gate 1 fires.
//
// Assert: validate_budget() returns error with kBudgetPerRuleExceeded.
// Covers: D37.
// =========================================================================

TEST(BudgetCornerC7_5, PerRuleCeilingOverflows) {
  const std::size_t overflow = kDefaultPerRuleCeiling + 1;  // 4097
  auto sizing = ::pktgate::config::kSizingProdDefaults;
  sizing.l4_entries_max = 100'000;  // generous aggregate

  const Config cfg = make_budget_config_l4(/*n_rules=*/1,
                                           /*ports_per_rule=*/overflow,
                                           sizing);
  const ValidateResult vr = validate_budget(cfg, generous_probe());

  ASSERT_FALSE(v_is_ok(vr))
      << "validate_budget accepted a rule expanding to " << overflow
      << " entries (ceiling is " << kDefaultPerRuleCeiling << ")";
  EXPECT_EQ(v_get_err(vr).kind, ValidateError::kBudgetPerRuleExceeded);
  const auto& msg = v_get_err(vr).message;
  EXPECT_NE(msg.find(std::to_string(overflow)), std::string::npos)
      << "error message must report the expansion count: " << msg;
  EXPECT_NE(msg.find("gate 1"), std::string::npos)
      << "error message should identify gate 1 (per-rule ceiling): " << msg;
}

// =========================================================================
// C7.6 — D37 aggregate ceiling just-fits.
//
// Config: N rules summing to exactly l4_entries_max post-expansion.
// Each individual rule stays at or below kDefaultPerRuleCeiling so
// gate 1 doesn't fire.
//
// Strategy: l4_entries_max = 4096. Use 4 rules × 1024 ports = 4096.
// Each rule (1024) is well under the per-rule ceiling (4096).
//
// Assert: validate_budget() returns success.
// Covers: D37.
// =========================================================================

TEST(BudgetCornerC7_6, AggregateCeilingJustFits) {
  auto sizing = ::pktgate::config::kSizingProdDefaults;
  sizing.l4_entries_max = 4096;

  // 4 rules × 1024 ports = 4096 total = l4_entries_max exactly.
  const Config cfg = make_budget_config_l4(/*n_rules=*/4,
                                           /*ports_per_rule=*/1024,
                                           sizing);
  const ValidateResult vr = validate_budget(cfg, generous_probe());

  ASSERT_TRUE(v_is_ok(vr))
      << "validate_budget rejected aggregate expansion 4×1024=4096 "
         "(== l4_entries_max=4096, should just-fit); kind="
      << static_cast<int>(v_get_err(vr).kind)
      << " msg=" << v_get_err(vr).message;
}

// =========================================================================
// C7.7 — D37 aggregate ceiling overflows.
//
// Config: N rules summing to l4_entries_max + 1 post-expansion.
// Each individual rule stays under per-rule ceiling so gate 1 doesn't
// fire first.
//
// Strategy: l4_entries_max = 4096. Use 4 rules: 3 × 1024 + 1 × 1025 =
// 4097 total. Each rule (max 1025) is under per-rule ceiling (4096).
//
// Assert: validate_budget() returns error with kBudgetAggregateExceeded.
// Covers: D37.
// =========================================================================

TEST(BudgetCornerC7_7, AggregateCeilingOverflows) {
  auto sizing = ::pktgate::config::kSizingProdDefaults;
  sizing.l4_entries_max = 4096;

  // 3 × 1024 + 1 × 1025 = 4097 = l4_entries_max + 1.
  const Config cfg = make_budget_config_l4_heterogeneous(
      {1024, 1024, 1024, 1025}, sizing);
  const ValidateResult vr = validate_budget(cfg, generous_probe());

  ASSERT_FALSE(v_is_ok(vr))
      << "validate_budget accepted aggregate expansion 4097 > l4_entries_max=4096";
  EXPECT_EQ(v_get_err(vr).kind, ValidateError::kBudgetAggregateExceeded);
  const auto& msg = v_get_err(vr).message;
  EXPECT_NE(msg.find("4097"), std::string::npos)
      << "error message must report aggregate expansion sum: " << msg;
}

// =========================================================================
// C7.8 — D37 hugepage budget just-fits.
//
// Config: a ruleset whose expected_ruleset_bytes equals available
// hugepages exactly. Gate 3 uses a strict `>` check, so exact-fit
// must pass.
//
// Strategy: build a small config, compute expected_ruleset_bytes() on
// it, then set the hugepage probe to return exactly that many bytes.
//
// Assert: validate_budget() returns success.
// Covers: D37.
// =========================================================================

TEST(BudgetCornerC7_8, HugepageBudgetJustFits) {
  auto sizing = ::pktgate::config::kSizingProdDefaults;
  sizing.l4_entries_max = 100'000;

  // 10 rules × 100 ports = 1000 L4 entries.
  const Config cfg = make_budget_config_l4(/*n_rules=*/10,
                                           /*ports_per_rule=*/100,
                                           sizing);

  // Compute the exact expected footprint.
  const std::size_t estimated = expected_ruleset_bytes(cfg);
  ASSERT_GT(estimated, 0u) << "precondition: estimated bytes must be > 0";

  // Set hugepage probe to return exactly the estimated bytes.
  const ValidateResult vr = validate_budget(cfg, exact_probe(estimated));

  ASSERT_TRUE(v_is_ok(vr))
      << "validate_budget rejected a config whose estimated footprint ("
      << estimated << " bytes) exactly equals available hugepages; kind="
      << static_cast<int>(v_get_err(vr).kind)
      << " msg=" << v_get_err(vr).message;
}

// =========================================================================
// C7.9 — D37 hugepage budget overflows.
//
// Config: expected_ruleset_bytes > available hugepages (by 1 byte).
//
// Strategy: same config as C7.8, but set available_bytes to
// expected_ruleset_bytes - 1.
//
// Assert: validate_budget() returns error with kBudgetHugepage.
// Covers: D37.
// =========================================================================

TEST(BudgetCornerC7_9, HugepageBudgetOverflows) {
  auto sizing = ::pktgate::config::kSizingProdDefaults;
  sizing.l4_entries_max = 100'000;

  // 10 rules × 100 ports = 1000 L4 entries.
  const Config cfg = make_budget_config_l4(/*n_rules=*/10,
                                           /*ports_per_rule=*/100,
                                           sizing);

  const std::size_t estimated = expected_ruleset_bytes(cfg);
  ASSERT_GT(estimated, 1u) << "precondition: need at least 2 bytes to underflow by 1";

  // Set hugepage probe to return one byte less than needed.
  const ValidateResult vr = validate_budget(cfg, exact_probe(estimated - 1));

  ASSERT_FALSE(v_is_ok(vr))
      << "validate_budget accepted a config whose estimated footprint ("
      << estimated << " bytes) exceeds available hugepages ("
      << (estimated - 1) << " bytes)";
  EXPECT_EQ(v_get_err(vr).kind, ValidateError::kBudgetHugepage);
  const auto& msg = v_get_err(vr).message;
  EXPECT_NE(msg.find(std::to_string(estimated)), std::string::npos)
      << "error message must report estimated footprint: " << msg;
  EXPECT_NE(msg.find(std::to_string(estimated - 1)), std::string::npos)
      << "error message must report available hugepages: " << msg;
}

}  // namespace
