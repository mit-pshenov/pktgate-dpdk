// tests/unit/test_parser.cpp
//
// M1 C1 — top-level parser contract. Transcribes
// `test-plan-drafts/unit.md` U1.1 / U1.2 / U1.3 into real gtest code.
//
// Design notes (C1 scope only):
//   * Target: `libpktgate_core.a` → `pktgate::config::parse`.
//   * No EAL, no mempool, no DPDK includes — strictly pure-C++.
//   * The tests assert against the **contract** (a minimal valid doc
//     parses; version skew rejected with a specific ParseError::Kind;
//     unknown top-level field rejected with a specific kind). The
//     stub impl that ships in the same commit fails all three on
//     purpose (it always returns `kJsonSyntax`); GREEN replaces the
//     stub with a real walker.
//
// Covers: U1.1, U1.2, U1.3. D-refs: D8, D17/P9, Q11.

#include <gtest/gtest.h>

#include <string_view>
#include <variant>

#include "src/config/model.h"
#include "src/config/parser.h"

namespace {

using ::pktgate::config::Config;
using ::pktgate::config::DefaultBehavior;
using ::pktgate::config::err_kind;
using ::pktgate::config::FragmentPolicy;
using ::pktgate::config::get_err;
using ::pktgate::config::get_ok;
using ::pktgate::config::InterfaceRole;
using ::pktgate::config::is_ok;
using ::pktgate::config::parse;
using ::pktgate::config::ParseError;
using ::pktgate::config::ParseResult;
using ::pktgate::config::PciSelector;
using ::pktgate::config::RoleSelector;

// -------------------------------------------------------------------------
// JSON objects are semantically unordered (RFC 8259 §4), so the AST's
// per-role order is parser-defined, not spec. Tests that want to pin a
// specific role must look it up by name.
const InterfaceRole* find_role(const Config& cfg, std::string_view name) {
  for (const auto& r : cfg.interface_roles) {
    if (r.name == name) return &r;
  }
  return nullptr;
}

// -------------------------------------------------------------------------
// Minimal legal document used as the baseline for U1.1 and as the host
// for the negative-test mutations in U1.2 / U1.3.
//
// Exercises exactly the surface C1 implements:
//   * `version` = 1 (strict equality with kSchemaVersion)
//   * two PCI interface_roles (upstream / downstream)
//   * empty pipeline.layer_{2,3,4}
//   * `default_behavior: "drop"`
//   * no `fragment_policy` (must default to l3_only per D17/P9)
//
// Raw string literal so the JSON stays human-auditable in-place.

constexpr std::string_view kMinimalJson = R"json({
  "version": 1,
  "interface_roles": {
    "upstream_port":   { "pci": "0000:00:00.0" },
    "downstream_port": { "pci": "0000:00:00.1" }
  },
  "pipeline": {
    "layer_2": [],
    "layer_3": [],
    "layer_4": []
  },
  "default_behavior": "drop"
})json";

// -------------------------------------------------------------------------
// U1.1 — Valid minimal config parses and populates the documented
// defaults.

TEST(ParserU1_1, ValidMinimalConfigParses) {
  const ParseResult result = parse(kMinimalJson);

  ASSERT_TRUE(is_ok(result))
      << "minimal valid config rejected; err kind="
      << static_cast<int>(std::get<ParseError>(result).kind)
      << " msg=" << std::get<ParseError>(result).message;

  const Config& cfg = get_ok(result);

  EXPECT_EQ(cfg.version, ::pktgate::config::kSchemaVersion);
  ASSERT_EQ(cfg.interface_roles.size(), 2u);

  // Upstream role — PCI branch, canonical BDF. Looked up by name so
  // the assertion is independent of parser iteration order.
  const auto* upstream = find_role(cfg, "upstream_port");
  ASSERT_NE(upstream, nullptr);
  ASSERT_TRUE(std::holds_alternative<PciSelector>(upstream->selector));
  EXPECT_EQ(std::get<PciSelector>(upstream->selector).bdf, "0000:00:00.0");

  // Downstream role — same shape, different BDF.
  const auto* downstream = find_role(cfg, "downstream_port");
  ASSERT_NE(downstream, nullptr);
  ASSERT_TRUE(std::holds_alternative<PciSelector>(downstream->selector));
  EXPECT_EQ(std::get<PciSelector>(downstream->selector).bdf, "0000:00:00.1");

  EXPECT_EQ(cfg.default_behavior, DefaultBehavior::kDrop);

  // D17 / P9 default: fragment_policy absent from JSON but parser must
  // fill in l3_only.
  EXPECT_EQ(cfg.fragment_policy, FragmentPolicy::kL3Only);
}

// -------------------------------------------------------------------------
// U1.2 — `version` strict mismatch rejected. Covers both `0` (below the
// compiled-in version) and `999` (above it). In both cases:
//   * result is an error, not a Config
//   * error kind is kVersionMismatch (not kJsonSyntax, not kUnknownField)
//   * the message surfaces both expected and received versions, so an
//     operator reading the log can understand the skew at a glance

constexpr std::string_view kVersionZero = R"json({
  "version": 0,
  "interface_roles": {
    "upstream_port":   { "pci": "0000:00:00.0" },
    "downstream_port": { "pci": "0000:00:00.1" }
  },
  "pipeline": { "layer_2": [], "layer_3": [], "layer_4": [] },
  "default_behavior": "drop"
})json";

constexpr std::string_view kVersionFuture = R"json({
  "version": 999,
  "interface_roles": {
    "upstream_port":   { "pci": "0000:00:00.0" },
    "downstream_port": { "pci": "0000:00:00.1" }
  },
  "pipeline": { "layer_2": [], "layer_3": [], "layer_4": [] },
  "default_behavior": "drop"
})json";

TEST(ParserU1_2, VersionZeroRejected) {
  const ParseResult result = parse(kVersionZero);
  ASSERT_FALSE(is_ok(result));
  EXPECT_EQ(err_kind(result), ParseError::kVersionMismatch);

  const auto& msg = get_err(result).message;
  EXPECT_NE(msg.find("1"), std::string::npos)
      << "error message must name the expected version: " << msg;
  EXPECT_NE(msg.find("0"), std::string::npos)
      << "error message must name the received version: " << msg;
}

TEST(ParserU1_2, VersionFutureRejected) {
  const ParseResult result = parse(kVersionFuture);
  ASSERT_FALSE(is_ok(result));
  EXPECT_EQ(err_kind(result), ParseError::kVersionMismatch);

  const auto& msg = get_err(result).message;
  EXPECT_NE(msg.find("999"), std::string::npos)
      << "error message must name the received version: " << msg;
}

// -------------------------------------------------------------------------
// U1.3 — Unknown top-level field rejected. Strict-schema posture (D8):
// any top-level key not in the whitelist (version, interface_roles,
// pipeline, default_behavior, fragment_policy, sizing, objects — the
// last two land in later cycles but are already on the whitelist) is
// a hard fail.
//
// The assertion specifically pins `kUnknownField`, not `kJsonSyntax` —
// the JSON itself parses fine, the schema walker is the one that
// objects.

constexpr std::string_view kUnknownField = R"json({
  "foo": 42,
  "version": 1,
  "interface_roles": {
    "upstream_port":   { "pci": "0000:00:00.0" },
    "downstream_port": { "pci": "0000:00:00.1" }
  },
  "pipeline": { "layer_2": [], "layer_3": [], "layer_4": [] },
  "default_behavior": "drop"
})json";

TEST(ParserU1_3, UnknownTopLevelFieldRejected) {
  const ParseResult result = parse(kUnknownField);
  ASSERT_FALSE(is_ok(result));
  EXPECT_EQ(err_kind(result), ParseError::kUnknownField);

  // The error message should name the offending key so an operator
  // editing JSON can jump straight to it.
  EXPECT_NE(get_err(result).message.find("foo"), std::string::npos)
      << "error message must name the offending key: "
      << get_err(result).message;
}

}  // namespace
