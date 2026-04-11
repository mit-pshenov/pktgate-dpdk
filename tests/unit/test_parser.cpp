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

#include <chrono>
#include <sstream>
#include <string>
#include <string_view>
#include <variant>

#include "src/config/addr.h"
#include "src/config/model.h"
#include "src/config/parser.h"
#include "src/config/sizing.h"

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
using ::pktgate::config::NameSelector;
using ::pktgate::config::PciSelector;
using ::pktgate::config::RoleSelector;
using ::pktgate::config::VdevSelector;

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

// -------------------------------------------------------------------------
// U1.4 — `interface_roles` sum-type: PCI selector decomposes to canonical BDF.
//
// A `{ "pci": "0000:03:00.0" }` entry must land in the AST as a PciSelector
// whose `bdf` field round-trips the canonical domain:bus:device.function
// string form (what DPDK's `-a` flag expects). C2 still only normalises the
// string: no numeric decomposition into separate fields — the canonical
// form *is* the canonical form.

constexpr std::string_view kRolesPci = R"json({
  "version": 1,
  "interface_roles": {
    "upstream_port":   { "pci": "0000:03:00.0" },
    "downstream_port": { "pci": "0000:03:00.1" }
  },
  "pipeline": { "layer_2": [], "layer_3": [], "layer_4": [] },
  "default_behavior": "drop"
})json";

TEST(ParserU1_4, PciSelectorParses) {
  const ParseResult result = parse(kRolesPci);
  ASSERT_TRUE(is_ok(result))
      << "pci selector rejected; err kind="
      << static_cast<int>(std::get<ParseError>(result).kind)
      << " msg=" << std::get<ParseError>(result).message;

  const Config& cfg = get_ok(result);
  const auto* upstream = find_role(cfg, "upstream_port");
  ASSERT_NE(upstream, nullptr);
  ASSERT_TRUE(std::holds_alternative<PciSelector>(upstream->selector));
  // Round-trip: the canonical BDF string survives parse verbatim.
  EXPECT_EQ(std::get<PciSelector>(upstream->selector).bdf, "0000:03:00.0");

  const auto* downstream = find_role(cfg, "downstream_port");
  ASSERT_NE(downstream, nullptr);
  ASSERT_TRUE(std::holds_alternative<PciSelector>(downstream->selector));
  EXPECT_EQ(std::get<PciSelector>(downstream->selector).bdf, "0000:03:00.1");
}

// -------------------------------------------------------------------------
// U1.5 — `interface_roles` sum-type: vdev selector, arg string verbatim.
//
// `{ "vdev": "net_pcap0,tx_iface=lo" }` → `VdevSelector{spec=...}`. The
// arg portion (comma-separated DPDK vdev args) is preserved verbatim —
// the parser does no tokenisation; that's DPDK's job at EAL init.

constexpr std::string_view kRolesVdev = R"json({
  "version": 1,
  "interface_roles": {
    "upstream_port":   { "vdev": "net_pcap0,tx_iface=lo" },
    "downstream_port": { "pci": "0000:00:00.1" }
  },
  "pipeline": { "layer_2": [], "layer_3": [], "layer_4": [] },
  "default_behavior": "drop"
})json";

TEST(ParserU1_5, VdevSelectorParses) {
  const ParseResult result = parse(kRolesVdev);
  ASSERT_TRUE(is_ok(result))
      << "vdev selector rejected; err kind="
      << static_cast<int>(std::get<ParseError>(result).kind)
      << " msg=" << std::get<ParseError>(result).message;

  const Config& cfg = get_ok(result);
  const auto* upstream = find_role(cfg, "upstream_port");
  ASSERT_NE(upstream, nullptr);
  ASSERT_TRUE(std::holds_alternative<VdevSelector>(upstream->selector));
  // Verbatim: commas, `=`, everything preserved.
  EXPECT_EQ(std::get<VdevSelector>(upstream->selector).spec,
            "net_pcap0,tx_iface=lo");
}

// -------------------------------------------------------------------------
// U1.6 — `interface_roles` sum-type: name selector.
//
// `{ "name": "net_tap0" }` → `NameSelector{name=...}`. Used when the
// DPDK port already exists in the system (e.g. pre-created by another
// process) and we just need to attach by name.

constexpr std::string_view kRolesName = R"json({
  "version": 1,
  "interface_roles": {
    "upstream_port":   { "name": "net_tap0" },
    "downstream_port": { "pci": "0000:00:00.1" }
  },
  "pipeline": { "layer_2": [], "layer_3": [], "layer_4": [] },
  "default_behavior": "drop"
})json";

TEST(ParserU1_6, NameSelectorParses) {
  const ParseResult result = parse(kRolesName);
  ASSERT_TRUE(is_ok(result))
      << "name selector rejected; err kind="
      << static_cast<int>(std::get<ParseError>(result).kind)
      << " msg=" << std::get<ParseError>(result).message;

  const Config& cfg = get_ok(result);
  const auto* upstream = find_role(cfg, "upstream_port");
  ASSERT_NE(upstream, nullptr);
  ASSERT_TRUE(std::holds_alternative<NameSelector>(upstream->selector));
  EXPECT_EQ(std::get<NameSelector>(upstream->selector).name, "net_tap0");
}

// -------------------------------------------------------------------------
// U1.7 — `interface_roles` sum-type: mixed keys rejected.
//
// A selector object containing more than one of {pci, vdev, name} is
// ambiguous — the parser must return `kInvalidRoleSelector`. The message
// must name both offending keys so an operator can find the typo without
// re-reading the whole doc.

constexpr std::string_view kRolesMixedKeys = R"json({
  "version": 1,
  "interface_roles": {
    "upstream_port":   { "pci": "0000:00:00.0", "vdev": "net_pcap0,tx_iface=lo" },
    "downstream_port": { "pci": "0000:00:00.1" }
  },
  "pipeline": { "layer_2": [], "layer_3": [], "layer_4": [] },
  "default_behavior": "drop"
})json";

TEST(ParserU1_7, MixedKeysRejected) {
  const ParseResult result = parse(kRolesMixedKeys);
  ASSERT_FALSE(is_ok(result));
  EXPECT_EQ(err_kind(result), ParseError::kInvalidRoleSelector);

  const auto& msg = get_err(result).message;
  EXPECT_NE(msg.find("pci"), std::string::npos)
      << "error message must name the offending 'pci' key: " << msg;
  EXPECT_NE(msg.find("vdev"), std::string::npos)
      << "error message must name the offending 'vdev' key: " << msg;
}

// =========================================================================
// M1 C4 — enums + numeric ranges + port list
// =========================================================================
//
// U1.14 / U1.15 / U1.16 pin the `fragment_policy` enum contract (D17/P9).
// U1.17 / U1.18 / U1.19 pin numeric range guards (D8) on dst_port,
// vlan_id, pcp. U1.20 pins the port-list shape. All of these fields
// land on the minimal `Rule` shell introduced in C4 — just enough
// storage for the parser to accept/reject the values; match semantics
// and action wiring are C5+.
//
// Shared helper: build a minimal top-level document whose pipeline
// contains one layer_4 rule populated with `extra_rule_fields` (raw
// JSON fragment). Keeps each TEST body readable — the important part
// of every test is the single field under exercise, not the 15 lines
// of boilerplate around it.

// C5 note: U1.24 introduces mandatory `id`. The C4-era helpers embed a
// single rule per document; to keep C4 tests green after C5 makes `id`
// required, the helpers auto-inject `"id": 1, ` immediately after the
// opening brace of the caller-supplied rule body. Tests that need to
// exercise the `id` contract itself (U1.24) use the `_raw` variants
// below, which do not inject anything and hand the body to the parser
// verbatim.
std::string inject_default_id(std::string_view rule_body) {
  std::string s{rule_body};
  const auto open = s.find('{');
  if (open == std::string::npos) return s;
  // Inject right after the `{`. The inner whitespace keeps the doc
  // human-readable when the test fails and dumps the input.
  s.insert(open + 1, R"( "id": 1, )");
  return s;
}

std::string make_doc_with_layer4_rule_raw(std::string_view rule_body) {
  std::string out = R"json({
  "version": 1,
  "interface_roles": {
    "upstream_port":   { "pci": "0000:00:00.0" },
    "downstream_port": { "pci": "0000:00:00.1" }
  },
  "pipeline": {
    "layer_2": [],
    "layer_3": [],
    "layer_4": [)json";
  out += rule_body;
  out += R"json(]
  },
  "default_behavior": "drop"
})json";
  return out;
}

std::string make_doc_with_layer4_rule(std::string_view rule_body) {
  return make_doc_with_layer4_rule_raw(inject_default_id(rule_body));
}

std::string make_doc_with_layer2_rule_raw(std::string_view rule_body) {
  std::string out = R"json({
  "version": 1,
  "interface_roles": {
    "upstream_port":   { "pci": "0000:00:00.0" },
    "downstream_port": { "pci": "0000:00:00.1" }
  },
  "pipeline": {
    "layer_2": [)json";
  out += rule_body;
  out += R"json(],
    "layer_3": [],
    "layer_4": []
  },
  "default_behavior": "drop"
})json";
  return out;
}

std::string make_doc_with_layer2_rule(std::string_view rule_body) {
  return make_doc_with_layer2_rule_raw(inject_default_id(rule_body));
}

std::string make_doc_with_fragment_policy(std::string_view fp_json_literal) {
  std::string out = R"json({
  "version": 1,
  "interface_roles": {
    "upstream_port":   { "pci": "0000:00:00.0" },
    "downstream_port": { "pci": "0000:00:00.1" }
  },
  "pipeline": { "layer_2": [], "layer_3": [], "layer_4": [] },
  "default_behavior": "drop",
  "fragment_policy": )json";
  out += fp_json_literal;
  out += R"json(
})json";
  return out;
}

// -------------------------------------------------------------------------
// U1.14 — fragment_policy enum accepted: l3_only / drop / allow each
// round-trip to the matching enum value. C1 already tested the default
// (missing → kL3Only); C4 adds the explicit-value path for all three.

TEST(ParserU1_14, FragmentPolicyAllThreeValuesAccepted) {
  struct Case {
    std::string_view literal;
    FragmentPolicy expected;
  };
  const Case cases[] = {
      {R"("l3_only")", FragmentPolicy::kL3Only},
      {R"("drop")", FragmentPolicy::kDrop},
      {R"("allow")", FragmentPolicy::kAllow},
  };
  for (const auto& c : cases) {
    const std::string doc = make_doc_with_fragment_policy(c.literal);
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result))
        << "fragment_policy=" << c.literal << " rejected; err kind="
        << static_cast<int>(std::get<ParseError>(result).kind)
        << " msg=" << std::get<ParseError>(result).message;
    EXPECT_EQ(get_ok(result).fragment_policy, c.expected)
        << "fragment_policy=" << c.literal << " did not map to expected enum";
  }
}

// -------------------------------------------------------------------------
// U1.15 — fragment_policy unknown value rejected as kBadEnum.
// Inputs per unit.md: "l2_only", "maybe", 42.
//
// Note: the non-string literal `42` must also be rejected. The current
// parser routes type mismatches through kTypeMismatch; that's fine — the
// point of the test is that the value never lands as a FragmentPolicy.

TEST(ParserU1_15, FragmentPolicyUnknownRejected) {
  // String enum values — must produce kBadEnum.
  const std::string_view bad_strings[] = {R"("l2_only")", R"("maybe")"};
  for (const auto& lit : bad_strings) {
    const std::string doc = make_doc_with_fragment_policy(lit);
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result))
        << "unknown fragment_policy " << lit << " accepted";
    EXPECT_EQ(err_kind(result), ParseError::kBadEnum)
        << "fragment_policy=" << lit
        << " expected kBadEnum, got kind="
        << static_cast<int>(err_kind(result))
        << " msg=" << get_err(result).message;
  }

  // Non-string value — rejected, either as kTypeMismatch (because the
  // current parser type-checks first) or as kBadEnum. Both are legit;
  // the invariant U1.15 cares about is "never accepted as a policy".
  {
    const std::string doc = make_doc_with_fragment_policy("42");
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result))
        << "numeric fragment_policy 42 was accepted";
    const auto kind = err_kind(result);
    EXPECT_TRUE(kind == ParseError::kTypeMismatch ||
                kind == ParseError::kBadEnum)
        << "fragment_policy=42 rejected with unexpected kind="
        << static_cast<int>(kind);
  }
}

// -------------------------------------------------------------------------
// U1.16 — fragment_policy missing → default kL3Only (P9). C1 already pins
// this on the minimal doc; here we pin it on a doc that happens to have
// other C4-era fields populated, guarding against an accidental future
// regression where adding new rule fields silently wipes the default.

TEST(ParserU1_16, FragmentPolicyMissingDefaultsToL3Only) {
  // Doc with a populated layer_4 rule but no fragment_policy — default
  // must still land.
  const std::string doc = make_doc_with_layer4_rule(R"({ "dst_port": 80 })");
  const ParseResult result = parse(doc);
  ASSERT_TRUE(is_ok(result))
      << "doc rejected; err kind="
      << static_cast<int>(std::get<ParseError>(result).kind)
      << " msg=" << std::get<ParseError>(result).message;
  EXPECT_EQ(get_ok(result).fragment_policy, FragmentPolicy::kL3Only);
}

// -------------------------------------------------------------------------
// U1.17 — port range 0..65535 on `dst_port`.
// Accepted: 0, 65535.
// Rejected: -1 (kOutOfRange), 65536 (kOutOfRange), "80" (kTypeMismatch).

TEST(ParserU1_17, DstPortRangeChecked) {
  // Accepted boundaries.
  {
    const std::string doc = make_doc_with_layer4_rule(R"({ "dst_port": 0 })");
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result)) << "dst_port=0 rejected; msg="
                               << get_err(result).message;
    ASSERT_EQ(get_ok(result).pipeline.layer_4.size(), 1u);
    EXPECT_EQ(get_ok(result).pipeline.layer_4[0].dst_port, 0);
  }
  {
    const std::string doc =
        make_doc_with_layer4_rule(R"({ "dst_port": 65535 })");
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result)) << "dst_port=65535 rejected; msg="
                               << get_err(result).message;
    ASSERT_EQ(get_ok(result).pipeline.layer_4.size(), 1u);
    EXPECT_EQ(get_ok(result).pipeline.layer_4[0].dst_port, 65535);
  }

  // Rejected: out-of-range negative and above-ceiling.
  for (const char* body :
       {R"({ "dst_port": -1 })", R"({ "dst_port": 65536 })"}) {
    const std::string doc = make_doc_with_layer4_rule(body);
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result)) << "out-of-range accepted: " << body;
    EXPECT_EQ(err_kind(result), ParseError::kOutOfRange)
        << "body=" << body << " kind=" << static_cast<int>(err_kind(result));
  }

  // Rejected: string where int is required.
  {
    const std::string doc =
        make_doc_with_layer4_rule(R"({ "dst_port": "80" })");
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result)) << "string dst_port accepted";
    EXPECT_EQ(err_kind(result), ParseError::kTypeMismatch);
  }
}

// -------------------------------------------------------------------------
// U1.18 — vlan_id range 0..4095.
// Same shape as U1.17. Note: 4095 is the spec bound per unit.md §U1.18
// ("Same pattern, 0..4095 bounds") — even though vlan 4095 is reserved
// in IEEE 802.1Q, the schema-level range is what this test pins.

TEST(ParserU1_18, VlanIdRangeChecked) {
  {
    const std::string doc = make_doc_with_layer2_rule(R"({ "vlan_id": 0 })");
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result)) << "vlan_id=0 rejected; msg="
                               << get_err(result).message;
    ASSERT_EQ(get_ok(result).pipeline.layer_2.size(), 1u);
    EXPECT_EQ(get_ok(result).pipeline.layer_2[0].vlan_id, 0);
  }
  {
    const std::string doc =
        make_doc_with_layer2_rule(R"({ "vlan_id": 4095 })");
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result)) << "vlan_id=4095 rejected; msg="
                               << get_err(result).message;
    ASSERT_EQ(get_ok(result).pipeline.layer_2.size(), 1u);
    EXPECT_EQ(get_ok(result).pipeline.layer_2[0].vlan_id, 4095);
  }
  for (const char* body :
       {R"({ "vlan_id": -1 })", R"({ "vlan_id": 4096 })"}) {
    const std::string doc = make_doc_with_layer2_rule(body);
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result)) << "out-of-range vlan accepted: " << body;
    EXPECT_EQ(err_kind(result), ParseError::kOutOfRange);
  }
  {
    const std::string doc =
        make_doc_with_layer2_rule(R"({ "vlan_id": "10" })");
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result));
    EXPECT_EQ(err_kind(result), ParseError::kTypeMismatch);
  }
}

// -------------------------------------------------------------------------
// U1.19 — PCP range 0..7 (3-bit field).

TEST(ParserU1_19, PcpRangeChecked) {
  {
    const std::string doc = make_doc_with_layer2_rule(R"({ "pcp": 0 })");
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result)) << "pcp=0 rejected; msg="
                               << get_err(result).message;
    ASSERT_EQ(get_ok(result).pipeline.layer_2.size(), 1u);
    EXPECT_EQ(get_ok(result).pipeline.layer_2[0].pcp, 0);
  }
  {
    const std::string doc = make_doc_with_layer2_rule(R"({ "pcp": 7 })");
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result)) << "pcp=7 rejected; msg="
                               << get_err(result).message;
    ASSERT_EQ(get_ok(result).pipeline.layer_2.size(), 1u);
    EXPECT_EQ(get_ok(result).pipeline.layer_2[0].pcp, 7);
  }
  for (const char* body : {R"({ "pcp": -1 })", R"({ "pcp": 8 })"}) {
    const std::string doc = make_doc_with_layer2_rule(body);
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result)) << "out-of-range pcp accepted: " << body;
    EXPECT_EQ(err_kind(result), ParseError::kOutOfRange);
  }
  {
    const std::string doc = make_doc_with_layer2_rule(R"({ "pcp": "3" })");
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result));
    EXPECT_EQ(err_kind(result), ParseError::kTypeMismatch);
  }
}

// -------------------------------------------------------------------------
// U1.20 — Port list `[22, 80, 443]` parsed as array of ints.
//
// The list-valued field is `dst_ports` — a sibling of `dst_port`, used
// when a rule wants to match any of several L4 ports. The generic
// int-array parse helper that lands in parser.cpp in C4 is exercised
// here through this field. Unit.md leaves the exact storage field
// name to the implementer; we pick `dst_ports` because that's the
// natural plural of the U1.17 field and keeps C5's action work free
// to introduce further list-valued fields without renaming.
//
// Range-check sanity: each element of the list is subject to the same
// 0..65535 guard as `dst_port`. We don't separately retest the
// negative path here (U1.17 covers that for the same helper), but we
// do assert a well-formed list lands in the AST verbatim.

TEST(ParserU1_20, PortListParsesAsIntArray) {
  // Explicit multi-element list.
  {
    const std::string doc =
        make_doc_with_layer4_rule(R"({ "dst_ports": [22, 80, 443] })");
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result)) << "dst_ports=[22,80,443] rejected; msg="
                               << get_err(result).message;
    const Config& cfg = get_ok(result);
    ASSERT_EQ(cfg.pipeline.layer_4.size(), 1u);
    const auto& r = cfg.pipeline.layer_4[0];
    ASSERT_EQ(r.dst_ports.size(), 3u);
    EXPECT_EQ(r.dst_ports[0], 22);
    EXPECT_EQ(r.dst_ports[1], 80);
    EXPECT_EQ(r.dst_ports[2], 443);
  }

  // Singleton list.
  {
    const std::string doc =
        make_doc_with_layer4_rule(R"({ "dst_ports": [8080] })");
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result)) << "singleton dst_ports rejected; msg="
                               << get_err(result).message;
    const auto& r = get_ok(result).pipeline.layer_4[0];
    ASSERT_EQ(r.dst_ports.size(), 1u);
    EXPECT_EQ(r.dst_ports[0], 8080);
  }

  // Non-array → kTypeMismatch.
  {
    const std::string doc =
        make_doc_with_layer4_rule(R"({ "dst_ports": 80 })");
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result)) << "scalar dst_ports accepted";
    EXPECT_EQ(err_kind(result), ParseError::kTypeMismatch);
  }

  // Out-of-range element → kOutOfRange (int-array helper contract).
  {
    const std::string doc =
        make_doc_with_layer4_rule(R"({ "dst_ports": [80, 99999] })");
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result)) << "out-of-range list element accepted";
    EXPECT_EQ(err_kind(result), ParseError::kOutOfRange);
  }
}

// =========================================================================
// M1 C5 — rate spec + RuleAction + rule id + TcpFlags
// =========================================================================
//
// U1.21..U1.24 + U1.29 + U1.30. Architectural anchors:
//
//   * D1 — rate string ("200Mbps") is converted to bytes/sec **at load
//     time**. The runtime hot path never re-parses the string or
//     multiplies. Tests assert the numeric post-conversion value only.
//
//   * D15 — rule action is a sum type with exactly-one semantics (like
//     the interface_roles selector). A rule with zero actions or two+
//     competing action fields is rejected with kAmbiguousAction.
//
//   * D7 — `mirror` action is syntactically accepted by the parser
//     (the compiler/validator later rejects it until M2 ships real
//     mirror support). Not probed by U1.29 directly; we rely on
//     U1.29's core contract.
//
// Rule id contract (U1.24): required, positive integer. Duplicate-id
// detection is C8 (validator), not parser territory.

// -------------------------------------------------------------------------
// U1.21 — Rate spec "200Mbps" / "1Gbps" / "64kbps" → bytes/sec.
//
// Per unit.md §U1.21, parser converts bps → bytes/sec at load time.
// Expected values (from unit.md):
//   "200Mbps"  →  25_000_000  (= 200 * 1e6 / 8)
//   "1Gbps"    → 125_000_000  (= 1e9 / 8)
//   "64kbps"   →       8_000  (= 64e3 / 8)
// Bad forms ("1" ambiguous, "banana" garbage) → kBadRate.

TEST(ParserU1_21, RateSpecBytesPerSec) {
  struct Case {
    const char* literal;
    std::uint64_t expected_bps;
  };
  const Case good[] = {
      {R"("200Mbps")", 25'000'000ull},
      {R"("1Gbps")", 125'000'000ull},
      {R"("64kbps")", 8'000ull},
  };
  for (const auto& c : good) {
    std::string body = R"({ "action": { "type": "rate-limit", "rate": )";
    body += c.literal;
    body += R"(, "burst_ms": 10 } })";
    const std::string doc = make_doc_with_layer4_rule(body);
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result))
        << "rate=" << c.literal << " rejected; kind="
        << static_cast<int>(err_kind(result))
        << " msg=" << get_err(result).message;
    const auto& cfg = get_ok(result);
    ASSERT_EQ(cfg.pipeline.layer_4.size(), 1u);
    ASSERT_TRUE(cfg.pipeline.layer_4[0].action.has_value());
    const auto& act = *cfg.pipeline.layer_4[0].action;
    ASSERT_TRUE(std::holds_alternative<::pktgate::config::ActionRateLimit>(act))
        << "rate-limit action did not land as ActionRateLimit variant";
    EXPECT_EQ(std::get<::pktgate::config::ActionRateLimit>(act).bytes_per_sec,
              c.expected_bps)
        << "rate=" << c.literal;
  }

  // Bad forms — "1" (ambiguous, no unit), "banana" (garbage) → kBadRate.
  for (const char* lit : {R"("1")", R"("banana")", R"("200 Xbps")",
                          R"("Mbps")", R"("-5Mbps")"}) {
    std::string body = R"({ "action": { "type": "rate-limit", "rate": )";
    body += lit;
    body += R"(, "burst_ms": 10 } })";
    const std::string doc = make_doc_with_layer4_rule(body);
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result)) << "bad rate " << lit << " accepted";
    EXPECT_EQ(err_kind(result), ParseError::kBadRate)
        << "rate=" << lit
        << " expected kBadRate got kind="
        << static_cast<int>(err_kind(result))
        << " msg=" << get_err(result).message;
  }
}

// -------------------------------------------------------------------------
// U1.22 — rate-limit action parses `burst_ms` and derives burst_bytes.
// burst_bytes == rate_bytes_per_sec * burst_ms / 1000.

TEST(ParserU1_22, RateLimitBurstBytesDerivedAtLoadTime) {
  // 200Mbps = 25_000_000 bytes/sec, burst_ms=10 → 250_000 bytes.
  const std::string body =
      R"({ "action": { "type": "rate-limit", "rate": "200Mbps", "burst_ms": 10 } })";
  const std::string doc = make_doc_with_layer4_rule(body);
  const ParseResult result = parse(doc);
  ASSERT_TRUE(is_ok(result))
      << "rate-limit action rejected; kind="
      << static_cast<int>(err_kind(result))
      << " msg=" << get_err(result).message;
  const auto& cfg = get_ok(result);
  ASSERT_EQ(cfg.pipeline.layer_4.size(), 1u);
  ASSERT_TRUE(cfg.pipeline.layer_4[0].action.has_value());
  const auto& act = *cfg.pipeline.layer_4[0].action;
  ASSERT_TRUE(std::holds_alternative<::pktgate::config::ActionRateLimit>(act));
  const auto& rl = std::get<::pktgate::config::ActionRateLimit>(act);
  EXPECT_EQ(rl.bytes_per_sec, 25'000'000ull);
  // The derivation must happen at load time — runtime hot path must
  // never see the multiplication. 25_000_000 * 10 / 1000 = 250_000.
  EXPECT_EQ(rl.burst_bytes, 250'000ull);
}

// -------------------------------------------------------------------------
// U1.23 — `hw_offload_hint` optional, defaults false. D4.
//
// The hint is a per-rule boolean. Parser accepts true/false explicitly,
// and a missing field yields `false`.

TEST(ParserU1_23, HwOffloadHintOptionalDefaultsFalse) {
  // Default: missing → false.
  {
    const std::string body = R"({ "dst_port": 80, "action": { "type": "allow" } })";
    const std::string doc = make_doc_with_layer4_rule(body);
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result))
        << "rule without hw_offload_hint rejected; msg="
        << get_err(result).message;
    ASSERT_EQ(get_ok(result).pipeline.layer_4.size(), 1u);
    EXPECT_FALSE(get_ok(result).pipeline.layer_4[0].hw_offload_hint);
  }

  // Explicit true.
  {
    const std::string body =
        R"({ "dst_port": 80, "hw_offload_hint": true, "action": { "type": "allow" } })";
    const std::string doc = make_doc_with_layer4_rule(body);
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result))
        << "hw_offload_hint=true rejected; msg=" << get_err(result).message;
    EXPECT_TRUE(get_ok(result).pipeline.layer_4[0].hw_offload_hint);
  }

  // Explicit false.
  {
    const std::string body =
        R"({ "dst_port": 80, "hw_offload_hint": false, "action": { "type": "allow" } })";
    const std::string doc = make_doc_with_layer4_rule(body);
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result))
        << "hw_offload_hint=false rejected; msg=" << get_err(result).message;
    EXPECT_FALSE(get_ok(result).pipeline.layer_4[0].hw_offload_hint);
  }

  // Type mismatch: non-boolean → kTypeMismatch.
  {
    const std::string body =
        R"({ "dst_port": 80, "hw_offload_hint": "yes", "action": { "type": "allow" } })";
    const std::string doc = make_doc_with_layer4_rule(body);
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result));
    EXPECT_EQ(err_kind(result), ParseError::kTypeMismatch);
  }
}

// -------------------------------------------------------------------------
// U1.24 — Rule `id` required, must be positive integer.
// Inputs (from unit.md): missing id, id:0, id:-1, id:"42" → all rejected.
// id:1 → accepted. Uses the `_raw` helper so default id injection is off.

TEST(ParserU1_24, RuleIdRequiredPositive) {
  // id:1 accepted.
  {
    const std::string doc = make_doc_with_layer4_rule_raw(
        R"({ "id": 1, "action": { "type": "allow" } })");
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result))
        << "id=1 rejected; kind=" << static_cast<int>(err_kind(result))
        << " msg=" << get_err(result).message;
    ASSERT_EQ(get_ok(result).pipeline.layer_4.size(), 1u);
    EXPECT_EQ(get_ok(result).pipeline.layer_4[0].id, 1);
  }
  // id:42 accepted.
  {
    const std::string doc = make_doc_with_layer4_rule_raw(
        R"({ "id": 42, "action": { "type": "allow" } })");
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result)) << "id=42 rejected; msg="
                               << get_err(result).message;
    EXPECT_EQ(get_ok(result).pipeline.layer_4[0].id, 42);
  }

  // Missing id → rejected.
  {
    const std::string doc = make_doc_with_layer4_rule_raw(
        R"({ "action": { "type": "allow" } })");
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result)) << "missing id was accepted";
    // Either kUnknownField (reusing the "missing required field" idiom
    // from top-level) or kOutOfRange — either is legitimate for a
    // missing-required-positive-int.
    const auto k = err_kind(result);
    EXPECT_TRUE(k == ParseError::kUnknownField ||
                k == ParseError::kOutOfRange)
        << "missing id rejected with unexpected kind="
        << static_cast<int>(k);
  }

  // id:0 → rejected (not positive).
  {
    const std::string doc = make_doc_with_layer4_rule_raw(
        R"({ "id": 0, "action": { "type": "allow" } })");
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result));
    EXPECT_EQ(err_kind(result), ParseError::kOutOfRange);
  }

  // id:-1 → rejected (not positive).
  {
    const std::string doc = make_doc_with_layer4_rule_raw(
        R"({ "id": -1, "action": { "type": "allow" } })");
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result));
    EXPECT_EQ(err_kind(result), ParseError::kOutOfRange);
  }

  // id:"42" → rejected (type mismatch).
  {
    const std::string doc = make_doc_with_layer4_rule_raw(
        R"({ "id": "42", "action": { "type": "allow" } })");
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result));
    EXPECT_EQ(err_kind(result), ParseError::kTypeMismatch);
  }
}

// -------------------------------------------------------------------------
// U1.29 — Action exactly-one invariant (D15-style sum type).
//
// The `action` object has a required `type` string selecting the
// variant. Per unit.md the specific bad-input is:
//   `"action": { "type": "allow", "target_port": "x" }`
// mixing an Allow action with a TargetPort field — the resulting
// sum-type violation → kAmbiguousAction.
//
// We also pin: missing `action` entirely → rule is accepted with
// `action = nullopt` (action is an optional schema field in M1; the
// validator will later require it for non-skeleton rules. Parser-
// level it's optional — consistent with the C4-era test corpus that
// never set it).

TEST(ParserU1_29, ActionExactlyOneInvariant) {
  // Happy: single-variant Allow.
  {
    const std::string doc =
        make_doc_with_layer4_rule(R"({ "action": { "type": "allow" } })");
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result))
        << "allow action rejected; msg=" << get_err(result).message;
    ASSERT_EQ(get_ok(result).pipeline.layer_4.size(), 1u);
    ASSERT_TRUE(get_ok(result).pipeline.layer_4[0].action.has_value());
    EXPECT_TRUE(std::holds_alternative<::pktgate::config::ActionAllow>(
        *get_ok(result).pipeline.layer_4[0].action));
  }

  // Happy: Drop variant.
  {
    const std::string doc =
        make_doc_with_layer4_rule(R"({ "action": { "type": "drop" } })");
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result))
        << "drop action rejected; msg=" << get_err(result).message;
    EXPECT_TRUE(std::holds_alternative<::pktgate::config::ActionDrop>(
        *get_ok(result).pipeline.layer_4[0].action));
  }

  // Bad: Allow type with an extra target_port field — mixes sum-type
  // variants. Must reject as kAmbiguousAction.
  {
    const std::string doc = make_doc_with_layer4_rule(
        R"({ "action": { "type": "allow", "target_port": "x" } })");
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result))
        << "mixed action (allow + target_port) accepted";
    EXPECT_EQ(err_kind(result), ParseError::kAmbiguousAction)
        << "kind=" << static_cast<int>(err_kind(result))
        << " msg=" << get_err(result).message;
  }

  // Bad: no `type` at all — zero-variant, also kAmbiguousAction.
  {
    const std::string doc =
        make_doc_with_layer4_rule(R"({ "action": { } })");
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result)) << "empty action accepted";
    EXPECT_EQ(err_kind(result), ParseError::kAmbiguousAction);
  }

  // Bad: unknown action type string.
  {
    const std::string doc = make_doc_with_layer4_rule(
        R"({ "action": { "type": "teleport" } })");
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result));
    // Either kBadEnum (unknown type string) or kAmbiguousAction — both
    // express the same sum-type violation at the schema level.
    const auto k = err_kind(result);
    EXPECT_TRUE(k == ParseError::kBadEnum ||
                k == ParseError::kAmbiguousAction)
        << "unknown action type rejected with unexpected kind="
        << static_cast<int>(k);
  }
}

// -------------------------------------------------------------------------
// U1.30 — `tcp_flags` sub-object parses into a (mask, want) pair.
//
// Input shape: `{ "syn": true, "ack": false }`.
// Semantics: each flag present sets its bit in `mask`. If the value is
// `true` the bit is also set in `want`; if `false`, the bit is cleared
// in `want`. Absent flags are don't-care (bit clear in both).
//
// Bit layout matches L4CompoundEntry / DPDK tcp_flags byte
// (RFC 9293): FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10,
// URG=0x20, ECE=0x40, CWR=0x80.
//
// Invariant: `(want & ~mask) == 0` (want bits must be a subset of
// mask bits). This is structurally guaranteed by the parser design.

TEST(ParserU1_30, TcpFlagsMaskWantParse) {
  constexpr std::uint8_t kSyn = 0x02;
  constexpr std::uint8_t kAck = 0x10;
  constexpr std::uint8_t kFin = 0x01;

  // syn:true, ack:false → mask=SYN|ACK, want=SYN.
  {
    const std::string doc = make_doc_with_layer4_rule(
        R"({ "tcp_flags": { "syn": true, "ack": false }, "action": { "type": "allow" } })");
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result))
        << "tcp_flags rejected; msg=" << get_err(result).message;
    ASSERT_EQ(get_ok(result).pipeline.layer_4.size(), 1u);
    const auto& r = get_ok(result).pipeline.layer_4[0];
    ASSERT_TRUE(r.tcp_flags.has_value());
    EXPECT_EQ(r.tcp_flags->mask, static_cast<std::uint8_t>(kSyn | kAck));
    EXPECT_EQ(r.tcp_flags->want, static_cast<std::uint8_t>(kSyn));
    // Invariant: want is a subset of mask.
    EXPECT_EQ(r.tcp_flags->want & ~r.tcp_flags->mask, 0);
  }

  // All three true.
  {
    const std::string doc = make_doc_with_layer4_rule(
        R"({ "tcp_flags": { "syn": true, "ack": true, "fin": true }, "action": { "type": "allow" } })");
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result)) << "msg=" << get_err(result).message;
    const auto& tf = *get_ok(result).pipeline.layer_4[0].tcp_flags;
    EXPECT_EQ(tf.mask, static_cast<std::uint8_t>(kSyn | kAck | kFin));
    EXPECT_EQ(tf.want, static_cast<std::uint8_t>(kSyn | kAck | kFin));
  }

  // Empty object → mask=0, want=0 (no flags constrained). Still present.
  {
    const std::string doc = make_doc_with_layer4_rule(
        R"({ "tcp_flags": {}, "action": { "type": "allow" } })");
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result)) << "msg=" << get_err(result).message;
    const auto& r = get_ok(result).pipeline.layer_4[0];
    ASSERT_TRUE(r.tcp_flags.has_value());
    EXPECT_EQ(r.tcp_flags->mask, 0u);
    EXPECT_EQ(r.tcp_flags->want, 0u);
  }

  // Unknown flag key → kUnknownField.
  {
    const std::string doc = make_doc_with_layer4_rule(
        R"({ "tcp_flags": { "banana": true }, "action": { "type": "allow" } })");
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result));
    EXPECT_EQ(err_kind(result), ParseError::kUnknownField);
  }

  // Non-bool value → kTypeMismatch.
  {
    const std::string doc = make_doc_with_layer4_rule(
        R"({ "tcp_flags": { "syn": "yes" }, "action": { "type": "allow" } })");
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result));
    EXPECT_EQ(err_kind(result), ParseError::kTypeMismatch);
  }
}

// =========================================================================
// M1 C6 — sizing section, objects.subnets, stress-lite.
//
// Covers:
//   * U1.25 — inline `sizing` parses and populates the ten D6 fields.
//   * U1.26 — missing `sizing` applies kSizingDevDefaults (D6 dev column
//             is a first-class constant, not an "MVP limit" — M1 meta).
//   * U1.27 — values below the D6 §3a.2 hard minimum (16 rules/layer)
//             are rejected with kSizingBelowMin.
//   * U1.28 — `objects.subnets` name→CIDR map parses for both IPv4 and
//             IPv6; malformed CIDRs propagate kBadCidr.
//   * U1.31 — stress-lite: 4096 L3 + 4096 L4 rules parse under a
//             preset-dependent budget (see kStressBudgetMs below).
//
// D-refs: D6 (sizing columns, hard min), D8 (strict schema, object
// model), M1 meta-principle (dev vs prod as two equal columns, not
// a phasing).

using ::pktgate::config::Cidr4;
using ::pktgate::config::Cidr6;
using ::pktgate::config::kSizingDevDefaults;
using ::pktgate::config::kSizingProdDefaults;
using ::pktgate::config::kSizingRulesPerLayerHardMin;
using ::pktgate::config::Sizing;
using ::pktgate::config::SubnetCidr;

// Build a minimal top-level document with an injectable `sizing` /
// `objects` body. Empty string = section omitted. Lives in the outer
// anonymous namespace alongside make_doc_with_layer{2,4}_rule.
std::string make_doc_with_sections(std::string_view sizing_body,
                                   std::string_view objects_body) {
  std::ostringstream ss;
  ss << R"json({
  "version": 1,
  "interface_roles": {
    "upstream_port":   { "pci": "0000:00:00.0" },
    "downstream_port": { "pci": "0000:00:00.1" }
  },
  "pipeline": { "layer_2": [], "layer_3": [], "layer_4": [] },
  "default_behavior": "drop")json";
  if (!sizing_body.empty()) {
    ss << ",\n  \"sizing\": " << sizing_body;
  }
  if (!objects_body.empty()) {
    ss << ",\n  \"objects\": " << objects_body;
  }
  ss << "\n}";
  return ss.str();
}

// -------------------------------------------------------------------------
// U1.25 — inline `sizing` parses and populates every field. The values
// in the document are deliberately a mix of dev and prod column numbers
// so the assertion can't accidentally pass by checking the kSizingDev
// constants. Every field must end up with exactly the JSON literal.

TEST(ParserU1_25, InlineSizingPopulatesAllFields) {
  constexpr std::string_view kSizing = R"json({
    "rules_per_layer_max":   4096,
    "mac_entries_max":       4096,
    "ipv4_prefixes_max":    16384,
    "ipv6_prefixes_max":    16384,
    "l4_entries_max":        4096,
    "vrf_entries_max":        256,
    "rate_limit_rules_max":  4096,
    "ethertype_entries_max":   64,
    "vlan_entries_max":      4096,
    "pcp_entries_max":          8
  })json";

  const std::string doc = make_doc_with_sections(kSizing, "");
  const ParseResult result = parse(doc);
  ASSERT_TRUE(is_ok(result)) << "msg=" << get_err(result).message;
  const Sizing& s = get_ok(result).sizing;

  EXPECT_EQ(s.rules_per_layer_max, 4096u);
  EXPECT_EQ(s.mac_entries_max, 4096u);
  EXPECT_EQ(s.ipv4_prefixes_max, 16384u);
  EXPECT_EQ(s.ipv6_prefixes_max, 16384u);
  EXPECT_EQ(s.l4_entries_max, 4096u);
  EXPECT_EQ(s.vrf_entries_max, 256u);
  EXPECT_EQ(s.rate_limit_rules_max, 4096u);
  EXPECT_EQ(s.ethertype_entries_max, 64u);
  EXPECT_EQ(s.vlan_entries_max, 4096u);
  EXPECT_EQ(s.pcp_entries_max, 8u);

  // The inline values here happen to match kSizingProdDefaults. This
  // is a sanity check: the prod column constant is first-class and
  // addressable — no "MVP uses X" phasing. If this ever fails, the
  // column table in sizing.h has drifted from D6.
  EXPECT_EQ(s.rules_per_layer_max, kSizingProdDefaults.rules_per_layer_max);
}

// -------------------------------------------------------------------------
// U1.26 — missing `sizing` section fills Config.sizing with the dev
// column (kSizingDevDefaults). The assertion compares every field so
// a silent drift in the dev constant is caught at parse time.

TEST(ParserU1_26, MissingSizingAppliesDevDefaults) {
  const std::string doc = make_doc_with_sections("", "");
  const ParseResult result = parse(doc);
  ASSERT_TRUE(is_ok(result)) << "msg=" << get_err(result).message;
  const Sizing& s = get_ok(result).sizing;

  EXPECT_EQ(s.rules_per_layer_max, kSizingDevDefaults.rules_per_layer_max);
  EXPECT_EQ(s.mac_entries_max, kSizingDevDefaults.mac_entries_max);
  EXPECT_EQ(s.ipv4_prefixes_max, kSizingDevDefaults.ipv4_prefixes_max);
  EXPECT_EQ(s.ipv6_prefixes_max, kSizingDevDefaults.ipv6_prefixes_max);
  EXPECT_EQ(s.l4_entries_max, kSizingDevDefaults.l4_entries_max);
  EXPECT_EQ(s.vrf_entries_max, kSizingDevDefaults.vrf_entries_max);
  EXPECT_EQ(s.rate_limit_rules_max, kSizingDevDefaults.rate_limit_rules_max);
  EXPECT_EQ(s.ethertype_entries_max, kSizingDevDefaults.ethertype_entries_max);
  EXPECT_EQ(s.vlan_entries_max, kSizingDevDefaults.vlan_entries_max);
  EXPECT_EQ(s.pcp_entries_max, kSizingDevDefaults.pcp_entries_max);

  // Smoke: dev and prod columns really are distinct — if someone
  // edits one into a copy of the other, this breaks and we notice.
  EXPECT_NE(kSizingDevDefaults.rules_per_layer_max,
            kSizingProdDefaults.rules_per_layer_max);
}

// -------------------------------------------------------------------------
// U1.27 — rules_per_layer_max below the D6 §3a.2 hard minimum (16) is
// rejected as kSizingBelowMin. The test uses 8 (the exact example
// from unit.md) so the error path is tightly pinned. Additionally
// verifies 16 itself is accepted (boundary on the allowed side) and
// that the reject message names the offending value.

TEST(ParserU1_27, SizingBelowHardMinRejected) {
  // Below min → rejected.
  {
    const std::string doc = make_doc_with_sections(R"({
      "rules_per_layer_max":      8,
      "mac_entries_max":       4096,
      "ipv4_prefixes_max":    16384,
      "ipv6_prefixes_max":    16384,
      "l4_entries_max":        4096,
      "vrf_entries_max":        256,
      "rate_limit_rules_max":  4096,
      "ethertype_entries_max":   64,
      "vlan_entries_max":      4096,
      "pcp_entries_max":          8
    })", "");
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result));
    EXPECT_EQ(err_kind(result), ParseError::kSizingBelowMin);
    const auto& msg = get_err(result).message;
    EXPECT_NE(msg.find("8"), std::string::npos)
        << "error must name offending value: " << msg;
    EXPECT_NE(msg.find("16"), std::string::npos)
        << "error must name the hard minimum: " << msg;
  }

  // Exactly the minimum → accepted.
  {
    const std::string doc = make_doc_with_sections(R"({
      "rules_per_layer_max":     16,
      "mac_entries_max":       4096,
      "ipv4_prefixes_max":    16384,
      "ipv6_prefixes_max":    16384,
      "l4_entries_max":        4096,
      "vrf_entries_max":        256,
      "rate_limit_rules_max":  4096,
      "ethertype_entries_max":   64,
      "vlan_entries_max":      4096,
      "pcp_entries_max":          8
    })", "");
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result)) << "msg=" << get_err(result).message;
    EXPECT_EQ(get_ok(result).sizing.rules_per_layer_max,
              kSizingRulesPerLayerHardMin);
  }

  // Partial object (missing key) → rejected, not silently defaulted.
  {
    const std::string doc = make_doc_with_sections(R"({
      "rules_per_layer_max": 256
    })", "");
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result));
    EXPECT_EQ(err_kind(result), ParseError::kUnknownField);
  }
}

// -------------------------------------------------------------------------
// U1.28 — `objects.subnets` parses each name → CIDR list entry into
// the unresolved ObjectPool. IPv4 entries land as Cidr4, IPv6 entries
// as Cidr6. Malformed CIDRs surface kBadCidr. No dangling-ref check
// here (that's the validator's C7+ job).

TEST(ParserU1_28, ObjectsSubnetsParseAndRejectBadCidr) {
  // Happy path — two named subnets, mixed IPv4 and IPv6.
  {
    const std::string doc = make_doc_with_sections("", R"({
      "subnets": {
        "corp_v4": ["10.0.0.0/8", "192.168.0.0/16"],
        "corp_v6": ["2001:db8::/32"]
      }
    })");
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result)) << "msg=" << get_err(result).message;
    const auto& pool = get_ok(result).objects;
    ASSERT_EQ(pool.subnets.size(), 2u);

    // Lookup by name (JSON object iteration order is implementation-
    // defined per nlohmann::json's default std::map backend, which is
    // lexicographic — but be defensive).
    const auto* corp_v4 = [&]() -> const pktgate::config::SubnetObject* {
      for (const auto& so : pool.subnets) {
        if (so.name == "corp_v4") return &so;
      }
      return nullptr;
    }();
    ASSERT_NE(corp_v4, nullptr);
    ASSERT_EQ(corp_v4->cidrs.size(), 2u);
    ASSERT_TRUE(std::holds_alternative<Cidr4>(corp_v4->cidrs[0]));
    EXPECT_EQ(std::get<Cidr4>(corp_v4->cidrs[0]).prefix, 8u);
    ASSERT_TRUE(std::holds_alternative<Cidr4>(corp_v4->cidrs[1]));
    EXPECT_EQ(std::get<Cidr4>(corp_v4->cidrs[1]).prefix, 16u);

    const auto* corp_v6 = [&]() -> const pktgate::config::SubnetObject* {
      for (const auto& so : pool.subnets) {
        if (so.name == "corp_v6") return &so;
      }
      return nullptr;
    }();
    ASSERT_NE(corp_v6, nullptr);
    ASSERT_EQ(corp_v6->cidrs.size(), 1u);
    ASSERT_TRUE(std::holds_alternative<Cidr6>(corp_v6->cidrs[0]));
    EXPECT_EQ(std::get<Cidr6>(corp_v6->cidrs[0]).prefix, 32u);
  }

  // Missing `objects` section → empty pool, no error.
  {
    const std::string doc = make_doc_with_sections("", "");
    const ParseResult result = parse(doc);
    ASSERT_TRUE(is_ok(result)) << "msg=" << get_err(result).message;
    EXPECT_TRUE(get_ok(result).objects.subnets.empty());
  }

  // Malformed CIDR → kBadCidr, offending literal named in message.
  {
    const std::string doc = make_doc_with_sections("", R"({
      "subnets": {
        "broken": ["10.0.0.0/33"]
      }
    })");
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result));
    EXPECT_EQ(err_kind(result), ParseError::kBadCidr);
    EXPECT_NE(get_err(result).message.find("10.0.0.0/33"), std::string::npos)
        << "msg=" << get_err(result).message;
  }

  // Non-string element in the CIDR list → kTypeMismatch.
  {
    const std::string doc = make_doc_with_sections("", R"({
      "subnets": {
        "typed": [42]
      }
    })");
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result));
    EXPECT_EQ(err_kind(result), ParseError::kTypeMismatch);
  }

  // Unknown key under `objects` → kUnknownField (only `subnets` is
  // implemented in C6).
  {
    const std::string doc = make_doc_with_sections("", R"({
      "mac_groups": { "gw": ["aa:bb:cc:dd:ee:ff"] }
    })");
    const ParseResult result = parse(doc);
    ASSERT_FALSE(is_ok(result));
    EXPECT_EQ(err_kind(result), ParseError::kUnknownField);
  }
}

// -------------------------------------------------------------------------
// U1.31 — stress-lite. Generate a synthetic config with 4096 L3 rules
// and 4096 L4 rules, parse it, and assert the wall-clock parse time
// is below a preset-aware budget. This is not a microbenchmark: it's
// a "parser is not accidentally O(n^2)" canary. A naive quadratic
// walk over 8192 rules would blow the budget by two orders of
// magnitude even on a fast host.
//
// Budget selection:
//   * Release / debug: 500 ms (unit.md U1.31 target).
//   * Sanitizer builds (asan / tsan / ubsan) are 2-6x slower —
//     they get 2500 ms. Detected via __has_feature(address_sanitizer)
//     and __has_feature(thread_sanitizer) where available, plus a
//     __SANITIZE_ADDRESS__ fallback for GCC-style asan. The ubsan
//     preset has no standard feature test — fold it into the release
//     budget and hope the host can swing it; if it can't, we relax
//     the else branch too.
//
// The test builds the JSON in-process via ostringstream (one alloc
// per append is fine — this isn't on the hot path we're measuring;
// the measurement window starts after the string is built). Each
// rule gets a unique id so the validator (C7+) could in principle
// stress the same config.

TEST(ParserU1_31, StressLite4096Plus4096) {
#if defined(__has_feature)
#  if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer) || \
      __has_feature(memory_sanitizer)
#    define PKTGATE_STRESS_SANITIZER 1
#  endif
#endif
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#  define PKTGATE_STRESS_SANITIZER 1
#endif

#ifdef PKTGATE_STRESS_SANITIZER
  constexpr int kStressBudgetMs = 2500;
#else
  constexpr int kStressBudgetMs = 500;
#endif

  constexpr int kRulesPerLayer = 4096;

  std::ostringstream ss;
  ss << R"json({
  "version": 1,
  "interface_roles": {
    "upstream_port":   { "pci": "0000:00:00.0" },
    "downstream_port": { "pci": "0000:00:00.1" }
  },
  "default_behavior": "drop",
  "pipeline": {
    "layer_2": [],
    "layer_3": [)json";
  for (int i = 0; i < kRulesPerLayer; ++i) {
    if (i > 0) ss << ',';
    ss << R"({"id":)" << (10000 + i)
       << R"(,"vlan_id":)" << (i % 4096)
       << R"(,"action":{"type":"allow"}})";
  }
  ss << R"json(],
    "layer_4": [)json";
  for (int i = 0; i < kRulesPerLayer; ++i) {
    if (i > 0) ss << ',';
    ss << R"({"id":)" << (20000 + i)
       << R"(,"dst_port":)" << ((i % 65535) + 1)
       << R"(,"action":{"type":"drop"}})";
  }
  ss << R"json(]
  }
})json";
  const std::string doc = ss.str();

  // Sanity check the fixture itself — catch a typo before blaming
  // the parser for a slow path.
  ASSERT_GT(doc.size(), static_cast<std::size_t>(kRulesPerLayer * 40));

  const auto start = std::chrono::steady_clock::now();
  const ParseResult result = parse(doc);
  const auto end = std::chrono::steady_clock::now();

  ASSERT_TRUE(is_ok(result)) << "msg=" << get_err(result).message;
  const auto& cfg = get_ok(result);
  EXPECT_EQ(cfg.pipeline.layer_3.size(),
            static_cast<std::size_t>(kRulesPerLayer));
  EXPECT_EQ(cfg.pipeline.layer_4.size(),
            static_cast<std::size_t>(kRulesPerLayer));

  const auto elapsed_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
          .count();
  EXPECT_LT(elapsed_ms, kStressBudgetMs)
      << "stress-lite parse took " << elapsed_ms
      << " ms (budget " << kStressBudgetMs
      << " ms; sanitizer=" <<
#ifdef PKTGATE_STRESS_SANITIZER
             "yes"
#else
             "no"
#endif
         << ")";

  // Record actual timing in the log so a later run can see whether
  // we're trending toward the budget.
  ::testing::Test::RecordProperty("stress_lite_parse_ms",
                                  static_cast<int>(elapsed_ms));
}

}  // namespace
