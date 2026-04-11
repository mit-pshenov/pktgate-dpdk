// tests/unit/test_validator.cpp
//
// M1 C7 — validator scaffolding + object/role resolution + cmd_socket
// schema. Transcribes `test-plan-drafts/unit.md` U2.1/U2.2/U2.3/U2.4/U2.18
// into real gtest code.
//
// Target: `libpktgate_core.a` → `pktgate::config::validate`.
// No EAL, no mempool, no DPDK includes — strictly pure-C++.
//
// Covers: U2.1, U2.2, U2.3, U2.4, U2.18. D-refs: D5, D8, D38.
//
// Cycle notes (C7 scope):
//   * The validator consumes the AST produced by `parse()` — tests build
//     the input document through the parser, then feed the Config into
//     `validate()`. This keeps the validator surface honest: we only
//     validate inputs that the parser can actually produce.
//   * Two error kinds land in this cycle: `kUnresolvedObject` (U2.2)
//     and `kUnresolvedInterfaceRef` (U2.4). Every other kind is out of
//     C7 scope and lives in C8+.
//   * U2.18 exercises the allow_gids schema parse + validator default.
//     The parser stores the field as an optional-of-vector so the
//     validator can distinguish "absent" (fill with singleton getgid())
//     from "present but empty". Design rationale lives in validator.cpp.

#include <gtest/gtest.h>

#include <sys/types.h>
#include <unistd.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "src/config/model.h"
#include "src/config/parser.h"
#include "src/config/validator.h"

namespace {

using ::pktgate::config::Config;
using ::pktgate::config::get_err;
using ::pktgate::config::get_ok;
using ::pktgate::config::is_ok;
using ::pktgate::config::parse;
using ::pktgate::config::ParseResult;
using ::pktgate::config::validate;
using ::pktgate::config::ValidateError;
using ::pktgate::config::ValidateResult;

// Success/error helpers mirror the parser's pattern. Keeping the
// `is_ok` / `get_ok` / `get_err` free-function style means that when
// we eventually flip to `std::expected` (C++23, D2 welcomes it), the
// tests need zero edits.
inline bool v_is_ok(const ValidateResult& r) noexcept {
  return std::holds_alternative<::pktgate::config::ValidateOk>(r);
}
inline const ValidateError& v_get_err(const ValidateResult& r) {
  return std::get<ValidateError>(r);
}

// Every helper below produces a self-contained minimal document with a
// single rule whose body is controlled by the caller. The two PCI
// interface_roles stay constant across all tests — the helpers differ
// only in how the rule body and the `objects` / `cmd_socket` sections
// are composed.
std::string make_doc_with_layer3_rule_and_subnets(
    std::string_view rule_body, std::string_view subnets_body) {
  std::string out = R"json({
  "version": 1,
  "interface_roles": {
    "upstream_port":   { "pci": "0000:00:00.0" },
    "downstream_port": { "pci": "0000:00:00.1" }
  },
  "pipeline": {
    "layer_2": [],
    "layer_3": [)json";
  out += rule_body;
  out += R"json(],
    "layer_4": []
  },
  "default_behavior": "drop",
  "objects": { "subnets": )json";
  out += subnets_body;
  out += R"json( }
})json";
  return out;
}

std::string make_doc_with_layer3_rule_no_objects(std::string_view rule_body) {
  std::string out = R"json({
  "version": 1,
  "interface_roles": {
    "upstream_port":   { "pci": "0000:00:00.0" },
    "downstream_port": { "pci": "0000:00:00.1" }
  },
  "pipeline": {
    "layer_2": [],
    "layer_3": [)json";
  out += rule_body;
  out += R"json(],
    "layer_4": []
  },
  "default_behavior": "drop"
})json";
  return out;
}

std::string make_doc_with_cmd_socket(std::string_view cmd_socket_body) {
  std::string out = R"json({
  "version": 1,
  "interface_roles": {
    "upstream_port":   { "pci": "0000:00:00.0" },
    "downstream_port": { "pci": "0000:00:00.1" }
  },
  "pipeline": { "layer_2": [], "layer_3": [], "layer_4": [] },
  "default_behavior": "drop",
  "cmd_socket": )json";
  out += cmd_socket_body;
  out += "\n}";
  return out;
}

std::string make_doc_no_cmd_socket() {
  return R"json({
  "version": 1,
  "interface_roles": {
    "upstream_port":   { "pci": "0000:00:00.0" },
    "downstream_port": { "pci": "0000:00:00.1" }
  },
  "pipeline": { "layer_2": [], "layer_3": [], "layer_4": [] },
  "default_behavior": "drop"
})json";
}

// Shared pre-check: any failure below means the test's JSON fixture is
// broken (typo, missing comma) — report it loudly so the reader doesn't
// chase a "validator bug" that's actually a fixture bug.
void expect_parse_ok(const ParseResult& r, const std::string& doc) {
  ASSERT_TRUE(is_ok(r))
      << "precondition parse failed (fixture bug?); kind="
      << static_cast<int>(get_err(r).kind)
      << " msg=" << get_err(r).message << "\n----DOC----\n"
      << doc;
}

// -------------------------------------------------------------------------
// U2.1 — object reference resolution, valid case.
//
// A rule carrying `src_subnet: "corp_v4"` against a config that declares
// `objects.subnets.corp_v4 = [10.0.0.0/8]` must validate clean.

TEST(ValidatorU2_1, ObjectRefValid) {
  const std::string doc = make_doc_with_layer3_rule_and_subnets(
      R"({ "id": 1, "src_subnet": "corp_v4" })",
      R"({ "corp_v4": ["10.0.0.0/8"] })");
  const ParseResult pr = parse(doc);
  expect_parse_ok(pr, doc);

  Config cfg = get_ok(pr);
  const ValidateResult vr = validate(cfg);

  ASSERT_TRUE(v_is_ok(vr))
      << "validator rejected a well-formed object reference; kind="
      << static_cast<int>(v_get_err(vr).kind)
      << " msg=" << v_get_err(vr).message;
}

// -------------------------------------------------------------------------
// U2.2 — dangling object reference rejected.
//
// Same shape as U2.1 but the rule references `src_subnet: "ghost"` which
// is not declared anywhere in `objects.subnets`. The validator must
// return `kUnresolvedObject` and the message must literally contain the
// offending name (`ghost`) so an operator can jump straight to the typo.

TEST(ValidatorU2_2, ObjectRefDangling) {
  const std::string doc = make_doc_with_layer3_rule_and_subnets(
      R"({ "id": 2, "src_subnet": "ghost" })",
      R"({ "corp_v4": ["10.0.0.0/8"] })");
  const ParseResult pr = parse(doc);
  expect_parse_ok(pr, doc);

  Config cfg = get_ok(pr);
  const ValidateResult vr = validate(cfg);

  ASSERT_FALSE(v_is_ok(vr))
      << "validator accepted a dangling object reference";
  EXPECT_EQ(v_get_err(vr).kind, ValidateError::kUnresolvedObject);
  const auto& msg = v_get_err(vr).message;
  EXPECT_NE(msg.find("ghost"), std::string::npos)
      << "error message must literally name the offending 'ghost' ref: "
      << msg;
}

// -------------------------------------------------------------------------
// U2.3 — interface_roles reference, valid case.
//
// A rule carrying `interface: "upstream_port"` against a config that
// declares `interface_roles.upstream_port = { pci: ... }` must validate
// clean. Covers D5.

TEST(ValidatorU2_3, InterfaceRefValid) {
  const std::string doc = make_doc_with_layer3_rule_no_objects(
      R"({ "id": 3, "interface": "upstream_port" })");
  const ParseResult pr = parse(doc);
  expect_parse_ok(pr, doc);

  Config cfg = get_ok(pr);
  const ValidateResult vr = validate(cfg);

  ASSERT_TRUE(v_is_ok(vr))
      << "validator rejected a well-formed interface role ref; kind="
      << static_cast<int>(v_get_err(vr).kind)
      << " msg=" << v_get_err(vr).message;
}

// -------------------------------------------------------------------------
// U2.4 — dangling interface_roles reference.
//
// The referenced role name (`nonexistent`) is not declared anywhere in
// `interface_roles`. The validator must return
// `kUnresolvedInterfaceRef` and name the offending role in the message.

TEST(ValidatorU2_4, InterfaceRefDangling) {
  const std::string doc = make_doc_with_layer3_rule_no_objects(
      R"({ "id": 4, "interface": "nonexistent" })");
  const ParseResult pr = parse(doc);
  expect_parse_ok(pr, doc);

  Config cfg = get_ok(pr);
  const ValidateResult vr = validate(cfg);

  ASSERT_FALSE(v_is_ok(vr))
      << "validator accepted a dangling interface role reference";
  EXPECT_EQ(v_get_err(vr).kind, ValidateError::kUnresolvedInterfaceRef);
  const auto& msg = v_get_err(vr).message;
  EXPECT_NE(msg.find("nonexistent"), std::string::npos)
      << "error message must name the offending role: " << msg;
}

// -------------------------------------------------------------------------
// U2.18 — `cmd_socket.allow_gids` parses and defaults (D38 schema-only).
//
// (a) Explicit list `[1, 2, 3]` survives parse + validate as-is.
// (b) Absent section → validator fills a singleton `[getgid()]`.
//
// The "singleton [pktgate_gid]" in the U-test goal means the gid the
// daemon runs as at validate time; the MVP approximation is `getgid()`
// (same answer in a single-user dev VM, distinct in a prod drop-privs
// setup — real SO_PEERCRED plumbing is M11, not M1).

TEST(ValidatorU2_18, CmdSocketAllowGidsParsesAndDefaults) {
  // (a) Explicit list.
  {
    const std::string doc =
        make_doc_with_cmd_socket(R"({ "allow_gids": [1, 2, 3] })");
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);
    ASSERT_TRUE(v_is_ok(vr))
        << "validator rejected cmd_socket.allow_gids list; kind="
        << static_cast<int>(v_get_err(vr).kind)
        << " msg=" << v_get_err(vr).message;

    ASSERT_TRUE(cfg.cmd_socket.allow_gids.has_value());
    const auto& gids = cfg.cmd_socket.allow_gids.value();
    ASSERT_EQ(gids.size(), 3u);
    EXPECT_EQ(gids[0], 1u);
    EXPECT_EQ(gids[1], 2u);
    EXPECT_EQ(gids[2], 3u);
  }

  // (b) Absent section → default-filled singleton.
  {
    const std::string doc = make_doc_no_cmd_socket();
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);
    ASSERT_TRUE(v_is_ok(vr))
        << "validator rejected missing cmd_socket section; kind="
        << static_cast<int>(v_get_err(vr).kind)
        << " msg=" << v_get_err(vr).message;

    ASSERT_TRUE(cfg.cmd_socket.allow_gids.has_value());
    const auto& gids = cfg.cmd_socket.allow_gids.value();
    ASSERT_EQ(gids.size(), 1u);
    EXPECT_EQ(gids[0], static_cast<std::uint32_t>(::getgid()));
  }
}

}  // namespace
