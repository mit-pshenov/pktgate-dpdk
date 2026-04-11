// tests/unit/test_validator.cpp
//
// M1 C7 / C7.5 — validator scaffolding + object/role resolution +
// cmd_socket schema. Transcribes `test-plan-drafts/unit.md`
// U2.1/U2.2/U2.3/U2.4/U2.18 into real gtest code.
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
//   * C7.5 update: U2.18 is now a **negative assertion** — the parser
//     and validator must NEVER resolve a gid default. The
//     `std::nullopt` sentinel survives verbatim through parse+validate;
//     real gid resolution happens at M11 cmd_socket bind time, after
//     the daemon has dropped privileges to the pktgate user. Validating
//     offline as root and then running as pktgate must not silently
//     capture the wrong gid.
//
// CTEST-SCAN: no gid resolution at parse/validate tier.
// A lint (grep for `getgid|getgrnam|getgrouplist|initgroups`) over
// `src/config/` must return empty. U2.18 pins the behavioural half of
// that invariant (sentinel survives); the grep lint pins the static
// half (no syscall site exists to begin with). Path chosen: (a) —
// see C7.5 supervisor prompt. Path (b) (injection-seam with a counting
// fake resolver) was considered but rejected because it would add an
// API surface that a future cycle could abuse; the grep lint + this
// test together encode the rule at lower maintenance cost.

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
// U2.18 — `cmd_socket.allow_gids` parses; resolution deferred to daemon
// init (C7.5 rewrite as **negative assertion**, D38).
//
// This test pins two things:
//
//   (a) Positive: an explicit list parses and survives validate verbatim
//       as `std::optional<std::vector<gid_t>>` with the exact values.
//       Explicit-empty `[]` is distinct from absent — the optional
//       wrapper is load-bearing.
//   (b) Negative: when `cmd_socket` is absent, or when `cmd_socket` is
//       present with no `allow_gids` key, the optional stays
//       `std::nullopt` after validate. **The validator must not invent
//       a default.** Offline `--validate-config` may run as a different
//       user than the final daemon; silently capturing `::getgid()` at
//       validate time would drift from the gid that M11's SO_PEERCRED
//       check will eventually use at cmd_socket bind (after drop-privs
//       to the pktgate user).
//
// Path (a) was chosen over an injection-seam (path b): this test pins
// "sentinel survives", and the static half — "no gid-resolution syscall
// exists anywhere under `src/config/`" — is enforced by a grep lint
// over `getgid|getgrnam|getgrouplist|initgroups`. Belt-and-suspenders
// via a counting fake resolver would add an API surface that a future
// cycle could accidentally wire up; the grep lint is cheaper and
// strictly stronger.

TEST(ValidatorU2_18, CmdSocketAllowGidsDefersResolution) {
  // (a) Positive — explicit list survives parse+validate verbatim.
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

    ASSERT_TRUE(cfg.cmd_socket.allow_gids.has_value())
        << "explicit list must survive into the validated Config";
    const auto& gids = cfg.cmd_socket.allow_gids.value();
    ASSERT_EQ(gids.size(), 3u);
    EXPECT_EQ(gids[0], static_cast<::gid_t>(1));
    EXPECT_EQ(gids[1], static_cast<::gid_t>(2));
    EXPECT_EQ(gids[2], static_cast<::gid_t>(3));
  }

  // (b.1) Negative — `cmd_socket` section absent entirely: nullopt
  // survives. The validator MUST NOT invent a default.
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

    ASSERT_FALSE(cfg.cmd_socket.allow_gids.has_value())
        << "validator default-filled allow_gids when cmd_socket was "
           "absent — resolution must be deferred to M11 daemon init, "
           "not captured at validate time (offline --validate-config "
           "running as a different user would drift silently).";
  }

  // (b.2) Negative — `cmd_socket` present but `allow_gids` absent:
  // same rule. Presence of the section alone is not a request to
  // resolve a default.
  {
    const std::string doc = make_doc_with_cmd_socket(R"({})");
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);
    ASSERT_TRUE(v_is_ok(vr))
        << "validator rejected empty cmd_socket; kind="
        << static_cast<int>(v_get_err(vr).kind)
        << " msg=" << v_get_err(vr).message;

    ASSERT_FALSE(cfg.cmd_socket.allow_gids.has_value())
        << "validator invented a default for cmd_socket.allow_gids "
           "when the section existed but the key was absent — the "
           "std::nullopt sentinel must survive verbatim.";
  }

  // (c) Explicit empty list is distinct from absent. This is the
  // whole reason `allow_gids` is wrapped in std::optional: an
  // explicit `[]` means "deny all peers" and must not collapse
  // into the "absent" sentinel.
  {
    const std::string doc =
        make_doc_with_cmd_socket(R"({ "allow_gids": [] })");
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);
    ASSERT_TRUE(v_is_ok(vr))
        << "validator rejected explicit empty allow_gids; kind="
        << static_cast<int>(v_get_err(vr).kind)
        << " msg=" << v_get_err(vr).message;

    ASSERT_TRUE(cfg.cmd_socket.allow_gids.has_value())
        << "explicit empty list must remain distinguishable from absent";
    EXPECT_EQ(cfg.cmd_socket.allow_gids->size(), 0u);
  }
}

}  // namespace
