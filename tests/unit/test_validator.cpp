// tests/unit/test_validator.cpp
//
// M1 C7 / C7.5 / C8 — validator scaffolding + object/role resolution +
// cmd_socket schema + rule-id dedup / L2 compound collision / layer
// evaluation order. Transcribes `test-plan-drafts/unit.md`
// U2.1/U2.2/U2.3/U2.4/U2.5/U2.6/U2.7/U2.18/U2.19/U2.20 into real gtest
// code.
//
// C8 additions:
//   * U2.5 — two rules in `layer_3` with identical `id` → DuplicateRuleId,
//     error message names BOTH layer indices.
//   * U2.6 — same `id` in `layer_2` and `layer_3` is NOT a collision,
//     because (layer, rule_id) is the composite key §4.3 layer_base().
//   * U2.7 — two `layer_2` rules constraining exactly the same set of
//     L2 compound fields with identical values → KeyCollision. Adding
//     any distinguishing constraint (different active-set) → no
//     collision. "filter_mask" is derived from which optionals have
//     a value; different constraint shapes are distinguishable at
//     the primary-key level (§4.1 L2CompoundEntry semantics, D15).
//   * U2.19 — `next_layer` must advance strictly by one (layer_N rule
//     ⇒ next_layer == layer_{N+1}). Backward (l3→l2), same-layer
//     (l3→l3), and skip (l2→l4) are all rejected. Absent next_layer
//     is the "terminal" signal and always ok. Design §3a.2 anchors
//     this: `next_layer` is 0=terminal|3|4 (see `uint8_t next_layer;`
//     in the RuleAction struct, design.md §4.1) — a layer_4 rule
//     cannot carry a next_layer at all (no further layer exists).
//   * U2.20 — positive happy-path test only. `default_behavior` enum
//     bounding is enforced by the parser (parser.cpp L892-L910, D8);
//     validator is pass-through, the test pins "valid configs stay
//     valid" so a future cycle can't accidentally add a validator-tier
//     rejection for `"allow"` or `"drop"`.
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
#include "src/config/sizing.h"
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

// C8 helpers — build a doc with caller-controlled contents for all
// three layers. Matches the style of the C7 helpers but is generic
// enough that U2.5..U2.19 don't need one helper each.
std::string make_doc_with_pipeline(std::string_view layer_2_body,
                                   std::string_view layer_3_body,
                                   std::string_view layer_4_body,
                                   std::string_view default_behavior) {
  std::string out = R"json({
  "version": 1,
  "interface_roles": {
    "upstream_port":   { "pci": "0000:00:00.0" },
    "downstream_port": { "pci": "0000:00:00.1" }
  },
  "pipeline": {
    "layer_2": [)json";
  out += layer_2_body;
  out += R"json(],
    "layer_3": [)json";
  out += layer_3_body;
  out += R"json(],
    "layer_4": [)json";
  out += layer_4_body;
  out += R"json(]
  },
  "default_behavior": ")json";
  out += default_behavior;
  out += R"json("
})json";
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
// A rule carrying `dst_subnet: "corp_v4"` against a config that declares
// `objects.subnets.corp_v4 = [10.0.0.0/8]` must validate clean.

TEST(ValidatorU2_1, ObjectRefValid) {
  const std::string doc = make_doc_with_layer3_rule_and_subnets(
      R"({ "id": 1, "dst_subnet": "corp_v4" })",
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
// Same shape as U2.1 but the rule references `dst_subnet: "ghost"` which
// is not declared anywhere in `objects.subnets`. The validator must
// return `kUnresolvedObject` and the message must literally contain the
// offending name (`ghost`) so an operator can jump straight to the typo.

TEST(ValidatorU2_2, ObjectRefDangling) {
  const std::string doc = make_doc_with_layer3_rule_and_subnets(
      R"({ "id": 2, "dst_subnet": "ghost" })",
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

// -------------------------------------------------------------------------
// U2.5 — duplicate rule `id` within a single layer rejected.
//
// Two rules in `layer_3` both carry `id: 2001`. The validator must
// return `DuplicateRuleId` and the message must literally contain both
// index strings ("layer_3[0]" and "layer_3[1]") so the operator can
// locate BOTH offending rules. (nlohmann::json drops source line
// numbers, so the vector index is the best locator we can produce —
// see the error-message convention comment in validator.cpp.)
//
// Covers: D8.

TEST(ValidatorU2_5, DuplicateRuleIdWithinLayerRejected) {
  const std::string doc = make_doc_with_pipeline(
      /*layer_2=*/"",
      /*layer_3=*/R"({ "id": 2001 }, { "id": 2001 })",
      /*layer_4=*/"",
      /*default_behavior=*/"drop");
  const ParseResult pr = parse(doc);
  expect_parse_ok(pr, doc);

  Config cfg = get_ok(pr);
  const ValidateResult vr = validate(cfg);

  ASSERT_FALSE(v_is_ok(vr))
      << "validator accepted duplicate rule id within layer_3";
  EXPECT_EQ(v_get_err(vr).kind, ValidateError::kDuplicateRuleId);
  const auto& msg = v_get_err(vr).message;
  EXPECT_NE(msg.find("layer_3[0]"), std::string::npos)
      << "DuplicateRuleId message must name the first offending index: "
      << msg;
  EXPECT_NE(msg.find("layer_3[1]"), std::string::npos)
      << "DuplicateRuleId message must name the second offending index: "
      << msg;
}

// -------------------------------------------------------------------------
// U2.6 — same rule `id` across different layers is allowed.
//
// Per design §4.3 `layer_base()`, the counter and rl_arena key is
// composite `(layer, rule_id)`, not a global `rule_id`. Operators must
// be free to reuse `id: 1001` in layer_2 and layer_3 without the
// validator flagging a collision.
//
// Covers: D8, §4.3.

TEST(ValidatorU2_6, SameRuleIdAcrossLayersAllowed) {
  const std::string doc = make_doc_with_pipeline(
      /*layer_2=*/R"({ "id": 1001 })",
      /*layer_3=*/R"({ "id": 1001 })",
      /*layer_4=*/"",
      /*default_behavior=*/"drop");
  const ParseResult pr = parse(doc);
  expect_parse_ok(pr, doc);

  Config cfg = get_ok(pr);
  const ValidateResult vr = validate(cfg);

  ASSERT_TRUE(v_is_ok(vr))
      << "validator rejected rule-id reuse across distinct layers; kind="
      << static_cast<int>(v_get_err(vr).kind)
      << " msg=" << v_get_err(vr).message;
}

// -------------------------------------------------------------------------
// U2.7 — L2 compound key collision rejected.
//
// Two rules in `layer_2` constrain exactly
// `{ src_mac, vlan_id, ethertype }` with **identical values** and no
// distinguishing field. Under first-match-wins the second rule is dead
// code — the validator catches it so operators don't silently lose
// rules. Rule ids differ (1, 2) so U2.5 doesn't fire first.
//
// Secondary assertion: a second config with the same two rules, but
// one also carries a `dst_mac` constraint (different active-set) →
// no collision, because filter_mask bits reflect which fields are
// active and the constraint shapes are distinguishable at the primary
// key level (§4.1 L2CompoundEntry, D15 compound model).
//
// Covers: D8, D15.

TEST(ValidatorU2_7, L2CompoundKeyCollisionRejected) {
  // Identical shape + identical values → collision.
  {
    const std::string doc = make_doc_with_pipeline(
        /*layer_2=*/
        R"({ "id": 1, "src_mac": "aa:bb:cc:dd:ee:ff", "vlan_id": 100, "ethertype": 2048 },
           { "id": 2, "src_mac": "aa:bb:cc:dd:ee:ff", "vlan_id": 100, "ethertype": 2048 })",
        /*layer_3=*/"",
        /*layer_4=*/"",
        /*default_behavior=*/"drop");
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);

    ASSERT_FALSE(v_is_ok(vr))
        << "validator accepted a colliding pair of L2 compound rules";
    EXPECT_EQ(v_get_err(vr).kind, ValidateError::kKeyCollision);
    const auto& msg = v_get_err(vr).message;
    EXPECT_NE(msg.find("layer_2[0]"), std::string::npos)
        << "KeyCollision message must name the first offending index: "
        << msg;
    EXPECT_NE(msg.find("layer_2[1]"), std::string::npos)
        << "KeyCollision message must name the second offending index: "
        << msg;
  }

  // Different active-set (second rule adds dst_mac) → not a collision.
  // This pins "filter_mask bits reflect which fields are active, and
  // two rules with different active-sets are distinguishable".
  {
    const std::string doc = make_doc_with_pipeline(
        /*layer_2=*/
        R"({ "id": 1, "src_mac": "aa:bb:cc:dd:ee:ff", "vlan_id": 100, "ethertype": 2048 },
           { "id": 2, "src_mac": "aa:bb:cc:dd:ee:ff", "vlan_id": 100, "ethertype": 2048, "dst_mac": "11:22:33:44:55:66" })",
        /*layer_3=*/"",
        /*layer_4=*/"",
        /*default_behavior=*/"drop");
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);

    ASSERT_TRUE(v_is_ok(vr))
        << "validator flagged a collision between rules with distinct "
           "active-set (second rule has dst_mac, first does not); kind="
        << static_cast<int>(v_get_err(vr).kind)
        << " msg=" << v_get_err(vr).message;
  }
}

// -------------------------------------------------------------------------
// U2.19 — layer evaluation order enforced by validator.
//
// `next_layer` is an advancement directive. The rule lives in whichever
// pipeline vector contains it (layer_2 / layer_3 / layer_4). A rule in
// `layer_3` with `next_layer: "l2"` is rejected — the pipeline walks
// strictly L2 → L3 → L4 (design §3a.2 / §4.1 schema: `uint8_t
// next_layer; // 0=terminal | 3 | 4`). Strict advancement by one means
// a layer_N rule may only set `next_layer` to layer_{N+1}. Same-layer,
// backward, and skip-ahead are all rejected. A layer_4 rule has no
// next layer at all and may not carry `next_layer`.
//
// Positive subcases pin the contract isn't over-eager:
//   * layer_2 rule + `next_layer: "l3"` → ok
//   * layer_3 rule + `next_layer: "l4"` → ok
//   * any rule with no `next_layer` at all → ok
//
// Covers: F1.

TEST(ValidatorU2_19, LayerEvaluationOrderEnforced) {
  // Negative — backward advancement: layer_3 rule pointing at l2.
  {
    const std::string doc = make_doc_with_pipeline(
        /*layer_2=*/"",
        /*layer_3=*/R"({ "id": 3001, "next_layer": "l2" })",
        /*layer_4=*/"",
        /*default_behavior=*/"drop");
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);

    ASSERT_FALSE(v_is_ok(vr))
        << "validator accepted backward next_layer advancement (l3→l2)";
    EXPECT_EQ(v_get_err(vr).kind, ValidateError::kInvalidLayerTransition);
    const auto& msg = v_get_err(vr).message;
    EXPECT_NE(msg.find("layer_3"), std::string::npos)
        << "InvalidLayerTransition message must name the hosting layer: "
        << msg;
  }

  // Negative — same-layer advancement: layer_3 rule pointing at l3.
  {
    const std::string doc = make_doc_with_pipeline(
        /*layer_2=*/"",
        /*layer_3=*/R"({ "id": 3002, "next_layer": "l3" })",
        /*layer_4=*/"",
        /*default_behavior=*/"drop");
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);

    ASSERT_FALSE(v_is_ok(vr))
        << "validator accepted same-layer next_layer (l3→l3)";
    EXPECT_EQ(v_get_err(vr).kind, ValidateError::kInvalidLayerTransition);
  }

  // Negative — skip-ahead: layer_2 rule pointing at l4.
  {
    const std::string doc = make_doc_with_pipeline(
        /*layer_2=*/R"({ "id": 2001, "next_layer": "l4" })",
        /*layer_3=*/"",
        /*layer_4=*/"",
        /*default_behavior=*/"drop");
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);

    ASSERT_FALSE(v_is_ok(vr))
        << "validator accepted skip-ahead next_layer (l2→l4)";
    EXPECT_EQ(v_get_err(vr).kind, ValidateError::kInvalidLayerTransition);
  }

  // Negative — layer_4 rule with next_layer set to anything. There is
  // no layer beyond L4; the field must be absent.
  {
    const std::string doc = make_doc_with_pipeline(
        /*layer_2=*/"",
        /*layer_3=*/"",
        /*layer_4=*/R"({ "id": 4001, "next_layer": "l4" })",
        /*default_behavior=*/"drop");
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);

    ASSERT_FALSE(v_is_ok(vr))
        << "validator accepted next_layer on a layer_4 rule (no further layer)";
    EXPECT_EQ(v_get_err(vr).kind, ValidateError::kInvalidLayerTransition);
  }

  // Positive — strict +1 advancement: layer_2 → l3.
  {
    const std::string doc = make_doc_with_pipeline(
        /*layer_2=*/R"({ "id": 2002, "next_layer": "l3" })",
        /*layer_3=*/"",
        /*layer_4=*/"",
        /*default_behavior=*/"drop");
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);

    ASSERT_TRUE(v_is_ok(vr))
        << "validator rejected valid next_layer advancement (l2→l3); kind="
        << static_cast<int>(v_get_err(vr).kind)
        << " msg=" << v_get_err(vr).message;
  }

  // Positive — strict +1 advancement: layer_3 → l4.
  {
    const std::string doc = make_doc_with_pipeline(
        /*layer_2=*/"",
        /*layer_3=*/R"({ "id": 3003, "next_layer": "l4" })",
        /*layer_4=*/"",
        /*default_behavior=*/"drop");
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);

    ASSERT_TRUE(v_is_ok(vr))
        << "validator rejected valid next_layer advancement (l3→l4); kind="
        << static_cast<int>(v_get_err(vr).kind)
        << " msg=" << v_get_err(vr).message;
  }

  // Positive — absent next_layer is terminal and always ok.
  {
    const std::string doc = make_doc_with_pipeline(
        /*layer_2=*/"",
        /*layer_3=*/R"({ "id": 3004 })",
        /*layer_4=*/R"({ "id": 4002 })",
        /*default_behavior=*/"drop");
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);

    ASSERT_TRUE(v_is_ok(vr))
        << "validator rejected terminal rules (no next_layer); kind="
        << static_cast<int>(v_get_err(vr).kind)
        << " msg=" << v_get_err(vr).message;
  }
}

// -------------------------------------------------------------------------
// U2.20 — `default_behavior` happy paths.
//
// The parser already enforces `default_behavior ∈ {"allow","drop"}` at
// parse time (parser.cpp ≈ L892-L910). If the AST reaches validate(),
// the value is already one of those two. This test is **documentation**:
// it pins the contract "validator accepts valid default_behavior" so a
// future cycle cannot accidentally add a validator-tier rejection for
// `"allow"` or `"drop"`. Rejection of `"banana"` is parser territory
// and lives in test_parser.cpp (U1.-ish literal-enum negatives).
//
// Covers: D8, F1.

TEST(ValidatorU2_20, DefaultBehaviorEnumHappyPaths) {
  // "allow" accepted.
  {
    const std::string doc = make_doc_with_pipeline(
        /*layer_2=*/"", /*layer_3=*/"", /*layer_4=*/"",
        /*default_behavior=*/"allow");
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);
    ASSERT_TRUE(v_is_ok(vr))
        << "validator rejected default_behavior 'allow'; kind="
        << static_cast<int>(v_get_err(vr).kind)
        << " msg=" << v_get_err(vr).message;
    EXPECT_EQ(cfg.default_behavior,
              ::pktgate::config::DefaultBehavior::kAllow);
  }

  // "drop" accepted.
  {
    const std::string doc = make_doc_with_pipeline(
        /*layer_2=*/"", /*layer_3=*/"", /*layer_4=*/"",
        /*default_behavior=*/"drop");
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);
    ASSERT_TRUE(v_is_ok(vr))
        << "validator rejected default_behavior 'drop'; kind="
        << static_cast<int>(v_get_err(vr).kind)
        << " msg=" << v_get_err(vr).message;
    EXPECT_EQ(cfg.default_behavior,
              ::pktgate::config::DefaultBehavior::kDrop);
  }
}

// -------------------------------------------------------------------------
// U2.8 — Action parameter bounds: dscp 0..63.
//
// The parser already range-checks dscp via `parse_bounded_int(j, "dscp",
// 0, 63, ...)` — values outside [0,63] (including the user writing
// literal -1) are rejected at parse time. The `-1` default in
// ActionTag.dscp is the "absent" sentinel; the parser only writes to
// it when the JSON key is present.
//
// This test is **acceptance-only at the validator tier**: feed dscp
// values 0 and 63 through parse+validate → ok. Rejection of 64/-1
// is parser territory (test_parser.cpp).
//
// Covers: D8, F2 (TAG).

TEST(ValidatorU2_8, DscpBoundsAcceptance) {
  // dscp: 0 → accepted.
  {
    const std::string doc = make_doc_with_pipeline(
        /*layer_2=*/"",
        /*layer_3=*/
        R"({ "id": 800, "action": { "type": "tag", "dscp": 0 } })",
        /*layer_4=*/"",
        /*default_behavior=*/"drop");
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);
    ASSERT_TRUE(v_is_ok(vr))
        << "validator rejected dscp=0; kind="
        << static_cast<int>(v_get_err(vr).kind)
        << " msg=" << v_get_err(vr).message;
  }

  // dscp: 63 → accepted.
  {
    const std::string doc = make_doc_with_pipeline(
        /*layer_2=*/"",
        /*layer_3=*/
        R"({ "id": 801, "action": { "type": "tag", "dscp": 63 } })",
        /*layer_4=*/"",
        /*default_behavior=*/"drop");
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);
    ASSERT_TRUE(v_is_ok(vr))
        << "validator rejected dscp=63; kind="
        << static_cast<int>(v_get_err(vr).kind)
        << " msg=" << v_get_err(vr).message;
  }
}

// -------------------------------------------------------------------------
// U2.9 — Action parameter bounds: pcp 0..7.
//
// Same tier analysis as U2.8: parser enforces [0,7] via
// `parse_bounded_int(j, "pcp", 0, 7, ...)`. Acceptance test only.
//
// Covers: D8, F2.

TEST(ValidatorU2_9, PcpBoundsAcceptance) {
  // pcp: 0 → accepted.
  {
    const std::string doc = make_doc_with_pipeline(
        /*layer_2=*/"",
        /*layer_3=*/
        R"({ "id": 900, "action": { "type": "tag", "pcp": 0 } })",
        /*layer_4=*/"",
        /*default_behavior=*/"drop");
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);
    ASSERT_TRUE(v_is_ok(vr))
        << "validator rejected pcp=0; kind="
        << static_cast<int>(v_get_err(vr).kind)
        << " msg=" << v_get_err(vr).message;
  }

  // pcp: 7 → accepted.
  {
    const std::string doc = make_doc_with_pipeline(
        /*layer_2=*/"",
        /*layer_3=*/
        R"({ "id": 901, "action": { "type": "tag", "pcp": 7 } })",
        /*layer_4=*/"",
        /*default_behavior=*/"drop");
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);
    ASSERT_TRUE(v_is_ok(vr))
        << "validator rejected pcp=7; kind="
        << static_cast<int>(v_get_err(vr).kind)
        << " msg=" << v_get_err(vr).message;
  }
}

// -------------------------------------------------------------------------
// U2.10 — Rate-limit `rate` > 0.
//
// The parser rejects zero-rate ("0bps" → "must be strictly positive")
// and malformed rates ("-10Mbps" → no numeric prefix). Validator gets
// acceptance-only: feed a valid rate-limit action through parse+validate
// → ok.
//
// Covers: D1.

TEST(ValidatorU2_10, RateLimitPositiveAcceptance) {
  const std::string doc = make_doc_with_pipeline(
      /*layer_2=*/"",
      /*layer_3=*/
      R"({ "id": 1000, "action": { "type": "rate-limit", "rate": "200Mbps", "burst_ms": 100 } })",
      /*layer_4=*/"",
      /*default_behavior=*/"drop");
  const ParseResult pr = parse(doc);
  expect_parse_ok(pr, doc);

  Config cfg = get_ok(pr);
  const ValidateResult vr = validate(cfg);
  ASSERT_TRUE(v_is_ok(vr))
      << "validator rejected valid rate-limit action; kind="
      << static_cast<int>(v_get_err(vr).kind)
      << " msg=" << v_get_err(vr).message;
}

// -------------------------------------------------------------------------
// U2.11 — `target_port` must reference a role in `interface_roles`.
//
// This is a cross-reference check. The parser stores the raw role_name
// string on ActionTargetPort / ActionMirror without resolving it. The
// validator must check that `role_name` matches one of the declared
// `Config.interface_roles[*].name` entries. On miss →
// `kUnresolvedTargetPort`.
//
// Both ActionTargetPort and ActionMirror carry the same `role_name`
// field and must both be resolved.
//
// Covers: D5.

TEST(ValidatorU2_11, TargetPortRoleMustResolve) {
  // Positive — `target_port` references an existing role.
  {
    const std::string doc = make_doc_with_pipeline(
        /*layer_2=*/"",
        /*layer_3=*/
        R"({ "id": 1100, "action": { "type": "target-port", "target_port": "upstream_port" } })",
        /*layer_4=*/"",
        /*default_behavior=*/"drop");
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);
    ASSERT_TRUE(v_is_ok(vr))
        << "validator rejected valid target-port referencing existing role; kind="
        << static_cast<int>(v_get_err(vr).kind)
        << " msg=" << v_get_err(vr).message;
  }

  // Negative — `target_port` references a non-existent role.
  {
    const std::string doc = make_doc_with_pipeline(
        /*layer_2=*/"",
        /*layer_3=*/
        R"({ "id": 1101, "action": { "type": "target-port", "target_port": "ghost_port" } })",
        /*layer_4=*/"",
        /*default_behavior=*/"drop");
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);
    ASSERT_FALSE(v_is_ok(vr))
        << "validator accepted target-port referencing nonexistent role";
    EXPECT_EQ(v_get_err(vr).kind, ValidateError::kUnresolvedTargetPort);
    const auto& msg = v_get_err(vr).message;
    EXPECT_NE(msg.find("ghost_port"), std::string::npos)
        << "error message must name the offending role: " << msg;
  }

  // Negative — mirror action's `target_port` must also resolve.
  {
    const std::string doc = make_doc_with_pipeline(
        /*layer_2=*/"",
        /*layer_3=*/
        R"({ "id": 1102, "action": { "type": "mirror", "target_port": "phantom_port" } })",
        /*layer_4=*/"",
        /*default_behavior=*/"drop");
    const ParseResult pr = parse(doc);
    expect_parse_ok(pr, doc);

    Config cfg = get_ok(pr);
    const ValidateResult vr = validate(cfg);
    ASSERT_FALSE(v_is_ok(vr))
        << "validator accepted mirror referencing nonexistent role";
    EXPECT_EQ(v_get_err(vr).kind, ValidateError::kUnresolvedTargetPort);
    const auto& msg = v_get_err(vr).message;
    EXPECT_NE(msg.find("phantom_port"), std::string::npos)
        << "error message must name the offending role: " << msg;
  }
}

// -------------------------------------------------------------------------
// U2.12 — Mirror action accepted syntactically at validator.
//
// The validator must NOT reject `action: mirror` by type. That
// rejection happens at the compiler tier (D7, future U3.17). This
// test verifies that a config with a mirror action whose target_port
// references a valid role passes validation cleanly.
//
// Covers: D7.

TEST(ValidatorU2_12, MirrorAcceptedSyntactically) {
  const std::string doc = make_doc_with_pipeline(
      /*layer_2=*/"",
      /*layer_3=*/
      R"({ "id": 1200, "action": { "type": "mirror", "target_port": "downstream_port" } })",
      /*layer_4=*/"",
      /*default_behavior=*/"drop");
  const ParseResult pr = parse(doc);
  expect_parse_ok(pr, doc);

  Config cfg = get_ok(pr);
  const ValidateResult vr = validate(cfg);
  ASSERT_TRUE(v_is_ok(vr))
      << "validator rejected mirror action (D7: only compiler rejects "
         "mirror in MVP, not validator); kind="
      << static_cast<int>(v_get_err(vr).kind)
      << " msg=" << v_get_err(vr).message;
}

// =========================================================================
// C10 — D37 budget pre-flight (validate_budget).
//
// Five tests: U2.13..U2.17. These exercise the three-gate budget check
// that runs AFTER validate() succeeds and BEFORE the compiler touches
// hugepages. The function `validate_budget()` is separate from
// `validate()` — it's a standalone gate (D37).
//
// Expansion model (heuristic, not exact compiler):
//   * L4 rules: expansion = max(1, rule.dst_ports.size())
//   * L2 / L3 rules: expansion = 1 per rule
// Gate 1: per-rule expansion <= kDefaultPerRuleCeiling (4096).
// Gate 2: aggregate L4 expansion <= sizing.l4_entries_max.
// Gate 3: expected_ruleset_bytes() <= HugepageProbe().available_bytes.
//
// Spy approach: (a) implicit — test is the orchestrator, checks the
// error return and never calls any compile function. See U2.17 comment.
// =========================================================================

using ::pktgate::config::HugepageInfo;
using ::pktgate::config::HugepageProbe;
using ::pktgate::config::kDefaultPerRuleCeiling;
using ::pktgate::config::validate_budget;

// Helper: build a Config directly (bypass parser) with N L4 rules, each
// having `ports_per_rule` entries in dst_ports. Sizing is caller-set.
// All other fields are minimal-valid (version=1, two interface roles,
// default_behavior=drop).
Config make_budget_config_l4(std::size_t n_rules,
                             std::size_t ports_per_rule,
                             ::pktgate::config::Sizing sizing) {
  Config cfg;
  cfg.version = ::pktgate::config::kSchemaVersion;
  cfg.default_behavior = ::pktgate::config::DefaultBehavior::kDrop;
  cfg.sizing = sizing;

  // Two interface roles so any future cross-check doesn't trip.
  cfg.interface_roles.push_back(
      {"upstream_port", ::pktgate::config::PciSelector{"0000:00:00.0"}});
  cfg.interface_roles.push_back(
      {"downstream_port", ::pktgate::config::PciSelector{"0000:00:00.1"}});

  for (std::size_t i = 0; i < n_rules; ++i) {
    ::pktgate::config::Rule r;
    r.id = static_cast<std::int32_t>(i + 1);
    // Fill dst_ports with sequential port numbers.
    r.dst_ports.reserve(ports_per_rule);
    for (std::size_t p = 0; p < ports_per_rule; ++p) {
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

// Tiny hugepage probe for gate 3 testing.
HugepageProbe tiny_probe(std::size_t bytes) {
  return [bytes] { return HugepageInfo{bytes}; };
}

// -------------------------------------------------------------------------
// U2.13 — Budget pre-flight: per-rule expansion ceiling (D37 gate 1).
//
// A single rule with `dst_ports` expanding to 65 536 L4 entries —
// well above the default ceiling of 4 096. validate_budget() must
// return `BudgetPerRuleExceeded` and report the rule id + expansion.
//
// Note: building a 65536-element vector may be slow under ASan.
// We use a smaller but still over-ceiling count (4097) to keep tests
// fast while still exercising the contract "expansion > ceiling".
//
// Covers: D37.

TEST(ValidatorBudgetU2_13, PerRuleExpansionCeilingExceeded) {
  const std::size_t over_ceiling = kDefaultPerRuleCeiling + 1;  // 4097
  auto sizing = ::pktgate::config::kSizingProdDefaults;
  // Make aggregate ceiling generous so gate 2 doesn't fire first.
  sizing.l4_entries_max = 100'000;

  const Config cfg = make_budget_config_l4(/*n_rules=*/1,
                                           /*ports_per_rule=*/over_ceiling,
                                           sizing);
  const ValidateResult vr = validate_budget(cfg, generous_probe());

  ASSERT_FALSE(v_is_ok(vr))
      << "validate_budget accepted a rule expanding to " << over_ceiling
      << " entries (ceiling is " << kDefaultPerRuleCeiling << ")";
  EXPECT_EQ(v_get_err(vr).kind, ValidateError::kBudgetPerRuleExceeded);
  const auto& msg = v_get_err(vr).message;
  // Message must report the rule id and the expansion count.
  EXPECT_NE(msg.find("rule"), std::string::npos) << msg;
  EXPECT_NE(msg.find(std::to_string(over_ceiling)), std::string::npos)
      << "message must report expansion count: " << msg;
}

// -------------------------------------------------------------------------
// U2.14 — Budget pre-flight: aggregate ceiling (D37 gate 2).
//
// 4 rules each expanding to 1 025 L4 entries (total 4 100). With
// `sizing.l4_entries_max = 4096`, aggregate exceeds → error.
//
// Covers: D37.

TEST(ValidatorBudgetU2_14, AggregateCeilingExceeded) {
  auto sizing = ::pktgate::config::kSizingProdDefaults;
  sizing.l4_entries_max = 4096;

  const Config cfg = make_budget_config_l4(/*n_rules=*/4,
                                           /*ports_per_rule=*/1025,
                                           sizing);
  const ValidateResult vr = validate_budget(cfg, generous_probe());

  ASSERT_FALSE(v_is_ok(vr))
      << "validate_budget accepted aggregate expansion 4100 > l4_entries_max=4096";
  EXPECT_EQ(v_get_err(vr).kind, ValidateError::kBudgetAggregateExceeded);
  const auto& msg = v_get_err(vr).message;
  // Message must report the sum.
  EXPECT_NE(msg.find("4100"), std::string::npos)
      << "message must report aggregate expansion sum: " << msg;
}

// -------------------------------------------------------------------------
// U2.15 — Budget pre-flight: hugepage estimate (D37 gate 3).
//
// Mock HugepageProbe returns { available_bytes: 1024 } (tiny). Sizing
// inflated so expected_ruleset_bytes() > 1024. Call → BudgetHugepage.
// Uses a test-only hugepage-probe injection point.
//
// Covers: D37.

TEST(ValidatorBudgetU2_15, HugepageEstimateExceeded) {
  auto sizing = ::pktgate::config::kSizingProdDefaults;
  // Keep l4_entries_max generous so gates 1+2 don't fire.
  sizing.l4_entries_max = 100'000;

  // 100 rules × 10 ports = 1000 L4 entries. Even at 64 bytes each that's
  // 64 KB — well above the 1024-byte mock. The exact threshold doesn't
  // matter; the contract is "estimate > available → error".
  const Config cfg = make_budget_config_l4(/*n_rules=*/100,
                                           /*ports_per_rule=*/10,
                                           sizing);
  const ValidateResult vr = validate_budget(cfg, tiny_probe(1024));

  ASSERT_FALSE(v_is_ok(vr))
      << "validate_budget accepted a config whose estimated bytes exceed "
         "the mocked 1024-byte hugepage budget";
  EXPECT_EQ(v_get_err(vr).kind, ValidateError::kBudgetHugepage);
  const auto& msg = v_get_err(vr).message;
  // Message must report estimated vs available.
  EXPECT_NE(msg.find("1024"), std::string::npos)
      << "message must report available hugepage bytes: " << msg;
}

// -------------------------------------------------------------------------
// U2.16 — Budget pre-flight: false-positive negative test.
//
// 100 rules each expanding to 30 entries (3 000 total). Well under
// kDefaultPerRuleCeiling (4096) and under sizing.l4_entries_max (4096).
// Generous hugepages. validate_budget() must succeed.
//
// Covers: D37.

TEST(ValidatorBudgetU2_16, FalsePositiveNegativeTest) {
  auto sizing = ::pktgate::config::kSizingProdDefaults;
  sizing.l4_entries_max = 4096;

  const Config cfg = make_budget_config_l4(/*n_rules=*/100,
                                           /*ports_per_rule=*/30,
                                           sizing);
  const ValidateResult vr = validate_budget(cfg, generous_probe());

  ASSERT_TRUE(v_is_ok(vr))
      << "validate_budget rejected 100×30=3000 entries (well under 4096); kind="
      << static_cast<int>(v_get_err(vr).kind)
      << " msg=" << v_get_err(vr).message;
}

// -------------------------------------------------------------------------
// U2.17 — Validator short-circuits on first budget failure.
//
// Same config as U2.13 (gate 1 fails). Assert is_error(result).
// Implicit short-circuit: the test is the orchestrator — it checks
// the error return and never proceeds to any compile function. This
// is approach (a) from the spec. A comment documents the implicit
// contract: "caller would not proceed to compile on error."
//
// Covers: D37.

TEST(ValidatorBudgetU2_17, ShortCircuitsOnBudgetFailure) {
  const std::size_t over_ceiling = kDefaultPerRuleCeiling + 1;
  auto sizing = ::pktgate::config::kSizingProdDefaults;
  sizing.l4_entries_max = 100'000;

  const Config cfg = make_budget_config_l4(/*n_rules=*/1,
                                           /*ports_per_rule=*/over_ceiling,
                                           sizing);
  const ValidateResult vr = validate_budget(cfg, generous_probe());

  // Implicit short-circuit — the caller (this test, or the future M10
  // reload orchestrator) checks the result and never proceeds to the
  // compile stage on error. No explicit compiler spy needed: the test
  // IS the orchestrator and it stops here.
  ASSERT_FALSE(v_is_ok(vr))
      << "validate_budget must return an error for over-ceiling expansion; "
         "compile spy is implicit — caller would not proceed to compile";
  // The error kind should be gate 1 (first gate to fire).
  EXPECT_EQ(v_get_err(vr).kind, ValidateError::kBudgetPerRuleExceeded);
}

}  // namespace
