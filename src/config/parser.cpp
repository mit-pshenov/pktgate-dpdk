// src/config/parser.cpp
//
// M1 C1 GREEN — minimal strict parser. Handles exactly the fields
// U1.1 / U1.2 / U1.3 touch:
//
//   * JSON syntax errors caught and translated to kJsonSyntax.
//   * Strict top-level whitelist (D8). Any unrecognised key → kUnknownField.
//   * Strict version equality with kSchemaVersion (D8 / Q11) → kVersionMismatch.
//   * Two PCI interface_roles (upstream_port / downstream_port).
//     The full sum-type (vdev/name, mixed-keys reject) lands in C2.
//   * `default_behavior` enum-bounded to {allow, drop}.
//   * Empty `pipeline.layer_{2,3,4}` — layer rule vectors are C3+.
//   * Missing `fragment_policy` defaults to kL3Only (D17/P9).
//
// The whitelist includes `sizing` and `objects` so later cycles can
// extend the parser without touching C1-era tests. They're silently
// ignored here and get real bodies in C6 / C6 respectively.
//
// No allocations on the happy path is an M1 aspiration, not a C1 gate —
// nlohmann::json and std::string already allocate. The zero-alloc goal
// applies to the runtime hot path, not the control-plane parser.

#include "src/config/parser.h"

#include <nlohmann/json.hpp>

#include "src/config/sizing.h"

#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace pktgate::config {

namespace {

using json = nlohmann::json;

// Top-level key whitelist. Any key outside this set triggers kUnknownField.
// Keep this in sync with model.h — when a new top-level field lands (e.g.
// `sizing` in C6), add it here first, then wire its consumer.
constexpr std::array<std::string_view, 8> kAllowedTopKeys = {
    "version",          // required (D8 strict equality)
    "interface_roles",  // required (D5)
    "pipeline",         // required (empty in C1; layer_2/3/4 in C3+)
    "default_behavior", // required enum
    "fragment_policy",  // optional (D17/P9 default l3_only)
    "sizing",           // optional (C6)
    "objects",          // optional (C6)
    "cmd_socket",       // optional (C7/D38 schema-only)
};

// Tiny helper: build a ParseError in one expression.
ParseError make_err(ParseError::Kind k, std::string msg) {
  return ParseError{k, std::move(msg)};
}

// -------------------------------------------------------------------------
// Int-range scalar parse helper (C4). Common code for dst_port /
// vlan_id / pcp and every future bounded integer field. Returns
// nullopt on success (value written to `out`); returns a ParseError
// otherwise. The error message names the offending field so operators
// can jump straight to the typo.
//
// Contract:
//   * field must be an integer JSON value → else kTypeMismatch
//   * field value must be in `[lo, hi]` (inclusive) → else kOutOfRange
//
// Intentionally signed: callers (U1.17/U1.18/U1.19) need the range
// check to reject negatives *explicitly*. A uint narrow here would
// fold -1 into 0xffff_ffff before we ever saw it.
std::optional<ParseError> parse_bounded_int(const json& container,
                                            const char* field,
                                            std::int32_t lo,
                                            std::int32_t hi,
                                            std::int32_t& out) {
  const json& v = container[field];
  if (!v.is_number_integer()) {
    return make_err(ParseError::kTypeMismatch,
                    std::string{"rule field '"} + field +
                        "' must be an integer");
  }
  // Pull as signed 64-bit so negative and above-i32 values both reach
  // the range check in one step.
  const std::int64_t raw = v.get<std::int64_t>();
  if (raw < static_cast<std::int64_t>(lo) ||
      raw > static_cast<std::int64_t>(hi)) {
    return make_err(ParseError::kOutOfRange,
                    std::string{"rule field '"} + field + "' = " +
                        std::to_string(raw) + " out of range [" +
                        std::to_string(lo) + ".." + std::to_string(hi) + "]");
  }
  out = static_cast<std::int32_t>(raw);
  return std::nullopt;
}

// -------------------------------------------------------------------------
// Int-array parse helper (C4, U1.20). Every element is validated
// against `[lo, hi]` via the same bounded-int contract. Used by
// `dst_ports` and by any future list-valued numeric field.
//
// A non-array top-level value → kTypeMismatch.
// Any element failing the bounds check → kOutOfRange, short-circuit.
std::optional<ParseError> parse_bounded_int_array(
    const json& container, const char* field, std::int32_t lo,
    std::int32_t hi, std::vector<std::int32_t>& out) {
  const json& v = container[field];
  if (!v.is_array()) {
    return make_err(ParseError::kTypeMismatch,
                    std::string{"rule field '"} + field +
                        "' must be a JSON array of integers");
  }
  out.clear();
  out.reserve(v.size());
  for (std::size_t i = 0; i < v.size(); ++i) {
    const json& e = v[i];
    if (!e.is_number_integer()) {
      return make_err(ParseError::kTypeMismatch,
                      std::string{"rule field '"} + field +
                          "' element " + std::to_string(i) +
                          " must be an integer");
    }
    const std::int64_t raw = e.get<std::int64_t>();
    if (raw < static_cast<std::int64_t>(lo) ||
        raw > static_cast<std::int64_t>(hi)) {
      return make_err(
          ParseError::kOutOfRange,
          std::string{"rule field '"} + field + "' element " +
              std::to_string(i) + " = " + std::to_string(raw) +
              " out of range [" + std::to_string(lo) + ".." +
              std::to_string(hi) + "]");
    }
    out.push_back(static_cast<std::int32_t>(raw));
  }
  return std::nullopt;
}

// -------------------------------------------------------------------------
// parse_rate (C5, D1). Converts a rate literal like "200Mbps" / "1Gbps"
// / "64kbps" to a bytes/sec integer. This is the load-time conversion
// the D1 anchor mandates — the runtime hot path MUST NEVER parse the
// string or redo the multiply. Returns std::nullopt on success
// (value written to `out`) and kBadRate on any parse failure.
//
// Grammar: `<positive-integer><unit>` where unit is exactly one of
// `kbps`, `Mbps`, `Gbps`. No whitespace, no floats, no bytes/sec. The
// unit is deliberately case-sensitive to avoid silent typos (`gbps`
// vs `Gbps` vs `GBps`): operators should get a crisp error rather
// than a 125x overread.
//
// Multipliers are SI decimal (1 Mbps = 10^6 bits/sec, per ITU-T),
// divided by 8 to land on bytes/sec:
//   kbps → 1000/8   = 125   bytes/sec per unit
//   Mbps → 1e6/8    = 125_000   bytes/sec per unit
//   Gbps → 1e9/8    = 125_000_000 bytes/sec per unit
std::optional<ParseError> parse_rate(std::string_view spec,
                                     std::uint64_t& out) {
  // Extract leading digits.
  std::size_t digit_end = 0;
  while (digit_end < spec.size() &&
         std::isdigit(static_cast<unsigned char>(spec[digit_end]))) {
    ++digit_end;
  }
  if (digit_end == 0) {
    return make_err(ParseError::kBadRate,
                    std::string{"rate '"} + std::string{spec} +
                        "' has no numeric prefix");
  }

  // Parse the digit run into an unsigned 64-bit.
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < digit_end; ++i) {
    const std::uint64_t digit = static_cast<std::uint64_t>(spec[i] - '0');
    // Simple overflow guard: 10^18 is well under UINT64_MAX so any
    // reasonable rate spec fits. Anything bigger is malformed input.
    if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
      return make_err(ParseError::kBadRate,
                      std::string{"rate '"} + std::string{spec} + "' overflows");
    }
    value = value * 10 + digit;
  }
  if (value == 0) {
    return make_err(ParseError::kBadRate,
                    std::string{"rate '"} + std::string{spec} +
                        "' must be strictly positive");
  }

  // Unit suffix — must be present and one of the three allowed forms.
  const std::string_view unit = spec.substr(digit_end);
  std::uint64_t bits_per_unit = 0;
  if (unit == "kbps") {
    bits_per_unit = 1000ull;
  } else if (unit == "Mbps") {
    bits_per_unit = 1000ull * 1000ull;
  } else if (unit == "Gbps") {
    bits_per_unit = 1000ull * 1000ull * 1000ull;
  } else {
    return make_err(ParseError::kBadRate,
                    std::string{"rate '"} + std::string{spec} +
                        "' has unknown or missing unit (expected kbps/Mbps/Gbps)");
  }

  // Convert to bytes/sec. Multiply first, then /8 — the inputs are
  // small enough to never overflow (max 1 Tbps worth = 1.25e11 bytes/sec).
  const std::uint64_t bits_per_sec = value * bits_per_unit;
  out = bits_per_sec / 8ull;
  return std::nullopt;
}

// -------------------------------------------------------------------------
// parse_action (C5, D15 exactly-one, D7 mirror-accept).
//
// The action object has a required `type` string field discriminating
// the variant. Additional fields are variant-specific and strictly
// whitelisted per type — anything outside that whitelist is a
// sum-type violation (kAmbiguousAction) because it names a field
// that belongs to a different variant.
//
// C5 scope: `allow`, `drop`, `rate-limit` for real. `tag`,
// `target-port`, `mirror` are scaffolded so the variant sum is
// complete and operators get a principled error if they try to
// use them before the validator lands — but they're parser-
// accepted, as D7 mandates for mirror.
std::optional<ParseError> parse_action(const json& j, RuleAction& out) {
  if (!j.is_object()) {
    return make_err(ParseError::kTypeMismatch,
                    "rule 'action' must be a JSON object");
  }

  // `type` is the discriminator. Missing or non-string → sum-type
  // violation expressed as kAmbiguousAction (zero variants selected).
  if (!j.contains("type")) {
    return make_err(ParseError::kAmbiguousAction,
                    "rule 'action' missing required 'type' discriminator");
  }
  if (!j["type"].is_string()) {
    return make_err(ParseError::kTypeMismatch,
                    "rule 'action.type' must be a string");
  }
  const std::string type = j["type"].get<std::string>();

  // Per-variant whitelist. Any key in `j` outside the union of
  // {"type"} and the variant-specific whitelist is a sum-type
  // violation → kAmbiguousAction. This is what catches the U1.29
  // `{ type: "allow", target_port: "x" }` case.
  auto check_whitelist = [&](std::initializer_list<std::string_view> allowed)
      -> std::optional<ParseError> {
    for (auto it = j.begin(); it != j.end(); ++it) {
      const std::string& key = it.key();
      if (key == "type") continue;
      bool ok = false;
      for (const auto& w : allowed) {
        if (key == w) {
          ok = true;
          break;
        }
      }
      if (!ok) {
        return make_err(
            ParseError::kAmbiguousAction,
            std::string{"rule 'action' has field '"} + key +
                "' that does not belong to variant '" + type +
                "' (sum-type violation, exactly-one per D15)");
      }
    }
    return std::nullopt;
  };

  if (type == "allow") {
    if (auto err = check_whitelist({})) return *err;
    out = ActionAllow{};
    return std::nullopt;
  }
  if (type == "drop") {
    if (auto err = check_whitelist({})) return *err;
    out = ActionDrop{};
    return std::nullopt;
  }
  if (type == "rate-limit") {
    if (auto err = check_whitelist({"rate", "burst_ms"})) return *err;
    if (!j.contains("rate")) {
      return make_err(ParseError::kBadRate,
                      "rate-limit action missing 'rate' field");
    }
    if (!j["rate"].is_string()) {
      return make_err(ParseError::kTypeMismatch,
                      "rate-limit 'rate' must be a string (e.g. '200Mbps')");
    }
    ActionRateLimit rl{};
    if (auto err = parse_rate(j["rate"].get<std::string>(), rl.bytes_per_sec)) {
      return *err;
    }
    if (!j.contains("burst_ms")) {
      return make_err(ParseError::kBadRate,
                      "rate-limit action missing 'burst_ms' field");
    }
    if (!j["burst_ms"].is_number_integer()) {
      return make_err(ParseError::kTypeMismatch,
                      "rate-limit 'burst_ms' must be an integer");
    }
    const std::int64_t burst_ms = j["burst_ms"].get<std::int64_t>();
    if (burst_ms <= 0) {
      return make_err(ParseError::kOutOfRange,
                      "rate-limit 'burst_ms' must be strictly positive");
    }
    // D1: derive burst_bytes at load time. burst_bytes = bytes/sec * ms / 1000.
    rl.burst_bytes = rl.bytes_per_sec *
                     static_cast<std::uint64_t>(burst_ms) / 1000ull;
    out = rl;
    return std::nullopt;
  }
  if (type == "tag") {
    if (auto err = check_whitelist({"dscp", "pcp"})) return *err;
    ActionTag tag{};
    if (j.contains("dscp")) {
      if (auto err = parse_bounded_int(j, "dscp", 0, 63, tag.dscp)) {
        return *err;
      }
    }
    if (j.contains("pcp")) {
      if (auto err = parse_bounded_int(j, "pcp", 0, 7, tag.pcp)) {
        return *err;
      }
    }
    out = tag;
    return std::nullopt;
  }
  if (type == "target-port") {
    if (auto err = check_whitelist({"target_port"})) return *err;
    if (!j.contains("target_port") || !j["target_port"].is_string()) {
      return make_err(ParseError::kTypeMismatch,
                      "target-port action requires string 'target_port'");
    }
    out = ActionTargetPort{j["target_port"].get<std::string>()};
    return std::nullopt;
  }
  if (type == "mirror") {
    // D7: parser-accept, compiler/validator rejects in MVP.
    if (auto err = check_whitelist({"target_port"})) return *err;
    if (!j.contains("target_port") || !j["target_port"].is_string()) {
      return make_err(ParseError::kTypeMismatch,
                      "mirror action requires string 'target_port'");
    }
    out = ActionMirror{j["target_port"].get<std::string>()};
    return std::nullopt;
  }

  return make_err(ParseError::kBadEnum,
                  std::string{"unknown action type: '"} + type + "'");
}

// -------------------------------------------------------------------------
// parse_tcp_flags (C5, D15). Each recognised flag key (syn, ack, fin,
// rst, psh, urg, ece, cwr) toggles bits in (mask, want) per the
// invariant in model.h. Absent keys = don't care. Empty object = no
// constraints (mask = want = 0). Non-boolean values → kTypeMismatch.
std::optional<ParseError> parse_tcp_flags(const json& j, TcpFlags& out) {
  if (!j.is_object()) {
    return make_err(ParseError::kTypeMismatch,
                    "rule 'tcp_flags' must be a JSON object");
  }
  struct FlagBit {
    std::string_view key;
    std::uint8_t bit;
  };
  constexpr FlagBit kFlags[] = {
      {"fin", 0x01}, {"syn", 0x02}, {"rst", 0x04}, {"psh", 0x08},
      {"ack", 0x10}, {"urg", 0x20}, {"ece", 0x40}, {"cwr", 0x80},
  };
  out = TcpFlags{};
  for (auto it = j.begin(); it != j.end(); ++it) {
    const std::string& key = it.key();
    const FlagBit* match = nullptr;
    for (const auto& f : kFlags) {
      if (key == f.key) {
        match = &f;
        break;
      }
    }
    if (!match) {
      return make_err(ParseError::kUnknownField,
                      std::string{"tcp_flags unknown flag: '"} + key + "'");
    }
    if (!it.value().is_boolean()) {
      return make_err(ParseError::kTypeMismatch,
                      std::string{"tcp_flags '"} + key + "' must be boolean");
    }
    // Always set the mask bit — the key's mere presence is a constraint.
    out.mask = static_cast<std::uint8_t>(out.mask | match->bit);
    if (it.value().get<bool>()) {
      // True: also set the want bit. Invariant (want & ~mask)==0 is
      // preserved because we set mask first.
      out.want = static_cast<std::uint8_t>(out.want | match->bit);
    }
    // False: leave want bit clear — "must be clear" constraint.
  }
  return std::nullopt;
}

// -------------------------------------------------------------------------
// Parse a single Rule object. C4 knew about dst_port / dst_ports /
// vlan_id / pcp. C5 adds: id (required positive int), action (D15
// exactly-one variant), hw_offload_hint (D4 optional bool), tcp_flags
// (D15 mask/want sub-object). Every other key → kUnknownField.
std::optional<ParseError> parse_rule(const json& j, Rule& out) {
  if (!j.is_object()) {
    return make_err(ParseError::kTypeMismatch,
                    "pipeline rule entry must be a JSON object");
  }

  // Strict per-rule whitelist. C5 adds id/action/hw_offload_hint/tcp_flags.
  // C6.5 adds src_subnet (U1.28 — unresolved object reference).
  // C7 adds `interface` (U2.3/U2.4 — unresolved interface_roles ref,
  // resolution happens in the C7 validator).
  // C7.6 adds the L2 compound key trio + `next_layer` (U1.33/U1.34/
  // U1.35). These were a latent plan-drift gap: C1-C6 never landed
  // them because no U1 test exercised them, and C8 (compound
  // collision / layer order) needs them in the AST. The parser
  // stores them verbatim; L2CompoundEntry filter_mask derivation
  // (design §4.1) happens at M2 compile time, NOT here — there is
  // deliberately no `filter_mask` JSON field.
  constexpr std::array<std::string_view, 14> kAllowedRuleKeys = {
      "id",         "dst_port",        "dst_ports",  "vlan_id",
      "pcp",        "hw_offload_hint", "tcp_flags",  "action",
      "src_subnet", "interface",       "src_mac",    "dst_mac",
      "ethertype",  "next_layer"};
  for (auto it = j.begin(); it != j.end(); ++it) {
    const std::string& key = it.key();
    bool allowed = false;
    for (const auto& w : kAllowedRuleKeys) {
      if (key == w) {
        allowed = true;
        break;
      }
    }
    if (!allowed) {
      return make_err(ParseError::kUnknownField,
                      std::string{"unknown rule field: '"} + key + "'");
    }
  }

  // C5 U1.24 — rule id required, positive integer. Enforced here
  // rather than downstream because the parser's job is to reject
  // structurally invalid input; duplicate-id detection (C8) is a
  // validator concern. Type mismatch ("42") wins over missing so the
  // error message is the most specific available.
  if (!j.contains("id")) {
    return make_err(ParseError::kUnknownField,
                    "missing required rule field: 'id'");
  }
  if (!j["id"].is_number_integer()) {
    return make_err(ParseError::kTypeMismatch,
                    "rule field 'id' must be an integer");
  }
  {
    const std::int64_t raw = j["id"].get<std::int64_t>();
    if (raw < 1 ||
        raw > static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::max())) {
      return make_err(ParseError::kOutOfRange,
                      std::string{"rule field 'id' = "} + std::to_string(raw) +
                          " must be a positive integer");
    }
    out.id = static_cast<std::int32_t>(raw);
  }

  if (j.contains("dst_port")) {
    if (auto err =
            parse_bounded_int(j, "dst_port", 0, 65535, out.dst_port)) {
      return *err;
    }
  }
  if (j.contains("dst_ports")) {
    if (auto err = parse_bounded_int_array(j, "dst_ports", 0, 65535,
                                           out.dst_ports)) {
      return *err;
    }
  }
  if (j.contains("vlan_id")) {
    if (auto err = parse_bounded_int(j, "vlan_id", 0, 4095, out.vlan_id)) {
      return *err;
    }
  }
  if (j.contains("pcp")) {
    if (auto err = parse_bounded_int(j, "pcp", 0, 7, out.pcp)) {
      return *err;
    }
  }

  // C5 U1.23 — hw_offload_hint: optional, defaults false (D4).
  if (j.contains("hw_offload_hint")) {
    if (!j["hw_offload_hint"].is_boolean()) {
      return make_err(ParseError::kTypeMismatch,
                      "rule field 'hw_offload_hint' must be boolean");
    }
    out.hw_offload_hint = j["hw_offload_hint"].get<bool>();
  }

  // C5 U1.30 — tcp_flags sub-object (D15).
  if (j.contains("tcp_flags")) {
    TcpFlags tf{};
    if (auto err = parse_tcp_flags(j["tcp_flags"], tf)) {
      return *err;
    }
    out.tcp_flags = tf;
  }

  // C5 U1.29 — action variant (D15 exactly-one). Optional at parser
  // tier; the validator (C7+) decides whether the absence is fatal.
  if (j.contains("action")) {
    RuleAction act;
    if (auto err = parse_action(j["action"], act)) {
      return *err;
    }
    out.action = act;
  }

  // C6.5 U1.28 — `src_subnet` unresolved object reference. Parser
  // stores the raw name verbatim in a SubnetRef; validator (C8) maps
  // it to an entry in `objects.subnets`. The parser stays dumb:
  // empty-string and dangling-name detection are not our business.
  // Only the structural type-check is enforced here.
  if (j.contains("src_subnet")) {
    const json& v = j["src_subnet"];
    if (!v.is_string()) {
      return make_err(ParseError::kTypeMismatch,
                      "rule field 'src_subnet' must be a string "
                      "(object reference into objects.subnets)");
    }
    out.src_subnet = SubnetRef{v.get<std::string>()};
  }

  // C7 U2.3/U2.4 — `interface` unresolved role reference. Parser
  // stores the raw name verbatim; the C7 validator maps it to an
  // entry in `Config.interface_roles`. Parser stays dumb: only the
  // structural type-check is enforced here (dangling detection is
  // not parser business).
  if (j.contains("interface")) {
    const json& v = j["interface"];
    if (!v.is_string()) {
      return make_err(ParseError::kTypeMismatch,
                      "rule field 'interface' must be a string "
                      "(role reference into interface_roles)");
    }
    out.interface_ref = v.get<std::string>();
  }

  // C7.6 U1.33/U1.34 — L2 compound key fields. `src_mac` / `dst_mac`
  // go through the pure-stdlib parse_mac from addr.h; the
  // AddrParseError variants collapse into the parser-facing
  // `kBadMac` kind. We deliberately surface the offending literal
  // in the diagnostic so operators can jump to the typo. The raw
  // MAC bytes land on Rule; filter_mask derivation is a compiler-
  // side concern (design §4.1 L2CompoundEntry), NOT a JSON field.
  if (j.contains("src_mac")) {
    const json& v = j["src_mac"];
    if (!v.is_string()) {
      return make_err(ParseError::kTypeMismatch,
                      "rule field 'src_mac' must be a string "
                      "(colon-separated 6-octet MAC)");
    }
    const std::string lit = v.get<std::string>();
    const auto res = parse_mac(lit);
    if (!is_ok(res)) {
      return make_err(ParseError::kBadMac,
                      std::string{"rule field 'src_mac' invalid MAC literal: '"} +
                          lit + "'");
    }
    out.src_mac = std::get<Mac>(res);
  }

  if (j.contains("dst_mac")) {
    const json& v = j["dst_mac"];
    if (!v.is_string()) {
      return make_err(ParseError::kTypeMismatch,
                      "rule field 'dst_mac' must be a string "
                      "(colon-separated 6-octet MAC)");
    }
    const std::string lit = v.get<std::string>();
    const auto res = parse_mac(lit);
    if (!is_ok(res)) {
      return make_err(ParseError::kBadMac,
                      std::string{"rule field 'dst_mac' invalid MAC literal: '"} +
                          lit + "'");
    }
    out.dst_mac = std::get<Mac>(res);
  }

  // `ethertype` — 16-bit unsigned; nlohmann::json gives us int64,
  // so we range-check through i64 to reject negatives and >0xFFFF
  // explicitly rather than silently truncating via a uint narrow.
  // Common values: 0x0800 IPv4, 0x86DD IPv6, 0x8100 VLAN, 0x88A8
  // QinQ. Type-check before range-check so an operator typo like
  // `"0x0800"` (string) surfaces kTypeMismatch rather than a
  // confusing "out of range" for an unparsed numeric.
  if (j.contains("ethertype")) {
    const json& v = j["ethertype"];
    if (!v.is_number_integer()) {
      return make_err(ParseError::kTypeMismatch,
                      "rule field 'ethertype' must be an integer "
                      "in [0..65535]");
    }
    const std::int64_t raw = v.get<std::int64_t>();
    if (raw < 0 || raw > 0xFFFF) {
      return make_err(
          ParseError::kOutOfRange,
          std::string{"rule field 'ethertype' = "} + std::to_string(raw) +
              " out of range [0..65535]");
    }
    out.ethertype = static_cast<std::uint16_t>(raw);
  }

  // C7.6 U1.35 — `next_layer` enum. Parser validates the value
  // space only; cross-layer ordering ("l2 on a layer_3 rule is
  // illegal") is the C8 validator's job (U2.19). Pattern mirrors
  // `default_behavior` and `fragment_policy`.
  if (j.contains("next_layer")) {
    const json& v = j["next_layer"];
    if (!v.is_string()) {
      return make_err(ParseError::kTypeMismatch,
                      "rule field 'next_layer' must be a string enum "
                      "('l2' | 'l3' | 'l4')");
    }
    const std::string nl = v.get<std::string>();
    if (nl == "l2") {
      out.next_layer = NextLayer::kL2;
    } else if (nl == "l3") {
      out.next_layer = NextLayer::kL3;
    } else if (nl == "l4") {
      out.next_layer = NextLayer::kL4;
    } else {
      return make_err(
          ParseError::kBadEnum,
          std::string{"rule field 'next_layer' must be 'l2'|'l3'|'l4', got '"} +
              nl + "'");
    }
  }
  return std::nullopt;
}

// -------------------------------------------------------------------------
// parse_cmd_socket (C7, D38 schema-only; C7.5 defers resolution).
// The section is strictly whitelisted: only `allow_gids` is
// recognised. Absent key leaves `out.allow_gids = nullopt`; that
// sentinel means "resolve at daemon init (M11)". Neither the parser
// nor the validator ever invokes `::getgid()` / `::getgrnam()` / any
// gid-resolution syscall — see the model.h CmdSocket comment for
// the offline `--validate-config` drift argument.
std::optional<ParseError> parse_cmd_socket(const json& j, CmdSocket& out) {
  if (!j.is_object()) {
    return make_err(ParseError::kTypeMismatch,
                    "top-level 'cmd_socket' must be a JSON object");
  }

  // Strict per-cmd_socket whitelist. Any unknown key → kUnknownField.
  constexpr std::array<std::string_view, 1> kAllowedCmdSocketKeys = {
      "allow_gids"};
  for (auto it = j.begin(); it != j.end(); ++it) {
    const std::string& key = it.key();
    bool allowed = false;
    for (const auto& w : kAllowedCmdSocketKeys) {
      if (key == w) {
        allowed = true;
        break;
      }
    }
    if (!allowed) {
      return make_err(ParseError::kUnknownField,
                      std::string{"unknown cmd_socket field: '"} + key + "'");
    }
  }

  if (!j.contains("allow_gids")) {
    // Field absent — leave the optional empty so the validator's
    // default path kicks in.
    out.allow_gids.reset();
    return std::nullopt;
  }

  const json& v = j["allow_gids"];
  if (!v.is_array()) {
    return make_err(ParseError::kTypeMismatch,
                    "'cmd_socket.allow_gids' must be a JSON array of "
                    "non-negative integers");
  }

  // Element type is ::gid_t (POSIX, unsigned on every Linux libc).
  // We still parse through int64_t so we can reject negative JSON
  // numbers explicitly — the cast to an unsigned `gid_t` would
  // silently wrap otherwise. Upper bound is uint32_t::max: ::gid_t
  // is 32-bit on every libc we target (glibc, musl) and making the
  // wire format tolerate a 64-bit gid would be meaningless.
  std::vector<::gid_t> gids;
  gids.reserve(v.size());
  for (std::size_t i = 0; i < v.size(); ++i) {
    const json& e = v[i];
    if (!e.is_number_integer()) {
      return make_err(ParseError::kTypeMismatch,
                      std::string{"'cmd_socket.allow_gids' element "} +
                          std::to_string(i) +
                          " must be an integer");
    }
    const std::int64_t raw = e.get<std::int64_t>();
    if (raw < 0 ||
        raw > static_cast<std::int64_t>(
                  std::numeric_limits<std::uint32_t>::max())) {
      return make_err(
          ParseError::kOutOfRange,
          std::string{"'cmd_socket.allow_gids' element "} +
              std::to_string(i) + " = " + std::to_string(raw) +
              " out of range [0..4294967295]");
    }
    gids.push_back(static_cast<::gid_t>(raw));
  }
  out.allow_gids = std::move(gids);
  return std::nullopt;
}

// Parse a layer rule array into a destination vector.
std::optional<ParseError> parse_rule_array(const json& arr,
                                           const char* layer_name,
                                           std::vector<Rule>& out) {
  if (!arr.is_array()) {
    return make_err(ParseError::kTypeMismatch,
                    std::string{"'pipeline."} + layer_name +
                        "' must be an array");
  }
  out.reserve(out.size() + arr.size());
  for (const auto& el : arr) {
    Rule r;
    if (auto err = parse_rule(el, r); err) {
      return *err;
    }
    out.push_back(std::move(r));
  }
  return std::nullopt;
}

// Parse a single role entry. C2 covers the full sum-type (D5):
// exactly one of {pci, vdev, name} must be present. Zero keys or two+
// keys → kInvalidRoleSelector. The three branches are mutually
// exclusive and the rejection message names every offending key so the
// operator can jump to the typo.
std::optional<ParseError> parse_role_selector(const json& j,
                                              RoleSelector& out) {
  if (!j.is_object()) {
    return make_err(ParseError::kTypeMismatch,
                    "interface_roles entry must be a JSON object");
  }

  // Inventory of recognised selector keys present in this entry.
  // Order matches the declared variant alternatives so diagnostics are
  // stable.
  constexpr std::array<std::string_view, 3> kSelectorKeys = {
      "pci", "vdev", "name"};

  int present_count = 0;
  std::string present_list;
  for (const auto& key : kSelectorKeys) {
    if (j.contains(std::string{key})) {
      ++present_count;
      if (!present_list.empty()) present_list += ", ";
      present_list += "'";
      present_list += key;
      present_list += "'";
    }
  }

  if (present_count == 0) {
    return make_err(ParseError::kInvalidRoleSelector,
                    "interface_roles entry missing selector: one of "
                    "'pci', 'vdev', 'name' required");
  }
  if (present_count > 1) {
    return make_err(
        ParseError::kInvalidRoleSelector,
        std::string{"interface_roles entry has mixed selector keys: "} +
            present_list +
            " (exactly one of 'pci', 'vdev', 'name' allowed)");
  }

  // Exactly one selector key is present — dispatch on it.
  if (j.contains("pci")) {
    if (!j["pci"].is_string()) {
      return make_err(ParseError::kTypeMismatch,
                      "interface_roles 'pci' must be a string");
    }
    out = PciSelector{j["pci"].get<std::string>()};
    return std::nullopt;
  }
  if (j.contains("vdev")) {
    if (!j["vdev"].is_string()) {
      return make_err(ParseError::kTypeMismatch,
                      "interface_roles 'vdev' must be a string");
    }
    out = VdevSelector{j["vdev"].get<std::string>()};
    return std::nullopt;
  }
  // Must be "name" — guaranteed by present_count == 1 and the branches
  // above not matching.
  if (!j["name"].is_string()) {
    return make_err(ParseError::kTypeMismatch,
                    "interface_roles 'name' must be a string");
  }
  out = NameSelector{j["name"].get<std::string>()};
  return std::nullopt;
}

}  // namespace

ParseResult parse(std::string_view json_text) {
  // ---- 1. JSON syntax ---------------------------------------------------
  json doc;
  try {
    doc = json::parse(json_text);
  } catch (const json::parse_error& e) {
    return make_err(ParseError::kJsonSyntax,
                    std::string{"JSON syntax error: "} + e.what());
  }

  if (!doc.is_object()) {
    return make_err(ParseError::kTypeMismatch,
                    "top-level JSON value must be an object");
  }

  // ---- 2. Strict top-level whitelist (D8) -------------------------------
  //
  // Walk every key in the document and reject the first one not on the
  // whitelist. This is the line that makes U1.3 green — the `foo` field
  // fails here, named in the error message so an operator can jump to it.
  for (auto it = doc.begin(); it != doc.end(); ++it) {
    const std::string& key = it.key();
    bool allowed = false;
    for (const auto& whitelisted : kAllowedTopKeys) {
      if (key == whitelisted) {
        allowed = true;
        break;
      }
    }
    if (!allowed) {
      return make_err(ParseError::kUnknownField,
                      std::string{"unknown top-level field: '"} + key + "'");
    }
  }

  // ---- 3. Strict version equality (D8 / Q11) ----------------------------
  if (!doc.contains("version")) {
    return make_err(ParseError::kUnknownField,
                    "missing required top-level field: 'version'");
  }
  if (!doc["version"].is_number_integer()) {
    return make_err(ParseError::kTypeMismatch,
                    "top-level 'version' must be an integer");
  }
  const int received_version = doc["version"].get<int>();
  if (received_version != kSchemaVersion) {
    return make_err(
        ParseError::kVersionMismatch,
        std::string{"schema version mismatch: expected "} +
            std::to_string(kSchemaVersion) + ", received " +
            std::to_string(received_version));
  }

  // ---- 4. Start building the Config ------------------------------------
  Config cfg;
  cfg.version = received_version;

  // ---- 5. interface_roles (D5, PCI-only in C1) --------------------------
  if (!doc.contains("interface_roles")) {
    return make_err(ParseError::kUnknownField,
                    "missing required top-level field: 'interface_roles'");
  }
  const json& roles = doc["interface_roles"];
  if (!roles.is_object()) {
    return make_err(ParseError::kTypeMismatch,
                    "'interface_roles' must be a JSON object keyed by role name");
  }
  for (auto it = roles.begin(); it != roles.end(); ++it) {
    InterfaceRole role;
    role.name = it.key();
    if (auto err = parse_role_selector(it.value(), role.selector); err) {
      return *err;
    }
    cfg.interface_roles.push_back(std::move(role));
  }

  // ---- 6. default_behavior ---------------------------------------------
  if (!doc.contains("default_behavior")) {
    return make_err(ParseError::kUnknownField,
                    "missing required top-level field: 'default_behavior'");
  }
  if (!doc["default_behavior"].is_string()) {
    return make_err(ParseError::kTypeMismatch,
                    "'default_behavior' must be a string enum");
  }
  const std::string db = doc["default_behavior"].get<std::string>();
  if (db == "allow") {
    cfg.default_behavior = DefaultBehavior::kAllow;
  } else if (db == "drop") {
    cfg.default_behavior = DefaultBehavior::kDrop;
  } else {
    return make_err(ParseError::kBadEnum,
                    std::string{"'default_behavior' must be 'allow' or 'drop', got '"} +
                        db + "'");
  }

  // ---- 7. pipeline (C4 parses minimal Rule shells) ----------------------
  //
  // C1 shape-checked the layer arrays but left them empty in the AST.
  // C4 walks each layer and parses rules into the minimal `Rule` shell
  // (dst_port / dst_ports / vlan_id / pcp). C5+ extends the Rule body.
  if (doc.contains("pipeline")) {
    const json& pipe = doc["pipeline"];
    if (!pipe.is_object()) {
      return make_err(ParseError::kTypeMismatch,
                      "'pipeline' must be a JSON object with layer_2/3/4 arrays");
    }
    if (pipe.contains("layer_2")) {
      if (auto err =
              parse_rule_array(pipe["layer_2"], "layer_2", cfg.pipeline.layer_2)) {
        return *err;
      }
    }
    if (pipe.contains("layer_3")) {
      if (auto err =
              parse_rule_array(pipe["layer_3"], "layer_3", cfg.pipeline.layer_3)) {
        return *err;
      }
    }
    if (pipe.contains("layer_4")) {
      if (auto err =
              parse_rule_array(pipe["layer_4"], "layer_4", cfg.pipeline.layer_4)) {
        return *err;
      }
    }
  }

  // ---- 8. fragment_policy (D17 / P9 default l3_only) --------------------
  if (doc.contains("fragment_policy")) {
    if (!doc["fragment_policy"].is_string()) {
      return make_err(ParseError::kTypeMismatch,
                      "'fragment_policy' must be a string enum");
    }
    const std::string fp = doc["fragment_policy"].get<std::string>();
    if (fp == "l3_only") {
      cfg.fragment_policy = FragmentPolicy::kL3Only;
    } else if (fp == "drop") {
      cfg.fragment_policy = FragmentPolicy::kDrop;
    } else if (fp == "allow") {
      cfg.fragment_policy = FragmentPolicy::kAllow;
    } else {
      return make_err(
          ParseError::kBadEnum,
          std::string{"'fragment_policy' must be 'l3_only'|'drop'|'allow', got '"} +
              fp + "'");
    }
  }
  // else: default already set in Config{} initializer.

  // ---- 9. sizing (C6 / D6) ----------------------------------------------
  //
  // D6 anchor: two first-class columns (kSizingDevDefaults /
  // kSizingProdDefaults) live in sizing.h. When the `sizing` section
  // is absent from the document, fill Config.sizing with the dev
  // column — the dev VM boot path stays zero-arg, and no "MVP
  // limit" phrasing appears anywhere (M1 meta-principle). When the
  // section is present, parse_sizing enforces the flat ten-key
  // schema and the 16-rules-per-layer hard minimum (kSizingBelowMin).
  if (doc.contains("sizing")) {
    if (auto err = parse_sizing(doc["sizing"], cfg.sizing); err) {
      return *err;
    }
  } else {
    cfg.sizing = kSizingDevDefaults;
  }

  // ---- 10. objects (C6) -------------------------------------------------
  //
  // C6 implements only `objects.subnets` as an unresolved
  // name → CIDR list map. The validator (C7+) resolves rule
  // references into this pool; the parser only structurally
  // accepts well-formed entries and fails on malformed CIDRs.
  if (doc.contains("objects")) {
    if (auto err = parse_objects(doc["objects"], cfg.objects); err) {
      return *err;
    }
  }

  // ---- 11. cmd_socket (C7 / D38 schema-only; C7.5 defers) ---------------
  //
  // Schema-only: the parser validates shape and bounds. When the
  // section or `allow_gids` key is absent, `cfg.cmd_socket.allow_gids`
  // stays `std::nullopt` — the sentinel means "resolve at daemon init
  // (M11)". Parser/validator MUST NOT invent a default; see the
  // model.h CmdSocket comment for the drift argument. Real SO_PEERCRED
  // plumbing against allow_gids is M11.
  if (doc.contains("cmd_socket")) {
    if (auto err = parse_cmd_socket(doc["cmd_socket"], cfg.cmd_socket); err) {
      return *err;
    }
  }

  return cfg;
}

}  // namespace pktgate::config
