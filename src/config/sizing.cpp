// src/config/sizing.cpp
//
// M1 C6 GREEN — parse glue for `sizing` and `objects.subnets`.
//
// D6 anchor: capacity ceilings are runtime parameters. This file
// contains no compile-time limits (the caps live in sizing.h as the
// two first-class dev/prod column constants). The only guardrail
// enforced here is the D6 §3a.2 hard minimum of 16 rules/layer,
// below which the parser rejects the config as `kSizingBelowMin`.
//
// M1 meta-principle: dev and prod are two equal-status columns.
// There is no "MVP uses X" branch in this file — the parser reads
// the column the operator wrote into the config, and fills in
// `kSizingDevDefaults` when no `sizing` section is present (so an
// empty dev VM config still boots).
//
// Scope: the flat schema in design.md §3a.1. Every one of the ten
// fields is required when the `sizing` section is present; partial
// objects are rejected so there is no silent half-defaulting. The
// `objects.subnets` helper reuses addr.h's CIDR parsers verbatim.

#include "src/config/sizing.h"

#include <cstdint>
#include <limits>
#include <string>

#include "src/config/addr.h"

namespace pktgate::config {

namespace {

using json = nlohmann::json;

ParseError make_err(ParseError::Kind k, std::string msg) {
  return ParseError{k, std::move(msg)};
}

// Parse one required uint32 field out of a JSON object. Integer only
// (no JSON floats); must be >= 0 and <= UINT32_MAX. Returns nullopt on
// success, or a ParseError naming the offending key.
std::optional<ParseError> parse_u32_required(const json& j,
                                              const char* key,
                                              std::uint32_t& out) {
  if (!j.contains(key)) {
    return make_err(ParseError::kUnknownField,
                    std::string{"sizing section missing required key: '"} +
                        key + "'");
  }
  const json& v = j[key];
  if (!v.is_number_integer()) {
    return make_err(ParseError::kTypeMismatch,
                    std::string{"sizing field '"} + key +
                        "' must be an integer");
  }
  const std::int64_t raw = v.get<std::int64_t>();
  if (raw < 0 ||
      raw > static_cast<std::int64_t>(std::numeric_limits<std::uint32_t>::max())) {
    return make_err(ParseError::kOutOfRange,
                    std::string{"sizing field '"} + key + "' = " +
                        std::to_string(raw) +
                        " out of range [0..4294967295]");
  }
  out = static_cast<std::uint32_t>(raw);
  return std::nullopt;
}

// Strict per-section key whitelist: any key in the JSON object that
// is not in `allowed` triggers kUnknownField. Mirrors the top-level
// whitelist discipline in parser.cpp.
std::optional<ParseError> reject_unknown_keys(
    const json& j, const char* section,
    std::initializer_list<std::string_view> allowed) {
  for (auto it = j.begin(); it != j.end(); ++it) {
    const std::string& key = it.key();
    bool ok = false;
    for (const auto& w : allowed) {
      if (key == w) {
        ok = true;
        break;
      }
    }
    if (!ok) {
      return make_err(ParseError::kUnknownField,
                      std::string{"unknown "} + section + " field: '" +
                          key + "'");
    }
  }
  return std::nullopt;
}

}  // namespace

std::optional<ParseError> parse_sizing(const nlohmann::json& j, Sizing& out) {
  if (!j.is_object()) {
    return make_err(ParseError::kTypeMismatch,
                    "top-level 'sizing' must be a JSON object");
  }

  // Strict whitelist — any extra key is a typo we want to catch.
  if (auto err = reject_unknown_keys(
          j, "sizing",
          {"rules_per_layer_max", "mac_entries_max", "ipv4_prefixes_max",
           "ipv6_prefixes_max", "l4_entries_max", "vrf_entries_max",
           "rate_limit_rules_max", "ethertype_entries_max",
           "vlan_entries_max", "pcp_entries_max",
           // M10 C3 / D42 — Prometheus /metrics listen port. Optional
           // field; when absent the struct-init default (9090) stands.
           "prom_port"})) {
    return *err;
  }

  // Start from tmp{} (default-constructed → prom_port=9090). The
  // required-field parsers below fill the ten mandatory fields; the
  // optional prom_port path (M10 C3) overwrites the default if the
  // key is present.
  Sizing tmp{};
  if (auto err = parse_u32_required(j, "rules_per_layer_max",
                                     tmp.rules_per_layer_max)) return *err;
  if (auto err = parse_u32_required(j, "mac_entries_max",
                                     tmp.mac_entries_max)) return *err;
  if (auto err = parse_u32_required(j, "ipv4_prefixes_max",
                                     tmp.ipv4_prefixes_max)) return *err;
  if (auto err = parse_u32_required(j, "ipv6_prefixes_max",
                                     tmp.ipv6_prefixes_max)) return *err;
  if (auto err = parse_u32_required(j, "l4_entries_max",
                                     tmp.l4_entries_max)) return *err;
  if (auto err = parse_u32_required(j, "vrf_entries_max",
                                     tmp.vrf_entries_max)) return *err;
  if (auto err = parse_u32_required(j, "rate_limit_rules_max",
                                     tmp.rate_limit_rules_max)) return *err;
  if (auto err = parse_u32_required(j, "ethertype_entries_max",
                                     tmp.ethertype_entries_max)) return *err;
  if (auto err = parse_u32_required(j, "vlan_entries_max",
                                     tmp.vlan_entries_max)) return *err;
  if (auto err = parse_u32_required(j, "pcp_entries_max",
                                     tmp.pcp_entries_max)) return *err;

  // M10 C3 / D42 — optional prom_port. Missing → struct-default 9090.
  // Range [0..65535]; 0 means OS-assigned ephemeral (functional tests
  // exercise this to avoid port collisions on CI).
  if (j.contains("prom_port")) {
    const json& v = j["prom_port"];
    if (!v.is_number_integer()) {
      return make_err(ParseError::kTypeMismatch,
                      "sizing field 'prom_port' must be an integer");
    }
    const std::int64_t raw = v.get<std::int64_t>();
    if (raw < 0 || raw > 65535) {
      return make_err(ParseError::kOutOfRange,
                      std::string{"sizing field 'prom_port' = "} +
                          std::to_string(raw) + " out of range [0..65535]");
    }
    tmp.prom_port = static_cast<std::uint16_t>(raw);
  }

  // D6 §3a.2 hard minimum — 16 rules per layer. Below this the
  // test suite loses first-match-wins signal, so the config is
  // structurally useless and we reject it crisply with a named
  // error kind (not a generic kOutOfRange, so telemetry and
  // operator diagnostics can key on it).
  if (tmp.rules_per_layer_max < kSizingRulesPerLayerHardMin) {
    return make_err(
        ParseError::kSizingBelowMin,
        std::string{"sizing.rules_per_layer_max = "} +
            std::to_string(tmp.rules_per_layer_max) + " below hard minimum " +
            std::to_string(kSizingRulesPerLayerHardMin) + " (D6 §3a.2)");
  }

  out = tmp;
  return std::nullopt;
}

std::optional<ParseError> parse_objects(const nlohmann::json& j,
                                        ObjectPool& out) {
  if (!j.is_object()) {
    return make_err(ParseError::kTypeMismatch,
                    "top-level 'objects' must be a JSON object");
  }

  // Only `subnets` is implemented in C6. Any other top-level
  // `objects` key is a parse error until its owning cycle lands.
  if (auto err = reject_unknown_keys(j, "objects", {"subnets"})) {
    return *err;
  }

  out.subnets.clear();
  if (!j.contains("subnets")) {
    // Empty objects section is legal — no subnet definitions.
    return std::nullopt;
  }

  const json& subnets = j["subnets"];
  if (!subnets.is_object()) {
    return make_err(ParseError::kTypeMismatch,
                    "'objects.subnets' must be a JSON object keyed by "
                    "subnet name");
  }

  out.subnets.reserve(subnets.size());
  for (auto it = subnets.begin(); it != subnets.end(); ++it) {
    const std::string& name = it.key();
    if (name.empty()) {
      return make_err(ParseError::kUnknownField,
                      "'objects.subnets' entry has empty name");
    }
    if (!it.value().is_array()) {
      return make_err(ParseError::kTypeMismatch,
                      std::string{"'objects.subnets."} + name +
                          "' must be a JSON array of CIDR strings");
    }

    SubnetObject so{};
    so.name = name;
    so.cidrs.reserve(it.value().size());

    for (std::size_t i = 0; i < it.value().size(); ++i) {
      const json& e = it.value()[i];
      if (!e.is_string()) {
        return make_err(
            ParseError::kTypeMismatch,
            std::string{"'objects.subnets."} + name + "[" +
                std::to_string(i) + "]' must be a CIDR string");
      }
      const std::string cidr_text = e.get<std::string>();

      // Prefer IPv4 first — faster common path, identical semantics on
      // success. If both parsers fail we report kBadCidr with the
      // offending literal so the operator can jump to it.
      {
        const Cidr4Result r4 = parse_cidr4(cidr_text);
        if (is_ok(r4)) {
          so.cidrs.emplace_back(std::get<Cidr4>(r4));
          continue;
        }
      }
      {
        const Cidr6Result r6 = parse_cidr6(cidr_text);
        if (is_ok(r6)) {
          so.cidrs.emplace_back(std::get<Cidr6>(r6));
          continue;
        }
      }
      return make_err(
          ParseError::kBadCidr,
          std::string{"'objects.subnets."} + name + "[" +
              std::to_string(i) + "]' = '" + cidr_text +
              "' is not a valid IPv4 or IPv6 CIDR");
    }

    out.subnets.push_back(std::move(so));
  }

  return std::nullopt;
}

}  // namespace pktgate::config
