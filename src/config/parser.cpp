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

#include <array>
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
constexpr std::array<std::string_view, 7> kAllowedTopKeys = {
    "version",          // required (D8 strict equality)
    "interface_roles",  // required (D5)
    "pipeline",         // required (empty in C1; layer_2/3/4 in C3+)
    "default_behavior", // required enum
    "fragment_policy",  // optional (D17/P9 default l3_only)
    "sizing",           // optional (C6)
    "objects",          // optional (C6)
};

// Tiny helper: build a ParseError in one expression.
ParseError make_err(ParseError::Kind k, std::string msg) {
  return ParseError{k, std::move(msg)};
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

  // ---- 7. pipeline (empty in C1; C3+ fills layer_2/3/4) -----------------
  if (doc.contains("pipeline")) {
    const json& pipe = doc["pipeline"];
    if (!pipe.is_object()) {
      return make_err(ParseError::kTypeMismatch,
                      "'pipeline' must be a JSON object with layer_2/3/4 arrays");
    }
    // Only shape-check the layer arrays for now. Rule bodies land in C3+.
    for (const char* layer : {"layer_2", "layer_3", "layer_4"}) {
      if (pipe.contains(layer) && !pipe[layer].is_array()) {
        return make_err(ParseError::kTypeMismatch,
                        std::string{"'pipeline."} + layer + "' must be an array");
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

  return cfg;
}

}  // namespace pktgate::config
