// src/config/parser.h
//
// M1 config parser public API. Consumes a raw JSON document (any
// std::string_view) and produces either a populated `Config` or a
// structured `ParseError`.
//
// Contract:
//   * No exceptions escape `parse()` — nlohmann::json::parse errors are
//     caught and translated to `ParseError{kJsonSyntax, ...}`.
//   * Strict schema (D8): any unrecognised top-level key is a hard fail.
//   * Strict version (D8/Q11): `version` must equal `kSchemaVersion`.
//   * Defaults are filled in by the parser, not the caller:
//       - missing `fragment_policy` → `FragmentPolicy::kL3Only` (D17/P9)
//
// Later cycles extend `ParseError::Kind` additively. Don't reorder the
// enum — tests reference values by name, but production diagnostics may
// also key on the underlying integer via logging.

#pragma once

#include <string>
#include <string_view>
#include <variant>

#include "src/config/model.h"

namespace pktgate::config {

struct ParseError {
  enum Kind : std::uint8_t {
    kJsonSyntax,            // nlohmann::json::parse exception
    kTypeMismatch,          // a field has the wrong JSON type
    kVersionMismatch,       // top-level `version` != kSchemaVersion
    kUnknownField,          // unrecognised top-level (or nested) key
    kInvalidRoleSelector,   // interface_roles sum-type violation
    kBadCidr,
    kBadMac,
    kBadEnum,
    kOutOfRange,
    kBadRate,
    kAmbiguousAction,
    kSizingBelowMin,
  };

  Kind kind{};
  std::string message;  // human-readable, names the offending key/value
};

// Success = the AST. Error = structured ParseError. The caller pattern-
// matches via the `is_ok` / `get_ok` / `get_err` helpers below so that
// switching to `std::expected` (C++23) later is a mechanical rename.
using ParseResult = std::variant<Config, ParseError>;

ParseResult parse(std::string_view json);

// -------------------------------------------------------------------------
// Access helpers. Kept in-header / inline because they're one-liners and
// exercised by every unit test in U1.*.

inline bool is_ok(const ParseResult& r) noexcept {
  return std::holds_alternative<Config>(r);
}

inline const Config& get_ok(const ParseResult& r) {
  return std::get<Config>(r);
}

inline const ParseError& get_err(const ParseResult& r) {
  return std::get<ParseError>(r);
}

inline ParseError::Kind err_kind(const ParseResult& r) {
  return std::get<ParseError>(r).kind;
}

}  // namespace pktgate::config
