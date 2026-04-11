// src/config/validator.h
//
// M1 C7 — validator public API. Consumes a parsed Config (produced by
// `parser.cpp::parse()`) and either signals success or returns a
// structured `ValidateError`. The validator MAY mutate the incoming
// Config (for default-filling — e.g. U2.18 `cmd_socket.allow_gids`
// singleton default). It does NOT touch any field the parser has
// already populated.
//
// Result shape mirrors `ParseResult` deliberately (a `std::variant` of
// ok-marker and error struct) so that a future move to `std::expected`
// (C++23, per D2) is a mechanical rename — not an API redesign. We
// stay on C++20 for M1 because the parser does, and a milestone-wide
// switch to C++23 is a decision, not a side-effect.
//
// Scope in C7:
//   * U2.1 / U2.2 — object reference resolution against
//     `Config.objects.subnets` (kUnresolvedObject on miss).
//   * U2.3 / U2.4 — `interface` role reference resolution against
//     `Config.interface_roles` (kUnresolvedInterfaceRef on miss).
//   * U2.18 — `cmd_socket.allow_gids` default-fill.
//
// Out of C7 scope (lives in C8+):
//   * duplicate rule id detection
//   * L2 compound key collision
//   * layer ordering enforcement
//   * default_behavior enum-bounding at validate tier
//   * action param bounds
//   * D37 budget pre-flight
//
// Later cycles extend `ValidateError::Kind` additively — don't reorder.

#pragma once

#include <string>
#include <variant>

#include "src/config/model.h"

namespace pktgate::config {

struct ValidateOk {};

struct ValidateError {
  enum Kind : std::uint8_t {
    kUnresolvedObject,        // U2.2 — rule.src_subnet name not in objects.subnets
    kUnresolvedInterfaceRef,  // U2.4 — rule.interface name not in interface_roles
  };

  Kind kind{};
  std::string message;  // human-readable, names the offending ref
};

// Ok = the (possibly default-filled) Config survived validation.
// Err = structured ValidateError. Callers pattern-match via the
// `v_is_ok` / `v_get_err` one-liners in tests — we don't ship helpers
// in this header yet because only the test file consumes this API.
using ValidateResult = std::variant<ValidateOk, ValidateError>;

// Validate a parsed Config. Takes the Config by non-const reference
// because C7 may default-fill `cmd_socket.allow_gids` on absence
// (U2.18). No other field is touched — an invariant tested by the
// U2.1 / U2.3 happy-path cases which assert their existing fields
// survive unchanged.
ValidateResult validate(Config& cfg);

}  // namespace pktgate::config
