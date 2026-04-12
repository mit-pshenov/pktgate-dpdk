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
// Added in C8 (U2.5/U2.6/U2.7/U2.19/U2.20):
//   * duplicate rule id within a single layer (kDuplicateRuleId).
//     `(layer, rule_id)` is a composite key per §4.3 layer_base(),
//     so re-using `id` across distinct layers stays legal.
//   * L2 compound key collision detection (kKeyCollision). Two rules
//     in `layer_2` with identical constrained-field shape AND values
//     are flagged — the second would be dead code under first-match-
//     wins. Derived from `std::optional::has_value()` on the L2
//     compound fields; filter_mask itself is a compile-time concept
//     and is NOT a JSON field. L3/L4 compound collision is later
//     work (C9+).
//   * Layer-evaluation-order enforcement (kInvalidLayerTransition).
//     `next_layer` must advance by exactly one: a rule in layer_N
//     may only carry `next_layer == layer_{N+1}`. Same-layer,
//     backward, skip-ahead, and layer_4-advancement are all rejected.
//   * `default_behavior` pass-through. Parser already enforces
//     `{allow, drop}` at parse time; validator must not reject a
//     value that made it through the AST (documentation-only test).
//
// Out of C8 scope (lives in C9+):
//   * action param bounds (dscp 0..63, pcp 0..7, rate > 0)
//   * target_port role resolution
//   * mirror compile-time reject
//   * D37 budget pre-flight (C10)
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
    kDuplicateRuleId,         // U2.5 — two rules in same layer share id
    kKeyCollision,            // U2.7 — identical L2 compound key (D15)
    kInvalidLayerTransition,  // U2.19 — next_layer not equal to layer+1
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
