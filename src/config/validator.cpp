// src/config/validator.cpp
//
// M1 C7 / C7.5 — validator scaffolding. Implements the contract
// U2.1 / U2.2 / U2.3 / U2.4 / U2.18 exercise:
//
//   * Walk every Rule in Pipeline.layer_{2,3,4}. For each rule:
//       - If `src_subnet` is set, look up the name in
//         `Config.objects.subnets`. Miss → kUnresolvedObject.
//       - If `interface_ref` is set, look up the name in
//         `Config.interface_roles`. Miss → kUnresolvedInterfaceRef.
//   * `Config.cmd_socket.allow_gids` is **pass-through**. An explicit
//     list survives verbatim; `std::nullopt` stays `std::nullopt`.
//     The validator NEVER resolves a default and NEVER calls
//     `::getgid()` / `::getgrnam()` / any gid-resolution syscall.
//
// D-refs: D5 (interface_roles), D8 (object model), D38 (allow_gids
// schema-only; real SO_PEERCRED is M11).
//
// Why allow_gids resolution is deferred (C7.5 fix, overrides the C7
// default-fill that lived here briefly):
//
//   Offline `--validate-config` may run as a different user than the
//   daemon. If the validator captured `::getgid()` at validate time,
//   an operator running `pktgate --validate-config foo.json` as root
//   would silently store root's gid in the validated Config. The
//   daemon — after drop-privs to the `pktgate` service user at M11
//   bind time — would then diverge from what SO_PEERCRED eventually
//   checks. The drift is silent: both the validate and the bind
//   "succeed", but the wrong gid ends up on the allow-list.
//
//   Resolution is a runtime-context-dependent concern and belongs at
//   cmd_socket bind time, after the process has already become the
//   daemon user. The `std::nullopt` sentinel carries this intent
//   through the AST: "I don't know yet, ask the bind path".
//
// CTEST-SCAN: no gid resolution at parse/validate tier.
// A `grep -rE 'getgid|getgrnam|getgrouplist|initgroups' src/config/`
// must return empty. U2.18 pins the behavioural half of the rule
// (sentinel survives through validate); the grep lint pins the
// static half (no syscall site exists).
//
// Invariant kept by this tier:
//   * The validator does NOT touch any field the parser populated.
//     C7.5 makes this stricter: no default-fill, no mutation. A
//     future C8+ cycle may populate a resolved-index sidecar on
//     Rule, but the parser-populated fields stay immutable.

#include "src/config/validator.h"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "src/config/model.h"

namespace pktgate::config {

namespace {

// One-liner error builder — matches parser.cpp style so both files
// read the same way at call sites.
ValidateError make_err(ValidateError::Kind k, std::string msg) {
  return ValidateError{k, std::move(msg)};
}

// Linear lookup in the (small) interface_roles vector. The validator
// runs at reload time, not the hot path, so O(N*M) on N rules x M
// roles is fine for any realistic N/M. If that stops being true, the
// compiler tier (M2) will materialise a name→index map once per
// reload and hand it to the validator as a sidecar input.
bool has_role_named(const Config& cfg, std::string_view name) {
  for (const auto& r : cfg.interface_roles) {
    if (r.name == name) return true;
  }
  return false;
}

// Same argument as has_role_named. objects.subnets is stored as a
// vector so insertion order is preserved; linear scan at validate
// time, potential hash at compile time if it ever matters.
bool has_subnet_named(const Config& cfg, std::string_view name) {
  for (const auto& s : cfg.objects.subnets) {
    if (s.name == name) return true;
  }
  return false;
}

// Walk every rule in one layer vector and resolve both ref types.
// Short-circuit on the first failure — the validator's contract is
// "first reason the config is bad", not a full error list. A future
// cycle can batch-collect diagnostics if operators ask for it.
std::optional<ValidateError> validate_rules(const Config& cfg,
                                            const std::vector<Rule>& rules,
                                            const char* layer_name) {
  for (std::size_t i = 0; i < rules.size(); ++i) {
    const Rule& r = rules[i];

    if (r.src_subnet.has_value()) {
      const std::string& name = r.src_subnet->name;
      if (!has_subnet_named(cfg, name)) {
        return make_err(
            ValidateError::kUnresolvedObject,
            std::string{"rule id "} + std::to_string(r.id) + " in " +
                layer_name + " references src_subnet '" + name +
                "' which is not declared in objects.subnets");
      }
    }

    if (r.interface_ref.has_value()) {
      const std::string& name = *r.interface_ref;
      if (!has_role_named(cfg, name)) {
        return make_err(
            ValidateError::kUnresolvedInterfaceRef,
            std::string{"rule id "} + std::to_string(r.id) + " in " +
                layer_name + " references interface '" + name +
                "' which is not declared in interface_roles");
      }
    }

    (void)i;  // index kept around for future diagnostics; unused in C7
  }
  return std::nullopt;
}

}  // namespace

ValidateResult validate(Config& cfg) {
  // ---- Rules: object + role reference resolution (U2.1..U2.4) -----------
  if (auto err =
          validate_rules(cfg, cfg.pipeline.layer_2, "pipeline.layer_2")) {
    return *err;
  }
  if (auto err =
          validate_rules(cfg, cfg.pipeline.layer_3, "pipeline.layer_3")) {
    return *err;
  }
  if (auto err =
          validate_rules(cfg, cfg.pipeline.layer_4, "pipeline.layer_4")) {
    return *err;
  }

  // ---- cmd_socket.allow_gids: PASS-THROUGH (U2.18, C7.5) -----------------
  //
  // No default-fill. If the parser left `allow_gids = std::nullopt`,
  // it stays nullopt — the M11 cmd_socket bind path will resolve the
  // default at the moment the process has dropped privileges to the
  // pktgate service user. An explicit list (possibly empty) survives
  // verbatim. See the file-top comment for the "offline validate as
  // root captures wrong gid" drift argument this fix closes.

  return ValidateOk{};
}

}  // namespace pktgate::config
