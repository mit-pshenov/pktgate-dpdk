// src/config/validator.cpp
//
// M1 C7 GREEN — validator scaffolding. Implements exactly the contract
// U2.1 / U2.2 / U2.3 / U2.4 / U2.18 exercise:
//
//   * Walk every Rule in Pipeline.layer_{2,3,4}. For each rule:
//       - If `src_subnet` is set, look up the name in
//         `Config.objects.subnets`. Miss → kUnresolvedObject.
//       - If `interface_ref` is set, look up the name in
//         `Config.interface_roles`. Miss → kUnresolvedInterfaceRef.
//   * If `Config.cmd_socket.allow_gids` is still nullopt after parse,
//     fill it with a singleton `[getgid()]`.
//
// D-refs: D5 (interface_roles), D8 (object model), D38 (allow_gids
// schema-only, real SO_PEERCRED is M11).
//
// Why `getgid()` and not a compile-time constant: U2.18's goal sentence
// reads "default is singleton [pktgate_gid]". In a single-user dev VM
// the gid the daemon runs under IS `getgid()`; in a drop-privs prod
// build (where pktgate runs as a dedicated service user) the daemon
// still reads its own effective gid at startup. The key property
// U2.18 pins is "one entry, matching the daemon's own gid" — which is
// exactly `getgid()`. The real privilege-separation story (setgid +
// SO_PEERCRED checks on the control-plane socket) is M11, not M1.
//
// Invariant kept by this tier:
//   * The validator does NOT touch any field the parser populated.
//     The only mutation is the allow_gids default-fill. A future C8
//     cycle may populate a resolved-index sidecar on Rule, but C7
//     leaves the AST otherwise untouched.

#include "src/config/validator.h"

#include <sys/types.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
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

  // ---- cmd_socket.allow_gids default-fill (U2.18, D38 schema-only) ------
  //
  // The parser leaves allow_gids as nullopt when:
  //   * the top-level cmd_socket section is absent, OR
  //   * cmd_socket is present but `allow_gids` is absent.
  // In both cases the validator fills a singleton `[getgid()]` so the
  // downstream control-plane code can treat `allow_gids.value()` as
  // always-populated. An explicit empty list (`[]`) remains distinct —
  // it survives into the runtime as "deny all" (tested by C8+).
  if (!cfg.cmd_socket.allow_gids.has_value()) {
    const std::uint32_t self_gid = static_cast<std::uint32_t>(::getgid());
    cfg.cmd_socket.allow_gids = std::vector<std::uint32_t>{self_gid};
  }

  return ValidateOk{};
}

}  // namespace pktgate::config
