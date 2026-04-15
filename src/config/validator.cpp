// src/config/validator.cpp
//
// M1 C7 / C7.5 / C8 — validator scaffolding + structural checks.
// Implements the contract U2.1 / U2.2 / U2.3 / U2.4 / U2.5 / U2.6 /
// U2.7 / U2.18 / U2.19 / U2.20 exercise:
//
//   * Walk every Rule in Pipeline.layer_{2,3,4}. For each rule:
//       - If `dst_subnet` is set, look up the name in
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
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include "src/config/addr.h"
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

// Canonical `NextLayer` → layer index int ∈ {2,3,4}. Used by the
// layer-transition check so we can write `next == current + 1`
// without re-switching on the enum at each call site.
constexpr int next_layer_as_int(NextLayer nl) noexcept {
  switch (nl) {
    case NextLayer::kL2:
      return 2;
    case NextLayer::kL3:
      return 3;
    case NextLayer::kL4:
      return 4;
  }
  return -1;
}

constexpr const char* next_layer_name(NextLayer nl) noexcept {
  switch (nl) {
    case NextLayer::kL2:
      return "l2";
    case NextLayer::kL3:
      return "l3";
    case NextLayer::kL4:
      return "l4";
  }
  return "?";
}

// ---------------------------------------------------------------------------
// C8 U2.5 — duplicate rule id within a single layer.
//
// Per design §4.3 `layer_base()`, counters and rl_arena key on
// `(layer, rule_id)` — so reuse across distinct layers is fine and
// intended. Inside one layer, a duplicate would corrupt the counter
// slot assignment the compiler makes at §4.3. Build a fresh
// unordered_set<int32_t> per layer; on a duplicate, return an error
// whose message names BOTH layer indices so an operator can locate
// both offending rules. (nlohmann::json drops source line numbers;
// vector index in the form "<layer_name>[N]" is the best locator.)
std::optional<ValidateError> check_duplicate_rule_ids(
    const std::vector<Rule>& rules, const char* layer_name) {
  // Map rule_id → first index seen. Linear rehash on collision, fine
  // for realistic layer sizes (≤ rules_per_layer_max ≈ 4096-16384).
  std::unordered_set<std::int32_t> seen;
  seen.reserve(rules.size());
  for (std::size_t i = 0; i < rules.size(); ++i) {
    const auto [it, inserted] = seen.insert(rules[i].id);
    (void)it;
    if (!inserted) {
      // Linear back-scan for the first occurrence — one-off error
      // path, not the hot loop. Using a parallel id→index map would
      // double the hash work on the happy path.
      std::size_t first = 0;
      for (; first < i; ++first) {
        if (rules[first].id == rules[i].id) break;
      }
      std::string msg = std::string{"duplicate rule id "} +
                        std::to_string(rules[i].id) + " in " + layer_name +
                        ": first at " + layer_name + "[" +
                        std::to_string(first) + "], second at " +
                        layer_name + "[" + std::to_string(i) + "]";
      return make_err(ValidateError::kDuplicateRuleId, std::move(msg));
    }
  }
  return std::nullopt;
}

// ---------------------------------------------------------------------------
// C8 U2.7 — L2 compound key collision.
//
// First-match-wins means two rules with structurally identical L2
// compound keys render the second rule dead code. We define
// "structurally identical" as: exactly the same **active-set** of
// constrained fields and exactly the same **value** for each field in
// that set. A rule that carries `dst_mac` has a different active-set
// from one that doesn't, so they do not collide (filter_mask bits
// differ, §4.1 L2CompoundEntry).
//
// We serialize each rule's L2 compound key into a canonical string
// and use std::unordered_set<std::string> for O(1) collision probe.
// std::optional<std::array<...>> isn't hashable out of the box, and a
// hand-rolled struct-hash would be brittle as fields land — a string
// key trades a small bit of per-rule copy for bulletproof equality.
//
// Scope: L2 only this cycle. L3/L4 compound collision is C9+.
std::optional<ValidateError> check_l2_compound_collisions(
    const std::vector<Rule>& rules) {
  // Canonical form:
  //   "sm:<12hex>|dm:<12hex>|vl:<int>|et:<int>|pc:<int>"
  // Each segment is either the literal "sm:<12hex>" (mac printed as
  // 12 lowercase hex) when the optional has_value, or empty (so the
  // separator "sm:" itself doesn't appear) when it doesn't. This
  // makes the active-set directly visible in the key: two rules with
  // different active-sets produce structurally different strings
  // even when their raw values overlap.
  auto mac_hex = [](const Mac& m) {
    static const char kHex[] = "0123456789abcdef";
    std::string s;
    s.resize(12);
    for (std::size_t i = 0; i < 6; ++i) {
      const unsigned b = m.bytes[i];
      s[i * 2] = kHex[(b >> 4) & 0xFu];
      s[i * 2 + 1] = kHex[b & 0xFu];
    }
    return s;
  };
  auto canonicalize_l2 = [&](const Rule& r) {
    std::string k;
    k.reserve(64);
    if (r.src_mac.has_value()) {
      k += "sm:";
      k += mac_hex(*r.src_mac);
    }
    k += '|';
    if (r.dst_mac.has_value()) {
      k += "dm:";
      k += mac_hex(*r.dst_mac);
    }
    k += '|';
    if (r.vlan_id >= 0) {
      k += "vl:";
      k += std::to_string(r.vlan_id);
    }
    k += '|';
    if (r.ethertype.has_value()) {
      k += "et:";
      k += std::to_string(static_cast<int>(*r.ethertype));
    }
    k += '|';
    if (r.pcp >= 0) {
      k += "pc:";
      k += std::to_string(r.pcp);
    }
    return k;
  };

  // If a rule constrains *nothing* at L2, its canonical key is just
  // the separator skeleton "||||" — two such rules would be flagged
  // as a collision, which is actually correct: two rules with an
  // empty L2 constraint shape match every L2 packet identically,
  // and the second is dead code. Keep the simple semantics.
  std::unordered_set<std::string> seen;
  seen.reserve(rules.size());
  std::vector<std::string> keys;
  keys.reserve(rules.size());
  for (std::size_t i = 0; i < rules.size(); ++i) {
    std::string k = canonicalize_l2(rules[i]);
    const auto [it, inserted] = seen.insert(k);
    if (!inserted) {
      // Find the first occurrence to report both indices.
      std::size_t first = 0;
      for (; first < keys.size(); ++first) {
        if (keys[first] == k) break;
      }
      std::string msg = std::string{"L2 compound key collision: "} +
                        "layer_2[" + std::to_string(first) +
                        "] (rule id " + std::to_string(rules[first].id) +
                        ") and layer_2[" + std::to_string(i) + "] (rule id " +
                        std::to_string(rules[i].id) +
                        ") have the same active-set and values; the "
                        "second rule is dead under first-match-wins";
      return make_err(ValidateError::kKeyCollision, std::move(msg));
    }
    keys.push_back(std::move(k));
  }
  return std::nullopt;
}

// ---------------------------------------------------------------------------
// C8 U2.19 — layer evaluation order enforcement.
//
// `next_layer` is an advancement directive. The pipeline walks
// strictly L2 → L3 → L4 (design §3a pipeline diagram; §4.1 schema
// `uint8_t next_layer; // 0=terminal | 3 | 4`). A rule living in
// `layer_N` may only set `next_layer` to `layer_{N+1}`:
//   * layer_2 → next_layer ∈ {l3}
//   * layer_3 → next_layer ∈ {l4}
//   * layer_4 → next_layer must be absent (no further layer exists)
// Absent `next_layer` is terminal and always ok.
std::optional<ValidateError> check_layer_transitions(
    const std::vector<Rule>& rules, int current_layer,
    const char* layer_name) {
  for (std::size_t i = 0; i < rules.size(); ++i) {
    const Rule& r = rules[i];
    if (!r.next_layer.has_value()) continue;
    const int target = next_layer_as_int(*r.next_layer);
    // Layer 4 is terminal: any next_layer is invalid.
    if (current_layer == 4) {
      std::string msg =
          std::string{"rule id "} + std::to_string(r.id) + " at " +
          layer_name + "[" + std::to_string(i) + "] sets next_layer='" +
          next_layer_name(*r.next_layer) +
          "' but layer_4 is terminal (no further layer exists)";
      return make_err(ValidateError::kInvalidLayerTransition, std::move(msg));
    }
    if (target != current_layer + 1) {
      std::string msg =
          std::string{"rule id "} + std::to_string(r.id) + " at " +
          layer_name + "[" + std::to_string(i) + "] sets next_layer='" +
          next_layer_name(*r.next_layer) +
          "' but pipeline advancement from layer_" +
          std::to_string(current_layer) + " must be to layer_" +
          std::to_string(current_layer + 1) +
          " (strict L2→L3→L4, no backward/same/skip)";
      return make_err(ValidateError::kInvalidLayerTransition, std::move(msg));
    }
  }
  return std::nullopt;
}

// ---------------------------------------------------------------------------
// C9 U2.11 — action target_port role resolution.
//
// ActionTargetPort and ActionMirror both carry a `role_name` field that
// must resolve to one of `Config.interface_roles[*].name`. The
// validator does NOT reject the mirror action type itself (that's the
// compiler tier, D7, U3.17) — it only checks that the role reference
// resolves.
//
// Returns an error on the first unresolved target_port, or nullopt.
std::optional<ValidateError> check_action_target_port(
    const Config& cfg, const Rule& r, const char* layer_name,
    std::size_t idx) {
  if (!r.action.has_value()) return std::nullopt;

  const auto* tp = std::get_if<ActionTargetPort>(&*r.action);
  const auto* mr = std::get_if<ActionMirror>(&*r.action);

  const std::string* role_name = nullptr;
  const char* action_type = nullptr;
  if (tp) {
    role_name = &tp->role_name;
    action_type = "target-port";
  } else if (mr) {
    role_name = &mr->role_name;
    action_type = "mirror";
  }

  if (role_name && !has_role_named(cfg, *role_name)) {
    return make_err(
        ValidateError::kUnresolvedTargetPort,
        std::string{"rule id "} + std::to_string(r.id) + " at " +
            layer_name + "[" + std::to_string(idx) + "] " + action_type +
            " action references target_port '" + *role_name +
            "' which is not declared in interface_roles");
  }
  return std::nullopt;
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

    if (r.dst_subnet.has_value()) {
      const std::string& name = r.dst_subnet->name;
      if (!has_subnet_named(cfg, name)) {
        return make_err(
            ValidateError::kUnresolvedObject,
            std::string{"rule id "} + std::to_string(r.id) + " in " +
                layer_name + " references dst_subnet '" + name +
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

    // C9 U2.11 — action target_port / mirror role resolution.
    if (auto err = check_action_target_port(cfg, r, layer_name, i)) {
      return *err;
    }
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

  // ---- C8 structural checks (U2.5/U2.6/U2.7/U2.19) ---------------------
  //
  // Order of operations per layer:
  //   1. Duplicate rule id within the layer        (U2.5, U2.6)
  //   2. L2 compound key collision  (layer_2 only) (U2.7)
  //   3. Layer-advancement direction                (U2.19)
  //
  // Each check short-circuits on first failure — the validator
  // contract is "first reason this config is bad", matching how the
  // C7 ref-resolution pass already behaves. Ordering is chosen so
  // the most specific symptom (exact id reuse) fires before the
  // structural ones; functionally the order is irrelevant because
  // any single hit aborts.
  //
  // U2.6 is covered implicitly: the dedup walk uses a FRESH set
  // per layer, so `id: 1001` in layer_2 and layer_3 cannot collide
  // with each other (§4.3 layer_base composite key).
  //
  // `default_behavior` is NOT re-checked here — the parser already
  // enforces `{allow, drop}` at parse time (D8), and re-validating
  // would be duplicate work. U2.20 is a documentation-only positive
  // test that pins this contract.
  // layer_2
  if (auto err = check_duplicate_rule_ids(cfg.pipeline.layer_2, "layer_2")) {
    return *err;
  }
  if (auto err = check_l2_compound_collisions(cfg.pipeline.layer_2)) {
    return *err;
  }
  if (auto err = check_layer_transitions(cfg.pipeline.layer_2, 2, "layer_2")) {
    return *err;
  }
  // layer_3
  if (auto err = check_duplicate_rule_ids(cfg.pipeline.layer_3, "layer_3")) {
    return *err;
  }
  if (auto err = check_layer_transitions(cfg.pipeline.layer_3, 3, "layer_3")) {
    return *err;
  }
  // layer_4
  if (auto err = check_duplicate_rule_ids(cfg.pipeline.layer_4, "layer_4")) {
    return *err;
  }
  if (auto err = check_layer_transitions(cfg.pipeline.layer_4, 4, "layer_4")) {
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

// ---------------------------------------------------------------------------
// D37 budget pre-flight (C10).
//
// Three gates, short-circuit on first failure. Runs after validate()
// succeeds, before the compiler touches any hugepage.
//
// Expansion model (heuristic, not exact compiler):
//   * L4 rules: expansion = max(1, dst_ports.size())
//   * L2 / L3 rules: expansion = 1 per rule
//
// Memory estimation constants (rough heuristic — document as such):
//   * L4CompoundEntry ≈ 64 bytes (design §4.1)
//   * L2 hash entry   ≈ 32 bytes
//   * L3 FIB entry    ≈ 48 bytes
//   * Overhead         ≈ 4096 bytes (page-level metadata, hash tables, etc.)
// These are estimates — the real structs don't exist yet in M1.

namespace {

constexpr std::size_t kL4EntryBytes = 64;
constexpr std::size_t kL2EntryBytes = 32;
constexpr std::size_t kL3EntryBytes = 48;
constexpr std::size_t kOverheadBytes = 4096;

// Estimate how many compiled entries a single rule will produce.
// L4: each port in dst_ports generates a separate L4 compound entry.
// L2 / L3: 1 entry per rule (no multi-entry explosion).
std::size_t estimate_expansion(const Rule& r) {
  // L4 expansion is driven by dst_ports. A rule with no dst_ports
  // (but a dst_port scalar) still expands to 1.
  if (r.dst_ports.empty()) return 1;
  return r.dst_ports.size();
}

}  // namespace

std::size_t expected_ruleset_bytes(const Config& cfg) {
  std::size_t l4_entries = 0;
  for (const auto& r : cfg.pipeline.layer_4) {
    l4_entries += estimate_expansion(r);
  }
  const auto l2_entries = cfg.pipeline.layer_2.size();
  const auto l3_entries = cfg.pipeline.layer_3.size();

  return l4_entries * kL4EntryBytes + l2_entries * kL2EntryBytes +
         l3_entries * kL3EntryBytes + kOverheadBytes;
}

ValidateResult validate_budget(const Config& cfg,
                               const HugepageProbe& probe) {
  // Gate 1 — per-rule expansion ceiling.
  // Check every rule across all layers. L2/L3 always expand to 1
  // (never exceeds any reasonable ceiling), but we check uniformly.
  auto check_per_rule = [](const std::vector<Rule>& rules,
                           const char* layer_name) -> std::optional<ValidateError> {
    for (std::size_t i = 0; i < rules.size(); ++i) {
      const auto expansion = estimate_expansion(rules[i]);
      if (expansion > kDefaultPerRuleCeiling) {
        return make_err(
            ValidateError::kBudgetPerRuleExceeded,
            std::string{"D37 gate 1: rule id "} +
                std::to_string(rules[i].id) + " at " + layer_name + "[" +
                std::to_string(i) + "] expands to " +
                std::to_string(expansion) + " entries (ceiling is " +
                std::to_string(kDefaultPerRuleCeiling) + ")");
      }
    }
    return std::nullopt;
  };

  if (auto err = check_per_rule(cfg.pipeline.layer_2, "layer_2")) {
    return *err;
  }
  if (auto err = check_per_rule(cfg.pipeline.layer_3, "layer_3")) {
    return *err;
  }
  if (auto err = check_per_rule(cfg.pipeline.layer_4, "layer_4")) {
    return *err;
  }

  // Gate 2 — aggregate post-expansion ceiling.
  // L4 expansion sum must not exceed sizing.l4_entries_max.
  // (L2 and L3 aggregate checks could be added but are trivial —
  // each rule expands to 1, so the aggregate == rule count, which
  // is already bounded by sizing.rules_per_layer_max at parse time.)
  std::size_t l4_total = 0;
  for (const auto& r : cfg.pipeline.layer_4) {
    l4_total += estimate_expansion(r);
  }
  if (l4_total > cfg.sizing.l4_entries_max) {
    return make_err(
        ValidateError::kBudgetAggregateExceeded,
        std::string{"D37 gate 2: aggregate L4 expansion is "} +
            std::to_string(l4_total) +
            " entries, exceeding sizing.l4_entries_max=" +
            std::to_string(cfg.sizing.l4_entries_max));
  }

  // Gate 3 — hugepage budget estimate.
  const std::size_t estimated = expected_ruleset_bytes(cfg);
  const HugepageInfo hp = probe();
  if (estimated > hp.available_bytes) {
    return make_err(
        ValidateError::kBudgetHugepage,
        std::string{"D37 gate 3: estimated ruleset footprint is "} +
            std::to_string(estimated) +
            " bytes but only " + std::to_string(hp.available_bytes) +
            " bytes of hugepage memory are available");
  }

  return ValidateOk{};
}

}  // namespace pktgate::config
