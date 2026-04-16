// src/compiler/compiler.h
//
// M2 C1 — compiler output types and top-level interface.
//
// The compiler takes M1's config AST (model.h types) as input after
// parse + validate and produces compiled structures that the ruleset
// builder (M2 later cycles) materialises into runtime data structures.
//
// Design anchors:
//   * D15 — compound primary + filter_mask pattern
//   * D22 — RuleAction 20 B + alignas(4)
//   * D33 — dense counter_slot assignment §4.3
//   * §4.1 — Ruleset struct layout (L2/L3/L4 compound + action arenas)
//
// C1 scope: object compiler output types, compiled action with
// counter_slot, port expansion scaffolding. L2/L3/L4 compound
// builders land in C3-C5.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

#include "src/config/addr.h"
#include "src/config/model.h"
#include "src/ruleset/types.h"

namespace pktgate::compiler {

// -------------------------------------------------------------------------
// CompiledObjects — expanded named objects ready for rule compilation.
//
// The object compiler resolves named definitions from ObjectPool into
// directly-indexable lookup tables. These are consumed by the rule
// compiler when expanding object references in rules.

struct CompiledSubnets {
  // name → flattened CIDR list. Each named subnet keeps its CIDRs in
  // declaration order (v4 and v6 may be interleaved).
  std::unordered_map<std::string, std::vector<config::SubnetCidr>> by_name;
};

struct CompiledPortGroups {
  // name → port list, preserved in declaration order.
  std::unordered_map<std::string, std::vector<std::uint16_t>> by_name;
};

struct CompiledObjects {
  CompiledSubnets subnets;
  CompiledPortGroups port_groups;
};

// -------------------------------------------------------------------------
// CompiledAction — compiler-assigned action descriptor for a single
// rule entry. This is the *compiler's view* of the action; the final
// runtime RuleAction (design.md §4.1, 20 B) is built by the ruleset
// builder from this plus runtime context (port resolution, rl_arena
// slot). C1 only needs the counter_slot and action verb to test
// dense slot assignment and port expansion.

enum class ActionVerb : std::uint8_t {
  kAllow = 0,
  kDrop = 1,
  kMirror = 2,
  kRateLimit = 3,
  kTag = 4,
  kRedirect = 5,
};

// D4: execution tier — SW (software tables) vs HW (rte_flow offload).
// Default is kSw. The compiler sets kHw when the rule's hw_offload_hint
// is true AND global hw_offload_enabled is true. MVP ships with global
// disable (all rules are SW regardless of hint).
enum class ExecutionTier : std::uint8_t {
  kSw = 0,
  kHw = 1,
};

struct CompiledAction {
  std::int32_t rule_id{-1};
  std::uint16_t counter_slot{0};
  ActionVerb verb{ActionVerb::kDrop};
  ExecutionTier execution_tier{ExecutionTier::kSw};  // D4: default SW

  // M7 C2b retrofit — action payload carried through to RuleAction.
  //
  // Before this cycle the compiler stored only the verb enum and the
  // builder hardcoded dscp/pcp=0 + redirect_port=0xFFFF. Result: TAG
  // actions were no-ops (DSCP=0, PCP=0) and REDIRECT silently dropped
  // every packet (sentinel port → apply_redirect guard). Same D41
  // silent-lowering class as M2 compound builders and M5 C3 fragment
  // policy — fixed by carrying the config::RuleAction variant payload
  // into CompiledAction and copying it in builder::copy_actions.
  //
  // Defaults match the "no TAG / no REDIRECT" case so non-TAG /
  // non-REDIRECT verbs behave unchanged: dscp=0 is a no-op rewrite and
  // redirect_port=0xFFFF matches the action::RuleAction sentinel used
  // by apply_redirect to reject bogus port indices.
  std::uint8_t dscp{0};
  std::uint8_t pcp{0};
  std::uint16_t redirect_port{0xFFFF};
};

// -------------------------------------------------------------------------
// CompileOptions — optional knobs for the compile() function.
//
// hw_offload_enabled: when false (MVP default), all rules are demoted
// to execution_tier == SW regardless of per-rule hw_offload_hint.
// When true, rules with hw_offload_hint produce execution_tier == HW.
// Covers D4, §14 MVP.

struct CompileOptions {
  bool hw_offload_enabled = false;  // MVP default: all SW
};

// -------------------------------------------------------------------------
// Layer enum — identifies which pipeline layer a compiled rule belongs to.

enum class Layer : std::uint8_t {
  kL2 = 0,
  kL3 = 1,
  kL4 = 2,
};

// -------------------------------------------------------------------------
// CompiledRuleEntry — a single expanded rule after port-list / port-group
// expansion. Multiple entries may share the same action_index (when a
// single logical rule expands into N entries via dst_ports/port_group).
//
// C1 scope: captures the expansion result for U3.2/U3.3/U3.4. Full
// L2/L4 compound construction (primary key, filter_mask) lands in C3-C5.

struct CompiledRuleEntry {
  std::uint32_t action_index;   // index into the layer's action array
  std::int32_t dst_port{-1};    // expanded port (-1 = not port-keyed)
  Layer layer{Layer::kL4};
};

// -------------------------------------------------------------------------
// CompileErrorCode — compile-time error codes (D7 et al.).

enum class CompileErrorCode : std::uint8_t {
  kMirrorNotImplemented = 1,  // D7: mirror action not supported in this build
};

// -------------------------------------------------------------------------
// CompileError — optional error carried by CompileResult.

struct CompileError {
  CompileErrorCode code;
  std::string message;
};

// -------------------------------------------------------------------------
// CompileResult — full compiler output.
//
// M4 C0 retrofit: CompileResult now holds L{2,3,4}CompiledRule vectors
// so the public compile() entry point exposes the full pipeline state
// end-to-end (D41 smoke invariant). The L*CompiledRule definitions
// live in rule_compiler.h, which is included below after the
// CompiledAction / CompiledObjects definitions above to break a
// potential cycle.

}  // namespace pktgate::compiler

#include "src/compiler/rule_compiler.h"  // L{2,3,4}CompiledRule

namespace pktgate::compiler {

struct CompileResult {
  CompiledObjects objects;

  // Per-layer action arrays. counter_slot is dense [0..N) within each layer.
  std::vector<CompiledAction> l2_actions;
  std::vector<CompiledAction> l3_actions;
  std::vector<CompiledAction> l4_actions;

  // Expanded rule entries per layer.
  std::vector<CompiledRuleEntry> l2_entries;
  std::vector<CompiledRuleEntry> l3_entries;
  std::vector<CompiledRuleEntry> l4_entries;

  // M4 C0 retrofit (D41): compound rules per layer, produced by
  // compile_l2_rules / compile_l3_rules / compile_l4_rules and
  // populated by the top-level compile() entry point. The ruleset
  // builder consumes these to populate rte_hash / rte_fib / rte_fib6.
  //
  // The per-layer `l{2,3,4}_entries` arrays above remain the port-
  // expansion helpers (U3.2/U3.3). The `l{2,3,4}_compound` arrays
  // are the compound-matching artefacts (D15).
  std::vector<L2CompiledRule> l2_compound;
  std::vector<L3CompiledRule> l3_compound;
  std::vector<L4CompiledRule> l4_compound;

  // D17: fragment_policy propagated from Config. The builder copies
  // this into Ruleset.fragment_policy. Numeric encoding matches
  // classify_l3.h FragmentPolicy (0=L3Only, 1=Drop, 2=Allow).
  std::uint8_t fragment_policy = 0;

  // M7 C2b retrofit (D41): default_behavior propagated from Config.
  // The builder copies this into Ruleset.default_action. Numeric
  // encoding matches config::DefaultBehavior (0=kAllow, 1=kDrop) and
  // the ruleset.h comment ("0 = ALLOW or DROP"). Pattern mirrors
  // fragment_policy above — see errata §M7 C2b.
  std::uint8_t default_action = 0;

  // D7: compile error (e.g., mirror not implemented in MVP).
  // When set, the result is invalid — the caller must not use the
  // compiled structures.
  std::optional<CompileError> error;
};

// -------------------------------------------------------------------------
// Enum dispatch helpers — exhaustive -Wswitch-enum switches (D25).
//
// verb_label:  ActionVerb  → human-readable string.
// layer_label: Layer       → human-readable string.
//
// Both use exhaustive switch statements so that adding a new enum value
// without handling it triggers a compile error under -Wswitch-enum.
// U3.22 / U3.23 verify runtime completeness via enum-scan tests.

const char* verb_label(ActionVerb verb);
const char* layer_label(Layer layer);

}  // namespace pktgate::compiler
