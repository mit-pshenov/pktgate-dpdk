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
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

#include "src/config/addr.h"
#include "src/config/model.h"

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

struct CompiledAction {
  std::int32_t rule_id{-1};
  std::uint16_t counter_slot{0};
  ActionVerb verb{ActionVerb::kDrop};
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
// CompileResult — full compiler output.

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
};

}  // namespace pktgate::compiler
