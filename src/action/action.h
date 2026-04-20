// src/action/action.h
//
// M2 C2 — runtime RuleAction: the compiled, fixed-layout action descriptor.
//
// This is the *runtime* representation stored in Ruleset arenas, NOT
// the config AST variant (config::RuleAction in model.h). The compiler
// lowers config::RuleAction → action::RuleAction during compilation.
//
// Design anchors:
//   * D22 — 20 B + alignas(4), not 64 B
//   * §4.1 — struct layout, field semantics
//
// alignas(4) matches the widest member (uint32_t rule_id). NOT
// cache-line-aligned: actions are read-only after publication, so
// multiple actions sharing a cache line only cause shared-read
// traffic, never coherence bouncing. Keeping the struct dense
// (sizeof = 20) keeps the arena small and improves prefetch coverage.

#pragma once

#include <cstdint>
#include <tuple>

namespace pktgate::action {

struct alignas(4) RuleAction {
  std::uint32_t rule_id;         // stable operator-assigned id; keys counters + rl_arena
  std::uint16_t counter_slot;    // dense per-layer slot in [0, rules_per_layer_max), §4.3
  std::uint8_t  verb;            // ALLOW | DROP | MIRROR | RL | TAG | REDIRECT
  std::uint8_t  next_layer;      // 0=terminal | 3 | 4
  std::uint8_t  execution_tier;  // SW | HW (D4)
  std::uint8_t  flags;
  std::uint16_t redirect_port;   // egress port idx (or 0xFFFF)
  std::uint16_t mirror_port;
  std::uint8_t  dscp;            // 6-bit DSCP target (for TAG)
  std::uint8_t  pcp;             // 3-bit PCP (for TAG)
  std::uint16_t rl_index;        // index into rs->rl_actions[] (ruleset-scoped handle)
};

static_assert(sizeof(RuleAction) == 20, "RuleAction layout drift (D22)");
static_assert(alignof(RuleAction) == 4, "RuleAction alignment drift (D22)");

// -------------------------------------------------------------------------
// D41 compile-time guard — observable-field projection (post-Phase 1).
//
// Allowlist of RuleAction fields that MUST be lowered through the
// compiler -> builder pipeline. A parallel projection of the same
// shape/types lives on compiler::CompiledAction (see
// src/compiler/compiler.h); the builder TU pairs them via two
// static_asserts (arity fold + per-element is_same_v fold) so any
// drift between the two structs fails at compile time.
//
// Fields deliberately EXCLUDED from the allowlist:
//
//   * next_layer — excluded: dead carrier, re-add if a dataplane
//     consumer appears. Zero readers in src/dataplane/; layer
//     sequencing is driven by classify_l{2,3,4} Disposition returns.
//   * flags      — excluded: dead carrier. Zero readers anywhere
//     in the tree; reserved stub space for future attribute bits.
//
// `mirror_port` — INCLUDED as of M16 C1 (D7 unlock + D41 #7 guard
// extension). Prior to M16 mirror was compile-rejected in the MVP
// (src/compiler/object_compiler.cpp scan-for-kMirror block) so the
// field stayed at its 0xFFFF reserved-slot sentinel for every live
// RuleAction and was correctly excluded from the projection. The
// M16 C1 unlock removes the reject, adds lowering in
// object_compiler.cpp::resolve_action + builder.cpp::copy_actions
// (both overloads), and adds `mirror_port` to both observable_fields
// tuples in lockstep — this is the D41 #7 guard landing per
// review-notes §D41 and the M16 supervisor handoff §C1.
//
// Types and element count MUST match compiler::observable_fields() —
// drift triggers `D41 guard: ...` static_assert failures at the TU
// that pairs the two projections (src/ruleset/builder.cpp).
// See also scratch/d41-discovery-report.md §3 (Candidate B) and
// review-notes.md §D41.
constexpr auto observable_fields(const RuleAction& ra) {
  return std::tuple{
      ra.rule_id,
      ra.counter_slot,
      ra.verb,
      ra.execution_tier,
      ra.redirect_port,
      ra.dscp,
      ra.pcp,
      ra.rl_index,
      ra.mirror_port,
  };
}

}  // namespace pktgate::action
