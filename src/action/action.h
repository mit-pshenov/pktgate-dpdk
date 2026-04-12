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

}  // namespace pktgate::action
