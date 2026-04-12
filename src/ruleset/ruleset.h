// src/ruleset/ruleset.h
//
// M2 C9 — Ruleset struct and counter types.
//
// The Ruleset is the compiled output consumed by the hot path. At M2
// level it holds action arrays (sized from config), per-lcore counter
// rows, and generation metadata. DPDK hash/FIB pointers are M3.
//
// Design anchors:
//   * §4.1 — Ruleset struct layout
//   * §4.3 — PerLcoreCounters, RuleCounter (D3)
//   * D6   — arena sizing from runtime config
//   * D12  — generation counter

#pragma once

#include <cstdint>
#include <memory>

#include "src/action/action.h"
#include "src/compiler/compiler.h"

namespace pktgate::ruleset {

// -------------------------------------------------------------------------
// RuleCounter — per-rule per-lcore counter row (§4.3).
//
// Exactly one cache line (64 B). Each RuleCounter is written only by
// its owning lcore — zero atomics. Aggregation is the telemetry
// thread's job (§10).

struct alignas(64) RuleCounter {
  std::uint64_t matched_packets;
  std::uint64_t matched_bytes;
  std::uint64_t drops;       // explicit drop action
  std::uint64_t rl_drops;    // rate-limit drops
  std::uint64_t _pad[4];
};

static_assert(sizeof(RuleCounter) == 64, "RuleCounter must be 64 B");
static_assert(alignof(RuleCounter) == 64, "RuleCounter must be 64 B aligned");

// -------------------------------------------------------------------------
// layer_base — constant index math for counter rows (§4.3).
//
// layer_base(L2) = 0, layer_base(L3) = M, layer_base(L4) = 2*M
// where M = sizing.rules_per_layer_max.

inline std::uint32_t layer_base(compiler::Layer layer,
                                std::uint32_t rules_per_layer_max) {
  switch (layer) {
    case compiler::Layer::kL2: return 0;
    case compiler::Layer::kL3: return rules_per_layer_max;
    case compiler::Layer::kL4: return 2 * rules_per_layer_max;
  }
  return 0;  // unreachable
}

// -------------------------------------------------------------------------
// Ruleset — the immutable compiled artifact (M2 subset).
//
// M2 scope: action arrays + counters + generation metadata.
// M3 adds: rte_hash, rte_fib, NUMA-local allocation.

struct Ruleset {
  // ---- L2 ----
  action::RuleAction* l2_actions = nullptr;
  std::uint32_t l2_actions_capacity = 0;
  std::uint32_t n_l2_rules = 0;

  // ---- L3 ----
  action::RuleAction* l3_actions = nullptr;
  std::uint32_t l3_actions_capacity = 0;
  std::uint32_t n_l3_rules = 0;

  // ---- L4 ----
  action::RuleAction* l4_actions = nullptr;
  std::uint32_t l4_actions_capacity = 0;
  std::uint32_t n_l4_rules = 0;

  // ---- Default behavior / fragment policy ----
  std::uint8_t default_action = 0;   // ALLOW or DROP
  std::uint8_t fragment_policy = 0;  // L3_ONLY | DROP | ALLOW

  // ---- Generation metadata (D12, §4.1) ----
  std::uint64_t generation = 0;

  // ---- Per-lcore counters (§4.3) ----
  RuleCounter* counters = nullptr;   // flat array [num_lcores][counter_slots_per_lcore]
  std::uint32_t counter_slots_per_lcore = 0;
  std::uint32_t num_lcores = 0;

  // Get the counter row for a given lcore.
  RuleCounter* counter_row(unsigned lcore_id) const {
    if (!counters || lcore_id >= num_lcores) return nullptr;
    return counters + static_cast<std::size_t>(lcore_id) * counter_slots_per_lcore;
  }

  // Destructor — free owned memory (M2 uses standard allocators).
  ~Ruleset();

  // Move-only.
  Ruleset() = default;
  Ruleset(Ruleset&& other) noexcept;
  Ruleset& operator=(Ruleset&& other) noexcept;

  // No copy.
  Ruleset(const Ruleset&) = delete;
  Ruleset& operator=(const Ruleset&) = delete;
};

}  // namespace pktgate::ruleset
