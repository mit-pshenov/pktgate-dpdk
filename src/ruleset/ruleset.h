// src/ruleset/ruleset.h
//
// M2 C9+C10 — Ruleset struct and counter types.
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
//   * D23  — NUMA awareness (allocator stored for proper deallocation)

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

#include "src/action/action.h"
#include "src/compiler/compiler.h"
#include "src/ruleset/types.h"

// Forward declarations for DPDK handles (M4 C0 retrofit). We do NOT
// include <rte_hash.h> / <rte_fib.h> here because this header is
// consumed by `libpktgate_core` (DPDK-free). The actual creation +
// population lives in `builder_eal.cpp` inside `libpktgate_dp` where
// the DPDK headers are in scope.
struct rte_hash;
struct rte_fib;
struct rte_fib6;

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

  // ---- DPDK compound tables (M4 C0 retrofit) ----
  //
  // Pointer handles opened and populated by the EAL-aware builder stage
  // (src/ruleset/builder_eal.cpp). The pure-C++ M2 builder leaves these
  // nullptr; only the full production boot path (or a test that runs
  // under EalFixture) calls `populate_ruleset_eal()` to open the hashes
  // / FIBs and key them from the CompileResult compound vectors.
  //
  // l2_compound_entries / l3_compound_entries / l4_compound_entries
  // are the backing arenas that own the values the hash tables / FIBs
  // point at — the hash stores a pointer into the arena, not a copy,
  // so the arena must outlive the hash. All four fields are freed in
  // ~Ruleset through the DPDK destroy helpers (conditional on the
  // `eal_owned` flag so a pure-C++ Ruleset doesn't call rte_hash_free
  // on a nullptr it was never given).
  rte_hash* l2_compound_hash = nullptr;
  rte_fib*  l3_v4_fib = nullptr;
  rte_fib6* l3_v6_fib = nullptr;
  rte_hash* l4_compound_hash = nullptr;

  L2CompoundEntry* l2_compound_entries = nullptr;
  std::uint32_t    l2_compound_count = 0;
  L3CompoundEntry* l3_compound_entries = nullptr;
  std::uint32_t    l3_compound_count = 0;
  L4CompoundEntry* l4_compound_entries = nullptr;
  std::uint32_t    l4_compound_count = 0;

  // Set when `populate_ruleset_eal` opened the DPDK handles, so the
  // destructor knows whether to call rte_hash_free / rte_fib_free.
  bool eal_owned = false;

  // ---- Default behavior / fragment policy ----
  std::uint8_t default_action = 0;   // ALLOW or DROP
  std::uint8_t fragment_policy = 0;  // L3_ONLY | DROP | ALLOW

  // ---- Generation metadata (D12, §4.1) ----
  std::uint64_t generation = 0;

  // ---- Per-lcore counters (§4.3) ----
  RuleCounter* counters = nullptr;   // flat array [num_lcores][counter_slots_per_lcore]
  std::uint32_t counter_slots_per_lcore = 0;
  std::uint32_t num_lcores = 0;

  // ---- Allocator bookkeeping (D23, C10) ----
  //
  // When a custom allocator was used (build_ruleset with allocator),
  // these are set so the destructor frees through the same path.
  // When null, the destructor uses ::operator delete (C9 compat).
  using FreeFn = void (*)(void* ptr, void* ctx);
  FreeFn free_fn = nullptr;
  void* free_ctx = nullptr;

  // ---- EAL handle deleter (M4 C0 retrofit) ----
  //
  // populate_ruleset_eal() fills this in so ~Ruleset can free the
  // rte_hash / rte_fib handles without pulling DPDK headers into
  // ruleset.cpp (which lives in libpktgate_core, the DPDK-free lib).
  // The callback walks the Ruleset's EAL fields and calls the
  // appropriate rte_*_free helpers. When nullptr (pure-C++ path),
  // the destructor leaves all DPDK pointers alone.
  using EalDeleterFn = void (*)(Ruleset& rs);
  EalDeleterFn eal_deleter = nullptr;

  // Get the counter row for a given lcore.
  RuleCounter* counter_row(unsigned lcore_id) const {
    if (!counters || lcore_id >= num_lcores) return nullptr;
    return counters + static_cast<std::size_t>(lcore_id) * counter_slots_per_lcore;
  }

  // Destructor — free owned memory. Uses free_fn if set (D23 custom
  // allocator), otherwise ::operator delete (C9 standard path).
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
