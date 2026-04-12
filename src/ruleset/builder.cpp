// src/ruleset/builder.cpp
//
// M2 C9 — RulesetBuilder: CompileResult + Sizing → Ruleset.
//
// Allocates action arenas sized from config (D6), per-lcore counter
// rows (§4.3, D3), copies compiled actions into the arenas, and
// assigns a monotonically incrementing generation (D12).
//
// M2 uses standard C++ allocators. DPDK-aware allocation (rte_malloc
// on target NUMA socket) is M3.

#include "src/ruleset/builder.h"

#include <atomic>
#include <cstring>
#include <new>

namespace pktgate::ruleset {

// Process-wide generation counter. Monotonically incrementing, never
// wraps in practice (2^64 builds). std::memory_order_relaxed is fine —
// generation is metadata, not a synchronization primitive.
static std::atomic<std::uint64_t> g_generation{0};

Ruleset build_ruleset(const compiler::CompileResult& cr,
                      const config::Sizing& sizing,
                      unsigned num_lcores) {
  Ruleset rs;

  const auto cap = sizing.rules_per_layer_max;

  // ---- Action arenas (D6: sized from config, not hardcoded) ----
  rs.l2_actions_capacity = cap;
  rs.l3_actions_capacity = cap;
  rs.l4_actions_capacity = cap;

  rs.l2_actions = new action::RuleAction[cap]();
  rs.l3_actions = new action::RuleAction[cap]();
  rs.l4_actions = new action::RuleAction[cap]();

  // Copy compiled actions into arenas. The compiler produces a dense
  // vector per layer; we copy into the pre-allocated arena.
  auto copy_actions = [](action::RuleAction* dst, std::uint32_t dst_cap,
                         const std::vector<compiler::CompiledAction>& src)
      -> std::uint32_t {
    const auto n = static_cast<std::uint32_t>(
        src.size() < dst_cap ? src.size() : dst_cap);
    for (std::uint32_t i = 0; i < n; ++i) {
      auto& d = dst[i];
      const auto& s = src[i];
      d.rule_id = static_cast<std::uint32_t>(s.rule_id);
      d.counter_slot = s.counter_slot;
      d.verb = static_cast<std::uint8_t>(s.verb);
      d.next_layer = 0;
      d.execution_tier = static_cast<std::uint8_t>(s.execution_tier);
      d.flags = 0;
      d.redirect_port = 0xFFFF;
      d.mirror_port = 0xFFFF;
      d.dscp = 0;
      d.pcp = 0;
      d.rl_index = 0;
    }
    return n;
  };

  rs.n_l2_rules = copy_actions(rs.l2_actions, cap, cr.l2_actions);
  rs.n_l3_rules = copy_actions(rs.l3_actions, cap, cr.l3_actions);
  rs.n_l4_rules = copy_actions(rs.l4_actions, cap, cr.l4_actions);

  // ---- Per-lcore counter rows (§4.3, D3) ----
  //
  // n_rules_total = rules_per_layer_max * 3. Each lcore gets a
  // contiguous array of RuleCounter[n_rules_total], 64B-aligned.
  // The flat buffer is [num_lcores][counter_slots_per_lcore].
  const std::uint32_t total_slots = 3u * cap;
  rs.counter_slots_per_lcore = total_slots;
  rs.num_lcores = num_lcores;

  if (num_lcores > 0 && total_slots > 0) {
    const auto total_counters =
        static_cast<std::size_t>(num_lcores) * total_slots;
    const auto alloc_bytes = total_counters * sizeof(RuleCounter);
    // Aligned allocation — RuleCounter is alignas(64).
    void* mem = ::operator new(alloc_bytes, std::align_val_t{64});
    std::memset(mem, 0, alloc_bytes);
    rs.counters = static_cast<RuleCounter*>(mem);
  }

  // ---- Generation (D12) ----
  rs.generation =
      g_generation.fetch_add(1, std::memory_order_relaxed) + 1;

  return rs;
}

}  // namespace pktgate::ruleset
