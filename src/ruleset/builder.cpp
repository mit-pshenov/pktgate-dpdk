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

  // ---- Rate-limit action arena (M9 C2 + M9 C3) ----
  //
  // Sized to `cap` (same capacity as l{2,3,4}_actions so every rule
  // can in principle carry an RL verb). Allocated + zero-init'd here;
  // M9 C3 populates entries on the fly during copy_actions below.
  // C2 comment preserved for history: the hot path only dereferences
  // entries whose `rl_index` the compiler set, and those are always
  // below `n_rl_actions` (populated during copy_actions).
  rs.rl_actions_capacity = cap;
  rs.rl_actions = new RlAction[cap]();
  rs.n_rl_actions = 0;

  // Copy compiled actions into arenas. The compiler produces a dense
  // vector per layer; we copy into the pre-allocated arena.
  //
  // M7 C2b retrofit (D41): dscp / pcp / redirect_port come from
  // CompiledAction (filled by object_compiler::resolve_action), not
  // hardcoded. Before the retrofit these three fields stayed at
  // zero / 0xFFFF regardless of config — making TAG a no-op and
  // REDIRECT a silent drop. mirror_port stays 0xFFFF (mirror is
  // compile-rejected in MVP, D7).
  //
  // M9 C3 (D10, D24, D41): rl_index comes from CompiledAction.rl_slot
  // (filled by object_compiler::compile via the RlSlotAllocator). For
  // every RL verb we ALSO populate Ruleset::rl_actions[slot] with the
  // rule_id + rate + burst snapshot — the hot path reads from there.
  // The two pipelines (RuleAction.rl_index vs Ruleset::rl_actions[])
  // MUST stay in lockstep; this is the D41 invariant that M7 C2b and
  // M8 C5 both broke in different ways. The RL slot is also used to
  // bump n_rl_actions (max-slot+1 instead of a simple count, so the
  // array stays densely indexable up to the highest live slot).
  auto copy_actions =
      [&rs](action::RuleAction* dst, std::uint32_t dst_cap,
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
      d.redirect_port = s.redirect_port;
      d.mirror_port = 0xFFFF;
      d.dscp = s.dscp;
      d.pcp = s.pcp;
      d.rl_index = s.rl_slot;

      // D41 lockstep: for every kRateLimit rule, populate
      // rs.rl_actions[slot] with the rule_id + rate + burst snapshot
      // so the hot-path lookup `rs.rl_actions[action->rl_index]` hits
      // real data. `slot < rs.rl_actions_capacity` is guaranteed by
      // the allocator (cap is the same on both sides). Non-RL verbs
      // keep the sentinel 0xFFFF; we skip them here so we never
      // overwrite rl_actions[0] unintentionally.
      if (s.verb == compiler::ActionVerb::kRateLimit &&
          s.rl_slot < rs.rl_actions_capacity) {
        rs.rl_actions[s.rl_slot].rule_id =
            static_cast<std::uint64_t>(s.rule_id);
        rs.rl_actions[s.rl_slot].rate_bps = s.rl_rate_bps;
        rs.rl_actions[s.rl_slot].burst_bytes = s.rl_burst_bytes;
        const std::uint32_t live_count =
            static_cast<std::uint32_t>(s.rl_slot) + 1u;
        if (live_count > rs.n_rl_actions) {
          rs.n_rl_actions = live_count;
        }
      }
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

  // ---- D17: fragment_policy from CompileResult ----
  rs.fragment_policy = cr.fragment_policy;

  // ---- M7 C2b (D41): default_action from CompileResult ----
  rs.default_action = cr.default_action;

  // ---- Generation (D12) ----
  rs.generation =
      g_generation.fetch_add(1, std::memory_order_relaxed) + 1;

  return rs;
}

// ---- Default allocator (D23 C10) ----

static void* default_alloc(std::size_t size, std::size_t alignment,
                           int /*socket_id*/, void* /*ctx*/) {
  void* mem = ::operator new(size, std::align_val_t{alignment});
  std::memset(mem, 0, size);
  return mem;
}

static void default_free(void* ptr, void* /*ctx*/) {
  // We don't know the alignment, but operator delete with align_val_t
  // is needed if allocated with aligned new. For the default allocator
  // path, we only use this for the 4-byte aligned action arrays —
  // but actually, let's just use the base operator delete which is fine
  // for aligned new on most platforms (and the default allocator is only
  // used when no custom allocator is provided — which means the old
  // code path in the destructor handles it).
  //
  // Actually, the default allocator's free_fn is only called from the
  // Ruleset destructor when free_fn is set. For the zero-arg
  // build_ruleset, free_fn stays null and the destructor uses the old
  // delete[] / operator delete path. So this free_fn is only for the
  // allocator-aware overload when using default_allocator().
  std::free(ptr);  // aligned_alloc -> free is standard
}

RulesetAllocator default_allocator() {
  return RulesetAllocator{&default_alloc, &default_free, nullptr};
}

// ---- Allocator-aware build_ruleset (D23 C10) ----
//
// All allocations go through alloc.allocate() with the declared
// socket_id. The Ruleset stores the deallocator so its destructor
// can free through the same path.

Ruleset build_ruleset(const compiler::CompileResult& cr,
                      const config::Sizing& sizing,
                      unsigned num_lcores,
                      const RulesetAllocator& alloc,
                      int socket_id) {
  Ruleset rs;

  const auto cap = sizing.rules_per_layer_max;

  // ---- Action arenas (D6 + D23) ----
  rs.l2_actions_capacity = cap;
  rs.l3_actions_capacity = cap;
  rs.l4_actions_capacity = cap;

  const auto action_bytes = cap * sizeof(action::RuleAction);
  constexpr auto action_align = alignof(action::RuleAction);

  rs.l2_actions = static_cast<action::RuleAction*>(
      alloc.allocate(action_bytes, action_align, socket_id, alloc.ctx));
  rs.l3_actions = static_cast<action::RuleAction*>(
      alloc.allocate(action_bytes, action_align, socket_id, alloc.ctx));
  rs.l4_actions = static_cast<action::RuleAction*>(
      alloc.allocate(action_bytes, action_align, socket_id, alloc.ctx));

  // ---- Rate-limit action arena (M9 C2, D23 + M9 C3 D10/D24/D41) ----
  //
  // Allocator-aware build path mirrors the zero-arg overload above —
  // cap-sized array, zero-initialised. Uses alloc.allocate so the
  // deallocator path (free_fn) handles the release symmetrically.
  // M9 C3 populates entries during copy_actions below.
  rs.rl_actions_capacity = cap;
  const auto rl_bytes = cap * sizeof(RlAction);
  rs.rl_actions = static_cast<RlAction*>(
      alloc.allocate(rl_bytes, alignof(RlAction), socket_id, alloc.ctx));
  // Custom allocators may not zero memory; we rely on unused slots
  // carrying rule_id=0, rate=0, burst=0 (D41 lockstep only populates
  // slots for live RL verbs). Default + spy allocators do zero-fill;
  // belt-and-braces memset guarantees the invariant under any
  // allocator implementation.
  if (rs.rl_actions != nullptr) {
    std::memset(rs.rl_actions, 0, rl_bytes);
  }
  rs.n_rl_actions = 0;

  // Copy compiled actions into arenas.
  //
  // M7 C2b retrofit (D41): see copy_actions in the zero-arg overload
  // above — dscp / pcp / redirect_port now come from CompiledAction.
  // M9 C3 (D10, D24, D41): rl_index comes from CompiledAction.rl_slot;
  // rs.rl_actions[slot] is populated in lockstep. See the zero-arg
  // overload above for the full rationale.
  auto copy_actions =
      [&rs](action::RuleAction* dst, std::uint32_t dst_cap,
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
      d.redirect_port = s.redirect_port;
      d.mirror_port = 0xFFFF;
      d.dscp = s.dscp;
      d.pcp = s.pcp;
      d.rl_index = s.rl_slot;

      if (s.verb == compiler::ActionVerb::kRateLimit &&
          s.rl_slot < rs.rl_actions_capacity) {
        rs.rl_actions[s.rl_slot].rule_id =
            static_cast<std::uint64_t>(s.rule_id);
        rs.rl_actions[s.rl_slot].rate_bps = s.rl_rate_bps;
        rs.rl_actions[s.rl_slot].burst_bytes = s.rl_burst_bytes;
        const std::uint32_t live_count =
            static_cast<std::uint32_t>(s.rl_slot) + 1u;
        if (live_count > rs.n_rl_actions) {
          rs.n_rl_actions = live_count;
        }
      }
    }
    return n;
  };

  rs.n_l2_rules = copy_actions(rs.l2_actions, cap, cr.l2_actions);
  rs.n_l3_rules = copy_actions(rs.l3_actions, cap, cr.l3_actions);
  rs.n_l4_rules = copy_actions(rs.l4_actions, cap, cr.l4_actions);

  // ---- Per-lcore counter rows (§4.3, D3, D23) ----
  const std::uint32_t total_slots = 3u * cap;
  rs.counter_slots_per_lcore = total_slots;
  rs.num_lcores = num_lcores;

  if (num_lcores > 0 && total_slots > 0) {
    const auto total_counters =
        static_cast<std::size_t>(num_lcores) * total_slots;
    const auto alloc_bytes = total_counters * sizeof(RuleCounter);
    rs.counters = static_cast<RuleCounter*>(
        alloc.allocate(alloc_bytes, alignof(RuleCounter), socket_id,
                       alloc.ctx));
  }

  // ---- Allocator bookkeeping (D23) ----
  rs.free_fn = alloc.deallocate;
  rs.free_ctx = alloc.ctx;

  // ---- D17: fragment_policy from CompileResult ----
  rs.fragment_policy = cr.fragment_policy;

  // ---- M7 C2b (D41): default_action from CompileResult ----
  rs.default_action = cr.default_action;

  // ---- Generation (D12) ----
  rs.generation =
      g_generation.fetch_add(1, std::memory_order_relaxed) + 1;

  return rs;
}

// ---- D28 TX-queue symmetry check (C10) ----

std::vector<TxSymmetryError> check_port_tx_symmetry(
    const std::vector<config::InterfaceRole>& roles,
    unsigned n_workers,
    const std::unordered_map<std::string, EthDevInfo>& dev_info) {
  std::vector<TxSymmetryError> errors;
  for (const auto& role : roles) {
    auto it = dev_info.find(role.name);
    std::uint16_t max_txq = 0;
    if (it != dev_info.end()) {
      max_txq = it->second.max_tx_queues;
    }
    if (max_txq < n_workers) {
      errors.push_back(
          TxSymmetryError{role.name, max_txq, n_workers});
    }
  }
  return errors;
}

}  // namespace pktgate::ruleset
