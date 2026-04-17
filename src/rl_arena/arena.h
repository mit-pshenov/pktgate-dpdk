// src/rl_arena/arena.h
//
// M9 C1 — `RateLimitArena` — slot lifecycle for per-rule token-bucket
// rows. Implements D24:
//
//   * alloc_slot(rule_id)
//       - first publish: pick the lowest free index via bitmap scan,
//         mark it live, zero-init the row's per-lcore bucket array,
//         insert rule_id → slot in `id_to_slot`.
//       - survives reload: if `rule_id` already has a slot, return
//         the existing slot and leave the row (bucket tokens, TSC,
//         dropped counters) UNCHANGED.
//       - exhaustion: when every slot is live, return `kInvalidSlot`
//         (0xFFFF). Caller's responsibility to refuse the build.
//   * free_slot(rule_id)
//       - clears `slot_live[slot]` and removes rule_id from id_to_slot.
//       - DOES NOT deallocate the row vector — the row's memory stays
//         allocated; it is re-zeroed on the NEXT alloc that reuses
//         the slot (D24: free slot, not free row).
//       - idempotent: unknown rule_id is a silent no-op.
//   * lookup_slot(rule_id) → optional<uint16_t>
//       - control-plane-only. Hot path reads `rows[slot].per_lcore[n]`
//         directly via the slot index stored in `RuleAction.rl_index`.
//   * get_row(slot) → RlRow&
//       - mutable row access for test/control-plane use. Hot path
//         uses this too but does not touch id_to_slot / slot_live.
//
// Layering (U5.9 invariant): this header/TU carries std::unordered_map,
// vector, optional — all banned from the bucket-math library. Therefore
// RateLimitArena lives in a SEPARATE translation unit and a SEPARATE
// static library (`pktgate_rl_ctl`) from `pktgate_rl` (bucket math).
// Both link into the control-plane side; only `pktgate_rl` links into
// the hot path symbol surface that U5.9 greps.
//
// D-refs: D1 (no atomic on row), D10 (arena outside Ruleset; survives
// reload), D24 (slot vs row lifecycle), §4.4.
//
// Test coverage: tests/unit/test_rl_arena_slot.cpp U4.9 .. U4.12.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <vector>

#include "src/rl_arena/rl_arena.h"

namespace pktgate::rl_arena {

// Sentinel returned by alloc_slot when the arena is full. Matches the
// max representable value of the `RuleAction.rl_index` field.
inline constexpr std::uint16_t kInvalidSlot = 0xFFFFu;

// Control-plane arena. Single-writer (reload path under
// ControlPlaneState::reload_mutex); multi-reader workers. Workers
// never access id_to_slot or slot_live_; they dereference `rows_[slot]`
// via the slot index stored in `RuleAction.rl_index` (built at compile
// time, C3). The per-lcore bucket row is the only data touched on the
// hot path — see D1 and U5.9.
//
// Slot reuse policy: lowest-free-index via bitmap scan on alloc. O(n)
// per alloc where n = max_rules; acceptable for control-plane (4096
// max at prod target). When a slot is freed, the next alloc with no
// lower-index free slot picks the freed slot and zero-initialises its
// row. When the freed slot is NOT the lowest free, it waits for the
// earlier indices to be exhausted first. Documented here so C4 GC
// tests can predict behaviour.
class RateLimitArena {
 public:
  explicit RateLimitArena(std::uint16_t max_rules);

  RateLimitArena(const RateLimitArena&) = delete;
  RateLimitArena& operator=(const RateLimitArena&) = delete;
  RateLimitArena(RateLimitArena&&) = delete;
  RateLimitArena& operator=(RateLimitArena&&) = delete;

  // First publish OR survives-reload. Returns `kInvalidSlot` when every
  // slot is live. When a slot is reused (a previously-freed slot is
  // picked up for a new rule_id), the row is zero-initialised BEFORE
  // return. When the same rule_id is alloc'd twice (reload), the row
  // state is preserved.
  std::uint16_t alloc_slot(std::uint64_t rule_id);

  // Release a slot. Idempotent / silent for unknown rule_id. Row
  // memory is NOT deallocated (D24).
  void free_slot(std::uint64_t rule_id);

  // Control-plane lookup. Hot path must NOT call this.
  std::optional<std::uint16_t> lookup_slot(std::uint64_t rule_id) const;

  // Row access. Hot path reads `get_row(slot).per_lcore[lcore_id]`
  // via the slot index baked into RuleAction at build time.
  RlRow& get_row(std::uint16_t slot);
  const RlRow& get_row(std::uint16_t slot) const;

  // Introspection for tests / telemetry. Control-plane only.
  bool slot_live(std::uint16_t slot) const;
  std::size_t row_vector_size() const { return rows_.size(); }
  std::uint16_t max_rules() const { return max_rules_; }

 private:
  std::uint16_t max_rules_;
  std::vector<RlRow> rows_;                       // indexed by slot
  std::vector<std::uint8_t> slot_live_;           // bitmap as bytes
  std::unordered_map<std::uint64_t, std::uint16_t> id_to_slot_;
};

}  // namespace pktgate::rl_arena
