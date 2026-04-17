// src/rl_arena/arena.cpp
//
// M9 C1 — RateLimitArena implementation. See arena.h for contract.

#include "src/rl_arena/arena.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>

namespace pktgate::rl_arena {

namespace {

// Zero-initialise every per-lcore bucket in a row. Used on alloc when
// a previously-freed slot is reused — D24 spec "row re-zeroed on next
// alloc" — and implicitly by RlRow value-initialisation on construct.
void zero_row(RlRow& row) {
  std::memset(&row, 0, sizeof(RlRow));
}

}  // namespace

RateLimitArena::RateLimitArena(std::uint16_t max_rules)
    : max_rules_(max_rules),
      rows_(max_rules),            // value-init zeros every TokenBucket
      slot_live_(max_rules, 0u) {  // all slots start free
  id_to_slot_.reserve(max_rules);
}

std::uint16_t RateLimitArena::alloc_slot(std::uint64_t rule_id) {
  // Survives-reload: already present → return existing slot, row state
  // unchanged.
  if (const auto it = id_to_slot_.find(rule_id); it != id_to_slot_.end()) {
    return it->second;
  }

  // Lowest-free-index scan. O(max_rules) on a cold alloc; control-plane
  // only, so acceptable up to the prod target (4096).
  for (std::uint16_t s = 0; s < max_rules_; ++s) {
    if (slot_live_[s] == 0u) {
      slot_live_[s] = 1u;
      // D24: a reused slot's row MUST be zero-initialised at alloc
      // time so the new rule_id starts with empty buckets. Fresh
      // (never-used) slots are already zero from the constructor, but
      // zeroing unconditionally keeps the code simple and a memset of
      // one row (~8 KiB at kMaxLcores=128) is a cold path.
      zero_row(rows_[s]);
      id_to_slot_.emplace(rule_id, s);
      return s;
    }
  }

  // Exhausted — caller (validator / builder) must refuse.
  return kInvalidSlot;
}

void RateLimitArena::free_slot(std::uint64_t rule_id) {
  const auto it = id_to_slot_.find(rule_id);
  if (it == id_to_slot_.end()) {
    // Silent no-op — matches §9.4 GC semantics where a second-pass or
    // shutdown drain may call free on an already-removed id.
    return;
  }
  const std::uint16_t slot = it->second;
  slot_live_[slot] = 0u;
  id_to_slot_.erase(it);
  // D24: DO NOT touch rows_[slot] — row memory stays allocated; the
  // row is re-zeroed on the next alloc that picks this index.
}

std::optional<std::uint16_t> RateLimitArena::lookup_slot(
    std::uint64_t rule_id) const {
  const auto it = id_to_slot_.find(rule_id);
  if (it == id_to_slot_.end()) {
    return std::nullopt;
  }
  return it->second;
}

RlRow& RateLimitArena::get_row(std::uint16_t slot) { return rows_[slot]; }

const RlRow& RateLimitArena::get_row(std::uint16_t slot) const {
  return rows_[slot];
}

bool RateLimitArena::slot_live(std::uint16_t slot) const {
  if (slot >= max_rules_) return false;
  return slot_live_[slot] != 0u;
}

}  // namespace pktgate::rl_arena
