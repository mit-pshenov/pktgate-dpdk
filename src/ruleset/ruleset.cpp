// src/ruleset/ruleset.cpp
//
// M2 C9+C10 — Ruleset lifetime management.

#include "src/ruleset/ruleset.h"

#include <cstdlib>
#include <cstring>
#include <new>

namespace pktgate::ruleset {

Ruleset::~Ruleset() {
  // M4 C0 retrofit — tear down DPDK handles first (while the compound
  // arenas the hashes/FIBs point into are still valid). The deleter
  // lives in builder_eal.cpp (libpktgate_dp) to keep this TU DPDK-free.
  if (eal_deleter) {
    eal_deleter(*this);
  }

  // M4 C0 retrofit — free compound arenas. These are always allocated
  // with new[] by populate_ruleset_eal(), regardless of the free_fn
  // path below (the action arenas use the custom allocator, but the
  // compound arenas are small and staged on the host heap — see
  // builder_eal.cpp for rationale).
  delete[] l2_compound_entries;
  delete[] l3_compound_entries;
  delete[] l4_compound_entries;

  if (free_fn) {
    // D23 custom allocator path — free through the same allocator.
    if (l2_actions) free_fn(l2_actions, free_ctx);
    if (l3_actions) free_fn(l3_actions, free_ctx);
    if (l4_actions) free_fn(l4_actions, free_ctx);
    if (rl_actions) free_fn(rl_actions, free_ctx);
    if (counters) free_fn(counters, free_ctx);
  } else {
    // C9 standard path — ::operator new / delete.
    delete[] l2_actions;
    delete[] l3_actions;
    delete[] l4_actions;
    // M9 C2: rl_actions always new[]-allocated on the no-custom-allocator
    // path (mirrors l{2,3,4}_actions — small, host-heap is fine).
    delete[] rl_actions;
    if (counters) {
      ::operator delete(counters, std::align_val_t{64});
    }
  }
}

Ruleset::Ruleset(Ruleset&& other) noexcept
    : l2_actions(other.l2_actions),
      l2_actions_capacity(other.l2_actions_capacity),
      n_l2_rules(other.n_l2_rules),
      l3_actions(other.l3_actions),
      l3_actions_capacity(other.l3_actions_capacity),
      n_l3_rules(other.n_l3_rules),
      l4_actions(other.l4_actions),
      l4_actions_capacity(other.l4_actions_capacity),
      n_l4_rules(other.n_l4_rules),
      l2_compound_hash(other.l2_compound_hash),
      l3_v4_fib(other.l3_v4_fib),
      l3_v6_fib(other.l3_v6_fib),
      l4_compound_hash(other.l4_compound_hash),
      l2_compound_entries(other.l2_compound_entries),
      l2_compound_count(other.l2_compound_count),
      l3_compound_entries(other.l3_compound_entries),
      l3_compound_count(other.l3_compound_count),
      l4_compound_entries(other.l4_compound_entries),
      l4_compound_count(other.l4_compound_count),
      eal_owned(other.eal_owned),
      rl_actions(other.rl_actions),
      rl_actions_capacity(other.rl_actions_capacity),
      n_rl_actions(other.n_rl_actions),
      default_action(other.default_action),
      fragment_policy(other.fragment_policy),
      generation(other.generation),
      counters(other.counters),
      counter_slots_per_lcore(other.counter_slots_per_lcore),
      num_lcores(other.num_lcores),
      free_fn(other.free_fn),
      free_ctx(other.free_ctx),
      eal_deleter(other.eal_deleter) {
  other.l2_actions = nullptr;
  other.l3_actions = nullptr;
  other.l4_actions = nullptr;
  other.counters = nullptr;
  other.free_fn = nullptr;
  other.free_ctx = nullptr;
  other.l2_compound_hash = nullptr;
  other.l3_v4_fib = nullptr;
  other.l3_v6_fib = nullptr;
  other.l4_compound_hash = nullptr;
  other.l2_compound_entries = nullptr;
  other.l3_compound_entries = nullptr;
  other.l4_compound_entries = nullptr;
  other.rl_actions = nullptr;
  other.rl_actions_capacity = 0;
  other.n_rl_actions = 0;
  other.eal_owned = false;
  other.eal_deleter = nullptr;
}

Ruleset& Ruleset::operator=(Ruleset&& other) noexcept {
  if (this != &other) {
    // Tear down EAL handles + compound arenas in the same order as
    // the destructor (see ~Ruleset for rationale).
    if (eal_deleter) {
      eal_deleter(*this);
    }
    delete[] l2_compound_entries;
    delete[] l3_compound_entries;
    delete[] l4_compound_entries;

    // Free existing through whichever allocator owns this Ruleset.
    if (free_fn) {
      if (l2_actions) free_fn(l2_actions, free_ctx);
      if (l3_actions) free_fn(l3_actions, free_ctx);
      if (l4_actions) free_fn(l4_actions, free_ctx);
      if (rl_actions) free_fn(rl_actions, free_ctx);
      if (counters) free_fn(counters, free_ctx);
    } else {
      delete[] l2_actions;
      delete[] l3_actions;
      delete[] l4_actions;
      delete[] rl_actions;
      if (counters) {
        ::operator delete(counters, std::align_val_t{64});
      }
    }

    // Move.
    l2_actions = other.l2_actions;
    l2_actions_capacity = other.l2_actions_capacity;
    n_l2_rules = other.n_l2_rules;
    l3_actions = other.l3_actions;
    l3_actions_capacity = other.l3_actions_capacity;
    n_l3_rules = other.n_l3_rules;
    l4_actions = other.l4_actions;
    l4_actions_capacity = other.l4_actions_capacity;
    n_l4_rules = other.n_l4_rules;
    l2_compound_hash = other.l2_compound_hash;
    l3_v4_fib = other.l3_v4_fib;
    l3_v6_fib = other.l3_v6_fib;
    l4_compound_hash = other.l4_compound_hash;
    l2_compound_entries = other.l2_compound_entries;
    l2_compound_count = other.l2_compound_count;
    l3_compound_entries = other.l3_compound_entries;
    l3_compound_count = other.l3_compound_count;
    l4_compound_entries = other.l4_compound_entries;
    l4_compound_count = other.l4_compound_count;
    eal_owned = other.eal_owned;
    rl_actions = other.rl_actions;
    rl_actions_capacity = other.rl_actions_capacity;
    n_rl_actions = other.n_rl_actions;
    default_action = other.default_action;
    fragment_policy = other.fragment_policy;
    generation = other.generation;
    counters = other.counters;
    counter_slots_per_lcore = other.counter_slots_per_lcore;
    num_lcores = other.num_lcores;
    free_fn = other.free_fn;
    free_ctx = other.free_ctx;
    eal_deleter = other.eal_deleter;

    other.l2_actions = nullptr;
    other.l3_actions = nullptr;
    other.l4_actions = nullptr;
    other.counters = nullptr;
    other.free_fn = nullptr;
    other.free_ctx = nullptr;
    other.l2_compound_hash = nullptr;
    other.l3_v4_fib = nullptr;
    other.l3_v6_fib = nullptr;
    other.l4_compound_hash = nullptr;
    other.l2_compound_entries = nullptr;
    other.l3_compound_entries = nullptr;
    other.l4_compound_entries = nullptr;
    other.rl_actions = nullptr;
    other.rl_actions_capacity = 0;
    other.n_rl_actions = 0;
    other.eal_owned = false;
    other.eal_deleter = nullptr;
  }
  return *this;
}

}  // namespace pktgate::ruleset
