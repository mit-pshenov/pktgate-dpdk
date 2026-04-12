// src/ruleset/ruleset.cpp
//
// M2 C9+C10 — Ruleset lifetime management.

#include "src/ruleset/ruleset.h"

#include <cstdlib>
#include <cstring>
#include <new>

namespace pktgate::ruleset {

Ruleset::~Ruleset() {
  if (free_fn) {
    // D23 custom allocator path — free through the same allocator.
    if (l2_actions) free_fn(l2_actions, free_ctx);
    if (l3_actions) free_fn(l3_actions, free_ctx);
    if (l4_actions) free_fn(l4_actions, free_ctx);
    if (counters) free_fn(counters, free_ctx);
  } else {
    // C9 standard path — ::operator new / delete.
    delete[] l2_actions;
    delete[] l3_actions;
    delete[] l4_actions;
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
      default_action(other.default_action),
      fragment_policy(other.fragment_policy),
      generation(other.generation),
      counters(other.counters),
      counter_slots_per_lcore(other.counter_slots_per_lcore),
      num_lcores(other.num_lcores),
      free_fn(other.free_fn),
      free_ctx(other.free_ctx) {
  other.l2_actions = nullptr;
  other.l3_actions = nullptr;
  other.l4_actions = nullptr;
  other.counters = nullptr;
  other.free_fn = nullptr;
  other.free_ctx = nullptr;
}

Ruleset& Ruleset::operator=(Ruleset&& other) noexcept {
  if (this != &other) {
    // Free existing through whichever allocator owns this Ruleset.
    if (free_fn) {
      if (l2_actions) free_fn(l2_actions, free_ctx);
      if (l3_actions) free_fn(l3_actions, free_ctx);
      if (l4_actions) free_fn(l4_actions, free_ctx);
      if (counters) free_fn(counters, free_ctx);
    } else {
      delete[] l2_actions;
      delete[] l3_actions;
      delete[] l4_actions;
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
    default_action = other.default_action;
    fragment_policy = other.fragment_policy;
    generation = other.generation;
    counters = other.counters;
    counter_slots_per_lcore = other.counter_slots_per_lcore;
    num_lcores = other.num_lcores;
    free_fn = other.free_fn;
    free_ctx = other.free_ctx;

    other.l2_actions = nullptr;
    other.l3_actions = nullptr;
    other.l4_actions = nullptr;
    other.counters = nullptr;
    other.free_fn = nullptr;
    other.free_ctx = nullptr;
  }
  return *this;
}

}  // namespace pktgate::ruleset
