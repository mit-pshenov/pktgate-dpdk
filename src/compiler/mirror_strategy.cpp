// src/compiler/mirror_strategy.cpp
//
// M2 C7 — Mirror strategy selection (D26) + verb classification.
//
// is_mutating_verb: D26 MUTATING_VERBS lookup. Uses -Wswitch-enum to
// ensure new ActionVerb values are handled (D25).
//
// determine_mirror_strategy: three-gate logic per D26 spec.

#include "src/compiler/mirror_strategy.h"

namespace pktgate::compiler {

bool is_mutating_verb(ActionVerb verb) {
  // D26: MUTATING_VERBS = { TAG } for baseline.
  // -Wswitch-enum ensures a compile error if a new ActionVerb value
  // is added without updating this switch.
  switch (verb) {
    case ActionVerb::kTag:
      return true;
    case ActionVerb::kAllow:
    case ActionVerb::kDrop:
    case ActionVerb::kMirror:
    case ActionVerb::kRateLimit:
    case ActionVerb::kRedirect:
      return false;
  }
  // Unreachable with exhaustive switch, but satisfies compilers that
  // warn about missing return after switch on enum.
  return false;
}

MirrorStrategy determine_mirror_strategy(
    const std::vector<ActionVerb>& verbs_present,
    bool config_zero_copy,
    const DriverCapabilities& caps) {
  // D26 three gates — all must be true for REFCNT_ZERO_COPY:
  //   1. config_requests_zero_copy (operator opt-in)
  //   2. no mutating verbs in ruleset
  //   3. driver capability tx_non_mutating

  if (!config_zero_copy) {
    return MirrorStrategy::kDeepCopy;
  }

  for (const auto verb : verbs_present) {
    if (is_mutating_verb(verb)) {
      return MirrorStrategy::kDeepCopy;
    }
  }

  if (!caps.tx_non_mutating) {
    return MirrorStrategy::kDeepCopy;
  }

  return MirrorStrategy::kRefcntZeroCopy;
}

}  // namespace pktgate::compiler
