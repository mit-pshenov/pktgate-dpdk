// src/compiler/compiler.cpp
//
// M2 C8 — Enum dispatch helpers (D25).
//
// verb_label:  ActionVerb  → human-readable string.
// layer_label: Layer       → human-readable string.
//
// Both use exhaustive switch statements (no default arm) so that
// -Wswitch-enum catches any new enum value that isn't handled.
// This is the "action dispatch skeleton" referenced by D25 and tested
// by U3.22/U3.23.

#include "src/compiler/compiler.h"

namespace pktgate::compiler {

const char* verb_label(ActionVerb verb) {
  switch (verb) {
    case ActionVerb::kAllow:     return "allow";
    case ActionVerb::kDrop:      return "drop";
    case ActionVerb::kMirror:    return "mirror";
    case ActionVerb::kRateLimit: return "rate_limit";
    case ActionVerb::kTag:       return "tag";
    case ActionVerb::kRedirect:  return "redirect";
  }
  // Unreachable with exhaustive switch, but satisfies compilers that
  // warn about missing return after switch on enum.
  return "unknown";
}

const char* layer_label(Layer layer) {
  switch (layer) {
    case Layer::kL2: return "l2";
    case Layer::kL3: return "l3";
    case Layer::kL4: return "l4";
  }
  return "unknown";
}

}  // namespace pktgate::compiler
