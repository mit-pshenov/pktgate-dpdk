// src/compiler/object_compiler.cpp
//
// M2 C1 — object compiler + rule expansion implementation.
//
// compile_objects: ObjectPool → CompiledObjects (subnet flatten, port
// group expand).
//
// compile: Config → CompileResult (full pipeline: objects + per-layer
// rule expansion with port-list fan-out and dense counter_slot
// assignment per §4.3/D33).
//
// No DPDK deps. Pure C++ stdlib.

#include "src/compiler/object_compiler.h"

#include <unordered_set>
#include <variant>

#include "src/compiler/rule_compiler.h"

namespace pktgate::compiler {

// -------------------------------------------------------------------------
// compile_objects — expand named object definitions.

CompiledObjects compile_objects(const config::ObjectPool& pool) {
  CompiledObjects out;

  // Subnets: flatten name → CIDR list (U3.1)
  for (const auto& sobj : pool.subnets) {
    auto& vec = out.subnets.by_name[sobj.name];
    vec.reserve(sobj.cidrs.size());
    for (const auto& cidr : sobj.cidrs) {
      vec.push_back(cidr);
    }
  }

  // Port groups: flatten name → port list (U3.2)
  for (const auto& pg : pool.port_groups) {
    auto& vec = out.port_groups.by_name[pg.name];
    vec.reserve(pg.ports.size());
    for (const auto port : pg.ports) {
      vec.push_back(port);
    }
  }

  return out;
}

// -------------------------------------------------------------------------
// Action verb resolution from config::RuleAction variant.

static ActionVerb resolve_verb(const config::RuleAction& action) {
  return std::visit(
      [](const auto& a) -> ActionVerb {
        using T = std::decay_t<decltype(a)>;
        if constexpr (std::is_same_v<T, config::ActionAllow>)
          return ActionVerb::kAllow;
        else if constexpr (std::is_same_v<T, config::ActionDrop>)
          return ActionVerb::kDrop;
        else if constexpr (std::is_same_v<T, config::ActionRateLimit>)
          return ActionVerb::kRateLimit;
        else if constexpr (std::is_same_v<T, config::ActionTag>)
          return ActionVerb::kTag;
        else if constexpr (std::is_same_v<T, config::ActionTargetPort>)
          return ActionVerb::kRedirect;
        else if constexpr (std::is_same_v<T, config::ActionMirror>)
          return ActionVerb::kMirror;
        else
          return ActionVerb::kDrop;  // unreachable with exhaustive variant
      },
      action);
}

// -------------------------------------------------------------------------
// compile — full pipeline.

CompileResult compile(const config::Config& cfg,
                      const CompileOptions& opts) {
  CompileResult result;

  // Phase 1: compile objects
  result.objects = compile_objects(cfg.objects);

  // Phase 2: compile rules per layer with dense counter_slot assignment.
  //
  // For each rule:
  //   1. Create a CompiledAction with monotonic counter_slot (U3.4).
  //   2. Set execution_tier from hw_offload_hint (D4, U3.13/U3.14).
  //      When hw_offload_enabled is false (MVP), all rules stay SW
  //      regardless of hint (U3.15).
  //   3. If the rule has dst_ports (port-list), expand into N entries
  //      each with a distinct dst_port, all sharing the same action
  //      index (U3.2, U3.3).
  //   4. If the rule has a single dst_port, create one entry.
  //   5. Otherwise, create one entry with dst_port = -1.

  const bool hw_enabled = opts.hw_offload_enabled;

  auto compile_layer =
      [hw_enabled](const std::vector<config::Rule>& rules, Layer layer,
         std::vector<CompiledAction>& actions,
         std::vector<CompiledRuleEntry>& entries) {
        std::uint16_t slot = 0;

        for (const auto& rule : rules) {
          // Create action with dense counter_slot
          CompiledAction action;
          action.rule_id = rule.id;
          action.counter_slot = slot++;
          action.verb = rule.action ? resolve_verb(*rule.action)
                                    : ActionVerb::kDrop;
          // D4 tiering: honor hw_offload_hint only when globally enabled.
          // MVP default: hw_enabled == false → everything stays kSw.
          action.execution_tier =
              (hw_enabled && rule.hw_offload_hint)
                  ? ExecutionTier::kHw
                  : ExecutionTier::kSw;

          const auto action_idx =
              static_cast<std::uint32_t>(actions.size());
          actions.push_back(action);

          // Port-list expansion (U3.2, U3.3) with dedup (U3.25).
          // Dedup preserves declaration order of first occurrence.
          if (!rule.dst_ports.empty()) {
            std::unordered_set<std::int32_t> seen;
            for (const auto port : rule.dst_ports) {
              if (!seen.insert(port).second) continue;  // duplicate
              CompiledRuleEntry entry;
              entry.action_index = action_idx;
              entry.dst_port = port;
              entry.layer = layer;
              entries.push_back(entry);
            }
          } else if (rule.dst_port >= 0) {
            // Single dst_port
            CompiledRuleEntry entry;
            entry.action_index = action_idx;
            entry.dst_port = rule.dst_port;
            entry.layer = layer;
            entries.push_back(entry);
          } else {
            // No port constraint
            CompiledRuleEntry entry;
            entry.action_index = action_idx;
            entry.dst_port = -1;
            entry.layer = layer;
            entries.push_back(entry);
          }
        }
      };

  compile_layer(cfg.pipeline.layer_2, Layer::kL2, result.l2_actions,
                result.l2_entries);
  compile_layer(cfg.pipeline.layer_3, Layer::kL3, result.l3_actions,
                result.l3_entries);
  compile_layer(cfg.pipeline.layer_4, Layer::kL4, result.l4_actions,
                result.l4_entries);

  // D7: reject mirror action in MVP. Scan all layers for kMirror.
  auto check_mirror = [](const std::vector<CompiledAction>& actions)
      -> bool {
    for (const auto& a : actions) {
      if (a.verb == ActionVerb::kMirror) return true;
    }
    return false;
  };

  if (check_mirror(result.l2_actions) ||
      check_mirror(result.l3_actions) ||
      check_mirror(result.l4_actions)) {
    result.error = CompileError{
        CompileErrorCode::kMirrorNotImplemented,
        "mirror action not implemented in this build"};
  }

  // M4 C0 retrofit (D41) — wire compound stages into the top-level
  // pipeline. Before this cycle M2 shipped with compile_l{2,4}_rules
  // orphaned: the unit tests in tests/unit/test_compiler.cpp called
  // them directly, but compile() itself never did. The D41 invariant
  // (review-notes) requires any multi-stage milestone to expose the
  // full pipeline state through its public entry point — this is
  // what the U3.Smoke1 test asserts on.
  result.l2_compound =
      compile_l2_rules(cfg.pipeline.layer_2, result.l2_actions);
  result.l3_compound = compile_l3_rules(cfg.pipeline.layer_3,
                                        result.l3_actions, result.objects);
  auto l4_out = compile_l4_rules(cfg.pipeline.layer_4, result.l4_actions);
  result.l4_compound = std::move(l4_out.rules);
  // L4 compound collisions are surfaced via the L4CompileOutput return
  // path but intentionally NOT wired into result.error here — collision
  // handling is a separate diagnostic stream (see tests/unit/test_compiler
  // U3.24) and the C0 retrofit is limited to exposing the per-layer
  // compound vectors, not changing error semantics.

  return result;
}

}  // namespace pktgate::compiler
