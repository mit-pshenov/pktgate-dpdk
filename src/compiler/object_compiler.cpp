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

namespace {

// D41 C1b — dependent-false sentinel for exhaustive `if constexpr`
// chains over closed variants. Using a plain `static_assert(false, …)`
// in the final `else` branch of a generic lambda would fire at
// template-definition time (i.e. unconditionally, even when every
// `if constexpr` arm matches a real variant member). Making the
// predicate depend on `T` defers the failure to instantiation, so
// it only fires if a future `config::RuleAction` variant arm lands
// without a matching branch in `resolve_action`.
//
// Anti-pattern fixed: the previous `else { out.verb = ActionVerb::
// kDrop; }` fallback silently lowered any unknown variant payload
// to DROP. See review-notes §D41 Amendment 2026-04-18 (C1b).
template <typename T>
inline constexpr bool always_false_v = false;

}  // namespace

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
//
// M7 C2b retrofit (D41): this helper is the single place where the
// config::RuleAction variant is lowered into the compiler's flat
// CompiledAction representation. Beyond the verb enum it fills the
// action-specific payload fields (dscp/pcp for TAG, redirect_port for
// REDIRECT) so the ruleset builder no longer has to hardcode zeros /
// sentinels. See errata §M7 C2b.
//
// Role-name resolution policy (REDIRECT): we resolve `role_name` against
// `cfg.interface_roles` in declaration order, matching the convention
// main.cpp uses to pair ports with roles (RTE_ETH_FOREACH_DEV iterates
// available ports in order and zips them with the interface_roles
// vector, so interface_roles[0] → port_ids[0], interface_roles[1] →
// port_ids[1]). Keeping resolution inside the compiler keeps the
// CompiledAction POD and avoids threading a port-name registry through
// the builder. Unknown role names fall back to 0xFFFF (sentinel drop),
// which the validator is expected to catch at a higher tier — the
// compiler does not enforce symbol resolution here.

struct ActionLowered {
  ActionVerb verb{ActionVerb::kDrop};
  std::uint8_t dscp{0};
  std::uint8_t pcp{0};
  std::uint16_t redirect_port{0xFFFF};
  // M16 C1 (D7 unlock, D41 #7): mirror destination role_idx.
  // Filled for kMirror via the same resolve_role_idx path redirect_port
  // uses — the mirror destination resolves against interface_roles and
  // the numeric port_id is lowered into CompiledAction.mirror_port
  // and, in turn, action::RuleAction.mirror_port by
  // builder::copy_actions. Sentinel 0xFFFF matches the struct default
  // when no mirror role is named (non-kMirror verbs keep it).
  std::uint16_t mirror_port{0xFFFF};
  // M9 C3 (D10, D24, D41): rate-limit payload. Filled for kRateLimit
  // by resolve_action; the builder copies these through to
  // Ruleset::rl_actions[] + RuleAction.rl_index. Default values match
  // the "not a rate-limit verb" case so the compiler never lies about
  // an RL rule by silently shipping zeros.
  std::uint64_t rl_rate_bps{0};
  std::uint64_t rl_burst_bytes{0};
};

static std::uint16_t resolve_role_idx(
    const std::vector<config::InterfaceRole>& roles,
    const std::string& role_name) {
  for (std::size_t i = 0; i < roles.size(); ++i) {
    if (roles[i].name == role_name) {
      return static_cast<std::uint16_t>(i);
    }
  }
  return 0xFFFFu;  // unknown role: keep sentinel (validator territory)
}

static ActionLowered resolve_action(
    const config::RuleAction& action,
    const std::vector<config::InterfaceRole>& roles) {
  ActionLowered out;
  std::visit(
      [&](const auto& a) {
        using T = std::decay_t<decltype(a)>;
        if constexpr (std::is_same_v<T, config::ActionAllow>) {
          out.verb = ActionVerb::kAllow;
        } else if constexpr (std::is_same_v<T, config::ActionDrop>) {
          out.verb = ActionVerb::kDrop;
        } else if constexpr (std::is_same_v<T, config::ActionRateLimit>) {
          out.verb = ActionVerb::kRateLimit;
          // M9 C3 (D41): carry rate / burst through the compiler TU so
          // the builder can populate `Ruleset::rl_actions[slot]`
          // without re-reading the config AST. This is the "left end"
          // of the compiler→builder roundtrip — the "right end" is
          // CompiledAction.rl_slot filled by the rl_alloc callable at
          // the compile_layer call site below.
          out.rl_rate_bps = a.bytes_per_sec;
          out.rl_burst_bytes = a.burst_bytes;
        } else if constexpr (std::is_same_v<T, config::ActionTag>) {
          out.verb = ActionVerb::kTag;
          // ActionTag stores signed fields with -1 = "unset". The
          // parser clamps the positive branch to valid ranges
          // (DSCP 0..63, PCP 0..7), so the cast-down is safe. When
          // unset we keep the POD default of 0 (no-op rewrite).
          if (a.dscp >= 0) {
            out.dscp = static_cast<std::uint8_t>(a.dscp);
          }
          if (a.pcp >= 0) {
            out.pcp = static_cast<std::uint8_t>(a.pcp);
          }
        } else if constexpr (std::is_same_v<T, config::ActionTargetPort>) {
          out.verb = ActionVerb::kRedirect;
          out.redirect_port = resolve_role_idx(roles, a.role_name);
        } else if constexpr (std::is_same_v<T, config::ActionMirror>) {
          out.verb = ActionVerb::kMirror;
          // M16 C1 (D7 unlock): resolve mirror destination through the
          // same interface_roles path redirect_port uses. The validator
          // (src/config/validator.cpp check_action_target_port) has
          // already rejected unresolved role_names before compile runs,
          // so the lookup below always returns a real port_id for any
          // config that reaches here. If a future refactor skips
          // validation, the 0xFFFF sentinel fallback preserves the
          // hot-path invariant that verb == kMirror implies a resolved
          // mirror_port — the dispatch arm (M16 C2) rejects the
          // sentinel defensively.
          out.mirror_port = resolve_role_idx(roles, a.role_name);
        } else {
          static_assert(always_false_v<T>,
                        "D41 C1b guard: unhandled config::RuleAction "
                        "variant arm — add a branch in resolve_action "
                        "(object_compiler.cpp) when config::RuleAction "
                        "gains a new variant member");
        }
      },
      action);
  return out;
}


// -------------------------------------------------------------------------
// compile — full pipeline.

CompileResult compile(const config::Config& cfg,
                      const CompileOptions& opts,
                      const RlSlotAllocator& rl_alloc) {
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
  const auto& roles = cfg.interface_roles;

  auto compile_layer =
      [hw_enabled, &roles, &rl_alloc](
          const std::vector<config::Rule>& rules, Layer layer,
          std::vector<CompiledAction>& actions,
          std::vector<CompiledRuleEntry>& entries) {
        std::uint16_t slot = 0;

        for (const auto& rule : rules) {
          // Create action with dense counter_slot + full payload
          // lowering (M7 C2b retrofit, D41): the verb AND the
          // action-specific fields (dscp/pcp for TAG,
          // redirect_port for REDIRECT) travel through
          // CompiledAction so the ruleset builder no longer
          // hardcodes zeros/sentinels in copy_actions.
          CompiledAction action;
          action.rule_id = rule.id;
          action.counter_slot = slot++;
          if (rule.action) {
            const auto lowered = resolve_action(*rule.action, roles);
            action.verb = lowered.verb;
            action.dscp = lowered.dscp;
            action.pcp = lowered.pcp;
            action.redirect_port = lowered.redirect_port;
            // M16 C1 (D7 unlock, D41 #7): mirror_port travels alongside
            // redirect_port through the compiler -> builder pipeline.
            // Non-kMirror verbs keep the 0xFFFF sentinel from the
            // ActionLowered default so only kMirror CompiledActions
            // carry a meaningful port_id.
            action.mirror_port = lowered.mirror_port;

            // M9 C3 (D10, D24, D41): for kRateLimit verbs, obtain a
            // slot via the caller-provided allocator. The allocator
            // owns the bridge to `rl_arena::RateLimitArena::alloc_slot`
            // — we never touch the arena here (keeps this TU DPDK-
            // free). When the allocator is empty (default in non-RL
            // callsites and tests), rl_slot stays at kInvalidSlot
            // (0xFFFF) and rate/burst stay at 0; such a CompileResult
            // must not be shipped to a worker that could hit this
            // rule — it would dispatch-unreachable. The roundtrip
            // test in C3 wires a real allocator; unit tests for
            // unrelated verbs keep passing unchanged.
            if (action.verb == ActionVerb::kRateLimit) {
              action.rl_rate_bps = lowered.rl_rate_bps;
              action.rl_burst_bytes = lowered.rl_burst_bytes;
              if (rl_alloc) {
                action.rl_slot = rl_alloc(
                    static_cast<std::uint64_t>(rule.id));
              }
              // else: leave rl_slot at the CompiledAction default
              // (0xFFFF == kInvalidSlot). Callers that care (reload
              // deploy path) always wire an allocator.
            }
          } else {
            action.verb = ActionVerb::kDrop;
          }
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

  // D17: propagate fragment_policy from config to CompileResult.
  result.fragment_policy = static_cast<std::uint8_t>(cfg.fragment_policy);

  // M7 C2b retrofit (D41): propagate default_behavior from config to
  // CompileResult. Encoding matches config::DefaultBehavior
  // (kAllow=0, kDrop=1). The builder copies this into
  // Ruleset.default_action — see errata §M7 C2b.
  result.default_action = static_cast<std::uint8_t>(cfg.default_behavior);

  // M16 C3.5 (grabli_role_idx_as_port_id_bug.md): propagate
  // interface_roles through CompileResult. Declaration order is the
  // semantic the compiler exposes via resolve_role_idx — storing the
  // vector here lets `populate_ruleset_eal` translate role_idx values
  // in `RuleAction.{redirect,mirror}_port` to live DPDK port_ids via
  // `rte_eth_dev_get_port_by_name` without re-threading `config::Config`
  // all the way through the builder. The copy is O(roles.size()) at
  // compile time — a handful of entries in every realistic config.
  result.interface_roles = cfg.interface_roles;

  // M16 C1 (D7 unlock, review-notes §D7 amendment 2026-04-20):
  // the previous scan-for-kMirror reject block is removed. Mirror is
  // now a lowered verb carried through compile -> build -> RuleAction
  // via the ActionLowered / CompiledAction / action::RuleAction
  // `mirror_port` chain; the validator still rejects unresolved
  // role_names before we reach here. Hot-path mirror dispatch lands
  // in M16 C2 (apply_action kMirror arm + stage_mirror /
  // mirror_drain helpers). The `CompileErrorCode::kMirrorNotImplemented`
  // enumerator remains in src/compiler/compiler.h for ABI continuity
  // but has no emitter site in this build; future mirror-related
  // compile-time failures (unresolved role that somehow bypassed the
  // validator, etc.) may re-emit it.

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
