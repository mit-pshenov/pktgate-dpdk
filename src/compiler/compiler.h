// src/compiler/compiler.h
//
// M2 C1 — compiler output types and top-level interface.
//
// The compiler takes M1's config AST (model.h types) as input after
// parse + validate and produces compiled structures that the ruleset
// builder (M2 later cycles) materialises into runtime data structures.
//
// Design anchors:
//   * D15 — compound primary + filter_mask pattern
//   * D22 — RuleAction 20 B + alignas(4)
//   * D33 — dense counter_slot assignment §4.3
//   * §4.1 — Ruleset struct layout (L2/L3/L4 compound + action arenas)
//
// C1 scope: object compiler output types, compiled action with
// counter_slot, port expansion scaffolding. L2/L3/L4 compound
// builders land in C3-C5.

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <tuple>
#include <unordered_map>
#include <variant>
#include <vector>

#include "src/config/addr.h"
#include "src/config/model.h"
#include "src/ruleset/types.h"

namespace pktgate::compiler {

// -------------------------------------------------------------------------
// CompiledObjects — expanded named objects ready for rule compilation.
//
// The object compiler resolves named definitions from ObjectPool into
// directly-indexable lookup tables. These are consumed by the rule
// compiler when expanding object references in rules.

struct CompiledSubnets {
  // name → flattened CIDR list. Each named subnet keeps its CIDRs in
  // declaration order (v4 and v6 may be interleaved).
  std::unordered_map<std::string, std::vector<config::SubnetCidr>> by_name;
};

struct CompiledPortGroups {
  // name → port list, preserved in declaration order.
  std::unordered_map<std::string, std::vector<std::uint16_t>> by_name;
};

struct CompiledObjects {
  CompiledSubnets subnets;
  CompiledPortGroups port_groups;
};

// -------------------------------------------------------------------------
// CompiledAction — compiler-assigned action descriptor for a single
// rule entry. This is the *compiler's view* of the action; the final
// runtime RuleAction (design.md §4.1, 20 B) is built by the ruleset
// builder from this plus runtime context (port resolution, rl_arena
// slot). C1 only needs the counter_slot and action verb to test
// dense slot assignment and port expansion.

enum class ActionVerb : std::uint8_t {
  kAllow = 0,
  kDrop = 1,
  kMirror = 2,
  kRateLimit = 3,
  kTag = 4,
  kRedirect = 5,
};

// D4: execution tier — SW (software tables) vs HW (rte_flow offload).
// Default is kSw. The compiler sets kHw when the rule's hw_offload_hint
// is true AND global hw_offload_enabled is true. MVP ships with global
// disable (all rules are SW regardless of hint).
enum class ExecutionTier : std::uint8_t {
  kSw = 0,
  kHw = 1,
};

struct CompiledAction {
  std::int32_t rule_id{-1};
  std::uint16_t counter_slot{0};
  ActionVerb verb{ActionVerb::kDrop};
  ExecutionTier execution_tier{ExecutionTier::kSw};  // D4: default SW

  // M7 C2b retrofit — action payload carried through to RuleAction.
  //
  // Before this cycle the compiler stored only the verb enum and the
  // builder hardcoded dscp/pcp=0 + redirect_port=0xFFFF. Result: TAG
  // actions were no-ops (DSCP=0, PCP=0) and REDIRECT silently dropped
  // every packet (sentinel port → apply_redirect guard). Same D41
  // silent-lowering class as M2 compound builders and M5 C3 fragment
  // policy — fixed by carrying the config::RuleAction variant payload
  // into CompiledAction and copying it in builder::copy_actions.
  //
  // Defaults match the "no TAG / no REDIRECT" case so non-TAG /
  // non-REDIRECT verbs behave unchanged: dscp=0 is a no-op rewrite and
  // redirect_port=0xFFFF matches the action::RuleAction sentinel used
  // by apply_redirect to reject bogus port indices.
  std::uint8_t dscp{0};
  std::uint8_t pcp{0};
  std::uint16_t redirect_port{0xFFFF};

  // M16 C1 (D7 unlock, D41 guard extension): mirror destination port.
  //
  // Before M16 C1 the compiler rejected any config carrying `action:
  // mirror` (object_compiler.cpp::compile scan-for-kMirror block), so
  // there was no need to carry a `mirror_port` field — the compiler
  // output never held a kMirror verb in practice. C1 removes that
  // reject (see review-notes §D7 amendment 2026-04-20 + design.md
  // §14 phase-plan row); the compiler now emits CompiledAction entries
  // with `verb == kMirror` and this field holds the resolved port_id
  // of the mirror destination (same port_resolver path redirect_port
  // uses — src/compiler/object_compiler.cpp::resolve_role_idx).
  //
  // Default 0xFFFF mirrors redirect_port's sentinel convention: an
  // action whose verb is NOT kMirror keeps the sentinel, and hot-path
  // dispatch (M16 C2) reads mirror_port only when verb == kMirror.
  // The validator (src/config/validator.cpp:310-376) rejects mirror
  // rules whose role_name does not resolve BEFORE compile runs, so
  // a live CompiledAction with verb == kMirror always has a resolved
  // mirror_port by construction.
  //
  // D41 lockstep: observable_fields(CompiledAction) and
  // observable_fields(RuleAction) both include `mirror_port` as of
  // M16 C1, and src/ruleset/builder.cpp copy_actions lowers it in
  // both build_ruleset overloads. The static_assert pair in
  // builder.cpp guards the projection drift; the runtime roundtrip
  // tests (test_d41_guard.cpp + test_d41_eal_smoke.cpp + new
  // test_object_compiler_mirror.cpp) guard the wiring drift.
  std::uint16_t mirror_port{0xFFFF};

  // M9 C3 (D10, D24, D41): rate-limit fields. When verb == kRateLimit,
  // rl_slot is the slot index obtained from the RateLimitArena via the
  // slot allocator passed to compile() and rl_rate_bps / rl_burst_bytes
  // are copied from config::ActionRateLimit. The builder copies these
  // three fields through TWO independent pipelines:
  //
  //   1. rl_slot → action::RuleAction.rl_index (hot-path lookup handle)
  //   2. {rule_id, rl_rate_bps, rl_burst_bytes} →
  //      Ruleset::rl_actions[rl_slot] (per-ruleset rate/burst snapshot)
  //
  // Default sentinel 0xFFFF matches rl_arena::kInvalidSlot; non-RL verbs
  // ship the sentinel unchanged so the builder can skip the rl_actions
  // population path for them. Same D41 silent-pipeline-gap class as
  // M7 C2b (dscp/pcp/redirect_port) and M8 C5 (RCU reader) — the whole
  // point of carrying all three fields is that compile → build cannot
  // silently drop any of them.
  std::uint16_t rl_slot{0xFFFF};
  std::uint64_t rl_rate_bps{0};
  std::uint64_t rl_burst_bytes{0};
};

// -------------------------------------------------------------------------
// D41 compile-time guard — observable-field projection (post-Phase 1).
//
// Parallel projection to action::observable_fields(). Each element MUST
// match the corresponding RuleAction projection in both order AND type
// (per-element is_same_v). Casts here normalise namespace / enum /
// signedness drift:
//
//   * CompiledAction::rule_id is int32_t (parser-validated positive);
//     RuleAction::rule_id is uint32_t. Cast up to uint32_t.
//   * ActionVerb / ExecutionTier are enum class with uint8_t underlying;
//     RuleAction::{verb,execution_tier} are raw uint8_t. Cast to the
//     underlying type via static_cast<uint8_t>.
//   * rl_slot (compiler side) and rl_index (action side) are the same
//     16-bit slot index under two names — the namespace drift is noted
//     in scratch/d41-discovery-report.md §1.1 and is not a defect.
//
// Fields excluded: dscp/pcp carry through directly; next_layer and
// flags are dead carriers on the action side (zero readers in
// src/dataplane/). `mirror_port` WAS excluded prior to M16 C1 because
// mirror was compile-rejected (D7); as of M16 C1 the D7 reject is
// removed and `mirror_port` is a live lowered field on both sides —
// see the matching comment in src/action/action.h.
constexpr auto observable_fields(const CompiledAction& ca) {
  return std::tuple{
      static_cast<std::uint32_t>(ca.rule_id),
      ca.counter_slot,
      static_cast<std::uint8_t>(ca.verb),
      static_cast<std::uint8_t>(ca.execution_tier),
      ca.redirect_port,
      ca.dscp,
      ca.pcp,
      ca.rl_slot,
      ca.mirror_port,
  };
}

// -------------------------------------------------------------------------
// RlSlotAllocator — M9 C3 (D10, D24): compile-time slot allocation
// interface.
//
// The compiler calls this once per RateLimit rule with the rule_id as
// u64 and stores the returned slot in `CompiledAction.rl_slot`. The
// callable is typically a thin lambda over
// `rl_arena::rl_arena_global().alloc_slot(id)` — that's the only place
// the arena is referenced. Keeping the dependency as a function-pointer-
// style callable keeps the compiler TU DPDK-free and arena-free
// (`grabli_m4c0_dpdk_free_core_library.md`).
//
// A default-constructed (empty) RlSlotAllocator is the "no allocator"
// sentinel used by all non-RL callsites (tests that never exercise RL,
// fuzzer entry point). The compiler treats an empty callable as
// `kInvalidSlot` for every RL rule — callers that build a Ruleset from
// such a CompileResult never dispatch RL, so the invalid slot never
// reaches the hot path.
using RlSlotAllocator =
    std::function<std::uint16_t(std::uint64_t rule_id)>;

// -------------------------------------------------------------------------
// CompileOptions — optional knobs for the compile() function.
//
// hw_offload_enabled: when false (MVP default), all rules are demoted
// to execution_tier == SW regardless of per-rule hw_offload_hint.
// When true, rules with hw_offload_hint produce execution_tier == HW.
// Covers D4, §14 MVP.

struct CompileOptions {
  bool hw_offload_enabled = false;  // MVP default: all SW
};

// -------------------------------------------------------------------------
// Layer enum — identifies which pipeline layer a compiled rule belongs to.

enum class Layer : std::uint8_t {
  kL2 = 0,
  kL3 = 1,
  kL4 = 2,
};

// -------------------------------------------------------------------------
// CompiledRuleEntry — a single expanded rule after port-list / port-group
// expansion. Multiple entries may share the same action_index (when a
// single logical rule expands into N entries via dst_ports/port_group).
//
// C1 scope: captures the expansion result for U3.2/U3.3/U3.4. Full
// L2/L4 compound construction (primary key, filter_mask) lands in C3-C5.

struct CompiledRuleEntry {
  std::uint32_t action_index;   // index into the layer's action array
  std::int32_t dst_port{-1};    // expanded port (-1 = not port-keyed)
  Layer layer{Layer::kL4};
};

// -------------------------------------------------------------------------
// CompileErrorCode — compile-time error codes (D7 et al.).

enum class CompileErrorCode : std::uint8_t {
  kMirrorNotImplemented = 1,  // D7: mirror action not supported in this build
};

// -------------------------------------------------------------------------
// CompileError — optional error carried by CompileResult.

struct CompileError {
  CompileErrorCode code;
  std::string message;
};

// -------------------------------------------------------------------------
// CompileResult — full compiler output.
//
// M4 C0 retrofit: CompileResult now holds L{2,3,4}CompiledRule vectors
// so the public compile() entry point exposes the full pipeline state
// end-to-end (D41 smoke invariant). The L*CompiledRule definitions
// live in rule_compiler.h, which is included below after the
// CompiledAction / CompiledObjects definitions above to break a
// potential cycle.

}  // namespace pktgate::compiler

#include "src/compiler/rule_compiler.h"  // L{2,3,4}CompiledRule

namespace pktgate::compiler {

struct CompileResult {
  CompiledObjects objects;

  // Per-layer action arrays. counter_slot is dense [0..N) within each layer.
  std::vector<CompiledAction> l2_actions;
  std::vector<CompiledAction> l3_actions;
  std::vector<CompiledAction> l4_actions;

  // Expanded rule entries per layer.
  std::vector<CompiledRuleEntry> l2_entries;
  std::vector<CompiledRuleEntry> l3_entries;
  std::vector<CompiledRuleEntry> l4_entries;

  // M4 C0 retrofit (D41): compound rules per layer, produced by
  // compile_l2_rules / compile_l3_rules / compile_l4_rules and
  // populated by the top-level compile() entry point. The ruleset
  // builder consumes these to populate rte_hash / rte_fib / rte_fib6.
  //
  // The per-layer `l{2,3,4}_entries` arrays above remain the port-
  // expansion helpers (U3.2/U3.3). The `l{2,3,4}_compound` arrays
  // are the compound-matching artefacts (D15).
  std::vector<L2CompiledRule> l2_compound;
  std::vector<L3CompiledRule> l3_compound;
  std::vector<L4CompiledRule> l4_compound;

  // D17: fragment_policy propagated from Config. The builder copies
  // this into Ruleset.fragment_policy. Numeric encoding matches
  // classify_l3.h FragmentPolicy (0=L3Only, 1=Drop, 2=Allow).
  std::uint8_t fragment_policy = 0;

  // M7 C2b retrofit (D41): default_behavior propagated from Config.
  // The builder copies this into Ruleset.default_action. Numeric
  // encoding matches config::DefaultBehavior (0=kAllow, 1=kDrop) and
  // the ruleset.h comment ("0 = ALLOW or DROP"). Pattern mirrors
  // fragment_policy above — see errata §M7 C2b.
  std::uint8_t default_action = 0;

  // M16 C3.5: interface_roles propagated from Config so the EAL-aware
  // population step (`populate_ruleset_eal`) can translate the compiler-
  // side `role_idx` stored in `CompiledAction.{redirect,mirror}_port`
  // to the resolved DPDK port_id before the hot path consumes it.
  //
  // Declaration order matters — `resolve_role_idx` uses vector index as
  // the `role_idx` value. At populate time we walk this vector and look
  // each selector up via `rte_eth_dev_get_port_by_name`; successful
  // lookups populate an internal `role_idx → port_id` map and drive the
  // translation. Unresolvable entries (e.g. PciSelector pointing at a
  // bus address not bound to vfio-pci in this EAL context) leave the
  // original role_idx untouched — backward-compat for M4 C0-era EAL
  // tests that use placeholder PciSelectors.
  //
  // Memory `grabli_role_idx_as_port_id_bug.md`, regression class pinned
  // by U16.12 / U16.13 (unit) and F16.4_nonlex (functional).
  std::vector<config::InterfaceRole> interface_roles;

  // D7: compile error (e.g., mirror not implemented in MVP).
  // When set, the result is invalid — the caller must not use the
  // compiled structures.
  std::optional<CompileError> error;
};

// -------------------------------------------------------------------------
// Enum dispatch helpers — exhaustive -Wswitch-enum switches (D25).
//
// verb_label:  ActionVerb  → human-readable string.
// layer_label: Layer       → human-readable string.
//
// Both use exhaustive switch statements so that adding a new enum value
// without handling it triggers a compile error under -Wswitch-enum.
// U3.22 / U3.23 verify runtime completeness via enum-scan tests.

const char* verb_label(ActionVerb verb);
const char* layer_label(Layer layer);

}  // namespace pktgate::compiler
