// src/compiler/object_compiler.h
//
// M2 C1 — object compiler: ObjectPool → CompiledObjects.
//
// Expands named object definitions (subnets, port_groups) into
// directly-indexable lookup tables. Also provides rule expansion
// helpers (port-list/port-group expansion, counter_slot assignment)
// that the rule compiler (C3-C5) will compose into full L2/L3/L4
// compound structures.
//
// No DPDK deps. Pure C++ stdlib.

#pragma once

#include "src/compiler/compiler.h"
#include "src/config/model.h"

namespace pktgate::compiler {

// Compile the objects pool into expanded lookup tables.
CompiledObjects compile_objects(const config::ObjectPool& pool);

// Compile a full pipeline: objects + rules → CompileResult.
// Handles port-list expansion (U3.3), port-group expansion (U3.2),
// counter_slot dense assignment (U3.4), rule tiering (D4), and
// (M9 C3) rate-limit slot allocation.
//
// The overload without CompileOptions uses default options (MVP:
// hw_offload_enabled = false, all rules demoted to SW).
//
// M9 C3 (D10, D24, D41): the optional `rl_alloc` callable is invoked
// ONCE per L2/L3/L4 rule whose action is kRateLimit, with the rule's
// stable operator-assigned rule_id (cast to u64). The returned slot
// (0..4095 in prod, 0xFFFF == kInvalidSlot on exhaustion) is written
// into `CompiledAction.rl_slot` so the ruleset builder can wire
// `RuleAction.rl_index` AND populate `Ruleset::rl_actions[slot]`
// symmetrically. When `rl_alloc` is not callable (default-constructed
// std::function), RL rules get `rl_slot = kInvalidSlot`; this keeps
// the existing non-RL callsites unchanged and is the right sentinel for
// runtime to dispatch-unreachable. The allocator hides the arena from
// the compiler TU (DPDK-free by `grabli_m4c0_dpdk_free_core_library.md`).
CompileResult compile(const config::Config& cfg,
                      const CompileOptions& opts = CompileOptions{},
                      const RlSlotAllocator& rl_alloc = RlSlotAllocator{});

}  // namespace pktgate::compiler
