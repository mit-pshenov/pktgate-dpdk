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
// counter_slot dense assignment (U3.4), and rule tiering (D4).
//
// The overload without CompileOptions uses default options (MVP:
// hw_offload_enabled = false, all rules demoted to SW).
CompileResult compile(const config::Config& cfg,
                      const CompileOptions& opts = CompileOptions{});

}  // namespace pktgate::compiler
