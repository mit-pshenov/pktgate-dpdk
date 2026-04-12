// src/ruleset/builder.h
//
// M2 C9 — RulesetBuilder: CompileResult + Sizing → Ruleset.
//
// The builder takes the compiler's output and the sizing config, and
// produces a fully-allocated Ruleset with action arrays, counter rows,
// and generation metadata. At M2, standard allocators are used (no
// rte_malloc). DPDK-aware allocation is M3.
//
// Design anchors:
//   * D6  — arena sizing from runtime config
//   * D3  — per-lcore counter row layout (§4.3)
//   * D12 — generation counter monotonic
//   * D23 — NUMA awareness (M3)

#pragma once

#include "src/compiler/compiler.h"
#include "src/config/model.h"
#include "src/ruleset/ruleset.h"

namespace pktgate::ruleset {

// Build a Ruleset from compiler output + sizing config.
//
// Each call increments a process-wide generation counter. The returned
// Ruleset owns all allocated memory (freed in destructor).
//
// Parameters:
//   cr         — CompileResult from compile()
//   sizing     — Sizing config (D6)
//   num_lcores — number of lcores to allocate counter rows for
Ruleset build_ruleset(const compiler::CompileResult& cr,
                      const config::Sizing& sizing,
                      unsigned num_lcores);

}  // namespace pktgate::ruleset
