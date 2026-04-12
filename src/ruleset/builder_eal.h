// src/ruleset/builder_eal.h
//
// M4 C0 — EAL-aware Ruleset population (D41 pipeline wiring).
//
// Stage that runs AFTER build_ruleset() to open the DPDK compound
// tables (rte_hash for L2/L4 primary, rte_fib/rte_fib6 for L3
// prefixes) and populate them from the CompileResult's l{2,3,4}_compound
// vectors. Lives in libpktgate_dp because it requires DPDK headers and
// EAL init; libpktgate_core (which holds ruleset.cpp / builder.cpp)
// stays DPDK-free.
//
// Design anchors:
//   * D15 — compound primary + filter_mask pattern
//   * D23 — NUMA-aware allocation (socket_id passed to rte_*_create)
//   * D41 — end-to-end pipeline smoke invariant
//   * §4.1 — L2/L3/L4 compound table layout

#pragma once

#include <cstdint>
#include <string>

#include "src/compiler/compiler.h"
#include "src/ruleset/ruleset.h"

namespace pktgate::ruleset {

// Result of populate_ruleset_eal. `ok == true` on success; otherwise
// `error` carries a human-readable description of what failed
// (rte_hash_create EEXIST, rte_fib_add ENOSPC, etc.).
struct EalPopulateResult {
  bool ok = false;
  std::string error;
};

// Parameters that tune the DPDK table sizes. M2's Sizing carries
// rules_per_layer_max which we reuse for table entry counts. Caller
// should pass a unique `name_prefix` per test / boot so the global
// rte_hash namespace doesn't collide across repeated builds.
struct EalPopulateParams {
  std::string name_prefix;   // unique prefix for rte_hash / rte_fib names
  int socket_id = 0;         // NUMA socket for rte_*_create
  std::uint32_t max_entries = 1024;  // per compound table capacity
};

// Open rte_hash / rte_fib / rte_fib6 handles and populate them from
// the CompileResult's per-layer compound vectors.
//
// On success, `rs.l2_compound_hash`, `rs.l3_v4_fib`, `rs.l3_v6_fib`,
// `rs.l4_compound_hash`, the `l{2,3,4}_compound_entries` arenas, and
// `rs.eal_owned = true` are all set. The Ruleset takes ownership:
// ~Ruleset will free the handles via `rs.eal_deleter` and the arenas
// via delete[].
//
// On failure, any partially-opened handle is freed before returning
// so the caller does not need to clean up.
EalPopulateResult populate_ruleset_eal(Ruleset& rs,
                                       const compiler::CompileResult& cr,
                                       const EalPopulateParams& params);

}  // namespace pktgate::ruleset
