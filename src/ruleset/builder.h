// src/ruleset/builder.h
//
// M2 C9+C10 — RulesetBuilder: CompileResult + Sizing → Ruleset.
//
// The builder takes the compiler's output and the sizing config, and
// produces a fully-allocated Ruleset with action arrays, counter rows,
// and generation metadata. C10 adds an allocator abstraction (D23)
// so that all allocations are funnelled through a single point that
// carries the NUMA socket_id. Production (M3) wires rte_malloc;
// tests use a spy that records each call.
//
// Design anchors:
//   * D6  — arena sizing from runtime config
//   * D3  — per-lcore counter row layout (§4.3)
//   * D12 — generation counter monotonic
//   * D23 — NUMA awareness: every allocation on the declared socket
//   * D28 — TX-queue symmetry pre-check

#pragma once

#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

#include "src/compiler/compiler.h"
#include "src/config/model.h"
#include "src/ruleset/ruleset.h"

namespace pktgate::ruleset {

// -------------------------------------------------------------------------
// RulesetAllocator — abstraction for NUMA-aware allocation (D23).
//
// The builder calls allocate() for every arena (action arrays, counter
// rows). The default implementation uses standard C++ aligned_alloc.
// Production (M3) replaces with rte_malloc_socket. Tests inject a spy.
//
// The destructor callback (deallocate) is stored in the Ruleset so
// that ~Ruleset can free memory through the same allocator that
// created it.

struct RulesetAllocator {
  // Allocate `size` bytes with `alignment` on NUMA `socket_id`.
  // Returns nullptr on failure.
  using AllocFn = void* (*)(std::size_t size, std::size_t alignment,
                            int socket_id, void* ctx);
  // Free a pointer previously returned by AllocFn.
  using FreeFn = void (*)(void* ptr, void* ctx);

  AllocFn allocate = nullptr;
  FreeFn deallocate = nullptr;
  void* ctx = nullptr;  // opaque context for the callbacks
};

// Default allocator — uses ::operator new with alignment. Ignores
// socket_id (no EAL). This is the M2 fallback; M3 replaces with
// rte_malloc_socket.
RulesetAllocator default_allocator();

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

// Overload with explicit allocator and NUMA socket (D23).
Ruleset build_ruleset(const compiler::CompileResult& cr,
                      const config::Sizing& sizing,
                      unsigned num_lcores,
                      const RulesetAllocator& alloc,
                      int socket_id);

// -------------------------------------------------------------------------
// D28 — TX-queue symmetry pre-check.
//
// Every port from interface_roles must have max_tx_queues >= n_workers.
// This is a compile/startup-time check, not a runtime check.

struct EthDevInfo {
  std::uint16_t max_tx_queues = 0;
};

struct TxSymmetryError {
  std::string role_name;
  std::uint16_t max_tx_queues;
  unsigned n_workers;
};

// Check that every role's port has at least n_workers TX queues.
// Returns empty vector on success, or one error per failing role.
std::vector<TxSymmetryError> check_port_tx_symmetry(
    const std::vector<config::InterfaceRole>& roles,
    unsigned n_workers,
    const std::unordered_map<std::string, EthDevInfo>& dev_info);

}  // namespace pktgate::ruleset
