// src/eal/port_init.h
//
// M3 C1 — basic DPDK port configuration.
//
// Configures RX/TX queues, sets up mempools, starts ports. D28/D39
// validators land in C2/C3 — this cycle handles happy-path-only port
// setup with 1 RX + 1 TX queue per worker.
//
// Design anchors:
//   * §6.1 — init sequence
//   * D23  — NUMA-aware mempool allocation
//   * D28  — TX-queue symmetry (C2)
//   * D39  — scatter-off invariant (C3)

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <rte_ethdev.h>
#include <rte_mempool.h>

namespace pktgate::eal {

// Result of port initialization.
struct PortInitResult {
  bool ok = false;
  std::string error;
};

// Configure and start a single port with `n_rxq` receive queues and
// `n_txq` transmit queues. Each RX queue draws mbufs from `mp`.
// Returns ok=true on success or ok=false with an error message.
PortInitResult port_init(std::uint16_t port_id,
                         std::uint16_t n_rxq,
                         std::uint16_t n_txq,
                         struct rte_mempool* mp);

// Resolve a port role selector to a DPDK port ID.
// For vdev selectors, the port must already be registered via EAL argv.
// For PCI selectors, uses rte_eth_dev_get_port_by_name().
// For name selectors, uses rte_eth_dev_get_port_by_name().
struct PortResolveResult {
  bool ok = false;
  std::uint16_t port_id = 0;
  std::string error;
};

PortResolveResult resolve_port_by_name(const std::string& name);

// Stop and close a port. Called during shutdown (§6.4).
void port_stop(std::uint16_t port_id);

// -------------------------------------------------------------------------
// D28 — TX-queue symmetry pre-check.
//
// Every port must have max_tx_queues >= n_workers. This is checked at
// startup time before port_init() configures queues. If any port
// violates the invariant, the binary exits with a clear error.

struct TxSymmetryCheckResult {
  bool ok = false;
  std::string error;            // human-readable: port, max_tx_queues, n_workers
  std::uint16_t port_id = 0;   // offending port (if !ok)
  std::uint16_t max_tx_queues = 0;
};

// Check that port `port_id` has at least `n_workers` TX queues.
// Returns ok=true if the port can support n_workers, or ok=false
// with a descriptive error.
TxSymmetryCheckResult check_tx_symmetry(std::uint16_t port_id,
                                        unsigned n_workers);

// -------------------------------------------------------------------------
// D39 — headers-in-first-seg invariant.
//
// Ensures that:
// 1. Scatter RX offload is NOT enabled on any port
// 2. Mempool element size is sufficient to hold the largest packet
//    the port can receive in a single segment
//
// This guarantees that all packet headers are in the first (and only)
// mbuf segment, so classify_l2/l3/l4 never needs multi-seg handling.

struct ScatterCheckResult {
  bool ok = false;
  std::string error;
};

// Check that port `port_id` does not require scatter RX and that
// the mempool `mp` can hold the port's max RX packet in one segment.
ScatterCheckResult check_no_scatter(std::uint16_t port_id,
                                    struct rte_mempool* mp);

}  // namespace pktgate::eal
