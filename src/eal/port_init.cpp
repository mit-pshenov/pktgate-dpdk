// src/eal/port_init.cpp
//
// M3 C1 — basic DPDK port configuration.

#include "src/eal/port_init.h"

#include <cstdio>
#include <cstring>

#include <rte_ethdev.h>

namespace pktgate::eal {

PortInitResult port_init(std::uint16_t port_id,
                         std::uint16_t n_rxq,
                         std::uint16_t n_txq,
                         struct rte_mempool* mp) {
  struct rte_eth_dev_info dev_info;
  int ret = rte_eth_dev_info_get(port_id, &dev_info);
  if (ret != 0) {
    return {false, "rte_eth_dev_info_get failed: " + std::to_string(ret)};
  }

  struct rte_eth_conf port_conf{};
  // D39: disable scatter explicitly so packets arrive in single segment.
  port_conf.rxmode.offloads &= ~RTE_ETH_RX_OFFLOAD_SCATTER;

  ret = rte_eth_dev_configure(port_id, n_rxq, n_txq, &port_conf);
  if (ret != 0) {
    return {false, "rte_eth_dev_configure failed: " + std::to_string(ret)};
  }

  int socket_id = rte_eth_dev_socket_id(port_id);
  unsigned u_socket = (socket_id < 0) ? 0u : static_cast<unsigned>(socket_id);

  // Setup RX queues.
  for (std::uint16_t q = 0; q < n_rxq; ++q) {
    ret = rte_eth_rx_queue_setup(port_id, q, 1024, u_socket, nullptr, mp);
    if (ret != 0) {
      return {false, "rte_eth_rx_queue_setup(q=" + std::to_string(q) +
                     ") failed: " + std::to_string(ret)};
    }
  }

  // Setup TX queues.
  for (std::uint16_t q = 0; q < n_txq; ++q) {
    ret = rte_eth_tx_queue_setup(port_id, q, 1024, u_socket, nullptr);
    if (ret != 0) {
      return {false, "rte_eth_tx_queue_setup(q=" + std::to_string(q) +
                     ") failed: " + std::to_string(ret)};
    }
  }

  // Start port.
  ret = rte_eth_dev_start(port_id);
  if (ret != 0) {
    return {false, "rte_eth_dev_start failed: " + std::to_string(ret)};
  }

  return {true, {}};
}

PortResolveResult resolve_port_by_name(const std::string& name) {
  std::uint16_t port_id = 0;
  int ret = rte_eth_dev_get_port_by_name(name.c_str(), &port_id);
  if (ret != 0) {
    return {false, 0, "port not found: " + name};
  }
  return {true, port_id, {}};
}

void port_stop(std::uint16_t port_id) {
  rte_eth_dev_stop(port_id);
  rte_eth_dev_close(port_id);
}

}  // namespace pktgate::eal
