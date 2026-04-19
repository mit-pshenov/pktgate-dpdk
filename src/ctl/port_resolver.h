// src/ctl/port_resolver.h
//
// M14 C1 — D43 port resolver. DPDK-free core library that maps
// `Config.interface_roles` (sum-type {pci|vdev|name}) to runtime
// `uint16_t` DPDK port ids, while enforcing the D28 TX-queue
// symmetry invariant for any registered port (generalised from
// pci-only to all PMD families per D43).
//
// Why DPDK-free here: the resolver is init-time control-plane code
// whose only contact with DPDK is "given a name, what port id does
// it map to?". We thread that question through two injected
// `std::function` callbacks so unit tests can drive the full
// resolution + D28-queue-symmetry path without `rte_eal_init`. The
// production wiring lives in main.cpp (C2) — it passes lambdas that
// call `rte_eth_dev_get_port_by_name` and `rte_eth_dev_info_get`.
// Mirrors the layering pattern from
// `grabli_m4c0_dpdk_free_core_library.md` (and pktgate_rl ↔ rl_eal
// split).
//
// Selector semantics (D43 schema, parser landed M1 C7):
//   * PciSelector{bdf}      — DPDK's port name for a pci-bound NIC
//                             matches the BDF (`rte_eth_dev_get_port_by_name`
//                             on `"0000:04:00.0"` returns the port id).
//   * VdevSelector{spec}    — the vdev *name* prefix preceding the
//                             first comma. `"net_tap0,iface=...,persist"`
//                             registers as port name `"net_tap0"`.
//                             We strip the comma tail before lookup.
//   * NameSelector{name}    — verbatim DPDK port name lookup. Used
//                             when the operator already knows the
//                             port name (e.g. another vdev type whose
//                             registration name does not match the BDF
//                             pattern).
//
// Errors:
//   * kUnresolvedRoleSelector  — caller asked for a role name that
//                                does not appear in
//                                `Config.interface_roles`. Matches
//                                the "static interface ref"
//                                semantics of validator's
//                                `kUnresolvedInterfaceRef` but applies
//                                at the resolver call site rather than
//                                at validate time. Tests query the
//                                resolved map for an unknown role.
//   * kPortNotRegistered       — selector decoded fine, but the
//                                injected name lookup returned
//                                std::nullopt (DPDK has no port for
//                                this name — vdev not on cmdline,
//                                pci not bound to vfio-pci, etc).
//   * kInsufficientTxQueues    — D28 generalised: the resolved port's
//                                `nb_tx_queues` capability < n_workers.
//                                Surfaces for any PMD family, not just
//                                pci.
//
// D-refs: D43 (this lib), D28 (TX queue symmetry generalised), D5
// (interface_roles sum type), D1 (zero atomics — none here, this is
// init-time control plane), D41 (compile-time variant exhaustiveness
// via `always_false_v` static_assert in resolver.cpp).
//
// Layering invariants (CTEST-SCAN):
//   * No `#include <rte_*>` in this header.
//   * No `#include <rte_*>` in port_resolver.cpp either; the lib is
//     DPDK-free end-to-end. The thin DPDK adapter that wires the two
//     callbacks lives in main.cpp (C2).

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>

#include "src/config/model.h"

namespace pktgate::ctl {

// Injected port-name lookup. Production passes a lambda over
// `rte_eth_dev_get_port_by_name`; unit tests pass a `std::map`
// closure. std::nullopt means "DPDK has no port registered under
// this name". The lookup must accept the *port name*, not the raw
// vdev spec — the resolver strips comma-tail args before invoking.
using PortLookupFn =
    std::function<std::optional<std::uint16_t>(std::string_view)>;

// Injected port-info probe — returns the port's `nb_tx_queues`
// capability (max_tx_queues from `rte_eth_dev_info_get`). nullopt
// means "info_get failed for this port id". Surfaced separately
// from the lookup callback so tests can assert each failure mode
// in isolation.
using PortQueueProbeFn =
    std::function<std::optional<std::uint16_t>(std::uint16_t port_id)>;

enum class PortResolveErrorKind : std::uint8_t {
  kUnresolvedRoleSelector,  // role name not declared in interface_roles
  kPortNotRegistered,       // injected lookup returned nullopt
  kInsufficientTxQueues,    // D28 generalised — nb_tx_queues < n_workers
};

struct PortResolveError {
  PortResolveErrorKind kind{};
  // The role name the caller (or the resolver itself) was working
  // on when the error fired. Empty for kUnresolvedRoleSelector when
  // the caller did not yet know which role to query — by convention
  // we always populate it.
  std::string role_name;
  // Free-form diagnostic; names BDF / vdev spec / port id and the
  // numeric mismatch where applicable. Operator-readable.
  std::string message;
};

// Successful resolution payload — role name → DPDK port id. Order
// is unspecified (std::unordered_map); callers use it as a lookup,
// not an iteration source.
struct PortResolveOk {
  std::unordered_map<std::string, std::uint16_t> by_role;
};

using PortResolveResult = std::variant<PortResolveOk, PortResolveError>;

// Resolve every entry in `cfg.interface_roles`. The function:
//
//   1. Decodes each `RoleSelector` to a port name (via std::visit
//      with `always_false_v` exhaustiveness — D41 C1b pattern).
//   2. Calls `lookup(port_name)`. nullopt → kPortNotRegistered.
//   3. Calls `probe(port_id)`. nullopt → kPortNotRegistered (info
//      get is part of the "is this port real?" check). nb_tx_queues
//      < `n_workers` → kInsufficientTxQueues.
//
// Short-circuits on first failure. The success branch carries every
// role's resolved port id.
PortResolveResult resolve_ports(const config::Config& cfg,
                                unsigned n_workers,
                                const PortLookupFn& lookup,
                                const PortQueueProbeFn& probe);

// Look up a single role in the resolved map. Surfaces the
// kUnresolvedRoleSelector diagnostic when the role name is not
// declared. Used by main.cpp to translate config role names like
// `"egress_port"` into the live port id at boot.
//
// Returns std::variant<port_id, error> rather than `std::optional`
// so the error message can name the missing role for diagnostic
// parity with the rest of the API.
std::variant<std::uint16_t, PortResolveError> lookup_role(
    const PortResolveOk& resolved, std::string_view role_name);

// Decode a `RoleSelector` into the DPDK port name we should hand
// to the lookup callback. Exposed for tests; production callers
// reach through `resolve_ports`.
//
// PciSelector → bdf string verbatim.
// VdevSelector → spec string up to the first ',' (exclusive).
// NameSelector → name string verbatim.
std::string port_name_from_selector(const config::RoleSelector& sel);

}  // namespace pktgate::ctl
