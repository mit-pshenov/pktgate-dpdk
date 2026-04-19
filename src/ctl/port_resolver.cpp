// src/ctl/port_resolver.cpp
//
// M14 C1 — D43 port resolver implementation. DPDK-free; the two
// DPDK contact points (port-name lookup + nb_tx_queues probe) are
// injected as `std::function` callbacks. See header for the
// rationale.

#include "src/ctl/port_resolver.h"

#include <string>
#include <type_traits>
#include <utility>
#include <variant>

namespace pktgate::ctl {

namespace {

// D41 C1b precedent — `static_assert(always_false_v<T>)` inside an
// `if constexpr` chain forces compile-time exhaustiveness on the
// std::visit lambda. If a future cycle adds a fourth selector arm
// to `config::RoleSelector` and forgets to extend
// `port_name_from_selector`, the build fails at instantiation
// rather than silently routing the new selector to an empty string.
template <typename T>
inline constexpr bool always_false_v = false;

// Build the concrete kInsufficientTxQueues diagnostic. The role
// name, port id, observed nb_tx_queues, and required n_workers
// must all appear so the operator sees the full picture in one
// log line.
std::string build_queue_msg(const std::string& role_name,
                            std::uint16_t port_id,
                            std::uint16_t observed,
                            unsigned required) {
  std::string out = "D28: role '";
  out += role_name;
  out += "' port_id=";
  out += std::to_string(port_id);
  out += " nb_tx_queues=";
  out += std::to_string(observed);
  out += " < n_workers=";
  out += std::to_string(required);
  return out;
}

}  // namespace

std::string port_name_from_selector(const config::RoleSelector& sel) {
  return std::visit(
      [](const auto& v) -> std::string {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, config::PciSelector>) {
          // DPDK's port name for a pci-bound NIC is the BDF string
          // verbatim (rte_eth_dev_get_port_by_name accepts it).
          return v.bdf;
        } else if constexpr (std::is_same_v<T, config::VdevSelector>) {
          // The vdev name is the substring before the first ',' —
          // arguments after the comma (`iface=`, `persist`, etc.)
          // are PMD options, not part of the registration name.
          const auto comma = v.spec.find(',');
          if (comma == std::string::npos) return v.spec;
          return v.spec.substr(0, comma);
        } else if constexpr (std::is_same_v<T, config::NameSelector>) {
          // Name selector value is already the EAL port name.
          return v.name;
        } else {
          static_assert(always_false_v<T>,
                        "port_name_from_selector: unhandled "
                        "RoleSelector variant arm — extend the "
                        "if-constexpr chain when a new selector "
                        "type lands in src/config/model.h");
        }
      },
      sel);
}

PortResolveResult resolve_ports(const config::Config& cfg,
                                unsigned n_workers,
                                const PortLookupFn& lookup,
                                const PortQueueProbeFn& probe) {
  PortResolveOk ok;
  ok.by_role.reserve(cfg.interface_roles.size());

  for (const auto& role : cfg.interface_roles) {
    const std::string port_name = port_name_from_selector(role.selector);

    auto port_id_opt = lookup(port_name);
    if (!port_id_opt.has_value()) {
      PortResolveError err{};
      err.kind = PortResolveErrorKind::kPortNotRegistered;
      err.role_name = role.name;
      err.message = "role '";
      err.message += role.name;
      err.message += "' selector resolves to port name '";
      err.message += port_name;
      err.message += "' but no DPDK port is registered under that name";
      return err;
    }

    const std::uint16_t port_id = *port_id_opt;

    auto caps_opt = probe(port_id);
    if (!caps_opt.has_value()) {
      // info_get failed — folded into kPortNotRegistered: the port
      // id existed in the lookup table but the runtime can't fetch
      // its capabilities, which is functionally the same "port not
      // usable" diagnostic from the operator's point of view.
      PortResolveError err{};
      err.kind = PortResolveErrorKind::kPortNotRegistered;
      err.role_name = role.name;
      err.message = "role '";
      err.message += role.name;
      err.message += "' port_id=";
      err.message += std::to_string(port_id);
      err.message += " (name '";
      err.message += port_name;
      err.message += "') failed dev_info probe";
      return err;
    }

    const std::uint16_t observed_caps = *caps_opt;
    if (observed_caps < n_workers) {
      PortResolveError err{};
      err.kind = PortResolveErrorKind::kInsufficientTxQueues;
      err.role_name = role.name;
      err.message =
          build_queue_msg(role.name, port_id, observed_caps, n_workers);
      return err;
    }

    ok.by_role.emplace(role.name, port_id);
  }

  return ok;
}

std::variant<std::uint16_t, PortResolveError> lookup_role(
    const PortResolveOk& resolved, std::string_view role_name) {
  // unordered_map<string,_>::find takes a string_view-compatible
  // key in C++20 only with the heterogeneous-lookup opt-in (which
  // we don't enable here — keeping the resolver minimal). One
  // string copy per main.cpp boot lookup is free.
  auto it = resolved.by_role.find(std::string{role_name});
  if (it == resolved.by_role.end()) {
    PortResolveError err{};
    err.kind = PortResolveErrorKind::kUnresolvedRoleSelector;
    err.role_name = std::string{role_name};
    err.message = "role '";
    err.message += role_name;
    err.message +=
        "' is not declared in interface_roles (no resolver entry)";
    return err;
  }
  return it->second;
}

}  // namespace pktgate::ctl
