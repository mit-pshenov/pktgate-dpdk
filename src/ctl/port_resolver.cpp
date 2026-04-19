// src/ctl/port_resolver.cpp
//
// M14 C1 STUB — RED phase. Compiles, links, fails the U14.* tests.
// GREEN phase fills in the real visit/lookup/probe wiring.

#include "src/ctl/port_resolver.h"

namespace pktgate::ctl {

std::string port_name_from_selector(const config::RoleSelector& /*sel*/) {
  // RED stub — returns empty so the lookup callback always misses.
  return {};
}

PortResolveResult resolve_ports(const config::Config& /*cfg*/,
                                unsigned /*n_workers*/,
                                const PortLookupFn& /*lookup*/,
                                const PortQueueProbeFn& /*probe*/) {
  // RED stub — always reports a generic kPortNotRegistered.
  PortResolveError err{};
  err.kind = PortResolveErrorKind::kPortNotRegistered;
  err.message = "RED stub — resolver impl not yet wired";
  return err;
}

std::variant<std::uint16_t, PortResolveError> lookup_role(
    const PortResolveOk& /*resolved*/, std::string_view /*role_name*/) {
  PortResolveError err{};
  err.kind = PortResolveErrorKind::kUnresolvedRoleSelector;
  err.message = "RED stub — lookup_role impl not yet wired";
  return err;
}

}  // namespace pktgate::ctl
