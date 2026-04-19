// tests/unit/test_port_resolver.cpp
//
// M14 C1 — D43 port resolver unit suite. Five tests U14.1 .. U14.5
// exercise the DPDK-free `pktgate::ctl::resolve_ports` API through
// the parser path (per handoff anti-creep rule: role inputs MUST
// arrive via `parse_config`, not direct InterfaceRole struct
// construction, so the parse → resolve contract is exercised
// end-to-end).
//
// Coverage matrix:
//   U14.1 — single PCI role resolves through fake lookup.
//   U14.2 — single vdev role resolves; resolver strips the comma-
//           tail args before lookup (the registered name is the
//           DPDK PMD name preceding the first `,`).
//   U14.3 — caller queries the resolved map for a role name not
//           declared in `interface_roles` → kUnresolvedRoleSelector.
//   U14.4 — declared role whose port name the injected lookup does
//           not recognise (vdev not on cmdline / pci not bound) →
//           kPortNotRegistered.
//   U14.5 — D28 generalised: vdev role whose `nb_tx_queues` capability
//           is below `n_workers` → kInsufficientTxQueues. Asserts the
//           check fires for non-pci PMDs (vdev) too — the M3 C2
//           pci-only `check_tx_symmetry` inferred the queue cap from
//           BDF info; D43 lifts that to any DPDK port.
//
// Layering:
//   * Links pktgate_ports_ctl (DPDK-free) + pktgate_core (Config /
//     parser).
//   * No EAL, no DPDK headers. Lookup + probe callbacks return
//     deterministic test values.

#include <gtest/gtest.h>

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include "src/config/model.h"
#include "src/config/parser.h"
#include "src/ctl/port_resolver.h"

namespace {

using ::pktgate::config::Config;
using ::pktgate::config::get_err;
using ::pktgate::config::get_ok;
using ::pktgate::config::is_ok;
using ::pktgate::config::parse;
using ::pktgate::config::ParseResult;
using ::pktgate::ctl::lookup_role;
using ::pktgate::ctl::PortLookupFn;
using ::pktgate::ctl::PortQueueProbeFn;
using ::pktgate::ctl::PortResolveError;
using ::pktgate::ctl::PortResolveErrorKind;
using ::pktgate::ctl::PortResolveOk;
using ::pktgate::ctl::PortResolveResult;
using ::pktgate::ctl::resolve_ports;

// Build a minimal config doc with the caller-controlled
// interface_roles body. Pipeline / objects / cmd_socket are all
// empty — the resolver does not consult them.
std::string make_doc(std::string_view interface_roles_body) {
  std::string out = R"json({
  "version": 1,
  "interface_roles": )json";
  out += interface_roles_body;
  out += R"json(,
  "pipeline": { "layer_2": [], "layer_3": [], "layer_4": [] },
  "default_behavior": "drop"
})json";
  return out;
}

Config parse_or_fail(const std::string& doc) {
  ParseResult pr = parse(doc);
  EXPECT_TRUE(is_ok(pr))
      << "fixture parse failed; kind=" << static_cast<int>(get_err(pr).kind)
      << " msg=" << get_err(pr).message << "\n----DOC----\n"
      << doc;
  return get_ok(pr);
}

// Convenience builder for a deterministic name → port_id lookup.
PortLookupFn lookup_from(std::map<std::string, std::uint16_t> table) {
  return [t = std::move(table)](std::string_view name)
             -> std::optional<std::uint16_t> {
    auto it = t.find(std::string{name});
    if (it == t.end()) return std::nullopt;
    return it->second;
  };
}

// Convenience builder for a deterministic port_id → nb_tx_queues
// probe.
PortQueueProbeFn probe_from(std::map<std::uint16_t, std::uint16_t> table) {
  return [t = std::move(table)](std::uint16_t port_id)
             -> std::optional<std::uint16_t> {
    auto it = t.find(port_id);
    if (it == t.end()) return std::nullopt;
    return it->second;
  };
}

// One-shot convenience: probe that always returns `caps` regardless
// of port id (useful when the test does not care about D28 and just
// wants the queue check to pass).
PortQueueProbeFn probe_all(std::uint16_t caps) {
  return [caps](std::uint16_t /*port_id*/)
             -> std::optional<std::uint16_t> { return caps; };
}

}  // namespace

// ---------------------------------------------------------------------------
// U14.1 — single PCI role resolves clean through the injected lookup.

TEST(PortResolverU14_1, SinglePciRoleResolves) {
  const std::string doc = make_doc(R"json({
    "egress_pci": { "pci": "0000:04:00.0" }
  })json");
  Config cfg = parse_or_fail(doc);

  // The injected lookup matches DPDK's behaviour — the port name for
  // a pci-bound NIC is the BDF string verbatim.
  auto lookup = lookup_from({{"0000:04:00.0", 0}});
  auto probe = probe_all(/*nb_tx_queues=*/4);

  PortResolveResult r =
      resolve_ports(cfg, /*n_workers=*/1, lookup, probe);
  ASSERT_TRUE(std::holds_alternative<PortResolveOk>(r))
      << "resolver rejected a happy-path pci role; kind="
      << static_cast<int>(std::get<PortResolveError>(r).kind)
      << " msg=" << std::get<PortResolveError>(r).message;

  const auto& ok = std::get<PortResolveOk>(r);
  ASSERT_EQ(ok.by_role.size(), 1u);
  auto it = ok.by_role.find("egress_pci");
  ASSERT_NE(it, ok.by_role.end());
  EXPECT_EQ(it->second, 0u);
}

// ---------------------------------------------------------------------------
// U14.2 — single vdev role resolves. The resolver must strip the
// comma-tail args before invoking the lookup (DPDK registers the
// vdev under just the PMD name, not the full `name,k=v,...` spec).

TEST(PortResolverU14_2, SingleVdevRoleStripsArgs) {
  const std::string doc = make_doc(R"json({
    "tap_egress": { "vdev": "net_tap0,iface=t0,persist" }
  })json");
  Config cfg = parse_or_fail(doc);

  // Port name presented to lookup must be `net_tap0` — no comma tail.
  auto lookup = lookup_from({{"net_tap0", 5}});
  auto probe = probe_all(/*nb_tx_queues=*/2);

  PortResolveResult r =
      resolve_ports(cfg, /*n_workers=*/1, lookup, probe);
  ASSERT_TRUE(std::holds_alternative<PortResolveOk>(r))
      << "resolver failed vdev happy-path; kind="
      << static_cast<int>(std::get<PortResolveError>(r).kind)
      << " msg=" << std::get<PortResolveError>(r).message;

  const auto& ok = std::get<PortResolveOk>(r);
  ASSERT_EQ(ok.by_role.size(), 1u);
  auto it = ok.by_role.find("tap_egress");
  ASSERT_NE(it, ok.by_role.end());
  EXPECT_EQ(it->second, 5u);
}

// ---------------------------------------------------------------------------
// U14.3 — caller queries an undeclared role name. The resolver
// builds the full role-name → port_id map first, then a separate
// `lookup_role` query against an unknown name surfaces
// kUnresolvedRoleSelector. Mirrors validator's static
// kUnresolvedInterfaceRef but at the runtime resolver tier.

TEST(PortResolverU14_3, UnknownRoleNameReturnsUnresolvedSelector) {
  const std::string doc = make_doc(R"json({
    "ingress": { "pci": "0000:04:00.0" }
  })json");
  Config cfg = parse_or_fail(doc);

  auto lookup = lookup_from({{"0000:04:00.0", 0}});
  auto probe = probe_all(8);
  PortResolveResult r =
      resolve_ports(cfg, /*n_workers=*/1, lookup, probe);
  ASSERT_TRUE(std::holds_alternative<PortResolveOk>(r));
  const auto& ok = std::get<PortResolveOk>(r);

  auto q = lookup_role(ok, "egress_phantom");
  ASSERT_TRUE(std::holds_alternative<PortResolveError>(q));
  const auto& err = std::get<PortResolveError>(q);
  EXPECT_EQ(err.kind, PortResolveErrorKind::kUnresolvedRoleSelector);
  EXPECT_NE(err.message.find("egress_phantom"), std::string::npos)
      << "diagnostic must name the missing role: " << err.message;
}

// ---------------------------------------------------------------------------
// U14.4 — declared role whose port name the lookup callback does
// not recognise. Models "vdev not on EAL cmdline" / "pci not bound
// to DPDK driver". Diagnostic kPortNotRegistered.

TEST(PortResolverU14_4, DeclaredRoleNotInDpdkRegistry) {
  const std::string doc = make_doc(R"json({
    "ghost_tap": { "vdev": "net_tap_ghost,iface=g0" }
  })json");
  Config cfg = parse_or_fail(doc);

  // Lookup table intentionally empty — lookup always returns nullopt.
  auto lookup = lookup_from({});
  auto probe = probe_all(8);

  PortResolveResult r =
      resolve_ports(cfg, /*n_workers=*/1, lookup, probe);
  ASSERT_TRUE(std::holds_alternative<PortResolveError>(r));
  const auto& err = std::get<PortResolveError>(r);
  EXPECT_EQ(err.kind, PortResolveErrorKind::kPortNotRegistered);
  EXPECT_EQ(err.role_name, "ghost_tap");
  // Diagnostic should mention either the role name or the decoded
  // port name so the operator can jump to the typo.
  const bool names_role =
      err.message.find("ghost_tap") != std::string::npos;
  const bool names_port =
      err.message.find("net_tap_ghost") != std::string::npos;
  EXPECT_TRUE(names_role || names_port)
      << "diagnostic must name the offending role or port: "
      << err.message;
}

// ---------------------------------------------------------------------------
// U14.5 — D28 generalised. The resolver must reject a role whose
// resolved port reports `nb_tx_queues < n_workers`, regardless of
// PMD family. Two roles in the doc — one pci with adequate caps,
// one vdev with caps below n_workers. The vdev role must trip the
// kInsufficientTxQueues diagnostic, proving the check fires for
// non-pci PMDs (the M3 C2 pre-existing helper was pci-tested only;
// D43 lifts the invariant to any port).

TEST(PortResolverU14_5, VdevWithInsufficientTxQueuesRejected) {
  const std::string doc = make_doc(R"json({
    "phys_in": { "pci": "0000:04:00.0" },
    "tap_out": { "vdev": "net_tap_short,iface=ts" }
  })json");
  Config cfg = parse_or_fail(doc);

  auto lookup = lookup_from({
      {"0000:04:00.0", 0},
      {"net_tap_short", 1},
  });
  // pci port (id 0) has 8 tx queues; vdev port (id 1) only 1 — under
  // n_workers=4 the vdev fails D28.
  auto probe = probe_from({
      {0, 8},
      {1, 1},
  });

  PortResolveResult r =
      resolve_ports(cfg, /*n_workers=*/4, lookup, probe);
  ASSERT_TRUE(std::holds_alternative<PortResolveError>(r));
  const auto& err = std::get<PortResolveError>(r);
  EXPECT_EQ(err.kind, PortResolveErrorKind::kInsufficientTxQueues);
  EXPECT_EQ(err.role_name, "tap_out");
  // Diagnostic should mention both the queue count and n_workers so
  // the operator knows the gap size.
  EXPECT_NE(err.message.find("4"), std::string::npos)
      << "diagnostic must mention n_workers=4: " << err.message;
  EXPECT_NE(err.message.find("1"), std::string::npos)
      << "diagnostic must mention nb_tx_queues=1: " << err.message;
}
