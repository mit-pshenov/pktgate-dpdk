// tests/unit/test_port_resolver_vhost.cpp
//
// M15 C1 — D44 vhost profile coverage against the existing M14 port
// resolver. Three unit tests U15.1..U15.3 exercise
// `pktgate::ctl::resolve_ports` with `net_vhost` vdev selectors,
// asserting that the same DPDK-free resolver handles vhost identically
// to pci / tap (D43 abstraction — PMD family is invisible to the
// resolver).
//
// Coverage matrix:
//   U15.1 — single vdev role `{vdev: "net_vhost0,iface=...,queues=1"}`
//           resolves through the injected lookup. The resolver MUST
//           strip the comma tail and invoke lookup with just
//           `"net_vhost0"` — any regression in `port_name_from_selector`
//           comma-strip logic would pass the full spec to the lookup
//           callback and miss, so the fake lookup is keyed only on
//           `"net_vhost0"`. Zero LOC expected to change in the resolver.
//   U15.2 — D28 generalised on vhost: same vhost role, `nb_tx_queues=1`,
//           `n_workers=2` → kInsufficientTxQueues with role name +
//           observed vs. required queue counts in the diagnostic.
//   U15.3 — heterogeneous config: one pci role + one vhost role resolve
//           to distinct port ids without cross-contamination (lookup
//           table has both entries with different ids).
//
// Style-matches `test_port_resolver.cpp` (M14 C1) — inputs go through
// `config::parse` (handoff anti-creep: resolver input MUST arrive via
// the real parser, not direct InterfaceRole struct construction), fake
// lookup / probe callbacks are deterministic std::function closures
// over std::map tables. No EAL, no DPDK headers.

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
using ::pktgate::ctl::PortLookupFn;
using ::pktgate::ctl::PortQueueProbeFn;
using ::pktgate::ctl::PortResolveError;
using ::pktgate::ctl::PortResolveErrorKind;
using ::pktgate::ctl::PortResolveOk;
using ::pktgate::ctl::PortResolveResult;
using ::pktgate::ctl::resolve_ports;

// Minimal config doc — resolver consults only `interface_roles`.
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

PortLookupFn lookup_from(std::map<std::string, std::uint16_t> table) {
  return [t = std::move(table)](std::string_view name)
             -> std::optional<std::uint16_t> {
    auto it = t.find(std::string{name});
    if (it == t.end()) return std::nullopt;
    return it->second;
  };
}

PortQueueProbeFn probe_all(std::uint16_t caps) {
  return [caps](std::uint16_t /*port_id*/)
             -> std::optional<std::uint16_t> { return caps; };
}

}  // namespace

// ---------------------------------------------------------------------------
// U15.1 — single vhost vdev role resolves via comma-stripped lookup.
//
// The operator passes the full spec `net_vhost0,iface=<path>,queues=1`
// on the EAL cmdline; DPDK registers the vdev under the name prefix
// `net_vhost0` (substring before the first `,`). The resolver's
// `port_name_from_selector` VdevSelector arm strips the comma tail
// (M14 C1, `src/ctl/port_resolver.cpp:56-63`) so the lookup callback
// receives just `net_vhost0`.
//
// The fake lookup is keyed ONLY on `"net_vhost0"` — if a future
// regression reverts the comma-strip logic, the resolver would invoke
// lookup with the raw spec, miss (nullopt), and surface
// kPortNotRegistered. This test pins the contract for vhost
// identically to how U14.2 pins it for net_tap.

TEST(PortResolverU15_1, Resolve_NetVhost_WithCommaTail_ReturnsPortId) {
  const std::string doc = make_doc(R"json({
    "downstream_port": { "vdev": "net_vhost0,iface=/tmp/m15.sock,queues=1" }
  })json");
  Config cfg = parse_or_fail(doc);

  // Lookup table is keyed on the comma-stripped port name. The
  // resolver MUST invoke lookup with just "net_vhost0", never the full
  // spec. Any regression in the comma-strip logic fails this test.
  auto lookup = lookup_from({{"net_vhost0", 7}});
  auto probe = probe_all(/*nb_tx_queues=*/4);

  PortResolveResult r =
      resolve_ports(cfg, /*n_workers=*/2, lookup, probe);
  ASSERT_TRUE(std::holds_alternative<PortResolveOk>(r))
      << "resolver rejected happy-path vhost role; kind="
      << static_cast<int>(std::get<PortResolveError>(r).kind)
      << " msg=" << std::get<PortResolveError>(r).message;

  const auto& ok = std::get<PortResolveOk>(r);
  ASSERT_EQ(ok.by_role.size(), 1u);
  auto it = ok.by_role.find("downstream_port");
  ASSERT_NE(it, ok.by_role.end());
  EXPECT_EQ(it->second, 7u);
}

// ---------------------------------------------------------------------------
// U15.2 — D28 generalised on vhost. A vhost port whose nb_tx_queues
// cap is below n_workers trips kInsufficientTxQueues. Same invariant
// U14.5 pins for net_tap; D43 lifted it to every PMD family.
//
// Diagnostic must name the role and both the observed caps and the
// required worker count so the operator can size the vhost
// `queues=<n>` vdev arg correctly on the next boot.

TEST(PortResolverU15_2, VhostPort_InsufficientTxQueues_ReturnsError) {
  const std::string doc = make_doc(R"json({
    "downstream_port": { "vdev": "net_vhost0,iface=/tmp/m15.sock,queues=1" }
  })json");
  Config cfg = parse_or_fail(doc);

  auto lookup = lookup_from({{"net_vhost0", 7}});
  // Only 1 TX queue — below n_workers=2.
  auto probe = probe_all(/*nb_tx_queues=*/1);

  PortResolveResult r =
      resolve_ports(cfg, /*n_workers=*/2, lookup, probe);
  ASSERT_TRUE(std::holds_alternative<PortResolveError>(r));
  const auto& err = std::get<PortResolveError>(r);
  EXPECT_EQ(err.kind, PortResolveErrorKind::kInsufficientTxQueues);
  EXPECT_EQ(err.role_name, "downstream_port");
  // Diagnostic names role, observed queue count, required workers.
  EXPECT_NE(err.message.find("downstream_port"), std::string::npos)
      << "diagnostic must name the role: " << err.message;
  EXPECT_NE(err.message.find("1"), std::string::npos)
      << "diagnostic must mention nb_tx_queues=1: " << err.message;
  EXPECT_NE(err.message.find("2"), std::string::npos)
      << "diagnostic must mention n_workers=2: " << err.message;
}

// ---------------------------------------------------------------------------
// U15.3 — heterogeneous config: one pci upstream + one vhost
// downstream resolve to distinct port ids. Asserts the resolver walks
// every role independently with no cross-contamination (each role
// lands at the port id its own selector/lookup pair returns).
//
// This is the canonical *prod DPI hand-off* deployment shape (D43
// canonical profiles): physical NIC ingest, vhost egress to the DPI
// consumer's virtio-user PMD. If the resolver ever cached the first
// role's port id and reused it, or swapped the order, we'd see the
// two ports collide.

TEST(PortResolverU15_3, MixedPciAndVhost_ResolveToDistinctPortIds) {
  const std::string doc = make_doc(R"json({
    "upstream_port":   { "pci":  "0000:03:00.0" },
    "downstream_port": { "vdev": "net_vhost0,iface=/tmp/m15.sock,queues=1" }
  })json");
  Config cfg = parse_or_fail(doc);

  auto lookup = lookup_from({
      {"0000:03:00.0", 3},
      {"net_vhost0", 7},
  });
  auto probe = probe_all(/*nb_tx_queues=*/4);

  PortResolveResult r =
      resolve_ports(cfg, /*n_workers=*/1, lookup, probe);
  ASSERT_TRUE(std::holds_alternative<PortResolveOk>(r))
      << "resolver rejected mixed pci+vhost config; kind="
      << static_cast<int>(std::get<PortResolveError>(r).kind)
      << " msg=" << std::get<PortResolveError>(r).message;

  const auto& ok = std::get<PortResolveOk>(r);
  ASSERT_EQ(ok.by_role.size(), 2u);

  auto up = ok.by_role.find("upstream_port");
  auto dn = ok.by_role.find("downstream_port");
  ASSERT_NE(up, ok.by_role.end());
  ASSERT_NE(dn, ok.by_role.end());
  EXPECT_EQ(up->second, 3u);
  EXPECT_EQ(dn->second, 7u);
  EXPECT_NE(up->second, dn->second)
      << "pci and vhost roles collapsed to the same port id";
}
