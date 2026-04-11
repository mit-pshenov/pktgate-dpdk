// src/config/model.h
//
// M1 config AST. Pure POD + std::string / std::vector / std::variant — no
// DPDK types, no allocator knobs. The parser (parser.cpp) produces one of
// these from a JSON document; the validator (M1 C7+) walks it; the
// compiler (M2) lowers it into the runtime Ruleset.
//
// Scope for C1: only the top-level shell that U1.1/U1.2/U1.3 touch.
// Later cycles extend this file — keep additions additive, never break
// already-green tests.
//
// Design anchors:
//   * D8   clean schema, no pktgate-compat keys
//   * D17  fragment_policy enum (default l3_only per P9)
//   * D5   interface_roles sum-type (Pci/Vdev/Name) — stubbed here,
//          fully exercised in C2
//
// Why this header is tiny right now: per TDD §0.1, "nothing speculative,
// nothing 'in preparation for the next milestone'". Fields land when a
// RED test references them.

#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace pktgate::config {

// Compiled-in schema version. The parser rejects any document whose
// top-level `version` field differs from this value (D8 / Q11 — strict
// version match, no forward-compat tolerance).
inline constexpr int kSchemaVersion = 1;

// -------------------------------------------------------------------------
// interface_roles sum-type (D5)
//
// C1 only needs the PCI branch — U1.1 minimal config uses two PCI
// selectors. C2 lands Vdev / Name branches and the mixed-keys rejection.

struct PciSelector {
  // Canonical DPDK BDF string: "0000:00:00.0". Parser normalises on load.
  std::string bdf;
};

struct VdevSelector {
  // Full DPDK vdev spec, e.g. "net_pcap0,tx_iface=lo". Preserved verbatim
  // per U1.5 (arg string round-trip).
  std::string spec;
};

struct NameSelector {
  // Pre-existing DPDK port name, e.g. "net_tap0".
  std::string name;
};

using RoleSelector = std::variant<PciSelector, VdevSelector, NameSelector>;

struct InterfaceRole {
  std::string name;  // role key, e.g. "upstream_port"
  RoleSelector selector;
};

// -------------------------------------------------------------------------
// Top-level enums
//
// `default_behavior` — what happens when no rule matches. D8 enum-bounded.
// `fragment_policy` — D17 / P9. Default `kL3Only` when the field is absent.

enum class DefaultBehavior : std::uint8_t { kAllow, kDrop };
enum class FragmentPolicy : std::uint8_t { kL3Only, kDrop, kAllow };

// -------------------------------------------------------------------------
// Rule shell (C4 minimal surface).
//
// C4 only needs the fields U1.17 / U1.18 / U1.19 / U1.20 probe: `dst_port`,
// `dst_ports`, `vlan_id`, `pcp`. Everything else (match predicates,
// actions, rate specs, rule ids) lands in C5+. Unset numeric fields carry
// the sentinel `-1` — the validator in M1 C7 rejects rules with no
// match fields at all; that's not C4's job.
//
// Rationale for int32_t (not uint16_t): the parser needs to *detect*
// out-of-range negatives at load time (U1.17/U1.18/U1.19 check `-1`
// rejection). A signed wider type captures the raw JSON integer before
// the range check decides accept/reject.

struct Rule {
  std::int32_t dst_port = -1;            // U1.17 range 0..65535, -1 = unset
  std::vector<std::int32_t> dst_ports;   // U1.20 port list
  std::int32_t vlan_id = -1;             // U1.18 range 0..4095, -1 = unset
  std::int32_t pcp = -1;                 // U1.19 range 0..7, -1 = unset
};

// Pipeline layer rule vectors. C1 shape-checked the layer arrays; C4
// starts populating them with minimal Rule shells so the parser has
// a home for the numeric-range fields U1.17..U1.20 land on.
struct Pipeline {
  std::vector<Rule> layer_2;
  std::vector<Rule> layer_3;
  std::vector<Rule> layer_4;
};

// -------------------------------------------------------------------------
// Top-level config

struct Config {
  int version = 0;
  std::vector<InterfaceRole> interface_roles;
  DefaultBehavior default_behavior = DefaultBehavior::kDrop;
  FragmentPolicy fragment_policy = FragmentPolicy::kL3Only;
  Pipeline pipeline{};
};

}  // namespace pktgate::config
