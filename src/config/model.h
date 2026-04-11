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

// Empty pipeline struct for C1. Real layer_2 / layer_3 / layer_4 rule
// vectors land in C3+.
struct Pipeline {
  // intentionally empty in C1
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
