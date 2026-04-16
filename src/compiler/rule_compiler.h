// src/compiler/rule_compiler.h
//
// M2 C3-C4 — L2/L4 compound construction: rule → primary key + filter_mask.
//
// The rule compiler takes compiled actions and raw rules, determines
// the most-selective field as primary hash key, and builds compound
// entry values with filter_mask bits for secondary constraints.
//
// Design anchors:
//   * D15 — compound primary + filter_mask pattern
//   * §5.2 — L2 selectivity order
//   * §5.4 — L4 compound matching
//   * §4.1 — L2CompoundEntry, L4CompoundEntry layouts
//   * D29 — ICMP type→dport, code→sport unification

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

#include "src/config/model.h"
#include "src/ruleset/types.h"

namespace pktgate::compiler {

// Forward declarations to avoid a cycle with compiler.h (which itself
// needs complete L{2,3,4}CompiledRule for CompileResult's vectors,
// M4 C0 D41 retrofit).
struct CompiledAction;
struct CompiledObjects;

// -------------------------------------------------------------------------
// L2 filter_mask bit definitions (§4.1, D15).
//
// Each bit indicates that the corresponding secondary field must match.
// The primary key field is never set in filter_mask (it's already
// matched by the hash lookup).

namespace l2_mask {
inline constexpr std::uint8_t kSrcMac    = 0x01;
inline constexpr std::uint8_t kDstMac    = 0x02;
inline constexpr std::uint8_t kPcp       = 0x04;
inline constexpr std::uint8_t kVlan      = 0x08;
inline constexpr std::uint8_t kEthertype = 0x10;
}  // namespace l2_mask

// -------------------------------------------------------------------------
// L4 filter_mask bit definitions (§4.1, D15).
//
// SRC_PORT: want_src_port must match the packet's source port (or
//   ICMP code, per D29 unification).
// TCP_FLAGS: tcp_flags_want/tcp_flags_mask must match.
// VRF: reserved for VRF-constrained rules (future).

namespace l4_mask {
inline constexpr std::uint8_t kSrcPort   = 0x01;
inline constexpr std::uint8_t kTcpFlags  = 0x02;
inline constexpr std::uint8_t kVrf       = 0x04;
}  // namespace l4_mask

// -------------------------------------------------------------------------
// L2PrimaryKind — which hash table the rule's primary key lands in.

enum class L2PrimaryKind : std::uint8_t {
  kSrcMac,
  kDstMac,
  kVlan,
  kEthertype,
  kPcp,
};

// -------------------------------------------------------------------------
// L4PrimaryKind — which L4 primary key shape the rule uses.
//
// §5.4 / D15 selectivity order (most to least selective):
//   kProtoDport  key = (proto << 16) | dport
//   kProtoSport  key = (1u << 24) | (proto << 16) | sport
//   kProtoOnly   key = (2u << 24) | proto
//
// All three kinds share the single `l4_compound_hash` rte_hash in the
// Ruleset. The high byte of the uint32_t key is a kind tag that
// prevents collisions between different primary kinds:
//   kProtoDport:  tag = 0 (proto is max 255, so bits 24-31 are 0)
//   kProtoSport:  tag = 1 << 24
//   kProtoOnly:   tag = 2 << 24

enum class L4PrimaryKind : std::uint8_t {
  kProtoDport,    // key = (proto << 16) | dport
  kProtoSport,    // key = (1u << 24) | (proto << 16) | sport
  kProtoOnly,     // key = (2u << 24) | proto
};

// L4 key construction helpers (shared by compiler + classifier).
namespace l4_key {
inline constexpr std::uint32_t kSportTag    = 1u << 24;
inline constexpr std::uint32_t kProtoOnlyTag = 2u << 24;

inline constexpr std::uint32_t proto_dport(std::uint8_t proto, std::uint16_t dport) {
  return (static_cast<std::uint32_t>(proto) << 16) | dport;
}
inline constexpr std::uint32_t proto_sport(std::uint8_t proto, std::uint16_t sport) {
  return kSportTag | (static_cast<std::uint32_t>(proto) << 16) | sport;
}
inline constexpr std::uint32_t proto_only(std::uint8_t proto) {
  return kProtoOnlyTag | static_cast<std::uint32_t>(proto);
}
}  // namespace l4_key

// -------------------------------------------------------------------------
// L2CompiledRule — one L2 rule after compound construction.
//
// Contains the primary key choice, the compound entry (filter_mask +
// secondary want_* fields + action_idx), and the primary key value
// (MAC packed as uint64_t, or vlan/ethertype/pcp as uint16_t).

struct L2CompiledRule {
  L2PrimaryKind primary_kind;
  std::uint64_t primary_key;      // MAC as u64, or narrow field zero-extended
  pktgate::ruleset::L2CompoundEntry entry;
};

// -------------------------------------------------------------------------
// L3PrimaryKind — which FIB the rule's primary key lands in.
//
// M4 C0 retrofit (D41). Primary key is the destination prefix of
// the rule, sourced from `Rule.dst_subnet` (renamed from `src_subnet`
// in M5 C1c, P10(c) resolution 2026-04-15). Rules with no L3 address
// constraint at all produce no L3 compound entry (no primary to
// key on).

enum class L3PrimaryKind : std::uint8_t {
  kIpv4DstPrefix,
  kIpv6DstPrefix,
};

// -------------------------------------------------------------------------
// L3CompiledRule — one L3 rule after compound construction (M4 C0).
//
// Holds the primary key (IPv4 32-bit or IPv6 128-bit prefix + depth),
// the compound entry (action_idx + filter_mask for future secondary
// constraints), and the kind discriminator.

struct L3CompiledRule {
  L3PrimaryKind primary_kind;
  std::uint8_t  prefix_len;

  // IPv4 prefix (host order); valid when primary_kind == kIpv4DstPrefix.
  std::uint32_t ipv4_prefix;

  // IPv6 prefix (network byte order); valid when primary_kind == kIpv6DstPrefix.
  std::array<std::uint8_t, 16> ipv6_prefix;

  pktgate::ruleset::L3CompoundEntry entry;
};

// -------------------------------------------------------------------------
// L4CompiledRule — one L4 rule after compound construction.
//
// Contains the primary key choice, the compound entry (filter_mask +
// secondary want_* fields + action_idx), and the primary key value
// (encoded as uint32_t: proto<<16|dport for kProtoDport, or proto for
// kProtoOnly).

struct L4CompiledRule {
  L4PrimaryKind primary_kind;
  std::uint32_t primary_key;
  pktgate::ruleset::L4CompoundEntry entry;
};

// -------------------------------------------------------------------------
// CompileCollision — describes a collision between two rules that
// produce identical primary key + filter_mask content in the same
// hash table. The later rule is dead (unreachable) and should be
// reported as a compiler warning or error.

struct CompileCollision {
  std::string description;
  std::size_t rule_index_first;   // index of the earlier rule
  std::size_t rule_index_second;  // index of the dead rule
};

// -------------------------------------------------------------------------
// L4CompileOutput — result of L4 compound construction.

struct L4CompileOutput {
  std::vector<L4CompiledRule> rules;
  std::vector<CompileCollision> collisions;
};

// -------------------------------------------------------------------------
// compile_l2_rules — build L2 compound entries from config rules.
//
// Takes the L2 rules from the config pipeline and the already-compiled
// L2 actions (from object_compiler::compile()), and produces one
// L2CompiledRule per input rule.
//
// Port-list dedup: if dst_ports contains duplicates, they are deduped
// (unique entries only). This is a compile-time policy (U3.25).

std::vector<L2CompiledRule> compile_l2_rules(
    const std::vector<config::Rule>& rules,
    const std::vector<CompiledAction>& actions);

// -------------------------------------------------------------------------
// compile_l4_rules — build L4 compound entries from config rules.
//
// For each L4 rule, determines whether the rule has a dport constraint
// (→ kProtoDport primary) or only a proto constraint (→ kProtoOnly).
// Builds the L4CompoundEntry with filter_mask bits for secondary
// constraints (SRC_PORT if src_port is set, TCP_FLAGS if tcp_flags
// is set).
//
// Reports collisions when two rules produce identical primary key +
// identical filter_mask content (dead rule detection, U3.24).

L4CompileOutput compile_l4_rules(
    const std::vector<config::Rule>& rules,
    const std::vector<CompiledAction>& actions);

// -------------------------------------------------------------------------
// compile_l3_rules — build L3 compound entries from config rules (M4 C0).
//
// For each L3 rule, resolves the rule's destination prefix by looking
// up `Rule.dst_subnet` in the compiled subnet pool and emits one
// L3CompiledRule per CIDR. Rules without any subnet ref produce no
// compound output.
//
// Invariants:
//   * Output order matches input rule order (first-match-wins preserved).
//   * action_idx in each entry maps 1:1 to rule index (matches L2/L4).
//   * Mixed-family subnets produce one L3CompiledRule per CIDR in the
//     named subnet's order (so a subnet with two CIDRs yields two
//     compiled rules sharing an action).

std::vector<L3CompiledRule> compile_l3_rules(
    const std::vector<config::Rule>& rules,
    const std::vector<CompiledAction>& actions,
    const CompiledObjects& objects);

}  // namespace pktgate::compiler
