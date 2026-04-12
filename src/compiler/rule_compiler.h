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

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

#include "src/compiler/compiler.h"
#include "src/config/model.h"
#include "src/ruleset/types.h"

namespace pktgate::compiler {

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
// L4PrimaryKind — which L4 hash table the rule's primary key lands in.
//
// §5.4 selectivity order:
//   l4_proto_dport  key = (proto << 16) | dport   // most common
//   l4_proto_only   key = proto                    // catch-all (proto only, no port)
//
// l4_proto_sport is a separate primary for rare sport-keyed rules
// but is not used in C4 scope (those rules have sport as secondary).

enum class L4PrimaryKind : std::uint8_t {
  kProtoDport,    // primary key = (proto << 16) | dport
  kProtoOnly,     // primary key = proto (no port constraint)
};

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

}  // namespace pktgate::compiler
