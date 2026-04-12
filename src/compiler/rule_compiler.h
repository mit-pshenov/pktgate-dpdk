// src/compiler/rule_compiler.h
//
// M2 C3 — L2 compound construction: rule → primary key + filter_mask.
//
// The rule compiler takes compiled actions and raw rules, determines
// the most-selective L2 field as primary hash key (§5.2 selectivity
// order: src_mac > dst_mac > vlan > ethertype > pcp), and builds
// L2CompoundEntry values with filter_mask bits for secondary constraints.
//
// Design anchors:
//   * D15 — compound primary + filter_mask pattern
//   * §5.2 — L2 selectivity order
//   * §4.1 — L2CompoundEntry layout

#pragma once

#include <cstdint>
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
// L2PrimaryKind — which hash table the rule's primary key lands in.

enum class L2PrimaryKind : std::uint8_t {
  kSrcMac,
  kDstMac,
  kVlan,
  kEthertype,
  kPcp,
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

}  // namespace pktgate::compiler
