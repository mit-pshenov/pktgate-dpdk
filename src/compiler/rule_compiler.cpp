// src/compiler/rule_compiler.cpp
//
// M2 C3 — L2 compound construction.
//
// Implements compile_l2_rules(): for each L2 rule, determine the
// most-selective constrained field as primary hash key (§5.2
// selectivity order: src_mac > dst_mac > vlan > ethertype > pcp),
// and build an L2CompoundEntry with filter_mask bits for secondary
// constraints and populated want_* fields.
//
// Design anchors:
//   * D15 — compound primary + filter_mask pattern
//   * §5.2 — L2 selectivity order
//   * §4.1 — L2CompoundEntry layout

#include "src/compiler/rule_compiler.h"

#include <cstring>

namespace pktgate::compiler {

// Pack a Mac into a uint64_t: first 6 bytes in memory order, upper 2
// bytes zero.
static std::uint64_t mac_to_u64(const config::Mac& m) {
  std::uint64_t v = 0;
  auto* p = reinterpret_cast<std::uint8_t*>(&v);
  for (std::size_t i = 0; i < 6; ++i) p[i] = m.bytes[i];
  return v;
}

std::vector<L2CompiledRule> compile_l2_rules(
    const std::vector<config::Rule>& rules,
    const std::vector<CompiledAction>& /*actions*/) {
  std::vector<L2CompiledRule> result;
  result.reserve(rules.size());

  for (std::size_t ri = 0; ri < rules.size(); ++ri) {
    const auto& rule = rules[ri];

    // Determine which fields are constrained.
    const bool has_src_mac = rule.src_mac.has_value();
    const bool has_dst_mac = rule.dst_mac.has_value();
    const bool has_vlan = (rule.vlan_id >= 0);
    const bool has_ether = rule.ethertype.has_value();
    const bool has_pcp = (rule.pcp >= 0);

    // §5.2 selectivity order: src_mac > dst_mac > vlan > ethertype > pcp.
    // Pick the most-selective constrained field as primary.
    L2PrimaryKind primary;
    std::uint64_t primary_key;

    if (has_src_mac) {
      primary = L2PrimaryKind::kSrcMac;
      primary_key = mac_to_u64(*rule.src_mac);
    } else if (has_dst_mac) {
      primary = L2PrimaryKind::kDstMac;
      primary_key = mac_to_u64(*rule.dst_mac);
    } else if (has_vlan) {
      primary = L2PrimaryKind::kVlan;
      primary_key = static_cast<std::uint64_t>(rule.vlan_id);
    } else if (has_ether) {
      primary = L2PrimaryKind::kEthertype;
      primary_key = static_cast<std::uint64_t>(*rule.ethertype);
    } else if (has_pcp) {
      primary = L2PrimaryKind::kPcp;
      primary_key = static_cast<std::uint64_t>(rule.pcp);
    } else {
      // No L2 constraint at all — this is a degenerate rule that
      // matches all L2 traffic. We still emit it with pcp primary
      // and key 0 so the ruleset builder can handle it. In practice
      // the validator should catch this before we get here.
      primary = L2PrimaryKind::kPcp;
      primary_key = 0;
    }

    // Build filter_mask: set a bit for each constrained field that is
    // NOT the primary.
    std::uint8_t mask = 0;
    if (has_src_mac && primary != L2PrimaryKind::kSrcMac)
      mask |= l2_mask::kSrcMac;
    if (has_dst_mac && primary != L2PrimaryKind::kDstMac)
      mask |= l2_mask::kDstMac;
    if (has_vlan && primary != L2PrimaryKind::kVlan)
      mask |= l2_mask::kVlan;
    if (has_ether && primary != L2PrimaryKind::kEthertype)
      mask |= l2_mask::kEthertype;
    if (has_pcp && primary != L2PrimaryKind::kPcp)
      mask |= l2_mask::kPcp;

    // Build the L2CompoundEntry.
    pktgate::ruleset::L2CompoundEntry entry{};
    entry.filter_mask = mask;
    entry.want_pcp = has_pcp ? static_cast<std::uint8_t>(rule.pcp) : 0;
    entry.want_ethertype = has_ether ? *rule.ethertype : 0;
    entry.want_vlan = has_vlan ? static_cast<std::uint16_t>(rule.vlan_id) : 0;

    // want_mac: the "other" MAC when both src and dst are constrained.
    // If primary is src_mac, want_mac holds dst_mac (and vice versa).
    // If neither is the secondary, want_mac is zeroed.
    std::memset(entry.want_mac, 0, 6);
    if (primary == L2PrimaryKind::kSrcMac && has_dst_mac) {
      std::memcpy(entry.want_mac, rule.dst_mac->bytes.data(), 6);
    } else if (primary == L2PrimaryKind::kDstMac && has_src_mac) {
      std::memcpy(entry.want_mac, rule.src_mac->bytes.data(), 6);
    }

    // action_idx: maps 1:1 by rule index (same ordering as actions).
    entry.action_idx = static_cast<std::uint16_t>(ri);
    entry._tail_pad = 0;

    L2CompiledRule compiled;
    compiled.primary_kind = primary;
    compiled.primary_key = primary_key;
    compiled.entry = entry;
    result.push_back(compiled);
  }

  return result;
}

}  // namespace pktgate::compiler
