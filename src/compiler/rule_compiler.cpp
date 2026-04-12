// src/compiler/rule_compiler.cpp
//
// M2 C3-C4 — L2/L4 compound construction.
//
// Implements compile_l2_rules() and compile_l4_rules().
//
// L2: for each L2 rule, determine the most-selective constrained field
// as primary hash key (§5.2 selectivity order: src_mac > dst_mac >
// vlan > ethertype > pcp), and build an L2CompoundEntry with
// filter_mask bits for secondary constraints.
//
// L4: for each L4 rule, determine whether proto+dport or proto-only
// is the primary key (§5.4), build L4CompoundEntry with filter_mask
// bits for secondary constraints (SRC_PORT, TCP_FLAGS).
//
// Design anchors:
//   * D15 — compound primary + filter_mask pattern
//   * §5.2 — L2 selectivity order
//   * §5.4 — L4 compound matching
//   * §4.1 — L2CompoundEntry, L4CompoundEntry layouts
//   * D29 — ICMP type→dport, code→sport unification

#include "src/compiler/rule_compiler.h"

#include <cstring>
#include <tuple>
#include <unordered_map>

// compiler.h defines CompiledAction / CompiledObjects which rule_compiler.h
// only forward-declares (to avoid a circular include — see rule_compiler.h
// top comment and compiler.h M4 C0 retrofit notes). rule_compiler.cpp needs
// full definitions of those types to call member functions like
// `objects.subnets.by_name.find()`.
#include "src/compiler/compiler.h"

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

// -------------------------------------------------------------------------
// compile_l4_rules — L4 compound construction (C4).

L4CompileOutput compile_l4_rules(
    const std::vector<config::Rule>& rules,
    const std::vector<CompiledAction>& /*actions*/) {
  L4CompileOutput output;
  output.rules.reserve(rules.size());

  // Collision detection key: (primary_kind, primary_key, filter_mask,
  // want_src_port, tcp_flags_want, tcp_flags_mask).
  // Two entries with identical key are a collision (dead rule).
  // We use a map from (primary_kind, primary_key) to a vector of
  // (rule_index, filter_mask content) pairs for comparison.
  struct FilterContent {
    std::uint8_t filter_mask;
    std::uint16_t want_src_port;
    std::uint8_t tcp_flags_want;
    std::uint8_t tcp_flags_mask;
  };

  // Key: (primary_kind, primary_key)
  struct PairHash {
    std::size_t operator()(const std::pair<std::uint8_t, std::uint32_t>& p) const {
      return std::hash<std::uint64_t>{}(
          (static_cast<std::uint64_t>(p.first) << 32) | p.second);
    }
  };

  std::unordered_map<
      std::pair<std::uint8_t, std::uint32_t>,
      std::vector<std::pair<std::size_t, FilterContent>>,
      PairHash>
      seen;

  for (std::size_t ri = 0; ri < rules.size(); ++ri) {
    const auto& rule = rules[ri];

    const bool has_proto = (rule.proto >= 0);
    const bool has_dport = (rule.dst_port >= 0);
    const bool has_sport = (rule.src_port >= 0);
    const bool has_tcp_flags = rule.tcp_flags.has_value();

    // Determine primary kind and key.
    L4PrimaryKind primary;
    std::uint32_t primary_key;

    if (has_proto && has_dport) {
      primary = L4PrimaryKind::kProtoDport;
      primary_key =
          (static_cast<std::uint32_t>(rule.proto) << 16) |
          static_cast<std::uint32_t>(rule.dst_port & 0xFFFF);
    } else if (has_proto) {
      primary = L4PrimaryKind::kProtoOnly;
      primary_key = static_cast<std::uint32_t>(rule.proto);
    } else {
      // No proto — degenerate. Still emit as proto-only with key 0.
      primary = L4PrimaryKind::kProtoOnly;
      primary_key = 0;
    }

    // Build filter_mask: set bits for secondary constraints.
    std::uint8_t mask = 0;
    if (has_sport) mask |= l4_mask::kSrcPort;
    if (has_tcp_flags) mask |= l4_mask::kTcpFlags;

    // Build the L4CompoundEntry.
    pktgate::ruleset::L4CompoundEntry entry{};
    entry.filter_mask = mask;
    entry.want_src_port = has_sport
        ? static_cast<std::uint16_t>(rule.src_port & 0xFFFF)
        : 0;
    entry.tcp_flags_want = has_tcp_flags ? rule.tcp_flags->want : 0;
    entry.tcp_flags_mask = has_tcp_flags ? rule.tcp_flags->mask : 0;
    entry._pad = 0;
    entry.action_idx = static_cast<std::uint16_t>(ri);
    entry._pad2 = 0;

    // Collision detection.
    auto map_key = std::make_pair(
        static_cast<std::uint8_t>(primary), primary_key);
    FilterContent fc{mask, entry.want_src_port,
                     entry.tcp_flags_want, entry.tcp_flags_mask};

    auto& bucket = seen[map_key];
    for (const auto& [prev_ri, prev_fc] : bucket) {
      if (prev_fc.filter_mask == fc.filter_mask &&
          prev_fc.want_src_port == fc.want_src_port &&
          prev_fc.tcp_flags_want == fc.tcp_flags_want &&
          prev_fc.tcp_flags_mask == fc.tcp_flags_mask) {
        CompileCollision col;
        col.rule_index_first = prev_ri;
        col.rule_index_second = ri;
        col.description = "L4 compound collision: identical primary key + filter_mask";
        output.collisions.push_back(std::move(col));
      }
    }
    bucket.push_back({ri, fc});

    L4CompiledRule compiled;
    compiled.primary_kind = primary;
    compiled.primary_key = primary_key;
    compiled.entry = entry;
    output.rules.push_back(compiled);
  }

  return output;
}

// -------------------------------------------------------------------------
// compile_l3_rules — L3 compound construction (M4 C0 retrofit, D41).
//
// Current M1 config model (src/config/model.h) only exposes
// `src_subnet` as an unresolved SubnetRef on Rule — there is no
// dst_subnet field yet. For parity with L2/L4 (D15 primary + mask),
// we read the resolved src_subnet CIDRs from CompiledObjects and
// emit one L3CompiledRule per CIDR. Rules with no subnet reference
// at all produce no compound output (they will fall through to
// default behaviour at classify_l3 time).
//
// This matches the "L3 rules need at least src_subnet or dst_subnet"
// comment in tests/unit/test_builder.cpp U4.1 — the builder doesn't
// enforce it, but the compound path skips address-less L3 rules.
//
// Planning note: when M1 grows `dst_subnet` on Rule, compile_l3_rules
// must switch the primary key source and emit one entry per dst CIDR.
// The L3CompoundEntry layout stays the same (filter_mask already has
// a reserved slot for the secondary constraint).

std::vector<L3CompiledRule> compile_l3_rules(
    const std::vector<config::Rule>& rules,
    const std::vector<CompiledAction>& /*actions*/,
    const CompiledObjects& objects) {
  std::vector<L3CompiledRule> result;
  result.reserve(rules.size());

  for (std::size_t ri = 0; ri < rules.size(); ++ri) {
    const auto& rule = rules[ri];
    if (!rule.src_subnet.has_value()) {
      // No address constraint — skip. Classify_l3 will fall through
      // to the default_behavior for packets this rule would have
      // matched if it carried a prefix constraint.
      continue;
    }
    const auto& subnet_name = rule.src_subnet->name;
    auto it = objects.subnets.by_name.find(subnet_name);
    if (it == objects.subnets.by_name.end()) {
      // Unresolved reference. The validator (M1 C8) is supposed to
      // catch dangling subnet refs, so reaching here means the caller
      // bypassed validation. We silently skip rather than emit garbage.
      continue;
    }

    const auto& cidrs = it->second;
    for (const auto& cidr_variant : cidrs) {
      L3CompiledRule compiled{};

      std::visit(
          [&compiled](const auto& c) {
            using T = std::decay_t<decltype(c)>;
            if constexpr (std::is_same_v<T, config::Cidr4>) {
              compiled.primary_kind = L3PrimaryKind::kIpv4DstPrefix;
              compiled.ipv4_prefix = c.addr;
              compiled.prefix_len = c.prefix;
            } else if constexpr (std::is_same_v<T, config::Cidr6>) {
              compiled.primary_kind = L3PrimaryKind::kIpv6DstPrefix;
              for (std::size_t i = 0; i < 16; ++i) {
                compiled.ipv6_prefix[i] = c.bytes[i];
              }
              compiled.prefix_len = c.prefix;
            }
          },
          cidr_variant);

      compiled.entry.filter_mask = 0;
      compiled.entry._pad0 = 0;
      compiled.entry.action_idx = static_cast<std::uint16_t>(ri);
      compiled.entry._pad1 = 0;

      result.push_back(compiled);
    }
  }

  return result;
}

}  // namespace pktgate::compiler
