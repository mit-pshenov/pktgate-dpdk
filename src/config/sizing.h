// src/config/sizing.h
//
// M1 C6 — sizing config primitives.
//
// D6 anchor: rule-count / capacity ceilings are **runtime parameters**,
// sized at startup from the config file. There are **no compile-time
// ceilings** — only a compile-time hard **minimum** (per review-notes
// D6 §3a.2, "hard minimum (compile rejects smaller): 16 per layer").
//
// M1 meta-principle: the dev VM does not shape architecture. Dev and
// prod sizing are **two explicit, equal-status columns** named below
// — not a "MVP=dev, v2=prod" phasing. Both constants always live in
// the binary. The operator chooses a column via the config file (or
// via `--sizing-config <file>` in a later cycle); both are first-class
// and neither is privileged over the other. See CLAUDE.md §M1 /
// review-notes D6.
//
// Schema shape in JSON is flat (ten keys, see design.md §3a.1):
//   sizing: {
//     rules_per_layer_max: 4096,
//     mac_entries_max:     4096,
//     ipv4_prefixes_max:   16384,
//     ipv6_prefixes_max:   16384,
//     l4_entries_max:      4096,
//     vrf_entries_max:     256,
//     rate_limit_rules_max:4096,
//     ethertype_entries_max:64,
//     vlan_entries_max:    4096,
//     pcp_entries_max:     8
//   }
//
// When the `sizing` key is absent from the document, the parser fills
// `Config.sizing` with `kSizingDevDefaults` so the dev VM boot path is
// a zero-arg config. Production deployments provide the `sizing`
// section (inlined or via a separate file in a later cycle) and
// typically select the `kSizingProdDefaults` numbers.
//
// No DPDK deps. Pure stdlib + nlohmann::json (via parser.cpp, not
// from this header). Tests: unit/test_parser.cpp U1.25..U1.28 and
// the stress-lite canary U1.31.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include "src/config/model.h"   // Sizing, ObjectPool
#include "src/config/parser.h"  // ParseError

namespace pktgate::config {

// The Sizing struct itself lives in model.h so Config can hold it
// inline without a circular include. Only the parse glue and the
// first-class dev/prod constants live here.

// Hard minimum for `rules_per_layer_max` (D6 §3a.2 — "compile rejects
// smaller: 16 per layer"). Anything below this is a parse error
// (`kSizingBelowMin`), even if all the other fields are fine. The
// minimum exists to keep tests meaningful — a 1-rule ruleset does
// not exercise first-match-wins.
inline constexpr std::uint32_t kSizingRulesPerLayerHardMin = 16;

// D6 dev column. First-class constant, **not** a "MVP limit". The dev
// VM (VirtualBox, 512 MiB hugepages) runs these because they fit in
// its memory budget, not because the architecture is limited to them.
inline constexpr Sizing kSizingDevDefaults{
    /*rules_per_layer_max   =*/256,
    /*mac_entries_max       =*/256,
    /*ipv4_prefixes_max     =*/1024,
    /*ipv6_prefixes_max     =*/1024,
    /*l4_entries_max        =*/256,
    /*vrf_entries_max       =*/32,
    /*rate_limit_rules_max  =*/256,
    /*ethertype_entries_max =*/32,
    /*vlan_entries_max      =*/256,
    /*pcp_entries_max       =*/8,
    /*prom_port             =*/9090,  // M10 C3 / D42
};

// D6 prod column. First-class constant, **not** a "v2 target". The
// production NIC path (Intel E810 / XL710, Mellanox CX-5/6) targets
// these; deployments typically paste them into the config file.
inline constexpr Sizing kSizingProdDefaults{
    /*rules_per_layer_max   =*/4096,
    /*mac_entries_max       =*/4096,
    /*ipv4_prefixes_max     =*/16384,
    /*ipv6_prefixes_max     =*/16384,
    /*l4_entries_max        =*/4096,
    /*vrf_entries_max       =*/256,
    /*rate_limit_rules_max  =*/4096,
    /*ethertype_entries_max =*/64,
    /*vlan_entries_max      =*/4096,
    /*pcp_entries_max       =*/8,
    /*prom_port             =*/9090,  // M10 C3 / D42
};

// Parse the inline `sizing` object. Returns nullopt on success (value
// written to `out`), or a ParseError otherwise. All fields are
// required when the section is present — partial `sizing` objects are
// rejected as kUnknownField on the missing key, to prevent silent
// half-defaulting ("did I mean dev or prod for the fields I left
// off?"). Out-of-range values below the hard minimum produce
// kSizingBelowMin.
std::optional<ParseError> parse_sizing(const nlohmann::json& j, Sizing& out);

// -------------------------------------------------------------------------
// objects.subnets — unresolved name → CIDR list mapping.
//
// Parser-tier concern: accept every well-formed CIDR literal,
// classify it as Cidr4 or Cidr6 via the existing addr.h parsers, and
// store the list verbatim under its object name. Whether a named
// object is actually referenced by any rule — or, conversely, whether
// a rule references an object that doesn't exist — is the validator's
// job (C7+).
//
// The CIDR variant element type reuses the exact Cidr4/Cidr6 types
// from addr.h so the validator can walk the list without an extra
// conversion step.

// Parse the `objects.subnets` map. Each entry is `name → [cidr, ...]`
// with every element parseable by parse_cidr4 / parse_cidr6. Returns
// nullopt on success (value written to `out`), or a ParseError. Any
// malformed CIDR is surfaced as kBadCidr. Every top-level key under
// `objects` that is not `subnets` is rejected as kUnknownField — C6
// only implements the one dictionary, additional object types land
// in later cycles.
std::optional<ParseError> parse_objects(const nlohmann::json& j,
                                        ObjectPool& out);

}  // namespace pktgate::config
