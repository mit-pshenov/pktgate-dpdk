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

#include <sys/types.h>  // ::gid_t (POSIX); used by CmdSocket.allow_gids.

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "src/config/addr.h"

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

// C7.6 / U1.35. `next_layer` scopes a rule to the subsequent pipeline
// layer for staged progression (l2 → l3 → l4). The parser only
// validates the enum value space — it never enforces ordering against
// the hosting layer (l2 on a `layer_3` rule). That cross-layer
// invariant belongs to the C8 validator (U2.19). Keeping the enum
// values exhaustive (no kNone sentinel) is deliberate: absence is
// modelled via `std::optional<NextLayer>` on Rule, not via a
// distinguished enum value.
enum class NextLayer : std::uint8_t { kL2, kL3, kL4 };

// -------------------------------------------------------------------------
// RuleAction sum-type (D15 exactly-one / D7 mirror-accept / D1 rate).
//
// C5 introduces the action variant on Rule. Each branch holds exactly
// the fields the parser converts from the JSON action object:
//
//   * ActionAllow / ActionDrop — no payload; the type itself is the decision.
//   * ActionRateLimit — D1 anchor. The parser resolves the rate string
//     ("200Mbps", "1Gbps", "64kbps") and the `burst_ms` window into
//     absolute byte counters at **load time**. Runtime never sees the
//     string or the milliseconds — only the pre-computed integers.
//   * ActionTag — DSCP / PCP rewrite carrier (C9 extends; C5 only needs
//     the tag to exist as a sum-type alternative if tests probe it).
//   * ActionTargetPort — role-name redirect. Resolution is C9 validator.
//   * ActionMirror — D7: parser-accept, validator/compiler reject in MVP.
//
// C5 scope only instantiates the variants exercised by U1.21/U1.22/U1.29
// (ActionRateLimit, ActionAllow, ActionDrop). Tag / TargetPort / Mirror
// are not test-probed in this cycle — but ActionTargetPort is referenced
// in U1.29's mixed-keys negative (`allow + target_port`), so the parser
// must at least know the "target_port" key is an action field. The
// ActionTargetPort variant therefore lands in the model even though
// no positive test exercises it yet.

struct ActionAllow {};
struct ActionDrop {};

struct ActionRateLimit {
  // D1: resolved at load time. Runtime hot path reads these directly.
  // uint64_t matches the per-lcore TokenBucket arithmetic used in
  // review-notes.md §D1 (elapsed_cycles * rate_bytes_per_sec / tsc_hz).
  std::uint64_t bytes_per_sec = 0;
  std::uint64_t burst_bytes = 0;
};

struct ActionTag {
  // C9 populates; C5 scaffold only.
  std::int32_t dscp = -1;
  std::int32_t pcp = -1;
};

struct ActionTargetPort {
  // Role name — resolution to PortId happens at validator / compile time.
  std::string role_name;
};

struct ActionMirror {
  // D7 — parser syntactically accepts; compiler/validator rejects in MVP.
  std::string role_name;
};

using RuleAction = std::variant<ActionAllow, ActionDrop, ActionRateLimit,
                                ActionTag, ActionTargetPort, ActionMirror>;

// -------------------------------------------------------------------------
// TcpFlags — compact (mask, want) pair matching the L4CompoundEntry
// filter_mask semantics (D15). Each flag in the JSON `tcp_flags` sub-
// object contributes:
//
//   * value true  → bit set in both mask and want ("must be set")
//   * value false → bit set in mask, cleared in want ("must be clear")
//   * absent      → bit cleared in both (don't-care)
//
// The invariant `(want & ~mask) == 0` is structural: the parser only
// writes bits into `want` after setting the same bit in `mask`.
//
// Bit layout (RFC 9293 §3.1):
//   FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08,
//   ACK=0x10, URG=0x20, ECE=0x40, CWR=0x80.

struct TcpFlags {
  std::uint8_t mask = 0;
  std::uint8_t want = 0;
};

// -------------------------------------------------------------------------
// SubnetRef (C6.5, D8). Unresolved reference to an entry in
// `objects.subnets`. The parser stores the raw name verbatim; the
// validator (C8) maps it to a concrete SubnetId / CIDR list. We keep
// this as a named struct rather than a bare std::string so the AST
// statically distinguishes "a name pointing at an object" from all the
// other string-typed fields on Rule (role names, action targets).
// Dangling-reference detection is explicitly out of parser scope.

struct SubnetRef {
  std::string name;
};

// -------------------------------------------------------------------------
// Rule shell.
//
// C4 minimal surface: `dst_port`, `dst_ports`, `vlan_id`, `pcp`.
// C5 extends with `id` (required, positive int — U1.24),
// `action` (optional variant — U1.29), `hw_offload_hint` (optional
// bool default false — U1.23), and `tcp_flags` (optional sub-object
// — U1.30).
//
// Unset sentinels for numeric fields remain `-1` per C4 convention.
// `id == -1` means "id was never populated" — the parser rejects such
// rules, so a valid AST never contains `id == -1`, but the default
// keeps the struct aggregate-initialisable without telling lies.

struct Rule {
  std::int32_t id = -1;                  // U1.24 required, positive integer
  std::int32_t dst_port = -1;            // U1.17 range 0..65535, -1 = unset
  std::vector<std::int32_t> dst_ports;   // U1.20 port list
  std::int32_t src_port = -1;            // M2 C4: range 0..65535, -1 = unset
  std::int32_t proto = -1;               // M2 C4: L4 protocol number 0..255, -1 = unset
  std::int32_t vlan_id = -1;             // U1.18 range 0..4095, -1 = unset
  std::int32_t pcp = -1;                 // U1.19 range 0..7, -1 = unset
  bool hw_offload_hint = false;          // U1.23 D4
  std::optional<TcpFlags> tcp_flags{};   // U1.30 D15
  std::optional<RuleAction> action{};    // U1.29 D15 exactly-one
  // U1.28 / C6.5 / M5 C1c (P10(c) rename, 2026-04-15): unresolved
  // `dst_subnet` reference. Populated by the parser when a rule carries
  // `"dst_subnet": "<name>"`; the C8 validator maps the name to an
  // entry in `objects.subnets`. The L3 compiler packs the resolved
  // CIDR(s) as the destination-prefix primary key for `kIpv{4,6}DstPrefix`.
  // Historical note: this slot was named `src_subnet` until M5 C1c —
  // the parser had always stored the value here and the compiler had
  // always packed it as a dst-prefix, so the rename retroactively
  // corrects the semantics with no FIB or storage changes. The
  // deprecated `"src_subnet"` JSON key is rejected at parse time
  // (see ParserU1_36).
  std::optional<SubnetRef> dst_subnet{};
  // C7 / U2.3 / U2.4 (D5): unresolved role name reference. Populated
  // by the parser when a rule carries `"interface": "<name>"`; the
  // validator maps the name to an entry in `interface_roles`.
  // Named `interface_ref` rather than `interface` because `interface`
  // is a reserved extension-identifier keyword under MSVC and the
  // Objective-C dialect — avoiding the collision now keeps a future
  // Windows host happy at zero cost.
  std::optional<std::string> interface_ref{};
  // C7.6 / U1.33/U1.34/U1.35. L2 compound key fields + next_layer.
  // These close a plan-drift gap: C1-C6 never added them because no
  // U1 test exercised them, and C8 (compound collision + layer order)
  // would have tripped on their absence. The parser only stores the
  // values; filter_mask derivation (design §4.1 L2CompoundEntry) is
  // the M2 compiler's job and is NOT represented as a JSON field.
  //
  // `ethertype` is stored as uint16_t (wire-format width). Common
  // values: 0x0800 IPv4, 0x86DD IPv6, 0x8100 VLAN, 0x88A8 QinQ.
  std::optional<Mac> src_mac{};               // U1.33/U1.34 D15 (L2 primary)
  std::optional<Mac> dst_mac{};               // U1.33/U1.34 D15 (L2 secondary)
  std::optional<std::uint16_t> ethertype{};   // U1.33/U1.34 D8
  // `next_layer` is scope-only at parser tier. Ordering (l2 cannot
  // appear on a layer_3 rule) is the C8 validator's problem.
  std::optional<NextLayer> next_layer{};      // U1.35 F1/D8
};

// -------------------------------------------------------------------------
// Objects pool (C6, D8). Unresolved form — names mapped to primitive
// values. The parser accepts well-formed entries; dangling-reference
// checks from rules into this pool are the validator's job (C7+).
//
// C6 only implements `subnets`: name → list of CIDRs. Each CIDR is a
// sum type of (Cidr4, Cidr6) — mixing v4 and v6 inside one named
// subnet is allowed at the parser tier (the validator enforces whatever
// dual-stack rule semantics we want later). Other object classes
// (mac_groups, port_groups, subnets6 split from subnets, etc.) land
// in follow-up cycles when their consumers exist.

// -------------------------------------------------------------------------
// Sizing struct (C6, D6). Runtime-parameterised capacity ceilings.
// Compile-time constants for dev/prod defaults and the schema-level
// parse helper live in sizing.h — the struct itself lives here so
// that Config can hold it by value without a circular include between
// parser.h and sizing.h.
//
// D6 anchor: no compile-time ceilings; only a compile-time hard
// minimum (sizing.h / kSizingRulesPerLayerHardMin). The fields below
// map 1:1 to the D6 table in review-notes.md.

struct Sizing {
  std::uint32_t rules_per_layer_max{};
  std::uint32_t mac_entries_max{};
  std::uint32_t ipv4_prefixes_max{};
  std::uint32_t ipv6_prefixes_max{};
  std::uint32_t l4_entries_max{};
  std::uint32_t vrf_entries_max{};
  std::uint32_t rate_limit_rules_max{};
  std::uint32_t ethertype_entries_max{};
  std::uint32_t vlan_entries_max{};
  std::uint32_t pcp_entries_max{};
};

using SubnetCidr = std::variant<Cidr4, Cidr6>;

struct SubnetObject {
  std::string name;                    // object key
  std::vector<SubnetCidr> cidrs;       // heterogeneous v4/v6 allowed
};

// M2 C1: named port group — a list of port numbers. The parser stores
// them verbatim; the M2 compiler expands references during rule
// compilation. Validator checks dangling refs (C7+).
struct PortGroupObject {
  std::string name;
  std::vector<std::uint16_t> ports;
};

struct ObjectPool {
  std::vector<SubnetObject> subnets;       // unresolved, order-preserving
  std::vector<PortGroupObject> port_groups; // M2 C1
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
// cmd_socket (C7, D38 schema-only; C7.5 defers resolution).
//
// `allow_gids` is an allow-list of gid values authorised to talk to
// the control-plane Unix-domain socket. The real SO_PEERCRED check
// against this list is M11 hot-plumbing work; M1 only wires the
// schema.
//
// Element type is `::gid_t` (POSIX, unsigned on every Linux libc we
// target). Keeping the native type here — rather than a bare
// `uint32_t` — makes the M11 `getsockopt(SO_PEERCRED → ucred.gid)`
// comparison a direct `==` with no casts, and documents at the type
// level that these are process-credential gids, not arbitrary ints.
//
// Why `std::optional<std::vector<...>>` and not a bare vector: the
// validator must distinguish three input shapes:
//   1. section absent                         → std::nullopt
//   2. section present, no `allow_gids` key    → std::nullopt
//   3. section present with explicit list     → populated vector
//                                                (possibly empty)
// Case 3 with an empty list means "deny all" and is load-bearing —
// collapsing it into "absent" would silently turn a typo'd empty
// list into full-open access.
//
// **Sentinel `std::nullopt` means "resolve at daemon init (M11)".
// Parser and validator never invent a default.** Doing gid
// resolution at parse or validate time breaks offline
// `--validate-config`: an operator running validate as root would
// capture root's gid, and the runtime daemon — after drop-privs to
// the `pktgate` service user — would silently diverge from the
// list that SO_PEERCRED eventually checks. Resolution is a runtime-
// context-dependent concern and belongs at cmd_socket bind time,
// not here.

struct CmdSocket {
  std::optional<std::vector<::gid_t>> allow_gids{};
};

// -------------------------------------------------------------------------
// Top-level config

struct Config {
  int version = 0;
  std::vector<InterfaceRole> interface_roles;
  DefaultBehavior default_behavior = DefaultBehavior::kDrop;
  FragmentPolicy fragment_policy = FragmentPolicy::kL3Only;
  Pipeline pipeline{};
  Sizing sizing{};        // C6/D6 — filled with kSizingDevDefaults on absence
  ObjectPool objects{};   // C6 — unresolved; validator checks references (C7+)
  CmdSocket cmd_socket{}; // C7/D38 — schema-only; validator fills default
};

}  // namespace pktgate::config
