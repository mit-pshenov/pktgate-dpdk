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
#include <optional>
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
  std::int32_t vlan_id = -1;             // U1.18 range 0..4095, -1 = unset
  std::int32_t pcp = -1;                 // U1.19 range 0..7, -1 = unset
  bool hw_offload_hint = false;          // U1.23 D4
  std::optional<TcpFlags> tcp_flags{};   // U1.30 D15
  std::optional<RuleAction> action{};    // U1.29 D15 exactly-one
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
