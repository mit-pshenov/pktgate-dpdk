// src/eal/dynfield.h
//
// M3 C4 — mbuf dynfield registration per §5.1.
//
// The pktgate dynfield is a 16-byte slot registered once at init via
// rte_mbuf_dynfield_register(). The hot path reads/writes it on every
// mbuf to carry classification state through the L2→L3→L4 pipeline.
//
// Design anchors:
//   * §5.1 — dynfield layout
//   * D13  — l3_offset for VLAN-tagged packets
//   * D14  — l4 offset via IHL
//   * D15  — compound primary + filter_mask
//   * D27  — l4_extra for IPv6 fragment differentiation

#pragma once

#include <cstdint>

#include <rte_mbuf.h>

namespace pktgate::eal {

// §5.1 dynfield layout — 16 bytes total, one slot.
struct __rte_aligned(2) PktgateDynfield {
  std::uint16_t verdict_action_idx;   // index into the layer's action arena
  std::uint8_t  verdict_layer;        // TERMINAL_* / NEXT_*
  std::uint8_t  l3_offset;            // D13: byte offset from frame start to L3
  std::uint8_t  parsed_l3_proto;      // cached after L3 parse
  std::uint8_t  flags;                // L4_UNCLASSIFIABLE, SKIP_L4, ...
  std::uint8_t  l4_extra;             // D27: extra bytes to L4 start
  std::uint8_t  _pad;
  std::uint16_t parsed_l4_dport;
  std::uint16_t parsed_l4_sport;
  std::uint16_t parsed_vlan;          // 0xFFFF if untagged
  std::uint16_t parsed_ethertype;     // inner ethertype after VLAN strip
};

static_assert(sizeof(PktgateDynfield) == 16, "dynfield must be 16 bytes");

// Verdict layer values (§5.1).
enum VerdictLayer : std::uint8_t {
  kNextL3          = 0,   // L2 pass → continue to L3
  kNextL4          = 1,   // L3 pass → continue to L4
  kTerminalPass    = 2,   // final: allow
  kTerminalDrop    = 3,   // final: drop
  kTerminalL3      = 4,   // final: L3 match (for fragment handling)
};

// Flags (§5.1).
enum DynfieldFlags : std::uint8_t {
  kSkipL4           = 0x01,  // L3 decided to skip L4
  kL4Unclassifiable = 0x02,  // L4 header not parseable
};

// Register the dynfield slot with EAL. Must be called once after
// rte_eal_init() and before any worker starts. Returns the offset
// within the mbuf where the dynfield is stored, or -1 on failure.
int register_dynfield();

// Get the dynfield offset (set by register_dynfield). Returns -1
// if not yet registered.
int dynfield_offset();

// Access the dynfield on an mbuf. Returns a pointer to the
// PktgateDynfield embedded in the mbuf's dynamic field area.
// UB if register_dynfield() was not called or failed.
inline PktgateDynfield* mbuf_dynfield(struct rte_mbuf* m) {
  return reinterpret_cast<PktgateDynfield*>(
      reinterpret_cast<char*>(m) + dynfield_offset());
}

inline const PktgateDynfield* mbuf_dynfield(const struct rte_mbuf* m) {
  return reinterpret_cast<const PktgateDynfield*>(
      reinterpret_cast<const char*>(m) + dynfield_offset());
}

}  // namespace pktgate::eal
