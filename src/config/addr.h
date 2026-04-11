// src/config/addr.h
//
// M1 C3 — CIDR and MAC primitives. Pure-stdlib parse helpers used by
// both the parser (hooked up in C4/C5 via the ParseError enum) and
// later by the validator. Kept deliberately DPDK-free and POSIX-free:
// no <arpa/inet.h>, no inet_pton. Rationale — portability, full control
// over IPv4-mapped IPv6 normalisation (U1.11), and no libc version
// ambiguity around `::ffff:` handling across glibc / musl.
//
// Scope is strictly what U1.8..U1.13 assert:
//   * IPv4 CIDR parse, host-bits-zero enforcement, prefix range 0..32
//   * IPv6 CIDR parse, host-bits-zero enforcement, prefix range 0..128
//   * IPv6 with embedded IPv4 (`::ffff:a.b.c.d/N`) stays Cidr6 — the
//     test (U1.11) explicitly forbids silent demotion to Cidr4.
//   * 6-byte MAC parse, case-insensitive, colon-separated
//
// The error enum is LOCAL to this translation unit's API. The glue into
// the parser-facing `ParseError::kBadCidr` / `kBadMac` codes happens in
// parser.cpp during C4/C5 — not here. This keeps addr.* reusable by the
// validator and by tests without dragging the whole parser surface.

#pragma once

#include <array>
#include <cstdint>
#include <string_view>
#include <variant>

namespace pktgate::config {

// IPv4 CIDR block. `addr` stored in host byte order for ease of masking
// in tests and in validator code; persistence / wire format conversions
// are the caller's problem.
struct Cidr4 {
  std::uint32_t addr{};
  std::uint8_t prefix{};
};

// IPv6 CIDR block. 16 bytes in network byte order (big-endian). A
// `::ffff:10.0.0.0/104` input lands here with bytes[10..11] = {0xff,0xff}
// and bytes[12..15] = {10,0,0,0} — see U1.11.
struct Cidr6 {
  std::array<std::uint8_t, 16> bytes{};
  std::uint8_t prefix{};
};

// 6-byte Ethernet MAC. Canonical textual form is lowercase colon-
// separated; see U1.12 for the round-trip assertion.
struct Mac {
  std::array<std::uint8_t, 6> bytes{};
};

// Reasons a parse helper can reject its input. Ordering is additive
// only — callers (tests, later parser.cpp glue) may key on the integer
// value in log output. Do not renumber.
enum class AddrParseError : std::uint8_t {
  kBadFormat,         // structurally malformed (no slash, bad tokens,
                      // wrong octet count, trailing garbage, empty, ...)
  kPrefixOutOfRange,  // /N with N outside 0..32 (Cidr4) or 0..128 (Cidr6)
  kHostBitsNonZero,   // valid prefix, but bits below /N are not all zero
  kBadHexOctet,       // MAC: non-hex digit or wrong per-octet length
};

using Cidr4Result = std::variant<Cidr4, AddrParseError>;
using Cidr6Result = std::variant<Cidr6, AddrParseError>;
using MacResult = std::variant<Mac, AddrParseError>;

Cidr4Result parse_cidr4(std::string_view text);
Cidr6Result parse_cidr6(std::string_view text);
MacResult parse_mac(std::string_view text);

// Canonical textual form for a MAC: lowercase hex, colon-separated.
// Used by U1.13 for the round-trip assertion.
std::string mac_to_string(const Mac& mac);

inline bool is_ok(const Cidr4Result& r) noexcept {
  return std::holds_alternative<Cidr4>(r);
}
inline bool is_ok(const Cidr6Result& r) noexcept {
  return std::holds_alternative<Cidr6>(r);
}
inline bool is_ok(const MacResult& r) noexcept {
  return std::holds_alternative<Mac>(r);
}

}  // namespace pktgate::config
