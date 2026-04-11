// tests/unit/test_addr.cpp
//
// M1 C3 — CIDR + MAC primitives. Transcribes
// `test-plan-drafts/unit.md` U1.8..U1.13 into real gtest cases against
// `src/config/addr.{h,cpp}`.
//
// The unit under test is pure stdlib: no DPDK, no inet_pton, no POSIX
// network headers. Tests assert parse success / specific error kinds,
// host-bits-zero enforcement, and the D8-anchored "IPv6 embedded-v4
// stays IPv6" rule (U1.11).

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>

#include "src/config/addr.h"

namespace {

using ::pktgate::config::AddrParseError;
using ::pktgate::config::Cidr4;
using ::pktgate::config::Cidr4Result;
using ::pktgate::config::Cidr6;
using ::pktgate::config::Cidr6Result;
using ::pktgate::config::is_ok;
using ::pktgate::config::Mac;
using ::pktgate::config::mac_to_string;
using ::pktgate::config::MacResult;
using ::pktgate::config::parse_cidr4;
using ::pktgate::config::parse_cidr6;
using ::pktgate::config::parse_mac;

// -------------------------------------------------------------------------
// Tiny helpers — extract the success or error alternative. gtest will
// have already asserted the right variant before these run.

const Cidr4& ok4(const Cidr4Result& r) { return std::get<Cidr4>(r); }
const Cidr6& ok6(const Cidr6Result& r) { return std::get<Cidr6>(r); }
const Mac& okmac(const MacResult& r) { return std::get<Mac>(r); }

AddrParseError err4(const Cidr4Result& r) {
  return std::get<AddrParseError>(r);
}
AddrParseError err6(const Cidr6Result& r) {
  return std::get<AddrParseError>(r);
}
AddrParseError errmac(const MacResult& r) {
  return std::get<AddrParseError>(r);
}

// -------------------------------------------------------------------------
// U1.8 — valid IPv4 CIDR.
//
// The three unit.md inputs are `10.0.0.0/8`, `0.0.0.0/0`, `192.168.1.1/32`.
// All three must parse; all three have no host-bit violation (/32 exposes
// every bit; /0 masks everything). addr is host-byte-order.

TEST(AddrU1_8, ValidIPv4CidrParses) {
  const auto r1 = parse_cidr4("10.0.0.0/8");
  ASSERT_TRUE(is_ok(r1)) << "10.0.0.0/8 err=" << static_cast<int>(err4(r1));
  EXPECT_EQ(ok4(r1).addr, 0x0A000000u);
  EXPECT_EQ(ok4(r1).prefix, 8u);

  const auto r2 = parse_cidr4("0.0.0.0/0");
  ASSERT_TRUE(is_ok(r2));
  EXPECT_EQ(ok4(r2).addr, 0u);
  EXPECT_EQ(ok4(r2).prefix, 0u);

  const auto r3 = parse_cidr4("192.168.1.1/32");
  ASSERT_TRUE(is_ok(r3));
  EXPECT_EQ(ok4(r3).addr, 0xC0A80101u);
  EXPECT_EQ(ok4(r3).prefix, 32u);
}

TEST(AddrU1_8, HostBitsNonZeroRejected) {
  // 1.2.3.5/24 — /24 masks the low 8 bits, but bit 0..7 = 5, not 0.
  const auto r = parse_cidr4("1.2.3.5/24");
  ASSERT_FALSE(is_ok(r));
  EXPECT_EQ(err4(r), AddrParseError::kHostBitsNonZero);
}

// -------------------------------------------------------------------------
// U1.9 — invalid IPv4 CIDR rejected.
//
// Each input is a different flavour of malformation: missing slash,
// prefix out of range, non-numeric octet, empty string, trailing garbage.
// Error kind is either kBadFormat (structural) or kPrefixOutOfRange
// (explicit /N with N>32 or /-1) — the test pins the distinction
// because operators reading logs will want to tell the two apart.

TEST(AddrU1_9, InvalidIPv4CidrRejected) {
  // No slash.
  {
    const auto r = parse_cidr4("10.0.0.0");
    ASSERT_FALSE(is_ok(r));
    EXPECT_EQ(err4(r), AddrParseError::kBadFormat);
  }
  // Prefix too large.
  {
    const auto r = parse_cidr4("10.0.0.0/33");
    ASSERT_FALSE(is_ok(r));
    EXPECT_EQ(err4(r), AddrParseError::kPrefixOutOfRange);
  }
  // Negative prefix — /-1 fails at format validation (we don't even
  // parse signed), so structurally it's kBadFormat.
  {
    const auto r = parse_cidr4("10.0.0.0/-1");
    ASSERT_FALSE(is_ok(r));
    EXPECT_EQ(err4(r), AddrParseError::kBadFormat);
  }
  // Non-numeric octet.
  {
    const auto r = parse_cidr4("10.0.x.0/8");
    ASSERT_FALSE(is_ok(r));
    EXPECT_EQ(err4(r), AddrParseError::kBadFormat);
  }
  // Octet out of range (256).
  {
    const auto r = parse_cidr4("256.0.0.0/8");
    ASSERT_FALSE(is_ok(r));
    EXPECT_EQ(err4(r), AddrParseError::kBadFormat);
  }
  // Trailing garbage after prefix.
  {
    const auto r = parse_cidr4("10.0.0.0/8extra");
    ASSERT_FALSE(is_ok(r));
    EXPECT_EQ(err4(r), AddrParseError::kBadFormat);
  }
  // Empty.
  {
    const auto r = parse_cidr4("");
    ASSERT_FALSE(is_ok(r));
    EXPECT_EQ(err4(r), AddrParseError::kBadFormat);
  }
  // Too few octets.
  {
    const auto r = parse_cidr4("10.0.0/8");
    ASSERT_FALSE(is_ok(r));
    EXPECT_EQ(err4(r), AddrParseError::kBadFormat);
  }
}

// -------------------------------------------------------------------------
// U1.10 — valid IPv6 CIDR.
//
// unit.md lists `2001:db8::/32`, `::/0`, `fe80::1/128`. All three parse;
// addresses normalise to 16 bytes in network order. Also adds the
// prefix-too-large rejection explicitly (/129 → kPrefixOutOfRange).

TEST(AddrU1_10, ValidIPv6CidrParses) {
  {
    const auto r = parse_cidr6("2001:db8::/32");
    ASSERT_TRUE(is_ok(r)) << "2001:db8::/32 err="
                          << static_cast<int>(err6(r));
    const auto& c = ok6(r);
    EXPECT_EQ(c.prefix, 32u);
    std::array<std::uint8_t, 16> expect{};
    expect[0] = 0x20;
    expect[1] = 0x01;
    expect[2] = 0x0d;
    expect[3] = 0xb8;
    EXPECT_EQ(c.bytes, expect);
  }
  {
    const auto r = parse_cidr6("::/0");
    ASSERT_TRUE(is_ok(r));
    EXPECT_EQ(ok6(r).prefix, 0u);
    std::array<std::uint8_t, 16> zero{};
    EXPECT_EQ(ok6(r).bytes, zero);
  }
  {
    const auto r = parse_cidr6("fe80::1/128");
    ASSERT_TRUE(is_ok(r));
    const auto& c = ok6(r);
    EXPECT_EQ(c.prefix, 128u);
    EXPECT_EQ(c.bytes[0], 0xfe);
    EXPECT_EQ(c.bytes[1], 0x80);
    EXPECT_EQ(c.bytes[15], 0x01);
    for (std::size_t i = 2; i < 15; ++i) {
      EXPECT_EQ(c.bytes[i], 0u) << "pos " << i;
    }
  }
}

TEST(AddrU1_10, IPv6PrefixOutOfRange) {
  const auto r = parse_cidr6("2001:db8::/129");
  ASSERT_FALSE(is_ok(r));
  EXPECT_EQ(err6(r), AddrParseError::kPrefixOutOfRange);
}

TEST(AddrU1_10, IPv6HostBitsNonZeroRejected) {
  // /32 masks everything past the first 32 bits. 2001:db8:1:: has the
  // bit at position 48 set, which is below /32 → must reject.
  const auto r = parse_cidr6("2001:db8:1::/32");
  ASSERT_FALSE(is_ok(r));
  EXPECT_EQ(err6(r), AddrParseError::kHostBitsNonZero);
}

// -------------------------------------------------------------------------
// U1.11 — IPv6 with embedded IPv4 parses as IPv6, NOT silently demoted
// to Cidr4. This is the "IPv6 embedded-v4 → IPv6" line in the plan.
//
// unit.md uses `::ffff:10.0.0.0/104`: 96 bits of IPv4-mapped prefix
// (0000:...:ffff) + 8 bits of value (10) = 104 set bits. /104 masks
// exactly those and the rest is zero → valid. The assertion pins the
// variant tag (this is a Cidr6Result, the ok alt is Cidr6).

TEST(AddrU1_11, IPv6WithEmbeddedIPv4StaysIPv6) {
  const auto r = parse_cidr6("::ffff:10.0.0.0/104");
  ASSERT_TRUE(is_ok(r)) << "err=" << static_cast<int>(err6(r));

  const Cidr6& c = ok6(r);
  EXPECT_EQ(c.prefix, 104u);

  // First 10 bytes zero.
  for (std::size_t i = 0; i < 10; ++i) {
    EXPECT_EQ(c.bytes[i], 0u) << "pos " << i;
  }
  // Bytes 10..11 must be 0xff 0xff (the IPv4-mapped marker).
  EXPECT_EQ(c.bytes[10], 0xff);
  EXPECT_EQ(c.bytes[11], 0xff);
  // Bytes 12..15 are the embedded IPv4 address 10.0.0.0.
  EXPECT_EQ(c.bytes[12], 10u);
  EXPECT_EQ(c.bytes[13], 0u);
  EXPECT_EQ(c.bytes[14], 0u);
  EXPECT_EQ(c.bytes[15], 0u);
}

// -------------------------------------------------------------------------
// U1.12 — valid MAC, canonicalised.
//
// `aa:bb:cc:dd:ee:ff` parses. The canonical round-trip form is lowercase
// colon-separated. Case-insensitive parse (upper-case input still parses).

TEST(AddrU1_12, ValidMacParses) {
  const auto r = parse_mac("aa:bb:cc:dd:ee:ff");
  ASSERT_TRUE(is_ok(r));
  const std::array<std::uint8_t, 6> expect{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  EXPECT_EQ(okmac(r).bytes, expect);
  EXPECT_EQ(mac_to_string(okmac(r)), "aa:bb:cc:dd:ee:ff");
}

TEST(AddrU1_12, MacCaseInsensitive) {
  const auto r = parse_mac("AA:BB:CC:DD:EE:FF");
  ASSERT_TRUE(is_ok(r));
  const std::array<std::uint8_t, 6> expect{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  EXPECT_EQ(okmac(r).bytes, expect);
  // Round-trip back to lowercase canonical form.
  EXPECT_EQ(mac_to_string(okmac(r)), "aa:bb:cc:dd:ee:ff");
}

// -------------------------------------------------------------------------
// U1.13 — invalid MAC rejected; edge cases.
//
// Rejects: wrong octet count (5, 7), empty, non-hex, wrong separator.
// Positive edge cases: all-zero, all-F broadcast, lowercase/uppercase
// round-trip (see U1.12 above too).

TEST(AddrU1_13, InvalidMacRejected) {
  // 5 octets.
  {
    const auto r = parse_mac("aa:bb:cc:dd:ee");
    ASSERT_FALSE(is_ok(r));
    EXPECT_EQ(errmac(r), AddrParseError::kBadFormat);
  }
  // 7 octets.
  {
    const auto r = parse_mac("aa:bb:cc:dd:ee:ff:00");
    ASSERT_FALSE(is_ok(r));
    EXPECT_EQ(errmac(r), AddrParseError::kBadFormat);
  }
  // Non-hex digit.
  {
    const auto r = parse_mac("zz:bb:cc:dd:ee:ff");
    ASSERT_FALSE(is_ok(r));
    EXPECT_EQ(errmac(r), AddrParseError::kBadHexOctet);
  }
  // Empty.
  {
    const auto r = parse_mac("");
    ASSERT_FALSE(is_ok(r));
    EXPECT_EQ(errmac(r), AddrParseError::kBadFormat);
  }
  // Wrong separator (dash instead of colon).
  {
    const auto r = parse_mac("aa-bb-cc-dd-ee-ff");
    ASSERT_FALSE(is_ok(r));
    EXPECT_EQ(errmac(r), AddrParseError::kBadFormat);
  }
  // Per-octet length wrong (single hex digit instead of two) — total
  // string length is 16, not 17, so this is a structural failure.
  {
    const auto r = parse_mac("a:bb:cc:dd:ee:ff");
    ASSERT_FALSE(is_ok(r));
    EXPECT_EQ(errmac(r), AddrParseError::kBadFormat);
  }
}

TEST(AddrU1_13, MacEdgeCases) {
  // All zeros.
  {
    const auto r = parse_mac("00:00:00:00:00:00");
    ASSERT_TRUE(is_ok(r));
    const std::array<std::uint8_t, 6> expect{};
    EXPECT_EQ(okmac(r).bytes, expect);
    EXPECT_EQ(mac_to_string(okmac(r)), "00:00:00:00:00:00");
  }
  // All Fs (broadcast), uppercase input round-trips to lowercase.
  {
    const auto r = parse_mac("FF:FF:FF:FF:FF:FF");
    ASSERT_TRUE(is_ok(r));
    const std::array<std::uint8_t, 6> expect{0xff, 0xff, 0xff, 0xff,
                                             0xff, 0xff};
    EXPECT_EQ(okmac(r).bytes, expect);
    EXPECT_EQ(mac_to_string(okmac(r)), "ff:ff:ff:ff:ff:ff");
  }
}

}  // namespace
