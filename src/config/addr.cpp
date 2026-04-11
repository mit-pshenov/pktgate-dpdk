// src/config/addr.cpp — M1 C3 GREEN impl.
//
// Pure-stdlib CIDR and MAC parsers. Deliberately hand-rolled: no
// inet_pton, no <arpa/inet.h>. Rationale — full control over IPv4-
// mapped IPv6 handling (U1.11 requires the result to stay Cidr6, not
// silently demote to Cidr4), portability across libc flavours, and
// the ability to distinguish "bad format" from "prefix out of range"
// and "host bits non-zero" at the error enum level.
//
// Implementation notes:
//   * IPv4: a 4-dotted-octet parser over std::from_chars for the
//     octets and for the prefix. Reject any character other than
//     [0-9] or the expected separators. Range check each octet.
//   * IPv6: a compact "two halves around ::" walker. Splits on the
//     optional double-colon, parses up to 8 16-bit groups on each
//     side, and handles the trailing IPv4-dotted-quad form used by
//     `::ffff:a.b.c.d/N`. No zone IDs (not in unit.md scope).
//   * Host-bits-zero: compute a /N byte mask, AND the bytes after
//     position `prefix/8` with the inverted intra-byte mask, and
//     fail if anything non-zero remains. Identical shape for v4
//     (uint32_t) and v6 (byte array).
//   * MAC: require exactly 17 chars, colons at positions 2,5,8,11,14,
//     and two hex digits in between. Uppercase accepted (U1.12);
//     round-trip form is lowercase (U1.13).

#include "src/config/addr.h"

#include <array>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <system_error>

namespace pktgate::config {

namespace {

// -------- IPv4 octet + prefix parsing ------------------------------------

// Accept only strictly numeric, bounded-length decimal with no sign and
// no leading + — std::from_chars already rejects sign/whitespace, we
// additionally enforce "every char is a digit" to reject `"8extra"`
// sub-tokens (from_chars would stop at `e` and report success on `8`).
bool all_digits(std::string_view s) {
  if (s.empty()) return false;
  for (char c : s) {
    if (c < '0' || c > '9') return false;
  }
  return true;
}

// Parse a decimal integer into a uint32_t; returns false on any issue.
bool parse_u32_strict(std::string_view s, std::uint32_t& out) {
  if (!all_digits(s)) return false;
  // Cap length so we don't silently overflow the parser — any IPv4
  // octet or prefix needs at most 3 digits; leave a little slack.
  if (s.size() > 10) return false;
  std::uint32_t v = 0;
  auto [p, ec] =
      std::from_chars(s.data(), s.data() + s.size(), v, /*base=*/10);
  if (ec != std::errc{} || p != s.data() + s.size()) return false;
  out = v;
  return true;
}

// Parse a CIDR4 "a.b.c.d/N" into address (host byte order) + prefix.
// Returns the variant error directly on failure.
Cidr4Result parse_cidr4_impl(std::string_view text) {
  const auto slash = text.find('/');
  if (slash == std::string_view::npos) return AddrParseError::kBadFormat;

  const auto addr_text = text.substr(0, slash);
  const auto prefix_text = text.substr(slash + 1);

  if (addr_text.empty() || prefix_text.empty())
    return AddrParseError::kBadFormat;

  // Split address into 4 octets on '.' — reject any count != 4.
  std::array<std::uint32_t, 4> octets{};
  std::size_t idx = 0;
  std::size_t start = 0;
  for (std::size_t i = 0; i <= addr_text.size(); ++i) {
    const bool end = (i == addr_text.size());
    if (end || addr_text[i] == '.') {
      if (idx >= 4) return AddrParseError::kBadFormat;
      const auto tok = addr_text.substr(start, i - start);
      std::uint32_t v{};
      if (!parse_u32_strict(tok, v)) return AddrParseError::kBadFormat;
      if (v > 255u) return AddrParseError::kBadFormat;
      octets[idx++] = v;
      start = i + 1;
    }
  }
  if (idx != 4) return AddrParseError::kBadFormat;

  // Prefix: strictly numeric (no sign); /-1 falls out here.
  std::uint32_t prefix_u{};
  if (!parse_u32_strict(prefix_text, prefix_u))
    return AddrParseError::kBadFormat;
  if (prefix_u > 32u) return AddrParseError::kPrefixOutOfRange;

  const std::uint32_t addr = (octets[0] << 24) | (octets[1] << 16) |
                             (octets[2] << 8) | octets[3];

  // Host-bits-zero: mask = all-ones in the top `prefix` bits. For
  // prefix=0, mask=0 and every address must have all 32 host bits
  // zero (only 0.0.0.0 passes). For prefix=32, mask=0xffffffff and
  // nothing is masked off.
  const std::uint32_t mask =
      (prefix_u == 0) ? 0u : (0xffffffffu << (32u - prefix_u));
  if ((addr & ~mask) != 0u) return AddrParseError::kHostBitsNonZero;

  Cidr4 out;
  out.addr = addr;
  out.prefix = static_cast<std::uint8_t>(prefix_u);
  return out;
}

// -------- IPv6 parsing ---------------------------------------------------

bool hex_nibble(char c, std::uint8_t& out) {
  if (c >= '0' && c <= '9') {
    out = static_cast<std::uint8_t>(c - '0');
    return true;
  }
  if (c >= 'a' && c <= 'f') {
    out = static_cast<std::uint8_t>(10 + (c - 'a'));
    return true;
  }
  if (c >= 'A' && c <= 'F') {
    out = static_cast<std::uint8_t>(10 + (c - 'A'));
    return true;
  }
  return false;
}

// Parse one IPv6 16-bit group (hex, 1..4 digits, lowercase or upper).
bool parse_v6_group(std::string_view tok, std::uint16_t& out) {
  if (tok.empty() || tok.size() > 4) return false;
  std::uint16_t v = 0;
  for (char c : tok) {
    std::uint8_t nib{};
    if (!hex_nibble(c, nib)) return false;
    v = static_cast<std::uint16_t>((v << 4) | nib);
  }
  out = v;
  return true;
}

// Parse a dotted-quad IPv4 into 4 bytes. Used for the `::ffff:a.b.c.d`
// tail form. The input must be exactly "a.b.c.d" with 0..255 per
// octet, strictly numeric.
bool parse_dotted_quad(std::string_view s,
                       std::array<std::uint8_t, 4>& out) {
  std::size_t idx = 0;
  std::size_t start = 0;
  for (std::size_t i = 0; i <= s.size(); ++i) {
    const bool end = (i == s.size());
    if (end || s[i] == '.') {
      if (idx >= 4) return false;
      const auto tok = s.substr(start, i - start);
      std::uint32_t v{};
      if (!parse_u32_strict(tok, v)) return false;
      if (v > 255u) return false;
      out[idx++] = static_cast<std::uint8_t>(v);
      start = i + 1;
    }
  }
  return idx == 4;
}

// Parse an IPv6 address body (no prefix) into 16 bytes in network
// byte order. Handles `::` zero-compression and trailing dotted-quad
// IPv4 form. Returns false on any structural issue.
bool parse_v6_body(std::string_view text,
                   std::array<std::uint8_t, 16>& out) {
  // Split on `::`. At most one occurrence is legal.
  const auto dc = text.find("::");
  if (text.find("::", dc == std::string_view::npos ? 0 : dc + 2) !=
      std::string_view::npos) {
    return false;  // two `::` occurrences — illegal
  }

  std::string_view head;
  std::string_view tail;
  bool has_dc = (dc != std::string_view::npos);
  if (has_dc) {
    head = text.substr(0, dc);
    tail = text.substr(dc + 2);
  } else {
    head = text;
    tail = {};
  }

  // A helper that walks a colon-separated sequence of groups. If the
  // last token contains a dot, it is parsed as a dotted-quad IPv4 and
  // expanded into two 16-bit groups (so 6 hex groups + 1 IPv4 = 8).
  auto parse_side =
      [&](std::string_view s,
          std::array<std::uint16_t, 8>& groups, std::size_t& count,
          bool& saw_v4) -> bool {
    count = 0;
    saw_v4 = false;
    if (s.empty()) return true;  // head/tail around `::` can be empty

    std::size_t start = 0;
    for (std::size_t i = 0; i <= s.size(); ++i) {
      const bool end = (i == s.size());
      if (end || s[i] == ':') {
        const auto tok = s.substr(start, i - start);
        if (tok.empty()) return false;  // `a::b` handled above; a single
                                        // `:` inside a side is illegal

        // Detect dotted-quad: only the LAST token may contain a '.'.
        if (tok.find('.') != std::string_view::npos) {
          if (!end) return false;  // IPv4 tail must be the final token
          std::array<std::uint8_t, 4> quad{};
          if (!parse_dotted_quad(tok, quad)) return false;
          if (count + 2 > 8) return false;
          groups[count++] = static_cast<std::uint16_t>(
              (quad[0] << 8) | quad[1]);
          groups[count++] = static_cast<std::uint16_t>(
              (quad[2] << 8) | quad[3]);
          saw_v4 = true;
        } else {
          std::uint16_t v{};
          if (!parse_v6_group(tok, v)) return false;
          if (count >= 8) return false;
          groups[count++] = v;
        }
        start = i + 1;
      }
    }
    return true;
  };

  std::array<std::uint16_t, 8> hg{};
  std::array<std::uint16_t, 8> tg{};
  std::size_t hn = 0;
  std::size_t tn = 0;
  bool hv4 = false;
  bool tv4 = false;
  if (!parse_side(head, hg, hn, hv4)) return false;
  if (!parse_side(tail, tg, tn, tv4)) return false;

  std::array<std::uint16_t, 8> groups{};
  if (has_dc) {
    const std::size_t total = hn + tn;
    if (total > 8) return false;
    // Without `::` we'd need exactly 8 groups. With `::` we need <8.
    if (total == 8 && has_dc) {
      // RFC allows `::` to compress zero groups in theory, but most
      // implementations reject it. We follow the strict reading.
      return false;
    }
    for (std::size_t i = 0; i < hn; ++i) groups[i] = hg[i];
    // Middle is zero-filled by default.
    for (std::size_t i = 0; i < tn; ++i) groups[8 - tn + i] = tg[i];
  } else {
    if (hn != 8) return false;
    groups = hg;
  }

  for (std::size_t i = 0; i < 8; ++i) {
    out[2 * i] = static_cast<std::uint8_t>(groups[i] >> 8);
    out[2 * i + 1] = static_cast<std::uint8_t>(groups[i] & 0xff);
  }
  return true;
}

Cidr6Result parse_cidr6_impl(std::string_view text) {
  const auto slash = text.find('/');
  if (slash == std::string_view::npos) return AddrParseError::kBadFormat;

  const auto addr_text = text.substr(0, slash);
  const auto prefix_text = text.substr(slash + 1);
  if (prefix_text.empty()) return AddrParseError::kBadFormat;

  std::uint32_t prefix_u{};
  if (!parse_u32_strict(prefix_text, prefix_u))
    return AddrParseError::kBadFormat;
  if (prefix_u > 128u) return AddrParseError::kPrefixOutOfRange;

  std::array<std::uint8_t, 16> bytes{};
  if (!parse_v6_body(addr_text, bytes)) return AddrParseError::kBadFormat;

  // Host-bits-zero check over the 16-byte array. `prefix_u` bits from
  // the top must mask, the rest must be zero.
  const std::size_t whole_bytes = prefix_u / 8u;
  const std::size_t intra = prefix_u % 8u;
  if (whole_bytes < 16) {
    if (intra != 0) {
      const std::uint8_t keep_mask =
          static_cast<std::uint8_t>(0xffu << (8u - intra));
      if ((bytes[whole_bytes] & ~keep_mask) != 0) {
        return AddrParseError::kHostBitsNonZero;
      }
      for (std::size_t i = whole_bytes + 1; i < 16; ++i) {
        if (bytes[i] != 0) return AddrParseError::kHostBitsNonZero;
      }
    } else {
      for (std::size_t i = whole_bytes; i < 16; ++i) {
        if (bytes[i] != 0) return AddrParseError::kHostBitsNonZero;
      }
    }
  }

  Cidr6 out;
  out.bytes = bytes;
  out.prefix = static_cast<std::uint8_t>(prefix_u);
  return out;
}

// -------- MAC parsing ----------------------------------------------------

// A valid MAC is exactly 17 chars: 6 pairs of hex separated by colons.
// Any other structure is kBadFormat; bad hex content inside an
// otherwise-structured string is kBadHexOctet (so operators can tell
// "wrong shape" from "typo in one byte" in the log).
MacResult parse_mac_impl(std::string_view text) {
  if (text.size() != 17) return AddrParseError::kBadFormat;
  for (std::size_t i = 0; i < 17; ++i) {
    if (i % 3 == 2) {
      if (text[i] != ':') return AddrParseError::kBadFormat;
    }
  }
  Mac out;
  for (std::size_t byte = 0; byte < 6; ++byte) {
    const char hi = text[byte * 3];
    const char lo = text[byte * 3 + 1];
    std::uint8_t hn{};
    std::uint8_t ln{};
    if (!hex_nibble(hi, hn) || !hex_nibble(lo, ln)) {
      return AddrParseError::kBadHexOctet;
    }
    out.bytes[byte] = static_cast<std::uint8_t>((hn << 4) | ln);
  }
  return out;
}

char to_lower_hex(std::uint8_t nib) {
  return static_cast<char>(nib < 10 ? ('0' + nib) : ('a' + (nib - 10)));
}

}  // namespace

// -------------------------------------------------------------------------
// Public API.

Cidr4Result parse_cidr4(std::string_view text) {
  return parse_cidr4_impl(text);
}

Cidr6Result parse_cidr6(std::string_view text) {
  return parse_cidr6_impl(text);
}

MacResult parse_mac(std::string_view text) { return parse_mac_impl(text); }

std::string mac_to_string(const Mac& mac) {
  std::string out;
  out.reserve(17);
  for (std::size_t i = 0; i < 6; ++i) {
    if (i != 0) out.push_back(':');
    out.push_back(to_lower_hex(static_cast<std::uint8_t>(mac.bytes[i] >> 4)));
    out.push_back(
        to_lower_hex(static_cast<std::uint8_t>(mac.bytes[i] & 0x0f)));
  }
  return out;
}

}  // namespace pktgate::config
