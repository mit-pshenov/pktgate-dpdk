// src/telemetry/prom_encoder.cpp
//
// M10 C0 — impl for prom_encoder.h. Pure string formatting.

#include "src/telemetry/prom_encoder.h"

#include <cassert>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace pktgate::telemetry {

std::string escape_label_value(std::string_view v) {
  std::string out;
  // Reserve for the common case (no escapes): len + a few bytes of
  // slack for rare backslash/quote.
  out.reserve(v.size() + 4);
  for (char c : v) {
    switch (c) {
      case '\\':
        out.push_back('\\');
        out.push_back('\\');
        break;
      case '"':
        out.push_back('\\');
        out.push_back('"');
        break;
      case '\n':
      case '\r':
        // OpenMetrics forbids raw CR/LF; encode both as `\n`.
        out.push_back('\\');
        out.push_back('n');
        break;
      default:
        out.push_back(c);
        break;
    }
  }
  return out;
}

std::string format_labels(std::span<const Label> labels) {
  if (labels.empty()) {
    return std::string{};
  }
  std::string out;
  out.reserve(2 + labels.size() * 16);
  out.push_back('{');
  bool first = true;
  for (const auto& lbl : labels) {
    if (!first) {
      out.push_back(',');
    }
    first = false;
    out.append(lbl.name);
    out.push_back('=');
    out.push_back('"');
    out.append(escape_label_value(lbl.value));
    out.push_back('"');
  }
  out.push_back('}');
  return out;
}

namespace {

// Small uint64 formatter — std::to_string allocates but is simple
// and correct. The hot path never calls this; the 1 Hz snapshot
// publisher can afford the allocation.
std::string u64_to_string(std::uint64_t v) { return std::to_string(v); }
std::string i64_to_string(std::int64_t v) { return std::to_string(v); }

// U10.4 helper: OpenMetrics counter names MUST end in `_total`.
// Asserted in debug; release relies on caller discipline + the
// D33 grep manifest (U7.5) catching names authored elsewhere.
// `[[maybe_unused]]` because under NDEBUG the `assert()` that uses
// it compiles to nothing and -Werror=unused-function would fire.
[[maybe_unused]] bool ends_with_total(std::string_view name) {
  constexpr std::string_view kSuffix = "_total";
  if (name.size() < kSuffix.size()) {
    return false;
  }
  return name.substr(name.size() - kSuffix.size()) == kSuffix;
}

}  // namespace

std::string format_counter(std::string_view name,
                           std::span<const Label> labels,
                           std::uint64_t value) {
  // U10.4: counters MUST end `_total`. Debug-assert; release is
  // caller-contract (D33 grep catches drift at manifest level).
  assert(ends_with_total(name) &&
         "OpenMetrics counter name must end with _total");

  std::string out;
  out.reserve(name.size() + 32);
  out.append(name);
  out.append(format_labels(labels));
  out.push_back(' ');
  out.append(u64_to_string(value));
  out.push_back('\n');
  return out;
}

std::string format_gauge(std::string_view name,
                         std::span<const Label> labels,
                         std::int64_t value) {
  std::string out;
  out.reserve(name.size() + 32);
  out.append(name);
  out.append(format_labels(labels));
  out.push_back(' ');
  out.append(i64_to_string(value));
  out.push_back('\n');
  return out;
}

Label format_rule_id_label(std::uint64_t rule_id) {
  return Label{"rule_id", std::to_string(rule_id)};
}

}  // namespace pktgate::telemetry
