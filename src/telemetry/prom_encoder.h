// src/telemetry/prom_encoder.h
//
// M10 C0 — Prometheus / OpenMetrics line-format encoder.
//
// Pure stateless string formatting. No HTTP, no IO, no DPDK headers.
// Lives in the DPDK-free control-plane library `pktgate_telemetry`;
// the hot path never links against this TU (see M4 C0 memory
// `grabli_m4c0_dpdk_free_core_library.md`).
//
// API surface (stable for M10 C1+ consumers — snapshot → metrics_endpoint):
//
//   enum class MetricType { Counter, Gauge, Histogram };
//   struct Label { std::string name; std::string value; };
//
//   std::string escape_label_value(std::string_view v);
//     - OpenMetrics label-value escaping: '\\' → '\\\\', '"' → '\\"',
//       literal LF → '\\n' (backslash + 'n', NOT a real newline).
//
//   std::string format_labels(std::span<const Label> labels);
//     - Produces `{k1="v1",k2="v2"}` or "" for empty input.
//     - Label ORDER is caller-chosen (insertion order preserved).
//       Callers that want grep-stable output sort their vector before
//       calling. OpenMetrics itself is ordering-insensitive.
//     - Values are escaped via escape_label_value.
//
//   std::string format_counter(std::string_view name,
//                              std::span<const Label> labels,
//                              std::uint64_t value);
//     - `<name>{labels} <value>\n`. Name MUST end with `_total`
//       (OpenMetrics counter convention). In debug builds the helper
//       asserts via assert(); in release builds the invariant is
//       caller-enforced (unchecked — one branch off the hot path is
//       fine but we pay the check only under NDEBUG-unset; see
//       U10.4).
//
//   std::string format_gauge(std::string_view name,
//                            std::span<const Label> labels,
//                            std::int64_t value);
//     - `<name>{labels} <value>\n`. No suffix convention; gauges
//       carry no `_total`.
//
//   std::string format_rule_id_label(std::uint64_t rule_id);
//     - Helper: produces an already-quoted-and-escaped `rule_id="N"`
//       fragment suitable for dropping into format_labels input as
//       a Label{"rule_id", to_string(rule_id)}. Equivalent to
//       Label{"rule_id", std::to_string(rule_id)} today; exists as
//       a named helper for U7.7 and so M10 C1 snapshot publisher
//       has a single call-site if the format ever changes (e.g.
//       adding a rule namespace prefix).
//
// Histogram deferral (Phase 1 scope trim — errata §M10):
//   `MetricType::Histogram` is part of the enum so that adding a
//   histogram formatter in Phase 2 does not require renaming the
//   type tag. U10.2 (cycles_per_burst histogram formatter) is
//   DROPPED in Phase 1 per trim; no `format_histogram()` declaration
//   exists here. When Phase 2 wires `pktgate_lcore_cycles_per_burst`,
//   add `format_histogram(name, labels, buckets, sum, count)` here
//   and a paired U10.2 test — no existing caller needs to change.
//
// Cardinality note: per-rule labels expand to
//   `pktgate_rule_packets_total{layer="l3",rule_id="2001"} 42`
// times every lcore and every rule. For max_rules=4096 × N lcores ×
// multiple labels, a single scrape can be several MB. No enforcement
// here — operator concern (scrape interval + rule count budget).
//
// D-refs: D3 (telemetry counting/export model), D33 (counter
// consistency invariant — every §10.3 name routes through this
// encoder, so the encoder API must accept any §10.3 name as-is).

#pragma once

#include <cassert>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace pktgate::telemetry {

// M10 C0: encoder type tags. Histogram is declared but no
// `format_histogram()` ships in Phase 1 (errata §M10 trim).
enum class MetricType {
  Counter,
  Gauge,
  Histogram,  // Phase 2 — see header comment above.
};

struct Label {
  std::string name;
  std::string value;
};

// Escape a label value per OpenMetrics text format §2:
//   backslash → `\\`
//   double-quote → `\"`
//   literal LF → `\n`  (two chars: backslash + 'n')
// CR is escaped the same as LF per OpenMetrics (`\n`) — the spec
// forbids raw CR/LF in label values.
std::string escape_label_value(std::string_view v);

// Format the label segment `{k1="v1",k2="v2"}` for a list of labels.
// Returns "" for an empty list (callers concatenate unconditionally).
std::string format_labels(std::span<const Label> labels);

// Format a single counter line, newline-terminated. `name` MUST end
// in `_total` (asserted in debug, caller contract in release).
std::string format_counter(std::string_view name,
                           std::span<const Label> labels,
                           std::uint64_t value);

// Format a single gauge line, newline-terminated. Signed to cover
// negative gauges (e.g. future pending-free depth wraparound if it
// were ever delta-encoded; today pktgate gauges are all >=0).
std::string format_gauge(std::string_view name,
                         std::span<const Label> labels,
                         std::int64_t value);

// Convenience: assemble the `rule_id="N"` label fragment as a
// standalone Label. Exists so M10 C1+ (snapshot publisher) has a
// single canonical construction site for rule-id labels; if the
// namespacing ever changes (e.g. `rule_id="l3:2001"`) we flip it
// here and every producer follows.
Label format_rule_id_label(std::uint64_t rule_id);

}  // namespace pktgate::telemetry
