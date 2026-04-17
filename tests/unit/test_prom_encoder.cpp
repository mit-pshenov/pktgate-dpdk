// tests/unit/test_prom_encoder.cpp
//
// M10 C0 — unit tests for src/telemetry/prom_encoder.{h,cpp}.
//
// RED → GREEN coverage:
//   * U10.1 Prometheus counter line — exact OpenMetrics string.
//   * U10.3 label escaping — backslash, quote, LF.
//   * U10.4 `_total` suffix convention — debug-mode assertion.
//   * U7.7  rule_id label assembly — helper produces
//           `pktgate_rule_packets_total{layer="l3",rule_id="2001"}`
//           as the exact exposition string.
//
// DEFERRED per Phase 1 scope trim (errata §M10):
//   * U10.2 histogram (cycles_per_burst) — dropped. The encoder API
//     keeps `MetricType::Histogram` in the type-tag enum so that
//     adding a `format_histogram()` in Phase 2 does not require a
//     refactor. See prom_encoder.h header comment for the rationale
//     and the Phase 2 follow-up marker.
//
// Pure C++; no DPDK, no IO, no threads. Runs under dev-asan and
// dev-tsan identically — no races, no sanitizer interaction
// surface. TU links against pktgate_telemetry only (control-plane,
// DPDK-free — memory grabli_m4c0_dpdk_free_core_library.md).

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "src/telemetry/prom_encoder.h"

namespace {

using ::pktgate::telemetry::escape_label_value;
using ::pktgate::telemetry::format_counter;
using ::pktgate::telemetry::format_gauge;
using ::pktgate::telemetry::format_labels;
using ::pktgate::telemetry::format_rule_id_label;
using ::pktgate::telemetry::Label;
using ::pktgate::telemetry::MetricType;

// ---------------------------------------------------------------
// U10.1 — Prometheus counter line.
//
// `format_counter("pktgate_rule_packets_total",
//                 labels={{"layer","l3"},{"rule_id","2001"}},
//                 value=42)`
// → `pktgate_rule_packets_total{layer="l3",rule_id="2001"} 42\n`.
// ---------------------------------------------------------------

TEST(PromEncoder, U10_1_CounterLineExactString) {
  std::vector<Label> labels = {
      {"layer", "l3"},
      {"rule_id", "2001"},
  };
  std::string out =
      format_counter("pktgate_rule_packets_total", labels, 42);
  EXPECT_EQ(out,
            "pktgate_rule_packets_total{layer=\"l3\",rule_id=\"2001\"} 42\n");
}

TEST(PromEncoder, U10_1_CounterLineNoLabels) {
  // §10.3 example `pktgate_watchdog_restarts_total` has no labels.
  std::string out = format_counter("pktgate_watchdog_restarts_total", {}, 7);
  EXPECT_EQ(out, "pktgate_watchdog_restarts_total 7\n");
}

TEST(PromEncoder, U10_1_CounterLineZeroValue) {
  // §10.3 contract: D31/D32/D39/D40 counters must appear in /metrics
  // even when zero. Encoder MUST produce the line unconditionally.
  std::vector<Label> labels = {{"lcore", "0"}};
  std::string out =
      format_counter("pktgate_lcore_qinq_outer_only_total", labels, 0);
  EXPECT_EQ(out, "pktgate_lcore_qinq_outer_only_total{lcore=\"0\"} 0\n");
}

TEST(PromEncoder, U10_1_GaugeLine) {
  // §10.3 has several gauges (pktgate_active_generation,
  // pktgate_reload_pending_free_depth). They do NOT carry `_total`.
  std::string out = format_gauge("pktgate_active_generation", {}, 5);
  EXPECT_EQ(out, "pktgate_active_generation 5\n");
}

TEST(PromEncoder, U10_1_GaugeLineWithLabels) {
  std::vector<Label> labels = {{"layer", "l2"}};
  std::string out = format_gauge("pktgate_active_rules", labels, 12);
  EXPECT_EQ(out, "pktgate_active_rules{layer=\"l2\"} 12\n");
}

// ---------------------------------------------------------------
// U10.3 — label escaping (quotes, backslashes, newline).
//
// OpenMetrics label-value rules:
//   `\\` → `\\\\`   (one backslash becomes two)
//   `"`  → `\\"`    (one quote becomes backslash + quote)
//   LF   → `\\n`    (real newline becomes backslash + 'n')
// ---------------------------------------------------------------

TEST(PromEncoder, U10_3_EscapeBackslash) {
  EXPECT_EQ(escape_label_value("a\\b"), "a\\\\b");
}

TEST(PromEncoder, U10_3_EscapeDoubleQuote) {
  EXPECT_EQ(escape_label_value("a\"b"), "a\\\"b");
}

TEST(PromEncoder, U10_3_EscapeNewline) {
  // Literal LF in the input must come out as backslash + 'n'
  // (two characters), NOT as a real LF.
  std::string escaped = escape_label_value("a\nb");
  ASSERT_EQ(escaped.size(), 4u);
  EXPECT_EQ(escaped[0], 'a');
  EXPECT_EQ(escaped[1], '\\');
  EXPECT_EQ(escaped[2], 'n');
  EXPECT_EQ(escaped[3], 'b');
}

TEST(PromEncoder, U10_3_EscapeCarriageReturn) {
  // CR is forbidden raw; encoder maps it to `\n` (two chars).
  std::string escaped = escape_label_value("a\rb");
  ASSERT_EQ(escaped.size(), 4u);
  EXPECT_EQ(escaped[1], '\\');
  EXPECT_EQ(escaped[2], 'n');
}

TEST(PromEncoder, U10_3_EscapeCombined) {
  // A hostile `site` value exercising all three substitutions.
  std::string in = "si\"te\\name\nwith-ctl";
  std::string out = escape_label_value(in);
  EXPECT_EQ(out, "si\\\"te\\\\name\\nwith-ctl");
}

TEST(PromEncoder, U10_3_EscapePassthroughASCII) {
  // Ordinary ASCII (space, digits, punctuation sans \ and ") is
  // passthrough. No spec requirement to escape `=` or `{` inside
  // a label value.
  std::string in = "pktgate site-01 rack=A1";
  EXPECT_EQ(escape_label_value(in), in);
}

TEST(PromEncoder, U10_3_CounterLineAppliesEscapingToLabels) {
  std::vector<Label> labels = {
      {"site", "s\"1"},
      {"lcore", "0"},
  };
  std::string out = format_counter(
      "pktgate_lcore_packets_total", labels, 100);
  EXPECT_EQ(out,
            "pktgate_lcore_packets_total{site=\"s\\\"1\",lcore=\"0\"} 100\n");
}

// ---------------------------------------------------------------
// U10.4 — `_total` suffix convention.
//
// OpenMetrics counters MUST end in `_total`. The encoder asserts
// this in debug builds (caller contract). The contract itself
// (every §10.3 counter name ends in `_total`) is upstream-enforced
// by U7.5 (D33 grep manifest) — the encoder assert is
// belt-and-suspenders for the happy-path caller.
//
// We can't portably test the assertion fires — `assert` is a
// no-op under NDEBUG and the test binary's build flags vary. What
// we CAN test is that every §10.3 counter that SHOULD pass does
// pass, and that gauge names (no `_total`) work through
// format_gauge without issue. That's the covered contract.
// ---------------------------------------------------------------

TEST(PromEncoder, U10_4_CounterNamesEndingInTotalAccepted) {
  // A sample of §10.3 counter names — each must format without
  // assertion. If any of these stop ending in `_total`, this
  // test stops building + the D33 manifest catches it upstream.
  constexpr const char* kSampleCounterNames[] = {
      "pktgate_rule_packets_total",
      "pktgate_rule_bytes_total",
      "pktgate_rule_drops_total",
      "pktgate_default_action_total",
      "pktgate_port_rx_packets_total",
      "pktgate_lcore_pkt_truncated_total",
      "pktgate_lcore_qinq_outer_only_total",
      "pktgate_lcore_pkt_frag_skipped_total",
      "pktgate_reload_total",
      "pktgate_watchdog_restarts_total",
  };
  for (const char* name : kSampleCounterNames) {
    std::string out = format_counter(name, {}, 0);
    // Sanity: output starts with the name and ends with "\n".
    ASSERT_GE(out.size(), std::string_view(name).size() + 3);
    EXPECT_EQ(out.substr(0, std::string_view(name).size()), name);
    EXPECT_EQ(out.back(), '\n');
    // The name's `_total` suffix is what U10.4 is really asserting
    // at the type level.
    std::string_view name_sv(name);
    EXPECT_TRUE(name_sv.ends_with("_total"))
        << "counter name missing _total suffix: " << name;
  }
}

TEST(PromEncoder, U10_4_GaugeNamesDoNotRequireTotal) {
  // §10.3 gauges: pktgate_port_link_up, pktgate_active_generation,
  // pktgate_reload_pending_free_depth, pktgate_mempool_in_use,
  // pktgate_bypass_active — none end in `_total`. `format_gauge`
  // must accept them without asserting.
  constexpr const char* kSampleGaugeNames[] = {
      "pktgate_port_link_up",
      "pktgate_active_generation",
      "pktgate_reload_pending_free_depth",
      "pktgate_mempool_in_use",
      "pktgate_bypass_active",
      "pktgate_active_rules",
  };
  for (const char* name : kSampleGaugeNames) {
    std::string out = format_gauge(name, {}, 0);
    EXPECT_EQ(out.back(), '\n');
  }
}

// ---------------------------------------------------------------
// U7.7 — rule_id label assembly.
//
// `pktgate_rule_packets_total{layer="l3",rule_id="2001"}` is the
// exact exposition string when the helper format_rule_id_label is
// combined with a `layer` label.
// ---------------------------------------------------------------

TEST(PromEncoder, U7_7_RuleIdLabelHelperShape) {
  Label l = format_rule_id_label(2001);
  EXPECT_EQ(l.name, "rule_id");
  EXPECT_EQ(l.value, "2001");
}

TEST(PromEncoder, U7_7_RuleIdLabelHelperLargeValue) {
  // The rule_id comes from the compiled ruleset — domain-wise a
  // 64-bit unsigned int. Exercise the upper range to confirm the
  // helper uses std::to_string correctly (decimal, no thousands
  // separator, no leading zeros).
  Label l = format_rule_id_label(18'446'744'073'709'551'615ULL);
  EXPECT_EQ(l.value, "18446744073709551615");
}

TEST(PromEncoder, U7_7_AssembledCounterLine) {
  // End-to-end U7.7: combine `layer` + rule_id helper into a full
  // counter line. This is the exact shape M10 C1 snapshot
  // publisher will emit.
  std::vector<Label> labels = {
      {"layer", "l3"},
      format_rule_id_label(2001),
  };
  std::string out =
      format_counter("pktgate_rule_packets_total", labels, 1);
  EXPECT_EQ(out,
            "pktgate_rule_packets_total{layer=\"l3\",rule_id=\"2001\"} 1\n");
}

// ---------------------------------------------------------------
// Type-tag enum — compile-time sanity for MetricType::Histogram
// existing even though no formatter ships in Phase 1.
// ---------------------------------------------------------------

TEST(PromEncoder, HistogramTypeTagRegisteredForPhase2) {
  // This is a degenerate test: its job is to fail the build if
  // MetricType::Histogram ever disappears from the enum — which
  // would signal a refactor that breaks the Phase 2 encoder
  // extension contract. See prom_encoder.h for the rationale.
  constexpr MetricType h = MetricType::Histogram;
  EXPECT_TRUE(h == MetricType::Histogram);
  static_assert(static_cast<int>(MetricType::Counter) !=
                    static_cast<int>(MetricType::Histogram),
                "Counter and Histogram are distinct enum values");
}

// ---------------------------------------------------------------
// format_labels — empty input → empty string (callers concatenate
// unconditionally).
// ---------------------------------------------------------------

TEST(PromEncoder, FormatLabelsEmptyProducesEmpty) {
  EXPECT_EQ(format_labels({}), "");
}

TEST(PromEncoder, FormatLabelsSingleLabel) {
  std::vector<Label> labels = {{"port", "0"}};
  EXPECT_EQ(format_labels(labels), "{port=\"0\"}");
}

TEST(PromEncoder, FormatLabelsPreservesCallerOrder) {
  // The encoder is deterministic and preserves insertion order
  // (documented in prom_encoder.h). Callers that want lex-sorted
  // output sort their input first.
  std::vector<Label> a = {{"z", "1"}, {"a", "2"}};
  std::vector<Label> b = {{"a", "2"}, {"z", "1"}};
  EXPECT_EQ(format_labels(a), "{z=\"1\",a=\"2\"}");
  EXPECT_EQ(format_labels(b), "{a=\"2\",z=\"1\"}");
}

}  // namespace
