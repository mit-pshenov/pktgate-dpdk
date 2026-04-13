# `stats_on_exit` JSON shape — `main.cpp` phase 9

## Purpose

F2.* functional tests need an observable of per-rule counter state
after the binary exits. M10 will replace this with a Prometheus
scrape endpoint; for M4 C8 we emit a single JSON log line during
phase 9 shutdown, after `rte_eal_mp_wait_lcore()` returns.

## Placement

`src/main.cpp` phase 9, between `rte_eal_mp_wait_lcore()` and
`rte_eth_dev_close()`. The worker has finished and joined, so its
per-lcore counter rows are stable.

## JSON shape

```json
{
  "event": "stats_on_exit",
  "rules": [
    {"rule_id": 101, "layer": "l2", "matched_packets": 42, "drops": 17},
    {"rule_id": 102, "layer": "l2", "matched_packets": 5,  "drops": 0}
  ]
}
```

Only rules with `matched_packets > 0 || drops > 0` are emitted, to
keep the line compact for suites with large rule counts. The
`layer` field is `"l2"` for C8 (L3/L4 rows land in M5-M6 when
those layers are classified).

## Code

```cpp
// ---- Phase 9: shutdown (§6.4) ----
log_json("{\"event\":\"workers_exit\"}");
rte_eal_mp_wait_lcore();

// ---- M4 C8: emit per-rule counter summary for functional tests ----
//
// Aggregates per-lcore RuleCounter rows across all workers. Emits one
// JSON log line with {rule_id, layer, matched_packets, drops}. Only
// non-zero rule entries are included. Real telemetry (M10) replaces
// this with a Prometheus scrape endpoint.
{
  const auto& rs = *ruleset;
  std::string stats_json =
      "{\"event\":\"stats_on_exit\",\"rules\":[";
  bool first_entry = true;

  // L2 rules.
  for (std::uint32_t idx = 0; idx < rs.n_l2_rules; ++idx) {
    if (!rs.l2_actions) break;
    const auto& act = rs.l2_actions[idx];
    const auto slot = static_cast<std::uint32_t>(act.counter_slot);

    // Aggregate across all lcores.
    std::uint64_t total_matched = 0;
    std::uint64_t total_drops   = 0;
    for (std::uint32_t lc = 0; lc < rs.num_lcores; ++lc) {
      const auto* row = rs.counter_row(lc);
      if (!row || slot >= rs.counter_slots_per_lcore) continue;
      total_matched += row[slot].matched_packets;
      total_drops   += row[slot].drops;
    }

    if (total_matched == 0 && total_drops == 0) continue;

    if (!first_entry) stats_json += ',';
    first_entry = false;
    stats_json += "{\"rule_id\":" + std::to_string(act.rule_id)
                + ",\"layer\":\"l2\""
                + ",\"matched_packets\":" + std::to_string(total_matched)
                + ",\"drops\":" + std::to_string(total_drops)
                + "}";
  }

  stats_json += "]}";
  log_json(stats_json);
}
```

## What is deliberately NOT here

- **No `pkt_rx_total` field.** The aborted worker added a
  `std::atomic<u64> pkt_rx_total` to `WorkerCtx` and emitted it
  here as a debug counter, paired with a release-store in the RX
  loop and an acquire-load here. That was scope creep in service
  of silencing a parked TSAN baseline. `stats_on_exit` is for
  per-rule counters only; `pkt_rx_total` is not required for any
  F2.* assertion and is a D1 violation on the hot path.
- **No per-lcore breakdown.** Aggregation across all lcores is
  sufficient for F2.* tests (they assert totals, not
  distribution). Per-lcore split lands in M10 telemetry proper.

## How tests assert on it

```python
# In test_f2_l2.py test helper:
def parse_stats_on_exit(log_lines):
    for line in reversed(log_lines):
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        if evt.get("event") == "stats_on_exit":
            return {r["rule_id"]: r for r in evt["rules"]}
    return {}
```

Assertion pattern:

```python
stats = parse_stats_on_exit(proc.log_lines)
assert stats.get(101, {}).get("matched_packets") == expected_match_count
assert stats.get(102, {}).get("drops") == expected_drop_count
# Rules with zero traffic are absent from the map, not present with zeros.
assert 103 not in stats
```
