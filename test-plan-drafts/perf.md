# Load / performance test plan (draft)

Scope: Part **L** (lab hardware, release gates) + Part **D** (dev VM,
pre-gates). Every test is tagged `[LAB]` or `[DEV]`. Pass criteria are
numeric and anchored to §5.6 cycle budget, §9.3 reload latency table,
§8.4 sizing, and the N1/N2/N3/N5 SLOs from `input.md`.

Authoring anchors:

- N1 40 Gbps bidi sustained, worst case 59.52 Mpps (64 B)
- N2 p99 ≤ 500 µs customer-facing; internal target ≤ 50 µs
- N3 < 0.01 % loss under peak load (< ~5.95 Kpps at worst case)
- N5 cold start ≤ 5 s; hot reload ≤ 100 ms (≤ 250 ms user-visible with debounce)
- §5.6 typ 201 cycles / packet typical, ~280–320 cycles worst realistic;
  400-cycle per-lcore budget at 7.4 Mpps / lcore × 8 lcores

Not in scope: functional correctness (unit-test agent), fault injection
and crash-only (chaos agent), happy-path e2e (functional agent). This
plan only addresses **shape of correctness under load**.

---

## Harness

### Lab harness (for all `[LAB]` tests)

**DUT (pktgate-dpdk)**:
- 2-socket x86-64 server, ≥ 16 physical cores per socket, SMT off on
  dataplane cores
- NICs (one of):
  - Intel E810-CQDA2 2×100 G (ice) — primary lab target
  - Intel XL710-QDA2 2×40 G (i40e) — secondary
  - Mellanox ConnectX-5 Ex 2×100 G (mlx5) — tertiary
- DPDK 25.11.0, hugepages: 4 × 1 GiB on NIC-local socket
- `isolcpus`, `rcu_nocbs`, `nohz_full` on dataplane lcores (§7)
- `pktgate_dpdk` built with `-O3 -march=native`, ASAN/UBSAN OFF

**Generator**: Cisco TRex stateless (`trex-stateless`) ≥ v3.04 on a
second host, identical NIC type to DUT, back-to-back cabled. Two ports
cross-connected through DUT inline. HW timestamping required for p99.9
(not `swq`, not software clocks). TRex profile: symmetric RSS-friendly
traffic (varying 5-tuple), with a stable seed so runs are reproducible.

**Topology**:

```
   TRex port 0 ──── DUT port A (RX)
                    DUT port B (TX) ──── TRex port 1
   TRex port 1 ──── DUT port B (RX)
                    DUT port A (TX) ──── TRex port 0
```

Bidirectional means both directions active simultaneously; unless a
test says "unidirectional" it is 2 × throughput of the one-direction
number.

**Rule sets used across Part L**:
- `baseline.json` — empty pipeline, `default_behavior: allow`
- `single_rule.json` — 1 L2-allow for benign traffic shape
- `r100.json` — 100 rules mixed across L2/L3/L4
- `r1000.json` — 1000 rules mixed across layers
- `prod_max.json` — §8.4 production max: 4096 L2 + 16384 L3-v4 +
  16384 L3-v6 + 4096 L4 + 4096 rl + 4096 VLAN + 4096 MAC
- `rl_one.json` — single rule, `rate-limit` at 1 Gbps
- `rl_many.json` — 16 rate-limit rules at different quotas
- `mirror_light.json`, `redirect_light.json` for §5.5 paths

**Telemetry capture**: scrape `/metrics` every 1 s during the run;
dump `rte_telemetry` every 5 s; sample `rte_eth_stats` on DUT every
1 s; capture TRex `stats` JSON every 1 s. Post-process into pass /
fail verdict plus raw CSV for regression tracking.

**Timestamping methodology for latency**:
- TRex "latency streams" with HW timestamping: 1000 pps latency
  probes interleaved with bulk traffic
- Histogram: capture min/p50/p90/p99/p99.9/max over the run window
- DUT adds wire-to-wire latency; baseline = loopback without DUT
  (TRex → passive coupler → TRex), subtract to isolate DUT overhead

### Dev VM harness (for all `[DEV]` tests)

**VM**: VirtualBox Fedora 43, 4 vCPU, 512 × 2 MiB hugepages, DPDK
25.11. 82545EM is NOT used for these tests — it is irrelevant.

**Microbench binary**: `pktgate_dpdk_ubench` — same compiled
dataplane code (`libpktgate_dp.a`) linked against a minimal driver.

Structure:

```
┌─ EAL init (1 lcore, no NIC) ─────────────────────────┐
│                                                      │
│ ┌── net_null vdev ──┐       ┌── worker lcore ───┐    │
│ │ tx_queue (stub)   │──────▶│ classify + action │    │
│ │ rx_queue (corpus) │       │ measured path     │    │
│ └───────────────────┘       └───────────────────┘    │
│                                                      │
└──────────────────────────────────────────────────────┘
```

- `net_null` vdev, one RX queue pre-populated with an mbuf corpus
  synthesized from a test JSON ("traffic spec"). No NIC, no wire.
- Worker lcore runs the real `worker_main` from `libpktgate_dp.a`
  but with the RX burst stubbed to pull from the corpus ring.
- Timing: `rte_rdtsc()` delta averaged over N ≥ 10⁶ packets, with
  the first 10⁴ discarded as warm-up (cache fill).
- `perf stat` wraps the binary for hardware counters
  (L1-dcache-load-misses, LLC-load-misses, branch-misses, cycles,
  instructions). Runs pinned to a single isolated vCPU.

**Corpus specs** (JSON-defined, compiled to mbuf chains at test
start-up):

- `c_l2_hit_tcp_v4` — TCP/IPv4, L2 compound match
- `c_l2_miss_tcp_v4` — no L2 rule matches, proceeds to L3
- `c_l3_hit_v4`, `c_l3_hit_v6`, `c_l3_miss_v4`
- `c_l4_hit_tcp`, `c_l4_miss_tcp`
- `c_mixed_imix` — classic IMIX 64/576/1500 mix
- `c_rl_sustained` — single flow at constant rate
- `c_rl_idle_burst` — 10 s of silence then full-rate burst (D34)

**Pass criteria baseline**: cycles/packet figures come from
design.md §5.6 "typ" column. A test passes iff measured mean
cycles/packet ≤ (§5.6 typ for the stage path) + **20 %** headroom.
Regression gate (see P-D2): cache / branch counters must not
regress by more than **+15 %** against the committed baseline file
`tests/perf/baseline.json`.

---

## Part L — Lab tests

## P-L1 — Throughput curves [LAB]

Methodology: RFC 2544 zero-loss search per size. Binary search from
`0 Gbps` to `line_rate_Gbps × 1.05`, step until loss ≤ 0.01 %
sustained for 60 s at the candidate rate. Report the max zero-loss
rate per size. Bidirectional unless marked UNI.

### P-L1.1 Baseline no-filter forwarding [LAB]
- Setup: `baseline.json` (empty pipeline, default_behavior=allow),
  no rules, E810 2 × 100 G
- Procedure: RFC 2544 sweep at 64 B, 128 B, 256 B, 512 B, 1024 B,
  1500 B, 9000 B (jumbo), IMIX-classic (64/576/1500 @ 7/4/1),
  IMIX-RFC6985 (64/128/256/512/1024/1518/9022 weighted)
- Pass criterion: 40 Gbps bidi sustained at **every** size
  ≥ 128 B with < 0.01 % loss. 64 B: ≥ 40 Gbps; target 100 G line
  rate on E810 is bonus. Jumbo 9000 B: line rate mandatory.
- Covers: baseline isolation (how much is DPDK forwarding vs filter)
- D/N: N1, N3

### P-L1.2 Single-rule ruleset [LAB]
- Setup: `single_rule.json`, one L2-allow rule
- Procedure: RFC 2544 sweep same sizes as P-L1.1
- Pass criterion: ≤ 2 % throughput delta vs P-L1.1 at every size
- Covers: rule-dispatch overhead (≈ 0)
- D/N: N1, N3, D22

### P-L1.3 100-rule ruleset [LAB]
- Setup: `r100.json`
- Procedure: RFC 2544 sweep
- Pass criterion: 40 Gbps bidi sustained at 64 B with < 0.01 % loss;
  ≤ 5 % throughput delta vs P-L1.1 at every size
- Covers: dispatch + L2/L3/L4 compound lookup cost at small table
- D/N: N1, N3

### P-L1.4 1000-rule ruleset [LAB]
- Setup: `r1000.json`, balanced across layers
- Procedure: RFC 2544 sweep
- Pass criterion: 40 Gbps bidi sustained at 64 B with < 0.01 % loss;
  ≤ 10 % throughput delta vs P-L1.1
- Covers: medium scale
- D/N: N1, N3

### P-L1.5 Production-max ruleset [LAB]
- Setup: `prod_max.json` (all §8.4 prod-column limits)
- Procedure: RFC 2544 sweep
- Pass criterion: 40 Gbps bidi sustained at 64 B with < 0.01 % loss.
  This is the **N1 release gate**.
- Covers: worst-case table scale
- D/N: N1 (release gate), N3, N4, D6, D23

### P-L1.6 Miss-only worst case [LAB]
- Setup: `prod_max.json` but all traffic synthesized to never match
  any rule (drops via `default_behavior: drop` OR proceeds through
  all layers via `default_behavior: allow`; run both)
- Procedure: 64 B unidirectional line rate, 5 min
- Pass criterion: ≥ 40 Gbps per direction at < 0.01 % loss
- Covers: miss-path dispatch cost ≈ L2 miss (95 cy) + L3 miss
  (30 cy) + L4 miss (110 cy) = ~235 cy dispatch; must fit § 5.6
  budget
- D/N: N1, N3, D18

### P-L1.7 Hit-only dispatch-dominant [LAB]
- Setup: `prod_max.json`, traffic shaped so that every packet hits
  a terminal L2 rule (fast path out of the pipeline)
- Procedure: 64 B bidi
- Pass criterion: ≥ line rate 100 G on E810 at 64 B (stretch);
  40 Gbps mandatory
- Covers: dispatch cost lower bound, RuleAction 20 B fast-load (D22)
- D/N: N1, D22

### P-L1.8 Beyond-line-rate resilience [LAB]
- Setup: `r1000.json`, 64 B
- Procedure: offer 110 % of NIC line rate, sustain 5 min
- Pass criterion: (a) no process crash; (b) loss is bounded by
  NIC RX drop counter (NOT by dataplane dispatch); (c) CPU
  utilization stays < 100 % on every dataplane lcore; (d)
  `rx_missed_total` accounts for all extras
- Covers: overload behavior, no pathological collapse
- D/N: N3, D18

### P-L1.9 Jumbo frame sanity [LAB]
- Setup: `r100.json`, 9000 B
- Procedure: line rate unidirectional
- Pass criterion: line rate at < 0.01 % loss, no truncation counter
  (`pkt_truncated_total{where=*}` must stay 0)
- Covers: large-frame classifier path, D31 truncation guards
- D/N: N1, D31

### P-L1.10 IMIX shape equivalence [LAB]
- Setup: `r100.json`
- Procedure: run IMIX-classic and IMIX-RFC6985 for 5 min each
- Pass criterion: verdict distribution (match counts per rule_id)
  identical ± 0.1 % between the two shapes at same rule hit ratio
- Covers: consistency of classification under different burst
  shape
- D/N: F1

---

## P-L2 — Latency percentiles [LAB]

Methodology: TRex latency streams at 1000 pps, HW timestamped.
Subtract wire baseline. Histogram over the whole run.

### P-L2.1 Idle-latency single probe [LAB]
- Setup: `r100.json`, 0.01 % offered load (1 probe / ms)
- Procedure: 5 min
- Pass criterion: p50 < 5 µs, p99 < 15 µs, p99.9 < 25 µs, max
  < 100 µs. (§5.6 typ 201 cy ≈ 67 ns; idle adds queue + TX scheduler
  delay dominated by hardware.)
- Covers: N2 (internal target headroom)
- D/N: N2

### P-L2.2 Latency at 50 % load [LAB]
- Setup: `r100.json`, 50 % of line rate, 512 B
- Procedure: 10 min
- Pass criterion: p50 < 10 µs, p99 < 30 µs, p99.9 < 50 µs
- Covers: N2
- D/N: N2

### P-L2.3 Latency at 80 % load [LAB]
- Setup: `r100.json`, 80 % line rate, 512 B
- Procedure: 10 min
- Pass criterion: p50 < 15 µs, p99 < 50 µs, p99.9 < 100 µs
- Covers: N2
- D/N: N2

### P-L2.4 Latency at 95 % load [LAB]
- Setup: `r100.json`, 95 % line rate, 512 B
- Procedure: 10 min
- Pass criterion: p50 < 25 µs, p99 < 100 µs, **p99.9 ≤ 500 µs**.
  This is the **N2 release gate**.
- Covers: N2 release gate
- D/N: N2 (release gate)

### P-L2.5 Latency under rate-limit [LAB]
- Setup: `rl_one.json` at 1 Gbps rule, offered 40 Gbps of
  matching traffic → most drops
- Procedure: 5 min, 512 B
- Pass criterion: p99.9 of **forwarded** packets ≤ 60 µs (no
  queue buildup from the rl path); dropped packets' latency N/A
- Covers: RL hot path latency discipline
- D/N: N2, D1, D10

### P-L2.6 Worst-case packet-path latency [LAB]
- Setup: `prod_max.json`, 64 B, 90 % line rate
- Procedure: 10 min
- Pass criterion: p99.9 ≤ 400 µs (leaves 100 µs headroom under N2)
- Covers: worst compiled-table + worst size
- D/N: N2, N1

### P-L2.7 Latency under mirror (Phase 2) [LAB]
- Setup: `mirror_light.json`, 50 % of rules mirror, 50 % line rate
- Procedure: 10 min
- Pass criterion: p99.9 of **primary** path ≤ 80 µs (§5.6 mirror
  adds ~30 cy amortized; latency impact is TX queue contention)
- Covers: D7 mirror budget
- D/N: N2, D7

---

## P-L3 — RSS / multi-queue scaling [LAB]

### P-L3.1 Symmetric Toeplitz flow pinning [LAB]
- Setup: `single_rule.json`, `r1000.json`, 8 workers, symmetric
  Toeplitz key (0x6D5A…) as specified in §7
- Procedure: TRex generates 1000 TCP flows, each with A→B and B→A
  directions. For each flow, scrape `per_lcore_rx_packets` and
  verify both directions hashed to the same lcore.
- Pass criterion: **100 %** of flows land on the same lcore in both
  directions. Any asymmetric hashing fails the test.
- Covers: §7 symmetric RSS invariant, D1/D10 rl per-lcore
  correctness prerequisite
- D/N: D1, D10

### P-L3.2 Per-lcore load balance [LAB]
- Setup: `baseline.json`, 8 workers, 10⁶ distinct flows, 64 B
- Procedure: 60 s run, collect per-lcore packet counters
- Pass criterion: max/min per-lcore pps ratio ≤ 1.25 (RSS Toeplitz
  distributes within 20 % on E810/mlx5)
- Covers: D1 Variant A rate-split assumption (≤ 20 % skew)
- D/N: D1

### P-L3.3 Lcore scaling 1→2→4→8→16 [LAB]
- Setup: `r100.json`, 64 B, bidi
- Procedure: boot with `--lcores 1`, measure max zero-loss rate.
  Repeat for 2, 4, 8, 16 workers. Plot Mpps vs lcores.
- Pass criterion: linear scaling within 15 % up to 8 workers; ≥
  80 % of ideal at 16 workers. No regression (adding a worker
  must not reduce throughput).
- Covers: scalability
- D/N: N1

### P-L3.4 Per-lcore counter NUMA locality [LAB]
- Setup: `r1000.json`, 2-socket server, workers pinned split
  across sockets
- Procedure: 5 min line rate
- Pass criterion: `perf stat -e node-load-misses` shows < 5 %
  cross-socket traffic from the dataplane lcores
- Covers: D23 NUMA awareness
- D/N: D23

---

## P-L4 — Rule-count scaling [LAB]

### P-L4.1 L2 compound scaling [LAB]
- Setup: vary L2 rule count {1, 16, 256, 1024, 4096} with L3/L4
  empty, 64 B uniform traffic hitting a middle-index rule
- Procedure: for each, measure max zero-loss throughput
- Pass criterion: throughput at 4096 L2 rules ≥ 95 % of throughput
  at 1 rule (compound primary hash is O(1))
- Covers: L2 classifier scaling
- D/N: N1, N4

### P-L4.2 L3 FIB scaling [LAB]
- Setup: vary v4 prefixes {1, 1024, 16384} using `rte_fib`
  DIR-24-8, traffic uniformly hits random prefixes
- Procedure: measure max zero-loss throughput
- Pass criterion: ≥ 95 % of baseline at 16384 prefixes (FIB is
  O(1) in the hot path)
- Covers: L3 scaling
- D/N: N1, N4

### P-L4.3 L4 compound scaling [LAB]
- Setup: vary L4 entries {1, 256, 4096} with balanced proto/port
- Procedure: max zero-loss throughput
- Pass criterion: ≥ 90 % of baseline at 4096 entries
- Covers: L4 scaling (compound-primary + filter_mask, D15)
- D/N: N1, N4

### P-L4.4 Worst-case all-miss, max table [LAB]
- Setup: `prod_max.json`, traffic synthesized to always miss
- Procedure: 64 B bidi, 5 min
- Pass criterion: 40 Gbps sustained at < 0.01 % loss
- Covers: miss-path worst case
- D/N: N1, N3, D18

### P-L4.5 Worst-case all-hit-last-rule [LAB]
- Setup: `prod_max.json`, every packet matches the last L4 rule
  (first-match-wins walks nothing, but hash lookup is O(1)). If
  the classifier is O(1) this should be identical to first-rule;
  if a bug reintroduces linearity this test fails.
- Procedure: 64 B bidi, 5 min
- Pass criterion: max-zero-loss rate within 2 % of P-L4.3@4096
- Covers: O(1) guarantee
- D/N: N1, N4

---

## P-L5 — Rate-limit under load [LAB]

### P-L5.1 Single RL rule at 1 Gbps [LAB]
- Setup: `rl_one.json` — 1 rule, `rate-limit: 1 Gbps`, all traffic
  matches; offered load 10 Gbps at 512 B
- Procedure: 5 min, sample TX rate every 1 s
- Pass criterion: output rate 1 Gbps ± 20 % (D1 documented
  RSS-skew tolerance). `rl_dropped_total` accounts for the rest.
- Covers: D1 per-lcore bucket, rate accuracy
- D/N: D1, D10

### P-L5.2 Multi-RL no cross-rule leakage [LAB]
- Setup: `rl_many.json` — 16 rules, quotas 100 Mbps / 500 Mbps /
  1 Gbps / 5 Gbps × 4 each; traffic partitioned into 16 classes
  proportional to quotas
- Procedure: offered total = 40 Gbps, sustain 10 min
- Pass criterion: each class's output rate is within ±20 % of
  its quota; zero cross-rule leakage (counter consistency per
  D33: `rl_pass_total{rule_id=i}` + `rl_drop_total{rule_id=i}` =
  `match_total{rule_id=i}` for every rule)
- Covers: D1, D33 counter invariant
- D/N: D1, D33

### P-L5.3 D34 idle-clamp regression [LAB]
- Setup: `rl_one.json` at 1 Gbps
- Procedure: run at 1 Gbps matching traffic for 30 s, STOP
  traffic for 12 s, resume at 40 Gbps burst, measure first-burst
  forwarded volume
- Pass criterion: first-second output ≤ `rate × 1 s × 1.2` =
  1.2 Gbps. Overflow into burst ≤ `burst_bytes` configured value
  (~10 ms × 1 Gbps = 1.25 MB). If clamp is missing, first-second
  output spikes to line rate briefly → test fails.
- Covers: D34 refill clamp
- D/N: D34

### P-L5.4 RL under worst-case dispatch [LAB]
- Setup: `prod_max.json` + 100 rate-limit rules mixed in
- Procedure: 40 Gbps at 64 B, 10 min
- Pass criterion: throughput ≥ 40 Gbps, loss < 0.01 %, rl action
  dispatch ≤ §5.6 "rate-limit 25 cy typ" + 20 %
- Covers: D1/D10 at full scale
- D/N: D1, N1

---

## P-L6 — Hot reload under load [LAB]

### P-L6.1 Continuous reload every 1 s [LAB]
- Setup: `r100.json` initial, 40 Gbps bidi IMIX, control-plane
  rewrites the file every 1 s for 10 min (alternating between two
  configs that differ by a single rule parameter)
- Procedure: run, scrape `reload_total`, `rcu_check_timeout_total`,
  `pending_free_depth`, `rx_dropped_total`, latency probes
- Pass criterion:
  - (a) zero `rx_dropped_total` increment attributable to reload
    (spikes bounded by NIC-level RX drops, not dataplane)
  - (b) latency p99.9 ≤ 500 µs throughout (no spikes correlated
    with reload events)
  - (c) `rcu_check_timeout_total` < 5 in 600 reloads
  - (d) `pending_free_depth` stabilizes at 0 between reloads
- Covers: D9/D12/D30/D35 reload correctness under load
- D/N: N5, D9, D12, D30, D35, D36

### P-L6.2 Reload storm via cmd_socket [LAB]
- Setup: `r100.json`, 20 Gbps bidi
- Procedure: send 100 `reload` commands to UDS in 1 s, then stop;
  verify behavior
- Pass criterion:
  - All 100 reloads serialize under `reload_mutex` (D35)
  - `reload_total` increments by 100
  - No drops attributable to reload, no latency spike > 200 µs
- Covers: D35 single mutex, UDS entry path
- D/N: D35, D38

### P-L6.3 Reload with hostile config (D37 gate) [LAB]
- Setup: `r100.json` active, 40 Gbps traffic
- Procedure: push a config containing a rule with `dst_port:
  [0-65535]` that expands to 65 k entries (exceeds per-rule ceiling
  of 4096)
- Pass criterion:
  - Validator rejects within ≤ 10 ms (D37 pre-flight is pure
    arithmetic)
  - `reload_total{result=validate_err}` increments by 1
  - Active ruleset unchanged, dataplane latency and throughput
    unaffected (p99.9 ≤ 500 µs during the reject window)
- Covers: D37 memory-budget pre-flight
- D/N: D37, N5 (failure path)

### P-L6.4 Reload budget at prod-max [LAB]
- Setup: active `r100.json`, new config `prod_max.json`
- Procedure: single reload, measure timestamps from inotify event
  to `g_active` swap to rcu_check completion
- Pass criterion: end-to-end reload latency ≤ 100 ms measured from
  trigger (N5) — matches §9.3 table (compile < 10 ms,
  ruleset_build 10–50 ms, rcu_check < 1 ms typical)
- Covers: N5, §9.3
- D/N: N5

### P-L6.5 Reload timeout / pending_free path [LAB]
- Setup: inject a test hook to hang one worker for 1 s
  (pre-arranged `rte_pause()` loop triggered via control channel
  — NOT `SIGSTOP`, we need the worker to own its lcore but not
  advance quiescent state)
- Procedure: trigger a reload; watch `rcu_check_timeout_total`,
  `pending_free_depth`, `pending_free_drained_total`
- Pass criterion:
  - `rcu_check` times out after configured 500 ms
  - Old ruleset is queued onto `pending_free`, NOT freed inline
  - After worker resumes, `pending_free` drains on next reload
  - No UAF, no double-free (ASAN-checked in the post-run build)
- Covers: D30 + D36 reload-timeout path
- D/N: D30, D36

---

## P-L7 — 24 h soak [LAB]

### P-L7.1 Steady-state soak [LAB]
- Setup: `r1000.json`, 40 Gbps bidi IMIX-classic, reload every
  60 s (cycle between two configs), telemetry scrape every 15 s,
  sFlow sampling at 1/10 000 (Phase 2 only; Phase 1 = Prometheus
  only)
- Procedure: run for 24 h
- Pass criterion:
  - `rx_dropped_total` growth < 5 Kpps/s sustained average
    (matches < 0.01 % loss)
  - p99.9 latency over every 10-min window ≤ 500 µs
  - Hugepage in-use flat after warm-up ± 64 KiB
  - `mbuf_in_use_total` flat ± BURST × n_ports × n_workers
    envelope (no leak)
  - `rl_arena_slots_live` stable (never grows)
  - `reload_pending_free_depth` returns to 0 after every reload
    within 60 s
  - No counter decreases (monotonic invariant per D33)
  - No `watchdog_restart_total` increments
- Covers: soak stability, leak detection, monotonicity
- D/N: N1, N2, N3, D33

### P-L7.2 Verdict-distribution invariant under load [LAB]
- Setup: `r1000.json`, exact same TRex profile as a prior short
  low-rate correctness run (e.g. the functional agent's reference
  run)
- Procedure: run 1 h at 40 Gbps, compare `rule_hit_total{rule_id=i}`
  proportions against the reference
- Pass criterion: per-rule hit proportion differs from low-rate
  reference by ≤ 0.01 % absolute for every rule_id
- Covers: "shape of correctness under load" — same ruleset +
  same traffic ⇒ same verdicts, regardless of rate
- D/N: F1, N1

---

## P-L8 — Hardware offload path (D4) [LAB, Phase 2+]

### P-L8.1 FDIR_ID fast-path activation [LAB]
- Setup: `prod_max.json` with 100 rules marked `hw_tier`, E810
  with `rte_flow` hw offload enabled
- Procedure: generate traffic matching hw-tier rules; watch DUT
  counter `dispatch_preclassified_total` vs `sw_compound_hit_total`
- Pass criterion:
  - `dispatch_preclassified_total` ≥ 99 % of matched packets for
    hw-tier rules
  - `sw_compound_hit_total` for those rule_ids stays ≈ 0
  - No duplicate accounting (verdict counted once, D33)
- Covers: D4 hw offload dispatch
- D/N: D4

### P-L8.2 SW/HW dual-path correctness under load [LAB]
- Setup: install the **same** rule in both sw and hw tiers, drive
  matching traffic at 40 Gbps
- Procedure: 5 min
- Pass criterion: `rule_hit_total` matches sw-only run ± 0 packets;
  no mbuf path difference detectable
- Covers: D4 correctness
- D/N: D4

### P-L8.3 HW offload install/teardown under reload [LAB]
- Setup: reload stream swapping 50 hw-tier rules each time
- Procedure: 1 reload/s for 5 min under 40 Gbps load
- Pass criterion: `rte_flow_create`/`rte_flow_destroy` errors = 0;
  no drops; p99.9 ≤ 500 µs (hw programming is out of hot path)
- Covers: D4 publish path, §9.5
- D/N: D4

---

## P-L9 — Redirect path [LAB]

### P-L9.1 Redirect at line rate [LAB]
- Setup: `redirect_light.json` with 1 rule redirecting ~50 % of
  traffic to a separate port (C); topology: DUT has ports A/B/C
- Procedure: 40 Gbps bidi between A↔B, of which 50 % is
  redirected to C
- Pass criterion:
  - C receives ~20 Gbps / direction matching the redirect rule
  - `redirect_dropped_total` = 0 (C is not saturated)
  - p99.9 latency on primary path ≤ 500 µs
  - p99.9 latency on redirect path ≤ 500 µs
- Covers: D16 redirect + staging
- D/N: D16

### P-L9.2 Redirect burst-end flush [LAB]
- Setup: same, but offered load = 1 Gbps (small bursts)
- Procedure: 5 min; watch that each TRex latency probe on the
  redirect path arrives within one BURST_SIZE window (not held
  over into the next burst)
- Pass criterion: p99 redirect latency ≤ 15 µs (would be ≥ 30 µs
  if flush was missing and probes held across bursts)
- Covers: D16 burst-end flush
- D/N: D16

### P-L9.3 Redirect TX saturation [LAB]
- Setup: `redirect_light.json` with 100 % of traffic redirected
  to a 10 G port while 40 G is offered
- Procedure: 2 min
- Pass criterion: `redirect_dropped_total` increments account for
  exactly the over-subscription; primary path stays healthy
  (no back-pressure into A↔B); dataplane does not crash or leak
- Covers: D16 TX-full handling
- D/N: D16

---

## P-L10 — TX-queue symmetry (D28) [LAB]

### P-L10.1 Port bring-up invariant [LAB]
- Setup: any ruleset, 8 workers
- Procedure: at init, enumerate `rte_eth_dev_info.nb_tx_queues`
  for every registered port (primary, mirror, redirect)
- Pass criterion: every port has exactly `n_workers` TX queues;
  bring-up fails hard if any port reports fewer (D28 invariant)
- Covers: D28
- D/N: D28

### P-L10.2 Worker-fault TX non-stall [LAB]
- Setup: `r100.json`, 8 workers, 40 Gbps
- Procedure: inject test hook to pause worker #3 for 500 ms;
  observe TX queue depth on its dedicated TX lane vs other lanes
- Pass criterion: other lanes' TX pps unchanged; only worker #3's
  RX ring grows then drops (RX losses count against its ring,
  not TX); no cross-contamination
- Covers: D28 (per-worker TX lanes don't share bottlenecks)
- D/N: D28

---

## P-L11 — Mirror path (Phase 2) [LAB]

### P-L11.1 Line-rate mirror fidelity [LAB]
- Setup: `mirror_light.json`, 1 mirror rule at 50 % of traffic,
  40 Gbps offered
- Procedure: 10 min; capture mirror port output via TRex port 2
- Pass criterion: mirror output packet count ≥ 99.99 % of
  `mirror_match_total` (< 0.01 % mirror-side loss tolerated)
- Covers: D7 mirror correctness under load
- D/N: D7

### P-L11.2 Mirror cycle budget [LAB]
- Setup: `mirror_light.json` with 100 % of traffic mirrored
- Procedure: 40 Gbps 512 B, 5 min; capture cycles/pkt via
  `per_lcore_cycles_per_burst` telemetry
- Pass criterion: cycles/pkt increase over non-mirror baseline
  ≤ `mirror_stage` §5.6 target + 20 %
- Covers: D7 budget
- D/N: D7, D18

### P-L11.3 Mirror refcount zero-copy gate (D26) [LAB]
- Setup: only runs when `MUTATING_VERBS=0` and build macro
  enables refcnt path; mirror at 100 %
- Procedure: ASAN-only run at 10 Gbps for 5 min
- Pass criterion: no mbuf use-after-free, refcount counter
  conserved across mirror + primary TX
- Covers: D26
- D/N: D26, D7

---

## Part D — Dev VM tests

## P-D1 — Cycle-budget microbench [DEV]

All these run against `libpktgate_dp.a` via `pktgate_dpdk_ubench`
on `net_null`. Pass criterion anchor: §5.6 "typ" column + 20 %.

### P-D1.1 RX burst amortized [DEV]
- Setup: corpus `c_l2_hit_tcp_v4`, BURST=32
- Procedure: 10⁶ packets, measure cycles from `rte_eth_rx_burst`
  entry to first packet classify
- Pass criterion: ≤ 18 cy (§5.6 typ 15 + 20 %)
- Covers: §5.6 row "RX burst amortized"
- D/N: D18, N2 (indirectly)

### P-D1.2 L2 parse cost [DEV]
- Setup: `c_l2_hit_tcp_v4`, 1-rule L2-only ruleset
- Procedure: measure cycles inside `classify_l2` excluding the
  primary hash lookup (use `__builtin_readcyclecounter` brackets)
- Pass criterion: ≤ 24 cy (§5.6 typ 20 + 20 %)
- Covers: §5.6 L2 parse
- D/N: D18

### P-D1.3 L2 compound hit [DEV]
- Setup: `c_l2_hit_tcp_v4`, 1-rule ruleset, rule matches
- Procedure: measure full `classify_l2`
- Pass criterion: ≤ 48 cy (§5.6 typ 20+20=40 + 20 %) — parse +
  1 primary hit
- Covers: §5.6 L2 hit
- D/N: D18

### P-D1.4 L2 miss worst case [DEV]
- Setup: `c_l2_miss_tcp_v4`, 100-rule L2 with all 4 primaries
  populated
- Procedure: measure full `classify_l2`
- Pass criterion: ≤ 114 cy (§5.6 typ 95 + 20 %)
- Covers: §5.6 L2 miss
- D/N: D18

### P-D1.5 L2 scaling microbench [DEV]
- Setup: vary L2 rule count {1, 16, 256, 1024}
- Procedure: 10⁶ packets each
- Pass criterion: mean cycles/pkt(1) ≤ mean cycles/pkt(1024)
  + 10 cy (compound hash is flat)
- Covers: O(1) L2 compound
- D/N: D18, N4

### P-D1.6 L3 IPv4 FIB hit [DEV]
- Setup: `c_l3_hit_v4`, 1024-prefix rte_fib
- Procedure: measure `classify_l3`
- Pass criterion: ≤ 42 cy (§5.6 typ 5 parse + 30 fib = 35 + 20 %)
- Covers: §5.6 L3 FIB lookup
- D/N: D18

### P-D1.7 L3 IPv4 FIB miss [DEV]
- Setup: same but traffic never matches
- Procedure: same
- Pass criterion: ≤ 42 cy
- Covers: §5.6 L3 miss (same budget as hit in DIR-24-8)
- D/N: D18

### P-D1.8 L3 IPv4 with IHL + VLAN [DEV]
- Setup: `c_l3_hit_v4` with VLAN-tagged frames (D13 path)
- Procedure: measure `classify_l3`, verify `l3_offset` dynfield
- Pass criterion: ≤ 48 cy (+5 cy over P-D1.6 for VLAN adjust)
- Covers: D13 VLAN L3 offset
- D/N: D13, D18

### P-D1.9 L3 IPv6 FIB hit [DEV]
- Setup: `c_l3_hit_v6`, 1024-prefix rte_fib6
- Procedure: measure `classify_l3`
- Pass criterion: ≤ 54 cy (+ ~10 cy over v4 for rte_fib6)
- Covers: §5.6 L3 IPv6
- D/N: D18, D20

### P-D1.10 L4 parse (IHL) [DEV]
- Setup: `c_l4_hit_tcp`
- Procedure: measure `classify_l4` parse phase
- Pass criterion: ≤ 12 cy (§5.6 typ 8 + 20 %) — D14 IHL respected
- Covers: D14, §5.6 L4 parse
- D/N: D14, D18

### P-D1.11 L4 compound hit [DEV]
- Setup: `c_l4_hit_tcp`, 1-rule L4
- Procedure: measure full `classify_l4`
- Pass criterion: ≤ 66 cy (§5.6 typ 55 + 20 %)
- Covers: §5.6 L4 hit, D15 compound + filter_mask
- D/N: D15, D18

### P-D1.12 L4 miss worst case [DEV]
- Setup: `c_l4_miss_tcp`, 3 primaries populated
- Procedure: measure full `classify_l4`
- Pass criterion: ≤ 132 cy (§5.6 typ 110 + 20 %)
- Covers: §5.6 L4 miss
- D/N: D15, D18

### P-D1.13 Action dispatch allow [DEV]
- Setup: `c_l2_hit_tcp_v4`, rule action allow
- Procedure: measure `apply_action`
- Pass criterion: ≤ 12 cy (§5.6 typ 10 + 20 %)
- Covers: §5.6 allow dispatch
- D/N: D18, D22

### P-D1.14 Action dispatch rate-limit [DEV]
- Setup: `rl_one.json`, corpus with all packets matching
- Procedure: measure `apply_action` through RL path
- Pass criterion: ≤ 30 cy (§5.6 typ 25 + 20 %)
- Covers: §5.6 RL dispatch
- D/N: D1, D10, D18

### P-D1.15 Counter update cost [DEV]
- Setup: any corpus, count per-layer counter bump
- Procedure: measure counter-update region
- Pass criterion: ≤ 8 cy (§5.6 typ 6 + 20 %)
- Covers: §5.6 counter update
- D/N: D3, D18

### P-D1.16 End-to-end realistic typ [DEV]
- Setup: `c_mixed_imix`, `r100.json`
- Procedure: full `worker_main` pass, measure cycles/pkt
- Pass criterion: mean ≤ 241 cy (§5.6 typ realistic 201 + 20 %)
- Covers: §5.6 realistic-typical headline
- D/N: D18, N2

### P-D1.17 End-to-end worst realistic [DEV]
- Setup: `prod_max.json`, corpus forcing L4-miss + rate-limit +
  counter update + tag rewrite
- Procedure: full `worker_main` pass
- Pass criterion: mean ≤ 384 cy (§5.6 worst 320 + 20 %)
- Covers: §5.6 worst realistic
- D/N: D18, N2

---

## P-D2 — Cache / branch microarchitecture [DEV]

### P-D2.1 Baseline cache-miss rate [DEV]
- Setup: `r100.json`, `c_mixed_imix`, via `perf stat -e
  L1-dcache-load-misses,L1-dcache-loads,LLC-load-misses,LLC-loads,
  branch-misses,branches`
- Procedure: 10⁷ packets
- Pass criterion: record baseline into `tests/perf/baseline.json`.
  On subsequent runs:
  - L1d miss rate regression < 15 %
  - LLC miss rate regression < 15 %
  - Branch miss rate regression < 15 %
- Covers: regression gate
- D/N: D18

### P-D2.2 Counter hot-line regression [DEV]
- Setup: `r1000.json` with tight counter hit distribution
- Procedure: `perf c2c` for false-sharing detection on
  `PerLcoreCounters`
- Pass criterion: zero HITM events on counter cache lines
  (per-lcore, NUMA-local → no cross-core sharing)
- Covers: D3 per-lcore counter isolation
- D/N: D3

### P-D2.3 RuleAction cache efficiency [DEV]
- Setup: `c_l2_hit_tcp_v4`, action arena of 4096 entries
- Procedure: `perf stat -e cache-references,cache-misses` in
  `apply_action`
- Pass criterion: cache-miss rate on action loads < 5 % (D22:
  20 B + alignas(4) packs 3 entries per cache line)
- Covers: D22 sizing
- D/N: D22

### P-D2.4 L2 compound primary hash c2c [DEV]
- Setup: `r1000.json`
- Procedure: `perf c2c`
- Pass criterion: zero HITM on Ruleset immutable data (RCU +
  read-only => no write sharing)
- Covers: D9/D23 NUMA / read-only
- D/N: D9, D23

---

## P-D3 — rl_arena hot-path microbench [DEV]

### P-D3.1 RL vs allow cost delta [DEV]
- Setup: two corpora, same shape, one goes through allow, one
  through rate-limit at a quota that doesn't drop
- Procedure: measure cycles/pkt delta
- Pass criterion: delta ≤ 18 cy (rate-limit 25 − allow 10 = 15 +
  20 % slop)
- Covers: D1 per-lcore bucket no-atomics cost
- D/N: D1

### P-D3.2 D34 clamp microbench [DEV]
- Setup: corpus `c_rl_idle_burst` (10 s silence → burst)
- Procedure: measure first-packet cycles/pkt after resume
- Pass criterion: first-packet cycles/pkt ≤ 50 cy (within RL
  hot-path + branch for clamp). If clamp missing, divide
  overflow → observable as cycle spike or garbage `b.tokens`
  (test also asserts `b.tokens ≤ burst_bytes`).
- Covers: D34 clamp
- D/N: D34

### P-D3.3 RL false-sharing check [DEV]
- Setup: `rl_many.json` (16 rules), corpus spreads across rules,
  single-lcore run
- Procedure: `perf c2c` on `TokenBucket[RTE_MAX_LCORE]` arrays
- Pass criterion: zero HITM between buckets (alignas(64)
  cache-line isolation)
- Covers: D1 cache-line isolation
- D/N: D1

### P-D3.4 RL arena slot lifecycle [DEV]
- Setup: build → reload → build → reload cycle, tracking
  `slot_live` per rule
- Procedure: 1000 reload cycles via test hook
- Pass criterion:
  - `slot_live` flat after N reloads (no leak)
  - D24 slot lifecycle: freed slots, not freed rows
  - `rl_arena_slot_reuse_total` > 0 (slots actually recycled)
- Covers: D11, D24
- D/N: D11, D24

---

## P-D4 — Reload latency budget microbench [DEV]

### P-D4.1 Reload latency 1 rule [DEV]
- Setup: 1-rule config
- Procedure: measure `compile → ruleset_build → exchange →
  rcu_check → drain` phases via `clock_gettime(CLOCK_MONOTONIC)`
- Pass criterion: total ≤ 12 ms (§9.3 parse 5 + validate 5 +
  compile 10 / 4 due to 1 rule ≈ 2.5 + build 10 + rcu 1 + drain
  1 = ~14.5 ms; allow 12 ms minus debounce)
- Covers: §9.3
- D/N: N5

### P-D4.2 Reload latency 100 rules [DEV]
- Setup: `r100.json`
- Procedure: same
- Pass criterion: total ≤ 40 ms
- Covers: §9.3
- D/N: N5

### P-D4.3 Reload latency 1000 rules [DEV]
- Setup: `r1000.json`
- Procedure: same
- Pass criterion: total ≤ 70 ms
- Covers: §9.3
- D/N: N5

### P-D4.4 Reload latency prod-max [DEV]
- Setup: `prod_max.json`
- Procedure: same
- Pass criterion: total ≤ 100 ms (N5 hot-reload ceiling, sans
  debounce)
- Covers: N5, §9.3
- D/N: N5

### P-D4.5 D37 validator pre-flight cost [DEV]
- Setup: `prod_max.json` → new config with ambiguous expansion
- Procedure: measure `validate_budget` alone
- Pass criterion: ≤ 500 µs (D37 is pure arithmetic)
- Covers: D37
- D/N: D37, N5

---

## P-D5 — Memory footprint at prod sizing [DEV]

### P-D5.1 Ruleset bytes at prod-max [DEV]
- Setup: boot with prod sizing, load `prod_max.json`
- Procedure: read `expected_ruleset_bytes` / `mallinfo2` /
  `rte_malloc_heap_stat` deltas
- Pass criterion: Ruleset allocation ≤ engineered bound (derive
  from §8 — as a figure to record; set hard ceiling at 2 GiB,
  fail if exceeded; record baseline file for regression)
- Covers: D6/D37/§8 footprint
- D/N: D6, D37

### P-D5.2 Per-lcore counter arena footprint [DEV]
- Setup: prod-max ruleset, 16 lcores configured (even if dev can
  only run 1)
- Procedure: measure `PerLcoreCounters` size per lcore
- Pass criterion: ≤ 1 MiB per lcore at prod-max
  (§8.3 target ~768 KiB + slack)
- Covers: D3, §8.3
- D/N: D3

### P-D5.3 rl_arena footprint [DEV]
- Setup: `rate_limit_rules_max = 4096`, 16 lcores
- Procedure: measure `RateLimitArena` allocation
- Pass criterion: ≤ 4 MiB (4096 rules × 16 buckets × 64 B =
  4 MiB exactly; +2× metadata slack)
- Covers: D1 sizing
- D/N: D1

### P-D5.4 Hugepage ceiling respected [DEV]
- Setup: dev VM 512 MiB hugepages, load a config exceeding
  500 MiB estimated
- Procedure: trigger reload, watch for D37 pre-flight reject
- Pass criterion: reload rejected with `result=validate_err`
  reason `hugepage_budget` before any hugepage allocation
  happens; no `ENOMEM` from deep in `ruleset_build`
- Covers: D37
- D/N: D37

---

## Part X — Coverage

### SLO → test ID mapping

| Requirement | Description | Test IDs |
|---|---|---|
| F1 | Rule model, first-match | P-L1.10, P-L7.2 |
| F2 | Actions | P-L5.*, P-L9.*, P-L11.* |
| F3 | JSON config | covered by functional agent (out of scope here) |
| F4 | Hot reload | P-L6.*, P-D4.* |
| F5 | Control plane | P-L6.2, P-L6.3 |
| F6 | Observability | P-L6.1 (counter consistency), P-L7.1 (monotonicity) |
| F7 | Safety | covered by chaos agent (out of scope) |
| **N1** | 40 Gbps throughput | **P-L1.5 (release gate)**, P-L1.1–1.4, P-L1.6–1.8, P-L3.3, P-L4.*, P-L7.1 |
| **N2** | ≤ 500 µs latency | **P-L2.4 (release gate)**, P-L2.1–2.3, P-L2.5–2.7, P-L5.*, P-L7.1, P-D1.16–17 |
| **N3** | < 0.01 % loss | P-L1.*, P-L2.*, P-L6.1, P-L7.1 |
| N4 | Rule scale | P-L1.5, P-L4.*, P-D1.5, P-D5.1 |
| **N5** | Reload ≤ 100 ms, cold ≤ 5 s | **P-L6.4**, P-L6.1, P-L6.3, P-D4.*, P-D5.4 |

### D-decision → test ID mapping

| D# | Topic | Perf-observable signature | Test IDs |
|---|---|---|---|
| D1 | per-lcore RL bucket | rate accuracy, zero atomics | P-L5.1, P-L5.2, P-L5.4, P-D3.1, P-D3.3 |
| D3 | telemetry counting | counter cost + false-sharing | P-D1.15, P-D2.2, P-D5.2 |
| D4 | hw offload hook | FDIR_ID dispatch | P-L8.* |
| D7 | mirror semantics | cycle budget, fidelity | P-L11.*, P-L2.7 |
| D9 | single g_active | reload correctness | P-L6.*, P-D3.4 |
| D10 | D1 companion | (same as D1) | P-L5.1, P-L5.4 |
| D11 | rl_arena GC ordering | slot_live stability | P-D3.4 |
| D12 | RCU polish (timeout) | rcu_check_timeout | P-L6.1, P-L6.5 |
| D13 | L3 offset VLAN | L3 offset correct on tagged | P-D1.8 |
| D14 | L4 via IHL | L4 parse cycles | P-D1.10 |
| D15 | L4 compound + filter_mask | L4 hit cost flat with scale | P-D1.11, P-D1.12, P-L4.3, P-L4.5 |
| D16 | redirect staging + flush | redirect latency, TX-full | P-L9.* |
| D18 | cycle budget min/typ/max | all §5.6 rows | P-D1.*, P-D2.1 |
| D22 | RuleAction 20 B alignas(4) | cache efficiency | P-L1.7, P-D2.3 |
| D23 | NUMA awareness | cross-socket traffic | P-L3.4, P-D2.4 |
| D24 | slot recycling | slot_live stability | P-D3.4 |
| D26 | mirror refcnt gate | refcnt leak under load | P-L11.3 |
| D27 | IPv6 frag first vs non-first | L3 IPv6 cycles | P-D1.9 |
| D28 | TX queue symmetry | per-port invariant, per-worker TX isolation | P-L10.* |
| D30 | rcu_qsbr_check token + deadline | reload under load | P-L6.*, P-D4.* |
| D31 | truncation guards | jumbo counter | P-L1.9 |
| D33 | counter consistency | invariant check | P-L5.2, P-L7.1 |
| D34 | rl_arena clamp | first-burst after idle | P-L5.3, P-D3.2 |
| D35 | single reload_mutex | reload storm serializes | P-L6.1, P-L6.2 |
| D36 | pending_free queue | reload-timeout survivor | P-L6.5 |
| D37 | validator memory budget | hostile-config reject | P-L6.3, P-D4.5, P-D5.4 |
| D38 | UDS SO_PEERCRED | (perf N/A — security agent) | — |

**N/A for perf** (covered elsewhere):
D2 (C++ toolchain), D5 (HA — chaos agent), D6 (sizing — partially
covered in P-D5 but core is config agent), D8 (schema — config
agent), D17 (fragment policy — functional agent), D19 (misc
cleanup), D20 (IPv6 stub — functional agent), D21 (NEXT_L4
dispatch — functional agent), D25 (switch defaults — compile
time), D29 (dead field — compile time), D32 (QinQ 0x88A8 —
functional agent).

---

## Known limits — "we cannot measure this on dev VM"

Dev VM (82545EM e1000, 1 vCPU per dataplane, single RX queue) **cannot**:

1. Validate N1 throughput at any size. e1000 is 1 Gbps, single-queue,
   no RSS, no multi-core traffic. Dev VM results do not generalize.
2. Validate N2 latency percentiles. HW timestamping is absent; VM
   clock drift and virt exit jitter dominate any µs-level signal.
3. Validate P-L3 RSS scaling. Toeplitz is not supported by the NIC.
4. Validate P-L8 rte_flow hw offload. No `FDIR_ID` capability.
5. Validate P-L11 mirror refcount zero-copy. e1000 driver does not
   accept shared mbufs in TX.
6. Validate P-L5 rate-limit aggregate accuracy at > 1 Gbps.
7. Validate P-L6 reload-under-40 Gbps. Only reload-under-1 Gbps is
   meaningful — acceptable as a smoke test, not a gate.
8. Validate P-L7 24 h soak at line rate. Dev VM can soak for 24 h
   at `c_mixed_imix` cycle-budget level via ubench, but that
   catches leaks, not throughput degradation.

Dev VM **can**:

- Run all P-D1..P-D5 (cycle budget, cache behavior, RL clamp,
  reload budget, footprint)
- Run reload-under-low-traffic smoke of P-L6.* (shape test, not
  release gate)
- Run sanitizer flavors (ASAN / UBSAN / TSAN) of every P-D test
  as a pre-commit gate

---

## Lab hardware bill of materials (for §14.2 Phase 2 perf gate)

Request from infra for Phase 2 release window:

- **DUT server**: 1 × 2-socket Xeon Gold 6338 (32 C/64 T per
  socket) or newer; 128 GB RAM; 2 × PCIe 4.0 ×16 slots; Fedora /
  RHEL 9 host; 4 × 1 GiB hugepages
- **DUT NIC, primary**: 1 × Intel E810-CQDA2 2×100 G (ice 1.11+)
- **DUT NIC, secondary**: 1 × Intel XL710-QDA2 2×40 G (i40e) —
  validates 40 G-class behavior
- **DUT NIC, tertiary**: 1 × Mellanox ConnectX-6 Dx 2×100 G (mlx5)
  — validates rte_flow offload alternative
- **Generator server**: identical spec to DUT; same NIC per test
  session; TRex v3.04+ installed; clock synced via PPS where HW
  timestamping is in use
- **Cabling**: 100 G DAC (1 m) for E810 / CX6; 40 G QSFP+ DAC for
  XL710; back-to-back pair per port
- **Optional third DUT port**: for P-L9 redirect tests — 10 G
  SFP+ on DUT + TRex (use a separate NIC or a breakout)
- **Console / OOB**: serial + BMC on both hosts; script-driven
  power-cycle for long soaks
- **Storage**: 500 GB NVMe on DUT for telemetry CSV + pcap
  captures (24 h soak can produce ~20 GB of scraped metrics)
- **Lab OS**: Fedora 43 or RHEL 9 with DPDK 25.11 built from
  source; `isolcpus` configured; `tuned-profile latency-performance`

Nice-to-have:
- 2 × hardware bypass NICs (e.g. Silicom PE310G2BPi9) — for
  later Phase 3 bypass validation
- 1 × dedicated test orchestration host running TRex-GUI /
  Grafana / Prometheus for the run dashboards

---

*End of perf test plan draft.*
