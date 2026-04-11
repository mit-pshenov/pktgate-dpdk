# Chaos / reload / security test plan (draft)

Scope: tests that break the dataplane on purpose and verify it
recovers (or fails cleanly). Exercises the watchdog, D35 reload
mutex, D36 pending_free, D37 validator budget, D38 UDS auth, and
the §11 failure-mode table. Correctness under stress, not
throughput.

Counter names are taken verbatim from design.md §10.3. Expected
log lines are the structured-JSON lines produced by the paths
referenced in §9.2 / §10.7 / §11.

Conventions:

- **Harness**: the binary is `pktgate-dpdk` running as root on the
  dev VM (sudo no password, CLAUDE.md). Workers are lcore-pinned
  per §7; dev VM degrades to `--workers=1` (M1).
- **net_pcap vdev** is the functional traffic path on the dev VM;
  tests that need two traffic sources use a second `net_pcap` or
  `net_null` vdev plus scapy/tcpreplay.
- **TSAN build** is a separate CMake flavor (§12.1). Every reload
  test that has a "race must be gone" assertion is re-run under
  TSAN with the same harness.
- **Fault injection** is introduced via:
  - `LD_PRELOAD` shims for libc / DPDK API interception,
  - gdb attach + `signal SIGSTOP` for worker freeze,
  - a debug `--inject=<site>` CLI flag (compile gated on
    `-DPKTGATE_CHAOS=1`) for in-process sites that a shim can't
    reach,
  - `systemd-run --property=MemoryLimit=` for pre-existing
    hugepage pressure where applicable.
- **Metric scrapes** go through either `/metrics` (Prometheus) or
  `dpdk-telemetry.py --path=/run/pktgate/telemetry/rte_tel.sock`
  for `rte_telemetry` endpoints. Both are specified by §10.
- **Coverage line**: every test names the D-decisions and the
  §11 failure-mode rows and §9.4 corner-case bullets it exercises.
  The end-of-document coverage matrix cross-checks D1–D38.

---

## X1 — Reload chaos (D9, D11, D12, D30, D35, D36, D37)

Every §9.4 corner-case bullet is a test in this group, plus every
§11 row that involves the reload path.

### X1.1 Inotify reload storm (debounce coalesce)

- **Setup**: baseline ruleset loaded. `pktgate_active_generation`
  starts at `G0`. `config.json` is watched via `IN_CLOSE_WRITE |
  IN_MOVED_TO` on its directory (D38).
- **Procedure**: run
  ```sh
  while true; do
    cp cfg.a cfg.tmp && mv cfg.tmp config.json
    cp cfg.b cfg.tmp && mv cfg.tmp config.json
  done
  ```
  at 100 Hz for 10 s (≈ 2000 rename events).
- **Assertion**:
  - Process does not crash.
  - `pktgate_reload_total{result="success"}` grows by **far less**
    than 2000 — debounce is working. Exact bound: at 150 ms
    debounce window, upper bound is `10 s / 150 ms ≈ 67`.
    Assert ≤ 80.
  - `pktgate_active_generation` advances monotonically,
    final value matches count of observed `reload_done` log
    lines.
  - No `reload_total{result!="success"}` entries.
- **Expected counters**: `pktgate_reload_total{result="success"}`
  increments ≤ 80; `pktgate_reload_latency_seconds` histogram
  accumulates ≤ 80 observations.
- **Expected logs**: `reload_done generation=<N>` once per
  coalesced group; `inotify_debounce coalesce=<k>` at debug level.
- **Covers**: D35, §9.4 "Nested / concurrent reload", D38 inotify
  filter, §11 row "reload mid-flight" (indirect).

### X1.2 cmd_socket reload storm (mutex serialization)

- **Setup**: baseline ruleset. Allowlist the caller gid in
  `config.cmd_socket.allow_gids` so the verbs actually land (D38).
- **Procedure**: spawn 1000 UDS clients in parallel (`xargs -P 100`
  over `socat UNIX-CONNECT:/run/pktgate/ctl.sock STDIO <<< '{"cmd":"reload"}'`);
  each fires once; total event count 1000.
- **Assertion**:
  - No crash, no hang > 10 s.
  - TSAN build: zero data-race reports.
  - `pktgate_reload_total{result="success"}` = 1000 (no debounce
    on UDS path, D35 mutex serializes rather than coalesces).
  - No double-free (ASAN run same scenario: zero reports).
  - `pktgate_cmd_socket_rejected_total{*}` = 0 (all callers are
    in the allow-list).
- **Expected counters**: `reload_total{result="success"}` += 1000;
  `reload_latency_seconds` observations = 1000.
- **Expected logs**: 1000 `reload_done` lines; one
  `reload_funnel_waiting` debug line per contending caller.
- **Covers**: D9, D35, D30, §9.4 "Nested / concurrent reload".

### X1.3 Cross-channel concurrent reload (D35 three-way funnel)

- **Setup**: baseline ruleset. Test harness holds (a) inotify
  directory writer, (b) UDS client, (c) `rte_telemetry`
  `/pktgate/reload` writer, and fires them at t=0, t=+10 µs,
  t=+100 µs respectively (coarse — use `usleep` + single parent
  process that forks three children and releases them with a
  shared eventfd).
- **Procedure**: run 100 trials. Each trial swaps `config.json`
  to a distinct content (so we can count distinct successful
  reloads by `pktgate_active_rules{layer=l3}` changes).
- **Assertion**:
  - All three callers return cleanly.
  - TSAN build: zero races on `g_cp.g_active`.
  - `pktgate_reload_total{result="success"}` increments by
    **at least 1** and **at most 3** per trial. Exactly which is
    allowed depends on debounce: inotify may coalesce with itself
    but NOT with UDS or telemetry (those hit the funnel directly).
    Expected outcome: 1–3 per trial, with the vast majority
    landing on exactly the number of non-inotify sources that
    actually fired (inotify path collapses into whatever UDS /
    telemetry already landed if it arrives while the mutex is
    held).
  - Final `pktgate_active_generation` matches the count of
    distinct successful deploys.
- **Expected counters**:
  `pktgate_reload_total{result="success"}` += [100, 300];
  no `timeout`, `validate_err`, or `parse_err`.
- **Covers**: D9, D35 (the main target), D30, §9.4
  "Nested / concurrent reload".

### X1.4 Reload timeout path (D30 + D36)

- **Setup**: single worker. Attach gdb to the worker thread;
  stage an LD_PRELOAD shim that intercepts
  `rte_rcu_qsbr_quiescent(qs, tid==worker_tid)` and converts it
  to a no-op for exactly 1 s.
- **Procedure**: trigger reload via UDS. The `deploy()` loop
  polls `rte_rcu_qsbr_check` against the 500 ms deadline and
  hits the timeout branch.
- **Assertion**:
  - `deploy()` returns `Err::ReloadTimeout` to the caller.
  - `pktgate_reload_total{result="timeout"}` += 1.
  - `pktgate_reload_pending_free_depth` gauge == 1.
  - `pktgate_active_generation` advanced (rs_new was installed
    before the timeout).
  - Process does not crash. Workers continue forwarding.
  - No crash when the shim is removed.
- **Procedure (part 2 — drain)**: remove the shim (worker
  starts reporting quiescent normally). Trigger a fresh reload.
- **Assertion (part 2)**:
  - `pktgate_reload_total{result="success"}` += 1.
  - `pktgate_reload_pending_free_depth` drains to 0
    (§9.2 `pending_free_drain`).
  - `/proc/$pid/status` VmRSS plateaus — no sustained leak.
- **Covers**: D12 (synchronize timeout spec), D30, D36, §9.4
  "Reload timeout", §11 row "Reload timeout (stuck worker)".

### X1.5 pending_free overflow (D36, K_PENDING)

- **Setup**: `K_PENDING = 8` per §9.2 comment. Inject a persistent
  "one worker always stuck" shim (X1.4 style), so every reload
  goes onto `pending_free`.
- **Procedure**: fire 9 successive reloads via UDS.
- **Assertion**:
  - First 8: `pktgate_reload_pending_free_depth` climbs 1→8,
    `reload_total{result="timeout"}` += 8.
  - 9th: `pktgate_reload_total{result="pending_full"}` += 1,
    `rs_old` for that reload is intentionally leaked,
    `pending_free_depth` stays at 8.
  - Process does not crash.
  - Alert log line: `reload_pending_full dataplane_wedged` at
    ERROR level, exactly once per overflow (not once per
    subsequent retry).
- **Procedure (part 2 — recovery)**: remove the stuck-worker
  shim, trigger one more reload.
- **Assertion (part 2)**:
  - `reload_total{result="success"}` += 1.
  - `pending_free_depth` drains from 8 to 0 in one call
    (single successful check covers every prior token).
  - VmRSS drops by 8 × ruleset_size (minus the one leaked
    overflow entry).
- **Covers**: D36 (the main target), §9.4 "Reload timeout"
  overflow branch, §11 "Reload timeout" row.

### X1.6 Validator budget gate — happy path (D37)

- **Setup**: six configs, each crafted to **exactly fit** one
  budget:
  - (a) Per-rule expansion = `sizing.max_expansion_per_rule`
    (default 4096) — one rule with 4096-element port list.
  - (b) Per-rule expansion = 4095 (just under).
  - (c) Aggregate L3 entries = `sizing.l3_entries_max` exactly.
  - (d) Aggregate L4 entries = `sizing.l4_entries_max` exactly.
  - (e) Hugepage estimate = free hugepages − safety margin.
  - (f) Mixed config at 0.9× of every ceiling.
- **Procedure**: load each in turn via UDS.
- **Assertion**: all six succeed. No false reject.
  `pktgate_reload_total{result="success"}` += 6.
- **Covers**: D37 lower-boundary behavior.

### X1.7 Validator budget gate — overflow (D37)

- **Setup**: six configs, each overflowing one budget by the
  smallest increment:
  - (a) Per-rule expansion = 4097 → `expansion_per_rule` reject.
  - (b) Aggregate L3 entries = `l3_entries_max + 1` →
    `aggregate` reject.
  - (c) Aggregate L4 entries = `l4_entries_max + 1` → `aggregate`.
  - (d) Hugepage estimate = free − margin + 1 MiB →
    `hugepage_budget`.
  - (e) Combo: per-rule overflow AND hugepage overflow → first
    gate wins (expansion_per_rule) — verify deterministic order.
  - (f) Aggregate L2 entries overflow.
- **Procedure**: load each in turn.
- **Assertion**:
  - Every load rejected: `pktgate_reload_total{result="validate_err"}`
    += 6.
  - Structured log carries the sub-reason
    (`expansion_per_rule | aggregate | hugepage_budget`) exactly
    as specified in §9.2.
  - `pktgate_active_generation` **unchanged** — old ruleset
    survives all six rejections.
  - No hugepage was allocated (probe `/proc/meminfo` HugePages_Free
    before/after: delta == 0).
  - Validator latency < 1 ms per reject (pure arithmetic).
- **Covers**: D37 (the main target), §11 row "Validation error".

### X1.8 Hugepage starvation during `ruleset_build`

- **Setup**: baseline running. Externally pin most hugepages
  before the reload: `echo $(($(cat /proc/meminfo | grep HugePages_Total | awk '{print $2}') - 4)) > /sys/.../nr_overcommit_hugepages`,
  or more portable: pre-reserve with a sacrificial DPDK secondary
  that holds onto all but ~8 MiB of hugepage memory. Goal: `ruleset_build`
  actually OOMs at allocation time, **past** the D37 validator
  estimate (use a config that fits the estimate by a whisker but
  real allocator happens to lose).
- **Procedure**: trigger reload.
- **Assertion**:
  - `pktgate_reload_total{result="oom"}` += 1.
  - Old ruleset survives: `pktgate_active_generation` unchanged.
  - No crash.
  - Alert log line: `reload_oom hugepages_free=<n>`.
  - Telemetry reports a non-zero `pktgate_mempool_free{socket}`
    delta (some fragments may have been allocated and freed).
- **Covers**: §11 row "Hugepage OOM during build", §9.4
  "Hugepage exhaustion mid-build".

### X1.9 Reload mid-shutdown (§11 row)

- **Setup**: baseline running. Inject a slow compile via `--inject=slow_compile=2s`.
- **Procedure**: trigger reload via UDS, then 500 ms later
  send `SIGTERM`.
- **Assertion**:
  - Reload aborts cleanly — compiler notices shutdown flag and
    returns `Err::ShuttingDown` or equivalent; rs_new is
    unique_ptr-freed.
  - Workers drain final bursts, `rcu_qsbr_thread_offline` +
    `_thread_unregister` fire on each.
  - `g_cp.g_active` cleared after the final `rcu_synchronize`
    (§6.4).
  - Process exits 0 (or clean-shutdown code).
  - No mbuf leak: mempool `in_use == 0` at exit.
  - No leaked hugepage segments (valgrind / `rte_malloc_dump_stats`
    shows empty).
- **Covers**: §6.4, §11 row "Reload mid-shutdown".

### X1.10 Orphan rs_old leak detector (long-running)

- **Setup**: single-worker build. Stuck-worker shim X1.4 style.
- **Procedure**: run 1 hour at 1 Hz reload cadence. 3600 timeouts
  over the hour; with K_PENDING=8 the 8 oldest stay pinned and
  the rest overflow.
- **Assertion**:
  - VmRSS grows to `baseline + 8 × sizeof(rs)`, plus one leaked
    slot per overflow if those are never freed.
  - After 1 h, VmRSS ceiling matches: `baseline + 8 × sizeof(rs)
    + (3600 - 8) × sizeof(rs)` if overflow leaks are intentional,
    OR ceiling is bounded and the leak is monotonic at a known
    rate. Assert the measured rate matches design expectation
    exactly (no surprise leaks).
  - `pktgate_reload_total{result="pending_full"}` == 3592.
  - `pktgate_reload_pending_free_depth` == 8 throughout.
- **Procedure (part 2 — recovery)**: remove shim, reload once.
- **Assertion (part 2)**: VmRSS drops by `8 × sizeof(rs)`.
  Leaked overflow entries remain (by design).
- **Covers**: D36 overflow leak accounting, long-running drift.

### X1.11 Debounce correctness (D35 + inotify)

- **Setup**: baseline. Very slow config file writer that sends
  exactly two rename events 150 ms apart (first inside debounce
  window, second after).
- **Procedure**: fire the two events; observe.
- **Assertion**:
  - `pktgate_reload_total{result="success"}` += 2 (not 1 — they
    are outside the same debounce group).
  - Two distinct `reload_done` log lines.
- **Covers**: debounce boundary.

### X1.12 Reload with no changes (no-op reload)

- **Setup**: baseline with ruleset G0.
- **Procedure**: UDS reload against the same config.json contents.
- **Assertion**:
  - `reload_total{result="success"}` += 1 (this is a full
    publish, not an early-out — D9 single-writer invariant).
  - `pktgate_active_generation` advances (compile produced a
    new ruleset, RCU swapped, arena GC freed 0 rules).
  - No spurious counter-reset on unchanged rules (§9.4
    step 5b zeros only *removed* rule slots; unchanged rules
    keep their counters).
  - Test: a specific rule had matched N packets before reload;
    its counter is still N after.
- **Covers**: §9.4 step 5b correctness, D33 counter consistency.

### X1.13 Reload while traffic is flowing

- **Setup**: net_pcap + tcpreplay, 1 kpps sustained.
- **Procedure**: reload once at t=5 s.
- **Assertion**:
  - Zero packet loss attributable to the reload (§9.4 "mid-burst
    reload impossible by construction").
  - Workers do not observe a mixed-version ruleset — a specific
    "before" rule stops matching atomically at the reload
    boundary; the "after" rule starts matching atomically.
    Check by sending a probe packet that only the old rule
    matches and a probe only the new rule matches.
  - `pktgate_lcore_cycles_per_burst` histogram has no outlier
    bursts > 10× median during the reload window.
- **Covers**: §9.4 "Mid-burst reload impossible", primary reload
  correctness invariant.

### X1.14 Reload where rule-id is reused with new semantics

- **Setup**: ruleset G0 has rule_id=42 as a rate-limit rule.
  Traffic has exercised its bucket for 10 s (bucket tokens
  depleted).
- **Procedure**: reload G1 where rule_id=42 is a different
  rate-limit rule (different rate, different match).
- **Assertion**:
  - Per §9.4 "Rule-id reassignment": arena keys verbatim on
    rule_id, so old bucket state carries over to the new rule
    (even though that is semantically suspect — operator
    responsibility documented in §3a.2).
  - The bucket row is **not** zeroed (§9.4 step 5 only
    touches *removed* rule_ids, and 42 was not removed).
- **Test variant**: G1 removes rule_id=42 entirely, then G2
  reintroduces rule_id=42 as yet another rule.
  - Between G1 and G2 the slot is freed and the row memory
    is ready for reuse.
  - G2 publish allocates a fresh slot; the bucket starts from
    zero (§9.4 step 5b + row zero-init).
- **Covers**: D11, D24 slot lifecycle, §9.4 "Rule-id reassignment",
  D33 counter consistency (counter slot is zeroed on slot reuse).

---

## X2 — Dataplane chaos

### X2.1 Worker stall → watchdog → SIGABRT → restart

- **Setup**: `systemd-run` the binary under its normal unit
  with `WatchdogSec=3s`. Baseline traffic at 1 kpps.
- **Procedure**: attach gdb to the worker thread, issue
  `signal SIGSTOP` to freeze it. Wait > `WatchdogSec`.
- **Assertion**:
  - Heartbeat counter in shared memory stops advancing.
  - systemd sends `SIGABRT`, process crashes.
  - systemd restarts the unit (`Restart=on-failure`).
  - `pktgate_watchdog_restarts_total` (visible in the
    metrics of the new process after restart) increments
    compared to baseline persisted across restarts
    (Prometheus-scraped externally).
  - Traffic flow resumes within backoff window.
- **Follow-up**: repeat freeze-kill K+1 times back-to-back,
  where K is the "repeated crash" threshold in §6.5.
- **Assertion (follow-up)**:
  - On the (K+1)-th failure, systemd unit transitions into
    `pktgate-bypass.target`.
  - `pktgate_bypass_active == 1` in the bypass supervisor's
    metrics.
  - Traffic is still flowing (software forward-only per §11
    default bypass mode).
- **Covers**: §6.5 crash recovery, §11 "Worker stall" and
  "Bypass mode triggered" rows.

### X2.2 Worker crash (SIGSEGV) via fault injection

- **Setup**: `-DPKTGATE_CHAOS=1` debug build with
  `--inject=worker_segv_at_packet=1000` — after processing 1000
  packets, the worker dereferences `nullptr`.
- **Procedure**: start, send 1500 packets via net_pcap.
- **Assertion**:
  - Process crashes on packet 1001.
  - No hang (watchdog is a backstop, not the primary detector
    — the signal handler + systemd should fire first).
  - Restart path fires cleanly (`Restart=on-failure`).
  - `pktgate_watchdog_restarts_total` += 1.
  - No zombie mbufs in the old mempool (shared memory from the
    previous incarnation is reclaimed on cold start).
- **Covers**: §6.5 "Process death", §11 "Process crash" row.

### X2.3 Mempool exhaustion under high RX

- **Setup**: override mempool sizing to a tiny value
  (`--sizing-config mempool.mbufs=512`). 4 kpps incoming.
- **Procedure**: run 30 s.
- **Assertion**:
  - `rte_pktmbuf_alloc` returns NULL under pressure.
  - `pktgate_port_rx_dropped_total{port,reason="nombuf"}`
    increments proportionally to pressure.
  - Process does not crash.
  - No `pkt_truncated` events (that would be a different bug).
- **Procedure (part 2 — relief)**: stop pressure, wait 5 s.
- **Assertion (part 2)**:
  - `port_rx_dropped{reason="nombuf"}` stops growing.
  - `pktgate_mempool_free{socket}` returns to near-baseline.
- **Covers**: §11 "Mempool exhausted" row.

### X2.4 TX ring saturation

- **Setup**: slow consumer on egress — second net_pcap vdev
  reading very slowly, or `tc tbf` rate-limit on the out-facing
  interface.
- **Procedure**: sustained 10 kpps TX for 30 s.
- **Assertion**:
  - `rte_eth_tx_burst` returns < n under backpressure.
  - `pktgate_port_tx_dropped_total{port}` climbs.
  - Unsent mbufs are freed via the bulk-free path — mempool
    `in_use` gauge does **not** grow unbounded.
  - After the slow consumer is removed, `in_use` returns to
    baseline within one snapshot interval.
- **Covers**: §11 "TX ring full" row, §5.5 bulk-free
  correctness.

### X2.5 D16 REDIRECT TX saturation

- **Setup**: a rule with `action=redirect target_port=mirror0`.
  Saturate `mirror0` (slow consumer / tbf).
- **Procedure**: send traffic matching the redirect rule at
  5 kpps while traffic not matching the redirect goes through
  the primary path at 5 kpps.
- **Assertion**:
  - `pktgate_redirect_dropped_total{lcore,port="mirror0"}` climbs.
  - Primary path (`pktgate_port_tx_dropped_total{port="out"}`)
    is **unaffected** — no cross-contamination.
  - The D16 burst-end flush actually fires: the per-burst
    staging is drained at the end of each burst and unsent
    mbufs are freed once, not leaked.
  - Mempool `in_use` does not grow.
- **Covers**: D16 (the main target), §11 "Redirect TX full".

### X2.6 NIC link flap

- **Setup**: a second NIC on the dev VM (or `net_pcap` that
  supports reopen). Loop `ip link set devX down; sleep 0.2; ip
  link set devX up; sleep 0.2`.
- **Procedure**: 2 min of flapping at 5 Hz.
- **Assertion**:
  - `pktgate_port_link_up{port}` gauge flips between 0 and 1
    in the telemetry history.
  - Process does not crash.
  - Reload state is consistent: run a reload mid-flap, assert
    it succeeds.
  - No stuck references to flapped port in the ruleset (rule
    references use logical roles, not raw link status — D5).
- **Covers**: §11 "NIC link down" row.

### X2.7 PCI error injection [LAB ONLY on dev VM]

- **Setup**: Determine if `echo 1 > /sys/bus/pci/devices/<BDF>/remove`
  works on the passed-through e1000. VirtualBox likely rejects —
  mark this test **lab-only**.
- **Procedure** (when available): `echo 1 > .../remove` on the
  bound NIC while the dataplane is running.
- **Assertion**:
  - `rte_eth_dev_get_status` or equivalent health poll detects
    the missing device.
  - Log line: `pci_error port=<n> fatal` at ERROR level.
  - Process exits non-zero.
  - Watchdog restarts; cold start fails to rebind the missing
    BDF; alert fires, process stays in backoff.
- **Dev VM fallback**: use a `net_pcap` vdev and `rmmod/modprobe`
  equivalent — imperfect but exercises the same detection path.
- **Covers**: §11 "PCI error" row.

### X2.8 D28 TX-queue symmetry violation detection

- **Setup**: config with `n_workers=4` and a `mirror_port` that
  reports `rte_eth_dev_info.max_tx_queues=2`. This is
  reproducible on the dev VM with `net_null,max_tx_queues=2`.
- **Procedure**: cold start with this config.
- **Assertion**:
  - `port_init` (§6.1) detects the mismatch and rejects.
  - Startup fails with a **clear** error:
    `D28 violation: port=mirror0 max_tx_queues=2 < n_workers=4`.
  - Process exits non-zero at init, **before** any worker
    launches — i.e. **not** at runtime when the first mirror
    packet shows up.
  - No partial RX queue setup leaking memory.
- **Covers**: D28 (the main target).

### X2.9 D25 dispatch_unreachable backstop

- **Setup**: debug build with `--inject=bogus_verdict=0xFF` that
  writes an invalid `verdict_layer` enum value into an mbuf's
  dynfield between `classify_l4` and `apply_action` (one in
  1000 packets).
- **Procedure**: 10k packets.
- **Assertion**:
  - `pktgate_lcore_dispatch_unreachable_total{lcore}` += ~10
    (one per injected packet).
  - Packets with the bogus verdict are freed, not leaked,
    not enqueued — mempool `in_use` stable.
  - No crash, no UB (debug build under UBSAN: zero reports).
- **Assertion (release build, no injection)**:
  - `dispatch_unreachable_total == 0` throughout the entire
    test suite. Make this a CI gate.
- **Covers**: D25, the "every enum has a default arm" invariant.

### X2.10 RX burst truncation shapes (D31 belt check)

(Overlap note: the malformed-packet corner-case agent owns shape
enumeration; this test only validates that the *counter plumbing*
works under stress, not the individual packet shapes.)

- **Setup**: injected 1 kpps of truncated packets (8 B
  Ethernet-only frames) mixed with 9 kpps of normal traffic.
- **Procedure**: 60 s run.
- **Assertion**:
  - `pktgate_lcore_pkt_truncated_total{lcore,where="l2"}`
    grows at ~1 kpps per lcore.
  - No crash, no SEGV (D31 guards all fire correctly under
    pressure).
  - Normal traffic at 9 kpps is unaffected.
- **Covers**: D31 under load, §11 indirectly (no row — this is
  a malformed-input-resilience test).

### X2.11 Burst-loop starvation (handle_idle spec)

- **Setup**: zero traffic. Baseline worker idle.
- **Procedure**: trigger reload. D19 spec says idle handler is
  tight busy-check (exit after 16 empty polls), stays RCU-online.
- **Assertion**:
  - `rte_rcu_qsbr_check` in `deploy()` returns 1 within one
    deadline window even with zero traffic, because the idle
    worker still reports quiescent (D19 / D12).
  - `pktgate_reload_total{result="success"}` += 1, not
    `timeout`.
  - `pktgate_lcore_idle_iters_total` visibly climbs during the
    no-traffic window.
- **Covers**: D19 idle handler spec, §9.4 reload correctness
  under idle.

---

## X3 — Control-plane security (D38)

### X3.1 SO_PEERCRED rejects unauthorized uid

- **Setup**: binary running as `pktgate:pktgate`. Create user
  `attacker` (uid ≠ 0, uid ≠ pktgate_uid).
- **Procedure**: as `attacker`, `socat UNIX-CONNECT:/run/pktgate/ctl.sock STDIO <<< '{"cmd":"reload"}'`.
- **Assertion**:
  - Connection is accepted at socket layer, then immediately
    closed by the control thread at the `SO_PEERCRED` check.
  - `pktgate_cmd_socket_rejected_total{reason="peer_uid"}` += 1.
  - Log line at WARN:
    `cmd_socket_rejected peer_uid=<X> peer_pid=<Y>`.
  - No reload fired; `pktgate_active_generation` unchanged.
- **Covers**: D38 (a), §11 (not a row; auth rejection is not
  a failure mode).

### X3.2 SO_PEERCRED rejects wrong gid

- **Setup**: user `attacker2` with `uid == pktgate_uid` (e.g.
  same user, different session), but `egid` is not in
  `config.cmd_socket.allow_gids`. Run via `sg attackers <cmd>`.
- **Procedure**: `{"cmd":"reload"}` over UDS.
- **Assertion**:
  - `pktgate_cmd_socket_rejected_total{reason="peer_gid"}` += 1.
  - Log line at WARN.
  - Reload does not fire.
- **Covers**: D38 (a) gid path.

### X3.3 Allow-listed gid succeeds

- **Setup**: config `cmd_socket.allow_gids: [pktgate_gid,
  wheel]`. Run a wheel user.
- **Procedure**: `{"cmd":"reload"}`.
- **Assertion**:
  - `reload_total{result="success"}` += 1.
  - `cmd_socket_rejected_total{*}` unchanged.
- **Covers**: D38 allow-list happy path.

### X3.4 Read-only verbs for allow-listed peer

- **Setup**: allow-listed peer as in X3.3.
- **Procedure**: send `{"cmd":"status"}`, `{"cmd":"dump-rule","layer":"l3","id":42}`,
  `{"cmd":"counters","layer":"l3","id":42}`.
- **Assertion**:
  - All three verbs return valid JSON responses.
  - No rejection counter bump.
  - No side effect on the ruleset.
- **Covers**: D38 — "read-only verbs allowed for allow-listed peer".

### X3.5 Mutating verbs require tighter gate

- **Setup**: a hypothetical peer that passes the allow-list but
  **not** the strict mutating gate (if the design were to grow
  such a layer — §10.7 reads as "allow-list gates both, mutating
  verbs additionally require SO_PEERCRED", so today "tighter"
  means "same check, enforced at verb dispatch time not just
  accept time").
- **Procedure**: close the peer connection between accept and
  verb dispatch using a misbehaving client (or send a
  non-ucred-bearing FD via `SCM_RIGHTS` — tricky, skip if not
  practical). Alternative: run with a deliberately corrupted
  ucred cache to verify verb dispatch re-checks.
- **Assertion**:
  - If design requires re-check on mutating verbs: the corrupted
    case is rejected with `reason="peer_uid"` or `peer_gid`.
  - If design only checks at accept: this test is a no-op and
    we document that as the spec.
- **Covers**: D38 verb-class distinction.

### X3.6 Socket permissions baseline

- **Setup**: fresh boot.
- **Procedure**: `stat /run/pktgate/ctl.sock`.
- **Assertion**:
  - Mode == `0600`.
  - Owner == `pktgate`, group == `pktgate`.
- **Variant**: launch with a sabotaged unit file that tries to
  chmod the socket to 0666 post-create.
- **Assertion (variant)**: boot fails OR emits a loud WARN
  at every telemetry tick: `ctl_socket_perm_drift mode=0666`.
- **Covers**: D38 filesystem layer, §10.7.

### X3.7 inotify IN_CLOSE_WRITE filter (D38 b)

- **Setup**: baseline running, watching `config/` directory.
- **Procedure**:
  ```sh
  echo -n 'partial' > config/config.json
  sleep 0.5
  echo -n ' more' >> config/config.json
  sleep 0.5
  echo -n ' valid_json_terminator' >> config/config.json
  ```
- **Assertion**:
  - Parser is **never** invoked on `partial` or `partial more`
    (those are intermediate `IN_MODIFY` events which the
    filter discards).
  - `pktgate_reload_total{result="parse_err"}` stays 0 —
    because the intermediate states never reach the parser.
  - **Only** the final `close(2)` fires `IN_CLOSE_WRITE`.
  - If the final content is valid JSON, exactly one successful
    reload fires. If it is invalid JSON (no
    `valid_json_terminator` case), exactly one `parse_err`
    fires.
- **Covers**: D38 (b) the main target.

### X3.8 inotify atomic replace (mv)

- **Setup**: baseline.
- **Procedure**: `cp cfg.new config.tmp && mv config.tmp config/config.json`.
- **Assertion**:
  - `IN_MOVED_TO` fires.
  - One successful reload.
- **Variant**: `rm config/config.json; echo '<contents>' > config/config.json`.
- **Assertion (variant)**:
  - `IN_CREATE` + `IN_CLOSE_WRITE` sequence observed; deploy
    fires exactly once.
- **Covers**: D38 — "watch is on the directory, never the file"
  correctness.

### X3.9 UDS malformed / oversized payload

- **Setup**: baseline.
- **Procedure**:
  - (a) `dd if=/dev/urandom bs=1M count=1 | socat - UNIX-CONNECT:/run/pktgate/ctl.sock`.
  - (b) Pipelined: `printf '{"cmd":"status"}\n{"cmd":"status"}\n{"cmd":"reload"}\n' | socat - UNIX-CONNECT:/...`
  - (c) Single JSON line with 10 MiB of garbage in a string
    field.
- **Assertion**:
  - (a) parse error response, connection closed, no crash,
    no read-buffer overflow (ASAN clean).
  - (b) three responses in order, all handled.
  - (c) input capped at a sane maximum (e.g. 64 KiB), connection
    closed with `{"err":"oversized"}`, no alloc OOM.
  - `pktgate_cmd_socket_rejected_total{reason}` may grow if we
    add an `oversized` reason — or the count stays 0 and the
    rejection is log-only. Define expected semantics explicitly
    and assert.
- **Covers**: D38 robustness, §10.7.

### X3.10 Race: reload arrives while another is in validate

- **Setup**: `--inject=slow_validate=200ms`. Two UDS clients.
- **Procedure**: client A sends reload → validator starts →
  client B sends reload 100 ms later (still in validate window).
- **Assertion**:
  - D35 mutex serializes: A finishes, B waits, B runs.
  - Both return cleanly.
  - TSAN build: zero races.
  - `reload_total{result="success"}` += 2.
  - Order of completion is A then B (ordering check).
- **Covers**: D35 (main target), §9.4 "Nested / concurrent
  reload".

### X3.11 UDS `activate` verb in --standby mode

- **Setup**: cold start with `--standby`. Ports configured but
  not started (§6.1).
- **Procedure**: send `{"cmd":"activate"}` over UDS.
- **Assertion**:
  - Workers are `rte_eal_remote_launch`'d.
  - `rte_eth_dev_start` runs on each port.
  - RSS / flow rules programmed.
  - First packet through the datapath lands successfully.
  - `pktgate_lcore_packets_total{lcore}` starts incrementing.
- **Negative case**: send `activate` from an unprivileged peer.
- **Assertion (negative)**: rejected (`cmd_socket_rejected_total`),
  park state unchanged.
- **Covers**: D5 --standby park mechanics, §6.1 activation
  ordering, D38 auth.

---

## X4 — Recovery / bypass / HA (§11.1, D5, D7 mirror fallback)

### X4.1 Bypass after K crashes

- **Setup**: `-DPKTGATE_CHAOS=1`. `--inject=worker_segv_at_start=1`
  so the worker dies one second after launch, every launch.
  Customer policy K=3 (check §6.5 for the actual number).
- **Procedure**: let systemd restart the unit until it gives up
  and pivots to `pktgate-bypass.target`.
- **Assertion**:
  - On the (K+1)-th failure, `pktgate-bypass.target` is active.
  - `pktgate_bypass_active == 1`.
  - Traffic is forwarded RX → TX untouched (software
    forward-only). Verify with a probe packet that would have
    been dropped by the normal ruleset — it passes.
  - Structured log: `bypass_activated mode=sw_forward_only
    reason=repeated_crashes`.
- **Covers**: §6.5 "repeated crash" branch, §11 "Bypass mode
  triggered" row, §11.1 fail-open default.

### X4.2 Standby park state

- **Setup**: `--standby` cold start.
- **Procedure**: run for 30 s in park; observe.
- **Assertion**:
  - Workers not launched.
  - Ports configured (`ethtool -i` or `dpdk-devbind.py --status`
    shows bound) but NOT started.
  - Zero traffic flows (no RX/TX counters increment — rings are
    quiescent per §6.1 decision).
  - Process is alive (heartbeat advances; watchdog happy).
  - `pktgate_reload_total` still works — reload in standby is
    expected to succeed (parks the new ruleset in the `g_active`
    global without serving traffic).
- **Procedure (part 2 — activate)**: send `{"cmd":"activate"}`.
- **Assertion (part 2)**: as X3.11 — workers launched, ports
  started, first packet through, no race between the verb
  return and the first burst.
- **Covers**: D5 --standby, §6.1 park/activate decision.

### X4.3 Graceful shutdown under traffic

- **Setup**: 1 kpps sustained traffic (dev VM cap).
- **Procedure**: SIGTERM mid-flow.
- **Assertion**:
  - Workers finish the in-progress burst (not mid-packet
    abort).
  - `rte_rcu_qsbr_thread_offline` then `_thread_unregister`
    per worker (§6.4).
  - Control thread's final `rcu_synchronize` succeeds.
  - `g_cp.g_active` cleared after synchronize.
  - Ports stopped and closed; mempool freed.
  - No leaked mbufs (mempool `in_use == 0`).
  - No leaked hugepage segments
    (`rte_malloc_dump_stats` empty).
  - Process exits 0 within 1 s (§6.4 total budget).
- **Covers**: §6.4 full shutdown sequence.

### X4.4 HA anti-pattern detection (D5)

- **Setup**: configs that violate §11.1 anti-patterns:
  - (a) Rule file references `pci=0000:01:00.0` directly.
  - (b) Rule file uses a `host_id` field in match conditions.
  - (c) Rule file uses `CLOCK_REALTIME` in a `time_window`
    field.
  - (d) Config specifies a path outside the process
    (`/var/run/pktgate.state`) for state sharing.
- **Procedure**: attempt to load each at boot.
- **Assertion**:
  - Each fails at validate: `reload_total{result="validate_err"}`
    (or startup reject). Structured log sub-reason identifies
    which anti-pattern.
  - Old ruleset (if any) survives.
  - Cold start with an anti-pattern config exits non-zero
    with a clear message.
- **Covers**: D5, §11.1 (all four bullets are tests).

### X4.5 Mirror-mode fallback activation [LAB ONLY on dev VM for traffic correctness]

- **Setup**: config declares mirror-mode fallback as the bypass
  target (§11, operator-configurable). `--inject=repeated_crash`
  to trip bypass.
- **Procedure**: after K crashes, bypass activates.
- **Assertion**:
  - `pktgate_bypass_active == 1`.
  - Traffic is being *observed* (mirrored to collector port),
    not filtered (per §11 mirror-mode fallback semantics).
  - Log line: `bypass_activated mode=mirror`.
- **Dev VM limitation**: traffic rate correctness not
  measurable on e1000; flag lab-only for the rate portion.
- **Covers**: §11.1 fail-open alternatives.

### X4.6 Watchdog heartbeat timeout (stall, not crash)

- **Setup**: attach gdb, `signal SIGSTOP` on the *main thread*
  (not worker) so the heartbeat-publisher stops advancing.
- **Procedure**: wait > `WatchdogSec`.
- **Assertion**:
  - systemd sends `SIGABRT`.
  - `pktgate_watchdog_restarts_total` += 1 after restart.
  - Workers are also killed (since they're in the same
    process), no zombie lcores.
- **Covers**: §6.5 "Stall" branch, §11 "Worker stall" row.

---

## Coverage matrix (D1–D38 → chaos test IDs)

| D | Topic | Chaos test(s) | Notes |
|---|---|---|---|
| D1 | per-lcore token bucket, zero atomics | **not in scope** | Perf agent (rate-limit throughput and fairness under contention). |
| D2 | C++20 baseline | **n/a** | Build config; unit-test agent's CMake scaffolding covers this. |
| D3 | telemetry counting model | indirect in every X* | Every test reads counters from §10.3; no standalone test. |
| D4 | rte_flow offload hooks | **not in scope MVP** | MVP ships disabled; when it lights up, add X4.7 "rte_flow publish failure → SW fallback". |
| D5 | HA-compat requirements | **X4.2**, **X4.4**, X3.11 (activate verb) | interface roles, --standby, anti-patterns. |
| D6 | runtime sizing | X1.6, X1.7 | Budget gate is the operational surface. |
| D7 | mirror action full semantics | **not in scope MVP** | Mirror ships Phase 2; X4.5 covers the bypass-via-mirror flavor. |
| D8 | JSON schema clean | **not in scope** | Unit / corner-case agents own schema semantics. |
| **D9** | single global `g_active` (fix UAF) | **X1.2, X1.3, X1.10, X1.12** (TSAN builds) | Reload-storm tests are the UAF detectors. |
| D10 | per-lcore bucket arena | **not in scope** | Perf agent. |
| **D11** | rl_arena GC ordering | **X1.14** | Rule-id reuse/removal lifecycle. |
| **D12** | RCU polish (offline/unregister, timeout) | **X1.4, X4.3, X4.6** | Shutdown + stall path. |
| D13 | L3 offset dynfield | **unit / corner-case agent** | Classifier-level. |
| D14 | L4 offset IHL | **unit / corner-case agent** | Classifier-level. |
| D15 | L4 compound + filter_mask | **unit / corner-case agent** | Classifier-level. |
| **D16** | REDIRECT staging + flush | **X2.5** | TX saturation is the scenario. |
| D17 / P9 | fragment_policy | **corner-case agent** | Malformed packet shapes. |
| D18 | cycle budget min/typ/max | **perf agent** | Not correctness. |
| D19 | misc idle / TAG / fib_lookup | **X2.11** (idle spec under reload) | Rest are perf/unit. |
| D20 / P8 | IPv6 ext headers | **corner-case agent** | Packet shapes. |
| D21 | apply_action NEXT_L4 cliff | **X2.9** (dispatch_unreachable backstop) | D25 is the runtime defence. |
| D22 | EXT_MASK UB | **corner-case agent** | Classifier-level. |
| D23 | RlAction.slot accessor | **unit agent** | Structure sanity. |
| D24 | slot lifecycle | **X1.14** | Slot reuse and counter zeroing. |
| **D25** | apply_action default arms | **X2.9** | Injection + release-build CI gate. |
| D26 | mirror refcnt gate | **not in scope MVP** | Phase 2 with mirror. |
| D27 | IPv6 fragment first/non-first | **corner-case agent** | Packet shapes; counter covered by D31 plumbing in X2.10. |
| **D28** | TX-queue symmetry invariant | **X2.8** | Cold-start validator reject. |
| D29 | drop `want_icmp_code` | **unit agent** | Struct cleanup. |
| **D30** | `rte_rcu_qsbr_check` token/deadline | **X1.4, X1.5, X1.11** | The embarrassing fix — must have dedicated tests. |
| **D31** | truncation guards | **X2.10** | Counter plumbing under load; shapes are corner-case agent. |
| D32 | QinQ outer accept | **corner-case agent** | Shape-level. |
| **D33** | counter consistency invariant | **X1.12, X1.14** | No dangling references; counter survives reload. |
| **D34** | rl_arena refill elapsed clamp | **perf / unit agent** | Numerics; hard to stress-test meaningfully without targeted fault injection. |
| **D35** | single `reload_mutex` | **X1.2, X1.3, X3.10** | The TSAN targets. |
| **D36** | `pending_free` queue | **X1.4, X1.5, X1.10** | Overflow + drain + long-running. |
| **D37** | validator memory budget | **X1.6, X1.7** | Happy path + overflow. |
| **D38** | UDS SO_PEERCRED + inotify filter | **X3.1–X3.9** | The whole security bucket. |

**Not in this agent's scope (handed off to others):**

- D1, D10, D18, D34 → perf agent (throughput, numerics).
- D13, D14, D15, D17, D20, D22, D27, D32 → corner-case / malformed-packet agent.
- D2, D8, D23, D29 → unit agent.
- D4, D7, D26 → out of MVP; tests added when they light up.

**§9.4 corner-case bullet coverage:**

| §9.4 bullet | Test |
|---|---|
| Failed reload | X1.7 |
| Nested / concurrent reload (D35) | X1.2, X1.3, X3.10 |
| Hugepage exhaustion mid-build | X1.8 |
| Mid-burst reload | X1.13 |
| Arena GC ordering (D11) | X1.14 |
| Rule-id reassignment | X1.14 variant |
| Reload timeout (D12+D30+D36) | X1.4, X1.5 |

**§11 failure-mode row coverage:**

| §11 row | Test |
|---|---|
| Bad JSON syntax | (unit agent) + X1.7 (plumbing) |
| Validation error | X1.7, X4.4 |
| Compilation key collision | (unit agent) |
| Hugepage OOM during build | X1.8 |
| Reload timeout | X1.4, X1.5 |
| Mempool exhausted | X2.3 |
| TX ring full | X2.4 |
| Redirect TX full | X2.5 |
| NIC link down | X2.6 |
| Worker stall | X2.1, X4.6 |
| Process crash | X2.2, X4.1 |
| Bypass mode triggered | X4.1, X4.5 |
| PCI error | X2.7 (lab) |
| Reload mid-shutdown | X1.9 |
| sFlow encoder failure | (telemetry agent) |

---

## Fault-injection tooling table

| Tool / mechanism | Used by | Notes |
|---|---|---|
| `LD_PRELOAD` shim on `rte_rcu_qsbr_quiescent` | X1.4, X1.5, X1.10 | Most reliable stuck-worker injection; targeted per-thread via `pthread_self()` check. |
| `gdb` attach + `SIGSTOP` | X2.1, X4.6 | Hard freeze; coarse but easy to script via `gdb -batch`. |
| `-DPKTGATE_CHAOS=1` debug build with `--inject=<site>=<val>` | X2.2, X2.9, X3.10, X4.1 | Compile-gated injection sites; never in release. Sites: `worker_segv_at_packet`, `worker_segv_at_start`, `slow_validate`, `slow_compile`, `bogus_verdict`. |
| `systemd-run --unit=pktgate-chaos ... WatchdogSec=3s Restart=on-failure` | X2.1, X2.2, X4.1, X4.6 | Reproduces production supervision; needs sudo. |
| Pre-allocate hugepages via sacrificial DPDK secondary process | X1.8 | Isolates the OOM path without perturbing system-wide state. |
| `echo N > /sys/.../hugepages/... ` | X1.8 alt | Kernel knob; revert after test. |
| `tc qdisc tbf` on egress | X2.4, X2.5 | Slow consumer emulation. |
| Second `net_pcap` vdev as slow consumer | X2.4, X2.5, X2.6 | Pure-DPDK alternative to tc. |
| `ip link set ... down/up` loop | X2.6 | Requires a real NIC; dev VM has two e1000s, use the non-primary. |
| `echo 1 > /sys/bus/pci/devices/.../remove` | X2.7 | **Lab only** — VirtualBox likely blocks. |
| `inotifywait` on the directory | X3.7, X3.8 (debugging only) | Observer, not injector. |
| `socat UNIX-CONNECT` + `xargs -P` | X1.2, X3.*, X4.* | UDS client storms. |
| `scapy` + `tcpreplay` | X1.13, X2.3, X2.5, X2.10, X3.7, X4.3 | Traffic generation on dev VM via net_pcap. |
| ASAN / UBSAN / TSAN build flavors | **every X1, X3.10 especially** | TSAN is the primary detector for D35 mutex correctness; ASAN catches UAF (D9); UBSAN catches D22-class bugs. Re-run the X1/X3 suite under each flavor in CI nightly. |
| `valgrind --tool=massif` or `rte_malloc_dump_stats` | X1.9, X1.10, X4.3 | Leak detection across many reloads. |
| `/proc/$pid/status` VmRSS polling | X1.4, X1.10 | Cheap leak detector. |
| `bpftrace` on `inotify_add_watch` / `IN_*` | X3.7, X3.8 | Verify the actual event mask; debug aid, not a gate. |
| `setpriv --reuid=N --regid=M` / `sg` | X3.1, X3.2, X3.3 | Impersonate different peers for SO_PEERCRED tests. Needs sudo. |

---

## Dev VM gating

| Category | Dev VM | Lab hardware | Special privilege |
|---|---|---|---|
| X1.1–X1.7 reload chaos | **yes** (all run in CI nightly) | lab re-run at higher scale | sudo (for root cap on hugepages, DPDK bind) |
| X1.8 hugepage starvation | yes (512 MiB on VM is enough to corner the allocator) | lab (stress the bigger numbers) | sudo |
| X1.9 reload mid-shutdown | yes | yes | sudo |
| X1.10 1-hour leak soak | **yes** (nightly only — too slow for per-commit) | lab for scale | sudo |
| X1.11–X1.14 | yes | yes | sudo |
| X2.1 worker stall → bypass | yes (single worker works fine) | yes | sudo + `systemd-run` |
| X2.2 worker SEGV | yes | yes | `-DPKTGATE_CHAOS=1` build |
| X2.3 mempool exhaustion | yes (tiny mempool config) | yes | sudo |
| X2.4 TX ring saturation | yes (tc tbf on net_tap, or slow net_pcap) | lab (real NIC backpressure) | sudo |
| X2.5 D16 REDIRECT saturation | yes | lab for rate correctness | sudo |
| X2.6 NIC link flap | **partial** — works on second NIC or emulated via net_pcap reopen; link-event fidelity is weak on VM | lab for real events | sudo |
| X2.7 PCI error | **lab only** | yes | privileged PCI sysfs access; VirtualBox likely rejects |
| X2.8 D28 symmetry violation | yes (net_null `max_tx_queues=2`) | yes | sudo |
| X2.9 D25 backstop | yes | yes | `-DPKTGATE_CHAOS=1` build |
| X2.10 D31 truncation plumbing | yes | yes | sudo |
| X2.11 idle handler reload | yes | yes | sudo |
| X3.1–X3.6 SO_PEERCRED / socket perm | yes | yes | sudo + extra user accounts |
| X3.7–X3.8 inotify filter | yes | yes | sudo |
| X3.9 oversized UDS payload | yes | yes | none beyond sudo |
| X3.10 concurrent reload race | yes (TSAN build) | yes | `-DPKTGATE_CHAOS=1` build |
| X3.11 activate verb + peer check | yes | yes | sudo + user accounts |
| X4.1 bypass after K crashes | yes | yes | sudo, systemd unit |
| X4.2 standby park | yes | yes | sudo |
| X4.3 graceful shutdown | yes | yes | sudo |
| X4.4 HA anti-pattern reject | yes | yes | none (pure config) |
| X4.5 mirror-mode fallback | **yes for trigger**, **lab for rate correctness** | yes | sudo, bypass unit file |
| X4.6 heartbeat stall | yes | yes | sudo, gdb |

**Dev VM caveat (M1)**: tests that need multi-worker parallelism
(X1.3 three-way race, X3.10, any TSAN race under load) are
restricted to single-worker semantics on the dev VM e1000 path
(no RSS, no multiqueue). That is *sufficient* for the D35 mutex
correctness check (the mutex is a cross-thread primitive between
control threads, not between workers). Re-run under multi-worker
config with a `net_null` vdev for true multi-lcore coverage —
`net_null` does support multiqueue on DPDK 25.11 and is the
preferred synthetic source for these tests.

**Special privileges beyond sudo**: none. All tests run with
root + hugepages + vfio/uio bind (CLAUDE.md — sudo without
password on dev VM).

---

## Open notes for later passes

- **X3.5** (mutating-verb tighter gate) has an ambiguity about
  whether the design re-checks SO_PEERCRED at verb dispatch or
  only at accept. §10.7 reads as "allow-list + SO_PEERCRED at
  accept; mutating verbs additionally require it" — but if the
  accept-time check already covers both classes, the "tighter"
  gate is a no-op in code. Flag for clarification against §10.7
  D38 paragraph; if clarified as "same check, enforced once",
  X3.5 collapses into X3.1/X3.2.
- **X4.5** mirror-mode fallback depends on mirror-ship-phase;
  this is a Phase 2 test (§14).
- **X1.10** VmRSS accounting assumes design never frees
  row memory on slot free (only the slot index cycles, per
  D24). Verify this assumption holds in implementation; if
  the implementation does free rows, the leak rate in X1.10
  differs and the assertion must be tightened.
- **X2.11** relies on D19 idle handler spec being implemented
  as "stay RCU-online during idle". If the implementation
  goes offline in idle, reload timeouts in no-traffic windows
  become a legitimate behavior and X2.11 needs a different
  assertion.
- `pending_full` alert cadence in X1.5 ("once per overflow,
  not per retry") is a spec choice — assert against whatever
  §9.2 / §11 chose. If unspecified, flag for clarification.
