# Functional / integration test plan (draft)

Scope: end-to-end tests that bring up the real `pktgate_dpdk` binary
on the dev VM, push packets through `net_pcap` vdevs, and assert on
observable behaviour (egress pcaps, Prometheus `/metrics`,
`rte_telemetry` UDS, `cmd_socket` JSON, structured log lines).

Out of scope (owned by other agents):
- unit-level tests on parser / validator / compiler / classifier /
  `L2CompoundEntry` / `L4CompoundEntry` in-memory;
- load, cycle-budget, latency-p99, throughput-SLO tests;
- adversarial malformed-packet and truncation corner cases (malformed
  testing here is config-level only);
- chaos / fault injection (SIGKILL storms, hugepage drain, reload
  storms).

The numbering convention is `Fx.y` where `x` groups tests
by theme (bring-up, matching, actions, fragments, reload, control
plane, inotify, telemetry, failure, negatives). Target count: ~110
cases.

## Harness overview

Dev VM is Fedora, VirtualBox, 4 vCPU, 512 x 2 MiB hugepages, 2 x
Intel 82545EM (e1000). By M1 we **do not** shape architecture around
it; for functional tests we accept the single-queue / single-lcore
constraints it imposes and skip multi-queue / RSS surfaces (deferred
to the lab plan).

The harness is pytest + scapy, and runs `pktgate_dpdk` under sudo.
Core mechanics:

- **Ports are `net_pcap` vdevs**, wired via `interface_roles` in the
  test config. For an ingress/egress pair we use
  `net_pcap0,rx_pcap=<in.pcap>,tx_pcap=<out.pcap>` on both sides.
  Mirror / redirect destinations use a third `net_pcap` vdev writing
  its own `tx_pcap`. Sink-only targets may use `net_null`.
- **Per test a fresh temp dir** holds `config.json`, `sizing.json`,
  `in.pcap`, `out.pcap`, `mirror.pcap`, `redirect.pcap`, the
  `/run/pktgate/ctl.sock`-equivalent (we override `--run-dir` to put
  it in the temp dir so tests do not collide).
- **EAL argv** (baseline):
  `--no-huge --no-pci --vdev=net_pcap0,... --vdev=net_pcap1,... -l 0-1`.
  For tests that need real hugepages we drop `--no-huge` and use
  `--file-prefix=<unique>` per test so parallel pytest workers do not
  collide.
- **Worker count**: `--workers=1`. The dev-VM NIC reports
  `max_tx_queues=1` (e1000), and D28 requires symmetric TX queues on
  every port; more than one worker is not functionally testable on
  dev VM and is deferred.
- **Packet synthesis**: scapy on the pytest side writes `in.pcap`
  before launching the binary, then the binary ingests it via
  `net_pcap` in one drain and the harness reads `out.pcap` after
  shutdown (or after a timed flush for reload tests).
- **Metrics scraping**: a helper function does one HTTP GET to
  `http://127.0.0.1:<metrics_port>/metrics` and returns a dict keyed
  by `(metric_name, labels)`. Counters are compared as deltas against
  a pre-exercise snapshot. `rte_telemetry` is accessed via the
  DPDK `dpdk-telemetry.py` UDS (we use a thin subprocess wrapper).
- **`cmd_socket` client**: a tiny Python helper `send_cmd(path, obj)`
  connects to the UDS, writes one JSON line, reads one JSON line back.
- **sFlow collector**: a pytest fixture binds a UDP socket on
  127.0.0.1:<port>, `recv`s with a short timeout, and decodes the
  sFlow v5 datagram with scapy's sFlow module (or a small hand-rolled
  parser if scapy's coverage is insufficient).
- **Log capture**: stderr of the binary is piped into the test, and
  a `find_log_line(regex)` helper scans the JSON lines.

Several tests need the dataplane process to outlive the `in.pcap`
drain so a later event (reload, cmd_socket verb) fires under traffic.
The harness supports this via a `replay.pcap` loop: when
`net_pcap0,rx_iface=<loopback_tap>` is combined with a scapy
`sendp` loop the binary sees continuous traffic. Dev VM has no real
tap needed for the most basic tests; the default path is single-shot
drain of the pcap file.

The binary is built with the `ASAN` flavor for functional CI runs.

## F1 — Bring-up and shutdown

### F1.1 Happy-path EAL init on dev VM
- **Setup**: minimal config (default_behavior=drop, no rules),
  two `net_pcap` vdevs (`upstream_port`, `downstream_port`),
  `sizing` at dev defaults (256/layer). One worker. No hugepages.
- **Action**: start binary; wait for `"ready":true` log line; send
  SIGTERM.
- **Assertion**: exit code 0; log contains `eal_init_ok`,
  `ports_started=2`, `ruleset_published generation=1`; total wall
  time < 2 s; no ASAN / UBSAN findings.
- **Covers**: F1, N5 cold start, D2

### F1.2 Interface role selector — `pci` form
- **Setup**: config with `interface_roles.upstream_port = {"pci": "<bogus BDF>"}`.
- **Action**: start binary.
- **Assertion**: exit non-zero; stderr contains a structured log with
  `role="upstream_port"` and `reason="pci_bind_failed"`; exit happens
  within 2 s (no hang).
- **Covers**: D5, F5, §3a.2 validation

### F1.3 Interface role selector — `vdev` form
- **Setup**: config with all roles as `vdev` (`net_pcap0,...`).
- **Action**: start binary; SIGTERM.
- **Assertion**: clean start, clean exit; log shows role resolution
  matches EAL-registered vdev ports.
- **Covers**: D5

### F1.4 Interface role selector — `name` form
- **Setup**: `upstream_port = {"name": "net_null0"}` with a `net_null`
  vdev declared in EAL argv.
- **Action**: start + SIGTERM.
- **Assertion**: role resolves; port index is the name-lookup result.
- **Covers**: D5, §3a.2

### F1.5 Interface role selector — mixed keys rejected
- **Setup**: role value is `{"pci": "...", "vdev": "..."}`.
- **Action**: start binary.
- **Assertion**: fails with `reason="role_selector_multi_key"` at
  validator stage; no EAL bind attempted; exit non-zero.
- **Covers**: D5, §3a.2, F5

### F1.6 `--standby` enters park mode
- **Setup**: happy config, add `--standby` flag.
- **Action**: start; wait 500 ms; snapshot metrics; then send
  `{"cmd":"status"}` on `cmd_socket`; then SIGTERM.
- **Assertion**: `"state":"standby"` in status response;
  `pktgate_active_generation=1`; `pktgate_port_rx_packets_total=0`
  (no dev_start); log shows `ports configured but not started`.
- **Covers**: D5 warm-standby, §6.1 park mechanism

### F1.7 `--standby` → activate transition under no traffic
- **Setup**: happy config, `--standby`, `in.pcap` with 5 IPv4 pings
  sitting behind the ingress port.
- **Action**: start in standby; verify `out.pcap` empty after 500 ms;
  send `{"cmd":"activate"}`; wait 500 ms; SIGTERM.
- **Assertion**: activate returns `{"result":"ok"}`; `out.pcap`
  contains the 5 packets after activate; logs show
  `rte_eth_dev_start` called after `remote_launch`, not before.
- **Covers**: D5 park mechanism, §6.1

### F1.8 `--standby` activate while standby was never loaded
- **Setup**: `--standby`, config file missing.
- **Action**: start binary.
- **Assertion**: exit non-zero at first parse (the park mode does not
  skip initial validation); log contains `parse_err`.
- **Covers**: D5, §3a.2, §6.1

### F1.9 SIGTERM happy shutdown
- **Setup**: happy config, running ~200 ms.
- **Action**: SIGTERM; wait for exit.
- **Assertion**: exit code 0; log sequence observed: `workers_exit`,
  `qsbr_thread_offline`, `qsbr_thread_unregister`, `ports_stopped`,
  `ruleset_freed`, `eal_cleanup`; total shutdown < 1 s.
- **Covers**: D12, §6.4

### F1.10 SIGINT equivalent to SIGTERM
- **Setup**: happy config.
- **Action**: SIGINT; wait for exit.
- **Assertion**: same assertions as F1.9.
- **Covers**: §6.4

### F1.11 SIGTERM mid-reload — drain cleanly
- **Setup**: happy config; fire a slow reload (large config, many
  rules) via cmd_socket in a background thread, then immediately
  SIGTERM.
- **Assertion**: process exits cleanly within 1 s; log shows either
  `reload_aborted` or `reload_total{result="success"}` followed by
  shutdown; no ASAN findings; `pending_free_depth=0` at exit.
- **Covers**: §9.4 "Reload mid-shutdown", §6.4

### F1.12 Cold-start latency budget smoke
- **Setup**: dev-default sizing; sample 5 runs.
- **Assertion**: each run boots to `ready` in ≤ 5 s wall time (N5).
- **Covers**: N5 cold start

## F2 — Happy-path L2 / L3 / L4 matching

### F2.1 L2 src_mac exact match → drop
- **Setup**: one L2 rule: `{match:{interface:upstream_port, src_mac:"aa:bb:cc:dd:ee:ff"}, action:drop}`.
- **Action**: `in.pcap` = 2 packets, one matching src_mac, one with
  different src_mac.
- **Assertion**: `out.pcap` contains 1 packet (the non-match, passes
  to default_behavior=allow); metric
  `pktgate_rule_packets_total{layer="l2",rule_id="1001"}` = 1;
  `pktgate_rule_drops_total{layer="l2",rule_id="1001",reason="explicit"}` = 1.
- **Covers**: F1 L2, D15 compound, D33

### F2.2 L2 dst_mac exact match → allow
- Setup: `{match:{dst_mac:"...", interface:upstream_port}, action:allow}`.
- Action: single matching packet.
- Assertion: appears in `out.pcap`; counter bumps by 1.
- Covers: F1 L2

### F2.3 L2 vlan_id match
- Setup: rule matches vlan 100; in.pcap = 3 packets (vlan 100, vlan
  200, untagged).
- Assertion: 1 rule-matched packet counted under rule id; 2 passed
  through to L3/default.
- Covers: F1 L2

### F2.4 L2 untagged — vlan match must not fire
- Setup: rule `{vlan_id: 0}` is **rejected** at validator (D6
  sizing has no such meaning). In scope: a rule matching vlan=100
  must not fire on an untagged frame.
- Assertion: untagged frames miss the L2 rule; no counter bump.
- Covers: F1, §5.2 parse semantics

### F2.5 L2 ethertype match (0x0800)
- Rule matches ethertype=0x0800; in.pcap contains IPv4, IPv6, ARP.
- Assertion: IPv4 hits, IPv6 and ARP miss.
- Covers: F1

### F2.6 L2 PCP match on VLAN-tagged frame
- Rule matches vlan=100 AND pcp=5.
- Assertion: a vlan=100 pcp=5 frame hits; vlan=100 pcp=0 misses.
- Covers: F1 L2 pcp

### F2.7 L2 compound — src_mac + vlan + ethertype
- Rule uses all three; filter_mask path exercised.
- Assertion: only a frame matching all three hits; any single-field
  mismatch misses.
- Covers: D15 compound pattern, §5.2

### F2.8 L2 first-match-wins across rules
- Setup: two rules in order: R1 `dst_mac=aa:bb...` action=allow,
  R2 `src_mac=cc:dd...` action=drop. Packet matches both criteria.
- Assertion: only R1 counter bumps; packet is allowed;
  R2 counter is 0.
- **Covers**: F1 first-match-wins, D15, §5.2

### F2.9 L2 miss → proceed to L3
- Setup: one L3 rule matching dst=10.0.0.0/24; L2 has a rule matching
  a different src_mac. Packet does not match any L2 rule but matches
  L3.
- Assertion: L3 counter bumps; L2 counter 0.
- Covers: F1 layer fallthrough

### F2.10 L3 IPv4 dst-prefix /24
- Rule: dst_subnet=10.0.0.0/24 action=drop.
- in.pcap: 10.0.0.5, 10.0.1.5, 10.0.0.255.
- Assertion: 10.0.0.5 and 10.0.0.255 dropped; 10.0.1.5 passes.
- Covers: F1 L3 IPv4, §4.1 `l3_v4` FIB

### F2.11 L3 IPv4 longest-prefix-match
- Rules: R1 10.0.0.0/8 allow, R2 10.0.0.0/24 drop.
- Assertion: 10.0.0.5 hits R2 (longer prefix, FIB semantics);
  10.1.2.3 hits R1.
- Covers: F1 L3, §4.1 DIR-24-8

### F2.12 L3 IPv4 src-prefix secondary FIB [DEFERRED_V2]
- Setup: a rule constraining the IPv4 source prefix
  (`192.168.0.0/16`) action=drop.
- Assertion: only packets originating in 192.168/16 are dropped.
- Covers: F1 L3 src-prefix, `l3_v4_src`
- Status: deferred to v2 — src-prefix secondary probe is a v2
  feature per `review-notes.md` §P10 / §5.3 (M5 C1c, 2026-04-15).
  Not shipping in MVP. The `dst_subnet` rename absorbed the
  primary-key concern; src-prefix secondary needs an independent
  config field, dedicated FIB storage, and a separate filter
  stage in classify_l3.

### F2.13 L3 IPv4 VRF match
- Setup: compound rule with `vrf=7` and a corresponding
  interface-role vrf assignment.
- Assertion: traffic tagged into vrf=7 hits the rule; vrf=0 does not.
- Covers: F1 L3 VRF, `l3_vrf`

### F2.14 L3 IPv6 dst-prefix /64
- Rule: dst=2001:db8::/64 drop.
- in.pcap: one inside /64, one outside.
- Assertion: inside dropped, outside passes.
- Covers: F1 IPv6, P8

### F2.15 L3 IPv6 first-protocol parse — TCP inner
- Setup: IPv6 packet with next_header=TCP; L4 rule matches dport=443.
- Assertion: hits; counter bumps.
- Covers: P8 first-protocol-only, §5.3 IPv6 parse

### F2.16 L3 IPv6 extension header → L4 skipped
- Setup: IPv6 with next_header=hop-by-hop (0); L4 rule matches
  dport=443.
- Assertion: L3 still applies (if a matching L3 rule exists); L4 rule
  does NOT fire; metric
  `pktgate_lcore_l4_skipped_ipv6_extheader_total{lcore="0"}`
  increments by 1.
- Covers: P8 ext-header, D20, §5.3

### F2.17 L4 TCP dport match
- Rule: proto=tcp, dport=443, action=drop.
- Assertion: TCP/443 dropped; TCP/80 passes; UDP/443 passes (proto
  discriminator).
- Covers: F1 L4, D15 compound primary

### F2.18 L4 UDP sport match
- Rule: proto=udp, src_port=53, action=drop.
- Assertion: hits `l4_proto_sport` primary hash.
- Covers: D15, §5.4 probing order

### F2.19 L4 proto-only catch-all
- Rule: proto=udp (no port), action=drop.
- Assertion: all UDP dropped; TCP passes. Hits `l4_proto_only`.
- Covers: D15 selectivity order

### F2.20 L4 TCP dport list → expanded
- Rule: proto=tcp, dst_port=[80,443,8080], action=drop.
- in.pcap: 80, 443, 8080, 25.
- Assertion: first three dropped; 25 passes. Only one rule_id.
- Covers: §4.1 L4 compound, compile-time expansion

### F2.21 L4 TCP sport + dport compound
- Rule: proto=tcp, src_port=12345, dst_port=443, action=drop.
- Assertion: only packets with both ports hit; either alone misses.
- Covers: D15 primary + filter_mask

### F2.22 L4 TCP flags — SYN-only
- Rule: proto=tcp, dst_port=22, tcp_flags={syn:true, ack:false}.
- Assertion: SYN matches, SYN+ACK does not.
- Covers: F1 tcp_flags, L4CompoundEntry.tcp_flags_*

### F2.23 L4 ICMP type match
- Rule: proto=icmp, icmp_type=8 (echo request), action=drop.
- Assertion: echo drops; reply (type 0) passes. ICMP type is packed
  into the sport/dport slot (D29).
- Covers: D14/D29 ICMP packing

### F2.24 L4 ICMP type+code match
- Rule: proto=icmp, icmp_type=3, icmp_code=1 (host unreachable),
  action=drop.
- Assertion: exact type+code drops; type=3 code=0 passes.
- Covers: D29, §5.4 ICMP packing into sport

### F2.25 L4 ICMPv6 match
- IPv6 payload with icmpv6; rule matches icmpv6 type 135 (NS).
- Assertion: fires on type 135 only.
- Covers: P8 + D14

### F2.26 L4 miss → terminal pass → default_behavior=allow
- Setup: one L4 rule (proto=tcp dport=999). Default=allow.
- Packet: TCP dport=22.
- Assertion: passes to egress; neither L2/L3/L4 rule counters move;
  `pktgate_default_action_total{verdict="allow"}` += 1.
- Covers: F1 default, §5.5 TERMINAL_PASS

### F2.27 L4 miss → default_behavior=drop
- Same setup but default=drop.
- Assertion: packet does not appear on egress;
  `pktgate_default_action_total{verdict="drop"}` += 1.
- Covers: F1 default drop

### F2.28 Layer ordering: L2 rule with `next_layer=l3`
- Setup: L2 rule action=allow `next_layer=l3`; L3 rule matches the
  packet's dst-prefix as drop.
- Assertion: packet dropped by L3 (not allowed by L2 terminally).
- Covers: F1 next_layer semantics

### F2.29 Layer ordering: L2 rule terminal allow (no next_layer)
- Setup: L2 rule action=allow without `next_layer`; L3 rule would
  drop the same packet.
- Assertion: packet passes (L2 terminal allow); L3 counter not
  bumped.
- Covers: F1

### F2.30 First-match-wins across L3 rules with overlapping prefixes
- R1 10.0.0.0/24 allow, R2 10.0.0.0/16 drop in config order.
- Assertion: within /24 → R1 allow; outside /24 but inside /16 → R2
  drop. Config-order semantics for equal-prefix-length ties on FIB;
  since prefixes differ this is LPM.
- Covers: F1, §5.3

## F3 — Actions end-to-end

### F3.1 ALLOW action forwards packet
- Covered in F2 baseline; explicit test: ALLOW rule on a specific
  dst_ip; verify presence in `out.pcap` byte-identical to input.
- Covers: §5.5 ALLOW

### F3.2 DROP action removes packet
- Covered in F2 baseline; explicit: rule action=drop;
  `pktgate_rule_drops_total{reason="explicit"}` += N, and the packets
  are absent from egress.
- Covers: §5.5 DROP

### F3.3 TAG — DSCP rewrite on IPv4
- Rule: l3 match, action=`{type:tag, dscp:46}`.
- Assertion: egress packet has DSCP=46 (EF) in ToS byte; IP header
  checksum valid (recomputed via HW offload; for net_pcap vdev the
  harness must verify the mbuf flag and either accept the zero
  checksum as "NIC will fix" or validate if vdev honors cksum
  offload — test asserts the ToS byte is 46<<2 and checksum is either
  recomputed correctly or zeroed-with-offload-flag).
- Covers: §5.5 TAG, D19

### F3.4 TAG — DSCP rewrite on IPv6 (Traffic Class)
- Rule action=`{type:tag, dscp:10}` against an IPv6 destination.
- Assertion: IPv6 TC field = 10 in output; no cksum change (IPv6 has
  no L3 cksum).
- Covers: D19

### F3.5 TAG — PCP rewrite on VLAN-tagged frame
- Rule against a vlan=100 packet: `{tag, pcp:3}`.
- Assertion: egress packet TCI has PCP=3;
  `pktgate_lcore_tag_pcp_noop_untagged_total` unchanged.
- Covers: D19, §5.5 TAG

### F3.6 TAG — PCP rewrite on untagged frame is a counted no-op
- Rule against an untagged packet: `{tag, pcp:3}`.
- Assertion: egress frame still untagged (no tag added);
  `pktgate_lcore_tag_pcp_noop_untagged_total` += 1.
- Covers: D19, §5.5 TAG no-op path

### F3.7 TAG — combined DSCP + PCP on tagged IPv4
- Rule: `{tag, dscp:46, pcp:5}`.
- Assertion: both fields rewritten; other bytes unchanged.
- Covers: §5.5 TAG

### F3.8 TAG — rejected at compile on port without HW ip-cksum
- Setup: TAG rule on an egress port whose driver_caps do not include
  HW ip-cksum. (On dev VM: `net_pcap` does not advertise ip-cksum;
  this test asserts that the validator / compiler rejects the TAG
  rule at publish time with `compile_err` sub-reason
  `tag_cksum_caps_missing`.)
- Assertion: reload fails;
  `pktgate_reload_total{result="compile_err"}` += 1; old ruleset
  still active.
- Covers: §5.5 TAG validator, §6.1 port_init

### F3.9 REDIRECT to mirror_port
- Rule on an L3 dst: `{type:redirect, target_port:"redirect_port"}`.
- Setup: three roles defined (`upstream`, `downstream`,
  `redirect_port`), all `net_pcap` vdevs. Ingress on upstream.
- Assertion: matching packet appears in `redirect.pcap` (from
  redirect_port tx), not in `downstream.pcap`; non-matching packets
  still go to downstream.
- Covers: §5.5 REDIRECT, D16

### F3.10 REDIRECT staging / burst-end flush
- Setup: burst of 24 packets in one pcap; REDIRECT rule hits all of
  them. BURST size is 32 in §5, so they all land in the same burst.
- Assertion: all 24 appear in the redirect pcap, in order;
  `stage_redirect` staging + `redirect_drain` exercised.
- Covers: D16, §5.5

### F3.11 REDIRECT drops on TX-full
- Setup: redirect port is a `net_pcap` vdev with a pcap backing file
  configured as a zero-length tmpfs-mounted file (or the simpler
  variant: use a `net_null` on the redirect role and manipulate the
  descriptor ring via the DPDK test hook — this may need a purpose-
  built test-only `net_backpressure` vdev; if unavailable, this test
  is gated to lab hardware).
- Action: fire enough packets to fill the tx ring.
- Assertion: `pktgate_redirect_dropped_total{lcore,port}` increments
  for the overflow count; mempool-in-use does not leak (mbufs get
  freed, not orphaned).
- Note: if dev-VM cannot easily simulate redirect TX-full, this case
  is deferred to the lab test plan and gets marked `LAB_ONLY`.
- Covers: D16, §11 Redirect TX full row

### F3.12 RATE-LIMIT — allow under limit
- Rule: rate=1 Mbps, burst_ms=10. in.pcap: 10 packets × 100 B over
  simulated 1 s (via scapy timestamps, `net_pcap` replays timestamps).
- Assertion: all 10 forwarded; `pktgate_rule_drops_total{reason=
  "rate"}` = 0.
- Covers: D1/D10 rate-limit, §5.5 RL

### F3.13 RATE-LIMIT — drops above limit
- Same rule, in.pcap: burst of 1000 × 1500 B in < 1 ms.
- Assertion: forwarded count ≈ `burst_bytes / 1500` (within 20 %
  error — D1 Variant A is allowed this tolerance);
  `pktgate_rule_drops_total{reason="rate",rule_id=...}` bumps by
  the drop count. Mirror to `rate_limit_drops` in per-rule snapshot.
- Covers: D1/D10, §4.4

### F3.14 RATE-LIMIT — survives hot reload (rl_arena stability)
- Setup: rule_id 2001 with rate=1 Mbps burst=10 ms; reload same
  config but perturb a comment; run RL test before and after reload;
  second burst should see the same bucket state (approximately — new
  refill deducts the interval).
- Assertion: rule_id 2001's slot is the same before and after (via
  `/pktgate/rules/dump,layer=l3` rte_telemetry); drop ratio does not
  reset to "full burst available" post-reload (the bucket state
  survives per D10/D11).
- Covers: D1, D10, D11 arena GC, D24 slot lifecycle

### F3.15 RATE-LIMIT — slot recycled on rule_id removal
- Setup: reload that removes rule 2001; introspect
  `pktgate_reload_total{result="success"}` += 1; then reload again
  with a fresh rule id 2002 same rate; inspect counter zeroing
  semantics per D11 5b.
- Assertion: rule_id 2002 gets a fresh slot; counter row for the
  freed rule_id 2001 is zeroed (verified via rte_telemetry
  `/pktgate/rules/dump` before shutdown).
- Covers: D11, D24 slot lifecycle, §9.4 step 5b

### F3.16 RATE-LIMIT — `elapsed` clamp on long idle (D34)
- Setup: rate=1 Mbps burst=10 ms. Fire 1 packet, then sleep 5 s,
  then fire another packet.
- Assertion: second packet is allowed (bucket refilled up to burst,
  not overflowed into garbage); no ASAN overflow trap;
  process remains healthy.
- Covers: D34 clamp

### F3.17 MIRROR action rejected at compile time (Phase 1)
- Rule: `{type:mirror, target_port:"mirror_port"}`.
- Action: reload with this config from happy baseline.
- Assertion: reload fails with `compile_err` sub-reason
  `mirror_not_implemented` (or similar); old ruleset still active;
  structured log line carries the rule id and a human-readable
  message.
- Covers: D7 Phase 1 reject, §14.1

### F3.18 Counter — per-layer + per-rule index
- Setup: one L2, one L3, one L4 rule. in.pcap exercises all three.
- Assertion: each counter row (layer,rule_id) bumps independently;
  no cross-talk. Verify via `/metrics` and via
  `/pktgate/rules/dump,layer=...`.
- Covers: D33 counter consistency, §4.3

## F4 — Fragment handling

### F4.1 IPv4 first fragment, `fragment_policy=l3_only`, L3 rule
- Setup: fragmented IPv4 where first fragment carries TCP header.
  L3 rule matches the dst prefix as drop.
- Assertion: first fragment dropped by L3 rule; counter bump.
- Covers: D17/P9 l3_only, §5.3

### F4.2 IPv4 first fragment, L4 rule still fires
- Setup: fragmented IPv4 first-fragment; L4 rule matches tcp dport=80.
- Assertion: first fragment fires the L4 rule normally (first frag
  carries L4 header).
- Covers: D27 first vs non-first symmetry, §5.3/§5.4

### F4.3 IPv4 non-first fragment, `l3_only`, L3 rule matches
- Non-first fragment of same IPv4 datagram.
- Assertion: L3 rule fires; L4 rule does NOT fire;
  `pktgate_lcore_pkt_truncated_total` unchanged.
- Covers: D17, P9, §5.3

### F4.4 IPv4 non-first fragment, `l3_only`, L3 miss → default
- Setup: non-first frag that does not match any L3 rule; default=drop.
- Assertion: dropped under default; `default_action_total{drop}` += 1.
- Covers: D21 NEXT_L4 cliff fix, P9

### F4.5 IPv4 non-first fragment, `fragment_policy=drop`
- Same packet, config with `drop`.
- Assertion: dropped regardless of L3 rules; `rule_drops_total`
  attributed to the fragment policy bucket (mapped to the
  `rule_drops_total{reason="explicit"}` path is NOT correct — frag
  drops go to `default_action_total{verdict="drop"}` per §5.3
  TERMINAL_DROP path; this test asserts the correct counter).
- Covers: D17, §5.3

### F4.6 IPv4 non-first fragment, `fragment_policy=allow`
- Same packet, config with `allow`.
- Assertion: packet appears on egress; L3 and L4 entirely skipped.
- Covers: D17

### F4.7 IPv6 first fragment (Fragment ext, frag_offset=0)
- Setup: IPv6 datagram with Fragment ext header, first fragment
  carries TCP header; L4 rule matches tcp dport=443.
- Assertion: L4 rule fires; `l4_skipped_ipv6_fragment_nonfirst`
  counter NOT bumped; `dyn->l4_extra=8` is exercised (indirect: L4
  rule actually matches, which it can only do if the offset is
  right).
- Covers: D27 first fragment walk, §5.3 IPv6 block

### F4.8 IPv6 non-first fragment
- Setup: same datagram, non-first fragment (frag_offset != 0).
- Assertion: L3 rule still applies; L4 rule does NOT fire;
  `pktgate_lcore_l4_skipped_ipv6_fragment_nonfirst_total{lcore="0"}`
  += 1.
- Covers: D27, §10.3

### F4.9 IPv6 Fragment-ext followed by another ext header
- Setup: IPv6 with Fragment(44) then Routing(43).
- Assertion: conservatively SKIP_L4 per D27; L3 applies; the ipv6
  extheader counter also bumps.
- Covers: D27 chain-after-fragment, P8 scope

### F4.10 fragment_policy schema — invalid value rejected
- Config with `fragment_policy:"yolo"`.
- Assertion: validator rejects; parse_err / validate_err;
  `reload_total{result="validate_err"}` += 1.
- Covers: §3a.2, D17

## F5 — Hot reload

### F5.1 Happy reload via inotify (mv newfile config.json)
- Setup: running binary with config A; rule R1 drops dst=10.0.0.0/24.
- Action: prepare config B with R1 replaced by R2 allowing the same
  prefix; `mv config.B config.json` inside the watched directory.
- Assertion: within 250 ms traffic flows to the new verdict;
  `pktgate_reload_total{result="success"}` += 1;
  `pktgate_active_generation` += 1; no ASAN findings.
- Covers: F4, §6.3, D9, §9.2, D38 IN_MOVED_TO

### F5.2 Happy reload via cmd_socket `{"cmd":"reload"}`
- Same setup, but trigger reload via UDS.
- Assertion: same success signals; reply `{"result":"ok"}`;
  `reload_total{result="success"}` += 1. D35 verifies this is the
  same funnel as F5.1 (no separate deploy pipeline).
- Covers: D35 single funnel, §10.7

### F5.3 Happy reload via `rte_telemetry /pktgate/reload` flag
- Setup: send `dpdk-telemetry.py` command to set the reload flag.
- Assertion: same success signals as F5.1.
- Covers: D35, §10.6

### F5.4 Reload drops no packets mid-traffic
- Setup: continuous traffic via a scapy replay loop on a tap
  (requires the `net_af_packet` variant — on dev VM gated as
  OPTIONAL if `net_af_packet` is unavailable, otherwise use a
  pcap replay that produces a large enough in.pcap that the reload
  lands mid-stream).
- Action: fire a reload while traffic is flowing.
- Assertion: `out.pcap` packet count == in.pcap packet count
  (lossless); no `port_rx_dropped_total` delta attributable to the
  reload window.
- Covers: F4 "no in-flight drops", §9.2, D9

### F5.5 Reload with invalid JSON (parse_err)
- Setup: write a truncated JSON into the watched file (atomic mv).
- Assertion: `reload_total{result="parse_err"}` += 1; old ruleset
  unchanged (`active_generation` unchanged); matching behaviour
  still the old rules.
- Covers: F4 rollback, §6.3

### F5.6 Reload with validator error
- Setup: JSON that parses but fails validation (e.g. unknown
  `default_behavior` value).
- Assertion: `reload_total{result="validate_err"}` += 1; old
  generation intact.
- Covers: F4 rollback, §11

### F5.7 Reload with compile error (key collision)
- Setup: two L2 rules with the same (src_mac, dst_mac, vlan, etype,
  pcp) tuple (compound key collision).
- Assertion: `reload_total{result="compile_err"}` += 1; old
  generation intact; log carries both conflicting rule ids.
- Covers: §11, §9.2 compile stage

### F5.8 Reload with D37 per-rule expansion ceiling exceeded
- Setup: a single rule with `dst_port:[0,1,...,4097]` (4097 port
  expansions — exceeds default `sizing.max_expansion_per_rule=4096`).
- Assertion: `reload_total{result="validate_err"}` += 1; structured
  log sub-reason `expansion_per_rule`; old generation intact.
- Covers: D37, §9.2

### F5.9 Reload with D37 aggregate post-expansion ceiling
- Setup: many rules whose total expanded entries exceed
  `sizing.l4_entries_max`.
- Assertion: `validate_err` sub-reason `aggregate`.
- Covers: D37

### F5.10 Reload with D37 hugepage budget estimate
- Setup: inflated sizing that would require more hugepages than the
  dev VM has (e.g. 64k IPv4 prefixes) combined with a config that
  actually demands them.
- Assertion: `validate_err` sub-reason `hugepage_budget`; failure
  happens in microseconds before compiler touches hugepages.
- Covers: D37

### F5.11 Concurrent reload — inotify and cmd_socket race
- Setup: send a reload via cmd_socket in one thread; atomic-replace
  config.json via `mv` in another thread at roughly the same time.
- Assertion: both reloads complete cleanly; D35 funnel serializes
  them; `reload_total{result="success"}` += 2 (or += 1 if the
  inotify debounce coalesces with the cmd_socket publish — either
  outcome is acceptable, but the assertion is: **no failure**,
  **no hang**, **no UAF**, and the final active generation equals
  whichever config landed last). ASAN + TSAN must both pass.
- Covers: D35 mutex, §9.4 "Nested / concurrent reload"

### F5.12 Reload timeout — D30 path, stuck worker injected
- Setup: happy config with one worker. Use a test-only config flag
  `--test-inject-stuck-worker-ms=2000` (the build exposes this under
  `#ifdef PKTGATE_TESTING`; the worker sleeps 2 s at the top of a
  burst before publishing quiescent).
- Action: fire a reload.
- Assertion: `reload_total{result="timeout"}` += 1;
  `pktgate_reload_pending_free_depth` = 1 after the timeout;
  cmd_socket reply `{"result":"err","reason":"reload_timeout"}`.
- Covers: D12, D30, D36, §9.4 Reload timeout

### F5.13 Pending_free drain on next successful reload
- Setup: continue from F5.12 with the injected stuck worker. Remove
  the stuck injection (via `--test-inject-stuck-worker-ms=0` applied
  through cmd_socket or SIGHUP variant). Fire another reload.
- Assertion: `reload_total{result="success"}` += 1;
  `pending_free_depth` drops back to 0.
- Covers: D36 drain

### F5.14 Pending_free overflow — D36 K_PENDING=8
- Setup: a test build with `K_PENDING=8`. Inject stuck-worker 9×
  back-to-back; each reload times out and pushes.
- Assertion: reloads 1..8 increment `pending_free_depth` to 8; the
  9th reload increments `reload_pending_full_total`; `rs_old` for
  that 9th reload is intentionally leaked (documented alert-loud
  condition).
- Covers: D36 overflow path

### F5.15 Reload when EAL hugepage OOM during build
- Setup: sizing config that would allocate more hugepages than
  available (e.g. by lowering VM hugepages to 128 × 2 MiB first, then
  reloading with a sizing demanding 500 MiB).
- Assertion: `reload_total{result="oom"}` += 1; old generation
  intact; structured log carries `malloc_site` hint.
- Covers: §11, §9.4, D37 (which ideally catches this earlier — this
  test specifically triggers the runtime-allocator OOM **after**
  D37 passes, to exercise the runtime fallback)

### F5.16 Latency SLO — reload < 100 ms typical
- Setup: happy config, small rule set.
- Action: 10 reloads back-to-back, measure end-to-end via cmd_socket
  round-trip.
- Assertion: all 10 under 100 ms p99 (N5); the histogram
  `pktgate_reload_latency_seconds` is populated.
- Covers: N5 hot reload

### F5.17 Reload during `--standby` still works
- Setup: `--standby` mode; reload to a new config.
- Assertion: standby binary accepts the reload;
  `active_generation` bumps; activation (F1.7-style) now uses the
  new ruleset.
- Covers: D5, §6.1

## F6 — Control plane: UDS `cmd_socket`

### F6.1 `{"cmd":"status"}` happy
- Assertion: reply includes `state`, `active_generation`,
  `ruleset_rules{l2,l3,l4}`, `uptime_sec`; JSON-valid.
- Covers: §10.7, F5

### F6.2 `{"cmd":"dump-config"}` returns the current config
- Assertion: reply is a JSON object whose `version` matches the
  on-disk file; round-trip through scapy’s JSON parser.
- Covers: §10.7

### F6.3 `{"cmd":"dump-rule","layer":"l3","id":2001}`
- Assertion: returns match/action fields of rule 2001 in layer l3;
  404-equivalent if id unknown.
- Covers: §10.7

### F6.4 `{"cmd":"counters","layer":"l3","id":2001}`
- Assertion: returns the aggregated snapshot counter row for that
  rule id; values match the per-layer rows exposed via `/metrics`.
- Covers: §10.7, D33

### F6.5 `{"cmd":"reload"}` happy
- Covered by F5.2; this case asserts explicitly that the reply
  comes back after the publish + rcu_check + GC pipeline finishes
  (synchronous round-trip).
- Covers: D35 funnel

### F6.6 `{"cmd":"activate"}` happy
- Covered by F1.7; this case covers the reply shape:
  `{"result":"ok","state":"running"}`.
- Covers: D5, §10.7

### F6.7 Unknown verb → structured error
- Send `{"cmd":"do_the_thing"}`.
- Assertion: reply `{"result":"err","reason":"unknown_verb"}`;
  connection closed; no process crash.
- Covers: §10.7

### F6.8 Malformed JSON → structured error
- Send `"{not json"` followed by newline.
- Assertion: reply `{"result":"err","reason":"parse_err"}` or
  similar; process unaffected.
- Covers: §10.7 robustness

### F6.9 Oversized line → structured error
- Send a JSON object with a 1 MiB padding field.
- Assertion: structured error, connection closed, no OOM.
- Covers: §10.7

### F6.10 Concurrent clients
- Two simultaneous clients, one runs `status`, the other `reload`.
- Assertion: both get clean replies; the reload's mutex (D35) does
  not hold up `status` indefinitely (read-only verbs may be
  implemented without taking reload_mutex — confirm in `/metrics`
  timings; this test simply asserts no deadlock and reasonable
  latency).
- Covers: §10.7, D35

### F6.11 Reject on peer uid mismatch (D38)
- Setup: a second test OS user `pktgate_test2`, not in
  `cmd_socket.allow_gids`. The UDS file mode is 0600 but the test
  has sudo and can chmod it temporarily to 0666.
- Action: reconnect from `pktgate_test2`, send `{"cmd":"reload"}`.
- Assertion: connection accepted but the verb is rejected;
  `pktgate_cmd_socket_rejected_total{reason="peer_uid"}` += 1;
  warn-level log line with `peer_uid`, `peer_pid`, `peer_gid`.
- Covers: D38 part (a)

### F6.12 Reject on peer gid mismatch (D38)
- Same idea but the test user's uid is allow-listed, gid is not.
- Assertion:
  `pktgate_cmd_socket_rejected_total{reason="peer_gid"}` += 1.
- Covers: D38

### F6.13 Read-only verbs allowed for allow-listed peer
- Setup: peer uid/gid allow-listed; send `status` and `dump-config`.
- Assertion: both succeed; no rejected counter bumps.
- Covers: D38 ("read-only verbs allowed for any allow-listed peer")

### F6.14 Mutating verb with right uid wrong gid
- Setup: peer uid matches `pktgate_uid`, gid not allow-listed;
  send `reload`.
- Assertion: rejected with `peer_gid`.
- Covers: D38

### F6.15 cmd_socket survives a failed reload
- Send a reload that will parse_err; then send `status`.
- Assertion: second reply returns normally; socket thread still alive.
- Covers: §10.7

## F7 — inotify behaviour (D38)

### F7.1 `IN_CLOSE_WRITE` on directly-edited file
- Setup: write-replace via `open(path, O_WRONLY); write; close`.
- Assertion: reload fires exactly once; `reload_total{result="success"}`
  += 1.
- Covers: D38 IN_CLOSE_WRITE

### F7.2 `IN_MOVED_TO` on atomic rename (`mv newfile config.json`)
- Covered by F5.1; this case explicitly asserts that one
  `IN_MOVED_TO` event triggers exactly one reload (no dup from
  debounce coalescing).
- Covers: D38 IN_MOVED_TO

### F7.3 No reload on `IN_MODIFY` (partial write)
- Setup: open the watched file O_WRONLY without O_TRUNC; write 10
  bytes of a new config; do NOT close yet.
- Assertion: no reload triggered within 500 ms (IN_MODIFY filtered
  out); `reload_total` unchanged. Then close the fd;
  `IN_CLOSE_WRITE` fires → exactly one reload.
- Covers: D38 inotify filtering, "parser does not see truncated
  mid-edit state"

### F7.4 Directory watch, not file watch — symlink swap
- Setup: config.json is actually a symlink to `config.v1.json`.
  Create `config.v2.json`, `mv -Tf` (rename) the symlink target.
- Assertion: the inotify watch is on the directory, so the watcher
  sees `IN_MOVED_TO config.v2.json`; reload fires.
  Note: because the watch is on the directory, the symlink case
  is explicitly tested so that future code refactors to watch
  the file itself break this test.
- Covers: D38 "watch is on the directory, never on the file", F4 §1.2

### F7.5 Debounce coalesces rapid writes
- Setup: 5 atomic replaces within 50 ms.
- Assertion: at most 1 or 2 reloads fire (not 5); the 150 ms
  debounce window coalesces them.
- Covers: §9.3 debounce

### F7.6 Watched directory race — file removed then re-added
- Setup: `rm config.json` followed immediately by atomic replace.
- Assertion: after the rm the binary logs a warning but does not
  tear down; after the re-add, the next reload succeeds.
- Covers: §9.4 edge, D38

## F8 — Telemetry / counters (D3, D33)

### F8.1 Prometheus `/metrics` endpoint reachable
- GET `http://127.0.0.1:<port>/metrics`.
- Assertion: HTTP 200; body is OpenMetrics; parses via the Python
  `prometheus_client` parser.
- Covers: F6, §10.2

### F8.2 Every §10.3 metric appears
- After a workload that exercises L2, L3, L4, drop, allow, rate-limit,
  reload, cmd_socket_reject, qinq outer, pkt_truncated, frag_nonfirst,
  ipv6_extheader, tag_pcp_noop: scrape once and assert that every
  metric name listed in §10.3 is present. **This is the D33 living
  invariant**; if §10.3 adds a row, this test fails until the
  metric is actually published.
- Covers: D33, §10.3

### F8.3 `rte_telemetry /pktgate/version`
- Use `dpdk-telemetry.py` to read the endpoint.
- Assertion: returns a version string matching the build.
- Covers: §10.6

### F8.4 `rte_telemetry /pktgate/active_generation`
- Scrape after 2 reloads.
- Assertion: gauge = 3.
- Covers: §10.6, F5

### F8.5 `rte_telemetry /pktgate/rules/dump,layer=l3`
- Assertion: returns the list of rule ids currently active in L3.
- Covers: §10.6

### F8.6 `rte_telemetry /pktgate/lcores`
- Assertion: per-lcore stats including
  `packets_processed`, `idle_iters`, `cycles_per_burst` histogram.
- Covers: §10.6

### F8.7 `rte_telemetry /pktgate/ports`
- Assertion: per-port rx/tx totals match `/metrics`.
- Covers: §10.6, D33

### F8.8 `rte_telemetry /pktgate/sizing`
- Assertion: returns the active sizing ceilings (from D37).
- Covers: D37 visibility

### F8.9 sFlow samples land on collector
- Setup: bind a UDP collector on 127.0.0.1:<port>; configure sFlow
  in the binary at `1:1` sample rate and target this collector;
  run 20 packets through.
- Assertion: collector receives at least 20 flow samples (one per
  packet at 1:1); each sample decodes, carries a truncated header
  (128 B max), an ingress ifIndex matching upstream_port, and
  matched rule id in `extended_user`. Counter samples received at
  30 s cadence.
- Covers: F6 sFlow, §10.4

### F8.10 sFlow sampling — `1:1024` rate drops proportionally
- Setup: 2048 packets; sample rate 1:1024.
- Assertion: collector receives approximately 2 samples (±1 due to
  sampling boundary).
- Covers: §10.4

### F8.11 Structured log JSON shape
- Assertion: every stderr line is valid JSON; has `ts`, `level`,
  `msg`, plus context fields for the event.
- Covers: §10.5, F6

### F8.12 Log overflow bumps `pktgate_log_dropped_total`
- Setup: test-only log-generator verb on cmd_socket (ifdef
  PKTGATE_TESTING) that floods the per-lcore log ring.
- Assertion: `pktgate_log_dropped_total` increments;
  dataplane unaffected.
- Covers: §10.5

### F8.13 Counter snapshot ring buffer — slow reader does not block
- Setup: throttle the Prometheus scraper by holding the HTTP
  connection open across 5 snapshot intervals.
- Assertion: dataplane continues unimpeded; scraper eventually reads
  a recent snapshot; `cycles_per_burst` histogram does not show a
  tail spike correlated with the scrape window.
- Covers: §10.1 `N=4` ring, D3

### F8.14 QinQ outer counter (D32)
- Setup: packet with outer 0x88A8 then inner 0x8100 (true QinQ
  stack).
- Assertion: `pktgate_lcore_qinq_outer_only_total{lcore="0"}` += 1;
  L2 classification still proceeds with the outer TCI as vlan.
- Covers: D32, §5.2

### F8.15 `pkt_truncated` counter — config-driven (not packet-level)
- Note: direct truncation packet tests belong to the adversarial
  agent. Here we only assert that the metric exists and is zero in
  a clean run, satisfying the D33 invariant.
- Covers: D33 counter consistency

## F9 — Failure modes and recovery (§11)

### F9.1 Hugepage OOM at startup → fatal exit
- Setup: sizing demanding > available hugepages (boot the VM with
  fewer hugepages).
- Action: start binary.
- Assertion: exit non-zero; log `"fatal":"hugepage_oom"`;
  no half-started ports.
- Covers: §11, §6.1

### F9.2 Mempool exhaustion on ingress
- Setup: dev-default mempool; ingress a burst of 10k packets in one
  pcap.
- Assertion: `pktgate_port_rx_dropped_total{reason="nombuf"}`
  increases; dataplane self-recovers as packets drain.
- Covers: §11 mempool exhausted

### F9.3 TX ring full on primary egress
- Setup: egress is a `net_null` but TX ring backpressure exists via
  `--test-inject-tx-backpressure-ms=500`.
- Assertion: `pktgate_port_tx_dropped_total{port="downstream_port"}`
  increments; ingress continues.
- Covers: §11 TX ring full

### F9.4 NIC link-down simulation
- Setup: `net_pcap` cannot easily simulate link; we use a test-only
  telemetry hook that pokes `link_up=0` in the cached `rte_eth_stats`
  wrapper.
- Assertion: `pktgate_port_link_up{port}` gauge reads 0; warn log;
  self-recovery when simulated back to 1.
- Covers: §11 link down
- Note: this is a test-hook exercise, not a real NIC link test;
  real link-down lives in the lab plan.

### F9.5 Watchdog restart — process crash
- Setup: run under systemd unit (or under a local test harness that
  emulates systemd `Restart=on-failure`). Force-exit the binary via
  test cmd_socket verb `{"cmd":"test-abort"}`.
- Assertion: the supervisor restarts the binary within its backoff
  window; `pktgate_watchdog_restarts_total` increments (carried by
  the supervisor script or read from a persistent file).
- Covers: F7, §6.5, §11

### F9.6 Watchdog stall detection
- Setup: inject a stall via `--test-inject-stuck-worker-ms=∞`; the
  worker's heartbeat counter stops advancing.
- Assertion: systemd `WatchdogSec` (configured short for the test)
  fires SIGABRT; process restarts; `watchdog_restarts_total` += 1.
- Covers: F7, §6.5

### F9.7 Bypass mode transition after K repeated crashes
- Setup: systemd unit configured for `StartLimitBurst=3
  StartLimitAction=exec:pktgate-bypass`. Force 3 crashes.
- Assertion: after the 3rd crash the bypass target is started;
  `pktgate_bypass_active=1`; raw L2 forwarding still traverses
  upstream ↔ downstream.
- Covers: F7 bypass, §11

### F9.8 Recovery out of bypass mode
- Setup: continue from F9.7; operator resets by stopping bypass and
  restarting normal unit.
- Assertion: `pktgate_bypass_active=0`; filtered traffic resumes.
- Covers: §11

## F10 — Phase 1 negative coverage

### F10.1 Mirror verb — validator accepts, compiler rejects
- Covered by F3.17; this case additionally asserts that the parser
  and validator pass (`action:mirror` is a valid schema shape, D7),
  and the rejection is in the compiler stage
  (`reload_total{result="compile_err"}`, not `validate_err`).
- Covers: D7 phase 1 reject

### F10.2 Unknown top-level field rejected
- Config with `{"galactic_federation": true, ...}`.
- Assertion: validate_err with a context field naming the unknown
  key and its JSON path.
- Covers: §3a.2

### F10.3 Unknown action verb rejected
- Rule with `action:{type:"obliterate"}`.
- Assertion: validate_err sub-reason `unknown_action_verb`.
- Covers: §3a.2

### F10.4 `version` mismatch rejected (strict match)
- Config with `"version": 9999`.
- Assertion: validate_err sub-reason `schema_version_mismatch`.
- Covers: §3a.3 Q11

### F10.5 Sizing below hard minimum
- Config with `"rules_per_layer_max": 8` (hard minimum is 16 per D6).
- Assertion: validate_err sub-reason `sizing_below_hard_min`.
- Covers: D6

### F10.6 Role reference to undefined role
- Rule references `"interface":"ghost_port"` not in
  `interface_roles`.
- Assertion: validate_err sub-reason `undefined_role_ref`.
- Covers: D5, §3a.2

### F10.7 Rule with both dst_subnet object-ref and literal
- Config where the same field is specified twice in conflicting ways.
- Assertion: validator rejects; old generation intact.
- Covers: §3a.2

### F10.8 `fragment_policy=allow` is loud
- Setup: config with `fragment_policy:"allow"` — explicitly unsafe.
- Assertion: startup log carries a warn-level line
  `"fragment_policy_unsafe"` with rule-file context. (Config still
  loads; this is a warning, not a rejection.)
- Covers: D17 "`allow` ... explicitly unsafe"

### F10.9 Duplicate rule id within a layer
- Setup: two rules with id 1001 in layer_2.
- Assertion: validate_err sub-reason `duplicate_rule_id`.
- Covers: §3a.2, D33 (counter keying invariant)

### F10.10 L2 rule with no match fields
- Setup: rule `{match:{}, action:drop}`.
- Assertion: either validate_err (empty match set not meaningful) or
  compile_err — whichever the compiler decides; test asserts one of
  the two, never silent acceptance.
- Covers: §3a.2

## Coverage matrix

Decision ID → functional test IDs that exercise it (or UT = must be
unit-tested). D-numbers that are design-internal and have no
observable functional surface are marked IN (internal-only).

| D | Topic | Functional tests | Notes |
|---|---|---|---|
| M1 | Dev VM does not shape arch | all | dev VM runs the subset that fits |
| M2 | Arch ≠ plan | F10.1 mirror reject | Phase-plan behaviour is what is tested |
| D1 | Per-lcore token bucket | F3.12, F3.13, F3.14, F3.16 | hot path correctness is functional; cache-line isolation is UT |
| D2 | C++20 + gcc14/clang18 | build-time; not functional | UT / CI build |
| D3 | Telemetry counting model | F8.* | §10.3 living invariant via F8.2 |
| D4 | rte_flow HW offload | none (Phase 1 disabled) | LAB only once enabled; UT on compiler tier marking |
| D5 | HA compat / interface_roles / --standby | F1.2–F1.8, F5.17, F10.6 | |
| D6 | Sizing runtime | F10.5, F5.8–F5.10 | other sizing surface is UT |
| D7 | Mirror full schema, phase 1 reject | F3.17, F10.1 | mirror dataplane in Phase 2 lab |
| D8 | Clean schema, no pktgate compat | all (schema everywhere) | structural |
| D9 | Single global `g_active` | F5.1–F5.4, F5.11, F5.12 | UAF absence verified via ASAN in CI |
| D10 | Per-lcore bucket arena | F3.12–F3.16 | |
| D11 | rl_arena GC ordering | F3.14, F3.15 | |
| D12 | RCU polish / offline+unregister, bounded sync | F1.9, F5.12 | |
| D13 | l3_offset on VLAN | F2.3, F2.6, F2.7 (implicit: VLAN frames must classify L3 correctly) | UT also recommended |
| D14 | L4 offset via IHL / IPv6 fixed 40 | F2.17–F2.25 | UT also recommended |
| D15 | L4 compound primary + filter_mask | F2.17–F2.22 | UT hash keying |
| D16 | REDIRECT staging / flush | F3.9, F3.10, F3.11 | F3.11 may be LAB_ONLY |
| D17 | fragment_policy | F4.1–F4.6, F4.10, F10.8 | |
| D18 | Cycle budget min/typ/max | none | perf-agent territory |
| D19 | Misc cleanups (fib_lookup single, idle, TAG semantics) | F3.3–F3.7 TAG, F1.9 idle | |
| D20 | IPv6 ext-headers scope | F2.15, F2.16, F4.7–F4.9 | |
| D21 | NEXT_L4 cliff fix | F4.4 | ASAN in all reload runs is the safety net |
| D22 | IPv6 EXT_MASK UB | none functional | UT on mask constant |
| D23 | NUMA awareness | none on dev VM (single socket) | LAB |
| D24 | rl_arena slot lifecycle | F3.14, F3.15, F5.14 | |
| D25 | default arms + -Wswitch-enum | none functional | UT + build flag |
| D26 | Mirror refcnt zero-copy gate | none in Phase 1 (mirror rejected) | Phase 2 LAB; UT on MUTATING_VERBS set |
| D27 | IPv6 first vs non-first fragment | F4.7, F4.8, F4.9 | |
| D28 | TX queue symmetry invariant | F1.1 (implicit, single worker), F1.2 with K<n_workers | functional check is covered by a negative test: config with `--workers=2` on the dev VM's 1-queue e1000 must be rejected at startup — add as F1.x (see note) |
| D29 | L4CompoundEntry.want_icmp_code removal | F2.23, F2.24 ICMP matching still works | UT on struct size |
| D30 | rte_rcu_qsbr_check token + deadline | F5.12 | bundled with D36 |
| D31 | Truncation guards + counter | F8.2 (counter exists), adversarial agent exercises the guard bodies | functional test is F8.2 presence check only; malformed packet drill is adversarial agent |
| D32 | QinQ outer accept | F8.14 | |
| D33 | Counter consistency invariant | F8.2 (living check) | D33 IS the invariant; F8.2 is its test |
| D34 | rl_arena elapsed clamp | F3.16 | |
| D35 | Single reload_mutex | F5.11, F6.10 | |
| D36 | pending_free queue | F5.12, F5.13, F5.14 | |
| D37 | Validator budget pre-flight | F5.8, F5.9, F5.10 | |
| D38 | SO_PEERCRED + IN_CLOSE_WRITE | F6.11–F6.14, F7.1–F7.4 | |

Add one missing test from the D28 row:

### F1.13 D28 TX-queue symmetry validator — `--workers=2` on e1000 rejected
- **Setup**: happy config, `--workers=2`, dev-VM e1000 (or `net_pcap`
  advertising `max_tx_queues=1`).
- **Action**: start binary.
- **Assertion**: exit non-zero; log `reason="tx_queue_symmetry"` with
  `port`, `max_tx_queues`, `n_workers`; no ports left in a running
  state.
- **Covers**: D28, §6.1 port_init

### F1.14 D39 scatter-off + mempool-fit validator — small mempool rejected
- **Setup**: happy config, `--mbuf-size=64` (deliberately too small
  for standard Ethernet frames).
- **Action**: start binary.
- **Assertion**: exit non-zero; log contains `multiseg_rx_unsupported`;
  no ports left in a running state.
- **Covers**: D39, §6.1 port_init

Decisions not directly functionally testable and deferred to unit
tests are: **D2 (build), D18 (cycle budget — perf), D22 (EXT_MASK
UB — static analysis / unit), D23 (NUMA — lab), D25 (switch-enum
compile flag), D26 (refcnt gate — unit on MUTATING_VERBS set plus
phase 2 lab for the dataplane), D29 (sizeof struct)**. The unit-
test agent is responsible for these.

## Dev VM constraints — not functionally testable here

The following architectural surfaces are deliberately out of scope
for the dev VM functional plan; they are deferred to the **lab**
test plan (TRex / E810 / XL710 / CX5/6):

- **Multi-queue RSS spread** — e1000 is single-queue, and by D28 we
  must run with `--workers=1`. All tests in this plan use one
  worker.
- **Symmetric Toeplitz RSS key** (§7) — e1000 does not expose
  Toeplitz. No way to verify symmetric hashing on dev VM.
- **`rte_flow` HW offload** (D4) — no NIC support under
  `uio_pci_generic`; Phase 1 ships with offload disabled, so this is
  a non-issue for the Phase 1 plan.
- **True NIC link-down** (F9.4 is a test-hook, not a real link event).
- **Real line-rate throughput** and **cycle budget** (D18, N1, N2, N3).
- **Mirror dataplane** (D7 / D26) — rejected at compile in Phase 1;
  functional-ish mirror tests will move into the Phase 2 lab plan
  once the compile gate is lifted.
- **Refcnt-zero-copy mirror gate** (D26) — a unit test on
  `MUTATING_VERBS` + `tx_non_mutating` capability; no dev VM surface.
- **HA failover** — external to this process; dev VM has no second
  host; warm-standby parking is in scope (F1.6–F1.8) but active-to-
  active promotion is not.
- **Hardware bypass NIC** — not e1000, not virtio; lab-only.
- **NUMA awareness** (D23) — dev VM is single socket; NUMA behaviour
  is a lab concern.
- **REDIRECT TX-full** (F3.11) — may need a purpose-built
  `net_backpressure` vdev; if unavailable on dev VM it gets marked
  `LAB_ONLY`.
- **Real hugepage OOM during reload** (F5.15) — dev VM has 512 MiB
  of hugepages; the test here boots with a reduced pool to trigger
  the path, but the interesting production hugepage exhaustion
  mode with 2 GiB hugepages and multi-ruleset publishes is lab-only.

All of the above are documented here rather than silently skipped so
that when the lab plan lands, the coverage boundary is explicit and
not discovered by regression.

*End of draft. Test count: ~112 cases (F1: 13, F2: 30, F3: 18,
F4: 10, F5: 17, F6: 15, F7: 6, F8: 15, F9: 8, F10: 10).*
