# Protocol corner-case / adversarial test plan (draft)

Scope: hostile / malformed / edge-case packets and configs that
stress the §5.2 / §5.3 / §5.4 classifiers and the §9 config pipeline.
Every test asserts (a) no crash / no UB / no leak and (b) the exact
`§10.3` counter that MUST fire, with cross-checks that unrelated
counters stay still.

Unless noted otherwise, every packet test is of the form:

    setup: bring dataplane up on net_pcap vdev vA (RX) + vdev vB (TX),
           feed one ruleset per test section, snapshot §10.3 counters
    feed:  scapy one-liner -> vdev vA via wrpcap + inotify deploy OR
           rte_pmd_pcap tx on the paired endpoint
    tick:  wait one burst period, snapshot counters again
    check: target counter == +N; mbuf_in_use returns to baseline;
           pktgate_default_action_total / pktgate_rule_* unchanged
           unless explicitly predicted; process_alive == 1

Harness tag legend:

- `[scapy-pytest]`  = functional pytest on the running dataplane
  (net_pcap vdev, one lcore) — this is the overwhelming majority.
- `[libFuzzer]`     = coverage-guided fuzz target, run under
  AddressSanitizer + UBSanitizer.
- `[gtest]`         = direct unit test against a classifier entry
  point linked into a test binary (no DPDK EAL).

Default ruleset used by C1–C5 unless stated otherwise:

```jsonc
{
  "version": 1,
  "default_behavior": "allow",
  "fragment_policy": "l3_only",
  "pipeline": { "layer_2": [], "layer_3": [], "layer_4": [] }
}
```

This keeps the dataplane in "pass everything unless truncated /
skipped" mode so that D31/D32/D27 counters are the only ones that
should move.

---

## C1 — L2 truncation (D31: `where="l2"` / `where="l2_vlan"`)

All tests `[scapy-pytest]`.

### C1.1 Zero-byte frame
- Packet: `b""` (injected via raw pcap write, bypasses scapy ether
  header).
- Assert: `pkt_truncated_total{where="l2"}` += 1; mbuf freed; no
  other counter moves; process alive.
- Covers: D31

### C1.2 One-byte frame
- Packet: `b"\x01"`
- Assert: `pkt_truncated_total{where="l2"}` += 1.
- Covers: D31

### C1.3 13-byte frame (one byte short of ether header)
- Packet: `b"\xff"*13`
- Assert: `pkt_truncated_total{where="l2"}` += 1.
- Covers: D31

### C1.4 14-byte frame claiming VLAN TPID
- Packet: raw bytes `dst(6) + src(6) + 0x8100` — 14 B total, no
  room for the TCI.
- Assert: `pkt_truncated_total{where="l2_vlan"}` += 1.
- Covers: D31 (`l2_vlan` bucket first test)

### C1.5 15-byte frame, VLAN TPID, one TCI byte present
- Packet: `dst(6) + src(6) + 0x8100 + \x00` — 15 B.
- Assert: `pkt_truncated_total{where="l2_vlan"}` += 1.
- Covers: D31

### C1.6 17-byte frame, VLAN TPID, 3 TCI bytes present
- Packet: `dst(6) + src(6) + 0x8100 + \x00\x64\x08` — 17 B.
- Assert: `pkt_truncated_total{where="l2_vlan"}` += 1.
- Covers: D31

### C1.7 14-byte frame claiming 0x88A8 (S-tag)
- Packet: `dst(6) + src(6) + 0x88A8` — 14 B total.
- Assert: `pkt_truncated_total{where="l2_vlan"}` += 1.
  (D32 says 0x88A8 takes the VLAN-walk path, so the truncation
  bucket is `l2_vlan`, not `l2`.)
- Covers: D31, D32

### C1.8 14-byte frame, non-VLAN ethertype (0x0800)
- Packet: `dst(6) + src(6) + 0x0800` — 14 B — no VLAN walk, would
  dereference IPv4 header and hit `l3_v4` truncation.
- Assert: `pkt_truncated_total{where="l3_v4"}` += 1 (NOT `l2`).
- Covers: D31 (confirms `l2` bucket does not fire when 14 B ether
  is well-formed)

---

## C2 — IPv4 header corner cases (D14, D17, D31)

All `[scapy-pytest]` unless noted.

### C2.1 IPv4 IHL=5 baseline (sanity)
- Packet: `Ether()/IP(ihl=5,src="1.1.1.1",dst="2.2.2.2")/UDP(sport=1,dport=53)/b"x"*8`
- Assert: no truncation counter, no drop; `default_action{allow}` += 1.
- Covers: happy-path smoke so the rest of C2 has a reference.

### C2.2 IPv4 full header but no L4 bytes
- Packet: 34-byte frame — ether(14)+ip(20)+proto=17, but no UDP
  payload: `Ether()/IP(proto=17,ihl=5)` with `pkt_len=34` and 0 B
  L4 ... force via `raw`.
- Assert: `pkt_truncated_total{where="l4"}` += 1 (§5.4 need=4).
- Covers: D14, D31

### C2.3 IPv4 IHL=5, frame cut at 19 B of L3 (1 byte short of IP hdr)
- Packet: ether(14) + first 19 B of IP header only. 33 B total.
- Assert: `pkt_truncated_total{where="l3_v4"}` += 1.
- Covers: D31

### C2.4 IPv4 IHL=5, frame cut at 15 B of L3 (5 bytes short)
- Packet: 29 B total.
- Assert: `pkt_truncated_total{where="l3_v4"}` += 1.
- Covers: D31

### C2.5 IPv4 IHL=15 (60 B claimed) in a 40 B packet
- Packet: ether(14) + raw 20 B where `version_ihl=0x4F`.
- Assert: `pkt_truncated_total{where="l4"}` += 1 (we pass the L3 20 B
  guard but `l4off = l3off + 60 = 74` > `pkt_len = 34`).
- Covers: D14, D31

### C2.6 IPv4 IHL=4 (bad, smaller than minimum)
- Packet: `Ether()/IP(ihl=4,...)` hand-crafted with version_ihl=0x44.
- Assert: `pkt_truncated_total{where="l3_v4"}` += 1 (D31 explicit
  `IHL<5` reject).
- Covers: D14, D31

### C2.7 IPv4 IHL=0
- Packet: version_ihl=0x40, hand-crafted.
- Assert: `pkt_truncated_total{where="l3_v4"}` += 1.
- Covers: D31 (`IHL<5` reject)

### C2.8 IPv4 version != 4 but ethertype = 0x0800 (spoof)
- Packet: `Ether()/IP()` with `version_ihl=0x65` (version=6 claimed
  under EtherType IPv4).
- Current design: §5.3 does not verify the version nibble — the
  IHL check still runs. `version_ihl & 0x0F = 5` — so the packet
  passes the guard and is treated as IPv4. Document this behavior.
- Assert: no truncation, L3 lookup runs, miss → default.
- Flag: if the design later adds a `version == 4` check this test
  flips to `pkt_truncated_total{where="l3_v4"}` — update the
  test at that time.
- Covers: D14 scope delimitation.

### C2.9 IPv4 with IHL=6, valid 4 B option (record-route stub)
- Packet: `Ether()/IP(ihl=6, options=IPOption_RR(length=4,pointer=4))/TCP(dport=80)`.
- Setup: L4 rule `{l3_proto:tcp, dst_port:80, action:drop}`.
- Assert: `pktgate_rule_drops_total{layer=l4,rule_id=X}` += 1 (L4
  offset must be 14+24=38, reading TCP header correctly).
- Covers: D14 regression — this is the flagship test for IHL.

### C2.10 IPv4 with IHL=15, 40 B of options, TCP dport=443
- Packet: `Ether()/IP(ihl=15, options=[NOP]*40)/TCP(dport=443)`.
- Setup: L4 rule on dport=443.
- Assert: L4 rule fires. L4 offset = 14+60=74.
- Covers: D14

### C2.11 IPv4 non-first fragment under `fragment_policy=l3_only`
- Packet: `Ether()/IP(frag=185, flags=0, proto=17)/Raw(b"x"*20)` —
  13-bit offset=185, MF=0, last fragment.
- Setup: default (l3_only), no L3 rules.
- Assert: SKIP_L4, L3 miss → `default_action{allow}` += 1. No
  truncation, no drop. `l4_skipped_ipv6_fragment_nonfirst` is NOT
  bumped (IPv4 has no analogous named counter; the SKIP_L4 path is
  silent for v4, flag as observability gap if desired).
- Covers: D17, D21

### C2.12 IPv4 non-first fragment under `fragment_policy=drop`
- Packet: same as C2.11.
- Setup: `fragment_policy="drop"`.
- Assert: `pktgate_default_action_total` unchanged;
  `pktgate_rule_drops_total{reason=explicit}` unchanged; mbuf freed;
  drop is via `TERMINAL_DROP` direct (no rule fired — this exposes a
  missing observability row, flag for §10.3). For the test, we
  accept "no user counter moves, packet gone".
- Covers: D17 `FRAG_DROP`

### C2.13 IPv4 non-first fragment under `fragment_policy=allow`
- Packet: same as C2.11.
- Setup: `fragment_policy="allow"`.
- Assert: `pktgate_default_action_total{verdict=allow}` += 1 (via
  `TERMINAL_PASS` before L3 runs — note: the §5.3 IPv4 block
  returns `TERMINAL_PASS` on `FRAG_ALLOW` regardless of L3
  match. That's a spec behavior, document and assert accordingly).
- Covers: D17 `FRAG_ALLOW`

### C2.14 IPv4 first fragment (MF=1, offset=0) under `l3_only`
- Packet: `Ether()/IP(flags="MF", frag=0, proto=17)/Raw(8 B UDP)`.
- Setup: default.
- Assert: L4 classifier runs normally, L4 miss → default allow.
- Covers: D17 (first fragment must NOT be SKIP_L4 on v4)

### C2.15 IPv4 first fragment (MF=1, offset=0) with L4 rule
- Packet: `Ether()/IP(flags="MF", frag=0, proto=17)/UDP(dport=53)`.
- Setup: L4 rule on dport=53 drop.
- Assert: L4 rule fires, dropped.
- Covers: D17 regression (first frag must reach L4)

### C2.16 IPv4 single fragment (DF=1, MF=0, offset=0)
- Packet: `Ether()/IP(flags="DF", proto=6)/TCP(dport=80)`.
- Assert: normal classification, L4 rule fires.
- Covers: sanity — not a fragment.

### C2.17 IPv4 MF=0, offset != 0 (last fragment)
- Packet: `Ether()/IP(flags=0, frag=100, proto=17)/Raw("payload")`.
- Setup: default `l3_only`.
- Assert: SKIP_L4 path — L3 runs, L3 miss → default allow.
- Covers: D17

### C2.18 IPv4 MF=1, offset != 0 (middle fragment)
- Packet: `Ether()/IP(flags="MF", frag=64, proto=17)`.
- Setup: default.
- Assert: SKIP_L4 path.
- Covers: D17

### C2.19 IPv4 frag_offset > datagram size (pathological)
- Packet: `Ether()/IP(flags=0, frag=8100, proto=17)` — offset claims
  64 KiB past origin.
- Setup: default.
- Assert: behaves identical to any non-first fragment — SKIP_L4
  under `l3_only`. No special handling, no crash. Document that
  pktgate-dpdk does NOT attempt reassembly sanity on fragment
  offsets.
- Covers: D17 robustness

### C2.20 IPv4 + TCP with only 2 B of transport header
- Packet: ether(14)+ip(20)+2 B only. 36 B total.
- Assert: `pkt_truncated_total{where="l4"}` += 1 (need=4).
- Covers: D31

### C2.21 IPv4 + ICMP with only 1 B (type but no code)
- Packet: ether(14)+ip(20, proto=1)+1 B. 35 B.
- Assert: `pkt_truncated_total{where="l4"}` += 1 (need=2 for ICMP).
- Covers: D31

### C2.22 VLAN-tagged IPv4 with IHL=6 (D13 + D14 compound)
- Packet: `Ether()/Dot1Q(vlan=100)/IP(ihl=6, options=IPOption_RR(length=4,pointer=4))/UDP(dport=53)`.
- Setup: L4 rule on dport=53.
- Assert: L4 rule fires. l3_offset=18, L4 offset = 18+24=42.
- Covers: D13, D14 regression compound.

### C2.23 QinQ outer + IPv4 (D32 + D13 compound)
- Packet: raw ether with TPID=0x88A8 vlan=200, then IP+TCP dport=80.
- Setup: L3 rule on dst IP /32.
- Assert: `qinq_outer_only_total` NOT bumped (inner ethertype is
  0x0800, not another VLAN). `l3_offset=18`, L3 rule fires.
- Covers: D13, D32

---

## C3 — IPv6 extension headers and fragments (D20, D27, D31)

Per P8, Phase 1 is first-protocol-only. Every extension header
value in `EXT_MASK_LT64` must fire `l4_skipped_ipv6_extheader`,
and each of the four ≥64 explicit values must do the same.
Fragment (44) is the D27 special case.

All `[scapy-pytest]`.

### C3.1 IPv6 baseline, TCP, no ext hdr
- Packet: `Ether()/IPv6(nh=6)/TCP(dport=443)`.
- Setup: L4 rule dport=443 drop.
- Assert: rule fires; no skip counter.
- Covers: sanity.

### C3.2 IPv6 truncated (39 B after L2)
- Packet: ether(14) + raw 39 B pretending to be v6.
- Assert: `pkt_truncated_total{where="l3_v6"}` += 1.
- Covers: D31

### C3.3 IPv6 truncated (40 B + no L4)
- Packet: `Ether()/IPv6(nh=6)` with `pkt_len=54`, 0 B L4.
- Assert: `pkt_truncated_total{where="l4"}` += 1 (need=4).
- Covers: D31

### C3.4 IPv6 next_header=0 (Hop-by-Hop)
- Packet: `Ether()/IPv6(nh=0)/IPv6ExtHdrHopByHop()/TCP(dport=80)`.
- Assert: `l4_skipped_ipv6_extheader` += 1; L3 runs; L4 skipped.
- Covers: D20, first-proto-only

### C3.5 IPv6 next_header=43 (Routing)
- Packet: `Ether()/IPv6(nh=43)/IPv6ExtHdrRouting()/TCP(dport=80)`.
- Assert: `l4_skipped_ipv6_extheader` += 1.
- Covers: D20

### C3.6 IPv6 next_header=50 (ESP)
- Packet: `Ether()/IPv6(nh=50)/Raw(b"\x00"*16)`.
- Assert: `l4_skipped_ipv6_extheader` += 1.
- Covers: D20

### C3.7 IPv6 next_header=51 (AH)
- Packet: `Ether()/IPv6(nh=51)/Raw(b"\x00"*16)`.
- Assert: `l4_skipped_ipv6_extheader` += 1.
- Covers: D20

### C3.8 IPv6 next_header=60 (Destination Options)
- Packet: `Ether()/IPv6(nh=60)/IPv6ExtHdrDestOpt()/UDP(dport=53)`.
- Assert: `l4_skipped_ipv6_extheader` += 1.
- Covers: D20

### C3.9 IPv6 next_header=135 (Mobility) — explicit ≥64 list
- Packet: `Ether()/IPv6(nh=135)/Raw(b"\x00"*8)`.
- Assert: `l4_skipped_ipv6_extheader` += 1 (explicit OR clause,
  NOT via mask — D22 UB proof).
- Covers: D20, D22

### C3.10 IPv6 next_header=139 (HIP)
- Packet: `Ether()/IPv6(nh=139)/Raw(b"\x00"*8)`.
- Assert: `l4_skipped_ipv6_extheader` += 1.
- Covers: D20, D22

### C3.11 IPv6 next_header=140 (shim6)
- Packet: `Ether()/IPv6(nh=140)/Raw(b"\x00"*8)`.
- Assert: `l4_skipped_ipv6_extheader` += 1.
- Covers: D20, D22

### C3.12 IPv6 next_header=253 (experimental)
- Packet: `Ether()/IPv6(nh=253)/Raw(b"\x00"*8)`.
- Assert: `l4_skipped_ipv6_extheader` += 1.
- Covers: D20, D22

### C3.13 IPv6 next_header=254 (experimental)
- Packet: `Ether()/IPv6(nh=254)/Raw(b"\x00"*8)`.
- Assert: `l4_skipped_ipv6_extheader` += 1.
- Covers: D20, D22

### C3.14 IPv6 Fragment ext, first fragment (offset=0), TCP
- Packet: `Ether()/IPv6(nh=44)/IPv6ExtHdrFragment(offset=0, m=1, nh=6)/TCP(dport=443)`.
- Setup: L4 rule on dport=443 drop.
- Assert: rule fires; `l4_skipped_ipv6_fragment_nonfirst` NOT
  bumped; `l4_skipped_ipv6_extheader` NOT bumped; `l4_extra=8` → L4
  offset = 18-tag? no tag = 14 + 40 + 8 = 62.
- Covers: D27 (critical regression — first frag must reach L4)

### C3.15 IPv6 Fragment ext, non-first (offset=185), UDP
- Packet: `Ether()/IPv6(nh=44)/IPv6ExtHdrFragment(offset=185, m=0, nh=17)/Raw("tail")`.
- Setup: default l3_only.
- Assert: `l4_skipped_ipv6_fragment_nonfirst` += 1; L4 skipped;
  default applies.
- Covers: D27

### C3.16 IPv6 Fragment ext, first, nh=44 (nested fragment)
- Packet: `Ether()/IPv6(nh=44)/IPv6ExtHdrFragment(offset=0, m=1, nh=44)/Raw(b"\x00"*8)`.
- Assert: `l4_skipped_ipv6_extheader` += 1 (D27 nested-frag → SKIP_L4
  via the "ext-after-fragment" branch); no crash.
- Covers: D27 nested case

### C3.17 IPv6 Fragment ext, first, nh=0 (Hop-by-Hop after Fragment)
- Packet: `Ether()/IPv6(nh=44)/IPv6ExtHdrFragment(offset=0, m=1, nh=0)/IPv6ExtHdrHopByHop()/TCP()`.
- Assert: `l4_skipped_ipv6_extheader` += 1 (ext-after-fragment
  under first-proto-only → SKIP_L4).
- Covers: D27

### C3.18 IPv6 Fragment ext truncated (only 4 B of 8 present)
- Packet: `Ether()/IPv6(nh=44)` followed by 4 raw bytes only.
  Total = 14+40+4=58 B.
- Assert: `pkt_truncated_total{where="l3_v6_frag_ext"}` += 1.
- Covers: D31, D27

### C3.19 IPv6 Fragment ext, 0 B of it present (48 B total after L2)
- Packet: `Ether()/IPv6(nh=44)` with `pkt_len=54` (no frag ext at
  all).
- Assert: `pkt_truncated_total{where="l3_v6_frag_ext"}` += 1.
- Covers: D31

### C3.20 VLAN-tagged IPv6 first fragment with TCP (D13+D27 compound)
- Packet: `Ether()/Dot1Q(vlan=100)/IPv6(nh=44)/IPv6ExtHdrFragment(offset=0, m=1, nh=6)/TCP(dport=443)`.
- Setup: L4 rule on dport=443.
- Assert: rule fires; l3_offset=18, l4_extra=8, L4 offset=18+40+8=66.
- Covers: D13, D27 compound (the flagship combined regression)

### C3.21 IPv6 Fragment ext, `nh` field swapped to an unknown proto
- Packet: first-frag with `nh=253`.
- Assert: `l4_skipped_ipv6_extheader` += 1 (253 in explicit
  ≥64 list).
- Covers: D27, D22

### C3.22 IPv6 jumbo (9000 B) with TCP
- Packet: `Ether()/IPv6(nh=6)/TCP()/b"x"*8900`.
- Requires: mbuf mempool data_room ≥ 9000 OR multi-seg handling.
  If mempool is 2048 B, this test transitions into C6 (multi-seg).
- Assert: normal classification (no truncation); L4 rule (if any)
  fires; `process_alive`.
- Covers: jumbo + possible multi-seg path

---

## C4 — VLAN / QinQ (D32)

All `[scapy-pytest]`.

### C4.1 Single 802.1Q VLAN (0x8100), untagged inner (pure sanity)
- Packet: `Ether()/Dot1Q(vlan=100)/IP()/UDP(dport=53)`.
- Setup: L2 rule on vlan_id=100 allow.
- Assert: L2 rule fires.
- Covers: baseline

### C4.2 Single 802.1ad S-tag (0x88A8), inner ethertype IPv4
- Packet: raw bytes: `dst+src+0x88A8+tci(vlan=200)+0x0800+ip+udp`.
- Setup: L3 rule on dst /32.
- Assert: L3 rule fires; `qinq_outer_only_total` NOT bumped (inner
  ethertype 0x0800 is NOT another VLAN); `l3_offset=18`.
- Covers: D32 — S-tag must be accepted without QinQ event.

### C4.3 True QinQ: S-tag (0x88A8) + C-tag (0x8100)
- Packet: `dst+src+0x88A8+tci(200)+0x8100+tci(50)+0x0800+ip+udp`.
- Assert: `qinq_outer_only_total` += 1; inner ethertype `0x8100`
  NOT drilled; L3 classification runs on outer offset 18 which
  will read the inner VLAN tag bytes as IPv4 header — that's a
  misread BUT the design says "L3 still runs on outer l3_offset=18".
  Real test assertion: the packet is not dropped (no truncation),
  L3 miss, default allow. The `qinq_outer_only_total` counter is
  the observability for this.
- Cover edge: this test also asserts `pkt_truncated_total{where="l3_v4"}`
  stays 0 (the inner 4 B TCI happens to have `version_ihl` nibble
  under most test TCI values that look like IHL>=5, which can be
  engineered. Pick a TCI value `0x00C8 (vlan=200)` so first byte
  of inner-as-"IP" = 0x00 → IHL=0 → D31 IHL reject → counter DOES
  fire in `l3_v4`). This test needs two variants:
  - **C4.3a** — TCI engineered so first "IP" byte has IHL<5 →
    `pkt_truncated_total{where="l3_v4"}` += 1.
  - **C4.3b** — TCI engineered so first "IP" byte has IHL>=5 →
    L3 miss, default allow, no truncation.
  Both variants assert `qinq_outer_only_total` += 1.
- Covers: D32 (critical)

### C4.4 QinQ: S-tag + S-tag (0x88A8 + 0x88A8)
- Packet: similar, inner is again 0x88A8.
- Assert: `qinq_outer_only_total` += 1 (inner is VLAN TPID).
- Covers: D32

### C4.5 QinQ: C-tag + C-tag (0x8100 + 0x8100) — "Q-in-Q with two C-tags"
- Packet: similar, outer 0x8100 and inner 0x8100.
- Assert: `qinq_outer_only_total` += 1.
- Covers: D32

### C4.6 VLAN TCI with DEI bit set
- Packet: `Ether()/Dot1Q(vlan=100, id=1)/IP()/UDP()`. DEI=1.
- Decision: design doesn't mention DEI — test documents that DEI is
  masked out (we only read `tci & 0x0FFF` for vlan and `(tci>>13)&0x7`
  for pcp; DEI bit 12 is ignored). Assert: L2 rule on vlan=100 fires
  normally; no counter anomaly.
- Covers: DEI semantics decision point.

### C4.7 VLAN TCI with PCP=7 (highest priority)
- Packet: `Ether()/Dot1Q(vlan=50, prio=7)/IP()/UDP()`.
- Setup: L2 rule with want_pcp=7.
- Assert: L2 rule fires.
- Covers: PCP parse.

### C4.8 Triple-tagged (0x8100 + 0x8100 + 0x8100) — deeper than QinQ
- Packet: three 0x8100 tags, then IP.
- Assert: First tag consumed, inner ethertype=0x8100 →
  `qinq_outer_only_total` += 1; third tag not walked; L3 runs on
  garbage at offset 18. No crash; behavior same as C4.3a/b depending
  on bytes.
- Covers: D32 — deeper stacks must not crash.

### C4.9 VLAN-tagged packet, VLAN walk into 14+4=18 B frame
- Packet: raw 18 B, TPID=0x8100, but no inner ethertype bytes.
- Actually 18 B is exactly ether(14)+vlan(4), with `vh->eth_proto`
  reading the last 2 B of that 18 B window. OK.
- Assert: no truncation counter (the 18 B threshold is the D31
  `l2_vlan` bound). L3 runs on the inner ethertype read from the
  TCI-adjacent bytes, almost certainly garbage, defaults to
  non-IP, `TERMINAL_PASS`.
- Covers: boundary test on D31 `l2_vlan` edge.

### C4.10 VLAN TPID 0x8100 inside a 17 B frame
- Packet: raw 17 B, TPID=0x8100.
- Assert: `pkt_truncated_total{where="l2_vlan"}` += 1.
- Covers: D31 edge

---

## C5 — Fragment policy matrix (D17, D27)

Explicit `fragment_policy × v4/v6 × first / non-first × rules-present`
matrix. 12 base cells + a few edge cases.

All `[scapy-pytest]`.

### C5.1 v4 first `l3_only` L3 miss
- Packet: `IP(flags=MF, frag=0)/UDP(dport=53)`; no rules.
- Assert: L4 runs, L4 miss, default allow.

### C5.2 v4 first `l3_only` L3 hit
- Packet: same.
- Setup: L3 rule on dst /32, action drop.
- Assert: L3 rule fires, dropped.

### C5.3 v4 first `l3_only` L4 rule hit
- Setup: L4 rule dport=53.
- Assert: L4 rule fires.

### C5.4 v4 non-first `l3_only` no rules
- Packet: `IP(flags=0, frag=100)/Raw()`; default.
- Assert: SKIP_L4, L3 miss, default allow.

### C5.5 v4 non-first `l3_only` L3 rule hit
- Setup: L3 rule on dst /32.
- Assert: L3 rule fires (fragment carries dst IP, L3 matches).

### C5.6 v4 non-first `l3_only` L4 rule would hit (first frag)
- Setup: L4 rule dport=53. Fragment has no L4 header.
- Assert: L4 skipped, L3 miss, default allow. L4 rule does NOT
  fire (first-match-wins + SKIP_L4 semantics).

### C5.7 v4 first `drop`
- Setup: `fragment_policy=drop`.
- Assert: terminal drop, mbuf freed, no rule fires.

### C5.8 v4 non-first `drop`
- Assert: same.

### C5.9 v4 first `allow`
- Setup: `fragment_policy=allow`.
- Assert: TERMINAL_PASS → default allow (L3/L4 skipped entirely).

### C5.10 v4 non-first `allow`
- Assert: same.

### C5.11 v6 first frag `l3_only` L4 rule hit
- Packet: C3.14.
- Assert: L4 rule fires.

### C5.12 v6 non-first `l3_only`
- Packet: C3.15.
- Assert: `l4_skipped_ipv6_fragment_nonfirst` += 1; L3 miss →
  default.

### C5.13 v6 first `drop`
- Setup: `fragment_policy=drop`.
- Packet: first-frag.
- Assert: terminal drop.

### C5.14 v6 non-first `drop`
- Assert: terminal drop.

### C5.15 v6 first `allow`
- Setup: `fragment_policy=allow`.
- Assert: TERMINAL_PASS → default allow.

### C5.16 v6 non-first `allow`
- Assert: same.

### C5.17 v4 non-first fragment with L3 hit that has `next_layer=l4`
- Setup: L3 `allow, next_layer=l4` rule on dst /32; L4 rule drop
  dport=53; fragment `l3_only`.
- Assert: L3 rule runs, `next_layer=l4` is set but SKIP_L4 is
  latched — resulting behavior: after L3 `allow` with next_layer=l4
  and SKIP_L4 set, §5.3 still sets `verdict_layer = TERMINAL_PASS`
  on L3 miss... but on L3 HIT with `next_layer=l4`, what happens?
  **Expected (from D21):** `allow` with `next_layer=l4` + SKIP_L4
  latched must NOT cause `NEXT_L4` dispatch. Verify the spec: if
  L3 hit latches NEXT_L4 and SKIP_L4 is set, §5.1 dispatcher must
  treat SKIP_L4 as a branch to §5.4 that short-circuits with
  TERMINAL_PASS (§5.4 first line checks `SKIP_L4`).
- Assert: L4 rule does NOT fire, L3 rule's allow applies, TX.
- Covers: D21 cliff regression — the very bug that prompted D21.

Matrix total: 12 base + 4 edge = 16 cells.

---

## C6 — L4 / ICMP / transport corner cases (D15, D29)

All `[scapy-pytest]`.

### C6.1 TCP SYN only, dport=443
- Packet: `Ether()/IP()/TCP(dport=443, flags="S")`.
- Setup: L4 rule `{proto:tcp, dport:443, tcp_flags:{syn:true}, drop}`.
- Assert: rule fires via compound filter_mask check.
- Covers: D15 compound with TCP_FLAGS secondary.

### C6.2 TCP FIN, dport=443 (same rule, wrong flags)
- Packet: `Ether()/IP()/TCP(dport=443, flags="F")`.
- Setup: same rule as C6.1.
- Assert: rule does NOT fire (filter_mask mismatch on tcp_flags);
  L4 miss; default allow.
- Covers: D15 secondary check correctness.

### C6.3 UDP dport=53 wildcard src
- Setup: L4 rule `{udp, dport:53, drop}` (no src_port).
- Assert: matches any sport.
- Covers: D15 — the real "why we switched to compound" regression.

### C6.4 UDP dport=53 with src_port=1234 constraint
- Setup: `{udp, dport:53, src_port:1234, drop}`.
- Packet: src=1234 → drop; src=5678 → miss.
- Assert: two sub-cases, counters separate.
- Covers: D15

### C6.5 ICMP echo request (type=8, code=0)
- Packet: `Ether()/IP()/ICMP(type=8, code=0)`.
- Setup: L4 rule `{proto:icmp, dst_port:8, drop}` — packing scheme
  from §5.4 puts ICMP type in dport slot (D29).
- Assert: rule fires.
- Covers: D29

### C6.6 ICMP dest unreachable, code=3 (port unreachable)
- Packet: `Ether()/IP()/ICMP(type=3, code=3)/IP()/UDP()`.
- Setup: L4 rule `{proto:icmp, dst_port:3, src_port:3, drop}`
  (type=3 → dport, code=3 → sport per D29 packing).
- Assert: rule fires via secondary `want_src_port` match.
- Covers: D29 — the flagship "ICMP code in sport slot" test.

### C6.7 ICMPv6 echo (type=128, code=0)
- Packet: `Ether()/IPv6()/ICMPv6EchoRequest()`.
- Setup: L4 rule `{proto:icmpv6, dst_port:128, drop}`.
- Assert: rule fires.
- Covers: D29 for v6.

### C6.8 ICMP with 2 B exactly (type+code, no body)
- Packet: `Ether()/IP(proto=1)/Raw(b"\x08\x00")`.
- Assert: L4 classifier runs without truncation (need=2 satisfied).
- Covers: D31 lower-bound

### C6.9 SCTP (proto=132), port pair
- Packet: `Ether()/IP()/SCTP(dport=2905)` or raw with SCTP header.
- Setup: L4 rule `{proto:sctp, dst_port:2905, drop}`.
- Assert: rule fires (4 B port pair read works for SCTP too — first
  4 B of SCTP common header are sport/dport, same offsets as
  TCP/UDP).
- Covers: SCTP shared read path (documented in D review)

### C6.10 GRE (proto=47) SKIP_L4-ish behavior
- Packet: `Ether()/IP(proto=47)/Raw()`.
- Setup: L4 rule `{proto:gre}` — unknown at primary lookup, falls
  through to `l4_proto_only`.
- Assert: if a rule matches proto=47 in l4_proto_only, it fires;
  else default. The `need=0` branch means no truncation read;
  compound still runs.
- Covers: D15 catch-all tier.

### C6.11 ESP (proto=50) over IPv4 (NOT IPv6 ext hdr — L4 ESP)
- Packet: `Ether()/IP(proto=50)/Raw(b"\x00"*16)`.
- Assert: proto=50 hits `l4_proto_only`; no truncation (need=0);
  rule fires or defaults.
- Covers: v4 ESP (distinct from v6 ext hdr of same value).

### C6.12 AH (proto=51) over IPv4
- Similar.
- Covers: v4 AH.

### C6.13 Raw IP (proto=0) over IPv4
- Packet: `Ether()/IP(proto=0)`.
- Assert: no truncation, fallthrough.
- Covers: unknown proto smoke.

### C6.14 Multi-seg mbuf chain (`pkt_len != data_len`)
- Setup: Construct a chained mbuf manually via a helper C harness
  linked into the test binary `[gtest]` — allocate two mbufs from
  the mempool, chain them with `rte_pktmbuf_chain`, first seg
  carries ether+ip(20)+4B TCP, second seg carries the TCP tail.
  `pkt_len = 38`, `data_len[0] = 34`, `data_len[1] = 4`.
- Assert: classifier reads only the first segment for header
  access (uses `rte_pktmbuf_mtod_offset` which linear-reads the
  first segment). If header straddles segment boundary the test
  exposes the behavior — the D31 length guard uses `pkt_len`, so
  the guard passes even though the data needed is in the second
  segment. **This is a latent bug surface**; the test either
  (a) confirms the classifier falls into a linear-read trap —
  FAIL and flag as a new D-decision, or (b) confirms it handles
  chain — PASS. Either outcome is informative.
- Covers: latent multi-seg assumption in D31.

### C6.15 Jumbo frame (9000 B), single-seg
- Packet: large ICMP echo 9000 B.
- Setup: mempool sized for jumbo OR rte_eth_dev_set_mtu.
- Assert: classify runs, no truncation.
- Covers: jumbo sanity.

---

## C7 — Config-level adversarial / fuzz (D37, D38, D8, D33)

### C7.1 Parser fuzz [libFuzzer]
- Target: `LLVMFuzzerTestOneInput(data, size)` →
  `pktgate::config::parse(std::string_view{data,size})`.
- Build: ASan + UBSan + libFuzzer, `-fsanitize=fuzzer,address,undefined`.
- Assert: never crash; any return value is either `ParseErr{...}`
  or `ConfigAst{...}`. No exceptions escape.
- Seed corpus: see "Fuzz corpus seeds" at end of doc.
- Covers: D8 parser hardening.

### C7.2 Validator fuzz [libFuzzer]
- Target: parse → validate, where parse always succeeds (use
  `structure-aware` harness: fuzz fills in specific fields of a
  pre-built AST rather than random bytes).
- Assert: `ValidateErr` or `ValidOk`, never crash. Hostile inputs:
  `dst_port` list 1e6 entries, 1e5 rules total, CIDR /0 on
  src+dst, VRF id 2^31, forward-ref object group, schema version
  mismatch, port_group cycle.
- Covers: D8, D37.

### C7.3 Compiler fuzz [libFuzzer]
- Target: parse+validate → compile. Structure-aware AST.
- Hostile: overlapping L2 keys (collision detection), port_group
  fan-out near the D37 ceiling, max MAC groups, contradictory
  actions on overlapping flows (first-match-wins must dominate).
- Assert: `CompileErr{collision, rule_ids:[...]}` with specific
  rule_ids reported, OR `CompileOk`.
- Covers: D8 compiler hardening.

### C7.4 D37 pre-flight gates — per-rule ceiling just-fits [scapy-pytest]
- Config: one L4 rule with `dst_port` expanding to exactly 4096
  entries.
- Assert: `reload_total{result=success}` += 1; generation bumps.
- Covers: D37

### C7.5 D37 pre-flight — per-rule ceiling overflows
- Config: one L4 rule, `dst_port` expanding to 4097 entries.
- Assert: `reload_total{result=validate_err}` += 1; structured log
  carries `validate_err_sub=per_rule_expansion_ceiling`; active
  ruleset unchanged.
- Covers: D37

### C7.6 D37 aggregate ceiling just-fits
- Config: N rules summing to exactly `l4_entries_max` post-
  expansion.
- Assert: success.
- Covers: D37

### C7.7 D37 aggregate ceiling overflows
- Config: N rules summing to `l4_entries_max + 1`.
- Assert: `validate_err`, sub-reason `aggregate_expansion_ceiling`.
- Covers: D37

### C7.8 D37 hugepage budget just-fits
- Config: a ruleset whose estimated `expected_ruleset_bytes` equals
  free hugepages minus safety margin.
- Assert: success.
- Covers: D37

### C7.9 D37 hugepage budget overflows
- Config: `expected_ruleset_bytes` > free hugepages.
- Assert: `validate_err`, sub-reason `hugepage_budget`.
- Covers: D37

### C7.10 cmd_socket — malformed JSON [scapy-pytest]
- Action: send `{"cmd":"reload` (unterminated) to UDS.
- Assert: connection closed; `cmd_socket_rejected_total` NOT
  bumped (D38 is for peer-cred, not parse); a parse error is
  logged; process alive.
- Covers: cmd_socket robustness.

### C7.11 cmd_socket — oversized payload
- Action: send 4 MiB of `{` bytes.
- Assert: bounded read; connection closed; no OOM.
- Covers: cmd_socket DoS.

### C7.12 cmd_socket — truncated request (half-sent)
- Action: send `{"cmd":"stat` then close.
- Assert: connection closed; no state corruption.

### C7.13 cmd_socket — pipelined requests
- Action: send `{"cmd":"status"}\n{"cmd":"status"}\n` in one write.
- Assert: both responses received.

### C7.14 cmd_socket — interleaved reload and status
- Action: open two connections; conn1 sends `reload`, conn2 sends
  `status` during the reload window.
- Assert: both complete; `reload_mutex` (D35) serializes; no race.
- Covers: D35

### C7.15 cmd_socket — peer UID rejection [scapy-pytest + setuid helper]
- Action: connect as non-`pktgate_uid` non-root.
- Assert: `cmd_socket_rejected_total{reason="peer_uid"}` += 1.
- Covers: D38

### C7.16 cmd_socket — peer GID rejection
- Action: connect as allowed uid but wrong gid.
- Assert: `cmd_socket_rejected_total{reason="peer_gid"}` += 1.
- Covers: D38

### C7.17 inotify — atomic rename via `mv`
- Action: `mv config.new config.json`.
- Assert: exactly one reload fires.
- Covers: D38

### C7.18 inotify — vim-style write-then-rename
- Action: `vim config.json`, save.
- Assert: one reload (no partial reads — `IN_MODIFY` filtered out
  per D38).
- Covers: D38

### C7.19 inotify — sed -i in-place
- Action: `sed -i s/foo/bar/ config.json`.
- Assert: one reload.
- Covers: D38

### C7.20 inotify — `echo > config.json` (partial write)
- Action: shell redirect that does multiple writes.
- Assert: at most one reload; no parse errors on half-written file.
- Covers: D38

### C7.21 Schema version mismatch
- Config: `{"version": 999, ...}`.
- Assert: `reload_total{result="validate_err"}` += 1; sub-reason
  `schema_version`.
- Covers: D8 strict version match.

### C7.22 Forward-reference to undefined object group
- Config: L3 rule uses `"src_subnet": "nonexistent_group"`.
- Assert: `validate_err`, sub-reason `unresolved_object_ref`.
- Covers: D8 validator.

### C7.23 VLAN id out of range
- Config: L2 rule `vlan_id: 5000` (> 4095).
- Assert: `validate_err`, sub-reason `vlan_range`.
- Covers: D8

### C7.24 Impossible VRF id
- Config: L3 rule `vrf: 99999`.
- Assert: `validate_err`, sub-reason `vrf_range`.
- Covers: D8

### C7.25 Contradictory actions on identical flow (first-match-wins)
- Config: two L4 rules, both `{tcp, dport:443}`, one `drop`, one
  `allow`. IDs: 1, 2.
- Packet: matching TCP 443.
- Assert: first rule (id=1, drop) fires; second rule counters
  stay 0.
- Covers: D15 semantics, D8 first-match-wins.

### C7.26 Overlapping L2 keys (compiler collision)
- Config: two L2 rules both with identical src_mac+vlan+ethertype
  and different actions.
- Assert: `compile_err`, log carries `rule_ids:[1,2]` with
  conflict description.
- Covers: D8 compiler.

### C7.27 Counter-consistency invariant [gtest]
- Test: walk every metric name in §10.3 and assert that (a) an
  adversarial input from C1–C7 above reaches the producer site,
  or (b) the counter is a system counter (rte_eth_stats, mempool,
  reload). No "named in §10.3 but never written by anything" rows.
- Failure mode: if a counter has no producer path from fuzz
  inputs, it is either dead code or unreachable — both are bugs.
- Covers: D33 as a living invariant, not just a point-in-time doc
  pass.

---

## Coverage matrix (D1–D38 → corner test IDs)

| D-id | Topic | Covered here? | Where |
|---|---|---|---|
| D1 | Rate-limit per-lcore bucket | No — functional-test layer | RL behavior tests live in the functional bucket; C7 touches RL schema only |
| D2 | C++20 baseline | No — build layer | — |
| D3 | Telemetry model | Indirect | C7.27 invariant |
| D4 | rte_flow offload | No — phase 2 | — |
| D5 | HA compat / roles | No — functional/smoke | — |
| D6 | Rule count ceilings | Partial | C7.6 / C7.7 overflow tests |
| D7 | Mirror semantics | No — phase 2 | — |
| D8 | Clean JSON schema | Yes | C7.1–C7.3, C7.21–C7.26 |
| D9 | Single g_active pointer | No — concurrency | covered in concurrency test plan |
| D10 | §4.4/§5.5 per-lcore RL | No — RL functional | — |
| D11 | rl_arena GC ordering | No — concurrency | — |
| D12 | RCU polish | No | — |
| D13 | l3_offset in dynfield (VLAN fix) | Yes | C2.22, C3.20, C4.3a/b |
| D14 | IHL / v4 L4 offset | Yes | C2.2, C2.5, C2.6, C2.7, C2.9, C2.10, C2.20, C2.22 |
| D15 | L4 compound + filter_mask | Yes | C6.1–C6.6, C7.25 |
| D16 | REDIRECT staging / TX full | No — dataplane concurrency | — |
| D17 | fragment_policy | Yes | C2.11–C2.19, C5.1–C5.16 |
| D18 | Cycle budget min/typ/max | No — perf layer | — |
| D19 | misc cleanups | No | — |
| D20 | IPv6 first-proto-only | Yes | C3.4–C3.13 |
| D21 | NEXT_L4 cliff fix | Yes | C5.17 (flagship), implicitly C3.16/C3.17 |
| D22 | EXT_MASK UB fix | Yes | C3.9–C3.13 |
| D23 | NUMA awareness | No — init layer | — |
| D24 | rl_arena slot lifecycle | No | — |
| D25 | apply_action default arms | Partial | C7.27 as invariant — `dispatch_unreachable_total` must stay 0 |
| D26 | Mirror refcnt gate | No — phase 2 | — |
| D27 | IPv6 first vs non-first frag | Yes | C3.14–C3.21, C5.11–C5.16, C3.20 |
| D28 | TX queue symmetry | No — init layer | — |
| D29 | drop `want_icmp_code` / ICMP packing | Yes | C6.5–C6.7 |
| D30 | `rte_rcu_qsbr_check` correctness | No — RCU layer | — |
| D31 | Truncation guards (all `where`) | Yes | C1.1–C1.8, C2.2–C2.7, C2.20, C2.21, C3.2, C3.3, C3.18, C3.19, C4.10, C6.8 |
| D32 | QinQ 0x88A8 accept | Yes | C1.7, C4.2–C4.5, C4.8, C2.23 |
| D33 | Counter consistency invariant | Yes | C7.27 (living), plus the implicit "no stray counters" check across every test |
| D34 | rl_arena refill clamp | No — RL functional / concurrency | — |
| D35 | reload_mutex covers all entry points | Yes | C7.14 |
| D36 | pending_free queue | No — RCU timeout layer | — |
| D37 | Validator memory budget | Yes | C7.4–C7.9 |
| D38 | SO_PEERCRED / inotify | Yes | C7.15–C7.20 |

**Gaps by design.** D1/D10/D34 (rate-limit mechanics) belong in
the functional / concurrency plan — they need real traffic at
controlled rates, not adversarial shapes. D9/D11/D12/D16/D30/D36
are concurrency corner cases, not protocol corner cases. D4/D7/D26
are phase-2 features. D18 is a perf-layer topic. D2/D22/D23/D28
are build/init topics.

---

## Test counts summary

| Section | Count |
|---|---|
| C1 — L2 truncation | 8 |
| C2 — IPv4 corners | 23 |
| C3 — IPv6 ext / fragments | 22 |
| C4 — VLAN / QinQ | 11 (C4.3 counts 2) |
| C5 — fragment policy matrix | 17 |
| C6 — L4 / ICMP / transport | 15 |
| C7 — config-level fuzz | 27 |
| **Total** | **~123** |

Density matches the "~90–150" target; D31 `where` buckets each
have ≥3 tests (l2: C1.1/C1.2/C1.3/C1.8; l2_vlan: C1.4–C1.7, C4.10;
l3_v4: C2.3/C2.4/C2.6/C2.7; l3_v6: C3.2/C3.3; l3_v6_frag_ext:
C3.18/C3.19; l4: C2.2/C2.5/C2.20/C2.21/C6.8). Fragment matrix has
all 12 base cells plus 4 edges (C5.1–C5.17). Every
`EXT_MASK_LT64` value (0, 43, 50, 51, 60) and every explicit ≥64
value (135, 139, 140, 253, 254) has its own test (C3.4–C3.13).

---

## Fuzz corpus seeds

### C7.1 — `parser_fuzz` initial corpus

- `seeds/parser/empty.json`        → `{}` (minimal)
- `seeds/parser/minimal.json`      → the default ruleset above
- `seeds/parser/default_drop.json` → the default with
  `default_behavior=drop`
- `seeds/parser/all_sections.json` → one ruleset that exercises
  every top-level key (version, interface_roles, sizing, objects,
  default_behavior, fragment_policy, pipeline.{l2,l3,l4})
- `seeds/parser/huge_list.json`    → one L4 rule with 4095 dst
  ports in a list (near ceiling but legal)
- `seeds/parser/deep_nest.json`    → object-group ref chain 8
  levels deep (legal, stress for the AST walker)
- `seeds/parser/unicode.json`      → comments and string values
  with non-ASCII UTF-8 bytes
- `seeds/parser/broken_json.json`  → `{` only
- `seeds/parser/trailing_comma.json` → `{"version":1,}` (strict
  JSON rejects)
- Real-world configs hand-ported from `/home/user/filter/scenarios/`
  expressed in the D8 clean schema, ~10 files.
- Known-evil shapes:
    - 1 MiB of `[` recursion
    - NUL bytes in string values
    - UTF-16 BOM prefix
    - Duplicate keys within one object
    - Numbers > 2^53 (JSON precision edge)

### C7.2 — `validator_fuzz` initial corpus

Structure-aware; start from the AST produced by parsing
`seeds/parser/all_sections.json` and mutate specific fields:

- `seeds/validator/port_range_abuse.json` — `dst_port: [0,65535]`
- `seeds/validator/max_rules.json` — N_rules_per_layer rules
- `seeds/validator/vlan_oob.json` — `vlan_id: 5000`
- `seeds/validator/vrf_oob.json` — `vrf: 999999`
- `seeds/validator/forward_ref.json` — rule refs undefined group
- `seeds/validator/cycle_group.json` — two port_groups referencing
  each other (if nesting is allowed)
- `seeds/validator/version_skew.json` — `version: 999`
- `seeds/validator/hostile_expansion.json` — a handful of rules
  each blowing up to 4096 entries (right at the per-rule ceiling)

### C7.3 — `compiler_fuzz` initial corpus

- `seeds/compiler/collision_l2.json` — two L2 rules with identical
  keys, different actions.
- `seeds/compiler/overlap_l4.json`   — two L4 rules with identical
  keys, different actions (first-match-wins).
- `seeds/compiler/mixed_layers.json` — heavy compound L2 + compound
  L4 to exercise both builder paths.
- `seeds/compiler/mac_group_max.json` — 4096 MAC entries (dev
  ceiling is 4096; fuzzer mutates around the edge).
- `seeds/compiler/fib_stress.json`   — 16k IPv4 prefixes with
  overlapping shorter prefixes.

### Hand-crafted minimal reproducers (kept in-tree as
`seeds/known-evil/`)

- `13B_ether.bin` — C1.3
- `14B_vlan_tpid.bin` — C1.4
- `17B_vlan.bin` — C1.6
- `ipv4_ihl_15_short.bin` — C2.5
- `ipv4_ihl_0.bin` — C2.7
- `ipv4_ihl_6_options_tcp443.bin` — C2.9
- `ipv4_frag_nonfirst.bin` — C2.11
- `ipv6_ext_hbh.bin` — C3.4
- `ipv6_ext_135_mobility.bin` — C3.9
- `ipv6_frag_first_tcp443.bin` — C3.14
- `ipv6_frag_nonfirst.bin` — C3.15
- `ipv6_frag_nested.bin` — C3.16
- `ipv6_frag_ext_truncated4.bin` — C3.18
- `qinq_88A8_ipv4.bin` — C4.2
- `qinq_88A8_8100_ipv4.bin` — C4.3a
- `qinq_c_c_ipv4.bin` — C4.5
- `vlan_ipv4_ihl6_udp53.bin` — C2.22
- `vlan_ipv6_frag_first_tcp443.bin` — C3.20 (D13+D27 flagship)
- `icmp_type3_code3.bin` — C6.6 (D29 flagship)

These reproducers double as regression files: every fix to
D13/D14/D15/D17/D20/D22/D27/D29/D31/D32 must be accompanied by
the corresponding `.bin` file going green.

---

## Open questions / flags to raise after this plan lands

- **C2.11** exposes an observability gap: IPv4 non-first-fragment
  SKIP_L4 under `l3_only` is silent — there is no
  `l4_skipped_ipv4_fragment_nonfirst` counter. Either add it for
  symmetry with D27's IPv6 counter, or explicitly document that
  IPv4 fragment skip is silent. Recommend: add it. D-number TBD.
- **C2.12** exposes another gap: `fragment_policy=drop` silent
  drop — no per-lcore counter. Recommend: add
  `pkt_frag_dropped_total{policy=drop}` or fold into
  `pkt_truncated_total[where=frag]`. D-number TBD.
- **C4.3a** is the cleanest assertion on the QinQ inner-garbage
  behavior, but the design only promises `qinq_outer_only_total`
  fires when the inner ethertype is another VLAN TPID. The actual
  L3 behavior on garbage bytes is an emergent property of §5.3
  guards, not spec. Flag: should §5.2 prose explicitly state
  "when inner ethertype is not recognised L3, behavior is L3 miss
  via TERMINAL_PASS or truncation via D31"? Minor doc clarity.
- **C6.14** multi-seg chain is the single highest-risk latent
  issue in this plan. If classify_l2/l3/l4 use
  `rte_pktmbuf_mtod_offset` on a chained mbuf whose header
  straddles a segment boundary, it will read garbage. The design
  does not discuss the single-seg assumption explicitly. Flag
  for a new D-decision: "classifier requires headers-in-first-seg
  invariant; validator enforces `rxconf.max_rx_pkt_len ≤ seg_size`
  OR classifier handles multi-seg via `rte_pktmbuf_read`."
- **C3.22** (jumbo) depends on mempool sizing decisions that are
  in the functional test plan's scope; coordinate.
- **C5.17** is the crown-jewel D21 regression — the exact cliff
  that D21 fixed. Make this test red if `NEXT_L4` ever re-appears
  as a live `verdict_layer` value after SKIP_L4 has been latched.
