# pktgate-dpdk — test plan (umbrella)

Umbrella / synthesis of six specialised drafts produced by the
test-architect brigade (unit, functional, corner, perf, chaos,
harness). This document is an **index** over those drafts, not a
copy. The drafts are the source of truth for individual test
cases; this file ties them together, states overall coverage,
lists findings that need user-level decisions, and maps every
decision D1–D38 to at least one test ID.

**Grounding:** `input.md` (F1–F7 / N1–N5), `design.md` (current
head, post-commit `b2235e1`), `review-notes.md` (D1–D38 + M1/M2),
`CLAUDE.md` (project conventions).

---

## 0. Executive summary

The plan has ~571 test cases across six layers plus a ninth-section
harness document:

| Layer | Draft | Cases | Primary owner | Dev VM runnable |
|---|---|---|---|---|
| Unit / gtest | [test-plan-drafts/unit.md](test-plan-drafts/unit.md) | ~180 (U1–U10) | per-module authors | yes (all) |
| Functional / end-to-end | [test-plan-drafts/functional.md](test-plan-drafts/functional.md) | ~112 (F1–F10) | integration QA | yes (all, with `net_pcap` / `net_null`) |
| Corner / adversarial / fuzz | [test-plan-drafts/corner.md](test-plan-drafts/corner.md) | ~123 (C1–C7) | security/robustness | yes (all) |
| Perf / lab + dev micro | [test-plan-drafts/perf.md](test-plan-drafts/perf.md) | 82 (38 LAB + 44 DEV) | perf team | partial (P-D only) |
| Chaos / fault / security | [test-plan-drafts/chaos.md](test-plan-drafts/chaos.md) | 74 (X1–X4) | SRE/chaos | yes (except X2.7 PCI error) |
| Harness / CI / build matrix | [test-plan-drafts/harness.md](test-plan-drafts/harness.md) | n/a (infra) | platform | n/a |

**Release gate tests** (must pass before Phase 1 tag):

- **N1 40 Gbps release gate** — `perf.md` **P-L1.5** (LAB only)
- **N2 500 µs latency release gate** — `perf.md` **P-L2.4** (LAB)
- **N3 < 0.01 % loss** — `perf.md` P-L1.* / P-L2.* / P-L7.1 (LAB)
- **N5 reload ≤ 100 ms** — `perf.md` **P-L6.4** (LAB; DEV smoke
  via P-L6.1)
- **All unit + corner + chaos dev-VM-runnable suites green**
  under ASAN/UBSAN/TSAN CI matrix (`harness.md` §H3)
- **D33 counter-consistency invariant** — `corner.md` **C7.27** +
  `unit.md` U7.5 (grep check) — as a living test, both must be
  green on every commit

---

## 1. How the layers divide work

Each decision D1–D38 is owned by exactly one "primary" layer and
may be observed from one or more secondary layers. The split is:

- **Unit** owns pure-function correctness, static contracts,
  struct packing, parser/validator/compiler fuzz harness,
  classifier per-stage behaviour with synthetic mbufs.
- **Functional** owns end-to-end config→datapath→counter wiring
  on a real DPDK app running under `net_pcap` / `net_null`.
  Observability surface = counters + structured logs.
- **Corner** owns adversarial / malformed / truncated / QinQ /
  fragment / ext-header / fuzz-seed territory. The tests here
  are the D31/D32 / D21 safety net in code form.
- **Perf** owns N1/N2/N3/N5 SLO gates (lab) plus cycle-budget
  micro (DEV). Perf numbers on the dev VM are **shape tests,
  not release gates** (M1).
- **Chaos** owns reload storms, crash/stall recovery, D35/D36
  timing paths, D38 socket security, HA anti-pattern reject,
  and the "D30 embarrassing fix" targeted tests.
- **Harness** owns build matrix, sanitizer flavors, CMake
  presets, CI pipeline, ctest tags, fuzz-target plumbing, pcap
  diff tooling, dev-vs-lab gating.

The same D-number may show up in multiple drafts deliberately:
e.g. D31 truncation guards are exercised by `unit.md` U6.10–U6.17
(every `where` bucket), `functional.md` F8.2 (counter existence
and presence in `/metrics`), `corner.md` C1.*/C2.*/C3.* (malformed
shapes that fire the guards), and `chaos.md` X2.10 (counter
plumbing under load). Redundant paths are **intentional** — D31
is the kind of safety surface where one-agent coverage is not
enough.

---

## 2. Aggregate D → test-ID coverage matrix

One row per decision. "Primary" is the draft that owns the test.
"Also covered by" lists drafts with corroborating tests. "Gap"
means the decision is **not** mechanically tested and relies on
code review or static analysis only.

| D | Topic | Primary tests | Also covered by | Gap? |
|---|---|---|---|---|
| M1 | Dev VM ≠ architecture | code-review / doc structure | all drafts respect it | no mechanical test — principle |
| M2 | Arch ≠ plan | code-review / doc structure | functional F10.1 | no mechanical test — principle |
| D1 | Per-lcore token bucket, zero atomics | **unit** U1.21, U1.22, U5.1–U5.10, U6.58 | functional F3.12–F3.16, perf P-L5.*, P-D3.* | — |
| D2 | C++20 + gcc≥14 / clang≥18 | **harness** H3 CI matrix | — | — |
| D3 | Telemetry counting model | **functional** F8.* | unit U7.*, U10.*, corner C7.27 | — |
| D4 | rte_flow HW offload hooks (Phase 1 disabled) | **unit** U3.13–U3.15 | perf P-L8.* (lab, Phase 2) | live path is Phase 2 only |
| D5 | HA compat, interface_roles, `--standby` | **functional** F1.2–F1.8, F5.17, F10.6 | unit U1.4–U1.7, chaos X4.2, X4.4 | — |
| D6 | Runtime sizing dev vs prod | **unit** U1.25–U1.27 | functional F5.8–F5.10, chaos X1.6, X1.7 | — |
| D7 | Mirror full schema, MVP reject | **unit** U2.12, U3.17 | functional F3.17, F10.1 | live mirror dataplane is Phase 2 |
| D8 | Clean schema, no pktgate compat | **unit** U1.2–U1.31, U2.1–U2.20 | corner C7.1–C7.26 | — |
| D9 | Single global `g_active` (UAF fix) | **chaos** X1.2, X1.3, X1.10, X1.12 (TSAN) | unit U6.42/43, functional F5.1–F5.4, perf P-L6.* | — |
| D10 | Per-lcore bucket arena (§4.4/§5.5 rewrite) | **unit** U5.*, U6.58 | functional F3.12–F3.16, perf P-L5.1/P-L5.4 | — |
| D11 | rl_arena GC ordering post-synchronize | **unit** U4.11, U4.13 | functional F3.14/F3.15, chaos X1.14 | — |
| D12 | RCU polish (offline/unregister, bounded sync) | **chaos** X1.4, X4.3, X4.6 | functional F1.9, F5.12 | unit gap: needs real QSBR → integration only |
| D13 | `l3_offset` dynfield on VLAN | **unit** U6.6, U6.7 | corner C2.22, C3.20 (D13+D27 flagship), C4.3a/b, functional F2.3/2.6/2.7 | — |
| D14 | L4 offset via IHL + IPv6 fixed 40 | **unit** U6.19, U6.41 | corner C2.2/C2.5/C2.6/C2.7/C2.9/C2.10/C2.20/C2.22, functional F2.17–F2.25 | — |
| D15 | L4 compound primary + filter_mask | **unit** U3.3, U3.9–U3.12, U6.33–U6.38, U6.41 | corner C6.1–C6.6, C7.25, functional F2.17–F2.22, perf P-L4.3/P-L4.5 | — |
| D16 | REDIRECT staging + burst-end flush | **unit** U6.52–U6.55 | functional F3.9–F3.11, perf P-L9.*, chaos X2.5 | — |
| D17 | `fragment_policy` field (P9) | **unit** U1.14–U1.16, U6.21–U6.25 | corner C2.11–C2.19, C5.1–C5.16, functional F4.1–F4.6, F4.10, F10.8 | — |
| D18 | Cycle budget min/typ/max | **perf** P-D1.*, P-D2.1 (all §5.6 rows) | — | lab only for validation |
| D19 | Misc (TAG, fib_lookup single, idle) | **unit** U6.48–U6.51 | functional F3.3–F3.7, F1.9, chaos X2.11 | idle spec needs integration (D19 `handle_idle`) |
| D20 | IPv6 ext-headers first-proto only (P8) | **unit** U6.27, U6.31 | corner C3.4–C3.13, functional F2.15, F2.16, F4.7–F4.9 | — |
| D21 | NEXT_L4 cliff fix | **corner** C5.17 (flagship) | unit U6.20/U6.21/U6.44/U8.20, functional F4.4, chaos X2.9 | — |
| D22 | RuleAction 20 B + `alignas(4)` | **unit** U3.5, U4.8 | perf P-L1.7, P-D2.3 | — |
| D23 | NUMA explicit in Ruleset/Workers | **unit** U4.7, U4.15, U5.9 | perf P-L3.4, P-D2.4 (lab) | unit smoke only; full NUMA check is lab |
| D24 | rl_arena slot lifecycle | **unit** U4.9–U4.12 | functional F3.14/F3.15/F5.14, chaos X1.14, perf P-D3.4 | see §3 open Q4 |
| D25 | apply_action default arms + `-Wswitch-enum` | **unit** U3.22, U3.23, U6.44, U6.45, U8.20, U8.21 | chaos X2.9 (injection + release-build gate), corner C7.27 | negative-compile harness is open (see unit.md OPEN) |
| D26 | Mirror refcnt zero-copy compile gate | **unit** U3.18–U3.21 | perf P-L11.3 (Phase 2) | live mirror is Phase 2 |
| D27 | IPv6 frag first vs non-first + `l4_extra` | **unit** U6.26, U6.28, U6.29, U6.30 | corner C3.14–C3.21, C5.11–C5.16 (C3.20 is the D13+D27 flagship), functional F4.7–F4.9, perf P-D1.9 | see §3 open Q2 (IPv4 symmetry) |
| D28 | TX-queue symmetry invariant | **functional** F1.13 | unit U4.16, U6.53, chaos X2.8, perf P-L10.* | — |
| D29 | Drop `want_icmp_code` | **unit** U3.12, U6.41 | corner C6.5–C6.7, functional F2.23/2.24 | — |
| D30 | `rte_rcu_qsbr_check` token + deadline (the embarrassing fix) | **chaos** X1.4, X1.5, X1.11 | functional F5.12, perf P-L6.*/P-D4.* | unit gap: needs real QSBR |
| D31 | Per-stage truncation guards + `where` counter | **unit** U6.10–U6.17 (every `where` bucket) | corner C1.1–C1.8, C2.2–C2.7, C2.20, C2.21, C3.2, C3.3, C3.18, C3.19, C4.10, C6.8; functional F8.2; chaos X2.10; perf P-L1.9 | see §3 open Q1 (multi-seg) |
| D32 | QinQ 0x88A8 outer accept + counter | **unit** U6.8, U6.9 | corner C1.7, C4.2–C4.5, C4.8, C2.23, functional F8.14 | see §3 open Q3 (prose clarity) |
| D33 | Counter consistency invariant (`§10.3` is SoT) | **corner** C7.27 (living invariant) | unit U4.14/U6.59/U7.4/U7.5, functional F8.2, chaos X1.12/X1.14, perf P-L5.2/P-L7.1 | — |
| D34 | rl_arena refill `elapsed` clamp at `tsc_hz` | **unit** U5.2, U5.3, U5.4 | functional F3.16, perf P-L5.3/P-D3.2 | — |
| D35 | Single `reload_mutex` all entry points | **chaos** X1.2, X1.3, X3.10 (TSAN targets) | functional F5.11/F6.10, corner C7.14, perf P-L6.1/P-L6.2 | unit gap: needs real threads |
| D36 | `pending_free` queue (reload timeout) | **chaos** X1.4, X1.5, X1.10 | functional F5.12–F5.14, perf P-L6.5 | see §3 open Q5 (cadence) |
| D37 | Validator memory-budget pre-flight | **unit** U2.13–U2.17 | corner C7.4–C7.9, functional F5.8–F5.10, chaos X1.6/X1.7, perf P-L6.3/P-D4.5/P-D5.4 | — |
| D38 | SO_PEERCRED + inotify `IN_CLOSE_WRITE` filter | **chaos** X3.1–X3.9 | unit U2.18, U9.11–U9.17, functional F6.11–F6.14/F7.1–F7.4, corner C7.15–C7.20 | Q6 resolved — single accept-time check |
| D39 | Headers-in-first-seg invariant | **unit** U4.16 variant (port_init validator), **corner** new C6.14 derivatives | functional F1.14 (new — multi-seg RX rejected at startup), chaos TBD | drafts need new tests added for D39 — see §3 / §8 open items |
| D40 | IPv4 fragment-skip/drop counters + IPv6 symmetry | **unit** new U6 variants at bump sites, **corner** C2.11/C2.12 + new C5 asserts | functional F8.x counter presence, chaos X2.10 plumbing | drafts need new test IDs added for D40 |

**Every D1–D38 has ≥1 mechanical test.** Gaps listed above are
each either (a) covered by CI build matrix (D2), (b) cross-layer
handoffs to a later tier (D4/D7/D12/D23/D26/D30/D35/D36), or
(c) require a clarification from the user (D24/D31 multi-seg /
D32 prose / D36 cadence / D38 dispatch — see §3).

---

## 3. Findings — RESOLVED

The architect brigade raised nine items. As of 2026-04-11 eight
are closed; **Q8** (perf numeric thresholds) is adopted as-is and
becomes the Phase 1 baseline, to be revisited with real lab
measurements at §14.2 gate time.

**Status summary:**

| Q | Topic | Resolution | Landed in |
|---|---|---|---|
| Q1 | multi-seg mbuf chain UB | **D39** — `nb_segs==1` invariant + scatter-off + mempool-fit validator | design.md §5.1/§5.2/§6.1/§4.3/§10.3, review-notes D39 |
| Q2 | IPv4 fragment-skip/drop counter asymmetry | **D40** — new `pkt_frag_skipped_total{af}` and `pkt_frag_dropped_total{policy,af}` | design.md §4.3/§5.3/§10.3, review-notes D40 |
| Q3 | §5.2 QinQ inner-garbage prose | clarification paragraph after §5.2 code block | design.md §5.2 prose |
| Q4 | D24 row memory free semantics | read-check against current §4.4 — confirmed slot-index-cycle, no row free | no edit needed |
| Q5 | `reload_pending_full_total` cadence | once-per-overflow, alert as `rate>0` | design.md §9.2 inline comment |
| Q6 | SO_PEERCRED dispatch-vs-accept | single accept-time check; mutating/read-only same gate | design.md §10.7 |
| Q7 | `handle_idle` RCU online/offline | **stays online** — explicit | design.md §5.1 reinforcement |
| Q8 | Perf numeric thresholds (RL ±20% / cycle +20% / cache +15% / 2 GiB) | **adopted as baseline**, revisit post-§14.2 lab | perf.md unchanged |
| Q9 | `PKTGATE_TESTING` build flag + `pktgate_test2` user | §13 test-only build flavour; release `static_assert` | design.md §13 |

The original findings text is preserved below for historical
reference — each entry is the "why" behind the resolved row above.

---

### Original findings (historical — now resolved)

### Q1 (CRITICAL) — multi-seg mbuf chain invariant (`corner.md` C6.14)

The classifier stages (`classify_l2` / `classify_l3` / `classify_l4`)
use `rte_pktmbuf_mtod_offset` / `rte_pktmbuf_mtod` to read headers.
That linear-reads the **first segment only**. The D31 truncation
guards check `m->pkt_len`, which is the **entire chain**. For a
chained mbuf with a header straddling a segment boundary, the
guard passes but the read is undefined behaviour — it scans past
the first segment's data area.

`design.md` does not document a "headers-in-first-seg" invariant.
Candidate new decision **D39**: either
- (a) require `rxconf.max_rx_pkt_len ≤ seg_size` at init-time and
  assert at classifier entry that `m->nb_segs == 1`, **or**
- (b) replace `mtod_offset` reads with `rte_pktmbuf_read` (slower,
  but handles chains correctly), **or**
- (c) explicitly document that jumbo / multi-seg is unsupported
  in Phase 1 (and assert in validator).

My lean: **(a)** — cheapest, single-seg is already the dev-VM
reality, and it's a one-line invariant at port init. Phase 2 can
revisit if jumbo becomes a real requirement.

Affected test writing: several unit / corner tests assume
single-seg. If we pick (b), `unit.md` U6 needs a chain-aware
variant per guard.

### Q2 — IPv4 fragment-skip counter asymmetry (`corner.md` C2.11 flag)

D27 added `l4_skipped_ipv6_fragment_nonfirst_total` for IPv6.
There is **no IPv4 equivalent**. IPv4 non-first fragments under
`fragment_policy=l3_only` go silently through SKIP_L4 with no
counter. That is an observability asymmetry.

Two options:
- (a) Add `l4_skipped_ipv4_fragment_nonfirst_total` for symmetry
  (candidate D40 if separate, otherwise fold into D27).
- (b) Document explicitly in §10.3 that v4 fragment skip is
  counted under the aggregate `rule_matches_total{layer=l4,
  action=pass}` and no dedicated counter exists.

My lean: **(a)**, tiny cost, large clarity win.

Also flagged: `fragment_policy=drop` silent path has no per-lcore
counter — candidate `pkt_frag_dropped_total{policy=drop}` or fold
into `pkt_truncated_total[where=frag]`.

### Q3 — §5.2 QinQ inner-garbage behaviour prose (`corner.md` C4.3a flag)

D32 specifies that `qinq_outer_only_total` fires when the inner
ethertype is another VLAN TPID (0x8100 / 0x88A8). For a
0x88A8-outer frame with **garbage** inner ethertype, the actual
behaviour is emergent: classifier falls through to L3 which then
either hits D31 truncation or a terminal-pass. §5.2 prose is
silent on this case.

Recommendation: **add one sentence to §5.2**: "When the inner
ethertype after a single VLAN tag is not itself a VLAN TPID,
classification proceeds to L3 with the inner ethertype as
`eth_type` and no further special handling; unknown L3 etypes
follow the default L3-miss path." Pure doc clarity; no code
change. No new D-number.

### Q4 — D24 row memory free semantics (`chaos.md` X1.10 open note)

`chaos.md` X1.10 (1-hour leak soak) asserts VmRSS stays flat
across many reloads. The assertion assumes row memory is
**never freed** on slot free (only the slot **index** cycles).
Verify this against the current §4.4 implementation sketch. If
the implementation does free the underlying row, the leak-rate
assertion needs tightening (it's not a leak, it's an expected
free).

This is a design read, not a decision — confirm with reference
to the latest §4.4 and update `chaos.md` X1.10 or D24 as needed.

### Q5 — `pending_full` alert cadence (`chaos.md` X1.5 open note)

D36 `pending_free` queue overflow has two reasonable reporting
cadences:
- (a) Once per overflow event (first overflow rings, subsequent
  fills silent until drained).
- (b) Once per retry (every attempt to push to a full queue
  increments the counter).

§9.2 / §11 do not explicitly choose. Tests need this pinned.
My lean: **(a)** — operational signal quality is better and
the counter already covers raw-occurrence counting.

### Q6 — D38 SO_PEERCRED re-check at dispatch (`chaos.md` X3.5 open note)

§10.7 reads as: "allow-list + SO_PEERCRED at accept; mutating
verbs additionally require it." If the accept-time check already
gates both classes, the "tighter" gate at verb dispatch is a
no-op in code and X3.5 collapses into X3.1/X3.2.

Clarify in §10.7: is the mutating-verb gate a re-check at
dispatch, or is it the same accept-time check enforced once?
Purely spec clarification; affects test enumeration only.

### Q7 — D19 idle handler RCU state (`chaos.md` X2.11 open note)

`chaos.md` X2.11 relies on the idle handler staying RCU-**online**
during idle (so reload progress continues during no-traffic
windows). If `handle_idle` goes offline, reload timeouts in idle
windows become legitimate and X2.11 needs the inverse assertion.

§5 / §9.2 should explicitly state one or the other. My lean:
**stay online** — otherwise D12's bounded sync path degrades to
the bad case in any quiet traffic window, which partly defeats
D30/D36.

### Q8 — Perf numeric thresholds (`perf.md` Part X open items)

`perf.md` flags four plan-level numbers that it currently
defaults to but wants user confirmation on before release gating:
- Rate-limit accuracy ± 20 % tolerance (P-L5.1 gate)
- Cycle-budget headroom: typ + 20 % as yellow, max as red
- Cache-miss regression gate: +15 % rss-miss triggers investigate
- Ruleset footprint hard cap: 2 GiB hugepage per ruleset

All four are arbitrary defaults chosen by the perf agent. Sane,
but not derived from input.md — so explicit sign-off before they
become CI gates.

### Q9 — `PKTGATE_TESTING` build guard + `pktgate_test2` user

`functional.md` assumes a `-DPKTGATE_TESTING=1` build flag that
exposes test hooks (deterministic RNG seed, drop-randomness
forcing, mempool-shrink control) and a secondary system user
`pktgate_test2` registered in the D38 allow-list to exercise
peer-differentiation tests.

Neither exists in the current design. Harness needs them.
Candidate notes in §13 / §14.1 (build) and §10.7 (auth).

---

## 4. Phase gating

Mapping of tests to phases from `design.md` §14 and
`review-notes.md` D4/D7/D26 (Phase 2 features):

### Phase 1 (Phase-plan §14.1 — first release)

All of:
- `unit.md` U1–U10 (minus U3.18–U3.21 `tx_non_mutating` fully
  plumbed — compile-time gate on Phase 1 is unit U3.17 reject)
- `functional.md` F1–F10 (excluding F3.17 / F10.1 — those are
  **reject tests**, which **are** Phase 1, pointing to mirror's
  absence)
- `corner.md` C1–C7 (all)
- `perf.md` P-D1–P-D5 (all DEV), P-L1–P-L7 and P-L10 (LAB)
- `chaos.md` X1.1–X1.14, X2.1–X2.11, X3.1–X3.11, X4.1–X4.4, X4.6
- `harness.md` H1–H9 (all infra)

### Phase 2 (lights up with mirror + rte_flow)

- `unit.md` U3.18–U3.21 full capability cap plumbing
- `functional.md` mirror live tests (currently only F3.17 reject)
- `perf.md` P-L8 (`rte_flow` offload), P-L11 (mirror), P-L2.7
  (mirror cycle budget)
- `chaos.md` X4.5 (mirror-mode fallback at real rate), X4.7
  (`rte_flow` publish failure → SW fallback) — **X4.7 is not
  in the current draft**; add it when Phase 2 lands

### Lab-only (never runnable on dev VM)

- `perf.md` P-L1.5 40 Gbps gate, P-L2.4 500 µs gate, P-L3
  RSS scaling, P-L7 24 h soak, P-L8 HW offload, P-L11 mirror
  zero-copy — dev VM e1000 cannot reproduce any of these at
  meaningful scale (M1)
- `chaos.md` X2.7 PCI error injection — VirtualBox blocks

### Nightly-only (runnable but too slow for per-commit)

- `chaos.md` X1.10 1-hour leak soak
- `harness.md` H3 full matrix (gcc × clang × ASAN × UBSAN × TSAN
  × release/debug) — per-commit runs one flavor; nightly runs
  all eight

---

## 5. Critical test recipes — the "don't regress" short list

If only six tests could run pre-merge, these six:

1. **`corner.md` C5.17** — D21 NEXT_L4 cliff. The exact regression
   that D21 fixed; if this ever goes red, `verdict_layer` is
   leaking the old cliff value.
2. **`corner.md` C7.27 + `unit.md` U7.5** — D33 counter consistency
   invariant. No dangling counters in §10.3, no orphan producers.
3. **`unit.md` U6.10–U6.17** — D31 truncation guards, every
   `where` bucket.
4. **`corner.md` C3.20** — D13 + D27 flagship: VLAN-tagged IPv6
   first-fragment TCP443. Fires two critical decision fixes in
   one packet.
5. **`chaos.md` X1.4 + X1.5** — D30 `rte_rcu_qsbr_check` token +
   deadline. The embarrassing fix; must never silently regress.
6. **`functional.md` F1.13** — D28 TX-queue symmetry validator
   reject on `--workers=2` + single-queue NIC. Cold-start guard.

Add any perf release-gate test (P-L1.5, P-L2.4, P-L6.4) **if**
the branch touches `classify_*`, rate limiting, reload path, or
`rte_flow` hooks. Otherwise perf gate is nightly.

---

## 6. Tooling one-liners (from harness.md §H1 / §H3)

For the operator running the plan locally on the dev VM:

```bash
# Build all flavors
cmake --preset dev-asan && cmake --build --preset dev-asan
cmake --preset dev-ubsan && cmake --build --preset dev-ubsan
cmake --preset dev-tsan && cmake --build --preset dev-tsan

# Run everything dev-VM runnable
sudo ctest --preset dev-asan -L 'unit|corner'
sudo ctest --preset dev-ubsan -L 'unit|corner'
sudo ctest --preset dev-tsan  -L 'chaos|reload'
sudo ctest --preset dev-asan  -L 'functional'  # needs hugepages
sudo ctest --preset dev-asan  -L 'perf-dev'    # P-D*
```

Full CMake preset list, ctest labels, sanitizer caveats, and
the fuzz-target invocation details live in
[test-plan-drafts/harness.md](test-plan-drafts/harness.md).

---

## 7. Open items — what this plan does not say

This umbrella (and every draft under it) is written against the
current `design.md` head. It does **not** yet cover:

- **Phase 2 mirror dataplane**, **Phase 2 rte_flow offload**, and
  **Phase 3 bypass NIC** — these get their own test-plan passes
  when the respective phase gates flip.
- **HA active-active promotion** — out of process scope; parking
  and anti-pattern reject are covered, but external HA coordinator
  wiring is not.
- **sFlow collector conformance** — §10.4 formatter tests are in
  `unit.md` U10.10/U10.11; end-to-end to a real collector is not
  in scope here.
- **Post-Q1-through-Q9 revisions** — once the user answers the
  findings in §3, at least C6.14 and one-to-two counter
  additions will trigger a second pass of the relevant drafts
  to add / adjust tests.

Drafts are kept as the nucleus and will be edited in place as
decisions land. This umbrella file is updated each time the
aggregate D-map shifts.

---

*End of umbrella. Drafts: [unit](test-plan-drafts/unit.md) ·
[functional](test-plan-drafts/functional.md) ·
[corner](test-plan-drafts/corner.md) ·
[perf](test-plan-drafts/perf.md) ·
[chaos](test-plan-drafts/chaos.md) ·
[harness](test-plan-drafts/harness.md).*
