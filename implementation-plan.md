# pktgate-dpdk — implementation plan (TDD-first)

This document is the **execution plan** after the design phase
closed on commit `6ec5910` (design.md + D1–D40 + full test plan
umbrella). The design is the "what"; this is the "how", ordered
into milestones that can be shipped, reviewed, and gated by tests.

**Inputs:** `input.md`, `design.md`, `review-notes.md` (D1–D40),
`test-plan.md` + `test-plan-drafts/{unit,functional,corner,perf,chaos,harness}.md`.

**Contract:** every line of code is covered by a test that was
written **before** it. Each milestone lists its **RED** tests
(from the drafts) that must be authored first, then the **GREEN**
implementation that makes them pass, then any **REFACTOR** that
keeps them green. No milestone closes while any of its RED tests
are untyped. No milestone merges while any sanitizer flavour is
red.

---

## 0. Ground rules (apply to every milestone)

### 0.1 TDD discipline

Every task has three phases, always in this order:

1. **RED** — author the failing test(s) first. If a test in the
   drafts is referenced by ID, it is **transcribed** into real
   `tests/` gtest / functional / fuzz code. If a new test is
   required for a D-decision not covered by the drafts, it is
   added back to the draft **and** written in code. The test
   compiles, runs, and **fails** for the expected reason — not
   "not implemented" (that's cheating — test the contract, not
   the stub).
2. **GREEN** — the minimum implementation that turns the RED
   tests green. Nothing speculative. Nothing "in preparation for
   the next milestone". If a helper you need isn't covered by a
   RED test yet, you write that test first (possibly in the same
   commit).
3. **REFACTOR** — clean up with the test suite green the whole
   time. Hot-path micro-opts, dead-code pruning, doxygen.

No "write a bunch of code, then add tests later". The user was
explicit: *«мы не пишем всё сразу и потом может быть тестируем».*

### 0.2 Sanitizer matrix gate

Every milestone's "done" criterion is the same:

- `dev-release`, `dev-debug`, `dev-asan`, `dev-ubsan`, `dev-tsan`
  all build cleanly (CMake presets, `harness.md` §H2)
- ctest labels `unit`, `corner` and whichever milestone-specific
  label (`reload`, `security`, …) all green under **release +
  asan + ubsan + tsan** flavours locally on the dev VM
- `-Wall -Wextra -Wpedantic -Werror -Wswitch-enum` is a hard gate
  (D25); any new warning fails the commit
- CI runs one flavour per commit (rotating), and the full matrix
  nightly (`harness.md` §H3)

Merging is blocked while any of the above is red. No exceptions
for "this flavour is flaky" — fix the flake first.

### 0.3 Commit hygiene

- Small commits. One RED→GREEN→REFACTOR cycle per commit where
  feasible.
- Commit message body lists the test IDs that changed red→green.
- Pre-commit hook runs `ctest --preset dev-asan -L unit` on every
  commit that touches `src/`. Never bypass with `--no-verify`.
- Per-milestone tag: `m00-harness`, `m01-config`, … `m15-lab-perf`.
  Tags are signposts for reviewers; no release meaning yet.

### 0.4 Living test plan

Drafts under `test-plan-drafts/` are a nucleus. When a milestone
surfaces a new test, **add it to the draft first, then write it
in code**, then reference the updated draft in the commit. Never
add a test in `tests/` that has no draft entry — the draft is the
contract.

### 0.5 The six "don't-regress" sentinels

From `test-plan.md` §5, these six tests are sacred and must run
green on **every commit** from the milestone that first
introduces them onward. They are the regression tripwire:

1. `corner.md` **C5.17** — D21 NEXT_L4 cliff
2. `corner.md` **C7.27** + `unit.md` **U7.5** — D33 counter
   consistency invariant (two halves — runtime + grep)
3. `unit.md` **U6.10–U6.17** — D31 truncation guards (every
   `where` bucket)
4. `corner.md` **C3.20** — D13 + D27 VLAN+IPv6-first-frag flagship
5. `chaos.md` **X1.4 + X1.5** — D30 `rte_rcu_qsbr_check` token +
   deadline
6. `functional.md` **F1.13** — D28 TX-queue symmetry reject

Once introduced in the relevant milestone, these go into the
`sentinel` ctest label which every preset runs by default.

---

## 1. Milestone map (summary)

Dependency edges listed inline. Every milestone is blocked until
its dependencies are green under the full matrix.

| # | Milestone | Primary D | Depends on | Exit gate |
|---|---|---|---|---|
| **M0** | Harness / CMake / presets / sanitizers / fuzz bootstrap | D2, D25, D33-grep, Q9 | — | empty binary builds clean under 5 flavours; `ctest -L smoke` green |
| **M1** | Config parser + validator + sizing + budget pre-flight | D8, D37 | M0 | U1.*, U2.*, C7.1–C7.9 green; parser_fuzz seeded |
| **M2** | Object / rule compiler + Ruleset builder | D8, D13, D15, D22, D23, D29 | M1 | U3.*, U4.* green; compiler_fuzz seeded |
| **M3** | EAL port init + D39 validator + mbuf dynfield + worker skeleton | D9, D28, D39, §5.1 | M2 | F1.1 minimal boot, F1.13 D28 reject, U4.16, new D39 U-test green |
| **M4** | Classifier L2 (D13 VLAN, D32 QinQ, D31 L2 truncation) | D13, D31, D32 | M3 | U6.1–U6.11, C1.*, C4.*, F2 L2 subset green |
| **M5** | Classifier L3 + fragments (D14, D17, D20, D27, D40, D31/l3 buckets) | D14, D17, D20, D27, D40, D31 | M4 | U6.12–U6.32, C2.*, C3.*, C5.* green; D27 + D40 counters plumbed |
| **M6** | Classifier L4 + compound + filter_mask (D15, D21, D29) | D14, D15, D21, D29, D31 | M5 | U6.33–U6.41, C6.*, C5.17, and the D21 cliff sentinel green |
| **M7** | Action dispatch + apply_action (D16, D19, D22, D25) | D16, D19, D22, D25 | M6 | U3.22/23 compile-fail harness, U6.42–U6.55, F3.*, D25 switch-enum green |
| **M8** | RCU-QSBR + single g_active + reload path (D9, D11, D12, D30, D35, D36) | D9, D11, D12, D30, D35, D36 | M7 | integration QSBR suite, X1.2–X1.14, F5.11–F5.14 green; D30 sentinel lives |
| **M9** | Rate-limit arena (D1, D10, D24, D34) | D1, D10, D24, D34 | M8 (needs ruleset+RCU) | U4.9–U4.12, U5.1–U5.10, F3.12–F3.16 green |
| **M10** | Telemetry — Prom + sFlow + rte_tel + logs + D33 invariant | D3, D33 | M9 | U7.*, U10.*, F8.*, C7.27 living check green |
| **M11** | cmd_socket + inotify (D38) | D38 | M10 | U2.18, U9.11–U9.17, X3.1–X3.11, F6.*, F7.* green |
| **M12** | Watchdog / bypass / HA park (--standby) | D5 | M11 | F1.2–F1.8, F5.17, X4.1–X4.6 green |
| **M13** | Dev VM full-suite smoke — e1000 + `net_pcap` vdev end-to-end | — | M12 | every dev-runnable test in all six drafts green under asan/ubsan/tsan; §14.1 Phase 1 exit criteria partly met |
| **M14** | rte_flow HW offload hook (disabled in Phase 1) | D4 | M13 | U3.13–U3.15 green; P-L8 stubs in place for Phase 2 |
| **M15** | Lab bring-up + Phase 1 release perf gate (LAB only) | D18, N1, N2, N3, N5 | M13 | P-L1.5, P-L2.4, P-L6.4, P-L7.1 green on lab hardware |

Timeline is **not** included — M1 explicit: stop asking "how
long". The gate is "tests green under sanitizers", not calendar.

---

## 2. Per-milestone detail

Each section below follows the same template:

> **Goal.** One sentence.
> **RED tests (authored first).** Draft IDs → source files.
> **GREEN impl.** Files to create / touch with source-section link.
> **REFACTOR.** What to clean once green.
> **Exit gate.** Specific ctest labels green under the required
> sanitizer flavours.

---

### M0 — Harness / CMake / fuzz bootstrap

**Goal.** A project skeleton that builds an empty `pktgate_dpdk`
binary under five sanitizer flavours, runs an empty `ctest`
suite, and is ready for RED tests to land.

**RED tests (first).**
- `harness.md` §H8 smoke tests: `tests/smoke/test_build.cpp` —
  static_asserts that `__cplusplus >= 202002L`, gcc ≥ 14 or
  clang ≥ 18, `PKTGATE_TESTING` undefined in release preset.
- `harness.md` §H4 ctest label reachability — a no-op gtest per
  label confirms `ctest -L unit|corner|reload|security|smoke`
  routes correctly.
- **D33 grep test** (`unit.md` U7.5): a CMake `check` target
  that greps `design.md §10.3` for all `pktgate_*` counter
  names and fails if any prose reference elsewhere is missing.
  This is M0 because it stops counter drift before code exists.
- `harness.md` §H6 libFuzzer minimal harness — a dummy target
  that exits clean with empty input.

**GREEN impl.**
- `CMakeLists.txt` + `cmake/presets.json` (`dev-release`,
  `dev-debug`, `dev-asan`, `dev-ubsan`, `dev-tsan`,
  `dev-testing`, `release`) — `harness.md` §H2.
- `cmake/Warnings.cmake` — full warning wall including
  `-Wswitch-enum -Werror`.
- `cmake/Sanitizers.cmake`, `cmake/Gtest.cmake`, `cmake/Fuzz.cmake`.
- `src/main.cpp` — `int main(){ return 0; }`, DPDK link present.
- `tests/CMakeLists.txt`, `tests/smoke/`.
- `scripts/check_counter_consistency.py` driving the §10.3 grep.
- `.github/workflows/ci.yml` (or equivalent) — rotating
  sanitizer per commit, full matrix nightly.

**REFACTOR.** ccache / sccache integration once the baseline
compile time is measured.

**Exit gate.** `ctest --preset dev-{release,debug,asan,ubsan,tsan}
-L smoke` all green. The D33 grep target is in the default ctest
set and green (it has nothing to check yet but the harness is
live).

**Tag:** `m00-harness`.

---

### M1 — Config schema: parser + validator + sizing + budget

**Goal.** `libpktgate_core.a` parses JSON into an AST, validates,
and pre-flights memory budget (D37). No DPDK dependency yet.

**RED tests.**
- `unit.md` U1.1–U1.31 parser happy/unhappy paths → `tests/unit/test_parser.cpp`
- `unit.md` U2.1–U2.20 validator incl. U2.13–U2.17 D37 budget
- `unit.md` U1.25–U1.27 D6 sizing (dev vs prod columns)
- `corner.md` C7.1 parser_fuzz seed corpus → `fuzz/parser_fuzz.cc`
- `corner.md` C7.2 validator_fuzz seed corpus → `fuzz/validator_fuzz.cc`
- `corner.md` C7.4–C7.9 validator budget corners

**GREEN impl.**
- `src/config/parser.{cpp,h}` — nlohmann/json driven; no
  allocations on happy path
- `src/config/validator.{cpp,h}` — pure function; returns
  `expected<void, ValidateError>`
- `src/config/sizing.{cpp,h}` — dev/prod columns per D6
- `src/config/model.h` — AST structs (plain POD + std::string)
- **D37 `validate_budget`** — per-rule expansion ceiling (4096
  default), aggregate post-expansion ceiling, hugepage estimate
- Implements D8 schema fields, rejects pktgate-compat keys
- `fuzz/parser_fuzz.cc`, `fuzz/validator_fuzz.cc`

**REFACTOR.** Pull common error plumbing into `util/expected.h`
once 2+ modules use it.

**Exit gate.** `ctest -L unit -R 'parser|validator|sizing'` green
under release/asan/ubsan. `parser_fuzz` runs 60 s clean under
libFuzzer.

**Tag:** `m01-config`.

---

### M2 — Compiler + Ruleset builder

**Goal.** Config AST → compiled `Ruleset` with L2 compound tables,
L3 FIB builder, L4 compound + filter_mask, actions sized and
aligned per D22, NUMA-aware allocation per D23.

**RED tests.**
- `unit.md` U3.1–U3.24 object + rule compiler
- `unit.md` U3.5, U4.8 — RuleAction **20 B + `alignas(4)`** (D22)
- `unit.md` U4.* Ruleset builder — sizing, counter layout, NUMA
- `unit.md` U4.16 — D28 invariant check (surface only; full
  check in M3 port init)
- `unit.md` U3.12, U6.41 — `want_icmp_code` **absent** (D29)
- `corner.md` C7.10–C7.26 compiler_fuzz
- `corner.md` C6.1–C6.6 L4 compound+filter_mask
- `corner.md` C7.27 stub — counter name list matches §10.3 (M10
  wires it live, this is the structural stub)

**GREEN impl.**
- `src/compiler/object_compiler.{cpp,h}`
- `src/compiler/rule_compiler.{cpp,h}` (L2/L3/L4 tiers)
- `src/ruleset/builder.{cpp,h}` — `rte_hash` / `rte_fib` /
  `rte_fib6` allocation on the target NUMA socket (D23)
- `src/ruleset/ruleset.cpp` — lifetime + ownership
- `src/action/` struct definitions sized by D22
- `fuzz/compiler_fuzz.cc`

**REFACTOR.** Counter-slot assignment centralised into a
`counter_layout.h` header so §4.3 math stays a single source of
truth.

**Exit gate.** Full `ctest -L unit` green under 4 flavours;
compiler_fuzz 60 s clean.

**Tag:** `m02-compiler`.

---

### M3 — EAL port init + D39 + D28 + mbuf dynfield + worker skeleton

**Goal.** The binary boots a DPDK EAL, validates port config
against D28 (TX symmetry) and D39 (scatter-off + mempool-fit),
registers the mbuf dynfield slot per §5.1, and runs a worker
loop that does nothing but RX+drop under RCU-QSBR. First point
where "functional" tests are meaningful.

**RED tests.**
- `functional.md` **F1.1** minimal boot (single worker, `net_pcap`)
- `functional.md` **F1.13** D28 — `--workers=2` on single-queue NIC → reject at startup
- `unit.md` U4.16, U6.53 D28 invariant
- `chaos.md` **X2.8** D28 symmetry violation via `net_null`
- **New RED**: `functional.md` **F1.14** — multi-seg RX port rejected at startup (D39 validator); add to draft first
- **New RED**: `unit.md` **U4.17** — D39 port validator logic pure test; add to draft
- **New RED**: `unit.md` **U6.2a** — `classify_l2` aborts `RTE_ASSERT` on synthetic multi-seg mbuf in debug build; add to draft
- `unit.md` U6.1 dynfield registration

**GREEN impl.**
- `src/eal/port_init.{cpp,h}` — D28 symmetry validator,
  D39 scatter-off + `elt_size` fit validator, mbuf dynfield
  registration per §5.1 schema
- `src/dataplane/worker.cpp` — RCU register/online, RX loop,
  mbuf free (no classification yet — that's M4+)
- `src/main.cpp` — EAL init, sizing load, validator calls,
  worker launch
- `src/ctl/bootstrap.cpp` — signal handlers, exit path

**REFACTOR.** Extract `eal::PortSet` from ad-hoc port vectors in
`main.cpp`.

**Exit gate.** F1.1, F1.13, F1.14, X2.8, U4.16, U4.17, U6.1, U6.2a
green under release + asan. TSAN of the boot path green too
(worker thread + control thread).

**Tag:** `m03-bootstrap`.

---

### M4 — Classifier L2 (D13 VLAN, D32 QinQ, D31 L2 truncation)

**Goal.** `classify_l2` fully functional per §5.2; D13 VLAN
`l3_offset` written correctly; D32 QinQ outer accepted; D31
length guards bump the two L2 `where` buckets; sentinel counter
`pkt_multiseg_drop_total` wired from M3.

**RED tests.**
- `unit.md` **U6.1–U6.9** dynfield + L2 paths (including VLAN
  + QinQ — D13 / D32)
- `unit.md` **U6.10, U6.11** — D31 `where={l2, l2_vlan}` — **sentinel** (see §0.5)
- `corner.md` **C1.1–C1.8** L2 truncation
- `corner.md` **C4.1–C4.11** VLAN / QinQ shapes (D32)
- `functional.md` F2 subset — L2 matching end-to-end
- `functional.md` **F8.14** — `qinq_outer_only_total` visible

**GREEN impl.**
- `src/dataplane/classify_l2.h` — full §5.2 body
- `src/dataplane/stats.h` — `ctx_stats_bump_*` per-lcore helpers
  for D31/D32/D39/D40 counters (zero-atomics)
- Counter rows in `src/telemetry/counter_layout.h` (dangling
  surface only — M10 wires exposure)

**REFACTOR.** Once U6.10/U6.11 are green, the "headers-in-first-seg"
invariant (D39 `RTE_ASSERT`) becomes a release-build `if` with a
counter bump — promote it out of `classify_l2` into a shared
`classify_entry` helper used by L3/L4 too.

**Exit gate.** All L2 unit + corner tests green under
release/asan/ubsan. D31 L2 sentinel locked in.

**Tag:** `m04-classify-l2`.

---

### M5 — Classifier L3 + fragments (D14, D17, D20, D27, D40, D31)

**Goal.** Full §5.3 body. IPv4 dst-prefix primary via
`rte_fib_lookup_bulk(n=1)`, IPv6 dst-prefix primary via
`rte_fib6_lookup_bulk(n=1)`. D17 `fragment_policy` (drop /
l3_only / allow) — P9 default `l3_only`. D20 IPv6 first-proto-only
ext-header handling. D27 IPv6 first-vs-non-first fragment + `l4_extra`.
**D40 new counters** fired at all four sites (v4 drop, v4 skip,
v6 drop, v6 skip). D31 guards at `l3_v4`, `l3_v6`, `l3_v6_frag_ext`.

**RED tests.**
- `unit.md` U6.12–U6.17 — D31 L3 `where` buckets (all three) — **sentinel**
- `unit.md` U6.19 D14 IHL
- `unit.md` U6.21–U6.25 D17 fragment policy per arm
- `unit.md` U6.26–U6.32 — D20 + D27 (first vs non-first)
- `unit.md` U6.27, U6.31 — IPv6 ext-header (D20 / P8)
- **New RED**: `unit.md` **U6.26a** — v4 `FRAG_DROP` bumps
  `pkt_frag_dropped_total{v4}` (D40); add to draft
- **New RED**: `unit.md` **U6.26b** — v4 `FRAG_L3_ONLY/nonfirst`
  bumps `pkt_frag_skipped_total{v4}` (D40); add to draft
- **New RED**: `unit.md` **U6.26c** — v6 skip bumps BOTH
  `l4_skipped_ipv6_fragment_nonfirst` and
  `pkt_frag_skipped_total{v6}` at the same site (D40 alias)
- `corner.md` **C2.2–C2.22** IPv4 corners
- `corner.md` **C3.2–C3.21** IPv6 + fragments + ext
- `corner.md` **C5.1–C5.16** fragment policy matrix (3 × 4)
- `corner.md` **C3.20** — D13 + D27 flagship — **sentinel**

**GREEN impl.**
- `src/dataplane/classify_l3.h` — full §5.3 body for v4 and v6
- D40 bump sites (pure function in `stats.h` already landed M4)
- `rte_fib`/`rte_fib6` lookup wrappers with the `n=1` contract
  captured in `util/fib.h`

**REFACTOR.** Merge the `is_ext_proto` lambda into a `constexpr`
function once both v6 sites use it. Reconsider whether the
IPv6 EXT_MASK can become a `constexpr uint64_t` member of a
class for easier unit testing.

**Exit gate.** All L3 unit + corner tests green. D31 L3 sentinel
and C3.20 sentinel in place. `fragment_policy` end-to-end matrix
green (`functional.md` F4.1–F4.10).

**Tag:** `m05-classify-l3`.

---

### M6 — Classifier L4 + compound primary + filter_mask (D15, D21, D29, D31)

**Goal.** `classify_l4` per §5.4: compound primary hash on
`(vrf, proto, dport)` (tunable), then `filter_mask` secondary
check. D21 NEXT_L4 cliff: the dispatcher routes SKIP_L4 packets
to TERMINAL_PASS and never re-enters L4. D29 `want_icmp_code`
absent from the struct. D31 `l4` `where` bucket.

**RED tests.**
- `unit.md` U6.33–U6.41 — D15 compound + filter_mask + D14 IHL use
- `unit.md` **U6.16** — D31 `where=l4` — **sentinel**
- `unit.md` U6.20, U6.44 — D21 NEXT_L4 cliff unit-level
- `corner.md` **C6.1–C6.15** L4 / ICMP / transport
- `corner.md` **C5.17** — D21 flagship — **sentinel**
- `functional.md` F2.17–F2.25 L4 end-to-end

**GREEN impl.**
- `src/dataplane/classify_l4.h` — full §5.4 body
- `src/compiler/rule_compiler.cpp` — update L4 code-gen to
  include the filter_mask layout if not already

**REFACTOR.** L4 compound primary key layout: confirm it's
`uint64_t` packable and the hash is salted for DoS resistance.

**Exit gate.** All L4 unit + corner tests green; C5.17 sentinel
lights; L4 filter_mask fuzz target 60 s clean.

**Tag:** `m06-classify-l4`.

---

### M7 — Action dispatch + apply_action (D16, D19, D22, D25)

**Goal.** `apply_action` routes verdicts to the right destination:
TX, mirror TX (D7 phase-gated), redirect TX with staging + burst-end
flush (D16), TAG rewrite (D19 TAG semantics), rate-limit call
(M9 wires actual bucket; stub until then — `return allow`). D25
-Wswitch-enum defends every switch. The `dispatch_unreachable_total`
counter must stay 0.

**RED tests.**
- `unit.md` **U3.22, U3.23** — D25 negative compile test
  (`check_fail_compile` macro from harness.md §H9) — **sentinel
  surface** via `dispatch_unreachable_total` stays 0
- `unit.md` U6.42–U6.55 — dispatch, REDIRECT staging, burst flush
- `unit.md` U6.48–U6.51 — D19 TAG, idle handler touches
- `chaos.md` **X2.9** — D25 backstop at runtime (release-build CI gate)
- `functional.md` F3.1–F3.17 action matrix
- `functional.md` F3.9–F3.11 — D16 REDIRECT (F3.11 may be LAB only)

**GREEN impl.**
- `src/dataplane/action_dispatch.h`
- `src/action/ratelimit.{cpp,h}` — **stub** that always allows
  (M9 plugs the real arena)
- `src/action/mirror.{cpp,h}` — Phase 1 compile-time reject (D7)
- `src/action/tag.{cpp,h}` — DSCP / PCP rewrite

**REFACTOR.** Verify all switches use the default-arm pattern
(D25) by running a grep lint in the pre-commit hook.

**Exit gate.** `ctest -L unit -R dispatch|action` green;
`F3.*` green; X2.9 green.

**Tag:** `m07-dispatch`.

---

### M8 — RCU-QSBR + single g_active + reload path (D9, D11, D12, D30, D35, D36)

**Goal.** Full hot-reload pipeline. `g_cp.g_active` is the single
writer (D9). `deploy()` holds `reload_mutex` (D35) across
parse→validate→budget→compile→publish→check→drain. `rte_rcu_qsbr_check`
uses token + deadline correctly (D30). Timeout path pushes to
`pending_free` (D36); `pending_full` is once-per-overflow (Q5).
`synchronize` deadline bounded (D12). Arena GC happens after
successful check (D11).

**RED tests.**
- `chaos.md` **X1.2, X1.3** — D35 two concurrent reload entry points (TSAN)
- `chaos.md` **X1.4, X1.5, X1.11** — D30 token/deadline, D12 bounded sync — **sentinel**
- `chaos.md` **X1.4, X1.5, X1.10** — D36 `pending_free` + drain, X1.10 leak soak
- `chaos.md` **X1.6, X1.7** — D37 budget gate under reload storm
- `chaos.md` **X1.14** — D11 GC ordering + D24 slot lifecycle
- `functional.md` F5.11–F5.14 — reload lifecycle observable
- `unit.md` U6.42/43 single `g_active` (D9 structural)
- Integration-tier test binary `test_reload` that brings up real
  EAL + QSBR; every D30/D35/D36 test lives here, not in unit

**GREEN impl.**
- `src/gen/gen_manager.{cpp,h}` — `deploy()` function, all reload
  state, `reload_mutex`, `pending_free[K_PENDING]` queue
- `src/ctl/reload_sources.h` — single funnel accepting inotify +
  cmd_socket + telemetry reload flag
- Wire `atomic_exchange` on `g_cp.g_active`
- Arena GC hook (GC walks removed rules, zeroes counter rows,
  frees arena slot indices per D24)
- `tests/integration/test_reload.cpp` with real QSBR

**REFACTOR.** Split `gen_manager.cpp` into `reload.cpp` +
`gc.cpp` once both are large enough to warrant it.

**Exit gate.** TSAN green on X1.2/X1.3; sentinels X1.4/X1.5 live;
integration `test_reload` green; 1-hour leak soak green
(nightly-only). No `-fsanitize=address` UAF report after 10k
reload storm.

**Tag:** `m08-reload`.

---

### M9 — Rate-limit arena (D1, D10, D24, D34)

**Goal.** Per-lcore token bucket arena. Zero atomics on hot path.
Slot lifecycle via free-list (D24). Refill `elapsed` clamped at
`rte_get_tsc_hz()` (D34). Variant A — split rate across active
lcores.

**RED tests.**
- `unit.md` U5.1–U5.10 — bucket math, precision, edge cases
- `unit.md` **U5.2, U5.3, U5.4** — D34 clamp
- `unit.md` **U4.9–U4.12** — D24 slot lifecycle (alloc/free/reuse)
- `functional.md` F3.12–F3.16 — RL end-to-end
- `chaos.md` X1.14 — RL slot reuse during reload

**GREEN impl.**
- `src/rl_arena/rl_arena.{cpp,h}` — per-lcore bucket arena
- Replace M7 stub in `src/action/ratelimit.cpp` with real
  bucket consume
- Hook arena GC into M8 `deploy()` (D11 ordering — GC after
  successful check; slot index freed, row zeroed)

**REFACTOR.** Confirm the per-lcore bucket row is cache-line
aligned (64 B) — verify with `static_assert(sizeof(...) == 64)`.

**Exit gate.** Unit RL suite green; F3.12–F3.16 green; X1.14
green.

**Tag:** `m09-rl-arena`.

---

### M10 — Telemetry — Prom + sFlow + rte_tel + logs + D33 invariant

**Goal.** All four export channels from §10.2 live. Snapshot
ring buffer N=4, single writer. D3 counting model fully
realised. D33 counter consistency invariant becomes a **living
CI gate** — the C7.27 runtime test fails if any §10.3 row has
no producer site; the U7.5 grep test stays green.

**RED tests.**
- `unit.md` U7.1–U7.7 — snapshot + ring buffer
- `unit.md` U10.1–U10.11 — Prom encoder, sFlow formatter, log ring
- `unit.md` **U7.5** — D33 grep — **sentinel** (already live from M0,
  now validates against growing counter set)
- `corner.md` **C7.27** — D33 living invariant — **sentinel**
- `functional.md` F8.1–F8.15 — counter exposure end-to-end
- `functional.md` F8.2 — `pkt_truncated_total` + `pkt_frag_*` +
  `pkt_multiseg_drop_total` all present in `/metrics`

**GREEN impl.**
- `src/telemetry/snapshot.{cpp,h}` — snapshot publisher thread
- `src/telemetry/prom.{cpp,h}` — HTTP exporter
- `src/telemetry/sflow.{cpp,h}` — UDP sFlow v5 encoder
- `src/telemetry/rte_tel.{cpp,h}` — DPDK telemetry endpoints
- `src/telemetry/log.{cpp,h}` — per-lcore SPSC log ring + drain
- Wire every D31/D32/D39/D40 counter from M4/M5 through to
  snapshot → exporters

**REFACTOR.** Extract a `CounterName` type that carries its
`§10.3` row so the D33 grep becomes unnecessary — but keep the
grep as belt-and-suspenders until the refactor is mature.

**Exit gate.** F8.* green; U7.5 + C7.27 sentinels live; 24 h
snapshot soak green (nightly).

**Tag:** `m10-telemetry`.

---

### M11 — cmd_socket + inotify (D38)

**Goal.** UDS command socket at `/run/pktgate/ctl.sock` with
SO_PEERCRED enforced exactly once at `accept(2)` (Q6 clarified).
Inotify subscriber with `IN_CLOSE_WRITE | IN_MOVED_TO` only, on
the parent directory, with debounce per §9.3. Both funnel into
M8 `deploy()` under `reload_mutex` (D35).

**RED tests.**
- `unit.md` **U2.18, U9.11–U9.17** — SO_PEERCRED pure + inotify
  filter
- `chaos.md` **X3.1–X3.9** — full D38 security bucket
- `chaos.md` **X3.10** — concurrent reload race — **sentinel edge**
- `chaos.md` **X3.11** — `activate` verb + peer check
- `functional.md` F6.11–F6.14, F7.1–F7.4 — end-to-end socket auth
- **Needs Q9 hooks** — `PKTGATE_TESTING` build flavour + second
  system user `pktgate_test2` (design.md §13 — land as part of
  this milestone's infra)

**GREEN impl.**
- `src/ctl/cmd_socket.{cpp,h}` — accept loop + SO_PEERCRED +
  allow-list + verb router
- `src/ctl/inotify.{cpp,h}` — `inotify_init1(IN_NONBLOCK|IN_CLOEXEC)`,
  watch on dir, event filter, debounce timer
- `systemd/pktgate.service` and `systemd/pktgate-test2.service`
  (test-only)

**REFACTOR.** Promote the debounce timer into `util/debounce.h`
once inotify and telemetry both want it.

**Exit gate.** X3.1–X3.11 green; TSAN green on X3.10; F6.*/F7.*
green.

**Tag:** `m11-ctl`.

---

### M12 — Watchdog / bypass / HA park (--standby) (D5)

**Goal.** `systemd` `WatchdogSec` integration, heartbeat publish,
`--standby` park/activate lifecycle (ports configured but not
started; activated via `{"cmd":"activate"}`), K-crash bypass
policy, HA anti-pattern reject in validator (D5 §11.1 list).

**RED tests.**
- `functional.md` F1.2–F1.8, F5.17 — `--standby` lifecycle
- `functional.md` F1.9 — idle handler stays RCU-online (Q7
  confirmed)
- `chaos.md` X4.1 — bypass after K crashes
- `chaos.md` X4.2, X4.4 — standby park, HA anti-pattern reject
- `chaos.md` X4.3 — graceful shutdown
- `chaos.md` X4.6 — heartbeat stall
- `chaos.md` X2.1, X2.2 — worker stall + SEGV + bypass

**GREEN impl.**
- `src/ctl/watchdog.{cpp,h}` — sdnotify / heartbeat publisher
- `src/ctl/park.{cpp,h}` — standby park loop
- `src/main.cpp` — `--standby` flag plumbing, crash counter,
  bypass mode switch
- `src/config/validator.cpp` — D5 anti-pattern reject rules

**REFACTOR.** Extract `Watchdog` as a class once it has more
than heartbeat tick logic.

**Exit gate.** All `X4.*` + `F1.2–F1.9` + `F5.17` green.

**Tag:** `m12-ha-park`.

---

### M13 — Dev VM end-to-end smoke

**Goal.** Every dev-runnable test in all six drafts runs green
under release + asan + ubsan + tsan on the dev VM (e1000 +
`net_pcap` vdev + `net_null` vdev). No code beyond what's
needed to stitch the remaining plumbing.

**RED tests.** None new — this milestone is the umbrella run.

**GREEN impl.** Whatever small gap-fillers show up during the
run. If a new bug appears, write the RED test first (add to
drafts), fix, re-run. Typical gap-fillers:
- `scripts/run_all.sh` that runs each ctest preset × label
- `scripts/dev_hugepages.sh` for hugepage bring-up
- `systemd/pktgate-devvm.service` for service-mode testing

**Exit gate.** Full dev-runnable test matrix green. §14.1 Phase 1
exit criteria met **except** N1/N2/N3/N5 which are LAB-only
(M15).

**Tag:** `m13-devvm-smoke`.

---

### M14 — rte_flow HW offload hook (disabled in Phase 1)

**Goal.** Implement the D4 architectural hooks — compiler tier
marking for hw-offloadable rules, publish-time detection,
`rte_flow` create plumbing — but ship **disabled**. Release
config does not light this path; lab config can.

**RED tests.**
- `unit.md` U3.13, U3.14, U3.15 — tier marking + hw-flag
  plumbing
- `perf.md` P-L8.* — LAB only, Phase 2 sign-off

**GREEN impl.**
- `src/compiler/rule_compiler.cpp` — tier marking for hw
  candidates
- `src/ruleset/hw_publish.{cpp,h}` — `rte_flow_create` /
  `rte_flow_destroy` publishers (no-op unless enabled)
- `src/dataplane/classify_l2.h` — FDIR_ID dispatch short-circuit
  (already commented in §5.2 — now wire it)

**REFACTOR.** None yet; the rollback path for partial install
failure is flagged `L4` in review-notes (future decision).

**Exit gate.** Unit tests green; the hook path is disabled in
`release` preset and static_assert'd off.

**Tag:** `m14-rte-flow-hook`.

---

### M15 — Lab bring-up + Phase 1 release perf gate

**Goal.** Provision lab hardware per `perf.md` §Lab BoM, run
the Phase 1 release gates. This is the only milestone where
M1 / dev-VM / e1000 is **not** the primary environment.

**RED tests.**
- `perf.md` **P-L1.5** — N1 40 Gbps release gate
- `perf.md` **P-L2.4** — N2 ≤ 500 µs latency gate
- `perf.md` **P-L6.4** — N5 reload ≤ 100 ms
- `perf.md` **P-L7.1** — 24 h soak at line rate (drift + leak)
- `perf.md` P-L1.* / P-L2.* / P-L3.* / P-L4.* supporting
- All lab-only items from `chaos.md` and `corner.md` that were
  gated

**GREEN impl.** Whatever tuning lands: isolcpus, IRQ affinity,
hugepage topology. Q8 perf numerics (RL ±20%, cycle +20%, cache
+15%, 2 GiB ruleset cap) are the Phase 1 baselines — **this is
the milestone where they get their first real-hardware
validation**; if they're too loose or too tight, propose a
correction back to `review-notes.md` as a new D-decision and
re-run.

**Exit gate.** N1/N2/N3/N5 green on E810 (primary) and XL710
(secondary). Phase 1 `§14.1 exit criteria` fully met.

**Tag:** `m15-lab-perf` — **this is the Phase 1 release tag**.

---

## 3. Decision → milestone matrix

One-line reminder: every D has a home milestone. If a D is not
in this table, it's not actually implemented anywhere — fix that
before merging.

| D | Home | Secondary / verified by |
|---|---|---|
| M1/M2 | (all) | Code review / document structure |
| D1  | M9 | M7 stub, M15 lab |
| D2  | M0 | H3 CI matrix |
| D3  | M10 | M4/M5/M9 bump sites land earlier |
| D4  | M14 | M2 tier marking |
| D5  | M12 | M1 validator anti-pattern reject |
| D6  | M1 | M3 sizing load |
| D7  | M2 (compile reject) | Phase 2 mirror live |
| D8  | M1/M2 | — |
| D9  | M8 | M3 `g_active` scaffold |
| D10 | M9 | — |
| D11 | M8 | M9 arena GC hook |
| D12 | M8 | — |
| D13 | M4 | M3 dynfield |
| D14 | M5/M6 | — |
| D15 | M6 | M2 compiler |
| D16 | M7 | M15 lab |
| D17 | M5 | M1 schema field |
| D18 | M15 | M7 dispatcher micro-cycle budget |
| D19 | M7 (TAG / idle), M3 (worker loop idle spec Q7) | — |
| D20 | M5 | — |
| D21 | M6 | M7 dispatcher NEXT_L4 routing |
| D22 | M2 | — |
| D23 | M2 | M3 mempool NUMA allocation |
| D24 | M9 | M8 GC ordering |
| D25 | M7 | M0 `-Wswitch-enum` CI gate |
| D26 | M7 (compile reject) | Phase 2 mirror live |
| D27 | M5 | — |
| D28 | M3 | M2 validator, M12 port init |
| D29 | M2 | — |
| D30 | M8 | — |
| D31 | M4/M5/M6 (per-stage) | M10 counter exposure |
| D32 | M4 | M10 counter exposure |
| D33 | M0 (grep) + M10 (living) | — |
| D34 | M9 | — |
| D35 | M8 | M11 cmd_socket + inotify funnel |
| D36 | M8 | — |
| D37 | M1 | M8 under reload |
| D38 | M11 | M10 counter exposure |
| D39 | M3 (validator) + M4 (classify_l2 assert) | M10 counter exposure |
| D40 | M5 (bump sites) | M10 counter exposure |

---

## 4. What this plan deliberately does not do

- **No timeline / calendar estimates.** Claude is not guessing
  how long M8 takes. The gate is "tests green", not "two weeks".
- **No pre-coding.** Nothing is written before its RED test
  lives in `tests/` and fails for the right reason.
- **No scope creep.** Any new bug found during implementation
  lands in drafts first, then in code. No "while I'm here" fixes.
- **No skipping sanitizers.** If asan is flaky, fix the flake.
  The user has root — we're allowed to spend time on the
  machine state, not on bypassing checks.
- **No `--no-verify` commits.** If the pre-commit hook fails,
  fix the underlying issue.
- **No merging with red tests.** A milestone is not done until
  its exit gate is met, regardless of how much feels "finished".

---

## 5. Ready-to-start checklist

Before `m00-harness` starts:

- [ ] `ssh dpdk` reachable, DPDK 25.11 installed, 512 MB hugepages (confirmed from CLAUDE.md)
- [ ] `dpdk-devel`, `gtest-devel`, `nlohmann-json-devel`, `cmake ≥ 3.22`, `ninja`, `clang ≥ 18`, `gcc ≥ 14` installed on dev VM
- [ ] `~/Dev/pktgate-dpdk/` synced to latest `main` (commit `6ec5910`)
- [ ] Test plan drafts and `test-plan.md` reviewed by whoever is implementing (that's probably me or next Opus session)
- [ ] `review-notes.md` skimmed end-to-end so D39/D40/Q-resolutions are in working memory
- [ ] This file (`implementation-plan.md`) committed

When all six checkboxes are ticked, M0 begins. The first commit
of M0 is the `tests/smoke/test_build.cpp` RED test that fails
because `CMakeLists.txt` doesn't exist yet — **that's the point**.
We write the test, watch it fail, add the skeleton, watch it pass,
commit.

That is what TDD looks like on a greenfield project.

---

*End of implementation plan. Next step: ticket M0 and start.*
