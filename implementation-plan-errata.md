# implementation-plan.md errata

Append-only log of known bugs in `implementation-plan.md`. Not a
replacement for the plan — a ledger of misreads, ID drift, and
scope misalignments so fresh supervisors don't re-discover them.

## How to use this file

- Read it once after `implementation-plan.md` on every fresh
  session start (add to `scratch/m{N}-supervisor-prompt.txt`
  first-read list).
- When dispatching worker for cycle Cn of milestone §Mn, cross-check
  the plan's RED list against this file's §Mn section. Trust the
  errata over the plan text.
- When you discover a new errata item, append it to the appropriate
  section with date + origin cycle + short rationale. **Do not
  modify `implementation-plan.md` itself** — errata batch-lands
  together with the next plan revision (tied to `design.md` batch
  revision per `review-notes.md` batch plan).

## Format

Each item: test ID or plan-line reference, one-line description of
the bug, rationale, resolution, origin (cycle + date).

---

## §M1 — Config parser + validator

No known errata.

## §M2 — Compiler + Ruleset builder (lines 244-278)

### Line 257 — `C7.10–C7.26 compiler_fuzz` is wrong
`C7.10-C7.26` in `corner.md` are `cmd_socket` + `inotify` tests
belonging to M11 scope. The actual compiler fuzz test is **C7.3**
(5 seed corpus files). Worker for M2 C11 used C7.3.
*Origin: M2 supervisor handoff, 2026-04-10.*

### Line 258 — `C6.1–C6.6` scope confusion
`C6.1–C6.6` are listed as M2 tests but `corner.md` treats them as
dataplane packet scenarios (M4-M6). M2 reinterpretation: they become
compiler-level entry-structure tests. Resolution: test-architect
accepted the reinterpretation; M2 C3-C5 implemented them as compiler
surface tests.
*Origin: M2 supervisor handoff, 2026-04-10.*

### `U4.*` scope drift
Plan says "U4.* Ruleset builder" but:
- **U4.2-U4.5** marked `[needs EAL]` in `unit.md` → deferred from
  M2 to M3 initially, then to **M4 C0b** after M2 silent pipeline
  gap was discovered (see §M4 below).
- **U4.9-U4.14** are `rl_arena` → **M9** scope.
- M2 actual scope: U4.1, U4.6, U4.7, U4.8, U4.15, U4.16, U4.17.
*Origin: M2 supervisor handoff, 2026-04-10.*

### `U3.25, U3.26` added after plan was written
Test architect added these after `implementation-plan.md` was
drafted. They belong in M2 (compiler surface). M2 C3 landed U3.25
alongside L2 compound tests.
*Origin: M2 supervisor handoff, 2026-04-10.*

## §M3 — EAL port init + D28/D39 + dynfield + worker skeleton (lines 282-317)

### Line 293 — `U6.53` misassigned to D28
`U6.53` is REDIRECT burst-end drain, which is **M7** scope. M3 D28
tests are `F1.13` + `X2.8` + `U4.16` (already done in M2 as pure
C++ test).
*Origin: M3 supervisor handoff, 2026-04-11.*

### Line 296 — `U4.17` already taken
Plan lists `U4.17` as new D39 port validator test, but `U4.17` is
"generation counter" landed in M2 C9. D39 port validator needs a
fresh ID. Resolution: use **U4.18**, add entry to `unit.md` in the
same commit as the test. M3 C3 landed U4.18 (functional F1.14 +
unit deferred to M4 C0b per [needs EAL]).
*Origin: M3 supervisor handoff, 2026-04-11.*

### Line 298 — `U6.1 dynfield registration` collides with unit.md
Plan assigns `U6.1` to mbuf dynfield registration (M3 C4), but
`unit.md:763` defines `U6.1` as **"L2 — empty ruleset → NEXT_L3"**
(a classify_l2 test belonging to M4). Collision resolved in M4 C0b
(`c6d0c97`) by renaming the M3 dynfield test to `U6.0a` "Mbuf
dynfield registration [needs EAL]" and freeing `U6.1` for its
`unit.md` spec (used by M4 C1 `7a13b6e`).
*Origin: M3 C4 (silent collision 2026-04-12) → M4 C0b fix 2026-04-13.*

### Unlisted: `U4.2-U4.5` needed EAL but plan didn't schedule them
`unit.md` marked U4.2-U4.5 as `[needs EAL]`, deferring them out of
M2. M3 supervisor handoff added them to M3 scope reasoning
"deferred from M2, M3 is first milestone with EAL". This turned
out to be a **misread** (M2 never had FIB/hash population in the
first place — see §M4 below). Tests actually landed in M4 C0b.
*Origin: M3 handoff misread 2026-04-11 → surfaced in M3 C6 blocker
2026-04-12 → fixed in M4 C0b 2026-04-13.*

## §M4 — Classifier L2 (lines 321-352)

### Missing: C0 retrofit not in plan
Plan §M4 starts directly with classify_l2 RED list. But per D41
(pipeline smoke invariant, `review-notes.md`) and user decision
2026-04-12, M4 C0 retrofit is the mandatory first cycle covering:
compile_l2/l4_rules wiring, L3CompiledRule + compile_l3_rules,
CompileResult compound fields, Ruleset rte_hash*/rte_fib*/rte_fib6*
fields, real DPDK allocations in builder, U3.Smoke1 pipeline smoke
test, U4.2-U4.5 + U4.18 EAL unit tests, U6.0a rename. Split into
C0a (compiler wiring, `bb73b5e`) and C0b (Ruleset EAL populate,
`c6d0c97`).
*Origin: M2 silent gap discovered in M3 C6 2026-04-12 → D41 accepted
same day → retrofit landed in M4 C0a/C0b 2026-04-13.*

### Line 329 — `U6.1-U6.9` includes `U6.2a`
`U6.2a` is D39 multi-seg drop, already done in M3 C5 (`44f6ac6`).
Read line 329 as "U6.1-U6.9 **except** U6.2a".
*Origin: M4 supervisor handoff, 2026-04-12.*

### `U4.18 [needs EAL]` deferred from M3
M3 C3 commit `56bc986` body notes: "U4.18 entry (needs EAL,
deferred to C6)". M3 C6 was deferred to M4 C0. Resolution: M4 C0b
(`c6d0c97`) landed U4.18 as EAL unit test.
*Origin: M3 C3 deferral 2026-04-12 → M4 C0b fix 2026-04-13.*

### C0b silent gap: `populate_ruleset_eal()` orphaned from `main.cpp`
M4 C0b (`c6d0c97`) added `populate_ruleset_eal()` in
`src/ruleset/builder_eal.{cpp,h}` with real `rte_hash_create` /
`rte_fib_create` / `rte_hash_add_key_with_hash` / `rte_fib_add`
calls, and U4.2–U4.5 unit tests passed under `eal_fixture.h`. But
`main.cpp` was **never updated** to call the function on the boot
path — `build_ruleset()` created the pure-C++ arenas and the boot
went straight to worker launch, leaving `rte_hash`/`rte_fib` tables
empty at runtime. Unit tests missed it because they invoked
`populate_ruleset_eal()` inline in the fixture helper, not through
`main()`. F1.1 (`test_f1_boot`) missed it because it only asserts
`"ready":true` and clean exit.

Surfaced in **M4 C8** (2026-04-13) when F2.* functional tests
injected traffic and observed zero `matched_packets` in
`stats_on_exit` despite a non-empty `l2_compound_count` in the
`ruleset_published` log line. C8 WIP added the missing
`populate_ruleset_eal()` call to `main.cpp` phase 6 (between
`build_ruleset()` and the `ruleset_published` log line).

Second silent gap of the M2/C0 family after `compile_l2/l4_rules`
orphaning. D41 amended same day to require a **boot-path smoke**
tier alongside the compile-side smoke; see `review-notes.md` §D41
"Amendment 2026-04-13 — boot-path wiring clause". F2.* retroactively
serves as M4's boot-path smoke.

*Origin: M4 C0b gap 2026-04-13 → surfaced in M4 C8 predecessor
work same day → fix landed in C8 WIP (main.cpp `populate_ruleset_eal`
call) + D41 amendment.*

## §M5 — Classifier L3 (lines 356-399)

### C1 RED list — plan↔unit.md ID drift on D14/D31 IPv4 row
Plan §M5 lists `unit.md U6.12–U6.17` as the D31 L3 bucket tests
and `U6.19` as the D14 IHL row. Reading the actual `unit.md` entries:

- **U6.12** = IPv4 short packet → `l3_v4` trunc — **C1 scope ✓**
- **U6.13** = IPv4 `IHL<5` drops `l3_v4` — **this is the D14 reject
  test; C1 scope ✓** (plan misattributes D14 to U6.19)
- **U6.14** = **IPv6** short packet → `l3_v6` trunc — **C4 scope**,
  NOT C1
- **U6.15** = IPv6 frag-ext truncated → `l3_v6_frag_ext` — C6
- **U6.16** = L4 truncated TCP → `l4` — M6
- **U6.17** = meta dispatch-table — structural, any milestone with
  full D31 surface
- **U6.18** = IPv4 dst FIB hit → (unit.md wording: `TERMINAL_L3`,
  stale pre-D21 text) — **C1 scope ✓** (the real dst FIB primary
  hit test; C0 shipped enum `{kNextL4, kTerminalPass, kTerminalDrop}`
  without `TERMINAL_L3`, so the verdict is `kNextL4` on allow /
  `kTerminalDrop` on drop rule action)
- **U6.19** = IPv4 IHL=6 L4 offset uses `ihl<<2` — **M6 scope**;
  D14's L4-offset contribution belongs to classify_l4, not M5

**Resolution.** M5 C1 transcribes **U6.12 + U6.13 + U6.18 + new
U6.18a** ("IPv4 dst FIB miss → kNextL4 fall-through"). U6.18a is
added to `unit.md` in the same commit (same precedent as M4 C0
U6.0a + M5 C0 U6.11a). U6.18's stale `TERMINAL_L3` wording is
updated inline to current enum dispatch (allow → `kNextL4`, drop →
`kTerminalDrop`). Drop the handoff's `U6.14`/`U6.19` C1 references
as ID drift.

M5 C4 transcribes U6.14 + U6.15 (IPv6 trunc family). M6 owns U6.19.

Also: the earlier errata note in `scratch/m5-supervisor-handoff.md`
§Plan errata #1 ("No plan edit in M5; worker reads U6.19 per the
narrow interpretation") is **wrong** — under the narrow
interpretation there is no M5 U6.19 test at all; the D14 IHL reject
test already exists as U6.13. Handoff file patched at the same
time as this errata entry.
*Origin: M5 C1 worker stopped at RED-prep 2026-04-15 → supervisor
resolution same day (Option A).*

### C1 U6.18 / U6.18a validate an interim wrong-primary-key schema

C1 tests (U6.18 dst FIB hit, U6.18a dst FIB miss) exercise the
current pipeline as it is: `compile_l3_rules` reads
`rule.src_subnet`, packs each CIDR as `L3PrimaryKind::kIpv4DstPrefix`,
`populate_ruleset_eal` inserts it into the dst-prefix FIB, and
`classify_l3` reads it back as a dst-prefix match. All three
layers agree on the wrong label, so the tests pass and the
dataplane routes packets correctly.

This is **not** an M5 bug — it is the same `src_subnet`-as-dst-primary
interim that `rule_compiler.{h:108-132,218-220; cpp:261-264}` has
documented since M2 and that `review-notes.md` §5.3 "try src?"
dead-branch item has been tracking as an open design question.
Formalised at handoff time as `review-notes.md` §P10. See that
entry for the three resolution options (defer / grow / rename)
and the consultant lean.

**Impact on U6.18 / U6.18a under each P10 option:**

- **(a) defer:** tests stay as-is, interim schema is MVP forever.
- **(b) grow dst_subnet:** U6.18 / U6.18a fixtures rewrite to
  feed `dst_subnet` as the address constraint. Logic of the tests
  (hit → dispatch, miss → fall through) stays identical.
- **(c) rename src_subnet → dst_subnet:** U6.18 / U6.18a fixtures
  update their JSON field name in one sed pass; test logic
  unchanged.

No action in M5 C1 errata — flagged here purely so the next
reader does not misread U6.18's "src\_subnet routes through the
dst FIB" as a C1 worker bug.

Under P10(c) (resolved 2026-04-15 in M5 C1c), fixtures
rename in one sed pass; test logic unchanged. U6.18 /
U6.18a / U6.18b stay green transparently — they live on
`action_idx >= 1` and the rename only touches field name /
JSON key.

*Origin: M5 C2 worker stop-and-report 2026-04-15 → consultant
verification of code paths → P10 promotion.*

### C2 BLOCKED on review-notes P10 → RESOLVED via M5 C1c rename

**RESOLVED 2026-04-15 → subsumed into M5 C1c rename.**
User chose P10 option (c). No secondary FIB cycle; no
`l3_v4_src`/`l3_v6_src` storage. C2 row in the state
table became SUBSUMED_BY_C1c. See C1c commit `de0ff83`.

Historical record below preserved verbatim for the
decision trail.

**M5 C2 as written in `implementation-plan.md` §M5 is
undispatchable until `review-notes.md` §P10 resolves.**

C2 cell description: *"IPv4 src-prefix secondary + compound L3
(src+dst / VRF)"*. M5 handoff `§C2` repeated the same. None of
this is implementable against current code, because:

- No `dst_subnet` field exists on `config::Rule` (model.h:205) —
  so "src-prefix secondary" has nothing to complement.
- `src_subnet` is already consumed as the primary key
  (rule_compiler.cpp:275-298) — a second "src-prefix probe" has
  no distinct source field.
- `Ruleset` has no `l3_v4_src` / `l3_v6_src` storage — the
  secondary FIB does not exist.
- `test-plan-drafts/unit.md` has zero src-prefix secondary
  tests — the plan cell's RED list is an empty set.

**Cause.** Plan cell was written in batch assuming M1/M2 would
grow `dst_subnet` before M5 arrived. They did not. The same
parallel-track debt is simultaneously tracked in
`review-notes.md` §5.3 dead-branch item. Nobody cross-checked
plan cells against open items at plan-authoring time. See memory
grabli `plan_cell_assumes_unscheduled_debt` for the generalised
pattern.

**Supervisor action.**

- M5 handoff state-table row for C2 → `BLOCKED_ON_P10` (per
  `scratch/m5-supervisor-handoff.md` patch landing with this
  errata entry).
- **Do not dispatch C2** until user resolves P10.
- **C3 – C10 are independent** of src-prefix secondary per the
  handoff dependencies matrix and may proceed:
  - C3 = IPv4 fragments + D40 — works on C1 body; no src probe.
  - C4 = IPv6 dst FIB + D31 — parallel IPv6 branch of C1.
  - C5 = IPv6 ext-header D20 — protocol walk only.
  - C6 = IPv6 Fragment ext D27 + D40 — fragment logic only.
  - C7 = IPv4 corner — uses C1-C3 body.
  - C8 = IPv6 corner — uses C4-C6 body.
  - C9 = fragment policy matrix — uses C3 + C6.
  - C10 = F4 functional + REFACTOR — uses C1-C6 body.
- M5 C1b retrofit (`valid_tag` disambiguation of FIB miss vs
  zero-packed entry) is **mechanical, independent of P10**, and
  dispatches first in the new order: `C1 → C1b → C3 → C4 → …`.
  C2 sits in a parking lot; if P10 option (a)/(c) resolves, C2
  closes as "deferred" or "subsumed into rename"; if option (b)
  resolves, C2 reopens after the multi-milestone growth work
  lands and gets a fresh row in the state table.

**Follow-up on P10 resolution.** Whoever closes P10 is responsible
for updating this errata entry (status: RESOLVED → option X
chosen) and either deleting C2's BLOCKED row in the handoff or
rewriting its scope per the chosen option.

*Origin: M5 C2 worker stop-and-report 2026-04-15 → consultant
claim verification → P10 promotion + C2 blocking.*

### C3 silent gap: `cfg.fragment_policy` → `rs.fragment_policy` never wired — RESOLVED by C3b `95ceea7`

**Surfaced 2026-04-15 by M5 C3 worker (`559c5b3`).** Not a C3
defect — a pre-existing compiler/builder hole exposed now that
`classify_l3` actually consumes `rs->fragment_policy` at
runtime. **Resolved 2026-04-16 by M5 C3b (`95ceea7`):**
`CompileResult.fragment_policy` added to `compiler.h`, set in
`object_compiler.cpp::compile()`, copied in both
`build_ruleset()` overloads in `builder.cpp`. U6.22 test
(FragmentPolicyWired) confirms kDrop/kAllow/kL3Only propagation.

**The hole.** `config::Config.fragment_policy` is parsed
correctly by M1, but neither `compile_ruleset` nor
`populate_ruleset_eal` copies the value into
`Ruleset.fragment_policy`. C3 unit tests work around this by
setting `rs.fragment_policy` directly on the test fixture
(`ClassifyL3Ipv4FragmentTest::SetUp`), so all 7 C3 REDs
(U6.21–U6.25, U6.26a, U6.26b) exercise the classify_l3
three-arm switch without going through the config path at
all. Config-path is effectively dead for this field.

**Scope boundary decision.** M5 C3 is a classify_l3 cycle; it
cannot touch compiler/ruleset under the milestone's layer
hygiene rules. Worker correctly flagged and did not fix.

**Closure plan: M5 C10 F4 functional.** C10 ships
`tests/functional/test_f4_l3.py` which drives the full
`config.json → parse → compile → populate → classify_l3`
pipeline end-to-end. F4.1–F4.10 cannot exercise
`fragment_policy` without the wiring, so C10 GREEN is blocked
until the copy lands. Expected touch: one-line field copy in
`compile_ruleset` (or wherever `Ruleset` is built from
`Config`) + one-line copy into the EAL-fill path if it
bypasses the compiler. No new D-number; the field already
exists on both sides.

**If C10 reveals the gap is broader** (per-interface override,
parser schema divergence, etc.) — escalate to a dedicated
C9b / C10a retrofit, not a quiet inline fix. D41 pipeline
smoke invariant was supposed to catch this class early;
the reason it didn't is that M4 smoke predated D17 landing,
so there was no `fragment_policy` to propagate yet. C3 is
the first cycle where the field actually matters at runtime.

**Memory echo.** Same class as `grabli_m2_silent_pipeline_gap`
(M2 compound builders orphaned from `compile()`), but this
one is one-field-shallow and C10 will pick it up naturally.
No new grabli file — existing precedent already covers the
lesson ("pipeline milestones need end-to-end smoke").

*Origin: M5 C3 worker closing report 2026-04-15 → supervisor
logged here before C4 dispatch so the C10 prompt carries the
dependency forward.*

### D32 QinQ `l3_offset = 22` never happens in MVP
Earlier handoff template prose said "QinQ → l3_offset=22" but
`classify_l2` walks exactly one tag in MVP (0x8100 or 0x88A8), so
`l3_offset` stays at 18 for single-tag shapes and D32's
`qinq_outer_only_total` bumps only when inner ethertype is itself
a VLAN TPID (the case we deliberately don't drill). Phase 2 may
add full QinQ drilling with `l3_offset=22`. Canonical wording:
`review-notes.md` §D32 + `unit.md` U6.8/U6.9.
*Origin: M4 C4 worker flagged inverted prose 2026-04-13 → handoff
template fixed same day.*

---

## §Scope trim — Phase 1 MVP reduction (2026-04-16)

User-approved scope trim to reduce remaining cycle count (~65 →
~45) and cut operational features that are not load-bearing for
Phase 1 acceptance criteria.

**Motivation:** M0–M5 consumed ~59 TDD cycles. Remaining M6–M15
at original scope is ~65 more. Ratio of ceremony to code output
is too high; trimming non-core milestones restores momentum.

### M10 — Telemetry: Prometheus-only

**Original scope**: four export channels (Prom HTTP, sFlow UDP v5,
`rte_tel` DPDK endpoints, per-lcore SPSC log ring), snapshot ring
buffer N=4, D33 living CI gate.

**Trimmed scope**: **Prometheus `/metrics` endpoint only.** Drop
sFlow encoder, `rte_tel` endpoints, per-lcore log ring. Snapshot
publisher thread stays (single consumer for Prom). D33 counter
consistency grep (U7.5 + C7.27) stays — it validates counter
names in the doc tree, not export channels. The counter layout
in `WorkerCtx` / `stats.h` is already wired from M4/M5 and does
not change.

**What moves out**: sFlow (F8.6–F8.9), rte_tel (F8.10–F8.13),
log ring (U10.5–U10.11). These become Phase 2 features if a
customer asks.

**Estimated reduction**: ~10-12 cycles → ~5-6 cycles.

### M11 — Control: inotify-only

**Original scope**: UDS command socket (`/run/pktgate/ctl.sock`)
with SO_PEERCRED (D38) + verb router + allow-list, AND inotify
file-watch with debounce (D38 `IN_CLOSE_WRITE`-only). Both funnel
into M8 `deploy()` under `reload_mutex` (D35).

**Trimmed scope**: **inotify file-watch reload only.** Drop UDS
cmd_socket entirely. Reload triggered by writing a new config
file; no runtime command interface. `activate` verb (HA park →
live) also drops — ties to M12 which is deferred.

**What moves out**: SO_PEERCRED (X3.1–X3.9), UDS verb router
(U9.11–U9.17, F6.11–F6.14, F7.1–F7.4), `activate` verb
(X3.11). These become Phase 2 if UDS control is needed.

**Estimated reduction**: ~6-8 cycles → ~3-4 cycles.

### M12 — Watchdog / bypass / HA: DEFERRED

**Original scope**: systemd `WatchdogSec` integration, heartbeat
publish, `--standby` park/activate lifecycle, K-crash bypass
policy, D5 HA anti-pattern reject in validator.

**Trimmed scope**: **entire milestone deferred to post-Phase-1.**
Binary runs as a foreground process without watchdog. No standby
mode. No crash-count bypass. D5 anti-pattern validator rules
stay in M1 config validator (they already exist and are
zero-cost) but the runtime HA machinery is not built.

**What moves out**: all of F1.2–F1.8, F5.17, X4.1–X4.6, X2.1,
X2.2. These become Phase 2 when the operator requests HA.

**Estimated reduction**: ~5-7 cycles → 0 cycles.

### M14 — rte_flow: confirmed minimal stubs

No change from plan — M14 already ships disabled with only
compiler tier-marking stubs and `static_assert`'d-off publish
path. Confirming this remains the intent: no real `rte_flow`
work in Phase 1. Lab-only gating via `perf.md` P-L8 stays
parked.

### Impact on M8 (RCU + reload)

M8 is **not trimmed** — reload path is load-bearing for Phase 1
(operator must be able to update rules without restarting the
binary). However, with M11 trimmed to inotify-only, M8's reload
entry points simplify: only one source (inotify) instead of
three (inotify + cmd_socket + telemetry). `reload_mutex` (D35)
still needed but the multi-source funnel in
`src/ctl/reload_sources.h` collapses to a single caller.

### Impact on M13 (dev VM smoke)

M13 umbrella run shrinks proportionally — fewer tests to run,
fewer channels to validate. Estimate stays ~2-3 cycles (it's
just a test pass).

### Impact on M15 (lab perf gate)

No change. Lab bring-up is orthogonal to feature trim — it
validates N1/N2/N3/N5 on real hardware regardless of telemetry
channel count or HA features.

### Summary table

| Milestone | Original cycles | Trimmed cycles | Delta |
|---|---|---|---|
| M6 | 8–10 | 8–10 | 0 |
| M7 | 8–10 | 8–10 | 0 |
| M8 | 12–15 | 10–13 | −2 (simpler reload sources) |
| M9 | 6–8 | 6–8 | 0 |
| M10 | 10–12 | 5–6 | **−5–6** |
| M11 | 6–8 | 3–4 | **−3–4** |
| M12 | 5–7 | 0 | **−5–7** |
| M13 | 2–3 | 2–3 | 0 |
| M14 | 3–4 | 3–4 | 0 |
| M15 | lab | lab | 0 |
| **Total** | **~65** | **~48** | **~−17** |

*Origin: user decision 2026-04-16, consultant-recommended trim
after M5 exit gate. Not a plan revision — a scope override that
takes precedence over `implementation-plan.md` §M10/§M11/§M12
until the next batch revision.*

---

## §M7 — Action dispatch (lines 434-467)

### Compiler→builder lowering gap: CompiledAction drops dscp/pcp/redirect_port — RESOLVED by C2b `79bbf9a`

**CRITICAL — same D41 silent pipeline gap class as M2 (compound builders)
and M5 C3 (fragment_policy).**

**Resolved 2026-04-16 by M7 C2b (`79bbf9a`):**
`CompiledAction` extended with `dscp` (uint8_t), `pcp` (uint8_t),
`redirect_port` (uint16_t). `resolve_verb` replaced by a single
`resolve_action` visitor in `object_compiler.cpp` that fills both
verb + payload from the `config::RuleAction` variant. REDIRECT
`role_name` resolved **in-compiler** via `cfg.interface_roles` by
declaration index (matches `main.cpp` RTE_ETH_FOREACH_DEV zip
convention) — CompiledAction stays POD, no string storage.
Both `copy_actions` overloads in `builder.cpp` now copy
`s.dscp`/`s.pcp`/`s.redirect_port` instead of hardcoding
zeros/sentinel. `CompileResult.default_action` added alongside
`fragment_policy` (same pattern), wired in `compile()` from
`cfg.default_behavior`, copied in `build_ruleset`. Tests
U3.Smoke2/U3.Smoke3/U3.Smoke4 confirm TAG/REDIRECT/default_action
config→runtime roundtrips. U6.44-U6.55 stayed green.

`compiler::CompiledAction` (compiler.h:83-88) only carries four fields:
`rule_id`, `counter_slot`, `verb`, `execution_tier`. The `resolve_verb`
visitor in `object_compiler.cpp:53-68` extracts only the verb enum from the
`config::RuleAction` variant, discarding all action-specific payload
(`dscp`, `pcp` from `ActionTag`; `role_name` → port_idx from
`ActionTargetPort`; rate fields from `ActionRateLimit`).

`builder.cpp` `copy_actions` (two overloads, lines 43-64 and 160-181)
copies from `CompiledAction` to `action::RuleAction` and **hardcodes**:
```
d.dscp = 0; d.pcp = 0; d.redirect_port = 0xFFFF;
d.mirror_port = 0xFFFF; d.rl_index = 0;
```

**Production impact:**
- **TAG** actions are no-op — DSCP stays 0, PCP stays 0.
- **REDIRECT** silently drops every packet — 0xFFFF sentinel triggers
  the "invalid port" guard in `apply_redirect`.
- RL stub is benign for M7 (always-allow, index not consulted).

**Why unit tests passed (C1, C2):** U6.48-U6.55 construct
`action::RuleAction` directly in the test body (`tag.dscp = 46;`
`redir.redirect_port = 1;`), completely bypassing compiler→builder.
Exactly the same pattern as M5 C3 (`SetUp` writes `rs.fragment_policy`
directly).

### `cfg.default_behavior` → `rs.default_action` never lowered

`config::Config.default_behavior` (model.h:348, parsed in parser.cpp)
is never read by the compiler or builder. `Ruleset.default_action`
(ruleset.h:125) stays at its POD default `0` (= ALLOW) regardless of
config. If operator sets `default_behavior: drop`, unmatched packets
are silently allowed.

Neither `CompileResult` nor `builder.cpp` has any reference to
`default_behavior` or `default_action` (verified by grep). Wiring
is needed alongside the action-field lowering.

### Resolution: C2b retrofit before C3

Insert a **C2b retrofit** cycle between C2 and C3 in the M7 plan:

1. `CompiledAction` += `dscp` (uint8_t), `pcp` (uint8_t),
   `redirect_port` (uint16_t).
2. `object_compiler.cpp` `compile_layer`: `std::visit` on
   `rule.action` variant to fill new CompiledAction fields (TAG →
   dscp/pcp, REDIRECT → port from `ActionTargetPort.role_name`
   resolved through interface_roles, other verbs → leave defaults).
3. Both `copy_actions` lambdas in `builder.cpp`: copy `s.dscp`,
   `s.pcp`, `s.redirect_port` instead of hardcoding zeros/sentinel.
4. Wire `cfg.default_behavior` → `rs.default_action`: either via
   `CompileResult.default_action` + builder copy (consistent with
   fragment_policy pattern), or direct wire in main.cpp after
   `build_ruleset` returns.
5. Unit test: config → compile → build_ruleset → assert
   `RuleAction.dscp/pcp/redirect_port` roundtrip per verb type +
   `rs.default_action` matches config.

*Origin: M7 C2 closure `ae926ef` 2026-04-16 → supervisor CRITICAL STOP
→ consultant verification of full lowering path. Third D41 instance.*

---

## §M8 — Hot reload + RCU polish (lines 470-509)

### Pre-M3 RCU reader gap: worker cached ruleset at launch, never re-read `g_active` — RESOLVED by C5

**CRITICAL — fourth D41 silent pipeline gap class.**

Before M8 C5, `worker_main` (`src/dataplane/worker.cpp`) stored
`ctx->ruleset` once at lcore launch and dereferenced it for every
packet burst thereafter. `g_active` was never acquire-loaded on the
hot path. This meant:

- **Every RCU publish machinery from M3 onwards was structurally
  useless.** `atomic_exchange` on `g_active` in `deploy()` updated a
  pointer nobody was reading.
- The first real `deploy()` against a running worker would cause
  `classify_l{2,3,4}` to dereference the *freed* old ruleset once
  the reload manager's `synchronize` completed + `free_ruleset`
  ran — heap-use-after-free, not a hypothetical.

**Why nothing surfaced before M8 C5:**
- Unit tests (M4-M7) constructed `Ruleset` directly in test bodies;
  they never went through `worker_main`.
- Integration X1.2/X1.4/X1.5 storm tests (M8 C1-C3) used *fake*
  QSBR fixture workers in `tests/integration/test_reload.cpp`
  (register / report-quiescent loop), NOT the real `worker_main`.
  Fake workers never dereferenced a ruleset pointer.
- Functional F1-F4 tests launch the real binary but never issue a
  second `deploy()` mid-run — the cached pointer stayed valid
  because no reload ever happened.
- **Only F5.11-F5.14 exercise real binary + real workers + real
  reload** — which is where F5.11 materialised the bug in C5.

**Resolution 2026-04-17 by M8 C5:**
Textbook RCU reader pattern in `worker_main`:
```cpp
while (ctx->running->load(std::memory_order_relaxed)) {
    ctx->ruleset = ctl::reload::active_ruleset();  // acquire-load g_active
    if (ctx->ruleset == nullptr) {
        rte_rcu_qsbr_quiescent(ctx->qs, ctx->qsbr_thread_id);
        continue;
    }
    const uint16_t nb_rx = rte_eth_rx_burst(...);
    if (nb_rx == 0) {
        rte_rcu_qsbr_quiescent(ctx->qs, ctx->qsbr_thread_id);  // idle too
        continue;
    }
    // classify / dispatch using the stable local pointer
    rte_rcu_qsbr_quiescent(ctx->qs, ctx->qsbr_thread_id);  // end of burst
}
```

Per-burst acquire-load is the RCU reader canonical form — single
`mov` with ordering on x86-64, zero contention, NOT a D1 violation.
The D1 amendment in review-notes.md was clarified the same day:
D1 forbids atomic RMW / CAS / fetch_add on the hot path, not
acquire-loads (the whole point of D9 is that workers acquire-load
`g_active` per burst). Idle-path quiescent report is a D19
clarification: a zero-RX worker would otherwise starve the
reload manager's synchronize deadline.

**Why the bug was specifically D41 (silent pipeline gap):**
All the RCU machinery (M8 C1 `atomic_exchange`, C2 `token+deadline`,
C3 `pending_free`, C4 offline/unregister) existed and passed all
its unit/integration tests. The **reader side** was never wired.
The pattern matches §M7 lowering gap exactly: intermediate struct
(here, `ctx->ruleset` cached raw pointer) drops the contract;
tests at each end construct the runtime struct directly and never
notice the gap. Only an end-to-end pipeline smoke (F5 functional,
real worker + real reload) surfaces it.

*Origin: M8 C5 `3e8d6fe` 2026-04-17 → worker fixed in-cycle
rather than STOP+report; fix is correct (textbook RCU reader) but
the D41-class find warrants erratum for future milestones'
pipeline-smoke guardrails.*

---

## §M9 — Per-lcore token bucket arena (lines 513-540)

### Boot-path RlSlotAllocator gap: main.cpp called `compile(cfg)` without allocator — RESOLVED by C5

**CRITICAL — fifth D41 silent pipeline gap class.**

M9 C3 (`f4c18ac`) extended the compiler signature with
`RlSlotAllocator = std::function<uint16_t(uint64_t)>` (option a;
keeps compiler DPDK/arena-free per `grabli_m4c0_dpdk_free_core_library.md`).
The reload path (`src/ctl/reload.cpp`) was wired correctly at the
same commit: `compile(cfg, opts, rl_alloc)` with a one-line lambda
over `rl_arena_global().alloc_slot()`.

The **boot path** — `src/main.cpp` initial config load before any
reload — kept calling `compile(cfg)` with the default-arg empty
allocator. Consequences on a fresh-boot binary with one or more
RL rules in config:

- Every boot-time `kRateLimit` action got `rl_slot = kInvalidSlot`.
- `build_ruleset` saw the sentinel and skipped the D41 lockstep
  populate of `Ruleset::rl_actions[slot] = {rule_id, rate, burst}`.
- `n_rl_actions` stayed 0 across the whole process lifetime.
- `apply_action(kRateLimit)` hit a slot the arena never knew about
  → either default-allow or undefined behavior depending on the
  branch order; in practice traffic just went through unfiltered.
- Real reloads (SIGHUP-triggered) overwrote the broken initial
  `g_active` with a correctly-built ruleset, hiding the boot bug
  for any test that exercised at least one reload before measurement.

**Why nothing surfaced before M9 C5:**
- C2 integration test `test_rl_integration.cpp` manually wired
  `arena.alloc_slot` + `Ruleset::rl_actions[s]` for hot-path-only
  coverage — bypassed compiler entirely.
- C3 integration test `test_rl_compile_build.cpp` constructed its
  OWN allocator lambda inline and called `compile(cfg, opts,
  rl_alloc)` directly. The boot-path `compile(cfg)` overload was
  never invoked from any test.
- Unit tests U4.* / U5.* construct `RateLimitArena` directly.
- Functional F5 (M8 reload) tests issue a reload before measuring
  → reload path wired correctly → no observable bug.
- **Only F3.12 (allow under limit, no reload before measurement)
  exercises real binary + boot path + RL classification.** F3.12
  failed with `rl` list empty in stats-on-exit despite one RL rule
  in config — surfaced the gap.

**Resolution 2026-04-17 by M9 C5 (`3fa66d9`):**
Symmetric wiring in `src/main.cpp` boot path:
```cpp
auto rl_alloc = [](uint64_t rule_id) -> uint16_t {
    return pktgate::rl::rl_arena_global().alloc_slot(rule_id);
};
auto compiled = compiler::compile(cfg, opts, rl_alloc);
```

Same lambda shape as `reload.cpp` deploy path — duplicated by hand.
A future cleanup could factor out a `make_default_rl_allocator()`
helper to prevent this exact divergence on the next allocator-style
field.

**Why the bug was specifically D41 (silent pipeline gap):**
The compiler signature change in C3 added a new "field" (the
allocator argument) that the boot path never threaded through.
Every test had its own allocator binding; production boot path
got the default. Pattern matches M2 / M5 / M7 / M8 exactly:
intermediate boundary (here, the compile() callsite) drops the
contract; tests at each end construct the binding directly and
never notice the gap. Only end-to-end pipeline smoke (F3
functional, real binary + real classification + measure-before-reload)
surfaces it.

This is now the **fifth** D41 instance and the **second** that the
M9 review missed at design time despite explicit `D41 watch in C3`
in the supervisor handoff. The watch caught the compiler→builder
roundtrip (covered by `C3-Roundtrip.TwoRulesThreeStagesLockstep`)
but missed the `compile()` call-site fan-out — main.cpp wasn't on
the surface area the integration test interrogated.

**Phase 2 follow-up reminder:** the compile-time guard suggested
in `grabli_m2_silent_pipeline_gap.md` (sizeof assert / lower-action
function with -Wswitch-enum) does not catch this *call-site*
variant. A separate guard for compiler entry-point arity drift —
e.g. removing the default-arg overload and forcing every caller to
supply the allocator explicitly — would. Defer to milestone-end
hygiene pass.

*Origin: M9 C5 `3fa66d9` 2026-04-17 → worker fixed in-cycle. The
fix is correct (symmetric wiring) but the D41-class find warrants
erratum so the call-site default-arg pattern is on the radar for
M10+ pipeline additions.*

---

## §M11 C1.5 — TSAN race fix + M10 C5 retroactive claim correction

### The race that ate M10 C5's exit-gate claim

At M10 C4 (commit `b87149b`, "wire §10.3 counters → snapshot →
encoder + F8.2 living invariant"), the telemetry snapshot pipeline
landed with:

- **Writer side** (worker lcore, in `classify_l{2,3,4}.h`,
  `classify_entry.h`, `action_dispatch.h`, `worker.cpp`): plain
  `++(*ctr)` / `++(*ctrs)[idx]` read-modify-write on
  `std::uint64_t` storage.
- **Reader side** (SnapshotPublisher thread, in
  `src/telemetry/snapshot.cpp::relaxed_load_u64` /
  `relaxed_load_bucket`): `__atomic_load_n(p, __ATOMIC_RELAXED)`.

The file header comment in `snapshot.cpp` at that point claimed
"reader-side uses `__atomic_load_n` to make TSan see the access as
synchronising". **That is false.** The C++ memory model requires
BOTH sides of a concurrent access to be atomic operations on the
same storage for the pair to be well-defined (and for TSan to not
report a race). Plain write + atomic load = data race, reported
every time.

### Exit-gate claim correction

M10 C5 commit `00b7d23` body asserted dev-tsan **38/38 GREEN** on
the functional label. Re-running dev-tsan on the
`m10-telemetry` tag at M11 C1.5 kickoff reproduced the race and
seven failing dtap-based functional tests:

- `functional.test_f2_l2`
- `functional.test_f2_l4`
- `functional.test_f4_l3`
- `functional.test_f3_action`
- `functional.test_f3_ratelimit`
- `functional.test_f8_qinq_counter`
- `functional.test_f8_metrics::test_f8_14_qinq_outer_counter_via_metrics`

All seven share the same root cause: the plain-write ↔ atomic-load
pair described above, on a counter stored in `WorkerCtx` (or a
RuleCounter row inside `ruleset::counter_row(lcore_id)`) on the main
thread's stack, bumped by the worker and sampled by the
SnapshotPublisher on every 1 Hz tick.

The **m10-telemetry annotated tag is NOT rewritten** — tag history
is immutable. The errata records the correction forward.

### Protocol addendum — exit-gate TSAN claim evidence

Henceforth every exit-gate commit body that mentions dev-tsan test
counts MUST paste the actual ctest tail (last ~20 lines of
`ctest --preset dev-tsan -L "..."  -j 1 --output-on-failure`) into
the commit body. Naked "N/N GREEN" claims without evidence are
rejected at exit gate. Applies to M0-M13 retroactively for future
milestones; supervisor handoff files should surface this as a
pre-commit checklist item.

### Fix summary (landed in M11 C1.5)

- **New header** `src/dataplane/lcore_counter.h` with three inline
  helpers: `relaxed_bump(p)`, `relaxed_bump_bucket(arr, idx)`,
  `relaxed_add(p, delta)`. Each lowers to `mov; op; mov` on x86-64
  (no `lock` prefix) — codegen story unchanged vs. the previous
  plain `++(*p)`; the only difference is that the load and store
  are tagged atomic so the C++ memory model treats the access as
  a matched pair with `relaxed_load_u64` on the reader side.
- **Writer-side replacements** at ~20 bump sites across
  `classify_l2.h`, `classify_l3.h`, `classify_l4.h`,
  `classify_entry.h`, `action_dispatch.h`, `worker.cpp`.
- **Reader side**: `src/telemetry/snapshot.cpp` comment rewritten
  to reflect the corrected model (both sides atomic; single-writer
  invariant; no `lock` prefix on x86-64).
- **D1 amendment**: `review-notes.md` §D1 gains a "telemetry
  counter clause" with the rationale + codegen check + forbidden
  alternatives (`fetch_add`, `no_sanitize`, `std::atomic::fetch_add`).
- **`tests/tsan.supp` unchanged** — still 16 lines (M3 baseline);
  no new suppression. This is a real-bug fix, not a silencer.

### Forward commitment

Any future change that adds a counter read by the publisher thread
MUST use `dataplane::relaxed_bump` (or `_bucket` / `_add`) on the
writer side, and MUST NOT introduce `fetch_add` / `std::atomic` on
the counter field. A reviewer seeing `++` on a cross-thread-read
counter treats it as a bug, not a stylistic preference.

*Origin: M11 C1.5 (2026-04-17). Seven functional tests turned RED
at M11 C1 HEAD; bisect traced to M10 C4, M10 C5's exit-gate claim
retroactively falsified. Fix approved in this cycle; no push, no
amend, no tag rewrite.*

## §M13 — dev-debug gate matrix

M13 gate matrix expanded from `{asan, tsan}` to
`{debug, release, asan, ubsan, tsan}`. `scripts/run_all.sh`
orchestrates the full matrix on the dev VM: clean `/run/dpdk`,
configure, build, `ctest -j 1 -L "smoke|unit|functional|integration|chaos"`,
chown back to `mit:mit`, one `===== MATRIX SUMMARY =====` line per
preset. Fuzz preset remains out per plan §0.2 (libFuzzer has its
own CI job; per-cycle gate stays green in seconds, not minutes).
Effective from C0 (`e7ce43e`); C0 also carried the real fixes
(release-build constexpr + ubsan alignment) that made `dev-release`
and `dev-ubsan` green in the first place.

*Origin: M13 C1 (2026-04-18).*

### M13 C2 — systemd skeleton + observed flake

`systemd/pktgate-devvm.service` added as a dev-VM-only oneshot
wrapper around `scripts/run_all.sh` (not enabled at boot, not a
production unit). `systemd-analyze verify` clean.

Observed flake during the C2 final matrix: `dev-tsan`
`functional.test_f2_l4::test_f2_25_l4_icmpv6_match` reported
`matched_packets=2` (expected 1) once when the test ran inside the
full back-to-back matrix; 3/3 isolated reruns passed, and a clean
full-preset re-run of `dev-tsan` went 43/43 green. Suspected cause
is kernel IPv6 NDP contamination on the `dtap_*` interface when
prior tests leave state behind — NM keyfile suppresses DHCP but
does not disable kernel neighbour-discovery. Not a code regression
(no `src/` or `tests/` change since C1 `aaf22a5`); tracked here as
a known-flake for a future harness hardening cycle.

*Origin: M13 C2 (2026-04-18).*

## §D41 closure — post-Phase-1 guard trilogy

D41 silent-pipeline-gap класс закрыт post-Phase-1. Три цикла:

- **C1** (`6e976c8`) — compile-time tuple-projection guard
  (`observable_fields()` в `action.h` / `compiler.h`) + runtime
  roundtrip unit test `test_d41_guard.cpp`.
- **C1b** (`2318371`) — `resolve_action` visitor exhaustiveness
  через `static_assert(always_false_v<T>)` (dependent-false idiom).
- **C2** (`1bfb806`) — EAL boot-path smoke `test_d41_eal_smoke.cpp`;
  per-rule projection roundtrip post-`populate_ruleset_eal` +
  Q6 lockstep `rs.rl_actions[slot]` runtime assertion.

Три-axis coverage: struct shape drift (static_assert pair),
variant arm drift (static_assert exhaustive), call-graph orphan
(EAL boot-path smoke).

**Инстансы покрыто** (6, все pre-Phase-1, все fixed):
M2 `compile_l2/l4_rules` orphan; M4 C0b `populate_ruleset_eal`
orphan; M5 C3 `fragment_policy` wiring; M7 C2b dscp/pcp/
redirect_port; M8 C5 RCU reader cache; M9 C5 RlSlotAllocator
boot-path wiring.

**Active regressions:** none. Full M13 matrix (5/5 presets) clean
first-pass 45/45 на C2 закрытии. Каждое будущее расширение
(новый CompiledAction field, новый `config::RuleAction` variant
arm, новая boot-path stage) должно расширять guard'ы lockstep;
dead-carrier re-add recipe в комментариях `src/action/action.h`
и `src/compiler/compiler.h`.

Canonical decision body: `review-notes.md §D41` + Amendment
2026-04-18 (C3 — class closure).

*Origin: post-Phase-1 debt, D41 supervisor brigade 2026-04-18.*

---

*Last updated: 2026-04-18 (D41 class closure — C1/C1b/C2 guard
trilogy landed; three-axis coverage struct-drift + variant-drift
+ orphan boot-path). Preceded by §Design.md bugs section removal —
sole entry L4CompoundEntry size mismatch closed in design.md
Round-2 batch revision commit `b0a3928`, finding F1+F6;
`static_assert(sizeof(L4CompoundEntry) == 10)` now lives in §4.1.*
