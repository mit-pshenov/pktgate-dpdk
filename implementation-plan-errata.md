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

## Design.md bugs (NOT plan errata — migrate to design.md batch revision)

This section tracks architectural doc bugs discovered during
implementation. They don't belong in this file long-term (errata
file is for `implementation-plan.md`), but dumping them here for
now so they aren't lost before the next `design.md` revision.

### L4CompoundEntry size mismatch (§4.1)
`design.md` §4.1 says `L4CompoundEntry = 12 B` but the field list
sums to **10 B**. Discovered in M2 C2 `dc8cecc` during static_assert.
Resolution: fix doc to match fields (10 B) or add padding (12 B).
*Origin: M2 C2, 2026-04-10. Should land in design.md batch revision.*

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

*Last updated: 2026-04-13 (M4 C8 predecessor work — populate_ruleset_eal
orphan discovery + D41 amendment). Add new items with date + origin
cycle at append time.*
