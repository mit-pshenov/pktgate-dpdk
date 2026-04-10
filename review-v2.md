# Review of design.v2.md

## Verdict

**APPROVE_WITH_FIXES.**

The writer applied all 24 batch-revision steps cleanly. Every
D1–D20 decision is visibly realized in code / pseudocode, not
just prose. M1 and M2 are respected in §1–§13. The previously
identified critical bugs (D9 UAF, D10 shared-atomic bucket,
D13 VLAN offset, D14 IHL, D15 L4 wildcard model, D16 REDIRECT
leak, D17 fragment policy) are fixed. However the review found
one new critical bug in the hot-path state machine (a missing
NEXT_L4 / SKIP_L4 terminal transition that leaves
`apply_action`'s `a` pointer uninitialized on L3 miss when L4
is skipped), one critical UB in the IPv6 ext-header mask
(`1ull << 135`), and a small set of medium / minor issues
worth resolving before implementation starts. None of them
require a new batch revision pass — a targeted touch-up of
§5.3 / §5.4 / §5.5 and §4.4 will close them.

## A. Decision application table

| Decision | Applied? | Section(s) in v2 | Notes |
|---|---|---|---|
| M1 | yes | §1.1, §8.4, §12.1 tail | Explicit "dev VM does not shape architecture" note; dev-vs-prod sizing table. |
| M2 | yes | §1–§13 vs §14 | Clean split. The few "§14 decides" dispatching mentions in §3a / §5.3 / §5.4 are M2-correct (arch describes the full model; §14 owns shipping). |
| D1 | yes | §4.4, §5.5 RL | Per-lcore TokenBucket[RTE_MAX_LCORE], lazy TSC refill, zero atomics, `rate / n_active_lcores` share. |
| D2 | yes | §13 | C++20 baseline, C++23 welcome, gcc ≥ 14 / clang ≥ 18, no hardcoded compiler. |
| D3 | yes | §4.3, §10.1–10.2 | Full counting/aggregation model + all four export channels described architecturally; channel shipping deferred to §14. |
| D4 | yes | §3a.1 (`hw_offload_hint`), §4.1 (`execution_tier`), §5.2 FDIR branch, §9.5, §14 | Rule tiering, dual-path, `rte_flow_create` at publish, SW fallback, SW tables authoritative. |
| D5 | yes | §3a.1 `interface_roles`, §6.1 `--standby`, §11.1 anti-patterns | Role abstraction, park mode, anti-patterns listed as architectural constraints. |
| D6 | yes | §3a.1 `sizing`, §4.1, §4.3, §8.4, §14.1 | Runtime-sized capacity arrays, dev/prod two columns, hard min 16/layer. |
| D7 | yes | §3a.1 mirror action, §5.5 MIRROR, §14.1/14.2, §15 | Full schema; Phase 1 compiler reject; cycle-budget validation as Phase 2 exit. |
| D8 | yes | §3a (new schema), §9, §17 | Clean new schema, no pktgate compat, scrubbed consistently. |
| D9 | yes | §4.2 (field removed), §4.5 `ControlPlaneState::g_active`, §5.1, §6.1, §6.4, §9.2 | Single process-wide atomic, acquire-load once per burst, initial publish during init, cleared after final synchronize. |
| D10 | yes | §4.4, §5.5 RL | Two-level mapping `rl_actions[rl_index] → rule_id → TokenBucket[RTE_MAX_LCORE]`; per-lcore `rte_lcore_id()` indexing; no CAS. (See issue D1 under "New issues" for the §4.4-vs-§5.5 pseudocode mismatch.) |
| D11 | yes | §9.2, §9.4 | Explicit six-step sequence: build → publish (exchange) → check/synchronize → diff → arena GC → destroy rs_old; rule_id-reassignment policy documented. |
| D12 | yes | §5.1 `thread_offline`/`_unregister`, §6.4, §9.2 (`rte_rcu_qsbr_check` + 500 ms) | Bounded reload, watchdog as backstop, explicit `reload_timeout` metric. |
| D13 | yes | §5.1 dynfield `l3_offset`, §5.2 set on parse, §5.3 / §5.4 consume | No `et == 0x8100 ? 18 : 14` ternary anywhere. QinQ at offset 22 noted as architectural. |
| D14 | partial/yes | §5.4 | IPv4 offset via `((ip->version_ihl & 0x0F) << 2)` — correct. IPv6 fixed 40 via `sizeof(rte_ipv6_hdr)` — correct. SKIP_L4 branch skips the computation entirely. OK. |
| D15 | yes | §4.1 L4 block, §5.4 | Three primary hashes in selectivity order (`l4_proto_dport` > `l4_proto_sport` > `l4_proto_only`) + `L4CompoundEntry` filter_mask. Mirrors the §5.2 L2 pattern. |
| D16 | yes | §4.2 `redirect_tx` / `mirror_tx`, §5.5 REDIRECT case, `redirect_drain` | Per-port staging, burst-end flush, `rte_pktmbuf_free_bulk` on unsent, `redirect_dropped_total` / `mirror_dropped_total` bump. |
| D17 | yes | §3a.1 `fragment_policy`, §5.3 IPv4 block, §14.1 | Default `l3_only`, alternatives `drop` / `allow`, semantics match P9 resolution (first fragment parsed normally, non-first sets SKIP_L4). |
| D18 | yes | §5.6 | min / typ / max table, realistic "L2-miss + L3 hit" example at ~201 cycles, honest "within budget, not substantial headroom" language. |
| D19 | yes | §5.1 (`handle_idle` spec), §5.3 (single `rte_fib_lookup`, src-prefix block completed), §5.5 TAG semantics (DSCP / PCP, no-op on untagged + counter), §5.1 triple-pass note | All sub-items addressed. |
| D20 / P8 | yes | §5.3 IPv6 block, §10.3 counter, §14.1 / §14.2 | First-protocol-only path, `SKIP_L4` on ext header, `l4_skipped_ipv6_extheader` bump, full chain walking described as a future capability in §14. (See issue C1 below — EXT_MASK has UB.) |

## B. M1 / M2 violations

grep of §1–§13 for `MVP`, `v2`, `v3`, `Phase`, "in the future",
"for now", "later", "future capability", "future improvement":

| Location | Context | Verdict |
|---|---|---|
| line 892 | `// Not IP — terminal pass (default is applied later in dispatch)` | OK — "later" is temporal within the same burst, not phase. |
| line 1433 | `// rs_old via a later deferred pass keyed by the next successful synchronize` | OK — runtime flow, not phase. |
| lines 240 / 841 / 904 / 981 | "phase plan in §14 decides which shipping phase" | OK — M2-correct dispatch to §14; arch describes full model. |
| line 1286 | "the dev VM's e1000 … degrades to single-queue" | OK — M1-compliant descriptive mention. |

**M1 violations**: none found.
**M2 violations**: none found.

## C. Critical bug regression status

- **D9** – **FIXED.** `ControlPlaneState::g_active` is the single
  atomic. §4.2 WorkerCtx explicitly lacks the `active` field.
  Hot path `atomic_load_explicit(&g_cp.g_active, acquire)` at
  §5.1 line 627. Init publishes via RELEASE (§6.1). Shutdown
  clears after final synchronize (§6.4).
- **D10** – **FIXED in §5.5, mismatched in §4.4.** The §5.5 case
  is per-lcore, zero-atomic, correct. The §4.4 illustrative
  snippet uses a phantom `.slot` field on `RlAction` that is
  not declared in the RlAction struct (lines 342–346). See new
  issue D1 below.
- **D11** – **FIXED.** §9.2 writer code and §9.4 corner-case
  list both state the six-step sequence (build → publish →
  check → diff → arena-free → destroy).
- **D12** – **FIXED.** §5.1 worker calls
  `rte_rcu_qsbr_thread_offline` and `_thread_unregister` on
  the exit path (lines 667–668); §6.4 describes the same.
  §9.2 uses `rte_rcu_qsbr_check` with a 500 ms bound.
- **D13** – **FIXED.** `l3_offset` byte lives in the §5.1
  dynfield schema, is set in §5.2 L2 parse, and read by §5.3 /
  §5.4 via `rte_pktmbuf_mtod_offset(m, void*, l3_off)`. No
  `0x8100 ? 18 : 14` anywhere in the file.
- **D14** – **FIXED.** `l4off = l3off + ((ip->version_ihl &
  0x0F) << 2);` for IPv4; `l4off = l3off +
  sizeof(rte_ipv6_hdr);` for IPv6.
- **D15** – **FIXED.** §4.1 declares
  `rte_hash* l4_proto_dport / _sport / _only` plus
  `L4CompoundEntry* l4_compound`; §5.4 probes the three
  primaries in selectivity order and validates the secondary
  `filter_mask`. Mirrors §5.2 L2 shape.
- **D16** – **FIXED.** §4.2 `redirect_tx[N_PORTS_MAX]` staging,
  §5.5 `stage_redirect`, §5.5 `redirect_drain` with
  `rte_pktmbuf_free_bulk` on unsent + counter bump. Mirror
  uses the same staging shape.
- **D17** – **FIXED.** Top-level `fragment_policy` with
  `"l3_only"` default, `drop`, `allow`. §5.3 IPv4 block
  honours `FRAG_DROP`, `FRAG_ALLOW`, and `FRAG_L3_ONLY`
  (sets SKIP_L4 only on non-first fragments, allowing L3 to
  run). Matches P9 resolution.
- **D18** – **FIXED.** §5.6 min/typ/max triple column, realistic
  L2-miss 95 cycles, typical-case example sums to ~201 (not a
  ~40-cycle best case), honest "within budget but not
  substantial headroom" wording.

## D. New issues

### C1 — CRITICAL: `apply_action` missing the "L3-miss + SKIP_L4" terminal path

§5.3 IPv4 block, on L3 miss with a non-first-fragment packet
(SKIP_L4 already set), executes:

```cpp
dyn->verdict_layer = (dyn->flags & SKIP_L4) ? NEXT_L4 : NEXT_L4;
```

(lines 827–828). Both ternary branches assign `NEXT_L4`. §5.1
then enters the L4 pass (line 651):

```cpp
if (mbuf_dyn(rx[i])->verdict_layer == NEXT_L4 &&
    !(mbuf_dyn(rx[i])->flags & SKIP_L4))
    classify_l4(rs, rx[i]);
```

Because SKIP_L4 is set, `classify_l4` is **not** called. The
packet keeps `verdict_layer = NEXT_L4` and enters
`apply_action` (§5.5 lines 985–1004). The `switch` there only
has cases for `TERMINAL_L2 / L3 / L4 / PASS / DROP`. `NEXT_L4`
falls off the end; control reaches the post-switch
`counter_inc(...)` call with `a` uninitialized → UB, and then
the second switch dereferences `a`. Crash, or worse, silent
mis-dispatch.

The same cliff exists for any path that terminates as
`NEXT_L4` without running `classify_l4`, and more subtly for
any `NEXT_L3` that is never followed up.

Fix sketch (pick one, any works):

1. In §5.3, when L3 misses and `SKIP_L4` is set, set
   `verdict_layer = TERMINAL_PASS` directly so §5.5's
   existing `TERMINAL_PASS` case applies the `default_action`.
2. Add an explicit `case NEXT_L3: case NEXT_L4:` in the §5.5
   switch that routes to `TERMINAL_PASS` semantics (apply
   `default_action`).
3. Add a `default:` arm to the switch that falls through to
   `TERMINAL_PASS`.

Any of these closes the hole. Option 1 is the cheapest and
matches the fragment-policy intent: non-first fragment + L3
miss → `default_action`.

Severity: **critical**. Fires on every non-first-fragment packet
whose prefix is not in the L3 ruleset — a category that
absolutely exists on a GGSN-Gi uplink.

### C2 — CRITICAL: `1ull << 135` is undefined behaviour in §5.3 IPv6 EXT_MASK

Lines 846–848:

```cpp
static const uint64_t EXT_MASK =
    (1ull<<0)|(1ull<<43)|(1ull<<44)|(1ull<<50)|(1ull<<51)|
    (1ull<<60)|(1ull<<135)|(1ull<<139)|(1ull<<140);
```

`1ull << 135` shifts a 64-bit integer by 135 bits. Per C++
[expr.shift] this is UB; in practice compilers reduce the
shift count modulo 64 (so `1ull << 135 == 1ull << 7`), which
silently flips bit 7 of the mask and incorrectly classifies
`next_header == 7` (unassigned) as an extension header.
`next_header` values 135 / 139 / 140 are caught by the
explicit `nxt == 135 || nxt == 139 || nxt == 140` clause
later, so functionally the ext detection still works for
those three, but the mask is nevertheless broken and is a
silent correctness landmine for future edits.

Fix: drop bits ≥ 64 from EXT_MASK entirely. Keep only the
`< 64` bits in the mask (0, 43, 44, 50, 51, 60) and the
explicit `nxt == 135 || 139 || 140 || 253 || 254` OR clause.

Severity: **critical** (silent wrong classification of an
unrelated protocol value; UB).

### M1 — MEDIUM: §4.4 `RlAction::slot` field is undeclared

The hot-path pseudocode in §4.4 (line 493) does:

```cpp
auto* row = &rl_arena->rows[rs->rl_actions[a->rl_index].slot];
```

but the `RlAction` struct at lines 342–346 has only

```cpp
struct RlAction {
    uint32_t rule_id;
    uint64_t rate_bytes_per_sec;
    uint64_t burst_bytes;
};
```

— no `slot` field. §5.5 uses a different shape
(`rl_arena_row(g_cp.rl_arena, rl.rule_id)`, implying a
rule_id → row lookup). Either:

- add `uint32_t slot;` to `RlAction` and have §5.5 also index
  by `.slot` (O(1) dense indexing, preferable — avoids a hash
  lookup on the hot path), or
- delete the `.slot` language from §4.4 and rely on
  `rl_arena_row(...)` as the canonical accessor everywhere,
  accepting that the §4.4 snippet is illustrative only.

Severity: **medium** (pseudocode inconsistency between §4.4
and §5.5; picks the wrong choice silently if implemented from
either snippet in isolation).

### M2 — MEDIUM: `id_to_slot` / slot recycling not specified

The `RateLimitArena::id_to_slot` hash and slot reuse policy on
reload is mentioned in §4.4 but not explained: when a rule is
removed and its row freed, does the slot become available for
a new rule? Which side of the `rl_arena_free_row` path drops
the `id_to_slot` entry? The writer flagged this as note N1.
Worth one paragraph in §4.4 or §9.4.

Severity: **medium** (implementation detail but load-bearing
for long-term reload stability).

### M3 — MEDIUM: `apply_action` has no `default:` and relies on exhaustive terminal cases

Tied to C1 but broader: the two `switch` statements in
`apply_action` do not have `default:` arms. The outer switch
only enumerates `TERMINAL_L2 / L3 / L4 / PASS / DROP`; the
inner switch only enumerates `ALLOW / DROP / REDIRECT /
MIRROR / TAG / RL`. C++ does not require default arms, and
the compiler won't warn by default. Any future new action
verb or verdict state that isn't added here at the same time
silently falls through. Suggest adding
`default: __builtin_unreachable();` or a defensive
`rte_pktmbuf_free(m); return;` in both, plus a compiler
`-Wswitch-enum` in the CMake build flags.

Severity: **medium**.

### m1 — MINOR: §3a example `interface_roles` uses `pci` selector only

The writer's own note N5 already flags this: the example has
`{"pci": "…"}` but dev-VM vdevs (`net_pcap`, `net_null`) need
`{"vdev": "…"}` or `{"name": "…"}`. The architecture should
explicitly state that `interface_roles` selectors are a sum
type (pci | vdev | name). Matters for the test matrix in §12
which runs on `net_pcap`.

Severity: **minor**.

### m2 — MINOR: `tag_pcp_noop_untagged_total` counter is named in §5.5 but not listed in §10.3

§5.5 line 1044 names a metric `tag_pcp_noop_untagged_total`
but it does not appear in §10.3's metric name list or in
§4.3's `LcoreStats` enumeration. Add to both, or drop the
name from §5.5.

Severity: **minor**.

### m3 — MINOR: dead ternary `(flag) ? NEXT_L4 : NEXT_L4`

§5.3 line 828 is a dead ternary. Cosmetic on its own, but
misleading — it suggests the writer meant to branch one side
to something else (probably `TERMINAL_PASS`, which is the
correct fix under C1). Resolve together with C1.

Severity: **minor** (but couples to C1).

### m4 — MINOR: `N_PORTS_MAX` used without declaration

`WorkerCtx::redirect_tx[N_PORTS_MAX]` and `mirror_tx[N_PORTS_MAX]`
reference a constant `N_PORTS_MAX` that isn't defined anywhere
in the document. Mention in §8.4 sizing table or in a
"constants" sub-section. A design-doc-level nit, not a
correctness issue.

Severity: **minor**.

### m5 — MINOR: §10.1 snapshot ring "N=4" is ungrounded

Writer's own note N4. `N = 4` generations is picked without
justification; `N = 2` would be enough for a single
writer/single reader. A passing sentence of rationale is
enough.

Severity: **minor**.

### m6 — MINOR: `counter_inc` / `counter_drop` / `counter_rl_drop` helpers are referenced but never defined

§5.5 uses these helpers and §4.3 describes the underlying
storage (`RuleCounter counters[n_lcores][n_rules_total]`) but
the mapping from `(layer, rule_id)` to the counter row index
isn't spelled out. A sentence saying "counters are indexed
by a layer-flat rule_id slot assigned at compile time" would
close the gap.

Severity: **minor**.

## E. Cross-section consistency issues

1. **Module list vs project structure** — §3 module list has
   `gen_manager`; §13 project layout places it under `src/gen/`.
   Consistent.
2. **§10 metrics vs §4 counters** — mostly aligned. Gaps:
   `tag_pcp_noop_untagged_total` (see m2) and the absence of
   explicit "how the counter index is computed" wording (see
   m6). Not blocking.
3. **§11 failure modes vs §6 lifecycle** — the failure table
   references states the lifecycle defines. `Reload timeout`
   ↔ §9.2 `rcu_check` path ↔ §11 row. Consistent.
4. **Schema fields in §3a vs §4 data structures vs §9 compiler** —
   `fragment_policy`, `interface_roles`, `sizing`,
   `hw_offload_hint`, per-rule `id` all consistent.
5. **Name consistency** — `rl_index`, `rule_id`,
   `RateLimitArena`, `g_active`, `l3_offset`, `fragment_policy`
   are used with identical names across sections. The sole
   exception is the undeclared `.slot` field on `RlAction`
   (see M1).
6. **`rule_id_set` (§4.1) vs `rule_ids` (§9.2 prose)** —
   trivial; same concept, prose naming diverges. Non-issue.

## F. P8 / P9 resolution compliance

| Resolution | Required behaviour | v2 compliance |
|---|---|---|
| **P9 / D17** | `fragment_policy: "l3_only" \| "drop" \| "allow"`, default `"l3_only"`; non-first fragment skips L4, L3 rules still run, L3 miss → `default_behavior`. | **PASS** for the three values and default at §3a.1 / §3a.2. **PASS** for the `FRAG_DROP` and `FRAG_ALLOW` branches at §5.3. **PARTIAL** for `FRAG_L3_ONLY`: the semantics on first fragment are correct (L4 still runs), but the L3-miss + SKIP_L4 fall-through to `default_behavior` is broken by the C1 bug. A one-line fix per C1 closes it. |
| **P8 / D20** | First-protocol-only in MVP; if `next_header` is an ext header, skip L4, bump `l4_skipped_ipv6_extheader`, L3 rules still apply. Full chain walking allowed to be described as future. | **PASS** on the structural side (ext detection, counter bump, SKIP_L4, first-protocol-only for the common case, full walk described in §14). **FAIL** on the mask (C2 UB). Same fall-through cliff as P9 / C1 when L3 misses on an ext-header IPv6 packet. Fix C2 in the mask, and the C1 fix covers the fall-through. |

## Recommended next action

Tell the user:

1. **Approve the overall v2 direction.** All 24 batch-revision
   steps are applied; every D1–D20 is visible in code, not
   just prose; M1 and M2 are clean across §1–§13; the three
   previously-unblocked correctness bugs (D9, D13, D14/D15)
   are fixed.

2. **Request a small in-place touch-up pass** before
   implementation starts, covering:
   - **C1** — fix the NEXT_L4 + SKIP_L4 cliff in §5.3 / §5.5.
     Simplest patch: in §5.3 IPv4 L3-miss block, set
     `verdict_layer = TERMINAL_PASS` when SKIP_L4 is set;
     apply the same pattern in §5.3 IPv6 block where it sets
     `verdict_layer = NEXT_L4` after SKIP_L4 was raised.
     Belt-and-braces: add `default: fall-through-to-PASS` arm
     to the `apply_action` outer switch.
   - **C2** — drop the bits ≥ 64 from the IPv6 EXT_MASK
     constant. Keep only `0, 43, 44, 50, 51, 60` in the mask;
     the explicit `|| nxt == 135 || 139 || 140 || 253 || 254`
     clause already covers the rest.
   - **M1** — decide whether `.slot` lives on `RlAction`
     (cleanest) and make §4.4 and §5.5 use the same accessor
     shape.
   - **M2** — one paragraph in §4.4 or §9.4 explaining
     `id_to_slot` lifetime and slot reuse on row free.
   - **M3** — add `default:` arms (or `-Wswitch-enum`) to the
     two `apply_action` switches.
   - **m1..m6** — sweep the minor items in the same pass;
     each is a single-line touch.

3. **Do not re-run the full writer → reviewer cycle** for
   these fixes. They are localized to §4.4, §5.3, §5.5, §10.3
   and can be applied in-place; a quick re-read of the
   touched sections is sufficient.

4. After the touch-up, mark D9–D20 as fully discharged in
   `review-notes.md` and move to the implementation-planning
   phase (what to build in Phase 1 week 1, CMake skeleton,
   gtest bootstrap).
