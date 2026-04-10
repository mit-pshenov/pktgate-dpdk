# pktgate-dpdk design review — notes

> Running log of the design review. Each entry: the point, its context,
> the agreed disposition, and the sections of `design.md` that will be
> revised when the review is complete.
>
> Entries are recorded as they come up; revision is applied in **one
> batch pass** at the end of review, not incrementally, so that the
> reviewer's context stays fresh across multiple decisions.

---

## Meta principles (apply globally to review)

### M1 — Dev VM must not shape architecture

The dev environment is a VirtualBox VM (Fedora 43, 4 vCPU, 5.6 GB RAM,
2× Intel 82545EM e1000 NICs on `uio_pci_generic`). **It is a correctness
and smoke-test sandbox only.** Its limitations **must not constrain
architectural decisions**.

- Production target is server-class hardware with 40 Gbps NICs
  (Intel E810/XL710 or Mellanox ConnectX-5/6 class).
- Design choices are made for the production case.
- The dev VM is expected to run whatever subset of the design works
  there, degrading gracefully to single-queue / single-lcore /
  no-offload paths as needed.
- **Any critique of the form "this won't work on our e1000" is
  invalid** unless it also breaks on the production hardware.
- Example application: symmetric Toeplitz RSS **stays** (design §7 or
  wherever RSS is configured), even though e1000 has no RSS at all.
  Dev VM runs single-queue and we accept that.

**Action on design.md**: add one-paragraph note in §1 (context) or §12
(test strategy) stating this principle explicitly.

### M2 — Architecture describes the target system; plan decides what ships when

They live in separate sections. Architectural sections must not contain
"MVP uses X, v2 uses Y" phrasing — that is plan material, belongs in
§14 (phase plan).

Architecture describes the full target system: every supported
mechanism, every extension point, every implementation strategy that
is valid for the design. The phase plan chooses which subset ships
first, which is deferred, and what the exit criteria for each phase
are.

The current `design.md` blends them throughout (rate-limit is "MVP:
shared, v2: ...", mirror is "MVP: deep-copy, v2: refcount", etc.).
Batch revision will clean this up:

- Architecture sections describe the full model
- `§14 Phase plan` gets all the "when" decisions
- Readers of the arch sections see a timeless spec; readers of §14 see
  the shipping schedule

**Action on design.md**: structural pass across all sections. Move all
phase-coupling out of §3–§13 into §14. Every statement of the form
"for MVP we use X" in an arch section becomes a plain description of X
in the arch section, plus an entry in §14 that says "MVP ships X".

---

## Decision log

### D1 — Rate-limit: per-lcore token bucket (MVP Variant A, Variant B as future improvement)

**Context.** Design §6 (data structures) proposed a home-grown
atomic-CAS token bucket, **shared across all lcores**, one per rule.
Architect's justification: `rte_meter` is color-aware/srTCM-shaped
(wrong fit), and RSS pins flows to lcores so contention is "naturally
low". The shared bucket gives an exact aggregate rate.

**Rejection.** "Contention naturally low" is wrong for rate-limit
rules specifically. RSS pins **flows** (5-tuple), but a single
rate-limit rule typically matches **many flows** at once (e.g. "all
TCP/443 from `10.0.0.0/8`", "all ICMP from suspicious source"). Those
flows are distributed by RSS across all lcores, and all lcores then
hammer the same shared cache line with CAS. Canonical worst case for
shared atomic RMW.

Back-of-envelope at 40 Gbps / 64 B worst case:

- ~7.5 Mpps per lcore at 8 lcores
- per-packet budget ~133 ns ≈ 400 cycles total
- contended CAS on a hot cache line: 100-300 cycles
- popular rule at 50 % traffic → ~30 M CAS/sec on one cache line,
  sequentializes and saturates interconnect

The architect's `design.md` §17 claim that pktgate's `PERCPU_HASH`
token bucket is a "BPF verifier workaround" is **factually wrong**.
Per-CPU / per-lcore thread-local state on pps-sensitive fast paths is
**universal best practice**: DPDK, VPP, nftables, XDP, kernel netdev —
all do it, independent of platform.

Customer priority: **throughput > accuracy**. Rate-limit here is flood
protection, not billing. 10-20 % error on aggregate rate is harmless;
packet loss from contention is not.

**Architecture (the full model, M2-clean)**:

```cpp
struct alignas(64) TokenBucket {
    uint64_t tokens;           // current tokens in bytes
    uint64_t last_refill_tsc;  // rte_rdtsc of last refill
    uint64_t dropped;          // per-lcore drop counter
    // padding to full 64 B cache line
};

struct RuleRateLimit {
    uint64_t rate_bytes_per_sec;   // configured aggregate rate
    uint64_t burst_bytes;          // burst tolerance (e.g. rate * 10 ms)
    TokenBucket bucket[RTE_MAX_LCORE];  // per-lcore state, cache-line isolated
};

// hot path:
auto& b = rule.rate.bucket[rte_lcore_id()];
uint64_t now = rte_rdtsc();
uint64_t elapsed_cycles = now - b.last_refill_tsc;
uint64_t new_tokens = elapsed_cycles * rule.rate.rate_bytes_per_sec
                     / rte_get_tsc_hz() / n_active_lcores;
b.tokens = min(b.tokens + new_tokens, rule.rate.burst_bytes);
b.last_refill_tsc = now;
if (b.tokens < pkt_len) {
    b.dropped++;
    return DROP;
}
b.tokens -= pkt_len;
```

Per-lcore bucket, cache-line isolated. Lazy refill via `rte_rdtsc`
delta. Zero atomics on hot path.

**Variant A (MVP implementation strategy)**: split rate equally across
all lcores at publish time — each bucket gets `rate / n_active_lcores`.
Accepts ~10-20 % aggregate rate error under skewed RSS distribution.
Simplest, ~60 LoC.

**Variant B (future improvement, documented in phase plan)**: control
thread samples per-lcore utilization every ~100 ms and redistributes
quota from under-utilized to over-utilized lcores. Error drops to
1-2 %. Uses existing RCU mechanism for control-thread writes — no new
synchronization primitive. Hot path unchanged.

**Sections to revise in design.md** (M2-split applied):

| Section | Change |
|---|---|
| §6 (data structures) | Full `TokenBucket` / `RuleRateLimit` description as architecture (not "MVP version") |
| §8 (hot path cycle budget) | Rate-limit check ~5-10 cycles (local load + sub + cmp + store) |
| §14 (phase plan) | MVP ships Variant A; v2 adds Variant B adaptive rebalancer |
| §15 (risks) | Remove rate-limit contention risk entirely |
| §17 (transformation table) | Flip `PERCPU_HASH` row from "BPF artifact, replaced" to "**KEPT as universal fast-path pattern**, per-lcore instead of per-CPU" |

---

### D2 — Language: C++20 baseline, newer welcome; compiler at implementer discretion

**Architecture**:

- **C++20 minimum baseline**. No falling below.
- **C++23 is welcome** where it brings real value: `std::expected`,
  `std::flat_map`, `std::print`, deducing `this`.
- **C++26** not a target but not forbidden if compelling.
- **Compiler**: gcc ≥ 14 or clang ≥ 18. Dev box has gcc 15.2 and
  clang 21.1 — either works. CMake must not hardcode.

**Sections to revise**: §13 (build) — clarify.

---

### D3 — Telemetry: counting model and export channels are architecture; shipping subset is plan

**Context** (P1 resolution).

User directive: "закладываем в архитектуру способ подсчёта/хранения,
необходимые варианты предоставления. В каких этапах реализовывать —
запланируем, когда дойдёт до плана."

**Architecture (full model, M2-clean)**:

**Counting model**:
- `RuleCounter` struct: 64-byte cache-line aligned
  - `matched_packets`, `matched_bytes`, `drops`, `rate_limit_drops`
- Storage: `RuleCounter counters[n_lcores][n_rules_total]` — per-lcore
  array of per-rule counters
- **Zero atomics on hot path**: each lcore writes only to its own row
- `n_rules_total` = sum of rules across all layers (L2+L3+L4)
- Per-port counters: `rte_eth_stats` is authoritative; we wrap and
  re-publish under our label schema
- Per-lcore counters: `LcoreStats` (cycles per burst, packets
  processed, queue depth samples)

**Aggregation model**:
- Dedicated telemetry thread (control-plane, not pinned to dataplane
  lcore)
- Periodic snapshot: `for lcore in 0..N: for rule in 0..M: snapshot
  += counters[lcore][rule]`
- Snapshot published to a lock-free ring buffer with N generations,
  all exporters read most recent
- Snapshot interval configurable, default 1 s

**Supported export channels (all defined by architecture)**:

1. **Prometheus HTTP exporter**
   - `/metrics` endpoint, OpenMetrics format
   - Metrics: per-rule, per-port, per-lcore, process-level
   - Labels: `rule_id`, `layer`, `port`, `lcore`, `site`
   - Own thread, configurable port
2. **sFlow UDP exporter**
   - Embedded encoder (not sidecar)
   - Sampled packet headers with ingress port, timestamp, matched
     rule ID
   - Configurable sample rate, collector address
3. **Structured JSON logs**
   - stderr (captured by journald) or syslog target
   - Levels: error, warn, info, debug
   - Rule-match events allowed at low sample rates; **no per-packet
     logging on hot path ever**
4. **rte_telemetry UDS**
   - Standard DPDK idiom, works with `dpdk-telemetry.py`
   - Exposes counter snapshots, rule list, lcore stats, reload status
   - Read-only; no mutating commands

All four channels pull from the **same snapshot buffer** — exporters
do not have separate data pipelines. This keeps the cost of having
multiple channels small (one extra thread per exporter, shared data).

**Phase question (deferred to plan discussion)**: which subset of the
four channels ships in MVP.

**Sections to revise**:

| Section | Change |
|---|---|
| §10 (telemetry surface) | Describe full counting + aggregation model, list all four channels as architecture; remove MVP-scope decisions |
| §14 (phase plan) | Decide which channels are in MVP (deferred — open question until plan discussion) |

---

### D4 — Hardware offload via rte_flow: architectural hook, MVP does not use it

**Context** (P2 resolution).

User directive: "нужны детали". Detailed analysis in review prose;
architectural requirements extracted below.

**What rte_flow offload can do on our target NICs (E810/XL710,
ConnectX-5/6)**:

- Exact-match drop/pass on L2/L3/L4 fields (huge win for DDoS rules)
- Queue steering by tuple (pre-classifier)
- Hardware counters (per-rule, async-readable)
- Mark action (NIC writes tag to mbuf metadata)
- Limited LPM (thousands of prefixes, not tens of thousands)

**What it cannot do**:

- Our full LPM (16 K IPv4 + 16 K IPv6 won't fit in NIC tables)
- First-match-wins semantics across software ruleset (NIC evaluates
  parallel)
- Fast hot reload on large rulesets (ms–s to reprogram)
- Compound L2 with all match fields together

**Critical correctness issue — first-match-wins across hw/sw boundary**:

If rule 10 (hw-offloaded) matches but rule 5 (sw-only) should have
matched first, the hw-offloaded rule wins → wrong behavior.

**Architectural requirements (always true, regardless of when MVP
ships them)**:

1. **Rule tiering**: compiler tags each rule
   `execution_tier: hardware | software`. Default software. Optimizer
   (if present) promotes safe rules to hardware.
2. **Dual-path dataplane**: hot path recognizes when NIC has already
   classified a packet (`mbuf->ol_flags & PKT_RX_FDIR` + mark value
   in metadata) and skips re-classification. Single branch at top of
   classify().
3. **`rte_flow_create` calls at ruleset publish time**, not on hot
   path. Part of the compile-and-publish pipeline after RCU swap.
4. **Graceful fallback**: if `rte_flow_create` returns
   ENOTSUP/ENOMEM, compiler moves rule back to software tier and
   logs warning. Never fail publish because of offload failure.
5. **Software tables always hold all rules**. Offload is an
   optimization, not the source of truth. Supports: NIC rule flush,
   restart, partial offload, operator-disabled offload.
6. **Promotion strategy**: operator opt-in via per-rule
   `hw_offload_hint: bool` in MVP schema. Automatic topological
   analysis is a v2/v3 improvement.

**Phase question (deferred)**: MVP ships with offload disabled
entirely (no `rte_flow_create` calls, all rules software tier). v2+
implements operator-hint-driven offload on E810. v3 considers
automatic promotion.

**Sections to revise**:

| Section | Change |
|---|---|
| §3 (config format) | Add `hw_offload_hint` field (optional) to rule schema |
| §6 (data structures) | Add `execution_tier` to compiled rule representation |
| §5 (hot path) | Add single-branch check for `PKT_RX_FDIR` at top of classify, architecture only — MVP may or may not actually set the mark |
| §9 (compilation pipeline) | Add tiering step: classify rules, program rte_flow for hw-tier at publish |
| §14 (phase plan) | Offload deferred from MVP |

---

### D5 — HA / hot-standby: architectural compatibility requirements (v2+ implementation)

**Context** (P3 resolution).

User directive: "HA дизайн должен не противоречить дизайну основной
функциональности и быть возможным, как минимум."

HA is not MVP, but architecture must not foreclose it.

**Good news — our design is already HA-friendly**:

- Hot path is stateless per packet (no conntrack, no flow table)
- Rate-limit buckets are approximate; losing them on failover is
  acceptable (warm up in seconds)
- No shared global state requiring replication

**Architectural requirements to keep HA open**:

1. **Deterministic rule evaluation**: `config → ruleset` is a pure
   function (no randomness, no wall-clock, no host ID). Two instances
   with the same config must produce identical verdicts. First-match-
   wins gives us deterministic iteration. Rate-limit per-lcore state
   may diverge between instances, which is fine.
2. **Interface role abstraction**: rules reference interfaces by
   **logical role** (`upstream_port`, `downstream_port`), not by PCI
   BDF or kernel name. Role-to-DPDK-port-ID mapping lives in a
   separate per-host config section or CLI flag. Two hosts with
   different BDFs run the same rule file.
3. **Warm standby mode**: process can load config, compile ruleset,
   and park without forwarding traffic. Activation via external
   signal (UDS command, config flag, signal). Simple: a `--standby`
   CLI mode that initializes but keeps RX queues drained (or does
   not start burst loop).
4. **Liveness / readiness exposure**: already covered by watchdog
   heartbeat (§7) and Prometheus/rte_telemetry (D3). External
   failover supervisor reads these.

**Anti-patterns architecture must NOT contain**:

- Host ID baked into rule semantics
- Wall-clock in rule matching (rdtsc deltas OK — relative)
- Global state outside the process (e.g. shared `/var/run/pktgate.state`)
- Non-deterministic hot reload (order of processing concurrent
  reloads must be stable)
- Direct PCI BDF in rule file

**What is out of scope (external to this process, handled by
operator/infra)**:

- Failover triggering (VRRP, HW relay, upstream reconvergence)
- Traffic steering between active/standby
- Split-brain detection

**Sections to revise**:

| Section | Change |
|---|---|
| §3 (config format) | Add interface role abstraction (top-level `interface_roles` or embedded per-rule); rules reference roles, not port names |
| §6 (data structures) | Role-to-port mapping in boot-time config |
| §7 (lifecycle) | Add `--standby` mode description |
| §11 (failure modes) | Mark HA integration as v2+, list anti-patterns as architectural constraints |
| §14 (phase plan) | HA: warm-standby support in v2, full active/standby pair in v3 |

---

### D6 — Rule count ceilings: parameterized at startup, no compile-time constants

**Context** (P5 resolution).

User directive: "для разработки можно уменьшить количество правил".

Interpretation: rule count must not block dev, and by extension
(M1 principle) dev constraints must not shape architecture numbers.

**Architectural requirement**: **no hard compile-time ceilings**. All
capacity parameters are runtime parameters, sized at startup from a
sizing config file or CLI:

| Parameter | Dev default | Production target |
|---|---|---|
| Rules per layer (max) | 256 | 4 096 |
| MAC entries (max) | 256 | 4 096 |
| IPv4 prefixes (max) | 1 024 | 16 384 |
| IPv6 prefixes (max) | 1 024 | 16 384 |
| L4 entries (post-expansion, max) | 256 | 4 096 |
| VRF entries (max) | 32 | 256 |
| Rate-limit rules (max) | 256 | 4 096 |
| EtherType entries (max) | 32 | 64 |
| VLAN entries (max) | 256 | 4 096 |
| PCP entries (max) | 8 | 8 |

Production targets inherited from pktgate (M1: justified by
production needs, not dev constraints). Dev defaults are chosen to
keep hugepage usage < 256 MiB and cold start < 1 s.

Hard minimum (compile rejects smaller): 16 per layer (to keep tests
meaningful).

**Sections to revise**:

| Section | Change |
|---|---|
| §3 (config format) | Sizing config spec; CLI flag `--sizing-config <file>` |
| §6 (data structures) | Show parameterization: all arrays sized at init from sizing config, allocated from mempool |
| §8 (resource sizing) | Add the above parameter table; show how hugepage requirement scales |
| §9 (compilation pipeline) | Compiler validates config fits within sized pools; clear error if overflow |

---

### D7 — Mirror action: full semantics in architecture, deferred to a later phase

**Context** (P6 resolution).

User directive: "Зеркалирование можно оставить на доработку."

Mirror is not MVP, but (M2 principle) architecture describes it fully.

**Architecture (full model)**:

- `mirror` action with `target_port` parameter (and optionally a
  sampling rate, deferred to implementation)
- Two implementation strategies, both valid for the architecture:
  - **Deep copy**: `rte_pktmbuf_copy` → TX on mirror port. One
    mempool alloc + memcpy per mirrored packet. Universally safe.
  - **Refcount zero-copy**: `rte_mbuf_refcnt_update` + direct TX on
    mirror port. Requires NIC driver support for shared mbufs.
- Both strategies are listed in architecture (M2); the phase plan
  picks which ships when.

**MVP behavior for unimplemented mirror**:

- Rule compiler **accepts** `action: mirror` syntactically
- Compiler **rejects at publish time** with clear error: "mirror
  action not implemented in this build"
- (Alternative considered and rejected: accept-and-stub — would
  silently drop visibility, operator may not notice)

**Risk register update**:

- §15 #2 (mirror cycle budget under heavy load) is not an active risk
  in MVP. It is a **precondition for the mirror implementation
  phase**: before mirror ships, cycle budget must be validated with
  lab tests. Move to §14 phase plan as a phase exit criterion, not a
  current risk.

**Sections to revise**:

| Section | Change |
|---|---|
| §3 (config format) | Mirror action stays in schema; describe fully |
| §5 (hot path) | Mirror action dispatch described architecturally (with both impl strategies) |
| §14 (phase plan) | Mirror + refcount optimization as separate phase with lab-test exit criterion |
| §15 (risks) | Remove risk #2 (mirror cycle budget); note it in phase plan as exit criterion |

---

### D8 — JSON schema: clean, no pktgate compatibility

**Context** (P4 resolution).

User directive: "давай не привязываться к pktgate на втором проходе
дизайна."

Option B from the P4 analysis: drop schema compat entirely. Simpler
than the hybrid C option — no compat translator to build, no dual
format to validate, no two CONFIG.md files to maintain.

**Architecture**:

- Config schema is designed fresh on the second design pass, serving
  `pktgate-dpdk`'s own requirements.
- No obligation to accept `pktgate` JSON configs.
- No obligation to use the same field names, rule structure, or object
  model as pktgate.
- Scenarios in `/home/user/filter/scenarios/` become **inspiration for
  test cases**, not schema reference. If we want to reuse a scenario,
  we re-express it in the new schema.
- `pktgate` `CONFIG.md` becomes **lessons reference only** (semantic
  choices worth preserving: first-match-wins, port group expansion,
  compound L2 with filter_mask, drop IPv4 non-first frags, etc.), not
  a schema source.

**What this unlocks (accumulated across decisions)**:

- `hw_offload_hint: bool` per-rule field (D4)
- Top-level `interface_roles` section, rules reference roles not port
  names (D5)
- Sizing config section or separate sizing file (D6)
- Cleaner rate-limit spec (explicit `burst_ms` or similar) (D1)
- Rule metadata fields where useful (`comment`, `owner`, `source`)
- Clean top-level `version` field for D11-style strict version match
- Free choice of `objects` / groups model; may diverge from pktgate's

**What we keep** (semantic decisions from pktgate that are still
right):

- First-match-wins per layer, no priority field
- Port group and object expansion at compile time
- Compound L2 rules with selectivity-ranked primary + filter_mask
  bitmap
- IPv4 non-first fragments and IPv6 fragment headers dropped at L3
- Dual-stack IPv4 + IPv6 from day one
- `default_behavior` at pipeline tail
- Layered L2 → L3 → L4 pipeline with per-layer first-match

These are **semantic** lessons, not schema lessons. The new schema may
encode them differently.

**Impact on input.md**: several sections become wrong and need update
at batch-revision time:

- §1.2 "What we DO reuse — as knowledge, not code": drop "JSON config
  schema" from the list; keep only "architectural lessons" and
  "scenarios and test cases (as inspiration)"
- §3.1 F3 "Config format": drop "schema-compatible with existing
  pktgate schema" language
- §3.3 "Constraints already agreed": drop "schema compatible with
  pktgate"
- §6.1 references: still valid but reframe as "lessons and scenarios,
  not schema"

**Impact on design.md batch revision**:

- §3 (config format) — full rewrite with clean schema design
- §9 (compilation pipeline) — parser/validator target the new schema
- §17 (transformation table) — pktgate→DPDK rows that referenced
  schema compatibility are re-scoped to semantic inheritance only
- All sections that mentioned "pktgate-compatible" or similar must be
  scrubbed

**Sections to revise**:

| Section | Change |
|---|---|
| §3 (config format) | Clean redesign of the schema, informed by D3–D7 needs |
| §9 (compilation pipeline) | Parser/validator for the new schema; no compat layer |
| §17 (transformation table) | Strip schema-compat rows; keep semantic-inheritance rows |
| All | Scrub every mention of "pktgate-compatible" or "schema from pktgate" |

**Input.md update at batch-revision time**: minor surgery as listed
above — roughly 5-10 lines changed across §1.2, §3.1 F3, §3.3, §6.1.

---

## Pending items

### P7 — rte_flow offload promotion strategy

Sub-question of D4. MVP uses operator-hint `hw_offload_hint`. Should
automatic topological analysis come in v2 or v3? Architectural hook
(rule tiering + dual-path dataplane) is the same either way; the
difference is compiler complexity. Defer to plan discussion.

---

## Batch revision plan

When the review pass completes, apply all decisions in one pass:

1. **Structural pass**: apply M2 principle across all sections. Move
   every "MVP uses X, v2 uses Y" statement out of arch sections into
   §14.
2. **M1 principle**: add note in §1 or §12.
3. **D1**: rewrite rate-limit in §6, §8, §14, §15, §17.
4. **D2**: C++ version note in §13.
5. **D3**: rewrite telemetry in §10; defer channel selection to §14.
6. **D4**: add offload hooks to §3, §5, §6, §9; defer to §14.
7. **D5**: add HA-compat requirements to §3, §6, §7, §11, §14.
8. **D6**: rewrite sizing in §3, §6, §8, §9.
9. **D7**: mirror full description in §3, §5; defer impl to §14;
   remove risk from §15.
10. **D8**: full rewrite of §3 (clean schema), §9 (clean compiler);
    scrub schema-compat mentions everywhere; update input.md
    (§1.2, §3.1 F3, §3.3, §6.1) at the same time.
11. Full-document consistency pass after edits.
12. Diff summary for final review.

**Revision executor**: TBD. Options: (a) self-edit in place,
(b) delegate back to architect agent with review-notes as input,
(c) hybrid — I do D1-D2 inline, architect redoes the structural pass
for M2.

---

## Review pass — §9 hot reload mechanics / RCU correctness

Reviewed: §4.1 Ruleset, §4.2 WorkerCtx, §4.4 RateLimitArena,
§5.1 pseudocode, §5.5 action dispatch (RL), §6.4/§6.5 shutdown,
§8.4 RCU memory, §9 hot reload.

### D9 — CRITICAL: inconsistent `active` pointer location (use-after-free)

The design has three conflicting statements about where the
`atomic<Ruleset*> active` lives:

- **§4.2 WorkerCtx** (line 179):
  `const Ruleset* _Atomic active;` — field *inside* per-lcore ctx.
- **§5.1 reader** (line 297):
  `atomic_load_explicit(&ctx->active, ...)` — reads the per-lcore slot.
- **§9.2 writer** (line 692):
  `atomic_exchange_explicit(&active, rs_new.release(), ...)` —
  writes a single unqualified `active` (i.e. a global variable).

These cannot both be true. As written, the writer updates exactly
one global, while each worker only looks at its own `ctx->active`.
After `rcu_synchronize` + `ruleset_destroy(rs_old)`, **every
worker that still has `rs_old` in its own `ctx->active` slot will
dereference freed memory on the next burst**. This is a textbook
use-after-free — exactly the class of bug RCU is supposed to
prevent.

**Resolution**: consolidate on a **single global**
`alignas(64) _Atomic(const Ruleset*) g_active;` kept in a process-
wide control-plane struct. Remove the `active` field from
`WorkerCtx` entirely. Hot path loads the global once per burst
with `memory_order_acquire` into a local `const Ruleset* rs`
(which goes out of scope at burst end — natural reference release).

Why single global, not per-lcore slots with writer broadcast:
- Broadcast needs N exchanges + N synchronizes *or* a fence
  sequence that's trivially wrong to code.
- The global pointer is cold-read once per burst (every ~5 µs at
  line rate); it lives in one cache line, shared-read, never
  bounced — zero contention.
- Matches the textbook QSBR pattern in `rte_rcu_qsbr` docs.

Touch points for revision: §4.2 (delete field), §5.1 (load from
global), §9.2 (already correct after field removal), §6.1 init
sequence (allocate + publish initial ruleset before any worker
launches), §6.4 shutdown (clear global *after* final
synchronize, free last ruleset).

### D10 — CRITICAL: §4.4 still has the rejected shared-atomic bucket

§4.4 `TokenBucket` uses `_Atomic uint64_t tokens` + `_Atomic
uint64_t last_tsc` and describes "Update is a CAS loop" — this is
the exact design D1 rejected. §5.5 `rl_consume` consumes from
`rs->rl_arena->bucket[a->rl_index]`, i.e. one shared bucket per
rule.

This must be rewritten per D1: per-lcore buckets in a
`TokenBucket[RTE_MAX_LCORE]` array, no atomics, lazy refill via
`rte_rdtsc`, `rate/n_active_lcores` share per core.

**Interaction with arena-survives-reload (good property from §4.4
we want to keep)**: the arena lives outside the Ruleset so
surviving rules keep their bucket state across reloads. With
per-lcore buckets, the *array* of buckets per rule lives in the
arena; the ruleset-local `rl_index` is just a ruleset-scoped
handle. Two-level mapping:

```
Ruleset::rl_actions[rl_index] -> { rule_id, rate, burst }
RateLimitArena: rule_id -> TokenBucket[RTE_MAX_LCORE]
```

Hot path (§5.5 rewrite):
```cpp
case RL: {
    auto* row = rl_arena_lookup(rs->rl_arena, a->rule_id);
    auto& b = row->bucket[rte_lcore_id()];
    // lazy refill + consume, zero atomics
    ...
}
```

The per-rule lookup in the arena must itself be O(1) — use a
direct array indexed by `rule_id` (stable across reloads,
bounded by `max_rules`). The arena is large but cold: ~64 B ×
RTE_MAX_LCORE × max_rules ≈ 64 B × 128 × 4096 = **32 MiB**
per rule class worst case. Budget check against the D6
production sizing: acceptable. Dev VM only sees 256 rules × 4
lcores = trivial.

Touch points: §4.1 rl_arena pointer semantics (rule_id-keyed),
§4.4 full rewrite, §5.5 hot path rewrite, §9.4 bullet about
bucket survival (still correct — just change "CAS" to "per-lcore
array").

### D11 — MEDIUM: rl_arena GC ordering on reload must be spelled out

§9.4 says "If rule N is removed, its bucket is released by the
arena GC pass, also under RCU." But the sequence isn't explicit:

1. Writer builds `rs_new`, which references rule_ids that are a
   subset/superset of `rs_old`.
2. Atomic exchange publishes `rs_new`.
3. `rcu_synchronize` — no more readers of rs_old.
4. Compute diff `removed = rs_old.rule_ids \ rs_new.rule_ids`.
5. Free arena rows for `removed` rule_ids.
6. Destroy `rs_old`.

Steps 4–5 must happen **after** step 3 and **before** step 6 (we
need rs_old to know the old rule_id set). No second synchronize
needed — the new ruleset never references the removed rule_ids,
so no reader could touch them after step 2.

Also: what if a rule_id is *reassigned* to a different rule in
the new ruleset? Per D8 (clean schema) rule_ids are operator-
assigned stable identifiers; if the same id denotes a different
rule semantically, bucket reset is the operator's intent. Policy:
**arena keys off rule_id verbatim; operators renaming a rule
should pick a new id if they want a clean bucket.** Document in
§9.4 and CONFIG.md.

### D12 — MINOR: misc RCU polish

1. **Memory order on writer exchange**: §9.2 uses
   `memory_order_acq_rel`. `memory_order_release` suffices (the
   writer's local `rs_old` copy doesn't need acquire ordering
   against its own writes). Nit; keep acq_rel for safety margin
   if it makes review easier.

2. **Worker shutdown and RCU**: §6.4 doesn't mention
   `rte_rcu_qsbr_thread_offline` + `_unregister` on the worker
   exit path. If a worker goes offline without announcing, a
   concurrent reload's `synchronize` will hang forever. Add to
   §6.4: workers call `thread_offline` before exiting the loop,
   and `thread_unregister` after.

3. **Control thread blocking in synchronize vs watchdog**: the
   control thread calls `rte_rcu_qsbr_synchronize` which spins
   until all workers quiesce. If a worker is genuinely stalled
   (not just slow), synchronize never returns and the reload
   command hangs. The watchdog monitors workers independently
   via heartbeat, so a stalled worker triggers SIGABRT → process
   restart → synchronize aborts naturally with the process.
   Acceptable, but document it: "reload can block indefinitely
   if a worker is stalled; the watchdog is the backstop, not the
   reload timeout." Consider also a `rte_rcu_qsbr_check` +
   timeout loop as a nicer alternative — return `reload_timeout`
   error after e.g. 500 ms and leave `rs_new` to be freed. Cleaner
   operational UX but still relies on watchdog to recover the
   stuck worker.

4. **Quiescent-state placement in §5.1 is correct**: publish
   quiescent → then acquire-load `active` → use `rs` for the
   burst → `rs` goes out of scope → next iteration publishes
   quiescent again. Classic QSBR read-side. No bug here.

5. **`WorkerCtx::active` removal side effect**: `WorkerCtx`
   shrinks by 8 B; no alignment damage because the struct is
   already `alignas(64)`.

### Summary of §9 review

- 2 critical bugs (D9 use-after-free via mislocated pointer;
  D10 rate-limit didn't follow D1 at all in §4.4/§5.5).
- 1 medium gap (D11 arena GC sequencing).
- 4 minor polish items (D12).

RCU *strategy* (QSBR, per-burst quiescent, atomic publish +
synchronize + free) is sound. The mechanics section is where
the bugs hide — mostly fallout from the design predating D1
and from copy-paste error on the pointer location.

Batch revision plan addition:
- Add step **13.** D9: consolidate `active` to single global;
  rewrite §4.2, §5.1, §6.1, §6.4.
- Add step **14.** D10: rewrite §4.4 and §5.5 per D1 (per-lcore
  bucket arena with rule_id-keyed rows).
- Add step **15.** D11: add GC ordering paragraph to §9.4.
- Add step **16.** D12: worker shutdown RCU offline/unregister
  in §6.4; optional timeout-based synchronize in §9.2.

---

## Review pass — §5 hot path walkthrough

Reviewed: §5.1 pseudocode, §5.2 L2 classifier, §5.3 L3 classifier,
§5.4 L4 classifier, §5.5 action dispatch, §5.6 cycle budget.

### D13 — CRITICAL: L3 offset bug on VLAN-tagged packets

§5.3 computes L3 header offset as:
```cpp
void* l3 = rte_pktmbuf_mtod_offset(m, void*,
             (et == RTE_BE16(0x8100) ? 18 : 14));
```

But `et` here is `dyn->parsed_ethertype`, which §5.2 already
overwrote with the **inner** ethertype after unwrapping the VLAN
tag:
```cpp
etype = vh->eth_proto;   // §5.2 line 364 — inner etype
```
So on a VLAN-tagged IPv4 packet, `parsed_ethertype == 0x0800`,
the ternary picks offset **14**, and the L3 parser reads
garbage (or the back half of the Ethernet+VLAN header) as if it
were an IPv4 header. Off-by-4 on every tagged packet. Silent.

Fix options:
- (a) Use `dyn->parsed_vlan != 0xFFFF ? 18 : 14` — clean, matches
  what §5.2 actually sets.
- (b) Store `l3_offset` directly in the dynfield during L2 parse
  (1 more byte, 0 extra cycles in L3 classify). Preferred — also
  naturally extends to QinQ (offset 22) later.

Touch points: dynfield schema in §5.1 header comment, §5.2 parse,
§5.3 offset use, §5.4 L4 offset computation (also benefits).

### D14 — CRITICAL: L4 offset ignores IPv4 IHL

§5.4 line 448:
```cpp
auto* l4 = (rte_udp_hdr*)((uint8_t*)l3 + 20); // TODO ip_hl
```

The TODO is load-bearing. Any IPv4 packet with options (IHL > 5)
gets its L4 header misread. Rare on a clean backbone but
absolutely present in the wild (record-route, timestamp, some
DPI injectors). Silent misclassification.

Fix: `((ip->version_ihl & 0x0F) << 2)` — 2 extra cycles. Same
treatment needed for IPv6 — the stub "similar with
rte_fib6_lookup" in §5.3 elides that IPv6 has a fixed 40 B
header but possible extension header chain. For MVP, scope
decision: parse extension chain up to K=2 hops, else drop or
pass per default policy. Document explicitly.

### D15 — CRITICAL: L4 matching model can't express wildcards

§4.1 has one `rte_hash* l4_proto_port` keyed by packed
`(proto:8 | dst_port:16 | src_port:16)`. §5.4 does a single
exact hash lookup. This **only matches fully-specified tuples**.

Real L4 rules in ISP filters are overwhelmingly:
- "TCP dst 443, any src" → can't represent (would need 65536
  hash entries per rule).
- "UDP dst 53, any src" → same.
- "TCP dst in [80, 443, 8080], any src" → 3 entries ok.
- "TCP src-port range 49152–65535, dst 25" → ranges not
  expressible at all.

The "compound primary + filter mask" pattern from L2 (§5.2 /
§4.1 `L2CompoundEntry`) is the obvious answer: primary hash on
`(proto | dst_port)` with a secondary `filter_mask` that
optionally checks src_port / src_port_range / flags. The
architect chose this pattern for L2 but dropped it for L4,
which is backwards — L4 is where wildcards are the common case.

Resolution: rewrite §4.1 L4 structures and §5.4 classifier to
the compound-primary pattern:
```
primary hashes (most-selective first):
  l4_proto_dport      (proto << 16 | dport)  — most common
  l4_proto_sport      (proto << 16 | sport)  — rare but needed
  l4_proto_only       (proto)                — catch-all tier
+ L4CompoundEntry arena with filter_mask for secondary fields
  (src_port exact / src_port_range / tcp_flags / …).
```
Ranges still don't fit a hash — punt to a second-tier linear
scan over "ranged L4 rules" if that set is small, or document
as non-goal for MVP per D6 (dev has 256 rules, small enough).

Touch points: §4.1 l4 section, §5.4 full rewrite, §5.6 cycle
budget (L4 lookup grows to ~60 cycles on secondary check),
input.md §3.1 F1 clarification of L4 matching scope.

### D16 — MEDIUM: REDIRECT leaks mbuf on TX failure

§5.5 line 478:
```cpp
case REDIRECT: rte_eth_tx_burst(a->redirect_port, ctx->qid, &m, 1); return;
```

If `rte_eth_tx_burst` returns 0 (TX ring full on redirect port),
the mbuf is never freed and never re-tried. Leak → mempool
exhaustion → RX starts returning NULL → gauge `nombuf` climbs.

Fixes, in order of preference:
1. Batch REDIRECT into a per-egress-port staging array (like
   mirror), flush at end of burst, free unsent. Also ~10× faster
   at scale because batched `rte_eth_tx_burst` amortizes.
2. Inline fallback: check return value, `rte_pktmbuf_free(m)` on
   0, bump `pktgate_redirect_dropped_total`.

Option 1 is right for production, option 2 is the minimum patch.

Touch points: §4.2 WorkerCtx (add `redirect_tx_buf[N_PORTS][BURST]`
or a small ring), §5.1 burst-end flush, §5.5 REDIRECT case.

### D17 — MEDIUM: hard-coded non-first-fragment drop is unasked policy

§5.3 line 417:
```cpp
if (unlikely((ip->fragment_offset & RTE_BE16(0x1FFF)) != 0)) {
    mbuf_dyn(m)->verdict_layer = TERMINAL_DROP;
    return;
}
```

This silently drops every non-first IPv4 fragment. Rationale
("no L4 header to inspect") is valid for L4-dependent rules but
the rule engine may also have pure L3 rules (matching on dst
prefix alone) that should still apply to fragments. And even
when no rule matches, the default_action might be ALLOW —
dropping fragments hard-codes DROP regardless.

Correct behavior:
- Non-first fragment → mark `dyn->verdict_layer = TERMINAL_PASS`
  (or equivalent "skip L4") → let L3 rules and/or default action
  decide.
- Optionally expose a global `fragment_policy: {allow, drop,
  l3_only}` in config (default `l3_only` — apply L3 rules, skip
  L4, use default for misses).

This matches pktgate's fragment handling (noted in the
transformation table §17). Don't regress.

Touch points: §5.3, config schema for `fragment_policy`,
CONFIG.md.

#### Resolution (P9, 2026-04-10)

User picked **`l3_only`** as the default `fragment_policy`.

Behavior of the default:
- Non-first IPv4 fragment / IPv6 fragment header packet:
  L3 classifier still runs (rules matching on src/dst prefix,
  VRF, etc. apply normally). L4 classifier is skipped — there
  is no reliable L4 header on a non-first fragment.
- If L3 produces a terminal verdict, that verdict applies.
- If L3 has no match and the rule pipeline would normally fall
  through to L4, the fragment instead falls through directly to
  `default_behavior`.

Other allowed values: `drop` (terminal drop on any fragment,
operator opt-in for stricter filtering), `allow` (skip L3+L4
entirely on fragments and pass — explicitly unsafe, not
recommended, included only for completeness / debugging).

Schema field: top-level `fragment_policy: "l3_only" | "drop" | "allow"`,
default `"l3_only"` if absent. Document in §3 (config) and
in CONFIG.md / writer notes.

### D18 — MEDIUM: cycle budget is best-case only

§5.6 cycle budget assumes "L2 hash lookup (1 hit)". In an ISP
filter the **common case is L2 miss** — most packets don't match
on src_mac/dst_mac/vlan/etype and pass through to L3. On miss
the classifier does:
1. `rte_hash_lookup(l2_src_mac)` → miss ~30 c
2. `rte_hash_lookup(l2_dst_mac)` → miss ~30 c
3. VLAN LUT check → ~5 c
4. ethertype LUT + fallback hash → ~30 c
5. (+ pcp branch if present)
→ ~95 cycles for an L2 miss, not ~40.

Then L3 hit or miss, then L4 if needed. Realistic total for a
TCP/IP packet with no L2 match, matching an L3 prefix rule:
```
RCU quiescent    ~2
RX burst amort   ~15
Prefetch hidden
L2 parse         ~20
L2 miss          ~95
L3 FIB hit       ~30 (fib_lookup single, not bulk-1)
L4 skipped       0 (terminal from L3)
Action dispatch  ~10
Counter update   ~5
TX burst amort   ~15
---
Total: ~192 cycles
```
Still within 400 c budget — but much closer than the document
suggests, and the "substantial headroom" claim is misleading.

Add a second budget table column for "L2-miss common case" or
replace the single column with min/typ/max.

Also missing from budget:
- D4 dual-path offload branch (one `PKT_RX_FDIR` test, ~3 c)
- Fragment / IHL checks (~5 c)
- Counter update on per-layer+rule_id (the layered indexing
  could be more than 5 c if it involves bounds checks)

### D19 — MINOR: §5.1/§5.3 cleanup

1. **`rte_fib_lookup_bulk(rs->l3_v4, &da, &nh, 1)`** — bulk with
   count 1 is slower than single-entry `rte_fib_lookup`. Either
   do the lookup single-entry, or actually batch across the
   burst (collect all V4 addrs into a stack array, one bulk call
   per burst). The latter fits the "three loops over burst"
   structure and amortizes nicely. Flag as plan-phase
   optimization.

2. **§5.3 "try src?" dead branch** — the comment is half-finished;
   either implement src-prefix FIB lookup or remove the stub.
   Tied to the compound-L3 compiler strategy (§5.3 last
   paragraph). Complete the description.

3. **§5.1 `handle_idle(ctx)`** — undefined. Must specify: does
   it sleep, spin, or call `rte_rcu_qsbr_thread_offline`? If it
   blocks without going offline, a concurrent reload's
   `rte_rcu_qsbr_synchronize` hangs until traffic resumes.
   Spec: idle handler is a tight busy-check (e.g. exit after 16
   empty polls to let CPU cool, but stay online). Document.

4. **§5.1 triple pass over burst (L2/L3/L4 in separate loops)** —
   defensible (keeps each classifier's tables hot), but worth
   noting as a conscious choice, not an accident. Alternative
   is fused per-packet classify. Plan-phase microbenchmark.

5. **§5.5 TAG action** — `apply_dscp_pcp` semantics need spelling
   out: DSCP lives in IPv4 ToS / IPv6 traffic class; PCP lives
   in VLAN tag. If packet has no VLAN, PCP tag is a no-op or
   adds a tag? Decide and document.

### D20 — MINOR: IPv6 is stub

§5.3 IPv6 branch is `// similar with rte_fib6_lookup` — no code,
no extension-header handling, no cycle budget entry. §5.4 same
story — L4 header offset hard-coded to IPv4's 20 B.

Per input.md §3.1 F1 dual-stack is required. The architect
handwaved it. Resolution: either

- (a) Full IPv6 spec in §5.3 (parse fixed 40 B header, walk up
  to K=2 extension headers — hop-by-hop, routing; anything
  deeper treats as unclassifiable and defers to default), OR
- (b) Scope-reduce IPv6 L4 matching to "first-protocol only, no
  ext headers" for MVP, flag ext-header support as v2.

User decision needed; pushing to pending list.

#### Resolution (P8, 2026-04-10)

User picked **(b) first-protocol only, ext-headers in v2**.

Architectural specification:

- L3 IPv6 parser reads the fixed 40-byte header. `next_header`
  field is treated as the L4 protocol identifier directly.
- If `next_header` ∈ {TCP, UDP, ICMPv6, SCTP, …} (i.e. a
  recognized L4 protocol with a known header at offset 40), L4
  classifier proceeds with `l4_offset = 40`.
- If `next_header` is any IPv6 extension header
  (hop-by-hop=0, routing=43, fragment=44, ESP=50, AH=51,
  destination-options=60, mobility=135, HIP=139, shim6=140,
  experimental=253/254): packet is treated as **L4-unclassifiable
  in MVP**.
  - L3 rules still apply normally (this is identical to the
    fragment policy `l3_only` semantics — and consistent with
    P9 resolution).
  - L4 classifier is skipped.
  - If L3 has no match → falls through to `default_behavior`.
  - Note: fragment header (44) is also handled by the
    `fragment_policy` field; ext-header treatment and fragment
    treatment converge on the same code path (skip L4, let L3
    decide).
- Counter `l4_skipped_ipv6_extheader` (per-lcore) bumped on
  every such packet so operators can size demand for v2.

Architecture (M2-clean) describes the **full** model — extension
header chain walking up to K hops — as a future capability. §14
phase plan ships only the first-protocol-only behavior in MVP;
ext-header walking is a v2 item.

Touch points: §5.3 IPv6 parse, §5.4 L4 dispatch (skip case),
§6/§4 counter additions, §3 config schema (no new field —
behavior is fixed in MVP, not configurable), §14 phase plan
(extension-header walking deferred to v2), §10 telemetry
(`l4_skipped_ipv6_extheader` counter).

### Summary of §5 review

- 3 critical (D13 off-by-4 on VLAN, D14 IHL ignored, D15 L4
  wildcard model missing).
- 3 medium (D16 REDIRECT leak, D17 fragment policy hard-coded,
  D18 best-case budget).
- 2 minor cleanup (D19 misc, D20 IPv6 stub).

The big picture: §5.2 L2 classifier is the most thought-through
piece (compound + filter_mask shows real rule-engine savvy).
§5.3 and especially §5.4 feel rushed — the L4 matching model is
the single biggest structural miss. The cycle budget oversells
headroom by picking the friendliest case.

Batch revision plan additions:
- **17.** D13: dynfield `l3_offset` byte; fix §5.2/§5.3.
- **18.** D14: IHL parse in §5.4; IPv6 L4 decision with D20.
- **19.** D15: rewrite §4.1 L4 structures and §5.4 with compound
  primary + filter_mask; cycle budget update.
- **20.** D16: redirect staging in §4.2/§5.5; burst-end flush.
- **21.** D17: `fragment_policy` config field; §5.3 behavior.
- **22.** D18: §5.6 min/typ/max cycle budget table.
- **23.** D19: misc cleanups (fib_lookup single, idle handler
  spec, TAG semantics, complete L3-src stub).
- **24.** D20: IPv6 scope decision (pending user input).

### Pending (need user input)

- **P8** — RESOLVED 2026-04-10 → option (b), first-protocol
  only, ext-headers v2. See Resolution block under D20.

- **P9** — RESOLVED 2026-04-10 → `l3_only` default. See
  Resolution block under D17.

- **P7** — rte_flow automatic topological offload promotion:
  v2 vs v3. Plan-level question, **does not block** batch
  revision. Architecture hooks are identical either way.
  Defer to phase-plan discussion after batch revision lands.

---

## Batch revision execution log

### Round 1 — writer + reviewer pass on design.v2.md (2026-04-10)

- **Writer agent** (Opus, general-purpose): produced
  `design.v2.md` (2118 lines) by applying all 24 batch-revision
  steps. Output written to `/home/user/pktgate-dpdk/design.v2.md`,
  `design.md` v1 preserved untouched. Writer flagged six new
  observations N1–N6 in the document's appendix.
- **Reviewer agent** (Opus, general-purpose, fresh independent
  instance): produced `review-v2.md`. **Verdict:
  APPROVE_WITH_FIXES.** All D1–D20 verified as applied in code,
  not just prose; M1/M2 clean across §1–§13; previously-known
  critical bugs (D9, D13, D14, D15, D16, D17) fixed. Two new
  critical bugs found (logged below as D21/D22), three medium
  (D23/D24/D25), six minor.

### D21 — CRITICAL: apply_action NEXT_L4 / SKIP_L4 cliff

Found by reviewer in design.v2.md §5.3 / §5.5. On a non-first
IPv4 fragment under `FRAG_L3_ONLY`, §5.3 set
`verdict_layer = NEXT_L4` after raising SKIP_L4. The dispatcher
in §5.1 then skipped `classify_l4` because SKIP_L4 was set, so
the packet entered `apply_action` carrying `verdict_layer =
NEXT_L4` — for which the outer switch had no case, leaving the
local `RuleAction* a` uninitialized and dereferenced one line
later. UB / silent mis-dispatch on every L3-miss fragment. The
same cliff existed on the IPv6 ext-header path (`is_ext` →
SKIP_L4 → L3 miss → `verdict_layer = NEXT_L4`).

Tell-tale fingerprint: a dead ternary
`(dyn->flags & SKIP_L4) ? NEXT_L4 : NEXT_L4` on the L3-miss
line, suggesting the writer meant to branch one side to
something else (correct value: `TERMINAL_PASS`).

**Resolution (in-place patch on design.v2.md, 2026-04-10)**: on
L3 miss with SKIP_L4 set, set `verdict_layer = TERMINAL_PASS`
directly. §5.5's existing `TERMINAL_PASS` case applies
`default_action`. Same fix applied to IPv6 ext-header path.
Belt-and-braces: D25 below adds compile-time defence.

### D22 — CRITICAL: IPv6 EXT_MASK undefined behaviour

Found by reviewer in design.v2.md §5.3 IPv6 block. The
`EXT_MASK` constant included `(1ull << 135)`, `(1ull << 139)`,
`(1ull << 140)`. Per C++ [expr.shift], shifting a 64-bit
operand by 64 or more bits is UB. In practice gcc/clang reduce
the count modulo 64, so `1ull << 135 == 1ull << 7` — the mask
silently flips bit 7 (`next_header == 7`, unassigned, IPv6 ICMP-
adjacent) and would falsely classify it as an extension header.
Functionally values 135/139/140/253/254 were also caught by an
explicit OR clause, so the visible bug surface was narrow, but
the mask was a silent correctness landmine for any future edit.

**Resolution (in-place patch on design.v2.md, 2026-04-10)**:
split the mask. `EXT_MASK_LT64` keeps only the bits < 64
(0, 43, 44, 50, 51, 60); the values ≥ 64 are tested with the
existing explicit `nxt == 135 || 139 || 140 || 253 || 254`
clause. No UB, no functional change for the values that already
worked, no silent landmine.

### D23 — MEDIUM: RlAction.slot accessor mismatch (§4.4 vs §5.5)

Found by reviewer. Writer's §4.4 hot-path snippet referenced
`rs->rl_actions[a->rl_index].slot`, but the `RlAction` struct
declared in §4.4 had no `slot` field. §5.5 used a different
shape entirely: `rl_arena_row(g_cp.rl_arena, rl.rule_id)`,
implying a per-packet hash lookup against `id_to_slot`. Either
shape works, but they were inconsistent — implementing from
§4.4 in isolation gives a struct that doesn't compile;
implementing from §5.5 in isolation puts a hash lookup on the
hot path.

**Resolution (in-place patch on design.v2.md, 2026-04-10)**:
chose the dense-slot accessor (cleaner, O(1), no hot-path hash
lookup). Added `uint32_t slot` to `RlAction`. §4.4 and §5.5 now
both index `&g_cp.rl_arena->rows[rl.slot]`. The `id_to_slot`
table moves to a compiler-only role (resolves rule_id → slot at
publish time, never touched per-packet).

### D24 — MEDIUM: id_to_slot lifetime / slot recycling unspecified

Writer-flagged as N1, reviewer escalated to medium. The
`RateLimitArena::id_to_slot` table and slot reuse policy were
mentioned but not explained: when is a slot freed, when is it
reusable, how does compile-time slot allocation interact with
the §9.4 GC pass.

**Resolution (in-place patch on design.v2.md, 2026-04-10)**:
added a "Slot lifecycle" subsection to §4.4 spelling out the
four cases (first publish, surviving rule, removed rule,
slot reuse) and updated the §9.4 GC sequence to use
`rl_arena_free_slot` (slot release) instead of
`rl_arena_free_row` (row deallocation). Row memory stays in
place for reuse; the slot index is what cycles.

### D25 — MEDIUM: apply_action switches lacked default arms

Found by reviewer. Both `switch` statements in `apply_action`
enumerated only the expected cases and had no `default:` arm,
so any new `Verdict` or `ActionVerb` added without updating the
dispatcher would fall through silently to UB. C++ does not
require default arms and the compiler does not warn by default —
which is why D21 (the NEXT_L4 cliff) compiled cleanly.

**Resolution (in-place patch on design.v2.md, 2026-04-10)**:
added `default:` arms to both switches that bump a new
per-lcore `dispatch_unreachable_total` counter and free the
mbuf as a runtime backstop. Added `-Wswitch-enum` to the
mandatory CMake warning flag list in §13 so future
out-of-sync enum values fail at compile time, not at runtime.

### Touch-up minors (m1–m6, 2026-04-10)

All applied in-place to design.v2.md:

- **m1** — `interface_roles` example in §3a now shows the
  selector as a sum type (`pci` | `vdev` | `name`); §3a.2
  spells out the validation rule.
- **m2** — `tag_pcp_noop_untagged_total` and the new
  `dispatch_unreachable_total` counter (from D25) added to
  §4.3 LcoreStats and §10.3 metric names.
- **m3** — covered by the D21 fix (the dead ternary was the
  fingerprint of the same cliff).
- **m4** — `N_PORTS_MAX` defined explicitly in §4.2 with
  rationale (compile-time per-burst staging bound, not a
  rule-scale parameter; production target 16; declared in
  `include/pktgate/limits.h`).
- **m5** — snapshot ring `N = 4` in §10.1 now carries the
  rationale (minimum 2, slack for slow exporters).
- **m6** — counter indexing model spelled out in §4.3:
  `RuleAction.counter_slot` carries a dense per-layer slot
  assigned at compile time, hot path is constant index math
  (`layer_base(L) + a->counter_slot`), no hash lookup.

### Status after touch-up

- All D1–D20 reviewer-verified as applied; the D9/D13/D14/D15
  class of correctness fixes is real and visible in code.
- D21–D25 (new findings from the reviewer pass on v2) are
  resolved in-place on design.v2.md without re-running the
  full writer → reviewer cycle. Reviewer's own recommended next
  action specifically said localized in-place fixes were
  appropriate.
- design.v2.md is now ready to be promoted to design.md (after
  user confirmation). The promotion should be a single rename
  + git add, no further architecture work scheduled.
- P7 remains the only open pending item; it is plan-level and
  does not affect the architecture document.
- Next phase: implementation planning. Phase 1 week 1 task
  decomposition, CMake skeleton bootstrap, gtest harness
  bootstrap, initial parser/validator scaffolding.

## External review pass (2026-04-10)

Six points + one bonus question received from an external reviewer
of design.md (post-promotion). Triage:

- **5 points + bonus: based on incomplete reading of design.md.**
  The proposed fixes are already in the design as written:
  - "per-rule counter cache-line bouncing" → §4.3:454-513,
    `PerLcoreCounters` is per-lcore, zero atomics, ruleset author
    quoted verbatim what the reviewer recommends as the only fix.
  - "VLAN should be a direct array" → §5.2:821, `l2_vlan_lut[vlan]`,
    direct LUT on 4096 entries.
  - "MAC should be packed in u64" → §5.2:804, `mac_to_u64()`.
  - "EtherType should not be hashed" → reviewer misread the
    compound primary + filter_mask pattern (D15); EtherType is a
    secondary equality filter inside the L2 compound entry, not
    a hash key.
  - "no NUMA in design" → §3, §4 (Ruleset NUMA-local), §6 init,
    §7:1404-1406, §8.2 (per-socket mempools), §8.3 (per-lcore
    structs all NUMA-local), §13 reserved `numa.h` header.
  - "dry-run reload to avoid hugepage exhaustion" → conflicts
    with M1 (5.6 GB is dev VM, production target is 2-4 GiB
    headroom in §8.1), and validate-before-swap is already the
    §9.2 RCU reload contract.
  - "pipeline flattening / dynfield metadata" → mbuf dynfield
    pipeline is already in §5.2-§5.3 (D13). Flattening would
    change first-match-wins semantics required by F1 in input.md.
  - bonus "IPv4 fragments should be checked early" → §5.3:866-888,
    fragment policy is the first check after the IP header is
    touched, well before FIB lookup. D17 / P9 already resolved.

- **1 point (mirror + payload-mutating actions): legitimate.** The
  reviewer correctly identified that an existing latent invariant
  was not documented. Resolved as **D26**.

### D26 — Mirror refcnt-zero-copy compile-time gate

**Decision.** When the active Ruleset contains any rule with a
payload-mutating verb, the compiler MUST select the deep-copy
mirror strategy (`rte_pktmbuf_copy`) — the refcnt zero-copy path
(`rte_mbuf_refcnt_update`) is unsafe in that case. Today the only
mutating verb is TAG (DSCP / PCP rewrite). The gate is a
whole-ruleset property in `ruleset_builder`, evaluated once per
build, no per-packet branching.

**Why it matters.** Refcnt-mirror creates a clone that shares the
mbuf data buffer with the original. Anything that modifies the
shared bytes between clone creation and DMA completion will
corrupt one or both copies. Three sources of mutation must be
considered:

1. **Action verbs.** The current dispatch (§5.5) is verb-exclusive
   per packet — a packet hit by MIRROR is never hit by TAG in the
   same dispatch — but a single Ruleset can carry both rules. The
   strategy choice is per-ruleset, not per-packet, because refcnt
   sharing extends past dispatch into TX/driver paths.
2. **TX prepare.** Drivers may rewrite headers in place (software
   VLAN insert, software cksum). Refcnt-mirror requires a
   per-driver capability flag `tx_non_mutating` set in the driver
   capability table; if absent, deep-copy is forced.
3. **Future mutating verbs.** Adding NAT, header rewrite, or any
   other byte-level rewrite verb expands `MUTATING_VERBS`. The
   D26 gate must be updated in lockstep — enforced by
   `-Wswitch-enum` coverage of the verb enum (§13) plus a unit
   test that scans the verb enum and asserts every value is
   classified mutating / non-mutating.

**Compiler gate (in `ruleset_builder`):**

```
use_refcnt_mirror :=
      config_requests_zero_copy
    ∧ ∀ rule ∈ ruleset : rule.verb ∉ MUTATING_VERBS
    ∧ driver_caps[mirror_port].tx_non_mutating
else strategy := deep_copy
```

`MUTATING_VERBS = { TAG }` for D26 baseline.

**Coverage in design.md:**
- §5.5 MIRROR case — full gate documented in the case comment
- §15 risk register row #6 — explicit invariant + mitigation
- D7 (mirror Phase 2 schedule) is unchanged; D26 governs HOW
  mirror ships in Phase 2, not whether

**Failure mode covered.** A live ruleset with refcnt-mirror is
hot-reloaded with a new ruleset that adds the first TAG rule:
the compiler selects deep_copy for the new ruleset, RCU swap is
atomic per §9.2, no in-flight packet sees a mixed state.

*Last updated: 2026-04-10 (D26 added from external review pass)*
