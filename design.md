# pktgate-dpdk — Architecture Design Document (v2)

> Revision v2 of `design.md`. Applies all batch-revision decisions
> (M1, M2, D1–D20) from `review-notes.md`, incorporating the P8/P9
> resolutions. Architectural sections (§1–§13) describe the full
> target system; §14 phase plan is the sole home of
> MVP/v2/v3 scoping.

---

## 1. Executive summary

`pktgate-dpdk` is a DPDK 25.11 userspace L2/L3/L4 packet filter for the
GGSN–Gi interface, designed to sustain 40 Gbps bidirectional (worst case
59.52 Mpps) per site with sub-50 µs added p99 latency and < 0.01 %
collateral loss. It runs a strict run-to-completion model with one
lcore pinned per RX/TX queue pair, classifies each burst through a
layered pipeline (L2 → L3 → L4) backed by `rte_hash`, `rte_fib` /
`rte_fib6`, and a per-lcore token-bucket rate-limiter keyed by stable
rule IDs; dispatches one of six actions (`allow`, `drop`, `mirror`,
`rate-limit`, `tag`, `redirect`); and updates the configuration
without restart through an atomic `rte_rcu_qsbr`-protected pointer
swap with ≤ 100 ms reload latency and full rollback on any
compilation failure. The on-disk configuration is a clean, purpose-
built JSON schema that is **not** compatible with the legacy pktgate
(XDP) schema — each uses the schema best suited to its runtime. The
system defaults to fail-open software-forward bypass on watchdog-
detected stalls, exposes Prometheus, sFlow, structured JSON logs and
`rte_telemetry`, and is built with CMake + `pkg-config libdpdk` in
C++20 (with C++23 idioms welcome).

### 1.1 Principle: dev VM does not shape architecture (M1)

The development environment is a VirtualBox VM (4 vCPU, 5.6 GB RAM,
2× Intel 82545EM e1000 NICs on `uio_pci_generic`, 512 MiB hugepages).
It is a correctness and smoke-test sandbox only. Its limitations
**must not** constrain any architectural decision in this document.
Architecture is defined for the production target — server-class
hardware with Intel E810 / XL710 or Mellanox ConnectX-5 / 6-class
40 Gbps NICs. The dev VM runs whatever subset of the design works
there, degrading gracefully to single-queue / single-lcore / no-
offload paths. A feature is **in** the architecture if it is needed
for the production target, even if the dev VM cannot exercise it
(canonical example: symmetric Toeplitz RSS stays in §7 even though
e1000 has no RSS). Runtime-sized ceilings (§3, §8) have an explicit
"dev default vs production target" split — see §8.4.

## 2. High-level architecture

```
                            pktgate-dpdk process
   ┌────────────────────────────────────────────────────────────────┐
   │                                                                │
   │  ┌──────────────────────── Control Plane (non-isolated cores) ─┐│
   │  │                                                             ││
   │  │  inotify ─► Loader ─► Parser ─► Validator ─► Compiler ──┐   ││
   │  │     ▲                                                   │   ││
   │  │     │                                                   ▼   ││
   │  │  UDS cmd                                          GenManager ││
   │  │   socket           Watchdog / Heartbeat              │      ││
   │  │     │                       │                       │      ││
   │  │     ▼                       ▼                       ▼      ││
   │  │  Telemetry  ◄────── stats aggregator ◄──── RCU pointer swap ││
   │  │  (Prom/sFlow/                                (g_active)    ││
   │  │   logs/rte_tel)                                      │     ││
   │  └──────────────────────────────────────────────────────┼─────┘│
   │                                                         │      │
   │  ────────────────────  Data Plane  ─────────────────────┼───── │
   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │      │
   │  │  lcore N    │  │  lcore N+1  │  │  lcore N+k  │      │      │
   │  │ RX q0/TX q0 │  │ RX q1/TX q1 │  │ RX qk/TX qk │      │      │
   │  │             │  │             │  │             │      │      │
   │  │ burst loop ─┼──┤ burst loop ─┼──┤ burst loop  │ ◄────┘      │
   │  │  acquire-   │  │  acquire-   │  │  acquire-   │  reads      │
   │  │  load       │  │  load       │  │  load       │  g_active   │
   │  │  g_active   │  │  g_active   │  │  g_active   │  once/burst │
   │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
   │         │                │                │                    │
   └─────────┼────────────────┼────────────────┼────────────────────┘
             ▼                ▼                ▼
       NIC port 0/1 RX queues          NIC port 0/1 TX queues
              (RSS spreads)                  (per-lcore)
```

Two physical NIC ports form an inline pair (port0 ↔ port1). Each port
has K RX and K TX queues; lcore i owns `(port0.rxq[i], port0.txq[i],
port1.rxq[i], port1.txq[i])`. RSS distributes flows with a symmetric
Toeplitz key. The control plane lives on non-isolated cores; the
dataplane lcores never see the control thread. The active compiled
ruleset is published through a single process-wide atomic pointer
(`g_active`); every worker reads it exactly once per burst via
acquire-load, uses that local reference for the whole burst, and
drops it on burst end (natural release).

## 3. Module breakdown

| Module | Responsibility | Public interface | DPDK deps |
|---|---|---|---|
| `eal_init` | EAL bring-up, port/queue/mempool configuration, NUMA placement | `bootstrap(argc, argv) → PortSet` | `rte_eal`, `rte_ethdev`, `rte_mempool` |
| `config_parser` | JSON → AST (`Config` struct) | `parse(path) → expected<Config, Err>` | none |
| `config_validator` | Semantic validation: refs, ranges, action params, collisions, schema version (strict match) | `validate(Config) → expected<void, Err>` | none |
| `sizing_loader` | Sizing config (rule ceilings, pool sizes) parser and merger with CLI overrides | `load(path) → SizingConfig` | none |
| `compiler::objects` | Expand `objects` (subnets, subnets6, mac_groups, port_groups) into tables | `compile(ObjectStore) → CompiledObjects` | none |
| `compiler::rules` | Layer-2/3/4 rule flattening, compound L2 and L4 primary/secondary split, port-group expansion, key collision detection, rule tiering (software / hardware) | `compile(Pipeline, CompiledObjects, Sizing) → CompiledRules` | none |
| `ruleset_builder` | Materialize compiled rules into a `Ruleset` (immutable, NUMA-local): `rte_hash`, `rte_fib`, per-layer action arenas; also programs `rte_flow` entries for hardware-tier rules, with graceful fallback to software | `build(CompiledRules) → unique_ptr<Ruleset>` | `rte_hash`, `rte_fib`, `rte_fib6`, `rte_flow` |
| `ruleset` | Read-only data structure consumed by the hot path | `lookup_l2(...)`, `lookup_l3(...)`, `lookup_l4(...)` (all `static inline`) | none at runtime |
| `gen_manager` | RCU-QSBR registration, single-global pointer swap, arena GC, deferred free | `commit(unique_ptr<Ruleset>)` | `rte_rcu_qsbr` |
| `rl_arena` | Process-wide per-lcore rate-limit state, keyed by stable `rule_id`, surviving reloads | `lookup(rule_id) → TokenBucketRow*` | none at runtime |
| `worker` | The lcore burst loop, including per-port TX staging drain | `run(WorkerCtx*)` via `rte_eal_remote_launch` | `rte_ethdev`, `rte_mbuf`, `rte_rcu_qsbr` |
| `actions` | Rate-limit, tag, mirror, redirect primitives | `static inline` action handlers | `rte_mbuf`, `rte_ip` |
| `mirror` | Mirror clone (deep copy and refcount-shared variants), target-port staging | `mirror_packet(...)` | `rte_mbuf` |
| `ratelimit` | Per-lcore token-bucket consume, lazy TSC refill | `rl_consume(row, len)` | none (no atomics) |
| `telemetry::prom` | HTTP `/metrics` exposition on a control thread | `start(port)` | none |
| `telemetry::sflow` | sFlow datagram encoder + UDP sender (control thread) | `submit_sample(...)` from worker | none |
| `telemetry::log` | Lock-free SPSC log ring per worker, drained to JSON-lines | `LOG_INFO(...)` | none |
| `telemetry::rte_tel` | Hooks into `rte_telemetry` for `/dpdk/telemetry` UDS | `register()` | `rte_telemetry` |
| `watchdog` | Heartbeat poll, restart counters, bypass-mode trigger | `tick()`, `enter_bypass()` | none |
| `cmd_socket` | Unix domain socket: `reload`, `status`, `dump-config`, `dump-rule N` | `serve()` | none |
| `inotify_loader` | Directory watch + debounce + reload trigger | `run()` | none |
| `main` | Wires modules, signal handling, control loop, interface-role binding, `--standby` entry | `int main(...)` | all of above |

## 3a. Configuration schema

This is a fresh, purpose-built JSON schema. It is **not** compatible
with the legacy pktgate (XDP) config-schema.json. Scenarios from
`/home/user/filter/scenarios/*.json` are treated as inspiration for
test cases only; they must be re-expressed in the new schema if they
are reused.

### 3a.1 Top-level document

```jsonc
{
  "version": 1,                              // integer, strict match against binary
  "interface_roles": {                       // logical role → port selector (sum type)
    // Each value is exactly one of: { "pci": <bdf> } | { "vdev": <arg> } |
    // { "name": <eal-port-name> }. Mixing keys within a single role is
    // rejected by the validator (§3a.2). Example below deliberately uses
    // all three selector shapes so that dev VM (net_pcap / net_null) and
    // production NICs share the same schema path:
    "upstream_port":   { "pci":  "0000:03:00.0" },       // production NIC
    "downstream_port": { "pci":  "0000:03:00.1" },       // production NIC
    "mirror_port":     { "vdev": "net_pcap0,tx_iface=lo" },// dev-friendly sink
    "tap_probe_port":  { "name": "net_tap0" }            // EAL-registered name
  },
  "sizing": {                                // optional; may also be a separate file
    "rules_per_layer_max": 4096,
    "mac_entries_max":     4096,
    "ipv4_prefixes_max":   16384,
    "ipv6_prefixes_max":   16384,
    "l4_entries_max":      4096,
    "vrf_entries_max":     256,
    "rate_limit_rules_max":4096,
    "ethertype_entries_max":64,
    "vlan_entries_max":    4096,
    "pcp_entries_max":     8
  },
  "objects": {
    "subnets":      { "corp_v4":   ["10.0.0.0/8"] },
    "subnets6":     { "corp_v6":   ["2001:db8::/32"] },
    "mac_groups":   { "gateways":  ["aa:bb:cc:dd:ee:ff"] },
    "port_groups":  { "web_ports": [80, 443, 8080] }
  },
  "default_behavior": "drop",                // "allow" | "drop"
  "fragment_policy":  "l3_only",             // "l3_only" (default) | "drop" | "allow"
  "pipeline": {
    "layer_2": [
      {
        "id":        1001,                   // operator-assigned, stable
        "match": {
          "interface":  "upstream_port",     // interface_roles reference
          "vlan_id":    100,
          "src_mac":    "aa:bb:cc:dd:ee:ff",
          "ethertype":  "0x0800"
        },
        "action":  { "type": "allow", "next_layer": "l3" },
        "hw_offload_hint": false,            // D4: operator opts in per rule
        "comment": "trusted gateway uplink"
      }
    ],
    "layer_3": [
      {
        "id":    2001,
        "match": {
          "interface":   "upstream_port",
          "vrf":         0,
          "dst_subnet":  "corp_v4"           // object ref
        },
        "action": { "type": "rate-limit",
                    "rate": "200Mbps", "burst_ms": 10 },
        "hw_offload_hint": false
      }
    ],
    "layer_4": [
      {
        "id":    3001,
        "match": {
          "l3_proto":  "tcp",
          "dst_port":  443,
          "tcp_flags": { "syn": true }
        },
        "action": { "type": "drop" },
        "hw_offload_hint": false
      }
    ]
  }
}
```

### 3a.2 Schema notes

- **`version`** is strict. Binary rejects any config whose `version`
  does not match the binary's compiled-in schema version with a clear
  error. Migration between schema versions is a separate off-line
  operator task (tooling out of scope here).
- **`interface_roles`** decouples rules from physical identity. Rules
  only reference logical roles; role → DPDK-port mapping is the per-
  host surface (config entry or CLI flag). Two hosts with different
  PCI BDFs run the same rule file (D5, HA-friendly). Each role value
  is a **sum type** with exactly one of these selector keys:
    - `pci`  — PCI BDF, e.g. `"0000:03:00.0"` (production NICs);
    - `vdev` — DPDK virtual device string, e.g.
       `"net_pcap0,iface=eth1"` (dev VM, CI, functional tests);
    - `name` — DPDK-reported port name (rare, mostly for diagnostics).
  The compiler validates that exactly one key is present and that
  the resulting port resolves at EAL init.
- **`sizing`** may be inlined or loaded from a separate file via
  `--sizing-config <file>`. All capacity arrays are sized from it at
  startup. No compile-time ceilings — only a hard compile-time
  **minimum** of 16 per layer to keep tests meaningful.
- **`fragment_policy`** is a top-level field. `"l3_only"` is the
  default: under it, **first** fragments (IPv4 with `frag_offset==0
  && MF==1`, IPv6 with a Fragment ext header carrying
  `frag_offset==0`) carry the inner L4 header in the same packet
  and run the **full** L4 stage; **non-first** fragments are
  L4-unclassifiable, so only the L3 rules run and `default_behavior`
  applies on L3 miss (D27). Operators writing L4 rules should be
  aware that under `l3_only` an L4 match against a fragmented flow
  will only ever fire on the first fragment of each datagram —
  observe the `l4_skipped_ipv6_fragment_nonfirst` counter (§10.3)
  to confirm. Strict
  symmetric handling requires `fragment_policy="drop"`. `"drop"` is
  terminal drop on any fragment. `"allow"` is pass-through (unsafe,
  debug only). See §5.3 for exact semantics and D17 rationale.
- **Per-rule `id`** is operator-assigned and stable. It keys per-rule
  counters and the rate-limit arena across reloads. Operators who
  want a clean rate-limit bucket for a semantically changed rule
  must pick a new `id`.
- **Per-rule `hw_offload_hint`** (D4) tells the compiler that the
  rule is a candidate for `rte_flow` offload. Default false. See §9.5.
- **`action`** is exactly one of: `allow` (with optional `next_layer`),
  `drop`, `mirror` (with `target_port` role ref, optional `sample`
  rate), `rate-limit` (`rate`, `burst_ms`), `tag` (`dscp`, `pcp`),
  `redirect` (`target_port` role ref).
- **Mirror** is fully modelled in the schema (D7). See §5.5 and §14
  for the shipping schedule.
- **L4 port lists** are expanded at compile time into the compound L4
  tables (§4.1, §5.4). True numeric port ranges (`src_port_range` /
  `dst_port_range`) are expressible in the architecture via a second-
  tier scan; the phase plan in §14 decides which shipping phase
  includes them.

### 3a.3 Open-question resolutions encoded in the schema

- Q6 control plane: inotify directory-watch + UDS command socket.
  Socket is `/run/pktgate/ctl.sock` (mode 0600, JSON line protocol).
- Q11 versioning: strict `version`, binary refuses mismatches.
- Q12 sizing: runtime `sizing` section (§8.4 operator guide).
- HA (D5): `interface_roles` + `--standby` CLI; see §6, §11.

## 4. Data structures

### 4.1 `Ruleset` — the immutable compiled artifact

A `Ruleset` is the unit of hot reload. It is allocated NUMA-local on
the socket of the dataplane lcores, read-only after publication, and
freed only after RCU quiescence. **All capacity arrays below are
sized at init time from the sizing config — no fixed constants.**

```cpp
// Read-only arena element. alignas(4) — matches the widest member
// (uint32_t rule_id). NOT cache-line-aligned: actions are read-only
// after publication, so multiple actions sharing a cache line only
// cause shared-read traffic, never coherence bouncing. Keeping the
// struct dense (sizeof = 20) keeps the arena small and improves
// prefetch coverage. Index scaling by 20 is IMUL on x86-64 (single
// cycle in practice) — acceptable trade vs. the 3x memory cost of
// a shift-indexed 64-byte layout.
struct alignas(4) RuleAction {
    uint32_t  rule_id;       // stable operator-assigned id; keys counters + rl_arena
    uint16_t  counter_slot;  // dense per-layer slot ∈ [0, rules_per_layer_max), §4.3
    uint8_t   verb;          // ALLOW | DROP | MIRROR | RL | TAG | REDIRECT
    uint8_t   next_layer;    // 0=terminal | 3 | 4
    uint8_t   execution_tier;// SW | HW (D4)
    uint8_t   flags;
    uint16_t  redirect_port; // egress port idx (or 0xFFFF)
    uint16_t  mirror_port;
    uint8_t   dscp;          // 6-bit DSCP target (for TAG)
    uint8_t   pcp;           // 3-bit PCP (for TAG)
    uint16_t  rl_index;      // index into rs->rl_actions[] (ruleset-scoped handle)
};
static_assert(sizeof(RuleAction) == 20, "RuleAction layout drift");

struct L2CompoundEntry {           // value of L2 primary hash
    uint8_t  filter_mask;          // bits: ETHERTYPE|VLAN|PCP|DST_MAC|SRC_MAC
    uint8_t  want_pcp;
    uint16_t want_ethertype;       // network byte order
    uint16_t want_vlan;            // host order
    uint8_t  want_mac[6];          // the *other* MAC if both src and dst constrained
    uint16_t action_idx;           // index into l2_actions[]
    uint16_t _tail_pad;            // hold sizeof at 16 B (matches §4.3 table)
};
static_assert(sizeof(L2CompoundEntry) == 16, "L2CompoundEntry layout drift");

// L4 compound entries mirror L2's pattern (D15): primary hash on the
// most-selective exact key, secondary filter_mask over the remaining
// L4 constraints.
//
// D29 — ICMP unification: §5.4 packs ICMP type into the dport slot
// and ICMP code into the sport slot of the compound key shape. Rules
// that match on ICMP code therefore reuse `want_src_port` for the
// expected code — no separate ICMP field exists in this struct. The
// `SRC_PORT` filter_mask bit means "verify the sport slot", whether
// the underlying L4 protocol is TCP/UDP (real source port) or ICMP
// (packed code value).
struct L4CompoundEntry {
    uint8_t  filter_mask;          // bits: SRC_PORT|TCP_FLAGS|VRF
    uint8_t  tcp_flags_want;
    uint8_t  tcp_flags_mask;
    uint8_t  _pad;
    uint16_t want_src_port;        // host order; ICMP: reused as code slot
    uint16_t action_idx;
    uint16_t _pad2;                // keeps sizeof a multiple of 4
}; // 10 bytes
static_assert(sizeof(L4CompoundEntry) == 10, "L4CompoundEntry layout drift");

struct alignas(64) Ruleset {
    // ---- L2 ----
    rte_hash*        l2_src_mac;        // key = uint64_t (MAC packed) → compound idx
    rte_hash*        l2_dst_mac;
    uint16_t*        l2_vlan_lut;       // [vlan_entries_max], 0xFFFF = miss
    uint16_t*        l2_ether_lut;      // folded-index direct table
    rte_hash*        l2_ether_full;     // fallback for arbitrary etypes
    L2CompoundEntry* l2_compound;       // arena of compound entries
    RuleAction*      l2_actions;
    uint32_t         n_l2_rules;

    // ---- L3 ----
    rte_fib*         l3_v4;             // dst-prefix primary (DIR-24-8)
    rte_fib*         l3_v4_src;         // optional src-prefix secondary
    rte_fib6*        l3_v6;
    rte_fib6*        l3_v6_src;
    rte_hash*        l3_vrf;            // vrf_id → action_idx
    RuleAction*      l3_actions;
    uint32_t         n_l3_rules;

    // ---- L4 (D15: compound primary + filter_mask pattern) ----
    //
    // Primary hashes, probed in selectivity order:
    //   l4_proto_dport   key = (proto << 16) | dport          // most common
    //   l4_proto_sport   key = (proto << 16) | sport          // rare
    //   l4_proto_only    key = proto                          // catch-all
    //
    // Each primary hit returns an index into l4_compound[]; that entry
    // carries a filter_mask for secondary exact fields (src_port,
    // tcp_flags, icmp_code, vrf …).
    rte_hash*        l4_proto_dport;
    rte_hash*        l4_proto_sport;
    rte_hash*        l4_proto_only;
    L4CompoundEntry* l4_compound;
    RuleAction*      l4_actions;
    uint32_t         n_l4_rules;

    // ---- Rate-limit ----
    // Ruleset-local table of RL actions indexed by the compiler-
    // assigned rl_index. Each entry carries the configured rate /
    // burst, the stable operator-assigned rule_id, and the dense
    // arena slot resolved at compile time (see §4.4, D1/D10). Hot
    // path indexes the per-lcore bucket row by .slot directly,
    // avoiding any per-packet hash lookup against id_to_slot.
    struct RlAction {
        uint32_t rule_id = 0;
        uint32_t slot = 0;              // dense [0, n_slots) row index in rl_arena
        uint64_t rate_bytes_per_sec = 0;
        uint64_t burst_bytes = 0;
    };
    // RlAction is non-trivially-default-constructible due to per-field
    // default initialisers (the `= 0` above); bulk initialisation must
    // use `std::fill_n(rs.rl_actions, cap, RlAction{})` or aggregate
    // init — never `memset`. Enforced by `-Werror=class-memaccess` on
    // release builds (M13 C0 chronic-fix).
    RlAction*        rl_actions;        // indexed by rl_index
    uint32_t         n_rl_actions;
    RateLimitArena*  rl_arena;          // pointer to the process-wide arena

    // ---- Default behavior / fragment policy ----
    uint8_t          default_action;    // ALLOW or DROP
    uint8_t          fragment_policy;   // L3_ONLY | DROP | ALLOW

    // ---- Generation metadata ----
    uint64_t         generation;
    uint64_t         compile_timestamp_ns;

    // ---- Rule-id set (for arena GC diff on reload) ----
    const uint32_t*  rule_id_set;
    uint32_t         n_rule_ids;
};
```

**Sizing of arenas (production target from §8.4):**

| Arena | Element | Count | Bytes |
|---|---|---|---|
| `l2_actions` | 20 B | 4 096 | ~80 KiB |
| `l2_compound` | 16 B | 4 096 | 64 KiB |
| `l3_actions` | 20 B | 4 096 | ~80 KiB |
| `l4_actions` | 20 B | 4 096 | ~80 KiB |
| `l4_compound` | 10 B | 4 096 | ~40 KiB |
| `rte_hash l2_src_mac` | n/a | 4 096 | ~256 KiB |
| `rte_hash l2_dst_mac` | n/a | 4 096 | ~256 KiB |
| `rte_fib v4` | n/a | 16 384 prefixes | ~64 MiB worst case |
| `rte_fib6 v6` | n/a | 16 384 prefixes | ~96 MiB worst case |
| `rte_hash l4_proto_dport` | n/a | 4 096 | ~256 KiB |
| `rte_hash l4_proto_sport` | n/a | 4 096 | ~256 KiB |
| `rte_hash l4_proto_only` | n/a | 256 | ~32 KiB |
| `rte_hash l3_vrf` | n/a | 256 | ~32 KiB |
| `l2_vlan_lut` | 2 B | 4 096 | 8 KiB |

Worst case footprint: ~160 MiB per live Ruleset. Two live rulesets
during reload: ~320 MiB. Plus the rate-limit arena (§4.4) which lives
outside the Ruleset, plus mempools (§8).

### 4.2 Per-lcore worker context

`N_PORTS_MAX` is a small compile-time upper bound on the number of
DPDK ports the worker may stage TX traffic to in a single burst
(redirect + mirror destinations). It is **not** a rule-scale
parameter (those live in the §3a `sizing` section per D6) — it
sizes a per-worker stack-resident array, not a heap pool, and
keeping it static lets the compiler unroll the burst-end drain
loops in §5.5. Production target: `N_PORTS_MAX = 16` (covers all
ports a single worker might TX to even in dense multi-NIC
deployments). Dev VM target: same value, the array footprint is
trivial. Defined in `include/pktgate/limits.h`.

`MAX_BURST` (the per-port staging buffer depth) tracks the EAL
burst size — compile-time constant, default 32, tunable via a
build-time define.

**D28 — Port TX-queue symmetry invariant.** Each worker uses its
own `ctx->qid` on *every* port it may send to — the primary egress
`port_b` and, for D16 staging, every `redirect_port` and
`mirror_port` referenced by any rule in the ruleset. There is no
per-destination queue-selection logic in the hot path (the
`redirect_drain` / `mirror_drain` loops in §5.5 call
`rte_eth_tx_burst(p, ctx->qid, …)` with the worker's own `qid`).

Therefore **every DPDK port registered by `eal_init` — regardless
of role — MUST be configured with at least `n_workers` TX queues**,
and queues `[0, n_workers)` must be owned one-per-worker. The
control thread enforces this at startup: the init sequence (§6.1)
rejects any `interface_roles` entry whose port cannot accept that
queue count, and hot reload refuses to install a rule with a
`redirect_port` / `mirror_port` whose target port does not satisfy
the invariant.

RX-queue count on the mirror / redirect destinations is
unconstrained — we never receive from them. This is a TX-only
symmetry requirement. The invariant is cheap (mirror / redirect
ports are low-volume; allocating n extra TX queues costs a few KiB
of descriptors per port), deterministic (no per-packet qid
selection or locking), and test-covered via the startup validator.

```cpp
struct alignas(64) WorkerCtx {
    // RX/TX
    uint16_t  port_a, port_b;
    uint16_t  qid;
    uint16_t  burst_size;       // 32 default

    // RCU
    rte_rcu_qsbr* qs;
    uint32_t      thread_id;

    // Note: NO 'active' field here. The active ruleset is a single
    // process-wide atomic (see §4.5) loaded once per burst.

    // Local stats (cache-line aligned, never shared)
    alignas(64) WorkerStats stats;

    // Per-port TX staging for REDIRECT (D16). Drained at burst end;
    // unsent mbufs are freed + counted.
    struct TxStage {
        rte_mbuf* buf[MAX_BURST];
        uint16_t  n;
    };
    TxStage   redirect_tx[N_PORTS_MAX];

    // Mirror staging, one slot per egress port (§5.5).
    TxStage   mirror_tx[N_PORTS_MAX];

    // Scratch for L3 bulk-batched FIB lookup
    uint32_t  l3v4_scratch[MAX_BURST];
    uint64_t  l3v4_nh_scratch[MAX_BURST];
};
```

### 4.3 Per-lcore rule counters (D3)

The full counting model is defined by the architecture; the phase
plan decides which export channels ship first (§10, §14).

```cpp
struct alignas(64) RuleCounter {
    uint64_t matched_packets;
    uint64_t matched_bytes;
    uint64_t drops;              // explicit drop action
    uint64_t rl_drops;           // rate-limit drops
    uint64_t _pad[4];
}; // exactly 64 B / 1 cache line

// n_rules_total = sizing.rules_per_layer_max * 3 at compile time
// (one block per layer, all sized to the L2/L3/L4 max so the index
// math is constant). Pulled from the sizing config ceiling at init
// so the per-lcore row is a fixed size for the lifetime of the
// process.
struct PerLcoreCounters {
    RuleCounter by_rule[n_rules_total];   // per-lcore array, zero atomics
};
```

**Counter indexing**. The (`layer`, `rule_id`) → row index mapping
is computed at ruleset compile time, not on the hot path. Each
`RuleAction` carries a `counter_slot ∈ [0, rules_per_layer_max)`
assigned by the compiler; the row for a hit is

```cpp
ctx->counters->by_rule[layer_base(L) + a->counter_slot]
```

where `layer_base(L2)=0`, `layer_base(L3)=M`, `layer_base(L4)=2M`,
and `M = sizing.rules_per_layer_max`. Constant index math, no
hash, no per-packet allocation. The slot is stable across reloads
for any rule whose operator-assigned `rule_id` survives — slot
reuse / GC mechanics for removed rules track the rate-limit arena
(§9.4).

**Counter zeroing on slot reuse**. When a rule_id disappears from
the ruleset, the §9.4 GC pass (after `rcu_synchronize`) walks the
removed rules and, for each, zeroes the `RuleCounter` row on
*every* lcore at index `layer_base(L) + counter_slot`. This is safe
because after synchronize no worker holds a reference to the old
ruleset, so the removed slot is guaranteed unreachable on the hot
path. A subsequent publish that reclaims the slot for a new rule
therefore starts with clean per-lcore rows — no counter values
leak between unrelated rules. The zeroing is cheap (~64 B × lcores
per removed rule); step 5b of the §9.4 GC sequence.

Additional per-lcore counters (`LcoreStats`):

- `cycles_per_burst_{sum,count}` (histogram feed)
- `packets_processed`
- `rx_queue_depth_samples`
- `l4_skipped_ipv6_extheader` (D20 / P8)
- `l4_skipped_ipv6_fragment_nonfirst` — D27, IPv6 fragment header
  with non-zero fragment offset; subsequent fragments cannot carry
  L4 headers, so the L4 stage is skipped. Distinct from
  `l4_skipped_ipv6_extheader` because the IPv6 first fragment with
  `frag_offset == 0` is **not** counted here — it walks through to
  L4 with `dyn->l4_extra = 8` (see §5.3 IPv6 block, §5.4).
- `redirect_dropped_total`
- `mirror_dropped_total`
- `idle_iters_total`
- `tag_pcp_noop_untagged_total` — TAG action with `pcp` rewrite
  on an untagged frame; the rewrite is a no-op (we do not insert a
  VLAN tag) but the event is counted so operators can spot
  mis-targeted TAG rules. See §5.5 TAG case.
- `dispatch_unreachable_total` — defensive counter from the
  `apply_action` switch defaults (§5.5 / §13 -Wswitch-enum). Should
  always read zero in a healthy build; non-zero indicates a state
  machine bug that bypassed the compile-time check.
- `pkt_truncated_total[where]` — D31, per-classifier-stage drops
  caused by length guards (`l2`, `l2_vlan`, `l3_v4`, `l3_v6`,
  `l3_v6_frag_ext`, `l4`). A length-guard miss free()s the mbuf
  and short-circuits the §5.5 dispatch via `TERMINAL_DROP`. Always
  per-lcore, never atomic. Surfaces malformed traffic and DoS
  shapes that try to land short headers in the parser.
- `qinq_outer_only_total` — D32, QinQ outer tag (0x88A8) was
  accepted as a single VLAN by the §5.2 fast path because the
  inner tag was either missing or unmatched. Distinct from
  `pkt_truncated_total[l2_vlan]` (which counts truncations under
  the QinQ outer header). Helps operators quantify real-world
  demand for full QinQ matching before committing to the feature.
- `pkt_multiseg_drop_total` — D39, a multi-segment mbuf reached
  `classify_l2` despite the port-init guarantee that RX scatter
  is disabled. Always expected to be zero; non-zero indicates a
  driver misbehaviour or a missing SCATTER-off enforcement and
  requires investigation. Route is `TERMINAL_DROP`.
- `pkt_frag_skipped_total{af}` — D40, IPv4 / IPv6 non-first
  fragment whose L4 stage was skipped under
  `fragment_policy=l3_only`. Keyed by address family (`v4`, `v6`).
  The IPv6 value MUST equal `l4_skipped_ipv6_fragment_nonfirst`
  (the latter stays as a named alias for backwards telemetry
  compatibility and is populated from the same bump site). Added
  for symmetry with D27 — IPv4 skip was previously silent.
- `pkt_frag_dropped_total{policy,af}` — D40, fragment drop under
  `fragment_policy=drop`. `policy` is always `"drop"` (kept as a
  label for forward compatibility with any future
  `fragment_policy=quarantine` or similar); `af` is `v4` / `v6`.
  Previously folded silently into `rule_matches_total{action=drop}`
  which made drop storms indistinguishable from normal drops.

All `PerLcoreCounters` fields (every `RuleCounter` row and every
`LcoreStats` scalar above) are written only by the owning lcore via
the `relaxed_bump` helper in `src/dataplane/lcore_counter.h`, which
expands to `__atomic_store_n(p, __atomic_load_n(p, __ATOMIC_RELAXED)
+ d, __ATOMIC_RELAXED)`. The telemetry thread (§10.1) reads via the
matching `__atomic_load_n(p, __ATOMIC_RELAXED)` in
`src/telemetry/snapshot.cpp`. Rationale: both sides must be atomic
for the C++ memory model (and TSan) to treat the access as
well-defined, but on x86-64 the single-writer RELAXED load+store
pair emits plain `mov; add; mov` with NO `lock` prefix and NO
cache-line ownership transfer — D1's "zero atomic RMW on the hot
path" prohibition targets `lock xadd` / CAS / `fetch_add`, not this
pattern. Counters never read cross-thread (pure per-lcore internal
state) may stay plain `++`. Aggregation is the telemetry thread's
job (§10).

### 4.4 Rate-limit arena (D1 / D10)

Rate-limit state lives **outside** the Ruleset so that surviving
rules keep their bucket state across reloads. Two-level mapping:

```
Ruleset::rl_actions[rl_index] → { rule_id, rate, burst }
RateLimitArena:  rule_id      → TokenBucket[RTE_MAX_LCORE]
```

```cpp
struct alignas(64) TokenBucket {
    uint64_t tokens;           // current tokens in bytes
    uint64_t last_refill_tsc;  // rte_rdtsc of last refill
    uint64_t dropped;          // per-lcore drop counter
    uint64_t _pad[5];
}; // 64 B cache line, cache-isolated

struct TokenBucketRow {
    TokenBucket per_lcore[RTE_MAX_LCORE];
};

struct RateLimitArena {
    // Dense row array indexed by `slot` ∈ [0, n_slots). Sized at
    // init from sizing.rate_limit_rules_max and never resized for
    // the lifetime of the process. A row is "live" while some
    // active ruleset references its slot via RlAction.slot;
    // otherwise the slot is free for reuse.
    TokenBucketRow* rows;       // rows[slot]: bucket state for a live slot
    uint8_t*        slot_live;  // 1 = live, 0 = free; cold map for the compiler
    uint32_t        n_slots;

    // Compiler-side index: rule_id → slot. Survives across reloads
    // so the same operator-assigned rule_id keeps its bucket state
    // until the rule is removed (or its slot is freed by GC). The
    // hot path NEVER touches this table — RlAction.slot is the only
    // accessor used per packet.
    rte_hash*       id_to_slot;
};

// Hot path (§5.5 RL action):
const auto& rl  = rs->rl_actions[a->rl_index];
auto*       row = &rl_arena->rows[rl.slot];      // O(1), no hash lookup
auto&       b   = row->per_lcore[rte_lcore_id()];
uint64_t    now     = rte_rdtsc();

// D34 — clamp `elapsed` to one second of TSC. After a long idle
// (no traffic on this lcore for many seconds, lcore freshly
// brought up, or first hit on a new bucket where last_refill_tsc
// is zero) the raw delta times rate_bytes_per_sec overflows the
// 64-bit `refill_bytes` multiply. The bucket is also capped at
// burst_bytes anyway, so any clamp ≥ "time to fill burst" is
// equivalent to no clamp for steady-state correctness; one second
// is comfortably above the worst-case burst-fill time at any
// realistic per-lcore rate. Zero special-case for fresh buckets
// (b.last_refill_tsc == 0) is folded into the same clamp.
uint64_t    raw     = now - b.last_refill_tsc;
uint64_t    elapsed = raw > rte_get_tsc_hz() ? rte_get_tsc_hz() : raw;

uint64_t    refill_bytes = elapsed * rl.rate_bytes_per_sec
                          / rte_get_tsc_hz() / n_active_lcores;
b.tokens                 = min(b.tokens + refill_bytes, rl.burst_bytes);
b.last_refill_tsc        = now;
if (b.tokens < pkt_len) { b.dropped++; return DROP; }
b.tokens                -= pkt_len;
return PASS;
```

Per-lcore bucket, cache-line isolated. Lazy refill via `rte_rdtsc`
delta. **Zero atomics on the hot path.** (The `b.dropped++` above is
pseudocode clarity — in the real apply_action RL case (§5.5) this
is written as `relaxed_bump(&b.dropped)` per the §4.3 invariant, so
the publisher thread's matching `__atomic_load_n(…, __ATOMIC_RELAXED)`
has a well-defined pair. Semantically identical on x86-64; codegen
is still `mov; inc; mov` with no `lock` prefix.) A rule's aggregate
rate is
split across active lcores as `rate / n_active_lcores` at publish
time. Skewed RSS distributions therefore tolerate ~10–20 % aggregate
error; for flood-protection rate-limit (which is what the customer
wants — throughput > accuracy) this is acceptable.

**Arena footprint**: 64 B × RTE_MAX_LCORE × rate_limit_rules_max.
Production target (128 lcore × 4096 rules) ≈ 32 MiB. Dev default
(4 × 256) is trivial.

**Slot lifecycle**. Slots are allocated by the compiler during
ruleset build, not during steady-state operation:

1. **First publish of a rule_id** — compiler calls
   `rl_arena_alloc_slot(rule_id)`. The arena consults `id_to_slot`;
   if no entry, it picks a free index from `slot_live`, marks it
   live, zero-initializes `rows[slot]`, and inserts the
   `rule_id → slot` mapping. The new RlAction record carries `slot`.
2. **Rule_id present in both old and new ruleset** — compiler
   reuses the existing slot. Bucket state survives the reload
   verbatim (the desirable property — operator-stable rule_id
   means stable rate-limit history).
3. **Rule_id removed** — handled by the §9.4 GC pass after
   `rcu_synchronize`. The arena drops the `id_to_slot` entry,
   clears `slot_live[slot]`, and the slot becomes available for
   reuse on the next publish. No row free / realloc — the row
   memory stays in place to keep the arena footprint flat.
4. **Slot reuse** — a freshly freed slot may be claimed by a
   different rule_id on a subsequent reload. The compiler
   zero-initializes the row at allocation time (step 1), so a
   reused slot starts with empty buckets — no stale tokens leak
   between unrelated rules.

The hot path never sees any of this. RlAction.slot is fixed for
the lifetime of the ruleset that contains it; rulesets are
swapped under RCU, so once a worker has loaded the active ruleset
into its local `rs`, the slot index is stable for the duration of
its burst.

**Arena GC on reload** (D11): see §9.4. Slots for rules removed in
the new ruleset are released after `rcu_synchronize`.

### 4.5 Process-wide ruleset pointer (D9)

```cpp
struct alignas(64) ControlPlaneState {
    alignas(64) _Atomic(const Ruleset*) g_active;
    RateLimitArena*                     rl_arena;
    rte_rcu_qsbr*                       qs;
    int                                 cp_socket_id;

    // D1 Variant A divisor — number of dataplane lcores currently
    // polling. Set once by the control thread at EAL bring-up
    // (§6.1), read by the RL hot path (§5.5) and rl_arena refill
    // (§4.4). Treated as read-only after init; if the worker count
    // ever becomes dynamic this promotes to an acquire-load.
    uint32_t                            n_active_lcores;

    // D35: single reload-path mutex. ALL entry points that call
    // deploy() (inotify, cmd_socket UDS reload verb, future push
    // channels) acquire this around the whole compile / publish /
    // GC pipeline. By construction g_active has exactly one writer
    // at a time. (Spec'd in §9.2 + §10.7; field declared here.)
    pthread_mutex_t                     reload_mutex;

    // D36: deferred-free queue for the reload-timeout path. The
    // bounded reload check in §9.2 cannot block forever, so on
    // timeout we leave rs_new published and stash rs_old here for
    // a later successful check to drain. Bounded depth K_PENDING:
    // on overflow the next reload is refused (`reload_total{result=
    // "pending_full"}`) and a watchdog alert fires — that condition
    // means the dataplane is wedged, not a transient hiccup.
    // Capacity at the production target: K_PENDING = 8 (each
    // entry is one Ruleset pointer; the actual rulesets stay
    // alive in their own NUMA-local heap until drain).
    static constexpr size_t K_PENDING = 8;
    const Ruleset*                      pending_free[K_PENDING];
    size_t                              pending_free_n;

    // … control-thread state
};

// single process-wide instance
ControlPlaneState g_cp;
```

The `pending_free` queue is operated by two helpers used in §9.2:

```cpp
// Called under reload_mutex on the timeout path. Pushes the orphan
// ruleset onto the FIFO. Caller checks the return; on overflow the
// reload is refused.
bool pending_free_push(ControlPlaneState* cp, const Ruleset* rs) {
    if (cp->pending_free_n >= cp->K_PENDING) return false;
    cp->pending_free[cp->pending_free_n++] = rs;
    return true;
}

// Called under reload_mutex after any successful rte_rcu_qsbr_check.
// That check covers every pointer published before its token, so
// every queued ruleset is now safe to free.
void pending_free_drain(ControlPlaneState* cp) {
    for (size_t i = 0; i < cp->pending_free_n; ++i)
        ruleset_destroy(cp->pending_free[i]);
    cp->pending_free_n = 0;
}
```

Drain is **all-or-nothing per call**: a successful check after a
publish covers all earlier publishes too, so we never partially
drain. The fallback (overflow → reload refused → operator alert) is
the explicit "dataplane wedged" backstop, not a silent leak.

There is exactly **one** `g_active` for the entire process. The hot
path loads it once at the top of each burst with
`memory_order_acquire` into a local `const Ruleset* rs`, uses that
local for the whole burst, and drops it at burst end (natural
release). The writer publishes via a single
`atomic_exchange_explicit(&g_cp.g_active, rs_new, …)` followed by
`rte_rcu_qsbr_synchronize`. This is the textbook QSBR pattern.

Rationale for single global instead of per-lcore slots:

- Broadcast to N per-lcore slots would need N exchanges plus a
  non-trivial fence sequence.
- A globally-shared read-only pointer is cold-read once per burst
  (~5 µs at line rate), lives in a single shared-read cache line,
  and is never bounced — zero contention.
- Matches the reference QSBR pattern in the `rte_rcu_qsbr` docs.

## 5. Hot path walkthrough

This is the load-bearing section. The worker loop runs uninterrupted
on a pinned lcore.

```
           ┌─ WorkerCtx (in L1)
           │
   ┌───────▼──────────┐
   │ rte_rcu_qsbr_qs  │  ← publish quiescent state at top of every burst
   └───────┬──────────┘
           │
   ┌───────▼──────────┐
   │ acquire-load     │  ← const Ruleset* rs = g_cp.g_active
   └───────┬──────────┘
           │
   ┌───────▼──────────┐
   │ rte_eth_rx_burst │  ← up to BURST mbufs from port_a queue qid
   └───────┬──────────┘
           │
   ┌───────▼──────────┐
   │ prefetch headers │  ← rte_prefetch0 on the next 8
   └───────┬──────────┘
           │
   ┌───────▼──────────┐
   │ classify L2      │  ← per-mbuf, fills dynfield with l3_offset etc.
   └───────┬──────────┘
           │ if not terminal
   ┌───────▼──────────┐
   │ classify L3      │
   └───────┬──────────┘
           │ if not terminal
   ┌───────▼──────────┐
   │ classify L4      │
   └───────┬──────────┘
           │
   ┌───────▼──────────┐
   │ apply actions    │  ← drop/mirror/tag/rl/redirect; stage TX bufs
   └───────┬──────────┘
           │
   ┌───────▼──────────┐
   │ drain TX stages  │  ← port_b tx, mirror tx, redirect tx (per port)
   └───────┬──────────┘
           │
   ┌───────▼──────────┐
   │ free unsent      │  ← rte_pktmbuf_free_bulk
   └───────┬──────────┘
           │
           └─► loop
```

### 5.1 Pseudocode

```cpp
// mbuf dynfield, registered once at init:
//   uint16_t verdict_action_idx;  // index into the layer's action arena
//   uint8_t  verdict_layer;       // which layer matched (TERMINAL_* / NEXT_*)
//   uint8_t  l3_offset;           // byte offset from frame start to L3 header (D13)
//   uint8_t  parsed_l3_proto;     // cached after L3 parse
//   uint8_t  flags;               // L4_UNCLASSIFIABLE, SKIP_L4, …
//   uint8_t  l4_extra;             // extra bytes past the fixed L3 header
//                                  // to the L4 start (D27: 8 for IPv6
//                                  // first fragments, 0 otherwise)
//   uint16_t parsed_l4_dport;
//   uint16_t parsed_l4_sport;
//   uint16_t parsed_vlan;         // 0xFFFF if untagged
//   uint16_t parsed_ethertype;    // inner ethertype after any VLAN strip
// total = 16 B, fits in one 16 B dynfield slot exactly.

void worker_main(WorkerCtx* ctx) {
    rte_rcu_qsbr_thread_register(ctx->qs, ctx->thread_id);
    rte_rcu_qsbr_thread_online(ctx->qs, ctx->thread_id);

    rte_mbuf* rx[BURST];
    while (likely(running)) {
        // (1) Quiescent state — tells the writer this thread has no Ruleset ref
        rte_rcu_qsbr_quiescent(ctx->qs, ctx->thread_id);

        // (2) Acquire-load the single global
        const Ruleset* rs = atomic_load_explicit(
            &g_cp.g_active, memory_order_acquire);

        // (3) RX
        uint16_t n = rte_eth_rx_burst(ctx->port_a, ctx->qid, rx, BURST);
        if (n == 0) { handle_idle(ctx); continue; }

        // (4) Prefetch first 8 packet headers
        for (uint16_t i = 0; i < min<uint16_t>(n, 8); i++)
            rte_prefetch0(rte_pktmbuf_mtod(rx[i], void*));

        // (5) Layer 2 classify (always runs). D31: classify_*
        // take ctx so they can bump pkt_truncated on a length
        // guard miss; on miss they set verdict_layer =
        // TERMINAL_DROP and the §5.5 dispatcher routes the
        // packet to free without further parsing.
        for (uint16_t i = 0; i < n; i++) {
            if (i + 8 < n) rte_prefetch0(rte_pktmbuf_mtod(rx[i+8], void*));
            classify_l2(ctx, rs, rx[i]);
        }

        // (6) Layer 3 classify (only those that proceeded)
        for (uint16_t i = 0; i < n; i++) {
            if (mbuf_dyn(rx[i])->verdict_layer == NEXT_L3)
                classify_l3(ctx, rs, rx[i]);
        }

        // (7) Layer 4 (skipped for L4_UNCLASSIFIABLE packets)
        for (uint16_t i = 0; i < n; i++) {
            if (mbuf_dyn(rx[i])->verdict_layer == NEXT_L4 &&
                !(mbuf_dyn(rx[i])->flags & SKIP_L4))
                classify_l4(ctx, rs, rx[i]);
        }

        // (8) Apply actions — stages into per-port TX / mirror / redirect bufs
        for (uint16_t i = 0; i < n; i++)
            apply_action(ctx, rs, rx[i]);

        // (9) Drain TX stages
        tx_drain(ctx);                // port_b primary TX
        mirror_drain(ctx);            // per-port mirror TX
        redirect_drain(ctx);          // per-port redirect TX (D16)
    }

    rte_rcu_qsbr_thread_offline(ctx->qs, ctx->thread_id);
    rte_rcu_qsbr_thread_unregister(ctx->qs, ctx->thread_id);
}
```

**`handle_idle(ctx)` specification (D19)**: tight busy-check. On an
empty RX burst the worker bumps an idle-iteration counter, continues
the loop, and after ~16 consecutive empty polls yields briefly to
let the CPU cool (`rte_pause()` or equivalent). **Crucially it does
NOT call `rte_rcu_qsbr_thread_offline`.** A worker that goes offline
without announcing would hang a concurrent reload's
`synchronize`. The worker stays online and keeps publishing quiescent
state every (even empty) iteration. This is **explicitly** the
required behaviour — reload progress during idle windows depends on
it (D12 / D30 bounded-sync path would otherwise stall for the full
deadline in any no-traffic window).

**Headers-in-first-seg invariant (D39).** Every classifier stage
below (`classify_l2` / `classify_l3` / `classify_l4`) reads packet
headers through `rte_pktmbuf_mtod[_offset]`, which linearly reads
**the first mbuf segment only**. D31 length guards check
`m->pkt_len`, which covers the full chain, so a chained mbuf with a
header straddling a segment boundary would pass the guard but read
undefined memory. D39 closes this structurally: the architecture
requires `m->nb_segs == 1` at classifier entry and refuses any
port configuration where the RX mempool segment size cannot hold
the largest admissible frame.

Runtime: `classify_l2` asserts `m->nb_segs == 1` under
`RTE_ASSERT` in debug builds; release builds rely on the port-init
guarantee (see §6.1). If the invariant is ever observed to fail in
production (counter `pkt_multiseg_drop_total`), the packet is
routed to `TERMINAL_DROP` — same path as truncation. Relaxing the
single-segment requirement is a structural change (switching the
classifier read path to `rte_pktmbuf_read` or equivalent) and
would require reopening D39 before it could be considered.

### 5.2 Layer 2 classifier

```cpp
static inline void classify_l2(WorkerCtx* ctx, const Ruleset* rs,
                               rte_mbuf* m) {
    auto* dyn  = mbuf_dyn(m);
    dyn->flags = 0;

    // D39 — headers-in-first-seg invariant. Port-init enforces
    // SCATTER=off and that the mempool element holds the largest
    // admissible frame, so a chained mbuf here is a driver bug.
    // Debug builds abort; release builds route to TERMINAL_DROP and
    // bump a dedicated counter so the anomaly is visible in metrics.
    RTE_ASSERT(m->nb_segs == 1);
    if (unlikely(m->nb_segs != 1)) {
        ctx_stats_bump_pkt_multiseg_drop(ctx);
        dyn->verdict_layer = TERMINAL_DROP;
        return;
    }

    // D31 — explicit length guard. The fast path will read 14 B
    // (ether) and possibly 4 more (VLAN) before any matching, so
    // a runt packet ≤ 13 B would otherwise be UB. We free the mbuf
    // and short-circuit via TERMINAL_DROP; §5.5 routes it to free
    // without further parsing. Counter is per-lcore (D31).
    if (unlikely(m->pkt_len < sizeof(rte_ether_hdr))) {
        ctx_stats_bump_pkt_truncated(ctx, "l2");
        dyn->verdict_layer = TERMINAL_DROP;
        return;
    }
    auto* eth = rte_pktmbuf_mtod(m, rte_ether_hdr*);

    uint16_t etype = eth->ether_type;
    uint16_t vlan  = 0xFFFF;
    uint8_t  pcp   = 0;
    uint8_t  l3_off = sizeof(rte_ether_hdr);  // 14

    // D32 — accept BOTH 0x8100 (single VLAN / inner C-tag) and
    // 0x88A8 (S-tag, QinQ outer) here. The first-phase parser
    // walks ONE tag and then treats the next ethertype as L3 — if
    // the next ethertype is itself 0x8100/0x88A8 (true QinQ stack)
    // we still do not drill the inner C-tag in this phase, but the
    // outer S-tag is recognized so its packets are not dropped as
    // "unknown ethertype" by downstream logic. Bumps
    // qinq_outer_only_total whenever we exit with the outer tag
    // consumed but the inner ethertype is *another* VLAN type;
    // operators use that counter to quantify real-world demand for
    // full QinQ matching before committing to the feature.
    bool is_vlan_tpid =
        (etype == RTE_BE16(RTE_ETHER_TYPE_VLAN)) ||
        (etype == RTE_BE16(RTE_ETHER_TYPE_QINQ));   // 0x88A8
    if (is_vlan_tpid) {
        // D31 — need 4 more bytes for the VLAN tag.
        if (unlikely(m->pkt_len <
                     sizeof(rte_ether_hdr) + sizeof(rte_vlan_hdr))) {
            ctx_stats_bump_pkt_truncated(ctx, "l2_vlan");
            dyn->verdict_layer = TERMINAL_DROP;
            return;
        }
        auto* vh = (rte_vlan_hdr*)(eth + 1);
        uint16_t tci = rte_be_to_cpu_16(vh->vlan_tci);
        vlan   = tci & 0x0FFF;
        pcp    = (tci >> 13) & 0x7;
        etype  = vh->eth_proto;                 // inner ethertype
        l3_off = sizeof(rte_ether_hdr) + sizeof(rte_vlan_hdr); // 18

        // D32 — true QinQ stack (S-tag then C-tag, or two C-tags).
        // We do NOT walk the inner tag in this phase; the inner
        // ethertype is unknown to downstream classifiers, so we
        // mark the event and proceed with L4 unclassifiable. L2
        // and L3 still run normally on the outer key.
        if (unlikely(etype == RTE_BE16(RTE_ETHER_TYPE_VLAN) ||
                     etype == RTE_BE16(RTE_ETHER_TYPE_QINQ))) {
            ctx_stats_bump_qinq_outer_only(ctx);
        }
    }

    dyn->parsed_vlan      = vlan;
    dyn->parsed_ethertype = etype;
    dyn->l3_offset        = l3_off;    // D13: record once, reuse in L3/L4

    // Selectivity order: src_mac > dst_mac > vlan > ethertype > pcp.
    // Try the most-selective primary first; on hit, validate filter_mask.
    uint64_t src_key = mac_to_u64(eth->src_addr);
    uint64_t dst_key = mac_to_u64(eth->dst_addr);

    L2CompoundEntry* e;
    int idx;

    if ((idx = rte_hash_lookup(rs->l2_src_mac, &src_key)) >= 0) {
        e = &rs->l2_compound[idx];
        if (l2_secondary_ok(e, dst_key, vlan, etype, pcp))
            { dispatch_l2(rs, m, e); return; }
    }
    if ((idx = rte_hash_lookup(rs->l2_dst_mac, &dst_key)) >= 0) {
        e = &rs->l2_compound[idx];
        if (l2_secondary_ok(e, src_key, vlan, etype, pcp))
            { dispatch_l2(rs, m, e); return; }
    }
    if (vlan != 0xFFFF) {
        uint16_t ai = rs->l2_vlan_lut[vlan];
        if (ai != 0xFFFF) {
            e = &rs->l2_compound[ai];
            if (l2_secondary_ok(e, src_key, vlan, etype, pcp))
                { dispatch_l2(rs, m, e); return; }
        }
    }
    // ethertype direct + fallback hash, then pcp — same pattern.

    // L2 miss → proceed to L3
    dyn->verdict_layer = NEXT_L3;
}
```

**D4 hw-offload hook at the top of classify** — runs before the
software lookups when the NIC has already classified the packet:

```cpp
if (unlikely(m->ol_flags & RTE_MBUF_F_RX_FDIR_ID)) {
    // NIC classifier has tagged the packet; the FDIR id is the
    // sw rule id. We still verify the rule is live in rs (it must
    // be — hw rules are only installed after publish) and dispatch.
    uint32_t rid = m->hash.fdir.hi;
    if (auto ai = rs->hw_id_to_action_idx.get(rid); ai) {
        dispatch_preclassified(rs, m, *ai);
        return;
    }
    // Mark mismatch fell through to software; counts toward a debug
    // metric. Software classification continues normally.
}
```

**QinQ inner-garbage path (D32 / Q3 clarification).** When the
outer tag is consumed and the inner ethertype is **not** another
VLAN TPID and **not** a recognised L3 ethertype (IPv4 / IPv6), the
L2 stage still records `parsed_ethertype = <inner value>` and
`l3_offset = 18`, and hands off to §5.3 via `NEXT_L3`. §5.3 then
falls through its IPv4 / IPv6 branches and terminates with
`TERMINAL_PASS`, so the packet is handed to §5.5 for the
default-behaviour verdict. No new counter: the drop (if any) is
charged to `default_action_total`, and the L2 stage's
`qinq_outer_only_total` bump only fires when the inner *is*
another VLAN TPID. This is deliberate — the outer-only counter
is a demand signal for full QinQ matching, and firing it on
random inner garbage would pollute that signal.

### 5.3 Layer 3 classifier

```cpp
static inline void classify_l3(WorkerCtx* ctx, const Ruleset* rs,
                               rte_mbuf* m) {
    auto*    dyn    = mbuf_dyn(m);
    uint8_t  l3_off = dyn->l3_offset;
    uint16_t et     = dyn->parsed_ethertype;

    // --------- IPv4 ---------
    if (et == RTE_BE16(RTE_ETHER_TYPE_IPV4)) {
        // D31 — need 20 B fixed IPv4 header before any header
        // read. We deliberately reject IHL<5 packets here too,
        // since the §5.4 IHL-driven L4 offset would otherwise
        // produce a bogus l4off value. (LOW finding from the
        // 5-lawyer pass: explicit IHL reject.)
        if (unlikely(m->pkt_len < l3_off + sizeof(rte_ipv4_hdr))) {
            ctx_stats_bump_pkt_truncated(ctx, "l3_v4");
            dyn->verdict_layer = TERMINAL_DROP;
            return;
        }
        auto* ip = rte_pktmbuf_mtod_offset(m, rte_ipv4_hdr*, l3_off);
        if (unlikely((ip->version_ihl & 0x0F) < 5)) {
            ctx_stats_bump_pkt_truncated(ctx, "l3_v4");  // bad IHL
            dyn->verdict_layer = TERMINAL_DROP;
            return;
        }

        // --- Fragment handling (D17, per-config fragment_policy) ---
        bool is_frag =
            (ip->fragment_offset & RTE_BE16(0x1FFF)) != 0 ||
            (ip->fragment_offset & RTE_BE16(0x2000)) != 0; // MF set on first frag
        bool is_nonfirst = (ip->fragment_offset & RTE_BE16(0x1FFF)) != 0;

        if (unlikely(is_frag)) {
            switch (rs->fragment_policy) {
            case FRAG_DROP:
                // D40: explicit per-lcore counter for fragment drops.
                ctx_stats_bump_pkt_frag_dropped(ctx, "drop", "v4");
                dyn->verdict_layer = TERMINAL_DROP;
                return;
            case FRAG_ALLOW:
                dyn->verdict_layer = TERMINAL_PASS;
                return;
            case FRAG_L3_ONLY:
                if (is_nonfirst) {
                    // No reliable L4 header. Mark packet
                    // L4-unclassifiable; L3 rules still apply.
                    // D40 — observable symmetry with IPv6 (D27).
                    dyn->flags |= SKIP_L4;
                    ctx_stats_bump_pkt_frag_skipped(ctx, "v4");
                }
                break;  // fall through to L3 matching
            }
        }

        // L3 lookup: dst-prefix primary.
        // The compiler picks dst over src as the primary FIB (dst
        // prefix tries are more discriminating in operator traffic).
        // Compound L3 rules (src+dst, or VRF+IP) carry secondary
        // constraints in the action descriptor for post-lookup
        // verification.
        // D30: rte_fib does NOT export a single-entry public lookup;
        // only rte_fib_lookup_bulk(fib, addrs, nh, n) exists. We pass
        // n=1 here. D19 already noted that a true bulk-over-burst
        // call is faster — that is the §5.1 batched-loop direction;
        // the per-packet form below is the architectural default.
        uint32_t da = rte_be_to_cpu_32(ip->dst_addr);
        uint64_t nh = FIB_DEFAULT_NH;
        rte_fib_lookup_bulk(rs->l3_v4, &da, &nh, 1);
        if (nh != FIB_DEFAULT_NH &&
            l3_secondary_ok(rs, (uint16_t)nh, ip)) {
            dispatch_l3(rs, m, (uint16_t)nh);
            return;
        }
        // Optional src-prefix FIB (only populated if any rule keys
        // solely on src-prefix; otherwise l3_v4_src is nullptr).
        if (rs->l3_v4_src) {
            uint32_t sa = rte_be_to_cpu_32(ip->src_addr);
            nh = FIB_DEFAULT_NH;
            rte_fib_lookup_bulk(rs->l3_v4_src, &sa, &nh, 1);
            if (nh != FIB_DEFAULT_NH &&
                l3_secondary_ok(rs, (uint16_t)nh, ip)) {
                dispatch_l3(rs, m, (uint16_t)nh);
                return;
            }
        }

        dyn->parsed_l3_proto = ip->next_proto_id;

        // L3 miss. If SKIP_L4 is set (non-first fragment under
        // FRAG_L3_ONLY), L4 cannot run — terminate at L3 and let
        // §5.5 apply default_action via TERMINAL_PASS. Otherwise
        // hand off to L4 classification.
        dyn->verdict_layer = (dyn->flags & SKIP_L4) ? TERMINAL_PASS : NEXT_L4;
        return;
    }

    // --------- IPv6 ---------
    if (et == RTE_BE16(RTE_ETHER_TYPE_IPV6)) {
        // D31 — need 40 B fixed IPv6 header before reading proto.
        if (unlikely(m->pkt_len < l3_off + sizeof(rte_ipv6_hdr))) {
            ctx_stats_bump_pkt_truncated(ctx, "l3_v6");
            dyn->verdict_layer = TERMINAL_DROP;
            return;
        }
        auto* ip6 = rte_pktmbuf_mtod_offset(m, rte_ipv6_hdr*, l3_off);
        uint8_t nxt      = ip6->proto;
        uint8_t l4_extra = 0;        // D27 — extra bytes past the fixed
                                     // 40 B L3 header before L4 starts

        // The architecture recognizes two variants of IPv6 parsing:
        //   (a) first-protocol-only (shown here) — treat next_header
        //       as the L4 protocol directly, with ONE exception: a
        //       Fragment extension header (44) is walked by eight
        //       bytes on the first fragment so that L3_ONLY / ALLOW
        //       policies still reach the L4 header that IS present.
        //       See D27.
        //   (b) full extension-header chain walking up to K hops.
        // §14 selects which variant is enabled per shipping phase.
        //
        // Extension header values split by range:
        //   < 64: hop-by-hop=0, routing=43, ESP=50, AH=51,
        //         destination-options=60 — packed into a 64-bit
        //         mask for branch-free testing.
        //   ≥ 64: mobility=135, HIP=139, shim6=140,
        //         experimental=253/254 — listed explicitly. Putting
        //         these in the mask would be UB (`1ull << 135`
        //         shifts past the operand width; compilers reduce
        //         the count mod 64 and silently flip an unrelated
        //         bit). They are rare enough that an OR chain costs
        //         nothing.
        //
        // Fragment (44) is deliberately NOT in the mask — D27
        // handles it as a special case so the first-fragment L4
        // header is reachable. A non-first fragment still hits
        // SKIP_L4.
        static const uint64_t EXT_MASK_LT64 =
            (1ull<<0)|(1ull<<43)|(1ull<<50)|(1ull<<51)|(1ull<<60);
        auto is_ext_proto = [](uint8_t p) {
            return (p < 64 && ((1ull << p) & EXT_MASK_LT64)) ||
                    p == 135 || p == 139 || p == 140 ||
                    p == 253 || p == 254;
        };

        if (unlikely(is_ext_proto(nxt))) {
            // Any non-fragment extension header → L4 unreachable
            // under first-protocol-only; L3 still runs.
            dyn->flags |= SKIP_L4;
            ctx_stats_bump_l4_skipped_ipv6_extheader();
        } else if (unlikely(nxt == 44)) {
            // D27 — Fragment extension header. Read the 8-byte
            // fragment header to differentiate first fragment
            // (offset == 0, carries L4) from subsequent (no L4).
            //
            // D31 — need 8 more bytes past the IPv6 fixed header
            // before reading fh. A truncated fragment-ext header
            // is dropped (we cannot tell first vs non-first).
            if (unlikely(m->pkt_len < l3_off + sizeof(rte_ipv6_hdr) +
                                      sizeof(rte_ipv6_fragment_ext))) {
                ctx_stats_bump_pkt_truncated(ctx, "l3_v6_frag_ext");
                dyn->verdict_layer = TERMINAL_DROP;
                return;
            }
            auto* fh = rte_pktmbuf_mtod_offset(
                m, rte_ipv6_fragment_ext*,
                l3_off + sizeof(rte_ipv6_hdr));
            uint16_t frag_data   = rte_be_to_cpu_16(fh->frag_data);
            uint16_t frag_offset = frag_data & 0xFFF8;  // 13-bit × 8
            bool     is_first    = (frag_offset == 0);

            switch (rs->fragment_policy) {
            case FRAG_DROP:
                // D40: explicit per-lcore counter for fragment drops.
                ctx_stats_bump_pkt_frag_dropped(ctx, "drop", "v6");
                dyn->verdict_layer = TERMINAL_DROP;
                return;
            case FRAG_ALLOW:
                dyn->verdict_layer = TERMINAL_PASS;
                return;
            case FRAG_L3_ONLY:
                if (is_first) {
                    // First fragment carries the transport header;
                    // drill through exactly one step to reach it.
                    nxt      = fh->next_header;
                    l4_extra = sizeof(rte_ipv6_fragment_ext);  // 8
                    // If fh->next_header is itself an extension
                    // header we do NOT walk further under
                    // first-protocol-only: set SKIP_L4 instead.
                    if (unlikely(is_ext_proto(nxt) || nxt == 44)) {
                        dyn->flags |= SKIP_L4;
                        ctx_stats_bump_l4_skipped_ipv6_extheader();
                    }
                } else {
                    // Non-first fragment: no L4 header available
                    // in this datagram fragment. L3 still applies.
                    dyn->flags |= SKIP_L4;
                    // D27 — the named backwards-compat counter.
                    ctx_stats_bump_l4_skipped_ipv6_fragment_nonfirst(ctx);
                    // D40 — the symmetric family-keyed counter; both
                    // are bumped at the same site.
                    ctx_stats_bump_pkt_frag_skipped(ctx, "v6");
                }
                break;
            }
        }

        dyn->parsed_l3_proto = nxt;        // P8/D20 first-proto-only + D27
        dyn->l4_extra        = l4_extra;    // consumed by §5.4

        // D30: same single-vs-bulk note as IPv4 above. n=1 form.
        uint64_t nh = FIB6_DEFAULT_NH;
        rte_fib6_lookup_bulk(rs->l3_v6, &ip6->dst_addr, &nh, 1);
        if (nh != FIB6_DEFAULT_NH &&
            l3_secondary_ok_v6(rs, (uint16_t)nh, ip6)) {
            dispatch_l3(rs, m, (uint16_t)nh);
            return;
        }
        if (rs->l3_v6_src) {
            nh = FIB6_DEFAULT_NH;
            rte_fib6_lookup_bulk(rs->l3_v6_src, &ip6->src_addr, &nh, 1);
            if (nh != FIB6_DEFAULT_NH &&
                l3_secondary_ok_v6(rs, (uint16_t)nh, ip6)) {
                dispatch_l3(rs, m, (uint16_t)nh);
                return;
            }
        }

        // L3 miss. SKIP_L4 may have been set above (extension header
        // present); in that case L4 cannot run, terminate at L3 with
        // TERMINAL_PASS so §5.5 applies default_action. Otherwise
        // proceed to L4.
        dyn->verdict_layer = (dyn->flags & SKIP_L4) ? TERMINAL_PASS : NEXT_L4;
        return;
    }

    // Not IP — terminal pass (default is applied later in dispatch)
    dyn->verdict_layer = TERMINAL_PASS;
}
```

**Architectural note on IPv6 extension headers**: the full
architecture recognizes and walks extension-header chains up to
some `K` hops, exposing each parsed next-protocol for L4 matching.
The code shown above is the first-protocol-only variant: packets
carrying any IPv6 extension header are marked L4-unclassifiable
and the counter `l4_skipped_ipv6_extheader` is bumped so operators
can measure demand for chain walking. The §14 phase plan decides
which variant is enabled in each shipping phase.

### 5.4 Layer 4 classifier (D15 — compound primary + filter mask)

```cpp
static inline void classify_l4(WorkerCtx* ctx, const Ruleset* rs,
                               rte_mbuf* m) {
    auto* dyn = mbuf_dyn(m);
    if (dyn->flags & SKIP_L4) {
        dyn->verdict_layer = TERMINAL_PASS;  // L3 verdict / default applies
        return;
    }

    uint8_t  proto = dyn->parsed_l3_proto;
    uint8_t  l3off = dyn->l3_offset;

    // D14: L4 header offset uses IHL for IPv4, fixed 40 B for IPv6
    // plus an optional D27 fragment-header extra (8 B for first IPv6
    // fragments under FRAG_L3_ONLY, 0 otherwise — §5.3 IPv6 block).
    uint8_t  l4off;
    if (dyn->parsed_ethertype == RTE_BE16(RTE_ETHER_TYPE_IPV4)) {
        auto* ip = rte_pktmbuf_mtod_offset(m, rte_ipv4_hdr*, l3off);
        l4off    = l3off + ((ip->version_ihl & 0x0F) << 2);
    } else { // IPv6
        l4off    = l3off + sizeof(rte_ipv6_hdr) + dyn->l4_extra;
    }

    // D31 — minimum bytes we'll read at l4off:
    //   TCP/UDP/SCTP: 4 B (src+dst port pair, big enough for the
    //                 unified compound key shape)
    //   ICMP/ICMPv6:  2 B (type+code)
    //   other:        0 (handled below as a no-op)
    uint16_t need = 0;
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP ||
        proto == IPPROTO_SCTP)         need = 4;
    else if (proto == IPPROTO_ICMP ||
             proto == IPPROTO_ICMPV6)  need = 2;

    if (unlikely(need && m->pkt_len < (uint32_t)l4off + need)) {
        ctx_stats_bump_pkt_truncated(ctx, "l4");
        dyn->verdict_layer = TERMINAL_DROP;
        return;
    }

    uint16_t sport = 0, dport = 0;
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP ||
        proto == IPPROTO_SCTP) {
        auto* l4 = rte_pktmbuf_mtod_offset(m, rte_udp_hdr*, l4off);
        sport = rte_be_to_cpu_16(l4->src_port);
        dport = rte_be_to_cpu_16(l4->dst_port);
    } else if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6) {
        auto* icmp = rte_pktmbuf_mtod_offset(m, uint8_t*, l4off);
        // ICMP type/code packed into the same slots as sport/dport
        // for a unified compound key shape.
        dport = icmp[0];
        sport = icmp[1];
    }
    dyn->parsed_l4_sport = sport;
    dyn->parsed_l4_dport = dport;

    // Selectivity-ordered probing against three primary hashes.
    uint32_t key_pd = ((uint32_t)proto << 16) | dport;
    int idx = rte_hash_lookup(rs->l4_proto_dport, &key_pd);
    if (idx >= 0) {
        auto* e = &rs->l4_compound[idx];
        if (l4_secondary_ok(e, sport, m))
            { dispatch_l4(rs, m, e); return; }
    }

    uint32_t key_ps = ((uint32_t)proto << 16) | sport;
    idx = rte_hash_lookup(rs->l4_proto_sport, &key_ps);
    if (idx >= 0) {
        auto* e = &rs->l4_compound[idx];
        if (l4_secondary_ok(e, dport, m))
            { dispatch_l4(rs, m, e); return; }
    }

    uint32_t key_p = proto;
    idx = rte_hash_lookup(rs->l4_proto_only, &key_p);
    if (idx >= 0) {
        auto* e = &rs->l4_compound[idx];
        if (l4_secondary_ok(e, sport, m))
            { dispatch_l4(rs, m, e); return; }
    }

    // L4 miss → terminal pass (default applies)
    dyn->verdict_layer = TERMINAL_PASS;
}
```

**Ranges**: the compound + filter_mask model handles exact matches
and `any` wildcards (the overwhelmingly common case in ISP filters),
and expanded port lists at compile time. True `src_port` /
`dst_port` *ranges* are not in the architecture's current L4 primary
tables. Ranges can be supported either via a second-tier linear scan
over "ranged L4 rules" or via ACL (`rte_acl`) — the architecture
leaves both doors open; the phase plan (§14) currently treats ranges
as a non-goal for the first shipping phase.

### 5.5 Action dispatch

```cpp
static inline void apply_action(WorkerCtx* ctx, const Ruleset* rs,
                                rte_mbuf* m) {
    auto*              dyn = mbuf_dyn(m);
    const RuleAction*  a;

    switch (dyn->verdict_layer) {
    case TERMINAL_L2: a = &rs->l2_actions[dyn->verdict_action_idx]; break;
    case TERMINAL_L3: a = &rs->l3_actions[dyn->verdict_action_idx]; break;
    case TERMINAL_L4: a = &rs->l4_actions[dyn->verdict_action_idx]; break;
    case TERMINAL_PASS:
        if (rs->default_action == ALLOW)
            stage_tx(ctx, ctx->port_b, m);
        else
            rte_pktmbuf_free(m);
        return;
    case TERMINAL_DROP:
        rte_pktmbuf_free(m);
        return;
    default:
        // Defensive belt-and-braces. NEXT_L2 / NEXT_L3 / NEXT_L4
        // must never reach apply_action — §5.1 routes those to
        // the next classifier instead. Build flags include
        // -Wswitch-enum (§13) so a future verdict variant added
        // without updating this switch is a compile error; the
        // default arm exists only as a runtime backstop in case
        // a state-machine bug slips past the warning.
        relaxed_bump(&ctx->stats.dispatch_unreachable_total);
        rte_pktmbuf_free(m);
        return;
    }

    counter_inc(ctx, dyn->verdict_layer, a->rule_id, m->pkt_len);

    switch (a->verb) {
    case ALLOW:
        stage_tx(ctx, ctx->port_b, m);
        return;

    case DROP:
        counter_drop(ctx, dyn->verdict_layer, a->rule_id);
        rte_pktmbuf_free(m);
        return;

    case REDIRECT: {
        // D16: stage into per-port redirect buffer; drained at
        // burst end with rte_eth_tx_burst, unsent mbufs freed and
        // counted as pktgate_redirect_dropped_total.
        stage_redirect(ctx, a->redirect_port, m);
        return;
    }

    case MIRROR: {
        // Architecture: two valid clone strategies, picked at COMPILE
        // time per Ruleset. The hot path does NOT branch on strategy
        // — mirror_clone is set once when the Ruleset is built.
        //
        //   (a) Deep copy via rte_pktmbuf_copy — universally safe;
        //       allocates a fresh mbuf, copies headers + payload.
        //   (b) Refcount zero-copy via rte_mbuf_refcnt_update — faster,
        //       but introduces a shared-buffer invariant: nothing
        //       between clone creation and DMA completion may mutate
        //       the mbuf data. See D26.
        //
        // D26 — Refcnt-mirror compile-time gate (in ruleset_builder):
        //
        //   use_refcnt_mirror :=
        //         config_requests_zero_copy
        //       ∧ ∀ rule ∈ ruleset : rule.verb ∉ MUTATING_VERBS
        //       ∧ driver_caps[mirror_port].tx_non_mutating
        //   else strategy := deep_copy
        //
        //   MUTATING_VERBS = { TAG }
        //     // TAG rewrites DSCP (IPv4 ToS / IPv6 TC byte) and PCP
        //     // (VLAN TCI byte) in place. Any new mutating verb (NAT,
        //     // header rewrite, ...) MUST be added to MUTATING_VERBS
        //     // or the gate will silently allow refcnt-mirror to
        //     // corrupt mirror destinations. Enforced by a unit test
        //     // that scans the verb enum and asserts every value is
        //     // classified mutating / non-mutating, paired with the
        //     // -Wswitch-enum coverage already in §13.
        //
        // Why per-ruleset (not per-packet): the verb-exclusivity
        // argument — "a packet hit by MIRROR is never hit by TAG in
        // the same dispatch" — is true for action match but does NOT
        // cover the future of the original mbuf. After clone, the
        // original goes through TX prepare, driver path, and possibly
        // HW-offload writeback; every byte the original ever sees is
        // also visible to the clone via the shared buffer. The gate
        // is therefore a conservative whole-ruleset property: easier
        // to reason about, easier to test, no per-packet cost.
        //
        // D7 currently rejects verb=mirror at publish-time (the
        // compiler refuses any ruleset that carries a mirror rule).
        // D26 governs the refcnt-mirror contract so that enabling
        // mirror later is additive, not structural — the hot path
        // already carries the correct strategy dispatch.
        rte_mbuf* clone = mirror_clone(m);  // strategy fixed at build
        if (likely(clone))
            stage_mirror(ctx, a->mirror_port, clone);
        stage_tx(ctx, ctx->port_b, m);
        return;
    }

    case TAG: {
        // D19: spelled-out semantics.
        //   DSCP lives in the IPv4 ToS byte / IPv6 traffic class field.
        //   PCP lives in the 802.1Q VLAN tag TCI; on untagged frames
        //   we DO NOT add a tag — PCP rewrite is a no-op and bumps
        //   a per-lcore counter (tag_pcp_noop_untagged_total).
        //
        // Checksum invariants:
        //   - IPv4 DSCP rewrite changes the ToS byte, which is part
        //     of the IPv4 header checksum. apply_dscp_pcp() does NOT
        //     incrementally update the cksum — instead it clears the
        //     current value, sets PKT_TX_IP_CKSUM in mbuf ol_flags,
        //     and lets the NIC recompute on TX (HW cksum offload is
        //     mandatory on all production target NICs: E810, XL710,
        //     CX5/6). A driver that lacks the capability is caught
        //     by the startup validator (§6.1) — a TAG rule against
        //     a port without HW ip-cksum is rejected at publish.
        //   - IPv6 has no L3 cksum, so TC byte rewrite is free.
        //   - VLAN TCI rewrite is in the L2 header, which carries no
        //     L2 checksum — no recompute needed.
        //   - L4 pseudo-header cksum is unaffected by DSCP/PCP
        //     rewrites (neither byte is part of the pseudo-header).
        apply_dscp_pcp(m, a->dscp, a->pcp);
        stage_tx(ctx, ctx->port_b, m);
        return;
    }

    case RL: {
        // D1/D10: per-lcore bucket, zero atomics.
        // Dense slot index resolved at compile time (§4.4); no
        // hash lookup on the hot path.
        //
        // Rate units: rl.rate_bytes_per_sec is already in bytes per
        // second (the JSON parser converts `"200Mbps"` → 25 000 000
        // B/s at schema load time, so `rate_bytes_per_sec = bps / 8`).
        // Packet length: we charge `m->pkt_len`, which is the L2
        // frame length including Ethernet and any VLAN tags but NOT
        // the preamble, SFD, or FCS. This matches how operators
        // size rate-limits — a "200 Mbps" limit on traffic means
        // 200 Mbps of on-the-wire bytes, and the 4-byte FCS is the
        // only constant delta we drop. For typical 1500 B frames
        // that is ~0.3 % under-counting; acceptable for flood
        // protection where the customer explicitly prefers
        // throughput over accuracy (§4.4).
        const auto& rl  = rs->rl_actions[a->rl_index];
        auto*       row = &g_cp.rl_arena->rows[rl.slot];
        auto&       b   = row->per_lcore[rte_lcore_id()];
        uint64_t    now = rte_rdtsc();
        uint64_t    elapsed = now - b.last_refill_tsc;
        uint64_t    refill  = elapsed * rl.rate_bytes_per_sec
                              / rte_get_tsc_hz() / g_cp.n_active_lcores;
        b.tokens          = min(b.tokens + refill, rl.burst_bytes);
        b.last_refill_tsc = now;
        if (b.tokens < m->pkt_len) {
            relaxed_bump(&b.dropped);
            counter_rl_drop(ctx, dyn->verdict_layer, a->rule_id);
            rte_pktmbuf_free(m);
            return;
        }
        b.tokens -= m->pkt_len;
        stage_tx(ctx, ctx->port_b, m);
        return;
    }
    default:
        // Same belt-and-braces as the outer switch: -Wswitch-enum
        // catches new verbs at compile time; this default is the
        // runtime backstop. Free the mbuf and bump a counter so
        // the situation is observable in telemetry.
        relaxed_bump(&ctx->stats.dispatch_unreachable_total);
        rte_pktmbuf_free(m);
        return;
    }
}
```

**Burst-end drains** (D16). At the end of every burst, after
`apply_action` has run over all mbufs:

```cpp
static inline void redirect_drain(WorkerCtx* ctx) {
    for (uint16_t p = 0; p < ctx->n_ports; p++) {
        auto& s = ctx->redirect_tx[p];
        if (s.n == 0) continue;
        uint16_t sent = rte_eth_tx_burst(p, ctx->qid, s.buf, s.n);
        if (unlikely(sent < s.n)) {
            rte_pktmbuf_free_bulk(&s.buf[sent], s.n - sent);
            relaxed_add(&ctx->stats.redirect_dropped_total, s.n - sent);
        }
        s.n = 0;
    }
}
// mirror_drain is structurally identical.
```

### 5.6 Cycle budget (D18)

Stage estimates at 3 GHz, fully cache-resident. Reported as a
min / typical / max triple (not single best case).

| Stage | min | typ | max |
|---|---|---|---|
| RCU quiescent publish | 2 | 2 | 3 |
| RX burst (amortized) | 10 | 15 | 20 |
| Header prefetch | hidden | hidden | hidden |
| D4 `RTE_MBUF_F_RX_FDIR_ID` branch | 3 | 3 | 3 |
| L2 parse | 15 | 20 | 25 |
| L2 hit (1 primary) | 30 | 40 | 50 |
| L2 miss (src + dst + vlan + etype) | 80 | 95 | 110 |
| L3 IPv4 fragment/IHL checks | 3 | 5 | 7 |
| L3 FIB lookup (single) | 20 | 30 | 45 |
| L3 miss | 20 | 30 | 45 |
| L4 parse (IHL) | 5 | 8 | 10 |
| L4 compound hit (primary + filter_mask) | 40 | 55 | 70 |
| L4 miss (three primaries probed) | 80 | 110 | 140 |
| Action dispatch (allow) | 8 | 10 | 12 |
| Action dispatch (rate-limit) | 20 | 25 | 35 |
| Counter update (per-layer indexing) | 4 | 6 | 8 |
| TX burst (amortized) | 10 | 15 | 20 |

**Realistic typical case** — TCP/IP packet, no L2 match, matches an
L3 dst-prefix rule that terminates at L3:

```
RCU quiescent          2
RX burst amortized    15
RTE_MBUF_F_RX_FDIR_ID branch     3
L2 parse              20
L2 miss               95
L3 IHL/frag check      5
L3 FIB hit            30
L4 skipped             0 (terminal L3)
Action dispatch       10
Counter update         6
TX burst amortized    15
─────────────────────────
Total: ~201 cycles
```

At 3 GHz that is ~67 ns per packet, or ~15 Mpps per lcore.
With 8 dataplane lcores the per-lcore budget at 64-byte line rate
(worst case 59.52 Mpps total → ~7.4 Mpps per lcore) is ~400 cycles,
so the typical case has headroom but not "substantial" headroom —
the L4 miss path, mirror clone path, and TAG-action combined with
a full L4 compound-secondary check will push realistic packets to
~280–320 cycles.

This is **within budget**, but only with care. Headroom is tight
enough that any additional per-packet work (new counter, new
classification layer, extra parse) must be justified with a cycle
estimate.

## 6. Lifecycle

### 6.1 Init sequence

```
main()
  ├─ parse CLI (--config, --sizing-config, --ports,
  │             --lcores, --hugepage-prefix, --standby)
  ├─ load sizing config (file or inline), validate against hard min (16/layer)
  ├─ rte_eal_init(...)
  ├─ bind interface_roles → DPDK port indices (from role config / CLI)
  ├─ register mbuf dynfield slot (must fit the §5.1 dynfield schema)
  ├─ create mempools (per-NUMA-socket, see §8)
  ├─ port_init(port_a), port_init(port_b), port_init(mirror/redirect …)
  │     ├─ rte_eth_dev_configure (RSS on 5-tuple, K rx/tx queues)
  │     │     D28: K ≥ n_workers on EVERY port registered from
  │     │     interface_roles, regardless of whether the port is a
  │     │     primary egress or a mirror / redirect destination.
  │     │     The startup validator rejects the config if any port
  │     │     reports `rte_eth_dev_info.max_tx_queues < n_workers`.
  │     │     D39: the startup validator also enforces that the
  │     │     per-port max admissible frame length (RTE_ETHER_MTU
  │     │     + headroom, or the offload-enabled jumbo MTU) fits
  │     │     in ONE mempool segment. Formally:
  │     │        (port.max_rx_pkt_len + RTE_PKTMBUF_HEADROOM)
  │     │          ≤ (mempool.elt_size - sizeof(rte_mbuf))
  │     │     AND `rxmode.offloads & SCATTER == 0` is set on every
  │     │     port at configure time. Any port that demands
  │     │     multi-seg RX is rejected at startup with reason
  │     │     `multiseg_rx_unsupported`. This guarantees the
  │     │     §5.1 D39 headers-in-first-seg invariant.
  │     ├─ rte_eth_rx_queue_setup × K (mempool from worker's NUMA socket)
  │     ├─ rte_eth_tx_queue_setup × K  (D28: per-worker lanes)
  │     └─ rte_eth_dev_start
  ├─ allocate RateLimitArena from sizing.rate_limit_rules_max
  ├─ first parse + validate + compile of config file → Ruleset v0
  │     │ on failure → fatal exit, watchdog will retry
  ├─ qsbr bring-up (D30):
  │     sz   = rte_rcu_qsbr_get_memsize(N_workers);
  │     mem  = rte_zmalloc_socket("qsbr", sz,
  │                               RTE_CACHE_LINE_SIZE,
  │                               g_cp.cp_socket_id);
  │     g_cp.qs = (rte_rcu_qsbr*)mem;
  │     rte_rcu_qsbr_init(g_cp.qs, N_workers);
  │     (DPDK 25.11 has no rte_rcu_qsbr_create — bring-up is the
  │      get_memsize / zmalloc_socket / init three-step.)
  ├─ atomic_store(&g_cp.g_active, ruleset_v0, RELEASE)
  ├─ if --standby: skip remote_launch of workers; enter park loop
  │              **Park mechanism (decision):** ports are
  │              `rte_eth_dev_configure`'d but NOT
  │              `rte_eth_dev_start`'ed — the NIC RX path is
  │              quiescent, no DMA, no descriptor ring activity,
  │              no risk of accidentally bridging traffic. On
  │              activation: workers are remote-launched first,
  │              then `rte_eth_dev_start` runs for each port,
  │              then RSS/flow rules are programmed. This gives
  │              a clean "no traffic in flight" guarantee for
  │              warm-standby pairs (§14.3 HA). Link-down is
  │              **not** used — it would still leave the RX
  │              ring active and is more racy on hot promote.
  ├─ else: rte_eal_remote_launch(worker_main, ctx_i, lcore_i) per worker
  ├─ start telemetry thread (Prometheus + sFlow + log drain + rte_tel)
  ├─ start cmd_socket thread
  ├─ start inotify thread
  └─ control loop: signals + heartbeat tick
```

Cold start budget: **≤ 5 s**, dominated by EAL hugepage scan and
port init. Mempool and ruleset allocation add hundreds of ms.

### 6.2 Steady state

Workers run uninterrupted. The control thread polls inotify, signals,
the cmd socket, and ticks the watchdog at 10 Hz. The telemetry thread
aggregates per-lcore counters at the snapshot interval (default 1 s)
and serves the export channels.

### 6.3 Hot reload sequence diagram

```
inotify       parser/validator     compiler    GenManager (RCU)   workers
   │                │                  │              │                │
   ▼                                                                    
file change ───►                                                        
   │                │                                                   
   ├──drain+debounce(150ms)                                              
   │                │                                                   
   ├──do_reload()─► parse(config.json)                                   
   │                │ ok? ────────────►compile()                         
   │                │                  │ ok?                            
   │                │                  ├──build Ruleset v(n+1)          
   │                │                  │     (NUMA-local alloc,         
   │                │                  │      rte_flow hw-tier install) 
   │                │                  └────►  publish via              
   │                │                          atomic_exchange(
   │                │                            &g_cp.g_active, v_new, RELEASE)
   │                │                                  │                
   │                │                                  ├─rcu_synchronize() or
   │                │                                  │  rcu_check+timeout
   │                │                                  │                ▼
   │                │                                  │     workers pass quiescent
   │                │                                  │     state (top of next burst)
   │                │                                  ├─arena GC: free removed
   │                │                                  │   rule_id bucket rows
   │                │                                  ├─free Ruleset v_old
   │                │                                  └─emit reload_done log+metric
   │                │
   │                └─on parse/validate/compile failure: log, bump
   │                   reload_total{result="parse_err|validate_err|
   │                   compile_err|oom"}, leave g_active untouched
```

### 6.4 Shutdown

`SIGTERM` sets `running = false`. Workers exit their burst loops, and
on the way out each worker calls `rte_rcu_qsbr_thread_offline` before
leaving the loop and `rte_rcu_qsbr_thread_unregister` after. Control
thread joins them with `rte_eal_mp_wait_lcore()`; ports are stopped
(`rte_eth_dev_stop`, `rte_eth_dev_close`); the final ruleset is
freed; `g_cp.g_active` is cleared **after** the last
`rcu_synchronize` returns. The rate-limit arena and mempools are
freed last. Total shutdown ≤ 1 s.

### 6.5 Crash recovery

Watchdog (systemd unit + internal heartbeat) detects:

- **Process death** → systemd `Restart=on-failure` with exponential
  backoff.
- **Stall** → internal heartbeat counter has not advanced in `K × tick`
  → systemd `WatchdogSec` triggers `SIGABRT`.
- **Repeated crash** (> K in a window) → systemd unit transitions
  into `pktgate-bypass.target`, which starts a tiny supervisor that
  performs forwarding via one of the bypass strategies (§11).

## 7. Threading and lcore layout

**Decision Q1 = Option A — lcore-per-RX-queue, run-to-completion.**
Pipeline mode (Option B) is rejected because:

- Per-packet budget is adequate at the chosen queue count;
  classification fits within run-to-completion.
- Option B would add ~30 ns of `rte_ring` enqueue / dequeue per
  packet plus cache-line bouncing across cores. At 59.52 Mpps that
  is >1.7 Gcycles/sec spent moving pointers.
- Run-to-completion makes hot-reload semantics simple: one reader
  per ruleset reference, no mid-pipeline state to flush.

**Lcore layout for a typical 40 Gbps production node** (single CPU
socket, 16 cores):

| lcore | role |
|---|---|
| 0 | OS housekeeping (`isolcpus` excludes it) |
| 1 | Control thread (inotify, watchdog, cmd socket) |
| 2 | Telemetry thread (Prometheus scrape, sFlow, log drain) |
| 3 | Reserved (validation / compile) |
| 4–11 | 8 dataplane workers, one per (port_a/b) RX queue |
| 12–15 | reserved / idle (or more workers if rules become heavier) |

`isolcpus=4-15`, `rcu_nocbs=4-15`, `nohz_full=4-15`. Control-plane
lcores are not isolated. NUMA: pin all dataplane workers and their
mempools to the socket attached to the NICs (`rte_eth_dev_socket_id`).

**RSS configuration**: symmetric Toeplitz key, 5-tuple (src/dst IP,
src/dst port, proto). Symmetric is required so that both directions
of the same flow land on the same lcore — the architecture relies on
this for per-flow rate-limit variants (§14) and for consistent
per-lcore counter locality. The canonical symmetric Toeplitz key is
the 40-byte repeating `0x6D5A` pattern (Woo & Park 2012 / RSS++
reference), programmed via `rte_eth_dev_rss_hash_update` at port init
(D30: the previous `rte_eth_rss_hash_conf_set` spelling does not exist
in DPDK 25.11 — `_dev_rss_hash_update` is the setter, paired with
`_dev_rss_hash_conf_get` for the read side);
it makes the Toeplitz function symmetric under src↔dst swap for the
standard IPv4/IPv6 5-tuple inputs. On NICs that do not expose
Toeplitz (e.g. the dev VM's e1000), the dataplane degrades to
single-queue and the design still applies.

**Per-queue depth**: RX = 1024, TX = 1024 descriptors. RX below 512
risks drops at burst peaks; above 4096 wastes memory and worst-case
latency. 1024 is the `l3fwd` default and the established sweet spot.

## 8. Memory layout

### 8.1 Hugepages

Production target: **2 GiB hugepages** (as 1024 × 2 MiB or 1 ×
1 GiB; 1 GiB is preferred for TLB efficiency). Recommended: 4 GiB
to leave headroom for two concurrent rulesets at scale plus
mempool growth.

Dev default: 512 MiB (matches the existing 512 × 2 MiB allocation on
the dev VM). Dev defaults are for sandbox only; production sizing
targets are the architectural numbers.

### 8.2 Mempools

One mempool per NUMA socket, shared among lcores on that socket.

```
n_mbufs = (n_rx_queues × rxd) +
          (n_tx_queues × txd) +
          (n_lcores × burst_size × 2) +     // RX/apply-action staging
          (n_lcores × burst_size × n_ports) + // TX stage buffers
          (n_lcores × burst_size) +         // mirror staging
          (n_lcores × MEMPOOL_CACHE_SIZE)   // per-lcore cache
        + safety_margin
```

For the 8-worker, 2-port, 1024-desc, BURST=32 target:

```
= 8 × 1024 × 2 (rxd, both ports)            16384
+ 8 × 1024 × 2 (txd, both ports)            16384
+ 8 × 32 × 2                                  512
+ 8 × 32 × 2                                  512
+ 8 × 32                                      256
+ 8 × 256                                    2048
+ ~8000 safety
≈ 44096 mbufs  → round up to 65535 (2^n − 1)
```

With `RTE_MBUF_DEFAULT_BUF_SIZE` = 2176 B, that's ~140 MiB per
mempool. One per socket. Mirror clones share the main mempool —
there is no separate mirror pool.

### 8.3 Per-lcore allocations

| Allocation | Size (production target) | Where |
|---|---|---|
| `WorkerCtx` | ~8 KiB (incl. TX stage buffers) | NUMA-local |
| `PerLcoreCounters` (rules) | ~768 KiB per lcore; ~N×768 KiB aggregate at N active dataplane lcores (n_rules_total = 12 288) | NUMA-local |
| `LcoreStats` | ~256 B | NUMA-local |
| Local prefetch scratch | stack | negligible |

### 8.4 Sizing: dev defaults vs production targets (M1)

**All capacity parameters are runtime**: sized at startup from a
sizing config section or file; no compile-time ceilings. Hard
compile-time **minimum** is 16 per layer so tests remain meaningful.

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
| Dataplane lcores | 1 | 8–16 |
| Hugepages | 512 MiB | 2–4 GiB |
| RX/TX queue depth | 256 | 1024 |

Dev defaults are chosen to keep hugepage usage < 256 MiB and cold
start < 1 s on the VM. Production targets are inherited from the
pktgate (XDP) scale points and are what the architecture is
designed for.

### 8.5 RCU memory

`rte_rcu_qsbr` requires `rte_rcu_qsbr_get_memsize(N_workers)` bytes
— typically a few hundred bytes.

## 9. Hot reload strategy

### 9.1 Decision

**Q2: use `rte_rcu_qsbr`** with an explicit `rcu_synchronize` (or
`rcu_check + timeout`) after an atomic exchange on a single global
`g_active` pointer. Rejected alternatives:

- *Plain atomic pointer + manual sleep*: hopes a sleep is enough for
  in-flight references; not a guarantee.
- *`rte_rcu_qsbr_dq` deferred queue*: good for streaming many delete
  operations, overkill for whole-ruleset swap.
- *Double-buffered structures (legacy BPF pattern)*: unnecessary
  with native pointer-and-arena allocation; each `Ruleset` is a
  fresh allocation and freed on its own.

### 9.2 Mechanics

Workers are QSBR readers. They do not hold a long-lived pointer;
each burst starts with `rte_rcu_qsbr_quiescent(qs, tid)` followed by
`atomic_load_explicit(&g_cp.g_active, memory_order_acquire)`. The
local `const Ruleset* rs` lives for the duration of the burst and
goes out of scope at its end, at which point the next iteration's
quiescent publication releases all references.

Writer (control thread on reload):

**Single funnel**. Every reload entry point — the inotify watcher,
the UDS `cmd_socket` `{"cmd":"reload"}` verb, the `rte_telemetry`
`/pktgate/reload` flag, and any future push channel — calls into
this **one** `deploy()` function. There is no second copy of the
publish pipeline anywhere in the control plane. The
`g_cp.reload_mutex` (D35, declared in §4.5) is acquired at the top
of `deploy()` and held across compile, publish, GC, and the §9.4
`pending_free` operations, so by construction `g_active` has
exactly one writer at a time even when multiple sources fire
concurrently. Threads contending for the mutex serialize cleanly;
nested reload from the same thread is structurally impossible
(`deploy` is a leaf in the call graph and never recurses).

**D37 — validator budget pre-flight**. Between `validate(*cfg)` and
`compile_*` the validator runs a **pure-arithmetic** memory and
ceiling check against the live sizing config. The goal is to fail
a hostile or careless reload **before** the compiler has touched
any hugepage, so a "10⁹-port-list expansion" or "256k synthetic
rules" payload can never even allocate. Three independent gates,
all hard-failing with a structured error:

- **Per-rule expansion ceiling.** Each rule's compile-time
  expansion (port lists, prefix lists, address-group inlining) is
  bounded by `sizing.max_expansion_per_rule` (default 4096 entries
  per rule). Operators wanting larger expansions raise the bound
  explicitly in `sizing` — there is no silent compiler accommodation.
- **Aggregate post-expansion ceiling.** The sum of all per-rule
  expansions must fit inside `sizing.l{2,3,4}_entries_max`. This
  is the same number §4.3 / §8.4 already use for arena sizing;
  the validator verifies the rule set fits **before** the
  compiler is asked to populate the arenas.
- **Hugepage budget.** The validator computes a conservative
  `expected_ruleset_bytes(cfg, sizing)` from the same formulas as
  §8.1 / §8.2 (Ruleset arenas + FIB tries + hash tables) and
  refuses the reload if it exceeds free hugepages on the
  control-plane socket minus a safety margin. This is a
  pre-flight estimate, not an allocator probe — the goal is to
  reject obviously oversized configs in a few microseconds rather
  than discover OOM 30 ms into `ruleset_build`.

Failure on any gate returns `Err::ValidateBudget` and bumps
`reload_total{result="validate_err"}` (sub-reason in the structured
log: `expansion_per_rule | aggregate | hugepage_budget`). The
configured sizing limits are surfaced via
`rte_telemetry /pktgate/sizing` so operators can introspect the
ceilings without grepping the binary.

```cpp
expected<void> deploy(std::string path) {
    // D35 — funnel guard. ALL reload entry points end here, so
    // this single mutex serializes the entire compile/publish/GC
    // pipeline against itself. Held across the bounded rcu_check
    // (§9.2 D30) so the §9.4 pending_free push/drain happens
    // under the same lock as everything else that touches
    // g_cp.pending_free.
    std::lock_guard<pthread_mutex_t> _g(g_cp.reload_mutex);

    auto cfg = parse(path);                     if (!cfg) return cfg.error();
    auto v   = validate(*cfg);                  if (!v)   return v.error();
    // D37 — pure-arithmetic pre-flight: per-rule expansion ceiling,
    // aggregate post-expansion ceiling, hugepage budget. Rejects
    // hostile / oversized configs before any compiler allocation.
    auto vb  = validate_budget(*cfg, sizing);   if (!vb)  return vb.error();
    auto co  = compile_objects(cfg->objects);   if (!co)  return co.error();
    auto cr  = compile_rules(cfg->pipeline, *co, sizing);
                                                if (!cr)  return cr.error();
    auto rs_new = ruleset_build(*cr);           if (!rs_new) return rs_new.error();

    rs_new->generation = ++gen_counter;
    rs_new->compile_timestamp_ns = now_ns();

    // Install rte_flow entries for hw-tier rules (D4). Failure is
    // non-fatal: the affected rule is moved back to software tier
    // in rs_new and a warning is logged.
    install_hw_offload(rs_new);

    // Publish (release).
    const Ruleset* rs_old = atomic_exchange_explicit(
        &g_cp.g_active, rs_new.release(), memory_order_acq_rel);

    // Wait for all workers to pass quiescent state.
    // Prefer bounded check + explicit deadline over unbounded
    // synchronize, so a stuck worker does not hang reload forever.
    // The watchdog is the ultimate backstop for stuck workers (D12).
    //
    // **D30 — correct rte_rcu_qsbr_check usage.** The `t` parameter
    // is NOT a timeout — it is a token returned by
    // rte_rcu_qsbr_start() that names the epoch the writer wants
    // confirmed quiescent. There is no built-in timeout on
    // rte_rcu_qsbr_check or rte_rcu_qsbr_synchronize. We get a
    // bounded wait by polling rte_rcu_qsbr_check(..., wait=false)
    // against an explicit TSC deadline tracked in user space.
    // (A previous revision of this section misread the API and
    // claimed `t` was a TSC-delta timeout. It is not. See D30 in
    // review-notes.md for the meta-finding.)
    const uint64_t token    = rte_rcu_qsbr_start(g_cp.qs);
    const uint64_t deadline = rte_rdtsc()
                            + (rte_get_tsc_hz() / 2);  // 500 ms
    int rc;
    while ((rc = rte_rcu_qsbr_check(g_cp.qs, token, /*wait=*/false))
           != 1) {
        if (rte_rdtsc() > deadline) {
            metric_inc(reload_timeout_total);
            // Leave rs_new published (it is now the active ruleset;
            // it just could not confirm old-reader drain in time).
            // rs_old goes onto g_cp.pending_free for the next
            // successful check to drain (see D36 / §4.5).
            if (!pending_free_push(&g_cp, rs_old)) {
                // Queue full → dataplane wedged. Refuse the timeout
                // path entirely (rs_new stays published, rs_old is
                // intentionally leaked to memory). Operator alert
                // fires; this is a "stop the world, page on-call"
                // condition, not a transient hiccup.
                //
                // Q5 cadence: `reload_pending_full_total` is a
                // counter with once-per-overflow semantics —
                // incremented exactly once per reload attempt that
                // hits an already-full queue. It is NOT incremented
                // on every retry of a stuck reload loop (the caller
                // is responsible for not reloading again until the
                // queue drains). Structured-log entry fires on the
                // same edge. Alerting rule should be
                // `rate(...[5m]) > 0`, not level.
                metric_inc(reload_pending_full_total);
            }
            return tl::unexpected(Err::ReloadTimeout);
        }
        rte_pause();
    }
    // Drain any prior reload-timeouts whose epoch is now safely
    // past quiescent (D36). The current successful check covers
    // every pointer that was published before `token`.
    pending_free_drain(&g_cp);

    // --- Arena GC diff (D11) ---
    // After synchronize, no worker can be holding rs_old.
    // Compute the set of rule_ids present in rs_old but not rs_new
    // and release their arena slots back to the free pool. The row
    // memory is NOT freed — it stays in place for slot reuse on a
    // future publish (see §4.4 slot lifecycle). What changes:
    //   - id_to_slot loses the rule_id → slot mapping
    //   - slot_live[slot] is cleared
    auto removed = diff_rule_ids(rs_old, rs_new);
    for (uint32_t rid : removed)
        rl_arena_free_slot(g_cp.rl_arena, rid);
    // No second synchronize is needed: rs_new never references
    // the removed rule_ids, so no reader could touch them after
    // the publish exchange.

    // Destroy rs_old.
    ruleset_destroy(rs_old);

    metric_inc(reload_success_total);
    return {};
}
```

### 9.3 Latency budget

| Stage | Time |
|---|---|
| inotify event → debounced trigger | 0–150 ms (debounce window) |
| parse JSON | < 5 ms (typical config) |
| validate | < 5 ms |
| compile objects + rules | < 10 ms |
| ruleset_build (FIB inserts dominate) | 10–50 ms |
| atomic exchange | < 1 µs |
| rcu_check (bounded poll vs deadline) | < 1 ms typical, 500 ms worst case |
| pending_free drain (D36, only if prior timeout) | < 1 ms |
| arena GC (row frees) | < 1 ms |
| destroy old ruleset | < 5 ms |

End-to-end target ≤ 100 ms (after debounce window). With the 150 ms
debounce the user-perceived latency is ≤ 250 ms. We comfortably hit
the customer-visible SLO.

### 9.4 Corner cases

- **Failed reload**: any `expected<>` error returns cleanly; the
  active ruleset is never replaced. The partially-built new ruleset
  is destroyed by the `unique_ptr` path.
- **Nested / concurrent reload** (D35): the single
  `g_cp.reload_mutex` serializes every reload entry point —
  inotify, UDS `cmd_socket` `reload`, `rte_telemetry`
  `/pktgate/reload` flag — through one `deploy()` call. The
  inotify watcher additionally **debounces** rapid file events
  into one trigger, so a burst of writes coalesces before it ever
  reaches the funnel; the mutex is the backstop for the
  cross-channel case (e.g. UDS reload arrives while inotify is
  mid-deploy). Subsequent contention is plain lock waiting; no
  reload is lost.
- **Hugepage exhaustion mid-build**: `ruleset_build` returns
  `ENOMEM`, old ruleset stays, `reload_oom_total` increments,
  operator alert fires.
- **Mid-burst reload**: impossible by construction. Workers grab
  `g_active` at the top of each burst and do not refresh until the
  next burst. A burst sees exactly one ruleset version end to end.
- **Arena GC ordering** (D11): the sequence is explicit —
  1. build `rs_new`,
  2. atomic exchange publishes `rs_new` (release),
  3. rcu synchronize (or bounded check),
  4. diff `removed = rs_old.rule_ids \ rs_new.rule_ids`,
  5. free arena slots for `removed` rule ids (clears `slot_live`
     and drops `id_to_slot` entries; row memory stays in place
     for reuse — see §4.4 slot lifecycle),
  5b. zero per-lcore counter rows for removed rules: for each
     removed rule, resolve its `(layer, counter_slot)` and
     memset `counters->by_rule[layer_base(L) + counter_slot]` to
     zero on every lcore (see §4.3 "Counter zeroing on slot
     reuse"). Safe after step 3 — no worker holds a reference.
  6. destroy `rs_old`.

  Steps 4–5b run after step 3, before step 6. No second synchronize
  needed; `rs_new` never references removed ids, so no reader could
  touch them after step 2.
- **Rule-id reassignment**: the arena keys off `rule_id` verbatim.
  If an operator reassigns the same `id` to a semantically different
  rule, the old bucket state carries over — the operator's
  responsibility is to pick a new `id` if they want a clean bucket.
  A rule_id that disappears and later reappears in a future reload
  starts fresh (its slot was freed in step 5 above; the next
  allocation zero-initializes the row). Documented in §3a.2 and the
  operator CONFIG doc.
- **Reload timeout** (D12 + D30 + D36): the bounded rcu check
  loop in §9.2 polls `rte_rcu_qsbr_check(qs, token, wait=false)`
  against an explicit 500 ms TSC deadline. On expiry: `rs_new`
  remains active (it was already exchanged in), `rs_old` goes
  onto `g_cp.pending_free` (D36), `reload_timeout_total` is bumped,
  and the function returns `Err::ReloadTimeout` to the caller.
  The next reload that achieves a successful check drains the
  whole pending queue (one successful check covers every
  publish that preceded its `start()` token). On `pending_free`
  overflow (queue depth > `K_PENDING = 8`) the timeout path
  bumps `reload_pending_full_total` and intentionally leaks
  `rs_old` — that condition is "dataplane wedged, page on-call",
  not a transient hiccup. Repeated timeouts also feed the
  watchdog as the backstop for stuck workers.

### 9.5 Hardware offload publish (D4)

For each rule marked `execution_tier = HW` by the compiler, the
builder calls `rte_flow_create` with the rule's match + action
patterns during publish (not on the hot path). On `ENOTSUP` or
`ENOMEM` the rule is quietly moved back to `SW` tier in `rs_new`,
a warning is logged with the rule id, and publish continues. The
software tables in `rs_new` always hold **all** rules, including
those also installed in hardware — offload is an optimization, not
the source of truth. This supports: NIC rule flush, process
restart, partial offload, and operator-disabled offload.

Hardware offload is a complete architectural capability of the
design; its shipping schedule is owned by §14.

## 10. Telemetry surface

### 10.1 Counting and aggregation model (D3)

The architecture defines the full counting and aggregation model.
Export channels listed below are all part of the architecture; which
channels ship in a given phase is a §14 question.

**Counting model**:

- `RuleCounter` is a 64-byte cache-line struct:
  `matched_packets`, `matched_bytes`, `drops`, `rate_limit_drops`.
- Storage: `RuleCounter counters[n_lcores][n_rules_total]` — a
  per-lcore array of per-rule counters, sized at init from the
  sizing config.
- **Zero atomics on the hot path**: each lcore writes only to its
  own row.
- Per-port counters wrap `rte_eth_stats` under the pktgate label
  schema.
- Per-lcore stats (`LcoreStats`): cycles per burst, packets
  processed, idle iterations, queue depth samples,
  `l4_skipped_ipv6_extheader`, redirect/mirror dropped counters.

**Aggregation model**:

- Dedicated telemetry thread (control plane, not pinned to a
  dataplane lcore).
- Periodic snapshot: for every (lcore, rule) pair the publisher
  loads the counter with `__atomic_load_n(p, __ATOMIC_RELAXED)`
  (matching the owning lcore's `relaxed_bump` store side per §4.3),
  then accumulates into the snapshot. Snapshot interval
  configurable, default 1 s.
- Snapshot published to a lock-free ring buffer with `N` generations.
  Default `N = 4`. The minimum correct value is 2 (one generation
  being written by the telemetry thread, one being read by the
  exporters). `N = 4` adds slack so that a slow exporter (e.g.
  Prometheus scraper that takes longer than the snapshot interval)
  does not force the writer to wait or skip a snapshot. Single
  writer (telemetry thread), multiple readers (one per exporter);
  exporters always read the most recent fully-published generation.

### 10.2 Supported export channels (all defined by architecture)

1. **Prometheus HTTP exporter** (D42 — hand-rolled, not vendored)
   - `/metrics` endpoint, OpenMetrics text format, configurable port.
   - Labels: `rule_id`, `layer`, `port`, `lcore`, `site`.
   - Own thread; no hot-path involvement.
   - **Hand-rolled HTTP server, no third-party dependency** (no
     cpp-httplib, no vendored HTTP blob). Rationale: scope is one
     verb + one path, keeping the surface auditable vs. a 10 k-LoC
     vendored framework on a high-trust GGSN-Gi position. Full
     rationale in review-notes D42; see also the D-table entry in
     `CLAUDE.md`.
   - **Protocol subset**: HTTP/1.0 and HTTP/1.1 request lines
     accepted; response always framed as HTTP/1.1 with
     `Connection: close`. No keep-alive, no
     `Transfer-Encoding: chunked`, no compression, no TLS, no auth.
     HTTP/2.0+ → 505. Non-GET → 405. Path != `/metrics` → 404.
     Malformed request line / body-bearing GET / explicit
     `Transfer-Encoding` header → 400.
   - **Request caps**: 8 KiB cap on request line; 8 KiB cap on total
     header block. Oversized → 400 (or 414/431 at implementer
     discretion).
   - **Socket timeouts**: `SO_RCVTIMEO` = 5 s and `SO_SNDTIMEO` = 5 s
     — bounds slowloris attacks and stuck readers/writers.
   - **Bind**: `127.0.0.1:<sizing.prom_port>` (AF_INET only, default
     `9090`). No IPv6 listen; loopback-only — operator firewalls at
     their edge (kube-prometheus convention).
   - **Concurrency**: single accept thread, sequential request
     handling, no pool / reactor. Prometheus scrape rate ≈ 1 req
     per 15 s; concurrency is unjustified complexity.
   - **Response framing**: always `Content-Length`-terminated; socket
     closed after the body. No chunked encoding.
2. **sFlow v5 UDP exporter**
   - Embedded encoder (no libsflow dependency).
   - Samples carry truncated header, ingress port, timestamp,
     matched rule id.
   - Configurable sample rate and collector address.
3. **Structured JSON logs**
   - stderr (captured by journald) or UDP syslog target.
   - Levels: error, warn, info, debug.
   - **No per-packet logging on the hot path, ever.** Rule-match
     events allowed only at low sample rates.
4. **`rte_telemetry` UDS**
   - Standard DPDK idiom via `dpdk-telemetry.py`.
   - Exposes counter snapshots, rule list, lcore stats, reload
     status; read-only.

All four channels pull from the **same snapshot buffer**; having
multiple channels costs an extra thread each but shares the data
pipeline.

### 10.3 Metric names

```
pktgate_rule_packets_total{layer="l2|l3|l4",rule_id="N"}          counter
pktgate_rule_bytes_total{layer,rule_id}                           counter
pktgate_rule_drops_total{layer,rule_id,reason="explicit|rate"}    counter
pktgate_default_action_total{verdict="allow|drop"}                counter

pktgate_port_rx_packets_total{port}                               counter
pktgate_port_tx_packets_total{port}                               counter
pktgate_port_rx_bytes_total{port}                                 counter
pktgate_port_tx_bytes_total{port}                                 counter
pktgate_port_rx_dropped_total{port,reason="nombuf|noqueue|err"}   counter
pktgate_port_tx_dropped_total{port}                               counter
pktgate_port_link_up{port}                                        gauge (0/1)

pktgate_lcore_packets_total{lcore}                                counter
pktgate_lcore_cycles_per_burst{lcore}                             histogram
pktgate_lcore_idle_iters_total{lcore}                             counter
pktgate_lcore_l4_skipped_ipv6_extheader_total{lcore}              counter
# D27 — aliased below as `pkt_frag_skipped_total{af="v6"}` (same bump site).
pktgate_lcore_l4_skipped_ipv6_fragment_nonfirst_total{lcore}      counter
pktgate_lcore_tag_pcp_noop_untagged_total{lcore}                  counter
pktgate_lcore_dispatch_unreachable_total{lcore}                   counter
# D31 — per-stage truncation guards (§5.2 / §5.3 / §5.4).
# `where` ∈ {l2, l2_vlan, l3_v4, l3_v6, l3_v6_frag_ext, l4}.
pktgate_lcore_pkt_truncated_total{lcore,where}                    counter
# D32 — QinQ outer (0x88A8) accepted by §5.2 fast path; the inner
# C-tag is left unparsed in this phase.
pktgate_lcore_qinq_outer_only_total{lcore}                        counter
# D39 — multi-seg mbuf observed at classifier entry despite the
# port-init scatter-off guarantee. Should always be zero.
pktgate_lcore_pkt_multiseg_drop_total{lcore}                      counter
# D40 — fragment-skip (l3_only policy) and fragment-drop (drop
# policy), symmetrical across IPv4 and IPv6.
# IPv6 skip value is duplicated as `l4_skipped_ipv6_fragment_nonfirst`
# above (same bump site) for backwards telemetry continuity.
pktgate_lcore_pkt_frag_skipped_total{lcore,af="v4|v6"}            counter
pktgate_lcore_pkt_frag_dropped_total{lcore,policy="drop",af="v4|v6"} counter
pktgate_redirect_dropped_total{lcore,port}                        counter
pktgate_mirror_dropped_total{lcore,port}                          counter

pktgate_reload_total{result="success|parse_err|validate_err|compile_err|oom|timeout|pending_full"} counter
pktgate_reload_latency_seconds                                    histogram
pktgate_reload_pending_free_depth                                 gauge   # D36
pktgate_active_generation                                         gauge
pktgate_active_rules{layer}                                       gauge
# M10 C5 / D3 — telemetry-publisher liveness gauge. Monotonic
# counter of completed snapshot publishes; scraped alongside the
# other reload/active gauges. Its forward progress under a slow
# scraper is the observable that proves the N=4 ring decouples
# the 1 Hz writer from the reader (F8.13).
pktgate_publisher_generation                                      gauge
# D38 — UDS peer-cred rejections.
pktgate_cmd_socket_rejected_total{reason="peer_uid|peer_gid"}     counter

pktgate_mempool_in_use{socket}                                    gauge
pktgate_mempool_free{socket}                                      gauge

pktgate_watchdog_restarts_total                                   counter
pktgate_bypass_active                                             gauge (0/1)
pktgate_log_dropped_total                                         counter  # §10.5
```

**D33 — counter consistency invariant.** Every counter named in the
prose of §3a / §4.3 / §5 / §11 / §15 / review-notes also appears in
the list above. The validator-budget sub-reasons are exposed via
`reload_total{result="validate_err"}`'s structured-log payload, not
as a separate metric (the failure rate is the operationally
interesting signal — sub-reason is for forensics).

### 10.4 sFlow details

- Default sample rate per ingress port `1:1024`, configurable.
- Sample record: `flow_sample` with raw truncated header (128 B),
  input ifIndex, output ifIndex, matched rule id in `extended_user`,
  packet length, drop status. Counter samples every 30 s.
- Worker writes a fixed-size sample record to a per-lcore SPSC ring;
  the telemetry thread builds and sends the sFlow datagram.
  **Encoding never happens on the hot path.**

### 10.5 Structured logs

JSON lines, per-lcore SPSC ring drained by the telemetry thread.
Overflow drops the oldest record and bumps
`pktgate_log_dropped_total`. Zero allocations on the hot path.

### 10.6 `rte_telemetry` endpoints

```
/pktgate/version
/pktgate/active_generation
/pktgate/rules/count
/pktgate/rules/dump,layer=l3
/pktgate/lcores
/pktgate/ports
/pktgate/reload                   ← writes a flag the inotify thread polls
```

### 10.7 UDS command socket (Q6)

`/run/pktgate/ctl.sock`, mode 0600, owned `pktgate:pktgate`, line-
delimited JSON:

```json
{"cmd":"reload"}
{"cmd":"status"}
{"cmd":"dump-config"}
{"cmd":"dump-rule","layer":"l3","id":42}
{"cmd":"counters","layer":"l3","id":42}
{"cmd":"activate"}      // exit --standby park state
```

**D38 — peer authentication.** Filesystem permissions
(`mode 0600`, owner `pktgate:pktgate`) are the first gate, but the
control thread additionally enforces caller identity at
`accept(2)` time using `SO_PEERCRED`. The accepted ucred must
satisfy **both**:

1. `uid == 0` *or* `uid == pktgate_uid` (the daemon's own uid;
   needed so the watchdog can self-reload), AND
2. `gid` ∈ a configurable allow-list (`config.cmd_socket.allow_gids`,
   default: just `pktgate_gid`).

A peer that fails the check is logged at warn (`peer_uid`,
`peer_gid`, `peer_pid`), the connection is closed immediately,
and `pktgate_cmd_socket_rejected_total{reason="peer_uid|peer_gid"}`
is bumped.

**Q6 clarification — single accept-time check.** `SO_PEERCRED`
is enforced **exactly once, at `accept(2)` time**, on the
connection socket. Every verb served on that connection reuses
the ucred captured at accept. There is no per-verb re-check: the
kernel's ucred is pinned at accept and cannot be spoofed by the
peer thereafter, and a long-lived connection cannot acquire new
capabilities mid-stream. Both mutating (`reload`, `activate`) and
read-only (`status`, `dump-*`, `counters`) verbs therefore run
under the same gate; the allow-list distinction between "anyone
allow-listed" and "must be authenticated" collapses to "must be
allow-listed at accept" — which is the only check there is.
This blocks the local-unprivileged-user attack against a
permissive `0666` socket left over from a misconfigured
deployment.

**D38 — inotify event filtering.** The directory watcher subscribes
to `IN_CLOSE_WRITE | IN_MOVED_TO` only — *not* `IN_MODIFY`. The
former two fire exactly once per atomic file replacement
(`mv tmp file` or `editor-buffer-flush; close`), so the parser
sees a fully-formed config; `IN_MODIFY` fires on every partial
write and would race the parser against in-progress edits. The
debounce window (§9.3) collapses bursts of these events into one
deploy. `inotify_init1` uses `IN_NONBLOCK | IN_CLOEXEC`, and the
watch is set on the **directory**, never on the file itself, so
atomic-replace via rename is observed correctly.

## 11. Failure modes and responses

| Failure | Detection | Action | Recovery |
|---|---|---|---|
| Bad JSON syntax | parser error | log, bump `reload_total{result="parse_err"}` | next reload |
| Validation error | validator error | log, bump `validate_err` | next reload |
| Compilation key collision | compiler error | log with rule ids | next reload |
| Hugepage OOM during build | malloc fail in builder | log, bump `oom` | operator intervention |
| Reload timeout (stuck worker) | `rcu_check` timeout | bump `timeout`, defer old-ruleset free, continue | watchdog kills stuck worker |
| Mempool exhausted | `rte_pktmbuf_alloc` NULL | drop packet, bump `port_rx_dropped{reason="nombuf"}` | self-resolves |
| TX ring full | `rte_eth_tx_burst` < n | bulk-free unsent, bump `port_tx_dropped` | self-resolves |
| Redirect TX full | `rte_eth_tx_burst` on redirect port < n | bulk-free, bump `redirect_dropped_total` | self-resolves |
| NIC link down | poll from telemetry thread | gauge `pktgate_port_link_up=0`, alert | auto when link returns |
| Worker stall | heartbeat counter stuck | systemd `WatchdogSec` `SIGABRT`, restart, then bypass after K crashes | automatic |
| Process crash | systemd notice | restart with backoff | bypass on repeat |
| Bypass mode triggered | watchdog policy | software forward-only (other variants available) | operator |
| PCI error | `rte_eth_dev_get_status` | log fatal, exit, watchdog restarts | manual |
| Reload mid-shutdown | shutdown flag set during reload | abort reload, free, exit clean | n/a |
| sFlow encoder failure | telemetry-thread exception | log, restart sFlow exporter, dataplane unaffected | automatic |

### 11.1 HA / architectural anti-patterns (D5)

These are **architectural constraints**, not warnings. The design
**must not** contain any of the following:

- **No host ID baked into rule semantics**. Two instances running
  the same config must produce identical verdicts from the same
  input.
- **No wall-clock in packet matching**. `rte_rdtsc` delta is fine
  (relative); `gettimeofday` / `CLOCK_REALTIME` is not.
- **No global state outside the process**. No `/var/run/pktgate.state`,
  no on-disk mutable state read by the hot path, no cross-process
  shared memory.
- **No PCI BDF in the rule file**. Rules reference interfaces by
  logical role; per-host role-to-port binding lives in its own
  config surface.
- **Deterministic reload ordering**. Concurrent reload events are
  serialized and processed in a stable order. The ruleset produced
  by processing a given config file depends only on the file, not
  on timing.

These constraints keep HA (warm-standby, active/standby pairs) an
open possibility. HA mechanics (failover triggering, traffic
steering, split-brain detection) are external to this process.

## 12. Test strategy

### 12.1 Test matrix

| Test type | Where | Blocks release? | Tooling |
|---|---|---|---|
| Unit (parser / validator / compiler) | dev VM, CI | yes | gtest |
| JSON schema conformance | dev VM, CI | yes | gtest + nlohmann/json schema validator |
| Ruleset builder unit | dev VM, CI | yes | gtest, EAL standalone |
| Functional dataplane on `net_pcap` vdev | dev VM, CI | yes | pytest + scapy |
| BURST_SIZE / dynfield / hot reload integration | dev VM, CI | yes | gtest with `net_null` + `net_pcap` |
| Stress: full-size rulesets + 1000 reloads | dev VM, CI nightly | yes | custom harness |
| Fuzzing: config parser, rule compiler | CI nightly | no | libFuzzer |
| Sanitizers (ASAN/UBSAN/TSAN) | dev VM, CI | yes | CMake build flavor |
| Line-rate throughput at 64 B / IMIX / 1500 B | lab hardware | yes for production release | TRex |
| Latency p50 / p99 / p99.9 | lab hardware | yes | TRex + HW timestamping |
| 24-hour soak | lab hardware | yes | TRex |
| Hot reload during traffic (no drop) | lab hardware | yes | TRex + scripted reload generator |
| Watchdog crash recovery | lab hardware | yes | fault injection |

The dev VM cannot validate throughput SLOs. Lab hardware (TRex
against E810/XL710) is the gating release test. All correctness
must pass in CI before lab time is requested. Dev VM limitations
(single-queue, e1000) do not reduce the architecture's surface —
they only reduce what is exercised in CI.

### 12.2 Per-phase exit criteria

See §14.

## 13. Project structure

```
pktgate-dpdk/
├── CMakeLists.txt                    ← top-level (uses pkg-config libdpdk)
├── README.md
├── ARCHITECTURE.md
├── CONFIG.md                         ← schema, metrics, operator docs
├── config-schema.json                ← JSON Schema for the new clean schema
│
├── include/pktgate/
│   ├── ruleset.h
│   ├── action.h
│   ├── limits.h                  ← N_PORTS_MAX, MAX_BURST (§4.2)
│   └── version.h
│
├── src/
│   ├── main.cpp
│   ├── eal/
│   │   └── port_init.{cpp,h}
│   ├── config/
│   │   ├── parser.{cpp,h}
│   │   ├── validator.{cpp,h}
│   │   ├── sizing.{cpp,h}
│   │   └── model.h
│   ├── compiler/
│   │   ├── object_compiler.{cpp,h}
│   │   └── rule_compiler.{cpp,h}
│   ├── ruleset/
│   │   ├── builder.{cpp,h}
│   │   └── ruleset.cpp
│   ├── gen/
│   │   └── gen_manager.{cpp,h}
│   ├── rl_arena/
│   │   └── rl_arena.{cpp,h}
│   ├── dataplane/
│   │   ├── worker.{cpp,h}
│   │   ├── classify_l2.h
│   │   ├── classify_l3.h
│   │   ├── classify_l4.h
│   │   ├── action_dispatch.h
│   │   └── lcore_counter.h       ← relaxed_bump / relaxed_add (§4.3)
│   ├── action/
│   │   ├── mirror.{cpp,h}
│   │   ├── ratelimit.{cpp,h}
│   │   └── tag.{cpp,h}
│   ├── telemetry/
│   │   ├── prom.{cpp,h}
│   │   ├── sflow.{cpp,h}
│   │   ├── rte_tel.{cpp,h}
│   │   └── log.{cpp,h}
│   ├── ctl/
│   │   ├── inotify.{cpp,h}
│   │   ├── cmd_socket.{cpp,h}
│   │   └── watchdog.{cpp,h}
│   └── util/
│       ├── numa.h
│       └── perf.h
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── stress/
│
├── functional_tests/
├── fuzz/
├── systemd/
├── scripts/
└── docs/
```

CMake targets:

- `pktgate_dpdk` — main binary
- `libpktgate_core.a` — parser/validator/compiler/ruleset/gen (DPDK-
  free where possible); fast unit tests link against this
- `libpktgate_dp.a` — dataplane code requiring DPDK
- `pktgate_dpdk_test_*` — gtest binaries
- `pktgate_dpdk_fuzz_*` — fuzz harnesses

**Build (D2)**: `cmake -B build && cmake --build build -j`.
Language baseline **C++20**; C++23 idioms welcome where they bring
real value (`std::expected`, `std::flat_map`, `std::print`,
deducing `this`); C++26 is not targeted but not forbidden.
Compiler: gcc ≥ 14 or clang ≥ 18, selected by the implementer —
CMake does not hardcode a compiler.

**Mandatory warning flags** (enforced as errors in CI):

- `-Wall -Wextra -Wpedantic -Werror`
- `-Wswitch-enum` — every enum-typed `switch` must enumerate all
  values; adding a new `Verdict` or `ActionVerb` without updating
  the dispatcher in §5.5 is a compile error. Defends against the
  same class of state-machine cliff that earlier review iterations
  caught at the architecture level.
- `-Wshadow -Wconversion -Wsign-conversion -Wnon-virtual-dtor`
- `-Wundef -Wcast-align -Wuninitialized -Wnull-dereference`
- ASAN/UBSAN/TSAN as separate build flavors via CMake presets.

**Test-only build flavour (Q9).** A `-DPKTGATE_TESTING=1` cmake
option exposes **test hooks** that must NEVER be present in a
release build: deterministic RNG seed override for the sample-rate
RNG, a force-shrink knob on the mempool sizer, a classify-stage
fault-injection site (deliberate `TERMINAL_DROP` for a named
rule_id), and an `accept(2)` path that bypasses `SO_PEERCRED` for
a test UID allow-list. The CMake preset `dev-testing` enables it;
the `release` preset asserts `PKTGATE_TESTING` is undefined via
`static_assert` so no accidental shipment is possible. Functional
and chaos test plans rely on these hooks; see
`test-plan-drafts/functional.md` H2 / H3.

**Test companion user (Q9).** Functional / chaos tests that
exercise D38 SO_PEERCRED differentiation use a secondary
system user `pktgate_test2` alongside the primary `pktgate` user.
Under `PKTGATE_TESTING`, the allow-list parser accepts a
`cmd_socket.test_allow_uids` list read from the config; under a
release build that key is rejected by the validator (`unknown
field` error). The systemd unit files for tests provision both
users in the `[Service]` stanza; release units create only
`pktgate`.

## 14. Phase plan

### 14.1 Phase 1 (MVP) — exit criteria

*Phase 1 implementation scope is tracked in `implementation-plan.md`;
any divergence in the bullets below is indicative, not authoritative.
Per the 2026-04-16 scope trim: M10 ships Prometheus-only (structured
JSON logs deferred), M11 ships inotify-only (UDS command socket
deferred).*

**Architectural features that ship in Phase 1**:

- EAL bring-up, two-port inline forwarding scaffolding
- New clean JSON schema (no legacy pktgate compatibility, D8)
- Parser + validator + compiler for the full L2 / L3 / L4 pipeline
- Ruleset builder for L2 (compound), L3 (IPv4 dst-prefix primary,
  IPv6 dst-prefix primary, VRF), L4 (compound primary + filter_mask
  over exact fields and explicit port lists)
- Single process-wide `g_active` atomic with RCU-QSBR hot reload
  (D9) and bounded `rcu_check + timeout` on reload (D12)
- Per-lcore rate-limit arena with rule_id stability across reloads,
  Variant A (split rate equally across active lcores) (D1 / D10)
- Arena GC diff on reload (D11)
- Six actions: allow, drop, rate-limit, tag (DSCP in IPv4 ToS /
  IPv6 traffic class; PCP rewrite on VLAN-tagged frames, no-op on
  untagged with counter), redirect (per-port staged drain with
  burst-end flush, D16)
- **Mirror action**: schema is complete (D7). Compiler **rejects
  rules with `action: mirror` at publish time with a clear error**
  message in Phase 1; the dataplane mirror path is validated in
  Phase 2.
- Fragment policy `l3_only | drop | allow`, default `l3_only` (D17)
- IPv6: first-protocol-only (no extension-header chain walking),
  extension-header packets marked L4-unclassifiable with counter
  `l4_skipped_ipv6_extheader` (D20 / P8)
- Interface-role abstraction and `--standby` park mode (D5)
- Sizing config (file or CLI), runtime-sized capacity arrays (D6)
- Run-to-completion worker, symmetric Toeplitz RSS, single CPU
  socket (NUMA)
- Inotify directory-watch reload trigger with 150 ms debounce
- UDS command socket: `reload`, `status`, `dump-config`, `dump-rule`,
  `activate`
- Telemetry counting + aggregation model complete; export channels
  shipping in Phase 1: **Prometheus** and **structured JSON logs**
  (sFlow and `rte_telemetry` deferred to Phase 2 as architectural
  capability validated on lab hardware)
- systemd unit + watchdog + heartbeat
- Software forward-only bypass mode
- Functional test suite running on dev VM `net_pcap`
- Unit + integration + stress tests in CI
- Sanitizer-clean build
- Documentation: ARCHITECTURE.md, CONFIG.md, METRICS.md

**Phase 1 exit criteria**:

1. Functional pytest+scapy suite green on `net_pcap` vdev.
2. ASAN/UBSAN clean.
3. Hot reload survives 1000 reload cycles under traffic in dev VM
   (loss = 0).
4. Stress test with production-target-sized rulesets
   (4096 L2 + 16384 L3 + 4096 L4) compiles in ≤ 50 ms.
5. Lab run on TRex against E810/XL710 sustains 40 Gbps bidirectional
   with 64 B packets, < 0.01 % loss, p99 latency < 50 µs added —
   for at least one configuration with ≥ 100 active rules per layer.
6. Watchdog crash test: `kill -9` the dataplane during traffic;
   traffic resumes within 5 s.

**Phase 1 explicitly does NOT ship**:

- The mirror dataplane path (schema accepted, compiler rejects)
- L4 `src_port_range` / `dst_port_range` (non-goal for Phase 1)
- IPv6 extension-header chain walking
- QinQ (double-tagged) L2 (`l3_offset = 22` code path kept hollow)
- Hardware offload via `rte_flow` (feature compiled, disabled by
  config — no `rte_flow_create` calls)
- Refcount-based zero-copy mirror
- Multi-socket NUMA topology
- Kernel driver fallback bypass
- Hardware bypass NIC integration
- Rate-limit adaptive rebalancer (Variant B from D1)
- sFlow exporter (architectural; shipping in Phase 2)
- `rte_telemetry` exporter (architectural; shipping in Phase 2)
- TCP flags matching at L4 (schema accepts; compiler emits warning
  that field is ignored until Phase 2)
- YAML config, gRPC push, HTTP push (permanently out of scope for
  this binary)

### 14.2 Phase 2 (v2)

- Mirror dataplane path, starting with deep-copy `rte_pktmbuf_copy`,
  then optional refcount zero-copy with a NIC compatibility table.
  **Phase exit criterion**: cycle budget validated on lab hardware
  with mirror-heavy workloads before mirror is declared production
  ready (was design.md v1 risk #2; moved here as a gate).
- L4 `src_port_range` / `dst_port_range`, via a second-tier linear
  scan over ranged rules or an `rte_acl` sidecar
- IPv6 extension-header chain walking (up to K hops), bounded and
  per-lcore counter-observed (`l4_skipped_ipv6_extheader` decreases
  as demand drops)
- QinQ (double-tagged) L2 matching (`l3_offset = 22`)
- TCP flags matching at L4
- Multi-socket NUMA support
- Mirror-mode fallback bypass
- Kernel driver fallback bypass (slow path)
- sFlow v5 exporter (embedded encoder)
- `rte_telemetry` endpoint wiring
- Rate-limit adaptive rebalancer (Variant B from D1): control
  thread samples per-lcore utilization every ~100 ms and
  redistributes quota; hot path unchanged
- Hardware offload via `rte_flow`: operator-hint-driven (D4) on
  E810-class NICs, with graceful fallback and software fallback
  tables always present
- YAML → JSON pre-processor (no core changes)
- Per-flow rate-limit (5-tuple keyed) — reuses the already-shipped
  symmetric RSS

### 14.3 Phase 3 (v3)

- Hardware bypass NIC integration (Silicom, Napatech, …)
- Hot-standby active/standby pair across nodes (uses interface-role
  abstraction and `--standby` park mode already shipped in Phase 1)
- Hardware offload with automatic topological promotion (P7 decision
  point; architecture hooks are identical to operator-hint)
- Telemetry pipeline integrated with NOC orchestrator
- Migration tool: pktgate (XDP) ↔ pktgate-dpdk runtime swap
- Schema v2 with explicit migration shims

### 14.4 Open phase-plan question

- **P7** (rte_flow automatic topological offload promotion): v2 or
  v3? The architectural hooks — rule tiering, dual-path dataplane,
  graceful fallback — are identical either way. The only difference
  is compiler complexity and the amount of automatic analysis the
  optimizer performs. Deferred to the next phase-plan discussion.

## 15. Risk register

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| 1 | `rte_fib` / `rte_fib6` memory at the high end of the sizing targets blows the hugepage budget | medium | high | Measure RSS with `scenarios_v2/` prefix mix early in Phase 1; fall back to `rte_lpm6` for v6 if > 256 MiB; tune `RTE_FIB_DIR24_8_GROUPS`. Decision point in Phase 1 week 2. |
| 2 | Compound L2 or L4 rules with rare primary keys cause cache thrash | low | medium | Compiler chooses primary by selectivity; secondary check is a single hot cache line; profile in stress test. |
| 3 | Hot reload of large IPv6 ruleset exceeds 100 ms | medium | medium | `rte_fib6` build dominates. Parallelize prefix insertion inside `ruleset_build`; if still slow, raise SLO to 250 ms. |
| 4 | Lab hardware (E810/XL710) availability gates release | high | high | Reserve TRex windows at Phase 1 start. Cross-test on `pktgen-dpdk` from a second host. |
| 5 | Cycle-budget tightness on realistic workloads (see §5.6) reduces headroom below what feels comfortable when adding new features | medium | medium | Any new per-packet work must come with a cycle estimate; hot-path reviews are required on changes to §5. |
| 6 | Refcnt-mirror is enabled while the active ruleset contains a payload-mutating verb (TAG today; future NAT / header rewrite) — mirror destination receives bytes corrupted by the mutation | low | high | **D26**: compile-time gate in `ruleset_builder` selects `deep_copy` whenever any rule's verb ∈ `MUTATING_VERBS` or the destination driver lacks `tx_non_mutating`. Whole-ruleset property, evaluated once per Ruleset build, hot path is non-branching. Adding a new mutating verb requires updating `MUTATING_VERBS` — enforced by `-Wswitch-enum` coverage (§13) plus a unit test that scans the verb enum. See §5.5 MIRROR case for the full gate. |
| 7 | `fragment_policy=l3_only` treats first vs subsequent IPv6 fragments asymmetrically — first fragment runs the full L4 chain (port/flag matching against the inner header carried after the Fragment ext), subsequent fragments take the `SKIP_L4` path. A rule author who expects "fragment = no L4" gets surprising behaviour when the first fragment matches an L4 rule. | low | medium | **D27**: documented in §5.3 IPv6 block as the explicit semantics — matches IPv4 behaviour where the first fragment also carries L4 headers and is matchable. The dynfield carries `l4_extra = 8` for IPv6 first fragments so §5.4 advances past the Fragment ext correctly; non-first fragments set `verdict_layer = SKIP_L4`. Operator-facing docs in §3a.1 must call out that L4 rules apply only to first fragments under `l3_only`. The `l4_skipped_ipv6_fragment_nonfirst` counter (§10.3) makes the asymmetry observable. Strict-symmetry deployments should set `fragment_policy=drop`. |

> Risk "mirror cycle budget" from design.md v1 is **not** a current
> risk; mirror does not ship in Phase 1. It is encoded in §14.2 as
> a phase-exit criterion instead.
>
> Risk "rate-limit atomic contention" from design.md v1 is **not**
> applicable: the per-lcore token-bucket model (D1 / D10) has zero
> atomics on the hot path.

## 16. Unresolved questions

All twelve open questions in `input.md` §5 are resolved in the body
of this document. Two verification items (owned by the implementer,
not blocking design approval):

- **`rte_fib6` actual memory at 16 384 prefixes** — verify the
  worst case against real scenarios early in Phase 1.
- **`rte_telemetry` link footprint** — measure.

Phase-plan-level open question:

- **P7** — rte_flow automatic promotion: v2 or v3. Does not block
  architecture.

## 17. Appendix: pktgate (XDP) → pktgate-dpdk semantic inheritance table

| pktgate (XDP) lesson | DPDK design | Status |
|---|---|---|
| First-match-wins per layer, no priority field | Same | KEPT |
| Port group and object expansion at compile time | Same | KEPT |
| Compound L2: selectivity-ranked primary + `filter_mask` bitmap secondary (precedence `src_mac > dst_mac > vlan > ethertype > pcp`) | Same, directly reused at L2; **also extended to L4** (D15) with primaries `(proto,dport) > (proto,sport) > proto` | KEPT + EXTENDED |
| Drop IPv4 non-first fragments and IPv6 fragment headers at L3 | Generalized to `fragment_policy` config field with `l3_only` default (D17) | KEPT, SOFTENED |
| Dual-stack IPv4 + IPv6 from day one | Same | KEPT |
| Double-buffered hot reload with drain window | Replaced by single global atomic pointer under `rte_rcu_qsbr` (D9) | UPGRADED |
| inotify on directory, not file | Same | KEPT |
| 4-program BPF pipeline with tail calls | Replaced by a single inlined C++ classify chain (no verifier limits) | REPLACED |
| `PERCPU_HASH` token bucket with `rate/NCPU` | Kept as the **universal fast-path pattern**: per-lcore bucket, zero atomics, cache-isolated (D1 / D10). Aggregate rate is split across active lcores at publish; Variant B (adaptive rebalancer) is a phase plan item. | KEPT, REFRAMED |
| TC companion program for mirror/tag | All actions live in one process (DPDK has `rte_pktmbuf_copy`, `rte_mbuf_refcnt_update`, direct byte rewrites) | COLLAPSED |
| LPM trie key `{prefixlen, addr}` byte layout | Replaced by `rte_fib` / `rte_fib6` opaque API (D8: no ABI to preserve) | REPLACED |
| 4096-rule per-layer ceiling | Runtime-sized (D6) with 4096 as the production target; dev default 256 | GENERALIZED |
| `BPF_PROG_TEST_RUN` for dataplane unit tests | DPDK `net_null` + `net_pcap` vdevs | REPLACED |
| JSON config schema compatibility | **Dropped** — clean purpose-built schema (D8) | DROPPED |

---

## Writer notes

### Batch-revision steps applied

All 24 steps from the `review-notes.md` Batch revision plan were
applied (step numbers match the plan where it gives them).

| Step | Decision | Where in v2 | Notes |
|---|---|---|---|
| 1 | M2 structural pass | all sections §1–§13 | All "MVP / v2 / Phase" hits moved to §14. §5.3 IPv6 text, §14 mirror text, and §14 offload text carry the M2-safe separation: architecture describes full model; §14 gives shipping schedule. |
| 2 | M1 principle | §1.1, §8.4, §12 | Explicit "dev VM does not shape architecture"; dev-vs-prod sizing table in §8.4. |
| 3 | D1 rate-limit rewrite | §4.4, §5.5 RL case, §5.6, §14.1, §14.2, §15, §17 | Per-lcore TokenBucket[] with lazy TSC refill, zero atomics. |
| 4 | D2 C++ | §13 | C++20 baseline, C++23 welcome, compiler unconstrained. |
| 5 | D3 telemetry | §4.3, §10.1–10.2 | Full counting + aggregation + four export channels architecturally; channel shipping schedule in §14. |
| 6 | D4 hw offload | §3a.1, §4.1, §5.2 (FDIR branch), §9.5, §14 | Rule tiering, dual-path, `rte_flow_create` at publish, graceful fallback, software tables always authoritative. |
| 7 | D5 HA compat | §3a, §6.1, §11.1, §14.3 | Interface roles, `--standby`, anti-patterns as architectural constraints. |
| 8 | D6 sizing | §3a.1, §4.1, §4.3, §8.4, §14 | Runtime-sized everything, dev vs prod columns, hard min 16/layer. |
| 9 | D7 mirror | §3a.1, §5.5, §14.1, §14.2, §15 | Schema describes mirror fully, compiler rejects in Phase 1, cycle-budget validation is a Phase 2 exit criterion. |
| 10 | D8 clean schema | §3a, §9, §17 | New schema, no pktgate compat, `version`, `interface_roles`, `fragment_policy`, `hw_offload_hint`, sizing section. |
| 11 | Consistency pass | (implicit) | §1 summary, §17 table, §14 scope all mutually consistent. |
| 12 | Diff summary | returned in report | see below |
| 13 | D9 global `g_active` | §4.2 (field removed), §4.5, §5.1, §6.1, §6.4, §9.2 | Single process-wide atomic in `ControlPlaneState`. |
| 14 | D10 per-lcore bucket arena (reinforces D1) | §4.4, §5.5 | Two-level mapping `rl_actions → rule_id → TokenBucket[RTE_MAX_LCORE]`. |
| 15 | D11 arena GC ordering | §9.2, §9.4 | Explicit six-step sequence, no second synchronize, rule_id verbatim policy documented. |
| 16 | D12 RCU polish | §5.1 (offline/unregister), §9.2 (`rcu_check + timeout`), §11 (watchdog backstop) | Bounded reload + `reload_timeout` error path. |
| 17 | D13 `l3_offset` dynfield | §5.1 (dynfield schema), §5.2 (set), §5.3 / §5.4 (consume) | QinQ noted as architectural (offset 22); §14 keeps it phase-plan. |
| 18 | D14 L4 offset via IHL | §5.4 | Also IPv6 fixed-40 with P8 first-protocol-only behaviour and `SKIP_L4` path. |
| 19 | D15 L4 compound | §4.1 L4 block, §5.4 | Three primaries in selectivity order + `L4CompoundEntry` filter_mask. Ranges called out as phase-plan non-goal. |
| 20 | D16 REDIRECT staging | §4.2 (`redirect_tx`), §5.5 REDIRECT case, §5.5 drain, §10.3 metric | Mirror uses the same staging shape. |
| 21 | D17 fragment policy | §3a.1, §5.3 IPv4 block, §14.1 | `l3_only` default per P9; `drop`/`allow` explicit. |
| 22 | D18 min/typ/max budget | §5.6 | Realistic typical ~201 cycles, honest "within budget, not substantial headroom". |
| 23 | D19 misc | §5.1 `handle_idle`, §5.3 `rte_fib_lookup` (single), §5.3 src-prefix block completed, §5.5 TAG semantics, §5.6 triple-pass note | Triple-pass-over-burst called out as a conscious choice in §5.1 code comments. |
| 24 | D20 IPv6 ext-header scope | §5.3 IPv6 block, §14.1 / §14.2, §10.3 counter | Architecture describes full walk; Phase 1 ships first-protocol-only with `l4_skipped_ipv6_extheader` counter. |

### New issues noticed while writing (do NOT fix — flag for next round)

- **N1**. The `RlAction` struct in §4.1 uses a named nested
  `rl_actions` array, but the pseudocode later refers to
  `rs->rl_actions[a->rl_index]`. The field name is consistent, but
  the section does not describe the "rule_id → slot" perfect-hash
  build step that the arena needs in order to remain dense across
  reloads. The arena section (§4.4) hand-waves `id_to_slot` as an
  `rte_hash`; the compile-time details of slot reuse on reload
  (so that freed slots become available for new rules) deserve an
  explicit paragraph. Suggest next-round expansion of §9.4 step 5.

- **N2**. §5.3 IPv4 fragment detection checks both `MF` and offset
  bits to declare `is_frag`, but `FRAG_L3_ONLY` only sets
  `SKIP_L4` when `is_nonfirst` is true — first-fragment packets
  still get L4-parsed. That is the correct behaviour for
  `l3_only` (first fragment has the L4 header), but the block
  would benefit from a comment spelling out the asymmetry. The
  architecture is correct; the exposition can be clearer.

- **N3**. The `--standby` park mode's exact mechanism (link-down
  vs start-and-don't-launch-workers) is listed as an option, not
  a decision. §6.1 says "link-down or non-start". This is a
  legitimate implementation choice but §14.3 (HA v3) depends on
  it being consistent; may deserve a decision entry.

- **N4**. §10.1 says the snapshot ring buffer has N generations
  default 4; the number was picked without justification.
  Realistically N=2 is enough (writer + reader); N=4 is safe but
  overkill. Worth a passing sentence of rationale or changing to 2.

- **N5**. The interface_roles example at §3a.1 uses `{"pci": ...}`
  as the only selector; DPDK also supports name-based binding and
  `net_vdev`. For dev VM (net_pcap, net_null) the `pci` selector
  will not work. Architecturally the selector should be a sum
  type — `{pci: …}` | `{vdev: …}` | `{name: …}`. The current
  schema example is too narrow. Phase-plan-level detail.

- **N6**. The triple-pass-over-burst choice (L2 / L3 / L4 in
  separate loops) has a subtle interaction with D16 redirect
  staging: a REDIRECT rule at L2 means the packet is staged in
  `redirect_tx` but still walks through L3/L4 classification
  loops as a "no-op" because its `verdict_layer` is already
  terminal. The current §5.1 pseudocode correctly skips the
  classify steps by checking `verdict_layer` at the top of each
  loop, but the action dispatcher is only called once. This is
  correct and efficient; I note it only because the
  triple-pass-vs-fused-per-packet trade-off was mentioned in D19
  and deserves its own microbench when it gets implemented.

### Steps not skipped

None. All 24 plan steps were applied.

### Structural choices

- **I did not restructure the 17-section outline.** The section
  numbering follows design.md v1 plus one addition (§3a
  Configuration schema) which is a subsection, not a renumber.
  This keeps the reviewer's side-by-side diff tractable.
- **Rate-limit Variant B** is in §14.2 as a phase-plan item only,
  per rule 6.
- **Hardware offload** is described architecturally in §3a, §4.1,
  §5.2, §9.5 with shipping status in §14.
- **Mirror** is described architecturally in §3a, §5.5 with a
  compiler reject in §14.1 and lab-exit criterion in §14.2.
- **`--standby`** mode is architectural (§6.1), HA is §14.3.

### Diff scope summary (for parent)

design.v2.md is a full rewrite of design.md v1 applying all 24
batch-revision steps. Critical correctness fixes land in §5.3
(L3 offset, fragment policy, IPv6 ext-header handling), §5.4 (L4
IHL, compound primary + filter_mask model), §5.5 (REDIRECT
staging, TAG semantics, rate-limit rewrite), §4.4 / §4.5 (per-
lcore rate-limit arena, single global `g_active`), and §9.2 / 9.4
(reload sequencing with arena GC). §3a is a clean new JSON
schema with no legacy compatibility. §10 describes the full
telemetry counting/aggregation model as architecture and leaves
channel shipping to §14. §14 is the single home of all Phase 1 /
Phase 2 / Phase 3 scoping decisions; §§1–13 contain no "MVP / v2 /
Phase" statements, satisfying M2. §1.1 and §8.4 encode M1 (dev
VM does not shape architecture). The 17-section outline is
preserved to keep the diff reviewable.
