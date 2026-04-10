Good — I now have a clear picture of pktgate's compound L2 algorithm: pick the most selective field as primary key for the hash, and use a `filter_mask` bitmap to enforce remaining secondary fields after the lookup. The selectivity precedence is `src_mac > dst_mac > vlan > ethertype > pcp`.

I have enough context. Now let me note my critical constraint: **I cannot write files in this read-only sandbox**. The user asked me to write to `/tmp/pktgate-dpdk-design.md` and return only a short summary. Since I cannot write files, I will produce the full design document directly in my response so the user has it, then provide the requested short structured summary at the end. This is the only way to deliver the deliverable given my read-only constraint.

I'll produce the full design content first (as a quoted block the user can save), then the short summary.

---

# pktgate-dpdk — Architecture Design Document

**NOTE TO READER**: I am operating in read-only planning mode and cannot create files on disk. The full design document is reproduced inline below; the user can save it to `/tmp/pktgate-dpdk-design.md` themselves. The short structured summary requested in the prompt follows the full document, at the very end.

---

## 1. Executive summary

`pktgate-dpdk` is a DPDK 25.11 userspace L2/L3/L4 packet filter for the GGSN–Gi interface, sustaining 40 Gbps bidirectional (worst case 59.52 Mpps) per site with sub-50 µs added p99 latency and < 0.01 % collateral loss. It runs a strict run-to-completion model with one lcore pinned per RX/TX queue pair, classifies each burst through a layered pipeline (L2 → L3 → L4) backed by `rte_hash`, `rte_fib`/`rte_fib6`, and a home-grown rule-keyed token bucket, dispatches one of six actions (`allow`, `drop`, `mirror`, `rate-limit`, `tag`, `redirect`), and updates the configuration without restart through an atomic `RCU-QSBR`-protected pointer swap targeting ≤ 100 ms reload latency with full rollback on any compilation failure. JSON configs are schema-compatible with the existing pktgate (XDP) project. The system defaults to fail-open software-forward bypass on watchdog-detected stalls, exposes Prometheus, sFlow, structured logs, and `rte_telemetry`, and is built with CMake + `pkg-config libdpdk` in C++20.

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
   │  │  (Prom/sFlow/                                        │     ││
   │  │   logs/rte_tel)                                      │     ││
   │  └──────────────────────────────────────────────────────┼─────┘│
   │                                                         │      │
   │  ────────────────────  Data Plane  ─────────────────────┼───── │
   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │      │
   │  │  lcore N    │  │  lcore N+1  │  │  lcore N+k  │      │      │
   │  │ RX q0/TX q0 │  │ RX q1/TX q1 │  │ RX qk/TX qk │      │      │
   │  │             │  │             │  │             │      │      │
   │  │ burst loop ─┼──┤ burst loop ─┼──┤ burst loop  │ ◄────┘      │
   │  │  reads      │  │  reads      │  │  reads      │  active     │
   │  │  active_rs  │  │  active_rs  │  │  active_rs  │  ruleset    │
   │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
   │         │                │                │                    │
   └─────────┼────────────────┼────────────────┼────────────────────┘
             ▼                ▼                ▼
       NIC port 0/1 RX queues          NIC port 0/1 TX queues
              (RSS spreads)                  (per-lcore)
```

Two physical NIC ports form an inline pair (port0 ↔ port1). Each port has K RX and K TX queues; lcore i owns `(port0.rxq[i], port0.txq[i], port1.rxq[i], port1.txq[i])`. RSS distributes flows. The control plane lives on non-isolated cores; the dataplane lcores never see the control thread.

## 3. Module breakdown

| Module | Responsibility | Public interface | DPDK deps |
|---|---|---|---|
| `eal_init` | EAL bring-up, port/queue/mempool configuration, NUMA placement | `bootstrap(argc, argv) → PortSet` | `rte_eal`, `rte_ethdev`, `rte_mempool` |
| `config_parser` | JSON → AST (`Config` struct) | `parse(path) → expected<Config, Err>` | none |
| `config_validator` | Semantic validation: refs, ranges, action params, collisions, schema version | `validate(Config) → expected<void, Err>` | none |
| `compiler::objects` | Expand `objects` (subnets, mac_groups, port_groups) into tables | `compile(ObjectStore) → CompiledObjects` | none |
| `compiler::rules` | Layer-2/3/4 rule flattening, compound L2 primary/secondary split, port-group expansion, key collision detection | `compile(Pipeline, CompiledObjects) → CompiledRules` | none |
| `ruleset_builder` | Materialize compiled rules into a `Ruleset` (immutable, NUMA-local) — populates `rte_hash`, `rte_fib`, port LUTs, action descriptor arrays, rate-limit state arena | `build(CompiledRules) → unique_ptr<Ruleset>` | `rte_hash`, `rte_fib`, `rte_fib6` |
| `ruleset` | Read-only data structure consumed by the hot path | `lookup_l2(...)`, `lookup_l3(...)`, `lookup_l4(...)` (all `static inline`) | none at runtime |
| `gen_manager` | RCU-QSBR registration, pointer swap, deferred free | `commit(unique_ptr<Ruleset>)` | `rte_rcu_qsbr` |
| `worker` | The lcore burst loop | `run(WorkerCtx*)` invoked via `rte_eal_remote_launch` | `rte_ethdev`, `rte_mbuf`, `rte_rcu_qsbr` |
| `actions` | Mirror, rate-limit, tag, redirect implementation primitives | `static inline` action handlers | `rte_mbuf`, `rte_ip` |
| `mirror` | Mirror queue, refcount-based clone, fallback to deep copy | `mirror_packet(mbuf, target_port)` | `rte_mbuf` |
| `ratelimit` | Per-rule token bucket, atomic operations across lcores | `consume(rule_id, len_bytes) → bool` | atomics |
| `telemetry::prom` | HTTP `/metrics` exposition on a control thread | `start(port)` | none |
| `telemetry::sflow` | sFlow datagram encoder + UDP sender (control thread) | `submit_sample(...)` from worker | none |
| `telemetry::log` | Lock-free SPSC log ring per worker, drained by control thread to JSON-lines | `LOG_INFO(...)` | none |
| `telemetry::rte_tel` | Hooks into `rte_telemetry` for `/dpdk/telemetry` UDS | `register()` | `rte_telemetry` |
| `watchdog` | Heartbeat poll, restart counters, bypass mode trigger | `tick()`, `enter_bypass()` | none |
| `cmd_socket` | Unix domain socket: `reload`, `status`, `dump-config`, `dump-rule N` | `serve()` | none |
| `inotify_loader` | Directory watch + debounce + reload trigger | `run()` | none |
| `main` | Wires modules, signal handling, control loop | `int main(...)` | all of above |

## 4. Data structures

### 4.1 `Ruleset` — the immutable compiled artifact

A `Ruleset` is the unit of hot reload. It is allocated NUMA-local on the socket of the dataplane lcores, read-only after publication, and freed only after RCU quiescence.

```cpp
struct alignas(64) RuleAction {
    uint16_t  rule_id;       // back-reference for counters
    uint8_t   verb;          // ALLOW | DROP | MIRROR | RL | TAG | REDIRECT
    uint8_t   next_layer;    // 0=terminal | 3 | 4
    uint16_t  redirect_port; // egress port idx (or 0xFFFF)
    uint16_t  mirror_port;
    uint8_t   dscp;          // 6-bit DSCP target (for TAG)
    uint8_t   pcp;           // 3-bit PCP (for TAG)
    uint16_t  rl_index;      // index into rate_limit_state[]
    uint16_t  _pad;
}; // 16 bytes — fits 4 per cache line

struct L2CompoundEntry {           // value of L2 primary hash
    uint8_t  filter_mask;          // bits: ETHERTYPE|VLAN|PCP|DST_MAC|SRC_MAC
    uint8_t  _pad;
    uint16_t want_ethertype;       // network byte order
    uint16_t want_vlan;            // host order
    uint8_t  want_pcp;
    uint8_t  _pad2;
    uint8_t  want_mac[6];          // the *other* MAC if both src and dst constrained
    uint16_t action_idx;           // index into l2_actions[]
}; // 16 bytes

struct alignas(64) Ruleset {
    // L2 lookup tables (one primary structure per match-type)
    rte_hash*       l2_src_mac;        // key = uint64_t (MAC packed) -> L2CompoundEntry idx
    rte_hash*       l2_dst_mac;
    uint16_t        l2_vlan_lut[4096]; // direct index, 0xFFFF = miss
    uint16_t        l2_ether_lut[256]; // small etype hash via folded index
    rte_hash*       l2_ether_full;     // fallback for arbitrary etypes
    L2CompoundEntry l2_compound[];     // arena of compound entries
    RuleAction      l2_actions[];      // arena of L2 actions
    uint16_t        n_l2_rules;

    // L3
    rte_fib*        l3_v4;             // DIR-24-8 trie, value = action_idx
    rte_fib6*       l3_v6;
    rte_hash*       l3_vrf;            // vrf_id -> action_idx
    RuleAction      l3_actions[];
    uint16_t        n_l3_rules;

    // L4
    rte_hash*       l4_proto_port;     // key = (proto:8 | dst_port:16 | src_port:16) packed
    RuleAction      l4_actions[];
    uint16_t        n_l4_rules;

    // Rate-limit state (lives outside Ruleset — survives reloads keyed by rule_id)
    RateLimitArena* rl_arena;          // pointer to per-process arena, see §4.4

    // Default behavior
    uint8_t         default_action;    // ALLOW or DROP

    // Generation metadata
    uint64_t        generation;
    uint64_t        compile_timestamp_ns;
};
```

**Sizing of arenas (worst case from N4):**

| Arena | Element | Count | Bytes |
|---|---|---|---|
| `l2_actions` | 16 B | 4 096 | 64 KiB |
| `l2_compound` | 16 B | 4 096 | 64 KiB |
| `l3_actions` | 16 B | 4 096 | 64 KiB |
| `l4_actions` | 16 B | 4 096 | 64 KiB |
| `rte_hash l2_src_mac` | n/a | 4 096 entries | ~256 KiB |
| `rte_hash l2_dst_mac` | n/a | 4 096 entries | ~256 KiB |
| `rte_fib v4` | n/a | 16 384 prefixes, 8-bit nexthop | ~64 MiB worst-case (DIR-24-8 trie group fan-out) |
| `rte_fib6 v6` | n/a | 16 384 prefixes | ~96 MiB worst-case |
| `rte_hash l4_proto_port` | n/a | 4 096 | ~256 KiB |
| `rte_hash l3_vrf` | n/a | 256 | ~32 KiB |
| `l2_vlan_lut` | 2 B | 4 096 | 8 KiB |

**Total Ruleset footprint (worst case): ~160 MiB.** Two live rulesets during reload: ~320 MiB. Plus mempools (§8) brings the steady-state hugepage requirement to **~2 GiB minimum** for a single-port-pair production node.

### 4.2 Per-lcore worker context

```cpp
struct alignas(64) WorkerCtx {
    // RX/TX
    uint16_t  port_a, port_b;
    uint16_t  qid;
    uint16_t  burst_size;       // 32 default

    // RCU
    rte_rcu_qsbr* qs;
    uint32_t      thread_id;

    // Active ruleset (read by reader())
    const Ruleset* _Atomic active;

    // Local stats (cache-line aligned, never shared)
    alignas(64) WorkerStats stats;

    // Per-lcore mirror TX staging
    rte_mbuf* mirror_tx_buf[BURST_SIZE];
    uint16_t  mirror_tx_n;
};
```

### 4.3 Per-rule counters

Counters are sharded **per-lcore** (no atomics on the hot path) and aggregated by the telemetry thread:

```cpp
struct alignas(64) RuleCounter {
    uint64_t pkts;
    uint64_t bytes;
    uint64_t drops;          // explicit drop action
    uint64_t rl_drops;       // rate-limit drops
    uint64_t _pad[4];
}; // exactly 64 bytes / 1 cache line

struct PerLcoreCounters {
    RuleCounter l2[N_RULES_MAX];   // 4096 * 64 B = 256 KiB per lcore per layer
    RuleCounter l3[N_RULES_MAX];
    RuleCounter l4[N_RULES_MAX];
}; // ~768 KiB per lcore worst case
```

This is large but lives in the lcore's L2/LLC; only the actively-touched indices are hot and the bulk is cold.

### 4.4 Rate-limit state arena

Rate-limit must aggregate **across all lcores** (one logical bucket per rule, not one per CPU — see "pktgate → DPDK transformations", §6.4). We use a shared arena indexed by `rl_index` from the action descriptor:

```cpp
struct alignas(64) TokenBucket {
    _Atomic uint64_t tokens;       // bytes available, fixed-point
    _Atomic uint64_t last_tsc;     // TSC of last refill
    uint64_t         rate_bytes_per_tsc; // pre-computed
    uint64_t         burst_bytes;
    uint64_t         _pad[4];
};
```

Update is a CAS loop. Contention is low because traffic for a given rule is typically RSS-local; cross-lcore contention only occurs for rules whose traffic spans queues. The arena lives outside `Ruleset` so reloads don't reset bucket state for rules that survive (matched by `rule_id`).

## 5. Hot path walkthrough

This is the load-bearing section. The worker loop runs uninterrupted on a pinned lcore.

```
           ┌─ WorkerCtx (in L1)
           │
   ┌───────▼──────────┐
   │ rte_rcu_qsbr_qs  │  ← publish quiescent state at top of every burst
   └───────┬──────────┘
           │
   ┌───────▼──────────┐
   │ rte_eth_rx_burst │  ← up to 32 mbufs from port_a queue qid
   └───────┬──────────┘
           │
   ┌───────▼──────────┐
   │ prefetch headers │  ← rte_prefetch0(mbuf->buf_addr + data_off) for next 8
   └───────┬──────────┘
           │
   ┌───────▼──────────┐
   │ classify L2      │  ← per-mbuf, fills mbuf dynfield with action_idx + verdict
   │   (compound)     │
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
   │ apply actions    │  ← drop/mirror/tag/rl/redirect on the burst
   └───────┬──────────┘
           │
   ┌───────▼──────────┐
   │ rte_eth_tx_burst │  ← surviving mbufs to port_b queue qid (and mirror)
   └───────┬──────────┘
           │
   ┌───────▼──────────┐
   │ free TX failures │  ← rte_pktmbuf_free_bulk on unsent mbufs
   └───────┬──────────┘
           │
           └─► loop
```

### 5.1 Pseudocode

```cpp
// dynfield, registered once at init:
//   uint16_t verdict_action_idx;    // index into the layer's action arena
//   uint8_t  verdict_layer;         // which layer matched (or 0xFF for default)
//   uint8_t  parsed_l3_proto;       // cached after L3 parse
//   uint16_t parsed_l4_dport;       // cached after L4 parse
//   uint16_t parsed_vlan;           // 0xFFFF if untagged
//   uint16_t parsed_ethertype;
// total: 10 bytes; fits in a single 16-byte mbuf dynfield slot

void worker_main(WorkerCtx* ctx) {
    rte_rcu_qsbr_thread_register(ctx->qs, ctx->thread_id);
    rte_rcu_qsbr_thread_online(ctx->qs, ctx->thread_id);

    rte_mbuf* rx[BURST];
    while (likely(running)) {
        // (1) Quiescent state — tells the writer this thread has no Ruleset references
        rte_rcu_qsbr_quiescent(ctx->qs, ctx->thread_id);

        // (2) Snapshot the current ruleset (acquire load)
        const Ruleset* rs = atomic_load_explicit(&ctx->active, memory_order_acquire);

        // (3) RX
        uint16_t n = rte_eth_rx_burst(ctx->port_a, ctx->qid, rx, BURST);
        if (n == 0) { handle_idle(ctx); continue; }

        // (4) Prefetch first 8 packet headers — typical L1d miss is 30-40 cycles
        for (uint16_t i = 0; i < min(n, 8); i++)
            rte_prefetch0(rte_pktmbuf_mtod(rx[i], void*));

        // (5) Layer 2 classify
        for (uint16_t i = 0; i < n; i++) {
            if (i + 8 < n) rte_prefetch0(rte_pktmbuf_mtod(rx[i+8], void*));
            classify_l2(rs, rx[i]);
        }

        // (6) Layer 3 classify (only those that proceeded)
        for (uint16_t i = 0; i < n; i++) {
            if (mbuf_dyn(rx[i])->verdict_layer == NEXT_L3) classify_l3(rs, rx[i]);
        }

        // (7) Layer 4
        for (uint16_t i = 0; i < n; i++) {
            if (mbuf_dyn(rx[i])->verdict_layer == NEXT_L4) classify_l4(rs, rx[i]);
        }

        // (8) Apply actions, build TX/MIRROR/FREE lists
        rte_mbuf* tx[BURST]; uint16_t tx_n = 0;
        rte_mbuf* fr[BURST]; uint16_t fr_n = 0;
        ctx->mirror_tx_n = 0;
        for (uint16_t i = 0; i < n; i++)
            apply_action(ctx, rs, rx[i], tx, &tx_n, fr, &fr_n);

        // (9) TX
        if (tx_n) {
            uint16_t sent = rte_eth_tx_burst(ctx->port_b, ctx->qid, tx, tx_n);
            if (unlikely(sent < tx_n))
                rte_pktmbuf_free_bulk(&tx[sent], tx_n - sent);
        }
        if (ctx->mirror_tx_n) {
            uint16_t s = rte_eth_tx_burst(ctx->mirror_port, ctx->qid,
                                          ctx->mirror_tx_buf, ctx->mirror_tx_n);
            if (unlikely(s < ctx->mirror_tx_n))
                rte_pktmbuf_free_bulk(&ctx->mirror_tx_buf[s],
                                      ctx->mirror_tx_n - s);
        }
        if (fr_n) rte_pktmbuf_free_bulk(fr, fr_n);
    }
}
```

### 5.2 Layer 2 classifier (compound primary + filter mask)

```cpp
static inline void classify_l2(const Ruleset* rs, rte_mbuf* m) {
    auto* eth = rte_pktmbuf_mtod(m, rte_ether_hdr*);

    // Parse VLAN if present (single-tagged 802.1Q only; QinQ → no-VLAN match)
    uint16_t etype = eth->ether_type;
    uint16_t vlan  = 0xFFFF;
    uint8_t  pcp   = 0;
    void*    l3hdr = eth + 1;
    if (etype == RTE_BE16(RTE_ETHER_TYPE_VLAN)) {
        auto* vh = (rte_vlan_hdr*)(eth + 1);
        uint16_t tci = rte_be_to_cpu_16(vh->vlan_tci);
        vlan = tci & 0x0FFF;
        pcp  = (tci >> 13) & 0x7;
        etype = vh->eth_proto;
        l3hdr = vh + 1;
    }
    auto* dyn = mbuf_dyn(m);
    dyn->parsed_vlan      = vlan;
    dyn->parsed_ethertype = etype;

    // Selectivity order: src_mac > dst_mac > vlan > ethertype > pcp
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
    // ethertype direct + fallback hash, then pcp ... (see §3 of pktgate analog)

    // L2 miss: proceed to L3
    mbuf_dyn(m)->verdict_layer = NEXT_L3;
}
```

`rte_hash_lookup_bulk` is used in a future optimization; the simple per-mbuf path is the MVP because compound L2 rules require sequential primary attempts in order of selectivity, which doesn't fit a single bulk call.

### 5.3 Layer 3 classifier

```cpp
static inline void classify_l3(const Ruleset* rs, rte_mbuf* m) {
    auto et = mbuf_dyn(m)->parsed_ethertype;
    void* l3 = rte_pktmbuf_mtod_offset(m, void*,
                 (et == RTE_BE16(0x8100) ? 18 : 14));

    if (et == RTE_BE16(RTE_ETHER_TYPE_IPV4)) {
        auto* ip = (rte_ipv4_hdr*)l3;
        // Drop non-first fragments — no L4 header to inspect
        if (unlikely((ip->fragment_offset & RTE_BE16(0x1FFF)) != 0)) {
            mbuf_dyn(m)->verdict_layer = TERMINAL_DROP;
            return;
        }
        uint32_t da = rte_be_to_cpu_32(ip->dst_addr);
        uint64_t nh; // next-hop = action_idx
        rte_fib_lookup_bulk(rs->l3_v4, &da, &nh, 1);
        if (nh != FIB_DEFAULT_NH) { dispatch_l3(rs, m, (uint16_t)nh); return; }
        // try src? (we use a separate FIB for src-prefix rules; see "compound L3" note)
        mbuf_dyn(m)->parsed_l3_proto = ip->next_proto_id;
        mbuf_dyn(m)->verdict_layer   = NEXT_L4;
    } else if (et == RTE_BE16(RTE_ETHER_TYPE_IPV6)) {
        // similar with rte_fib6_lookup
    } else {
        // not IP — terminal pass per default
        mbuf_dyn(m)->verdict_layer = TERMINAL_PASS;
    }
}
```

Compound L3 rules (src-and-dst, or VRF-and-IP) are flattened by the compiler into the same primary/secondary pattern as L2: pick the most-selective field (preferring `dst_ip` over `src_ip` because dst-prefix tries are more discriminating in operator traffic), put it in a `rte_fib`, and store the auxiliary constraints inline in the action descriptor for post-lookup verification.

### 5.4 Layer 4

```cpp
static inline void classify_l4(const Ruleset* rs, rte_mbuf* m) {
    auto* dyn = mbuf_dyn(m);
    if (dyn->parsed_l3_proto != IPPROTO_TCP && dyn->parsed_l3_proto != IPPROTO_UDP) {
        dyn->verdict_layer = TERMINAL_PASS; return;
    }
    auto* l3 = ip_header(m);
    auto* l4 = (rte_udp_hdr*)((uint8_t*)l3 + 20); // TODO ip_hl
    uint64_t key = ((uint64_t)dyn->parsed_l3_proto << 48)
                 | ((uint64_t)l4->dst_port      << 32)
                 | (uint64_t)l4->src_port;
    int idx = rte_hash_lookup(rs->l4_proto_port, &key);
    if (idx >= 0) { dyn->verdict_action_idx = (uint16_t)idx; dyn->verdict_layer = TERMINAL_L4; }
    else          { dyn->verdict_layer = TERMINAL_PASS; }
}
```

### 5.5 Action dispatch

```cpp
static inline void apply_action(WorkerCtx* ctx, const Ruleset* rs, rte_mbuf* m,
                                rte_mbuf** tx, uint16_t* tx_n,
                                rte_mbuf** fr, uint16_t* fr_n) {
    auto*       dyn = mbuf_dyn(m);
    const RuleAction* a;
    if      (dyn->verdict_layer == TERMINAL_L2)   a = &rs->l2_actions[dyn->verdict_action_idx];
    else if (dyn->verdict_layer == TERMINAL_L3)   a = &rs->l3_actions[dyn->verdict_action_idx];
    else if (dyn->verdict_layer == TERMINAL_L4)   a = &rs->l4_actions[dyn->verdict_action_idx];
    else if (dyn->verdict_layer == TERMINAL_PASS) { tx[(*tx_n)++] = m; return; }
    else if (dyn->verdict_layer == TERMINAL_DROP) { fr[(*fr_n)++] = m; return; }

    counter_inc(ctx, dyn->verdict_layer, a->rule_id, m->pkt_len);

    switch (a->verb) {
    case ALLOW:    tx[(*tx_n)++] = m; return;
    case DROP:     counter_drop(ctx, dyn->verdict_layer, a->rule_id);
                   fr[(*fr_n)++] = m; return;
    case REDIRECT: rte_eth_tx_burst(a->redirect_port, ctx->qid, &m, 1); return;
    case MIRROR:   ctx->mirror_tx_buf[ctx->mirror_tx_n++] = mirror_clone(m);
                   tx[(*tx_n)++] = m; return;
    case TAG:      apply_dscp_pcp(m, a->dscp, a->pcp);
                   tx[(*tx_n)++] = m; return;
    case RL:
        if (rl_consume(&rs->rl_arena->bucket[a->rl_index], m->pkt_len)) {
            tx[(*tx_n)++] = m;
        } else {
            counter_rl_drop(ctx, dyn->verdict_layer, a->rule_id);
            fr[(*fr_n)++] = m;
        }
        return;
    }
}
```

### 5.6 Cycle budget

At 59.52 Mpps on a 3.0 GHz core, the per-packet budget is **~50 cycles** if we expect a single lcore to handle line rate. We do not — we fan out across queues. With **8 RX queues per port** and 8 lcores, the per-lcore packet rate at 64 B line rate is ~7.4 Mpps, giving us **~400 cycles per packet**, which is comfortable. Stage estimates (3 GHz, fully cache-resident):

| Stage | Cycles |
|---|---|
| RX burst (amortized) | ~15 |
| Header prefetch | hidden |
| L2 parse | ~20 |
| L2 hash lookup (1 hit) | ~40 |
| L3 FIB lookup (DIR-24-8) | ~25 |
| L4 hash lookup | ~40 |
| Action dispatch (allow) | ~10 |
| TX burst (amortized) | ~15 |
| Counter update (per-lcore, no atomic) | ~5 |
| **Total typical packet** | **~170** |

This leaves substantial headroom for cache misses, mirror clones, and TAG rewrites.

## 6. Lifecycle

### 6.1 Init sequence

```
main()
  ├─ parse CLI (--config, --ports, --lcores, --hugepage-prefix)
  ├─ rte_eal_init(...)
  ├─ register mbuf dynfield slot
  ├─ create mempools (per-NUMA-socket, see §8)
  ├─ port_init(port_a), port_init(port_b)
  │     ├─ rte_eth_dev_configure (RSS on 5-tuple, K rx/tx queues)
  │     ├─ rte_eth_rx_queue_setup × K (mempool from worker's NUMA socket)
  │     ├─ rte_eth_tx_queue_setup × K
  │     └─ rte_eth_dev_start
  ├─ first parse + validate + compile of config file → Ruleset v0
  │     │ on failure → fatal exit, watchdog will retry
  ├─ rte_rcu_qsbr_create(N_workers)
  ├─ atomic_store(&active, ruleset_v0)
  ├─ rte_eal_remote_launch(worker_main, ctx_i, lcore_i) for each worker
  ├─ start telemetry thread (Prometheus + sFlow + log drain)
  ├─ start cmd_socket thread
  ├─ start inotify thread
  └─ control loop: signals + heartbeat tick
```

Cold start budget: **≤ 5 s**, dominated by EAL hugepage scan and port init. Mempool/ruleset alloc add hundreds of ms.

### 6.2 Steady state

Workers run uninterrupted. The control thread polls inotify, signals, the cmd socket, and ticks the watchdog at 10 Hz. The telemetry thread aggregates per-lcore counters at the Prometheus scrape interval (typically 15 s).

### 6.3 Hot reload sequence diagram

```
inotify       parser/validator      compiler    GenManager (RCU)   workers
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
   │                │                  │     (NUMA-local alloc)         
   │                │                  └────►  publish via              
   │                │                          atomic_store(active, v_new, RELEASE)
   │                │                                  │                
   │                │                                  ├─rcu_synchronize() (qsbr)
   │                │                                  │                ▼
   │                │                                  │     workers pass quiescent
   │                │                                  │     state (top of next burst)
   │                │                                  ├─free Ruleset v_old
   │                │                                  │
   │                │                                  └─emit reload_done log+metric
   │                │
   │                └─on parse/validate/compile failure: log, bump
   │                   reload_failures_total, leave active untouched
```

### 6.4 Shutdown

`SIGTERM` sets `running = false`. Workers exit their loops; control thread joins them with `rte_eal_mp_wait_lcore()`; ports are stopped (`rte_eth_dev_stop`, `rte_eth_dev_close`); mempools and rulesets freed. Total shutdown ≤ 1 s.

### 6.5 Crash recovery

Watchdog (systemd unit + internal heartbeat) detects:

- **Process death** → systemd `Restart=on-failure` with exponential backoff
- **Stall** → internal heartbeat counter has not advanced in `K * tick` → systemd `WatchdogSec` triggers `SIGABRT`
- **Repeated crash** (> 5 in 60 s) → systemd unit transitions into `pktgate-bypass.target`, which starts a tiny supervisor that performs forwarding via either (a) software forward-only mode if any worker is alive or (b) link-down on both ports if hardware bypass NIC is in use.

## 7. Threading and lcore layout

**Decision: Q1 = Option A — lcore-per-RX-queue, run-to-completion.** Pipeline mode (Option B) is rejected because:

- Per-packet budget is ample at the chosen queue count, classification fits within run-to-completion easily.
- Option B introduces ~30 ns of `rte_ring` enqueue/dequeue per packet, plus cache-line bouncing for the mbuf pointer crossing cores. At 59.52 Mpps that's > 1.7 Gcycles/sec spent moving pointers.
- Run-to-completion makes hot reload semantics simple — there is one reader per ruleset reference, no mid-pipeline state to flush.

**Lcore layout for a typical 40 G production node** (single CPU socket, 16 cores):

| lcore | role |
|---|---|
| 0 | OS housekeeping (`isolcpus` excludes it) |
| 1 | Control thread (inotify, watchdog, cmd socket) |
| 2 | Telemetry thread (Prometheus scrape, sFlow, log drain) |
| 3 | Reserved (compile/validation in worker thread) |
| 4–11 | 8 dataplane workers, one per (port_a/b) RX queue |
| 12–15 | reserved/idle (or more workers if rules become heavier) |

`isolcpus=4-15`, `rcu_nocbs=4-15`, `nohz_full=4-15`. The control plane lcores are not isolated. NUMA: pin all dataplane workers and their mempools to the socket attached to the NICs (`rte_eth_dev_socket_id`). Cross-NUMA traffic costs ~150 cycles per cache line and would blow the budget.

**RSS configuration:** symmetric Toeplitz key, 5-tuple (src/dst IP, src/dst port, proto). Symmetric is required so that both directions of the same flow land on the same lcore — this makes per-flow rate-limit accounting (a v2 feature) possible without cross-core synchronization.

**Per-queue depth:** RX = 1024, TX = 1024 descriptors. RX descriptors below 512 risk drops at burst peaks; above 4096 wastes memory and increases worst-case latency. 1024 is the l3fwd default and the established sweet spot.

## 8. Memory layout

### 8.1 Hugepages

**Production minimum: 2 GiB hugepages** (or 1024 × 2 MiB pages, or 1 × 1 GiB page; 1 GiB is preferred for TLB efficiency). Recommended: **4 GiB** to leave headroom for two concurrent rulesets at scale plus mempool growth.

Dev VM minimum: 512 MiB (matches the existing 512 × 2 MiB allocation in §1.3 of input).

### 8.2 Mempools

One mempool per NUMA socket, shared among lcores on that socket.

**Mempool size formula** (the standard DPDK rule):

```
n_mbufs = (n_rx_queues × rxd) +
          (n_tx_queues × txd) +
          (n_lcores × burst_size × 2) +     // RX/apply-action staging
          (n_lcores × burst_size) +         // mirror staging
          (n_lcores × MEMPOOL_CACHE_SIZE)   // per-lcore cache
        + safety_margin
```

For our 8-worker, 2-port, 1024-desc, BURST=32 case:

```
= 8 × 1024 × 2 (rxd, both ports)            16384
+ 8 × 1024 × 2 (txd, both ports)            16384
+ 8 × 32 × 2                                  512
+ 8 × 32                                      256
+ 8 × 256                                    2048
+ ~8000 safety
≈ 43584 mbufs  → round up to 65535 (2^n − 1)
```

With `RTE_MBUF_DEFAULT_BUF_SIZE` = 2176 B, that's **~140 MiB per mempool**. One per socket. Mirror packets share the main mempool — there is no separate mirror pool because mirror clones are short-lived.

### 8.3 Per-lcore allocations

| Allocation | Size | Where |
|---|---|---|
| `WorkerCtx` | ~512 B | NUMA-local, malloc-aligned |
| `PerLcoreCounters` | ~768 KiB | NUMA-local |
| Mirror staging buffers | 32 × 8 B = 256 B | inside `WorkerCtx` |
| Local prefetch scratch | negligible | stack |

### 8.4 RCU memory

`rte_rcu_qsbr` requires `rte_rcu_qsbr_get_memsize(N_workers)` bytes — typically a few hundred bytes.

## 9. Hot reload strategy

### 9.1 Decision

**Q2: Use `rte_rcu_qsbr` with explicit `rte_rcu_qsbr_synchronize()` after pointer swap.** Rejected alternatives:

- *Plain atomic pointer + manual sleep(100 ms):* hopes a sleep is enough for in-flight references; not a guarantee. If a worker is briefly preempted (it shouldn't be on isolated cores, but BIOS SMIs can do it) the old ruleset is still referenced.
- *`rte_rcu_qsbr_dq` (deferred queue):* good for streaming many delete operations, overkill for whole-ruleset swap.
- *Double-buffered structures (pktgate's pattern):* an artifact of BPF map limits. With pointer-and-arena allocation we get the same effect more cleanly: each `Ruleset` is a fresh allocation.

### 9.2 Mechanics

Workers are RCU readers. They do not hold a long-lived pointer; each burst loop iteration starts with `rte_rcu_qsbr_quiescent(qs, tid)` and then does an `atomic_load_explicit(&active, memory_order_acquire)` to grab the current `Ruleset*` for the duration of that burst. Between bursts there is no reference, so quiescence is reached every burst iteration — which is microseconds.

Writer (control thread on reload):

```cpp
expected<void> deploy(string path) {
    auto cfg = parse(path);                    if (!cfg)  return cfg.error();
    auto v   = validate(*cfg);                 if (!v)    return v.error();
    auto co  = compile_objects(cfg->objects);  if (!co)   return co.error();
    auto cr  = compile_rules(cfg->pipeline, *co); if (!cr) return cr.error();
    auto rs_new = ruleset_build(*cr);          if (!rs_new) return rs_new.error();

    // Stamp generation
    rs_new->generation = ++gen_counter;
    rs_new->compile_timestamp_ns = now_ns();

    // Publish (release)
    Ruleset* rs_old = atomic_exchange_explicit(&active, rs_new.release(),
                                               memory_order_acq_rel);

    // Wait for all workers to pass through quiescent state
    rte_rcu_qsbr_synchronize(qs, RTE_QSBR_THRID_INVALID);

    // Now no worker can be holding rs_old; safe to free
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
| rcu_synchronize | < 1 ms (workers quiesce every burst) |
| destroy old ruleset | < 5 ms |

**End-to-end target ≤ 100 ms (after debounce window).** With the 150 ms debounce, the actual user-perceived latency is ≤ 250 ms; the SLO interpretation is "from inotify-event-finished to new-ruleset-active" which we hit comfortably.

### 9.4 Corner cases

- **Failed reload**: any expected<> error returns cleanly; the active ruleset is never replaced. The new (partially built) ruleset is destroyed by the unique_ptr.
- **Nested reload**: a second inotify event arriving during compilation. Solution: the inotify thread holds a reload mutex; only one reload runs at a time. Subsequent events coalesce into a single follow-up reload.
- **Hugepage exhaustion mid-build**: ruleset_build returns ENOMEM, old ruleset stays. Metric `reload_oom_total` increments. Operator alert fires.
- **Mid-burst reload**: impossible by construction — workers grab the pointer at the top of each burst iteration and don't refresh it until the next iteration. A burst sees a single ruleset version end-to-end.
- **Reload where rule_id N changes meaning**: rate-limit bucket state for N is preserved (the `RateLimitArena` is keyed by stable rule_id and survives reloads). If rule N is removed, its bucket is released by the arena GC pass, also under RCU.

## 10. Telemetry surface

### 10.1 Decision (Q7)

Ship all of the following in MVP:

- **Prometheus HTTP `/metrics`** on a configurable TCP port (default 9750), served by a control thread, OpenMetrics format. **Required.**
- **`rte_telemetry`** registration for DPDK-idiomatic introspection (`/dpdk/telemetry` UDS), exposing the same counters plus port stats and ring depths. **Required (cheap).**
- **sFlow v5** UDP exporter, embedded encoder (no `libsflow` dependency — it's small and we want to avoid runtime deps; ~400 LoC). **Required.**
- **Structured logs** as JSON-lines on stderr (captured by journald) plus optional UDP syslog target. **Required.**

### 10.2 Metric names

```
pktgate_rule_packets_total{layer="l2|l3|l4",rule_id="N"}        counter
pktgate_rule_bytes_total{layer,rule_id}                         counter
pktgate_rule_drops_total{layer,rule_id,reason="explicit|rate"}  counter
pktgate_default_action_total{verdict="allow|drop"}              counter

pktgate_port_rx_packets_total{port="0|1"}                       counter
pktgate_port_tx_packets_total{port}                             counter
pktgate_port_rx_bytes_total{port}                               counter
pktgate_port_tx_bytes_total{port}                               counter
pktgate_port_rx_dropped_total{port,reason="nombuf|noqueue|err"} counter
pktgate_port_tx_dropped_total{port}                             counter

pktgate_lcore_packets_total{lcore}                              counter
pktgate_lcore_cycles_per_burst{lcore}                           histogram
pktgate_lcore_idle_iters_total{lcore}                           counter

pktgate_reload_total{result="success|parse_err|validate_err|compile_err|oom"} counter
pktgate_reload_latency_seconds                                  histogram
pktgate_active_generation                                       gauge
pktgate_active_rules{layer}                                     gauge

pktgate_mempool_in_use{socket}                                  gauge
pktgate_mempool_free{socket}                                    gauge

pktgate_watchdog_restarts_total                                 counter
pktgate_bypass_active                                           gauge (0/1)
```

This is intentionally **not** a clone of pktgate's metric names. The new prefix (`pktgate_*`) uses Prometheus naming conventions. A short mapping appendix in `CONFIG.md` documents the renaming.

### 10.3 sFlow

- Sample rate: configurable per ingress port, default `1:1024`.
- Sample contents: `flow_sample` with raw header (truncated to 128 B), input ifIndex, output ifIndex, **matched rule ID** in `extended_user` element, packet length, drop status.
- Counter samples (interface counters) emitted every 30 s.

Implementation: each worker, on a "this is the Nth packet sampled this RSS-bucket", writes a fixed-size sample record to a per-lcore SPSC ring drained by the telemetry thread, which builds and sends sFlow datagrams. **Encoding never happens on the hot path.**

### 10.4 Structured logs

JSON lines: `{"ts":"...","level":"info","msg":"reload_ok","gen":42,"rules":{"l2":120,"l3":350,"l4":18}}`. Hot path uses a per-lcore SPSC ring (size 1024) of fixed-size log records; drained by the telemetry thread. Overflow drops the oldest record and increments `pktgate_log_dropped_total`. **Zero allocations on the hot path. No per-packet logging ever.**

### 10.5 `rte_telemetry`

Registered commands:
```
/pktgate/version
/pktgate/active_generation
/pktgate/rules/count
/pktgate/rules/dump,layer=l3
/pktgate/lcores
/pktgate/ports
/pktgate/reload                   ← writes a flag the inotify thread polls
```

### 10.6 UDS command socket (Q6)

A purpose-built protocol over a Unix domain socket (`/run/pktgate/ctl.sock`, mode 0600, owned by `pktgate:pktgate`). Single connection, line-delimited JSON requests:

```json
{"cmd":"reload"}
{"cmd":"status"}
{"cmd":"dump-config"}
{"cmd":"dump-rule","layer":"l3","id":42}
{"cmd":"counters","layer":"l3","id":42}
```

This duplicates some of `rte_telemetry` deliberately — `rte_telemetry` is DPDK-internal and the UDS API is the operator-facing surface.

## 11. Failure modes and responses

| Failure | Detection | Action | Recovery |
|---|---|---|---|
| Bad JSON syntax | parser returns error | log, bump `reload_total{result="parse_err"}`, leave active untouched | next reload |
| Validation error (bad ref, out-of-range) | validator returns error | log, bump `reload_total{result="validate_err"}` | next reload |
| Compilation key collision | rule_compiler returns error | log with both rule IDs | next reload |
| Hugepage OOM during build | malloc fails inside ruleset_build | log, bump `reload_total{result="oom"}` | operator must reduce rule count or add hugepages |
| Mempool exhausted in steady state | `rte_pktmbuf_alloc` returns NULL on RX | drop packet, bump `port_rx_dropped{reason="nombuf"}` | self-resolves when traffic recedes or operator increases pool |
| TX ring full | `rte_eth_tx_burst` returns < n | bulk-free unsent mbufs, bump `port_tx_dropped` | self-resolves |
| NIC link down | poll `rte_eth_link_get_nowait` from telemetry thread | gauge `pktgate_port_link_up=0`, alert | recovers automatically when link comes back |
| Worker stall | heartbeat counter doesn't advance for N ticks | systemd `WatchdogSec` aborts, restart, then bypass after K crashes | automatic via systemd |
| Process crash | systemd notices | restart with backoff, after K crashes → bypass | bypass mode keeps traffic flowing |
| Bypass mode triggered | watchdog policy | software forward-only mode (or kernel-rebind v2) | manual operator intervention |
| PCI error | `rte_eth_dev_get_status` reports error | log fatal, exit, watchdog handles | manual |
| Reload mid-shutdown | shutdown flag set during reload | reload aborted, ruleset freed, exit clean | n/a |
| sFlow encoder failure | telemetry thread exception | log, restart sFlow exporter, do not affect dataplane | automatic |

**Q9 confirmed:** the three categories (config errors → reject and rollback; hot-path errors → drop and continue; fatal errors → fail fast and let watchdog restart) are sufficient. Added explicit handling for hugepage exhaustion during reload, NIC link state, and PCI errors.

## 12. Test strategy (Q10)

### 12.1 Test matrix

| Test type | Where it runs | Blocks release? | Tooling |
|---|---|---|---|
| Unit (parser/validator/compiler) | dev VM, CI | yes | gtest |
| JSON schema conformance vs `pktgate/scenarios/*.json` | dev VM, CI | yes | gtest + nlohmann/json schema validator |
| Ruleset builder unit (rte_hash/rte_fib correctness) | dev VM, CI | yes | gtest, EAL in standalone mode |
| Functional dataplane on `net_pcap` vdev | dev VM, CI | yes | pytest + scapy, mirror of pktgate's `functional_tests/` structure |
| BURST_SIZE / dynfield / hot reload integration | dev VM, CI | yes | gtest with `net_null` + `net_pcap` vdevs |
| Stress: 4096 rules per layer, 1000 reloads | dev VM, CI nightly | yes | custom harness |
| Fuzzing: config parser, rule compiler | CI nightly | no | libFuzzer harness |
| Sanitizers (ASAN/UBSAN/TSAN) | dev VM, CI | yes | CMake build flavor |
| Line-rate throughput at 64 B / IMIX / 1500 B | lab hardware | yes for production release | TRex |
| Latency p50/p99/p99.9 | lab hardware | yes for production release | TRex with high-resolution timestamping |
| 24-hour soak | lab hardware | yes for production release | TRex |
| Hot reload during traffic, no drop | lab hardware | yes | TRex + scripted reload generator |
| Watchdog crash recovery | lab hardware | yes | fault injection |

The dev VM (e1000 NICs) cannot validate the throughput SLOs at all. The lab hardware run (TRex against XL710 or E810) is the gating release test. All correctness must pass in CI before lab time is requested.

### 12.2 Per-phase exit criteria — see §14.

## 13. Project structure

```
pktgate-dpdk/
├── CMakeLists.txt                    ← top-level (uses pkg-config libdpdk)
├── README.md
├── ARCHITECTURE.md                   ← (this document, to be checked in)
├── CONFIG.md                         ← schema delta + Prometheus metric mapping
├── config-schema.json                ← schema (initially copied verbatim from pktgate)
│
├── include/pktgate/                  ← public-ish headers
│   ├── ruleset.h                     ← Ruleset, RuleAction, lookup helpers
│   ├── action.h
│   └── version.h
│
├── src/
│   ├── main.cpp                      ← bootstrap, signals, control loop
│   ├── eal/
│   │   └── port_init.{cpp,h}
│   ├── config/
│   │   ├── parser.{cpp,h}
│   │   ├── validator.{cpp,h}
│   │   └── model.h
│   ├── compiler/
│   │   ├── object_compiler.{cpp,h}
│   │   └── rule_compiler.{cpp,h}     ← compound L2 algorithm, port group expansion
│   ├── ruleset/
│   │   ├── builder.{cpp,h}
│   │   └── ruleset.cpp               ← rte_hash/rte_fib lifecycle
│   ├── gen/
│   │   └── gen_manager.{cpp,h}       ← RCU swap
│   ├── dataplane/
│   │   ├── worker.{cpp,h}
│   │   ├── classify_l2.h
│   │   ├── classify_l3.h
│   │   ├── classify_l4.h
│   │   └── action_dispatch.h
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
├── tests/                            ← gtest unit/integration
│   ├── unit/
│   ├── integration/                  ← uses net_pcap vdev
│   └── stress/
│
├── functional_tests/                 ← pytest+scapy via net_pcap
│
├── fuzz/                             ← libFuzzer harnesses
│
├── systemd/
│   ├── pktgate-dpdk.service
│   ├── pktgate-dpdk-bypass.target
│   └── pktgate-dpdk.conf
│
├── scripts/
│   ├── setup_dev.sh                  ← hugepages, drivers, env
│   └── lab_run.sh                    ← TRex orchestration
│
└── docs/
    ├── METRICS.md
    ├── OPS.md
    └── PROVISIONING.md
```

CMake targets:

- `pktgate_dpdk` — main binary
- `libpktgate_core.a` — parser/validator/compiler/ruleset/gen (no DPDK linkage where possible) — fast unit tests link against this
- `libpktgate_dp.a` — dataplane code requiring DPDK
- `pktgate_dpdk_test_*` — one per gtest binary
- `pktgate_dpdk_fuzz_*` — fuzz harnesses

Build: `cmake -B build && cmake --build build -j`. Tooling: gcc 15 or clang 21, both supported. C++ standard: **C++20** (concepts and `<expected>` desired; gcc 15 supports both fully).

## 14. Phase plan

### 14.1 MVP (Phase 1) — exit criteria

**Ships with:**
- EAL bring-up, two-port inline forwarding scaffolding
- JSON parser + validator + compiler that accepts every existing pktgate scenario file in `/home/user/filter/scenarios/*.json`
- Ruleset builder for L2 (compound), L3 (IPv4 + IPv6 + VRF), L4 (proto+port)
- All six actions: allow, drop, mirror (deep-copy), rate-limit, tag (DSCP only — PCP rewrite if cheap, else v2), redirect
- Run-to-completion worker, RSS, single CPU socket
- RCU-QSBR hot reload with rollback
- Inotify directory-watch reload trigger with 150 ms debounce
- UDS command socket: `reload`, `status`, `dump-config`, `dump-rule`
- Prometheus `/metrics` endpoint
- `rte_telemetry` integration
- sFlow exporter (v5, embedded encoder)
- Structured JSON logs
- systemd unit + watchdog + heartbeat
- Software forward-only bypass mode
- Functional test suite running on dev VM `net_pcap`
- Unit + integration + stress tests in CI
- Sanitizer build clean
- Documentation: ARCHITECTURE.md, CONFIG.md, METRICS.md

**MVP exit criteria (must all be true):**

1. All scenarios in `pktgate/scenarios/*.json` parse, validate, compile without modification.
2. Functional pytest+scapy suite green on `net_pcap` vdev.
3. ASAN/UBSAN clean.
4. Hot reload survives 1000 reload cycles under traffic in dev VM (loss = 0).
5. Stress test with 4096 L2 + 16384 L3 + 4096 L4 rules compiles in ≤ 50 ms.
6. Lab run on TRex against E810/XL710 sustains 40 Gbps bidirectional with 64 B packets, < 0.01 % loss, p99 latency < 50 µs added — for at least one configuration with at least 100 active rules per layer.
7. Watchdog crash test: kill -9 the dataplane during traffic, traffic resumes within 5 s.

**MVP explicitly does NOT include:**

- YAML config (Q-deferred)
- gRPC / HTTP push from NOC (Q-deferred)
- Hardware bypass NIC integration
- Kernel driver fallback bypass
- VLAN PCP rewrite (CoS only via tag action — v2)
- TCP flags matching (defer to v2; the schema accepts the field but the compiler emits a warning that it is ignored)
- Per-flow state, connection tracking, NAT, anything stateful
- `rte_flow` HW offload of classification
- Multi-socket NUMA topology (single socket only)
- Refcount-based zero-copy mirror (deep-copy in MVP)

### 14.2 Phase 2 (v2)

- VLAN PCP rewrite (`rte_vlan_strip`/`rte_vlan_insert` or manual TCI rewrite)
- TCP flags matching at L4
- Refcount-based zero-copy mirror, with NIC compatibility table
- Multi-socket NUMA support
- Mirror-mode fallback bypass
- Kernel driver fallback bypass (slow path)
- Optional gRPC push receiver (mTLS)
- YAML→JSON pre-processor (no core changes)
- Per-flow rate-limit (5-tuple keyed) — requires symmetric RSS already in MVP
- HW offload via `rte_flow` for L2 hash steering and obvious drops, with software fallback

### 14.3 Phase 3 (v3)

- Hardware bypass NIC integration (Silicom/Napatech)
- Hot-standby active/standby pair across nodes
- Telemetry pipeline integrated with NOC orchestrator
- Migration tool: pktgate (XDP) ↔ pktgate-dpdk runtime swap
- Schema v2 with explicit migration shims

## 15. Risk register

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| 1 | `rte_fib` worst-case memory blows the hugepage budget | medium | high | Benchmark with worst-case prefix mix early in MVP build; if memory > 256 MiB, switch to `rte_lpm` (smaller, slightly slower) for v6, or profile and tune `RTE_FIB_DIR24_8_GROUPS`. Decision point in MVP week 2. |
| 2 | Cycle budget blown on real workload (e.g. high mirror rate forces deep copy on every packet) | medium | high | Mirror is the main free variable. Mitigation: limit mirror to a sampling rate by default; benchmark mirror-heavy scenarios on lab hardware before MVP exit. v2 zero-copy mirror reduces this. |
| 3 | Compound L2 rules with rare primary keys cause cache thrash | low | medium | Compiler chooses primary by selectivity; secondary check is a single hot cache line; profile in stress test. |
| 4 | Hot reload of large IPv6 ruleset exceeds 100 ms | medium | medium | `rte_fib6` build dominates. Mitigation: parallelize prefix insertion across threads inside `ruleset_build`; if still slow, bump SLO to 250 ms — operator-acceptable. |
| 5 | Lab hardware (E810/XL710) availability gates release | high | high | Reserve TRex windows now. Cross-test on `pktgen-dpdk` from a second host as soon as possible — won't validate full 40 Gbps but catches gross regressions. |

## 16. Unresolved questions

All twelve open questions in input §5 are resolved in the body of this document (decisions inline). The two items I am explicitly flagging as **verification items** rather than truly unresolved are:

- **`rte_fib` actual memory at 16 384 IPv6 prefixes** — the documented worst case is large, the typical case is much smaller. Verification experiment: insert the prefix mix from `scenarios_v2/` into a synthetic builder and measure RSS; decide whether to switch to `rte_lpm6`. **Owner: implementer in MVP week 2. Does not block design approval.**
- **Whether `rte_telemetry` thread bloats the binary or pulls in unwanted deps** — unlikely (it's DPDK upstream) but the link footprint should be measured. **Owner: implementer in MVP week 1.**

No question from input §5 is left "either could work."

## 17. Appendix: pktgate → pktgate-dpdk transformation table

| pktgate (XDP) decision | Cause | DPDK design | Why |
|---|---|---|---|
| 4 separate BPF programs with tail calls | BPF verifier 1 M instruction limit per program | Single C++ function chain inlined into worker burst loop | No instruction limit; inlining is faster; one function easier to profile |
| `pkt_meta` in 20-byte XDP `data_meta` | BPF cannot use thread-local C state | `rte_mbuf` dynfield (registered slot, ~10 bytes) | Same idea, native primitive; no bounds-check overhead |
| Double-buffered BPF maps `*_0/_1` | BPF maps cannot be freed while in use, no user-space RCU | Pointer-and-arena `Ruleset` swapped under `rte_rcu_qsbr` | One allocation, one swap, deferred free; cleaner semantics |
| Generation counter in `gen_config` array | BPF entry program needs to dispatch to one of two map sets | Direct atomic pointer read at top of burst | One memory load, no branch on generation |
| TC companion program (`tc_ingress.bpf.c`) for mirror/tag | XDP cannot do `bpf_clone_redirect` or skb rewrites | Mirror via `rte_pktmbuf_copy` (MVP) or `rte_mbuf_refcnt_update` (v2); tag via direct DSCP byte rewrite in mbuf | All actions live in one process |
| `PERCPU_HASH` rate-limit with `rate_bps / NCPU` divider | BPF verifier hates locks; per-CPU is the verifier-friendly path | Single shared `TokenBucket` per rule with atomic CAS refill | Aggregate matches configured rate exactly; cross-lcore contention is low because RSS pins flows |
| `filter_mask` bitmap for compound L2 rules | Primary lookup must be O(1) hash; secondary fields verified after | **KEPT** (universal lesson), implemented identically in `L2CompoundEntry.filter_mask` | The selectivity-ordered primary + bitmap secondary is the right design regardless of platform |
| Rule precedence src_mac > dst_mac > vlan > ethertype > pcp | Selectivity-driven; chosen via empirical analysis | **KEPT** verbatim | Same reasoning applies |
| First-match-wins, no priority field, config order | Operator-friendly | **KEPT** | Universal lesson |
| inotify on directory not file | Atomic-rename editors | **KEPT** verbatim | Universal lesson |
| Drop IPv4 non-first frags & IPv6 frag headers in L3 | No L4 header to inspect | **KEPT** | Universal lesson |
| Compile-time hard resource ceilings | Predictable memory | **KEPT** (compile rejects > N4 limits with clear error) | Universal lesson |
| 4096-rule per-layer ceiling | Map size choice in BPF | **KEPT but justified separately**: at 4096 rules, action arenas fit in L2 cache; counter arrays fit in 1 MiB per lcore | Same number, different reason |
| LPM trie key `{prefixlen, addr}` byte layout | BPF map ABI | Replaced by `rte_fib` opaque API | No ABI to preserve |
| `BPF_PROG_TEST_RUN` for dataplane unit tests | BPF-specific harness | DPDK `net_null` + `net_pcap` vdevs in unit tests | DPDK-native equivalent |
| nlohmann/json + custom validator (C++23) | C++ control plane | nlohmann/json + json-schema-validator (C++20) | Same library family, narrower std |
| 4 separate L2 hash maps (one per match field) | BPF map-of-maps complexity | Same: one `rte_hash` per primary match type | Universal — selectivity-ordered probing requires distinct tables |

---

# SHORT STRUCTURED SUMMARY (the requested return)

### 1. Executive summary (verbatim from §1)

`pktgate-dpdk` is a DPDK 25.11 userspace L2/L3/L4 packet filter for the GGSN–Gi interface, sustaining 40 Gbps bidirectional (worst case 59.52 Mpps) per site with sub-50 µs added p99 latency and < 0.01 % collateral loss. It runs a strict run-to-completion model with one lcore pinned per RX/TX queue pair, classifies each burst through a layered pipeline (L2 → L3 → L4) backed by `rte_hash`, `rte_fib`/`rte_fib6`, and a home-grown rule-keyed token bucket, dispatches one of six actions (`allow`, `drop`, `mirror`, `rate-limit`, `tag`, `redirect`), and updates the configuration without restart through an atomic `RCU-QSBR`-protected pointer swap targeting ≤ 100 ms reload latency with full rollback on any compilation failure. JSON configs are schema-compatible with the existing pktgate (XDP) project. The system defaults to fail-open software-forward bypass on watchdog-detected stalls, exposes Prometheus, sFlow, structured logs, and `rte_telemetry`, and is built with CMake + `pkg-config libdpdk` in C++20.

### 2. Big architectural decisions

- **Threading model: lcore-per-RX-queue, run-to-completion (Q1=A).** Why: lowest latency, no inter-core ring traffic, keeps RCU semantics trivial.
- **L2 lookup: per-match-type `rte_hash` for MAC + `rte_hash`/direct LUT for ethertype/vlan/pcp, with selectivity-ordered probing and a `filter_mask` bitmap for secondary fields.** Why: pktgate's compound algorithm is universal, not BPF-specific.
- **L3 IPv4 lookup: `rte_fib` (DIR-24-8).** Why: faster than `rte_lpm` and our prefix counts fit comfortably in expected hugepage budget.
- **L3 IPv6 lookup: `rte_fib6`, with a measured fallback to `rte_lpm6` if memory exceeds 256 MiB.** Why: same speed argument; risk-flagged.
- **L4 lookup: `rte_hash` keyed on packed `(proto, dst_port, src_port)`.** Why: O(1), trivial, fits 4096 rules.
- **Rate-limit: home-grown atomic-CAS token bucket per rule, aggregated across lcores.** Why: `rte_meter` is color-aware/srTCM-shaped — wrong fit; pktgate's `rate/NCPU` workaround was a BPF artifact we explicitly drop.
- **Hot reload primitive: `rte_rcu_qsbr` with full pointer-and-arena replacement and `rcu_synchronize` deferred free (Q2).** Why: cleanest semantics, no double-buffer ABI to maintain.
- **Mirror implementation in MVP: deep `rte_pktmbuf_copy` (Q4=A); zero-copy refcount in v2 with NIC compatibility table.** Why: deep copy is universally safe; refcount needs driver vetting.
- **Action layer: one shared `RuleAction` struct (16 B, cache-fits-4-per-line) referenced by index from each layer's lookup result.** Why: minimizes branch on action verb, keeps all action data in one prefetched line.
- **Rule compilation: in-process (Q5=a), C++20, no external compiler binary.** Why: simplest, one artifact to deploy.
- **Control plane v1 (Q6): inotify directory-watch + UDS command socket + `rte_telemetry`. No gRPC, no HTTP push.** Why: matches pktgate idiom, adds operator-grade introspection cheaply.
- **Telemetry surface (Q7): Prometheus + sFlow (embedded encoder) + structured JSON logs + `rte_telemetry`. All four are MVP.** Why: no single channel covers all stakeholders; cost is small.
- **Bypass mode in MVP (Q8): software forward-only, triggered by watchdog after K crashes; mirror-mode fallback only when site is mirror-deployed.** Why: always available, no hardware dependency. Kernel rebind and HW bypass are v2/v3.
- **Error taxonomy (Q9): config errors → reject and rollback; runtime errors → drop packet, bump counter; fatal init errors → exit, watchdog restarts. Plus explicit handling of hugepage OOM during reload, NIC link state, and PCI errors.** Why: matches operator expectations and survives every failure mode we identified.
- **Test strategy (Q10): unit + functional + sanitizers + stress in dev VM CI; line-rate and latency on TRex against E810/XL710 in lab; lab run gates release.** Why: dev hardware can't validate the SLOs, but everything else can.
- **Schema versioning (Q11): strict version match; the schema embeds a `version` field; binary refuses mismatches with a clear error.** Why: predictable; migration tooling is a v3 item.
- **Resource sizing (Q12): 2 GiB hugepages minimum (4 GiB recommended); mempool formula in §8.2; 8 dataplane lcores per socket; `isolcpus`/`rcu_nocbs`/`nohz_full` on dataplane cores.** Why: explicit numbers so operators don't guess.
- **Counters: per-lcore arrays of 64-byte `RuleCounter`, no atomics on the hot path, aggregated by telemetry thread.** Why: zero contention, true cache locality.
- **Build: CMake + `pkg-config libdpdk`, C++20, gcc 15 or clang 21.** Why: matches constraints from input §3.3.
- **Symmetric RSS Toeplitz key.** Why: enables future per-flow rate-limit and keeps both directions of a flow on the same lcore.

### 3. Things that surprised me / shaped decisions

- pktgate's compound L2 algorithm (selectivity-ranked primary key + `filter_mask` bitmap for secondary fields) is genuinely elegant and platform-independent — I expected to redesign it but kept it verbatim. The selectivity precedence `src_mac > dst_mac > vlan > ethertype > pcp` is real engineering, not arbitrary.
- pktgate's `PERCPU_HASH` token bucket with `rate_bps / NCPU` is a worse design than a single shared atomic bucket — but only because BPF couldn't easily do shared atomics. In DPDK, with RSS pinning flows to lcores, contention on a shared bucket is naturally low and the aggregate rate is exact, not approximate.
- The pktgate TC companion program exists *only* because XDP can't `bpf_clone_redirect` or rewrite skb fields. In DPDK every action lives in one address space — collapsing the hybrid model into a single C++ function chain is one of the biggest simplifications.
- The DPDK `rte_rcu_qsbr` API with explicit `quiescent` calls per burst maps almost perfectly onto our run-to-completion model — the worker has no ruleset reference *between* burst iterations, so quiescence is microseconds.
- mbuf `dynfield` is the natural replacement for XDP `data_meta`, but only ~16 bytes are typically usable; we fit our state into 10 bytes by aggressive packing.
- pktgate's LPM_TRIE iteration limitation (open question #9 in pktgate's doc) is a BPF-specific artifact that doesn't apply to `rte_fib` at all.

### 4. Open questions I could not resolve

**None of the 12 open questions in input §5 are unresolved.** Two design *verification items* (not unresolved questions) are flagged in §16: actual `rte_fib6` memory at 16 384 prefixes, and `rte_telemetry` link footprint. Both are owned by the implementer in MVP week 1–2 and do not block design approval.

### 5. Top 3 risks

1. **`rte_fib`/`rte_fib6` memory at the high end of N4** could exceed the hugepage budget. Mitigation: measure early, fall back to `rte_lpm6` if needed. Decision point in MVP week 2.
2. **Cycle budget under mirror-heavy workloads.** Deep-copy mirror at 40 Gbps with high mirror selectivity can dominate the per-packet budget. Mitigation: default sampled mirror, lab-validate mirror-heavy scenarios, plan v2 zero-copy refcount path.
3. **Lab hardware availability (TRex + E810/XL710) gates release.** Dev VM cannot validate any throughput SLO. Mitigation: book lab time at MVP start, use `pktgen-dpdk` cross-host for mid-range validation in the meantime.

### 6. Document path and section count

- **Document path:** `/tmp/pktgate-dpdk-design.md` *(NB: I am in read-only mode and could not write the file myself; the full document above is the deliverable. The user should save it to that path.)*
- **Section count: 17** (16 required deliverables from input §7, plus an appendix §17 containing the explicit pktgate→DPDK transformation table requested in the prompt body).