# pktgate-dpdk — Input Requirements

> Input document for the architecture design phase.
> Aggregates customer requirements (as received), project context,
> explicit constraints already agreed, and open questions to be resolved.
> Prepared 2026-04-10.

---

## 1. Context

### 1.1 Deployment target

Mobile operator backbone, between GGSN and the Gi interface.
40 Gbps per site, bidirectional. `pktgate-dpdk` sits inline (or in mirror mode,
depending on site) as an L2/L3 filter — **before** any DPI or L7 processing
further up the pipeline. Its purpose is to keep the downstream DPI clean
by discarding uninteresting or hostile traffic at line rate, without adding
meaningful latency.

### 1.2 Sibling project: pktgate (XDP)

An existing XDP/eBPF implementation of the same concept — **pktgate** — lives in
`/home/user/filter`. `pktgate-dpdk` is a **greenfield sibling** targeting the
DPDK packet path for sites where DPDK is a better fit than AF_XDP
(predictable performance on 40/100G NICs, dedicated cores, kernel out of the
hot path).

**We are NOT reusing pktgate's code.** Its internals are tightly coupled to:

- BPF map byte layouts (MAC 8-byte alignment, LPM trie `{prefixlen, addr}` key
  format)
- tail-call prog arrays between L2/L3/L4 programs (an artifact of the BPF
  verifier complexity limit)
- generation-swap through BPF map updates
- TC companion program for actions XDP cannot do (mirror, DSCP rewrite)
- libbpf skeleton codegen

Re-tooling that into DPDK idioms costs more than writing fresh.

**What we DO reuse — as knowledge, not code:**

- **JSON config schema.** Scenarios must be interchangeable, within reason,
  between pktgate and pktgate-dpdk.
- **Architectural lessons**, paid for in pktgate development:
  - first-match-wins per layer, rules in config order, no `priority` field
  - port-group and object expansion at compile time (not at runtime)
  - compound L2 rules flattened into primary-key lookup + secondary
    `filter_mask` bitmap (the precedence `src_mac > dst_mac > vlan_id >
    ethertype > pcp` was chosen for a reason; worth keeping)
  - IPv4 non-first fragments and IPv6 fragment headers are dropped at L3
  - dual-stack IPv4 + IPv6 from day one, not retrofitted
  - double-buffered hot reload with a short drain window
  - inotify on the **directory** containing the config, not the file itself
    (atomic-rename editors such as vim and `sed -i` would miss a file watch)
  - hard resource ceilings enforced at compile time, not runtime
- **Scenarios and functional test cases** in `/home/user/filter/scenarios/`
  and `/home/user/filter/functional_tests/` — as inputs for our own test
  suite.

### 1.3 Development environment (current)

| | |
|---|---|
| Host | Fedora 43, kernel 6.19, VirtualBox VM |
| CPU / RAM | 4 vCPU (i7-8665U), 5.6 GB |
| DPDK | 25.11.0 built from source at `~/Dev/dpdk-25.11/` |
| Hugepages | 1 GB (512 × 2M) |
| Dev NICs | 2 × Intel 82545EM (e1000), bound to `uio_pci_generic` |
| Toolchain | gcc 15.2, clang 21.1, meson 1.8.5, CMake, ninja 1.13 |
| Debugging | gdb, perf, bpftrace, strace, tcpdump |

Production hardware (not available in dev): multi-socket server class,
40 Gbps NICs (likely Intel XL710/E810 or Mellanox ConnectX-5/6). Dev hardware
is for correctness and smoke testing only; performance validation happens on
real hardware with TRex / IXIA.

### 1.4 Note on "DPDK and AF_XDP" compatibility

The raw requirements state: *"Compatible with both DPDK and AF_XDP packet
paths."* This is satisfied at the **product level** by two sibling binaries:

- `pktgate` (existing) — XDP / AF_XDP path
- `pktgate-dpdk` (this project) — DPDK path

`pktgate-dpdk` itself is DPDK-only and does **not** need to support AF_XDP
as an alternative I/O backend internally. The "both paths" requirement is
covered by the product family, not by a single binary.

---

## 2. Raw requirements (customer, verbatim)

> We need to deploy a line-rate L2 traffic filtering layer on all 40 Gbps
> GGSN–Gi interfaces to gain fine-grained control, visibility, and protection
> at the packet level without introducing noticeable latency or impacting
> throughput.
>
> **Purpose.** To control and monitor raw network traffic directly on the Gi
> side — before it reaches higher layers — ensuring clean separation between
> trusted and untrusted segments, compliance with routing policy, and early
> mitigation of anomalous traffic.
>
> **Scope.**
>
> - Operates exclusively at Layer 2 / Layer 3 (Ethernet, VLAN, IPv4/IPv6)
> - No DPI, protocol dissection, or L7 filtering
> - Inline or mirror mode depending on site configuration
> - Compatible with both DPDK and AF_XDP packet paths
>
> **Performance & Reliability Targets.**
>
> - Throughput: sustained 40 Gbps per site (bidirectional)
> - Latency overhead: ≤ 500 µs added per packet
> - Packet loss: < 0.01 % under peak load
> - Failover: hot-standby or bypass mode in case of failure
>
> **Functional Requirements.**
>
> - Configurable rule hierarchy:
>   - L2: interface, VLAN ID, MAC, EtherType
>   - L3: source/destination IP, subnet, routing domain
>   - L4: optional port-based matching for basic flow classification (no
>     payload parsing)
> - Actions: allow, drop, mirror, rate-limit, tag, or redirect
> - Config source: central YAML/JSON rule file, reloadable at runtime (no
>   restart)
> - Sync: per-site configuration sync via control plane; optional push from NOC
> - Observability: per-rule counters (pps/bps/drops), Prometheus metrics,
>   sFlow export, structured logs
> - Safety: watchdog monitoring of worker health; automatic restart and alert
>   on failure
>
> **Initial Tasks.**
>
> 1. Architecture design: per-core worker model pinned to NIC queues;
>    zero-copy packet flow (DPDK or AF_XDP).
> 2. Config engine: define schema for hierarchical rules (interface → IP
>    range → action).
> 3. Control plane: lightweight management service for rule updates and
>    telemetry collection.
> 4. Metrics & logging: expose counters per rule and per interface; integrate
>    with Prometheus and Grafana.
> 5. Fail-safe mode: ensure bypass or mirror mode if worker fails; validate
>    watchdog recovery.
> 6. Testing: synthetic 40 Gbps load (IXIA or TRex) to validate throughput,
>    latency, and drop rate.
>
> **Expected Outcome.** A stable, high-performance L2 filtering layer
> operating transparently between GGSN and Gi, providing: configurable control
> at Ethernet/IP level; centralized rule management and observability;
> deterministic performance at 40 Gbps; safe failure behavior and operational
> visibility.

---

## 3. Formalized requirements

### 3.1 Functional

#### F1 — Rule model

Hierarchical, layered pipeline. For each packet the layers are evaluated in
order **L2 → L3 → L4** (with early exit on action):

**L2 match fields**:

- ingress interface / DPDK port identifier
- VLAN ID (including no-VLAN and 802.1Q tagged)
- source MAC
- destination MAC
- EtherType
- optionally PCP (802.1p class)

**L3 match fields**:

- source IPv4 (exact or CIDR prefix)
- destination IPv4 (exact or CIDR prefix)
- source IPv6 (exact or CIDR prefix)
- destination IPv6 (exact or CIDR prefix)
- VRF / routing domain identifier

**L4 match fields** (optional on a per-rule basis):

- IP protocol (TCP / UDP / ICMP / others)
- destination port (single, range, or port group reference)
- source port (single, range, or port group reference)
- optionally TCP flags

**Matching semantics**:

- rules within a layer are evaluated in config order
- **first match wins**, no priority field, no implicit ordering
- on match within a layer, the rule's action is executed; if the action is
  `allow` and the rule sets `next_layer`, evaluation proceeds to that layer
- if no rule matches within a layer, traffic **proceeds** to the next layer
- if no rule matches anywhere, `default_behavior` applies (`allow` | `drop`)

#### F2 — Actions

Exactly one action per rule. The set:

| Action | Semantics | Parameters |
|---|---|---|
| `allow` | Forward (to next layer if set, else egress) | optional `next_layer` |
| `drop` | Discard packet, bump drop counter | none |
| `mirror` | Clone to a target port, original continues | `target_port` |
| `rate-limit` | Token bucket per rule; over-limit → drop | `bandwidth` (bps) |
| `tag` | Rewrite DSCP and/or 802.1p CoS, then forward | `dscp`, `cos` |
| `redirect` | Forward to non-default egress / VRF | `target_vrf` or `target_port` |

#### F3 — Config format

- **JSON only in v1.** YAML is explicitly deferred; one format means one
  parser, one validator, one schema, one set of tests. A YAML→JSON
  pre-processor can be added later without changing the core.
- **Schema-compatible with existing pktgate schema**
  (`/home/user/filter/config-schema.json`), so that
  `/home/user/filter/scenarios/*.json` validate against `pktgate-dpdk` as
  well. Divergence from pktgate's schema is allowed **only** where DPDK
  semantics demand it (e.g. rate-limit precision, interface naming), and
  each divergence must be explicitly documented in `CONFIG.md`.
- **Top-level sections** (inherited from pktgate):
  - `device_info` — interface metadata, link speed hints
  - `objects` — reusable named groups (subnets, subnets6, mac_groups,
    port_groups)
  - `pipeline.layer_2` — array of L2 rules
  - `pipeline.layer_3` — array of L3 rules
  - `pipeline.layer_4` — array of L4 rules
  - `default_behavior` — `allow` or `drop`

#### F4 — Hot reload

- Config changes take effect **without restart** and **without dropping
  in-flight packets**.
- Detection: inotify on the **directory** containing the config file.
  Watching the file directly would miss atomic-rename updates produced by
  vim, `sed -i`, and most config-distribution tools.
- Swap mechanism: atomic publication of a new compiled ruleset pointer;
  readers drain the old ruleset via a quiescent-state barrier
  (`rte_rcu_qsbr` is the expected primitive, to be confirmed in design).
- Target latency from inotify signal to new ruleset active: **≤ 100 ms**.
- **Rollback on failure**: if parsing, validation, or compilation of a new
  config fails, the old config stays active. The error is surfaced via logs
  and metrics. No partial / corrupt state is ever published.

#### F5 — Central config sync / control plane

- **v1 (MVP)**: local file + inotify reload is sufficient, matching pktgate
  today. This is simple, testable, and battle-tested.
- **v2+**: optional push channel from NOC / central orchestrator. Candidates
  (to be chosen in design, or deferred):
  - Unix domain socket command interface (`reload`, `status`, `dump-config`)
  - File-drop from a config distribution daemon (Ansible / Salt / custom)
  - HTTP POST receiver
  - gRPC server
  - Git-pull agent
- Atomicity: every push is either fully applied or fully rejected; no
  partial rule updates.
- Authentication/authorization for remote push is out of scope for v1 — if
  push is added, the design must address it (mTLS, Unix socket permissions,
  etc.).

#### F6 — Observability

**Per-rule counters**: packets matched, bytes matched, drops attributable to
the rule, rate-limit drops. Keyed by rule ID.

**Per-interface (DPDK port) counters**: RX pps/bps, TX pps/bps, RX drops, TX
drops, NIC-reported errors (via `rte_eth_stats`).

**Per-lcore counters**: packets processed, cycles per burst, RX queue depth
samples — for diagnosing imbalance and burst-loop health.

**Prometheus exposition**: HTTP `/metrics` endpoint in OpenMetrics format.
Separate control-plane thread, never in the hot path. Port configurable.
Parity with pktgate's metric naming is a nice-to-have but not mandatory —
the design may propose cleaner names as long as it justifies the break.

**sFlow export**: sampled packet headers over UDP to a configurable
collector. Configurable sample rate. Each sample includes: truncated
packet header, ingress port, timestamp, matched rule ID (if any). Encoder:
either `libsflow` (system package) or embedded; design to pick.

**Structured logs**: JSON lines written to stderr (captured by systemd /
journald) or UDP syslog. Levels: error, warn, info, debug. **No per-packet
logging on the hot path ever.** Rule match events can be sampled into the
log stream but only at low sample rates.

#### F7 — Safety and resilience

**Watchdog**: a supervisor process (systemd is the default; a dedicated
helper is acceptable if systemd cannot cover all requirements) monitors the
dataplane process. On crash: automatic restart with exponential backoff.
Each restart increments a metric and triggers an alert.

**Liveness signal**: the dataplane updates a heartbeat (shared memory
counter, file mtime, or telemetry value) every N milliseconds. The watchdog
detects **stalls** — a live process stuck in a loop or deadlocked — by
checking that the heartbeat advances, not just that the process exists.

**Bypass mode on sustained failure** (> K restart attempts within a window):
enter a fallback that keeps traffic flowing. Exact mechanism depends on
deployment:

- **Software forward-only mode**: dataplane stays up but skips filtering,
  forwarding RX → TX untouched. Always available; does not protect against
  a hard crash.
- **Kernel fallback**: unbind DPDK port, rebind to kernel driver, let kernel
  forwarding take over. Slow to engage, probably unusable at 40 Gbps, but
  reliable as a last resort.
- **Hardware bypass NIC**: bypass cards physically short-circuit on power
  loss or signal loss. Requires specific hardware (not e1000, not virtio).
- **Mirror-mode fallback** (inline → mirror): stop intercepting, start
  observing. Loses protection, keeps visibility.

**Fail-open vs fail-closed**: the customer wording implies **fail-open**
(bypass / mirror). This must be explicit: default behavior on unrecoverable
failure is **traffic flows unfiltered**, with loud alerting. Operators who
need fail-closed can override via config.

### 3.2 Non-functional (SLOs)

#### N1 — Throughput

40 Gbps sustained bidirectional per site.

The worst case for a packet-rate-limited design is 64-byte packets at line
rate: **59.52 Mpps bidirectional** at 40 Gbps. The design must target this
worst case, not just IMIX, even if the SLO is only formally defined against
"peak load".

#### N2 — Latency

≤ 500 µs p99 added per packet, customer-facing ceiling.

Internal target: **≤ 50 µs p99**. 500 µs is generous by two orders of
magnitude for a run-to-completion DPDK design; a well-written burst loop
runs in tens of microseconds at most. If internal measurements ever
approach 500 µs something has gone seriously wrong.

#### N3 — Packet loss

< 0.01 % under peak load. At 59.5 Mpps that is a budget of **< 5.95 Kpps**
sustained loss. This budget includes drops from classification (intentional
`drop` actions do NOT count — those are expected).

#### N4 — Rule scale

Starting point inherited from pktgate; revise during design if DPDK memory
and lookup structures make different numbers cheap:

| Category | Limit |
|---|---|
| Rules per layer | 4 096 |
| MAC entries (combined src + dst) | 4 096 |
| IPv4 prefixes | 16 384 |
| IPv6 prefixes | 16 384 |
| L4 port entries (post-expansion) | 4 096 |
| VRF entries | 256 |
| Rate-limit rules | 4 096 |
| EtherType entries | 64 |
| VLAN entries | 4 096 |
| PCP entries | 8 |

#### N5 — Startup and reload times

- Cold start (EAL init, port probe, mempool allocation, first config load):
  ≤ **5 seconds**
- Hot reload (inotify trigger → new ruleset active): ≤ **100 ms**

### 3.3 Constraints already agreed

These are **not** open questions. The design must take them as given.

- **Config format**: JSON only in v1, schema compatible with pktgate.
- **Code**: greenfield, no binary or source dependency on pktgate.
- **DPDK version baseline**: 25.11 (current stable, LTS candidate).
- **Build system**: CMake with `pkg-config libdpdk`. No meson for the
  project itself (DPDK is built with meson, that is upstream, not ours).
- **Language**: C++. C++17 or C++20 — design may pick, with C++20 preferred
  unless compiler compatibility forces C++17.
- **No YAML in v1.**
- **No gRPC / no REST in v1 control plane.** Local file + inotify only.
- **No runtime code generation.** Rules compile into static lookup
  structures; no LLVM, no JIT, no eBPF.
- **No kernel module.** Pure DPDK userspace.

---

## 4. Non-goals (explicit)

Calling these out is as important as the positive requirements — it shapes
the design and prevents scope creep.

- **No DPI, no L7 inspection, no protocol dissection.** `pktgate-dpdk` is a
  pre-filter; DPI lives upstream of it.
- **No TLS inspection, no decryption, no MITM.** Payloads past L4 headers
  are never touched.
- **No NAT, no connection tracking, no stateful firewalling.**
- **No routing protocol participation.** No BGP, no OSPF. VRF and prefix
  information is provided statically via config.
- **No IPSec, no VPN termination.**
- **No QoS scheduling, no WRED, no active queue management** beyond the
  simple per-rule rate-limit.
- **No flow table, no 5-tuple state.** Rate-limit buckets in MVP are keyed
  per rule, not per flow.
- **No eBPF anywhere in this project.**
- **No GUI, no web UI.** The operator surface is Prometheus + Grafana plus
  the config file.
- **Not a standalone product.** It is a component in a larger mobile-core
  observability/security stack.
- **Not a full replacement for pktgate.** pktgate (XDP) remains the choice
  for sites where AF_XDP or kernel integration is preferred.

---

## 5. Open questions for the design phase

The design agent is expected to pick and **justify** answers to these.
Where multiple options exist, the design document must list alternatives
and explain why the rejected ones were rejected.

### Q1 — Threading model

- **Option A**: lcore-per-RX-queue, run-to-completion. Each lcore does
  RX → classify → action → TX on its own queues. RSS spreads traffic
  across queues. Simplest, lowest latency, no inter-lcore queueing.
- **Option B**: RX lcore(s) + worker lcores via `rte_ring`. Classic
  pipeline. More flexible (workers can rebalance), but introduces ring
  latency and cross-core cache traffic.

**Likely default**: A, unless design shows classification cost on one lcore
exceeds the per-packet budget. Justify the choice.

### Q2 — Hot reload mechanism

- Atomic pointer swap with `rte_rcu_qsbr` quiescent-state barrier is the
  expected primitive. Readers publish quiescent state at the top of each
  burst loop; writer (control thread) swaps pointer, waits for all
  readers to pass quiescence, then frees old ruleset.
- Confirm this is the right primitive. Consider alternatives: plain atomic
  pointer with a generation counter, `rte_rcu_qsbr_dq` for deferred free,
  or a double-buffer with explicit barrier.
- Address corner cases: mid-burst reload, failed reload, nested reloads.

### Q3 — Lookup data structures (per layer)

Tentative mapping, to be confirmed:

| Field | Structure | Alternatives |
|---|---|---|
| L2 src / dst MAC | `rte_hash` (48-bit key packed into `uint64_t`) | `rte_member` |
| L2 EtherType | Small `rte_hash` or direct index | `rte_member` |
| L2 VLAN ID | `rte_hash` or direct index (12-bit space) | direct index |
| L3 IPv4 prefix | `rte_fib` (DIR-24-8) | `rte_lpm` |
| L3 IPv6 prefix | `rte_fib6` | `rte_lpm6` |
| L3 VRF | `rte_hash` keyed on VRF ID | direct index |
| L4 (proto, port) | `rte_hash` | ACL trie |
| Rate-limit | `rte_meter` (srTCM per rule) | home-grown token bucket |

Key questions:

- `rte_fib` vs `rte_lpm`: `rte_fib` is faster, uses more memory. For our
  prefix counts, is memory a concern?
- `rte_meter` vs home-grown bucket: `rte_meter` is standard but has quirks
  (color-aware, fixed committed/excess model). Is it a better fit than a
  simple token bucket?
- Compound L2 rules (src_mac + vlan_id + …): single multi-field `rte_hash`
  with a tuple key, or sequential lookups as pktgate does? Evaluate cache
  behavior on both.

### Q4 — Mirror implementation

- **Option A**: `rte_pktmbuf_copy` → TX on mirror port. Costs one mempool
  alloc and one memcpy per mirrored packet. Simple and safe.
- **Option B**: `rte_mbuf_refcnt_update` + direct TX on mirror port.
  Zero-copy, but both TX paths must tolerate shared mbufs. Driver support
  varies.

At 40 Gbps the cost of mirror is not negligible if many rules mirror.
Design must pick and justify; if Option B is chosen, the supported NIC
list must be documented.

### Q5 — Rule compilation pipeline

- JSON → AST (C++ structs) → validator → compiled ruleset (lookup tables,
  per-rule action descriptors, action parameter blobs).
- Where does compilation happen?
  - **(a)** In the dataplane process on reload. Simpler, one binary, less
    state to manage. **Default choice.**
  - **(b)** In a separate compiler binary that emits a binary blob; the
    dataplane loads the blob. Enables offline validation, smaller hot
    binary, clearer failure isolation.
- v1 should be (a). Call out in design whether (b) is a future option.

### Q6 — Control plane shape (v1)

- Local file + inotify (pktgate-style) — the default.
- Plus an optional **Unix domain socket command interface** for
  introspection (`reload`, `status`, `dump-config`, `dump-rule N`) and for
  triggering a reload from an external tool without touching the file
  mtime. `rte_telemetry`-style, or a small purpose-built protocol.
- Which combination is MVP? Design decides.

### Q7 — Telemetry surface

Decide how these coexist:

- Prometheus HTTP endpoint (own thread, off hot path)
- `rte_telemetry` over UDS (DPDK idiomatic, integrates with
  `dpdk-telemetry.py`)
- sFlow UDP exporter (embedded or sidecar process)
- Structured logs (stderr JSON vs syslog vs both)

At least Prometheus + sFlow + structured logs are required. `rte_telemetry`
is a bonus that is cheap to enable.

### Q8 — Bypass mode (MVP selection)

Which bypass modes are **MVP**, which are follow-ups?

- Software forward-only mode — always available, always MVP
- Kernel driver fallback — MVP or v2?
- Hardware bypass NIC — v2 or later (hardware-dependent)
- Mirror-mode fallback — only meaningful for inline-deployed sites

Recommendation: **software forward-only as MVP**; mirror-mode fallback as
MVP **if** mirror deployment is day-one; hardware bypass as a future item.
Justify in design.

### Q9 — Error handling philosophy

- **Config errors**: reject the entire new config, keep the old one active,
  log loudly, increment a metric.
- **Runtime errors on the hot path** (TX drop, mempool exhaustion, mbuf
  alloc fail): drop the offending packet, bump the appropriate counter,
  continue. **Never crash on a packet-path error.**
- **Fatal errors** (mempool allocation failure at startup, port
  initialization failure, ruleset compilation failure at first load):
  fail fast with a clear error message, exit non-zero, let the watchdog
  restart.

Confirm this taxonomy and call out any additional categories the design
needs (e.g. NIC link down, PCI error, hugepage exhaustion during reload).

### Q10 — Performance validation strategy

The dev VM has no production hardware. How do we validate the 40 Gbps SLO?

- **Dev VM**: correctness tests only. `net_pcap` vdev or `net_af_packet`
  vdev, small synthetic traffic, functional equivalence.
- **Lab hardware**: TRex or IXIA for line-rate validation. Requires
  scheduling, not day-one.
- **Software generator cross-test**: `pktgen-dpdk` on a second host for
  mid-range validation.

Design must produce a **test matrix**: which tests run where, which block
release, which are nice-to-have.

### Q11 — Rule schema versioning

The schema will evolve. How do we handle:

- running old binary + new config: strict rejection? Best-effort?
- running new binary + old config: implicit upgrade? Explicit migration?

Recommendation: **strict version match in v1** (config has a `version`
field; binary rejects mismatches). Migration story documented as future
work.

### Q12 — Resource sizing guidance

The design should include **concrete heuristics** operators can use to
size a deployment:

- mempool size as a function of ports, queues, burst size, drain latency
- number of lcores as a function of RX queues and RSS
- hugepage minimums at various rule scales and port counts
- CPU isolation recommendations (`isolcpus`, `rcu_nocbs`, `nohz_full`)

These can be rough rules of thumb; the point is operators should not have
to guess.

---

## 6. Reference material

### 6.1 Existing pktgate (XDP) — for architecture lessons and JSON schema

- `/home/user/filter/ARCHITECTURE.md` — full architecture description. The
  sections on layered pipeline, hot reload, compound L2 rules, counters,
  and action semantics are especially relevant.
- `/home/user/filter/CONFIG.md` — JSON schema narrative, action
  parameters, rule examples, limits table.
- `/home/user/filter/config-schema.json` — formal JSON schema.
  `pktgate-dpdk` must validate against this (or a documented superset).
- `/home/user/filter/scenarios/*.json` — real-world scenario configs.
  These **must** validate on `pktgate-dpdk`.
- `/home/user/filter/scenarios_v2/` — extended scenarios,
  requirements-driven.
- `/home/user/filter/src/compiler/` — rule compiler in pktgate (C++).
  Read for algorithms: compound rule flattening, port group expansion,
  key collision detection. **Code is not reused**, only the algorithms.
- `/home/user/filter/functional_tests/` — pytest + scapy functional tests.
  Useful as a source of test cases and traffic patterns, even though the
  test harness must be reinvented for DPDK (`net_pcap` vdev or
  `net_af_packet` vdev).

### 6.2 DPDK 25.11 APIs likely to be load-bearing

- `rte_eal` — environment, lcores, memory
- `rte_ethdev` — port config, queues, offloads, RSS
- `rte_mbuf` + `rte_mempool` — packet buffers, metadata area, dynfields
- `rte_fib` / `rte_fib6` — IPv4/IPv6 LPM
- `rte_hash` — L2 / L4 lookup tables
- `rte_meter` — rate-limit (srTCM / trTCM)
- `rte_rcu_qsbr` — hot reload quiescence
- `rte_telemetry` — introspection and control plane option
- `rte_timer` — periodic tasks (stats snapshot, heartbeat)
- `rte_ring` — if pipeline threading model is chosen
- `rte_flow` — offload L2 / L3 classification to the NIC if supported
  (future optimization, flag in design)
- `rte_ether` / `rte_ip` / `rte_tcp` / `rte_udp` — header parsing macros

### 6.3 DPDK examples worth cribbing patterns from

- `examples/l3fwd` — lcore-per-queue + LPM. Closest baseline for our
  dataplane.
- `examples/l3fwd-acl` — ACL lookup with multi-field classification.
  Closest to our multi-field match semantics.
- `examples/skeleton` — minimal init; reference for "hello world".
- `examples/ip_pipeline` — more elaborate pipeline with
  rte_pipeline/rte_table. Useful even if we do not adopt it wholesale.
- `examples/bond` — port bonding. Not MVP, but useful reading for
  failover patterns.

---

## 7. Expected deliverables from the design phase

The design agent should produce **one comprehensive design document**
covering, at minimum:

1. **Executive summary** — one paragraph: what the system is and how it
   satisfies the SLOs.
2. **High-level architecture** — block diagram (ASCII or mermaid),
   data flow from RX to TX, and from control plane to dataplane.
3. **Module breakdown** — each module's responsibility, public interface,
   dependencies on other modules, and on DPDK libraries.
4. **Data structures** — compiled ruleset layout, cache-alignment choices,
   per-lcore private state, mempool layout.
5. **Hot path walkthrough** — pseudocode of the burst loop, showing
   classification, action dispatch, TX. Explicit about branch behavior and
   cache access patterns.
6. **Lifecycle** — init, steady state, hot reload, shutdown, crash
   recovery. Sequence diagrams where useful.
7. **Threading and lcore layout** — which lcore does what, how many of
   each, how RSS is configured, NUMA policy.
8. **Memory layout** — mempools, hugepage usage, per-port and per-lcore
   allocations.
9. **Hot reload strategy** — RCU mechanics, failure handling, corner
   cases, measured / expected reload latency.
10. **Telemetry surface** — exact metric names, label dimensions, sFlow
    sampling details, log schema, `rte_telemetry` endpoint list.
11. **Failure modes and responses** — table of failure → detection →
    action → recovery.
12. **Test strategy** — unit, functional, perf; what runs in dev VM vs
    hardware; CI integration; acceptance criteria per phase.
13. **Project structure** — directory layout, CMake targets, dependency
    graph between targets.
14. **Phase plan** — MVP scope (what ships first), v2, v3, with explicit
    exit criteria for each phase.
15. **Risk register** — top 5 risks with mitigations.
16. **Unresolved open questions** — any Q from §5 that the design could
    not resolve, with reasoning and a path to resolution.

**Out of scope for the design phase**: no code, no `CMakeLists.txt`, no
real file layout on disk yet. Just the document. Implementation starts
after the design is reviewed and approved.

---

*End of input document.*
