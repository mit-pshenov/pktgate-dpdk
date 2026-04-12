# Unit test plan (draft)

> Scope: fast, in-memory, pure-C++ unit tests. Primary link target:
> `libpktgate_core.a` (DPDK-free where possible). Tests that must
> touch EAL minimally — mbuf pools, dynfield registration — are
> explicitly tagged **[needs EAL]** so the harness author can put
> them in a separate binary that runs with a tiny test EAL (one
> lcore, ~64 MiB hugepages, `--no-huge --no-pci` where it works).
>
> Not in scope here: functional dataplane tests on `net_pcap`
> vdev, stress/soak, perf on lab hardware, fuzzing. Those live
> in sibling plans.
>
> Each test references the `D`-decision(s) it covers. D-decisions
> that are not unit-testable at all (need multi-process, real NIC,
> lab hardware, or a full reload cycle with mempools) are called
> out in the coverage matrix with a pointer to the right layer.

---

## U1 — Config parser (`src/config/parser.*`)

Link target: `libpktgate_core.a`. Pure JSON → AST / model.h.
No EAL, no mempool, no sockets.

### U1.1 Valid minimal config
- Goal: a document containing only `version`, `interface_roles`,
  `default_behavior`, and an empty `pipeline` parses cleanly.
- Inputs: smallest legal JSON with `version: 1`,
  `interface_roles: { upstream_port: { pci: "0000:00:00.0" },
  downstream_port: { pci: "0000:00:00.1" } }`, empty
  `pipeline.layer_{2,3,4}`, `default_behavior: "drop"`,
  no `fragment_policy` (must default).
- Assertions: parser returns success; model exposes exactly two
  `interface_roles`; both layers are empty; `default_behavior ==
  DROP`; `fragment_policy == L3_ONLY` (default per D17/P9); no
  diagnostics.
- Covers: F3, D8, D17/P9.

### U1.2 Strict `version` mismatch rejected (D8/Q11)
- Goal: parser rejects a document whose `version` differs from
  the binary's compiled-in `PKTGATE_SCHEMA_VERSION`.
- Inputs: `version: 0` and `version: 999`.
- Assertions: parser returns `VersionMismatch` error; error
  message names both expected and received versions; no partial
  model produced.
- Covers: D8, Q11.

### U1.3 Unknown top-level field rejected
- Goal: strict-schema posture — any unknown top-level key fails.
- Inputs: top-level `{"foo": 42, …rest valid…}`.
- Assertions: `UnknownField` error citing the offending key; no
  partial model; exit code non-zero (if called via CLI
  test harness).
- Covers: D8.

### U1.4 `interface_roles` sum-type — pci selector
- Goal: `{ "pci": "0000:03:00.0" }` parses as a `PciSelector`
  with correctly decomposed domain/bus/device/function.
- Assertions: selector discriminant is `Pci`; BDF round-trips
  through the model's canonical string form.
- Covers: D5, D8.

### U1.5 `interface_roles` sum-type — vdev selector
- Goal: `{ "vdev": "net_pcap0,tx_iface=lo" }` parses; arg string
  preserved verbatim.
- Covers: D5, D8, M1 (dev VM vdev path).

### U1.6 `interface_roles` sum-type — name selector
- Goal: `{ "name": "net_tap0" }` parses.
- Covers: D5, D8.

### U1.7 `interface_roles` sum-type — mixed keys rejected
- Goal: `{ "pci": "…", "vdev": "…" }` is an error.
- Assertions: parser returns `InvalidRoleSelector` with both
  offending keys named.
- Covers: D5 (architectural anti-pattern), D8.

### U1.8 CIDR — valid IPv4
- Inputs: `"10.0.0.0/8"`, `"0.0.0.0/0"`, `"192.168.1.1/32"`.
- Assertions: each parses to a `Cidr4{addr, prefixlen}` with
  host bits zeroed where required by prefix length.
- Covers: F1/L3, D8.

### U1.9 CIDR — invalid IPv4 rejected
- Inputs: `"10.0.0.0/33"`, `"256.0.0.0/8"`, `"10.0.0.0/-1"`,
  `"10.0.0.0"` (missing prefix length), `"10.0.0.0/8extra"`.
- Assertions: each is a parse error; error kind is
  `BadCidr`; offending string reported.
- Covers: D8.

### U1.10 CIDR — valid IPv6
- Inputs: `"2001:db8::/32"`, `"::/0"`, `"fe80::1/128"`,
  `"::ffff:192.0.2.1/128"`.
- Assertions: each parses; addr normalized to 16 bytes.
- Covers: F1/L3, D8.

### U1.11 CIDR — IPv6 with embedded IPv4 parsed as IPv6
- Inputs: `"::ffff:10.0.0.0/104"`.
- Assertions: parsed as IPv6, not IPv4.
- Covers: D8.

### U1.12 MAC — valid and canonicalized
- Inputs: `"aa:bb:cc:dd:ee:ff"`, `"AA-BB-CC-DD-EE-FF"` (if the
  schema allows hyphen form — otherwise U1.13 rejects it).
- Assertions: parses to 6-byte MAC; canonical string is
  lowercase colon form.
- Covers: D8.

### U1.13 MAC — invalid rejected
- Inputs: `"aa:bb:cc:dd:ee"` (5 octets), `"zz:…"`, `""`,
  `"aa:bb:cc:dd:ee:ff:00"` (7 octets).
- Assertions: `BadMac` error.
- Covers: D8.

### U1.14 `fragment_policy` enum accepted
- Inputs: each of `"l3_only"`, `"drop"`, `"allow"`.
- Assertions: each parses to the corresponding enum value.
- Covers: D17, P9.

### U1.15 `fragment_policy` unknown value rejected
- Inputs: `"l2_only"`, `"maybe"`, `42`.
- Assertions: `BadEnum` error on each.
- Covers: D17.

### U1.16 `fragment_policy` missing defaults to `l3_only`
- Goal: confirm P9 default.
- Covers: D17, P9.

### U1.17 Numeric range — port 0..65535
- Inputs: `{ "dst_port": 0 }`, `{ "dst_port": 65535 }`,
  `{ "dst_port": -1 }`, `{ "dst_port": 65536 }`,
  `{ "dst_port": "80" }`.
- Assertions: 0 and 65535 accepted; others rejected with
  `OutOfRange` / `TypeMismatch`.
- Covers: D8.

### U1.18 Numeric range — vlan_id 0..4095
- Same pattern, 0..4095 bounds.
- Covers: D8.

### U1.19 Numeric range — PCP 0..7
- Same pattern.
- Covers: D8.

### U1.20 Port list `[22, 80, 443]` parsed as array of ints
- Covers: D8, F1 (port groups / lists).

### U1.21 Rate spec `"200Mbps"` → bytes/sec
- Goal: parser converts bps → bytes/sec at load time (per §5.5
  comment).
- Inputs: `"200Mbps"`, `"1Gbps"`, `"64kbps"`, `"1"` (bytes?
  depends on schema — reject if ambiguous), `"banana"`.
- Assertions: first three produce the expected
  `rate_bytes_per_sec` (25_000_000, 125_000_000, 8_000); bad
  forms are rejected.
- Covers: D1, D8.

### U1.22 `rate-limit` action parses `burst_ms`
- Inputs: `{ "type": "rate-limit", "rate": "200Mbps",
  "burst_ms": 10 }`.
- Assertions: `burst_bytes == rate_bytes_per_sec * 10 / 1000`.
- Covers: D1, D8.

### U1.23 `hw_offload_hint` optional, defaults false
- Covers: D4, D8.

### U1.24 Rule `id` required, must be positive integer
- Inputs: missing `id`, `id: 0`, `id: -1`, `id: "42"`.
- Assertions: all rejected; `id: 1` accepted.
- Covers: D8 (stable ids), D11 (rule_id lifecycle).

### U1.25 `sizing` section inline accepted
- Goal: inline `sizing` parses and populates the sizing struct.
- Covers: D6, D8.

### U1.26 `sizing` missing → dev defaults applied
- Goal: missing `sizing` section yields the documented dev
  defaults (256 rules/layer, …).
- Covers: D6, M1.

### U1.27 `sizing` values below hard minimum rejected
- Inputs: `rules_per_layer_max: 8` (< 16 minimum per D6 §3a.2).
- Assertions: `SizingBelowMin` error.
- Covers: D6.

### U1.28 `objects.subnets` object-reference resolved
- Goal: `src_subnet: "corp_v4"` parses as object reference and
  the unresolved form survives the parse stage (resolution is
  the validator's job).
- Covers: D8 (object model), compiler pipeline step.

### U1.29 Action exactly-one invariant
- Goal: a rule with two `action` values or none is rejected.
- Inputs: `"action": { "type": "allow", "target_port": "x" }`
  where mixing fields violates the sum-type.
- Assertions: rejected with `AmbiguousAction` or equivalent.
- Covers: D7, D8, F2.

### U1.30 `tcp_flags` sub-object parses
- Inputs: `{ "syn": true, "ack": false }`.
- Assertions: produces a mask/want pair matching the
  L4CompoundEntry semantics.
- Covers: F1, D15.

### U1.31 Large-but-valid config (stress-lite)
- Goal: a synthetic config with 4096 L3 rules and 4096 L4
  rules parses in < 500 ms and produces a model of the
  expected size.
- Covers: D6, performance regression guard.

### U1.32 `objects.subnets` dictionary parses
- Goal: the `objects.subnets` top-level dictionary parses as an
  ordered list of `SubnetObject` entries (name → list of CIDRs).
  Each CIDR element is a string, parsed via `addr.h` into a
  `SubnetCidr` sum of (`Cidr4`, `Cidr6`); v4/v6 may be mixed in
  one named subnet. Missing `objects` section produces an empty
  pool, not an error. Malformed CIDR → `kBadCidr` with the
  offending literal named in the message. Non-string CIDR list
  element → `kTypeMismatch`. Unknown key under `objects` (e.g.
  `mac_groups`) → `kUnknownField` — C6 only implements `subnets`.
  Dangling rule → pool references are **not** checked here; that
  is the validator's job (C7+).
- Covers: D8 (strict object dict parsing, object model).

### U1.33 L2 compound key happy path
- Goal: a single rule carries `src_mac`, `dst_mac`, `ethertype`
  and `vlan_id` simultaneously and the parser populates all four
  fields on the resulting `Rule`. Canonical "L2 compound key"
  shape the C8 collision detector will build on. `filter_mask`
  is NOT a JSON field — the M2 compiler derives it from which
  secondary fields are present (design §4.1 L2CompoundEntry).
- Inputs: layer_2 rule with `src_mac: "aa:bb:cc:dd:ee:ff"`,
  `dst_mac: "11:22:33:44:55:66"`, `ethertype: 2048` (= 0x0800
  IPv4), `vlan_id: 42`, `action: { "type": "drop" }`.
- Assertions: `Rule.src_mac.has_value()` and bytes match;
  `Rule.dst_mac` same; `Rule.ethertype == 0x0800`;
  `Rule.vlan_id == 42`.
- Covers: D8, D15 (L2 compound primary — parser half).

### U1.34 L2 compound field negatives
- Goal: malformed literals for the three new L2 fields are
  rejected with the matching `ParseError` kind. Proves the
  parser validates the fields rather than blindly storing
  strings.
- Inputs: `src_mac: "not_a_mac"` → `kBadMac`;
  `dst_mac: "aa:bb:cc:dd:ee"` (five octets) → `kBadMac`;
  `ethertype: 65536` → `kOutOfRange`;
  `ethertype: -1` → `kOutOfRange`;
  `ethertype: "0x0800"` (string) → `kTypeMismatch`.
- Covers: D8.

### U1.35 `next_layer` enum parses
- Goal: `next_layer` accepts `"l2"`, `"l3"`, `"l4"` and
  populates `Rule.next_layer` as `std::optional<NextLayer>`.
  Rejects any other literal and non-string types. The parser
  does NOT enforce ordering — cross-layer validity ("l2 on a
  layer_3 rule is illegal") is the C8 validator's job (U2.19).
  Absent field → `Rule.next_layer.has_value()` false.
- Inputs: `"l2"`/`"l3"`/`"l4"` each parses to the matching
  `NextLayer` enum value; `"l5"` → `kBadEnum`; `3` (integer) →
  `kTypeMismatch`; field omitted → optional stays empty.
- Covers: F1 (pipeline order, parser half), D8.

---

## U2 — Validator (`src/config/validator.*`)

### U2.1 Object reference resolution — valid
- Goal: a rule referencing an existing
  `objects.subnets.corp_v4` resolves to the CIDR list.
- Covers: D8 (object model).

### U2.2 Object reference — dangling rejected
- Inputs: rule references `src_subnet: "ghost"` not declared.
- Assertions: `UnresolvedObject` error naming `ghost`.
- Covers: D8.

### U2.3 `interface_roles` reference resolution — valid
- Goal: a rule with `interface: "upstream_port"` resolves to a
  role defined in `interface_roles`.
- Covers: D5.

### U2.4 `interface_roles` reference — dangling
- Goal: rule referencing an undeclared role is rejected.
- Covers: D5, D8.

### U2.5 Duplicate rule `id` within a layer rejected
- Inputs: two `layer_3` rules both `id: 2001`.
- Assertions: `DuplicateRuleId` error; both line/index
  locations reported.
- Covers: D8.

### U2.6 Same rule `id` allowed across different layers
- Goal: rule_id `1001` may appear once in layer_2 and once in
  layer_3 — counters/rl_arena key on `(layer, rule_id)` not
  globally, per §4.3 layer_base().
- Assertions: no error.
- Covers: D8, §4.3.

### U2.7 Collision detection — two L2 rules with identical
  compound key
- Inputs: two rules with the same src_mac + vlan + ethertype
  and no distinguishing filter_mask bit.
- Assertions: `KeyCollision` error (first-match-wins would
  render the second rule dead; the validator catches it so
  operators don't silently lose rules).
- Covers: D15 (compound model), D8.

### U2.8 Action parameter bounds — `dscp` 0..63
- Inputs: DSCP values 0, 63, 64, -1.
- Assertions: 0 and 63 accepted; 64/-1 rejected.
- Covers: D8, F2 (TAG).

### U2.9 Action parameter bounds — `pcp` 0..7
- Covers: D8, F2.

### U2.10 Rate-limit `rate` > 0
- Inputs: `"0bps"`, `"-10Mbps"`.
- Assertions: rejected; positive values accepted.
- Covers: D1.

### U2.11 `target_port` must reference a role
- Goal: redirect/mirror `target_port` must resolve to
  `interface_roles`.
- Covers: D5.

### U2.12 Mirror action accepted syntactically at validator
- Goal: validator accepts `action: mirror` (the compiler
  rejects at publish time per D7 — tested in U3.17).
- Covers: D7.

### U2.13 Budget pre-flight — per-rule expansion ceiling
  (D37 gate 1)
- Inputs: a rule with `dst_port: [0..65535]` expanding to
  65 536 L4 entries (above the default ceiling 4 096).
- Assertions: `BudgetPerRuleExceeded` error; rule_id and
  expansion count reported; compile stage never reached.
- Covers: D37.

### U2.14 Budget pre-flight — aggregate ceiling
  (D37 gate 2)
- Inputs: 4 rules each expanding to 1 025 L4 entries (total
  4 100 > `sizing.l4_entries_max=4096`).
- Assertions: `BudgetAggregateExceeded`; sum reported.
- Covers: D37.

### U2.15 Budget pre-flight — hugepage estimate
  (D37 gate 3)
- Inputs: sizing config inflated so the estimated
  `expected_ruleset_bytes()` exceeds a provided (mocked) free
  hugepage count.
- Assertions: `BudgetHugepage` error; estimated vs available
  reported. Uses a test-only hugepage-probe injection point.
- Covers: D37.

### U2.16 Budget pre-flight — hostile config under
  aggregate ceiling but within per-rule ceiling passes
- Goal: negative test for false-positive. 100 rules each
  expanding to 30 entries (3 000 total, well under 4 096).
- Assertions: validator succeeds; compiler stage reachable.
- Covers: D37.

### U2.17 Validator short-circuits on first budget failure
- Goal: on D37 failure the validator returns without invoking
  any compile stage — verified by a test compiler spy that
  asserts it was never called.
- Covers: D37.

### U2.18 `cmd_socket.allow_gids` parses; resolution deferred to daemon init
- Goal: parser accepts an explicit `allow_gids` list (non-negative
  integers → `gid_t`). Absent `cmd_socket` or absent `allow_gids`
  leaves `Config.cmd_socket.allow_gids` as `std::nullopt` — the
  sentinel "resolve at daemon init (M11)".
- Negative assertion: neither parser nor validator may invoke
  `::getgid()` / `::getgrnam()` / any gid-resolution syscall.
  Resolution is M11 cmd_socket bind territory, after the daemon
  has dropped to the pktgate user. Offline `--validate-config`
  running as a different user must not capture the wrong gid.
- Covers: D38 (schema-only at M1; real SO_PEERCRED in M11).

### U2.19 Layer evaluation order enforced by validator
- Goal: a rule with `next_layer: "l2"` from inside layer_3 is
  rejected (can only advance L2→L3→L4).
- Covers: F1.

### U2.20 `default_behavior` present and enum-bounded
- Covers: D8, F1.

---

## U3 — Compiler (object compiler, rule compiler, ruleset
 builder scaffolding — `src/compiler/*`)

Unit scope: pure-C++ transformations from validated AST to
compiled-model structs. No `rte_hash`/`rte_fib` allocation in
these tests — those live in U4 (`needs EAL`).

### U3.1 Object compiler — subnet list flatten
- Goal: `subnets.corp_v4 = ["10.0.0.0/8", "10.1.0.0/16"]`
  flattens to a 2-element `Cidr4[]` post-expansion.
- Covers: D8.

### U3.2 Object compiler — port group expansion
- Goal: `port_groups.web_ports = [80, 443, 8080]` expands into
  three L4 primary entries keyed
  `{proto=tcp, dport=80 / 443 / 8080}` (selectivity preserved).
- Covers: D15, F1.

### U3.3 Port-list on a single rule expands to multiple entries
- Goal: a rule with `dst_port: [22, 80, 443]` produces three
  L4 compound entries, all pointing at the *same*
  `L4CompoundEntry` index (the action descriptor is shared).
- Covers: D15.

### U3.4 Monotonic `counter_slot` assignment per layer
- Goal: N L2 rules get counter_slots in `[0..N)` contiguously
  per layer_base. Verifies §4.3 dense slot assignment.
- Covers: §4.3, D33.

### U3.5 Compiled `RuleAction` sizing invariant (static_assert)
- Goal: a static-assert test confirming
  `sizeof(RuleAction) == 20` and `alignof(RuleAction) == 4`.
- Covers: D22.

### U3.6 Compiled `L2CompoundEntry` sizing invariant
- Goal: `sizeof(L2CompoundEntry) == 16` static_assert.
- Covers: 2nd external review result, §4.1.

### U3.7 L2 compound construction — src_mac primary
- Goal: a rule with src_mac constraint becomes an entry in
  `l2_src_mac` hash with `filter_mask` bits reflecting any
  secondary constraints (vlan / ethertype / dst_mac / pcp).
- Covers: D15, F1.

### U3.8 L2 compound — src+dst+vlan selectivity ordering
- Goal: when a rule constrains src_mac, dst_mac, vlan, and
  ethertype, the compiler picks src_mac as primary (per
  §5.2 selectivity order) and puts the rest in the filter_mask
  bitmap.
- Covers: D15, §5.2.

### U3.9 L4 compound — proto+dport primary
- Goal: rule `{proto: tcp, dst_port: 443}` becomes an entry in
  `l4_proto_dport` keyed `(tcp<<16 | 443)`; `filter_mask` has
  no bits set.
- Covers: D15.

### U3.10 L4 compound — proto+dport+sport has SRC_PORT bit
- Goal: with src_port also constrained, the SRC_PORT bit is
  set in `L4CompoundEntry.filter_mask` and `want_src_port` is
  populated.
- Covers: D15.

### U3.11 L4 compound — proto only goes to `l4_proto_only`
- Goal: rule `{proto: icmp}` with no port constraint lands in
  `l4_proto_only` hash, not the dport/sport tables.
- Covers: D15.

### U3.12 L4 compound — ICMP type+code packing (D29)
- Goal: a rule matching `icmp type=8 code=0` packs type into
  dport slot, code into sport slot; SRC_PORT bit set because
  code is constrained; no separate `want_icmp_code` field.
- Covers: D14 (packing), D29.

### U3.13 Rule tiering — default software
- Goal: rules without `hw_offload_hint` get
  `execution_tier == SW`.
- Covers: D4.

### U3.14 Rule tiering — operator hint honored
- Goal: `hw_offload_hint: true` produces `execution_tier == HW`
  in the compiled `RuleAction`.
- Covers: D4.

### U3.15 Rule tiering — MVP may globally disable
- Goal: with `g_cp.hw_offload_enabled == false`, compiler
  demotes all rules back to SW at publish time.
- Covers: D4, §14 MVP.

### U3.16 First-match-wins iteration order preserved
- Goal: within a layer, compiled `RuleAction[]` entries appear
  in the order the rules were declared in the JSON — the
  `action_idx` assigned to each primary-hash entry reflects
  config order.
- Covers: F1.

### U3.17 Mirror action compile-time reject (D7 MVP)
- Goal: compiling a ruleset containing `action: mirror`
  produces a `MirrorNotImplemented` error at the compile
  stage (not at parse/validate).
- Covers: D7.

### U3.18 D26 mirror strategy selection — deep copy if TAG
  present
- Goal: a ruleset with any TAG rule forces
  `mirror_strategy == DEEP_COPY`, even if
  `config_requests_zero_copy == true`. The `MUTATING_VERBS`
  set is consulted.
- Assertions: builder output carries `DEEP_COPY`; log / field
  records the reason "mutating verbs present".
- Covers: D26.

### U3.19 D26 mirror strategy — refcnt allowed when no
  mutating verbs
- Goal: a ruleset without TAG (only ALLOW/DROP/RL/REDIRECT)
  plus `config_requests_zero_copy == true` plus a mocked
  driver capability `tx_non_mutating == true` yields
  `REFCNT_ZERO_COPY`.
- Covers: D26.

### U3.20 D26 mirror strategy — driver capability gate
- Goal: same as U3.19 but driver cap is false → forced back
  to `DEEP_COPY`.
- Covers: D26.

### U3.21 D26 `MUTATING_VERBS` enum-scan test
- Goal: test iterates all values of the `ActionVerb` enum
  and asserts each is classified as mutating or non-mutating
  in the compiler's `is_mutating_verb()` lookup table.
  Prevents a new verb being added without D26 update.
- Covers: D26 (enforcement arm), D25 (switch-enum pairing).

### U3.22 `-Wswitch-enum` compile-time coverage — action verbs
- Goal: a negative compile test (test build target that is
  *expected* to fail) adds a new dummy `ActionVerb` and
  confirms `apply_action`'s switch does not compile without
  handling it. Alternative: runtime enum iteration asserting
  every value of `ActionVerb` maps to a known case in the
  compiler's dispatch table.
- Covers: D25.

### U3.23 `-Wswitch-enum` — verdict layer coverage
- Same pattern as U3.22 for `Verdict` enum in the apply_action
  outer switch.
- Covers: D21, D25.

### U3.24 Collision detection — L4 compound identical keys
- Goal: two L4 rules with identical primary key AND identical
  filter_mask content are reported as a collision (dead rule).
- Covers: D15, compiler correctness.

### U3.25 Port-list with duplicates flagged or deduped
- Goal: `dst_port: [80, 80, 443]` either errors or produces
  two unique entries (policy per schema doc, test whichever
  is chosen — assert the policy is consistent).
- Covers: D8.

### U3.26 Empty pipeline compiles to a valid empty ruleset
- Goal: all three layers empty produces a ruleset where every
  hash lookup misses and the packet falls through to
  `default_behavior` at every layer.
- Covers: F1 (default behavior).

---

## U4 — Ruleset builder (`src/ruleset/builder.*`)

Link: `libpktgate_core.a` for the pure parts; `rte_hash` /
`rte_fib` allocation tests are **[needs EAL]**.

### U4.1 Arena sizing from `sizing` config
- Goal: builder reads `sizing.rules_per_layer_max == 1024` and
  allocates `l2_actions[1024]`, `l3_actions[1024]`,
  `l4_actions[1024]`, and `by_rule[3072]` counter rows per
  lcore. No hardcoded constants anywhere in the allocated
  sizes. Allocation sizes verified against expected byte
  counts.
- Covers: D6.

### U4.2 FIB4 population [needs EAL]
- Goal: for a ruleset with three L3v4 rules with distinct
  destination prefixes, the compiled `rte_fib*` answers
  `rte_fib_lookup_bulk` correctly for addresses inside and
  outside each prefix.
- Covers: F1/L3, §4.1.

### U4.3 FIB6 population [needs EAL]
- Same as U4.2 for IPv6.
- Covers: F1/L3.

### U4.4 L2 `rte_hash` population [needs EAL]
- Goal: `l2_src_mac` returns the expected `action_idx` for
  configured src_mac rules and -ENOENT for random MACs.
- Covers: F1/L2, §5.2.

### U4.5 L4 primary hash population [needs EAL]
- Goal: `l4_proto_dport` returns index for `(tcp|443)`,
  `l4_proto_sport` for `(udp|53)` src case, `l4_proto_only`
  for `icmp` catch-all.
- Covers: D15.

### U4.6 Per-lcore counter row layout
- Goal: `PerLcoreCounters` is laid out
  `[lcore_id][layer_base + counter_slot]` and each
  `RuleCounter` is 64 B aligned. No row straddles cache lines.
- Assertions: pointer arithmetic checks + `static_assert`.
- Covers: D3, §4.3.

### U4.7 NUMA socket id propagation (D23)
- Goal: builder invoked with `socket_id = 1` allocates all
  Ruleset arrays on socket 1 (verified by inspecting the
  passed socket id through an allocator spy that records
  each call).
- Covers: D23.

### U4.8 `RuleAction` 20 B / alignas(4) static_assert in
  builder
- Goal: unit test is a compile-time assertion that the
  builder's declaration of `RuleAction` still matches the
  layout invariant. If someone ever adds a field the build
  breaks.
- Covers: D22.

### U4.9 `rl_arena` slot lifecycle — first publish
- Goal: calling `rl_arena_alloc_slot(rule_id=100)` on an
  empty arena picks a free index, marks it live, zero-inits
  `rows[slot].per_lcore[*]`, and inserts 100→slot in
  `id_to_slot`.
- Covers: D24.

### U4.10 `rl_arena` slot lifecycle — rule survives reload
- Goal: two successive builder passes with the same rule_id;
  the second pass finds the existing slot via `id_to_slot`
  and returns the same slot index. Bucket state is preserved
  (tokens / last_refill_tsc unchanged).
- Covers: D11, D24.

### U4.11 `rl_arena` slot lifecycle — rule removed
- Goal: rule_id present in `rs_old`, absent in `rs_new`. GC
  pass (§9.4) calls `rl_arena_free_slot(rule_id)`; slot is
  marked free in `slot_live`; `id_to_slot` entry dropped;
  row memory is **not** deallocated.
- Covers: D11, D24 (slot release, not row free).

### U4.12 `rl_arena` slot lifecycle — slot reuse clears
- Goal: allocate slot, free slot, allocate new rule_id — slot
  may be reused; new allocation zeroes `rows[slot].per_lcore`.
  Tokens and last_refill_tsc all zero after reuse.
- Covers: D24 (slot reuse), §4.4.

### U4.13 GC ordering — remove-before-free invariant (D11)
- Goal: a mocked reload pipeline where the GC pass is
  triggered while the arena still carries both rule_ids.
  Assertion: `rl_arena_free_slot` is called *after* the
  rcu_synchronize callback fires — the test replaces
  synchronize with a barrier it controls. If slot free
  happens before barrier, test fails.
- Covers: D11.

### U4.14 Counter row zeroed on slot reuse (§4.3 / 2nd
  external review)
- Goal: the GC pass walks removed `counter_slot`s and zeroes
  `by_rule[layer_base + counter_slot]` on *every* lcore.
  Verified by pre-populating the rows with non-zero values,
  running GC for the removed rule, and checking zeros.
- Covers: D33 (counter-slot zeroing invariant).

### U4.15 Ruleset NUMA locality — pointers point to
  expected socket
- Goal: D23; after build, every major arena pointer is on the
  declared socket (verified via a `rte_malloc_socket_id` spy
  or, when EAL is available, `rte_malloc_virt2iova` + socket
  lookup).
- Covers: D23.

### U4.16 Port TX-queue symmetry pre-check (D28)
- Goal: builder-time helper `check_port_tx_symmetry(roles,
  n_workers, eth_dev_info_mock)` rejects any role whose
  mocked `max_tx_queues < n_workers`. Pure-C++ unit with a
  fake `EthDevInfo` struct (no EAL).
- Covers: D28.

### U4.17 Generation counter increments monotonically
- Goal: each successful build increments `ruleset.generation`
  exactly once.
- Covers: D12 polish, §4.1 metadata.

### U4.18 D39 port scatter-off + mempool-fit validator [needs EAL]
- Goal: `check_no_scatter()` rejects when mempool data room is
  smaller than `max_rx_pkt_len`, accepts when it fits.
- Setup: EAL with `net_null` vdev; create two mempools: one with
  `data_room=64` (too small), one with `data_room=2048` (fits).
- Assertions:
  - `check_no_scatter(port, small_mp)` returns `!ok` with error
    containing "multiseg_rx_unsupported"
  - `check_no_scatter(port, big_mp)` returns `ok`
- Covers: D39, §6.1 port_init.

---

## U5 — Token bucket / rl_arena
(`src/rl_arena/rl_arena.*`)

### U5.1 Per-lcore isolation
- Goal: refills and consumes on lcore 0 do not touch
  `row->per_lcore[1]` state. Verified by memcmp on an
  adjacent lcore's bucket before/after.
- Covers: D1.

### U5.2 Refill — elapsed clamp at `tsc_hz` (D34) — fresh
  bucket
- Goal: `last_refill_tsc == 0`, `now = 1e10`. Raw elapsed ~
  1e10 cycles; clamp forces elapsed = `tsc_hz`; refill is
  `tsc_hz * rate / tsc_hz / n_lcores == rate / n_lcores`.
  No overflow.
- Covers: D34.

### U5.3 Refill clamp — 10 s idle
- Goal: `last_refill_tsc = X`, `now = X + 10*tsc_hz`. Same
  check: clamp applies, refill bounded, bucket capped at
  `burst_bytes`.
- Covers: D34.

### U5.4 Refill clamp — 1 µs idle (steady state)
- Goal: small elapsed → no clamp, normal arithmetic, refill
  is small but non-zero.
- Covers: D34 (negative case — clamp must not fire when
  unneeded).

### U5.5 Bucket capped at `burst_bytes`
- Goal: a heavily refilled bucket never exceeds
  `rl.burst_bytes`.
- Covers: D1, §4.4.

### U5.6 Drop on insufficient tokens
- Goal: `b.tokens < pkt_len` yields drop, `dropped++`, no
  token change.
- Covers: D1, F2 (rate-limit action).

### U5.7 Consume on sufficient tokens
- Goal: `b.tokens >= pkt_len` deducts and returns PASS.
- Covers: D1.

### U5.8 Zero-atomic invariant — thread-sanitizer build
- Goal: TSAN build of a test that fires two fake lcores at
  different `rows[slot].per_lcore[*]` must report zero data
  races. (Alternative: a static analysis assertion that no
  `std::atomic` / `_Atomic` appears in the hot path symbol.)
- Covers: D1.

### U5.9 `id_to_slot` never touched on hot path
- Goal: a test harness replaces `id_to_slot` with a poisoned
  pointer after build; hot-path consumes still work (they
  index `rows[rl.slot]` directly).
- Covers: D23 (hot path slot discipline), §4.4.

### U5.10 Mock TSC injection
- Goal: all U5.2/U5.3/U5.4 use an injected `tsc_now()` hook.
  Verifies the test harness can control clock.
- Covers: testability scaffolding for D1/D34.

---

## U6 — Classifier unit tests (needs EAL for mbuf + dynfield,
or synthesized fake mbufs if rte_mbuf struct layout permits)

All U6.* tests tagged **[needs EAL]** unless noted otherwise.
Each uses a tiny test-only mempool (e.g. 256 mbufs) and a
dynfield registered by a test fixture. Ruleset fixtures are
built in-process via U3/U4 helpers.

### U6.1 L2 — empty ruleset → NEXT_L3
- Goal: plain IPv4/Ethernet frame, empty L2 ruleset,
  `classify_l2` sets `verdict_layer = NEXT_L3`.
- Covers: §5.2 control flow, F1 default.

### U6.2a Worker — D39 multi-seg mbuf drop [needs EAL]
- Goal: synthesize a multi-segment mbuf (chain two mbufs via
  `head->next`, `nb_segs=2`), verify `is_single_segment()` returns
  false, and that the WorkerCtx `pkt_multiseg_drop_total` counter
  increments on the drop path. Single-segment mbuf must return true.
- Inputs: two mbufs from `rte_pktmbuf_pool_create`, manually chained.
- Assertions: `is_single_segment(single) == true`;
  `is_single_segment(chained) == false`; counter goes from 0 to 1
  after simulated drop.
- Covers: D39, §5.1 (worker pre-classify check).

### U6.2 L2 — src_mac match → dispatch_l2
- Goal: rule on src_mac aa:bb:cc:dd:ee:ff; packet with that
  src → compound entry hit → verdict_layer = TERMINAL_L2,
  action_idx points at the right `l2_actions[]` row.
- Covers: D15, §5.2.

### U6.3 L2 — compound filter_mask rejects partial match
- Goal: rule on `(src_mac + vlan)`; packet has matching
  src_mac but wrong VLAN → primary hit, filter_mask check
  fails, fall through to next probe (vlan table / miss).
- Covers: D15.

### U6.4 L2 — selectivity order probed correctly
- Goal: one rule on src_mac and a separate rule on vlan,
  packet matches vlan; classifier must still run src_mac
  probe first, miss, fall through to vlan LUT, hit there.
- Covers: §5.2 selectivity order.

### U6.5 L2 — first-match-wins
- Goal: two rules that could both match on vlan=100; verify
  only the **first** (by config order) dispatches.
- Covers: F1.

### U6.6 L2 — VLAN-tagged IPv4 parse sets `l3_offset = 18`
  (D13)
- Goal: a VLAN-tagged IPv4 frame; after `classify_l2`,
  `dyn->l3_offset == 18`, `dyn->parsed_vlan == 100`,
  `dyn->parsed_ethertype == 0x0800`.
- Covers: D13.

### U6.7 L2 — untagged IPv4 parse sets `l3_offset = 14`
- Covers: D13.

### U6.8 L2 — QinQ outer (0x88A8) accepted, inner 0x8100
  bumps counter (D32)
- Goal: frame with S-tag 0x88A8 wrapping C-tag 0x8100
  wrapping IPv4. `classify_l2` walks ONE tag (S-tag),
  sees inner ethertype 0x8100, bumps
  `qinq_outer_only_total`, proceeds (no terminal drop).
  `l3_offset == 18`, not 22.
- Covers: D32.

### U6.9 L2 — single 0x88A8 tag over IPv4 (no inner VLAN)
- Goal: single S-tag over IPv4; outer accepted, NO
  `qinq_outer_only_total` bump (inner etype is 0x0800).
- Covers: D32.

### U6.10 L2 truncation — packet < 14 B drops + counter
  `l2` (D31)
- Goal: synthesize a 10-byte mbuf, call `classify_l2`;
  verdict = TERMINAL_DROP; `pkt_truncated_total[l2] == 1`;
  no further classifiers run.
- Covers: D31 bucket `l2`.

### U6.11 L2 truncation — VLAN header short (D31 `l2_vlan`)
- Goal: 16-byte mbuf with 0x8100 ethertype (needs 18 B for
  the VLAN tag). Drops, bumps `pkt_truncated_total[l2_vlan]`.
- Covers: D31 bucket `l2_vlan`.

### U6.12 L3 IPv4 — short packet (< l3_off + 20) drops
  `l3_v4`
- Covers: D31 bucket `l3_v4` (truncation arm).

### U6.13 L3 IPv4 — `IHL < 5` drops `l3_v4`
- Goal: IPv4 header with version_ihl byte `0x44` (IHL=4).
  Drops, bumps `pkt_truncated_total[l3_v4]`.
- Covers: D31 bucket `l3_v4` (bad IHL arm).

### U6.14 L3 IPv6 — short packet (< l3_off + 40) drops
  `l3_v6`
- Covers: D31 bucket `l3_v6`.

### U6.15 L3 IPv6 frag-ext truncated drops
  `l3_v6_frag_ext`
- Goal: IPv6 header with `proto=44` but packet stops at
  l3_off+40+4 (missing fragment ext header).
- Covers: D31 bucket `l3_v6_frag_ext`.

### U6.16 L4 truncated TCP — drops `l4`
- Goal: TCP packet with pkt_len < l4off + 4.
- Covers: D31 bucket `l4`.

### U6.17 Truncation-guard counter dispatch table (D31)
- Goal: meta-test — for each bucket name, assert a counter
  exists, assert the hot-path can reach it via
  `ctx_stats_bump_pkt_truncated(ctx, "<name>")`.
- Covers: D31 (structural).

### U6.18 L3 IPv4 — dst FIB hit → TERMINAL_L3
- Goal: L3v4 rule matches dst prefix; classify_l3 looks up
  FIB, finds next-hop, dispatches.
- Covers: D14 (offset via IHL), §5.3.

### U6.19 L3 IPv4 — IHL=6 L4 offset uses `ihl << 2`
  (D14)
- Goal: IPv4 header with options (IHL=6, 24-byte header).
  L4 classifier reads TCP ports at `l3off + 24`, not
  `l3off + 20`.
- Covers: D14.

### U6.20 L3 IPv4 — L3 miss and SKIP_L4 clear → NEXT_L4
- Goal: no matching L3 rule, no fragment flag; verdict
  becomes NEXT_L4 so L4 classifier runs.
- Covers: §5.3, D21 (cliff fix: only sets TERMINAL_PASS
  when SKIP_L4 set).

### U6.21 L3 IPv4 — non-first fragment, FRAG_L3_ONLY, L3
  miss → TERMINAL_PASS (D21)
- Goal: non-first fragment + SKIP_L4 flag + no L3 match →
  verdict = TERMINAL_PASS (NOT NEXT_L4). apply_action
  applies `default_action`.
- Covers: D21 (the exact cliff), D17.

### U6.22 L3 IPv4 — non-first fragment, FRAG_L3_ONLY, L3
  hit → TERMINAL_L3
- Goal: non-first fragment but an L3 rule matches anyway;
  L3 rule's action is applied, L4 never runs.
- Covers: D17.

### U6.23 L3 IPv4 — fragment, FRAG_DROP → TERMINAL_DROP
- Covers: D17.

### U6.24 L3 IPv4 — fragment, FRAG_ALLOW → TERMINAL_PASS
- Covers: D17.

### U6.25 L3 IPv4 — first fragment (offset=0, MF=1) runs
  full L4 (D27 symmetry)
- Goal: first fragment of an IPv4 datagram still runs L4
  classification (mirrors IPv6 first fragment semantics).
- Covers: D17, D27 (IPv4/IPv6 symmetry under L3_ONLY).

### U6.26 L3 IPv6 — plain TCP → NEXT_L4, `l4_extra = 0`
- Goal: IPv6 packet with next_header = 6 (TCP). `l4_extra`
  stays 0; L4 classifier reads at `l3off + 40`.
- Covers: §5.3 IPv6, D14, D27.

### U6.27 L3 IPv6 — non-fragment extension header (0) →
  SKIP_L4, `l4_skipped_ipv6_extheader` bumped
- Goal: IPv6 with hop-by-hop (0) → SKIP_L4 set, counter
  bumped, L3 still runs.
- Covers: D20, §5.3.

### U6.28 L3 IPv6 — Fragment ext, first fragment → walks
  8 bytes, `l4_extra = 8`, NEXT_L4 (D27)
- Goal: IPv6 with frag-ext (44), `frag_offset == 0`, inner
  proto TCP. After classify_l3, `dyn->l4_extra == 8`,
  `verdict_layer == NEXT_L4`. L4 classifier reads TCP ports
  at `l3off + 40 + 8`.
- Covers: D27 (critical bug fix).

### U6.29 L3 IPv6 — Fragment ext, non-first → SKIP_L4
  and `l4_skipped_ipv6_fragment_nonfirst` bumped (D27)
- Goal: IPv6 frag-ext with `frag_offset != 0` → SKIP_L4
  set, counter bumped, L4 never runs.
- Covers: D27.

### U6.30 L3 IPv6 — fragment-ext with nested fragment →
  SKIP_L4
- Goal: frag ext followed by another frag ext (nxt=44);
  treated as SKIP_L4 per §5.3 "chain-after-fragment"
  paragraph.
- Covers: D27 (edge case).

### U6.31 L3 IPv6 — high-value proto 135 (mobility) detected
  as ext (no shift UB regression)
- Goal: proto=135 with dummy payload → SKIP_L4. Does NOT
  match `EXT_MASK_LT64 & (1<<135)` (which would be UB per
  D22).
- Covers: D22 (IPv6 EXT_MASK UB fix).

### U6.32 L3 IPv6 — fib hit on dst prefix → TERMINAL_L3
- Covers: §5.3 IPv6, F1 L3.

### U6.33 L4 — proto+dport primary hit
- Goal: rule `tcp dst 443`. TCP/443 packet → `l4_proto_dport`
  hit → dispatch.
- Covers: D15.

### U6.34 L4 — proto+dport with src-port wildcard (the
  common case)
- Goal: rule has no src_port constraint. Packets with any
  src port match. `filter_mask == 0`.
- Covers: D15 (wildcard support).

### U6.35 L4 — proto+dport+sport exact match
- Goal: rule constrains both ports. Only the exact pair
  dispatches; src_port mismatch falls through.
- Covers: D15.

### U6.36 L4 — proto-only catch-all (ICMP any)
- Goal: rule `{proto: icmp}`. Any ICMP packet → hit via
  `l4_proto_only`.
- Covers: D15.

### U6.37 L4 — selectivity order: dport primary before
  sport primary
- Goal: rule A on `tcp dport 443`, rule B on `tcp sport 443`;
  packet with dport=443, sport=80 must match A (probes
  `l4_proto_dport` first).
- Covers: D15 selectivity.

### U6.38 L4 — first-match-wins on multiple dport rules
- Covers: F1.

### U6.39 L4 — SKIP_L4 flag → TERMINAL_PASS without hash
  lookup
- Goal: dyn.flags has SKIP_L4; classify_l4 exits immediately
  with TERMINAL_PASS. Verified by a spy `rte_hash_lookup`
  that records 0 calls.
- Covers: §5.4 fast-path exit, D17, D27.

### U6.40 L4 — L4 miss → TERMINAL_PASS
- Covers: §5.4.

### U6.41 L4 — ICMP type/code packing (D29)
- Goal: rule matches `icmp type=8 code=0`. Crafted ICMP
  echo-request packet → classify_l4 packs
  `dport=type=8, sport=code=0`, primary `l4_proto_dport`
  keyed `(icmp<<16 | 8)` hits, filter_mask SRC_PORT check
  on code passes.
- Covers: D14, D29.

### U6.42 D9 — single `g_active` pointer swap semantics
  (in-process RCU-free)
- Goal: a test without RCU simply swaps `g_cp.g_active`
  between two Ruleset instances; two simulated "bursts"
  (calls to classify on the same mbuf) pick up different
  rulesets. Verifies acquire-load reads the swap.
- Covers: D9.

### U6.43 D9 — no per-WorkerCtx `active` field
- Goal: a static_assert in the test that `WorkerCtx` does
  NOT contain a member named `active` (reflection via
  `offsetof` / SFINAE, or structural check).
- Covers: D9 (architectural invariant).

### U6.44 D25 — apply_action default arm bumps
  `dispatch_unreachable_total`
- Goal: set `dyn->verdict_layer = NEXT_L3` (which must never
  reach apply_action); call `apply_action`; assert mbuf is
  freed, counter incremented, no crash.
- Covers: D25.

### U6.45 D25 — inner switch default arm
- Goal: forge a `RuleAction.verb = 99` (out of enum range);
  call apply_action on a packet that terminates at L2 with
  this action; default arm fires, counter bumps, mbuf freed.
- Covers: D25.

### U6.46 TERMINAL_PASS + default_action=ALLOW → stage_tx
- Goal: empty ruleset, default allow; packet flows through
  to `stage_tx(ctx, port_b)`. Verified by a stage_tx spy.
- Covers: F1 default_action, §5.5.

### U6.47 TERMINAL_PASS + default_action=DROP → free
- Covers: F1, §5.5.

### U6.48 TAG action — IPv4 DSCP rewrite
- Goal: rule dispatches TAG with `dscp=46`; packet's
  `ip->type_of_service` high 6 bits become 46;
  `PKT_TX_IP_CKSUM` flag set; packet staged for TX.
- Covers: F2 TAG, §5.5 TAG case.

### U6.49 TAG action — IPv6 traffic-class rewrite
- Goal: TC byte of IPv6 header updated; no cksum flag
  touched.
- Covers: §5.5.

### U6.50 TAG action — PCP rewrite on tagged frame
- Goal: VLAN TCI PCP bits updated.
- Covers: §5.5.

### U6.51 TAG action — PCP on untagged frame is no-op +
  counter
- Goal: untagged frame + TAG with PCP; TCI unchanged; no
  tag inserted; `tag_pcp_noop_untagged_total` bumped;
  packet still staged for TX.
- Covers: D19, §5.5 TAG case.

### U6.52 REDIRECT — staged to per-port buffer (D16)
- Goal: a REDIRECT action enqueues the mbuf into
  `ctx->redirect_tx[a->redirect_port].buf`, increments `n`;
  does NOT call `rte_eth_tx_burst` inline.
- Covers: D16.

### U6.53 REDIRECT — burst-end drain succeeds
- Goal: after apply_action, `redirect_drain(ctx)` calls a
  spy `rte_eth_tx_burst` once per non-empty staged port
  with `qid == ctx->qid` (D28 TX-queue symmetry).
- Covers: D16, D28.

### U6.54 REDIRECT — drain partial send frees unsent, bumps
  counter
- Goal: spy returns `sent < s.n`; unsent mbufs freed,
  `redirect_dropped_total += (s.n - sent)`.
- Covers: D16.

### U6.55 REDIRECT — staging full → drop at stage time
- Goal: fill `redirect_tx[p]` to MAX_BURST, then stage one
  more; it is dropped (not OOB write). Implementation may
  bump a different counter — assert no overflow.
- Covers: D16 (defensive).

### U6.56 Counter update — hit bumps matched_packets/bytes
- Goal: after dispatch_l2, `by_rule[layer_base(L2) +
  counter_slot].matched_packets++` and
  `matched_bytes += pkt_len` on the current lcore row only.
- Covers: D3, D33.

### U6.57 Counter update — drop bumps `drops`
- Covers: D3, §5.5.

### U6.58 Counter update — RL drop bumps `rl_drops` not
  `drops`
- Goal: RL over-limit path bumps `rl_drops`, not the
  explicit-drop counter.
- Covers: D1, D3.

### U6.59 Counter update — indexing is constant math (no
  hash)
- Goal: a spy rte_hash_lookup confirms it is *not* called
  during counter update — proves D33 / §4.3 dense slot
  design.
- Covers: §4.3, m6 touch-up.

### U6.60 Default action TERMINAL_PASS counter ?
- Goal: TERMINAL_PASS hitting default_action should bump
  `pktgate_default_action_total{verdict}` only, not any
  rule counter.
- Covers: D33 counter consistency.

---

## U7 — Counter aggregation (telemetry snapshot path)

Pure C++; no DPDK required.

### U7.1 Snapshot sum — single lcore
- Goal: one lcore has `by_rule[0] = {10, 1500, 0, 0}`;
  snapshot reads, sums, produces same values.
- Covers: D3.

### U7.2 Snapshot sum — N lcores
- Goal: N = 4 lcores each with distinct per-rule values;
  snapshot sum is the element-wise sum.
- Covers: D3.

### U7.3 Snapshot ring buffer N=4 (m5)
- Goal: ring of 4 generations; publish 6 snapshots; the
  oldest 2 are overwritten, readers always see latest
  fully-published generation. Single-writer invariant
  verified under TSAN.
- Covers: D3, m5.

### U7.4 Zero-init on slot reuse (§4.3 / §9.4 step 5b)
- Goal: see U4.14 but from the telemetry side: after slot
  reuse, the aggregator reads zero for the new rule's
  first snapshot, not carryover from the old rule.
- Covers: D33, §4.3 / §9.4.

### U7.5 Counter consistency invariant — every named counter
  has a producer site (D33)
- Goal: static list of counter names from §10.3 is
  enumerated; for each, a grep-style search finds at least
  one producer site in the source tree. Test fails if any
  name has no producer or any producer uses a name not in
  the list. (Implementation: a small manifest file and a
  reflection helper.)
- Covers: D33.

### U7.6 Per-port counter wrapping — rte_eth_stats mapping
- Goal: a mock `rte_eth_stats` struct is translated into
  `pktgate_port_*` metric values with correct label
  assembly.
- Covers: F6, §10.3.

### U7.7 Metric label assembly for `rule_id`
- Goal: `pktgate_rule_packets_total{layer="l3",rule_id="2001"}`
  is the exact exposition string.
- Covers: F6, §10.3.

---

## U8 — Verdict dispatch (apply_action) matrix

Most of these are "fixture-level" inputs into U6 (`apply_action`
takes a dispatched mbuf), but the matrix itself is worth
enumerating explicitly.

### U8.1 TERMINAL_L2 × ALLOW → stage_tx
### U8.2 TERMINAL_L2 × DROP → free + counter_drop
### U8.3 TERMINAL_L2 × RL (pass) → stage_tx + token deducted
### U8.4 TERMINAL_L2 × RL (drop) → free + `rl_drops` + bucket.dropped
### U8.5 TERMINAL_L2 × TAG (IPv4 DSCP) → see U6.48
### U8.6 TERMINAL_L2 × REDIRECT → staged, not inline TX
### U8.7 TERMINAL_L3 × ALLOW
### U8.8 TERMINAL_L3 × DROP
### U8.9 TERMINAL_L3 × RL
### U8.10 TERMINAL_L3 × TAG
### U8.11 TERMINAL_L3 × REDIRECT
### U8.12 TERMINAL_L4 × ALLOW
### U8.13 TERMINAL_L4 × DROP
### U8.14 TERMINAL_L4 × RL
### U8.15 TERMINAL_L4 × TAG
### U8.16 TERMINAL_L4 × REDIRECT
### U8.17 TERMINAL_PASS × default=ALLOW (U6.46)
### U8.18 TERMINAL_PASS × default=DROP (U6.47)
### U8.19 TERMINAL_DROP (from truncation guard) → free
### U8.20 NEXT_L3 / NEXT_L4 arrive at apply_action → default
   arm fires (D21, D25) — covered by U6.44
### U8.21 Unknown verb (raw 99) → default arm fires (U6.45)

**Goal for U8.1–U8.16**: every `(verdict_layer, verb)`
cross-product has at least one dedicated test case exercising
the exact branch. Each asserts the side effect (TX stage,
free, counter, bucket state) and nothing else. Most share the
fixture from U6, differing only in `RuleAction.verb` and
`verdict_layer`.

Covers: F2 actions, §5.5 outer and inner switches, D21, D25.

---

## U9 — Command socket parser (`src/ctl/cmd_socket.*`)

Pure-C++ unit: the JSON verb parser + the `SO_PEERCRED` check
is unit-tested via an injected `PeerCreds` struct — no actual
socket, no fork.

### U9.1 `{"cmd":"reload"}` parses
### U9.2 `{"cmd":"status"}` parses
### U9.3 `{"cmd":"dump-config"}` parses
### U9.4 `{"cmd":"dump-rule","layer":"l3","id":42}` parses
### U9.5 `{"cmd":"counters","layer":"l3","id":42}` parses
### U9.6 `{"cmd":"activate"}` parses
### U9.7 Unknown verb rejected (`{"cmd":"hack"}`)
### U9.8 Missing `cmd` rejected
### U9.9 Malformed JSON rejected (truncated, extra commas)
### U9.10 Multiple commands per line rejected (line protocol)
### U9.11 SO_PEERCRED — root uid accepted for reload
### U9.12 SO_PEERCRED — pktgate_uid accepted for reload
- Covers: D38.
### U9.13 SO_PEERCRED — other uid rejected, rejection counter
   bumped (`reason=peer_uid`)
- Covers: D38, §10.3.
### U9.14 SO_PEERCRED — allowed uid but disallowed gid →
   rejected, `reason=peer_gid`
- Covers: D38.
### U9.15 Read-only verb (`status`) allowed for any
   allow-listed peer, even non-mutating gid
- Covers: D38.
### U9.16 Mutating verb (`reload`) requires full auth
- Covers: D38.
### U9.17 `activate` counts as mutating
- Covers: D38.

**Harness note**: the SO_PEERCRED check itself can be unit-
tested by exposing `check_peer(PeerCreds, CmdKind)` as a pure
function taking struct values. No real socket, no real fork.

---

## U10 — Metrics / exposition formatters

### U10.1 Prometheus exposition — counter line
- Goal: `format_counter("pktgate_rule_packets_total",
  labels={{"layer","l3"},{"rule_id","2001"}}, value=42)`
  produces the exact OpenMetrics line.
- Covers: F6, §10.3.

### U10.2 Prometheus exposition — histogram (cycles_per_burst)
- Goal: known buckets → expected `_bucket`, `_sum`, `_count`
  lines.
- Covers: F6, §10.3.

### U10.3 Prometheus — label escaping (quotes, backslashes
  in `site` label)
- Covers: F6, robustness.

### U10.4 Prometheus — counter with `_total` suffix convention
- Covers: F6.

### U10.5 `rte_telemetry` JSON — rules count endpoint
- Goal: pure formatter test: given a Ruleset fixture,
  `/pktgate/rules/count` JSON emission equals expected.
- Covers: D3, §10.6.

### U10.6 `rte_telemetry` — lcores endpoint shape
- Covers: §10.6.

### U10.7 Structured log record — JSON line schema
- Goal: `format_log_record(LogLevel::Warn, "reload",
  {{"result","validate_err"}, {"sub","budget_per_rule"}})`
  emits a JSON object with exactly the expected keys;
  stable key order for grep-ability.
- Covers: F6, §10.5, D37 (structured sub-reason).

### U10.8 Structured log — reload outcome
- Goal: `reload_total{result=...}` success, parse_err,
  validate_err, compile_err, oom, timeout, pending_full —
  each produces a distinct log record kind.
- Covers: D30, D33, D36, D37, §11.

### U10.9 Log ring overflow bumps `log_dropped_total`
- Goal: enqueue more than ring capacity; oldest dropped,
  counter incremented.
- Covers: §10.5.

### U10.10 sFlow — flow_sample packing for TCP packet
- Goal: pure formatter: given a synthetic mbuf and a
  matched rule_id, the sFlow record has the documented
  fields (truncated header 128 B, ingress ifIndex, matched
  rule id in extended_user, length).
- Covers: F6, §10.4.

### U10.11 sFlow — datagram assembly (multiple samples
  into one UDP payload)
- Covers: §10.4.

---

## Coverage matrix — D1..D38 → test IDs

| D | Topic | Unit-tested here | Or covered elsewhere |
|---|---|---|---|
| **M1** | Dev VM does not shape architecture | n/a — meta principle | (review only) |
| **M2** | Arch ≠ Plan | n/a — meta principle | (review only) |
| **D1** | Per-lcore token bucket, zero atomics | U1.21, U1.22, U5.1–U5.10, U6.58, U8.3, U8.4 | — |
| **D2** | C++20/23, gcc≥14 / clang≥18 | n/a (CMake level) | build-system test |
| **D3** | Telemetry counting model | U4.6, U6.56–U6.60, U7.1–U7.7, U10.* | — |
| **D4** | rte_flow offload hooks, MVP disabled | U3.13, U3.14, U3.15 | integration for actual `rte_flow_create`; functional layer |
| **D5** | HA compat: interface_roles, --standby | U1.4–U1.7, U2.3, U2.4, U2.11 | integration for --standby park/activate end-to-end |
| **D6** | Runtime sizing, dev vs prod | U1.25–U1.27, U4.1 | — |
| **D7** | Mirror schema full, MVP reject | U2.12, U3.17 | functional: once mirror actually ships |
| **D8** | Clean schema, no pktgate compat | U1.2–U1.35, U2.1–U2.20 | — |
| **D9** | Single global `g_active`, no per-lcore slot | U6.42, U6.43 | integration: real RCU swap with EAL |
| **D10** | Rewrite §4.4/§5.5 per D1 | U5.*, U6.58 | same as D1 |
| **D11** | rl_arena GC ordering after synchronize | U4.11, U4.13 | integration: real RCU synchronize |
| **D12** | RCU polish (offline/unregister, timeout) | — | integration: hot reload with real qsbr |
| **D13** | L3 offset dynfield for VLAN | U6.6, U6.7 | — |
| **D14** | L4 offset via IHL + ICMP packing | U6.19, U6.41 | — |
| **D15** | L4 compound primary + filter_mask | U3.3, U3.9–U3.12, U3.24, U6.33–U6.38, U6.41 | — |
| **D16** | REDIRECT staging + burst-end flush | U6.52–U6.55 | — |
| **D17** | `fragment_policy` config field | U1.14–U1.16, U6.21–U6.25 | — |
| **D18** | Cycle budget min/typ/max | n/a (prose in design; enforceable only in lab) | lab perf pass |
| **D19** | Misc (TAG semantics, fib_bulk, idle handler) | U6.48–U6.51 | idle handler: integration; fib_bulk: lab perf |
| **D20** | IPv6 ext-headers first-proto only | U6.27, U6.31 | — |
| **D21** | NEXT_L4 cliff fix → TERMINAL_PASS on skip | U6.20, U6.21, U6.44, U8.20 | — |
| **D22** | RuleAction 20 B + alignas(4) | U3.5, U4.8 | — |
| **D23** | NUMA explicit in Ruleset/Workers | U4.7, U4.15, U5.9 | integration: real socket allocation |
| **D24** | rl_arena slot lifecycle | U4.9–U4.12 | — |
| **D25** | apply_action default arms + -Wswitch-enum | U3.22, U3.23, U6.44, U6.45, U8.20, U8.21 | — |
| **D26** | Mirror refcnt compile-time gate (MUTATING_VERBS) | U3.18–U3.21 | functional: once mirror ships |
| **D27** | IPv6 first-frag vs non-first, `l4_extra` dynfield | U6.26, U6.28, U6.29, U6.30, U6.25 | — |
| **D28** | Dataplane port TX-queue symmetry | U4.16, U6.53 | integration: real port init |
| **D29** | Drop `want_icmp_code` | U3.12, U6.41 | (compile-time assertion in U3.6 family) |
| **D30** | `rte_rcu_qsbr_check` correct usage | — | integration ONLY: real DPDK QSBR with timed pause |
| **D31** | Per-stage truncation guards | U6.10–U6.17 (every `where` bucket has a dedicated test: `l2` U6.10, `l2_vlan` U6.11, `l3_v4` U6.12, `l3_v4` bad IHL U6.13, `l3_v6` U6.14, `l3_v6_frag_ext` U6.15, `l4` U6.16) | — |
| **D32** | QinQ 0x88A8 outer accept + counter | U6.8, U6.9 | — |
| **D33** | Counter consistency invariant | U4.14, U6.59, U7.4, U7.5 | structural grep test (U7.5) |
| **D34** | rl_arena refill clamp at `tsc_hz` | U5.2, U5.3, U5.4 | — |
| **D35** | Single `reload_mutex` covering all reload paths | — | integration: two concurrent reload sources (inotify + cmd_socket) |
| **D36** | `pending_free` queue for timeout path | — | integration: real reload with stalled worker |
| **D37** | Validator budget pre-flight | U2.13–U2.17 | — |
| **D38** | SO_PEERCRED + inotify `IN_CLOSE_WRITE` only | U2.18, U9.11–U9.17 | integration for inotify event filtering (needs real inotify kernel events) |

### D-decisions NOT covered here (reason)

- **M1, M2** — meta-principles. Enforced by code review and
  document structure, not by unit tests.
- **D2** — compiler/toolchain choice. Enforced by CMake, not
  unit tests. A single smoke build under gcc≥14 and clang≥18
  belongs in CI, not here.
- **D12** — full RCU polish (thread offline/unregister on
  worker exit; synchronize timeout behavior). Needs real
  multi-thread + `rte_rcu_qsbr` — goes to the integration
  tier.
- **D18** — cycle budget min/typ/max. Unit tests can't
  measure cycles meaningfully on a VM. Lab perf pass
  territory.
- **D19 (partial)** — `handle_idle` spec and bulk-vs-single
  `rte_fib_lookup` tradeoff are runtime behaviors; unit tests
  only cover the static contract, not the perf.
- **D30** — correct use of `rte_rcu_qsbr_check` with token +
  deadline. Needs real QSBR primitive. Integration tier with
  a minimal EAL.
- **D35** — two concurrent reload entry points (inotify +
  cmd_socket) serializing through one mutex. Requires actual
  threads + real inotify events; integration tier.
- **D36** — `pending_free` drain-on-next-successful-check is
  observable only with a real stalled worker and real QSBR.
  Integration tier.
- **D38 (inotify half)** — kernel inotify event filtering
  needs a real filesystem event to fire; unit tests cover
  only the SO_PEERCRED half (pure function over PeerCreds).

---

## Open items

- **OPEN (U6 harness)**: confirm whether gtest binaries can
  register an mbuf dynfield without a full `rte_eal_init()`.
  If not, U6.* all move under a `test_dp` binary that runs
  EAL once at suite start. Cost: slightly slower suite, no
  change in coverage.
- **OPEN (U3.22/U3.23 negative compile test)**: the harness
  for negative compile tests (expected-to-fail builds) needs
  CMake plumbing — a `check_fail_compile()` macro or similar.
  Alternative is runtime enum iteration with a manifest.
  Decide at harness-bootstrap time.
- **OPEN (U10.8 sub-reason list)**: the structured-log
  sub-reason vocabulary for `validate_err` (D37) is named
  but not exhaustively enumerated in design.md. Test must
  pin the list somewhere — either a shared header enum or
  a schema file — so U10.8 is stable against drift.
- **OPEN (driver capability table for D26 U3.19/U3.20)**:
  the driver_caps lookup (`tx_non_mutating`) is sketched in
  D26 but not fleshed out in §4/§5. The test builds a mock
  cap table; confirm the real shape in design before
  implementing.
