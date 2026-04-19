# tests/functional/test_f14_main_resolver.py
#
# M14 C2 — F14.1..F14.4 + F14.boot_smoke (D41 boot-path guard).
#
# Verifies that `main.cpp` resolves `worker_ctx.port_id` /
# `worker_ctx.tx_port_id` through the C1 port resolver
# (`pktgate::ctl::resolve_ports`) instead of the legacy hardcoded
# `port_ids[0]` / `port_ids[1]` positional assignment. The D41
# guard (F14.boot_smoke) asserts that the resolved `tx_port_id`
# round-trips through a live binary and tracks the declared
# `downstream_port` role even when that role's port is NOT at
# position 1 in DPDK's port registry — which is the canonical
# "orphaned resolver call" failure mode (M9 C5 / M4 C0b precedent).
#
# Boot-path observable: main.cpp emits structured log lines around
# the resolver call. Tests parse these lines from stdout:
#
#   {"event":"port_resolved","role":"upstream_port","port_id":N}
#   {"event":"port_resolved","role":"downstream_port","port_id":M}
#   {"event":"worker_ports","port_id":N,"tx_port_id":M}
#
# Every test in this module boots a fresh EAL instance with
# `--no-pci --no-huge` so it runs everywhere without requiring a
# specific NIC. No taps, no NM keyfile extension, no F2.25 NDP
# risk surface — F14 is a control-plane wiring test, traffic
# injection lands in C4 (TAP profile smoke).

import json
import os
import socket
import time

import pytest


DPDK_DRIVER_DIR = os.environ.get(
    "DPDK_DRIVER_DIR", "/home/mit/Dev/dpdk-25.11/build/drivers/"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _eal_args(file_prefix: str, extra_vdevs=None):
    """EAL argv with the two baseline net_null vdevs + optional extras."""
    base = [
        "--no-pci",
        "--no-huge",
        "-m", "64",
        "-d", DPDK_DRIVER_DIR,
        "--vdev", "net_null0",
        "--vdev", "net_null1",
        "-l", "0,1",
        "--log-level", "lib.*:error",
        "--file-prefix", file_prefix,
    ]
    if extra_vdevs:
        for v in extra_vdevs:
            base += ["--vdev", v]
    return base


def _parse_event_lines(stdout: str) -> list:
    """Return every JSON object on its own line (one per emitted log_json)."""
    out = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        out.append(obj)
    return out


def _resolved_map(stdout: str) -> dict:
    """Return {role_name: port_id} from `port_resolved` log lines."""
    out = {}
    for obj in _parse_event_lines(stdout):
        if obj.get("event") == "port_resolved":
            out[obj["role"]] = obj["port_id"]
    return out


def _worker_ports(stdout: str) -> dict:
    """Return the latest `worker_ports` event payload, or {}."""
    last = {}
    for obj in _parse_event_lines(stdout):
        if obj.get("event") == "worker_ports":
            last = obj
    return last


# ---------------------------------------------------------------------------
# Configs
# ---------------------------------------------------------------------------

def _config_base(roles: dict, l4_rules=None) -> dict:
    # `prom_port: 0` requests an OS-assigned ephemeral port so successive
    # F14 sub-tests (each its own short-lived binary) don't fight over
    # the default 9090 socket — irrelevant to F14's port-resolver
    # contract, but the log noise muddies a stdout assertion failure.
    # The sizing block below mirrors F2's explicit non-zero defaults
    # so the parser doesn't reject the doc on a missing required key.
    return {
        "version": 1,
        "interface_roles": roles,
        "default_behavior": "drop",
        "pipeline": {
            "layer_2": [],
            "layer_3": [],
            "layer_4": l4_rules or [],
        },
        "sizing": {
            "rules_per_layer_max": 64,
            "mac_entries_max": 64,
            "ipv4_prefixes_max": 64,
            "ipv6_prefixes_max": 64,
            "l4_entries_max": 64,
            "vrf_entries_max": 8,
            "rate_limit_rules_max": 8,
            "ethertype_entries_max": 64,
            "vlan_entries_max": 64,
            "pcp_entries_max": 8,
            "prom_port": 0,
        },
    }


# ---------------------------------------------------------------------------
# F14.1 — regression baseline: two vdev roles in registry order.
# ---------------------------------------------------------------------------

def test_f14_1_two_vdev_roles_baseline(pktgate_process):
    """upstream + downstream resolve to port_ids 0 and 1 respectively
    (DPDK registers vdevs in cmdline order). Mirrors the historical
    hardcoded-port behaviour, so this passes both before and after C2 —
    catches a regression that breaks the simple case. The D41 contract
    is exercised by F14.boot_smoke below."""
    config = _config_base({
        "upstream_port":   {"vdev": "net_null0"},
        "downstream_port": {"vdev": "net_null1"},
    })

    proc = pktgate_process(config, eal_args=_eal_args("pktgate_f14_1"))
    proc.start()

    ready = proc.wait_ready(timeout=10)
    assert ready, (
        f"Binary did not reach 'ready'. exit={proc.returncode} "
        f"stdout={proc.stdout_text!r} stderr={proc.stderr_text!r}"
    )
    proc.stop()

    assert proc.returncode == 0, (
        f"Expected exit 0, got {proc.returncode}. stdout={proc.stdout_text!r}"
    )

    resolved = _resolved_map(proc.stdout_text)
    assert resolved.get("upstream_port") == 0, (
        f"expected upstream_port → port 0, got resolved={resolved!r} "
        f"stdout={proc.stdout_text!r}"
    )
    assert resolved.get("downstream_port") == 1, (
        f"expected downstream_port → port 1, got resolved={resolved!r}"
    )

    wp = _worker_ports(proc.stdout_text)
    assert wp.get("port_id") == 0 and wp.get("tx_port_id") == 1, (
        f"worker_ports mismatch: {wp!r}"
    )


# ---------------------------------------------------------------------------
# F14.2 — non-positional egress (vdev role pointed at port 2, not port 1).
#
# This is THE C2 contract: tx_port_id must follow the declared role,
# not the second slot in port_ids[]. With 3 vdevs registered and
# downstream_port → net_null2 (NameSelector), tx_port_id MUST be 2.
# Pre-C2 hardcoded `port_ids[1]` would assign tx_port_id=1 here.
# ---------------------------------------------------------------------------

def test_f14_2_non_positional_egress(pktgate_process):
    """downstream_port resolves to the third vdev via NameSelector;
    tx_port_id must be 2 (resolver), not 1 (hardcoded position)."""
    config = _config_base({
        "upstream_port":   {"vdev": "net_null0"},
        "downstream_port": {"name": "net_null2"},
    })

    eal = _eal_args("pktgate_f14_2", extra_vdevs=["net_null2"])
    proc = pktgate_process(config, eal_args=eal)
    proc.start()

    ready = proc.wait_ready(timeout=10)
    assert ready, (
        f"Binary did not reach 'ready'. exit={proc.returncode} "
        f"stdout={proc.stdout_text!r} stderr={proc.stderr_text!r}"
    )
    proc.stop()

    assert proc.returncode == 0, (
        f"Expected exit 0, got {proc.returncode}. stdout={proc.stdout_text!r}"
    )

    resolved = _resolved_map(proc.stdout_text)
    assert resolved.get("upstream_port") == 0, (
        f"upstream_port must resolve to port 0 (first registered), "
        f"got resolved={resolved!r}"
    )
    assert resolved.get("downstream_port") == 2, (
        f"downstream_port → net_null2 must resolve to port 2 (third vdev), "
        f"got resolved={resolved!r}. If this is 1, main.cpp is still "
        f"using the hardcoded port_ids[1] path — D43/D41 violation."
    )

    wp = _worker_ports(proc.stdout_text)
    assert wp.get("tx_port_id") == 2, (
        f"worker_ports.tx_port_id must equal resolved downstream_port=2, "
        f"got {wp!r}. Hardcoded-position regression."
    )


# ---------------------------------------------------------------------------
# F14.3 — rule action references a role not declared in interface_roles.
#
# Validator's existing `kUnresolvedInterfaceRef` check (M1 C7) catches
# this BEFORE the resolver runs. The functional contract is that the
# binary exits non-zero with a structured diagnostic — never SIGSEGV,
# never silently boots with a dangling ref.
# ---------------------------------------------------------------------------

def test_f14_3_rule_references_unknown_role(pktgate_process):
    """layer_4 rule action redirects to an undeclared role → boot rejects."""
    config = _config_base(
        {
            "upstream_port":   {"vdev": "net_null0"},
            "downstream_port": {"vdev": "net_null1"},
        },
        l4_rules=[
            {
                "id": 14003,
                "proto": 17,
                "dst_port": 5353,
                # Action discriminator: `target-port` (parser convention).
                # `target_port` (underscored) is the payload key naming
                # the role the traffic should be redirected to.
                "action": {"type": "target-port", "target_port": "phantom_port"},
            }
        ],
    )

    proc = pktgate_process(config, eal_args=_eal_args("pktgate_f14_3"))
    proc.start()

    ready = proc.wait_ready(timeout=5)
    if ready:
        proc.stop()
    if proc.returncode is None:
        proc.wait_exit(timeout=5)

    assert proc.returncode != 0, (
        f"Expected non-zero exit on dangling role ref, got "
        f"returncode={proc.returncode} stdout={proc.stdout_text!r}"
    )
    stdout = proc.stdout_text
    assert "phantom_port" in stdout, (
        f"diagnostic must name the missing role. stdout={stdout!r}"
    )
    # Either the static validator path or the runtime resolver path is
    # acceptable as the rejection site — both are structured "config
    # references missing role" diagnostics. The contract is "no silent
    # boot with a broken role ref".
    assert ("validate_err" in stdout
            or "interface_roles" in stdout
            or "port_resolve" in stdout), (
        f"Expected a structured config-rejection diagnostic, got "
        f"stdout={stdout!r}"
    )


# ---------------------------------------------------------------------------
# F14.4 — declared vdev role whose name is not in EAL --vdev cmdline.
#
# Resolver path: name lookup returns nullopt → kPortNotRegistered.
# The diagnostic must surface (a) the role name, (b) the port name
# that failed lookup, and exit non-zero before any worker launches.
# ---------------------------------------------------------------------------

def test_f14_4_vdev_role_not_registered(pktgate_process):
    """downstream_port declares net_pcap_phantom; EAL was not told
    about that vdev. Resolver must reject; no worker launch."""
    config = _config_base({
        "upstream_port":   {"vdev": "net_null0"},
        # net_null1 IS in EAL argv, but downstream points elsewhere on purpose
        "downstream_port": {"vdev": "net_pcap_phantom,iface=nope"},
    })

    proc = pktgate_process(config, eal_args=_eal_args("pktgate_f14_4"))
    proc.start()

    ready = proc.wait_ready(timeout=5)
    if ready:
        proc.stop()
    if proc.returncode is None:
        proc.wait_exit(timeout=5)

    assert proc.returncode != 0, (
        f"Expected non-zero exit on unregistered vdev, got "
        f"returncode={proc.returncode} stdout={proc.stdout_text!r}"
    )
    stdout = proc.stdout_text
    # The error diagnostic must surface BOTH the role name and the
    # port name we failed to find — operator readability.
    assert "downstream_port" in stdout, (
        f"diagnostic must name the failing role: stdout={stdout!r}"
    )
    assert "net_pcap_phantom" in stdout, (
        f"diagnostic must name the unresolved port name: stdout={stdout!r}"
    )
    # Workers must not have been launched.
    assert '"ready":true' not in stdout and '"ready": true' not in stdout, (
        f"Binary must not reach ready when port resolution fails: "
        f"stdout={stdout!r}"
    )


# ---------------------------------------------------------------------------
# F14.boot_smoke — D41 mandatory boot-path guard.
#
# Catches the "orphaned resolver call" failure mode: if the resolver
# is called but its result is dropped (e.g. someone reverts to
# `worker_ctx.tx_port_id = port_ids[1]` after the resolver returns),
# the constructed-WorkerCtx unit tests pass while the binary silently
# regresses. The smoke runs the LIVE binary, parses the
# `worker_ports` log line, and asserts that tx_port_id matches the
# resolved downstream_port from the SAME stdout — round-trip through
# the call graph, not through a directly-constructed WorkerCtx.
#
# Precedents: M4 C0b (populate_ruleset_eal orphan), M9 C5
# (RlSlotAllocator orphan). Compile-time guards (D41 C1/C1b) cannot
# reason about which entry points are called at boot.
# ---------------------------------------------------------------------------

def test_f14_boot_smoke_resolver_wired_in_main(pktgate_process):
    """LIVE binary: tx_port_id round-trips through main.cpp from the
    resolver, not from positional port_ids[1]. Three vdevs, downstream
    declared as net_null2 (NameSelector). If main.cpp drops the
    resolver result, tx_port_id collapses to 1 and this test fails."""
    config = _config_base({
        "upstream_port":   {"vdev": "net_null0"},
        "downstream_port": {"name": "net_null2"},
    })

    eal = _eal_args("pktgate_f14_boot", extra_vdevs=["net_null2"])
    proc = pktgate_process(config, eal_args=eal)
    proc.start()

    ready = proc.wait_ready(timeout=10)
    assert ready, (
        f"Binary did not reach 'ready'. exit={proc.returncode} "
        f"stdout={proc.stdout_text!r} stderr={proc.stderr_text!r}"
    )
    proc.stop()
    assert proc.returncode == 0, (
        f"Expected exit 0, got {proc.returncode}. stdout={proc.stdout_text!r}"
    )

    # D41 round-trip invariant: the resolved downstream_port port_id
    # MUST equal worker_ports.tx_port_id, AND it must be 2 (the third
    # vdev), not 1 (positional fallback). Both halves matter:
    #   * tx_port_id == resolved → resolver wired into main.cpp
    #   * tx_port_id == 2        → resolver result is actually used,
    #                              not silently overwritten by
    #                              port_ids[1]
    resolved = _resolved_map(proc.stdout_text)
    wp = _worker_ports(proc.stdout_text)

    assert "downstream_port" in resolved, (
        f"port_resolved log line missing for downstream_port; resolver "
        f"was not invoked in main. resolved={resolved!r} "
        f"stdout={proc.stdout_text!r}"
    )
    assert resolved["downstream_port"] == 2, (
        f"downstream_port must resolve to net_null2 → port 2; "
        f"got {resolved['downstream_port']}. resolved={resolved!r}"
    )

    assert wp.get("tx_port_id") == resolved["downstream_port"], (
        f"D41 GUARD: worker_ports.tx_port_id ({wp.get('tx_port_id')!r}) "
        f"must equal the resolved downstream_port "
        f"({resolved['downstream_port']!r}). If they diverge, the "
        f"resolver was called but its result was dropped on the way to "
        f"WorkerCtx — orphaned-resolver-call regression (M9 C5 class)."
    )

    assert wp["tx_port_id"] != 1, (
        f"D41 GUARD: tx_port_id collapsed to positional port_ids[1]=1 "
        f"despite the resolver returning 2. wp={wp!r}. The hardcoded "
        f"path was reintroduced or the resolver result was discarded."
    )


# ---------------------------------------------------------------------------
# F14.5 — M14 C3 D43 per-port backpressure counters exposed on /metrics.
#
# The new counter families `pktgate_tx_dropped_total{port}` and
# `pktgate_tx_burst_short_total{port}` are emitted by pktgate's own
# tx wrappers in src/dataplane/action_dispatch.h; publisher aggregates
# per-lcore scalars indexed by port_id and BodyFn in main.cpp emits
# one line per port label inside the same per-port loop that already
# handles pktgate_port_* families.
#
# Dataplane shape check: boot the binary with `sizing.prom_port: 0` +
# the same two-vdev baseline (net_null0/net_null1) used in F14.1,
# scrape /metrics, assert BOTH counter base names appear with a
# per-port label. Values are zero in a steady-state net_null run (no
# TX drops generated by net_null) — the test is presence-only,
# matching the F8.2 D33 living-invariant arm. Value-observing TX-drop
# scenarios (TAP with a paused reader) land in M14 C4.
#
# Why this is the boot-smoke-equivalent for C3: if the GREEN commit
# extends snapshot_metric_names() but forgets to wire the BodyFn
# emits (or vice versa), F14.5 catches the last-mile D41 gap —
# integration/c7_27 passes (snapshot side), F8.2 passes (names
# present somewhere in /metrics), but a new D43-specific scrape must
# show the `{port="N"}` shape. Keeps the C3 exit contract narrow.
# ---------------------------------------------------------------------------

def test_f14_5_tx_counters_exposed_on_metrics(pktgate_process):
    """/metrics scrape surfaces D43 per-port tx counter families with
    the {port="N"} label for every active port."""
    from test_f8_metrics import wait_for_prom_endpoint, http_get

    config = _config_base({
        "upstream_port":   {"vdev": "net_null0"},
        "downstream_port": {"vdev": "net_null1"},
    })

    eal = [
        "--no-pci",
        "--no-huge",
        "-m", "512",
        "-d", DPDK_DRIVER_DIR,
        "--vdev", "net_null0",
        "--vdev", "net_null1",
        "-l", "0,1",
        "--log-level", "lib.*:error",
        "--file-prefix", "pktgate_f14_5",
    ]
    proc = pktgate_process(config, eal_args=eal)
    proc.start()
    assert proc.wait_ready(timeout=30), (
        f"binary not ready. stdout={proc.stdout_text!r} "
        f"stderr={proc.stderr_text!r}"
    )
    port = wait_for_prom_endpoint(proc)
    assert port is not None and port > 0, (
        f"prom_endpoint_ready not seen. stdout={proc.stdout_text!r}"
    )

    # Allow >= 1 publisher tick so the ring has a snapshot to serve.
    time.sleep(2.0)

    status, headers, body = http_get(port, "/metrics")
    proc.stop()
    assert status == 200, f"GET /metrics failed, status={status}"

    text = body.decode("utf-8", errors="replace")

    # Presence assertions — both base names must appear with a per-port
    # label. We check for `pktgate_tx_dropped_total{port=` rather than
    # `pktgate_tx_dropped_total{port="0"}` so the test doesn't flake on
    # DPDK port-id ordering (whichever port(s) the binary sees is fine).
    for name in ("pktgate_tx_dropped_total", "pktgate_tx_burst_short_total"):
        assert (name + "{port=") in text, (
            f"M14 C3: /metrics body missing {name}{{port=...}} line. "
            f"BodyFn in main.cpp is not emitting the new counter family, "
            f"or snapshot_metric_names()/build_snapshot forgot to surface "
            f"it. body[:4096]={text[:4096]}"
        )

    # Also verify at least two ports are represented (net_null0 +
    # net_null1), keeping the per-port label loop honest. A single
    # port in the output would mean BodyFn accidentally fell out of
    # the per-port loop.
    port0_hit = ('pktgate_tx_dropped_total{port="0"}' in text)
    port1_hit = ('pktgate_tx_dropped_total{port="1"}' in text)
    assert port0_hit and port1_hit, (
        f"M14 C3: tx_dropped must emit one line per active port. "
        f"port0={port0_hit} port1={port1_hit}. body[:4096]={text[:4096]}"
    )
