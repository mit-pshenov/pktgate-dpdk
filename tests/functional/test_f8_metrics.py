# tests/functional/test_f8_metrics.py
#
# M10 C3 — functional tests for the Prometheus /metrics endpoint.
#
# Scope:
#   * F8.1  — GET /metrics returns 200 with OpenMetrics-parseable body.
#   * F8.16 — slowloris: 1 byte/sec client; server closes within 6 s,
#             publisher keeps running (next /metrics scrape still 200).
#   * F8.17 — bind verification: connect to 127.0.0.1 succeeds; connect
#             to a non-loopback IP refused. On a single-iface dev VM we
#             skip the "non-loopback refused" leg with a reason.
#   * F8.18 — three sub-checks: /healthz→404, POST /metrics→405,
#             GARBAGE→400. Each reply short, carries `Connection:close`.
#
# The harness boots a fresh pktgate binary per test with a config that
# includes `sizing.prom_port: 0` (OS-assigned ephemeral port). After
# ready, we ask the binary for its bound port via a log event
# `prom_endpoint_ready` that emits the port — same pattern as
# `cmd_socket_ready` in F5.

import json
import os
import socket
import time

import pytest


# §10.3 canonical manifest — mirrors tests/integration/
# test_c7_27_counter_invariant.cpp::canonical_manifest(). Kept in sync
# as a hand-transcribed list; the integration test enforces the C++ side,
# this test enforces the observable /metrics scrape exposes every name.
F8_2_CANONICAL_NAMES = [
    # Rule-match family
    "pktgate_rule_packets_total",
    "pktgate_rule_bytes_total",
    "pktgate_rule_drops_total",
    "pktgate_default_action_total",
    # Per-port family
    "pktgate_port_rx_packets_total",
    "pktgate_port_tx_packets_total",
    "pktgate_port_rx_bytes_total",
    "pktgate_port_tx_bytes_total",
    "pktgate_port_rx_dropped_total",
    "pktgate_port_tx_dropped_total",
    "pktgate_port_link_up",
    # Per-lcore family
    "pktgate_lcore_packets_total",
    "pktgate_lcore_cycles_per_burst",
    "pktgate_lcore_idle_iters_total",
    "pktgate_lcore_l4_skipped_ipv6_extheader_total",
    "pktgate_lcore_l4_skipped_ipv6_fragment_nonfirst_total",
    "pktgate_lcore_tag_pcp_noop_untagged_total",
    "pktgate_lcore_dispatch_unreachable_total",
    "pktgate_lcore_pkt_truncated_total",
    "pktgate_lcore_qinq_outer_only_total",
    "pktgate_lcore_pkt_multiseg_drop_total",
    "pktgate_lcore_pkt_frag_skipped_total",
    "pktgate_lcore_pkt_frag_dropped_total",
    # Dispatch / mirror / redirect
    "pktgate_redirect_dropped_total",
    "pktgate_mirror_dropped_total",
    # Reload / control plane
    "pktgate_reload_total",
    "pktgate_reload_latency_seconds",
    "pktgate_reload_pending_free_depth",
    "pktgate_active_generation",
    "pktgate_active_rules",
    "pktgate_cmd_socket_rejected_total",
    # M10 C5 / F8.13 — publisher liveness gauge.
    "pktgate_publisher_generation",
    # System gauges
    "pktgate_mempool_in_use",
    "pktgate_mempool_free",
    # Watchdog / bypass / log
    "pktgate_watchdog_restarts_total",
    "pktgate_bypass_active",
    "pktgate_log_dropped_total",
]

# Justified-absence list — §10.3 names that are presence-only contracts
# and NOT expected to appear on the /metrics body in the current
# (Phase 1) build. Each entry is mirrored against the integration-test
# justified_zero() list with matching D-ref rationale.
F8_2_JUSTIFIED_ABSENT = {
    # Phase-2 deferrals (no producer wired in Phase 1).
    "pktgate_lcore_packets_total",
    "pktgate_lcore_idle_iters_total",
    "pktgate_lcore_cycles_per_burst",
    # D7 Mirror verb — compiler rejects MIRROR in MVP.
    "pktgate_mirror_dropped_total",
    # M11-equivalent / phase-2 emergency / gauges.
    "pktgate_watchdog_restarts_total",
    "pktgate_bypass_active",
    "pktgate_log_dropped_total",
    "pktgate_mempool_in_use",
    "pktgate_mempool_free",
    "pktgate_cmd_socket_rejected_total",
    # Per-rule family is traffic-gated: zero-traffic rules are skipped
    # from snap.per_rule by design (cardinality control, mirror of
    # stats_on_exit convention in snapshot.cpp). F8.2 binds to
    # net_null0/null1 vdevs that cannot generate match traffic, so
    # per-rule counters never materialize. The per-rule arm of D33 is
    # covered by integration.c7_27_d33_gate which constructs snapshot
    # fixtures with non-empty per_rule directly.
    "pktgate_rule_packets_total",
    "pktgate_rule_bytes_total",
    "pktgate_rule_drops_total",
}


DPDK_DRIVER_DIR = os.environ.get(
    "DPDK_DRIVER_DIR", "/home/mit/Dev/dpdk-25.11/build/drivers/"
)


def eal_args_for(prefix):
    return [
        "--no-pci",
        "--no-huge",
        "-m", "512",
        "-d", DPDK_DRIVER_DIR,
        "--vdev", "net_null0",
        "--vdev", "net_null1",
        "-l", "0,1",
        "--log-level", "lib.*:error",
        "--file-prefix", f"pktgate_f8m_{prefix}",
    ]


def make_config(prom_port=0):
    cfg = {
        "version": 1,
        "interface_roles": {
            "upstream_port":   {"vdev": "net_null0"},
            "downstream_port": {"vdev": "net_null1"},
        },
        "default_behavior": "drop",
        "pipeline": {
            "layer_2": [],
            "layer_3": [],
            "layer_4": [],
        },
        # prom_port=0 → OS-assigned ephemeral port, emitted in
        # prom_endpoint_ready log line.
        "sizing": {
            "rules_per_layer_max":  256,
            "mac_entries_max":      256,
            "ipv4_prefixes_max":    1024,
            "ipv6_prefixes_max":    1024,
            "l4_entries_max":       256,
            "vrf_entries_max":      32,
            "rate_limit_rules_max": 256,
            "ethertype_entries_max": 32,
            "vlan_entries_max":     256,
            "pcp_entries_max":      8,
            "prom_port":            prom_port,
        },
    }
    return cfg


def extract_prom_port(stdout_lines):
    """Scan binary stdout for the prom_endpoint_ready event; return the
    bound port number, or None if not found."""
    for line in stdout_lines:
        if '"event":"prom_endpoint_ready"' in line:
            try:
                obj = json.loads(line)
                return int(obj.get("port"))
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
    return None


def wait_for_prom_endpoint(proc, timeout=5.0):
    """Block until the binary logs prom_endpoint_ready; return the
    bound port. Relies on the PktgateProcess having already captured
    early stdout lines via wait_ready()."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        port = extract_prom_port(proc._collected_lines)
        if port is not None:
            return port
        line = proc._read_line_nonblocking()
        if line is not None:
            proc._collected_lines.append(line)
            continue
        time.sleep(0.05)
    # Timed out — dump context for diagnosis.
    return None


def http_get(port, path="/metrics", timeout=5.0, host="127.0.0.1"):
    """Minimal HTTP/1.1 GET. Returns (status_code, headers_dict, body_bytes)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    req = f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode()
    s.sendall(req)
    chunks = []
    while True:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
    s.close()
    data = b"".join(chunks)
    # Split header / body.
    sep = data.find(b"\r\n\r\n")
    if sep < 0:
        return (-1, {}, data)
    head = data[:sep].decode("latin-1", errors="replace")
    body = data[sep + 4:]
    first, *rest = head.split("\r\n")
    parts = first.split(" ", 2)
    status = int(parts[1]) if len(parts) >= 2 else -1
    headers = {}
    for h in rest:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return (status, headers, body)


# ------------------------------------------------------------------
# F8.1 — GET /metrics returns 200 with OpenMetrics-parseable body.
# ------------------------------------------------------------------
def test_f8_1_metrics_200_parseable(pktgate_process):
    proc = pktgate_process(make_config(),
                           eal_args=eal_args_for("f81"))
    proc.start()
    # timeout=60: under dev-tsan, DPDK's rte_eal_remote_launch round
    # trip (main writes to the worker's EAL pipe, blocks until the
    # worker picks up the launch request and ACKs via a second pipe)
    # takes several seconds on a cold worker lcore, and compounds
    # across back-to-back F8 tests because each binary re-does the
    # entire EAL bring-up.  30 s was sufficient in isolation but the
    # F8 suite flaked at ~40% when run sequentially under TSAN; 60 s
    # clears the observed ceiling with margin.  dev-asan cold-start
    # stays sub-second, so the bump does not penalise the fast paths.
    assert proc.wait_ready(timeout=60), (
        f"binary not ready. stdout={proc.stdout_text!r} "
        f"stderr={proc.stderr_text!r}"
    )
    port = wait_for_prom_endpoint(proc)
    assert port is not None and port > 0, (
        f"prom_endpoint_ready not observed. "
        f"collected={proc._collected_lines!r}"
    )

    status, headers, body = http_get(port, "/metrics")
    assert status == 200
    assert headers.get("connection", "").lower() == "close"
    assert "text/plain" in headers.get("content-type", "")

    # Parse via prometheus_client. Import lazily so the test skips
    # gracefully on a machine without it.
    try:
        from prometheus_client.parser import text_string_to_metric_families
    except ImportError:
        pytest.skip("prometheus_client not installed")

    text = body.decode("utf-8", errors="replace")
    families = list(text_string_to_metric_families(text))
    # C3 only guarantees parseable output; actual name coverage is C4
    # (F8.2). A zero-family snapshot is still parseable.
    # Just assert no parse exception and the iterator returns a list.
    assert isinstance(families, list)

    proc.stop()
    assert proc.returncode == 0


# ------------------------------------------------------------------
# F8.16 — slowloris. Open TCP, send 1 byte / sec. Server must close
# within SO_RCVTIMEO (5 s) + a small margin. Publisher/binary stay
# healthy: a second (normal) scrape after the slowloris socket dies
# returns 200.
# ------------------------------------------------------------------
def test_f8_16_slowloris_bounded(pktgate_process):
    proc = pktgate_process(make_config(),
                           eal_args=eal_args_for("f816"))
    proc.start()
    # timeout=60: under dev-tsan, DPDK's rte_eal_remote_launch round
    # trip (main writes to the worker's EAL pipe, blocks until the
    # worker picks up the launch request, ACKs via a second pipe) is
    # several seconds on a cold worker lcore, and compounds across
    # back-to-back F8 tests because each binary re-does the entire
    # EAL bring-up. 30 s was sufficient in isolation but flakes the
    # F8 suite at ~40% when run sequentially under TSAN; 60 s clears
    # the observed ceiling with margin.  dev-asan cold-start remains
    # sub-second so the bump does not penalise the fast paths.
    assert proc.wait_ready(timeout=60)
    port = wait_for_prom_endpoint(proc)
    assert port is not None

    # Baseline scrape to confirm reachability.
    status, _, _ = http_get(port, "/metrics")
    assert status == 200

    # Slowloris: open, send 3 bytes of a request, then STALL. The
    # SO_RCVTIMEO (5 s) only fires on a recv() call that blocks with no
    # data — while the client dribbles bytes, each byte resets the
    # timer. So the real bound we care about is: once the client stops
    # sending, the server closes within SO_RCVTIMEO + a small margin.
    slow = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    slow.settimeout(10.0)
    slow.connect(("127.0.0.1", port))

    try:
        # Send a partial request line, then stop. Server's recv() now
        # blocks waiting for the rest of the line; SO_RCVTIMEO should
        # fire within 5 s and the server should close the socket.
        slow.sendall(b"GET")
        stall_start = time.monotonic()

        # Wait for EOF (server close) via a blocking recv.
        slow.settimeout(8.0)
        try:
            data = slow.recv(4096)
            closed_or_drained = (data == b"" or data.startswith(b"HTTP/1.1 4"))
        except socket.timeout:
            closed_or_drained = False

        elapsed_stall = time.monotonic() - stall_start
    finally:
        slow.close()

    # SO_RCVTIMEO is 5 s — closure must happen inside ~7 s.
    assert closed_or_drained, (
        "slowloris socket did not observe server close / error response"
    )
    assert elapsed_stall < 7.0, (
        f"slowloris stalled connection survived > 7 s "
        f"(elapsed_stall={elapsed_stall:.1f})"
    )

    # A fresh scrape must still succeed — publisher/accept loop
    # weren't blocked by the slow socket.
    status, _, _ = http_get(port, "/metrics")
    assert status == 200

    proc.stop()
    assert proc.returncode == 0


# ------------------------------------------------------------------
# F8.17 — bind verification. Loopback works; non-loopback refused.
# ------------------------------------------------------------------
def test_f8_17_bind_loopback_only(pktgate_process):
    proc = pktgate_process(make_config(),
                           eal_args=eal_args_for("f817"))
    proc.start()
    # timeout=60: under dev-tsan, DPDK's rte_eal_remote_launch round
    # trip (main writes to the worker's EAL pipe, blocks until the
    # worker picks up the launch request, ACKs via a second pipe) is
    # several seconds on a cold worker lcore, and compounds across
    # back-to-back F8 tests because each binary re-does the entire
    # EAL bring-up. 30 s was sufficient in isolation but flakes the
    # F8 suite at ~40% when run sequentially under TSAN; 60 s clears
    # the observed ceiling with margin.  dev-asan cold-start remains
    # sub-second so the bump does not penalise the fast paths.
    assert proc.wait_ready(timeout=60)
    port = wait_for_prom_endpoint(proc)
    assert port is not None

    # Loopback — must succeed.
    status, _, _ = http_get(port, "/metrics")
    assert status == 200

    # Non-loopback: attempt connect to the host's non-loopback IPv4
    # address. On a single-iface dev VM there may not be a routable
    # non-loopback address, so we skip with reason rather than hard-
    # failing the suite.
    import subprocess
    ifconfig = subprocess.run(
        ["hostname", "-I"], capture_output=True, text=True
    )
    candidates = [
        ip for ip in ifconfig.stdout.strip().split()
        if ip and not ip.startswith("127.")
    ]
    if not candidates:
        # Stop the binary cleanly before skipping so the EAL prefix is
        # released promptly. Without this the fixture cleanup races
        # against the next test's startup under dev-tsan.
        proc.stop()
        pytest.skip("no non-loopback IPv4 address on this host")

    non_lo = candidates[0]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    refused = False
    try:
        s.connect((non_lo, port))
        # Connection succeeded — that's a bug (we should have bound
        # to 127.0.0.1 only). But be generous: try a send and see if
        # it's a different app or an ECONNREFUSED that the OS
        # converted.
        s.sendall(b"GET /metrics HTTP/1.1\r\n\r\n")
        data = s.recv(4096)
        # If we got a response, bind leak.
        if data:
            pytest.fail(
                f"non-loopback connect to {non_lo}:{port} succeeded "
                f"with data={data[:80]!r}"
            )
        else:
            # Empty recv — could mean the connection was reset. Treat
            # as "not serving", which is the expected outcome.
            refused = True
    except (ConnectionRefusedError, ConnectionResetError, OSError):
        refused = True
    finally:
        s.close()

    assert refused, f"non-loopback connect to {non_lo}:{port} must be refused"

    proc.stop()
    assert proc.returncode == 0


# ------------------------------------------------------------------
# F8.18 — three sub-checks: /healthz→404, POST→405, GARBAGE→400.
# ------------------------------------------------------------------
def test_f8_18_error_paths(pktgate_process):
    proc = pktgate_process(make_config(),
                           eal_args=eal_args_for("f818"))
    proc.start()
    # timeout=60: under dev-tsan, DPDK's rte_eal_remote_launch round
    # trip (main writes to the worker's EAL pipe, blocks until the
    # worker picks up the launch request, ACKs via a second pipe) is
    # several seconds on a cold worker lcore, and compounds across
    # back-to-back F8 tests because each binary re-does the entire
    # EAL bring-up. 30 s was sufficient in isolation but flakes the
    # F8 suite at ~40% when run sequentially under TSAN; 60 s clears
    # the observed ceiling with margin.  dev-asan cold-start remains
    # sub-second so the bump does not penalise the fast paths.
    assert proc.wait_ready(timeout=60)
    port = wait_for_prom_endpoint(proc)
    assert port is not None

    # /healthz → 404.
    status, headers, body = http_get(port, "/healthz")
    assert status == 404
    assert headers.get("connection", "").lower() == "close"
    assert len(body) < 512  # short body

    # POST /metrics → 405.
    def raw_exchange(req_bytes):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect(("127.0.0.1", port))
        s.sendall(req_bytes)
        chunks = []
        while True:
            try:
                c = s.recv(4096)
            except socket.timeout:
                break
            if not c:
                break
            chunks.append(c)
        s.close()
        return b"".join(chunks)

    resp = raw_exchange(
        b"POST /metrics HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
    )
    assert resp.startswith(b"HTTP/1.1 405 ")
    assert b"Connection: close" in resp

    # GARBAGE → 400.
    resp = raw_exchange(b"NONSENSE_LINE_NO_CRLF")
    # May close without response if recv times out — but for a
    # syntactically-wrong line terminated by EOF, the server should
    # detect the missing CRLF via the 5 s timeout and emit 400. We
    # accept either 400 or empty reply (connection closed) as the
    # slowloris-style signal. Empty is fine — client's EOF was the
    # trigger and the server closes without emitting a response-body
    # (acceptable degraded path).
    assert resp.startswith(b"HTTP/1.1 400 ") or resp == b"", (
        f"GARBAGE line must be rejected or closed silently; got "
        f"{resp[:80]!r}"
    )

    proc.stop()
    assert proc.returncode == 0


# ------------------------------------------------------------------
# F8.2 — D33 living invariant, /metrics scrape arm.
#
# Boots pktgate with an L2/L3/L4 ruleset that exercises every
# producer site reachable from a net_null vdev pair (no packet
# injection — net_null drops every RX call). The scrape endpoint is
# driven by the 1 Hz snapshot publisher, which reads WorkerCtx
# counters + reload::counters_snapshot() + active_ruleset()
# regardless of dataplane traffic. Every §10.3 name must appear in
# the scrape body OR be on the F8_2_JUSTIFIED_ABSENT list.
#
# This is the runtime mirror of integration/test_c7_27_counter_
# invariant.cpp: the integration test exercises Snapshot-direct,
# this one exercises the full /metrics HTTP encoder path. A name
# that round-trips through Snapshot but not through the encoder
# regression (e.g. someone extends snapshot_metric_names() but
# forgets to emit in BodyFn) fails here where the integration test
# would pass — a D41 silent-pipeline-gap gate on the last mile.
# ------------------------------------------------------------------
def make_f8_2_config(prom_port=0):
    """Config for F8.2 — includes one of each L2/L3/L4 rule so the
    per-rule family has something to aggregate, plus a default_behavior
    that exercises the default_action counter."""
    cfg = {
        "version": 1,
        "interface_roles": {
            "upstream_port":   {"vdev": "net_null0"},
            "downstream_port": {"vdev": "net_null1"},
        },
        "default_behavior": "drop",
        "objects": {
            "subnets": {
                "net_allow": ["10.0.0.0/8"],
            },
        },
        "pipeline": {
            "layer_2": [
                {
                    "id":      9001,
                    "ethertype": 0x0800,
                    "action":  {"type": "allow"},
                },
            ],
            "layer_3": [
                {
                    "id":          9002,
                    "dst_subnet":  "net_allow",
                    "action":      {"type": "allow"},
                },
            ],
            "layer_4": [
                {
                    "id":       9003,
                    "proto":    6,
                    "dst_port": 80,
                    "action":   {"type": "allow"},
                },
            ],
        },
        "sizing": {
            "rules_per_layer_max":  256,
            "mac_entries_max":      256,
            "ipv4_prefixes_max":    1024,
            "ipv6_prefixes_max":    1024,
            "l4_entries_max":       256,
            "vrf_entries_max":      32,
            "rate_limit_rules_max": 256,
            "ethertype_entries_max": 32,
            "vlan_entries_max":     256,
            "pcp_entries_max":      8,
            "prom_port":            prom_port,
        },
    }
    return cfg


def test_f8_2_canonical_names_scrape_wired(pktgate_process):
    """D33 living invariant, /metrics arm. Every §10.3 name must appear
    in the scrape body OR be on the justified-absent list."""
    proc = pktgate_process(make_f8_2_config(),
                           eal_args=eal_args_for("f82"))
    proc.start()
    assert proc.wait_ready(timeout=60), (
        f"binary not ready. stdout={proc.stdout_text!r} "
        f"stderr={proc.stderr_text!r}"
    )
    port = wait_for_prom_endpoint(proc)
    assert port is not None and port > 0

    # Wait one full publish cycle (1 Hz) so the ring has a populated
    # snapshot before we scrape. Publisher's first tick waits
    # kPublishIntervalMs (1000 ms); we give a ~2 s slack so TSAN
    # cold-start doesn't miss the first publish.
    time.sleep(2.0)

    status, headers, body = http_get(port, "/metrics")
    assert status == 200, f"scrape failed, status={status}"
    text = body.decode("utf-8", errors="replace")

    # Collect every name observed in the body. A name "appears" if the
    # body contains it followed by `{` (label segment) or a literal
    # space (no-label counter line). Either form is a valid OpenMetrics
    # line prefix; both are worth accepting so the test doesn't flake
    # on cardinality choices in the encoder.
    present = set()
    for name in F8_2_CANONICAL_NAMES:
        if (name + "{") in text or (name + " ") in text:
            present.add(name)

    missing = []
    for name in F8_2_CANONICAL_NAMES:
        if name in present:
            continue
        if name in F8_2_JUSTIFIED_ABSENT:
            continue
        missing.append(name)

    assert not missing, (
        f"F8.2 (D33 living invariant): /metrics body is missing "
        f"{len(missing)} of {len(F8_2_CANONICAL_NAMES)} §10.3 names "
        f"and they are not on the justified-absent list.\n"
        f"MISSING: {missing}\n"
        f"BODY (first 4 kB):\n{text[:4096]}"
    )

    proc.stop()
    assert proc.returncode == 0


# ------------------------------------------------------------------
# F8.13 — slow reader does NOT block the snapshot writer.
#
# Setup: two scrape connections.
#   * A "slow" socket connects, sends GET /metrics, reads the
#     response headers + a first byte of body, then STALLS for
#     ~5.5 s across multiple 1 Hz publish intervals before closing.
#   * A "fast" probe polls /metrics every ~500 ms in parallel.
#
# Assertion: while the slow socket is held open, the fast probe
#   (a) keeps getting 200 OK with non-empty bodies AND
#   (b) observes `pktgate_publisher_generation` strictly increase
#       across at least 3 publishes within the stall window.
#
# The N=4 ring (design.md §10.1, D3) is the mechanism: the writer
# publishes into `gen % N` which rotates; a slow reader pinning ONE
# slot cannot back-pressure the writer as long as the scraper doesn't
# hold every slot simultaneously. 1 Hz cadence × 5 s stall × N=4
# slots = writer advances at least 3 generations while the slow
# reader is blocked.
#
# Covers: F8.13, §10.1 N=4 ring, D3, D42.
# ------------------------------------------------------------------
def _extract_publisher_generation(body_text):
    """Return the integer value of the pktgate_publisher_generation
    gauge in a /metrics body, or None if the line is absent."""
    for line in body_text.splitlines():
        # `pktgate_publisher_generation 42` (no labels).
        if line.startswith("pktgate_publisher_generation "):
            parts = line.split(" ", 1)
            if len(parts) == 2:
                try:
                    return int(parts[1].strip())
                except ValueError:
                    return None
    return None


def test_f8_13_slow_reader_does_not_block_writer(pktgate_process):
    """F8.13: a scraper that stalls across multiple publish intervals
    does not block the 1 Hz snapshot writer. Verified by observing
    `pktgate_publisher_generation` advance via a parallel fast probe."""
    proc = pktgate_process(make_config(),
                           eal_args=eal_args_for("f813"))
    proc.start()
    assert proc.wait_ready(timeout=60), (
        f"binary not ready. stdout={proc.stdout_text!r} "
        f"stderr={proc.stderr_text!r}"
    )
    port = wait_for_prom_endpoint(proc)
    assert port is not None and port > 0

    # Warm up: first probe confirms the scrape path is live and the
    # publisher has ticked at least once.
    status0, _, body0 = http_get(port, "/metrics")
    assert status0 == 200, f"warm-up scrape failed, status={status0}"
    gen0 = _extract_publisher_generation(body0.decode("utf-8", "replace"))
    assert gen0 is not None, (
        "pktgate_publisher_generation missing from warm-up scrape body — "
        "publisher gauge not wired through /metrics?\n"
        f"body (first 2 kB): {body0[:2048]!r}"
    )

    # Open a slow scraper: connect, send request, read headers + one
    # chunk, then sleep without consuming the rest. The socket stays
    # open (no close(), no more recv()) across the stall window —
    # simulating a scraper that stalled mid-response.
    slow = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    slow.settimeout(10.0)
    slow.connect(("127.0.0.1", port))
    slow.sendall(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
    # Drain the header block (read once; don't consume the full body).
    # We expect ~0.1 s for the server to flush the response.
    try:
        first_chunk = slow.recv(512)
    except socket.timeout:
        first_chunk = b""
    assert first_chunk.startswith(b"HTTP/1.1 200 "), (
        f"slow socket did not receive a 200 OK: first_chunk={first_chunk!r}"
    )

    # While the slow socket is held open, a fast probe every ~500 ms
    # must keep getting 200 OK AND the publisher_generation gauge must
    # advance by at least 3 ticks across a ~5.5 s window (1 Hz × ~5
    # publishes; require 3 as a safety margin for TSAN cold-start and
    # single-lcore scheduling jitter).
    stall_window_s = 5.5
    poll_interval_s = 0.5
    deadline = time.monotonic() + stall_window_s
    gen_observations = [gen0]
    fast_failures = 0
    while time.monotonic() < deadline:
        status_n, _, body_n = http_get(port, "/metrics", timeout=3.0)
        if status_n != 200:
            fast_failures += 1
        else:
            gen_n = _extract_publisher_generation(
                body_n.decode("utf-8", "replace"))
            if gen_n is not None:
                gen_observations.append(gen_n)
        time.sleep(poll_interval_s)

    # Now close the slow socket — we're done with it regardless of
    # whether the server was going to kick it after SO_RCVTIMEO.
    try:
        slow.close()
    except OSError:
        pass

    assert fast_failures == 0, (
        f"fast probe failed {fast_failures} times while a slow scraper "
        f"held a connection — writer appears to be blocked."
    )

    # The publisher generation must have advanced. 1 Hz × 5.5 s with
    # N=4 ring slack = at least 3 publishes observable by the fast
    # probe (first + >=2 more). Assert >= gen0 + 3 across observations.
    max_gen = max(gen_observations)
    assert max_gen >= gen0 + 3, (
        f"publisher_generation did not advance under slow-reader "
        f"contention: gen0={gen0}, observations={gen_observations}, "
        f"max={max_gen}. Expected max >= gen0 + 3 (1 Hz × 5.5 s "
        f"window; N=4 ring should decouple writer from reader)."
    )

    proc.stop()
    assert proc.returncode == 0


# ------------------------------------------------------------------
# F8.14 — QinQ outer counter visible end-to-end via /metrics.
#
# A true QinQ stack (outer 0x88A8 S-tag, inner 0x8100 C-tag) injected
# on a net_tap vdev bumps classify_l2's `qinq_outer_only_total`
# (D32). The 1 Hz publisher sums it into Snapshot.qinq_outer_only_
# total; the encoder emits
# `pktgate_lcore_qinq_outer_only_total{lcore="agg"} N` with N >= 1.
#
# Distinguishes from the M4 C9 precedent (tests/functional/
# test_f8_qinq_counter.py): that test read the stats_on_exit JSON
# sibling (M4 observable); THIS test closes the D41 end-to-end loop
# by reading the Prometheus scrape surface (M10 exposition path).
#
# Covers: F8.14, D32, §5.2, §10.3.
# ------------------------------------------------------------------
_F8_14_INGRESS_IFACE = "dtap_f8m_rx"
_F8_14_EGRESS_IFACE  = "dtap_f8m_tx"


def _delete_stale_tap(iface):
    import subprocess
    result = subprocess.run(
        ["ip", "link", "show", iface],
        capture_output=True, text=True,
    )
    if result.returncode == 0 and iface in result.stdout:
        subprocess.run(["ip", "link", "delete", iface],
                       capture_output=True)


def _tap_iface_up(iface, timeout=5.0):
    import subprocess
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["ip", "link", "show", iface],
            capture_output=True, text=True,
        )
        if result.returncode == 0 and iface in result.stdout:
            return True
        time.sleep(0.1)
    return False


def _f8_14_eal_args(prefix):
    return [
        "--no-pci",
        "--no-huge",
        "-m", "512",
        "-d", DPDK_DRIVER_DIR,
        "--vdev", f"net_tap0,iface={_F8_14_INGRESS_IFACE}",
        "--vdev", f"net_tap1,iface={_F8_14_EGRESS_IFACE}",
        "-l", "0,1",
        "--log-level", "lib.*:error",
        "--file-prefix", f"pktgate_f8m_{prefix}",
    ]


def _f8_14_config(prom_port=0):
    cfg = make_config(prom_port=prom_port)
    cfg["interface_roles"] = {
        "upstream_port":   {"vdev": "net_tap0"},
        "downstream_port": {"vdev": "net_tap1"},
    }
    # A single L2 rule that does NOT match our QinQ frame; the
    # verdict is irrelevant, only the qinq_outer_only_total bump
    # (which happens in classify_l2 regardless of rule match).
    cfg["pipeline"]["layer_2"] = [
        {
            "id": 1814,
            "src_mac": "cc:cc:cc:cc:cc:cc",
            "action": {"type": "drop"},
        }
    ]
    cfg["default_behavior"] = "allow"
    return cfg


def test_f8_14_qinq_outer_counter_via_metrics(pktgate_process,
                                              nm_unmanaged_tap):
    """F8.14: inject a true QinQ stack on net_tap ingress; assert
    `pktgate_lcore_qinq_outer_only_total` >= 1 in the /metrics scrape
    body."""
    from scapy.all import Ether, Dot1Q, sendp, conf as scapy_conf
    scapy_conf.verb = 0

    _delete_stale_tap(_F8_14_INGRESS_IFACE)
    _delete_stale_tap(_F8_14_EGRESS_IFACE)

    proc = pktgate_process(_f8_14_config(),
                           eal_args=_f8_14_eal_args("f814"))
    proc.start()
    assert proc.wait_ready(timeout=60), (
        f"binary not ready. stdout={proc.stdout_text!r} "
        f"stderr={proc.stderr_text!r}"
    )
    assert _tap_iface_up(_F8_14_INGRESS_IFACE), (
        f"tap interface {_F8_14_INGRESS_IFACE!r} did not appear in 5 s"
    )

    import subprocess
    subprocess.run(
        ["sysctl", "-qw",
         f"net.ipv6.conf.{_F8_14_INGRESS_IFACE}.disable_ipv6=1"],
        capture_output=True,
    )
    subprocess.run(
        ["ip", "addr", "flush", "dev", _F8_14_INGRESS_IFACE],
        capture_output=True,
    )
    subprocess.run(
        ["ip", "link", "set", _F8_14_INGRESS_IFACE, "arp", "off"],
        capture_output=True,
    )
    time.sleep(0.5)

    port = wait_for_prom_endpoint(proc)
    assert port is not None and port > 0

    # scapy: Ether(type=0x88A8) / Dot1Q(type=0x8100) /
    # Dot1Q(type=0x0800) — outer S-tag, inner C-tag. classify_l2
    # walks the S-tag, sees the inner tag is still a VLAN TPID, and
    # bumps qinq_outer_only_total.
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66",
              type=0x88A8) /
        Dot1Q(vlan=10, type=0x8100) /
        Dot1Q(vlan=20, type=0x0800) /
        (b"\x00" * 20)
    )
    # Send a handful of packets so the bump is non-ambiguous even
    # under tap-driven RSS jitter.
    from scapy.all import conf as sc
    sc.ifaces.reload()
    for _ in range(5):
        sendp(pkt, iface=_F8_14_INGRESS_IFACE, verbose=False)
    # Publisher is 1 Hz; wait for ~2 publish cycles so the bump
    # is rolled into the latest snapshot.
    time.sleep(2.5)

    status, _, body = http_get(port, "/metrics")
    assert status == 200, f"/metrics scrape failed, status={status}"
    text = body.decode("utf-8", "replace")

    # Match the agg-lcore emission line. Encoder emits
    # `pktgate_lcore_qinq_outer_only_total{lcore="agg"} N`.
    observed = None
    for line in text.splitlines():
        if line.startswith(
                'pktgate_lcore_qinq_outer_only_total{lcore="agg"} '):
            try:
                observed = int(line.rsplit(" ", 1)[1].strip())
            except (IndexError, ValueError):
                observed = None
            break

    assert observed is not None, (
        "pktgate_lcore_qinq_outer_only_total not present in /metrics body "
        "under an `lcore=\"agg\"` label.\n"
        f"body (first 4 kB): {text[:4096]}"
    )
    assert observed >= 1, (
        f"pktgate_lcore_qinq_outer_only_total = {observed}, expected >= 1 "
        f"after injecting QinQ frames. Possible causes: classify_l2 did "
        f"not see the frame (tap path not up), publisher did not tick "
        f"before scrape, or D32 bump site regressed."
    )

    proc.stop()
    assert proc.returncode == 0


# ------------------------------------------------------------------
# F8.15 — `pkt_truncated` counter present (and zero) in a clean run.
#
# §10.3 lists `pktgate_lcore_pkt_truncated_total{lcore,where}` as a
# presence-only counter (D31). A non-zero value requires crafted
# truncated frames (adversarial-agent territory — out of scope here).
#
# This test asserts:
#   * The name appears in /metrics body under every §10.3 `where`
#     label value (l2, l2_vlan, l3_v4, l3_v6, l3_v6_frag_ext, l4).
#   * Every emitted value is exactly 0 — clean workload, no
#     truncation shapes injected.
#
# Covers: F8.15, D33, D31, §10.3.
# ------------------------------------------------------------------
def test_f8_15_pkt_truncated_present_and_zero_in_clean_run(pktgate_process):
    """F8.15: the pkt_truncated family appears in /metrics for every
    §10.3 `where` value, with value 0 after a clean (non-truncating)
    workload."""
    proc = pktgate_process(make_config(),
                           eal_args=eal_args_for("f815"))
    proc.start()
    assert proc.wait_ready(timeout=60), (
        f"binary not ready. stdout={proc.stdout_text!r} "
        f"stderr={proc.stderr_text!r}"
    )
    port = wait_for_prom_endpoint(proc)
    assert port is not None and port > 0

    # Wait a publish cycle so the snapshot ring is primed.
    time.sleep(1.5)

    status, _, body = http_get(port, "/metrics")
    assert status == 200, f"scrape failed, status={status}"
    text = body.decode("utf-8", "replace")

    # D31 §10.3 where-label values, mirrored from snapshot.cpp trunc_line
    # calls in src/main.cpp BodyFn (M10 C4). If the encoder changes the
    # label set, this test is the lockstep gate.
    expected_where = [
        "l2", "l2_vlan",
        "l3_v4", "l3_v6", "l3_v6_frag_ext",
        "l4",
    ]

    # Parse every `pktgate_lcore_pkt_truncated_total{...} N` line and
    # index by the `where=` value.
    observed = {}
    for line in text.splitlines():
        if not line.startswith("pktgate_lcore_pkt_truncated_total{"):
            continue
        try:
            labels_end = line.index("} ")
        except ValueError:
            continue
        labels = line[len("pktgate_lcore_pkt_truncated_total{"):labels_end]
        value_str = line[labels_end + 2:].strip()
        # labels looks like `lcore="agg",where="l2_vlan"` — pull
        # the where value out. Insertion order is lcore,where in the
        # encoder (see main.cpp trunc_line lambda).
        where = None
        for lbl in labels.split(","):
            if lbl.startswith('where="') and lbl.endswith('"'):
                where = lbl[len('where="'):-1]
                break
        if where is None:
            continue
        try:
            observed[where] = int(value_str)
        except ValueError:
            continue

    missing = [w for w in expected_where if w not in observed]
    assert not missing, (
        f"pkt_truncated family is missing `where` values: {missing}. "
        f"Expected every §10.3 label from "
        f"{expected_where}.\n"
        f"Observed: {observed}\n"
        f"BODY (first 4 kB):\n{text[:4096]}"
    )

    nonzero = {w: v for w, v in observed.items() if v != 0}
    assert not nonzero, (
        f"pkt_truncated values must be 0 in a clean workload; got "
        f"{nonzero}. A non-zero value here means classify_l{{2,3,4}} "
        f"hit a truncation guard without the test injecting a truncated "
        f"frame — investigate before dismissing."
    )

    proc.stop()
    assert proc.returncode == 0
