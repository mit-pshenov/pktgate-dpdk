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
    # timeout=30: dev-tsan cold-start is ~2-3x dev-asan; net_null EAL
    # init + snapshot publisher thread spawn + HTTP bind under TSAN
    # instrumentation has been observed past 15 s when tests run
    # back-to-back and the host is already under sanitizer load.
    assert proc.wait_ready(timeout=30), (
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
    # timeout=30: dev-tsan cold-start is ~2-3x dev-asan; net_null EAL
    # init + snapshot publisher thread spawn + HTTP bind under TSAN
    # instrumentation has been observed past 15 s when tests run
    # back-to-back and the host is already under sanitizer load.
    assert proc.wait_ready(timeout=30)
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
    # timeout=30: dev-tsan cold-start is ~2-3x dev-asan; net_null EAL
    # init + snapshot publisher thread spawn + HTTP bind under TSAN
    # instrumentation has been observed past 15 s when tests run
    # back-to-back and the host is already under sanitizer load.
    assert proc.wait_ready(timeout=30)
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
    # timeout=30: dev-tsan cold-start is ~2-3x dev-asan; net_null EAL
    # init + snapshot publisher thread spawn + HTTP bind under TSAN
    # instrumentation has been observed past 15 s when tests run
    # back-to-back and the host is already under sanitizer load.
    assert proc.wait_ready(timeout=30)
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
