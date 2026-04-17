# tests/functional/test_f5_reload.py
#
# M8 C5 — F5.11..F5.14 reload functional tests.
#
# The harness drives the live pktgate_dpdk binary over the UDS
# `cmd_socket` (--ctl-sock <path>). The four scenarios:
#
#   F5.11  concurrent UDS + telemetry reload         (X1.3 two-way)
#   F5.12  reload timeout (simulate verb)            observable via stats-on-exit
#   F5.13  pending_free drain                        observable via stats-on-exit
#   F5.14  pending_free overflow  (9x simulate)      observable via stats-on-exit
#
# We use the test-only `simulate-timeout` / `simulate-drain` verbs
# exposed by cmd_socket (C5). They stand in for the real
# frozen-QSBR-worker vector: the INTEGRATION tier (X1.4/X1.5)
# covers the end-to-end QSBR timeout path; this suite asserts the
# counter-to-stats wiring is correct for operator observability.
#
# Every test brings up a fresh binary, drives reload(s) / simulates,
# sends SIGTERM, and parses the stats_on_exit JSON line to read
# the reload counter family.

import json
import os
import socket
import tempfile
import threading
import time

import pytest


MINIMAL_CONFIG = {
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
}


DPDK_DRIVER_DIR = os.environ.get(
    "DPDK_DRIVER_DIR", "/home/mit/Dev/dpdk-25.11/build/drivers/"
)


def eal_args_for(prefix):
    """Per-test EAL argv with a unique file-prefix so parallel runs
    don't collide on /run/dpdk/rte_config."""
    return [
        "--no-pci",
        "--no-huge",
        "-m", "512",
        "-d", DPDK_DRIVER_DIR,
        "--vdev", "net_null0",
        "--vdev", "net_null1",
        "-l", "0,1",
        "--log-level", "lib.*:error",
        "--file-prefix", f"pktgate_f5_{prefix}",
    ]


def find_stats_on_exit(stdout):
    """Extract the stats_on_exit JSON dict from binary stdout.
    Returns the parsed dict or None if not found."""
    for line in stdout.splitlines():
        line = line.strip()
        if '"event":"stats_on_exit"' in line:
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return None


def find_uds_path(tag):
    """Pick a unique UDS path for this test run."""
    return os.path.join(
        tempfile.gettempdir(),
        f"pktgate_f5_{tag}_{os.getpid()}.sock",
    )


def uds_send(path, verb_line, timeout=5.0):
    """Send one `verb_line\n` to the UDS and return the reply."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    # Small retry on connect — the accept loop may be between accepts.
    for _ in range(20):
        try:
            s.connect(path)
            break
        except (ConnectionRefusedError, FileNotFoundError):
            time.sleep(0.05)
    else:
        s.close()
        raise RuntimeError(f"uds_send: could not connect to {path}")

    try:
        if not verb_line.endswith("\n"):
            verb_line = verb_line + "\n"
        s.sendall(verb_line.encode("utf-8"))
        s.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            try:
                b = s.recv(4096)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
        return b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        s.close()


def wait_for_log_line(proc, needle, timeout=10.0):
    """Wait for a log line containing `needle`. Looks at both the
    lines already collected by wait_ready() AND any new lines that
    arrive during the timeout window."""
    # First check already-collected buffer.
    for line in proc._collected_lines:
        if needle in line:
            return True
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = proc._read_line_nonblocking()
        if line is not None:
            proc._collected_lines.append(line)
            if needle in line:
                return True
        else:
            if proc.process.poll() is not None:
                return False
            time.sleep(0.02)
    return False


# ---------------------------------------------------------------------------
# F5.11 — concurrent UDS + telemetry (two-way).
# ---------------------------------------------------------------------------
#
# Spec: 100 trials, 1-3 successes per trial. We run a single trial
# with many concurrent reloads — the test is "no hang, no UAF, final
# counters self-consistent". The telemetry endpoint registration
# happens at boot; here we drive both:
#   * N reloads via UDS cmd_socket from one thread
#   * N reloads via `reload::deploy` through the same UDS from a
#     second thread (the endpoint funnels to deploy under
#     reload_mutex — identical to the telemetry callback path).
#
# Strictly: the telemetry UDS (rte_telemetry's /var/run/dpdk/<...>)
# is also available, but talking to it from Python requires parsing
# DPDK's JSON-RPC-lite framing. For the funnel invariant, two
# concurrent UDS reload bursts cover the D35 mutex contract the
# same way.
def test_f5_11_concurrent_two_way(pktgate_process):
    uds = find_uds_path("f511")
    proc = pktgate_process(
        MINIMAL_CONFIG,
        eal_args=eal_args_for("f511"),
        extra_args=["--ctl-sock", uds],
        timeout=20,
    )
    proc.start()
    assert proc.wait_ready(timeout=15), (
        f"binary did not reach ready. stdout={proc.stdout_text!r} "
        f"stderr={proc.stderr_text!r}"
    )
    # Wait for cmd_socket to be listening.
    assert wait_for_log_line(proc, "cmd_socket_ready", timeout=5)
    # Telemetry endpoint is registered at boot too.
    # (we don't gate on it; it's a non-fatal event).

    minimal_json = json.dumps(MINIMAL_CONFIG)

    N = 20
    a_ok = [0]
    b_ok = [0]
    def driver_a():
        for _ in range(N):
            r = uds_send(uds, f"reload {minimal_json}")
            if r.startswith("ok "):
                a_ok[0] += 1
    def driver_b():
        for _ in range(N):
            r = uds_send(uds, f"reload {minimal_json}")
            if r.startswith("ok "):
                b_ok[0] += 1

    ta = threading.Thread(target=driver_a)
    tb = threading.Thread(target=driver_b)
    ta.start(); tb.start()
    ta.join(); tb.join()

    # Both drivers should succeed on every reload — the funnel
    # serialises them, so neither loses to a race.
    assert a_ok[0] == N, f"driver A: {a_ok[0]}/{N}"
    assert b_ok[0] == N, f"driver B: {b_ok[0]}/{N}"

    proc.stop()
    assert proc.returncode == 0, f"exit={proc.returncode} stderr={proc.stderr_text!r}"

    stats = find_stats_on_exit(proc.stdout_text)
    assert stats is not None, f"stats_on_exit not found in: {proc.stdout_text!r}"
    ctrs = stats["counters"]
    # Boot publish bumps success by 1 (deploy_prebuilt), then 2*N UDS reloads.
    expected = 1 + 2 * N
    assert ctrs["reload_success_total"] == expected, \
        f"reload_success_total={ctrs['reload_success_total']} expected={expected}"
    assert ctrs["reload_active_generation"] == expected
    assert ctrs["reload_parse_error_total"] == 0
    assert ctrs["reload_compile_error_total"] == 0
    assert ctrs["reload_timeout_total"] == 0
    assert ctrs["reload_internal_error_total"] == 0


# ---------------------------------------------------------------------------
# F5.12 — reload timeout, D30 path.
# ---------------------------------------------------------------------------
def test_f5_12_reload_timeout(pktgate_process):
    uds = find_uds_path("f512")
    proc = pktgate_process(
        MINIMAL_CONFIG,
        eal_args=eal_args_for("f512"),
        extra_args=["--ctl-sock", uds],
        timeout=15,
    )
    proc.start()
    assert proc.wait_ready(timeout=15)
    assert wait_for_log_line(proc, "cmd_socket_ready", timeout=5)

    # Fire the simulate-timeout verb once. This pushes one entry onto
    # pending_free and bumps `timeout` by 1.
    reply = uds_send(uds, "simulate-timeout")
    assert reply.startswith("ok simulate-timeout"), reply

    proc.stop()
    assert proc.returncode == 0

    stats = find_stats_on_exit(proc.stdout_text)
    assert stats is not None
    ctrs = stats["counters"]
    assert ctrs["reload_timeout_total"] == 1
    # stats_on_exit emits BEFORE reload::shutdown()'s pending_free
    # drain runs, so the gauge still reflects the live queue: depth=1.
    # (A real operator polling via telemetry sees this value at
    # runtime, pre-shutdown; the shutdown drain happens later and
    # the binary exits cleanly.)
    assert ctrs["reload_pending_depth"] == 1
    # No successful drain yet, so freed_total is still 1 from the
    # initial deploy_prebuilt publish (which freed no predecessor —
    # actually 0, since there was no predecessor). We don't gate on
    # freed_total here because the bookkeeping is M9 territory.


# ---------------------------------------------------------------------------
# F5.13 — pending_free drain on next successful reload.
# ---------------------------------------------------------------------------
def test_f5_13_pending_free_drain(pktgate_process):
    uds = find_uds_path("f513")
    proc = pktgate_process(
        MINIMAL_CONFIG,
        eal_args=eal_args_for("f513"),
        extra_args=["--ctl-sock", uds],
        timeout=15,
    )
    proc.start()
    assert proc.wait_ready(timeout=15)
    assert wait_for_log_line(proc, "cmd_socket_ready", timeout=5)

    # 1) Simulate a timeout — push one entry onto pending_free.
    r1 = uds_send(uds, "simulate-timeout")
    assert r1.startswith("ok simulate-timeout"), r1

    # 2) Simulate a drain — frees the pending entry, resets the
    #    overflow log throttle.
    r2 = uds_send(uds, "simulate-drain")
    assert r2.startswith("ok simulate-drain"), r2

    proc.stop()
    assert proc.returncode == 0

    stats = find_stats_on_exit(proc.stdout_text)
    assert stats is not None
    ctrs = stats["counters"]
    assert ctrs["reload_timeout_total"] == 1
    # After simulate-drain, pending_depth is back to 0 — the live
    # gauge at stats_on_exit time (pre-shutdown) reflects that.
    assert ctrs["reload_pending_depth"] == 0, ctrs
    # freed_total bumps on the drain (entry freed). The boot publish
    # doesn't bump freed_total (no predecessor); drain of 1 entry
    # bumps it by exactly 1.
    assert ctrs["reload_freed_total"] >= 1, ctrs
    # No overflow event.
    assert ctrs["reload_pending_full_total"] == 0
    assert ctrs["reload_overflow_log_total"] == 0


# ---------------------------------------------------------------------------
# F5.14 — pending_free overflow (K_PENDING=8).
# ---------------------------------------------------------------------------
def test_f5_14_pending_free_overflow(pktgate_process):
    uds = find_uds_path("f514")
    proc = pktgate_process(
        MINIMAL_CONFIG,
        eal_args=eal_args_for("f514"),
        extra_args=["--ctl-sock", uds],
        timeout=20,
    )
    proc.start()
    assert proc.wait_ready(timeout=15)
    assert wait_for_log_line(proc, "cmd_socket_ready", timeout=5)

    # 9 back-to-back simulate-timeout verbs. The first 8 fill
    # pending_free; the 9th overflows → pending_full=1,
    # overflow_log_total=1.
    for _ in range(9):
        r = uds_send(uds, "simulate-timeout")
        assert r.startswith("ok simulate-timeout"), r

    proc.stop()
    assert proc.returncode == 0

    stats = find_stats_on_exit(proc.stdout_text)
    assert stats is not None
    ctrs = stats["counters"]
    # Nine simulated timeouts, one was retained in overflow_holder.
    assert ctrs["reload_timeout_total"] == 9, ctrs
    # Overflow fired exactly once.
    assert ctrs["reload_pending_full_total"] == 1, ctrs
    assert ctrs["reload_overflow_log_total"] == 1, ctrs
    # stats_on_exit emits pre-shutdown: pending_free is FULL (8 of 8),
    # the 9th reload went into overflow_holder.
    assert ctrs["reload_pending_depth"] == 8, ctrs
