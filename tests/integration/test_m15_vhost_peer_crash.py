# tests/integration/test_m15_vhost_peer_crash.py
#
# M15 C4 — F15.4 peer-crash chaos.
#
# Extends the C3 vhost-pair harness (test_m15_vhost_pair.py) with a
# hard-kill of the virtio-user peer in the middle of a sustained burst.
# Asserts that:
#
#   (a) pktgate survives — process still alive after testpmd SIGKILL,
#       the M15 C2 scoped `rte_eal_cleanup()` bypass is NOT exercised
#       because we never shut pktgate down during the chaos phase.
#   (b) pktgate's per-port `tx_dropped_total{port="<vhost_id>"}` counter
#       strictly climbs over the post-SIGKILL burst — the M14 C3
#       backend-agnostic counter family already covers vhost port
#       backpressure (DPDK `net_vhost` `rte_eth_tx_burst` returns
#       `sent < nb_pkts` once the UDS peer disconnects).
#
# Zero new counter families, zero `src/` edits expected. If the counter
# does NOT climb, that's a hot-path regression in M14 C3's tx_one /
# redirect_drain bump sites — stop and report, do not paper over.
#
# Design anchors:
#   D43 — exit port abstraction, vhost as prod DPI hand-off canonical
#          profile.
#   D44 — vhost socket lifecycle (server mode, cleanup on graceful exit).
#   M14 C3 — tx_dropped_total{port} / tx_burst_short_total{port} as the
#            per-port backpressure family, PMD-agnostic.
#
# DPDK multi-process hygiene — distinct `--file-prefix` per process
# (memory grabli_run_dpdk_tmpfs_leak.md + standard DPDK rules). This
# test uses prefix tail `crash` rather than C3's `pair` so back-to-back
# runs of both tests in the same ctest pass don't collide on
# `/run/dpdk/<prefix>/`.
#
# F2.25 NDP guard (memory grabli_f2_25_icmpv6_ndp_flake.md) — the same
# sysctl disable_ipv6 + arp off + addr flush recipe the C3 harness
# applies to dtap_m15_ing is mirrored here for dtap_m15c_ing; these
# are separate kernel tap names so the C3 + C4 tests can cohabitate in
# a single pytest session without racing on each other's bring-up.

import json
import os
import re
import select
import shutil
import signal
import socket
import subprocess
import tempfile
import time

import pytest
from scapy.all import (
    Ether, IP, UDP, Raw, conf as scapy_conf, sendp,
)

scapy_conf.verb = 0

# Re-uses the session-scoped NM keyfile fixture. conftest.py extension
# (below) adds dtap_m15c_ing to _TAP_IFACES_TO_UNMANAGE.
pytestmark = pytest.mark.usefixtures("nm_unmanaged_tap")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_INGRESS_IFACE = "dtap_m15c_ing"

_TESTPMD_BIN = os.environ.get(
    "PKTGATE_TESTPMD_BIN", "/usr/local/bin/dpdk-testpmd",
)

_TEST_SRC = "aa:bb:cc:dd:ee:c4"
_TEST_DST = "11:22:33:44:55:c4"

_WARMUP_COUNT = 100
_POST_CRASH_BURST = 500

# RED sentinel — impossible to satisfy: `_POST_CRASH_BURST=500` can at
# most bump `tx_dropped_total` by a few hundred (per-packet loop in
# redirect_drain; peer-gone short-bursts + rejects accumulate). A
# threshold of 10 000 000 will never be reached. GREEN flips to
# `_DROP_THRESHOLD_REAL = 1` — we only want to witness *crossing zero*,
# not a specific count (NDP warmup, UDS socket-gone timing, and PMD
# internal buffering all affect the exact delta).
_DROP_THRESHOLD_RED = 10_000_000
_DROP_THRESHOLD_REAL = 1


# ---------------------------------------------------------------------------
# Helpers — shaped after test_m15_vhost_pair.py + test_f14_tap_exit.py.
# ---------------------------------------------------------------------------

def _find_pktgate_binary():
    env_path = os.environ.get("PKTGATE_BINARY")
    if env_path and os.path.isfile(env_path):
        return env_path
    base = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    for preset in ["dev-asan", "dev-debug", "dev-release", "dev-ubsan", "dev-tsan"]:
        p = os.path.join(base, "build", preset, "pktgate_dpdk")
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    pytest.skip("pktgate_dpdk binary not found")


def _require_testpmd():
    if not os.path.isfile(_TESTPMD_BIN) or not os.access(_TESTPMD_BIN, os.X_OK):
        pytest.skip(
            f"{_TESTPMD_BIN} not found or not executable — "
            "M15 C4 chaos requires the system DPDK install "
            "(memory vm_dpdk_layout.md). Set PKTGATE_TESTPMD_BIN "
            "to override."
        )


def _delete_stale_tap(iface: str):
    result = subprocess.run(
        ["ip", "link", "show", iface],
        capture_output=True, text=True,
    )
    if result.returncode == 0 and iface in result.stdout:
        subprocess.run(
            ["ip", "link", "delete", iface],
            capture_output=True,
        )


def _tap_iface_up(iface: str, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = subprocess.run(
            ["ip", "link", "show", iface],
            capture_output=True, text=True,
        )
        if r.returncode == 0 and iface in r.stdout:
            return True
        time.sleep(0.1)
    return False


def _pktgate_config(sock_path: str, l4_rules=None):
    """pktgate config: net_tap ingress, net_vhost downstream, prom on."""
    return {
        "version": 1,
        "interface_roles": {
            "upstream_port":   {"vdev": "net_tap0"},
            "downstream_port": {
                "vdev": f"net_vhost0,iface={sock_path},queues=1"
            },
        },
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
            # /metrics endpoint on an ephemeral port; chaos scrape hits it.
            "prom_port": 0,
        },
    }


def _pktgate_eal_args(sock_path: str, file_prefix: str):
    return [
        "--no-pci",
        "--no-huge",
        "-m", "512",
        "--vdev", f"net_tap0,iface={_INGRESS_IFACE}",
        "--vdev", f"net_vhost0,iface={sock_path},queues=1",
        "-l", "0,1",
        "--log-level", "lib.*:error",
        "--file-prefix", file_prefix,
    ]


def _testpmd_cmd(sock_path: str, file_prefix: str):
    # virtio-user client on pktgate's UDS. rxonly consumer, auto-start
    # forwarding, interactive CLI stdin so `__exit__` teardown can ask
    # it to quit cleanly if it's still alive.
    return [
        _TESTPMD_BIN,
        "-l", "2,3",
        "--no-pci",
        "--no-huge",
        "-m", "256",
        "--file-prefix", file_prefix,
        "--vdev", f"net_virtio_user0,path={sock_path},queues=1",
        "--log-level", "lib.*:error",
        "--",
        "-i",
        "--forward-mode=rxonly",
        "--auto-start",
        "--total-num-mbufs=2048",
        "--no-mlockall",
    ]


def _wait_ready_pktgate(proc, stdout_buf, collected, timeout=30.0):
    """Wait for {"ready":true} on pktgate stdout. Returns (ready, buf, lines)."""
    deadline = time.monotonic() + timeout
    ready = False
    buf = stdout_buf
    lines = list(collected)
    while time.monotonic() < deadline:
        r, _, _ = select.select([proc.stdout.fileno()], [], [], 0.1)
        if r:
            try:
                chunk = os.read(proc.stdout.fileno(), 4096)
            except OSError:
                chunk = b""
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                text = line.decode(errors="replace")
                lines.append(text)
                if '"ready":true' in text or '"ready": true' in text:
                    ready = True
                    break
            if ready:
                break
        if proc.poll() is not None:
            break
    return ready, buf, lines


def _wait_testpmd_port_up(proc, stdout_buf, collected, timeout=10.0):
    """Wait for testpmd to log port-up / auto-start forwarding.

    Best-effort — the per-packet post-crash scrape is the authoritative
    witness; here we just give testpmd a chance to finish the virtio-user
    handshake before we start the chaos sequence.
    """
    deadline = time.monotonic() + timeout
    buf = stdout_buf
    lines = list(collected)
    seen = False
    while time.monotonic() < deadline:
        r, _, _ = select.select([proc.stdout.fileno()], [], [], 0.1)
        if r:
            try:
                chunk = os.read(proc.stdout.fileno(), 4096)
            except OSError:
                chunk = b""
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                text = line.decode(errors="replace")
                lines.append(text)
                if ("link state change" in text
                        or "Start automatic packet forwarding" in text
                        or "testpmd>" in text):
                    seen = True
                    break
            if seen:
                break
        if proc.poll() is not None:
            break
    return seen, buf, lines


def _drain_nonblocking(proc, buf, collected, timeout=0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r, _, _ = select.select([proc.stdout.fileno()], [], [], 0.1)
        if not r:
            break
        try:
            chunk = os.read(proc.stdout.fileno(), 4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            collected.append(line.decode(errors="replace"))
    return buf


def _drain_all(proc, buf, collected, timeout=5.0):
    try:
        remaining, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            remaining, _ = proc.communicate(timeout=5)
        except Exception:
            remaining = b""
    if isinstance(remaining, bytes):
        tail = (buf + (remaining or b"")).decode(errors="replace")
    else:
        tail = (buf.decode(errors="replace")
                + (remaining if isinstance(remaining, str) else ""))
    pre = "\n".join(collected)
    if pre and tail:
        return pre + "\n" + tail
    if pre:
        return pre
    return tail


def _extract_prom_port(stdout_lines):
    for line in stdout_lines:
        if '"event":"prom_endpoint_ready"' in line:
            try:
                obj = json.loads(line)
                return int(obj.get("port"))
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
    return None


def _resolved_downstream_port(stdout_lines):
    """Parse `port_resolved` events for downstream_port → port_id."""
    for line in stdout_lines:
        if '"event":"port_resolved"' not in line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("role") == "downstream_port":
            return int(obj.get("port_id"))
    return None


def _http_get(port, path="/metrics", timeout=5.0, host="127.0.0.1"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
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
    sep = data.find(b"\r\n\r\n")
    if sep < 0:
        return (-1, b"")
    head = data[:sep].decode("latin-1", errors="replace")
    body = data[sep + 4:]
    parts = head.split("\r\n", 1)[0].split(" ", 2)
    status = int(parts[1]) if len(parts) >= 2 else -1
    return (status, body)


def _scrape_tx_counter(port, name, port_id):
    status, body = _http_get(port, "/metrics")
    if status != 200:
        return None
    text = body.decode("utf-8", errors="replace")
    pat = re.compile(
        r'^' + re.escape(name) + r'\{port="' + str(port_id) + r'"\}\s+(\d+)',
        re.MULTILINE,
    )
    m = pat.search(text)
    if m:
        return int(m.group(1))
    return None


def _proc_is_alive(proc):
    """Return True if proc is still running. Uses `proc.poll()` so it's
    agnostic to the signaller's uid."""
    if proc is None:
        return False
    return proc.poll() is None


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

class _VhostCrashHarness:
    """pktgate (vhost server) + testpmd (virtio-user client) on a shared
    UDS, with explicit hooks for hard-kill of the testpmd peer.

    Teardown order in __exit__:
      1. If testpmd is still alive → SIGTERM it (chaos phase may have
         already SIGKILLed it).
      2. SIGTERM pktgate → wait for clean exit.
      3. Remove the UDS path (pktgate's C2 cleanup hook handles this;
         belt-and-braces).
      4. Drop per-prefix /run/dpdk/ runtime dirs for both processes.
    """

    def __init__(self):
        self._tmpdir = None
        self.sock_path = None
        self.pktgate_config_path = None
        self.pktgate_file_prefix = None
        self.testpmd_file_prefix = None

        self.pktgate_proc = None
        self._pktgate_buf = b""
        self._pktgate_lines = []
        self.pktgate_stdout = ""
        self.pktgate_returncode = None
        self.prom_port = None
        self.downstream_port_id = None

        self.testpmd_proc = None
        self._testpmd_buf = b""
        self._testpmd_lines = []
        self.testpmd_stdout = ""
        self.testpmd_returncode = None

        self._binary = _find_pktgate_binary()

    def __enter__(self):
        _require_testpmd()

        self._tmpdir = tempfile.mkdtemp(prefix="m15-crash-")
        self.sock_path = os.path.join(self._tmpdir, "vhost-m15-crash.sock")

        nonce = time.monotonic_ns() % 10**9
        self.pktgate_file_prefix = f"pktgate_m15_crash_{nonce:09d}"
        self.testpmd_file_prefix = f"testpmd_m15_crash_{nonce:09d}"

        _delete_stale_tap(_INGRESS_IFACE)

        self.pktgate_config_path = os.path.join(self._tmpdir, "pktgate.json")
        config = _pktgate_config(
            self.sock_path,
            l4_rules=[{
                "id": 15004,
                "proto": 17,     # UDP
                "dst_port": 5616,
                "action": {"type": "allow"},
            }],
        )
        with open(self.pktgate_config_path, "w") as f:
            json.dump(config, f)

        pktgate_cmd = (
            [self._binary]
            + _pktgate_eal_args(self.sock_path, self.pktgate_file_prefix)
            + ["--config", self.pktgate_config_path]
        )
        self.pktgate_proc = subprocess.Popen(
            pktgate_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )

        ready, self._pktgate_buf, self._pktgate_lines = _wait_ready_pktgate(
            self.pktgate_proc, self._pktgate_buf, self._pktgate_lines,
            timeout=30.0,
        )
        if not ready:
            self._pktgate_stop()
            raise RuntimeError(
                f"pktgate did not reach ready. "
                f"exit={self.pktgate_proc.returncode if self.pktgate_proc else None} "
                f"stdout={self.pktgate_stdout!r}"
            )

        if not _tap_iface_up(_INGRESS_IFACE):
            self._pktgate_stop()
            raise RuntimeError(
                f"Tap {_INGRESS_IFACE} did not appear within 5s after "
                "pktgate ready."
            )
        subprocess.run(
            ["sysctl", "-qw",
             f"net.ipv6.conf.{_INGRESS_IFACE}.disable_ipv6=1"],
            capture_output=True,
        )
        subprocess.run(
            ["ip", "addr", "flush", "dev", _INGRESS_IFACE],
            capture_output=True,
        )
        subprocess.run(
            ["ip", "link", "set", _INGRESS_IFACE, "arp", "off"],
            capture_output=True,
        )

        if not os.path.exists(self.sock_path):
            self._pktgate_stop()
            raise RuntimeError(
                f"vhost UDS {self.sock_path} not created by DPDK "
                "net_vhost within pktgate boot window."
            )

        # Parse the prom endpoint port + downstream port_id from captured
        # stdout. Both events fire before `ready:true`, so by now they're
        # in self._pktgate_lines.
        self.prom_port = _extract_prom_port(self._pktgate_lines)
        self.downstream_port_id = _resolved_downstream_port(self._pktgate_lines)
        if self.prom_port is None or self.prom_port <= 0:
            self._pktgate_stop()
            raise RuntimeError(
                f"prom_endpoint_ready not observed in pktgate stdout; "
                f"stdout={'|'.join(self._pktgate_lines)[-2048:]!r}"
            )
        if self.downstream_port_id is None:
            # Conservative fallback: two vdevs declared
            # (net_tap0, net_vhost0); downstream_port maps to port 1.
            self.downstream_port_id = 1

        # Spawn testpmd on the same UDS.
        testpmd_cmd = _testpmd_cmd(self.sock_path, self.testpmd_file_prefix)
        self.testpmd_proc = subprocess.Popen(
            testpmd_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )

        _, self._testpmd_buf, self._testpmd_lines = _wait_testpmd_port_up(
            self.testpmd_proc, self._testpmd_buf, self._testpmd_lines,
            timeout=10.0,
        )

        # Settle — give the virtio-user handshake time to complete and
        # the kernel tap time to drain any bring-up chatter.
        time.sleep(1.0)

        return self

    def inject(self, packets):
        for pkt in packets:
            sendp(pkt, iface=_INGRESS_IFACE, verbose=False)

    def hard_kill_testpmd(self, timeout: float = 5.0):
        """SIGKILL testpmd and wait for the kernel to reap it.

        Returns True if testpmd exited within `timeout`, False otherwise.
        We use SIGKILL (not SIGTERM) by design — the chaos spec is hard
        peer-gone so DPDK's `net_vhost` backend sees EPIPE on the UDS,
        which is what drives `rte_eth_tx_burst` to return sent < nb_pkts
        and bump `tx_dropped_total{port}` per M14 C3.
        """
        if self.testpmd_proc is None or self.testpmd_proc.poll() is not None:
            return True
        self.testpmd_proc.send_signal(signal.SIGKILL)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.testpmd_proc.poll() is not None:
                self.testpmd_returncode = self.testpmd_proc.returncode
                return True
            time.sleep(0.05)
        return False

    def scrape_tx_dropped(self):
        return _scrape_tx_counter(
            self.prom_port,
            "pktgate_tx_dropped_total",
            self.downstream_port_id,
        )

    def scrape_tx_burst_short(self):
        return _scrape_tx_counter(
            self.prom_port,
            "pktgate_tx_burst_short_total",
            self.downstream_port_id,
        )

    def _pktgate_stop(self):
        if self.pktgate_proc and self.pktgate_proc.poll() is None:
            self.pktgate_proc.send_signal(signal.SIGTERM)
        if self.pktgate_proc:
            self.pktgate_stdout = _drain_all(
                self.pktgate_proc, self._pktgate_buf, self._pktgate_lines,
                timeout=10.0,
            )
            self.pktgate_returncode = self.pktgate_proc.returncode

    def __exit__(self, exc_type, exc_val, exc_tb):
        # testpmd: if chaos phase already SIGKILLed it, this is a no-op;
        # otherwise SIGTERM + short drain.
        if self.testpmd_proc and self.testpmd_proc.poll() is None:
            try:
                self.testpmd_proc.send_signal(signal.SIGTERM)
                self.testpmd_stdout = _drain_all(
                    self.testpmd_proc, self._testpmd_buf, self._testpmd_lines,
                    timeout=5.0,
                )
                self.testpmd_returncode = self.testpmd_proc.returncode
            except Exception:
                try:
                    self.testpmd_proc.kill()
                except Exception:
                    pass
        elif self.testpmd_proc:
            # Already dead — drain any buffered output so the assertion
            # messages have useful context.
            self.testpmd_stdout = _drain_all(
                self.testpmd_proc, self._testpmd_buf, self._testpmd_lines,
                timeout=1.0,
            )
            self.testpmd_returncode = self.testpmd_proc.returncode

        self._pktgate_stop()

        if self.sock_path and os.path.exists(self.sock_path):
            try:
                os.unlink(self.sock_path)
            except OSError:
                pass

        if self._tmpdir and os.path.isdir(self._tmpdir):
            shutil.rmtree(self._tmpdir, ignore_errors=True)

        xdg = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
        for prefix in (self.pktgate_file_prefix, self.testpmd_file_prefix):
            if not prefix:
                continue
            for base in (
                os.path.join(xdg, "dpdk", prefix),
                os.path.join("/run/dpdk", prefix),
                os.path.join("/var/run/dpdk", prefix),
            ):
                if os.path.isdir(base):
                    shutil.rmtree(base, ignore_errors=True)

        time.sleep(0.2)
        return False


# ---------------------------------------------------------------------------
# The test
# ---------------------------------------------------------------------------

def test_m15_vhost_peer_crash_tx_dropped_climbs():
    """F15.4 — peer-crash chaos.

    Warmup: inject _WARMUP_COUNT packets → baseline tx_dropped_total.
    Chaos: SIGKILL testpmd mid-flight → inject _POST_CRASH_BURST packets
           at best-effort → wait >= 2.5 s for publisher tick.
    Assert:
      * pktgate process still alive (proc.poll() is None).
      * final tx_dropped_total{port=<downstream_port_id>} strictly > baseline.

    The assertion threshold is _DROP_THRESHOLD_REAL (=1). RED predecessor
    used _DROP_THRESHOLD_RED (=10_000_000), impossible to satisfy. The
    contract is crossing-zero, not a specific drop count — exact delta
    depends on UDS EPIPE timing, PMD internal buffering, and publisher
    tick cadence, none of which we want to hard-wire.
    """
    warmup_pkts = []
    for i in range(_WARMUP_COUNT):
        warmup_pkts.append(
            Ether(src=_TEST_SRC, dst=_TEST_DST)
            / IP(src="10.15.4.1", dst="10.15.4.2")
            / UDP(sport=4242, dport=5616)
            / Raw(b"M15-C4-WARMUP-" + bytes([i & 0xFF]) * 32)
        )

    burst_pkts = []
    for i in range(_POST_CRASH_BURST):
        burst_pkts.append(
            Ether(src=_TEST_SRC, dst=_TEST_DST)
            / IP(src="10.15.4.1", dst="10.15.4.2")
            / UDP(sport=4242, dport=5616)
            / Raw(b"M15-C4-POSTKILL-" + bytes([i & 0xFF]) * 32)
        )

    with _VhostCrashHarness() as h:
        # Warmup — pump a few packets through the live path so we've
        # exercised the tx_one / redirect_drain loop before the peer
        # dies. Not strictly required for the counter to bump after
        # SIGKILL, but it gives the publisher tick a meaningful
        # pre-crash baseline to diff against.
        time.sleep(0.2)
        h.inject(warmup_pkts)
        time.sleep(0.5)

        baseline_drop = h.scrape_tx_dropped()
        assert baseline_drop is not None, (
            f"baseline scrape: pktgate_tx_dropped_total"
            f"{{port=\"{h.downstream_port_id}\"}} not present in /metrics. "
            f"prom_port={h.prom_port} "
            f"downstream_port_id={h.downstream_port_id} "
            f"pktgate_stdout_tail="
            f"{'|'.join(h._pktgate_lines)[-2048:]!r}"
        )
        baseline_short = h.scrape_tx_burst_short()  # may be None; advisory

        # Hard-kill the peer.
        assert h.hard_kill_testpmd(timeout=5.0), (
            "testpmd did not exit within 5s of SIGKILL; the kernel "
            "should have reaped it immediately."
        )

        # Fire the burst at best-effort. DPDK net_vhost's peer-disconnect
        # path fires inside rte_eth_tx_burst; once the UDS has seen EPIPE
        # on the backend's side, sent < nb_pkts → M14 C3 bump sites run.
        h.inject(burst_pkts)

        # Wait for the publisher tick (~Hz cadence under dev-tsan). 2.5 s
        # leaves headroom even under cold-start sanitiser cadence.
        time.sleep(2.5)

        final_drop = h.scrape_tx_dropped()
        final_short = h.scrape_tx_burst_short()

        pktgate_alive = _proc_is_alive(h.pktgate_proc)

        # Assertions.
        assert pktgate_alive, (
            "pktgate exited after testpmd SIGKILL — peer-gone path "
            "crashed the process. This is a hot-path regression in "
            "net_vhost peer-disconnect handling or in the pktgate tx "
            "wrapper. pktgate_rc="
            f"{h.pktgate_proc.returncode if h.pktgate_proc else None} "
            f"stdout_tail={'|'.join(h._pktgate_lines)[-2048:]!r}"
        )
        assert final_drop is not None, (
            "post-crash scrape returned None for tx_dropped_total. "
            f"prom_port={h.prom_port} "
            f"port_id={h.downstream_port_id}"
        )

        drop_delta = final_drop - (baseline_drop or 0)

        # GREEN threshold — strictly positive delta witnesses that the
        # M14 C3 backend-agnostic counter covers the vhost peer-gone
        # path by construction. RED predecessor used
        # `_DROP_THRESHOLD_RED` (10_000_000), impossible to satisfy.
        assert drop_delta >= _DROP_THRESHOLD_REAL, (
            f"F15.4: SIGKILL of testpmd peer did NOT raise "
            f"pktgate_tx_dropped_total{{port=\"{h.downstream_port_id}\"}} "
            f"above baseline. baseline={baseline_drop} "
            f"final={final_drop} delta={drop_delta}; "
            f"baseline_burst_short={baseline_short} "
            f"final_burst_short={final_short}. "
            "Either the vhost backend is swallowing the disconnect "
            "silently (no EPIPE → tx_burst never sees sent<nb_pkts) "
            "or the M14 C3 per-port bump sites regressed. Investigate "
            "redirect_drain / tx_one in src/dataplane/action_dispatch.h."
        )

    # Post-harness: pktgate should have exited cleanly after our SIGTERM
    # in __exit__. testpmd was SIGKILLed mid-run so its returncode is
    # -9 (SIGKILL) — not something we assert on.
    assert h.pktgate_returncode == 0, (
        f"pktgate unclean exit rc={h.pktgate_returncode} after peer "
        f"crash chaos. stdout_tail={h.pktgate_stdout[-2048:]!r}"
    )
