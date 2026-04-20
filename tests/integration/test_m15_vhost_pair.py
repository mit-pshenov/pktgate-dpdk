# tests/integration/test_m15_vhost_pair.py
#
# M15 C3 — paired DPDK integration harness.
#
# Spawns pktgate (vhost server-side) and `dpdk-testpmd` (virtio-user
# client-side) simultaneously on a shared UDS, bridges scapy-injected
# IPv4 traffic through pktgate's ingress TAP, and verifies testpmd's
# virtio-user port saw the packets.
#
# This is the first M15 test that exercises the full data-plane
# round-trip for the vhost profile — C1 covered server-mode boot
# (control-plane only, net_null upstream) and C2 covered the socket
# lifecycle (SIGTERM + stale guard + normal-exit cleanup). Here the
# vhost downstream is driven by a real consumer, and the ingress is a
# net_tap so we can inject with scapy.
#
# Design anchors:
#   - D43 (exit port abstraction) — vhost ships as the prod DPI
#     hand-off canonical profile.
#   - D44 (vhost socket lifecycle) — path convention + cleanup.
#   - M14 C3 counters (tx_dropped_total / tx_burst_short_total{port})
#     — backend-agnostic, cover the vhost port by construction. No new
#     counter family needed for M15.
#
# DPDK multi-process hygiene:
#   - Distinct `--file-prefix` for pktgate (`pktgate_m15_pair`) and
#     testpmd (`testpmd_m15_pair`) — mandatory or EAL races on
#     /run/dpdk/<prefix>/ (memory grabli_run_dpdk_tmpfs_leak.md).
#   - Cleanup in the finally guard for BOTH processes' runtime dirs
#     plus the shared UDS path.
#
# NDP / kernel-noise discipline (mirroring test_f14_tap_exit):
#   - NM keyfile session scope for `dtap_m15_ing` (extended in
#     tests/functional/conftest.py).
#   - sysctl disable_ipv6=1 + arp off + addr flush on the tap the
#     moment it appears.
#
# `-d` EAL flag policy: **opt-in** via PKTGATE_DPDK_DRIVER_DIR. We do
# NOT inject `-d drivers/` into either pktgate or testpmd cmdline;
# the dev VM's ldconfig already exposes the build-tree PMDs and the
# default /usr/local/ install handles testpmd. Memory
# grabli_eal_d_flag_env_opt_in.md.

import json
import os
import re
import select
import shutil
import signal
import subprocess
import tempfile
import time

import pytest
from scapy.all import (
    Ether, IP, UDP, Raw, conf as scapy_conf, sendp,
)

scapy_conf.verb = 0

# Session-scoped NM keyfile: conftest already lists dtap_m15_ing below.
pytestmark = pytest.mark.usefixtures("nm_unmanaged_tap")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_INGRESS_IFACE = "dtap_m15_ing"

_TESTPMD_BIN = os.environ.get(
    "PKTGATE_TESTPMD_BIN", "/usr/local/bin/dpdk-testpmd",
)

_TEST_SRC = "aa:bb:cc:dd:ee:15"
_TEST_DST = "11:22:33:44:55:15"

_INJECT_COUNT = 128
# Allow headroom for NDP-chatter / TAP bring-up lost frames. We want a
# strongly positive signal without being so strict it flakes.
_RX_THRESHOLD_REAL = 100
# RED sentinel — impossible to hit with _INJECT_COUNT injected packets.
# GREEN flips this to _RX_THRESHOLD_REAL.
_RX_THRESHOLD_RED = 10_000_000


# ---------------------------------------------------------------------------
# Helpers
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
            "M15 C3 integration requires the system DPDK install "
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


def _parse_json_lines(text: str):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        out.append(obj)
    return out


def _pktgate_config(sock_path: str, l4_rules=None):
    """pktgate config: net_tap ingress, net_vhost downstream.

    L4 ALLOW is used — L2 ALLOW is a no-op under default_behavior=drop
    (memory grabli_l2_allow_fallthrough.md: classify_l2 returns NEXT_L3
    on ALLOW-match, default drop sinks the packet).
    """
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
    # testpmd as virtio-user client on the pktgate-owned UDS.
    # --forward-mode=rxonly: pure consumer; --auto-start begins forwarding
    # immediately after init so we don't need an interactive stdin.
    # --no-mlockall: dev VM has modest RLIMIT_MEMLOCK; testpmd does not
    # need locked pages for a correctness smoke.
    # --total-num-mbufs=2048: enough for rxonly on a single 1-queue port.
    return [
        _TESTPMD_BIN,
        "-l", "2,3",           # distinct from pktgate's 0,1
        "--no-pci",
        "--no-huge",
        "-m", "256",
        "--file-prefix", file_prefix,
        "--vdev", f"net_virtio_user0,path={sock_path},queues=1",
        "--log-level", "lib.*:error",
        "--",
        "-i",                  # interactive CLI (we send `quit` on stdin)
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
    """Wait for testpmd to log a port-up event. Returns (ok, buf, lines).

    testpmd emits various startup banners; we look for either a link-up
    event or the "Port 0: ... started" line. Falls through on timeout
    so the caller can decide whether to proceed anyway.
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
                # testpmd's "Port 0: link state change event" or
                # "Start automatic packet forwarding" both work.
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
    """Drain any pending stdout bytes from `proc` for up to `timeout`
    wall-time seconds; append decoded lines to `collected`."""
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
    """After process exit, drain any remaining stdout bytes. Returns
    the final combined text."""
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


_TESTPMD_RX_RE = re.compile(
    r"^\s*RX-packets:\s*(\d+)", re.MULTILINE,
)
_TESTPMD_PORT0_RE = re.compile(
    r"######################## NIC statistics for port 0 "
    r"########################"
)


def _parse_testpmd_rx(stdout_text: str):
    """Extract the largest RX-packets value seen in testpmd output.

    testpmd prints stats blocks per port in this shape:
      ######################## NIC statistics for port 0 #############
        RX-packets: 128        RX-missed: 0          RX-bytes: 16384
        ...
    We take the MAX across all stat dumps — the SIGINT final dump
    is the authoritative one but interactive sessions may emit
    intermediate "show port stats 0" output too.
    """
    matches = _TESTPMD_RX_RE.findall(stdout_text)
    if not matches:
        return None
    return max(int(m) for m in matches)


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

class _VhostPairHarness:
    """Brings up pktgate (vhost server) + testpmd (virtio-user client)
    on a shared UDS. Manages lifecycle + cleanup for BOTH processes and
    the tmpfs runtime dirs."""

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

        self.testpmd_proc = None
        self._testpmd_buf = b""
        self._testpmd_lines = []
        self.testpmd_stdout = ""
        self.testpmd_returncode = None

        self._binary = _find_pktgate_binary()

    def __enter__(self):
        _require_testpmd()

        self._tmpdir = tempfile.mkdtemp(prefix="m15-pair-")
        self.sock_path = os.path.join(self._tmpdir, "vhost-m15-pair.sock")

        # Nondeterministic suffix so sequential runs in the same session
        # can't collide on EAL runtime dirs.
        nonce = time.monotonic_ns() % 10**9
        self.pktgate_file_prefix = f"pktgate_m15_pair_{nonce:09d}"
        self.testpmd_file_prefix = f"testpmd_m15_pair_{nonce:09d}"

        # Pre-clean any stale tap from an aborted run.
        _delete_stale_tap(_INGRESS_IFACE)

        # Write pktgate config.
        self.pktgate_config_path = os.path.join(self._tmpdir, "pktgate.json")
        config = _pktgate_config(
            self.sock_path,
            l4_rules=[{
                "id": 15003,
                "proto": 17,      # UDP
                "dst_port": 5615,
                "action": {"type": "allow"},
            }],
        )
        with open(self.pktgate_config_path, "w") as f:
            json.dump(config, f)

        # Spawn pktgate.
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

        # Wait for the tap to appear, then harden against NDP / DHCP /
        # ARP noise immediately.
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

        # Verify the vhost socket actually got created by DPDK.
        if not os.path.exists(self.sock_path):
            self._pktgate_stop()
            raise RuntimeError(
                f"vhost UDS {self.sock_path} not created by DPDK "
                "net_vhost within pktgate boot window."
            )

        # Spawn testpmd on the same UDS.
        testpmd_cmd = _testpmd_cmd(self.sock_path, self.testpmd_file_prefix)
        self.testpmd_proc = subprocess.Popen(
            testpmd_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )

        # Brief wait for testpmd to negotiate the virtio-user link and
        # start forwarding. It doesn't print a JSON ready event; we look
        # for a link-up line or the "Start automatic packet forwarding"
        # banner. Failure to find either is not fatal — testpmd may
        # already be consuming; the per-packet stat check below is the
        # authoritative witness.
        _, self._testpmd_buf, self._testpmd_lines = _wait_testpmd_port_up(
            self.testpmd_proc, self._testpmd_buf, self._testpmd_lines,
            timeout=10.0,
        )

        # Settle — let testpmd-side virtio-user finish handshake and let
        # any residual kernel chatter on the tap drain out.
        time.sleep(1.0)

        return self

    def inject(self, packets):
        for pkt in packets:
            sendp(pkt, iface=_INGRESS_IFACE, verbose=False)

    def collect_testpmd_rx(self):
        """Ask testpmd for its final stats, then SIGINT it so the RX
        total lands on stdout before process exit."""
        # Drain any pending output from both processes so the final
        # stats dump appears at the tail.
        self._testpmd_buf = _drain_nonblocking(
            self.testpmd_proc, self._testpmd_buf, self._testpmd_lines,
            timeout=0.5,
        )

        # Send `stop` + `show port stats 0` + `quit` on testpmd's CLI.
        # testpmd prints the per-port stats block which includes
        # RX-packets: N.
        if self.testpmd_proc and self.testpmd_proc.poll() is None:
            try:
                self.testpmd_proc.stdin.write(b"stop\n")
                self.testpmd_proc.stdin.write(b"show port stats 0\n")
                self.testpmd_proc.stdin.write(b"quit\n")
                self.testpmd_proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass

        # Drain testpmd until it exits.
        self.testpmd_stdout = _drain_all(
            self.testpmd_proc, self._testpmd_buf, self._testpmd_lines,
            timeout=10.0,
        )
        self.testpmd_returncode = self.testpmd_proc.returncode
        return _parse_testpmd_rx(self.testpmd_stdout)

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
        # testpmd first (it's the consumer; kill it so pktgate's TX
        # path sees its disconnect cleanly, exercising the M15 C2
        # vhost-scoped cleanup bypass).
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

        self._pktgate_stop()

        # Clean the UDS (pktgate's C2 cleanup hook should have handled
        # this; belt-and-braces).
        if self.sock_path and os.path.exists(self.sock_path):
            try:
                os.unlink(self.sock_path)
            except OSError:
                pass

        if self._tmpdir and os.path.isdir(self._tmpdir):
            shutil.rmtree(self._tmpdir, ignore_errors=True)

        # Wipe per-prefix DPDK runtime dirs for both processes.
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
        return False  # do not suppress


# ---------------------------------------------------------------------------
# The test
# ---------------------------------------------------------------------------

def test_m15_vhost_pair_forwards():
    """End-to-end vhost data-plane witness.

    pktgate boots as vhost server + net_tap ingress; dpdk-testpmd boots
    as virtio-user client on the same UDS; scapy injects _INJECT_COUNT
    IPv4/UDP frames matching an ALLOW rule on the ingress tap; testpmd
    reports its RX counter via `show port stats 0` on stdin-driven CLI.

    Asserts testpmd's RX-packets counter crosses a threshold proving
    the data path from kernel tap → DPDK rx → pktgate pipeline →
    vhost TX → virtio-user consumer is end-to-end live.

    GREEN (M15 C3): threshold is _RX_THRESHOLD_REAL (100), leaving
    headroom for small-burst boundary losses or NDP-chatter drops
    on the tap. RED predecessor used _RX_THRESHOLD_RED (10_000_000)
    impossible-to-satisfy sentinel; see RED commit body for rationale.
    """
    pkts = []
    for i in range(_INJECT_COUNT):
        pkts.append(
            Ether(src=_TEST_SRC, dst=_TEST_DST)
            / IP(src="10.15.3.1", dst="10.15.3.2")
            / UDP(sport=4242, dport=5615)
            / Raw(b"M15-C3-VHOST-PAIR-" + bytes([i & 0xFF]) * 32)
        )

    with _VhostPairHarness() as h:
        # Let testpmd settle with auto-start forwarding active before we
        # push injects through, then a short drain window after.
        time.sleep(0.2)
        h.inject(pkts)
        time.sleep(0.5)
        rx = h.collect_testpmd_rx()

    # testpmd has exited at this point; pktgate teardown follows from
    # __exit__. Pull the per-process exit codes for the failure message.
    assert rx is not None, (
        "testpmd stats never printed RX-packets line. "
        f"testpmd_rc={h.testpmd_returncode} "
        f"testpmd_stdout_tail={h.testpmd_stdout[-2048:]!r} "
        f"pktgate_stdout_tail={h.pktgate_stdout[-1024:]!r}"
    )

    # GREEN: threshold is the real minimum — 100 out of 128 injected,
    # leaving headroom for tap-bringup boundary losses or stray NDP
    # drops. RED used the 10_000_000 sentinel (see _RX_THRESHOLD_RED
    # kept as a documented constant so the RED→GREEN diff is legible).
    assert rx >= _RX_THRESHOLD_REAL, (
        f"testpmd saw only {rx} RX packets via virtio-user on the "
        f"shared vhost UDS; expected >= {_RX_THRESHOLD_REAL}. "
        f"Injected {_INJECT_COUNT} frames. "
        f"pktgate_rc={h.pktgate_returncode} "
        f"testpmd_rc={h.testpmd_returncode} "
        f"testpmd_stdout_tail={h.testpmd_stdout[-2048:]!r}"
    )

    assert h.pktgate_returncode == 0, (
        f"pktgate unclean exit rc={h.pktgate_returncode} "
        f"stdout_tail={h.pktgate_stdout[-2048:]!r}"
    )
