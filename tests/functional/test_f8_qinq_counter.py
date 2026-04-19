# tests/functional/test_f8_qinq_counter.py
#
# M4 C9 — F8.14: QinQ outer counter visibility (D32).
#
# Injects a true QinQ stack (outer 0x88A8 S-tag, inner 0x8100 C-tag) and
# asserts that the per-lcore `qinq_outer_only_total` counter is visible in
# the stats_on_exit JSON log line.
#
# Plan-doc wording in functional.md references a Prometheus label
# (`pktgate_lcore_qinq_outer_only_total{lcore="0"}`); the Prometheus scrape
# surface lands in M10.  For M4 the observable is the stats_on_exit JSON
# counters sibling — one aggregated integer across all lcores.  Dev VM runs
# single-queue e1000, so the aggregate equals the single-lcore value.
#
# D41 (pipeline smoke): this test exercises the full compile → ruleset
# populate → classify_l2 → counter bump → stats_on_exit chain through the
# live boot path, so it doubles as additional M4 pipeline smoke.
#
# Covers: F8.14, D32, D41.

import json
import os
import select
import signal
import subprocess
import tempfile
import time

import pytest
from scapy.all import Ether, Dot1Q, conf as scapy_conf

scapy_conf.verb = 0  # suppress scapy output

# Use the session-scoped NM-unmanaged fixture so NetworkManager does not
# fire DHCP / NDP on the dtap_f8_* interfaces while the test runs.
pytestmark = pytest.mark.usefixtures("nm_unmanaged_tap")


# EAL `-d <path>` opt-in: default empty, rely on the dev VM's ldconfig
# exposure of the build-tree DPDK PMDs (memory `vm_dpdk_layout.md`).
# Set PKTGATE_DPDK_DRIVER_DIR to force an explicit directory; see the
# shared helper comment in conftest.py for the dual-install rationale.
_DPDK_DRIVER_DIR_ARGS = (
    ["-d", os.environ["PKTGATE_DPDK_DRIVER_DIR"].strip()]
    if os.environ.get("PKTGATE_DPDK_DRIVER_DIR", "").strip()
    else []
)

_INGRESS_IFACE = "dtap_f8_rx"
_EGRESS_IFACE = "dtap_f8_tx"

_EAL_ARGS_TEMPLATE = [
    "--no-pci",
    "--no-huge",
    "-m", "64",
    *_DPDK_DRIVER_DIR_ARGS,
    "--vdev", f"net_tap0,iface={_INGRESS_IFACE}",
    "--vdev", f"net_tap1,iface={_EGRESS_IFACE}",
    "-l", "0,1",
    "--log-level", "lib.*:error",
]

_SIZING = {
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
}


# ---------------------------------------------------------------------------
# Helpers (mirrored from test_f2_l2.py — kept local to this module so F2
# refactors do not accidentally break F8).
# ---------------------------------------------------------------------------

def _find_binary():
    env_path = os.environ.get("PKTGATE_BINARY")
    if env_path and os.path.isfile(env_path):
        return env_path
    base = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    for preset in ["dev-asan", "dev-debug", "dev-release", "dev-ubsan", "dev-tsan"]:
        path = os.path.join(base, "build", preset, "pktgate_dpdk")
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    pytest.skip("pktgate_dpdk binary not found")


def _delete_stale_tap(iface: str) -> None:
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
        result = subprocess.run(
            ["ip", "link", "show", iface],
            capture_output=True, text=True,
        )
        if result.returncode == 0 and iface in result.stdout:
            return True
        time.sleep(0.1)
    return False


def _parse_stats_on_exit(stdout: str) -> dict:
    """Return the raw stats_on_exit JSON object, or {} if absent."""
    for line in stdout.splitlines():
        line = line.strip()
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("event") == "stats_on_exit":
            return obj
    return {}


class _F8Harness:
    def __init__(self, config: dict, file_prefix: str):
        self._config = config
        self._file_prefix = (
            f"{file_prefix}_{time.monotonic_ns() % 10**9:09d}"
        )
        self._binary = _find_binary()
        self._proc = None
        self._lines: list = []
        self._raw_buf = b""
        self.stdout_text = ""
        self.returncode = None
        self._tmpf = None

    def __enter__(self):
        _delete_stale_tap(_INGRESS_IFACE)
        _delete_stale_tap(_EGRESS_IFACE)

        self._tmpf = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        )
        json.dump(self._config, self._tmpf)
        self._tmpf.close()

        eal_args = _EAL_ARGS_TEMPLATE + ["--file-prefix", self._file_prefix]
        cmd = [self._binary] + eal_args + ["--config", self._tmpf.name]

        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )

        deadline = time.monotonic() + 15.0
        ready = False
        while time.monotonic() < deadline:
            r, _, _ = select.select(
                [self._proc.stdout.fileno()], [], [], 0.1,
            )
            if r:
                try:
                    chunk = os.read(self._proc.stdout.fileno(), 4096)
                except OSError:
                    chunk = b""
                if not chunk:
                    break
                self._raw_buf += chunk
                while b"\n" in self._raw_buf:
                    line, self._raw_buf = self._raw_buf.split(b"\n", 1)
                    text = line.decode(errors="replace")
                    self._lines.append(text)
                    if '"ready":true' in text or '"ready": true' in text:
                        ready = True
                        break
                if ready:
                    break
            if self._proc.poll() is not None:
                break

        if not ready:
            self._proc.kill()
            try:
                remaining, _ = self._proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                remaining = b""
            if isinstance(remaining, bytes):
                remaining = remaining.decode(errors="replace")
            tail = self._raw_buf.decode(errors="replace")
            self.stdout_text = (
                "\n".join(self._lines) + "\n" + tail + "\n" + remaining
            )
            raise RuntimeError(
                f"Binary did not reach ready. exit={self._proc.returncode} "
                f"stdout={self.stdout_text!r}"
            )

        if not _tap_iface_up(_INGRESS_IFACE):
            self._proc.terminate()
            raise RuntimeError(
                f"Tap interface {_INGRESS_IFACE!r} did not appear within 5s"
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

        time.sleep(0.5)

        return self

    def inject(self, packets, pause: float = 0.3):
        from scapy.all import sendp, conf as sc
        sc.ifaces.reload()
        for pkt in packets:
            sendp(pkt, iface=_INGRESS_IFACE, verbose=False)
        time.sleep(pause)

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._proc and self._proc.poll() is None:
            self._proc.send_signal(signal.SIGTERM)
        try:
            remaining, _ = self._proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            remaining, _ = self._proc.communicate(timeout=5)

        if isinstance(remaining, bytes):
            remaining = remaining.decode(errors="replace")
        tail = self._raw_buf.decode(errors="replace")
        pre = "\n".join(self._lines)
        combined = pre
        if tail:
            combined = (combined + "\n" + tail) if combined else tail
        if remaining:
            combined = (
                (combined + "\n" + remaining) if combined else remaining
            )
        self.stdout_text = combined
        self.returncode = self._proc.returncode

        if self._tmpf and os.path.exists(self._tmpf.name):
            os.unlink(self._tmpf.name)

        time.sleep(0.2)
        return False


def _config(l2_rules: list, default_behavior: str = "allow") -> dict:
    return {
        "version": 1,
        "interface_roles": {
            "upstream_port":   {"vdev": "net_tap0"},
            "downstream_port": {"vdev": "net_tap1"},
        },
        "default_behavior": default_behavior,
        "pipeline": {
            "layer_2": l2_rules,
            "layer_3": [],
            "layer_4": [],
        },
        "sizing": _SIZING,
    }


# ---------------------------------------------------------------------------
# F8.14 — QinQ outer counter visible in stats_on_exit
# ---------------------------------------------------------------------------

def test_f8_14_qinq_outer_only_counter_visible():
    """F8.14: injecting a true QinQ stack (outer 0x88A8, inner 0x8100) bumps
    qinq_outer_only_total; the counter is readable from stats_on_exit JSON
    under the `counters` sibling key (M4 observable path — M10 adds the
    Prometheus scrape surface)."""
    # Rule that will not match our QinQ frame: we only care about the
    # counter being visible, not the verdict.  default_behavior=allow keeps
    # classify_l2 on the NEXT_L3 path for a miss.
    config = _config([
        {
            "id": 1800,
            "src_mac": "cc:cc:cc:cc:cc:cc",
            "action": {"type": "drop"},
        }
    ])

    # scapy: Ether(type=0x88A8) / Dot1Q(vlan=10) inner type=0x8100 /
    # Dot1Q(vlan=20) → outer S-tag, inner C-tag (true QinQ).  classify_l2
    # walks one tag, sees pkt_etype=0x8100 still being a VLAN TPID, and
    # bumps qinq_outer_only_total.
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66", type=0x88A8) /
        Dot1Q(vlan=10, type=0x8100) /
        Dot1Q(vlan=20, type=0x0800) /
        (b"\x00" * 20)
    )

    with _F8Harness(config, "pktgate_f8_14") as h:
        h.inject([pkt])

    assert h.returncode == 0, (
        f"exit={h.returncode} stdout={h.stdout_text!r}"
    )
    assert "stats_on_exit" in h.stdout_text, (
        f"missing stats_on_exit in: {h.stdout_text!r}"
    )

    stats = _parse_stats_on_exit(h.stdout_text)
    assert "counters" in stats, (
        f"stats_on_exit missing `counters` sibling; got keys={list(stats)!r} "
        f"raw={h.stdout_text!r}"
    )
    counters = stats["counters"]
    assert "qinq_outer_only_total" in counters, (
        f"counters missing qinq_outer_only_total: {counters!r}"
    )
    assert counters["qinq_outer_only_total"] >= 1, (
        f"qinq_outer_only_total = {counters['qinq_outer_only_total']}, "
        f"expected >= 1; stats={stats!r}"
    )
