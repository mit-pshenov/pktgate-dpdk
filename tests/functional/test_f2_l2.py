# tests/functional/test_f2_l2.py
#
# M4 C8 — F2.1-F2.9: Happy-path L2 matching, end-to-end.
#
# Injection path: net_tap vdevs. The DPDK binary creates dtap_f2_rx / dtap_f2_tx
# kernel tap interfaces; the test harness writes Ethernet frames via
# scapy.sendp() to dtap_f2_rx (ingress), then SIGTERMs the binary and inspects
# the "stats_on_exit" JSON log line for per-rule counters.
#
# Observable contract:
#   - stats_on_exit log line carries {rule_id, matched_packets, drops} per rule.
#   - Per-rule counters are bumped by the worker AFTER classify_l2 returns.
#   - D41: every test exercises the top-level classify_l2 entry point
#     through the live boot path.
#
# Covers: F2.1-F2.9, D15 compound, D13 l3_offset, D41 (boot-path smoke clause).

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

# Every test in this module wants the session-scoped NM-unmanaged fixture
# so NetworkManager does not fire DHCP / NDP on the dtap_f2_* interfaces
# between tests (the cross-test contamination root-caused in M4 C8 rollback).
pytestmark = pytest.mark.usefixtures("nm_unmanaged_tap")


DPDK_DRIVER_DIR = os.environ.get(
    "DPDK_DRIVER_DIR", "/home/mit/Dev/dpdk-25.11/build/drivers/"
)

_INGRESS_IFACE = "dtap_f2_rx"
_EGRESS_IFACE = "dtap_f2_tx"

_EAL_ARGS_TEMPLATE = [
    "--no-pci",
    "--no-huge",
    "-m", "64",
    "-d", DPDK_DRIVER_DIR,
    "--vdev", f"net_tap0,iface={_INGRESS_IFACE}",
    "--vdev", f"net_tap1,iface={_EGRESS_IFACE}",
    "-l", "0,1",
    "--log-level", "lib.*:error",
]

# Explicit non-zero sizing so validator does not bring in unexpected defaults
# that may drift between commits.
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
# Helpers
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
    """Remove any stale kernel tap left over from a previous crashed run.

    DPDK net_tap creates persistent TUN/TAP interfaces.  A stale interface
    can preserve kernel-side queue counts from an older DPDK instance,
    silently misrouting AF_PACKET injected frames; deleting first and
    letting the new DPDK instance re-create it guarantees a clean queue.
    """
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
    """Return {rule_id: {matched_packets, drops}} parsed from the stats_on_exit
    JSON log line, or {} if absent."""
    for line in stdout.splitlines():
        line = line.strip()
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("event") == "stats_on_exit":
            out = {}
            for entry in obj.get("rules", []):
                rid = entry.get("rule_id")
                if rid is not None:
                    out[rid] = {
                        "matched_packets": entry.get("matched_packets", 0),
                        "drops": entry.get("drops", 0),
                    }
            return out
    return {}


class _F2Harness:
    """Context manager: start pktgate with a config, wait for ready, inject
    packets, SIGTERM, and make `stdout_text` available."""

    def __init__(self, config: dict, file_prefix: str):
        self._config = config
        # Unique suffix per instance so repeated runs do not collide on the
        # DPDK runtime dir used as a file lock.
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

        # Raw stdout with bufsize=0: read bytes straight from the fd to keep
        # the select()-based ready-wait loop honest; Python's text-mode line
        # buffer can otherwise hold a complete line the select poll never
        # flags as ready.
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )

        # Wait for {"ready":true}.
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

        # Defense-in-depth against kernel control traffic on the tap device.
        # The session-wide nm_unmanaged_tap fixture covers NM; these disable
        # IPv6 autoconf / ARP on the freshly-created kernel tap device.
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

        # Settle: let any one-shot kernel bring-up traffic drain through
        # classify_l2 before our injected frames land.
        time.sleep(0.5)

        return self

    def inject(self, packets, pause: float = 0.3):
        from scapy.all import sendp, conf as sc
        # Reload scapy's interface cache in case a previous test deleted the
        # device and the cache holds a stale if_index.
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

        time.sleep(0.2)  # allow EAL to release hugepage mappings
        return False  # do not suppress


def _config(l2_rules: list, default_behavior: str = "drop") -> dict:
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
# F2.1 — L2 src_mac exact match → drop
# ---------------------------------------------------------------------------

def test_f2_1_l2_src_mac_drop():
    """F2.1: one L2 rule on src_mac; match bumps matched+drops, miss untouched."""
    config = _config([
        {
            "id": 1001,
            "src_mac": "aa:bb:cc:dd:ee:ff",
            "action": {"type": "drop"},
        }
    ])

    pkt_match = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
    pkt_miss = Ether(src="00:00:00:00:00:01", dst="11:22:33:44:55:66")

    with _F2Harness(config, "pktgate_f2_1") as h:
        h.inject([pkt_match, pkt_miss])

    assert h.returncode == 0, (
        f"exit={h.returncode} stdout={h.stdout_text!r}"
    )
    assert "stats_on_exit" in h.stdout_text, (
        f"missing stats_on_exit in: {h.stdout_text!r}"
    )
    stats = _parse_stats_on_exit(h.stdout_text)
    assert 1001 in stats, f"rule 1001 absent: {stats!r}"
    assert stats[1001]["matched_packets"] == 1, stats
    assert stats[1001]["drops"] == 1, stats


# ---------------------------------------------------------------------------
# F2.2 — L2 dst_mac exact match → allow
# ---------------------------------------------------------------------------

def test_f2_2_l2_dst_mac_allow():
    """F2.2: dst_mac allow — matched_packets=1, drops=0."""
    config = _config([
        {
            "id": 1002,
            "dst_mac": "11:22:33:44:55:66",
            "action": {"type": "allow"},
        }
    ])

    pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")

    with _F2Harness(config, "pktgate_f2_2") as h:
        h.inject([pkt])

    assert h.returncode == 0
    stats = _parse_stats_on_exit(h.stdout_text)
    assert 1002 in stats, f"rule 1002 absent: {stats!r}"
    assert stats[1002]["matched_packets"] == 1, stats
    assert stats[1002]["drops"] == 0, stats


# ---------------------------------------------------------------------------
# F2.3 — L2 vlan_id match
# ---------------------------------------------------------------------------

def test_f2_3_l2_vlan_id_match():
    """F2.3: vlan_id=100 rule hits the vlan=100 packet only."""
    config = _config([
        {
            "id": 1003,
            "vlan_id": 100,
            "action": {"type": "drop"},
        }
    ])

    pkt_vlan100 = Ether(src="aa:bb:cc:dd:ee:ff",
                        dst="11:22:33:44:55:66") / Dot1Q(vlan=100)
    pkt_vlan200 = Ether(src="aa:bb:cc:dd:ee:ff",
                        dst="11:22:33:44:55:66") / Dot1Q(vlan=200)
    pkt_untag = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")

    with _F2Harness(config, "pktgate_f2_3") as h:
        h.inject([pkt_vlan100, pkt_vlan200, pkt_untag])

    assert h.returncode == 0
    stats = _parse_stats_on_exit(h.stdout_text)
    assert 1003 in stats, f"rule 1003 absent: {stats!r}"
    assert stats[1003]["matched_packets"] == 1, stats


# ---------------------------------------------------------------------------
# F2.4 — untagged frame must not trigger a vlan rule
# ---------------------------------------------------------------------------

def test_f2_4_l2_untagged_misses_vlan_rule():
    """F2.4: an untagged frame does not bump the vlan_id=100 rule."""
    config = _config([
        {
            "id": 1004,
            "vlan_id": 100,
            "action": {"type": "drop"},
        }
    ])

    pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")

    with _F2Harness(config, "pktgate_f2_4") as h:
        h.inject([pkt])

    assert h.returncode == 0
    stats = _parse_stats_on_exit(h.stdout_text)
    matched = stats.get(1004, {}).get("matched_packets", 0)
    assert matched == 0, (
        f"expected untagged frame to miss vlan rule; stats={stats!r}"
    )


# ---------------------------------------------------------------------------
# F2.5 — L2 ethertype match (0x0800) under a src_mac anchor
#
# Anchoring on src_mac=aa:bb:cc:dd:ee:ff keeps kernel-generated background
# traffic (which uses a different src_mac) from accidentally matching the
# ethertype filter.  Still exercises the D15 filter_mask path because the
# ethertype probe happens as a secondary constraint on the src_mac primary.
# ---------------------------------------------------------------------------

def test_f2_5_l2_ethertype_match():
    """F2.5: src_mac + ethertype=0x0800 hits only the IPv4-shaped frame."""
    config = _config([
        {
            "id": 1005,
            "src_mac": "aa:bb:cc:dd:ee:ff",
            "ethertype": 0x0800,
            "action": {"type": "drop"},
        }
    ])

    # Parenthesise the payload: `Ether()/b"\x00"*N` parses as a packet list
    # of length N due to scapy's `/` and `*` sharing precedence left-to-right.
    pkt_ipv4 = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66",
                     type=0x0800) / (b"\x00" * 20)
    pkt_ipv6 = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66",
                     type=0x86DD) / (b"\x00" * 40)
    pkt_arp = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66",
                    type=0x0806) / (b"\x00" * 28)

    with _F2Harness(config, "pktgate_f2_5") as h:
        h.inject([pkt_ipv4, pkt_ipv6, pkt_arp])

    assert h.returncode == 0
    stats = _parse_stats_on_exit(h.stdout_text)
    assert 1005 in stats, f"rule 1005 absent: {stats!r}"
    assert stats[1005]["matched_packets"] == 1, stats


# ---------------------------------------------------------------------------
# F2.6 — PCP match on VLAN-tagged frame
# ---------------------------------------------------------------------------

def test_f2_6_l2_pcp_match():
    """F2.6: vlan=100 + pcp=5 hits only the pcp=5 frame."""
    config = _config([
        {
            "id": 1006,
            "vlan_id": 100,
            "pcp": 5,
            "action": {"type": "drop"},
        }
    ])

    pkt_match = Ether(src="aa:bb:cc:dd:ee:ff",
                      dst="11:22:33:44:55:66") / Dot1Q(vlan=100, prio=5)
    pkt_miss = Ether(src="aa:bb:cc:dd:ee:ff",
                     dst="11:22:33:44:55:66") / Dot1Q(vlan=100, prio=0)

    with _F2Harness(config, "pktgate_f2_6") as h:
        h.inject([pkt_match, pkt_miss])

    assert h.returncode == 0
    stats = _parse_stats_on_exit(h.stdout_text)
    assert 1006 in stats, f"rule 1006 absent: {stats!r}"
    assert stats[1006]["matched_packets"] == 1, stats


# ---------------------------------------------------------------------------
# F2.7 — L2 compound: src_mac + vlan + ethertype (D15 filter_mask)
# ---------------------------------------------------------------------------

def test_f2_7_l2_compound_src_mac_vlan_ethertype():
    """F2.7: compound rule hits only when all three fields match."""
    config = _config([
        {
            "id": 1007,
            "src_mac": "aa:bb:cc:dd:ee:ff",
            "vlan_id": 100,
            "ethertype": 0x0800,
            "action": {"type": "drop"},
        }
    ])

    pkt_ok = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") /
        Dot1Q(vlan=100, type=0x0800) /
        (b"\x00" * 20)
    )
    pkt_wrong_vlan = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") /
        Dot1Q(vlan=200, type=0x0800) /
        (b"\x00" * 20)
    )
    pkt_no_vlan = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66",
              type=0x0800) /
        (b"\x00" * 20)
    )
    pkt_wrong_etype = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") /
        Dot1Q(vlan=100, type=0x86DD) /
        (b"\x00" * 40)
    )

    with _F2Harness(config, "pktgate_f2_7") as h:
        h.inject([pkt_ok, pkt_wrong_vlan, pkt_no_vlan, pkt_wrong_etype])

    assert h.returncode == 0
    stats = _parse_stats_on_exit(h.stdout_text)
    assert 1007 in stats, f"rule 1007 absent: {stats!r}"
    assert stats[1007]["matched_packets"] == 1, stats


# ---------------------------------------------------------------------------
# F2.8 — first-match-wins across two L2 rules
#
# Selectivity order in classify_l2 is src_mac > dst_mac.  R1 keys on src_mac
# and fires first; R2 keys on dst_mac and must never see the packet.
# ---------------------------------------------------------------------------

def test_f2_8_l2_first_match_wins():
    """F2.8: src_mac rule wins over dst_mac rule when both would match."""
    config = _config([
        {
            "id": 1008,
            "src_mac": "aa:bb:cc:dd:ee:ff",
            "action": {"type": "allow"},
        },
        {
            "id": 1009,
            "dst_mac": "11:22:33:44:55:66",
            "action": {"type": "drop"},
        },
    ])

    pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")

    with _F2Harness(config, "pktgate_f2_8") as h:
        h.inject([pkt])

    assert h.returncode == 0
    stats = _parse_stats_on_exit(h.stdout_text)
    assert stats.get(1008, {}).get("matched_packets", 0) == 1, stats
    assert stats.get(1009, {}).get("matched_packets", 0) == 0, stats
    assert stats.get(1008, {}).get("drops", 0) == 0, stats


# ---------------------------------------------------------------------------
# F2.9 — L2 miss → fall through to default_behavior (allow)
# ---------------------------------------------------------------------------

def test_f2_9_l2_miss_proceeds_to_l3():
    """F2.9: L2 miss with default_behavior=allow — rule counter stays 0."""
    config = _config(
        l2_rules=[
            {
                "id": 1010,
                "src_mac": "cc:dd:ee:ff:00:11",  # will not match our packet
                "action": {"type": "drop"},
            }
        ],
        default_behavior="allow",
    )

    pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")

    with _F2Harness(config, "pktgate_f2_9") as h:
        h.inject([pkt])

    assert h.returncode == 0
    stats = _parse_stats_on_exit(h.stdout_text)
    matched = stats.get(1010, {}).get("matched_packets", 0)
    assert matched == 0, (
        f"expected L2 miss on rule 1010; stats={stats!r}"
    )
