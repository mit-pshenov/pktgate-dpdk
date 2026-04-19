# tests/functional/test_f4_l3.py
#
# M5 C10 — F4.1-F4.10: Fragment handling end-to-end through the live binary.
#
# Injection path: net_tap vdevs (dtap_f4_rx / dtap_f4_tx). The harness
# writes Ethernet frames via scapy sendp() to the kernel tap, then
# SIGTERMs the binary and inspects the "stats_on_exit" JSON log line for
# per-lcore counters.
#
# Observable contract (M5 scope):
#   - stats_on_exit counters: pkt_frag_{dropped,skipped}_total_{v4,v6},
#     l4_skipped_ipv6_extheader, l4_skipped_ipv6_fragment_nonfirst,
#     pkt_truncated_l3_{v4,v6,v6_frag_ext}.
#   - Per-rule L3 counters are NOT yet observable (no L3 counter infra).
#   - ALL classify_l3 verdicts (kNextL4, kTerminalPass, kTerminalDrop)
#     currently free the mbuf (no TX path). Tests assert on stats_on_exit
#     counters + clean exit.
#
# Memory requirement: FIB DIR24_8 needs ~128 MB heap (grabli). Tests
# that populate L3 rules use --no-huge -m 512.
#
# Covers: F4.1-F4.10, D17 fragment_policy, D27 IPv6 frag, D40 counters,
#         D41 (pipeline smoke through classify_l3).

import json
import os
import select
import signal
import subprocess
import tempfile
import time

import pytest
from scapy.all import (
    Ether, IP, IPv6, IPv6ExtHdrFragment, IPv6ExtHdrRouting,
    TCP, UDP, Raw, conf as scapy_conf,
)

scapy_conf.verb = 0  # suppress scapy output

# Session-scoped NM-unmanaged fixture — conftest.py lists dtap_f4_* names.
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

_INGRESS_IFACE = "dtap_f4_rx"
_EGRESS_IFACE = "dtap_f4_tx"

# FIB needs ~128 MB heap → -m 512 for headroom under sanitizers.
_EAL_ARGS_TEMPLATE = [
    "--no-pci",
    "--no-huge",
    "-m", "512",
    *_DPDK_DRIVER_DIR_ARGS,
    "--vdev", f"net_tap0,iface={_INGRESS_IFACE}",
    "--vdev", f"net_tap1,iface={_EGRESS_IFACE}",
    "-l", "0,1",
    "--log-level", "lib.*:error",
]

# Sizing must have ipv4/ipv6_prefixes_max >= 1 for FIB population.
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


def _get_counters(stdout: str) -> dict:
    """Extract the counters dict from stats_on_exit, or {} if absent."""
    stats = _parse_stats_on_exit(stdout)
    return stats.get("counters", {})


class _F4Harness:
    """Context manager: start pktgate with a config, wait for ready, inject
    packets, SIGTERM, and make `stdout_text` available."""

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


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _config_l3(l3_rules: list, fragment_policy: str = "l3_only",
               default_behavior: str = "drop",
               objects_subnets: dict = None) -> dict:
    """Build a full config dict with L3 rules and optional fragment_policy."""
    cfg = {
        "version": 1,
        "interface_roles": {
            "upstream_port":   {"vdev": "net_tap0"},
            "downstream_port": {"vdev": "net_tap1"},
        },
        "default_behavior": default_behavior,
        "fragment_policy": fragment_policy,
        "pipeline": {
            "layer_2": [],
            "layer_3": l3_rules,
            "layer_4": [],
        },
        "sizing": _SIZING,
    }
    if objects_subnets:
        cfg["objects"] = {"subnets": objects_subnets}
    return cfg


# Reusable subnet objects for L3 rules.
_SUBNETS_V4 = {"net_drop": ["10.0.0.0/8"]}
_SUBNETS_V6 = {"v6_drop": ["2001:db8::/32"]}
_SUBNETS_BOTH = {**_SUBNETS_V4, **_SUBNETS_V6}

# Anchored src_mac for test packets to avoid kernel background traffic.
_TEST_SRC = "aa:bb:cc:dd:ee:f4"
_TEST_DST = "11:22:33:44:55:66"


# ---------------------------------------------------------------------------
# F4.1 — IPv4 first fragment, fragment_policy=l3_only, L3 rule exists
# ---------------------------------------------------------------------------

def test_f4_1_ipv4_first_frag_l3_only():
    """F4.1: first IPv4 fragment under l3_only. The first fragment carries
    the L4 header and is not frag-dropped/skipped. L3 rule matching is
    not directly observable (no per-rule L3 counters yet). Assert clean
    exit + fragment counters stay 0 + truncation stays 0."""
    config = _config_l3(
        l3_rules=[{
            "id": 2001,
            "dst_subnet": "net_drop",
            "action": {"type": "drop"},
        }],
        objects_subnets=_SUBNETS_V4,
    )

    # First fragment: MF=1, offset=0, dst in 10.0.0.0/8.
    pkt = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.5", flags="MF", frag=0) /
        TCP(sport=12345, dport=80) /
        Raw(b"\x00" * 20)
    )

    with _F4Harness(config, "pktgate_f4_1") as h:
        h.inject([pkt])

    assert h.returncode == 0, f"exit={h.returncode} stdout={h.stdout_text!r}"
    ctrs = _get_counters(h.stdout_text)
    # First fragment under l3_only is NOT frag-dropped or frag-skipped.
    assert ctrs.get("pkt_frag_dropped_total_v4", 0) == 0, ctrs
    assert ctrs.get("pkt_frag_skipped_total_v4", 0) == 0, ctrs
    assert ctrs.get("pkt_truncated_l3_v4", 0) == 0, ctrs


# ---------------------------------------------------------------------------
# F4.2 — IPv4 first fragment + L4 rule (adapted: no classify_l4 yet)
# ---------------------------------------------------------------------------

def test_f4_2_ipv4_first_frag_l4_deferred():
    """F4.2: first IPv4 fragment reaching kNextL4. classify_l4 does not
    exist yet (M6). Assert clean exit + no frag counters bump.
    L4 rule assertion is M6 scope."""
    config = _config_l3(
        l3_rules=[],
        objects_subnets=None,
    )

    # First fragment: MF=1, offset=0, dst NOT in any L3 rule → L3 miss → kNextL4.
    pkt = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="172.16.0.1", flags="MF", frag=0) /
        TCP(sport=12345, dport=80) /
        Raw(b"\x00" * 20)
    )

    with _F4Harness(config, "pktgate_f4_2") as h:
        h.inject([pkt])

    assert h.returncode == 0, f"exit={h.returncode} stdout={h.stdout_text!r}"
    ctrs = _get_counters(h.stdout_text)
    assert ctrs.get("pkt_frag_dropped_total_v4", 0) == 0, ctrs
    assert ctrs.get("pkt_frag_skipped_total_v4", 0) == 0, ctrs


# ---------------------------------------------------------------------------
# F4.3 — IPv4 non-first fragment, l3_only, L3 rule exists
# ---------------------------------------------------------------------------

def test_f4_3_ipv4_nonfirst_frag_l3_only_rule():
    """F4.3: non-first IPv4 fragment under l3_only. L3 rule exists but
    per-rule counter not observable. pkt_frag_skipped_total_v4 += 1
    (non-first under l3_only sets SKIP_L4 and bumps the skip counter)."""
    config = _config_l3(
        l3_rules=[{
            "id": 2003,
            "dst_subnet": "net_drop",
            "action": {"type": "drop"},
        }],
        objects_subnets=_SUBNETS_V4,
    )

    # Non-first fragment: offset=185 (non-zero), MF=0.
    pkt = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.5", frag=185) /
        Raw(b"\x00" * 20)
    )

    with _F4Harness(config, "pktgate_f4_3") as h:
        h.inject([pkt])

    assert h.returncode == 0, f"exit={h.returncode} stdout={h.stdout_text!r}"
    ctrs = _get_counters(h.stdout_text)
    assert ctrs.get("pkt_frag_skipped_total_v4", 0) >= 1, (
        f"expected pkt_frag_skipped_total_v4 >= 1; ctrs={ctrs!r}"
    )
    assert ctrs.get("pkt_frag_dropped_total_v4", 0) == 0, ctrs
    assert ctrs.get("pkt_truncated_l3_v4", 0) == 0, ctrs


# ---------------------------------------------------------------------------
# F4.4 — IPv4 non-first fragment, l3_only, L3 miss → default
# ---------------------------------------------------------------------------

def test_f4_4_ipv4_nonfirst_frag_l3_only_miss():
    """F4.4: non-first fragment, L3 miss. Under l3_only the SKIP_L4 path
    collapses kNextL4 to kTerminalPass (packet freed). No default_action
    counter exists yet. Assert pkt_frag_skipped_total_v4 += 1 + clean exit."""
    config = _config_l3(
        l3_rules=[],  # no L3 rules → guaranteed miss
        default_behavior="drop",
        objects_subnets=None,
    )

    # Non-first fragment: offset=100 (non-zero).
    pkt = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="172.16.0.1", frag=100) /
        Raw(b"\x00" * 20)
    )

    with _F4Harness(config, "pktgate_f4_4") as h:
        h.inject([pkt])

    assert h.returncode == 0, f"exit={h.returncode} stdout={h.stdout_text!r}"
    ctrs = _get_counters(h.stdout_text)
    assert ctrs.get("pkt_frag_skipped_total_v4", 0) >= 1, (
        f"expected pkt_frag_skipped_total_v4 >= 1; ctrs={ctrs!r}"
    )


# ---------------------------------------------------------------------------
# F4.5 — IPv4 non-first fragment, fragment_policy=drop
# ---------------------------------------------------------------------------

def test_f4_5_ipv4_nonfirst_frag_drop():
    """F4.5: any fragment under drop policy → pkt_frag_dropped_total_v4 += 1."""
    config = _config_l3(
        l3_rules=[],
        fragment_policy="drop",
        objects_subnets=None,
    )

    pkt = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="172.16.0.1", frag=50) /
        Raw(b"\x00" * 20)
    )

    with _F4Harness(config, "pktgate_f4_5") as h:
        h.inject([pkt])

    assert h.returncode == 0, f"exit={h.returncode} stdout={h.stdout_text!r}"
    ctrs = _get_counters(h.stdout_text)
    assert ctrs.get("pkt_frag_dropped_total_v4", 0) >= 1, (
        f"expected pkt_frag_dropped_total_v4 >= 1; ctrs={ctrs!r}"
    )
    assert ctrs.get("pkt_frag_skipped_total_v4", 0) == 0, ctrs


# ---------------------------------------------------------------------------
# F4.6 — IPv4 non-first fragment, fragment_policy=allow
# ---------------------------------------------------------------------------

def test_f4_6_ipv4_nonfirst_frag_allow():
    """F4.6: fragment under allow policy → FRAG_ALLOW is silent (no frag
    counter bumps). Assert all frag counters = 0."""
    config = _config_l3(
        l3_rules=[],
        fragment_policy="allow",
        objects_subnets=None,
    )

    pkt = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="172.16.0.1", frag=50) /
        Raw(b"\x00" * 20)
    )

    with _F4Harness(config, "pktgate_f4_6") as h:
        h.inject([pkt])

    assert h.returncode == 0, f"exit={h.returncode} stdout={h.stdout_text!r}"
    ctrs = _get_counters(h.stdout_text)
    assert ctrs.get("pkt_frag_dropped_total_v4", 0) == 0, ctrs
    assert ctrs.get("pkt_frag_skipped_total_v4", 0) == 0, ctrs


# ---------------------------------------------------------------------------
# F4.7 — IPv6 first fragment (Fragment ext, frag_offset=0), L4 deferred
# ---------------------------------------------------------------------------

def test_f4_7_ipv6_first_frag():
    """F4.7: IPv6 first fragment (offset=0, MF=1). No classify_l4 yet (M6).
    l4_skipped counters must stay 0 because first fragment is not skipped.
    l4_extra=8 is written but not observable in stats_on_exit."""
    config = _config_l3(
        l3_rules=[],
        objects_subnets=None,
    )

    # IPv6 first fragment: offset=0, M=1 (more fragments).
    # frag_data in scapy IPv6ExtHdrFragment: offset in bytes, m=1.
    pkt = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IPv6(src="2001:db8::1", dst="2001:db8::2") /
        IPv6ExtHdrFragment(offset=0, m=1, id=0xDEAD, nh=6) /
        TCP(sport=12345, dport=443) /
        Raw(b"\x00" * 20)
    )

    with _F4Harness(config, "pktgate_f4_7") as h:
        h.inject([pkt])

    assert h.returncode == 0, f"exit={h.returncode} stdout={h.stdout_text!r}"
    ctrs = _get_counters(h.stdout_text)
    # First fragment is not skipped.
    assert ctrs.get("l4_skipped_ipv6_fragment_nonfirst", 0) == 0, ctrs
    assert ctrs.get("pkt_frag_dropped_total_v6", 0) == 0, ctrs
    assert ctrs.get("pkt_frag_skipped_total_v6", 0) == 0, ctrs
    assert ctrs.get("pkt_truncated_l3_v6", 0) == 0, ctrs
    assert ctrs.get("pkt_truncated_l3_v6_frag_ext", 0) == 0, ctrs


# ---------------------------------------------------------------------------
# F4.8 — IPv6 non-first fragment
# ---------------------------------------------------------------------------

def test_f4_8_ipv6_nonfirst_frag():
    """F4.8: IPv6 non-first fragment (frag_offset != 0).
    l4_skipped_ipv6_fragment_nonfirst += 1 AND pkt_frag_skipped_total_v6 += 1
    (D40 alias invariant)."""
    config = _config_l3(
        l3_rules=[],
        objects_subnets=None,
    )

    # Non-first fragment: offset=185 (in 8-byte units), M=0.
    pkt = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IPv6(src="2001:db8::1", dst="2001:db8::2") /
        IPv6ExtHdrFragment(offset=185, m=0, id=0xBEEF, nh=6) /
        Raw(b"\x00" * 20)
    )

    with _F4Harness(config, "pktgate_f4_8") as h:
        h.inject([pkt])

    assert h.returncode == 0, f"exit={h.returncode} stdout={h.stdout_text!r}"
    ctrs = _get_counters(h.stdout_text)
    assert ctrs.get("l4_skipped_ipv6_fragment_nonfirst", 0) >= 1, (
        f"expected l4_skipped_ipv6_fragment_nonfirst >= 1; ctrs={ctrs!r}"
    )
    assert ctrs.get("pkt_frag_skipped_total_v6", 0) >= 1, (
        f"expected pkt_frag_skipped_total_v6 >= 1; ctrs={ctrs!r}"
    )
    assert ctrs.get("pkt_frag_dropped_total_v6", 0) == 0, ctrs


# ---------------------------------------------------------------------------
# F4.9 — IPv6 Fragment-ext followed by another ext header
# ---------------------------------------------------------------------------

def test_f4_9_ipv6_frag_chain_after_fragment():
    """F4.9: IPv6 first fragment whose inner next_header is Routing (43)
    — an extension header. Under first-protocol-only + D27
    chain-after-fragment, this sets SKIP_L4 and bumps
    l4_skipped_ipv6_extheader."""
    config = _config_l3(
        l3_rules=[],
        objects_subnets=None,
    )

    # First fragment with inner next_header = 43 (Routing).
    # Scapy: IPv6ExtHdrFragment(nh=43, offset=0, m=1) then some payload.
    pkt = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IPv6(src="2001:db8::1", dst="2001:db8::2") /
        IPv6ExtHdrFragment(offset=0, m=1, id=0xCAFE, nh=43) /
        Raw(b"\x00" * 40)
    )

    with _F4Harness(config, "pktgate_f4_9") as h:
        h.inject([pkt])

    assert h.returncode == 0, f"exit={h.returncode} stdout={h.stdout_text!r}"
    ctrs = _get_counters(h.stdout_text)
    assert ctrs.get("l4_skipped_ipv6_extheader", 0) >= 1, (
        f"expected l4_skipped_ipv6_extheader >= 1; ctrs={ctrs!r}"
    )


# ---------------------------------------------------------------------------
# F4.10 — fragment_policy schema: invalid value rejected
# ---------------------------------------------------------------------------

def test_f4_10_invalid_fragment_policy_rejected():
    """F4.10: config with fragment_policy='yolo' must be rejected at parse
    time. Binary exits non-zero. No stats_on_exit needed."""
    config = {
        "version": 1,
        "interface_roles": {
            "upstream_port":   {"vdev": "net_tap0"},
            "downstream_port": {"vdev": "net_tap1"},
        },
        "default_behavior": "drop",
        "fragment_policy": "yolo",
        "pipeline": {
            "layer_2": [],
            "layer_3": [],
            "layer_4": [],
        },
        "sizing": _SIZING,
    }

    tmpf = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(config, tmpf)
    tmpf.close()

    binary = _find_binary()
    file_prefix = f"pktgate_f4_10_{time.monotonic_ns() % 10**9:09d}"
    eal_args = _EAL_ARGS_TEMPLATE + ["--file-prefix", file_prefix]
    cmd = [binary] + eal_args + ["--config", tmpf.name]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=15,
        )
        stdout = proc.stdout.decode(errors="replace") if isinstance(proc.stdout, bytes) else proc.stdout
        assert proc.returncode != 0, (
            f"Expected non-zero exit for invalid fragment_policy; "
            f"exit={proc.returncode} stdout={stdout!r}"
        )
    finally:
        os.unlink(tmpf.name)
        time.sleep(0.2)
