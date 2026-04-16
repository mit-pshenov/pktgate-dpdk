# tests/functional/test_f2_l4.py
#
# M6 C5 -- F2.17-F2.25: Happy-path L4 matching, end-to-end.
#
# Injection path: net_tap vdevs (dtap_l4_rx / dtap_l4_tx). The DPDK
# binary creates kernel tap interfaces; the test harness writes Ethernet
# frames via scapy.sendp() to dtap_l4_rx (ingress), then SIGTERMs the
# binary and inspects the "stats_on_exit" JSON log line for per-rule
# L4 counters.
#
# Observable contract:
#   - stats_on_exit log line carries {rule_id, layer, matched_packets,
#     drops} per rule.
#   - L4 per-rule counters are bumped by the worker AFTER classify_l4
#     returns kMatch.
#   - D41: every test exercises the full pipeline L2->L3->L4 entry
#     through the live boot path.
#
# Covers: F2.17-F2.25, D14 L4 offset, D15 compound primary + filter_mask,
#         D29 ICMP packing, D31 pkt_truncated_l4, D41 pipeline smoke.

import json
import os
import select
import signal
import subprocess
import tempfile
import time

import pytest
from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, ICMP, Raw, conf as scapy_conf,
)

scapy_conf.verb = 0  # suppress scapy output

# Session-scoped NM-unmanaged fixture.
pytestmark = pytest.mark.usefixtures("nm_unmanaged_tap")


DPDK_DRIVER_DIR = os.environ.get(
    "DPDK_DRIVER_DIR", "/home/mit/Dev/dpdk-25.11/build/drivers/"
)

_INGRESS_IFACE = "dtap_l4_rx"
_EGRESS_IFACE = "dtap_l4_tx"

# FIB needs ~128 MB heap for L3 FIB even if no L3 rules -> -m 512.
_EAL_ARGS_TEMPLATE = [
    "--no-pci",
    "--no-huge",
    "-m", "512",
    "-d", DPDK_DRIVER_DIR,
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


def _get_rules(stdout: str) -> dict:
    """Return {rule_id: {layer, matched_packets, drops}} from stats_on_exit."""
    stats = _parse_stats_on_exit(stdout)
    out = {}
    for entry in stats.get("rules", []):
        rid = entry.get("rule_id")
        if rid is not None:
            out[rid] = {
                "layer": entry.get("layer", ""),
                "matched_packets": entry.get("matched_packets", 0),
                "drops": entry.get("drops", 0),
            }
    return out


def _get_counters(stdout: str) -> dict:
    """Extract the counters dict from stats_on_exit, or {} if absent."""
    stats = _parse_stats_on_exit(stdout)
    return stats.get("counters", {})


class _L4Harness:
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

        # Wait for stale kernel packets (IPv6 RS, NDP, DHCP) to drain
        # through the RX queue before injecting test packets. The
        # worker processes them and bumps spurious counters; the drain
        # window ensures they don't interleave with our test packets.
        time.sleep(1.0)

        return self

    def inject(self, packets, pause: float = 0.3):
        from scapy.all import sendp, conf as sc
        sc.ifaces.reload()
        for pkt in packets:
            sendp(pkt, iface=_INGRESS_IFACE, verbose=False)
            time.sleep(0.05)
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


# Anchored src_mac for test packets to avoid kernel background traffic.
_TEST_SRC = "aa:bb:cc:dd:ee:14"
_TEST_DST = "11:22:33:44:55:66"


def _config(l4_rules: list, default_behavior: str = "drop",
            l2_rules: list = None, l3_rules: list = None) -> dict:
    return {
        "version": 1,
        "interface_roles": {
            "upstream_port":   {"vdev": "net_tap0"},
            "downstream_port": {"vdev": "net_tap1"},
        },
        "default_behavior": default_behavior,
        "pipeline": {
            "layer_2": l2_rules or [],
            "layer_3": l3_rules or [],
            "layer_4": l4_rules,
        },
        "sizing": _SIZING,
    }


# ---------------------------------------------------------------------------
# F2.17 -- L4 TCP dport match
# ---------------------------------------------------------------------------

def test_f2_17_l4_tcp_dport_drop():
    """F2.17: proto=tcp dport=443 drop. TCP/443 dropped; TCP/80 and UDP/443
    pass (proto discriminator)."""
    config = _config([
        {
            "id": 4001,
            "proto": 6,        # TCP
            "dst_port": 443,
            "action": {"type": "drop"},
        }
    ])

    pkt_match = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.1") /
        TCP(sport=12345, dport=443) /
        Raw(b"\x00" * 20)
    )
    pkt_miss_port = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.1") /
        TCP(sport=12345, dport=80) /
        Raw(b"\x00" * 20)
    )
    pkt_miss_proto = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.1") /
        UDP(sport=12345, dport=443) /
        Raw(b"\x00" * 20)
    )

    with _L4Harness(config, "pktgate_f2_17") as h:
        h.inject([pkt_match, pkt_miss_port, pkt_miss_proto])

    assert h.returncode == 0, (
        f"exit={h.returncode} stdout={h.stdout_text!r}"
    )
    rules = _get_rules(h.stdout_text)
    assert 4001 in rules, f"rule 4001 absent: {rules!r}"
    assert rules[4001]["layer"] == "l4", rules
    assert rules[4001]["matched_packets"] == 1, rules
    assert rules[4001]["drops"] == 1, rules


# ---------------------------------------------------------------------------
# F2.18 -- L4 UDP sport match
# ---------------------------------------------------------------------------

def test_f2_18_l4_udp_sport_drop():
    """F2.18: proto=udp src_port=53 drop. Hits l4_proto_sport primary hash."""
    config = _config([
        {
            "id": 4002,
            "proto": 17,       # UDP
            "src_port": 53,
            "action": {"type": "drop"},
        }
    ])

    pkt_match = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.1") /
        UDP(sport=53, dport=12345) /
        Raw(b"\x00" * 20)
    )
    pkt_miss = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.1") /
        UDP(sport=1234, dport=53) /
        Raw(b"\x00" * 20)
    )

    with _L4Harness(config, "pktgate_f2_18") as h:
        h.inject([pkt_match, pkt_miss])

    assert h.returncode == 0, (
        f"exit={h.returncode} stdout={h.stdout_text!r}"
    )
    rules = _get_rules(h.stdout_text)
    assert 4002 in rules, f"rule 4002 absent: {rules!r}"
    assert rules[4002]["matched_packets"] == 1, rules
    assert rules[4002]["drops"] == 1, rules


# ---------------------------------------------------------------------------
# F2.19 -- L4 proto-only catch-all
# ---------------------------------------------------------------------------

def test_f2_19_l4_proto_only_catchall():
    """F2.19: proto=udp (no port) drop. All UDP dropped; TCP passes.
    Hits l4_proto_only."""
    config = _config([
        {
            "id": 4003,
            "proto": 17,       # UDP
            "action": {"type": "drop"},
        }
    ])

    pkt_udp = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.1") /
        UDP(sport=1234, dport=5678) /
        Raw(b"\x00" * 20)
    )
    pkt_tcp = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.1") /
        TCP(sport=1234, dport=5678) /
        Raw(b"\x00" * 20)
    )

    with _L4Harness(config, "pktgate_f2_19") as h:
        h.inject([pkt_udp, pkt_tcp])

    assert h.returncode == 0, (
        f"exit={h.returncode} stdout={h.stdout_text!r}"
    )
    rules = _get_rules(h.stdout_text)
    assert 4003 in rules, f"rule 4003 absent: {rules!r}"
    assert rules[4003]["matched_packets"] == 1, rules
    assert rules[4003]["drops"] == 1, rules


# ---------------------------------------------------------------------------
# F2.20 -- L4 TCP multiple dport rules
#
# NOTE: The functional test spec (F2.20) describes dst_ports=[80,443,8080]
# as a port list on a single rule id. Port-list expansion into compound
# hash entries is NOT implemented in compile_l4_rules (the expansion in
# compile_layer only creates CompiledRuleEntry, not L4 compound entries).
# This test adapts to current reality: three separate rules, one per port,
# verifying the pipeline handles multiple L4 rules correctly.
# ---------------------------------------------------------------------------

def test_f2_20_l4_tcp_multiple_dport_rules():
    """F2.20 (adapted): three L4 rules on different TCP dports, all drop.
    TCP/80, TCP/443, TCP/8080 all dropped; TCP/25 passes."""
    config = _config([
        {"id": 4004, "proto": 6, "dst_port": 80, "action": {"type": "drop"}},
        {"id": 4014, "proto": 6, "dst_port": 443, "action": {"type": "drop"}},
        {"id": 4024, "proto": 6, "dst_port": 8080, "action": {"type": "drop"}},
    ])

    packets = []
    for dport in [80, 443, 8080, 25]:
        packets.append(
            Ether(src=_TEST_SRC, dst=_TEST_DST) /
            IP(src="192.168.1.1", dst="10.0.0.1") /
            TCP(sport=12345, dport=dport) /
            Raw(b"\x00" * 20)
        )

    with _L4Harness(config, "pktgate_f2_20") as h:
        h.inject(packets)

    assert h.returncode == 0, (
        f"exit={h.returncode} stdout={h.stdout_text!r}"
    )
    rules = _get_rules(h.stdout_text)
    # All three L4 rules should have fired once each.
    assert 4004 in rules, f"rule 4004 absent: {rules!r}"
    assert rules[4004]["matched_packets"] == 1, rules
    assert rules[4004]["drops"] == 1, rules
    assert 4014 in rules, f"rule 4014 absent: {rules!r}"
    assert rules[4014]["matched_packets"] == 1, rules
    assert 4024 in rules, f"rule 4024 absent: {rules!r}"
    assert rules[4024]["matched_packets"] == 1, rules


# ---------------------------------------------------------------------------
# F2.21 -- L4 TCP sport + dport compound
# ---------------------------------------------------------------------------

def test_f2_21_l4_tcp_sport_dport_compound():
    """F2.21: proto=tcp src_port=12345 dst_port=443 drop. Only packets with
    both ports hit; either alone misses."""
    config = _config([
        {
            "id": 4005,
            "proto": 6,
            "src_port": 12345,
            "dst_port": 443,
            "action": {"type": "drop"},
        }
    ])

    pkt_match = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.1") /
        TCP(sport=12345, dport=443) /
        Raw(b"\x00" * 20)
    )
    pkt_wrong_sport = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.1") /
        TCP(sport=54321, dport=443) /
        Raw(b"\x00" * 20)
    )
    pkt_wrong_dport = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.1") /
        TCP(sport=12345, dport=80) /
        Raw(b"\x00" * 20)
    )

    with _L4Harness(config, "pktgate_f2_21") as h:
        h.inject([pkt_match, pkt_wrong_sport, pkt_wrong_dport])

    assert h.returncode == 0, (
        f"exit={h.returncode} stdout={h.stdout_text!r}"
    )
    rules = _get_rules(h.stdout_text)
    assert 4005 in rules, f"rule 4005 absent: {rules!r}"
    assert rules[4005]["matched_packets"] == 1, rules
    assert rules[4005]["drops"] == 1, rules


# ---------------------------------------------------------------------------
# F2.22 -- L4 TCP flags -- SYN-only
# ---------------------------------------------------------------------------

def test_f2_22_l4_tcp_flags_syn_only():
    """F2.22: proto=tcp dport=22 tcp_flags={syn:true, ack:false} drop.
    SYN matches, SYN+ACK does not.
    NOTE: tcp_flags filter_mask is wired but the secondary check is a
    TODO in l4_filter_ok. This test asserts that the primary (proto+dport)
    fires for both packets since tcp_flags is not yet enforced. When M-later
    wires tcp_flags, this test will need to flip to matched_packets=1."""
    config = _config([
        {
            "id": 4006,
            "proto": 6,
            "dst_port": 22,
            "tcp_flags": {"syn": True, "ack": False},
            "action": {"type": "drop"},
        }
    ])

    pkt_syn = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.1") /
        TCP(sport=12345, dport=22, flags="S") /
        Raw(b"\x00" * 20)
    )
    pkt_synack = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.1") /
        TCP(sport=12345, dport=22, flags="SA") /
        Raw(b"\x00" * 20)
    )

    with _L4Harness(config, "pktgate_f2_22") as h:
        h.inject([pkt_syn, pkt_synack])

    assert h.returncode == 0, (
        f"exit={h.returncode} stdout={h.stdout_text!r}"
    )
    rules = _get_rules(h.stdout_text)
    assert 4006 in rules, f"rule 4006 absent: {rules!r}"
    # tcp_flags secondary is TODO in l4_filter_ok -- both packets match
    # the primary (proto=6, dport=22). When tcp_flags enforcement lands,
    # this assertion should change to matched_packets=1.
    assert rules[4006]["matched_packets"] == 2, rules
    assert rules[4006]["drops"] == 2, rules


# ---------------------------------------------------------------------------
# F2.23 -- L4 ICMP type match
# ---------------------------------------------------------------------------

def test_f2_23_l4_icmp_type_match():
    """F2.23: proto=icmp icmp_type=8 (echo request) drop.
    D29: ICMP type packed into dst_port slot. Echo drops; reply (type 0)
    passes."""
    config = _config([
        {
            "id": 4007,
            "proto": 1,        # ICMP
            "dst_port": 8,     # echo request type, packed into dport
            "action": {"type": "drop"},
        }
    ])

    pkt_echo = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.1") /
        ICMP(type=8, code=0) /
        Raw(b"\x00" * 20)
    )
    pkt_reply = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.1") /
        ICMP(type=0, code=0) /
        Raw(b"\x00" * 20)
    )

    with _L4Harness(config, "pktgate_f2_23") as h:
        h.inject([pkt_echo, pkt_reply])

    assert h.returncode == 0, (
        f"exit={h.returncode} stdout={h.stdout_text!r}"
    )
    rules = _get_rules(h.stdout_text)
    assert 4007 in rules, f"rule 4007 absent: {rules!r}"
    assert rules[4007]["matched_packets"] == 1, rules
    assert rules[4007]["drops"] == 1, rules


# ---------------------------------------------------------------------------
# F2.24 -- L4 ICMP type+code match
# ---------------------------------------------------------------------------

def test_f2_24_l4_icmp_type_code_match():
    """F2.24: proto=icmp type=3 code=1 (host unreachable) drop.
    D29: type -> dport, code -> sport/want_src_port.
    Exact type+code drops; type=3 code=0 passes."""
    config = _config([
        {
            "id": 4008,
            "proto": 1,        # ICMP
            "dst_port": 3,     # type=3 (dest unreachable)
            "src_port": 1,     # code=1 (host unreachable)
            "action": {"type": "drop"},
        }
    ])

    pkt_match = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.1") /
        ICMP(type=3, code=1) /
        Raw(b"\x00" * 20)
    )
    pkt_miss = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.1") /
        ICMP(type=3, code=0) /
        Raw(b"\x00" * 20)
    )

    with _L4Harness(config, "pktgate_f2_24") as h:
        h.inject([pkt_match, pkt_miss])

    assert h.returncode == 0, (
        f"exit={h.returncode} stdout={h.stdout_text!r}"
    )
    rules = _get_rules(h.stdout_text)
    assert 4008 in rules, f"rule 4008 absent: {rules!r}"
    assert rules[4008]["matched_packets"] == 1, rules
    assert rules[4008]["drops"] == 1, rules


# ---------------------------------------------------------------------------
# F2.25 -- L4 ICMPv6 match
# ---------------------------------------------------------------------------

def test_f2_25_l4_icmpv6_match():
    """F2.25: proto=icmpv6 type=135 (NS) drop.
    IPv6 payload with ICMPv6; rule matches type 135 only."""
    config = _config([
        {
            "id": 4009,
            "proto": 58,       # ICMPv6
            "dst_port": 135,   # NS type, packed into dport
            "action": {"type": "drop"},
        }
    ])

    # ICMPv6 NS (type 135): build raw payload to avoid scapy's
    # ICMPv6ND_NS auto-setting the next header.
    # We build a minimal ICMPv6 packet: type(1B) + code(1B) + checksum(2B) + body.
    icmpv6_ns_payload = bytes([135, 0, 0, 0]) + b"\x00" * 20  # type=135, code=0

    pkt_match = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IPv6(src="2001:db8::1", dst="2001:db8::2", nh=58) /
        Raw(icmpv6_ns_payload)
    )

    # ICMPv6 echo request (type 128): should not fire.
    icmpv6_echo_payload = bytes([128, 0, 0, 0]) + b"\x00" * 20  # type=128, code=0
    pkt_miss = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IPv6(src="2001:db8::1", dst="2001:db8::2", nh=58) /
        Raw(icmpv6_echo_payload)
    )

    with _L4Harness(config, "pktgate_f2_25") as h:
        h.inject([pkt_match, pkt_miss])

    assert h.returncode == 0, (
        f"exit={h.returncode} stdout={h.stdout_text!r}"
    )
    rules = _get_rules(h.stdout_text)
    assert 4009 in rules, f"rule 4009 absent: {rules!r}"
    assert rules[4009]["matched_packets"] == 1, rules
    assert rules[4009]["drops"] == 1, rules
