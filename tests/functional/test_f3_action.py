# tests/functional/test_f3_action.py
#
# M7 C3 — F3.1-F3.7: ALLOW / DROP / TAG action verbs end-to-end.
#
# First functional tests that inspect egress *packet contents* (not just
# counters): a scapy AsyncSniffer runs on the egress tap in parallel with
# sendp() on the ingress tap, captures whatever DPDK TX'd, and the test
# asserts on DSCP / TC / PCP bytes directly.
#
# Observable contract:
#   - ALLOW rule → packet appears on dtap_f3_tx with body intact.
#   - DROP rule → sniff times out (packet absent).
#   - TAG rule (DSCP / PCP) → egress packet carries the rewritten bits.
#   - stats_on_exit surfaces `tag_pcp_noop_untagged_total` (D19) +
#     `redirect_dropped_total` (D16) + `dispatch_unreachable_total`
#     (D25 runtime backstop — stays 0).
#
# F3.3 IPv4 cksum caveat: apply_dscp_pcp rewrites the ToS byte, zeroes
# the IP header checksum, and sets RTE_MBUF_F_TX_IP_CKSUM +
# RTE_MBUF_F_TX_IPV4. The dev-VM DPDK net_tap PMD does NOT advertise HW
# ip-cksum offload, so the egress packet's hdr_checksum is left at zero.
# This test accepts (a) valid recomputed cksum, (b) cksum=0 (the
# offload-flag-was-set-but-no-HW case), or (c) any cksum value — we
# assert the DSCP bits, not the cksum validity. The compiler-level
# rejection F3.8 (no-HW-ip-cksum port) is deferred to the M13 lab plan.
#
# Covers: F3.1-F3.7, D16 REDIRECT counter (surfaced, not exercised here —
# C4 scope), D19 TAG semantics, D25 dispatch_unreachable backstop, D33
# counter consistency.

import json
import os
import select
import signal
import subprocess
import tempfile
import time

import pytest
from scapy.all import (
    AsyncSniffer, Ether, Dot1Q, IP, IPv6, TCP, UDP, Raw, conf as scapy_conf,
)

scapy_conf.verb = 0  # suppress scapy output

# Session-scoped NM-unmanaged fixture — conftest.py lists dtap_f3_* names.
pytestmark = pytest.mark.usefixtures("nm_unmanaged_tap")


DPDK_DRIVER_DIR = os.environ.get(
    "DPDK_DRIVER_DIR", "/home/mit/Dev/dpdk-25.11/build/drivers/"
)

_INGRESS_IFACE = "dtap_f3_rx"
_EGRESS_IFACE = "dtap_f3_tx"

# FIB / ruleset init needs ~128 MB heap even without L3 rules → -m 512.
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

# Anchored src_mac so kernel background traffic on the tap cannot match
# any of our L2 rules by accident.
_TEST_SRC = "aa:bb:cc:dd:ee:f3"
_TEST_DST = "11:22:33:44:55:66"


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
    return _parse_stats_on_exit(stdout).get("counters", {})


class _F3Harness:
    """Start pktgate_dpdk, wait for ready, run an egress AsyncSniffer in
    parallel with scapy.sendp() on the ingress tap.  Expose the captured
    egress packets via `h.captured` and the stats_on_exit JSON via
    `h.stdout_text` after __exit__."""

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
        self.captured: list = []
        self._sniffer = None

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

        if not _tap_iface_up(_INGRESS_IFACE) or not _tap_iface_up(_EGRESS_IFACE):
            self._proc.terminate()
            raise RuntimeError(
                f"Tap interfaces did not appear within 5s"
            )

        # Defence-in-depth against kernel control traffic on both taps.
        for iface in (_INGRESS_IFACE, _EGRESS_IFACE):
            subprocess.run(
                ["sysctl", "-qw",
                 f"net.ipv6.conf.{iface}.disable_ipv6=1"],
                capture_output=True,
            )
            subprocess.run(
                ["ip", "addr", "flush", "dev", iface],
                capture_output=True,
            )
            subprocess.run(
                ["ip", "link", "set", iface, "arp", "off"],
                capture_output=True,
            )

        # Let the kernel one-shot bring-up traffic drain before our
        # injected frames land.
        time.sleep(1.0)

        return self

    def inject_and_sniff(self, packets, sniff_timeout: float = 1.5):
        """Start the egress sniffer, send `packets` on the ingress tap,
        then stop the sniffer after `sniff_timeout`. Populates
        `self.captured` with the list of rte_eth_tx_burst'd packets that
        landed on dtap_f3_tx."""
        from scapy.all import sendp, conf as sc
        sc.ifaces.reload()

        # Filter: only frames with our anchored src_mac. The kernel tap
        # will also see any control frames the kernel itself posts
        # (ICMPv6 RS, DAD) — anchoring on our test src_mac filters them
        # out deterministically even though we already disabled ipv6/arp.
        def _lfilter(p):
            try:
                return p.haslayer(Ether) and p[Ether].src == _TEST_SRC
            except Exception:
                return False

        self._sniffer = AsyncSniffer(
            iface=_EGRESS_IFACE,
            store=True,
            lfilter=_lfilter,
        )
        self._sniffer.start()
        # Give the sniffer a moment to attach to the AF_PACKET socket.
        time.sleep(0.3)

        for pkt in packets:
            sendp(pkt, iface=_INGRESS_IFACE, verbose=False)
            time.sleep(0.05)

        # Wait for the worker's TX to land on the egress tap.
        time.sleep(sniff_timeout)

        self._sniffer.stop()
        captured = list(self._sniffer.results or [])
        self.captured = captured
        return captured

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Defensive: stop any still-running sniffer.
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass

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

def _config(l2_rules=None, l3_rules=None, l4_rules=None,
            default_behavior: str = "drop",
            objects_subnets: dict = None) -> dict:
    cfg = {
        "version": 1,
        "interface_roles": {
            "upstream_port":   {"vdev": "net_tap0"},
            "downstream_port": {"vdev": "net_tap1"},
        },
        "default_behavior": default_behavior,
        "pipeline": {
            "layer_2": l2_rules or [],
            "layer_3": l3_rules or [],
            "layer_4": l4_rules or [],
        },
        "sizing": _SIZING,
    }
    if objects_subnets:
        cfg["objects"] = {"subnets": objects_subnets}
    return cfg


def _has_frame_for(packets, src_mac=_TEST_SRC):
    """Return True iff any captured packet has src_mac."""
    for p in packets:
        try:
            if p.haslayer(Ether) and p[Ether].src == src_mac:
                return True
        except Exception:
            continue
    return False


# ---------------------------------------------------------------------------
# F3.1 — ALLOW action forwards packet
# ---------------------------------------------------------------------------
#
# Layer choice: L4 (not L2).  classify_l2 returns kNextL3 for both
# ALLOW-rule-match and empty-ruleset-miss — that is, an L2 ALLOW rule
# does NOT short-circuit to a terminal ALLOW disposition; the packet
# falls through to L3/L4/default.  With default_behavior=drop that
# path ends in Disposition::kTerminalDrop (mbuf freed) and the ALLOW
# rule is observationally a no-op.  To actually exercise the
# apply_action ALLOW → tx_burst_fn path we need a layer whose classify
# returns kMatch on ALLOW.  Only classify_l4 does that today (see
# classify_l4.h ClassifyL4Verdict::kMatch).  So F3.1 pins the ALLOW
# rule to L4, symmetric with F3.3-F3.7 TAG tests.

def test_f3_1_allow_forwards():
    """F3.1: L4 ALLOW rule → packet appears on egress tap byte-identical
    to input.  D25 backstop stays 0."""
    config = _config(
        l4_rules=[{
            "id": 3001,
            "proto": 17,        # UDP
            "dst_port": 5678,
            "action": {"type": "allow"},
        }],
        default_behavior="drop",
    )

    pkt = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.1") /
        UDP(sport=1234, dport=5678) /
        Raw(b"F3.1-ALLOW-PAYLOAD-0123456789")
    )

    with _F3Harness(config, "pktgate_f3_1") as h:
        captured = h.inject_and_sniff([pkt])

    assert h.returncode == 0, (
        f"exit={h.returncode} stdout={h.stdout_text!r}"
    )
    assert _has_frame_for(captured), (
        f"ALLOW rule: expected a matching frame on egress tap; "
        f"captured={[p.summary() for p in captured]!r}"
    )
    # Body round-trip check on the first matching frame.
    first = next(p for p in captured if p[Ether].src == _TEST_SRC)
    assert first.haslayer(UDP), first.summary()
    assert bytes(first[Raw].load).startswith(b"F3.1-ALLOW-PAYLOAD"), (
        first[Raw].load
    )
    ctrs = _get_counters(h.stdout_text)
    assert ctrs.get("dispatch_unreachable_total", -1) == 0, ctrs


# ---------------------------------------------------------------------------
# F3.2 — DROP action removes packet
# ---------------------------------------------------------------------------

def test_f3_2_drop_removes():
    """F3.2: DROP rule — sniff times out, no matching frame on egress.
    D25 backstop stays 0."""
    config = _config(
        l2_rules=[{
            "id": 3002,
            "src_mac": _TEST_SRC,
            "action": {"type": "drop"},
        }],
        default_behavior="allow",  # miss path would ALLOW — isolates the DROP
    )

    pkt = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.1") /
        UDP(sport=1234, dport=5678) /
        Raw(b"F3.2-DROP")
    )

    with _F3Harness(config, "pktgate_f3_2") as h:
        captured = h.inject_and_sniff([pkt])

    assert h.returncode == 0, (
        f"exit={h.returncode} stdout={h.stdout_text!r}"
    )
    assert not _has_frame_for(captured), (
        f"DROP rule: expected NO matching frame on egress tap; "
        f"captured={[p.summary() for p in captured]!r}"
    )
    ctrs = _get_counters(h.stdout_text)
    assert ctrs.get("dispatch_unreachable_total", -1) == 0, ctrs


# ---------------------------------------------------------------------------
# TAG-test layer choice note (M7 C3):
#
# The worker calls `apply_action(ctx, rs, m, kMatch, action)` only for
# L4 matches — that's the single site where `apply_dscp_pcp` actually
# fires and rewrites header bytes. L2/L3 TAG rules record the match
# slot in dyn->verdict_action_idx but fall through (classify_l2 returns
# kNextL3 for TAG, classify_l3 returns kNextL4), so the TAG verb never
# gets dispatched through apply_action. This is a known C0-era design
# choice (handoff §M7-specific guidance option c); extending per-layer
# TAG dispatch is a Phase-2 follow-up.
#
# F3.3-F3.7 therefore exercise TAG via L4 compound rules (proto + dport
# primary, which reliably hits kMatch and runs the full verb switch in
# apply_action). The test spec (functional.md §F3) says "TAG rule"
# without mandating a layer — L4 is the cleanest surface that exercises
# the D19 apply_dscp_pcp body end-to-end today.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# F3.3 — TAG DSCP rewrite on IPv4
# ---------------------------------------------------------------------------

def test_f3_3_tag_dscp_ipv4():
    """F3.3: TAG dscp=46 (EF) on IPv4 → egress ToS top-6-bits == 46.

    cksum caveat: dev-VM net_tap does NOT advertise HW ip-cksum, so the
    header checksum will be left at 0 (apply_dscp_pcp zeros it + sets
    RTE_MBUF_F_TX_IP_CKSUM, but the PMD has no HW to honour that flag).
    We assert ONLY the DSCP bits. Valid vs zero vs stale cksum is all
    accepted here; the compiler-time reject for non-HW-cksum ports is
    F3.8 and lives in the M13 lab plan.

    Rule fires at L4 (proto=udp dport=5678). See layer-choice note above.
    """
    config = _config(
        l4_rules=[{
            "id": 3003,
            "proto": 17,        # UDP
            "dst_port": 5678,
            "action": {"type": "tag", "dscp": 46},
        }],
        default_behavior="drop",
    )

    pkt = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.1", tos=0) /
        UDP(sport=1234, dport=5678) /
        Raw(b"F3.3-TAG-DSCP")
    )

    with _F3Harness(config, "pktgate_f3_3") as h:
        captured = h.inject_and_sniff([pkt])

    assert h.returncode == 0
    assert _has_frame_for(captured), (
        f"TAG rule: expected the packet on egress tap; "
        f"captured={[p.summary() for p in captured]!r}"
    )
    # Inspect the ToS byte on the raw bytes — scapy's IP parser may or
    # may not have the DSCP field exposed consistently across versions.
    first = next(p for p in captured if p[Ether].src == _TEST_SRC)
    raw = bytes(first)
    # Ether header = 14 B; IP ToS byte is at offset 15 (ver+ihl at 14).
    tos = raw[15]
    dscp_bits = (tos >> 2) & 0x3F
    assert dscp_bits == 46, (
        f"expected DSCP=46, got DSCP={dscp_bits} (ToS=0x{tos:02x})"
    )
    ctrs = _get_counters(h.stdout_text)
    assert ctrs.get("dispatch_unreachable_total", -1) == 0, ctrs
    assert ctrs.get("tag_pcp_noop_untagged_total", -1) == 0, ctrs


# ---------------------------------------------------------------------------
# F3.4 — TAG DSCP rewrite on IPv6 (Traffic Class)
# ---------------------------------------------------------------------------

def test_f3_4_tag_tc_ipv6():
    """F3.4: TAG dscp=46 on IPv6 → TC field top-6-bits == 46.

    Rule fires at L4 (proto=udp dport=5678). See layer-choice note above.
    """
    config = _config(
        l4_rules=[{
            "id": 3004,
            "proto": 17,        # UDP
            "dst_port": 5678,
            "action": {"type": "tag", "dscp": 46},
        }],
        default_behavior="drop",
    )

    pkt = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IPv6(src="2001:db8::1", dst="2001:db8::2", tc=0) /
        UDP(sport=1234, dport=5678) /
        Raw(b"F3.4-TAG-TC")
    )

    with _F3Harness(config, "pktgate_f3_4") as h:
        captured = h.inject_and_sniff([pkt])

    assert h.returncode == 0
    assert _has_frame_for(captured)
    first = next(p for p in captured if p[Ether].src == _TEST_SRC)
    raw = bytes(first)
    # Ether = 14 B; IPv6 version_tc_flow = bytes 14..17.
    #   byte 14 = version(4 high) | TC(4 high)
    #   byte 15 = TC(4 low)       | FL(4 high)
    tc_byte = ((raw[14] & 0x0F) << 4) | ((raw[15] & 0xF0) >> 4)
    dscp_bits = (tc_byte >> 2) & 0x3F
    assert dscp_bits == 46, (
        f"expected DSCP=46 in IPv6 TC, got {dscp_bits} "
        f"(TC=0x{tc_byte:02x}, b14=0x{raw[14]:02x}, b15=0x{raw[15]:02x})"
    )


# ---------------------------------------------------------------------------
# F3.5 — TAG PCP rewrite on VLAN-tagged frame
# ---------------------------------------------------------------------------

def test_f3_5_tag_pcp_tagged():
    """F3.5: TAG pcp=5 on a VLAN-tagged frame → TCI bits [15:13] == 5.

    Rule fires at L4 (proto=udp dport=5678). See layer-choice note above.
    """
    config = _config(
        l4_rules=[{
            "id": 3005,
            "proto": 17,
            "dst_port": 5678,
            "action": {"type": "tag", "pcp": 5},
        }],
        default_behavior="drop",
    )

    pkt = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        Dot1Q(vlan=100, prio=0) /
        IP(src="192.168.1.1", dst="10.0.0.1") /
        UDP(sport=1234, dport=5678) /
        Raw(b"F3.5-TAG-PCP")
    )

    with _F3Harness(config, "pktgate_f3_5") as h:
        captured = h.inject_and_sniff([pkt])

    assert h.returncode == 0
    assert _has_frame_for(captured)
    first = next(p for p in captured if p[Ether].src == _TEST_SRC)
    raw = bytes(first)
    # Ether = 14 B; Dot1Q TPID at 12-13, TCI at 14-15. PCP = bits [15:13]
    # = top 3 bits of byte 14.
    tpid = (raw[12] << 8) | raw[13]
    assert tpid == 0x8100, f"expected TPID 0x8100, got 0x{tpid:04x}"
    pcp_bits = (raw[14] >> 5) & 0x07
    assert pcp_bits == 5, (
        f"expected PCP=5, got PCP={pcp_bits} (TCI byte 14=0x{raw[14]:02x})"
    )
    ctrs = _get_counters(h.stdout_text)
    # Tagged PCP path — noop counter must stay 0.
    assert ctrs.get("tag_pcp_noop_untagged_total", -1) == 0, ctrs


# ---------------------------------------------------------------------------
# F3.6 — TAG PCP on untagged frame → counted no-op
# ---------------------------------------------------------------------------

def test_f3_6_tag_pcp_untagged_noop():
    """F3.6: TAG pcp=5 on an untagged frame → egress frame still untagged,
    tag_pcp_noop_untagged_total == 1 (D19: do NOT insert a VLAN tag on
    the operator's behalf).

    Rule fires at L4 (proto=udp dport=5678). See layer-choice note above.
    """
    config = _config(
        l4_rules=[{
            "id": 3006,
            "proto": 17,
            "dst_port": 5678,
            "action": {"type": "tag", "pcp": 5},
        }],
        default_behavior="drop",
    )

    pkt = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.1.1", dst="10.0.0.1") /
        UDP(sport=1234, dport=5678) /
        Raw(b"F3.6-PCP-UNTAGGED")
    )
    pkt_bytes = bytes(pkt)

    with _F3Harness(config, "pktgate_f3_6") as h:
        captured = h.inject_and_sniff([pkt])

    assert h.returncode == 0
    assert _has_frame_for(captured), (
        "PCP-on-untagged should still forward the packet unmodified"
    )
    first = next(p for p in captured if p[Ether].src == _TEST_SRC)
    raw = bytes(first)
    # Outer ethertype at bytes 12-13: MUST be the original IP ethertype,
    # NOT a freshly-inserted 0x8100 VLAN TPID.
    outer_etype = (raw[12] << 8) | raw[13]
    assert outer_etype == 0x0800, (
        f"PCP-on-untagged must NOT insert a VLAN tag; "
        f"outer ethertype=0x{outer_etype:04x}"
    )
    # Byte-identical body check on the first 34 bytes (Ether 14 + IPv4 20).
    # We don't compare *all* bytes because the kernel tap may trim /
    # pad; the first bytes through the IP header are stable.
    min_len = min(len(raw), len(pkt_bytes), 34)
    assert raw[:min_len] == pkt_bytes[:min_len], (
        "untagged+PCP rewrite should be a no-op on the leading bytes"
    )
    ctrs = _get_counters(h.stdout_text)
    assert ctrs.get("tag_pcp_noop_untagged_total", -1) == 1, ctrs
    assert ctrs.get("dispatch_unreachable_total", -1) == 0, ctrs


# ---------------------------------------------------------------------------
# F3.7 — TAG combined DSCP + PCP on tagged IPv4
# ---------------------------------------------------------------------------

def test_f3_7_tag_combined_dscp_pcp():
    """F3.7: TAG dscp=46 pcp=5 on a VLAN-tagged IPv4 frame → both fields
    rewritten.

    Rule fires at L4 (proto=udp dport=5678). See layer-choice note above.
    """
    config = _config(
        l4_rules=[{
            "id": 3007,
            "proto": 17,
            "dst_port": 5678,
            "action": {"type": "tag", "dscp": 46, "pcp": 5},
        }],
        default_behavior="drop",
    )

    pkt = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        Dot1Q(vlan=100, prio=0) /
        IP(src="192.168.1.1", dst="10.0.0.1", tos=0) /
        UDP(sport=1234, dport=5678) /
        Raw(b"F3.7-BOTH")
    )

    with _F3Harness(config, "pktgate_f3_7") as h:
        captured = h.inject_and_sniff([pkt])

    assert h.returncode == 0
    assert _has_frame_for(captured)
    first = next(p for p in captured if p[Ether].src == _TEST_SRC)
    raw = bytes(first)

    # TCI at bytes 14-15; PCP = top 3 bits of byte 14.
    pcp_bits = (raw[14] >> 5) & 0x07
    assert pcp_bits == 5, (
        f"expected PCP=5, got {pcp_bits} (TCI byte 14=0x{raw[14]:02x})"
    )

    # IPv4 starts at 18 (Ether 14 + Dot1Q 4). ToS at offset 19.
    tos = raw[19]
    dscp_bits = (tos >> 2) & 0x3F
    assert dscp_bits == 46, (
        f"expected DSCP=46, got {dscp_bits} (ToS=0x{tos:02x})"
    )

    ctrs = _get_counters(h.stdout_text)
    assert ctrs.get("dispatch_unreachable_total", -1) == 0, ctrs
    assert ctrs.get("tag_pcp_noop_untagged_total", -1) == 0, ctrs
