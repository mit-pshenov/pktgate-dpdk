# tests/functional/test_f14_tap_exit.py
#
# M14 C4 — F14.6 TAP visibility smoke + F14.7 slow-consumer drop counter
# scrape. Closes M14: D43 (exit port abstraction) on the actual TAP
# deployment profile.
#
# Boots pktgate with two `net_tap` vdevs declared via `interface_roles`
# (D43 sum-type — same selector vocabulary as F14.1..F14.5 but the
# resolver now points at real kernel taps, not net_null) and verifies:
#
#   F14.6 — packets injected on the ingress tap, after a configured L4
#     ALLOW (the only verb that round-trips traffic to egress; L2 ALLOW
#     short-circuits to NEXT_L3 with default_behavior=drop, so the
#     packet would be dropped — see grabli_l2_allow_fallthrough.md),
#     surface byte-recognisable on the egress tap. PMD-agnostic egress
#     wired through the C2 main.cpp resolver + C3 tx wrappers.
#
#   F14.7 — same boot config, throttle the egress kernel side with a
#     `tc tbf` qdisc to force the DPDK→kernel handover to either reject
#     bursts entirely or accept fewer than offered. Inject a burst,
#     scrape /metrics, assert that EITHER `pktgate_tx_dropped_total` OR
#     `pktgate_tx_burst_short_total` (whichever the TBF actually
#     triggers — depends on burst depth vs. token budget at the
#     instant DPDK presses a TX descriptor through) climbs above zero
#     for the egress port.
#
# NM unmanaged: extends the conftest dtap_* list with `dtap_m14_ing` /
# `dtap_m14_egr` (memory `grabli_nm_unmanaged_tap.md` — keyfile is the
# only race-free way to keep NM off; nmcli per-test races DHCP).
#
# F2.25 NDP guard: preemptive `sysctl net.ipv6.conf.<iface>.disable_ipv6=1`
# immediately after the tap appears, before the first inject. Kernel NDP
# packets on a freshly-up tap can leak NS frames the worker classifies
# (memory `grabli_f2_25_icmpv6_ndp_flake.md`).

import json
import os
import re
import select
import signal
import socket
import subprocess
import tempfile
import time

import pytest
from scapy.all import (
    AsyncSniffer, Ether, IP, UDP, Raw, conf as scapy_conf,
)

scapy_conf.verb = 0  # suppress scapy output

# Session-scoped NM-unmanaged fixture — conftest.py lists dtap_m14_*.
pytestmark = pytest.mark.usefixtures("nm_unmanaged_tap")


DPDK_DRIVER_DIR = os.environ.get(
    "DPDK_DRIVER_DIR", "/home/mit/Dev/dpdk-25.11/build/drivers/"
)

_INGRESS_IFACE = "dtap_m14_ing"
_EGRESS_IFACE = "dtap_m14_egr"

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
    # /metrics endpoint on an ephemeral port; F14.7 scrapes it.
    "prom_port": 0,
}

_TEST_SRC = "aa:bb:cc:dd:ee:14"
_TEST_DST = "11:22:33:44:55:14"


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


def _config(l4_rules=None, default_behavior: str = "drop") -> dict:
    return {
        "version": 1,
        "interface_roles": {
            "upstream_port":   {"vdev": "net_tap0"},
            "downstream_port": {"vdev": "net_tap1"},
        },
        "default_behavior": default_behavior,
        "pipeline": {
            "layer_2": [],
            "layer_3": [],
            "layer_4": l4_rules or [],
        },
        "sizing": _SIZING,
    }


def _extract_prom_port(stdout_lines):
    for line in stdout_lines:
        if '"event":"prom_endpoint_ready"' in line:
            try:
                obj = json.loads(line)
                return int(obj.get("port"))
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
    return None


def _resolved_egress_port(stdout_lines):
    """Parse the `port_resolved` events for downstream_port → port_id.
    M14 C2 main.cpp emits one such event per role at boot."""
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
    """Return the {name}{port="<port_id>"} value, or None if not found."""
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


# ---------------------------------------------------------------------------
# Harness — boot, drain ready, harden taps, expose stdout + prom port.
# ---------------------------------------------------------------------------

class _F14TapHarness:
    """Run pktgate with the two-tap config; harden taps for NDP/ARP/IPv6,
    sniff the egress tap with an AsyncSniffer keyed on _TEST_SRC."""

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
        self.prom_port = None
        self.egress_port_id = None

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

        deadline = time.monotonic() + 30.0  # tsan cold-start headroom
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

        for iface in (_INGRESS_IFACE, _EGRESS_IFACE):
            if not _tap_iface_up(iface):
                self._proc.terminate()
                raise RuntimeError(
                    f"Tap interface {iface} did not appear within 5s"
                )

        # F2.25-class NDP defence: kill v6 + ARP + flush addrs on both
        # taps the moment they appear, BEFORE the first inject. The
        # session-scoped NM keyfile already silences DHCP; this
        # additionally suppresses kernel-originated NDP / GARP that
        # would otherwise fire as the tap link comes up.
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

        # Pull the bound /metrics port out of the captured stdout.
        self.prom_port = _extract_prom_port(self._lines)
        # Pull the egress port_id from main.cpp's port_resolved event.
        self.egress_port_id = _resolved_egress_port(self._lines)
        if self.egress_port_id is None:
            # Conservative fallback: with `--vdev net_tap0 net_tap1` and
            # role declarations matching cmdline order, the resolver
            # lands downstream_port at port 1.
            self.egress_port_id = 1

        # Settle: drain any one-shot kernel bring-up traffic before
        # injected frames land.
        time.sleep(0.5)

        return self

    def sniff_start(self):
        """Begin capturing egress traffic with our anchored src_mac."""
        from scapy.all import conf as sc
        sc.ifaces.reload()

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
        time.sleep(0.3)  # let the AF_PACKET socket attach

    def inject(self, packets, pause: float = 0.05):
        """Send a packet list on the ingress tap with a small inter-packet
        pause so the kernel TAP can drain into DPDK's RX ring."""
        from scapy.all import sendp, conf as sc
        sc.ifaces.reload()
        for pkt in packets:
            sendp(pkt, iface=_INGRESS_IFACE, verbose=False)
            time.sleep(pause)

    def sniff_stop(self, settle: float = 1.5):
        time.sleep(settle)
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self.captured = list(self._sniffer.results or [])
            self._sniffer = None
        return self.captured

    def __exit__(self, exc_type, exc_val, exc_tb):
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

        time.sleep(0.2)  # let EAL release hugepage mappings
        return False  # do not suppress exceptions


def _has_test_frame(packets):
    """True iff any captured packet has _TEST_SRC."""
    for p in packets:
        try:
            if p.haslayer(Ether) and p[Ether].src == _TEST_SRC:
                return True
        except Exception:
            continue
    return False


# ---------------------------------------------------------------------------
# F14.6 — TAP visibility smoke.
# ---------------------------------------------------------------------------

def test_f14_6_tap_egress_visibility():
    """L4 ALLOW for UDP/5614 → packet injected on dtap_m14_ing emerges
    on dtap_m14_egr with the marker payload intact. End-to-end witness
    that D43's PMD-agnostic egress works on net_tap (the canonical
    *dev / test* deployment profile in D43)."""
    config = _config(
        l4_rules=[{
            "id": 14006,
            "proto": 17,        # UDP
            "dst_port": 5614,
            "action": {"type": "allow"},
        }],
        default_behavior="drop",
    )

    pkt = (
        Ether(src=_TEST_SRC, dst=_TEST_DST) /
        IP(src="192.168.14.6", dst="10.14.6.1") /
        UDP(sport=4242, dport=5614) /
        Raw(b"F14.6-TAP-VISIBILITY-MARKER-0123456789")
    )

    with _F14TapHarness(config, "pktgate_f14_6") as h:
        h.sniff_start()
        h.inject([pkt])
        captured = h.sniff_stop()

    assert h.returncode == 0, (
        f"binary exit={h.returncode} stdout={h.stdout_text!r}"
    )
    assert _has_test_frame(captured), (
        f"F14.6: ALLOW UDP/5614 must round-trip to dtap_m14_egr; "
        f"captured={[p.summary() for p in captured]!r} "
        f"stdout_tail={h.stdout_text[-2048:]!r}"
    )
    # Body marker check on the first matching frame — confirms it's
    # the packet we injected, not stray kernel chatter that happened
    # to share src_mac.
    first = next(p for p in captured if p[Ether].src == _TEST_SRC)
    assert first.haslayer(Raw), first.summary()
    assert b"F14.6-TAP-VISIBILITY-MARKER" in bytes(first[Raw].load), (
        f"F14.6: payload marker not in egress frame: "
        f"{bytes(first[Raw].load)!r}"
    )


# ---------------------------------------------------------------------------
# F14.7 — slow-consumer drop counter scrape.
# ---------------------------------------------------------------------------

def test_f14_7_slow_consumer_tx_drop_visible_on_metrics():
    """TBF qdisc on the egress tap throttles the kernel side; pushing
    a burst through DPDK's tx wrapper either fully rejects (sent==0 →
    pktgate_tx_dropped_total++) or partially accepts (0<sent<count →
    pktgate_tx_burst_short_total++). Either signal proves the C3
    backpressure family is live and labelled per-port."""
    config = _config(
        l4_rules=[{
            "id": 14007,
            "proto": 17,        # UDP
            "dst_port": 5615,
            "action": {"type": "allow"},
        }],
        default_behavior="drop",
    )

    qdisc_armed = False
    with _F14TapHarness(config, "pktgate_f14_7") as h:
        try:
            assert h.prom_port and h.prom_port > 0, (
                f"prom_endpoint_ready not observed; "
                f"stdout={h.stdout_text[-2048:]!r}"
            )

            # Throttle the egress tap kernel-side. TBF: 1 kbit/s avg,
            # 1 KB burst budget, 50 ms latency cap. Anything beyond
            # that gets dropped at the qdisc, which back-propagates as
            # rte_eth_tx_burst returning < nb_tx (or 0).
            tc_add = subprocess.run(
                ["tc", "qdisc", "add", "dev", _EGRESS_IFACE, "root",
                 "tbf", "rate", "1kbit", "burst", "1kb", "latency", "50ms"],
                capture_output=True, text=True,
            )
            if tc_add.returncode != 0:
                pytest.fail(
                    f"tc qdisc add failed (need root + iproute2): "
                    f"rc={tc_add.returncode} stderr={tc_add.stderr!r}"
                )
            qdisc_armed = True

            # Baseline scrape — both per-port counters should be 0
            # on a fresh boot before any traffic is injected.
            base_drop = _scrape_tx_counter(
                h.prom_port,
                "pktgate_tx_dropped_total",
                h.egress_port_id,
            )
            base_short = _scrape_tx_counter(
                h.prom_port,
                "pktgate_tx_burst_short_total",
                h.egress_port_id,
            )
            assert base_drop is not None, (
                f"baseline scrape: pktgate_tx_dropped_total{{port=\""
                f"{h.egress_port_id}\"}} not present in /metrics; "
                f"the C3 BodyFn loop is not emitting per-port labels."
            )
            assert base_short is not None, (
                f"baseline scrape: pktgate_tx_burst_short_total{{port=\""
                f"{h.egress_port_id}\"}} not present in /metrics."
            )

            # Inject a fat burst — well beyond the TBF budget. 200x 256-
            # byte UDP frames pushes ~50 KB into the tap; the 1 kbit/s
            # rate will starve out the consumer side fast.
            payload = b"X" * 224
            burst = []
            for i in range(200):
                p = (
                    Ether(src=_TEST_SRC, dst=_TEST_DST) /
                    IP(src="192.168.14.7", dst="10.14.7.1") /
                    UDP(sport=4242, dport=5615) /
                    Raw(payload)
                )
                burst.append(p)
            h.inject(burst, pause=0.0)

            # Wait for ≥ 1 publisher tick so the snapshot ring has a
            # post-burst entry. snapshot_publisher rate is ~Hz; 2 s
            # leaves comfortable headroom under dev-tsan cadence.
            time.sleep(2.5)

            final_drop = _scrape_tx_counter(
                h.prom_port,
                "pktgate_tx_dropped_total",
                h.egress_port_id,
            ) or 0
            final_short = _scrape_tx_counter(
                h.prom_port,
                "pktgate_tx_burst_short_total",
                h.egress_port_id,
            ) or 0

            drop_delta = final_drop - (base_drop or 0)
            short_delta = final_short - (base_short or 0)

            # The contract: SOMETHING climbed. Whether TBF kicks at the
            # full-reject end (drop++) or partial-accept end (short++)
            # depends on the precise instant DPDK presses TX vs. the
            # token bucket replenishment cycle — both are valid wins
            # for this test.
            assert (drop_delta > 0) or (short_delta > 0), (
                f"F14.7: TBF throttle did not surface on either tx "
                f"backpressure counter for port="
                f"{h.egress_port_id}. "
                f"baseline drop={base_drop} short={base_short}; "
                f"final drop={final_drop} short={final_short}. "
                f"Either the TBF qdisc is not engaged or the C3 "
                f"counters are not bumped on the live tx path."
            )
        finally:
            if qdisc_armed:
                subprocess.run(
                    ["tc", "qdisc", "del", "dev", _EGRESS_IFACE, "root"],
                    capture_output=True,
                )

    assert h.returncode == 0, (
        f"binary exit={h.returncode} stdout_tail={h.stdout_text[-2048:]!r}"
    )
