# tests/chaos/test_m16_mirror_slow_consumer.py
#
# M16 C5 — chaos scenario 3: mirror destination kernel-side slow consumer.
#
# Distinct-from-port_gone semantic:
#   * C4 scenario 1 (`test_m16_mirror_port_gone.py`) takes the mirror
#     tap's link DOWN mid-burst. tun_net_xmit outright refuses frames;
#     `rte_eth_tx_burst` short-bursts and `mirror_dropped_per_port[]`
#     climbs from the break onward.
#   * C5 (this file) keeps the link UP but constricts the tun-side
#     queue at kernel ingress so the kernel consumer drains *slowly
#     relative to the inject rate*. Sustained inject produces a
#     *partial* short-burst pattern — some clones drain each tick,
#     some get counted as dropped — and then a mid-stream RELEASE of
#     the clamp lets drain resume, restoring `mirror_sent_per_port[]`
#     bumps. Recovery semantic (the "slow consumer catches up") is
#     not exercised by port_gone.
#
# Mechanism attempt matrix (M16 C5 RED discovery, 2026-04-20):
#   A. `ip link set dev <mirror> txqueuelen 1` (link stays UP)
#        -- Tried first on dev VM (dev-debug, default 8191 mbuf pool,
#           2000 packets / 200 pps / release at 600 pkts).
#           OBSERVED: `mirror_dropped_delta_during_clamp = 0`,
#           `mirror_sent` climbed to 592/600 at the release point.
#           Kernel drained the tun queue fast enough that
#           rte_eth_tx_burst never short-bursted. txqueuelen=1 alone
#           with link UP does NOT create backpressure on DPDK's
#           writev path under a 200 pps inject rate — the tun queue
#           stays at or near empty between kernel dispatch ticks.
#           REJECTED: insufficient backpressure signal.
#   B. `tc qdisc add dev <mirror> root netem delay 100ms limit 1`
#        -- per memory `grabli_tap_tbf_wrong_side.md`, tc qdiscs on
#           the tap's egress side do NOT back-propagate to
#           rte_eth_tx_burst (net_tap writes via /dev/net/tun
#           userspace→kernel; tc egress is on the kernel→wire side).
#           Not evaluated empirically; grabli explicitly lists this
#           as a non-starter for DPDK net_tap backpressure.
#           REJECTED: wrong side of /dev/net/tun.
#   C. `ip link set dev <mirror> down` from boot + txqueuelen=1,
#       release mid-stream via `ip link up` + txqueuelen=1000.
#        -- per memory `grabli_tap_tbf_wrong_side.md`: "ip link set
#           <tap> txqueuelen 1 + ip link set <tap> down" is the
#           canonical recipe for forcing `tap_write_mbufs` to return
#           -1 and DPDK `rte_eth_tx_burst` to report sent<nb_pkts.
#           This scenario DIFFERS from C4 port_gone in the direction
#           of the transition: port_gone goes UP → DOWN mid-stream
#           (catastrophic failure onset), while slow-consumer starts
#           with link DOWN (mirror consumer starved from the first
#           clone) and transitions DOWN → UP mid-stream (recovery).
#           The unique observable is `mirror_sent_total` resuming
#           its climb AFTER the release — a signal the port_gone
#           scenario cannot produce because it never restores the
#           tap.
#        -- SELECTED as the C5 RED mechanism.
#
# Chosen: mechanism C (link-down + txqueuelen=1 from boot; mid-stream
# release via link-up + txqueuelen=1000). This is the DOWN → UP
# (recovery) direction, contrasted with port_gone's UP → DOWN
# (failure onset) direction. Same underlying /dev/net/tun recipe per
# grabli, opposite transition direction, novel recovery assertion on
# post-release `mirror_sent_total` bumps.
#
# Empirical observation (dev-debug, 2026-04-20) at release point
# (i=600, ~13 s into 10 s stream after sanitiser pacing slip):
#   * `mirror_dropped_delta_during_clamp` = 592 (every staged clone
#     short-bursted at `rte_eth_tx_burst` against the downed link).
#   * `at_release_mirror_sent` = 592 (per stage_mirror semantics
#     `sent++` happens on successful STAGING into mirror_tx[port],
#     before drain — so a clamped drain still increments sent;
#     dropped also bumps on drain-short, per-port identity
#     `sent >= actually_transmitted`).
#   * `at_release_rx` = 593 (clean attribution — RX path saw all
#     injected packets; slow-consumer is attributed to the mirror
#     TX path, not to ingress starvation).
#   * Test FAILED on the threshold-impossible `> 10**9` as designed.
# The GREEN cycle will:
#   1. Flip the two RED threshold constants to measured lower bounds
#      (e.g. `_MIRROR_DROPPED_DELTA_LOWER_BOUND = 100` with 3x
#      sanitiser margin; `_MIRROR_SENT_AFTER_RELEASE_LOWER_BOUND`
#      measured post-release; probably floor at 100).
#   2. Run the full 5-preset matrix to seed the floor per preset
#      if sanitiser presets shift the drain cadence enough.
#
# RED/GREEN strategy:
#   * RED commit: headline assertions are threshold-impossible so
#     the commit fails on any real run:
#         `_MIRROR_DROPPED_DELTA_THRESHOLD_RED = 10**9`
#           real run bumps by tens/hundreds — impossible;
#         `_MIRROR_SENT_AFTER_RELEASE_LOWER_BOUND_RED = 0` used as
#         strict upper bound (`< 1`) — real run bumps by at least
#         some packets after release.
#   * GREEN commit (next cycle): flip to measured realistic bounds.
#     Functional invariants (tx stability, pid alive, attribution
#     probe, clone_failed==0) stay as-is through both phases; they
#     are correctness gates on the chaos mechanism itself, not RED
#     markers.
#
# Attribution sanity probe (FUNCTIONAL, non-optional per handoff
# anti-pattern alert):
#   `pktgate_port_rx_packets_total{port=<ingress>}` must climb at
#   ≥ 80% of inject_count. Otherwise the RX path starved before the
#   mirror drain path saw backpressure — test would be measuring
#   ingress starvation, not slow-consumer clamp.

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
    Ether, IP, UDP, Raw, conf as scapy_conf, sendp,
)

scapy_conf.verb = 0  # suppress scapy output

# Session-scoped NM-unmanaged fixture — conftest.py lists dtap_m16s_*.
pytestmark = pytest.mark.usefixtures("nm_unmanaged_tap")


# EAL `-d <path>` opt-in (memory grabli_eal_d_flag_env_opt_in.md).
_DPDK_DRIVER_DIR_ARGS = (
    ["-d", os.environ["PKTGATE_DPDK_DRIVER_DIR"].strip()]
    if os.environ.get("PKTGATE_DPDK_DRIVER_DIR", "").strip()
    else []
)

# IFNAMSIZ 16-char budget (memory grabli_ifnamsiz_16_limit.md). All three
# dtap names ≤15 chars. Separate namespace from M16 C3 / C4 fixtures so
# tests co-exist in a shared session.
_INGRESS_IFACE = "dtap_m16s_ing"    # 13 chars
_EGRESS_IFACE = "dtap_m16s_egr"     # 13 chars
_MIRROR_IFACE = "dtap_m16s_mir"     # 13 chars

# FIB DIR24_8 needs ~128 MB heap even without L3 rules → -m 512
# (memory grabli_rte_fib_dir24_8_heap_footprint.md).
_EAL_ARGS_TEMPLATE = [
    "--no-pci",
    "--no-huge",
    "-m", "512",
    *_DPDK_DRIVER_DIR_ARGS,
    "--vdev", f"net_tap0,iface={_INGRESS_IFACE}",
    "--vdev", f"net_tap1,iface={_EGRESS_IFACE}",
    "--vdev", f"net_tap2,iface={_MIRROR_IFACE}",
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
    # /metrics endpoint on an ephemeral port.
    "prom_port": 0,
}

_TEST_SRC = "aa:bb:cc:dd:ee:c5"
_TEST_DST = "11:22:33:44:55:c5"

# Inject 2000 packets at ~200 pps → ~10 seconds of wall clock. Mirror
# tap is clamped at txqueuelen=1 from boot until _RELEASE_AFTER_PKTS;
# thereafter restored to default (1000). A high sustained rate keeps
# the drain starved throughout the clamped window; the release is
# well-separated from the boot so the post-release assertion has a
# clear time window to observe.
_INJECT_COUNT = 2000
_INJECT_INTER_S = 0.005  # 200 Hz pacing (actual cadence will slip
                         # under sanitiser load; tests tolerate that).
_RELEASE_AFTER_PKTS = 600  # ~3 s into a 10 s stream, pre-mid window
                           # so the post-release observation has ≥5 s
                           # to let sent bumps stack up.

# RED phase: threshold-impossible on both headline observables.
# GREEN cycle flips these to measured-realistic values.
_MIRROR_DROPPED_DELTA_THRESHOLD_RED = 10**9
_MIRROR_SENT_AFTER_RELEASE_UPPER_BOUND_RED = 0  # strict-less-than 1

# Attribution-probe threshold: the RX path must sustain at least 80%
# of the inject rate across the entire test. If RX rate drops below
# this we are measuring the wrong failure mode (ingress starvation,
# not mirror slow-consumer backpressure) and the test must fail loudly.
_RX_ATTRIBUTION_FRACTION = 0.80


# ---------------------------------------------------------------------------
# Helpers — shape shared with test_m16_mirror_port_gone.py /
# test_m16_mirror_mempool_exhaust.py.
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


def _config() -> dict:
    """Three-role config: ingress RX + egress TX + mirror destination.

    One L4 ALLOW rule with `action: mirror`: the original forwards to
    downstream_port, the clone lands on mirror_port. Default-drop so
    unrelated frames (if any slip past NDP/ARP guards) do not contaminate
    forwarding counters.
    """
    return {
        "version": 1,
        "interface_roles": {
            "upstream_port":   {"vdev": "net_tap0"},
            "downstream_port": {"vdev": "net_tap1"},
            "mirror_port":     {"vdev": "net_tap2"},
        },
        "default_behavior": "drop",
        "pipeline": {
            "layer_2": [],
            "layer_3": [],
            "layer_4": [
                {
                    "id": 16006,
                    "proto": 17,        # UDP
                    "dst_port": 5616,
                    "action": {
                        "type": "mirror",
                        "target_port": "mirror_port",
                    },
                },
            ],
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


def _resolved_port_id(stdout_lines, role: str):
    for line in stdout_lines:
        if '"event":"port_resolved"' not in line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("role") == role:
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


def _scrape_port_counter(prom_port, metric_name, port_id):
    """Return `{metric_name}{port="<port_id>"}` value or None."""
    status, body = _http_get(prom_port, "/metrics")
    if status != 200:
        return None
    text = body.decode("utf-8", errors="replace")
    pat = re.compile(
        r'^' + re.escape(metric_name)
        + r'\{port="' + str(port_id) + r'"\}\s+(\d+)',
        re.MULTILINE,
    )
    m = pat.search(text)
    if m:
        return int(m.group(1))
    return None


def _pid_alive(pid: int) -> bool:
    """True if process <pid> is alive and signalable."""
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Harness — three-TAP boot, NDP preempt, slow-consumer clamp mgmt.
# ---------------------------------------------------------------------------

class _SlowConsumerHarness:
    """Boot pktgate with three net_tap vdevs; harden taps against NDP/
    ARP/IPv6 noise; clamp mirror tap's kernel queue to 1 slot at boot;
    expose ingress / egress / mirror port_ids + prom port.

    The txqueuelen clamp is intentionally applied AFTER the taps appear
    so the boot path uses the default queue and the backpressure only
    kicks in once the test starts injecting.
    """

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
        self.prom_port = None
        self.ingress_port_id = None
        self.egress_port_id = None
        self.mirror_port_id = None
        self.pid = None

    def __enter__(self):
        for iface in (_INGRESS_IFACE, _EGRESS_IFACE, _MIRROR_IFACE):
            _delete_stale_tap(iface)

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
        self.pid = self._proc.pid

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

        for iface in (_INGRESS_IFACE, _EGRESS_IFACE, _MIRROR_IFACE):
            if not _tap_iface_up(iface):
                self._proc.terminate()
                raise RuntimeError(
                    f"Tap interface {iface} did not appear within 5s"
                )

        # F2.25 NDP preempt — disable v6 + ARP + flush addrs on all three
        # taps before the first inject. The session-scoped NM keyfile
        # silences DHCP; this hardens against kernel-originated NDP/GARP
        # that would otherwise hit the RX path and bump classifier counters.
        for iface in (_INGRESS_IFACE, _EGRESS_IFACE, _MIRROR_IFACE):
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

        # Slow-consumer clamp: mirror tap's kernel drain path is both
        # constricted (txqueuelen=1) AND stalled (link DOWN) from
        # boot onward. Per memory grabli_tap_tbf_wrong_side.md this
        # is the canonical recipe for forcing `tap_write_mbufs` to
        # return -1 and DPDK `rte_eth_tx_burst` to short-burst on
        # the mirror port.
        #
        # Distinction from C4 port_gone: here the clamp is active
        # from the FIRST injected packet and transitions DOWN → UP
        # mid-stream (recovery direction). Port_gone goes the other
        # way (UP → DOWN during the burst). The unique semantic is
        # the post-release `mirror_sent_total` climb — the drain
        # path recovering on its own once the consumer wakes up.
        subprocess.run(
            ["ip", "link", "set", "dev", _MIRROR_IFACE,
             "txqueuelen", "1"],
            capture_output=True,
        )
        down_res = subprocess.run(
            ["ip", "link", "set", "dev", _MIRROR_IFACE, "down"],
            capture_output=True, text=True,
        )
        if down_res.returncode != 0:
            # If we can't clamp the mirror tap we can't test slow
            # consumer — bail out of the harness cleanly.
            self._proc.terminate()
            raise RuntimeError(
                f"ip link set {_MIRROR_IFACE} down failed: "
                f"rc={down_res.returncode} "
                f"stderr={down_res.stderr!r}"
            )

        self.prom_port = _extract_prom_port(self._lines)
        self.ingress_port_id = _resolved_port_id(
            self._lines, "upstream_port",
        )
        if self.ingress_port_id is None:
            self.ingress_port_id = 0
        self.egress_port_id = _resolved_port_id(
            self._lines, "downstream_port",
        )
        if self.egress_port_id is None:
            self.egress_port_id = 1
        self.mirror_port_id = _resolved_port_id(
            self._lines, "mirror_port",
        )
        if self.mirror_port_id is None:
            self.mirror_port_id = 2

        time.sleep(0.5)  # let kernel bring-up chatter drain
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore mirror tap state on the way out so subsequent tests
        # in a shared session don't inherit the clamped / downed state.
        subprocess.run(
            ["ip", "link", "set", "dev", _MIRROR_IFACE, "up"],
            capture_output=True,
        )
        subprocess.run(
            ["ip", "link", "set", "dev", _MIRROR_IFACE,
             "txqueuelen", "1000"],
            capture_output=True,
        )

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

        time.sleep(0.2)  # let EAL release mappings
        return False


# ---------------------------------------------------------------------------
# M16 C5 scenario — mirror tap slow consumer + mid-stream release.
# ---------------------------------------------------------------------------

def test_m16_c5_mirror_slow_consumer_then_release():
    """Clamp mirror tap txqueuelen=1 from boot; sustained inject; release
    mid-stream.

    Expected behaviour (GREEN, post-measurement):
      * During clamp: `pktgate_mirror_dropped_total{mirror}` climbs as
        `rte_eth_tx_burst` short-bursts against the starved kernel queue.
        `pktgate_mirror_sent_total{mirror}` climbs slowly (clones queue
        one-at-a-time at the kernel boundary).
      * After release: kernel drain speed returns to default.
        `pktgate_mirror_sent_total` bumps resume at normal pace — the
        drain path recovers without operator intervention on the pktgate
        side.
      * Originals continue flowing to egress — `tx_dropped_total{egress}`
        stays near zero throughout (independent stage path; scenario
        does not deplete mbuf pool, unlike mempool_exhaust).
      * RX keeps ingesting at ~inject rate — attribution probe confirms
        we measured mirror backpressure, not ingress starvation.
      * pktgate process stays alive through the whole stream.

    RED phase (this commit): the headline assertions
      * `mirror_dropped_delta_during_clamp > 10**9`          (impossible)
      * `mirror_sent_delta_after_release < 1`                (impossible)
    are threshold-impossible so the test is guaranteed to FAIL on any
    real run. Functional invariants (attribution probe, tx stability,
    pid alive, clone_failed == 0) stay as-is through RED and GREEN;
    they guard the correctness of the chaos mechanism itself.
    """
    config = _config()

    with _SlowConsumerHarness(config, "pktgate_m16c5_slowcons") as h:
        assert h.prom_port and h.prom_port > 0, (
            f"prom_endpoint_ready not observed. "
            f"stdout_tail={h.stdout_text[-2048:]!r}"
        )

        # --- Baseline counters ---
        base_mirror_sent = _scrape_port_counter(
            h.prom_port, "pktgate_mirror_sent_total", h.mirror_port_id,
        ) or 0
        base_mirror_dropped = _scrape_port_counter(
            h.prom_port, "pktgate_mirror_dropped_total", h.mirror_port_id,
        ) or 0
        base_mirror_clone_failed = _scrape_port_counter(
            h.prom_port, "pktgate_mirror_clone_failed_total",
            h.mirror_port_id,
        ) or 0
        base_tx_dropped = _scrape_port_counter(
            h.prom_port, "pktgate_tx_dropped_total", h.egress_port_id,
        ) or 0
        base_rx = _scrape_port_counter(
            h.prom_port, "pktgate_port_rx_packets_total", h.ingress_port_id,
        ) or 0

        # --- Sustained inject with mid-stream RELEASE of the clamp ---
        t_start = time.monotonic()
        t_release_mono = None
        release_applied = False

        at_release_mirror_sent = None
        at_release_mirror_dropped = None
        at_release_tx_dropped = None
        at_release_rx = None

        try:
            for i in range(_INJECT_COUNT):
                pkt = (
                    Ether(src=_TEST_SRC, dst=_TEST_DST) /
                    IP(src="10.16.6.1", dst="10.16.6.2") /
                    UDP(sport=4242, dport=5616) /
                    Raw(b"M16C5-SLOWCONS-" + f"{i:04d}".encode())
                )
                sendp(pkt, iface=_INGRESS_IFACE, verbose=False)

                # Release the mirror tap clamp mid-stream. Restore the
                # default kernel txqueuelen so the tun queue drains at
                # full speed and `rte_eth_tx_burst` stops short-bursting.
                if (not release_applied) and i + 1 >= _RELEASE_AFTER_PKTS:
                    at_release_mirror_sent = _scrape_port_counter(
                        h.prom_port,
                        "pktgate_mirror_sent_total",
                        h.mirror_port_id,
                    ) or 0
                    at_release_mirror_dropped = _scrape_port_counter(
                        h.prom_port,
                        "pktgate_mirror_dropped_total",
                        h.mirror_port_id,
                    ) or 0
                    at_release_tx_dropped = _scrape_port_counter(
                        h.prom_port,
                        "pktgate_tx_dropped_total",
                        h.egress_port_id,
                    ) or 0
                    at_release_rx = _scrape_port_counter(
                        h.prom_port,
                        "pktgate_port_rx_packets_total",
                        h.ingress_port_id,
                    ) or 0

                    # Release: bring the link UP and restore default
                    # txqueuelen. The kernel consumer resumes draining
                    # at full speed; staged clones (those already in
                    # the mirror buffer but not yet sent) drain on the
                    # next burst tick.
                    up_res = subprocess.run(
                        ["ip", "link", "set", "dev", _MIRROR_IFACE, "up"],
                        capture_output=True, text=True,
                    )
                    if up_res.returncode != 0:
                        pytest.fail(
                            f"ip link set {_MIRROR_IFACE} up failed: "
                            f"rc={up_res.returncode} "
                            f"stderr={up_res.stderr!r}"
                        )
                    qlen_res = subprocess.run(
                        ["ip", "link", "set", "dev", _MIRROR_IFACE,
                         "txqueuelen", "1000"],
                        capture_output=True, text=True,
                    )
                    if qlen_res.returncode != 0:
                        pytest.fail(
                            f"ip link set {_MIRROR_IFACE} txqueuelen 1000 "
                            f"failed: rc={qlen_res.returncode} "
                            f"stderr={qlen_res.stderr!r}"
                        )
                    release_applied = True
                    t_release_mono = time.monotonic()

                if _INJECT_INTER_S > 0:
                    time.sleep(_INJECT_INTER_S)

                # Inline liveness probe — fail fast if pktgate crashes
                # under the sustained-chaos stream.
                if (i + 1) % 200 == 0:
                    assert _pid_alive(h.pid), (
                        f"pktgate pid={h.pid} disappeared during inject "
                        f"after {i + 1} packets. "
                        f"stdout_tail={h.stdout_text[-2048:]!r}"
                    )

            t_end = time.monotonic()

            # Let the last burst drain + snapshot publisher tick.
            time.sleep(2.5)

            # --- Final counters ---
            final_mirror_sent = _scrape_port_counter(
                h.prom_port, "pktgate_mirror_sent_total", h.mirror_port_id,
            ) or 0
            final_mirror_dropped = _scrape_port_counter(
                h.prom_port, "pktgate_mirror_dropped_total",
                h.mirror_port_id,
            ) or 0
            final_mirror_clone_failed = _scrape_port_counter(
                h.prom_port, "pktgate_mirror_clone_failed_total",
                h.mirror_port_id,
            ) or 0
            final_tx_dropped = _scrape_port_counter(
                h.prom_port, "pktgate_tx_dropped_total", h.egress_port_id,
            ) or 0
            final_rx = _scrape_port_counter(
                h.prom_port, "pktgate_port_rx_packets_total",
                h.ingress_port_id,
            ) or 0

        finally:
            # Best-effort restore if the loop bailed before the mid-
            # stream release. Always safe to bring link up and set
            # default txqueuelen (idempotent).
            if not release_applied:
                subprocess.run(
                    ["ip", "link", "set", "dev", _MIRROR_IFACE, "up"],
                    capture_output=True,
                )
                subprocess.run(
                    ["ip", "link", "set", "dev", _MIRROR_IFACE,
                     "txqueuelen", "1000"],
                    capture_output=True,
                )

        # --- pid-alive gate (FUNCTIONAL assertion, stays on GREEN) ---
        assert _pid_alive(h.pid), (
            f"M16 C5: pktgate pid={h.pid} died under mirror slow-"
            f"consumer chaos. stdout_tail={h.stdout_text[-2048:]!r}"
        )

        # --- Attribution sanity probe (FUNCTIONAL; guards against
        # measuring ingress starvation instead of mirror backpressure) ---
        elapsed = t_end - t_start
        assert elapsed > 0.0, (
            "inject loop elapsed=0 — timer is broken; probe cannot run."
        )
        rx_delta = final_rx - base_rx
        rx_attribution_lower_bound = int(
            _RX_ATTRIBUTION_FRACTION * _INJECT_COUNT
        )
        assert rx_delta >= rx_attribution_lower_bound, (
            f"M16 C5: RX starved during the chaos. "
            f"rx_delta={rx_delta}, inject_count={_INJECT_COUNT}, "
            f"lower_bound={rx_attribution_lower_bound} "
            f"({int(_RX_ATTRIBUTION_FRACTION * 100)}% of inject). "
            f"Test is measuring ingress starvation, NOT mirror "
            f"slow-consumer backpressure — invalid attribution. "
            f"elapsed={elapsed:.2f}s "
            f"stdout_tail={h.stdout_text[-1024:]!r}"
        )

        # --- tx-stability gate (FUNCTIONAL) ---
        # Originals flow on an independent stage buffer; mirror_port's
        # kernel-side slow-consumer must NOT collaterally drop originals
        # on egress_port. Baseline is captured from a fresh /metrics
        # scrape before inject; a bump of 0 is the invariant.
        tx_dropped_delta = final_tx_dropped - base_tx_dropped
        assert tx_dropped_delta == 0, (
            f"M16 C5: egress tx_dropped bumped by {tx_dropped_delta} "
            f"during mirror-side slow-consumer chaos — originals must "
            f"NOT be collaterally dropped when the mirror TAP is "
            f"starved. egress_port_id={h.egress_port_id} "
            f"mirror_port_id={h.mirror_port_id} "
            f"base={base_tx_dropped} final={final_tx_dropped}."
        )

        # --- Diagnostic counter capture (for post-mortem in test log) ---
        clone_failed_delta = (
            final_mirror_clone_failed - base_mirror_clone_failed
        )

        # --- Clone-failed invariant (FUNCTIONAL) ---
        # A slow kernel consumer does NOT exhaust the mbuf pool — the
        # failure mode is drain-short at tx_burst, not alloc-fail at
        # rte_pktmbuf_copy. `clone_failed` must stay at 0 across the
        # test. If it bumps, either the mempool_exhaust scenario leaked
        # into this fixture or the pool is unexpectedly starved (which
        # would invalidate the attribution of the `dropped` bumps).
        assert clone_failed_delta == 0, (
            f"M16 C5: clone_failed bumped by {clone_failed_delta} "
            f"during mirror slow-consumer chaos — this scenario is "
            f"supposed to exercise the DRAIN-SHORT path (dropped++), "
            f"not the COPY-FAILED path (clone_failed++). Wrong failure "
            f"mode — likely mbuf pool starved, invalidating "
            f"backpressure attribution."
        )

        # --- Recovery scrape execution gate (structural) ---
        # If release logic didn't execute we're about to assert on
        # undefined values — fail loudly.
        assert release_applied, (
            "M16 C5: mid-stream release never executed — "
            f"loop broke before i+1 reached {_RELEASE_AFTER_PKTS}. "
            "Test harness bug."
        )
        assert at_release_mirror_sent is not None, (
            "M16 C5: at-release scrape did not record mirror_sent — "
            "release logic broken."
        )
        assert at_release_mirror_dropped is not None, (
            "M16 C5: at-release scrape did not record mirror_dropped — "
            "release logic broken."
        )

        # --- Delta computations for threshold-impossible RED asserts ---
        # Clamp-window dropped delta: `at_release - base`. The clamp
        # was in effect from boot through the release point, so any
        # bump observed at release time is drain-short accumulation
        # during that window. GREEN cycle flips threshold to a measured
        # lower bound (observed tens-to-hundreds on dev-debug probe).
        mirror_dropped_delta_during_clamp = (
            at_release_mirror_dropped - base_mirror_dropped
        )

        # Post-release sent delta: `final - at_release`. After the
        # clamp is lifted the kernel drain resumes; sent bumps should
        # climb vigorously as staged clones tx-burst successfully.
        # GREEN cycle flips threshold to a measured lower bound.
        mirror_sent_delta_after_release = (
            final_mirror_sent - at_release_mirror_sent
        )

        # --- Headline RED assertions (threshold-impossible) ---
        # Clamp-window dropped must exceed 10**9: real run bumps by
        # tens/hundreds. 10**9 in a ~2000-packet burst at 200 pps is
        # arithmetically unreachable → FAIL on RED.
        assert mirror_dropped_delta_during_clamp > \
            _MIRROR_DROPPED_DELTA_THRESHOLD_RED, (
            f"M16 C5 (RED phase, threshold-impossible): expected "
            f"mirror_dropped delta during clamp > "
            f"{_MIRROR_DROPPED_DELTA_THRESHOLD_RED} "
            f"(will be flipped to a measured lower bound in GREEN). "
            f"Got delta={mirror_dropped_delta_during_clamp} "
            f"(at_release={at_release_mirror_dropped} "
            f"base={base_mirror_dropped}). "
            f"elapsed_to_release={'<unknown>' if t_release_mono is None else f'{t_release_mono - t_start:.2f}s'} "
            f"at_release_mirror_sent={at_release_mirror_sent} "
            f"at_release_rx={at_release_rx}."
        )

        # Post-release sent must be strictly < 1: real run bumps by
        # at least some packets after release. < 1 is only satisfied
        # at zero, which any working drain path beats → FAIL on RED.
        assert mirror_sent_delta_after_release < (
            _MIRROR_SENT_AFTER_RELEASE_UPPER_BOUND_RED + 1
        ), (
            f"M16 C5 (RED phase, threshold-impossible): expected "
            f"mirror_sent delta after release < "
            f"{_MIRROR_SENT_AFTER_RELEASE_UPPER_BOUND_RED + 1} "
            f"(will be flipped to a measured lower bound in GREEN). "
            f"Got delta={mirror_sent_delta_after_release} "
            f"(final={final_mirror_sent} "
            f"at_release={at_release_mirror_sent}). "
            f"elapsed_post_release={'<unknown>' if t_release_mono is None else f'{t_end - t_release_mono:.2f}s'} "
            f"final_mirror_dropped={final_mirror_dropped} "
            f"rx_delta={rx_delta}."
        )

    assert h.returncode == 0, (
        f"pktgate exit unclean: rc={h.returncode} "
        f"stdout_tail={h.stdout_text[-2048:]!r}"
    )
