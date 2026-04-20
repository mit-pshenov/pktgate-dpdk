# tests/chaos/test_m16_mirror_port_gone.py
#
# M16 C4 — chaos scenario 1: mirror destination link goes down mid-burst.
#
# What this test exercises:
#   The M16 C2 counter taxonomy was built to distinguish three kinds of
#   clone-side failure:
#     * `pktgate_mirror_sent_total{port}`         — clone staged + drained
#       through rte_eth_tx_burst successfully.
#     * `pktgate_mirror_clone_failed_total{port}` — rte_pktmbuf_copy
#       returned null (mempool exhausted, out of mbufs, etc).
#     * `pktgate_mirror_dropped_total{port}`      — clone staged but
#       rte_eth_tx_burst consumed fewer than staged at drain time; the
#       unsent tail is freed and the delta attributed to drops.
#
#   Scenario 1 forces the third case: while a sustained 100 pps stream
#   is in flight, drop the mirror destination tap's kernel-side link via
#   `ip link set dtap_m16c_mir down` (IFF_UP=0). Future drain attempts
#   for that port see tun_net_xmit refusing frames; rte_eth_tx_burst
#   reports a short burst and `mirror_drain` counts the unsent tail into
#   `mirror_dropped_per_port[port]`. Originals continue flowing through
#   the separate `stage_tx` path, unaffected by the mirror side's
#   backpressure (D16 staging pattern separates the two).
#
# What this test does NOT assert:
#   - Deterministic ordering between egress and mirror taps (D16
#     separate buffers, drained in undefined order).
#   - Per-packet loss accounting. `mirror_dropped_total` climbs by an
#     UNKNOWN amount that depends on:
#       * exact moment the link transitions down relative to RX bursts,
#       * kernel queue drain cadence,
#       * inject pacing vs. DPDK RX polling rate.
#     A realistic threshold for GREEN will be measured empirically on
#     the dev VM. RED phase asserts an IMPOSSIBLE threshold (>10**9)
#     to keep the RED commit genuinely red.
#
# Attribution sanity probe (non-optional per handoff anti-pattern alert):
#   `pktgate_port_rx_packets_total{port=<ingress_port>}` is observed at
#   start, end, and at the break point. The test asserts RX climbs at
#   ≥80% of the injection rate through the whole test — otherwise we'd
#   be measuring ingress starvation, not the intended mirror-side
#   backpressure. Threshold is FUNCTIONAL (not impossible) — it's a
#   correctness gate on the chaos, not a RED marker.
#
# Mechanism choice note (for Scenario 2, which runs in the sibling file
# `test_m16_mirror_mempool_exhaust.py`):
#   mempool exhaustion cannot be forced today without adding a src/
#   knob — `src/main.cpp:414` hardcodes `kMbufCount = 8191` as constexpr
#   and there is no CLI / env override. The sibling test is therefore
#   `pytest.skip`ed with an explicit reason until the GREEN cycle
#   wires a `PKTGATE_TEST_MBUF_POOL_SIZE` env var (or equivalent).
#
# RED/GREEN strategy:
#   - RED commit: assertions use `_MIRROR_DROPPED_THRESHOLD_RED = 10**9`.
#     Any real run bumps `mirror_dropped_total` by at most a few hundred;
#     10**9 is unreachable by arithmetic — test FAILS.
#   - RED commit: `_SENT_BEFORE_BREAK_RED = 1` as upper bound; real run
#     bumps it to many tens-to-hundreds — test FAILS on `sent < 1`.
#   - GREEN commit (next cycle): empirically measure realistic bounds
#     and flip both thresholds. Attribution probe + tx-stability +
#     pid-alive assertions already functional and stay as-is.

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

# Session-scoped NM-unmanaged fixture — conftest.py lists dtap_m16c_*.
pytestmark = pytest.mark.usefixtures("nm_unmanaged_tap")


# EAL `-d <path>` opt-in (memory grabli_eal_d_flag_env_opt_in.md).
_DPDK_DRIVER_DIR_ARGS = (
    ["-d", os.environ["PKTGATE_DPDK_DRIVER_DIR"].strip()]
    if os.environ.get("PKTGATE_DPDK_DRIVER_DIR", "").strip()
    else []
)

# IFNAMSIZ 16-char budget (memory grabli_ifnamsiz_16_limit.md). All three
# dtap names ≤15 chars (one byte for NUL terminator). Separate namespace
# from M16 C3 (`dtap_m16_*`) so tests co-exist in a shared session.
_INGRESS_IFACE = "dtap_m16c_ing"    # 13 chars
_EGRESS_IFACE = "dtap_m16c_egr"     # 13 chars
_MIRROR_IFACE = "dtap_m16c_mir"     # 13 chars

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

_TEST_SRC = "aa:bb:cc:dd:ee:c4"
_TEST_DST = "11:22:33:44:55:c4"

# Inject 1000 packets at ~100 pps → ~10 seconds of wall clock.
_INJECT_COUNT = 1000
_INJECT_INTER_S = 0.01  # 100 Hz pacing (actual cadence will slip under
                        # sanitiser load; the test does NOT depend on
                        # exact 100 pps — see attribution probe below).
_BREAK_AFTER_PKTS = 300  # mid-stream break: ~3 s into the 10 s stream.

# GREEN thresholds (measured-realistic) — see commit body for the
# three stability-run deltas that seeded each floor. Lower bounds were
# chosen at roughly one-third of observed minimum to keep headroom for
# sanitiser presets (TSan/ASan can slip pacing and/or pool reclaim by
# 2-5x vs. dev-debug baseline). Chaos counters are stochastic; always
# use inequality with generous margin, never equality on chaos deltas.
_MIRROR_SENT_LOWER_BOUND = 100   # pre-break ~300 packet burst ships
                                 # many tens of clones; floor at 100
                                 # well below dev-debug minimum of 298.
_MIRROR_DROPPED_LOWER_BOUND = 1  # post-break drain-short; observed
                                 # tens-to-hundreds across presets;
                                 # floor at 1 to tolerate slow-tap
                                 # presets where break lands after
                                 # pool has already drained.

# Attribution-probe threshold: the RX path must sustain at least 80% of
# the inject rate across the entire test. If RX rate drops below this
# we are measuring the wrong failure mode (ingress starvation, not
# mirror backpressure) and the test must fail loudly.
_RX_ATTRIBUTION_FRACTION = 0.80


# ---------------------------------------------------------------------------
# Helpers (shape borrowed from tests/functional/test_f16_mirror_tap.py and
# test_f14_tap_exit.py so mechanics stay uniform).
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
                    "id": 16004,
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
# Harness — three-TAP boot, NDP preempt, scrape helpers.
# ---------------------------------------------------------------------------

class _MirrorChaosHarness:
    """Boot pktgate with three net_tap vdevs; harden taps against NDP/
    ARP/IPv6 noise; expose ingress / egress / mirror port_ids + prom
    port."""

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
        return False


# ---------------------------------------------------------------------------
# M16 C4 scenario 1 — mirror destination link down mid-burst.
# ---------------------------------------------------------------------------

def test_m16_c4_mirror_port_gone_mid_burst():
    """Sustained 100 pps; at ~3 s mark `ip link set <mirror_tap> down`.

    Expected behaviour (GREEN, post-measurement):
      * Originals continue flowing to egress — `tx_dropped_total{egress}`
        stays near zero across the test (independent stage path).
      * Mirror-side clones start hitting short-burst drains after the
        break — `pktgate_mirror_dropped_total{mirror_port}` climbs from
        the break onward.
      * RX keeps ingesting at ~inject rate — attribution probe confirms
        we measured mirror backpressure, not ingress starvation.
      * pktgate process stays alive through the whole stream.

    RED phase (this commit): the `sent < 1` and `dropped > 1e9`
    assertions are threshold-impossible so the test is guaranteed to
    FAIL on any real run. Attribution + tx-stability + pid-alive
    assertions are FUNCTIONAL (not RED markers) and must pass end-to-
    end; they guard correctness of the chaos mechanism itself.
    """
    config = _config()

    with _MirrorChaosHarness(config, "pktgate_m16c4_portgone") as h:
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

        # --- Sustained inject with a mid-stream break ---
        t_start = time.monotonic()
        t_break_mono = None
        break_applied = False
        link_downed = False

        mid_mirror_sent = None
        mid_tx_dropped = None
        mid_rx = None

        try:
            for i in range(_INJECT_COUNT):
                pkt = (
                    Ether(src=_TEST_SRC, dst=_TEST_DST) /
                    IP(src="10.16.4.1", dst="10.16.4.2") /
                    UDP(sport=4242, dport=5616) /
                    Raw(b"M16C4-PORTGONE-" + f"{i:04d}".encode())
                )
                sendp(pkt, iface=_INGRESS_IFACE, verbose=False)

                # Break the mirror tap mid-stream. txqueuelen=1 makes the
                # tun internal queue fill immediately; `link set down`
                # forces rte_eth_tx_burst into short-burst territory.
                if (not break_applied) and i + 1 >= _BREAK_AFTER_PKTS:
                    mid_mirror_sent = _scrape_port_counter(
                        h.prom_port,
                        "pktgate_mirror_sent_total",
                        h.mirror_port_id,
                    ) or 0
                    mid_tx_dropped = _scrape_port_counter(
                        h.prom_port,
                        "pktgate_tx_dropped_total",
                        h.egress_port_id,
                    ) or 0
                    mid_rx = _scrape_port_counter(
                        h.prom_port,
                        "pktgate_port_rx_packets_total",
                        h.ingress_port_id,
                    ) or 0

                    subprocess.run(
                        ["ip", "link", "set", "dev", _MIRROR_IFACE,
                         "txqueuelen", "1"],
                        capture_output=True,
                    )
                    down_res = subprocess.run(
                        ["ip", "link", "set", "dev", _MIRROR_IFACE,
                         "down"],
                        capture_output=True, text=True,
                    )
                    if down_res.returncode != 0:
                        pytest.fail(
                            f"ip link set {_MIRROR_IFACE} down failed: "
                            f"rc={down_res.returncode} "
                            f"stderr={down_res.stderr!r}"
                        )
                    link_downed = True
                    break_applied = True
                    t_break_mono = time.monotonic()

                if _INJECT_INTER_S > 0:
                    time.sleep(_INJECT_INTER_S)

                # Inline liveness probe every 100 packets — if pktgate
                # has crashed under the chaos we want to know *here*,
                # not after the whole stream finishes.
                if (i + 1) % 100 == 0:
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
            # Restore the mirror tap so subsequent tests in the same
            # session don't inherit a broken state.
            if link_downed:
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
            f"M16 C4 scenario 1: pktgate pid={h.pid} died under mirror "
            f"link-down chaos. stdout_tail={h.stdout_text[-2048:]!r}"
        )

        # --- Attribution sanity probe (FUNCTIONAL; guards against
        # measuring ingress starvation instead of mirror backpressure) ---
        elapsed = t_end - t_start
        assert elapsed > 0.0, (
            "inject loop elapsed=0 — timer is broken; probe cannot run."
        )
        rx_delta = final_rx - base_rx
        # Under F2.25 NDP preempt the RX path sees essentially only the
        # injected traffic. We assert that RX climbed by at least 80%
        # of the inject count (slack for late-arrived packets still
        # queued in the tap when we scraped).
        rx_attribution_lower_bound = int(
            _RX_ATTRIBUTION_FRACTION * _INJECT_COUNT
        )
        assert rx_delta >= rx_attribution_lower_bound, (
            f"M16 C4 scenario 1: RX starved during the chaos. "
            f"rx_delta={rx_delta}, inject_count={_INJECT_COUNT}, "
            f"lower_bound={rx_attribution_lower_bound} "
            f"({int(_RX_ATTRIBUTION_FRACTION * 100)}% of inject). "
            f"Test is measuring ingress starvation, NOT mirror "
            f"backpressure — invalid attribution. "
            f"elapsed={elapsed:.2f}s "
            f"stdout_tail={h.stdout_text[-1024:]!r}"
        )

        # --- tx-stability gate (FUNCTIONAL) ---
        # Originals flow on an independent stage buffer; mirror_port's
        # backpressure must NOT collaterally drop originals on
        # egress_port. Baseline is captured from a fresh /metrics scrape
        # before inject; a bump of 0 is the invariant.
        tx_dropped_delta = final_tx_dropped - base_tx_dropped
        assert tx_dropped_delta == 0, (
            f"M16 C4 scenario 1: egress tx_dropped bumped by "
            f"{tx_dropped_delta} during mirror-side chaos — originals "
            f"must NOT be collaterally dropped when the mirror TAP "
            f"goes down. egress_port_id={h.egress_port_id} "
            f"mirror_port_id={h.mirror_port_id} "
            f"base={base_tx_dropped} final={final_tx_dropped}."
        )

        # --- Diagnostic counter capture (for post-mortem in test log) ---
        mirror_sent_delta = final_mirror_sent - base_mirror_sent
        mirror_dropped_delta = final_mirror_dropped - base_mirror_dropped
        clone_failed_delta = (
            final_mirror_clone_failed - base_mirror_clone_failed
        )

        # --- Clone-failed invariant (FUNCTIONAL) ---
        # A down link does NOT exhaust the mbuf pool — the failure mode
        # is at tx_burst drain, not at rte_pktmbuf_copy. `clone_failed`
        # must stay at 0 across the test. If it bumps, either scenario 2
        # leaked into scenario 1 or the mbuf pool is unexpectedly starved.
        assert clone_failed_delta == 0, (
            f"M16 C4 scenario 1: clone_failed bumped by "
            f"{clone_failed_delta} during mirror-port-gone chaos — "
            f"this scenario is supposed to exercise the DRAIN-SHORT "
            f"path (dropped++), not the COPY-FAILED path "
            f"(clone_failed++). Wrong failure mode."
        )

        # --- sent-before-break threshold (chaos observable, lower bound) ---
        # Pre-break ~300-packet burst should ship many tens of clones.
        # Measured dev-debug baseline ~298; floor at 100 for margin.
        assert mid_mirror_sent is not None, (
            "mid-stream scrape did not execute — break logic broken."
        )
        mid_sent_delta = mid_mirror_sent - base_mirror_sent
        assert mid_sent_delta >= _MIRROR_SENT_LOWER_BOUND, (
            f"M16 C4 scenario 1: expected mid-stream mirror_sent delta "
            f">= {_MIRROR_SENT_LOWER_BOUND} (pre-break burst of "
            f"~{_BREAK_AFTER_PKTS} packets should ship many tens of "
            f"clones). Got mid_sent_delta={mid_sent_delta} "
            f"(mid={mid_mirror_sent} base={base_mirror_sent}). "
            f"Threshold floor is 1/3 of observed minimum; a value below "
            f"this indicates broken mirror staging or a stalled drain."
        )

        # --- dropped threshold (chaos observable, lower bound) ---
        # Post-break drain-short counting — `mirror_dropped_total` climbs
        # by an undetermined amount that depends on kernel queue drain
        # cadence, inject pacing, RX polling. Observed tens-to-hundreds
        # across presets; floor at 1 tolerates slow-preset corner cases
        # where the break happens to land after the pool drained.
        assert mirror_dropped_delta >= _MIRROR_DROPPED_LOWER_BOUND, (
            f"M16 C4 scenario 1: expected mirror_dropped delta >= "
            f"{_MIRROR_DROPPED_LOWER_BOUND} after mid-stream link-down "
            f"(drain-short path must bump at least once). "
            f"Got delta={mirror_dropped_delta} "
            f"(final={final_mirror_dropped} base={base_mirror_dropped}). "
            f"elapsed_wall={elapsed:.2f}s mid_mirror_sent={mid_mirror_sent} "
            f"mid_rx={mid_rx} final_rx={final_rx} rx_delta={rx_delta} "
            f"final_mirror_sent={final_mirror_sent} "
            f"final_clone_failed={final_mirror_clone_failed}."
        )

    assert h.returncode == 0, (
        f"pktgate exit unclean: rc={h.returncode} "
        f"stdout_tail={h.stdout_text[-2048:]!r}"
    )
