# tests/functional/test_f16_mirror_tap.py
#
# M16 C3 — TAP mirror destination functional smoke (F16.2 + F16.3).
#
# Closes the M16 C2 hot-path dispatch with a live end-to-end witness on
# the canonical deployment profile (net_tap). The M16 C2 dispatch arm
# in apply_action (`case kMirror:`) clones each matched packet via
# rte_pktmbuf_copy, stages the clone into ctx->mirror_tx[mirror_port]
# (drained at burst end via mirror_drain), and forwards the ORIGINAL
# along the usual tx_one() path to ctx->tx_port_id. Two kernel taps
# are needed to observe both sides: one for the original egress and
# one for the clone destination.
#
# F16.2 — happy path:
#   Three-TAP layout (`dtap_m16_ing`, `dtap_m16_egress`, `dtap_m16_mirror`).
#   One L4 ALLOW rule with `action: mirror, target_port: <mirror_role>`.
#   Inject 50 scapy UDP packets with deterministic per-packet payload
#   suffixes; AsyncSniffer on both egress and mirror TAPs; assert the
#   payload sets match on both sides AND `pktgate_mirror_sent_total
#   {port="<mirror_port_id>"}` == 50 on /metrics, with clone_failed and
#   dropped both 0. Arrival order is NOT asserted — original-egress
#   and clone-mirror live in separate stage_* buffers drained in
#   undefined order (D16 pattern).
#
# F16.3 — config reject:
#   Same boot shape but `ActionMirror.role_name` references a role
#   NOT declared in `interface_roles`. The validator's M14 C2 D43
#   `kUnresolvedTargetPort` path (src/config/validator.cpp:306-342)
#   rejects the config BEFORE EAL ever launches — pktgate exits
#   non-zero with `"error":"validate_err"` on stdout. Assertion
#   shape follows the existing reject-path tests (F14.3 at
#   tests/functional/test_f14_main_resolver.py:236-282).
#
# ---------------------------------------------------------------------
# NDP / kernel-noise discipline (F2.25 guard):
#   The moment net_tap brings up each dtap, preemptively kill IPv6,
#   disable ARP, and flush addrs. NM keyfile already marks the three
#   interface names `dtap_m16_*` as unmanaged (see conftest.py). Same
#   pattern as tests/functional/test_f14_tap_exit.py:317-342.
#
# IFNAMSIZ 16-char budget:
#   `dtap_m16_ing` (12), `dtap_m16_egress` (15), `dtap_m16_mirror`
#   (15) — all ≤15 characters (one byte for NUL terminator). Memory
#   anchor: grabli_ifnamsiz_16_limit.md.
#
# role_idx -> port_id translation (M16 C3.5 fix landed):
#   Pre-C3.5: `RuleAction.mirror_port` carried the compiler role_idx
#   (lex-sorted nlohmann ordering of `interface_roles` keys) straight
#   to `rte_eth_tx_burst(port, ...)`. The F16.2 config therefore had to
#   force the mirror role's lex rank to equal its DPDK port_id
#   (`zz_mirror_port` -> lex idx 2 -> net_tap2 -> port_id 2).
#
#   Post-C3.5: `populate_ruleset_eal` walks `rs.l{2,3,4}_actions[]` and
#   translates `{redirect,mirror}_port` from role_idx to the live DPDK
#   port_id via `rte_eth_dev_get_port_by_name`, so the role name can be
#   anything. Natural ordering is used below (`mirror_port`) — no
#   lex-rank workaround required. Memory
#   `grabli_role_idx_as_port_id_bug.md` (FIXED in M16 C3.5). The
#   non-lex regression twin lives at
#   `tests/functional/test_f16_mirror_tap_nonlex.py`.
#
# RED/GREEN strategy:
#   RED commit asserts an impossible threshold (`sent == 1000` on 50
#   injected; phantom diagnostic substring in F16.3). GREEN flips
#   thresholds to realistic values (50 == 50 exact; `validate_err`
#   string match). Precedent: M15 C3 _RX_THRESHOLD_RED pattern
#   (tests/integration/test_m15_vhost_pair.py:82-85).

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
    AsyncSniffer, Ether, IP, UDP, Raw, conf as scapy_conf, sendp,
)

scapy_conf.verb = 0  # suppress scapy output

# Session-scoped NM-unmanaged fixture — conftest.py lists dtap_m16_*.
pytestmark = pytest.mark.usefixtures("nm_unmanaged_tap")


# EAL `-d <path>` opt-in (memory grabli_eal_d_flag_env_opt_in.md).
_DPDK_DRIVER_DIR_ARGS = (
    ["-d", os.environ["PKTGATE_DPDK_DRIVER_DIR"].strip()]
    if os.environ.get("PKTGATE_DPDK_DRIVER_DIR", "").strip()
    else []
)

# IFNAMSIZ 16-char budget (memory grabli_ifnamsiz_16_limit.md).
_INGRESS_IFACE = "dtap_m16_ing"     # 12 chars
_EGRESS_IFACE = "dtap_m16_egress"   # 15 chars
_MIRROR_IFACE = "dtap_m16_mirror"   # 15 chars

# FIB DIR24_8 needs ~128 MB heap even without L3 rules -> -m 512
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

_TEST_SRC = "aa:bb:cc:dd:ee:16"
_TEST_DST = "11:22:33:44:55:16"

_INJECT_COUNT = 50

# RED sentinels, preserved as named constants so the RED->GREEN diff is
# a single-value flip and the historical threshold is legible from the
# test source (same pattern as M15 C3 _RX_THRESHOLD_RED kept alongside
# _RX_THRESHOLD_REAL in tests/integration/test_m15_vhost_pair.py).
_SENT_THRESHOLD_RED = 1000  # pre-C3-GREEN impossible sentinel; see commit
_REJECT_DIAGNOSTIC_RED = "M16C3_RED_IMPOSSIBLE_STRING_SENTINEL"

# GREEN: exact-match threshold on successful clone staging. 50 out of
# 50 because the mirror destination tap is idle (no back-pressure) and
# stage_mirror's kMirrorBurstMax=32 is drained per RX burst, so no
# buffer-full drops accumulate.
_SENT_THRESHOLD_REAL = _INJECT_COUNT
# GREEN: main.cpp's structured validation failure marker
# (src/main.cpp:321 log_json "validate_err" string). Full line also
# contains the validator message text which names the offending role.
_REJECT_DIAGNOSTIC_REAL = "validate_err"


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


def _config_happy(mirror_role: str = "mirror_port") -> dict:
    """Happy-path config: three roles + one L4 ALLOW rule with mirror.

    Post-M16 C3.5: role names are natural — `populate_ruleset_eal`
    translates role_idx to DPDK port_id, so lex-rank alignment is no
    longer required. `mirror_role` names the role the rule mirrors
    into; defaults to `mirror_port`.
    """
    return {
        "version": 1,
        "interface_roles": {
            # Resolver: upstream_port -> net_tap0 -> port_id 0
            # (worker RX, scapy injects on dtap_m16_ing).
            "upstream_port":   {"vdev": "net_tap0"},
            # Resolver: downstream_port -> net_tap1 -> port_id 1
            # (worker TX, egress original forwards here).
            "downstream_port": {"vdev": "net_tap1"},
            # Resolver: mirror_port -> net_tap2 -> port_id 2
            # (mirror destination). Post-C3.5 the populate step maps
            # role_idx to this port_id via rte_eth_dev_get_port_by_name
            # — no lex-rank alignment required.
            "mirror_port":     {"vdev": "net_tap2"},
        },
        "default_behavior": "drop",
        "pipeline": {
            "layer_2": [],
            "layer_3": [],
            "layer_4": [
                {
                    "id": 16002,
                    "proto": 17,        # UDP
                    "dst_port": 5616,
                    "action": {
                        "type": "mirror",
                        "target_port": mirror_role,
                    },
                },
            ],
        },
        "sizing": _SIZING,
    }


def _config_reject_unregistered() -> dict:
    """Reject-path config: mirror targets an undeclared role.

    `phantom_mirror_port` is NOT listed in interface_roles. The
    validator's check_action_target_port() (validator.cpp:315) folds
    this into `kUnresolvedTargetPort` and main.cpp surfaces it as
    `{"error":"validate_err", "message":"... phantom_mirror_port ..."}`
    on stdout, then exits 1 before EAL launch.
    """
    cfg = _config_happy()
    # Overwrite the L4 rule to target a phantom role.
    cfg["pipeline"]["layer_4"] = [
        {
            "id": 16003,
            "proto": 17,
            "dst_port": 5617,
            "action": {
                "type": "mirror",
                "target_port": "phantom_mirror_port",
            },
        },
    ]
    return cfg


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
    """Return the port_id main.cpp bound to `role`, via port_resolved
    events (M14 C2). Returns None if no event names the role."""
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
    """Extract `{metric_name}{port="<port_id>"}` from /metrics body, or
    None if the label triple is not present."""
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


def _marker_for(i: int) -> bytes:
    """Deterministic per-packet payload marker. Each of the _INJECT_COUNT
    packets carries a unique 3-digit suffix so a capture's payload set
    can be compared by identity, not just count."""
    return b"F16.2-MIRROR-" + f"{i:03d}".encode()


def _extract_markers(captured):
    """Return the set of marker bytes observed across captured packets.

    Filters on _TEST_SRC so kernel chatter that happens to land on the
    tap cannot pollute the set (defence-in-depth atop the NM keyfile +
    sysctl mitigations)."""
    markers = set()
    for p in captured:
        try:
            if not p.haslayer(Ether) or p[Ether].src != _TEST_SRC:
                continue
            if not p.haslayer(Raw):
                continue
            payload = bytes(p[Raw].load)
            # One marker per frame; extract the deterministic slice.
            m = re.search(rb"F16\.2-MIRROR-\d{3}", payload)
            if m:
                markers.add(m.group(0))
        except Exception:
            continue
    return markers


# ---------------------------------------------------------------------------
# Harness — three-TAP boot, NDP-proof, dual AsyncSniffer, /metrics scrape.
# ---------------------------------------------------------------------------

class _F16MirrorHarness:
    """Boot pktgate with three net_tap vdevs; harden all three kernel
    taps against NDP/ARP/IPv6 noise; expose AsyncSniffer handles for
    the egress and mirror TAPs."""

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
        self.egress_port_id = None
        self.mirror_port_id = None
        # Dual sniffer state.
        self._egress_sniffer = None
        self._mirror_sniffer = None
        self.egress_captured: list = []
        self.mirror_captured: list = []

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

        # F2.25-class preempt on all three taps.
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
        # Pull per-role port_ids from main.cpp's port_resolved events.
        # Fallback: vdev cmdline order -> port_ids 0/1/2 (upstream on
        # net_tap0, downstream on net_tap1, mirror_port on net_tap2).
        self.egress_port_id = (
            _resolved_port_id(self._lines, "downstream_port")
        )
        if self.egress_port_id is None:
            self.egress_port_id = 1
        self.mirror_port_id = (
            _resolved_port_id(self._lines, "mirror_port")
        )
        if self.mirror_port_id is None:
            self.mirror_port_id = 2

        # Let any one-shot kernel bring-up chatter drain out.
        time.sleep(0.5)

        return self

    def _lfilter(self, p):
        try:
            return p.haslayer(Ether) and p[Ether].src == _TEST_SRC
        except Exception:
            return False

    def sniff_start(self):
        """Start AsyncSniffers on BOTH egress and mirror taps."""
        from scapy.all import conf as sc
        sc.ifaces.reload()
        self._egress_sniffer = AsyncSniffer(
            iface=_EGRESS_IFACE, store=True, lfilter=self._lfilter,
        )
        self._mirror_sniffer = AsyncSniffer(
            iface=_MIRROR_IFACE, store=True, lfilter=self._lfilter,
        )
        self._egress_sniffer.start()
        self._mirror_sniffer.start()
        # Let AF_PACKET sockets attach.
        time.sleep(0.3)

    def inject(self, packets, pause: float = 0.02):
        from scapy.all import conf as sc
        sc.ifaces.reload()
        for pkt in packets:
            sendp(pkt, iface=_INGRESS_IFACE, verbose=False)
            if pause:
                time.sleep(pause)

    def sniff_stop(self, settle: float = 2.0):
        """Stop both sniffers after a quiescence window."""
        time.sleep(settle)
        if self._egress_sniffer is not None:
            try:
                self._egress_sniffer.stop()
            except Exception:
                pass
            self.egress_captured = list(self._egress_sniffer.results or [])
            self._egress_sniffer = None
        if self._mirror_sniffer is not None:
            try:
                self._mirror_sniffer.stop()
            except Exception:
                pass
            self.mirror_captured = list(self._mirror_sniffer.results or [])
            self._mirror_sniffer = None

    def __exit__(self, exc_type, exc_val, exc_tb):
        for sniffer_attr in ("_egress_sniffer", "_mirror_sniffer"):
            s = getattr(self, sniffer_attr, None)
            if s is not None:
                try:
                    s.stop()
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


# ---------------------------------------------------------------------------
# F16.2 — TAP mirror happy path.
# ---------------------------------------------------------------------------

def test_f16_2_mirror_tap_happy_path():
    """Mirror verb end-to-end on net_tap profile.

    Fifty UDP packets matched by an L4 `action: mirror, target_port:
    mirror_port` rule: the ORIGINAL lands on `dtap_m16_egress`
    (worker.cpp forwards matched frames via tx_one to tx_port_id =
    downstream_port), and a CLONE lands on `dtap_m16_mirror` (D7
    dispatch + stage_mirror + mirror_drain). Counter witness:
    `pktgate_mirror_sent_total{port="<mirror_port_id>"}` equals the
    inject count exactly; clone_failed and dropped are both 0 for an
    idle 3rd tap with a tiny 50-packet flow.

    Order NOT asserted — original-egress and clone-mirror are staged
    into separate per-port buffers drained in undefined order (D16).
    Set equality on payload markers + exact counter values is the
    canonical shape.

    RED (this test in the RED commit): asserts `sent == 1000` on 50
    injected -> impossible -> FAIL. GREEN (next commit): flips the
    threshold to the real value `_INJECT_COUNT`.
    """
    config = _config_happy()

    packets = []
    for i in range(_INJECT_COUNT):
        packets.append(
            Ether(src=_TEST_SRC, dst=_TEST_DST) /
            IP(src="10.16.2.1", dst="10.16.2.2") /
            UDP(sport=4242, dport=5616) /
            Raw(_marker_for(i))
        )
    expected_markers = {_marker_for(i) for i in range(_INJECT_COUNT)}

    with _F16MirrorHarness(config, "pktgate_f16_2") as h:
        assert h.prom_port and h.prom_port > 0, (
            f"prom_endpoint_ready not observed. "
            f"stdout={h.stdout_text[-2048:]!r}"
        )

        h.sniff_start()
        h.inject(packets)
        h.sniff_stop(settle=2.5)

        sent = _scrape_port_counter(
            h.prom_port,
            "pktgate_mirror_sent_total",
            h.mirror_port_id,
        )
        clone_failed = _scrape_port_counter(
            h.prom_port,
            "pktgate_mirror_clone_failed_total",
            h.mirror_port_id,
        )
        dropped = _scrape_port_counter(
            h.prom_port,
            "pktgate_mirror_dropped_total",
            h.mirror_port_id,
        )

    assert h.returncode == 0, (
        f"binary unclean exit rc={h.returncode} "
        f"stdout_tail={h.stdout_text[-2048:]!r}"
    )

    # Payload set parity — the ORIGINAL must reach egress and the CLONE
    # must reach mirror with the same deterministic markers. Drop-in
    # defence against a regression where one side stops forwarding
    # independently of the counter bumps.
    egress_markers = _extract_markers(h.egress_captured)
    mirror_markers = _extract_markers(h.mirror_captured)
    assert egress_markers == expected_markers, (
        f"F16.2: egress payload set mismatch on {_EGRESS_IFACE}. "
        f"missing={sorted(expected_markers - egress_markers)!r} "
        f"extra={sorted(egress_markers - expected_markers)!r} "
        f"stdout_tail={h.stdout_text[-1024:]!r}"
    )
    assert mirror_markers == expected_markers, (
        f"F16.2: mirror payload set mismatch on {_MIRROR_IFACE}. "
        f"missing={sorted(expected_markers - mirror_markers)!r} "
        f"extra={sorted(mirror_markers - expected_markers)!r} "
        f"stdout_tail={h.stdout_text[-1024:]!r}"
    )

    # /metrics scrape — M16 C2 counter triplet, per-port labelled.
    assert sent is not None, (
        f"F16.2: pktgate_mirror_sent_total{{port=\"{h.mirror_port_id}\"}} "
        "not present in /metrics; the C2 BodyFn loop is not emitting "
        "per-port mirror labels."
    )
    assert clone_failed is not None, (
        f"F16.2: pktgate_mirror_clone_failed_total{{port=\""
        f"{h.mirror_port_id}\"}} not present in /metrics."
    )
    assert dropped is not None, (
        f"F16.2: pktgate_mirror_dropped_total{{port=\""
        f"{h.mirror_port_id}\"}} not present in /metrics."
    )

    # GREEN: exact match. kMirrorBurstMax (32) + one drain per RX
    # burst handles the 50-packet flow without stage-full drops; the
    # idle mirror tap accepts all staged clones without short-burst
    # unsent. If either channel ever produces a loss the clone_failed
    # / dropped asserts below catch it precisely rather than this
    # sent counter drifting below _INJECT_COUNT.
    assert sent == _SENT_THRESHOLD_REAL, (
        f"F16.2: pktgate_mirror_sent_total{{port=\"{h.mirror_port_id}\"}}"
        f" = {sent}, expected {_SENT_THRESHOLD_REAL} (exact). "
        f"mirror_port_id={h.mirror_port_id} "
        f"egress_port_id={h.egress_port_id} "
        f"inject_count={_INJECT_COUNT}. "
        f"stdout_tail={h.stdout_text[-2048:]!r}"
    )

    assert clone_failed == 0, (
        f"F16.2: unexpected clone failures={clone_failed} on an idle "
        f"mempool with a 50-packet flow. mirror_port_id={h.mirror_port_id}."
    )
    assert dropped == 0, (
        f"F16.2: unexpected mirror drops={dropped} on an idle 3rd tap "
        f"with a 50-packet flow. mirror_port_id={h.mirror_port_id}."
    )


# ---------------------------------------------------------------------------
# F16.3 — mirror target_port references an undeclared role.
# ---------------------------------------------------------------------------

def test_f16_3_mirror_unregistered_port_rejects():
    """Mirror verb with an unresolved target_port must NOT boot.

    The validator's check_action_target_port() (M14 C2 D43 path, file
    src/config/validator.cpp:315) folds any mirror `role_name` that
    isn't in `interface_roles` into ValidateError::kUnresolvedTargetPort.
    main.cpp (src/main.cpp:319-323) logs
    `{"error":"validate_err","message":"..."}` on stdout and exits 1
    BEFORE EAL launches or any port is registered. This test asserts
    that the failure mode is exactly that structured diagnostic.

    Shape mirrors F14.3 (test_f14_main_resolver.py:236-282).

    RED (this test in the RED commit): asserts stdout contains
    `_REJECT_DIAGNOSTIC_RED` ("M16C3_RED_IMPOSSIBLE_STRING_SENTINEL"),
    which never appears in the real diagnostic. GREEN flips this to
    `validate_err` + `phantom_mirror_port` substring checks, matching
    what main.cpp actually emits.
    """
    config = _config_reject_unregistered()

    binary = _find_binary()
    file_prefix = f"pktgate_f16_3_{time.monotonic_ns() % 10**9:09d}"

    tmpf = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    )
    json.dump(config, tmpf)
    tmpf.close()

    eal_args = _EAL_ARGS_TEMPLATE + ["--file-prefix", file_prefix]
    cmd = [binary] + eal_args + ["--config", tmpf.name]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )

    try:
        # The binary should exit fast — validation runs well before the
        # ~second-scale EAL init. 10 s is comfortable headroom under
        # any sanitiser.
        try:
            stdout_bytes, _ = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_bytes, _ = proc.communicate(timeout=5)

        stdout = (
            stdout_bytes.decode(errors="replace")
            if isinstance(stdout_bytes, bytes) else str(stdout_bytes)
        )

        # Primary contract — no silent boot with a dangling mirror target.
        assert proc.returncode is not None and proc.returncode != 0, (
            f"F16.3: expected non-zero exit on unresolved mirror "
            f"target_port, got rc={proc.returncode}. "
            f"stdout={stdout!r}"
        )

        # GREEN: the structured validator marker is the real one.
        # src/main.cpp:321 emits
        #   `{"error":"validate_err","message":"<validator text>"}`
        # on any ValidateError path; this is what F14.3 also checks
        # (tests/functional/test_f14_main_resolver.py:277-282). The
        # `validate_err` substring proves it's the validator tier,
        # NOT a parse error or a runtime resolver error.
        assert _REJECT_DIAGNOSTIC_REAL in stdout, (
            f"F16.3: expected diagnostic marker "
            f"{_REJECT_DIAGNOSTIC_REAL!r} in stdout; got "
            f"stdout={stdout!r}"
        )
        # Always assert that the offending role name surfaces — operator
        # readability invariant shared with F14.3.
        assert "phantom_mirror_port" in stdout, (
            f"F16.3: diagnostic must name the missing role. "
            f"stdout={stdout!r}"
        )
    finally:
        if os.path.exists(tmpf.name):
            os.unlink(tmpf.name)
