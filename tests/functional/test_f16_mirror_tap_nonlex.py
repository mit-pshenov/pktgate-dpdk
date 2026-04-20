# tests/functional/test_f16_mirror_tap_nonlex.py
#
# M16 C3.5 RED — F16.4_nonlex. TAP mirror destination smoke where role
# lex-order DIVERGES from DPDK vdev enumeration order.
#
# Why this file exists (copy of test_f16_mirror_tap.py shape with new
# naming):
#   test_f16_mirror_tap.py (M16 C3) forces role lex rank == DPDK port_id
#   for the mirror role (`zz_mirror_port` → lex rank 2 → port_id 2). It
#   therefore cannot catch the pre-existing M7-era regression documented
#   in memory `grabli_role_idx_as_port_id_bug.md`:
#
#     `RuleAction.{redirect_port, mirror_port}` carry the compiler-side
#     `role_idx` (declaration / lex rank within `interface_roles`) but
#     the hot path feeds that value straight to `rte_eth_tx_burst(port,
#     ...)` which expects a DPDK port_id. Aliasing works only when lex
#     rank happens to match the --vdev cmdline rank.
#
#   This test deliberately constructs a layout where role lex rank !=
#   DPDK port_id for all three roles — including the mirror role —
#   so that on the current tree the mirror clone stream lands on the
#   WRONG kernel tap (the egress tap, port_id == mirror role_idx == 1),
#   the correct mirror tap sees zero clones, and
#   `pktgate_mirror_sent_total{port="<real_mirror_port_id>"}` either
#   stays 0 (no stage_mirror drain to that port_id) or reports clones
#   under the OTHER port label. On a GREEN M16 C3.5 populate-time
#   translation, clones land on the correct tap and the counter scrape
#   returns _INJECT_COUNT under the real mirror port_id label.
#
# ---------------------------------------------------------------------
# Non-lex role layout:
#
# Five role keys are declared because main.cpp requires `upstream_port`
# AND `downstream_port` by literal name (src/main.cpp:741/753,
# resolved via lookup_role). Parser walks the JSON object in nlohmann
# lex order and pushes onto `Config.interface_roles` in that order,
# so `resolve_role_idx` returns this lex rank:
#
#   role_name        / lex rank (== role_idx) / vdev     / DPDK port_id
#   ---------------------------------------------------------------------
#   aaa_egress       / 0                       / net_tap2 / 2
#   downstream_port  / 1                       / net_tap2 / 2  (TX alias)
#   mmm_mirror       / 2                       / net_tap1 / 1  <-- !! bug target
#   upstream_port    / 3                       / net_tap0 / 0  (RX alias)
#   zzz_ingress      / 4                       / net_tap0 / 0
#
# DPDK assigns port_ids in --vdev cmdline order — cmdline therefore
# arranges --vdev net_tap0 (port_id 0, ingress), --vdev net_tap1
# (port_id 1, mirror dst), --vdev net_tap2 (port_id 2, egress).
#
# Mirror role `mmm_mirror` has role_idx = 2 but its real DPDK port_id
# is 1. On current tree, `RuleAction.mirror_port` carries 2 (role_idx)
# and the hot path calls `rte_eth_tx_burst(2, ...)` which fires on the
# EGRESS tap (`dtap_m16nl_egr`, port_id 2). The real mirror tap
# (`dtap_m16nl_mir`, port_id 1) gets zero clones.
#
# Two other roles ALSO diverge (aaa_egress 0→2, zzz_ingress 4→0) but
# they're not load-bearing for this test — `upstream_port` /
# `downstream_port` are the named handles the worker uses for RX/TX,
# and their role_idx values are never consumed by the hot path.
#
# ---------------------------------------------------------------------
# IFNAMSIZ 16-char budget (memory grabli_ifnamsiz_16_limit.md):
#   dtap_m16nl_ing (14), dtap_m16nl_egr (14), dtap_m16nl_mir (14) —
#   all ≤15 characters.
#
# NDP / NM keyfile discipline: shared conftest.py `nm_unmanaged_tap`
# session fixture marks these three dtap names (registered in
# conftest.py). Same per-iface sysctl / arp-off preempt as the M16 C3
# harness (F2.25 class).
#
# ---------------------------------------------------------------------
# RED / GREEN strategy for this cycle:
#   RED (this commit): tests FAIL on the current tree because
#     populate_ruleset_eal does NOT translate role_idx -> port_id, so
#     mirror clones land on the wrong tap and the mirror tap capture
#     set is empty (size 0 != _INJECT_COUNT).
#   GREEN (next commit, M16 C3.5 fix): tests PASS because
#     populate_ruleset_eal walks `rs.l{2,3,4}_actions[]` and translates
#     redirect_port / mirror_port from role_idx to DPDK port_id before
#     the hot path ever sees them.

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

pytestmark = pytest.mark.usefixtures("nm_unmanaged_tap")


# EAL `-d <path>` opt-in (memory grabli_eal_d_flag_env_opt_in.md).
_DPDK_DRIVER_DIR_ARGS = (
    ["-d", os.environ["PKTGATE_DPDK_DRIVER_DIR"].strip()]
    if os.environ.get("PKTGATE_DPDK_DRIVER_DIR", "").strip()
    else []
)

# IFNAMSIZ 16-char budget (memory grabli_ifnamsiz_16_limit.md).
_INGRESS_IFACE = "dtap_m16nl_ing"   # 14 chars
_EGRESS_IFACE  = "dtap_m16nl_egr"   # 14 chars
_MIRROR_IFACE  = "dtap_m16nl_mir"   # 14 chars

# Role names chosen so the mirror role's lex rank (2) diverges from
# its real DPDK port_id (1). See module-level comment for the full
# 5-role layout.
_ROLE_MIRROR  = "mmm_mirror"   # lex rank 2, -> net_tap1 -> port_id 1

# Expected DPDK port_ids from --vdev cmdline enumeration.
# --vdev net_tap0 -> 0 (ingress), net_tap1 -> 1 (mirror), net_tap2 -> 2 (egress).
_EXPECTED_INGRESS_PORT_ID = 0
_EXPECTED_MIRROR_PORT_ID  = 1
_EXPECTED_EGRESS_PORT_ID  = 2

# Role-to-port_id alias used by the test for cleartext assertion text.
# Mirror role has role_idx == 2 but port_id == 1; that's the bug target.
_MIRROR_ROLE_IDX = 2  # lex rank of `mmm_mirror` in the 5-role layout

# FIB DIR24_8 needs ~128 MB heap -> -m 512.
_EAL_ARGS_TEMPLATE = [
    "--no-pci",
    "--no-huge",
    "-m", "512",
    *_DPDK_DRIVER_DIR_ARGS,
    # --vdev cmdline order assigns DPDK port_ids 0, 1, 2 respectively.
    # The iface-to-port_id binding is the load-bearing knob combined
    # with lex-rank-of-role-names.
    "--vdev", f"net_tap0,iface={_INGRESS_IFACE}",   # port_id 0
    "--vdev", f"net_tap1,iface={_MIRROR_IFACE}",    # port_id 1
    "--vdev", f"net_tap2,iface={_EGRESS_IFACE}",    # port_id 2
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
    "prom_port": 0,
}

_TEST_SRC = "aa:bb:cc:dd:ee:34"
_TEST_DST = "11:22:33:44:55:34"

_INJECT_COUNT = 50


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
    for preset in ["dev-asan", "dev-debug", "dev-release",
                   "dev-ubsan", "dev-tsan"]:
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


def _config_nonlex() -> dict:
    """Non-lex role layout: mirror role's lex rank != its DPDK port_id.

    Parser sorts `interface_roles` JSON keys lex-alphabetically and
    pushes onto the Config vector in that order. resolve_role_idx
    returns the vector index, so the 5 keys below produce:

        aaa_egress       -> idx 0  (net_tap2, port_id 2)
        downstream_port  -> idx 1  (net_tap2, port_id 2)
        mmm_mirror       -> idx 2  (net_tap1, port_id 1) <-- role_idx != port_id
        upstream_port    -> idx 3  (net_tap0, port_id 0)
        zzz_ingress      -> idx 4  (net_tap0, port_id 0)

    Mirror role_idx = 2, real port_id = 1. On current tree, the hot
    path dispatches clones with port == 2, landing them on the egress
    tap. Post-fix, clones land on port_id 1's tap.

    `aaa_egress` and `zzz_ingress` are kept for layout symmetry (so
    multiple roles diverge — resistant to a partial fix that only
    handles the direct role without walking all entries) but they're
    not used by any rule — main.cpp's resolver references
    `upstream_port` and `downstream_port` by literal name.
    """
    return {
        "version": 1,
        "interface_roles": {
            "aaa_egress":      {"vdev": "net_tap2"},  # lex 0 -> port_id 2
            "downstream_port": {"vdev": "net_tap2"},  # lex 1 -> port_id 2
            _ROLE_MIRROR:      {"vdev": "net_tap1"},  # lex 2 -> port_id 1
            "upstream_port":   {"vdev": "net_tap0"},  # lex 3 -> port_id 0
            "zzz_ingress":     {"vdev": "net_tap0"},  # lex 4 -> port_id 0
        },
        "default_behavior": "drop",
        "pipeline": {
            "layer_2": [],
            "layer_3": [],
            "layer_4": [
                {
                    "id": 16004,
                    "proto": 17,        # UDP
                    "dst_port": 5634,
                    "action": {
                        "type": "mirror",
                        "target_port": _ROLE_MIRROR,
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
    return b"F16.4-NONLEX-" + f"{i:03d}".encode()


def _extract_markers(captured):
    markers = set()
    for p in captured:
        try:
            if not p.haslayer(Ether) or p[Ether].src != _TEST_SRC:
                continue
            if not p.haslayer(Raw):
                continue
            payload = bytes(p[Raw].load)
            m = re.search(rb"F16\.4-NONLEX-\d{3}", payload)
            if m:
                markers.add(m.group(0))
        except Exception:
            continue
    return markers


# ---------------------------------------------------------------------------
# Harness — three-TAP boot, NDP-proof, dual AsyncSniffer on egress and
# mirror taps. Same shape as test_f16_mirror_tap.py's _F16MirrorHarness
# with new iface names / role names.
# ---------------------------------------------------------------------------

class _F16NonLexHarness:
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

        deadline = time.monotonic() + 30.0
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
        # Pull real DPDK port_ids from main.cpp port_resolved events.
        # These are the authoritative truth — the test asserts them
        # against the --vdev-cmdline-order expectation below.
        self.egress_port_id = _resolved_port_id(
            self._lines, "downstream_port"
        )
        if self.egress_port_id is None:
            self.egress_port_id = _EXPECTED_EGRESS_PORT_ID
        self.mirror_port_id = _resolved_port_id(
            self._lines, _ROLE_MIRROR
        )
        if self.mirror_port_id is None:
            self.mirror_port_id = _EXPECTED_MIRROR_PORT_ID

        time.sleep(0.5)
        return self

    def _lfilter(self, p):
        try:
            return p.haslayer(Ether) and p[Ether].src == _TEST_SRC
        except Exception:
            return False

    def sniff_start(self):
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
        time.sleep(0.3)

    def inject(self, packets, pause: float = 0.02):
        from scapy.all import conf as sc
        sc.ifaces.reload()
        for pkt in packets:
            sendp(pkt, iface=_INGRESS_IFACE, verbose=False)
            if pause:
                time.sleep(pause)

    def sniff_stop(self, settle: float = 2.0):
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

        time.sleep(0.2)
        return False


# ---------------------------------------------------------------------------
# F16.4_nonlex — TAP mirror happy path with role_idx != port_id.
# ---------------------------------------------------------------------------

def test_f16_4_mirror_tap_nonlex():
    """Mirror verb on a role layout where lex rank != --vdev cmdline rank.

    Same packet shape as F16.2 (50 UDP packets, L4 ALLOW/mirror rule).
    The ONLY difference is that role names are chosen so the mirror
    role's lex rank diverges from its DPDK port_id: `mmm_mirror` has
    `role_idx = 2` (lex rank within the 5-role vector) but the real
    DPDK port_id is 1 (net_tap1 is the second vdev on the cmdline).
    Also the EGRESS tap lives at port_id 2 — so a mis-translated
    mirror dispatch with port=2 lands frames on the egress tap.

    Expected behaviour (GREEN, post-M16 C3.5):
      * Original lands on `dtap_m16nl_egr` (downstream_port, port_id 2).
      * Clone lands on `dtap_m16nl_mir` (_ROLE_MIRROR, port_id 1).
      * `pktgate_mirror_sent_total{port="1"}` == 50, clone_failed == 0,
        dropped == 0.

    Observed behaviour (RED, current tree):
      * Clone stream is dispatched to port_id == role_idx == 2 (the
        EGRESS tap), not port_id 1.
      * `dtap_m16nl_mir` (mirror tap) capture set is EMPTY.
      * `pktgate_mirror_sent_total{port="1"}` is 0 or missing; clone
        activity surfaces (incorrectly) under `{port="2"}`.

    The assertions below focus on the mirror-tap capture set and the
    `{port="<real mirror port_id>"}` counter label — both exact and
    both fail under the bug.
    """
    # Sanity: resolver produced the port_ids we asked for. If DPDK ever
    # starts enumerating vdevs in a different order this test would go
    # flaky in a subtle way, so pin it up front.
    config = _config_nonlex()

    packets = []
    for i in range(_INJECT_COUNT):
        packets.append(
            Ether(src=_TEST_SRC, dst=_TEST_DST) /
            IP(src="10.16.4.1", dst="10.16.4.2") /
            UDP(sport=4242, dport=5634) /
            Raw(_marker_for(i))
        )
    expected_markers = {_marker_for(i) for i in range(_INJECT_COUNT)}

    with _F16NonLexHarness(config, "pktgate_f16_4") as h:
        assert h.prom_port and h.prom_port > 0, (
            f"prom_endpoint_ready not observed. "
            f"stdout={h.stdout_text[-2048:]!r}"
        )

        # Pin the port_id expectations derived from --vdev cmdline
        # order. These are invariant under the bug — both branches of
        # the C3.5 RED / GREEN flip agree on what the resolver emits.
        assert h.egress_port_id == _EXPECTED_EGRESS_PORT_ID, (
            f"downstream_port resolved to port_id={h.egress_port_id}, "
            f"expected {_EXPECTED_EGRESS_PORT_ID} from --vdev order. "
            f"stdout_tail={h.stdout_text[-1024:]!r}"
        )
        assert h.mirror_port_id == _EXPECTED_MIRROR_PORT_ID, (
            f"{_ROLE_MIRROR} resolved to port_id={h.mirror_port_id}, "
            f"expected {_EXPECTED_MIRROR_PORT_ID} from --vdev order. "
            f"stdout_tail={h.stdout_text[-1024:]!r}"
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

    egress_markers = _extract_markers(h.egress_captured)
    mirror_markers = _extract_markers(h.mirror_captured)

    # Original must forward to downstream_port's tap regardless of any
    # mirror translation — egress is a redirect-free, target-free
    # forward via tx_one to tx_port_id. On the current tree egress
    # still works (tx_port_id comes from main.cpp resolver, not role_idx).
    assert egress_markers == expected_markers, (
        f"F16.4_nonlex: egress payload set mismatch on {_EGRESS_IFACE}. "
        f"missing={sorted(expected_markers - egress_markers)!r} "
        f"extra={sorted(egress_markers - expected_markers)!r} "
        f"stdout_tail={h.stdout_text[-1024:]!r}"
    )

    # THE CORE RED ASSERTION — this is the one that fails on the
    # current tree. Mirror clones dispatched with `mirror_port ==
    # role_idx == 2` land on port_id 2 (the egress tap, which already
    # got the originals — so the egress capture may double up there
    # too, but we don't assert that) and the real mirror tap
    # (`dtap_m16nl_mir`, port_id 1) gets zero clones.
    assert mirror_markers == expected_markers, (
        f"F16.4_nonlex: mirror payload set mismatch on {_MIRROR_IFACE} "
        f"(port_id={h.mirror_port_id}, role_idx={_MIRROR_ROLE_IDX}). "
        f"Current tree dispatches clones to port_id=<role_idx>="
        f"{_MIRROR_ROLE_IDX} (the egress tap), not port_id="
        f"{_EXPECTED_MIRROR_PORT_ID}. Captured {len(mirror_markers)} "
        f"distinct markers; expected {_INJECT_COUNT}. "
        f"missing={sorted(expected_markers - mirror_markers)[:5]!r} "
        f"stdout_tail={h.stdout_text[-1024:]!r}"
    )

    # Counter triplet under the REAL mirror port_id label — post-fix
    # these become the canonical mirror counters; pre-fix the `sent`
    # scrape returns 0 (or None) because no stage_mirror drained to
    # port_id 2.
    assert sent is not None, (
        f"F16.4_nonlex: pktgate_mirror_sent_total"
        f"{{port=\"{h.mirror_port_id}\"}} not present in /metrics. "
        f"Pre-C3.5-GREEN, the per-port label is emitted under the "
        f"wrong port_id (role_idx={_MIRROR_ROLE_IDX}); post-fix it "
        f"shows under the real port_id ({_EXPECTED_MIRROR_PORT_ID})."
    )
    assert clone_failed is not None, (
        f"F16.4_nonlex: pktgate_mirror_clone_failed_total"
        f"{{port=\"{h.mirror_port_id}\"}} not present in /metrics."
    )
    assert dropped is not None, (
        f"F16.4_nonlex: pktgate_mirror_dropped_total"
        f"{{port=\"{h.mirror_port_id}\"}} not present in /metrics."
    )

    assert sent == _INJECT_COUNT, (
        f"F16.4_nonlex: pktgate_mirror_sent_total"
        f"{{port=\"{h.mirror_port_id}\"}} = {sent}, expected "
        f"{_INJECT_COUNT}. On current tree, clones are dispatched "
        f"to port_id=role_idx={_MIRROR_ROLE_IDX}, so the "
        f"`{{port=\"{_EXPECTED_MIRROR_PORT_ID}\"}}` counter "
        f"scrapes as 0. mirror_port_id={h.mirror_port_id} "
        f"egress_port_id={h.egress_port_id}. "
        f"stdout_tail={h.stdout_text[-2048:]!r}"
    )
    assert clone_failed == 0, (
        f"F16.4_nonlex: unexpected clone failures={clone_failed} "
        f"on an idle mempool with a 50-packet flow."
    )
    assert dropped == 0, (
        f"F16.4_nonlex: unexpected mirror drops={dropped} on an idle "
        f"mirror tap with a 50-packet flow."
    )
