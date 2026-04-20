# tests/functional/conftest.py
#
# M3 C1 — PktgateProcess pytest fixture.
#
# Starts the pktgate_dpdk binary as a subprocess with a given config
# and EAL argv, waits for the "ready" log line, and provides helpers
# for sending signals and capturing output.
#
# Design anchors: harness.md §H1.5 (EAL argv), §H8 (dev-test.sh).

import fcntl
import json
import os
import signal
import subprocess
import tempfile
import time

import pytest


# ---------------------------------------------------------------------------
# EAL driver-directory opt-in helper — shared across functional + chaos tests
# ---------------------------------------------------------------------------
#
# The dev VM runs a dual DPDK 25.11 install (2026-04-19 onward, memory
# `vm_dpdk_layout.md`): build-tree at `/home/mit/Dev/dpdk-25.11/build/drivers/`
# AND `/usr/local/lib64/dpdk/pmds-*/`. `/etc/ld.so.conf.d/dpdk-dev.conf`
# already exposes the build-tree PMDs via ldconfig; explicitly passing
# `-d <path>` on top of that double-loads every PMD `.so` and trips EAL's
# tailq double-registration panic:
#
#   EAL: VFIO_CDX_RESOURCE_LIST tailq is already registered
#   EAL: PANIC in tailqinitfn_cdx_vfio_tailq()
#
# Policy: `-d` is **opt-in** via PKTGATE_DPDK_DRIVER_DIR. Default: empty →
# rely on ldconfig. Operators pointing at a non-ldconfig DPDK install set
# the env and the argv picks it up explicitly.
#
# `pktgate_eal_driver_args()` returns `["-d", path]` or `[]`. Shared by
# PktgateProcess (below) and by tests that build their own subprocess
# cmdline (test_f2_l2, test_f2_l4, test_f3_action, test_f4_l3,
# test_f8_qinq_counter, test_f14_tap_exit).
def pktgate_eal_driver_args():
    path = os.environ.get("PKTGATE_DPDK_DRIVER_DIR", "").strip()
    if path:
        return ["-d", path]
    return []


def _strip_legacy_driver_flag(eal_args):
    """Remove any inline `-d <path>` pair that predates the opt-in helper.

    Historical test modules hard-coded `"-d", DPDK_DRIVER_DIR` directly in
    their EAL argv templates (pre-2026-04-19 single-install layout). The
    fixup keeps those hard-codes for backwards reference but strips them
    here so the run-time argv obeys the opt-in policy. If
    PKTGATE_DPDK_DRIVER_DIR is set, the caller gets the env-driven path
    back (via `pktgate_eal_driver_args()` prepended below); otherwise
    nothing is injected and EAL uses ldconfig.
    """
    if not eal_args:
        return list(eal_args or [])
    out = []
    i = 0
    while i < len(eal_args):
        if eal_args[i] == "-d" and i + 1 < len(eal_args):
            i += 2  # drop the pair
            continue
        out.append(eal_args[i])
        i += 1
    return out


# ---------------------------------------------------------------------------
# M4 C8 — NetworkManager unmanaged-devices fixture for F2 L2 tests
# ---------------------------------------------------------------------------
#
# DPDK net_tap creates kernel tap interfaces (e.g. dtap_f2_rx / dtap_f2_tx).
# The moment NetworkManager sees them it starts managing them like any other
# NIC and fires DHCPv4 / IPv6 RS.  Those background frames land in the DPDK
# RX ring and contaminate per-rule counter assertions non-deterministically
# across tests in a full session run.
#
# Fix: write an NM keyfile marking the test interface names as unmanaged for
# the whole pytest session.  The fixture is session-scoped and NOT autouse —
# modules that need it (tests/functional/test_f2_l2.py) opt in via
# `pytestmark = pytest.mark.usefixtures("nm_unmanaged_tap")`.
#
# Rationale for keyfile vs. `nmcli device set`: the tap device only exists
# between binary start and shutdown; a keyfile is applied declaratively as
# soon as NM sees the device appear, closing the race window DHCP would
# otherwise race through.
#
# Root cause note salvaged from M4 C8 aborted attempt 2026-04-13:
# `scratch/c8-salvage/nm_unmanaged_tap.md`.

_NM_CONF_PATH = "/etc/NetworkManager/conf.d/pktgate_test_unmanaged.conf"
_TAP_IFACES_TO_UNMANAGE = [
    "dtap_f2_rx", "dtap_f2_tx",
    # M4 C9 — F8.14 QinQ counter visibility test uses its own dtap pair.
    "dtap_f8_rx", "dtap_f8_tx",
    # M10 C5 — F8.14 /metrics scrape arm uses a separate dtap pair so it
    # runs alongside the M4 C9 stats_on_exit arm in the same session.
    "dtap_f8m_rx", "dtap_f8m_tx",
    # M5 C10 — F4 L3 functional tests use their own dtap pair.
    "dtap_f4_rx", "dtap_f4_tx",
    # M6 C5 — F2 L4 functional tests use their own dtap pair.
    "dtap_l4_rx", "dtap_l4_tx",
    # M7 C3 — F3 action functional tests (ALLOW/DROP/TAG). Egress tap
    # is *sniffed* via scapy.sniff() to verify apply_action actually
    # forwards/tags/drops packets end-to-end (not just counter deltas).
    "dtap_f3_rx", "dtap_f3_tx",
    # M7 C4 — F3.9/F3.10 REDIRECT tests need a third tap so REDIRECT's
    # target port resolves to something different from the default
    # egress (dtap_f3_tx). Sniffed independently.
    "dtap_f3_redir",
    # M9 C5 — F3.12-F3.16 rate-limit tests use their own dtap pair so
    # they don't collide with F3.1-F3.10 harnesses run in the same
    # session. Separate pair keeps the NM keyfile session-scoped and
    # lets the ctest entries run in any order.
    "dtap_f3rl_rx", "dtap_f3rl_tx",
    # M14 C4 — F14.6 / F14.7 TAP deployment profile smoke. Separate
    # pair so the test module can run alongside any other dtap_*
    # functional entry in the same session without sharing taps.
    "dtap_m14_ing", "dtap_m14_egr",
    # M15 C3 — integration.test_m15_vhost_pair. Single ingress tap
    # (downstream is a vhost UDS, no egress tap needed). Name-scoped
    # to the M15 cycle so it doesn't collide with M14 taps in a
    # shared session run.
    "dtap_m15_ing",
    # M15 C4 — integration.test_m15_vhost_peer_crash. Separate ingress
    # tap so C3 and C4 tests can cohabitate in a shared session without
    # racing on each other's bring-up. Downstream is a vhost UDS.
    # Short name: IFNAMSIZ is 16 incl NUL, so the 15-char budget
    # rules out "dtap_m15_crash_ing" (18).
    "dtap_m15c_ing",
    # M16 C3 — functional.test_f16_mirror_tap (mirror destination
    # smoke). Three dtaps: ingress / egress / mirror. All ≤15 chars
    # (IFNAMSIZ budget, memory grabli_ifnamsiz_16_limit.md). Separate
    # names from the C4/C5 chaos cycle fixtures so M16 tests run in
    # any order in a shared session.
    "dtap_m16_ing", "dtap_m16_egress", "dtap_m16_mirror",
    # M16 C3.5 — functional.test_f16_mirror_tap_nonlex. Same three-tap
    # shape as C3 but with dtap names distinct so session fixtures
    # don't collide; role names are lex-chosen so role_idx != port_id
    # for every role (RED test for the populate_ruleset_eal translation
    # step). All names 14 chars (IFNAMSIZ budget).
    "dtap_m16nl_ing", "dtap_m16nl_egr", "dtap_m16nl_mir",
    # M16 C4 — chaos.test_m16_mirror_port_gone. Three dtaps; mid-stream
    # the mirror tap's link is brought down to force rte_eth_tx_burst
    # short-burst drains on the mirror drain path. Separate dtap names
    # from the C3 / C3.5 / C5 cycles so all of them co-exist in one
    # shared session. All names 13 chars (IFNAMSIZ budget).
    "dtap_m16c_ing", "dtap_m16c_egr", "dtap_m16c_mir",
    # M16 C4 — chaos.test_m16_mirror_mempool_exhaust. Three dtaps;
    # tiny mbuf pool forces rte_pktmbuf_copy to return null, bumping
    # mirror_clone_failed_total. Namespaced distinct from
    # port_gone so tests are session-safe back-to-back.
    "dtap_m16m_ing", "dtap_m16m_egr", "dtap_m16m_mir",
    # M16 C5 — chaos.test_m16_mirror_slow_consumer. Three dtaps;
    # mirror tap txqueuelen=1 at boot (link UP) constricts kernel
    # drain, forcing mirror_drain short-bursts; mid-stream release
    # restores default queue length and sent bumps resume. Distinct
    # from port_gone's link-down signal; see memory
    # grabli_tap_tbf_wrong_side.md for recipe rationale.
    "dtap_m16s_ing", "dtap_m16s_egr", "dtap_m16s_mir",
]


@pytest.fixture(scope="session", autouse=False)
def nm_unmanaged_tap():
    """Mark DPDK functional-test tap interfaces as NM-unmanaged for the session."""
    nm_conf_written = False
    try:
        iface_spec = ",".join(
            f"interface-name:{n}" for n in _TAP_IFACES_TO_UNMANAGE
        )
        with open(_NM_CONF_PATH, "w") as f:
            f.write("[keyfile]\n")
            f.write(f"unmanaged-devices={iface_spec}\n")
        subprocess.run(
            ["nmcli", "general", "reload", "conf"],
            capture_output=True,
        )
        nm_conf_written = True
    except OSError:
        # Not writable (e.g. non-root CI): best-effort, test may contaminate.
        pass

    yield

    if nm_conf_written:
        try:
            os.unlink(_NM_CONF_PATH)
            subprocess.run(
                ["nmcli", "general", "reload", "conf"],
                capture_output=True,
            )
        except OSError:
            pass


def find_binary():
    """Find the pktgate_dpdk binary. Prefers PKTGATE_BINARY env var (set by
    CMake) so ctest runs the binary matching the active preset."""
    # Primary: env var set by CMakeLists.txt (generator expression).
    env_path = os.environ.get("PKTGATE_BINARY")
    if env_path and os.path.isfile(env_path):
        return env_path
    # Fallback: scan build directories.
    base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for preset in ["dev-asan", "dev-debug", "dev-release", "dev-ubsan", "dev-tsan"]:
        path = os.path.join(base, "build", preset, "pktgate_dpdk")
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    pytest.skip("pktgate_dpdk binary not found in any build directory")


class PktgateProcess:
    """Manages a pktgate_dpdk subprocess for functional testing."""

    def __init__(self, config_dict, eal_args=None, extra_args=None, timeout=10):
        self.config_dict = config_dict
        # Normalise EAL argv: strip any hard-coded `-d <path>` pair and
        # re-inject it only when the operator opts in via
        # PKTGATE_DPDK_DRIVER_DIR. Rationale in the module-level comment
        # next to `pktgate_eal_driver_args()`.
        self.eal_args = (
            pktgate_eal_driver_args()
            + _strip_legacy_driver_flag(eal_args or [])
        )
        self.extra_args = extra_args or []
        self.timeout = timeout
        self.process = None
        self.stdout_text = ""
        self.stderr_text = ""
        self.returncode = None
        self._config_file = None
        self._stderr_file = None
        self._binary = find_binary()

    def start(self):
        """Write config and start the binary."""
        self._config_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        )
        json.dump(self.config_dict, self._config_file)
        self._config_file.close()

        cmd = [self._binary] + self.eal_args + [
            "--config", self._config_file.name
        ] + self.extra_args

        # stderr goes to a temp file rather than a PIPE.  Under dev-tsan,
        # EAL + TSan runtime can dump >64 kB of diagnostics into stderr
        # during cold-start; if the test harness does not drain the
        # stderr PIPE concurrently, the binary blocks inside write(2)
        # on a full pipe and stdout progress stalls as a side effect
        # (observed as "wait_ready empty stdout/stderr" under ctest).
        # A file has no backpressure, so the binary never blocks on log
        # output regardless of sanitiser chatter.
        self._stderr_file = tempfile.NamedTemporaryFile(
            mode="w+", suffix=".stderr", delete=False
        )
        # Binary mode (no text=True) + fcntl O_NONBLOCK on stdout so the
        # harness can use os.read() directly.  Using Popen's TextIOWrapper
        # readline() combined with select() misses lines that arrive in a
        # burst: select returns readable once, readline() drains the kernel
        # pipe into the TextIOWrapper's 8 KB buffer, returns a single line,
        # and leaves the rest buffered.  Subsequent select() calls see an
        # empty kernel fd and sleep forever while the remaining lines
        # (including {"ready":true}) sit unread in user-space buffer.
        # Observed under dev-tsan F8 suite where pktgate emits 7 startup
        # log_json lines within ~0.2 s — all batch into one kernel read.
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=self._stderr_file,
        )
        fd = self.process.stdout.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        self._stdout_buf = b""
        self._collected_lines = []

    def _drain_stderr_file(self):
        """Read whatever is currently in the stderr temp-file into
        self.stderr_text, if the file is open."""
        if not self._stderr_file:
            return ""
        try:
            self._stderr_file.flush()
            with open(self._stderr_file.name, "r", errors="replace") as fh:
                return fh.read()
        except OSError:
            return ""

    def wait_ready(self, timeout=None):
        """Wait for the 'ready' log line in stdout."""
        timeout = timeout or self.timeout
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            line = self._read_line_nonblocking()
            if line is not None:
                self._collected_lines.append(line)
                if '"ready":true' in line or '"ready": true' in line:
                    return True
            else:
                # Check if process exited
                if self.process.poll() is not None:
                    # Process exited before ready
                    remaining_bytes, _ = self.process.communicate(timeout=1)
                    tail = (self._stdout_buf + (remaining_bytes or b"")
                            ).decode("utf-8", errors="replace")
                    self.stdout_text = "\n".join(self._collected_lines) + "\n" + tail
                    self.stderr_text = self._drain_stderr_file()
                    self.returncode = self.process.returncode
                    return False
                time.sleep(0.05)
        # Timed out without ready: make stdout/stderr available for the
        # caller's assertion message so a hang is debuggable instead of
        # silent ("stdout='' stderr=''").  Some tests call wait_ready
        # with a bare assert (no f-string), so print the dump here too
        # so the ctest log captures it unconditionally.
        self.stdout_text = "\n".join(self._collected_lines)
        self.stderr_text = self._drain_stderr_file()
        return False

    def _read_line_nonblocking(self):
        """Return one line from stdout, or None if none buffered / pending.

        Uses os.read on the raw fd + an internal byte buffer rather than
        proc.stdout.readline() — the latter's TextIOWrapper drains the
        kernel pipe into an 8 KB buffer on the first readable notify and
        subsequent select() calls see the empty kernel fd, never handing
        back the buffered tail (silently losing {"ready":true} under
        burst-emission cold-start conditions).
        """
        import select
        # 1. Emit any complete line already in the byte buffer.
        if b"\n" in self._stdout_buf:
            line, self._stdout_buf = self._stdout_buf.split(b"\n", 1)
            return line.decode("utf-8", errors="replace").strip()
        if not (self.process and self.process.stdout):
            return None
        # 2. Pump more bytes if the kernel fd is readable.
        fd = self.process.stdout.fileno()
        r, _, _ = select.select([fd], [], [], 0.1)
        if not r:
            return None
        try:
            data = os.read(fd, 4096)
        except BlockingIOError:
            return None
        if not data:
            return None
        self._stdout_buf += data
        if b"\n" in self._stdout_buf:
            line, self._stdout_buf = self._stdout_buf.split(b"\n", 1)
            return line.decode("utf-8", errors="replace").strip()
        return None

    def send_signal(self, sig=signal.SIGTERM):
        """Send a signal to the process."""
        if self.process and self.process.poll() is None:
            self.process.send_signal(sig)

    def wait_exit(self, timeout=None):
        """Wait for the process to exit and capture output."""
        timeout = timeout or self.timeout
        try:
            remaining_bytes, _ = self.process.communicate(timeout=timeout)
            tail = (self._stdout_buf + (remaining_bytes or b"")
                    ).decode("utf-8", errors="replace")
            pre = "\n".join(self._collected_lines)
            if pre and tail:
                self.stdout_text = pre + "\n" + tail
            elif pre:
                self.stdout_text = pre + "\n"
            else:
                self.stdout_text = tail
            self.stderr_text = self._drain_stderr_file()
            self.returncode = self.process.returncode
        except subprocess.TimeoutExpired:
            self.process.kill()
            remaining_bytes, _ = self.process.communicate(timeout=5)
            tail = (self._stdout_buf + (remaining_bytes or b"")
                    ).decode("utf-8", errors="replace")
            pre = "\n".join(self._collected_lines)
            self.stdout_text = (pre + "\n" + tail) if pre else tail
            self.stderr_text = self._drain_stderr_file()
            self.returncode = self.process.returncode

    def stop(self):
        """Send SIGTERM and wait for clean exit."""
        self.send_signal(signal.SIGTERM)
        self.wait_exit()

    def cleanup(self):
        """Kill process if still running, remove temp files."""
        if self.process and self.process.poll() is None:
            self.process.kill()
            try:
                self.process.communicate(timeout=5)
            except Exception:
                pass
        if self._config_file and os.path.exists(self._config_file.name):
            os.unlink(self._config_file.name)
        # Close and remove the stderr backing file now that stderr_text
        # has been captured (or can be re-read on demand from the path).
        if self._stderr_file is not None:
            try:
                self._stderr_file.close()
            except OSError:
                pass
            try:
                os.unlink(self._stderr_file.name)
            except OSError:
                pass
            self._stderr_file = None
        # Drain leaked per-process DPDK runtime dirs from this pktgate
        # instance's file-prefix.  With `--no-huge` the EAL writes its
        # fbarray / config files under $XDG_RUNTIME_DIR/dpdk/<prefix>/
        # rather than /run/dpdk/.  Nothing cleans them after SIGTERM,
        # so successive tests accumulate an ever-growing pool that can
        # slow EAL init (stat + namespace scan) and, under dev-tsan,
        # push worker cold-start past the 30 s wait_ready budget.
        self._cleanup_dpdk_runtime_dir()
        # Give EAL a moment to release hugepage mappings.
        time.sleep(0.2)

    def _cleanup_dpdk_runtime_dir(self):
        """Remove this instance's per-prefix DPDK runtime dir if it was
        pointed at one via `--file-prefix`."""
        prefix = None
        eal = self.eal_args or []
        for i, a in enumerate(eal):
            if a == "--file-prefix" and i + 1 < len(eal):
                prefix = eal[i + 1]
                break
        if not prefix:
            return
        xdg = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
        candidates = [
            os.path.join(xdg, "dpdk", prefix),
            os.path.join("/run/dpdk", prefix),
            os.path.join("/var/run/dpdk", prefix),
        ]
        for path in candidates:
            if os.path.isdir(path):
                try:
                    import shutil
                    shutil.rmtree(path, ignore_errors=True)
                except OSError:
                    pass


@pytest.fixture
def pktgate_process():
    """Fixture that yields a PktgateProcess factory and handles cleanup."""
    processes = []

    def factory(config_dict, eal_args=None, extra_args=None, timeout=10):
        proc = PktgateProcess(config_dict, eal_args, extra_args, timeout)
        processes.append(proc)
        return proc

    yield factory

    for proc in processes:
        proc.cleanup()
