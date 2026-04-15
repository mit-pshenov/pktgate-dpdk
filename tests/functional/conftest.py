# tests/functional/conftest.py
#
# M3 C1 — PktgateProcess pytest fixture.
#
# Starts the pktgate_dpdk binary as a subprocess with a given config
# and EAL argv, waits for the "ready" log line, and provides helpers
# for sending signals and capturing output.
#
# Design anchors: harness.md §H1.5 (EAL argv), §H8 (dev-test.sh).

import json
import os
import signal
import subprocess
import tempfile
import time

import pytest


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
        self.eal_args = eal_args or []
        self.extra_args = extra_args or []
        self.timeout = timeout
        self.process = None
        self.stdout_text = ""
        self.stderr_text = ""
        self.returncode = None
        self._config_file = None
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

        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._collected_lines = []

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
                    remaining_out, remaining_err = self.process.communicate(timeout=1)
                    self.stdout_text = "\n".join(self._collected_lines) + "\n" + remaining_out
                    self.stderr_text = remaining_err
                    self.returncode = self.process.returncode
                    return False
                time.sleep(0.05)
        return False

    def _read_line_nonblocking(self):
        """Read a single line from stdout, non-blocking."""
        import select
        if self.process and self.process.stdout:
            r, _, _ = select.select([self.process.stdout], [], [], 0.1)
            if r:
                line = self.process.stdout.readline()
                if line:
                    return line.strip()
        return None

    def send_signal(self, sig=signal.SIGTERM):
        """Send a signal to the process."""
        if self.process and self.process.poll() is None:
            self.process.send_signal(sig)

    def wait_exit(self, timeout=None):
        """Wait for the process to exit and capture output."""
        timeout = timeout or self.timeout
        try:
            remaining_out, remaining_err = self.process.communicate(timeout=timeout)
            # Combine lines collected during wait_ready with remaining output.
            pre = "\n".join(self._collected_lines)
            if pre and remaining_out:
                self.stdout_text = pre + "\n" + remaining_out
            elif pre:
                self.stdout_text = pre + "\n"
            else:
                self.stdout_text = remaining_out
            self.stderr_text = remaining_err
            self.returncode = self.process.returncode
        except subprocess.TimeoutExpired:
            self.process.kill()
            remaining_out, remaining_err = self.process.communicate(timeout=5)
            pre = "\n".join(self._collected_lines)
            self.stdout_text = (pre + "\n" + (remaining_out or "")) if pre else (remaining_out or "")
            self.stderr_text = remaining_err or ""
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
        # Give EAL a moment to release hugepage mappings.
        time.sleep(0.2)


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
