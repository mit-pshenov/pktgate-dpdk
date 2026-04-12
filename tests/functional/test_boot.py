# tests/functional/test_boot.py
#
# M3 C1 — F1.1 Happy-path EAL init on dev VM.
#
# Setup: minimal config (default_behavior=drop, no rules), two net_pcap
# vdevs, sizing at dev defaults. One worker.
# Action: start binary; wait for "ready":true log line; send SIGTERM.
# Assertion: exit code 0; log contains eal_init_ok, ports_started=2,
# ruleset_published generation=1; total wall time < 5 s.

import os
import time


# Minimal valid config: version 1, two roles (vdev), default_behavior=drop,
# empty pipeline. Sizing defaults are filled by the parser.
MINIMAL_CONFIG = {
    "version": 1,
    "interface_roles": {
        "upstream_port": {"vdev": "net_null0"},
        "downstream_port": {"vdev": "net_null1"},
    },
    "default_behavior": "drop",
    "pipeline": {
        "layer_2": [],
        "layer_3": [],
        "layer_4": [],
    },
}

# Default DPDK driver directory. The dev VM's DPDK 25.11 is a shared build
# with drivers as separate .so files — EAL needs `-d <path>` to find them.
# Production (system-installed DPDK) has drivers in a well-known path;
# the dev VM doesn't.
DPDK_DRIVER_DIR = os.environ.get(
    "DPDK_DRIVER_DIR", "/home/mit/Dev/dpdk-25.11/build/drivers/"
)

# EAL argv for functional tests with net_null vdevs.
# --no-pci: don't probe PCI devices.
# -d: load PMD drivers from the build tree.
# --vdev net_null0/net_null1: create two null vdevs (no real traffic —
#   F1.1 only needs the binary to boot with 2 ports).
# -l 0,1: use lcores 0 and 1 (main + one worker).
# Note: harness.md §H1.5 prefers net_pcap for traffic-carrying tests,
# but net_pcap PMD requires DPDK to be built with libpcap. The dev VM's
# DPDK was compiled without it, so F1.1 (no-traffic boot test) uses
# net_null. Traffic-carrying tests (M4+) will rebuild DPDK with pcap.
EAL_ARGS = [
    "--no-pci",
    "--no-huge",
    "-m", "64",
    "-d", DPDK_DRIVER_DIR,
    "--vdev", "net_null0",
    "--vdev", "net_null1",
    "-l", "0,1",
    "--log-level", "lib.*:error",
    "--file-prefix", "pktgate_test",
]


def test_f1_1_happy_boot(pktgate_process):
    """F1.1: Happy-path EAL init — boot, ready, SIGTERM, exit 0."""
    t0 = time.monotonic()

    proc = pktgate_process(MINIMAL_CONFIG, eal_args=EAL_ARGS)
    proc.start()

    ready = proc.wait_ready(timeout=10)
    assert ready, (
        f"Binary did not reach 'ready' state. "
        f"exit={proc.returncode}, stdout={proc.stdout_text!r}, "
        f"stderr={proc.stderr_text!r}"
    )

    # Send SIGTERM for clean shutdown.
    proc.stop()

    elapsed = time.monotonic() - t0

    # Assertions per F1.1 spec:
    assert proc.returncode == 0, (
        f"Expected exit 0, got {proc.returncode}. "
        f"stdout={proc.stdout_text!r}, stderr={proc.stderr_text!r}"
    )

    # Check structured log events.
    stdout = proc.stdout_text
    assert "eal_init_ok" in stdout, f"Missing eal_init_ok in: {stdout!r}"
    assert "ports_started" in stdout, f"Missing ports_started in: {stdout!r}"
    assert '"ports_started":2' in stdout or '"ports_started": 2' in stdout, (
        f"Expected ports_started=2 in: {stdout!r}"
    )
    assert "ruleset_published" in stdout, f"Missing ruleset_published in: {stdout!r}"
    assert "generation" in stdout, f"Missing generation in: {stdout!r}"

    # Wall time budget: < 5 s (generous for dev VM).
    assert elapsed < 5.0, f"Boot+shutdown took {elapsed:.1f}s, budget is 5s"
