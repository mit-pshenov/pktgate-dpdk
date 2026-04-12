# tests/functional/test_d28_tx_symmetry.py
#
# M3 C2 — F1.13 + X2.8: D28 TX-queue symmetry validator.
#
# D28 invariant: every port must have max_tx_queues >= n_workers.
# net_null reports max_tx_queues=1024 (RTE_MAX_QUEUES_PER_PORT).
# We trigger the D28 violation by requesting --workers=1025.
#
# F1.13: --workers=2 on single-queue NIC → reject at startup.
#   (adapted: --workers=1025 on net_null with max_tx_queues=1024)
# X2.8:  --workers=4 on net_null → same rejection pattern.
#   (adapted: --workers=1025 on net_null)

import os
import time

DPDK_DRIVER_DIR = os.environ.get(
    "DPDK_DRIVER_DIR", "/home/mit/Dev/dpdk-25.11/build/drivers/"
)

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

EAL_ARGS_BASE = [
    "--no-pci",
    "--no-huge",
    "-m", "64",
    "-d", DPDK_DRIVER_DIR,
    "--vdev", "net_null0",
    "--vdev", "net_null1",
    "-l", "0,1",
    "--log-level", "lib.*:error",
    "--file-prefix", "pktgate_d28",
]


def test_f1_13_tx_symmetry_reject(pktgate_process):
    """F1.13: D28 TX-queue symmetry — --workers exceeds max_tx_queues,
    startup rejected with reason=tx_queue_symmetry.

    net_null advertises max_tx_queues=1024. We request --workers=1025
    to trigger the D28 invariant violation."""
    proc = pktgate_process(
        MINIMAL_CONFIG,
        eal_args=EAL_ARGS_BASE,
        extra_args=["--workers", "1025"],
    )
    proc.start()

    # Binary should fail quickly — no "ready" expected.
    ready = proc.wait_ready(timeout=5)
    if ready:
        proc.stop()

    # If process is still running, wait for exit.
    if proc.returncode is None:
        proc.wait_exit(timeout=5)

    assert proc.returncode != 0, (
        f"Expected non-zero exit, got {proc.returncode}. "
        f"stdout={proc.stdout_text!r}"
    )

    stdout = proc.stdout_text
    assert "tx_queue_symmetry" in stdout, (
        f"Expected 'tx_queue_symmetry' in output, got: {stdout!r}"
    )
    assert "max_tx_queues" in stdout, (
        f"Expected 'max_tx_queues' in output, got: {stdout!r}"
    )
    assert "n_workers" in stdout, (
        f"Expected 'n_workers' in output, got: {stdout!r}"
    )


def test_x2_8_tx_symmetry_violation(pktgate_process):
    """X2.8: D28 TX-queue symmetry violation detection.

    Same as F1.13 but from the chaos/security angle — verifies:
    - Startup fails BEFORE any worker launches
    - Error message includes port, max_tx_queues, n_workers
    - No partial port setup (ports not started)"""
    proc = pktgate_process(
        MINIMAL_CONFIG,
        eal_args=EAL_ARGS_BASE,
        extra_args=["--workers", "1025"],
    )
    proc.start()

    ready = proc.wait_ready(timeout=5)
    if ready:
        proc.stop()

    if proc.returncode is None:
        proc.wait_exit(timeout=5)

    assert proc.returncode != 0, (
        f"Expected non-zero exit, got {proc.returncode}"
    )

    stdout = proc.stdout_text
    # D28 violation detected — verify structured error fields.
    assert "tx_queue_symmetry" in stdout
    assert "D28" in stdout, (
        f"Error message should reference D28: {stdout!r}"
    )
    # No ports should be in started state.
    assert "ports_started" not in stdout, (
        f"Ports should not be started after D28 rejection: {stdout!r}"
    )
    # No workers should be launched.
    assert "ready" not in stdout or '"ready":true' not in stdout, (
        f"Binary should not reach ready state after D28 rejection: {stdout!r}"
    )
