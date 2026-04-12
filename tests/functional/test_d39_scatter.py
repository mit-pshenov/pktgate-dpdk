# tests/functional/test_d39_scatter.py
#
# M3 C3 — F1.14: D39 scatter-off + mempool-fit validator.
#
# D39 invariant: every port must receive packets in a single mbuf segment.
# The startup validator rejects if mempool data room is too small for
# the port's max_rx_pkt_len (which would force scatter/multi-seg RX).
#
# F1.14: config with deliberately small mempool → rejected at startup
# with reason="multiseg_rx_unsupported".

import os

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

EAL_ARGS = [
    "--no-pci",
    "--no-huge",
    "-m", "64",
    "-d", DPDK_DRIVER_DIR,
    "--vdev", "net_null0",
    "--vdev", "net_null1",
    "-l", "0,1",
    "--log-level", "lib.*:error",
    "--file-prefix", "pktgate_d39",
]


def test_f1_14_small_mempool_rejected(pktgate_process):
    """F1.14: D39 mempool-fit — deliberately small mbuf data room
    triggers multiseg_rx_unsupported rejection at startup.

    --mbuf-size=64 creates mbufs that are too small for standard
    Ethernet frames (1518 bytes). The D39 validator rejects this."""
    proc = pktgate_process(
        MINIMAL_CONFIG,
        eal_args=EAL_ARGS,
        extra_args=["--mbuf-size", "64"],
    )
    proc.start()

    ready = proc.wait_ready(timeout=5)
    if ready:
        proc.stop()

    if proc.returncode is None:
        proc.wait_exit(timeout=5)

    assert proc.returncode != 0, (
        f"Expected non-zero exit, got {proc.returncode}. "
        f"stdout={proc.stdout_text!r}"
    )

    stdout = proc.stdout_text
    assert "multiseg_rx_unsupported" in stdout, (
        f"Expected 'multiseg_rx_unsupported' in output, got: {stdout!r}"
    )
