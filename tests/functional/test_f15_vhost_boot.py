# tests/functional/test_f15_vhost_boot.py
#
# M15 C1 — F15.1 vhost boot smoke.
#
# Verifies pktgate boots with a `net_vhost` downstream role, reaches
# the "ready" state in server mode without a consumer attached (DPDK's
# net_vhost listens on the configured UDS path and does NOT block
# init waiting for a peer), emits a structured `port_resolved` event
# naming the vhost port id, and the socket file actually exists on
# disk after ready.
#
# Upstream choice: **net_null**. Pure control-plane wiring test — no
# packet inject, no sniff, no NM keyfile interaction. net_null avoids
# the F2.25 NDP flake class, TAP bring-up races, and NM DHCP
# contamination. Actual cross-port data plane exercise for vhost
# lands in M15 C3 (testpmd paired integration) and C4 (peer crash
# chaos); C1's contract is strictly boot-path observables.
#
# Distinct EAL --file-prefix per sub-test + wildcard-friendly
# `pktgate_f15_*` shape so `/run/dpdk/pktgate_f15*` cleanup between
# test runs is trivial (memory `grabli_run_dpdk_tmpfs_leak.md` +
# `grabli_ssh_sudo_glob_expansion.md`).
#
# Runtime dir contract: `/run/pktgate/` must exist before EAL
# registers the net_vhost vdev (DPDK opens the UDS on the given
# `iface=<path>` at vdev-probe time). The fixture below creates it
# if missing, pre-cleans any stale `vhost-m15*.sock` files, and
# removes the socket after SIGTERM as a safety net (C2 will add the
# in-binary unlink hook; for C1 the test fixture owns cleanup).

import json
import os
import socket as _socket
import stat
import time

import pytest


# EAL driver-dir is **opt-in** for F15.1. Rationale: the dev VM's
# `/etc/ld.so.conf.d/dpdk-dev.conf` already exposes DPDK PMDs at
# `/home/mit/Dev/dpdk-25.11/build/drivers/` via ldconfig (memory
# `vm_dpdk_layout.md`). Explicitly passing `-d <dir>` plus ldconfig
# hits EAL twice per PMD `.so`, which on the post-2026-04-19 dual
# install (build-tree + `/usr/local/lib64/dpdk/pmds-*/`) causes
# per-driver tailq double-registration (`VFIO_CDX_RESOURCE_LIST
# tailq is already registered` → panic in `tailqinitfn_cdx_vfio_
# tailq`). F15.1 relies on ldconfig. If the operator overrides
# the behaviour (e.g. to run this test against a DPDK install
# outside the ldconfig path), they can set PKTGATE_DPDK_DRIVER_DIR
# and the EAL argv picks it up explicitly.
DPDK_DRIVER_DIR = os.environ.get("PKTGATE_DPDK_DRIVER_DIR", "").strip()

_RUNTIME_DIR = "/run/pktgate"
_SOCK_NAME = "vhost-m15.sock"
_SOCK_PATH = os.path.join(_RUNTIME_DIR, _SOCK_NAME)


# ---------------------------------------------------------------------------
# Runtime-dir fixture — ensure /run/pktgate exists, clean stale sockets.
# ---------------------------------------------------------------------------

@pytest.fixture
def vhost_runtime_dir():
    """Ensure /run/pktgate/ exists and no stale vhost-m15*.sock lingers.

    C1 scope: fixture owns cleanup — pktgate's in-binary cleanup hook
    lands in C2. For C1 the test provides pre- and post-cleanup so
    successive sub-tests in the same session do not inherit a stale
    socket from an earlier aborted run.
    """
    # Pre-cleanup: ensure dir exists (operator convention is systemd
    # RuntimeDirectory=pktgate, but in the test harness we own it).
    try:
        os.makedirs(_RUNTIME_DIR, mode=0o755, exist_ok=True)
    except OSError as e:
        pytest.skip(f"cannot create {_RUNTIME_DIR}: {e}")

    # Remove any stale sockets from a previous aborted run.
    _rm_stale()

    yield _SOCK_PATH

    # Post-cleanup safety net.
    _rm_stale()


def _rm_stale():
    try:
        for name in os.listdir(_RUNTIME_DIR):
            if name.startswith("vhost-m15") and name.endswith(".sock"):
                try:
                    os.unlink(os.path.join(_RUNTIME_DIR, name))
                except OSError:
                    pass
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _eal_args(file_prefix: str, sock_path: str):
    """EAL argv: net_null upstream + net_vhost downstream (server mode)."""
    argv = [
        "--no-pci",
        "--no-huge",
        "-m", "512",       # FIB DIR24_8 baseline (~128 MB)
    ]
    if DPDK_DRIVER_DIR:
        argv += ["-d", DPDK_DRIVER_DIR]
    argv += [
        "--vdev", "net_null0",
        "--vdev", f"net_vhost0,iface={sock_path},queues=1",
        "-l", "0,1",
        "--log-level", "lib.*:error",
        "--file-prefix", file_prefix,
    ]
    return argv


def _config():
    return {
        "version": 1,
        "interface_roles": {
            "upstream_port":   {"vdev": "net_null0"},
            "downstream_port": {
                "vdev": f"net_vhost0,iface={_SOCK_PATH},queues=1"
            },
        },
        "default_behavior": "drop",
        "pipeline": {
            "layer_2": [],
            "layer_3": [],
            "layer_4": [],
        },
        "sizing": {
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
        },
    }


def _parse_event_lines(stdout: str):
    out = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        out.append(obj)
    return out


def _resolved_map(stdout: str):
    out = {}
    for obj in _parse_event_lines(stdout):
        if obj.get("event") == "port_resolved":
            out[obj["role"]] = obj["port_id"]
    return out


# ---------------------------------------------------------------------------
# F15.1 — pktgate boots with vhost downstream, reaches ready, socket
#          appears on disk, port_resolved event names the vhost port id.
# ---------------------------------------------------------------------------

def test_pktgate_boots_with_vhost_downstream(
    pktgate_process, vhost_runtime_dir
):
    """F15.1: vhost server-mode boot, no consumer attached.

    Contract:
      1. pktgate reaches `"ready":true` — init MUST NOT block waiting
         for a peer (net_vhost listens, does not connect).
      2. `{"event":"port_resolved","role":"downstream_port",...}` is
         emitted naming the vhost port id.
      3. `/run/pktgate/vhost-m15.sock` exists on disk (socket-type inode).

    Upstream is net_null so this test is pure control-plane — no TAP
    bring-up, no NM keyfile interaction, no NDP surface. Data-plane
    vhost exercise lands in M15 C3 / C4.
    """
    sock_path = vhost_runtime_dir  # = _SOCK_PATH

    # Pre-condition: fixture cleaned any stale socket.
    assert not os.path.exists(sock_path), (
        f"fixture failed to clean stale {sock_path}"
    )

    config = _config()
    proc = pktgate_process(
        config,
        eal_args=_eal_args("pktgate_f15_1", sock_path),
        timeout=30,
    )
    proc.start()

    ready = proc.wait_ready(timeout=30)
    assert ready, (
        f"pktgate did not reach 'ready' with vhost downstream. "
        f"exit={proc.returncode} stdout={proc.stdout_text!r} "
        f"stderr={proc.stderr_text!r}"
    )

    # Socket must be on disk by the time pktgate emits ready — DPDK
    # net_vhost creates the UDS at vdev-probe time, which happens
    # during rte_eal_init, strictly before the ready emit.
    assert os.path.exists(sock_path), (
        f"vhost socket {sock_path} not created by DPDK net_vhost. "
    )
    st = os.stat(sock_path)
    assert stat.S_ISSOCK(st.st_mode), (
        f"{sock_path} exists but is not a socket inode: "
        f"mode=0o{st.st_mode:o}"
    )

    # Tear the binary down so `proc.stdout_text` is populated with the
    # full captured output (the PktgateProcess harness only snapshots
    # stdout_text on wait_ready timeout or on wait_exit; successful
    # wait_ready leaves the rolling buffer in-place until stop()).
    proc.stop()

    assert proc.returncode == 0, (
        f"unclean exit after SIGTERM: rc={proc.returncode} "
        f"stdout={proc.stdout_text!r}"
    )

    # port_resolved event names the vhost role with a concrete port id.
    resolved = _resolved_map(proc.stdout_text)
    assert "downstream_port" in resolved, (
        f"port_resolved event missing for downstream_port. "
        f"resolved={resolved!r} stdout={proc.stdout_text!r}"
    )
    vhost_port_id = resolved["downstream_port"]
    # net_null0 registers as port 0 (first --vdev on cmdline); net_vhost0
    # is the second --vdev, expected port 1.
    assert vhost_port_id == 1, (
        f"downstream_port expected to resolve to port 1 (second --vdev), "
        f"got {vhost_port_id}. resolved={resolved!r}"
    )
