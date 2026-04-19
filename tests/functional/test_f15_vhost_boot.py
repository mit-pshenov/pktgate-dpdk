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
import signal
import socket as _socket
import stat
import time

import pytest


# EAL driver-dir is **opt-in** via PKTGATE_DPDK_DRIVER_DIR. The shared
# PktgateProcess factory (conftest.py) injects `-d <path>` from that env
# and strips any legacy hard-coded `-d` pair, so this file does not need
# to splice the flag itself — see the `pktgate_eal_driver_args()` helper
# comment in conftest.py for the dual-install rationale.

_RUNTIME_DIR = "/run/pktgate"
_SOCK_NAME = "vhost-m15.sock"
_SOCK_PATH = os.path.join(_RUNTIME_DIR, _SOCK_NAME)

# M15 C2 socket paths. Distinct per sub-test so a crashed run does not
# contaminate the next one and so /run/pktgate stale hygiene is tractable.
_F15_2_SOCK_NAME = "vhost-f15-2.sock"
_F15_2_SOCK_PATH = os.path.join(_RUNTIME_DIR, _F15_2_SOCK_NAME)
_F15_2B_SOCK_NAME = "vhost-f15-2b.sock"
_F15_2B_SOCK_PATH = os.path.join(_RUNTIME_DIR, _F15_2B_SOCK_NAME)
_F15_3_SOCK_NAME = "vhost-f15-3.sock"
_F15_3_SOCK_PATH = os.path.join(_RUNTIME_DIR, _F15_3_SOCK_NAME)


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
    # Match both the C1 smoke socket (vhost-m15.sock) and the C2
    # lifecycle sockets (vhost-f15-2*.sock, vhost-f15-3.sock) so
    # successive sub-tests in the same session always start clean.
    try:
        for name in os.listdir(_RUNTIME_DIR):
            if name.endswith(".sock") and (
                name.startswith("vhost-m15")
                or name.startswith("vhost-f15-")
            ):
                try:
                    os.unlink(os.path.join(_RUNTIME_DIR, name))
                except OSError:
                    pass
    except OSError:
        pass


def _parsed_events_with(stdout: str, event_name: str):
    """Return the list of parsed JSON event objects whose `event`
    field equals `event_name`. Non-JSON lines (including structured
    logger noise without an `event` key) are skipped."""
    out = []
    for obj in _parse_event_lines(stdout):
        if obj.get("event") == event_name:
            out.append(obj)
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _eal_args(file_prefix: str, sock_path: str):
    """EAL argv: net_null upstream + net_vhost downstream (server mode).

    Note: no `-d` here — conftest.py injects it from PKTGATE_DPDK_DRIVER_DIR
    when set (the default dev VM relies on ldconfig). See the shared helper
    comment in conftest.py for rationale.
    """
    return [
        "--no-pci",
        "--no-huge",
        "-m", "512",       # FIB DIR24_8 baseline (~128 MB)
        "--vdev", "net_null0",
        "--vdev", f"net_vhost0,iface={sock_path},queues=1",
        "-l", "0,1",
        "--log-level", "lib.*:error",
        "--file-prefix", file_prefix,
    ]


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


# ---------------------------------------------------------------------------
# M15 C2 sub-test helpers — config + EAL argv keyed on a caller-supplied
# socket path. C1's `_config()` / `_eal_args()` hard-code the C1 path;
# C2 needs one path per sub-test so the filesystem probe is
# un-ambiguous and cross-test contamination is impossible.
# ---------------------------------------------------------------------------

def _eal_args_for(file_prefix: str, sock_path: str):
    """EAL argv variant keyed on an arbitrary socket path.

    Mirrors `_eal_args()` above, parameterised on the path so C2
    sub-tests each get their own UDS inode. Same `-d` opt-in
    contract via conftest; we do not splice it here.
    """
    return [
        "--no-pci",
        "--no-huge",
        "-m", "512",       # FIB DIR24_8 baseline (~128 MB)
        "--vdev", "net_null0",
        "--vdev", f"net_vhost0,iface={sock_path},queues=1",
        "-l", "0,1",
        "--log-level", "lib.*:error",
        "--file-prefix", file_prefix,
    ]


def _config_for(sock_path: str):
    """Config variant keyed on a caller-supplied vhost socket path.

    The downstream role references the same `net_vhost0` port name as
    C1 (resolver comma-strip handles the iface= tail identically); only
    the iface path differs from `_config()`.
    """
    return {
        "version": 1,
        "interface_roles": {
            "upstream_port":   {"vdev": "net_null0"},
            "downstream_port": {
                "vdev": f"net_vhost0,iface={sock_path},queues=1"
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


# ---------------------------------------------------------------------------
# F15.2 — SIGTERM cleanup.
#
# Pktgate boots with a vhost downstream role → reaches ready → socket
# inode exists on disk → SIGTERM → process exits cleanly → socket path
# MUST no longer exist AND the binary MUST have emitted
# `{"event":"vhost_socket_cleaned","path":"<p>"}` on stdout BEFORE the
# final exit.
#
# RED today (`a3c9dfd`): main.cpp has no cleanup hook — the SIGTERM
# path runs Phase 9 shutdown + `rte_eal_cleanup()` and leaves the UDS
# inode on disk. The observable is also absent. Both assertions fail.
# GREEN (C2 impl): main.cpp signal-handler path + shared helper
# walks config `interface_roles` and `unlink()`s each `net_vhost*`
# iface= path, emitting the structured observable on each unlink.
# ---------------------------------------------------------------------------

def test_sigterm_unlinks_vhost_socket(pktgate_process, vhost_runtime_dir):
    """F15.2: graceful SIGTERM exit MUST unlink the vhost socket.

    Asserts the two halves D44 pins (§3a.2):
      (1) filesystem probe — socket path gone after exit;
      (2) observable — `vhost_socket_cleaned` event naming the path
          appears on stdout BEFORE the process exits.

    The observable half is the one that structurally closes the D41
    silent-gap class: a filesystem probe alone would be satisfied by
    any path that races `unlink()` with `rte_eal_cleanup()`, but only
    a single shared helper can emit the structured event. F15.2 +
    F15.2b together verify both exit paths route through the helper.
    """
    _ = vhost_runtime_dir  # fixture ensures /run/pktgate/ exists + is clean
    sock_path = _F15_2_SOCK_PATH

    # Pre-condition: fixture cleaned any stale socket (the C1 rm_stale
    # sweep matches vhost-f15-* too after the C2 extension).
    assert not os.path.exists(sock_path), (
        f"fixture failed to clean stale {sock_path}"
    )

    config = _config_for(sock_path)
    proc = pktgate_process(
        config,
        eal_args=_eal_args_for("pktgate_f15_2", sock_path),
        timeout=30,
    )
    proc.start()

    ready = proc.wait_ready(timeout=30)
    assert ready, (
        f"pktgate did not reach 'ready' with vhost downstream. "
        f"exit={proc.returncode} stdout={proc.stdout_text!r} "
        f"stderr={proc.stderr_text!r}"
    )

    # DPDK net_vhost created the UDS at vdev-probe time.
    assert os.path.exists(sock_path), (
        f"vhost socket {sock_path} not created by DPDK net_vhost "
        "at vdev-probe time (pre-SIGTERM)."
    )
    st = os.stat(sock_path)
    assert stat.S_ISSOCK(st.st_mode), (
        f"{sock_path} exists but is not a socket inode: "
        f"mode=0o{st.st_mode:o}"
    )

    # Graceful SIGTERM → wait for process exit → stdout_text populated.
    proc.send_signal(signal.SIGTERM)
    proc.wait_exit(timeout=20)

    assert proc.returncode == 0, (
        f"unclean exit after SIGTERM: rc={proc.returncode} "
        f"stdout={proc.stdout_text!r} stderr={proc.stderr_text!r}"
    )

    # (1) filesystem probe — socket file MUST be gone after graceful exit.
    assert not os.path.exists(sock_path), (
        f"vhost socket {sock_path} still present after SIGTERM + clean "
        f"exit — cleanup hook missing. stdout={proc.stdout_text!r}"
    )

    # (2) observable — vhost_socket_cleaned event named the path.
    cleaned_events = _parsed_events_with(
        proc.stdout_text, "vhost_socket_cleaned"
    )
    assert cleaned_events, (
        "no `vhost_socket_cleaned` event emitted before exit — D41 "
        "observable missing on the SIGTERM path. "
        f"stdout={proc.stdout_text!r}"
    )
    paths_seen = {ev.get("path") for ev in cleaned_events}
    assert sock_path in paths_seen, (
        f"vhost_socket_cleaned event(s) present but did not name "
        f"{sock_path}. paths_seen={paths_seen!r} "
        f"events={cleaned_events!r}"
    )


# ---------------------------------------------------------------------------
# F15.2b — normal-exit cleanup (D41 twin-path coverage).
#
# D44 §cleanup-on-exit names TWO paths that MUST share the helper:
# SIGTERM/SIGINT AND clean `main()` return. F15.2 covered the signal
# path; F15.2b covers the non-signal path — without it one path could
# be wired and a test hitting only the other would pass (precedent
# M8 C5, memory `grabli_m8_rcu_reader_gap.md`).
#
# Mechanism chosen: `--exit-after-init` diagnostic flag explicitly
# named in D44 prose ("clean `main()` return — the helper runs on the
# normal-exit path (e.g. reload-init failure, `--exit-after-init`
# diagnostic mode)"). The flag does not exist at `a3c9dfd`; GREEN
# worker adds it in the same commit that lands the cleanup helper.
#
# RED today: `--exit-after-init` is an unknown pktgate flag so it
# falls through to EAL argv where `rte_eal_init` rejects it with
# "unrecognized option", pktgate exits non-zero BEFORE ever reaching
# `{"ready":true}`, and the `wait_ready(timeout)` returns False.
# Assertion message surfaces the real reason so the GREEN worker
# understands the contract.
#
# GREEN: `--exit-after-init` consumed by main.cpp's argv scan (same
# shape as `--config` / `--workers`), the main loop short-circuits
# after emitting `{"ready":true}`, the shared cleanup helper runs
# ahead of `rte_eal_cleanup()`, and the filesystem + observable
# assertions fire identically to F15.2.
# ---------------------------------------------------------------------------

def test_normal_exit_unlinks_vhost_socket(pktgate_process, vhost_runtime_dir):
    """F15.2b: non-signal exit MUST also unlink the vhost socket.

    Covers the D41 twin of F15.2 — the `main()` return path MUST
    share a helper with the signal path. Test forces the non-signal
    exit via the `--exit-after-init` diagnostic flag called out in
    D44 prose, then asserts the same filesystem + observable pair.

    RED note: the flag is introduced by the C2 GREEN commit. At
    RED time the flag is unknown to pktgate, passes through to EAL
    where it is rejected, and pktgate exits non-zero pre-ready —
    the assertion surfaces this as a meaningful failure rather
    than silently passing on a vacuous "socket never existed"
    branch.
    """
    _ = vhost_runtime_dir
    sock_path = _F15_2B_SOCK_PATH

    assert not os.path.exists(sock_path), (
        f"fixture failed to clean stale {sock_path}"
    )

    config = _config_for(sock_path)
    proc = pktgate_process(
        config,
        eal_args=_eal_args_for("pktgate_f15_2b", sock_path),
        extra_args=["--exit-after-init"],
        timeout=30,
    )
    proc.start()

    # Binary MUST reach ready even with --exit-after-init (the flag
    # means "tear down AFTER init succeeds", not "skip init"). If
    # ready never fires, EAL likely rejected the flag as an unknown
    # option — that is the RED signal at `a3c9dfd`.
    ready = proc.wait_ready(timeout=30)
    assert ready, (
        "pktgate did not reach 'ready' with --exit-after-init. "
        "On RED tree the flag is unknown, gets passed to EAL which "
        "rejects it pre-init. GREEN: main.cpp argv scan must "
        "consume the flag before EAL sees it. "
        f"exit={proc.returncode} stdout={proc.stdout_text!r} "
        f"stderr={proc.stderr_text!r}"
    )

    # On the non-signal path the binary initiates its own shutdown
    # right after ready; no SIGTERM is sent. Wait for self-exit.
    proc.wait_exit(timeout=20)

    assert proc.returncode == 0, (
        f"non-signal exit path returned non-zero: rc={proc.returncode} "
        f"stdout={proc.stdout_text!r} stderr={proc.stderr_text!r}"
    )

    # (1) filesystem probe.
    assert not os.path.exists(sock_path), (
        f"vhost socket {sock_path} still present after normal exit — "
        "cleanup helper not shared with the non-signal path (D41 gap). "
        f"stdout={proc.stdout_text!r}"
    )

    # (2) observable.
    cleaned_events = _parsed_events_with(
        proc.stdout_text, "vhost_socket_cleaned"
    )
    assert cleaned_events, (
        "no `vhost_socket_cleaned` event emitted on the non-signal "
        "exit path — helper either absent or only wired into the "
        "signal path (D41 silent-gap). "
        f"stdout={proc.stdout_text!r}"
    )
    paths_seen = {ev.get("path") for ev in cleaned_events}
    assert sock_path in paths_seen, (
        f"vhost_socket_cleaned event(s) present but did not name "
        f"{sock_path}. paths_seen={paths_seen!r} "
        f"events={cleaned_events!r}"
    )


# ---------------------------------------------------------------------------
# F15.3 — stale-socket guard on boot.
#
# D44 §stale-socket-guard-on-boot: before `rte_eal_init` registers the
# vhost vdev, pktgate `stat()`s the configured path and `unlink()`s it
# if it is a socket-type inode. Rationale — crash-exit (SIGKILL,
# SIGSEGV, abort) leaves the UDS on disk; without the guard the next
# boot's DPDK net_vhost `bind(2)` fails EADDRINUSE and init aborts.
#
# Pre-create a valid UDS inode at the configured path via
# `socket(AF_UNIX).bind(path)` → close (closing without listening
# leaves the inode on disk; the kernel only removes UDS files when
# explicitly `unlink()`ed). Boot pktgate on that path → assert it
# reaches ready (proving the guard removed the stale inode) AND
# emitted a structured observable naming the path (so the operator
# can tell from logs that a stale inode was taken over).
#
# RED today: no guard in main.cpp → DPDK net_vhost bind fails →
# `rte_eal_init` returns < 0 → pktgate exits with the
# `{"error":"rte_eal_init failed"}` log BEFORE ready. Both the
# ready assertion and the observable assertion fail.
#
# GREEN: main.cpp walks interface_roles before EAL init, stat+unlink
# on each `net_vhost*` iface= path that is a socket-type inode, emit
# `{"event":"vhost_stale_socket_unlinked","path":"<p>"}` per unlink.
# Event-name choice is a supervisor-visible hint the GREEN worker
# should mirror (same verb stem as `vhost_socket_cleaned`, distinct
# so an operator can grep-separate "we cleaned up after ourselves"
# from "we took over a stale inode left by a crashed predecessor").
# ---------------------------------------------------------------------------

_STALE_EVENT = "vhost_stale_socket_unlinked"


def _create_stale_uds(path: str):
    """Materialise a valid UDS inode at `path` without a listener.

    `bind(2)` on an AF_UNIX socket creates the filesystem entry as a
    socket-type inode; closing the fd leaves the inode on disk (the
    kernel only unlinks UDS files on explicit `unlink(2)`, unless
    SOCK_ABSTRACT is used — which we explicitly avoid here). This
    shape matches what a crashed pktgate leaves behind.
    """
    s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    try:
        s.bind(path)
    finally:
        s.close()


def test_stale_socket_unlinked_on_boot(pktgate_process, vhost_runtime_dir):
    """F15.3: boot-time guard MUST unlink a stale vhost UDS inode.

    Pre-create a valid UDS inode at the configured path (simulating a
    prior crash-exit), boot pktgate on the same path, assert:
      (1) pktgate reaches ready (without the guard, EAL init would
          fail on net_vhost bind EADDRINUSE → non-zero exit pre-ready);
      (2) structured stdout observable names the path that was
          unlinked so operators can audit "took-over" events.
    """
    _ = vhost_runtime_dir
    sock_path = _F15_3_SOCK_PATH

    # Fixture cleaned any stale inode; materialise the one we want.
    assert not os.path.exists(sock_path), (
        f"fixture failed to clean stale {sock_path}"
    )
    _create_stale_uds(sock_path)
    pre_stat = os.stat(sock_path)
    assert stat.S_ISSOCK(pre_stat.st_mode), (
        f"test-setup failure: pre-created {sock_path} is not a socket "
        f"inode: mode=0o{pre_stat.st_mode:o}"
    )

    config = _config_for(sock_path)
    proc = pktgate_process(
        config,
        eal_args=_eal_args_for("pktgate_f15_3", sock_path),
        timeout=30,
    )
    proc.start()

    ready = proc.wait_ready(timeout=30)
    assert ready, (
        "pktgate did not reach 'ready' with a pre-existing stale "
        "socket at the configured vhost iface= path. RED: no "
        "stale-socket guard in main.cpp → DPDK net_vhost bind(2) "
        "fails EADDRINUSE → rte_eal_init < 0 → pre-ready exit. "
        f"exit={proc.returncode} stdout={proc.stdout_text!r} "
        f"stderr={proc.stderr_text!r}"
    )

    # Socket file MUST still be present (pktgate re-created it after
    # unlinking the stale inode and DPDK net_vhost bound to the path).
    # We don't strictly assert this — F15.1 already pins
    # "post-ready socket exists" for the non-stale case — but we do
    # assert the *observable* that declares the stale inode was taken
    # over, which is the contract-level guarantee D44 makes.

    # Tear down so `stdout_text` is populated with the full run.
    proc.stop()

    assert proc.returncode == 0, (
        f"unclean exit after SIGTERM: rc={proc.returncode} "
        f"stdout={proc.stdout_text!r}"
    )

    stale_events = _parsed_events_with(proc.stdout_text, _STALE_EVENT)
    assert stale_events, (
        f"no `{_STALE_EVENT}` event emitted — boot-time stale-socket "
        "guard either absent or silent. Operator loses the audit "
        "trail for 'we took over a crashed predecessor's path'. "
        f"stdout={proc.stdout_text!r}"
    )
    paths_seen = {ev.get("path") for ev in stale_events}
    assert sock_path in paths_seen, (
        f"{_STALE_EVENT} event(s) present but did not name "
        f"{sock_path}. paths_seen={paths_seen!r} "
        f"events={stale_events!r}"
    )
