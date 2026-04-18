# tests/functional/test_f7_inotify.py
#
# M11 C1 — F7.1 IN_CLOSE_WRITE direct-edit fires exactly one reload.
# M11 C2 — F7.2..F7.6 full functional suite.
#
# End-to-end living invariant for the inotify → debounce → deploy()
# pipeline:
#   kernel event → event_filter → Debouncer → read file →
#   ctl::reload::deploy() → RCU publish → counter bumps →
#   /metrics scrape observes pktgate_reload_total{result="success"} += 1
#   and pktgate_active_generation +=1
#
# Every test drives events through the REAL kernel inotify path
# (actual filesystem mutations: write/close, rename, unlink).  D41
# living invariant — no test shortcut (direct deploy(), SIGHUP, etc.).

import json
import os
import re
import socket
import time

import pytest


DPDK_DRIVER_DIR = os.environ.get(
    "DPDK_DRIVER_DIR", "/home/mit/Dev/dpdk-25.11/build/drivers/"
)


def eal_args_for(prefix):
    return [
        "--no-pci",
        "--no-huge",
        "-m", "512",
        "-d", DPDK_DRIVER_DIR,
        "--vdev", "net_null0",
        "--vdev", "net_null1",
        "-l", "0,1",
        "--log-level", "lib.*:error",
        "--file-prefix", f"pktgate_f7_{prefix}",
    ]


def make_config(prom_port=0):
    return {
        "version": 1,
        "interface_roles": {
            "upstream_port":   {"vdev": "net_null0"},
            "downstream_port": {"vdev": "net_null1"},
        },
        "default_behavior": "drop",
        "pipeline": {
            "layer_2": [],
            "layer_3": [],
            "layer_4": [],
        },
        "sizing": {
            "rules_per_layer_max":  256,
            "mac_entries_max":      256,
            "ipv4_prefixes_max":    1024,
            "ipv6_prefixes_max":    1024,
            "l4_entries_max":       256,
            "vrf_entries_max":      32,
            "rate_limit_rules_max": 256,
            "ethertype_entries_max": 32,
            "vlan_entries_max":     256,
            "pcp_entries_max":      8,
            "prom_port":            prom_port,
        },
    }


def extract_prom_port(stdout_lines):
    for line in stdout_lines:
        if '"event":"prom_endpoint_ready"' in line:
            try:
                obj = json.loads(line)
                return int(obj.get("port"))
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
    return None


def wait_for_prom_endpoint(proc, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        port = extract_prom_port(proc._collected_lines)
        if port is not None:
            return port
        line = proc._read_line_nonblocking()
        if line is not None:
            proc._collected_lines.append(line)
            continue
        time.sleep(0.05)
    return None


def http_get(port, path="/metrics", timeout=5.0, host="127.0.0.1"):
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
        return (-1, {}, data)
    head = data[:sep].decode("latin-1", errors="replace")
    body = data[sep + 4:]
    first, *rest = head.split("\r\n")
    parts = first.split(" ", 2)
    status = int(parts[1]) if len(parts) >= 2 else -1
    headers = {}
    for h in rest:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return (status, headers, body)


# Tolerate both OpenMetrics label forms:
#   pktgate_reload_total{result="success"} 3
#   pktgate_reload_total{result="success",foo="bar"} 3
_RELOAD_SUCCESS_RE = re.compile(
    r'^pktgate_reload_total\{[^}]*result="success"[^}]*\}\s+(\d+)',
    re.MULTILINE,
)
_ACTIVE_GENERATION_RE = re.compile(
    r'^pktgate_active_generation\s+(\d+)',
    re.MULTILINE,
)


def scrape_reload_counters(port):
    """Return (reload_success_total, active_generation) from /metrics.
    Returns (None, None) on scrape / parse failure."""
    status, _headers, body = http_get(port, "/metrics")
    if status != 200:
        return (None, None)
    text = body.decode("utf-8", errors="replace")
    m_reload = _RELOAD_SUCCESS_RE.search(text)
    m_gen = _ACTIVE_GENERATION_RE.search(text)
    reload_n = int(m_reload.group(1)) if m_reload else 0
    gen_n = int(m_gen.group(1)) if m_gen else 0
    return (reload_n, gen_n)


def wait_for_reload_bump(port, baseline_reload, baseline_gen,
                         timeout=4.0, interval=0.05):
    """Poll /metrics until pktgate_reload_total{result=success} exceeds
    baseline_reload AND pktgate_active_generation exceeds baseline_gen.
    Returns the final (reload_n, gen_n) pair.  Under dev-tsan the
    binary is 2-5× slower so the window is generous relative to the
    150 ms debounce + deploy latency."""
    deadline = time.monotonic() + timeout
    last = (baseline_reload, baseline_gen)
    while time.monotonic() < deadline:
        reload_n, gen_n = scrape_reload_counters(port)
        if reload_n is None:
            time.sleep(interval)
            continue
        last = (reload_n, gen_n)
        if reload_n > baseline_reload and gen_n > baseline_gen:
            return last
        time.sleep(interval)
    return last


# ------------------------------------------------------------------
# F7.1 — direct-edit IN_CLOSE_WRITE triggers exactly one reload.
# ------------------------------------------------------------------
def test_f7_1_direct_edit_in_close_write(pktgate_process):
    proc = pktgate_process(make_config(),
                           eal_args=eal_args_for("f71"))
    proc.start()

    # PktgateProcess writes the config to a NamedTemporaryFile on
    # start(); we drive the inotify event by rewriting that path.
    # The watcher watches the parent directory (D38) so an in-place
    # O_WRONLY + close() delivers exactly one IN_CLOSE_WRITE event
    # for the watched basename.
    config_path = proc._config_file.name

    # wait_ready timeout 60 s matches the F8 suite convention — dev-tsan
    # cold-start takes several seconds on the worker lcore handshake.
    assert proc.wait_ready(timeout=60), (
        f"binary not ready. stdout={proc.stdout_text!r} "
        f"stderr={proc.stderr_text!r}"
    )
    port = wait_for_prom_endpoint(proc)
    assert port is not None and port > 0, (
        f"prom_endpoint_ready not observed. "
        f"collected={proc._collected_lines!r}"
    )

    # Give the watcher a moment to install its inotify_add_watch.
    # start() is synchronous up to thread spawn so by the time we get
    # here the watch is usually already armed; a 200 ms cushion
    # removes the remaining race across slow dev-tsan bring-up.
    time.sleep(0.2)

    # Baseline reload counters.
    baseline_reload, baseline_gen = scrape_reload_counters(port)
    assert baseline_reload is not None, (
        "could not scrape /metrics for baseline reload counter"
    )

    # Direct edit — rewrite the existing file in place. The kernel
    # delivers IN_CLOSE_WRITE on close(), which the watcher's event
    # filter accepts (event_filter.h should_trigger()).
    new_cfg = make_config()
    # Add a distinguishing sizing tweak so the config is truly
    # different from the baseline (not strictly required for the
    # reload counter, but makes debugging via stderr easier).
    new_cfg["sizing"]["rules_per_layer_max"] = 128
    with open(config_path, "w") as f:
        json.dump(new_cfg, f)
        f.flush()
        os.fsync(f.fileno())
    # `with` close triggers IN_CLOSE_WRITE.

    # Poll /metrics for reload bump. Debounce window is 150 ms; deploy
    # completes in ~milliseconds on a null-rule config; total end-to-
    # end under 500 ms on dev-asan, under 1-2 s on dev-tsan.
    reload_n, gen_n = wait_for_reload_bump(
        port, baseline_reload, baseline_gen, timeout=8.0
    )

    assert reload_n == baseline_reload + 1, (
        f"pktgate_reload_total{{result=success}} did not bump by exactly 1: "
        f"baseline={baseline_reload} final={reload_n}"
    )
    assert gen_n == baseline_gen + 1, (
        f"pktgate_active_generation did not bump by exactly 1: "
        f"baseline={baseline_gen} final={gen_n}"
    )

    proc.stop()
    assert proc.returncode == 0, (
        f"binary exited non-zero: rc={proc.returncode} "
        f"stderr={proc.stderr_text!r}"
    )


# ------------------------------------------------------------------
# Helpers for C2 tests.
# ------------------------------------------------------------------
def _boot_and_baseline(pktgate_process, prefix, proc_kwargs=None,
                       config_override=None, extra_args=None):
    """Boot a pktgate instance, wait until ready + prom endpoint up,
    install-cushion the watcher, and return (proc, port, baseline)."""
    cfg = config_override if config_override is not None else make_config()
    proc = pktgate_process(
        cfg,
        eal_args=eal_args_for(prefix),
        extra_args=extra_args,
    )
    if proc_kwargs is not None:
        for k, v in proc_kwargs.items():
            setattr(proc, k, v)
    proc.start()
    assert proc.wait_ready(timeout=60), (
        f"binary not ready. stdout={proc.stdout_text!r} "
        f"stderr={proc.stderr_text!r}"
    )
    port = wait_for_prom_endpoint(proc)
    assert port is not None and port > 0, (
        f"prom_endpoint_ready not observed. "
        f"collected={proc._collected_lines!r}"
    )
    # Install cushion (same as F7.1): let inotify_add_watch settle.
    time.sleep(0.2)
    baseline_reload, baseline_gen = scrape_reload_counters(port)
    assert baseline_reload is not None, (
        "could not scrape /metrics for baseline reload counter"
    )
    return proc, port, (baseline_reload, baseline_gen)


def _atomic_replace(target_path, new_cfg):
    """Write `new_cfg` into a tmp file in the same directory, then
    os.rename() over `target_path`. This is the cp+mv pattern that
    emits IN_MOVED_TO on the watched basename. Same-directory rename
    is atomic on POSIX."""
    dir_ = os.path.dirname(target_path)
    # NamedTemporaryFile with delete=False in same dir; close before
    # rename so the tmp is fully on disk before the mv.
    import tempfile
    fd, tmp_path = tempfile.mkstemp(
        prefix=".pktgate_f7_swap_", suffix=".json", dir=dir_,
    )
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(new_cfg, f)
            f.flush()
            os.fsync(f.fileno())
        os.rename(tmp_path, target_path)
    except Exception:
        # On failure leave no stray tmp behind.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _final_reload_count(port, baseline_reload, baseline_gen,
                        settle_s=1.0, poll_interval=0.05):
    """Wait until /metrics is quiescent for `settle_s` (no new reloads)
    then return the final (reload_n, gen_n). Different from
    wait_for_reload_bump — this one lets the debounce+deploy chain
    fully settle, even if the final count is > baseline+1 (F7.5 bound)
    or == baseline (F7.3 negative assertion)."""
    last_reload = baseline_reload
    last_gen = baseline_gen
    last_change = time.monotonic()
    deadline = time.monotonic() + max(4.0, settle_s + 3.0)
    while time.monotonic() < deadline:
        reload_n, gen_n = scrape_reload_counters(port)
        if reload_n is None:
            time.sleep(poll_interval)
            continue
        if reload_n != last_reload or gen_n != last_gen:
            last_change = time.monotonic()
            last_reload = reload_n
            last_gen = gen_n
        if time.monotonic() - last_change >= settle_s:
            return (last_reload, last_gen)
        time.sleep(poll_interval)
    return (last_reload, last_gen)


# ------------------------------------------------------------------
# F7.2 — IN_MOVED_TO atomic rename fires exactly one reload.
# ------------------------------------------------------------------
# Pattern: `cp config_new tmp; mv tmp config.json`. The watcher is on
# the parent dir, so kernel delivers TWO raw events within a few ms:
#   IN_CLOSE_WRITE  name=<tmp-basename>   (we wrote+closed the tmp)
#   IN_MOVED_TO     name=config.json      (atomic rename landed)
# watcher.cpp filters by basename — only the MOVED_TO survives. Even
# if the tmp happened to share the basename (it does not here — we
# use mkstemp with a ".pktgate_f7_swap_*" prefix), the 150 ms debounce
# would coalesce to one deploy(). Expected: reload_total += 1 exactly.
def test_f7_2_moved_to_atomic_rename(pktgate_process):
    proc, port, (baseline_reload, baseline_gen) = _boot_and_baseline(
        pktgate_process, "f72",
    )
    try:
        config_path = proc._config_file.name

        new_cfg = make_config()
        new_cfg["sizing"]["rules_per_layer_max"] = 128
        _atomic_replace(config_path, new_cfg)

        reload_n, gen_n = _final_reload_count(
            port, baseline_reload, baseline_gen, settle_s=1.0,
        )
        assert reload_n == baseline_reload + 1, (
            f"F7.2: atomic rename must yield exactly one reload. "
            f"baseline={baseline_reload} final={reload_n} "
            f"(2 would indicate dup-event leak; 0 would indicate "
            f"IN_MOVED_TO not accepted by the filter)."
        )
        assert gen_n == baseline_gen + 1, (
            f"F7.2: active_generation bumped {gen_n - baseline_gen} "
            f"times, expected exactly 1."
        )
    finally:
        proc.stop()
        assert proc.returncode == 0, (
            f"binary exited non-zero: rc={proc.returncode} "
            f"stderr={proc.stderr_text!r}"
        )


# ------------------------------------------------------------------
# F7.3 — IN_MODIFY alone does NOT reload; close does.
# ------------------------------------------------------------------
# Open O_WRONLY (no O_TRUNC) on the watched file. Every write(2)
# emits IN_MODIFY, which event_filter.h should_trigger() rejects.
# During the partial-write window the reload counter MUST stay
# unchanged (design.md §F7.3: "parser does not see truncated mid-edit
# state"). After close, IN_CLOSE_WRITE fires and exactly one reload
# lands.
def test_f7_3_in_modify_no_reload_until_close(pktgate_process):
    proc, port, (baseline_reload, baseline_gen) = _boot_and_baseline(
        pktgate_process, "f73",
    )
    try:
        config_path = proc._config_file.name

        # Open without O_TRUNC so no CLOSE_WRITE lingers from an earlier
        # editor. Python's `open(..., "r+b")` is O_RDWR — use os.open to
        # get pure O_WRONLY semantics consistent with the §F7.3 recipe.
        fd = os.open(config_path, os.O_WRONLY)
        try:
            # Write 10 bytes of garbage (partial, not valid JSON). This
            # fires IN_MODIFY but NOT IN_CLOSE_WRITE.
            os.write(fd, b"0123456789")
            # Do NOT close yet. Wait longer than the 150 ms debounce
            # window plus generous slack under dev-tsan cadence.
            time.sleep(1.0)

            mid_reload, mid_gen = scrape_reload_counters(port)
            assert mid_reload == baseline_reload, (
                f"F7.3: IN_MODIFY leaked through the filter! "
                f"baseline={baseline_reload} mid={mid_reload} "
                f"(watcher must reject partial-write events)."
            )
            assert mid_gen == baseline_gen, (
                f"F7.3: active_generation bumped during partial write: "
                f"baseline={baseline_gen} mid={mid_gen}."
            )

            # Now write a full valid config and close — IN_CLOSE_WRITE
            # fires, watcher reads the now-complete file, deploy() runs.
            # Seek back to 0 and truncate so the final contents are the
            # new config (the garbage head was invalidated).
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            new_cfg = make_config()
            new_cfg["sizing"]["rules_per_layer_max"] = 128
            payload = json.dumps(new_cfg).encode("utf-8")
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)

        # Close triggers IN_CLOSE_WRITE → reload.
        reload_n, gen_n = _final_reload_count(
            port, baseline_reload, baseline_gen, settle_s=1.0,
        )
        assert reload_n == baseline_reload + 1, (
            f"F7.3: close-after-write must fire exactly one reload. "
            f"baseline={baseline_reload} final={reload_n}."
        )
        assert gen_n == baseline_gen + 1
    finally:
        proc.stop()
        assert proc.returncode == 0, (
            f"binary exited non-zero: rc={proc.returncode} "
            f"stderr={proc.stderr_text!r}"
        )


# ------------------------------------------------------------------
# F7.4 — Directory watch sees through a symlink swap.
# ------------------------------------------------------------------
# Setup: the config path we pass to pktgate is a symlink (cfg.json)
# targeting cfg.v1.json. We atomically retarget the symlink to
# cfg.v2.json via `mv -Tf` (os.rename of a new symlink over the old
# name). Because the watcher is on the parent DIRECTORY (D38), the
# retarget emits IN_MOVED_TO name=cfg.json → reload fires. If a
# future refactor ever changes the watch target to the file itself
# (via an nfollow_symlink flag or IN_DONT_FOLLOW), this test breaks —
# that's the regression shield this case exists for.
#
# This test bypasses PktgateProcess's NamedTemporaryFile by
# pre-creating its own directory + symlink layout and monkey-patching
# proc._config_file before .start() runs json.dump into its place.
def test_f7_4_symlink_swap_via_dir_watch(pktgate_process, tmp_path):
    # Build the symlink triad.
    cfg_dir = tmp_path / "f74"
    cfg_dir.mkdir()
    v1_path = cfg_dir / "cfg.v1.json"
    v2_path = cfg_dir / "cfg.v2.json"
    link_path = cfg_dir / "cfg.json"

    v1 = make_config()
    v2 = make_config()
    v2["sizing"]["rules_per_layer_max"] = 128
    v1_path.write_text(json.dumps(v1))
    v2_path.write_text(json.dumps(v2))
    os.symlink(str(v1_path), str(link_path))

    # Build the proc but DON'T call start() yet — we need to override
    # the config path that .start() will wire in.
    proc = pktgate_process(v1, eal_args=eal_args_for("f74"))

    # Replace the NamedTemporaryFile with a fake whose .name points at
    # our symlink. PktgateProcess.start() will `json.dump(config_dict,
    # fh)` + `fh.close()` — we give it a throwaway NamedTemporaryFile
    # open in the SAME dir, then overwrite its .name attribute AFTER
    # close so the binary launches with the symlink as --config.
    import tempfile
    staging = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, dir=str(cfg_dir),
    )
    # Let start() write into the staging NamedTemporaryFile (it's
    # thrown away afterwards; the binary reads from `link_path`).
    proc._config_file = staging

    # Wrap start() so the binary's --config arg points at link_path,
    # not staging.name.
    _orig_start = proc.start

    def _patched_start():
        # Write config to staging + close it (same as default start()).
        json.dump(proc.config_dict, staging)
        staging.close()
        # Binary launch path — mirrors conftest.PktgateProcess.start()
        # body, substituting link_path for staging.name.
        cmd = [proc._binary] + proc.eal_args + [
            "--config", str(link_path),
        ] + proc.extra_args
        # Need a stderr file in the normal pattern.
        proc._stderr_file = tempfile.NamedTemporaryFile(
            mode="w+", suffix=".stderr", delete=False
        )
        import subprocess, fcntl
        proc.process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=proc._stderr_file,
        )
        fd = proc.process.stdout.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        proc._stdout_buf = b""
        proc._collected_lines = []

    proc.start = _patched_start
    proc.start()

    try:
        assert proc.wait_ready(timeout=60), (
            f"binary not ready. stdout={proc.stdout_text!r} "
            f"stderr={proc.stderr_text!r}"
        )
        port = wait_for_prom_endpoint(proc)
        assert port is not None and port > 0
        time.sleep(0.2)
        baseline_reload, baseline_gen = scrape_reload_counters(port)
        assert baseline_reload is not None

        # Atomically retarget the symlink to v2. On Linux, os.symlink
        # fails if the target exists; the standard trick is to create
        # a new symlink at a tmp name in the same dir and os.rename()
        # it over the old one (rename across the same dir is atomic
        # and works on symlinks themselves).
        new_link = cfg_dir / ".cfg.json.new"
        os.symlink(str(v2_path), str(new_link))
        os.rename(str(new_link), str(link_path))

        reload_n, gen_n = _final_reload_count(
            port, baseline_reload, baseline_gen, settle_s=1.0,
        )
        assert reload_n == baseline_reload + 1, (
            f"F7.4: symlink swap did not fire exactly one reload. "
            f"baseline={baseline_reload} final={reload_n}. "
            f"This usually means the watch is on the file (via the "
            f"resolved symlink target) instead of the parent dir."
        )
        assert gen_n == baseline_gen + 1
    finally:
        proc.stop()
        assert proc.returncode == 0, (
            f"binary exited non-zero: rc={proc.returncode} "
            f"stderr={proc.stderr_text!r}"
        )


# ------------------------------------------------------------------
# F7.5 — Debounce coalesces 5 rapid writes into ≤ 2 reloads.
# ------------------------------------------------------------------
# Five IN_CLOSE_WRITE bursts within ~50 ms total. The 150 ms
# quiescent window coalesces them into (usually) 1 deploy() call;
# worst case 2 if the burst straddles a window boundary under
# dev-tsan cadence.
def test_f7_5_debounce_coalesce_rapid_writes(pktgate_process):
    proc, port, (baseline_reload, baseline_gen) = _boot_and_baseline(
        pktgate_process, "f75",
    )
    try:
        config_path = proc._config_file.name

        # Fire 5 direct-edits back-to-back. Each one truncates+writes
        # so the deliverable event is IN_CLOSE_WRITE. Small sleep
        # between writes — total burst under 50 ms, comfortably inside
        # the 150 ms debounce window.
        for i in range(5):
            new_cfg = make_config()
            # Each iteration changes a value so reads see distinct
            # content — not strictly required for the counter test.
            new_cfg["sizing"]["rules_per_layer_max"] = 128 + i
            with open(config_path, "w") as f:
                json.dump(new_cfg, f)
                f.flush()
                os.fsync(f.fileno())
            time.sleep(0.005)

        reload_n, gen_n = _final_reload_count(
            port, baseline_reload, baseline_gen, settle_s=1.5,
        )
        bump = reload_n - baseline_reload
        assert 1 <= bump <= 2, (
            f"F7.5: 5 rapid writes must coalesce to ≤ 2 reloads "
            f"(150 ms debounce). baseline={baseline_reload} "
            f"final={reload_n} bump={bump}."
        )
        assert gen_n - baseline_gen == bump, (
            f"F7.5: reload/generation bump mismatch: "
            f"reload={bump} gen={gen_n - baseline_gen}."
        )
    finally:
        proc.stop()
        assert proc.returncode == 0, (
            f"binary exited non-zero: rc={proc.returncode} "
            f"stderr={proc.stderr_text!r}"
        )


# ------------------------------------------------------------------
# F7.6 — Watched-directory race: rm + re-add fires one reload.
# ------------------------------------------------------------------
# The watch is on the parent directory (not the file), so `rm cfg;
# cp v2 cfg` in the same dir stays fully observable. IN_DELETE on rm
# is dropped by the filter; IN_CLOSE_WRITE on the re-create is
# accepted → exactly one reload.
def test_f7_6_rm_then_readd(pktgate_process):
    proc, port, (baseline_reload, baseline_gen) = _boot_and_baseline(
        pktgate_process, "f76",
    )
    try:
        config_path = proc._config_file.name

        # Remove + re-add within the same debounce window. Kernel
        # delivers IN_DELETE name=cfg (filtered out by should_trigger)
        # then IN_CLOSE_WRITE name=cfg (accepted). One reload.
        os.unlink(config_path)
        time.sleep(0.05)  # short gap; well inside debounce coalesce
        new_cfg = make_config()
        new_cfg["sizing"]["rules_per_layer_max"] = 128
        with open(config_path, "w") as f:
            json.dump(new_cfg, f)
            f.flush()
            os.fsync(f.fileno())

        reload_n, gen_n = _final_reload_count(
            port, baseline_reload, baseline_gen, settle_s=1.5,
        )
        assert reload_n == baseline_reload + 1, (
            f"F7.6: rm+re-add must fire exactly one reload. "
            f"baseline={baseline_reload} final={reload_n}."
        )
        assert gen_n == baseline_gen + 1
    finally:
        proc.stop()
        assert proc.returncode == 0, (
            f"binary exited non-zero: rc={proc.returncode} "
            f"stderr={proc.stderr_text!r}"
        )
