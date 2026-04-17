# tests/functional/test_f7_inotify.py
#
# M11 C1 — F7.1 IN_CLOSE_WRITE direct-edit fires exactly one reload.
#
# End-to-end living invariant for the inotify → debounce → deploy()
# pipeline:
#   kernel event → event_filter → Debouncer → read file →
#   ctl::reload::deploy() → RCU publish → counter bumps →
#   /metrics scrape observes pktgate_reload_total{result="success"} += 1
#   and pktgate_active_generation +=1
#
# F7.2 / F7.3 / F7.4 / F7.5 / F7.6 land in C2; this file owns the
# fixture shape they'll extend.

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
