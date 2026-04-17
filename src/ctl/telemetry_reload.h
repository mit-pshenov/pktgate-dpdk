// src/ctl/telemetry_reload.h
//
// M8 C5 — X1.3 two-way reload: DPDK telemetry endpoint that routes to
// `ctl::reload::deploy()` under the single `reload_mutex` funnel (D35).
//
// The /pktgate/reload command is registered at boot via
// `rte_telemetry_register_cmd` and invoked whenever an operator /
// test client calls it on the rte_telemetry UNIX socket
// (`/var/run/dpdk/<prefix>/dpdk_telemetry.v2`). The callback takes
// the `params` string as JSON config (the same wire format as the
// cmd_socket's `reload <json>\n` body, minus the "reload " verb
// prefix) and returns a dict with `{ok, error?, generation?, kind?}`.
//
// D35 funnel: the callback just forwards to reload::deploy(), which
// itself takes reload_mutex. Telemetry's own dispatch thread is a
// single serialised consumer, but even if that were not true the
// funnel would still hold — there is no code path here that touches
// g_active / pending_free / counters directly.
//
// This module ships only the M8-required two-way (UDS + telemetry);
// inotify/file-watch is M11 scope (scope trim §Phase 1).

#pragma once

namespace pktgate::ctl::telemetry_reload {

// Register the /pktgate/reload command with DPDK telemetry.
// Returns 0 on success, negative errno-style on failure (mirrors
// `rte_telemetry_register_cmd`). Idempotent: calling twice is safe;
// DPDK rejects duplicate registrations with -EINVAL and the second
// call simply returns the same error. Main.cpp boot wires this once
// after rte_eal_init() has started the telemetry subsystem.
int register_endpoint();

}  // namespace pktgate::ctl::telemetry_reload
