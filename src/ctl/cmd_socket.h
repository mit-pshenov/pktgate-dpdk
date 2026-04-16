// src/ctl/cmd_socket.h
//
// M8 C1 — minimal UDS command socket for reload triggering.
//
// Accepts connections on an AF_UNIX SOCK_STREAM socket and funnels
// every reload request into reload::deploy() under the module's
// reload_mutex (D35). The funnel contract is the important half —
// payload/verb grammar is intentionally minimal for C1.
//
// Wire format (C1):
//   Client connects. Sends a single message:
//     "reload <json-payload>\n"
//   The bytes after "reload " until newline (or EOF) ARE the full
//   config JSON text. Simplifies X1.2 harness: same inline payload
//   per connection, no file staging.
//
//   Server replies:
//     "ok <generation>\n"          — on success
//     "err <kind>:<message>\n"     — on any deploy failure
//
// Out of C1 scope:
//   * SO_PEERCRED (D38)                          — M11
//   * allow-list gid check                        — M11
//   * inotify file-watch                          — M11 (scope trim)
//   * telemetry /pktgate/reload endpoint          — M8 C5
//   * verb routing ("activate", "stats", …)       — M11

#pragma once

#include <atomic>
#include <string>
#include <thread>

namespace pktgate::ctl {

// CmdSocketServer — single-accept-loop UDS listener.
//
// `start()` opens `path`, backlogs 16, and spawns an accept-loop
// thread. Each accepted connection handles one reload request
// (see wire format above). `stop()` flips a stop flag, wakes the
// accept loop via a self-connect to release accept(), and joins the
// thread. `path` is `unlink()`-ed on stop().
struct CmdSocketServer {
  std::string       path;
  int               listen_fd = -1;
  std::thread       server_thread;
  std::atomic<bool> running{false};
  // Counters for tests. C5 elevates these to the Prometheus surface.
  std::atomic<std::uint64_t> accepted{0};
  std::atomic<std::uint64_t> rejected{0};

  ~CmdSocketServer();
};

// Start the server. Returns false on socket / bind / listen failure.
// `path` is an AF_UNIX pathname — caller ensures the parent directory
// exists and the path is writable.
bool cmd_socket_start(CmdSocketServer& srv, const std::string& path);

// Stop the server. Idempotent. Blocks until the accept loop returns.
void cmd_socket_stop(CmdSocketServer& srv);

}  // namespace pktgate::ctl
