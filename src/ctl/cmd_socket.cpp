// src/ctl/cmd_socket.cpp
//
// M8 C1 — minimal UDS command socket implementation.
//
// One thread per server; each accepted connection handled inline in
// that thread. Serialization across connections is provided by the
// single accept-loop + reload::deploy()'s reload_mutex (D35): even if
// two clients race on connect, the server accepts and handles them
// sequentially, and each deploy() takes the mutex.
//
// This is intentionally simple. M11 will add proper verb routing,
// SO_PEERCRED (D38), gid allow-list, and concurrent accept handling
// if throughput demands it. For C1, the one-connection-at-a-time
// shape is exactly what X1.2 exercises.

#include "src/ctl/cmd_socket.h"

#include <cerrno>
#include <cstring>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "src/ctl/reload.h"

namespace pktgate::ctl {

namespace {

constexpr std::size_t kMaxRequestBytes = 64 * 1024;  // 64 KB cap; plenty for M8 configs.

// Read the full request from `fd`. Reads until either newline, EOF,
// or the request cap. Returns the raw bytes read (newline included if
// observed); caller parses.
std::string read_request(int fd) {
  std::string buf;
  buf.reserve(1024);
  char tmp[1024];
  while (buf.size() < kMaxRequestBytes) {
    ssize_t n = ::read(fd, tmp, sizeof(tmp));
    if (n < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (n == 0) break;  // peer closed
    buf.append(tmp, static_cast<std::size_t>(n));
    // Stop on first newline — the wire format is single-line-delimited.
    if (buf.find('\n') != std::string::npos) break;
  }
  return buf;
}

// write() wrapper that retries on short write / EINTR. Best-effort —
// the server does not care if the client hangs up before receiving
// the reply (the deploy() call is already committed at that point).
void write_all(int fd, std::string_view s) {
  const char* p = s.data();
  std::size_t left = s.size();
  while (left > 0) {
    ssize_t n = ::write(fd, p, left);
    if (n < 0) {
      if (errno == EINTR) continue;
      return;
    }
    p += n;
    left -= static_cast<std::size_t>(n);
  }
}

// Handle a single connection. Reads the request, extracts the
// "reload <json>" payload, calls reload::deploy(), writes the reply.
void handle_connection(int cfd) {
  std::string req = read_request(cfd);

  // Strip trailing newline for parsing.
  while (!req.empty() && (req.back() == '\n' || req.back() == '\r')) {
    req.pop_back();
  }

  // C5 — test-only simulate verbs. These take no payload and just
  // invoke the named reload-manager hook. Used by the F5.12/F5.13/F5.14
  // functional tests so Python can drive timeout/drain/overflow
  // without owning QSBR state. The production reload path is
  // completely untouched.
  constexpr std::string_view kVerbSimTimeout = "simulate-timeout";
  constexpr std::string_view kVerbSimDrain   = "simulate-drain";
  if (std::string_view(req) == kVerbSimTimeout) {
    reload::simulate_timeout_for_test();
    write_all(cfd, std::string_view("ok simulate-timeout\n"));
    return;
  }
  if (std::string_view(req) == kVerbSimDrain) {
    reload::simulate_drain_for_test();
    write_all(cfd, std::string_view("ok simulate-drain\n"));
    return;
  }

  constexpr std::string_view kVerb = "reload";
  if (req.size() < kVerb.size() ||
      std::string_view(req).substr(0, kVerb.size()) != kVerb) {
    write_all(cfd, std::string_view("err bad_verb:expected 'reload <json>'\n"));
    return;
  }

  // Everything after "reload " (if present) is the JSON payload. For
  // "reload\n" with no payload, pass an empty string (will hit the
  // parser's error path cleanly).
  std::string_view payload;
  if (req.size() > kVerb.size()) {
    std::size_t start = kVerb.size();
    // Skip one separator (' ' or any whitespace).
    if (req[start] == ' ' || req[start] == '\t') ++start;
    payload = std::string_view(req).substr(start);
  }

  reload::DeployResult r = reload::deploy(payload);
  if (r.ok) {
    std::string reply = "ok " + std::to_string(r.generation) + "\n";
    write_all(cfd, reply);
  } else {
    std::string reply = "err " + std::to_string(static_cast<int>(r.kind)) +
                        ":" + r.error + "\n";
    write_all(cfd, reply);
  }
}

void accept_loop(CmdSocketServer* srv) {
  while (srv->running.load(std::memory_order_acquire)) {
    const int lfd = srv->listen_fd.load(std::memory_order_acquire);
    if (lfd < 0) break;
    int cfd = ::accept(lfd, nullptr, nullptr);
    if (cfd < 0) {
      if (errno == EINTR) continue;
      // Listen fd was closed from under us — shutdown path.
      break;
    }
    // Recheck running — a wake-up connect from stop() may have raced
    // us to accept. Close and exit cleanly.
    if (!srv->running.load(std::memory_order_acquire)) {
      ::close(cfd);
      break;
    }
    srv->accepted.fetch_add(1, std::memory_order_relaxed);
    handle_connection(cfd);
    ::close(cfd);
  }
}

}  // namespace

bool cmd_socket_start(CmdSocketServer& srv, const std::string& path) {
  srv.path = path;

  int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return false;

  // Ensure no stale socket from a prior run.
  ::unlink(path.c_str());

  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  // -1 leaves room for the NUL. Reject paths that wouldn't fit.
  if (path.size() + 1 > sizeof(addr.sun_path)) {
    ::close(fd);
    return false;
  }
  std::memcpy(addr.sun_path, path.data(), path.size());

  if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    ::close(fd);
    return false;
  }
  if (::listen(fd, 16) < 0) {
    ::close(fd);
    ::unlink(path.c_str());
    return false;
  }

  srv.listen_fd.store(fd, std::memory_order_release);
  srv.running.store(true, std::memory_order_release);
  srv.server_thread = std::thread(accept_loop, &srv);
  return true;
}

void cmd_socket_stop(CmdSocketServer& srv) {
  if (!srv.running.exchange(false, std::memory_order_acq_rel)) {
    // Already stopped (or never started).
    return;
  }

  // Wake the accept loop by closing the listen fd. Any in-flight
  // accept() returns EBADF / EINVAL and the loop exits.
  int fd = srv.listen_fd.exchange(-1, std::memory_order_acq_rel);
  if (fd >= 0) {
    ::shutdown(fd, SHUT_RDWR);
    ::close(fd);
  }

  // Also do a dummy connect to unblock accept() on some kernels where
  // close() alone isn't enough. Best-effort; ignore errors.
  {
    int wake = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (wake >= 0) {
      sockaddr_un addr{};
      addr.sun_family = AF_UNIX;
      std::memcpy(addr.sun_path, srv.path.data(),
                  std::min(srv.path.size(), sizeof(addr.sun_path) - 1));
      (void)::connect(wake, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
      ::close(wake);
    }
  }

  if (srv.server_thread.joinable()) {
    srv.server_thread.join();
  }

  ::unlink(srv.path.c_str());
}

CmdSocketServer::~CmdSocketServer() {
  cmd_socket_stop(*this);
}

}  // namespace pktgate::ctl
