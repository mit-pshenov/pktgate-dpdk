// src/telemetry/http_server.h
//
// M10 C3 — hand-rolled HTTP `/metrics` server. D42 anchor (review-
// notes.md): control-plane HTTP is project-owned, NOT vendored
// (no cpp-httplib, no Boost.Beast). One verb + one path + one
// bound port — 10 k LoC single-header dep is unjustified.
//
// Hard-bounded shape (D42):
//   * Bind 127.0.0.1:<port> AF_INET only. IPv6 NOT supported on
//     Phase 1 — Prometheus scrape is always v4 on local loopback.
//     (Phase 2 may re-open this; until then, no `::1` listen.)
//   * Accept HTTP/1.0 and HTTP/1.1 request lines. Response always
//     framed as HTTP/1.1. HTTP/2.0+ → 505 Version Not Supported.
//   * Verb = GET only. Non-GET → 405 Method Not Allowed.
//   * Path = exact `/metrics`. Any other path → 404 Not Found.
//   * Malformed request line (missing CRLF, bare LF / CR, wrong
//     field count) → 400 Bad Request.
//   * `Content-Length` or `Transfer-Encoding` header on GET → 400
//     (body-bearing GET rejected — no request-body parser).
//   * Request-line cap 8 KB; header-block total cap 8 KB. Oversized
//     request line → 400. Oversized headers → 400.
//   * Response always carries `Connection: close`. No keep-alive,
//     no chunked transfer, no gzip, no TLS, no auth, no threadpool.
//   * `SO_RCVTIMEO = 5 s` bounds slowloris — a client that drips
//     bytes under the 5 s read deadline gets dropped.
//   * Single accept thread, sequential request handling. Prometheus
//     scrape cadence ≈ 1 req / 15 s — a reactor is unjustified.
//
// Shutdown: the accept loop uses `poll(2)` with 100 ms timeout and
// checks `running->load(acquire)`; when false, the loop exits.
// `stop()` joins the thread. Same lifecycle atomic contract as
// SnapshotPublisher (D1 amendment 2026-04-17 — acquire-load on
// lifecycle flag is NOT a hot-path RMW).
//
// Body generation: the server takes a `BodyFn` callback. Unit tests
// supply a static string fake; main.cpp supplies a lambda that
// reads the snapshot ring + feeds the Prom encoder.
//
// TU size target: <300 LoC body. Enforced at code-review time (D42
// anti-creep rail: if it's > 300 LoC, something non-essential has
// crept in — review before merging).

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

namespace pktgate::telemetry {

class HttpServer {
 public:
  // Signature of the 200-OK body generator. Called per accepted
  // GET /metrics request (sequential; the server never calls this
  // concurrently). Returns the body payload as a std::string —
  // the server adds Content-Length, Content-Type, Connection:close.
  //
  // May be invoked with an empty ring (the publisher hasn't run
  // yet): the callback is expected to return "" (valid empty body)
  // in that case, NOT throw. The server emits 200 + Content-Length:0
  // so the scrape stays syntactically valid.
  using BodyFn = std::function<std::string()>;

  // Hard bounds — also exposed for tests so U10.X6/X7 can pin the
  // exact request-line / header cap numbers.
  static constexpr std::size_t kMaxRequestLine  = 8192;   // 8 KB
  static constexpr std::size_t kMaxHeaderBlock  = 8192;   // 8 KB
  // SO_RCVTIMEO on the accepted socket — slowloris bound.
  static constexpr int kSocketRecvTimeoutSec    = 5;
  // `poll(2)` timeout in the accept loop — wake interval for
  // shutdown responsiveness.
  static constexpr int kAcceptPollTimeoutMs     = 100;

  HttpServer() = default;
  HttpServer(const HttpServer&) = delete;
  HttpServer& operator=(const HttpServer&) = delete;
  HttpServer(HttpServer&&) = delete;
  HttpServer& operator=(HttpServer&&) = delete;
  ~HttpServer() { stop(); }

  // Start listening on 127.0.0.1:port. If `port == 0`, the OS
  // assigns an ephemeral port — `bound_port()` returns it (used by
  // functional tests for isolation). Returns true on success; on
  // failure, emits an errno-bearing message via `error_out` when
  // non-null and returns false.
  //
  // `running` and `body_fn` must outlive the server.
  bool start(std::uint16_t port,
             std::atomic<bool>& running,
             BodyFn body_fn,
             std::string* error_out = nullptr);

  // Join the accept thread. Safe to call repeatedly / without start.
  // Does NOT flip `running` — caller owns that flag.
  void stop();

  // Ephemeral port assigned by the kernel when start was called
  // with port==0. Available after start() returns true. Returns 0
  // if the server has not been started.
  std::uint16_t bound_port() const { return bound_port_; }

  // Single-request synchronous handler. Exposed for unit tests
  // (U10.X1..X11) that build a fake socket pair and pipe the
  // request line/headers through this entry point without spawning
  // the accept thread. Reads up to `kMaxRequestLine +
  // kMaxHeaderBlock` bytes from `client_fd`, writes the full HTTP
  // response, then closes `client_fd`.
  //
  // Public for test hooking; main.cpp never calls this directly.
  void handle_client_for_test(int client_fd, const BodyFn& body_fn);

 private:
  void run_accept_loop(int listen_fd,
                       std::atomic<bool>* running,
                       BodyFn body_fn);

  std::thread thread_;
  int listen_fd_{-1};
  std::uint16_t bound_port_{0};
  bool started_{false};
};

}  // namespace pktgate::telemetry
