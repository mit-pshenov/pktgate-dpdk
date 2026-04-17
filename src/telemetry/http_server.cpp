// src/telemetry/http_server.cpp
//
// M10 C3 — hand-rolled HTTP `/metrics` server (D42). See
// http_server.h for contract, bounds, and anti-creep rationale.
//
// Body target: < 300 LoC. Keep it flat and auditable — this is the
// reason D42 was taken over cpp-httplib.

#include "src/telemetry/http_server.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace pktgate::telemetry {

namespace {

// ---- response builders ------------------------------------------
std::string response_status_line(int code, std::string_view reason) {
  std::string out = "HTTP/1.1 ";
  out += std::to_string(code);
  out += ' ';
  out.append(reason);
  out += "\r\n";
  return out;
}

std::string build_response(int code,
                           std::string_view reason,
                           std::string_view content_type,
                           const std::string& body) {
  std::string r = response_status_line(code, reason);
  r += "Content-Type: ";
  r.append(content_type);
  r += "\r\n";
  r += "Content-Length: ";
  r += std::to_string(body.size());
  r += "\r\n";
  r += "Connection: close\r\n";
  r += "\r\n";
  r += body;
  return r;
}

std::string build_error(int code, std::string_view reason) {
  // Short plain-text body — sized for curl output lines.
  std::string body;
  body += std::to_string(code);
  body += ' ';
  body.append(reason);
  body += '\n';
  return build_response(code, reason, "text/plain; charset=utf-8", body);
}

// ---- request parsing --------------------------------------------
// Parse "METHOD SP PATH SP HTTP/V\r\n". Returns (ok, method, path,
// version) where version is "1.0"/"1.1"/"2.0" etc. On any syntactic
// failure returns ok=false.
struct RequestLine {
  bool ok = false;
  std::string method;
  std::string path;
  std::string version;
};

RequestLine parse_request_line(std::string_view line) {
  RequestLine r;
  // Line MUST end with exactly CRLF (not bare LF, not CR+anything).
  if (line.size() < 2) return r;
  if (line[line.size() - 2] != '\r' || line[line.size() - 1] != '\n') return r;
  line.remove_suffix(2);
  // No stray CR / LF inside.
  if (line.find('\r') != std::string_view::npos) return r;
  if (line.find('\n') != std::string_view::npos) return r;
  // Exactly two spaces → three fields.
  const auto sp1 = line.find(' ');
  if (sp1 == std::string_view::npos) return r;
  const auto sp2 = line.find(' ', sp1 + 1);
  if (sp2 == std::string_view::npos) return r;
  if (line.find(' ', sp2 + 1) != std::string_view::npos) return r;

  r.method  = std::string(line.substr(0, sp1));
  r.path    = std::string(line.substr(sp1 + 1, sp2 - sp1 - 1));
  const auto vfield = line.substr(sp2 + 1);
  // Must start with "HTTP/".
  constexpr std::string_view kPfx = "HTTP/";
  if (vfield.size() <= kPfx.size()) return r;
  if (vfield.substr(0, kPfx.size()) != kPfx) return r;
  r.version = std::string(vfield.substr(kPfx.size()));
  if (r.method.empty() || r.path.empty() || r.version.empty()) return r;
  r.ok = true;
  return r;
}

// Case-insensitive prefix match for "Name:" header lookup.
bool header_name_matches(std::string_view line, std::string_view name) {
  if (line.size() < name.size() + 1) return false;
  for (std::size_t i = 0; i < name.size(); ++i) {
    char a = line[i];
    char b = name[i];
    if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
    if (b >= 'A' && b <= 'Z') b = static_cast<char>(b - 'A' + 'a');
    if (a != b) return false;
  }
  return line[name.size()] == ':';
}

// Read until CRLFCRLF or hitting the combined byte cap. Returns
// (ok, bytes_read). If cap is exceeded, bytes_read = cap+1 so the
// caller can emit 400.
std::pair<bool, std::size_t> recv_headers(int fd,
                                          std::string& buf,
                                          std::size_t cap) {
  buf.clear();
  buf.reserve(1024);
  char tmp[1024];
  while (true) {
    const ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
    if (n == 0) {
      // Peer closed. Maybe header block is already complete.
      break;
    }
    if (n < 0) {
      // recv error (timeout / EINTR / ECONNRESET).
      return {false, buf.size()};
    }
    buf.append(tmp, static_cast<std::size_t>(n));
    if (buf.size() > cap) {
      return {false, buf.size()};
    }
    if (buf.find("\r\n\r\n") != std::string::npos) {
      break;
    }
  }
  return {true, buf.size()};
}

// Write full response. send() may partial-write on non-blocking or
// SIGPIPE'd sockets; we loop until complete.
void write_all(int fd, const std::string& data) {
  std::size_t off = 0;
  while (off < data.size()) {
    const ssize_t n = ::send(fd, data.data() + off, data.size() - off,
                             MSG_NOSIGNAL);
    if (n <= 0) return;  // best-effort; peer likely gone.
    off += static_cast<std::size_t>(n);
  }
}

}  // namespace

void HttpServer::handle_client_for_test(int client_fd,
                                        const BodyFn& body_fn) {
  std::string buf;
  const auto [ok, nread] =
      recv_headers(client_fd, buf, kMaxRequestLine + kMaxHeaderBlock);

  // Hard cap breach → 400. `ok == false` may be recv error OR cap
  // exceeded; either way 400 is the right answer.
  if (!ok) {
    write_all(client_fd, build_error(400, "Bad Request"));
    ::close(client_fd);
    return;
  }

  // Find CRLF terminating request line.
  const auto line_end = buf.find("\r\n");
  if (line_end == std::string::npos) {
    // No proper request line → 400.
    write_all(client_fd, build_error(400, "Bad Request"));
    ::close(client_fd);
    return;
  }
  const std::size_t line_len = line_end + 2;
  if (line_len > kMaxRequestLine) {
    write_all(client_fd, build_error(400, "Bad Request"));
    ::close(client_fd);
    return;
  }

  const auto rl = parse_request_line(
      std::string_view(buf.data(), line_len));
  if (!rl.ok) {
    write_all(client_fd, build_error(400, "Bad Request"));
    ::close(client_fd);
    return;
  }

  // HTTP version gate — accept only 1.0 / 1.1.
  if (rl.version != "1.0" && rl.version != "1.1") {
    write_all(client_fd,
              build_error(505, "HTTP Version Not Supported"));
    ::close(client_fd);
    return;
  }

  // Header block size check (total after request line).
  const std::size_t hdr_start = line_len;
  const auto body_sep = buf.find("\r\n\r\n", hdr_start == 0 ? 0 : hdr_start - 2);
  if (body_sep == std::string::npos) {
    write_all(client_fd, build_error(400, "Bad Request"));
    ::close(client_fd);
    return;
  }
  const std::size_t hdr_len = body_sep + 4 - hdr_start;
  if (hdr_len > kMaxHeaderBlock) {
    write_all(client_fd, build_error(400, "Bad Request"));
    ::close(client_fd);
    return;
  }

  // Method gate — GET only.
  if (rl.method != "GET") {
    write_all(client_fd, build_error(405, "Method Not Allowed"));
    ::close(client_fd);
    return;
  }

  // Walk header lines; reject Content-Length / Transfer-Encoding.
  std::size_t pos = hdr_start;
  while (pos < body_sep) {
    const auto nl = buf.find("\r\n", pos);
    if (nl == std::string::npos || nl > body_sep) break;
    const std::string_view line(buf.data() + pos, nl - pos);
    if (header_name_matches(line, "content-length") ||
        header_name_matches(line, "transfer-encoding")) {
      write_all(client_fd, build_error(400, "Bad Request"));
      ::close(client_fd);
      return;
    }
    pos = nl + 2;
  }

  // Path gate — exact /metrics.
  if (rl.path != "/metrics") {
    write_all(client_fd, build_error(404, "Not Found"));
    ::close(client_fd);
    return;
  }

  // 200 + Prom body.
  std::string body = body_fn ? body_fn() : std::string{};
  write_all(client_fd,
            build_response(200, "OK",
                           "text/plain; version=0.0.4; charset=utf-8",
                           body));
  ::close(client_fd);
}

bool HttpServer::start(std::uint16_t port,
                       std::atomic<bool>& running,
                       BodyFn body_fn,
                       std::string* error_out) {
  if (started_) return false;

  int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    if (error_out) *error_out = std::string{"socket: "} + std::strerror(errno);
    return false;
  }
  int one = 1;
  ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // 127.0.0.1 only
  if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    if (error_out) *error_out = std::string{"bind: "} + std::strerror(errno);
    ::close(fd);
    return false;
  }
  socklen_t alen = sizeof(addr);
  if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &alen) != 0) {
    if (error_out) *error_out = std::string{"getsockname: "} + std::strerror(errno);
    ::close(fd);
    return false;
  }
  bound_port_ = ntohs(addr.sin_port);

  if (::listen(fd, 16) != 0) {
    if (error_out) *error_out = std::string{"listen: "} + std::strerror(errno);
    ::close(fd);
    return false;
  }

  listen_fd_ = fd;
  started_ = true;
  thread_ = std::thread(&HttpServer::run_accept_loop, this, fd,
                        &running, std::move(body_fn));
  return true;
}

void HttpServer::stop() {
  if (thread_.joinable()) {
    thread_.join();
  }
  if (listen_fd_ >= 0) {
    ::close(listen_fd_);
    listen_fd_ = -1;
  }
}

void HttpServer::run_accept_loop(int listen_fd,
                                 std::atomic<bool>* running,
                                 BodyFn body_fn) {
  while (running->load(std::memory_order_acquire)) {
    pollfd pfd{};
    pfd.fd = listen_fd;
    pfd.events = POLLIN;
    const int pr = ::poll(&pfd, 1, kAcceptPollTimeoutMs);
    if (pr <= 0) continue;  // timeout or EINTR — re-check running.
    if (!(pfd.revents & POLLIN)) continue;

    sockaddr_in ca{};
    socklen_t cl = sizeof(ca);
    int cfd =
        ::accept4(listen_fd, reinterpret_cast<sockaddr*>(&ca), &cl,
                  SOCK_CLOEXEC);
    if (cfd < 0) continue;

    // Apply SO_RCVTIMEO — bounds slowloris.
    timeval tv{};
    tv.tv_sec  = kSocketRecvTimeoutSec;
    tv.tv_usec = 0;
    ::setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    handle_client_for_test(cfd, body_fn);
  }
}

}  // namespace pktgate::telemetry
