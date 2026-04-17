// tests/unit/test_http_server.cpp
//
// M10 C3 — unit tests for the hand-rolled HTTP server (D42).
//
// RED → GREEN coverage — U10.X1..X11 (D42 anti-creep rail list).
// Each test drives the server through a `socketpair(2)` so we exercise
// the real request parser / response formatter without binding a TCP
// port (unit tier).
//
//   * U10.X1 — `GET /metrics HTTP/1.1` → 200
//   * U10.X2 — `GET /metrics HTTP/1.0` → 200 (normalised to /1.1 resp)
//   * U10.X3 — `POST /metrics HTTP/1.1` → 405
//   * U10.X4 — `GET /healthz HTTP/1.1` → 404
//   * U10.X5 — `GET /metrics HTTP/2.0` → 505
//   * U10.X6 — request-line 8193 bytes → 400
//              request-line 8192 bytes → accepted (boundary proof)
//   * U10.X7 — header block 8193 bytes → 400
//   * U10.X8 — GET with `Content-Length: 5` → 400 (no body expected)
//   * U10.X9 — 200 response carries `Content-Length`, `Content-Type`,
//              `Connection: close`
//   * U10.X10 — 4xx / 5xx response carries minimal body +
//               `Connection: close`
//   * U10.X11 — malformed request line (bare LF, bare CR, \r\r\n) →
//               400
//
// Pure C++, POSIX only. Links pktgate_telemetry.

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "src/telemetry/http_server.h"

namespace {

using ::pktgate::telemetry::HttpServer;

// Drive the server's handler through a blocking socketpair. Sends
// `request` to the server side, returns the full server response.
// Uses SOCK_STREAM AF_UNIX — interchangeable with an AF_INET socket
// from the handler's perspective (recv/send are socket-agnostic).
std::string run_exchange(const std::string& request,
                     HttpServer::BodyFn body_fn = [] {
                       return std::string{"# HELP foo\nfoo 1\n"};
                     }) {
  int sv[2];
  if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
    ADD_FAILURE() << "socketpair failed";
    return {};
  }
  // sv[0] = client end, sv[1] = server end.

  // Write the full request to the client end, then close write-side
  // so the server sees EOF. The server is sequential; single write
  // is fine for request sizes up to the socket buffer (64 KB on
  // Linux defaults, well above our 8 KB cap).
  if (!request.empty()) {
    const ssize_t wrote = ::send(sv[0], request.data(), request.size(), 0);
    EXPECT_EQ(static_cast<std::size_t>(wrote), request.size());
  }
  // Half-close the client side so the server's recv returns 0 if it
  // reads past the request. This makes the server's read bounded
  // even if the request is shorter than the CRLF-CRLF header
  // terminator.
  ::shutdown(sv[0], SHUT_WR);

  HttpServer server;
  server.handle_client_for_test(sv[1], body_fn);
  // handle_client_for_test closes sv[1] before returning.

  // Read full response from client end.
  std::string response;
  char buf[4096];
  while (true) {
    const ssize_t n = ::recv(sv[0], buf, sizeof(buf), 0);
    if (n <= 0) break;
    response.append(buf, static_cast<std::size_t>(n));
  }
  ::close(sv[0]);
  return response;
}

// Extract status code from response line "HTTP/1.1 <code> <reason>".
int status_code(std::string_view resp) {
  const auto sp1 = resp.find(' ');
  if (sp1 == std::string_view::npos) return -1;
  const auto sp2 = resp.find(' ', sp1 + 1);
  if (sp2 == std::string_view::npos) return -1;
  const auto code_sv = resp.substr(sp1 + 1, sp2 - sp1 - 1);
  try {
    return std::stoi(std::string{code_sv});
  } catch (...) {
    return -1;
  }
}

bool has_header(std::string_view resp, std::string_view header_line) {
  // case-sensitive; server emits canonical case
  return resp.find(header_line) != std::string_view::npos;
}

// ------------------------------------------------------------------
// U10.X1 — GET /metrics HTTP/1.1 → 200.
// ------------------------------------------------------------------
TEST(HttpServer, U10_X1_GetMetricsHttp11Accepted) {
  const std::string req =
      "GET /metrics HTTP/1.1\r\n"
      "Host: localhost\r\n"
      "\r\n";
  const auto resp = run_exchange(req);
  EXPECT_EQ(status_code(resp), 200);
  // Response ALWAYS framed as HTTP/1.1.
  EXPECT_EQ(resp.substr(0, 9), "HTTP/1.1 ");
}

// ------------------------------------------------------------------
// U10.X2 — GET /metrics HTTP/1.0 → 200 (normalised to /1.1 response).
// ------------------------------------------------------------------
TEST(HttpServer, U10_X2_GetMetricsHttp10AcceptedNormalisedResponse) {
  const std::string req =
      "GET /metrics HTTP/1.0\r\n"
      "\r\n";
  const auto resp = run_exchange(req);
  EXPECT_EQ(status_code(resp), 200);
  // Response framing is still /1.1 — D42 rule.
  EXPECT_EQ(resp.substr(0, 9), "HTTP/1.1 ");
}

// ------------------------------------------------------------------
// U10.X3 — POST /metrics → 405.
// ------------------------------------------------------------------
TEST(HttpServer, U10_X3_PostMetrics405) {
  const std::string req =
      "POST /metrics HTTP/1.1\r\n"
      "Content-Length: 0\r\n"
      "\r\n";
  const auto resp = run_exchange(req);
  EXPECT_EQ(status_code(resp), 405);
  EXPECT_TRUE(has_header(resp, "Connection: close"));
}

// ------------------------------------------------------------------
// U10.X4 — GET /healthz → 404.
// ------------------------------------------------------------------
TEST(HttpServer, U10_X4_GetHealthz404) {
  const std::string req =
      "GET /healthz HTTP/1.1\r\n"
      "\r\n";
  const auto resp = run_exchange(req);
  EXPECT_EQ(status_code(resp), 404);
  EXPECT_TRUE(has_header(resp, "Connection: close"));
}

// ------------------------------------------------------------------
// U10.X5 — GET /metrics HTTP/2.0 → 505.
// ------------------------------------------------------------------
TEST(HttpServer, U10_X5_GetMetricsHttp2_0Rejected) {
  const std::string req =
      "GET /metrics HTTP/2.0\r\n"
      "\r\n";
  const auto resp = run_exchange(req);
  EXPECT_EQ(status_code(resp), 505);
  EXPECT_TRUE(has_header(resp, "Connection: close"));
}

// ------------------------------------------------------------------
// U10.X5b — GET /metrics HTTP/0.9 → 505 (symmetric — no /0.9 support).
// ------------------------------------------------------------------
TEST(HttpServer, U10_X5b_GetMetricsHttp0_9Rejected) {
  const std::string req =
      "GET /metrics HTTP/0.9\r\n"
      "\r\n";
  const auto resp = run_exchange(req);
  EXPECT_EQ(status_code(resp), 505);
}

// ------------------------------------------------------------------
// U10.X6 — request-line cap: 8192 OK, 8193 rejected.
// ------------------------------------------------------------------
TEST(HttpServer, U10_X6_RequestLineCapBoundary) {
  // Build a request line with `GET /<pad> HTTP/1.1\r\n` where the
  // total length (including \r\n) is kMaxRequestLine=8192. Padding
  // makes the path unknown → 404, proving the line was parsed.
  //
  //   Fixed: "GET /" (5) + " HTTP/1.1\r\n" (11) = 16 bytes.
  //   Variable path size = 8192 - 16 = 8176.
  {
    const std::size_t pad = HttpServer::kMaxRequestLine - 16;
    std::string req = "GET /";
    req.append(pad, 'a');
    req += " HTTP/1.1\r\n\r\n";
    ASSERT_EQ(req.find("\r\n") + 2, HttpServer::kMaxRequestLine);
    const auto resp = run_exchange(req);
    // Parsed successfully → 404 (unknown path).
    EXPECT_EQ(status_code(resp), 404)
        << "request line at exactly kMaxRequestLine must be accepted "
           "and routed";
  }

  // 8193-byte request line (one over the cap) → 400.
  {
    const std::size_t pad = HttpServer::kMaxRequestLine - 16 + 1;
    std::string req = "GET /";
    req.append(pad, 'a');
    req += " HTTP/1.1\r\n\r\n";
    ASSERT_EQ(req.find("\r\n") + 2, HttpServer::kMaxRequestLine + 1u);
    const auto resp = run_exchange(req);
    EXPECT_EQ(status_code(resp), 400)
        << "request line one byte over kMaxRequestLine must be rejected";
  }
}

// ------------------------------------------------------------------
// U10.X7 — header-block cap: 8193 bytes total → 400.
// ------------------------------------------------------------------
TEST(HttpServer, U10_X7_HeaderBlockOversized400) {
  std::string req =
      "GET /metrics HTTP/1.1\r\n";
  // Pad headers until the header block crosses kMaxHeaderBlock.
  // Each header line: "X-Pad-N: <val>\r\n". We build one big header
  // value that by itself exceeds the cap.
  std::string big_header = "X-Pad: ";
  big_header.append(HttpServer::kMaxHeaderBlock + 16, 'a');
  big_header += "\r\n\r\n";
  req += big_header;
  const auto resp = run_exchange(req);
  EXPECT_EQ(status_code(resp), 400);
  EXPECT_TRUE(has_header(resp, "Connection: close"));
}

// ------------------------------------------------------------------
// U10.X8 — Content-Length on GET → 400.
// ------------------------------------------------------------------
TEST(HttpServer, U10_X8_ContentLengthOnGet400) {
  const std::string req =
      "GET /metrics HTTP/1.1\r\n"
      "Content-Length: 5\r\n"
      "\r\n"
      "hello";
  const auto resp = run_exchange(req);
  EXPECT_EQ(status_code(resp), 400)
      << "GET with Content-Length must be rejected (no body parser)";
}

// ------------------------------------------------------------------
// U10.X8b — Transfer-Encoding on GET → 400.
// ------------------------------------------------------------------
TEST(HttpServer, U10_X8b_TransferEncodingOnGet400) {
  const std::string req =
      "GET /metrics HTTP/1.1\r\n"
      "Transfer-Encoding: chunked\r\n"
      "\r\n";
  const auto resp = run_exchange(req);
  EXPECT_EQ(status_code(resp), 400);
}

// ------------------------------------------------------------------
// U10.X9 — 200 response carries the three required headers.
// ------------------------------------------------------------------
TEST(HttpServer, U10_X9_200ResponseHeaders) {
  const std::string req =
      "GET /metrics HTTP/1.1\r\n"
      "\r\n";
  const auto resp = run_exchange(req, [] {
    return std::string{"# HELP pktgate_test 1\npktgate_test 42\n"};
  });
  EXPECT_EQ(status_code(resp), 200);
  EXPECT_TRUE(has_header(resp, "Content-Length: "));
  // Prom convention: `version=0.0.4`.
  EXPECT_TRUE(has_header(resp, "Content-Type: text/plain"));
  EXPECT_TRUE(has_header(resp, "Connection: close"));
  // Body echoes what the BodyFn returned.
  EXPECT_NE(resp.find("pktgate_test 42"), std::string::npos);
}

// ------------------------------------------------------------------
// U10.X10 — error response carries minimal body + Connection: close.
// ------------------------------------------------------------------
TEST(HttpServer, U10_X10_ErrorResponseMinimalBody) {
  const std::string req =
      "GET /healthz HTTP/1.1\r\n"
      "\r\n";
  const auto resp = run_exchange(req);
  EXPECT_EQ(status_code(resp), 404);
  // Body is a short textual reason — server emits at least a tiny
  // explanatory line so operators see it in curl output.
  EXPECT_TRUE(has_header(resp, "Content-Length: "));
  EXPECT_TRUE(has_header(resp, "Connection: close"));
  // Response must terminate cleanly (headers + body, no trailing
  // garbage beyond declared Content-Length).
  EXPECT_NE(resp.find("\r\n\r\n"), std::string::npos);
}

// ------------------------------------------------------------------
// U10.X11 — malformed request line → 400.
// ------------------------------------------------------------------
TEST(HttpServer, U10_X11a_BareLF400) {
  // Bare LF (no CR).
  const std::string req = "GET /metrics HTTP/1.1\n\n";
  const auto resp = run_exchange(req);
  EXPECT_EQ(status_code(resp), 400)
      << "bare LF must be rejected (HTTP requires CRLF per RFC 7230)";
}

TEST(HttpServer, U10_X11b_BareCR400) {
  // Bare CR, no LF.
  const std::string req = "GET /metrics HTTP/1.1\r\r\n";
  const auto resp = run_exchange(req);
  EXPECT_EQ(status_code(resp), 400);
}

TEST(HttpServer, U10_X11c_WrongFieldCount400) {
  // Request line missing the HTTP-version field.
  const std::string req = "GET /metrics\r\n\r\n";
  const auto resp = run_exchange(req);
  EXPECT_EQ(status_code(resp), 400);
}

}  // namespace
