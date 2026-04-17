// src/ctl/inotify/watcher.cpp
//
// M11 C1 — InotifyWatcher thread implementation. See watcher.h.

#include "src/ctl/inotify/watcher.h"

#include <poll.h>
#include <sys/inotify.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>

#include "src/ctl/inotify/event_filter.h"

namespace pktgate::ctl::inotify {

// Verify the hardcoded event_filter.h constants match the kernel
// header (event_filter.h intentionally doesn't pull <sys/inotify.h>
// so the C0 unit tests stay kernel-include-free; C1 is the TU that
// reconciles the two).
static_assert(kInotifyCloseWrite == static_cast<std::uint32_t>(IN_CLOSE_WRITE),
              "event_filter.h kInotifyCloseWrite drift vs <sys/inotify.h>");
static_assert(kInotifyMovedTo == static_cast<std::uint32_t>(IN_MOVED_TO),
              "event_filter.h kInotifyMovedTo drift vs <sys/inotify.h>");

namespace {

// Minimal JSON log emitter. We intentionally do NOT link against the
// log_json helper in main.cpp — this library must stay free of
// main-TU coupling so unit tests that construct a watcher against a
// temp directory can run without a running pktgate process. Writes
// directly to stderr; each record is a newline-terminated JSON object.
void log_line(const std::string& body) {
  std::fputs(body.c_str(), stderr);
  std::fputc('\n', stderr);
  std::fflush(stderr);
}

// Read entire file into a std::string. Returns std::nullopt on any
// error (file not found, permission, short read etc.). Never throws.
// If the file exists but is empty, returns an empty string (valid).
bool read_file_to_string(const std::filesystem::path& path,
                         std::string& out) {
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs) {
    return false;
  }
  std::ostringstream oss;
  oss << ifs.rdbuf();
  if (ifs.bad()) {
    return false;
  }
  out = oss.str();
  return true;
}

}  // namespace

bool InotifyWatcher::start(std::filesystem::path config_path,
                           TriggerFn on_trigger,
                           std::chrono::milliseconds debounce_window) {
  // Idempotent double-start guard — mirrors SnapshotPublisher.
  bool expected = false;
  if (!started_.compare_exchange_strong(expected, true,
                                        std::memory_order_acq_rel)) {
    return true;  // already started; treat as success (no-op)
  }

  config_path_       = std::move(config_path);
  watched_basename_  = config_path_.filename().string();
  on_trigger_        = std::move(on_trigger);
  debouncer_         = Debouncer(debounce_window, nullptr);

  if (watched_basename_.empty()) {
    log_line("{\"event\":\"inotify_watch_failed\",\"reason\":"
             "\"empty_basename\"}");
    started_.store(false, std::memory_order_release);
    return false;
  }

  const std::filesystem::path parent_dir =
      config_path_.has_parent_path() ? config_path_.parent_path()
                                     : std::filesystem::path(".");

  inotify_fd_ = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
  if (inotify_fd_ < 0) {
    const int err = errno;
    log_line(std::string("{\"event\":\"inotify_watch_failed\","
                         "\"reason\":\"inotify_init1\",\"errno\":") +
             std::to_string(err) + "}");
    started_.store(false, std::memory_order_release);
    return false;
  }

  // D38: watch the directory, filter by basename. IN_CLOSE_WRITE covers
  // direct-edit; IN_MOVED_TO covers atomic-rename (cp tmp; mv tmp cfg).
  watch_desc_ = inotify_add_watch(
      inotify_fd_, parent_dir.c_str(),
      IN_CLOSE_WRITE | IN_MOVED_TO);
  if (watch_desc_ < 0) {
    const int err = errno;
    log_line(std::string("{\"event\":\"inotify_watch_failed\","
                         "\"reason\":\"inotify_add_watch\",\"errno\":") +
             std::to_string(err) + ",\"dir\":\"" + parent_dir.string() +
             "\"}");
    ::close(inotify_fd_);
    inotify_fd_ = -1;
    started_.store(false, std::memory_order_release);
    return false;
  }

  log_line("{\"event\":\"inotify_watch_ready\",\"dir\":\"" +
           parent_dir.string() + "\",\"basename\":\"" +
           watched_basename_ + "\"}");

  stop_flag_.store(false, std::memory_order_release);
  thread_ = std::thread(&InotifyWatcher::run_loop, this);
  return true;
}

void InotifyWatcher::stop() {
  stop_flag_.store(true, std::memory_order_release);
  if (thread_.joinable()) {
    thread_.join();
  }
  if (inotify_fd_ >= 0) {
    // inotify_rm_watch is implicit on close of the inotify fd; the
    // kernel drains pending events on close.
    ::close(inotify_fd_);
    inotify_fd_ = -1;
    watch_desc_ = -1;
  }
  // Leave started_ true: the watcher is one-shot by contract (same
  // convention as SnapshotPublisher).
}

void InotifyWatcher::run_loop() {
  // inotify_event + max NAME_MAX + 1 slack, rounded up to a
  // comfortable buffer so we can read several events per syscall.
  // kernel doesn't split a single event across reads.
  constexpr std::size_t kBufSize = 4096;
  alignas(struct inotify_event) char buf[kBufSize];

  while (!stop_flag_.load(std::memory_order_acquire)) {
    struct pollfd pfd{};
    pfd.fd     = inotify_fd_;
    pfd.events = POLLIN;

    const int pr = ::poll(&pfd, 1, kPollTickMs);

    if (pr < 0) {
      if (errno == EINTR) {
        continue;  // signal — re-check stop flag next iter
      }
      log_line(std::string("{\"event\":\"inotify_poll_error\","
                           "\"errno\":") +
               std::to_string(errno) + "}");
      // Back off: don't tight-loop on a broken fd. Next iteration
      // checks stop flag, so shutdown still lands within kPollTickMs.
      continue;
    }

    if (pr > 0 && (pfd.revents & POLLIN)) {
      // Drain all currently-available events. Read returns
      // EAGAIN when the queue is empty (IN_NONBLOCK).
      for (;;) {
        const ssize_t n = ::read(inotify_fd_, buf, kBufSize);
        if (n < 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) break;
          if (errno == EINTR) continue;
          log_line(std::string("{\"event\":\"inotify_read_error\","
                               "\"errno\":") +
                   std::to_string(errno) + "}");
          break;
        }
        if (n == 0) break;

        ssize_t off = 0;
        while (off < n) {
          auto* ev = reinterpret_cast<struct inotify_event*>(buf + off);
          const std::size_t rec_size =
              sizeof(struct inotify_event) + ev->len;

          // Filter by basename: the watch is on the parent directory
          // and kernel delivers events for every child. ev->len==0
          // means a directory-self event (ignore).
          const bool name_match =
              ev->len > 0 &&
              std::strcmp(ev->name, watched_basename_.c_str()) == 0;

          if (name_match && should_trigger(ev->mask)) {
            debouncer_.feed();
          }

          off += static_cast<ssize_t>(rec_size);
        }
      }
    }

    // Whether or not we got an event, check if the debouncer is
    // ready to fire. This also drives the window-elapsed case where
    // events stopped arriving and we just need the clock to tick.
    if (debouncer_.poll()) {
      std::string contents;
      if (!read_file_to_string(config_path_, contents)) {
        log_line(std::string("{\"event\":\"inotify_read_config_failed\","
                             "\"path\":\"") +
                 config_path_.string() + "\"}");
        // Skip the trigger; next event re-fires the debounce.
        continue;
      }
      if (on_trigger_) {
        // Callback owns its own error handling (ctl::reload::deploy
        // returns DeployResult + logs). Catch any stray exception so
        // it never unwinds the thread.
        try {
          on_trigger_(std::move(contents));
        } catch (...) {
          log_line("{\"event\":\"inotify_trigger_exception\"}");
        }
      }
    }
  }
}

}  // namespace pktgate::ctl::inotify
