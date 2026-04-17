// src/ctl/inotify/watcher.h
//
// M11 C1 — inotify watcher thread (D38 inotify half).
//
// Watches the **parent directory** of a config file for
// `IN_CLOSE_WRITE | IN_MOVED_TO` events on the file's basename
// (D38 b: watch the directory, never the file). On each accepted
// event feeds the debouncer; when the debouncer fires (§9.3 — 150 ms
// quiescent window) the watcher reads the current file contents
// into memory and invokes the caller-supplied `on_trigger(contents)`
// callback.
//
// Wiring: in production `on_trigger` calls `ctl::reload::deploy()`,
// which funnels through the D35 `reload_mutex`. The watcher does
// NOT re-implement any part of the reload pipeline — it is a pure
// event → debounce → read → deploy bridge.
//
// Thread lifecycle mirrors `SnapshotPublisher` (M10 C1/C3):
//   * owned `std::thread`,
//   * `std::atomic<bool>` stop flag,
//   * `poll(fd, 1, 100ms)` tick so shutdown stays responsive,
//   * `stop()` sets the flag + joins; destructor calls `stop()`.
//
// Shutdown ordering (§9.3, mirror of publisher):
//   main.cpp stops the watcher BEFORE tearing down EAL / reload
//   manager / workers — same sequence `SnapshotPublisher.stop()`
//   already occupies. This keeps `reload::deploy()` from being
//   invoked after `reload::shutdown()` has torn down `g_active`.
//
// No exceptions are allowed to escape the worker thread; any
// runtime failure (inotify read error, file read failure, etc.) is
// logged + the loop continues. The next event retries.

#pragma once

#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <string>
#include <thread>

#include "src/ctl/inotify/debounce.h"

namespace pktgate::ctl::inotify {

class InotifyWatcher {
 public:
  // Signature of the trigger callback. Receives the freshly-read
  // contents of the watched file. Runs on the watcher thread; must
  // be thread-safe w.r.t. whatever it touches (typically
  // ctl::reload::deploy(), which is already D35-serialised).
  using TriggerFn = std::function<void(std::string /*config_contents*/)>;

  // Poll tick budget (also the upper bound on shutdown latency).
  // 100 ms mirrors SnapshotPublisher::kWakeIntervalMs so the two
  // control-plane threads have identical shutdown cadence under
  // `g_running.store(false)`.
  static constexpr int kPollTickMs = 100;

  InotifyWatcher() = default;
  InotifyWatcher(const InotifyWatcher&) = delete;
  InotifyWatcher& operator=(const InotifyWatcher&) = delete;
  InotifyWatcher(InotifyWatcher&&) = delete;
  InotifyWatcher& operator=(InotifyWatcher&&) = delete;
  ~InotifyWatcher() { stop(); }

  // Spawn the watcher thread.
  //   * `config_path` — absolute or relative path to the config file.
  //     The watcher takes an inotify watch on the parent directory
  //     and filters events by `config_path.filename()`.
  //   * `on_trigger` — called with the freshly-read file contents on
  //     each debounced fire. Copied into an internal std::function
  //     member.
  //   * `debounce_window` — defaults to §9.3 (150 ms).
  //
  // Returns false on inotify_init1 / inotify_add_watch failure; the
  // failure reason is emitted via a log_json line identifiable by
  // `{"event":"inotify_watch_failed", ...}`. Does not throw.
  //
  // Calling start() twice without an intervening stop() is a
  // programmer error; the second call is a silent no-op (preserves
  // thread_).
  bool start(std::filesystem::path config_path,
             TriggerFn on_trigger,
             std::chrono::milliseconds debounce_window =
                 std::chrono::milliseconds(150));

  // Signal shutdown + join. Idempotent. Safe to call without a
  // prior start(). Does not throw.
  void stop();

 private:
  void run_loop();

  std::thread           thread_;
  std::atomic<bool>     stop_flag_{false};
  std::atomic<bool>     started_{false};

  int                   inotify_fd_ = -1;
  int                   watch_desc_ = -1;
  std::filesystem::path config_path_;
  std::string           watched_basename_;
  TriggerFn             on_trigger_;
  Debouncer             debouncer_;
};

}  // namespace pktgate::ctl::inotify
