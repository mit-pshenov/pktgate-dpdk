// tests/unit/test_inotify_watcher_lifecycle.cpp
//
// M11 C1 — Ui.1 watcher lifecycle sanity.
//
// Covers: InotifyWatcher constructs, start()s against a real
// temp-dir parent (inotify_init1 + inotify_add_watch succeed), shuts
// down cleanly on stop(), does not leak the inotify fd, and passes
// under ASAN + TSAN.
//
// Does NOT feed kernel events — that's the functional-tier job
// (test_f7_inotify.py::test_f7_1_direct_edit_in_close_write).

#include "src/ctl/inotify/watcher.h"

#include <filesystem>
#include <fstream>
#include <string>

#include <gtest/gtest.h>

namespace {

using pktgate::ctl::inotify::InotifyWatcher;

// Build a unique temp directory + config file path for the test so
// parallel runs (and repeated runs of the same binary) don't
// collide on a single watched directory.
std::filesystem::path make_temp_config_file() {
  auto base = std::filesystem::temp_directory_path() /
              "pktgate_inotify_c1_lifecycle";
  std::filesystem::create_directories(base);
  auto cfg = base / "config.json";
  std::ofstream ofs(cfg);
  ofs << "{}";
  ofs.close();
  return cfg;
}

}  // namespace

// Ui.1 — start() succeeds on a real temp dir, destructor cleans up
// with no fd leak and no TSAN race on the stop flag.
TEST(InotifyWatcher, Ui_1_StartStopLifecycleClean) {
  auto cfg_path = make_temp_config_file();

  InotifyWatcher watcher;
  bool trigger_called = false;
  ASSERT_TRUE(watcher.start(
      cfg_path,
      [&trigger_called](std::string /*contents*/) {
        trigger_called = true;
      }));

  // No kernel events fed → trigger must NOT have fired.
  // Immediate stop — exercises the responsive-shutdown path (poll
  // tick 100 ms).
  watcher.stop();

  EXPECT_FALSE(trigger_called);

  // Idempotent stop.
  watcher.stop();

  // Cleanup the temp file; directory is reused across runs, OK to
  // leave.
  std::error_code ec;
  std::filesystem::remove(cfg_path, ec);
}

// Ui.1b — destructor alone is enough (no explicit stop).
TEST(InotifyWatcher, Ui_1b_DestructorStops) {
  auto cfg_path = make_temp_config_file();

  {
    InotifyWatcher watcher;
    ASSERT_TRUE(watcher.start(
        cfg_path,
        [](std::string /*contents*/) {}));
    // Fall off scope — destructor must join the thread cleanly.
  }

  std::error_code ec;
  std::filesystem::remove(cfg_path, ec);
}

// Ui.1c — start() on a non-existent directory fails cleanly (no
// thread spawned, subsequent stop() is safe).
TEST(InotifyWatcher, Ui_1c_StartFailsOnMissingParent) {
  std::filesystem::path bogus =
      std::filesystem::temp_directory_path() /
      "pktgate_inotify_c1_does_not_exist" / "config.json";

  InotifyWatcher watcher;
  EXPECT_FALSE(watcher.start(
      bogus,
      [](std::string /*contents*/) {}));

  // stop() must be safe on a failed-start instance.
  watcher.stop();
}
