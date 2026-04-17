// tests/unit/test_inotify_event_filter.cpp
//
// M11 C0 — event-mask filter unit tests (Ud.3a / Ud.3b / Ud.3c / Ud.4).
//
// D38 b: watcher accepts IN_CLOSE_WRITE + IN_MOVED_TO only. All other
// event kinds (IN_MODIFY, IN_OPEN, IN_ACCESS, IN_CREATE, IN_DELETE,
// IN_MOVED_FROM, IN_ATTRIB) must be dropped.
//
// The header under test intentionally does NOT include <sys/inotify.h>
// so this TU uses hardcoded numeric constants to stand in for mocked
// kernel masks. Real kernel values will be verified via static_assert
// in C1 when the watcher TU pulls <sys/inotify.h>.

#include "src/ctl/inotify/event_filter.h"

#include <cstdint>

#include <gtest/gtest.h>

namespace {

// Mocked kernel constants (verified against <sys/inotify.h> in C1).
constexpr std::uint32_t kInAccess     = 0x00000001u;  // IN_ACCESS
constexpr std::uint32_t kInModify     = 0x00000002u;  // IN_MODIFY
constexpr std::uint32_t kInAttrib     = 0x00000004u;  // IN_ATTRIB
constexpr std::uint32_t kInCloseWrite = 0x00000008u;  // IN_CLOSE_WRITE
constexpr std::uint32_t kInOpen       = 0x00000020u;  // IN_OPEN
constexpr std::uint32_t kInMovedFrom  = 0x00000040u;  // IN_MOVED_FROM
constexpr std::uint32_t kInMovedTo    = 0x00000080u;  // IN_MOVED_TO
constexpr std::uint32_t kInCreate     = 0x00000100u;  // IN_CREATE
constexpr std::uint32_t kInDelete     = 0x00000200u;  // IN_DELETE

using pktgate::ctl::inotify::should_trigger;

}  // namespace

// Ud.3a — IN_CLOSE_WRITE is the direct-edit-then-close signal.
TEST(InotifyEventFilter, Ud_3a_AcceptsCloseWrite) {
  EXPECT_TRUE(should_trigger(kInCloseWrite));
}

// Ud.3b — IN_MOVED_TO covers atomic rename into place (`mv new config`).
TEST(InotifyEventFilter, Ud_3b_AcceptsMovedTo) {
  EXPECT_TRUE(should_trigger(kInMovedTo));
}

// Ud.3c — both bits set simultaneously (defensive: inotify can OR them).
TEST(InotifyEventFilter, Ud_3c_AcceptsCloseWriteOrMovedTo) {
  EXPECT_TRUE(should_trigger(kInCloseWrite | kInMovedTo));
}

// Ud.4 — every other kind must be dropped. This is the §F7.3 contract:
// we never react to a partial-write signal (IN_MODIFY) and we never
// reload on transient open/create/delete/attr events.
TEST(InotifyEventFilter, Ud_4_DropsEverythingElse) {
  EXPECT_FALSE(should_trigger(kInModify));
  EXPECT_FALSE(should_trigger(kInOpen));
  EXPECT_FALSE(should_trigger(kInAccess));
  EXPECT_FALSE(should_trigger(kInCreate));
  EXPECT_FALSE(should_trigger(kInDelete));
  EXPECT_FALSE(should_trigger(kInMovedFrom));
  EXPECT_FALSE(should_trigger(kInAttrib));

  // Compound rejects: even if we OR together several dropped events,
  // none of them promote to accepted.
  EXPECT_FALSE(should_trigger(kInModify | kInOpen | kInAccess));
  EXPECT_FALSE(should_trigger(kInCreate | kInDelete | kInMovedFrom));

  // Zero mask: nothing to react to.
  EXPECT_FALSE(should_trigger(0u));
}

// Ud.4b — an accepted bit mixed with dropped bits still triggers.
// The filter is additive (any accepted bit wins), not strict-equal.
TEST(InotifyEventFilter, Ud_4b_MixedMaskFiresOnAcceptedBit) {
  EXPECT_TRUE(should_trigger(kInModify | kInCloseWrite));
  EXPECT_TRUE(should_trigger(kInCreate | kInMovedTo));
}
