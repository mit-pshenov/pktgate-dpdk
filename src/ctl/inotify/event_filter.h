// src/ctl/inotify/event_filter.h
//
// M11 C0 — inotify event-mask filter (D38, inotify half).
//
// D38 b. The watcher sits on the **parent directory** of the config
// file (never on the file itself — inotify watches on a regular file
// silently break across atomic-rename and through symlink swap). Of
// the 20+ event bits the kernel can emit for a directory watch, only
// two mean "the config file is now in a fresh, fully-written state":
//
//   IN_CLOSE_WRITE (0x00000008) — editor opened, wrote, closed the file
//   IN_MOVED_TO    (0x00000080) — atomic rename `mv new.json config.json`
//
// Everything else must be ignored. In particular:
//
//   IN_MODIFY  (0x02)  — fires on every write() call during an editor
//                        save; if we reacted to it we'd parse a
//                        truncated file (§F7.3).
//   IN_OPEN    (0x20)  — irrelevant: the file hasn't changed yet.
//   IN_ACCESS  (0x01)  — irrelevant: even read() fires this.
//   IN_CREATE  (0x100) — fires on the tmp-file creation half of a
//                        `cp x config.json.tmp; mv` pattern.
//                        The matching IN_MOVED_TO on the real name
//                        is what we care about.
//   IN_DELETE  (0x200) — transient; IN_MOVED_TO / IN_CLOSE_WRITE will
//                        follow if the config reappears.
//   IN_MOVED_FROM (0x40) — dual of IN_MOVED_TO; source-side only.
//   IN_ATTRIB  (0x04)  — chmod / touch; content unchanged.
//
// Kernel constants are hardcoded here so this header stays usable in
// any TU (tests mock the masks without pulling <sys/inotify.h> into
// their own headers). The C1 watcher.cpp will `#include <sys/inotify.h>`
// and `static_assert` the constants match IN_CLOSE_WRITE / IN_MOVED_TO.

#pragma once

#include <cstdint>

namespace pktgate::ctl::inotify {

// Kernel constants from <sys/inotify.h> (verified in C1 via static_assert
// once the watcher TU pulls in the header).
inline constexpr std::uint32_t kInotifyCloseWrite = 0x00000008u;
inline constexpr std::uint32_t kInotifyMovedTo    = 0x00000080u;

inline constexpr std::uint32_t kAcceptedMask =
    kInotifyCloseWrite | kInotifyMovedTo;

// D38 b — return true iff at least one accepted bit is set in the
// event mask. Rejects partial-write signals (IN_MODIFY), open/access,
// create/delete, attr-change, moved-from.
[[nodiscard]] inline constexpr bool should_trigger(std::uint32_t event_mask) noexcept {
  return (event_mask & kAcceptedMask) != 0u;
}

}  // namespace pktgate::ctl::inotify
