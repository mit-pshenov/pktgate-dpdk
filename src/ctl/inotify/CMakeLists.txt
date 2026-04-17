# src/ctl/inotify/CMakeLists.txt
#
# M11 C0 — DPDK-free control-plane library for inotify-triggered
# reload (D38 inotify half).
#
# `pktgate_inotify_ctl` hosts the debounce timer (C0), event-mask
# filter (C0, header-only), and the watcher thread (C1). Same layering
# contract as `pktgate_telemetry`: the hot path never links against
# this library. The watcher thread calls `ctl::reload::deploy()`
# through the M8-frozen public API and the single `reload_mutex`
# funnel (D35).
#
# C0 intentionally does NOT pull in <sys/inotify.h> — all kernel
# syscalls land in C1's watcher.cpp. Keeping the C0 surface kernel-
# include-free means unit tests run on any host and no static_assert
# footguns leak into tests that mock the mask values.

add_library(pktgate_inotify_ctl STATIC
  debounce.cpp
  # Header-only filter; listed so IDEs surface it and target_sources
  # sees the full public surface. No object code.
  event_filter.h
)
target_include_directories(pktgate_inotify_ctl PUBLIC ${CMAKE_SOURCE_DIR})
pktgate_apply_warnings(pktgate_inotify_ctl)
pktgate_apply_sanitizer(pktgate_inotify_ctl)
