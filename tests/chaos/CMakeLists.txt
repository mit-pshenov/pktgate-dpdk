# tests/chaos/CMakeLists.txt
#
# M11 C3 — chaos test registration.
#
# Chaos tests are Python pytest scripts labelled "chaos". They are the
# stress-surface sentinels: concurrency (TSAN), storm coalescing,
# resource-exhaustion paths. Unlike functional tests, they run with
# longer timeouts and are expected to sustain activity for 10+ s.
#
# Labels: "chaos" (harness.md §H3.1; exit gate regex
# "smoke|unit|functional|integration|chaos").

find_program(PYTEST_EXECUTABLE NAMES pytest pytest-3 py.test)
if(NOT PYTEST_EXECUTABLE)
  message(STATUS "pytest not found — chaos tests will be skipped")
  return()
endif()

set(_binary "$<TARGET_FILE:pktgate_dpdk>")
set(_test_dir "${CMAKE_CURRENT_SOURCE_DIR}")

# M11 C3 — X1.1 inotify reload storm + X1.11 integration cross-check.
#
# X1.1 procedure: 2000 rename events at 100 Hz over 10 s; debounce must
# coalesce into ≤ 80 successful reloads. The test asserts monotonic
# active_generation and zero failure entries in the counter family.
#
# X1.11 unit tier lives in tests/unit/test_inotify_debounce.cpp
# (Ud.X4_X1_11_BoundaryTwoEventsYieldTwoFires) — the window-boundary
# edge case is a pure-debouncer property (clock arithmetic against
# Debouncer::window_) and more deterministic + cheaper at the unit
# tier. No chaos-tier duplicate is needed; the chaos tier owns the
# storm-coalesce invariant (X1.1) while X1.11 owns the boundary
# edge case at the tier best suited to each.
#
# Timeout sized for dev-tsan: 10 s storm + wait_ready + teardown +
# 2-5× TSAN slowdown factor. 300 s is generous; the test itself has
# an internal 30 s wall cap for the storm phase so it can't runaway.
add_test(
  NAME chaos.test_x1_reload_storm
  COMMAND ${PYTEST_EXECUTABLE} -xvs "${_test_dir}/test_x1_reload_storm.py"
)
set_tests_properties(chaos.test_x1_reload_storm PROPERTIES
  LABELS "chaos"
  ENVIRONMENT "PKTGATE_BINARY=${_binary}"
  TIMEOUT 300
)
