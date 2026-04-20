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

# M16 C4 — chaos part 1: mirror destination link-down mid-burst.
#
# Three-tap harness boots pktgate with an L4 mirror rule. A sustained
# 1000-packet / 100 Hz stream is injected on the ingress tap; ~300
# packets in, the mirror destination's kernel-side link is brought
# down via `ip link set dtap_m16c_mir down` with txqueuelen=1. The
# drain side of the D16 mirror staging now sees rte_eth_tx_burst
# short-bursting frames, bumping `pktgate_mirror_dropped_total{port}`.
# Originals continue flowing on the independent egress stage path.
#
# Timeout sized for dev-tsan: ~10 s inject + ~2.5 s drain + 15 s
# boot + 2-5× TSAN slowdown factor. 200 s is comfortable headroom.
add_test(
  NAME chaos.test_m16_mirror_port_gone
  COMMAND ${PYTEST_EXECUTABLE} -xvs
          "${_test_dir}/test_m16_mirror_port_gone.py"
)
set_tests_properties(chaos.test_m16_mirror_port_gone PROPERTIES
  LABELS "chaos"
  ENVIRONMENT "PKTGATE_BINARY=${_binary}"
  TIMEOUT 200
)

# M16 C4 — chaos part 2: mirror mempool exhaustion.
#
# Tiny mbuf pool forces rte_pktmbuf_copy to fail on a fast 1000-packet
# burst, bumping `pktgate_mirror_clone_failed_total{port}`. Mempool
# sizing is controlled via PKTGATE_TEST_MBUF_POOL_SIZE (test-only env
# var); the knob is NOT yet wired in src/main.cpp — the RED commit
# pytest.skips with an explicit reason, and the GREEN cycle lands the
# one-line env override + flips the threshold-impossible assertions.
add_test(
  NAME chaos.test_m16_mirror_mempool_exhaust
  COMMAND ${PYTEST_EXECUTABLE} -xvs
          "${_test_dir}/test_m16_mirror_mempool_exhaust.py"
)
set_tests_properties(chaos.test_m16_mirror_mempool_exhaust PROPERTIES
  LABELS "chaos"
  ENVIRONMENT "PKTGATE_BINARY=${_binary}"
  TIMEOUT 200
)

# M16 C5 — chaos part 3: mirror destination slow consumer + recovery.
#
# Three-tap harness boots pktgate with an L4 mirror rule; the mirror
# tap's kernel txqueuelen is clamped to 1 (link stays UP) so the tun
# queue drains glacially relative to the inject rate. A sustained
# 2000-packet / 200 Hz stream piles clones at the kernel boundary;
# `rte_eth_tx_burst` short-bursts and `pktgate_mirror_dropped_total
# {port}` climbs. Mid-stream (~3 s in) the clamp is released
# (txqueuelen restored to 1000) and `pktgate_mirror_sent_total
# {port}` bumps resume — recovery semantic distinct from port_gone.
#
# See memory grabli_tap_tbf_wrong_side.md for why tc tbf/netem on
# the tap egress side is NOT the correct mechanism (wrong side of
# /dev/net/tun); txqueuelen=1 with link-up is the textbook
# slow-consumer recipe for net_tap.
#
# Timeout sized for dev-tsan: ~10 s inject + ~2.5 s drain + 15 s
# boot + 2-5× TSAN slowdown factor. 240 s is comfortable headroom.
add_test(
  NAME chaos.test_m16_mirror_slow_consumer
  COMMAND ${PYTEST_EXECUTABLE} -xvs
          "${_test_dir}/test_m16_mirror_slow_consumer.py"
)
set_tests_properties(chaos.test_m16_mirror_slow_consumer PROPERTIES
  LABELS "chaos"
  ENVIRONMENT "PKTGATE_BINARY=${_binary}"
  TIMEOUT 240
)
