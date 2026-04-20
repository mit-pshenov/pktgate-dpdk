# tests/functional/CMakeLists.txt
#
# M3 C1 — functional test registration.
#
# Functional tests are Python pytest scripts. They are registered as
# CTest entries that invoke pytest with the appropriate markers. The
# binary must be built before running these tests.
#
# Labels: "functional" (harness.md §H3.1).

# Find pytest.
find_program(PYTEST_EXECUTABLE NAMES pytest pytest-3 py.test)
if(NOT PYTEST_EXECUTABLE)
  message(STATUS "pytest not found — functional tests will be skipped")
  return()
endif()

# Register each test file as a CTest entry.
# The PKTGATE_BINARY env var tells conftest.py where to find the binary.
set(_binary "$<TARGET_FILE:pktgate_dpdk>")
set(_test_dir "${CMAKE_CURRENT_SOURCE_DIR}")

add_test(
  NAME functional.test_boot
  COMMAND ${PYTEST_EXECUTABLE} -xvs "${_test_dir}/test_boot.py"
)
set_tests_properties(functional.test_boot PROPERTIES
  LABELS "functional"
  ENVIRONMENT "PKTGATE_BINARY=${_binary}"
  TIMEOUT 30
)

add_test(
  NAME functional.test_d28_tx_symmetry
  COMMAND ${PYTEST_EXECUTABLE} -xvs "${_test_dir}/test_d28_tx_symmetry.py"
)
set_tests_properties(functional.test_d28_tx_symmetry PROPERTIES
  LABELS "functional"
  ENVIRONMENT "PKTGATE_BINARY=${_binary}"
  TIMEOUT 30
)

add_test(
  NAME functional.test_d39_scatter
  COMMAND ${PYTEST_EXECUTABLE} -xvs "${_test_dir}/test_d39_scatter.py"
)
set_tests_properties(functional.test_d39_scatter PROPERTIES
  LABELS "functional"
  ENVIRONMENT "PKTGATE_BINARY=${_binary}"
  TIMEOUT 30
)

# M4 C8 — F2.1-F2.9 L2 happy-path functional tests.
# Uses net_tap vdevs and scapy packet injection; requires root (NM keyfile
# write + scapy AF_PACKET injection).  Longer timeout because each test
# boots a fresh EAL instance.
add_test(
  NAME functional.test_f2_l2
  COMMAND ${PYTEST_EXECUTABLE} -xvs "${_test_dir}/test_f2_l2.py"
)
set_tests_properties(functional.test_f2_l2 PROPERTIES
  LABELS "functional"
  ENVIRONMENT "PKTGATE_BINARY=${_binary}"
  TIMEOUT 240
)

# M4 C9 — F8.14: QinQ outer-only counter visibility through stats_on_exit.
# Uses a dedicated dtap_f8_* interface pair, shares the nm_unmanaged_tap
# fixture with F2 (conftest.py lists both f2 and f8 names).
add_test(
  NAME functional.test_f8_qinq_counter
  COMMAND ${PYTEST_EXECUTABLE} -xvs "${_test_dir}/test_f8_qinq_counter.py"
)
set_tests_properties(functional.test_f8_qinq_counter PROPERTIES
  LABELS "functional"
  ENVIRONMENT "PKTGATE_BINARY=${_binary}"
  TIMEOUT 60
)

# M6 C5 — F2.17-F2.25: L4 happy-path functional tests.
# Uses dtap_l4_* interface pair. FIB DIR24_8 needs ~128 MB heap so
# tests use --no-huge -m 512. Longer timeout for 9 sub-tests.
add_test(
  NAME functional.test_f2_l4
  COMMAND ${PYTEST_EXECUTABLE} -xvs "${_test_dir}/test_f2_l4.py"
)
set_tests_properties(functional.test_f2_l4 PROPERTIES
  LABELS "functional"
  ENVIRONMENT "PKTGATE_BINARY=${_binary}"
  TIMEOUT 300
)

# M5 C10 — F4.1-F4.10: Fragment handling L3 functional tests.
# Uses dtap_f4_* interface pair. FIB DIR24_8 needs ~128 MB heap so
# tests use --no-huge -m 512. Longer timeout for 10 sub-tests.
add_test(
  NAME functional.test_f4_l3
  COMMAND ${PYTEST_EXECUTABLE} -xvs "${_test_dir}/test_f4_l3.py"
)
set_tests_properties(functional.test_f4_l3 PROPERTIES
  LABELS "functional"
  ENVIRONMENT "PKTGATE_BINARY=${_binary}"
  TIMEOUT 300
)

# M7 C3 — F3.1-F3.7: ALLOW/DROP/TAG action end-to-end functional tests.
# M7 C4 — extended with F3.9/F3.10 (REDIRECT, needs a third tap vdev
# dtap_f3_redir) + F3.17 (MIRROR compile-time reject, no taps needed).
# First functional suite that verifies egress *packet contents* (scapy
# AsyncSniffer on dtap_f3_tx).  FIB needs --no-huge -m 512 even without
# L3 rules.  10 sub-tests, each boots a fresh EAL instance → generous
# timeout.
add_test(
  NAME functional.test_f3_action
  COMMAND ${PYTEST_EXECUTABLE} -xvs "${_test_dir}/test_f3_action.py"
)
set_tests_properties(functional.test_f3_action PROPERTIES
  LABELS "functional"
  ENVIRONMENT "PKTGATE_BINARY=${_binary}"
  TIMEOUT 420
)

# M8 C5 — F5.11..F5.14: reload functional tests (UDS cmd_socket +
# telemetry two-way + simulate-verb observable counters). No packet
# injection; each test brings up the binary with --ctl-sock and
# drives it over a Python AF_UNIX socket, then parses stats_on_exit
# for the reload counter family.
add_test(
  NAME functional.test_f5_reload
  COMMAND ${PYTEST_EXECUTABLE} -xvs "${_test_dir}/test_f5_reload.py"
)
set_tests_properties(functional.test_f5_reload PROPERTIES
  LABELS "functional"
  ENVIRONMENT "PKTGATE_BINARY=${_binary}"
  TIMEOUT 180
)

# M10 C3 — F8.1 / F8.16 / F8.17 / F8.18: Prometheus /metrics HTTP
# endpoint. Uses net_null vdevs (no packet injection needed — scrape
# works off the snapshot ring regardless of dataplane traffic).
# Needs prometheus_client for F8.1 OpenMetrics parsing (skipped
# gracefully if absent). Boots fresh EAL per test-case; 4 cases
# under 8 s each + EAL teardown slack → 120 s total.
add_test(
  NAME functional.test_f8_metrics
  COMMAND ${PYTEST_EXECUTABLE} -xvs "${_test_dir}/test_f8_metrics.py"
)
set_tests_properties(functional.test_f8_metrics PROPERTIES
  LABELS "functional"
  ENVIRONMENT "PKTGATE_BINARY=${_binary}"
  TIMEOUT 180
)

# M11 C1 — F7.1: inotify direct-edit IN_CLOSE_WRITE triggers exactly
# one reload. Uses net_null vdevs (no dataplane traffic needed —
# assertion is purely on the /metrics scrape of the reload counter
# family). Boots one binary, rewrites the watched config file in
# place, polls /metrics for the bump. Extended in C2 with F7.2..F7.6.
add_test(
  NAME functional.test_f7_inotify
  COMMAND ${PYTEST_EXECUTABLE} -xvs "${_test_dir}/test_f7_inotify.py"
)
set_tests_properties(functional.test_f7_inotify PROPERTIES
  LABELS "functional"
  ENVIRONMENT "PKTGATE_BINARY=${_binary}"
  TIMEOUT 120
)

# M9 C5 — F3.12..F3.16: rate-limit end-to-end functional tests.
# Uses dedicated dtap_f3rl_* interface pair. FIB DIR24_8 needs ~128 MB
# heap so tests use --no-huge -m 512. F3.16 alone sleeps 5 s, F3.13
# hammers 200 packets; 5 sub-tests each boot a fresh EAL instance →
# long timeout.
add_test(
  NAME functional.test_f3_ratelimit
  COMMAND ${PYTEST_EXECUTABLE} -xvs "${_test_dir}/test_f3_ratelimit.py"
)
set_tests_properties(functional.test_f3_ratelimit PROPERTIES
  LABELS "functional"
  ENVIRONMENT "PKTGATE_BINARY=${_binary}"
  TIMEOUT 300
)

# M14 C2 — F14.1..F14.4 + F14.boot_smoke: main.cpp port resolution
# via the C1 resolver + D41 boot-path guard. No taps, no NM keyfile;
# pure control-plane wiring tests using net_null vdevs. 5 sub-tests
# each boot a fresh EAL instance → 120 s is comfortable.
add_test(
  NAME functional.test_f14_main_resolver
  COMMAND ${PYTEST_EXECUTABLE} -xvs "${_test_dir}/test_f14_main_resolver.py"
)
set_tests_properties(functional.test_f14_main_resolver PROPERTIES
  LABELS "functional"
  ENVIRONMENT "PKTGATE_BINARY=${_binary}"
  TIMEOUT 120
)

# M14 C4 — F14.6 TAP visibility smoke + F14.7 slow-consumer drop scrape.
# Boots pktgate on two net_tap vdevs (dtap_m14_ing / dtap_m14_egr) via
# the D43 interface_roles selectors, injects with scapy, asserts egress
# sniff + /metrics scrape of pktgate_tx_dropped_total{port} /
# pktgate_tx_burst_short_total{port}. Requires root (scapy AF_PACKET
# inject + tc qdisc). 2 sub-tests × EAL cold start + sniff/throttle
# settles → 180 s timeout.
add_test(
  NAME functional.test_f14_tap_exit
  COMMAND ${PYTEST_EXECUTABLE} -xvs "${_test_dir}/test_f14_tap_exit.py"
)
set_tests_properties(functional.test_f14_tap_exit PROPERTIES
  LABELS "functional"
  ENVIRONMENT "PKTGATE_BINARY=${_binary}"
  TIMEOUT 180
)

# M16 C3 — F16.2 TAP mirror happy path + F16.3 unresolved target_port
# reject. Boots pktgate on three net_tap vdevs (dtap_m16_ing /
# dtap_m16_egress / dtap_m16_mirror) via the D43 interface_roles
# selectors, injects 50 UDP packets with scapy on the ingress tap,
# asserts dual AsyncSniffer capture (egress + mirror) sets match
# inject set AND /metrics scrape of pktgate_mirror_{sent,clone_failed,
# dropped}_total{port}. F16.3 surfaces the validator's
# kUnresolvedTargetPort reject path. Requires root (scapy AF_PACKET
# inject + NM keyfile + sysctl). 2 sub-tests × EAL cold-start + dual
# sniff settles -> 180 s timeout (matches F14.7 budget).
add_test(
  NAME functional.test_f16_mirror_tap
  COMMAND ${PYTEST_EXECUTABLE} -xvs "${_test_dir}/test_f16_mirror_tap.py"
)
set_tests_properties(functional.test_f16_mirror_tap PROPERTIES
  LABELS "functional"
  ENVIRONMENT "PKTGATE_BINARY=${_binary}"
  TIMEOUT 180
)

# M15 C1 — F15.1 vhost boot smoke. net_null upstream + net_vhost
# downstream (server mode); asserts pktgate reaches ready without a
# peer, emits a port_resolved event naming the vhost port id, and
# creates the configured UDS socket inode at /run/pktgate/. Pure
# control-plane — no TAP / NM keyfile / NDP surface. Data-plane vhost
# exercise lands in M15 C3 (testpmd pair) and C4 (peer crash chaos).
# Requires root (creates /run/pktgate/ and sockets).
#
# M15 C2 — same file extended with F15.2 (SIGTERM unlink), F15.2b
# (normal-exit unlink; D41 twin of F15.2), F15.3 (stale-socket guard
# on boot). 4 sub-tests each boot a fresh EAL instance → 240 s
# timeout.
add_test(
  NAME functional.test_f15_vhost_boot
  COMMAND ${PYTEST_EXECUTABLE} -xvs "${_test_dir}/test_f15_vhost_boot.py"
)
set_tests_properties(functional.test_f15_vhost_boot PROPERTIES
  LABELS "functional"
  ENVIRONMENT "PKTGATE_BINARY=${_binary}"
  TIMEOUT 240
)
