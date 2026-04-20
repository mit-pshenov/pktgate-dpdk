# tests/integration/CMakeLists.txt
#
# M8 C0 — integration tier scaffold.
#
# Integration tests bring up a real DPDK EAL instance (same pattern as
# tests/unit/test_eal_unit.cpp) and exercise subsystems that cannot be
# covered by pure-C++ unit tests or Python functional tests: RCU-QSBR
# lifecycle, reload coordination (D9/D30/D35/D36), shutdown sequencing
# (D12), validator memory budget (D37), arena GC ordering (D11). The
# tier is the *only* home for D30/D35/D36 scenarios per the M8 plan —
# unit tests cannot run real QSBR, functional tests cannot reach into
# the reload_manager internals.
#
# Cycles wiring this tree (supervisor handoff: scratch/m8-supervisor-
# handoff.md):
#   C0  test_reload.cpp   — EAL + QSBR bring-up fixture + smoke (THIS FILE)
#   C1  test_reload.cpp   — deploy() happy path, reload_mutex funnel
#   C2  test_reload.cpp   — D30 token+deadline, D12 bounded sync (X1.4, X1.11)
#   C3  test_reload.cpp   — D36 pending_free queue (X1.5, X1.10-short)
#   C4  test_reload.cpp   — D12 shutdown sequence, D37 budget gate (X1.6/X1.7)
#   C5  test_reload.cpp   — F5.11-F5.14 reload-observable counters + X1.3
#
# Binaries link pktgate_dp (DPDK-aware) + GTest, same as test_eal_unit.
# Label `integration` is the scope handle — callers filter with
# `ctest -L integration`. CI gates add it alongside smoke/unit/
# functional: `ctest -L "smoke|unit|functional|integration"`.

pktgate_add_test(
  NAME    integration.test_reload
  SOURCES test_reload.cpp
  LABELS  "integration;needs-eal"
  LINK    pktgate_dp
)

# M9 C2 — hot-path integration of the rl_arena. Drives apply_action
# through the real RateLimit verb arm with the arena singleton, and
# asserts per-lcore isolation on the dispatch path. Links pktgate_dp
# (DPDK-aware) + pktgate_rl_ctl (control-plane arena singleton) —
# pktgate_dp already links pktgate_rl_ctl transitively because the
# RateLimit verb path pulls the arena type in from action_dispatch.
pktgate_add_test(
  NAME    integration.test_rl_integration
  SOURCES test_rl_integration.cpp
  LABELS  "integration;needs-eal"
  LINK    pktgate_dp pktgate_rl_ctl
)

# M9 C3 — compile → build roundtrip for rate-limit rules. Tests the
# full config → CompiledAction.rl_slot → RuleAction.rl_index +
# Ruleset::rl_actions[slot] pipeline in lockstep; see errata §M7 C2b /
# §M8 C5 for the D41 "silent pipeline gap" class this guards against.
# No EAL required — build_ruleset (M2 zero-arg path) is DPDK-free and
# the arena singleton has its own storage.
pktgate_add_test(
  NAME    integration.test_rl_compile_build
  SOURCES test_rl_compile_build.cpp
  LABELS  "integration"
  LINK    pktgate_core pktgate_rl_ctl
)

# M10 C2 — D33 living invariant, runtime enumeration arm (C7.27).
#
# RED → GREEN ladder across C2 → C4.
#
# The binary bundles three TEST cases:
#   * EveryCanonicalNameHasProducerOrIsJustifiedZero — the D33 gate.
#       Fails in C2 because most §10.3 names are not wired through
#       Snapshot yet. WILL_FAIL TRUE on the primary ctest entry below
#       so a RED gtest result counts as PASS. C4 wires the missing
#       names + flips WILL_FAIL to FALSE.
#   * ScalarFamilyWired         — C1 wiring safety net; must stay GREEN.
#   * ManifestIsSorted          — manifest uniqueness; must stay GREEN.
#
# Two ctest entries share one binary and split by --gtest_filter:
# `integration.c7_27_sanity` runs the must-be-green cases (standard
# label), and `integration.c7_27_d33_gate` runs only the D33 gate with
# WILL_FAIL TRUE so RED counts as PASS in C2.
#
# We build the executable directly (not via pktgate_add_test) because
# the helper would also register a default wildcard ctest entry, and
# we want explicit control over which gtest cases each ctest entry
# invokes. The warnings + sanitizer helpers are applied manually.
#
# DPDK-free — links pktgate_telemetry + pktgate_core only. No EAL init,
# no mempool. Snapshot-direct harness: builds fake producer state
# in-process and calls build_snapshot() directly. C5 may re-run the
# same assertion over a live /metrics scrape (F8.2) as end-to-end
# validation.
add_executable(integration_test_c7_27_counter_invariant
  test_c7_27_counter_invariant.cpp
)
target_link_libraries(integration_test_c7_27_counter_invariant
  PRIVATE GTest::gtest GTest::gtest_main pktgate_telemetry pktgate_core
)
pktgate_apply_warnings(integration_test_c7_27_counter_invariant)
pktgate_apply_sanitizer(integration_test_c7_27_counter_invariant)

# Entry 1 — sanity cases (GREEN, standard `integration` label).
add_test(
  NAME    integration.c7_27_sanity
  COMMAND integration_test_c7_27_counter_invariant
          --gtest_filter=*ScalarFamilyWired*:*ManifestIsSorted*
)
set_tests_properties(integration.c7_27_sanity
  PROPERTIES LABELS "integration")

# Entry 2 — the D33 runtime gate. WILL_FAIL flipped to FALSE in M10 C4:
# Snapshot now surfaces every §10.3 name via extended LcoreCounterView /
# ReloadState / ActiveRuleCounts plus the justified-zero list covers
# the Phase-2 deferrals (lcore_packets, lcore_idle_iters,
# lcore_cycles_per_burst, mirror_dropped). If a new §10.3 name ever
# lands without Snapshot wiring, this test RED will be a real failure —
# exactly the living-invariant signal D33 exists to provide.
add_test(
  NAME    integration.c7_27_d33_gate
  COMMAND integration_test_c7_27_counter_invariant
          --gtest_filter=*EveryCanonicalName*
)
set_tests_properties(integration.c7_27_d33_gate
  PROPERTIES
    LABELS "integration"
    WILL_FAIL FALSE)

# M15 C3 — paired DPDK integration harness.
#
# test_m15_vhost_pair.py spawns pktgate (net_vhost server) alongside
# `dpdk-testpmd` (net_virtio_user client) on a shared UDS and verifies
# the data-plane round-trip: scapy → net_tap ingress → pktgate pipeline
# → net_vhost TX → virtio-user consumer. First integration-tier Python
# pytest entry; CMake needs a find_program(pytest) gate + a generic
# pytest-based add_test (mirror of tests/functional/CMakeLists.txt).
#
# Requires root (scapy AF_PACKET inject + /run/dpdk/ ownership + tap
# bring-up + NM keyfile write) — ctest is launched under sudo by the
# preset matrix.
find_program(PYTEST_EXECUTABLE NAMES pytest pytest-3 py.test)
if(PYTEST_EXECUTABLE)
  set(_binary "$<TARGET_FILE:pktgate_dpdk>")
  set(_test_dir "${CMAKE_CURRENT_SOURCE_DIR}")

  add_test(
    NAME integration.test_m15_vhost_pair
    COMMAND ${PYTEST_EXECUTABLE} -xvs "${_test_dir}/test_m15_vhost_pair.py"
  )
  set_tests_properties(integration.test_m15_vhost_pair PROPERTIES
    LABELS "integration"
    ENVIRONMENT "PKTGATE_BINARY=${_binary}"
    TIMEOUT 240
  )

  # M15 C4 — peer-crash chaos (F15.4). Extends the C3 pair harness with
  # a mid-burst SIGKILL of the virtio-user consumer; asserts pktgate
  # survives and tx_dropped_total{port=<vhost_id>} climbs. No new
  # counter families — the M14 C3 backend-agnostic family covers
  # vhost peer-gone by construction.
  add_test(
    NAME integration.test_m15_vhost_peer_crash
    COMMAND ${PYTEST_EXECUTABLE} -xvs "${_test_dir}/test_m15_vhost_peer_crash.py"
  )
  set_tests_properties(integration.test_m15_vhost_peer_crash PROPERTIES
    LABELS "integration;chaos"
    ENVIRONMENT "PKTGATE_BINARY=${_binary}"
    TIMEOUT 240
  )
else()
  message(STATUS
    "pytest not found — integration.test_m15_vhost_pair + "
    "integration.test_m15_vhost_peer_crash will be skipped"
  )
endif()
