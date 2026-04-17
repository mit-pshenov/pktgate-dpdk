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

# Entry 2 — the D33 runtime gate. WILL_FAIL TRUE — the test IS
# expected to fail in C2 (most §10.3 names not wired). C4 flips this
# to FALSE after extending Snapshot + snapshot_metric_names().
#
# Document the ladder here so a future reader knows the RED is
# deliberate. If this test ever goes green in C2, CTest reports a
# `Failed (Ignored)` regression on the gate (WILL_FAIL + actual pass
# = CTest FAIL) — the desired signal that C4 wiring sneaked in early.
add_test(
  NAME    integration.c7_27_d33_gate
  COMMAND integration_test_c7_27_counter_invariant
          --gtest_filter=*EveryCanonicalName*
)
set_tests_properties(integration.c7_27_d33_gate
  PROPERTIES
    LABELS "integration"
    WILL_FAIL TRUE)
