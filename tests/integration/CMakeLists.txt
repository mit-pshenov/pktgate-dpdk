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
