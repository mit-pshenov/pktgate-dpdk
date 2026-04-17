# tests/unit/CMakeLists.txt
#
# Unit-tier tests for libpktgate_core.a — pure C++, no EAL, no mempool.
# Each cycle in M1 adds (or extends) exactly one test file here:
#
#   C1       test_parser.cpp    — U1.1, U1.2, U1.3 (top-level parser)
#   C2-C6    test_parser.cpp    — U1.4..U1.31 (parser coverage)
#   C6       test_sizing.cpp    — U1.25..U1.27 (D6 sizing)
#   C7-C11   test_validator.cpp — U2.*, C7.4..C7.9
#
# Tests link against libpktgate_core.a (the DPDK-free static lib the
# root CMakeLists.txt declares next to the product binary) plus gtest.

pktgate_add_test(
  NAME    unit.test_parser
  SOURCES test_parser.cpp
  LABELS  unit
  LINK    pktgate_core
)

pktgate_add_test(
  NAME    unit.test_addr
  SOURCES test_addr.cpp
  LABELS  unit
  LINK    pktgate_core
)

pktgate_add_test(
  NAME    unit.test_validator
  SOURCES test_validator.cpp
  LABELS  unit
  LINK    pktgate_core
)

pktgate_add_test(
  NAME    unit.test_budget_corners
  SOURCES test_budget_corners.cpp
  LABELS  unit corner
  LINK    pktgate_core
)

pktgate_add_test(
  NAME    unit.test_compiler
  SOURCES test_compiler.cpp
  LABELS  unit
  LINK    pktgate_core
)

pktgate_add_test(
  NAME    unit.test_builder
  SOURCES test_builder.cpp
  LABELS  unit
  LINK    pktgate_core
)

# M3 C4: EAL-needing unit tests. Separate binary because EAL can only
# be initialized once per process. Links pktgate_dp (which includes DPDK).
pktgate_add_test(
  NAME    unit.test_eal_unit
  SOURCES test_eal_unit.cpp
  LABELS  "unit;needs-eal"
  LINK    pktgate_dp
)
# M8 C1: flip U6.43b — g_active now lives in the reload manager
# (src/ctl/reload.{h,cpp}), not in main.cpp. Defined as a compile-time
# flag so the test body at tests/unit/test_eal_unit.cpp U6.43b can
# include the reload header and assert the owning symbol exists.
target_compile_definitions(unit_test_eal_unit PRIVATE M8_C1_DONE=1)

# M9 C0: rl_arena bucket-math (DPDK-free). U5.1 .. U5.10. The U5.8 /
# U5.9 symbol-grep tests need the on-disk archive path; we inject it
# as a quoted compile definition (see grabli_cmake_path_defines.md).
pktgate_add_test(
  NAME    unit.test_rl_arena
  SOURCES test_rl_arena.cpp
  LABELS  unit
  LINK    pktgate_rl
)
target_compile_definitions(unit_test_rl_arena PRIVATE
  "PKTGATE_RL_ARCHIVE_PATH=\"$<TARGET_FILE:pktgate_rl>\""
)

# M9 C1: RateLimitArena slot lifecycle (D24). U4.9 .. U4.12 + U4.9b
# exhaustion sentinel. Links against pktgate_rl_ctl (which pulls in
# pktgate_rl transitively). Separate TU/archive from pktgate_rl so the
# U5.9 invariant (no unordered_map / id_to_slot in the math archive)
# holds — see top-level CMakeLists.txt pktgate_rl_ctl comment.
pktgate_add_test(
  NAME    unit.test_rl_arena_slot
  SOURCES test_rl_arena_slot.cpp
  LABELS  unit
  LINK    pktgate_rl_ctl
)

# M9 C2: U5.8 extension — TSAN runtime race-free harness. Two threads
# consuming disjoint per_lcore[] slots of the same RlRow. D1 isolation
# is asserted dynamically under dev-tsan (halts on race) and statically
# under dev-asan (pass, same as the unit tier).
pktgate_add_test(
  NAME    unit.test_rl_arena_tsan
  SOURCES test_rl_arena_tsan.cpp
  LABELS  unit
  LINK    pktgate_rl_ctl
)

# M9 C4: runtime::rl_arena_gc body (D11 GC + D24 slot release + D33
# eager counter-row zeroing). Links pktgate_runtime (the DPDK-free
# TU that owns arena_gc.cpp). No EAL — the GC body operates purely
# on Ruleset::rl_actions + the arena singleton.
pktgate_add_test(
  NAME    unit.test_rl_arena_gc
  SOURCES test_rl_arena_gc.cpp
  LABELS  unit
  LINK    pktgate_runtime
)

# M10 C0: Prometheus OpenMetrics encoder formatters (U10.1 / U10.3 /
# U10.4 / U7.7). Pure string formatting, DPDK-free, no EAL. Links
# pktgate_telemetry (the control-plane archive that C1 will extend
# with snapshot + ring; C3 with HTTP endpoint). U10.2 histogram is
# DEFERRED per Phase 1 scope trim (errata §M10) — enum tag retained
# so the Phase 2 addition is a pure extension.
pktgate_add_test(
  NAME    unit.test_prom_encoder
  SOURCES test_prom_encoder.cpp
  LABELS  unit
  LINK    pktgate_telemetry
)

# M10 C1: build_snapshot pure aggregation (U7.1, U7.2, U7.6). Fake
# LcoreCounterView + fake PortStats — no DPDK, no threads, no EAL.
# Lives in pktgate_telemetry alongside the encoder so the publisher
# adapter (C3, main.cpp) sees a single archive.
pktgate_add_test(
  NAME    unit.test_snapshot_sum
  SOURCES test_snapshot_sum.cpp
  LABELS  unit
  LINK    pktgate_telemetry
)

# M10 C1: SnapshotRing single-writer + multi-reader (U7.3, U7.4).
# U7.3 includes a std::thread-based TSAN harness — publish/read loop
# under dev-tsan must be race-free (acquire/release pair on
# latest_gen_ + plain slot store BEFORE the release). Failing this
# test under dev-tsan (TSAN_OPTIONS halt_on_error=1) is the
# observable signal that D3 ring ordering regressed.
pktgate_add_test(
  NAME    unit.test_snapshot_ring
  SOURCES test_snapshot_ring.cpp
  LABELS  unit
  LINK    pktgate_telemetry
)
