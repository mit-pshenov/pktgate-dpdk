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
