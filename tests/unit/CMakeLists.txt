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
