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
