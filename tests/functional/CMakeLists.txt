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
