# cmake/Gtest.cmake — test registration helper for pktgate-dpdk
#
# Exposes two entry points:
#
#   pktgate_add_test(
#       NAME   <ctest-name>            # e.g. smoke.test_build
#       SOURCES <file.cpp> [...]       # at least one translation unit
#       LABELS  <label> [...]          # one scope label, any capabilities
#       [LINK   <lib> [...]])          # extra target_link_libraries
#
#   pktgate_add_placeholder_test(
#       NAME   <ctest-name>
#       LABELS <label> [...])
#
# The first builds a real gtest binary, wires warnings + sanitizer,
# and registers it. The second registers a no-op (`cmake -E true`)
# entry so a label is reachable before a real test exists — this is
# the crutch for M0, peeled off when each later milestone actually
# fills the label with content.
#
# Labels follow harness.md §H3.1 (scope: smoke/unit/functional/corner/
# perf-dev/chaos/fuzz) and §H3.2 (capability: needs-root, needs-
# hugepages, asan-safe, tsan-safe, ubsan-safe, ...). The helper does
# not enforce the taxonomy — if you pass a typo, check-ctest-labels.sh
# will tell you at runtime, which is exactly the kind of guard rail
# D33's grep philosophy demands.

include_guard(GLOBAL)

function(pktgate_add_test)
  set(options)
  set(oneValueArgs NAME)
  set(multiValueArgs SOURCES LABELS LINK)
  cmake_parse_arguments(PGT "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

  if(NOT PGT_NAME)
    message(FATAL_ERROR "pktgate_add_test: NAME is required")
  endif()
  if(NOT PGT_SOURCES)
    message(FATAL_ERROR "pktgate_add_test(${PGT_NAME}): SOURCES is required")
  endif()
  if(NOT PGT_LABELS)
    message(FATAL_ERROR "pktgate_add_test(${PGT_NAME}): LABELS is required")
  endif()

  # Derive executable name from NAME: "smoke.test_build" -> "smoke_test_build".
  string(REPLACE "." "_" _exe "${PGT_NAME}")
  add_executable(${_exe} ${PGT_SOURCES})
  target_link_libraries(${_exe} PRIVATE GTest::gtest GTest::gtest_main ${PGT_LINK})
  pktgate_apply_warnings(${_exe})
  pktgate_apply_sanitizer(${_exe})

  add_test(NAME ${PGT_NAME} COMMAND ${_exe})
  # ctest expects labels as a single ;-separated string; forward the
  # list as-is and CMake serializes it correctly.
  set_tests_properties(${PGT_NAME} PROPERTIES LABELS "${PGT_LABELS}")
endfunction()

function(pktgate_add_placeholder_test)
  set(options)
  set(oneValueArgs NAME)
  set(multiValueArgs LABELS)
  cmake_parse_arguments(PGP "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

  if(NOT PGP_NAME OR NOT PGP_LABELS)
    message(FATAL_ERROR "pktgate_add_placeholder_test: NAME and LABELS required")
  endif()

  # `cmake -E true` is CMake's portable /bin/true. Zero-cost no-op.
  add_test(NAME ${PGP_NAME} COMMAND ${CMAKE_COMMAND} -E true)
  set_tests_properties(${PGP_NAME} PROPERTIES LABELS "${PGP_LABELS}")
endfunction()
