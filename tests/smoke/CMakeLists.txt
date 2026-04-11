# tests/smoke/CMakeLists.txt
#
# Smoke tests — the "don't-ship-if-these-fail" floor. Run on every
# preset, on every commit, via the `smoke` ctest label.

pktgate_add_test(
  NAME    smoke.test_build
  SOURCES test_build.cpp
  LABELS  smoke
)

pktgate_add_test(
  NAME    smoke.test_presets
  SOURCES test_presets.cpp
  LABELS  smoke
)

# Label-reachability guard. Not a gtest binary — shell script that
# runs `ctest -N -L <label>` and asserts each required label matches
# >= 1 test. Runs on every smoke-label invocation, so label drift is
# caught on every commit and under every preset.
add_test(
  NAME smoke.label_reachability
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/check-ctest-labels.sh"
          "${CMAKE_BINARY_DIR}"
)
set_tests_properties(smoke.label_reachability PROPERTIES LABELS "smoke")
