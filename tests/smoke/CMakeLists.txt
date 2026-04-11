# tests/smoke/CMakeLists.txt
#
# Smoke tests — the "don't-ship-if-these-fail" floor. Run on every
# preset, on every commit, via the `smoke` ctest label.

add_executable(smoke_test_build test_build.cpp)
target_link_libraries(smoke_test_build PRIVATE GTest::gtest GTest::gtest_main)

add_test(NAME smoke.build COMMAND smoke_test_build)
set_tests_properties(smoke.build PROPERTIES LABELS "smoke")
