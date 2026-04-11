# tests/smoke/CMakeLists.txt
#
# Smoke tests — the "don't-ship-if-these-fail" floor. Run on every
# preset, on every commit, via the `smoke` ctest label.

function(pktgate_add_smoke_test name)
  add_executable(smoke_${name} ${name}.cpp)
  target_link_libraries(smoke_${name} PRIVATE GTest::gtest GTest::gtest_main)
  pktgate_apply_warnings(smoke_${name})
  pktgate_apply_sanitizer(smoke_${name})
  add_test(NAME smoke.${name} COMMAND smoke_${name})
  set_tests_properties(smoke.${name} PROPERTIES LABELS "smoke")
endfunction()

pktgate_add_smoke_test(test_build)
pktgate_add_smoke_test(test_presets)
