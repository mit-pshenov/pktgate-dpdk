# fuzz/CMakeLists.txt
#
# libFuzzer target tree. Only add_subdirectory()-d from the root
# CMakeLists under `PKTGATE_FUZZ=ON` (the `fuzz` preset). The root
# CMakeLists does not build the product binary or the gtest tree
# in that configuration — libFuzzer requires LLVMFuzzerTestOneInput
# as the program entry point, so coexisting with gtest's `main`
# would fail the link step.
#
# Target lifecycle (matches harness.md §H2.9):
#
#   smoke_fuzz           — C5 bootstrap, proves the toolchain works.
#   fuzz_config_parser   — M1, corner.md C7.1 seeds.
#   fuzz_rule_compiler   — M2, corner.md C7.10–C7.26.
#   fuzz_l2_classify     — M4.
#   fuzz_l3_classify     — M5.
#   fuzz_l4_classify     — M6.
#
# Each real target will land alongside its implementing milestone
# and pass `LABELS fuzz` to pktgate_add_fuzz_test (not smoke). Only
# the bootstrap target below lives under `smoke` — it is cheap and
# its sole job is to catch toolchain bit-rot in the `ctest --preset
# fuzz -L smoke` gate run.

pktgate_add_fuzz_test(
  NAME    smoke.fuzz_smoke
  SOURCES smoke_fuzz.cc
  LABELS  smoke
)

# ---- parser_fuzz (M1 C12, corner.md C7.1) --------------------------------
#
# Coverage-guided fuzz target for the config parser. Feeds raw bytes
# into pktgate::config::parse() and asserts (via ASan + UBSan) that
# no crash / UB / leak occurs on any input. Seed corpus lives in
# fuzz/seeds/parser/.
#
# ctest smoke entry: `parser_fuzz -runs=1` (wiring sanity).
# CI shortrun: `parser_fuzz fuzz/seeds/parser/ -max_total_time=60`.
pktgate_add_fuzz_test(
  NAME    fuzz.parser_fuzz
  SOURCES parser_fuzz.cc
  LABELS  fuzz
)
target_link_libraries(fuzz_parser_fuzz PRIVATE pktgate_core)
