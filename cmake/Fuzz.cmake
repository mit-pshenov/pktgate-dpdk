# cmake/Fuzz.cmake — libFuzzer target wiring for pktgate-dpdk
#
# Exposes one entry point:
#
#   pktgate_add_fuzz_test(
#       NAME    <ctest-name>           # e.g. smoke.fuzz_smoke
#       SOURCES <file.cc> [...]        # at least one translation unit
#       [LABELS  <label> [...]])       # defaults to "smoke" for the
#                                      # bootstrap target; real fuzz
#                                      # targets in M1+ use "fuzz"
#
# The helper is only included under the `fuzz` CMake preset, where
# PKTGATE_FUZZ=ON. Under the five dev-* presets the fuzz subtree is
# skipped entirely, so this file is never load-bearing there — we
# gate on PKTGATE_FUZZ anyway to make a mis-wired add_subdirectory
# loudly reject itself instead of silently producing a broken binary.
#
# Why not just re-use pktgate_add_test: gtest binaries have `main()`,
# libFuzzer binaries must not — the runtime supplies its own `main`
# and expects the target to define `LLVMFuzzerTestOneInput` instead.
# The two link models are incompatible, so the preset matrix keeps
# them on disjoint build dirs (`build/dev-*` vs `build/fuzz`) and
# CMake only wires one family per configure.
#
# Runtime wiring (harness.md §H2.9):
#   * -O1 -g -fno-omit-frame-pointer (already in CMakePresets.json
#     CMAKE_CXX_FLAGS)
#   * -fsanitize=fuzzer,address,undefined on both compile and link,
#     applied here per-target so the fuzz preset's root CMakeLists
#     doesn't force the flags onto unrelated helpers if any land.
#   * -fno-sanitize-recover=all — a finding must abort, not warn.
#
# ctest entry runs the binary with `-runs=1` so a smoke invocation
# just instantiates libFuzzer, executes LLVMFuzzerTestOneInput once
# on an empty input, and exits 0. Per-target corpus directories and
# time budgets (harness.md §H4.7 / §H4.8) will layer on top in later
# milestones; C5 is only the toolchain bootstrap.

include_guard(GLOBAL)

if(NOT PKTGATE_FUZZ)
  message(FATAL_ERROR
    "pktgate: cmake/Fuzz.cmake included without PKTGATE_FUZZ=ON. "
    "Fuzz targets only build under the `fuzz` CMake preset.")
endif()

# libFuzzer is clang-only on the toolchain matrix pinned by D2 and
# harness.md §H2.9. Refuse to pretend otherwise — a gcc fuzz build
# compiles but the link step fails with a confusing missing-symbol
# error on __sanitizer_cov_trace_pc_guard.
if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  message(FATAL_ERROR
    "pktgate: fuzz preset requires clang (got '${CMAKE_CXX_COMPILER_ID}'). "
    "harness.md §H2.9 pins clang for libFuzzer.")
endif()

function(pktgate_add_fuzz_test)
  set(options)
  set(oneValueArgs NAME)
  set(multiValueArgs SOURCES LABELS)
  cmake_parse_arguments(PGF "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

  if(NOT PGF_NAME)
    message(FATAL_ERROR "pktgate_add_fuzz_test: NAME is required")
  endif()
  if(NOT PGF_SOURCES)
    message(FATAL_ERROR "pktgate_add_fuzz_test(${PGF_NAME}): SOURCES is required")
  endif()
  if(NOT PGF_LABELS)
    # C5 bootstrap: smoke.fuzz_smoke lands under `smoke` so the cycle
    # exit gate `ctest --preset fuzz -L smoke` actually sees it. When
    # real fuzz targets land in M1+ they'll pass LABELS fuzz explicitly.
    set(PGF_LABELS smoke)
  endif()

  # Derive executable name: "smoke.fuzz_smoke" -> "smoke_fuzz_smoke".
  string(REPLACE "." "_" _exe "${PGF_NAME}")
  add_executable(${_exe} ${PGF_SOURCES})

  # libFuzzer flags. Also keep the warning wall so dead or sloppy
  # fuzz-target code still gets -Werror-ed the same way product code
  # does (Warnings.cmake is already included by the root CMakeLists).
  target_compile_options(${_exe} PRIVATE
    -fsanitize=fuzzer,address,undefined
    -fno-sanitize-recover=all
    -fno-omit-frame-pointer)
  target_link_options(${_exe} PRIVATE
    -fsanitize=fuzzer,address,undefined)
  pktgate_apply_warnings(${_exe})

  # The ctest entry runs the fuzz binary in "one iteration and exit"
  # mode. harness.md §H4.7 documents `-max_total_time=60` for the
  # shortrun CI job — that's a separate invocation from this smoke
  # entry, which is purely a wiring sanity check.
  add_test(
    NAME    ${PGF_NAME}
    COMMAND $<TARGET_FILE:${_exe}> -runs=1
  )
  set_tests_properties(${PGF_NAME} PROPERTIES LABELS "${PGF_LABELS}")
endfunction()
