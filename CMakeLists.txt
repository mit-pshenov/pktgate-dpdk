# pktgate-dpdk — root CMakeLists
#
# Build system entry point. The C++ baseline (D2), warning wall
# (D25), DPDK discovery (harness.md §H1) and the preset/fuzz gate
# are all set up here. Per-milestone history lives in `git log`
# and `implementation-plan.md`, not in this header — don't turn
# this comment back into a cycle changelog.
#
# Modules (cmake/):
#   Warnings.cmake    — -Wall -Wextra -Wpedantic -Werror -Wswitch-enum
#   Sanitizers.cmake  — PKTGATE_SANITIZER={asan,ubsan,tsan,""} wiring
#   Gtest.cmake       — pktgate_add_test / pktgate_add_placeholder_test
#   Fuzz.cmake        — included only under PKTGATE_FUZZ=ON

cmake_minimum_required(VERSION 3.22)
project(pktgate_dpdk
  VERSION 0.0.0
  LANGUAGES CXX
)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(Warnings)
include(Sanitizers)
include(Gtest)

# ---- Fuzz preset gate (M0 C5) --------------------------------------------
#
# PKTGATE_FUZZ is set by the `fuzz` CMake preset (see CMakePresets.json,
# harness.md §H2.9). When it is ON, this tree builds ONLY the fuzz
# target subdirectory — the product binary, the gtest tree, and the
# placeholder labels are all skipped. Reason: libFuzzer binaries use
# LLVMFuzzerTestOneInput as the entry point, which is mutually
# exclusive with gtest's `main()` under `-fsanitize=fuzzer`. Mixing
# them in one build directory fails the link step in confusing ways,
# so we keep `build/fuzz` and `build/dev-*` as disjoint worlds.
option(PKTGATE_FUZZ
  "Build the fuzz/ subtree (libFuzzer, clang-only) instead of product+tests"
  OFF)
if(PKTGATE_FUZZ)
  include(Fuzz)
endif()

# ---- C++ baseline (D2) ---------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile_commands.json for clangd / clang-tidy (harness.md §H8.5).
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# -fPIC everywhere. Required by the tsan preset (harness.md §H5.3); doing
# it globally from the start avoids a future link-time surprise.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Every preset bakes PKTGATE_PRESET so tests/smoke/test_presets.cpp can
# cross-check the preset name against the compiler's view of sanitizer
# reality. Fallback for the manual `cmake ..` case without a preset.
if(NOT DEFINED PKTGATE_PRESET_NAME)
  set(PKTGATE_PRESET_NAME "dev-debug")
endif()
add_compile_definitions(PKTGATE_PRESET=${PKTGATE_PRESET_NAME})

# ---- Locate DPDK via pkg-config (harness.md §H1, M0 checklist §5) --------
#
# The dev VM exposes DPDK 25.11 via a meson "uninstalled" pkg-config file
# (see user memory: "Dev VM DPDK layout"). That file is generated from the
# build tree and its Cflags list references a handful of include dirs that
# do not physically exist — e.g. .../build/kernel/linux — because the
# corresponding meson subproject was not built. CMake ≥ 3.19 validates
# every entry of INTERFACE_INCLUDE_DIRECTORIES on an imported target and
# fails configure if any path is missing. We strip the phantoms below.
find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)

function(_pktgate_strip_missing_include_dirs _tgt)
  get_target_property(_inc ${_tgt} INTERFACE_INCLUDE_DIRECTORIES)
  if(NOT _inc)
    return()
  endif()
  set(_kept "")
  set(_dropped "")
  foreach(_d IN LISTS _inc)
    if(IS_DIRECTORY "${_d}")
      list(APPEND _kept "${_d}")
    else()
      list(APPEND _dropped "${_d}")
    endif()
  endforeach()
  set_target_properties(${_tgt} PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${_kept}")
  if(_dropped)
    list(LENGTH _dropped _n)
    message(STATUS "pktgate: dropped ${_n} phantom include dir(s) from ${_tgt}")
  endif()
endfunction()

_pktgate_strip_missing_include_dirs(PkgConfig::DPDK)

# ---- nlohmann_json (M1 C1) ----------------------------------------------
#
# The config parser uses nlohmann::json — small, header-only, already
# packaged on the dev VM (json-devel) and available via pkg-config as
# `nlohmann_json`. Keep the dependency import minimal: one
# IMPORTED_TARGET that libpktgate_core links against PUBLIC so every
# translation unit that includes src/config/parser.cpp gets the headers.
pkg_check_modules(NLOHMANN_JSON REQUIRED IMPORTED_TARGET nlohmann_json)

# ---- libpktgate_core (M1) -----------------------------------------------
#
# Pure C++ static library that the product binary, every unit test, and
# the fuzz harnesses all link against. No DPDK includes — kept
# deliberately DPDK-free so unit tests run under the dev-* presets
# without EAL init. The runtime / dataplane modules (M3+) live in a
# separate library, added alongside this one when they land.
#
# Builds under BOTH dev-* and fuzz presets: fuzz targets (C12+) link
# against pktgate_core to call parse() / validate(). Under the fuzz
# preset, PKTGATE_SANITIZER=asan applies address+undefined sanitizer
# flags to the library — the libFuzzer-specific `-fsanitize=fuzzer`
# flag is only on fuzz executables (via Fuzz.cmake per-target).
#
# Source list grows one file per M1 cycle: C1 seeds parser.cpp; C6
# adds sizing.cpp; C7 adds validator.cpp; etc. Keep it explicit (no
# glob) so a missing file is a configure error, not a silent drop.
add_library(pktgate_core STATIC
  src/config/parser.cpp
  src/config/addr.cpp
  src/config/sizing.cpp
  src/config/validator.cpp
  src/compiler/compiler.cpp
  src/compiler/object_compiler.cpp
  src/compiler/rule_compiler.cpp
  src/compiler/mirror_strategy.cpp
  src/ruleset/ruleset.cpp
  src/ruleset/builder.cpp
)
target_include_directories(pktgate_core PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(pktgate_core PUBLIC PkgConfig::NLOHMANN_JSON)
pktgate_apply_warnings(pktgate_core)
pktgate_apply_sanitizer(pktgate_core)

# ---- libpktgate_rl (M9 C0) — rate-limit arena (DPDK-free math layer) -----
#
# The bucket-math TU is deliberately DPDK-free (see memory
# `grabli_m4c0_dpdk_free_core_library.md`): it takes `now_tsc` and
# `tsc_hz` as explicit parameters instead of calling `rte_rdtsc()` /
# `rte_get_tsc_hz()`. Unit tests run under the dev-* presets without
# EAL. C1 adds the arena class (still DPDK-free). C2 wires the hot
# path in a thin worker-side glue TU that links against DPDK.
#
# D1 is the load-bearing invariant: NO `std::atomic` / `_Atomic` in
# this library. U5.8 asserts this via symbol grep on the built
# archive, so a future regression wires a race back into the hot
# path and fails the test at link time, not at runtime.
add_library(pktgate_rl STATIC
  src/rl_arena/rl_arena.cpp
)
target_include_directories(pktgate_rl PUBLIC ${CMAKE_SOURCE_DIR})
pktgate_apply_warnings(pktgate_rl)
pktgate_apply_sanitizer(pktgate_rl)

# ---- libpktgate_dp (M3) — DPDK-dependent dataplane library ---------------
#
# Modules that require DPDK headers at compile time and rte_eal_init() at
# runtime. Separated from pktgate_core (DPDK-free) so that unit tests of
# the config/compiler layer continue to build and run without EAL.
if(NOT PKTGATE_FUZZ)
  add_library(pktgate_dp STATIC
    src/eal/port_init.cpp
    src/eal/dynfield.cpp
    src/dataplane/worker.cpp
    src/ctl/bootstrap.cpp
    src/ctl/cmd_socket.cpp
    src/ctl/reload.cpp
    src/ctl/telemetry_reload.cpp
    src/runtime/arena_gc.cpp
    src/ruleset/builder_eal.cpp
  )
  target_include_directories(pktgate_dp PUBLIC ${CMAKE_SOURCE_DIR})
  target_link_libraries(pktgate_dp PUBLIC PkgConfig::DPDK pktgate_core)
  pktgate_apply_warnings(pktgate_dp)
  pktgate_apply_sanitizer(pktgate_dp)
endif()

# ---- Product binary (M3: full boot — EAL init + worker skeleton) ---------
#
# Skipped under PKTGATE_FUZZ — the fuzz preset does not ship a product
# binary, and linking main() next to LLVMFuzzerTestOneInput would fail.
if(NOT PKTGATE_FUZZ)
  add_executable(pktgate_dpdk src/main.cpp)
  target_link_libraries(pktgate_dpdk PRIVATE pktgate_dp)
  pktgate_apply_warnings(pktgate_dpdk)
  pktgate_apply_sanitizer(pktgate_dpdk)
endif()

# ---- Tests ---------------------------------------------------------------
#
# Enable testing unconditionally; we need `ctest` to work under every
# preset. Individual tests gate themselves on capabilities via labels.
include(CTest)
enable_testing()
if(PKTGATE_FUZZ)
  # Fuzz preset — only the fuzz tree is wired. No dev-* smoke tests,
  # no placeholder label scaffolding; `ctest --preset fuzz -L smoke`
  # sees just the smoke.fuzz_smoke entry from fuzz/CMakeLists.txt.
  add_subdirectory(fuzz)
else()
  add_subdirectory(tests)
endif()
