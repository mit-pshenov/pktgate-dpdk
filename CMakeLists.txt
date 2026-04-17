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

# ---- libpktgate_rl_ctl (M9 C1) — control-plane arena (slot lifecycle) ----
#
# The `RateLimitArena` class lives in a SEPARATE TU and SEPARATE static
# library from the bucket-math TU above. Rationale: U5.8 / U5.9 grep
# `libpktgate_rl.a` for banned symbols (`std::atomic`, `unordered_map`,
# `id_to_slot`, hash iterator symbols). The arena uses unordered_map
# for `id_to_slot` — a control-plane-only lookup — so it must not land
# in pktgate_rl.a. Control-plane callers (compiler, builder, reload,
# telemetry) link BOTH libraries; the hot path links only pktgate_rl.
#
# Still DPDK-free: the arena owns RlRow storage but does no rte_* calls.
# Worker integration (C2) adds a thin DPDK-aware TU that bridges.
add_library(pktgate_rl_ctl STATIC
  src/rl_arena/arena.cpp
)
target_include_directories(pktgate_rl_ctl PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(pktgate_rl_ctl PUBLIC pktgate_rl)
pktgate_apply_warnings(pktgate_rl_ctl)
pktgate_apply_sanitizer(pktgate_rl_ctl)

# ---- libpktgate_telemetry (M10 C0) — DPDK-free control-plane telemetry ---
#
# Hosts the Prometheus OpenMetrics encoder (C0), snapshot ring (C1),
# snapshot publisher (C1), and HTTP /metrics endpoint (C3). Kept
# DPDK-free in C0 so unit tests (tests/unit/test_prom_encoder.cpp)
# run under dev-* presets without EAL. Introduce a thin DPDK-aware
# bridge TU in C1+ when `rte_eth_stats` wiring lands; link it into
# pktgate_dp then, not into this archive.
#
# Mirrors the pktgate_rl / pktgate_rl_ctl split: hot-path-adjacent
# code stays in small math-only archives; control-plane logic with
# heap + STL containers lives here.
add_subdirectory(src/telemetry)

# ---- libpktgate_inotify_ctl (M11 C0) — DPDK-free inotify control ---------
#
# Debounce timer + event-mask filter (C0) and watcher thread (C1) for
# D38 inotify-triggered reload. Control-plane, DPDK-free; consumed by
# the product binary (main.cpp) in C1+ when the watcher thread is
# wired alongside SnapshotPublisher. The library calls into the
# M8-frozen `ctl::reload::deploy()` through the single `reload_mutex`
# funnel (D35) — no new synchronisation surface added.
#
# C0 is pure unit surface: no thread, no kernel syscall, no DPDK.
add_subdirectory(src/ctl/inotify)

# ---- libpktgate_runtime (M9 C4) — DPDK-free runtime helpers --------------
#
# Home for TUs that participate in the reload/runtime lifecycle but do
# NOT require DPDK headers or EAL init. M9 C4 seeds this with arena_gc
# (the D11 rl_arena GC body) so unit tests can exercise the GC against
# the arena singleton without linking DPDK or running rte_eal_init.
#
# Layering: depends on pktgate_core (Ruleset definition) + pktgate_rl_ctl
# (RateLimitArena singleton). Consumed by pktgate_dp (call sites in
# src/ctl/reload.cpp invoke rl_arena_gc from inside the EAL-backed
# reload pipeline).
add_library(pktgate_runtime STATIC
  src/runtime/arena_gc.cpp
)
target_include_directories(pktgate_runtime PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(pktgate_runtime PUBLIC pktgate_core pktgate_rl_ctl)
pktgate_apply_warnings(pktgate_runtime)
pktgate_apply_sanitizer(pktgate_runtime)

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
    src/ruleset/builder_eal.cpp
  )
  target_include_directories(pktgate_dp PUBLIC ${CMAKE_SOURCE_DIR})
  # M9 C2: action_dispatch's kRateLimit verb arm references the
  # RateLimitArena and the rl_consume math function. pktgate_rl_ctl
  # (control-plane arena) transitively brings in pktgate_rl (math) via
  # its PUBLIC link. U5.8 / U5.9 invariants still hold: those tests
  # grep libpktgate_rl.a — NOT libpktgate_dp.a — so bringing
  # unordered_map symbols into pktgate_dp does not violate the
  # hot-path-zero-atomic invariant on the math archive.
  target_link_libraries(pktgate_dp PUBLIC
      PkgConfig::DPDK pktgate_core pktgate_rl_ctl pktgate_runtime)
  pktgate_apply_warnings(pktgate_dp)
  pktgate_apply_sanitizer(pktgate_dp)
endif()

# ---- Product binary (M3: full boot — EAL init + worker skeleton) ---------
#
# Skipped under PKTGATE_FUZZ — the fuzz preset does not ship a product
# binary, and linking main() next to LLVMFuzzerTestOneInput would fail.
if(NOT PKTGATE_FUZZ)
  add_executable(pktgate_dpdk src/main.cpp)
  # M10 C3: pktgate_telemetry carries snapshot_publisher + http_server,
  # which main.cpp wires into the boot sequence (Phase 6b). Must be
  # linked alongside pktgate_dp. pktgate_telemetry stays DPDK-free;
  # the DPDK-facing BuildFn/BodyFn lambdas live here in main.cpp.
  target_link_libraries(pktgate_dpdk PRIVATE pktgate_dp pktgate_telemetry
                                             pktgate_inotify_ctl)
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
