# pktgate-dpdk — root CMakeLists
#
# M0 Cycle 1 GREEN: minimal skeleton that makes
# tests/smoke/test_build.cpp compile and pass under `dev-debug`.
#
# Scope grows per cycle, not per milestone:
#   C1: this file + tests/smoke, dev-debug preset only.
#   C2: five presets (dev-{release,debug,asan,ubsan,tsan}), sanitizer
#       and warning modules.
#   C3: pktgate_add_test helper + label taxonomy.
#   C4: D33 counter-consistency script + ctest target.
#   C5: Fuzz.cmake (libFuzzer, clang-only).
#   C6: git hooks + CI workflow stub.

cmake_minimum_required(VERSION 3.22)
project(pktgate_dpdk
  VERSION 0.0.0
  LANGUAGES CXX
)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(Warnings)
include(Sanitizers)
include(Gtest)

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

# ---- Product binary (empty in M0; main{return 0;}) ----------------------
add_executable(pktgate_dpdk src/main.cpp)
target_link_libraries(pktgate_dpdk PRIVATE PkgConfig::DPDK)
pktgate_apply_warnings(pktgate_dpdk)
pktgate_apply_sanitizer(pktgate_dpdk)

# ---- Tests ---------------------------------------------------------------
#
# Enable testing unconditionally; we need `ctest` to work under every
# preset. Individual tests gate themselves on capabilities via labels.
include(CTest)
enable_testing()
add_subdirectory(tests)
