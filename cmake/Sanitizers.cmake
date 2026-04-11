# cmake/Sanitizers.cmake — sanitizer wiring for pktgate-dpdk
#
# A single cache variable PKTGATE_SANITIZER selects the flavor. It is
# set by each CMakePresets.json entry (dev-asan, dev-ubsan, dev-tsan);
# the dev-debug / dev-release presets leave it empty.
#
# The function pktgate_apply_sanitizer(<target>) attaches the
# corresponding compile + link flags to <target>. It is called from
# CMakeLists for both the product binary and every test executable, so
# a single knob drives the whole build.
#
# Invariants worth noting:
#   * -fno-sanitize-recover=all on every flavor — any finding is fatal,
#     matching harness.md §H2.4/§H2.5/§H2.6 CI gate semantics.
#   * -fPIC is set globally (CMAKE_POSITION_INDEPENDENT_CODE), which
#     satisfies §H5.3 for tsan.
#   * PKTGATE_PRESET is baked in for every preset (including unsanitized
#     ones) so tests/smoke/test_presets.cpp can cross-check (M0 C2 RED).

set(PKTGATE_SANITIZER "" CACHE STRING
    "Sanitizer flavor: asan (addr+ub), ubsan (ub only), tsan, or empty")
set_property(CACHE PKTGATE_SANITIZER PROPERTY STRINGS "" asan ubsan tsan)

function(pktgate_apply_sanitizer tgt)
  if(PKTGATE_SANITIZER STREQUAL "")
    return()
  elseif(PKTGATE_SANITIZER STREQUAL "asan")
    # harness.md §H2.4 — combined address + undefined.
    target_compile_options(${tgt} PRIVATE
      -fsanitize=address,undefined
      -fno-sanitize-recover=all
      -fno-omit-frame-pointer)
    target_link_options(${tgt} PRIVATE -fsanitize=address,undefined)
  elseif(PKTGATE_SANITIZER STREQUAL "ubsan")
    # harness.md §H2.6 — pure ubsan. Drop vptr; we don't ship
    # polymorphism on the hot path (review-notes / H2.6).
    target_compile_options(${tgt} PRIVATE
      -fsanitize=undefined
      -fno-sanitize=vptr
      -fno-sanitize-recover=all
      -fno-omit-frame-pointer)
    target_link_options(${tgt} PRIVATE -fsanitize=undefined)
  elseif(PKTGATE_SANITIZER STREQUAL "tsan")
    # harness.md §H2.5 — thread sanitizer, PIE required.
    target_compile_options(${tgt} PRIVATE
      -fsanitize=thread
      -fno-sanitize-recover=all
      -fno-omit-frame-pointer)
    target_link_options(${tgt} PRIVATE -fsanitize=thread)
  else()
    message(FATAL_ERROR "pktgate: unknown PKTGATE_SANITIZER='${PKTGATE_SANITIZER}'")
  endif()
endfunction()
