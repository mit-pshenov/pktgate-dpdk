// tests/smoke/test_build.cpp
//
// M0 Cycle 1 — build-level sanity.
//
// Rules encoded (implementation-plan.md §2 M0, review-notes D2, Q9):
//   * C++20 baseline (D2).
//   * Toolchain floor: gcc ≥ 14 or clang ≥ 18 (D2).
//   * PKTGATE_TESTING must NOT be defined in release builds (Q9).
//
// Failure mode (RED for this cycle): there is no CMakeLists.txt yet,
// so this file cannot even be configured, let alone compiled. That is
// the intended RED state per implementation-plan.md §5 — "the first
// commit of M0 is the failing test that fails because CMakeLists.txt
// doesn't exist yet."
//
// GREEN for this cycle arrives when the minimal CMake skeleton lands
// and `ctest --preset dev-debug -L smoke` passes.

#include <gtest/gtest.h>

// ---- C++20 floor (D2) ----------------------------------------------------
static_assert(__cplusplus >= 202002L,
              "pktgate-dpdk requires C++20 or newer (D2)");

// ---- Compiler floor (D2) -------------------------------------------------
//
// Clang defines __GNUC__ too, so check __clang_major__ first.
#if defined(__clang__)
static_assert(__clang_major__ >= 18,
              "pktgate-dpdk requires clang >= 18 (D2)");
#elif defined(__GNUC__)
static_assert(__GNUC__ >= 14,
              "pktgate-dpdk requires gcc >= 14 (D2)");
#else
#error "unknown compiler — D2 requires gcc >= 14 or clang >= 18"
#endif

// ---- PKTGATE_TESTING guard (Q9) ------------------------------------------
//
// PKTGATE_TESTING gates test-only hooks (deterministic RNG, drop-forcing,
// mempool-shrink control). It is allowed in dev-debug / dev-asan / dev-ubsan
// / dev-tsan. It must NEVER be set in dev-release — that preset models the
// production build and must not carry test hooks.
//
// In M0 we only enforce the negative direction: release must not define it.
// The positive flavor (-DPKTGATE_TESTING=1) does not yet exist — it lights
// up in M8 (reload worker-sleep injection) and M10 (log flood test hook).
#if defined(NDEBUG) && defined(PKTGATE_TESTING)
#error "PKTGATE_TESTING must not be defined in release builds (Q9)"
#endif

// A runtime test so the smoke binary actually produces a ctest line,
// not just a translation-unit that passes static_asserts.
TEST(BuildSanity, CompilerMatchesPreset) {
  // If we got here, all static_asserts above held. Record the toolchain
  // in the gtest output so ctest logs show which compiler ran.
#if defined(__clang__)
  RecordProperty("compiler", "clang");
  RecordProperty("compiler_major", __clang_major__);
#else
  RecordProperty("compiler", "gcc");
  RecordProperty("compiler_major", __GNUC__);
#endif
  RecordProperty("cxx_standard", __cplusplus);

#if defined(NDEBUG)
  RecordProperty("ndebug", "1");
#else
  RecordProperty("ndebug", "0");
#endif

#if defined(PKTGATE_TESTING)
  RecordProperty("pktgate_testing", "1");
#else
  RecordProperty("pktgate_testing", "0");
#endif

  SUCCEED();
}
