// tests/smoke/test_presets.cpp
//
// M0 Cycle 2 — preset / sanitizer consistency check.
//
// Every preset bakes a `PKTGATE_PRESET="dev-<name>"` macro at compile
// time. This test cross-checks that macro against what the compiler
// actually thinks about the current translation unit — i.e. whether
// ASan, TSan, UBSan, NDEBUG, etc. are really on. The point is to catch
// "the preset claims to be dev-tsan but the sanitizer was never wired
// into CXX flags" — a silent misconfiguration that would otherwise only
// show up months later when D9/D35 regress under the assumption that
// `ci-tsan` was actually running tsan.
//
// RED for this cycle: tests/smoke/CMakeLists.txt does not yet set
// PKTGATE_PRESET, so the test fails to compile (missing macro).
// GREEN arrives when CMakePresets.json carries five presets and each
// one bakes a matching define via cmake/Sanitizers.cmake.

#include <gtest/gtest.h>
#include <string_view>

#ifndef PKTGATE_PRESET
#  error "PKTGATE_PRESET must be defined by the build system (M0 C2)"
#endif

// Stringification dance so PKTGATE_PRESET can come in as either a bare
// token or a quoted string from the build system.
#define PKTGATE_STR2(x) #x
#define PKTGATE_STR(x)  PKTGATE_STR2(x)

// ---- Sanitizer introspection --------------------------------------------
//
// __SANITIZE_ADDRESS__ is gcc-only. Clang uses __has_feature(...).
// __SANITIZE_THREAD__ likewise. UBSan has no gcc predefine at all, so
// we only detect it under clang.
#if defined(__has_feature)
#  if __has_feature(address_sanitizer)
#    define PKTGATE_HAVE_ASAN 1
#  endif
#  if __has_feature(thread_sanitizer)
#    define PKTGATE_HAVE_TSAN 1
#  endif
#  if __has_feature(undefined_behavior_sanitizer)
#    define PKTGATE_HAVE_UBSAN 1
#  endif
#endif
#if defined(__SANITIZE_ADDRESS__)
#  define PKTGATE_HAVE_ASAN 1
#endif
#if defined(__SANITIZE_THREAD__)
#  define PKTGATE_HAVE_TSAN 1
#endif

#ifndef PKTGATE_HAVE_ASAN
#  define PKTGATE_HAVE_ASAN 0
#endif
#ifndef PKTGATE_HAVE_TSAN
#  define PKTGATE_HAVE_TSAN 0
#endif
#ifndef PKTGATE_HAVE_UBSAN
#  define PKTGATE_HAVE_UBSAN 0
#endif

TEST(PresetSanity, MatchesSanitizerReality) {
  constexpr std::string_view preset = PKTGATE_STR(PKTGATE_PRESET);
  RecordProperty("preset", std::string(preset).c_str());
  RecordProperty("asan", PKTGATE_HAVE_ASAN);
  RecordProperty("tsan", PKTGATE_HAVE_TSAN);
  RecordProperty("ubsan", PKTGATE_HAVE_UBSAN);

  if (preset == "dev-release") {
    // Release must be NDEBUG and carry zero sanitizers.
#ifndef NDEBUG
    FAIL() << "dev-release must define NDEBUG";
#endif
    EXPECT_EQ(PKTGATE_HAVE_ASAN, 0) << "dev-release must not enable ASan";
    EXPECT_EQ(PKTGATE_HAVE_TSAN, 0) << "dev-release must not enable TSan";
    EXPECT_EQ(PKTGATE_HAVE_UBSAN, 0) << "dev-release must not enable UBSan";
#ifdef PKTGATE_TESTING
    FAIL() << "dev-release must not define PKTGATE_TESTING (Q9)";
#endif
  } else if (preset == "dev-debug") {
    // Debug is unsanitized and unoptimized. NDEBUG must be OFF.
#ifdef NDEBUG
    FAIL() << "dev-debug must not define NDEBUG";
#endif
    EXPECT_EQ(PKTGATE_HAVE_ASAN, 0);
    EXPECT_EQ(PKTGATE_HAVE_TSAN, 0);
    EXPECT_EQ(PKTGATE_HAVE_UBSAN, 0);
  } else if (preset == "dev-asan") {
    // harness.md §H2.4 — dev-asan combines address + undefined.
    EXPECT_EQ(PKTGATE_HAVE_ASAN, 1) << "dev-asan must enable ASan";
    EXPECT_EQ(PKTGATE_HAVE_UBSAN, 1) << "dev-asan must enable UBSan";
    EXPECT_EQ(PKTGATE_HAVE_TSAN, 0) << "dev-asan must not enable TSan";
  } else if (preset == "dev-ubsan") {
    // harness.md §H2.6 — pure UBSan flavor.
    EXPECT_EQ(PKTGATE_HAVE_UBSAN, 1) << "dev-ubsan must enable UBSan";
    EXPECT_EQ(PKTGATE_HAVE_ASAN, 0) << "dev-ubsan must not enable ASan";
    EXPECT_EQ(PKTGATE_HAVE_TSAN, 0) << "dev-ubsan must not enable TSan";
  } else if (preset == "dev-tsan") {
    // harness.md §H2.5 — thread sanitizer only.
    EXPECT_EQ(PKTGATE_HAVE_TSAN, 1) << "dev-tsan must enable TSan";
    EXPECT_EQ(PKTGATE_HAVE_ASAN, 0) << "dev-tsan must not enable ASan";
    EXPECT_EQ(PKTGATE_HAVE_UBSAN, 0) << "dev-tsan must not enable UBSan";
  } else {
    FAIL() << "unknown preset: " << preset;
  }
}
