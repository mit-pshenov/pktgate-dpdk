// tests/smoke/test_fuzz_sanity.cpp
//
// M0 Cycle 5 — structural sentinel for the fuzz preset scaffolding.
//
// The libFuzzer harness (harness.md §H2.9, implementation-plan.md §2
// M0 C5 checklist) ships its own CMake preset `fuzz`, its own
// `cmake/Fuzz.cmake` wiring module, and a minimal `fuzz/smoke_fuzz.cc`
// target that proves the toolchain can build a libFuzzer binary and
// run it under -runs=1. None of that is wired under the five dev-*
// presets (-fsanitize=fuzzer would turn every gtest binary into a
// link failure, because libFuzzer requires LLVMFuzzerTestOneInput
// rather than main()).
//
// This test does NOT exercise the fuzz preset itself. The functional
// proof is a separate `ctest --preset fuzz -L smoke` invocation in
// the cycle exit gate — this file's job is to catch bit-rot on the
// plumbing that dev-* presets can still see: the CMake module, the
// fuzz/ source dir, and the preset entry in CMakePresets.json. If
// any of that drifts away, this test fails under the five dev-*
// smoke runs — i.e. on every commit — before anyone notices the
// fuzz preset stopped working.
//
// RED for C5: none of cmake/Fuzz.cmake, fuzz/, or the "fuzz" preset
// entry exist yet, so the four file-existence checks fail and the
// preset-name check grep-misses. GREEN arrives when the plumbing is
// in place.

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#ifndef PKTGATE_SOURCE_DIR
#  error "PKTGATE_SOURCE_DIR must be defined by the build system (M0 C5)"
#endif

namespace fs = std::filesystem;

namespace {

fs::path source_root() {
  return fs::path(PKTGATE_SOURCE_DIR);
}

std::string slurp(const fs::path& p) {
  std::ifstream in(p);
  if (!in) {
    return {};
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

}  // namespace

TEST(FuzzSanity, FuzzCMakeModuleExists) {
  // cmake/Fuzz.cmake exposes pktgate_add_fuzz_test() — the mirror of
  // pktgate_add_test() for libFuzzer targets. Like Gtest.cmake it is
  // include()-d from the root CMakeLists only when PKTGATE_FUZZ=ON so
  // dev-* presets ignore it entirely.
  const auto p = source_root() / "cmake" / "Fuzz.cmake";
  EXPECT_TRUE(fs::exists(p)) << "missing: " << p;
}

TEST(FuzzSanity, FuzzSubtreeExists) {
  // The fuzz subtree holds the minimal smoke target and (later in
  // M1+) the per-component fuzz targets listed in harness.md §H2.9
  // (fuzz_config_parser, fuzz_rule_compiler, etc.). Checking just
  // the CMakeLists + the smoke source is enough to assert the
  // subtree is wired; individual fuzz targets land with their
  // corresponding milestones.
  const auto cml   = source_root() / "fuzz" / "CMakeLists.txt";
  const auto smoke = source_root() / "fuzz" / "smoke_fuzz.cc";
  EXPECT_TRUE(fs::exists(cml))   << "missing: " << cml;
  EXPECT_TRUE(fs::exists(smoke)) << "missing: " << smoke;

  // The smoke source must actually define LLVMFuzzerTestOneInput —
  // otherwise libFuzzer's link step fails with a confusing missing-
  // symbol error. Catch the shape mismatch up front under dev-*
  // smoke instead of waiting for the fuzz preset CI job.
  const std::string body = slurp(smoke);
  EXPECT_NE(body.find("LLVMFuzzerTestOneInput"), std::string::npos)
      << "fuzz/smoke_fuzz.cc must define LLVMFuzzerTestOneInput "
         "(libFuzzer entry point)";
}

TEST(FuzzSanity, FuzzPresetRegistered) {
  // CMakePresets.json must carry a "fuzz" configure preset. We don't
  // try to parse JSON here — a contains-check is enough for the
  // sentinel and avoids pulling nlohmann::json into the smoke tree
  // just for one grep. Full schema checking happens when someone
  // actually does `cmake --preset fuzz`, which is the cycle exit
  // gate's job.
  const auto presets = source_root() / "CMakePresets.json";
  ASSERT_TRUE(fs::exists(presets)) << "missing: " << presets;

  const std::string body = slurp(presets);
  EXPECT_NE(body.find("\"name\": \"fuzz\""), std::string::npos)
      << "CMakePresets.json must declare a configure preset named "
         "\"fuzz\" (harness.md §H2.9)";
}
