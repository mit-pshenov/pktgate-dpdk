// fuzz/smoke_fuzz.cc
//
// M0 Cycle 5 — minimal libFuzzer bootstrap target.
//
// The whole purpose of this translation unit is to prove that the
// `fuzz` CMake preset can compile, link, and execute a libFuzzer
// binary on the dev VM. Anything beyond that — real input parsing,
// differential checking, seed corpora — lands with the component-
// specific fuzz targets listed in harness.md §H2.9:
//
//   fuzz_config_parser   (M1 — driven by corner.md C7.1)
//   fuzz_rule_compiler   (M2 — driven by corner.md C7.10–C7.26)
//   fuzz_l2_classify     (M4)
//   fuzz_l3_classify     (M5)
//   fuzz_l4_classify     (M6)
//
// This file is **not** a fuzz target in the normal sense — it just
// accepts any input and returns 0. The cycle exit gate runs it under
// `-runs=1`, so libFuzzer instantiates, executes the callback once
// on an empty buffer, and exits cleanly. If that fails, the fuzz
// toolchain itself is broken and we learn about it before the real
// fuzz targets land on top.
//
// The LLVM libFuzzer contract: the runtime calls back into
// `LLVMFuzzerTestOneInput` for each generated input. Returning 0
// signals "not interesting / keep fuzzing"; non-zero aborts the
// session. Crashes — asserts, sanitizer findings, segfaults — are
// reported by the runtime, not the target.
//
// References:
//   https://llvm.org/docs/LibFuzzer.html
//   harness.md §H2.9 (preset shape)
//   harness.md §H4.7 (ci-fuzz-shortrun, separate from this smoke)

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Touch the buffer so an optimizing compiler cannot prove the
  // parameters are dead and strip the whole function. That would be
  // legal but would also mean libFuzzer coverage instrumentation has
  // no live code to trace, which in turn makes `-runs=1` take zero
  // useful samples — a regression we wouldn't notice until real
  // targets land and exhibit the same shape.
  volatile std::uint8_t sink = 0;
  for (std::size_t i = 0; i < size; ++i) {
    sink ^= data[i];
  }
  (void)sink;
  return 0;
}
