// fuzz/compiler_fuzz.cc
//
// M2 C11 — libFuzzer target for the full compile pipeline (corner.md C7.3).
//
// Contract:
//   LLVMFuzzerTestOneInput(data, size) feeds raw bytes into the parser.
//   If parsing succeeds, validate() is called. If validation succeeds,
//   compile() is called. The compiler MUST return cleanly (CompileResult
//   with or without error) — never crash, never throw an uncaught
//   exception, never trigger ASan/UBSan findings.
//
//   The pipeline is: parse → validate → compile. Structure-aware: the
//   seed corpus provides valid JSON starting points that libFuzzer mutates
//   at the byte level, occasionally producing valid JSON that exercises
//   new compiler paths.
//
// Hostile inputs exercised by seed corpus:
//   - Overlapping L2 keys (collision detection)
//   - Port-group fan-out near D37 ceiling
//   - Max MAC groups
//   - Contradictory actions on overlapping flows (first-match-wins)
//   - Heavy FIB prefix overlap
//
// Build: linked with -fsanitize=fuzzer,address,undefined via Fuzz.cmake.
//        pktgate_core is linked as a static library.
//
// Seed corpus: fuzz/seeds/compiler/*.json — 5 files covering collision,
//   overlap, mixed layers, MAC group max, and FIB stress.
//
// Exit gate: `compiler_fuzz fuzz/seeds/compiler/ -max_total_time=60`
//   runs clean (no crashes, no findings).
//
// References:
//   corner.md C7.3
//   D8 compiler hardening
//   https://llvm.org/docs/LibFuzzer.html

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <variant>

#include "src/compiler/object_compiler.h"
#include "src/config/parser.h"
#include "src/config/validator.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Step 1: parse. If it fails, this input is not interesting for
  // compiler fuzzing — return immediately.
  auto parse_result =
      pktgate::config::parse(std::string_view{reinterpret_cast<const char*>(data), size});
  if (!pktgate::config::is_ok(parse_result)) {
    return 0;
  }

  // Step 2: validate. If it fails, skip compile — the compiler trusts
  // the validator's contract.
  auto& cfg = std::get<pktgate::config::Config>(parse_result);
  auto vr = pktgate::config::validate(cfg);
  if (!std::holds_alternative<pktgate::config::ValidateOk>(vr)) {
    return 0;
  }

  // Step 3: validate_budget. Use a generous hugepage probe so gate 3
  // doesn't always block the compiler from running.
  auto budget_result = pktgate::config::validate_budget(
      cfg, []() -> pktgate::config::HugepageInfo {
        return {/*.available_bytes=*/std::size_t{1} << 30};  // 1 GiB
      });
  if (!std::holds_alternative<pktgate::config::ValidateOk>(budget_result)) {
    return 0;
  }

  // Step 4: compile. Must return cleanly — CompileResult with or
  // without error. Crashes here are the bugs we're looking for.
  auto cr = pktgate::compiler::compile(cfg);

  // Volatile sinks prevent DCE from stripping the calls above.
  volatile bool has_error = cr.error.has_value();
  volatile auto n_l2 = cr.l2_actions.size();
  volatile auto n_l4 = cr.l4_actions.size();
  (void)has_error;
  (void)n_l2;
  (void)n_l4;
  return 0;
}
