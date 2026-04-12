// fuzz/validator_fuzz.cc
//
// M1 C13 -- libFuzzer target for the config validator (corner.md C7.2).
//
// Contract:
//   LLVMFuzzerTestOneInput(data, size) feeds raw bytes into the parser.
//   If parsing succeeds, validate() and validate_budget() are called on
//   the resulting Config. Both MUST return cleanly (ValidateOk or
//   ValidateError) -- never crash, never throw an uncaught exception,
//   never trigger ASan/UBSan findings.
//
//   If parsing fails, we return 0 immediately -- the input is not
//   interesting for validator fuzzing. The seed corpus provides valid
//   JSON starting points that libFuzzer will mutate at the byte level,
//   occasionally producing valid JSON that exercises new validator paths.
//
// Build: linked with -fsanitize=fuzzer,address,undefined via Fuzz.cmake.
//        pktgate_core is linked as a static library.
//
// Seed corpus: fuzz/seeds/validator/*.json -- 8 files covering
//   port-range abuse, max rules, vlan OOB, vrf OOB, forward refs,
//   cycle groups, version skew, and hostile expansion. See corner.md
//   C7.2 for the rationale behind each seed.
//
// Exit gate: `validator_fuzz fuzz/seeds/validator/ -max_total_time=60`
//   runs clean (no crashes, no findings).
//
// References:
//   corner.md C7.2
//   D8 (clean schema), D37 (budget pre-flight)
//   https://llvm.org/docs/LibFuzzer.html

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <variant>

#include "src/config/parser.h"
#include "src/config/validator.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Step 1: parse. If it fails, this input is not interesting for
  // validator fuzzing -- return immediately.
  auto parse_result =
      pktgate::config::parse(std::string_view{reinterpret_cast<const char*>(data), size});
  if (!pktgate::config::is_ok(parse_result)) {
    return 0;
  }

  // Step 2: validate. Must return ValidateOk or ValidateError, never crash.
  auto& cfg = std::get<pktgate::config::Config>(parse_result);
  auto vr = pktgate::config::validate(cfg);
  volatile bool v_ok = std::holds_alternative<pktgate::config::ValidateOk>(vr);

  // Step 3: validate_budget. Use a generous hugepage probe so gate 3
  // exercises the estimation arithmetic without always tripping on
  // "not enough hugepages". The probe returns 1 GiB -- enough for any
  // sane config but small enough that a truly hostile input might still
  // trigger gate 3.
  auto budget_result = pktgate::config::validate_budget(
      cfg, []() -> pktgate::config::HugepageInfo {
        return {/*.available_bytes=*/std::size_t{1} << 30};  // 1 GiB
      });
  volatile bool b_ok =
      std::holds_alternative<pktgate::config::ValidateOk>(budget_result);

  // Volatile sinks prevent DCE from stripping the calls above.
  (void)v_ok;
  (void)b_ok;
  return 0;
}
