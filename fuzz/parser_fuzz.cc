// fuzz/parser_fuzz.cc
//
// M1 C12 — libFuzzer target for the config parser (corner.md C7.1).
//
// Contract:
//   LLVMFuzzerTestOneInput(data, size) feeds raw bytes as a JSON
//   document into pktgate::config::parse(). The parser MUST return
//   either a valid Config (ParseResult holds Config) or a structured
//   ParseError — never crash, never throw an uncaught exception,
//   never trigger ASan/UBSan findings.
//
// Build: linked with -fsanitize=fuzzer,address,undefined via Fuzz.cmake.
//        pktgate_core is linked as a static library (built with
//        -fsanitize=address,undefined via PKTGATE_SANITIZER=asan).
//
// Seed corpus: fuzz/seeds/parser/*.json — 9+ files covering valid,
//   invalid, edge-case, and adversarial JSON shapes. See corner.md
//   §"C7.1 initial corpus" for the rationale behind each seed.
//
// Exit gate: `parser_fuzz fuzz/seeds/parser/ -max_total_time=60`
//   runs clean (no crashes, no findings).
//
// References:
//   corner.md C7.1
//   D8 parser hardening
//   https://llvm.org/docs/LibFuzzer.html

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "src/config/parser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Feed arbitrary bytes into the parser. The parse() contract
  // guarantees no exceptions escape and the return is always a valid
  // variant (Config or ParseError). We deliberately do NOT inspect
  // the result — the fuzzer's job is to find crashes and sanitizer
  // findings, not to validate semantics.
  //
  // The volatile sink prevents the compiler from optimising away the
  // parse() call entirely (it could prove the result is unused and
  // DCE the whole thing, stripping coverage instrumentation).
  const auto result =
      pktgate::config::parse(std::string_view{reinterpret_cast<const char*>(data), size});
  volatile bool ok = pktgate::config::is_ok(result);
  (void)ok;
  return 0;
}
