// src/rl_arena/rl_arena.cpp
//
// M9 C0 — bucket-math implementation. See rl_arena.h for contract.

#include "src/rl_arena/rl_arena.h"

#include <algorithm>
#include <cstdint>

namespace pktgate::rl_arena {

bool rl_consume(TokenBucket& b, std::uint64_t now_tsc, std::uint64_t tsc_hz,
                std::uint32_t pkt_len, std::uint64_t rate,
                std::uint64_t burst, std::uint32_t n_lcores) noexcept {
  // D34: clamp `elapsed` to one TSC second BEFORE the multiply.
  //
  // Raw delta covers three cases collapsed into one:
  //   * Fresh bucket: `last_refill_tsc == 0`, so `raw = now_tsc`.
  //     For any non-trivial `now_tsc` (worker uses `rte_rdtsc()`
  //     which is the CPU's running TSC since boot — quickly > 1e9),
  //     `raw > tsc_hz` and the clamp snaps it to `tsc_hz`. No
  //     overflow in the subsequent multiply because the max value
  //     used is `tsc_hz * rate`, both ~1e10, product ~1e20 fits in
  //     uint64_t.
  //   * Long idle: same path. `raw = (now - last) > tsc_hz` → clamp.
  //   * Steady state: `raw < tsc_hz` → no clamp, normal arithmetic.
  //
  // Unsigned subtraction wraps cleanly on a monotonic TSC. A caller
  // that feeds a non-monotonic `now_tsc` (time travel) gets a very
  // large wrapped value → clamped → bucket picks up one TSC second
  // of refill, which is harmless because `burst` is the hard cap.
  const std::uint64_t raw = now_tsc - b.last_refill_tsc;
  const std::uint64_t elapsed = std::min<std::uint64_t>(raw, tsc_hz);

  // Variant A: each active lcore gets `rate / n_active_lcores` of
  // the rule's aggregate rate. Caller guarantees `n_lcores > 0` and
  // `tsc_hz > 0` — neither can be zero in a running system. No
  // defensive branch here on the hot path.
  const std::uint64_t refill_bytes = elapsed * rate / tsc_hz / n_lcores;

  b.tokens = std::min<std::uint64_t>(b.tokens + refill_bytes, burst);
  b.last_refill_tsc = now_tsc;

  if (b.tokens < pkt_len) {
    b.dropped += 1;
    return false;
  }
  b.tokens -= pkt_len;
  return true;
}

}  // namespace pktgate::rl_arena
