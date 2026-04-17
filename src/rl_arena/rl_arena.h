// src/rl_arena/rl_arena.h
//
// M9 C0 — per-lcore token bucket data model + pure bucket-math layer.
//
// This file ships the *math* layer of the rate-limit arena. The C1
// arena class (`RateLimitArena` with `id_to_slot`, `slot_live`, and
// the row storage) lands in the next cycle. C0's scope is:
//
//   1. Data model: `TokenBucket` (64-byte cache-line isolated) and
//      `RlRow` (per-lcore bucket array).
//   2. Pure bucket-math free function `rl_consume` — lazy TSC refill,
//      D34 elapsed clamp, zero atomics, zero RMW.
//
// Design anchors:
//   * D1   — per-lcore bucket, ZERO atomics / CAS / fetch_add on the
//            hot path. Each lcore mutates only its own row slot.
//   * D10  — `rl_arena` lives OUTSIDE the Ruleset; row memory + slot
//            state survives reloads. C0 defines the types; C1 adds
//            the arena class; C2 wires the hot path.
//   * D24  — slot lifecycle (free slot, not row). Not exercised by
//            C0 math — row type only.
//   * D34  — refill `elapsed` clamp at one TSC second (`tsc_hz`).
//            Prevents 64-bit overflow on fresh buckets
//            (`last_refill_tsc == 0`) and long-idle lcores. Applied
//            BEFORE the multiply.
//
// DPDK-free by design (see `grabli_m4c0_dpdk_free_core_library.md`).
// The math signature takes `now_tsc` and `tsc_hz` as explicit
// parameters — the worker layer supplies them from `rte_rdtsc()` /
// `rte_get_tsc_hz()`. Tests inject deterministic values (U5.10).
//
// The per-lcore array is sized by `kMaxLcores`, a pktgate-local
// compile-time constant that equals DPDK's `RTE_MAX_LCORE` default
// (128) — kept here so the bucket-math TU does not need to include
// `<rte_lcore.h>`. A static_assert in `rl_arena.cpp` pins the
// identity once we link against DPDK.
//
// Test coverage: tests/unit/test_rl_arena.cpp U5.1 .. U5.10.

#pragma once

#include <cstddef>
#include <cstdint>

namespace pktgate::rl_arena {

// RTE_MAX_LCORE default in DPDK 25.11 build config is 128. This
// constant mirrors that value without dragging DPDK into the core
// math TU. An `eal`-facing wrapper will pin `kMaxLcores ==
// RTE_MAX_LCORE` via static_assert when it lands.
inline constexpr std::size_t kMaxLcores = 128;

// Per-lcore bucket state. One cache line per bucket — the explicit
// `_pad` array guarantees `sizeof(TokenBucket) == 64` under every
// supported compiler without relying on trailing padding rules.
// Only the owning lcore writes to its bucket, so the cache line is
// never shared by multiple writers — D1 zero-atomics invariant.
struct alignas(64) TokenBucket {
  std::uint64_t tokens;           // current tokens in bytes
  std::uint64_t last_refill_tsc;  // TSC of last refill; 0 == fresh
  std::uint64_t dropped;          // per-lcore drop counter
  std::uint64_t _pad[5];          // pad to exactly 64 B (D1)
};

static_assert(sizeof(TokenBucket) == 64,
              "TokenBucket must be exactly one 64-byte cache line (D1)");
static_assert(alignof(TokenBucket) == 64,
              "TokenBucket must be cache-line aligned (D1)");

// One row = per-lcore bucket array for a single rate-limit rule
// slot. The C1 arena will own an array of these indexed by slot.
struct RlRow {
  TokenBucket per_lcore[kMaxLcores];
};

static_assert(sizeof(RlRow) == 64 * kMaxLcores,
              "RlRow sizing drift — buckets must be contiguous 64-B rows");

// Consume `pkt_len` bytes from `b` after a lazy refill.
//
// Inputs:
//   * `b`           — this lcore's bucket row slot. Mutated in place.
//   * `now_tsc`     — caller's TSC sample (worker: `rte_rdtsc()`).
//   * `tsc_hz`      — caller's TSC frequency (worker:
//                     `rte_get_tsc_hz()`). Must be > 0.
//   * `pkt_len`     — packet length in bytes (L2 frame or whatever
//                     the caller chose to account; the math is
//                     indifferent).
//   * `rate`        — configured rule rate in bytes/second.
//   * `burst`       — bucket cap in bytes (e.g. rate * 10 ms).
//   * `n_lcores`    — Variant A per-lcore share divisor. Must be > 0.
//
// Returns:
//   * true  — `pkt_len` consumed from the bucket (PASS).
//   * false — insufficient tokens after refill; `b.dropped` bumped
//             by one, `b.tokens` left at its post-refill value (DROP).
//
// D34 clamp: `elapsed = min(now_tsc - last_refill_tsc, tsc_hz)`,
// applied BEFORE the multiply by `rate`. Handles fresh bucket
// (`last_refill_tsc == 0`) and long-idle lcores in one branch.
//
// Purity: reads and writes only `b`. No atomics. No shared state.
// Worker passes a pointer into its own lcore's slot, so cross-lcore
// access cannot happen by construction (D1 isolation).
bool rl_consume(TokenBucket& b, std::uint64_t now_tsc, std::uint64_t tsc_hz,
                std::uint32_t pkt_len, std::uint64_t rate,
                std::uint64_t burst, std::uint32_t n_lcores) noexcept;

}  // namespace pktgate::rl_arena
