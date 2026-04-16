// src/dataplane/classify_l3.h
//
// M5 C0  — classify_l3 skeleton: plumbing + pass-through pipeline hook.
// M5 C1  — IPv4 branch: dst-prefix FIB lookup + D31 l3_v4 truncation
//          guard + D14 IHL reject.
// M5 C1b — L3CompoundEntry `valid_tag` retrofit: unpack the FIB next-hop
//          slot and check the `0xA5` tag byte to disambiguate a real
//          hit at `action_idx = 0, filter_mask = 0` from the
//          `rte_fib_conf.default_nh = 0` miss sentinel. Closes memory
//          grabli `rte_fib_default_nh_aliases_action_idx_0`.
// M5 C3  — IPv4 fragment handling (D17 `fragment_policy`) + D40 v4
//          fragment counter family (`pkt_frag_dropped_total{v4}` and
//          `pkt_frag_skipped_total{v4}`). Reads `rs.fragment_policy`
//          (u8 encoded as `FragmentPolicy::kL3Only|kDrop|kAllow`),
//          detects `is_frag` / `is_nonfirst` from the IPv4
//          `fragment_offset_and_flags` word, dispatches on policy, and
//          writes the `SKIP_L4` dynfield flag on the non-first L3_ONLY
//          arm (consumed by §5.4 classify_l4 in M6). Mirrors the v6
//          fragment branch that C6 will add in the same shape.
// M5 C4  — IPv6 branch: dst-prefix primary FIB lookup via
//          rte_fib6_lookup_bulk(n=1), D31 l3_v6 truncation guard.
//          Mirrors the IPv4 branch from C1; no fragment handling yet
//          (C6 scope), no ext-header handling (C5 scope).
// M5 C5  — IPv6 ext-header detection (D20 first-protocol-only + D22
//          EXT_MASK_LT64 UB fix): if next_header is a recognized
//          extension header protocol (except fragment=44, which is C6),
//          set SKIP_L4 in dynfield and bump `l4_skipped_ipv6_extheader`.
//          L3 FIB lookup still runs. All kNextL4 return paths collapse
//          to kTerminalPass when SKIP_L4 is set (same pattern as IPv4
//          fragment L3_ONLY in C3).
//
// The classify_l3 stage consumes `dyn->l3_offset` and
// `dyn->parsed_ethertype` (both written by classify_l2 per D13) and
// dispatches on ethertype into the IPv4 or IPv6 branch. The full body
// is built incrementally across M5 cycles:
//
//   C0           — function signature, verdict enum, empty pass-through
//                  body that unconditionally returns kNextL4 so the
//                  worker can wire the L2 → L3 → L4 chain end-to-end
//                  before any real header parsing lands.
//   C1 (this)    — IPv4 branch: dst-prefix primary FIB lookup via
//                  rte_fib_lookup_bulk(n=1), D14 IHL reject, D31 l3_v4
//                  truncation guard, dispatch on match.
//   C2           — IPv4 src-prefix secondary + compound L3.
//   C3           — IPv4 fragment handling (D17 fragment_policy) + D40
//                  pkt_frag_{dropped,skipped}_total{v4} counters.
//   C4           — IPv6 branch: dst-prefix primary FIB lookup via
//                  rte_fib6_lookup_bulk(n=1), D31 l3_v6 truncation guard.
//   C5           — IPv6 first-protocol-only ext-header handling per D20
//                  (SKIP_L4 + l4_skipped_ipv6_extheader bump).
//   C6           — IPv6 Fragment ext (next_header=44) per D27 first-vs-
//                  non-first split, D31 l3_v6_frag_ext guard, D40 alias
//                  invariant (both D27 named counter and D40 family
//                  fire at the same site).
//
// Design anchors:
//   * §5.3 classify_l3 (design.md lines 1108-1360) — full target spec
//   * §5.1 dynfield layout (PktgateDynfield)
//   * D14  — IPv4 IHL reject (L4 offset formula itself is M6 territory)
//   * D17  — fragment_policy (drop / l3_only / allow), default l3_only
//   * D20  — IPv6 first-protocol-only ext-header scope
//   * D27  — IPv6 Fragment ext first-vs-non-first differentiation
//   * D30  — rte_fib_lookup_bulk(n=1) per-packet form is the default
//   * D31  — per-stage truncation sentinels (l3_v4 / l3_v6 / l3_v6_frag_ext)
//   * D39  — headers-in-first-seg invariant (enforced by the shared
//            classify_entry_ok gate in the worker; do NOT re-guard here)
//   * D40  — fragment counter family (v4/v6 × drop/skip)
//   * D41  — classify_l3 is a top-level pipeline stage reachable from
//            the worker kNextL3 arm; pipeline smoke invariant applies
//
// Layer hygiene: classify_l3 reads the dynfield written by classify_l2
// and does NOT reparse the L2 header. The worker's shared
// classify_entry_ok (src/dataplane/classify_entry.h) already enforces
// `nb_segs == 1` for the whole RX loop — no duplication here.

#pragma once

#include <array>
#include <cstdint>
#include <cstring>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_fib.h>
#include <rte_fib6.h>
#include <rte_ip.h>
#include <rte_ip6.h>
#include <rte_mbuf.h>

#include "src/action/action.h"
#include "src/compiler/compiler.h"
#include "src/eal/dynfield.h"
#include "src/ruleset/ruleset.h"
#include "src/ruleset/types.h"

namespace pktgate::dataplane {

// -------------------------------------------------------------------------
// L3TruncBucket — D31 per-stage truncation counter buckets for classify_l3.
//
// kL3V4        — IPv4 header truncated (pkt_len < l3_off + 20) OR IPv4
//                header with IHL < 5 (D14 reject). Both arms share the
//                same bucket per errata §M5 C1: the IHL reject is a
//                "the header we were told to read is malformed" event,
//                semantically identical to truncation from classify_l3's
//                perspective.
// kL3V6        — IPv6 header truncated (pkt_len < l3_off + 40). IPv6 has
//                a fixed 40-byte header; anything shorter cannot be parsed.
//                M5 C4 landing.
//   C6 adds kL3V6FragExt.

enum class L3TruncBucket : std::size_t {
  kL3V4 = 0,
  kL3V6 = 1,          // C4: IPv6 header truncated (pkt_len < l3_off + 40)
  kL3V6FragExt = 2,   // C6: IPv6 fragment ext truncated (pkt_len < l3_off + 48)
};
inline constexpr std::size_t kL3TruncBucketCount = 3;

// Convenience alias used by WorkerCtx and test code.
using L3TruncCtrs = std::array<std::uint64_t, kL3TruncBucketCount>;

// -------------------------------------------------------------------------
// FragmentPolicy — D17 / P9 numeric encoding for `Ruleset.fragment_policy`.
//
// The config-layer enum (`config::FragmentPolicy`, src/config/model.h) is
// declared in insertion order {kL3Only=0, kDrop=1, kAllow=2} so the
// underlying u8 values line up with the numeric constants used here.
// classify_l3 reads `rs.fragment_policy` as a u8 and switches on it
// directly — adding an intermediate enum cast would cost a branch-free
// compare but no semantic clarity.
//
// Default (u8 zero) is `kL3Only` per P9 user resolution, so an
// unconfigured Ruleset (e.g. a test fixture that skips the config→
// ruleset fragment_policy wiring) gets the standard behavior: L3 still
// runs, L4 is skipped on non-first fragments, counter bumps only on the
// D17 drop-arm and the non-first L3_ONLY arm.
enum FragmentPolicy : std::uint8_t {
  kFragL3Only = 0,  // default — L3 runs, L4 skipped on non-first
  kFragDrop   = 1,  // terminal drop on any fragment (first or non-first)
  kFragAllow  = 2,  // skip L3+L4 entirely, terminal pass
};

// -------------------------------------------------------------------------
// L3FragBucket — D40 per-stage fragment counter buckets for classify_l3.
//
// kL3FragDroppedV4 — `pkt_frag_dropped_total{v4}`: any IPv4 fragment seen
//                    under `FragmentPolicy::kFragDrop` (both first and
//                    non-first). Bumped once per dropped fragment.
// kL3FragSkippedV4 — `pkt_frag_skipped_total{v4}`: non-first IPv4 fragment
//                    seen under `FragmentPolicy::kFragL3Only`. Bumped at
//                    the same site where `dyn->flags |= kSkipL4` is set.
//                    First IPv4 fragment under L3_ONLY passes through
//                    without bumping this counter and without setting
//                    SKIP_L4 (the first fragment carries the L4 header,
//                    so L4 classification can proceed normally). Mirrors
//                    D27 IPv6 semantics that C6 adds.
//
// C6 will add `kL3FragDroppedV6` and `kL3FragSkippedV6` at the v6 site,
// bumping both this D40 symmetric counter and the D27 named
// `l4_skipped_ipv6_fragment_nonfirst` counter at the same site — the
// D40 alias invariant (U6.26c sentinel).

enum class L3FragBucket : std::size_t {
  kL3FragDroppedV4 = 0,
  kL3FragSkippedV4 = 1,
  kL3FragDroppedV6 = 2,  // C6: D40 any v6 fragment under FRAG_DROP
  kL3FragSkippedV6 = 3,  // C6: D40 non-first v6 fragment under L3_ONLY
};
inline constexpr std::size_t kL3FragBucketCount = 4;

// Convenience alias used by WorkerCtx and test code.
using L3FragCtrs = std::array<std::uint64_t, kL3FragBucketCount>;

// -------------------------------------------------------------------------
// ClassifyL3Verdict — result of classify_l3.
//
// Mirrors §5.3 `verdict_layer` values (design.md):
//   kNextL4       — L3 pass, continue to L4 classification.
//   kTerminalPass — final allow (e.g. fragment with FRAG_ALLOW policy,
//                   or non-first fragment under FRAG_L3_ONLY that has
//                   already run through L3 matching).
//   kTerminalDrop — final drop (truncation sentinel, IHL reject,
//                   fragment drop, or L3 rule with DROP action).
//
// Rule-driven terminal verdicts (match with ALLOW/DROP action) land
// in C1/C2 with additional variants as needed; C0 only ships the
// three §5.3 baseline values. The enum is fixed-width (std::uint8_t)
// to stay ABI-stable for the dynfield `verdict_layer` field.

enum class ClassifyL3Verdict : std::uint8_t {
  kNextL4       = 0,  // L3 pass — proceed to L4 pipeline
  kTerminalPass = 1,  // final allow at L3
  kTerminalDrop = 2,  // final drop at L3
};

// -------------------------------------------------------------------------
// Internal helpers (anonymous namespace in a header — inline-only hot path).

// -------------------------------------------------------------------------
// is_ext_proto — IPv6 extension header protocol detection (D20, D22).
//
// Returns true if `p` is a recognized IPv6 extension header protocol
// number, EXCLUDING Fragment (44) which gets its own branch in D27.
//
// Values < 64 are packed into a 64-bit bitmask for branch-free testing:
//   hop-by-hop=0, routing=43, ESP=50, AH=51, destination-options=60.
// Values >= 64 are explicit OR clauses to avoid UB from `1ull << N`
// where N >= 64: mobility=135, HIP=139, shim6=140, experimental=253/254.
//
// Extracted from the classify_l3 function body in M5 C10 REFACTOR so
// both IPv6 code sites (ext-header detection and chain-after-fragment)
// share a single definition, and the constant is available for unit tests.

inline constexpr std::uint64_t kExtMaskLt64 =
    (1ull << 0) | (1ull << 43) | (1ull << 50) | (1ull << 51) | (1ull << 60);

inline constexpr bool is_ext_proto(std::uint8_t p) noexcept {
  return (p < 64 && ((1ull << p) & kExtMaskLt64)) ||
         p == 135 || p == 139 || p == 140 || p == 253 || p == 254;
}

namespace detail {

// Dispatch a matched L3 compound entry on its action verb.
//
// Reads rs.l3_actions[idx].verb. ALLOW passes to L4 (kNextL4); DROP is
// terminal (kTerminalDrop). Mirror/RL/Tag/Redirect in L3 context are
// deferred to later cycles — for C1 we treat them as "pass to L4" so
// the hot path keeps progressing. No per-rule counter bump yet (L3
// counter wiring lands in C2 together with compound secondary; C1 is
// the minimal primary-hit body).
//
// Guard: if l3_actions is nullptr or idx out of range, default to drop
// — a build/populate bug on the side path must not leak packets.
inline ClassifyL3Verdict l3_dispatch(const ruleset::Ruleset& rs,
                                     std::uint16_t action_idx) noexcept {
  if (!rs.l3_actions || action_idx >= rs.n_l3_rules) {
    return ClassifyL3Verdict::kTerminalDrop;
  }
  const auto verb = static_cast<compiler::ActionVerb>(
      rs.l3_actions[action_idx].verb);
  switch (verb) {
    case compiler::ActionVerb::kAllow:
      return ClassifyL3Verdict::kNextL4;
    case compiler::ActionVerb::kDrop:
      return ClassifyL3Verdict::kTerminalDrop;
    case compiler::ActionVerb::kMirror:
    case compiler::ActionVerb::kRateLimit:
    case compiler::ActionVerb::kTag:
    case compiler::ActionVerb::kRedirect:
      // Not yet dispatched in L3; pass to L4 for the C1 primary path.
      return ClassifyL3Verdict::kNextL4;
  }
  return ClassifyL3Verdict::kNextL4;  // unreachable
}

}  // namespace detail

// -------------------------------------------------------------------------
// classify_l3 — top-level L3 classification entry point (§5.3).
//
// Preconditions (enforced by the caller via classify_entry_ok, M4 C9):
//   m->nb_segs == 1   — headers-in-first-seg invariant (D39)
//
// Dynfield contract (written by classify_l2, read here):
//   dyn->l3_offset        — byte offset from frame start to L3 header
//                           (14 untagged, 18 single VLAN / QinQ-outer)
//   dyn->parsed_ethertype — inner ethertype after VLAN strip (network
//                           byte order; compare with RTE_BE16(...))
//
// C1 body — IPv4 branch only:
//   0. Read dyn->l3_offset / parsed_ethertype. On non-IPv4 ethertypes
//      (including IPv6, ARP, unknown) fall through to kNextL4; IPv6
//      body lands in C4.
//   1. D31 l3_v4 truncation guard — if pkt_len < l3_off + 20, bump
//      trunc_ctrs[kL3V4] (if non-null) and return kTerminalDrop.
//   2. D14 IHL reject — if (version_ihl & 0x0F) < 5, bump the SAME
//      l3_v4 bucket (per errata §M5 C1) and return kTerminalDrop.
//      NOTE: L4-offset-via-IHL (the other half of D14) is M6.
//   3. dst-prefix primary FIB lookup — rte_fib_lookup_bulk(n=1) with
//      host-order dst IP. The miss-vs-hit discrimination runs on the
//      unpacked `L3CompoundEntry.valid_tag` byte (M5 C1b retrofit) —
//      a real match at `action_idx = 0, filter_mask = 0` would
//      otherwise be byte-identical to the builder_eal miss sentinel
//      (`rte_fib_conf.default_nh = 0`). On miss (valid_tag != 0xA5)
//      fall through to kNextL4 without bumping any D31 counter.
//   4. Hit (valid_tag matches) → resolve the rule's action via
//      rs.l3_actions[action_idx], and dispatch: allow → kNextL4,
//      drop → kTerminalDrop (per errata §M5 C1 unit.md wording
//      reconciliation for U6.18: the stale TERMINAL_L3 wording in
//      unit.md predates the C0 enum shape, and C0 shipped
//      {kNextL4, kTerminalPass, kTerminalDrop} without a TERMINAL_L3
//      slot).
//
//   Empty-ruleset / unpopulated-FIB short-circuit: if rs.l3_v4_fib is
//   nullptr, skip the FIB lookup entirely and fall through to kNextL4.
//   This is the M5 C0 U6.11a baseline path and must remain green here.
//   We still run the D31 + D14 guards first so memory safety and
//   malformed-header observability hold regardless of ruleset state
//   (symmetric to classify_l2's C7 fix — see memory grabli
//   `empty_ruleset_short_circuit_hides_parse`).
//
// C4 body — IPv6 branch:
//   0. If et == RTE_ETHER_TYPE_IPV6:
//   1. D31 l3_v6 truncation guard — if pkt_len < l3_off + 40, bump
//      trunc_ctrs[kL3V6] (if non-null) and return kTerminalDrop.
//   2. No ext-header handling yet (C5 scope).
//   3. No fragment handling yet (C6 scope).
//   4. dst-prefix primary FIB lookup — rte_fib6_lookup_bulk(n=1) with
//      the dst_addr in network byte order (no conversion needed). Same
//      valid_tag check as IPv4 (C1b retrofit).
//   5. Hit → l3_dispatch, miss → kNextL4 fall-through.
//
// trunc_ctrs (optional, D31):
//   Pointer to a L3TruncCtrs array (std::array<uint64_t, 2> indexed by
//   L3TruncBucket::kL3V4/kL3V6). Pass nullptr to skip the bump (backward-
//   compatible default — the C0 baseline test calls without it).
//   Worker passes &ctx->pkt_truncated_l3. Follows the optional-counter
//   pattern established by classify_l2 (memory grabli
//   `classify_l2_optional_counter_pattern`).
//
// frag_ctrs (optional, D40, M5 C3):
//   Pointer to a L3FragCtrs array (std::array<uint64_t, 2> indexed by
//   L3FragBucket::{kL3FragDroppedV4, kL3FragSkippedV4}). Pass nullptr
//   to skip the bump (backward-compatible default — older tests that
//   predate C3 call without it and observe no counter state). Worker
//   passes &ctx->pkt_frag_l3. Same optional-counter pattern as trunc
//   above — hot path stays pure when the caller does not care about
//   observability. C6 extends the enum with v6 slots and reuses the
//   same pointer.
//
// exthdr_ctr (optional, D20, M5 C5):
//   Pointer to a uint64_t counter for `l4_skipped_ipv6_extheader`.
//   Bumped when an IPv6 packet's next_header is a recognized extension
//   header protocol (excluding fragment=44, which is C6). Pass nullptr
//   to skip the bump (backward-compatible default — all pre-C5 tests
//   compile unchanged). Worker passes &ctx->l4_skipped_ipv6_extheader.
//
// The function is `noexcept`: like classify_l2 it runs on the hot
// path and must not throw. All DPDK calls it makes (rte_fib_lookup_bulk
// / rte_fib6_lookup_bulk in C4 / rte_hash_lookup_data) are C APIs that
// return error codes, not exceptions.

inline ClassifyL3Verdict classify_l3(struct rte_mbuf* m,
                                     const ruleset::Ruleset& rs,
                                     L3TruncCtrs* trunc_ctrs = nullptr,
                                     L3FragCtrs*  frag_ctrs  = nullptr,
                                     std::uint64_t* exthdr_ctr = nullptr,
                                     std::uint64_t* frag_nonfirst_ctr = nullptr) noexcept {
  // D39: caller (worker.cpp) has already run classify_entry_ok which
  // enforces nb_segs == 1. See src/dataplane/classify_entry.h.

  // Non-const: C3 fragment branch writes `dyn->flags |= kSkipL4` on the
  // non-first L3_ONLY arm. C5/C6 will additionally write `dyn->l4_extra`
  // and `dyn->parsed_l3_proto`.
  auto* dyn = eal::mbuf_dynfield(m);
  const std::uint8_t  l3_off = dyn->l3_offset;
  const std::uint16_t et     = dyn->parsed_ethertype;

  // --------------------------- IPv4 branch ---------------------------------
  // parsed_ethertype is stored in HOST byte order by classify_l2
  // (assembled as `(raw[12] << 8) | raw[13]`). Compare directly against
  // the host-order constant. M5 C10 fix: previous code used
  // RTE_BE16(RTE_ETHER_TYPE_IPV4) which byte-swaps on little-endian,
  // making the comparison always false. Unit tests that set
  // dyn->parsed_ethertype = RTE_BE16(...) must be updated to use 0x0800.
  if (et == RTE_ETHER_TYPE_IPV4) {
    // ---- D31 l3_v4 truncation guard (U6.12) -----------------------------
    // Must fire before any header byte read. pkt_len >= l3_off + 20 is
    // the minimum to have a well-formed IPv4 header (without options);
    // anything less cannot be parsed at all.
    const std::uint32_t need = static_cast<std::uint32_t>(l3_off) +
                               sizeof(struct rte_ipv4_hdr);
    if (rte_pktmbuf_pkt_len(m) < need) {
      if (trunc_ctrs) {
        ++(*trunc_ctrs)[static_cast<std::size_t>(L3TruncBucket::kL3V4)];
      }
      return ClassifyL3Verdict::kTerminalDrop;
    }

    // Now safe to read the IPv4 header at [l3_off .. l3_off + 20).
    const auto* raw = rte_pktmbuf_mtod(m, const std::uint8_t*);
    const auto* ip4 = reinterpret_cast<const struct rte_ipv4_hdr*>(
        raw + l3_off);

    // ---- D14 IHL reject (U6.13) -----------------------------------------
    // In MVP, M5's D14 contribution is reject-only: IHL < 5 cannot
    // describe a valid IPv4 header, drop at the same l3_v4 bucket per
    // errata §M5 C1. The L4-offset-via-IHL half of D14 lives in M6.
    const std::uint8_t ihl = ip4->version_ihl & 0x0F;
    if (ihl < 5) {
      if (trunc_ctrs) {
        ++(*trunc_ctrs)[static_cast<std::size_t>(L3TruncBucket::kL3V4)];
      }
      return ClassifyL3Verdict::kTerminalDrop;
    }

    // ---- D17 fragment handling (U6.21-U6.25, U6.26a, U6.26b) -----------
    // Detect fragment bits from the IPv4 `fragment_offset_and_flags`
    // 16-bit big-endian word at offset 6:
    //   bits 0-12: fragment offset (in units of 8 bytes)
    //   bit 13   : MF (more fragments)
    //   bit 14   : DF (reserved here)
    //   bit 15   : reserved / must-be-zero
    //
    // `is_frag` is true when EITHER MF is set (fragmented datagram, this
    // is a first-or-middle fragment that carries the L4 header) OR the
    // fragment offset is non-zero (non-first fragment, no L4 header in
    // this datagram). `is_nonfirst` is the pure offset!=0 subset.
    //
    // Design anchor: §5.3 IPv4 fragment paragraph (lines 1135-1161) +
    // review-notes D17 "Resolution (P9, 2026-04-10)".
    //
    // Note on `rte_ipv4_hdr` field naming: DPDK 25.11 exposes this as
    // `fragment_offset` (host-accessible big-endian u16). We read the
    // big-endian masks directly — no byteswap, no overall host conversion
    // — so the hot path costs at most one AND and one compare per bit.
    const std::uint16_t frag_word = ip4->fragment_offset;
    const bool is_frag =
        (frag_word & RTE_BE16(0x1FFFu)) != 0 ||      // offset != 0
        (frag_word & RTE_BE16(0x2000u)) != 0;        // MF set
    const bool is_nonfirst =
        (frag_word & RTE_BE16(0x1FFFu)) != 0;        // offset != 0

    if (is_frag) {
      const std::uint8_t policy = rs.fragment_policy;
      switch (policy) {
        case kFragDrop: {
          // D40: every dropped fragment (first or non-first) bumps the
          // v4 drop counter at this single site.
          if (frag_ctrs) {
            ++(*frag_ctrs)[static_cast<std::size_t>(L3FragBucket::kL3FragDroppedV4)];
          }
          return ClassifyL3Verdict::kTerminalDrop;
        }
        case kFragAllow: {
          // Skip L3+L4 entirely, let default_action apply at the end of
          // the pipeline (§5.3 "FRAG_ALLOW" arm). No counter bump — this
          // policy is explicitly unsafe and operator-visible via config
          // rather than per-packet observability.
          return ClassifyL3Verdict::kTerminalPass;
        }
        case kFragL3Only:
        default: {
          // Default policy (P9 user-chosen). Non-first fragment has no
          // reliable L4 header — mark the packet L4-unclassifiable via
          // the `SKIP_L4` dynfield flag and bump the D40 v4 skip
          // counter, then fall through to L3 matching so any pure-L3
          // rule (dst-prefix match) still applies. First fragment under
          // L3_ONLY passes through unchanged: L4 header is present in
          // the first-fragment payload, so classify_l4 can still run.
          if (is_nonfirst) {
            dyn->flags |= static_cast<std::uint8_t>(eal::kSkipL4);
            if (frag_ctrs) {
              ++(*frag_ctrs)[static_cast<std::size_t>(L3FragBucket::kL3FragSkippedV4)];
            }
          }
          break;  // fall through to L3 matching
        }
      }
    }

    // After the fragment branch, SKIP_L4 may have been set by the
    // non-first L3_ONLY arm. Snapshot the bit once so the FIB-miss and
    // rule-hit paths below can pick the right terminal verdict without
    // re-reading the dynfield:
    //
    //   SKIP_L4 unset — L4 runs next:
    //     miss       → kNextL4
    //     allow hit  → kNextL4 (L4 classifier still runs per §5.3)
    //     drop hit   → kTerminalDrop
    //
    //   SKIP_L4 set (non-first fragment under L3_ONLY):
    //     miss       → kTerminalPass   (U6.21: §5.3 TERMINAL_PASS cliff)
    //     allow hit  → kTerminalPass   (U6.22: L3 rule applies, L4 skipped)
    //     drop hit   → kTerminalDrop   (L3 drop wins regardless)
    //
    // See design.md §5.3 line 1201 "(dyn->flags & SKIP_L4) ? TERMINAL_PASS
    // : NEXT_L4" and review-notes D17 Resolution.
    const bool skip_l4 =
        (dyn->flags & static_cast<std::uint8_t>(eal::kSkipL4)) != 0;

    // ---- dst-prefix primary FIB lookup (U6.18 / U6.18a) -----------------
    // If the FIB is unpopulated (C0 baseline / empty L3 ruleset), skip
    // the lookup and fall through — this is the U6.11a path, and it
    // must remain green post-C1.
    if (rs.l3_v4_fib == nullptr) {
      return skip_l4 ? ClassifyL3Verdict::kTerminalPass
                     : ClassifyL3Verdict::kNextL4;
    }

    // rte_fib_lookup_bulk takes host-order IPv4 addresses per the DPDK
    // API (see doc.dpdk.org/api-25.11/rte__fib_8h.html). The wire
    // layout stores dst_addr big-endian; convert before the lookup.
    // Per D30, n=1 is the default per-packet form.
    std::uint32_t da = rte_be_to_cpu_32(ip4->dst_addr);
    std::uint64_t nh = 0;
    int lret = rte_fib_lookup_bulk(rs.l3_v4_fib, &da, &nh, 1);
    if (lret < 0) {
      // Lookup error: fall through. A clean lookup contract under n=1
      // is success-only from DPDK's perspective, so lret<0 indicates a
      // programming bug (e.g. null FIB handle slipping past the guard
      // above). We deliberately bump no counter here.
      return skip_l4 ? ClassifyL3Verdict::kTerminalPass
                     : ClassifyL3Verdict::kNextL4;
    }

    // Unpack the packed L3CompoundEntry from the 8-byte next-hop slot.
    // Layout is static_assert'd to 8 bytes in src/ruleset/types.h, so
    // memcpy round-trip is safe regardless of host alignment.
    //
    // M5 C1b: check `entry.valid_tag == L3_ENTRY_VALID_TAG (0xA5)` to
    // disambiguate a FIB miss (`rte_fib_conf.default_nh = 0` → nh == 0,
    // valid_tag byte reads as 0x00) from a valid hit at `action_idx = 0,
    // filter_mask = 0` (packed via `make_l3_entry` which stamps
    // valid_tag to 0xA5). Any tag value other than the sentinel is
    // treated as a miss and falls through — same counter-free semantics
    // as the pre-C1b `nh == 0` arm.
    ruleset::L3CompoundEntry entry{};
    std::memcpy(&entry, &nh, sizeof(entry));
    if (entry.valid_tag != ruleset::L3_ENTRY_VALID_TAG) {
      // Miss (default_nh / unstamped slot). C2 will add the optional
      // src-prefix secondary probe on miss; for C1 / C1b a clean miss
      // means fall through, not drop. No counter bump on clean miss.
      return skip_l4 ? ClassifyL3Verdict::kTerminalPass
                     : ClassifyL3Verdict::kNextL4;
    }
    const ClassifyL3Verdict v = detail::l3_dispatch(rs, entry.action_idx);
    // Under SKIP_L4 the `kNextL4` arm of l3_dispatch (allow action)
    // collapses to `kTerminalPass` because L4 classifier cannot run on
    // a non-first fragment. Drop stays terminal regardless.
    if (skip_l4 && v == ClassifyL3Verdict::kNextL4) {
      return ClassifyL3Verdict::kTerminalPass;
    }
    return v;
  }

  // --------------------------- IPv6 branch ---------------------------------
  // C4: dst-prefix primary FIB lookup via rte_fib6_lookup_bulk(n=1),
  // D31 l3_v6 truncation guard. C5 adds ext-header handling, C6 adds
  // fragment handling. This branch mirrors the IPv4 branch above.
  if (et == RTE_ETHER_TYPE_IPV6) {
    // ---- D31 l3_v6 truncation guard (U6.14) -----------------------------
    // IPv6 has a fixed 40-byte header. Must fire before any header byte
    // read. pkt_len >= l3_off + 40 is the minimum.
    const std::uint32_t need = static_cast<std::uint32_t>(l3_off) +
                               sizeof(struct rte_ipv6_hdr);
    if (rte_pktmbuf_pkt_len(m) < need) {
      if (trunc_ctrs) {
        ++(*trunc_ctrs)[static_cast<std::size_t>(L3TruncBucket::kL3V6)];
      }
      return ClassifyL3Verdict::kTerminalDrop;
    }

    // Now safe to read the IPv6 header at [l3_off .. l3_off + 40).
    const auto* raw = rte_pktmbuf_mtod(m, const std::uint8_t*);
    const auto* ip6 = reinterpret_cast<const struct rte_ipv6_hdr*>(
        raw + l3_off);

    const std::uint8_t nxt = ip6->proto;  // next_header field

    // ---- D20 first-protocol-only ext-header detection (U6.27) -----------
    // D22: kExtMaskLt64 + is_ext_proto live at namespace scope (REFACTOR
    // M5 C10). Fragment (44) excluded — D27 (C6).
    if (is_ext_proto(nxt)) {
      dyn->flags |= static_cast<std::uint8_t>(eal::kSkipL4);
      if (exthdr_ctr) ++(*exthdr_ctr);
    }

    // ---- D27 Fragment extension header (U6.15, U6.28-U6.30) ----------------
    // IPv6 Fragment ext header (proto 44) is excluded from is_ext_proto above
    // — it gets its own branch because the first-vs-non-first differentiation
    // (D27) requires reading the 8-byte frag ext header fields. Mirrors the
    // IPv4 C3 fragment pattern but with the IPv6 Fragment Extension Header
    // struct (`struct rte_ipv6_fragment_ext` in rte_ip6.h).
    if (nxt == 44) {
      // D31 l3_v6_frag_ext: need 8 more bytes for the fragment ext header
      // (8 = sizeof(rte_ipv6_fragment_ext)). Total: l3_off + 40 + 8 = 48
      // bytes from frame start.
      const std::uint32_t frag_need = static_cast<std::uint32_t>(l3_off) +
          sizeof(struct rte_ipv6_hdr) + 8u;
      if (rte_pktmbuf_pkt_len(m) < frag_need) {
        if (trunc_ctrs) {
          ++(*trunc_ctrs)[static_cast<std::size_t>(L3TruncBucket::kL3V6FragExt)];
        }
        return ClassifyL3Verdict::kTerminalDrop;
      }

      // Read fragment ext header at l3_off + 40.
      const auto* fh = reinterpret_cast<const struct rte_ipv6_fragment_ext*>(
          raw + l3_off + sizeof(struct rte_ipv6_hdr));
      // frag_data layout (after host conversion):
      //   bits [3..15] = 13-bit fragment offset (in units of 8 bytes)
      //   bits [1..2]  = reserved
      //   bit  [0]     = MF (more fragments)
      // frag_offset != 0 → non-first fragment.
      const std::uint16_t frag_data = rte_be_to_cpu_16(fh->frag_data);
      const bool is_first = (frag_data & RTE_IPV6_EHDR_FO_MASK) == 0;

      // D17 fragment_policy switch (mirrors IPv4 C3)
      const std::uint8_t policy = rs.fragment_policy;
      switch (policy) {
        case kFragDrop: {
          if (frag_ctrs) {
            ++(*frag_ctrs)[static_cast<std::size_t>(L3FragBucket::kL3FragDroppedV6)];
          }
          return ClassifyL3Verdict::kTerminalDrop;
        }
        case kFragAllow: {
          return ClassifyL3Verdict::kTerminalPass;
        }
        case kFragL3Only:
        default: {
          if (is_first) {
            // D27: first fragment — drill one step to reach L4 header.
            // l4_extra = 8 so M6 knows L4 starts at l3off + 40 + 8.
            dyn->l4_extra = 8;
            // Check if inner next_header is itself an ext-header (or
            // nested fragment=44). Chain-after-fragment → SKIP_L4 (D27).
            const std::uint8_t inner_nxt = fh->next_header;
            if (is_ext_proto(inner_nxt) || inner_nxt == 44) {
              dyn->flags |= static_cast<std::uint8_t>(eal::kSkipL4);
              if (exthdr_ctr) ++(*exthdr_ctr);
            }
          } else {
            // D27: non-first fragment — no L4 header, SKIP_L4.
            dyn->flags |= static_cast<std::uint8_t>(eal::kSkipL4);
            // D27 named counter + D40 alias invariant (U6.26c sentinel):
            // both bump at the same site.
            if (frag_nonfirst_ctr) ++(*frag_nonfirst_ctr);
            if (frag_ctrs) {
              ++(*frag_ctrs)[static_cast<std::size_t>(L3FragBucket::kL3FragSkippedV6)];
            }
          }
          break;  // fall through to FIB lookup
        }
      }
    }

    // Snapshot the SKIP_L4 bit once (same pattern as IPv4 branch).
    // If an ext-header was detected above, SKIP_L4 is set and all
    // kNextL4 return paths below collapse to kTerminalPass.
    const bool skip_l4 =
        (dyn->flags & static_cast<std::uint8_t>(eal::kSkipL4)) != 0;

    // ---- dst-prefix primary FIB lookup (U6.32 / U6.32a) -----------------
    // If the FIB is unpopulated (empty L3 ruleset), skip the lookup and
    // fall through — same baseline path as the IPv4 branch.
    if (rs.l3_v6_fib == nullptr) {
      return skip_l4 ? ClassifyL3Verdict::kTerminalPass
                     : ClassifyL3Verdict::kNextL4;
    }

    // rte_fib6_lookup_bulk takes `const struct rte_ipv6_addr*` in network
    // byte order — no byteswap needed, unlike IPv4 which converts to
    // host order. Per D30, n=1 is the default per-packet form.
    std::uint64_t nh = 0;
    int lret = rte_fib6_lookup_bulk(rs.l3_v6_fib, &ip6->dst_addr, &nh, 1);
    if (lret < 0) {
      return skip_l4 ? ClassifyL3Verdict::kTerminalPass
                     : ClassifyL3Verdict::kNextL4;
    }

    // Unpack the packed L3CompoundEntry from the 8-byte next-hop slot
    // (same as IPv4 — M5 C1b valid_tag check).
    ruleset::L3CompoundEntry entry{};
    std::memcpy(&entry, &nh, sizeof(entry));
    if (entry.valid_tag != ruleset::L3_ENTRY_VALID_TAG) {
      return skip_l4 ? ClassifyL3Verdict::kTerminalPass
                     : ClassifyL3Verdict::kNextL4;  // miss
    }
    const ClassifyL3Verdict v = detail::l3_dispatch(rs, entry.action_idx);
    // Under SKIP_L4 the `kNextL4` arm of l3_dispatch (allow action)
    // collapses to `kTerminalPass` because L4 classifier cannot run on
    // an ext-header packet. Drop stays terminal regardless.
    if (skip_l4 && v == ClassifyL3Verdict::kNextL4) {
      return ClassifyL3Verdict::kTerminalPass;
    }
    return v;
  }

  // Unknown ethertype — pass through. No header read, no counter bump.
  return ClassifyL3Verdict::kNextL4;
}

}  // namespace pktgate::dataplane
