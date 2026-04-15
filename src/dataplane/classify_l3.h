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
#include <rte_ip.h>
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
//   C4 adds kL3V6; C6 adds kL3V6FragExt.

enum class L3TruncBucket : std::size_t {
  kL3V4 = 0,
};
inline constexpr std::size_t kL3TruncBucketCount = 1;

// Convenience alias used by WorkerCtx and test code.
using L3TruncCtrs = std::array<std::uint64_t, kL3TruncBucketCount>;

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
// trunc_ctrs (optional, D31):
//   Pointer to a L3TruncCtrs array (std::array<uint64_t, 1> indexed by
//   L3TruncBucket::kL3V4). Pass nullptr to skip the bump (backward-
//   compatible default — the C0 baseline test calls without it).
//   Worker passes &ctx->pkt_truncated_l3. Follows the optional-counter
//   pattern established by classify_l2 (memory grabli
//   `classify_l2_optional_counter_pattern`).
//
// The function is `noexcept`: like classify_l2 it runs on the hot
// path and must not throw. All DPDK calls it makes (rte_fib_lookup_bulk
// / rte_fib6_lookup_bulk in C4 / rte_hash_lookup_data) are C APIs that
// return error codes, not exceptions.

inline ClassifyL3Verdict classify_l3(struct rte_mbuf* m,
                                     const ruleset::Ruleset& rs,
                                     L3TruncCtrs* trunc_ctrs = nullptr) noexcept {
  // D39: caller (worker.cpp) has already run classify_entry_ok which
  // enforces nb_segs == 1. See src/dataplane/classify_entry.h.

  const auto* dyn = eal::mbuf_dynfield(m);
  const std::uint8_t  l3_off = dyn->l3_offset;
  const std::uint16_t et     = dyn->parsed_ethertype;

  // --------------------------- IPv4 branch ---------------------------------
  // parsed_ethertype is in network byte order (classify_l2 writes raw
  // 16-bit as assembled from wire bytes). Compare via RTE_BE16.
  if (et == RTE_BE16(RTE_ETHER_TYPE_IPV4)) {
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

    // ---- dst-prefix primary FIB lookup (U6.18 / U6.18a) -----------------
    // If the FIB is unpopulated (C0 baseline / empty L3 ruleset), skip
    // the lookup and fall through to kNextL4 — this is the U6.11a path,
    // and it must remain green post-C1.
    if (rs.l3_v4_fib == nullptr) {
      return ClassifyL3Verdict::kNextL4;
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
      return ClassifyL3Verdict::kNextL4;
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
    // treated as a miss and falls through to L4 — same counter-free
    // semantics as the pre-C1b `nh == 0` arm.
    ruleset::L3CompoundEntry entry{};
    std::memcpy(&entry, &nh, sizeof(entry));
    if (entry.valid_tag != ruleset::L3_ENTRY_VALID_TAG) {
      // Miss (default_nh / unstamped slot). C2 will add the optional
      // src-prefix secondary probe on miss; for C1 / C1b a clean miss
      // means fall through, not drop. No counter bump on clean miss.
      return ClassifyL3Verdict::kNextL4;
    }
    return detail::l3_dispatch(rs, entry.action_idx);
  }

  // Non-IPv4 ethertype — IPv6 body lands in C4, unknown ethertypes
  // pass through. No header read, no counter bump.
  return ClassifyL3Verdict::kNextL4;
}

}  // namespace pktgate::dataplane
