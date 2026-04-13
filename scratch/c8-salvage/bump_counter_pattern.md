# Per-rule counter bump pattern — `worker.cpp`

## Design note (not a formal D-decision — handoff note per consultant discussion 2026-04-13)

**Where the per-rule counter bump lives:** in `worker.cpp`,
**after** `classify_l2()` returns, reading `dyn->verdict_action_idx`
from the mbuf dynfield. `classify_l2` itself stays pure (its only
counter side effect remains the optional truncation / qinq
counters wired via `uint64_t*` pointers as in C5/C6/C7).

**Rationale:** the worker has access to both the `Ruleset*` and
the `lcore_id` needed to index `rs.counter_row(lcore_id)[slot]`.
Pushing the bump into `classify_l2` would require threading one
or both into its signature, which either widens the interface
(against the grain of classify_l2's purity) or requires a
helper struct the worker would construct per burst. Keeping the
bump in the caller is the cheaper layering.

## Sentinel protocol — `verdict_action_idx == 0xFFFF`

`classify_l2::dispatch_l2_match` already writes
`dyn->verdict_action_idx = idx` on match. On miss (verdict
`kNextL3` without a rule hit) it does **not** write anything. The
worker needs to distinguish "matched rule 0" from "no match".

The clean fix is to pre-initialize `dyn->verdict_action_idx` to a
sentinel before the `classify_l2` call. Value `0xFFFF`
(`kNoMatchSentinel`) is outside any valid action_idx range
(`rs.n_l2_rules` is bounded well below 65535 by sizing).

**Placement:** the pre-init runs inside the per-mbuf loop in
`worker_main`, between the D39 multi-seg check and the
`classify_l2()` call.

## Code

In `worker.cpp`, above `worker_main`:

```cpp
namespace {

constexpr std::uint16_t kNoMatchSentinel = 0xFFFFu;

// bump_l2_counter — M4 C8: post-classify_l2 counter increment.
//
// If classify_l2 matched a rule it writes the rule's action_idx into
// dyn->verdict_action_idx. We pre-initialize to kNoMatchSentinel before
// the call, so any value != kNoMatchSentinel means a rule was matched.
//
// Bumps:
//   - RuleCounter::matched_packets always on match.
//   - RuleCounter::drops on kDrop verdict (explicit DROP action).
//
// Runs on the worker lcore — zero atomics (D3). Aggregation by
// telemetry thread (M10).
inline void bump_l2_counter(const ruleset::Ruleset& rs,
                            std::uint16_t action_idx,
                            ClassifyL2Verdict verdict,
                            unsigned lcore_id) {
  if (action_idx >= rs.n_l2_rules || !rs.l2_actions || !rs.counters) return;

  const auto& act = rs.l2_actions[action_idx];
  const auto slot = static_cast<std::uint32_t>(act.counter_slot);

  ruleset::RuleCounter* row = rs.counter_row(lcore_id);
  if (!row || slot >= rs.counter_slots_per_lcore) return;

  ruleset::RuleCounter& ctr = row[slot];
  ++ctr.matched_packets;
  if (verdict == ClassifyL2Verdict::kDrop) {
    ++ctr.drops;
  }
}

}  // namespace
```

Inside `worker_main`, once at the top:

```cpp
// Get this worker's lcore id for counter indexing (§4.3 D3).
const unsigned lcore_id = rte_lcore_id();
```

Inside the per-mbuf loop, between the D39 multi-seg assert and
the `classify_l2()` call:

```cpp
// M4 C8: initialize verdict_action_idx to no-match sentinel so
// bump_l2_counter can reliably detect whether classify_l2 wrote
// a match result or returned a miss. A zero from zero-init mbuf
// memory would be ambiguous (rule-slot-0 is valid).
auto* dyn = eal::mbuf_dynfield(bufs[i]);
dyn->verdict_action_idx = kNoMatchSentinel;
```

After the `classify_l2()` call, before the `switch (l2v)`:

```cpp
// M4 C8: bump per-rule counter if classify_l2 matched a rule.
// A miss leaves verdict_action_idx == kNoMatchSentinel (set above).
{
  const std::uint16_t act_idx = dyn->verdict_action_idx;
  if (act_idx != kNoMatchSentinel) {
    bump_l2_counter(*ctx->ruleset, act_idx, l2v, lcore_id);
  }
}
```

Includes to add to `worker.cpp`:

```cpp
#include <rte_lcore.h>

#include "src/action/action.h"
#include "src/eal/dynfield.h"
#include "src/ruleset/ruleset.h"
```

## What is deliberately NOT here

- **No `std::atomic<u64> pkt_rx_total` in `WorkerCtx`.** The
  aborted worker added this as a "TSAN shutdown edge" — release
  in the RX loop, acquire in main after `rte_eal_mp_wait_lcore`.
  The rationale was that `std::memory_order_release` on x86-64
  compiles to the same `add [mem], imm` as a plain `+=`. That is
  factually wrong: `fetch_add` with any memory order on x86-64
  compiles to `lock xadd` (or `lock add` when return is
  discarded), a LOCK-prefixed RMW which is orders of magnitude
  more expensive than a non-atomic increment. This was a D1
  violation ("zero atomics on the hot path"), and the underlying
  TSAN race it tried to silence is parked until M8 RCU shutdown.
  The remaining per-worker counters
  (`qinq_outer_only_total`, `pkt_truncated_l2`,
  `pkt_multiseg_drop_total`) stay plain `uint64_t`.
- **No `fetch_add(0, release)` on shutdown.** Same reason.
- **No `pkt_rx_total.load(acquire)` in `main.cpp`.** Same reason.

## References

- `src/ruleset/ruleset.h` — `counter_row()`, `counter_slots_per_lcore`,
  `RuleCounter`.
- `src/action/action.h` — `RuleAction::counter_slot`,
  `RuleAction::rule_id`.
- `src/eal/dynfield.h` — `MbufDynfield::verdict_action_idx`.
- `src/dataplane/classify_l2.h` — `dispatch_l2_match` writes the
  dynfield on hit.
- `review-notes.md` D1 — zero atomics on the hot path.
- `review-notes.md` D3 — per-lcore counters, aggregated by
  telemetry thread.
- `review-notes.md` D33 — counter consistency invariant.
