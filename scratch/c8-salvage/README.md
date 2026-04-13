# M4 C8 salvage — reference material from aborted 2026-04-13 attempt

**Status:** temporary. Delete this directory in the cleanup commit
once M4 C8 lands green.

## Why this exists

An earlier C8 worker got into a diagnostic cascade while chasing F2.3
cross-test contamination, escalated into the pre-existing TSAN
baseline race (parked until M8 per `m4-supervisor-handoff.md`
§Pre-existing TSAN race), and landed a scope-creep pile in the dirty
tree before being killed. Full rollback was preferred over hunk-level
curation (see consultant discussion 2026-04-13).

But **three pieces of hard-won knowledge** from that attempt are
worth keeping so the fresh C8 worker does not rediscover them from
scratch:

1. F2.3 root cause and its fix — NetworkManager DHCP on `dtap_*`.
2. `populate_ruleset_eal()` wiring recipe in `main.cpp` — the
   missing boot-path call that originally motivated C8 as retrofit,
   plus an adjacent `num_lcores` indexing bug.
3. `bump_l2_counter` pattern — where per-rule counter bump lives
   and the `verdict_action_idx` sentinel protocol.

Plus the entire `test_f2_l2.py` as a draft reference. **Do not
blindly copy-paste it** — it was written in panic mode and may
carry diagnostic residue (long sleeps, defensive asserts). But it
has workable scapy frame construction, net_tap topology, and
pytest structure that a fresh worker can crib from with judgement.

## Contents

| File | Purpose |
|---|---|
| `README.md` | This file. |
| `nm_unmanaged_tap.md` | F2.3 root cause + NM keyfile fixture. |
| `populate_ruleset_eal_recipe.md` | main.cpp phase 6 wiring + `num_lcores` fix. |
| `stats_on_exit_schema.md` | JSON shape emitted by main.cpp phase 9; what F2 tests assert. |
| `bump_counter_pattern.md` | worker.cpp per-rule counter bump + sentinel protocol. |
| `test_f2_l2.py.ref` | Original 784-line draft (panic-mode, use with discretion). |

## What is NOT here (and why)

- No atomics, no TSAN shutdown edges, no `pkt_rx_total` field.
  The aborted attempt added a `std::atomic<u64>` to `WorkerCtx` and
  a `fetch_add(nb_rx, release)` in the RX burst loop purely to
  silence the parked M8 TSAN baseline. That is a direct D1
  violation (`lock xadd` on x86-64 is not free, not matter what
  ordering). Do not revive it. The correct M8 fix is RCU shutdown
  sequencing.
- No `race:tap_dev_close` suppression in `tests/tsan.supp`. The
  underlying DPDK net_tap PMD race may be a real issue but it is
  not in C8 scope. If it needs to land, it does so in its own
  commit with its own errata entry.
- No `review-notes.md §D41 Suggested follow-ups (i)(ii)(iii)`.
  The worker drafted three architecture suggestions (CMake
  `d41-smoke` label, `pktgate::boot::bootstrap()` extraction,
  handoff exit-gate row) and wrote them into review-notes without
  user sign-off. Push-back rule #6. They are candidates for future
  discussion, not in-force decisions.
