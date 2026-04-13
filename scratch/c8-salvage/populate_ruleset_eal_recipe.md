# `populate_ruleset_eal()` wiring recipe — `main.cpp` phase 6

## Context

M4 C0b (`c6d0c97`) added `populate_ruleset_eal()` in
`src/ruleset/builder_eal.{cpp,h}` with real `rte_hash_create` /
`rte_fib_create` / `rte_hash_add_key_with_hash` / `rte_fib_add`
calls. Unit tests passed under `eal_fixture.h` because the fixture
helper called `populate_ruleset_eal()` inline. But the function
was **never wired into `main.cpp`** — `build_ruleset()` created
the pure-C++ action arenas and the boot went straight to worker
launch, leaving `rte_hash`/`rte_fib` tables empty at runtime.

C8 is the retrofit cycle for this gap plus F2 functional tests.
Errata entry: `implementation-plan-errata.md §C0b silent gap`.
D41 amendment: `review-notes.md §D41 Amendment 2026-04-13`.

## Where it goes

`src/main.cpp` phase 6, **between** `build_ruleset()` and the
`ruleset_published` log line. Failure returns 1 with
`ruleset_eal_populate_failed` event.

## Code

```cpp
// ---- Phase 6: build and publish Ruleset ----
//
// M4 C8: num_lcores for counter indexing must be rte_lcore_count(), NOT
// n_workers. The counter array is indexed by lcore_id (0..rte_lcore_count()-1).
// Worker lcores start at ID 1 (main=0, worker=1 with -l 0,1), so if we
// pass n_workers=1 the Ruleset only allocates 1 row (index 0), and
// worker lcore 1 would be out of range. rte_lcore_count() returns the
// total number of configured lcores (main + workers) — sufficient to
// cover all possible lcore_id values.
const unsigned num_lcores_for_counters = rte_lcore_count();
auto ruleset = std::make_unique<pktgate::ruleset::Ruleset>(
    pktgate::ruleset::build_ruleset(compile_result, cfg.sizing,
                                    num_lcores_for_counters));

// ---- M4 C8: populate EAL compound tables (rte_hash / rte_fib) ----------
//
// build_ruleset() creates the pure-C++ action arenas. populate_ruleset_eal()
// opens the DPDK hash and FIB tables and populates them from the CompileResult
// compound vectors. This is the call that was missing from the boot path.
//
// EalPopulateParams: unique name_prefix per boot so repeated restarts don't
// hit the global rte_hash name-collision check. socket_id from NUMA (D23).
// max_entries from sizing (D6): use the per-layer rule cap.
{
  pktgate::ruleset::EalPopulateParams eal_params;
  eal_params.name_prefix = "pktgate_g" + std::to_string(ruleset->generation);
  eal_params.socket_id = static_cast<int>(socket_id);
  eal_params.max_entries = cfg.sizing.rules_per_layer_max;
  auto eal_res = pktgate::ruleset::populate_ruleset_eal(
      *ruleset, compile_result, eal_params);
  if (!eal_res.ok) {
    log_json("{\"error\":\"ruleset_eal_populate_failed\",\"reason\":\"" +
             eal_res.error + "\"}");
    rte_mempool_free(mp);
    rte_eal_cleanup();
    return 1;
  }
}

log_json(("{\"event\":\"ruleset_published\",\"generation\":" +
          std::to_string(ruleset->generation) +
          ",\"l2_rules\":" + std::to_string(ruleset->n_l2_rules) +
          ",\"l2_compound_count\":" + std::to_string(ruleset->l2_compound_count) +
          ",\"num_lcores\":" + std::to_string(ruleset->num_lcores) +
          "}").c_str());
```

Header include to add at the top of `main.cpp`:

```cpp
#include "src/ruleset/builder_eal.h"
```

## Second bug — `num_lcores` indexing

Independent of the orphan gap: the previous `build_ruleset(..., n_workers)`
call sized the per-lcore counter array to `n_workers` rows. Counter
rows are indexed by **raw lcore_id** from `rte_lcore_id()`. With
`-l 0,1` the main thread is lcore 0 and the worker is lcore 1. A
worker calling `rs.counter_row(1)` on a 1-row array reads out of
bounds.

Fix: size the array to `rte_lcore_count()` so every configured
lcore_id has a row. This is **not** in the C0b errata — that entry
covers only the orphaned `populate_ruleset_eal()` call. Add a
separate errata line or fold it into C8's RED→GREEN commentary.

## Test hook

The extended `ruleset_published` log line gives functional tests
a way to assert that non-trivial state made it through the boot
path: `l2_rules > 0`, `l2_compound_count > 0`, `num_lcores == rte_lcore_count()`.
If a fresh regression drops `populate_ruleset_eal()` again,
`l2_compound_count` goes back to 0 and any F2.* test that checks
for it in the boot log fails immediately — boot-path smoke per
D41 amendment.
