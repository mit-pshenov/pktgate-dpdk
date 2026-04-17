// src/runtime/arena_gc.cpp
//
// M8 C5 — D11 arena GC hook (stub body).
//
// See arena_gc.h for the contract. This TU holds the test-hook
// override + the default no-op. M9 C5 replaces the default with real
// rl_arena slot lifecycle per D11 + D24.

#include "src/runtime/arena_gc.h"

#include <mutex>
#include <utility>

namespace pktgate::runtime {

namespace {

// Hook override + mutex. Small lock contention footprint: the hook is
// called once per successful reload, long after the hot path. Tests
// swap the function under the same lock so the override is visible
// the next time deploy() runs.
std::mutex  g_hook_mutex;
ArenaGcHook g_hook;

}  // namespace

void rl_arena_gc(ruleset::Ruleset* rs) noexcept {
  // Snapshot under lock so a concurrent test-swap does not race the
  // call. std::function copy is allocation-free for small lambdas.
  ArenaGcHook local;
  {
    std::lock_guard<std::mutex> lk(g_hook_mutex);
    local = g_hook;
  }
  if (local) {
    // Test hook present — invoke it. noexcept on the function is a
    // promise to the reload caller that we won't propagate exceptions,
    // so wrap the std::function call in a try/catch-all.
    try {
      local(rs);
    } catch (...) {
      // Swallow — tests must not throw out of the hook.
    }
    return;
  }

  // TODO(M9 C5): real rl_arena slot lifecycle (D11 + D24).
  // Hook point here ensures deferred frees happen AFTER synchronize,
  // which is the D11 ordering invariant. For M8 the body is empty —
  // the reload manager invokes us at the correct point, M9 will fill
  // the actual slot walk / counter-row zeroing / free-list push.
  (void)rs;
}

void set_arena_gc_hook_for_test(ArenaGcHook hook) {
  std::lock_guard<std::mutex> lk(g_hook_mutex);
  g_hook = std::move(hook);
}

}  // namespace pktgate::runtime
