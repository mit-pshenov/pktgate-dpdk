// tests/unit/test_builder.cpp
//
// M2 C2 — builder-scope struct sizing static_asserts.
// RED test: U4.8.
//
// Compile-time assertion that the builder's view of RuleAction matches
// the layout invariant. When the builder (C9) lands, further U4.* tests
// go here. For now, only the sizing guard.
//
// No DPDK. No EAL. Pure C++ unit tests.

#include <gtest/gtest.h>

#include <cstdint>

#include "src/action/action.h"

namespace {

// -------------------------------------------------------------------------
// U4.8 RuleAction 20 B / alignas(4) static_assert in builder
//
// Compile-time assertion that the builder's declaration of RuleAction
// still matches the layout invariant. If someone ever adds a field the
// build breaks. Covers D22.
// -------------------------------------------------------------------------
TEST(BuilderStructSizing, RuleActionLayout_U4_8) {
  static_assert(sizeof(pktgate::action::RuleAction) == 20,
                "RuleAction layout drift — expected 20 B (D22)");
  static_assert(alignof(pktgate::action::RuleAction) == 4,
                "RuleAction alignment drift — expected 4 (D22)");
  SUCCEED() << "RuleAction 20 B / alignas(4) — D22 builder invariant holds";
}

}  // namespace
