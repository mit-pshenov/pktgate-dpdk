// src/compiler/mirror_strategy.h
//
// M2 C7 — Mirror strategy selection (D26) + compile-time reject (D7).
//
// D7: Mirror action is architecturally defined but MVP-rejected at
// compile time. The compiler refuses to produce a Ruleset containing
// mirror rules — it returns a CompileError with kMirrorNotImplemented.
//
// D26: The mirror strategy selection logic exists even in MVP so that:
//   (a) the code path is tested,
//   (b) when mirror ships (Phase 2), the gate is already in place.
//
// Strategy selection is a whole-ruleset property, evaluated once per
// build, no per-packet branching. The three gates:
//   1. config_requests_zero_copy — operator opt-in
//   2. no mutating verbs in ruleset — MUTATING_VERBS = { TAG }
//   3. driver capability tx_non_mutating — NIC driver can do it
// All three must be true for REFCNT_ZERO_COPY; else DEEP_COPY.
//
// Design anchors:
//   * D7  — mirror compile-time reject in MVP
//   * D26 — mirror refcnt-zero-copy compile-time gate
//   * D25 — -Wswitch-enum coverage of ActionVerb

#pragma once

#include <cstdint>
#include <vector>

#include "src/compiler/compiler.h"  // ActionVerb

namespace pktgate::compiler {

// -------------------------------------------------------------------------
// MirrorStrategy — which mirror implementation the ruleset will use.

enum class MirrorStrategy : std::uint8_t {
  kDeepCopy = 0,        // rte_pktmbuf_copy — always safe
  kRefcntZeroCopy = 1,  // rte_mbuf_refcnt_update — requires all 3 gates
};

// -------------------------------------------------------------------------
// DriverCapabilities — mocked at M2 level. Real driver query comes in M3.

struct DriverCapabilities {
  bool tx_non_mutating = false;  // D26 gate #3: driver can TX shared mbufs
};

// -------------------------------------------------------------------------
// is_mutating_verb — D26 MUTATING_VERBS classification.
//
// Returns true if the verb modifies packet payload/headers, making
// refcnt-mirror unsafe. Currently only TAG (DSCP/PCP rewrite).
// -Wswitch-enum ensures new verbs cause a compile error if not handled.

bool is_mutating_verb(ActionVerb verb);

// -------------------------------------------------------------------------
// determine_mirror_strategy — D26 three-gate logic.
//
// Examines the set of verbs present in the ruleset, the operator's
// config preference, and the driver capability to select the mirror
// strategy. Used by the ruleset builder (or compiler) once per build.
//
// Parameters:
//   verbs_present        — all ActionVerb values present in the ruleset
//   config_zero_copy     — operator requested zero-copy mirror
//   caps                 — driver capabilities for the mirror port
//
// Returns kRefcntZeroCopy only when ALL three gates pass; else kDeepCopy.

MirrorStrategy determine_mirror_strategy(
    const std::vector<ActionVerb>& verbs_present,
    bool config_zero_copy,
    const DriverCapabilities& caps);

}  // namespace pktgate::compiler
