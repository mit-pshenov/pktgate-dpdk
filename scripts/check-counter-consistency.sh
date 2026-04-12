#!/usr/bin/env bash
# scripts/check-counter-consistency.sh — D33 counter consistency driver
#
# D33 (review-notes) + harness.md §H7 state: §10.3 of design.md is the
# single source of truth for pktgate_* metric names. Every counter
# mentioned in prose (design.md outside §10.3, plus review-notes.md
# anywhere) must appear in §10.3; every counter §10.3 declares must
# have a producer call site under src/. Both directions, both files.
#
# The script runs in three passes:
#
#   Pass 1 — §10.3 → canonical set.
#            Extracts the list of base metric names from the §10.3
#            fenced block in design.md. This is the source-of-truth
#            set the other passes compare against. Empty canonical set
#            is a hard error (would make Pass 3 trivially green).
#
#   Pass 2 — §10.3 → src/ producers. *Stub until M3.*
#            src/ is empty in M0 so the pass prints a deferred notice
#            and continues. Once M3 lands the first producer macros,
#            the pass turns into: "for every canonical name, ≥ 1 match
#            under src/ against stats_bump / metric_inc / COUNTER_INC"
#            (harness.md §H7.2). DO NOT mark this TODO as done before
#            the producer macros actually exist — a stub that returns
#            green is the worst-case D33 outcome.
#
#   Pass 3 — prose → §10.3.
#            Scans design.md (excluding §10.3 itself) and all of
#            review-notes.md for `pktgate_\w+` tokens, filters out a
#            small allowlist of known non-metric identifiers (binary /
#            library / user / uid-gid-variable names), and asserts
#            every remaining token is in the Pass 1 canonical set.
#            Any orphan is a DRIFT: line plus exit 1.
#
# Usage: check-counter-consistency.sh [design.md [review-notes.md]]
#        Defaults resolve relative to the script's own directory so
#        ctest-driven invocations don't have to care about cwd.
#
# Exit codes:
#   0  — all passes green.
#   1  — drift detected (Pass 3 found orphan prose references).
#   2  — usage error / missing input / empty canonical set.
#
# Why bash + awk + grep and not python: harness.md §H7 is explicit —
# the whole script must run in < 1 s in CI and have no runtime deps
# beyond coreutils. Python would pull in a venv story for the M0
# harness, which we don't need.

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "${script_dir}/.." && pwd)

DESIGN_MD="${1:-${repo_root}/design.md}"
REVIEW_NOTES_MD="${2:-${repo_root}/review-notes.md}"

usage() {
  cat <<EOF >&2
usage: $0 [design.md [review-notes.md]]

Checks D33 counter consistency across design.md §10.3 and the prose in
design.md + review-notes.md. Exit 0 = clean, 1 = drift, 2 = usage error.
EOF
  exit 2
}

for f in "$DESIGN_MD" "$REVIEW_NOTES_MD"; do
  if [[ ! -f "$f" ]]; then
    echo "check-counter-consistency: missing input file: $f" >&2
    usage
  fi
done

# ---------------------------------------------------------------------
# Pass 1 — canonical set from design.md §10.3
# ---------------------------------------------------------------------
#
# The §10.3 block is delimited by the `### 10.3` and `### 10.4` Markdown
# headings. Inside that block, metric names start at column 0 and look
# like `pktgate_<something>{labels...}  counter`. We strip everything
# from the first `{` or whitespace on and dedupe.
canonical=$(mktemp)
trap 'rm -f "$canonical"' EXIT

awk '
  /^### 10\.3/ { in_sec = 1; next }
  /^### 10\.4/ { in_sec = 0 }
  in_sec && /^pktgate_[A-Za-z0-9_]+/ {
    # Split on first whitespace or `{` — whichever comes first.
    name = $0
    sub(/[ \t{].*$/, "", name)
    print name
  }
' "$DESIGN_MD" | sort -u > "$canonical"

if [[ ! -s "$canonical" ]]; then
  echo "check-counter-consistency: Pass 1 produced an empty canonical set." >&2
  echo "check-counter-consistency: verify $DESIGN_MD contains a '### 10.3' heading." >&2
  exit 2
fi

canonical_count=$(wc -l < "$canonical")
echo "pass1: canonical set = ${canonical_count} metric(s) from §10.3"

# ---------------------------------------------------------------------
# Pass 2 — §10.3 → src/ producers (partial since M2 C11, C7.27)
# ---------------------------------------------------------------------
#
# M2 C11: the compiler assigns dense counter_slots per layer, mapping
# to the pktgate_rule_* family in §10.3. We verify that the three
# rule-counter base names exist in the canonical set — these are the
# counters the compiler's output structures will eventually feed.
#
# All other counters (port_*, lcore_*, reload_*, system gauges) have
# no src/ producer yet — those are deferred to M4-M10. We enumerate
# them explicitly so the deferred list shrinks as milestones land.
#
# When M3+ lands real producer macros (stats_bump / metric_inc /
# COUNTER_INC), extend this pass per harness.md §H7.2: for every
# canonical name, assert >= 1 match under src/ against the producer
# pattern.

pass2_errors=0

# Counter families the compiler output directly maps to (via
# counter_slot → rule_id → pktgate_rule_{packets,bytes,drops}_total).
# These base names MUST exist in §10.3.
for family in pktgate_rule_packets_total \
              pktgate_rule_bytes_total \
              pktgate_rule_drops_total; do
  if ! grep -Fxq -- "$family" "$canonical"; then
    echo "pass2: ERROR — compiler counter family '$family' missing from §10.3" >&2
    pass2_errors=$((pass2_errors + 1))
  fi
done

# Counters deferred to later milestones (no src/ producer yet).
# Tracked explicitly so the list shrinks as milestones land.
deferred_families=(
  # Port counters (M3 port init)
  pktgate_port_rx_packets_total
  pktgate_port_tx_packets_total
  pktgate_port_rx_bytes_total
  pktgate_port_tx_bytes_total
  pktgate_port_rx_dropped_total
  pktgate_port_tx_dropped_total
  pktgate_port_link_up
  # Lcore counters (M4-M6 dataplane)
  pktgate_lcore_packets_total
  pktgate_lcore_cycles_per_burst
  pktgate_lcore_idle_iters_total
  pktgate_lcore_l4_skipped_ipv6_extheader_total
  pktgate_lcore_l4_skipped_ipv6_fragment_nonfirst_total
  pktgate_lcore_tag_pcp_noop_untagged_total
  pktgate_lcore_dispatch_unreachable_total
  pktgate_lcore_pkt_truncated_total
  pktgate_lcore_qinq_outer_only_total
  pktgate_lcore_pkt_multiseg_drop_total
  pktgate_lcore_pkt_frag_skipped_total
  pktgate_lcore_pkt_frag_dropped_total
  # Redirect/mirror counters (M7+)
  pktgate_redirect_dropped_total
  pktgate_mirror_dropped_total
  # Default action counter (M4 classify)
  pktgate_default_action_total
  # Reload counters (M8+ reload pipeline)
  pktgate_reload_total
  pktgate_reload_latency_seconds
  pktgate_reload_pending_free_depth
  # System gauges (M8+ runtime)
  pktgate_active_generation
  pktgate_active_rules
  pktgate_cmd_socket_rejected_total
  pktgate_mempool_in_use
  pktgate_mempool_free
  pktgate_watchdog_restarts_total
  pktgate_bypass_active
  pktgate_log_dropped_total
)

deferred_count=0
for family in "${deferred_families[@]}"; do
  if grep -Fxq -- "$family" "$canonical"; then
    deferred_count=$((deferred_count + 1))
  else
    echo "pass2: WARNING — deferred counter '$family' not in §10.3 (stale deferred list?)" >&2
  fi
done

if [[ "$pass2_errors" -gt 0 ]]; then
  echo "pass2: FAIL — ${pass2_errors} compiler counter families missing from §10.3" >&2
  exit 1
fi
echo "pass2: ok — 3 compiler counter families verified, ${deferred_count} deferred to M3-M10 (no src/ producer yet)"

# ---------------------------------------------------------------------
# Pass 3 — prose → §10.3
# ---------------------------------------------------------------------
#
# Allowlist of pktgate_*-prefixed identifiers that are known NOT to be
# metrics. Keep this list as narrow as possible: every entry here is
# a blind spot, so we extend it only when the grabli is genuinely not
# a metric. Current entries (all verified in design.md / review-notes):
#
#   pktgate_dpdk           — product binary name (§14).
#   pktgate_dpdk_test_*    — gtest binary prefix (§14).
#   pktgate_dpdk_fuzz_*    — fuzz harness prefix (§14).
#   pktgate_core           — lib name (from libpktgate_core.a, §14).
#   pktgate_dp             — lib name (from libpktgate_dp.a, §14).
#   pktgate_uid            — the daemon's own-uid variable (§10.7 / D38).
#   pktgate_gid            — the daemon's own-gid variable (§10.7 / D38).
#   pktgate_test           — auxiliary Q9 test user account name.
#   pktgate_test2          — auxiliary Q9 test user account name.
is_allowlisted() {
  case "$1" in
    pktgate_dpdk|pktgate_dpdk_test_*|pktgate_dpdk_fuzz_*|\
    pktgate_core|pktgate_dp|\
    pktgate_uid|pktgate_gid|\
    pktgate_test|pktgate_test2)
      return 0
      ;;
  esac
  return 1
}

# Emit `path:lineno:token` triples. For design.md we skip the §10.3
# block (same state machine as Pass 1). For review-notes.md we scan
# the whole file — it has no §10.3 of its own and prose anywhere in
# it counts.
scan_prose() {
  local path="$1"
  local skip_canonical_block="$2"  # "1" to skip §10.3..§10.4

  awk -v skip="$skip_canonical_block" -v path="$path" '
    /^### 10\.3/ { in_sec = 1; if (skip == "1") next }
    /^### 10\.4/ { in_sec = 0 }
    skip == "1" && in_sec { next }
    {
      line = $0
      while (match(line, /pktgate_[A-Za-z0-9_]+/)) {
        tok = substr(line, RSTART, RLENGTH)
        print path ":" NR ":" tok
        line = substr(line, RSTART + RLENGTH)
      }
    }
  ' "$path"
}

hits=$(mktemp)
trap 'rm -f "$canonical" "$hits"' EXIT
{
  scan_prose "$DESIGN_MD" 1
  scan_prose "$REVIEW_NOTES_MD" 0
} > "$hits"

drift_count=0
while IFS=: read -r path lno tok; do
  [[ -z "$tok" ]] && continue
  if is_allowlisted "$tok"; then
    continue
  fi
  if ! grep -Fxq -- "$tok" "$canonical"; then
    echo "DRIFT: ${path}:${lno}: ${tok} not in §10.3 canonical set"
    drift_count=$((drift_count + 1))
  fi
done < "$hits"

if [[ "$drift_count" -gt 0 ]]; then
  echo "pass3: FAIL — ${drift_count} prose reference(s) missing from §10.3" >&2
  exit 1
fi
echo "pass3: ok — every prose pktgate_* token is in §10.3 (or allowlisted)"
exit 0
