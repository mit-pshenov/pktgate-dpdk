#!/usr/bin/env bash
# scripts/check-ctest-labels.sh — ctest label reachability guard
#
# Usage: check-ctest-labels.sh <build-dir>
#
# Asserts that every scope/sentinel label in harness.md §H3.1 matches
# at least one test in the given build tree. Runs as a ctest entry
# itself (see tests/smoke/CMakeLists.txt) so it catches label drift on
# every commit.
#
# Why care: `ctest -L` takes a *regex*, so a typo in set_tests_properties
# (say, `LABELS "uint"` instead of `"unit"`) silently routes the test
# nowhere — and the CI job for `unit` then reports green because it
# ran zero tests. This script is the canary.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <build-dir>" >&2
  exit 2
fi

BUILD_DIR="$1"
if [[ ! -d "$BUILD_DIR" ]]; then
  echo "check-ctest-labels: build dir does not exist: $BUILD_DIR" >&2
  exit 2
fi

# Required label set — see harness.md §H3.1 (scope labels) plus the
# `sentinel` aggregate label from implementation-plan.md §0.5. We
# deliberately use the narrow "at least one test per label" rule; as
# milestones add real tests the count per label grows on its own.
required_labels=(smoke unit corner reload security sentinel)

fail=0
for label in "${required_labels[@]}"; do
  # `ctest -N -L <label>` prints "Test #N: name" lines for each match.
  # We anchor with `^` to require an exact-word match — ctest treats
  # -L as a regex, and `unit` would otherwise also match `unit-fast`
  # or similar compound labels introduced later.
  count=$(ctest --test-dir "$BUILD_DIR" -N -L "^${label}\$" 2>/dev/null \
            | grep -cE '^\s*Test #[0-9]+:' || true)
  if [[ "$count" -lt 1 ]]; then
    echo "check-ctest-labels: MISSING label '$label' — zero tests matched" >&2
    fail=1
  else
    echo "check-ctest-labels: OK label '$label' -> $count test(s)"
  fi
done

if [[ "$fail" -ne 0 ]]; then
  echo "check-ctest-labels: FAIL — one or more required labels unreachable" >&2
  exit 1
fi
echo "check-ctest-labels: all ${#required_labels[@]} required labels reachable"
