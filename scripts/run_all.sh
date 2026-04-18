#!/usr/bin/env bash
# scripts/run_all.sh — M13 dev-VM full-matrix orchestrator
#
# Runs the full dev-runnable ctest matrix across the five non-fuzz
# presets and reports PASS/FAIL per preset + a final MATRIX SUMMARY.
# Designed to be invoked ON the dev VM (it calls sudo directly; a
# remote wrapper can ssh-invoke this script but that is out of scope).
#
# Contract (CLAUDE.md / implementation-plan.md §M13 / handoff):
#   - Iterates: dev-debug, dev-release, dev-asan, dev-ubsan, dev-tsan
#     (cheapest first; tsan last because slowest). Fuzz preset is
#     explicitly OUT of the per-cycle gate (plan §0.2 lines 55-68).
#   - Per preset: clean /run/dpdk, configure, build, ctest (-j 1,
#     labels smoke|unit|functional|integration|chaos), then chown
#     build tree back to mit:mit (memory: sudo ctest leaves root-owned
#     artifacts that break next user-side build).
#   - --keep-going is the DEFAULT: the whole matrix runs even on the
#     first failure so we get the full picture.
#   - Each preset's full output is captured under build/<preset>/run_all.log
#     for drill-down; stdout shows the last ~25 lines (ctest tail +
#     label time summary) under a `===== <preset> =====` banner.
#
# Flags:
#   --presets a,b,c   Run only the given subset (comma-separated).
#                     Default = all 5. Useful for quick plumbing
#                     iteration: `run_all.sh --presets dev-debug`.
#   --no-chown        Skip the `chown -R mit:mit build/<preset>` step
#                     (for CI environments already running as the
#                     target user — dev VM default expects chown).
#   --keep-going      Explicit opt-in to the default policy. Present
#                     as a flag so readers don't have to guess whether
#                     the matrix short-circuits; it does not.
#
# Exit: 0 iff every requested preset's ctest exits 0. Otherwise 1, with
# the MATRIX SUMMARY listing which preset(s) failed.

set -euo pipefail

# --- Defaults ----------------------------------------------------------

readonly DEFAULT_PRESETS=(dev-debug dev-release dev-asan dev-ubsan dev-tsan)
readonly LABEL_FILTER='smoke|unit|functional|integration|chaos'
# DPDK 25.11 lives at a meson-uninstalled .pc path on the dev VM — see
# memory `vm_dpdk_layout.md`. Carry it through sudo via env override.
readonly PKG_CONFIG_PATH_VALUE='/home/mit/Dev/dpdk-25.11/build/meson-uninstalled'

presets=("${DEFAULT_PRESETS[@]}")
do_chown=1

# --- Arg parse ---------------------------------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --presets)
      if [[ $# -lt 2 || -z "${2:-}" ]]; then
        echo "run_all.sh: --presets requires a comma-separated list" >&2
        exit 2
      fi
      IFS=',' read -r -a presets <<< "$2"
      shift 2
      ;;
    --presets=*)
      IFS=',' read -r -a presets <<< "${1#--presets=}"
      shift
      ;;
    --no-chown)
      do_chown=0
      shift
      ;;
    --keep-going)
      # Explicit; this is already the default. Accepted for clarity.
      shift
      ;;
    -h|--help)
      sed -n '2,34p' "$0"
      exit 0
      ;;
    *)
      echo "run_all.sh: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

# Validate preset names against the known set (typo guard).
for p in "${presets[@]}"; do
  found=0
  for ok in "${DEFAULT_PRESETS[@]}"; do
    [[ "$p" == "$ok" ]] && { found=1; break; }
  done
  if [[ "$found" -eq 0 ]]; then
    echo "run_all.sh: unknown preset '$p' (allowed: ${DEFAULT_PRESETS[*]})" >&2
    exit 2
  fi
done

# --- Repo root ---------------------------------------------------------

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$repo_root" ]]; then
  echo "run_all.sh: must be invoked inside the pktgate-dpdk git work tree" >&2
  exit 2
fi
cd "$repo_root"

# --- Header ------------------------------------------------------------

echo "run_all.sh: repo root     = $repo_root"
echo "run_all.sh: PKG_CONFIG_PATH = $PKG_CONFIG_PATH_VALUE"
echo "run_all.sh: presets       = ${presets[*]}"
echo "run_all.sh: label filter  = $LABEL_FILTER"
echo "run_all.sh: chown back to mit:mit after ctest = $([[ $do_chown -eq 1 ]] && echo yes || echo no)"
echo

# --- Matrix loop -------------------------------------------------------

declare -a results=()   # element format: "<preset>|<pass|fail>|<n>/<total>"
overall_rc=0

for preset in "${presets[@]}"; do
  build_dir="build/$preset"
  log_file="$build_dir/run_all.log"
  mkdir -p "$build_dir"

  echo "===== $preset ====="
  echo "run_all.sh[$preset]: clean /run/dpdk/*"
  sudo sh -c 'rm -rf /run/dpdk/*'

  # Run configure + build + ctest together and tee into log_file. We
  # tolerate non-zero exit so the matrix keeps going; rc is captured
  # from PIPESTATUS[0].
  set +e
  (
    set -e
    echo "--- configure ---"
    sudo "PKG_CONFIG_PATH=$PKG_CONFIG_PATH_VALUE" cmake --preset "$preset"
    echo "--- build ---"
    sudo cmake --build "$build_dir" -j
    echo "--- ctest ---"
    sudo ctest --preset "$preset" -L "$LABEL_FILTER" -j 1 --output-on-failure
  ) 2>&1 | tee "$log_file"
  rc=${PIPESTATUS[0]}
  set -e

  # Chown back to mit:mit so next user-side build doesn't hit
  # root-owned artifacts (memory: grabli_sudo_ctest_root_artifacts.md).
  if [[ $do_chown -eq 1 ]]; then
    sudo chown -R mit:mit "$build_dir" || true
  fi

  # Parse the ctest tail for the tally. Typical last line:
  #   "100% tests passed, 0 tests failed out of 43"
  tally=""
  if grep -qE 'tests passed,.*tests failed out of' "$log_file"; then
    tally=$(grep -E 'tests passed,.*tests failed out of' "$log_file" | tail -1)
  fi

  # Tail for stdout (ctest summary + label time block).
  echo
  echo "--- $preset tail ---"
  tail -n 25 "$log_file" || true
  echo "--- end $preset tail ---"
  echo

  if [[ $rc -eq 0 ]]; then
    # Extract <n>/<total> from "100% tests passed, 0 tests failed out of 43".
    total=$(echo "$tally" | sed -nE 's/.*out of ([0-9]+).*/\1/p')
    total=${total:-0}
    results+=("$preset|PASS|$total/$total")
  else
    overall_rc=1
    # On fail, try to extract N passed / M total to report "N/M".
    n_pass=$(echo "$tally" | sed -nE 's/.*\b([0-9]+) tests passed.*/\1/p')
    total=$(echo "$tally" | sed -nE 's/.*out of ([0-9]+).*/\1/p')
    n_pass=${n_pass:-0}
    total=${total:-0}
    if [[ -n "$tally" ]]; then
      results+=("$preset|FAIL|$n_pass/$total")
    else
      results+=("$preset|FAIL|?")
    fi
  fi
done

# --- Summary -----------------------------------------------------------

echo "===== MATRIX SUMMARY ====="
failed_presets=()
for row in "${results[@]}"; do
  IFS='|' read -r name status tally <<< "$row"
  # Pad preset name to 11 chars for alignment (dev-release is widest @ 11).
  printf '%-11s : %s  (%s)\n' "$name" "$status" "$tally"
  [[ "$status" == "FAIL" ]] && failed_presets+=("$name")
done

if [[ ${#failed_presets[@]} -gt 0 ]]; then
  echo
  echo "run_all.sh: FAILED presets: ${failed_presets[*]}"
fi

exit $overall_rc
