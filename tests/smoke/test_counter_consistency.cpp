// tests/smoke/test_counter_consistency.cpp
//
// M0 Cycle 4 — D33 counter consistency invariant, live check.
//
// D33 (review-notes, harness.md §H7) says: every pktgate_* counter name
// mentioned in design.md / review-notes.md prose must also be listed in
// design.md §10.3 (the canonical metric set), and vice-versa. The grep
// harness is supposed to ship in M0 so that counter drift is caught
// before any code that produces counters even exists.
//
// This smoke test drives `scripts/check-counter-consistency.sh` from the
// build tree. It runs two cases:
//
//   * OkRealTree — runs the script against the repo's live design.md +
//     review-notes.md. Must exit 0. If this fails with drift, the fix
//     is in the *prose*: either §10.3 is missing a counter that prose
//     references, or prose still mentions a counter that was renamed
//     or removed. Do NOT silence the script — D33 exists precisely
//     because silence is how the original pkt_truncated_total regression
//     slipped past four review rounds.
//
//   * Injection — copies design.md to a temp file, appends a fake
//     `pktgate_foobar_total` reference in prose (outside §10.3), runs
//     the script against the mutated copy, and asserts exit != 0. This
//     proves Pass 3 is actually doing the comparison and not just
//     returning 0 regardless.
//
// Pass 2 (§10.3 → src/ producers) is intentionally a stub in M0 because
// src/ is still empty. It lights up in M3 once the first producer macro
// lands. harness.md §H7.2 describes the target shape.
//
// The test is a `smoke` label ctest — it runs under every preset on
// every commit (implementation-plan.md §0.2 matrix). The script is
// pure bash + ripgrep + awk, so sanitizer flavour is irrelevant: we
// only shell out, nothing is linked against the checker.

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>

#ifndef PKTGATE_SOURCE_DIR
#  error "PKTGATE_SOURCE_DIR must be defined by the build system (M0 C4)"
#endif

namespace fs = std::filesystem;

namespace {

// PKTGATE_SOURCE_DIR is defined as a string literal at build time via
// tests/smoke/CMakeLists.txt (e.g. "/home/user/pktgate-dpdk"). A path
// cannot be passed as a bare preprocessor token because `/` does not
// form a valid C++ identifier, so we rely on the pre-quoted form and
// use PKTGATE_SOURCE_DIR directly as a string literal.
fs::path source_root() {
  return fs::path(PKTGATE_SOURCE_DIR);
}

fs::path checker_script() {
  return source_root() / "scripts" / "check-counter-consistency.sh";
}

fs::path design_md() {
  return source_root() / "design.md";
}

fs::path review_notes_md() {
  return source_root() / "review-notes.md";
}

// Run checker with explicit design/review-notes paths. We do NOT rely
// on the script's default argument behaviour — tests should always be
// explicit about which files they're feeding in, so the injection case
// can swap design.md without touching review-notes.md.
int run_checker(const fs::path& design, const fs::path& review_notes) {
  std::string cmd;
  cmd.reserve(512);
  cmd += "bash ";
  cmd += checker_script().string();
  cmd += " ";
  cmd += design.string();
  cmd += " ";
  cmd += review_notes.string();
  // Route stdout/stderr to the gtest log so a failing ctest output
  // carries the DRIFT: lines from the script — otherwise we'd have
  // to re-run the script manually to see why it failed.
  const int raw = std::system(cmd.c_str());
  if (raw == -1) {
    return -1;
  }
  if (WIFEXITED(raw)) {
    return WEXITSTATUS(raw);
  }
  return -1;
}

// Generate a unique temp path under the system temp dir. We don't use
// tmpnam() / mktemp() because those warn-on-link; std::filesystem plus
// a random suffix is enough and plays well with all five sanitizers.
fs::path make_temp_design_copy() {
  std::random_device rd;
  std::mt19937_64 rng(rd());
  const auto suffix = std::to_string(rng());
  fs::path p = fs::temp_directory_path() /
               ("pktgate_counter_inject_" + suffix + ".md");
  fs::copy_file(design_md(), p, fs::copy_options::overwrite_existing);
  return p;
}

void inject_fake_counter(const fs::path& path) {
  // Append a prose paragraph that references `pktgate_foobar_total`.
  // We deliberately place it at end-of-file, which is well after the
  // §10.3 / §10.4 boundary — so the script's Pass 3 state machine
  // must classify it as "prose outside §10.3" and flag the drift.
  std::ofstream out(path, std::ios::app);
  ASSERT_TRUE(out.good()) << "failed to reopen " << path << " for append";
  out << "\n\n## Z99 — injected drift (test fixture, delete on read)\n\n"
      << "This paragraph intentionally references `pktgate_foobar_total` "
      << "to verify that check-counter-consistency.sh Pass 3 detects "
      << "prose references to counters not listed in §10.3.\n";
}

}  // namespace

TEST(CounterConsistency, ScriptExists) {
  // Sanity: the script itself must be on disk before we can run it.
  // A RED state for C4 has this test failing because the script
  // doesn't exist yet — that's the entry point of the cycle.
  EXPECT_TRUE(fs::exists(checker_script()))
      << "missing: " << checker_script();
  EXPECT_TRUE(fs::exists(design_md()))
      << "missing: " << design_md();
  EXPECT_TRUE(fs::exists(review_notes_md()))
      << "missing: " << review_notes_md();
}

TEST(CounterConsistency, OkRealTree) {
  // The real repo must be clean. Any drift here is a *real* bug in
  // prose vs §10.3, and the fix is to update the docs, not to edit
  // this test.
  const int rc = run_checker(design_md(), review_notes_md());
  EXPECT_EQ(rc, 0)
      << "check-counter-consistency.sh reported drift against the live "
         "repo. Fix design.md §10.3 or the offending prose — do NOT "
         "silence the script (see D33, harness.md §H7).";
}

TEST(CounterConsistency, InjectionDetectsFakeCounter) {
  const fs::path mutated = make_temp_design_copy();
  struct Cleanup {
    fs::path p;
    ~Cleanup() {
      std::error_code ec;
      fs::remove(p, ec);
    }
  } cleanup{mutated};

  inject_fake_counter(mutated);

  const int rc = run_checker(mutated, review_notes_md());
  EXPECT_NE(rc, 0)
      << "check-counter-consistency.sh failed to detect an injected "
         "`pktgate_foobar_total` reference in prose. Pass 3 is not "
         "actually comparing prose against the §10.3 canonical set.";
}
