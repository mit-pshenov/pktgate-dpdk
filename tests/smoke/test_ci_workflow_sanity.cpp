// tests/smoke/test_ci_workflow_sanity.cpp
//
// M0 Cycle 6 — structural sentinel for the CI workflow + pre-commit
// hook scaffolding. Same shape as C5's test_fuzz_sanity.cpp, just
// pointed at .github/workflows/ci.yml and scripts/git-hooks/pre-commit
// instead of the fuzz preset files.
//
// Background. implementation-plan.md §0.2 (sanitizer matrix gate) and
// M0's scope list (§2 M0 C6) require two pieces of plumbing before M0
// closes:
//
//   1. `.github/workflows/ci.yml` — a GitHub Actions workflow that
//      rotates one sanitizer flavour per push (so every commit gets
//      *some* sanitizer coverage cheaply) and runs the full five-
//      preset matrix nightly (harness.md §H3). Fuzz preset is
//      deliberately excluded from the per-cycle / per-commit gate
//      and shipped as a separate short-run job (harness.md §H4.7) —
//      libFuzzer is too slow for a commit-gating path.
//
//   2. `scripts/git-hooks/pre-commit` — a local git hook that runs
//      `ctest --preset dev-asan -L unit` on every commit touching
//      `src/`. In M0 `src/` only contains `main.cpp`, so the hook is
//      effectively a no-op; the point of landing it in M0 is that
//      M1 can't be the milestone that also introduces hook
//      infrastructure (that's where the first real src/ files land
//      and we need the guard to already be present).
//
// What this test does (same philosophy as C5's FuzzSanity):
//
//   * It does NOT exercise the workflow. Running GitHub Actions from
//     a ctest is out of scope; that's what the CI job itself does.
//     The test's job is to catch bit-rot on the *plumbing*: file
//     exists, contains the identifiers we promised downstream tools
//     would find, and the hook is executable.
//
//   * It runs under all five dev-* smoke runs — i.e. on every
//     commit — so if someone deletes .github/workflows/ci.yml or
//     removes `dev-tsan` from the matrix definition, the local
//     build bar goes red before the CI bar does.
//
// RED for C6: none of .github/workflows/ci.yml,
// scripts/git-hooks/pre-commit exist yet, so every expectation
// below fails. GREEN arrives when the ci.yml + hook land.

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>

#ifndef PKTGATE_SOURCE_DIR
#  error "PKTGATE_SOURCE_DIR must be defined by the build system (M0 C6)"
#endif

namespace fs = std::filesystem;

namespace {

fs::path source_root() {
  return fs::path(PKTGATE_SOURCE_DIR);
}

std::string slurp(const fs::path& p) {
  std::ifstream in(p);
  if (!in) {
    return {};
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

bool is_executable(const fs::path& p) {
  struct stat st{};
  if (::stat(p.c_str(), &st) != 0) {
    return false;
  }
  // Any of owner/group/other execute bits is enough; we don't care
  // which — git preserves the mode flag, that's what matters.
  return (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0;
}

}  // namespace

TEST(CiWorkflowSanity, CiYmlExists) {
  // .github/workflows/ci.yml must exist. We deliberately grep the
  // raw file rather than parse YAML — parsing would pull a
  // dependency into the smoke tree for one sanity check, and the
  // authoritative schema check is whatever GitHub itself does when
  // the workflow actually runs.
  const auto p = source_root() / ".github" / "workflows" / "ci.yml";
  EXPECT_TRUE(fs::exists(p)) << "missing: " << p;
}

TEST(CiWorkflowSanity, CiYmlMentionsAllFiveDevPresets) {
  // Every dev-* preset from CMakePresets.json must appear in the
  // workflow, either in the rotating per-commit job or in the
  // nightly matrix. If someone adds a sixth sanitizer preset and
  // forgets to wire it into CI, this test is the tripwire.
  //
  // The fuzz preset is deliberately *not* checked here. Fuzz runs
  // in a separate shortrun job per harness.md §H4.7 and is
  // intentionally excluded from the per-cycle exit gate (see
  // implementation-plan.md §0.2 note about per-commit flavour
  // rotation).
  const auto p = source_root() / ".github" / "workflows" / "ci.yml";
  ASSERT_TRUE(fs::exists(p)) << "missing: " << p;
  const std::string body = slurp(p);

  for (const char* preset :
       {"dev-debug", "dev-release", "dev-asan", "dev-ubsan", "dev-tsan"}) {
    EXPECT_NE(body.find(preset), std::string::npos)
        << "ci.yml does not mention preset \"" << preset << "\"";
  }
}

TEST(CiWorkflowSanity, CiYmlHasRotatingAndNightlyJobs) {
  // Two job shapes must be present: a push-triggered job that picks
  // one sanitizer per commit (the "rotating" path) and a scheduled
  // job that runs the full matrix nightly. We check by grepping for
  // the standard GitHub Actions trigger keys rather than by job
  // name, so renaming the jobs later doesn't break this test.
  //
  //   on: push            — per-commit rotating flavour
  //   schedule: cron:     — nightly full matrix
  //
  // The cron string itself is not pinned; harness.md §H3 leaves the
  // exact hour up to whoever runs the fleet.
  const auto p = source_root() / ".github" / "workflows" / "ci.yml";
  ASSERT_TRUE(fs::exists(p)) << "missing: " << p;
  const std::string body = slurp(p);

  EXPECT_NE(body.find("push"), std::string::npos)
      << "ci.yml must have a push-triggered (rotating) job";
  EXPECT_NE(body.find("schedule"), std::string::npos)
      << "ci.yml must have a scheduled (nightly matrix) job";
  EXPECT_NE(body.find("cron"), std::string::npos)
      << "ci.yml's scheduled job must use a cron expression";
}

TEST(CiWorkflowSanity, PreCommitHookExistsAndIsExecutable) {
  // scripts/git-hooks/pre-commit — the hook itself lives in the
  // source tree so it can be reviewed and diffed; each clone
  // installs it by symlinking (or copying) into .git/hooks/.
  // Installation is documented in the hook's own header comment;
  // this test only asserts the source-tree file is present and
  // has the execute bit set, because git clone preserves mode
  // and a non-executable hook is silently ignored by git.
  const auto p = source_root() / "scripts" / "git-hooks" / "pre-commit";
  EXPECT_TRUE(fs::exists(p)) << "missing: " << p;
  if (fs::exists(p)) {
    EXPECT_TRUE(is_executable(p))
        << p << " must have the execute bit set "
             "(git preserves mode, non-executable hooks are silently ignored)";
  }
}

TEST(CiWorkflowSanity, PreCommitHookRunsDevAsanUnitLabel) {
  // The hook must actually invoke `ctest --preset dev-asan -L unit`
  // (or the exact equivalent) — §0.3 of implementation-plan.md is
  // explicit. In M0 src/ is effectively empty so the hook is a
  // no-op in practice, but the string needs to be present so M1's
  // first src/ commit runs under the gate from the moment it
  // lands. Grep check, no execution.
  const auto p = source_root() / "scripts" / "git-hooks" / "pre-commit";
  ASSERT_TRUE(fs::exists(p)) << "missing: " << p;
  const std::string body = slurp(p);

  EXPECT_NE(body.find("dev-asan"), std::string::npos)
      << "pre-commit must invoke the dev-asan preset";
  EXPECT_NE(body.find("-L unit"), std::string::npos)
      << "pre-commit must scope ctest to the `unit` label";
  // Sanity: the hook has to mention src/ because it only runs when
  // that path changed. If this line drifts (e.g. someone moves src
  // to source/) the hook needs to follow.
  EXPECT_NE(body.find("src/"), std::string::npos)
      << "pre-commit must gate on changes under src/";
}
