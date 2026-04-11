# Test harness / CI / build matrix plan (draft)

> Operational plumbing under the pktgate-dpdk test plan. Describes **how**
> the tests defined by the unit / functional / corner / perf / chaos agents
> actually get built and executed. What tests exist is scoped by those
> agents; this document is strictly the machinery.
>
> Grounding: `input.md`, `design.md` §12 / §13 / §14, `review-notes.md`
> D2 (toolchain), D3 (telemetry channels), D8 (no legacy schema → no
> legacy fuzz corpus), D22 (alignment), D31 (truncation guards — UBSAN
> territory), D33 (counter consistency invariant → CI gate), D34 (refill
> clamp), D35 (single reload mutex → TSAN territory), D38 (peer-cred
> tests).
>
> Anywhere this document says "verify against doc.dpdk.org/api-25.11/":
> the claim is plausible but must be confirmed on the dev VM before
> landing in committed CMake / scripts. Hearsay ≠ fact (CLAUDE.md rule,
> D30 precedent).

---

## H1 — Dev VM prerequisites

The dev VM is Fedora 43 with DPDK 25.11 already installed (CLAUDE.md).
This section describes what else must be present to run the full CI
matrix on that VM, and the one-shot bring-up script that provisions it.

### H1.1 — Package dependencies (Fedora dnf)

Single `dnf install` stanza, split by role. Versions given are lower
bounds, not pins — Fedora 43 ships newer in almost every case.

**Toolchains (D2 — gcc ≥ 14 or clang ≥ 18, BOTH required for matrix)**

- `gcc`, `gcc-c++` (Fedora 43 ships gcc 15.x — above baseline)
- `clang`, `clang-tools-extra`, `clang-devel`, `llvm`, `lld`,
  `compiler-rt` (needed for sanitizer runtimes and libFuzzer)
- `libatomic`, `libstdc++-devel`, `glibc-devel`
- `libasan`, `libubsan`, `libtsan` (gcc sanitizer runtimes — Fedora
  packages them separately from gcc)

**Build system**

- `cmake` ≥ 3.22 (Fedora 43 ships 3.28+)
- `ninja-build`
- `pkgconf-pkg-config`
- `ccache` (optional but recommended — halves matrix build time)

**DPDK**

- `dpdk-devel` (25.11 — already installed per CLAUDE.md; listed for
  completeness on fresh VM provisioning)
- `dpdk-tools` (provides `dpdk-devbind.py`, `dpdk-hugepages.py`,
  `dpdk-telemetry.py`)
- `libpcap-devel` (needed by `net_pcap` PMD — confirm actually linked
  at DPDK build time on Fedora; `pkg-config --libs libdpdk` will tell)

**Test-code dependencies**

- `gtest-devel`, `gmock-devel`
- `nlohmann-json-devel` (config parser uses nlohmann/json; design §13
  lists it as project dep, tests need headers)
- `json-schema-validator-devel` if available; otherwise vendor in
  `third_party/` (verify on dev VM — Fedora packaging is intermittent)

**Python test harness**

- `python3`, `python3-pip`, `python3-pytest`, `python3-scapy`,
  `python3-psutil`, `python3-pyroute2`, `python3-pyelftools`
- Virtualenv under `tests/integration/.venv` is an acceptable
  alternative if distro packages lag scapy features; default is
  distro packages for reproducibility.

**Sanitizers + fuzzing**

- libFuzzer comes bundled with clang (`-fsanitize=fuzzer`); no separate
  package. Requires `compiler-rt`.
- AFL++ is **not** a baseline dependency — libFuzzer covers the MVP
  fuzz targets. Revisit if a target doesn't fit libFuzzer shape.

**Coverage**

- `lcov` (HTML reports, good Fedora packaging, stable)
- `gcovr` as an alternative frontend — install both, pick lcov as
  primary (H6 justifies)

**Observability / debugging / forensics**

- `perf` (`perf` package on Fedora — kernel-version-matched)
- `valgrind` (not used in gating CI; kept for ad-hoc memory debugging
  that ASAN cannot catch cleanly, e.g. EAL-internal mmap surprises)
- `gdb`, `strace`, `ltrace`
- `tcpdump`, `tshark` (functional test assertions look at pcap
  artifacts)

**Control-plane test dependencies**

- `socat` (hand-drive `/run/pktgate/ctl.sock` from test scripts)
- `inotify-tools` (manual reload trigger in tests)

**Documentation gates (H4.11)**

- `python3-pyyaml` for the §10.3-versus-src counter grep script (D33)
- `ripgrep` (`rg`) — the D33 consistency check and the dev-ergonomic
  grep scripts both use it; the Fedora package is `ripgrep`

### H1.2 — Hugepage provisioning

Two orthogonal decisions: **when** they're reserved, and **by whom**.

Dev VM default (CLAUDE.md baseline): 512 × 2 MiB, reserved at boot
via kernel cmdline. Persistent across reboots. Sufficient for
`dev-default` sized rulesets per design §8.4.

**Provisioning mechanism (pick one, default is option A)**

- **Option A — kernel cmdline flag** (default, matches existing dev
  VM): add `default_hugepagesz=2M hugepagesz=2M hugepages=512` to
  GRUB_CMDLINE_LINUX in `/etc/default/grub`, then
  `grub2-mkconfig -o /boot/grub2/grub.cfg`, reboot. Pros: allocated
  before memory fragmentation. Cons: needs a reboot to change.
- **Option B — systemd-tmpfiles / sysfs write at boot**: write to
  `/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages`. Works
  at runtime. Cons: later boot = more fragmentation, allocation can
  partial-fail on a long-up VM.

Prefer Option A for dev VM (no reboots expected during CI runs).
Document Option B as an escape hatch for lab runners where reboot
windows are expensive.

**Mount point**: `/dev/hugepages` (systemd default; DPDK EAL uses it
without arg). Confirm it's mounted `hugetlbfs` with `mount | grep
huge` before any test run.

**Permissions**: owned `root:hugetlbfs` by default. Tests that do
NOT run as root need either:
- the `pktgate` user added to `hugetlbfs` group, OR
- tests run with `sudo` wrapper (acceptable on dev VM where sudo is
  passwordless per CLAUDE.md).

Default in CI: tests run under `sudo` wrapper via a `ctest` runner
script (H8.1). Avoids group churn.

**Count as a function of preset**

| Preset / suite        | hugepages (2 MiB pages) | Rationale |
|---|---|---|
| unit (no EAL)         | 0                  | Core lib tests link libpktgate_core only |
| functional (net_pcap) | 256                | Dev-default sizing fits |
| perf-dev (net_null)   | 384                | Mempool + two rulesets for reload test |
| chaos                 | 512                | Full dev default |
| asan / tsan           | 512 + headroom     | Sanitizers inflate mmap (H5.1) |

If total hugepage count is too low for the asan flavor, ASAN test
jobs fail early with a clear message from the H8 runner script, not
deep inside EAL. Check is: count free huge pages via
`/proc/meminfo:HugePages_Free` against a per-preset minimum.

### H1.3 — vfio-pci binding

Two modes co-exist on the dev VM:

1. **vdev-only suites** (unit, functional-on-net_pcap, perf-dev on
   net_null): no PCI binding required, no physical NIC touched. EAL
   started with `--no-pci` or with vdev-only.
2. **Real-NIC suites** (dev VM has 2 × Intel 82545EM, driver
   `e1000e` on the host, `uio_pci_generic` or `vfio-pci` for DPDK):
   optional; used by smoke tests that exercise the ethdev path on
   real hw, even if the hw is hopelessly slow.

**Rebind script** (`scripts/dev-bind-nics.sh`, idempotent):

1. Load modules: `modprobe vfio-pci` (or `uio_pci_generic` as
   documented fallback — CLAUDE.md mentions both as working on the VM)
2. Unbind the target BDF from `e1000e` if currently bound
3. Bind to `vfio-pci` via `dpdk-devbind.py --bind=vfio-pci <BDF>`
4. Verify binding with `dpdk-devbind.py --status-dev net`

Idempotency: the script is a no-op if the NIC is already bound to
vfio-pci. CI smoke job runs this unconditionally before each test
pass that needs real NICs.

**IOMMU caveat**: vfio-pci requires IOMMU. On VirtualBox VMs IOMMU
is unreliable; `uio_pci_generic` is the practical fallback. The
script probes `/sys/kernel/iommu_groups/` — empty → falls back to
uio_pci_generic with a log warning. Documented tradeoff: no
`vfio_noiommu` hacks.

**Reverse-bind on shutdown**: CI teardown runs `dpdk-devbind.py
--bind=e1000e <BDF>` to return the NIC to the kernel before the
runner exits. Dev VM is shared between interactive and CI use; not
returning the NIC strands networking.

### H1.4 — Users and groups for D38 tests

D38 tests need two users: one in the `pktgate_gid` allow-list, one
NOT. Bring-up script creates:

- `pktgate` user + `pktgate` group, system-level
  (`useradd --system --user-group pktgate`)
- `pktgate_test_allowed` user, member of `pktgate` group
- `pktgate_test_denied` user, NOT member of `pktgate` group
- `/run/pktgate/` directory (systemd-tmpfiles snippet; `0755
  pktgate:pktgate`)

The D38 test suite connects to `/run/pktgate/ctl.sock` from both test
users and asserts:
- `pktgate_test_allowed` → mutating verbs (`reload`, `activate`)
  accepted
- `pktgate_test_denied` → rejected with
  `pktgate_cmd_socket_rejected_total{reason="peer_gid"}` incremented
- anonymous / no peer creds → rejected

Test runner uses `sudo -u pktgate_test_denied socat - UNIX-CONNECT:
/run/pktgate/ctl.sock` style. All sudo usage is
NOPASSWD-wrapped via a `/etc/sudoers.d/pktgate-ci` drop-in (installed
by the bring-up script; dev VM only, never in production).

### H1.5 — EAL argv per suite

| Suite | EAL argv | Reason |
|---|---|---|
| unit (core lib only) | none — no EAL | tests link `libpktgate_core.a`, no DPDK runtime |
| unit (dp helpers) | `--no-pci --no-huge -m 64 --vdev net_null0` | in-proc unit tests needing mbuf alloc; `--no-huge` bypasses hugepage requirement for small tests |
| functional | `--no-pci --vdev net_pcap0,rx_pcap=tests/pcaps/in.pcap,tx_pcap=tests/pcaps/out.pcap --vdev net_pcap1,rx_pcap=...,tx_pcap=... -l 0,1` | pcap-in/pcap-out for scapy-comparable functional suite |
| perf-dev | `--vdev net_null0,copy=0 -l 0-3 -n 4` | null PMD for microbench; `copy=0` avoids the memcpy bias |
| chaos | same as functional plus `--force-max-simd-bitwidth` tuning where relevant | reload storms + fault injection |
| lab | real PCI — out of scope here (H9) | lab runner owns this |

**`--no-huge` caveat**: works for `net_null` and lightweight tests,
but `net_pcap` on some DPDK versions falls back to standard mempool
allocation that still wants hugepages. **Verify on dev VM** whether
DPDK 25.11's `net_pcap` accepts `--no-huge -m <N>` and if not, fall
back to hugepages for functional suite (and pay the 256-page cost
per H1.2).

### H1.6 — One-shot bring-up (`scripts/dev-vm-bootstrap.sh`)

Idempotent shell script. Steps:

1. `dnf install` the list from H1.1 (idempotent when packages are
   already present)
2. Ensure hugepages are reserved (checks `/proc/meminfo`; if under
   target, invoke `dpdk-hugepages.py -p 2M --setup 1G` and log a
   warning that a reboot is recommended for lock-in)
3. Create pktgate users + group + `/run/pktgate/` + sudoers drop-in
4. Source `scripts/dev-bind-nics.sh` for real-NIC mode (optional,
   gated by `PKTGATE_BIND_NICS=1`)
5. Sanity-check: `pkg-config --modversion libdpdk` prints `25.11.x`
6. Print "dev VM ready" and exit 0

Script is invoked once per fresh VM image. CI runner calls it at
the start of each job with `--check-only` which asserts prerequisites
without modifying anything — if the image drifted, the runner fails
early.

---

## H2 — CMake presets

Implemented as `CMakePresets.json` at repo root. Ten presets, all
inherit from a single `base` configured to use the pkg-config DPDK
package. All build under `build/<preset-name>/` so multiple matrix
flavors coexist without rebuilds stepping on each other.

### H2.1 — `base` (inherit only)

- Generator: `Ninja`
- `CMAKE_EXPORT_COMPILE_COMMANDS=ON` (clangd + clang-tidy)
- `PKTGATE_WARNINGS_AS_ERRORS=ON`
- Common CFLAGS/CXXFLAGS pulled in via `target_compile_options` in
  CMakeLists, not preset-level strings — presets override compiler
  and sanitizer flags, not the warning surface.

### H2.2 — `dev-debug`

- Inherits `base`
- `CMAKE_BUILD_TYPE=Debug`
- `-O0 -g3 -fno-omit-frame-pointer`
- No sanitizers, default compiler (system gcc)
- `ctest -L unit` runs in seconds
- Primary iteration loop for `scripts/dev-test.sh unit` (H8)

### H2.3 — `dev-release`

- `CMAKE_BUILD_TYPE=Release`
- `-O3 -march=native -DNDEBUG`
- Default compiler
- Used by `ctest -L perf-dev` microbenches so the numbers correspond
  to release semantics. Must NOT be used for correctness tests —
  UBSAN-level bugs are invisible at `-O3`.

### H2.4 — `asan` (clang)

- Toolchain: clang (`CC=clang CXX=clang++`)
- `-O1 -g -fno-omit-frame-pointer`
- `-fsanitize=address,undefined` (AsanUbsan combined; catches both
  classes with one build)
- `-fno-sanitize-recover=all` → any fault is fatal (no silent
  continue, matches CI gate semantics)
- Env at runtime: `ASAN_OPTIONS=detect_leaks=1:abort_on_error=1:
  symbolize=1:print_stacktrace=1`
- LSAN suppressions file `tests/lsan.supp` for EAL-internal
  allocations that live for the process lifetime (DPDK's `rte_malloc`
  backs onto mmap'd hugepages; LSAN has known false positives —
  verify on dev VM and pin the suppressions to specific symbols)
- Label: `asan-safe` — tests that don't trip H5.1 gotchas

### H2.5 — `tsan` (clang)

- Toolchain: clang
- `-O1 -g -fno-omit-frame-pointer -fPIE -pie`
- `-fsanitize=thread`
- Env: `TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1:
  history_size=7`
- `TSAN_SUPPRESSIONS=tests/tsan.supp` — DPDK's internal synchronization
  (`rte_rwlock`, `rte_mcslock`, `rte_rcu_qsbr` itself) is outside our
  model and TSAN will flag it; we document the specific rte_ symbols
  suppressed, with commentary pointing at the H5.2 section.
- **TSAN job is the D9/D35 guard**: loads the reload storm and
  concurrent cmd_socket reload test; any TSAN report on the g_active
  atomics or reload_mutex is a regression on the single-writer
  invariant.
- Label: `tsan-safe`

### H2.6 — `ubsan` (clang)

- `-O1 -g -fno-omit-frame-pointer`
- `-fsanitize=undefined`
  with `-fno-sanitize=vptr` (we don't ship polymorphism on the hot
  path — vptr check is cost without value; verify flag syntax on
  dev VM against `clang --help`)
- `-fno-sanitize-recover=all`
- UBSAN-only flavor (not combined with ASAN) exists so we can run
  a broader set of suites that ASAN can't run cheaply (e.g.
  long-running chaos).
- **Load-bearing for**: D22 (`alignas(4) RuleAction`), D31 (truncation
  guards — off-by-one → read-past-end caught), D34 (`elapsed`
  multiply overflow caught before the clamp shields it, which
  proves the clamp is actually the only fix — see H5.4)
- Env: `UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:
  symbolize=1`

### H2.7 — `msan` (optional, best-effort)

- Toolchain: clang
- `-fsanitize=memory -fsanitize-memory-track-origins=2 -O1 -g`
- **Known not to work end-to-end with DPDK** — MSAN requires every
  library in the process to be instrumented, and DPDK is not.
  Treated as "run unit tests that don't link DPDK at all"
  (`libpktgate_core.a` only: parser, validator, compiler). Anything
  that calls into `rte_*` is excluded by a `msan-unsafe` ctest label.
- Best-effort, not a CI gate. Manually run by an engineer chasing
  a specific uninitialized-memory bug. Documented so it exists and
  can be picked up if it ever proves useful.
- Flag for H5.5.

### H2.8 — `coverage`

- Toolchain: gcc (gcov integration is more reliable than clang's
  source-based coverage on Fedora's packaging — verify)
- `CMAKE_BUILD_TYPE=Debug`
- `--coverage -O0 -g` (adds `-fprofile-arcs -ftest-coverage`)
- Link flag `--coverage`
- Runs the unit + functional labels only (perf and chaos are
  coverage-agnostic and would 10× the run time)
- Post-run: `lcov --capture --directory build/coverage --output
  build/coverage/raw.info`, filter out `build/`, `third_party/`,
  `tests/`, `/usr/**`, produce HTML with `genhtml`.

### H2.9 — `fuzz`

- Toolchain: clang
- `-O1 -g -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer`
- Per fuzz target: a separate executable that links
  `libpktgate_core.a` + the fuzzer runtime. Not the whole project.
- Targets (named per the unit/fuzz agents — this harness only wires
  them): `fuzz_config_parser`, `fuzz_rule_compiler`,
  `fuzz_l2_classify`, `fuzz_l3_classify`, `fuzz_l4_classify`. Each
  has its own `LLVMFuzzerTestOneInput`.
- Corpus seeded from `tests/fuzz/corpus/<target>/` in the repo.
  **No pktgate-legacy seed** — D8 dropped schema compat, so the
  pktgate scenarios would only drive parse-reject paths that aren't
  on the real hot path.
- `ci-fuzz-shortrun` caps per-target runtime at 60 s; `ci-fuzz-nightly`
  at 3600 s. Any crash is an artifact dropped into the job's artifacts
  directory (`crash-<target>-<hash>.bin`).

### H2.10 — `ci-gcc`

- gcc (any ≥ 14, dev VM has 15.x)
- `CMAKE_BUILD_TYPE=RelWithDebInfo` (`-O2 -g`)
- Full warning set from design §13:
  `-Wall -Wextra -Wpedantic -Werror`
  `-Wswitch-enum` (D21 / D25 enforcement)
  `-Wshadow -Wconversion -Wsign-conversion -Wnon-virtual-dtor`
  `-Wundef -Wcast-align -Wuninitialized -Wnull-dereference`
  `-Wformat=2 -Wmissing-declarations`
  `-Wstrict-aliasing=2` (L1 from the 4th review — deferred to build
  flags, landed here)
- `-fstrict-aliasing -fno-common`
- Primary compile-gate CI job. Runs `ctest -L unit`.

### H2.11 — `ci-clang`

- clang ≥ 18 (dev VM has 21.x)
- Same `CMAKE_BUILD_TYPE` and warning set as `ci-gcc`, with clang
  translations where needed. Must also be `-Werror`.
- Catches diagnostics gcc misses and vice versa (Clang's
  `-Wshadow-field-in-constructor-modified`, `-Wthread-safety`, …).
  `-Wthread-safety` is worth enabling for the reload_mutex callsites
  (D35) if we annotate them with `GUARDED_BY` — **architecture
  decision, not harness**, flag for implementer.
- Runs `ctest -L unit`.

### H2.12 — Preset / compiler combinations summary

| Preset | Compiler | Opt | Sanitizers | Coverage | Used by CI job |
|---|---|---|---|---|---|
| dev-debug | gcc (default) | -O0 | none | no | dev only |
| dev-release | gcc (default) | -O3 | none | no | perf dev bench |
| asan | clang | -O1 | addr+ub | no | `ci-asan` |
| tsan | clang | -O1 | thread | no | `ci-tsan` |
| ubsan | clang | -O1 | ub | no | `ci-ubsan` |
| msan | clang | -O1 | memory | no | manual |
| coverage | gcc | -O0 | none | yes | `ci-coverage` |
| fuzz | clang | -O1 | fuzz+addr+ub | no | `ci-fuzz-*` |
| ci-gcc | gcc | -O2 | none | no | `ci-build-gcc` |
| ci-clang | clang | -O2 | none | no | `ci-build-clang` |

Common pitfall to avoid: do NOT combine sanitizer and release
presets. Bug classes UBSAN catches at `-O1` are silently folded by
`-O3`. Release and sanitizers are separate dimensions.

---

## H3 — ctest label taxonomy

Labels are OR-able via `ctest -L 'pattern'`. Every test carries one
**scope** label and any number of **capability** labels.

### H3.1 — Scope labels (mutually exclusive per test)

- `unit` — pure-core, no EAL, <1 s each. Link `libpktgate_core.a`.
- `functional` — exercises the compiled dataplane against `net_pcap`.
  EAL required. Seconds to minutes.
- `corner` — same machinery as `functional`, exhaustive edge cases
  (truncation, QinQ, IPv6 ext headers, reload races). May take
  minutes per test.
- `perf-dev` — microbench against `net_null`. Release preset. Emits
  JSON numbers compared against a checked-in baseline.
- `chaos` — fault injection, reload storms, ENOMEM simulation,
  ctest-driven. Tens of minutes.
- `fuzz` — libFuzzer targets. Time-bounded, not count-bounded. Run
  manually or via the fuzz-shortrun / fuzz-nightly CI jobs.

### H3.2 — Capability labels (any combination)

- `needs-root` — sudo required (vfio binding, inotify with user not
  in group, hugepage reservation changes). CI runner wraps in sudo.
- `needs-hugepages` — hugepage count ≥ test-declared minimum,
  runner checks `/proc/meminfo:HugePages_Free` before launch.
- `needs-vfio` — needs a PCI device bound to vfio-pci. Usually
  skipped in dev VM because of VirtualBox IOMMU quirks; real lab
  runs always have this.
- `needs-net-capable` — scapy tests that send from the test host
  into the DUT (or vice-versa). Implies `needs-root` for raw sockets.
- `needs-pktgate-user` — D38 tests that require the pktgate test
  users from H1.4.
- `slow` — runtime > 60 s. Excluded from default `ctest` runs.
- `lab-only` — explicitly excluded from dev VM runs. Owned by H9.

### H3.3 — Sanitizer compatibility labels

- `asan-safe` — works under ASAN+UBSAN combined preset without false
  positives. Positive list (opt-in) — tests are `asan-safe` only
  after a human confirms they pass under the suppressions file.
- `tsan-safe` — same idea for thread sanitizer. Narrower set,
  because any test that loads EAL on multiple lcores hits H5.2 gotchas.
- `ubsan-safe` — broadest; almost every test should be in this set
  unless it deliberately triggers UB for a counter-example.
- `msan-unsafe` — explicitly excluded from MSAN preset runs. Any
  test that pulls in `libpktgate_dp.a` (EAL-linked) is MSAN-unsafe
  by default.

### H3.4 — Label usage rules

A test that is `functional` + `asan-safe` + `needs-hugepages` is
written once, picked up by both the ASAN CI job (via
`ctest -L 'functional&&asan-safe'` — note the `&&` syntax requires
recent ctest, verify) and by the default functional run.

`needs-root` labels → the harness wrapper (H8) knows to invoke via
sudo. Individual test executables do not `setuid` themselves.

The CTEST_LABELS_FOR_SUBPROJECTS variable is NOT used; we lean on
explicit labels per `add_test`.

---

## H4 — CI pipeline jobs (Phase 1 gating)

Runner assumption: a single Fedora 43 image that matches the dev VM
exactly, with `scripts/dev-vm-bootstrap.sh` applied. Jobs run in
parallel where possible; dependencies between jobs are called out.
Phase 1 CI is the dev VM. Phase 2 adds the lab runner (H9).

Jobs are gated per trigger:
- **PR**: ci-build-gcc, ci-build-clang, ci-asan, ci-ubsan, ci-fuzz-
  shortrun, ci-coverage, ci-doc
- **Push to main**: same as PR plus ci-tsan and ci-perf-dev
- **Nightly**: ci-fuzz-nightly, ci-chaos
- **Manual**: anything, plus the lab runner trigger (H9)

### H4.1 — `ci-build-gcc`

- **Trigger**: PR, push
- **Duration budget**: 4 min
- **Command**: `cmake --preset ci-gcc && cmake --build
  build/ci-gcc -j && ctest --preset ci-gcc -L unit --output-on-
  failure`
- **Pass criterion**: clean build, all `unit`-labeled tests green
- **Artifacts**: `build/ci-gcc/compile_commands.json` (feeds
  downstream lint jobs), test log

### H4.2 — `ci-build-clang`

- **Trigger**: PR, push
- **Duration budget**: 4 min
- **Command**: same with `ci-clang`
- **Pass criterion**: clean build, unit tests green
- **Artifacts**: same

Both `ci-build-*` must pass before any sanitizer or integration job
is allowed to proceed. This is the fast first gate; every subsequent
job assumes the code compiles under both toolchains.

### H4.3 — `ci-asan`

- **Trigger**: PR, push
- **Duration budget**: 15 min
- **Command**: `cmake --preset asan && cmake --build build/asan -j
  && ctest --preset asan -L 'unit|functional|corner|asan-safe'
  --output-on-failure`
- **Pass criterion**: no ASAN report, no UBSAN report, all tests
  green. `ASAN_OPTIONS=halt_on_error=1` means the first finding
  kills the job.
- **Artifacts**: test log, ASAN report file if any
- Depends on H4.1 / H4.2 succeeding

### H4.4 — `ci-tsan`

- **Trigger**: push (not every PR — TSAN is slower and D35/D9 are
  the main regressions we watch)
- **Duration budget**: 20 min
- **Command**: `cmake --preset tsan ... && ctest --preset tsan -L
  'unit|functional|tsan-safe' --output-on-failure`
- **Pass criterion**: no TSAN report on any worker / reload / ctl
  path. Suppressions are allowed only against DPDK-internal symbols.
- **Artifacts**: test log, TSAN report if any, current
  `tests/tsan.supp` snapshot in case it needs updating
- **D9 / D35 regression gate**: the reload-storm test
  (`chaos_reload_storm`, also labeled `tsan-safe`) is REQUIRED to
  pass here.

### H4.5 — `ci-ubsan`

- **Trigger**: PR, push
- **Duration budget**: 15 min
- **Command**: `cmake --preset ubsan ... && ctest --preset ubsan -L
  'unit|functional|corner|ubsan-safe' --output-on-failure`
- **Pass criterion**: no UBSAN report, all tests green
- **Load-bearing gates**: D22 alignment tests (misaligned read of
  `RuleAction` → UBSAN error), D31 truncation tests (read-past-end),
  D34 multiply-clamp tests (the clamp is asserted BEFORE the shield
  via a deliberate large-elapsed test that would otherwise overflow)

### H4.6 — `ci-coverage`

- **Trigger**: PR, push (informational on PR, gating on push)
- **Duration budget**: 20 min
- **Command**: `cmake --preset coverage ... && ctest --preset
  coverage -L 'unit|functional' && scripts/coverage-report.sh
  build/coverage`
- **Pass criterion**: line coverage ≥ **targets in H6.3**; regression
  from last main-branch run ≤ 1 percentage point.
- **Coverage target**: **78 % overall line, 90 % for
  src/dataplane/, 85 % for src/config/, 80 % for src/ruleset/**.
  Justification in H6.3; short version: hot path is load-bearing
  (critical correctness region → 90 %), control plane has more
  irreducible error-path code. 78 % overall is below common FAANG
  80 % floor but we're a systems project with unreachable-by-design
  fallback paths (e.g. NUMA fallback is coded but dev VM is
  single-socket), and the number is hard-floored — it only goes up.
- **Artifacts**: `coverage.html`, `coverage.json` (summary), trend
  file `coverage-history.json` appended per run

### H4.7 — `ci-fuzz-shortrun`

- **Trigger**: PR
- **Duration budget**: (targets × 60 s) + build ≈ 8 min
- **Command**: `cmake --preset fuzz ... && for t in
  fuzz_config_parser fuzz_rule_compiler fuzz_l2_classify
  fuzz_l3_classify fuzz_l4_classify; do build/fuzz/$t
  tests/fuzz/corpus/$t -max_total_time=60 -print_final_stats=1;
  done`
- **Pass criterion**: no crash, no OOM, no timeout. Any crash is
  a PR red.
- **Artifacts**: per-target `stats.txt`, any `crash-*` / `leak-*` /
  `timeout-*` file in the corpus dir.
- **Not a coverage gate**: 60 s of libFuzzer does not meaningfully
  increase coverage; this is a "any new input crashes?" smoke.

### H4.8 — `ci-fuzz-nightly`

- **Trigger**: nightly (`cron` or scheduler)
- **Duration budget**: (targets × 1 h) ≈ 6 h
- **Command**: same targets, `-max_total_time=3600`
- **Pass criterion**: no crash. Any crash is a filed ticket, not an
  immediate red — nightly jobs do not block anyone, but the crash
  corpus is promoted into the PR shortrun corpus to prevent
  regression.
- **Artifacts**: new corpus entries (dedupped by input hash), any
  crashes, final coverage snapshot from `-print_final_stats`

### H4.9 — `ci-chaos`

- **Trigger**: nightly, manual
- **Duration budget**: 45 min
- **Command**: `cmake --preset asan && ctest --preset asan -L
  'chaos&&asan-safe' --output-on-failure --timeout 2400`
  (chaos runs under ASAN to catch use-after-free on the reload
  race; the asan-safe subset excludes anything that trips H5.1)
- **Pass criterion**: all chaos tests green (reload storm, ENOMEM
  injection, kill-and-restart watchdog, …). This is the D9 / D11 /
  D35 stress surface.
- **Artifacts**: full test log, per-test per-lcore counter dumps

### H4.10 — `ci-perf-dev`

- **Trigger**: push to main, manual
- **Duration budget**: 15 min
- **Command**: `cmake --preset dev-release && ctest --preset
  dev-release -L perf-dev --output-on-failure`
- **Pass criterion**: per-test cycles-per-packet within ±10 % of
  baseline numbers stored in `tests/perf/baseline.json`. A
  regression > 10 % fails the job; an improvement > 10 % also
  fails (the baseline must be deliberately updated by the change
  that causes the improvement — prevents accidental baseline drift).
- **Artifacts**: JSON per-test perf output, diff vs baseline. If
  baseline is updated in the same PR, the diff is included in the
  review.
- **Scope**: **dev microbench**, NOT the 40 Gbps SLO. 40 Gbps is
  lab-only per design §12 and H9. Dev perf is directional — it
  catches "someone added a cache miss to the hot path", not
  "someone lost 15 % of 40 Gbps".

### H4.11 — `ci-doc` and counter consistency

- **Trigger**: PR, push
- **Duration budget**: 1 min
- **Command**: `scripts/check-counter-consistency.sh` +
  `scripts/check-dangling-refs.sh`
- **Pass criterion**: zero dangling counter references, zero
  counters-in-prose absent from §10.3, zero section cross-refs
  to nonexistent sections
- **Artifacts**: diff-like output listing any missing / extra rows
- Details in H7.

---

## H5 — Sanitizer gotchas (DPDK specifics)

DPDK + sanitizers is a known rough surface. Each entry below is a
real, verified-or-plausible gotcha with the workaround. Anything
tagged "verify" must be confirmed on the dev VM before landing in
committed config.

### H5.1 — ASAN + hugepages + mmap

**Gotcha**. ASAN reserves a very large shadow memory region (1/8 of
the virtual address space on x86_64) at process start. EAL then
tries to reserve hugepages at specific virtual addresses via
`mmap(MAP_HUGETLB)`. Historically this collided on x86_64 with
ASAN shadow in certain kernel layouts. DPDK 20.11+ should handle
this more cleanly via its dynamic memory allocator. Verify against
`doc.dpdk.org/api-25.11/rte__memory_8h.html` and EAL release notes
on sanitizer-specific mapping behavior.

**Workaround if it does bite**:
- `EAL_OPTIONS="... --iova-mode=va"` (default on x86_64, explicit
  in tests)
- `EAL_OPTIONS="... --legacy-mem"` — forces legacy static allocator.
  Less flexible but better-behaved with address-space-greedy
  sanitizers. Documented fallback.
- `EAL_OPTIONS="... --in-memory"` — avoids `/dev/hugepages` entirely,
  can dodge some mapping constraints.
- `ASAN_OPTIONS=disable_core=1:abort_on_error=1:symbolize=1`
  (standard).

**How to verify**: functional test that boots EAL under asan and
allocates a mempool of 4 K mbufs; if that works, the ordinary
functional suite will too.

### H5.2 — TSAN + `rte_rcu_qsbr`

**Gotcha**. TSAN models happens-before via explicit atomics and
locks; DPDK's QSBR uses memory barriers plus thread-register
protocol (workers call `rte_rcu_qsbr_quiescent` at safe points).
TSAN cannot see the "I was quiescent just now" state and will
flag the writer-side `pending_free_drain` (D36) as racing with the
read on the same pointer, even though the D30 token-based pattern
is correct.

**Workaround**:
- Suppress via `tests/tsan.supp`:
  ```
  race:rte_rcu_qsbr_*
  race:pktgate::deploy  # covered by D35 reload_mutex, TSAN can't see QSBR
  ```
- **Keep the suppression file narrow** — any suppression broader
  than the `rte_rcu_qsbr_*` family is a red flag. If we end up
  suppressing `race:worker_*` we are hiding a real bug.
- Review the suppressions file in every PR that touches §9.2 or
  §4.5.

**Verification**: the D35 single-writer invariant is tested via a
deliberate two-writer chaos test that races inotify and cmd_socket
reload paths; that test MUST report a TSAN race (then we know TSAN
can detect the class), and then we add the reload_mutex and confirm
the race disappears. Positive + negative coverage.

### H5.3 — TSAN requires `-fPIC` everywhere

TSAN builds need position-independent code in every translation
unit, including DPDK itself. Fedora's `dpdk-devel` package builds
DPDK with `-fPIC` by default for the shared-lib build
(`libdpdk.so`). **Verify** with `readelf -d /usr/lib64/libdpdk.so |
grep TEXTREL` — empty = PIC-clean. If static DPDK libs are linked,
they may not be PIC and TSAN will fail cryptically at link.

**Workaround**: always link the shared libdpdk under TSAN preset.
`pkg-config --libs libdpdk` returns `-ldpdk` by default which
pulls `libdpdk.so`; the tsan preset adds
`-DCMAKE_EXE_LINKER_FLAGS=-pie` explicitly.

### H5.4 — UBSAN and the D22 / D31 / D34 invariants

**Load-bearing**:

- **D22 `alignas(4) RuleAction`**: UBSAN's alignment checker
  (`-fsanitize=alignment`) catches any read through an
  insufficiently-aligned pointer. If a code path pulls a
  `RuleAction*` from a `uint8_t` array without the proper offset,
  UBSAN fires. That's the whole point — keeps the structural
  invariant enforced by a machine, not by a review comment.
- **D31 truncation guards**: UBSAN's pointer-overflow
  (`-fsanitize=pointer-overflow`) and object-size
  (`-fsanitize=object-size`) checks catch a read past a short mbuf
  data buffer if a guard is missing. Tests deliberately craft
  truncated pcaps (14-byte → VLAN → missing L3, etc.) and run
  them under UBSAN; a missing guard shows up as a clean finding.
- **D34 elapsed clamp**: UBSAN's
  `-fsanitize=unsigned-integer-overflow` + signed variant catches
  the `elapsed * rate_bps / tsc_hz` multiply. A deliberate test
  sets `last_refill_tsc` to zero and calls refill — without the
  clamp UBSAN reports overflow; with the clamp it's clean. Both
  cases are asserted (missing-clamp test is `#ifdef`-gated to
  `PKTGATE_UBSAN_NEGATIVE=1` so it's not run in normal CI but is
  run when we specifically want to verify UBSAN is wired correctly).
- **`-Wswitch-enum` + UBSAN = belt and suspenders**: `-Wswitch-enum`
  catches compile-time omissions, UBSAN catches runtime "cast this
  int to enum and then switch" bugs. D25 apply_action default
  arm is the reference.

### H5.5 — MSAN and DPDK

**Gotcha**. MSAN requires every dependency to be MSAN-instrumented,
including libc and libstdc++. DPDK itself is not. In practice,
any call that enters `rte_*` produces "use of uninitialized value"
noise from the EAL and mbuf subsystems that is not representative of
real bugs in pktgate code.

**Workaround**: MSAN preset only runs unit tests that link
`libpktgate_core.a` and do NOT go through EAL. These are the parser,
validator, compiler, and config-model tests. Anything labeled
`msan-unsafe` is excluded. Useful for chasing uninitialized-field
bugs in `compile_rule` output structs, not for hot path debugging.

Do NOT attempt `-fsanitize=memory -fsanitize-memory-use-after-dtor`
with EAL; verified failure mode is that EAL's internal
`rte_memseg_list_alloc` trips MSAN immediately and you get nothing
useful.

**Verification**: the core-only unit suite under MSAN is run by
hand (not a CI gate) every time someone chases a bug that smells
like "oh we forgot to initialize that field". Its value is
diagnostic, not preventive.

### H5.6 — ASAN + hugepage count

ASAN shadow memory doesn't count against hugepage budget — it's
ordinary anonymous mappings — but the ASAN-instrumented process
allocates 2-3× as much virtual memory for book-keeping. On the dev
VM with 5.6 GB RAM and 512 hugepages already reserved, an ASAN
test that additionally spins up EAL at dev-default sizes uses about
600 MB of regular memory. Budget OK; no action needed unless we
scale the dev VM down.

### H5.7 — Fuzz + ASAN + UBSAN combined

The `fuzz` preset combines three sanitizers. Runtime overhead is
large (libFuzzer + ASAN + UBSAN ≈ 5-8× baseline). 60 s shortrun
therefore executes ~5-10 million inputs per target, depending on
target complexity. For the `fuzz_config_parser` target which is
CPU-cheap, that's enough to exercise most of the grammar.

---

## H6 — Coverage collection and reporting

### H6.1 — Tool choice: lcov

- **lcov** over **gcovr**: lcov's HTML reports are more battle-tested
  for Fedora's gcc (gcovr sometimes miscounts branches on modern gcc).
  lcov also has a cleaner `--exclude` interface.
- Primary tool: `lcov` + `genhtml` (both from Fedora's `lcov`
  package).
- Secondary format: JSON summary produced by `gcovr -j 0
  --json-summary` — only for the CI trend graph, not for the
  pass/fail gate.

### H6.2 — Exclusions

Applied via `lcov --remove`:

- `build/*` (generated code, object files)
- `*third_party/*`
- `tests/*` (self-coverage is noise)
- `*/fuzz/*`
- `/usr/*` (system headers and libdpdk inlines)
- `*moc_*.cpp` (none right now but keep for future)
- `*/generated/*` (schema-generated code if the compiler ever adds
  any)

### H6.3 — Per-directory targets and their justification

| Directory | Target | Justification |
|---|---|---|
| `src/dataplane/` | 90 % line / 85 % branch | Hot path, load-bearing correctness (D13, D14, D15, D21, D27, D31, D32) |
| `src/config/` | 85 % line / 75 % branch | Parser + validator, lots of error paths. Some branches are unreachable-by-design (defensive `if (cfg == nullptr)`) |
| `src/compiler/` | 85 % line / 75 % branch | Rule compilation, object expansion, budget pre-flight (D37) |
| `src/ruleset/` | 80 % line / 70 % branch | RCU publish, pending_free (D36), GC (D11, D24) |
| `src/rl_arena/` | 85 % line / 75 % branch | D1, D10, D34 — small module, should cover almost everything |
| `src/ctl/` | 75 % line / 65 % branch | inotify + UDS + watchdog; error paths involve OS interaction we don't cleanly fake |
| `src/telemetry/` | 70 % line / 60 % branch | Prometheus / sFlow / log exporters — IO-heavy, hard to cover without mocks |
| `src/eal/` | 50 % line | Thin EAL bring-up; mostly initialization code exercised at boot only |
| **Overall** | **78 % line / 68 % branch** | Weighted average with a built-in floor. Once achieved, the job fails if any subsequent run drops below the current max-seen value (monotonically non-decreasing gate). |

78 % overall is deliberately lower than a "nice round 80". Two
reasons: (a) some subsystems (NUMA, multi-socket) are dead in the
dev VM and will not be exercised until lab. (b) we'd rather have
honest coverage numbers than a target that forces us to write
meaningless tests to hit a round number. Coverage should describe
behavior, not game a gate.

### H6.4 — HTML + JSON artifacts

- `coverage.html` — for humans, linked from the CI job page
- `coverage.json` — summary `{file, line_pct, branch_pct}` per file,
  machine-readable
- `coverage-history.json` — appended per run, feeds the trend graph;
  kept to last 90 runs, oldest pruned

### H6.5 — Trend regression alarm

After each push-to-main coverage run, compare against the running
median of the last 10 runs (not the single previous run — noisy).
Alert if overall line coverage drops by > 1 percentage point off the
median. Alert channel is the same Slack / mail channel as other CI
notifications (project decision, not harness — flag for implementer).

---

## H7 — D33 counter consistency automation

D33 states: every counter named in `design.md` (§3a, §4.3, §5, §11,
§15, review-notes prose) appears in §10.3; every counter §10.3
declares has a producer site somewhere under `src/`. Both directions.

**Script**: `scripts/check-counter-consistency.sh`. Bash + ripgrep.
Three passes:

### H7.1 — Pass 1: §10.3 → prose references

Extract the canonical list of metric names from §10.3 of `design.md`:

```
rg '^pktgate_' design.md | sed 's/[{ ].*//' | sort -u
```

This produces the source-of-truth set. Anything later compared
against this list.

### H7.2 — Pass 2: §10.3 → src/ producers

For each canonical name in the §10.3 list, assert at least one
occurrence in `src/` matches one of:

- `stats_bump(<name>`
- `metric_inc(<name>`
- `COUNTER_INC(<name>`
- direct `rte_telemetry` registration naming the metric

The exact naming is implementer choice — the script takes a list
of producer macros as a configurable allow-list, initially
`{stats_bump, metric_inc, COUNTER_INC}`. Adding a new producer
macro requires updating the allow-list; grep with
`-w` to avoid partial matches.

Failure mode: one entry per orphan, one line each, with the §10.3
line number and the canonical name. CI job fails with exit code 1.

### H7.3 — Pass 3: prose → §10.3

Grep all prose mentions of `pktgate_` in `design.md` and
`review-notes.md` OUTSIDE §10.3 itself. For each match, confirm it
exists in the §10.3 set. The D27 `pkt_truncated` → D31 regression
is exactly this case: prose mentioned the counter, §10.3 didn't
list it for four weeks, the 4th review caught it. This script
catches it in 1 s in CI.

The prose extraction needs to be careful not to false-positive on
text inside §10.3 fenced block. `ripgrep` + a simple state machine
that toggles on `### 10.3` / `### 10.4` headers suffices.

### H7.4 — Integration into CI

`ci-doc` job runs the script, exit code 0 is green, 1 is red with
the list of discrepancies printed verbatim. Takes < 1 second.

Optional: a pre-commit hook on `design.md` (H8.5) runs the same
script locally so drift is caught before the commit lands.

---

## H8 — Dev ergonomics

### H8.1 — `scripts/dev-test.sh`

One entry point for all local test invocations. Subcommands:

- `dev-test.sh unit` → `dev-debug` preset, `ctest -L unit`.
  ~10 s.
- `dev-test.sh functional` → `dev-debug`, `ctest -L functional`.
  Several minutes.
- `dev-test.sh asan [label]` → `asan` preset; label defaults to
  `'unit|functional|asan-safe'`, can be narrowed.
- `dev-test.sh tsan [label]` → `tsan` preset; same.
- `dev-test.sh ubsan [label]` → `ubsan` preset; same.
- `dev-test.sh coverage` → `coverage` preset, full run, opens HTML.
- `dev-test.sh fuzz <target> [duration]` → e.g.
  `dev-test.sh fuzz parser 5m`. Parses human duration
  (`30s`, `5m`, `1h`) into libFuzzer `-max_total_time`.
- `dev-test.sh perf [test-regex]` → `dev-release`, perf-dev label,
  optional regex filter.
- `dev-test.sh chaos [label]` → `asan` preset (same as CI),
  chaos label.
- `dev-test.sh clean` → `rm -rf build/`.

Under the hood: runs `cmake --preset <name>`, `cmake --build
build/<name> -j`, then `ctest`. Caches the fact that the build is
up-to-date (Ninja handles this correctly); no re-configure unless
the preset changed.

Wraps the invocation in sudo only if `needs-root` is a label on
the selected tests. The runner reads `ctest -N -L <label>`
output to decide.

Env-overridable: `PKTGATE_JOBS`, `PKTGATE_VERBOSE`, `PKTGATE_GDB=1`
(runs the failing test under gdb on first failure — dev-local
convenience).

### H8.2 — `scripts/dev-bench.sh`

Dedicated perf microbench driver. Builds `dev-release`, runs a
single `perf-dev`-labeled test with `perf stat -d` wrapped, prints
cycle-per-packet and IPC. Not for gating, for local exploration.

### H8.3 — `scripts/dev-fuzz-replay.sh <target> <crash-file>`

Replay a single saved crash artifact against a target under `asan`
preset (not fuzz preset — no libFuzzer runtime needed). Prints the
faulting stack. Used when a nightly fuzz run drops a crash and the
developer needs to reproduce.

### H8.4 — Pre-commit hook

`scripts/pre-commit.sh` installed via `git config core.hooksPath
scripts/git-hooks`. Steps in order:

1. `clang-format --dry-run --Werror` on staged `*.cpp`/`*.h`
2. `scripts/dev-test.sh unit` (fast path, dev-debug unit only)
3. `scripts/check-counter-consistency.sh`
4. `scripts/check-dangling-refs.sh` (section xrefs in design.md)

Total budget: ~30 seconds on a warm build. The `unit fast` variant
skips any unit test labeled `slow`. If all four pass, commit
proceeds.

Opt-out: `git commit --no-verify` is documented in CONTRIBUTING.md
as "for emergencies only", not a normal flow.

### H8.5 — clangd integration

`CMAKE_EXPORT_COMPILE_COMMANDS=ON` is set in the base preset. A
symlink `compile_commands.json → build/dev-debug/compile_commands.
json` is created by `scripts/dev-test.sh unit` automatically so
clangd, clang-tidy, and editor integrations find it.

### H8.6 — Formatting config

`.clang-format` in repo root. Style choice is implementer's, but
the harness requires that the format check is deterministic on all
toolchain versions we support (gcc 14/15, clang 18/21) — verified
by running `clang-format --dry-run` against both versions in the
dev image. If the two versions disagree, pin to clang-format from
the `ci-clang` toolchain in CI.

---

## H9 — Lab runner interface (Phase 2 preview)

Shallow by design — the perf agent owns the lab hardware plan. This
section describes only the **interface** between dev-VM CI and the
lab runner.

### H9.1 — Artifact handoff

When a `ci-build-gcc` + `ci-build-clang` + sanitizer + coverage
all pass on a PR, the commit SHA becomes eligible for lab
promotion. Eligibility is a label on the PR (e.g. `lab-ready`) set
by CI.

Lab runner trigger is manual in Phase 1 (operator-initiated) and
semi-automatic in Phase 2 (nightly pick of the most recent
lab-ready commit).

### H9.2 — Lab runner inputs

- **Source**: the lab runner pulls the same git SHA; it builds
  locally on the lab host with the `ci-gcc` preset (or a
  `lab-release` preset that differs only in `-march=` for the
  specific CPU SKU). No binary handoff — build artifacts are
  host-specific and tying dev-VM binaries to a Xeon SP build is
  asking for SIMD-width surprises.
- **Config**: `tests/lab/<scenario>.json` — same schema as the
  dataplane reads. Per-hardware-profile sizing config
  (`tests/lab/sizing-e810.json`, `tests/lab/sizing-xl710.json`).
- **Traffic pattern**: declared in `tests/lab/<scenario>.trex.py`,
  TRex Python driver.

### H9.3 — Lab runner outputs

- `lab-results.json` per scenario: `{pps, bps, p50_lat_ns,
  p99_lat_ns, p99_9_lat_ns, loss_pct, duration_s, reload_events,
  counter_snapshots}`
- Uploaded back to the dev-VM CI as a job artifact on the original
  PR (even if the run was manual). Path:
  `artifacts/lab/<sha>-<scenario>.json`.

### H9.4 — "Release gate: lab green" operational definition

Operationally, a release is blocked until:

- all Phase 1 CI gates green on the release commit
- at least one lab scenario per production-target NIC (E810, XL710,
  ConnectX-5/6 as available) has green results meeting:
  - 64 B packets at 40 Gbps bidirectional, < 0.01 % loss
  - p99 latency < 50 µs added (internal N2 target), < 500 µs
    customer-facing ceiling
  - 1 000 reload cycles under traffic with loss = 0 on reload
    boundaries
  - 24 h soak green (watchdog-restart metric still 0 at the end)

The lab runner produces the JSON; a small gate script
(`scripts/lab-gate.sh`) compares against these thresholds and
flips the release label. Gate script is implementer-owned detail
in Phase 2 — the harness only guarantees the artifact format.

### H9.5 — What dev VM CI will NEVER do

Explicit non-goals to prevent scope creep:
- 40 Gbps correctness — always lab
- Real NIC performance — always lab
- Long-running soak tests (> 1 h) — lab only
- Any test labeled `lab-only`

Dev VM is for correctness, sanitizers, coverage, and fuzz. Lab is
for performance and endurance. These do not mix.

---

## Appendix A — package list (Fedora dnf)

Single copy-paste-able command for bootstrap:

```sh
sudo dnf install -y \
  gcc gcc-c++ clang clang-tools-extra clang-devel llvm lld compiler-rt \
  libatomic libstdc++-devel glibc-devel \
  libasan libubsan libtsan \
  cmake ninja-build pkgconf-pkg-config ccache \
  dpdk-devel dpdk-tools libpcap-devel \
  gtest-devel gmock-devel nlohmann-json-devel \
  python3 python3-pip python3-pytest python3-scapy python3-psutil \
  python3-pyroute2 python3-pyelftools python3-pyyaml \
  lcov gcovr \
  perf valgrind gdb strace ltrace tcpdump wireshark-cli \
  socat inotify-tools \
  ripgrep \
  jq
```

Any package that Fedora 43 does not ship (`json-schema-validator-devel`
at time of writing) is vendored into `third_party/` with a version
pin. The bootstrap script detects missing packages and prints a
clear "vendored" message.

**Verify every line on the actual dev VM before committing this
appendix to the harness.** Fedora package names drift over releases
and this document is the operational contract — a typo here wastes
30 minutes for every new engineer.

---

## Appendix B — CMakePresets.json sketch

```json
{
  "version": 6,
  "cmakeMinimumRequired": { "major": 3, "minor": 22, "patch": 0 },
  "configurePresets": [
    {
      "name": "base",
      "hidden": true,
      "generator": "Ninja",
      "binaryDir": "${sourceDir}/build/${presetName}",
      "cacheVariables": {
        "CMAKE_EXPORT_COMPILE_COMMANDS": "ON",
        "PKTGATE_WARNINGS_AS_ERRORS": "ON"
      }
    },

    {
      "name": "dev-debug",
      "inherits": "base",
      "cacheVariables": {
        "CMAKE_BUILD_TYPE": "Debug",
        "CMAKE_CXX_FLAGS": "-O0 -g3 -fno-omit-frame-pointer"
      }
    },

    {
      "name": "dev-release",
      "inherits": "base",
      "cacheVariables": {
        "CMAKE_BUILD_TYPE": "Release",
        "CMAKE_CXX_FLAGS": "-O3 -march=native -DNDEBUG"
      }
    },

    {
      "name": "asan",
      "inherits": "base",
      "cacheVariables": {
        "CMAKE_C_COMPILER": "clang",
        "CMAKE_CXX_COMPILER": "clang++",
        "CMAKE_BUILD_TYPE": "Debug",
        "CMAKE_CXX_FLAGS": "-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all",
        "CMAKE_EXE_LINKER_FLAGS": "-fsanitize=address,undefined"
      }
    },

    {
      "name": "tsan",
      "inherits": "base",
      "cacheVariables": {
        "CMAKE_C_COMPILER": "clang",
        "CMAKE_CXX_COMPILER": "clang++",
        "CMAKE_BUILD_TYPE": "Debug",
        "CMAKE_CXX_FLAGS": "-O1 -g -fno-omit-frame-pointer -fPIE -fsanitize=thread",
        "CMAKE_EXE_LINKER_FLAGS": "-pie -fsanitize=thread"
      }
    },

    {
      "name": "ubsan",
      "inherits": "base",
      "cacheVariables": {
        "CMAKE_C_COMPILER": "clang",
        "CMAKE_CXX_COMPILER": "clang++",
        "CMAKE_BUILD_TYPE": "Debug",
        "CMAKE_CXX_FLAGS": "-O1 -g -fno-omit-frame-pointer -fsanitize=undefined -fno-sanitize=vptr -fno-sanitize-recover=all",
        "CMAKE_EXE_LINKER_FLAGS": "-fsanitize=undefined"
      }
    },

    {
      "name": "msan",
      "inherits": "base",
      "cacheVariables": {
        "CMAKE_C_COMPILER": "clang",
        "CMAKE_CXX_COMPILER": "clang++",
        "CMAKE_BUILD_TYPE": "Debug",
        "CMAKE_CXX_FLAGS": "-O1 -g -fsanitize=memory -fsanitize-memory-track-origins=2",
        "PKTGATE_NO_DPDK": "ON"
      }
    },

    {
      "name": "coverage",
      "inherits": "base",
      "cacheVariables": {
        "CMAKE_BUILD_TYPE": "Debug",
        "CMAKE_CXX_FLAGS": "-O0 -g --coverage",
        "CMAKE_EXE_LINKER_FLAGS": "--coverage"
      }
    },

    {
      "name": "fuzz",
      "inherits": "base",
      "cacheVariables": {
        "CMAKE_C_COMPILER": "clang",
        "CMAKE_CXX_COMPILER": "clang++",
        "CMAKE_BUILD_TYPE": "Debug",
        "CMAKE_CXX_FLAGS": "-O1 -g -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer",
        "PKTGATE_FUZZ": "ON"
      }
    },

    {
      "name": "ci-gcc",
      "inherits": "base",
      "cacheVariables": {
        "CMAKE_C_COMPILER": "gcc",
        "CMAKE_CXX_COMPILER": "g++",
        "CMAKE_BUILD_TYPE": "RelWithDebInfo",
        "CMAKE_CXX_FLAGS": "-O2 -g"
      }
    },

    {
      "name": "ci-clang",
      "inherits": "base",
      "cacheVariables": {
        "CMAKE_C_COMPILER": "clang",
        "CMAKE_CXX_COMPILER": "clang++",
        "CMAKE_BUILD_TYPE": "RelWithDebInfo",
        "CMAKE_CXX_FLAGS": "-O2 -g"
      }
    }
  ],

  "buildPresets": [
    { "name": "dev-debug",   "configurePreset": "dev-debug" },
    { "name": "dev-release", "configurePreset": "dev-release" },
    { "name": "asan",        "configurePreset": "asan" },
    { "name": "tsan",        "configurePreset": "tsan" },
    { "name": "ubsan",       "configurePreset": "ubsan" },
    { "name": "msan",        "configurePreset": "msan" },
    { "name": "coverage",    "configurePreset": "coverage" },
    { "name": "fuzz",        "configurePreset": "fuzz" },
    { "name": "ci-gcc",      "configurePreset": "ci-gcc" },
    { "name": "ci-clang",    "configurePreset": "ci-clang" }
  ],

  "testPresets": [
    {
      "name": "dev-debug", "configurePreset": "dev-debug",
      "output": { "outputOnFailure": true }
    },
    {
      "name": "asan", "configurePreset": "asan",
      "environment": {
        "ASAN_OPTIONS": "halt_on_error=1:abort_on_error=1:symbolize=1:print_stacktrace=1:detect_leaks=1",
        "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1:symbolize=1",
        "LSAN_OPTIONS": "suppressions=${sourceDir}/tests/lsan.supp"
      },
      "output": { "outputOnFailure": true }
    },
    {
      "name": "tsan", "configurePreset": "tsan",
      "environment": {
        "TSAN_OPTIONS": "halt_on_error=1:second_deadlock_stack=1:history_size=7:suppressions=${sourceDir}/tests/tsan.supp"
      },
      "output": { "outputOnFailure": true }
    },
    {
      "name": "ubsan", "configurePreset": "ubsan",
      "environment": {
        "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1:symbolize=1"
      },
      "output": { "outputOnFailure": true }
    },
    {
      "name": "coverage", "configurePreset": "coverage",
      "output": { "outputOnFailure": true }
    },
    {
      "name": "ci-gcc", "configurePreset": "ci-gcc",
      "output": { "outputOnFailure": true }
    },
    {
      "name": "ci-clang", "configurePreset": "ci-clang",
      "output": { "outputOnFailure": true }
    }
  ]
}
```

Verify the schema version (`"version": 6`) works with the CMake
shipped on the dev VM before committing. `cmake --version` should
be 3.25 or newer for full v6 feature set. Fedora 43 is well above
that, but the exact keys (`environment` in `testPresets`,
`configurePreset` inheritance) have landed in different versions
over the past couple of years.

*End of draft harness plan.*
