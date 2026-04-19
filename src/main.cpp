// src/main.cpp
//
// M3 C1 — full binary boot: config parse → validate → compile →
// EAL init → port config → mempool → start ports → publish Ruleset →
// worker launch → SIGTERM → shutdown.
//
// Design anchors: §6.1 (init sequence), §6.4 (shutdown),
// D9 (g_active scaffold), D23 (NUMA-aware mempool).

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>      // M14 C2 — port resolver lookup return type
#include <sstream>
#include <string>
#include <string_view>   // M14 C2 — port resolver lookup callback param
#include <utility>
#include <variant>       // M14 C2 — PortResolveResult discrimination
#include <vector>

#include <rte_common.h>  // M13 C0 — RTE_CACHE_LINE_SIZE, RTE_ALIGN_CEIL (QSBR alignment fix)
#include <rte_cycles.h>  // M9 C2 — rte_get_tsc_hz for WorkerCtx cache
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_rcu_qsbr.h>  // M8 C4 — D12 process-wide QSBR handle

#include "src/action/action.h"
#include "src/compiler/compiler.h"
#include "src/compiler/object_compiler.h"
#include "src/config/parser.h"
#include "src/config/sizing.h"
#include "src/config/validator.h"
#include "src/ctl/bootstrap.h"
#include "src/ctl/cmd_socket.h"
#include "src/ctl/port_resolver.h"  // M14 C2 — D43 port resolver wiring
#include "src/ctl/reload.h"
#include "src/ctl/telemetry_reload.h"
#include "src/dataplane/worker.h"
#include "src/eal/dynfield.h"
#include "src/eal/port_init.h"
#include "src/rl_arena/arena.h"  // M9 C2 — rl_arena_global()
#include "src/ruleset/builder.h"
#include "src/ruleset/builder_eal.h"
#include "src/ruleset/ruleset.h"
// M10 C3 — Prometheus /metrics scrape pipeline (D42 hand-rolled HTTP).
#include "src/telemetry/http_server.h"
#include "src/telemetry/prom_encoder.h"
#include "src/telemetry/snapshot.h"
#include "src/telemetry/snapshot_publisher.h"
#include "src/telemetry/snapshot_ring.h"
// M11 C1 — inotify watcher thread (D38 inotify half) → reload::deploy().
#include "src/ctl/inotify/watcher.h"

// -------------------------------------------------------------------------
// Structured logging helpers.
//
// Production will use a proper JSON logger; M3 uses a simple printf-based
// approach that emits key=value pairs detectable by functional tests.

namespace {

void log_json(const char* msg) {
  std::fprintf(stdout, "%s\n", msg);
  std::fflush(stdout);
}

void log_json(const std::string& msg) {
  log_json(msg.c_str());
}

// Read entire file into string.
std::string read_file(const std::string& path) {
  std::ifstream f(path);
  if (!f.is_open()) {
    return {};
  }
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

// D9 (M8 C1): g_active now lives inside the reload manager
// (src/ctl/reload.{h,cpp}). The main binary uses the accessor
// pktgate::ctl::reload::active_ruleset() to read it — no local atomic
// needed. The old `std::atomic<Ruleset*> g_active` that lived here
// moved to the manager so reload_mutex (D35) can serialise every
// publish and the single-owner invariant (D9) is enforced by
// construction.

}  // namespace

int main(int argc, char* argv[]) {
  // ---- Phase 1: find --config in argv (before EAL consumes args) ----
  //
  // EAL's rte_eal_init() consumes argc/argv and rewrites them. We need
  // to extract --config before that happens. Everything after -- is
  // passed to EAL.
  std::string config_path;
  std::string ctl_sock_path;  // M8 C5: UDS reload endpoint (two-way X1.3).
  unsigned requested_workers = 0;  // 0 = auto-detect from available lcores
  unsigned mbuf_data_size = 0;     // 0 = RTE_MBUF_DEFAULT_BUF_SIZE
  int eal_argc = 0;
  std::vector<char*> eal_argv;

  // Scan for our flags in argv. Everything else goes to EAL.
  for (int i = 0; i < argc; ++i) {
    if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
      config_path = argv[i + 1];
      ++i;
      continue;
    }
    if (std::strcmp(argv[i], "--workers") == 0 && i + 1 < argc) {
      requested_workers = static_cast<unsigned>(std::atoi(argv[i + 1]));
      ++i;
      continue;
    }
    if (std::strcmp(argv[i], "--mbuf-size") == 0 && i + 1 < argc) {
      mbuf_data_size = static_cast<unsigned>(std::atoi(argv[i + 1]));
      ++i;
      continue;
    }
    if (std::strcmp(argv[i], "--ctl-sock") == 0 && i + 1 < argc) {
      // M8 C5: path for the AF_UNIX reload socket (two-way X1.3).
      // Empty / unset means the cmd_socket thread is NOT started; the
      // telemetry endpoint remains available regardless.
      ctl_sock_path = argv[i + 1];
      ++i;
      continue;
    }
    eal_argv.push_back(argv[i]);
  }
  eal_argc = static_cast<int>(eal_argv.size());

  if (config_path.empty()) {
    log_json("{\"error\":\"missing --config argument\"}");
    return 1;
  }

  // ---- Phase 2: load + parse + validate + compile config ----
  std::string json_text = read_file(config_path);
  if (json_text.empty()) {
    log_json("{\"error\":\"config file empty or unreadable\",\"path\":\"" +
             config_path + "\"}");
    return 1;
  }

  auto parse_result = pktgate::config::parse(json_text);
  if (!pktgate::config::is_ok(parse_result)) {
    auto& err = pktgate::config::get_err(parse_result);
    log_json(("{\"error\":\"parse_err\",\"message\":\"" + err.message + "\"}").c_str());
    return 1;
  }

  auto& cfg = std::get<pktgate::config::Config>(parse_result);

  auto validate_result = pktgate::config::validate(cfg);
  if (std::holds_alternative<pktgate::config::ValidateError>(validate_result)) {
    auto& err = std::get<pktgate::config::ValidateError>(validate_result);
    log_json(("{\"error\":\"validate_err\",\"message\":\"" + err.message + "\"}").c_str());
    return 1;
  }

  // Compile the config into runtime structures.
  //
  // M9 C5 boot-path fix: wire the rate-limit slot allocator into the
  // first compile() call (reload.cpp already does this for live
  // reloads).  Without this the boot-time CompiledAction.rl_slot stays
  // at kInvalidSlot for every kRateLimit verb, the builder skips the
  // D41 lockstep populate of rs.rl_actions[slot], n_rl_actions stays
  // zero, and the hot-path RL dispatch never fires. The integration
  // test for the compile → build roundtrip (test_rl_compile_build.cpp)
  // wires an allocator explicitly, which is how the stage-1 / stage-2
  // / stage-3 invariants stayed green while the boot path silently
  // dropped them — a textbook D41 silent pipeline gap, symmetric to
  // the three already catalogued (M2 compile(), M5 fragment_policy,
  // M7 dscp/pcp/redirect_port).
  pktgate::compiler::RlSlotAllocator rl_alloc =
      [](std::uint64_t rule_id) {
        return pktgate::rl_arena::rl_arena_global().alloc_slot(rule_id);
      };
  auto compile_result = pktgate::compiler::compile(cfg, /*opts=*/{}, rl_alloc);
  if (compile_result.error) {
    log_json(("{\"error\":\"compile_err\",\"message\":\"" +
              compile_result.error->message + "\"}").c_str());
    return 1;
  }

  // ---- Phase 3: EAL init ----
  int ret = rte_eal_init(eal_argc, eal_argv.data());
  if (ret < 0) {
    log_json("{\"error\":\"rte_eal_init failed\"}");
    return 1;
  }
  log_json("{\"event\":\"eal_init_ok\"}");

  // Register mbuf dynfield (§5.1). Must happen before any worker starts.
  int dyn_offset = pktgate::eal::register_dynfield();
  if (dyn_offset < 0) {
    log_json("{\"error\":\"dynfield registration failed\"}");
    rte_eal_cleanup();
    return 1;
  }
  log_json("{\"event\":\"dynfield_registered\",\"offset\":" +
           std::to_string(dyn_offset) + "}");

  // Install signal handlers AFTER EAL init (EAL may install its own).
  pktgate::ctl::install_signal_handlers();

  // ---- Phase 4: discover ports and create mempool ----
  std::uint16_t nb_ports = rte_eth_dev_count_avail();
  if (nb_ports < 2) {
    log_json(("{\"error\":\"insufficient ports\",\"available\":" +
              std::to_string(nb_ports) + "}").c_str());
    rte_eal_cleanup();
    return 1;
  }

  // Determine worker count: from --workers or auto-detect from available lcores.
  unsigned n_workers_u;
  if (requested_workers > 0) {
    n_workers_u = requested_workers;
  } else {
    // Count available worker lcores.
    n_workers_u = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
    unsigned lid;
    RTE_LCORE_FOREACH_WORKER(lid) { ++n_workers_u; }
#pragma GCC diagnostic pop
    if (n_workers_u == 0) n_workers_u = 1;  // fallback to main-thread worker
  }
  auto n_workers = static_cast<std::uint16_t>(n_workers_u);

  // D23: NUMA-aware mempool. For dev VM (single NUMA node), socket 0.
  unsigned socket_id = rte_socket_id();

  // mbuf count: enough for all RX/TX descriptors + burst headroom.
  // 8192 is generous for the functional test with net_pcap.
  constexpr unsigned kMbufCount = 8191;  // prime, DPDK convention
  constexpr unsigned kMbufCacheSize = 256;
  unsigned actual_mbuf_size = (mbuf_data_size > 0) ? mbuf_data_size
                                                    : RTE_MBUF_DEFAULT_BUF_SIZE;

  struct rte_mempool* mp = rte_pktmbuf_pool_create(
      "pktgate_pool", kMbufCount, kMbufCacheSize, 0,
      static_cast<std::uint16_t>(actual_mbuf_size),
      static_cast<int>(socket_id));
  if (mp == nullptr) {
    log_json("{\"error\":\"mempool creation failed\"}");
    rte_eal_cleanup();
    return 1;
  }

  // ---- Phase 5: configure and start ports ----
  //
  // In M3, we use the first two available ports. Port role resolution
  // (interface_roles → port_id mapping) is simplified: we iterate
  // available ports and assign them in order.
  std::vector<std::uint16_t> port_ids;
  {
    // DPDK 25.11: RTE_ETH_FOREACH_DEV internally mixes uint16_t params
    // with uint64_t return values. GCC -Wconversion warns; this is DPDK's
    // API design, not our bug.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
    std::uint16_t pid;
    RTE_ETH_FOREACH_DEV(pid) {
      port_ids.push_back(pid);
      // M7 C4: raise the cap to 3 so F3.9/F3.10 REDIRECT functional
      // tests can target a third tap vdev distinct from RX (port_ids[0])
      // and default TX (port_ids[1]). Production deployments only
      // declare 2 ports; this cap is purely a functional-test affordance.
      if (port_ids.size() >= 3) break;
    }
#pragma GCC diagnostic pop
  }

  // D28: TX-queue symmetry pre-check. Every port must support
  // at least n_workers TX queues before we configure anything.
  for (auto port_id : port_ids) {
    auto sym = pktgate::eal::check_tx_symmetry(port_id, n_workers_u);
    if (!sym.ok) {
      log_json("{\"error\":\"tx_queue_symmetry\",\"reason\":\"" +
               sym.error + "\",\"port\":" + std::to_string(port_id) +
               ",\"max_tx_queues\":" + std::to_string(sym.max_tx_queues) +
               ",\"n_workers\":" + std::to_string(n_workers_u) + "}");
      rte_mempool_free(mp);
      rte_eal_cleanup();
      return 1;
    }
  }

  // D39: scatter-off + mempool-fit pre-check.
  for (auto port_id : port_ids) {
    auto scatter = pktgate::eal::check_no_scatter(port_id, mp);
    if (!scatter.ok) {
      log_json("{\"error\":\"multiseg_rx_unsupported\",\"reason\":\"" +
               scatter.error + "\"}");
      rte_mempool_free(mp);
      rte_eal_cleanup();
      return 1;
    }
  }

  for (auto port_id : port_ids) {
    auto result = pktgate::eal::port_init(port_id, n_workers, n_workers, mp);
    if (!result.ok) {
      log_json("{\"error\":\"port_init_failed\",\"port\":" +
               std::to_string(port_id) + ",\"reason\":\"" +
               result.error + "\"}");
      rte_mempool_free(mp);
      rte_eal_cleanup();
      return 1;
    }
  }
  log_json(("{\"event\":\"ports_started\",\"ports_started\":" +
            std::to_string(port_ids.size()) + "}").c_str());

  // ---- Phase 6: build and publish Ruleset ----
  //
  // M4 C8: num_lcores for counter indexing must be rte_lcore_count(), NOT
  // n_workers.  The counter row array is indexed by raw lcore_id (0..n-1);
  // with `-l 0,1` the main thread is lcore 0 and the worker is lcore 1,
  // so if we sized only to n_workers the worker's counter_row(1) would
  // overflow a 1-row allocation.  rte_lcore_count() returns main+workers,
  // which is the tightest safe bound.
  const unsigned num_lcores_for_counters = rte_lcore_count();
  auto ruleset = std::make_unique<pktgate::ruleset::Ruleset>(
      pktgate::ruleset::build_ruleset(compile_result, cfg.sizing,
                                      num_lcores_for_counters));

  // M4 C8: populate the DPDK compound tables (rte_hash / rte_fib / rte_fib6)
  // from the CompileResult compound vectors.  build_ruleset() only creates
  // the pure-C++ action arenas; the DPDK side of the compiled-ruleset
  // pipeline lives in populate_ruleset_eal() (C0b silent gap fix — see
  // implementation-plan-errata.md §M4 "C0b silent gap").
  {
    pktgate::ruleset::EalPopulateParams eal_params;
    eal_params.name_prefix =
        "pktgate_g" + std::to_string(ruleset->generation);
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
            ",\"l2_compound_count\":" +
            std::to_string(ruleset->l2_compound_count) +
            ",\"num_lcores\":" + std::to_string(ruleset->num_lcores) +
            "}").c_str());

  // M8 C4 — D12: allocate the process-wide QSBR handle BEFORE any
  // worker starts + BEFORE reload::init so every subsequent reload
  // (C2 bounded synchronize, C4 shutdown synchronize) shares the
  // same QSBR variable. Workers register on this handle in their
  // prologue; shutdown() calls rte_rcu_qsbr_check against it before
  // deleting the current ruleset, giving TSan the happens-before
  // edge that closes the M4-M7 baseline race.
  //
  // `max_threads` sizing: n_workers is the worker count; we also
  // allow the main thread to register in case a later cycle wants to
  // sync-from-main. +1 headroom is cheap (per-thread QSBR state is
  // cacheline-sized).
  const std::uint32_t qsbr_max_threads =
      static_cast<std::uint32_t>(n_workers + 1u);
  // M13 C0 — `struct rte_rcu_qsbr` is `__rte_cache_aligned` (64 B) and
  // its internal accessors use aligned loads/stores. `alignof(max_align_t)`
  // on x86-64 is 16, which UBSan's alignment check correctly flags the
  // moment rte_rcu_qsbr_thread_online touches the handle. Align to the
  // DPDK cache line, and round size up to the same multiple (POSIX
  // aligned_alloc requires `size % alignment == 0`).
  size_t qsbr_sz_raw = rte_rcu_qsbr_get_memsize(qsbr_max_threads);
  size_t qsbr_sz = RTE_ALIGN_CEIL(qsbr_sz_raw, RTE_CACHE_LINE_SIZE);
  void* qsbr_raw = std::aligned_alloc(RTE_CACHE_LINE_SIZE, qsbr_sz);
  if (qsbr_raw == nullptr) {
    log_json("{\"error\":\"qsbr_alloc_failed\"}");
    rte_mempool_free(mp);
    rte_eal_cleanup();
    return 1;
  }
  auto* qs = static_cast<struct rte_rcu_qsbr*>(qsbr_raw);
  if (rte_rcu_qsbr_init(qs, qsbr_max_threads) != 0) {
    log_json("{\"error\":\"qsbr_init_failed\"}");
    std::free(qsbr_raw);
    rte_mempool_free(mp);
    rte_eal_cleanup();
    return 1;
  }

  // D9 (M8 C1): publish via the reload manager instead of a bare
  // atomic store in main.cpp. The manager owns the single g_active
  // pointer and the reload_mutex (D35); every future publish (the
  // UDS cmd_socket in later cycles, inotify in M11) funnels through
  // deploy(). For the initial boot-time publish we use
  // `deploy_prebuilt` because main.cpp already drove the
  // parse/validate/compile/build/populate pipeline above.
  {
    pktgate::ctl::reload::InitParams rp;
    rp.socket_id   = static_cast<int>(socket_id);
    rp.num_lcores  = num_lcores_for_counters;
    rp.max_entries = cfg.sizing.rules_per_layer_max;
    rp.name_prefix = "pktgate_boot";
    rp.qs          = qs;  // M8 C4 — D12 shutdown synchronize
    pktgate::ctl::reload::init(rp);

    // Hand ownership of the built Ruleset to the manager. The
    // unique_ptr above is released; the manager becomes the owner.
    auto publish_res =
        pktgate::ctl::reload::deploy_prebuilt(std::move(ruleset));
    if (!publish_res.ok) {
      log_json("{\"error\":\"reload_publish_failed\",\"reason\":\"" +
               publish_res.error + "\"}");
      std::free(qsbr_raw);
      rte_mempool_free(mp);
      rte_eal_cleanup();
      return 1;
    }
  }

  // M8 C5 — X1.3 two-way reload entry points.
  //
  // Register the DPDK telemetry `/pktgate/reload` command regardless
  // of whether --ctl-sock is provided — the telemetry UDS is always
  // exposed by rte_eal_init(). Optional UDS cmd_socket is started
  // only when --ctl-sock provides a path; both paths funnel through
  // reload::deploy() under reload_mutex (D35).
  {
    const int tele_ret = pktgate::ctl::telemetry_reload::register_endpoint();
    if (tele_ret != 0) {
      // Non-fatal: process continues without the telemetry endpoint.
      log_json("{\"event\":\"telemetry_reload_register_failed\",\"errno\":" +
               std::to_string(-tele_ret) + "}");
    } else {
      log_json("{\"event\":\"telemetry_reload_registered\"}");
    }
  }

  pktgate::ctl::CmdSocketServer cmd_sock{};
  if (!ctl_sock_path.empty()) {
    if (!pktgate::ctl::cmd_socket_start(cmd_sock, ctl_sock_path)) {
      log_json("{\"error\":\"cmd_socket_start_failed\",\"path\":\"" +
               ctl_sock_path + "\"}");
      pktgate::ctl::reload::shutdown();
      std::free(qsbr_raw);
      rte_mempool_free(mp);
      rte_eal_cleanup();
      return 1;
    }
    log_json("{\"event\":\"cmd_socket_ready\",\"path\":\"" +
             ctl_sock_path + "\"}");
  }

  // ---- Phase 5b: D43 port-role resolution (M14 C2) ----
  //
  // Replaces the legacy hardcoded `worker_ctx.port_id = port_ids[0];
  // worker_ctx.tx_port_id = port_ids[1];` positional assignment with
  // the C1 `pktgate::ctl::resolve_ports` helper. The resolver maps
  // every entry in `cfg.interface_roles` to a live DPDK port id via
  // injected lambdas over `rte_eth_dev_get_port_by_name` and
  // `rte_eth_dev_info_get` (D28 generalised — kInsufficientTxQueues
  // fires for any PMD, not just pci).
  //
  // Roles convention: `upstream_port` is the ingress and
  // `downstream_port` is the egress, matching every existing config
  // fixture across `tests/functional/`, `tests/integration/`, and
  // `tests/unit/test_*.cpp`.
  //
  // Failure modes — emit a structured diagnostic and exit non-zero
  // BEFORE any worker launches:
  //   * kPortNotRegistered     — declared role's port name not in EAL
  //                              registry (vdev not on cmdline,
  //                              pci not bound, name mismatch).
  //   * kInsufficientTxQueues  — port's nb_tx_queues < n_workers (D28).
  //   * kUnresolvedRoleSelector → only fires when `lookup_role` is
  //                              called for a role missing from
  //                              interface_roles (the two required
  //                              roles below).
  //
  // Boot-path observables (D41 guard, F14.boot_smoke):
  //   {"event":"port_resolved","role":"<name>","port_id":N}
  //     emitted per resolved role.
  //   {"event":"worker_ports","port_id":U,"tx_port_id":D}
  //     emitted once after worker_ctx is wired (Phase 6b.pre below)
  //     so functional tests can verify tx_port_id round-trips through
  //     the live binary, not via a directly-constructed WorkerCtx.
  std::uint16_t resolved_upstream_port = 0;
  std::uint16_t resolved_downstream_port = 0;
  {
    auto lookup_fn = [](std::string_view name)
        -> std::optional<std::uint16_t> {
      // rte_eth_dev_get_port_by_name takes a NUL-terminated string and
      // writes the port id on success. The string_view we receive may
      // not be NUL-terminated (it comes from the resolver after vdev
      // arg-string trimming), so allocate a std::string for the call.
      std::string nm{name};
      std::uint16_t pid = 0;
      if (rte_eth_dev_get_port_by_name(nm.c_str(), &pid) != 0) {
        return std::nullopt;
      }
      return pid;
    };
    auto probe_fn = [](std::uint16_t port_id)
        -> std::optional<std::uint16_t> {
      struct rte_eth_dev_info info{};
      if (rte_eth_dev_info_get(port_id, &info) != 0) {
        return std::nullopt;
      }
      // max_tx_queues is the cap; the resolver compares against
      // n_workers and surfaces kInsufficientTxQueues on shortfall.
      return info.max_tx_queues;
    };

    auto resolve_res = pktgate::ctl::resolve_ports(
        cfg, n_workers_u, lookup_fn, probe_fn);
    if (std::holds_alternative<pktgate::ctl::PortResolveError>(resolve_res)) {
      const auto& err =
          std::get<pktgate::ctl::PortResolveError>(resolve_res);
      log_json(std::string{"{\"error\":\"port_resolve_failed\""
                           ",\"kind\":"} +
               std::to_string(static_cast<int>(err.kind)) +
               ",\"role\":\"" + err.role_name +
               "\",\"message\":\"" + err.message + "\"}");
      rte_mempool_free(mp);
      rte_eal_cleanup();
      return 1;
    }
    const auto& resolved =
        std::get<pktgate::ctl::PortResolveOk>(resolve_res);

    // Emit a per-role diagnostic so the F14 boot-smoke (D41 guard) can
    // assert role → port_id round-trip directly off stdout. The
    // iteration order of `unordered_map` is unspecified; the assertion
    // payload doesn't depend on order, only on values.
    for (const auto& [role_name, pid] : resolved.by_role) {
      log_json(std::string{"{\"event\":\"port_resolved\""
                           ",\"role\":\""} +
               role_name + "\",\"port_id\":" +
               std::to_string(pid) + "}");
    }

    // The two roles the dataplane MUST have. Every existing fixture
    // and the in-tree integration tests declare these names; missing
    // either is a config error and we surface it the same way the
    // resolver surfaces a missing port.
    auto upstream = pktgate::ctl::lookup_role(resolved, "upstream_port");
    if (std::holds_alternative<pktgate::ctl::PortResolveError>(upstream)) {
      const auto& err =
          std::get<pktgate::ctl::PortResolveError>(upstream);
      log_json(std::string{"{\"error\":\"port_resolve_role_missing\""
                           ",\"role\":\""} +
               err.role_name + "\",\"message\":\"" + err.message + "\"}");
      rte_mempool_free(mp);
      rte_eal_cleanup();
      return 1;
    }
    auto downstream = pktgate::ctl::lookup_role(resolved, "downstream_port");
    if (std::holds_alternative<pktgate::ctl::PortResolveError>(downstream)) {
      const auto& err =
          std::get<pktgate::ctl::PortResolveError>(downstream);
      log_json(std::string{"{\"error\":\"port_resolve_role_missing\""
                           ",\"role\":\""} +
               err.role_name + "\",\"message\":\"" + err.message + "\"}");
      rte_mempool_free(mp);
      rte_eal_cleanup();
      return 1;
    }
    resolved_upstream_port = std::get<std::uint16_t>(upstream);
    resolved_downstream_port = std::get<std::uint16_t>(downstream);
  }

  // ---- Phase 6b.pre: WorkerCtx setup ----
  //
  // M10 C4 reorder: declare + initialise worker_ctx BEFORE the telemetry
  // publisher starts so the publisher's BuildFn can capture &worker_ctx
  // and wire LcoreCounterView fields to the live counter storage. The
  // worker thread doesn't observe worker_ctx until the rte_eal_remote_launch
  // call below (Phase 7); the publisher only reads via relaxed atomic
  // loads, which are safe against uninitialised-but-zeroed worker state.
  //
  // M14 C2 — port_id / tx_port_id come from the D43 resolver above,
  // not from positional `port_ids[0]` / `port_ids[1]`. The
  // `worker_ports` log line below is the D41 boot-path observable
  // verifying the resolver's result actually lands on the worker (an
  // orphaned-resolver-call regression — M9 C5 class — would show as
  // worker_ports.tx_port_id reverting to 1 even though the
  // `port_resolved` line above named a different port id).
  pktgate::dataplane::WorkerCtx worker_ctx{};
  worker_ctx.port_id = resolved_upstream_port;
  worker_ctx.tx_port_id = resolved_downstream_port;
  worker_ctx.queue_id = 0;
  worker_ctx.running = &pktgate::ctl::g_running;
  // M8 C1: the reload manager now owns the Ruleset; fetch the live
  // pointer via active_ruleset() (acquire-load). `ruleset` above was
  // moved into deploy_prebuilt(), so `ruleset.get()` is nullptr here.
  worker_ctx.ruleset = pktgate::ctl::reload::active_ruleset();
  // M7 C0: wire the production TX burst function. Unit tests swap
  // this for a spy; production always uses rte_eth_tx_burst.
  worker_ctx.tx_burst_fn = &rte_eth_tx_burst;
  // M8 C4 — D12 RCU QSBR lifecycle. M3/M4 shipped a single worker,
  // so thread_id 0 is unique for the lifetime of this process. When
  // multi-worker launches land (later milestone) the thread_id becomes
  // a monotonic counter over the RTE_LCORE_FOREACH_WORKER walk.
  worker_ctx.qs = qs;
  worker_ctx.qsbr_thread_id = 0;
  // M9 C2 — rate-limit arena + cached TSC frequency. Arena is the
  // process-wide singleton (outlives every Ruleset per D10); tsc_hz
  // is cached once to avoid the DPDK helper's first-call cost on
  // each packet in the RL verb path.
  worker_ctx.rl_arena = &pktgate::rl_arena::rl_arena_global();
  worker_ctx.tsc_hz = rte_get_tsc_hz();

  // M14 C2 — D41 boot-path observable. Emit AFTER worker_ctx is fully
  // wired (so what we log is what the worker will see) and BEFORE the
  // worker is launched (so the event is visible on stdout even if a
  // later step fails). Functional test F14.boot_smoke parses this line
  // to assert tx_port_id round-trips through the live binary, not via
  // a directly-constructed WorkerCtx.
  log_json(std::string{"{\"event\":\"worker_ports\""
                       ",\"port_id\":"} +
           std::to_string(worker_ctx.port_id) +
           ",\"tx_port_id\":" +
           std::to_string(worker_ctx.tx_port_id) + "}");

  // ---- Phase 6b: telemetry (snapshot publisher + /metrics HTTP) ----
  //
  // M10 C3 (D42 hand-rolled HTTP; D3 snapshot ring).
  // M10 C4 — extended BuildFn/BodyFn to surface every §10.3 name.
  //
  // Publisher: 1 Hz loop that builds a Snapshot from live WorkerCtx
  // counter sources + rte_eth_stats + Ruleset rule rows and publishes
  // into the SnapshotRing. Runs on its own thread; shutdown when
  // ctl::g_running flips false (same atomic SIGTERM flips for the
  // workers).
  //
  // D41 watch: prom_port flows config → sizing → main → HttpServer
  // — four edges. Boot-path smoke F8.1 covers: if the port never
  // arrives, connect refused; if the snapshot never publishes, body
  // fn returns empty but 200 still emits (empty-but-valid scrape).
  //
  // Layering (D10): publisher BuildFn + HttpServer BodyFn are the
  // seams through which DPDK state (rte_eth_stats_get) enters this
  // otherwise-DPDK-free telemetry lib. Only main.cpp links both
  // sides; pktgate_telemetry stays `nm`-clean of rte_* symbols.
  pktgate::telemetry::ProdSnapshotRing prom_ring;
  pktgate::telemetry::SnapshotPublisher prom_publisher;
  pktgate::telemetry::HttpServer prom_http;

  {
    const auto& ports_ref = port_ids;
    prom_publisher.start(
        prom_ring, pktgate::ctl::g_running,
        [&ports_ref, &worker_ctx](std::uint64_t gen) {
          using namespace pktgate::telemetry;
          // Port stats + link-up: one per live port. rte_eth_stats_get
          // + rte_eth_link_get_nowait are the only DPDK calls on this
          // control-plane path; invoked here (main.cpp is DPDK-aware)
          // and the results flow into the DPDK-free Snapshot struct.
          std::vector<PortStats> ps;
          std::vector<std::uint8_t> link_up;
          ps.reserve(ports_ref.size());
          link_up.reserve(ports_ref.size());
          for (auto pid : ports_ref) {
            struct rte_eth_stats es{};
            rte_eth_stats_get(pid, &es);
            PortStats s;
            s.ipackets  = es.ipackets;
            s.opackets  = es.opackets;
            s.ibytes    = es.ibytes;
            s.obytes    = es.obytes;
            s.imissed   = es.imissed;
            s.ierrors   = es.ierrors;
            s.oerrors   = es.oerrors;
            s.rx_nombuf = es.rx_nombuf;
            ps.push_back(s);

            // M13 C0 — `rte_eth_link_get_nowait` is declared
            // warn_unused_result; GCC -O3 refuses a plain `(void)` cast.
            // Treat a failing probe as "link unknown / down" (0). The
            // zero-initialised `link` above already has link_status=0,
            // so the fallback naturally degrades to "down".
            struct rte_eth_link link{};
            if (rte_eth_link_get_nowait(pid, &link) != 0) {
              link.link_status = 0;
            }
            link_up.push_back(link.link_status ? 1u : 0u);
          }

          // C4 — wire every §10.3 scalar/per-rule/reload name through
          // LcoreCounterView + RuleIdent + ReloadState + ActiveRuleCounts.
          // WorkerCtx pointers alias into live worker fields; reader-side
          // relaxed atomic loads satisfy TSan (D1 amendment 2026-04-17).
          //
          // This process currently runs a single worker (M3/M4/.../M10
          // scope), so views has length 1. Multi-worker extension is a
          // later milestone: push one view per launched WorkerCtx.
          LcoreCounterView view{};
          view.pkt_multiseg_drop_total = &worker_ctx.pkt_multiseg_drop_total;
          view.qinq_outer_only_total   = &worker_ctx.qinq_outer_only_total;
          view.pkt_truncated_l2        = worker_ctx.pkt_truncated_l2.data();
          view.pkt_truncated_l2_count  =
              static_cast<std::uint32_t>(worker_ctx.pkt_truncated_l2.size());
          view.pkt_truncated_l3        = worker_ctx.pkt_truncated_l3.data();
          view.pkt_truncated_l3_count  =
              static_cast<std::uint32_t>(worker_ctx.pkt_truncated_l3.size());
          view.pkt_truncated_l4        = worker_ctx.pkt_truncated_l4.data();
          view.pkt_truncated_l4_count  =
              static_cast<std::uint32_t>(worker_ctx.pkt_truncated_l4.size());
          view.pkt_frag_l3             = worker_ctx.pkt_frag_l3.data();
          view.pkt_frag_l3_count       =
              static_cast<std::uint32_t>(worker_ctx.pkt_frag_l3.size());
          view.l4_skipped_ipv6_extheader =
              &worker_ctx.l4_skipped_ipv6_extheader;
          view.l4_skipped_ipv6_fragment_nonfirst =
              &worker_ctx.l4_skipped_ipv6_fragment_nonfirst;
          view.dispatch_unreachable_total =
              &worker_ctx.dispatch_unreachable_total;
          view.tag_pcp_noop_untagged_total =
              &worker_ctx.tag_pcp_noop_untagged_total;
          view.redirect_dropped_total = &worker_ctx.redirect_dropped_total;

          // Walk the currently-active ruleset to build RuleIdent spans
          // + ActiveRuleCounts. The manager's active_ruleset() acquire-
          // loads under RCU; the pointer is valid for the duration of
          // this callback (publisher stops BEFORE reload::shutdown()).
          const auto* rs = pktgate::ctl::reload::active_ruleset();
          std::vector<RuleIdent> rule_ids;
          ActiveRuleCounts arc{};
          if (rs != nullptr) {
            arc.l2 = rs->n_l2_rules;
            arc.l3 = rs->n_l3_rules;
            arc.l4 = rs->n_l4_rules;
            rule_ids.reserve(
                static_cast<std::size_t>(rs->n_l2_rules) +
                static_cast<std::size_t>(rs->n_l3_rules) +
                static_cast<std::size_t>(rs->n_l4_rules));
            // L2 layer_base = 0.
            if (rs->l2_actions != nullptr) {
              for (std::uint32_t i = 0; i < rs->n_l2_rules; ++i) {
                const auto& a = rs->l2_actions[i];
                rule_ids.push_back(RuleIdent{
                    a.rule_id,
                    static_cast<std::uint32_t>(a.counter_slot),
                    std::uint8_t{2}});
              }
            }
            // L3 layer_base = 1 * l2_actions_capacity.
            if (rs->l3_actions != nullptr) {
              const auto l3_base = rs->l2_actions_capacity;
              for (std::uint32_t i = 0; i < rs->n_l3_rules; ++i) {
                const auto& a = rs->l3_actions[i];
                rule_ids.push_back(RuleIdent{
                    a.rule_id,
                    static_cast<std::uint32_t>(a.counter_slot) + l3_base,
                    std::uint8_t{3}});
              }
            }
            // L4 layer_base = 2 * l2_actions_capacity.
            if (rs->l4_actions != nullptr) {
              const auto l4_base = 2u * rs->l2_actions_capacity;
              for (std::uint32_t i = 0; i < rs->n_l4_rules; ++i) {
                const auto& a = rs->l4_actions[i];
                rule_ids.push_back(RuleIdent{
                    a.rule_id,
                    static_cast<std::uint32_t>(a.counter_slot) + l4_base,
                    std::uint8_t{4}});
              }
            }
            // Wire the per-rule counter row pointer into the view.
            // Single worker: use lcore 0 unconditionally; multi-worker
            // extension pushes one view per worker and picks each
            // worker's own lcore id.
            view.counter_row = rs->counter_row(0);
            view.n_slots     = rs->counter_slots_per_lcore;
          }

          // Reload state — snapshot under reload_mutex (D35). Copies
          // happen on this publisher thread, no torn reads.
          ReloadState rl{};
          const auto rc = pktgate::ctl::reload::counters_snapshot();
          rl.success_total         = rc.success;
          rl.parse_error_total     = rc.parse_error;
          rl.validate_error_total  = rc.validate_error;
          rl.compile_error_total   = rc.compile_error;
          rl.build_eal_error_total = rc.build_eal_error;
          rl.timeout_total         = rc.timeout;
          rl.internal_error_total  = rc.internal_error;
          rl.pending_free_depth    = rc.pending_depth;
          rl.active_generation     = rc.active_generation;
          // Latency gauge stays at 0 until reload.cpp stamps a per-
          // deploy duration (Phase 2 per handoff obstacle #5). The
          // name still ships via snapshot_metric_names for D33.
          rl.latency_seconds_last  = 0;

          std::array<LcoreCounterView, 1> views{view};
          return build_snapshot(
              gen,
              std::span<const LcoreCounterView>(views),
              std::span<const RuleIdent>(rule_ids),
              std::span<const PortStats>(ps.data(), ps.size()),
              rl,
              arc,
              std::span<const std::uint8_t>(link_up.data(), link_up.size()));
        });

    std::string err;
    if (!prom_http.start(
            cfg.sizing.prom_port, pktgate::ctl::g_running,
            [&prom_ring]() -> std::string {
              using namespace pktgate::telemetry;
              auto snap_opt = prom_ring.read_latest();
              if (!snap_opt) return {};
              const auto& snap = *snap_opt;
              std::string body;
              body.reserve(4096);

              // ---- Per-port family (counter + link-up gauge) --------
              for (std::size_t pid = 0; pid < snap.per_port.size(); ++pid) {
                const auto& s = snap.per_port[pid];
                std::vector<Label> lbls{{"port", std::to_string(pid)}};
                body += format_counter("pktgate_port_rx_packets_total",
                                       lbls, s.ipackets);
                body += format_counter("pktgate_port_tx_packets_total",
                                       lbls, s.opackets);
                body += format_counter("pktgate_port_rx_bytes_total",
                                       lbls, s.ibytes);
                body += format_counter("pktgate_port_tx_bytes_total",
                                       lbls, s.obytes);
                body += format_counter("pktgate_port_rx_dropped_total",
                                       lbls, s.imissed + s.ierrors +
                                                s.rx_nombuf);
                body += format_counter("pktgate_port_tx_dropped_total",
                                       lbls, s.oerrors);
                const std::uint8_t up =
                    pid < snap.per_port_link_up.size()
                        ? snap.per_port_link_up[pid]
                        : 0u;
                body += format_gauge("pktgate_port_link_up",
                                     lbls,
                                     static_cast<std::int64_t>(up));
              }

              // ---- Per-rule family ---------------------------------
              for (const auto& r : snap.per_rule) {
                std::vector<Label> lbls;
                // layer label if present (2/3/4 → "l2"/"l3"/"l4").
                if (r.layer == 2 || r.layer == 3 || r.layer == 4) {
                  lbls.push_back(
                      Label{"layer",
                            std::string{"l"} + std::to_string(r.layer)});
                }
                lbls.push_back(format_rule_id_label(r.rule_id));
                body += format_counter("pktgate_rule_packets_total",
                                       lbls, r.matched_packets);
                body += format_counter("pktgate_rule_bytes_total",
                                       lbls, r.matched_bytes);
                body += format_counter("pktgate_rule_drops_total",
                                       lbls, r.drops + r.rl_drops);
              }

              // ---- Scalar per-lcore family (D31/D32/D39/D40/D20/D27/
              // D25/D19/D16). Single aggregated lcore label for MVP;
              // multi-worker extension will emit per-lcore later. ----
              std::vector<Label> lc_lbls{{"lcore", "agg"}};
              body += format_counter("pktgate_lcore_pkt_multiseg_drop_total",
                                     lc_lbls, snap.pkt_multiseg_drop_total);
              body += format_counter("pktgate_lcore_qinq_outer_only_total",
                                     lc_lbls, snap.qinq_outer_only_total);

              // D31 truncation buckets — one line per `where` value.
              auto trunc_line = [&](std::string where,
                                    std::uint64_t v) {
                std::vector<Label> lbls{{"lcore", "agg"},
                                        {"where", std::move(where)}};
                body += format_counter("pktgate_lcore_pkt_truncated_total",
                                       lbls, v);
              };
              trunc_line("l2",             snap.pkt_truncated_l2);
              trunc_line("l2_vlan",        snap.pkt_truncated_l2_vlan);
              trunc_line("l3_v4",          snap.pkt_truncated_l3_v4);
              trunc_line("l3_v6",          snap.pkt_truncated_l3_v6);
              trunc_line("l3_v6_frag_ext", snap.pkt_truncated_l3_v6_frag_ext);
              trunc_line("l4",             snap.pkt_truncated_l4);

              // D40 fragment rollups — `af` label.
              auto frag_skip = [&](std::string af, std::uint64_t v) {
                std::vector<Label> lbls{{"lcore", "agg"},
                                        {"af", std::move(af)}};
                body += format_counter("pktgate_lcore_pkt_frag_skipped_total",
                                       lbls, v);
              };
              auto frag_drop = [&](std::string af, std::uint64_t v) {
                std::vector<Label> lbls{{"lcore", "agg"},
                                        {"af", std::move(af)}};
                body += format_counter("pktgate_lcore_pkt_frag_dropped_total",
                                       lbls, v);
              };
              frag_skip("v4", snap.pkt_frag_skipped_v4);
              frag_skip("v6", snap.pkt_frag_skipped_v6);
              frag_drop("v4", snap.pkt_frag_dropped_v4);
              frag_drop("v6", snap.pkt_frag_dropped_v6);

              // D20 / D27 IPv6 skips.
              body += format_counter(
                  "pktgate_lcore_l4_skipped_ipv6_extheader_total",
                  lc_lbls, snap.l4_skipped_ipv6_extheader_total);
              body += format_counter(
                  "pktgate_lcore_l4_skipped_ipv6_fragment_nonfirst_total",
                  lc_lbls, snap.l4_skipped_ipv6_fragment_nonfirst_total);

              // D25 backstop + D19 TAG no-op + D16 REDIRECT drop.
              body += format_counter(
                  "pktgate_lcore_dispatch_unreachable_total",
                  lc_lbls, snap.dispatch_unreachable_total);
              body += format_counter(
                  "pktgate_lcore_tag_pcp_noop_untagged_total",
                  lc_lbls, snap.tag_pcp_noop_untagged_total);
              body += format_counter(
                  "pktgate_redirect_dropped_total",
                  /*no labels*/ std::span<const Label>{},
                  snap.redirect_dropped_total);

              // Default-action fallthrough — `action` label.
              {
                std::vector<Label> lbls{{"action", "allow"}};
                body += format_counter("pktgate_default_action_total",
                                       lbls, snap.default_action_allow_total);
              }
              {
                std::vector<Label> lbls{{"action", "drop"}};
                body += format_counter("pktgate_default_action_total",
                                       lbls, snap.default_action_drop_total);
              }

              // ---- Reload family (counter + gauges) -----------------
              auto reload_line = [&](std::string result,
                                     std::uint64_t v) {
                std::vector<Label> lbls{{"result", std::move(result)}};
                body += format_counter("pktgate_reload_total", lbls, v);
              };
              reload_line("success",         snap.reload.success_total);
              reload_line("parse_error",     snap.reload.parse_error_total);
              reload_line("validate_error",  snap.reload.validate_error_total);
              reload_line("compile_error",   snap.reload.compile_error_total);
              reload_line("build_eal_error", snap.reload.build_eal_error_total);
              reload_line("timeout",         snap.reload.timeout_total);
              reload_line("internal_error",  snap.reload.internal_error_total);

              body += format_gauge(
                  "pktgate_reload_latency_seconds",
                  std::span<const Label>{},
                  snap.reload.latency_seconds_last);
              body += format_gauge(
                  "pktgate_reload_pending_free_depth",
                  std::span<const Label>{},
                  static_cast<std::int64_t>(snap.reload.pending_free_depth));
              body += format_gauge(
                  "pktgate_active_generation",
                  std::span<const Label>{},
                  static_cast<std::int64_t>(snap.reload.active_generation));

              // C5 / F8.13 — publisher liveness gauge. Monotonic
              // counter of completed snapshot publishes; scraped
              // alongside the other reload/active gauges. Its forward
              // progress under a slow scraper is the observable that
              // proves the N=4 ring decouples the 1 Hz writer from
              // the reader.
              body += format_gauge(
                  "pktgate_publisher_generation",
                  std::span<const Label>{},
                  static_cast<std::int64_t>(snap.publisher_generation_gauge));

              // Active ruleset rule counts by layer.
              auto active_rules_line = [&](std::string layer,
                                           std::uint64_t v) {
                std::vector<Label> lbls{{"layer", std::move(layer)}};
                body += format_gauge(
                    "pktgate_active_rules", lbls,
                    static_cast<std::int64_t>(v));
              };
              active_rules_line("l2", snap.active_rules.l2);
              active_rules_line("l3", snap.active_rules.l3);
              active_rules_line("l4", snap.active_rules.l4);

              return body;
            },
            &err)) {
      log_json(std::string{"{\"error\":\"prom_http_start_failed\",\"reason\":\""}
               + err + "\"}");
      // Non-fatal: continue without /metrics. F5 / F2 tests don't
      // need scrape to pass.
    } else {
      log_json(std::string{"{\"event\":\"prom_endpoint_ready\",\"port\":"}
               + std::to_string(prom_http.bound_port()) + "}");
    }
  }

  // ---- Phase 6c: inotify watcher (M11 C1, D38 inotify half) ----
  //
  // Spawns a control-plane thread that watches the parent directory
  // of --config for IN_CLOSE_WRITE | IN_MOVED_TO on the config
  // basename, debounces 150 ms (§9.3), and invokes
  // ctl::reload::deploy(contents) via the D35 funnel.
  //
  // The watcher is started AFTER reload::init() (Phase 5) but
  // BEFORE workers launch so an early edit during bring-up is
  // handled cleanly once the first deploy() completes.
  //
  // Shutdown ordering (below, Phase 9): stopped BEFORE
  // reload::shutdown() tears down g_active — same slot where
  // prom_publisher.stop() lives so new deploy() calls can't race
  // the reload manager teardown.
  pktgate::ctl::inotify::InotifyWatcher inotify_watcher;
  if (!inotify_watcher.start(
          config_path,
          [](std::string contents) {
            auto r = pktgate::ctl::reload::deploy(contents);
            if (r.ok) {
              log_json(std::string{"{\"event\":\"inotify_reload_ok\","
                                   "\"generation\":"} +
                       std::to_string(r.generation) + "}");
            } else {
              log_json(std::string{"{\"event\":\"inotify_reload_failed\","
                                   "\"kind\":"} +
                       std::to_string(static_cast<int>(r.kind)) +
                       ",\"error\":\"" + r.error + "\"}");
            }
          })) {
    // Non-fatal: binary continues without file-watch reload. The
    // telemetry /pktgate/reload endpoint (M8 C5) remains available.
    log_json("{\"event\":\"inotify_watcher_start_failed\"}");
  }

  // ---- Phase 7: launch worker(s) ----
  //
  // M3: single worker on the first available worker lcore.
  // M10 C4: worker_ctx already declared + populated above (before the
  // publisher). Nothing else to initialise here.

  unsigned worker_lcore = RTE_MAX_LCORE;
  unsigned count = 0;
  {
    // DPDK macro passes -1 as unsigned to rte_get_next_lcore — intentional
    // sentinel. Suppress GCC's -Wsign-conversion for this block.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
    unsigned lcore_id;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
      if (count == 0) {
        worker_lcore = lcore_id;
      }
      ++count;
    }
#pragma GCC diagnostic pop
  }

  if (worker_lcore == RTE_MAX_LCORE) {
    // No worker lcores available — run on main lcore fallback.
    // This happens with `-l 0` (single lcore). We'll run the worker
    // in a trivial loop on main.
    log_json("{\"event\":\"no_worker_lcores\",\"fallback\":\"main_thread\"}");

    // Signal ready, then run worker inline (for -l 0 single-core case).
    log_json("{\"ready\":true}");

    pktgate::dataplane::worker_main(&worker_ctx);
  } else {
    rte_eal_remote_launch(pktgate::dataplane::worker_main,
                          &worker_ctx, worker_lcore);

    log_json("{\"ready\":true}");

    // ---- Phase 8: control loop — wait for signal ----
    while (pktgate::ctl::g_running.load(std::memory_order_acquire)) {
      // 10 Hz heartbeat tick. Real telemetry/inotify/cmd_socket threads
      // land in later milestones.
      usleep(100'000);
    }

    // ---- Phase 9: shutdown (§6.4) ----
    log_json("{\"event\":\"workers_exit\"}");

    // Stop the cmd_socket accept loop BEFORE waiting on workers so
    // no late reload attempt can race the shutdown synchronize. The
    // telemetry endpoint cannot be unregistered via the DPDK API; a
    // late /pktgate/reload arriving during shutdown still funnels
    // through reload::deploy() which will see `initialised == false`
    // after reload::shutdown() below and reject with kInternal.
    if (!ctl_sock_path.empty()) {
      pktgate::ctl::cmd_socket_stop(cmd_sock);
    }

    rte_eal_mp_wait_lcore();

    // M8 C4 — D12: close the stats-on-exit race.
    //
    // `rte_eal_mp_wait_lcore()` pthread_join's each worker. That's a
    // real happens-before edge, BUT ThreadSanitizer is blind to it:
    // librte_eal.so isn't instrumented, so TSan can't observe the
    // fences DPDK's join emits. Without the explicit acquire load
    // below, TSan flags the main-thread reads of the per-lcore
    // counter row (and WorkerCtx scalar fields) in the stats_on_exit
    // emitter as races against the worker's last writes.
    //
    // Worker puts a `worker_done.store(true, release)` as its last
    // instrumented action before returning; we pair with an acquire
    // load here. Both atomics live in pktgate-owned TUs so TSan sees
    // the HB edge directly.
    //
    // This is NOT a D1 hot-path atomic: one load per worker lifetime
    // at shutdown. The classify/dispatch path stays atomic-free.
    while (!worker_ctx.worker_done.load(std::memory_order_acquire)) {
      usleep(1000);
    }
  }

  // ---- M10 C3: stop telemetry threads before touching Ruleset ----
  //
  // Order: HTTP accept loop first (no new scrape requests), then the
  // publisher (no new snapshot builds). Both honour
  // ctl::g_running.load(acquire) which is already false by this
  // point, so each join returns promptly (< 200 ms — U7.X2 guards).
  //
  // Why BEFORE stats_on_exit + reload::shutdown: the publisher's
  // BuildFn captures port_ids and calls rte_eth_stats_get; stopping
  // it here means no new callback fires while we're tearing down
  // ports / the ruleset. The BodyFn only reads prom_ring (no DPDK),
  // so HTTP is safe to drop at any point — but we stop it first
  // anyway so no pending scrape holds a response half-written.
  //
  // M11 C1 — stop the inotify watcher FIRST so no late kernel event
  // can land a deploy() call after reload::shutdown() has torn down
  // g_active. The watcher's poll() tick is bounded at 100 ms, so
  // stop() returns within that window.
  inotify_watcher.stop();
  prom_http.stop();
  prom_publisher.stop();

  // ---- M4 C8: emit per-rule counter summary for functional tests ---------
  //
  // Aggregates per-lcore RuleCounter rows across all workers and emits
  // one JSON log line {event, rules: [{rule_id, layer, matched_packets,
  // drops}, ...]}.  Only rules with non-zero traffic are listed.  Real
  // telemetry (M10) replaces this with a proper scrape endpoint; for M4
  // the log line is the functional observable F2 tests assert on.
  {
    // M8 C1: fetch the live ruleset via the reload manager. Under
    // the shutdown guarantees the manager owns the single pointer;
    // `active_ruleset()` returns non-null for the whole lifetime of
    // the worker and for this stats emission (shutdown comes later).
    const pktgate::ruleset::Ruleset* rs_ptr =
        pktgate::ctl::reload::active_ruleset();
    const auto& rs = *rs_ptr;
    std::string stats_json =
        "{\"event\":\"stats_on_exit\",\"rules\":[";
    bool first_entry = true;

    for (std::uint32_t idx = 0; idx < rs.n_l2_rules; ++idx) {
      if (!rs.l2_actions) break;
      const auto& act = rs.l2_actions[idx];
      const auto slot = static_cast<std::uint32_t>(act.counter_slot);

      std::uint64_t total_matched = 0;
      std::uint64_t total_drops   = 0;
      for (std::uint32_t lc = 0; lc < rs.num_lcores; ++lc) {
        const auto* row = rs.counter_row(lc);
        if (!row || slot >= rs.counter_slots_per_lcore) continue;
        total_matched += row[slot].matched_packets;
        total_drops   += row[slot].drops;
      }

      if (total_matched == 0 && total_drops == 0) continue;

      if (!first_entry) stats_json += ',';
      first_entry = false;
      stats_json += "{\"rule_id\":" + std::to_string(act.rule_id) +
                    ",\"layer\":\"l2\""
                    ",\"matched_packets\":" + std::to_string(total_matched) +
                    ",\"drops\":" + std::to_string(total_drops) + "}";
    }

    // M6 C5: L4 per-rule counter summary (symmetric to L2 above).
    // L4 layer_base offset: 2 * rules_per_layer_max (same as in bump_l4_counter).
    for (std::uint32_t idx = 0; idx < rs.n_l4_rules; ++idx) {
      if (!rs.l4_actions) break;
      const auto& act = rs.l4_actions[idx];
      const auto slot = static_cast<std::uint32_t>(act.counter_slot) +
                        2u * rs.l2_actions_capacity;

      std::uint64_t total_matched = 0;
      std::uint64_t total_drops   = 0;
      for (std::uint32_t lc = 0; lc < rs.num_lcores; ++lc) {
        const auto* row = rs.counter_row(lc);
        if (!row || slot >= rs.counter_slots_per_lcore) continue;
        total_matched += row[slot].matched_packets;
        total_drops   += row[slot].drops;
      }

      if (total_matched == 0 && total_drops == 0) continue;

      if (!first_entry) stats_json += ',';
      first_entry = false;
      stats_json += "{\"rule_id\":" + std::to_string(act.rule_id) +
                    ",\"layer\":\"l4\""
                    ",\"matched_packets\":" + std::to_string(total_matched) +
                    ",\"drops\":" + std::to_string(total_drops) + "}";
    }

    // M9 C5 — per-RL-rule aggregate drops from the arena (D10 per-lcore
    // row → sum across kMaxLcores). Emits a dedicated list `rl` in the
    // stats_on_exit envelope so functional F3 tests (and future
    // operator telemetry) can observe:
    //   * F3.13 — drops-above-limit, ±20% Variant A tolerance
    //   * F3.14 — slot stability across reload (rule_id persists with
    //             non-zero drops if bucket state survived)
    //   * F3.15 — slot recycling (rule_id disappears from `rl` after
    //             removal; reappears with drops reset to 0 on re-add).
    //
    // Note: the arena outlives the Ruleset (D10), but we enumerate
    // through the currently-live rs.rl_actions — that is the operator-
    // visible set of RL rules for this generation. Removed rules were
    // already GC'd by rl_arena_gc (C4) and their slots zeroed (§9.4
    // step 5b).
    std::uint64_t rl_dropped_total = 0;
    std::string rl_json = ",\"rl\":[";
    bool first_rl = true;
    if (rs.rl_actions != nullptr) {
      auto& arena = pktgate::rl_arena::rl_arena_global();
      for (std::uint32_t i = 0; i < rs.n_rl_actions; ++i) {
        const auto& rl = rs.rl_actions[i];
        if (rl.rule_id == 0) continue;   // defensive, see arena_gc.cpp
        const auto slot_opt = arena.lookup_slot(rl.rule_id);
        if (!slot_opt) continue;
        const auto& row = arena.get_row(*slot_opt);
        std::uint64_t rule_dropped = 0;
        for (std::size_t lc = 0; lc < pktgate::rl_arena::kMaxLcores; ++lc) {
          rule_dropped += row.per_lcore[lc].dropped;
        }
        rl_dropped_total += rule_dropped;

        if (!first_rl) rl_json += ',';
        first_rl = false;
        rl_json += "{\"rule_id\":" + std::to_string(rl.rule_id) +
                   ",\"slot\":" + std::to_string(*slot_opt) +
                   ",\"rl_dropped\":" + std::to_string(rule_dropped) + "}";
      }
    }
    rl_json += "]";

    // M4 C9 — F8.14: expose per-lcore dataplane counters that are NOT
    // per-rule through a sibling `counters` object.  M4 shipped only
    // `qinq_outer_only_total` (D32); M5 C3 adds the first D40 fragment
    // counters (`pkt_frag_dropped_total_v4` and `pkt_frag_skipped_total_v4`).
    // M5 C6 adds the v6 family (`pkt_frag_dropped_total_v6`,
    // `pkt_frag_skipped_total_v6`) + D27 `l4_skipped_ipv6_fragment_nonfirst`.
    // M6 adds the D31 L3 truncation
    // buckets. M10 replaces this ad-hoc JSON with a proper Prometheus
    // scrape endpoint; flat keys keep the shape greppable from
    // functional tests until then.
    //
    // Aggregation is a sum across workers.  The dev VM runs a single
    // worker, so the aggregate equals the single WorkerCtx field.  When
    // M-later adds multi-worker launches, this loop will extend over the
    // worker_ctx array — kept as an explicit sum so that extension does
    // not require a test-surface change.
    const std::uint64_t frag_dropped_v4 = worker_ctx.pkt_frag_l3[
        static_cast<std::size_t>(
            pktgate::dataplane::L3FragBucket::kL3FragDroppedV4)];
    const std::uint64_t frag_skipped_v4 = worker_ctx.pkt_frag_l3[
        static_cast<std::size_t>(
            pktgate::dataplane::L3FragBucket::kL3FragSkippedV4)];
    // M5 C6: D40 v6 fragment counters (symmetric to v4 above).
    const std::uint64_t frag_dropped_v6 = worker_ctx.pkt_frag_l3[
        static_cast<std::size_t>(
            pktgate::dataplane::L3FragBucket::kL3FragDroppedV6)];
    const std::uint64_t frag_skipped_v6 = worker_ctx.pkt_frag_l3[
        static_cast<std::size_t>(
            pktgate::dataplane::L3FragBucket::kL3FragSkippedV6)];
    stats_json += "],\"counters\":{\"qinq_outer_only_total\":" +
                  std::to_string(worker_ctx.qinq_outer_only_total) +
                  ",\"pkt_frag_dropped_total_v4\":" +
                  std::to_string(frag_dropped_v4) +
                  ",\"pkt_frag_skipped_total_v4\":" +
                  std::to_string(frag_skipped_v4) +
                  ",\"pkt_frag_dropped_total_v6\":" +
                  std::to_string(frag_dropped_v6) +
                  ",\"pkt_frag_skipped_total_v6\":" +
                  std::to_string(frag_skipped_v6) +
                  ",\"l4_skipped_ipv6_extheader\":" +
                  std::to_string(worker_ctx.l4_skipped_ipv6_extheader) +
                  ",\"l4_skipped_ipv6_fragment_nonfirst\":" +
                  std::to_string(worker_ctx.l4_skipped_ipv6_fragment_nonfirst) +
                  // M5 C10: D31 L3 truncation counters (three buckets).
                  // Data lives on WorkerCtx.pkt_truncated_l3; wired here for
                  // F4 functional test observability.
                  ",\"pkt_truncated_l3_v4\":" +
                  std::to_string(worker_ctx.pkt_truncated_l3[
                      static_cast<std::size_t>(
                          pktgate::dataplane::L3TruncBucket::kL3V4)]) +
                  ",\"pkt_truncated_l3_v6\":" +
                  std::to_string(worker_ctx.pkt_truncated_l3[
                      static_cast<std::size_t>(
                          pktgate::dataplane::L3TruncBucket::kL3V6)]) +
                  ",\"pkt_truncated_l3_v6_frag_ext\":" +
                  std::to_string(worker_ctx.pkt_truncated_l3[
                      static_cast<std::size_t>(
                          pktgate::dataplane::L3TruncBucket::kL3V6FragExt)]) +
                  // M6 C5: D31 L4 truncation counter.
                  ",\"pkt_truncated_l4\":" +
                  std::to_string(worker_ctx.pkt_truncated_l4[
                      static_cast<std::size_t>(
                          pktgate::dataplane::L4TruncBucket::kL4)]) +
                  // M7 C0: D25 runtime backstop. Must stay 0 across
                  // the full suite (X2.9 simplified form).
                  ",\"dispatch_unreachable_total\":" +
                  std::to_string(worker_ctx.dispatch_unreachable_total) +
                  // M7 C3 (D33): surface the two remaining M7 counters
                  // for F3 action functional tests. `tag_pcp_noop_untagged_total`
                  // is bumped by apply_dscp_pcp when the TAG verb carries a
                  // non-zero pcp and the packet is untagged (D19 — do NOT
                  // insert a VLAN tag on the operator's behalf).
                  // `redirect_dropped_total` covers both the stage-full
                  // drop and the drain partial-send drop (D16).
                  ",\"tag_pcp_noop_untagged_total\":" +
                  std::to_string(worker_ctx.tag_pcp_noop_untagged_total) +
                  ",\"redirect_dropped_total\":" +
                  std::to_string(worker_ctx.redirect_dropped_total);

    // M8 C5 — reload counter family. The F5 functional tests assert
    // on these flat keys; later M10 replaces this with Prometheus.
    // All values are read under reload_mutex via counters_snapshot().
    const pktgate::ctl::reload::ReloadCounters rc =
        pktgate::ctl::reload::counters_snapshot();
    stats_json += ",\"reload_success_total\":" +
                  std::to_string(rc.success) +
                  ",\"reload_parse_error_total\":" +
                  std::to_string(rc.parse_error) +
                  ",\"reload_validate_error_total\":" +
                  std::to_string(rc.validate_error) +
                  ",\"reload_compile_error_total\":" +
                  std::to_string(rc.compile_error) +
                  ",\"reload_build_eal_error_total\":" +
                  std::to_string(rc.build_eal_error) +
                  ",\"reload_timeout_total\":" +
                  std::to_string(rc.timeout) +
                  ",\"reload_internal_error_total\":" +
                  std::to_string(rc.internal_error) +
                  ",\"reload_freed_total\":" +
                  std::to_string(rc.freed_total) +
                  ",\"reload_pending_depth\":" +
                  std::to_string(rc.pending_depth) +
                  ",\"reload_pending_full_total\":" +
                  std::to_string(rc.pending_full) +
                  ",\"reload_overflow_log_total\":" +
                  std::to_string(rc.overflow_log_total) +
                  ",\"reload_validate_budget_expansion_per_rule_total\":" +
                  std::to_string(rc.validate_budget_expansion_per_rule) +
                  ",\"reload_validate_budget_aggregate_total\":" +
                  std::to_string(rc.validate_budget_aggregate) +
                  ",\"reload_validate_budget_hugepage_total\":" +
                  std::to_string(rc.validate_budget_hugepage) +
                  ",\"reload_active_generation\":" +
                  std::to_string(rc.active_generation) +
                  // M9 C5 — aggregate across every live RL rule.
                  ",\"rl_dropped_total\":" +
                  std::to_string(rl_dropped_total);

    stats_json += "}";
    stats_json += rl_json;  // ",\"rl\":[...]"
    stats_json += "}";
    log_json(stats_json);
  }

  // Stop and close ports.
  for (auto port_id : port_ids) {
    pktgate::eal::port_stop(port_id);
  }
  log_json("{\"event\":\"ports_stopped\"}");

  // M8 C4 — D12: proper shutdown sequence.
  //
  // At this point rte_eal_mp_wait_lcore() has already joined every
  // worker (line 410), so workers have called rte_rcu_qsbr_thread_offline
  // + _thread_unregister for themselves. reload::shutdown() now does
  // a bounded rte_rcu_qsbr_synchronize against the process-wide QSBR
  // handle before deleting the currently-published ruleset. That sync
  // introduces a happens-before edge visible to TSAN between the
  // workers' last classify_l{2,3,4} reads and main's delete, closing
  // the M4-M7 baseline race.
  pktgate::ctl::reload::shutdown();
  log_json("{\"event\":\"ruleset_freed\"}");

  // Free the QSBR handle — after shutdown() returned, no code in the
  // process references it.
  std::free(qsbr_raw);

  // Free mempool.
  rte_mempool_free(mp);

  // EAL cleanup.
  rte_eal_cleanup();
  log_json("{\"event\":\"eal_cleanup\"}");

  return 0;
}
