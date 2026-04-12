// src/main.cpp
//
// M3 C1 — full binary boot: config parse → validate → compile →
// EAL init → port config → mempool → start ports → publish Ruleset →
// worker launch → SIGTERM → shutdown.
//
// Design anchors: §6.1 (init sequence), §6.4 (shutdown),
// D9 (g_active scaffold), D23 (NUMA-aware mempool).

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include "src/compiler/compiler.h"
#include "src/compiler/object_compiler.h"
#include "src/config/parser.h"
#include "src/config/sizing.h"
#include "src/config/validator.h"
#include "src/ctl/bootstrap.h"
#include "src/dataplane/worker.h"
#include "src/eal/dynfield.h"
#include "src/eal/port_init.h"
#include "src/ruleset/builder.h"
#include "src/ruleset/ruleset.h"

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

// D9 scaffold: global active ruleset pointer. Real QSBR arrives in M8.
std::atomic<pktgate::ruleset::Ruleset*> g_active{nullptr};

}  // namespace

int main(int argc, char* argv[]) {
  // ---- Phase 1: find --config in argv (before EAL consumes args) ----
  //
  // EAL's rte_eal_init() consumes argc/argv and rewrites them. We need
  // to extract --config before that happens. Everything after -- is
  // passed to EAL.
  std::string config_path;
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
  auto compile_result = pktgate::compiler::compile(cfg);
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
      if (port_ids.size() >= 2) break;
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
  auto ruleset = std::make_unique<pktgate::ruleset::Ruleset>(
      pktgate::ruleset::build_ruleset(compile_result, cfg.sizing, n_workers));
  log_json(("{\"event\":\"ruleset_published\",\"generation\":" +
            std::to_string(ruleset->generation) + "}").c_str());

  // D9 scaffold: publish ruleset via atomic store.
  g_active.store(ruleset.get(), std::memory_order_release);

  // ---- Phase 7: launch worker(s) ----
  //
  // M3: single worker on the first available worker lcore.
  pktgate::dataplane::WorkerCtx worker_ctx{};
  worker_ctx.port_id = port_ids[0];
  worker_ctx.queue_id = 0;
  worker_ctx.running = &pktgate::ctl::g_running;

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
    rte_eal_mp_wait_lcore();
  }

  // Stop and close ports.
  for (auto port_id : port_ids) {
    pktgate::eal::port_stop(port_id);
  }
  log_json("{\"event\":\"ports_stopped\"}");

  // Free ruleset.
  g_active.store(nullptr, std::memory_order_release);
  ruleset.reset();
  log_json("{\"event\":\"ruleset_freed\"}");

  // Free mempool.
  rte_mempool_free(mp);

  // EAL cleanup.
  rte_eal_cleanup();
  log_json("{\"event\":\"eal_cleanup\"}");

  return 0;
}
