# src/telemetry/CMakeLists.txt
#
# M10 C0 — DPDK-free control-plane telemetry library.
#
# `pktgate_telemetry` hosts the Prometheus OpenMetrics encoder (C0),
# the snapshot ring (C1), the snapshot publisher (C1), and the HTTP
# `/metrics` endpoint (C3). Everything here is control-plane — the
# hot path (classify_l{2,3,4}, action_dispatch) never links against
# this library; see memory grabli_m4c0_dpdk_free_core_library.md.
#
# STL containers (std::string, std::vector, std::unordered_map) are
# fine here — control-plane runs on its own thread(s). The only
# hard rule: NO `#include <rte_*>` in this lib in C0. When C1 needs
# `rte_eth_stats`, introduce a thin DPDK-aware bridge TU in
# `src/telemetry/<bridge>.cpp` and link it separately; keep the
# encoder / snapshot / ring TUs DPDK-free so unit tests run without
# EAL (same split as pktgate_rl vs pktgate_rl_ctl).

add_library(pktgate_telemetry STATIC
  prom_encoder.cpp
  # M10 C1 — snapshot aggregation + single-writer/multi-reader ring.
  # Pure C++; pulls in ruleset.h (DPDK-free header, forward-declares
  # rte_hash / rte_fib). No DPDK symbols leak into this archive; the
  # publisher adapter that calls `rte_eth_stats_get` will live in a
  # separate DPDK-aware TU when the publisher thread wires into
  # main.cpp (C3). In C1 the unit tests exercise build_snapshot with
  # fake PortStats injected via span — zero DPDK.
  snapshot.cpp
)
target_include_directories(pktgate_telemetry PUBLIC ${CMAKE_SOURCE_DIR})
# M10 C1 — snapshot.h uses RuleCounter from src/ruleset/ruleset.h; the
# header also transitively includes src/action/action.h +
# src/compiler/compiler.h. These are DPDK-free cores of libpktgate_core;
# link it here for the header chain, NOT because we need any DPDK
# surface (D1 + grabli_m4c0_dpdk_free_core_library.md).
target_link_libraries(pktgate_telemetry PUBLIC pktgate_core)
pktgate_apply_warnings(pktgate_telemetry)
pktgate_apply_sanitizer(pktgate_telemetry)
