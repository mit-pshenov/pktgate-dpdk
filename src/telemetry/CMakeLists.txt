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
)
target_include_directories(pktgate_telemetry PUBLIC ${CMAKE_SOURCE_DIR})
pktgate_apply_warnings(pktgate_telemetry)
pktgate_apply_sanitizer(pktgate_telemetry)
