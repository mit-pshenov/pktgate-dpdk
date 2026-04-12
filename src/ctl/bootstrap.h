// src/ctl/bootstrap.h
//
// M3 C1 — signal handler bootstrap.
//
// Installs SIGTERM + SIGINT handlers that flip a global atomic bool.
// Workers and control loop poll this flag to initiate orderly shutdown
// per design.md §6.4.

#pragma once

#include <atomic>

namespace pktgate::ctl {

// Global stop flag. Set by signal handler; polled by workers and
// control thread. Declared here (extern), defined in bootstrap.cpp.
extern std::atomic<bool> g_running;

// Install signal handlers for SIGTERM and SIGINT. Must be called
// AFTER rte_eal_init() because EAL may install its own handlers.
void install_signal_handlers();

}  // namespace pktgate::ctl
