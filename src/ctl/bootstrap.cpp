// src/ctl/bootstrap.cpp
//
// M3 C1 — signal handler bootstrap.

#include "src/ctl/bootstrap.h"

#include <csignal>

namespace pktgate::ctl {

std::atomic<bool> g_running{false};

namespace {

void signal_handler(int /*sig*/) {
  // Signal-safe: atomic store with relaxed is safe from a signal
  // context. Workers and control loop use acquire loads.
  g_running.store(false, std::memory_order_relaxed);
}

}  // namespace

void install_signal_handlers() {
  g_running.store(true, std::memory_order_release);

  struct sigaction sa{};
  sa.sa_handler = signal_handler;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);

  sigaction(SIGTERM, &sa, nullptr);
  sigaction(SIGINT, &sa, nullptr);
}

}  // namespace pktgate::ctl
