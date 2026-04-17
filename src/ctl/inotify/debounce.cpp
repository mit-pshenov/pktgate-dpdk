// src/ctl/inotify/debounce.cpp
//
// M11 C0 — Debouncer implementation. See debounce.h for the contract.

#include "src/ctl/inotify/debounce.h"

#include <chrono>

namespace pktgate::ctl::inotify {

namespace {

Debouncer::TimePoint real_steady_now() {
  return Debouncer::Clock::now();
}

}  // namespace

Debouncer::Debouncer(Duration window, NowFn now_fn)
    : window_(window),
      now_fn_(now_fn ? std::move(now_fn) : NowFn{&real_steady_now}) {}

void Debouncer::feed(TimePoint t) {
  last_feed_ = t;
  pending_   = true;
}

void Debouncer::feed() {
  feed(now_fn_());
}

bool Debouncer::poll(TimePoint now) {
  if (!pending_) {
    return false;
  }
  if (now - last_feed_ < window_) {
    return false;
  }
  pending_ = false;
  return true;
}

bool Debouncer::poll() {
  return poll(now_fn_());
}

}  // namespace pktgate::ctl::inotify
