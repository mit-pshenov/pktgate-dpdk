// src/ctl/inotify/debounce.h
//
// M11 C0 — debounce timer for inotify event bursts (§9.3, D38).
//
// Kernel inotify bursts dramatically: a single editor save on a
// directory watch can emit 3-8 events (CREATE tmp, CLOSE_WRITE tmp,
// MOVED_FROM tmp, MOVED_TO config, ...). Even after event_filter.h
// drops the irrelevant kinds, `cp; mv; cp; mv` patterns deliver
// multiple accepted events within a few milliseconds. We want ONE
// deploy() per quiescent window, not N.
//
// §9.3 latency budget: 150 ms debounce window. That's long enough to
// coalesce a saved-in-editor + re-save (common case when the operator
// re-saves a typo'd value) and short enough that the user-perceived
// reload latency stays well under the 250 ms target.
//
// Mechanics: the caller `feed()`s the debouncer when an accepted event
// arrives. `poll(now)` returns true exactly once when `now - last_feed
// >= window` AND at least one feed() has happened since the previous
// successful poll(). Further poll()s return false until the next
// feed() arrives — no double-fire.
//
// Clock is injected via a `std::function<TimePoint()>` callback so
// unit tests can drive the timer with explicit time points (Ud.1, Ud.2,
// Ud.X1, Ud.X2). The default (nullptr `now_fn`) falls back to
// `std::chrono::steady_clock::now()` for production.

#pragma once

#include <chrono>
#include <functional>

namespace pktgate::ctl::inotify {

class Debouncer {
 public:
  using Clock     = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;
  using Duration  = std::chrono::milliseconds;
  using NowFn     = std::function<TimePoint()>;

  // `window` defaults to §9.3 (150 ms). `now_fn` defaults to
  // real-clock steady_clock::now().
  explicit Debouncer(Duration window = std::chrono::milliseconds(150),
                     NowFn now_fn = nullptr);

  // Called when an accepted inotify event arrives. Resets the window.
  void feed(TimePoint t);

  // Convenience overload — samples the injected clock.
  void feed();

  // Returns true exactly once per quiescent window. The caller then
  // performs the reload action (read config, call deploy()).
  bool poll(TimePoint now);
  bool poll();

 private:
  Duration  window_;
  NowFn     now_fn_;
  bool      pending_   = false;
  TimePoint last_feed_{};
};

}  // namespace pktgate::ctl::inotify
