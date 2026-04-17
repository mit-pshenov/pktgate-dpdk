// tests/unit/test_inotify_debounce.cpp
//
// M11 C0 — debounce timer unit tests (Ud.1 / Ud.2 / Ud.X1 / Ud.X2 / Ud.X3).
//
// §9.3 spec: 150 ms debounce window. One trigger per quiescent window,
// reset on each incoming event. Clock is injected for deterministic
// unit tests; Ud.X3 exercises the default real-clock path.

#include "src/ctl/inotify/debounce.h"

#include <chrono>
#include <thread>

#include <gtest/gtest.h>

namespace {

using pktgate::ctl::inotify::Debouncer;
using TimePoint = Debouncer::TimePoint;

// Fake clock helper. Wraps a mutable `now` that tests step forward
// in explicit chunks.
struct MockClock {
  TimePoint now;

  TimePoint get() const { return now; }
};

// t0 is an arbitrary anchor. Using a fixed anchor rather than
// `steady_clock::now()` keeps the arithmetic test-readable.
TimePoint t0_anchor() {
  return TimePoint{std::chrono::milliseconds{1'000'000}};
}

constexpr auto kWindow = std::chrono::milliseconds{150};

}  // namespace

// Ud.1 — coalesce within window.
//   feed(t=0), feed(t=50), feed(t=100); poll(t=149) false; poll(t=250) true
//   once; poll(t=260) false (no re-fire without a new feed).
TEST(InotifyDebounce, Ud_1_CoalesceWithinWindow) {
  auto t0 = t0_anchor();
  MockClock clock{t0};
  Debouncer d{kWindow, [&clock]() { return clock.get(); }};

  d.feed(t0 + std::chrono::milliseconds{0});
  d.feed(t0 + std::chrono::milliseconds{50});
  d.feed(t0 + std::chrono::milliseconds{100});

  // 149 ms after the last feed (t=100) is still inside the 150 ms window.
  EXPECT_FALSE(d.poll(t0 + std::chrono::milliseconds{249}));

  // 150 ms after the last feed: window elapsed, fire exactly once.
  EXPECT_TRUE(d.poll(t0 + std::chrono::milliseconds{250}));

  // No new feed → subsequent polls stay false.
  EXPECT_FALSE(d.poll(t0 + std::chrono::milliseconds{260}));
  EXPECT_FALSE(d.poll(t0 + std::chrono::milliseconds{500}));
}

// Ud.2 — fires exactly once per quiescent window. After a successful
// poll(), the next fire requires a fresh feed().
TEST(InotifyDebounce, Ud_2_FiresOncePerQuiescentWindow) {
  auto t0 = t0_anchor();
  Debouncer d{kWindow, nullptr};

  // First burst + fire.
  d.feed(t0);
  EXPECT_TRUE(d.poll(t0 + std::chrono::milliseconds{200}));
  EXPECT_FALSE(d.poll(t0 + std::chrono::milliseconds{210}));

  // Second burst + fire.
  d.feed(t0 + std::chrono::milliseconds{300});
  EXPECT_TRUE(d.poll(t0 + std::chrono::milliseconds{500}));
  EXPECT_FALSE(d.poll(t0 + std::chrono::milliseconds{510}));
  EXPECT_FALSE(d.poll(t0 + std::chrono::milliseconds{700}));
}

// Ud.X1 — no feed ever → no fire. Polling an unfed debouncer must not
// false-positive on the zero-initialised last_feed_ timestamp.
TEST(InotifyDebounce, Ud_X1_NoFeedNoFire) {
  auto t0 = t0_anchor();
  Debouncer d{kWindow, nullptr};

  EXPECT_FALSE(d.poll(t0));
  EXPECT_FALSE(d.poll(t0 + std::chrono::milliseconds{500}));
  EXPECT_FALSE(d.poll(t0 + std::chrono::seconds{10}));
}

// Ud.X2 — rapid-fire reset. A steady stream of events keeps resetting
// the window; no fire happens during the burst, then exactly one fire
// 150 ms after the last event.
TEST(InotifyDebounce, Ud_X2_RapidFireReset) {
  auto t0 = t0_anchor();
  Debouncer d{kWindow, nullptr};

  // Feed every 30 ms for 600 ms (21 events total, t=0..t=600).
  TimePoint last_feed = t0;
  for (int i = 0; i <= 600; i += 30) {
    auto t_now = t0 + std::chrono::milliseconds{i};
    d.feed(t_now);
    last_feed = t_now;
    // Poll at the same instant — window hasn't elapsed since *this*
    // feed, so no fire.
    EXPECT_FALSE(d.poll(t_now))
        << "unexpected fire during burst at t=" << i << "ms";
  }

  // Still inside the window after the last feed.
  EXPECT_FALSE(d.poll(last_feed + std::chrono::milliseconds{149}));

  // Window elapsed: fire exactly once.
  EXPECT_TRUE(d.poll(last_feed + std::chrono::milliseconds{150}));
  EXPECT_FALSE(d.poll(last_feed + std::chrono::milliseconds{500}));
}

// Ud.X3 — default clock fallback. Construct with `now_fn = nullptr`
// and drive via real steady_clock. Sleeps briefly past the window;
// asserts the production code path is live.
TEST(InotifyDebounce, Ud_X3_DefaultClockFallback) {
  Debouncer d{std::chrono::milliseconds{50}, nullptr};

  d.feed();
  // Inside the 50 ms window: poll() should be false.
  EXPECT_FALSE(d.poll());

  // Sleep long past the window. 200 ms is generous on loaded CI.
  std::this_thread::sleep_for(std::chrono::milliseconds{200});

  EXPECT_TRUE(d.poll());
  EXPECT_FALSE(d.poll());  // one fire only per quiescent window
}
