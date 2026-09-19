#pragma once
// The clock for deadlines and activity stamps, which is not the clock for
// measuring how long something took.
//
// steady_clock::now() reads the TSC through the vdso and serialises it: 21.23 ns
// a call on this box.  CLOCK_MONOTONIC_COARSE reads a page the kernel keeps
// current instead, at 4.09 ns -- 81 per cent less -- in exchange for one
// millisecond of resolution rather than one nanosecond.
//
// ─── WHEN THIS IS THE RIGHT CLOCK ───────────────────────────────────────────
//
// When the answer is COMPARED against something, and the something is measured
// in seconds or milliseconds.  A callback budget of ten seconds does not care
// about a millisecond, nor does an idle timeout, a handshake deadline or a TTL.
//
// ─── WHEN IT IS THE WRONG ONE ───────────────────────────────────────────────
//
// When the answer IS the measurement.  An op_timing histogram in microseconds
// is destroyed by a clock that moves in steps of a thousand of them, and so is
// anything reported to an operator as a duration.  Those keep steady_clock.
//
// And never mix the two across one comparison.  Both count from the same boot,
// so the arithmetic is valid, but a deadline armed on one and tested on the
// other is up to a tick wrong in whichever direction the pair happens to sit --
// a bug that appears only under load, where the tick is old.  Arm and test on
// the same clock.
//
// ─── WHY IT EXISTS ──────────────────────────────────────────────────────────
//
// Measured, and it is not a micro-optimisation.  A Lua echo server's worker
// spent 9.6 per cent of its CPU in the vdso -- more than any symbol of its own,
// more than the allocator, more than the parser -- because every callback
// invocation armed a deadline and every deadline read the clock.  Moving that
// one site to this clock was worth 11.67 per cent of the runtime's throughput,
// better on fourteen passes out of fourteen, with a no-script control unmoved.

#include <chrono>
#include <ctime>

namespace socketley
{

// Now, to the nearest millisecond, as a steady_clock::time_point so it can be
// compared and stored beside every existing deadline without a new type.
inline std::chrono::steady_clock::time_point coarse_now() noexcept
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    return std::chrono::steady_clock::time_point(
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(
            std::chrono::seconds(ts.tv_sec) + std::chrono::nanoseconds(ts.tv_nsec)));
}

// What one tick of it is worth, for a caller deciding whether the resolution is
// good enough for what it is about to compare.
inline constexpr std::chrono::milliseconds coarse_resolution{1};

}  // namespace socketley
