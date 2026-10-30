#pragma once
// The time a loop turn began dispatching, read once per turn by the event loop, so a duration that spans turns costs
// a subtraction and not a clock read.
//
// A duration measured on it is in turns: work begun and ended inside one dispatch reads 0, and the end of a span is
// the start of the turn that ends it.  CLOCK_MONOTONIC, the clock steady_clock reads, so a stamp taken here compares
// with a steady_clock::time_point's count.
#include <chrono>
#include <cstdint>
#include <ctime>

namespace socketley::turn_clock
{

// Per thread, because the daemon and a worker's helper threads may each drive a loop of their own.
inline thread_local uint64_t t_turn_ns = 0;

inline uint64_t read_ns() noexcept
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<uint64_t>(ts.tv_nsec);
}

// Called by the loop just before a turn's completions are dispatched.
inline uint64_t stamp() noexcept
{
    return t_turn_ns = read_ns();
}

// The current turn's start, 0 on a thread whose loop has not turned yet.
inline uint64_t now_ns() noexcept
{
    return t_turn_ns;
}

// The current turn's start as the steady_clock time the worker paces itself by.
inline std::chrono::steady_clock::time_point now() noexcept
{
    return std::chrono::steady_clock::time_point(
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::nanoseconds(t_turn_ns)));
}

}   // namespace socketley::turn_clock
