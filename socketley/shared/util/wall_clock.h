#pragma once

#include <chrono>
#include <cstdint>
#include <ctime>

// The Unix time, which is what a stamp a file, a peer or a client keeps must be counted in; an interval is not.
namespace socketley::wall
{

inline int64_t now_sec()
{
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

inline int64_t now_ms()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// What the kernel last ticked, a read without a syscall for a path that counts whole seconds per request.
inline int64_t now_sec_coarse()
{
    timespec ts{};
    ::clock_gettime(CLOCK_REALTIME_COARSE, &ts);
    return static_cast<int64_t>(ts.tv_sec);
}

// The same in milliseconds, a few of them behind, for what is counted in seconds and asked per packet.
inline int64_t now_ms_coarse()
{
    timespec ts{};
    ::clock_gettime(CLOCK_REALTIME_COARSE, &ts);
    return static_cast<int64_t>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

} // namespace socketley::wall
