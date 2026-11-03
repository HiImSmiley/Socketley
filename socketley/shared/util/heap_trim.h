#pragma once
// The heap a burst freed handed back to the kernel, at most once a minute and only where enough of it lies idle, as
// glibc keeps freed memory below the top of its arenas for the process that freed it.
#include <chrono>
#include <cstddef>
#include <malloc.h>

namespace heap_trim
{

inline constexpr size_t idle_floor = 4u << 20;

inline void tick(std::chrono::steady_clock::time_point now)
{
    static std::chrono::steady_clock::time_point next{};
    if (now < next)
        return;
    next = now + std::chrono::seconds(60);
#if defined(__GLIBC__)
    if (mallinfo2().fordblks >= idle_floor)
        malloc_trim(0);
#endif
}

}   // namespace heap_trim
