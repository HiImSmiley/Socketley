#pragma once
// The heap a burst freed handed back to the kernel, at most once a minute and only where enough of it lies idle, as
// glibc keeps freed memory below the top of its arenas for the process that freed it.
#include <atomic>
#include <chrono>
#include <cstddef>
#include <malloc.h>
#include <system_error>
#include <thread>

namespace heap_trim
{

inline constexpr size_t idle_floor = 4u << 20;

inline void tick(std::chrono::steady_clock::time_point now)
{
    static std::chrono::steady_clock::time_point next{};
    static std::atomic<bool> busy{false};
    if (now < next)
        return;
    next = now + std::chrono::seconds(60);
#if defined(__GLIBC__)
    // Both calls walk every free chunk, tens of milliseconds after a burst of small frees, so a thread of its own
    // walks them while the loop answers from its thread cache.
    if (busy.exchange(true, std::memory_order_acq_rel))
        return;
    try
    {
        std::thread([] {
            if (mallinfo2().fordblks >= idle_floor)
                malloc_trim(0);
            busy.store(false, std::memory_order_release);
        }).detach();
    }
    catch (const std::system_error&)
    {
        busy.store(false, std::memory_order_release);
    }
#endif
}

}   // namespace heap_trim
