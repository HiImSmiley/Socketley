#pragma once
#include <chrono>
#include <time.h>

// The CPU this thread has spent, so a bound on work holds on a machine busy with other work.
inline std::chrono::nanoseconds thread_cpu_now()
{
    timespec ts{};
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return std::chrono::seconds(ts.tv_sec) + std::chrono::nanoseconds(ts.tv_nsec);
}
