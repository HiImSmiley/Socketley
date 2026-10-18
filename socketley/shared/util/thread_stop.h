#pragma once

#include <condition_variable>
#include <mutex>
#include <thread>

namespace socketley
{

// The flag is set under the thread's lock, so the wake cannot fall between its check and its wait.
inline void stop_and_join(std::thread& t, std::mutex& mx, std::condition_variable& cv, bool& stop)
{
    if (!t.joinable())
        return;
    {
        std::lock_guard lk(mx);
        stop = true;
    }
    cv.notify_all();
    t.join();
}

}   // namespace socketley
