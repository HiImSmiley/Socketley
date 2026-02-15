#pragma once
#include <string>
#include <chrono>
#include <cmath>

inline std::string format_duration(std::chrono::seconds duration)
{
    auto secs = duration.count();

    if (secs < 60)
        return std::to_string(secs) + " second" + (secs == 1 ? "" : "s");

    auto mins = secs / 60;
    if (mins < 60)
        return std::to_string(mins) + " minute" + (mins == 1 ? "" : "s");

    auto hours = mins / 60;
    if (hours < 24)
        return std::to_string(hours) + " hour" + (hours == 1 ? "" : "s");

    auto days = hours / 24;
    return std::to_string(days) + " day" + (days == 1 ? "" : "s");
}

inline std::string format_time_ago(std::chrono::system_clock::time_point tp)
{
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - tp);
    return format_duration(duration) + " ago";
}

inline std::string format_uptime(std::chrono::system_clock::time_point start_time)
{
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - start_time);
    return "Up " + format_duration(duration);
}
