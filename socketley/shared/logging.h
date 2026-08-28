#pragma once
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <chrono>
#include <mutex>

enum log_level : uint8_t
{
    log_debug = 0,
    log_info  = 1,
    log_warn  = 2,
    log_error = 3
};

// The config file's spelling, both directions -- shared so the daemon and a
// worker cannot disagree about what "warn" means.
inline bool log_level_from_string(const char* s, log_level& out)
{
    if (!s)                          return false;
    if (std::strcmp(s, "debug") == 0) { out = log_debug; return true; }
    if (std::strcmp(s, "info")  == 0) { out = log_info;  return true; }
    if (std::strcmp(s, "warn")  == 0) { out = log_warn;  return true; }
    if (std::strcmp(s, "error") == 0) { out = log_error; return true; }
    return false;
}

inline const char* log_level_name(log_level l)
{
    switch (l)
    {
        case log_debug: return "debug";
        case log_info:  return "info";
        case log_warn:  return "warn";
        case log_error: return "error";
    }
    return "info";
}

// The level travels in the environment because that is the one channel already
// inherited across the fork and readable after the exec, before the worker's
// first frame arrives.
inline constexpr const char* log_level_env = "SOCKETLEY_LOG_LEVEL";

inline void export_log_level(log_level l)
{
    ::setenv(log_level_env, log_level_name(l), 1);
}

inline void inherit_log_level();   // defined below the logger it writes into

struct logger
{
    static inline log_level g_level = log_info;

    static void log(log_level level, const char* msg)
    {
        if (level < g_level)
            return;

        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
        localtime_r(&t, &tm);

        const char* tag;
        switch (level)
        {
            case log_debug: tag = "DEBUG"; break;
            case log_info:  tag = "INFO";  break;
            case log_warn:  tag = "WARN";  break;
            case log_error: tag = "ERROR"; break;
            default:        tag = "?";     break;
        }

        static std::mutex mtx;
        std::lock_guard<std::mutex> lock(mtx);
        std::fprintf(stderr, "[%02d:%02d:%02d] [%s] %s\n",
            tm.tm_hour, tm.tm_min, tm.tm_sec, tag, msg);
    }
};

// Take the level the parent exported, or leave the default alone.
inline void inherit_log_level()
{
    log_level l;
    if (log_level_from_string(std::getenv(log_level_env), l))
        logger::g_level = l;
}

#define LOG_DEBUG(msg) do { if (logger::g_level <= log_debug) logger::log(log_debug, msg); } while(0)
#define LOG_INFO(msg)  do { if (logger::g_level <= log_info)  logger::log(log_info,  msg); } while(0)
#define LOG_WARN(msg)  do { if (logger::g_level <= log_warn)  logger::log(log_warn,  msg); } while(0)
#define LOG_ERROR(msg) do { if (logger::g_level <= log_error) logger::log(log_error, msg); } while(0)
