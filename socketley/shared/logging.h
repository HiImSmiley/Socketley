#pragma once
#include <cstdio>
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

#define LOG_DEBUG(msg) do { if (logger::g_level <= log_debug) logger::log(log_debug, msg); } while(0)
#define LOG_INFO(msg)  do { if (logger::g_level <= log_info)  logger::log(log_info,  msg); } while(0)
#define LOG_WARN(msg)  do { if (logger::g_level <= log_warn)  logger::log(log_warn,  msg); } while(0)
#define LOG_ERROR(msg) do { if (logger::g_level <= log_error) logger::log(log_error, msg); } while(0)
