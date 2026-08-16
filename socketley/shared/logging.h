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

// The spelling used in the daemon's config file, in both directions.
//
// It lived in daemon.cpp as a private helper while the daemon was the only
// process with a level to set.  A worker is a second one — see
// inherit_log_level() below — and the one thing worse than a worker that cannot
// be asked for debug output is two tables of names that disagree about what
// "warn" means.
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

// ── A worker logs at the level its daemon does ──────────────────────────────
//
// It did not, and could not.  A worker is a fork+exec of the daemon that reads
// no configuration file of its own, so logger::g_level was `info` in every
// worker that has ever run — which means every LOG_DEBUG in the worker, in the
// runtimes it holds, and in the event loop underneath them has been dead code
// since runtimes started living out there.  Turning debug logging on in the
// daemon's config produced debug output for the runtimes that stayed behind and
// silence from the ones that moved, with nothing saying so.
//
// The level travels in the environment because that is the one channel that is
// already inherited across the fork and read after the exec: the control socket
// is not open yet at the moment this has to be known — the worker logs before
// its first frame arrives — and putting it in argv would mean a parser in the
// one place this file's own comment says has nothing to parse.
//
// export_log_level() is called by whoever decided the level, in the parent, at
// startup: a setenv() between the fork and the exec would be an allocation in a
// child that must not allocate.
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

// Take the level the parent exported, or leave the default alone.  Called once,
// at the top of a child process's main, before anything it might want to say.
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
