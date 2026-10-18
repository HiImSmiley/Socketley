#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>

#include <sys/types.h>

namespace socketley
{

// The fields of /proc/<pid>/stat a supervisor reads: the state letter, the CPU ticks and the resident pages.
struct proc_stat
{
    char     state{0};
    uint64_t utime{0};
    uint64_t stime{0};
    int64_t  rss_pages{0};
};

// False when the process is gone or its line does not parse, and `out` is then untouched.
inline bool read_proc_stat(pid_t pid, proc_stat& out)
{
    char path[48];
    std::snprintf(path, sizeof path, "/proc/%d/stat", static_cast<int>(pid));
    FILE* f = std::fopen(path, "re");
    if (!f)
        return false;
    // The fields read end long before this, past a command name of 16 bytes at most.
    char buf[1024];
    const size_t n = std::fread(buf, 1, sizeof buf - 1, f);
    std::fclose(f);
    buf[n] = '\0';
    // The command name may hold spaces and parentheses, so the fields are counted from its last closing parenthesis.
    const char* p = std::strrchr(buf, ')');
    if (!p)
        return false;
    char state = 0;
    unsigned long long utime = 0, stime = 0;
    long long rss = 0;
    if (std::sscanf(p + 1, " %c %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %llu %llu %*s %*s %*s %*s %*s %*s %*s %*s %lld",
                    &state, &utime, &stime, &rss) != 4)
        return false;
    out = proc_stat{state, utime, stime, rss};
    return true;
}

} // namespace socketley
