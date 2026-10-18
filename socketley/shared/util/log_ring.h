#pragma once
// The daemon's recent log, for the dashboard: the lines the daemon writes itself and every line its workers write
// to stderr, each worker through a pipe of its own so a line names the runtime that wrote it even when the line
// does not. One thread reads the pipes, passes each line on to the daemon's stderr unchanged -- the journal still
// gets everything -- and keeps the last `capacity` lines in memory. A worker started before or without it writes
// to the daemon's stderr as before.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace log_ring
{

inline constexpr size_t capacity = 10000;

struct entry
{
    uint64_t seq{0};
    int64_t at_ms{0};
    // The runtime whose worker wrote it, empty for the daemon's own.
    std::string runtime;
    // debug, info, warn or error, read off the line's tag; a line without one is info.
    std::string level;
    std::string text;
};

// Starts the reader; from then on the daemon's own lines are kept too. Once, in the daemon.
void start();
// Passes on what is still in the pipes; at the daemon's exit, so a worker's last words reach its stderr.
void drain();

// A pipe a worker started now for `runtime` writes its stderr into: the write end to place on fd 2 in the child,
// -1 when there is no reader. The read end is the reader's from here; the caller closes the write end after the
// fork.
int worker_pipe(std::string_view runtime);

// A line the daemon wrote itself, as the logger formats it.
void add_own(std::string_view line);

// The lines after `seq`, at most `max`, of `runtime` (its workers' and the daemon's that name it) or of all, at
// `level` or above; `next` is the sequence to ask after next time.
std::vector<entry> since(uint64_t seq, size_t max, std::string_view runtime, std::string_view level, uint64_t& next);

}   // namespace log_ring
