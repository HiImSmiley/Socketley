#pragma once
// Opt-in connection accounting under -DSOCKETLEY_TRACE, which makes silent
// loss visible: a connection that reads N commands must produce and write N
// responses.

#ifdef SOCKETLEY_TRACE

#include <cstdio>
#include <cstdint>
#include <chrono>

namespace skl_trace {

inline double now_ms()
{
    using namespace std::chrono;
    return duration<double, std::milli>(steady_clock::now().time_since_epoch()).count();
}

// Per-connection accounting, on the connection struct so the numbers travel
// with it and can be reported at close.
struct conn_stats
{
    uint64_t bytes_read{0};
    uint64_t commands_parsed{0};
    uint64_t responses_made{0};   // responses appended to the response buffer
    uint64_t bytes_queued{0};     // response bytes handed to the write path
    uint64_t bytes_written{0};    // response bytes the kernel confirmed
    uint32_t reads{0};
    uint32_t writes{0};
    uint32_t enobufs{0};          // provided-buffer pool ran dry
    uint32_t multishot_ends{0};   // multishot recv had to be re-armed
    double   opened_ms{0.0};

    // Why the connection ended, since a teardown with no reason here was
    // decided somewhere other than the read path.
    int      last_read_res{1};    // 1 = no read completion has failed yet
    unsigned last_read_flags{0};

    // What the kernel moved and what the last splice completion said, because
    // a spliced connection leaves the read/write counters above at zero.
    uint64_t spliced{0};
    // The conservation law: what a connection takes into the pipe must come
    // out onto the peer's socket, and whichever counter fell short names the
    // hop.
    uint64_t sp_in{0};    // socket -> pipe   (leg 1 on a client, leg 3 on a backend)
    uint64_t sp_out{0};   // pipe   -> socket (leg 2 on a client, leg 4 on a backend)
    int      last_splice_res{1};
    unsigned splice_leg{0};       // 1=c->pipe 2=pipe->be 3=be->pipe 4=pipe->c
    // When a splice on this connection last completed, which is what tells a
    // pipeline waiting on a peer from one nobody armed.
    double   splice_cqe_ms{0.0};
};

} // namespace skl_trace

#define SKL_TRACE_FIELD(name) ::skl_trace::conn_stats name;
#define SKL_TRACE_ADD(conn, field, n) ((conn)->tr.field += (n))
#define SKL_TRACE_SET(conn, field, v) ((conn)->tr.field = (v))
// Pooled connections are reused, so the counters have to start over with
// each one or every report is a running total of the pool slot.
#define SKL_TRACE_RESET(obj) ((obj).tr = ::skl_trace::conn_stats{})

#define SKL_TRACE_LOG(...)                                                     \
    do {                                                                       \
        std::fprintf(stderr, "[trace %.3f] ", ::skl_trace::now_ms());          \
        std::fprintf(stderr, __VA_ARGS__);                                     \
        std::fputc('\n', stderr);                                              \
    } while (0)

// Emitted for every teardown, where "owed" is responses produced but never
// confirmed written.
#define SKL_TRACE_CLOSE(conn, fd, reason)                                       \
    do {                                                                        \
        SKL_TRACE_LOG("close fd=%d reason=%s lifetime=%.1fms "                  \
                      "read=%llu cmds=%llu resp=%llu queued=%llu written=%llu " \
                      "owed=%lld reads=%u writes=%u enobufs=%u msend=%u "                  \
                      "partial_left=%zu respbuf_left=%zu wq_left=%zu",          \
            (fd), (reason), ::skl_trace::now_ms() - (conn)->tr.opened_ms,       \
            (unsigned long long)(conn)->tr.bytes_read,                          \
            (unsigned long long)(conn)->tr.commands_parsed,                     \
            (unsigned long long)(conn)->tr.responses_made,                      \
            (unsigned long long)(conn)->tr.bytes_queued,                        \
            (unsigned long long)(conn)->tr.bytes_written,                       \
            (long long)((conn)->tr.bytes_queued - (conn)->tr.bytes_written),    \
            (conn)->tr.reads, (conn)->tr.writes, (conn)->tr.enobufs,          \
            (conn)->tr.multishot_ends,       \
            (conn)->partial.size(), (conn)->response_buf.size(),                \
            (conn)->write_queue.size());                                        \
    } while (0)

#else   // !SOCKETLEY_TRACE

#define SKL_TRACE_FIELD(name)
#define SKL_TRACE_ADD(conn, field, n) ((void)0)
#define SKL_TRACE_SET(conn, field, v) ((void)0)
#define SKL_TRACE_RESET(obj)          ((void)0)
#define SKL_TRACE_LOG(...)            ((void)0)
#define SKL_TRACE_CLOSE(conn, fd, reason) ((void)0)

#endif  // SOCKETLEY_TRACE
