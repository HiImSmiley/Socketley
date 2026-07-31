#pragma once
// Shared oracle for the two fuzz targets that drive a *live runtime* against a
// real io_uring loop as a sequence of lifecycle and connection operations:
// test/fuzz/fuzz_server_ops.cpp and test/fuzz/fuzz_client_ops.cpp.
//
// ─── WHY THESE TARGETS ARE NOT BYTE FUZZERS ─────────────────────────────────
//
// The parser targets next door (fuzz_resp, fuzz_ws_frame, fuzz_http_request,
// fuzz_http_response) throw bytes at a function.  That is the right tool for a
// parser and it found a remote crash on its first run.  It cannot reach the
// defects the server and the client actually have, because those do not live in
// the content of a packet — they live in the *order* of operations:
//
//   * a completion dispatched into an instance that had already been torn down;
//   * an arm with no disarm, so the loop went on owing an owner a completion for
//     thirty seconds and the instance was never freed;
//   * a descriptor closed while an SQE naming its number was still queued, so
//     the next accept took the number and the queued read landed on a stranger;
//   * a connection struct pushed back to its pool with a read still armed on its
//     buffer, handed straight to the next client.
//
// Every one of those needs a *history* — start, connect, send, abort, stop,
// start again, in an order nobody tried — and none is a function of any byte on
// any socket.  So the input decodes to a program of typed operations, the
// program runs against a real event_loop and a real runtime, and the invariants
// below are checked after every single step.
//
// ─── THE FOUR INVARIANTS ────────────────────────────────────────────────────
//
//  1. NO COMPLETION OUTLIVES ITS OWNER.  An instance is destroyed only once
//     event_loop::owner_inflight() says the ring owes it nothing.  If that count
//     will not reach zero within the drain budget — a short one first, then a
//     hard bound no scheduling delay can explain, because a slow completion and
//     an absent one are different claims — the breakdown says which operation
//     kind is holding it and that is the finding.  It is precisely the shape of
//     the un-withdrawn timer that used to keep 6 MB per removed runtime
//     resident until the daemon exited.  Once an instance *is* destroyed the
//     harness keeps pumping: a completion that arrives for freed storage is read
//     by the loop before anything is dispatched, so ASan reports it.
//
//  2. EVERY ARM HAS ITS DISARM.  Once the runtime has stopped and drained, both
//     the per-owner count and the per-operation-kind breakdown must be zero, and
//     so must event_loop::fd_inflight() for every descriptor number the process
//     can be handed.  Per connection: when a client goes away, the count on its
//     descriptor goes to zero.
//
//  3. NO DESCRIPTOR IS NAMED IN A QUEUED SQE AFTER IT WAS CLOSED.  This one is
//     checked from the outside, which is the only place it is visible: every
//     time the *harness* is handed a fresh descriptor by socket() or accept(),
//     it asks the loop whether anything in the ring still names that number.  A
//     non-zero answer means the number was released while an SQE carried it and
//     the kernel has just given it to us — the redirect hazard itself, caught at
//     the moment it happens rather than inferred from corrupted traffic.
//
//  4. NO STRUCT GOES BACK TO A POOL WITH ANYTHING ARMED.  socketley/shared/
//     invariants.h already states this and the runtimes already call it; these
//     targets are built with SOCKETLEY_INVARIANTS so those calls are live.  The
//     harness also walks the pool itself after every step, because the in-tree
//     check fires at the moment of the push and the walk catches a struct that
//     became unsafe afterwards.
//
// ─── TRIAGE ─────────────────────────────────────────────────────────────────
//
// On a violation the raw bytes say nothing, so the report prints the decoded
// operation sequence.  <TARGET>_SKIP=id1,id2 demotes named findings to a printed
// observation so a run can continue past a known one and look for the next; the
// ids are the first argument of each RT_FINDING.  Nothing is skipped unless the
// variable names it, so CI still fails on the first one.

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include "fuzz_common.h"
#include "shared/event_loop.h"
#include "shared/event_loop_definitions.h"

namespace fuzzrt {

// ─────────────────────────── findings and triage ────────────────────────────

// Set once by the target: the environment variable its findings are suppressed
// through, and the hook that prints the decoded program on a failure.
inline const char*& skip_env()
{
    static const char* v = "";
    return v;
}
inline void (*&print_program_hook())()
{
    static void (*fn)() = nullptr;
    return fn;
}

inline bool finding_suppressed(const char* id)
{
    static const char* const env = [] {
        const char* e = std::getenv(skip_env());
        return (e && *e) ? e : nullptr;
    }();
    if (!env)
        return false;
    const size_t n = std::strlen(id);
    for (const char* p = env; *p; )
    {
        const char* e   = std::strchr(p, ',');
        const char* end = e ? e : p + std::strlen(p);
        // Trim: a YAML folded scalar in a workflow file joins its lines with a
        // space, so an id can arrive with whitespace glued to the front of it.
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n')) p++;
        while (end > p && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\n')) end--;
        if (static_cast<size_t>(end - p) == n && std::strncmp(p, id, n) == 0)
            return true;
        if (!e)
            break;
        p = e + 1;
    }
    return false;
}

// Allocation-free on purpose, like its counterpart in fuzz_cache_ops: libFuzzer
// runs a full LeakSanitizer scan for every input whose malloc and free counts
// disagree, and a harness that grows a buffer as it goes triggers that scan over
// and over.  Ids are string literals, so pointer identity is enough.
inline void observe_once(const char* id, const char* what)
{
    static const char* ids[24] = {nullptr};
    static int         hits[24] = {0};
    for (int i = 0; i < 24; i++)
    {
        if (ids[i] == nullptr)
            ids[i] = id;
        if (ids[i] == id)
        {
            if (hits[i]++ < 3)
                std::fprintf(stderr, "[fuzz-rt] suppressed finding '%s': %s\n", id, what);
            return;
        }
    }
}

// Numbers a violated check wants to show.  "The owner never drained" is a
// claim; "1 operation still owed, kind=timeout, 41 ms after the stop" is a
// diagnosis.  Filled in by the check about to run and cleared afterwards.
inline char g_detail[768] = {0};

inline void set_detail(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
inline void set_detail(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(g_detail, sizeof(g_detail), fmt, ap);
    va_end(ap);
}

[[noreturn]] inline void fail(const char* expr, const char* file, int line, const char* what)
{
    if (g_detail[0])
        std::fprintf(stderr, "\n--- measurements ---\n  %s\n", g_detail);
    if (print_program_hook())
        print_program_hook()();
    ::fuzz::fail(expr, file, line, what);
}

} // namespace fuzzrt

#define RT_CHECK(expr, what) \
    do { if (!(expr)) ::fuzzrt::fail(#expr, __FILE__, __LINE__, (what)); } while (0)

// A named check that can be demoted to a printed observation.  This exists so
// that one known defect does not stop the fuzzer at step 12 of every input and
// hide the next one behind it.
#define RT_FINDING(id, expr, what)                                           \
    do {                                                                     \
        if (!(expr))                                                         \
        {                                                                    \
            if (::fuzzrt::finding_suppressed(id))                            \
                ::fuzzrt::observe_once(id, what);                            \
            else                                                             \
                ::fuzzrt::fail(#expr, __FILE__, __LINE__, (what));           \
        }                                                                    \
    } while (0)

namespace fuzzrt {

// ───────────────────────────── socket helpers ───────────────────────────────

// Every descriptor the harness itself holds is closed abortively.  Two reasons,
// and the second is the one that decides it: an RST is a teardown the runtime
// has to survive as surely as a clean FIN, and a graceful close would leave the
// harness end in TIME_WAIT for sixty seconds — a fuzzer opening a few hundred
// connections a second exhausts the ephemeral range in under a minute and then
// stops connecting at all, which looks exactly like a target that found nothing.
// The FIN half of the state machine is still reached, by shutdown(SHUT_WR).
inline void set_abortive(int fd)
{
    struct linger lg{};
    lg.l_onoff  = 1;
    lg.l_linger = 0;
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
}

// The largest descriptor number event_loop's tables cover, which is exactly the
// range this process can be handed — see event_loop::init_fd_tables().  The
// sweep has to stop where the table does: fd_inflight() answers zero for a
// number outside it, and a zero that means "not tracked" would read as clean.
inline uint32_t fd_scan_limit()
{
    static const uint32_t n = [] {
        struct rlimit rl{};
        uint64_t want = 4096;
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY)
            want = static_cast<uint64_t>(rl.rlim_cur);
        if (want < 4096)   want = 4096;
        if (want > 65536)  want = 65536;   // the harness never opens more
        return static_cast<uint32_t>(want);
    }();
    return n;
}

// ─────────────────────────────── the oracle ─────────────────────────────────

struct ring_watch
{
    event_loop* loop{nullptr};

    // Invariant 3, checked at the one moment it is observable from outside.
    //
    // The kernel has just handed this number to the harness.  If the loop still
    // counts a submission that named it, then an SQE in the ring is going to
    // resolve to *our* socket when the kernel gets to it: a read into a buffer
    // the runtime still owns, a write of the runtime's bytes into our stream, a
    // cancel taking back I/O that was never the runtime's.  A number is only
    // free to be reissued once nothing in the ring names it, and close_fd()
    // exists to hold it until then.
    void fresh_fd(int fd, const char* where) const
    {
        if (fd < 0 || !loop)
            return;
        const uint32_t armed = loop->fd_inflight(fd);
        if (armed != 0)
        {
            set_detail("the kernel handed the harness fd %d at %s while the ring still "
                       "counts %u submission(s) naming that number",
                       fd, where, armed);
            RT_FINDING("fd-reissued-while-armed", armed == 0,
                       "a descriptor number was released while an SQE in the ring still "
                       "named it, and the kernel has now given that number to somebody "
                       "else — every queued operation on it is redirected onto the new owner");
            g_detail[0] = 0;
        }
    }

    // Invariant 2, in its whole-process form.  Nothing may still name any
    // descriptor number once everything the harness started has stopped and
    // drained.  A non-zero here is an arm whose disarm never came.
    void sweep_descriptors(const char* where) const
    {
        if (!loop)
            return;
        const uint32_t limit = fd_scan_limit();
        for (uint32_t fd = 0; fd < limit; fd++)
        {
            const uint32_t n = loop->fd_inflight(static_cast<int>(fd));
            if (n == 0)
                continue;
            set_detail("at %s, with every runtime stopped and drained, the ring still "
                       "counts %u submission(s) naming descriptor %u",
                       where, n, fd);
            RT_FINDING("fd-armed-after-drain", false,
                       "a submission was counted against a descriptor and never counted "
                       "off — the number can never be closed or reissued, and the owner "
                       "that armed it can never be told it is quiescent");
            g_detail[0] = 0;
            return;   // one report is the diagnosis; the rest are the same fact
        }
    }

    // Invariant 1.  Pump until the ring owes this owner nothing.  Returns true
    // when it drained.
    //
    // Two bounds, because "this operation is slow" and "this operation is never
    // coming" are different claims and only the second is a defect.  The first
    // bound is short, so the overwhelmingly common case — everything already
    // drained — costs nothing.  When it expires the drain escalates to a bound
    // generous enough that no scheduling delay can explain it, and only an
    // owner still outstanding at *that* point is reported.
    //
    // The short bound used to be the whole test, and it produced a finding on a
    // loaded machine and none on an idle one: a multishot accept's cancellation
    // was landing three to twenty-nine milliseconds after a thirty millisecond
    // budget, measured over five reproductions.  That is a budget racing the
    // scheduler, not a completion that never arrives, and this invariant is
    // about the second.  An operation that is genuinely stuck does not become
    // fine if you wait longer, which is why the escalation is bounded too.
    bool drain_owner(const io_handler* owner, int budget_ms)
    {
        if (!loop || !owner)
            return true;
        if (pump_until_idle(owner, budget_ms))
            return true;

        const int hard  = hard_drain_ms();
        const int extra = hard > budget_ms ? hard - budget_ms : 0;
        if (extra > 0 && pump_until_idle(owner, extra))
        {
            note_late_drain(budget_ms);
            return true;
        }
        return false;
    }

    // One pumping pass, up to ms milliseconds of waiting.  Returns true when the
    // owner is idle.
    bool pump_until_idle(const io_handler* owner, int ms)
    {
        for (int i = 0; i < ms && loop->owner_inflight(owner) != 0; i++)
            loop->poll_completions(1);
        // One last non-blocking pass, so a completion that landed inside the
        // final wait is dispatched rather than counted against the owner.
        loop->poll_completions(0);
        return loop->owner_inflight(owner) == 0;
    }

    // How long a drain may take in total before it is a defect rather than a
    // delay.  Two seconds: two orders of magnitude above the delays this has
    // actually been measured at, and still far below what a stuck operation
    // costs, which is unbounded.  Overridable so a slower machine can raise it
    // without editing the oracle.
    static int hard_drain_ms()
    {
        static const int ms = [] {
            const char* e = std::getenv("FUZZ_DRAIN_MS");
            const int   v = e ? std::atoi(e) : 0;
            return v > 0 ? v : 2000;
        }();
        return ms;
    }

    // A drain that needed the escalation is not a failure, but it is worth
    // seeing: it is the early shape of a latency regression, and absorbing it
    // silently is how the next one goes unnoticed.  Rate-limited like
    // fuzz_observe(), for the same reason.
    static void note_late_drain(int short_budget_ms)
    {
        static unsigned long reported = 0;
        if (reported++ < 5)
            std::fprintf(stderr,
                         "[fuzz] observation: an owner drained only after its %d ms budget "
                         "expired — slow, not stuck\n", short_budget_ms);
    }

    // Report what is holding an owner that would not drain.  A count says the
    // storage cannot be freed; the kind says where to look.
    void report_stuck_owner(const io_handler* owner, const char* where) const
    {
        if (!loop || !owner)
            return;
        uint32_t by_type[op_type_count] = {0};
        loop->owner_inflight_breakdown(owner, by_type);

        char buf[512];
        int off = std::snprintf(buf, sizeof(buf), "%u operation(s) still owed at %s:",
                                loop->owner_inflight(owner), where);
        for (uint8_t t = 0; t < op_type_count && off > 0 && off < static_cast<int>(sizeof(buf)); t++)
        {
            if (by_type[t] == 0)
                continue;
            off += std::snprintf(buf + off, sizeof(buf) - static_cast<size_t>(off),
                                 " %s=%u", io_op_name(t), by_type[t]);
        }
        set_detail("%s", buf);
    }
};

} // namespace fuzzrt
