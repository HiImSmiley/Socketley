#pragma once
// Opt-in liveness and struct-reuse checks, compiled to nothing without
// SOCKETLEY_INVARIANTS; what they cannot see is listed in AGENTS.md.

#ifdef SOCKETLEY_INVARIANTS

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

// Consecutive barren completions before a connection is called a loop,
// measured rather than chosen and re-derivable with
// SOCKETLEY_INV_PROGRESS_REPORT=1.
#ifndef SOCKETLEY_INV_BARREN_LIMIT
#define SOCKETLEY_INV_BARREN_LIMIT 8
#endif

namespace skl_inv {

// One half of a connection, filled in by the runtime that owns it -- only it
// knows which pending flags its connections carry.
struct half
{
    bool present{false};    // there is a connection on this side at all
    bool in_flight{false};  // the ring still owes it at least one completion
    bool queued{false};     // bytes waiting to be written out
    bool closing{false};
    int  fd{-1};
};

// What the pair waits for, which cannot be read off the ring, so the runtime
// states it and `stated` is the opt-in.
struct exchange
{
    bool stated{false};

    // The half that initiates has shut its write side, so only the answer to
    // the request it already sent can finish this pair.
    bool half_closed{false};

    // NOT "the ring owes the peer a completion": under multishot recv that is
    // true of an idle peer, which is how the leak stayed invisible.
    bool answer_owed{false};
};

// The progress ledger for one half, on the connection struct so it is reset
// with the struct and travels with it through a pool.
struct progress
{
    uint64_t digest{0};     // the runtime's account of this connection's state
    uint64_t moved{0};      // bytes the kernel has confirmed on this descriptor
    uint32_t barren{0};     // completions since either of the two above changed
    bool     stated{false}; // a digest has been taken at least once
    bool     reported{false};
};

// Printed on every new peak, not at exit: nothing here exits cleanly.
inline uint32_t& progress_peak()
{
    static uint32_t v = 0;
    return v;
}

// Adds output and nothing else -- it cannot raise the limit or suppress the
// abort, because a knob that quiets this check is how all of them get switched off.
inline bool progress_report_on()
{
    static const bool on = [] {
        const char* e = std::getenv("SOCKETLEY_INV_PROGRESS_REPORT");
        return e && *e && *e != '0';
    }();
    return on;
}

// Lets a fuzz target print its reproducer before the abort, and is null in a
// daemon, where the core dump is the report.
inline void (*&pre_abort_hook())()
{
    static void (*fn)() = nullptr;
    return fn;
}

inline void run_pre_abort_hook()
{
    if (pre_abort_hook())
        pre_abort_hook()();
}

inline void fail(const char* what, const char* where)
{
    std::fprintf(stderr, "[invariant] %s at %s\n", what, where);
    std::fflush(stderr);
#ifndef SOCKETLEY_INVARIANTS_WARN_ONLY
    run_pre_abort_hook();
    std::abort();
#endif
}

// (1) and (1b) over the pair, where a pair with neither half present has
// already been torn down and is the good case.
inline void check_pair(const char* where, const half& a, const half& b,
                       const exchange& x = exchange{})
{
    if (!a.present && !b.present)
        return;

    // (1) Nothing in flight anywhere: no completion is coming and nothing else
    // drives a connection here.
    if (!a.in_flight && !b.in_flight)
    {
        std::fprintf(stderr,
            "[invariant] nothing in flight on either half — this pair will never be "
            "woken again | at %s | a: fd=%d present=%d queued=%d closing=%d"
            " | b: fd=%d present=%d queued=%d closing=%d\n",
            where,
            a.fd, static_cast<int>(a.present), static_cast<int>(a.queued),
            static_cast<int>(a.closing),
            b.fd, static_cast<int>(b.present), static_cast<int>(b.queued),
            static_cast<int>(b.closing));
        std::fflush(stderr);
#ifndef SOCKETLEY_INVARIANTS_WARN_ONLY
        run_pre_abort_hook();
        std::abort();
#endif
        return;
    }

    // (1b) Something is in flight and none of it can finish this pair; see
    // AGENTS.md for what each of the five terms rules out.
    if (!x.stated || !a.present || !x.half_closed || x.answer_owed ||
        a.in_flight || a.closing)
        return;

    std::fprintf(stderr,
        "[invariant] this half has half-closed and is owed no answer — nothing in "
        "flight on the peer can finish it, and it is being held anyway | at %s"
        " | a: fd=%d present=%d queued=%d closing=%d"
        " | b: fd=%d present=%d in_flight=%d queued=%d closing=%d\n",
        where,
        a.fd, static_cast<int>(a.present), static_cast<int>(a.queued),
        static_cast<int>(a.closing),
        b.fd, static_cast<int>(b.present), static_cast<int>(b.in_flight),
        static_cast<int>(b.queued), static_cast<int>(b.closing));
    std::fflush(stderr);
#ifndef SOCKETLEY_INVARIANTS_WARN_ONLY
    run_pre_abort_hook();
    std::abort();
#endif
}

// (3) Progress, once per completion charged to a connection, with `bytes`
// added rather than compared so traffic is never suspected.
inline void check_progress(const char* where, progress& p, uint64_t digest,
                           uint64_t bytes, int fd, const char* op, int res)
{
    // -EAGAIN is charged to nobody and does not reset the run: it says the
    // operation was not attempted, and counting it would put the limit above
    // the loop this exists to catch.
    if (res == -EAGAIN || res == -ENOBUFS)
        return;

    if (!p.stated || digest != p.digest || bytes != 0)
    {
        p.digest = digest;
        p.moved += bytes;
        p.barren = 0;
        p.stated = true;
        return;
    }

    p.barren++;

    if (progress_report_on() && p.barren > progress_peak())
    {
        progress_peak() = p.barren;
        std::fprintf(stderr, "[invariant-progress] new high-water mark: %u barren "
                             "completions at %s | fd=%d op=%s res=%d moved=%llu "
                             "digest=%016llx\n",
                     p.barren, where, fd, op, res,
                     static_cast<unsigned long long>(p.moved),
                     static_cast<unsigned long long>(digest));
        std::fflush(stderr);
    }

    if (p.barren < SOCKETLEY_INV_BARREN_LIMIT || p.reported)
        return;

    // Latched, so that a warn-only build reports the loop once instead of once
    // per iteration — which for this defect is once per iteration of a loop that
    // reached 1.35 million.
    p.reported = true;

    std::fprintf(stderr,
        "[invariant] %u completions charged to this connection and not one "
        "observable thing about it has changed — the loop is turning and nothing "
        "is moving | at %s | fd=%d op=%s res=%d moved=%llu digest=%016llx\n",
        p.barren, where, fd, op, res, static_cast<unsigned long long>(p.moved),
        static_cast<unsigned long long>(digest));
    std::fflush(stderr);
#ifndef SOCKETLEY_INVARIANTS_WARN_ONLY
    run_pre_abort_hook();
    std::abort();
#endif
}

// (2) Pool safety, where either the ring still owing this struct something or
// a completion still being dispatchable makes the reuse unsafe.
inline void check_poolable(const char* where, int fd, bool pending, bool owner_set)
{
    if (!pending && !owner_set)
        return;

    std::fprintf(stderr,
        "[invariant] struct returned to the pool while the ring can still name it"
        " | at %s | fd=%d pending=%d owner_set=%d\n",
        where, fd, static_cast<int>(pending), static_cast<int>(owner_set));
    std::fflush(stderr);
#ifndef SOCKETLEY_INVARIANTS_WARN_ONLY
    run_pre_abort_hook();
    std::abort();
#endif
}

} // namespace skl_inv

#define SKL_INV_PAIR(where, a, b)             ::skl_inv::check_pair((where), (a), (b))
#define SKL_INV_PAIR_X(where, a, b, x)        ::skl_inv::check_pair((where), (a), (b), (x))
#define SKL_INV_POOLABLE(where, fd, p, o)     ::skl_inv::check_poolable((where), (fd), (p), (o))
#define SKL_INV_PROGRESS(where, p, d, n, fd, op, res) \
    ::skl_inv::check_progress((where), (p), (d), (n), (fd), (op), (res))
#define SKL_INV_FAIL(what, where)             ::skl_inv::fail((what), (where))

// The progress ledger on a connection struct, arranged like SKL_TRACE_FIELD so
// the member does not exist at all in a build without the checks.
#define SKL_INV_FIELD(name)                   ::skl_inv::progress name;
#define SKL_INV_RESET(obj)                    ((obj).pr = ::skl_inv::progress{})

#else   // !SOCKETLEY_INVARIANTS

#define SKL_INV_PAIR(where, a, b)             ((void)0)
#define SKL_INV_PAIR_X(where, a, b, x)        ((void)0)
#define SKL_INV_POOLABLE(where, fd, p, o)     ((void)0)
#define SKL_INV_PROGRESS(where, p, d, n, fd, op, res)  ((void)0)
#define SKL_INV_FAIL(what, where)             ((void)0)
#define SKL_INV_FIELD(name)
#define SKL_INV_RESET(obj)                    ((void)0)

#endif  // SOCKETLEY_INVARIANTS
