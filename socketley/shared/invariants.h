#pragma once
// Opt-in invariant checks for connection liveness and struct reuse.
//
// Build with:  make config=debug_x64 CPPFLAGS=-DSOCKETLEY_INVARIANTS
// (the generated makefiles already pass $(CPPFLAGS) through, so no build system
// change is needed to turn this on — the same arrangement trace.h uses.)
//
// Everything here compiles to nothing unless SOCKETLEY_INVARIANTS is defined:
// nothing is added to any connection struct and every call site becomes an
// empty statement, so a release build carries no cost for having the checks in
// place.
//
// Two invariants.  Every defect of the family these were written for — a
// connection that hangs until the runtime stops, a completion charged to a
// connection it has nothing to do with — is a violation of one of them, so they
// are stated here in words first and checked in code second.
//
//   (1) REACHABILITY.  A connection the runtime still believes it is serving
//       must have something that will wake it again: an operation the ring
//       still owes a completion for, on itself or on the peer it is paired
//       with.  Nothing else drives a connection here — there is no poll loop
//       and no per-connection timer, every step happens inside a completion
//       handler — so a pair with nothing in flight is a pair nobody will ever
//       come back to.  It sits there holding its descriptors until the runtime
//       stops, with the peer waiting on an answer that will never be written.
//
//       Bytes in a write queue do not satisfy this.  The queue is only ever
//       flushed from inside a completion handler, so a pair with an unflushed
//       queue and nothing in flight is not "about to send" — it is stuck, and
//       those bytes are the measure of what was lost.  They are reported all
//       the same, because they say how much a violation cost.
//
//       It has to be the *pair*.  A client parked while its backend connects or
//       replies legitimately has nothing of its own in flight; asserting on one
//       half alone fires on perfectly healthy traffic.
//
//   (2) POOL SAFETY.  A struct handed back to a pool must have no request the
//       ring can still complete.  The pool gives its structs to the very next
//       connection, so a completion landing on one that has already been
//       reissued is charged to a connection it has nothing to do with — and the
//       kernel may still be reading out of buffers that the reuse clears.  Both
//       halves of that have to hold at the moment of the push: every pending
//       flag down, and every io_request owner cleared, so that a completion
//       which somehow arrives anyway is dropped by the loop rather than
//       dispatched into the newcomer.
//
// A violation is reported with enough to name the connection and then aborts,
// because neither state is one the process can recover from and the core dump
// is the point.  Define SOCKETLEY_INVARIANTS_WARN_ONLY alongside it to report
// and keep going.

#ifdef SOCKETLEY_INVARIANTS

#include <cstdio>
#include <cstdlib>

namespace skl_inv {

// One half of a connection, reduced to the facts the invariants need.  Filled
// in by the runtime that owns the struct: only it knows which pending flags its
// connections carry — the proxy's client has a connect, the server's has a file
// read, the cache's has neither.
struct half
{
    bool present{false};    // there is a connection on this side at all
    bool in_flight{false};  // the ring still owes it at least one completion
    bool queued{false};     // bytes waiting to be written out
    bool closing{false};
    int  fd{-1};
};

inline void fail(const char* what, const char* where)
{
    std::fprintf(stderr, "[invariant] %s at %s\n", what, where);
    std::fflush(stderr);
#ifndef SOCKETLEY_INVARIANTS_WARN_ONLY
    std::abort();
#endif
}

// (1) Reachability, over the pair.  A pair with neither half present is one
// that has already been torn down, which is the good case, not a violation.
inline void check_pair(const char* where, const half& a, const half& b)
{
    if (!a.present && !b.present)
        return;
    if (a.in_flight || b.in_flight)
        return;

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
    std::abort();
#endif
}

// (2) Pool safety.  `pending` is "the ring still owes this struct something",
// `owner_set` is "a completion that arrives anyway would be dispatched rather
// than dropped".  Either one alone is enough to make the reuse unsafe.
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
    std::abort();
#endif
}

} // namespace skl_inv

#define SKL_INV_PAIR(where, a, b)             ::skl_inv::check_pair((where), (a), (b))
#define SKL_INV_POOLABLE(where, fd, p, o)     ::skl_inv::check_poolable((where), (fd), (p), (o))
#define SKL_INV_FAIL(what, where)             ::skl_inv::fail((what), (where))

#else   // !SOCKETLEY_INVARIANTS

#define SKL_INV_PAIR(where, a, b)             ((void)0)
#define SKL_INV_POOLABLE(where, fd, p, o)     ((void)0)
#define SKL_INV_FAIL(what, where)             ((void)0)

#endif  // SOCKETLEY_INVARIANTS
