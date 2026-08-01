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
// Three invariants.  Every defect of the family these were written for — a
// connection that hangs until the runtime stops, a completion charged to a
// connection it has nothing to do with, a loop that turns for ever without
// carrying anybody's traffic one byte further — is a violation of one of them,
// so they are stated here in words first and checked in code second.
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
//   (1b) REACHABILITY IS NOT PROGRESS.  (1) as written above reads "something is
//       in flight" as "this pair can still finish", and those are not the same
//       claim.  An operation is in flight because somebody armed it; whether any
//       completion it can produce moves this exchange forward is a different
//       question, and it is the one that matters.
//
//       The pair that leaked 26 connections on 2026-08-01 (6f7b9e2) passed (1)
//       for exactly that reason.  A client sent `Connection: close`, was
//       answered, and half-closed.  The proxy held the pair open for an answer
//       that had already been delivered, and (1) saw the backend's idle
//       multishot read and called the pair reachable — but that read completes
//       only if the backend sends something, the backend had nothing to send
//       because no request was outstanding, and the only thing that could ever
//       end the hold was a response completing.  For a client with no request
//       outstanding, no response ever completes.  So: something in flight, and
//       dead anyway, for as long as the runtime ran.
//
//       Stated sharply, over the exchange rather than over the ring: a half that
//       has HALF-CLOSED will send no further request, so the only completion
//       that can still finish it is the answer to the request it already sent.
//       If no answer is owed, nothing armed anywhere can finish this pair.  It
//       is dead, whatever the ring happens to have outstanding on the peer.
//
//       "Half-closed" and "an answer is owed" are the runtime's own terms and
//       cannot be read off the ring, so the runtime states them — see `exchange`
//       below.  A runtime that does not state them gets (1) and nothing else,
//       which is the right default: a check that guesses at those two would fire
//       on healthy traffic, and one spurious abort is worse than the hole it
//       closes, because the way out of it is to switch every one of these
//       assertions off.
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
//   (3) PROGRESS.  A connection the ring keeps completing operations for must be
//       getting somewhere.  (1) and (2) are both about a pair that has stopped
//       receiving completions; this is the opposite failure, and until now
//       nothing in this project could see it at all.
//
//       On 2026-08-01 a re-arm on a socket at end of stream turned into a loop:
//       the read was armed, the kernel completed it immediately with res=0 and
//       IORING_CQE_F_SOCK_NONEMPTY, the handler re-armed it, for ever.
//       Measured at 1,352,398 iterations on a single connection in one run, with
//       a core saturated for the whole of it.  Every functional assertion in the
//       project passed while that happened: no byte was lost, no framing was
//       wrong, no descriptor was misfiled at that instant, and both the fuzzer
//       and the integration suite ran it and said nothing.  Only the descriptor
//       count at the end of a load test noticed, and only because the pair was
//       never torn down.
//
//       The conservation law that catches it: COMPLETIONS ARE SPENT ON
//       PROGRESS.  Charge every completion to the connection it named, and
//       require that some observable thing about that connection has changed
//       since the last one.  "Observable" is two terms, and both are needed:
//
//         * BYTES THE KERNEL CONFIRMED on this descriptor — the res of a read, a
//           write, a splice, a zero-copy send.  This is the traffic itself, and
//           it is the term that keeps a busy connection from ever being
//           suspected: a connection moving data is making progress by
//           definition, whatever its flags happen to say.
//
//         * THE CONNECTION'S OWN STATE, digested by the runtime that owns it:
//           how much is buffered awaiting a parse, how much is queued to go out,
//           where the message framing has got to, and the lifecycle flags.  This
//           is what covers the completions that legitimately move no bytes — a
//           zero-copy notification, a cancellation, a poll reporting a peer's
//           death — each of which changes something and so is not counted
//           against the connection twice.
//
//       A run of completions with neither term moving is a loop that is turning
//       and going nowhere.  The limit is not a round number; it is measured —
//       see SOCKETLEY_INV_BARREN_LIMIT.  It counts CONSECUTIVE barren
//       completions and any progress at all puts it back to nought, so a
//       long-lived connection cannot drift into a report by collecting one every
//       so often; it has to be a run.
//
// ─── WHAT THESE CANNOT SEE ──────────────────────────────────────────────────
//
// Stated because an oracle whose blind spots are not written down gets read as
// covering them.
//
// (1b) is silent on:
//   * a pair held for any reason other than a half-close.  It keys on the
//     initiating half having said it will send no more, which is what makes "no
//     answer is owed" conclusive; a pair stuck while its client could still send
//     is outside it, and invariant (1) is all such a pair has;
//   * a slow answer as against an absent one.  It fires only when nothing is
//     owed at all.  How long an owed answer may take is --backend-timeout's
//     question and deliberately not this one;
//   * every runtime that does not fill in `exchange`.  Today that is the server
//     and the cache: they get (1), and adopting (1b) means saying what their own
//     "half-closed" and "answer owed" are, not passing something that looks
//     close enough.
//
// (3) is silent on:
//   * a loop that moves bytes.  Any completion carrying traffic clears the
//     ledger, so a livelock that shuffles the same bytes round for ever is
//     invisible here.  That is the deliberate cost of never suspecting a busy
//     connection;
//   * a loop that changes state.  The digest is compared against the previous
//     value and against no history, so two states alternating look like a
//     connection making progress twice a round;
//   * a loop with no completions in it: a spin inside one handler, or a
//     submission that never reaches the ring.  Nothing is charged, so nothing is
//     counted;
//   * a busy-wait on -EAGAIN.  Those completions are deliberately charged to
//     nobody — see check_progress for why, and for the measurement that forced
//     it — so a leg that re-submits a refused splice for ever is invisible to
//     this.  It is a real way to burn a core and it wants a check of its own,
//     over the rate of refusals rather than over the state of a connection;
//   * the server and the cache, which do not call it.  The ledger and the report
//     are here for them; what is missing is a digest of their own state and the
//     measurement behind a limit, and neither should be guessed at.
//
// A violation is reported with enough to name the connection and then aborts,
// because none of these is a state the process can recover from and the core
// dump is the point.  Define SOCKETLEY_INVARIANTS_WARN_ONLY alongside it to
// report and keep going.
//
// A process that knows how to say more than the report does — a fuzz target
// holding the decoded input that got here — hands a printer to pre_abort_hook()
// and it runs just before the abort.  See the note there.

#ifdef SOCKETLEY_INVARIANTS

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

// How many completions may be charged to one connection without one observable
// thing about it changing, before that is called a loop.
//
// Measured, not chosen, and the measurement is the reason the number is small.
// Set SOCKETLEY_INV_PROGRESS_REPORT=1 in the environment and every new
// high-water mark is printed; on the proxy, the only runtime that states this
// today, the longest barren run on traffic that is working is ZERO.  Not a small
// number — none.  All 64 seeds of test/fuzz/corpus/proxy, then seven minutes of
// coverage-guided mutation on top of them, and not one completion was charged to
// a connection without either moving a byte on it or changing something about
// it.  That is what makes this invariant worth having: on working traffic the
// conservation law holds exactly, so any margin at all is margin.
//
// Eight is therefore an absolute cushion and not a ratio — room for a legitimate
// shape the measurement did not reach — and it is chosen against the defect from
// the other side as well.  The end-of-stream re-arm 6f7b9e2 removed reaches
// twelve iterations inside a single program of the existing corpus, so a limit
// of eight is reported by a plain corpus replay rather than only by a load test;
// a limit of sixteen would have been quiet on every seed in the tree.  In a
// daemon, where the loop turns as fast as the ring can post, eight is
// microseconds, against the 1,352,398 iterations that loop actually reached.
//
// The number rests on -EAGAIN being charged to nobody — see check_progress.  The
// splice legs retry on it and reach 19 in a row on working traffic, rising with
// every hour of fuzzing; counting those would have forced this limit above the
// loop it exists to catch.
//
// Re-derive it rather than trusting it.
#ifndef SOCKETLEY_INV_BARREN_LIMIT
#define SOCKETLEY_INV_BARREN_LIMIT 8
#endif

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

// What the pair is waiting FOR, as against what the ring happens to have armed
// on it.  This is invariant (1b), and neither term can be read off the ring —
// they are statements about the exchange, so the runtime that runs the exchange
// makes them.
//
// `stated` is the opt-in.  A runtime that leaves it false is asserting nothing
// here and gets invariant (1) alone; that is deliberate, and it is why the
// server and the cache are not exposed to this check at all.  A default-
// constructed `exchange` is the safe thing to pass and the safe thing to forget.
struct exchange
{
    bool stated{false};

    // The half that initiates has shut its write side.  It will never send
    // another request, so the only completion that can still finish this pair is
    // the answer to the one it already sent.
    bool half_closed{false};

    // An answer to that request is genuinely outstanding: it has not reached the
    // other end yet, or it has and the response is not finished.  Note what this
    // is NOT — "the ring owes the peer a completion".  Under multishot recv a
    // read is armed on an idle peer essentially all of the time, so that
    // question answers yes for a peer that owes nothing whatever, which is
    // precisely how the leak this invariant was written for stayed invisible.
    bool answer_owed{false};
};

// The progress ledger for one half, invariant (3).  Lives on the connection
// struct, so it is reset with the struct and travels with it through a pool.
struct progress
{
    uint64_t digest{0};     // the runtime's account of this connection's state
    uint64_t moved{0};      // bytes the kernel has confirmed on this descriptor
    uint32_t barren{0};     // completions since either of the two above changed
    bool     stated{false}; // a digest has been taken at least once
    bool     reported{false};
};

// High-water mark across the process, for deriving the limit above.  Printing on
// every new peak rather than at exit is deliberate: nothing here exits cleanly —
// a fuzz target is killed, a daemon is signalled — and a report that only lands
// at exit is a report nobody ever reads.
inline uint32_t& progress_peak()
{
    static uint32_t v = 0;
    return v;
}

// SOCKETLEY_INV_PROGRESS_REPORT=1 in the environment turns the high-water marks
// on.  It ADDS output and does nothing else: it does not raise the limit and it
// does not suppress the abort, so a run with it set enforces exactly what a run
// without it enforces.  That is the point — a knob that could quiet this check
// is the one thing it must not have, because reaching for it is how every
// assertion in this header gets switched off at once.
inline bool progress_report_on()
{
    static const bool on = [] {
        const char* e = std::getenv("SOCKETLEY_INV_PROGRESS_REPORT");
        return e && *e && *e != '0';
    }();
    return on;
}

// Something for a harness to print before the process dies.
//
// These checks abort on their own account, which for a long time meant a
// violation found by a fuzzer landed as a message and nothing else: the nightly
// has carried "FUZZ_PROXY_SKIP cannot reach this, it is invariants.h aborting on
// its own account" as a standing note since found-55a07a18, and what that costs
// is the reproducer.  A target that owns a decoded input hands its printer over
// here and gets the same report for a violation of one of these as for one of
// its own findings.
//
// Deliberately a bare function pointer set by the owner of the process, and
// deliberately not a way to *stop* the abort: it adds output and takes nothing
// away.  Null in a daemon, where there is no program to decode and the core dump
// is the report.
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

// (1) Reachability and (1b) progress-reachability, both over the pair.  A pair
// with neither half present is one that has already been torn down, which is the
// good case, not a violation.
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

    // (1b) Something is in flight, and none of it can finish this pair.
    //
    // Five terms, and every one of them is load-bearing against a false report:
    //
    //   stated       — the runtime has an opinion on the two questions below.
    //                  Without it this check does not run at all.
    //   half_closed  — the initiating half has said it will send nothing more.
    //                  A half that can still send has a request in its future
    //                  and every completion in the world ahead of it.
    //   !answer_owed — nothing is outstanding for it to be waiting on.  While an
    //                  answer is owed the exchange is alive by construction: the
    //                  peer will deliver it, or the deadline sweep will answer in
    //                  its place, and either way something ends the hold.
    //   !a.in_flight — the held half has nothing of its own outstanding.  A write
    //                  still draining the tail of an answer is exactly the case
    //                  the deferred teardown exists for, and its completion is
    //                  what closes the pair; reporting that as dead would fire on
    //                  every well-behaved close in the runtime.
    //   !a.closing   — a teardown already under way is not a hold.  close_pair
    //                  leaves a half indexed and closing while its queue drains,
    //                  which looks like this shape from the outside and is the
    //                  correct behaviour rather than the defect.
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

// (3) Progress.  Called once for every completion the loop charges to a
// connection, with that completion's confirmed byte count and the runtime's
// digest of everything else about the connection that a caller could observe.
//
// `bytes` is added rather than compared, so a connection that moves one byte per
// completion for ever is never suspected — which is correct, because it is
// carrying somebody's traffic.  Everything else is the digest's business.
//
// `op` and `res` are the last completion's, and they are carried purely so that
// a report names the operation that is turning.  "This connection is looping" is
// a claim; "it is looping on a recv_multishot answering res=0" is where to look.
inline void check_progress(const char* where, progress& p, uint64_t digest,
                           uint64_t bytes, int fd, const char* op, int res)
{
    // A completion that reports the kernel DECLINING is charged to nobody.
    //
    // -EAGAIN says the operation did not happen: the socket had nothing to give,
    // the pipe was full, the buffer group was empty.  That is not this exchange
    // failing to advance, it is this exchange not being attempted, and what
    // bounds a run of them is the peer and the scheduler rather than anything
    // about the connection's own state.  Measured on the proxy's splice legs,
    // which retry on exactly this: 19 in a row on working traffic, and rising
    // slowly with every hour of fuzzing, because it is a tail and not a bound.
    // Counting those would put the limit above the loop this exists to catch —
    // measured at 12 within one fuzz program — and an oracle whose threshold is
    // above its subject is not an oracle.
    //
    // The run is not RESET by one either.  The ledger is about consecutive
    // completions that carried the exchange nowhere, and a refusal in the middle
    // of such a run does not make it two runs.
    //
    // What this gives up is stated with the rest of the blind spots at the top:
    // a busy-wait on -EAGAIN is invisible here, and it is a real way to burn a
    // core.  It needs its own check, over the rate of refusals rather than over
    // the state of a connection.
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

// The progress ledger, on a connection struct.  Same arrangement as
// SKL_TRACE_FIELD in trace.h: the member does not exist at all in a build
// without the checks, so nothing about the struct's layout depends on them.
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
