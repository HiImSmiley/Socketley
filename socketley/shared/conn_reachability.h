#pragma once

// ─── May a teardown be deferred to an operation still in flight? ────────────
//
// Every runtime in this tree tears its connections down out of a completion
// handler, and every handler asks the same question before it does: is anything
// still in flight on this connection?  If something is, the teardown is
// deferred — "a completion is owed, so this will run when it lands."
//
// That reasoning is only as good as the promise behind the operation it defers
// to, and the operations do not all make the same promise.  A write, a zero-copy
// notification, a read from a *file*, a splice: the ring answers these whatever
// the socket does, and if the socket has failed the answer is an error rather
// than silence.  An armed read on a socket is different in kind.  It is ended by
// the peer sending something, or by the socket ending — and a connection that is
// `closing` is, by definition, one whose peer has already gone.  Deferring to it
// is a promise nothing is obliged to keep.
//
// When it is broken, the connection stays in its runtime's table holding its
// descriptor, its fixed-file slot and whatever its write queue still owns, until
// the runtime stops.  Nothing looks at it again.
//
// THIS HAS BEEN FOUND TWICE, IN TWO RUNTIMES, WITH ONE MECHANISM
//
//   * cache (78c9ecc).  A client reset while its reply was being written: the
//     write took the ECONNRESET, marked the connection closing, and deferred to
//     a multishot recv armed on a fixed file index.  The peer was gone and the
//     reset had been consumed by the write, so it never reported.  11 of 50 runs
//     of test_abrupt_client_abort.sh, 0 of 50 after.
//
//   * server.  The identical shape, through conn_ops_pending().  Measured over
//     8 storm rounds and 15,794 aborted connections: the teardown was declined
//     with an armed read as the ONLY thing outstanding 15,165 times, every one of
//     them on a direct descriptor, and about 15% of rounds left a connection
//     that was never reaped.  See test_server_abrupt_abort.sh.
//
// The second occurrence in a different runtime is why the rule lives here rather
// than in either of them.  free_fixed_file_slot() in event_loop.cpp records the
// same finding one level down, in the same words: a multishot recv on a direct
// connection "could only ever end by itself, and by itself means the peer or the
// socket" — and adds the part that closes the circle, that a submission naming a
// fixed index is not counted against a descriptor and so cannot be withdrawn by
// close_fd().  Withdrawing it is the teardown's job, which is precisely the
// thing being deferred.
//
// WHAT THIS DOES AND DOES NOT DO
//
// It classifies flags and returns a verdict.  It does not close anything, does
// not touch a ring, and does not know what a connection is: the four event loops
// genuinely differ and keep their own control flow.  What they must not differ
// about is which operations count, and that is the whole content of `owed`
// below — a flag added to a connection has to be classified here before any
// runtime can decide anything with it.

#include <cstdint>

namespace socketley::reach
{

// The operations outstanding on one connection, sorted by who is obliged to
// report them.
//
// Everything above `read` is a request the ring answers whatever the socket
// does.  `read` is below the line, is named so that no caller can pass it as
// something owed, and is deliberately still a member: an omission reads as an
// oversight, whereas a field the rule explicitly excludes states the rule.
struct owed
{
    // ── The ring answers these ──────────────────────────────────────────────
    bool write{false};        // write / writev / send_zc: an error is still an answer
    bool zc_notif{false};     // the notification half of a zero-copy send.  Its
                              // absence is not implied by write being down —
                              // the first completion clears that while the
                              // kernel is still DMA-ing out of the batch
    bool file_read{false};    // a read from a file.  Nothing about it depends on
                              // the socket or on the peer
    bool splice_in{false};    // file or socket -> pipe
    bool splice_out{false};   // pipe -> socket
    bool connect{false};      // an outbound connect, or the poll standing in
                              // for one: the ring reports it either way
    bool promised_reply{false};   // a request handed to something that promises
                                  // exactly one reply per request and delivers
                                  // it back into this loop — a cross-runtime
                                  // channel, not the ring

    // ── Only the peer or the socket can end this ────────────────────────────
    // NOT counted by ring_will_report(), on purpose.  See the header comment.
    bool read{false};
};

// "Something outstanding will come back and ask this question again."
inline constexpr bool ring_will_report(const owed& o)
{
    return o.write || o.zc_notif || o.file_read || o.splice_in || o.splice_out ||
           o.connect || o.promised_reply;
    // o.read is absent.  That is the rule, not a mistake.
}

enum class verdict : uint8_t
{
    // Not closing, or something the ring owes is outstanding.  Somebody else's
    // business: leave it exactly as it is.
    keep,

    // Closing, nothing the ring owes — but bytes the peer already handed over
    // and considers answered are still queued.  Push them out first: dropping
    // them is throwing away a reply the client is entitled to.
    //
    // The caller must ASK AGAIN after flushing.  A flush that reached the ring
    // turns this into `keep` and its completion finishes the teardown; a flush
    // can also legitimately submit nothing — a TLS session with a reply queued
    // while the handshake is still running has output and no way to send it —
    // and that turns it into `finish`, because nothing would wake it either.
    flush,

    // Closing and unreachable.  Finish it now.  Taking the armed read back is
    // the teardown's own job and every runtime's teardown already does it:
    // close_fd() cancels one armed on a descriptor, free_fixed_file_slot()
    // cancels one armed on a fixed index, and the retire path holds the struct
    // until that -ECANCELED lands.
    finish
};

inline constexpr verdict classify(bool closing, const owed& o, bool has_output)
{
    if (!closing || ring_will_report(o))
        return verdict::keep;
    return has_output ? verdict::flush : verdict::finish;
}

}   // namespace socketley::reach
