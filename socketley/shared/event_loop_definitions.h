#pragma once
#include <cstdint>

// Branch prediction hints for hot-path optimization
#ifndef SOCKETLEY_LIKELY
#define SOCKETLEY_LIKELY(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef SOCKETLEY_UNLIKELY
#define SOCKETLEY_UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif

class event_loop;

class io_handler
{
public:
    virtual ~io_handler() = default;
    virtual void on_cqe(struct io_uring_cqe* cqe) = 0;

private:
    friend class event_loop;

    // Who this handler is as far as the loop is concerned: the index of its
    // slot in the loop's owner table in the low bits, the epoch of the
    // registration holding that slot in the high 16.  Written only by
    // event_loop::register_owner() and cleared only by deregister_owner().
    //
    // Every submission copies it into its io_request, so a completion carries
    // the identity its owner had at submit time.  The loop can then decide
    // whether that owner is still there without dereferencing it — which it
    // must not do, because "still there" is exactly the question.
    uint32_t m_loop_token{0};
};

// Stamp source for io_request::generation below.  One counter for the whole
// process: the comparison it feeds is only meaningful if no two structs that
// are alive at the same time can hold the same value, and per-struct counters
// cannot promise that.  Only the loop thread calls this, so a plain increment
// is enough.  Zero stays reserved for "never stamped" and is skipped on wrap,
// so a request that was never given a generation never looks current.
inline uint32_t next_io_generation()
{
    static uint32_t seq = 0;
    if (SOCKETLEY_UNLIKELY(++seq == 0))
        seq = 1;
    return seq;
}

// io_request::buf_group for a submission that selected no provided buffer.
// Outside every valid group id, so returning it is a no-op.
inline constexpr uint8_t NO_BUF_GROUP = 0xFF;

// ── Descriptor targets ──────────────────────────────────────────────────────
// An SQE does not carry a file.  It carries a *number* — a raw descriptor, or
// an index into the ring's fixed-file table — and the kernel resolves that
// number to a file when it consumes the SQE.  With SQPOLL that happens on
// another thread at a moment nothing here controls, and even without it this
// loop batches a whole completion round before it submits.
//
// So a number that is given away between the submission and the consumption is
// not a cancelled operation, it is a *redirected* one: the read, write or
// splice lands on whatever now answers to that number.  This was measured on
// the proxy — about 6% of healthy connections received an aborting client's
// 8192 bytes spliced into the middle of their own stream, because the aborting
// client's descriptor had been closed and reissued by the next accept while its
// splice was still queued.  Giving the number away covers three moves, not one:
// close() and let the next accept take it, hand it to a connection pool, or
// free a fixed-file slot and let the next allocation have the index.
//
// event_loop counts, per number, the submissions that named it, and refuses all
// three moves until that count is zero.  These are how a submission records
// which number it named, so the count can be undone when the completion lands.
// IO_TARGET_FIXED separates the two namespaces: fixed index 7 and raw
// descriptor 7 are different things and must not share a counter.
inline constexpr uint32_t IO_TARGET_NONE  = 0xFFFFFFFFu;
inline constexpr uint32_t IO_TARGET_FIXED = 0x80000000u;

enum op_type : uint8_t
{
    op_accept                = 0,
    op_read                  = 1,
    op_write                 = 2,
    op_nop                   = 3,
    op_multishot_accept      = 4,
    op_read_provided         = 5,
    op_writev                = 6,
    op_recvmsg               = 7,
    op_timeout               = 8,
    op_recv_multishot        = 9,
    op_send_zc               = 10,
    op_send_zc_notif         = 11,
    op_multishot_accept_direct = 12,  // multishot accept with direct descriptors
    op_read_fixed_buf        = 13,    // read using registered buffer
    op_write_fixed_buf       = 14,    // write using registered buffer
    op_splice                = 15,    // splice between fds through pipe
    op_file_read             = 16,    // async file read via io_uring
    op_connect               = 17,    // async connect via io_uring
    op_health_check          = 18,    // async health check (connect/write/read phases)
    op_poll                  = 19,    // wait for readiness (used to finish a non-blocking connect)
    op_poll_abort            = 20     // wait for a peer to die (POLLERR/POLLHUP), reading nothing
};

inline constexpr uint8_t op_type_count = 21;

// For diagnostics only.  A count of outstanding operations says an owner cannot
// be released yet; the kind says why, which is the difference between reading a
// number and knowing where to look.
inline const char* io_op_name(uint8_t t)
{
    switch (t)
    {
        case op_accept:                  return "accept";
        case op_read:                    return "read";
        case op_write:                   return "write";
        case op_nop:                     return "nop";
        case op_multishot_accept:        return "multishot-accept";
        case op_read_provided:           return "read-provided";
        case op_writev:                  return "writev";
        case op_recvmsg:                 return "recvmsg";
        case op_timeout:                 return "timeout";
        case op_recv_multishot:          return "recv-multishot";
        case op_send_zc:                 return "send-zc";
        case op_send_zc_notif:           return "send-zc-notif";
        case op_multishot_accept_direct: return "multishot-accept-direct";
        case op_read_fixed_buf:          return "read-fixed-buf";
        case op_write_fixed_buf:         return "write-fixed-buf";
        case op_splice:                  return "splice";
        case op_file_read:               return "file-read";
        case op_connect:                 return "connect";
        case op_health_check:            return "health-check";
        case op_poll:                    return "poll";
        case op_poll_abort:              return "poll-abort";
        default:                         return "unknown";
    }
}

struct io_request
{
    io_handler* owner;
    char* buffer;
    int fd;
    uint32_t length;
    op_type type;

    // Connection structs are pooled and their io_requests live inside them, so
    // a completion that arrives after the struct was handed to a new connection
    // is indistinguishable from that connection's own — same address, same fd
    // number, and the same owner, so owner_token below cannot separate them:
    // the owner really is unchanged.  This is the finer-grained stamp for that
    // case.  A struct writes the value it was reset with into every request it
    // submits, and the handler compares before acting on the completion.
    //
    // The value must come from next_io_generation() and from nowhere else.  A
    // counter kept per struct does not work, because both check sites reach the
    // struct through the fd index first: once a descriptor is handed to a
    // different struct, the stamp is compared against a *different* object's
    // counter, and with a pool of a few dozen structs those counters sit in a
    // narrow band, so two unrelated connections agreeing is common rather than
    // rare.  One monotonic source makes agreement mean identity again.
    uint32_t generation{0};

    // Which handler this submission belonged to, copied from the owner's
    // io_handler::m_loop_token by the submit_* helpers.  run() compares it
    // against the loop's owner table before dispatching: a handler that has
    // deregistered since — or a request left over from an earlier registration
    // that happened to land on the same slot — fails the compare and its
    // completion is dropped instead of delivered.  Zero means the request had
    // no owner at submit time, which never matches a live registration.
    uint32_t owner_token{0};

    // The provided-buffer group this submission selected from, so the loop can
    // put the buffer back when it drops the completion — by then the owner that
    // knew the group may be gone.  Set only by the helpers that ask for a
    // provided buffer; a value left behind by an earlier such submission on the
    // same request is never read, because it is only consulted when the
    // completion carries IORING_CQE_F_BUFFER and only those helpers can produce
    // that.
    uint8_t buf_group{NO_BUF_GROUP};

    // The number(s) this submission wrote into its SQE, in the encoding
    // described above.  Written by event_loop::arm() from the argument the
    // submit_* helper was called with — not from ::fd, which several helpers
    // deliberately set to something else (submit_file_read names the file but
    // records the socket, so the completion routes to the right connection).
    //
    // Two of them because splice names two: the pipe it reads from and the
    // socket it writes into, and both have to be held.  The measured bug was on
    // the second one.
    //
    // These are read by run() *before* the handler is dispatched, for the same
    // reason ::type is: on_cqe may free the storage this request lives in, and
    // may re-arm the request onto a different descriptor.  The value that has
    // to be undone is the one that was armed.
    uint32_t armed_target{IO_TARGET_NONE};
    uint32_t armed_target2{IO_TARGET_NONE};
};
