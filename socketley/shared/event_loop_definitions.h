#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <unistd.h>
#include "op_timing_fwd.h"

// Branch prediction hints for hot-path optimization
#ifndef SOCKETLEY_LIKELY
#define SOCKETLEY_LIKELY(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef SOCKETLEY_UNLIKELY
#define SOCKETLEY_UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif

class event_loop;

// Which CPUs a loop's I/O may run on, where `all` makes no sched_setaffinity
// call at all rather than pinning to the CPUs online now.
struct cpu_set_spec
{
    // A 65-CPU box is refused by parsing rather than losing its high half.
    static constexpr uint32_t max_cpus = 64;

    bool     all{true};
    uint64_t mask{0};

    bool empty() const { return !all && mask == 0; }

    uint32_t count() const
    {
        return all ? 0u : static_cast<uint32_t>(__builtin_popcountll(mask));
    }

    // What `stats` shows, so it must be a string the user could have typed.
    std::string to_string() const
    {
        if (all) return "max";
        if (mask == 0) return "none";

        std::string out;
        uint32_t i = 0;
        bool first_group = true;
        while (i < max_cpus)
        {
            if (!(mask & (1ull << i))) { ++i; continue; }
            uint32_t start = i;
            while (i + 1 < max_cpus && (mask & (1ull << (i + 1)))) ++i;
            if (!first_group) out += ',';
            first_group = false;
            out += std::to_string(start);
            if (i > start)
            {
                out += '-';
                out += std::to_string(i);
            }
            ++i;
        }
        return out;
    }
};

// How many CPUs this machine has, separate so the parser can be tested against
// a number the caller chooses.
inline uint32_t online_cpu_count()
{
    const long n = ::sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? static_cast<uint32_t>(n) : 1u;
}

// `max`, `0`, `0-3`, `0,1,2,3`, `0-1,3`, refusing an absent CPU and an empty
// set rather than falling back to "all".
inline bool parse_cpu_set(std::string_view spec, uint32_t ncpus,
                          cpu_set_spec& out, std::string& err)
{
    out = cpu_set_spec{};

    if (spec.empty())
    {
        err = "empty CPU set";
        return false;
    }

    if (spec == "max")
    {
        out.all = true;
        out.mask = 0;
        return true;
    }

    if (ncpus > cpu_set_spec::max_cpus)
        ncpus = cpu_set_spec::max_cpus;

    auto parse_num = [&](std::string_view s, uint32_t& v) -> bool
    {
        if (s.empty()) return false;
        uint64_t acc = 0;
        for (char c : s)
        {
            if (c < '0' || c > '9') return false;
            acc = acc * 10 + static_cast<uint64_t>(c - '0');
            if (acc > cpu_set_spec::max_cpus) return false;   // no wrap, no silent truncation
        }
        v = static_cast<uint32_t>(acc);
        return true;
    };

    uint64_t mask = 0;
    size_t pos = 0;
    while (pos <= spec.size())
    {
        const size_t comma = spec.find(',', pos);
        const std::string_view item = spec.substr(pos, comma == std::string_view::npos
                                                          ? std::string_view::npos
                                                          : comma - pos);
        if (item.empty())
        {
            err = "empty element in CPU set";
            return false;
        }

        const size_t dash = item.find('-');
        uint32_t lo = 0, hi = 0;
        if (dash == std::string_view::npos)
        {
            if (!parse_num(item, lo))
            {
                err = std::string("not a CPU number: ") + std::string(item);
                return false;
            }
            hi = lo;
        }
        else
        {
            if (!parse_num(item.substr(0, dash), lo) ||
                !parse_num(item.substr(dash + 1), hi))
            {
                err = std::string("not a CPU range: ") + std::string(item);
                return false;
            }
            if (hi < lo)
            {
                err = std::string("descending CPU range: ") + std::string(item);
                return false;
            }
        }

        if (hi >= ncpus)
        {
            err = "CPU " + std::to_string(hi) + " does not exist on this machine ("
                + std::to_string(ncpus) + " online)";
            return false;
        }

        for (uint32_t c = lo; c <= hi; ++c)
            mask |= (1ull << c);

        if (comma == std::string_view::npos) break;
        pos = comma + 1;
        if (pos == spec.size())
        {
            err = "trailing comma in CPU set";
            return false;
        }
    }

    if (mask == 0)
    {
        err = "empty CPU set";
        return false;
    }

    out.all = false;
    out.mask = mask;
    return true;
}

inline bool parse_cpu_set(std::string_view spec, cpu_set_spec& out, std::string& err)
{
    return parse_cpu_set(spec, online_cpu_count(), out, err);
}

class io_handler
{
public:
    virtual ~io_handler() = default;
    virtual void on_cqe(struct io_uring_cqe* cqe) = 0;

private:
    friend class event_loop;

    // Slot index in the low bits, registration epoch in the high 16, copied
    // into every submission -- so the loop can ask whether an owner is still
    // there without dereferencing it, which is the question.
    uint32_t m_loop_token{0};
};

// One counter for the whole process, since two live structs must never hold
// the same value, with zero reserved for never stamped.
inline uint32_t next_io_generation()
{
    static uint32_t seq = 0;
    if (SOCKETLEY_UNLIKELY(++seq == 0))
        seq = 1;
    return seq;
}

// io_request::buf_group for a submission that selected no provided buffer,
// outside every valid group id.
inline constexpr uint8_t NO_BUF_GROUP = 0xFF;

// Giving a descriptor number away before the kernel consumes the SQE REDIRECTS
// the operation rather than cancelling it, so event_loop counts submissions per
// number and refuses close, pooling and slot reuse until zero.
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
    op_multishot_accept_direct = 12,  // multishot accept with direct descriptors
    op_read_fixed_buf        = 13,    // read using registered buffer
    op_write_fixed_buf       = 14,    // write using registered buffer
    op_splice                = 15,    // splice between fds through pipe
    op_file_read             = 16,    // async file read via io_uring
    op_connect               = 17,    // async connect via io_uring
    op_health_check          = 18,    // async health check (connect/write/read phases)
    op_poll                  = 19,    // wait for readiness (used to finish a non-blocking connect)
    op_poll_abort            = 20,    // wait for a peer to die (POLLERR/POLLHUP), reading nothing
    // Its own kind because it reports to the splice handler, and because only
    // one of "waiting to splice" and "splicing" costs a kernel thread.
    op_splice_poll           = 21,
    // One completion may carry SEVERAL buffers; the CQE names only the first,
    // and the rest are known to the loop's cursor.
    op_recv_multishot_bundle = 22,
    // Disk operations behind a durable log, usually linked into one chain.
    op_file_write            = 23,
    op_fsync                 = 24,
    op_rename                = 25,
    op_unlink                = 26
};

inline constexpr uint8_t op_type_count = 27;

// For diagnostics only, because a count says an owner cannot be released yet
// and the kind says where to look.
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
        case op_multishot_accept_direct: return "multishot-accept-direct";
        case op_read_fixed_buf:          return "read-fixed-buf";
        case op_write_fixed_buf:         return "write-fixed-buf";
        case op_splice:                  return "splice";
        case op_file_read:               return "file-read";
        case op_connect:                 return "connect";
        case op_health_check:            return "health-check";
        case op_poll:                    return "poll";
        case op_poll_abort:              return "poll-abort";
        case op_splice_poll:             return "splice-poll";
        case op_recv_multishot_bundle:   return "recv-multishot-bundle";
        case op_file_write:              return "file-write";
        case op_fsync:                   return "fsync";
        case op_rename:                  return "rename";
        case op_unlink:                  return "unlink";
        default:                         return "unknown";
    }
}

// A predicate, not a comparison per site: adding the bundle op without this
// cost a hang, because three sites compared against the plain variant alone.
constexpr bool is_multishot_recv_op(op_type t)
{
    return t == op_recv_multishot || t == op_recv_multishot_bundle;
}

// Every op that delivers received bytes, however it was armed.
constexpr bool is_read_op(op_type t)
{
    return t == op_read || t == op_read_provided || is_multishot_recv_op(t);
}

struct io_request
{
    // Initialisers on every member, so default-initialising one is the same
    // as value-initialising it.  That is what lets a connection be built
    // without zero-filling the whole struct -- see socketley::make_connection.
    // Still an aggregate, so `{ this, buf, fd, len, op }` at the call sites is
    // unchanged and `generation` keeps its default.
    io_handler* owner{nullptr};
    char* buffer{nullptr};
    int fd{-1};
    uint32_t length{0};
    op_type type{};

    // Tells a pooled struct's completion from its successor's, which
    // owner_token cannot, and comes from next_io_generation() because a
    // per-struct counter agrees by accident after reuse.
    uint32_t generation{0};

    // Submit-to-complete timing, -DSOCKETLEY_TIMING only; the field is absent
    // otherwise so a shipping build carries no cost for it.
    SKL_TIMING_FIELD


    // Compared against the owner table before dispatch, so a deregistered
    // handler or an old registration on the same slot is dropped.
    uint32_t owner_token{0};

    // So the loop can return the buffer when it drops a completion, read only
    // when the CQE carries IORING_CQE_F_BUFFER.
    uint8_t buf_group{NO_BUF_GROUP};

    // The numbers the SQE named, two because splice names a pipe and a socket,
    // read before dispatch since on_cqe may free this storage.
    uint32_t armed_target{IO_TARGET_NONE};
    uint32_t armed_target2{IO_TARGET_NONE};
};
