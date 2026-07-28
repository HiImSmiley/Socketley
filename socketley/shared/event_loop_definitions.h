#pragma once
#include <cstdint>

// Branch prediction hints for hot-path optimization
#ifndef SOCKETLEY_LIKELY
#define SOCKETLEY_LIKELY(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef SOCKETLEY_UNLIKELY
#define SOCKETLEY_UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif

class io_handler
{
public:
    virtual ~io_handler() = default;
    virtual void on_cqe(struct io_uring_cqe* cqe) = 0;
};

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
    op_health_check          = 18     // async health check (connect/write/read phases)
};

struct io_request
{
    io_handler* owner;
    char* buffer;
    int fd;
    uint32_t length;
    op_type type;
};
