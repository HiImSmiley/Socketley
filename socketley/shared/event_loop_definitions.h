#pragma once
#include <cstdint>

class io_handler
{
public:
    virtual ~io_handler() = default;
    virtual void on_cqe(struct io_uring_cqe* cqe) = 0;
};

enum op_type : uint8_t
{
    op_accept           = 0,
    op_read             = 1,
    op_write            = 2,
    op_nop              = 3,
    op_multishot_accept = 4,
    op_read_provided    = 5,
    op_writev           = 6,
    op_recvmsg          = 7
};

struct io_request
{
    op_type type;
    int fd;
    char* buffer;
    uint32_t length;
    io_handler* owner;
};
