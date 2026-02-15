#include "event_loop.h"
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>

event_loop::event_loop(uint32_t queue_depth)
    : m_running(false), m_queue_depth(queue_depth), m_pending_submissions(0)
{
}

event_loop::~event_loop()
{
    for (auto& [gid, pool] : m_buf_rings)
    {
        if (pool.ring)
            io_uring_free_buf_ring(&m_ring, pool.ring, pool.buf_count, gid);
        free(pool.base);
    }
    m_buf_rings.clear();

    if (m_signal_pipe[0] >= 0) close(m_signal_pipe[0]);
    if (m_signal_pipe[1] >= 0) close(m_signal_pipe[1]);
}

bool event_loop::supports_multishot_accept()
{
    struct io_uring ring;
    if (io_uring_queue_init(2, &ring, 0) < 0)
        return false;

    struct io_uring_probe* probe = io_uring_get_probe_ring(&ring);
    bool supported = false;
    if (probe)
    {
        supported = io_uring_opcode_supported(probe, IORING_OP_ACCEPT);
        io_uring_free_probe(probe);
    }
    io_uring_queue_exit(&ring);
    return supported;
}

void event_loop::setup_signal_pipe()
{
    if (pipe(m_signal_pipe) < 0)
        return;

    m_signal_req = { op_read, m_signal_pipe[0], &m_signal_buf, 1, nullptr };

    struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
    if (sqe)
    {
        io_uring_prep_read(sqe, m_signal_pipe[0], &m_signal_buf, 1, 0);
        io_uring_sqe_set_data(sqe, &m_signal_req);
        io_uring_submit(&m_ring);
    }
}

bool event_loop::init()
{
    bool initialized = false;

    // Priority 1: SQPOLL + SINGLE_ISSUER (avoids submit syscalls, needs root)
    {
        struct io_uring_params params{};
        params.flags = IORING_SETUP_SQPOLL | IORING_SETUP_SINGLE_ISSUER;
        params.sq_thread_idle = 1000;
        if (io_uring_queue_init_params(m_queue_depth, &m_ring, &params) == 0)
        {
            m_sqpoll_enabled = true;
            initialized = true;
        }
    }

    // Priority 3: Plain mode
    if (!initialized)
    {
        if (io_uring_queue_init(m_queue_depth, &m_ring, 0) < 0)
            return false;
    }

    m_multishot_supported = supports_multishot_accept();
    setup_signal_pipe();

    return true;
}

void event_loop::flush()
{
    if (m_pending_submissions > 0)
    {
        io_uring_submit(&m_ring);
        m_pending_submissions = 0;
    }
}

void event_loop::process_cqes()
{
    // unused
}

void event_loop::run()
{
    m_running.store(true, std::memory_order_release);

    while (m_running.load(std::memory_order_acquire))
    {
        struct io_uring_cqe* cqe;

        // Flush any pending submissions, then wait
        if (m_pending_submissions > 0)
        {
            io_uring_submit_and_wait(&m_ring, 1);
            m_pending_submissions = 0;
        }
        else
        {
            if (io_uring_wait_cqe(&m_ring, &cqe) < 0)
                break;
        }

        // Batch CQE processing — single io_uring_cq_advance instead of per-CQE atomic
        unsigned head;
        unsigned count = 0;
        bool got_signal = false;

        io_uring_for_each_cqe(&m_ring, head, cqe)
        {
            count++;

            auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));

            if (req == &m_signal_req)
            {
                got_signal = true;
                break;
            }

            if (req && req->owner)
                req->owner->on_cqe(cqe);
        }

        io_uring_cq_advance(&m_ring, count);

        if (got_signal)
        {
            m_running.store(false, std::memory_order_release);
            break;
        }
    }

    io_uring_queue_exit(&m_ring);
}

void event_loop::request_stop()
{
    m_running.store(false, std::memory_order_release);

    if (m_signal_pipe[1] >= 0)
    {
        char c = 1;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
        write(m_signal_pipe[1], &c, 1);
#pragma GCC diagnostic pop
    }
}

int event_loop::get_signal_write_fd() const
{
    return m_signal_pipe[1];
}

struct io_uring* event_loop::get_ring()
{
    return &m_ring;
}

void event_loop::submit_accept(int listen_fd, struct sockaddr_in* addr, socklen_t* addrlen, io_request* req)
{
    struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe)
    {
        flush();
        sqe = io_uring_get_sqe(&m_ring);
        if (!sqe) return;
    }

    io_uring_prep_accept(sqe, listen_fd, reinterpret_cast<struct sockaddr*>(addr), addrlen, 0);
    io_uring_sqe_set_data(sqe, req);
    m_pending_submissions++;
}

void event_loop::submit_multishot_accept(int listen_fd, io_request* req)
{
    struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe)
    {
        flush();
        sqe = io_uring_get_sqe(&m_ring);
        if (!sqe) return;
    }

    if (m_multishot_supported)
    {
        // Multishot: one SQE handles ALL incoming connections
        io_uring_prep_multishot_accept(sqe, listen_fd, nullptr, nullptr, 0);
    }
    else
    {
        io_uring_prep_accept(sqe, listen_fd, nullptr, nullptr, 0);
    }
    io_uring_sqe_set_data(sqe, req);
    m_pending_submissions++;
}

void event_loop::submit_read(int fd, char* buf, uint32_t len, io_request* req)
{
    struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe)
    {
        // Queue full, flush and retry
        flush();
        sqe = io_uring_get_sqe(&m_ring);
        if (!sqe) return;
    }

    io_uring_prep_read(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data(sqe, req);
    m_pending_submissions++;
}

void event_loop::submit_write(int fd, const char* buf, uint32_t len, io_request* req)
{
    struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe)
    {
        // Queue full, flush and retry
        flush();
        sqe = io_uring_get_sqe(&m_ring);
        if (!sqe) return;
    }

    io_uring_prep_write(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data(sqe, req);
    m_pending_submissions++;
}

void event_loop::submit_writev(int fd, struct iovec* iovs, uint32_t count, io_request* req)
{
    struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe)
    {
        flush();
        sqe = io_uring_get_sqe(&m_ring);
        if (!sqe) return;
    }

    io_uring_prep_writev(sqe, fd, iovs, count, 0);
    io_uring_sqe_set_data(sqe, req);
    m_pending_submissions++;
}

void event_loop::submit_recvmsg(int fd, struct msghdr* msg, io_request* req)
{
    struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe)
    {
        flush();
        sqe = io_uring_get_sqe(&m_ring);
        if (!sqe) return;
    }

    io_uring_prep_recvmsg(sqe, fd, msg, 0);
    io_uring_sqe_set_data(sqe, req);
    m_pending_submissions++;
}

bool event_loop::setup_buf_ring(uint16_t group_id, uint32_t buf_count, uint32_t buf_size)
{
    // Already registered — reuse
    if (m_buf_rings.count(group_id))
        return true;

    int ret;
    struct io_uring_buf_ring* br = io_uring_setup_buf_ring(&m_ring, buf_count, group_id, 0, &ret);
    if (!br)
        return false;

    char* base = static_cast<char*>(malloc(static_cast<size_t>(buf_count) * buf_size));
    if (!base)
    {
        io_uring_free_buf_ring(&m_ring, br, buf_count, group_id);
        return false;
    }

    // Register all buffers
    for (uint32_t i = 0; i < buf_count; i++)
    {
        io_uring_buf_ring_add(br, base + (i * buf_size), buf_size, static_cast<uint16_t>(i),
            io_uring_buf_ring_mask(buf_count), static_cast<int>(i));
    }
    io_uring_buf_ring_advance(br, buf_count);

    m_buf_rings[group_id] = { br, base, buf_count, buf_size };
    return true;
}

void event_loop::submit_read_provided(int fd, uint16_t group_id, io_request* req)
{
    auto it = m_buf_rings.find(group_id);
    if (it == m_buf_rings.end())
        return;

    struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe)
    {
        flush();
        sqe = io_uring_get_sqe(&m_ring);
        if (!sqe) return;
    }

    io_uring_prep_read(sqe, fd, nullptr, it->second.buf_size, 0);
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = group_id;
    io_uring_sqe_set_data(sqe, req);
    req->type = op_read_provided;
    m_pending_submissions++;
}

char* event_loop::get_buf_ptr(uint16_t group_id, uint16_t buf_id)
{
    auto it = m_buf_rings.find(group_id);
    if (it == m_buf_rings.end())
        return nullptr;

    auto& pool = it->second;
    if (buf_id >= pool.buf_count)
        return nullptr;

    return pool.base + (static_cast<size_t>(buf_id) * pool.buf_size);
}

void event_loop::return_buf(uint16_t group_id, uint16_t buf_id)
{
    auto it = m_buf_rings.find(group_id);
    if (it == m_buf_rings.end())
        return;

    auto& pool = it->second;
    io_uring_buf_ring_add(pool.ring,
        pool.base + (static_cast<size_t>(buf_id) * pool.buf_size),
        pool.buf_size, buf_id,
        io_uring_buf_ring_mask(pool.buf_count), 0);
    io_uring_buf_ring_advance(pool.ring, 1);
}

bool event_loop::has_buf_ring(uint16_t group_id) const
{
    return m_buf_rings.count(group_id) > 0;
}
