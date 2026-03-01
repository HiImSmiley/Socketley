#include "event_loop.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sched.h>


event_loop::event_loop(uint32_t queue_depth)
    : m_running(false), m_queue_depth(queue_depth), m_pending_submissions(0)
{
}

event_loop::~event_loop()
{
    for (uint16_t gid = 0; gid < MAX_BUF_GROUPS; ++gid)
    {
        auto& pool = m_buf_rings[gid];
        if (pool.ring)
            io_uring_free_buf_ring(&m_ring, pool.ring, pool.buf_count, gid);
        free(pool.base);
    }

    if (m_bufs_registered)
        io_uring_unregister_buffers(&m_ring);

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
    // O_NONBLOCK prevents the signal write from blocking if the pipe buffer
    // is somehow full (shouldn't happen, but defensive).  O_CLOEXEC prevents
    // leaking fds to child processes.
    if (pipe2(m_signal_pipe, O_NONBLOCK | O_CLOEXEC) < 0)
        return;

    m_signal_req = { nullptr, &m_signal_buf, m_signal_pipe[0], 1, op_read };

    struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
    if (sqe)
    {
        io_uring_prep_read(sqe, m_signal_pipe[0], &m_signal_buf, 1, 0);
        io_uring_sqe_set_data(sqe, &m_signal_req);
        io_uring_submit(&m_ring);
    }
}

// Centralized SQE acquisition: get an SQE, flushing if the ring is full.
// The fast path (SQE available) is branch-predicted; the flush path is cold.
// After flush, retry once — if still null the SQ is genuinely full (shouldn't
// happen at our queue depths, but defensive).
inline struct io_uring_sqe* event_loop::get_sqe()
{
    struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
    if (__builtin_expect(!sqe, 0))
    {
        io_uring_submit(&m_ring);
        m_pending_submissions = 0;
        sqe = io_uring_get_sqe(&m_ring);
    }
    return sqe;
}

bool event_loop::init()
{
    bool initialized = false;

    // Priority 1: SQPOLL + SINGLE_ISSUER (avoids submit syscalls, needs root)
    {
        struct io_uring_params params{};
        params.flags = IORING_SETUP_SQPOLL | IORING_SETUP_SINGLE_ISSUER
                     | IORING_SETUP_SUBMIT_ALL;
        // Tuned sq_thread_idle: 2000ms keeps the SQPOLL thread alive longer during
        // bursty traffic, avoiding the cost of waking it back up.  The SQPOLL thread
        // consumes ~0 CPU when idle (it sleeps on a waitqueue), so a longer idle
        // timeout is essentially free.
        params.sq_thread_idle = 2000;
        // Oversized CQ: 4x SQ depth avoids CQ overflow under burst
        params.flags |= IORING_SETUP_CQSIZE;
        params.cq_entries = m_queue_depth * 4;
        if (io_uring_queue_init_params(m_queue_depth, &m_ring, &params) == 0)
        {
            m_sqpoll_enabled = true;
            initialized = true;
        }
    }

    // Priority 2: SINGLE_ISSUER + DEFER_TASKRUN (defers task_work to
    // io_uring_enter, avoiding async interrupts; needs kernel 6.1+)
    if (!initialized)
    {
        struct io_uring_params p2{};
        p2.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN
                 | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_COOP_TASKRUN;
        p2.flags |= IORING_SETUP_CQSIZE;
        p2.cq_entries = m_queue_depth * 4;
        if (io_uring_queue_init_params(m_queue_depth, &m_ring, &p2) == 0)
            initialized = true;
    }

    // Priority 3: Plain mode
    if (!initialized)
    {
        if (io_uring_queue_init(m_queue_depth, &m_ring, 0) < 0)
            return false;
    }

    // Register the ring fd itself: eliminates an fget/fput per io_uring
    // syscall (submit, wait, enter).  ~1-3% throughput improvement.
    io_uring_register_ring_fd(&m_ring);

    m_multishot_supported = supports_multishot_accept();

    // Probe for advanced io_uring features
    {
        struct io_uring_probe* probe = io_uring_get_probe_ring(&m_ring);
        if (probe)
        {
            m_send_zc_supported = io_uring_opcode_supported(probe, IORING_OP_SEND_ZC);
            m_recv_multishot_supported = io_uring_opcode_supported(probe, IORING_OP_RECV);
            io_uring_free_probe(probe);
        }
    }

    // Pre-register a sparse fixed file table for direct-descriptor accept
    // and fixed-file I/O.  All slots start as -1 (empty).
    // Heap-allocated to avoid 32KB stack frame.
    {
        int* sparse_fds = static_cast<int*>(malloc(MAX_FIXED_FILES * sizeof(int)));
        if (sparse_fds)
        {
            std::memset(sparse_fds, 0xFF, MAX_FIXED_FILES * sizeof(int)); // -1 in every slot
            int ret = io_uring_register_files(&m_ring, sparse_fds, MAX_FIXED_FILES);
            free(sparse_fds);
            if (ret == 0)
            {
                m_files_registered = true;
                m_registered_file_count = MAX_FIXED_FILES;
                m_direct_accept_supported = m_multishot_supported;
                // Bitmap: all zeros means all slots are free
                std::memset(m_file_bitmap, 0, sizeof(m_file_bitmap));
                m_file_bitmap_hint = 0;
            }
        }
    }

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

void event_loop::run()
{
    m_running.store(true, std::memory_order_release);

    struct io_uring_cqe* cqe;

    while (__builtin_expect(m_running.load(std::memory_order_relaxed), 1))
    {
        // Flush any pending submissions, then ensure at least one CQE is ready.
        // Peek first -- if CQEs from the previous iteration's submitted SQEs already
        // landed (common at high throughput), skip the blocking wait entirely.
        if (m_pending_submissions > 0)
        {
            if (__builtin_expect(m_sqpoll_enabled, 1))
                io_uring_submit(&m_ring);  // SQPOLL: tail update only, no syscall
            else
                io_uring_submit_and_wait(&m_ring, 1);
            m_pending_submissions = 0;
        }

        if (io_uring_peek_cqe(&m_ring, &cqe) != 0)
        {
            // Ring is empty: block until at least one CQE arrives
            if (io_uring_wait_cqe(&m_ring, &cqe) < 0)
                break;
        }

        // Batch-drain all available CQEs in one pass -- single io_uring_cq_advance.
        // We prefetch the NEXT CQE's user_data while processing the current one,
        // hiding the L2/L3 cache-miss latency on the io_request pointer.
        unsigned head;
        unsigned count = 0;
        bool got_signal = false;

        io_uring_for_each_cqe(&m_ring, head, cqe)
        {
            count++;

            auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));

            if (__builtin_expect(req == &m_signal_req, 0))
            {
                got_signal = true;
                break;
            }

            if (__builtin_expect(req != nullptr && req->owner != nullptr, 1))
                req->owner->on_cqe(cqe);
        }

        io_uring_cq_advance(&m_ring, count);

        if (__builtin_expect(got_signal, 0))
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
        if (write(m_signal_pipe[1], &c, 1) < 0) {}
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
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;

    io_uring_prep_accept(sqe, listen_fd, reinterpret_cast<struct sockaddr*>(addr), addrlen, 0);
    io_uring_sqe_set_data(sqe, req);
    m_pending_submissions++;
}

void event_loop::submit_multishot_accept(int listen_fd, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;

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

void event_loop::submit_multishot_accept_direct(int listen_fd, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;

    if (m_multishot_supported && m_files_registered)
    {
        // Direct-descriptor multishot accept: accepted fds go straight into
        // the fixed file table, skipping the per-process fd table entirely.
        // cqe->res will contain the fixed file index, not an fd number.
        io_uring_prep_multishot_accept(sqe, listen_fd, nullptr, nullptr, 0);
        sqe->file_index = IORING_FILE_INDEX_ALLOC;
    }
    else if (m_multishot_supported)
    {
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
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;

    // recv() is more efficient than read() for sockets: skips VFS layer,
    // avoids file-position locking, and enables MSG_NOSIGNAL
    io_uring_prep_recv(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data(sqe, req);
    m_pending_submissions++;
}

void event_loop::submit_write(int fd, const char* buf, uint32_t len, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;

    // send() with MSG_NOSIGNAL: avoids SIGPIPE if peer closed the connection
    // between our check and the actual send, without needing a global signal mask.
    io_uring_prep_send(sqe, fd, buf, len, MSG_NOSIGNAL);
    io_uring_sqe_set_data(sqe, req);
    m_pending_submissions++;
}

void event_loop::submit_writev(int fd, struct iovec* iovs, uint32_t count, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;

    io_uring_prep_writev(sqe, fd, iovs, count, 0);
    io_uring_sqe_set_data(sqe, req);
    m_pending_submissions++;
}

void event_loop::submit_recvmsg(int fd, struct msghdr* msg, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;

    io_uring_prep_recvmsg(sqe, fd, msg, 0);
    io_uring_sqe_set_data(sqe, req);
    m_pending_submissions++;
}

void event_loop::submit_timeout(struct __kernel_timespec* ts, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;

    io_uring_prep_timeout(sqe, ts, 0, 0);
    io_uring_sqe_set_data(sqe, req);
    m_pending_submissions++;
}

void event_loop::submit_cancel_fd(int fd)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;

    // IORING_ASYNC_CANCEL_ALL cancels ALL pending ops for this fd in one shot.
    // Without it, only one op is cancelled per SQE -- leaving the second CQE
    // (e.g. a write when read is also pending) to arrive after the deferred-
    // delete timeout fires and the owning object is freed.
    io_uring_prep_cancel_fd(sqe, fd, IORING_ASYNC_CANCEL_ALL);
    // Null user_data so the cancel-result CQE is silently discarded by event_loop::run()
    io_uring_sqe_set_data(sqe, nullptr);
    m_pending_submissions++;
}

// Fixed-file variants: use the IOSQE_FIXED_FILE flag so the kernel uses
// the pre-registered file reference, skipping fget/fput per I/O op.
void event_loop::submit_read_fixed_file(int fixed_idx, char* buf, uint32_t len, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;

    io_uring_prep_recv(sqe, fixed_idx, buf, len, 0);
    sqe->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data(sqe, req);
    m_pending_submissions++;
}

void event_loop::submit_write_fixed_file(int fixed_idx, const char* buf, uint32_t len, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;

    io_uring_prep_send(sqe, fixed_idx, buf, len, MSG_NOSIGNAL);
    sqe->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data(sqe, req);
    m_pending_submissions++;
}

// Registered buffers: the kernel pins these pages and skips
// copy_from_user/copy_to_user on each I/O operation.
bool event_loop::register_buffers(const struct iovec* iovs, uint32_t count)
{
    if (m_bufs_registered)
        return false;

    int ret = io_uring_register_buffers(&m_ring, iovs, count);
    if (ret < 0)
        return false;

    m_bufs_registered = true;
    return true;
}

void event_loop::unregister_buffers()
{
    if (m_bufs_registered)
    {
        io_uring_unregister_buffers(&m_ring);
        m_bufs_registered = false;
    }
}

void event_loop::submit_read_fixed_buf(int fd, char* buf, uint32_t len, uint16_t buf_idx, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;

    io_uring_prep_read_fixed(sqe, fd, buf, len, 0, buf_idx);
    io_uring_sqe_set_data(sqe, req);
    req->type = op_read_fixed_buf;
    m_pending_submissions++;
}

void event_loop::submit_write_fixed_buf(int fd, const char* buf, uint32_t len, uint16_t buf_idx, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;

    io_uring_prep_write_fixed(sqe, fd, buf, len, 0, buf_idx);
    io_uring_sqe_set_data(sqe, req);
    req->type = op_write_fixed_buf;
    m_pending_submissions++;
}

bool event_loop::setup_buf_ring(uint16_t group_id, uint32_t buf_count, uint32_t buf_size)
{
    if (group_id >= MAX_BUF_GROUPS)
        return false;

    // Already registered -- reuse
    if (m_buf_rings[group_id].ring)
        return true;

    int ret;
    struct io_uring_buf_ring* br = io_uring_setup_buf_ring(&m_ring, buf_count, group_id, 0, &ret);
    if (!br)
        return false;

    size_t total = static_cast<size_t>(buf_count) * buf_size;
    // Align to huge page boundary (2MB) for better TLB coverage on the hot-path
    // buffer pool.  Falls back to 4K alignment if the allocation is small.
    size_t align = (total >= 2 * 1024 * 1024) ? (2 * 1024 * 1024) : 4096;
    size_t alloc_size = (total + align - 1) & ~(align - 1);
    char* base = static_cast<char*>(aligned_alloc(align, alloc_size));
    if (!base)
    {
        io_uring_free_buf_ring(&m_ring, br, buf_count, group_id);
        return false;
    }

    // Prefault pages with madvise to avoid minor page faults on first access
    if (madvise(base, alloc_size, MADV_WILLNEED) < 0) {}
    // Request huge pages if available (transparent, no error on failure)
    if (alloc_size >= 2 * 1024 * 1024)
    {
        if (madvise(base, alloc_size, MADV_HUGEPAGE) < 0) {}
    }

    // Touch all pages to prefault them
    for (size_t i = 0; i < alloc_size; i += 4096)
    {
        volatile char touch = base[i];
        (void)touch;
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
    if (group_id >= MAX_BUF_GROUPS || !m_buf_rings[group_id].ring)
        return;

    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;

    io_uring_prep_recv(sqe, fd, nullptr, m_buf_rings[group_id].buf_size, 0);
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = group_id;
    io_uring_sqe_set_data(sqe, req);
    req->type = op_read_provided;
    m_pending_submissions++;
}

char* event_loop::get_buf_ptr(uint16_t group_id, uint16_t buf_id)
{
    if (__builtin_expect(group_id >= MAX_BUF_GROUPS, 0))
        return nullptr;

    auto& pool = m_buf_rings[group_id];
    if (__builtin_expect(!pool.ring || buf_id >= pool.buf_count, 0))
        return nullptr;

    return pool.base + (static_cast<size_t>(buf_id) * pool.buf_size);
}

void event_loop::return_buf(uint16_t group_id, uint16_t buf_id)
{
    if (__builtin_expect(group_id >= MAX_BUF_GROUPS, 0))
        return;

    auto& pool = m_buf_rings[group_id];
    if (__builtin_expect(!pool.ring, 0))
        return;

    io_uring_buf_ring_add(pool.ring,
        pool.base + (static_cast<size_t>(buf_id) * pool.buf_size),
        pool.buf_size, buf_id,
        io_uring_buf_ring_mask(pool.buf_count), 0);
    io_uring_buf_ring_advance(pool.ring, 1);
}

void event_loop::return_bufs_batch(uint16_t group_id, const uint16_t* buf_ids, uint32_t count)
{
    if (__builtin_expect(group_id >= MAX_BUF_GROUPS, 0))
        return;
    auto& pool = m_buf_rings[group_id];
    if (__builtin_expect(!pool.ring, 0))
        return;
    for (uint32_t i = 0; i < count; i++)
    {
        uint16_t bid = buf_ids[i];
        io_uring_buf_ring_add(pool.ring,
            pool.base + (static_cast<size_t>(bid) * pool.buf_size),
            pool.buf_size, bid,
            io_uring_buf_ring_mask(pool.buf_count), 0);
    }
    io_uring_buf_ring_advance(pool.ring, count);
}

bool event_loop::has_buf_ring(uint16_t group_id) const
{
    return group_id < MAX_BUF_GROUPS && m_buf_rings[group_id].ring != nullptr;
}

bool event_loop::recv_multishot_supported() const
{
    return m_recv_multishot_supported;
}

bool event_loop::send_zc_supported() const
{
    return m_send_zc_supported;
}

void event_loop::submit_recv_multishot(int fd, uint16_t group_id, io_request* req)
{
    if (group_id >= MAX_BUF_GROUPS || !m_buf_rings[group_id].ring)
        return;

    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;

    io_uring_prep_recv_multishot(sqe, fd, nullptr, 0, 0);
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = group_id;
    io_uring_sqe_set_data(sqe, req);
    req->type = op_recv_multishot;
    m_pending_submissions++;
}

void event_loop::submit_send_zc(int fd, const char* buf, uint32_t len, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;

    io_uring_prep_send_zc(sqe, fd, buf, len, MSG_NOSIGNAL, 0);
    io_uring_sqe_set_data(sqe, req);
    req->type = op_send_zc;
    m_pending_submissions++;
}

void event_loop::submit_splice(int fd_in, int fd_out, uint32_t len, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;

    // off_in = off_out = -1 for pipes/sockets (no seekable offset)
    io_uring_prep_splice(sqe, fd_in, -1, fd_out, -1, len, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    io_uring_sqe_set_data(sqe, req);
    req->type = op_splice;
    m_pending_submissions++;
}

void event_loop::submit_file_read(int file_fd, char* buf, uint32_t len, uint64_t offset, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;

    // Use io_uring_prep_read (not recv) — works on regular files
    io_uring_prep_read(sqe, file_fd, buf, len, offset);
    io_uring_sqe_set_data(sqe, req);
    req->type = op_file_read;
    m_pending_submissions++;
}

void event_loop::submit_connect(int fd, const struct sockaddr* addr, socklen_t len, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;

    io_uring_prep_connect(sqe, fd, addr, len);
    io_uring_sqe_set_data(sqe, req);
    m_pending_submissions++;
}

bool event_loop::register_files(const int* fds, uint32_t count)
{
    if (m_files_registered)
        return false;

    int ret = io_uring_register_files(&m_ring, fds, count);
    if (ret < 0)
        return false;

    m_files_registered = true;
    m_registered_file_count = count;
    return true;
}

bool event_loop::update_registered_file(uint32_t idx, int fd)
{
    if (!m_files_registered || idx >= m_registered_file_count)
        return false;

    int ret = io_uring_register_files_update(&m_ring, idx, &fd, 1);
    return ret >= 0;
}

void event_loop::unregister_files()
{
    if (m_files_registered)
    {
        io_uring_unregister_files(&m_ring);
        m_files_registered = false;
        m_registered_file_count = 0;
    }
}

// Bitmap-based fixed file slot allocator.
// Returns the index of a free slot, or -1 if full.
int event_loop::alloc_fixed_file_slot()
{
    if (!m_files_registered)
        return -1;

    // Start scanning from the hint (the word where the last free was found)
    for (uint32_t i = 0; i < BITMAP_WORDS; i++)
    {
        uint32_t w = (m_file_bitmap_hint + i) % BITMAP_WORDS;
        if (m_file_bitmap[w] != ~0ULL)
        {
            // Find the first zero bit
            int bit = __builtin_ctzll(~m_file_bitmap[w]);
            m_file_bitmap[w] |= (1ULL << bit);
            m_file_bitmap_hint = w;
            return static_cast<int>(w * 64 + static_cast<uint32_t>(bit));
        }
    }
    return -1; // All slots occupied
}

void event_loop::free_fixed_file_slot(uint32_t idx)
{
    if (idx >= MAX_FIXED_FILES)
        return;
    uint32_t w = idx / 64;
    uint32_t bit = idx % 64;
    m_file_bitmap[w] &= ~(1ULL << bit);
    // Update hint to this word since it now has a free slot
    m_file_bitmap_hint = w;

    // Unregister the fd from the kernel's fixed file table
    int neg = -1;
    if (m_files_registered)
    {
        if (io_uring_register_files_update(&m_ring, idx, &neg, 1) < 0) {}
    }
}
