#pragma once
#include <atomic>
#include <cstdint>
#include <liburing.h>
#include <netinet/in.h>

#include "event_loop_definitions.h"

struct buf_ring_pool
{
    struct io_uring_buf_ring* ring{nullptr};
    char* base{nullptr};
    uint32_t buf_count{0};
    uint32_t buf_size{0};
};

class event_loop
{
public:
    explicit event_loop(uint32_t queue_depth = 2048);
    ~event_loop();

    bool init();
    void run();
    void request_stop();
    int get_signal_write_fd() const;

    // Batched submissions - these queue SQEs without submitting
    void submit_accept(int listen_fd, struct sockaddr_in* addr, socklen_t* addrlen, io_request* req);
    void submit_multishot_accept(int listen_fd, io_request* req);
    // Direct-descriptor multishot accept: accepted fds go straight into the
    // fixed file table at IORING_FILE_INDEX_ALLOC, skipping the process fd table.
    void submit_multishot_accept_direct(int listen_fd, io_request* req);
    void submit_read(int fd, char* buf, uint32_t len, io_request* req);
    void submit_write(int fd, const char* buf, uint32_t len, io_request* req);
    void submit_writev(int fd, struct iovec* iovs, uint32_t count, io_request* req);
    void submit_recvmsg(int fd, struct msghdr* msg, io_request* req);
    void submit_timeout(struct __kernel_timespec* ts, io_request* req);

    // Fixed-file variants: use registered fd index instead of raw fd.
    // Avoids fget/fput per I/O op (hot path).
    void submit_read_fixed_file(int fixed_idx, char* buf, uint32_t len, io_request* req);
    void submit_write_fixed_file(int fixed_idx, const char* buf, uint32_t len, io_request* req);

    // Registered buffers: eliminate copy_from_user/copy_to_user per I/O op.
    bool register_buffers(const struct iovec* iovs, uint32_t count);
    void unregister_buffers();
    void submit_read_fixed_buf(int fd, char* buf, uint32_t len, uint16_t buf_idx, io_request* req);
    void submit_write_fixed_buf(int fd, const char* buf, uint32_t len, uint16_t buf_idx, io_request* req);
    bool buffers_registered() const { return m_bufs_registered; }

    // Provided buffer ring API
    bool setup_buf_ring(uint16_t group_id, uint32_t buf_count, uint32_t buf_size);
    void submit_read_provided(int fd, uint16_t group_id, io_request* req);
    // Cancel all pending io_uring ops for a fd (user_data=null, CQE is ignored).
    // Submit this BEFORE close(fd) to guarantee the kernel generates cancellation
    // CQEs before any subsequently-submitted timeout/cleanup SQE fires.
    void submit_cancel_fd(int fd);
    char* get_buf_ptr(uint16_t group_id, uint16_t buf_id);
    void return_buf(uint16_t group_id, uint16_t buf_id);
    void return_bufs_batch(uint16_t group_id, const uint16_t* buf_ids, uint32_t count);
    bool has_buf_ring(uint16_t group_id) const;

    // Multishot recv: single SQE generates multiple CQEs until error or cancel.
    // Uses provided buffer ring. Resubmit only when !(cqe->flags & IORING_CQE_F_MORE).
    void submit_recv_multishot(int fd, uint16_t group_id, io_request* req);
    bool recv_multishot_supported() const;

    // Zero-copy send: kernel DMAs directly from user buffer.
    // Generates TWO CQEs: completion + notification (IORING_CQE_F_NOTIF).
    // Buffer must stay alive until NOTIF CQE arrives.
    void submit_send_zc(int fd, const char* buf, uint32_t len, io_request* req);
    bool send_zc_supported() const;

    // Registered files: pre-register fds to avoid fget/fput per op
    bool register_files(const int* fds, uint32_t count);
    bool update_registered_file(uint32_t idx, int fd);
    void unregister_files();
    bool files_registered() const { return m_files_registered; }
    uint32_t registered_file_count() const { return m_registered_file_count; }

    // Allocate a slot in the registered file table, returns index or -1
    int alloc_fixed_file_slot();
    void free_fixed_file_slot(uint32_t idx);

    // Splice: zero-copy data transfer between two fds through a pipe.
    // fd_in -> fd_out, len bytes, off_in/off_out = -1 for pipes/sockets.
    void submit_splice(int fd_in, int fd_out, uint32_t len, io_request* req);

    // Async file read: uses io_uring_prep_read (not recv) for regular files.
    // req->fd should be set to the *socket* fd for CQE dispatch routing.
    void submit_file_read(int file_fd, char* buf, uint32_t len, uint64_t offset, io_request* req);

    // Async connect: non-blocking connect via io_uring.
    // CQE res is 0 on success, negative errno on failure.
    void submit_connect(int fd, const struct sockaddr* addr, socklen_t len, io_request* req);

    // Flush all pending submissions (single syscall)
    void flush();

    struct io_uring* get_ring();

    // Check if multishot accept is supported
    static bool supports_multishot_accept();

    // Feature queries
    bool sqpoll_enabled() const { return m_sqpoll_enabled; }
    bool direct_accept_supported() const { return m_direct_accept_supported; }

private:
    struct io_uring_sqe* get_sqe();
    void setup_signal_pipe();

    struct io_uring m_ring{};
    std::atomic<bool> m_running;
    uint32_t m_queue_depth;
    uint32_t m_pending_submissions{0};
    int m_signal_pipe[2]{-1, -1};
    io_request m_signal_req{};
    char m_signal_buf{};
    bool m_multishot_supported{false};
    bool m_sqpoll_enabled{false};
    bool m_send_zc_supported{false};
    bool m_recv_multishot_supported{false};
    bool m_files_registered{false};
    bool m_bufs_registered{false};
    bool m_direct_accept_supported{false};
    uint32_t m_registered_file_count{0};

    // Fixed file slot allocation (bitmap-based)
    static constexpr uint32_t MAX_FIXED_FILES = 8192;
    // Each uint64_t covers 64 slots; 8192/64 = 128 words
    static constexpr uint32_t BITMAP_WORDS = MAX_FIXED_FILES / 64;
    uint64_t m_file_bitmap[BITMAP_WORDS]{};
    uint32_t m_file_bitmap_hint{0};  // hint for next scan start

    static constexpr uint16_t MAX_BUF_GROUPS = 8;
    buf_ring_pool m_buf_rings[MAX_BUF_GROUPS]{};
};
