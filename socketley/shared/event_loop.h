#pragma once
#include <atomic>
#include <cstdint>
#include <liburing.h>
#include <netinet/in.h>
#include <sys/socket.h>

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

    // ── Owner registration ──────────────────────────────────────────────────
    // The loop delivers a completion only while the handler that submitted it
    // is still the handler that owns it.  Registration hands out that identity;
    // deregistration revokes it, and from that moment every completion still in
    // the ring for that handler is dropped — with whatever it carries released
    // — instead of dispatched.
    //
    // Registration is implicit: the first submission from an unregistered
    // handler registers it.  Nothing has to remember to call this, because
    // forgetting to would mean the loop silently swallowing all of that
    // handler's I/O — a far worse failure than forgetting to deregister, which
    // only costs the check.  Call it explicitly when the identity is wanted
    // before the first submission.  Idempotent.
    uint32_t register_owner(io_handler* owner);

    // Call when the handler can no longer service a completion: a runtime that
    // has torn down, a timer about to free itself.  A handler that frees itself
    // from inside its own on_cqe must deregister there and not earlier —
    // deregistering while its last completion is still in flight means that
    // completion is dropped and the callback that would have freed it never
    // runs.
    void deregister_owner(io_handler* owner);

    bool owner_registered(const io_handler* owner) const;

    // Submissions by this handler that are still owed a final completion, over
    // every registration it has held.  Zero means no request the handler
    // submitted is still in the ring, so the storage those requests live in —
    // the handler itself, the connection structs it kept alive for exactly this
    // reason — can finally be freed.  Note that dropping a completion still
    // reads the request it points at, so "deregistered" is not on its own a
    // licence to free that storage; this reaching zero is.
    uint32_t owner_inflight(const io_handler* owner) const;

    // The same figure broken down by operation kind, summed over every
    // registration the handler has held.  out must hold op_type_count entries.
    // A count alone says an owner cannot be released; the kind says why.
    void owner_inflight_breakdown(const io_handler* owner, uint32_t* out) const;

    // True once the owner table has run out and handlers began sharing one
    // identity.  From that point owner_inflight() cannot answer for any single
    // one of them — it reports zero for a handler that never got a slot, which
    // is indistinguishable from a handler that has fully drained.  A caller
    // that frees storage on the strength of a zero has to stop doing so.
    bool owner_table_full() const { return m_owner_table_full_logged; }

    // Give back the provided buffer a completion is carrying, for a caller that
    // is about to drop that completion — a connection index that no longer
    // resolves, a handler that cannot place the request.  A buffer dropped with
    // its completion never comes back to the group, and the groups are shared
    // by every instance of a runtime type on this loop, so one instance leaking
    // them starves all of them.  No-op unless the completion actually carries
    // one.
    void return_cqe_buf(const struct io_uring_cqe* cqe, const io_request* req);

    // Batched submissions - these queue SQEs without submitting
    // The submit_* helpers return false when no SQE could be obtained even after
    // flushing the ring.  Nothing is queued in that case, so a caller that has
    // already marked an operation in flight must undo that and give up on the
    // connection — otherwise nothing will ever complete for it and it hangs
    // until the runtime stops.
    bool submit_accept(int listen_fd, struct sockaddr_in* addr, socklen_t* addrlen, io_request* req);
    bool submit_multishot_accept(int listen_fd, io_request* req);
    // Direct-descriptor multishot accept: accepted fds go straight into the
    // fixed file table at IORING_FILE_INDEX_ALLOC, skipping the process fd table.
    bool submit_multishot_accept_direct(int listen_fd, io_request* req);
    bool submit_read(int fd, char* buf, uint32_t len, io_request* req);
    bool submit_write(int fd, const char* buf, uint32_t len, io_request* req);
    bool submit_writev(int fd, struct iovec* iovs, uint32_t count, io_request* req);
    bool submit_sendmsg(int fd, struct msghdr* msg, io_request* req);
    bool submit_recvmsg(int fd, struct msghdr* msg, io_request* req);
    bool submit_timeout(struct __kernel_timespec* ts, io_request* req);

    // Fixed-file variants: use registered fd index instead of raw fd.
    // Avoids fget/fput per I/O op (hot path).
    bool submit_read_fixed_file(int fixed_idx, char* buf, uint32_t len, io_request* req);
    bool submit_write_fixed_file(int fixed_idx, const char* buf, uint32_t len, io_request* req);
    bool submit_writev_fixed_file(int fixed_idx, struct iovec* iovs, uint32_t count, io_request* req);
    bool submit_sendmsg_fixed_file(int fixed_idx, struct msghdr* msg, io_request* req);
    bool submit_recv_multishot_fixed_file(int fixed_idx, uint16_t group_id, io_request* req);
    bool submit_read_provided_fixed_file(int fixed_idx, uint16_t group_id, io_request* req);
    bool submit_send_zc_fixed_file(int fixed_idx, const char* buf, uint32_t len, io_request* req);

    // Registered buffers: eliminate copy_from_user/copy_to_user per I/O op.
    bool register_buffers(const struct iovec* iovs, uint32_t count);
    void unregister_buffers();
    bool submit_read_fixed_buf(int fd, char* buf, uint32_t len, uint16_t buf_idx, io_request* req);
    bool submit_write_fixed_buf(int fd, const char* buf, uint32_t len, uint16_t buf_idx, io_request* req);
    bool buffers_registered() const { return m_bufs_registered; }

    // Provided buffer ring API
    bool setup_buf_ring(uint16_t group_id, uint32_t buf_count, uint32_t buf_size);
    bool submit_read_provided(int fd, uint16_t group_id, io_request* req);
    // Cancel all pending io_uring ops for a fd (user_data=null, CQE is ignored).
    // Submit this BEFORE close(fd) to guarantee the kernel generates cancellation
    // CQEs before any subsequently-submitted timeout/cleanup SQE fires.
    bool submit_cancel_fd(int fd);
    char* get_buf_ptr(uint16_t group_id, uint16_t buf_id);
    void return_buf(uint16_t group_id, uint16_t buf_id);
    void return_bufs_batch(uint16_t group_id, const uint16_t* buf_ids, uint32_t count);
    bool has_buf_ring(uint16_t group_id) const;

    // Multishot recv: single SQE generates multiple CQEs until error or cancel.
    // Uses provided buffer ring. Resubmit only when !(cqe->flags & IORING_CQE_F_MORE).
    bool submit_recv_multishot(int fd, uint16_t group_id, io_request* req);
    bool recv_multishot_supported() const;

    // Zero-copy send: kernel DMAs directly from user buffer.
    // Generates TWO CQEs: completion + notification (IORING_CQE_F_NOTIF).
    // Buffer must stay alive until NOTIF CQE arrives.
    bool submit_send_zc(int fd, const char* buf, uint32_t len, io_request* req);
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
    bool submit_splice(int fd_in, int fd_out, uint32_t len, io_request* req);

    // Async file read: uses io_uring_prep_read (not recv) for regular files.
    // req->fd should be set to the *socket* fd for CQE dispatch routing.
    bool submit_file_read(int file_fd, char* buf, uint32_t len, uint64_t offset, io_request* req);

    // Async connect: non-blocking connect via io_uring.
    // CQE res is 0 on success, negative errno on failure.
    bool submit_connect(int fd, const struct sockaddr* addr, socklen_t len, io_request* req);

    // Wait for readiness on an fd.  A connect() that returned EINPROGRESS is
    // finished by polling for POLLOUT and then reading SO_ERROR — issuing a
    // second connect on the same socket instead only ever answers EISCONN.
    bool submit_poll_add(int fd, unsigned mask, io_request* req);

    // Flush all pending submissions (single syscall)
    void flush();

    struct io_uring* get_ring();

    // Check if multishot accept is supported
    static bool supports_multishot_accept();

    // NAPI busy polling: reduce latency by busy-polling the NIC driver.
    bool enable_napi_busy_poll(uint32_t busy_poll_usec, bool prefer = false);

    // Feature queries
    bool sqpoll_enabled() const { return m_sqpoll_enabled; }
    bool direct_accept_supported() const { return m_direct_accept_supported; }

private:
    struct io_uring_sqe* get_sqe();
    void setup_eventfd();

    // Stamp the owner identity onto a submission, count it as outstanding and
    // count it towards the next flush.  Every submit_* helper ends with this.
    void arm(io_request* req);
    // One completion for that submission has landed and no more will follow.
    void disarm(uint32_t token, uint8_t type);
    // A completion nobody can act on any more.
    void drop_completion(const struct io_uring_cqe* cqe, const io_request* req);

    struct io_uring m_ring{};
    std::atomic<bool> m_running;
    uint32_t m_queue_depth;
    uint32_t m_pending_submissions{0};
    int m_eventfd{-1};
    io_request m_signal_req{};
    uint64_t m_signal_buf{};
    bool m_multishot_supported{false};
    // IORING_ACCEPT_POLL_FIRST needs kernel 6.11; probed rather than assumed,
    // because an unknown ioprio bit makes the kernel refuse every accept.
    bool m_accept_poll_first{false};
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

    // ── Owner table ─────────────────────────────────────────────────────────
    // run() asks "is this owner still there?" of every single completion, so
    // the answer has to be one indexed load and one compare — an array reached
    // through a small id the owner was given, never a lookup keyed on the
    // handler pointer.
    //
    // A power of two so a token from a corrupted request still indexes inside
    // the array; the compare that follows then rejects it.
    static constexpr uint32_t MAX_OWNERS = 1024;
    static constexpr uint32_t OWNER_SLOT_MASK = MAX_OWNERS - 1;

    // Slot 0 is never handed out.  It is what a handler gets when the table is
    // full: its completions still validate, so a runtime that is doing nothing
    // wrong keeps working, it just cannot be told apart from the others in the
    // same position.  That is precisely the guarantee the loop gave before this
    // table existed, and far better than refusing to deliver its I/O.  Epoch 1,
    // slot 0.
    static constexpr uint32_t OWNER_UNVERIFIED = 1u << 16;

    struct owner_slot
    {
        io_handler* handler{nullptr};
        // The same total split by operation kind.  Diagnostics only: when a
        // slot will not drain, this says which operation is holding it.
        uint32_t    by_type[op_type_count]{};
        // The one value run() compares against; 0 while no registration holds
        // this slot, which no stamped token can equal.
        uint32_t    token{0};
        // Submissions stamped with this slot that are still owed a final
        // completion.  Kept accurate on the drop path too, or a slot whose
        // owner is gone would never look drained.
        uint32_t    inflight{0};
        // Survives the slot being freed, so a later registration on the same
        // slot cannot reproduce a token that a request in the ring still holds.
        uint16_t    epoch{0};
    };
    owner_slot m_owners[MAX_OWNERS]{};
    uint32_t m_owner_hint{0};
    bool m_owner_table_full_logged{false};
};
