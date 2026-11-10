#pragma once
// Before <liburing.h>, so a liburing too old for this file says so, and here
// as well as in premake5.lua because a header must not depend on the build
// system to be correct.
#include "liburing_version.h"

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <liburing.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "event_loop_definitions.h"
#include "op_timing.h"

namespace socketley { class orderly_close; }

struct buf_ring_pool
{
    struct io_uring_buf_ring* ring{nullptr};
    char* base{nullptr};
    uint32_t buf_count{0};
    uint32_t buf_size{0};
    // Bytes kept free in front of every buffer, which the kernel never writes, for a reader to put a leftover before.
    uint32_t headroom{0};

    char* buf(uint16_t id) const
    {
        return base + static_cast<size_t>(id) * (static_cast<size_t>(buf_size) + headroom) + headroom;
    }

    // ── Consumption cursor ──────────────────────────────────────────────────
    // How many ring entries the kernel has consumed, which is the only way to
    // name buffers 2..k of a bundle -- the CQE carries the first bid alone --
    // with cursor_ok the tripwire that stops bundles being armed once a
    // reported bid misses the prediction.
    uint32_t consumed{0};
    bool     cursor_ok{true};
};

class event_loop
{
public:
    explicit event_loop(uint32_t queue_depth = 2048);
    ~event_loop();

    // ── Ring policy ─────────────────────────────────────────────────────────
    // Takes effect at init() and only there, because io_uring fixes a ring's
    // flags at creation, and calling it marks the choice explicit so a flag
    // beats the environment.
    void set_cpus(const cpu_set_spec& cpus);
    // Threads this process starts later keep the CPUs it was started with, only the I/O thread narrowing to its set.
    void keep_helpers_wide() { m_helpers_wide = true; }
    // How many CPUs a helper thread of this process runs on, which the I/O thread's own set no longer says.
    static unsigned helper_cpu_count();
    // Whether a quiet turn enters the ring again before it sleeps; on unless a runtime says otherwise.
    void set_busy_spin(bool on) { m_spin = on; }

    bool init();

    // ── Ring setup tiers ────────────────────────────────────────────────────
    // What init() asks io_uring_queue_init_params for, best first: DEFER_TASKRUN and SINGLE_ISSUER need 6.1,
    // NO_SQARRAY 6.6, and SUBMIT_ALL, COOP_TASKRUN and CQSIZE 5.19, which the middle tiers keep on 5.19 and 6.0.
    static constexpr unsigned RING_SETUP_BASE = IORING_SETUP_SUBMIT_ALL | IORING_SETUP_COOP_TASKRUN
                                              | IORING_SETUP_CQSIZE;
    static constexpr unsigned RING_SETUP_DEFER = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;
    static constexpr unsigned RING_SETUP_TIERS[] = {
        RING_SETUP_DEFER | RING_SETUP_BASE | IORING_SETUP_NO_SQARRAY,
        RING_SETUP_DEFER | RING_SETUP_BASE,
        RING_SETUP_BASE | IORING_SETUP_NO_SQARRAY,
        RING_SETUP_BASE,
        0u,
    };

    // The index of the first tier try_setup accepts, or -1 when it accepts none, apart from init() so a test can
    // play any kernel.
    template <typename F>
    static int pick_ring_setup(F&& try_setup)
    {
        constexpr int n = static_cast<int>(sizeof(RING_SETUP_TIERS) / sizeof(RING_SETUP_TIERS[0]));
        for (int i = 0; i < n; i++)
            if (try_setup(RING_SETUP_TIERS[i]))
                return i;
        return -1;
    }

    // The flags of the tier init() built the ring with.
    unsigned ring_setup_flags() const { return m_ring_setup_flags; }
    void run();

    // End the ring, which run() returning deliberately does not do, at the one
    // point where nothing more will be submitted and nothing has been released
    // yet; idempotent.
    void shutdown_ring();

    // One pass of run()'s completion drain for a caller that owns the thread,
    // using the same body run() does, and observing no stop eventfd.
    uint32_t poll_completions(int timeout_ms = 0);

    void request_stop();
    int get_signal_write_fd() const;

    // ── Owner registration ──────────────────────────────────────────────────
    // The loop delivers a completion only while the handler that submitted it
    // still owns it, and registration is implicit on first submission, because
    // forgetting to register would silently swallow all of a handler's I/O.
    uint32_t register_owner(io_handler* owner);

    // Call when the handler can no longer service a completion, and a handler
    // that frees itself from its own on_cqe must deregister there and not
    // earlier.
    void deregister_owner(io_handler* owner);

    bool owner_registered(const io_handler* owner) const;

    // Submissions still owed a final completion over every registration this
    // handler has held, whose reaching zero -- and not being deregistered --
    // is the licence to free their storage.
    uint32_t owner_inflight(const io_handler* owner) const;

    // The same figure broken down by operation kind, into op_type_count
    // entries, because a count says an owner cannot be released and the kind
    // says why.
    void owner_inflight_breakdown(const io_handler* owner, uint32_t* out) const;

    // The same question asked of a token, captured before deregistering,
    // because a handler is deregistered exactly when it can no longer be named
    // and its address is what a later allocation may reuse.
    uint32_t token_inflight(uint32_t token) const;

    // True once the owner table has run out and handlers began sharing one
    // identity, from which point a zero from owner_inflight() proves nothing.
    bool owner_table_full() const { return m_owner_table_full_logged; }

    // True once nothing the kernel holds can still name this owner, the one
    // condition under which a handler's storage may be freed.
    bool owner_drained(const io_handler* owner) const
    {
        return owner_inflight(owner) == 0 && !owner_table_full();
    }

    // Give back the provided buffer a completion is carrying, for a caller
    // about to drop it, because the groups are shared by every instance of a
    // runtime type on this loop.
    void return_cqe_buf(const struct io_uring_cqe* cqe, const io_request* req);

    // ── Descriptor lifetime ─────────────────────────────────────────────────
    // The only safe way to close a descriptor this loop has submitted for: it
    // holds the number open until every queued operation naming it has
    // reported, because close() frees the number and the next accept redirects
    // those operations onto a stranger.
    void close_fd(int fd);

    // The same for a connection whose answer is written: once the ring is done with it the number goes to
    // orderly_close, which closes it without the kernel throwing away what it still holds of that answer.
    // `kernel_tls` when the kernel encrypts its records.
    void close_fd_orderly(int fd, bool kernel_tls = false);
    // The ends being closed that way, null before the first.
    const socketley::orderly_close* closer() const { return m_closer; }

    // Operations still in the ring that named this descriptor, which is the
    // condition for giving the number away without closing it, and
    // deliberately excluding cancels.
    uint32_t fd_inflight(int fd) const;

    // The same question for a registered file, so a report can tell an
    // operation on a fixed index from one counted nowhere.
    uint32_t fixed_inflight(uint32_t idx) const
    {
        return idx < MAX_FIXED_FILES ? m_fixed_armed[idx] : 0;
    }

    // The submit_* helpers queue an SQE without submitting and return false
    // when none could be obtained, in which case nothing is queued and a
    // caller that marked an operation in flight must undo that.
    bool submit_accept(int listen_fd, struct sockaddr_in* addr, socklen_t* addrlen, io_request* req);
    bool submit_multishot_accept(int listen_fd, io_request* req);
    // Direct-descriptor multishot accept: accepted fds go straight into the
    // fixed file table at IORING_FILE_INDEX_ALLOC, skipping the process fd table.
    bool submit_multishot_accept_direct(int listen_fd, io_request* req);
    // poll_first says the last read left this socket empty, so the kernel
    // waits for data instead of trying a receive that can only say EAGAIN.
    bool submit_read(int fd, char* buf, uint32_t len, io_request* req, bool poll_first = false);
    // Whether a stream receive took data and left the socket empty, which is
    // what a caller passes as poll_first when it re-arms that socket.
    static bool recv_drained(const struct io_uring_cqe* cqe)
    {
        return cqe->res > 0 && !(cqe->flags & IORING_CQE_F_SOCK_NONEMPTY);
    }
    bool submit_write(int fd, const char* buf, uint32_t len, io_request* req);
    bool submit_writev(int fd, struct iovec* iovs, uint32_t count, io_request* req);
    bool submit_sendmsg(int fd, struct msghdr* msg, io_request* req);
    bool submit_recvmsg(int fd, struct msghdr* msg, io_request* req);
    bool submit_timeout(struct __kernel_timespec* ts, io_request* req);

    // A submission that does nothing but report, so a handler can ask the loop
    // to come back once the current pass has unwound -- cheaper than a
    // zero-length timeout, which arms an hrtimer and completes with -ETIME.
    bool submit_nop(io_request* req);

    // Withdraw a timeout by the request it was submitted with, which is the
    // only thing naming it, so a teardown does not leave the loop owing an
    // owner a completion for thirty seconds -- the withdrawal itself is
    // deliberately not arm()ed, since nothing acts on its answer.
    bool submit_timeout_remove(io_request* target);

    // Fixed-file variants using a registered index instead of a raw fd,
    // avoiding an fget/fput per operation.
    bool submit_read_fixed_file(int fixed_idx, char* buf, uint32_t len, io_request* req);
    bool submit_write_fixed_file(int fixed_idx, const char* buf, uint32_t len, io_request* req);
    bool submit_writev_fixed_file(int fixed_idx, struct iovec* iovs, uint32_t count, io_request* req);
    bool submit_sendmsg_fixed_file(int fixed_idx, struct msghdr* msg, io_request* req);
    bool submit_recv_multishot_fixed_file(int fixed_idx, uint16_t group_id, io_request* req);
    bool submit_read_provided_fixed_file(int fixed_idx, uint16_t group_id, io_request* req);

    // Registered buffers: eliminate copy_from_user/copy_to_user per I/O op.
    bool register_buffers(const struct iovec* iovs, uint32_t count);
    void unregister_buffers();
    bool submit_read_fixed_buf(int fd, char* buf, uint32_t len, uint16_t buf_idx, io_request* req);
    bool submit_write_fixed_buf(int fd, const char* buf, uint32_t len, uint16_t buf_idx, io_request* req);

    // A buffer group belongs to a runtime type and not an instance, so the
    // first instance to reach here decides the geometry and a later one asking
    // for different dimensions gets the existing pool and a warning.
    bool setup_buf_ring(uint16_t group_id, uint32_t buf_count, uint32_t buf_size, uint32_t headroom = 0);
    bool submit_read_provided(int fd, uint16_t group_id, io_request* req, bool poll_first = false);
    // Cancel every pending operation on a descriptor in one SQE, counted
    // against that descriptor like any other submission because it too names a
    // number the kernel resolves late; close_fd() submits one when it needs
    // to, so call this directly only for a descriptor that is staying open.
    bool submit_cancel_fd(int fd);

    // The same for an operation armed on a fixed-file index, submitted before
    // the file is unregistered because a cancel can only match while the index
    // still resolves.
    bool submit_cancel_fixed(uint32_t idx);
    char* get_buf_ptr(uint16_t group_id, uint16_t buf_id);
    void return_buf(uint16_t group_id, uint16_t buf_id);
    void return_bufs_batch(uint16_t group_id, const uint16_t* buf_ids, uint32_t count);

    // Multishot recv, one SQE producing completions from the buffer ring until
    // error or cancel, resubmitted only when IORING_CQE_F_MORE is clear, and refused once the kernel has refused one
    // on this loop, so a caller's chain falls to its provided-buffer read.
    bool submit_recv_multishot(int fd, uint16_t group_id, io_request* req);

    // Whether arming one is worth attempting -- kernel support and not disabled
    // by SOCKETLEY_RECV_MULTISHOT=0 -- which is the switch every runtime's A/B
    // is taken on, so it is read in one place and means one thing.
    bool recv_multishot_enabled() const;

    // ── Bundled multishot recv ──────────────────────────────────────────────
    // IORING_RECVSEND_BUNDLE packs as many provided buffers into one
    // completion as the socket queue could fill, so a handler that arms it
    // must consume through cqe_buf_count()/cqe_buf_id() rather than the CQE's
    // own id, and falls back to the plain multishot variant whenever the flag,
    // the environment or the group's cursor says no.
    bool submit_recv_multishot_bundle(int fd, uint16_t group_id, io_request* req);
    bool submit_recv_multishot_bundle_fixed_file(int fixed_idx, uint16_t group_id, io_request* req);

    // Whether arming a bundle is worth attempting -- kernel support and not
    // disabled by SOCKETLEY_RECV_BUNDLE=0 -- with per-group cursor health
    // checked by the submit itself.
    bool recv_bundle_enabled() const;

    // The buffers of the completion being dispatched, valid only inside on_cqe
    // and only with IORING_CQE_F_BUFFER, snapshotted before dispatch so
    // returning early entries cannot corrupt later ones.
    uint32_t cqe_buf_count() const { return m_cqe_buf_count; }
    uint16_t cqe_buf_id(uint32_t i) const
    {
        return i < m_cqe_buf_count ? m_cqe_bids[i] : 0;
    }
    // The pool geometry a consumer needs to slice a bundle's bytes, from the
    // pool rather than the runtime's own constant.
    uint32_t buf_ring_buf_size(uint16_t group_id) const
    {
        return group_id < MAX_BUF_GROUPS ? m_buf_rings[group_id].buf_size : 0;
    }
    uint32_t buf_ring_headroom(uint16_t group_id) const
    {
        return group_id < MAX_BUF_GROUPS ? m_buf_rings[group_id].headroom : 0;
    }

    // Every buffer of this completion sliced and returned in one place,
    // because a buffer whose pointer fails to resolve must still advance
    // `remaining` and a buffer left unreturned is one the group has
    // permanently lost.
    template <typename F>
    void for_each_cqe_buf(uint16_t group_id, const struct io_uring_cqe* cqe, F&& fn)
    {
        if (!cqe || cqe->res <= 0)
            return;
        const uint32_t buf_sz = buf_ring_buf_size(group_id);
        const uint32_t nbufs  = cqe_buf_count();
        uint32_t remaining    = static_cast<uint32_t>(cqe->res);
        for (uint32_t i = 0; i < (nbufs ? nbufs : 1u) && remaining; i++)
        {
            // nbufs of zero cannot happen for a buffered completion; the CQE's
            // own id keeps even that case from touching buffer 0 by accident.
            const uint16_t buf_id = nbufs
                ? cqe_buf_id(i)
                : static_cast<uint16_t>(cqe->flags >> IORING_CQE_BUFFER_SHIFT);
            const uint32_t take = (buf_sz && remaining > buf_sz) ? buf_sz : remaining;
            if (char* p = get_buf_ptr(group_id, buf_id))
            {
                fn(p, take);
                return_buf(group_id, buf_id);
            }
            remaining -= take;
        }
    }

    // Registered files: pre-register fds to avoid fget/fput per op
    bool update_registered_file(uint32_t idx, int fd);

    // Allocate a slot in the registered file table, returns index or -1
    int alloc_fixed_file_slot();

    // Give a slot back, unregistering the file at once but returning the index
    // to the allocator only once nothing in the ring still names it, because a
    // fixed-file SQE carries the index and the kernel resolves it late.
    void free_fixed_file_slot(uint32_t idx);

    // Splice never runs on the loop thread -- the kernel punts every one to an
    // io-wq worker, measured at 17 us against 1.2 us for a ready send -- so it
    // is right for server_instance's file serving and wrong for a proxy
    // relaying small messages.
    bool submit_splice(int fd_in, int fd_out, uint32_t len, io_request* req, op_type type = op_splice);

    // Async file read using io_uring_prep_read, with req->fd set to the socket
    // for CQE dispatch routing.
    bool submit_file_read(int file_fd, char* buf, uint32_t len, uint64_t offset, io_request* req);

    // Disk operations for a durable log, where `link` makes the next submission
    // start only once this one has succeeded (IOSQE_IO_LINK), and a chain must
    // be preceded by reserve_sqes() so no submit falls inside it.
    bool submit_file_write(int fd, const char* buf, uint32_t len, uint64_t offset,
                           io_request* req, bool link);
    bool submit_fsync(int fd, bool datasync, io_request* req, bool link);
    bool submit_renameat(int olddir, const char* oldpath, int newdir, const char* newpath,
                         io_request* req, bool link);
    bool submit_unlinkat(int dir, const char* path, io_request* req, int flags = 0);
    bool submit_linkat(int olddir, const char* oldpath, int newdir, const char* newpath, io_request* req);
    // Completes with the new descriptor or a negative errno, and the path must
    // stay valid until it does because the kernel may read it late.
    bool submit_openat(int dir, const char* path, int flags, mode_t mode, io_request* req);
    bool submit_mkdirat(int dir, const char* path, mode_t mode, io_request* req, bool link = false);
    // A regular file at `offset` into a pipe, which is what a zero-copy send
    // starts with; the file's own position is not touched.
    bool submit_splice_file(int file_fd, uint64_t offset, int pipe_wr, uint32_t len, io_request* req,
                            op_type type = op_splice_file);

    // Room for `n` submissions without a submit in between, flushing what is
    // queued first when there is not, and false only when the ring is smaller.
    bool reserve_sqes(unsigned n);

    // Async connect, whose completion is 0 on success and a negative errno on
    // failure.
    bool submit_connect(int fd, const struct sockaddr* addr, socklen_t len, io_request* req);

    // Wait for readiness on an fd, which is how a connect() that returned
    // EINPROGRESS is finished, since a second connect only ever answers
    // EISCONN.
    bool submit_poll_add(int fd, unsigned mask, io_request* req);

    // Withdraw a poll by the request that submitted it, needed because a poll
    // holds its own reference to the file and closing the descriptor does not
    // end it.
    bool submit_poll_remove(io_request* target);

    // Withdraw ONE submission by the user_data it carries, where
    // submit_cancel_fd() withdraws everything armed on a descriptor.  The
    // difference is what the kernel has to do to find it: a match on the file
    // walks the ring's live requests, a match on user_data does not.
    bool submit_cancel_request(const io_request* target);

    // Hand every queued SQE to the ring, which is not a barrier and not a
    // licence to close a descriptor one of them names -- close_fd() is.
    void flush();

    struct io_uring* get_ring();

    // Check if multishot accept is supported
    static bool supports_multishot_accept();

    // What this process's ring probes found, one character each ('1', '0', '?' for not asked), and the same handed
    // in by a process that already asked them, which a worker is so that it builds no throwaway rings.
    static std::string kernel_facts();
    static void assume_kernel_facts(std::string_view facts);

    // NAPI busy polling: reduce latency by busy-polling the NIC driver.
    bool enable_napi_busy_poll(uint32_t busy_poll_usec, bool prefer = false);

    // Whether a ring exists right now, which a caller deferring init() until
    // its config arrives has to ask, because poll_completions() returns
    // immediately until then.
    bool ring_open() const { return m_ring_open; }

    // The CPU set this loop was configured with.
    const cpu_set_spec& cpus() const { return m_cpus; }

    // Whether the loop thread's affinity was actually narrowed, which
    // distinguishes not asked from asked and refused.
    bool affinity_applied() const { return m_affinity_applied; }


private:
    struct io_uring_sqe* get_sqe();
    struct io_uring_sqe* get_sqe_when_full();
    void setup_eventfd();
    bool init_fd_tables();
    void apply_cpu_affinity();

    // What run()'s drain loop must do after one completion, where `stop` is
    // only ever the eventfd's own read reporting.
    enum class cqe_outcome : uint8_t { next, stop };
    cqe_outcome dispatch_cqe(struct io_uring_cqe* cqe);

    // Dispatch every completion currently in the ring, returning how many were
    // consumed and leaving the ones behind the stop eventfd for the next pass.
    unsigned dispatch_ready(bool& got_signal);

    // One ring entry each, carrying whatever is queued so a turn with
    // submissions costs one syscall and not a submit plus the entry it was
    // about to make anyway.
    int enter_get_events();
    int enter_wait_timeout(struct io_uring_cqe** cqe, struct __kernel_timespec* ts);

    // Stamp the owner identity and the descriptors named onto a submission and
    // count it, taking the number written into the SQE rather than req->fd,
    // which several helpers set to something else.
    void arm(io_request* req, uint32_t target, uint32_t target2 = IO_TARGET_NONE);
    // One completion for that submission has landed and no more will follow.
    void disarm(uint32_t token, uint8_t type, uint32_t target, uint32_t target2);
    // A completion nobody can act on any more.
    void drop_completion(const struct io_uring_cqe* cqe, const io_request* req);

    // ── Per-descriptor accounting ───────────────────────────────────────────
    // One counter per number a submission can name, and the release that
    // number is waiting for.
    void target_ref(uint32_t target);
    void target_unref(uint32_t target);
    // Perform a close or a slot release that was waiting on the count.
    void settle_deferred(uint32_t target);
    // The number given back: closed, or handed to orderly_close when close_fd_orderly() asked for it.
    void release_number(int fd);

    bool fd_tracked(int fd) const
    { return fd >= 0 && static_cast<uint32_t>(fd) < m_fd_table_size; }

    struct io_uring m_ring{};
    std::atomic<bool> m_running;
    uint32_t m_queue_depth;
    uint32_t m_pending_submissions{0};
    // What the previous turn drained, which is the only evidence available
    // here for whether this loop is mid-batch or idle.
    uint32_t m_last_batch{0};
    // Ring entries to try before sleeping; 32 covers the 92% of eligible
    // turns whose completion arrives within 2.2 of them.
    static constexpr uint32_t SPIN_BUDGET = 32;
    // Turns of spinning a batch or a successful spin buys; bounded so traffic
    // that stops leaves at most this many extra ring entries behind it.
    static constexpr uint32_t BUSY_CREDIT = 64;
    uint32_t m_busy_credit{0};
    bool     m_spin{true};
    // The credit after a turn that found nothing: a batch refills it and a
    // quiet turn spends one, written once so a turn can read what the
    // settlement will say before it makes the entry the answer depends on.
    static constexpr uint32_t credit_after_turn(uint32_t last_batch, uint32_t credit)
    { return last_batch > 1 ? BUSY_CREDIT : credit > 0 ? credit - 1 : 0; }
    bool     m_warned_ownerless{false};
    int m_eventfd{-1};
    io_request m_signal_req{};
    uint64_t m_signal_buf{};
    bool m_multishot_supported{false};
    // IORING_ACCEPT_POLL_FIRST needs kernel 6.10; probed rather than assumed,
    // because an unknown ioprio bit makes the kernel refuse every accept.
    bool m_accept_poll_first{false};
    // IORING_RECVSEND_POLL_FIRST, probed for the same reason in the same field.
    bool m_recv_poll_first{false};
    // Whether a caller chose, which the value below cannot say because
    // "unrestricted" is both a legitimate choice and the state of having made
    // none.
    bool m_cpus_explicit{false};
    bool m_helpers_wide{false};
    bool m_affinity_applied{false};
    cpu_set_spec m_cpus{};
    unsigned m_ring_setup_flags{0};
    bool m_recv_multishot_supported{false};
    // Set once the kernel refuses a multishot receive the probe passed, after which none is armed on this loop.
    bool m_recv_multishot_refused{false};
    bool m_files_registered{false};
    bool m_bufs_registered{false};
    bool m_direct_accept_supported{false};
    // Whether m_ring is a ring at all, tested in get_sqe(), which is the
    // single door every submission goes through.
    bool m_ring_open{false};
    uint64_t m_sq_exhausted_count{0};
    uint32_t m_registered_file_count{0};

    // Fixed file slot allocation (bitmap-based)
    static constexpr uint32_t MAX_FIXED_FILES = 8192;
    // Each uint64_t covers 64 slots; 8192/64 = 128 words
    static constexpr uint32_t BITMAP_WORDS = MAX_FIXED_FILES / 64;
    uint64_t m_file_bitmap[BITMAP_WORDS]{};
    uint32_t m_file_bitmap_hint{0};  // hint for next scan start

    // ── Descriptor tables ───────────────────────────────────────────────────
    // Submissions still naming each raw descriptor plus the two bits saying
    // what waits on that count, sized from RLIMIT_NOFILE, in uint16 because a
    // descriptor cannot outstand the ring's depth.
    uint16_t* m_fd_armed{nullptr};
    uint16_t* m_fd_cancels{nullptr};
    uint64_t* m_fd_close_deferred{nullptr};
    // Whether a held number's close goes to orderly_close, and with kernel TLS.
    uint64_t* m_fd_orderly{nullptr};
    uint64_t* m_fd_orderly_ktls{nullptr};
    socketley::orderly_close* m_closer{nullptr};
    uint32_t  m_fd_table_size{0};
    // Descriptors held open only because the ring still names them, reported
    // at shutdown because a number that never drains is otherwise invisible.
    uint32_t  m_fd_close_pending{0};
    // Said once: a descriptor above the table cannot be tracked, so it is
    // closed the old way and the hazard is open again for it.
    bool      m_fd_untracked_logged{false};

    // The same two things for fixed-file table indices: submissions in the ring
    // naming each slot, and whether the slot is waiting to go back to the
    // allocator.
    uint16_t m_fixed_armed[MAX_FIXED_FILES]{};
    // Submit-to-complete histogram, -DSOCKETLEY_TIMING only.
    SKL_TIMING_MEMBER
    bool m_timing_dumped{false};

    uint64_t m_fixed_free_deferred[BITMAP_WORDS]{};

    // Slots whose unregister is owed as well as their index, because
    // unregistering before a cancel naming the index is consumed makes that
    // cancel answer EBADF and withdraw nothing.
    uint64_t m_fixed_unreg_deferred[BITMAP_WORDS]{};

    // The descriptors named by the completion being dispatched while it is
    // that submission's last, so close_fd() can discount it rather than make
    // the commonest close pay for a cancel round trip.
    uint32_t m_cqe_target{IO_TARGET_NONE};
    uint32_t m_cqe_target2{IO_TARGET_NONE};

    // Filled by decode_cqe_bufs() before the handler runs and cleared after,
    // copied up front because a return writes at the ring's tail and can wrap
    // onto entries a long bundle is still reading.
    static constexpr uint32_t MAX_CQE_BUFS = 1024;
    uint16_t m_cqe_bids[MAX_CQE_BUFS];
    uint32_t m_cqe_buf_count{0};
    const struct io_uring_cqe* m_cqe_current{nullptr};
    // Advance the group cursor and snapshot the buffer ids for every
    // completion carrying IORING_CQE_F_BUFFER, because the cursor stays
    // truthful only if every consumption passes this one chokepoint.
    void decode_cqe_bufs(const struct io_uring_cqe* cqe, const io_request* req,
                         uint8_t rtype);
    // Kernel support for IORING_RECVSEND_BUNDLE, established by one real
    // submission on a throwaway ring the first time anyone asks.
    static bool probe_recv_bundle();
    // The -EINVAL a kernel without IORING_RECV_MULTISHOT answers, turned into a single provided-buffer receive on
    // the same request, and true when that receive was armed and the completion must not be delivered.
    bool rearm_refused_multishot(const struct io_uring_cqe* cqe, io_request* req, uint8_t rtype, uint32_t target);
    // Kernel support for IORING_RECV_MULTISHOT, established the same way at init().
    static bool probe_recv_multishot();

    static constexpr uint16_t MAX_BUF_GROUPS = 8;
    buf_ring_pool m_buf_rings[MAX_BUF_GROUPS]{};

    // ── Owner table ─────────────────────────────────────────────────────────
    // An array reached through a small id rather than a lookup keyed on the
    // handler pointer, because run() asks this of every completion; a power of
    // two so a corrupted token still indexes inside it.
    static constexpr uint32_t MAX_OWNERS = 1024;
    static constexpr uint32_t OWNER_SLOT_MASK = MAX_OWNERS - 1;

    // Slot 0 is never handed out and is what a handler gets when the table is
    // full, so its completions still validate and it merely cannot be told
    // apart from the others.
    static constexpr uint32_t OWNER_UNVERIFIED = 1u << 16;

    struct owner_slot
    {
        io_handler* handler{nullptr};
        // The same total split by operation kind, for diagnostics: when a slot
        // will not drain, this says which operation is holding it.
        uint32_t    by_type[op_type_count]{};
        // The one value run() compares against; 0 while no registration holds
        // this slot, which no stamped token can equal.
        uint32_t    token{0};
        // Submissions stamped with this slot still owed a final completion,
        // kept accurate on the drop path too or a slot whose owner is gone
        // would never look drained.
        uint32_t    inflight{0};
        // Survives the slot being freed, so a later registration on the same
        // slot cannot reproduce a token that a request in the ring still holds.
        uint16_t    epoch{0};
    };
    // An aggregate with a trivial destructor, so calloc's zeroes are the slots, with the zero every initialiser above names.
    static_assert(std::is_aggregate_v<owner_slot> && std::is_trivially_destructible_v<owner_slot>);
    struct owner_table_free { void operator()(owner_slot* p) const noexcept { std::free(p); } };
    // Calloc'd and not a member array, because a value-initialised member wrote all 172 KB in every process that made
    // a loop, while calloc's pages stay the kernel's zero page until a slot on them is first used.
    std::unique_ptr<owner_slot[], owner_table_free> m_owners{
        static_cast<owner_slot*>(std::calloc(MAX_OWNERS, sizeof(owner_slot)))};
    uint32_t m_owner_hint{0};
    bool m_owner_table_full_logged{false};
};
