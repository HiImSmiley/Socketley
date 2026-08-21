#pragma once
// Before <liburing.h>, so that a liburing too old for this file says so instead
// of producing `not declared in this scope` for the identifiers below.  Also
// force-included into every translation unit by premake5.lua; here as well
// because a header must not depend on the build system to be correct, and the
// clang advisory job in CI compiles these sources without premake.
#include "liburing_version.h"

#include <atomic>
#include <cstdint>
#include <liburing.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "event_loop_definitions.h"
#include "op_timing.h"

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

    // ── Ring policy ─────────────────────────────────────────────────────────
    // Both take effect at init() and only there.  io_uring fixes a ring's flags
    // when the ring is created and offers no way to change them afterwards, so
    // these are not settings a running daemon can be asked to change — and that
    // is also why neither is a per-runtime choice today: every in-process
    // runtime shares this one ring, created before the first `create` command
    // has been read.
    //
    // Calling either after init() is a no-op and says so in the log rather than
    // leaving the caller believing a ring changed shape.  Which is why a
    // process that will be told what shape its ring should be has to hold init()
    // until it has been told: see proxy_worker, which builds its ring on the
    // config frame.
    //
    // SQPOLL costs a kernel thread per ring for as long as the ring exists, and
    // that thread spins on the submission queue whether or not anything is
    // being submitted.  It is therefore off unless asked for.
    //
    // Calling either marks the choice explicit, and an explicit choice beats the
    // environment at init().  The distinction is what makes `--no-sqpoll` and
    // `--cpus max` mean anything: without it init() cannot tell "nobody chose,
    // so the default is off" from "the command line said off", and
    // SOCKETLEY_SQPOLL=1 in the environment would turn the poller back on under
    // a flag that had just asked for it to be gone.
    void set_sqpoll(bool on);
    void set_cpus(const cpu_set_spec& cpus);

    bool init();
    void run();

    // End the ring.  run() returning does not do this, on purpose: a daemon
    // shutting down still has runtimes to stop, and stopping one submits —
    // teardown() cancels the operations attached to its descriptors and
    // withdraws its own timers, both of which need a ring to submit into.
    //
    // Call it once those are done and before anything an in-flight operation
    // could still be naming is freed.  That is the one point where both halves
    // hold: nothing more will be submitted, and nothing has been released yet.
    // Afterwards every submit_* answers false instead of reaching into an
    // unmapped queue, and the kernel can no longer be writing into memory the
    // process is about to give back.  Idempotent; the destructor calls it.
    void shutdown_ring();

    // One pass of run()'s completion drain, without its loop and without its
    // unbounded wait.  Dispatches every completion the ring has ready and
    // returns how many; waits up to timeout_ms for the first one, or not at all
    // when that is zero.
    //
    // This exists for a caller that owns the thread and cannot give it to run()
    // — the operation-sequence fuzz targets, which have to interleave "arm
    // something" and "let the ring report" under their own control.  It is the
    // same body run() uses, deliberately: a harness with a drain loop of its own
    // would be checking a dispatcher the daemon does not have.
    //
    // Not a substitute for run() in the daemon.  It never observes the stop
    // eventfd, so nothing here ends on request_stop().
    uint32_t poll_completions(int timeout_ms = 0);

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

    // Submissions queued with no owner, whose completions were therefore
    // dropped.  Never anything but a defect; see arm().  Counted as well as
    // logged so a test can assert zero rather than grep a log the daemon
    // deletes.
    uint64_t stat_ownerless() const { return m_stat_ownerless; }

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

    // The same question asked of a token instead of a handler, for a caller
    // that is holding storage it may not free yet.
    //
    // Both of the above take an io_handler*, and neither can be asked once the
    // handler is on its way out.  deregister_owner() clears the handler's copy
    // of its token as its first act, and it is deregistered precisely when its
    // storage is about to go — so the moment the question matters is the moment
    // the handler can no longer be named.  Matching on the pointer instead is
    // worse, not better: the address is exactly what a later allocation may
    // reuse, so a fresh object at the old address would answer for the dead
    // one.  A token cannot be confused that way — the slot's epoch changes on
    // every re-registration, so a token names one registration for good.
    //
    // A caller that means to defer a free therefore captures the token BEFORE
    // deregistering, and asks here afterwards.  Zero means nothing in the ring
    // will name that registration again, which is the only licence to free the
    // storage its io_requests live in.  Note that this is a stronger condition
    // than "deregistered": a dropped completion is still a completion, and
    // dropping one reads the owner token out of the request to decide.
    uint32_t token_inflight(uint32_t token) const;

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

    // ── Descriptor lifetime ─────────────────────────────────────────────────
    // The only safe way to close a descriptor this loop has ever submitted for.
    //
    // An SQE carries a descriptor *number*; the kernel resolves it when it
    // consumes the SQE, which under SQPOLL is another thread at a moment
    // nothing here can observe.  close() does not withdraw a queued operation —
    // it only frees the number, and the next accept takes it, so the queued
    // operation is redirected onto a stranger.  That is not a theory: on the
    // proxy it put an aborting client's 8192 bytes into the middle of 6% of
    // healthy connections' streams, and the pairing checks on the forwarding
    // path could not see it because they were right when they ran.
    //
    // Neither flush() nor submit_cancel_fd() is a defence.  flush() hands the
    // SQE to the ring and returns; under SQPOLL it does not even make a
    // syscall, so it says nothing about consumption.  And a cancel is itself an
    // SQE naming that same number, so it inherits the whole problem: closing
    // before it is consumed lets it cancel whatever inherited the number
    // instead — a healthy connection's read completing -ECANCELED for no
    // reason anyone can trace.
    //
    // This closes the descriptor now when nothing in the ring names it, and
    // otherwise holds the number — the descriptor stays open, so every queued
    // operation still resolves to the file it was submitted for — and closes it
    // from disarm() once the last of them has reported.  Submitting a cancel
    // for the ones that would not end on their own is part of the same step,
    // and that cancel is counted like any other submission, so the number
    // outlives it too.
    //
    // Call it for every descriptor the loop may name, including ones it
    // probably does not: with nothing armed it is exactly close(), so a
    // needless call costs one indexed load.  shutdown() first where the caller
    // already does — it is what makes a socket's pending reads and writes
    // report at once, and holding the number does not change that.
    void close_fd(int fd);

    // Operations still in the ring that named this descriptor.  Zero is the
    // condition for giving the *number* to someone else without closing it: a
    // connection pool handing the socket to the next request, a fixed-file slot
    // going back to the allocator.  Same hazard as close, same answer.
    //
    // Cancels are deliberately not counted here, only in what close_fd() waits
    // for.  A cancel that lands on a number still bound to the same file is a
    // no-op for a pool — the file did not change — but a caller that pools a
    // descriptor with a cancel of its own outstanding must know that cancel has
    // already run, or IORING_ASYNC_CANCEL_ALL will take back the *next*
    // request's I/O on that socket.  detach_and_pool_backend has that proof and
    // says so; nothing else submits a cancel it does not close behind.
    uint32_t fd_inflight(int fd) const;

    // The same question for a registered file.  A submission that names one is
    // counted here and not in the descriptor table, so an operation invisible
    // to fd_inflight() is either on a fixed index or counted nowhere — and
    // those two are very different faults.  Exists so a report can tell them
    // apart; nothing in the runtimes needs it.
    uint32_t fixed_inflight(uint32_t idx) const
    {
        return idx < MAX_FIXED_FILES ? m_fixed_armed[idx] : 0;
    }

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

    // A submission that does nothing but report.  The completion arrives on the
    // next pass of the drain, so this is how a handler asks the loop to come
    // back to it once the current one has unwound — no descriptor, no timer, no
    // wait.  request_channel uses it to get a cross-runtime request off the
    // stack of the handler that made it.
    //
    // Cheaper than a zero-length timeout, which is the obvious alternative: a
    // timeout arms an hrtimer and is charged to the kernel's timer wheel, and
    // its completion carries -ETIME that every caller then has to ignore.  This
    // one is consumed and reported in the same pass the SQE is read.
    //
    // Counted like every other submission, so an owner with one outstanding is
    // not quiescent and its storage may not be freed.
    bool submit_nop(io_request* req);

    // Withdraw a timeout that submit_timeout() put in the ring, named by the
    // request it was submitted with — a timeout hangs off no descriptor, so
    // there is nothing else to name it by, and neither close() nor
    // submit_cancel_fd() reaches one.  Every teardown used to close its sockets
    // and leave its own timers counting down; the loop went on owing that owner
    // a completion for up to thirty seconds, reap_retired() frees an instance
    // only once that count is zero, and so the instance was never freed at all —
    // about 6 MB per removed runtime, held until the daemon exited.
    //
    // Two completions follow this, and only one of them is accounted for:
    //
    //   * The withdrawn timeout reports once more, with -ECANCELED and without
    //     IORING_CQE_F_MORE.  That is the completion its own submit_timeout()
    //     was already owed, so its arm() is answered by that single disarm()
    //     exactly as if it had run to term.  This call changes no count; it only
    //     makes the completion arrive now instead of when the timer would have
    //     fired.
    //
    //   * The withdrawal itself reports whether the kernel found the timeout (0)
    //     or not (-ENOENT).  Nothing acts on either answer, so it goes out with
    //     no request attached and run() skips it without dispatching or
    //     counting — which is why this is deliberately not arm()ed.  An arm()
    //     with no disarm to answer it is this very bug again, and a disarm with
    //     no arm wraps the counter so the owner's slot is never reusable.
    //
    // Only call this for a request a completion is genuinely owed on: the
    // kernel compares the key without ever dereferencing it, but the cancelled
    // timeout is delivered carrying that same pointer, and run() does read it.
    // Calling it for a timeout that has already fired is still safe — the kernel
    // answers -ENOENT and the completion it already posted does the disarm — but
    // the storage behind the request has to be alive either way.
    //
    // False means the submission never reached the ring, so the timeout stays
    // armed and ends only when it fires.
    bool submit_timeout_remove(io_request* target);

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
    //
    // A group belongs to a runtime *type*, not to an instance: the ids are
    // compile-time constants in the runtime headers and there are only
    // MAX_BUF_GROUPS of them, so every server on this loop draws from one pool,
    // every proxy from another, and so on.  The first instance of a type to
    // reach here therefore decides the geometry for all of them; a later one
    // asking for a different buf_count or buf_size gets the pool that already
    // exists and a WARN saying so, rather than the silent substitution this used
    // to perform.  True means there is a usable pool under group_id — not that
    // it is the one this caller asked for.
    bool setup_buf_ring(uint16_t group_id, uint32_t buf_count, uint32_t buf_size);
    bool submit_read_provided(int fd, uint16_t group_id, io_request* req);
    // Cancel every pending operation on a descriptor in one SQE
    // (IORING_ASYNC_CANCEL_ALL — without it only one is taken back per SQE, and
    // the second completion arrives after whatever was waiting on the first has
    // given up and freed itself).
    //
    // This is itself an SQE naming a descriptor number, so it is subject to the
    // hazard it is usually submitted to help with: consumed after the number
    // has been reissued, it cancels the new owner's operations.  It is
    // therefore counted against that descriptor exactly like a read or a write,
    // and close_fd() holds the number until it has reported.  Its completion
    // carries no io_request — there is nothing to act on but "found it" or
    // -ENOENT — so run() recognises it by a tag in the user_data and does the
    // accounting without dispatching anything.
    //
    // Callers rarely need this directly: close_fd() submits one when, and only
    // when, the descriptor has something armed.  Use it on its own only to take
    // an operation back from a descriptor that is *staying* open.
    bool submit_cancel_fd(int fd);

    // The same, for an operation armed on a fixed-file index rather than on a
    // descriptor number.  Submitted by free_fixed_file_slot() before it
    // unregisters the file, because a cancel can only match while the index
    // still resolves to one.
    bool submit_cancel_fixed(uint32_t idx);
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

    // Whether the kernel has the opcode.  Says nothing about whether using it
    // is a good idea here — see send_zc_enabled().
    bool send_zc_supported() const;

    // Whether a runtime should use it.  Off unless SOCKETLEY_SEND_ZC=1.
    //
    // A NOTIFICATION IS NOT A REQUEST, AND NOTHING LOCAL CAN MAKE IT ARRIVE.
    //
    // The notification is posted when the kernel has released the pages it
    // borrowed, which for TCP means when the socket's write queue is freed.
    // That is the peer's decision, not ours.  Measured directly against this
    // kernel (test program in the commit message), on a loopback pair with a
    // 544 KB zero-copy send and a receiver that does not read:
    //
    //     300 rounds of ring activity      no notification
    //     close() the sender's descriptor  no notification
    //     receiver reads the bytes         notification, immediately
    //     SO_LINGER 0 + close (RST)        notification, immediately
    //
    // So the only two things that release it are the peer reading and an
    // abortive close.  The second is not available to a graceful teardown: it
    // would reset precisely those connections that have a large response in
    // flight and have not read it yet, which turns "stop" into guaranteed
    // truncation for the biggest responses.
    //
    // A plain write does not have this shape.  It is a request, so the cancel
    // that free_fixed_file_slot() and close_fd() already submit withdraws it
    // and it reports -ECANCELED.  A pending notification cannot be cancelled —
    // there is no request left to name; the send has already completed.
    // Observed on the seed that found this: the fixed-index cancel withdrew the
    // multishot recv on the same index and left the notification standing.
    //
    // What that costs is a runtime that can never be freed.  retire()'s
    // graveyard holds a stopped instance until owner_inflight() reaches zero,
    // so one client that stops reading a >= 512 KB response pins the whole
    // instance — its buffer rings, its connection table, all of it — for as
    // long as it likes.  `socketley stop` returns, the runtime reports stopped,
    // and the memory never comes back.
    //
    // The gain being given up is narrow by the callers' own rule: zero-copy is
    // only ever reached for a single write of 512 KB or more, because below
    // that the notification round trip costs more than the copy saves.  A
    // deployment whose readers are known to drain can set SOCKETLEY_SEND_ZC=1.
    bool send_zc_enabled() const;

    // Registered files: pre-register fds to avoid fget/fput per op
    bool register_files(const int* fds, uint32_t count);
    bool update_registered_file(uint32_t idx, int fd);
    void unregister_files();
    bool files_registered() const { return m_files_registered; }
    uint32_t registered_file_count() const { return m_registered_file_count; }

    // Allocate a slot in the registered file table, returns index or -1
    int alloc_fixed_file_slot();

    // Give a slot back.  The file behind it is unregistered at once — until
    // that happens the kernel still holds a reference to the socket and its
    // close() did not really close it — but the *index* is only returned to the
    // allocator once nothing in the ring still names it.
    //
    // A fixed-file SQE carries the index, not the file, and the kernel resolves
    // it when it consumes the SQE, so an index handed straight back is the same
    // redirection as a reissued descriptor number one level up: the next
    // connection allocates the slot, points it at its own socket, and the
    // previous connection's queued read lands there.  Nothing has ever measured
    // this one — the fixed-file path is only taken when the accept registered a
    // slot — but it is the same construction and it costs one counter to be rid
    // of.
    void free_fixed_file_slot(uint32_t idx);

    // Splice: zero-copy data transfer between two fds through a pipe.
    // fd_in -> fd_out, len bytes, off_in/off_out = -1 for pipes/sockets.
    //
    // This is the one submission here that never runs on the loop thread.
    // IORING_OP_SPLICE has no non-blocking fast path: the kernel hands every
    // one of them to an io-wq worker before it looks at whether the data is
    // there, so the completion costs a worker round trip even when the
    // operation could not possibly have blocked.  Measured directly, with the
    // bytes already in the pipe and room at the far end (p50 over 3000
    // submissions on 7.0.0-28):
    //
    //   read() from that same ready pipe        0.72 us
    //   send() to that same ready socket        1.20 us
    //   send() forced async with IOSQE_ASYNC   17.32 us
    //   splice                                 17.19 us
    //   splice + SPLICE_F_NONBLOCK             17.18 us
    //   splice + SPLICE_F_FD_IN_FIXED          17.78 us
    //
    // Splice is indistinguishable from a submission deliberately forced onto a
    // worker, and neither flag moves it.  There is no variant that stays on the
    // fast path — registered pipes do not help, because the cost is the punt and
    // not the descriptor lookup.
    //
    // What follows from that is a size rule, since the punt is a fixed cost per
    // operation and a relay needs two of them per direction.  Over 16
    // connections, 7 runs each:
    //
    //   128 B payload   splice 3037-83914 req/s   copy path 126673-152614 req/s
    //   128 KB payload  splice 22286 req/s median, 5.06 us of loop-thread CPU
    //                   copy   16014 req/s median, 55.89 us
    //
    // At small payloads splice is not merely slower, it is unstable: that 28x
    // spread is one io-wq pool being contended by every connection at once, and
    // the pool grew to 128 workers at 64 connections while throughput fell to
    // 2676 req/s.  At large payloads the punt amortises and splice wins on both
    // throughput and, by an order of magnitude, on loop-thread CPU.
    //
    // So: right for server_instance's file serving, wrong for a proxy relaying
    // small messages.  A caller that cannot say which regime it is in should use
    // the copy path, which is never catastrophic.
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

    // Withdraw a poll submitted with submit_poll_add.  Needed because a poll
    // holds its own reference to the file: closing the descriptor does not end
    // it, so a poll nobody withdraws is a completion the ring owes for as long
    // as the file lives — see submit_cancel_fd for the same hazard on the
    // whole-descriptor scale.  This one is keyed on the request rather than the
    // descriptor, so it takes back exactly the poll it names and leaves a read
    // or a write armed on the same socket alone.
    bool submit_poll_remove(io_request* target);

    // Hand every queued SQE to the ring.  Not a barrier, and in particular not
    // a licence to close a descriptor one of them names: under SQPOLL this is a
    // tail update with no syscall at all, and it returns long before the kernel
    // thread has looked at anything.  Several teardowns used to read as
    // "cancel, flush, close" and take the flush for the guarantee that made the
    // order safe.  It never was one — close_fd() is.
    void flush();

    struct io_uring* get_ring();

    // Check if multishot accept is supported
    static bool supports_multishot_accept();

    // NAPI busy polling: reduce latency by busy-polling the NIC driver.
    bool enable_napi_busy_poll(uint32_t busy_poll_usec, bool prefer = false);

    // Feature queries
    //
    // sqpoll_enabled() is what the ring actually got, which is not the same as
    // what was asked for: SQPOLL needs a kernel that will grant it, and a
    // request that was refused must not be reported back as if it had been
    // honoured.  sqpoll_requested() is the asking side, so the two can be shown
    // apart when they differ.
    bool sqpoll_enabled() const { return m_sqpoll_enabled; }
    bool sqpoll_requested() const { return m_sqpoll_requested; }
    bool direct_accept_supported() const { return m_direct_accept_supported; }

    // Whether a ring exists right now.  False before init() and again after
    // shutdown_ring().  A caller that defers init() until it knows what shape
    // the ring should be — a worker waiting for its config frame — needs to be
    // able to ask, because until this is true poll_completions() returns
    // immediately however long a timeout it was given, and a drain loop written
    // against it would spin a core on nothing.
    bool ring_open() const { return m_ring_open; }

    // The CPU set this loop was configured with, and the one CPU the SQPOLL
    // kernel thread was pinned to (-1 when there is none, either because the
    // set is unrestricted or because SQPOLL is off).
    const cpu_set_spec& cpus() const { return m_cpus; }
    int sq_thread_cpu() const { return m_sq_thread_cpu; }

    // Whether the loop thread's affinity was actually narrowed.  False for an
    // unrestricted set and for a sched_setaffinity that the kernel refused —
    // the difference between "not asked" and "asked and did not get" belongs to
    // the caller, not to a log line nobody reads.
    bool affinity_applied() const { return m_affinity_applied; }

    // How often the submission queue was found full, and how often that ended
    // in an operation being refused the ring anyway.  The second number is the
    // one that costs something: every caller turns a refusal into dropped bytes
    // or a closed connection, so a non-zero count is a delivery defect that has
    // already happened.  Exposed because the alternative is a shortage that
    // only shows up as unexplained losses somewhere else entirely.
    uint64_t sq_full_count() const { return m_sq_full_count; }
    uint64_t sq_exhausted_count() const { return m_sq_exhausted_count; }

private:
    struct io_uring_sqe* get_sqe();
    struct io_uring_sqe* get_sqe_when_full();
    void setup_eventfd();
    bool init_fd_tables();
    void apply_cpu_affinity();

    // What run()'s drain loop must do after one completion.  `stop` is only
    // ever the eventfd's own read reporting, which is how request_stop() ends
    // the loop.  See the note above event_loop::dispatch_cqe in event_loop.cpp
    // for why the decision below is a function at all.
    enum class cqe_outcome : uint8_t { next, stop };
    cqe_outcome dispatch_cqe(struct io_uring_cqe* cqe);

    // Dispatch every completion currently in the ring and advance the queue.
    // Returns how many were consumed; sets got_signal when one of them was the
    // stop eventfd, in which case the ones behind it are deliberately left for
    // the next pass rather than dispatched into a daemon that is shutting down.
    unsigned dispatch_ready(bool& got_signal);

    // Stamp the owner identity and the descriptor(s) named onto a submission,
    // count it as outstanding and count it towards the next flush.  Every
    // submit_* helper ends with this, and passes the number it wrote into the
    // SQE — encoded per IO_TARGET_* — rather than req->fd, which is a routing
    // hint several helpers deliberately set to a different descriptor.
    void arm(io_request* req, uint32_t target, uint32_t target2 = IO_TARGET_NONE);
    // One completion for that submission has landed and no more will follow.
    void disarm(uint32_t token, uint8_t type, uint32_t target, uint32_t target2);
    // A completion nobody can act on any more.
    void drop_completion(const struct io_uring_cqe* cqe, const io_request* req);

    // ── Per-descriptor accounting ───────────────────────────────────────────
    // One counter per number a submission can name, and the release that number
    // is waiting for.  See close_fd() for what the counters are protecting.
    void target_ref(uint32_t target);
    void target_unref(uint32_t target);
    // Perform a close or a slot release that was waiting on the count.
    void settle_deferred(uint32_t target);

    bool fd_tracked(int fd) const
    { return fd >= 0 && static_cast<uint32_t>(fd) < m_fd_table_size; }

    struct io_uring m_ring{};
    std::atomic<bool> m_running;
    uint32_t m_queue_depth;
    uint32_t m_pending_submissions{0};
    uint64_t m_stat_ownerless{0};
    bool     m_warned_ownerless{false};
    int m_eventfd{-1};
    io_request m_signal_req{};
    uint64_t m_signal_buf{};
    bool m_multishot_supported{false};
    // IORING_ACCEPT_POLL_FIRST needs kernel 6.11; probed rather than assumed,
    // because an unknown ioprio bit makes the kernel refuse every accept.
    bool m_accept_poll_first{false};
    bool m_sqpoll_enabled{false};
    // Asked for, as opposed to granted.  Set before init() by set_sqpoll() or,
    // when nothing called that, from the environment inside init().
    bool m_sqpoll_requested{false};
    // Whether a caller chose, as opposed to the value merely being what it
    // starts as.  Only these two say the environment has nothing left to
    // decide; the values above cannot, because "off" and "unrestricted" are
    // both a legitimate choice and the state of having made none.
    bool m_sqpoll_explicit{false};
    bool m_cpus_explicit{false};
    bool m_affinity_applied{false};
    cpu_set_spec m_cpus{};
    int m_sq_thread_cpu{-1};
    bool m_send_zc_supported{false};
    bool m_recv_multishot_supported{false};
    bool m_files_registered{false};
    bool m_bufs_registered{false};
    bool m_direct_accept_supported{false};
    // Whether m_ring is a ring at all: false before init() and again after
    // shutdown_ring().  get_sqe() is the single door every submission goes
    // through, so testing it there covers all of them.
    bool m_ring_open{false};
    // See get_sqe_when_full().  m_sq_full_logged keeps the warning to one line
    // per ring: the condition repeats once per submission for the rest of a
    // fan-out, and a line each would bury the thing it is reporting.
    bool m_sq_full_logged{false};
    uint64_t m_sq_full_count{0};
    uint64_t m_sq_exhausted_count{0};
    // How many times IORING_ENTER_SQ_WAIT may be re-entered for one SQE.  Each
    // return either freed an entry or ended the loop, so this is a bound on
    // signal interruptions and not a retry budget.
    static constexpr unsigned SQ_WAIT_ATTEMPTS = 8;
    uint32_t m_registered_file_count{0};

    // Fixed file slot allocation (bitmap-based)
    static constexpr uint32_t MAX_FIXED_FILES = 8192;
    // Each uint64_t covers 64 slots; 8192/64 = 128 words
    static constexpr uint32_t BITMAP_WORDS = MAX_FIXED_FILES / 64;
    uint64_t m_file_bitmap[BITMAP_WORDS]{};
    uint32_t m_file_bitmap_hint{0};  // hint for next scan start

    // ── Descriptor tables ───────────────────────────────────────────────────
    // Submissions still in the ring that named each raw descriptor, and the two
    // bits per descriptor that say what is waiting on that count: a close, and
    // a cancel of our own we have not seen report yet.  Sized from
    // RLIMIT_NOFILE at init(), because that is exactly the range of numbers the
    // kernel can hand this process.
    //
    // uint16 is not a guess: a descriptor cannot have more submissions
    // outstanding than the ring is deep, and the ring is two thousand entries.
    // Two bytes per possible descriptor keeps a daemon at the usual 1024-file
    // limit under 3 KB of tables.
    uint16_t* m_fd_armed{nullptr};
    uint16_t* m_fd_cancels{nullptr};
    uint64_t* m_fd_close_deferred{nullptr};
    uint32_t  m_fd_table_size{0};
    // Descriptors currently held open only because the ring still names them.
    // Reported at shutdown if any are left, because a number that never drains
    // is the one failure mode this scheme has and it is otherwise invisible.
    uint32_t  m_fd_close_pending{0};
    // Said once: a descriptor above the table cannot be tracked, so it is closed
    // the old way and the hazard is open again for it.  Only reachable if the
    // process's file limit rose after init(), which nothing here does.
    bool      m_fd_untracked_logged{false};

    // The same two things for fixed-file table indices: submissions in the ring
    // naming each slot, and whether the slot is waiting to go back to the
    // allocator.
    uint16_t m_fixed_armed[MAX_FIXED_FILES]{};
    // Submit-to-complete histogram, -DSOCKETLEY_TIMING only.
    SKL_TIMING_MEMBER
    bool m_timing_dumped{false};

    uint64_t m_fixed_free_deferred[BITMAP_WORDS]{};

    // Slots whose unregister is owed as well as their index.  Set when
    // free_fixed_file_slot() had to cancel something first: the cancel names
    // the index and the kernel resolves it when it consumes the SQE, so
    // unregistering before then makes the cancel answer EBADF and withdraw
    // nothing.  Cleared in settle_deferred(), once the operations have
    // reported and the file has done its last work.
    uint64_t m_fixed_unreg_deferred[BITMAP_WORDS]{};

    // The descriptor(s) named by the completion currently being dispatched, and
    // only while it is the last completion that submission will produce.  A
    // handler closing the descriptor it was just called about is the ordinary
    // teardown in every runtime here, and that operation is still counted while
    // the handler runs; close_fd() discounts it rather than making the most
    // common close in the process pay for a cancel round trip.  IO_TARGET_NONE
    // outside a dispatch.
    uint32_t m_cqe_target{IO_TARGET_NONE};
    uint32_t m_cqe_target2{IO_TARGET_NONE};

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
