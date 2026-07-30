#include "event_loop.h"
#include "logging.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sched.h>


event_loop::event_loop(uint32_t queue_depth)
    : m_running(false), m_queue_depth(queue_depth), m_pending_submissions(0)
{
    // Slot 0 is the shared identity for handlers the table had no room for, and
    // it is live from the start: a submission can happen before init() (nothing
    // stops it), and the compare in run() must not reject it for a reason the
    // owner cannot see or fix.
    m_owners[0].handler = nullptr;
    m_owners[0].token   = OWNER_UNVERIFIED;
    m_owners[0].epoch   = 1;
}

event_loop::~event_loop()
{
    shutdown_ring();

    if (m_eventfd >= 0) close(m_eventfd);
}

void event_loop::shutdown_ring()
{
    if (!m_ring_open)
        return;

    // Before the ring goes, not after.  Every one of these names the ring —
    // io_uring_free_buf_ring unregisters the group through it, and
    // unregister_buffers is a syscall on its fd — and they used to run in this
    // destructor, which is reached long after run() had already exited the
    // ring: a closed descriptor that the process may well have reissued by
    // then, told to release buffers on somebody else's behalf.
    for (uint16_t gid = 0; gid < MAX_BUF_GROUPS; ++gid)
    {
        auto& pool = m_buf_rings[gid];
        if (pool.ring)
        {
            io_uring_free_buf_ring(&m_ring, pool.ring, pool.buf_count, gid);
            pool.ring = nullptr;
        }
        free(pool.base);
        pool.base = nullptr;
    }

    if (m_bufs_registered)
    {
        io_uring_unregister_buffers(&m_ring);
        m_bufs_registered = false;
    }

    // From here every submit_* answers false rather than reaching into an
    // unmapped submission queue: get_sqe() is the single door they all go
    // through, and a caller that is told its submission never landed already
    // knows what to do with that.
    m_ring_open = false;
    io_uring_queue_exit(&m_ring);
}

// Submit one accept SQE built the way submit_multishot_accept() would, against
// a throwaway listener, and report whether the kernel took it.
//
// Probing by opcode is not sufficient for either capability this decides.
// IORING_OP_ACCEPT has existed since 5.5, but *multishot* accept only since
// 5.19 and IORING_ACCEPT_POLL_FIRST only since 6.11 — and both live in
// sqe->ioprio, which older kernels validate against the flags they know,
// rejecting the whole submission with -EINVAL.
//
// Getting this wrong is not a graceful degradation.  The rejection completes
// immediately without IORING_CQE_F_MORE, the accept handler treats a missing
// F_MORE as "multishot ended, re-arm", and the re-armed SQE is rejected again:
// a tight loop that pins roughly two cores per listener while the runtime
// accepts nothing at all.  Measured on 6.17 with a bit no kernel knows, a cache
// runtime answered no PING and the daemon sat at 193% CPU.
//
// An accept that arms successfully produces no completion while no client is
// connecting, so "no CQE waiting straight after submit" is the success signal.
static bool probe_accept_variant(bool multishot, bool poll_first)
{
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
        return false;

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;                       // any free port
    if (bind(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0 ||
        listen(listen_fd, 1) < 0)
    {
        close(listen_fd);
        return false;
    }

    struct io_uring ring;
    if (io_uring_queue_init(4, &ring, 0) < 0)
    {
        close(listen_fd);
        return false;
    }

    bool ok = false;
    struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
    if (sqe)
    {
        if (multishot)
            io_uring_prep_multishot_accept(sqe, listen_fd, nullptr, nullptr, 0);
        else
            io_uring_prep_accept(sqe, listen_fd, nullptr, nullptr, 0);
        if (poll_first)
            sqe->ioprio |= IORING_ACCEPT_POLL_FIRST;
        io_uring_sqe_set_data(sqe, nullptr);

        if (io_uring_submit(&ring) >= 0)
        {
            struct io_uring_cqe* cqe = nullptr;
            if (io_uring_peek_cqe(&ring, &cqe) != 0)
            {
                ok = true;               // armed, nothing to report yet
            }
            else
            {
                ok = (cqe->res >= 0);    // an immediate result here means refusal
                io_uring_cqe_seen(&ring, cqe);
            }
        }
    }

    io_uring_queue_exit(&ring);
    close(listen_fd);
    return ok;
}

bool event_loop::supports_multishot_accept()
{
    return probe_accept_variant(true, false);
}

void event_loop::setup_eventfd()
{
    m_eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (m_eventfd < 0)
        return;

    m_signal_req = { nullptr, reinterpret_cast<char*>(&m_signal_buf), m_eventfd, sizeof(m_signal_buf), op_read };

    struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
    if (sqe)
    {
        io_uring_prep_read(sqe, m_eventfd, &m_signal_buf, sizeof(m_signal_buf), 0);
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
    // There is no ring to hand out an SQE from before init() and none after
    // shutdown_ring(); in both cases the queue pointers are null or unmapped and
    // io_uring_get_sqe() would dereference them.  Every submit_* helper already
    // reports "this never reached the ring" by returning false, so answering
    // that here costs one predictable branch and turns a segfault into the
    // outcome the callers are written for.
    if (__builtin_expect(!m_ring_open, 0))
        return nullptr;

    struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
    if (__builtin_expect(!sqe, 0))
    {
        io_uring_submit(&m_ring);
        m_pending_submissions = 0;
        sqe = io_uring_get_sqe(&m_ring);
    }
    return sqe;
}

uint32_t event_loop::register_owner(io_handler* owner)
{
    if (!owner)
        return 0;

    // Idempotent, and it has to be: re-registering a handler that already has
    // an identity would strand every submission already in the ring under the
    // old one, and those are exactly the completions it is still waiting for.
    if (owner->m_loop_token != 0)
        return owner->m_loop_token;

    for (uint32_t i = 0; i < MAX_OWNERS - 1; ++i)
    {
        const uint32_t s = 1u + ((m_owner_hint + i) % (MAX_OWNERS - 1u));
        auto& slot = m_owners[s];

        // A slot the previous occupant left is only free once nothing is still
        // owed to it.  Handing it out earlier would let a decrement that
        // belongs to a completion already in the ring land on the new
        // occupant's counter, and its slot would then look drained while it is
        // not.
        if (slot.token != 0 || slot.inflight != 0)
            continue;

        // The epoch is the whole reason a recycled slot is a different
        // identity.  It deliberately survives the free above, so the next
        // registration cannot reproduce a token some request is still carrying.
        slot.epoch = static_cast<uint16_t>(slot.epoch + 1);
        if (slot.epoch == 0)
            slot.epoch = 1;

        slot.handler = owner;
        slot.token   = (static_cast<uint32_t>(slot.epoch) << 16) | s;
        m_owner_hint = s;
        owner->m_loop_token = slot.token;
        return slot.token;
    }

    // Said once, because it is a capacity fact rather than an event: from here
    // on some handlers share one identity and stale completions for them are
    // delivered rather than dropped.
    if (!m_owner_table_full_logged)
    {
        m_owner_table_full_logged = true;
        LOG_WARN("event loop owner table full: further handlers share one identity, "
                 "so their completions are delivered without a staleness check");
    }
    owner->m_loop_token = OWNER_UNVERIFIED;
    return OWNER_UNVERIFIED;
}

void event_loop::deregister_owner(io_handler* owner)
{
    if (!owner)
        return;

    const uint32_t tok = owner->m_loop_token;
    owner->m_loop_token = 0;

    // Nothing to revoke for a handler that never registered, and slot 0 is
    // shared — clearing it would revoke every other handler that landed there.
    if (tok == 0 || tok == OWNER_UNVERIFIED)
        return;

    auto& slot = m_owners[tok & OWNER_SLOT_MASK];
    if (slot.token != tok)
        return;

    // Clearing the token is what makes every completion still in the ring for
    // this handler stale.  The slot itself stays claimed until those have
    // drained — see the reuse test in register_owner() — and disarm() releases
    // it when the last one lands.
    slot.token = 0;
    if (slot.inflight == 0)
        slot.handler = nullptr;
}

bool event_loop::owner_registered(const io_handler* owner) const
{
    if (!owner)
        return false;

    const uint32_t tok = owner->m_loop_token;
    if (tok == 0)
        return false;
    if (tok == OWNER_UNVERIFIED)
        return true;

    return m_owners[tok & OWNER_SLOT_MASK].token == tok;
}

void event_loop::owner_inflight_breakdown(const io_handler* owner, uint32_t* out) const
{
    for (uint8_t t = 0; t < op_type_count; ++t)
        out[t] = 0;
    if (!owner)
        return;

    // Slot 0 is skipped for the same reason owner_inflight() skips it: it
    // aggregates every handler that could not be registered, so it cannot
    // answer for any single one of them.
    for (uint32_t s = 1; s < MAX_OWNERS; ++s)
    {
        if (m_owners[s].handler != owner)
            continue;
        for (uint8_t t = 0; t < op_type_count; ++t)
            out[t] += m_owners[s].by_type[t];
    }
}

uint32_t event_loop::owner_inflight(const io_handler* owner) const
{
    if (!owner)
        return 0;

    // Summed over every registration this handler has held, not just its
    // current one: a handler that stopped and started again has a draining slot
    // from the old run and a fresh slot from the new one, and the question this
    // answers — is any request inside my storage still in the ring — is only
    // answered by both.  Slot 0 is skipped on purpose: it counts every handler
    // that could not be registered together, so it cannot answer for any single
    // one of them.
    uint32_t total = 0;
    for (uint32_t s = 1; s < MAX_OWNERS; ++s)
    {
        if (m_owners[s].handler == owner)
            total += m_owners[s].inflight;
    }
    return total;
}

// Stamp the owner identity onto the submission and count it as outstanding.
// Reached from every submit_* helper on the path where the SQE was obtained,
// so the count only ever includes submissions that were really queued.
inline void event_loop::arm(io_request* req)
{
    uint32_t tok = 0;
    if (__builtin_expect(req->owner != nullptr, 1))
    {
        tok = req->owner->m_loop_token;
        if (__builtin_expect(tok == 0, 0))
            tok = register_owner(req->owner);
    }
    req->owner_token = tok;

    // A token of 0 lands on slot 0 next to the unverifiable handlers.  Slot 0
    // is never freed, so counting there costs nothing and keeps this increment
    // and the decrement in run() symmetric without a branch on either side.
    auto& aslot = m_owners[tok & OWNER_SLOT_MASK];
    ++aslot.inflight;
    if (__builtin_expect(req->type < op_type_count, 1))
        ++aslot.by_type[req->type];
    ++m_pending_submissions;
}

inline void event_loop::disarm(uint32_t token, uint8_t type)
{
    auto& slot = m_owners[token & OWNER_SLOT_MASK];
    // Guarded rather than assumed: an unmatched decrement would wrap the
    // counter and the slot would never be reusable again.
    if (__builtin_expect(slot.inflight > 0, 1))
        --slot.inflight;
    if (__builtin_expect(type < op_type_count, 1) && slot.by_type[type] > 0)
        --slot.by_type[type];

    // The owner deregistered while this was still in flight and this was the
    // last one: the slot is now genuinely free, and the handler pointer is
    // dropped so a later object at the same address is not mistaken for it.
    if (__builtin_expect(slot.inflight == 0 && slot.token == 0, 0))
        slot.handler = nullptr;
}

// The completion cannot be delivered.  Whatever the kernel attached to it still
// has to come back, and the loop is the only one left that can do it: the owner
// that would have released the buffer is the reason we are here.
inline void event_loop::drop_completion(const struct io_uring_cqe* cqe, const io_request* req)
{
    if (__builtin_expect((cqe->flags & IORING_CQE_F_BUFFER) != 0, 0))
        return_buf(req->buf_group,
                   static_cast<uint16_t>(cqe->flags >> IORING_CQE_BUFFER_SHIFT));
}

void event_loop::return_cqe_buf(const struct io_uring_cqe* cqe, const io_request* req)
{
    if (!cqe || !req)
        return;
    drop_completion(cqe, req);
}

bool event_loop::init()
{
    bool initialized = false;

    // IORING_SETUP_NO_SQARRAY requires kernel 6.6.  All it saves is one level of
    // indirection when submitting, so it must never cost us the far more valuable
    // SINGLE_ISSUER / DEFER_TASKRUN modes: each setup below is retried without it
    // before giving up and falling through to a weaker configuration.  Without
    // the retry an older kernel drops straight to plain mode and loses every
    // optimization at once, silently.
    const unsigned no_sqarray_opts[2] = { static_cast<unsigned>(IORING_SETUP_NO_SQARRAY), 0u };
    for (unsigned no_sqarray : no_sqarray_opts)
    {
        if (initialized) break;

    // Priority 1: SQPOLL + SINGLE_ISSUER (avoids submit syscalls, needs root)
    {
        struct io_uring_params params{};
        params.flags = IORING_SETUP_SQPOLL | IORING_SETUP_SINGLE_ISSUER
                     | IORING_SETUP_SUBMIT_ALL | no_sqarray;
        // sq_thread_idle: how long the SQPOLL kernel thread keeps polling the
        // submission queue before it sleeps.
        //
        // This interacts with periodic timers in a way that is easy to get
        // wrong.  Any timer re-arming faster than this window prevents the
        // thread from ever sleeping, and a thread that never sleeps is a
        // saturated core no matter how little traffic there is.  Idle cost
        // measured on the dev VM with a cache holding TTL keys, i.e. with the
        // 500ms sweep timer running:
        //
        //   1000ms   100% of a core   (also 50% with no runtime at all,
        //                              the 2s daemon health check suffices)
        //    100ms    21.2%
        //     10ms     2.8%
        //
        // Throughput over redis-benchmark, median of three runs, 100ms vs 10ms:
        // +2.6% mean at pipeline depth 1, -0.8% at depth 100 — both inside the
        // run-to-run noise of the machine.  Sleeping sooner costs nothing
        // measurable because under real load the queue never drains long enough
        // for the timeout to apply; it only decides how fast an *idle* daemon
        // stops burning a core.
        params.sq_thread_idle = 10;
        // Override for tuning against a specific workload.  Lower values let
        // the poller sleep sooner between periodic timers; higher values keep
        // it hot across longer idle gaps at the cost of a busy core.
        const char* idle_env = getenv("SOCKETLEY_SQPOLL_IDLE_MS");
        if (idle_env)
        {
            char* iend;
            long ms = strtol(idle_env, &iend, 10);
            if (iend != idle_env && ms >= 0)
                params.sq_thread_idle = static_cast<uint32_t>(ms);
        }
        // Optional CPU affinity for the SQPOLL kernel thread.
        // Pin to a dedicated core to avoid cross-core cache misses on the SQ.
        // Set SOCKETLEY_SQPOLL_CPU=<N> in the environment before starting the daemon.
        const char* sq_cpu_env = getenv("SOCKETLEY_SQPOLL_CPU");
        if (sq_cpu_env)
        {
            char* end;
            long cpu = strtol(sq_cpu_env, &end, 10);
            if (end != sq_cpu_env && cpu >= 0)
            {
                params.flags |= IORING_SETUP_SQ_AFF;
                params.sq_thread_cpu = static_cast<uint32_t>(cpu);
            }
        }
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
                 | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_COOP_TASKRUN
                 | no_sqarray;
        p2.flags |= IORING_SETUP_CQSIZE;
        p2.cq_entries = m_queue_depth * 4;
        if (io_uring_queue_init_params(m_queue_depth, &m_ring, &p2) == 0)
        {
            initialized = true;
        }
    }

    }   // end NO_SQARRAY retry loop

    // Priority 3: Plain mode
    if (!initialized)
    {
        if (io_uring_queue_init(m_queue_depth, &m_ring, 0) < 0)
            return false;
    }

    // The ring exists from here on, and only from here: everything below and
    // every submission afterwards may reach into it.
    m_ring_open = true;

    // Register the ring fd itself: eliminates an fget/fput per io_uring
    // syscall (submit, wait, enter).  ~1-3% throughput improvement.
    io_uring_register_ring_fd(&m_ring);

    m_multishot_supported = supports_multishot_accept();
    // Only worth probing when multishot itself works; the flag lives in the same
    // ioprio field and is meaningless without it.
    m_accept_poll_first = m_multishot_supported && probe_accept_variant(true, true);

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
                if (io_uring_register_file_alloc_range(&m_ring, 0, MAX_FIXED_FILES) < 0) {}
            }
        }
    }

    setup_eventfd();

    const char* napi_env = getenv("SOCKETLEY_NAPI_BUSY_POLL_US");
    if (napi_env)
    {
        char* end;
        long usec = strtol(napi_env, &end, 10);
        if (end != napi_env && usec > 0)
            enable_napi_busy_poll(static_cast<uint32_t>(usec));
    }

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

            if (__builtin_expect(req != nullptr, 1))
            {
                // Being readable is not the same as being current.  The owner
                // may have torn down since it submitted this, or the connection
                // struct holding the request may have come back from a pool
                // under a different owner entirely.  One indexed load and one
                // compare settle it, and the answer is known before anything
                // dereferences the handler.
                const uint32_t tok = req->owner_token;

                // Both of these are read before the dispatch, and that is not a
                // convenience: on_cqe may free the storage the request lives in.
                // A handler is entitled to — this completion is the one that
                // said the kernel was finished with it, and daemon_handler does
                // exactly that when a CLI client hangs up, destroying the
                // ipc_connection whose read_req this is.  Reading req->type
                // afterwards was therefore a read of freed memory on every CLI
                // disconnect.  It survived because the block was normally still
                // mapped; churning server runtimes frees megabytes at a time, so
                // the free that released the connection coalesced into the top
                // chunk, glibc trimmed the heap back to the kernel, and the
                // read landed on an unmapped page.
                //
                // Reading it early is also the more correct value: it is the
                // type this submission was armed with, which is the counter
                // arm() incremented, whatever a re-arm inside on_cqe may have
                // written into the request since.
                const uint8_t rtype = req->type;

                if (__builtin_expect(m_owners[tok & OWNER_SLOT_MASK].token == tok
                                     && req->owner != nullptr, 1))
                    req->owner->on_cqe(cqe);
                else
                    drop_completion(cqe, req);

                // IORING_CQE_F_MORE means the submission is still armed and
                // will complete again; without it this was its last completion,
                // delivered or dropped.  Accounting for the dropped ones too is
                // the point: a slot that keeps looking armed is never reusable,
                // and its owner can never be told it is quiescent.  cqe is the
                // ring's own memory, so it stays readable whatever the handler
                // did with its own.
                if (__builtin_expect((cqe->flags & IORING_CQE_F_MORE) == 0, 1))
                    disarm(tok, rtype);
            }
        }

        io_uring_cq_advance(&m_ring, count);

        if (__builtin_expect(got_signal, 0))
        {
            m_running.store(false, std::memory_order_release);
            break;
        }
    }

    // The ring is deliberately left standing.  This used to end with
    // io_uring_queue_exit(), and everything the daemon does after run() returns
    // — stopping the runtimes that are still up — was then submitting into a
    // ring that had been unmapped and whose fd was closed: teardown() cancels
    // the operations attached to its descriptors and withdraws its own timers,
    // and the first of those calls dereferenced the freed submission queue.
    // That is a segfault on every SIGTERM with a runtime still running.
    // shutdown_ring() ends it instead, at the point the caller knows both that
    // no more submissions are coming and that nothing has been freed yet.
}

void event_loop::request_stop()
{
    m_running.store(false, std::memory_order_release);

    if (m_eventfd >= 0)
    {
        uint64_t val = 1;
        if (write(m_eventfd, &val, sizeof(val)) < 0) {}
    }
}

int event_loop::get_signal_write_fd() const
{
    return m_eventfd;
}

struct io_uring* event_loop::get_ring()
{
    return &m_ring;
}

bool event_loop::submit_accept(int listen_fd, struct sockaddr_in* addr, socklen_t* addrlen, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_accept(sqe, listen_fd, reinterpret_cast<struct sockaddr*>(addr), addrlen, 0);
    io_uring_sqe_set_data(sqe, req);
    arm(req);
    return true;
}

bool event_loop::submit_multishot_accept(int listen_fd, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    if (m_multishot_supported)
    {
        // Multishot: one SQE handles ALL incoming connections
        io_uring_prep_multishot_accept(sqe, listen_fd, nullptr, nullptr, 0);
        if (m_accept_poll_first)
            sqe->ioprio |= IORING_ACCEPT_POLL_FIRST;
    }
    else
    {
        io_uring_prep_accept(sqe, listen_fd, nullptr, nullptr, 0);
    }
    io_uring_sqe_set_data(sqe, req);
    arm(req);
    return true;
}

bool event_loop::submit_multishot_accept_direct(int listen_fd, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    if (m_multishot_supported && m_files_registered)
    {
        // Direct-descriptor multishot accept: accepted fds go straight into
        // the fixed file table, skipping the per-process fd table entirely.
        // cqe->res will contain the fixed file index, not an fd number.
        io_uring_prep_multishot_accept(sqe, listen_fd, nullptr, nullptr, 0);
        sqe->file_index = IORING_FILE_INDEX_ALLOC;
        if (m_accept_poll_first)
            sqe->ioprio |= IORING_ACCEPT_POLL_FIRST;
    }
    else if (m_multishot_supported)
    {
        io_uring_prep_multishot_accept(sqe, listen_fd, nullptr, nullptr, 0);
        if (m_accept_poll_first)
            sqe->ioprio |= IORING_ACCEPT_POLL_FIRST;
    }
    else
    {
        io_uring_prep_accept(sqe, listen_fd, nullptr, nullptr, 0);
    }
    io_uring_sqe_set_data(sqe, req);
    arm(req);
    return true;
}

bool event_loop::submit_read(int fd, char* buf, uint32_t len, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    // recv() is more efficient than read() for sockets: skips VFS layer,
    // avoids file-position locking, and enables MSG_NOSIGNAL
    io_uring_prep_recv(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data(sqe, req);
    arm(req);
    return true;
}

bool event_loop::submit_write(int fd, const char* buf, uint32_t len, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    // send() with MSG_NOSIGNAL: avoids SIGPIPE if peer closed the connection
    // between our check and the actual send, without needing a global signal mask.
    io_uring_prep_send(sqe, fd, buf, len, MSG_NOSIGNAL);
    io_uring_sqe_set_data(sqe, req);
    arm(req);
    return true;
}

bool event_loop::submit_writev(int fd, struct iovec* iovs, uint32_t count, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_writev(sqe, fd, iovs, count, 0);
    io_uring_sqe_set_data(sqe, req);
    arm(req);
    return true;
}

bool event_loop::submit_sendmsg(int fd, struct msghdr* msg, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;
    io_uring_prep_sendmsg(sqe, fd, msg, MSG_NOSIGNAL);
    io_uring_sqe_set_data(sqe, req);
    arm(req);
    return true;
}

bool event_loop::submit_recvmsg(int fd, struct msghdr* msg, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_recvmsg(sqe, fd, msg, 0);
    io_uring_sqe_set_data(sqe, req);
    arm(req);
    return true;
}

bool event_loop::submit_timeout(struct __kernel_timespec* ts, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_timeout(sqe, ts, 0, 0);
    io_uring_sqe_set_data(sqe, req);
    arm(req);
    return true;
}

bool event_loop::submit_timeout_remove(io_request* target)
{
    if (!target)
        return false;

    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    // Keyed on the user_data the timeout was submitted with, which is the
    // address of its io_request — event_loop.h says why there is nothing else
    // to key on.  The kernel only compares the value; it never dereferences it.
    io_uring_prep_timeout_remove(
        sqe, static_cast<__u64>(reinterpret_cast<std::uintptr_t>(target)), 0);
    // No request of its own, exactly like submit_cancel_fd: the removal's answer
    // is only "found it" or "-ENOENT", nothing here acts on either, and run()
    // skips a completion that names no request without dispatching or counting
    // it.  So there is no arm() here and no disarm() owed for it.  The timeout
    // being withdrawn keeps the one it already had — it still reports, with
    // -ECANCELED, and that completion is what balances its submit_timeout().
    io_uring_sqe_set_data(sqe, nullptr);
    m_pending_submissions++;
    return true;
}

bool event_loop::submit_cancel_fd(int fd)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    // IORING_ASYNC_CANCEL_ALL cancels ALL pending ops for this fd in one shot.
    // Without it, only one op is cancelled per SQE -- leaving the second CQE
    // (e.g. a write when read is also pending) to arrive after the deferred-
    // delete timeout fires and the owning object is freed.
    io_uring_prep_cancel_fd(sqe, fd, IORING_ASYNC_CANCEL_ALL);
    // Null user_data so the cancel-result CQE is silently discarded by event_loop::run()
    io_uring_sqe_set_data(sqe, nullptr);
    m_pending_submissions++;
    return true;
}

// Fixed-file variants: use the IOSQE_FIXED_FILE flag so the kernel uses
// the pre-registered file reference, skipping fget/fput per I/O op.
bool event_loop::submit_read_fixed_file(int fixed_idx, char* buf, uint32_t len, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_recv(sqe, fixed_idx, buf, len, 0);
    sqe->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data(sqe, req);
    arm(req);
    return true;
}

bool event_loop::submit_write_fixed_file(int fixed_idx, const char* buf, uint32_t len, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_send(sqe, fixed_idx, buf, len, MSG_NOSIGNAL);
    sqe->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data(sqe, req);
    arm(req);
    return true;
}

bool event_loop::submit_writev_fixed_file(int fixed_idx, struct iovec* iovs, uint32_t count, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_writev(sqe, fixed_idx, iovs, count, 0);
    sqe->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data(sqe, req);
    arm(req);
    return true;
}

bool event_loop::submit_sendmsg_fixed_file(int fixed_idx, struct msghdr* msg, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;
    io_uring_prep_sendmsg(sqe, fixed_idx, msg, MSG_NOSIGNAL);
    sqe->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data(sqe, req);
    arm(req);
    return true;
}

bool event_loop::submit_recv_multishot_fixed_file(int fixed_idx, uint16_t group_id, io_request* req)
{
    if (group_id >= MAX_BUF_GROUPS || !m_buf_rings[group_id].ring)
        return false;

    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_recv_multishot(sqe, fixed_idx, nullptr, 0, 0);
    sqe->flags |= IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE;
    sqe->buf_group = group_id;
    io_uring_sqe_set_data(sqe, req);
    req->type = op_recv_multishot;
    // Recorded on the request because a completion never names its group, and
    // the loop may end up having to return the buffer itself.
    req->buf_group = static_cast<uint8_t>(group_id);
    arm(req);
    return true;
}

bool event_loop::submit_read_provided_fixed_file(int fixed_idx, uint16_t group_id, io_request* req)
{
    if (group_id >= MAX_BUF_GROUPS || !m_buf_rings[group_id].ring)
        return false;

    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_recv(sqe, fixed_idx, nullptr, m_buf_rings[group_id].buf_size, 0);
    sqe->flags |= IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE;
    sqe->buf_group = group_id;
    io_uring_sqe_set_data(sqe, req);
    req->type = op_read_provided;
    req->buf_group = static_cast<uint8_t>(group_id);
    arm(req);
    return true;
}

bool event_loop::submit_send_zc_fixed_file(int fixed_idx, const char* buf, uint32_t len, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_send_zc(sqe, fixed_idx, buf, len, MSG_NOSIGNAL, 0);
    sqe->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data(sqe, req);
    req->type = op_send_zc;
    arm(req);
    return true;
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

bool event_loop::submit_read_fixed_buf(int fd, char* buf, uint32_t len, uint16_t buf_idx, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_read_fixed(sqe, fd, buf, len, 0, buf_idx);
    io_uring_sqe_set_data(sqe, req);
    req->type = op_read_fixed_buf;
    arm(req);
    return true;
}

bool event_loop::submit_write_fixed_buf(int fd, const char* buf, uint32_t len, uint16_t buf_idx, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_write_fixed(sqe, fd, buf, len, 0, buf_idx);
    io_uring_sqe_set_data(sqe, req);
    req->type = op_write_fixed_buf;
    arm(req);
    return true;
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

bool event_loop::submit_read_provided(int fd, uint16_t group_id, io_request* req)
{
    if (group_id >= MAX_BUF_GROUPS || !m_buf_rings[group_id].ring)
        return false;

    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_recv(sqe, fd, nullptr, m_buf_rings[group_id].buf_size, 0);
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = group_id;
    io_uring_sqe_set_data(sqe, req);
    req->type = op_read_provided;
    req->buf_group = static_cast<uint8_t>(group_id);
    arm(req);
    return true;
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
            io_uring_buf_ring_mask(pool.buf_count), static_cast<int>(i));
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

bool event_loop::submit_recv_multishot(int fd, uint16_t group_id, io_request* req)
{
    if (group_id >= MAX_BUF_GROUPS || !m_buf_rings[group_id].ring)
        return false;

    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_recv_multishot(sqe, fd, nullptr, 0, 0);
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = group_id;
    io_uring_sqe_set_data(sqe, req);
    req->type = op_recv_multishot;
    req->buf_group = static_cast<uint8_t>(group_id);
    arm(req);
    return true;
}

bool event_loop::submit_send_zc(int fd, const char* buf, uint32_t len, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_send_zc(sqe, fd, buf, len, MSG_NOSIGNAL, 0);
    io_uring_sqe_set_data(sqe, req);
    req->type = op_send_zc;
    arm(req);
    return true;
}

bool event_loop::submit_splice(int fd_in, int fd_out, uint32_t len, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    // off_in = off_out = -1 for pipes/sockets (no seekable offset)
    // No SPLICE_F_NONBLOCK: io_uring handles the operation asynchronously, so the
    // kernel waits for data internally. NONBLOCK would return EAGAIN immediately
    // when the socket has no data, causing a tight re-submit loop in SQPOLL mode.
    io_uring_prep_splice(sqe, fd_in, -1, fd_out, -1, len, SPLICE_F_MOVE);
    io_uring_sqe_set_data(sqe, req);
    req->type = op_splice;
    arm(req);
    return true;
}

bool event_loop::submit_file_read(int file_fd, char* buf, uint32_t len, uint64_t offset, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    // Use io_uring_prep_read (not recv) — works on regular files
    io_uring_prep_read(sqe, file_fd, buf, len, offset);
    io_uring_sqe_set_data(sqe, req);
    req->type = op_file_read;
    arm(req);
    return true;
}

bool event_loop::submit_poll_add(int fd, unsigned mask, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_poll_add(sqe, fd, mask);
    io_uring_sqe_set_data(sqe, req);
    arm(req);
    return true;
}

bool event_loop::submit_poll_remove(io_request* target)
{
    if (!target)
        return false;

    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    // Keyed on the user_data the poll was submitted with, which is the address
    // of its io_request — the same key submit_timeout_remove uses, and for the
    // same reason.  The kernel only compares the value; it never dereferences
    // it, so a request whose storage has since been retired is still a safe key.
    io_uring_prep_poll_remove(
        sqe, static_cast<__u64>(reinterpret_cast<std::uintptr_t>(target)));
    // No request of its own, exactly like submit_timeout_remove: the removal's
    // answer is only "found it" or "-ENOENT", nothing acts on either, and run()
    // skips a completion that names no request without dispatching or counting
    // it.  So there is no arm() here and no disarm() owed for it.  The poll
    // being withdrawn keeps the one it already had — it still reports, with
    // -ECANCELED, and that completion is what balances its submit_poll_add().
    io_uring_sqe_set_data(sqe, nullptr);
    m_pending_submissions++;
    return true;
}

bool event_loop::submit_connect(int fd, const struct sockaddr* addr, socklen_t len, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_connect(sqe, fd, addr, len);
    io_uring_sqe_set_data(sqe, req);
    arm(req);
    return true;
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
            uint32_t idx = w * 64 + static_cast<uint32_t>(bit);

            // The bitmap spans MAX_FIXED_FILES, but only m_registered_file_count
            // entries actually exist in the kernel's table.  Handing out anything
            // past that produces a slot update_registered_file always rejects,
            // and the caller then has a number it cannot use and cannot give
            // back — the bit stayed set for the lifetime of the loop, so the
            // table filled up with slots that were never really in use.
            if (idx >= m_registered_file_count)
                return -1;

            m_file_bitmap[w] |= (1ULL << bit);
            m_file_bitmap_hint = w;
            return static_cast<int>(idx);
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

bool event_loop::enable_napi_busy_poll(uint32_t busy_poll_usec, bool prefer)
{
    struct io_uring_napi napi{};
    napi.busy_poll_to = busy_poll_usec;
    napi.prefer_busy_poll = prefer ? 1u : 0u;
    return io_uring_register_napi(&m_ring, &napi) == 0;
}
