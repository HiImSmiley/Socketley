#include "event_loop.h"
#include "logging.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <cerrno>
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

    free(m_fd_armed);
    free(m_fd_cancels);
    free(m_fd_close_deferred);
}

void event_loop::shutdown_ring()
{
    // The frame times, if this build was asked to keep them.  Here because it is
    // the one point every process passes through with the numbers complete:
    // run() has returned, the runtimes have stopped, nothing more will be
    // submitted.
    //
    // Guarded, because this function is documented idempotent and the
    // destructor calls it after the explicit call — which printed the whole
    // table twice, and a histogram that appears twice is one a reader has to
    // check is not two different measurements.
    if (!m_timing_dumped)
    {
        m_timing_dumped = true;
        SKL_TIMING_DUMP(m_op_timing, "event loop");
    }

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

    // Descriptors close_fd() is still holding because the ring named them.  The
    // ring is gone now, so nothing can resolve a number any more and the reason
    // to hold them is gone with it — this is the one point where that is true,
    // which is why the sweep lives here and not in the destructor.
    //
    // Reaching here with any is not itself a bug: a daemon told to exit does
    // not wait for every completion first.  It is reported all the same,
    // because a count that grows run after run would mean operations that never
    // report, and that is the one way this scheme leaks descriptors.
    if (m_fd_close_deferred && m_fd_close_pending > 0)
    {
        char msg[160];
        snprintf(msg, sizeof(msg),
            "event loop: %u descriptor(s) were still held open for operations the ring "
            "had not reported; closing them with the ring",
            m_fd_close_pending);
        LOG_INFO(msg);
        for (uint32_t fd = 0; fd < m_fd_table_size; ++fd)
        {
            if ((m_fd_close_deferred[fd >> 6] >> (fd & 63)) & 1u)
            {
                m_fd_close_deferred[fd >> 6] &= ~(1ULL << (fd & 63));
                close(static_cast<int>(fd));
            }
        }
        m_fd_close_pending = 0;
    }

    // Same for fixed-file slots.  The table itself went with the ring, so the
    // bits are only the allocator's idea of what is in use; clearing them keeps
    // a loop that is somehow reused from starting out full.
    for (uint32_t w = 0; w < BITMAP_WORDS; ++w)
    {
        m_file_bitmap[w] &= ~m_fixed_free_deferred[w];
        m_fixed_free_deferred[w] = 0;
    }
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
    int listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
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
        // SOCK_CLOEXEC here for the same reason the port is bound and listened
        // on for real: the probe is only worth its cost if it submits the shape
        // the runtimes submit.  A kernel that refused this flag would refuse it
        // on the live path too, and the probe saying so is the right answer.
        if (multishot)
            io_uring_prep_multishot_accept(sqe, listen_fd, nullptr, nullptr, SOCK_CLOEXEC);
        else
            io_uring_prep_accept(sqe, listen_fd, nullptr, nullptr, SOCK_CLOEXEC);
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

// Centralized SQE acquisition: get an SQE, and go the long way round when the
// ring has none.  The fast path is branch-predicted; everything else is out of
// line in get_sqe_when_full().
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
        sqe = get_sqe_when_full();
    return sqe;
}

// ─── The submission queue is full ───────────────────────────────────────────
//
// Two very different situations arrive here and they need different answers.
//
// WITHOUT SQPOLL, io_uring_submit() is a syscall that consumes everything the
// ring holds, so one submit-and-retry always makes room.  If it does not, the
// kernel refused the submission outright and no amount of waiting changes that.
// That is what the code below the retry is for, and it is unchanged.
//
// UNDER SQPOLL it is not a syscall at all — it is a store to the ring tail —
// and the entries are consumed by a kernel thread at a moment nothing here can
// observe.  The retry therefore waited for room that nothing was making, and
// every caller was told "this never reached the ring" for what is only a
// transient local shortage.  That answer is then read as a permanent
// per-connection failure at nineteen sites across cache, server and proxy: the
// queued bytes are dropped, `closing` is set, or a read is never re-armed.
// Measured on this tree, SQPOLL on, a 2048-entry ring:
//
//     one publish to 3000 subscribers      2048 delivered, 952 thrown away
//                                          silently — never retried, never
//                                          reported, and every one of those
//                                          subscribers still believed it was
//                                          subscribed
//     3000 subscribes, acks read after     up to 250 acknowledgements lost, so
//       all of them were sent                those clients never subscribed at
//                                            all
//
// So the answer here is back-pressure, not loss.  Nothing is wrong with the
// connection and nothing is wrong with the data; the only thing that has run
// out is a queue somebody else is draining right now.  Waiting for one entry
// restores the contract all 145 submit_* call sites already assume — that a
// submission fails when the ring is closed, and otherwise does not.
//
// Growing the ring was the other candidate and it is not an answer: it moves
// the width at which a fan-out overruns the queue without removing it, and the
// next report is the same defect at 8192 subscribers.
//
// The submit() below is load-bearing beyond flushing.  Under SQPOLL liburing
// only enters the kernel when the poller has parked and set IORING_SQ_NEED_WAKEUP,
// and it is that call which carries IORING_ENTER_SQ_WAKEUP; waiting on a parked
// poller without having woken it would be a wait nobody ends.
struct io_uring_sqe* event_loop::get_sqe_when_full()
{
    io_uring_submit(&m_ring);
    m_pending_submissions = 0;

    struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
    if (sqe)
        return sqe;

    if (m_sqpoll_enabled)
    {
        ++m_sq_full_count;

        // io_uring_sqring_wait() returns as soon as the poller has consumed at
        // least one entry, so one pass is normally the whole story; the loop
        // exists for a signal arriving in the middle of it.  A kernel that does
        // not support IORING_ENTER_SQ_WAIT answers -EINVAL, and that must end
        // the loop rather than turn it into a spin.
        for (unsigned attempt = 0; attempt < SQ_WAIT_ATTEMPTS; ++attempt)
        {
            const int r = io_uring_sqring_wait(&m_ring);
            if (r < 0 && r != -EINTR)
                break;
            sqe = io_uring_get_sqe(&m_ring);
            if (sqe)
                break;
        }

        // Once per ring.  The condition repeats for every remaining submission
        // of the fan-out that provoked it, and a line each would bury it.
        if (!m_sq_full_logged)
        {
            m_sq_full_logged = true;
            LOG_WARN("event loop: the submission queue was full and this ring had "
                     "to wait for the SQPOLL thread to drain it; the queue depth "
                     "is below what this workload submits in one go");
        }
    }

    if (!sqe)
    {
        // Whatever else happens, this does not go unsaid.  The caller is about
        // to be told the submission never reached the ring, and every caller
        // turns that into dropped bytes, a closed connection or a read that is
        // never re-armed — none of which the peer is ever told about.
        ++m_sq_exhausted_count;
        if (m_sq_exhausted_count == 1 || (m_sq_exhausted_count % 1000) == 0)
        {
            char msg[192];
            snprintf(msg, sizeof(msg),
                     "event loop: no submission queue entry could be obtained; "
                     "%llu operation(s) have now been refused the ring and their "
                     "data dropped",
                     static_cast<unsigned long long>(m_sq_exhausted_count));
            LOG_ERROR(msg);
        }
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

uint32_t event_loop::token_inflight(uint32_t token) const
{
    // Registration is implicit on the first submission, so a handler still
    // holding a token of zero has never put anything in the ring under an
    // identity of its own and nothing is owed to one.
    if (token == 0)
        return 0;

    // The unverifiable identity shares slot 0 with every other handler that
    // could not be given one, so the slot cannot answer for any single one of
    // them.  What it can answer is the whole slot: while nothing at all is owed
    // there, nothing is owed to this handler either.  That is the honest
    // conservative reading, and it is the same slot the masked lookup below
    // would reach anyway — spelled out because the reasoning is different.
    if (token == OWNER_UNVERIFIED)
        return m_owners[0].inflight;

    const auto& slot = m_owners[token & OWNER_SLOT_MASK];

    // Still the current registration: what the slot counts is what it owes.
    if (slot.token == token)
        return slot.inflight;

    // Revoked, and the slot not handed out since.  deregister_owner() clears
    // the token and deliberately leaves the count standing, so the count is
    // still this registration's and disarm() is what will bring it down.
    if (slot.token == 0)
        return slot.inflight;

    // Handed out again — which register_owner() will only do once the slot's
    // inflight has reached zero, so everything this token named has already
    // reported.  The count now standing belongs to the new occupant.
    return 0;
}

// The two encodings IO_TARGET_* describes, in the form the submit_* helpers
// already have the number in.  A negative one means the caller had no
// descriptor to name, which is not an error here — submit_timeout has none at
// all, and a helper handed -1 would have been refused by the kernel anyway.
static inline uint32_t raw_target(int fd)
{
    return fd >= 0 ? static_cast<uint32_t>(fd) : IO_TARGET_NONE;
}

static inline uint32_t fixed_target(int idx)
{
    return idx >= 0 ? (IO_TARGET_FIXED | static_cast<uint32_t>(idx)) : IO_TARGET_NONE;
}

// ── Per-descriptor accounting ───────────────────────────────────────────────
// One counter per number an SQE can name, so the loop can answer "is anything
// in the ring still going to resolve this number?" — the question every one of
// close_fd(), fd_inflight() and free_fixed_file_slot() is really asking.
//
// It is kept here rather than in the runtimes on purpose.  Each runtime had its
// own idea of what made a descriptor safe to give away, expressed as a list of
// per-connection flags, and the lists disagreed: close_pair's client path was
// missing both splice flags, the backend path was missing the zero-copy
// notification, and none of them could see an operation that another struct had
// armed *onto* their descriptor, which is exactly the shape of the one bug that
// was measured.  Counting where the submission happens cannot have that class of
// gap: the number counted is the number written into the SQE.

inline void event_loop::target_ref(uint32_t target)
{
    if (__builtin_expect(target == IO_TARGET_NONE, 0))
        return;

    if (target & IO_TARGET_FIXED)
    {
        const uint32_t idx = target & ~IO_TARGET_FIXED;
        if (__builtin_expect(idx < MAX_FIXED_FILES, 1) &&
            m_fixed_armed[idx] != UINT16_MAX)
            ++m_fixed_armed[idx];
        return;
    }

    if (__builtin_expect(m_fd_armed != nullptr && target < m_fd_table_size, 1) &&
        m_fd_armed[target] != UINT16_MAX)
        ++m_fd_armed[target];
}

inline void event_loop::target_unref(uint32_t target)
{
    if (__builtin_expect(target == IO_TARGET_NONE, 0))
        return;

    if (target & IO_TARGET_FIXED)
    {
        const uint32_t idx = target & ~IO_TARGET_FIXED;
        // Guarded, not assumed, for the same reason the owner counters are: an
        // unmatched decrement wraps to 65535 and the number is never released
        // again.  A saturated counter stops decrementing too, which is the
        // conservative direction — it holds the number rather than freeing it
        // early — and the ring is two thousand deep, so it cannot be reached.
        if (__builtin_expect(idx < MAX_FIXED_FILES && m_fixed_armed[idx] > 0, 1) &&
            m_fixed_armed[idx] != UINT16_MAX)
        {
            if (--m_fixed_armed[idx] == 0)
                settle_deferred(target);
        }
        return;
    }

    if (__builtin_expect(m_fd_armed != nullptr && target < m_fd_table_size &&
                         m_fd_armed[target] > 0, 1) &&
        m_fd_armed[target] != UINT16_MAX)
    {
        if (--m_fd_armed[target] == 0)
            settle_deferred(target);
    }
}

// The last thing naming this number has reported.  Whatever was waiting on that
// — a close, a slot going back to the allocator — happens now.
void event_loop::settle_deferred(uint32_t target)
{
    if (target & IO_TARGET_FIXED)
    {
        const uint32_t idx = target & ~IO_TARGET_FIXED;
        if (idx >= MAX_FIXED_FILES)
            return;
        const uint32_t w = idx / 64, bit = idx % 64;
        if (!((m_fixed_free_deferred[w] >> bit) & 1u))
            return;
        m_fixed_free_deferred[w] &= ~(1ULL << bit);

        // And the unregister, which free_fixed_file_slot() left to here when it
        // had something to cancel first.  The two cannot both happen at the
        // moment of the release: a cancel naming a fixed index is matched when
        // the kernel CONSUMES the SQE, and register_files_update() is a syscall
        // that takes effect at once — so unregistering on the way out left the
        // cancel resolving an index that pointed at nothing.  Measured, on the
        // seed this was found with: "fixed cancel idx=0 -> res=-9 (Bad file
        // descriptor)", with the recv it was meant to withdraw still armed
        // afterwards.  Here the operations have reported, so the file has done
        // its last work and dropping the reference is safe and final.
        if (m_files_registered && ((m_fixed_unreg_deferred[w] >> bit) & 1u))
        {
            m_fixed_unreg_deferred[w] &= ~(1ULL << bit);
            int neg = -1;
            if (io_uring_register_files_update(&m_ring, idx, &neg, 1) < 0) {}
        }

        m_file_bitmap[w] &= ~(1ULL << bit);
        m_file_bitmap_hint = w;
        return;
    }

    if (!m_fd_close_deferred || target >= m_fd_table_size)
        return;
    const uint32_t w = target >> 6, bit = target & 63;
    if (!((m_fd_close_deferred[w] >> bit) & 1u))
        return;
    // Both counters, not just the one that reached zero: a cancel still in the
    // ring names this number as surely as a read does, and one consumed after
    // the number is reissued takes back the new owner's I/O.
    if (m_fd_armed[target] != 0 || m_fd_cancels[target] != 0)
        return;

    m_fd_close_deferred[w] &= ~(1ULL << bit);
    if (m_fd_close_pending > 0)
        --m_fd_close_pending;
    close(static_cast<int>(target));
}

void event_loop::close_fd(int fd)
{
    if (fd < 0)
        return;

    // No ring, no hazard: before init() nothing can have been submitted
    // (get_sqe refuses), and after shutdown_ring() no SQE can resolve a number
    // any more.  Holding one then would be a descriptor nothing will ever free,
    // because the completion that would release it is never coming.
    if (__builtin_expect(!m_ring_open, 0))
    {
        close(fd);
        return;
    }

    // Above the table, so nothing was ever counted for it and nothing can be
    // promised about it.  Only reachable if the process's file limit grew after
    // init(), which nothing here does — said once so it is not silent if it
    // ever starts happening.
    if (__builtin_expect(!fd_tracked(fd) || !m_fd_armed, 0))
    {
        if (!m_fd_untracked_logged)
        {
            m_fd_untracked_logged = true;
            LOG_WARN("event loop: a descriptor outside the tracked range was closed "
                     "without checking the ring for operations naming it");
        }
        close(fd);
        return;
    }

    const uint32_t t = static_cast<uint32_t>(fd);
    if (__builtin_expect(m_fd_armed[t] == 0 && m_fd_cancels[t] == 0, 1))
    {
        // The common case by a wide margin: the caller closes a descriptor it
        // has already seen every completion for.  One indexed load, then the
        // close it was going to do anyway.
        close(fd);
        return;
    }

    // The second most common case, and the reason this is not simply "count is
    // nonzero, hold it": a handler closing the very descriptor its completion
    // was just delivered for.  Every teardown in the daemon that starts from a
    // read of zero bytes looks like this.  That read is still counted here —
    // run() disarms after the handler returns, not before, so that a handler
    // cannot be shown a half-updated count — and treating it as an operation
    // still to come would put a cancel and a full completion round trip on the
    // most-travelled close path in the process, to withdraw something that has
    // already reported.
    //
    // So the completion in hand is discounted.  The number still is not freed
    // here — the disarm is a few instructions away and settle_deferred() does
    // it there — but nothing is submitted for it.
    uint32_t armed = m_fd_armed[t];
    if (m_cqe_target  == t && armed > 0) --armed;
    if (m_cqe_target2 == t && armed > 0) --armed;

    const uint32_t w = t >> 6, bit = t & 63;
    if ((m_fd_close_deferred[w] >> bit) & 1u)
        return;  // already held; a second close would be a double close

    m_fd_close_deferred[w] |= (1ULL << bit);
    ++m_fd_close_pending;

    // Nothing left to cancel: either only the completion in hand, or only a
    // cancel of our own that has not reported yet — and a second cancel would
    // just answer -ENOENT and cost another SQE.  Either way the number is
    // released by whichever of them settles last.
    if (armed == 0)
        return;

    // Something else really is outstanding.  Make it report now rather than
    // whenever the peer gets around to it: a multishot accept and a poll each
    // hold their own reference to the file, so neither shutdown() nor the close
    // this is standing in for would ever end them, and without this the number
    // would be held for the life of the runtime.  The cancel can only be
    // submitted while the descriptor is still open — after a close, fget
    // answers NULL and it fails -ENOENT — which is exactly the state holding
    // the number keeps it in.
    //
    // If it does not reach the ring, the operations still end on their own and
    // the number is released then; a listener's accept would not, and that
    // descriptor is held until shutdown_ring() reports and sweeps it.
    submit_cancel_fd(fd);
}

uint32_t event_loop::fd_inflight(int fd) const
{
    if (!fd_tracked(fd) || !m_fd_armed)
        return 0;

    const uint32_t t = static_cast<uint32_t>(fd);
    uint32_t armed = m_fd_armed[t];

    // Discounted exactly as close_fd() discounts it, and it matters more here.
    // The proxy pools a backend socket from inside the completion of the read
    // it cancelled to free it — that read is the reason this is being asked,
    // and it has reported: its SQE was consumed to produce the completion in
    // hand, so nothing queued can still resolve this number.  Counting it would
    // mean the answer is never zero on the path that exists to reuse the
    // socket, and every keep-alive connection would be thrown away instead of
    // pooled.
    if (m_cqe_target  == t && armed > 0) --armed;
    if (m_cqe_target2 == t && armed > 0) --armed;
    return armed;
}

// Stamp the owner identity onto the submission and count it as outstanding.
// Reached from every submit_* helper on the path where the SQE was obtained,
// so the count only ever includes submissions that were really queued.
inline void event_loop::arm(io_request* req, uint32_t target, uint32_t target2)
{
    // The submission side of the frame.  Everything below this point is the
    // kernel's time until the completion comes back.
    SKL_TIMING_STAMP(req);

    uint32_t tok = 0;
    if (__builtin_expect(req->owner != nullptr, 1))
    {
        tok = req->owner->m_loop_token;
        if (__builtin_expect(tok == 0, 0))
            tok = register_owner(req->owner);
    }
    else
    {
        // ─── A SUBMISSION WITH NO OWNER IS ONE NOTHING WILL COMPLETE ────────
        //
        // The code below already knows this: a token of 0 "never matches a live
        // registration", so run() drops the completion rather than dispatching
        // it.  What it did not do was SAY so, and the failure that produces has
        // no other symptom — the operation is queued, the kernel performs it,
        // the completion arrives, and it goes in the bin.  Whatever was waiting
        // for it waits for ever.
        //
        // Found the expensive way: a hand-built io_request for a poll on a new
        // kind of socket was left with its owner unset.  Everything was
        // submitted, nothing was ever answered, and the only visible behaviour
        // was that operations needing that socket hung while every operation
        // that did not touch it answered normally — which reads as a protocol
        // defect, not as a missing field.
        //
        // Here rather than at that call site, because this is the one function
        // every submit_* helper passes through on the path where the SQE was
        // obtained.  A caller that forgets is the case this exists for, and a
        // caller cannot be relied on to remember what it did not know about.
        //
        // Once, not per submission: the failure is structural — one forgotten
        // assignment, then every submission on that request — so a line per
        // completion would bury the first one under its own repetitions.
        if (!m_warned_ownerless)
        {
            m_warned_ownerless = true;
            LOG_ERROR("event_loop: a submission was queued with no owner; its "
                      "completion will be dropped and whatever waits for it will "
                      "wait for ever.  Set io_request::owner before submitting.");
        }
        ++m_stat_ownerless;
    }
    req->owner_token = tok;

    // A token of 0 lands on slot 0 next to the unverifiable handlers.  Slot 0
    // is never freed, so counting there costs nothing and keeps this increment
    // and the decrement in run() symmetric without a branch on either side.
    auto& aslot = m_owners[tok & OWNER_SLOT_MASK];
    ++aslot.inflight;
    if (__builtin_expect(req->type < op_type_count, 1))
        ++aslot.by_type[req->type];

    // Recorded on the request, because the completion is the only thing that
    // will name this submission again and it carries nothing else.  Written
    // here rather than by the helpers so that a helper physically cannot queue
    // an SQE without the number in it being counted.
    req->armed_target  = target;
    req->armed_target2 = target2;
    target_ref(target);
    target_ref(target2);

    ++m_pending_submissions;
}

inline void event_loop::disarm(uint32_t token, uint8_t type,
                               uint32_t target, uint32_t target2)
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

    // Last, and after the handler has already run: settle_deferred() can close
    // a descriptor, and doing that before on_cqe would hand the number away
    // while the handler is still reading it out of the completion.  These are
    // the numbers this submission named, saved before the dispatch — see
    // io_request::armed_target.
    target_unref(target);
    target_unref(target2);
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

// Descriptor tables, sized to the range of numbers this process can be handed.
// RLIMIT_NOFILE is exactly that range, so a table this size cannot be indexed
// out of by any descriptor open(), accept() or socket() returns — which is what
// makes close_fd()'s guarantee hold by construction rather than by a cap picked
// to look big enough.
//
// The floor is there because the tables are cheap and a tiny limit can be
// raised out from under us.  The ceiling is there so the allocation stays
// proportional to what the operator actually asked for: four bytes per possible
// descriptor, so a daemon at the usual 1024-file limit spends 4 KB and one
// deliberately configured for a million spends 4 MB — next to nothing beside
// what a million open sockets cost the kernel.
bool event_loop::init_fd_tables()
{
    // Idempotent: a second init() must not strand the counts the first one is
    // already keeping, and the ring the second one builds inherits nothing from
    // the first anyway.
    if (m_fd_armed)
        return true;

    struct rlimit rl{};
    uint64_t want = 4096;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY)
        want = static_cast<uint64_t>(rl.rlim_cur);

    if (want < 4096)    want = 4096;
    if (want > 1048576) want = 1048576;

    const uint32_t n = static_cast<uint32_t>(want);
    const uint32_t words = (n + 63) / 64;

    m_fd_armed          = static_cast<uint16_t*>(calloc(n, sizeof(uint16_t)));
    m_fd_cancels        = static_cast<uint16_t*>(calloc(n, sizeof(uint16_t)));
    m_fd_close_deferred = static_cast<uint64_t*>(calloc(words, sizeof(uint64_t)));

    if (!m_fd_armed || !m_fd_cancels || !m_fd_close_deferred)
    {
        free(m_fd_armed);          m_fd_armed = nullptr;
        free(m_fd_cancels);        m_fd_cancels = nullptr;
        free(m_fd_close_deferred); m_fd_close_deferred = nullptr;
        m_fd_table_size = 0;
        return false;
    }

    m_fd_table_size = n;
    return true;
}

void event_loop::set_sqpoll(bool on)
{
    if (m_ring_open)
    {
        LOG_WARN("event loop: SQPOLL cannot be changed on a ring that already exists");
        return;
    }
    m_sqpoll_requested = on;
    m_sqpoll_explicit = true;
}

void event_loop::set_cpus(const cpu_set_spec& cpus)
{
    if (m_ring_open)
    {
        LOG_WARN("event loop: the CPU set cannot be changed on a ring that already exists");
        return;
    }
    m_cpus = cpus;
    m_cpus_explicit = true;
}

namespace
{

// A boolean written by a human into an environment variable.  Absent is false;
// anything that is not one of these is false and says so, because a daemon that
// silently reads SOCKETLEY_SQPOLL=yes as "off" is a support ticket.
bool env_flag(const char* name, bool& out)
{
    const char* v = getenv(name);
    if (!v || !*v) return false;

    const std::string_view s{v};
    if (s == "1" || s == "true" || s == "on"  || s == "yes") { out = true;  return true; }
    if (s == "0" || s == "false"|| s == "off" || s == "no")  { out = false; return true; }

    char msg[160];
    snprintf(msg, sizeof(msg), "event loop: %s=%s is not a boolean, ignoring", name, v);
    LOG_WARN(msg);
    return false;
}

}   // namespace

// Narrow this thread to the configured set.  Called from init(), before the
// ring is built.
//
// "max" deliberately makes no call at all rather than setting a mask with every
// online CPU in it: those are not the same thing.  A full mask is a snapshot,
// and it would keep the loop off any CPU that comes online afterwards — an
// unrestricted thread is one the scheduler is still free to place anywhere.
void event_loop::apply_cpu_affinity()
{
    m_affinity_applied = false;
    if (m_cpus.all || m_cpus.mask == 0)
        return;

    cpu_set_t set;
    CPU_ZERO(&set);
    for (uint32_t c = 0; c < cpu_set_spec::max_cpus; ++c)
        if (m_cpus.mask & (1ull << c))
            CPU_SET(c, &set);

    if (sched_setaffinity(0, sizeof(set), &set) == 0)
    {
        m_affinity_applied = true;
        return;
    }

    // Not fatal: a cpuset or a container can forbid the move, and a loop on the
    // wrong CPU still serves traffic.  It must not be reported as applied,
    // though — that is the difference between a tuning knob and a lie, and
    // affinity_applied() exists so `stats` can tell them apart.
    char msg[192];
    snprintf(msg, sizeof(msg), "event loop: could not pin the I/O thread to CPUs %s (%s)",
             m_cpus.to_string().c_str(), strerror(errno));
    LOG_WARN(msg);
}

bool event_loop::init()
{
    bool initialized = false;

    // Before the ring, so that no submission can ever be counted against a
    // table that does not exist yet.  A failure here is fatal rather than
    // degraded: without the tables every close is the old unchecked one, and a
    // daemon quietly crossing connections is worse than one that does not start.
    if (!init_fd_tables())
    {
        LOG_ERROR("event loop: could not allocate the descriptor tables");
        return false;
    }

    // ── Where the policy comes from ─────────────────────────────────────────
    // The daemon's ring is created in daemon_start(), before any runtime
    // configuration has been read, so the only thing that can reach it in time
    // is the environment it was launched with.
    //
    // A worker's is not: proxy_worker builds its ring on the config frame and
    // not before, precisely so that a per-runtime ring policy has somewhere to
    // arrive.  Until such a setting exists the worker inherits the daemon's
    // environment and lands in the same place, but the ordering no longer
    // forbids the setting.
    //
    // Explicit set_sqpoll()/set_cpus() win; these fill in for a caller that made
    // no choice.  "No choice" is the explicit-marker and not the value: `daemon
    // --no-sqpoll` and `daemon --cpus max` are choices that happen to name the
    // defaults, and reading them off the value would let the environment
    // silently overrule the command line that was typed to overrule it.
    if (!m_sqpoll_explicit)
        env_flag("SOCKETLEY_SQPOLL", m_sqpoll_requested);

    if (!m_cpus_explicit)
    {
        if (const char* cpus_env = getenv("SOCKETLEY_CPUS"); cpus_env && *cpus_env)
        {
            cpu_set_spec parsed;
            std::string err;
            if (parse_cpu_set(cpus_env, parsed, err))
                m_cpus = parsed;
            else
            {
                char msg[224];
                snprintf(msg, sizeof(msg),
                         "event loop: SOCKETLEY_CPUS=%s rejected (%s), leaving the "
                         "I/O thread unpinned", cpus_env, err.c_str());
                LOG_WARN(msg);
            }
        }
    }

    // Narrowing this thread happens before the ring is built, so that anything
    // the ring allocates is allocated on a CPU the loop will actually run on.
    apply_cpu_affinity();

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

    // ── Priority 1: SQPOLL + SINGLE_ISSUER, and only when asked ─────────────
    // This used to be tried first and unconditionally, so every ring in the
    // process tree came with a kernel thread spinning on its submission queue —
    // one per ring, held for the ring's whole life, whether or not anything was
    // ever submitted into it.  A daemon holding a single idle cache paid for it;
    // with a runtime per process it would be paid once per runtime, which on a
    // small box is three kernel threads polling three empty queues.
    //
    // What it buys, when it is bought deliberately, is that a submission is a
    // store to the tail and nothing else — no io_uring_enter, no syscall at all
    // on the hot path.  That is worth a core to a runtime saturating a link and
    // worth nothing to a runtime waiting for its next connection, and only the
    // operator knows which one this is.
    if (m_sqpoll_requested)
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
        // Where the poller runs.  The CPU set governs it: pinning it inside the
        // same set as the loop thread is the point of naming a set at all —
        // otherwise the two halves of one ring sit on opposite ends of the
        // machine and every submission crosses a cache line between them.
        //
        // io_uring takes a single CPU number here, not a mask, so a set with
        // several members puts the poller on its lowest.  That asymmetry is
        // real and is reported by `stats` as sq_thread_cpu rather than left for
        // someone to discover in /proc.
        //
        // SOCKETLEY_SQPOLL_CPU still overrides, for pinning the poller outside
        // the set the loop thread runs on — the one arrangement --cpus cannot
        // express, and the one a NUMA box sometimes wants.
        int sq_cpu = m_cpus.first();
        if (const char* sq_cpu_env = getenv("SOCKETLEY_SQPOLL_CPU"); sq_cpu_env)
        {
            char* end;
            const long cpu = strtol(sq_cpu_env, &end, 10);
            if (end != sq_cpu_env && cpu >= 0)
                sq_cpu = static_cast<int>(cpu);
        }
        if (sq_cpu >= 0)
        {
            params.flags |= IORING_SETUP_SQ_AFF;
            params.sq_thread_cpu = static_cast<uint32_t>(sq_cpu);
        }
        // Oversized CQ: 4x SQ depth avoids CQ overflow under burst
        params.flags |= IORING_SETUP_CQSIZE;
        params.cq_entries = m_queue_depth * 4;
        if (io_uring_queue_init_params(m_queue_depth, &m_ring, &params) == 0)
        {
            m_sqpoll_enabled = true;
            m_sq_thread_cpu = sq_cpu;
            initialized = true;
        }
        else if (sq_cpu >= 0)
        {
            // SQ_AFF is refused on its own by some kernels and by a cpuset the
            // process is not allowed to leave.  Retry unpinned before giving up
            // on SQPOLL altogether: a poller on the wrong CPU is still a poller,
            // and the alternative is silently answering "no SQPOLL" to an
            // operator who asked for it and only got the pinning wrong.
            params.flags &= ~static_cast<unsigned>(IORING_SETUP_SQ_AFF);
            params.sq_thread_cpu = 0;
            if (io_uring_queue_init_params(m_queue_depth, &m_ring, &params) == 0)
            {
                char msg[128];
                snprintf(msg, sizeof(msg),
                         "event loop: SQPOLL could not be pinned to CPU %d, "
                         "running it unpinned", sq_cpu);
                LOG_WARN(msg);
                m_sqpoll_enabled = true;
                m_sq_thread_cpu = -1;
                initialized = true;
            }
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

    // Asked for and not granted.  Worth a line of its own because the fallback
    // is silent otherwise and looks exactly like a machine that is simply slow:
    // every measurement taken to justify turning SQPOLL on would have been taken
    // without it.
    if (m_sqpoll_requested && !m_sqpoll_enabled)
        LOG_WARN("event loop: SQPOLL was requested but the kernel refused it; "
                 "running without a submission poller");

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

// ─── one completion ─────────────────────────────────────────────────────────
//
// WHY THIS IS A FUNCTION RATHER THAN THE BODY OF THE LOOP BELOW
//
// The kernel chooses the order completions arrive in, and every lifetime defect
// this project found in the last two days came from an order nobody had tried:
// a completion for an owner that had already retired, a multishot that stopped
// without saying so, a provided buffer attached to a completion nothing could
// deliver.  Reproducing one of those needed a running daemon, a load generator
// and a core dump.  The order itself, though, is just a sequence of CQEs, and a
// sequence is something a fuzzer can *write* — if there is anything to hand it
// to.
//
// There was not.  This decision lived inside io_uring_for_each_cqe, and a block
// of code inside a loop is not a symbol: no test can call it, and neither the
// explicit-instantiation trick nor the access-specifier one reaches it, because
// both of those get at *functions*.  That is the same wall
// shared/http_framing.h was lifted over, and the same answer —
// take what was already a self-contained decision and give it a name, so that
// test/fuzz/fuzz_event_loop.cpp can feed it a completion the ring never
// produced.
//
// Nothing about the decision changed in the move.  What it needs from the ring
// is one field of the completion in front of it; everything else is this
// object's own accounting, which is exactly what the fuzz target checks after
// each step.  dispatch_ready() below is the same loop it always was, one call
// shorter.
event_loop::cqe_outcome event_loop::dispatch_cqe(struct io_uring_cqe* cqe)
{
    // A cancel submitted by submit_cancel_fd() reports here.  It has no
    // io_request — there is nothing to act on but "found it" or -ENOENT — but
    // it *did* name a descriptor number, so the fact that it has now been
    // consumed is exactly what close_fd() is waiting for.  It is told apart by
    // the low bit, which no io_request address can have set: they are at least
    // four-byte aligned, and the two removal helpers that also carry no request
    // use a plain zero.
    if (__builtin_expect((cqe->user_data & 1u) != 0, 0))
    {
        const uint32_t cfd = static_cast<uint32_t>(cqe->user_data >> 1);
        if (m_fd_cancels && cfd < m_fd_table_size && m_fd_cancels[cfd] > 0)
        {
            --m_fd_cancels[cfd];
            settle_deferred(cfd);
        }
        return cqe_outcome::next;
    }

    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));

    if (__builtin_expect(req == &m_signal_req, 0))
        return cqe_outcome::stop;

    if (__builtin_expect(req != nullptr, 1))
    {
        // Being readable is not the same as being current.  The owner may have
        // torn down since it submitted this, or the connection struct holding
        // the request may have come back from a pool under a different owner
        // entirely.  One indexed load and one compare settle it, and the answer
        // is known before anything dereferences the handler.
        const uint32_t tok = req->owner_token;

        // Both of these are read before the dispatch, and that is not a
        // convenience: on_cqe may free the storage the request lives in.  A
        // handler is entitled to — this completion is the one that said the
        // kernel was finished with it, and daemon_handler does exactly that
        // when a CLI client hangs up, destroying the ipc_connection whose
        // read_req this is.  Reading req->type afterwards was therefore a read
        // of freed memory on every CLI disconnect.  It survived because the
        // block was normally still mapped; churning server runtimes frees
        // megabytes at a time, so the free that released the connection
        // coalesced into the top chunk, glibc trimmed the heap back to the
        // kernel, and the read landed on an unmapped page.
        //
        // Reading it early is also the more correct value: it is the type this
        // submission was armed with, which is the counter arm() incremented,
        // whatever a re-arm inside on_cqe may have written into the request
        // since.
        const uint8_t rtype = req->type;

        // Read early for the same two reasons, and for a third: on_cqe very
        // often re-arms this very request — the next read on the same
        // connection, or the next leg of a splice onto a different descriptor —
        // and arm() overwrites both fields.  The number to release is the one
        // this completion is for, not the one the handler has just claimed.
        const uint32_t rt1 = req->armed_target;
        const uint32_t rt2 = req->armed_target2;

        // What close_fd() discounts while the handler runs — see there.  Only
        // for a completion that is the operation's last: with
        // IORING_CQE_F_MORE the submission stays armed and is going to resolve
        // its descriptor again, so it is not a number anyone may give away yet.
        const bool final_cqe = (cqe->flags & IORING_CQE_F_MORE) == 0;

        // THE DESCRIPTOR IS DONE BEFORE THE REQUEST IS, AND ONLY HERE.
        //
        // Two different questions are being answered on the way out of this
        // function, and for every operation but one they are answered at the
        // same moment:
        //
        //   may this number be closed, unregistered, reissued?   the targets
        //   may this request's storage be freed?                 the owner
        //
        // IORING_OP_SEND_ZC reports twice — once for the send, and again with
        // IORING_CQE_F_NOTIF once the kernel has released the pages it borrowed
        // — and it answers the two at different times.  After the send CQE the
        // file has done its last work: the SQE has been consumed and nothing
        // queued will resolve the index or the descriptor again.  The
        // notification resolves no file at all; it is the kernel saying it has
        // finished with memory.  So the target reference has to come off here,
        // while the owner count stays up, because that notification is still
        // going to arrive and dispatch it through this same io_request.
        //
        // Holding the target until the notification is not merely
        // conservative — it holds the number for a time nothing local bounds.
        // The notification is released when the socket's write queue is freed,
        // and that is the peer's decision; see send_zc_enabled() for the
        // measurement.  Until it comes, free_fixed_file_slot() cannot run its
        // deferred unregister so the index is never handed back, and close_fd()
        // cannot run its deferred close so the descriptor number is never
        // reissued — both of them waiting on a completion that resolves
        // neither.  Measured on the seed that found it: a 544 KB zero-copy send
        // to a peer that never read, then a stop — "1 operation(s) still owed
        // at OP_DESTROY: send-zc=1 on fixed=0(1)", after 1970 rounds of polling
        // in 2018 ms, with index 0 still reserved.  The cancel that
        // free_fixed_file_slot() submits does not reach it: the send has
        // already completed and a notification is not a request that can be
        // cancelled — on that same seed the cancel withdrew the multishot recv
        // on the index and left this standing.  The raw-descriptor path holds
        // the same way through close_fd(), which is why this is settled here,
        // once, rather than in either release path.
        //
        // Releasing the target here does not make the notification arrive, and
        // is not meant to — nothing in this process can.  It stops one stalled
        // peer from also taking a descriptor number and a registered-file slot
        // out of circulation for the life of the loop.
        const bool zc_send_phase = !final_cqe && rtype == op_send_zc &&
                                   (cqe->flags & IORING_CQE_F_NOTIF) == 0;
        if (__builtin_expect(zc_send_phase, 0))
        {
            // So the notification's own disarm() does not release them a second
            // time.  Safe to clear before the dispatch: every caller of
            // submit_send_zc* refuses to re-arm a request whose notification is
            // outstanding (zc_notif_pending), and a re-arm would overwrite both
            // fields here anyway.
            req->armed_target  = IO_TARGET_NONE;
            req->armed_target2 = IO_TARGET_NONE;
        }

        // What close_fd() discounts while the handler runs — see there.  Only
        // for a completion after which the submission will not resolve its
        // descriptor again: with IORING_CQE_F_MORE a multishot stays armed and
        // is going to name that number once more, so it is not a number anyone
        // may give away yet.  The zero-copy send phase is the exception above —
        // its SQE is spent, so a handler closing the descriptor from inside
        // this completion is entitled to the same discount.
        if (__builtin_expect(final_cqe || zc_send_phase, 1))
        {
            m_cqe_target  = rt1;
            m_cqe_target2 = rt2;
        }

        // Before the dispatch, not after: on_cqe may free the storage this
        // request lives in, and may re-arm it — either way the stamp is gone.
        SKL_TIMING_COMPLETE(m_op_timing, req);

        if (__builtin_expect(m_owners[tok & OWNER_SLOT_MASK].token == tok
                             && req->owner != nullptr, 1))
        {
            SKL_TIMING_HANDLER_BEGIN(req);
            req->owner->on_cqe(cqe);
            SKL_TIMING_HANDLER_END(m_op_timing);
        }
        else
            drop_completion(cqe, req);

        m_cqe_target  = IO_TARGET_NONE;
        m_cqe_target2 = IO_TARGET_NONE;

        // IORING_CQE_F_MORE means the submission is still armed and will
        // complete again; without it this was its last completion, delivered or
        // dropped.  Accounting for the dropped ones too is the point: a slot
        // that keeps looking armed is never reusable, and its owner can never
        // be told it is quiescent.  cqe is the ring's own memory, so it stays
        // readable whatever the handler did with its own.
        if (__builtin_expect(final_cqe, 1))
            disarm(tok, rtype, rt1, rt2);
        else if (__builtin_expect(zc_send_phase, 0))
        {
            // The owner keeps its count — the notification is still owed — but
            // the file is released now.  Last, and after the handler has run,
            // for the reason disarm() gives: settle_deferred() can close a
            // descriptor or unregister a file, and doing that before on_cqe
            // would pull it out from under a handler still reading it.
            target_unref(rt1);
            target_unref(rt2);
        }
    }

    return cqe_outcome::next;
}

// Batch-drain all available CQEs in one pass -- single io_uring_cq_advance.
inline unsigned event_loop::dispatch_ready(bool& got_signal)
{
    struct io_uring_cqe* cqe;
    unsigned head;
    unsigned count = 0;
    got_signal = false;

    io_uring_for_each_cqe(&m_ring, head, cqe)
    {
        count++;
        if (__builtin_expect(dispatch_cqe(cqe) == cqe_outcome::stop, 0))
        {
            got_signal = true;
            break;
        }
    }

    io_uring_cq_advance(&m_ring, count);

    return count;
}

void event_loop::submit_pending()
{
    if (!m_ring_open || m_pending_submissions == 0)
        return;
    io_uring_submit(&m_ring);
    m_pending_submissions = 0;
}

uint32_t event_loop::poll_completions(int timeout_ms)
{
    if (!m_ring_open)
        return 0;

    if (m_pending_submissions > 0)
    {
        io_uring_submit(&m_ring);
        m_pending_submissions = 0;
    }

    struct io_uring_cqe* cqe = nullptr;
    if (io_uring_peek_cqe(&m_ring, &cqe) != 0 || !cqe)
    {
        if (timeout_ms <= 0)
        {
            // Peeking is not enough on its own.  With DEFER_TASKRUN the kernel
            // only runs the task work that posts completions when the ring is
            // entered, so a caller that never enters can watch an empty queue
            // for ever while the work it is waiting for sits ready.
            if (io_uring_get_events(&m_ring) < 0)
                return 0;
            if (io_uring_peek_cqe(&m_ring, &cqe) != 0 || !cqe)
                return 0;
        }
        else
        {
            struct __kernel_timespec ts{
                timeout_ms / 1000,
                static_cast<long long>(timeout_ms % 1000) * 1000000LL };
            if (io_uring_wait_cqe_timeout(&m_ring, &cqe, &ts) < 0 || !cqe)
                return 0;
        }
    }

    bool got_signal = false;
    return dispatch_ready(got_signal);
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
            // The hint points at the default now that SQPOLL is opt-in: most
            // rings in most processes take the submit_and_wait branch, and the
            // one that does not is the one someone deliberately configured.
            if (SOCKETLEY_UNLIKELY(m_sqpoll_enabled))
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

        bool got_signal = false;
        dispatch_ready(got_signal);

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

// ── SOCK_CLOEXEC on every accept, and why it is an SQE field here ───────────
//
// There is no accept() or accept4() call in the daemon: every connection it
// owns arrives through one of these three submissions, and the flags argument
// the kernel reads is the trailing int on the prep, not a flag on any socket()
// this process ever made.  So "the accepted connection must not cross an exec"
// cannot be arranged at creation time the way SOCK_CLOEXEC arranges it for a
// listener — it has to be said on each submission, and a submission that
// forgets is a connection the next proxy worker inherits.
//
// It was forgotten on all of them.  Measured on a worker spawned while one CLI
// command was in flight, /proc/<worker>/fd held the daemon's accepted IPC
// connection as fd 8 alongside the listener as fd 5 — a private channel between
// the daemon and one CLI process, open in an unrelated child, for as long as
// that child lives.
//
// The kernel takes SOCK_CLOEXEC and SOCK_NONBLOCK here and rejects anything
// else with -EINVAL, on the one-shot and the multishot form alike; this is the
// same accept_flags field accept4() would have been given.
bool event_loop::submit_accept(int listen_fd, struct sockaddr_in* addr, socklen_t* addrlen, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_accept(sqe, listen_fd, reinterpret_cast<struct sockaddr*>(addr), addrlen,
                         SOCK_CLOEXEC);
    io_uring_sqe_set_data(sqe, req);
    arm(req, raw_target(listen_fd));
    return true;
}

bool event_loop::submit_multishot_accept(int listen_fd, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    if (m_multishot_supported)
    {
        // Multishot: one SQE handles ALL incoming connections
        io_uring_prep_multishot_accept(sqe, listen_fd, nullptr, nullptr, SOCK_CLOEXEC);
        if (m_accept_poll_first)
            sqe->ioprio |= IORING_ACCEPT_POLL_FIRST;
    }
    else
    {
        io_uring_prep_accept(sqe, listen_fd, nullptr, nullptr, SOCK_CLOEXEC);
    }
    io_uring_sqe_set_data(sqe, req);
    arm(req, raw_target(listen_fd));
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
        //
        // SOCK_CLOEXEC is set on this branch too even though a direct
        // descriptor has no number in the process fd table to inherit: the
        // branch below it is reached whenever registration is not in force, and
        // that one does, so leaving it off here would make whether a connection
        // crosses an exec depend on a capability probe.
        io_uring_prep_multishot_accept(sqe, listen_fd, nullptr, nullptr, SOCK_CLOEXEC);
        sqe->file_index = IORING_FILE_INDEX_ALLOC;
        if (m_accept_poll_first)
            sqe->ioprio |= IORING_ACCEPT_POLL_FIRST;
    }
    else if (m_multishot_supported)
    {
        io_uring_prep_multishot_accept(sqe, listen_fd, nullptr, nullptr, SOCK_CLOEXEC);
        if (m_accept_poll_first)
            sqe->ioprio |= IORING_ACCEPT_POLL_FIRST;
    }
    else
    {
        io_uring_prep_accept(sqe, listen_fd, nullptr, nullptr, SOCK_CLOEXEC);
    }
    io_uring_sqe_set_data(sqe, req);
    arm(req, raw_target(listen_fd));
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
    arm(req, raw_target(fd));
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
    arm(req, raw_target(fd));
    return true;
}

bool event_loop::submit_writev(int fd, struct iovec* iovs, uint32_t count, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_writev(sqe, fd, iovs, count, 0);
    io_uring_sqe_set_data(sqe, req);
    arm(req, raw_target(fd));
    return true;
}

bool event_loop::submit_sendmsg(int fd, struct msghdr* msg, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;
    io_uring_prep_sendmsg(sqe, fd, msg, MSG_NOSIGNAL);
    io_uring_sqe_set_data(sqe, req);
    arm(req, raw_target(fd));
    return true;
}

bool event_loop::submit_recvmsg(int fd, struct msghdr* msg, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_recvmsg(sqe, fd, msg, 0);
    io_uring_sqe_set_data(sqe, req);
    arm(req, raw_target(fd));
    return true;
}

bool event_loop::submit_timeout(struct __kernel_timespec* ts, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_timeout(sqe, ts, 0, 0);
    io_uring_sqe_set_data(sqe, req);
    arm(req, IO_TARGET_NONE);
    return true;
}

bool event_loop::submit_nop(io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_nop(sqe);
    io_uring_sqe_set_data(sqe, req);
    arm(req, IO_TARGET_NONE);
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

// The same withdrawal, for an operation armed on a fixed-file index.
//
// close_fd() cannot reach one: it reads m_fd_armed[fd], and a fixed submission
// is counted in m_fixed_armed[idx] instead, so the descriptor number looks idle
// and its fast path closes without cancelling anything.  This is the other half
// of that question, and until it existed the answer to "how does a fixed
// operation get withdrawn" was that it did not.
//
// IORING_ASYNC_CANCEL_FD_FIXED makes the kernel read the fd field as an index
// into the registered table rather than as a descriptor number; ALL takes every
// request on it in one SQE, as the raw path does.  It must be submitted while
// the index still resolves to a file — free_fixed_file_slot() calls it before
// its unregister for that reason.
//
// No user_data: there is no storage to keep alive and nothing acts on the
// answer, exactly as on the untracked branch of submit_cancel_fd().  The
// operations it withdraws report -ECANCELED to their own owners, which is where
// m_fixed_armed[idx] is decremented and the deferred index finally freed.
bool event_loop::submit_cancel_fixed(uint32_t idx)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_cancel_fd(sqe, static_cast<int>(idx),
                            IORING_ASYNC_CANCEL_ALL | IORING_ASYNC_CANCEL_FD_FIXED);
    io_uring_sqe_set_data(sqe, nullptr);
    m_pending_submissions++;
    return true;
}

bool event_loop::submit_cancel_fd(int fd)
{
    if (fd < 0)
        return false;

    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    // IORING_ASYNC_CANCEL_ALL cancels ALL pending ops for this fd in one shot.
    // Without it, only one op is cancelled per SQE -- leaving the second CQE
    // (e.g. a write when read is also pending) to arrive after the deferred-
    // delete timeout fires and the owning object is freed.
    io_uring_prep_cancel_fd(sqe, fd, IORING_ASYNC_CANCEL_ALL);

    // Tagged with the descriptor rather than left null.  The answer still does
    // not matter — "found it" or -ENOENT, and nothing acts on either — but the
    // arrival does: this SQE names a descriptor number the kernel resolves when
    // it consumes it, so until it reports, that number is no safer to give away
    // than one with a read on it.  Closing first and letting the next accept
    // take the number turns this into a cancel of *that* connection's I/O,
    // which surfaces as a healthy read completing -ECANCELED with nothing in
    // the logs to explain it.
    //
    // The low bit is what tells run() this is not an io_request pointer.  It
    // carries no request deliberately: there is no storage to keep alive for
    // it, and giving it one would mean a per-descriptor allocation on every
    // teardown path.
    if (fd_tracked(fd) && m_fd_cancels && m_fd_cancels[fd] != UINT16_MAX)
    {
        ++m_fd_cancels[fd];
        sqe->user_data = (static_cast<__u64>(static_cast<uint32_t>(fd)) << 1) | 1u;
    }
    else
    {
        // Outside the table, so there is nothing to balance: keep the old
        // behaviour of a completion run() throws away.
        io_uring_sqe_set_data(sqe, nullptr);
    }

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
    arm(req, fixed_target(fixed_idx));
    return true;
}

bool event_loop::submit_write_fixed_file(int fixed_idx, const char* buf, uint32_t len, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_send(sqe, fixed_idx, buf, len, MSG_NOSIGNAL);
    sqe->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data(sqe, req);
    arm(req, fixed_target(fixed_idx));
    return true;
}

bool event_loop::submit_writev_fixed_file(int fixed_idx, struct iovec* iovs, uint32_t count, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_writev(sqe, fixed_idx, iovs, count, 0);
    sqe->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data(sqe, req);
    arm(req, fixed_target(fixed_idx));
    return true;
}

bool event_loop::submit_sendmsg_fixed_file(int fixed_idx, struct msghdr* msg, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;
    io_uring_prep_sendmsg(sqe, fixed_idx, msg, MSG_NOSIGNAL);
    sqe->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data(sqe, req);
    arm(req, fixed_target(fixed_idx));
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
    arm(req, fixed_target(fixed_idx));
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
    arm(req, fixed_target(fixed_idx));
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
    arm(req, fixed_target(fixed_idx));
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
    arm(req, raw_target(fd));
    return true;
}

bool event_loop::submit_write_fixed_buf(int fd, const char* buf, uint32_t len, uint16_t buf_idx, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_write_fixed(sqe, fd, buf, len, 0, buf_idx);
    io_uring_sqe_set_data(sqe, req);
    req->type = op_write_fixed_buf;
    arm(req, raw_target(fd));
    return true;
}

bool event_loop::setup_buf_ring(uint16_t group_id, uint32_t buf_count, uint32_t buf_size)
{
    if (group_id >= MAX_BUF_GROUPS)
        return false;

    // A group is per runtime *type*, not per instance, and that stays: the id is
    // a compile-time constant in each runtime's header (server 1, proxy 2,
    // cache 3, client 4).  A group per instance is not on the table — there are
    // MAX_BUF_GROUPS of them, eight, so it would cap the daemon at eight
    // runtimes in total, and the pools are not small either: a proxy's is
    // 512 x 64 KB = 32 MB, a server's 1024 x 16 KB = 16 MB, so ten proxies with
    // private pools would pin 320 MB before taking a single connection.
    //
    // What was wrong was the silence.  A second instance of a type asked for its
    // own geometry and was handed the first one's without a word: two caches on
    // one daemon share 512 buffers sized by whichever started first, and an
    // operator who raised SOCKETLEY_CACHE_BUF_SIZE for the larger of the two got
    // the smaller one's 4 KB with nothing to read that off.  Sharing is the
    // answer; being quiet about it is not.
    if (m_buf_rings[group_id].ring)
    {
        const auto& existing = m_buf_rings[group_id];
        if (existing.buf_count != buf_count || existing.buf_size != buf_size)
        {
            // Reported rather than refused.  Refusing means answering false, and
            // every caller reads that as "no provided buffers on this loop" and
            // drops to the slower per-connection read path for its whole life —
            // a real throughput loss inflicted to punish a configuration that
            // still works.  The instance runs on the pool that exists, and the
            // operator is told which geometry actually applies to it.
            char msg[224];
            snprintf(msg, sizeof(msg),
                "buffer group %u already exists as %u x %u bytes; this runtime asked for "
                "%u x %u and will run on the existing pool. Buffer geometry is per runtime "
                "type and is set by whichever instance of that type started first",
                static_cast<unsigned>(group_id), existing.buf_count, existing.buf_size,
                buf_count, buf_size);
            LOG_WARN(msg);
        }
        else if (logger::g_level <= log_debug)
        {
            // Even a matching re-registration is worth a line: the pool is now
            // carrying two instances' traffic on one set of buffers, and running
            // it dry is a whole-type symptom, not a per-instance one.
            char msg[160];
            snprintf(msg, sizeof(msg),
                "buffer group %u shared with an already-running runtime of the same type "
                "(%u x %u bytes)",
                static_cast<unsigned>(group_id), existing.buf_count, existing.buf_size);
            LOG_DEBUG(msg);
        }
        return true;
    }

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
    arm(req, raw_target(fd));
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

bool event_loop::send_zc_enabled() const
{
    // Read once: the answer cannot change under a running process, and this is
    // consulted from every runtime's setup().
    static const bool opted_in = [] {
        const char* e = getenv("SOCKETLEY_SEND_ZC");
        return e && e[0] == '1' && e[1] == '\0';
    }();
    return m_send_zc_supported && opted_in;
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
    arm(req, raw_target(fd));
    return true;
}

bool event_loop::submit_send_zc(int fd, const char* buf, uint32_t len, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_send_zc(sqe, fd, buf, len, MSG_NOSIGNAL, 0);
    io_uring_sqe_set_data(sqe, req);
    req->type = op_send_zc;
    arm(req, raw_target(fd));
    return true;
}

bool event_loop::submit_splice(int fd_in, int fd_out, uint32_t len, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    // off_in = off_out = -1 for pipes/sockets (no seekable offset)
    //
    // Still no SPLICE_F_NONBLOCK — the EAGAIN-and-resubmit hazard the previous
    // comment named is a real reason to leave it off, and nothing here has
    // tested the empty-socket case that would trigger it.
    //
    // What that comment got wrong is the other half: it said io_uring "handles
    // the operation asynchronously, so the kernel waits for data internally",
    // which reads as though this were an ordinary poll-driven submission that
    // merely sleeps until data arrives.  It is not.  Every splice is handed to
    // an io-wq worker, and that happens whether or not the data is already
    // there: with the pipe pre-filled and room at the far end, so that blocking
    // was impossible, it still measured 17.19 us against 0.72 us for a read()
    // from that same ready pipe — and 17.32 us for a send() deliberately forced
    // async with IOSQE_ASYNC.  Setting NONBLOCK does not change that number
    // either (17.18 us), because the punt happens before the flag is consulted.
    //
    // See submit_splice in the header for the full table and for the payload
    // size at which the punt stops mattering.
    io_uring_prep_splice(sqe, fd_in, -1, fd_out, -1, len, SPLICE_F_MOVE);
    io_uring_sqe_set_data(sqe, req);
    req->type = op_splice;
    arm(req, raw_target(fd_in), raw_target(fd_out));
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
    arm(req, raw_target(file_fd));
    return true;
}

bool event_loop::submit_poll_add(int fd, unsigned mask, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_poll_add(sqe, fd, mask);
    io_uring_sqe_set_data(sqe, req);
    arm(req, raw_target(fd));
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
    arm(req, raw_target(fd));
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

    // WITH SOMETHING STILL ARMED, THE CANCEL GOES FIRST AND THE UNREGISTER LAST.
    //
    // Until this existed, an operation armed on a fixed index had no way to be
    // withdrawn at all.  close_fd() cancels by descriptor number and a fixed
    // submission is not counted against one — arm(req, fixed_target(idx)) puts
    // it in a different table — so a multishot recv on a direct connection
    // could only ever end by itself, and a multishot recv holds its own
    // reference to the file, so "by itself" means the peer or the socket.  On
    // this project's development machine shutdown() ends it through the socket
    // wait queue every time.  On the nightly runner's kernel it does not, and
    // the harness reported the result there for months in the only words it
    // had: "1 operation(s) still owed at end of input: recv-multishot=1", after
    // 1970 rounds of polling in 2010 ms — a ring being serviced and an
    // operation that was never going to report.
    //
    // The ORDER is the whole of it, and getting it wrong looks exactly like not
    // cancelling.  A cancel naming a fixed index is matched when the kernel
    // consumes the SQE; register_files_update() is a syscall that takes effect
    // immediately.  Submitting the cancel and unregistering on the next line
    // therefore hands the kernel an index pointing at nothing by the time it
    // looks — measured, on the seed this was found with:
    //
    //     [trace] fixed cancel idx=0 -> res=-9 (Bad file descriptor)
    //
    // with the recv it was meant to withdraw still armed afterwards.  Same
    // shape as the flush-then-close hazard this file documents for descriptor
    // numbers, one level up.
    //
    // So the unregister is deferred to settle_deferred(), where it runs once
    // the operations have reported.  Nothing is lost by waiting: the point of
    // unregistering is to drop the kernel's last reference to the socket, and
    // an operation still in flight is that reference.
    if (m_fixed_armed[idx] > 0)
    {
        submit_cancel_fixed(idx);
        m_fixed_free_deferred[w]  |= (1ULL << bit);
        m_fixed_unreg_deferred[w] |= (1ULL << bit);
        return;
    }

    // Nothing armed: unregister now, as this always did.  This is what drops
    // the kernel's reference to the socket; until it runs the descriptor's own
    // close() has not really closed anything.
    int neg = -1;
    if (m_files_registered)
    {
        if (io_uring_register_files_update(&m_ring, idx, &neg, 1) < 0) {}
    }

    // The index itself is a different matter.  Handing it straight back to the
    // allocator while an SQE still names it is the redirection this whole file
    // is about, one level up from descriptor numbers: the next accept takes the
    // slot, points it at its own socket, and the previous connection's queued
    // read is delivered from — or its write into — a stranger.  Neither the
    // unregister above nor the connection's close() prevents it; the SQE
    // carries the index and the kernel looks it up when it consumes it.
    //
    // So the bit stays set until the count says nothing names it.  Callers are
    // not asked to check: release_fixed_slot() runs on the teardown path with
    // reads still armed by design, and every one of them had reasoned that the
    // request "took its own reference when it was issued" — true of a submission
    // the kernel has consumed, and the entire question is the ones it has not.
    m_file_bitmap[w] &= ~(1ULL << bit);
    // Update hint to this word since it now has a free slot
    m_file_bitmap_hint = w;
}

bool event_loop::enable_napi_busy_poll(uint32_t busy_poll_usec, bool prefer)
{
    struct io_uring_napi napi{};
    napi.busy_poll_to = busy_poll_usec;
    napi.prefer_busy_poll = prefer ? 1u : 0u;
    return io_uring_register_napi(&m_ring, &napi) == 0;
}
