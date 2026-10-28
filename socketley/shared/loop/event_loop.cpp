#include "event_loop.h"
#include "../util/logging.h"
#include "eventfd_wake.h"
#include "../util/number_parse.h"
#include "../util/settings.h"
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <sched.h>


event_loop::event_loop(uint32_t queue_depth)
    : m_running(false), m_queue_depth(queue_depth), m_pending_submissions(0)
{
    // Slot 0 is the shared identity for handlers the table had no room for,
    // live from the start because a submission can happen before init().
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
    // The frame times if this build kept them, here because it is the one
    // point every process passes with the numbers complete, and guarded
    // because this function is idempotent and the destructor calls it again.
    if (!m_timing_dumped)
    {
        m_timing_dumped = true;
        SKL_TIMING_DUMP(m_op_timing, "event loop");
    }

    if (!m_ring_open)
        return;

    // Before the ring goes, because every one of these names the ring, and
    // running them in the destructor told a closed and possibly reissued
    // descriptor to release buffers.
    // The buffers themselves go only after the ring has, since a receive the kernel already gave one to may still
    // be writing into it until the ring's requests are cancelled.
    std::vector<char*> bases;
    for (uint16_t gid = 0; gid < MAX_BUF_GROUPS; ++gid)
    {
        auto& pool = m_buf_rings[gid];
        if (pool.ring)
        {
            io_uring_free_buf_ring(&m_ring, pool.ring, pool.buf_count, gid);
            pool.ring = nullptr;
        }
        if (pool.base)
            bases.push_back(pool.base);
        pool.base = nullptr;
    }

    if (m_bufs_registered)
    {
        io_uring_unregister_buffers(&m_ring);
        m_bufs_registered = false;
    }

    // From here every submit_* answers false rather than reaching into an
    // unmapped submission queue, because get_sqe() is the single door they all
    // go through.
    m_ring_open = false;
    // Whatever was queued dies with the ring and the registrations with it, so
    // nothing left standing says a submission or a file table is still there.
    m_pending_submissions  = 0;
    m_files_registered     = false;
    m_registered_file_count = 0;
    io_uring_queue_exit(&m_ring);
    for (char* b : bases)
        free(b);

    // Descriptors close_fd() was holding because the ring named them, swept
    // here because this is the one point where nothing can resolve a number
    // any more, and reported because a count that grows run after run is how
    // this scheme leaks.
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

    // Same for fixed-file slots, whose table went with the ring, so clearing
    // the bits keeps a reused loop from starting out full.
    for (uint32_t w = 0; w < BITMAP_WORDS; ++w)
    {
        m_file_bitmap[w] &= ~m_fixed_free_deferred[w];
        m_fixed_free_deferred[w] = 0;
    }
}

// Submit one real accept SQE against a throwaway listener, because multishot
// accept and IORING_ACCEPT_POLL_FIRST live in sqe->ioprio and an older kernel
// rejects the whole submission -- which the accept handler reads as "re-arm"
// and spins two cores per listener on.
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
        // SOCK_CLOEXEC here for the same reason the port is really bound: the
        // probe is only worth its cost if it submits the shape the runtimes
        // submit.
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

// One real recv carrying IORING_RECVSEND_POLL_FIRST on an empty socket pair,
// because the bit lives in sqe->ioprio and a kernel that checks that field
// without knowing the bit fails every read that carries it with -EINVAL.
static bool probe_recv_poll_first()
{
    int sv[2] = { -1, -1 };
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0)
        return false;

    struct io_uring ring;
    if (io_uring_queue_init(4, &ring, 0) < 0)
    {
        close(sv[0]);
        close(sv[1]);
        return false;
    }

    bool ok = false;
    char buf[16];
    struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
    if (sqe)
    {
        io_uring_prep_recv(sqe, sv[0], buf, sizeof(buf), 0);
        sqe->ioprio |= IORING_RECVSEND_POLL_FIRST;
        io_uring_sqe_set_data(sqe, nullptr);

        if (io_uring_submit(&ring) >= 0)
        {
            struct io_uring_cqe* cqe = nullptr;
            if (io_uring_peek_cqe(&ring, &cqe) != 0)
            {
                ok = true;               // armed on an empty socket, as it should be
            }
            else
            {
                ok = (cqe->res >= 0);    // an immediate answer here means refusal
                io_uring_cqe_seen(&ring, cqe);
            }
        }
    }

    io_uring_queue_exit(&ring);
    close(sv[0]);
    close(sv[1]);
    return ok;
}

// Whether a file taken out of the fixed table is put at once while a recv on
// another slot is still armed, because a kernel that frees its resource nodes
// in order holds every socket closed after an idle connection's recv, and the
// peer of each sits in FIN-WAIT-2 with this side in CLOSE-WAIT until that one
// connection goes.
static bool probe_fixed_file_release()
{
    int idle[2] = { -1, -1 }, gone[2] = { -1, -1 };
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, idle) < 0)
        return false;
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, gone) < 0)
    {
        close(idle[0]);
        close(idle[1]);
        return false;
    }

    struct io_uring ring;
    bool ring_open = (io_uring_queue_init(4, &ring, 0) == 0);
    bool ok = false;
    int files[2] = { idle[0], gone[0] };
    if (ring_open && io_uring_register_files(&ring, files, 2) == 0)
    {
        char buf[16];
        struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
        if (sqe)
        {
            // The idle connection: a recv on slot 0 that nothing will answer.
            io_uring_prep_recv(sqe, 0, buf, sizeof(buf), 0);
            sqe->flags |= IOSQE_FIXED_FILE;
            io_uring_sqe_set_data(sqe, nullptr);
            if (io_uring_submit(&ring) == 1)
            {
                // The closed connection: its own descriptor and then its slot,
                // which is the order every teardown here takes.
                close(gone[0]);
                gone[0] = -1;
                int neg = -1;
                if (io_uring_register_files_update(&ring, 1, &neg, 1) == 1)
                {
                    // The put runs as task work before the update returns to
                    // this thread, so a kernel that has done it shows the
                    // hangup without waiting.
                    struct pollfd p = { gone[1], POLLIN | POLLRDHUP, 0 };
                    ok = (::poll(&p, 1, 0) == 1 && (p.revents & (POLLHUP | POLLRDHUP)));
                }
            }
        }
    }
    if (ring_open)
        io_uring_queue_exit(&ring);
    const int fds[] = { idle[0], idle[1], gone[0], gone[1] };
    for (int fd : fds)
        if (fd >= 0) close(fd);
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

// Centralised SQE acquisition, with everything but the branch-predicted fast
// path out of line in get_sqe_when_full().
inline struct io_uring_sqe* event_loop::get_sqe()
{
    // There is no ring before init() and none after shutdown_ring(), so one
    // predictable branch turns a dereference of null queue pointers into the
    // false every submit_* helper is already written for.
    if (__builtin_expect(!m_ring_open, 0))
        return nullptr;

    struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
    if (__builtin_expect(!sqe, 0))
        sqe = get_sqe_when_full();
    return sqe;
}

// ─── The submission queue is full ───────────────────────────────────────────
// Back-pressure and not loss: one submit-and-retry always makes room, which is
// what keeps a transient shortage from being reported to nineteen call sites
// as a permanent per-connection failure.
struct io_uring_sqe* event_loop::get_sqe_when_full()
{
    io_uring_submit(&m_ring);
    m_pending_submissions = 0;

    struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe)
    {
        // Whatever else happens this does not go unsaid, because every caller
        // turns a refused submission into dropped bytes or a closed connection
        // and the peer is never told.
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
        // owed to it, or a decrement belonging to a completion already in the
        // ring lands on the new occupant's counter.
        if (slot.token != 0 || slot.inflight != 0)
            continue;

        // The epoch is what makes a recycled slot a different identity, so it
        // survives the free above and no registration can reproduce a token
        // some request is still carrying.
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

    // Clearing the token makes every completion still in the ring for this
    // handler stale, while the slot stays claimed until they have drained.
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

    // Summed over every registration this handler has held, because a handler
    // that stopped and started has a draining slot and a fresh one, and slot 0
    // is skipped because it cannot answer for any single handler.
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

    // The unverifiable identity shares slot 0, which cannot answer for one
    // handler but can answer for the whole slot: while nothing is owed there,
    // nothing is owed to this handler either.
    if (token == OWNER_UNVERIFIED)
        return m_owners[0].inflight;

    const auto& slot = m_owners[token & OWNER_SLOT_MASK];

    // Still the current registration: what the slot counts is what it owes.
    if (slot.token == token)
        return slot.inflight;

    // Revoked and not handed out since, because deregister_owner() clears the
    // token and leaves the count standing for disarm() to bring down.
    if (slot.token == 0)
        return slot.inflight;

    // Handed out again, which register_owner() only does once the slot's
    // inflight reached zero, so the count now standing belongs to the new
    // occupant.
    return 0;
}

// The two IO_TARGET_* encodings in the form the submit_* helpers already hold
// the number, where a negative one means the caller had no descriptor to name.
static inline uint32_t raw_target(int fd)
{
    return fd >= 0 ? static_cast<uint32_t>(fd) : IO_TARGET_NONE;
}

static inline uint32_t fixed_target(int idx)
{
    return idx >= 0 ? (IO_TARGET_FIXED | static_cast<uint32_t>(idx)) : IO_TARGET_NONE;
}

// ── Per-descriptor accounting ───────────────────────────────────────────────
// One counter per number an SQE can name, kept here rather than in the
// runtimes because each runtime's own list of what made a descriptor safe
// disagreed and none could see an operation another struct had armed onto its
// descriptor.

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
        // Guarded rather than assumed, because an unmatched decrement wraps to
        // 65535 and the number is never released, while a saturated counter
        // merely holds it.
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

// The last thing naming this number has reported, so whatever was waiting on
// that happens now.
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

        // And the unregister free_fixed_file_slot() deferred, because a cancel
        // naming a fixed index is matched when the SQE is consumed while
        // register_files_update() takes effect at once, leaving the cancel
        // resolving an index pointing at nothing.
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

    // No ring, no hazard: nothing can have been submitted before init() and no
    // SQE can resolve a number after shutdown_ring(), so holding one then
    // would be a descriptor nothing will ever free.
    if (__builtin_expect(!m_ring_open, 0))
    {
        close(fd);
        return;
    }

    // Above the table, so nothing was counted for it and nothing can be
    // promised about it, said once in case it ever starts happening.
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
        // has already seen every completion for.
        close(fd);
        return;
    }

    // The completion in hand is discounted, because a handler closing the
    // descriptor its completion was just delivered for is every teardown in
    // the daemon, and counting it would put a cancel round trip on the
    // most-travelled close path.
    uint32_t armed = m_fd_armed[t];
    if (m_cqe_target  == t && armed > 0) --armed;
    if (m_cqe_target2 == t && armed > 0) --armed;

    const uint32_t w = t >> 6, bit = t & 63;
    if ((m_fd_close_deferred[w] >> bit) & 1u)
        return;  // already held; a second close would be a double close

    m_fd_close_deferred[w] |= (1ULL << bit);
    ++m_fd_close_pending;

    // Nothing left to cancel -- only the completion in hand, or only a cancel
    // of our own not yet reported -- and the number is released by whichever
    // settles last.
    if (armed == 0)
        return;

    // Something else really is outstanding, so make it report now: a multishot
    // accept and a poll each hold their own reference to the file, and the
    // cancel can only be submitted while the descriptor is still open.
    submit_cancel_fd(fd);
}

uint32_t event_loop::fd_inflight(int fd) const
{
    if (!fd_tracked(fd) || !m_fd_armed)
        return 0;

    const uint32_t t = static_cast<uint32_t>(fd);
    uint32_t armed = m_fd_armed[t];

    // Discounted exactly as close_fd() discounts it, and it matters more here,
    // because the proxy pools a backend socket from inside the completion of
    // the read it cancelled and the answer would otherwise never be zero.
    if (m_cqe_target  == t && armed > 0) --armed;
    if (m_cqe_target2 == t && armed > 0) --armed;
    return armed;
}

// Stamp the owner identity onto the submission and count it, reached only
// where the SQE was obtained so the count includes only submissions that were
// really queued.
inline void event_loop::arm(io_request* req, uint32_t target, uint32_t target2)
{
    // The submission side of the frame, after which everything is the kernel's
    // time until the completion comes back.
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
        // A submission with no owner is one nothing will complete, and the
        // failure has no other symptom, so it is said here -- the one function
        // every submit_* helper passes through -- and said once, because it is
        // structural.
        if (!m_warned_ownerless)
        {
            m_warned_ownerless = true;
            LOG_ERROR("event_loop: a submission was queued with no owner; its "
                      "completion will be dropped and whatever waits for it will "
                      "wait for ever.  Set io_request::owner before submitting.");
        }
    }
    req->owner_token = tok;

    // A token of 0 lands on slot 0, which is never freed, so counting there
    // keeps this increment and run()'s decrement symmetric without a branch.
    auto& aslot = m_owners[tok & OWNER_SLOT_MASK];
    ++aslot.inflight;
    if (__builtin_expect(req->type < op_type_count, 1))
        ++aslot.by_type[req->type];

    // Recorded on the request because the completion carries nothing else, and
    // written here so a helper physically cannot queue an SQE whose number
    // goes uncounted.
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

    // Last, and after the handler has run, because settle_deferred() can close
    // a descriptor the handler is still reading out of the completion.
    target_unref(target);
    target_unref(target2);
}

// The completion cannot be delivered, and the loop is the only one left that
// can return what the kernel attached to it.
inline void event_loop::drop_completion(const struct io_uring_cqe* cqe, const io_request* req)
{
    if (__builtin_expect((cqe->flags & IORING_CQE_F_BUFFER) != 0, 0))
    {
        // A bundle names only its first buffer, so returning that one alone
        // would leak the rest from a pool every instance of the runtime type
        // shares.
        if (cqe == m_cqe_current && m_cqe_buf_count > 1)
            return_bufs_batch(req->buf_group, m_cqe_bids, m_cqe_buf_count);
        else
            return_buf(req->buf_group,
                       static_cast<uint16_t>(cqe->flags >> IORING_CQE_BUFFER_SHIFT));
    }
}

// The consumption cursor's one chokepoint, checked on every buffered
// completion, where a mismatch disables bundles for the group rather than
// silently appending the wrong buffer's bytes; the ids are snapshotted because
// a return writes at the ring's tail.
inline void event_loop::decode_cqe_bufs(const struct io_uring_cqe* cqe,
                                        const io_request* req, uint8_t rtype)
{
    m_cqe_current = cqe;
    const uint16_t first =
        static_cast<uint16_t>(cqe->flags >> IORING_CQE_BUFFER_SHIFT);
    m_cqe_bids[0]   = first;
    m_cqe_buf_count = 1;

    const uint16_t group = req->buf_group;
    if (__builtin_expect(group >= MAX_BUF_GROUPS, 0))
        return;
    auto& pool = m_buf_rings[group];
    if (__builtin_expect(!pool.ring || !pool.cursor_ok, 0))
        return;

    uint32_t count = 1;
    if (rtype == op_recv_multishot_bundle && cqe->res > 0 &&
        static_cast<uint32_t>(cqe->res) > pool.buf_size)
    {
        count = (static_cast<uint32_t>(cqe->res) + pool.buf_size - 1) / pool.buf_size;
        // Unreachable, because a completion cannot carry more buffers than the
        // group holds, but clamped anyway rather than writing past m_cqe_bids.
        if (__builtin_expect(count > MAX_CQE_BUFS, 0))
            count = MAX_CQE_BUFS;
    }

    const uint32_t mask = pool.buf_count - 1;
    if (__builtin_expect(
            static_cast<uint16_t>(pool.ring->bufs[pool.consumed & mask].bid)
                != first, 0))
    {
        // The cursor no longer describes the kernel's consumption, so bundles
        // stop being armed for this group and the cursor is not advanced past
        // an entry it cannot vouch for.
        pool.cursor_ok = false;
        char msg[160];
        snprintf(msg, sizeof(msg),
            "buffer group %u: consumption cursor predicted buffer %u, kernel "
            "reported %u; bundled recv disabled for this group",
            static_cast<unsigned>(group),
            static_cast<unsigned>(pool.ring->bufs[pool.consumed & mask].bid),
            static_cast<unsigned>(first));
        LOG_ERROR(msg);
        return;
    }

    for (uint32_t i = 1; i < count; i++)
        m_cqe_bids[i] = static_cast<uint16_t>(
            pool.ring->bufs[(pool.consumed + i) & mask].bid);
    pool.consumed += count;
    m_cqe_buf_count = count;
}

void event_loop::return_cqe_buf(const struct io_uring_cqe* cqe, const io_request* req)
{
    if (!cqe || !req)
        return;
    drop_completion(cqe, req);
}

// Descriptor tables sized to RLIMIT_NOFILE, which is exactly the range of
// numbers this process can be handed, with a floor because the tables are
// cheap and a ceiling to keep the allocation proportional.
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

// Narrow this thread to the configured set before the ring is built, where
// "max" makes no call at all rather than pinning to the CPUs that happen to be
// online now.
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

    // Not fatal, since a cpuset can forbid the move and a loop on the wrong
    // CPU still serves traffic, but not reported as applied either.
    char msg[192];
    snprintf(msg, sizeof(msg), "event loop: could not pin the I/O thread to CPUs %s (%s)",
             m_cpus.to_string().c_str(), strerror(errno));
    LOG_WARN(msg);
}

bool event_loop::init()
{
    bool initialized = false;

    // Before the ring, so no submission is counted against a table that does
    // not exist, and fatal on failure because a daemon quietly crossing
    // connections is worse than one that does not start.
    if (!init_fd_tables())
    {
        LOG_ERROR("event loop: could not allocate the descriptor tables");
        return false;
    }

    // ── Where the policy comes from ─────────────────────────────────────────
    // The daemon's ring is created before any runtime configuration is read,
    // so only the environment can reach it in time, and an explicit set_cpus()
    // wins because the marker and not the value is what says a choice was made.
    if (!m_cpus_explicit)
    {
        if (const char* cpus_env = socketley::settings::text("SOCKETLEY_CPUS"); cpus_env && *cpus_env)
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

    // IORING_SETUP_NO_SQARRAY saves one indirection and needs 6.6, so each
    // setup below is retried without it rather than dropping straight to plain
    // mode and losing SINGLE_ISSUER and DEFER_TASKRUN at once.
    const unsigned no_sqarray_opts[2] = { static_cast<unsigned>(IORING_SETUP_NO_SQARRAY), 0u };
    for (unsigned no_sqarray : no_sqarray_opts)
    {
        if (initialized) break;

    // Priority 1: SINGLE_ISSUER + DEFER_TASKRUN (defers task_work to
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

    // Priority 2: plain mode, once SINGLE_ISSUER with and without NO_SQARRAY
    // has been refused.
    if (!initialized)
    {
        if (io_uring_queue_init(m_queue_depth, &m_ring, 0) < 0)
            return false;
    }

    // The ring exists from here on, and only from here: everything below and
    // every submission afterwards may reach into it.
    m_ring_open = true;

    // A loop waits with its accepts and receives armed, which the kernel counts as I/O wait unless told otherwise, so
    // a host idle but for socketley read one blocked task per process in its load average and its iowait.
    if (io_uring_set_iowait(&m_ring, false) < 0) {}

    // Register the ring fd itself, which removes an fget/fput per io_uring
    // syscall for about 1-3% throughput.
    io_uring_register_ring_fd(&m_ring);

    m_multishot_supported = supports_multishot_accept();
    // Only worth probing when multishot itself works; the flag lives in the same
    // ioprio field and is meaningless without it.
    m_accept_poll_first = m_multishot_supported && probe_accept_variant(true, true);
    m_recv_poll_first = probe_recv_poll_first();

    // IORING_OP_RECV exists from 5.6 and its multishot flag only from 6.0, so the opcode table cannot answer this.
    m_recv_multishot_supported = probe_recv_multishot();

    // Pre-register a sparse fixed file table with every slot empty,
    // heap-allocated to avoid a 32 KB stack frame, and only on a kernel that
    // closes a removed socket while another one is idle, because every caller
    // keeps its plain descriptor and falls back to it when no slot is handed out.
    if (probe_fixed_file_release())
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

    if (const auto usec = socketley::settings::number<uint32_t>("SOCKETLEY_NAPI_BUSY_POLL_US"))
        enable_napi_busy_poll(*usec);

    return true;
}

void event_loop::flush()
{
    // The ring test get_sqe() makes, because this is the one submission-side
    // entry that does not go through it and io_uring_submit() on a torn-down
    // ring dereferences an unmapped queue.
    if (m_ring_open && m_pending_submissions > 0)
    {
        io_uring_submit(&m_ring);
        m_pending_submissions = 0;
    }
}

// ─── one completion ─────────────────────────────────────────────────────────
// A function rather than the body of the loop below, so
// test/fuzz/fuzz_event_loop.cpp can feed it a completion sequence the ring
// never produced -- a block of code inside a loop is not a symbol.
event_loop::cqe_outcome event_loop::dispatch_cqe(struct io_uring_cqe* cqe)
{
    // A cancel submitted by submit_cancel_fd() carries no io_request but did
    // name a descriptor, and is told apart by a low bit no io_request address
    // can have set.
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
        // Being readable is not the same as being current, so one indexed load
        // and one compare settle it before anything dereferences the handler.
        const uint32_t tok = req->owner_token;

        // Read before the dispatch, because on_cqe may free the storage the
        // request lives in, and because this is the type the submission was
        // armed with whatever a re-arm has since written.
        const uint8_t rtype = req->type;

        // Read early for the same reasons and a third: on_cqe often re-arms
        // this very request, and the number to release is the one this
        // completion is for.
        const uint32_t rt1 = req->armed_target;
        const uint32_t rt2 = req->armed_target2;

        // Before the owner check, because a dropped completion consumed its
        // buffers exactly like a delivered one, and with no branch hint since
        // this function serves both kinds of loop.
        if ((cqe->flags & IORING_CQE_F_BUFFER) != 0)
            decode_cqe_bufs(cqe, req, rtype);

        // What close_fd() discounts while the handler runs, only for a
        // completion that is the operation's last, since IORING_CQE_F_MORE
        // means the submission will resolve its descriptor again.
        const bool final_cqe = (cqe->flags & IORING_CQE_F_MORE) == 0;
        if (__builtin_expect(final_cqe, 1))
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
            // A multishot receive the kernel refused is re-armed as a single one here, once for every runtime,
            // rather than handed to a read chain that closes the connection over it.
            if (__builtin_expect(cqe->res != -EINVAL, 1) || !rearm_refused_multishot(cqe, req, rtype, rt1))
            {
                SKL_TIMING_HANDLER_BEGIN(req);
                req->owner->on_cqe(cqe);
                SKL_TIMING_HANDLER_END(m_op_timing);
            }
        }
        else
            drop_completion(cqe, req);

        m_cqe_target  = IO_TARGET_NONE;
        m_cqe_target2 = IO_TARGET_NONE;
        m_cqe_buf_count = 0;
        m_cqe_current   = nullptr;

        // Without IORING_CQE_F_MORE this was the submission's last completion,
        // delivered or dropped, and accounting for the dropped ones too is the
        // point, since a slot that keeps looking armed is never reusable.
        if (__builtin_expect(final_cqe, 1))
            disarm(tok, rtype, rt1, rt2);
    }

    return cqe_outcome::next;
}

bool event_loop::rearm_refused_multishot(const struct io_uring_cqe* cqe, io_request* req,
                                         uint8_t rtype, uint32_t target)
{
    // Only the final, bufferless answer to a kind the probe passed, which is what a kernel refusing the flag sends.
    if (!is_multishot_recv_op(static_cast<op_type>(rtype)) || !m_recv_multishot_supported
        || (cqe->flags & (IORING_CQE_F_MORE | IORING_CQE_F_BUFFER)) != 0 || target == IO_TARGET_NONE)
        return false;

    if (!m_recv_multishot_refused)
    {
        m_recv_multishot_refused = true;
        LOG_WARN("event loop: the kernel refused a multishot receive the probe had accepted, so this loop "
                 "reads with single receives from now on");
    }

    // A number waiting to be closed takes the refusal itself, since a receive armed now would hold it open with
    // nothing left to cancel it.
    const bool     fixed = (target & IO_TARGET_FIXED) != 0;
    const uint32_t idx   = target & ~IO_TARGET_FIXED;
    if (fixed)
    {
        if (idx >= MAX_FIXED_FILES || ((m_fixed_unreg_deferred[idx >> 6] >> (idx & 63)) & 1u))
            return false;
        return submit_read_provided_fixed_file(static_cast<int>(idx), req->buf_group, req);
    }
    if (!fd_tracked(static_cast<int>(idx)) || !m_fd_close_deferred
        || ((m_fd_close_deferred[idx >> 6] >> (idx & 63)) & 1u))
        return false;
    return submit_read_provided(static_cast<int>(idx), req->buf_group, req);
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

// ─── one ring entry ─────────────────────────────────────────────────────────
// The counter is zeroed here and in the sibling below, on the entry that handed
// the SQEs to the kernel and on no path that only peeked.
inline int event_loop::enter_get_events()
{
    if (m_pending_submissions == 0)
        return io_uring_get_events(&m_ring);
    const int rc = io_uring_submit_and_get_events(&m_ring);
    m_pending_submissions = 0;
    return rc;
}

// Like io_uring_wait_cqe_timeout this can come back non-negative with no
// completion, so the caller tests the pointer and not the return.
inline int event_loop::enter_wait_timeout(struct io_uring_cqe** cqe,
                                          struct __kernel_timespec* ts)
{
    if (m_pending_submissions == 0)
        return io_uring_wait_cqe_timeout(&m_ring, cqe, ts);
    const int rc = io_uring_submit_and_wait_timeout(&m_ring, cqe, 1, ts, nullptr);
    m_pending_submissions = 0;
    return rc;
}

uint32_t event_loop::poll_completions(int timeout_ms)
{
    if (!m_ring_open)
        return 0;

    struct io_uring_cqe* cqe = nullptr;
    if (io_uring_peek_cqe(&m_ring, &cqe) != 0)
        cqe = nullptr;

    // A turn that will spin makes its first entry before the credit is
    // settled, because that entry also carries the queued submissions and one
    // of them completing inline is a hit the credit is not charged for.
    uint32_t spun = 0;
    if (!cqe && m_spin && m_pending_submissions > 0 && timeout_ms > 0
        && credit_after_turn(m_last_batch, m_busy_credit) > 0)
    {
        if (enter_get_events() < 0 || io_uring_peek_cqe(&m_ring, &cqe) != 0)
            cqe = nullptr;
        spun = 1;
    }

    if (cqe)
    {
        // A completion already posted is dispatched only after the queued
        // submissions have gone out, or a reply queued by the last dispatch
        // sits in the ring for as long as completions keep arriving without it.
        if (m_pending_submissions > 0)
            enter_get_events();
    }
    else if (timeout_ms <= 0)
    {
        // Peeking is not enough on its own, because with DEFER_TASKRUN the
        // kernel only runs the task work that posts completions when the
        // ring is entered.
        if (enter_get_events() < 0)
        { m_last_batch = 0; return 0; }
        if (io_uring_peek_cqe(&m_ring, &cqe) != 0 || !cqe)
        { m_last_batch = 0; return 0; }
    }
    else
    {
        // A turn that drained more than one completion is mid-batch and
        // its next one is due in well under the sleep it would otherwise
        // take, so it enters the ring again instead; one completion per
        // turn is an idle loop and must sleep at once, or a runtime with
        // no traffic burns a core.
        // A turn is asked whether the loop is busy exactly when it is
        // about to sleep, which is the one moment the previous turn is a
        // poor witness; a credit that a batch refills and every quiet turn
        // spends answers for the phase instead of the instant.
        m_busy_credit = m_spin ? credit_after_turn(m_last_batch, m_busy_credit) : 0;

        for (uint32_t s = m_busy_credit ? SPIN_BUDGET - spun : 0; s > 0; --s)
        {
            // Entering the ring is what runs the task work that posts
            // completions under DEFER_TASKRUN, so this is a syscall and
            // not a userspace read of the completion queue.
            if (enter_get_events() < 0)
                break;
            if (io_uring_peek_cqe(&m_ring, &cqe) == 0 && cqe)
            {
                // A spin that found work is the phase still being busy, even
                // when every turn of it drains one completion.
                m_busy_credit = BUSY_CREDIT;
                break;
            }
            cqe = nullptr;
        }

        if (!cqe)
        {
            struct __kernel_timespec ts{
                timeout_ms / 1000,
                static_cast<long long>(timeout_ms % 1000) * 1000000LL };
            if (enter_wait_timeout(&cqe, &ts) < 0 || !cqe)
            { m_last_batch = 0; return 0; }
        }
    }

    bool got_signal = false;
    m_last_batch = dispatch_ready(got_signal);
    return m_last_batch;
}

void event_loop::run()
{
    m_running.store(true, std::memory_order_release);

    struct io_uring_cqe* cqe;

    while (__builtin_expect(m_running.load(std::memory_order_relaxed), 1))
    {
        // Flush pending submissions, then peek first so a completion that
        // already landed skips the blocking wait entirely.
        if (m_pending_submissions > 0)
        {
            io_uring_submit_and_wait(&m_ring, 1);
            m_pending_submissions = 0;
        }

        if (io_uring_peek_cqe(&m_ring, &cqe) != 0)
        {
            // Ring is empty: block until at least one CQE arrives.  Any signal
            // ends the wait with -EINTR, and one that is not a stop request of
            // ours -- a ptrace attach, a SIGSTOP -- must not end the daemon.
            const int rc = io_uring_wait_cqe(&m_ring, &cqe);
            if (rc == -EINTR)
                continue;
            if (rc < 0)
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

    // The ring is deliberately left standing, because stopping the runtimes
    // that are still up submits into it, and shutdown_ring() ends it at the
    // point the caller knows no more submissions are coming.
}

void event_loop::request_stop()
{
    m_running.store(false, std::memory_order_release);

    if (m_eventfd >= 0)
        socketley::eventfd_bump(m_eventfd);
}

int event_loop::get_signal_write_fd() const
{
    return m_eventfd;
}

struct io_uring* event_loop::get_ring()
{
    return &m_ring;
}

// SOCK_CLOEXEC has to be said on every accept submission rather than at socket
// creation, because there is no accept4() call in the daemon and a submission
// that forgets is a connection the next worker inherits.
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
        // Direct-descriptor multishot accept puts the fd straight into the
        // fixed table and reports an index, with SOCK_CLOEXEC set here too so
        // whether a connection crosses an exec does not depend on a capability
        // probe.
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

bool event_loop::submit_read(int fd, char* buf, uint32_t len, io_request* req, bool poll_first)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    // recv() is more efficient than read() for sockets: skips VFS layer,
    // avoids file-position locking, and enables MSG_NOSIGNAL
    io_uring_prep_recv(sqe, fd, buf, len, 0);
    if (poll_first && m_recv_poll_first)
        sqe->ioprio |= IORING_RECVSEND_POLL_FIRST;
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

    // Keyed on the user_data the timeout was submitted with, which the kernel
    // compares without ever dereferencing.
    io_uring_prep_timeout_remove(
        sqe, static_cast<__u64>(reinterpret_cast<std::uintptr_t>(target)), 0);
    // No request of its own, so no arm() and no disarm() owed, while the
    // timeout being withdrawn keeps the one it already had and reports
    // -ECANCELED.
    io_uring_sqe_set_data(sqe, nullptr);
    m_pending_submissions++;
    return true;
}

// The same withdrawal for a fixed-file index, which close_fd() cannot reach
// because a fixed submission is counted elsewhere, submitted while the index
// still resolves and carrying no user_data.
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

    // IORING_ASYNC_CANCEL_ALL takes every pending operation on this fd in one
    // SQE, without which the second completion arrives after the owning object
    // has been freed.
    io_uring_prep_cancel_fd(sqe, fd, IORING_ASYNC_CANCEL_ALL);

    // Tagged with the descriptor rather than left null, because this SQE names
    // a number the kernel resolves late and its arrival is what close_fd()
    // waits for; the low bit tells run() it is not an io_request pointer.
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
    if (m_recv_multishot_refused || group_id >= MAX_BUF_GROUPS || !m_buf_rings[group_id].ring)
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

    // A buffer group is per runtime type and stays that way, because eight
    // groups would cap the daemon at eight runtimes and private pools would
    // pin hundreds of megabytes -- what was wrong was handing a second
    // instance the first one's geometry without a word.
    if (m_buf_rings[group_id].ring)
    {
        const auto& existing = m_buf_rings[group_id];
        if (existing.buf_count != buf_count || existing.buf_size != buf_size)
        {
            // Reported rather than refused, because every caller reads false
            // as "no provided buffers on this loop" and drops to the slower
            // path for its whole life.
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
    // Align to a 2 MB huge page for TLB coverage on the buffer pool, falling
    // back to 4 K when the allocation is small.
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
        io_uring_buf_ring_add(br, base + (static_cast<size_t>(i) * buf_size), buf_size, static_cast<uint16_t>(i),
            io_uring_buf_ring_mask(buf_count), static_cast<int>(i));
    }
    io_uring_buf_ring_advance(br, buf_count);

    m_buf_rings[group_id] = { br, base, buf_count, buf_size };
    return true;
}

bool event_loop::submit_read_provided(int fd, uint16_t group_id, io_request* req, bool poll_first)
{
    if (group_id >= MAX_BUF_GROUPS || !m_buf_rings[group_id].ring)
        return false;

    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_recv(sqe, fd, nullptr, m_buf_rings[group_id].buf_size, 0);
    if (poll_first && m_recv_poll_first)
        sqe->ioprio |= IORING_RECVSEND_POLL_FIRST;
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

bool event_loop::recv_multishot_enabled() const
{
    // The environment read once, the same way recv_bundle_enabled() reads its
    // own: neither it nor the kernel changes under a running process.
    static const bool opted_out = [] {
        const char* e = socketley::settings::text("SOCKETLEY_RECV_MULTISHOT");
        return e && std::string_view(e) == "0";
    }();
    return m_recv_multishot_supported && !m_recv_multishot_refused && !opted_out;
}

bool event_loop::submit_recv_multishot(int fd, uint16_t group_id, io_request* req)
{
    // Refused here as well as in recv_multishot_enabled(), because every runtime caches that answer at start.
    if (m_recv_multishot_refused || group_id >= MAX_BUF_GROUPS || !m_buf_rings[group_id].ring)
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

// Kernel support for IORING_RECV_MULTISHOT established the way probe_recv_bundle() establishes its flag, because a
// 5.19 kernel accepts the opcode and refuses the flag with -EINVAL at the first read of every connection.
bool event_loop::probe_recv_multishot()
{
    struct io_uring r;
    if (io_uring_queue_init(8, &r, 0) < 0)
        return false;

    bool ok = false;
    int  e  = 0;
    struct io_uring_buf_ring* br = io_uring_setup_buf_ring(&r, 4, 0, 0, &e);
    char bufs[4][64];
    int  sv[2] = { -1, -1 };
    if (br && ::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0)
    {
        for (int i = 0; i < 4; i++)
            io_uring_buf_ring_add(br, bufs[i], 64, static_cast<uint16_t>(i),
                                  io_uring_buf_ring_mask(4), i);
        io_uring_buf_ring_advance(br, 4);

        struct io_uring_sqe* sqe = io_uring_get_sqe(&r);
        if (sqe)
        {
            io_uring_prep_recv_multishot(sqe, sv[0], nullptr, 0, 0);
            sqe->flags  |= IOSQE_BUFFER_SELECT;
            sqe->buf_group = 0;
            io_uring_submit(&r);

            char payload[32] = {};
            if (::write(sv[1], payload, sizeof(payload)) < 0) {}

            struct io_uring_cqe* cqe = nullptr;
            struct __kernel_timespec ts = { 0, 200 * 1000 * 1000 };
            if (io_uring_wait_cqe_timeout(&r, &cqe, &ts) == 0 && cqe)
            {
                // The bytes alone are not enough: a receive that delivered them and ended is a single-shot one.
                ok = cqe->res == static_cast<int>(sizeof(payload))
                  && (cqe->flags & IORING_CQE_F_MORE) != 0;
                io_uring_cqe_seen(&r, cqe);
            }
        }
    }
    if (sv[0] >= 0) ::close(sv[0]);
    if (sv[1] >= 0) ::close(sv[1]);
    if (br) io_uring_free_buf_ring(&r, br, 4, 0);
    io_uring_queue_exit(&r);
    return ok;
}

// Kernel support for IORING_RECVSEND_BUNDLE established by a real bundled
// submission on a throwaway ring, because the flag is not an opcode and a
// version number has already lied to this tree once.
bool event_loop::probe_recv_bundle()
{
    struct io_uring r;
    if (io_uring_queue_init(8, &r, 0) < 0)
        return false;

    bool ok = false;
    int  e  = 0;
    struct io_uring_buf_ring* br = io_uring_setup_buf_ring(&r, 4, 0, 0, &e);
    char bufs[4][64];
    int  sv[2] = { -1, -1 };
    if (br && ::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0)
    {
        for (int i = 0; i < 4; i++)
            io_uring_buf_ring_add(br, bufs[i], 64, static_cast<uint16_t>(i),
                                  io_uring_buf_ring_mask(4), i);
        io_uring_buf_ring_advance(br, 4);

        struct io_uring_sqe* sqe = io_uring_get_sqe(&r);
        if (sqe)
        {
            io_uring_prep_recv_multishot(sqe, sv[0], nullptr, 0, 0);
            sqe->ioprio |= IORING_RECVSEND_BUNDLE;
            sqe->flags  |= IOSQE_BUFFER_SELECT;
            sqe->buf_group = 0;
            io_uring_submit(&r);

            char payload[100] = {};
            if (::write(sv[1], payload, sizeof(payload)) < 0) {}

            struct io_uring_cqe* cqe = nullptr;
            struct __kernel_timespec ts = { 0, 200 * 1000 * 1000 };
            if (io_uring_wait_cqe_timeout(&r, &cqe, &ts) == 0 && cqe)
            {
                // A kernel without the flag answers -EINVAL and one with it
                // delivers the bytes, and anything else is treated as no,
                // because arming a mode this probe could not see working is
                // how a probe becomes a version number.
                ok = cqe->res == static_cast<int>(sizeof(payload));
                io_uring_cqe_seen(&r, cqe);
            }
        }
    }
    if (sv[0] >= 0) ::close(sv[0]);
    if (sv[1] >= 0) ::close(sv[1]);
    if (br) io_uring_free_buf_ring(&r, br, 4, 0);
    io_uring_queue_exit(&r);
    return ok;
}

bool event_loop::recv_bundle_enabled() const
{
    // Read and probed once: neither the kernel nor the environment changes
    // under a running process.
    static const bool enabled = [] {
        if (!socketley::settings::flag("SOCKETLEY_RECV_BUNDLE", true))
            return false;
        return probe_recv_bundle();
    }();
    return enabled;
}

bool event_loop::submit_recv_multishot_bundle(int fd, uint16_t group_id, io_request* req)
{
    if (m_recv_multishot_refused || group_id >= MAX_BUF_GROUPS || !m_buf_rings[group_id].ring)
        return false;
    auto& pool = m_buf_rings[group_id];
    // A tripped cursor cannot name a bundle's buffers, and false here is not
    // an error: the caller arms the plain multishot variant every consumer
    // handles identically.
    if (!pool.cursor_ok || pool.buf_count > MAX_CQE_BUFS)
        return false;

    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_recv_multishot(sqe, fd, nullptr, 0, 0);
    sqe->ioprio |= IORING_RECVSEND_BUNDLE;
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = group_id;
    io_uring_sqe_set_data(sqe, req);
    req->type = op_recv_multishot_bundle;
    req->buf_group = static_cast<uint8_t>(group_id);
    arm(req, raw_target(fd));
    return true;
}

bool event_loop::submit_recv_multishot_bundle_fixed_file(int fixed_idx, uint16_t group_id, io_request* req)
{
    if (m_recv_multishot_refused || group_id >= MAX_BUF_GROUPS || !m_buf_rings[group_id].ring)
        return false;
    auto& pool = m_buf_rings[group_id];
    if (!pool.cursor_ok || pool.buf_count > MAX_CQE_BUFS)
        return false;

    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_recv_multishot(sqe, fixed_idx, nullptr, 0, 0);
    sqe->ioprio |= IORING_RECVSEND_BUNDLE;
    sqe->flags |= IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE;
    sqe->buf_group = group_id;
    io_uring_sqe_set_data(sqe, req);
    req->type = op_recv_multishot_bundle;
    req->buf_group = static_cast<uint8_t>(group_id);
    arm(req, fixed_target(fixed_idx));
    return true;
}

bool event_loop::submit_splice(int fd_in, int fd_out, uint32_t len, io_request* req, op_type type)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    // off_in and off_out are -1 for pipes and sockets, and still no
    // SPLICE_F_NONBLOCK, because the punt to an io-wq worker happens before
    // the flag is consulted -- measured at 17.19 us with the pipe pre-filled
    // against 0.72 us for a read from the same ready pipe.
    io_uring_prep_splice(sqe, fd_in, -1, fd_out, -1, len, SPLICE_F_MOVE);
    io_uring_sqe_set_data(sqe, req);
    req->type = type;
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

bool event_loop::submit_file_write(int fd, const char* buf, uint32_t len, uint64_t offset,
                                   io_request* req, bool link)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_write(sqe, fd, buf, len, offset);
    if (link)
        sqe->flags |= IOSQE_IO_LINK;
    io_uring_sqe_set_data(sqe, req);
    req->type = op_file_write;
    arm(req, raw_target(fd));
    return true;
}

bool event_loop::submit_fsync(int fd, bool datasync, io_request* req, bool link)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_fsync(sqe, fd, datasync ? IORING_FSYNC_DATASYNC : 0);
    if (link)
        sqe->flags |= IOSQE_IO_LINK;
    io_uring_sqe_set_data(sqe, req);
    req->type = op_fsync;
    arm(req, raw_target(fd));
    return true;
}

bool event_loop::submit_renameat(int olddir, const char* oldpath, int newdir, const char* newpath,
                                 io_request* req, bool link)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_renameat(sqe, olddir, oldpath, newdir, newpath, 0);
    if (link)
        sqe->flags |= IOSQE_IO_LINK;
    io_uring_sqe_set_data(sqe, req);
    req->type = op_rename;
    arm(req, raw_target(olddir), raw_target(newdir));
    return true;
}

bool event_loop::submit_linkat(int olddir, const char* oldpath, int newdir, const char* newpath,
                               io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_linkat(sqe, olddir, oldpath, newdir, newpath, 0);
    io_uring_sqe_set_data(sqe, req);
    req->type = op_link;
    arm(req, raw_target(olddir), raw_target(newdir));
    return true;
}

bool event_loop::submit_unlinkat(int dir, const char* path, io_request* req, int flags)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_unlinkat(sqe, dir, path, flags);
    io_uring_sqe_set_data(sqe, req);
    req->type = op_unlink;
    arm(req, raw_target(dir));
    return true;
}

bool event_loop::submit_openat(int dir, const char* path, int flags, mode_t mode, io_request* req)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    // O_CLOEXEC is said here rather than by each caller, because a descriptor
    // this loop hands out must not cross an exec whatever the caller forgot.
    io_uring_prep_openat(sqe, dir, path, flags | O_CLOEXEC, mode);
    io_uring_sqe_set_data(sqe, req);
    req->type = op_openat;
    arm(req, raw_target(dir));
    return true;
}

bool event_loop::submit_mkdirat(int dir, const char* path, mode_t mode, io_request* req, bool link)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_mkdirat(sqe, dir, path, mode);
    if (link)
        sqe->flags |= IOSQE_IO_LINK;
    io_uring_sqe_set_data(sqe, req);
    req->type = op_mkdir;
    arm(req, raw_target(dir));
    return true;
}

bool event_loop::submit_splice_file(int file_fd, uint64_t offset, int pipe_wr, uint32_t len, io_request* req,
                                    op_type type)
{
    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_splice(sqe, file_fd, static_cast<int64_t>(offset), pipe_wr, -1, len, SPLICE_F_MOVE);
    io_uring_sqe_set_data(sqe, req);
    req->type = type;
    arm(req, raw_target(file_fd), raw_target(pipe_wr));
    return true;
}

bool event_loop::reserve_sqes(unsigned n)
{
    if (!m_ring_open)
        return false;
    if (io_uring_sq_space_left(&m_ring) >= n)
        return true;
    io_uring_submit(&m_ring);
    m_pending_submissions = 0;
    return io_uring_sq_space_left(&m_ring) >= n;
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

// Withdraw exactly the submission this user_data names.  The kernel compares
// the key without ever dereferencing it, so a retired request's address is
// still a safe one -- the same property submit_poll_remove() relies on.
bool event_loop::submit_cancel_request(const io_request* target)
{
    if (!target)
        return false;

    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_cancel64(
        sqe, static_cast<__u64>(reinterpret_cast<std::uintptr_t>(target)), 0);

    // No request of its own, so no arm() and no disarm() owed; the submission
    // being withdrawn keeps the one it already had and reports -ECANCELED.
    io_uring_sqe_set_data(sqe, nullptr);
    m_pending_submissions++;
    return true;
}

bool event_loop::submit_poll_remove(io_request* target)
{
    if (!target)
        return false;

    struct io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    // Keyed on the user_data the poll was submitted with, which the kernel
    // compares without ever dereferencing, so a retired request's address is
    // still a safe key.
    io_uring_prep_poll_remove(
        sqe, static_cast<__u64>(reinterpret_cast<std::uintptr_t>(target)));
    // No request of its own, so no arm() and no disarm() owed, while the poll
    // being withdrawn keeps the one it already had and reports -ECANCELED.
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

bool event_loop::update_registered_file(uint32_t idx, int fd)
{
    if (!m_files_registered || idx >= m_registered_file_count)
        return false;

    int ret = io_uring_register_files_update(&m_ring, idx, &fd, 1);
    return ret >= 0;
}

// Bitmap-based fixed file slot allocator, returning the index of a free slot
// or -1 when full.
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

            // The bitmap spans MAX_FIXED_FILES but only
            // m_registered_file_count entries exist, so handing out anything
            // past that gives the caller a slot it can neither use nor give
            // back.
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

    // The completion in hand is discounted exactly as close_fd() and
    // fd_inflight() discount it, because releasing the slot the handler's own
    // completion was delivered for is every direct-descriptor teardown here --
    // and counting it put a cancel round trip on all of them.
    const uint32_t t = IO_TARGET_FIXED | idx;
    uint32_t armed = m_fixed_armed[idx];
    if (m_cqe_target  == t && armed > 0) --armed;
    if (m_cqe_target2 == t && armed > 0) --armed;

    // With something still armed the cancel goes first and the unregister is
    // deferred, because a cancel naming a fixed index is matched when the SQE
    // is consumed while register_files_update() takes effect at once --
    // measured as "fixed cancel idx=0 -> res=-9" with the recv still armed
    // afterwards.
    if (armed > 0)
    {
        submit_cancel_fixed(idx);
        m_fixed_free_deferred[w]  |= (1ULL << bit);
        m_fixed_unreg_deferred[w] |= (1ULL << bit);
        return;
    }

    // Nothing armed, so unregister now: this is what drops the kernel's
    // reference, and until it runs the descriptor's own close() has not really
    // closed anything.
    int neg = -1;
    if (m_files_registered)
    {
        if (io_uring_register_files_update(&m_ring, idx, &neg, 1) < 0) {}
    }

    // The index stays claimed until the count says nothing names it, because
    // an SQE carries the index and the next accept would otherwise point the
    // slot at its own socket -- and callers are not asked to check, having all
    // reasoned about submissions the kernel had already consumed.
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
