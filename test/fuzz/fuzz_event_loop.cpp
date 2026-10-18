// Fuzz target: event_loop's completion handling, driven by a *scripted order of
// completions* rather than by the order a kernel happened to choose.
//
// ─── WHY THIS TARGET EXISTS ─────────────────────────────────────────────────
//
// Every lifetime defect this project found by hand came from an order nobody
// had tried:
//
//   * a completion delivered to an owner that had already torn down, because
//     the slot it held had been handed to somebody else;
//   * a provided buffer attached to a completion nothing could deliver, and
//     therefore never returned to its group — the pool bled out one connection
//     at a time until every runtime of that type stalled;
//   * a multishot recv that stopped without IORING_CQE_F_MORE while the loop
//     went on believing something was still armed, so the descriptor it named
//     was held for the life of the runtime;
//   * a timer withdrawn with IORING_OP_TIMEOUT_REMOVE whose two completions
//     were accounted once between them, so the owner never drained and its
//     ~6 MB were never freed.
//
// Finding any one of those took a running daemon, a load generator and a core
// dump, and reproducing it took hours — because the *order* was the input, and
// the order was the kernel's to choose.  It does not have to be.  A CQE is
// three fields, the loop's reaction to one is a decision over its own tables,
// and a sequence of them is something a fuzzer can write.  So this target
// writes the sequence and checks the loop's own accounting after every single
// completion.  The bug is not the crash; the bug is the completion after which
// a conservation law stopped holding, and the report below names it.
//
// ─── THE SEAM ───────────────────────────────────────────────────────────────
//
// The decision used to be the body of run()'s io_uring_for_each_cqe, and a
// block of code inside a loop is not a symbol — the same wall
// shared/http/http_framing.h was lifted over, and lifted the same
// way: it is now event_loop::dispatch_cqe(), one completion in, one "keep going
// or stop" out.  Nothing else about the loop changed.  See the note above it in
// event_loop.cpp.
//
// ─── ON DRIVING A LOOP WITH NO KERNEL BEHIND IT ─────────────────────────────
//
// This target constructs a real event_loop and calls the real submit_* helpers,
// close_fd(), register_owner() and dispatch_cqe() on it.  What it does not do
// is init() one: an event_loop with a live ring would hand the SQEs built here
// to the kernel, and those SQEs name real descriptors of this process — a
// fuzzer submitting a recv on a descriptor libFuzzer is writing its corpus to
// is not a test, it is a hazard.  So the ring is a private one the kernel never
// sees, and the two shared-memory protocols the loop uses are played by the
// harness:
//
//   * the submission queue — get_sqe() reads *khead and sq.sqe_tail and hands
//     back &sq.sqes[...].  Given real memory it works exactly as it does
//     against a mapped ring, and sq_reset() below stands in for the kernel
//     consuming what was queued.
//
//   * the provided-buffer rings — io_uring_buf_ring_add() and
//     io_uring_buf_ring_advance() are plain stores into shared memory, no
//     syscall at any point.  So a group's ring here is ordinary memory with the
//     ordinary layout, and reading its tail afterwards is exactly what the
//     kernel would read.  That is what makes "the buffer went back to its
//     group" checkable rather than assumed.
//
// Descriptors are the one thing that must be real, because close_fd() ends in
// close(2) and the whole question it answers is when that is allowed to happen.
// So the harness opens its own from /dev/null, hands the loop those numbers
// only, and puts a number back with dup2() once the loop has closed it — which
// is also the "closed, and the next accept took the number" case in the list
// below.
//
// ─── WHAT IS CHECKED, AFTER EVERY STEP ──────────────────────────────────────
//
//  1. THE OWNER LEDGER.  The harness knows which slot every submission was
//     charged to, because it made the submission.  m_owners[slot].inflight must
//     equal that count — never more (a decrement that never came, so the slot
//     is never reusable and its owner can never be told it is quiescent) and
//     never less (a decrement that was not owed, which wraps a uint32 the next
//     time it happens and holds the slot for ever).  The per-op-type breakdown
//     must sum to the same figure.
//
//  2. EVERY ARM HAS ITS DISARM.  At the end of a program every outstanding
//     submission is completed once, and then every counter in the loop —
//     1024 owner slots, their 21 op-type counters each, the whole descriptor
//     table and the whole fixed-file table — must read zero.  A single leaked
//     count is a runtime that can never be reaped.
//
//  3. A DISCARDED COMPLETION RELEASES WHAT IT CARRIES.  A completion with
//     IORING_CQE_F_BUFFER that cannot be delivered must publish its buffer back
//     to the group's ring, with the buffer id the completion named.  One that
//     *was* delivered must not: the handler owns it, and a loop that returns it
//     too puts one buffer into the ring twice.
//
//  4. A NUMBER IS NOT GIVEN AWAY WHILE THE RING NAMES IT.  A descriptor may not
//     be closed while the harness's own ledger says a submission still names
//     it, and a fixed-file index may not go back to the allocator on the same
//     terms.  The other direction too: once nothing names it, a close that was
//     asked for must actually happen, or the daemon leaks the descriptor.
//
//  5. STALENESS IS DECIDED, NOT GUESSED.  A completion whose owner has
//     deregistered since it was submitted must not reach a handler; one whose
//     registration is still current must.
//
// ─── THE CASES THE ALPHABET REACHES ─────────────────────────────────────────
//
// Retired owners (slot recycled, epoch bumped, stale token still in flight),
// IORING_CQE_F_BUFFER on a completion that is discarded, multishot completions
// with and without IORING_CQE_F_MORE, short reads, -ENOBUFS, -ECANCELED,
// -EBADF and results no handler expects, a descriptor closed and its number
// reissued underneath a submission that still names it, timeouts, the
// no-request completions that IORING_OP_TIMEOUT_REMOVE and
// IORING_OP_POLL_REMOVE produce, the cancel acknowledgement close_fd() waits
// for, and handlers that re-arm, close their own descriptor or deregister
// themselves from inside their own on_cqe.
//
// ─── WHAT THIS TARGET DOES NOT COVER ────────────────────────────────────────
//
// The kernel's half of any of it: whether a submission the loop counted was
// really consumed, whether a descriptor number really was reissued between the
// SQE and its consumption, and CQ overflow.  Those need a kernel and belong in
// the integration suite.
// This target checks that the loop's books balance for every order of arrivals,
// which is the half that was getting them wrong.
//
// ─── ON A TARGET THAT FINDS NOTHING ─────────────────────────────────────────
//
// A fuzz target that reports no defects looks exactly like one that cannot see
// any, so this one was checked against defects put there on purpose — each in a
// throwaway copy of event_loop.cpp, never in the tree:
//
//   * drop_completion() made a no-op, so a discarded completion keeps its
//     buffer.  Caught in under 25 s from an empty corpus, as buf-not-returned.
//   * disarm() reached only on the delivered path, so a dropped completion
//     leaves its owner armed — the exact thing the note in dispatch_cqe warns
//     about.  Caught in seconds, as owner-inflight-drift, with the slot and the
//     ledger figure in the report.
//   * close_fd() made to close at once whatever the ring still names.  Caught,
//     as fd-cancel-drift, before the descriptor checks even got to it.
//
// Anyone changing this file should repeat that: break something on purpose and
// watch it fail, or the green run means nothing.
//
// ─── TRIAGE ─────────────────────────────────────────────────────────────────
//
// On a violation the raw bytes say nothing, so the report prints the decoded
// program.  FUZZ_LOOP_SKIP=id1,id2 demotes named findings to a printed
// observation so a run can continue past a known one and look for the next; the
// ids are the first argument of each LOOP_FINDING below.  Nothing is skipped
// unless the variable names it, so CI still fails on the first one.

#include <cerrno>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <fcntl.h>
#include <poll.h>
#include <sys/resource.h>
#include <unistd.h>

#include "fuzz_common.h"

// Everything event_loop.h needs, included before the macro below so that it is
// never in effect over libstdc++, liburing or the kernel headers.
#include <atomic>
#include <liburing.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>

// The same idiom fuzz_cache_ops.cpp uses, for the same reason and with the same
// justification: the alternative is a friend declaration or a test-only
// accessor in socketley/, and neither of those should exist to suit a test.
// Member access affects neither layout nor mangling, so event_loop.cpp compiled
// normally and this translation unit agree on the object.
#define private public
#include "../../socketley/shared/loop/event_loop.h"
#undef private

// Completion flags this target sets deliberately.  Spelled with a fallback
// because a build host's liburing headers may predate them, and a target that
// stops compiling on an older box teaches nobody anything — the flag is a bit
// in a word the loop reads either way.
#ifndef IORING_CQE_F_SOCK_NONEMPTY
#define IORING_CQE_F_SOCK_NONEMPTY (1U << 2)
#endif

namespace {

// ───────────────────────────── harness geometry ─────────────────────────────
//
// Small tables on purpose.  Every invariant here is *relational* — this slot
// against that ledger, this descriptor against the submissions naming it — so
// they need the same handful of owners, requests and descriptors revisited over
// and over.  A wide alphabet would make every step touch something fresh and no
// history would ever build up.

constexpr int      NOWNERS = 5;
constexpr int      NREQS   = 12;
constexpr int      NFDS    = 6;
constexpr int      NFIXED  = 5;
constexpr uint16_t NGROUPS = 3;
constexpr uint32_t BUFS_PER_GROUP = 8;      // power of two: the ring is masked
constexpr uint32_t BUF_SIZE       = 64;
// One io_request can be armed more than once at a time here, because a handler
// is allowed to re-arm from inside its own on_cqe while the completion it was
// called for has not been disarmed yet.  That is a real shape — the loop reads
// the fields it must undo *before* the dispatch precisely because of it — so
// the ledger keeps a FIFO rather than a flag.
constexpr int      MAX_ARMS = 4;
constexpr size_t   MAX_STEPS = 2048;
constexpr size_t   STEP_BYTES = 6;

// The loop's own constants, repeated so a check can be written against them.
constexpr uint32_t OWNER_SLOTS = 1024;
constexpr uint32_t SLOT_MASK   = OWNER_SLOTS - 1;

// ───────────────────────── findings and reporting ───────────────────────────

struct step
{
    uint8_t op = 0, a = 0, b = 0, c = 0, d = 0, e = 0;
    uint8_t note = 0;       // the harness declined it; see step_note()
};

constexpr uint8_t NOTE_RUN = 0, NOTE_SKIPPED = 1;

step   g_prog[MAX_STEPS];
size_t g_steps = 0;
char   g_detail[512] = {0};

void set_detail(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void set_detail(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(g_detail, sizeof(g_detail), fmt, ap);
    va_end(ap);
}

const char* op_name(uint8_t op);

void print_program()
{
    std::fprintf(stderr,
        "\n--- decoded completion program (%zu steps) ---\n"
        "// op(owner/req, target, res, flags, aux)\n", g_steps);
    for (size_t i = 0; i < g_steps; i++)
    {
        const step& s = g_prog[i];
        std::fprintf(stderr, "  /* %4zu */ %s%-22s a=%3u b=%3u c=%3u flags=%3u aux=%3u\n",
                     i, s.note == NOTE_SKIPPED ? "// NOT RUN: " : "",
                     op_name(s.op), s.a, s.b, s.c, s.d, s.e);
    }
    std::fputs("--- end of program ---\n", stderr);
}

[[noreturn]] void loop_fail(const char* expr, const char* file, int line, const char* what)
{
    if (g_detail[0])
        std::fprintf(stderr, "\n--- measurements ---\n  %s\n", g_detail);
    print_program();
    ::fuzz::fail(expr, file, line, what);
}

#define LOOP_CHECK(expr, what) \
    do { if (!(expr)) loop_fail(#expr, __FILE__, __LINE__, (what)); } while (0)

// A named check that FUZZ_LOOP_SKIP=<id>[,<id>...] can demote to a printed
// observation.  This exists so one known defect does not stop the fuzzer at the
// same step of every input and hide the next one behind it.
bool finding_suppressed(const char* id)
{
    static const char* const env = [] {
        const char* e = std::getenv("FUZZ_LOOP_SKIP");
        return (e && *e) ? e : nullptr;
    }();
    if (!env)
        return false;
    const size_t n = std::strlen(id);
    for (const char* p = env; *p; )
    {
        const char* e   = std::strchr(p, ',');
        const char* end = e ? e : p + std::strlen(p);
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n')) p++;
        while (end > p && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\n')) end--;
        if (static_cast<size_t>(end - p) == n && std::strncmp(p, id, n) == 0)
            return true;
        if (!e)
            break;
        p = e + 1;
    }
    return false;
}

// Allocation-free, and deliberately: libFuzzer runs a full LeakSanitizer scan
// for any input whose malloc and free counts disagree, and a harness that grows
// a buffer as it goes triggers a forked heap walk per input.  Ids are string
// literals, so pointer identity is enough to count them.
void observe_once(const char* id, const char* what)
{
    static const char* ids[24]  = {nullptr};
    static int         hits[24] = {0};
    for (int i = 0; i < 24; i++)
    {
        if (ids[i] == nullptr)
            ids[i] = id;
        if (ids[i] == id)
        {
            if (hits[i]++ < 3)
                std::fprintf(stderr, "[fuzz-loop] suppressed finding '%s': %s\n", id, what);
            return;
        }
    }
}

#define LOOP_FINDING(id, expr, what)                                         \
    do {                                                                     \
        if (!(expr))                                                         \
        {                                                                    \
            if (finding_suppressed(id)) observe_once(id, what);              \
            else loop_fail(#expr, __FILE__, __LINE__, (what));               \
        }                                                                    \
    } while (0)

// ─────────────────────────── the input alphabet ─────────────────────────────

enum step_op : uint8_t
{
    // Submissions and completions carry the weight of the program, so they get
    // several slots each in the selector below.
    OP_ARM = 0, OP_ARM_B,
    OP_CQE, OP_CQE_B, OP_CQE_C,
    OP_CQE_CANCEL,      // the acknowledgement close_fd() is waiting for
    OP_CQE_NULL,        // what IORING_OP_{TIMEOUT,POLL}_REMOVE report
    OP_CQE_SIGNAL,      // the stop eventfd's own read
    OP_REGISTER,
    OP_DEREGISTER,      // retire an owner with submissions still in the ring
    OP_CLOSE_FD,
    OP_CANCEL_FD,
    OP_TIMEOUT_REMOVE,
    OP_POLL_REMOVE,
    OP_ALLOC_FIXED,
    OP_FREE_FIXED,
    OP_RETURN_CQE_BUF,  // the public "I am dropping this, take the buffer back"
    OP_REUSE_FD,        // close the number behind the loop's back and reissue it
    OP_QUERY,           // the read-only accessors, checked against the ledger
    OP_STEP_COUNT
};

const char* op_name(uint8_t op)
{
    switch (op)
    {
        case OP_ARM: case OP_ARM_B:                 return "arm";
        case OP_CQE: case OP_CQE_B: case OP_CQE_C:  return "cqe";
        case OP_CQE_CANCEL:                         return "cqe-cancel-ack";
        case OP_CQE_NULL:                           return "cqe-no-request";
        case OP_CQE_SIGNAL:                         return "cqe-stop-eventfd";
        case OP_REGISTER:                           return "register_owner";
        case OP_DEREGISTER:                         return "deregister_owner";
        case OP_CLOSE_FD:                           return "close_fd";
        case OP_CANCEL_FD:                          return "submit_cancel_fd";
        case OP_TIMEOUT_REMOVE:                     return "submit_timeout_remove";
        case OP_POLL_REMOVE:                        return "submit_poll_remove";
        case OP_ALLOC_FIXED:                        return "alloc_fixed_file_slot";
        case OP_FREE_FIXED:                         return "free_fixed_file_slot";
        case OP_RETURN_CQE_BUF:                     return "return_cqe_buf";
        case OP_REUSE_FD:                           return "raw close + reissue";
        case OP_QUERY:                              return "accessors";
        default:                                    return "?";
    }
}

// Which submit_* helper an arm step uses.  Chosen to span every shape the
// accounting has to tell apart: a raw descriptor, a fixed-file index, no
// descriptor at all, two descriptors at once, and the two that select a
// provided buffer.
enum arm_kind : uint8_t
{
    A_ACCEPT = 0, A_MSHOT_ACCEPT, A_MSHOT_ACCEPT_DIRECT,
    A_READ, A_WRITE, A_WRITEV, A_RECVMSG, A_SENDMSG,
    A_TIMEOUT,
    A_READ_PROVIDED, A_RECV_MULTISHOT,
    A_READ_FIXED, A_WRITE_FIXED, A_MSHOT_FIXED, A_PROVIDED_FIXED,
    A_SPLICE, A_FILE_READ, A_CONNECT, A_POLL,
    A_READ_FIXED_BUF, A_WRITE_FIXED_BUF,
    A_KIND_COUNT
};

// Results worth handing a handler: the ordinary ones, the short read, and the
// errors that used to arrive where nobody was looking for them.
constexpr int32_t RES_TABLE[] = {
    0, 1, 15, 64, 4096, 65535,
    -EAGAIN, -ECANCELED, -ENOBUFS, -ECONNRESET, -EPIPE, -EBADF,
    -EINVAL, -ENOENT, -EINTR, -EMFILE, -ETIME, -EFAULT, -1, INT32_MIN
};
constexpr int NRES = static_cast<int>(sizeof(RES_TABLE) / sizeof(RES_TABLE[0]));

// What the handler does from inside its own on_cqe.  Every one of these is
// something a runtime here really does on that path.
enum handler_action : uint8_t
{
    H_NONE = 0, H_REARM, H_CLOSE_FD, H_DEREGISTER, H_QUERY, H_ACTION_COUNT
};

// ──────────────────────────── the ledger ────────────────────────────────────

struct arm_rec
{
    uint32_t tok   = 0;                 // the owner identity stamped at submit
    uint32_t slot  = 0;
    uint8_t  type  = 0;
    uint32_t t1    = IO_TARGET_NONE;
    uint32_t t2    = IO_TARGET_NONE;
    int      owner = -1;                // index into world::owners, -1 = none
    int      group = -1;                // provided-buffer group, -1 = none
};

struct world;
world* g_w = nullptr;

struct fake_owner : io_handler
{
    int  idx        = -1;
    bool registered = false;
    uint32_t token  = 0;
    void on_cqe(struct io_uring_cqe* cqe) override;
};

struct req_rec
{
    io_request req{};
    arm_rec    arms[MAX_ARMS];
    int        narms = 0;
};

// The descriptors handed to the loop.  Opened once for the process — a
// per-input open/close pair would churn descriptor numbers between inputs and
// make a libFuzzer artifact reproduce against different numbers than the ones
// that found it.
struct fd_pool
{
    int master = -1;
    int fd[NFDS];

    fd_pool()
    {
        for (int i = 0; i < NFDS; i++) fd[i] = -1;

        // event_loop sizes its descriptor tables from RLIMIT_NOFILE, because
        // that is exactly the range of numbers the kernel can hand the process.
        // On a box whose soft limit is a million that is a four-megabyte
        // allocation and two million-entry sweeps per input — 28 ms an input,
        // which is not fuzzing.  Lowering the limit is a configuration a daemon
        // is routinely started with, and 4096 is the floor init_fd_tables()
        // applies anyway, so the tables under test are the same tables either
        // way.  Only the soft limit is touched, and only downwards.
        struct rlimit rl{};
        if (::getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur > 1024)
        {
            rl.rlim_cur = 1024;
            if (::setrlimit(RLIMIT_NOFILE, &rl) < 0) {}
        }

        master = ::open("/dev/null", O_RDWR | O_CLOEXEC);
        if (master < 0)
            return;
        for (int i = 0; i < NFDS; i++)
            fd[i] = ::dup(master);
    }
};

fd_pool& fds()
{
    static fd_pool p;
    return p;
}

bool fd_is_open(int fd)
{
    return ::fcntl(fd, F_GETFD) >= 0;
}

struct world
{
    event_loop* loop = nullptr;

    fake_owner owners[NOWNERS];
    req_rec    reqs[NREQS];

    // Owner accounting, kept by the harness rather than read back out of the
    // loop: what is being checked is whether the loop agrees with it.
    uint32_t exp_inflight[OWNER_SLOTS]{};
    uint32_t last_token[OWNER_SLOTS]{};     // the epoch guarantee, checked below
    uint64_t touched[OWNER_SLOTS / 64]{};
    uint32_t arms_issued = 0;

    // Descriptor accounting.  fd_open is what the harness believes; fd_is_open()
    // is what the operating system says, and the two are compared every step.
    uint32_t exp_fd_armed[NFDS]{};
    uint32_t exp_fd_cancels[NFDS]{};
    bool     fd_open[NFDS]{};
    bool     fd_close_req[NFDS]{};

    // Fixed-file slots.
    int      fixed[NFIXED];                 // the index alloc_fixed_file_slot gave
    uint32_t exp_fixed_armed[NFIXED]{};
    bool     fixed_free_req[NFIXED]{};

    // Provided-buffer groups, played by the harness (see the header note).
    struct io_uring_buf_ring* ring[NGROUPS]{};
    char*                     base[NGROUPS]{};
    unsigned short            ring_tail[NGROUPS]{};   // what we last saw

    // A private submission queue nothing ever enters.
    struct io_uring_sqe sqes[8]{};
    unsigned            khead = 0;

    // Scratch the SQEs point at.  Never read by anything: no kernel sees them.
    char        iobuf[256]{};
    struct iovec iov{};
    struct msghdr msg{};
    struct sockaddr_in addr{};
    socklen_t   addrlen = sizeof(struct sockaddr_in);
    struct __kernel_timespec ts{};

    // Set around a dispatch to exactly what the loop sets m_cqe_target to, so
    // the harness can predict close_fd()'s discount without reading it back.
    uint32_t cqe_t1 = IO_TARGET_NONE;
    uint32_t cqe_t2 = IO_TARGET_NONE;
    // Which request the completion in flight belongs to, for the handler.
    int      cqe_req = -1;
    uint8_t  cqe_action = H_NONE;
    uint8_t  cqe_aux = 0;
    bool     cqe_expect_dispatch = false;
    bool     cqe_dispatched = false;
    bool     cqe_final = false;
    bool     draining = false;

    world()
    {
        for (int i = 0; i < NFIXED; i++) fixed[i] = -1;
    }
};

// ───────────────────── target encoding, both directions ─────────────────────

uint32_t raw_t(int fd)   { return fd >= 0 ? static_cast<uint32_t>(fd) : IO_TARGET_NONE; }
uint32_t fixed_t(int ix) { return ix >= 0 ? (IO_TARGET_FIXED | static_cast<uint32_t>(ix)) : IO_TARGET_NONE; }

int fd_slot(const world& w, uint32_t target)
{
    if (target == IO_TARGET_NONE || (target & IO_TARGET_FIXED))
        return -1;
    for (int i = 0; i < NFDS; i++)
        if (raw_t(fds().fd[i]) == target && fds().fd[i] >= 0) return i;
    (void)w;
    return -1;
}

int fixed_slot(const world& w, uint32_t target)
{
    if (target == IO_TARGET_NONE || !(target & IO_TARGET_FIXED))
        return -1;
    for (int i = 0; i < NFIXED; i++)
        if (w.fixed[i] >= 0 && fixed_t(w.fixed[i]) == target) return i;
    return -1;
}

void touch_slot(world& w, uint32_t s)
{
    w.touched[s >> 6] |= (1ULL << (s & 63));
}

// A settle can only happen where a count is decremented, which is exactly what
// event_loop::target_unref() and the cancel branch of dispatch_cqe() do.  Same
// rule here: both counters at zero and a close waiting on them.
void ledger_settle_fd(world& w, int i)
{
    if (!w.fd_close_req[i]) return;
    if (w.exp_fd_armed[i] != 0 || w.exp_fd_cancels[i] != 0) return;
    w.fd_close_req[i] = false;
    w.fd_open[i]      = false;
}

void ledger_ref(world& w, uint32_t target)
{
    const int f = fd_slot(w, target);
    if (f >= 0) { w.exp_fd_armed[f]++; return; }
    const int x = fixed_slot(w, target);
    if (x >= 0) w.exp_fixed_armed[x]++;
}

void ledger_unref(world& w, uint32_t target)
{
    const int f = fd_slot(w, target);
    if (f >= 0)
    {
        if (w.exp_fd_armed[f] > 0) { w.exp_fd_armed[f]--; ledger_settle_fd(w, f); }
        return;
    }
    const int x = fixed_slot(w, target);
    if (x >= 0 && w.exp_fixed_armed[x] > 0)
        w.exp_fixed_armed[x]--;
}

// ─────────────────────────────── the checks ─────────────────────────────────

uint32_t slot_by_type_sum(const world& w, uint32_t s)
{
    uint32_t total = 0;
    for (uint8_t t = 0; t < op_type_count; t++)
        total += w.loop->m_owners[s].by_type[t];
    return total;
}

void check_slot(world& w, uint32_t s, const char* where)
{
    const auto& slot = w.loop->m_owners[s];

    if (slot.inflight != w.exp_inflight[s])
    {
        set_detail("at %s: owner slot %u reports %u submissions in flight, the "
                   "ledger says %u (%u arms issued in this program)",
                   where, s, slot.inflight, w.exp_inflight[s], w.arms_issued);
        LOOP_FINDING("owner-inflight-drift", slot.inflight == w.exp_inflight[s],
                     "the loop's count of submissions still in the ring for an owner has "
                     "drifted from what was submitted — too high and the slot is never "
                     "reusable and its owner never reaps, too low and the next unmatched "
                     "decrement wraps the counter and holds the slot for ever");
        g_detail[0] = 0;
    }

    // Stated separately from the drift check because it is the failure that
    // cannot be recovered from: a uint32 that has gone below zero reads as four
    // billion and the slot is never handed out again.
    if (slot.inflight > w.arms_issued)
    {
        set_detail("at %s: owner slot %u reports %u in flight after only %u arms in the "
                   "whole program", where, s, slot.inflight, w.arms_issued);
        LOOP_FINDING("owner-inflight-wrapped", slot.inflight <= w.arms_issued,
                     "an owner's in-flight counter has wrapped: it was decremented more "
                     "often than it was incremented, so the slot can never drain and the "
                     "handler that holds it can never be freed");
        g_detail[0] = 0;
    }

    const uint32_t sum = slot_by_type_sum(w, s);
    if (sum != slot.inflight)
    {
        set_detail("at %s: owner slot %u has %u in flight but its per-op-type counters "
                   "sum to %u", where, s, slot.inflight, sum);
        LOOP_FINDING("owner-bytype-drift", sum == slot.inflight,
                     "the per-operation-type breakdown of an owner's in-flight count no "
                     "longer sums to the count itself — the breakdown is what says which "
                     "operation is holding a slot that will not drain");
        g_detail[0] = 0;
    }
}

void check_descriptors(world& w, const char* where)
{
    for (int i = 0; i < NFDS; i++)
    {
        const int fd = fds().fd[i];
        if (fd < 0) continue;
        const uint32_t t = static_cast<uint32_t>(fd);

        if (w.loop->m_fd_armed[t] != w.exp_fd_armed[i])
        {
            set_detail("at %s: descriptor %d is counted %u times by the loop, %u by the "
                       "ledger", where, fd, static_cast<unsigned>(w.loop->m_fd_armed[t]),
                       w.exp_fd_armed[i]);
            LOOP_FINDING("fd-armed-drift", w.loop->m_fd_armed[t] == w.exp_fd_armed[i],
                         "the count of submissions naming a descriptor has drifted from "
                         "what was submitted — this is the count close_fd() and the "
                         "connection pool ask before giving the number away");
            g_detail[0] = 0;
        }
        if (w.loop->m_fd_cancels[t] != w.exp_fd_cancels[i])
        {
            set_detail("at %s: descriptor %d has %u cancels outstanding by the loop, %u by "
                       "the ledger", where, fd,
                       static_cast<unsigned>(w.loop->m_fd_cancels[t]), w.exp_fd_cancels[i]);
            LOOP_FINDING("fd-cancel-drift", w.loop->m_fd_cancels[t] == w.exp_fd_cancels[i],
                         "the count of cancels the loop still owes a completion for on a "
                         "descriptor has drifted — a number released while one is queued "
                         "lets that cancel take back the next owner's I/O");
            g_detail[0] = 0;
        }

        const bool really_open = fd_is_open(fd);
        if (really_open != w.fd_open[i])
        {
            set_detail("at %s: descriptor %d is %s, the ledger says %s (%u submissions "
                       "name it, %u cancels, close requested=%d)",
                       where, fd, really_open ? "open" : "closed",
                       w.fd_open[i] ? "open" : "closed",
                       w.exp_fd_armed[i], w.exp_fd_cancels[i],
                       static_cast<int>(w.fd_close_req[i]));
            if (!really_open && w.exp_fd_armed[i] > 0)
                LOOP_FINDING("fd-closed-early", false,
                             "a descriptor was closed while the ring still names it — the "
                             "number goes to the next accept and the queued operation is "
                             "redirected onto a stranger's socket");
            else
                LOOP_FINDING("fd-close-drift", false,
                             "a descriptor is open or closed at a moment the submissions "
                             "naming it say it should not be");
            g_detail[0] = 0;
            w.fd_open[i] = really_open;      // resynchronise so one report is one report
        }

        // The other direction: a close that was asked for, nothing left naming
        // the number, and the descriptor still open is a descriptor the daemon
        // has leaked.
        if (w.fd_close_req[i] && w.exp_fd_armed[i] == 0 && w.exp_fd_cancels[i] == 0)
        {
            set_detail("at %s: close_fd(%d) was called, nothing names the number any more, "
                       "and it is still open", where, fd);
            LOOP_FINDING("fd-never-closed", false,
                         "a deferred close never settled although the last submission "
                         "naming the descriptor has reported — the descriptor is held for "
                         "the life of the process");
            g_detail[0] = 0;
            w.fd_close_req[i] = false;
        }
    }

    for (int i = 0; i < NFIXED; i++)
    {
        if (w.fixed[i] < 0) continue;
        const uint32_t idx = static_cast<uint32_t>(w.fixed[i]);

        if (w.loop->m_fixed_armed[idx] != w.exp_fixed_armed[i])
        {
            set_detail("at %s: fixed-file index %u is counted %u times by the loop, %u by "
                       "the ledger", where, idx,
                       static_cast<unsigned>(w.loop->m_fixed_armed[idx]), w.exp_fixed_armed[i]);
            LOOP_FINDING("fixed-armed-drift", w.loop->m_fixed_armed[idx] == w.exp_fixed_armed[i],
                         "the count of submissions naming a fixed-file index has drifted "
                         "from what was submitted — the index is what the kernel resolves "
                         "when it consumes the SQE, one level up from a descriptor number");
            g_detail[0] = 0;
        }

        if (!w.fixed_free_req[i]) continue;

        const bool in_use = ((w.loop->m_file_bitmap[idx / 64] >> (idx % 64)) & 1u) != 0;
        if (w.exp_fixed_armed[i] > 0)
        {
            set_detail("at %s: fixed-file index %u was released with %u submissions still "
                       "naming it", where, idx, w.exp_fixed_armed[i]);
            LOOP_FINDING("fixed-freed-early", in_use,
                         "a fixed-file index went back to the allocator while a submission "
                         "still named it — the next connection takes the slot, points it "
                         "at its own socket, and the previous one's queued read lands there");
            g_detail[0] = 0;
        }
        else
        {
            set_detail("at %s: fixed-file index %u has nothing naming it and is still "
                       "marked in use", where, idx);
            LOOP_FINDING("fixed-never-freed", !in_use,
                         "a fixed-file index never went back to the allocator although the "
                         "last submission naming it has reported — the table fills up with "
                         "slots nothing is using");
            g_detail[0] = 0;
            w.fixed_free_req[i] = false;
            w.fixed[i] = -1;
        }
    }
}

// The tail of a group's ring is what the kernel reads to find the buffers that
// have been given back.  Nothing else here writes it, so a delta is exactly the
// number of buffers the loop published.
unsigned buf_published(world& w, int group)
{
    const unsigned short now = w.ring[group]->tail;
    const unsigned delta = static_cast<unsigned short>(now - w.ring_tail[group]);
    return delta;
}

void buf_sync(world& w, int group)
{
    w.ring_tail[group] = w.ring[group]->tail;
}

// ───────────────────────────── the handler ──────────────────────────────────

void ledger_close_fd(world& w, int i);
bool do_arm(world& w, int ri, uint8_t kind, uint8_t a, uint8_t b, bool in_handler);

void fake_owner::on_cqe(struct io_uring_cqe* cqe)
{
    world& w = *g_w;
    w.cqe_dispatched = true;

    LOOP_FINDING("stale-dispatch", w.cqe_expect_dispatch,
                 "a completion was delivered to a handler whose registration had already "
                 "been revoked — the storage behind the request may have been freed, and "
                 "this is the read that lands in it");

    if (w.draining)
        return;

    switch (w.cqe_action)
    {
        case H_REARM:
        {
            // The shape run() reads req->type and req->armed_target early for:
            // the handler claims the request for a *new* submission before the
            // old one has been disarmed.
            if (w.cqe_req >= 0 && w.cqe_final)
                do_arm(w, w.cqe_req, static_cast<uint8_t>(w.cqe_aux % A_KIND_COUNT),
                       w.cqe_aux, static_cast<uint8_t>(w.cqe_aux >> 3), true);
            break;
        }
        case H_CLOSE_FD:
        {
            // The most travelled close in the daemon: a handler closing the very
            // descriptor its completion was just delivered for, while that
            // submission is still counted.
            const int f = fd_slot(w, w.cqe_t1 != IO_TARGET_NONE ? w.cqe_t1
                                                                : raw_t(fds().fd[w.cqe_aux % NFDS]));
            if (f >= 0 && w.fd_open[f])
                ledger_close_fd(w, f);
            break;
        }
        case H_DEREGISTER:
        {
            // "A handler that frees itself from inside its own on_cqe must
            // deregister there and not earlier."
            w.loop->deregister_owner(this);
            registered = false;
            break;
        }
        case H_QUERY:
        {
            // fd_inflight() discounts the completion in hand, and the proxy
            // pools a backend socket on the strength of that discount.  Check it
            // against the ledger rather than against the loop's own counters.
            for (int i = 0; i < NFDS; i++)
            {
                const int fd = fds().fd[i];
                if (fd < 0 || !w.fd_open[i]) continue;
                uint32_t expect = w.exp_fd_armed[i];
                if (w.cqe_t1 == raw_t(fd) && expect > 0) expect--;
                if (w.cqe_t2 == raw_t(fd) && expect > 0) expect--;
                const uint32_t got = w.loop->fd_inflight(fd);
                if (got != expect)
                {
                    set_detail("inside on_cqe: fd_inflight(%d) is %u, the ledger with the "
                               "completion in hand discounted is %u", fd, got, expect);
                    LOOP_FINDING("fd-inflight-discount", got == expect,
                                 "fd_inflight() disagrees with the submissions naming the "
                                 "descriptor once the completion being dispatched is "
                                 "discounted — this is the answer a connection pool reuses "
                                 "a socket on");
                    g_detail[0] = 0;
                }
            }
            break;
        }
        default:
            break;
    }
    (void)cqe;
}

// ───────────────────────────── the operations ───────────────────────────────

// A private submission queue the kernel never sees.  Rewinding it is the
// harness standing in for the kernel consuming what was queued; without that,
// get_sqe() would reach its full path, call io_uring_submit() and make a real
// syscall on a ring that does not exist.
void sq_reset(world& w)
{
    w.khead = 0;
    w.loop->m_ring.sq.sqe_tail = 0;
    w.loop->m_ring.sq.sqe_head = 0;
}

// close_fd(), predicted from the ledger and from what the harness knows about
// the dispatch it may be inside.  Only the *arithmetic* is mirrored here; the
// properties that matter — a number is not given away while something names it,
// and a close that was asked for eventually happens — are checked against the
// operating system in check_descriptors().
void ledger_close_fd(world& w, int i)
{
    const int fd = fds().fd[i];
    if (fd < 0 || !w.fd_open[i])
        return;

    if (w.exp_fd_armed[i] == 0 && w.exp_fd_cancels[i] == 0)
    {
        w.loop->close_fd(fd);
        w.fd_open[i] = false;
        return;
    }

    uint32_t armed = w.exp_fd_armed[i];
    if (w.cqe_t1 == raw_t(fd) && armed > 0) armed--;
    if (w.cqe_t2 == raw_t(fd) && armed > 0) armed--;

    const bool already = w.fd_close_req[i];
    w.loop->close_fd(fd);
    if (already)
        return;

    w.fd_close_req[i] = true;
    if (armed != 0)
        w.exp_fd_cancels[i]++;       // close_fd() submitted the cancel itself
    ledger_settle_fd(w, i);
}

// Arm one request through the real submit_* helper for `kind`, and record what
// it charged.  Returns false when the harness declined the step.
bool do_arm(world& w, int ri, uint8_t kind, uint8_t a, uint8_t b, bool in_handler)
{
    req_rec& r = w.reqs[ri];

    // ONE SUBMISSION PER io_request AT A TIME.  Not a harness convenience — it
    // is the contract every submit_* helper is written against, and the loop
    // depends on it: a completion is charged with the identity, the operation
    // type and the descriptor numbers that are *on the request when it
    // arrives*, so a second submission queued behind the first would have the
    // first's completion undoing the second's accounting.  A harness that armed
    // one request twice would be checking a shape nothing produces and calling
    // the resulting mismatch a defect.
    //
    // The one exception is the shape the loop reads those fields early for: a
    // handler re-arming from inside its own on_cqe, on a completion that is the
    // old submission's last.  The loop has already taken what it needs by then,
    // which is exactly why it takes it before the dispatch.
    if (in_handler ? (r.narms > 1) : (r.narms > 0))
        return false;
    if (r.narms >= MAX_ARMS)
        return false;

    const int oi = (a % (NOWNERS + 1)) - 1;             // -1 selects "no owner"
    const int fi = b % NFDS;
    const int fi2 = (b / NFDS) % NFDS;
    const int xi = a % NFIXED;
    const uint16_t grp = static_cast<uint16_t>(b % NGROUPS);

    const int fd  = w.fd_open[fi]  ? fds().fd[fi]  : -1;
    const int fd2 = w.fd_open[fi2] ? fds().fd[fi2] : -1;
    if (fd < 0)
        return false;

    const int fx = w.fixed[xi];

    r.req.owner   = (oi >= 0) ? static_cast<io_handler*>(&w.owners[oi]) : nullptr;
    r.req.buffer  = w.iobuf;
    r.req.fd      = fd;
    r.req.length  = 64;

    uint32_t t1 = IO_TARGET_NONE, t2 = IO_TARGET_NONE;
    uint8_t  ty = op_nop;
    int      group = -1;
    bool     ok = false;

    sq_reset(w);
    switch (kind)
    {
        case A_ACCEPT:
            r.req.type = op_accept; ty = op_accept; t1 = raw_t(fd);
            ok = w.loop->submit_accept(fd, &w.addr, &w.addrlen, &r.req);
            break;
        case A_MSHOT_ACCEPT:
            r.req.type = op_multishot_accept; ty = op_multishot_accept; t1 = raw_t(fd);
            ok = w.loop->submit_multishot_accept(fd, &r.req);
            break;
        case A_MSHOT_ACCEPT_DIRECT:
            r.req.type = op_multishot_accept_direct; ty = op_multishot_accept_direct;
            t1 = raw_t(fd);
            ok = w.loop->submit_multishot_accept_direct(fd, &r.req);
            break;
        case A_READ:
            r.req.type = op_read; ty = op_read; t1 = raw_t(fd);
            ok = w.loop->submit_read(fd, w.iobuf, 64, &r.req);
            break;
        case A_WRITE:
            r.req.type = op_write; ty = op_write; t1 = raw_t(fd);
            ok = w.loop->submit_write(fd, w.iobuf, 64, &r.req);
            break;
        case A_WRITEV:
            w.iov.iov_base = w.iobuf; w.iov.iov_len = 64;
            r.req.type = op_writev; ty = op_writev; t1 = raw_t(fd);
            ok = w.loop->submit_writev(fd, &w.iov, 1, &r.req);
            break;
        case A_RECVMSG:
            w.iov.iov_base = w.iobuf; w.iov.iov_len = 64;
            w.msg = {}; w.msg.msg_iov = &w.iov; w.msg.msg_iovlen = 1;
            r.req.type = op_recvmsg; ty = op_recvmsg; t1 = raw_t(fd);
            ok = w.loop->submit_recvmsg(fd, &w.msg, &r.req);
            break;
        case A_SENDMSG:
            w.iov.iov_base = w.iobuf; w.iov.iov_len = 64;
            w.msg = {}; w.msg.msg_iov = &w.iov; w.msg.msg_iovlen = 1;
            r.req.type = op_write; ty = op_write; t1 = raw_t(fd);
            ok = w.loop->submit_sendmsg(fd, &w.msg, &r.req);
            break;
        case A_TIMEOUT:
            w.ts = { 3600, 0 };
            r.req.type = op_timeout; ty = op_timeout; t1 = IO_TARGET_NONE;
            ok = w.loop->submit_timeout(&w.ts, &r.req);
            break;
        case A_READ_PROVIDED:
            ty = op_read_provided; t1 = raw_t(fd); group = grp;
            ok = w.loop->submit_read_provided(fd, grp, &r.req);
            break;
        case A_RECV_MULTISHOT:
            ty = op_recv_multishot; t1 = raw_t(fd); group = grp;
            ok = w.loop->submit_recv_multishot(fd, grp, &r.req);
            break;
        case A_READ_FIXED:
            if (fx < 0) return false;
            r.req.type = op_read; ty = op_read; t1 = fixed_t(fx);
            ok = w.loop->submit_read_fixed_file(fx, w.iobuf, 64, &r.req);
            break;
        case A_WRITE_FIXED:
            if (fx < 0) return false;
            r.req.type = op_write; ty = op_write; t1 = fixed_t(fx);
            ok = w.loop->submit_write_fixed_file(fx, w.iobuf, 64, &r.req);
            break;
        case A_MSHOT_FIXED:
            if (fx < 0) return false;
            ty = op_recv_multishot; t1 = fixed_t(fx); group = grp;
            ok = w.loop->submit_recv_multishot_fixed_file(fx, grp, &r.req);
            break;
        case A_PROVIDED_FIXED:
            if (fx < 0) return false;
            ty = op_read_provided; t1 = fixed_t(fx); group = grp;
            ok = w.loop->submit_read_provided_fixed_file(fx, grp, &r.req);
            break;
        case A_SPLICE:
            if (fd2 < 0) return false;
            ty = op_splice; t1 = raw_t(fd); t2 = raw_t(fd2);
            ok = w.loop->submit_splice(fd, fd2, 64, &r.req);
            break;
        case A_FILE_READ:
            ty = op_file_read; t1 = raw_t(fd);
            ok = w.loop->submit_file_read(fd, w.iobuf, 64, 0, &r.req);
            break;
        case A_CONNECT:
            w.addr = {}; w.addr.sin_family = AF_INET;
            r.req.type = op_connect; ty = op_connect; t1 = raw_t(fd);
            ok = w.loop->submit_connect(fd, reinterpret_cast<struct sockaddr*>(&w.addr),
                                        sizeof(w.addr), &r.req);
            break;
        case A_POLL:
            r.req.type = op_poll; ty = op_poll; t1 = raw_t(fd);
            ok = w.loop->submit_poll_add(fd, POLLIN, &r.req);
            break;
        case A_READ_FIXED_BUF:
            ty = op_read_fixed_buf; t1 = raw_t(fd);
            ok = w.loop->submit_read_fixed_buf(fd, w.iobuf, 64, 0, &r.req);
            break;
        case A_WRITE_FIXED_BUF:
            ty = op_write_fixed_buf; t1 = raw_t(fd);
            ok = w.loop->submit_write_fixed_buf(fd, w.iobuf, 64, 0, &r.req);
            break;
        default:
            return false;
    }

    if (!ok)
        return false;

    // arm() has run.  Everything below is the ledger recording what it charged,
    // and the checks that it charged what the caller asked for.
    const uint32_t tok  = r.req.owner_token;
    const uint32_t slot = tok & SLOT_MASK;

    LOOP_CHECK(r.req.armed_target == t1 && r.req.armed_target2 == t2,
               "the submission recorded a different descriptor on the request than the "
               "helper wrote into the SQE — the number released when it completes would "
               "then be the wrong one");
    LOOP_CHECK(r.req.type == ty,
               "the helper left a different operation type on the request than the one "
               "the loop counted it as");

    if (oi >= 0)
    {
        fake_owner& o = w.owners[oi];
        LOOP_CHECK(o.m_loop_token == tok,
                   "the submission was stamped with an identity its owner does not hold");
        if (!o.registered)
        {
            // Registration is implicit on first submission.  The epoch is the
            // whole reason a recycled slot is a different identity, so a new
            // registration reproducing a token some request still carries is a
            // defect in its own right.
            LOOP_FINDING("owner-token-reused", w.last_token[slot] != tok,
                         "a new registration was handed a token that is byte for byte one "
                         "an earlier registration on the same slot held — a completion "
                         "still in the ring for the old one would pass the staleness check "
                         "and be delivered into the new owner");
            o.registered = true;
            o.token      = tok;
            w.last_token[slot] = tok;
            LOOP_CHECK(w.loop->m_owners[slot].handler == &o,
                       "the owner table's slot does not point at the handler it was just "
                       "registered for");
        }
        else
        {
            LOOP_CHECK(o.token == tok,
                       "a submission from a registered owner was stamped with an identity "
                       "other than the one that registration holds");
        }
    }
    else
    {
        LOOP_CHECK(tok == 0, "a submission with no owner was stamped with an identity");
    }

    arm_rec& rec = r.arms[r.narms++];
    rec.tok = tok; rec.slot = slot; rec.type = ty;
    rec.t1 = t1; rec.t2 = t2; rec.owner = oi; rec.group = group;

    w.exp_inflight[slot]++;
    touch_slot(w, slot);
    w.arms_issued++;
    ledger_ref(w, t1);
    ledger_ref(w, t2);

    check_slot(w, slot, "after a submission");
    return true;
}

// Deliver one completion for request `ri`, or decline if it has nothing armed.
bool do_cqe(world& w, int ri, uint8_t res_sel, uint8_t flag_sel, uint8_t aux)
{
    req_rec& r = w.reqs[ri];
    if (r.narms == 0)
        return false;

    const arm_rec rec = r.arms[0];       // FIFO: the oldest arm is the one reporting

    uint32_t flags = 0;
    const bool more = (flag_sel & 1u) != 0;
    if (more)            flags |= IORING_CQE_F_MORE;
    if (flag_sel & 4u)   flags |= IORING_CQE_F_SOCK_NONEMPTY;

    // A provided buffer only ever rides on a completion for a submission that
    // selected one; anything else is a shape no kernel produces, and asserting
    // over it would be asserting over fiction.
    int      buf_group = -1;
    uint16_t bid = 0;
    if ((flag_sel & 2u) && rec.group >= 0)
    {
        buf_group = rec.group;
        bid = static_cast<uint16_t>(aux % BUFS_PER_GROUP);
        flags |= IORING_CQE_F_BUFFER | (static_cast<uint32_t>(bid) << IORING_CQE_BUFFER_SHIFT);
    }

    const bool expect_dispatch =
        rec.owner >= 0 && w.owners[rec.owner].registered && w.owners[rec.owner].token == rec.tok;

    struct io_uring_cqe cqe;
    std::memset(&cqe, 0, sizeof(cqe));
    cqe.user_data = static_cast<__u64>(reinterpret_cast<std::uintptr_t>(&r.req));
    cqe.res       = RES_TABLE[res_sel % NRES];
    cqe.flags     = flags;

    if (buf_group >= 0)
        buf_sync(w, buf_group);

    // A zero-copy send answers the two questions this loop tracks at different
    // moments, and it is the only operation that does.  Its send completion
    // ends the descriptor's involvement — the SQE is spent, and the
    w.cqe_req    = ri;
    w.cqe_action = w.draining ? static_cast<uint8_t>(H_NONE)
                              : static_cast<uint8_t>(aux % H_ACTION_COUNT);
    w.cqe_aux    = aux;
    w.cqe_expect_dispatch = expect_dispatch;
    w.cqe_dispatched      = false;
    // Exactly what the loop puts in m_cqe_target for the duration of the
    // dispatch, so a close_fd() from inside the handler can be predicted.
    w.cqe_t1 = more ? IO_TARGET_NONE : rec.t1;
    w.cqe_t2 = more ? IO_TARGET_NONE : rec.t2;
    w.cqe_final = !more;

    const auto outcome = w.loop->dispatch_cqe(&cqe);

    w.cqe_t1 = IO_TARGET_NONE;
    w.cqe_t2 = IO_TARGET_NONE;
    w.cqe_req = -1;

    LOOP_CHECK(outcome == event_loop::cqe_outcome::next,
               "an ordinary completion was reported as the loop's stop signal");

    if (expect_dispatch)
    {
        LOOP_FINDING("live-not-dispatched", w.cqe_dispatched,
                     "a completion whose owner is still registered was not delivered to it "
                     "— the handler is waiting on an answer that will never come and the "
                     "connection hangs until the runtime stops");
    }

    // What the completion was carrying had to go somewhere.
    if (buf_group >= 0)
    {
        const unsigned published = buf_published(w, buf_group);
        if (w.cqe_dispatched)
        {
            set_detail("a delivered completion published %u buffer(s) back to group %d",
                       published, buf_group);
            LOOP_FINDING("buf-double-return", published == 0,
                         "the loop returned a provided buffer that it had just handed to a "
                         "handler — the same buffer is now in the group twice, and two "
                         "connections will be given the same memory");
            g_detail[0] = 0;
        }
        else
        {
            set_detail("a discarded completion published %u buffer(s) back to group %d "
                       "(buffer id %u)", published, buf_group, static_cast<unsigned>(bid));
            LOOP_FINDING("buf-not-returned", published == 1,
                         "a completion that could not be delivered did not return its "
                         "provided buffer to the group — the pool is shared by every "
                         "runtime of that type, so one instance dropping buffers starves "
                         "all of them");
            if (published == 1)
            {
                const struct io_uring_buf& e =
                    w.ring[buf_group]->bufs[w.ring_tail[buf_group] & (BUFS_PER_GROUP - 1)];
                LOOP_FINDING("buf-wrong-id", e.bid == bid,
                             "the buffer returned to the group is not the one the "
                             "completion carried — one buffer is now in the ring twice and "
                             "another has been lost");
            }
            g_detail[0] = 0;
        }
        buf_sync(w, buf_group);
    }


    if (!more)
    {
        // Last completion for this submission: the arm is answered.  Shift the
        // FIFO down; a re-arm from inside the handler has already appended.
        for (int i = 1; i < r.narms; i++) r.arms[i - 1] = r.arms[i];
        r.narms--;

        if (w.exp_inflight[rec.slot] > 0) w.exp_inflight[rec.slot]--;
        ledger_unref(w, rec.t1);
        ledger_unref(w, rec.t2);

        // The slot is free to be handed out again only once nothing is owed to
        // it.  Losing the handler pointer while something still is would make
        // owner_inflight() answer for the wrong object.
        if (w.exp_inflight[rec.slot] == 0 && rec.owner >= 0 &&
            !w.owners[rec.owner].registered)
        {
            LOOP_FINDING("owner-slot-not-released",
                         w.loop->m_owners[rec.slot].handler == nullptr ||
                         w.loop->m_owners[rec.slot].token != 0,
                         "an owner slot whose registration was revoked and whose last "
                         "submission has reported still points at the retired handler — a "
                         "later object at the same address is mistaken for it");
        }
    }

    check_slot(w, rec.slot, more ? "after a multishot completion" : "after a final completion");
    return true;
}

// ─────────────────────────────── the driver ─────────────────────────────────

void setup(world& w)
{
    w.loop = new event_loop(64);
    event_loop& L = *w.loop;

    LOOP_CHECK(L.init_fd_tables(), "the descriptor tables could not be allocated");

    // A ring the kernel never sees.  ring_fd is deliberately invalid: the one
    // path that still reaches a syscall (free_fixed_file_slot's unregister)
    // fails with EBADF, which is a return value that code already ignores.
    std::memset(&L.m_ring, 0, sizeof(L.m_ring));
    L.m_ring.ring_fd = -1;
    L.m_ring.enter_ring_fd = -1;
    L.m_ring.sq.khead         = &w.khead;
    L.m_ring.sq.ktail         = &w.khead;
    L.m_ring.sq.kflags        = &w.khead;
    L.m_ring.sq.kdropped      = &w.khead;
    L.m_ring.sq.array         = &w.khead;
    L.m_ring.sq.sqes          = w.sqes;
    L.m_ring.sq.ring_entries  = 8;
    L.m_ring.sq.ring_mask     = 7;
    L.m_ring_open = true;

    // The feature flags decide which branch each submit_* helper takes; turning
    // them on is what makes the multishot and fixed-file shapes reachable.
    L.m_multishot_supported     = true;
    L.m_direct_accept_supported = true;
    L.m_files_registered        = true;
    L.m_registered_file_count   = 4096;

    for (uint16_t g = 0; g < NGROUPS; g++)
    {
        w.ring[g] = static_cast<struct io_uring_buf_ring*>(
            std::calloc(BUFS_PER_GROUP, sizeof(struct io_uring_buf)));
        w.base[g] = static_cast<char*>(std::calloc(BUFS_PER_GROUP, BUF_SIZE));
        LOOP_CHECK(w.ring[g] != nullptr && w.base[g] != nullptr,
                   "the harness could not allocate a provided-buffer group");
        L.m_buf_rings[g].ring      = w.ring[g];
        L.m_buf_rings[g].base      = w.base[g];
        L.m_buf_rings[g].buf_count = BUFS_PER_GROUP;
        L.m_buf_rings[g].buf_size  = BUF_SIZE;
        w.ring_tail[g] = w.ring[g]->tail;
    }

    for (int i = 0; i < NOWNERS; i++)
    {
        w.owners[i].idx = i;
        w.owners[i].registered = false;
        w.owners[i].m_loop_token = 0;
    }
    for (int i = 0; i < NFDS; i++)
    {
        if (fds().fd[i] < 0) continue;
        if (!fd_is_open(fds().fd[i]))
        {
            if (::dup2(fds().master, fds().fd[i]) < 0) {}
        }
        w.fd_open[i] = fd_is_open(fds().fd[i]);
        LOOP_CHECK(!w.fd_open[i] ||
                   static_cast<uint32_t>(fds().fd[i]) < L.m_fd_table_size,
                   "the harness opened a descriptor outside the loop's tracked range");
    }
}

void teardown(world& w)
{
    // Before the destructor: shutdown_ring() would unregister buffer groups and
    // munmap a submission queue that is this harness's own memory.  Closing the
    // door first is what makes the destructor a plain free().
    if (w.loop)
    {
        for (uint16_t g = 0; g < NGROUPS; g++)
            w.loop->m_buf_rings[g] = buf_ring_pool{};
        w.loop->m_ring_open   = false;
        w.loop->m_bufs_registered = false;
        w.loop->m_files_registered = false;
        std::memset(&w.loop->m_ring, 0, sizeof(w.loop->m_ring));
        delete w.loop;
        w.loop = nullptr;
    }
    for (uint16_t g = 0; g < NGROUPS; g++)
    {
        std::free(w.ring[g]); w.ring[g] = nullptr;
        std::free(w.base[g]); w.base[g] = nullptr;
    }
    // Put back every number the loop closed, so the next input starts from the
    // same alphabet the artifact that found a bug was recorded against.
    for (int i = 0; i < NFDS; i++)
    {
        if (fds().fd[i] < 0) continue;
        if (!fd_is_open(fds().fd[i]))
        {
            if (::dup2(fds().master, fds().fd[i]) < 0) {}
        }
    }
}

bool run_step(world& w, const step& s)
{
    event_loop& L = *w.loop;

    switch (s.op)
    {
        case OP_ARM: case OP_ARM_B:
            return do_arm(w, s.a % NREQS, static_cast<uint8_t>(s.b % A_KIND_COUNT), s.c, s.d, false);

        case OP_CQE: case OP_CQE_B: case OP_CQE_C:
            return do_cqe(w, s.a % NREQS, s.c, s.d, s.e);

        case OP_CQE_CANCEL:
        {
            const int i = s.a % NFDS;
            const int fd = fds().fd[i];
            if (fd < 0) return false;
            struct io_uring_cqe cqe;
            std::memset(&cqe, 0, sizeof(cqe));
            cqe.user_data = (static_cast<__u64>(static_cast<uint32_t>(fd)) << 1) | 1u;
            cqe.res = RES_TABLE[s.c % NRES];
            const auto outcome = L.dispatch_cqe(&cqe);
            LOOP_CHECK(outcome == event_loop::cqe_outcome::next,
                       "a cancel acknowledgement was reported as the loop's stop signal");
            if (w.exp_fd_cancels[i] > 0)
            {
                w.exp_fd_cancels[i]--;
                ledger_settle_fd(w, i);
            }
            return true;
        }

        case OP_CQE_NULL:
        {
            // What submit_timeout_remove() and submit_poll_remove() report: no
            // request, nothing to act on, and — the part that has to hold —
            // nothing counted either.  An arm() with no disarm to answer it is
            // the timer leak; a disarm with no arm wraps the counter.
            struct io_uring_cqe cqe;
            std::memset(&cqe, 0, sizeof(cqe));
            cqe.res = RES_TABLE[s.c % NRES];
            uint32_t before[NFDS];
            for (int i = 0; i < NFDS; i++)
                before[i] = fds().fd[i] >= 0 ? L.m_fd_armed[fds().fd[i]] : 0u;
            const auto outcome = L.dispatch_cqe(&cqe);
            LOOP_CHECK(outcome == event_loop::cqe_outcome::next,
                       "a removal's answer was reported as the loop's stop signal");
            for (int i = 0; i < NFDS; i++)
            {
                if (fds().fd[i] < 0) continue;
                LOOP_FINDING("null-req-side-effects",
                             L.m_fd_armed[fds().fd[i]] == before[i],
                             "a completion carrying no request changed the loop's "
                             "accounting — the removal helpers deliberately arm nothing, so "
                             "anything counted here has no arm to answer it");
            }
            return true;
        }

        case OP_CQE_SIGNAL:
        {
            struct io_uring_cqe cqe;
            std::memset(&cqe, 0, sizeof(cqe));
            cqe.user_data = static_cast<__u64>(reinterpret_cast<std::uintptr_t>(&L.m_signal_req));
            cqe.res = 8;
            const auto outcome = L.dispatch_cqe(&cqe);
            LOOP_CHECK(outcome == event_loop::cqe_outcome::stop,
                       "the stop eventfd's completion did not end the drain — the daemon "
                       "would go on dispatching into runtimes that are shutting down");
            return true;
        }

        case OP_REGISTER:
        {
            fake_owner& o = w.owners[s.a % NOWNERS];
            const uint32_t tok = L.register_owner(&o);
            const uint32_t slot = tok & SLOT_MASK;
            LOOP_CHECK(tok != 0, "register_owner() handed out the reserved zero identity");
            if (!o.registered)
            {
                LOOP_FINDING("owner-token-reused", w.last_token[slot] != tok,
                             "a new registration reproduced a token an earlier registration "
                             "on the same slot held, so a completion still in the ring for "
                             "the old one would be delivered into the new owner");
                w.last_token[slot] = tok;
                o.registered = true;
                o.token = tok;
            }
            else
            {
                LOOP_CHECK(tok == o.token,
                           "register_owner() is not idempotent: a second call handed the "
                           "owner a new identity, stranding every submission already in the "
                           "ring under the old one");
            }
            LOOP_CHECK(L.owner_registered(&o), "an owner that just registered does not read "
                                               "as registered");
            touch_slot(w, slot);
            return true;
        }

        case OP_DEREGISTER:
        {
            fake_owner& o = w.owners[s.a % NOWNERS];
            L.deregister_owner(&o);
            o.registered = false;
            LOOP_CHECK(!L.owner_registered(&o),
                       "an owner that just deregistered still reads as registered, so its "
                       "completions would be delivered into storage it has released");
            return true;
        }

        case OP_CLOSE_FD:
        {
            const int i = s.a % NFDS;
            if (fds().fd[i] < 0 || !w.fd_open[i]) return false;
            ledger_close_fd(w, i);
            return true;
        }

        case OP_CANCEL_FD:
        {
            const int i = s.a % NFDS;
            if (fds().fd[i] < 0 || !w.fd_open[i]) return false;
            sq_reset(w);
            if (L.submit_cancel_fd(fds().fd[i]))
                w.exp_fd_cancels[i]++;
            return true;
        }

        case OP_TIMEOUT_REMOVE:
        case OP_POLL_REMOVE:
        {
            // Neither of these arms anything, and that is the whole point: the
            // withdrawn operation keeps the completion it was already owed, and
            // the withdrawal's own answer is skipped by the loop.  Anything
            // counted here would be an arm with no disarm to answer it.
            req_rec& r = w.reqs[s.a % NREQS];
            sq_reset(w);
            const uint32_t before = w.loop->m_owners[0].inflight;
            if (s.op == OP_TIMEOUT_REMOVE) L.submit_timeout_remove(&r.req);
            else                           L.submit_poll_remove(&r.req);
            LOOP_FINDING("removal-armed", w.loop->m_owners[0].inflight == before,
                         "a removal helper counted a submission of its own — it produces a "
                         "completion the loop deliberately skips, so nothing will ever "
                         "answer that count and the owner never drains");
            return true;
        }

        case OP_ALLOC_FIXED:
        {
            const int i = s.a % NFIXED;
            if (w.fixed[i] >= 0) return false;
            const int idx = L.alloc_fixed_file_slot();
            if (idx < 0) return false;
            for (int j = 0; j < NFIXED; j++)
                LOOP_CHECK(j == i || w.fixed[j] != idx,
                           "the fixed-file allocator handed out an index it had already "
                           "given to somebody else");
            w.fixed[i] = idx;
            w.exp_fixed_armed[i] = 0;
            w.fixed_free_req[i] = false;
            return true;
        }

        case OP_FREE_FIXED:
        {
            const int i = s.a % NFIXED;
            if (w.fixed[i] < 0 || w.fixed_free_req[i]) return false;
            L.free_fixed_file_slot(static_cast<uint32_t>(w.fixed[i]));
            w.fixed_free_req[i] = true;
            if (w.exp_fixed_armed[i] == 0)
            {
                // Released at once; the index is somebody else's now.
                w.fixed_free_req[i] = false;
                w.fixed[i] = -1;
            }
            return true;
        }

        case OP_RETURN_CQE_BUF:
        {
            // The public door for a caller that is about to drop a completion
            // itself: a connection index that no longer resolves, a handler that
            // cannot place the request.
            req_rec& r = w.reqs[s.a % NREQS];
            if (r.narms == 0 || r.arms[0].group < 0) return false;
            const int g = r.arms[0].group;
            const uint16_t bid = static_cast<uint16_t>(s.e % BUFS_PER_GROUP);
            struct io_uring_cqe cqe;
            std::memset(&cqe, 0, sizeof(cqe));
            cqe.flags = IORING_CQE_F_BUFFER | (static_cast<uint32_t>(bid) << IORING_CQE_BUFFER_SHIFT);
            buf_sync(w, g);
            L.return_cqe_buf(&cqe, &r.req);
            LOOP_FINDING("buf-not-returned", buf_published(w, g) == 1,
                         "return_cqe_buf() did not put the completion's buffer back into "
                         "its group");
            buf_sync(w, g);
            return true;
        }

        case OP_REUSE_FD:
        {
            // The hazard the descriptor counters exist for, from the other side:
            // the number is given away and taken back by something else while
            // submissions still name it.  The loop counts numbers, not files, so
            // its books must be untouched by this.
            const int i = s.a % NFDS;
            if (fds().fd[i] < 0 || !w.fd_open[i] || w.fd_close_req[i]) return false;
            const uint32_t armed_before = L.m_fd_armed[fds().fd[i]];
            ::close(fds().fd[i]);
            if (::dup2(fds().master, fds().fd[i]) < 0) {}
            LOOP_CHECK(L.m_fd_armed[fds().fd[i]] == armed_before,
                       "reissuing a descriptor number changed the loop's count of the "
                       "submissions naming it");
            return true;
        }

        case OP_QUERY:
        {
            for (int i = 0; i < NOWNERS; i++)
            {
                fake_owner& o = w.owners[i];
                uint32_t expect = 0;
                for (uint32_t sl = 1; sl < OWNER_SLOTS; sl++)
                    if (L.m_owners[sl].handler == &o) expect += w.exp_inflight[sl];
                const uint32_t got = L.owner_inflight(&o);
                if (got != expect)
                {
                    set_detail("owner %d: owner_inflight() is %u, the ledger over the slots "
                               "it holds is %u", i, got, expect);
                    LOOP_FINDING("owner-inflight-drift", got == expect,
                                 "owner_inflight() disagrees with what was submitted for "
                                 "that handler — this is the figure reap_retired() frees a "
                                 "runtime's six megabytes on");
                    g_detail[0] = 0;
                }
                uint32_t bd[op_type_count];
                L.owner_inflight_breakdown(&o, bd);
                uint32_t sum = 0;
                for (uint8_t t = 0; t < op_type_count; t++) sum += bd[t];
                LOOP_FINDING("owner-bytype-drift", sum == got,
                             "the per-operation-type breakdown does not sum to the "
                             "in-flight count it breaks down");
            }
            return true;
        }

        default:
            return false;
    }
}

// Complete every submission still outstanding, then require the books to be
// empty.  This is where "every arm has its disarm" is actually stated: not as a
// count that looks plausible, but as every counter in the loop reading zero.
void drain_and_verify(world& w)
{
    w.draining = true;

    for (int round = 0; round < MAX_ARMS + 1; round++)
    {
        for (int ri = 0; ri < NREQS; ri++)
            while (w.reqs[ri].narms > 0)
                do_cqe(w, ri, 0, 0, 0);          // res 0, no F_MORE, no buffer
    }

    for (int ri = 0; ri < NREQS; ri++)
        LOOP_CHECK(w.reqs[ri].narms == 0,
                   "a submission could not be completed even after every request was given "
                   "a final completion");

    event_loop& L = *w.loop;

    // The cancels are submissions too, and close_fd() waits on them exactly as
    // it waits on a read.  A descriptor still counting one at the end of the
    // program is not a leak, it is a cancel the harness has not acknowledged
    // yet — so acknowledge them, and only then ask for the books to be empty.
    for (int i = 0; i < NFDS; i++)
    {
        const int fd = fds().fd[i];
        if (fd < 0) continue;
        while (w.exp_fd_cancels[i] > 0)
        {
            struct io_uring_cqe cqe;
            std::memset(&cqe, 0, sizeof(cqe));
            cqe.user_data = (static_cast<__u64>(static_cast<uint32_t>(fd)) << 1) | 1u;
            L.dispatch_cqe(&cqe);
            w.exp_fd_cancels[i]--;
            ledger_settle_fd(w, i);
        }
    }

    for (uint32_t s = 1; s < OWNER_SLOTS; s++)
    {
        if (L.m_owners[s].inflight == 0 && w.exp_inflight[s] == 0)
            continue;
        set_detail("owner slot %u still reports %u submissions in flight at the end of the "
                   "program (ledger says %u)", s, L.m_owners[s].inflight, w.exp_inflight[s]);
        LOOP_FINDING("owner-leak", L.m_owners[s].inflight == 0 && w.exp_inflight[s] == 0,
                     "every submission in the program has reported and an owner slot is "
                     "still armed — the handler that holds it can never be told it is "
                     "quiescent, so the storage its requests live in is never freed");
        g_detail[0] = 0;
    }

    // The op-type breakdown of every slot the program touched.
    for (uint32_t word = 0; word < OWNER_SLOTS / 64; word++)
    {
        uint64_t bits = w.touched[word];
        while (bits)
        {
            const uint32_t s = word * 64 + static_cast<uint32_t>(__builtin_ctzll(bits));
            bits &= bits - 1;
            for (uint8_t t = 0; t < op_type_count; t++)
            {
                if (L.m_owners[s].by_type[t] == 0) continue;
                set_detail("owner slot %u still counts %u %s operation(s) at the end of the "
                           "program", s, L.m_owners[s].by_type[t], io_op_name(t));
                LOOP_FINDING("owner-bytype-leak", L.m_owners[s].by_type[t] == 0,
                             "an operation-kind counter did not come back to zero when "
                             "every submission had reported");
                g_detail[0] = 0;
            }
        }
    }

    for (uint32_t t = 0; t < L.m_fd_table_size; t++)
    {
        if (L.m_fd_armed[t] == 0 && L.m_fd_cancels[t] == 0) continue;
        set_detail("descriptor %u still counts %u submission(s) and %u cancel(s) at the end "
                   "of the program", t, static_cast<unsigned>(L.m_fd_armed[t]),
                   static_cast<unsigned>(L.m_fd_cancels[t]));
        LOOP_FINDING("fd-leak", false,
                     "a descriptor's count did not come back to zero when every submission "
                     "had reported — that number can never be closed or pooled again");
        g_detail[0] = 0;
        break;
    }

    for (uint32_t i = 0; i < event_loop::MAX_FIXED_FILES; i++)
    {
        if (L.m_fixed_armed[i] == 0) continue;
        set_detail("fixed-file index %u still counts %u submission(s) at the end of the "
                   "program", i, static_cast<unsigned>(L.m_fixed_armed[i]));
        LOOP_FINDING("fixed-leak", false,
                     "a fixed-file index's count did not come back to zero when every "
                     "submission had reported — the slot can never be reallocated");
        g_detail[0] = 0;
        break;
    }

    check_descriptors(w, "end of program");
    w.draining = false;
}

// From an empty ledger, feed completions that answer no submission at all.  A
// kernel cannot produce one — every CQE is a consumed SQE — but a corrupted
// user_data or a request struct reused underneath the ring can, and the guards
// in disarm() and target_unref() are there for exactly that.  Checked from zero
// so that a decrement that is not refused is immediately visible as a counter
// four billion wide.
void check_unmatched(world& w, const uint8_t* data, size_t size, size_t off)
{
    event_loop& L = *w.loop;

    for (int n = 0; n < 4; n++)
    {
        req_rec& r = w.reqs[::fuzz::byte_at(data, size, off + static_cast<size_t>(n), 0) % NREQS];
        struct io_uring_cqe cqe;
        std::memset(&cqe, 0, sizeof(cqe));
        cqe.user_data = static_cast<__u64>(reinterpret_cast<std::uintptr_t>(&r.req));
        cqe.res = 0;
        w.cqe_expect_dispatch = true;    // whatever it does, it must not be checked as stale
        w.draining = true;
        L.dispatch_cqe(&cqe);
        w.draining = false;
    }

    for (uint32_t s = 0; s < OWNER_SLOTS; s++)
    {
        if (L.m_owners[s].inflight == 0) continue;
        set_detail("owner slot %u reads %u in flight after only unmatched completions from "
                   "an empty ledger", s, L.m_owners[s].inflight);
        LOOP_FINDING("owner-inflight-wrapped", false,
                     "a completion that answered no submission was allowed to decrement an "
                     "owner's in-flight count from zero — it wraps to four billion and the "
                     "slot is never reusable again");
        g_detail[0] = 0;
        break;
    }
    for (uint32_t t = 0; t < L.m_fd_table_size; t++)
    {
        if (L.m_fd_armed[t] == 0) continue;
        set_detail("descriptor %u reads %u submissions after only unmatched completions",
                   t, static_cast<unsigned>(L.m_fd_armed[t]));
        LOOP_FINDING("fd-armed-wrapped", false,
                     "a completion that answered no submission was allowed to decrement a "
                     "descriptor's count from zero — the number is then held for ever");
        g_detail[0] = 0;
        break;
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    data = ::fuzz::never_null(data);
    ::fuzz::set_current(data, size);
    g_steps = 0;
    g_detail[0] = 0;

    if (size < STEP_BYTES)
        return 0;
    if (fds().master < 0 || fds().fd[0] < 0)
        return 0;                       // no descriptors to hand out; nothing to check

    world w;
    g_w = &w;
    setup(w);

    size_t off = 0;
    while (off + STEP_BYTES <= size && g_steps < MAX_STEPS)
    {
        step s;
        s.op = static_cast<uint8_t>(data[off + 0] % OP_STEP_COUNT);
        s.a  = data[off + 1];
        s.b  = data[off + 2];
        s.c  = data[off + 3];
        s.d  = data[off + 4];
        s.e  = data[off + 5];
        off += STEP_BYTES;

        const size_t idx = g_steps;
        g_prog[g_steps++] = s;
        g_prog[idx].note = run_step(w, s) ? NOTE_RUN : NOTE_SKIPPED;

        check_descriptors(w, "after a step");

        // Whatever the loop closed, put back — that is both the tidy-up and the
        // "the number was reissued by the next accept" case.
        for (int i = 0; i < NFDS; i++)
        {
            if (fds().fd[i] < 0 || w.fd_open[i]) continue;
            if (::dup2(fds().master, fds().fd[i]) < 0) {}
            w.fd_open[i] = true;
            w.fd_close_req[i] = false;
        }
    }

    drain_and_verify(w);
    check_unmatched(w, data, size, off);

    teardown(w);
    g_w = nullptr;
    ::fuzz::set_current(nullptr, 0);
    return 0;
}
