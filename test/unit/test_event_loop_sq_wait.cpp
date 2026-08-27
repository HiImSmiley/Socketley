#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "shared/event_loop.h"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

// ─── WHY THIS FILE IS A UNIT TEST AND NOT AN INTEGRATION ONE ────────────────
//
// d2d3255 made get_sqe() wait for the SQPOLL thread instead of reporting a full
// submission queue as a permanent failure, and left two things written down as
// reasoning rather than as results.  Its own commit message says so:
//
//   "a kernel that answers -EINVAL to IORING_ENTER_SQ_WAIT falls back to
//    today's behaviour -- that fallback was reasoned, not exercised, because
//    this kernel supports the call"
//
//   "teardown walks every connection calling close_fd(), which submits a cancel
//    per descriptor, so a runtime with more than the ring's depth of
//    connections could leave cancels unsubmitted [...] was not measured"
//
// Neither is reachable from an integration test.  The first cannot be entered
// at all on a kernel that supports the call, however much load is put through
// it.  The second can be provoked with a few thousand connections and a stop,
// but what it costs there -- a descriptor held until the ring itself closes,
// because the cancel that would have ended its poll never entered the ring --
// is exactly what this file arranges in one process, one ring and a few hundred
// socketpairs.
//
// ─── THE SEAM, AND WHY IT IS NOT A CONFIGURATION SURFACE ────────────────────
//
// io_uring_sqring_wait() is a static inline in <liburing.h> that shortcuts on
// a non-full ring and otherwise calls __io_uring_sqring_wait(), which is a real
// symbol in the library.  This binary is linked with
//
//     -Wl,--wrap=__io_uring_sqring_wait
//
// so the reference emitted by event_loop.cpp resolves here instead.  That is a
// link-time seam belonging to this test target alone: the daemon and every
// other target link the same event_loop.cpp against the real symbol, and the
// product gains no flag, no environment variable and no branch.  A run-time
// switch would have been a configuration surface existing only for a test, and
// the next person to find it would have no way to tell it from a real one.
//
// It also buys the thing that makes the teardown result a measurement rather
// than a claim: BOTH ARMS COME OUT OF ONE BINARY.  With the wrapper passing
// through, get_sqe() is the fixed code exactly as shipped; with it answering
// -EINVAL, the wait is a no-op and get_sqe_when_full() degrades to precisely
// what stood there before d2d3255 -- submit once, retry once, refuse.  Nothing
// is rebuilt between the two, so nothing but that one decision differs.

namespace
{

enum class wait_mode
{
    passthrough,    // the shipped behaviour: really wait for the poller
    einval,         // a kernel that does not support IORING_ENTER_SQ_WAIT
    eintr_then_real // a signal arriving in the middle of the wait
};

std::atomic<wait_mode> g_mode{wait_mode::passthrough};
std::atomic<unsigned>  g_wait_calls{0};
std::atomic<unsigned>  g_eintr_budget{0};

} // namespace

extern "C" int __real___io_uring_sqring_wait(struct io_uring* ring) noexcept;

extern "C" int __wrap___io_uring_sqring_wait(struct io_uring* ring) noexcept
{
    g_wait_calls.fetch_add(1, std::memory_order_relaxed);
    switch (g_mode.load(std::memory_order_relaxed))
    {
        case wait_mode::einval:
            return -EINVAL;
        case wait_mode::eintr_then_real:
            if (g_eintr_budget.load(std::memory_order_relaxed) > 0)
            {
                g_eintr_budget.fetch_sub(1, std::memory_order_relaxed);
                return -EINTR;
            }
            return __real___io_uring_sqring_wait(ring);
        case wait_mode::passthrough:
        default:
            return __real___io_uring_sqring_wait(ring);
    }
}

namespace
{

// A ring small enough that one pass of submissions overruns it, which is the
// shape every caller of get_sqe_when_full() arrives in: one loop, one
// submission per connection, no return to the event loop in between.  The
// production ring is 2048 and the production loop is teardown over every
// connection a runtime holds; the ratio is what matters and it is reproduced
// here at 1:32 rather than 1:1.5, so the provocation does not depend on how
// fast this box happens to be.
constexpr uint32_t RING_DEPTH = 8;

// Completions are what stalls the SQPOLL thread once its completion queue
// (RING_DEPTH * 4) has nowhere to put them, and a teardown loop drains nothing
// while it runs -- that is why the submission queue backs up in the first
// place.  Enough descriptors that this is certain rather than a race with the
// scheduler.
constexpr int CONNECTIONS = 256;

struct counting_handler : io_handler
{
    std::atomic<uint64_t> completions{0};
    void on_cqe(struct io_uring_cqe*) override
    {
        completions.fetch_add(1, std::memory_order_relaxed);
    }
};

// SQPOLL is the entire precondition: get_sqe_when_full() only reaches the wait
// when the ring has a poller, because without one io_uring_submit() is a real
// syscall that always makes room.  An arm that quietly loses SQPOLL therefore
// looks exactly like a build in which nothing can go wrong, which is the
// failure mode d2d3255 called out by name.  Checked, never assumed.
bool start_ring(event_loop& loop)
{
    loop.set_sqpoll(true);
    if (!loop.init())
        return false;
    return loop.sqpoll_enabled();
}

// Drain until the ring has nothing left, bounded by the clock rather than by a
// count, because the number of completions differs between the two arms and is
// part of what is being measured.
void drain(event_loop& loop, int budget_ms)
{
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(budget_ms);
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (loop.poll_completions(2) == 0)
        {
            // One more empty pass before believing it: a completion flushed out
            // of the kernel's overflow list can arrive after an empty one.
            if (loop.poll_completions(5) == 0)
                return;
        }
    }
}

bool fd_open(int fd)
{
    return ::fcntl(fd, F_GETFD) != -1;
}

} // namespace

// ════════════════════════════════════════════════════════════════════════════
// FINDING 3 -- the -EINVAL fallback, which had never run
// ════════════════════════════════════════════════════════════════════════════

TEST_CASE("a kernel that refuses IORING_ENTER_SQ_WAIT ends the wait, and says so")
{
    event_loop loop(RING_DEPTH);
    REQUIRE_MESSAGE(start_ring(loop),
                    "SQPOLL is the precondition for this whole file; without a "
                    "poller get_sqe() never reaches the wait at all");

    counting_handler h;
    loop.register_owner(&h);

    g_mode.store(wait_mode::einval);
    g_wait_calls.store(0);

    // Submit until one is refused.  The bound is generous and its exhaustion is
    // itself a failure: on a build where the ring never fills, nothing below
    // measures anything.
    std::vector<io_request> reqs(4096);
    bool refused = false;
    size_t submitted = 0;
    for (size_t i = 0; i < reqs.size(); ++i)
    {
        reqs[i] = io_request{ &h, nullptr, -1, 0, op_nop };
        if (!loop.submit_nop(&reqs[i]))
        {
            refused = true;
            break;
        }
        ++submitted;
    }

    CHECK_MESSAGE(refused,
                  "the submission queue never filled, so the branch under test "
                  "was never entered and every assertion below is vacuous");
    CHECK_MESSAGE(loop.sq_full_count() > 0,
                  "get_sqe_when_full() was never reached -- the provocation did "
                  "not happen");
    CHECK_MESSAGE(loop.sq_exhausted_count() > 0,
                  "a submission was refused but the refusal was not counted, so "
                  "nothing would appear in the log either");

    // The claim the code makes about -EINVAL, and the one thing no kernel here
    // can be made to demonstrate: it must END the loop rather than turn it into
    // a spin.  SQ_WAIT_ATTEMPTS is 8, so a build that treated every error like
    // -EINTR would call the wait eight times for each refusal instead of once.
    // This is the assertion that separates those two builds; it is the reason
    // the wrapper counts its calls at all.
    CHECK_MESSAGE(g_wait_calls.load() == loop.sq_exhausted_count(),
                  "-EINVAL did not end the wait: the loop re-entered it, which "
                  "on a kernel without IORING_ENTER_SQ_WAIT is a spin of "
                  "SQ_WAIT_ATTEMPTS per refused submission");

    MESSAGE("EINVAL arm: submitted=" << submitted
            << " sq_full=" << loop.sq_full_count()
            << " sq_exhausted=" << loop.sq_exhausted_count()
            << " sqring_wait_calls=" << g_wait_calls.load());

    g_mode.store(wait_mode::passthrough);
    drain(loop, 500);
    loop.deregister_owner(&h);
    loop.shutdown_ring();
}

TEST_CASE("a wait interrupted by a signal is retried, and then succeeds")
{
    // The control for the case above.  Without it, "-EINVAL ends the loop"
    // would also be true of a build that ended the loop on every error --
    // including -EINTR, which is the one error the loop exists for.  A build
    // like that passes the EINVAL case and fails this one.
    event_loop loop(RING_DEPTH);
    REQUIRE(start_ring(loop));

    counting_handler h;
    loop.register_owner(&h);

    g_mode.store(wait_mode::eintr_then_real);
    g_wait_calls.store(0);
    g_eintr_budget.store(3);

    std::vector<io_request> reqs(RING_DEPTH * 8);
    bool refused = false;
    for (size_t i = 0; i < reqs.size(); ++i)
    {
        reqs[i] = io_request{ &h, nullptr, -1, 0, op_nop };
        if (!loop.submit_nop(&reqs[i]))
        {
            refused = true;
            break;
        }
    }

    CHECK_MESSAGE(loop.sq_full_count() > 0,
                  "the ring never filled, so no wait was interrupted and this "
                  "control checked nothing");
    CHECK_MESSAGE(!refused,
                  "a submission interrupted by a signal was reported as a "
                  "permanent failure");
    CHECK(loop.sq_exhausted_count() == 0);
    CHECK_MESSAGE(g_eintr_budget.load() == 0,
                  "the loop gave up before consuming the interruptions, so it "
                  "never retried");
    CHECK(g_wait_calls.load() > loop.sq_full_count());

    MESSAGE("EINTR arm: sq_full=" << loop.sq_full_count()
            << " sq_exhausted=" << loop.sq_exhausted_count()
            << " sqring_wait_calls=" << g_wait_calls.load());

    g_mode.store(wait_mode::passthrough);
    drain(loop, 500);
    loop.deregister_owner(&h);
    loop.shutdown_ring();
}

// ════════════════════════════════════════════════════════════════════════════
// FINDING 2 -- teardown with more connections than the ring is deep
// ════════════════════════════════════════════════════════════════════════════
//
// close_fd() holds a descriptor whose number the ring still names, and submits
// one cancel to make the outstanding operation report.  A poll is the case its
// own comment singles out: it holds a reference to the file, so neither the
// close being stood in for nor a shutdown() would ever end it.  If that cancel
// does not reach the ring, nothing ends it at all -- the number stays held and
// the descriptor stays open for the life of the process.
//
// A runtime's teardown is that loop over every connection it has, with no
// return to the event loop in between, so a runtime with more connections than
// the ring is deep runs out of submission queue in the middle of it.  That is
// the shape below: CONNECTIONS descriptors on a RING_DEPTH ring, every one of
// them armed, then closed in one pass.
//
// The measurement is not the counter.  The counter says a submission was
// refused; what a user gets is a leaked descriptor, and that is what is
// counted here -- fcntl(F_GETFD) on every one of them after the ring has been
// given every chance to finish.

namespace
{

struct teardown_result
{
    bool     sqpoll{false};
    uint64_t full_delta{0};
    uint64_t exhausted_delta{0};
    int      leaked{0};
    int      armed{0};
};

teardown_result run_teardown(wait_mode mode)
{
    teardown_result r;

    event_loop loop(RING_DEPTH);
    if (!start_ring(loop))
        return r;
    r.sqpoll = true;

    counting_handler h;
    loop.register_owner(&h);

    // A socketpair per "connection", with the far end kept open so the near end
    // never becomes readable and the poll below never completes on its own.
    std::vector<int> near(CONNECTIONS, -1), far(CONNECTIONS, -1);
    std::vector<io_request> reqs(CONNECTIONS);

    for (int i = 0; i < CONNECTIONS; ++i)
    {
        int sv[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
            break;
        near[i] = sv[0];
        far[i]  = sv[1];
    }

    // Arming is setup, not the thing under test, so it does not lean on the
    // behaviour being measured.  The wait is on, and a refusal is retried after
    // giving the poller the CPU -- which is what a caller would have to do by
    // hand if get_sqe() did not do it, and is exactly the difference this file
    // exists to price.  Without this, taking the fix back out of the source
    // fails the arming REQUIRE below and the teardown assertions never run: the
    // case would be red for the right reason at the wrong line, and the
    // descriptor count -- the thing a user actually loses -- would go
    // unmeasured.
    g_mode.store(wait_mode::passthrough);
    for (int i = 0; i < CONNECTIONS; ++i)
    {
        if (near[i] < 0) continue;
        reqs[i] = io_request{ &h, nullptr, near[i], 0, op_poll };
        for (int attempt = 0; attempt < 200; ++attempt)
        {
            if (loop.submit_poll_add(near[i], POLLIN, &reqs[i]))
            {
                ++r.armed;
                break;
            }
            loop.poll_completions(1);
        }
    }

    // Give the poller the arming submissions before the counters are read, so
    // the deltas below belong to the teardown and to nothing else.
    loop.poll_completions(5);
    const uint64_t full_before = loop.sq_full_count();
    const uint64_t exh_before  = loop.sq_exhausted_count();

    // ── the teardown ──
    // One pass, one close per connection, nothing drained in between.
    g_mode.store(mode);
    for (int i = 0; i < CONNECTIONS; ++i)
    {
        if (near[i] < 0) continue;
        loop.close_fd(near[i]);
    }

    r.full_delta      = loop.sq_full_count() - full_before;
    r.exhausted_delta = loop.sq_exhausted_count() - exh_before;

    // Every chance to finish: the wait works again and the loop drains for as
    // long as anything is arriving.  A descriptor still open after this is one
    // nothing is ever going to close.
    g_mode.store(wait_mode::passthrough);
    drain(loop, 2000);

    for (int i = 0; i < CONNECTIONS; ++i)
        if (near[i] >= 0 && fd_open(near[i]))
            ++r.leaked;

    loop.deregister_owner(&h);
    loop.shutdown_ring();

    // shutdown_ring() sweeps the descriptors it was still holding, so anything
    // measured above is already recorded; close the far ends and whatever the
    // sweep did not take.
    for (int i = 0; i < CONNECTIONS; ++i)
    {
        if (far[i] >= 0)  ::close(far[i]);
        if (near[i] >= 0) ::close(near[i]);
    }
    return r;
}

} // namespace

TEST_CASE("teardown of more connections than the ring is deep loses no cancel")
{
    const teardown_result fixed = run_teardown(wait_mode::passthrough);
    REQUIRE_MESSAGE(fixed.sqpoll, "no SQPOLL, so no submission queue can fill");
    REQUIRE(fixed.armed == CONNECTIONS);

    // Without this the whole case is vacuous: a teardown that never ran out of
    // submission queue proves nothing about one that does.
    CHECK_MESSAGE(fixed.full_delta > 0,
                  "the teardown never exhausted the submission queue, so the "
                  "situation under test did not occur");

    CHECK_MESSAGE(fixed.exhausted_delta == 0,
                  "a cancel was refused the ring during teardown");
    CHECK_MESSAGE(fixed.leaked == 0,
                  "a descriptor is still open after teardown and the drain: its "
                  "poll was never cancelled, so nothing will ever release the "
                  "number");

    MESSAGE("with the fix:    sq_full=" << fixed.full_delta
            << " sq_exhausted=" << fixed.exhausted_delta
            << " leaked=" << fixed.leaked << "/" << CONNECTIONS);

    // ── the same run with d2d3255's one line taken back out ──
    //
    // The wrapper answering -EINVAL makes the wait a no-op, which leaves
    // get_sqe_when_full() doing what it did before that commit: submit, retry
    // once, refuse.  This arm is the red the fix was never watched against, and
    // it is red in the counter AND in the descriptors -- which is the point,
    // because the counter is bookkeeping and the descriptors are what a user
    // loses.
    const teardown_result reverted = run_teardown(wait_mode::einval);
    REQUIRE(reverted.sqpoll);
    REQUIRE(reverted.armed == CONNECTIONS);

    CHECK_MESSAGE(reverted.exhausted_delta > 0,
                  "the pre-fix behaviour refused no submission, so this arm is "
                  "not the control it claims to be");
    CHECK_MESSAGE(reverted.leaked > 0,
                  "the pre-fix behaviour leaked no descriptor, so the fix has "
                  "nothing to prevent and this file should say so");

    MESSAGE("fix reverted:    sq_full=" << reverted.full_delta
            << " sq_exhausted=" << reverted.exhausted_delta
            << " leaked=" << reverted.leaked << "/" << CONNECTIONS);
}
