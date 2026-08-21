#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "shared/event_loop.h"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <unistd.h>
#include <vector>

// ─── WHY THIS FILE IS A UNIT TEST AND NOT AN INTEGRATION ONE ────────────────
//
// 57d4add made get_sqe() wait for the SQPOLL thread instead of reporting a full
// submission queue as a permanent failure, and left two things written down as
// reasoning rather than as results.  Its own commit message says so:
//
//   "a kernel that answers -EINVAL to IORING_ENTER_SQ_WAIT falls back to
//    today's behaviour -- that fallback was reasoned, not exercised, because
//    this kernel supports the call"
//
// It is not reachable from an integration test.  A daemon, a port and a runtime
// bring it no closer: on a kernel that supports IORING_ENTER_SQ_WAIT the branch
// cannot be entered at all, however much load is put through it.  What can
// reach it is a link-time stub, and that costs one process, one ring and
// milliseconds.
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
// what stood there before 57d4add -- submit once, retry once, refuse.  Nothing
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
// submission per connection, no return to the event loop in between.  Small
// rather than slow, so that the provocation does not depend on how fast this
// box happens to be.
constexpr uint32_t RING_DEPTH = 8;

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
// failure mode 57d4add called out by name.  Checked, never assumed.
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
