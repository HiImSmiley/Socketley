#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

// Every standard header event_loop.h reaches, included before private is
// redefined, so only the loop's own class is opened up.
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <netinet/in.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <vector>
#include <liburing.h>

// Reaching inside the loop by the same means as test_udp_recv_ladder: the
// lever below is the submission queue itself, and it is private.
#define private public
#include "shared/loop/event_loop.h"
#undef private

// ─── WHAT THIS EXISTS TO CATCH ──────────────────────────────────────────────
//
// A KERNEL THAT HAS IORING_OP_RECV BUT NOT IORING_RECV_MULTISHOT CLOSED EVERY
// CONNECTION AT ITS FIRST READ.  5.19 is the stated floor and multishot recv
// arrived in 6.0, but the loop asked the opcode table, which has said yes since
// 5.6.  liburing puts the flag in the SQE's ioprio, 5.19's recv answers -EINVAL
// without IORING_CQE_F_MORE, and every runtime's read chain treats res <= 0 as
// the peer going away.
//
// Two things stand against that now: probe_recv_multishot() at init(), and,
// behind it, dispatch_cqe() turning a refused multishot receive into a single
// provided-buffer receive on the same request before any runtime sees it.
//
// ─── HOW THE REFUSAL IS PRODUCED ────────────────────────────────────────────
//
// 5.19 cannot be booted here, so the refusal is made by the kernel that is
// running: after a multishot receive is queued and before it is submitted, an
// ioprio bit no kernel defines is set on its SQE.  The receive's prep then
// fails exactly as 5.19's does on the multishot bit, with -EINVAL, no
// IORING_CQE_F_MORE and no buffer.  The lever itself is checked first, on a
// single receive the loop does not rescue, so a kernel that one day accepts the
// bit fails that case instead of passing the others vacuously.

namespace {

constexpr uint16_t GROUP     = 0;
constexpr uint32_t BUF_COUNT = 16;
constexpr uint32_t BUF_SIZE  = 4096;

// An ioprio bit above every IORING_RECVSEND_* flag.
constexpr uint16_t UNKNOWN_RECV_FLAG = 1u << 15;

struct seen
{
    int         res;
    uint32_t    flags;
    op_type     type;
    std::string bytes;
};

// A reader shaped like every runtime's: the chain multishot, then provided,
// re-armed when a completion ends the submission.
struct reader : io_handler
{
    event_loop&       loop;
    int               fd;
    int               fixed;
    io_request        req{};
    bool              pending{false};
    std::vector<seen> got;

    reader(event_loop& l, int f, int fx = -1) : loop(l), fd(f), fixed(fx)
    {
        req.owner  = this;
        req.fd     = f;
        req.length = 0;
    }

    bool arm()
    {
        bool queued = fixed >= 0 ? loop.submit_recv_multishot_fixed_file(fixed, GROUP, &req)
                                 : loop.submit_recv_multishot(fd, GROUP, &req);
        if (!queued)
            queued = fixed >= 0 ? loop.submit_read_provided_fixed_file(fixed, GROUP, &req)
                                : loop.submit_read_provided(fd, GROUP, &req);
        pending = queued;
        return queued;
    }

    void on_cqe(struct io_uring_cqe* cqe) override
    {
        seen s{cqe->res, cqe->flags, req.type, {}};
        if (cqe->res > 0)
            loop.for_each_cqe_buf(GROUP, cqe, [&](const char* p, uint32_t n) { s.bytes.append(p, n); });
        else if (cqe->flags & IORING_CQE_F_BUFFER)
            loop.return_cqe_buf(cqe, &req);
        got.push_back(s);
        if (!(cqe->flags & IORING_CQE_F_MORE))
        {
            pending = false;
            if (cqe->res > 0)
                arm();
        }
    }
};

// The SQE most recently handed out, which is the one the caller just queued.
struct io_uring_sqe* last_sqe(event_loop& loop)
{
    auto& sq = loop.m_ring.sq;
    return &sq.sqes[(sq.sqe_tail - 1) & sq.ring_mask];
}

// Turns of the loop until the predicate holds or a second has passed.
template <typename P>
bool pump_until(event_loop& loop, P&& done)
{
    for (int i = 0; i < 40 && !done(); i++)
        loop.poll_completions(25);
    return done();
}

bool send_text(int fd, const char* what)
{
    return ::write(fd, what, std::strlen(what)) == static_cast<ssize_t>(std::strlen(what));
}

bool kernel_at_least(int major, int minor)
{
    struct utsname u{};
    if (::uname(&u) != 0)
        return false;
    int ma = 0, mi = 0;
    if (std::sscanf(u.release, "%d.%d", &ma, &mi) != 2)
        return false;
    return ma > major || (ma == major && mi >= minor);
}

struct fixture
{
    event_loop loop{64};
    int        sv[2] = { -1, -1 };

    fixture()
    {
        REQUIRE(loop.init());
        REQUIRE(loop.setup_buf_ring(GROUP, BUF_COUNT, BUF_SIZE));
        REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) == 0);
    }

    ~fixture()
    {
        if (sv[1] >= 0) ::close(sv[1]);
        loop.shutdown_ring();
        if (sv[0] >= 0) ::close(sv[0]);
    }
};

} // namespace

TEST_CASE("the multishot probe answers what the running kernel does")
{
    // Every kernel this is built and run on is 6.0 or newer, where the answer
    // has to be yes, and older ones have to say no.
    CHECK(event_loop::probe_recv_multishot() == kernel_at_least(6, 0));

    fixture f;
    CHECK(f.loop.m_recv_multishot_supported == kernel_at_least(6, 0));
    CHECK_FALSE(f.loop.m_recv_multishot_refused);
}

TEST_CASE("the lever: an unknown receive flag is refused with -EINVAL and reaches the handler")
{
    fixture f;
    reader r(f.loop, f.sv[0]);
    REQUIRE(f.loop.submit_read_provided(f.sv[0], GROUP, &r.req));
    r.pending = true;
    last_sqe(f.loop)->ioprio |= UNKNOWN_RECV_FLAG;

    REQUIRE(pump_until(f.loop, [&] { return !r.got.empty(); }));
    CHECK(r.got[0].res == -EINVAL);
    CHECK((r.got[0].flags & IORING_CQE_F_MORE) == 0);
    // A single receive is not what the loop rescues, so multishot stays on.
    CHECK_FALSE(f.loop.m_recv_multishot_refused);
}

TEST_CASE("a refused multishot receive is re-armed as a single one and the connection reads on")
{
    fixture f;
    if (!f.loop.m_recv_multishot_supported)
        return;

    reader r(f.loop, f.sv[0]);
    REQUIRE(r.arm());
    REQUIRE(r.req.type == op_recv_multishot);
    last_sqe(f.loop)->ioprio |= UNKNOWN_RECV_FLAG;

    // The refusal is not delivered: the loop arms a provided-buffer receive in
    // its place and turns multishot off for itself.
    REQUIRE(pump_until(f.loop, [&] { return f.loop.m_recv_multishot_refused; }));
    CHECK(r.got.empty());
    CHECK(r.req.type == op_read_provided);
    CHECK_FALSE(f.loop.recv_multishot_enabled());
    CHECK(f.loop.fd_inflight(f.sv[0]) == 1);
    CHECK(f.loop.owner_inflight(&r) == 1);

    // The pending receive takes the bytes, and the reader's own chain re-arms a
    // single receive because the multishot arm now refuses.
    REQUIRE(send_text(f.sv[1], "hello"));
    REQUIRE(pump_until(f.loop, [&] { return r.got.size() >= 1; }));
    CHECK(r.got[0].res == 5);
    CHECK(r.got[0].bytes == "hello");
    CHECK(r.got[0].type == op_read_provided);
    CHECK(r.pending);
    CHECK(r.req.type == op_read_provided);

    REQUIRE(send_text(f.sv[1], "world"));
    REQUIRE(pump_until(f.loop, [&] { return r.got.size() >= 2; }));
    CHECK(r.got[1].bytes == "world");

    // And the books still balance: one receive in flight, on one descriptor.
    CHECK(f.loop.fd_inflight(f.sv[0]) == 1);
    CHECK(f.loop.owner_inflight(&r) == 1);

    // The peer leaving is still delivered as it always was.
    ::close(f.sv[1]);
    f.sv[1] = -1;
    REQUIRE(pump_until(f.loop, [&] { return r.got.size() >= 3; }));
    CHECK(r.got[2].res == 0);
    CHECK(f.loop.owner_inflight(&r) == 0);
}

TEST_CASE("every multishot receive in flight when the refusal lands is rescued, not just the first")
{
    fixture f;
    if (!f.loop.m_recv_multishot_supported)
        return;

    int sv2[2] = { -1, -1 };
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv2) == 0);
    reader a(f.loop, f.sv[0]);
    reader b(f.loop, sv2[0]);
    REQUIRE(a.arm());
    last_sqe(f.loop)->ioprio |= UNKNOWN_RECV_FLAG;
    REQUIRE(b.arm());
    last_sqe(f.loop)->ioprio |= UNKNOWN_RECV_FLAG;

    REQUIRE(pump_until(f.loop, [&] {
        return a.req.type == op_read_provided && b.req.type == op_read_provided;
    }));
    CHECK(a.got.empty());
    CHECK(b.got.empty());

    REQUIRE(send_text(sv2[1], "second"));
    REQUIRE(pump_until(f.loop, [&] { return !b.got.empty(); }));
    CHECK(b.got[0].bytes == "second");

    ::close(sv2[1]);
    REQUIRE(pump_until(f.loop, [&] { return b.got.size() >= 2; }));
    f.loop.close_fd(sv2[0]);
}

TEST_CASE("a refused multishot receive on a registered file is re-armed on the same index")
{
    fixture f;
    if (!f.loop.m_recv_multishot_supported || !f.loop.m_files_registered)
        return;

    const int slot = f.loop.alloc_fixed_file_slot();
    REQUIRE(slot >= 0);
    REQUIRE(f.loop.update_registered_file(static_cast<uint32_t>(slot), f.sv[0]));

    reader r(f.loop, f.sv[0], slot);
    REQUIRE(r.arm());
    last_sqe(f.loop)->ioprio |= UNKNOWN_RECV_FLAG;

    REQUIRE(pump_until(f.loop, [&] { return r.req.type == op_read_provided; }));
    CHECK(r.got.empty());
    CHECK(f.loop.fixed_inflight(static_cast<uint32_t>(slot)) == 1);

    REQUIRE(send_text(f.sv[1], "fixed"));
    REQUIRE(pump_until(f.loop, [&] { return !r.got.empty(); }));
    CHECK(r.got[0].bytes == "fixed");

    ::close(f.sv[1]);
    f.sv[1] = -1;
    REQUIRE(pump_until(f.loop, [&] { return r.got.size() >= 2; }));
    CHECK(r.got[1].res == 0);
    f.loop.free_fixed_file_slot(static_cast<uint32_t>(slot));
}

TEST_CASE("a descriptor already being closed gets the refusal itself rather than a receive that holds it open")
{
    fixture f;
    if (!f.loop.m_recv_multishot_supported)
        return;

    reader r(f.loop, f.sv[0]);
    REQUIRE(r.arm());
    last_sqe(f.loop)->ioprio |= UNKNOWN_RECV_FLAG;

    // Closed while the receive is still queued, so the number is held until it
    // reports, and what reports is the refusal.
    const int fd = f.sv[0];
    f.sv[0] = -1;
    f.loop.close_fd(fd);

    REQUIRE(pump_until(f.loop, [&] { return !r.got.empty(); }));
    CHECK(r.got[0].res == -EINVAL);
    CHECK(f.loop.owner_inflight(&r) == 0);
    CHECK(pump_until(f.loop, [&] { return f.loop.fd_inflight(fd) == 0 && f.loop.m_fd_close_pending == 0; }));
}

// ─── RING SETUP TIERS ───────────────────────────────────────────────────────
//
// A kernel below 6.1 refuses DEFER_TASKRUN, and init() went from the full set
// straight to a ring with no flags at all, losing SUBMIT_ALL with it, so one
// failing SQE stopped the rest of its batch.  Which tier a kernel gets is
// decided by pick_ring_setup(), played here against the flag sets of the
// kernels that matter; every tier is then built for real on this one.

namespace {

// The setup flags each kernel knows, cumulatively, as io_uring_setup checks them.
constexpr unsigned K_5_19 = IORING_SETUP_CQSIZE | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_COOP_TASKRUN;
constexpr unsigned K_6_0  = K_5_19 | IORING_SETUP_SINGLE_ISSUER;
constexpr unsigned K_6_1  = K_6_0 | IORING_SETUP_DEFER_TASKRUN;
constexpr unsigned K_6_6  = K_6_1 | IORING_SETUP_NO_SQARRAY;

unsigned picked_on(unsigned known)
{
    const int tier = event_loop::pick_ring_setup([&](unsigned flags) { return (flags & ~known) == 0; });
    REQUIRE(tier >= 0);
    return event_loop::RING_SETUP_TIERS[tier];
}

} // namespace

TEST_CASE("each kernel gets every setup flag it has")
{
    CHECK(picked_on(K_6_6) == (event_loop::RING_SETUP_DEFER | event_loop::RING_SETUP_BASE
                               | IORING_SETUP_NO_SQARRAY));
    CHECK(picked_on(K_6_1) == (event_loop::RING_SETUP_DEFER | event_loop::RING_SETUP_BASE));
    // The two kernels the old fallback left with nothing.
    CHECK(picked_on(K_6_0) == event_loop::RING_SETUP_BASE);
    CHECK(picked_on(K_5_19) == event_loop::RING_SETUP_BASE);
    CHECK((picked_on(K_5_19) & IORING_SETUP_SUBMIT_ALL) != 0);
    // Below the floor the bare ring is still there to fall back to.
    CHECK(picked_on(IORING_SETUP_CQSIZE) == 0u);
    CHECK(event_loop::pick_ring_setup([](unsigned) { return false; }) == -1);
}

TEST_CASE("every setup tier builds a ring on this kernel, and init() takes the best")
{
    for (unsigned flags : event_loop::RING_SETUP_TIERS)
    {
        CAPTURE(flags);
        struct io_uring r;
        struct io_uring_params p{};
        p.flags = flags;
        if (flags & IORING_SETUP_CQSIZE)
            p.cq_entries = 256;
        const bool needs_6_6 = (flags & IORING_SETUP_NO_SQARRAY) != 0;
        const bool needs_6_1 = (flags & IORING_SETUP_DEFER_TASKRUN) != 0;
        if ((needs_6_6 && !kernel_at_least(6, 6)) || (needs_6_1 && !kernel_at_least(6, 1)))
            continue;
        REQUIRE(io_uring_queue_init_params(64, &r, &p) == 0);
        io_uring_queue_exit(&r);
    }

    if (kernel_at_least(6, 6))
    {
        fixture f;
        CHECK(f.loop.ring_setup_flags() == event_loop::RING_SETUP_TIERS[0]);
    }
}
