#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "shared/loop/event_loop.h"
#include "shared/loop/event_loop_definitions.h"

#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

// Reaching inside the class by the same means and for the same reason as
// fuzz_server_ops: what is asserted here is which ear is armed on a UDP
// server, and every member that says so is private.
#define private public
#include "runtime/server/server_instance.h"
#undef private

// ─── WHAT THIS EXISTS TO CATCH ──────────────────────────────────────────────
//
// A UDP SERVER WHOSE recvmsg THE RING REFUSED WAS DEAF FOR THE REST OF ITS
// LIFE.  arm_udp_recv() stored submit_recvmsg()'s answer and did nothing with
// a false, and the only three places that call it again are inside
// handle_udp_read(), which runs on the completion of the read that was never
// armed.  So the chain ended there: the runtime stayed `Up`, kept its port,
// answered `ps` and `stats`, and never received another datagram.
//
// The TCP arm cannot reach this state -- a refused accept is re-armed off a
// hundred-millisecond timer, and the fuzz target asserts a bound listener
// always has one or the other -- and the UDP ear is the one socket in the
// tree with nothing behind it.
//
// ─── HOW THE REFUSAL IS PRODUCED ────────────────────────────────────────────
//
// By starting the runtime on a loop whose ring is not open yet.  event_loop
// funnels every submission through get_sqe(), and its comment says what that
// buys: "one predictable branch turns a dereference of null queue pointers
// into the false every submit_* helper is already written for".  A full
// submission queue and an absent one are therefore the same false to
// arm_udp_recv(), and that false is the whole subject here.
//
// It is produced this way because it cannot be produced the honest way on this
// kernel: 262,144 unreaped nops on an eight-entry ring never made
// io_uring_submit() refuse, so the completion queue overflowing is not a lever
// a test has.  What a production refusal costs is therefore taken on the
// loop's word, and what the runtime does with it is measured here.
//
// The flag is never set by hand, because a test that does that asserts about a
// state the program may never be in -- and the assertion is not "a flag is up"
// but "a datagram sent to the port arrives", because a flag can be raised by a
// fix that never gets an SQE.

namespace {

uint16_t port_base()
{
    if (const char* e = ::getenv("SL_PORT_BASE"))
        return static_cast<uint16_t>(std::atoi(e) + 1430);
    if (const char* e = ::getenv("SOCKETLEY_PORT_BASE"))
        return static_cast<uint16_t>(std::atoi(e) + 1430);
    return 19000 + 1430;
}

// One datagram from a fresh ephemeral port, so each one is its own peer.
bool send_datagram(uint16_t port, const char* what)
{
    const int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return false;
    struct sockaddr_in to{};
    to.sin_family      = AF_INET;
    to.sin_port        = htons(port);
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const ssize_t n = ::sendto(s, what, std::strlen(what), 0,
                               reinterpret_cast<struct sockaddr*>(&to), sizeof(to));
    ::close(s);
    return n >= 0;
}

// The worker's turn, in the worker's order: reap what the kernel posted, then
// give the runtime the part of the turn no completion returns for.
void turns(event_loop& loop, server_instance& rt, int n)
{
    for (int i = 0; i < n; i++)
    {
        loop.poll_completions(0);
        rt.on_loop_turn();
    }
}

}  // namespace

TEST_CASE("a UDP server whose first read the ring refused still hears")
{
    const uint16_t port = port_base();

    // Not init()ed yet, so the ring refuses everything the runtime submits --
    // setup()'s read among them, which is call site one of the four.
    event_loop loop(8);
    REQUIRE(loop.ring_open() == false);

    server_instance rt("udp-deaf");
    rt.set_port(port);
    rt.set_udp(true);
    rt.set_event_loop(&loop);
    REQUIRE(rt.start(loop));
    struct teardown
    {
        server_instance& rt;
        event_loop& loop;
        ~teardown()
        {
            rt.stop(loop);
            loop.shutdown_ring();
        }
    } down{rt, loop};

    // The precondition, stated so a run that never reached it cannot be read
    // as a pass: the socket is bound and the read on it was refused.
    REQUIRE(rt.m_udp_fd >= 0);
    REQUIRE(rt.m_udp_recv_armed == false);

    // The ring has room from here, exactly as it does one turn after a full
    // submission queue has been drained.
    REQUIRE(loop.init());

    // And from here the loop turns exactly as the worker turns it.
    turns(loop, rt, 64);

    REQUIRE(send_datagram(port, "hello\n"));
    turns(loop, rt, 64);

    CHECK_MESSAGE(rt.m_udp_peers.size() == 1u,
                  "a UDP server whose read the ring refused never armed another one: "
                  "the port is bound, the runtime is running, and every datagram sent "
                  "to it is dropped by the kernel for the life of the process");
}

// The control.  Without it, "no datagram arrived" is also what a harness that
// cannot deliver one at all looks like.
TEST_CASE("control: the same server on a ring with room hears the same datagram")
{
    const uint16_t port = static_cast<uint16_t>(port_base() + 1);

    event_loop loop(8);
    REQUIRE(loop.init());

    server_instance rt("udp-hears");
    rt.set_port(port);
    rt.set_udp(true);
    rt.set_event_loop(&loop);
    REQUIRE(rt.start(loop));

    REQUIRE(rt.m_udp_fd >= 0);
    REQUIRE(rt.m_udp_recv_armed == true);

    REQUIRE(send_datagram(port, "hello\n"));
    turns(loop, rt, 64);

    CHECK(rt.m_udp_peers.size() == 1u);

    rt.stop(loop);
    loop.shutdown_ring();
}
