#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "shared/net/conn_identity.h"
#include "shared/net/conn_transfer.h"
#include "shared/loop/event_loop.h"

#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

// What a handover has to be true of, and it is not "the receiver can read".
//
// SCM_RIGHTS duplicates: after a successful send BOTH processes hold a working
// descriptor for the same socket.  A test that only checks the receiving side
// passes just as happily against an implementation that never relinquishes,
// and an implementation that never relinquishes puts two writers on one stream.
// So every case here checks the sender as well, and the control is the case
// that proves the duplication is real in the first place — without it, "the
// sender cannot write" would also be what a failed send looks like.

namespace
{

// A connected TCP pair on loopback, so the descriptor being moved is the kind
// of thing that is actually moved: an accepted client socket, not a socketpair.
struct tcp_pair
{
    int listener{-1};
    int client{-1};      // the dialling end, kept by the test
    int accepted{-1};    // the end that gets handed around

    tcp_pair()
    {
        listener = ::socket(AF_INET, SOCK_STREAM, 0);
        REQUIRE(listener >= 0);
        int one = 1;
        ::setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

        struct sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port        = 0;                     // let the kernel choose
        REQUIRE(::bind(listener, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0);
        REQUIRE(::listen(listener, 4) == 0);

        socklen_t len = sizeof(addr);
        REQUIRE(::getsockname(listener, reinterpret_cast<struct sockaddr*>(&addr), &len) == 0);

        client = ::socket(AF_INET, SOCK_STREAM, 0);
        REQUIRE(client >= 0);
        REQUIRE(::connect(client, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0);

        accepted = ::accept(listener, nullptr, nullptr);
        REQUIRE(accepted >= 0);
    }

    ~tcp_pair()
    {
        if (listener >= 0) ::close(listener);
        if (client >= 0)   ::close(client);
        if (accepted >= 0) ::close(accepted);
    }
};

std::string read_some(int fd, size_t want)
{
    std::string out;
    char buf[512];
    while (out.size() < want)
    {
        const ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
    }
    return out;
}

}   // namespace

// ─── The descriptor moves, and the name moves with it ───────────────────────

TEST_CASE("a handed-over descriptor arrives with its name and its backlog")
{
    int chan[2];
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, chan) == 0);

    tcp_pair pair;

    conn_transfer::handover out;
    out.ref     = conn_ref{conn_owner_key("abc123"), 987654321ull};
    out.origin  = "gateway";
    out.backlog = "GET / HTTP/1.1\r\n";      // already read before the decision

    REQUIRE(conn_transfer::send_handover(chan[0], out, pair.accepted));

    conn_transfer::handover in;
    int received = -1;
    REQUIRE(conn_transfer::recv_handover(chan[1], in, received));

    CHECK(received >= 0);
    CHECK(received != pair.accepted);        // a different number, the same file
    CHECK(in.ref == out.ref);
    CHECK(in.origin == "gateway");
    CHECK(in.backlog == out.backlog);

    // The received descriptor is the connection: a write on it reaches the
    // client that dialled in.
    const char* msg = "hello from the receiver\n";
    CHECK(::write(received, msg, strlen(msg)) == static_cast<ssize_t>(strlen(msg)));
    CHECK(read_some(pair.client, strlen(msg)) == msg);

    ::close(received);
    ::close(chan[0]);
    ::close(chan[1]);
}

TEST_CASE("relinquishing is what makes the receiver the owner")
{
    int chan[2];
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, chan) == 0);

    tcp_pair pair;

    conn_transfer::handover out;
    out.ref    = conn_ref{conn_owner_key("abc123"), 42};
    out.origin = "gateway";

    REQUIRE(conn_transfer::send_handover(chan[0], out, pair.accepted));

    conn_transfer::handover in;
    int received = -1;
    REQUIRE(conn_transfer::recv_handover(chan[1], in, received));

    SUBCASE("the control: before relinquishing, the sender can still write")
    {
        // This is not a nice-to-have.  SCM_RIGHTS duplicates, so the sender
        // holds a working descriptor until it gives it up — and if that were
        // not true here, "the sender cannot write" below would be proving
        // nothing but that the send failed.
        const char* from_sender = "sender still holds it\n";
        CHECK(::write(pair.accepted, from_sender, strlen(from_sender))
              == static_cast<ssize_t>(strlen(from_sender)));
        CHECK(read_some(pair.client, strlen(from_sender)) == from_sender);
    }

    SUBCASE("after relinquishing, the sender cannot write and the receiver still can")
    {
        const int given_up = pair.accepted;
        CHECK(conn_transfer::relinquish(nullptr, given_up));
        pair.accepted = -1;                  // the destructor must not close it again

        errno = 0;
        const ssize_t n = ::write(given_up, "x", 1);
        CHECK(n < 0);
        CHECK(errno == EBADF);

        // And the connection itself is alive: closing a duplicate is not
        // closing the socket, which is the whole reason a handover works.
        const char* msg = "receiver owns it now\n";
        CHECK(::write(received, msg, strlen(msg)) == static_cast<ssize_t>(strlen(msg)));
        CHECK(read_some(pair.client, strlen(msg)) == msg);
    }

    ::close(received);
    ::close(chan[0]);
    ::close(chan[1]);
}

namespace
{

// A handler that does nothing but exist, so the loop has an owner to attribute
// a submission to.
struct counting_handler : io_handler
{
    uint32_t completions{0};
    void on_cqe(struct io_uring_cqe*) override { ++completions; }
};

}   // namespace

TEST_CASE("relinquish waits for the ring rather than closing under it")
{
    // The hazard this is about: an SQE carries a descriptor NUMBER and the
    // kernel resolves it when it consumes the SQE.  Closing between the
    // submission and the consumption does not cancel the read — it aims it at
    // whatever inherits the number.  After a handover the receiver is writing
    // to that socket, so a read still armed on the sender's side would also be
    // taking bytes that now belong to somebody else.
    event_loop loop;
    REQUIRE(loop.init());

    tcp_pair pair;
    counting_handler handler;

    char buf[64];
    io_request req{};
    req.owner      = &handler;
    req.buffer     = buf;
    req.fd         = pair.accepted;
    req.length     = sizeof(buf);
    req.type       = op_read;
    req.generation = 1;

    REQUIRE(loop.submit_read(pair.accepted, buf, sizeof(buf), &req));

    // The loop batches, so the SQE is not in the kernel until something
    // submits.  One pass with no wait does that and dispatches nothing: the
    // peer has written nothing, so the read cannot have completed.
    loop.poll_completions(0);
    REQUIRE(loop.fd_inflight(pair.accepted) > 0);

    // The read is armed, so relinquish must refuse.  A version that closed
    // here is the defect: the number would go back to the kernel with a read
    // still queued against it.
    CHECK_FALSE(conn_transfer::relinquish(&loop, pair.accepted));

    // Ask for the read back — once — and then wait for it to report.
    conn_transfer::withdraw(&loop, pair.accepted);

    bool given_up = false;
    for (int i = 0; i < 200 && !given_up; ++i)
    {
        loop.poll_completions(10);
        given_up = conn_transfer::relinquish(&loop, pair.accepted);
    }

    CHECK(given_up);
    CHECK(handler.completions > 0);           // the read really did report back
    pair.accepted = -1;                       // the loop owns the close now

    loop.shutdown_ring();
}

// ─── Relay framing ──────────────────────────────────────────────────────────

TEST_CASE("a relay frame survives being cut anywhere")
{
    const conn_ref ref{conn_owner_key("deadbe"), 7};
    const std::string one = conn_transfer::relay_frame(
        conn_transfer::relay_op::data, ref, "the payload");
    const std::string two = conn_transfer::relay_frame(
        conn_transfer::relay_op::close, ref, "");

    SUBCASE("whole frames come back exactly")
    {
        std::string buf = one + two;
        conn_transfer::relay_op op{};
        conn_ref got{};
        std::string payload;
        bool fatal = false;

        REQUIRE(conn_transfer::take_relay_frame(buf, op, got, payload, fatal));
        CHECK(op == conn_transfer::relay_op::data);
        CHECK(got == ref);
        CHECK(payload == "the payload");

        REQUIRE(conn_transfer::take_relay_frame(buf, op, got, payload, fatal));
        CHECK(op == conn_transfer::relay_op::close);
        CHECK(payload.empty());
        CHECK(buf.empty());
    }

    SUBCASE("every truncation is 'not yet', never a wrong answer")
    {
        // A stream socket cuts wherever it likes.  Each prefix has to be
        // refused without consuming anything, or a reader that is one byte
        // behind resynchronises onto garbage.
        for (size_t cut = 0; cut < one.size(); ++cut)
        {
            std::string buf = one.substr(0, cut);
            const std::string before = buf;
            conn_transfer::relay_op op{};
            conn_ref got{};
            std::string payload;
            bool fatal = false;

            CHECK_FALSE(conn_transfer::take_relay_frame(buf, op, got, payload, fatal));
            CHECK_FALSE(fatal);
            CHECK(buf == before);            // untouched, so the next read appends
        }
    }

    SUBCASE("an opcode this build does not know is skipped by its length")
    {
        std::string buf = conn_transfer::relay_frame(
            static_cast<conn_transfer::relay_op>(200), ref, "from a newer build");
        buf += two;

        conn_transfer::relay_op op{};
        conn_ref got{};
        std::string payload;
        bool fatal = false;

        REQUIRE(conn_transfer::take_relay_frame(buf, op, got, payload, fatal));
        CHECK(static_cast<int>(op) == 200);
        CHECK(payload == "from a newer build");

        // The frame behind it is still readable, which is the entire point of
        // the length being ahead of the opcode.
        REQUIRE(conn_transfer::take_relay_frame(buf, op, got, payload, fatal));
        CHECK(op == conn_transfer::relay_op::close);
    }

    SUBCASE("a nonsense length is fatal rather than allocated")
    {
        std::string buf;
        for (int i = 0; i < 4; ++i) buf.push_back(static_cast<char>(0xFF));
        buf.push_back(static_cast<char>(conn_transfer::relay_op::data));
        put_conn_ref(buf, ref);

        conn_transfer::relay_op op{};
        conn_ref got{};
        std::string payload;
        bool fatal = false;

        CHECK_FALSE(conn_transfer::take_relay_frame(buf, op, got, payload, fatal));
        CHECK(fatal);
    }
}

// ─── Identity ───────────────────────────────────────────────────────────────

TEST_CASE("a conn_ref means the same thing on both sides of a wire")
{
    const conn_ref ref{conn_owner_key("a1b2c3"), 0x0123456789ABCDEFull};

    std::string wire;
    put_conn_ref(wire, ref);
    CHECK(wire.size() == conn_ref_wire_size);

    const char* p = wire.data();
    conn_ref back{};
    REQUIRE(take_conn_ref(p, wire.data() + wire.size(), back));
    CHECK(back == ref);
    CHECK(p == wire.data() + wire.size());
}

TEST_CASE("a truncated name is refused without half-consuming it")
{
    std::string wire;
    put_conn_ref(wire, conn_ref{1, 2});
    wire.resize(wire.size() - 1);

    const char* p = wire.data();
    conn_ref back{};
    CHECK_FALSE(take_conn_ref(p, wire.data() + wire.size(), back));
    CHECK(p == wire.data());
}

TEST_CASE("serials do not restart when a runtime does")
{
    // Two sources stand for the same runtime across a stop and a start.  If the
    // second began where the first did, a name the peer is still holding from
    // before the restart would resolve to a connection accepted after it.
    conn_serial_source first;
    const uint64_t a = first.next();
    const uint64_t b = first.next();
    CHECK(b == a + 1);

    conn_serial_source second;
    CHECK(second.next() > b);
}

TEST_CASE("two shards of one runtime cannot mint the same serial")
{
    // `owner` is derived from the runtime id, and every shard of a runtime has
    // the same id — so the owner half does NOT tell two shards apart, and for
    // as long as a runtime was one process nothing had to.
    //
    // What kept them apart was the gap between the moments they were seeded,
    // and that gap is finite.  Measured on this box, four shards forked and
    // exec'd the way proxy_supervisor does it: the closest two seeds were
    // 1,602,540 ns apart.  A counter moves once per connection, so the first
    // shard to accept that many connections begins handing out serials its
    // sibling has already used — about 25 minutes at a thousand a second.
    //
    // The case below is that collision, forced: two sources seeded to the same
    // counter, which is what a sibling reaches by counting.
    const uint64_t owner = conn_owner_key("abc123");

    conn_serial_source s0, s2;
    s0.set_shard(0);
    s2.set_shard(2);

    const conn_ref a{owner, s0.next()};
    const conn_ref b{owner, s2.next()};

    // Both were seeded from the same clock within the same microsecond, so
    // without the shard tag these two are the SAME name for two different
    // connections in two different processes.
    CHECK(a != b);
    CHECK(conn_ref_shard(a) == 0u);
    CHECK(conn_ref_shard(b) == 2u);

    // And a ref says which shard owns it without anybody being asked, which is
    // what lets a routed message go to one shard instead of to all N.
    // The whole shard field, from conn_identity.h's own constant rather than
    // from max_shards: this header does not include runtime_definitions.h, and
    // the two are tied together by a static_assert in server_instance.cpp.
    for (uint32_t sh = 0; sh <= conn_serial_shard_mask; ++sh)
    {
        conn_serial_source src;
        src.set_shard(sh);
        const conn_ref r{owner, src.next()};
        CHECK(conn_ref_shard(r) == sh);
        CHECK(r.valid());
    }
}

TEST_CASE("the shard tag cannot be reached by a counter that wraps")
{
    // The counter is masked on the way out rather than carried with the tag in
    // one word.  Without that, a source that ran past 2^58 would climb into the
    // shard field and start minting refs naming a different process — the same
    // defect one level up from the descriptor reuse this file exists for.
    conn_serial_source s;
    s.set_shard(1);
    for (int i = 0; i < 1000; ++i)
        CHECK(conn_ref_shard(conn_ref{1, s.next()}) == 1u);
}

TEST_CASE("an unsharded runtime reads as shard 0, which is what it is")
{
    conn_serial_source s;          // set_shard never called
    const conn_ref r{conn_owner_key("abc123"), s.next()};
    CHECK(conn_ref_shard(r) == 0u);
    CHECK(r.valid());
}

TEST_CASE("a runtime with no id mints nothing that can be resolved")
{
    CHECK(conn_owner_key("") == 0);
    CHECK_FALSE((conn_ref{conn_owner_key(""), 5}).valid());
    CHECK_FALSE((conn_ref{7, 0}).valid());
    CHECK((conn_ref{7, 5}).valid());
}

TEST_CASE("a handle can never be mistaken for a descriptor")
{
    // 8192 is the server's connection table; 1048576 is well past any
    // RLIMIT_NOFILE this project runs under.
    CHECK_FALSE(is_conn_handle(0));
    CHECK_FALSE(is_conn_handle(8191));
    CHECK_FALSE(is_conn_handle(1048576));
    CHECK(is_conn_handle(conn_handle_base));
    CHECK(is_conn_handle(conn_handle_base + 1000));
}
