#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "shared/loop/ring_read.h"

// The one place a connection's read is decided (shared/loop/ring_read.h): what it arms, what a completion hands back,
// and that every buffer the ring lent goes back to it.  Against a real ring and a loopback TCP pair, since what is
// asserted is what the kernel does with the arms.

namespace
{

using socketley::ring_bytes;
using kind = ring_bytes::kind;

// A connected loopback pair: [0] the side read through the ring, [1] the side the test writes.
struct tcp_pair
{
    int fd[2]{-1, -1};
    tcp_pair()
    {
        const int l = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t len = sizeof a;
        REQUIRE(::bind(l, reinterpret_cast<sockaddr*>(&a), sizeof a) == 0);
        REQUIRE(::listen(l, 1) == 0);
        REQUIRE(::getsockname(l, reinterpret_cast<sockaddr*>(&a), &len) == 0);
        fd[1] = ::socket(AF_INET, SOCK_STREAM, 0);
        REQUIRE(::connect(fd[1], reinterpret_cast<sockaddr*>(&a), sizeof a) == 0);
        fd[0] = ::accept(l, nullptr, nullptr);
        REQUIRE(fd[0] >= 0);
        ::close(l);
    }
    ~tcp_pair()
    {
        for (int f : fd)
            if (f >= 0)
                ::close(f);
    }
    void say(const std::string& s) const { REQUIRE(::send(fd[1], s.data(), s.size(), 0) == static_cast<ssize_t>(s.size())); }
};

// What the owner is handed, kept as the owner would keep it: the bytes held until it lets them go.
struct owner final : io_handler
{
    socketley::ring_reader& reads;
    socketley::ring_read rd;
    std::vector<ring_bytes> got;
    bool keep{false};
    explicit owner(socketley::ring_reader& r) : reads(r) {}
    void on_cqe(struct io_uring_cqe* cqe) override
    {
        auto b = reads.take(rd, cqe);
        got.push_back(std::move(b));
        if (!keep)
            got.back().give_back();
    }
};

// Turns until `n` completions were handed over, or a second passed.
void until(event_loop& loop, owner& o, size_t n)
{
    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while (o.got.size() < n && std::chrono::steady_clock::now() < end)
        loop.poll_completions(10);
}

char own_buf[256];
auto own = [] { return std::pair<char*, uint32_t>{own_buf, sizeof own_buf}; };

}   // namespace

TEST_CASE("a multishot recv stands across reads, hands each one's bytes, and ends when withdrawn")
{
    event_loop loop(64);
    REQUIRE(loop.init());
    if (!loop.recv_multishot_enabled())
        return;
    socketley::ring_reader reads(loop, {1, 4, 64});
    REQUIRE(reads.setup());
    owner o(reads);
    tcp_pair p;

    REQUIRE(reads.arm(o.rd, &o, &o, p.fd[0], {}, own));
    CHECK(o.rd.multi);
    for (int i = 0; i < 20; i++)
    {
        p.say("ping " + std::to_string(i));
        until(loop, o, static_cast<size_t>(i) + 1);
        REQUIRE(o.got.size() == static_cast<size_t>(i) + 1);
        CHECK(o.got.back().what == kind::data);
        CHECK(o.got.back().more);
        CHECK(o.rd.pending);
    }
    // Twenty reads through four buffers: each was given back, or the fifth would have found the ring empty.
    CHECK(reads.withdraw(o.rd));
    until(loop, o, 21);
    REQUIRE(o.got.size() == 21);
    CHECK(o.got.back().what == kind::withdrawn);
    CHECK_FALSE(o.rd.pending);
    CHECK_FALSE(o.rd.multi);
    o.got.clear();
    loop.shutdown_ring();
}

TEST_CASE("a single recv from the ring ends with its one read")
{
    event_loop loop(64);
    REQUIRE(loop.init());
    socketley::ring_reader reads(loop, {1, 4, 64});
    REQUIRE(reads.setup());
    owner o(reads);
    tcp_pair p;

    REQUIRE(reads.arm(o.rd, &o, &o, p.fd[0], {.multishot = false}, own));
    CHECK_FALSE(o.rd.multi);
    p.say("GET / HTTP/1.1\r\n\r\n");
    until(loop, o, 1);
    REQUIRE(o.got.size() == 1);
    CHECK(o.got[0].what == kind::data);
    CHECK_FALSE(o.got[0].more);
    CHECK_FALSE(o.rd.pending);
    ::shutdown(p.fd[1], SHUT_WR);
    REQUIRE(reads.arm(o.rd, &o, &o, p.fd[0], {.multishot = false}, own));
    until(loop, o, 2);
    REQUIRE(o.got.size() == 2);
    CHECK(o.got[1].what == kind::eof);
    o.got.clear();
    loop.shutdown_ring();
}

TEST_CASE("a ring with no buffer left ends the recv, and the next read lands in the owner's own")
{
    event_loop loop(64);
    REQUIRE(loop.init());
    if (!loop.recv_multishot_enabled())
        return;
    socketley::ring_reader reads(loop, {1, 2, 64});
    REQUIRE(reads.setup());
    owner o(reads);
    o.keep = true;
    tcp_pair p;

    REQUIRE(reads.arm(o.rd, &o, &o, p.fd[0], {}, own));
    // Both buffers held by the owner, so the third read finds none.
    for (int i = 0; i < 3; i++)
    {
        p.say("x" + std::to_string(i));
        until(loop, o, static_cast<size_t>(i) + 1);
    }
    REQUIRE(o.got.size() == 3);
    CHECK(o.got[2].what == kind::no_buffer);
    CHECK_FALSE(o.rd.pending);
    CHECK(o.rd.own_next);
    o.got.clear();

    REQUIRE(reads.arm(o.rd, &o, &o, p.fd[0], {}, own));
    CHECK(o.rd.req.type == op_read);
    CHECK(o.rd.own == own_buf);
    until(loop, o, 1);
    REQUIRE(o.got.size() == 1);
    CHECK(o.got[0].what == kind::data);
    CHECK(o.got[0].data() == own_buf);
    CHECK(o.got[0].view() == "x2");
    // And the read after that is lent again.
    REQUIRE(reads.arm(o.rd, &o, &o, p.fd[0], {}, own));
    CHECK(o.rd.multi);
    o.got.clear();
    loop.shutdown_ring();
}

TEST_CASE("without the ring every read lands in the owner's own buffer")
{
    event_loop loop(64);
    REQUIRE(loop.init());
    socketley::ring_reader reads(loop, {1, 0, 64});
    CHECK_FALSE(reads.setup());
    owner o(reads);
    o.keep = true;
    tcp_pair p;

    REQUIRE(reads.arm(o.rd, &o, &o, p.fd[0], {}, own));
    CHECK(o.rd.req.type == op_read);
    p.say("hello");
    until(loop, o, 1);
    REQUIRE(o.got.size() == 1);
    CHECK(o.got[0].view() == "hello");
    o.got.clear();
    loop.shutdown_ring();
}

TEST_CASE("bytes are parsed where they lie, and only what spans completions is kept")
{
    // Messages of a length byte and that many bytes, the parse answering what it used of whole ones.
    std::vector<std::string> seen;
    const auto parse = [&](std::string_view v) {
        size_t off = 0;
        while (off < v.size() && v.size() - off - 1 >= static_cast<unsigned char>(v[off]))
        {
            const size_t n = static_cast<unsigned char>(v[off]);
            seen.emplace_back(v.substr(off + 1, n));
            off += 1 + n;
        }
        return off;
    };
    std::string in;
    socketley::take_into(in, std::string_view("\x02" "ab" "\x01" "c", 5), parse);
    CHECK(in.empty());
    CHECK(seen == std::vector<std::string>{"ab", "c"});
    socketley::take_into(in, std::string_view("\x03" "de", 3), parse);
    CHECK(in == std::string("\x03" "de", 3));
    socketley::take_into(in, std::string_view("f" "\x01", 2), parse);
    CHECK(seen.back() == "def");
    CHECK(in == "\x01");
}
