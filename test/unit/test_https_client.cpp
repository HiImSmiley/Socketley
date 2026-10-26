// The blocking HTTP client the ACME client, alert webhooks and db replicas call out with: a chunked answer is read
// only when it is chunked framing, and one cut short or with a size that is no hex number is a failure.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>
#include <thread>

#include "shared/http/https_client.h"

namespace
{

// Answers one connection with `reply` after reading its request head, then closes it; the port it listens on.
struct one_answer
{
    int fd{-1};
    uint16_t port{0};
    std::thread th;
    explicit one_answer(std::string reply)
    {
        fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t len = sizeof a;
        REQUIRE(::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) == 0);
        REQUIRE(::listen(fd, 1) == 0);
        REQUIRE(::getsockname(fd, reinterpret_cast<sockaddr*>(&a), &len) == 0);
        port = ntohs(a.sin_port);
        th = std::thread([this, reply = std::move(reply)] {
            const int c = ::accept(fd, nullptr, nullptr);
            if (c < 0)
                return;
            std::string in;
            char buf[4096];
            while (in.find("\r\n\r\n") == std::string::npos)
            {
                const ssize_t n = ::recv(c, buf, sizeof buf, 0);
                if (n <= 0)
                    break;
                in.append(buf, static_cast<size_t>(n));
            }
            if (::send(c, reply.data(), reply.size(), MSG_NOSIGNAL) < 0) {}
            ::close(c);
        });
    }
    ~one_answer()
    {
        if (::shutdown(fd, SHUT_RDWR) < 0) {}
        th.join();
        ::close(fd);
    }
    std::string url() const { return "http://127.0.0.1:" + std::to_string(port) + "/x"; }
};

const std::string head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";

bool get(const std::string& body, https_client::reply& r, std::string& err)
{
    one_answer srv(head + body);
    https_client::client c;
    REQUIRE(c.init(err));
    return c.request("GET", srv.url(), {}, {}, r, err, 5);
}

}   // namespace

TEST_CASE("a chunked answer is read whole, its trailers aside")
{
    https_client::reply r;
    std::string err;
    REQUIRE(get("5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: y\r\n\r\n", r, err));
    CHECK(r.status == 200);
    CHECK(r.body == "hello world");
}

TEST_CASE("a chunk size that is no hex number, or is signed, fails rather than ending the body")
{
    https_client::reply r;
    std::string err;
    CHECK_FALSE(get("zz\r\nhello\r\n0\r\n\r\n", r, err));
    CHECK_FALSE(err.empty());
    CHECK_FALSE(get("5\r\nhello\r\nzz\r\nmore\r\n0\r\n\r\n", r, err));
    CHECK_FALSE(get("-1\r\nhello\r\n0\r\n\r\n", r, err));
    CHECK_FALSE(get("+5\r\nhello\r\n0\r\n\r\n", r, err));
}

TEST_CASE("a chunked answer cut short fails")
{
    https_client::reply r;
    std::string err;
    CHECK_FALSE(get("5\r\nhel", r, err));
    CHECK_FALSE(get("5\r\nhello\r\n", r, err));
}

TEST_CASE("a stream hands on its chunks and fails on a size that is no hex number")
{
    one_answer srv(head + "3\r\nabc\r\nzz\r\ndef\r\n");
    https_client::client c;
    std::string err, got;
    REQUIRE(c.init(err));
    const bool closed = c.stream(srv.url(), {}, [](int st) { return st == 200; },
                                 [&](std::string_view d) { got.append(d); return true; }, err, 5);
    CHECK_FALSE(closed);
    CHECK(got == "abc");
    CHECK_FALSE(err.empty());

    one_answer done(head + "3\r\nabc\r\n0\r\n\r\n");
    got.clear();
    err.clear();
    CHECK(c.stream(done.url(), {}, [](int st) { return st == 200; },
                   [&](std::string_view d) { got.append(d); return true; }, err, 5));
    CHECK(got == "abc");
}
