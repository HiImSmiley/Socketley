// Functional SDK test — the first one that RUNS the wrappers.
//
// test_sdk_engine is a compile/link test by design (its own comment says so),
// and the four SDK tests together never started a loop: a wrapper whose
// start() failed to serve a single byte passed the whole set.  This file is
// the missing half: each case starts a wrapper's event loop in a thread,
// exercises it over a real socket, and stops it with the wrapper's stop().
//
// Ports are taken from the [25000, 27000) block; unix socket paths carry the
// pid so two runs cannot collide on a node.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "socketley/server.h"
#include "socketley/client.h"
#include "socketley/cache.h"

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

constexpr uint16_t k_tcp_port = 25890;

// Dial until the listener answers, bounded.  A wrapper's start() runs in a
// thread and there is no readiness signal to block on, so the connect itself
// is the probe — each attempt either completes or fails fast on loopback.
int dial_tcp(uint16_t port, int attempts = 200)
{
    for (int i = 0; i < attempts; ++i)
    {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        REQUIRE(fd >= 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0)
            return fd;
        ::close(fd);
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    return -1;
}

int dial_unix(const std::string& path, int attempts = 200)
{
    for (int i = 0; i < attempts; ++i)
    {
        int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        REQUIRE(fd >= 0);
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path.c_str());
        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0)
            return fd;
        ::close(fd);
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    return -1;
}

// One request, one reply.  The server frames on newline; the reply is read
// until its newline so a short read cannot pass as a full one.
std::string roundtrip(int fd, const std::string& msg)
{
    std::string out = msg + "\n";
    REQUIRE(::write(fd, out.data(), out.size()) == static_cast<ssize_t>(out.size()));
    std::string reply;
    char buf[512];
    for (;;)
    {
        ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n <= 0)
            break;
        reply.append(buf, static_cast<size_t>(n));
        if (reply.find('\n') != std::string::npos)
            break;
    }
    if (!reply.empty() && reply.back() == '\n')
        reply.pop_back();
    return reply;
}

std::string unix_path_for(const char* tag)
{
    return "/tmp/sdk_runtime_" + std::string(tag) + "_" +
           std::to_string(getpid()) + ".sock";
}

} // namespace

TEST_CASE("server wrapper serves a TCP echo end to end")
{
    socketley::server srv(k_tcp_port);
    std::atomic<int> connects{0};
    std::atomic<int> disconnects{0};

    srv.on_connect([&](int) { ++connects; })
       .on_disconnect([&](int) { ++disconnects; })
       .on_message([&](int fd, std::string_view msg) {
           srv.send(fd, "echo: " + std::string(msg));
       });

    std::thread t([&] { srv.start(); });

    int fd = dial_tcp(k_tcp_port);
    REQUIRE(fd >= 0);
    CHECK(roundtrip(fd, "hello") == "echo: hello");
    CHECK(roundtrip(fd, "second") == "echo: second");
    ::close(fd);

    srv.stop();
    t.join();

    CHECK(connects.load() == 1);
    // The disconnect may race the stop; what must hold is that it never
    // exceeds the connects.
    CHECK(disconnects.load() <= connects.load());
}

TEST_CASE("server wrapper listens on an AF_UNIX socket")
{
    const std::string path = unix_path_for("srv");
    ::unlink(path.c_str());

    socketley::server srv("unix:" + path);
    CHECK(srv.get_listen_path() == path);
    CHECK(srv.port() == 0);

    srv.on_message([&](int fd, std::string_view msg) {
        srv.send(fd, "u: " + std::string(msg));
    });

    std::thread t([&] { srv.start(); });

    int fd = dial_unix(path);
    REQUIRE(fd >= 0);
    CHECK(roundtrip(fd, "over-the-node") == "u: over-the-node");
    ::close(fd);

    srv.stop();
    t.join();
}

TEST_CASE("client wrapper dials a unix listener with the -t spelling")
{
    const std::string path = unix_path_for("cli");
    ::unlink(path.c_str());

    socketley::server srv("unix:" + path);
    srv.on_message([&](int fd, std::string_view msg) {
        srv.send(fd, "pong " + std::string(msg));
    });
    std::thread ts([&] { srv.start(); });

    // Wait for the node before starting the client: its reconnect budget is
    // not the thing under test.
    int probe = dial_unix(path);
    REQUIRE(probe >= 0);
    ::close(probe);

    socketley::client cli("unix:" + path);
    std::string got;
    std::atomic<bool> answered{false};
    cli.reconnect(5);
    cli.on_connect([&](int) { cli.send("ping\n"); })
       .on_message([&](std::string_view msg) {
           got = std::string(msg);
           answered = true;
           cli.stop();
       });
    std::thread tc([&] { cli.start(); });

    for (int i = 0; i < 200 && !answered; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(25));

    cli.stop();
    tc.join();
    srv.stop();
    ts.join();

    CHECK(answered.load());
    CHECK(got.find("pong ping") != std::string::npos);
}

TEST_CASE("start() refuses instead of serving nothing when the port is taken")
{
    // Hold the port WITHOUT SO_REUSEPORT, so the wrapper's bind must fail.
    int holder = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(holder >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(25894);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(::bind(holder, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    REQUIRE(::listen(holder, 1) == 0);

    // The old void start() entered the loop with the runtime already failed
    // and blocked forever, silently.  The contract now: return false, do not
    // enter the loop.  Run it in a thread so a regression fails the assert
    // below instead of hanging the suite.
    socketley::server srv(static_cast<uint16_t>(25894));
    std::atomic<bool> returned{false};
    std::atomic<bool> result{true};
    std::thread t([&] { result = srv.start(); returned = true; });

    for (int i = 0; i < 200 && !returned; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(25));

    CHECK(returned.load());          // it came back at all
    CHECK_FALSE(result.load());      // and said no
    CHECK(srv.state() == runtime_failed);

    if (!returned)                   // regression path: unblock via stop()
        srv.stop();
    t.join();
    ::close(holder);
}

TEST_CASE("cache wrapper store operations work without the network")
{
    socketley::cache c(static_cast<uint16_t>(25891));

    CHECK(c.set("k", "v"));
    CHECK(c.get("k") == "v");
    CHECK(c.del("k"));
    CHECK(c.get("k").empty());

    CHECK(c.rpush("q", "a"));
    CHECK(c.rpush("q", "b"));
    CHECK(c.llen("q") == 2);
    CHECK(c.lpop("q") == "a");

    CHECK(c.hset("h", "f", "1"));
    CHECK(c.hget("h", "f") == "1");

    CHECK(c.set("t", "x"));
    CHECK(c.expire("t", 100));
    CHECK(c.ttl("t") > 0);
    CHECK(c.persist("t"));
    CHECK(c.ttl("t") == -1);

    // execute() speaks the same text protocol the port would, newline and all.
    CHECK(c.execute("set exec_k exec_v") == "ok\n");
    CHECK(c.get("exec_k") == "exec_v");
}
