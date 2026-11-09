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
#include "socketley/proxy.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

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
    // Bounded, so a runtime that accepts and never answers fails the check instead of hanging the binary.
    struct timeval tv{};
    tv.tv_sec = 5;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
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

// Bounded, and an empty answer is a legitimate result rather than a failure --
// roundtrip() waits for a line because it expects one; this is for the client
// that must NOT be sent anything.
std::string read_line(int fd, int ms)
{
    struct timeval tv{};
    tv.tv_sec  = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char buf[512];
    const ssize_t n = ::read(fd, buf, sizeof(buf));
    if (n <= 0)
        return {};
    std::string out(buf, static_cast<size_t>(n));
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r'))
        out.pop_back();
    return out;
}

// connect() returning is not the server having accepted: the relay only
// reaches clients the runtime has registered, and dial_tcp comes back as soon
// as the kernel completes the handshake.  Under the sanitizer that window is
// wide enough to lose the relay, which is how the mode case failed there and
// passed in Release -- a race in the test, not in the runtime.
bool wait_for_connects(const std::atomic<int>& seen, int want, int ms = 5000)
{
    for (int i = 0; i < ms / 25; ++i)
    {
        if (seen.load() >= want)
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    return false;
}

// Stops the runtime and joins its thread on any exit, so a failed REQUIRE
// unwinds into a red case instead of ~thread calling std::terminate.
template <typename R>
struct loop_guard
{
    R& rt;
    std::thread& t;
    ~loop_guard()
    {
        if (t.joinable())
        {
            rt.stop();
            t.join();
        }
    }
};

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
    loop_guard<socketley::server> guard{srv, t};

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
    loop_guard<socketley::server> guard{srv, t};

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
    loop_guard<socketley::server> guard_s{srv, ts};

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
    loop_guard<socketley::client> guard_c{cli, tc};

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
    // Its own port and not one a later case reuses: the holder cannot set
    // SO_REUSEADDR without letting the runtime bind over it too, so a port
    // shared with another case fails this bind whenever that case's socket is
    // still in TIME-WAIT -- seen once in a full suite run, green alone after.
    int holder = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(holder >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(25897);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(::bind(holder, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    REQUIRE(::listen(holder, 1) == 0);

    // The old void start() entered the loop with the runtime already failed
    // and blocked forever, silently.  The contract now: return false, do not
    // enter the loop.  Run it in a thread so a regression fails the assert
    // below instead of hanging the suite.
    socketley::server srv(static_cast<uint16_t>(25897));
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

// The defect the shipped examples carried: the wrapper defaults to
// mode_inout, in which the runtime is a hub and relays every inbound line to
// every other client on top of whatever on_message sends.  A Lua script that
// defines a message handler suppresses that relay; a C++ callback does not.
// Every example whose on_message IS the protocol therefore double-delivered as
// soon as a second client connected -- and with one client there is nobody to
// relay to, which is why it was never seen.
TEST_CASE("the default mode relays each client's bytes to the others")
{
    socketley::server srv(static_cast<uint16_t>(25892));
    std::atomic<int> seen{0};
    srv.on_connect([&](int) { ++seen; })
       .on_message([&](int fd, std::string_view msg) {
           srv.send(fd, "[fmt] " + std::string(msg));
       });

    std::thread t([&] { srv.start(); });
    loop_guard<socketley::server> guard{srv, t};

    int a = dial_tcp(25892);
    REQUIRE(a >= 0);
    int b = dial_tcp(25892);
    REQUIRE(b >= 0);
    // Both registered before either speaks, or the relay has nobody to reach
    // and the assertion below measures the wait rather than the mode.
    REQUIRE(wait_for_connects(seen, 2));

    // A's own reply is the formatted one; B is the neighbour that hears the
    // raw line on top of it.
    CHECK(roundtrip(a, "just one line") == "[fmt] just one line");

    const std::string heard = read_line(b, 5000);
    CHECK(heard == "just one line");   // the raw relay, unformatted

    ::close(a); ::close(b);
    srv.stop();
    t.join();
}

TEST_CASE("mode_in stops it, which is what the examples set")
{
    socketley::server srv(static_cast<uint16_t>(25893));
    std::atomic<int> seen{0};
    srv.mode(mode_in)
       .on_connect([&](int) { ++seen; })
       .on_message([&](int fd, std::string_view msg) {
           srv.send(fd, "[fmt] " + std::string(msg));
       });

    std::thread t([&] { srv.start(); });
    loop_guard<socketley::server> guard{srv, t};

    int a = dial_tcp(25893);
    REQUIRE(a >= 0);
    int b = dial_tcp(25893);
    REQUIRE(b >= 0);
    // The same wait as the case above, and it is what makes this one mean
    // anything: B silent because it was never registered proves nothing about
    // mode_in.
    REQUIRE(wait_for_connects(seen, 2));

    CHECK(roundtrip(a, "just one line") == "[fmt] just one line");
    CHECK(read_line(b, 1500).empty());

    ::close(a); ::close(b);
    srv.stop();
    t.join();
}

// The proxy wrapper, and the hook contract that reads backwards.  Nothing in
// the suite ran a proxy through the SDK, and the SDK's own engine test modelled
// the trap: its example hook returned nullopt as "no edit", which DROPS.
TEST_CASE("proxy wrapper forwards, and its hooks mean what the header says")
{
    constexpr uint16_t back_port  = 25894;
    constexpr uint16_t front_pass = 25895;
    constexpr uint16_t front_drop = 25896;

    socketley::server backend(back_port, "_sdk_backend");
    backend.mode(mode_in).on_message([&](int fd, std::string_view msg) {
        backend.send(fd, "backend: " + std::string(msg));
    });
    std::thread bt([&] { backend.start(); });
    loop_guard<socketley::server> guard_b{backend, bt};
    REQUIRE(dial_tcp(back_port) >= 0);

    // ── An empty string is "unchanged", and a non-empty one replaces ───────
    {
        socketley::proxy px(front_pass, "_sdk_px_pass");
        px.backend("127.0.0.1:" + std::to_string(back_port))
          .protocol(protocol_tcp)
          .on_proxy_request([](int, std::string_view bytes) -> std::optional<std::string> {
              if (bytes.rfind("swap", 0) == 0)
                  return std::string("replaced\n");
              return std::string{};          // pass through
          });
        std::thread pt([&] { px.start(); });
        loop_guard<socketley::proxy> guard_p{px, pt};

        int c = dial_tcp(front_pass);
        REQUIRE(c >= 0);
        CHECK(roundtrip(c, "hello") == "backend: hello");
        ::close(c);

        int c2 = dial_tcp(front_pass);
        REQUIRE(c2 >= 0);
        CHECK(roundtrip(c2, "swap") == "backend: replaced");
        ::close(c2);

        px.stop();
        pt.join();
    }

    // ── nullopt is a DROP, not "no edit" ──────────────────────────────────
    {
        socketley::proxy px(front_drop, "_sdk_px_drop");
        px.backend("127.0.0.1:" + std::to_string(back_port))
          .protocol(protocol_tcp)
          .on_proxy_request([](int, std::string_view) -> std::optional<std::string> {
              return std::nullopt;
          });
        std::thread pt([&] { px.start(); });
        loop_guard<socketley::proxy> guard_p{px, pt};

        int c = dial_tcp(front_drop);
        REQUIRE(c >= 0);
        const std::string sent = "hello\n";
        REQUIRE(::write(c, sent.data(), sent.size()) == static_cast<ssize_t>(sent.size()));
        // The bytes are swallowed and the connection stays open, which is the
        // asymmetry with a Lua hook's refusal that the header now names.
        CHECK(read_line(c, 600).empty());
        ::close(c);

        px.stop();
        pt.join();
    }

    backend.stop();
    bt.join();
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

// on_read where the trace compiler stays shut, which is an embedding with a
// callback deadline: no daemon watches this thread, so the view there is the
// plain one over a string of the read, and it has to answer exactly what the
// FFI view and the string functions answer.
TEST_CASE("a client's on_read view answers as the string functions where the compiler stays shut")
{
    constexpr uint16_t port = 25898;
    const std::string script = "/tmp/sdk_runtime_onread_" + std::to_string(getpid()) + ".lua";
    {
        FILE* f = std::fopen(script.c_str(), "w");
        REQUIRE(f != nullptr);
        std::fputs(R"lua(
local function compare(v, s)
    local n, bad, first = #s, 0, nil
    local function diff(what, a, b)
        if a ~= b then bad = bad + 1; first = first or (what .. " view=" .. tostring(a) .. " string=" .. tostring(b)) end
    end
    diff("len", v:len(), n)
    diff("byte()", v:byte(), s:byte())
    for i = -n - 3, n + 3 do
        diff("byte(" .. i .. ")", v:byte(i), s:byte(i))
        diff("sub(" .. i .. ")", v:sub(i), s:sub(i))
        for j = -n - 3, n + 3 do
            local want = s:sub(i, j)
            diff("sub(" .. i .. "," .. j .. ")", v:sub(i, j), want)
            diff("eq(" .. i .. "," .. j .. ")", v:eq(i, j, want), true)
            diff("eq+(" .. i .. "," .. j .. ")", v:eq(i, j, want .. "x"), false)
        end
    end
    for _, nd in ipairs({ "\n", "o", "lo", "", "zz", s, s .. "x" }) do
        for _, init in ipairs({ -n - 3, -1, 0, 1, 2, 2.5, -1.5, n, n + 1, n + 3 }) do
            local a1, a2 = v:find(nd, init)
            local b1, b2 = s:find(nd, init, true)
            diff("find", tostring(a1) .. "," .. tostring(a2), tostring(b1) .. "," .. tostring(b2))
        end
    end
    local got = {}
    for i, j in v:lines() do got[#got + 1] = v:sub(i, j) end
    diff("lines", table.concat(got, "|"), "hello world|one|END")
    return bad .. (first and (" " .. first) or "")
end

local kept
function on_read(v)
    self.send("JIT " .. type(jit))
    self.send("CMP " .. compare(v, v:sub(1, -1)))
    self.send("SEAL mt=" .. type(getmetatable(v)) .. " tostring=" .. tostring(v)
              .. " write=" .. tostring((pcall(function() v.x = 1 end)))
              .. " notaview=" .. tostring((select(2, pcall(v.len, {})) or ""):match("not on a view") ~= nil))
    kept = v
    socketley.set_timeout(20, function()
        local ok, err = pcall(function() return kept:find("o") end)
        self.send("STALE " .. tostring(ok) .. " "
                  .. tostring(tostring(err):find("a view is valid only inside the on_read call", 1, true) ~= nil))
    end)
end
)lua", f);
        std::fclose(f);
    }

    socketley::server srv(port);
    std::mutex mu;
    std::vector<std::string> heard;
    srv.mode(mode_in)
       .on_connect([&](int fd) { srv.send(fd, "hello world\none\r\n\nEND\n"); })
       .on_message([&](int, std::string_view msg) {
           std::lock_guard<std::mutex> lk(mu);
           heard.emplace_back(msg);
       });
    std::thread ts([&] { srv.start(); });
    loop_guard<socketley::server> guard_s{srv, ts};
    int probe = dial_tcp(port);
    REQUIRE(probe >= 0);
    ::close(probe);

    socketley::client cli("127.0.0.1", port);
    cli.lua(script);
    std::thread tc([&] { cli.start(); });
    loop_guard<socketley::client> guard_c{cli, tc};

    const auto count = [&] { std::lock_guard<std::mutex> lk(mu); return heard.size(); };
    for (int i = 0; i < 200 && count() < 4; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(25));

    cli.stop();
    tc.join();
    srv.stop();
    ts.join();
    ::unlink(script.c_str());

    std::lock_guard<std::mutex> lk(mu);
    REQUIRE(heard.size() == 4);
    CHECK(heard[0] == "JIT nil");
    CHECK(heard[1] == "CMP 0");
    CHECK(heard[2] == "SEAL mt=string tostring=view write=false notaview=true");
    CHECK(heard[3] == "STALE false true");
}
