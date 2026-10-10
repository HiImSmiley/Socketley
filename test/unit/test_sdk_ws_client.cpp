// SDK compile test + unit tests for ws_client.h
#include "socketley/ws_client.h"
#include <cassert>

// assert() expands to nothing under NDEBUG, which the Release build defines —
// and Release is what the test suite runs.  Every assertion in this file was
// therefore compiled away, leaving a test that verified nothing while still
// exiting 0.  CHECK stays live in every configuration.
#define CHECK(cond) do { \
    if (!(cond)) { \
        std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        std::exit(1); \
    } \
} while (0)

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

// ── SHA-1 test vectors (RFC 3174) ───────────────────────────────

static void test_sha1_empty()
{
    auto d = socketley::detail::sha1::hash("", 0);
    // SHA-1("") = da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709
    CHECK(d[0] == 0xda && d[1] == 0x39 && d[2] == 0xa3 && d[3] == 0xee);
    CHECK(d[4] == 0x5e && d[5] == 0x6b && d[6] == 0x4b && d[7] == 0x0d);
    CHECK(d[8] == 0x32 && d[9] == 0x55 && d[10] == 0xbf && d[11] == 0xef);
    CHECK(d[12] == 0x95 && d[13] == 0x60 && d[14] == 0x18 && d[15] == 0x90);
    CHECK(d[16] == 0xaf && d[17] == 0xd8 && d[18] == 0x07 && d[19] == 0x09);
}

static void test_sha1_abc()
{
    auto d = socketley::detail::sha1::hash("abc", 3);
    // SHA-1("abc") = a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d
    CHECK(d[0] == 0xa9 && d[1] == 0x99 && d[2] == 0x3e && d[3] == 0x36);
    CHECK(d[4] == 0x47 && d[5] == 0x06 && d[6] == 0x81 && d[7] == 0x6a);
    CHECK(d[8] == 0xba && d[9] == 0x3e && d[10] == 0x25 && d[11] == 0x71);
    CHECK(d[12] == 0x78 && d[13] == 0x50 && d[14] == 0xc2 && d[15] == 0x6c);
    CHECK(d[16] == 0x9c && d[17] == 0xd0 && d[18] == 0xd8 && d[19] == 0x9d);
}

static void test_sha1_long()
{
    const char* msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    auto d = socketley::detail::sha1::hash(msg, std::strlen(msg));
    // SHA-1 = 84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1
    CHECK(d[0] == 0x84 && d[1] == 0x98 && d[2] == 0x3e && d[3] == 0x44);
    CHECK(d[4] == 0x1c && d[5] == 0x3b && d[6] == 0xd2 && d[7] == 0x6e);
    CHECK(d[8] == 0xba && d[9] == 0xae && d[10] == 0x4a && d[11] == 0xa1);
    CHECK(d[12] == 0xf9 && d[13] == 0x51 && d[14] == 0x29 && d[15] == 0xe5);
    CHECK(d[16] == 0xe5 && d[17] == 0x46 && d[18] == 0x70 && d[19] == 0xf1);
}

// ── Base64 test vectors ─────────────────────────────────────────

static void test_base64_empty()
{
    auto r = socketley::detail::base64::encode(
        reinterpret_cast<const uint8_t*>(""), 0);
    CHECK(r.empty());
}

static void test_base64_f()
{
    auto r = socketley::detail::base64::encode(
        reinterpret_cast<const uint8_t*>("f"), 1);
    CHECK(r == "Zg==");
}

static void test_base64_fo()
{
    auto r = socketley::detail::base64::encode(
        reinterpret_cast<const uint8_t*>("fo"), 2);
    CHECK(r == "Zm8=");
}

static void test_base64_foo()
{
    auto r = socketley::detail::base64::encode(
        reinterpret_cast<const uint8_t*>("foo"), 3);
    CHECK(r == "Zm9v");
}

static void test_base64_foob()
{
    auto r = socketley::detail::base64::encode(
        reinterpret_cast<const uint8_t*>("foob"), 4);
    CHECK(r == "Zm9vYg==");
}

static void test_base64_fooba()
{
    auto r = socketley::detail::base64::encode(
        reinterpret_cast<const uint8_t*>("fooba"), 5);
    CHECK(r == "Zm9vYmE=");
}

static void test_base64_foobar()
{
    auto r = socketley::detail::base64::encode(
        reinterpret_cast<const uint8_t*>("foobar"), 6);
    CHECK(r == "Zm9vYmFy");
}

// ── RFC 6455 accept key ─────────────────────────────────────────

static void test_ws_accept_key()
{
    // RFC 6455 Section 4.2.2 example
    std::string result = socketley::detail::ws_compute_accept(
        "dGhlIHNhbXBsZSBub25jZQ==");
    CHECK(result == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

// ── Frame construction verification ─────────────────────────────

static void test_frame_mask_bit()
{
    // A listener on an ephemeral port, answered by hand so the client's own bytes can be read.
    int ls = ::socket(AF_INET, SOCK_STREAM, 0);
    CHECK(ls >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(::bind(ls, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    CHECK(::listen(ls, 1) == 0);
    socklen_t alen = sizeof(addr);
    CHECK(::getsockname(ls, reinterpret_cast<sockaddr*>(&addr), &alen) == 0);
    const uint16_t port = ntohs(addr.sin_port);

    pid_t pid = ::fork();
    CHECK(pid >= 0);
    if (pid == 0)
    {
        ::close(ls);
        socketley::ws_client c;
        const bool ok = c.connect("127.0.0.1", port) && c.send("test");
        c.close();
        ::_exit(ok ? 0 : 1);
    }

    // Bounded, so a client that never dials or never sends fails rather than hangs.
    timeval tv{5, 0};
    CHECK(::setsockopt(ls, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0);
    int fd = ::accept(ls, nullptr, nullptr);
    CHECK(fd >= 0);
    CHECK(::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0);

    std::string req;
    char buf[1024];
    while (req.find("\r\n\r\n") == std::string::npos)
    {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        CHECK(n > 0);
        if (n <= 0)
            break;
        req.append(buf, static_cast<size_t>(n));
    }
    const std::string hdr = "Sec-WebSocket-Key: ";
    size_t k = req.find(hdr);
    CHECK(k != std::string::npos);
    k = k == std::string::npos ? req.size() : k + hdr.size();
    const std::string key = req.substr(k, req.find("\r\n", k) - k);
    const std::string resp = "HTTP/1.1 101 Switching Protocols\r\n"
                             "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                             "Sec-WebSocket-Accept: " + socketley::detail::ws_compute_accept(key) + "\r\n\r\n";
    CHECK(::send(fd, resp.data(), resp.size(), 0) == static_cast<ssize_t>(resp.size()));

    // FIN and text, the mask bit with a length of 4, the mask, then the payload under it.
    unsigned char f[10];
    size_t got = 0;
    while (got < sizeof(f))
    {
        ssize_t n = ::recv(fd, f + got, sizeof(f) - got, 0);
        CHECK(n > 0);
        if (n <= 0)
            break;
        got += static_cast<size_t>(n);
    }
    CHECK(f[0] == 0x81);
    CHECK((f[1] & 0x80) != 0);
    CHECK((f[1] & 0x7f) == 4);
    char plain[4];
    for (int i = 0; i < 4; i++)
        plain[i] = static_cast<char>(f[6 + i] ^ f[2 + i]);
    CHECK(std::memcmp(plain, "test", 4) == 0);

    // The client is reaped before its peer closes, so its close frame meets an open socket.
    int st = 0;
    CHECK(::waitpid(pid, &st, 0) == pid);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    ::close(fd);
    ::close(ls);
}

// ── Compile verification ────────────────────────────────────────

static void verify_ws_client_api()
{
    if (false)
    {
        socketley::ws_client c;
        bool ok = c.connect("localhost", 8080);
        ok = c.connect("localhost", 8080, socketley::ws_mode::websocket, "/");
        ok = c.connect("localhost", 8080, socketley::ws_mode::raw_tcp);
        c.close();
        ok = c.reconnect();
        ok = c.is_connected();
        ok = c.send("hello");
        ok = c.send_ping("ping");
        socketley::ws_message msg = c.recv();
        c.set_recv_timeout(5000);
        socketley::ws_mode m = c.mode();
        const std::string& h = c.host();
        uint16_t p = c.port();
        (void)ok; (void)msg; (void)m; (void)h; (void)p;
    }
}

int main()
{
    // SHA-1 tests
    test_sha1_empty();
    test_sha1_abc();
    test_sha1_long();

    // Base64 tests
    test_base64_empty();
    test_base64_f();
    test_base64_fo();
    test_base64_foo();
    test_base64_foob();
    test_base64_fooba();
    test_base64_foobar();

    // WebSocket accept key
    test_ws_accept_key();

    // Frame verification
    test_frame_mask_bit();

    // Compile check
    verify_ws_client_api();

    return 0;
}
