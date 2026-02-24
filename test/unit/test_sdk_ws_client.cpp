// SDK compile test + unit tests for ws_client.h
#include "socketley/ws_client.h"
#include <cassert>
#include <cstdio>
#include <cstring>

// ── SHA-1 test vectors (RFC 3174) ───────────────────────────────

static void test_sha1_empty()
{
    auto d = socketley::detail::sha1::hash("", 0);
    // SHA-1("") = da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709
    assert(d[0] == 0xda && d[1] == 0x39 && d[2] == 0xa3 && d[3] == 0xee);
    assert(d[4] == 0x5e && d[5] == 0x6b && d[6] == 0x4b && d[7] == 0x0d);
    assert(d[8] == 0x32 && d[9] == 0x55 && d[10] == 0xbf && d[11] == 0xef);
    assert(d[12] == 0x95 && d[13] == 0x60 && d[14] == 0x18 && d[15] == 0x90);
    assert(d[16] == 0xaf && d[17] == 0xd8 && d[18] == 0x07 && d[19] == 0x09);
}

static void test_sha1_abc()
{
    auto d = socketley::detail::sha1::hash("abc", 3);
    // SHA-1("abc") = a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d
    assert(d[0] == 0xa9 && d[1] == 0x99 && d[2] == 0x3e && d[3] == 0x36);
    assert(d[4] == 0x47 && d[5] == 0x06 && d[6] == 0x81 && d[7] == 0x6a);
    assert(d[8] == 0xba && d[9] == 0x3e && d[10] == 0x25 && d[11] == 0x71);
    assert(d[12] == 0x78 && d[13] == 0x50 && d[14] == 0xc2 && d[15] == 0x6c);
    assert(d[16] == 0x9c && d[17] == 0xd0 && d[18] == 0xd8 && d[19] == 0x9d);
}

static void test_sha1_long()
{
    const char* msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    auto d = socketley::detail::sha1::hash(msg, std::strlen(msg));
    // SHA-1 = 84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1
    assert(d[0] == 0x84 && d[1] == 0x98 && d[2] == 0x3e && d[3] == 0x44);
    assert(d[4] == 0x1c && d[5] == 0x3b && d[6] == 0xd2 && d[7] == 0x6e);
    assert(d[8] == 0xba && d[9] == 0xae && d[10] == 0x4a && d[11] == 0xa1);
    assert(d[12] == 0xf9 && d[13] == 0x51 && d[14] == 0x29 && d[15] == 0xe5);
    assert(d[16] == 0xe5 && d[17] == 0x46 && d[18] == 0x70 && d[19] == 0xf1);
}

// ── Base64 test vectors ─────────────────────────────────────────

static void test_base64_empty()
{
    auto r = socketley::detail::base64::encode(
        reinterpret_cast<const uint8_t*>(""), 0);
    assert(r.empty());
}

static void test_base64_f()
{
    auto r = socketley::detail::base64::encode(
        reinterpret_cast<const uint8_t*>("f"), 1);
    assert(r == "Zg==");
}

static void test_base64_fo()
{
    auto r = socketley::detail::base64::encode(
        reinterpret_cast<const uint8_t*>("fo"), 2);
    assert(r == "Zm8=");
}

static void test_base64_foo()
{
    auto r = socketley::detail::base64::encode(
        reinterpret_cast<const uint8_t*>("foo"), 3);
    assert(r == "Zm9v");
}

static void test_base64_foob()
{
    auto r = socketley::detail::base64::encode(
        reinterpret_cast<const uint8_t*>("foob"), 4);
    assert(r == "Zm9vYg==");
}

static void test_base64_fooba()
{
    auto r = socketley::detail::base64::encode(
        reinterpret_cast<const uint8_t*>("fooba"), 5);
    assert(r == "Zm9vYmE=");
}

static void test_base64_foobar()
{
    auto r = socketley::detail::base64::encode(
        reinterpret_cast<const uint8_t*>("foobar"), 6);
    assert(r == "Zm9vYmFy");
}

// ── RFC 6455 accept key ─────────────────────────────────────────

static void test_ws_accept_key()
{
    // RFC 6455 Section 4.2.2 example
    std::string result = socketley::detail::ws_compute_accept(
        "dGhlIHNhbXBsZSBub25jZQ==");
    assert(result == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

// ── Frame construction verification ─────────────────────────────

static void test_frame_mask_bit()
{
    // Verify that client frames have mask bit set (0x80 in second byte)
    // We can't easily call the private build_text_frame, but we can verify
    // the public API compiles and types are correct.

    // Verify ws_mode enum
    static_assert(static_cast<int>(socketley::ws_mode::websocket) == 0, "");
    static_assert(static_cast<int>(socketley::ws_mode::raw_tcp) == 1, "");

    // Verify ws_message fields
    socketley::ws_message msg;
    msg.data = "test";
    msg.is_close = false;
    msg.is_ping = false;
    msg.error = false;
    assert(msg.data == "test");
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
