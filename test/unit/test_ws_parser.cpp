#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "shared/ws_protocol.h"

TEST_CASE("ws_frame_text: small payload")
{
    std::string frame = ws_frame_text("hello");
    REQUIRE(frame.size() == 7); // 2 header + 5 payload
    CHECK(static_cast<uint8_t>(frame[0]) == 0x81); // FIN + text
    CHECK(static_cast<uint8_t>(frame[1]) == 5);    // length
    CHECK(frame.substr(2) == "hello");
}

TEST_CASE("ws_frame_text: medium payload (126-65535)")
{
    std::string payload(200, 'A');
    std::string frame = ws_frame_text(payload);
    REQUIRE(frame.size() == 4 + 200); // 4 header + 200 payload
    CHECK(static_cast<uint8_t>(frame[0]) == 0x81);
    CHECK(static_cast<uint8_t>(frame[1]) == 126);
    uint16_t len = (static_cast<uint8_t>(frame[2]) << 8) | static_cast<uint8_t>(frame[3]);
    CHECK(len == 200);
    CHECK(frame.substr(4) == payload);
}

TEST_CASE("ws_frame_text: empty payload")
{
    std::string frame = ws_frame_text("");
    REQUIRE(frame.size() == 2);
    CHECK(static_cast<uint8_t>(frame[0]) == 0x81);
    CHECK(static_cast<uint8_t>(frame[1]) == 0);
}

TEST_CASE("ws_parse_frame: unmasked text frame")
{
    std::string frame = ws_frame_text("test");
    ws_frame out;
    bool ok = ws_parse_frame(frame.data(), frame.size(), out);
    CHECK(ok);
    CHECK(out.opcode == WS_OP_TEXT);
    CHECK(out.payload == "test");
    CHECK(out.consumed == frame.size());
}

TEST_CASE("ws_parse_frame: masked text frame")
{
    // Build a masked frame manually: FIN+text, masked, 5 bytes
    char raw[11];
    raw[0] = static_cast<char>(0x81); // FIN + text
    raw[1] = static_cast<char>(0x85); // masked + len 5
    // Mask key
    raw[2] = 0x37; raw[3] = 0xfa; raw[4] = 0x21; raw[5] = 0x3d;
    // Masked "Hello"
    const char* hello = "Hello";
    uint8_t mask[4] = {0x37, 0xfa, 0x21, 0x3d};
    for (int i = 0; i < 5; i++)
        raw[6 + i] = hello[i] ^ mask[i % 4];

    ws_frame out;
    bool ok = ws_parse_frame(raw, sizeof(raw), out);
    CHECK(ok);
    CHECK(out.opcode == WS_OP_TEXT);
    CHECK(out.payload == "Hello");
    CHECK(out.consumed == 11);
}

TEST_CASE("ws_parse_frame: incomplete frame")
{
    ws_frame out;
    // Too short
    CHECK_FALSE(ws_parse_frame("a", 1, out));
    // Header says 5 bytes but only 4 available
    char raw[6];
    raw[0] = static_cast<char>(0x81);
    raw[1] = static_cast<char>(5);
    raw[2] = 'h'; raw[3] = 'e';
    CHECK_FALSE(ws_parse_frame(raw, 4, out));
}

TEST_CASE("ws_parse_frame: ping frame")
{
    std::string frame = ws_frame_pong("data");
    // Rewrite opcode to ping for testing
    frame[0] = static_cast<char>(0x80 | WS_OP_PING);
    ws_frame out;
    bool ok = ws_parse_frame(frame.data(), frame.size(), out);
    CHECK(ok);
    CHECK(out.opcode == WS_OP_PING);
    CHECK(out.payload == "data");
}

TEST_CASE("ws_parse_frame: close frame")
{
    std::string frame = ws_frame_close();
    ws_frame out;
    bool ok = ws_parse_frame(frame.data(), frame.size(), out);
    CHECK(ok);
    CHECK(out.opcode == WS_OP_CLOSE);
    CHECK(out.payload.size() == 2);
    // Status code 1000 (normal closure) in network byte order
    CHECK(static_cast<uint8_t>(out.payload[0]) == 0x03);
    CHECK(static_cast<uint8_t>(out.payload[1]) == 0xE8);
}

TEST_CASE("ws_parse_frame: oversized payload rejected")
{
    // Craft a frame header claiming 17MB payload (> WS_MAX_PAYLOAD)
    char raw[10];
    raw[0] = static_cast<char>(0x81); // FIN + text
    raw[1] = static_cast<char>(127); // 64-bit length
    uint64_t big_len = 17 * 1024 * 1024;
    for (int i = 0; i < 8; i++)
        raw[2 + i] = static_cast<char>((big_len >> (56 - 8 * i)) & 0xFF);

    ws_frame out;
    // Should reject before trying to read the payload
    CHECK_FALSE(ws_parse_frame(raw, 10, out));
}

TEST_CASE("ws_accept_key: RFC 6455 example")
{
    // RFC 6455 Section 4.2.2 example
    std::string result = ws_accept_key("dGhlIHNhbXBsZSBub25jZQ==");
    CHECK(result == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

TEST_CASE("ws_handshake_response: contains required headers")
{
    std::string resp = ws_handshake_response("dGhlIHNhbXBsZSBub25jZQ==");
    CHECK(resp.find("101 Switching Protocols") != std::string::npos);
    CHECK(resp.find("Upgrade: websocket") != std::string::npos);
    CHECK(resp.find("Connection: Upgrade") != std::string::npos);
    CHECK(resp.find("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != std::string::npos);
    CHECK(resp.find("\r\n\r\n") != std::string::npos);
}
