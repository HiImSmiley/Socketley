#pragma once
#include <string>
#include <string_view>
#include <cstdint>
#include <cstring>
#include <openssl/sha.h>
#include <openssl/evp.h>

// WebSocket frame opcodes
constexpr uint8_t WS_OP_TEXT  = 0x1;
constexpr uint8_t WS_OP_CLOSE = 0x8;
constexpr uint8_t WS_OP_PING  = 0x9;
constexpr uint8_t WS_OP_PONG  = 0xA;

// Max payload size (16 MB) to prevent memory exhaustion
constexpr uint64_t WS_MAX_PAYLOAD = 16 * 1024 * 1024;

static constexpr const char* WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

struct ws_frame
{
    uint8_t opcode;
    std::string payload;
    size_t consumed;
};

// Compute Sec-WebSocket-Accept from client key
inline std::string ws_accept_key(std::string_view client_key)
{
    std::string combined;
    combined.reserve(client_key.size() + 36);
    combined.append(client_key);
    combined.append(WS_GUID);

    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(combined.data()),
         combined.size(), sha1_hash);

    // Base64 encode (SHA1 = 20 bytes -> 28 chars base64 + null)
    char b64[32];
    EVP_EncodeBlock(reinterpret_cast<unsigned char*>(b64), sha1_hash, SHA_DIGEST_LENGTH);
    return std::string(b64);
}

// Build 101 Switching Protocols response
inline std::string ws_handshake_response(std::string_view client_key)
{
    std::string accept = ws_accept_key(client_key);
    std::string resp;
    resp.reserve(160 + accept.size());
    resp += "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: ";
    resp += accept;
    resp += "\r\n\r\n";
    return resp;
}

// Create text frame (server->client, unmasked)
inline std::string ws_frame_text(std::string_view payload)
{
    std::string frame;
    size_t len = payload.size();

    if (len <= 125)
    {
        frame.resize(2 + len);
        frame[0] = static_cast<char>(0x81); // FIN + text
        frame[1] = static_cast<char>(len);
        std::memcpy(&frame[2], payload.data(), len);
    }
    else if (len <= 65535)
    {
        frame.resize(4 + len);
        frame[0] = static_cast<char>(0x81);
        frame[1] = static_cast<char>(126);
        frame[2] = static_cast<char>((len >> 8) & 0xFF);
        frame[3] = static_cast<char>(len & 0xFF);
        std::memcpy(&frame[4], payload.data(), len);
    }
    else
    {
        frame.resize(10 + len);
        frame[0] = static_cast<char>(0x81);
        frame[1] = static_cast<char>(127);
        for (int i = 0; i < 8; i++)
            frame[2 + i] = static_cast<char>((len >> (56 - 8 * i)) & 0xFF);
        std::memcpy(&frame[10], payload.data(), len);
    }

    return frame;
}

// Create pong frame
inline std::string ws_frame_pong(std::string_view payload)
{
    // RFC 6455: control frame payloads must not exceed 125 bytes
    if (payload.size() > 125)
        payload = payload.substr(0, 125);
    std::string frame;
    frame.resize(2 + payload.size());
    frame[0] = static_cast<char>(0x80 | WS_OP_PONG); // FIN + pong
    frame[1] = static_cast<char>(payload.size());
    if (!payload.empty())
        std::memcpy(&frame[2], payload.data(), payload.size());
    return frame;
}

// Create close frame with 1000 (normal closure) status code
inline std::string ws_frame_close()
{
    std::string frame(4, '\0');
    frame[0] = static_cast<char>(0x80 | WS_OP_CLOSE); // FIN + close
    frame[1] = 2;                                       // payload = 2 bytes (status code)
    frame[2] = static_cast<char>(0x03);                 // 1000 >> 8
    frame[3] = static_cast<char>(0xE8);                 // 1000 & 0xFF
    return frame;
}

// Parse one frame from buffer. Returns false if incomplete.
// Handles masked client frames (RFC 6455 requires clients to mask).
inline bool ws_parse_frame(const char* data, size_t len, ws_frame& out)
{
    if (len < 2)
        return false;

    uint8_t b0 = static_cast<uint8_t>(data[0]);
    uint8_t b1 = static_cast<uint8_t>(data[1]);

    out.opcode = b0 & 0x0F;
    bool fin = (b0 & 0x80) != 0;
    bool masked = (b1 & 0x80) != 0;
    uint64_t payload_len = b1 & 0x7F;
    size_t header_size = 2;

    if (payload_len == 126)
    {
        if (len < 4) return false;
        payload_len = (static_cast<uint64_t>(static_cast<uint8_t>(data[2])) << 8) |
                       static_cast<uint64_t>(static_cast<uint8_t>(data[3]));
        header_size = 4;
    }
    else if (payload_len == 127)
    {
        if (len < 10) return false;
        payload_len = 0;
        for (int i = 0; i < 8; i++)
            payload_len = (payload_len << 8) | static_cast<uint64_t>(static_cast<uint8_t>(data[2 + i]));
        header_size = 10;
    }

    if (payload_len > WS_MAX_PAYLOAD)
        return false;

    // Reject control frames with payload > 125 (RFC 6455 §5.5)
    if (out.opcode >= 0x8 && payload_len > 125)
        return false;

    // Reject fragmented frames (FIN=0) — we don't support reassembly
    if (!fin)
        return false;

    size_t mask_size = masked ? 4 : 0;
    size_t total = header_size + mask_size + payload_len;
    if (len < total)
        return false;

    const uint8_t* mask_key = masked ?
        reinterpret_cast<const uint8_t*>(data + header_size) : nullptr;
    const char* payload_start = data + header_size + mask_size;

    out.payload.resize(payload_len);
    if (masked)
    {
        for (uint64_t i = 0; i < payload_len; i++)
            out.payload[i] = payload_start[i] ^ mask_key[i & 3];
    }
    else
    {
        std::memcpy(out.payload.data(), payload_start, payload_len);
    }

    out.consumed = total;
    return true;
}

// Zero-alloc frame view — points into the (now unmasked) input buffer
struct ws_frame_view
{
    uint8_t opcode;
    const char* payload_ptr;
    size_t payload_len;
    size_t consumed;
};

// In-place unmask parse — modifies data buffer, sets view pointers into it.
// Uses uint64_t-widened XOR for ~4-8x fewer mask iterations.
inline bool ws_parse_frame_inplace(char* data, size_t len, ws_frame_view& out)
{
    if (len < 2)
        return false;

    uint8_t b0 = static_cast<uint8_t>(data[0]);
    uint8_t b1 = static_cast<uint8_t>(data[1]);

    out.opcode = b0 & 0x0F;
    bool fin = (b0 & 0x80) != 0;
    bool masked = (b1 & 0x80) != 0;
    uint64_t payload_len = b1 & 0x7F;
    size_t header_size = 2;

    if (payload_len == 126)
    {
        if (len < 4) return false;
        payload_len = (static_cast<uint64_t>(static_cast<uint8_t>(data[2])) << 8) |
                       static_cast<uint64_t>(static_cast<uint8_t>(data[3]));
        header_size = 4;
    }
    else if (payload_len == 127)
    {
        if (len < 10) return false;
        payload_len = 0;
        for (int i = 0; i < 8; i++)
            payload_len = (payload_len << 8) | static_cast<uint64_t>(static_cast<uint8_t>(data[2 + i]));
        header_size = 10;
    }

    if (payload_len > WS_MAX_PAYLOAD)
        return false;

    if (out.opcode >= 0x8 && payload_len > 125)
        return false;

    if (!fin)
        return false;

    size_t mask_size = masked ? 4 : 0;
    size_t total = header_size + mask_size + payload_len;
    if (len < total)
        return false;

    char* payload_start = data + header_size + mask_size;

    if (masked)
    {
        const uint8_t* mask_key = reinterpret_cast<const uint8_t*>(data + header_size);

        // Replicate 4-byte mask to 8 bytes for widened XOR
        uint32_t mask32;
        std::memcpy(&mask32, mask_key, 4);
        uint64_t mask64 = (static_cast<uint64_t>(mask32) << 32) | mask32;

        size_t i = 0;
        for (; i + 8 <= payload_len; i += 8)
        {
            uint64_t chunk;
            std::memcpy(&chunk, payload_start + i, 8);
            chunk ^= mask64;
            std::memcpy(payload_start + i, &chunk, 8);
        }
        for (; i < payload_len; i++)
            payload_start[i] ^= mask_key[i & 3];
    }

    out.payload_ptr = payload_start;
    out.payload_len = payload_len;
    out.consumed = total;
    return true;
}

// Append text frame directly into buf (no intermediate allocation)
inline void ws_frame_text_into(std::string& buf, std::string_view payload)
{
    size_t len = payload.size();
    if (len <= 125)
    {
        size_t off = buf.size();
        buf.resize(off + 2 + len);
        buf[off]     = static_cast<char>(0x81);
        buf[off + 1] = static_cast<char>(len);
        std::memcpy(&buf[off + 2], payload.data(), len);
    }
    else if (len <= 65535)
    {
        size_t off = buf.size();
        buf.resize(off + 4 + len);
        buf[off]     = static_cast<char>(0x81);
        buf[off + 1] = static_cast<char>(126);
        buf[off + 2] = static_cast<char>((len >> 8) & 0xFF);
        buf[off + 3] = static_cast<char>(len & 0xFF);
        std::memcpy(&buf[off + 4], payload.data(), len);
    }
    else
    {
        size_t off = buf.size();
        buf.resize(off + 10 + len);
        buf[off]     = static_cast<char>(0x81);
        buf[off + 1] = static_cast<char>(127);
        for (int i = 0; i < 8; i++)
            buf[off + 2 + i] = static_cast<char>((len >> (56 - 8 * i)) & 0xFF);
        std::memcpy(&buf[off + 10], payload.data(), len);
    }
}

// Append pong frame directly into buf
inline void ws_frame_pong_into(std::string& buf, std::string_view payload)
{
    if (payload.size() > 125)
        payload = payload.substr(0, 125);
    size_t off = buf.size();
    buf.resize(off + 2 + payload.size());
    buf[off]     = static_cast<char>(0x80 | WS_OP_PONG);
    buf[off + 1] = static_cast<char>(payload.size());
    if (!payload.empty())
        std::memcpy(&buf[off + 2], payload.data(), payload.size());
}

// Append close frame (1000 normal closure) directly into buf
inline void ws_frame_close_into(std::string& buf)
{
    size_t off = buf.size();
    buf.resize(off + 4, '\0');
    buf[off]     = static_cast<char>(0x80 | WS_OP_CLOSE);
    buf[off + 1] = 2;
    buf[off + 2] = static_cast<char>(0x03);
    buf[off + 3] = static_cast<char>(0xE8);
}

// Compute Sec-WebSocket-Accept and append to buf (no intermediate string)
inline void ws_accept_key_into(std::string& buf, std::string_view client_key)
{
    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    SHA_CTX sha_ctx;
    SHA1_Init(&sha_ctx);
    SHA1_Update(&sha_ctx, client_key.data(), client_key.size());
    SHA1_Update(&sha_ctx, WS_GUID, 36);
    SHA1_Final(sha1_hash, &sha_ctx);
#pragma GCC diagnostic pop

    char b64[32];
    EVP_EncodeBlock(reinterpret_cast<unsigned char*>(b64), sha1_hash, SHA_DIGEST_LENGTH);
    buf.append(b64);
}

// Build full 101 response directly into buf (no intermediate strings)
inline void ws_handshake_response_into(std::string& buf, std::string_view client_key)
{
    buf += "HTTP/1.1 101 Switching Protocols\r\n"
           "Upgrade: websocket\r\n"
           "Connection: Upgrade\r\n"
           "Sec-WebSocket-Accept: ";
    ws_accept_key_into(buf, client_key);
    buf += "\r\n\r\n";
}
