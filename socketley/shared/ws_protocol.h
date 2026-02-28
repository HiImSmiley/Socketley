#pragma once
#include <string>
#include <string_view>
#include <cstdint>
#include <cstring>
#include <memory>
#include <openssl/evp.h>

// SSE2 is baseline for x86-64; AVX2 is optional
#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#define WS_HAS_SSE2 1
#if defined(__AVX2__)
#define WS_HAS_AVX2 1
#else
#define WS_HAS_AVX2 0
#endif
#else
#define WS_HAS_SSE2 0
#define WS_HAS_AVX2 0
#endif

// Cached EVP_sha1() -- avoids repeated lookup on every WS handshake
inline const EVP_MD* ws_sha1_md()
{
    static const EVP_MD* md = EVP_sha1();
    return md;
}

// WebSocket frame opcodes
constexpr uint8_t WS_OP_CONT   = 0x0;
constexpr uint8_t WS_OP_TEXT   = 0x1;
constexpr uint8_t WS_OP_BINARY = 0x2;
constexpr uint8_t WS_OP_CLOSE  = 0x8;
constexpr uint8_t WS_OP_PING   = 0x9;
constexpr uint8_t WS_OP_PONG   = 0xA;

// Max payload size (16 MB) to prevent memory exhaustion
constexpr uint64_t WS_MAX_PAYLOAD = 16 * 1024 * 1024;

static constexpr const char* WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// Pre-computed close frame (1000 normal closure) -- 4 bytes, never changes
static constexpr char WS_CLOSE_FRAME_DATA[4] = {
    static_cast<char>(0x80 | WS_OP_CLOSE), // FIN + close
    2,                                       // payload = 2 bytes
    static_cast<char>(0x03),                 // 1000 >> 8
    static_cast<char>(0xE8)                  // 1000 & 0xFF
};

struct ws_frame
{
    uint8_t opcode;
    std::string payload;
    size_t consumed;
};

// ─── SIMD / widened XOR unmask helpers ───

// Unmask payload in-place using the fastest available method.
// mask32 is the 4-byte mask key as a uint32_t (native byte order).
inline void ws_unmask_payload(char* payload, size_t len, uint32_t mask32)
{
    const uint8_t* mask_bytes = reinterpret_cast<const uint8_t*>(&mask32);

#if WS_HAS_AVX2
    // AVX2 path: 32 bytes per iteration
    if (len >= 32)
    {
        // Broadcast 4-byte mask to 32 bytes
        __m256i mask_vec = _mm256_set1_epi32(static_cast<int>(mask32));
        size_t i = 0;
        for (; i + 32 <= len; i += 32)
        {
            __m256i data = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(payload + i));
            data = _mm256_xor_si256(data, mask_vec);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(payload + i), data);
        }
        // Handle 16-byte remainder with SSE2
        for (; i + 16 <= len; i += 16)
        {
            __m128i mask128 = _mm_set1_epi32(static_cast<int>(mask32));
            __m128i data = _mm_loadu_si128(reinterpret_cast<const __m128i*>(payload + i));
            data = _mm_xor_si128(data, mask128);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(payload + i), data);
        }
        // Handle 8-byte remainder with uint64_t
        uint64_t mask64 = (static_cast<uint64_t>(mask32) << 32) | mask32;
        for (; i + 8 <= len; i += 8)
        {
            uint64_t chunk;
            std::memcpy(&chunk, payload + i, 8);
            chunk ^= mask64;
            std::memcpy(payload + i, &chunk, 8);
        }
        // 4-byte tail
        if (i + 4 <= len)
        {
            uint32_t chunk;
            std::memcpy(&chunk, payload + i, 4);
            chunk ^= mask32;
            std::memcpy(payload + i, &chunk, 4);
            i += 4;
        }
        // Byte-by-byte remainder
        for (; i < len; i++)
            payload[i] ^= mask_bytes[i & 3];
        return;
    }
#endif

#if WS_HAS_SSE2
    // SSE2 path: 16 bytes per iteration
    if (len >= 16)
    {
        __m128i mask_vec = _mm_set1_epi32(static_cast<int>(mask32));
        size_t i = 0;
        for (; i + 16 <= len; i += 16)
        {
            __m128i data = _mm_loadu_si128(reinterpret_cast<const __m128i*>(payload + i));
            data = _mm_xor_si128(data, mask_vec);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(payload + i), data);
        }
        // Handle 8-byte remainder with uint64_t
        uint64_t mask64 = (static_cast<uint64_t>(mask32) << 32) | mask32;
        for (; i + 8 <= len; i += 8)
        {
            uint64_t chunk;
            std::memcpy(&chunk, payload + i, 8);
            chunk ^= mask64;
            std::memcpy(payload + i, &chunk, 8);
        }
        // 4-byte tail
        if (i + 4 <= len)
        {
            uint32_t chunk;
            std::memcpy(&chunk, payload + i, 4);
            chunk ^= mask32;
            std::memcpy(payload + i, &chunk, 4);
            i += 4;
        }
        // Byte-by-byte remainder
        for (; i < len; i++)
            payload[i] ^= mask_bytes[i & 3];
        return;
    }
#endif

    // Scalar fallback: uint64_t-widened XOR
    uint64_t mask64 = (static_cast<uint64_t>(mask32) << 32) | mask32;
    size_t i = 0;
    for (; i + 8 <= len; i += 8)
    {
        uint64_t chunk;
        std::memcpy(&chunk, payload + i, 8);
        chunk ^= mask64;
        std::memcpy(payload + i, &chunk, 8);
    }
    // 4-byte tail
    if (i + 4 <= len)
    {
        uint32_t chunk;
        std::memcpy(&chunk, payload + i, 4);
        chunk ^= mask32;
        std::memcpy(payload + i, &chunk, 4);
        i += 4;
    }
    // Byte-by-byte remainder
    for (; i < len; i++)
        payload[i] ^= mask_bytes[i & 3];
}

// ─── SHA-1 for WS accept key (EVP API, no deprecated calls) ───

// Compute Sec-WebSocket-Accept from client key.
// Uses EVP_Digest (non-deprecated single-call API) + stack buffer.
// RFC 6455 keys are always 24 bytes, but we handle up to 88 bytes safely.
inline std::string ws_accept_key(std::string_view client_key)
{
    // Stack fast path (covers all valid WS keys: 24 + 36 = 60 bytes)
    constexpr size_t STACK_LIMIT = 92; // 128 - 36 GUID = 92 max key
    if (client_key.size() <= STACK_LIMIT)
    {
        char combined[128];
        std::memcpy(combined, client_key.data(), client_key.size());
        std::memcpy(combined + client_key.size(), WS_GUID, 36);

        unsigned char sha1_hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len = 0;
        EVP_Digest(combined, client_key.size() + 36, sha1_hash, &hash_len,
                   ws_sha1_md(), nullptr);

        char b64[32];
        EVP_EncodeBlock(reinterpret_cast<unsigned char*>(b64), sha1_hash, static_cast<int>(hash_len));
        return std::string(b64);
    }

    // Heap fallback for oversized keys (shouldn't happen per RFC)
    std::string combined;
    combined.reserve(client_key.size() + 36);
    combined.append(client_key);
    combined.append(WS_GUID, 36);

    unsigned char sha1_hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    EVP_Digest(combined.data(), combined.size(), sha1_hash, &hash_len,
               ws_sha1_md(), nullptr);

    char b64[32];
    EVP_EncodeBlock(reinterpret_cast<unsigned char*>(b64), sha1_hash, static_cast<int>(hash_len));
    return std::string(b64);
}

// Forward declaration — defined below, after frame encoding
inline void ws_accept_key_into(std::string& buf, std::string_view client_key);

// Build 101 Switching Protocols response
inline std::string ws_handshake_response(std::string_view client_key)
{
    std::string resp;
    resp.reserve(200);
    resp += "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: ";
    ws_accept_key_into(resp, client_key);
    resp += "\r\n\r\n";
    return resp;
}

// ─── Frame encoding (stack-buffer headers, memcpy payload) ───

// Write WS frame header into hdr[]. Returns header length (2, 4, or 10).
// opcode should already include FIN bit (e.g. 0x81 for FIN+text).
inline int ws_write_header(char* hdr, uint8_t opcode_with_fin, size_t payload_len)
{
    hdr[0] = static_cast<char>(opcode_with_fin);
    if (payload_len <= 125)
    {
        hdr[1] = static_cast<char>(payload_len);
        return 2;
    }
    else if (payload_len <= 65535)
    {
        hdr[1] = static_cast<char>(126);
        hdr[2] = static_cast<char>((payload_len >> 8) & 0xFF);
        hdr[3] = static_cast<char>(payload_len & 0xFF);
        return 4;
    }
    else
    {
        hdr[1] = static_cast<char>(127);
        for (int i = 0; i < 8; i++)
            hdr[2 + i] = static_cast<char>((payload_len >> (56 - 8 * i)) & 0xFF);
        return 10;
    }
}

// Create text frame (server->client, unmasked)
inline std::string ws_frame_text(std::string_view payload)
{
    char hdr[14]; // max WS header = 14 bytes (10 + 4 mask, but server doesn't mask)
    int hdr_len = ws_write_header(hdr, 0x81, payload.size());

    std::string frame;
    frame.reserve(static_cast<size_t>(hdr_len) + payload.size());
    frame.append(hdr, static_cast<size_t>(hdr_len));
    frame.append(payload);
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
    frame[0] = static_cast<char>(0x80 | WS_OP_PONG);
    frame[1] = static_cast<char>(payload.size());
    if (!payload.empty())
        std::memcpy(&frame[2], payload.data(), payload.size());
    return frame;
}

// Create close frame with 1000 (normal closure) status code
inline std::string ws_frame_close()
{
    return std::string(WS_CLOSE_FRAME_DATA, 4);
}

// ─── Frame parsing ───

// Parsed WS header (shared between ws_parse_frame and ws_parse_frame_inplace)
struct ws_header
{
    uint8_t opcode;
    bool fin;
    bool masked;
    uint64_t payload_len;
    size_t header_size;
};

// Parse WS frame header. Returns false if buffer is too short or frame is invalid.
inline bool ws_parse_header(const char* data, size_t len, ws_header& hdr)
{
    if (len < 2)
        return false;

    uint8_t b0 = static_cast<uint8_t>(data[0]);
    uint8_t b1 = static_cast<uint8_t>(data[1]);

    hdr.opcode = b0 & 0x0F;
    hdr.fin = (b0 & 0x80) != 0;
    hdr.masked = (b1 & 0x80) != 0;
    hdr.payload_len = b1 & 0x7F;
    hdr.header_size = 2;

    if (hdr.payload_len == 126)
    {
        if (len < 4) return false;
        hdr.payload_len = (static_cast<uint64_t>(static_cast<uint8_t>(data[2])) << 8) |
                           static_cast<uint64_t>(static_cast<uint8_t>(data[3]));
        hdr.header_size = 4;
    }
    else if (hdr.payload_len == 127)
    {
        if (len < 10) return false;
        hdr.payload_len = 0;
        for (int i = 0; i < 8; i++)
            hdr.payload_len = (hdr.payload_len << 8) | static_cast<uint64_t>(static_cast<uint8_t>(data[2 + i]));
        hdr.header_size = 10;
    }

    if (hdr.payload_len > WS_MAX_PAYLOAD)
        return false;

    // Reject control frames with payload > 125 (RFC 6455 5.5)
    if (hdr.opcode >= 0x8 && hdr.payload_len > 125)
        return false;

    // Reject fragmented frames (FIN=0) -- we don't support reassembly
    if (!hdr.fin)
        return false;

    size_t mask_size = hdr.masked ? 4 : 0;
    size_t total = hdr.header_size + mask_size + hdr.payload_len;
    if (len < total)
        return false;

    return true;
}

// Parse one frame from buffer. Returns false if incomplete.
// Handles masked client frames (RFC 6455 requires clients to mask).
inline bool ws_parse_frame(const char* data, size_t len, ws_frame& out)
{
    ws_header hdr;
    if (!ws_parse_header(data, len, hdr))
        return false;

    out.opcode = hdr.opcode;
    size_t mask_size = hdr.masked ? 4 : 0;
    size_t total = hdr.header_size + mask_size + hdr.payload_len;
    const char* payload_start = data + hdr.header_size + mask_size;

    out.payload.resize(hdr.payload_len);
    if (hdr.masked)
    {
        // Copy then unmask in-place using widened/SIMD XOR
        std::memcpy(out.payload.data(), payload_start, hdr.payload_len);
        uint32_t mask32;
        std::memcpy(&mask32, data + hdr.header_size, 4);
        ws_unmask_payload(out.payload.data(), hdr.payload_len, mask32);
    }
    else
    {
        std::memcpy(out.payload.data(), payload_start, hdr.payload_len);
    }

    out.consumed = total;
    return true;
}

// Zero-alloc frame view -- points into the (now unmasked) input buffer
struct ws_frame_view
{
    uint8_t opcode;
    const char* payload_ptr;
    size_t payload_len;
    size_t consumed;
};

// In-place unmask parse -- modifies data buffer, sets view pointers into it.
// Uses SIMD (AVX2/SSE2) or uint64_t-widened XOR for fast unmasking.
inline bool ws_parse_frame_inplace(char* data, size_t len, ws_frame_view& out)
{
    ws_header hdr;
    if (!ws_parse_header(data, len, hdr))
        return false;

    out.opcode = hdr.opcode;
    size_t mask_size = hdr.masked ? 4 : 0;
    size_t total = hdr.header_size + mask_size + hdr.payload_len;
    char* payload_start = data + hdr.header_size + mask_size;

    if (hdr.masked)
    {
        uint32_t mask32;
        std::memcpy(&mask32, data + hdr.header_size, 4);
        ws_unmask_payload(payload_start, hdr.payload_len, mask32);
    }

    out.payload_ptr = payload_start;
    out.payload_len = hdr.payload_len;
    out.consumed = total;
    return true;
}

// ─── Append-to-buffer variants (zero intermediate allocation) ───

// Append text frame directly into buf (no intermediate allocation)
inline void ws_frame_text_into(std::string& buf, std::string_view payload)
{
    char hdr[14];
    int hdr_len = ws_write_header(hdr, 0x81, payload.size());

    size_t off = buf.size();
    buf.resize(off + static_cast<size_t>(hdr_len) + payload.size());
    std::memcpy(&buf[off], hdr, static_cast<size_t>(hdr_len));
    std::memcpy(&buf[off + hdr_len], payload.data(), payload.size());
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
    buf.resize(off + 4);
    std::memcpy(&buf[off], WS_CLOSE_FRAME_DATA, 4);
}

// Compute Sec-WebSocket-Accept and append to buf (no intermediate string).
// Uses EVP_Digest (single-call, non-deprecated) instead of SHA_CTX.
inline void ws_accept_key_into(std::string& buf, std::string_view client_key)
{
    constexpr size_t STACK_LIMIT = 92;
    unsigned char sha1_hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    if (client_key.size() <= STACK_LIMIT)
    {
        char combined[128];
        std::memcpy(combined, client_key.data(), client_key.size());
        std::memcpy(combined + client_key.size(), WS_GUID, 36);
        EVP_Digest(combined, client_key.size() + 36, sha1_hash, &hash_len,
                   ws_sha1_md(), nullptr);
    }
    else
    {
        std::string combined;
        combined.reserve(client_key.size() + 36);
        combined.append(client_key);
        combined.append(WS_GUID, 36);
        EVP_Digest(combined.data(), combined.size(), sha1_hash, &hash_len,
                   ws_sha1_md(), nullptr);
    }

    char b64[32];
    EVP_EncodeBlock(reinterpret_cast<unsigned char*>(b64), sha1_hash, static_cast<int>(hash_len));
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

// ─── Broadcast helpers (encode once, share across all clients) ───

// Create a pre-encoded WS text frame as a shared_ptr for broadcast.
// Encodes the frame once; all recipients share the same buffer (zero-copy on send).
inline std::shared_ptr<const std::string> ws_frame_text_shared(std::string_view payload)
{
    char hdr[14];
    int hdr_len = ws_write_header(hdr, 0x81, payload.size());

    auto frame = std::make_shared<std::string>();
    frame->resize(static_cast<size_t>(hdr_len) + payload.size());
    std::memcpy(frame->data(), hdr, static_cast<size_t>(hdr_len));
    std::memcpy(frame->data() + hdr_len, payload.data(), payload.size());
    return frame;
}

// Create a pre-encoded WS pong frame as a shared_ptr
inline std::shared_ptr<const std::string> ws_frame_pong_shared(std::string_view payload)
{
    if (payload.size() > 125)
        payload = payload.substr(0, 125);
    auto frame = std::make_shared<std::string>();
    frame->resize(2 + payload.size());
    (*frame)[0] = static_cast<char>(0x80 | WS_OP_PONG);
    (*frame)[1] = static_cast<char>(payload.size());
    if (!payload.empty())
        std::memcpy(frame->data() + 2, payload.data(), payload.size());
    return frame;
}

// Pre-computed close frame shared_ptr (singleton, never reallocated)
inline const std::shared_ptr<const std::string>& ws_frame_close_shared()
{
    static const auto frame = std::make_shared<const std::string>(WS_CLOSE_FRAME_DATA, 4);
    return frame;
}
