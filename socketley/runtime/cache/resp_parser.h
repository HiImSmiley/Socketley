#pragma once
#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <cstring>
#include <charconv>

// RESP2 protocol encoder/decoder for Redis compatibility
// Auto-detect: first byte '*' = RESP mode, else plaintext

namespace resp {

// Safety limits to prevent resource exhaustion
constexpr int RESP_MAX_ARRAY_SIZE = 1024;
constexpr int RESP_MAX_BULK_LEN = 512 * 1024; // 512 KB

// ─── Fast \r\n scanner — avoids std::string_view::find overhead ───
// Uses memchr for the first byte, then checks second byte. Faster than
// two-byte search on short buffers because memchr is SIMD-optimized.
inline const char* find_crlf(const char* data, size_t len) noexcept
{
    const char* end = data + len;
    while (true)
    {
        const char* p = static_cast<const char*>(std::memchr(data, '\r', static_cast<size_t>(end - data)));
        if (__builtin_expect(!p || p + 1 >= end, 0))
            return nullptr;
        if (__builtin_expect(p[1] == '\n', 1))
            return p;
        data = p + 1;
    }
}

// ─── Pre-computed constant responses (SSO-friendly, <= 22 bytes) ───
// These are used by inline fast-paths to avoid any encode overhead.
static constexpr const char RESP_OK[]     = "+OK\r\n";
static constexpr const char RESP_NULL[]   = "$-1\r\n";
static constexpr const char RESP_PONG[]   = "+PONG\r\n";
static constexpr const char RESP_ZERO[]   = ":0\r\n";
static constexpr const char RESP_ONE[]    = ":1\r\n";
static constexpr const char RESP_NEG1[]   = ":-1\r\n";
static constexpr const char RESP_NEG2[]   = ":-2\r\n";

// ─── Zero-allocation encoding (appends directly to caller's buffer) ───

inline void encode_ok_into(std::string& buf)
{
    buf.append(RESP_OK, 5);
}

inline void encode_null_into(std::string& buf)
{
    buf.append(RESP_NULL, 5);
}

inline void encode_error_into(std::string& buf, std::string_view msg)
{
    buf.append("-ERR ", 5);
    buf.append(msg.data(), msg.size());
    buf.append("\r\n", 2);
}

inline void encode_simple_into(std::string& buf, std::string_view msg)
{
    buf += '+';
    buf.append(msg.data(), msg.size());
    buf.append("\r\n", 2);
}

inline void encode_integer_into(std::string& buf, int64_t n)
{
    // Fast-path for common small integers (avoids to_chars entirely)
    if (__builtin_expect(n >= -2 && n <= 1, 1))
    {
        switch (n)
        {
            case 0:  buf.append(RESP_ZERO, 4); return;
            case 1:  buf.append(RESP_ONE, 4); return;
            case -1: buf.append(RESP_NEG1, 5); return;
            case -2: buf.append(RESP_NEG2, 5); return;
        }
    }
    char tmp[24];
    auto [end, ec] = std::to_chars(tmp, tmp + sizeof(tmp), n);
    buf += ':';
    buf.append(tmp, static_cast<size_t>(end - tmp));
    buf.append("\r\n", 2);
}

inline void encode_bulk_into(std::string& buf, std::string_view str)
{
    // Fast-path for tiny values (most cache values in benchmarks are small).
    // Avoid to_chars for single-digit lengths (0-9), which covers values up to 9 bytes.
    size_t sz = str.size();
    if (__builtin_expect(sz <= 9, 1))
    {
        char hdr[4] = { '$', static_cast<char>('0' + sz), '\r', '\n' };
        buf.append(hdr, 4);
        buf.append(str.data(), sz);
        buf.append("\r\n", 2);
        return;
    }
    char tmp[24];
    auto [end, ec] = std::to_chars(tmp, tmp + sizeof(tmp), sz);
    buf += '$';
    buf.append(tmp, static_cast<size_t>(end - tmp));
    buf.append("\r\n", 2);
    buf.append(str.data(), sz);
    buf.append("\r\n", 2);
}

inline void encode_array_header_into(std::string& buf, int n)
{
    // Fast-path for single-digit array sizes (0-9)
    if (__builtin_expect(n >= 0 && n <= 9, 1))
    {
        char hdr[4] = { '*', static_cast<char>('0' + n), '\r', '\n' };
        buf.append(hdr, 4);
        return;
    }
    char tmp[16];
    auto [end, ec] = std::to_chars(tmp, tmp + sizeof(tmp), n);
    buf += '*';
    buf.append(tmp, static_cast<size_t>(end - tmp));
    buf.append("\r\n", 2);
}

// ─── Allocating encoding (kept for use in execute() / tests) ───

inline std::string encode_ok()
{
    return "+OK\r\n";
}

inline std::string encode_error(std::string_view msg)
{
    std::string out;
    out.reserve(5 + msg.size());
    out += "-ERR ";
    out.append(msg.data(), msg.size());
    out += "\r\n";
    return out;
}

inline std::string encode_integer(int64_t n)
{
    std::string out = ":";
    out += std::to_string(n);
    out += "\r\n";
    return out;
}

inline std::string encode_bulk(std::string_view str)
{
    std::string out = "$";
    out += std::to_string(str.size());
    out += "\r\n";
    out.append(str.data(), str.size());
    out += "\r\n";
    return out;
}

inline std::string encode_null()
{
    return "$-1\r\n";
}

inline std::string encode_array_header(int n)
{
    std::string out = "*";
    out += std::to_string(n);
    out += "\r\n";
    return out;
}

inline std::string encode_simple(std::string_view msg)
{
    std::string out = "+";
    out.append(msg.data(), msg.size());
    out += "\r\n";
    return out;
}

// ─── Decoding ───

enum class parse_result { ok, incomplete, error };

// Parse a single RESP message from partial buffer.
// Returns parse_result::ok and fills `args` with extracted strings.
// `consumed` is set to how many bytes were consumed from `buf`.
inline parse_result parse_message(std::string_view buf, std::vector<std::string>& args, size_t& consumed)
{
    args.clear();
    consumed = 0;

    const char* data = buf.data();
    size_t sz = buf.size();

    if (__builtin_expect(sz == 0, 0))
        return parse_result::incomplete;

    if (__builtin_expect(data[0] != '*', 0))
        return parse_result::error;

    const char* crlf = find_crlf(data + 1, sz - 1);
    if (__builtin_expect(!crlf, 0))
        return parse_result::incomplete;

    int count = 0;
    auto [ptr, ec] = std::from_chars(data + 1, crlf, count);
    if (ec != std::errc{} || count < 0 || count > RESP_MAX_ARRAY_SIZE)
        return parse_result::error;

    size_t offset = static_cast<size_t>(crlf - data) + 2;

    for (int i = 0; i < count; i++)
    {
        if (offset >= sz)
            return parse_result::incomplete;

        if (data[offset] != '$')
            return parse_result::error;

        const char* end_crlf = find_crlf(data + offset + 1, sz - offset - 1);
        if (!end_crlf)
            return parse_result::incomplete;

        int len = 0;
        auto [p2, e2] = std::from_chars(data + offset + 1, end_crlf, len);
        if (e2 != std::errc{} || len < 0 || len > RESP_MAX_BULK_LEN)
            return parse_result::error;

        offset = static_cast<size_t>(end_crlf - data) + 2;

        if (offset + static_cast<size_t>(len) + 2 > sz)
            return parse_result::incomplete;

        args.emplace_back(data + offset, static_cast<size_t>(len));
        offset += static_cast<size_t>(len) + 2;
    }

    consumed = offset;
    return parse_result::ok;
}

// Zero-allocation RESP parser: fills string_view array pointing into buf.
// args[] must have room for at least max_args entries.
// Safe to call in a tight loop — no heap allocations.
// Uses find_crlf() for SIMD-accelerated \r\n scanning.
inline parse_result parse_message_views(std::string_view buf,
    std::string_view* args, int max_args, int& argc, size_t& consumed)
{
    argc = 0;
    consumed = 0;

    const char* data = buf.data();
    size_t sz = buf.size();

    if (__builtin_expect(sz == 0, 0))
        return parse_result::incomplete;

    if (__builtin_expect(data[0] != '*', 0))
        return parse_result::error;

    int count = 0;
    size_t offset;

    // Fast-path: single-digit array count "*N\r\n" (covers 1-9 args — the common case)
    if (__builtin_expect(sz >= 4 && data[1] >= '1' && data[1] <= '9' && data[2] == '\r' && data[3] == '\n', 1))
    {
        count = data[1] - '0';
        offset = 4;
    }
    else
    {
        const char* crlf = find_crlf(data + 1, sz - 1);
        if (__builtin_expect(!crlf, 0))
            return parse_result::incomplete;

        auto [ptr, ec] = std::from_chars(data + 1, crlf, count);
        if (__builtin_expect(ec != std::errc{} || count < 0 || count > RESP_MAX_ARRAY_SIZE, 0))
            return parse_result::error;

        offset = static_cast<size_t>(crlf - data) + 2;
    }

    if (__builtin_expect(count > max_args, 0))
        return parse_result::error;

    for (int i = 0; i < count; i++)
    {
        if (__builtin_expect(offset + 4 > sz, 0))  // minimum: $N\r\n
            return parse_result::incomplete;

        if (__builtin_expect(data[offset] != '$', 0))
            return parse_result::error;

        // Fast-path for single-digit bulk lengths (0-9): "$N\r\n" is 4 bytes.
        // This covers SET/GET/DEL key/value args up to 9 bytes — the common case.
        char d = data[offset + 1];
        if (__builtin_expect(d >= '0' && d <= '9' && data[offset + 2] == '\r' && data[offset + 3] == '\n', 1))
        {
            int len = d - '0';
            offset += 4;  // skip "$N\r\n"
            if (__builtin_expect(offset + static_cast<size_t>(len) + 2 > sz, 0))
                return parse_result::incomplete;
            args[i] = std::string_view(data + offset, static_cast<size_t>(len));
            offset += static_cast<size_t>(len) + 2;
        }
        else
        {
            // Slow path: multi-digit or negative length
            const char* end_crlf = find_crlf(data + offset + 1, sz - offset - 1);
            if (__builtin_expect(!end_crlf, 0))
                return parse_result::incomplete;

            int len = 0;
            auto [p2, e2] = std::from_chars(data + offset + 1, end_crlf, len);
            if (__builtin_expect(e2 != std::errc{} || len < 0 || len > RESP_MAX_BULK_LEN, 0))
                return parse_result::error;

            offset = static_cast<size_t>(end_crlf - data) + 2;

            if (__builtin_expect(offset + static_cast<size_t>(len) + 2 > sz, 0))
                return parse_result::incomplete;

            args[i] = std::string_view(data + offset, static_cast<size_t>(len));
            offset += static_cast<size_t>(len) + 2;
        }
    }

    argc = count;
    consumed = offset;
    return parse_result::ok;
}

// Convert uppercase Redis command to lowercase for FNV-1a dispatch
inline void to_lower(std::string& s)
{
    for (auto& c : s)
    {
        if (c >= 'A' && c <= 'Z')
            c += 32;
    }
}

} // namespace resp
