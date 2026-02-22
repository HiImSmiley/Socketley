#pragma once
#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <charconv>

// RESP2 protocol encoder/decoder for Redis compatibility
// Auto-detect: first byte '*' = RESP mode, else plaintext

namespace resp {

// Safety limits to prevent resource exhaustion
constexpr int RESP_MAX_ARRAY_SIZE = 1024;
constexpr int RESP_MAX_BULK_LEN = 512 * 1024; // 512 KB

// ─── Zero-allocation encoding (appends directly to caller's buffer) ───

inline void encode_ok_into(std::string& buf)
{
    buf.append("+OK\r\n", 5);
}

inline void encode_null_into(std::string& buf)
{
    buf.append("$-1\r\n", 5);
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
    char tmp[24];
    auto [end, ec] = std::to_chars(tmp, tmp + sizeof(tmp), n);
    buf += ':';
    buf.append(tmp, static_cast<size_t>(end - tmp));
    buf.append("\r\n", 2);
}

inline void encode_bulk_into(std::string& buf, std::string_view str)
{
    char tmp[24];
    auto [end, ec] = std::to_chars(tmp, tmp + sizeof(tmp), str.size());
    buf += '$';
    buf.append(tmp, static_cast<size_t>(end - tmp));
    buf.append("\r\n", 2);
    buf.append(str.data(), str.size());
    buf.append("\r\n", 2);
}

inline void encode_array_header_into(std::string& buf, int n)
{
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

    if (buf.empty())
        return parse_result::incomplete;

    if (buf[0] != '*')
        return parse_result::error;

    // Find end of array count line
    size_t pos = buf.find("\r\n");
    if (pos == std::string_view::npos)
        return parse_result::incomplete;

    int count = 0;
    auto [ptr, ec] = std::from_chars(buf.data() + 1, buf.data() + pos, count);
    if (ec != std::errc{} || count < 0 || count > RESP_MAX_ARRAY_SIZE)
        return parse_result::error;

    size_t offset = pos + 2;

    for (int i = 0; i < count; i++)
    {
        if (offset >= buf.size())
            return parse_result::incomplete;

        if (buf[offset] != '$')
            return parse_result::error;

        size_t end = buf.find("\r\n", offset);
        if (end == std::string_view::npos)
            return parse_result::incomplete;

        int len = 0;
        auto [p2, e2] = std::from_chars(buf.data() + offset + 1, buf.data() + end, len);
        if (e2 != std::errc{} || len < 0 || len > RESP_MAX_BULK_LEN)
            return parse_result::error;

        offset = end + 2;

        if (offset + static_cast<size_t>(len) + 2 > buf.size())
            return parse_result::incomplete;

        args.emplace_back(buf.data() + offset, static_cast<size_t>(len));
        offset += static_cast<size_t>(len) + 2; // skip \r\n
    }

    consumed = offset;
    return parse_result::ok;
}

// Zero-allocation RESP parser: fills string_view array pointing into buf.
// args[] must have room for at least max_args entries.
// Safe to call in a tight loop — no heap allocations.
inline parse_result parse_message_views(std::string_view buf,
    std::string_view* args, int max_args, int& argc, size_t& consumed)
{
    argc = 0;
    consumed = 0;

    if (buf.empty())
        return parse_result::incomplete;

    if (buf[0] != '*')
        return parse_result::error;

    size_t pos = buf.find("\r\n");
    if (pos == std::string_view::npos)
        return parse_result::incomplete;

    int count = 0;
    auto [ptr, ec] = std::from_chars(buf.data() + 1, buf.data() + pos, count);
    if (ec != std::errc{} || count < 0 || count > RESP_MAX_ARRAY_SIZE || count > max_args)
        return parse_result::error;

    size_t offset = pos + 2;

    for (int i = 0; i < count; i++)
    {
        if (offset >= buf.size())
            return parse_result::incomplete;

        if (buf[offset] != '$')
            return parse_result::error;

        size_t end = buf.find("\r\n", offset);
        if (end == std::string_view::npos)
            return parse_result::incomplete;

        int len = 0;
        auto [p2, e2] = std::from_chars(buf.data() + offset + 1, buf.data() + end, len);
        if (e2 != std::errc{} || len < 0 || len > RESP_MAX_BULK_LEN)
            return parse_result::error;

        offset = end + 2;

        if (offset + static_cast<size_t>(len) + 2 > buf.size())
            return parse_result::incomplete;

        args[i] = std::string_view(buf.data() + offset, static_cast<size_t>(len));
        offset += static_cast<size_t>(len) + 2;
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
