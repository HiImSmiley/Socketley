#pragma once
// The small rules S3 states about names and their spellings on the wire: what a
// bucket may be called, how a key is percent-encoded, and the two time formats.
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <string>
#include <string_view>

namespace socketley::storage
{

// The bucket naming rules of the S3 documentation, stated as the subset that
// can be checked from the name alone.
inline bool valid_bucket_name(std::string_view n)
{
    if (n.size() < 3 || n.size() > 63)
        return false;
    for (char c : n)
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.'))
            return false;
    const auto alnum = [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'); };
    if (!alnum(n.front()) || !alnum(n.back()))
        return false;
    if (n.find("..") != std::string_view::npos || n.find(".-") != std::string_view::npos ||
        n.find("-.") != std::string_view::npos)
        return false;
    // Not an IPv4 address.
    {
        int dots = 0;
        bool digits_only = true;
        for (char c : n)
        {
            if (c == '.') ++dots;
            else if (c < '0' || c > '9') digits_only = false;
        }
        if (dots == 3 && digits_only)
            return false;
    }
    // Reserved prefixes and suffixes.
    if (n.starts_with("xn--") || n.starts_with("sthree-") || n.starts_with("amzn-s3-demo-") ||
        n.ends_with("-s3alias") || n.ends_with("--ol-s3") || n.ends_with(".mrap") ||
        n.ends_with("--x-s3"))
        return false;
    return true;
}

inline int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// %XX decoding, false on a malformed escape; `plus_is_space` is the query
// string's reading and never the path's.
inline bool percent_decode(std::string_view in, std::string& out, bool plus_is_space)
{
    out.clear();
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i)
    {
        const char c = in[i];
        if (c == '%')
        {
            if (i + 2 >= in.size())
                return false;
            const int hi = hex_digit(in[i + 1]);
            const int lo = hex_digit(in[i + 2]);
            if (hi < 0 || lo < 0)
                return false;
            out.push_back(static_cast<char>(hi * 16 + lo));
            i += 2;
        }
        else if (c == '+' && plus_is_space)
            out.push_back(' ');
        else
            out.push_back(c);
    }
    return true;
}

// The encoding `encoding-type=url` asks for in a listing: everything but the
// unreserved set and '/' is escaped.
inline std::string url_encode(std::string_view in, bool keep_slash = true)
{
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(in.size());
    for (unsigned char c : in)
    {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' ||
            (keep_slash && c == '/'))
            out.push_back(static_cast<char>(c));
        else
        {
            out.push_back('%');
            out.push_back(digits[c >> 4]);
            out.push_back(digits[c & 15]);
        }
    }
    return out;
}

inline std::string base64url_encode(std::string_view in)
{
    static constexpr char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    size_t i = 0;
    while (i + 2 < in.size())
    {
        const uint32_t v = (static_cast<uint8_t>(in[i]) << 16) |
                           (static_cast<uint8_t>(in[i + 1]) << 8) |
                            static_cast<uint8_t>(in[i + 2]);
        out.push_back(tbl[v >> 18]);
        out.push_back(tbl[(v >> 12) & 63]);
        out.push_back(tbl[(v >> 6) & 63]);
        out.push_back(tbl[v & 63]);
        i += 3;
    }
    if (i + 1 == in.size())
    {
        const uint32_t v = static_cast<uint8_t>(in[i]) << 16;
        out.push_back(tbl[v >> 18]);
        out.push_back(tbl[(v >> 12) & 63]);
    }
    else if (i + 2 == in.size())
    {
        const uint32_t v = (static_cast<uint8_t>(in[i]) << 16) |
                           (static_cast<uint8_t>(in[i + 1]) << 8);
        out.push_back(tbl[v >> 18]);
        out.push_back(tbl[(v >> 12) & 63]);
        out.push_back(tbl[(v >> 6) & 63]);
    }
    return out;
}

inline bool base64url_decode(std::string_view in, std::string& out)
{
    out.clear();
    uint32_t acc = 0;
    int bits = 0;
    for (char c : in)
    {
        int v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '-') v = 62;
        else if (c == '_') v = 63;
        else return false;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            out.push_back(static_cast<char>((acc >> bits) & 0xFF));
        }
    }
    return true;
}

// 2006-01-02T15:04:05.000Z, what S3 writes into every XML timestamp.
inline std::string iso8601(int64_t ms)
{
    const time_t s = static_cast<time_t>(ms / 1000);
    struct tm tm{};
    gmtime_r(&s, &tm);
    char buf[40];
    const size_t n = std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%S", &tm);
    std::string out(buf, n);
    char frac[8];
    std::snprintf(frac, sizeof frac, ".%03dZ", static_cast<int>(ms % 1000));
    out += frac;
    return out;
}

// Mon, 02 Jan 2006 15:04:05 GMT, the HTTP date every header carries.
inline std::string http_date(int64_t ms)
{
    const time_t s = static_cast<time_t>(ms / 1000);
    struct tm tm{};
    gmtime_r(&s, &tm);
    char buf[40];
    const size_t n = std::strftime(buf, sizeof buf, "%a, %d %b %Y %H:%M:%S GMT", &tm);
    return std::string(buf, n);
}

// Seconds since the epoch of an HTTP date, or -1 when it is not one.
inline int64_t parse_http_date(std::string_view s)
{
    struct tm tm{};
    const std::string z(s);
    const char* end = strptime(z.c_str(), "%a, %d %b %Y %H:%M:%S GMT", &tm);
    if (!end)
        return -1;
    return static_cast<int64_t>(timegm(&tm));
}

}   // namespace socketley::storage
