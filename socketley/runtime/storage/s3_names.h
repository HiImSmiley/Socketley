#pragma once
// The small rules S3 states about names and their spellings on the wire: what a
// bucket may be called, how a key is percent-encoded, and the two time formats.
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <string_view>
#include "../../shared/http/url.h"

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

using socketley::http::hex_digit;
using socketley::http::percent_decode;
using socketley::http::url_keeps;

// S3's encoding-type=url keeps '/' unless told otherwise.
inline void url_encode_to(std::string& out, std::string_view in, bool keep_slash = true)
{
    socketley::http::url_encode_to(out, in, keep_slash);
}

inline std::string url_encode(std::string_view in, bool keep_slash = true)
{
    return socketley::http::url_encode(in, keep_slash);
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

// A UTC time in its fields, by arithmetic rather than gmtime_r, which takes the time zone lock.
struct utc_fields
{
    int64_t  year;
    unsigned month, day, hour, minute, second, weekday, milli;
};

inline utc_fields utc_of(int64_t ms)
{
    int64_t s = ms / 1000, milli = ms % 1000;
    if (milli < 0)
    {
        milli += 1000;
        --s;
    }
    int64_t days = s / 86400, rem = s % 86400;
    if (rem < 0)
    {
        rem += 86400;
        --days;
    }
    utc_fields f{};
    f.weekday = static_cast<unsigned>((days % 7 + 11) % 7);
    // Howard Hinnant's civil_from_days.
    const int64_t z   = days + 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const auto doe    = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp  = (5 * doy + 2) / 153;
    f.day    = doy - (153 * mp + 2) / 5 + 1;
    f.month  = mp < 10 ? mp + 3 : mp - 9;
    f.year   = static_cast<int64_t>(yoe) + era * 400 + (f.month <= 2);
    f.hour   = static_cast<unsigned>(rem / 3600);
    f.minute = static_cast<unsigned>(rem / 60 % 60);
    f.second = static_cast<unsigned>(rem % 60);
    f.milli  = static_cast<unsigned>(milli);
    return f;
}

inline void append_digits(std::string& out, uint64_t v, int width)
{
    char buf[24];
    int n = 0;
    do
    {
        buf[n++] = static_cast<char>('0' + v % 10);
        v /= 10;
    } while (v || n < width);
    while (n)
        out.push_back(buf[--n]);
}

inline void append_year(std::string& out, int64_t y)
{
    if (y < 0)
        out.push_back('-');
    append_digits(out, static_cast<uint64_t>(y < 0 ? -y : y), 4);
}

// The two digits of `v` (below 100) written at `p`.
inline char* put_two(char* p, unsigned v)
{
    p[0] = static_cast<char>('0' + v / 10);
    p[1] = static_cast<char>('0' + v % 10);
    return p + 2;
}

// 2006-01-02T15:04:05.000Z, what S3 writes into every XML timestamp, at `p`;
// room for 40 bytes, and the end of what was written comes back.
inline char* write_iso8601(char* p, int64_t ms)
{
    const utc_fields f = utc_of(ms);
    if (f.year < 0 || f.year > 9999)
    {
        std::string wide;
        append_year(wide, f.year);
        wide.push_back('-');
        append_digits(wide, f.month, 2);
        wide.push_back('-');
        append_digits(wide, f.day, 2);
        wide.push_back('T');
        append_digits(wide, f.hour, 2);
        wide.push_back(':');
        append_digits(wide, f.minute, 2);
        wide.push_back(':');
        append_digits(wide, f.second, 2);
        wide.push_back('.');
        append_digits(wide, f.milli, 3);
        wide.push_back('Z');
        std::memcpy(p, wide.data(), wide.size());
        return p + wide.size();
    }
    const auto year = static_cast<unsigned>(f.year);
    p = put_two(p, year / 100);
    p = put_two(p, year % 100);
    *p++ = '-';
    p = put_two(p, f.month);
    *p++ = '-';
    p = put_two(p, f.day);
    *p++ = 'T';
    p = put_two(p, f.hour);
    *p++ = ':';
    p = put_two(p, f.minute);
    *p++ = ':';
    p = put_two(p, f.second);
    *p++ = '.';
    *p++ = static_cast<char>('0' + f.milli / 100);
    p = put_two(p, f.milli % 100);
    *p++ = 'Z';
    return p;
}

inline void append_iso8601(std::string& out, int64_t ms)
{
    char buf[48];
    out.append(buf, static_cast<size_t>(write_iso8601(buf, ms) - buf));
}

inline std::string iso8601(int64_t ms)
{
    std::string out;
    out.reserve(24);
    append_iso8601(out, ms);
    return out;
}

// Mon, 02 Jan 2006 15:04:05 GMT, the HTTP date every header carries.
inline std::string http_date(int64_t ms)
{
    static constexpr std::string_view days[]   = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static constexpr std::string_view months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    const utc_fields f = utc_of(ms);
    std::string out;
    out.reserve(32);
    out += days[f.weekday];
    out += ", ";
    append_digits(out, f.day, 2);
    out.push_back(' ');
    out += months[f.month - 1];
    out.push_back(' ');
    append_year(out, f.year);
    out.push_back(' ');
    append_digits(out, f.hour, 2);
    out.push_back(':');
    append_digits(out, f.minute, 2);
    out.push_back(':');
    append_digits(out, f.second, 2);
    out += " GMT";
    return out;
}

inline int64_t days_from_civil(int64_t y, unsigned m, unsigned d)
{
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const auto yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

// YYYY-MM-DD, optionally with THH:MM:SS, a fraction and Z or +00:00; `midnight` says whether the time was 00:00:00.000.
inline bool parse_iso8601(std::string_view s, int64_t& ms, bool& midnight)
{
    auto num = [&](size_t at, size_t n, unsigned& v) -> bool
    {
        if (at + n > s.size())
            return false;
        v = 0;
        for (size_t i = at; i < at + n; ++i)
        {
            if (s[i] < '0' || s[i] > '9')
                return false;
            v = v * 10 + static_cast<unsigned>(s[i] - '0');
        }
        return true;
    };
    unsigned y = 0, mo = 0, d = 0, h = 0, mi = 0, se = 0;
    if (!num(0, 4, y) || s.size() < 10 || s[4] != '-' || !num(5, 2, mo) || s[7] != '-' || !num(8, 2, d))
        return false;
    static constexpr unsigned month_days[] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (mo < 1 || mo > 12 || d < 1 || d > month_days[mo - 1])
        return false;
    const bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    if (mo == 2 && d == 29 && !leap)
        return false;
    size_t at = 10;
    bool zero_fraction = true;
    int64_t offset_s = 0;
    if (at < s.size())
    {
        if (s[at] != 'T' || !num(at + 1, 2, h) || s.size() < at + 9 || s[at + 3] != ':' || !num(at + 4, 2, mi) ||
            s[at + 6] != ':' || !num(at + 7, 2, se) || h > 23 || mi > 59 || se > 59)
            return false;
        at += 9;
        if (at < s.size() && s[at] == '.')
        {
            ++at;
            const size_t from = at;
            while (at < s.size() && s[at] >= '0' && s[at] <= '9')
            {
                zero_fraction = zero_fraction && s[at] == '0';
                ++at;
            }
            if (at == from)
                return false;
        }
        // Z, nothing, or an offset from UTC as +hh:mm or -hh:mm, which the time is taken back by.
        const std::string_view zone = s.substr(at);
        if (zone.size() == 6 && (zone[0] == '+' || zone[0] == '-') && zone[3] == ':')
        {
            unsigned oh = 0, om = 0;
            if (!num(at + 1, 2, oh) || !num(at + 4, 2, om) || oh > 23 || om > 59)
                return false;
            offset_s = (zone[0] == '+' ? 1 : -1) * static_cast<int64_t>(oh * 3600 + om * 60);
        }
        else if (zone != "Z" && !zone.empty())
            return false;
    }
    const int64_t secs = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se - offset_s;
    ms = secs * 1000;
    midnight = secs % 86400 == 0 && zero_fraction;
    return true;
}

// Seconds since the epoch of an HTTP date, or -1 when it is not one.
inline int64_t parse_http_date(std::string_view s)
{
    struct tm tm{};
    const std::string z(s);
    const char* end = strptime(z.c_str(), "%a, %d %b %Y %H:%M:%S GMT", &tm);
    // The whole of it, and no instant before 1970, which leaves -1 meaning only "not a date".
    if (!end || *end != '\0')
        return -1;
    const int64_t t = static_cast<int64_t>(timegm(&tm));
    return t < 0 ? -1 : t;
}

}   // namespace socketley::storage
