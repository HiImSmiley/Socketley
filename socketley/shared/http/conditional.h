#pragma once
// Conditional requests (RFC 9110 13): whether a request's preconditions hold against what a resource is now, asked in
// the order the RFC fixes, for every runtime that answers with a file or an object of its own.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <string_view>

#include "../persist/file_stamp.h"
#include "../util/text_list.h"

namespace socketley::http
{

// Whether `etag`, unquoted, is in an If-Match or If-None-Match list, compared weakly and with * matching any.
inline bool etag_list_matches(std::string_view list, std::string_view etag)
{
    const auto trim = [](std::string_view v) {
        while (!v.empty() && (v.front() == ' ' || v.front() == '\t'))
            v.remove_prefix(1);
        while (!v.empty() && (v.back() == ' ' || v.back() == '\t'))
            v.remove_suffix(1);
        return v;
    };
    while (!list.empty())
    {
        std::string_view one = trim(socketley::take_item(list));
        if (one.starts_with("W/"))
            one.remove_prefix(2);
        if (one.size() >= 2 && one.front() == '"' && one.back() == '"')
            one = one.substr(1, one.size() - 2);
        if (one == "*" || one == etag)
            return true;
    }
    return false;
}

// A file's entity tag, unquoted as evaluate() takes it: its inode, its modification to the nanosecond and its size,
// so a file moved in under the name with the old one's size and time (mv after touch -r) is not the client's copy.
inline std::string etag_of(const file_stamp& s)
{
    // The digits written here, as %llx would, where snprintf was a file answer's largest piece of its own work.
    char tag[3 * 16 + 2];
    char* p = tag;
    const auto hex = [&p](unsigned long long v)
    {
        char t[16];
        int n = 0;
        do
            t[n++] = "0123456789abcdef"[v & 15];
        while ((v >>= 4) != 0);
        while (n > 0)
            *p++ = t[--n];
    };
    hex(static_cast<unsigned long long>(s.ino));
    *p++ = '-';
    hex(static_cast<unsigned long long>(s.mtime_ns));
    *p++ = '-';
    hex(static_cast<unsigned long long>(s.size));
    return std::string(tag, static_cast<size_t>(p - tag));
}

// Mon, 02 Jan 2006 15:04:05 GMT, the HTTP date of the second `secs` since the epoch.
inline std::string http_date_of(int64_t secs)
{
    static constexpr const char* days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static constexpr const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                             "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    // The civil date of the day count, by the inverse of Hinnant's days_from_civil: gmtime_r takes the time zone lock
    // and snprintf parses its format, which was most of what a Last-Modified cost.
    {
        const int64_t day = secs >= 0 ? secs / 86400 : -((-secs + 86399) / 86400);
        const int64_t sod = secs - day * 86400;
        const int64_t z = day + 719468;
        const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
        const int64_t doe = z - era * 146097;
        const int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        const int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        const int64_t mp = (5 * doy + 2) / 153;
        const int64_t mday = doy - (153 * mp + 2) / 5 + 1;
        const int64_t mon = mp < 10 ? mp + 2 : mp - 10;
        const int64_t year = yoe + era * 400 + (mon < 2 ? 1 : 0);
        // Four digits, which is every year the format below writes without widening.
        if (year >= 0 && year <= 9999)
        {
            const int64_t wday = ((day % 7) + 11) % 7;
            char b[29];
            const auto two = [&b](int at, int64_t v)
            {
                b[at] = static_cast<char>('0' + v / 10);
                b[at + 1] = static_cast<char>('0' + v % 10);
            };
            std::memcpy(b, days[wday], 3);
            b[3] = ',';
            b[4] = ' ';
            two(5, mday);
            b[7] = ' ';
            std::memcpy(b + 8, months[mon], 3);
            b[11] = ' ';
            two(12, year / 100);
            two(14, year % 100);
            b[16] = ' ';
            two(17, sod / 3600);
            b[19] = ':';
            two(20, sod / 60 % 60);
            b[22] = ':';
            two(23, sod % 60);
            std::memcpy(b + 25, " GMT", 4);
            return std::string(b, sizeof b);
        }
    }
    const time_t t = static_cast<time_t>(secs);
    std::tm tm{};
    if (!::gmtime_r(&t, &tm))
        return {};
    char buf[64];
    const int n = std::snprintf(buf, sizeof buf, "%s, %02d %s %04lld %02d:%02d:%02d GMT", days[tm.tm_wday], tm.tm_mday,
                                months[tm.tm_mon], static_cast<long long>(tm.tm_year) + 1900, tm.tm_hour, tm.tm_min,
                                tm.tm_sec);
    return n > 0 ? std::string(buf, static_cast<size_t>(n)) : std::string();
}

// Seconds since the epoch of an HTTP date, or -1 when it is not one.
inline int64_t parse_http_date(std::string_view s)
{
    struct tm tm{};
    const std::string z(s);
    const char* end = ::strptime(z.c_str(), "%a, %d %b %Y %H:%M:%S GMT", &tm);
    // The whole of it, and no instant before 1970, which leaves -1 meaning only "not a date".
    if (!end || *end != '\0')
        return -1;
    const int64_t t = static_cast<int64_t>(::timegm(&tm));
    return t < 0 ? -1 : t;
}

enum class precondition { proceed, not_modified, failed };

// The four fields a read's preconditions are in, empty when the request has none.
struct conditions
{
    std::string_view if_match;
    std::string_view if_unmodified_since;
    std::string_view if_none_match;
    std::string_view if_modified_since;
};

// Whether a Range may be answered as asked (RFC 9110 13.1.5): no If-Range, or one naming this copy by its strong ETag
// or by a Last-Modified date the answer gave (`mtime_s` below zero when none was given); otherwise the whole file.
inline bool if_range_holds(std::string_view if_range, std::string_view etag, int64_t mtime_s)
{
    if (if_range.empty())
        return true;
    if (if_range.size() == etag.size() + 2 && if_range.front() == '"' && if_range.back() == '"')
        return if_range.substr(1, etag.size()) == etag;
    return mtime_s >= 0 && if_range.front() != 'W' && if_range.front() != '"' && parse_http_date(if_range) == mtime_s;
}

// RFC 9110 13.2.2 in the order it fixes: If-Match, If-Unmodified-Since, If-None-Match, If-Modified-Since.
inline precondition evaluate(const conditions& c, std::string_view etag, int64_t mtime_s)
{
    if (!c.if_match.empty())
    {
        if (!etag_list_matches(c.if_match, etag))
            return precondition::failed;
    }
    else if (!c.if_unmodified_since.empty())
    {
        const int64_t t = parse_http_date(c.if_unmodified_since);
        if (t >= 0 && mtime_s > t)
            return precondition::failed;
    }
    if (!c.if_none_match.empty())
    {
        if (etag_list_matches(c.if_none_match, etag))
            return precondition::not_modified;
    }
    else if (!c.if_modified_since.empty())
    {
        const int64_t t = parse_http_date(c.if_modified_since);
        if (t >= 0 && mtime_s <= t)
            return precondition::not_modified;
    }
    return precondition::proceed;
}

}   // namespace socketley::http
