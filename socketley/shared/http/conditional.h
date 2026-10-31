#pragma once
// Conditional requests (RFC 9110 13): whether a request's preconditions hold against what a resource is now, asked in
// the order the RFC fixes, for every runtime that answers with a file or an object of its own.

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <string>
#include <string_view>

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

// Mon, 02 Jan 2006 15:04:05 GMT, the HTTP date of the second `secs` since the epoch.
inline std::string http_date_of(int64_t secs)
{
    static constexpr const char* days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static constexpr const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                             "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
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
