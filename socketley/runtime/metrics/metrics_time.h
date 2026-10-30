#pragma once
// Times and durations as the Prometheus HTTP API writes and reads them: RFC 3339, unix seconds with a fraction, and
// its duration spelling of y, w, d, h, m, s and ms.
#include <charconv>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <string>
#include <string_view>

namespace socketley::metrics
{

// `ms` as 2026-10-30T12:00:00.123Z, the fraction only when there is one.
inline std::string format_rfc3339(int64_t ms)
{
    const time_t secs = static_cast<time_t>(ms >= 0 ? ms / 1000 : (ms - 999) / 1000);
    const int frac = static_cast<int>(ms - static_cast<int64_t>(secs) * 1000);
    struct tm tm{};
    gmtime_r(&secs, &tm);
    char buf[48];
    if (frac)
        std::snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900, tm.tm_mon + 1,
                      tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, frac);
    else
        std::snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02dZ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                      tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

// `ms` as Prometheus writes a duration: 30d, 1h30m, 10s, 500ms.
inline std::string format_duration_ms(int64_t ms)
{
    if (ms == 0)
        return "0s";
    std::string out;
    if (ms < 0)
    {
        out += '-';
        ms = -ms;
    }
    constexpr struct
    {
        int64_t ms;
        const char* unit;
    } units[] = {{365ll * 86400000, "y"}, {7ll * 86400000, "w"}, {86400000, "d"}, {3600000, "h"},
                 {60000, "m"},           {1000, "s"},           {1, "ms"}};
    for (const auto& u : units)
        if (ms >= u.ms)
        {
            out += std::to_string(ms / u.ms);
            out += u.unit;
            ms %= u.ms;
        }
    return out;
}

// Unix seconds with an optional fraction, or RFC 3339, into milliseconds; false when it is neither.
inline bool parse_api_time(std::string_view s, int64_t& ms)
{
    if (s.empty())
        return false;
    double d = 0;
    if (const auto r = std::from_chars(s.data(), s.data() + s.size(), d);
        r.ec == std::errc() && r.ptr == s.data() + s.size())
    {
        if (!std::isfinite(d) || std::fabs(d) > 9.0e12)
            return false;
        ms = static_cast<int64_t>(std::llround(d * 1000.0));
        return true;
    }
    // YYYY-MM-DDTHH:MM:SS[.frac](Z|+HH:MM|-HH:MM)
    const auto num = [&](size_t at, size_t len, int& out) {
        if (at + len > s.size())
            return false;
        const auto r = std::from_chars(s.data() + at, s.data() + at + len, out);
        return r.ec == std::errc() && r.ptr == s.data() + at + len;
    };
    struct tm tm{};
    int year = 0, mon = 0, day = 0, hour = 0, min = 0, sec = 0;
    if (s.size() < 20 || !num(0, 4, year) || s[4] != '-' || !num(5, 2, mon) || s[7] != '-' || !num(8, 2, day) ||
        (s[10] != 'T' && s[10] != 't' && s[10] != ' ') || !num(11, 2, hour) || s[13] != ':' || !num(14, 2, min) ||
        s[16] != ':' || !num(17, 2, sec))
        return false;
    size_t at = 19;
    int64_t frac_ms = 0;
    if (at < s.size() && s[at] == '.')
    {
        ++at;
        int64_t scale = 100;
        const size_t from = at;
        while (at < s.size() && s[at] >= '0' && s[at] <= '9')
        {
            frac_ms += (s[at] - '0') * scale;
            scale /= 10;
            ++at;
        }
        if (at == from)
            return false;
    }
    int64_t offset_s = 0;
    if (at < s.size() && (s[at] == 'Z' || s[at] == 'z') && at + 1 == s.size())
        ++at;
    else if (at < s.size() && (s[at] == '+' || s[at] == '-') && at + 6 == s.size() && s[at + 3] == ':')
    {
        int oh = 0, om = 0;
        if (!num(at + 1, 2, oh) || !num(at + 4, 2, om))
            return false;
        offset_s = (oh * 3600 + om * 60) * (s[at] == '+' ? 1 : -1);
        at += 6;
    }
    else
        return false;
    if (mon < 1 || mon > 12 || day < 1 || day > 31 || hour > 23 || min > 59 || sec > 60)
        return false;
    tm.tm_year = year - 1900;
    tm.tm_mon = mon - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = min;
    tm.tm_sec = sec;
    const time_t t = timegm(&tm);
    ms = (static_cast<int64_t>(t) - offset_s) * 1000 + frac_ms;
    return true;
}

}   // namespace socketley::metrics
