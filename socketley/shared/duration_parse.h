#pragma once
#include <cstdint>
#include <string_view>
#include <charconv>

// One grammar for every flag that takes a duration: digits with at most one
// of the suffixes s, m, h, d, w, and bare digits stay seconds because that is
// what every duration flag has always meant.
enum class duration_parse : uint8_t
{
    ok,
    malformed,
    out_of_range,
};

// Whole seconds out rather than a chrono type, because every caller stores an
// integer count of seconds and would unwrap the type on the next line.
inline duration_parse parse_duration_seconds(std::string_view sv,
                                             uint64_t max_seconds,
                                             uint64_t& out)
{
    uint64_t per_unit = 1;
    if (!sv.empty())
    {
        // Lowercase only: `5M` reads as months everywhere else, and a guess
        // that is wrong by a factor of 43200 is worse than a refusal.
        switch (sv.back())
        {
            case 's': per_unit = 1;      sv.remove_suffix(1); break;
            case 'm': per_unit = 60;     sv.remove_suffix(1); break;
            case 'h': per_unit = 3600;   sv.remove_suffix(1); break;
            case 'd': per_unit = 86400;  sv.remove_suffix(1); break;
            case 'w': per_unit = 604800; sv.remove_suffix(1); break;
            default: break;
        }
    }

    // The whole string or nothing, like every parser in flag_handlers.h,
    // which also refuses sign, whitespace and fractions in one stroke.
    uint64_t count = 0;
    auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), count);
    if (ec == std::errc::result_out_of_range)
        return duration_parse::out_of_range;
    if (ec != std::errc{} || ptr != sv.data() + sv.size())
        return duration_parse::malformed;

    // Divide instead of multiply, so the overflow check cannot itself wrap.
    if (count > max_seconds / per_unit)
        return duration_parse::out_of_range;

    out = count * per_unit;
    return duration_parse::ok;
}
