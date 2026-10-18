#pragma once
// A byte count as a flag or a file gives it: digits and an optional K, M or G of 1024s.
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>

// The whole string or nothing here too, with a checked multiplication, because
// `100MB` configured a cache to a hundred bytes and `17179869184G` wrapped to
// 0, which is documented as unlimited.
inline bool parse_size_suffix(std::string_view sv, size_t& out)
{
    if (sv.empty()) return false;
    size_t multiplier = 1;
    std::string_view num_part = sv;
    char last = sv.back();
    if (last == 'K' || last == 'k') { multiplier = 1024; num_part = sv.substr(0, sv.size()-1); }
    else if (last == 'M' || last == 'm') { multiplier = 1024*1024; num_part = sv.substr(0, sv.size()-1); }
    else if (last == 'G' || last == 'g') { multiplier = 1024ULL*1024*1024; num_part = sv.substr(0, sv.size()-1); }
    uint64_t val;
    auto [ptr, ec] = std::from_chars(num_part.data(), num_part.data() + num_part.size(), val);
    if (ec != std::errc{}) return false;

    // The whole of it, digits and one known suffix and nothing else.
    if (ptr != num_part.data() + num_part.size()) return false;

    // Checked before it is done, in size_t so the bound is the width the
    // caller stores into, because a check made afterwards would be
    // always-false here and real on a 32-bit build.
    static_assert(sizeof(size_t) >= sizeof(uint32_t),
                  "parse_size_suffix accumulates into size_t");
    if (val > static_cast<uint64_t>(std::numeric_limits<size_t>::max()) / multiplier)
        return false;

    out = static_cast<size_t>(val) * multiplier;
    return true;
}
