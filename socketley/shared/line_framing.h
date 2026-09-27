#pragma once
// Newline framing over bytes wherever they lie, so a line can be handed on
// from the buffer it arrived in rather than from a copy of it.
#include <cstddef>
#include <cstring>
#include <string_view>

namespace socketley
{

// What for_each_line returns when `deliver` asked it to stop, in place of the
// offset just past the last newline it consumed.
inline constexpr size_t line_framing_stopped = static_cast<size_t>(-1);

// Each complete line in [data, data + len), '\r' stripped and empty ones
// skipped, goes to `deliver`, which returns false when the bytes may no longer
// be read, and the search starts at `search_from` because the caller knows the
// bytes before it hold no newline.
template <class Deliver>
inline size_t for_each_line(const char* data, size_t len, size_t search_from,
                            Deliver&& deliver)
{
    size_t start = 0;
    while (search_from < len)
    {
        const void* nl = std::memchr(data + search_from, '\n', len - search_from);
        if (!nl)
            break;
        const size_t pos = static_cast<size_t>(static_cast<const char*>(nl) - data);
        std::string_view line(data + start, pos - start);
        start = search_from = pos + 1;

        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (line.empty())
            continue;
        if (!deliver(line))
            return line_framing_stopped;
    }
    return start;
}

} // namespace socketley
