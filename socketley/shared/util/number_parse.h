#pragma once
// A whole number read from the whole of a string or not at all: no sign it may not have, no space, nothing after it,
// nothing past its type's range.
#include <charconv>
#include <cstdlib>
#include <limits>
#include <optional>
#include <string_view>
#include <system_error>

namespace socketley
{

template <class T>
bool parse_whole(std::string_view s, T& out)
{
    const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), out);
    return ec == std::errc{} && end == s.data() + s.size();
}

// The whole number environment variable `name` holds, nullopt when it is unset, empty, anything but a whole number,
// or outside [lo, hi]: a typo in a unit file is then the default and never a number read off its front.
template <class T>
std::optional<T> getenv_whole(const char* name, T lo = std::numeric_limits<T>::min(),
                              T hi = std::numeric_limits<T>::max())
{
    const char* e = std::getenv(name);
    T v{};
    if (!e || !parse_whole(std::string_view(e), v) || v < lo || v > hi)
        return std::nullopt;
    return v;
}

}   // namespace socketley
