#pragma once
// A whole number read from the whole of a string or not at all: no sign it may not have, no space, nothing after it,
// nothing past its type's range.
#include <charconv>
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

}   // namespace socketley
