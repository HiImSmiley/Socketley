#pragma once

#include <string_view>

namespace socketley
{

// The item before the next `sep`, taken off the front of `list`, which is empty after the last one.
inline std::string_view take_item(std::string_view& list, char sep = ',')
{
    const size_t at = list.find(sep);
    const std::string_view item = list.substr(0, at);
    list = at == std::string_view::npos ? std::string_view{} : list.substr(at + 1);
    return item;
}

// `s` without the spaces and tabs around it.
inline std::string_view trim_blanks(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t'))
        s.remove_suffix(1);
    return s;
}

}   // namespace socketley
