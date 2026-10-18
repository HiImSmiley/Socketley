#pragma once

#include <string>
#include <string_view>

// ASCII case, folded by range and never by the locale, for the protocol words, header names and keywords that are
// case-insensitive by their grammar.
namespace socketley::ascii
{

inline constexpr char lower(char c)
{
    return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
}

inline constexpr char upper(char c)
{
    return c >= 'a' && c <= 'z' ? static_cast<char>(c - 'a' + 'A') : c;
}

inline bool iequals(std::string_view a, std::string_view b)
{
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (lower(a[i]) != lower(b[i]))
            return false;
    return true;
}

inline void lower_in_place(std::string& s)
{
    for (char& c : s)
        c = lower(c);
}

} // namespace socketley::ascii
