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

// `s` with each control character a terminal acts on, C0 but tab and newline, DEL and C1 as UTF-8 writes it, made a
// '?' and a CR before a newline dropped, so text another host sent can neither move the cursor nor show other text.
inline std::string printable(std::string_view s)
{
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i)
    {
        const auto c = static_cast<unsigned char>(s[i]);
        const int next = i + 1 < s.size() ? static_cast<unsigned char>(s[i + 1]) : -1;
        if (c == '\r' && next == '\n')
            continue;
        if (c == 0xC2 && next >= 0x80 && next <= 0x9F)
        {
            out += '?';
            ++i;
        }
        else
            out += (c < 0x20 && c != '\t' && c != '\n') || c == 0x7F ? '?' : s[i];
    }
    return out;
}

} // namespace socketley::ascii
