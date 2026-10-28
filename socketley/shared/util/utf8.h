#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace socketley::utf8
{

// Whether `s` is well-formed UTF-8: the shortest form only, and no surrogate or code point past U+10FFFF, as
// RFC 3629 allows.
inline bool valid(std::string_view s)
{
    for (size_t i = 0; i < s.size();)
    {
        const auto b = static_cast<uint8_t>(s[i]);
        const size_t n = b < 0x80 ? 1 : (b >> 5) == 6 ? 2 : (b >> 4) == 14 ? 3 : (b >> 3) == 30 ? 4 : 0;
        if (n == 0 || i + n > s.size())
            return false;
        uint32_t cp = n == 1 ? b : n == 2 ? (b & 0x1f) : n == 3 ? (b & 0x0f) : (b & 0x07);
        for (size_t k = 1; k < n; ++k)
        {
            if ((static_cast<uint8_t>(s[i + k]) & 0xc0) != 0x80)
                return false;
            cp = (cp << 6) | (static_cast<uint8_t>(s[i + k]) & 0x3f);
        }
        static constexpr uint32_t least[] = {0, 0, 0x80, 0x800, 0x10000};
        if (cp < least[n] || (cp >= 0xd800 && cp <= 0xdfff) || cp > 0x10ffff)
            return false;
        i += n;
    }
    return true;
}

}   // namespace socketley::utf8
