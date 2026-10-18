#pragma once
// Bytes as hex and back: lower case unless asked otherwise, and a decoder that takes an even run of hex digits or
// nothing.
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace socketley
{

inline int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

inline void hex_encode_to(std::string& out, const void* data, size_t n, bool upper = false)
{
    const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    const auto* p = static_cast<const uint8_t*>(data);
    const size_t at = out.size();
    out.resize(at + 2 * n);
    for (size_t i = 0; i < n; ++i)
    {
        out[at + 2 * i] = digits[p[i] >> 4];
        out[at + 2 * i + 1] = digits[p[i] & 15];
    }
}

inline std::string hex_encode(const void* data, size_t n, bool upper = false)
{
    std::string out;
    hex_encode_to(out, data, n, upper);
    return out;
}

inline std::string hex_encode(std::string_view bytes, bool upper = false)
{
    return hex_encode(bytes.data(), bytes.size(), upper);
}

// False, `out` empty, for an odd length or a byte that is no hex digit.
inline bool hex_decode(std::string_view h, std::string& out)
{
    out.clear();
    if (h.size() % 2)
        return false;
    out.reserve(h.size() / 2);
    for (size_t i = 0; i < h.size(); i += 2)
    {
        const int a = hex_digit(h[i]), b = hex_digit(h[i + 1]);
        if (a < 0 || b < 0)
        {
            out.clear();
            return false;
        }
        out.push_back(static_cast<char>(a << 4 | b));
    }
    return true;
}

}   // namespace socketley
