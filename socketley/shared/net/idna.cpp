#include "idna.h"

#include <algorithm>
#include <cstdint>
#include <vector>

#include "../util/ascii.h"

namespace socketley::idna
{

namespace
{

// The code points of `s`, false where it is not UTF-8.
bool code_points(std::string_view s, std::vector<uint32_t>& out)
{
    for (size_t i = 0; i < s.size();)
    {
        const auto c = static_cast<unsigned char>(s[i]);
        size_t n = 0;
        uint32_t cp = 0;
        if (c < 0x80)
        {
            n = 1;
            cp = c;
        }
        else if (c >= 0xC2 && c < 0xE0)
        {
            n = 2;
            cp = c & 0x1F;
        }
        else if (c >= 0xE0 && c < 0xF0)
        {
            n = 3;
            cp = c & 0x0F;
        }
        else if (c >= 0xF0 && c < 0xF5)
        {
            n = 4;
            cp = c & 0x07;
        }
        else
            return false;
        if (i + n > s.size())
            return false;
        for (size_t k = 1; k < n; ++k)
        {
            const auto b = static_cast<unsigned char>(s[i + k]);
            if ((b & 0xC0) != 0x80)
                return false;
            cp = (cp << 6) | (b & 0x3F);
        }
        if ((n == 3 && cp < 0x800) || (n == 4 && (cp < 0x10000 || cp > 0x10FFFF)) || (cp >= 0xD800 && cp < 0xE000))
            return false;
        // ASCII in lower case, as every label of a name compares.
        if (cp >= 'A' && cp <= 'Z')
            cp += 'a' - 'A';
        out.push_back(cp);
        i += n;
    }
    return true;
}

char digit(uint32_t d)
{
    return static_cast<char>(d < 26 ? 'a' + d : '0' + (d - 26));
}

uint32_t adapt(uint32_t delta, uint32_t points, bool first)
{
    delta = first ? delta / 700 : delta / 2;
    delta += delta / points;
    uint32_t k = 0;
    while (delta > ((36 - 1) * 26) / 2)
    {
        delta /= 36 - 1;
        k += 36;
    }
    return k + (36 * delta) / (delta + 38);
}

// RFC 3492 6.3, with its base 36, tmin 1, tmax 26, skew 38, damp 700, initial bias 72 and n 128.
bool punycode(const std::vector<uint32_t>& in, std::string& out)
{
    uint32_t n = 128, delta = 0, bias = 72;
    size_t h = 0;
    for (const uint32_t c : in)
        if (c < 0x80)
        {
            out += static_cast<char>(c);
            ++h;
        }
    const size_t b = h;
    if (b > 0)
        out += '-';
    while (h < in.size())
    {
        uint32_t m = UINT32_MAX;
        for (const uint32_t c : in)
            if (c >= n && c < m)
                m = c;
        if (static_cast<uint64_t>(m - n) * (h + 1) + delta > UINT32_MAX)
            return false;
        delta += (m - n) * static_cast<uint32_t>(h + 1);
        n = m;
        for (const uint32_t c : in)
        {
            if (c < n && ++delta == 0)
                return false;
            if (c != n)
                continue;
            uint32_t q = delta;
            for (uint32_t k = 36;; k += 36)
            {
                const uint32_t t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
                if (q < t)
                    break;
                out += digit(t + (q - t) % (36 - t));
                q = (q - t) / (36 - t);
            }
            out += digit(q);
            bias = adapt(delta, static_cast<uint32_t>(h + 1), h == b);
            delta = 0;
            ++h;
        }
        ++delta;
        ++n;
    }
    return true;
}

}   // namespace

std::string to_ascii(std::string_view name)
{
    std::string out;
    for (size_t at = 0; at <= name.size();)
    {
        const size_t dot = std::min(name.find('.', at), name.size());
        const std::string_view label = name.substr(at, dot - at);
        std::vector<uint32_t> cps;
        if (!code_points(label, cps))
            return {};
        std::string l;
        if (std::all_of(cps.begin(), cps.end(), [](uint32_t c) { return c < 0x80; }))
            for (const uint32_t c : cps)
                l += static_cast<char>(c);
        else if (l = "xn--"; !punycode(cps, l))
            return {};
        if (l.size() > 63)
            return {};
        out += l;
        if (dot == name.size())
            break;
        out += '.';
        at = dot + 1;
    }
    return out;
}

}   // namespace socketley::idna
