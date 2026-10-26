#include "imap_utf7.h"

#include <cstdint>
#include <vector>

namespace socketley::mail::imap_utf7
{

namespace
{

// RFC 2152's base64 with ',' for '/', as RFC 3501 5.1.3 has it.
constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

bool code_points(std::string_view s, std::vector<uint32_t>& out)
{
    for (size_t i = 0; i < s.size();)
    {
        const auto c = static_cast<unsigned char>(s[i]);
        const size_t n = c < 0x80 ? 1 : c >= 0xC2 && c < 0xE0 ? 2 : c >= 0xE0 && c < 0xF0 ? 3 : c >= 0xF0 && c < 0xF5 ? 4 : 0;
        if (n == 0 || i + n > s.size())
            return false;
        uint32_t cp = n == 1 ? c : n == 2 ? (c & 0x1F) : n == 3 ? (c & 0x0F) : (c & 0x07);
        for (size_t k = 1; k < n; ++k)
        {
            const auto b = static_cast<unsigned char>(s[i + k]);
            if ((b & 0xC0) != 0x80)
                return false;
            cp = (cp << 6) | (b & 0x3F);
        }
        if ((n == 3 && cp < 0x800) || (n == 4 && (cp < 0x10000 || cp > 0x10FFFF)) || (cp >= 0xD800 && cp < 0xE000))
            return false;
        out.push_back(cp);
        i += n;
    }
    return true;
}

void put_utf8(std::string& out, uint32_t cp)
{
    if (cp < 0x80)
        out += static_cast<char>(cp);
    else if (cp < 0x800)
    {
        out += static_cast<char>(0xC0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
    else if (cp < 0x10000)
    {
        out += static_cast<char>(0xE0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
    else
    {
        out += static_cast<char>(0xF0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

}   // namespace

std::string encode(std::string_view utf8)
{
    std::vector<uint32_t> cps;
    if (!code_points(utf8, cps))
        return {};
    std::string out;
    std::vector<uint16_t> run;
    const auto flush = [&] {
        if (run.empty())
            return;
        out += '&';
        uint32_t bits = 0;
        int have = 0;
        for (const uint16_t u : run)
        {
            bits = (bits << 16) | u;
            have += 16;
            while (have >= 6)
            {
                have -= 6;
                out += alphabet[(bits >> have) & 63];
            }
        }
        if (have > 0)
            out += alphabet[(bits << (6 - have)) & 63];
        out += '-';
        run.clear();
    };
    for (const uint32_t cp : cps)
    {
        if (cp >= 0x20 && cp < 0x7F)
        {
            flush();
            // The one printable that is itself escaped.
            out += cp == '&' ? std::string("&-") : std::string(1, static_cast<char>(cp));
            continue;
        }
        if (cp >= 0x10000)
        {
            const uint32_t v = cp - 0x10000;
            run.push_back(static_cast<uint16_t>(0xD800 | (v >> 10)));
            run.push_back(static_cast<uint16_t>(0xDC00 | (v & 0x3FF)));
        }
        else
            run.push_back(static_cast<uint16_t>(cp));
    }
    flush();
    return out;
}

std::string decode(std::string_view in)
{
    std::string out;
    for (size_t i = 0; i < in.size();)
    {
        const char c = in[i];
        if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) >= 0x7F)
            return {};
        if (c != '&')
        {
            out += c;
            ++i;
            continue;
        }
        const size_t end = in.find('-', i + 1);
        if (end == std::string_view::npos)
            return {};
        if (end == i + 1)
        {
            out += '&';
            i = end + 1;
            continue;
        }
        uint32_t bits = 0;
        int have = 0;
        uint16_t high = 0;
        for (size_t k = i + 1; k < end; ++k)
        {
            const size_t v = alphabet.find(in[k]);
            if (v == std::string_view::npos)
                return {};
            bits = (bits << 6) | static_cast<uint32_t>(v);
            have += 6;
            if (have >= 16)
            {
                have -= 16;
                const auto u = static_cast<uint16_t>((bits >> have) & 0xFFFF);
                if (high && (u < 0xDC00 || u >= 0xE000))
                    return {};
                if (u >= 0xD800 && u < 0xDC00)
                    high = u;
                else if (u >= 0xDC00 && u < 0xE000)
                {
                    if (!high)
                        return {};
                    put_utf8(out, 0x10000 + ((static_cast<uint32_t>(high) - 0xD800) << 10) + (u - 0xDC00));
                    high = 0;
                }
                else
                {
                    // A printable that should not have been encoded makes the name no valid one.
                    if (u >= 0x20 && u < 0x7F)
                        return {};
                    put_utf8(out, u);
                }
            }
        }
        if (high || have >= 6 || (bits & ((1u << have) - 1)) != 0)
            return {};
        i = end + 1;
    }
    return out;
}

}   // namespace socketley::mail::imap_utf7
