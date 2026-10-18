#include "base64.h"

#include <cstdint>

namespace socketley
{

namespace
{

constexpr char std_digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr char url_digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

struct alphabet
{
    int8_t v[256];
};

constexpr alphabet make_alphabet(const char* digits)
{
    alphabet a{};
    for (int c = 0; c < 256; ++c)
        a.v[c] = -1;
    for (int i = 0; i < 64; ++i)
        a.v[static_cast<unsigned char>(digits[i])] = static_cast<int8_t>(i);
    return a;
}

std::string encode_with(std::string_view in, const char* digits, bool pad)
{
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    const auto* p = reinterpret_cast<const unsigned char*>(in.data());
    size_t i = 0;
    for (; i + 3 <= in.size(); i += 3)
    {
        const uint32_t v = uint32_t(p[i]) << 16 | uint32_t(p[i + 1]) << 8 | p[i + 2];
        out.push_back(digits[v >> 18]);
        out.push_back(digits[(v >> 12) & 63]);
        out.push_back(digits[(v >> 6) & 63]);
        out.push_back(digits[v & 63]);
    }
    if (const size_t rest = in.size() - i; rest > 0)
    {
        uint32_t v = uint32_t(p[i]) << 16;
        if (rest == 2)
            v |= uint32_t(p[i + 1]) << 8;
        out.push_back(digits[v >> 18]);
        out.push_back(digits[(v >> 12) & 63]);
        if (rest == 2)
            out.push_back(digits[(v >> 6) & 63]);
        if (pad)
            out.append(rest == 2 ? 1 : 2, '=');
    }
    return out;
}

// The bytes of `in` in digits of `a`, refusing every other spelling of them: a stray length, a foreign character,
// and set bits below the last byte, which no encoder writes.
bool decode_with(std::string_view in, const alphabet& a, std::string& out)
{
    out.clear();
    if (in.size() % 4 == 1)
        return false;
    out.reserve(in.size() / 4 * 3 + 2);
    uint32_t acc = 0;
    int bits = 0;
    for (const char c : in)
    {
        const int v = a.v[static_cast<unsigned char>(c)];
        if (v < 0)
        {
            out.clear();
            return false;
        }
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            out.push_back(static_cast<char>((acc >> bits) & 0xFF));
        }
    }
    if ((acc & ((1u << bits) - 1)) != 0)
    {
        out.clear();
        return false;
    }
    return true;
}

constexpr alphabet std_alphabet = make_alphabet(std_digits);
constexpr alphabet url_alphabet = make_alphabet(url_digits);

} // namespace

namespace base64
{

std::string encode(std::string_view in)
{
    return encode_with(in, std_digits, true);
}

bool decode(std::string_view in, std::string& out)
{
    // Padded to whole quanta, as every encoder writes it, with no '=' but at the end.
    if (in.size() % 4 != 0)
    {
        out.clear();
        return false;
    }
    size_t pad = 0;
    while (pad < 2 && pad < in.size() && in[in.size() - 1 - pad] == '=')
        ++pad;
    return decode_with(in.substr(0, in.size() - pad), std_alphabet, out);
}

} // namespace base64

namespace base64url
{

std::string encode(std::string_view in)
{
    return encode_with(in, url_digits, false);
}

bool decode(std::string_view in, std::string& out)
{
    return decode_with(in, url_alphabet, out);
}

} // namespace base64url

} // namespace socketley
