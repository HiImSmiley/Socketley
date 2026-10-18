#pragma once
// Percent-encoding as URLs, query strings and forms carry it: one set of bytes kept as they are (RFC 3986's unreserved
// set, and '/' where a path keeps it), one decoder whose answer to a malformed escape each caller names, and one walk
// over a query's name=value pairs.
#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace socketley::http
{

inline int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// What a '%' that is not followed by two hex digits means.
enum class bad_escape : uint8_t
{
    reject,   // the whole is no encoding
    keep,     // a literal '%', as SigV4 canonicalises it and a lenient path reader reads it
};

// %XX decoding into `out`; `plus_is_space` is a query's or a form's reading, never a path's.
inline bool percent_decode(std::string_view in, std::string& out, bool plus_is_space,
                           bad_escape bad = bad_escape::reject)
{
    out.clear();
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i)
    {
        const char c = in[i];
        if (c == '%')
        {
            const int hi = i + 2 < in.size() ? hex_digit(in[i + 1]) : -1;
            const int lo = hi >= 0 ? hex_digit(in[i + 2]) : -1;
            if (lo < 0)
            {
                if (bad == bad_escape::reject)
                    return false;
                out.push_back('%');
                continue;
            }
            out.push_back(static_cast<char>(hi * 16 + lo));
            i += 2;
        }
        else if (c == '+' && plus_is_space)
            out.push_back(' ');
        else
            out.push_back(c);
    }
    return true;
}

// The bytes url_encode keeps as they are: the unreserved set, and '/' when `keep_slash`.
inline bool url_keeps(unsigned char c, bool keep_slash)
{
    static constexpr auto table = []
    {
        std::array<bool, 256> t{};
        for (int i = 0; i < 256; ++i)
            t[static_cast<size_t>(i)] = (i >= '0' && i <= '9') || (i >= 'a' && i <= 'z') || (i >= 'A' && i <= 'Z') ||
                                        i == '-' || i == '_' || i == '.' || i == '~';
        return t;
    }();
    return table[c] || (keep_slash && c == '/');
}

// Every other byte as %XX, upper case, appended to `out`; byte for byte what SigV4 and S3's encoding-type=url write.
inline void url_encode_to(std::string& out, std::string_view in, bool keep_slash)
{
    static constexpr char digits[] = "0123456789ABCDEF";
    out.reserve(out.size() + in.size());
    size_t run = 0;
    for (size_t i = 0; i < in.size(); ++i)
    {
        const unsigned char c = static_cast<unsigned char>(in[i]);
        if (url_keeps(c, keep_slash))
            continue;
        out.append(in, run, i - run);
        const char esc[3] = {'%', digits[c >> 4], digits[c & 15]};
        out.append(esc, 3);
        run = i + 1;
    }
    out.append(in, run, in.size() - run);
}

inline std::string url_encode(std::string_view in, bool keep_slash)
{
    std::string out;
    url_encode_to(out, in, keep_slash);
    return out;
}

// Each name=value of a raw query, empty parts skipped, a name without '=' given an empty value; nothing decoded.
template <class F>
void for_each_pair(std::string_view q, F&& f)
{
    while (!q.empty())
    {
        const size_t amp = q.find('&');
        const std::string_view part = q.substr(0, amp);
        q = amp == std::string_view::npos ? std::string_view{} : q.substr(amp + 1);
        if (part.empty())
            continue;
        const size_t eq = part.find('=');
        if (eq == std::string_view::npos)
            f(part, std::string_view{});
        else
            f(part.substr(0, eq), part.substr(eq + 1));
    }
}

}   // namespace socketley::http
