#pragma once
// A JSON string, written: the quote, the backslash and every byte below 0x20 escaped -- \n, \r and \t by name, the
// rest as \u00xx -- and every other byte as it is, so whatever is handed in comes out a valid string of the same bytes.
#include <string>
#include <string_view>

namespace socketley::json
{

// The string's body, without its quotes, appended to `out`.
inline void escape_into(std::string& out, std::string_view s)
{
    static constexpr char hex[] = "0123456789abcdef";
    size_t from = 0;
    for (size_t i = 0; i < s.size(); ++i)
    {
        const auto u = static_cast<unsigned char>(s[i]);
        if (u >= 0x20 && u != '"' && u != '\\')
            continue;
        // The run before it as it is, then the byte escaped.
        out.append(s.data() + from, i - from);
        from = i + 1;
        if (u == '"' || u == '\\')
        {
            out += '\\';
            out += static_cast<char>(u);
        }
        else if (u == '\n')
            out += "\\n";
        else if (u == '\t')
            out += "\\t";
        else if (u == '\r')
            out += "\\r";
        else
        {
            const char esc[] = {'\\', 'u', '0', '0', hex[u >> 4], hex[u & 15]};
            out.append(esc, sizeof esc);
        }
    }
    out.append(s.data() + from, s.size() - from);
}

inline std::string escape(std::string_view s)
{
    std::string out;
    out.reserve(s.size() + 2);
    escape_into(out, s);
    return out;
}

// The string between its quotes, appended to `out`.
inline void quote_into(std::string& out, std::string_view s)
{
    out.reserve(out.size() + s.size() + 2);
    out += '"';
    escape_into(out, s);
    out += '"';
}

inline std::string quote(std::string_view s)
{
    std::string out;
    quote_into(out, s);
    return out;
}

}   // namespace socketley::json
