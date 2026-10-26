#pragma once
// A JSON document read strictly: the shortest UTF-8 forms only, no member named twice and a bounded depth, so a
// document is read here as whoever wrote it meant: a bucket policy, a db document, a provider's account snapshot.
#include <algorithm>
#include <charconv>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "json_escape.h"

namespace socketley::json
{

// A policy nests four deep, so anything far past that is not one.
inline constexpr int json_max_depth = 16;

struct jvalue
{
    enum class kind : uint8_t { null, boolean, number, string, array, object };
    kind k{kind::null};
    bool b{false};
    // A string's bytes, or a number's text.
    std::string s;
    std::vector<jvalue> items;
    std::vector<std::pair<std::string, jvalue>> members;

    // Defined once the type is whole, since clang sizes a pair holding one while it is still being declared.
    jvalue();
    jvalue(const jvalue&);
    jvalue(jvalue&&) noexcept;
    jvalue& operator=(const jvalue&);
    jvalue& operator=(jvalue&&) noexcept;
    ~jvalue();
};

inline jvalue::jvalue()                               = default;
inline jvalue::jvalue(const jvalue&)                  = default;
inline jvalue::jvalue(jvalue&&) noexcept              = default;
inline jvalue& jvalue::operator=(const jvalue&)       = default;
inline jvalue& jvalue::operator=(jvalue&&) noexcept   = default;
inline jvalue::~jvalue()                              = default;

// What a reader admits past a configuration document's rules, for a reader of data such as S3 Select's records.
struct json_policy
{
    int  max_depth{json_max_depth};
    bool object_root{true};
    bool unique_names{true};
    bool check_utf8{true};
};

class json_reader
{
public:
    explicit json_reader(std::string_view in, json_policy policy = {}) : m_in(in), m_policy(policy) {}

    bool document(jvalue& out)
    {
        // A value read into before would otherwise keep its members, and each read again would be named twice.
        out = jvalue{};
        ws();
        if (m_policy.object_root && (m_pos >= m_in.size() || m_in[m_pos] != '{'))
            return false;
        if (!value(out, 0))
            return false;
        ws();
        return m_pos == m_in.size();
    }

private:
    void ws()
    {
        while (m_pos < m_in.size() &&
               (m_in[m_pos] == ' ' || m_in[m_pos] == '\t' || m_in[m_pos] == '\n' || m_in[m_pos] == '\r'))
            ++m_pos;
    }

    bool literal(std::string_view word)
    {
        if (m_in.substr(m_pos, word.size()) != word)
            return false;
        m_pos += word.size();
        return true;
    }

    bool value(jvalue& v, int depth)
    {
        if (depth > m_policy.max_depth)
            return false;
        ws();
        if (m_pos >= m_in.size())
            return false;
        const char c = m_in[m_pos];
        if (c == '{')
            return object(v, depth);
        if (c == '[')
            return array(v, depth);
        if (c == '"')
        {
            v.k = jvalue::kind::string;
            return string(v.s);
        }
        if (c == 't' || c == 'f')
        {
            v.k = jvalue::kind::boolean;
            v.b = c == 't';
            return literal(v.b ? "true" : "false");
        }
        if (c == 'n')
        {
            v.k = jvalue::kind::null;
            return literal("null");
        }
        return number(v);
    }

    bool number(jvalue& v)
    {
        const size_t start = m_pos;
        auto digits = [this]()
        {
            const size_t from = m_pos;
            while (m_pos < m_in.size() && m_in[m_pos] >= '0' && m_in[m_pos] <= '9')
                ++m_pos;
            return m_pos > from;
        };
        if (m_pos < m_in.size() && m_in[m_pos] == '-')
            ++m_pos;
        const size_t first = m_pos;
        // JSON writes no leading zero, so "01" is not a number some other reader would take as one.
        if (!digits() || (m_in[first] == '0' && m_pos - first > 1))
            return false;
        if (m_pos < m_in.size() && m_in[m_pos] == '.')
        {
            ++m_pos;
            if (!digits())
                return false;
        }
        if (m_pos < m_in.size() && (m_in[m_pos] == 'e' || m_in[m_pos] == 'E'))
        {
            ++m_pos;
            if (m_pos < m_in.size() && (m_in[m_pos] == '+' || m_in[m_pos] == '-'))
                ++m_pos;
            if (!digits())
                return false;
        }
        v.k = jvalue::kind::number;
        v.s = std::string(m_in.substr(start, m_pos - start));
        return true;
    }

    bool hex4(uint32_t& out)
    {
        if (m_pos + 4 > m_in.size())
            return false;
        out = 0;
        for (int i = 0; i < 4; ++i)
        {
            const char h = m_in[m_pos++];
            out <<= 4;
            if (h >= '0' && h <= '9')
                out |= static_cast<uint32_t>(h - '0');
            else if (h >= 'a' && h <= 'f')
                out |= static_cast<uint32_t>(h - 'a' + 10);
            else if (h >= 'A' && h <= 'F')
                out |= static_cast<uint32_t>(h - 'A' + 10);
            else
                return false;
        }
        return true;
    }

    static void utf8(std::string& out, uint32_t cp)
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

    // One character of raw UTF-8 whose first byte was just read, refused unless it is the shortest form of a scalar value.
    bool utf8_char(unsigned char lead, std::string& out)
    {
        size_t   n  = 0;
        uint32_t cp = 0;
        if (lead >= 0xC2 && lead <= 0xDF)
            n = 1, cp = lead & 0x1Fu;
        else if (lead >= 0xE0 && lead <= 0xEF)
            n = 2, cp = lead & 0x0Fu;
        else if (lead >= 0xF0 && lead <= 0xF4)
            n = 3, cp = lead & 0x07u;
        else
            return false;
        if (n > m_in.size() - m_pos)
            return false;
        for (size_t i = 0; i < n; ++i)
        {
            const auto b = static_cast<unsigned char>(m_in[m_pos + i]);
            if ((b & 0xC0) != 0x80)
                return false;
            cp = (cp << 6) | (b & 0x3Fu);
        }
        if ((n == 2 && cp < 0x800) || (n == 3 && cp < 0x10000) || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
            return false;
        out.append(m_in.data() + m_pos - 1, n + 1);
        m_pos += n;
        return true;
    }

    // A byte a string holds as it is, copied with the ones beside it.
    bool plain(unsigned char c) const
    {
        return c >= 0x20 && c != '"' && c != '\\' && (c < 0x80 || !m_policy.check_utf8);
    }

    bool string(std::string& out)
    {
        ++m_pos;
        out.clear();
        while (m_pos < m_in.size())
        {
            size_t run = m_pos;
            while (run < m_in.size() && plain(static_cast<unsigned char>(m_in[run])))
                ++run;
            out.append(m_in.data() + m_pos, run - m_pos);
            m_pos = run;
            if (m_pos >= m_in.size())
                return false;
            const char c = m_in[m_pos++];
            if (c == '"')
                return true;
            if (static_cast<unsigned char>(c) < 0x20)
                return false;
            if (static_cast<unsigned char>(c) >= 0x80)
            {
                if (!utf8_char(static_cast<unsigned char>(c), out))
                    return false;
                continue;
            }
            if (c != '\\')
            {
                out += c;
                continue;
            }
            if (m_pos >= m_in.size())
                return false;
            switch (m_in[m_pos++])
            {
                case '"':  out += '"'; break;
                case '\\': out += '\\'; break;
                case '/':  out += '/'; break;
                case 'b':  out += '\b'; break;
                case 'f':  out += '\f'; break;
                case 'n':  out += '\n'; break;
                case 'r':  out += '\r'; break;
                case 't':  out += '\t'; break;
                case 'u':
                {
                    uint32_t cp = 0;
                    if (!hex4(cp))
                        return false;
                    if (cp >= 0xD800 && cp <= 0xDBFF)
                    {
                        uint32_t lo = 0;
                        if (!literal("\\u") || !hex4(lo) || lo < 0xDC00 || lo > 0xDFFF)
                            return false;
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    }
                    else if (cp >= 0xDC00 && cp <= 0xDFFF)
                        return false;
                    utf8(out, cp);
                    break;
                }
                default:
                    return false;
            }
        }
        return false;
    }

    bool array(jvalue& v, int depth)
    {
        ++m_pos;
        v.k = jvalue::kind::array;
        ws();
        if (m_pos < m_in.size() && m_in[m_pos] == ']')
        {
            ++m_pos;
            return true;
        }
        for (;;)
        {
            v.items.emplace_back();
            if (!value(v.items.back(), depth + 1))
                return false;
            ws();
            if (m_pos >= m_in.size())
                return false;
            if (m_in[m_pos] == ']')
            {
                ++m_pos;
                return true;
            }
            if (m_in[m_pos++] != ',')
                return false;
        }
    }

    bool object(jvalue& v, int depth)
    {
        ++m_pos;
        v.k = jvalue::kind::object;
        ws();
        if (m_pos < m_in.size() && m_in[m_pos] == '}')
        {
            ++m_pos;
            return true;
        }
        for (;;)
        {
            ws();
            if (m_pos >= m_in.size() || m_in[m_pos] != '"')
                return false;
            std::string name;
            if (!string(name))
                return false;
            ws();
            if (m_pos >= m_in.size() || m_in[m_pos++] != ':')
                return false;
            v.members.emplace_back(std::move(name), jvalue{});
            if (!value(v.members.back().second, depth + 1))
                return false;
            ws();
            if (m_pos >= m_in.size())
                return false;
            if (m_in[m_pos] == '}')
            {
                ++m_pos;
                return !m_policy.unique_names || unique_names(v);
            }
            if (m_in[m_pos++] != ',')
                return false;
        }
    }

    // A field given twice would be read one way here and another way by whoever wrote it.
    static bool unique_names(const jvalue& v)
    {
        std::vector<std::string_view> names;
        names.reserve(v.members.size());
        for (const auto& m : v.members)
            names.emplace_back(m.first);
        std::sort(names.begin(), names.end());
        return std::adjacent_find(names.begin(), names.end()) == names.end();
    }

    std::string_view m_in;
    json_policy      m_policy;
    size_t m_pos{0};
};

// The value of an object's member `name`, null when it has none or is no object; the reader admits no second.
inline const jvalue* member(const jvalue& obj, std::string_view name)
{
    if (obj.k != jvalue::kind::object)
        return nullptr;
    for (const auto& [k, m] : obj.members)
        if (k == name)
            return &m;
    return nullptr;
}

inline jvalue* member(jvalue& obj, std::string_view name)
{
    return const_cast<jvalue*>(member(static_cast<const jvalue&>(obj), name));
}

// A string member's text, empty when it is missing or no string.
inline std::string_view string_of(const jvalue& obj, std::string_view name)
{
    const jvalue* v = member(obj, name);
    return v && v->k == jvalue::kind::string ? std::string_view(v->s) : std::string_view{};
}

// A number member written as an integer, `otherwise` when it is missing, no number, or written with a point or exponent.
inline int64_t int_of(const jvalue& obj, std::string_view name, int64_t otherwise = 0)
{
    const jvalue* v = member(obj, name);
    int64_t n = 0;
    if (!v || v->k != jvalue::kind::number)
        return otherwise;
    const auto [end, ec] = std::from_chars(v->s.data(), v->s.data() + v->s.size(), n);
    return ec == std::errc{} && end == v->s.data() + v->s.size() ? n : otherwise;
}

// The document as compact JSON appended to `out`, as every runtime that answers with one writes it.
inline void write_into(std::string& out, const jvalue& v)
{
    switch (v.k)
    {
        case jvalue::kind::null: out += "null"; return;
        case jvalue::kind::boolean: out += v.b ? "true" : "false"; return;
        case jvalue::kind::number: out += v.s; return;
        case jvalue::kind::string: quote_into(out, v.s); return;
        case jvalue::kind::array:
            out += '[';
            for (size_t i = 0; i < v.items.size(); ++i)
            {
                if (i)
                    out += ',';
                write_into(out, v.items[i]);
            }
            out += ']';
            return;
        case jvalue::kind::object:
            out += '{';
            for (size_t i = 0; i < v.members.size(); ++i)
            {
                if (i)
                    out += ',';
                quote_into(out, v.members[i].first);
                out += ':';
                write_into(out, v.members[i].second);
            }
            out += '}';
            return;
    }
}

inline std::string written(const jvalue& v)
{
    std::string out;
    write_into(out, v);
    return out;
}

}   // namespace socketley::json
