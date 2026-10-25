#pragma once
// An XML document read into a tree whose elements know their namespace, as WebDAV's bodies need: each element's
// local name and the URI its prefix is bound to, its attributes, and its text with the entities undone.  A doctype,
// CDATA and a processing instruction past the declaration are refused, as no client of ours sends them.
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace socketley::xml
{

struct node
{
    std::string name;
    std::string ns;
    std::vector<std::pair<std::string, std::string>> attrs;
    std::string text;
    std::vector<node> kids;

    // The first child of that name in that namespace, null where there is none.
    const node* child(std::string_view n, std::string_view space) const
    {
        for (const auto& k : kids)
            if (k.name == n && k.ns == space)
                return &k;
        return nullptr;
    }
    std::string_view attr(std::string_view n) const
    {
        for (const auto& [k, v] : attrs)
            if (k == n)
                return v;
        return {};
    }
};

// `in` with &, <, >, " and ' written as references, and a control character XML may not carry dropped.
inline std::string escape(std::string_view in)
{
    std::string out;
    out.reserve(in.size());
    for (const char ch : in)
    {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (c == '&')
            out += "&amp;";
        else if (c == '<')
            out += "&lt;";
        else if (c == '>')
            out += "&gt;";
        else if (c == '"')
            out += "&quot;";
        else if (c == '\'')
            out += "&apos;";
        else if (c >= 0x20 || c == '\t' || c == '\n' || c == '\r')
            out += ch;
    }
    return out;
}

// `in` with its five named references and numeric ones undone, as UTF-8; false for one that is none of them.
inline bool unescape(std::string_view in, std::string& out)
{
    out.clear();
    for (size_t i = 0; i < in.size(); ++i)
    {
        if (in[i] != '&')
        {
            out += in[i];
            continue;
        }
        const size_t semi = in.find(';', i);
        if (semi == std::string_view::npos || semi - i > 10)
            return false;
        const std::string_view ref = in.substr(i + 1, semi - i - 1);
        i = semi;
        if (ref == "amp")
            out += '&';
        else if (ref == "lt")
            out += '<';
        else if (ref == "gt")
            out += '>';
        else if (ref == "quot")
            out += '"';
        else if (ref == "apos")
            out += '\'';
        else if (ref.size() > 1 && ref[0] == '#')
        {
            const bool hex = ref[1] == 'x';
            uint32_t cp = 0;
            const std::string_view digits = ref.substr(hex ? 2 : 1);
            if (digits.empty() || digits.size() > 6)
                return false;
            for (const char d : digits)
            {
                const int v = d >= '0' && d <= '9' ? d - '0'
                            : hex && d >= 'a' && d <= 'f' ? d - 'a' + 10
                            : hex && d >= 'A' && d <= 'F' ? d - 'A' + 10
                                                          : -1;
                if (v < 0)
                    return false;
                cp = cp * (hex ? 16 : 10) + static_cast<uint32_t>(v);
            }
            if (cp == 0 || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
                return false;
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
        else
            return false;
    }
    return true;
}

class reader
{
public:
    explicit reader(std::string_view x, int max_depth = 32) : m_x(x), m_max_depth(max_depth) {}

    bool document(node& root)
    {
        if (m_x.starts_with("\xEF\xBB\xBF"))
            m_pos = 3;
        if (!skip_misc())
            return false;
        std::vector<std::pair<std::string, std::string>> scope;
        if (!element(root, 0, scope))
            return false;
        return skip_misc() && m_pos == m_x.size();
    }

private:
    static bool space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

    void skip_ws()
    {
        while (m_pos < m_x.size() && space(m_x[m_pos]))
            ++m_pos;
    }

    // Whitespace, the declaration and comments, which may stand outside and between elements.
    bool skip_misc()
    {
        for (;;)
        {
            skip_ws();
            if (m_x.substr(m_pos, 5) == "<?xml" && m_pos == first_tag())
            {
                const size_t e = m_x.find("?>", m_pos);
                if (e == std::string_view::npos)
                    return false;
                m_pos = e + 2;
                continue;
            }
            if (m_x.substr(m_pos, 4) == "<!--")
            {
                const size_t e = m_x.find("-->", m_pos + 4);
                if (e == std::string_view::npos)
                    return false;
                m_pos = e + 3;
                continue;
            }
            return true;
        }
    }

    // Where the first tag stands, after the whitespace and a byte-order mark before it.
    size_t first_tag() const
    {
        size_t p = m_x.starts_with("\xEF\xBB\xBF") ? 3 : 0;
        while (p < m_x.size() && space(m_x[p]))
            ++p;
        return p;
    }

    static std::string_view prefix_of(std::string_view q)
    {
        const size_t colon = q.find(':');
        return colon == std::string_view::npos ? std::string_view{} : q.substr(0, colon);
    }
    static std::string_view local_of(std::string_view q)
    {
        const size_t colon = q.find(':');
        return colon == std::string_view::npos ? q : q.substr(colon + 1);
    }
    static std::string resolve(const std::vector<std::pair<std::string, std::string>>& scope, std::string_view prefix)
    {
        for (auto it = scope.rbegin(); it != scope.rend(); ++it)
            if (it->first == prefix)
                return it->second;
        return {};
    }

    bool element(node& out, int depth, std::vector<std::pair<std::string, std::string>>& scope)
    {
        if (depth > m_max_depth || m_pos >= m_x.size() || m_x[m_pos] != '<')
            return false;
        ++m_pos;
        const size_t name_end = m_x.find_first_of(" \t\r\n/>", m_pos);
        if (name_end == std::string_view::npos || name_end == m_pos)
            return false;
        const std::string_view qname = m_x.substr(m_pos, name_end - m_pos);
        if (qname.front() == '!' || qname.front() == '?' || qname.front() == '/')
            return false;
        m_pos = name_end;
        const size_t scope_mark = scope.size();
        std::vector<std::pair<std::string, std::string>> raw_attrs;
        bool self_closing = false;
        for (;;)
        {
            skip_ws();
            if (m_pos >= m_x.size())
                return false;
            if (m_x[m_pos] == '>')
            {
                ++m_pos;
                break;
            }
            if (m_x.substr(m_pos, 2) == "/>")
            {
                m_pos += 2;
                self_closing = true;
                break;
            }
            const size_t eq = m_x.find('=', m_pos);
            if (eq == std::string_view::npos)
                return false;
            std::string_view an = m_x.substr(m_pos, eq - m_pos);
            while (!an.empty() && space(an.back()))
                an.remove_suffix(1);
            m_pos = eq + 1;
            skip_ws();
            if (an.empty() || m_pos >= m_x.size() || (m_x[m_pos] != '"' && m_x[m_pos] != '\''))
                return false;
            const char quote = m_x[m_pos];
            const size_t close = m_x.find(quote, m_pos + 1);
            if (close == std::string_view::npos)
                return false;
            std::string value;
            if (!unescape(m_x.substr(m_pos + 1, close - m_pos - 1), value))
                return false;
            m_pos = close + 1;
            if (an == "xmlns")
                scope.emplace_back("", value);
            else if (an.starts_with("xmlns:"))
                scope.emplace_back(std::string(an.substr(6)), value);
            else
                raw_attrs.emplace_back(std::string(an), std::move(value));
        }
        out.name = std::string(local_of(qname));
        out.ns = resolve(scope, prefix_of(qname));
        for (auto& [k, v] : raw_attrs)
            out.attrs.emplace_back(std::string(local_of(k)), std::move(v));
        bool ok = true;
        if (!self_closing)
            ok = content(out, qname, depth, scope);
        scope.resize(scope_mark);
        return ok;
    }

    bool content(node& out, std::string_view qname, int depth, std::vector<std::pair<std::string, std::string>>& scope)
    {
        std::string raw;
        for (;;)
        {
            const size_t lt = m_x.find('<', m_pos);
            if (lt == std::string_view::npos)
                return false;
            raw.append(m_x.substr(m_pos, lt - m_pos));
            m_pos = lt;
            if (m_x.substr(m_pos, 4) == "<!--")
            {
                const size_t e = m_x.find("-->", m_pos + 4);
                if (e == std::string_view::npos)
                    return false;
                m_pos = e + 3;
                continue;
            }
            if (m_x.substr(m_pos, 2) == "</")
            {
                const size_t e = m_x.find('>', m_pos);
                if (e == std::string_view::npos)
                    return false;
                std::string_view close = m_x.substr(m_pos + 2, e - m_pos - 2);
                while (!close.empty() && space(close.back()))
                    close.remove_suffix(1);
                if (close != qname)
                    return false;
                m_pos = e + 1;
                break;
            }
            if (m_x.substr(m_pos, 2) == "<!" || m_x.substr(m_pos, 2) == "<?")
                return false;
            out.kids.emplace_back();
            if (!element(out.kids.back(), depth + 1, scope))
                return false;
        }
        // Text beside child elements is only the indentation between them.
        if (!out.kids.empty())
            return raw.find_first_not_of(" \t\r\n") == std::string::npos;
        return unescape(raw, out.text);
    }

    std::string_view m_x;
    int m_max_depth;
    size_t m_pos{0};
};

}   // namespace socketley::xml
