#pragma once
// A small XML document read into a tree of elements, for the documents S3 takes in a request body.
#include <string>
#include <string_view>
#include <vector>

#include "s3_xml.h"

namespace socketley::storage
{

// An element of the document, with its text unescaped and namespaces and attributes dropped.
struct xml_node
{
    std::string name;
    std::string text;
    std::vector<xml_node> kids;
    bool has_text{false};
};

// A reader of plain elements and text, refusing what a configuration never holds: CDATA, a doctype, a mismatched close.
class xml_reader
{
public:
    explicit xml_reader(std::string_view x) : m_x(x) {}

    bool document(xml_node& root)
    {
        skip_misc();
        if (!element(root, 0))
            return false;
        skip_misc();
        return m_pos == m_x.size();
    }

private:
    static constexpr int max_depth = 16;

    void skip_ws()
    {
        while (m_pos < m_x.size() && (m_x[m_pos] == ' ' || m_x[m_pos] == '\t' || m_x[m_pos] == '\r' || m_x[m_pos] == '\n'))
            ++m_pos;
    }

    // Whitespace, the declaration and comments, which may stand outside and between elements.
    bool skip_misc()
    {
        for (;;)
        {
            skip_ws();
            if (m_x.substr(m_pos, 5) == "<?xml")
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

    static std::string_view local_name(std::string_view n)
    {
        const size_t colon = n.find(':');
        return colon == std::string_view::npos ? n : n.substr(colon + 1);
    }

    bool element(xml_node& out, int depth)
    {
        if (depth > max_depth || m_pos >= m_x.size() || m_x[m_pos] != '<')
            return false;
        const size_t gt = m_x.find('>', m_pos);
        if (gt == std::string_view::npos)
            return false;
        std::string_view inner = m_x.substr(m_pos + 1, gt - m_pos - 1);
        m_pos = gt + 1;
        const bool self_closing = !inner.empty() && inner.back() == '/';
        if (self_closing)
            inner.remove_suffix(1);
        const size_t sp = inner.find_first_of(" \t\r\n");
        const std::string_view qname = inner.substr(0, sp);
        if (qname.empty() || qname.front() == '/' || qname.front() == '!' || qname.front() == '?')
            return false;
        out.name = std::string(local_name(qname));
        if (self_closing)
            return true;

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
                while (!close.empty() && (close.back() == ' ' || close.back() == '\t' || close.back() == '\r' ||
                                          close.back() == '\n'))
                    close.remove_suffix(1);
                if (close != qname)
                    return false;
                m_pos = e + 1;
                break;
            }
            if (m_x.substr(m_pos, 2) == "<!" || m_x.substr(m_pos, 2) == "<?")
                return false;
            out.kids.emplace_back();
            if (!element(out.kids.back(), depth + 1))
                return false;
        }
        // Text beside child elements is only the indentation between them.
        if (!out.kids.empty())
            return raw.find_first_not_of(" \t\r\n") == std::string::npos;
        out.has_text = true;
        return xml_unescape(raw, out.text);
    }

    std::string_view m_x;
    size_t           m_pos{0};
};

}   // namespace socketley::storage
