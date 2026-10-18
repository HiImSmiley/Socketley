#pragma once
// A bucket's CORS rules as S3 takes them: the CORSConfiguration document, the
// rule a browser's request matches, and the headers it is answered with.
//
// Pure, with no I/O, so the shards and a unit test reach it alike.
#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "s3_xml.h"
#include "../../shared/http/http_framing.h"
#include "../../shared/util/ascii.h"

namespace socketley::storage
{

struct cors_rule
{
    std::string              id;
    std::vector<std::string> origins;
    std::vector<std::string> methods;
    std::vector<std::string> headers;
    std::vector<std::string> expose;
    // -1 when the rule does not say.
    int64_t                  max_age{-1};
};

struct cors_config
{
    std::vector<cors_rule> rules;
    // The document as GetBucketCors answers it, which is also what is kept on disk.
    std::string            xml;
};

inline constexpr size_t cors_max_rules = 100;
inline constexpr size_t cors_max_bytes = 64 * 1024;

// The methods a rule may allow, which are also the only ones a preflight may ask about.
inline bool cors_method_known(std::string_view m)
{
    return m == "GET" || m == "PUT" || m == "HEAD" || m == "POST" || m == "DELETE";
}

// `pattern` with at most one '*' standing for any run of bytes; header names compare without case.
inline bool cors_wildcard_match(std::string_view pattern, std::string_view s, bool fold)
{
    const auto eq = [fold](std::string_view a, std::string_view b) { return fold ? ascii::iequals(a, b) : a == b; };
    const size_t star = pattern.find('*');
    if (star == std::string_view::npos)
        return eq(pattern, s);
    const std::string_view pre  = pattern.substr(0, star);
    const std::string_view post = pattern.substr(star + 1);
    return s.size() >= pre.size() + post.size() && eq(s.substr(0, pre.size()), pre) &&
           eq(s.substr(s.size() - post.size()), post);
}

inline std::string cors_xml(const cors_config& c)
{
    std::string x(xml_decl);
    x += "<CORSConfiguration xmlns=\"";
    x += s3_xmlns;
    x += "\">";
    const auto element = [&x](std::string_view name, std::string_view value)
    {
        x += '<';
        x += name;
        x += '>';
        xml_escape_to(x, value);
        x += "</";
        x += name;
        x += '>';
    };
    for (const cors_rule& r : c.rules)
    {
        x += "<CORSRule>";
        if (!r.id.empty())
            element("ID", r.id);
        for (const auto& v : r.headers) element("AllowedHeader", v);
        for (const auto& v : r.methods) element("AllowedMethod", v);
        for (const auto& v : r.origins) element("AllowedOrigin", v);
        for (const auto& v : r.expose) element("ExposeHeader", v);
        if (r.max_age >= 0)
            element("MaxAgeSeconds", std::to_string(r.max_age));
        x += "</CORSRule>";
    }
    x += "</CORSConfiguration>";
    return x;
}

// False with `err` for a document S3 would refuse, MalformedXML when it is not a
// CORSConfiguration and InvalidRequest when its rules ask for what S3 does not allow.
inline bool parse_cors_xml(std::string_view x, cors_config& out, s3_error& err)
{
    out = {};
    err = make_error("MalformedXML");
    size_t pos = 0;
    const auto skip_ws = [&]
    {
        for (;;)
        {
            while (pos < x.size() && (x[pos] == ' ' || x[pos] == '\t' || x[pos] == '\r' || x[pos] == '\n'))
                ++pos;
            if (x.substr(pos, 4) != "<!--")
                return true;
            const size_t e = x.find("-->", pos + 4);
            if (e == std::string_view::npos)
                return false;
            pos = e + 3;
        }
    };
    struct tag { std::string_view name; bool closing{false}; bool empty{false}; };
    const auto read_tag = [&](tag& t) -> bool
    {
        if (!skip_ws() || pos >= x.size() || x[pos] != '<')
            return false;
        const size_t gt = x.find('>', pos);
        if (gt == std::string_view::npos)
            return false;
        std::string_view inner = x.substr(pos + 1, gt - pos - 1);
        pos = gt + 1;
        t.closing = !inner.empty() && inner.front() == '/';
        if (t.closing)
            inner.remove_prefix(1);
        t.empty = !inner.empty() && inner.back() == '/';
        if (t.empty)
            inner.remove_suffix(1);
        // Attributes, such as the namespace, and a namespace prefix are not part of the name.
        inner = inner.substr(0, inner.find_first_of(" \t\r\n"));
        if (const size_t colon = inner.find(':'); colon != std::string_view::npos)
            inner.remove_prefix(colon + 1);
        t.name = inner;
        return !inner.empty() && !(t.closing && t.empty);
    };
    const auto invalid = [&](std::string message)
    {
        err = make_error("InvalidRequest");
        err.message = std::move(message);
        return false;
    };

    if (!skip_ws())
        return false;
    if (x.substr(pos, 5) == "<?xml")
    {
        const size_t e = x.find("?>", pos);
        if (e == std::string_view::npos)
            return false;
        pos = e + 2;
    }
    tag t;
    if (!read_tag(t) || t.closing || t.name != "CORSConfiguration")
        return false;
    bool closed = t.empty;
    while (!closed)
    {
        if (!read_tag(t))
            return false;
        if (t.closing && t.name == "CORSConfiguration")
            break;
        if (t.closing || t.empty || t.name != "CORSRule")
            return false;
        if (out.rules.size() == cors_max_rules)
            return invalid("The number of CORS rules should not exceed allowed limit of 100 rules.");
        cors_rule& r = out.rules.emplace_back();
        bool have_id = false, have_age = false;
        for (;;)
        {
            if (!read_tag(t))
                return false;
            if (t.closing && t.name == "CORSRule")
                break;
            if (t.closing)
                return false;
            std::string value;
            if (!t.empty)
            {
                const size_t lt = x.find('<', pos);
                std::string_view text = x.substr(pos, lt == std::string_view::npos ? 0 : lt - pos);
                while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front())))
                    text.remove_prefix(1);
                while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())))
                    text.remove_suffix(1);
                if (lt == std::string_view::npos || !xml_unescape(text, value))
                    return false;
                // Every value may end up in a header line, which a control character would break.
                for (const char ch : value)
                    if (static_cast<unsigned char>(ch) < 0x20 || ch == 0x7f)
                        return false;
                pos = lt;
                tag end;
                if (!read_tag(end) || !end.closing || end.name != t.name)
                    return false;
            }
            const std::string_view n = t.name;
            if (n == "AllowedOrigin")
            {
                if (std::count(value.begin(), value.end(), '*') > 1)
                    return invalid("AllowedOrigin \"" + value + "\" can not have more than one wildcard.");
                r.origins.push_back(std::move(value));
            }
            else if (n == "AllowedMethod")
            {
                if (!cors_method_known(value))
                    return invalid("Found unsupported HTTP method in CORS config. Unsupported method is " + value);
                r.methods.push_back(std::move(value));
            }
            else if (n == "AllowedHeader")
            {
                if (std::count(value.begin(), value.end(), '*') > 1)
                    return invalid("AllowedHeader \"" + value + "\" can not have more than one wildcard.");
                r.headers.push_back(std::move(value));
            }
            else if (n == "ExposeHeader")
                r.expose.push_back(std::move(value));
            else if (n == "MaxAgeSeconds" && !have_age)
            {
                int32_t v = 0;
                const auto res = std::from_chars(value.data(), value.data() + value.size(), v);
                if (value.empty() || res.ec != std::errc{} || res.ptr != value.data() + value.size() || v < 0)
                    return false;
                r.max_age = v;
                have_age  = true;
            }
            else if (n == "ID" && !have_id)
            {
                if (value.size() > 255)
                    return invalid("The ID of a CORS rule should not exceed 255 characters.");
                r.id    = std::move(value);
                have_id = true;
            }
            else
                return false;
        }
        if (r.origins.empty() || r.methods.empty())
            return false;
    }
    if (!skip_ws() || pos != x.size() || out.rules.empty())
        return false;
    out.xml = cors_xml(out);
    if (out.xml.size() > cors_max_bytes)
        return invalid("The CORS configuration may not be larger than 64 KiB.");
    err = {};
    return true;
}

// The first rule that allows `origin` to make a `method` request, sending the
// comma-separated `request_headers` a preflight names; null when none does.
inline const cors_rule* cors_match(const cors_config& c, std::string_view origin, std::string_view method,
                                   std::string_view request_headers = {})
{
    for (const cors_rule& r : c.rules)
    {
        bool ok = false;
        for (const auto& o : r.origins)
            if ((ok = cors_wildcard_match(o, origin, false)))
                break;
        if (!ok)
            continue;
        ok = false;
        for (const auto& m : r.methods)
            if ((ok = m == method))
                break;
        if (!ok)
            continue;
        std::string_view rest = request_headers;
        while (ok && !rest.empty())
        {
            const size_t comma = rest.find(',');
            const std::string_view h = http_trim_ows(rest.substr(0, comma));
            rest = comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
            if (h.empty())
                continue;
            ok = false;
            for (const auto& a : r.headers)
                if ((ok = cors_wildcard_match(a, h, true)))
                    break;
        }
        if (ok)
            return &r;
    }
    return nullptr;
}

// The header lines an allowed request is answered with, appended to `out`; a
// preflight also hears the request headers it may send.
inline void cors_render(std::string& out, const cors_rule& r, std::string_view origin, bool preflight,
                        std::string_view request_headers = {})
{
    const auto line = [&out](std::string_view name, std::string_view value)
    {
        out += name;
        out += ": ";
        out += value;
        out += "\r\n";
    };
    const auto list = [&out](std::string_view name, const std::vector<std::string>& vs)
    {
        out += name;
        out += ": ";
        for (size_t i = 0; i < vs.size(); ++i)
        {
            if (i)
                out += ", ";
            out += vs[i];
        }
        out += "\r\n";
    };
    // The origin a rule allows by "*" is answered "*", which a browser never sends credentials to.
    bool any = false;
    for (const auto& o : r.origins)
        if (cors_wildcard_match(o, origin, false))
        {
            any = o == "*";
            break;
        }
    line("Access-Control-Allow-Origin", any ? std::string_view("*") : origin);
    list("Access-Control-Allow-Methods", r.methods);
    if (!any)
        line("Access-Control-Allow-Credentials", "true");
    if (preflight && !request_headers.empty())
    {
        out += "Access-Control-Allow-Headers: ";
        bool first = true;
        std::string_view rest = request_headers;
        while (!rest.empty())
        {
            const size_t comma = rest.find(',');
            const std::string_view h = http_trim_ows(rest.substr(0, comma));
            rest = comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
            if (h.empty())
                continue;
            if (!first)
                out += ", ";
            first = false;
            for (char ch : h)
                out += static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }
        out += "\r\n";
    }
    if (!r.expose.empty())
        list("Access-Control-Expose-Headers", r.expose);
    if (r.max_age >= 0)
        line("Access-Control-Max-Age", std::to_string(r.max_age));
    line("Vary", "Origin, Access-Control-Request-Headers, Access-Control-Request-Method");
}

}   // namespace socketley::storage
