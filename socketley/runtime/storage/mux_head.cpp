#include "mux_head.h"

#include <charconv>

namespace socketley::storage
{

namespace
{

bool lower_token(std::string_view n)
{
    if (n.empty())
        return false;
    for (const char ch : n)
        if ((ch >= 'A' && ch <= 'Z') || static_cast<uint8_t>(ch) <= 0x20 || ch == ':' || ch == 0x7f)
            return false;
    return true;
}

bool clean_value(std::string_view v)
{
    for (const char ch : v)
        if (ch == '\0' || ch == '\r' || ch == '\n')
            return false;
    return v.empty() || (v.front() != ' ' && v.front() != '\t' && v.back() != ' ' && v.back() != '\t');
}

}   // namespace

mux_verdict mux_request_head(const std::vector<std::pair<std::string, std::string>>& fields, bool end_stream,
                             size_t max_head, mux_request& out)
{
    // RFC 9113 8.2-8.3 and RFC 9114 4.2-4.3 say alike what a request may hold.
    std::string_view method, scheme, path, authority;
    bool regular = false, has_host = false;
    std::string head, cookies;
    for (const auto& [name, value] : fields)
    {
        if (!name.empty() && name[0] == ':')
        {
            std::string_view* slot = name == ":method" ? &method : name == ":scheme" ? &scheme
                                   : name == ":path" ? &path : name == ":authority" ? &authority : nullptr;
            if (!slot || regular || !slot->empty() || value.empty())
                return mux_verdict::malformed;
            *slot = value;
            continue;
        }
        regular = true;
        if (!lower_token(name) || !clean_value(value) || name == "connection" || name == "keep-alive" ||
            name == "proxy-connection" || name == "transfer-encoding" || name == "upgrade" ||
            (name == "te" && value != "trailers"))
            return mux_verdict::malformed;
        if (name == "cookie")
        {
            cookies += cookies.empty() ? "" : "; ";
            cookies += value;
            continue;
        }
        if (name == "content-length")
        {
            const auto r = std::from_chars(value.data(), value.data() + value.size(), out.cl);
            if (r.ec != std::errc{} || r.ptr != value.data() + value.size() || out.has_cl)
                return mux_verdict::malformed;
            out.has_cl = true;
        }
        has_host = has_host || name == "host";
        head += name;
        head += ": ";
        head += value;
        head += "\r\n";
    }
    if (method.empty() || method == "CONNECT" || scheme.empty() || path.empty())
        return mux_verdict::malformed;
    if (end_stream && out.has_cl && out.cl != 0)
        return mux_verdict::malformed;
    out.synth_chunked = !end_stream && !out.has_cl;

    std::string& line = out.line;
    line.reserve(head.size() + path.size() + authority.size() + cookies.size() + 64);
    line += method;
    line += ' ';
    line += path;
    line += " HTTP/1.1\r\n";
    if (!has_host && !authority.empty())
    {
        line += "host: ";
        line += authority;
        line += "\r\n";
    }
    line += head;
    if (!cookies.empty())
    {
        line += "cookie: ";
        line += cookies;
        line += "\r\n";
    }
    if (out.synth_chunked)
        line += "transfer-encoding: chunked\r\n";
    line += "\r\n";
    return line.size() > max_head ? mux_verdict::too_large : mux_verdict::ok;
}

void mux_response_head(std::string_view head, mux_response& out)
{
    const size_t sp = head.find(' ');
    out.status = sp == std::string_view::npos ? "500" : std::string(head.substr(sp + 1, 3));
    out.interim = out.status.size() == 3 && out.status[0] == '1';
    size_t at = head.find("\r\n");
    at = at == std::string_view::npos ? head.size() : at + 2;
    while (at < head.size())
    {
        size_t eol = head.find("\r\n", at);
        if (eol == std::string_view::npos)
            eol = head.size();
        const std::string_view l = head.substr(at, eol - at);
        at = eol + 2;
        const size_t colon = l.find(':');
        if (colon == std::string_view::npos)
            continue;
        std::string name(l.substr(0, colon));
        for (char& ch : name)
            ch = static_cast<char>(ch >= 'A' && ch <= 'Z' ? ch + 32 : ch);
        std::string_view value = l.substr(colon + 1);
        while (!value.empty() && value.front() == ' ')
            value.remove_prefix(1);
        if (name == "transfer-encoding")
        {
            out.chunked = value.find("chunked") != std::string_view::npos;
            continue;
        }
        if (name == "connection" || name == "keep-alive" || name == "proxy-connection" || name == "upgrade")
            continue;
        out.fields.emplace_back(std::move(name), std::string(value));
    }
}

}   // namespace socketley::storage
