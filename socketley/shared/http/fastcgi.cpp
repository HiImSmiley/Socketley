#include "fastcgi.h"

#include <algorithm>
#include <cctype>

namespace socketley::fastcgi
{

namespace
{

void append_header(std::string& out, record_type type, size_t length)
{
    const char h[header_size] = {
        1,
        static_cast<char>(type),
        static_cast<char>(request_id >> 8),
        static_cast<char>(request_id & 0xff),
        static_cast<char>((length >> 8) & 0xff),
        static_cast<char>(length & 0xff),
        0,
        0,
    };
    out.append(h, header_size);
}

// A stream's bytes as records of at most max_content, and the empty record that ends the stream when `end`.
void append_stream(std::string& out, record_type type, std::string_view data, bool end)
{
    while (!data.empty())
    {
        const size_t n = std::min(data.size(), max_content);
        append_header(out, type, n);
        out.append(data.substr(0, n));
        data.remove_prefix(n);
    }
    if (end)
        append_header(out, type, 0);
}

void append_length(std::string& out, size_t n)
{
    if (n < 128)
    {
        out.push_back(static_cast<char>(n));
        return;
    }
    out.push_back(static_cast<char>(((n >> 24) & 0x7f) | 0x80));
    out.push_back(static_cast<char>((n >> 16) & 0xff));
    out.push_back(static_cast<char>((n >> 8) & 0xff));
    out.push_back(static_cast<char>(n & 0xff));
}

// RFC 9110 5.6.2's tchar, what a field name is made of.
bool token_char(unsigned char c)
{
    if (std::isalnum(c))
        return true;
    switch (c)
    {
        case '!': case '#': case '$': case '%': case '&': case '\'': case '*': case '+':
        case '-': case '.': case '^': case '_': case '`': case '|': case '~':
            return true;
        default:
            return false;
    }
}

bool iequals(std::string_view a, std::string_view b)
{
    return a.size() == b.size() &&
           std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
               return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
           });
}

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t'))
        s.remove_suffix(1);
    return s;
}

}   // namespace

void append_begin(std::string& out, bool keep_conn)
{
    append_header(out, record_type::begin_request, 8);
    const char body[8] = {0, 1, static_cast<char>(keep_conn ? 1 : 0), 0, 0, 0, 0, 0};
    out.append(body, sizeof body);
}

void append_params(std::string& out, const std::vector<std::pair<std::string, std::string>>& params)
{
    std::string pairs;
    for (const auto& [name, value] : params)
    {
        append_length(pairs, name.size());
        append_length(pairs, value.size());
        pairs += name;
        pairs += value;
    }
    append_stream(out, record_type::params, pairs, true);
}

void append_stdin(std::string& out, std::string_view data)
{
    append_stream(out, record_type::stdin_data, data, data.empty());
}

void append_abort(std::string& out)
{
    append_header(out, record_type::abort_request, 0);
}

take next_record(std::string_view buf, record& out, size_t& consumed)
{
    consumed = 0;
    if (buf.size() < header_size)
        return take::need_more;
    const auto* p = reinterpret_cast<const unsigned char*>(buf.data());
    if (p[0] != 1)
        return take::bad;
    const size_t length = (static_cast<size_t>(p[4]) << 8) | p[5];
    const size_t total = header_size + length + p[6];
    if (buf.size() < total)
        return take::need_more;
    out.type = static_cast<record_type>(p[1]);
    out.id = static_cast<uint16_t>((p[2] << 8) | p[3]);
    out.content = buf.substr(header_size, length);
    consumed = total;
    return take::record;
}

bool parse_end_request(std::string_view content, uint32_t& app_status, uint8_t& protocol_status)
{
    if (content.size() < 8)
        return false;
    const auto* p = reinterpret_cast<const unsigned char*>(content.data());
    app_status = (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
                 (static_cast<uint32_t>(p[2]) << 8) | p[3];
    protocol_status = p[4];
    return true;
}

head_result parse_cgi_head(std::string_view stdout_bytes, size_t& head_len, cgi_head& out, size_t max_head)
{
    head_len = 0;
    out = cgi_head{};
    bool status_given = false;
    size_t at = 0;
    for (;;)
    {
        const size_t nl = stdout_bytes.find('\n', at);
        if (nl == std::string_view::npos)
            return stdout_bytes.size() > max_head ? head_result::bad : head_result::need_more;
        if (nl + 1 > max_head)
            return head_result::bad;
        std::string_view line = stdout_bytes.substr(at, nl - at);
        at = nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (line.empty())
            break;
        const size_t colon = line.find(':');
        if (colon == 0 || colon == std::string_view::npos)
            return head_result::bad;
        const std::string_view name = line.substr(0, colon);
        const std::string_view value = trim(line.substr(colon + 1));
        if (!std::all_of(name.begin(), name.end(), [](char c) { return token_char(static_cast<unsigned char>(c)); }))
            return head_result::bad;
        // Nothing but tab may stand among a value's visible characters, so no answer carries a control byte on.
        if (std::any_of(value.begin(), value.end(), [](char c) {
                const auto u = static_cast<unsigned char>(c);
                return (u < 0x20 && u != '\t') || u == 0x7f;
            }))
            return head_result::bad;
        if (iequals(name, "status"))
        {
            if (value.size() < 3 || !std::isdigit(static_cast<unsigned char>(value[0])) ||
                !std::isdigit(static_cast<unsigned char>(value[1])) || !std::isdigit(static_cast<unsigned char>(value[2])) ||
                (value.size() > 3 && value[3] != ' '))
                return head_result::bad;
            out.status = (value[0] - '0') * 100 + (value[1] - '0') * 10 + (value[2] - '0');
            if (out.status < 100)
                return head_result::bad;
            out.reason = std::string(trim(value.substr(3)));
            status_given = true;
            continue;
        }
        if (iequals(name, "x-accel-redirect"))
        {
            out.accel_redirect = std::string(value);
            continue;
        }
        if (iequals(name, "location"))
            out.location = std::string(value);
        if (iequals(name, "content-length"))
            out.has_length = true;
        if (out.fields.size() >= 256)
            return head_result::bad;
        out.fields.emplace_back(std::string(name), std::string(value));
    }
    // A Location with no Status is a redirect (RFC 3875 6.2.3 and 6.2.4, which a proxy answers as the client's own).
    if (!status_given && !out.location.empty())
        out.status = 302;
    head_len = at;
    return head_result::done;
}

std::vector<std::pair<std::string, std::string>> cgi_params(const request_info& r)
{
    std::vector<std::pair<std::string, std::string>> p;
    p.reserve(24 + r.headers.size());
    const auto put = [&](std::string name, std::string_view value) { p.emplace_back(std::move(name), std::string(value)); };
    put("GATEWAY_INTERFACE", "CGI/1.1");
    put("SERVER_SOFTWARE", "socketley");
    put("SERVER_PROTOCOL", r.protocol.empty() ? std::string_view("HTTP/1.1") : r.protocol);
    put("REQUEST_METHOD", r.method);
    put("REQUEST_URI", r.target);
    put("QUERY_STRING", r.query);
    put("DOCUMENT_URI", r.path);
    put("DOCUMENT_ROOT", r.document_root);
    put("SCRIPT_NAME", r.script_name);
    put("SCRIPT_FILENAME", r.script_filename);
    if (!r.path_info.empty())
        put("PATH_INFO", r.path_info);
    put("SERVER_NAME", r.server_name);
    put("SERVER_PORT", r.server_port);
    put("REMOTE_ADDR", r.remote_addr);
    put("REMOTE_PORT", r.remote_port);
    // What php-cgi's cgi.force_redirect looks for, set as every web server in front of PHP sets it.
    put("REDIRECT_STATUS", "200");
    if (r.https)
        put("HTTPS", "on");
    bool content_type = false;
    for (const auto& [name, value] : r.headers)
    {
        if (iequals(name, "content-type"))
        {
            if (!content_type)
                put("CONTENT_TYPE", value);
            content_type = true;
            continue;
        }
        if (iequals(name, "content-length") || iequals(name, "proxy") || name.find('_') != std::string_view::npos ||
            name.empty())
            continue;
        std::string var = "HTTP_";
        for (const char c : name)
            var += c == '-' ? '_' : static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        const auto same = std::find_if(p.begin(), p.end(), [&](const auto& e) { return e.first == var; });
        if (same != p.end())
            same->second += (var == "HTTP_COOKIE" ? "; " : ", ") + std::string(value);
        else
            put(std::move(var), value);
    }
    if (r.has_body || r.content_length)
        put("CONTENT_LENGTH", std::to_string(r.content_length));
    return p;
}

}   // namespace socketley::fastcgi
