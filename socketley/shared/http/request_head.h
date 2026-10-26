#pragma once
// One HTTP/1.x request at the front of a connection's input, read as db and idp both read it: the request line, the
// framing http_scan_request_headers decides, keep-alive by the version and the last Connection field, and the body's
// length -- with every other field handed to the caller, which keeps the ones it answers by.
#include <cstddef>
#include <string_view>

#include "http_framing.h"

namespace socketley::http
{

struct request_view
{
    std::string_view method;
    std::string_view path;
    std::string_view query;
    // Through the blank line, and the body after it.
    size_t head_len{0};
    size_t body_len{0};
    bool close{false};
};

// 1 when the request is whole, 0 when more is to come, -1 refused with `status` (400, 411, 413 or 431); `field` is
// called with each field line and its trimmed value, the Connection ones aside, before the body is known to be whole.
template <class F>
int take_request(std::string_view in, size_t max_head, size_t max_body, request_view& out, int& status, F&& field)
{
    status = 400;
    const size_t end = in.find("\r\n\r\n");
    if (end == std::string_view::npos)
    {
        if (in.size() > max_head)
        {
            status = 431;
            return -1;
        }
        return 0;
    }
    // The bound holds for a head that arrived whole as well, not only for one still coming.
    if (end + 4 > max_head)
    {
        status = 431;
        return -1;
    }
    const std::string_view head = in.substr(0, end + 2);
    if (!http_eol_framing_ok(head, true))
        return -1;
    const size_t line_end = head.find("\r\n");
    const std::string_view line = head.substr(0, line_end);
    const size_t sp1 = line.find(' ');
    const size_t sp2 = sp1 == std::string_view::npos ? sp1 : line.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos)
        return -1;
    const std::string_view target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    const std::string_view version = line.substr(sp2 + 1);
    if (version != "HTTP/1.1" && version != "HTTP/1.0")
        return -1;
    out.method = line.substr(0, sp1);
    const size_t q = target.find('?');
    out.path = target.substr(0, q);
    out.query = q == std::string_view::npos ? std::string_view{} : target.substr(q + 1);

    const std::string_view fields = head.substr(line_end + 2);
    const http_request_framing_scan scan = http_scan_request_headers(fields);
    if (!scan.ok || scan.transfer_encoding)
    {
        status = scan.ok ? 411 : 400;
        return -1;
    }
    bool close = version == "HTTP/1.0";
    for (size_t pos = 0; pos < fields.size();)
    {
        size_t nl = fields.find("\r\n", pos);
        if (nl == std::string_view::npos)
            nl = fields.size();
        const std::string_view f = fields.substr(pos, nl - pos);
        pos = nl + 2;
        const size_t colon = f.find(':');
        if (colon == std::string_view::npos)
            continue;
        const std::string_view value = http_trim_ows(f.substr(colon + 1));
        if (header_name_equals(f, "connection", 10))
        {
            if (http_list_has_token(value, "close", 5))
                close = true;
            else if (http_list_has_token(value, "keep-alive", 10))
                close = false;
        }
        else
            field(f, value);
    }
    const size_t body_len = scan.has_content_length ? scan.content_length : 0;
    if (body_len > max_body)
    {
        status = 413;
        return -1;
    }
    if (in.size() < end + 4 + body_len)
        return 0;
    out.head_len = end + 4;
    out.body_len = body_len;
    out.close = close;
    return 1;
}

}   // namespace socketley::http
