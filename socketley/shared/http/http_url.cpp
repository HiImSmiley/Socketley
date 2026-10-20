#include "http_url.h"

#include <charconv>

namespace socketley
{

std::string http_target::authority() const
{
    const bool default_port = port == (tls ? 443 : 80);
    const bool v6 = host.find(':') != std::string::npos;
    return (v6 ? "[" + host + "]" : host) + (default_port ? "" : ":" + std::to_string(port));
}

bool parse_http_url(std::string_view url, http_target& t, std::string& why)
{
    std::string_view rest;
    t.tls = false;
    if (url.starts_with("http://"))
        rest = url.substr(7);
    else if (url.starts_with("https://"))
    {
        rest  = url.substr(8);
        t.tls = true;
    }
    else
    {
        why = "a URL starts with http:// or https://";
        return false;
    }
    t.url = std::string(url);
    const size_t slash = rest.find('/');
    std::string_view authority = rest.substr(0, slash);
    t.path = slash == std::string_view::npos ? "/" : std::string(rest.substr(slash));
    t.port = t.tls ? 443 : 80;
    std::string_view port;
    if (authority.starts_with("["))
    {
        const size_t close = authority.find(']');
        if (close == std::string_view::npos)
        {
            why = "an IPv6 host is closed with ]";
            return false;
        }
        t.host = std::string(authority.substr(1, close - 1));
        if (close + 1 < authority.size())
        {
            if (authority[close + 1] != ':')
            {
                why = "a port follows the host after a colon";
                return false;
            }
            port = authority.substr(close + 2);
        }
    }
    else
    {
        const size_t colon = authority.rfind(':');
        t.host = std::string(authority.substr(0, colon));
        if (colon != std::string_view::npos)
            port = authority.substr(colon + 1);
    }
    if (t.host.empty() || t.host.find('@') != std::string::npos)
    {
        why = "a URL names a host, and no credentials before it";
        return false;
    }
    if (authority.find_first_of(" \t") != std::string_view::npos || t.path.find_first_of(" \t\r\n") != std::string::npos)
    {
        why = "a URL has no spaces";
        return false;
    }
    if (!port.empty() || (slash != std::string_view::npos && authority.ends_with(":")))
    {
        uint32_t p = 0;
        const auto r = std::from_chars(port.data(), port.data() + port.size(), p);
        if (port.empty() || r.ec != std::errc{} || r.ptr != port.data() + port.size() || p == 0 || p > 65535)
        {
            why = "the port is a number from 1 to 65535";
            return false;
        }
        t.port = static_cast<uint16_t>(p);
    }
    return true;
}

}   // namespace socketley
