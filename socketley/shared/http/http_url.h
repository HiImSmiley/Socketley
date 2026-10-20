#pragma once
// A URL a runtime sends to, parsed to what a connection and a request need of it.
#include <cstdint>
#include <string>
#include <string_view>

namespace socketley
{

// Where a target's requests go: the URL's scheme, host, port and path, and the CA an https host is checked against.
struct http_target
{
    std::string url;
    bool        tls{false};
    std::string host;
    uint16_t    port{0};
    std::string path;
    // The CA an https target's certificate is checked against, the system's when empty.
    std::string ca_file;

    // What a Host header names: the host, bracketed when it is IPv6, and the port when it is not the scheme's.
    std::string authority() const;
};

// `http://host[:port][/path]` or `https://...`, a host in brackets for IPv6; false with `why` for anything else.
bool parse_http_url(std::string_view url, http_target& t, std::string& why);

}   // namespace socketley
