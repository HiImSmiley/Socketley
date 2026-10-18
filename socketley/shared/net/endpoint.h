#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace socketley
{

struct endpoint
{
    sockaddr_storage addr{};
    socklen_t        len{0};
};

// `host` as an IPv4 or IPv6 literal with `port`, false when it is a name.
inline bool literal_endpoint(const std::string& host, uint16_t port, endpoint& out)
{
    out = endpoint{};
    auto* v4 = reinterpret_cast<sockaddr_in*>(&out.addr);
    if (::inet_pton(AF_INET, host.c_str(), &v4->sin_addr) == 1)
    {
        v4->sin_family = AF_INET;
        v4->sin_port   = htons(port);
        out.len        = sizeof(sockaddr_in);
        return true;
    }
    auto* v6 = reinterpret_cast<sockaddr_in6*>(&out.addr);
    if (::inet_pton(AF_INET6, host.c_str(), &v6->sin6_addr) == 1)
    {
        v6->sin6_family = AF_INET6;
        v6->sin6_port   = htons(port);
        out.len         = sizeof(sockaddr_in6);
        return true;
    }
    return false;
}

// Every stream address getaddrinfo gives for `host`, with `service` as the port, or none when it is null; this blocks.
inline std::vector<endpoint> resolve_all(const std::string& host, const char* service, int family)
{
    std::vector<endpoint> out;
    addrinfo hints{};
    hints.ai_family   = family;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), service, &hints, &res) != 0)
        return out;
    for (const addrinfo* a = res; a; a = a->ai_next)
    {
        endpoint e;
        e.len = static_cast<socklen_t>(std::min<size_t>(a->ai_addrlen, sizeof(e.addr)));
        std::memcpy(&e.addr, a->ai_addr, e.len);
        out.push_back(e);
    }
    ::freeaddrinfo(res);
    return out;
}

}   // namespace socketley
