#pragma once

#include <string>
#include <string_view>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace socketley
{

// Whether a peer is on this machine: 127/8, ::1, or an IPv4 one of those on a dual-stack socket.
inline bool is_loopback(const sockaddr_storage& a)
{
    if (a.ss_family == AF_INET)
        return (ntohl(reinterpret_cast<const sockaddr_in&>(a).sin_addr.s_addr) >> 24) == 127;
    if (a.ss_family == AF_INET6)
    {
        const auto& v6 = reinterpret_cast<const sockaddr_in6&>(a).sin6_addr;
        return IN6_IS_ADDR_LOOPBACK(&v6) || (IN6_IS_ADDR_V4MAPPED(&v6) && v6.s6_addr[12] == 127);
    }
    return false;
}

// The same for an address as text, where none at all is a unix socket's peer and so on this machine too.
inline bool is_loopback(std::string_view ip)
{
    return ip.empty() || ip.starts_with("127.") || ip == "::1" || ip.starts_with("::ffff:127.");
}

// Whether a URL's host[:port] names this machine, the only place plain http may carry a credential to.
inline bool authority_is_this_machine(std::string_view authority)
{
    std::string_view host = authority;
    if (host.starts_with('['))
    {
        const size_t close = host.find(']');
        if (close == std::string_view::npos)
            return false;
        host = host.substr(1, close - 1);
    }
    else if (const size_t colon = host.rfind(':'); colon != std::string_view::npos)
        host = host.substr(0, colon);
    if (host == "localhost")
        return true;
    const std::string h(host);
    in_addr v4{};
    in6_addr v6{};
    if (::inet_pton(AF_INET, h.c_str(), &v4) == 1)
        return (ntohl(v4.s_addr) >> 24) == 127;
    return ::inet_pton(AF_INET6, h.c_str(), &v6) == 1 && IN6_IS_ADDR_LOOPBACK(&v6);
}

} // namespace socketley
