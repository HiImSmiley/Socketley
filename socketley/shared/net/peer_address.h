#pragma once

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

} // namespace socketley
