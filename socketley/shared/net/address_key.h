#pragma once
// What a client's failures and connections are counted under, so a host given a whole IPv6 network is one client
// and not one per address it can pick.
#include <algorithm>
#include <string>
#include <string_view>

#include <arpa/inet.h>
#include <netinet/in.h>

namespace socketley
{

// The address, and for IPv6 its /64, which one host is given whole; an IPv4 address written as IPv6 is the IPv4 one.
inline std::string address_key(std::string_view ip)
{
    const std::string text(ip);
    unsigned char a[16];
    if (text.find(':') == std::string::npos || ::inet_pton(AF_INET6, text.c_str(), a) != 1)
        return text;
    static constexpr unsigned char mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    char buf[INET6_ADDRSTRLEN] = {};
    if (std::equal(mapped, mapped + 12, a))
        return ::inet_ntop(AF_INET, a + 12, buf, sizeof buf) ? std::string(buf) : text;
    std::fill(a + 8, a + 16, 0);
    return ::inet_ntop(AF_INET6, a, buf, sizeof buf) ? std::string(buf) + "/64" : text;
}

} // namespace socketley
