#pragma once
// Wrong keys counted per client for the runtimes that answer HTTP under --keys (mcp, metrics, db), on the bar every
// other sign-in keeps.
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "http_framing.h"
#include "../net/failure_bar.h"

namespace socketley::http
{

class key_bar
{
public:
    // Who a request is charged to: its peer, or behind the entrance on this machine the hop that names last; empty,
    // and so never counted, for this machine's own 127.0.0.1 and ::1. An IPv6 holder is its whole /64.
    static std::string client(const sockaddr_storage& peer, std::string_view forwarded_for)
    {
        // Only 127.0.0.1 and ::1 are the entrance: a tunnel's visitor comes from 127.0.0.2 and names no client.
        if (!is_this_machine(key_of(peer)))
            return key_of(peer);
        const std::string hop(http_last_forwarded_hop(forwarded_for));
        sockaddr_storage named{};
        if (::inet_pton(AF_INET, hop.c_str(), &reinterpret_cast<sockaddr_in*>(&named)->sin_addr) == 1)
            named.ss_family = AF_INET;
        else if (::inet_pton(AF_INET6, hop.c_str(), &reinterpret_cast<sockaddr_in6*>(&named)->sin6_addr) == 1)
            named.ss_family = AF_INET6;
        const std::string key = key_of(named);
        return is_this_machine(key) ? std::string() : key;
    }

    // Whole seconds until `client` may show a key again, 0 while it may now.
    int64_t barred_for(const std::string& client)
    {
        return client.empty() ? 0 : m_misses.barred_for(client, failure_bar::clock::now());
    }

    void missed(const std::string& client)
    {
        if (!client.empty())
            m_misses.missed(client, failure_bar::clock::now());
    }

private:
    // The address as the key it is counted under, ::1 as its sixteen bytes so that it is no /64 of anyone's.
    static std::string key_of(const sockaddr_storage& a)
    {
        if (a.ss_family == AF_INET)
            return std::string(reinterpret_cast<const char*>(&reinterpret_cast<const sockaddr_in&>(a).sin_addr), 4);
        if (a.ss_family != AF_INET6)
            return {};
        const auto& v6 = reinterpret_cast<const sockaddr_in6&>(a).sin6_addr;
        if (IN6_IS_ADDR_V4MAPPED(&v6))
            return std::string(reinterpret_cast<const char*>(v6.s6_addr + 12), 4);
        return std::string(reinterpret_cast<const char*>(v6.s6_addr), IN6_IS_ADDR_LOOPBACK(&v6) ? 16 : 8);
    }

    static bool is_this_machine(const std::string& key)
    {
        static const std::string lo6 = std::string(15, '\0') + '\1';
        return key.empty() || key == std::string_view("\x7f\0\0\1", 4) || key == lo6;
    }

    socketley::failure_bar m_misses{10, std::chrono::minutes(15)};
};

} // namespace socketley::http
