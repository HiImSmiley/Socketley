#pragma once
// An address or a block of them, IPv4 or IPv6, as an operator writes it -- 192.0.2.7, 192.0.2.0/24, 2001:db8::/32 --
// and whether a peer's address is in it. An IPv4 peer reached over an IPv6 socket (::ffff:192.0.2.7) is matched as
// the IPv4 address it is.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <charconv>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace socketley
{

struct ip_block
{
    uint8_t family{0};   // AF_INET or AF_INET6
    uint8_t addr[16]{};
    uint8_t bits{0};

    // `text` as a block; false when it is not one.
    static bool parse(std::string_view text, ip_block& out)
    {
        out = ip_block{};
        std::string_view a = text;
        int bits = -1;
        if (const size_t slash = text.find('/'); slash != std::string_view::npos)
        {
            a = text.substr(0, slash);
            const std::string_view b = text.substr(slash + 1);
            unsigned v = 0;
            const auto [end, ec] = std::from_chars(b.data(), b.data() + b.size(), v);
            if (b.empty() || ec != std::errc{} || end != b.data() + b.size() || v > 128)
                return false;
            bits = static_cast<int>(v);
        }
        const std::string s(a);
        if (::inet_pton(AF_INET, s.c_str(), out.addr) == 1)
        {
            if (bits > 32)
                return false;
            out.family = AF_INET;
            out.bits = static_cast<uint8_t>(bits < 0 ? 32 : bits);
            return true;
        }
        if (::inet_pton(AF_INET6, s.c_str(), out.addr) == 1)
        {
            out.family = AF_INET6;
            out.bits = static_cast<uint8_t>(bits < 0 ? 128 : bits);
            return true;
        }
        return false;
    }

    // A comma-separated list; false naming the item that is not a block.
    static bool parse_list(std::string_view text, std::vector<ip_block>& out, std::string& bad)
    {
        out.clear();
        size_t pos = 0;
        while (pos <= text.size())
        {
            const size_t comma = text.find(',', pos);
            std::string_view item = text.substr(pos, comma == std::string_view::npos ? std::string_view::npos : comma - pos);
            while (!item.empty() && item.front() == ' ')
                item.remove_prefix(1);
            while (!item.empty() && item.back() == ' ')
                item.remove_suffix(1);
            ip_block b;
            if (!parse(item, b))
            {
                bad = std::string(item);
                return false;
            }
            out.push_back(b);
            if (comma == std::string_view::npos)
                break;
            pos = comma + 1;
        }
        return !out.empty();
    }

    bool contains(const sockaddr* sa) const
    {
        const uint8_t* a = nullptr;
        uint8_t fam = 0;
        if (sa->sa_family == AF_INET)
        {
            a = reinterpret_cast<const uint8_t*>(&reinterpret_cast<const sockaddr_in*>(sa)->sin_addr);
            fam = AF_INET;
        }
        else if (sa->sa_family == AF_INET6)
        {
            const auto* a6 = &reinterpret_cast<const sockaddr_in6*>(sa)->sin6_addr;
            if (IN6_IS_ADDR_V4MAPPED(a6))
            {
                a = reinterpret_cast<const uint8_t*>(a6) + 12;
                fam = AF_INET;
            }
            else
            {
                a = reinterpret_cast<const uint8_t*>(a6);
                fam = AF_INET6;
            }
        }
        if (!a || fam != family)
            return false;
        const unsigned full = bits / 8, rest = bits % 8;
        if (std::memcmp(a, addr, full) != 0)
            return false;
        if (rest == 0)
            return true;
        const uint8_t mask = static_cast<uint8_t>(0xFF << (8 - rest));
        return (a[full] & mask) == (addr[full] & mask);
    }

    static bool any_contains(const std::vector<ip_block>& list, const sockaddr* sa)
    {
        for (const auto& b : list)
            if (b.contains(sa))
                return true;
        return false;
    }
};

}   // namespace socketley
