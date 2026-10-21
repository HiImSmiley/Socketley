#include "mail_dnsbl.h"

#include <arpa/inet.h>

#include "../../shared/net/dns_client.h"
#include "../../shared/util/wall_clock.h"

namespace socketley::mail
{

namespace
{

constexpr int64_t keep_ms = 300000;

}   // namespace

void dnsbl::set_zones(std::string_view list)
{
    m_zones.clear();
    while (!list.empty())
    {
        const size_t comma = list.find(',');
        std::string_view z = list.substr(0, comma);
        list = comma == std::string_view::npos ? std::string_view{} : list.substr(comma + 1);
        while (!z.empty() && z.back() == '.')
            z.remove_suffix(1);
        if (!z.empty())
            m_zones.emplace_back(z);
    }
}

std::string dnsbl::reversed(std::string_view ip)
{
    const std::string s(ip);
    in_addr v4{};
    if (::inet_pton(AF_INET, s.c_str(), &v4) == 1)
    {
        const auto* b = reinterpret_cast<const unsigned char*>(&v4);
        return std::to_string(b[3]) + "." + std::to_string(b[2]) + "." + std::to_string(b[1]) + "." +
               std::to_string(b[0]);
    }
    in6_addr v6{};
    if (::inet_pton(AF_INET6, s.c_str(), &v6) != 1)
        return {};
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    for (int i = 15; i >= 0; --i)
    {
        out += hex[v6.s6_addr[i] & 15];
        out += '.';
        out += hex[v6.s6_addr[i] >> 4];
        if (i)
            out += '.';
    }
    return out;
}

void dnsbl::check(const std::string& ip, std::function<void(std::string zone)> done)
{
    const int64_t now = wall::now_ms_coarse();
    if (const auto it = m_kept.find(ip); it != m_kept.end() && it->second.until_ms > now)
    {
        done(it->second.zone);
        return;
    }
    const std::string rev = reversed(ip);
    if (rev.empty() || m_zones.empty())
    {
        done({});
        return;
    }
    auto [it, fresh] = m_asking.try_emplace(ip);
    it->second.waiting.push_back(std::move(done));
    if (!fresh)
        return;
    ++m_asked;
    for (const auto& z : m_zones)
        it->second.names.push_back(rev + "." + z);
    it->second.done.assign(it->second.names.size(), false);
    step(ip);
}

void dnsbl::step(const std::string& ip)
{
    const auto it = m_asking.find(ip);
    if (it == m_asking.end())
        return;
    asking& a = it->second;
    bool pending = false;
    for (size_t i = 0; i < a.names.size(); ++i)
    {
        if (a.done[i])
            continue;
        std::vector<endpoint> got;
        const dns_client::state st = dns_client::here().ask(a.names[i], AF_INET, got);
        if (st == dns_client::state::pending)
        {
            pending = true;
            continue;
        }
        a.done[i] = true;
        for (const auto& e : got)
        {
            const uint32_t v = ntohl(reinterpret_cast<const sockaddr_in*>(&e.addr)->sin_addr.s_addr);
            if ((v >> 24) == 127 && (v >> 8) != 0x7FFFFF && a.listed_by.empty())
                a.listed_by = m_zones[i];
        }
    }
    if (pending)
    {
        poll();
        return;
    }
    const std::string zone = a.listed_by;
    auto waiting = std::move(a.waiting);
    m_asking.erase(it);
    m_kept[ip] = {zone, wall::now_ms_coarse() + keep_ms};
    if (m_kept.size() > 65536)
        m_kept.clear();
    m_listed += !zone.empty();
    for (auto& w : waiting)
        w(zone);
}

void dnsbl::poll()
{
    if (m_polling)
        return;
    // With no timer to wait on, what is still being asked is taken as listed nowhere.
    const auto give_up = [this] {
        std::vector<std::string> ips;
        for (const auto& [ip, a] : m_asking)
            ips.push_back(ip);
        for (const auto& ip : ips)
        {
            auto waiting = std::move(m_asking[ip].waiting);
            m_asking.erase(ip);
            for (auto& w : waiting)
                w({});
        }
    };
    m_polling = m_io.after(std::chrono::milliseconds(2), [this, alive = m_alive](int64_t) {
        if (!*alive)
            return;
        m_polling = false;
        std::vector<std::string> ips;
        for (const auto& [ip, a] : m_asking)
            ips.push_back(ip);
        for (const auto& ip : ips)
            step(ip);
    });
    if (!m_polling)
        give_up();
}

}   // namespace socketley::mail
