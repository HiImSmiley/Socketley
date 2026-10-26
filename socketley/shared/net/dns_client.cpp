#include "dns_client.h"
#include "peer_address.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>

#include <fcntl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../runtime/dns/dns_wire.h"
#include "../util/settings.h"

namespace socketley
{

namespace
{

// The test aid SOCKETLEY_RESOLV_CONF names another, so a test can point the resolver at a server of its own.
const char* resolv_conf()
{
    const char* e = settings::text("SOCKETLEY_RESOLV_CONF");
    return e && *e ? e : "/etc/resolv.conf";
}
constexpr const char* hosts_file = "/etc/hosts";
// A job nobody asked about again for this long is let go, its sockets with it.
constexpr auto abandoned = std::chrono::seconds(60);

int64_t mtime_of(const char* path)
{
    struct stat st{};
    if (::stat(path, &st) != 0)
        return -1;
    return static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec;
}

std::string lower_copy(std::string_view s)
{
    std::string out(s);
    for (char& c : out)
        c = static_cast<char>(dns::lower(static_cast<uint8_t>(c)));
    return out;
}

// `name` in wire form, folded to lower case; false for one that is no host name a question may carry.
bool to_wire(std::string_view name, std::string& out)
{
    out.clear();
    if (name.empty() || name.size() > 253)
        return false;
    while (!name.empty())
    {
        const size_t dot = name.find('.');
        const std::string_view label = name.substr(0, dot);
        if (label.empty() || label.size() > dns::max_label)
            return false;
        out += static_cast<char>(label.size());
        for (char c : label)
        {
            // A name a resolver is asked for, not a zone's data: letters, digits, '-' and '_'.
            if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_')
                return false;
            out += static_cast<char>(dns::lower(static_cast<uint8_t>(c)));
        }
        name = dot == std::string_view::npos ? std::string_view() : name.substr(dot + 1);
    }
    out += '\0';
    return true;
}

uint16_t random_id()
{
    uint16_t id = 0;
    if (::getrandom(&id, sizeof id, GRND_NONBLOCK) != sizeof id)
        id = static_cast<uint16_t>(std::chrono::steady_clock::now().time_since_epoch().count());
    return id;
}

}  // namespace

dns_client& dns_client::here()
{
    thread_local dns_client c;
    return c;
}

dns_client::~dns_client()
{
    for (auto& [_, j] : m_jobs)
        close_all(j);
}

void dns_client::refresh()
{
    const auto now = clock::now();
    if (m_checked != clock::time_point{} && now - m_checked < std::chrono::seconds(1))
        return;
    m_checked = now;

    if (const int64_t mt = mtime_of(resolv_conf()); mt != m_conf_mtime)
    {
        m_conf_mtime = mt;
        config c;
        int port = 53;
        std::ifstream f(resolv_conf());
        for (std::string line; std::getline(f, line);)
        {
            std::istringstream words(line.substr(0, line.find_first_of("#;")));
            std::string key;
            if (!(words >> key))
                continue;
            if (key == "nameserver")
            {
                std::string addr;
                endpoint e;
                // At most three, as the resolver library reads; a scope id is the kernel's business here.
                if (words >> addr && c.servers.size() < 3 && literal_endpoint(addr.substr(0, addr.find('%')), 53, e))
                    c.servers.push_back(e);
            }
            else if (key == "search" || key == "domain")
            {
                c.search.clear();
                // "." is the root, which searches nothing.
                for (std::string d; words >> d && c.search.size() < 6;)
                    if (d != ".")
                        c.search.push_back(lower_copy(d.back() == '.' ? d.substr(0, d.size() - 1) : d));
            }
            else if (key == "options")
                for (std::string o; words >> o;)
                {
                    const auto num = [&](std::string_view k, int lo, int hi, int& into)
                    {
                        if (o.rfind(k, 0) == 0)
                            into = std::clamp(std::atoi(o.c_str() + k.size()), lo, hi);
                    };
                    int t = static_cast<int>(c.timeout.count() / 1000);
                    num("ndots:", 0, 15, c.ndots);
                    num("timeout:", 1, 30, t);
                    num("attempts:", 1, 5, c.attempts);
                    // Ours alone, which the resolver library passes over: every nameserver asked on this port.
                    num("port:", 1, 65535, port);
                    c.timeout = std::chrono::milliseconds(t * 1000);
                }
        }
        // No nameserver line is the local one, as the resolver library takes it.
        if (c.servers.empty())
        {
            endpoint e;
            literal_endpoint("127.0.0.1", 53, e);
            c.servers.push_back(e);
        }
        for (endpoint& e : c.servers)
            reinterpret_cast<sockaddr_in*>(&e.addr)->sin_port = htons(static_cast<uint16_t>(port));
        m_cfg = std::move(c);
    }

    if (const int64_t mt = mtime_of(hosts_file); mt != m_hosts_mtime)
    {
        m_hosts_mtime = mt;
        m_hosts.clear();
        std::ifstream f(hosts_file);
        for (std::string line; std::getline(f, line);)
        {
            std::istringstream words(line.substr(0, line.find('#')));
            std::string addr, name;
            endpoint e;
            if (!(words >> addr) || !literal_endpoint(addr.substr(0, addr.find('%')), 0, e))
                continue;
            while (words >> name)
                m_hosts[lower_copy(name)].push_back(e);
        }
    }
}

bool dns_client::from_hosts(const std::string& host, int family, std::vector<endpoint>& out) const
{
    std::string key = lower_copy(host);
    if (!key.empty() && key.back() == '.')
        key.pop_back();
    const auto it = m_hosts.find(key);
    if (it == m_hosts.end())
        return false;
    out.clear();
    for (const endpoint& e : it->second)
        if (family == AF_UNSPEC || e.addr.ss_family == family)
            out.push_back(e);
    return !out.empty();
}

dns_client::state dns_client::ask(const std::string& host, int family, std::vector<endpoint>& out)
{
    endpoint lit;
    if (literal_endpoint(host, 0, lit))
    {
        if (family != AF_UNSPEC && lit.addr.ss_family != family)
            return state::unsure;
        out.assign(1, lit);
        return state::ready;
    }
    refresh();
    if (from_hosts(host, family, out))
    {
        ++m_c.from_hosts;
        return state::ready;
    }

    // Questions no caller came back for are let go once a second, not on every ask.
    const auto now = clock::now();
    if (now - m_swept > std::chrono::seconds(1))
    {
        m_swept = now;
        for (auto it = m_jobs.begin(); it != m_jobs.end();)
            if (now - it->second.sent > abandoned)
            {
                close_all(it->second);
                it = m_jobs.erase(it);
            }
            else
                ++it;
    }

    const std::string key = lower_copy(host) + '\n' + std::to_string(family);
    auto it = m_jobs.find(key);
    if (it == m_jobs.end())
    {
        job j;
        j.family = family;
        std::string n = lower_copy(host);
        const bool absolute = !n.empty() && n.back() == '.';
        if (absolute)
            n.pop_back();
        std::string wire;
        if (!to_wire(n, wire))
        {
            ++m_c.unsure;
            return state::unsure;
        }
        const auto dots = std::count(n.begin(), n.end(), '.');
        std::vector<std::string> searched;
        if (!absolute)
            for (const std::string& d : m_cfg.search)
                searched.push_back(n + "." + d);
        // As the resolver library orders them: the name as given first when it has ndots dots, else last.
        if (absolute || dots >= m_cfg.ndots)
            j.names.push_back(n);
        j.names.insert(j.names.end(), searched.begin(), searched.end());
        if (!absolute && dots < m_cfg.ndots)
            j.names.push_back(n);
        if (family != AF_INET6)
            j.qs.push_back(question{dns::type::A, 0, -1, false, false, {}, {}, false});
        if (family != AF_INET)
            j.qs.push_back(question{dns::type::AAAA, 0, -1, false, false, {}, {}, false});
        if (!send(j))
        {
            close_all(j);
            ++m_c.unsure;
            return state::unsure;
        }
        m_jobs.emplace(key, std::move(j));
        return state::pending;
    }

    job& j = it->second;
    pump(j);
    if (!j.over)
        return state::pending;
    const state st = j.result;
    if (st == state::ready)
    {
        out = std::move(j.addrs);
        ++m_c.answered;
    }
    else
        ++m_c.unsure;
    close_all(j);
    m_jobs.erase(it);
    return st;
}

bool dns_client::send(job& j)
{
    std::string wire;
    // A candidate the search list made too long to be a name is passed over.
    while (j.at < j.names.size() && !to_wire(j.names[j.at], wire))
        ++j.at;
    // No resolv.conf, as in a bare container, leaves no server to ask, and the modulo below would divide by zero.
    if (j.at >= j.names.size() || m_cfg.servers.empty())
        return false;
    const endpoint& server = m_cfg.servers[j.server % m_cfg.servers.size()];
    for (question& q : j.qs)
    {
        if (q.done)
            continue;
        if (q.fd >= 0)
            ::close(q.fd);
        q.fd = ::socket(server.addr.ss_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (q.fd < 0)
            return false;
        // Connected, so the kernel lets only that server's datagrams in.
        if (::connect(q.fd, reinterpret_cast<const sockaddr*>(&server.addr), server.len) != 0)
            return false;
        q.id = random_id();
        uint8_t msg[dns::header_len + 260 + 4 + 11]{};
        dns::wr16(msg, q.id);
        msg[2] = 0x01;   // recursion desired
        // AD asked of a validating resolver, which says so without the signatures DO would bring (RFC 6840 5.7).
        msg[3] = 0x20;
        dns::wr16(msg + 4, 1);
        // An OPT record, so an answer up to 1232 bytes comes whole over UDP rather than cut at 512 (RFC 6891).
        dns::wr16(msg + 10, 1);
        std::memcpy(msg + dns::header_len, wire.data(), wire.size());
        size_t len = dns::header_len + wire.size();
        dns::wr16(msg + len, q.type);
        dns::wr16(msg + len + 2, dns::rclass::IN);
        len += 4;
        msg[len] = 0;
        dns::wr16(msg + len + 1, dns::type::OPT);
        dns::wr16(msg + len + 3, dns::udp_payload);
        len += 11;
        // One a full socket buffer kept is answered by the deadline as a lost one is.
        if (::send(q.fd, msg, len, MSG_DONTWAIT) < 0 && errno != EAGAIN) {}
        ++m_c.sent;
    }
    j.sent = clock::now();
    ++j.tries;
    return true;
}

void dns_client::pump(job& j)
{
    uint8_t buf[dns::max_message < 4096 ? dns::max_message : 4096];
    for (question& q : j.qs)
        while (!q.done && !j.over && q.fd >= 0)
        {
            const ssize_t n = ::recv(q.fd, buf, sizeof buf, MSG_DONTWAIT);
            if (n <= 0)
                break;
            take(j, q, buf, static_cast<size_t>(n));
        }
    if (j.over)
        return;
    if (std::all_of(j.qs.begin(), j.qs.end(), [](const question& q) { return q.done; }))
    {
        settle(j);
        return;
    }
    if (clock::now() - j.sent < m_cfg.timeout)
        return;
    ++m_c.timeouts;
    // The next server, round them all `attempts` times, and then the system's resolver is asked instead.
    ++j.server;
    if (j.tries >= m_cfg.attempts * static_cast<int>(m_cfg.servers.size()) || !send(j))
    {
        j.over   = true;
        j.result = state::unsure;
    }
}

void dns_client::take(job& j, question& q, const uint8_t* msg, size_t len)
{
    if (len < dns::header_len || dns::rd16(msg) != q.id || !(msg[2] & 0x80) || ((msg[2] >> 3) & 0x0F) != 0 ||
        dns::rd16(msg + 4) != 1)
        return;
    // Cut short: what it left out could be every address, so the system's resolver, which retries over TCP, asks.
    if (msg[2] & 0x02)
    {
        j.over   = true;
        j.result = state::unsure;
        return;
    }
    uint8_t name[dns::max_name];
    size_t next = 0;
    const size_t nl = dns::read_name(msg, len, dns::header_len, name, next);
    std::string asked;
    if (nl == 0 || next + 4 > len || !to_wire(j.names[j.at], asked) ||
        std::string_view(reinterpret_cast<const char*>(name), nl) != asked || dns::rd16(msg + next) != q.type ||
        dns::rd16(msg + next + 2) != dns::rclass::IN)
        return;
    size_t at = next + 4;

    const uint8_t rc = msg[3] & 0x0F;
    q.authentic = (msg[3] & 0x20) != 0;
    if (rc == dns::rcode::NXDOMAIN)
    {
        q.done = q.none = q.nxdomain = true;
        return;
    }
    if (rc != dns::rcode::NOERROR)
    {
        // A server that will not answer is passed over at once rather than at its deadline.
        j.sent = clock::time_point{};
        return;
    }
    std::vector<endpoint> got;
    for (uint16_t an = dns::rd16(msg + 6); an > 0; --an)
    {
        if (dns::read_name(msg, len, at, name, next) == 0 || next + 10 > len)
            break;
        const uint16_t type = dns::rd16(msg + next), cls = dns::rd16(msg + next + 2);
        const uint16_t rdlen = dns::rd16(msg + next + 8);
        const uint8_t* rd = msg + next + 10;
        if (next + 10 + rdlen > len)
            break;
        // The chain of aliases is the server's to follow; what it ends in is every record of the type asked.
        endpoint e;
        if (cls == dns::rclass::IN && type == q.type && type == dns::type::MX && rdlen > 2)
        {
            uint8_t ex[dns::max_name];
            size_t after = 0;
            const size_t el = dns::read_name(msg, len, next + 12, ex, after);
            if (el > 0)
                q.records.push_back({dns::rd16(rd), dns::to_text(std::string_view(reinterpret_cast<char*>(ex), el))});
        }
        else if (cls == dns::rclass::IN && type == q.type && type == dns::type::TXT)
        {
            // Character strings, each a length and its bytes, one record's joined as SPF and DKIM read them.
            std::string text;
            for (size_t i = 0; i < rdlen;)
            {
                const size_t n = rd[i];
                if (i + 1 + n > rdlen)
                    break;
                text.append(reinterpret_cast<const char*>(rd + i + 1), n);
                i += 1 + n;
            }
            q.records.push_back({0, std::move(text)});
        }
        else if (cls == dns::rclass::IN && type == q.type && type == dns::type::TLSA && rdlen >= 3)
            q.records.push_back({0, std::string(reinterpret_cast<const char*>(rd), rdlen)});
        else if (cls == dns::rclass::IN && type == q.type && type == dns::type::A && rdlen == 4)
        {
            auto* v4 = reinterpret_cast<sockaddr_in*>(&e.addr);
            v4->sin_family = AF_INET;
            std::memcpy(&v4->sin_addr, rd, 4);
            e.len = sizeof(sockaddr_in);
            got.push_back(e);
        }
        else if (cls == dns::rclass::IN && type == q.type && type == dns::type::AAAA && rdlen == 16)
        {
            auto* v6 = reinterpret_cast<sockaddr_in6*>(&e.addr);
            v6->sin6_family = AF_INET6;
            std::memcpy(&v6->sin6_addr, rd, 16);
            e.len = sizeof(sockaddr_in6);
            got.push_back(e);
        }
        at = next + 10 + rdlen;
    }
    q.addrs = std::move(got);
    q.done  = true;
    q.none  = q.addrs.empty() && q.records.empty();
}

dns_client::state dns_client::ask_records(const std::string& name, uint16_t type, std::vector<record>& out,
                                          bool& no_domain, bool* secure)
{
    refresh();
    no_domain = false;
    if (secure)
        *secure = false;
    const auto now = clock::now();
    std::string n = lower_copy(name);
    if (!n.empty() && n.back() == '.')
        n.pop_back();
    const std::string key = n + '\n' + std::to_string(type) + "\nr";
    auto it = m_jobs.find(key);
    if (it == m_jobs.end())
    {
        std::string wire;
        if (m_cfg.servers.empty() || !to_wire(n, wire))
        {
            ++m_c.unsure;
            return state::unsure;
        }
        job j;
        j.names.push_back(n);
        j.qs.push_back(question{type, 0, -1, false, false, {}, {}, false});
        if (!send(j))
        {
            close_all(j);
            ++m_c.unsure;
            return state::unsure;
        }
        j.sent = now;
        m_jobs.emplace(key, std::move(j));
        return state::pending;
    }
    job& j = it->second;
    if (!j.over)
    {
        pump_records(j);
        if (!j.over)
            return state::pending;
    }
    const state st = j.result;
    if (st == state::ready)
    {
        out = std::move(j.qs.front().records);
        no_domain = j.qs.front().nxdomain;
        if (secure)
        {
            // Every nameserver asked is on this machine, or the AD bit came across a network anyone may write to.
            bool local = !m_cfg.servers.empty();
            for (const endpoint& e : m_cfg.servers)
                local = local && is_loopback(e.addr);
            *secure = local && j.qs.front().authentic;
        }
        ++m_c.answered;
    }
    else
        ++m_c.unsure;
    close_all(j);
    m_jobs.erase(it);
    return st;
}

void dns_client::pump_records(job& j)
{
    uint8_t buf[dns::max_message < 4096 ? dns::max_message : 4096];
    question& q = j.qs.front();
    while (!q.done && !j.over && q.fd >= 0)
    {
        const ssize_t n = ::recv(q.fd, buf, sizeof buf, MSG_DONTWAIT);
        if (n <= 0)
            break;
        take(j, q, buf, static_cast<size_t>(n));
    }
    if (j.over)
        return;
    if (q.done)
    {
        // An answer with no record, or no such name, is as good an answer as one with some.
        j.over = true;
        j.result = state::ready;
        return;
    }
    if (clock::now() - j.sent < m_cfg.timeout)
        return;
    ++m_c.timeouts;
    ++j.server;
    if (j.tries >= m_cfg.attempts * static_cast<int>(m_cfg.servers.size()) || !send(j))
    {
        j.over = true;
        j.result = state::unsure;
    }
}

void dns_client::settle(job& j)
{
    std::vector<endpoint> all;
    for (const question& q : j.qs)
        all.insert(all.end(), q.addrs.begin(), q.addrs.end());
    if (!all.empty())
    {
        j.over   = true;
        j.result = state::ready;
        j.addrs  = std::move(all);
        return;
    }
    // No address under this candidate: the next, from the first server again.
    ++j.at;
    for (question& q : j.qs)
        q = question{q.type, 0, q.fd, false, false, {}, {}, false};
    j.server = 0;
    j.tries  = 0;
    if (j.at >= j.names.size() || !send(j))
    {
        j.over   = true;
        j.result = state::unsure;
    }
}

void dns_client::close_all(job& j)
{
    for (question& q : j.qs)
        if (q.fd >= 0)
        {
            ::close(q.fd);
            q.fd = -1;
        }
}

}  // namespace socketley
