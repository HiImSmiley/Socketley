#include "mail_verify.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <sstream>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>

#include "mail_compose.h"
#include "mail_dkim.h"
#include "../dns/dns_wire.h"
#include "../../shared/net/public_suffix.h"
#include "../../shared/util/ascii.h"
#include "../../shared/util/settings.h"

namespace socketley::mail
{

namespace
{

std::string lower(std::string_view s)
{
    std::string out(s);
    socketley::ascii::lower_in_place(out);
    return out;
}

std::vector<std::string_view> words(std::string_view s)
{
    std::vector<std::string_view> out;
    size_t at = 0;
    while (at < s.size())
    {
        while (at < s.size() && (s[at] == ' ' || s[at] == '\t'))
            ++at;
        const size_t end = s.find_first_of(" \t", at);
        if (at < s.size())
            out.push_back(s.substr(at, end == std::string_view::npos ? std::string_view::npos : end - at));
        at = end == std::string_view::npos ? s.size() : end;
    }
    return out;
}

// Whether `ip` falls in `net`/`bits`, both IPv4 or both IPv6 text.
bool in_net(const std::string& ip, std::string_view net, int bits)
{
    unsigned char a[16], b[16];
    const bool v6 = ip.find(':') != std::string::npos;
    if ((net.find(':') != std::string_view::npos) != v6)
        return false;
    const int fam = v6 ? AF_INET6 : AF_INET;
    if (::inet_pton(fam, ip.c_str(), a) != 1 || ::inet_pton(fam, std::string(net).c_str(), b) != 1)
        return false;
    const int max = v6 ? 128 : 32;
    if (bits < 0 || bits > max)
        bits = max;
    for (int i = 0; i < bits; ++i)
        if (((a[i / 8] >> (7 - i % 8)) & 1) != ((b[i / 8] >> (7 - i % 8)) & 1))
            return false;
    return true;
}

struct spf_state
{
    const std::string& ip;
    const std::string& sender;
    check_resolver& r;
    int lookups{0};
    int voids{0};
};

// The macros of RFC 7208 7, the letters a mechanism's domain is written with, without the ones only exp= takes.
bool expand(std::string_view spec, const std::string& domain, spf_state& s, std::string& out)
{
    out.clear();
    const size_t at = s.sender.rfind('@');
    const std::string local = at == std::string::npos ? "postmaster" : s.sender.substr(0, at);
    const std::string sdom = at == std::string::npos ? domain : s.sender.substr(at + 1);
    for (size_t i = 0; i < spec.size(); ++i)
    {
        if (spec[i] != '%')
        {
            out += spec[i];
            continue;
        }
        if (++i >= spec.size())
            return false;
        if (spec[i] == '%')
            out += '%';
        else if (spec[i] == '_')
            out += ' ';
        else if (spec[i] == '-')
            out += "%20";
        else if (spec[i] == '{')
        {
            const size_t close = spec.find('}', i);
            if (close == std::string_view::npos || close == i + 1)
                return false;
            const char letter = socketley::ascii::lower(spec[i + 1]);
            std::string_view tr = spec.substr(i + 2, close - i - 2);
            i = close;
            std::string v;
            switch (letter)
            {
                case 's': v = s.sender; break;
                case 'l': v = local; break;
                case 'o': v = sdom; break;
                case 'd': v = domain; break;
                case 'i': v = s.ip; break;
                case 'h': v = domain; break;
                case 'v': v = s.ip.find(':') == std::string::npos ? "in-addr" : "ip6"; break;
                default: return false;
            }
            // Digits keep that many labels from the right, r reverses them first.
            size_t keep = 0;
            bool reverse = false;
            while (!tr.empty() && std::isdigit(static_cast<unsigned char>(tr.front())))
            {
                keep = keep * 10 + static_cast<size_t>(tr.front() - '0');
                tr.remove_prefix(1);
            }
            if (!tr.empty() && socketley::ascii::lower(tr.front()) == 'r')
                reverse = true;
            std::vector<std::string> labels;
            std::stringstream ss(v);
            for (std::string l; std::getline(ss, l, '.');)
                labels.push_back(l);
            if (reverse)
                std::reverse(labels.begin(), labels.end());
            if (keep && keep < labels.size())
                labels.erase(labels.begin(), labels.end() - static_cast<long>(keep));
            std::string joined;
            for (const auto& l : labels)
                joined += (joined.empty() ? "" : ".") + l;
            out += joined;
        }
        else
            return false;
    }
    return true;
}

std::string check_host(const std::string& domain, spf_state& s, int depth);

// One mechanism: whether it matched, or the error it ran into.
enum class hit : uint8_t { no, yes, temperror, permerror };

hit mechanism(std::string_view term, const std::string& domain, spf_state& s, int depth)
{
    std::string_view name = term;
    std::string_view arg;
    const size_t colon = term.find(':');
    const size_t slash = term.find('/');
    if (colon != std::string_view::npos)
    {
        name = term.substr(0, colon);
        arg = term.substr(colon + 1);
    }
    else if (slash != std::string_view::npos)
    {
        name = term.substr(0, slash);
        arg = term.substr(slash);
    }
    const std::string n = lower(name);
    // The CIDR lengths after a domain, /v4 and //v6.
    int v4bits = 32, v6bits = 128;
    std::string_view dspec = arg;
    if (const size_t cut = arg.find('/'); cut != std::string_view::npos && n != "ip4" && n != "ip6")
    {
        std::string_view cidr = arg.substr(cut);
        dspec = arg.substr(0, cut);
        if (cidr.starts_with("//"))
            v6bits = std::atoi(std::string(cidr.substr(2)).c_str());
        else
        {
            const size_t dbl = cidr.find("//");
            v4bits = std::atoi(std::string(cidr.substr(1, dbl == std::string_view::npos ? std::string_view::npos : dbl - 1)).c_str());
            if (dbl != std::string_view::npos)
                v6bits = std::atoi(std::string(cidr.substr(dbl + 2)).c_str());
        }
    }
    std::string target = domain;
    if (!dspec.empty() && n != "ip4" && n != "ip6" && !expand(dspec, domain, s, target))
        return hit::permerror;
    const bool v6 = s.ip.find(':') != std::string::npos;
    const auto addr_match = [&](const std::string& host) -> hit {
        std::vector<std::string> addrs;
        bool nx = false;
        if (!s.r.addrs(host, addrs, nx))
            return hit::temperror;
        if (addrs.empty() && ++s.voids > 2)
            return hit::permerror;
        for (const auto& a : addrs)
            if (in_net(s.ip, a, v6 ? v6bits : v4bits))
                return hit::yes;
        return hit::no;
    };
    if (n == "all")
        return hit::yes;
    if (n == "ip4" || n == "ip6")
    {
        std::string_view net = arg;
        int bits = -1;
        if (const size_t cut = net.find('/'); cut != std::string_view::npos)
        {
            bits = std::atoi(std::string(net.substr(cut + 1)).c_str());
            net = net.substr(0, cut);
        }
        return in_net(s.ip, net, bits) ? hit::yes : hit::no;
    }
    if (++s.lookups > 10)
        return hit::permerror;
    if (n == "a")
        return addr_match(target);
    if (n == "mx")
    {
        std::vector<std::string> hosts;
        bool nx = false;
        if (!s.r.mx(target, hosts, nx))
            return hit::temperror;
        if (hosts.empty() && ++s.voids > 2)
            return hit::permerror;
        for (size_t i = 0; i < hosts.size() && i < 10; ++i)
        {
            const hit h = addr_match(hosts[i]);
            if (h != hit::no)
                return h;
        }
        return hit::no;
    }
    if (n == "include")
    {
        if (arg.empty())
            return hit::permerror;
        const std::string sub = check_host(target, s, depth + 1);
        if (sub == "pass")
            return hit::yes;
        if (sub == "temperror")
            return hit::temperror;
        if (sub == "permerror" || sub == "none")
            return hit::permerror;
        return hit::no;
    }
    if (n == "exists")
    {
        std::vector<std::string> addrs;
        bool nx = false;
        if (!s.r.addrs(target, addrs, nx))
            return hit::temperror;
        return addrs.empty() ? hit::no : hit::yes;
    }
    // ptr is not to be used (RFC 7208 5.5), and is taken as matching nothing.
    if (n == "ptr")
        return hit::no;
    return hit::permerror;
}

std::string check_host(const std::string& domain, spf_state& s, int depth)
{
    if (depth > 10 || domain.empty())
        return "permerror";
    std::vector<std::string> txts;
    bool nx = false;
    if (!s.r.txt(domain, txts, nx))
        return "temperror";
    const std::string* record = nullptr;
    for (const auto& t : txts)
        if (const std::string l = lower(t); l == "v=spf1" || l.starts_with("v=spf1 "))
        {
            if (record)
                return "permerror";
            record = &t;
        }
    if (!record)
        return "none";
    std::string redirect;
    for (const std::string_view term : words(std::string_view(*record).substr(6)))
    {
        if (term.empty())
            continue;
        if (const size_t eq = term.find('='); eq != std::string_view::npos && term.find(':') > eq)
        {
            if (lower(term.substr(0, eq)) == "redirect")
                redirect = std::string(term.substr(eq + 1));
            continue;
        }
        char q = '+';
        std::string_view m = term;
        if (m.front() == '+' || m.front() == '-' || m.front() == '~' || m.front() == '?')
        {
            q = m.front();
            m.remove_prefix(1);
        }
        const hit h = mechanism(m, domain, s, depth);
        if (h == hit::temperror)
            return "temperror";
        if (h == hit::permerror)
            return "permerror";
        if (h == hit::yes)
            return q == '+' ? "pass" : q == '-' ? "fail" : q == '~' ? "softfail" : "neutral";
    }
    if (!redirect.empty())
    {
        std::string target;
        if (!expand(redirect, domain, s, target) || ++s.lookups > 10)
            return "permerror";
        const std::string r = check_host(target, s, depth + 1);
        return r == "none" ? "permerror" : r;
    }
    return "neutral";
}

// An answer the system's resolver gave, its records of `type` as text: addresses, exchanges, or TXT strings joined.
bool parse(const uint8_t* msg, int len, uint16_t type, std::vector<std::string>& out)
{
    if (len < static_cast<int>(dns::header_len))
        return false;
    const auto n = static_cast<size_t>(len);
    uint8_t name[dns::max_name];
    size_t next = 0, at = dns::header_len;
    for (uint16_t q = dns::rd16(msg + 4); q > 0; --q)
    {
        if (dns::read_name(msg, n, at, name, next) == 0)
            return false;
        at = next + 4;
    }
    for (uint16_t an = dns::rd16(msg + 6); an > 0; --an)
    {
        if (dns::read_name(msg, n, at, name, next) == 0 || next + 10 > n)
            return false;
        const uint16_t t = dns::rd16(msg + next);
        const uint16_t rdlen = dns::rd16(msg + next + 8);
        const uint8_t* rd = msg + next + 10;
        if (next + 10 + rdlen > n)
            return false;
        if (t == type)
        {
            if (t == dns::type::A && rdlen == 4)
            {
                char buf[INET_ADDRSTRLEN];
                out.emplace_back(::inet_ntop(AF_INET, rd, buf, sizeof buf));
            }
            else if (t == dns::type::AAAA && rdlen == 16)
            {
                char buf[INET6_ADDRSTRLEN];
                out.emplace_back(::inet_ntop(AF_INET6, rd, buf, sizeof buf));
            }
            else if (t == dns::type::MX && rdlen > 2)
            {
                uint8_t ex[dns::max_name];
                size_t after = 0;
                const size_t el = dns::read_name(msg, n, next + 12, ex, after);
                if (el)
                {
                    std::string h = dns::to_text(std::string_view(reinterpret_cast<char*>(ex), el));
                    if (!h.empty() && h.back() == '.')
                        h.pop_back();
                    out.push_back(std::move(h));
                }
            }
            else if (t == dns::type::TXT)
            {
                std::string text;
                for (size_t i = 0; i < rdlen;)
                {
                    const size_t l = rd[i];
                    if (i + 1 + l > rdlen)
                        break;
                    text.append(reinterpret_cast<const char*>(rd + i + 1), l);
                    i += 1 + l;
                }
                out.push_back(std::move(text));
            }
        }
        at = next + 10 + rdlen;
    }
    return true;
}

class system_resolver : public check_resolver
{
public:
    system_resolver()
    {
        std::memset(&m_st, 0, sizeof m_st);
        m_ok = res_ninit(&m_st) == 0;
        // A test's nameserver, on a port of its own, as the loop's resolver takes it.
        const char* conf = settings::text("SOCKETLEY_RESOLV_CONF");
        if (!m_ok || !conf)
            return;
        std::ifstream in(conf);
        std::vector<in_addr> servers;
        int port = 53;
        for (std::string line; std::getline(in, line);)
        {
            std::istringstream ls(line);
            std::string key;
            ls >> key;
            if (key == "nameserver")
            {
                std::string a;
                ls >> a;
                in_addr x{};
                if (::inet_pton(AF_INET, a.c_str(), &x) == 1)
                    servers.push_back(x);
            }
            else if (key == "options")
                for (std::string o; ls >> o;)
                {
                    if (o.starts_with("port:"))
                        port = std::atoi(o.c_str() + 5);
                    else if (o.starts_with("timeout:"))
                        m_st.retrans = std::atoi(o.c_str() + 8);
                    else if (o.starts_with("attempts:"))
                        m_st.retry = std::atoi(o.c_str() + 9);
                }
        }
        m_st.nscount = 0;
        for (const auto& x : servers)
            if (m_st.nscount < MAXNS)
            {
                sockaddr_in& sa = m_st.nsaddr_list[m_st.nscount++];
                sa = sockaddr_in{};
                sa.sin_family = AF_INET;
                sa.sin_port = htons(static_cast<uint16_t>(port));
                sa.sin_addr = x;
            }
    }
    ~system_resolver() override
    {
        if (m_ok)
            res_nclose(&m_st);
    }
    bool txt(const std::string& name, std::vector<std::string>& out, bool& nx) override
    {
        return ask(name, dns::type::TXT, out, nx);
    }
    bool addrs(const std::string& name, std::vector<std::string>& out, bool& nx) override
    {
        bool nx6 = false;
        std::vector<std::string> v6;
        const bool a = ask(name, dns::type::A, out, nx);
        const bool b = ask(name, dns::type::AAAA, v6, nx6);
        out.insert(out.end(), v6.begin(), v6.end());
        return a || b;
    }
    bool mx(const std::string& name, std::vector<std::string>& out, bool& nx) override
    {
        return ask(name, dns::type::MX, out, nx);
    }

private:
    bool ask(const std::string& name, uint16_t type, std::vector<std::string>& out, bool& nx)
    {
        nx = false;
        if (!m_ok)
            return false;
        uint8_t buf[8192];
        const int n = res_nquery(&m_st, name.c_str(), ns_c_in, type, buf, sizeof buf);
        if (n < 0)
        {
            // No such name and no record of the type are answers; anything else is a failure to ask.
            nx = m_st.res_h_errno == HOST_NOT_FOUND;
            return m_st.res_h_errno == HOST_NOT_FOUND || m_st.res_h_errno == NO_DATA;
        }
        return parse(buf, n, type, out);
    }

    struct __res_state m_st;
    bool m_ok{false};
};

}   // namespace

std::unique_ptr<check_resolver> system_check_resolver()
{
    return std::make_unique<system_resolver>();
}

std::string organizational_domain(std::string_view domain)
{
    return socketley::public_suffix::registrable(domain);
}

std::string spf_check(const std::string& ip, const std::string& domain, const std::string& sender, check_resolver& r)
{
    spf_state s{ip, sender, r};
    return check_host(lower(domain), s, 0);
}

std::string inbound_result::header() const
{
    std::string out = "spf=" + spf + (spf_domain.empty() ? std::string() : " smtp.mailfrom=" + spf_domain);
    if (dkim.empty())
        out += "; dkim=none";
    for (const auto& [res, d] : dkim)
        out += "; dkim=" + res + " header.d=" + d;
    out += "; dmarc=" + dmarc + (from_domain.empty() ? std::string() : " header.from=" + from_domain);
    if (dmarc == "fail" && !dmarc_policy.empty())
        out += " (p=" + dmarc_policy + ")";
    return out;
}

inbound_result check_inbound(std::string_view message, const std::string& ip, const std::string& helo,
                             const std::string& mail_from, check_resolver& r, int64_t now_s)
{
    inbound_result out;
    // SPF of the envelope sender's domain, or of HELO's for a bounce (RFC 7208 2.4).
    const size_t at = mail_from.rfind('@');
    out.spf_domain = lower(at == std::string::npos ? helo : mail_from.substr(at + 1));
    out.spf = spf_check(ip, out.spf_domain, mail_from.empty() ? "postmaster@" + out.spf_domain : mail_from, r);

    for (const auto& sig : dkim::signatures(message))
    {
        if (out.dkim.size() >= 5)
            break;
        std::vector<std::string> txts;
        bool nx = false;
        std::string record;
        dkim::result res = dkim::result::permerror;
        if (!r.txt(sig.s + "._domainkey." + sig.d, txts, nx))
            res = dkim::result::temperror;
        else
        {
            for (const auto& t : txts)
                if (t.find("p=") != std::string::npos)
                {
                    record = t;
                    break;
                }
            res = dkim::verify(message, sig, record, now_s);
        }
        out.dkim.emplace_back(dkim::result_name(res), sig.d);
    }

    // DMARC of the domain From names, the one a reader sees.
    std::vector<address> from;
    const std::string from_header = header_value(header_block(message), "From");
    if (!parse_mailbox_list(from_header, from) || from.size() != 1 || from[0].domain.empty())
    {
        out.dmarc = "permerror";
        return out;
    }
    out.from_domain = from[0].domain;
    const std::string org = organizational_domain(out.from_domain);
    std::string record;
    bool from_org = false;
    for (const std::string& d : {out.from_domain, org})
    {
        std::vector<std::string> txts;
        bool nx = false;
        if (!r.txt("_dmarc." + d, txts, nx))
        {
            out.dmarc = "temperror";
            return out;
        }
        for (const auto& t : txts)
            if (lower(t.substr(0, 8)) == "v=dmarc1")
                record = t;
        if (!record.empty())
        {
            from_org = d != out.from_domain;
            break;
        }
        if (d == org)
            break;
    }
    if (record.empty())
    {
        out.dmarc = "none";
        return out;
    }
    std::string p = "none", sp, adkim = "r", aspf = "r";
    std::string_view rest = record;
    while (!rest.empty())
    {
        const size_t semi = rest.find(';');
        std::string_view tag = rest.substr(0, semi);
        rest = semi == std::string_view::npos ? std::string_view{} : rest.substr(semi + 1);
        while (!tag.empty() && tag.front() == ' ')
            tag.remove_prefix(1);
        while (!tag.empty() && tag.back() == ' ')
            tag.remove_suffix(1);
        const size_t eq = tag.find('=');
        if (eq == std::string_view::npos)
            continue;
        const std::string k = lower(tag.substr(0, eq));
        const std::string v = lower(tag.substr(eq + 1));
        if (k == "p")
            p = v;
        else if (k == "sp")
            sp = v;
        else if (k == "adkim")
            adkim = v;
        else if (k == "aspf")
            aspf = v;
    }
    const auto aligned = [&](const std::string& d, const std::string& mode) {
        return mode == "s" ? lower(d) == out.from_domain : organizational_domain(d) == org;
    };
    bool pass = out.spf == "pass" && aligned(out.spf_domain, aspf);
    for (const auto& [res, d] : out.dkim)
        pass = pass || (res == "pass" && aligned(d, adkim));
    out.dmarc = pass ? "pass" : "fail";
    out.dmarc_policy = from_org && !sp.empty() ? sp : p;
    return out;
}

}   // namespace socketley::mail
