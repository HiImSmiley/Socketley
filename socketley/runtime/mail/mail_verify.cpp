#include "mail_verify.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>

#include "mail_arc.h"
#include "mail_compose.h"
#include "mail_dkim.h"
#include "../dns/dns_wire.h"
#include "../../shared/crypto/mac.h"
#include "../../shared/net/idna.h"
#include "../../shared/net/public_suffix.h"
#include "../../shared/util/ascii.h"
#include "../../shared/util/random_id.h"
#include "../../shared/util/settings.h"
#include "../../shared/util/wall_clock.h"

namespace socketley::mail
{

namespace
{

// A key of this process's own for DMARC's pct= sample, which no sender can compute offline.
const std::string& sample_key()
{
    static const std::string key = [] {
        std::string k(32, '\0');
        if (!socketley::random_bytes(k.data(), k.size()))
            for (size_t i = 0; i + 8 <= k.size(); i += 8)
            {
                const uint64_t v = socketley::random_u64();
                std::memcpy(k.data() + i, &v, sizeof v);
            }
        return k;
    }();
    return key;
}

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
    const std::string& helo;
    int lookups{0};
    int voids{0};
};

// An IPv6 address as %{i} writes it, its 32 nibbles dot-separated (RFC 7208 7.3); an IPv4 one as it is.
std::string macro_ip(const std::string& ip)
{
    unsigned char a[16];
    if (ip.find(':') == std::string::npos || ::inet_pton(AF_INET6, ip.c_str(), a) != 1)
        return ip;
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    for (const unsigned char b : a)
    {
        out += (out.empty() ? "" : ".");
        out += hex[b >> 4];
        out += '.';
        out += hex[b & 15];
    }
    return out;
}

// A length after a slash, read strictly: digits up to `max`, or -1 for none that is one.
int cidr_bits(std::string_view s, int max)
{
    if (s.empty() || s.size() > 3 || !std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; }))
        return -1;
    const int n = std::atoi(std::string(s).c_str());
    return n <= max ? n : -1;
}

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
            const char given = spec[i + 1];
            const char letter = socketley::ascii::lower(given);
            std::string_view tr = spec.substr(i + 2, close - i - 2);
            i = close;
            std::string v;
            switch (letter)
            {
                case 's': v = s.sender; break;
                case 'l': v = local; break;
                case 'o': v = sdom; break;
                case 'd': v = domain; break;
                case 'i': v = macro_ip(s.ip); break;
                case 'h': v = s.helo.empty() ? domain : s.helo; break;
                case 'v': v = s.ip.find(':') == std::string::npos ? "in-addr" : "ip6"; break;
                default: return false;
            }
            // Digits keep that many labels from the right, r reverses them first, and what follows names the
            // delimiters the value is split on, a dot where none is named (RFC 7208 7.1).
            size_t keep = 0;
            bool reverse = false;
            while (!tr.empty() && std::isdigit(static_cast<unsigned char>(tr.front())))
            {
                keep = keep * 10 + static_cast<size_t>(tr.front() - '0');
                tr.remove_prefix(1);
            }
            if (!tr.empty() && socketley::ascii::lower(tr.front()) == 'r')
            {
                reverse = true;
                tr.remove_prefix(1);
            }
            if (tr.find_first_not_of(".-+,/_=") != std::string_view::npos)
                return false;
            const std::string_view delims = tr.empty() ? std::string_view(".") : tr;
            std::vector<std::string> labels;
            for (size_t from = 0;;)
            {
                const size_t cut = v.find_first_of(delims, from);
                labels.push_back(v.substr(from, cut == std::string::npos ? std::string::npos : cut - from));
                if (cut == std::string::npos)
                    break;
                from = cut + 1;
            }
            if (reverse)
                std::reverse(labels.begin(), labels.end());
            if (keep && keep < labels.size())
                labels.erase(labels.begin(), labels.end() - static_cast<long>(keep));
            std::string joined;
            for (size_t i = 0; i < labels.size(); ++i)
            {
                if (i)
                    joined += '.';
                joined += labels[i];
            }
            // An upper-case letter asks for the value URL-escaped (RFC 7208 7.3).
            if (given != letter)
            {
                static constexpr char hex[] = "0123456789ABCDEF";
                std::string esc;
                for (const char c : joined)
                {
                    const auto u = static_cast<unsigned char>(c);
                    if (std::isalnum(u) || c == '-' || c == '.' || c == '_' || c == '~')
                        esc += c;
                    else
                    {
                        esc += '%';
                        esc += hex[u >> 4];
                        esc += hex[u & 15];
                    }
                }
                joined = std::move(esc);
            }
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
        // A length that is not one is a syntax error, not /0 (RFC 7208 5.6).
        if (cidr.starts_with("//"))
            v6bits = cidr_bits(cidr.substr(2), 128);
        else
        {
            const size_t dbl = cidr.find("//");
            v4bits = cidr_bits(cidr.substr(1, dbl == std::string_view::npos ? std::string_view::npos : dbl - 1), 32);
            if (dbl != std::string_view::npos)
                v6bits = cidr_bits(cidr.substr(dbl + 2), 128);
        }
        if (v4bits < 0 || v6bits < 0)
            return hit::permerror;
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
            bits = cidr_bits(net.substr(cut + 1), n == "ip4" ? 32 : 128);
            if (bits < 0)
                return hit::permerror;
            net = net.substr(0, cut);
        }
        unsigned char probe[16];
        if (::inet_pton(n == "ip4" ? AF_INET : AF_INET6, std::string(net).c_str(), probe) != 1)
            return hit::permerror;
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
        if (!s.r.addrs4(target, addrs, nx))
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
    // redirect= and exp= each at most once, wherever in the record and whatever matches first (RFC 7208 6).
    int redirects = 0, exps = 0;
    for (const std::string_view term : words(std::string_view(*record).substr(6)))
        if (const size_t eq = term.find('='); eq != std::string_view::npos && term.find(':') > eq)
        {
            const std::string name = lower(term.substr(0, eq));
            redirects += name == "redirect";
            exps += name == "exp";
        }
    if (redirects > 1 || exps > 1)
        return "permerror";
    std::string redirect;
    for (const std::string_view term : words(std::string_view(*record).substr(6)))
    {
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
            else if (t == dns::type::PTR && rdlen > 0)
            {
                uint8_t pn[dns::max_name];
                size_t after = 0;
                if (const size_t pl = dns::read_name(msg, n, next + 10, pn, after))
                {
                    std::string h = dns::to_text(std::string_view(reinterpret_cast<char*>(pn), pl));
                    if (!h.empty() && h.back() == '.')
                        h.pop_back();
                    out.push_back(std::move(h));
                }
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

// A helper thread's resolver state, made once and kept, with the answers it had in the last minute.
struct thread_resolver
{
    struct __res_state st;
    bool ok{false};
    struct cached
    {
        bool ok{false};
        bool nx{false};
        std::vector<std::string> out;
        int64_t until_ms{0};
    };
    std::unordered_map<std::string, cached> answers;
    thread_resolver();
    ~thread_resolver()
    {
        if (ok)
            res_nclose(&st);
    }
};

thread_resolver& resolver_here()
{
    static thread_local thread_resolver t;
    return t;
}

class system_resolver : public check_resolver
{
public:
    explicit system_resolver(int64_t budget_ms) : m_deadline_ms(socketley::wall::now_ms() + budget_ms) {}
    bool txt(const std::string& name, std::vector<std::string>& out, bool& nx) override
    {
        return ask(name, dns::type::TXT, out, nx);
    }
    bool addrs(const std::string& name, std::vector<std::string>& out, bool& nx) override
    {
        // Both families answered, each with addresses or none; one that failed is a failure of the whole.
        bool nx6 = false;
        std::vector<std::string> v6;
        const bool a = ask(name, dns::type::A, out, nx);
        const bool b = ask(name, dns::type::AAAA, v6, nx6);
        out.insert(out.end(), v6.begin(), v6.end());
        nx = nx && nx6;
        return a && b;
    }
    bool addrs4(const std::string& name, std::vector<std::string>& out, bool& nx) override
    {
        return ask(name, dns::type::A, out, nx);
    }
    bool mx(const std::string& name, std::vector<std::string>& out, bool& nx) override
    {
        return ask(name, dns::type::MX, out, nx);
    }
    bool ptr(const std::string& ip, std::vector<std::string>& out, bool& nx) override
    {
        in_addr a{};
        if (::inet_pton(AF_INET, ip.c_str(), &a) != 1)
            return false;
        const auto* b = reinterpret_cast<const unsigned char*>(&a.s_addr);
        return ask(std::to_string(b[3]) + "." + std::to_string(b[2]) + "." + std::to_string(b[1]) + "." +
                       std::to_string(b[0]) + ".in-addr.arpa",
                   dns::type::PTR, out, nx);
    }

private:
    bool ask(const std::string& name, uint16_t type, std::vector<std::string>& out, bool& nx)
    {
        nx = false;
        thread_resolver& t = resolver_here();
        if (!t.ok)
            return false;
        const int64_t now = socketley::wall::now_ms();
        const std::string key = std::to_string(type) + " " + name;
        if (const auto it = t.answers.find(key); it != t.answers.end() && it->second.until_ms > now)
        {
            nx = it->second.nx;
            out.insert(out.end(), it->second.out.begin(), it->second.out.end());
            return it->second.ok;
        }
        // A message's checks have a budget, past which a lookup is a temporary failure rather than a wait.
        if (now >= m_deadline_ms)
            return false;
        uint8_t buf[8192];
        thread_resolver::cached c;
        const int n = res_nquery(&t.st, name.c_str(), ns_c_in, type, buf, sizeof buf);
        if (n < 0)
        {
            // No such name and no record of the type are answers; anything else is a failure to ask.
            c.nx = t.st.res_h_errno == HOST_NOT_FOUND;
            c.ok = t.st.res_h_errno == HOST_NOT_FOUND || t.st.res_h_errno == NO_DATA;
        }
        else
            c.ok = parse(buf, n, type, c.out);
        // An answer is kept a minute, a failure not at all.
        if (c.ok)
        {
            if (t.answers.size() >= 8192)
                t.answers.clear();
            c.until_ms = now + 60000;
            t.answers[key] = c;
        }
        nx = c.nx;
        out.insert(out.end(), c.out.begin(), c.out.end());
        return c.ok;
    }

    int64_t m_deadline_ms;
};

thread_resolver::thread_resolver()
{
    std::memset(&st, 0, sizeof st);
    ok = res_ninit(&st) == 0;
    // Each query is tried twice, two seconds apart, unless a test's configuration says otherwise.
    st.retrans = 2;
    st.retry = 2;
    // A test's nameserver, on a port of its own, as the loop's resolver takes it.
    const char* conf = settings::text("SOCKETLEY_RESOLV_CONF");
    if (!ok || !conf)
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
                    st.retrans = std::atoi(o.c_str() + 8);
                else if (o.starts_with("attempts:"))
                    st.retry = std::atoi(o.c_str() + 9);
            }
    }
    st.nscount = 0;
    for (const auto& x : servers)
        if (st.nscount < MAXNS)
        {
            sockaddr_in& sa = st.nsaddr_list[st.nscount++];
            sa = sockaddr_in{};
            sa.sin_family = AF_INET;
            sa.sin_port = htons(static_cast<uint16_t>(port));
            sa.sin_addr = x;
        }
}

}   // namespace

int system_query(const std::string& name, int type, uint8_t* buf, int len, bool& no_domain, bool& answered)
{
    thread_resolver& t = resolver_here();
    no_domain = answered = false;
    if (!t.ok)
        return -1;
    const int n = res_nquery(&t.st, name.c_str(), ns_c_in, type, buf, len);
    if (n < 0)
    {
        no_domain = t.st.res_h_errno == HOST_NOT_FOUND;
        answered = no_domain || t.st.res_h_errno == NO_DATA;
    }
    else
        answered = true;
    return n;
}

std::unique_ptr<check_resolver> system_check_resolver(int64_t budget_ms)
{
    return std::make_unique<system_resolver>(budget_ms);
}

std::string organizational_domain(std::string_view domain)
{
    return socketley::public_suffix::registrable(domain);
}

std::string spf_check(const std::string& ip, const std::string& domain, const std::string& sender, check_resolver& r,
                      const std::string& helo)
{
    spf_state s{ip, sender, r, helo};
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
    if (arc != "none")
        out += "; arc=" + arc + " (i=" + std::to_string(arc_sets) + (arc_sealer.empty() ? "" : " d=" + arc_sealer) +
               (arc_vouched ? ", vouched" : "") + ")";
    return out;
}

inbound_result check_inbound(std::string_view message, const std::string& ip, const std::string& helo,
                             const std::string& mail_from, check_resolver& r, int64_t now_s,
                             const std::vector<std::string>& arc_trusted)
{
    inbound_result out;
    const std::string_view head = header_block(message);
    const std::string from_header = header_value(head, "From");
    std::vector<address> from;
    const size_t authors = from_headers(head);
    const bool authors_ok = parse_mailbox_list(from_header, from) && !from.empty() && authors == 1 &&
                            std::all_of(from.begin(), from.end(), [&](const address& a) {
                                return !a.domain.empty() && a.domain == from[0].domain;
                            });
    // A name past ASCII is looked up and compared as its A-labels, as DNS and a signature's d= write it.
    const std::string author_domain = authors_ok ? socketley::idna::to_ascii(lower(from[0].domain)) : std::string();
    const std::string org = author_domain.empty() ? std::string() : organizational_domain(author_domain);
    // The From domain's DMARC record is read before any name the sender chose, so names it makes slow cannot spend
    // the lookup budget the policy needs.
    std::string policy;
    bool at_org = false, policy_unread = false;
    for (const std::string& d : {author_domain, org})
    {
        if (d.empty())
            break;
        std::vector<std::string> txts;
        bool nx = false;
        if (!r.txt("_dmarc." + d, txts, nx))
        {
            policy_unread = true;
            break;
        }
        // A record begins v=DMARC1 and a ; or its end; two of them at one name are none (RFC 7489 6.6.3).
        size_t found = 0;
        for (const auto& t : txts)
        {
            const std::string l = lower(t);
            size_t q = 0;
            while (q < l.size() && l[q] == ' ')
                ++q;
            if (l.compare(q, 8, "v=dmarc1") != 0)
                continue;
            q += 8;
            while (q < l.size() && l[q] == ' ')
                ++q;
            if (q < l.size() && l[q] != ';')
                continue;
            ++found;
            policy = t;
        }
        if (found > 1)
            policy.clear();
        if (found > 0)
        {
            at_org = d != author_domain;
            break;
        }
        if (d == org)
            break;
    }

    // SPF of the envelope sender's domain, or of HELO's for a bounce (RFC 7208 2.4).
    const size_t at = mail_from.rfind('@');
    out.spf_domain = socketley::idna::to_ascii(lower(at == std::string::npos ? helo : mail_from.substr(at + 1)));
    out.spf = spf_check(ip, out.spf_domain, mail_from.empty() ? "postmaster@" + out.spf_domain : mail_from, r, helo);

    // A selector's key record: the one TXT that holds a key, empty where there is none.
    const auto key_of = [&r](const std::string& name, std::string& record) {
        std::vector<std::string> txts;
        bool nx = false;
        if (!r.txt(name, txts, nx))
            return false;
        record.clear();
        for (const auto& t : txts)
            if (t.find("p=") != std::string::npos)
            {
                record = t;
                break;
            }
        return true;
    };
    std::string from_org;
    {
        std::vector<address> a;
        if (parse_mailbox_list(from_header, a) && !a.empty())
            from_org = organizational_domain(socketley::idna::to_ascii(lower(a[0].domain)));
    }
    // Ten at most are checked, those of the From's organization first, so one that aligns is never left past the cap.
    auto sigs = dkim::signatures(message);
    std::stable_partition(sigs.begin(), sigs.end(),
                          [&](const dkim::signature& s) { return organizational_domain(s.d) == from_org; });
    dkim::bodies bodies;
    for (const auto& sig : sigs)
    {
        if (out.dkim.size() >= 10)
            break;
        std::string record;
        const dkim::result res = !key_of(sig.s + "._domainkey." + sig.d, record)
                                     ? dkim::result::temperror
                                     : dkim::verify(message, sig, record, now_s, nullptr, &bodies);
        out.dkim.emplace_back(dkim::result_name(res), sig.d);
    }
    const arc::chain chain = arc::verify(message, key_of, now_s);
    out.arc = chain.result;
    out.arc_sets = chain.count;
    out.arc_sealer = chain.sealer;

    // DMARC of the domain From names, the one a reader sees.
    // A message with no From names no author to pass for, and DMARC has nothing to say of it.
    if (authors == 0)
    {
        out.dmarc = "none";
        return out;
    }
    // One whose author cannot be told -- two From headers, one that does not read, or authors of several domains --
    // would pass DMARC by no domain's policy, so it is refused as a failing one would be (RFC 7489 6.6.1).
    if (!authors_ok)
    {
        out.dmarc = "fail";
        out.dmarc_policy = "reject";
        out.why = "its From names no single author's domain";
        return out;
    }
    out.from_domain = author_domain;
    if (out.from_domain.empty())
    {
        out.dmarc = "permerror";
        return out;
    }
    if (policy_unread)
    {
        out.dmarc = "temperror";
        return out;
    }
    const auto aligned = [&](const std::string& d, const std::string& mode) {
        const std::string a = socketley::idna::to_ascii(lower(d));
        return mode == "s" ? a == out.from_domain : organizational_domain(a) == org;
    };
    if (policy.empty())
    {
        // With no policy the alignment is still told, relaxed, for what trusts a sender that is who it says.
        out.spf_aligned = out.spf == "pass" && aligned(out.spf_domain, "r");
        for (const auto& [res, d] : out.dkim)
            out.dkim_aligned = out.dkim_aligned || (res == "pass" && aligned(d, "r"));
        out.dmarc = "none";
        return out;
    }
    std::string p = "none", sp, adkim = "r", aspf = "r";
    int pct = 100;
    std::string_view rest = policy;
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
        std::string_view kk = tag.substr(0, eq);
        std::string_view vv = tag.substr(eq + 1);
        while (!kk.empty() && (kk.back() == ' ' || kk.back() == '\t'))
            kk.remove_suffix(1);
        while (!vv.empty() && (vv.front() == ' ' || vv.front() == '\t'))
            vv.remove_prefix(1);
        const std::string k = lower(kk);
        const std::string v = lower(vv);
        if (k == "p")
            p = v;
        else if (k == "sp")
            sp = v;
        else if (k == "adkim")
            adkim = v;
        else if (k == "aspf")
            aspf = v;
        else if (k == "pct" && !v.empty() && v.size() <= 3 &&
                 std::all_of(v.begin(), v.end(), [](char c) { return c >= '0' && c <= '9'; }))
            pct = std::min(100, std::atoi(v.c_str()));
        else if (k == "rua")
            out.rua = std::string(tag.substr(eq + 1));
    }
    out.policy_domain = at_org ? org : out.from_domain;
    out.adkim = adkim;
    out.aspf = aspf;
    out.p = p;
    out.sp = sp;
    out.pct = pct;
    out.spf_aligned = out.spf == "pass" && aligned(out.spf_domain, aspf);
    for (const auto& [res, d] : out.dkim)
        out.dkim_aligned = out.dkim_aligned || (res == "pass" && aligned(d, adkim));
    const bool pass = out.spf_aligned || out.dkim_aligned;
    out.dmarc = pass ? "pass" : "fail";
    out.dmarc_policy = at_org && !sp.empty() ? sp : p;
    if (pass)
        return out;
    // pct= samples the failing mail the policy is for; the rest is taken by the policy below it (RFC 7489 6.6.4),
    // the sample the same for every copy of one message and, keyed by this process, not the sender's to pick.
    if (pct < 100)
    {
        const std::string mac =
            socketley::crypto::hmac_sha256(sample_key(), out.from_domain + "\n" + header_value(head, "Message-ID"));
        uint64_t h = 0;
        for (size_t i = 0; i < 8 && i < mac.size(); ++i)
            h = h << 8 | static_cast<uint8_t>(mac[i]);
        if (mac.size() == socketley::crypto::sha256_bytes && static_cast<int>(h % 100) >= pct)
            out.dmarc_policy = out.dmarc_policy == "reject" ? "quarantine" : "none";
    }
    // A forwarder trusted here vouches with a passing chain for what it broke (RFC 8617 7.2).
    if (out.arc == "pass" && std::find(arc_trusted.begin(), arc_trusted.end(), out.arc_sealer) != arc_trusted.end())
    {
        out.arc_vouched = true;
        out.dmarc_policy = "none";
    }
    return out;
}

}   // namespace socketley::mail
