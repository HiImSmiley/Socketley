#pragma once
// What a mail runtime checks of mail from elsewhere before it says 250: SPF (RFC 7208) for the address of the sender's
// domain, every DKIM signature (RFC 6376), and DMARC (RFC 7489) for the domain of From, whose policy may send the
// message to the Junk folder or refuse it.  Blocking functions of a resolver given them, so they run on a helper
// thread and a test hands them records of its own.
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace socketley::mail
{

// The DNS the checks ask; each answers false when the lookup failed (a temporary error), and `nx` for no such name.
struct check_resolver
{
    virtual ~check_resolver() = default;
    virtual bool txt(const std::string& name, std::vector<std::string>& out, bool& nx) = 0;
    // The addresses of a name, as text.
    virtual bool addrs(const std::string& name, std::vector<std::string>& out, bool& nx) = 0;
    // Its IPv4 addresses alone, as exists asks (RFC 7208 5.7).
    virtual bool addrs4(const std::string& name, std::vector<std::string>& out, bool& nx)
    {
        std::vector<std::string> all;
        if (!addrs(name, all, nx))
            return false;
        for (auto& a : all)
            if (a.find(':') == std::string::npos)
                out.push_back(std::move(a));
        return true;
    }
    virtual bool mx(const std::string& name, std::vector<std::string>& out, bool& nx) = 0;
    // The names an address's PTR records give it, for a check of this host's own; none where it is not asked.
    virtual bool ptr(const std::string& /*ip*/, std::vector<std::string>& /*out*/, bool& nx)
    {
        nx = false;
        return false;
    }
};

// The system's resolver, through res_nquery, pointed at the servers of SOCKETLEY_RESOLV_CONF where it is set; its
// state and the last minute's answers are the calling thread's, and a lookup past `budget_ms` from now fails.
std::unique_ptr<check_resolver> system_check_resolver(int64_t budget_ms = 20000);
// One query of that resolver, its answer in `buf`: its length, or -1 with `answered` where the name or the type
// does not exist and `no_domain` where the name does not.
int system_query(const std::string& name, int type, uint8_t* buf, int len, bool& no_domain, bool& answered);

// SPF's verdict for `ip` sending as `domain` (pass, fail, softfail, neutral, none, temperror, permerror), `helo` what
// %{h} stands for.
std::string spf_check(const std::string& ip, const std::string& domain, const std::string& sender, check_resolver& r,
                      const std::string& helo = {});

struct inbound_result
{
    std::string spf;
    std::string spf_domain;
    // Each signature's result and its domain.
    std::vector<std::pair<std::string, std::string>> dkim;
    std::string dmarc;
    std::string dmarc_policy;
    std::string from_domain;
    // The ARC chain: none, pass or fail, its sets, the newest sealer, and whether that sealer's word let a message
    // that failed DMARC through.
    std::string arc{"none"};
    int arc_sets{0};
    std::string arc_sealer;
    bool arc_vouched{false};
    // The DMARC record's domain and what it published, for the aggregate report its rua asks for.
    std::string policy_domain, rua, adkim{"r"}, aspf{"r"}, p{"none"}, sp;
    int pct{100};
    // Whether SPF and a DKIM signature passed aligned with From, as a report's policy_evaluated says.
    bool spf_aligned{false}, dkim_aligned{false};
    // Why it is refused where that is not a domain's policy.
    std::string why;
    // The value of the Authentication-Results this host writes, after its own name.
    std::string header() const;
    bool reject() const { return dmarc == "fail" && dmarc_policy == "reject"; }
    bool quarantine() const { return dmarc == "fail" && dmarc_policy == "quarantine"; }
};

// Every check of `message`, received from `ip` that said HELO `helo` and MAIL FROM `mail_from` (empty for a bounce);
// a passing ARC chain sealed last by one of `arc_trusted` stands in for a failed DMARC.
inbound_result check_inbound(std::string_view message, const std::string& ip, const std::string& helo,
                             const std::string& mail_from, check_resolver& r, int64_t now_s,
                             const std::vector<std::string>& arc_trusted = {});

// The domain DMARC's relaxed alignment compares, its registrable domain by the Public Suffix List.
std::string organizational_domain(std::string_view domain);

}   // namespace socketley::mail
