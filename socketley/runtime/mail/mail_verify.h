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
    virtual bool mx(const std::string& name, std::vector<std::string>& out, bool& nx) = 0;
};

// The system's resolver, through res_nquery, pointed at the servers of SOCKETLEY_RESOLV_CONF where it is set.
std::unique_ptr<check_resolver> system_check_resolver();

// SPF's verdict for `ip` sending as `domain` (pass, fail, softfail, neutral, none, temperror, permerror).
std::string spf_check(const std::string& ip, const std::string& domain, const std::string& sender, check_resolver& r);

struct inbound_result
{
    std::string spf;
    std::string spf_domain;
    // Each signature's result and its domain.
    std::vector<std::pair<std::string, std::string>> dkim;
    std::string dmarc;
    std::string dmarc_policy;
    std::string from_domain;
    // The value of the Authentication-Results this host writes, after its own name.
    std::string header() const;
    bool reject() const { return dmarc == "fail" && dmarc_policy == "reject"; }
    bool quarantine() const { return dmarc == "fail" && dmarc_policy == "quarantine"; }
};

// Every check of `message`, received from `ip` that said HELO `helo` and MAIL FROM `mail_from` (empty for a bounce).
inbound_result check_inbound(std::string_view message, const std::string& ip, const std::string& helo,
                             const std::string& mail_from, check_resolver& r, int64_t now_s);

// The domain DMARC's relaxed alignment compares, its registrable domain by the Public Suffix List.
std::string organizational_domain(std::string_view domain);

}   // namespace socketley::mail
