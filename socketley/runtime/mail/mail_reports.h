#pragma once
// The reports other domains ask for of the mail this runtime takes and sends: DMARC aggregate reports (RFC 7489 7.2)
// to the rua of each domain whose mail it checked, and TLS reports (RFC 8460) to the rua of each domain it sent to
// under an MTA-STS or DANE policy.  A day's results are counted in memory and written up when the day turns, in UTC,
// as gzip'd XML and JSON; what a shard counted it reports itself, under a report id of its own.
#include <cstdint>
#include <map>
#include <string>
#include <tuple>
#include <vector>

namespace socketley::mail
{

struct report_mail
{
    // The mailto: addresses it goes to, its subject, extra headers, and its one attachment.
    std::vector<std::string> to;
    std::string subject;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string filename, content_type, data;
};

class reports
{
public:
    // A message whose From domain's DMARC record named `rua`: what was published, where it came from and what the
    // checks and the policy made of it.
    struct dmarc_seen
    {
        std::string policy_domain, rua, adkim{"r"}, aspf{"r"}, p{"none"}, sp, header_from, source_ip, disposition{"none"};
        int pct{100};
        bool dkim_pass{false}, spf_pass{false};
        std::vector<std::pair<std::string, std::string>> dkim;   // domain, result
        std::string spf_domain, spf_result;
    };
    void dmarc(const dmarc_seen& s);

    // A session to an exchanger of `domain`, under the policy of `type` (sts or tlsa) that `lines` wrote, which
    // succeeded or failed as `failure` (RFC 8460 4.3's result types) says.
    void tls(const std::string& domain, const std::string& type, const std::vector<std::string>& lines,
             const std::string& mx, bool success, const std::string& failure, const std::string& mx_ip,
             const std::string& sending_ip);

    // The reports of a day that has ended, once `now_s` is past it; the TLS ones still need their domain's rua,
    // looked up by the caller (_smtp._tls.<domain>), and are handed with `to` empty and the domain as a header.
    std::vector<report_mail> due(int64_t now_s, const std::string& organization, const std::string& contact);

    static std::string gzip(const std::string& data);

private:
    int64_t m_day{-1};
    // DMARC rows: by policy domain, what was published and the rows by their fields, each a count.
    struct published
    {
        std::string rua, adkim, aspf, p, sp;
        int pct{100};
        std::map<std::string, uint64_t> rows;
    };
    std::map<std::string, published> m_dmarc;
    struct tls_domain
    {
        std::string type;
        std::vector<std::string> lines, mx;
        uint64_t ok{0}, failed{0};
        std::map<std::tuple<std::string, std::string, std::string, std::string>, uint64_t> failures;
    };
    std::map<std::string, tls_domain> m_tls;
    uint64_t m_serial{0};
    void roll(int64_t now_s);
};

}   // namespace socketley::mail
