#include "mail_reports.h"

#include <algorithm>
#include <ctime>

#include "../../shared/json/json_escape.h"
#include "../../shared/util/crc.h"
#include "../../shared/util/random_id.h"

namespace socketley::mail
{

namespace
{

constexpr int64_t day_s = 86400;

std::string xml(std::string_view s)
{
    std::string out;
    for (const char c : s)
        switch (c)
        {
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '&': out += "&amp;"; break;
            case '"': out += "&quot;"; break;
            default:
                if (static_cast<unsigned char>(c) >= 0x20 || c == '\t')
                    out += c;
        }
    return out;
}

std::string iso(int64_t t)
{
    std::tm tm{};
    const time_t tt = static_cast<time_t>(t);
    ::gmtime_r(&tt, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

// Fields of a row joined by a byte no field holds, so a map counts the rows alike.
std::string row_key(const std::vector<std::string>& fields)
{
    std::string out;
    for (const auto& f : fields)
    {
        for (const char c : f)
            out.push_back(c == '\x1f' ? ' ' : c);
        out.push_back('\x1f');
    }
    return out;
}

std::vector<std::string> row_fields(const std::string& key)
{
    std::vector<std::string> out;
    size_t at = 0;
    for (size_t sep = key.find('\x1f'); sep != std::string::npos; sep = key.find('\x1f', at))
    {
        out.push_back(key.substr(at, sep - at));
        at = sep + 1;
    }
    return out;
}

}   // namespace

std::string reports::gzip(const std::string& data)
{
    // RFC 1952 around stored deflate blocks (RFC 1951 3.2.4): a valid gzip every reader opens, the reports small.
    std::string out = {'\x1f', '\x8b', '\x08', '\0', '\0', '\0', '\0', '\0', '\0', '\x03'};
    size_t at = 0;
    do
    {
        const size_t n = std::min<size_t>(65535, data.size() - at);
        const bool last = at + n >= data.size();
        out += static_cast<char>(last ? 1 : 0);
        out += static_cast<char>(n & 0xFF);
        out += static_cast<char>(n >> 8);
        out += static_cast<char>(~n & 0xFF);
        out += static_cast<char>((~n >> 8) & 0xFF);
        out.append(data, at, n);
        at += n;
    } while (at < data.size());
    const uint32_t c = socketley::crc::crc32(data);
    const auto size = static_cast<uint32_t>(data.size());
    for (int i = 0; i < 4; ++i)
        out += static_cast<char>((c >> (8 * i)) & 0xFF);
    for (int i = 0; i < 4; ++i)
        out += static_cast<char>((size >> (8 * i)) & 0xFF);
    return out;
}

void reports::roll(int64_t now_s)
{
    if (m_day < 0)
        m_day = now_s / day_s;
}

void reports::dmarc(const dmarc_seen& s)
{
    roll(static_cast<int64_t>(::time(nullptr)));
    if (s.rua.empty() || s.policy_domain.empty())
        return;
    if (m_dmarc.size() >= 10000 && !m_dmarc.count(s.policy_domain))
        return;
    published& p = m_dmarc[s.policy_domain];
    p.rua = s.rua;
    p.adkim = s.adkim;
    p.aspf = s.aspf;
    p.p = s.p;
    p.sp = s.sp;
    p.pct = s.pct;
    std::vector<std::string> f = {s.source_ip, s.disposition, s.dkim_pass ? "pass" : "fail", s.spf_pass ? "pass" : "fail",
                                  s.header_from, s.spf_domain, s.spf_result};
    for (const auto& [d, r] : s.dkim)
    {
        f.push_back(d);
        f.push_back(r);
    }
    // A bound on what one day of a stranger's mail can grow to.
    if (p.rows.size() < 100000 || p.rows.count(row_key(f)))
        ++p.rows[row_key(f)];
}

void reports::tls(const std::string& domain, const std::string& type, const std::vector<std::string>& lines,
                  const std::string& mx, bool success, const std::string& failure, const std::string& mx_ip,
                  const std::string& sending_ip)
{
    roll(static_cast<int64_t>(::time(nullptr)));
    if (m_tls.size() >= 10000 && !m_tls.count(domain))
        return;
    tls_domain& t = m_tls[domain];
    t.type = type;
    t.lines = lines;
    if (std::find(t.mx.begin(), t.mx.end(), mx) == t.mx.end() && t.mx.size() < 32)
        t.mx.push_back(mx);
    if (success)
        ++t.ok;
    else
    {
        ++t.failed;
        const auto key = std::make_tuple(failure, sending_ip, mx, mx_ip);
        if (t.failures.size() < 1000 || t.failures.count(key))
            ++t.failures[key];
    }
}

std::vector<report_mail> reports::due(int64_t now_s, const std::string& organization, const std::string& contact)
{
    std::vector<report_mail> out;
    if (m_day < 0 || now_s / day_s <= m_day)
        return out;
    const int64_t begin = m_day * day_s, end = begin + day_s - 1;
    for (const auto& [domain, p] : m_dmarc)
    {
        const std::string id = socketley::random_hex(8) + "." + std::to_string(++m_serial);
        std::string x = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<feedback>\n  <report_metadata>\n    <org_name>" +
                        xml(organization) + "</org_name>\n    <email>" + xml(contact) + "</email>\n    <report_id>" + id +
                        "</report_id>\n    <date_range><begin>" + std::to_string(begin) + "</begin><end>" +
                        std::to_string(end) + "</end></date_range>\n  </report_metadata>\n  <policy_published>\n" +
                        "    <domain>" + xml(domain) + "</domain>\n    <adkim>" + xml(p.adkim) + "</adkim>\n    <aspf>" +
                        xml(p.aspf) + "</aspf>\n    <p>" + xml(p.p) + "</p>\n    <sp>" + xml(p.sp.empty() ? p.p : p.sp) +
                        "</sp>\n    <pct>" + std::to_string(p.pct) + "</pct>\n  </policy_published>\n";
        for (const auto& [key, count] : p.rows)
        {
            const auto f = row_fields(key);
            if (f.size() < 7)
                continue;
            x += "  <record>\n    <row>\n      <source_ip>" + xml(f[0]) + "</source_ip>\n      <count>" +
                 std::to_string(count) + "</count>\n      <policy_evaluated><disposition>" + xml(f[1]) +
                 "</disposition><dkim>" + f[2] + "</dkim><spf>" + f[3] + "</spf></policy_evaluated>\n    </row>\n" +
                 "    <identifiers><header_from>" + xml(f[4]) + "</header_from></identifiers>\n    <auth_results>\n";
            for (size_t i = 7; i + 1 < f.size(); i += 2)
                x += "      <dkim><domain>" + xml(f[i]) + "</domain><result>" + xml(f[i + 1]) + "</result></dkim>\n";
            x += "      <spf><domain>" + xml(f[5]) + "</domain><result>" + xml(f[6]) + "</result></spf>\n" +
                 std::string("    </auth_results>\n  </record>\n");
        }
        x += "</feedback>\n";
        report_mail r;
        // rua is a list of URIs, each mailto: with an optional size limit after '!' (RFC 7489 6.2).
        for (std::string_view rest = p.rua; !rest.empty();)
        {
            const size_t comma = rest.find(',');
            std::string_view uri = rest.substr(0, comma);
            rest = comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
            while (!uri.empty() && uri.front() == ' ')
                uri.remove_prefix(1);
            if (uri.size() > 7 && (uri.substr(0, 7) == "mailto:" || uri.substr(0, 7) == "MAILTO:"))
            {
                const std::string_view address = uri.substr(7, uri.find('!') == std::string_view::npos
                                                                   ? std::string_view::npos
                                                                   : uri.find('!') - 7);
                if (!address.empty())
                    r.to.emplace_back(address);
            }
        }
        if (r.to.empty())
            continue;
        r.subject = "Report Domain: " + domain + " Submitter: " + organization + " Report-ID: <" + id + ">";
        r.filename = organization + "!" + domain + "!" + std::to_string(begin) + "!" + std::to_string(end) + ".xml.gz";
        r.content_type = "application/gzip";
        r.data = gzip(x);
        out.push_back(std::move(r));
    }
    for (const auto& [domain, t] : m_tls)
    {
        const std::string id = socketley::random_hex(8) + "." + std::to_string(++m_serial);
        std::string j = "{\"organization-name\":" + socketley::json::quote(organization) + ",\"date-range\":{\"start-datetime\":" +
                        socketley::json::quote(iso(begin)) + ",\"end-datetime\":" + socketley::json::quote(iso(end)) + "},\"contact-info\":" +
                        socketley::json::quote(contact) + ",\"report-id\":" + socketley::json::quote(id) + ",\"policies\":[{\"policy\":{\"policy-type\":" +
                        socketley::json::quote(t.type) + ",\"policy-string\":[";
        for (size_t i = 0; i < t.lines.size(); ++i)
            j += (i ? "," : "") + socketley::json::quote(t.lines[i]);
        j += "],\"policy-domain\":" + socketley::json::quote(domain) + ",\"mx-host\":[";
        for (size_t i = 0; i < t.mx.size(); ++i)
            j += (i ? "," : "") + socketley::json::quote(t.mx[i]);
        j += "]},\"summary\":{\"total-successful-session-count\":" + std::to_string(t.ok) +
             ",\"total-failure-session-count\":" + std::to_string(t.failed) + "},\"failure-details\":[";
        bool first = true;
        for (const auto& [k, n] : t.failures)
        {
            j += std::string(first ? "" : ",") + "{\"result-type\":" + socketley::json::quote(std::get<0>(k)) + ",\"sending-mta-ip\":" +
                 socketley::json::quote(std::get<1>(k)) + ",\"receiving-mx-hostname\":" + socketley::json::quote(std::get<2>(k)) +
                 ",\"receiving-ip\":" + socketley::json::quote(std::get<3>(k)) + ",\"failed-session-count\":" + std::to_string(n) + "}";
            first = false;
        }
        j += "]}]}\n";
        report_mail r;
        r.subject = "Report Domain: " + domain + " Submitter: " + organization + " Report-ID: <" + id + ">";
        r.headers = {{"TLS-Report-Domain", domain}, {"TLS-Report-Submitter", organization}};
        r.filename = organization + "!" + domain + "!" + std::to_string(begin) + "!" + std::to_string(end) + "!" + id +
                     ".json.gz";
        r.content_type = "application/tlsrpt+gzip";
        r.data = gzip(j);
        out.push_back(std::move(r));
    }
    m_dmarc.clear();
    m_tls.clear();
    m_day = now_s / day_s;
    return out;
}

}   // namespace socketley::mail
