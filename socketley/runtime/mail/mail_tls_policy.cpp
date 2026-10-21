#include "mail_tls_policy.h"

#include <algorithm>
#include <cctype>
#include <charconv>

#include "../../shared/util/ascii.h"

namespace socketley::mail::tls_policy
{

namespace
{

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n'))
        s.remove_suffix(1);
    return s;
}

std::string lower(std::string_view s)
{
    std::string out(s);
    socketley::ascii::lower_in_place(out);
    if (!out.empty() && out.back() == '.')
        out.pop_back();
    return out;
}

}   // namespace

bool sts_record_id(std::string_view txt, std::string& id)
{
    id.clear();
    bool first = true, versioned = false;
    while (!txt.empty())
    {
        const size_t semi = txt.find(';');
        const std::string_view field = trim(txt.substr(0, semi));
        txt = semi == std::string_view::npos ? std::string_view{} : txt.substr(semi + 1);
        if (field.empty())
            continue;
        const size_t eq = field.find('=');
        if (eq == std::string_view::npos)
            return false;
        const std::string_view key = trim(field.substr(0, eq)), val = trim(field.substr(eq + 1));
        // The version is the first field, and only "STSv1" is one.
        if (first)
        {
            if (key != "v" || val != "STSv1")
                return false;
            versioned = true;
            first = false;
            continue;
        }
        if (key == "id")
        {
            if (val.empty() || val.size() > 32)
                return false;
            for (const char c : val)
                if (!std::isalnum(static_cast<unsigned char>(c)))
                    return false;
            id = std::string(val);
        }
    }
    return versioned && !id.empty();
}

bool parse_sts(std::string_view text, sts& out, int64_t& max_age_s, std::string& why)
{
    out = {};
    max_age_s = -1;
    bool version = false, mode = false;
    while (!text.empty())
    {
        const size_t nl = text.find('\n');
        const std::string_view line = trim(text.substr(0, nl));
        text = nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
        if (line.empty())
            continue;
        const size_t colon = line.find(':');
        if (colon == std::string_view::npos)
            continue;
        const std::string_view key = trim(line.substr(0, colon)), val = trim(line.substr(colon + 1));
        if (key == "version")
            version = val == "STSv1";
        else if (key == "mode")
        {
            mode = true;
            if (val == "enforce")
                out.mode = sts_mode::enforce;
            else if (val == "testing")
                out.mode = sts_mode::testing;
            else if (val == "none")
                out.mode = sts_mode::none;
            else
            {
                why = "mode " + std::string(val) + " is none of enforce, testing and none";
                return false;
            }
        }
        else if (key == "max_age")
        {
            int64_t v = 0;
            const auto r = std::from_chars(val.data(), val.data() + val.size(), v);
            if (r.ec != std::errc() || r.ptr != val.data() + val.size() || v < 0)
            {
                why = "max_age " + std::string(val) + " is not a number of seconds";
                return false;
            }
            // RFC 8461 3.2 caps it at a year.
            max_age_s = std::min<int64_t>(v, 31557600);
        }
        else if (key == "mx" && !val.empty())
            out.mx.push_back(lower(val));
    }
    if (!version)
        why = "it says no version STSv1";
    else if (!mode)
        why = "it says no mode";
    else if (max_age_s < 0)
        why = "it says no max_age";
    else if (out.mode != sts_mode::none && out.mx.empty())
        why = "it names no exchanger";
    else
        return true;
    return false;
}

bool mx_matches(const sts& p, std::string_view host)
{
    const std::string h = lower(host);
    for (const auto& m : p.mx)
    {
        if (m == h)
            return true;
        // "*.example.com" stands for one label, not for example.com itself nor for two labels.
        if (m.starts_with("*.") && h.size() > m.size() - 1 && h.ends_with(m.substr(1)) &&
            h.substr(0, h.size() - (m.size() - 1)).find('.') == std::string::npos)
            return true;
    }
    return false;
}

std::string cache_line(const std::string& domain, const sts& p)
{
    std::string line = domain + " " + p.id + " " +
                       (p.mode == sts_mode::enforce ? "enforce" : p.mode == sts_mode::testing ? "testing" : "none") +
                       " " + std::to_string(p.expires_s);
    for (const auto& m : p.mx)
        line += " " + m;
    return line + "\n";
}

bool from_cache_line(std::string_view line, std::string& domain, sts& p)
{
    p = {};
    std::vector<std::string_view> w;
    while (!line.empty())
    {
        const size_t sp = line.find(' ');
        const std::string_view word = trim(line.substr(0, sp));
        line = sp == std::string_view::npos ? std::string_view{} : line.substr(sp + 1);
        if (!word.empty())
            w.push_back(word);
    }
    if (w.size() < 4)
        return false;
    domain = std::string(w[0]);
    p.id = std::string(w[1]);
    p.mode = w[2] == "enforce" ? sts_mode::enforce : w[2] == "testing" ? sts_mode::testing : sts_mode::none;
    const auto r = std::from_chars(w[3].data(), w[3].data() + w[3].size(), p.expires_s);
    if (r.ec != std::errc())
        return false;
    for (size_t i = 4; i < w.size(); ++i)
        p.mx.emplace_back(w[i]);
    return true;
}

bool parse_tlsa(std::string_view rdata, tlsa& out)
{
    if (rdata.size() < 4)
        return false;
    out.usage = static_cast<uint8_t>(rdata[0]);
    out.selector = static_cast<uint8_t>(rdata[1]);
    out.mtype = static_cast<uint8_t>(rdata[2]);
    out.data = std::string(rdata.substr(3));
    return true;
}

bool usable(const tlsa& t)
{
    if ((t.usage != 2 && t.usage != 3) || t.selector > 1 || t.mtype > 2)
        return false;
    // A digest is as long as its kind says.
    return t.mtype == 0 ? !t.data.empty() : t.data.size() == (t.mtype == 1 ? 32u : 64u);
}

}   // namespace socketley::mail::tls_policy
