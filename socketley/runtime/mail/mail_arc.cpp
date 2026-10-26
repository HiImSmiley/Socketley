#include "mail_arc.h"

#include <algorithm>
#include <map>
#include <vector>

#include "mail_compose.h"
#include "mail_dkim.h"
#include "../../shared/util/ascii.h"

namespace socketley::mail::arc
{

namespace
{

constexpr int max_sets = 50;

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n'))
        s.remove_suffix(1);
    return s;
}

// The value of tag `name` in `name=value; ...`, empty where there is none.
std::string tag(std::string_view v, std::string_view name)
{
    while (!v.empty())
    {
        const size_t semi = v.find(';');
        const std::string_view one = trim(v.substr(0, semi));
        v = semi == std::string_view::npos ? std::string_view{} : v.substr(semi + 1);
        const size_t eq = one.find('=');
        if (eq != std::string_view::npos && trim(one.substr(0, eq)) == name)
        {
            std::string out;
            for (const char c : one.substr(eq + 1))
                if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
                    out += c;
            return out;
        }
    }
    return {};
}

// One set's three headers, by their place among the message's.
struct set
{
    int aar{-1}, ams{-1}, as{-1};
};

// The sets of `headers` by instance; false where one is given twice, has no number, or the numbers leave a gap.
bool sets_of(const std::vector<std::pair<std::string_view, std::string_view>>& headers, std::map<int, set>& out)
{
    for (size_t i = 0; i < headers.size(); ++i)
    {
        const std::string_view name = trim(headers[i].first);
        int set::*which = nullptr;
        if (socketley::ascii::iequals(name, "ARC-Authentication-Results"))
            which = &set::aar;
        else if (socketley::ascii::iequals(name, "ARC-Message-Signature"))
            which = &set::ams;
        else if (socketley::ascii::iequals(name, "ARC-Seal"))
            which = &set::as;
        else
            continue;
        const std::string n = tag(headers[i].second, "i");
        if (n.empty() || n.size() > 2 || !std::all_of(n.begin(), n.end(), [](char c) { return c >= '0' && c <= '9'; }))
            return false;
        const int instance = std::stoi(n);
        if (instance < 1 || instance > max_sets)
            return false;
        int& slot = out[instance].*which;
        if (slot >= 0)
            return false;
        slot = static_cast<int>(i);
    }
    int expect = 1;
    for (const auto& [n, s] : out)
        if (n != expect++ || s.aar < 0 || s.ams < 0 || s.as < 0)
            return false;
    return true;
}

// What seal `i` signs: every set up to it, each's results, message signature and seal in that order, its own seal's
// b= emptied and without the line's end (RFC 8617 5.1.1).
std::string seal_data(const std::vector<std::pair<std::string_view, std::string_view>>& headers,
                      const std::map<int, set>& sets, int upto, std::string_view own_seal)
{
    std::string data;
    for (const auto& [n, s] : sets)
    {
        if (n > upto)
            break;
        data += dkim::relaxed_header(headers[static_cast<size_t>(s.aar)].first,
                                     headers[static_cast<size_t>(s.aar)].second) + "\r\n";
        data += dkim::relaxed_header(headers[static_cast<size_t>(s.ams)].first,
                                     headers[static_cast<size_t>(s.ams)].second) + "\r\n";
        if (n < upto)
            data += dkim::relaxed_header(headers[static_cast<size_t>(s.as)].first,
                                         headers[static_cast<size_t>(s.as)].second) + "\r\n";
    }
    return data + dkim::relaxed_header("ARC-Seal", own_seal);
}

}   // namespace

chain verify(std::string_view message, const key_lookup& key_of, int64_t now_s)
{
    chain out;
    const auto headers = split_headers(header_block(message));
    std::map<int, set> sets;
    const auto failed = [&](std::string why) {
        out.result = "fail";
        out.why = std::move(why);
        return out;
    };
    if (!sets_of(headers, sets))
        return failed("the sets are not numbered 1 to n, each with its three headers");
    if (sets.empty())
        return out;
    out.count = static_cast<int>(sets.size());
    const auto& newest = sets.rbegin()->second;
    out.sealer = tag(headers[static_cast<size_t>(newest.as)].second, "d");
    socketley::ascii::lower_in_place(out.sealer);
    // Each seal says what the chain was as it came: none under the first, pass under every later one.
    for (const auto& [n, s] : sets)
    {
        const std::string cv = tag(headers[static_cast<size_t>(s.as)].second, "cv");
        if (cv != (n == 1 ? "none" : "pass"))
            return failed("seal " + std::to_string(n) + " says the chain was " + (cv.empty() ? "nothing" : cv));
    }
    // The newest message signature is checked as DKIM checks one; the older ones may be broken by later forwarders.
    bool signed_ok = false;
    for (auto sig : dkim::signatures(message, "ARC-Message-Signature"))
    {
        if (sig.index != static_cast<size_t>(newest.ams))
            continue;
        std::string h = sig.h;
        socketley::ascii::lower_in_place(h);
        if (h.find("arc-seal") != std::string::npos)
            return failed("the message signature signs a seal");
        // It carries no v=, which is DKIM's alone.
        sig.v = "1";
        std::string record, why;
        if (!key_of(sig.s + "._domainkey." + sig.d, record))
            return failed("the message signature's key could not be looked up");
        if (dkim::verify(message, sig, record, now_s, &why) != dkim::result::pass)
            return failed("the newest message signature: " + why);
        signed_ok = true;
    }
    if (!signed_ok)
        return failed("the newest message signature does not read");
    // Every seal, newest first, over the sets up to it.
    for (auto it = sets.rbegin(); it != sets.rend(); ++it)
    {
        const std::string_view raw = headers[static_cast<size_t>(it->second.as)].second;
        const std::string d = tag(raw, "d"), s = tag(raw, "s"), a = tag(raw, "a"), b = tag(raw, "b");
        if (!dkim::ldh_name(d) || !dkim::ldh_name(s) || b.empty())
            return failed("seal " + std::to_string(it->first) + " does not read");
        std::string record, why;
        if (!key_of(s + "._domainkey." + d, record))
            return failed("seal " + std::to_string(it->first) + "'s key could not be looked up");
        const std::string data = seal_data(headers, sets, it->first, dkim::without_b(raw));
        if (dkim::verify_bytes(record, a, data, b, &why) != dkim::result::pass)
            return failed("seal " + std::to_string(it->first) + ": " + why);
    }
    out.result = "pass";
    return out;
}

std::string seal(std::string_view message, std::string_view authserv, std::string_view results, std::string_view domain,
                 std::string_view selector, EVP_PKEY* key, int64_t now_s, std::string_view cv)
{
    const auto headers = split_headers(header_block(message));
    std::map<int, set> sets;
    // A chain that does not read is one of n sets as far as its numbers go, sealed as failed.
    const bool readable = sets_of(headers, sets);
    int highest = 0;
    if (!readable)
        for (const auto& h : headers)
        {
            const std::string_view name = trim(h.first);
            if (!socketley::ascii::iequals(name, "ARC-Authentication-Results") &&
                !socketley::ascii::iequals(name, "ARC-Message-Signature") && !socketley::ascii::iequals(name, "ARC-Seal"))
                continue;
            const std::string n = tag(h.second, "i");
            if (!n.empty() && n.size() <= 2 && std::all_of(n.begin(), n.end(), [](char c) { return c >= '0' && c <= '9'; }))
                highest = std::max(highest, std::stoi(n));
        }
    const int i = (readable ? static_cast<int>(sets.size()) : highest) + 1;
    if (i > max_sets)
        return {};
    const std::string n = std::to_string(i);
    const std::string aar = "ARC-Authentication-Results: i=" + n + "; " + std::string(authserv) + "; " +
                            std::string(results) + "\r\n";
    // The message signature over the message as it leaves, its results set among the headers it may name.
    const std::string with_aar = aar + std::string(message);
    const std::string ams = dkim::sign(with_aar, domain, selector, key, now_s, "ARC-Message-Signature", "i=" + n + "; ");
    if (ams.empty())
        return {};
    const std::string sealed = readable ? std::string(cv) : std::string("fail");
    std::string value = " i=" + n + "; a=" + dkim::algorithm_of(key) + "; cv=" + (readable && i == 1 ? std::string("none") : sealed) +
                        "; d=" + std::string(domain) + "; s=" + std::string(selector) + ";\r\n\tt=" +
                        std::to_string(now_s) + "; b=";
    // The new set read among the old ones, as a checker will read it.
    const std::string whole = ams + aar + std::string(message);
    const auto all = split_headers(header_block(whole));
    std::map<int, set> next;
    if (readable)
        next = sets;
    for (auto& [k, s] : next)
        s = {s.aar + 2, s.ams + 2, s.as + 2};
    next[i] = {1, 0, -1};
    std::string data;
    for (const auto& [k, s] : next)
    {
        data += dkim::relaxed_header(all[static_cast<size_t>(s.aar)].first, all[static_cast<size_t>(s.aar)].second) +
                "\r\n";
        data += dkim::relaxed_header(all[static_cast<size_t>(s.ams)].first, all[static_cast<size_t>(s.ams)].second) +
                "\r\n";
        if (k < i)
            data += dkim::relaxed_header(all[static_cast<size_t>(s.as)].first, all[static_cast<size_t>(s.as)].second) +
                    "\r\n";
    }
    data += dkim::relaxed_header("ARC-Seal", value);
    const std::string b = dkim::sign_bytes(key, data);
    if (b.empty())
        return {};
    for (size_t at = 0; at < b.size(); at += 72)
        value += (at ? "\r\n\t " : "") + b.substr(at, 72);
    return "ARC-Seal:" + value + "\r\n" + ams + aar;
}

}   // namespace socketley::mail::arc
