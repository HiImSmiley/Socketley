#include "mail_rspamd.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>

#include "../../shared/http/https_client.h"

namespace socketley::mail
{

int spam_verdict::level() const
{
    if (!scored)
        return 0;
    if (score <= 0 || required <= 0)
        return 1;
    return 1 + static_cast<int>(std::lround(9 * std::min(1.0, score / required)));
}

int spam_verdict::percent() const
{
    if (!scored)
        return 0;
    if (score <= 0 || required <= 0)
        return 0;
    return static_cast<int>(std::lround(100 * std::min(1.0, score / required)));
}

std::string json_member(std::string_view json, std::string_view key)
{
    int depth = 0;
    for (size_t i = 0; i < json.size(); ++i)
    {
        const char c = json[i];
        if (c == '{' || c == '[')
        {
            ++depth;
            continue;
        }
        if (c == '}' || c == ']')
        {
            --depth;
            continue;
        }
        if (c != '"')
            continue;
        // A string: a member's name where it is at the top and a colon follows it.
        size_t j = i + 1;
        std::string text;
        for (; j < json.size() && json[j] != '"'; ++j)
        {
            if (json[j] == '\\' && j + 1 < json.size())
                ++j;
            text += json[j];
        }
        size_t k = j + 1;
        while (k < json.size() && (json[k] == ' ' || json[k] == '\t' || json[k] == '\r' || json[k] == '\n'))
            ++k;
        if (depth == 1 && k < json.size() && json[k] == ':' && text == key)
        {
            ++k;
            while (k < json.size() && (json[k] == ' ' || json[k] == '\t' || json[k] == '\r' || json[k] == '\n'))
                ++k;
            if (k < json.size() && json[k] == '"')
            {
                std::string v;
                for (size_t m = k + 1; m < json.size() && json[m] != '"'; ++m)
                {
                    if (json[m] == '\\' && m + 1 < json.size())
                        ++m;
                    v += json[m];
                }
                return v;
            }
            size_t e = k;
            while (e < json.size() && json[e] != ',' && json[e] != '}' && json[e] != ']')
                ++e;
            std::string_view v = json.substr(k, e - k);
            while (!v.empty() && (v.back() == ' ' || v.back() == '\n' || v.back() == '\r' || v.back() == '\t'))
                v.remove_suffix(1);
            return std::string(v);
        }
        i = j;
    }
    return {};
}

spam_verdict rspamd_check(const std::string& url, std::string_view message, const std::string& ip,
                          const std::string& helo, const std::string& from, const std::vector<std::string>& rcpts,
                          const std::string& user, int timeout_s)
{
    spam_verdict out;
    https_client::client cl;
    if (!cl.init(out.why))
        return out;
    std::vector<std::pair<std::string, std::string>> headers = {{"IP", ip}, {"Helo", helo}, {"From", from}};
    for (const auto& r : rcpts)
        headers.emplace_back("Rcpt", r);
    if (!user.empty())
        headers.emplace_back("User", user);
    std::string base = url;
    while (!base.empty() && base.back() == '/')
        base.pop_back();
    https_client::reply rep;
    if (!cl.request("POST", base + "/checkv2", "application/octet-stream", message, rep, out.why, timeout_s, 1u << 20,
                    headers))
        return out;
    if (rep.status != 200)
    {
        out.why = "rspamd answered " + std::to_string(rep.status);
        return out;
    }
    const std::string score = json_member(rep.body, "score");
    const std::string required = json_member(rep.body, "required_score");
    out.action = json_member(rep.body, "action");
    if (score.empty() || out.action.empty())
    {
        out.why = "rspamd's answer names no score and action";
        return out;
    }
    out.score = std::strtod(score.c_str(), nullptr);
    out.required = required.empty() ? 15.0 : std::strtod(required.c_str(), nullptr);
    out.scored = true;
    return out;
}

}   // namespace socketley::mail
