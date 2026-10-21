#include "mail_aliases.h"

#include "smtp_session.h"
#include "../../shared/util/ascii.h"
#include "../../shared/util/text_list.h"

namespace socketley::mail
{

namespace
{

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

std::string lower(std::string_view s)
{
    std::string out(s);
    socketley::ascii::lower_in_place(out);
    return out;
}

}   // namespace

bool alias_table::parse(std::string_view text, std::string& why)
{
    map.clear();
    size_t n = 0;
    while (!text.empty())
    {
        ++n;
        std::string_view line = socketley::take_item(text, '\n');
        if (const size_t hash = line.find('#'); hash != std::string_view::npos)
            line = line.substr(0, hash);
        line = trim(line);
        if (line.empty())
            continue;
        const size_t sp = line.find_first_of(" \t");
        if (sp == std::string_view::npos)
        {
            why = "line " + std::to_string(n) + " is not <address> <target>[,<target>...]";
            return false;
        }
        const std::string key = lower(line.substr(0, sp));
        address a;
        if (key.starts_with("*@") ? !parse_address("x" + key.substr(1), a) : !parse_address(key, a))
        {
            why = "line " + std::to_string(n) + ": " + key + " is not an address";
            return false;
        }
        std::vector<std::string> targets;
        std::string_view rest = trim(line.substr(sp + 1));
        while (!rest.empty())
        {
            const std::string t(trim(socketley::take_item(rest, ',')));
            if (t.empty())
                continue;
            if (t.find('@') != std::string::npos && !parse_address(t, a))
            {
                why = "line " + std::to_string(n) + ": " + t + " is not an address";
                return false;
            }
            targets.push_back(t.find('@') == std::string::npos ? lower(t) : t);
        }
        if (targets.empty())
        {
            why = "line " + std::to_string(n) + " names no target";
            return false;
        }
        map[key] = std::move(targets);
    }
    return true;
}

const std::vector<std::string>* alias_table::find(std::string_view local, std::string_view domain) const
{
    std::string key = lower(local);
    key += '@';
    key += domain;
    if (const auto it = map.find(key); it != map.end())
        return &it->second;
    if (const auto it = map.find("*@" + std::string(domain)); it != map.end())
        return &it->second;
    return nullptr;
}

}   // namespace socketley::mail
