#include "mqtt_auth.h"

#include "mqtt_codec.h"
#include "mqtt_topics.h"
#include "../../shared/util/text_list.h"

namespace socketley::mqtt
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

// The next word of `s`, taken off its front.
std::string_view word(std::string_view& s)
{
    s = trim(s);
    const size_t end = s.find_first_of(" \t");
    const std::string_view w = s.substr(0, end);
    s = end == std::string_view::npos ? std::string_view{} : s.substr(end);
    return w;
}

}   // namespace

bool topic_matches(std::string_view filter, std::string_view topic)
{
    const auto f = split_levels(filter);
    const auto t = split_levels(topic);
    const bool dollar = !topic.empty() && topic.front() == '$';
    size_t i = 0;
    for (; i < f.size(); ++i)
    {
        if (f[i] == "#")
            return !(i == 0 && dollar);
        if (i >= t.size())
            return false;
        if (f[i] == "+")
        {
            if (i == 0 && dollar)
                return false;
            continue;
        }
        if (f[i] != t[i])
            return false;
    }
    return i == t.size();
}

bool filter_covers(std::string_view acl, std::string_view sub)
{
    const auto a = split_levels(acl);
    const auto s = split_levels(sub);
    const bool dollar = !sub.empty() && sub.front() == '$';
    for (size_t i = 0; i < a.size(); ++i)
    {
        if (a[i] == "#")
            return !(i == 0 && dollar);
        if (i >= s.size())
            return false;
        if (a[i] == "+")
        {
            if (s[i] == "#" || (i == 0 && dollar))
                return false;
            continue;
        }
        if (a[i] != s[i])
            return false;
    }
    if (s.size() == a.size())
        return true;
    // "a/#" is covered by "a/#" alone; "a" does not cover "a/b".
    return false;
}

bool acl_rules::parse(std::string_view text, std::string& why)
{
    m_rules.clear();
    m_loaded = true;
    std::string current;
    size_t n = 0;
    while (!text.empty())
    {
        ++n;
        std::string_view line = trim(socketley::take_item(text, '\n'));
        if (line.empty() || line.front() == '#')
            continue;
        const std::string_view kind = word(line);
        if (kind == "user")
        {
            const std::string_view u = trim(line);
            if (u.empty())
            {
                why = "line " + std::to_string(n) + ": `user` names nobody";
                return false;
            }
            current = std::string(u);
            continue;
        }
        if (kind != "topic" && kind != "pattern")
        {
            why = "line " + std::to_string(n) + ": `" + std::string(kind) + "` is not user, topic or pattern";
            return false;
        }
        rule r;
        r.pattern = kind == "pattern";
        r.user = r.pattern ? std::string("*") : current;
        std::string_view rest = line;
        std::string_view right = word(rest);
        std::string_view filter = trim(rest);
        if (filter.empty())
        {
            // "topic <filter>" alone grants both, as Mosquitto reads it.
            filter = right;
            right  = "readwrite";
        }
        if (right == "read")
            r.rights = static_cast<uint8_t>(access::read);
        else if (right == "write")
            r.rights = static_cast<uint8_t>(access::write);
        else if (right == "readwrite")
            r.rights = static_cast<uint8_t>(access::read) | static_cast<uint8_t>(access::write);
        else if (right == "deny")
        {
            r.deny = true;
            r.rights = static_cast<uint8_t>(access::read) | static_cast<uint8_t>(access::write);
        }
        else
        {
            why = "line " + std::to_string(n) + ": `" + std::string(right) + "` is not read, write, readwrite or deny";
            return false;
        }
        r.filter = std::string(filter);
        // A pattern's %u and %c stand for a whole level, so the filter is checked with them in place.
        std::string probe = r.filter;
        for (const char* tok : {"%u", "%c"})
            for (size_t at = probe.find(tok); at != std::string::npos; at = probe.find(tok))
                probe.replace(at, 2, "x");
        if (!valid_filter(probe) || probe.starts_with("$share/"))
        {
            why = "line " + std::to_string(n) + ": `" + r.filter + "` is not a topic filter";
            return false;
        }
        m_rules.push_back(std::move(r));
    }
    return true;
}

std::string acl_rules::expand(const rule& r, std::string_view user, std::string_view client)
{
    if (!r.pattern)
        return r.filter;
    // A name holding a separator or a wildcard would widen the rule beyond the one level it stands for.
    const auto bad = [](std::string_view v) { return v.empty() || v.find_first_of("/+#") != std::string_view::npos; };
    std::string out;
    for (size_t i = 0; i < r.filter.size(); ++i)
    {
        if (r.filter[i] == '%' && i + 1 < r.filter.size() && (r.filter[i + 1] == 'u' || r.filter[i + 1] == 'c'))
        {
            const std::string_view v = r.filter[i + 1] == 'u' ? user : client;
            if (bad(v))
                return {};
            out += v;
            ++i;
            continue;
        }
        out += r.filter[i];
    }
    return out;
}

bool acl_rules::applies(const rule& r, std::string_view user) const
{
    return r.pattern || r.user == user;
}

bool acl_rules::check(std::string_view user, std::string_view client, std::string_view topic, uint8_t right,
                      bool as_filter) const
{
    if (m_rules.empty())
        return !m_loaded;
    const auto hits = [&](const rule& r) {
        if (!applies(r, user) || !(r.rights & right))
            return false;
        const std::string f = expand(r, user, client);
        // A deny whose name cannot be put in holds for everything, so it fails closed.
        if (f.empty())
            return r.deny;
        if (!as_filter)
            return topic_matches(f, topic);
        // A subscription is refused only where a rule covers all of it; what a deny covers in part is held back
        // message by message when it is delivered.
        return filter_covers(f, topic);
    };
    for (const auto& r : m_rules)
        if (r.deny && hits(r))
            return false;
    for (const auto& r : m_rules)
        if (!r.deny && hits(r))
            return true;
    return false;
}

bool acl_rules::may_write(std::string_view user, std::string_view client, std::string_view topic) const
{
    return check(user, client, topic, static_cast<uint8_t>(access::write), false);
}

bool acl_rules::may_read(std::string_view user, std::string_view client, std::string_view topic) const
{
    return check(user, client, topic, static_cast<uint8_t>(access::read), false);
}

bool acl_rules::may_subscribe(std::string_view user, std::string_view client, std::string_view filter) const
{
    return check(user, client, filter, static_cast<uint8_t>(access::read), true);
}

}   // namespace socketley::mqtt
