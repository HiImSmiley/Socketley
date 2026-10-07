#include "runtime_names.h"
#include "runtime_instance.h"
#include "../runtime/proxy/proxy_instance.h"
#include "../runtime/storage/storage_instance.h"

#include <algorithm>

namespace runtime_names
{

namespace
{

void add_list(std::string_view csv, std::vector<std::string>& out, bool with_wildcard)
{
    for (size_t p = 0; p <= csv.size();)
    {
        const size_t comma = std::min(csv.find(',', p), csv.size());
        std::string n = normal(csv.substr(p, comma - p));
        if (!n.empty())
        {
            if (with_wildcard && !n.starts_with("*."))
                out.push_back("*." + n);
            out.push_back(std::move(n));
        }
        p = comma + 1;
    }
}

}   // namespace

std::string normal(std::string_view name)
{
    std::string n;
    for (char c : name)
        if (c != ' ' && c != '\t')
            n += (c >= 'A' && c <= 'Z') ? static_cast<char>(c | 0x20) : c;
    while (!n.empty() && n.back() == '.')
        n.pop_back();
    return n;
}

std::vector<std::string> of(const runtime_instance& rt, bool with_buckets)
{
    std::vector<std::string> out;
    if (rt.get_type() == runtime_storage)
    {
        const auto& stg = static_cast<const storage_instance&>(rt);
        add_list(stg.get_domain(), out, with_buckets);
        add_list(stg.get_website_domain(), out, with_buckets);
    }
    add_list(rt.get_domains(), out, false);
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

bool is_entrance(const runtime_instance& rt)
{
    if (rt.get_type() != runtime_proxy)
        return false;
    const auto& prx = static_cast<const proxy_instance&>(rt);
    return prx.get_protocol() == protocol_http && prx.get_backends().empty();
}

bool speaks_http(const runtime_instance& rt)
{
    switch (rt.get_type())
    {
        case runtime_server:
        case runtime_storage:
            return true;
        case runtime_proxy:
            return static_cast<const proxy_instance&>(rt).get_protocol() == protocol_http && !is_entrance(rt);
        default:
            return false;
    }
}

std::string refusal(const runtime_instance& rt, const std::vector<const runtime_instance*>& others)
{
    const auto mine = of(rt);
    if (mine.empty())
        return {};
    if (is_entrance(rt))
        return "--domain: a proxy without --backend is the entrance every name is reached through, and has no name "
               "of its own; give the names to the runtimes behind it\n";
    const std::string_view group = rt.get_group();
    for (const runtime_instance* o : others)
    {
        if (!o || o == &rt || o->get_name() == rt.get_name())
            continue;
        // The runtimes of one group share a name: a proxy spreads its requests over them.
        if (!group.empty() && o->get_group() == group)
            continue;
        for (const auto& n : of(*o))
            if (std::binary_search(mine.begin(), mine.end(), n))
                return "--domain: " + n + " is already the name of runtime '" + std::string(o->get_name()) +
                       "'; a name belongs to one runtime, or to the runtimes of one group (-g)\n";
    }
    return {};
}

}   // namespace runtime_names
