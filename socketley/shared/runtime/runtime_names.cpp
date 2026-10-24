#include "runtime_names.h"
#include "runtime_instance.h"
#include "../../runtime/mail/mail_instance.h"
#include "../../runtime/proxy/proxy_instance.h"
#include "../../runtime/storage/storage_instance.h"
#include "../../runtime/dns/dns_instance.h"
#include "../util/text_list.h"

#include <algorithm>

namespace runtime_names
{

namespace
{

void add_list(std::string_view csv, std::vector<std::string>& out, bool with_wildcard)
{
    while (!csv.empty())
    {
        std::string n = normal(socketley::take_item(csv));
        if (!n.empty())
        {
            if (with_wildcard && !n.starts_with("*."))
                out.push_back("*." + n);
            out.push_back(std::move(n));
        }
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
        case runtime_idp:
        case runtime_db:
            return true;
        case runtime_proxy:
            return static_cast<const proxy_instance&>(rt).get_protocol() == protocol_http && !is_entrance(rt);
        case runtime_mail:
            return static_cast<const mail_instance&>(rt).get_web_port() != 0;
        default:
            return false;
    }
}

namespace
{

// Where the entrance reaches a runtime, empty for none: a mail runtime's webmail port, whose TLS is the entrance's
// while its own --tls is for SMTP and IMAP, and any other's own port where it does not terminate TLS itself.
std::string http_address(const runtime_instance& r)
{
    if (r.get_type() == runtime_mail)
        return "127.0.0.1:" + std::to_string(static_cast<const mail_instance&>(r).get_web_port());
    if (r.get_tls())
        return {};
    if (!r.get_listen_path().empty())
        return "unix:" + std::string(r.get_listen_path());
    const std::string_view bind = r.get_bind_address();
    return (bind.empty() || bind == "0.0.0.0" ? std::string("127.0.0.1") : std::string(bind)) + ":" +
           std::to_string(r.effective_port());
}

}   // namespace

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

std::string entrance_table(const runtime_instance& entrance, const std::vector<const runtime_instance*>& all,
                           const std::function<std::vector<std::string>(const runtime_instance&)>& origins_of)
{
    std::vector<std::string> zones;
    for (const runtime_instance* r : all)
        if (r && r->get_type() == runtime_dns &&
            static_cast<const dns_instance*>(r)->get_proxy() == entrance.get_name())
            for (auto& z : origins_of(*r))
                zones.push_back(normal(z));
    std::sort(zones.begin(), zones.end());
    zones.erase(std::unique(zones.begin(), zones.end()), zones.end());

    // Name -> the addresses of the runtimes that have it, ordered so the text is the same every time it is built.
    std::vector<std::pair<std::string, std::vector<std::string>>> routes;
    const auto add = [&](const std::string& name, const std::string& addr)
    {
        auto it = std::find_if(routes.begin(), routes.end(), [&](const auto& r) { return r.first == name; });
        if (it == routes.end())
            routes.push_back({name, {addr}});
        else if (std::find(it->second.begin(), it->second.end(), addr) == it->second.end())
            it->second.push_back(addr);
    };
    for (const runtime_instance* r : all)
    {
        if (!r || r == &entrance || !speaks_http(*r))
            continue;
        const std::string addr = http_address(*r);
        if (addr.empty())
            continue;
        for (const auto& n : of(*r, /*with_buckets=*/true))
        {
            const bool relative = n.find('.') == std::string::npos ||
                                  (n.starts_with("*.") && n.find('.', 2) == std::string::npos);
            if (!relative)
                add(n, addr);
            else
                for (const auto& z : zones)
                    add(n + "." + z, addr);
        }
    }
    std::sort(routes.begin(), routes.end());
    std::string out;
    for (const auto& z : zones)
        out += "zone " + z + "\n";
    for (auto& [name, addrs] : routes)
    {
        std::sort(addrs.begin(), addrs.end());
        out += "route " + name;
        for (const auto& a : addrs)
            out += " " + a;
        out += "\n";
    }
    return out;
}

}   // namespace runtime_names
