#include "runtime_names.h"
#include "runtime_instance.h"
#include "../../runtime/mail/mail_instance.h"
#include "../../runtime/proxy/proxy_instance.h"
#include "../../runtime/storage/storage_instance.h"
#include "../../runtime/dns/dns_instance.h"
#include "../../runtime/tunnel/tunnel_instance.h"
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

namespace
{

// A tunnel edge's service is named beside the edge, `ollama` for an edge called `edge`, so it reads as any other; an
// edge named as a whole domain has no name beside it, and its services none.
std::string service_name(std::string_view edge_name, std::string_view service)
{
    const size_t dot = edge_name.find('.');
    if (dot == std::string_view::npos)
        return std::string(service);
    if (edge_name.find('.', dot + 1) == std::string_view::npos)
        return {};
    return std::string(service) + std::string(edge_name.substr(dot));
}

// The names of an edge's HTTP services with the socket each is served on.
std::vector<std::pair<std::string, std::string>> edge_services(const runtime_instance& rt)
{
    std::vector<std::pair<std::string, std::string>> out;
    if (rt.get_type() != runtime_tunnel)
        return out;
    const std::string_view domains = rt.get_domains();
    const std::string base = normal(domains.substr(0, domains.find(',')));
    if (base.empty())
        return out;
    for (auto& [svc, sock] : static_cast<const tunnel_instance&>(rt).http_services())
        if (std::string name = service_name(base, svc); !name.empty())
            out.emplace_back(std::move(name), std::move(sock));
    return out;
}

// The names `rt` itself is reached by, without the services of an edge.
std::vector<std::string> own(const runtime_instance& rt, bool with_buckets)
{
    std::vector<std::string> out;
    if (rt.get_type() == runtime_storage)
    {
        const auto& stg = static_cast<const storage_instance&>(rt);
        add_list(stg.get_domain(), out, with_buckets);
        add_list(stg.get_website_domain(), out, with_buckets);
    }
    add_list(rt.get_domains(), out, false);
    // A mail runtime's webmail answers mail clients too, under the names they ask for its zones' setup.
    if (rt.get_type() == runtime_mail && static_cast<const mail_instance&>(rt).get_web_port() && !rt.get_domains().empty())
    {
        out.emplace_back("autoconfig");
        out.emplace_back("autodiscover");
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

}   // namespace

std::vector<std::string> of(const runtime_instance& rt, bool with_buckets)
{
    std::vector<std::string> out = own(rt, with_buckets);
    for (auto& [name, sock] : edge_services(rt))
        out.push_back(std::move(name));
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
        case runtime_metrics:
        case runtime_mcp:
            return true;
        case runtime_proxy:
            return static_cast<const proxy_instance&>(rt).get_protocol() == protocol_http && !is_entrance(rt);
        case runtime_mail:
            return static_cast<const mail_instance&>(rt).get_web_port() != 0;
        case runtime_tunnel:
            return static_cast<const tunnel_instance&>(rt).get_mode() == tunnel_instance::mode::edge;
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
    // Its own names against all of every other's, an edge's services among them.
    const auto mine = own(rt, false);
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
        for (const auto& n : own(*r, /*with_buckets=*/true))
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
    // Each HTTP service of a tunnel edge goes to the socket the edge serves it on, unless a runtime or an edge before
    // it has that name, since one name spread over two machines would hand visitors to either.
    // A runtime's wildcard counts as having the name too, since an exact route would take it from under the wildcard.
    const auto routed = [&](const std::string& name)
    {
        return std::any_of(routes.begin(), routes.end(), [&](const auto& r) {
            return r.first == name || (r.first.starts_with("*.") && name.size() > r.first.size() - 1 &&
                                       name.ends_with(std::string_view(r.first).substr(1)));
        });
    };
    // Edges in the order of their names, so which keeps a name both have does not hang on the order runtimes are listed.
    std::vector<const runtime_instance*> edges;
    for (const runtime_instance* r : all)
        if (r && r->get_type() == runtime_tunnel && speaks_http(*r))
            edges.push_back(r);
    std::sort(edges.begin(), edges.end(), [](const auto* a, const auto* b) { return a->get_name() < b->get_name(); });
    for (const runtime_instance* r : edges)
    {
        for (const auto& [name, sock] : edge_services(*r))
        {
            if (name.find('.') != std::string::npos)
            {
                if (!routed(name))
                    add(name, "unix:" + sock);
            }
            else
                for (const auto& z : zones)
                    if (!routed(name + "." + z))
                        add(name + "." + z, "unix:" + sock);
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
