#include "tunnel_instance.h"

#include <charconv>

#include "tunnel_registry.h"
#include "tunnel_run.h"
#include "../../shared/net/endpoint.h"
#include "../../shared/net/peer_address.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/text_list.h"

tunnel_instance::tunnel_instance(std::string_view name) : runtime_instance(runtime_tunnel, name) {}

tunnel_instance::~tunnel_instance() = default;

std::vector<std::pair<std::string, std::string>> tunnel_instance::http_services() const
{
    std::vector<std::pair<std::string, std::string>> out;
    if (m_mode != mode::edge)
        return out;
    std::vector<socketley::tunnel::agent> agents;
    std::string why;
    if (!socketley::tunnel::load_agents(get_name(), agents, why))
        return out;
    // An agent only invited serves nobody yet, so its names stay free until it joins.
    for (const auto& a : agents)
        for (const auto& s : a.services)
            if (s.http && a.joined)
                if (std::string sock = socketley::tunnel::service_socket(get_name(), s.name); !sock.empty())
                    out.emplace_back(s.name, std::move(sock));
    // What people share now, each for as long as the link that shares it.
    std::vector<socketley::tunnel::share> shares;
    if (socketley::tunnel::load_shares(get_name(), shares, why))
        for (const auto& s : shares)
            if (std::string sock = socketley::tunnel::service_socket(get_name(), s.svc.name); !sock.empty())
                out.emplace_back(s.svc.name, std::move(sock));
    return out;
}

namespace
{

// `host:port` with a literal address or localhost.
bool target_ok(std::string_view t)
{
    const size_t colon = t.rfind(':');
    if (colon == std::string_view::npos)
        return false;
    std::string host(t.substr(0, colon));
    if (host == "localhost")
        host = "127.0.0.1";
    if (host.size() > 2 && host.front() == '[' && host.back() == ']')
        host = host.substr(1, host.size() - 2);
    uint32_t port = 0;
    const std::string_view p = t.substr(colon + 1);
    const auto [end, ec] = std::from_chars(p.data(), p.data() + p.size(), port);
    socketley::endpoint ep;
    return ec == std::errc{} && end == p.data() + p.size() && port > 0 && port < 65536 &&
           socketley::literal_endpoint(host, static_cast<uint16_t>(port), ep);
}

}   // namespace

std::string tunnel_instance::config_refusal() const
{
    if (m_mode == mode::edge)
    {
        if (!get_port())
            return "tunnel: an edge needs -p, the port agents and people reach it on behind the entrance\n";
        if (!m_to.empty() || !m_join.empty() || !m_offers.empty())
            return "tunnel: --to, --join and --offer are an agent's; this is an edge (--mode agent for one)\n";
        std::string_view list = m_forward;
        while (!list.empty())
            if (const std::string_view f = socketley::trim_blanks(socketley::take_item(list)); !f.empty() && !target_ok(f))
                return "tunnel: --forward takes host:port with an address or localhost: " + std::string(f) + "\n";
        if (!m_forward.empty() && m_idp.empty())
            return "tunnel: --forward needs --idp, whose signed-in people may use it\n";
        return {};
    }
    if (get_port() || !get_domains().empty() || !m_forward.empty() || !m_idp.empty() || !m_idp_audience.empty())
        return "tunnel: -p, --domain, --forward, --idp and --idp-audience are an edge's; this is an agent, which dials "
               "out (--mode edge for one)\n";
    if (!m_to.starts_with("https://") && !m_to.starts_with("http://"))
        return "tunnel: an agent needs --to, the edge's https address\n";
    if (const std::string_view rest = std::string_view(m_to).substr(m_to.find("://") + 3);
        m_to.starts_with("http://") && !socketley::authority_is_this_machine(rest.substr(0, rest.find('/'))))
        return "tunnel: --to over http:// is only for an edge on this machine, as the invitation and key go in "
               "clear; use https://\n";
    if (m_offers.empty())
        return "tunnel: an agent needs --offer <service>=<host>:<port>, what it carries the edge's streams to\n";
    std::string_view list = m_offers;
    while (!list.empty())
    {
        const std::string_view o = socketley::trim_blanks(socketley::take_item(list));
        const size_t eq = o.find('=');
        if (eq == std::string_view::npos || !socketley::tunnel::valid_name(o.substr(0, eq)) || !target_ok(o.substr(eq + 1)))
            return "tunnel: --offer takes <service>=<host>:<port>, with an address or localhost: " + std::string(o) + "\n";
    }
    std::string key;
    if (m_join.empty() &&
        !(socketley::read_file(socketley::tunnel::agent_key_path(get_name()), key, {.missing_ok = true}, nullptr) &&
          !key.empty()))
        return "tunnel: an agent that has not joined needs --join, the invitation `socketley tunnel <edge> invite` "
               "printed\n";
    return {};
}

void tunnel_instance::on_cqe(struct io_uring_cqe*)
{
    // Every completion belongs to the run, which is its own owner.
}

bool tunnel_instance::setup(event_loop& loop)
{
    auto run = std::make_unique<socketley::tunnel::tunnel_run>(*this, loop);
    std::string why;
    if (!run->start(why))
    {
        LOG_ERROR(("tunnel " + std::string(get_name()) + ": " + why).c_str());
        m_graveyard.retire(std::move(run));
        return false;
    }
    m_run = std::move(run);
    return true;
}

void tunnel_instance::teardown(event_loop&)
{
    m_graveyard.retire(std::move(m_run));
}

bool tunnel_instance::runs_drained()
{
    return m_graveyard.drain();
}

void tunnel_instance::on_loop_turn()
{
    m_graveyard.reap();
    if (m_run)
        m_run->on_loop_turn();
}

size_t tunnel_instance::get_connection_count() const
{
    return m_run ? m_run->conn_count() : 0;
}

std::string tunnel_instance::stats_lines() const
{
    return m_run ? m_run->stats() : std::string();
}

void tunnel_instance::listen_addresses(std::vector<std::string>& out) const
{
    if (m_mode == mode::edge && get_port())
        out.push_back("tcp:" + std::to_string(get_port()));
}

uint16_t tunnel_instance::effective_port() const
{
    return m_mode == mode::edge ? get_port() : 0;
}
