#include "mcp_instance.h"

#include "mcp_run.h"
#include "../idp/idp_logic.h"
#include "../../shared/util/logging.h"

mcp_instance::mcp_instance(std::string_view name) : runtime_instance(runtime_mcp, name) {}

mcp_instance::~mcp_instance() = default;

std::string mcp_instance::config_refusal() const
{
    if (get_port() == 0)
        return "mcp: -p is required: the port the entrance or a client reaches the server on\n";
    if (!get_listen_path().empty())
        return "mcp: --listen unix: is not served; the server listens on its port\n";
    if (m_keys.empty() && !m_anonymous && m_idp.empty())
        return "mcp: give --keys, the file of the keys that may ask, --idp, the idp runtime whose people sign in, or "
               "--anonymous for a port only this machine reaches\n";
    if (m_anonymous && (!m_keys.empty() || !m_idp.empty()))
        return "mcp: --anonymous lets anyone ask, so it goes with neither --keys nor --idp\n";
    if (!m_idp.empty() && resource().empty())
        return "mcp: --idp needs a --domain, the name clients reach the server at, which its tokens name; the first "
               "is a whole name such as mcp.example.com, since one without a dot stands for a name under every zone\n";
    if (!m_idp_audience.empty() && m_idp.empty())
        return "mcp: --idp-audience names clients of the --idp runtime, which is not given\n";
    if (m_tools != "none" && m_tools != "daemon")
        return "mcp: --tools is none or daemon, not " + m_tools + "\n";
    return {};
}

std::string mcp_instance::resource() const
{
    const std::string_view domains = get_domains();
    const std::string_view first = domains.substr(0, domains.find(','));
    // A name without a dot is one under each zone a dns runtime serves, so it names no one address.
    if (first.find('.') == std::string_view::npos || first.starts_with("*."))
        return {};
    return socketley::idp::canonical_resource("https://" + std::string(first) + "/mcp");
}

void mcp_instance::on_cqe(struct io_uring_cqe*)
{
    // Every completion belongs to the run, which is its own owner; nothing lands here.
}

bool mcp_instance::setup(event_loop& loop)
{
    auto run = std::make_unique<socketley::mcp::mcp_run>(*this, loop);
    std::string why;
    if (!run->start(why))
    {
        LOG_ERROR(("mcp " + std::string(get_name()) + ": " + why).c_str());
        m_graveyard.retire(std::move(run));
        return false;
    }
    m_run = std::move(run);
    return true;
}

void mcp_instance::teardown(event_loop&)
{
    m_graveyard.retire(std::move(m_run));
}

void mcp_instance::on_loop_turn()
{
    m_graveyard.reap();
    if (m_run)
        m_run->on_loop_turn();
}

size_t mcp_instance::get_connection_count() const
{
    return m_run ? m_run->conn_count() : 0;
}

std::string mcp_instance::stats_lines() const
{
    return m_run ? m_run->stats() : std::string();
}

void mcp_instance::listen_addresses(std::vector<std::string>& out) const
{
    if (get_port())
        out.push_back("tcp:" + std::to_string(get_port()));
}

uint16_t mcp_instance::effective_port() const
{
    return get_port();
}
