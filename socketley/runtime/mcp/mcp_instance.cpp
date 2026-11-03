#include "mcp_instance.h"

#include "mcp_run.h"
#include "../../shared/util/logging.h"

mcp_instance::mcp_instance(std::string_view name) : runtime_instance(runtime_mcp, name) {}

mcp_instance::~mcp_instance() = default;

std::string mcp_instance::config_refusal() const
{
    if (get_port() == 0)
        return "mcp: -p is required: the port the entrance or a client reaches the server on\n";
    if (!get_listen_path().empty())
        return "mcp: --listen unix: is not served; the server listens on its port\n";
    if (m_keys.empty() && !m_anonymous)
        return "mcp: give --keys, the file of the keys that may ask, or --anonymous for a port only this machine reaches\n";
    if (m_tools != "none" && m_tools != "daemon")
        return "mcp: --tools is none or daemon, not " + m_tools + "\n";
    return {};
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
