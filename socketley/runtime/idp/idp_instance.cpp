#include "idp_instance.h"

#include "idp_run.h"
#include "../../shared/logging.h"
#include "../../shared/paths.h"

std::string idp_key_path(std::string_view runtime_name)
{
    return (socketley_paths::resolve().state_dir / "idp" / (std::string(runtime_name) + ".key")).string();
}

std::string idp_jwks_path(std::string_view runtime_name)
{
    return (socketley_paths::resolve().state_dir / "idp" / (std::string(runtime_name) + ".jwks")).string();
}

std::string idp_accounts_dir(std::string_view runtime_name)
{
    return (socketley_paths::resolve().state_dir / "idp" / (std::string(runtime_name) + ".accounts")).string();
}

idp_instance::idp_instance(std::string_view name) : runtime_instance(runtime_idp, name) {}

idp_instance::~idp_instance() = default;

std::string idp_instance::issuer() const
{
    std::string i = m_issuer;
    if (i.empty())
    {
        const std::string_view domains = get_domains();
        const std::string_view first = domains.substr(0, domains.find(','));
        if (!first.empty())
            i = "https://" + std::string(first);
    }
    while (!i.empty() && i.back() == '/')
        i.pop_back();
    return i;
}

std::string idp_instance::config_refusal() const
{
    if (get_port() == 0)
        return "idp: -p is required: the port the entrance or a proxy reaches the provider on\n";
    const std::string i = issuer();
    if (i.empty())
        return "idp: --issuer is required, or a --domain to make it https://<domain> from\n";
    if (!socketley::idp::url_host(i).size() || i.find_first_of("?#") != std::string::npos ||
        (!i.starts_with("https://") && !i.starts_with("http://localhost") && !i.starts_with("http://127.0.0.1")))
        return "idp: --issuer must be an https address without a query (http only for localhost): " + i + "\n";
    if (!get_listen_path().empty())
        return "idp: --listen unix: is not served; the provider listens on its port\n";
    return {};
}

void idp_instance::on_cqe(struct io_uring_cqe*)
{
    // Every completion belongs to the run, which is its own owner; nothing lands here.
}

bool idp_instance::setup(event_loop& loop)
{
    auto run = std::make_unique<socketley::idp::idp_run>(*this, loop);
    std::string why;
    if (!run->start(why))
    {
        LOG_ERROR(("idp " + std::string(get_name()) + ": " + why).c_str());
        run->stop();
        m_graveyard.push_back(std::move(run));
        return false;
    }
    m_run = std::move(run);
    return true;
}

void idp_instance::teardown(event_loop&)
{
    if (m_run)
    {
        m_run->stop();
        // Kept until the ring owes it nothing, since a cancelled read still completes into it.
        m_graveyard.push_back(std::move(m_run));
    }
}

void idp_instance::on_loop_turn()
{
    if (!m_graveyard.empty())
        std::erase_if(m_graveyard, [](const auto& r) { return r->drained(); });
    if (m_run)
        m_run->on_loop_turn();
}

bool idp_instance::serve_deferred(uint64_t ticket, std::string_view, std::string_view payload)
{
    // Only what `socketley idp-user` sends; any other runtime's request is no command this provider takes.
    if (!m_run || !payload.starts_with(socketley::idp::command_marker))
        return false;
    m_run->command(ticket, payload);
    return true;
}

size_t idp_instance::get_connection_count() const
{
    return m_run ? m_run->conn_count() : 0;
}

std::string idp_instance::stats_lines() const
{
    return m_run ? m_run->stats() : std::string();
}

void idp_instance::listen_addresses(std::vector<std::string>& out) const
{
    if (get_port())
        out.push_back("tcp:" + std::to_string(get_port()));
}

uint16_t idp_instance::effective_port() const
{
    return get_port();
}
