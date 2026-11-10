#include "web_instance.h"

#include "web_fcgi.h"
#include "web_run.h"
#include "../../shared/util/logging.h"

web_instance::web_instance(std::string_view name) : runtime_instance(runtime_web, name) {}

web_instance::~web_instance() = default;

std::string web_instance::config_refusal() const
{
    if (get_port() == 0)
        return "web: -p is required: the port the entrance reaches the site on\n";
    if (!get_listen_path().empty())
        return "web: --listen unix: is not served; the site listens on its port\n";
    if (m_root.empty() || m_root.front() != '/')
        return "web: --root is required: the absolute path of the directory whose files are the site\n";
    if (m_index.empty() || m_index.find('/') != std::string::npos || m_index.front() == '.')
        return "web: --index is a file name such as index.html, not a path\n";
    if (!m_fallback.empty() && (m_fallback.front() == '.' || m_fallback.find("..") != std::string::npos))
        return "web: --fallback is a page under --root, such as index.html\n";
    if (!m_backend.empty())
    {
        socketley::web::fcgi_target t;
        std::string why;
        if (!socketley::web::parse_fcgi_target(m_backend, t, why))
            return "web: --backend " + m_backend + ": " + why + "\n";
    }
    if (!m_fastcgi_root.empty() && (m_backend.empty() || m_fastcgi_root.front() != '/'))
        return "web: --fastcgi-root is the absolute directory --root is to the --backend fastcgi:// server\n";
    if (get_tls())
        return "web: --tls is not served here; the entrance proxy terminates TLS for the site's --domain\n";
    if (!get_lua_script_path().empty())
        return "web: --lua is not run; a .lua file under --root is a page with --lua-pages\n";
#ifdef SOCKETLEY_NO_LUA
    if (m_lua_pages)
        return "web: --lua-pages needs a build with Lua\n";
#endif
    return {};
}

void web_instance::on_cqe(struct io_uring_cqe*)
{
    // Every completion belongs to the run, which is its own owner; nothing lands here.
}

bool web_instance::setup(event_loop& loop)
{
    auto run = std::make_unique<socketley::web::web_run>(*this, loop);
    std::string why;
    if (!run->start(why))
    {
        LOG_ERROR(("web " + std::string(get_name()) + ": " + why).c_str());
        m_graveyard.retire(std::move(run));
        return false;
    }
    m_run = std::move(run);
    return true;
}

void web_instance::teardown(event_loop&)
{
    m_graveyard.retire(std::move(m_run));
}

void web_instance::on_loop_turn()
{
    m_graveyard.reap();
    if (m_run)
        m_run->on_loop_turn();
}

size_t web_instance::get_connection_count() const
{
    return m_run ? m_run->conn_count() : 0;
}

std::string web_instance::stats_lines() const
{
    return m_run ? m_run->stats() : std::string();
}

void web_instance::listen_addresses(std::vector<std::string>& out) const
{
    if (get_port())
        out.push_back("tcp:" + std::to_string(get_port()));
}

uint16_t web_instance::effective_port() const
{
    return get_port();
}
