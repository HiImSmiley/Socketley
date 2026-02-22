#include "daemon_handler.h"
#include "flag_handlers.h"
#include "../shared/event_loop.h"
#include "../shared/runtime_manager.h"
#include "../shared/runtime_definitions.h"
#include "../shared/time_format.h"
#include "../shared/state_persistence.h"
#include "../cli/runtime_type_parser.h"
#include "../cli/command_hashing.h"
#include "../runtime/cache/cache_instance.h"
#include "../runtime/server/server_instance.h"
#include "../runtime/client/client_instance.h"
#include "../runtime/proxy/proxy_instance.h"

#include <unistd.h>
#include <cstring>
#include <charconv>
#include <sys/socket.h>
#include <sys/stat.h>
#include "../shared/name_resolver.h"
#include <iomanip>
#include <sstream>
#include <iostream>

std::string daemon_handler::socket_path = "/tmp/socketley.sock";

namespace {
    constexpr const char* type_to_string(runtime_type type)
    {
        switch (type)
        {
            case runtime_server: return "server";
            case runtime_client: return "client";
            case runtime_proxy:  return "proxy";
            case runtime_cache:  return "cache";
            default:             return "unknown";
        }
    }
}

daemon_handler::daemon_handler(runtime_manager& manager, event_loop& loop)
    : m_manager(manager), m_loop(loop), m_listen_fd(-1)
{
    std::memset(&m_accept_addr, 0, sizeof(m_accept_addr));
    m_accept_addrlen = sizeof(m_accept_addr);
    m_accept_req = { op_accept, -1, nullptr, 0, this };
}

daemon_handler::~daemon_handler()
{
    teardown();
}

void daemon_handler::set_state_persistence(state_persistence* sp)
{
    m_persistence = sp;
}

bool daemon_handler::setup()
{
    unlink(socket_path.c_str());

    m_listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (m_listen_fd < 0)
        return false;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

    if (bind(m_listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    // Allow all users to connect (needed when daemon runs as socketley user via systemd)
    chmod(socket_path.c_str(), 0666);

    if (listen(m_listen_fd, 16) < 0)
    {
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    m_loop.submit_accept(m_listen_fd,
        reinterpret_cast<struct sockaddr_in*>(&m_accept_addr),
        &m_accept_addrlen, &m_accept_req);

    return true;
}

void daemon_handler::teardown()
{
    for (auto& [fd, conn] : m_clients)
    {
        if (conn->interactive)
        {
            auto* inst = m_manager.get(conn->interactive_name);
            if (inst)
                inst->remove_interactive_fd(fd);
        }
        close(fd);
    }

    m_clients.clear();

    if (m_listen_fd >= 0)
    {
        close(m_listen_fd);
        m_listen_fd = -1;
    }

    unlink(socket_path.c_str());
}

void daemon_handler::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req)
        return;

    switch (req->type)
    {
        case op_accept:
            handle_accept(cqe);
            break;
        case op_read:
            handle_read(cqe, req);
            break;
        case op_write:
            break;
        case op_timeout:
            // Deferred-delete cleanup: all in-flight CQEs for the removed runtimes have
            // now been processed (event loop completed at least one full iteration), so
            // it is safe to destroy the runtime objects.
            m_deferred_delete.clear();
            m_cleanup_pending = false;
            break;
        default:
            break;
    }
}

void daemon_handler::handle_accept(struct io_uring_cqe* cqe)
{
    int client_fd = cqe->res;

    if (client_fd >= 0)
    {
        auto conn = std::make_unique<ipc_connection>();
        conn->fd = client_fd;
        conn->read_req = { op_read, client_fd, conn->read_buf, sizeof(conn->read_buf), this };
        conn->write_req = { op_write, client_fd, nullptr, 0, this };

        auto* ptr = conn.get();
        m_clients[client_fd] = std::move(conn);

        m_loop.submit_read(client_fd, ptr->read_buf, sizeof(ptr->read_buf), &ptr->read_req);
    }

    m_accept_addrlen = sizeof(m_accept_addr);
    m_loop.submit_accept(m_listen_fd,
        reinterpret_cast<struct sockaddr_in*>(&m_accept_addr),
        &m_accept_addrlen, &m_accept_req);
}

void daemon_handler::handle_read(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    auto it = m_clients.find(fd);
    if (it == m_clients.end())
        return;

    auto* conn = it->second.get();

    if (cqe->res <= 0)
    {
        if (conn->interactive)
        {
            auto* inst = m_manager.get(conn->interactive_name);
            if (inst)
                inst->remove_interactive_fd(fd);
        }
        close(fd);
        m_clients.erase(it);
        return;
    }

    conn->partial.append(conn->read_buf, cqe->res);

    // Interactive mode: forward input lines to runtime
    if (conn->interactive)
    {
        size_t pos;
        while ((pos = conn->partial.find('\n')) != std::string::npos)
        {
            std::string line = conn->partial.substr(0, pos);
            conn->partial.erase(0, pos + 1);

            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            if (line.empty())
                continue;

            auto* inst = m_manager.get(conn->interactive_name);
            if (!inst || inst->get_state() != runtime_running)
                break;

            switch (inst->get_type())
            {
                case runtime_server:
                    static_cast<server_instance*>(inst)->lua_broadcast(line);
                    break;
                case runtime_client:
                    static_cast<client_instance*>(inst)->lua_send(line);
                    break;
                case runtime_cache:
                {
                    std::string resp = static_cast<cache_instance*>(inst)->execute(line);
                    if (!resp.empty())
                        if (::write(conn->fd, resp.data(), resp.size()) < 0) {}
                    break;
                }
                default:
                    break;
            }
        }
        m_loop.submit_read(fd, conn->read_buf, sizeof(conn->read_buf), &conn->read_req);
        return;
    }

    size_t pos;
    while ((pos = conn->partial.find('\n')) != std::string::npos)
    {
        std::string line = conn->partial.substr(0, pos);
        conn->partial.erase(0, pos + 1);

        if (!line.empty() && line.back() == '\r')
            line.pop_back();

        conn->write_buf.clear();
        int exit_code = process_command(conn, line);
        send_response(conn, exit_code);
    }

    m_loop.submit_read(fd, conn->read_buf, sizeof(conn->read_buf), &conn->read_req);
}

int daemon_handler::check_empty_names(const std::vector<std::string>& names,
    const parsed_args& pa, const char* verb, ipc_connection* conn) const
{
    if (!names.empty())
        return -1;

    for (size_t i = 1; i < pa.count; ++i)
    {
        if (!pa.args[i].empty() && pa.args[i][0] != '-')
        {
            std::string msg = std::string(verb) + std::string(pa.args[i]) + "\n";
            if (conn)
            {
                conn->write_buf = msg;
                return 1;
            }
            std::cout << msg;
            return 2;
        }
    }
    return 0;
}

int daemon_handler::process_command(ipc_connection* conn, std::string_view line)
{
    parsed_args pa;
    pa.parse(line);

    if (pa.count == 0)
    {
        std::cout << "no command\n";
        return 1;
    }

    switch (pa.hashes[0])
    {
        case fnv1a("create"):     return cmd_create(pa);
        case fnv1a("start"):     return cmd_start(conn, pa);
        case fnv1a("stop"):      return cmd_stop(conn, pa);
        case fnv1a("remove"):    return cmd_remove(conn, pa);
        case fnv1a("ls"):        return cmd_ls(conn, pa);
        case fnv1a("ps"):        return cmd_ps(conn, pa);
        case fnv1a("send"):      return cmd_send(pa);
        case fnv1a("edit"):      return cmd_edit(pa);
        case fnv1a("show"):
        case fnv1a("dump"):      return cmd_dump(conn, pa);
        case fnv1a("import"):    return cmd_import(conn, pa);
        case fnv1a("action"):    return cmd_action(conn, pa);
        case fnv1a("stats"):     return cmd_stats(conn, pa);
        case fnv1a("reload"):    return cmd_reload(conn, pa);
        case fnv1a("reload-lua"):return cmd_reload_lua(conn, pa);
        case fnv1a("owner"):     return cmd_owner(conn, pa);
        case fnv1a("attach"):    return cmd_attach(conn, pa);
        default:
            std::cout << "unknown command: " << pa.args[0] << "\n";
            return 1;
    }
}

int daemon_handler::cmd_create(const parsed_args& pa)
{
    if (pa.count < 3)
    {
        std::cout << "usage: create <type> <name> [flags]\n";
        return 1;
    }

    runtime_type type;
    if (!parse_runtime_type(pa.args[1], type))
    {
        std::cout << "unknown runtime type: " << pa.args[1] << "\n";
        return 1;
    }

    std::string_view name = pa.args[2];

    if (!m_manager.create(type, name))
    {
        std::cout << "runtime already exists: " << name << "\n";
        return 1;
    }

    auto* instance = m_manager.get(name);
    if (!instance)
    {
        std::cout << "internal error\n";
        return 2;
    }

    instance->set_runtime_manager(&m_manager);
    instance->set_event_loop(&m_loop);

    if (type == runtime_proxy)
        static_cast<proxy_instance*>(instance)->set_runtime_manager(&m_manager);

    bool autostart = false;

    for (size_t i = 3; i < pa.count; ++i)
    {
        int result = parse_common_flags(instance, pa, i, autostart);
        if (result == -1)
        {
            switch (type)
            {
                case runtime_server:
                    result = parse_server_flags(
                        static_cast<server_instance*>(instance), pa, i, &m_manager, name);
                    break;
                case runtime_client:
                    result = parse_client_flags(
                        static_cast<client_instance*>(instance), pa, i, name);
                    break;
                case runtime_proxy:
                    result = parse_proxy_flags(
                        static_cast<proxy_instance*>(instance), pa, i, name);
                    break;
                case runtime_cache:
                    result = parse_cache_flags(
                        static_cast<cache_instance*>(instance), pa, i, name);
                    break;
            }
        }

        if (result == -1)
        {
            std::cout << "unknown flag: " << pa.args[i] << "\n";
            m_manager.remove(name);
            return 1;
        }

        if (result > 0)
        {
            m_manager.remove(name);
            return result;
        }
    }

    if (autostart && !instance->get_test_mode())
    {
        if (!m_manager.run(name, m_loop))
        {
            std::cout << "could not start runtime\n";
            m_manager.remove(name);
            return 2;
        }
    }

    if (m_persistence && !instance->get_test_mode() && !instance->is_lua_created())
        m_persistence->save_runtime(instance);

    return 0;
}

std::vector<std::string> daemon_handler::resolve_names(const parsed_args& pa, size_t start) const
{
    std::shared_lock lock(m_manager.mutex);
    return resolve_names_impl(pa.args, pa.count, m_manager.list(), start);
}

int daemon_handler::cmd_start(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2)
    {
        std::cout << "usage: start <name|pattern>... [-i]\n";
        return 1;
    }

    bool want_interactive = false;
    for (size_t i = 1; i < pa.count; ++i)
    {
        if (pa.args[i] == "-i")
        {
            want_interactive = true;
            break;
        }
    }

    auto names = resolve_names(pa);
    int rc = check_empty_names(names, pa, "runtime not found: ", conn);
    if (rc >= 0) return rc;

    if (want_interactive && names.size() > 1)
    {
        conn->write_buf = "cannot use -i with multiple runtimes\n";
        return 1;
    }

    for (const auto& n : names)
    {
        // Allow -i on already-running runtimes (attach without start)
        auto* inst = m_manager.get(n);
        bool already_running = inst && inst->get_state() == runtime_running;

        if (!already_running)
        {
            if (!m_manager.run(n, m_loop))
                continue;
            if (m_persistence)
                m_persistence->set_was_running(n, true);
            inst = m_manager.get(n);
        }

        if (want_interactive && inst)
        {
            if (inst->get_type() == runtime_proxy)
            {
                conn->write_buf = "interactive mode not supported for proxy\n";
                return 1;
            }
            conn->interactive = true;
            conn->interactive_name = n;
            inst->add_interactive_fd(conn->fd);
        }
    }

    return 0;
}

int daemon_handler::cmd_stop(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2)
    {
        conn->write_buf = "usage: stop <name|pattern>...\n";
        return 1;
    }

    auto names = resolve_names(pa);
    int rc = check_empty_names(names, pa, "runtime not found: ", conn);
    if (rc >= 0) return rc;

    for (const auto& n : names)
    {
        if (m_manager.stop(n, m_loop) && m_persistence)
            m_persistence->set_was_running(n, false);
    }
    return 0;
}

int daemon_handler::cmd_remove(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2)
    {
        conn->write_buf = "usage: remove <name|pattern>...\n";
        return 1;
    }

    auto names = resolve_names(pa);
    int rc = check_empty_names(names, pa, "runtime not found: ", conn);
    if (rc >= 0) return rc;

    for (const auto& n : names)
    {
        auto* inst = m_manager.get(n);
        if (inst && inst->get_state() == runtime_running)
            m_manager.stop(n, m_loop);
    }

    for (const auto& n : names)
    {
        // Use extract() instead of remove() so we hold the runtime alive for one
        // event loop tick.  Any io_uring CQEs that are still in-flight reference
        // io_request members embedded in the runtime object; freeing the object
        // immediately would make those pointers dangling and crash the daemon.
        auto ptr = m_manager.extract(n);
        if (ptr)
        {
            m_deferred_delete.push_back(std::move(ptr));
            if (m_persistence)
                m_persistence->remove_runtime(n);
        }
    }

    // Schedule a 0-ms timeout so we get a CQE in the very next event loop
    // iteration.  By the time that CQE fires, all pending CQEs for the removed
    // runtimes will have been processed and it is safe to destroy the objects.
    if (!m_deferred_delete.empty() && !m_cleanup_pending)
    {
        m_cleanup_pending = true;
        m_cleanup_ts = {};   // {0, 0} — fires immediately
        m_cleanup_req = { op_timeout, -1, nullptr, 0, this };
        m_loop.submit_timeout(&m_cleanup_ts, &m_cleanup_req);
    }

    return 0;
}

int daemon_handler::cmd_ls(ipc_connection* conn, const parsed_args& pa)
{
    std::shared_lock lock(m_manager.mutex);

    const auto& runtimes = m_manager.list();
    if (runtimes.empty())
        return 0;

    bool silent = false;
    bool col_id = false, col_name = false, col_type = false, col_port = false;
    bool col_status = false, col_conn = false, col_owner = false, col_created = false;

    for (size_t i = 1; i < pa.count; ++i)
    {
        switch (pa.hashes[i])
        {
            case fnv1a("-s"):
            case fnv1a("--silent"):  silent     = true; break;
            case fnv1a("--id"):      col_id      = true; break;
            case fnv1a("--name"):    col_name    = true; break;
            case fnv1a("--type"):    col_type    = true; break;
            case fnv1a("--port"):    col_port    = true; break;
            case fnv1a("--status"):  col_status  = true; break;
            case fnv1a("--conn"):    col_conn    = true; break;
            case fnv1a("--owner"):   col_owner   = true; break;
            case fnv1a("--created"): col_created = true; break;
        }
    }

    bool any_col = col_id || col_name || col_type || col_port ||
                   col_status || col_conn || col_owner || col_created;

    std::ostringstream out;
    out << std::left;

    if (!any_col)
    {
        if (!silent)
            out << std::setw(10) << "ID"
                << std::setw(16) << "NAME"
                << std::setw(8)  << "TYPE"
                << std::setw(8)  << "PORT"
                << std::setw(6)  << "CONN"
                << std::setw(12) << "OWNED BY"
                << std::setw(20) << "STATUS"
                << "CREATED\n";

        for (const auto& [name, instance] : runtimes)
        {
            runtime_state state = instance->get_state();
            const char* status_str;
            std::string uptime_buf;
            switch (state)
            {
                case runtime_created: status_str = "Created"; break;
                case runtime_running:
                    uptime_buf = format_uptime(instance->get_start_time());
                    status_str = uptime_buf.c_str();
                    break;
                case runtime_stopped: status_str = "Stopped"; break;
                case runtime_failed:  status_str = "Failed";  break;
                default:              status_str = "Unknown"; break;
            }
            uint16_t port = instance->get_port();
            auto owner = instance->get_owner();
            out << std::setw(10) << instance->get_id()
                << std::setw(16) << name
                << std::setw(8)  << type_to_string(instance->get_type())
                << std::setw(8)  << (port > 0 ? std::to_string(port) : "-")
                << std::setw(6)  << instance->get_connection_count()
                << std::setw(12) << (owner.empty() ? "-" : std::string(owner))
                << std::setw(20) << status_str
                << format_time_ago(instance->get_created_time()) << "\n";
        }
    }
    else
    {
        if (!silent)
        {
            bool first = true;
            auto hdr = [&](const char* h) { if (!first) out << '\t'; out << h; first = false; };
            if (col_id)      hdr("ID");
            if (col_name)    hdr("NAME");
            if (col_type)    hdr("TYPE");
            if (col_port)    hdr("PORT");
            if (col_conn)    hdr("CONN");
            if (col_owner)   hdr("OWNER");
            if (col_status)  hdr("STATUS");
            if (col_created) hdr("CREATED");
            out << '\n';
        }

        for (const auto& [name, instance] : runtimes)
        {
            runtime_state state = instance->get_state();
            std::string status;
            switch (state)
            {
                case runtime_created: status = "Created"; break;
                case runtime_running: status = format_uptime(instance->get_start_time()); break;
                case runtime_stopped: status = "Stopped"; break;
                case runtime_failed:  status = "Failed";  break;
                default:              status = "Unknown"; break;
            }
            uint16_t port = instance->get_port();
            auto owner = instance->get_owner();
            bool first = true;
            auto col = [&](const std::string& v) { if (!first) out << '\t'; out << v; first = false; };
            if (col_id)      col(std::string(instance->get_id()));
            if (col_name)    col(std::string(name));
            if (col_type)    col(std::string(type_to_string(instance->get_type())));
            if (col_port)    col(port > 0 ? std::to_string(port) : "-");
            if (col_conn)    col(std::to_string(instance->get_connection_count()));
            if (col_owner)   col(owner.empty() ? "-" : std::string(owner));
            if (col_status)  col(status);
            if (col_created) col(format_time_ago(instance->get_created_time()));
            out << '\n';
        }
    }

    conn->write_buf = out.str();
    return 0;
}

int daemon_handler::cmd_ps(ipc_connection* conn, const parsed_args& pa)
{
    std::shared_lock lock(m_manager.mutex);

    const auto& runtimes = m_manager.list();

    bool has_running = std::any_of(runtimes.begin(), runtimes.end(),
        [](const auto& p) { return p.second->get_state() == runtime_running; });

    if (!has_running)
        return 0;

    bool silent = false;
    bool col_id = false, col_name = false, col_type = false, col_port = false;
    bool col_uptime = false, col_conn = false, col_owner = false, col_created = false;

    for (size_t i = 1; i < pa.count; ++i)
    {
        switch (pa.hashes[i])
        {
            case fnv1a("-s"):
            case fnv1a("--silent"):  silent     = true; break;
            case fnv1a("--id"):      col_id      = true; break;
            case fnv1a("--name"):    col_name    = true; break;
            case fnv1a("--type"):    col_type    = true; break;
            case fnv1a("--port"):    col_port    = true; break;
            case fnv1a("--uptime"):  col_uptime  = true; break;
            case fnv1a("--status"):  col_uptime  = true; break;
            case fnv1a("--conn"):    col_conn    = true; break;
            case fnv1a("--owner"):   col_owner   = true; break;
            case fnv1a("--created"): col_created = true; break;
        }
    }

    bool any_col = col_id || col_name || col_type || col_port ||
                   col_uptime || col_conn || col_owner || col_created;

    std::ostringstream out;
    out << std::left;

    if (!any_col)
    {
        if (!silent)
            out << std::setw(10) << "ID"
                << std::setw(16) << "NAME"
                << std::setw(8)  << "TYPE"
                << std::setw(8)  << "PORT"
                << std::setw(6)  << "CONN"
                << std::setw(12) << "OWNED BY"
                << std::setw(20) << "STATUS"
                << "CREATED\n";

        for (const auto& [name, instance] : runtimes)
        {
            if (instance->get_state() != runtime_running)
                continue;
            uint16_t port = instance->get_port();
            auto owner = instance->get_owner();
            out << std::setw(10) << instance->get_id()
                << std::setw(16) << name
                << std::setw(8)  << type_to_string(instance->get_type())
                << std::setw(8)  << (port > 0 ? std::to_string(port) : "-")
                << std::setw(6)  << instance->get_connection_count()
                << std::setw(12) << (owner.empty() ? "-" : std::string(owner))
                << std::setw(20) << format_uptime(instance->get_start_time())
                << format_time_ago(instance->get_created_time()) << "\n";
        }
    }
    else
    {
        if (!silent)
        {
            bool first = true;
            auto hdr = [&](const char* h) { if (!first) out << '\t'; out << h; first = false; };
            if (col_id)      hdr("ID");
            if (col_name)    hdr("NAME");
            if (col_type)    hdr("TYPE");
            if (col_port)    hdr("PORT");
            if (col_conn)    hdr("CONN");
            if (col_owner)   hdr("OWNER");
            if (col_uptime)  hdr("UPTIME");
            if (col_created) hdr("CREATED");
            out << '\n';
        }

        for (const auto& [name, instance] : runtimes)
        {
            if (instance->get_state() != runtime_running)
                continue;
            uint16_t port = instance->get_port();
            auto owner = instance->get_owner();
            bool first = true;
            auto col = [&](const std::string& v) { if (!first) out << '\t'; out << v; first = false; };
            if (col_id)      col(std::string(instance->get_id()));
            if (col_name)    col(std::string(name));
            if (col_type)    col(std::string(type_to_string(instance->get_type())));
            if (col_port)    col(port > 0 ? std::to_string(port) : "-");
            if (col_conn)    col(std::to_string(instance->get_connection_count()));
            if (col_owner)   col(owner.empty() ? "-" : std::string(owner));
            if (col_uptime)  col(format_uptime(instance->get_start_time()));
            if (col_created) col(format_time_ago(instance->get_created_time()));
            out << '\n';
        }
    }

    conn->write_buf = out.str();
    return 0;
}

int daemon_handler::cmd_owner(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2)
    {
        conn->write_buf = "usage: owner <name>\n";
        return 1;
    }

    auto* inst = m_manager.get(pa.args[1]);
    if (!inst)
    {
        conn->write_buf = "runtime not found\n";
        return 1;
    }

    std::ostringstream out;
    auto owner = inst->get_owner();
    out << "name:" << inst->get_name() << "\n";
    out << "owner:" << (owner.empty() ? "-" : std::string(owner)) << "\n";
    out << "on_parent_stop:" << (inst->get_child_policy() == runtime_instance::child_policy::remove ? "remove" : "stop") << "\n";

    auto children = m_manager.get_children(inst->get_name());
    out << "children:" << children.size() << "\n";
    for (auto& c : children)
        out << "  " << c << "\n";

    conn->write_buf = out.str();
    return 0;
}

int daemon_handler::cmd_send(const parsed_args& pa)
{
    if (pa.count < 3)
    {
        std::cout << "usage: send <name> <message>\n";
        return 1;
    }

    std::string_view name = pa.args[1];
    std::string_view message = pa.rest_from(2);

    auto* instance = m_manager.get(name);
    if (!instance)
    {
        std::cout << "runtime not found: " << name << "\n";
        return 1;
    }

    if (instance->get_state() != runtime_running)
    {
        std::cout << "runtime is not running: " << name << "\n";
        return 1;
    }

    switch (instance->get_type())
    {
        case runtime_server:
        {
            auto* srv = static_cast<server_instance*>(instance);
            if (srv->get_mode() != mode_in)
                srv->lua_broadcast(message);
            break;
        }
        case runtime_client:
        {
            auto* cli = static_cast<client_instance*>(instance);
            if (cli->get_mode() != client_mode_in)
                cli->lua_send(message);
            break;
        }
        default:
            std::cout << "send is only supported for server and client runtimes\n";
            return 1;
    }

    return 0;
}

int daemon_handler::cmd_action(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 3)
    {
        conn->write_buf = "usage: <name> <action> [args]\n";
        return 1;
    }

    std::string_view name = pa.args[1];
    std::string_view action = pa.args[2];

    auto* instance = m_manager.get(name);
    if (!instance)
    {
        conn->write_buf = "runtime not found: " + std::string(name) + "\n";
        return 1;
    }

    if (instance->get_state() != runtime_running)
    {
        conn->write_buf = "runtime is not running: " + std::string(name) + "\n";
        return 1;
    }

    runtime_type type = instance->get_type();

    uint32_t action_hash = fnv1a_lower(action);

    switch (action_hash)
    {
        case fnv1a("get"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "get is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> get <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = cache->lua_get(pa.args[3]);
            if (conn->write_buf.empty())
                conn->write_buf = "nil\n";
            else
                conn->write_buf += '\n';
            return 0;
        }
        case fnv1a("set"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "set is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> set <key> <value>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            std::string_view value = pa.rest_from(4);
            if (!cache->lua_set(pa.args[3], value))
            {
                conn->write_buf = "denied: readonly mode\n";
                return 1;
            }
            return 0;
        }
        case fnv1a("del"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "del is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> del <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            if (cache->get_mode() == cache_mode_readonly)
            {
                conn->write_buf = "denied: readonly mode\n";
                return 1;
            }
            if (!cache->lua_del(pa.args[3]))
                conn->write_buf = "nil\n";
            return 0;
        }
        case fnv1a("size"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "size is only valid for cache runtimes\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = std::to_string(cache->get_size());
            conn->write_buf += '\n';
            return 0;
        }
        case fnv1a("exists"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "exists is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> exists <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = cache->lua_ttl(pa.args[3]) != -2 ? "1\n" : "0\n";
            return 0;
        }

        // ─── List actions ───

        case fnv1a("lpush"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "lpush is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> lpush <key> <value>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            std::string_view value = pa.rest_from(4);
            if (!cache->lua_lpush(pa.args[3], value))
            {
                conn->write_buf = "error: type conflict or readonly\n";
                return 1;
            }
            return 0;
        }
        case fnv1a("rpush"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "rpush is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> rpush <key> <value>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            std::string_view value = pa.rest_from(4);
            if (!cache->lua_rpush(pa.args[3], value))
            {
                conn->write_buf = "error: type conflict or readonly\n";
                return 1;
            }
            return 0;
        }
        case fnv1a("lpop"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "lpop is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> lpop <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = cache->lua_lpop(pa.args[3]);
            if (conn->write_buf.empty())
                conn->write_buf = "nil\n";
            else
                conn->write_buf += '\n';
            return 0;
        }
        case fnv1a("rpop"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "rpop is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> rpop <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = cache->lua_rpop(pa.args[3]);
            if (conn->write_buf.empty())
                conn->write_buf = "nil\n";
            else
                conn->write_buf += '\n';
            return 0;
        }
        case fnv1a("llen"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "llen is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> llen <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = std::to_string(cache->lua_llen(pa.args[3]));
            conn->write_buf += '\n';
            return 0;
        }

        // ─── Set actions ───

        case fnv1a("sadd"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "sadd is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> sadd <key> <member>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            int result = cache->lua_sadd(pa.args[3], pa.args[4]);
            if (result < 0)
            {
                conn->write_buf = "error: type conflict or readonly\n";
                return 1;
            }
            conn->write_buf = result ? "ok\n" : "exists\n";
            return 0;
        }
        case fnv1a("srem"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "srem is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> srem <key> <member>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            if (!cache->lua_srem(pa.args[3], pa.args[4]))
                conn->write_buf = "nil\n";
            return 0;
        }
        case fnv1a("sismember"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "sismember is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> sismember <key> <member>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = cache->lua_sismember(pa.args[3], pa.args[4]) ? "1\n" : "0\n";
            return 0;
        }
        case fnv1a("scard"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "scard is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> scard <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = std::to_string(cache->lua_scard(pa.args[3]));
            conn->write_buf += '\n';
            return 0;
        }

        // ─── Hash actions ───

        case fnv1a("hset"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "hset is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 6)
            {
                conn->write_buf = "usage: <cache> hset <key> <field> <value>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            std::string_view value = pa.rest_from(5);
            if (!cache->lua_hset(pa.args[3], pa.args[4], value))
            {
                conn->write_buf = "error: type conflict or readonly\n";
                return 1;
            }
            return 0;
        }
        case fnv1a("hget"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "hget is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> hget <key> <field>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = cache->lua_hget(pa.args[3], pa.args[4]);
            if (conn->write_buf.empty())
                conn->write_buf = "nil\n";
            else
                conn->write_buf += '\n';
            return 0;
        }
        case fnv1a("hdel"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "hdel is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> hdel <key> <field>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            if (!cache->lua_hdel(pa.args[3], pa.args[4]))
                conn->write_buf = "nil\n";
            return 0;
        }
        case fnv1a("hlen"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "hlen is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> hlen <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = std::to_string(cache->lua_hlen(pa.args[3]));
            conn->write_buf += '\n';
            return 0;
        }

        // ─── TTL actions ───

        case fnv1a("expire"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "expire is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> expire <key> <seconds>\n";
                return 1;
            }
            int seconds;
            auto sv = pa.args[4];
            auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), seconds);
            if (ec != std::errc{} || seconds <= 0)
            {
                conn->write_buf = "error: invalid seconds\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            if (!cache->lua_expire(pa.args[3], seconds))
                conn->write_buf = "nil\n";
            return 0;
        }
        case fnv1a("ttl"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "ttl is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> ttl <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = std::to_string(cache->lua_ttl(pa.args[3]));
            conn->write_buf += '\n';
            return 0;
        }
        case fnv1a("persist"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "persist is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> persist <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            if (!cache->lua_persist(pa.args[3]))
                conn->write_buf = "nil\n";
            return 0;
        }
        case fnv1a("flush"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "flush is only valid for cache runtimes\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            if (cache->get_mode() != cache_mode_admin)
            {
                conn->write_buf = "denied: admin mode required\n";
                return 1;
            }
            std::string_view path = pa.count > 3 ? pa.args[3] : cache->get_persistent();
            if (path.empty())
            {
                conn->write_buf = "no persistent path set\n";
                return 1;
            }
            if (!cache->flush_to(path))
            {
                conn->write_buf = "flush failed\n";
                return 2;
            }
            return 0;
        }
        case fnv1a("load"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "load is only valid for cache runtimes\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            if (cache->get_mode() != cache_mode_admin)
            {
                conn->write_buf = "denied: admin mode required\n";
                return 1;
            }
            std::string_view path = pa.count > 3 ? pa.args[3] : cache->get_persistent();
            if (path.empty())
            {
                conn->write_buf = "no persistent path set\n";
                return 1;
            }
            if (!cache->load_from(path))
            {
                conn->write_buf = "load failed\n";
                return 2;
            }
            return 0;
        }
        case fnv1a("publish"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "publish is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> publish <channel> <message>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            std::string_view message = pa.rest_from(4);
            int count = cache->publish(pa.args[3], message);
            conn->write_buf = std::to_string(count) + "\n";
            return 0;
        }
        case fnv1a("memory"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "memory is only valid for cache runtimes\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = std::to_string(cache->get_max_memory()) + " " +
                              std::to_string(cache->store_memory_used()) + "\n";
            return 0;
        }
        case fnv1a("send"):
        {
            if (type != runtime_server && type != runtime_client)
            {
                conn->write_buf = "send is only valid for server/client runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <runtime> send <message>\n";
                return 1;
            }
            std::string_view message = pa.rest_from(3);

            if (type == runtime_server)
            {
                auto* srv = static_cast<server_instance*>(instance);
                if (srv->get_mode() != mode_in)
                    srv->lua_broadcast(message);
            }
            else
            {
                auto* cli = static_cast<client_instance*>(instance);
                if (cli->get_mode() != client_mode_in)
                    cli->lua_send(message);
            }
            return 0;
        }
        default:
            conn->write_buf = "unknown action: " + std::string(action) + "\n";
            return 1;
    }
}

int daemon_handler::cmd_edit(const parsed_args& pa)
{
    if (pa.count < 3)
    {
        std::cout << "usage: edit <name> [flags]\n";
        return 1;
    }

    std::string_view name = pa.args[1];
    auto* instance = m_manager.get(name);
    if (!instance)
    {
        std::cout << "runtime not found: " << name << "\n";
        return 1;
    }

    runtime_type type = instance->get_type();
    bool is_running = instance->get_state() == runtime_running;

    for (size_t i = 2; i < pa.count; ++i)
    {
        int result = parse_common_edit_flags(instance, pa, i, is_running);
        if (result == -1)
        {
            switch (type)
            {
                case runtime_server:
                    result = parse_server_edit_flags(
                        static_cast<server_instance*>(instance), pa, i, is_running, &m_manager);
                    break;
                case runtime_client:
                    result = parse_client_edit_flags(
                        static_cast<client_instance*>(instance), pa, i, is_running);
                    break;
                case runtime_proxy:
                    result = parse_proxy_edit_flags(
                        static_cast<proxy_instance*>(instance), pa, i);
                    break;
                case runtime_cache:
                    result = -1;
                    break;
            }
        }

        if (result == -1)
        {
            std::cout << "unknown flag: " << pa.args[i] << "\n";
            return 1;
        }

        if (result > 0)
            return result;
    }

    if (m_persistence)
        m_persistence->save_runtime(instance);

    return 0;
}

int daemon_handler::cmd_dump(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2)
    {
        conn->write_buf = "usage: show <name|pattern>...\n";
        return 1;
    }

    if (!m_persistence)
    {
        conn->write_buf = "state persistence not available\n";
        return 2;
    }

    auto names = resolve_names(pa);
    int rc = check_empty_names(names, pa, "runtime not found: ", conn);
    if (rc >= 0) return rc;

    bool first = true;
    for (const auto& n : names)
    {
        auto* inst = m_manager.get(n);
        if (!inst)
            continue;
        if (!first)
            conn->write_buf += '\n';
        first = false;
        runtime_config cfg = m_persistence->read_from_instance(inst);
        conn->write_buf += m_persistence->format_json_pretty(cfg);
    }
    return 0;
}

int daemon_handler::cmd_import(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 3)
    {
        conn->write_buf = "usage: import <name> <json>\n";
        return 1;
    }

    std::string_view name = pa.args[1];
    auto* instance = m_manager.get(name);
    if (!instance)
    {
        conn->write_buf = "runtime not found: " + std::string(name) + "\n";
        return 1;
    }

    if (!m_persistence)
    {
        conn->write_buf = "state persistence not available\n";
        return 2;
    }

    // Extract JSON from everything after the name
    std::string json_str(pa.rest_from(2));
    runtime_config cfg;
    if (!m_persistence->parse_json_string(json_str, cfg))
    {
        conn->write_buf = "invalid JSON\n";
        return 1;
    }

    bool is_running = instance->get_state() == runtime_running;
    runtime_type type = instance->get_type();

    // Handle rename
    std::string old_name(name);
    bool renamed = false;
    if (!cfg.name.empty() && cfg.name != old_name)
    {
        if (is_running)
        {
            conn->write_buf = "cannot rename while running\n";
            return 1;
        }
        if (!m_manager.rename(old_name, cfg.name))
        {
            conn->write_buf = "rename failed: name already taken\n";
            return 1;
        }
        // Re-fetch instance under new name
        instance = m_manager.get(cfg.name);
        renamed = true;
    }

    // Validate changes that require restart
    if (is_running)
    {
        if (cfg.port != instance->get_port())
        {
            conn->write_buf = "cannot change port while running\n";
            return 1;
        }
        if (cfg.tls != instance->get_tls())
        {
            conn->write_buf = "cannot change TLS while running\n";
            return 1;
        }
        if (type == runtime_server || type == runtime_client)
        {
            bool cur_udp = instance->is_udp();
            if (cfg.udp != cur_udp)
            {
                conn->write_buf = "cannot change protocol while running\n";
                return 1;
            }
        }
        if (type == runtime_client)
        {
            if (cfg.target != std::string(instance->get_target()))
            {
                conn->write_buf = "cannot change target while running\n";
                return 1;
            }
        }
        if (type == runtime_proxy)
        {
            auto* prx = static_cast<proxy_instance*>(instance);
            if (cfg.protocol != static_cast<uint8_t>(prx->get_protocol()))
            {
                conn->write_buf = "cannot change protocol while running\n";
                return 1;
            }
        }
        if (type == runtime_cache)
        {
            auto* cache = static_cast<cache_instance*>(instance);
            if (cfg.resp_forced != cache->get_resp_forced())
            {
                conn->write_buf = "cannot change RESP mode while running\n";
                return 1;
            }
            if (cfg.replicate_target != std::string(cache->get_replicate_target()))
            {
                conn->write_buf = "cannot change replication while running\n";
                return 1;
            }
        }
    }

    // Apply common fields
    instance->set_port(cfg.port);
    instance->set_log_file(cfg.log_file);
    instance->set_write_file(cfg.write_file);
    instance->set_bash_output(cfg.bash_output);
    instance->set_bash_prefix(cfg.bash_prefix);
    instance->set_bash_timestamp(cfg.bash_timestamp);
    instance->set_max_connections(cfg.max_connections);
    instance->set_rate_limit(cfg.rate_limit);
    instance->set_drain(cfg.drain);
    instance->set_reconnect(cfg.reconnect);
    instance->set_tls(cfg.tls);
    instance->set_cert_path(cfg.cert_path);
    instance->set_key_path(cfg.key_path);
    instance->set_ca_path(cfg.ca_path);
    instance->set_target(cfg.target);
    instance->set_cache_name(cfg.cache_name);

    // Lua script: reload if changed
    std::string cur_lua(instance->get_lua_script_path());
    if (cfg.lua_script != cur_lua)
    {
        if (!cfg.lua_script.empty())
        {
            if (!instance->load_lua_script(cfg.lua_script))
            {
                conn->write_buf = "could not load Lua script: " + cfg.lua_script + "\n";
                return 1;
            }
        }
    }

    // Apply type-specific fields
    switch (type)
    {
        case runtime_server:
        {
            auto* srv = static_cast<server_instance*>(instance);
            srv->set_mode(static_cast<server_mode>(cfg.mode));
            srv->set_udp(cfg.udp);
            if (!cfg.cache_name.empty())
                srv->set_runtime_manager(&m_manager);
            if (!cfg.master_pw.empty())
                srv->set_master_pw(cfg.master_pw);
            if (cfg.master_forward)
                srv->set_master_forward(true);
            break;
        }
        case runtime_client:
        {
            auto* cli = static_cast<client_instance*>(instance);
            cli->set_mode(static_cast<client_mode>(cfg.mode));
            cli->set_udp(cfg.udp);
            break;
        }
        case runtime_proxy:
        {
            auto* prx = static_cast<proxy_instance*>(instance);
            prx->set_protocol(static_cast<proxy_protocol>(cfg.protocol));
            prx->set_strategy(static_cast<proxy_strategy>(cfg.strategy));
            prx->clear_backends();
            for (const auto& b : cfg.backends)
                prx->add_backend(b);
            prx->set_runtime_manager(&m_manager);
            break;
        }
        case runtime_cache:
        {
            auto* cache = static_cast<cache_instance*>(instance);
            cache->set_persistent(cfg.persistent_path);
            cache->set_mode(static_cast<cache_mode>(cfg.cache_mode));
            cache->set_resp_forced(cfg.resp_forced);
            cache->set_replicate_target(cfg.replicate_target);
            cache->set_max_memory(cfg.max_memory);
            cache->set_eviction(static_cast<eviction_policy>(cfg.eviction));
            break;
        }
    }

    if (renamed)
        m_persistence->remove_runtime(old_name);
    m_persistence->save_runtime(instance);
    return 0;
}

int daemon_handler::cmd_stats(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2)
    {
        conn->write_buf = "usage: stats <name|pattern>...\n";
        return 1;
    }

    auto names = resolve_names(pa);
    int rc = check_empty_names(names, pa, "runtime not found: ", conn);
    if (rc >= 0) return rc;

    for (const auto& n : names)
    {
        auto* inst = m_manager.get(n);
        if (inst)
        {
            conn->write_buf += inst->get_stats();
            conn->write_buf += '\n';
        }
    }
    return 0;
}

int daemon_handler::cmd_reload(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2)
    {
        conn->write_buf = "usage: reload <name|pattern>...\n";
        return 1;
    }

    auto names = resolve_names(pa);
    int rc = check_empty_names(names, pa, "runtime not found: ", conn);
    if (rc >= 0) return rc;

    for (const auto& n : names)
    {
        auto* inst = m_manager.get(n);
        if (!inst || inst->get_state() != runtime_running)
            continue;
        m_manager.stop(n, m_loop);
        if (m_manager.run(n, m_loop) && m_persistence)
            m_persistence->set_was_running(n, true);
    }
    return 0;
}

int daemon_handler::cmd_reload_lua(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2)
    {
        conn->write_buf = "usage: reload-lua <name|pattern>...\n";
        return 1;
    }

    auto names = resolve_names(pa);
    int rc = check_empty_names(names, pa, "runtime not found: ", conn);
    if (rc >= 0) return rc;

    for (const auto& n : names)
    {
        auto* inst = m_manager.get(n);
        if (inst && !inst->get_lua_script_path().empty())
            inst->reload_lua_script();
    }
    return 0;
}

int daemon_handler::cmd_attach(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 4)
    {
        conn->write_buf = "usage: attach <type> <name> <port> [--owner <name>]\n";
        return 1;
    }

    runtime_type type;
    if (!parse_runtime_type(pa.args[1], type))
    {
        conn->write_buf = std::string("unknown runtime type: ") + std::string(pa.args[1]) + "\n";
        return 1;
    }

    std::string_view name = pa.args[2];

    // Parse port
    uint16_t port = 0;
    {
        auto sv = pa.args[3];
        auto result = std::from_chars(sv.data(), sv.data() + sv.size(), port);
        if (result.ec != std::errc{} || port == 0)
        {
            conn->write_buf = "invalid port: " + std::string(sv) + "\n";
            return 1;
        }
    }

    // Check for name collision
    if (m_manager.get(name))
    {
        conn->write_buf = std::string("runtime already exists: ") + std::string(name) + "\n";
        return 1;
    }

    if (!m_manager.create(type, name))
    {
        conn->write_buf = "internal error: could not create runtime\n";
        return 2;
    }

    auto* inst = m_manager.get(name);
    if (!inst)
    {
        conn->write_buf = "internal error\n";
        return 2;
    }

    inst->set_port(port);
    inst->set_runtime_manager(&m_manager);
    inst->set_event_loop(&m_loop);

    // Parse optional flags
    for (size_t i = 4; i < pa.count; ++i)
    {
        if ((pa.args[i] == "--owner" || pa.args[i] == "-o") && i + 1 < pa.count)
        {
            inst->set_owner(pa.args[++i]);
        }
        else if (pa.args[i] == "--pid" && i + 1 < pa.count)
        {
            pid_t pid = 0;
            auto sv = pa.args[++i];
            std::from_chars(sv.data(), sv.data() + sv.size(), pid);
            if (pid > 0)
                inst->set_pid(pid);
        }
    }

    // Mark as external — must come before run() so start() skips io_uring setup
    inst->mark_external();

    if (!m_manager.run(name, m_loop))
    {
        conn->write_buf = "could not register external runtime\n";
        m_manager.remove(name);
        return 2;
    }

    if (m_persistence)
        m_persistence->save_runtime(inst);

    return 0;
}

void daemon_handler::send_response(ipc_connection* conn, int exit_code)
{
    std::string response;
    response += static_cast<char>(exit_code);
    response += conn->write_buf;
    response += '\0';
    conn->write_buf = std::move(response);

    conn->write_req.buffer = conn->write_buf.data();
    conn->write_req.length = static_cast<uint32_t>(conn->write_buf.size());

    m_loop.submit_write(conn->fd, conn->write_buf.data(),
        static_cast<uint32_t>(conn->write_buf.size()), &conn->write_req);
}
