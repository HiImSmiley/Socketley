#include "lua_context.h"

#ifndef SOCKETLEY_NO_LUA

#include "runtime_instance.h"
#include "runtime_definitions.h"
#include "runtime_manager.h"
#include "cluster_discovery.h"
#include "event_loop.h"
#include "../runtime/server/server_instance.h"
#include "../cli/command_hashing.h"
#include "../cli/runtime_type_parser.h"
#include <iostream>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#ifndef SOCKETLEY_NO_HTTPS
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

lua_context::lua_context()
{
    m_lua.open_libraries(sol::lib::base, sol::lib::string, sol::lib::table,
                         sol::lib::math, sol::lib::os, sol::lib::io);
}

lua_context::~lua_context()
{
    *m_alive = false;
}

// ─── lua_timer: heap-allocated one-shot / repeating timer via op_timeout ───
struct lua_timer : io_handler
{
    std::shared_ptr<bool> alive;
    sol::function         fn;
    event_loop*           loop{};
    struct __kernel_timespec ts{};
    io_request            req{};
    bool                  repeat{false};

    void on_cqe(struct io_uring_cqe* cqe) override
    {
        if (!*alive || cqe->res == -ECANCELED) { delete this; return; }
        try { fn(); } catch (const sol::error& e) {
            fprintf(stderr, "[lua] timer error: %s\n", e.what());
        }
        if (repeat && *alive)
            loop->submit_timeout(&ts, &req);
        else
            delete this;
    }
};

static const char* type_to_string(runtime_type t)
{
    switch (t)
    {
        case runtime_server: return "server";
        case runtime_client: return "client";
        case runtime_proxy:  return "proxy";
        case runtime_cache:  return "cache";
    }
    return "unknown";
}

static const char* state_to_string(runtime_state s)
{
    switch (s)
    {
        case runtime_created: return "created";
        case runtime_running: return "running";
        case runtime_stopped: return "stopped";
        case runtime_failed:  return "failed";
    }
    return "unknown";
}

bool lua_context::load_script(std::string_view path, runtime_instance* owner)
{
    register_bindings(owner);

    auto result = m_lua.safe_script_file(std::string(path), sol::script_pass_on_error);
    if (!result.valid())
    {
        sol::error err = result;
        std::cerr << "[lua] script error: " << err.what() << std::endl;
        return false;
    }

    m_on_start = m_lua["on_start"];
    m_on_stop = m_lua["on_stop"];
    m_on_message = m_lua["on_message"];
    m_on_send = m_lua["on_send"];
    m_on_connect = m_lua["on_connect"];
    m_on_disconnect = m_lua["on_disconnect"];
    m_on_route = m_lua["on_route"];
    m_on_master_auth = m_lua["on_master_auth"];
    m_on_client_message = m_lua["on_client_message"];
    m_on_tick = m_lua["on_tick"];
    if (m_on_tick.valid()) {
        sol::optional<int> tms = m_lua["tick_ms"];
        m_tick_ms = (tms && *tms >= 10) ? static_cast<uint32_t>(*tms) : 100;
    }
    m_on_miss   = m_lua["on_miss"];
    m_on_write  = m_lua["on_write"];
    m_on_delete = m_lua["on_delete"];
    m_on_expire = m_lua["on_expire"];
    m_on_auth       = m_lua["on_auth"];
    m_on_websocket  = m_lua["on_websocket"];
    m_on_proxy_request  = m_lua["on_proxy_request"];
    m_on_proxy_response = m_lua["on_proxy_response"];
    m_on_cluster_join   = m_lua["on_cluster_join"];
    m_on_cluster_leave  = m_lua["on_cluster_leave"];
    m_on_group_change   = m_lua["on_group_change"];

    return true;
}

bool lua_context::has_on_start() const { return m_on_start.valid(); }
bool lua_context::has_on_stop() const { return m_on_stop.valid(); }
bool lua_context::has_on_message() const { return m_on_message.valid(); }
bool lua_context::has_on_send() const { return m_on_send.valid(); }
bool lua_context::has_on_connect() const { return m_on_connect.valid(); }
bool lua_context::has_on_disconnect() const { return m_on_disconnect.valid(); }
bool lua_context::has_on_route() const { return m_on_route.valid(); }
bool lua_context::has_on_master_auth() const { return m_on_master_auth.valid(); }
bool lua_context::has_on_client_message() const { return m_on_client_message.valid(); }
bool lua_context::has_on_tick() const { return m_on_tick.valid(); }
bool lua_context::has_on_miss()   const { return m_on_miss.valid(); }
bool lua_context::has_on_write()  const { return m_on_write.valid(); }
bool lua_context::has_on_delete() const { return m_on_delete.valid(); }
bool lua_context::has_on_expire() const { return m_on_expire.valid(); }
bool lua_context::has_on_auth()            const { return m_on_auth.valid(); }
bool lua_context::has_on_websocket()       const { return m_on_websocket.valid(); }
bool lua_context::has_on_proxy_request()   const { return m_on_proxy_request.valid(); }
bool lua_context::has_on_proxy_response()  const { return m_on_proxy_response.valid(); }
bool lua_context::has_on_cluster_join()    const { return m_on_cluster_join.valid(); }
bool lua_context::has_on_cluster_leave()   const { return m_on_cluster_leave.valid(); }
bool lua_context::has_on_group_change()    const { return m_on_group_change.valid(); }

void lua_context::dispatch_publish(std::string_view cache_name, std::string_view channel, std::string_view message)
{
    auto key = std::string(cache_name) + '\0' + std::string(channel);
    auto it = m_subscriptions.find(key);
    if (it == m_subscriptions.end()) return;
    for (auto& fn : it->second)
    {
        try { fn(std::string(channel), std::string(message)); }
        catch (const sol::error& e)
        {
            fprintf(stderr, "[lua] subscribe callback error: %s\n", e.what());
        }
    }
}

void lua_context::update_self_state(const char* state_str)
{
    sol::optional<sol::table> self = m_lua["self"];
    if (self)
        (*self)["state"] = state_str;
}

// ---------------------------------------------------------------------------
// socketley.http(opts) — synchronous HTTP/HTTPS client for Lua scripts
// opts = { url, method="GET", body="", headers={}, timeout_ms=5000 }
// Returns { ok=bool, status=int, body=string, error=string }
// WARNING: Blocks the event loop thread. Use only in on_start/on_stop or
// low-frequency on_tick callbacks. For HTTPS, cert verification is skipped
// (SSL_VERIFY_NONE) — suitable for trusted internal services.
// ---------------------------------------------------------------------------
static sol::table socketley_http_call(sol::state& lua, sol::table opts)
{
    sol::table result = lua.create_table();
    result["ok"]     = false;
    result["status"] = 0;
    result["body"]   = std::string{};
    result["error"]  = std::string{};

    sol::optional<std::string> url_opt = opts["url"];
    if (!url_opt || url_opt->empty()) { result["error"] = "url required"; return result; }

    std::string method  = sol::optional<std::string>(opts["method"]).value_or("GET");
    std::string url     = *url_opt;
    std::string body    = sol::optional<std::string>(opts["body"]).value_or("");
    int timeout_ms      = sol::optional<int>(opts["timeout_ms"]).value_or(5000);

    // Parse scheme
    bool is_https = false;
    if (url.rfind("https://", 0) == 0)      { is_https = true;  url = url.substr(8); }
    else if (url.rfind("http://", 0) == 0)  {                   url = url.substr(7); }
    else { result["error"] = "unsupported scheme (use http:// or https://)"; return result; }

#ifdef SOCKETLEY_NO_HTTPS
    if (is_https) {
        result["error"] = "HTTPS not supported in this build; use io.popen(\"curl -s https://...\")";
        return result;
    }
#endif

    // Parse host:port/path
    int port = is_https ? 443 : 80;
    std::string host, path;
    auto slash = url.find('/');
    std::string host_port = (slash != std::string::npos) ? url.substr(0, slash) : url;
    path = (slash != std::string::npos) ? url.substr(slash) : "/";
    auto colon = host_port.rfind(':');
    if (colon != std::string::npos) {
        host = host_port.substr(0, colon);
        try { port = std::stoi(host_port.substr(colon + 1)); } catch (...) {}
    } else {
        host = host_port;
    }

    // DNS resolve
    struct addrinfo hints{}, *addrs = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &addrs) != 0 || !addrs) {
        result["error"] = "DNS resolution failed for: " + host;
        return result;
    }

    // Connect
    int sock = ::socket(addrs->ai_family, SOCK_STREAM, 0);
    if (sock < 0) { freeaddrinfo(addrs); result["error"] = "socket() failed"; return result; }

    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (::connect(sock, addrs->ai_addr, addrs->ai_addrlen) != 0) {
        freeaddrinfo(addrs); ::close(sock);
        result["error"] = "connect() failed";
        return result;
    }
    freeaddrinfo(addrs);

    // Build HTTP/1.0 request
    std::string req;
    req.reserve(256 + body.size());
    req += method + " " + path + " HTTP/1.0\r\n";
    req += "Host: " + host + "\r\n";
    if (!body.empty())
        req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    sol::optional<sol::table> hdrs = opts["headers"];
    if (hdrs) {
        (*hdrs).for_each([&](sol::object k, sol::object v) {
            if (k.is<std::string>() && v.is<std::string>())
                req += k.as<std::string>() + ": " + v.as<std::string>() + "\r\n";
        });
    }
    req += "Connection: close\r\n\r\n";
    req += body;

    // Send + receive
    std::string response;
    std::string send_err;

#ifndef SOCKETLEY_NO_HTTPS
    if (is_https) {
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { ::close(sock); result["error"] = "SSL_CTX_new failed"; return result; }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        SSL* ssl = SSL_new(ctx);
        if (!ssl) { SSL_CTX_free(ctx); ::close(sock); result["error"] = "SSL_new failed"; return result; }
        SSL_set_fd(ssl, sock);
        SSL_set_tlsext_host_name(ssl, host.c_str());
        if (SSL_connect(ssl) != 1) {
            SSL_free(ssl); SSL_CTX_free(ctx); ::close(sock);
            result["error"] = "TLS handshake failed"; return result;
        }
        if (SSL_write(ssl, req.c_str(), static_cast<int>(req.size())) <= 0) {
            send_err = "SSL_write failed";
        } else {
            char buf[4096]; int n;
            while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0)
                response.append(buf, n);
        }
        SSL_shutdown(ssl);
        SSL_free(ssl); SSL_CTX_free(ctx);
        ::close(sock);
    } else
#endif
    {
        if (::send(sock, req.c_str(), req.size(), 0) < 0) {
            send_err = "send() failed";
        } else {
            char buf[4096]; ssize_t n;
            while ((n = ::recv(sock, buf, sizeof(buf), 0)) > 0)
                response.append(buf, n);
        }
        ::close(sock);
    }

    if (!send_err.empty()) { result["error"] = send_err; return result; }

    // Parse HTTP status line: "HTTP/1.x NNN Reason"
    int status = 0;
    auto sp1 = response.find(' ');
    if (sp1 != std::string::npos) {
        auto sp2 = response.find(' ', sp1 + 1);
        try { status = std::stoi(response.substr(sp1 + 1, sp2 - sp1 - 1)); } catch (...) {}
    }
    auto body_start = response.find("\r\n\r\n");
    result["status"] = status;
    result["body"]   = (body_start != std::string::npos) ? response.substr(body_start + 4) : "";
    result["ok"]     = (status >= 200 && status < 300);
    return result;
}

void lua_context::register_bindings(runtime_instance* owner)
{
    // Register socketley.log() and management API
    sol::table sk = m_lua.create_table();
    sk["log"] = [](std::string msg) {
        std::cerr << "[lua] " << msg << std::endl;
    };

    // socketley.create(type, name, config_table) → bool
    sk["create"] = [owner, this](std::string type_str, std::string name, sol::optional<sol::table> config) -> bool {
        auto* mgr = owner->get_runtime_manager();
        auto* loop = owner->get_event_loop();
        if (!mgr || !loop) return false;

        runtime_type type;
        if (!parse_runtime_type(type_str, type)) return false;

        if (!mgr->create(type, name)) return false;

        auto* inst = mgr->get(name);
        if (!inst) return false;

        inst->set_runtime_manager(mgr);
        inst->set_event_loop(loop);
        inst->set_owner(owner->get_name());
        inst->set_lua_created(true);

        if (config) {
            sol::optional<int> port = (*config)["port"];
            if (port) inst->set_port(static_cast<uint16_t>(*port));

            sol::optional<std::string> lua_script = (*config)["config"];
            if (!lua_script) lua_script = (*config)["lua"];
            if (lua_script && !lua_script->empty())
                inst->load_lua_script(*lua_script);

            sol::optional<std::string> target = (*config)["target"];
            if (target) inst->set_target(*target);

            sol::optional<std::string> mode_str = (*config)["mode"];
            if (mode_str && type == runtime_server) {
                auto* srv = static_cast<server_instance*>(inst);
                switch (fnv1a(*mode_str)) {
                    case fnv1a("in"):     srv->set_mode(mode_in);     break;
                    case fnv1a("out"):    srv->set_mode(mode_out);    break;
                    case fnv1a("master"): srv->set_mode(mode_master); break;
                    default:              srv->set_mode(mode_inout);  break;
                }
            }

            if (type == runtime_server) {
                auto* srv = static_cast<server_instance*>(inst);
                sol::optional<std::string> http_dir = (*config)["http"];
                if (http_dir && !http_dir->empty())
                    srv->set_http_dir(*http_dir);
                sol::optional<bool> http_cache = (*config)["http_cache"];
                if (http_cache && *http_cache)
                    srv->set_http_cache(true);
            }

            sol::optional<std::string> group = (*config)["group"];
            if (group && !group->empty())
                inst->set_group(*group);

            sol::optional<std::string> on_stop_str = (*config)["on_parent_stop"];
            if (on_stop_str && fnv1a(*on_stop_str) == fnv1a("remove"))
                inst->set_child_policy(runtime_instance::child_policy::remove);

            sol::optional<bool> autostart = (*config)["autostart"];
            if (autostart && *autostart)
                mgr->run(name, *loop);
        }

        return true;
    };

    // socketley.start(name) → bool
    sk["start"] = [owner](std::string name) -> bool {
        auto* mgr = owner->get_runtime_manager();
        auto* loop = owner->get_event_loop();
        if (!mgr || !loop) return false;
        return mgr->run(name, *loop);
    };

    // socketley.stop(name) → bool
    sk["stop"] = [owner](std::string name) -> bool {
        auto* mgr = owner->get_runtime_manager();
        auto* loop = owner->get_event_loop();
        if (!mgr || !loop) return false;
        return mgr->stop(name, *loop);
    };

    // socketley.remove(name) → bool
    sk["remove"] = [owner](std::string name) -> bool {
        auto* mgr = owner->get_runtime_manager();
        auto* loop = owner->get_event_loop();
        if (!mgr || !loop) return false;
        auto* inst = mgr->get(name);
        if (inst && inst->get_state() == runtime_running)
            mgr->stop(name, *loop);
        return mgr->remove(name);
    };

    // socketley.send(name, msg) → bool
    sk["send"] = [owner](std::string name, std::string msg) -> bool {
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return false;
        auto* inst = mgr->get(name);
        if (!inst || inst->get_state() != runtime_running) return false;
        if (inst->get_type() == runtime_server)
            inst->lua_broadcast(msg);
        else
            inst->lua_send(msg);
        return true;
    };

    // socketley.list() → table of names
    sk["list"] = [owner, this]() -> sol::table {
        sol::table result = m_lua.create_table();
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return result;
        std::shared_lock lock(mgr->mutex);
        int i = 1;
        for (const auto& [name, _] : mgr->list())
            result[i++] = name;
        return result;
    };

    // socketley.get(name) → table {name, type, state, port, connections, owner} or nil
    sk["get"] = [owner, this](std::string name) -> sol::object {
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return sol::nil;
        auto* inst = mgr->get(name);
        if (!inst) return sol::nil;
        sol::table info = m_lua.create_table();
        info["name"] = std::string(inst->get_name());
        info["type"] = type_to_string(inst->get_type());
        info["state"] = state_to_string(inst->get_state());
        info["port"] = inst->get_port();
        info["connections"] = inst->get_connection_count();
        auto ow = inst->get_owner();
        info["owner"] = ow.empty() ? sol::object(sol::nil) : sol::make_object(m_lua, std::string(ow));
        return info;
    };

    sk["http"] = [this](sol::table opts) -> sol::table {
        return socketley_http_call(m_lua, opts);
    };

    // socketley.set_timeout(ms, fn) — fires fn once after ms milliseconds
    sk["set_timeout"] = [this, owner](int ms, sol::function fn) {
        auto* loop = owner->get_event_loop();
        if (!loop || ms <= 0) return;
        auto* t  = new lua_timer{};
        t->alive  = m_alive;
        t->fn     = std::move(fn);
        t->loop   = loop;
        t->ts     = { (long long)ms / 1000, ((long long)ms % 1000) * 1'000'000LL };
        t->req    = { op_timeout, -1, nullptr, 0, t };
        t->repeat = false;
        loop->submit_timeout(&t->ts, &t->req);
    };

    // socketley.set_interval(ms, fn) — fires fn every ms milliseconds
    sk["set_interval"] = [this, owner](int ms, sol::function fn) {
        auto* loop = owner->get_event_loop();
        if (!loop || ms <= 0) return;
        auto* t  = new lua_timer{};
        t->alive  = m_alive;
        t->fn     = std::move(fn);
        t->loop   = loop;
        t->ts     = { (long long)ms / 1000, ((long long)ms % 1000) * 1'000'000LL };
        t->req    = { op_timeout, -1, nullptr, 0, t };
        t->repeat = true;
        loop->submit_timeout(&t->ts, &t->req);
    };

    // socketley.subscribe(cache_name, channel, fn) — receive published messages
    sk["subscribe"] = [this](std::string cache_name, std::string channel, sol::function fn) {
        m_subscriptions[cache_name + '\0' + channel].push_back(std::move(fn));
    };

    // ─── socketley.cluster.* — cluster introspection API ───
    sol::table cluster_tbl = m_lua.create_table();

    // socketley.cluster.daemons() → array of {name, host, healthy, runtimes}
    cluster_tbl["daemons"] = [owner, this]() -> sol::table {
        sol::table result = m_lua.create_table();
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return result;
        auto* cd = mgr->get_cluster_discovery();
        if (!cd) return result;

        int i = 1;
        // Local daemon entry
        {
            sol::table d = m_lua.create_table();
            d["name"] = std::string(cd->get_daemon_name());
            d["host"] = std::string(cd->get_cluster_addr());
            d["healthy"] = true;
            size_t count = 0;
            {
                std::shared_lock lock(mgr->mutex);
                count = mgr->list().size();
            }
            d["runtimes"] = static_cast<int>(count);
            result[i++] = d;
        }
        // Remote daemons
        auto daemons = cd->get_all_daemons();
        for (const auto& rd : daemons)
        {
            sol::table d = m_lua.create_table();
            d["name"] = rd.name;
            d["host"] = rd.host;
            d["healthy"] = true;
            d["runtimes"] = static_cast<int>(rd.runtimes.size());
            result[i++] = d;
        }
        return result;
    };

    // socketley.cluster.runtimes() → array of {daemon, name, type, port, group, state, connections}
    cluster_tbl["runtimes"] = [owner, this]() -> sol::table {
        sol::table result = m_lua.create_table();
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return result;
        auto* cd = mgr->get_cluster_discovery();
        if (!cd) return result;

        int i = 1;
        // Local runtimes
        {
            std::shared_lock lock(mgr->mutex);
            for (const auto& [name, inst] : mgr->list())
            {
                sol::table r = m_lua.create_table();
                r["daemon"] = std::string(cd->get_daemon_name());
                r["name"] = std::string(name);
                r["type"] = type_to_string(inst->get_type());
                r["port"] = inst->get_port();
                r["group"] = std::string(inst->get_group());
                r["state"] = state_to_string(inst->get_state());
                r["connections"] = static_cast<int>(inst->get_connection_count());
                result[i++] = r;
            }
        }
        // Remote runtimes
        auto daemons = cd->get_all_daemons();
        for (const auto& rd : daemons)
        {
            for (const auto& rt : rd.runtimes)
            {
                sol::table r = m_lua.create_table();
                r["daemon"] = rt.daemon_name;
                r["name"] = rt.name;
                r["type"] = rt.type;
                r["port"] = rt.port;
                r["group"] = rt.group;
                r["state"] = rt.state;
                r["connections"] = static_cast<int>(rt.connections);
                result[i++] = r;
            }
        }
        return result;
    };

    // socketley.cluster.group(name) → array of {daemon, host, port, connections}
    cluster_tbl["group"] = [owner, this](std::string group_name) -> sol::table {
        sol::table result = m_lua.create_table();
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return result;
        auto* cd = mgr->get_cluster_discovery();
        if (!cd) return result;

        int i = 1;
        // Local group members
        {
            std::shared_lock lock(mgr->mutex);
            for (const auto& [_, inst] : mgr->list())
            {
                if (inst->get_group() == group_name &&
                    inst->get_state() == runtime_running &&
                    inst->get_port() > 0)
                {
                    sol::table m = m_lua.create_table();
                    m["daemon"] = std::string(cd->get_daemon_name());
                    m["host"] = std::string(cd->get_cluster_addr());
                    m["port"] = inst->get_port();
                    m["connections"] = static_cast<int>(inst->get_connection_count());
                    result[i++] = m;
                }
            }
        }
        // Remote group members
        auto daemons = cd->get_all_daemons();
        for (const auto& rd : daemons)
        {
            for (const auto& rt : rd.runtimes)
            {
                if (rt.group == group_name && rt.state == "running" && rt.port > 0)
                {
                    sol::table m = m_lua.create_table();
                    m["daemon"] = rt.daemon_name;
                    m["host"] = rt.host;
                    m["port"] = rt.port;
                    m["connections"] = static_cast<int>(rt.connections);
                    result[i++] = m;
                }
            }
        }
        return result;
    };

    // socketley.cluster.stats() → {daemons, healthy, stale, runtimes, running, groups={name=count}}
    cluster_tbl["stats"] = [owner, this]() -> sol::table {
        sol::table result = m_lua.create_table();
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return result;
        auto* cd = mgr->get_cluster_discovery();
        if (!cd) return result;

        int daemon_count = 1;  // include local
        int healthy = 1;
        int stale = 0;
        int rt_total = 0;
        int rt_running = 0;
        std::unordered_map<std::string, int> groups;

        // Local runtimes
        {
            std::shared_lock lock(mgr->mutex);
            for (const auto& [_, inst] : mgr->list())
            {
                ++rt_total;
                if (inst->get_state() == runtime_running) ++rt_running;
                auto g = inst->get_group();
                if (!g.empty()) ++groups[std::string(g)];
            }
        }

        // Remote daemons
        auto daemons = cd->get_all_daemons();
        for (const auto& rd : daemons)
        {
            ++daemon_count;
            ++healthy;  // get_all_daemons already filters stale
            for (const auto& rt : rd.runtimes)
            {
                ++rt_total;
                if (rt.state == "running") ++rt_running;
                if (!rt.group.empty()) ++groups[rt.group];
            }
        }

        result["daemons"] = daemon_count;
        result["healthy"] = healthy;
        result["stale"] = stale;
        result["runtimes"] = rt_total;
        result["running"] = rt_running;

        sol::table grp_tbl = m_lua.create_table();
        for (const auto& [name, count] : groups)
            grp_tbl[name] = count;
        result["groups"] = grp_tbl;

        return result;
    };

    sk["cluster"] = cluster_tbl;

    m_lua["socketley"] = sk;

    // Register "self" table with runtime properties and actions
    sol::table self = m_lua.create_table();
    self["name"] = std::string(owner->get_name());
    self["port"] = owner->get_port();
    self["type"] = type_to_string(owner->get_type());
    self["state"] = state_to_string(owner->get_state());

    // Register type-specific action methods
    switch (owner->get_type())
    {
        case runtime_server:
            register_server_table(owner, self);
            break;
        case runtime_client:
            register_client_table(owner, self);
            break;
        case runtime_cache:
            register_cache_table(owner, self);
            break;
        case runtime_proxy:
            register_proxy_table(owner, self);
            break;
    }

    m_lua["self"] = self;

    // Also register type-specific alias (server/client/cache/proxy) pointing to same table
    m_lua[type_to_string(owner->get_type())] = self;
}

void lua_context::register_server_table(runtime_instance* owner, sol::table& self)
{
    self["broadcast"] = [owner](std::string msg) {
        owner->lua_broadcast(msg);
    };
    self["send"] = [owner](int client_id, std::string msg) {
        owner->lua_send_to(client_id, msg);
    };
    self["connections"] = [owner]() -> size_t {
        return owner->get_connection_count();
    };
    self["protocol"] = owner->is_udp() ? "udp" : "tcp";

    // Client routing
    self["route"] = [owner](int client_id, std::string target) -> bool {
        return static_cast<server_instance*>(owner)->route_client(client_id, target);
    };
    self["unroute"] = [owner](int client_id) -> bool {
        return static_cast<server_instance*>(owner)->unroute_client(client_id);
    };
    self["get_route"] = [owner, this](int client_id) -> sol::object {
        auto route = static_cast<server_instance*>(owner)->get_client_route(client_id);
        if (route.empty()) return sol::nil;
        return sol::make_object(m_lua, std::string(route));
    };

    // Owner-targeted sending (sub-server → owner's clients)
    self["owner_send"] = [owner](int client_id, std::string msg) -> bool {
        return static_cast<server_instance*>(owner)->owner_send(client_id, msg);
    };
    self["owner_broadcast"] = [owner](std::string msg) -> bool {
        return static_cast<server_instance*>(owner)->owner_broadcast(msg);
    };

    // Connection control
    self["disconnect"] = [owner](int client_id) {
        static_cast<server_instance*>(owner)->lua_disconnect(client_id);
    };
    self["peer_ip"] = [owner](int client_id) -> std::string {
        return static_cast<server_instance*>(owner)->lua_peer_ip(client_id);
    };
    self["ws_headers"] = [owner, this](int client_id) -> sol::object {
        auto h = static_cast<server_instance*>(owner)->lua_ws_headers(client_id);
        if (!h.is_websocket) return sol::nil;
        sol::table t = m_lua.create_table();
        if (!h.cookie.empty())   t["cookie"]        = h.cookie;
        if (!h.origin.empty())   t["origin"]        = h.origin;
        if (!h.protocol.empty()) t["protocol"]      = h.protocol;
        if (!h.auth.empty())     t["authorization"] = h.auth;
        return t;
    };

    // Client enumeration
    self["clients"] = [owner, this]() -> sol::table {
        sol::table t = m_lua.create_table();
        auto ids = static_cast<server_instance*>(owner)->lua_clients();
        for (int i = 0; i < (int)ids.size(); ++i) t[i + 1] = ids[i];
        return t;
    };

    // Targeted multicast to a subset of clients
    self["multicast"] = [owner](sol::table ids, std::string msg) {
        std::vector<int> fds;
        ids.for_each([&](sol::object, sol::object v) {
            if (v.is<int>()) fds.push_back(v.as<int>());
        });
        static_cast<server_instance*>(owner)->lua_multicast(fds, msg);
    };

    // Per-connection metadata: nil value deletes the key
    self["set_data"] = [owner](int id, std::string key, sol::optional<std::string> val) {
        if (val)
            static_cast<server_instance*>(owner)->lua_set_data(id, key, *val);
        else
            static_cast<server_instance*>(owner)->lua_del_data(id, key);
    };
    self["get_data"] = [owner, this](int id, std::string key) -> sol::object {
        auto v = static_cast<server_instance*>(owner)->lua_get_data(id, key);
        if (v.empty()) return sol::nil;
        return sol::make_object(m_lua, v);
    };
}

void lua_context::register_client_table(runtime_instance* owner, sol::table& self)
{
    self["send"] = [owner](std::string msg) {
        owner->lua_send(msg);
    };
    self["connections"] = [owner]() -> size_t {
        return owner->get_connection_count();
    };
    self["protocol"] = owner->is_udp() ? "udp" : "tcp";
}

void lua_context::register_cache_table(runtime_instance* owner, sol::table& self)
{
    // Strings
    self["get"] = [owner](std::string key) -> std::string {
        return owner->lua_cache_get(key);
    };
    self["set"] = [owner](std::string key, std::string value) -> bool {
        return owner->lua_cache_set(key, value);
    };
    self["del"] = [owner](std::string key) -> bool {
        return owner->lua_cache_del(key);
    };

    // Lists
    self["lpush"] = [owner](std::string key, std::string val) -> bool {
        return owner->lua_cache_lpush(key, val);
    };
    self["rpush"] = [owner](std::string key, std::string val) -> bool {
        return owner->lua_cache_rpush(key, val);
    };
    self["lpop"] = [owner](std::string key) -> std::string {
        return owner->lua_cache_lpop(key);
    };
    self["rpop"] = [owner](std::string key) -> std::string {
        return owner->lua_cache_rpop(key);
    };
    self["llen"] = [owner](std::string key) -> int {
        return owner->lua_cache_llen(key);
    };

    // Sets
    self["sadd"] = [owner](std::string key, std::string member) -> int {
        return owner->lua_cache_sadd(key, member);
    };
    self["srem"] = [owner](std::string key, std::string member) -> bool {
        return owner->lua_cache_srem(key, member);
    };
    self["sismember"] = [owner](std::string key, std::string member) -> bool {
        return owner->lua_cache_sismember(key, member);
    };
    self["scard"] = [owner](std::string key) -> int {
        return owner->lua_cache_scard(key);
    };

    // Hashes
    self["hset"] = [owner](std::string key, std::string field, std::string val) -> bool {
        return owner->lua_cache_hset(key, field, val);
    };
    self["hget"] = [owner](std::string key, std::string field) -> std::string {
        return owner->lua_cache_hget(key, field);
    };
    self["hdel"] = [owner](std::string key, std::string field) -> bool {
        return owner->lua_cache_hdel(key, field);
    };
    self["hlen"] = [owner](std::string key) -> int {
        return owner->lua_cache_hlen(key);
    };

    // TTL
    self["expire"] = [owner](std::string key, int seconds) -> bool {
        return owner->lua_cache_expire(key, seconds);
    };
    self["ttl"] = [owner](std::string key) -> int {
        return owner->lua_cache_ttl(key);
    };
    self["persist"] = [owner](std::string key) -> bool {
        return owner->lua_cache_persist(key);
    };

    // Pub/Sub
    self["publish"] = [owner](std::string channel, std::string message) -> int {
        return owner->lua_cache_publish(channel, message);
    };

    self["connections"] = [owner]() -> size_t {
        return owner->get_connection_count();
    };
}

void lua_context::register_proxy_table(runtime_instance* owner, sol::table& self)
{
    self["connections"] = [owner]() -> size_t {
        return owner->get_connection_count();
    };
}

#endif // SOCKETLEY_NO_LUA
