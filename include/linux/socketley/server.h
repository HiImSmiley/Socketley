// socketley/server.h — Server runtime (Tier 2, requires libsocketley_sdk.a)
#pragma once
#include "core.h"
#include "socketley/runtime/server/server_instance.h"

namespace socketley {

// ─── High-level server wrapper ──────────────────────────────────────────────
// Usage:
//   socketley::server srv(9000);
//   srv.on_message([&](int fd, std::string_view msg) {
//       srv.send(fd, "echo: " + std::string(msg));
//   });
//   srv.start();
//
// Limitations:
//   - One start() per process (signal handler points to one event_loop)
//   - start() blocks; for async patterns, use the raw API via instance()/loop()
class server {
public:
    explicit server(uint16_t port) : m_name("_sdk_server") {
        m_mgr.create(runtime_server, m_name);
        auto* inst = raw();
        inst->set_port(port);
        inst->set_runtime_manager(&m_mgr);
        inst->set_event_loop(&m_loop);
    }

    // ── Chainable config ────────────────────────────────────────────────
    server& tls(std::string_view cert, std::string_view key) {
        auto* i = raw(); i->set_tls(true); i->set_cert_path(cert); i->set_key_path(key); return *this;
    }
    server& tls_ca(std::string_view ca)    { raw()->set_tls(true); raw()->set_ca_path(ca); return *this; }
    server& max_connections(uint32_t n)    { raw()->set_max_connections(n); return *this; }
    server& rate_limit(double r)           { raw()->set_rate_limit(r); return *this; }
    server& global_rate_limit(double r)    { raw()->set_global_rate_limit(r); return *this; }
    server& idle_timeout(uint32_t s)       { raw()->set_idle_timeout(s); return *this; }
    server& log_file(std::string_view p)   { raw()->set_log_file(p); return *this; }
    server& lua(std::string_view path)     { raw()->load_lua_script(path); return *this; }
    server& mode(server_mode m)            { srv()->set_mode(m); return *this; }
    server& udp()                          { srv()->set_udp(true); return *this; }
    server& http_dir(std::string_view p)   { srv()->set_http_dir(p); return *this; }
    server& http_cache()                   { srv()->set_http_cache(true); return *this; }
    server& upstream(std::string_view a)   { srv()->add_upstream_target(a); return *this; }
    server& clear_upstreams()              { srv()->clear_upstream_targets(); return *this; }
    server& master_pw(std::string_view pw) { srv()->set_master_pw(pw); return *this; }
    server& master_forward(bool fwd)       { srv()->set_master_forward(fwd); return *this; }
    server& drain()                        { raw()->set_drain(true); return *this; }
    server& group(std::string_view g)      { raw()->set_group(g); return *this; }
    server& tick_interval(uint32_t ms)     { raw()->set_tick_interval(ms); return *this; }

    // ── Callbacks (chainable) ───────────────────────────────────────────
    server& on_start(std::function<void()> cb)                              { raw()->set_on_start(std::move(cb)); return *this; }
    server& on_stop(std::function<void()> cb)                               { raw()->set_on_stop(std::move(cb)); return *this; }
    server& on_connect(std::function<void(int)> cb)                         { raw()->set_on_connect(std::move(cb)); return *this; }
    server& on_disconnect(std::function<void(int)> cb)                      { raw()->set_on_disconnect(std::move(cb)); return *this; }
    server& on_message(std::function<void(int, std::string_view)> cb)       { raw()->set_on_client_message(std::move(cb)); return *this; }
    server& on_tick(std::function<void(double)> cb)                         { raw()->set_on_tick(std::move(cb)); return *this; }
    server& on_auth(std::function<bool(int)> cb)                            { raw()->set_on_auth(std::move(cb)); return *this; }
    server& on_websocket(std::function<void(int, const server_instance::ws_headers_result&)> cb) { srv()->set_on_websocket(std::move(cb)); return *this; }

    // ── Actions ─────────────────────────────────────────────────────────
    void send(int fd, std::string_view msg)                          { srv()->lua_send_to(fd, msg); }
    void broadcast(std::string_view msg)                             { srv()->lua_broadcast(msg); }
    void disconnect(int fd)                                          { srv()->lua_disconnect(fd); }
    std::string peer_ip(int fd)                                      { return srv()->lua_peer_ip(fd); }
    std::vector<int> clients()                                       { return srv()->lua_clients(); }
    void multicast(const std::vector<int>& fds, std::string_view m)  { srv()->lua_multicast(fds, m); }
    void set_data(int fd, std::string_view k, std::string_view v)    { srv()->lua_set_data(fd, k, v); }
    std::string get_data(int fd, std::string_view k)                 { return srv()->lua_get_data(fd, k); }
    void del_data(int fd, std::string_view k)                        { srv()->lua_del_data(fd, k); }
    server_instance::ws_headers_result ws_headers(int fd)            { return srv()->lua_ws_headers(fd); }
    void rebuild_http_cache()                                        { srv()->rebuild_http_cache(); }

    // ── Multicast groups ────────────────────────────────────────────────
    void join_group(int fd, std::string_view group)                  { srv()->lua_join_group(fd, group); }
    void leave_group(int fd, std::string_view group)                 { srv()->lua_leave_group(fd, group); }
    void group_send(std::string_view group, std::string_view msg)    { srv()->lua_group_send(group, msg); }

    // ── Zero-copy pipe pairing ──────────────────────────────────────────
    void pipe(int fd_a, int fd_b)                                    { srv()->lua_pipe(fd_a, fd_b); }
    void unpipe(int fd)                                              { srv()->lua_unpipe(fd); }

    // ── Upstream connections ────────────────────────────────────────────
    void upstream_send(int conn_id, std::string_view msg)            { srv()->lua_upstream_send(conn_id, msg); }
    void upstream_broadcast(std::string_view msg)                    { srv()->lua_upstream_broadcast(msg); }
    std::vector<int> upstreams()                                     { return srv()->lua_upstreams(); }

    // ── Ownership / hierarchy ───────────────────────────────────────────
    server& owner(std::string_view name)                   { raw()->set_owner(name); return *this; }
    server& child_policy(runtime_instance::child_policy p) { raw()->set_child_policy(p); return *this; }

    // ── Introspection ───────────────────────────────────────────────────
    size_t           connection_count()  { return raw()->get_connection_count(); }
    runtime_state    state()             { return raw()->get_state(); }
    std::string_view name()              { return raw()->get_name(); }
    uint16_t         port()              { return raw()->get_port(); }
    std::string      stats()             { return raw()->get_stats(); }
    std::string_view id()                { return raw()->get_id(); }
    std::string_view get_group()         { return raw()->get_group(); }
    std::string_view get_owner()         { return raw()->get_owner(); }
    bool             get_drain()         { return raw()->get_drain(); }
    bool             get_tls()           { return raw()->get_tls(); }
    std::string_view get_cert_path()     { return raw()->get_cert_path(); }
    std::string_view get_key_path()      { return raw()->get_key_path(); }
    std::string_view get_ca_path()       { return raw()->get_ca_path(); }
    std::string_view get_log_file()      { return raw()->get_log_file(); }
    uint32_t         get_max_connections() { return raw()->get_max_connections(); }
    uint32_t         get_idle_timeout()  { return raw()->get_idle_timeout(); }
    double           get_rate_limit()    { return raw()->get_rate_limit(); }
    double           get_global_rate_limit() { return raw()->get_global_rate_limit(); }
    runtime_instance::child_policy get_child_policy() { return raw()->get_child_policy(); }
    bool             reload_lua()        { return raw()->reload_lua_script(); }
    std::string_view lua_script()        { return raw()->get_lua_script_path(); }
    server_mode      get_mode()          { return srv()->get_mode(); }
    bool             get_master_forward() { return srv()->get_master_forward(); }
    std::string_view get_master_pw()     { return srv()->get_master_pw(); }
    bool             get_http_cache()    { return srv()->get_http_cache(); }
    const std::filesystem::path& get_http_dir() { return srv()->get_http_dir(); }
    const std::vector<upstream_target>& get_upstream_targets() { return srv()->get_upstream_targets(); }
    std::chrono::system_clock::time_point created_time() { return raw()->get_created_time(); }
    std::chrono::system_clock::time_point start_time()   { return raw()->get_start_time(); }

    // ── Lifecycle ───────────────────────────────────────────────────────
    void start() {
        if (!m_loop.init()) return;
        detail::install_signal_handlers(&m_loop);
        m_mgr.start(m_name, m_loop);
        m_loop.run();
        m_mgr.stop_all(m_loop);
    }
    void stop() { m_loop.request_stop(); }

    // ── Escape hatches ──────────────────────────────────────────────────
    server_instance*  instance() { return srv(); }
    runtime_manager&  manager()  { return m_mgr; }
    event_loop&       loop()     { return m_loop; }

private:
    runtime_instance* raw() { return m_mgr.get(m_name); }
    server_instance*  srv() { return static_cast<server_instance*>(raw()); }

    std::string     m_name;
    event_loop      m_loop;
    runtime_manager m_mgr;
};

} // namespace socketley
