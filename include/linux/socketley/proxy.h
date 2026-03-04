// socketley/proxy.h — Proxy runtime (Tier 2, requires libsocketley_sdk.a)
#pragma once
#include "core.h"
#include "socketley/runtime/proxy/proxy_instance.h"

namespace socketley {

// ─── High-level proxy wrapper ───────────────────────────────────────────────
// Usage:
//   socketley::proxy px(8080);
//   px.backend("127.0.0.1:9000").protocol(protocol_tcp);
//   px.start();
class proxy {
public:
    explicit proxy(uint16_t port) : m_name("_sdk_proxy") {
        m_mgr.create(runtime_proxy, m_name);
        auto* inst = raw();
        inst->set_port(port);
        inst->set_runtime_manager(&m_mgr);
        inst->set_event_loop(&m_loop);
    }

    // ── Chainable config ────────────────────────────────────────────────
    proxy& backend(std::string_view addr)  { prx()->add_backend(addr); return *this; }
    proxy& clear_backends()                { prx()->clear_backends(); return *this; }
    proxy& strategy(proxy_strategy s)      { prx()->set_strategy(s); return *this; }
    proxy& protocol(proxy_protocol p)      { prx()->set_protocol(p); return *this; }
    proxy& tls(std::string_view cert, std::string_view key) {
        auto* i = raw(); i->set_tls(true); i->set_cert_path(cert); i->set_key_path(key); return *this;
    }
    proxy& tls_ca(std::string_view ca)     { raw()->set_tls(true); raw()->set_ca_path(ca); return *this; }
    proxy& max_connections(uint32_t n)     { raw()->set_max_connections(n); return *this; }
    proxy& rate_limit(double r)            { raw()->set_rate_limit(r); return *this; }
    proxy& global_rate_limit(double r)     { raw()->set_global_rate_limit(r); return *this; }
    proxy& idle_timeout(uint32_t s)        { raw()->set_idle_timeout(s); return *this; }
    proxy& log_file(std::string_view p)    { raw()->set_log_file(p); return *this; }
    proxy& lua(std::string_view path)      { raw()->load_lua_script(path); return *this; }
    proxy& group(std::string_view g)       { raw()->set_group(g); return *this; }

    // ── Service mesh config (chainable) ─────────────────────────────────
    proxy& health_check(mesh_config::health_type t) { prx()->set_health_check(t); return *this; }
    proxy& health_interval(int seconds)             { prx()->set_health_interval(seconds); return *this; }
    proxy& health_path(std::string_view path)       { prx()->set_health_path(path); return *this; }
    proxy& health_threshold(int n)                  { prx()->set_health_threshold(n); return *this; }
    proxy& circuit_threshold(int n)                 { prx()->set_circuit_threshold(n); return *this; }
    proxy& circuit_timeout(int seconds)             { prx()->set_circuit_timeout(seconds); return *this; }
    proxy& retry_count(int n)                       { prx()->set_retry_count(n); return *this; }
    proxy& retry_all(bool v)                        { prx()->set_retry_all(v); return *this; }
    proxy& mesh_client_ca(std::string_view path)    { prx()->set_mesh_client_ca(path); return *this; }
    proxy& mesh_client_cert(std::string_view path)  { prx()->set_mesh_client_cert(path); return *this; }
    proxy& mesh_client_key(std::string_view path)   { prx()->set_mesh_client_key(path); return *this; }

    // ── Callbacks (chainable) ───────────────────────────────────────────
    proxy& on_start(std::function<void()> cb)              { raw()->set_on_start(std::move(cb)); return *this; }
    proxy& on_stop(std::function<void()> cb)               { raw()->set_on_stop(std::move(cb)); return *this; }
    proxy& on_connect(std::function<void(int)> cb)         { raw()->set_on_connect(std::move(cb)); return *this; }
    proxy& on_disconnect(std::function<void(int)> cb)      { raw()->set_on_disconnect(std::move(cb)); return *this; }
    proxy& on_tick(std::function<void(double)> cb)         { raw()->set_on_tick(std::move(cb)); return *this; }
    proxy& tick_interval(uint32_t ms)                      { raw()->set_tick_interval(ms); return *this; }
    proxy& on_proxy_request(proxy_instance::proxy_hook cb) { prx()->set_on_proxy_request(std::move(cb)); return *this; }
    proxy& on_proxy_response(proxy_instance::proxy_hook cb){ prx()->set_on_proxy_response(std::move(cb)); return *this; }

    // ── Actions ─────────────────────────────────────────────────────────
    std::string peer_ip(int fd)                               { return prx()->lua_peer_ip(fd); }
    void close_client(int fd)                                 { prx()->lua_close_client(fd); }
    std::vector<int> clients()                                { return prx()->lua_clients(); }
    std::vector<std::string> backends()                       { return prx()->lua_backends(); }
    std::vector<std::pair<int, std::string>> backend_health() { return prx()->lua_backend_health(); }

    // ── Ownership / hierarchy ───────────────────────────────────────────
    proxy& owner(std::string_view name)                    { raw()->set_owner(name); return *this; }
    proxy& child_policy(runtime_instance::child_policy p)  { raw()->set_child_policy(p); return *this; }

    // ── Introspection ───────────────────────────────────────────────────
    size_t           connection_count()      { return raw()->get_connection_count(); }
    runtime_state    state()                 { return raw()->get_state(); }
    std::string_view name()                  { return raw()->get_name(); }
    uint16_t         port()                  { return raw()->get_port(); }
    std::string      stats()                 { return raw()->get_stats(); }
    std::string_view id()                    { return raw()->get_id(); }
    std::string_view get_group()             { return raw()->get_group(); }
    std::string_view get_owner()             { return raw()->get_owner(); }
    bool             get_drain()             { return raw()->get_drain(); }
    bool             get_tls()               { return raw()->get_tls(); }
    std::string_view get_cert_path()         { return raw()->get_cert_path(); }
    std::string_view get_key_path()          { return raw()->get_key_path(); }
    std::string_view get_ca_path()           { return raw()->get_ca_path(); }
    std::string_view get_log_file()          { return raw()->get_log_file(); }
    uint32_t         get_max_connections()   { return raw()->get_max_connections(); }
    uint32_t         get_idle_timeout()      { return raw()->get_idle_timeout(); }
    double           get_rate_limit()        { return raw()->get_rate_limit(); }
    double           get_global_rate_limit() { return raw()->get_global_rate_limit(); }
    runtime_instance::child_policy get_child_policy() { return raw()->get_child_policy(); }
    bool             reload_lua()            { return raw()->reload_lua_script(); }
    std::string_view lua_script()            { return raw()->get_lua_script_path(); }
    proxy_protocol   get_protocol()          { return prx()->get_protocol(); }
    proxy_strategy   get_strategy()          { return prx()->get_strategy(); }
    const std::vector<backend_info>& get_backends()   { return prx()->get_backends(); }
    const mesh_config& get_mesh_config()              { return prx()->get_mesh_config(); }
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
    proxy_instance*  instance() { return prx(); }
    runtime_manager& manager()  { return m_mgr; }
    event_loop&      loop()     { return m_loop; }

private:
    runtime_instance* raw() { return m_mgr.get(m_name); }
    proxy_instance*   prx() { return static_cast<proxy_instance*>(raw()); }

    std::string     m_name;
    event_loop      m_loop;
    runtime_manager m_mgr;
};

} // namespace socketley
