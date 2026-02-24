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
    server& max_connections(uint32_t n)  { raw()->set_max_connections(n); return *this; }
    server& rate_limit(double r)         { raw()->set_rate_limit(r); return *this; }
    server& global_rate_limit(double r)  { raw()->set_global_rate_limit(r); return *this; }
    server& idle_timeout(uint32_t s)     { raw()->set_idle_timeout(s); return *this; }
    server& lua(std::string_view path)   { raw()->load_lua_script(path); return *this; }
    server& mode(server_mode m)          { srv()->set_mode(m); return *this; }
    server& udp()                        { srv()->set_udp(true); return *this; }
    server& http_dir(std::string_view p) { srv()->set_http_dir(p); return *this; }
    server& http_cache()                 { srv()->set_http_cache(true); return *this; }
    server& upstream(std::string_view a) { srv()->add_upstream_target(a); return *this; }
    server& master_pw(std::string_view pw) { srv()->set_master_pw(pw); return *this; }
    server& drain()                      { raw()->set_drain(true); return *this; }
    server& group(std::string_view g)    { raw()->set_group(g); return *this; }
    server& tick_interval(uint32_t ms)   { raw()->set_tick_interval(ms); return *this; }

    // ── Callbacks (chainable) ───────────────────────────────────────────
    server& on_start(std::function<void()> cb)                              { raw()->set_on_start(std::move(cb)); return *this; }
    server& on_stop(std::function<void()> cb)                               { raw()->set_on_stop(std::move(cb)); return *this; }
    server& on_connect(std::function<void(int)> cb)                         { raw()->set_on_connect(std::move(cb)); return *this; }
    server& on_disconnect(std::function<void(int)> cb)                      { raw()->set_on_disconnect(std::move(cb)); return *this; }
    server& on_message(std::function<void(int, std::string_view)> cb)       { raw()->set_on_client_message(std::move(cb)); return *this; }
    server& on_tick(std::function<void(double)> cb)                         { raw()->set_on_tick(std::move(cb)); return *this; }

    // ── Actions ─────────────────────────────────────────────────────────
    void send(int fd, std::string_view msg)                          { srv()->lua_send_to(fd, msg); }
    void broadcast(std::string_view msg)                             { srv()->lua_broadcast(msg); }
    void disconnect(int fd)                                          { srv()->lua_disconnect(fd); }
    std::string peer_ip(int fd)                                      { return srv()->lua_peer_ip(fd); }
    std::vector<int> clients()                                       { return srv()->lua_clients(); }
    void multicast(const std::vector<int>& fds, std::string_view m)  { srv()->lua_multicast(fds, m); }
    void set_data(int fd, std::string_view k, std::string_view v)    { srv()->lua_set_data(fd, k, v); }
    std::string get_data(int fd, std::string_view k)                 { return srv()->lua_get_data(fd, k); }

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
