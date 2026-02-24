// socketley/proxy.h — Proxy runtime (Tier 2, requires libsocketley_sdk.a)
#pragma once
#include "core.h"
#include "socketley/runtime/proxy/proxy_instance.h"

namespace socketley {

// ─── High-level proxy wrapper ───────────────────────────────────────────────
// Usage:
//   socketley::proxy px(8080);
//   px.backend("127.0.0.1:9000").protocol(protocol_tcp);
//   px.run();
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
    proxy& backend(std::string_view addr)   { prx()->add_backend(addr); return *this; }
    proxy& strategy(proxy_strategy s)       { prx()->set_strategy(s); return *this; }
    proxy& protocol(proxy_protocol p)       { prx()->set_protocol(p); return *this; }
    proxy& tls(std::string_view cert, std::string_view key) {
        auto* i = raw(); i->set_tls(true); i->set_cert_path(cert); i->set_key_path(key); return *this;
    }
    proxy& max_connections(uint32_t n)      { raw()->set_max_connections(n); return *this; }
    proxy& idle_timeout(uint32_t s)         { raw()->set_idle_timeout(s); return *this; }
    proxy& lua(std::string_view path)       { raw()->load_lua_script(path); return *this; }
    proxy& group(std::string_view g)        { raw()->set_group(g); return *this; }

    // ── Callbacks (chainable) ───────────────────────────────────────────
    proxy& on_start(std::function<void()> cb) { raw()->set_on_start(std::move(cb)); return *this; }
    proxy& on_stop(std::function<void()> cb)  { raw()->set_on_stop(std::move(cb)); return *this; }

    // ── Lifecycle ───────────────────────────────────────────────────────
    void run() {
        if (!m_loop.init()) return;
        detail::install_signal_handlers(&m_loop);
        m_mgr.start(m_name, m_loop);
        m_loop.run();
        m_mgr.stop_all(m_loop);
    }
    void stop() { m_loop.request_stop(); }

    // ── Escape hatches ──────────────────────────────────────────────────
    proxy_instance*   instance() { return prx(); }
    runtime_manager&  manager()  { return m_mgr; }
    event_loop&       loop()     { return m_loop; }

private:
    runtime_instance* raw() { return m_mgr.get(m_name); }
    proxy_instance*   prx() { return static_cast<proxy_instance*>(raw()); }

    std::string     m_name;
    event_loop      m_loop;
    runtime_manager m_mgr;
};

} // namespace socketley
