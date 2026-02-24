// socketley/client.h — Client runtime (Tier 2, requires libsocketley_sdk.a)
#pragma once
#include "core.h"
#include "socketley/runtime/client/client_instance.h"

namespace socketley {

// ─── High-level client wrapper ──────────────────────────────────────────────
// Usage:
//   socketley::client cli("127.0.0.1", 9000);
//   cli.on_message([](std::string_view msg) { printf("%.*s\n", (int)msg.size(), msg.data()); });
//   cli.on_connect([&](int) { cli.send("hello"); });
//   cli.start();
class client {
public:
    client(std::string_view host, uint16_t port) : m_name("_sdk_client") {
        m_mgr.create(runtime_client, m_name);
        auto* inst = raw();
        inst->set_target(std::string(host) + ":" + std::to_string(port));
        inst->set_runtime_manager(&m_mgr);
        inst->set_event_loop(&m_loop);
    }

    // ── Chainable config ────────────────────────────────────────────────
    client& tls()                         { raw()->set_tls(true); return *this; }
    client& tls_ca(std::string_view ca)   { raw()->set_tls(true); raw()->set_ca_path(ca); return *this; }
    client& reconnect(int max)            { raw()->set_reconnect(max); return *this; }
    client& mode(client_mode m)           { cli()->set_mode(m); return *this; }
    client& udp()                         { cli()->set_udp(true); return *this; }
    client& lua(std::string_view path)    { raw()->load_lua_script(path); return *this; }
    client& tick_interval(uint32_t ms)    { raw()->set_tick_interval(ms); return *this; }

    // ── Callbacks (chainable) ───────────────────────────────────────────
    client& on_start(std::function<void()> cb)                        { raw()->set_on_start(std::move(cb)); return *this; }
    client& on_stop(std::function<void()> cb)                         { raw()->set_on_stop(std::move(cb)); return *this; }
    client& on_connect(std::function<void(int)> cb)                   { raw()->set_on_connect(std::move(cb)); return *this; }
    client& on_disconnect(std::function<void(int)> cb)                { raw()->set_on_disconnect(std::move(cb)); return *this; }
    client& on_message(std::function<void(std::string_view)> cb)      { raw()->set_on_message(std::move(cb)); return *this; }
    client& on_tick(std::function<void(double)> cb)                   { raw()->set_on_tick(std::move(cb)); return *this; }

    // ── Actions ─────────────────────────────────────────────────────────
    void send(std::string_view msg) { cli()->lua_send(msg); }

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
    client_instance*  instance() { return cli(); }
    runtime_manager&  manager()  { return m_mgr; }
    event_loop&       loop()     { return m_loop; }

private:
    runtime_instance* raw() { return m_mgr.get(m_name); }
    client_instance*  cli() { return static_cast<client_instance*>(raw()); }

    std::string     m_name;
    event_loop      m_loop;
    runtime_manager m_mgr;
};

} // namespace socketley
