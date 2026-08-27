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
    client(std::string_view host, uint16_t port,
           std::string_view name = "_sdk_client") : m_name(name) {
        m_mgr.create(runtime_client, m_name);
        auto* inst = raw();
        inst->set_target(std::string(host) + ":" + std::to_string(port));
        inst->set_runtime_manager(&m_mgr);
        inst->set_event_loop(&m_loop);
    }

    // The `-t` spelling, verbatim: `host:port`, or `unix:/path/to.sock` — the
    // connect side of a server's `--listen unix:`.  This is the only way to
    // dial a unix socket from the SDK; the two-argument constructor always
    // builds `host:port`.
    explicit client(std::string_view target,
                    std::string_view name = "_sdk_client") : m_name(name) {
        m_mgr.create(runtime_client, m_name);
        auto* inst = raw();
        inst->set_target(target);
        inst->set_runtime_manager(&m_mgr);
        inst->set_event_loop(&m_loop);
    }

    // ── Chainable config ────────────────────────────────────────────────
    // Dial over TLS.  Complete on its own for this role: a client has no
    // listener to present a certificate on, the host from the constructor is
    // pinned before the ClientHello, and the chain is verified against the
    // system trust store.  See tls_context.h.
    client& tls()                          { raw()->set_tls(true); return *this; }
    // Verify the peer against this CA instead of the system store.
    client& tls_ca(std::string_view ca)    { raw()->set_tls(true); raw()->set_ca_path(ca); return *this; }
    // The certificate this client presents when the peer asks for one — the
    // client half of mutual TLS.  Needs tls() as well, and both halves or
    // neither: a certificate with no key presents nothing, and start() refuses
    // the pair rather than dialling and presenting nothing.
    //
    // Named for what it configures rather than after the two flags it sets.
    // --cert/--key on a *client* are not the listener certificate they are on
    // every other role, and the SDK had no spelling for them at all: an
    // embedding that needed mutual TLS had to drop to
    // raw()->set_cert_path(), which is the escape hatch, not the interface.
    client& client_cert(std::string_view cert, std::string_view key) {
        auto* i = raw(); i->set_cert_path(cert); i->set_key_path(key); return *this;
    }
    client& reconnect(int max)             { raw()->set_reconnect(max); return *this; }
    client& mode(client_mode m)            { cli()->set_mode(m); return *this; }
    client& udp()                          { cli()->set_udp(true); return *this; }
    client& log_file(std::string_view p)   { raw()->set_log_file(p); return *this; }
    client& write_file(std::string_view p) { raw()->set_write_file(p); return *this; }
    client& lua(std::string_view path)     { raw()->load_lua_script(path); return *this; }
    client& tick_interval(uint32_t ms)     { raw()->set_tick_interval(ms); return *this; }
    client& group(std::string_view g)      { raw()->set_group(g); return *this; }
    // See server::cpus / server::sqpoll — same contract, this wrapper's loop.
    client& cpus(std::string_view spec)    { detail::apply_cpus(m_loop, spec); return *this; }
    client& sqpoll(bool on = true)         { m_loop.set_sqpoll(on); return *this; }

    // ── Callbacks (chainable) ───────────────────────────────────────────
    client& on_start(std::function<void()> cb)                   { raw()->set_on_start(std::move(cb)); return *this; }
    client& on_stop(std::function<void()> cb)                    { raw()->set_on_stop(std::move(cb)); return *this; }
    client& on_connect(std::function<void(int)> cb)              { raw()->set_on_connect(std::move(cb)); return *this; }
    client& on_disconnect(std::function<void(int)> cb)           { raw()->set_on_disconnect(std::move(cb)); return *this; }
    client& on_message(std::function<void(std::string_view)> cb) { raw()->set_on_message(std::move(cb)); return *this; }
    client& on_tick(std::function<void(double)> cb)              { raw()->set_on_tick(std::move(cb)); return *this; }

    // ── Actions ─────────────────────────────────────────────────────────
    void send(std::string_view msg) { cli()->lua_send(msg); }

    // ── Ownership / hierarchy ───────────────────────────────────────────
    client& owner(std::string_view name)                   { raw()->set_owner(name); return *this; }
    client& child_policy(runtime_instance::child_policy p) { raw()->set_child_policy(p); return *this; }

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
    std::string_view get_write_file()        { return raw()->get_write_file(); }
    std::string_view get_target()            { return raw()->get_target(); }
    uint32_t         get_idle_timeout()      { return raw()->get_idle_timeout(); }
    double           get_rate_limit()        { return raw()->get_rate_limit(); }
    double           get_global_rate_limit() { return raw()->get_global_rate_limit(); }
    int              get_reconnect()         { return raw()->get_reconnect(); }
    runtime_instance::child_policy get_child_policy() { return raw()->get_child_policy(); }
    bool             reload_lua()            { return raw()->reload_lua_script(); }
    std::string_view lua_script()            { return raw()->get_lua_script_path(); }
    client_mode      get_mode()              { return cli()->get_mode(); }
    std::chrono::system_clock::time_point created_time() { return raw()->get_created_time(); }
    std::chrono::system_clock::time_point start_time()   { return raw()->get_start_time(); }

    // ── Lifecycle ───────────────────────────────────────────────────────
    void start() {
        if (!m_loop.init()) return;
        detail::warn_if_sqpoll_denied(m_loop);
        detail::install_signal_handlers(&m_loop);
        m_mgr.start(m_name, m_loop);
        m_loop.run();
        // Still with a live ring: stopping a runtime submits — teardown()
        // cancels what is attached to its descriptors and withdraws its own
        // timers.  run() deliberately leaves the ring standing for this.
        m_mgr.stop_all(m_loop);
        // And ended here, not in the destructor.  m_mgr is destroyed before
        // m_loop, so a ring still open at that point would let the kernel go on
        // writing into the buffers of connections the manager is freeing.
        m_loop.shutdown_ring();
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
