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
    // `name` is not cosmetic on a proxy: in protocol_http mode the runtime
    // routes by path prefix "/<name>/" -- a GET that does not start with it is
    // answered 404 before any backend is consulted, exactly as the daemon's
    // named proxies behave.  So proxy(8443, "gw") serves /gw/..., and the
    // default name serves /_sdk_proxy/....  protocol_tcp has no prefix.
    explicit proxy(uint16_t port, std::string_view name = "_sdk_proxy")
        : m_name(name) {
        m_mgr.create(runtime_proxy, m_name);
        auto* inst = raw();
        inst->set_port(port);
        inst->set_runtime_manager(&m_mgr);
        inst->set_event_loop(&m_loop);
    }

    // Listen on an AF_UNIX socket instead of a TCP port — see the same
    // constructor on server for why this is a constructor and why tls() does
    // not combine with it.  Accepts the path with or without `unix:`.
    explicit proxy(std::string_view unix_path, std::string_view name = "_sdk_proxy")
        : m_name(name) {
        m_mgr.create(runtime_proxy, m_name);
        auto* inst = raw();
        if (unix_path.rfind("unix:", 0) == 0)
            unix_path.remove_prefix(5);
        inst->set_listen_path(unix_path);
        inst->set_runtime_manager(&m_mgr);
        inst->set_event_loop(&m_loop);
    }

    // ── Chainable config ────────────────────────────────────────────────
    // `host:port`, `unix:/path/to.sock`, or `@group` — every spelling
    // `--backend` takes.
    proxy& backend(std::string_view addr)  { prx()->add_backend(addr); return *this; }
    proxy& clear_backends()                { prx()->clear_backends(); return *this; }
    proxy& strategy(proxy_strategy s)      { prx()->set_strategy(s); return *this; }
    proxy& protocol(proxy_protocol p)      { prx()->set_protocol(p); return *this; }
    // Terminate TLS on this proxy's own listening port.
    proxy& tls(std::string_view cert, std::string_view key) {
        auto* i = raw(); i->set_tls(true); i->set_cert_path(cert); i->set_key_path(key); return *this;
    }
    // The trust store for the *backend* leg, and — because none of the
    // backend-TLS options means anything against a cleartext peer — what turns
    // that leg to TLS for every backend.  It does not switch on the listener:
    // a proxy has two legs, and the one this configures is not the one tls()
    // above configures.  (It used to call set_tls(true) as well, from when
    // neither leg had a handshake behind it and the distinction was moot.)
    proxy& backend_ca(std::string_view ca) { raw()->set_ca_path(ca); return *this; }
    // The certificate a client presents to this proxy has to be signed by this
    // CA — mutual TLS on the listener, so it needs tls() as well.
    proxy& client_ca(std::string_view ca)  { prx()->set_mesh_client_ca(ca); return *this; }
    // The certificate this proxy presents to a backend that asks for one.
    // Both or neither: half a pair is refused at start.
    proxy& client_cert(std::string_view cert, std::string_view key) {
        auto* i = prx(); i->set_mesh_client_cert(cert); i->set_mesh_client_key(key); return *this;
    }
    proxy& max_connections(uint32_t n)     { raw()->set_max_connections(n); return *this; }
    proxy& rate_limit(double r)            { raw()->set_rate_limit(r); return *this; }
    proxy& global_rate_limit(double r)     { raw()->set_global_rate_limit(r); return *this; }
    proxy& idle_timeout(uint32_t s)        { raw()->set_idle_timeout(s); return *this; }
    proxy& log_file(std::string_view p)    { raw()->set_log_file(p); return *this; }
    proxy& lua(std::string_view path)      { raw()->load_lua_script(path); return *this; }
    proxy& group(std::string_view g)       { raw()->set_group(g); return *this; }
    proxy& drain()                         { raw()->set_drain(true); return *this; }
    // See server::cpus / server::sqpoll — same contract, this wrapper's loop.
    proxy& cpus(std::string_view spec)     { detail::apply_cpus(m_loop, spec); return *this; }
    proxy& sqpoll(bool on = true)          { m_loop.set_sqpoll(on); return *this; }

    // `--sidecar`: the service-mesh defaults in one word — TCP health checks,
    // circuit breaker (5 failures, 30s), 2 retries, drain on stop.  Sugar
    // only: each piece can still be overridden by the setters below, and the
    // values here are the flag handler's, not this header's own.
    proxy& sidecar() {
        prx()->set_health_check(mesh_config::health_tcp);
        prx()->set_circuit_threshold(5);
        prx()->set_circuit_timeout(30);
        prx()->set_retry_count(2);
        raw()->set_drain(true);
        return *this;
    }

    // ── Service mesh config (chainable) ─────────────────────────────────
    proxy& health_check(mesh_config::health_type t) { prx()->set_health_check(t); return *this; }
    proxy& health_interval(int seconds)             { prx()->set_health_interval(seconds); return *this; }
    proxy& health_path(std::string_view path)       { prx()->set_health_path(path); return *this; }
    proxy& health_threshold(int n)                  { prx()->set_health_threshold(n); return *this; }
    proxy& circuit_threshold(int n)                 { prx()->set_circuit_threshold(n); return *this; }
    proxy& circuit_timeout(int seconds)             { prx()->set_circuit_timeout(seconds); return *this; }
    // Seconds a backend may take to produce the first response byte; 0 = no
    // deadline.  On by default — see mesh_config::backend_timeout.
    proxy& backend_timeout(int seconds)             { prx()->set_backend_timeout(seconds); return *this; }
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
    // The byte-path hooks, and their return contract is NOT the obvious one:
    //
    //     return std::nullopt;      -> DROP: the bytes are not forwarded.
    //     return std::string{};     -> pass through unmodified (empty = "no edit")
    //     return std::string(...);  -> forward this instead of the original
    //
    // std::optional reads as "optionally return a replacement", which makes
    // nullopt look like "no change" -- it is the opposite, and a hook written
    // that way forwards nothing: on HTTP every request then runs into
    // backend_timeout and answers 504, and with backend_timeout(0) the client
    // hangs.  Measured here before this comment existed.  Note the asymmetry
    // with a Lua on_proxy_request, whose refusal CLOSES the connection; the
    // C++ drop leaves it open with the bytes swallowed.
    //
    // On protocol_http the request hook runs on the request head and again on
    // body chunks; on protocol_tcp it runs on every read.  The response hook
    // is the same contract on the backend-to-client direction.
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
    std::string_view get_listen_path()       { return raw()->get_listen_path(); }
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
    // Blocks serving until stop().  False when the runtime never started -- a
    // taken port, a refused TLS or listener configuration -- and then the loop
    // is not entered at all.  The old signature ran the loop anyway: a wrapper
    // whose runtime had failed blocked forever serving nothing, with no line
    // of output, until a signal arrived.  The refusal reason, when the runtime
    // produced one, is in the log already; the LOG_ERROR here is for the paths
    // that produce none (a TCP bind failure returns false silently).
    bool start() {
        if (!m_loop.init()) return false;
        detail::warn_if_sqpoll_denied(m_loop);
        detail::install_signal_handlers(&m_loop);
        if (!m_mgr.start(m_name, m_loop) || raw()->get_state() != runtime_running) {
            LOG_ERROR((std::string(raw()->get_name()) +
                       ": did not reach running; not entering the event loop. "
                       "The refusal reason, if any, is logged above -- a silent "
                       "one is a TCP bind/listen failure (port taken?)").c_str());
            m_loop.shutdown_ring();
            return false;
        }
        m_loop.run();
        // Still with a live ring: stopping a runtime submits — teardown()
        // cancels what is attached to its descriptors and withdraws its own
        // timers.  run() deliberately leaves the ring standing for this.
        m_mgr.stop_all(m_loop);
        // And ended here, not in the destructor.  m_mgr is destroyed before
        // m_loop, so a ring still open at that point would let the kernel go on
        // writing into the buffers of connections the manager is freeing.
        m_loop.shutdown_ring();
        return true;
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
