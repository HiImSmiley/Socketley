// socketley/cache.h — Cache runtime (Tier 2, requires libsocketley_sdk.a)
#pragma once
#include "core.h"
#include "socketley/runtime/cache/cache_instance.h"

namespace socketley {

// ─── High-level cache wrapper ───────────────────────────────────────────────
// Usage:
//   socketley::cache c(6379);
//   c.persistent("/tmp/cache.dat").resp();
//   c.start();
class cache {
public:
    explicit cache(uint16_t port) : m_name("_sdk_cache") {
        m_mgr.create(runtime_cache, m_name);
        auto* inst = raw();
        inst->set_port(port);
        inst->set_runtime_manager(&m_mgr);
        inst->set_event_loop(&m_loop);
    }

    // ── Chainable config ────────────────────────────────────────────────
    cache& persistent(std::string_view path) { cch()->set_persistent(path); return *this; }
    cache& max_memory(size_t bytes)          { cch()->set_max_memory(bytes); return *this; }
    cache& eviction(eviction_policy p)       { cch()->set_eviction(p); return *this; }
    cache& resp()                            { cch()->set_resp_forced(true); return *this; }
    cache& mode(cache_mode m)                { cch()->set_mode(m); return *this; }
    cache& tls(std::string_view cert, std::string_view key) {
        auto* i = raw(); i->set_tls(true); i->set_cert_path(cert); i->set_key_path(key); return *this;
    }
    cache& max_connections(uint32_t n)       { raw()->set_max_connections(n); return *this; }
    cache& idle_timeout(uint32_t s)          { raw()->set_idle_timeout(s); return *this; }
    cache& replicate(std::string_view target){ cch()->set_replicate_target(target); return *this; }
    cache& lua(std::string_view path)        { raw()->load_lua_script(path); return *this; }
    cache& group(std::string_view g)         { raw()->set_group(g); return *this; }

    // ── Callbacks (chainable) ───────────────────────────────────────────
    cache& on_start(std::function<void()> cb) { raw()->set_on_start(std::move(cb)); return *this; }
    cache& on_stop(std::function<void()> cb)  { raw()->set_on_stop(std::move(cb)); return *this; }

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
    cache_instance*   instance() { return cch(); }
    runtime_manager&  manager()  { return m_mgr; }
    event_loop&       loop()     { return m_loop; }

private:
    runtime_instance* raw() { return m_mgr.get(m_name); }
    cache_instance*   cch() { return static_cast<cache_instance*>(raw()); }

    std::string     m_name;
    event_loop      m_loop;
    runtime_manager m_mgr;
};

} // namespace socketley
