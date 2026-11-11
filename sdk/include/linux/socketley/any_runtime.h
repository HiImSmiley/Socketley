// socketley/any_runtime.h — Any runtime type, by the flags `socketley create` takes (Tier 2, requires libsocketley_sdk.a)
#pragma once
#include "core.h"
#include "../../../../socketley/cli/runtime_type_parser.h"

#include <iostream>

namespace socketley {

// One runtime of any type in this process, its flags read by the daemon's own parsers:
//   socketley::any_runtime site("web", "site", "-p 8080 --root /srv/site --lua-pages");
//   if (!site.start()) return 1;
//
// The typed classes (server, client, proxy, cache) are for hooks in C++; this is for everything else.
//
// Limitations:
//   - One start() per process, as with the typed classes
//   - start() blocks until stop() or SIGINT/SIGTERM
//   - --shards is refused: shards are forked by the daemon
class any_runtime {
public:
    any_runtime(std::string_view type, std::string_view name, std::string_view flags = {}) : m_name(name) {
        runtime_type t;
        if (!parse_runtime_type(type, t)) {
            std::cout << "unknown runtime type: " << type << "\n";
            return;
        }
        if (!m_mgr.create(t, m_name))
            return;
        raw()->set_runtime_manager(&m_mgr);
        raw()->set_event_loop(&m_loop);
        m_usable = apply_create_flags(raw(), m_mgr, flags);
    }

    // False when the type is unknown or a flag was refused, and start() then answers false.
    bool ok() const { return m_usable; }

    // Blocks serving until stop().  False when the runtime never started.
    bool start() {
        if (!m_usable || !m_loop.init()) return false;
        const detail::signal_scope signals(&m_loop);
        if (!m_mgr.start(m_name, m_loop) || raw()->get_state() != runtime_running) {
            LOG_ERROR((m_name + ": did not reach running; not entering the event loop").c_str());
            m_loop.shutdown_ring();
            return false;
        }
        m_loop.run();
        m_mgr.stop_all(m_loop);
        m_loop.shutdown_ring();
        return true;
    }
    void stop() { m_loop.request_stop(); }

    runtime_state    state() { return raw()->get_state(); }
    std::string_view name()  { return m_name; }
    uint16_t         port()  { return raw()->get_port(); }
    std::string      stats() { return raw()->get_stats(); }

    // ── Escape hatches ──
    runtime_instance* instance() { return raw(); }
    runtime_manager&  manager()  { return m_mgr; }
    event_loop&       loop()     { return m_loop; }

private:
    runtime_instance* raw() { return m_mgr.get(m_name); }

    bool            m_usable = false;
    std::string     m_name;
    event_loop      m_loop;
    runtime_manager m_mgr;
};

} // namespace socketley
