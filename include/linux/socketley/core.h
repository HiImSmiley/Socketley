// ═══════════════════════════════════════════════════════════════════
//  socketley/core.h — Engine core (Tier 2, requires libsocketley_sdk.a)
//
//  Provides the event loop, runtime manager, and shared infrastructure.
//  Requires building from source: link with -lsocketley_sdk -luring -lssl -lcrypto
// ═══════════════════════════════════════════════════════════════════
#pragma once

#ifndef __linux__
#  error "Socketley requires Linux (io_uring)"
#endif

#include "../../../socketley/shared/runtime/runtime_definitions.h"
#include "../../../socketley/shared/loop/event_loop_definitions.h"
#include "../../../socketley/shared/util/logging.h"
#include "../../../socketley/shared/net/scoped_fd.h"
#include "../../../socketley/shared/crypto/tls_context.h"
#include "../../../socketley/shared/loop/event_loop.h"
#ifndef SOCKETLEY_NO_LUA
#include "../../../socketley/shared/lua/lua_context.h"
#endif
#include "runtime/instance.h"
#include "../../../socketley/shared/runtime/runtime_manager.h"
#include "../../../socketley/shared/runtime/runtime_factory.h"

#include <csignal>

namespace socketley {
namespace detail {

inline event_loop*& signal_loop_ptr() {
    static event_loop* ptr = nullptr;
    return ptr;
}
inline void signal_handler(int) {
    if (auto* lp = signal_loop_ptr()) lp->request_stop();
}
inline void install_signal_handlers(event_loop* loop) {
    signal(SIGPIPE, SIG_IGN);
    signal_loop_ptr() = loop;
    struct sigaction sa{};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
}

// The wrappers' cpus(<spec>) — `max`, `0-3`, `0,2,5` — applied to the loop the
// wrapper owns, which is where an embedded runtime's affinity lives: the
// runtime-side set_cpus() is a *request* checked against the ring, and a ring
// this wrapper creates itself has nobody to negotiate with.  A spec that does
// not parse is logged and ignored rather than half-honoured — the SDK's
// setters have no error channel (see server::upstream), and falling back to
// "all" in silence is exactly the failure parse_cpu_set exists to name.
inline void apply_cpus(event_loop& loop, std::string_view spec) {
    cpu_set_spec set;
    std::string err;
    if (!parse_cpu_set(spec, online_cpu_count(), set, err)) {
        LOG_WARN((std::string("cpus(\"") + std::string(spec) +
                  "\") ignored: " + err).c_str());
        return;
    }
    loop.set_cpus(set);
}

} // namespace detail
} // namespace socketley
