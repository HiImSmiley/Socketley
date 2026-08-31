// socketley/daemon.h — the daemon itself (Tier 2, requires libsocketley_sdk.a)
//
// Serves the control socket, restores persisted runtimes, supervises workers
// and runs until signalled -- the same daemon_start the socketley binary's
// `daemon` command enters.
//
// Usage:
//   #include <socketley/daemon.h>
//   int main(int argc, char** argv) {
//       runtime_manager manager;
//       event_loop loop;
//       return socketley::daemon_start(manager, loop, argc, argv);
//   }
//
// The supervisor serves each runtime by exec'ing THIS binary with
// `proxy-worker`, which daemon_start() dispatches before it does anything
// else.  Two things follow: the binary must stay at its path while the daemon
// runs, and everything main() does before daemon_start() runs once per worker
// as well -- so keep it to registration and leave side effects to a runtime.
#pragma once

#ifndef __linux__
#  error "Socketley requires Linux (io_uring)"
#endif

#include "../../../socketley/shared/event_loop.h"
#include "../../../socketley/shared/runtime_manager.h"
#include "../../../socketley/daemon/daemon.h"

namespace socketley {

// Blocks until the daemon exits, returning its exit code; argv is read the
// way `socketley daemon` reads it, so argv[1] should be "daemon" and ring
// flags follow.
inline int daemon_start(runtime_manager& manager, event_loop& loop,
                        int argc, char** argv)
{
    return ::daemon_start(manager, loop, argc, argv);
}

} // namespace socketley
