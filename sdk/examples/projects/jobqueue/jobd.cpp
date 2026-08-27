// jobqueue — a working job queue service in one process.
//
// Two runtimes on one event loop, which is what the raw API exists for (the
// wrapper classes each own a loop, so one process, one wrapper):
//
//   * a cache, "jobs", on port 6380 — the queue itself.  Anything that can
//     speak the text protocol can drain it, including the cross-platform
//     cache_client.h (see worker.cpp) and redis-cli against the same port.
//   * a server, "ingest", on port 9000 — the submit API.  It validates, then
//     pushes into the cache DIRECTLY: both instances live in this process, so
//     the coordinator (your code) calls both without a byte of IPC.
//
// Protocol on 9000, newline-framed:
//   submit <payload>   -> "queued <depth>"
//   status             -> "depth <n>  submitted <total>"
//
// Build (from the repo root, after building libsocketley_sdk.a):
//   g++ -std=c++23 sdk/examples/projects/jobqueue/jobd.cpp \
//       -I. -Iinclude/linux -Ithirdparty/sol2 -Ithirdparty/luajit \
//       -Lbin/Release -Lthirdparty/luajit \
//       -lsocketley_sdk -luring -lssl -lcrypto -lluajit -o /tmp/jobd
//
// Run:   /tmp/jobd
// Try:   echo "submit build-42" | nc -q1 127.0.0.1 9000
//        echo "status"          | nc -q1 127.0.0.1 9000
//        /tmp/jobworker                (see worker.cpp)

#include <socketley/core.h>
#include "socketley/runtime/server/server_instance.h"
#include "socketley/runtime/cache/cache_instance.h"

#include <atomic>
#include <csignal>
#include <cstdio>
#include <string>

static constexpr const char* k_queue_key = "queue";

int main()
{
    event_loop loop;
    if (!loop.init())
    {
        fprintf(stderr, "io_uring init failed\n");
        return 2;
    }

    runtime_manager mgr;

    // ── the queue store ─────────────────────────────────────────────────
    mgr.create(runtime_cache, "jobs");
    auto* jobs = static_cast<cache_instance*>(mgr.get("jobs"));
    jobs->set_port(6380);
    jobs->set_mode(cache_mode_admin);          // workers may flush/load
    jobs->set_persistent("/tmp/jobqueue.dat"); // survive a restart
    jobs->set_runtime_manager(&mgr);
    jobs->set_event_loop(&loop);

    // ── the submit API ──────────────────────────────────────────────────
    mgr.create(runtime_server, "ingest");
    auto* ingest = static_cast<server_instance*>(mgr.get("ingest"));
    ingest->set_port(9000);
    ingest->set_runtime_manager(&mgr);
    ingest->set_event_loop(&loop);

    std::atomic<uint64_t> submitted{0};

    ingest->set_on_client_message([&](int fd, std::string_view msg) {
        // strip the newline framing
        while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r'))
            msg.remove_suffix(1);

        if (msg.rfind("submit ", 0) == 0 && msg.size() > 7)
        {
            std::string_view payload = msg.substr(7);
            jobs->lua_rpush(k_queue_key, payload);
            ++submitted;
            ingest->lua_send_to(fd,
                "queued " + std::to_string(jobs->lua_llen(k_queue_key)) + "\n");
            return;
        }
        if (msg == "status")
        {
            ingest->lua_send_to(fd,
                "depth " + std::to_string(jobs->lua_llen(k_queue_key)) +
                "  submitted " + std::to_string(submitted.load()) + "\n");
            return;
        }
        ingest->lua_send_to(fd, "usage: submit <payload> | status\n");
    });

    // ── lifecycle ───────────────────────────────────────────────────────
    socketley::detail::install_signal_handlers(&loop);

    if (!mgr.start("jobs", loop) || !mgr.start("ingest", loop))
    {
        fprintf(stderr, "start failed\n");
        return 2;
    }
    printf("jobd: submit on :9000, queue on :6380 (text protocol)\n");

    loop.run();
    mgr.stop_all(loop);
    loop.shutdown_ring();
    return 0;
}
