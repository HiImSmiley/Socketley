// Socketley SDK — a daemon of your own, carrying a runtime type of your own
//
// This one binary is BOTH halves.  It serves the control socket the ordinary
// `socketley` CLI dials, so `socketley ls`, `create`, `stats` and `--lua` all
// drive it with nothing added; and the supervisor execs this same binary with
// `proxy-worker` to serve each runtime, which daemon_start() dispatches.
//
// Whoever binds the socket IS the daemon: point SOCKETLEY_SOCKET at a path of
// your own to run beside the packaged daemon, or take over
// /run/socketley/socketley.sock to replace it.
//
// Build:
//   g++ -std=c++23 sdk/examples/custom-daemon/counter_daemon.cpp \
//       $(sdk/socketley-config --cflags --libs) -o /usr/local/bin/counter-daemon
//
// Install counter.toml (beside this file) into the daemon's types directory
// with its `exec` pointing back at this binary, then:
//   SOCKETLEY_SOCKET=/tmp/mine.sock counter-daemon daemon &
//   SOCKETLEY_SOCKET=/tmp/mine.sock socketley create counter hits -p 9000 -s
//   printf 'a\na\nb\n' | nc -q1 127.0.0.1 9000     # -> 1 2 1
//
// EVERYTHING BEFORE daemon_start() RUNS IN EVERY WORKER TOO, because the
// supervisor execs this binary rather than forking it.  Keep main() to
// registration; anything with a side effect happens once per runtime.
#include <socketley/daemon.h>
#include <socketley/worker.h>

#include <map>
#include <memory>
#include <string>
#include <socketley/runtime/server.h>

namespace {
class counter final : public server_instance
{
public:
    explicit counter(std::string_view name) : server_instance(name)
    {
        set_on_client_message([this](int fd, std::string_view line) {
            while (!line.empty() && (line.back()=='\n'||line.back()=='\r'))
                line.remove_suffix(1);
            send_to(fd, std::to_string(++m_hits[std::string(line)]) + "\n");
        });
    }
private:
    std::map<std::string, long> m_hits;
};
}

int main(int argc, char** argv)
{
    // Runs in BOTH roles, because the supervisor execs this same binary.
    socketley::worker::register_type("counter",
        [](std::string_view n) -> std::unique_ptr<runtime_instance> {
            return std::make_unique<counter>(n);
        });

    runtime_manager manager;
    event_loop loop;
    return socketley::daemon_start(manager, loop, argc, argv);
}
