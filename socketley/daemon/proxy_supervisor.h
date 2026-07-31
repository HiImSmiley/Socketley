#pragma once
// The daemon's half of an out-of-process proxy.
//
// ─── WHAT IT OWNS ───────────────────────────────────────────────────────────
//
// One child process, one control socket, and the placeholder runtime_instance
// that stands for the child inside the daemon.  The placeholder is a real
// proxy_instance that is never started: it holds the name, id, port, group,
// owner and state that every other part of the daemon already reads — `ps`,
// `inspect`, ownership cascades, state persistence — so none of them has to
// learn that this proxy lives somewhere else.
//
// ─── WHY THE STATS ARRIVE THE WAY THEY DO ───────────────────────────────────
//
// runtime_instance already separates "figures a reader off the event-loop
// thread may have" from "containers only the event-loop thread may walk", and
// publishes the former.  A reader in another process is that same reader with
// the prohibition made physical, so the child publishes exactly those figures
// and the supervisor writes them into the placeholder.  `stats`, `inspect` and
// the Prometheus endpoint then read the placeholder and cannot tell the
// difference — which is the property this whole first step exists to prove.
//
// ─── WHY THERE IS NO io_uring HERE ──────────────────────────────────────────
//
// The control socket is drained with ordinary non-blocking reads, from the
// daemon's existing 2-second health timer and from any command that is about
// to read the figures.  It is deliberately not armed on the ring.  Adding a
// descriptor to the ring means an owner token, a balanced arm/disarm, and a
// completion that can outlive what it names — the exact shape of this
// project's worst defects — and it would buy nothing: the child pushes on its
// own schedule and the daemon only has to pick the newest one up.
#include <chrono>
#include <string>
#include <sys/types.h>

class proxy_instance;
class runtime_instance;
struct runtime_config;

class proxy_supervisor
{
public:
    // What to do when the child dies without being asked to.
    enum class death_policy
    {
        restart,   // fork a new one and re-send config; the state stays running
        fail,      // leave the runtime in `failed` for the operator to see
    };

    proxy_supervisor(runtime_instance* placeholder, std::string exec_path);
    ~proxy_supervisor();

    proxy_supervisor(const proxy_supervisor&)            = delete;
    proxy_supervisor& operator=(const proxy_supervisor&) = delete;

    // Fork, exec, and send the config.  The placeholder is left in `running`
    // only once the child has been forked and the config written.
    bool spawn(const runtime_config& cfg);

    // Ask the child to stop serving but stay alive, or to exit outright.
    void send_start();
    void send_stop();
    void shutdown();

    // A new membership snapshot.  Cheap enough to send unconditionally: the
    // daemon publishes only when a runtime is created, started, stopped,
    // removed or renamed, or when the cluster's view moves.
    void send_endpoints(const std::string& encoded_payload);

    // Drain whatever the child has sent and apply it to the placeholder.
    // Called from the health timer and before any command that reads figures.
    void poll();

    // waitpid(WNOHANG) plus the death policy.  Returns true if the child was
    // found dead — the caller uses that to decide whether to persist a state
    // change.
    bool check_liveness();

    bool  is_alive() const { return m_pid > 0; }
    pid_t pid()      const { return m_pid; }

    void set_death_policy(death_policy p) { m_policy = p; }
    death_policy get_death_policy() const { return m_policy; }

private:
    void   close_control();
    bool   write_frame(const std::string& framed);
    void   apply_stats(const std::string& payload);
    void   ingest(const std::string& buf);

    runtime_instance* m_placeholder{nullptr};
    proxy_instance*   m_proxy{nullptr};
    std::string       m_exec_path;
    std::string       m_config_json;      // kept so a restart can re-send it
    std::string       m_endpoints;        // last table, re-sent to a new child
    std::string       m_in;               // partial frames from the child

    pid_t        m_pid{0};
    int          m_control_fd{-1};
    death_policy m_policy{death_policy::restart};
    unsigned     m_restarts{0};
    std::chrono::steady_clock::time_point m_last_restart{};
};
