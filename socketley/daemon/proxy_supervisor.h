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

#include "../shared/request_channel.h"

class proxy_instance;
class runtime_instance;
struct runtime_config;

// Also the request_sink for the runtime it supervises.  A placeholder in this
// process has the name and the port but none of the state, so the channel is
// pointed here instead: serve_deferred() puts the request on the control socket
// the supervisor already holds, and the reply frame comes back to
// complete_deferred().  Nothing on the asking side changes, which is what
// request_channel.h promised before either half existed.
// And the request_origin for requests coming the other way.  A runtime in a
// worker knows one name — its own — so everything else it asks for arrives here
// as a chan_req, is posted into the daemon's channel, and the reply is written
// back as a chan_rep.  The daemon is the only process holding the whole map, so
// it is the only one that can route; the supervisor is where a worker's request
// enters that map and where its answer leaves it.
class proxy_supervisor : public request_sink, public request_origin
{
public:
    // Never inline: the answer is in another process and the only ways to
    // pretend otherwise are to block this thread or to make it up.
    bool serves_inline() const override { return false; }
    void serve_request(std::string_view, std::string&) override {}
    bool serve_deferred(uint64_t ticket, std::string_view target,
                        std::string_view payload) override;

    // A reply to something the worker asked.  The cookie is the worker's own
    // ticket, handed back unchanged so it can pair the two without this side
    // keeping a table.
    void on_request_reply(uint64_t cookie, request_status st,
                          std::string_view reply) override;

    void set_channel(request_channel* ch) { m_channel = ch; }
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

    // One published message, on its way to the child's subscribe callbacks.
    //
    // Not kept the way the endpoint table is: a table is a state a new child has
    // to be brought up to, a publish is an event that already happened, and
    // re-sending one to a child forked afterwards would deliver it twice to a
    // daemon that restarted its worker mid-stream.
    void send_publish(const std::string& encoded_payload);

    // Drain whatever the child has sent and apply it to the placeholder.
    // Called from the health timer and before any command that reads figures.
    void poll();

    // waitpid(WNOHANG) plus the death policy.  Returns true if the child was
    // found dead — the caller uses that to decide whether to persist a state
    // change.
    bool check_liveness();

    bool  is_alive() const { return m_pid > 0; }
    pid_t pid()      const { return m_pid; }

    // Hand the child over to somebody who will outlive this object.
    //
    // shutdown() signals and tries once to reap, which nearly always fails: the
    // child is unwinding its ring at that instant.  Everything after that
    // depended on this supervisor still being in the map for the health timer to
    // find — and on the stop path it is erased in the same statement, so nothing
    // ever waited on the child again and it stayed a zombie for the life of the
    // daemon.  Returning the pid and forgetting it here makes the handover
    // explicit and keeps the destructor from signalling a second time.
    pid_t release_pid() { const pid_t p = m_pid; m_pid = 0; return p; }

    void set_death_policy(death_policy p) { m_policy = p; }
    death_policy get_death_policy() const { return m_policy; }

private:
    void   close_control();
    bool   write_frame(const std::string& framed);
    void   on_chan_req(std::string_view payload);
    void   apply_stats(const std::string& payload);
    void   ingest(const std::string& buf);

    // Deliberately a runtime_instance and nothing narrower.  Everything this
    // class does — fork and exec the child, hand it a config frame, re-send the
    // endpoint table, restart it, read its stats back — is the same work
    // whatever kind of runtime is on the other side.  It held a
    // proxy_instance* beside this one for a while; that pointer was assigned in
    // the constructor and never read again, which is the clearest evidence
    // available that nothing here needs the type.
    //
    // Which is what makes a cache or a server in a worker cheap: this file does
    // not have to change for it.  What does is the worker's own side, where
    // create_runtime() is called with runtime_proxy hardcoded and the stats
    // frame is filled from proxy_instance members by hand.
    request_channel*  m_channel{nullptr};
    runtime_instance* m_placeholder{nullptr};
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
