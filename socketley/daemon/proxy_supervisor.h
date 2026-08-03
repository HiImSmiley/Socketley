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
// ─── WHY THERE IS io_uring HERE NOW ─────────────────────────────────────────
//
// There was not, and the reason given was sound for what the socket carried:
// a stats push, an endpoint table, a publish.  For all three, a drain on the
// 2-second health timer and before any command that reads figures is enough —
// the child pushes on its own schedule, `stats` prints the age of what it
// found, and nobody is waiting on a particular byte.  Arming a descriptor costs
// an owner token, a balanced arm/disarm and a completion that can outlive what
// it names, which is the shape of this project's worst defects.
//
// Then a request went on the same socket, and the reasoning did not survive it.
// A request has somebody waiting on it by definition.  Measured: an in-daemon
// `cache set` answers in 0.15 ms, and the same command against a cache in a
// worker answered in 2000.02 ms — one health tick, to the hundredth of a
// millisecond, because that is the only thing that was going to read the reply.
//
// So the fd is armed for readability and the loop wakes on the answer.  The
// timer still drains, as the backstop for a poll that could not be submitted.
#include <chrono>
#include <functional>
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
// And an io_handler, because the control socket carries requests now.
//
// It used to carry three things — a stats push, an endpoint table, a publish —
// and for all three a drain every two seconds on the health tick was right:
// `stats` prints figures with their age attached, and nobody is waiting.  A
// request is not that.  Putting one on this socket without changing how it is
// serviced made a cross-process `cache get` cost one whole tick: measured
// against an in-daemon cache at 0.15 ms, a cache in a worker answered in
// 2000.02 ms, which is the timer and nothing else.
//
// So the fd is armed in the ring for readability and the loop wakes on the
// reply.  The health tick still drains as a backstop, for the case where a poll
// submission is refused.
class proxy_supervisor : public request_sink, public request_origin,
                         public io_handler
{
public:
    // Where the control socket is armed.  Without one the supervisor still
    // works and still answers, on the health tick, which is what it did before.
    void set_event_loop(event_loop* loop);

    void on_cqe(struct io_uring_cqe* cqe) override;

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

    // What to do with a publish coming UP from the child.  A cache in a worker
    // reaches its subscribers only through here: the daemon holds every other
    // runtime and every other worker's socket, so it is the only process that
    // can fan one out.  The supervisor passes itself so the daemon can leave
    // this child out of that fan-out — it has already delivered to its own
    // runtime, and a second copy would run every subscriber in it twice.
    using publish_handler = std::function<void(proxy_supervisor* from,
                                               std::string_view cache_name,
                                               std::string_view channel,
                                               std::string_view message)>;
    void set_publish_handler(publish_handler h) { m_on_publish = std::move(h); }
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

    // `socketley send <name> <message>`, on its way to the runtime that has the
    // connections.  Best-effort like every other frame going down: a false is a
    // child that is not reading, and cmd_send reports it rather than returning
    // the 0 it used to return for a message nobody received.
    bool send_deliver(std::string_view message);

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

    // True once for each time the child reported a state this side had to
    // adopt.  Same shape as check_liveness(): the supervisor decides, the
    // caller persists, so the state file and the runtime map cannot disagree
    // about a runtime that failed in another process.
    bool take_state_change() { const bool c = m_state_changed; m_state_changed = false; return c; }

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

    // Arm the control socket for readability, if there is a loop and a socket
    // and nothing armed already.  Re-armed from on_cqe(): one-shot, because a
    // multishot poll on a descriptor this class closes on several paths is a
    // completion outliving its fd, and the arm costs one SQE per exchange.
    void   flush_control();
    size_t pending_out() const { return m_out.size() - m_out_off; }

    void   arm_control_poll();
    // Give the arm back before the descriptor goes.  A completion for a closed
    // fd is dropped by the loop for a deregistered owner, and this is what makes
    // sure the owner is deregistered.
    void   disarm_control_poll();
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

    // Frames written but not yet taken by the socket.  Bounded, because the
    // alternative to a bound is the daemon growing without limit on behalf of a
    // child that has stopped reading.  Generous next to what a control socket
    // holds — about 270 request frames — so a burst is absorbed rather than
    // refused, and small next to the channel's own 16 MB queue, which is the
    // thing actually meant to bound a client that pipelines.
    static constexpr size_t MAX_CONTROL_BACKLOG = 4u << 20;

    std::string  m_out;
    size_t       m_out_off{0};
    bool         m_out_full{false};

    event_loop*  m_loop{nullptr};
    io_request   m_poll_req{};
    unsigned     m_poll_mask{0};
    bool         m_poll_armed{false};

    publish_handler m_on_publish;

    bool         m_state_changed{false};

    pid_t        m_pid{0};
    int          m_control_fd{-1};
    death_policy m_policy{death_policy::restart};
    unsigned     m_restarts{0};
    std::chrono::steady_clock::time_point m_last_restart{};
};
