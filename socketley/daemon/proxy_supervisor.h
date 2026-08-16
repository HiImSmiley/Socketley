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
// For runtime_state: await_startup() remembers the state the child reported
// without adopting it, so the enum is part of this class's own storage now
// rather than something only the .cpp had to know about.
#include "../shared/runtime_definitions.h"

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

    // Stop supervising: give up everything that could still reach this object,
    // give the ring back, and return the identity it was submitting under so
    // that whoever holds it can ask the loop when its storage is free.  See the
    // quarantine in daemon_handler.
    //
    // This exists because the destructor cannot do the job.  An io_request
    // lives INSIDE this class — m_poll_req — so a completion still in the ring
    // names storage that ~proxy_supervisor is about to release, and the loop's
    // own staleness check has to read the owner token out of that request to
    // find out whether to drop it.  When the request lives inside the owner,
    // the check IS the use-after-free; deregistering harder cannot help.
    //
    // Nor can the destructor wait for the ring.  A supervisor is destroyed from
    // inside a command handler, which is itself inside a completion being
    // dispatched, so waiting would mean re-entering the loop from there and
    // dispatching completions — possibly the one for the object mid-destruction
    // — while the loop's own per-turn accounting is half-updated.
    //
    // So it is two calls, for the reason conn_transfer.h gives for its own pair
    // and in almost the same words: the answer to "is the ring finished with
    // this" arrives on a later turn of the loop than the question, and a
    // destructor is a one-call interface by construction.  This is the first
    // call.  The second is event_loop::token_inflight() reaching zero, and only
    // then may the object be destroyed.
    //
    // The severance has to happen HERE and not in the destructor, and that is
    // not tidiness.  The destructor used to run at the moment of retirement, so
    // reaching for the placeholder there was reaching for a live runtime; once
    // the free is deferred it is not, because cmd_remove retires the supervisor
    // and then has runtime_manager::remove() free the very instance
    // m_placeholder points at.  Everything this object is holding a pointer to
    // is known to be alive at retirement and not one moment longer.
    //
    // Returns 0 for a supervisor that never had a loop, which is a supervisor
    // that never submitted and can be destroyed on the spot.
    uint32_t retire();

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

    // What to do with a `send` coming UP from the child.  A script in a worker
    // names a runtime it cannot see; the daemon holds the map, so it is the only
    // process that can decide whether that name is one of its own runtimes, one
    // in another worker, or nothing at all.
    //
    // No `from` argument and no exclusion, unlike the publish above: a send is
    // addressed, not broadcast, and a worker sending to its OWN runtime never
    // reaches this — the worker's deliver sink answers that one where it stands.
    using deliver_handler = std::function<void(std::string_view name,
                                               std::string_view message)>;
    void set_deliver_handler(deliver_handler h) { m_on_deliver = std::move(h); }

    // ── The figures this child last published ───────────────────────────────
    //
    // Held here rather than written straight into the placeholder, which is
    // what apply_stats() used to do.  A placeholder can stand for N worker
    // processes now — see --shards — and each publishes its own counters on its
    // own timer, so N supervisors writing the same fields meant the last frame
    // to arrive won: four shards serving 25 connections each reported 25, and
    // which shard's 25 it was changed every 250 ms.
    //
    // The reader is daemon_handler::aggregate_worker_stats(), which adds these
    // up across a runtime's shards and writes the total where every reader in
    // this process already looks.  For a runtime with one shard the sum IS that
    // shard, so nothing about the unsharded case changes.
    struct published_stats
    {
        uint64_t    total_connections{0};
        uint64_t    total_messages{0};
        uint64_t    bytes_in{0};
        uint64_t    bytes_out{0};
        uint64_t    active_connections{0};
        std::string detail;

        // The child's own steady_clock reading at the instant it took the
        // counters above, or 0 from a child that predates the field.  See the
        // note above stats_wire for why the age has to be measured from when
        // they were read rather than from when this process drained them.
        int64_t     taken_ns{0};

        // Whether this child has published at all.  A shard forked one turn ago
        // has no figures, and letting its zeros into the sum would report a
        // runtime as losing connections for the length of every restart.
        bool        seen{false};
    };
    const published_stats& last_stats() const { return m_last_stats; }

    // This child has just published its figures.
    //
    // Not "here they are" — those are in last_stats() above, and the handler is
    // what adds them to its siblings'.  What the handler is told is the MOMENT,
    // and that matters because it is the only clock in the daemon that ticks
    // when a connection count moves: nothing else happens here when a client
    // connects to a runtime in a worker.
    //
    // The runtime map carries those counts on to the OTHER workers, and this is
    // what tells it there is something new to carry.  See
    // daemon_handler::on_worker_stats().
    using stats_handler = std::function<void()>;
    void set_stats_handler(stats_handler h) { m_on_stats = std::move(h); }

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

    // Ask the child to re-run its script.  The script lives in the worker, so
    // this is the only way `reload-lua` can reach a runtime that is out of
    // process; the child answers with a `routes` frame, which is what
    // await_routes() below waits for.
    void send_reload();

    // Block until this child has installed a declaration other than
    // `previous` — the placeholder's worker_routes() pointer read before
    // send_reload(), so a frame arriving between the two cannot be mistaken for
    // the one still being waited on.  Same shape and the same rules as
    // await_startup(): ::poll on the control descriptor, no SQE, and no waitpid
    // of its own — see the note above its definition.  False means the child
    // never answered, and the caller publishes what it already had.
    bool await_routes(const void* previous, std::chrono::milliseconds bound);

    // Why this child's last reload failed, or empty if it did not.
    //
    // send_reload() clears it and the child sets it by sending a `reload_err`
    // frame before the `routes` frame that ends await_routes(), so reading it
    // straight after that wait is reading the answer to that reload and no
    // other.  Taken rather than peeked: one reload, one report.
    std::string take_reload_error();

    // Why this child's on_start raised when it was started, or empty if it did
    // not.  The child sends a `start_err` frame before the `state` frame that
    // ends await_startup(), so reading it straight after that wait is reading
    // the answer for that start.  Taken rather than peeked, for the same reason:
    // one start, one report — and a second read must not attribute the first
    // start's failure to a later one.
    std::string take_start_error();

    // A new membership snapshot.  Cheap enough to send unconditionally: the
    // daemon publishes only when a runtime is created, started, stopped,
    // removed or renamed, or when the cluster's view moves.
    void send_endpoints(const std::string& encoded_payload);

    // A new copy of the runtime map, which is what the worker answers
    // socketley.list() and socketley.get() from.
    //
    // Unlike the endpoint table this one is sent on the health tick as well as
    // on membership changes, because it carries connection counts and those move
    // with traffic rather than with events.  So it is the one push that has a
    // reason to arrive unchanged, and it drops a payload byte-identical to the
    // one this child already holds: an idle daemon then costs a string compare
    // per worker per tick instead of a frame.
    //
    // Kept for the same reason the endpoint table is kept: a child forked after
    // the last push would otherwise hold an empty map until something moved.
    void send_runtime_map(const std::string& encoded_payload);

    // What the cluster looks like, for the four socketley.cluster.* calls.
    //
    // Same discipline as the map — cached, deduped, re-sent to a new child —
    // with one difference that is not this function's doing: the payload
    // carries a heartbeat per remote daemon, so on a clustered daemon it
    // differs on every scan and the dedupe rarely fires.  A daemon that is not
    // in a cluster sends this frame once, empty, and then never again.
    void send_cluster_view(const std::string& encoded_payload);

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

    // ─── What the child made of the configuration it was handed ─────────────
    //
    // `create` reports on a runtime whose configuration is applied in another
    // process, and it used to report before that process had looked at it: a
    // script the worker would refuse got rc=0 and an `ls` line saying Up, and
    // the reason arrived in the log afterwards, addressed to nobody.  A
    // declaration is the case that made this visible — a path without a leading
    // slash is perfectly good Lua, so the placeholder's compile-only check
    // passes it — but the shape is older than routes and is not specific to
    // them: anything the worker alone can judge was judged after the answer.
    enum class startup
    {
        pending,   // nothing conclusive yet
        serving,   // the child applied the configuration and bound its socket
        refused,   // the child would not, or could not, serve this configuration
    };

    // Block this thread — NOT the event loop — until the child has reached one
    // of those, or `bound` runs out.
    //
    // The distinction matters and is the whole reason this is safe to call from
    // a command handler.  Waiting here does not pump the ring: it is ::poll(2)
    // on one descriptor, ::read(2) to drain it, and the existing waitpid inside
    // check_liveness().  No SQE is submitted and no completion is reaped, so
    // nothing re-enters the dispatch that called us.  What it does cost is the
    // loop standing still for as long as the wait lasts, which is why the
    // routine case has to be short and is: a worker reports in about 20 ms, and
    // a refusal comes back sooner still because the child exits on the spot.
    // The bound is the backstop for a worker that has wedged, not a budget the
    // normal path spends.
    startup await_startup(std::chrono::milliseconds bound);

    // waitpid(WNOHANG) plus the death policy.  Returns true if the child was
    // found dead — the caller uses that to decide whether to persist a state
    // change.
    bool check_liveness();

    // True once for each time the child reported a state this side had to
    // adopt.  Same shape as check_liveness(): the supervisor decides, the
    // caller persists, so the state file and the runtime map cannot disagree
    // about a runtime that failed in another process.
    // True once after the child has sent a route declaration.  Same shape as
    // take_state_change(): the supervisor decides, the caller republishes.
    bool take_routes_change() { const bool c = m_routes_changed; m_routes_changed = false; return c; }

    bool take_state_change() { const bool c = m_state_changed; m_state_changed = false; return c; }

    // True once each time the child has become answerable at its port — the
    // transition, not the condition.  Same shape as the two above: the
    // supervisor observes, the caller republishes the endpoint table, because a
    // member that has just started listening is only reachable once the
    // gateways have been told it is.  See runtime_instance::endpoint_live().
    bool take_reachability_change()
    { const bool c = m_reachability_changed; m_reachability_changed = false; return c; }

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
    std::string       m_runtime_map;      // last map, re-sent to a new child
    std::string       m_cluster_view;     // last cluster view, likewise
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

    // The token register_owner() handed back, kept because the loop clears the
    // handler's own copy the instant it is deregistered — and deregistering is
    // exactly what retire() has to do before it can hand the token on.
    // io_handler::m_loop_token is private to the loop, and reading it after the
    // fact would read a zero anyway.
    uint32_t     m_owner_token{0};

    io_request   m_poll_req{};
    unsigned     m_poll_mask{0};
    bool         m_poll_armed{false};

    publish_handler m_on_publish;
    deliver_handler m_on_deliver;
    stats_handler   m_on_stats;

    bool         m_state_changed{false};
    bool         m_routes_changed{false};
    bool         m_reachability_changed{false};

    // Why the last `reload` this child was sent did not load.  Empty when it
    // did, because a worker that reloaded cleanly sends no frame at all.
    std::string  m_reload_error;

    // See published_stats above.
    published_stats m_last_stats;

    // Why this child's on_start raised when it was started.  Empty when it did
    // not, for the same reason: the frame is only sent on a raise.  Held apart
    // from m_reload_error because the two are cleared on different asks — a
    // reload clears its own before sending — and one member for both would hand
    // a startup failure to the first reload that asked.
    std::string  m_start_error;

    // The last state the child reported about itself, observed and not adopted.
    //
    // ingest() is explicit that created/running are not written through to the
    // placeholder, because the daemon's own record is what the CLI is promised
    // and a second writer for one value is how those two come to disagree.
    // That rule is about who OWNS the value; it does not stop this side from
    // remembering what it was told.  await_startup() reads this to tell "the
    // child has bound its socket" from "the child has not answered yet", and
    // writes nothing anywhere on the strength of it.
    runtime_state m_worker_state{runtime_created};
    bool          m_worker_state_seen{false};

    pid_t        m_pid{0};
    int          m_control_fd{-1};
    death_policy m_policy{death_policy::restart};
    unsigned     m_restarts{0};
    std::chrono::steady_clock::time_point m_last_restart{};
};
