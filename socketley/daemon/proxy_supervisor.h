#pragma once
// One child process, one control socket, and the placeholder that stands for
// the child inside the daemon, whose published figures let `stats` and
// `inspect` read it without knowing the runtime lives elsewhere -- and whose
// socket is armed in the ring, because a request has somebody waiting on it
// and a health-tick drain made a cross-process `cache set` cost 2000.02 ms.
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <sys/types.h>

#include "../shared/loop/backlog_gate.h"
#include "../shared/net/conn_identity.h"
#include "../shared/ipc/request_channel.h"
// For runtime_state: await_startup() remembers the state the child reported
// without adopting it, so the enum is part of this class's own storage now
// rather than something only the .cpp had to know about.
#include "../shared/runtime/runtime_definitions.h"
#include "../shared/ipc/worker_protocol.h"
#include "../shared/ipc/deadline_slot.h"

class runtime_instance;
struct runtime_config;

// A child that dies immediately and repeatedly is not fixed by forking it
// again, so after this many restarts inside the window the runtime is left
// `failed`.  Here rather than in the .cpp because two paths restart children
// -- this class for a worker, and daemon_handler's managed sweep for an `add`
// runtime -- and they owe the operator the same answer.
inline constexpr unsigned restart_burst_limit  = 5;
inline constexpr auto     restart_burst_window = std::chrono::seconds(10);

// Also the request_sink for the runtime it supervises and the request_origin
// for requests coming the other way, because the daemon holds the whole map
// and is the only process that can route.
class proxy_supervisor : public deferred_request_sink, public request_origin,
                         public io_handler
{
public:
    // Where the control socket is armed, without which the supervisor still
    // answers on the health tick, which is what it did before.
    void set_event_loop(event_loop* loop);

    // Stop supervising and hand back the identity it submitted under, because
    // an io_request lives inside this class and the destructor can neither
    // wait for the ring nor re-enter the loop -- and everything this object
    // points at is known alive at retirement and not one moment longer.
    uint32_t retire();

    void on_cqe(struct io_uring_cqe* cqe) override;

    bool serve_deferred(uint64_t ticket, std::string_view target,
                        std::string_view payload) override;
    // A child still connected refused a request for its backlog.
    request_status refusal(std::string_view target, size_t size) const override;

    // A reply to something the worker asked, carrying the worker's own ticket
    // back unchanged so this side keeps no table.
    void on_request_reply(uint64_t cookie, request_status st,
                          std::string_view reply) override;

    void set_channel(request_channel* ch) { m_channel = ch; }

    // What to do with a publish coming up from the child, which passes itself
    // so the daemon can leave this child out of the fan-out it has already
    // served.
    using publish_handler = std::function<void(proxy_supervisor* from,
                                               std::string_view cache_name,
                                               std::string_view channel,
                                               std::string_view message)>;
    void set_publish_handler(publish_handler h) { m_on_publish = std::move(h); }

    // What to do with a `send` coming up from the child, including one naming
    // the worker's own runtime, because on N shards the local half is 1/N of
    // the clients and the sending shard must be left out of the fan-out.
    using deliver_handler = std::function<void(proxy_supervisor* from,
                                               std::string_view name,
                                               std::string_view message)>;

    // A message for a connection held by a sibling of the shard that asked,
    // resolved by the minting shard in the ref's serial, so this is a lookup
    // and one write rather than a fan-out.
    using send_ref_handler = std::function<void(proxy_supervisor* from,
                                                const conn_ref& ref,
                                                std::string_view message)>;
    void set_send_ref_handler(send_ref_handler h) { m_on_send_ref = std::move(h); }

    // The message on its way down to the shard that owns the connection.
    bool send_deliver_ref(const conn_ref& ref, std::string_view message);
    void set_deliver_handler(deliver_handler h) { m_on_deliver = std::move(h); }

    // A connection served by this child and answered by another runtime, which
    // unlike send_ref addresses a different runtime entirely, so the frame
    // carries two names and the daemon resolves them.
    using route_handler = std::function<void(proxy_supervisor* from,
                                             std::string_view to,
                                             std::string_view frm,
                                             worker_proto::route_op op,
                                             const conn_ref& ref,
                                             std::string_view payload)>;
    void set_route_handler(route_handler h) { m_on_route = std::move(h); }

    // Which runtime this supervisor stands for, const because a reader of a
    // worker's frame has no business writing to the daemon's record, and null
    // after retire().
    const runtime_instance* placeholder() const { return m_placeholder; }

    // The same frame going the other way, one codec with two names, for the
    // reason send_ref/deliver_ref are one codec.
    bool send_route(std::string_view to, std::string_view frm,
                    worker_proto::route_op op, const conn_ref& ref,
                    std::string_view payload);

    // The figures this child last published, held here rather than written
    // into the placeholder, because N supervisors writing the same fields
    // meant the last frame to arrive won.
    struct published_stats
    {
        shard_stats::figures f;
        std::string          detail;

        // Whether this child has published at all, since letting a just-forked
        // shard's zeros into the sum reports a runtime losing connections for
        // the length of every restart.
        bool        seen{false};
    };
    const published_stats& last_stats() const { return m_last_stats; }

    // This child has just published, which is the only clock in the daemon
    // that ticks when a connection count moves, and what tells the runtime map
    // there is something new to carry.
    using stats_handler = std::function<void()>;
    void set_stats_handler(stats_handler h) { m_on_stats = std::move(h); }

    // The four map calls are the only thing a worker waits for, and they
    // travel on a second socketpair because the control socket's writes queue
    // for the ring and its reads are a standing recv a direct read would race.
    // ─── WHAT THE HANDLER OWES ──────────────────────────────────────────────
    // `reply_fd` is a dup owned by the handler, because
    // `socketley.remove(own_name)` destroys the very supervisor the request
    // came through and a member read afterwards is freed memory.
    using map_handler = std::function<void(uint64_t ticket, int reply_fd,
                                           std::string op, std::string name,
                                           std::string config)>;
    void set_map_handler(map_handler h) { m_on_map = std::move(h); }

    // The runtime map as it is now and its generation, which a child is handed when it first reads the map, or at
    // its spawn when it has no map socket to ask on.
    using map_source = std::function<std::pair<const std::string*, uint64_t>()>;
    void set_map_source(map_source s) { m_map_source = std::move(s); }

    // ─── Peer links ─────────────────────────────────────────────────────────
    // A crossing this worker made to another runtime, reported so the daemon
    // can introduce the two processes to each other instead of carrying every
    // one of them; called on the relay path, which stops happening once the
    // link is up, so it needs no registry to know when to stop.
    using peer_handler = std::function<void(proxy_supervisor* from,
                                            std::string target)>;
    void set_peer_handler(peer_handler h) { m_on_peer = std::move(h); }

    // A metrics runtime's pull of this daemon's series, and what the daemon keeps of what it sent this child, which
    // goes with the supervisor so a child that is gone takes it along.
    using series_handler = std::function<void(proxy_supervisor* from, std::string payload)>;
    void set_series_handler(series_handler h) { m_on_series = std::move(h); }
    // A metrics runtime's alert for the daemon's notifier.
    void set_alert_handler(series_handler h) { m_on_alert = std::move(h); }
    std::shared_ptr<void>& series_state() { return m_series_state; }
    bool send_series_feed(const std::string& framed) { return write_frame(framed); }

    // One end of a link, handed to this child.  False means it stays on the
    // relay, which is where every crossing was before links existed.
    bool grant_peer_link(std::string_view peer, int fd);

    // The operator's interactive session, over the same channel; see the
    // definition for why it is a marker and not a second one.
    bool grant_interactive(int fd);

    // Whether this child has been introduced to `peer` recently enough that a
    // second grant would be waste rather than repair.
    bool grant_suppressed(std::string_view peer);

    // One answer on the descriptor the request arrived on, static because the
    // supervisor may be gone, and a blocking write because the frame is tens
    // of bytes against a socketpair buffer of a hundred kilobytes.
    static void answer_map_request(int reply_fd, uint64_t ticket, bool ok,
                                   std::string_view err);

    proxy_supervisor(runtime_instance* placeholder, std::string exec_path);
    ~proxy_supervisor();

    proxy_supervisor(const proxy_supervisor&)            = delete;
    proxy_supervisor& operator=(const proxy_supervisor&) = delete;

    // Which shard this child is and where it publishes, with `region_fd` and
    // `clients_fd` borrowed descriptors the daemon holds for as long as the
    // runtime exists, since a replacement shard must map what its siblings
    // already have.
    void set_shard(uint32_t index, int region_fd, int clients_fd)
    { m_shard_index = index; m_shard_region_fd = region_fd;
      m_shard_clients_fd = clients_fd; }
    uint32_t shard_index() const { return m_shard_index; }

    // The shard mesh ends this child inherits, consumed by the fork because
    // the daemon closes its own copies once the whole set is forked, so a
    // restarted shard relays instead.
    void set_mesh_fds(std::vector<int> fds) { m_mesh_fds = std::move(fds); }
    void clear_mesh_fds() { m_mesh_fds.clear(); }

    // Fork, exec, and send the config, leaving the placeholder `running` only
    // once the child is forked and the config written.
    bool spawn(const runtime_config& cfg);

    // Ask the child to stop serving but stay alive, or to exit outright.
    void send_start();
    void shutdown();

    // Ask the child to re-run its script, which is the only way `reload-lua`
    // reaches an out-of-process runtime, answered with the `routes` frame
    // await_routes() waits for.
    // `lua_path` is the script the daemon believes this runtime has, empty
    // when the caller has nothing to add; the worker keeps its own on empty.
    void send_reload(std::string_view lua_path = {});

    // A config frame to a worker that already has one, which is `edit` on a
    // running runtime.  See worker_main's on_config for what a live one takes.
    void send_config(std::string_view json);

    // A cluster cache replica's order, false when the frame could not be queued.
    bool send_replica_order(std::string_view payload);

    // Block until this child has installed a declaration other than
    // `previous`, read before send_reload() so a frame arriving between the
    // two is not mistaken for the one waited on.
    // A deadline and not a bound, because the caller waits on one of these per
    // runtime and a bound each is a bound times however many were named.
    bool await_routes(const void* previous,
                      std::chrono::steady_clock::time_point deadline);

    // Why this child's last reload failed, cleared by send_reload() and set
    // before the `routes` frame, taken rather than peeked because one reload
    // gets one report.
    std::string take_reload_error();

    // Why this child's on_start raised, set before the `state` frame that ends
    // await_startup(), taken rather than peeked so a second read cannot
    // attribute it to a later start.
    std::string take_start_error();

    // The same, for a worker that would not accept its configuration at all.
    std::string take_config_error();

    // A new membership snapshot, cheap enough to send unconditionally because
    // the daemon publishes only on the few events that move one.
    void send_endpoints(const std::string& encoded_payload);

    // Generation `gen` of the runtime map, to a child that reads the map: only the rows that moved when it holds
    // gen - 1, the whole map from `full` otherwise, nothing when it holds gen.
    void send_runtime_map(const std::function<const std::string&()>& full, const std::string& delta, uint64_t gen);

    // What the cluster looks like, cached and deduped like the map, except
    // that a heartbeat per remote daemon makes the payload differ on every
    // scan of a clustered daemon.
    void send_cluster_view(const std::string& encoded_payload);

    // One event rather than the snapshot above, because a script that only
    // reads the view can never see a change it slept through.
    void send_cluster_event(const std::string& encoded_payload);

    // `socketley send` on its way to the runtime that has the connections,
    // best-effort like every frame going down, with a false reported rather
    // than answered 0.
    bool send_deliver(std::string_view message);

    // One published message on its way to the child's subscribe callbacks, not
    // kept like the endpoint table, because a publish is an event that already
    // happened.
    void send_publish(const std::string& encoded_payload);

    // Whether this child's publishes have anywhere to go, sent only when the
    // answer changes, which for a daemon serving one runtime is once.
    void send_publish_interest(bool on);

    // Drain whatever the child has sent and apply it to the placeholder, from
    // the health timer and before any command that reads figures.
    void poll();
    // Up to `slice` ms on the control and map sockets, the control backlog written as the child takes it.
    void wait_on_sockets(int slice);

    // What the child made of the configuration it was handed, because `create`
    // used to report rc=0 and an `ls` line saying Up while the reason arrived
    // in the log addressed to nobody.
    enum class startup
    {
        pending,   // nothing conclusive yet
        serving,   // the child applied the configuration and bound its socket
        refused,   // the child would not, or could not, serve this configuration
    };

    // Block this thread and not the event loop -- ::poll, ::read and the
    // existing waitpid, with no SQE submitted and no completion reaped -- so
    // nothing re-enters the dispatch that called it, and `bound` is the
    // backstop for a wedged child rather than a budget.
    startup await_startup(std::chrono::milliseconds bound);

    // ── A request the daemon itself makes ───────────────────────────────────
    // The channel is the route between two runtimes and it drains on the ring,
    // so a command handler that posted into it and then blocked would wait for
    // a drain its own blocking prevents.  This is the same chan_req frame with
    // a ticket the daemon mints, answered into a slot rather than into the
    // channel's parked table.
    //
    // Tickets carry the top bit, which the channel's counter never reaches, so
    // the two numbering schemes cannot name the same request.
    static constexpr uint64_t direct_ticket_bit = 1ull << 63;

    bool send_direct(uint64_t ticket, std::string_view payload);

    // Blocks like await_startup and for the same reasons; false means the
    // deadline passed or the child went away with nothing said.
    bool await_direct(uint64_t ticket, std::chrono::milliseconds bound,
                      uint8_t& status, std::string& reply);

    // waitpid(WNOHANG) plus the death policy, answering true if the child was
    // found dead so the caller can decide whether to persist a state change.
    bool check_liveness();

    // A child that is alive and no longer serving, which waitpid cannot see.
    // The worker sets stats_dirty on every completion, so a worker doing any
    // work at all speaks within stats_interval_ms; one that is silent is either
    // idle, which costs no cpu, or stuck inside a handler, which costs a core.
    // Reads /proc/<pid>/stat and sends nothing, because a probe would wake the
    // idle case sixteen times more often than its own loop intends to.
    //
    // Reports and never kills: a long computation in a script looks the same
    // from out here, and the operator is the one who knows which it is.
    void check_wedged();

    // ── The Lua callback deadline, watched from out here ────────────────────
    // Every live worker's line read once, at most every deadline_slot::scan_ms
    // whoever asks: the daemon's timer, and the waits that hold its loop while
    // a worker runs its top level or on_start.
    static void sweep_deadlines();

    // Whether any child is there to watch, which is what keeps the timer
    // behind sweep_deadlines() armed.
    static bool any_watched();

    // Whether a child killed at its deadline is still waiting to be reaped,
    // so its replacement is forked on the next sweep and not the next health tick.
    static bool any_killed();

    // Who to tell that a child has just been forked, so a timer that stopped
    // for want of children starts again before the child runs a line of Lua.
    static void set_spawn_hook(std::function<void()> hook);

    // True once for each state or route declaration the child reported: the
    // supervisor decides and the caller persists or republishes.
    bool take_routes_change() { const bool c = m_routes_changed; m_routes_changed = false; return c; }

    bool take_state_change() { const bool c = m_state_changed; m_state_changed = false; return c; }

    // True once each time the child has become answerable at its port -- the
    // transition, not the condition -- so the caller republishes the endpoint
    // table.
    bool take_reachability_change()
    { const bool c = m_reachability_changed; m_reachability_changed = false; return c; }

    bool  is_alive() const { return m_pid > 0; }
    pid_t pid()      const { return m_pid; }

    // Hand the child over to somebody who will outlive this object, because on
    // the stop path the supervisor is erased in the same statement and nothing
    // ever waited on the child again.
    pid_t release_pid() { const pid_t p = m_pid; m_pid = 0; return p; }

private:
    void   close_control();
    // With no cap named, a frame nobody waits on, held to MAX_CONTROL_BACKLOG of those beside what is owed; a cap
    // named is a request's or an answer's, owed to an asker and counting everything queued.
    bool   write_frame(const std::string& framed, size_t cap = 0);

    // One outstanding direct request, because a command handler blocks until
    // its own answer arrives and cannot start a second.
    uint64_t    m_direct_ticket{0};
    bool        m_direct_done{false};
    uint8_t     m_direct_status{0};
    std::string m_direct_reply;

    void   on_chan_req(std::string_view payload);

    // Arm the control socket for readability if there is a loop, a socket and
    // nothing armed, re-armed from on_cqe() because a multishot poll on a
    // descriptor this class closes on several paths outlives its fd.
    void   flush_control();
    size_t pending_out() const { return m_out.size() - m_out_off; }

    void   arm_control_poll();
    // Give the arm back before the descriptor goes, which is what makes sure
    // the owner is deregistered when the loop drops the completion.
    void   disarm_control_poll();

    // The same three for the map socket, separate rather than parameterised
    // because the two descriptors differ in every property that matters.
    void   arm_map_poll();
    void   disarm_map_poll();
    void   poll_map();
    void   close_map();
    // The child's ask for the map, answered with all of it, after which it is pushed every change.
    void   subscribe_map(uint64_t ticket);
    void   close_link_chan();

    void   apply_stats(const std::string& payload);
    void   ingest();

    // "runtime 'name' shard N: ", the start of every line this class logs
    // about its worker, because the daemon supervises many and a crash that
    // names none of them sends the operator matching timestamps by hand.
    std::string who() const;

    // Deliberately a runtime_instance and nothing narrower, because everything
    // this class does is the same work whatever kind of runtime is on the
    // other side.
    request_channel*  m_channel{nullptr};
    runtime_instance* m_placeholder{nullptr};
    std::string       m_exec_path;
    std::string       m_config_json;      // kept so a restart can re-send it
    std::string       m_endpoints;        // last table, re-sent to a new child
    bool              m_endpoints_held{false}; // the running child was handed m_endpoints
    uint64_t          m_map_gen_held{0};     // the generation the running child holds, 0 for none
    bool              m_map_pushed{false};   // the running child asked for the map, or has no socket to ask on
    std::string       m_cluster_view;     // last cluster view, likewise
    std::string       m_in;               // partial frames from the child
    worker_proto::part_joiner m_part;     // a frame past max_payload, while its pieces come in

    // Frames written but not yet taken by the socket, bounded because the
    // alternative is the daemon growing without limit on behalf of a child
    // that has stopped reading.
    static constexpr size_t MAX_CONTROL_BACKLOG = 4u << 20;
    // A request or an answer of `size` is let past the cap as far as worker_proto::owed_cap_for says.
    static constexpr size_t owed_cap(size_t size) { return MAX_CONTROL_BACKLOG + worker_proto::owed_cap_for(size); }
    // An answer for the child: queued within owed_cap(), else an empty one saying the way was overloaded.
    void   write_answer(uint64_t ticket, uint8_t status, std::string_view reply);

    std::string  m_out;
    size_t       m_out_off{0};
    backlog_gate m_out_gate;
    // Every byte ever queued in m_out, and of those the ones owed to an asker.
    uint64_t     m_out_total{0};
    owed_bytes   m_out_owed;
    // Those of them that went in pieces, under a cap of their own beside the rest.
    owed_bytes   m_out_lone;

    event_loop*  m_loop{nullptr};

    // The token register_owner() handed back, kept because the loop clears the
    // handler's own copy the instant it is deregistered, which retire() must
    // do first.
    uint32_t     m_owner_token{0};

    io_request   m_poll_req{};
    unsigned     m_poll_mask{0};
    bool         m_poll_armed{false};

    // The map socket and its own arm, a second io_request because the loop
    // tells two submissions of the same shape apart by the address of the
    // request and by nothing else.
    io_request   m_map_poll_req{};
    bool         m_map_armed{false};
    std::string  m_map_in;            // partial map frames from the child

    publish_handler  m_on_publish;

    // Tri-state, so the first answer is always sent: a child that starts
    // assuming it has receivers must hear "no" even when "no" is the value
    // this field would otherwise have been born with.
    int m_publish_interest_sent{-1};
    deliver_handler  m_on_deliver;
    send_ref_handler m_on_send_ref;
    route_handler    m_on_route;
    stats_handler   m_on_stats;
    map_handler      m_on_map;
    map_source       m_map_source;
    peer_handler     m_on_peer;
    series_handler   m_on_series;
    series_handler   m_on_alert;
    std::shared_ptr<void> m_series_state;

    bool         m_state_changed{false};
    bool         m_routes_changed{false};
    bool         m_reachability_changed{false};

    // Why the last `reload` this child was sent did not load, empty when it
    // did, because a clean reload sends no frame at all.
    std::string  m_reload_error;

    // See published_stats above.
    published_stats m_last_stats;

    // Stamped in ingest(), where every frame passes.
    std::chrono::steady_clock::time_point m_last_frame_at{};

    // The child's cpu time at the last sample, which is what tells silence
    // apart from a spin.  Zero `m_last_cpu_at` means nothing sampled yet.
    uint64_t                              m_last_cpu_ticks{0};
    std::chrono::steady_clock::time_point m_last_cpu_at{};
    bool                                  m_wedged{false};
    // When a reported wedge first spent under the share, zero while it spends at least that.
    std::chrono::steady_clock::time_point m_cool_since{};

    // Why this child's on_start raised, held apart from m_reload_error because
    // the two are cleared on different asks.
    std::string  m_start_error;
    std::string  m_config_error;
    // Whether this child ever spoke the protocol, which separates a worker
    // that refused its configuration from a binary that was never a worker.
    bool         m_saw_worker_frame{false};

    // The last state the child reported, observed and not adopted, which
    // await_startup() reads to tell "the child has bound its socket" from "the
    // child has not answered".
    runtime_state m_worker_state{runtime_created};
    bool          m_worker_state_seen{false};

    // See set_shard(): zero and -1 mean the only process serving this runtime,
    // which every unsharded runtime is.
    uint32_t     m_shard_index{0};
    std::vector<int> m_mesh_fds;
    int          m_shard_region_fd{-1};
    int          m_shard_clients_fd{-1};

    // This child's callback as the daemon sees it, judged on every sweep: told
    // to stop past its limit, and killed for the death policy to replace once
    // it has had its grace.
    void check_deadline(uint64_t now_ns);

    // The one line the child writes its running callback into, kept across
    // restarts and zeroed for each new child.
    deadline_slot::region m_deadline;
    deadline_slot::watch  m_deadline_watch;
    bool                  m_deadline_killed{false};

    pid_t        m_pid{0};
    int          m_control_fd{-1};
    int          m_map_fd{-1};

    // The grant channel to this child, and when each peer was last named on
    // it, so a worker relaying a burst before its link arrives is introduced
    // once rather than once per request.
    int          m_link_chan_fd{-1};
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> m_granted;
    unsigned     m_restarts{0};
    std::chrono::steady_clock::time_point m_last_restart{};
};
