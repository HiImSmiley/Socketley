#pragma once
#include <string>
#include <string_view>
#include <unordered_map>
#include <memory>
#include <vector>
#include <chrono>
#include <sys/un.h>

#include "../shared/event_loop_definitions.h"
#include "../shared/runtime_instance.h"
#include "../shared/shard_clients.h"
#include "../cli/arg_parser.h"

class event_loop;
class runtime_manager;
class state_persistence;
class cluster_discovery;
class endpoint_table;
class proxy_supervisor;
class request_channel;
struct cluster_event;

struct ipc_connection
{
    int fd;
    io_request read_req;
    io_request write_req;
    char read_buf[4096];

    // Scratch for the command being processed.  Every cmd_* assigns to it
    // outright and it is cleared before each one, so it must never be storage
    // the ring is reading from: append_response() copies it into out_buf and
    // that is the only thing a write SQE ever points at.
    std::string write_buf;

    // The framed replies waiting to go out, and the one buffer a write is
    // submitted from.  Untouched between a submission and its completion — see
    // send_response() for what it cost when it was not.
    std::string out_buf;
    size_t write_off = 0;

    // A write is in the ring naming out_buf.  While it is set no read is armed
    // on this connection, so nothing can arrive that would want to rebuild the
    // buffer underneath it.
    bool write_pending = false;

    std::string partial;

    bool interactive = false;
    std::string interactive_name;
};

class daemon_handler : public io_handler
{
public:
    daemon_handler(runtime_manager& manager, event_loop& loop);
    ~daemon_handler() override;

    static bool is_running();
    bool setup();
    void teardown();
    void on_cqe(struct io_uring_cqe* cqe) override;

    void set_state_persistence(state_persistence* sp);
    void set_cluster_discovery(cluster_discovery* cd);
    void set_metrics_port(uint16_t port);

    static std::string socket_path;

    // Whether the path above is the packaged deployment's socket — /run/socketley
    // — rather than a socket this daemon owns alone.  Set from
    // socketley_paths::system_mode by the one caller that starts a daemon, and
    // read only by setup(), which uses it to decide who may open the control
    // plane.  See the block of reasoning there.
    //
    // False is the safe answer and therefore the default: a daemon that never
    // says otherwise gets a socket only its own uid can open.
    static bool system_socket;

private:
    using client_map = std::unordered_map<int, std::unique_ptr<ipc_connection>>;

    void handle_accept(struct io_uring_cqe* cqe);
    void handle_read(struct io_uring_cqe* cqe, io_request* req);
    void handle_write(struct io_uring_cqe* cqe, const io_request* req);
    void close_client(client_map::iterator it);
    void release_closing(const io_request* req);

    // Returns -1 if names resolved OK (caller should continue), otherwise the exit code to return.
    // conn == nullptr → stdout errors, conn != nullptr → conn->write_buf errors.
    int check_empty_names(const std::vector<std::string>& names,
        const parsed_args& pa, const char* verb, ipc_connection* conn) const;

    int process_command(ipc_connection* conn, std::string_view line);
    int cmd_create(ipc_connection* conn, const parsed_args& pa);
    int cmd_start(ipc_connection* conn, const parsed_args& pa);
    int cmd_stop(ipc_connection* conn, const parsed_args& pa);
    int cmd_remove(ipc_connection* conn, const parsed_args& pa);
    int cmd_ls(ipc_connection* conn, const parsed_args& pa);
    int cmd_ps(ipc_connection* conn, const parsed_args& pa);
    int cmd_send(const parsed_args& pa);

    // Where a message addressed to a runtime name goes: to the connections in
    // this process, or on to the one worker that holds them.  False with `why`
    // filled in when there is nowhere for it to go.
    //
    // Shared by `send` at the CLI and by a worker's socketley.send arriving as a
    // frame, so the two cannot come to different conclusions about whether a
    // message was delivered.
    //
    // `exclude` is the one shard NOT to deliver to, and it is null for every
    // caller but one: a worker fanning a broadcast out to its own siblings has
    // already delivered locally, so echoing the frame back to it would reach
    // every one of its clients twice.  Same shape and the same reason as the
    // publish origin — see on_worker_publish.
    bool deliver_to_runtime(std::string_view name, std::string_view message,
                            std::string& why,
                            const proxy_supervisor* exclude = nullptr);
    int cmd_edit(ipc_connection* conn, const parsed_args& pa);
    int cmd_dump(ipc_connection* conn, const parsed_args& pa);
    int cmd_import(ipc_connection* conn, const parsed_args& pa);
    int cmd_action(ipc_connection* conn, const parsed_args& pa);
    int cmd_stats(ipc_connection* conn, const parsed_args& pa);
    int cmd_reload(ipc_connection* conn, const parsed_args& pa);
    int cmd_reload_lua(ipc_connection* conn, const parsed_args& pa);
    int cmd_owner(ipc_connection* conn, const parsed_args& pa);
    int cmd_attach(ipc_connection* conn, const parsed_args& pa);
    int cmd_add(ipc_connection* conn, const parsed_args& pa);
    int cmd_cluster_dir(ipc_connection* conn);
    int cmd_cluster_status(ipc_connection* conn);
    int cmd_daemon_name(ipc_connection* conn, const parsed_args& pa);
    int cmd_daemon_cluster(ipc_connection* conn, const parsed_args& pa);
    int cmd_dashboard(ipc_connection* conn);

    // The daemon saying which daemon it is.  Asked by every CLI command before
    // it sends anything, so that "something accepted my connection" stops being
    // read as "a daemon is here"; see shared/daemon_client.h.
    int cmd_ping(ipc_connection* conn);

    // Bring cluster discovery up under NAME in DIR, replacing whatever is
    // running.  On failure nothing is left running and m_cluster_error says
    // why, in the words the operator gets.
    bool start_cluster(const std::string& name, const std::string& dir);
    void stop_cluster();

    // What the daemon says about clustering when it is off: the flag it was
    // given and could not honour.  Nothing here is a substitute for the reply
    // to the command that failed — it is what `socketley cluster ...` reports
    // afterwards, when the exit code has long been thrown away.
    std::string cluster_off_reason() const;

    std::vector<std::string> resolve_names(const parsed_args& pa, size_t start = 1) const;

    // Frame one command's reply into the connection's outgoing stream; submit
    // the single write that carries all of them.  Split because a packet may
    // hold several commands and only one write may be outstanding at a time.
    void append_response(ipc_connection* conn, int exit_code);
    bool send_response(ipc_connection* conn);

    runtime_manager& m_manager;
    event_loop& m_loop;

    int m_listen_fd;
    struct sockaddr_un m_accept_addr;
    socklen_t m_accept_addrlen;
    io_request m_accept_req;
    bool m_accept_armed{false};

    client_map m_clients;

    // Connections whose client hung up while the reply send_response() submitted
    // for them was still in the ring.  They are gone as far as the daemon is
    // concerned — closed and out of m_clients — but the kernel is still reading
    // out_buf out of them and the completion still names write_req, so the
    // storage is held until that write reports.  Normally empty: a reply is out
    // long before the hangup unless it outgrew the socket buffer.
    std::vector<std::unique_ptr<ipc_connection>> m_closing;

    state_persistence* m_persistence = nullptr;
    cluster_discovery* m_cluster = nullptr;
    std::unique_ptr<cluster_discovery> m_owned_cluster;
    std::string m_daemon_name;
    uint16_t m_metrics_port{0};

    // The last --cluster this daemon was given and refused, and why.  Kept so
    // that a node running with clustering off can say so when asked, instead of
    // reporting the same "not in cluster mode" as a daemon that was never
    // asked to join one.
    std::string m_cluster_error;
    std::string m_cluster_want_dir;

    // Health monitoring for managed runtimes, and the periodic reap of retired
    // runtime instances — see the op_timeout branch of on_cqe().
    io_request m_health_req{};
    struct __kernel_timespec m_health_ts{};
    bool m_health_pending{false};

    // teardown() has run.  Only the health timer cares: withdrawing it makes
    // its completion arrive at once, and that completion is what re-arms the
    // chain, so without this a teardown under a live ring would start the timer
    // it just withdrew.  Cleared by setup().
    bool m_torn_down{false};

    void start_health_timer();
    void start_accept();
    void check_managed_health();

    // ── Out-of-process proxies ──────────────────────────────────────────────
    // The supervisors for one runtime that runs in workers, keyed by runtime
    // name.  Owned here rather than by the instance because a supervisor
    // outlives a stop: `stop` takes the child down but the runtime stays in the
    // map, and `start` must bring a new one up against the same record.
    //
    // ─── WHY THE VALUE IS A VECTOR AND NOT A POINTER ────────────────────────
    //
    // --shards N gives one runtime N worker processes sharing its listening
    // socket, so "the supervisor for this name" stopped being a thing there is
    // one of.  The alternative was to keep this map as it was, with the first
    // shard in it, and put the extra ones in a second container beside it.
    // That shape was rejected on the rule this tree already states about the
    // half-close hold: an invariant every path has to REMEMBER is one that new
    // paths will not know about.  Thirteen functions here reach into this map
    // across 30 sites, and a second container would have meant thirteen chances
    // to publish a frame to shard 0 and silently not to shards 1..N-1 — where
    // the symptom is not a failure but 1/N of the work quietly going undone.
    //
    // Changing the TYPE is what makes that impossible rather than merely
    // discouraged: the compiler names every one of the 30 sites, and each was
    // read and answered on its own terms — fan out to all shards, ask any one
    // shard, or sum across them.  Which of those three a site wanted was not
    // uniform, which is exactly why a mechanical sweep would have been wrong.
    using worker_shards = std::vector<std::unique_ptr<proxy_supervisor>>;
    std::unordered_map<std::string, worker_shards> m_proxy_workers;

    // ── The shared table each runtime's shards publish into ─────────────────
    //
    // One region per SHARDED runtime, keyed the same way as the shards above
    // and created beside them.  See shard_stats.h for what is in it and why it
    // is a memfd; what belongs here is why the DAEMON holds it when the daemon
    // never reads a figure out of it.
    //
    // Because it has to outlive any one shard.  A shard that dies is replaced,
    // and the replacement has to map the same region as its siblings — so the
    // descriptor cannot belong to the supervisor that hands it over, or a
    // restart would hand out a fresh region and the runtime would split into
    // two aggregations that each answer for half of itself.  The daemon is the
    // only object here whose lifetime covers the runtime rather than one of its
    // processes.
    //
    // Absent for every unsharded runtime, which is the ordinary case: nothing
    // is mapped, nothing is created, and the shards path costs a lookup that
    // misses.
    std::unordered_map<std::string, shard_stats::shard_table> m_shard_regions;

    // And which connections each shard is holding, by name.  A second region
    // for the reason shard_clients.h opens with: the counter is touched every
    // turn of every shard's loop and the list is touched when a connection
    // arrives or leaves, so putting the cold 128 KB behind the same fd as the
    // hottest line in the process buys nothing and costs cache.
    //
    // Same lifetime rule as the counters above, and for the same reason: it has
    // to outlive any one shard, because a replacement must map what its
    // siblings already have.
    std::unordered_map<std::string, shard_clients::client_table> m_shard_client_regions;

    // What every shard of one runtime last reported, added up and written into
    // the placeholder that stands for it.
    //
    // A shard is an implementation detail of a runtime and not a runtime, so
    // `ls` shows one line, `inspect` shows one record, and the connection count
    // on it is the number of connections the runtime is serving — which is the
    // sum over its shards and not whichever one published most recently.
    // apply_stats() used to write the placeholder directly, and with N shards
    // that made the figure a race between siblings: four shards with 25
    // connections each reported 25.
    void aggregate_worker_stats(const std::string& name);

    // Bring the children into line with what the runtime map says.  Called from
    // the health timer and straight after any command that moves a runtime's
    // state, so the CLI never has to wait a tick to see the effect.
    //
    // Reconciling beats intercepting: a runtime's state is moved from `create
    // --start`, `start`, `stop`, `remove`, `reload`, an ownership cascade and
    // the boot-time restore, and a rule applied in one place cannot be
    // forgotten at the seventh call site.
    void reconcile_proxy_workers();

    // Wait for a just-started out-of-process runtime to say whether it can serve
    // the configuration it was handed, and turn that into an exit status.
    //
    // Returns 0 if the child is serving, non-zero otherwise, with the reason
    // appended to `out`.  A runtime that is not out-of-process, or that has no
    // supervisor, is 0: there is nothing in another process to wait for.
    //
    // The reason goes into a string rather than onto std::cout because the two
    // callers answer on different channels: cmd_create borrows cout for the
    // length of the command (cout_to_reply), and cmd_start and cmd_reload write
    // to conn->write_buf.  Printing from in here put `start`'s reason on the
    // daemon's own stdout, which is the place these messages were already being
    // lost — the same mistake cmd_reload_lua writes its own note about.
    //
    // `deadline` is an absolute point, not a duration, so that a command
    // starting several runtimes spends ONE budget across all of them.  The
    // children are forked by a single reconcile_proxy_workers() before any of
    // these waits, so they come up concurrently: a `start` of twenty pays about
    // one child's startup, and only a wedged child can reach the bound.
    int await_worker_startup(std::string_view name, std::string& out,
                             std::chrono::steady_clock::time_point deadline);

    // Why this runtime's on_start raised, wherever the script ran.
    //
    // The instance holds it when the script ran in the daemon; when it ran in a
    // worker the child sent it up as a `start_err` frame and the supervisor
    // holds it.  Taken, not peeked — one start, one report — so this must be
    // called once per start, after the wait that guarantees the frame has been
    // ingested.  Empty when on_start ran, which is the ordinary case.
    std::string on_start_error(std::string_view name);

    // Drain every worker's control socket so the figures are current.  Called
    // before the commands that print them.
    void poll_proxy_workers();

    // ── Children whose supervisor is gone ───────────────────────────────────
    // A worker that has been signalled but not yet exited, taken over from the
    // supervisor being destroyed.  Nobody else can reap it: the daemon also
    // waitpid()s its managed runtimes by pid, so a catch-all SIGCHLD reaper
    // would swallow their exit status.
    struct orphan_worker
    {
        pid_t                                 pid;
        std::chrono::steady_clock::time_point signalled_at;
        bool                                  killed{false};
    };
    std::vector<orphan_worker> m_orphan_workers;

    // waitpid(WNOHANG) over the list, and SIGKILL for anything still there a few
    // seconds after its SIGTERM.  Called from the health timer.
    void reap_orphan_workers();

    // ── Handlers the ring has not finished with ─────────────────────────────
    // The same shape one level up, and for a reason that rhymes: above, a pid
    // that cannot be reaped yet; here, storage that cannot be freed yet.
    //
    // Two of this daemon's handlers embed an io_request in their own storage —
    // proxy_supervisor's control-socket poll, cluster_discovery's publish timer
    // — and both are freed while the daemon is running.  A completion still in
    // the ring therefore names memory inside the object, and the loop reads the
    // owner token out of that request to decide whether the completion is
    // stale.  Freeing one with a completion outstanding does not merely risk a
    // stale dispatch: it makes the staleness check itself a read of freed
    // memory.  Stopping or removing an out-of-process runtime did exactly that,
    // and so did pointing --cluster at a second directory.
    //
    // The wait cannot go in either destructor.  Both frees happen inside a
    // command handler, which is itself inside a completion the loop is
    // dispatching, so a destructor that waited would have to re-enter the loop
    // and dispatch completions from there — including, possibly, the one for
    // the object it is in the middle of destroying.  Deferring instead is what
    // conn_transfer.h already does for a descriptor and for the same stated
    // reason: the answer arrives on a later turn than the question.  It is also
    // what runtime_manager already does for a stopped runtime_instance, whose
    // requests live in its storage for exactly the same reason.
    //
    // Held as io_handler because that is the whole of what this needs — it has
    // a virtual destructor, and every object that can land here is one.
    struct retired_handler
    {
        std::unique_ptr<io_handler> obj;
        // The identity it submitted under, captured before deregistration
        // because that is what clears the handler's own copy.  The loop is
        // asked about this, not about the pointer: an address can be reused by
        // the next object, a token cannot.
        uint32_t                    token;
    };
    std::vector<retired_handler> m_retired_handlers;

    // Free whichever of them the ring owes nothing.  Called from the health
    // timer, beside reap_orphan_workers(), because that is already the place
    // this daemon revisits what it could not finish earlier — and because the
    // tick is by construction a later turn of the loop than the command that
    // put them here, which is the whole property being waited on.
    void drain_retired_handlers();

    // Encode the manager's endpoint table and push it to every worker.
    void publish_endpoints_to_workers(const endpoint_table& tbl);

    // Encode the runtime map — what runtimes exist, in what state, on what port,
    // with how many connections — and push it to every worker, where it becomes
    // the replica socketley.list() and socketley.get() are answered from.
    //
    // Called on every membership change, beside the endpoint table and for the
    // same reason; on every stats frame, coalesced, for the counts; and on the
    // health tick as the backstop for both.
    void publish_runtime_map_to_workers();

    // Encode what the cluster looks like — this daemon's cluster name, the
    // address it advertises, and every remote daemon with its runtimes — and
    // push it to every worker, where it becomes the snapshot the four
    // socketley.cluster.* calls are answered from.  See shared/cluster_view.h.
    //
    // Pushed on the cluster's own scan cadence, which is the health tick's, and
    // again the moment discovery reports an event.  A daemon that is in no
    // cluster pushes nothing and those four calls stay refused out there, which
    // is the honest answer rather than an empty table.
    void publish_cluster_view_to_workers();

    // The two payloads, built without being sent.
    //
    // Split out because a supervisor has to be handed both BEFORE it forks: it
    // writes them ahead of the config frame, and the config frame is what loads
    // the child's script.  See the priming in reconcile_proxy_workers().
    //
    // build_cluster_view_payload() answers empty for a daemon that has never
    // been in a cluster — nothing to say and nothing to withdraw — and the
    // callers send no frame for that.
    std::string build_runtime_map_payload();
    std::string build_cluster_view_payload();

    // Whether a cluster view has ever gone out.  What makes "this daemon has
    // left its cluster" expressible at all: an empty view is the withdrawal,
    // and without this flag it would also be what every never-clustered daemon
    // sent to every worker it forked.
    bool m_cluster_view_pushed{false};

    // A worker has published its figures.  Pushes the map on, at most once per
    // stats interval however many children report inside one — the counts are
    // the one thing in the map that moves with no event behind it, and a stats
    // frame is the only clock in this daemon that ticks when they do.  See the
    // note above the definition for why it is coalesced rather than per frame.
    //
    // Takes the runtime the reporting child serves, because the first thing it
    // has to do is re-total that runtime's shards into its placeholder — and
    // that part is NOT coalesced.  The map push below it is a frame to every
    // other worker and is worth a floor; rewriting one placeholder from figures
    // already in hand is not, and skipping it would leave `stats` reading the
    // total from before this frame arrived for up to a full health tick, which
    // is the two-second staleness that arming the control socket removed.
    void on_worker_stats(const std::string& name);

    // When the last map push went out, for that floor.  Set by every push, so a
    // membership change resets the window instead of being followed a moment
    // later by a round carrying the same rows.
    std::chrono::steady_clock::time_point m_last_map_push{};

    // Encode one published message and push it to every worker, so a proxy's
    // subscribe callbacks fire in the process that is serving its traffic.
    void publish_to_workers(std::string_view cache_name, std::string_view channel,
                            std::string_view message);

    // Hand one message to the single worker holding a named runtime's
    // connections.  False when there is no such worker or its control socket
    // would not take the frame — the caller has to be able to say so.
    bool deliver_to_worker(std::string_view name, std::string_view message,
                           const proxy_supervisor* exclude = nullptr);

    // Add `name#index` for every shard of every sharded runtime to the request
    // channel's sink table, which the manager has just rebuilt.  Installed as
    // the manager's shard sink publisher; see shared/shard_target.h for why a
    // qualified name and not a second wire.
    void publish_shard_sinks(request_channel& ch);

    // Whether RLIMIT_NOFILE leaves room to mesh this many shards.  Says so in
    // the log when it refuses; see the definition.
    bool mesh_fits(size_t shards) const;

    // A `send` that came UP from a worker's script, addressed to a runtime that
    // worker cannot see.  Routed exactly as cmd_send() routes the same verb
    // typed at the CLI: to the connections in this process, or on to the one
    // worker that holds them.
    void on_worker_deliver(proxy_supervisor* from, std::string_view name,
                           std::string_view message);

    // A `send` addressed by conn_ref: one shard asking that a message reach a
    // connection a SIBLING is holding.  The ref names its own shard, so this
    // resolves to one supervisor and writes one frame.
    void on_worker_send_ref(proxy_supervisor* from, const conn_ref& ref,
                            std::string_view message);

    // A publish that came UP from a worker's cache, fanned out to everything
    // this daemon can reach — its own runtimes and every OTHER worker.  The
    // sender is excluded: it has already delivered to its own runtime.
    void on_worker_publish(proxy_supervisor* from, std::string_view cache_name,
                           std::string_view channel, std::string_view message);

    // Set only while a worker's publish is being fanned out; see above.
    proxy_supervisor* m_publish_origin{nullptr};
};
