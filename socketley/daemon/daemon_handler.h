#pragma once
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <list>
#include <memory>
#include <vector>
#include <chrono>
#include <sys/un.h>

#include "../shared/loop/event_loop_definitions.h"
#include "../shared/runtime/runtime_instance.h"
#include "../shared/ipc/shard_clients.h"
#include "../shared/ipc/route_relay.h"
#include "../shared/http/notifier.h"
#include "../shared/loop/file_io.h"
#include "../shared/loop/hash_pool.h"
#include "../cli/arg_parser.h"

class event_loop;
class runtime_manager;
class state_persistence;
class cluster_discovery;
class endpoint_table;
class proxy_supervisor;
class request_channel;
class cluster_reconciler;
struct cluster_event;

struct ipc_connection
{
    int fd;
    io_request read_req;
    io_request write_req;
    char read_buf[4096];

    // Scratch for the command being processed, never storage the ring reads
    // from, because append_response() copies it into out_buf and only that is
    // ever named by a write SQE.
    std::string write_buf;

    // The framed replies waiting to go out and the one buffer a write is
    // submitted from, untouched between a submission and its completion.
    std::string out_buf;
    size_t write_off = 0;

    // A write is in the ring naming out_buf, and while it is set no read is
    // armed, so nothing can arrive that would rebuild the buffer underneath
    // it.
    bool write_pending = false;

    std::string partial;

    bool interactive = false;
    std::string interactive_name;

    // Which connection this is, since a descriptor number is reused by the next one accepted.
    uint64_t serial = 0;
    // The least exit code a parked reply may answer with, for what the command said before it parked.
    int parked_floor = 0;
};

// What a command handler returns when its reply waits for a worker that is not forked yet.
inline constexpr int reply_parked = -1000;

// route_relay::sink is the second base because the daemon is the only process
// that can turn a runtime name into either an object it may call or a child's
// socket.
class daemon_handler : public io_handler, public route_relay::sink
{
public:
    daemon_handler(runtime_manager& manager, event_loop& loop);
    ~daemon_handler() override;

    // What is on socket_path.  "A daemon is already running" and "that socket
    // belongs to somebody else" used to be one boolean, and the caller exits 0
    // on it -- so `socketley daemon` against a foreign socket said nothing and
    // reported success, with no daemon of the caller's anywhere.
    enum class socket_state { free, ours, foreign };
    static socket_state probe_socket();
    bool setup();
    void teardown();
    void on_cqe(struct io_uring_cqe* cqe) override;

    void set_state_persistence(state_persistence* sp);
    void set_cluster_discovery(cluster_discovery* cd);
    // Both, because a configured port and a bound one are different answers
    // and `dashboard` was giving the first when it meant the second.
    void set_metrics_port(uint16_t port, bool bound);

    // The daemon's Raft node, when --raft-listen started one, for `cluster raft-status` and the cluster's runtimes,
    // which it then reconciles on every Raft tick.
    void set_raft(class raft_host* host);
    // Runs a command as the daemon itself, its words exactly as given and never split again, with its output in `out`.
    // This is how the cluster's reconciliation reaches create, start, stop and remove, and it returns once a worker
    // is forked rather than once it is serving.
    int run_internal(const std::vector<std::string>& words, std::string& out, bool cluster_owned);
    // The entrance `create dns` makes as the dns runtime's child (--proxy, --proxy-port), 0 or the exit code.
    int make_dns_entrance(class dns_instance* dns, bool start);
    std::vector<std::string> dns_entrance_children(std::string_view dns_name) const;
    // The stats text the worker of runtime `name` last published, empty until it has published; a cluster replica's report is read from it.
    std::string worker_detail(const std::string& name) const;
    // Sends the worker of runtime `name` a cluster replica's order; false when there is no worker to take it.
    bool send_replica_order(const std::string& name, std::string_view payload);
    // The file this daemon read its settings from, so `dashboard` can say
    // where to put the setting it is asking for.
    void set_config_path(std::string path);

    // The webhook the alerts go to and the mqtt runtime the daemon's events are published on, either empty for none,
    // their outbox under `state_dir` so what they had not taken goes after a restart; blocking, so it runs before the
    // loop, and false with `why`.
    bool open_notifications(const std::string& webhook, const std::string& mail, const std::string& events,
                            const std::string& state_dir,
                            std::string& why);
    // An alert's message for that webhook, and an event kept on the broker under `sub`, from any thread.
    void send_alert(std::string body);
    void send_event(std::string sub, std::string json);

    // Called once after restore and before the loop runs.  restore_runtimes()
    // puts a runtime in `running` and forks nothing, so the first child used
    // to wait for the health tick: every restored out-of-process runtime read
    // `Up` with no process behind it for up to two seconds after the daemon
    // said it had started, and a request in that window was refused.
    void start_restored_workers();

    // The identity a daemon configuration file asks for, applied at startup
    // because `daemon-name` and `daemon-cluster` both need a daemon that is
    // already serving, returning the reason on refusal and nothing on success.
    std::string apply_startup_identity(const std::string& name,
                                       const std::string& cluster_dir);

    static std::string socket_path;

    // Where every daemon writes the one file naming its socket, so a listing
    // can say how many are running rather than answer for one and not say
    // which -- empty when nothing registered this daemon.
    static std::string daemons_dir;

    // Whether the path above is the packaged deployment's socket rather than
    // one this daemon owns alone, read only by setup(), and false by default
    // because that is the safe answer.
    static bool system_socket;

private:
    using client_map = std::unordered_map<int, std::unique_ptr<ipc_connection>>;

    void handle_accept(struct io_uring_cqe* cqe);
    void handle_read(struct io_uring_cqe* cqe, io_request* req);
    void handle_write(struct io_uring_cqe* cqe, const io_request* req);
    void close_client(client_map::iterator it);
    void release_closing(const io_request* req);

    // Returns -1 when names resolved and the caller should continue, otherwise
    // the exit code, writing errors to stdout or to conn->write_buf.
    int check_empty_names(const std::vector<std::string>& names,
        const parsed_args& pa, const char* verb, ipc_connection* conn) const;

    int process_command(ipc_connection* conn, std::string& line);
    int process_parsed(ipc_connection* conn, const parsed_args& pa);

    // The switch, split out so process_command can read the exit code of the
    // handler it dispatched to instead of returning it straight through.
    int dispatch_command(ipc_connection* conn, const parsed_args& pa);

    int cmd_create(ipc_connection* conn, const parsed_args& pa);
    int cmd_start(ipc_connection* conn, const parsed_args& pa);
    int cmd_stop(ipc_connection* conn, const parsed_args& pa);
    int cmd_remove(ipc_connection* conn, const parsed_args& pa);
    int cmd_ls(ipc_connection* conn, const parsed_args& pa);
    int cmd_ps(ipc_connection* conn, const parsed_args& pa);
    int cmd_send(const parsed_args& pa);

    // Where a message addressed to a runtime name goes, shared by `send` at
    // the CLI and by a worker's socketley.send, with `exclude` naming the one
    // shard that has already delivered locally.
    bool deliver_to_runtime(std::string_view name, std::string_view message,
                            std::string& why,
                            const proxy_supervisor* exclude = nullptr);
    int cmd_edit(ipc_connection* conn, const parsed_args& pa, bool may_restart = true);
    int cmd_dump(ipc_connection* conn, const parsed_args& pa);
    // The whole configuration to every worker serving this runtime, so a change
    // reaches the process holding the port; see the definition.
    void push_config_to_workers(std::string_view name, runtime_instance* instance);

    // An operator's interactive session to the workers, so what a client says
    // reaches their terminal; and the same for a worker that has just been
    // forked under a session that is already open.
    void grant_interactive_to_workers(std::string_view name, int fd);

    int cmd_import(ipc_connection* conn, const parsed_args& pa, bool may_restart = true);
    // Stop the runtime, do `apply`, start it again -- one command, so a caller whose connection the runtime carries
    // cannot be cut off between the three. `name` is the runtime before `apply` runs; a rename inside it is followed.
    // `always_start` is restart's own meaning -- it ends with the runtime running, a stopped one included, as it did
    // when it was a stop and a start. A configuration command's --restart leaves a stopped runtime stopped: it was
    // asked to change a setting, not to bring something up that somebody had taken down.
    // `verb` is the command the caller gave, so a refusal names it.
    int across_restart(ipc_connection* conn, const char* verb, std::string_view name,
                       const std::function<int()>& apply, bool always_start, bool interactive = false);
    // restart <name>: the same with nothing to apply.
    int cmd_restart(ipc_connection* conn, const parsed_args& pa);
    int cmd_action(ipc_connection* conn, const parsed_args& pa);
    int cmd_idp_user(ipc_connection* conn, const parsed_args& pa);
    int cmd_db_backup(ipc_connection* conn, const parsed_args& pa);
    int cmd_db_restore(ipc_connection* conn, const parsed_args& pa);
    // One request to a runtime's worker and its answer, waited for here; false with the reason in conn's write_buf.
    bool ask_worker(ipc_connection* conn, std::string_view runtime, std::string_view payload, std::string& reply,
                    std::chrono::milliseconds bound = std::chrono::milliseconds(4000), size_t shard = 0);
    // mqtt-pub, mqtt-sessions, mqtt-kick, mqtt-retained and mqtt-tap, which ask a broker's shards.
    int cmd_mqtt(ipc_connection* conn, const parsed_args& pa);
    int cmd_mail(ipc_connection* conn, const parsed_args& pa);
    int cmd_stats(ipc_connection* conn, const parsed_args& pa);
    int cmd_reload(ipc_connection* conn, const parsed_args& pa);
    int cmd_reload_lua(ipc_connection* conn, const parsed_args& pa);
    int cmd_owner(ipc_connection* conn, const parsed_args& pa);
    int cmd_attach(ipc_connection* conn, const parsed_args& pa);
    int cmd_add(ipc_connection* conn, const parsed_args& pa);
    // Ends this daemon, answered before it goes so the caller learns it was
    // heard rather than seeing the socket close under the reply.
    int cmd_daemon_stop(ipc_connection* conn);
    // The daemon's own figures, not a runtime's: today the loopback shortcut,
    // whose bytes tcpdump and nftables on lo never see.
    int cmd_daemon_stats(ipc_connection* conn);
    int cmd_cluster_dir(ipc_connection* conn);
    int cmd_cluster_status(ipc_connection* conn);
    int cmd_raft_status(ipc_connection* conn);
    int cmd_cluster_create(ipc_connection* conn, const parsed_args& pa);
    int cmd_cluster_remove(ipc_connection* conn, const parsed_args& pa);
    int cmd_cluster_scale(ipc_connection* conn, const parsed_args& pa);
    int cmd_cluster_has(ipc_connection* conn, const parsed_args& pa);
    int cmd_cluster_placement(ipc_connection* conn);
    // What to say to an operator who names a cluster replica in a verb that would change it from underneath the
    // cluster, and drops it from `names`; the number dropped.
    size_t withhold_cluster_names(std::vector<std::string>& names, const char* verb, ipc_connection* conn) const;
    int cmd_daemon_name(ipc_connection* conn, const parsed_args& pa);
    int cmd_daemon_cluster(ipc_connection* conn, const parsed_args& pa);
    int cmd_dashboard(ipc_connection* conn);
    int cmd_settings(ipc_connection* conn, const parsed_args& pa);

    // The daemon saying which daemon it is, asked by every CLI command so that
    // "something accepted my connection" stops being read as "a daemon is
    // here".
    int cmd_ping(ipc_connection* conn);
    // Whether a runtime a command left starting is serving yet, without waiting: what the CLI asks while a worker
    // reads its files for longer than a command waits.
    int cmd_startup(ipc_connection* conn, const parsed_args& pa);

    // Bring cluster discovery up under NAME in DIR, leaving nothing running on
    // failure and m_cluster_error saying why in the operator's words.
    bool start_cluster(const std::string& name, const std::string& dir);
    void stop_cluster();

    // What the daemon says about clustering when it is off, for `socketley
    // cluster ...` afterwards, when the failing command's exit code is long
    // gone.
    std::string cluster_off_reason() const;

    std::vector<std::string> resolve_names(const parsed_args& pa, size_t start = 1);

    // ─── THE NAMES IN THE LIST THAT NAMED NOTHING ───────────────────────────
    // Filled by resolve_names and reported by process_command, which is the
    // only pair of places that sees both the list and the exit code -- seven
    // handlers resolve names and an eighth would forget to ask.  Empty unless
    // at least one name DID resolve: a list where nothing resolved is
    // check_empty_names' case and its message is unchanged.
    std::vector<std::string> m_unresolved;

    // Frame one command's reply and submit the single write that carries all
    // of them, split because a packet may hold several commands and only one
    // write may be outstanding.
    void append_response(ipc_connection* conn, int exit_code);
    bool send_response(ipc_connection* conn);

    runtime_manager& m_manager;
    event_loop& m_loop;

    // The alerts' webhook, posted to from this loop and retried until it answers, the file operations its outbox and
    // connections go through, and the way a message comes here from the thread that checks; only post_done() is used
    // of the pool, which starts no thread.
    socketley::file_io  m_fio;
    socketley::notifier m_alert_out;
    // Which of the alerts' ways open_notifications() opened: a webhook, a mail runtime.
    bool m_alert_hook{false};
    bool m_alert_mail{false};
    socketley::hash_pool m_alert_box{1};
    // Each runtime's state as last published on daemon.events, by name; empty and unused when none is set.
    bool m_events{false};
    std::unordered_map<std::string, std::string> m_event_states;
    void publish_runtime_events();

    int m_listen_fd;
    struct sockaddr_un m_accept_addr;
    socklen_t m_accept_addrlen;
    io_request m_accept_req;
    bool m_accept_armed{false};

    client_map m_clients;

    // Connections whose client hung up while their reply was still in the
    // ring, held until that write reports, and normally empty unless the reply
    // outgrew the socket buffer.
    std::vector<std::unique_ptr<ipc_connection>> m_closing;

    state_persistence* m_persistence = nullptr;
    cluster_discovery* m_cluster = nullptr;
    std::unique_ptr<cluster_discovery> m_owned_cluster;
    std::string m_daemon_name;
    uint16_t m_metrics_port{0};
    bool     m_metrics_bound{false};
    std::string m_config_path;

    // The last --cluster this daemon refused and why, so a node with
    // clustering off can say so rather than reporting the same as one never
    // asked to join.
    std::string m_cluster_error;
    class raft_host* m_raft = nullptr;
    std::unique_ptr<cluster_reconciler> m_reconciler;
    // Set while the daemon runs a command as itself, which is what lets the cluster act on the replicas it owns.
    bool m_cluster_internal = false;
    bool m_cluster_creating = false;
    std::string m_cluster_want_dir;

    // Health monitoring for managed runtimes, and the periodic reap of retired
    // runtime instances — see the op_timeout branch of on_cqe().
    io_request m_health_req{};
    struct __kernel_timespec m_health_ts{};
    bool m_health_pending{false};

    // teardown() has run, which only the health timer cares about, because
    // withdrawing it makes the completion that re-arms the chain arrive at
    // once.
    bool m_torn_down{false};

    void start_health_timer();
    void start_accept();
    void check_managed_health();

    // ── Out-of-process proxies ──────────────────────────────────────────────
    // The supervisors for one runtime, owned here because a supervisor
    // outlives a stop, and a vector rather than a pointer so that the compiler
    // names all 30 sites --shards affects instead of leaving a second
    // container for a new path to forget.
    using worker_shards = std::vector<std::unique_ptr<proxy_supervisor>>;
    std::unordered_map<std::string, worker_shards> m_proxy_workers;

    // One shared counter region per sharded runtime, held by the daemon
    // because it has to outlive any one shard: a replacement must map the
    // region its siblings already have.
    std::unordered_map<std::string, shard_stats::shard_table> m_shard_regions;

    // And which connections each shard is holding, a second region because the
    // counters are touched every loop turn and the list only when a connection
    // arrives or leaves.
    std::unordered_map<std::string, shard_clients::client_table> m_shard_client_regions;

    // What every shard of one runtime last reported, added up and written into
    // its placeholder, because a shard is not a runtime and the last frame to
    // arrive used to win.
    void aggregate_worker_stats(const std::string& name);

    // Bring the children into line with the runtime map, called from the
    // health timer and after any command that moves a state, because
    // reconciling cannot be forgotten at a seventh call site.
    void reconcile_proxy_workers();

    // Burst state for managed (`add`) runtimes, the counterpart of
    // proxy_supervisor's own.  Not the instance's m_restarts: that is the
    // lifetime count `stats` prints and a window must not reset it.
    struct managed_restart
    {
        unsigned                              count{0};
        std::chrono::steady_clock::time_point last{};
    };
    std::unordered_map<std::string, managed_restart> m_managed_restarts;

    // Wait for a just-started out-of-process runtime to say whether it can
    // serve its configuration, on one deadline shared across a multi-runtime
    // command -- and take a NAME across this call, never a pointer, because it
    // serves map requests inline and those can free runtimes.
    int await_worker_startup(std::string_view name, std::string& out,
                             std::chrono::steady_clock::time_point deadline);

    // ── A cache command, run where the cache is ─────────────────────────────
    // Every verb below `<name> <verb>` used to be a direct call on the
    // placeholder, which since every runtime moved into a worker is a store no
    // client can read.  This hands the same text a port client would send to
    // the worker and waits, like await_worker_startup and with the same
    // consequences for the loop.
    //
    // Shard zero and no key routing: a sharded cache forwards a key it does
    // not own, which is what a client landing on the wrong shard already
    // relies on.
    int run_cache_action(ipc_connection* conn, std::string_view name,
                         std::string_view action, std::string_view command);

    uint64_t m_direct_ticket_seq{0};

    // Why this runtime's on_start raised, wherever the script ran, taken
    // rather than peeked, so it must be called once per start after the wait
    // that guarantees the frame arrived.
    std::string on_start_error(std::string_view name);

    // Drain every worker's control socket so the figures are current, called
    // before the commands that print them.
    void poll_proxy_workers();

    // ── Children whose supervisor is gone ───────────────────────────────────
    // A worker signalled but not yet exited, taken over from the supervisor
    // being destroyed, because a catch-all SIGCHLD reaper would swallow a
    // managed runtime's exit status.
    struct orphan_worker
    {
        pid_t                                 pid;
        std::chrono::steady_clock::time_point signalled_at;
        bool                                  killed{false};
        // How long before SIGKILL: five seconds, or the dump's own bound for a
        // cache that writes one on its way out.
        std::chrono::seconds                  grace{5};
        // The runtime it served, whose next worker is not forked until this one has exited.
        std::string                           runtime;
    };
    std::vector<orphan_worker> m_orphan_workers;

    // waitpid(WNOHANG) over the list, and SIGKILL for anything still there a
    // few seconds after its SIGTERM.
    void reap_orphan_workers();

    // ── A runtime's next worker waits for its last one to exit ──────────────
    // A retired worker's pidfd, polled on the ring so its exit forks what was waiting for it; a list for stable addresses.
    struct exit_watch
    {
        io_request req;
        int        pidfd{-1};
    };
    std::list<exit_watch> m_exit_watches;
    void watch_exit(pid_t pid);
    void on_exit_watch(const io_request* req);

    // Whether a retired worker of `name` is still running, reaping the ones that are not.
    bool predecessor_running(const std::string& name);
    // Brokers and mail runtimes removed, whose files under the state directory go once their last worker has exited,
    // which writes them as it stops.
    std::map<std::string, runtime_type, std::less<>> m_forget_snapshots;
    void forget_settled_snapshots();

    // Runtimes wanted running whose fork the last reconcile held back for a predecessor.
    std::unordered_set<std::string> m_spawn_waiting;

    // A command's answer that waits for the workers of `names` to be forked, finished with `abandoned` false
    // once none is held back and with true when the daemon goes down first.
    struct deferred_start
    {
        std::vector<std::string>   names;
        std::function<void(bool)>  finish;
    };
    std::vector<deferred_start> m_deferred_starts;
    bool any_spawn_waiting(const std::vector<std::string>& names) const;
    void finish_deferred_starts(bool abandoned);

    // A CLI command's reply deferred until its starts can be waited for, resumed from where the packet left off.
    void park_reply(ipc_connection* conn, std::vector<std::string> names,
                    std::function<int(ipc_connection*)> verdict);
    uint64_t m_next_serial{0};

    // Runs the commands a connection's buffer holds, sending what they answered, unless one of them parks.
    void serve_commands(client_map::iterator it, bool queued);

    // Waits for each named runtime's worker and reads its on_start, writing what failed under `verb`; the count failed.
    int await_started(std::string& out, const std::vector<std::string>& names, std::string_view verb);

    // Handlers the ring has not finished with, because both embed an
    // io_request in their own storage and the loop's staleness check reads the
    // owner token out of it -- and neither destructor can wait, being itself
    // inside a completion being dispatched.
    struct retired_handler
    {
        std::unique_ptr<io_handler> obj;
        // The identity it submitted under, captured before deregistration,
        // because an address can be reused by the next object and a token
        // cannot.
        uint32_t                    token;
    };
    std::vector<retired_handler> m_retired_handlers;

    // Free whichever of them the ring owes nothing, from the health timer,
    // which is by construction a later turn of the loop than the command that
    // put them here.
    void drain_retired_handlers();

    // Encode the manager's endpoint table and push it to every worker.
    void publish_endpoints_to_workers(const endpoint_table& tbl);

    // Encode the runtime map and push it to every worker, where it becomes the
    // replica socketley.list() and socketley.get() answer from.
    void publish_runtime_map_to_workers();

    // Tell every worker whether its publishes have anywhere to go, which is
    // the whole of what dispatch_publish() reaches from here.
    void refresh_publish_interest();

    // Encode what the cluster looks like and push it to every worker, on the
    // cluster's own scan cadence, with a daemon in no cluster pushing nothing
    // so those four calls stay refused.
    void publish_cluster_view_to_workers();

    // The two payloads built without being sent, because a supervisor has to
    // be handed both before it forks and the config frame is what loads the
    // child's script.
    std::string build_runtime_map_payload();
    std::string build_cluster_view_payload();

    // Whether a cluster view has ever gone out, which is what makes an empty
    // view a withdrawal rather than what every never-clustered daemon sends.
    bool m_cluster_view_pushed{false};

    // A worker has published its figures, which re-totals that runtime's
    // shards into its placeholder at once and pushes the map on at most once
    // per stats interval.
    void on_worker_stats(const std::string& name);

    // Introduce two workers to each other: one socketpair, one end down each
    // one's grant channel, after which their crossings stop coming through
    // here.  Only for two runtimes of one worker apiece -- N shards on either
    // side would need N*M links, and their crossings already have the mesh.
    void link_peers(proxy_supervisor* from, const std::string& target);

    // When the last map push went out, set by every push, so a membership
    // change resets the window.
    std::chrono::steady_clock::time_point m_last_map_push{};

    // Encode one published message and push it to every worker, so a proxy's
    // subscribe callbacks fire in the process that is serving its traffic.
    void publish_to_workers(std::string_view cache_name, std::string_view channel,
                            std::string_view message);

    // Hand one message to the single worker holding a named runtime's
    // connections, false when there is none or its control socket would not
    // take the frame.
    bool deliver_to_worker(std::string_view name, std::string_view message,
                           const proxy_supervisor* exclude = nullptr);

    // Add `name#index` for every shard of every sharded runtime to the request
    // channel's sink table, which the manager has just rebuilt.
    void publish_shard_sinks(request_channel& ch);

    // Whether RLIMIT_NOFILE leaves room to mesh this many shards, saying so in
    // the log when it refuses.
    bool mesh_fits(size_t shards) const;

    // A `send` that came up from a worker's script, routed exactly as
    // cmd_send() routes the same verb typed at the CLI.
    void on_worker_deliver(proxy_supervisor* from, std::string_view name,
                           std::string_view message);

    // A `send` addressed by conn_ref, which names its own shard, so this
    // resolves to one supervisor and writes one frame.
    void on_worker_send_ref(proxy_supervisor* from, const conn_ref& ref,
                            std::string_view message);

    // A publish that came up from a worker's cache, fanned out to everything
    // this daemon can reach except the sender, which has already delivered to
    // its own runtime.
    void on_worker_publish(proxy_supervisor* from, std::string_view cache_name,
                           std::string_view channel, std::string_view message);

    // Set only while a worker's publish is being fanned out; see above.
    proxy_supervisor* m_publish_origin{nullptr};

    // The four map calls are queued rather than served where they arrive,
    // because they arrive on a supervisor's own completion and three of them
    // can destroy that supervisor, freeing the io_request the loop is holding.
    struct pending_map_request
    {
        uint64_t    ticket{0};

        // A dup of the supervisor's map socket, owned from here, which is what
        // makes the deferral safe when the supervisor is gone by the time this
        // is answered.
        int         reply_fd{-1};

        std::string op;
        std::string name;
        std::string config;
    };

    std::vector<pending_map_request> m_map_queue;
    io_request                       m_map_defer_req{};
    bool                             m_map_defer_armed{false};

    // Above zero while this daemon is blocked waiting on a worker, during
    // which map requests are served where they arrive -- safe because
    // reconcile_proxy_workers() retires a supervisor rather than destroying
    // one -- and a counter because these nest.
    int                              m_worker_wait_depth{0};

    // Raises the count for a scope.  Nothing else may set it.
    struct worker_wait_scope
    {
        int& d;
        explicit worker_wait_scope(int& depth) : d(depth) { ++d; }
        ~worker_wait_scope() { --d; }
        worker_wait_scope(const worker_wait_scope&)            = delete;
        worker_wait_scope& operator=(const worker_wait_scope&) = delete;
    };

    // Take one in, answering immediately only when the loop will not come
    // back, so a worker waiting on the answer does not sit until its own
    // deadline.
    void queue_map_request(uint64_t ticket, int reply_fd, std::string op,
                           std::string name, std::string config);

    // ── route_relay::sink ──────────────────────────────────────────────────
    //
    // Public through the base, private as a name: nothing calls these except
    // the manager, which was handed the base pointer.
public:
    void post(std::string_view to, std::string_view frm,
              worker_proto::route_op op, const conn_ref& ref,
              std::string_view payload) override;
    bool open(std::string_view target, const conn_ref& ref,
              std::string_view origin, std::string& err) override;
    void forget(std::string_view gone) override;

private:
    // One resolution for both directions, because post() and on_worker_route()
    // ask the identical question and two copies of the answer would disagree
    // about which shard a routed connection lands on.
    void route_dispatch(std::string_view to, std::string_view frm,
                        worker_proto::route_op op, const conn_ref& ref,
                        std::string_view payload);
    // The map's verdict on `target` alone, which is what a worker asks before
    // sending the open itself.
    bool admit(std::string_view target, std::string& err);
    void on_worker_route(proxy_supervisor* from, std::string_view to,
                         std::string_view frm, worker_proto::route_op op,
                         const conn_ref& ref, std::string_view payload);

    // Serve everything queued, answer each one and close each descriptor,
    // called from the nop's completion so nothing on the stack belongs to a
    // supervisor.
    void serve_map_requests();

    // One of the four against this daemon's map, with `err` filled in as the
    // text the script is handed, and `parked` set when a start's answer waits
    // for its worker's predecessor to exit.
    bool serve_map_request(const std::string& op, const std::string& name,
                           const std::string& config, std::string& err, bool& parked);

    // A started runtime's verdict as a map call reports it: its worker up and its on_start clean.
    bool map_started(const std::string& name, std::string& err);
};
