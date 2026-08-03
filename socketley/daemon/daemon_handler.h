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
#include "../cli/arg_parser.h"

class event_loop;
class runtime_manager;
class state_persistence;
class cluster_discovery;
class endpoint_table;
class proxy_supervisor;
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
    // One supervisor per runtime that runs in a worker, keyed by runtime
    // name.  Owned here rather than by the instance because the supervisor
    // outlives a stop: `stop` takes the child down but the runtime stays in the
    // map, and `start` must bring a new one up against the same record.
    std::unordered_map<std::string, std::unique_ptr<proxy_supervisor>> m_proxy_workers;

    // Bring the children into line with what the runtime map says.  Called from
    // the health timer and straight after any command that moves a runtime's
    // state, so the CLI never has to wait a tick to see the effect.
    //
    // Reconciling beats intercepting: a runtime's state is moved from `create
    // --start`, `start`, `stop`, `remove`, `reload`, an ownership cascade and
    // the boot-time restore, and a rule applied in one place cannot be
    // forgotten at the seventh call site.
    void reconcile_proxy_workers();

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

    // Encode the manager's endpoint table and push it to every worker.
    void publish_endpoints_to_workers(const endpoint_table& tbl);

    // Encode one published message and push it to every worker, so a proxy's
    // subscribe callbacks fire in the process that is serving its traffic.
    void publish_to_workers(std::string_view cache_name, std::string_view channel,
                            std::string_view message);

    // A publish that came UP from a worker's cache, fanned out to everything
    // this daemon can reach — its own runtimes and every OTHER worker.  The
    // sender is excluded: it has already delivered to its own runtime.
    void on_worker_publish(proxy_supervisor* from, std::string_view cache_name,
                           std::string_view channel, std::string_view message);

    // Set only while a worker's publish is being fanned out; see above.
    proxy_supervisor* m_publish_origin{nullptr};
};
