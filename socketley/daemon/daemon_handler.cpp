#include "daemon_handler.h"
#include "flag_handlers.h"
#include "../shared/event_loop.h"
#include "../shared/runtime_manager.h"
#include "../shared/runtime_definitions.h"
#include "../shared/time_format.h"
#include "../shared/state_persistence.h"
#include "../cli/runtime_type_parser.h"
#include "../cli/command_hashing.h"
#include "../runtime/cache/cache_instance.h"
#include "../runtime/server/server_instance.h"
#include "../runtime/client/client_instance.h"
#include "../runtime/proxy/proxy_instance.h"
#include "../shared/cluster_discovery.h"
#include "../shared/daemon_client.h"
#include "../cli/cli.h"
#include "../shared/tls_context.h"
#include "../shared/endpoint_table.h"
#include "../shared/worker_protocol.h"
#include "../shared/ipc_framing.h"
#include "../shared/lua_context.h"
#include "proxy_supervisor.h"

#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <charconv>
#include <chrono>
#include <optional>
#include <grp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "../shared/name_resolver.h"
#include <iomanip>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <sys/wait.h>
#include <csignal>
#include "../shared/logging.h"

// ─── How long a command will wait for a worker to answer ────────────────────
//
// Measured on this machine: a worker that has to compile a script, build its
// ring and bind its listener reports back 17-22 ms after `create` has forked it,
// over ten runs.  A refusal comes back sooner, because the child stops at the
// script and exits rather than going on to bind anything.
//
// Two seconds is therefore about a hundred times the cost of the case it is
// timing, which is the point: it is not a budget the normal path spends, it is
// the backstop for a worker that has wedged and will never answer.  The wait
// ends on the answer, so what a create actually costs is the 20 ms, and the
// bound is only ever reached when something is already wrong.
//
// Two seconds rather than a new number of its own because it is the interval
// this daemon already uses for the health tick -- the longest anything here
// waits to notice a worker. One timescale in the file is easier to reason about
// than two, and a wait that outlived the tick meant to supersede it would be the
// confusing combination.
//
// Four commands wait on this: `create`, for the verdict on a configuration;
// `reload-lua`, for the declaration a re-read script produces; and `start` and
// `reload`, which fork exactly the same child `create -s` does and used to
// return the moment they had asked for the fork.  All four are the control
// path, and all four would otherwise report success for something the worker
// had not done yet.
//
// It is one budget per COMMAND, not per runtime.  Each of those commands forks
// every child it is going to fork before it waits for any of them, so the
// children come up concurrently and the waits overlap: `start` of twenty pays
// about one child's startup.  Spending the bound per name instead would let a
// single wedged worker multiply it by the number of names on the command line,
// which is how a two-second backstop becomes a minute.
namespace
{
constexpr auto worker_startup_bound = std::chrono::milliseconds(2000);
}

std::string daemon_handler::socket_path = "/tmp/socketley.sock";
bool        daemon_handler::system_socket = false;

// Why this runtime's TLS configuration cannot be honoured, or an empty string
// if it can.
//
// The parse gate in flag_handlers.cpp stops the unsupported options being set
// by `create`, but an instance can also be configured from a state file written
// before that gate existed, so the check is repeated wherever a runtime is
// about to go live.  Without it a state file from an older daemon still brings
// up a listener that answers cleartext on a port `inspect` describes as
// encrypted.
//
// A server and a cache terminate TLS on their own listener, a client on its
// outbound socket and a proxy on both of its legs, so a complete configuration
// for any of them passes.  What is refused is a configuration that would leave
// part of the traffic in the clear — a cache replicating out of a TLS port
// being the one that is not simply a half-typed flag set.  See tls_context.h.
static std::string instance_tls_refusal(const runtime_instance* inst)
{
    if (!inst)
        return {};

    std::string_view mesh_ca, mesh_cert, mesh_key;
    inst->get_mesh_tls_paths(mesh_ca, mesh_cert, mesh_key);

    return tls_config_refusal(inst->get_type(),
                              inst->get_tls(), inst->is_udp(), inst->get_cert_path(),
                              inst->get_key_path(), inst->get_ca_path(),
                              mesh_ca, mesh_cert, mesh_key,
                              inst->get_replication_target());
}

// Why this runtime's shard count cannot be honoured, or an empty string if it
// can.  The instance's own answer to shards_config_refusal — see
// runtime_definitions.h for the rule and why it lives there rather than here.
//
// `lua_override` is for the one caller that cannot ask the instance: `create`
// defers --lua to after every flag has been read, so at the point the set is
// checked the script is still a local string and get_lua_script_path() is
// empty.  Passing it explicitly is what makes `--shards 4 --lua x` and
// `--lua x --shards 4` the same command.  Every other caller passes nullopt and
// gets the instance's own.
static std::string instance_shards_refusal(const runtime_instance* inst,
                                           std::optional<bool> lua_override = std::nullopt)
{
    if (!inst)
        return {};

    return shards_config_refusal(inst->get_type(),
                                 inst->get_shards(),
                                 lua_override.value_or(
                                     !inst->get_lua_script_path().empty()),
                                 inst->get_listen_path(),
                                 inst->is_out_of_process());
}

// ─── MAY THIS CALLER HAND THE DAEMON THIS PID ───────────────────────────────
//
// `attach --pid` is how an embedded process registers a runtime it is serving
// itself, and it is meant to be its own: the SDK example passes getpid().  The
// daemon remembers it and sends it SIGTERM when the runtime is stopped, which
// is the feature — `socketley stop app_cache` stops the process behind it.
//
// Nothing checked whose pid it was.  Measured on the parent commit, against a
// process the daemon had nothing to do with:
//
//     $ sleep 300 &                       # pid 1328283
//     $ socketley attach server bystander 18790 --pid 1328283
//     $ socketley stop bystander
//     [2]+  Terminated              sleep 300
//
// On a single-user daemon that is not a boundary — whoever may open the socket
// could signal the process themselves.  On the packaged one it is: the socket
// is 0660 socketley:socketley precisely so operators can reach a daemon that
// runs as its own user (as root, in the container image), and any member of
// that group could make it signal anything that uid can signal.  That is the
// one line the whole threat model rests on; see setup() below.
//
// So the pid has to belong to the caller.  SO_PEERCRED gives the uid on the
// other end of this connection — the kernel's answer, not the client's — and
// /proc/<pid> is owned by the uid running that process.  Equal, and the caller
// could have signalled it without the daemon's help; different, and the daemon
// would be lending out a privilege it was never asked to lend.
//
// Deliberately NOT a check that the pid is the peer itself.  Both documented
// spellings are legitimate and neither is the peer: the SDK's own connection
// carries the process's pid, and a shell that starts a program and attaches it
// with `--pid $!` names a sibling of the CLI, not the CLI.  Ownership is the
// property that separates those from the escalation.
//
// A root peer passes everything, because root can signal everything anyway and
// refusing would only break the container image's own arrangement.
//
// Returns an empty string when the pid may be used.
static std::string attach_pid_refusal(int conn_fd, pid_t pid)
{
    if (pid <= 0)
        return {};

    struct ucred cred{};
    socklen_t    len = sizeof(cred);
    if (conn_fd < 0 ||
        ::getsockopt(conn_fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
    {
        // No credentials means no way to judge, and this runs on the path that
        // decides who may be signalled.  Refusing is the answer that cannot be
        // wrong in the direction that matters.
        return "could not establish who is asking, so --pid was not accepted\n";
    }

    if (cred.uid == 0)
        return {};

    struct stat st{};
    const std::string proc = "/proc/" + std::to_string(static_cast<long long>(pid));
    if (::stat(proc.c_str(), &st) < 0)
        return "no process " + std::to_string(static_cast<long long>(pid)) +
               " to attach to\n";

    if (st.st_uid != cred.uid)
        return "process " + std::to_string(static_cast<long long>(pid)) +
               " belongs to another user, so --pid was refused\n"
               "  The daemon signals this pid when the runtime is stopped, and "
               "it will not do that\n"
               "  on behalf of a caller who could not signal it themselves.\n";

    return {};
}

// Why this runtime's --cpus / --sqpoll request cannot be honoured, or an empty
// string if it can.
//
// The reasoning and the text live on runtime_instance, next to the request they
// are about, because `create` is no longer the only place that asks: the
// request is persisted now, and the daemon's restore path meets it again on a
// ring that was created before the state file was read.  See
// runtime_instance::ring_policy_refusal.
static std::string instance_ring_refusal(const runtime_instance* inst,
                                         const event_loop& loop)
{
    if (!inst)
        return {};
    return inst->ring_policy_refusal(loop);
}

// Everything `create` prints, delivered to the client that typed it.
//
// cmd_create and every flag parser it calls report their refusals on std::cout,
// which is the daemon's stdout — /dev/null in any daemon a user actually starts.
// So a mistyped flag, a port that will not parse, a TLS set with a key and no
// certificate, an impossible CPU set: all of them answered exit code 1 and not
// one word about why.  The command's own reply channel is conn->write_buf, and
// nothing was putting them there.
//
// Rewriting seventeen hundred lines of parser to take a connection would be the
// thorough fix.  This is the one that reaches every one of them at once and
// leaves them printing the way they read: cout is borrowed for the length of the
// command and given back.  Safe on this thread because it is the only one that
// writes cout — the metrics endpoint has its own thread and logs to stderr —
// and the swap is undone by the destructor whatever the command does.
namespace
{

class cout_to_reply
{
public:
    explicit cout_to_reply(ipc_connection* conn)
        : m_conn(conn), m_saved(std::cout.rdbuf(m_buf.rdbuf())) {}

    ~cout_to_reply()
    {
        std::cout.rdbuf(m_saved);
        std::string text = m_buf.str();
        if (text.empty())
            return;
        // No connection means the command came from somewhere with no reply
        // channel — the boot-time restore, a Lua call.  Those keep the old
        // behaviour rather than losing the text entirely.
        if (m_conn) m_conn->write_buf += text;
        else        std::cout << text;
    }

    cout_to_reply(const cout_to_reply&) = delete;
    cout_to_reply& operator=(const cout_to_reply&) = delete;

private:
    ipc_connection*   m_conn;
    std::ostringstream m_buf;
    std::streambuf*   m_saved;
};

// The STATUS column for a listing that can carry a runtime in any state.
//
// A running runtime shows how long it has been up.  Every other state shows the
// state's name instead, because "how long has it been up" has no answer for a
// runtime that never came up — and printing an uptime for one is how a listing
// makes a failed runtime look healthy.
std::string state_column(const runtime_instance* inst)
{
    switch (inst->get_state())
    {
        case runtime_created: return "Created";
        case runtime_running: return format_uptime(inst->get_start_time());
        case runtime_stopped: return "Stopped";
        case runtime_failed:  return "Failed";
        default:              return "Unknown";
    }
}

// The same thing for the machine-readable form.
const char* state_json(runtime_state s)
{
    switch (s)
    {
        case runtime_created: return "created";
        case runtime_running: return "running";
        case runtime_stopped: return "stopped";
        case runtime_failed:  return "failed";
        default:              return "unknown";
    }
}

}   // namespace

daemon_handler::daemon_handler(runtime_manager& manager, event_loop& loop)
    : m_manager(manager), m_loop(loop), m_listen_fd(-1)
{
    std::memset(&m_accept_addr, 0, sizeof(m_accept_addr));
    m_accept_addrlen = sizeof(m_accept_addr);
    m_accept_req = { this, nullptr, -1, 0, op_accept };

    // Every republished table also goes to the workers.  Registered here rather
    // than in setup() because the manager can publish before the listener is
    // up — the boot-time restore does exactly that.
    // And the map itself, on the same trigger.
    //
    // Two tables, one moment: the endpoint table says where a runtime can be
    // reached and the map says what runtimes there are, and both are stale the
    // instant a runtime is created, started, stopped, removed or renamed.
    // publish_endpoints() is called at every one of those already — that is the
    // whole reason it is a republish rather than an update — so the map rides it
    // instead of growing a second list of call sites for the next one to be
    // forgotten from.  The periodic push in check_managed_health() is the other
    // half: it carries the connection counts, which move with no event at all.
    m_manager.set_endpoint_sink([this](const endpoint_table& tbl)
                                {
                                    publish_endpoints_to_workers(tbl);
                                    publish_runtime_map_to_workers();
                                });

    // And every published message, for the same reason: a worker's subscribers
    // are not reachable by calling into an instance, so the manager hands them
    // over here instead of walking a map it cannot find them in.
    m_manager.set_publish_sink([this](std::string_view cache_name,
                                      std::string_view channel,
                                      std::string_view message)
                               { publish_to_workers(cache_name, channel, message); });

    // And a message addressed to one named runtime whose connections are in a
    // worker.  cmd_send() reaches the supervisor by hand because it has
    // m_proxy_workers in scope; socketley.send() has only the manager, so the
    // manager gets the same route the other two have.
    m_manager.set_deliver_sink([this](std::string_view name,
                                      std::string_view message)
                               { return deliver_to_worker(name, message); });

    // And the moment before a runtime leaves the map, for whoever is holding a
    // pointer into it.  This is the reconcile cmd_remove() runs by hand, given
    // to the manager so that a caller which has only the manager — a Lua
    // script — cannot free a placeholder out from under its supervisor.
    m_manager.set_worker_release_sink([this] { reconcile_proxy_workers(); });
}

daemon_handler::~daemon_handler()
{
    teardown();
}

void daemon_handler::set_state_persistence(state_persistence* sp)
{
    m_persistence = sp;
}

void daemon_handler::set_cluster_discovery(cluster_discovery* cd)
{
    m_cluster = cd;
}

bool daemon_handler::is_running()
{
    int probe = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (probe < 0)
        return false;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);
    bool alive = connect(probe, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0;

    // EACCES/EPERM counts as running.  The socket is there and this uid may not
    // open it, which since the mode was tightened is what another user's daemon
    // looks like — and the caller's next move on `false` is setup(), which
    // opens with unlink(socket_path).  On /tmp the sticky bit refuses that, but
    // SOCKETLEY_SOCKET can name a directory with no sticky bit, and there the
    // unlink succeeds: a second user starting a daemon would take the path away
    // from the daemon that owns it, leaving that daemon serving a socket with
    // no name and every CLI command going to the new one.  Refusing to start is
    // the same answer as for a daemon we could talk to, and the right one.
    if (!alive)
    {
        const int err = errno;
        alive = (err == EACCES || err == EPERM);
    }

    // Raw close on purpose: this is a static probe with no event loop anywhere
    // in reach, so no SQE can ever have named this number and there is nothing
    // for close_fd() to hold it against.
    close(probe);
    return alive;
}

bool daemon_handler::setup()
{
    unlink(socket_path.c_str());

    // SOCK_CLOEXEC: this is the socket every CLI command arrives on, and the
    // daemon forks and execs a worker for every runtime that does not ask for
    // --daemon-process.  Without the flag the worker inherits it — measured, as
    // fd 5 of a live worker, an SO_ACCEPTCON row on the daemon's own path — and
    // then answers the question "is a daemon serving this socket" in the
    // affirmative for as long as it lives.  The test suite asks exactly that
    // question, by inode, to decide whether a daemon is up; a worker that
    // outlives a killed daemon made it say yes with no daemon in existence.
    m_listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (m_listen_fd < 0)
        return false;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

    // ─── WHO MAY OPEN THE CONTROL PLANE ─────────────────────────────────────
    //
    // This was `chmod(socket_path, 0666)` — "Allow all users to connect".  It
    // did exactly that, and connecting is not a small thing to grant: every
    // command the CLI can send arrives here.  Any local uid could stop a
    // runtime, read `stats`, rewrite a runtime's configuration, and — because
    // `create --lua` takes a script and a handler runs with the daemon's
    // privileges, which is a property of the design and not a defect (see the
    // sandbox note in lua_context.cpp) — run code as the daemon's user.
    //
    // Measured on the parent commit, dev mode, daemon owned by uid 1000:
    //
    //     socket mode                                srw-rw-rw-  (0666)
    //     uid nobody: connect + "ping"               answered
    //     uid nobody: create --lua + start           accepted
    //     the handler's io.popen("id -un") wrote     the daemon's user
    //     the file it created was owned by           the daemon's user
    //
    // That is privilege escalation with Lua as one route to it and the rest of
    // the command set as the others, so the fix is here rather than in the
    // interpreter.
    //
    // THE RULE.  A daemon serving the packaged path shares its socket with its
    // own group and nobody else; every other daemon keeps its socket to itself.
    //
    //     /run/socketley/socketley.sock   0660  socketley:socketley
    //     anything else                   0600  <the user who started it>
    //
    // Both halves matter.  0600 everywhere would break the packaged deployment,
    // where the daemon runs as `socketley` and the operator does not; 0660
    // everywhere would be a hole on any distribution that gives its users a
    // shared primary group — `users`, which several do — since there the
    // daemon's group is every human on the machine.  system_socket is the only
    // thing that distinguishes the two, and it defaults to false.
    //
    // The unprivileged single-user case, which is the ordinary one, is
    // unaffected: the socket belongs to the uid that started the daemon and
    // that uid is the one running the CLI.
    //
    // WHERE THE MODE IS SET, AND WHY THERE IS NO WINDOW.  bind() creates the
    // file with 0777 & ~umask — commonly 0755 — and the mode is not corrected
    // until a few lines below it.  That gap is not reachable: an AF_UNIX
    // stream socket that has been bound but not yet listen()ed refuses every
    // connect() with ECONNREFUSED, and the listen() below is the first moment
    // a connect() to this path can succeed.  Both chmods are above it, so the
    // socket is never both connectable and open, in either order.  The widening
    // pair is ordered the same way — chown to the group first, chmod second —
    // so the group bits are never granted to a group that has not been set.
    //
    // Setting a umask around the bind instead would also work and was tried;
    // it was dropped because umask is process-wide and state_persistence has
    // already started its writer thread by the time setup() runs, so the
    // narrow window would silently apply to whatever that thread happened to
    // create.  A property of the socket should not be paid for by every other
    // file in the process.
    if (bind(m_listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        // Raw close on purpose: the first submission this descriptor can ever
        // appear in is the accept at the bottom of this function, and the
        // failure paths do not reach it.  The number provably never entered the
        // ring, so there is nothing to hold it for.
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    // 0600 first and unconditionally, so the packaged branch below only ever
    // widens from a closed door and every other path is done in one line.
    //
    // Fatal when it fails, which is the one place in this function where an
    // errno is worth refusing to start over.  Everything that reaches this
    // socket is a command, so a daemon that could not put a mode on it would
    // be serving its control plane at whatever the umask left — 0755 under the
    // usual one, which already refuses another uid's connect(), but 0777 for a
    // daemon started from a shell with `umask 0`.  "Started, and might be open
    // to the machine" is not a state to have; not starting says so plainly and
    // costs nothing that cannot be retried.
    if (::chmod(socket_path.c_str(), 0600) < 0)
    {
        LOG_ERROR("ipc socket: could not set its mode, so it may be reachable "
                  "by other users; refusing to serve it");
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    if (system_socket)
    {
        // The group by name, not by whatever this process happens to have.  The
        // unit runs the daemon as socketley:socketley and the two agree, but
        // `sudo socketley daemon` on the same installation runs it as root:root
        // and 0660 there would hand the socket to group root instead of to the
        // operators who were added to `socketley` — an installation that works
        // under systemd and not by hand.  Failure here is not fatal, unlike the
        // 0600 above: a chown that is refused, or an installation with no such
        // group, leaves the socket at the 0600 it already has — a working
        // daemon with a narrower door rather than a broken one, and never a
        // wider one.
        if (struct group* gr = ::getgrnam("socketley"); gr != nullptr)
        {
            if (::chown(socket_path.c_str(), static_cast<uid_t>(-1), gr->gr_gid) < 0)
                LOG_WARN("ipc socket: could not give it to group socketley; "
                         "it stays owner-only");
            else if (::chmod(socket_path.c_str(), 0660) < 0)
                LOG_WARN("ipc socket: could not widen it to the group; "
                         "it stays owner-only");
        }
        else if (::geteuid() != 0)
        {
            // Only worth saying when the daemon is a dedicated user, which is
            // the packaged case: there, no group means no operator can reach
            // it and someone needs to know before they go looking.  A daemon
            // running as root with no such group is the container image's
            // arrangement — root administers it and root opens anything — and
            // a warning there is noise on every start.
            LOG_WARN("ipc socket: no `socketley` group on this system, so the "
                     "socket stays owner-only — members of that group are how "
                     "an operator reaches the packaged daemon");
        }
    }

    if (listen(m_listen_fd, 16) < 0)
    {
        // Raw close, same reason as the bind failure above: still no submission.
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    m_torn_down = false;

    // The one submission the daemon cannot do without: refused here there is no
    // way to reach it at all, so this is a failed setup rather than a daemon
    // that comes up and answers nothing.
    start_accept();
    if (!m_accept_armed)
    {
        // Raw close, same reason as the two failures above: the accept is the
        // only submission this number appears in and it did not reach the ring.
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    start_health_timer();

    return true;
}

// Arm the accept that every CLI connection arrives through.
//
// Nothing re-arms this but its own completion, so a submission that never
// reached the ring leaves the daemon deaf — running, holding its runtimes, and
// answering no command until it is restarted.  The flag lets the health tick
// pick the chain back up, the same shape as start_health_timer().
void daemon_handler::start_accept()
{
    m_accept_addrlen = sizeof(m_accept_addr);
    m_accept_armed = m_loop.submit_accept(m_listen_fd,
        reinterpret_cast<struct sockaddr_in*>(&m_accept_addr),
        &m_accept_addrlen, &m_accept_req);

    if (!m_accept_armed)
        LOG_ERROR("daemon accept refused: no new CLI connection can be served "
                  "until it is re-armed");
}

void daemon_handler::teardown()
{
    // The workers first.  Each is asked to shut down over its control socket
    // and then signalled, so a child stops its proxy while it still has a ring
    // of its own to cancel into.  Left to the destructor these would be orphans
    // reparented to init, still bound to their ports, and the next daemon would
    // fail to bind.
    // Every shard of every runtime, and not one per name: a runtime with four
    // workers has four members of the REUSEPORT group to give back, and three
    // left bound is what the next daemon fails to bind against.
    for (auto& [_, shards] : m_proxy_workers)
    for (auto& sup : shards)
    {
        sup->shutdown();
        if (const pid_t p = sup->release_pid(); p > 0)
            m_orphan_workers.push_back({p, std::chrono::steady_clock::now(), false});

        // Retired here too, so that "a supervisor is never destroyed while
        // something still holds it" holds on both paths that destroy one rather
        // than on the one that happened to be reported.  The clear() below is
        // safe in the daemon for a different reason — daemon_start() shuts the
        // ring down before this runs, so no completion can be dispatched
        // afterwards — but this is also the destructor's path, and that reason
        // belongs to the caller, not to this function.  There is nothing to
        // wait for afterwards and nothing left to wait with, so the token is
        // dropped.
        if (sup->retire() != 0) {}
    }
    m_proxy_workers.clear();

    // ─── Wait for the children that were just told to go ────────────────────
    //
    // This did not wait, and until the workers acquired PR_SET_PDEATHSIG it did
    // not have to: a signalled worker unwound as an orphan after this process
    // was gone, which was untidy but harmless.  It is no longer harmless.  The
    // parent-death signal is SIGKILL — see the note above claim_current_daemon()
    // for why it cannot be anything softer — so exiting while a worker is still
    // unwinding turns the graceful shutdown into a kill, and on_stop stops
    // running for out-of-process runtimes whenever the daemon itself goes down.
    //
    // A worker unwinds in single-digit milliseconds: cancel the ring, close the
    // connections, run on_stop.  So this costs nothing in the normal case and
    // is bounded for the case that is not normal.  The bound is deliberately
    // shorter than reap_orphan_workers()' own five-second escalation, because
    // that escalation is what handles a worker that will not leave and this is
    // only here to let the ordinary one finish.
    {
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(1500);
        while (std::chrono::steady_clock::now() < deadline)
        {
            bool any_left = false;
            for (auto& o : m_orphan_workers)
                if (o.pid > 0 && ::waitpid(o.pid, nullptr, WNOHANG) == 0)
                    any_left = true;
            if (!any_left)
                break;
            ::usleep(2000);
        }
    }

    // The children are on their way out and this process is too, so init would
    // adopt whatever is left.  Reaped here anyway for the case teardown() does
    // not end in exit(): a daemon that is torn down and set up again would
    // otherwise carry the previous generation's zombies for the rest of its life.
    reap_orphan_workers();

    // Nothing may call the sink once the workers are gone: it would encode a
    // table for an empty map, which is harmless, but the manager outlives this
    // handler and the lambda captures `this`.
    m_manager.set_endpoint_sink(nullptr);
    m_manager.set_publish_sink(nullptr);
    m_manager.set_deliver_sink(nullptr);
    m_manager.set_worker_release_sink(nullptr);

    // Reap managed children
    {
        std::shared_lock lock(m_manager.mutex);
        for (auto& [name, inst] : m_manager.list())
        {
            if (inst->is_managed() && inst->get_pid() > 0)
                waitpid(inst->get_pid(), nullptr, WNOHANG);
        }
    }

    // The health timer, which nothing below reaches.  A timeout hangs off no
    // descriptor, so the close_fd() calls further down and the cancels they
    // submit walk straight past it and the loop goes on owing this handler a
    // completion for up to two seconds.  Every runtime teardown withdraws its
    // own timers for exactly that reason; this is the daemon's own, and it was
    // the last one left counting down.
    //
    // On the daemon's path this is a formality and known to be one, like the
    // closes below: daemon.cpp ends the ring before it gets here, so the
    // submission is refused and the timer died with the ring.  It is written
    // for the destructor's path, which does not get to assume that ordering.
    //
    // What it does not buy is worth saying: a withdrawn timeout still reports
    // once more, with -ECANCELED, carrying this same request.  Tearing a
    // handler down under a live ring therefore still needs the handler to
    // outlive that completion — this only makes it arrive now rather than two
    // seconds from now.
    //
    // Once per teardown, not once per call: daemon.cpp tears down explicitly and
    // the destructor does it again, and the second withdrawal would name a
    // request the first one already took back.
    if (m_health_pending && !m_torn_down)
    {
        // The answer is ignored on purpose, and this is the one place that is
        // right: false means either the ring is already gone — the daemon's own
        // path, where the timer went with it — or the submission was refused,
        // and all that is left to do about the second is let the timer fire,
        // which is what happened before this call existed.
        if (!m_loop.submit_timeout_remove(&m_health_req)) {}

        // m_health_pending stays set.  The withdrawn timeout is still owed
        // exactly one completion carrying this request, and clearing the flag
        // would let a later start_health_timer() hand the kernel a request it
        // is already carrying one for.  on_cqe() clears it when that completion
        // lands, and m_torn_down is what stops it starting the chain again.
    }
    m_torn_down = true;

    // Stop cluster discovery before closing IPC.  This is the graceful path the
    // man page's stale-detection table calls "file deleted, peers drop it at
    // once", so it has to reach unpublish().
    stop_cluster();

    // After stop_cluster(), because that is the last thing that can add to it.
    // Everything here was retired — detached from the loop and dropped by
    // whatever held it — on a path where waiting longer is not on offer, and
    // the same reasoning covers it as the clears above: daemon.cpp ends the
    // ring before this runs, so no completion can be dispatched afterwards.
    m_retired_handlers.clear();

    // Through the loop, not close(): every one of these numbers has been named
    // by an SQE — a read on each client, an accept on the listener — and a
    // close that only frees the number lets the next accept inherit it while
    // the old operation is still queued against it.
    //
    // On the daemon's own shutdown path this is a formality and known to be
    // one: daemon.cpp ends the ring before it gets here, so close_fd() sees no
    // ring and is exactly close(), and the accept that was armed on the
    // listener died with the ring rather than with the descriptor.  It is
    // written this way because teardown() is also the destructor's path and
    // does not get to assume that ordering, and because the one arrangement
    // that would be wrong — closing these while the ring is live — is the one
    // close_fd() is free to handle.
    for (auto& [fd, conn] : m_clients)
    {
        if (conn->interactive)
        {
            auto* inst = m_manager.get(conn->interactive_name);
            if (inst)
                inst->remove_interactive_fd(fd);
        }
        m_loop.close_fd(fd);
    }

    m_clients.clear();

    // Connections already handed to close_fd() in handle_read().  Their
    // descriptors are the loop's business now — either still held for an
    // operation that has not reported or already closed by the sweep in
    // shutdown_ring() — so a second close here would be closing a number that
    // may since have been reissued.  Only the storage is ours to drop, and
    // nothing can still be pointing at it: reaching here means the ring is down
    // (daemon shutdown) or nothing was ever submitted (setup failure).
    m_closing.clear();

    if (m_listen_fd >= 0)
    {
        m_loop.close_fd(m_listen_fd);
        m_listen_fd = -1;
        m_accept_armed = false;
    }

    unlink(socket_path.c_str());
}

void daemon_handler::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req)
        return;

    switch (req->type)
    {
        case op_accept:
            handle_accept(cqe);
            break;
        case op_read:
            handle_read(cqe, req);
            break;
        case op_write:
            handle_write(cqe, req);
            break;
        case op_timeout:
            if (req == &m_health_req)
            {
                m_health_pending = false;

                // The withdrawal teardown() submitted, answered.  There is
                // nothing left to supervise and nothing to re-arm.
                if (m_torn_down)
                    break;

                // The accept chain ends at a refused submission and only
                // something outside it can restart one — this tick is the only
                // thing that runs without a CLI connection to run for.
                if (m_listen_fd >= 0 && !m_accept_armed)
                    start_accept();

                check_managed_health();
                // Release the retired runtimes the ring has finished with.
                // Removal reaps too, but only ever the ones retired before it —
                // the instance it retires itself is still owed completions at
                // that moment.  Without a second caller, the last runtime a
                // daemon removes keeps its whole object until something else is
                // removed or the daemon exits: two megabytes for a proxy before
                // a single connection, six with its connection pools.
                m_manager.reap_retired(m_loop);
                start_health_timer();
            }
            break;
        default:
            break;
    }
}

// A write submitted by send_response() has reported.
//
// For a connection the daemon still owns this is where the exchange finishes:
// the reply is out, the buffer is free to be rebuilt, and the read that was
// deliberately left un-armed while the write was queued goes back in.  For one
// that close_client() parked because the client hung up while its reply was
// still in the ring, it is the only thing that can say the ring has finished
// with the request and the buffer inside it.
void daemon_handler::handle_write(struct io_uring_cqe* cqe, const io_request* req)
{
    auto it = m_clients.find(req->fd);
    if (it == m_clients.end())
    {
        release_closing(req);
        return;
    }

    auto* conn = it->second.get();
    conn->write_pending = false;

    // A failed send says the reply is not going to be delivered — -EPIPE is the
    // ordinary form, a client that read what it wanted and hung up.  There is
    // no one left to answer, so this connection goes rather than sitting in
    // m_clients holding a descriptor with nothing armed on it.
    if (cqe->res <= 0)
    {
        close_client(it);
        return;
    }

    // send() is entitled to take less than it was given, and does as soon as a
    // reply outgrows the socket buffer — `ls` over a few hundred runtimes, or a
    // `dump` of any size.  The rest of it was simply dropped: the CLI reads
    // until the NUL terminator that ends the reply, so it sat out its five
    // second SO_RCVTIMEO and then reported the daemon as unreachable.
    conn->write_off += static_cast<size_t>(cqe->res);
    if (conn->write_off < conn->out_buf.size())
    {
        if (!send_response(conn))
            close_client(it);
        return;
    }

    conn->out_buf.clear();
    conn->write_off = 0;

    if (!m_loop.submit_read(conn->fd, conn->read_buf, sizeof(conn->read_buf), &conn->read_req))
    {
        LOG_ERROR("daemon: could not re-arm the read on a CLI connection after its "
                  "reply went out; closing it");
        close_client(it);
    }
}

// Take a client connection down: its interactive registration, its descriptor,
// then its storage.
//
// Reached from the client's own hangup and from every path where the daemon can
// no longer finish the exchange — a reply that could not be queued, a send that
// failed, a read that could not be re-armed.  All of them have the same
// requirement: the connection must not be left in m_clients waiting for a
// completion that is never coming.
void daemon_handler::close_client(client_map::iterator it)
{
    auto* conn = it->second.get();
    const int fd = conn->fd;

    if (conn->interactive)
    {
        auto* inst = m_manager.get(conn->interactive_name);
        if (inst)
            inst->remove_interactive_fd(fd);
    }

    // The only close in this file that happens while the ring is live, and the
    // only one where the number can still be spoken for.  A response is not
    // written here — send_response() submits it — so a client that hangs up
    // before draining a reply larger than the socket buffer leaves that write
    // queued against this descriptor number.  close() would free the number
    // with the write still in the queue, the next CLI connection would be
    // handed it by accept, and that client would find somebody else's `ls`
    // output spliced into its own reply.  Same shape as the proxy's crossed
    // streams, one runtime up.
    //
    // close_fd() holds the number instead until the write reports, and
    // discounts the completion we are inside — so on the ordinary path, where
    // the reply went out long before the hangup, this is one indexed load and
    // then the close it was always going to do.
    m_loop.close_fd(fd);

    // Whatever fd_inflight() still counts after that discount is that queued
    // write, and it is pointing at write_req and out_buf inside this
    // connection.  Erasing now would leave the ring holding a request that no
    // longer exists and a buffer the kernel is still reading from; run() reads
    // the request back out of the completion, so it would be reading freed
    // memory, and the only reason that was survivable before is that the block
    // was usually still mapped.  Park the connection instead and let the
    // write's own completion release it.
    if (m_loop.fd_inflight(fd) > 0)
        m_closing.push_back(std::move(it->second));

    m_clients.erase(it);
}

// The parked connection a write completion belongs to, if it is one of those.
void daemon_handler::release_closing(const io_request* req)
{
    if (__builtin_expect(m_closing.empty(), 1))
        return;

    for (auto it = m_closing.begin(); it != m_closing.end(); ++it)
    {
        if ((*it)->fd != req->fd)
            continue;

        // Not "a completion arrived" but "nothing else names this number" —
        // the same condition close_fd() releases the descriptor on, asked
        // rather than assumed, because only the loop knows what is still queued
        // against an fd this connection was parked for.
        //
        // With one write outstanding at a time it is this completion and no
        // other, so the discount for the one in hand makes it zero.  It was not
        // always: a client that pipelined two commands into one packet got two
        // writes submitted through the one write_req, and releasing on the
        // first of them handed the ring back the freed storage the parking
        // exists to prevent.  send_response() is what ended that.
        //
        // The descriptor is still close_fd()'s to release, and it does that
        // after this returns — which is why the number cannot have gone to a
        // new client while this entry was still standing.
        if (m_loop.fd_inflight((*it)->fd) == 0)
            m_closing.erase(it);
        return;
    }
}

void daemon_handler::handle_accept(struct io_uring_cqe* cqe)
{
    // This completion is the accept, spent.  Cleared before anything can fail
    // so the re-arm below, and the health tick behind it, both see the truth.
    m_accept_armed = false;

    int client_fd = cqe->res;

    if (client_fd >= 0)
    {
        auto conn = std::make_unique<ipc_connection>();
        conn->fd = client_fd;
        conn->read_req = { this, conn->read_buf, client_fd, sizeof(conn->read_buf), op_read };
        conn->write_req = { this, nullptr, client_fd, 0, op_write };

        auto it = m_clients.insert_or_assign(client_fd, std::move(conn)).first;
        auto* ptr = it->second.get();

        // Refused, this connection never hears from the daemon again and the
        // client waits out its own timeout for a command that was never even
        // read.  Nothing is queued against the number, so close_client() closes
        // it outright and the client gets an immediate EOF instead.
        if (!m_loop.submit_read(client_fd, ptr->read_buf, sizeof(ptr->read_buf), &ptr->read_req))
        {
            LOG_ERROR("daemon: could not arm the read on an accepted CLI connection; "
                      "closing it");
            close_client(it);
        }
    }

    start_accept();
}

void daemon_handler::handle_read(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    auto it = m_clients.find(fd);
    if (it == m_clients.end())
        return;

    auto* conn = it->second.get();

    if (cqe->res <= 0)
    {
        close_client(it);
        return;
    }

    // Cannot happen, and checked because of what it would mean if it did: a read
    // is only ever armed on a connection with no write outstanding, so reaching
    // here with one would mean the daemon is about to rebuild out_buf — or, on
    // the interactive path below, write to the socket directly — while the
    // kernel is still reading the buffer.  That is precisely the defect
    // send_response() was rewritten to make impossible; if it comes back, it
    // comes back as a dropped connection and a line in the log, not as a
    // corrupted reply.
    if (SOCKETLEY_UNLIKELY(conn->write_pending))
    {
        LOG_ERROR("daemon: a CLI connection was read while its reply was still in "
                  "the ring; closing it rather than rebuilding the buffer");
        close_client(it);
        return;
    }

    conn->partial.append(conn->read_buf, cqe->res);

    // Interactive mode: forward input lines to runtime
    if (conn->interactive)
    {
        size_t pos;
        while ((pos = conn->partial.find('\n')) != std::string::npos)
        {
            std::string line = conn->partial.substr(0, pos);
            conn->partial.erase(0, pos + 1);

            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            if (line.empty())
                continue;

            auto* inst = m_manager.get(conn->interactive_name);
            if (!inst || inst->get_state() != runtime_running)
                break;

            switch (inst->get_type())
            {
                case runtime_server:
                    static_cast<server_instance*>(inst)->lua_broadcast(line);
                    break;
                case runtime_client:
                    static_cast<client_instance*>(inst)->lua_send(line);
                    break;
                case runtime_cache:
                {
                    std::string resp = static_cast<cache_instance*>(inst)->execute(line);
                    if (!resp.empty())
                    {
                        size_t total = 0;
                        while (total < resp.size())
                        {
                            ssize_t w = ::write(conn->fd, resp.data() + total, resp.size() - total);
                            if (w < 0) break;
                            total += static_cast<size_t>(w);
                        }
                    }
                    break;
                }
                default:
                    break;
            }
        }

        if (!m_loop.submit_read(fd, conn->read_buf, sizeof(conn->read_buf), &conn->read_req))
        {
            LOG_ERROR("daemon: could not re-arm the read on an interactive CLI "
                      "connection; closing it");
            close_client(it);
        }
        return;
    }

    // ─── TWO FRAMINGS ON ONE CONNECTION ─────────────────────────────────────
    //
    // A command is a line, unless it begins with the frame marker — see
    // ipc_framing.h for the whole of it and for why a marker rather than a
    // negotiation.  The short version: a payload with a newline in it cannot
    // travel on a line protocol, and every command that has no newline is sent
    // exactly as it always was, so nothing about the ordinary path changes.
    //
    // Both are handled in one loop because both can arrive in one packet: a CLI
    // is free to pipeline, and the `send` that needs a frame may follow a `ls`
    // that does not.
    bool queued = false;
    while (!conn->partial.empty())
    {
        std::string command;

        if (conn->partial[0] == ipc_frame::marker)
        {
            std::string payload;
            const auto r = ipc_frame::take_frame(conn->partial, payload);
            if (r == ipc_frame::take::need_more)
                break;
            if (r == ipc_frame::take::fatal)
            {
                // A length past the cap means this stream's framing is wrong,
                // and there is no point in the buffer that is provably the
                // start of the next frame.  Closing is the only answer that
                // cannot make it worse.
                LOG_ERROR("daemon: a CLI connection sent a frame longer than the "
                          "limit; closing it rather than guessing where the next "
                          "one starts");
                close_client(it);
                return;
            }
            command = std::move(payload);
        }
        else
        {
            const size_t pos = conn->partial.find('\n');
            if (pos == std::string::npos)
                break;
            command = conn->partial.substr(0, pos);
            conn->partial.erase(0, pos + 1);
            if (!command.empty() && command.back() == '\r')
                command.pop_back();
        }

        conn->write_buf.clear();
        int exit_code = process_command(conn, command);
        append_response(conn, exit_code);
        queued = true;
    }

    // One write for every command this packet held, and no read re-armed until
    // it has reported — see send_response() for why the two are tied together.
    if (queued)
    {
        if (!send_response(conn))
            close_client(it);
        return;
    }

    if (!m_loop.submit_read(fd, conn->read_buf, sizeof(conn->read_buf), &conn->read_req))
    {
        LOG_ERROR("daemon: could not re-arm the read on a CLI connection; closing it");
        close_client(it);
    }
}

int daemon_handler::check_empty_names(const std::vector<std::string>& names,
    const parsed_args& pa, const char* verb, ipc_connection* conn) const
{
    if (!names.empty())
        return -1;

    for (size_t i = 1; i < pa.count; ++i)
    {
        if (!pa.args[i].empty() && pa.args[i][0] != '-')
        {
            std::string msg = std::string(verb) + std::string(pa.args[i]) + "\n";
            if (conn)
            {
                conn->write_buf = msg;
                return 1;
            }
            std::cout << msg;
            return 2;
        }
    }
    return 0;
}

int daemon_handler::process_command(ipc_connection* conn, std::string_view line)
{
    // ─── One guard, for every command ───────────────────────────────────────
    //
    // cout_to_reply was written to "reach every one of them at once" and was
    // then installed on two of them.  cmd_create and cmd_edit had it; cmd_send,
    // cmd_start, cmd_attach and the `default:` arm below did not, and every
    // std::cout in those went to the daemon's own stdout — which is /dev/null
    // once it has daemonised.  Measured, against a daemon whose stdout and
    // stderr were both redirected to a file:
    //
    //     $ socketley send nosuchruntime hello ; echo $?
    //     1                        <- and not one word, on either stream
    //     $ socketley start ; echo $?
    //     1                        <- the usage line, likewise gone
    //
    // "runtime not found: nosuchruntime" is written, and nobody can read it.
    // An exit code with no sentence behind it is the same defect this whole
    // audit is about, one command family over from the Lua one.
    //
    // Here rather than in each handler, because a per-handler guard is a list
    // that goes stale the moment somebody adds a command — which is exactly how
    // these four came to be missing one.  There is a single caller and no
    // re-entry, and the destructor runs before append_response() reads
    // write_buf, so the text is in the frame that answers this command.
    //
    // It also fixes cmd_send without changing its signature: the guard needs a
    // connection, the handler does not, and cmd_send is the one command whose
    // parameter list has no ipc_connection at all.
    const cout_to_reply reply_guard(conn);

    parsed_args pa;
    pa.parse(line);

    if (pa.count == 0)
    {
        std::cout << "no command\n";
        return 1;
    }

    // ─── A COMMAND WITH MORE ARGUMENTS THAN THE PARSER HAS SLOTS ────────────
    //
    // parsed_args puts the whole remainder in its last slot, so a command whose
    // final argument is free text is complete and correct: `send`, `action` and
    // `import` all read their payload with rest_from(), which spans to the end
    // of the line.  That is the case worth keeping — a message, a cache value
    // or a configuration document has no business having a word limit.
    //
    // Every other command reads its arguments as a LIST, and for those the
    // merged tail is not the request that was made.  `start a b c ...` past the
    // limit would look up one impossible name made of the rest; `create` would
    // lose flags and build a runtime nobody asked for.  Both used to happen
    // silently, which is what this refuses.
    //
    // The allowlist is here rather than in parsed_args because this is where
    // the commands are known, and it is three entries rather than a rule
    // because there are three: everything else would be guessing.
    if (pa.overflowed)
    {
        switch (pa.hashes[0])
        {
            case fnv1a("send"):
            case fnv1a("action"):
            case fnv1a("import"):
                break;   // the tail is the payload, and it is all there

            default:
                std::cout << "too many arguments for " << pa.args[0]
                          << " (at most " << (MAX_ARGS - 1) << ")\n"
                             "  Everything past that used to be dropped without a word; "
                             "it is refused now\n"
                             "  rather than acted on in part.\n";
                return 1;
        }
    }

    switch (pa.hashes[0])
    {
        case fnv1a("create"):     return cmd_create(conn, pa);
        case fnv1a("start"):     return cmd_start(conn, pa);
        case fnv1a("stop"):      return cmd_stop(conn, pa);
        case fnv1a("remove"):    return cmd_remove(conn, pa);
        case fnv1a("ls"):        return cmd_ls(conn, pa);
        case fnv1a("ps"):        return cmd_ps(conn, pa);
        case fnv1a("send"):      return cmd_send(pa);
        case fnv1a("edit"):      return cmd_edit(conn, pa);
        case fnv1a("show"):
        case fnv1a("dump"):      return cmd_dump(conn, pa);
        case fnv1a("import"):    return cmd_import(conn, pa);
        case fnv1a("action"):    return cmd_action(conn, pa);
        case fnv1a("stats"):     return cmd_stats(conn, pa);
        case fnv1a("reload"):    return cmd_reload(conn, pa);
        case fnv1a("reload-lua"):return cmd_reload_lua(conn, pa);
        case fnv1a("owner"):     return cmd_owner(conn, pa);
        case fnv1a("attach"):    return cmd_attach(conn, pa);
        case fnv1a("add"):       return cmd_add(conn, pa);
        case fnv1a("cluster-dir"): return cmd_cluster_dir(conn);
        case fnv1a("cluster-status"): return cmd_cluster_status(conn);
        case fnv1a("daemon-name"):    return cmd_daemon_name(conn, pa);
        case fnv1a("daemon-cluster"): return cmd_daemon_cluster(conn, pa);
        case fnv1a("dashboard"):     return cmd_dashboard(conn);
        case fnv1a("ping"):          return cmd_ping(conn);
        default:
            std::cout << "unknown command: " << pa.args[0] << "\n";
            return 1;
    }
}

// conn is unused now and the parameter stays anyway: the dispatcher hands every
// handler the connection, and a handler that prints its refusals needs nothing
// else — process_command holds the reply guard for all of them.  Dropping it
// here would make this signature the odd one out for a reason that is no longer
// about this command.
int daemon_handler::cmd_create([[maybe_unused]] ipc_connection* conn,
                              const parsed_args& pa)
{
    if (pa.count < 3)
    {
        std::cout << "usage: create <type> <name> [flags]\n";
        return 1;
    }

    runtime_type type;
    if (!parse_runtime_type(pa.args[1], type))
    {
        std::cout << "unknown runtime type: " << pa.args[1] << "\n";
        return 1;
    }

    std::string_view name = pa.args[2];

    // The reason, not a guess at it.  This reported "runtime already exists"
    // for a name that was refused for its characters, on a daemon holding
    // nothing — see runtime_manager::create_result.
    switch (m_manager.try_create(type, name))
    {
        case runtime_manager::create_result::ok:
            break;

        case runtime_manager::create_result::name_taken:
            std::cout << "runtime already exists: " << name << "\n";
            return 1;

        case runtime_manager::create_result::invalid_name:
            std::cout << "invalid runtime name: " << name << "\n"
                         "  A name may contain letters, digits, '-', '_' and "
                         "'.', may not begin with '.',\n"
                         "  and may be at most 128 characters.\n";
            return 1;

        case runtime_manager::create_result::internal:
            std::cout << "could not build a runtime of type "
                      << type_to_string(type) << "\n";
            return 2;
    }

    auto* instance = m_manager.get(name);
    if (!instance)
    {
        std::cout << "internal error\n";
        return 2;
    }

    instance->set_runtime_manager(&m_manager);
    instance->set_event_loop(&m_loop);

    if (type == runtime_proxy)
        static_cast<proxy_instance*>(instance)->set_runtime_manager(&m_manager);

    bool autostart = false;

    // What --lua asked for, loaded once every flag has been seen; see the --lua
    // case in parse_common_flags for why it cannot be loaded where it is
    // parsed, and the block below the TLS and ring refusals for where it is.
    std::string lua_script;

    // ─── One flag has to be known before the others are read ────────────────
    //
    // What --lua does depends on whether this runtime will live in a worker: an
    // out-of-process placeholder compiles the script and discards it, an
    // in-process runtime loads and runs it (see
    // runtime_instance::load_lua_script).  Flags arrive in whatever order the
    // operator typed them, so when --lua was acted on where it was parsed,
    // `--lua x --daemon-process` compiled-and-discarded the script before
    // anyone knew it was staying in the daemon -- and `--daemon-process --lua x`
    // did not.  A create whose behaviour depends on argument order is a bug
    // waiting for someone to reorder a command line.
    //
    // --lua is deferred to after the loop now, for the other half of the same
    // sentence, and this pre-scan still has to happen: it settles the bit the
    // deferred load reads.
    //
    // Scanned rather than reordered: the flag takes no value, so finding it is
    // exact, and marking early is idempotent with the case below that marks it
    // again when the loop reaches it.  It stays a pre-scan now that --lua is
    // deferred to after the loop, and for the same reason it was one: this bit
    // decides what load_lua_script DOES, so it has to be settled before the
    // load, and the load is still inside this command.
    // Any type, not only a proxy.  mark_out_of_process() has always been on
    // runtime_instance; what kept this to proxies was the cast, and the worker
    // no longer needs one — it builds whatever the config frame's type says.
    // Where this runtime runs.  A process of its own unless it says otherwise.
    //
    // One flag, naming the one state that is not the default.  A boolean needs
    // one name, not two: `--out-of-process` and `--in-daemon` were one bit under
    // two spellings, and the pair had to be kept level in four places.
    //
    // A runtime in a process of its own cannot take the daemon down with it,
    // cannot stall another runtime's event loop, and is scheduled by the kernel
    // rather than by whatever else that loop was doing. What --daemon-process
    // buys back is what only shared memory can give: the cross-runtime Lua
    // management API, a routes declaration the placeholder can publish, and
    // about 50 µs per cross-runtime request.
    //
    // What this default costs where it is not yet free is written down in
    // test/out_of_process_gaps.md, measured rather than guessed.
    bool want_worker = true;
    for (size_t i = 3; i < pa.count; ++i)
        if (std::string_view(pa.args[i]) == "--daemon-process")
            want_worker = false;
    if (want_worker)
        instance->mark_out_of_process();

    for (size_t i = 3; i < pa.count; ++i)
    {
        int result = parse_common_flags(instance, pa, i, autostart, lua_script);
        if (result == -1)
        {
            switch (type)
            {
                case runtime_server:
                    result = parse_server_flags(
                        static_cast<server_instance*>(instance), pa, i, &m_manager, name);
                    break;
                case runtime_client:
                    result = parse_client_flags(
                        static_cast<client_instance*>(instance), pa, i, name);
                    break;
                case runtime_proxy:
                    result = parse_proxy_flags(
                        static_cast<proxy_instance*>(instance), pa, i, name);
                    break;
                case runtime_cache:
                    result = parse_cache_flags(
                        static_cast<cache_instance*>(instance), pa, i, name);
                    break;
            }
        }

        if (result == -1)
        {
            std::cout << "unknown flag: " << pa.args[i] << "\n";
            m_manager.remove(name);
            return 1;
        }

        if (result > 0)
        {
            m_manager.remove(name);
            return result;
        }
    }

    // The TLS options are checked as a set, once every flag has been seen.
    // Individually they are meaningless — --tls says nothing about whether a
    // certificate was also given, and the flag that completes the set may come
    // later on the command line — so this is the first point at which the
    // question can be answered.  Refusing here rather than at the next start
    // keeps the runtime from being created at all, which is what an operator
    // who mistyped one flag of three wants.
    if (const std::string msg = instance_tls_refusal(instance); !msg.empty())
    {
        std::cout << msg;
        m_manager.remove(name);
        return 1;
    }

    // Checked as a set for the same reason TLS is, and at the same point: the
    // flag that completes the request may be further along the command line.
    if (const std::string msg = instance_ring_refusal(instance, m_loop); !msg.empty())
    {
        std::cout << msg;
        m_manager.remove(name);
        return 1;
    }

    // And the shard count, for the third time the same reason — this one with
    // the sharpest edge.  --shards is refused on a server that has a script,
    // and the script arrives as --lua, which may be typed on either side of it.
    // Checked only in the --shards case label, `--shards 4 --lua x.lua` would
    // be accepted and `--lua x.lua --shards 4` refused: one runtime, two
    // answers, decided by the order somebody's fingers happened to reach.
    //
    // lua_script rather than the instance, because the load below is what sets
    // the path on the instance and it has deliberately not run yet.
    if (const std::string msg = instance_shards_refusal(instance, !lua_script.empty());
        !msg.empty())
    {
        std::cout << msg;
        m_manager.remove(name);
        return 1;
    }

    // ─── The script, last, because it reads everything else back ────────────
    //
    // Loading builds the interpreter, runs the file's top level and snapshots
    // `self` from the instance — so it has to happen after every flag has been
    // applied, or `self` describes a half-configured runtime.  See the --lua
    // case in parse_common_flags for what that cost.
    //
    // After the two refusals above and not before them, for the reason they
    // give for being where they are: a runtime that is about to be refused must
    // not have run a line of anybody's script first.  A top level is allowed to
    // create children, open sockets and send messages, and undoing that is not
    // something `m_manager.remove(name)` can do.
    if (!lua_script.empty() && !instance->load_lua_script(lua_script))
    {
        // The reason, not just the fact.  This used to print exactly the four
        // words below while the parse error, or the sentence one of the
        // `filters`/`routes` validators wrote for the person editing the file,
        // went to stderr — and stderr is the daemon's log, one process away
        // from the terminal that ran the command.  An operator was told their
        // script would not load and never told why.
        std::cout << "could not load Lua script: " << lua_script << "\n";
        if (!lua_diag::text().empty())
            std::cout << lua_diag::text() << "\n";
        m_manager.remove(name);
        return 1;
    }

    if (autostart && !instance->get_test_mode())
    {
        if (!m_manager.start(name, m_loop))
        {
            std::cout << "could not start runtime\n";
            m_manager.remove(name);
            return 2;
        }
    }

    if (m_persistence && !instance->get_test_mode() && !instance->is_lua_created())
        m_persistence->save_runtime(instance);

    // After the save, because the supervisor describes the child with the same
    // runtime_config the state file holds and reads it back off the instance.
    if (autostart && !instance->get_test_mode())
    {
        reconcile_proxy_workers();

        // ─── The answer waits for the process that decides it ───────────────
        //
        // Everything above this line was judged in the daemon, and for a runtime
        // that lives in the daemon that was the whole configuration.  For one
        // that lives in a worker it is not: the script runs there, the port is
        // bound there, the TLS pair is checked there.  `create` returned on the
        // strength of having forked a process, which is not the same as that
        // process having accepted anything -- and the gap was a report of
        // success for a configuration that was about to be refused, with the
        // reason arriving in the log afterwards.
        //
        // A declaration is where that finally bit, because `--daemon-process`
        // made servers out-of-process by default and servers are the role that
        // declares routes.  `path = "no-slash"` is faultless Lua, so the
        // placeholder's compile-only check passes it and only the worker ever
        // discovers it is not a path.
        //
        // Waiting is what this tree does everywhere else a setting might not be
        // honoured -- --sqpoll a ring cannot give, --tls on a role with no
        // handshake, a restored runtime whose ring requirement cannot be met --
        // and all three refuse the create rather than reporting one. The rule
        // against synchronous cross-runtime calls is not this: that is the data
        // path, where a request would have to suspend across a round trip.  This
        // is the control path, which already waits -- on the IPC socket, and on
        // the fork above.
        // The runtime is deliberately left where the refusal put it, which is
        // `failed`, rather than being removed as the in-daemon path removes a
        // runtime whose script will not load.  Two things in the tree already
        // say so and outrank the symmetry argument: proxy_supervisor keeps a
        // refused configuration `failed` "where the operator can see it", and
        // a restored runtime whose ring requirement cannot be met lands there
        // too.  A create that refuses and leaves nothing to look at would make
        // the worker's reason the only record, in a log, of a runtime the
        // operator can no longer ask about.
        std::string wmsg;
        const int   wrc = await_worker_startup(
            name, wmsg, std::chrono::steady_clock::now() + worker_startup_bound);
        if (wrc != 0)
        {
            std::cout << wmsg;
            return wrc;
        }
    }

    // ─── A script whose on_start raised is not a silent success ─────────────
    //
    // Last, after the save and after the worker's verdict, because the runtime
    // IS created and IS running and nothing above this line is being undone.
    // start() will not fail on a raise — the listener is already up by the time
    // on_start runs, and taking it down over a callback is not something this
    // tree does anywhere else — so the runtime stays exactly where it is, with
    // whatever on_start managed before it gave up.
    //
    // But `create -s` reported that with exit 0 and not one character of output,
    // and the only record was a line in the daemon's log.  `reload-lua` has
    // answered 1 with the reason since it began re-running on_start, on the
    // rule that a command does not report success for something that did not
    // happen; the same script, the same callback and the same raise answered 0
    // here.  An operator cannot be expected to know that the exit code for a
    // broken on_start depends on which command they used to reach it.
    //
    // 1 rather than 2, per this tree's codes: the fault is in the file the
    // operator named, which is bad input.  It is also the code `create` already
    // gives when that same file will not PARSE — "could not load Lua script",
    // one step earlier in the same script's life — and answering the two
    // differently would be the arbitrary part.
    if (autostart && !instance->get_test_mode())
    {
        // Two places to ask, because on_start runs wherever the script runs.
        // In the daemon the instance itself kept the reason; in a worker the
        // script never came near this process, and the child sent it up as a
        // `start_err` frame before the `state` frame the wait above ended on.
        // Asking only the first would have covered the flag nobody passes:
        // since 2313c26 a runtime is out of process unless it says otherwise,
        // so the worker leg IS the ordinary `create -s`.
        std::string why = on_start_error(name);

        if (!why.empty())
        {
            std::cout << "create " << name << ": " << why << "\n"
                      << "the runtime is created and running, with whatever "
                         "on_start established before it raised; fix the script "
                         "and run `reload-lua " << name << "` to re-run it.\n";
            return 1;
        }
    }

    return 0;
}

std::vector<std::string> daemon_handler::resolve_names(const parsed_args& pa, size_t start) const
{
    std::shared_lock lock(m_manager.mutex);
    return resolve_names_impl(pa.args, pa.count, m_manager.list(), start);
}

int daemon_handler::cmd_start(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2)
    {
        std::cout << "usage: start <name|pattern>... [-i]\n";
        return 1;
    }

    bool want_interactive = false;
    for (size_t i = 1; i < pa.count; ++i)
    {
        if (pa.args[i] == "-i")
        {
            want_interactive = true;
            break;
        }
    }

    auto names = resolve_names(pa);
    int rc = check_empty_names(names, pa, "runtime not found: ", conn);
    if (rc >= 0) return rc;

    if (want_interactive && names.size() > 1)
    {
        conn->write_buf = "cannot use -i with multiple runtimes\n";
        return 1;
    }

    // Refused before anything is started, not after.
    //
    // This check used to sit below the start loop, so `start myproxy -i` started
    // the proxy, persisted was_running, and then exited 1 saying interactive mode
    // was not supported — an operator told the command failed, with a listener up
    // and a state file that would bring it back on the next daemon restart.
    //
    // And it stays a refusal.  Interactive mode is a stream: for a server what is
    // typed is broadcast to its clients, for a client it is sent to its server,
    // for a cache it is executed as a command and the reply comes back.  A proxy
    // has no such stream — it relays between a client and a backend and speaks
    // for neither — so there is nothing for typed input to mean.  Offering it
    // would mean inventing a semantics rather than exposing one.  This is the
    // same on both paths: a worker's proxy has no more of a stream than the
    // daemon's does, so nothing here is about where the runtime runs.
    if (want_interactive)
    {
        if (auto* first = m_manager.get(names.front());
            first && first->get_type() == runtime_proxy)
        {
            conn->write_buf =
                "interactive mode is not offered for a proxy: a proxy relays "
                "between a client and a backend and has no stream of its own for "
                "typed input to join. Nothing was started; run `start " +
                std::string(names.front()) + "` without -i.\n";
            return 1;
        }
    }

    int failed = 0;
    // The ones this command actually brought up, in order.  Collected because
    // the verdict on a runtime that lives in a worker cannot be read until
    // reconcile_proxy_workers() below has forked the child; see the wait there.
    std::vector<std::string> started;
    for (const auto& n : names)
    {
        // Allow -i on already-running runtimes (attach without start)
        auto* inst = m_manager.get(n);
        bool already_running = inst && inst->get_state() == runtime_running;

        if (!already_running)
        {
            // Refuse to bring up a listener that would serve cleartext under a
            // configuration promising encryption.  Reached by runtimes restored
            // from a state file written before TLS was gated at parse time.
            if (const std::string msg = instance_tls_refusal(inst); !msg.empty())
            {
                conn->write_buf += std::string(n) + ": " + msg;
                ++failed;
                continue;
            }

            // Reached by a runtime whose shard count did not come from a flag:
            // a state file written by hand or by another build, restored at
            // boot without passing a parser.  runtime_instance::start() refuses
            // it too and is the gate that cannot be walked around, but it can
            // only say so by failing — this is what puts the reason on the
            // terminal of whoever typed `start`.
            if (const std::string msg = instance_shards_refusal(inst); !msg.empty())
            {
                conn->write_buf += std::string(n) + ": " + msg;
                ++failed;
                continue;
            }

            if (!m_manager.start(n, m_loop))
            {
                conn->write_buf += "failed to start: " + std::string(n) + "\n";
                ++failed;
                continue;
            }
            if (m_persistence)
                m_persistence->set_was_running(n, true);
            inst = m_manager.get(n);
            started.push_back(n);

            // The runtime is up; its script's set-up is not.  Counted as a
            // failure and reported with the reason, for the reasoning written
            // out at the end of cmd_create — and counted rather than returned,
            // because `start a b c` has to start b and c whatever a's script
            // did, exactly as it does for a TLS refusal above.
            //
            // was_running is set anyway, deliberately: it records that the
            // operator asked for this runtime to be up, and it is up.  Clearing
            // it would mean a daemon restart silently leaving down a listener
            // that is serving traffic right now.
            // Read below rather than here.  When the script runs in a worker
            // the reason is a frame that has not arrived yet — the child has
            // not even been forked until reconcile_proxy_workers() — so asking
            // at this line would answer "nothing went wrong" for the case that
            // is now the ordinary one.
        }

        if (want_interactive && inst)
        {
            // The proxy case was refused above, before anything was started.
            conn->interactive = true;
            conn->interactive_name = n;
            inst->add_interactive_fd(conn->fd);
        }
    }

    // Any runtime just moved into `running` in a worker now needs its
    // child.  Doing it here rather than waiting for the health timer is what
    // makes `start` followed immediately by a request work.
    reconcile_proxy_workers();

    // ─── And `start` waits for the answer, exactly as `create -s` does ──────
    //
    // It did not, and what that cost is not the on_start report it was noticed
    // through.  Measured on the parent commit, one runtime whose script
    // declares `path = "no-slash"` — faultless Lua, so the placeholder's
    // compile-only check passes it and only the worker discovers it is not a
    // path:
    //
    //     create -s        exit 1   "the worker did not accept its configuration"
    //     start            exit 0   (silence)      ls, 2s later: Failed
    //     reload           exit 0   (silence)      ls, 2s later: Failed
    //
    // Same runtime, same configuration, same refusal, and the answer depended
    // on which command reached it.  `start` was reporting success for a start
    // that did not happen — not a missing detail about one that did.
    // await_worker_startup()'s own comment already says the wait is what turns
    // "the fork was requested" into "the child is serving", and `start` forks
    // exactly the same child.
    //
    // ─── What the wait costs ────────────────────────────────────────────────
    //
    // One child's startup, not one per runtime.  reconcile_proxy_workers()
    // above forks every one of them before this loop begins, so they come up
    // concurrently and these waits overlap; the deadline is shared across the
    // command for the same reason, so a wedged child cannot multiply the bound
    // by the number of names.  Measured, ten worker-backed servers started with
    // one `start 'wk*'`:
    //
    //     before   84 ms / 103 ms   returning before any child had bound
    //     after    (see the commit) returning when all ten were serving
    //
    // The runtimes are left exactly where the verdict put them, and `failed`
    // is counted rather than returned, for the reason the TLS refusal above is
    // written under: `start a b c` has to start b and c whatever a did.
    if (!started.empty())
    {
        const auto deadline = std::chrono::steady_clock::now() + worker_startup_bound;
        for (const auto& n : started)
        {
            std::string wmsg;
            if (await_worker_startup(n, wmsg, deadline) != 0)
            {
                conn->write_buf += wmsg;
                ++failed;
                continue;   // it is not serving; on_start is the smaller news
            }

            // The runtime is up; its script's set-up is not.  Counted as a
            // failure and reported with the reason, for the reasoning written
            // out at the end of cmd_create — and counted rather than returned,
            // because `start a b c` has to start b and c whatever a's script
            // did, exactly as it does for a TLS refusal above.
            //
            // was_running is set anyway, deliberately: it records that the
            // operator asked for this runtime to be up, and it is up.  Clearing
            // it would mean a daemon restart silently leaving down a listener
            // that is serving traffic right now.
            if (std::string why = on_start_error(n); !why.empty())
            {
                conn->write_buf += "start " + std::string(n) + ": " + why + "\n"
                                 + "the runtime is running, with whatever on_start "
                                   "established before it raised; fix the script and "
                                   "run `reload-lua " + std::string(n) + "` to re-run it.\n";
                ++failed;
            }
        }
    }

    return failed > 0 ? 1 : 0;
}

int daemon_handler::cmd_stop(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2)
    {
        conn->write_buf = "usage: stop <name|pattern>...\n";
        return 1;
    }

    auto names = resolve_names(pa);
    int rc = check_empty_names(names, pa, "runtime not found: ", conn);
    if (rc >= 0) return rc;

    for (const auto& n : names)
    {
        if (m_manager.stop(n, m_loop) && m_persistence)
            m_persistence->set_was_running(n, false);
    }

    // Takes down the children of everything that just stopped, before the
    // command returns: `stop` has to mean the port is free by the time the CLI
    // exits, whichever side the proxy was running on.
    reconcile_proxy_workers();
    return 0;
}

int daemon_handler::cmd_remove(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2)
    {
        conn->write_buf = "usage: remove <name|pattern>...\n";
        return 1;
    }

    auto names = resolve_names(pa);
    int rc = check_empty_names(names, pa, "runtime not found: ", conn);
    if (rc >= 0) return rc;

    for (const auto& n : names)
    {
        auto* inst = m_manager.get(n);
        if (inst && inst->get_state() == runtime_running)
            m_manager.stop(n, m_loop);
    }

    // Before the instances leave the map: the supervisor holds a pointer to the
    // placeholder it writes stats into, and that pointer must be dropped while
    // the object it names is still there.  Reconciling after the removal would
    // read a name that no longer resolves and leave the child running.
    reconcile_proxy_workers();

    for (const auto& n : names)
    {
        // Nothing is held on this side any more.  remove() hands the runtime to
        // the manager's graveyard, which is what waits for the ring to finish
        // with the io_requests embedded in it — the reason this used to keep the
        // object alive for a tick.  A tick was never the right measure anyway: a
        // POLLOUT on a connect socket or a parked splice outlives one easily.
        //
        // Holding it here as well was worse than redundant.  The list was
        // emptied by a timeout whose "did it reach the ring" answer nobody read,
        // and the flag saying one was pending was set before the submission
        // rather than after it, so a submission that never made it left the flag
        // set for the life of the daemon and the list was never emptied again —
        // one whole runtime retained per removal from then on, six megabytes for
        // a proxy once its connection pools are counted, with nothing said.
        if (m_manager.remove(n))
        {
            if (m_persistence)
                m_persistence->remove_runtime(n);
        }
    }

    return 0;
}

int daemon_handler::cmd_ls(ipc_connection* conn, const parsed_args& pa)
{
    std::shared_lock lock(m_manager.mutex);

    const auto& runtimes = m_manager.list();
    if (runtimes.empty())
        return 0;

    bool silent = false;
    bool json_format = false;
    bool col_id = false, col_name = false, col_type = false, col_port = false;
    bool col_status = false, col_conn = false, col_owner = false, col_created = false;
    bool col_group = false;

    for (size_t i = 1; i < pa.count; ++i)
    {
        switch (pa.hashes[i])
        {
            case fnv1a("-s"):
            case fnv1a("--silent"):  silent     = true; break;
            case fnv1a("--json"):
            case fnv1a("-j"):        json_format = true; break;
            case fnv1a("--id"):      col_id      = true; break;
            case fnv1a("--name"):    col_name    = true; break;
            case fnv1a("--type"):    col_type    = true; break;
            case fnv1a("--port"):    col_port    = true; break;
            case fnv1a("--status"):  col_status  = true; break;
            case fnv1a("--conn"):    col_conn    = true; break;
            case fnv1a("--owner"):   col_owner   = true; break;
            case fnv1a("--created"): col_created = true; break;
            case fnv1a("--group"):   col_group   = true; break;
        }
        // Handle --format json
        // `--format json` is the only spelling there is.  Anything else was
        // consumed and ignored, so `--format xml` produced the default table
        // and said nothing — an operator asking for a format they do not have
        // deserves to be told, not answered in a different one.
        if (pa.hashes[i] == fnv1a("--format") && i + 1 < pa.count)
        {
            if (pa.hashes[i + 1] == fnv1a("json"))
                json_format = true;
            else
            {
                conn->write_buf = "unknown format: " + std::string(pa.args[i + 1]) +
                                  " (the only one is json)\n";
                return 1;
            }
            ++i;
        }
    }

    // `-s` with no column named is the documented listing: "prints only runtime
    // names (one per line)".  It used to suppress the header and print the
    // whole eight-column table underneath it, so the operator who read that
    // sentence and wrote `for n in $(socketley ls -s)` iterated over ids,
    // ports, connection counts and the words "Up" and "seconds".  Naming a
    // column is a request for that column and still means header-off only.
    if (silent && !col_id && !col_name && !col_type && !col_port &&
        !col_status && !col_conn && !col_owner && !col_created && !col_group)
        col_name = true;

    bool any_col = col_id || col_name || col_type || col_port ||
                   col_status || col_conn || col_owner || col_created || col_group;

    if (json_format)
    {
        std::ostringstream out;
        out << "[";
        bool first = true;
        for (const auto& [name, instance] : runtimes)
        {
            if (!first) out << ",";
            first = false;
            runtime_state state = instance->get_state();
            const char* state_str;
            switch (state)
            {
                case runtime_created: state_str = "created"; break;
                case runtime_running: state_str = "running"; break;
                case runtime_stopped: state_str = "stopped"; break;
                case runtime_failed:  state_str = "failed";  break;
                default:              state_str = "unknown"; break;
            }
            uint16_t port = instance->get_port();
            auto owner = instance->get_owner();
            auto group = instance->get_group();
            // Escaped, all of them.  A name is validated now, but a group and
            // an owner are arbitrary operator strings, and a quote in either
            // used to produce a document no JSON parser would accept.
            // Where a runtime with no port listens.  Empty for every other
            // runtime, so a consumer reading `port` alone sees exactly what it
            // saw before -- but a server on a unix socket reports `"port":0`
            // and nothing else, and a caller reading this document has no other
            // way to find out where it is.
            const std::string_view listen_path = instance->get_listen_path();
            out << "{\"id\":\"" << sp_detail::json_escape(instance->get_id())
                << "\",\"name\":\"" << sp_detail::json_escape(name)
                << "\",\"type\":\"" << type_to_string(instance->get_type())
                << "\",\"port\":" << port
                << ",\"listen\":\""
                << (listen_path.empty() ? std::string()
                                        : "unix:" + sp_detail::json_escape(listen_path))
                << "\",\"status\":\"" << state_str
                << "\",\"connections\":" << instance->reported_connection_count()
                << ",\"owner\":\"" << sp_detail::json_escape(owner)
                << "\",\"group\":\"" << sp_detail::json_escape(group)
                << "\"}";
        }
        out << "]\n";
        conn->write_buf = out.str();
        return 0;
    }

    std::ostringstream out;
    out << std::left;

    if (!any_col)
    {
        if (!silent)
            out << std::setw(10) << "ID"
                << std::setw(16) << "NAME"
                << std::setw(8)  << "TYPE"
                << std::setw(8)  << "PORT"
                << std::setw(6)  << "CONN"
                << std::setw(12) << "OWNED BY"
                << std::setw(20) << "STATUS"
                << "CREATED\n";

        for (const auto& [name, instance] : runtimes)
        {
            runtime_state state = instance->get_state();
            const char* status_str;
            std::string uptime_buf;
            switch (state)
            {
                case runtime_created: status_str = "Created"; break;
                case runtime_running:
                    uptime_buf = format_uptime(instance->get_start_time());
                    status_str = uptime_buf.c_str();
                    break;
                case runtime_stopped: status_str = "Stopped"; break;
                case runtime_failed:  status_str = "Failed";  break;
                default:              status_str = "Unknown"; break;
            }
            uint16_t port = instance->get_port();
            auto owner = instance->get_owner();
            out << std::setw(10) << instance->get_id()
                << std::setw(16) << name
                << std::setw(8)  << type_to_string(instance->get_type())
                << std::setw(8)  << (port > 0 ? std::to_string(port) : "-")
                << std::setw(6)  << instance->reported_connection_count()
                << std::setw(12) << (owner.empty() ? "-" : std::string(owner))
                << std::setw(20) << status_str
                << format_time_ago(instance->get_created_time()) << "\n";
        }
    }
    else
    {
        if (!silent)
        {
            bool first = true;
            auto hdr = [&](const char* h) { if (!first) out << '\t'; out << h; first = false; };
            if (col_id)      hdr("ID");
            if (col_name)    hdr("NAME");
            if (col_type)    hdr("TYPE");
            if (col_port)    hdr("PORT");
            if (col_conn)    hdr("CONN");
            if (col_owner)   hdr("OWNER");
            if (col_group)   hdr("GROUP");
            if (col_status)  hdr("STATUS");
            if (col_created) hdr("CREATED");
            out << '\n';
        }

        for (const auto& [name, instance] : runtimes)
        {
            runtime_state state = instance->get_state();
            std::string status;
            switch (state)
            {
                case runtime_created: status = "Created"; break;
                case runtime_running: status = format_uptime(instance->get_start_time()); break;
                case runtime_stopped: status = "Stopped"; break;
                case runtime_failed:  status = "Failed";  break;
                default:              status = "Unknown"; break;
            }
            uint16_t port = instance->get_port();
            auto owner = instance->get_owner();
            auto group = instance->get_group();
            bool first = true;
            auto col = [&](const std::string& v) { if (!first) out << '\t'; out << v; first = false; };
            if (col_id)      col(std::string(instance->get_id()));
            if (col_name)    col(std::string(name));
            if (col_type)    col(std::string(type_to_string(instance->get_type())));
            if (col_port)    col(port > 0 ? std::to_string(port) : "-");
            if (col_conn)    col(std::to_string(instance->reported_connection_count()));
            if (col_owner)   col(owner.empty() ? "-" : std::string(owner));
            if (col_group)   col(group.empty() ? "-" : std::string(group));
            if (col_status)  col(status);
            if (col_created) col(format_time_ago(instance->get_created_time()));
            out << '\n';
        }
    }

    conn->write_buf = out.str();
    return 0;
}

// `ps`, and `ps -a`.
//
// Bare `ps` lists running runtimes and nothing else, which is what the name
// promises and what every script in test/integration and examples/ that greps
// this output already assumes.  It is also why a runtime that failed to start
// produced no row at all — and when nothing else was up, no output at all.  The
// operator who has just watched a runtime not come up types the command named
// after "what is running", gets an empty screen, and reads it as "the runtime
// does not exist" rather than "it exists and is broken".  `failed` is exactly
// the state you go looking for, and it was the one state this could not show.
//
// So the widening is opt-in, spelled the way `docker ps -a` is spelled, and the
// rows it adds carry their state in the STATUS column so that a script which
// asks for them can still tell them apart.  Default output is untouched, byte
// for byte.
int daemon_handler::cmd_ps(ipc_connection* conn, const parsed_args& pa)
{
    std::shared_lock lock(m_manager.mutex);

    const auto& runtimes = m_manager.list();

    bool silent = false;
    bool json_format = false;
    bool all = false;
    bool col_id = false, col_name = false, col_type = false, col_port = false;
    bool col_uptime = false, col_conn = false, col_owner = false, col_created = false;

    for (size_t i = 1; i < pa.count; ++i)
    {
        switch (pa.hashes[i])
        {
            case fnv1a("-s"):
            case fnv1a("--silent"):  silent     = true; break;
            case fnv1a("--json"):
            case fnv1a("-j"):        json_format = true; break;
            case fnv1a("-a"):
            case fnv1a("--all"):     all         = true; break;
            case fnv1a("--id"):      col_id      = true; break;
            case fnv1a("--name"):    col_name    = true; break;
            case fnv1a("--type"):    col_type    = true; break;
            case fnv1a("--port"):    col_port    = true; break;
            case fnv1a("--uptime"):  col_uptime  = true; break;
            case fnv1a("--status"):  col_uptime  = true; break;
            case fnv1a("--conn"):    col_conn    = true; break;
            case fnv1a("--owner"):   col_owner   = true; break;
            case fnv1a("--created"): col_created = true; break;
        }
        // `--format json` is the only spelling there is.  Anything else was
        // consumed and ignored, so `--format xml` produced the default table
        // and said nothing — an operator asking for a format they do not have
        // deserves to be told, not answered in a different one.
        if (pa.hashes[i] == fnv1a("--format") && i + 1 < pa.count)
        {
            if (pa.hashes[i + 1] == fnv1a("json"))
                json_format = true;
            else
            {
                conn->write_buf = "unknown format: " + std::string(pa.args[i + 1]) +
                                  " (the only one is json)\n";
                return 1;
            }
            ++i;
        }
    }

    // Nothing to list means no output, not an empty table — the same silence
    // `ls` keeps for an empty inventory.  The flags are parsed above this
    // rather than below it because `-a` decides what "nothing to list" means.
    const auto listed = [&](const runtime_instance* inst)
    { return all || inst->get_state() == runtime_running; };

    if (std::none_of(runtimes.begin(), runtimes.end(),
                     [&](const auto& p) { return listed(p.second.get()); }))
        return 0;

    // As in cmd_ls: `-s` alone is the names-only listing both the man page and
    // the help script promise; a named column keeps it meaning header-off.
    if (silent && !col_id && !col_name && !col_type && !col_port &&
        !col_uptime && !col_conn && !col_owner && !col_created)
        col_name = true;

    bool any_col = col_id || col_name || col_type || col_port ||
                   col_uptime || col_conn || col_owner || col_created;

    if (json_format)
    {
        std::ostringstream out;
        out << "[";
        bool first = true;
        for (const auto& [name, instance] : runtimes)
        {
            if (!listed(instance.get()))
                continue;
            if (!first) out << ",";
            first = false;
            uint16_t port = instance->get_port();
            auto owner = instance->get_owner();
            auto group = instance->get_group();
            const bool running = instance->get_state() == runtime_running;
            // The literal "running" used to be written here because every row
            // this could print was running.  Under -a that would be a row for a
            // failed runtime claiming to be up, which is worse than no row.
            // uptime goes empty for the same reason: a runtime that never
            // started has no start time to measure from.
            // See the note in `ls --json` above.
            const std::string_view listen_path = instance->get_listen_path();
            out << "{\"id\":\"" << sp_detail::json_escape(instance->get_id())
                << "\",\"name\":\"" << sp_detail::json_escape(name)
                << "\",\"type\":\"" << type_to_string(instance->get_type())
                << "\",\"port\":" << port
                << ",\"listen\":\""
                << (listen_path.empty() ? std::string()
                                        : "unix:" + sp_detail::json_escape(listen_path))
                << "\",\"status\":\"" << state_json(instance->get_state())
                << "\",\"uptime\":\""
                << (running ? format_uptime(instance->get_start_time()) : std::string())
                << "\",\"connections\":" << instance->reported_connection_count()
                << ",\"owner\":\"" << sp_detail::json_escape(owner)
                << "\",\"group\":\"" << sp_detail::json_escape(group)
                << "\"}";
        }
        out << "]\n";
        conn->write_buf = out.str();
        return 0;
    }

    std::ostringstream out;
    out << std::left;

    if (!any_col)
    {
        if (!silent)
            out << std::setw(10) << "ID"
                << std::setw(16) << "NAME"
                << std::setw(8)  << "TYPE"
                << std::setw(8)  << "PORT"
                << std::setw(6)  << "CONN"
                << std::setw(12) << "OWNED BY"
                << std::setw(20) << "STATUS"
                << "CREATED\n";

        for (const auto& [name, instance] : runtimes)
        {
            if (!listed(instance.get()))
                continue;
            uint16_t port = instance->get_port();
            auto owner = instance->get_owner();
            out << std::setw(10) << instance->get_id()
                << std::setw(16) << name
                << std::setw(8)  << type_to_string(instance->get_type())
                << std::setw(8)  << (port > 0 ? std::to_string(port) : "-")
                << std::setw(6)  << instance->reported_connection_count()
                << std::setw(12) << (owner.empty() ? "-" : std::string(owner))
                << std::setw(20) << state_column(instance.get())
                << format_time_ago(instance->get_created_time()) << "\n";
        }
    }
    else
    {
        if (!silent)
        {
            bool first = true;
            auto hdr = [&](const char* h) { if (!first) out << '\t'; out << h; first = false; };
            if (col_id)      hdr("ID");
            if (col_name)    hdr("NAME");
            if (col_type)    hdr("TYPE");
            if (col_port)    hdr("PORT");
            if (col_conn)    hdr("CONN");
            if (col_owner)   hdr("OWNER");
            if (col_uptime)  hdr("UPTIME");
            if (col_created) hdr("CREATED");
            out << '\n';
        }

        for (const auto& [name, instance] : runtimes)
        {
            if (!listed(instance.get()))
                continue;
            uint16_t port = instance->get_port();
            auto owner = instance->get_owner();
            bool first = true;
            auto col = [&](const std::string& v) { if (!first) out << '\t'; out << v; first = false; };
            if (col_id)      col(std::string(instance->get_id()));
            if (col_name)    col(std::string(name));
            if (col_type)    col(std::string(type_to_string(instance->get_type())));
            if (col_port)    col(port > 0 ? std::to_string(port) : "-");
            if (col_conn)    col(std::to_string(instance->reported_connection_count()));
            if (col_owner)   col(owner.empty() ? "-" : std::string(owner));
            if (col_uptime)  col(state_column(instance.get()));
            if (col_created) col(format_time_ago(instance->get_created_time()));
            out << '\n';
        }
    }

    conn->write_buf = out.str();
    return 0;
}

// The one command whose answer is the daemon itself.
//
// A CLI that has only connect() to go on cannot tell a daemon from a stranger
// bound to the same path, and it was writing the operator's command into
// whichever it found.  This is what it asks first.  The reply has to be
// something no other program produces by accident, so it leads with a literal
// that names this project, and it carries the version and pid because the
// second question after "is this a daemon" is always "which one".
//
// Cheap on purpose: no lock, no runtime touched, one string.  It runs ahead of
// every CLI command in the tree.
int daemon_handler::cmd_ping(ipc_connection* conn)
{
    if (!conn)
        return 0;

    std::ostringstream out;
    out << socketley::daemon_ident_prefix << SOCKETLEY_VERSION
        << ' ' << getpid();

    // And which executable this daemon is, exactly.
    //
    // The version cannot answer that.  Nothing in premake5.lua defines
    // SOCKETLEY_VERSION, so it is one literal in cli.h that every build of a
    // release carries: a daemon started before a rebuild and a CLI built after
    // it report the same string, which is the one case an operator actually
    // hits — "I rebuilt and my new flag is rejected" is a same-version rebuild
    // against a daemon still holding its runtimes.  The inode does answer it.
    //
    // Read fresh rather than cached, because the interesting change happens
    // while the daemon is running: the link gains " (deleted)" the moment the
    // file it was started from is unlinked, and a value captured at startup
    // would be the one value that can never show it.  Two syscalls against a
    // page-cached /proc entry, in a command that already costs an accept, a
    // read, a write and a close.
    //
    // The path goes last in the reply, because a path may contain spaces.
    std::string exe;
    uint64_t    dev = 0, ino = 0;
    if (socketley::self_exe_identity(exe, dev, ino))
        out << ' ' << dev << ':' << ino << ' ' << exe;

    out << '\n';
    conn->write_buf = out.str();
    return 0;
}

int daemon_handler::cmd_owner(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2)
    {
        conn->write_buf = "usage: owner <name>\n";
        return 1;
    }

    auto* inst = m_manager.get(pa.args[1]);
    if (!inst)
    {
        conn->write_buf = "runtime not found\n";
        return 1;
    }

    std::ostringstream out;
    auto owner = inst->get_owner();
    out << "name:" << inst->get_name() << "\n";
    out << "owner:" << (owner.empty() ? "-" : std::string(owner)) << "\n";
    out << "on_parent_stop:" << (inst->get_child_policy() == runtime_instance::child_policy::remove ? "remove" : "stop") << "\n";

    auto children = m_manager.get_children(inst->get_name());
    out << "children:" << children.size() << "\n";
    for (auto& c : children)
        out << "  " << c << "\n";

    conn->write_buf = out.str();
    return 0;
}

// ─── Where a message addressed to a name goes ───────────────────────────────
//
// One rule, two callers.  `send` typed at the CLI reaches it through cmd_send()
// below and reports `why` to the terminal; `socketley.send` called in a worker's
// script reaches it through on_worker_deliver() and reports `why` to the log.
//
// Written as one function because the interesting half is the routing — is this
// runtime in this process, in a worker, or nowhere — and two copies of that
// would be two answers to "is a send delivered", which is the question this
// tree has already got wrong once in exactly this place.
bool daemon_handler::deliver_to_runtime(std::string_view name,
                                        std::string_view message,
                                        std::string& why)
{
    auto* instance = m_manager.get(name);
    if (!instance)
    {
        why = "runtime not found: " + std::string(name);
        return false;
    }

    if (instance->get_state() != runtime_running)
    {
        why = "runtime is not running: " + std::string(name);
        return false;
    }

    if (instance->get_type() != runtime_server && instance->get_type() != runtime_client)
    {
        why = "send is only supported for server and client runtimes";
        return false;
    }

    // The connections are wherever the runtime is.
    //
    // This used to switch on the type and call lua_broadcast() straight away,
    // which for a runtime in a worker reached the placeholder: it has the name,
    // the port and the state, and not one connection.  The call succeeded, the
    // command returned 0, and the message went nowhere.  A `send` that reports
    // success and delivers nothing is worse than one that fails.
    if (instance->is_out_of_process())
    {
        // deliver_to_worker() fans the message out across every shard of this
        // runtime and answers true if any of them took it; see the note there
        // for why delivering to one is not an option once there is more than
        // one.
        if (!deliver_to_worker(name, message))
        {
            why = "could not reach the worker holding " + std::string(name);
            return false;
        }
        return true;
    }

    switch (instance->get_type())
    {
        case runtime_server:
        {
            if (auto* srv = instance->as_server(); srv && srv->get_mode() != mode_in)
                srv->lua_broadcast(message);
            break;
        }
        case runtime_client:
        {
            auto* cli = static_cast<client_instance*>(instance);
            if (cli->get_mode() != client_mode_in)
                cli->lua_send(message);
            break;
        }
        default:
            break;
    }

    return true;
}

int daemon_handler::cmd_send(const parsed_args& pa)
{
    if (pa.count < 3)
    {
        std::cout << "usage: send <name> <message>\n";
        return 1;
    }

    std::string why;
    if (!deliver_to_runtime(pa.args[1], pa.rest_from(2), why))
    {
        std::cout << why << "\n";
        return 1;
    }
    return 0;
}

// The same verb arriving from a worker's script instead of from a terminal.
//
// Nothing is answered: the frame is one-way, and the caller's own error cases
// were decided out there against the replica of this map — see the note on
// deliver_to in worker_protocol.h.  What can still go wrong here is what the
// replica was too old to know, so it is said in the log rather than dropped:
// the window is one push interval wide, and a send into it is a message the
// script believes it made.
void daemon_handler::on_worker_deliver(std::string_view name,
                                       std::string_view message)
{
    std::string why;
    if (!deliver_to_runtime(name, message, why))
        LOG_WARN(("a worker's send could not be delivered: " + why).c_str());
}

int daemon_handler::cmd_action(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 3)
    {
        conn->write_buf = "usage: <name> <action> [args]\n";
        return 1;
    }

    std::string_view name = pa.args[1];
    std::string_view action = pa.args[2];

    auto* instance = m_manager.get(name);
    if (!instance)
    {
        conn->write_buf = "runtime not found: " + std::string(name) + "\n";
        return 1;
    }

    if (instance->get_state() != runtime_running)
    {
        conn->write_buf = "runtime is not running: " + std::string(name) + "\n";
        return 1;
    }

    runtime_type type = instance->get_type();

    uint32_t action_hash = fnv1a_lower(action);

    switch (action_hash)
    {
        case fnv1a("get"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "get is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> get <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = cache->lua_get(pa.args[3]);
            if (conn->write_buf.empty())
                conn->write_buf = "nil\n";
            else
                conn->write_buf += '\n';
            return 0;
        }
        case fnv1a("set"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "set is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> set <key> <value>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            std::string_view value = pa.rest_from(4);
            if (!cache->lua_set(pa.args[3], value))
            {
                conn->write_buf = "denied: readonly mode\n";
                return 1;
            }
            return 0;
        }
        case fnv1a("del"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "del is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> del <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            if (cache->get_mode() == cache_mode_readonly)
            {
                conn->write_buf = "denied: readonly mode\n";
                return 1;
            }
            if (!cache->lua_del(pa.args[3]))
                conn->write_buf = "nil\n";
            return 0;
        }
        case fnv1a("size"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "size is only valid for cache runtimes\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = std::to_string(cache->get_size());
            conn->write_buf += '\n';
            return 0;
        }
        case fnv1a("exists"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "exists is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> exists <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = cache->lua_ttl(pa.args[3]) != -2 ? "1\n" : "0\n";
            return 0;
        }

        // ─── List actions ───

        case fnv1a("lpush"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "lpush is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> lpush <key> <value>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            std::string_view value = pa.rest_from(4);
            if (!cache->lua_lpush(pa.args[3], value))
            {
                conn->write_buf = "error: type conflict or readonly\n";
                return 1;
            }
            return 0;
        }
        case fnv1a("rpush"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "rpush is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> rpush <key> <value>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            std::string_view value = pa.rest_from(4);
            if (!cache->lua_rpush(pa.args[3], value))
            {
                conn->write_buf = "error: type conflict or readonly\n";
                return 1;
            }
            return 0;
        }
        case fnv1a("lpop"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "lpop is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> lpop <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = cache->lua_lpop(pa.args[3]);
            if (conn->write_buf.empty())
                conn->write_buf = "nil\n";
            else
                conn->write_buf += '\n';
            return 0;
        }
        case fnv1a("rpop"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "rpop is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> rpop <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = cache->lua_rpop(pa.args[3]);
            if (conn->write_buf.empty())
                conn->write_buf = "nil\n";
            else
                conn->write_buf += '\n';
            return 0;
        }
        case fnv1a("llen"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "llen is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> llen <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = std::to_string(cache->lua_llen(pa.args[3]));
            conn->write_buf += '\n';
            return 0;
        }

        // ─── Set actions ───

        case fnv1a("sadd"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "sadd is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> sadd <key> <member>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            int result = cache->lua_sadd(pa.args[3], pa.args[4]);
            if (result < 0)
            {
                conn->write_buf = "error: type conflict or readonly\n";
                return 1;
            }
            conn->write_buf = result ? "ok\n" : "exists\n";
            return 0;
        }
        case fnv1a("srem"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "srem is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> srem <key> <member>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            if (!cache->lua_srem(pa.args[3], pa.args[4]))
                conn->write_buf = "nil\n";
            return 0;
        }
        case fnv1a("sismember"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "sismember is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> sismember <key> <member>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = cache->lua_sismember(pa.args[3], pa.args[4]) ? "1\n" : "0\n";
            return 0;
        }
        case fnv1a("scard"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "scard is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> scard <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = std::to_string(cache->lua_scard(pa.args[3]));
            conn->write_buf += '\n';
            return 0;
        }

        // ─── Hash actions ───

        case fnv1a("hset"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "hset is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 6)
            {
                conn->write_buf = "usage: <cache> hset <key> <field> <value>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            std::string_view value = pa.rest_from(5);
            if (!cache->lua_hset(pa.args[3], pa.args[4], value))
            {
                conn->write_buf = "error: type conflict or readonly\n";
                return 1;
            }
            return 0;
        }
        case fnv1a("hget"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "hget is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> hget <key> <field>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = cache->lua_hget(pa.args[3], pa.args[4]);
            if (conn->write_buf.empty())
                conn->write_buf = "nil\n";
            else
                conn->write_buf += '\n';
            return 0;
        }
        case fnv1a("hdel"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "hdel is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> hdel <key> <field>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            if (!cache->lua_hdel(pa.args[3], pa.args[4]))
                conn->write_buf = "nil\n";
            return 0;
        }
        case fnv1a("hlen"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "hlen is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> hlen <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = std::to_string(cache->lua_hlen(pa.args[3]));
            conn->write_buf += '\n';
            return 0;
        }

        // ─── TTL actions ───

        case fnv1a("expire"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "expire is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> expire <key> <seconds>\n";
                return 1;
            }
            int seconds;
            auto sv = pa.args[4];
            auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), seconds);
            if (ec != std::errc{} || seconds <= 0)
            {
                conn->write_buf = "error: invalid seconds\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            if (!cache->lua_expire(pa.args[3], seconds))
                conn->write_buf = "nil\n";
            return 0;
        }
        case fnv1a("ttl"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "ttl is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> ttl <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = std::to_string(cache->lua_ttl(pa.args[3]));
            conn->write_buf += '\n';
            return 0;
        }
        case fnv1a("persist"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "persist is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> persist <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            if (!cache->lua_persist(pa.args[3]))
                conn->write_buf = "nil\n";
            return 0;
        }
        case fnv1a("flush"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "flush is only valid for cache runtimes\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            if (cache->get_mode() != cache_mode_admin)
            {
                conn->write_buf = "denied: admin mode required\n";
                return 1;
            }
            std::string_view path = pa.count > 3 ? pa.args[3] : cache->get_persistent();
            if (path.empty())
            {
                conn->write_buf = "no persistent path set\n";
                return 1;
            }
            if (!cache->flush_to(path))
            {
                conn->write_buf = "flush failed\n";
                return 2;
            }
            return 0;
        }
        case fnv1a("load"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "load is only valid for cache runtimes\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            if (cache->get_mode() != cache_mode_admin)
            {
                conn->write_buf = "denied: admin mode required\n";
                return 1;
            }
            std::string_view path = pa.count > 3 ? pa.args[3] : cache->get_persistent();
            if (path.empty())
            {
                conn->write_buf = "no persistent path set\n";
                return 1;
            }
            if (!cache->load_from(path))
            {
                conn->write_buf = "load failed\n";
                return 2;
            }
            return 0;
        }
        case fnv1a("publish"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "publish is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> publish <channel> <message>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            std::string_view message = pa.rest_from(4);
            int count = cache->publish(pa.args[3], message);
            conn->write_buf = std::to_string(count) + "\n";
            return 0;
        }
        case fnv1a("memory"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "memory is only valid for cache runtimes\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            conn->write_buf = std::to_string(cache->get_max_memory()) + " " +
                              std::to_string(cache->store_memory_used()) + "\n";
            return 0;
        }
        case fnv1a("send"):
        {
            if (type != runtime_server && type != runtime_client)
            {
                conn->write_buf = "send is only valid for server/client runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <runtime> send <message>\n";
                return 1;
            }
            std::string_view message = pa.rest_from(3);

            if (type == runtime_server)
            {
                auto* srv = static_cast<server_instance*>(instance);
                if (srv->get_mode() != mode_in)
                    srv->lua_broadcast(message);
            }
            else
            {
                auto* cli = static_cast<client_instance*>(instance);
                if (cli->get_mode() != client_mode_in)
                    cli->lua_send(message);
            }
            return 0;
        }

        // ─── String arithmetic actions (via execute()) ───

        case fnv1a("incr"):
        case fnv1a("decr"):
        case fnv1a("append"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = std::string(action) + " is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> " + std::string(action) + " <key> [value]\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            std::string cmd(pa.rest_from(2));
            conn->write_buf = cache->execute(cmd);
            if (!conn->write_buf.empty() && conn->write_buf.back() != '\n')
                conn->write_buf += '\n';
            return 0;
        }
        case fnv1a("incrby"):
        case fnv1a("decrby"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = std::string(action) + " is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> " + std::string(action) + " <key> <delta>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            std::string cmd(pa.rest_from(2));
            conn->write_buf = cache->execute(cmd);
            if (!conn->write_buf.empty() && conn->write_buf.back() != '\n')
                conn->write_buf += '\n';
            return 0;
        }

        // ─── List range/index actions (via execute()) ───

        case fnv1a("lrange"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "lrange is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 6)
            {
                conn->write_buf = "usage: <cache> lrange <key> <start> <stop>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            std::string cmd(pa.rest_from(2));
            conn->write_buf = cache->execute(cmd);
            if (!conn->write_buf.empty() && conn->write_buf.back() != '\n')
                conn->write_buf += '\n';
            return 0;
        }
        case fnv1a("lindex"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "lindex is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 5)
            {
                conn->write_buf = "usage: <cache> lindex <key> <index>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            std::string cmd(pa.rest_from(2));
            conn->write_buf = cache->execute(cmd);
            if (!conn->write_buf.empty() && conn->write_buf.back() != '\n')
                conn->write_buf += '\n';
            return 0;
        }

        // ─── Set enumeration (via execute()) ───

        case fnv1a("smembers"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "smembers is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> smembers <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            std::string cmd(pa.rest_from(2));
            conn->write_buf = cache->execute(cmd);
            if (!conn->write_buf.empty() && conn->write_buf.back() != '\n')
                conn->write_buf += '\n';
            return 0;
        }

        // ─── Hash enumeration (via execute()) ───

        case fnv1a("hgetall"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "hgetall is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> hgetall <key>\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            std::string cmd(pa.rest_from(2));
            conn->write_buf = cache->execute(cmd);
            if (!conn->write_buf.empty() && conn->write_buf.back() != '\n')
                conn->write_buf += '\n';
            return 0;
        }

        // ─── Multi-key actions (via execute()) ───

        case fnv1a("keys"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "keys is only valid for cache runtimes\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            std::string cmd(pa.rest_from(2));
            conn->write_buf = cache->execute(cmd);
            if (!conn->write_buf.empty() && conn->write_buf.back() != '\n')
                conn->write_buf += '\n';
            return 0;
        }
        case fnv1a("mget"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "mget is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 4)
            {
                conn->write_buf = "usage: <cache> mget <key1> [key2] ...\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            std::string cmd(pa.rest_from(2));
            conn->write_buf = cache->execute(cmd);
            if (!conn->write_buf.empty() && conn->write_buf.back() != '\n')
                conn->write_buf += '\n';
            return 0;
        }
        case fnv1a("mset"):
        {
            if (type != runtime_cache)
            {
                conn->write_buf = "mset is only valid for cache runtimes\n";
                return 1;
            }
            if (pa.count < 6)
            {
                conn->write_buf = "usage: <cache> mset <key1> <val1> [key2] [val2] ...\n";
                return 1;
            }
            auto* cache = static_cast<cache_instance*>(instance);
            std::string cmd(pa.rest_from(2));
            conn->write_buf = cache->execute(cmd);
            if (!conn->write_buf.empty() && conn->write_buf.back() != '\n')
                conn->write_buf += '\n';
            return 0;
        }
        default:
            conn->write_buf = "unknown action: " + std::string(action) + "\n";
            return 1;
    }
}

// Same as cmd_create: guarded by process_command, along with every other command.
int daemon_handler::cmd_edit([[maybe_unused]] ipc_connection* conn,
                             const parsed_args& pa)
{
    if (pa.count < 3)
    {
        std::cout << "usage: edit <name> [flags]\n";
        return 1;
    }

    std::string_view name = pa.args[1];
    auto* instance = m_manager.get(name);
    if (!instance)
    {
        std::cout << "runtime not found: " << name << "\n";
        return 1;
    }

    runtime_type type = instance->get_type();
    bool is_running = instance->get_state() == runtime_running;

    // What the runtime's TLS configuration was before this edit.  The flags
    // are applied one at a time as they are parsed, but they only mean
    // anything as a set — and a set that comes out incomplete has to leave no
    // trace, or an operator who mistyped `--key` is left with a runtime whose
    // in-memory configuration no longer matches its state file.
    const bool        tls_before  = instance->get_tls();
    const std::string cert_before(instance->get_cert_path());
    const std::string key_before(instance->get_key_path());
    const std::string ca_before(instance->get_ca_path());
    // The same rule for the same reason, one set along: --shards and --listen
    // are only meaningful together, and a pair that comes out incompatible has
    // to leave the runtime exactly as it found it.
    const uint32_t    shards_before = instance->get_shards();
    const std::string listen_before(instance->get_listen_path());
    // The proxy's half of the same set.  Its backend leg is configured by
    // three more paths, and they are as much a set as the listener's: half a
    // client-certificate pair is refused, so an edit that leaves one behind
    // has to leave no trace either.
    std::string_view mca_v, mcert_v, mkey_v;
    instance->get_mesh_tls_paths(mca_v, mcert_v, mkey_v);
    const std::string mesh_ca_before(mca_v), mesh_cert_before(mcert_v),
                      mesh_key_before(mkey_v);

    for (size_t i = 2; i < pa.count; ++i)
    {
        int result = parse_common_edit_flags(instance, pa, i, is_running);
        if (result == -1)
        {
            switch (type)
            {
                case runtime_server:
                    result = parse_server_edit_flags(
                        static_cast<server_instance*>(instance), pa, i, is_running, &m_manager);
                    break;
                case runtime_client:
                    result = parse_client_edit_flags(
                        static_cast<client_instance*>(instance), pa, i, is_running);
                    break;
                case runtime_proxy:
                    result = parse_proxy_edit_flags(
                        static_cast<proxy_instance*>(instance), pa, i);
                    break;
                case runtime_cache:
                    // There is no parse_cache_edit_flags, so every
                    // cache-specific flag falls through to the refusal below.
                    // That is a decision rather than an omission — `import` is
                    // the fuller of the two ways to reconfigure a runtime and
                    // applies all of these — but "unknown flag" was the wrong
                    // sentence for it: the flag exists, spelling it differently
                    // will not help, and the operator needs to be sent to the
                    // command that does take it.
                    result = -1;
                    break;
            }
        }

        if (result == -1)
        {
            static constexpr uint32_t cache_only[] = {
                fnv1a("--maxmemory"), fnv1a("--eviction"), fnv1a("--persistent"),
                fnv1a("--replicate"), fnv1a("--resp"),
            };
            bool is_cache_flag = false;
            for (uint32_t h : cache_only)
                if (pa.hashes[i] == h) { is_cache_flag = true; break; }

            if (is_cache_flag && type == runtime_cache)
            {
                std::cout << pa.args[i] << " cannot be changed with `edit`\n"
                             "  A cache's own settings are applied by `import`:\n"
                             "    socketley show " << name
                          << " > cfg.json   # edit the field, then\n"
                             "    socketley import " << name << " < cfg.json\n";
                return 1;
            }

            std::cout << "unknown flag: " << pa.args[i] << "\n";
            return 1;
        }

        if (result > 0)
            return result;
    }

    if (const std::string msg = instance_tls_refusal(instance); !msg.empty())
    {
        instance->set_tls(tls_before);
        instance->set_cert_path(cert_before);
        instance->set_key_path(key_before);
        instance->set_ca_path(ca_before);
        if (type == runtime_proxy)
        {
            auto* prx = static_cast<proxy_instance*>(instance);
            prx->set_mesh_client_ca(mesh_ca_before);
            prx->set_mesh_client_cert(mesh_cert_before);
            prx->set_mesh_client_key(mesh_key_before);
        }
        std::cout << msg;
        return 1;
    }

    // The shard set, checked here for the reason the TLS set is: --listen and
    // --shards are both editable, and either can be the flag that completes an
    // incompatible pair.  `edit srv --listen unix:/tmp/s.sock` on a runtime
    // already carrying --shards 4 is refused by nothing in the --listen case
    // label, because that label has no reason to know about shards.
    //
    // Rolled back the same way and for the same sentence: a set that comes out
    // incomplete has to leave no trace, or an operator who mistyped one flag is
    // left with a runtime whose in-memory configuration no longer matches its
    // state file.
    if (const std::string msg = instance_shards_refusal(instance); !msg.empty())
    {
        instance->set_shards(shards_before);
        instance->set_listen_path(listen_before);
        std::cout << msg;
        return 1;
    }

    if (m_persistence)
        m_persistence->save_runtime(instance);

    return 0;
}

int daemon_handler::cmd_dump(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2)
    {
        conn->write_buf = "usage: show <name|pattern>...\n";
        return 1;
    }

    if (!m_persistence)
    {
        conn->write_buf = "state persistence not available\n";
        return 2;
    }

    auto names = resolve_names(pa);
    int rc = check_empty_names(names, pa, "runtime not found: ", conn);
    if (rc >= 0) return rc;

    bool first = true;
    for (const auto& n : names)
    {
        auto* inst = m_manager.get(n);
        if (!inst)
            continue;
        if (!first)
            conn->write_buf += '\n';
        first = false;
        runtime_config cfg = m_persistence->read_from_instance(inst);
        conn->write_buf += m_persistence->format_json_pretty(cfg);
    }
    return 0;
}

int daemon_handler::cmd_import(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 3)
    {
        conn->write_buf = "usage: import <name> <json>\n";
        return 1;
    }

    std::string_view name = pa.args[1];
    auto* instance = m_manager.get(name);
    if (!instance)
    {
        conn->write_buf = "runtime not found: " + std::string(name) + "\n";
        return 1;
    }

    if (!m_persistence)
    {
        conn->write_buf = "state persistence not available\n";
        return 2;
    }

    // Extract JSON from everything after the name
    std::string json_str(pa.rest_from(2));
    runtime_config cfg;
    if (!m_persistence->parse_json_string(json_str, cfg))
    {
        conn->write_buf = "invalid JSON\n";
        return 1;
    }

    // The listener field, judged by the same function the flag is.  It has to
    // be re-read from the document rather than taken from cfg, because
    // parse_json_string has no error channel for a single field: it strips the
    // `unix:` prefix and leaves the field empty when there is none, which is
    // indistinguishable from a document that clears it on purpose.  Without
    // this, `"listen": "/run/x.sock"` -- the same value with the prefix
    // forgotten -- imported as "no unix listener at all" and the server came
    // back on a TCP port, reported by nothing.
    if (cfg.has("listen"))
    {
        const std::string raw = m_persistence->raw_field(json_str, "listen");
        if (!raw.empty())
        {
            std::string parsed;
            const std::string why = validate_listen_value(raw, parsed);
            if (!why.empty())
            {
                conn->write_buf = "listen: " + why + "\n";
                return 1;
            }
        }
    }

    bool is_running = instance->get_state() == runtime_running;
    runtime_type type = instance->get_type();

    // Same gate as the create path: a config carrying TLS this build cannot
    // honour is rejected before anything is applied or written back to the
    // state file.
    //
    // ─── JUDGED ON THE RESULT, NOT ON THE DOCUMENT ──────────────────────────
    //
    // This used to read cfg directly, on the reasoning that a document which
    // omits the TLS fields is clearing them — which was true when every field
    // was applied unconditionally.  It is not any more: an omitted field now
    // leaves the runtime's own value in place (see the apply block below), so
    // reading cfg would judge a configuration that is not the one about to
    // exist.
    //
    // Concretely, and this is the hole it would have opened: a TLS cache with
    // no replication, handed a document that names only replicate_target.  cfg
    // says tls=false, the gate passes, and the apply gives it a replication
    // leg — the exact cleartext-replication pair tls_config_refusal exists to
    // refuse.  So each value is taken from the document where the document
    // names it and from the instance where it does not, which is what the
    // runtime will be carrying a few lines from now.
    std::string_view inst_mca, inst_mcert, inst_mkey;
    instance->get_mesh_tls_paths(inst_mca, inst_mcert, inst_mkey);

    const auto merged = [&cfg](const char* key, auto from_doc, auto from_inst) {
        return cfg.has(key) ? from_doc : from_inst;
    };

    const bool        eff_tls  = merged("tls", cfg.tls, instance->get_tls());
    const bool        eff_udp  = merged("udp", cfg.udp, instance->is_udp());
    const std::string eff_cert = merged("cert_path", cfg.cert_path,
                                        std::string(instance->get_cert_path()));
    const std::string eff_key  = merged("key_path", cfg.key_path,
                                        std::string(instance->get_key_path()));
    const std::string eff_ca   = merged("ca_path", cfg.ca_path,
                                        std::string(instance->get_ca_path()));
    const std::string eff_mca  = merged("mesh_client_ca", cfg.mesh_client_ca,
                                        std::string(inst_mca));
    const std::string eff_mcrt = merged("mesh_client_cert", cfg.mesh_client_cert,
                                        std::string(inst_mcert));
    const std::string eff_mkey = merged("mesh_client_key", cfg.mesh_client_key,
                                        std::string(inst_mkey));
    const std::string eff_repl = merged("replicate_target", cfg.replicate_target,
                                        std::string(instance->get_replication_target()));

    if (const std::string msg = tls_config_refusal(type,
                                                   eff_tls, eff_udp, eff_cert, eff_key,
                                                   eff_ca, eff_mca, eff_mcrt, eff_mkey,
                                                   eff_repl);
        !msg.empty())
    {
        conn->write_buf = msg;
        return 1;
    }

    // The shard set, merged the same way and for the same reason.  Reading cfg
    // alone would judge a configuration that is not the one about to exist: a
    // document naming only `shards` on a server that already carries a script
    // says lua_script="" and would pass, and the apply would then produce
    // exactly the sharded scripted server the flag parser refuses.
    //
    // Before the apply rather than after it, because import has no rollback: it
    // writes each field as it reads it, so a refusal that came later would
    // leave the runtime half-changed and its state file disagreeing with it.
    const uint32_t    eff_shards = merged("shards", cfg.shards,
                                          instance->get_shards());
    const std::string eff_lua    = merged("lua_script", cfg.lua_script,
                                          std::string(instance->get_lua_script_path()));
    const std::string eff_listen = merged("listen", cfg.listen_path,
                                          std::string(instance->get_listen_path()));

    if (const std::string msg = shards_config_refusal(type, eff_shards,
                                                      !eff_lua.empty(), eff_listen,
                                                      instance->is_out_of_process());
        !msg.empty())
    {
        conn->write_buf = msg;
        return 1;
    }

    // Handle rename
    std::string old_name(name);
    bool renamed = false;
    if (!cfg.name.empty() && cfg.name != old_name)
    {
        if (is_running)
        {
            conn->write_buf = "cannot rename while running\n";
            return 1;
        }
        // Two reasons, said apart.  rename() refuses a taken name and an
        // invalid one, and "already taken" for a name with a slash in it sends
        // the operator looking for a runtime that does not exist — the same
        // defect cmd_create still has one command over.
        if (!runtime_manager::valid_name(cfg.name))
        {
            conn->write_buf = "invalid runtime name: " + cfg.name + "\n"
                "  A name may contain letters, digits, '-', '_' and '.', "
                "may not begin with '.',\n"
                "  and may be at most 128 characters.\n";
            return 1;
        }
        if (!m_manager.rename(old_name, cfg.name))
        {
            conn->write_buf = "rename failed: name already taken\n";
            return 1;
        }
        // Re-fetch instance under new name
        instance = m_manager.get(cfg.name);
        renamed = true;
    }

    // Validate changes that require restart
    if (is_running)
    {
        if (cfg.port != instance->get_port())
        {
            conn->write_buf = "cannot change port while running\n";
            return 1;
        }
        // The listener's other spelling, under the same rule.  A running
        // server is bound to the socket node it has; moving it would mean
        // unbinding one path and binding another underneath whatever is already
        // connected, and the node the old listener owns would be left for the
        // teardown that never came.
        if (cfg.listen_path != std::string(instance->get_listen_path()))
        {
            conn->write_buf = "cannot change the listen socket while running\n";
            return 1;
        }
        // The same rule as the port above, and as `edit --shards`: applying it
        // to a running proxy would mean retiring workers out from under live
        // connections.  Refused rather than quietly dropped — see the note
        // where the field is applied below for what quietly dropping it cost.
        if (cfg.shards != instance->get_shards())
        {
            conn->write_buf = "cannot change the shard count while running\n";
            return 1;
        }
        if (cfg.tls != instance->get_tls())
        {
            conn->write_buf = "cannot change TLS while running\n";
            return 1;
        }
        if (type == runtime_server || type == runtime_client)
        {
            bool cur_udp = instance->is_udp();
            if (cfg.udp != cur_udp)
            {
                conn->write_buf = "cannot change protocol while running\n";
                return 1;
            }
        }
        if (type == runtime_client)
        {
            if (cfg.target != std::string(instance->get_target()))
            {
                conn->write_buf = "cannot change target while running\n";
                return 1;
            }
        }
        if (type == runtime_proxy)
        {
            auto* prx = static_cast<proxy_instance*>(instance);
            if (cfg.protocol != static_cast<uint8_t>(prx->get_protocol()))
            {
                conn->write_buf = "cannot change protocol while running\n";
                return 1;
            }
        }
        if (type == runtime_cache)
        {
            auto* cache = static_cast<cache_instance*>(instance);
            if (cfg.resp_forced != cache->get_resp_forced())
            {
                conn->write_buf = "cannot change RESP mode while running\n";
                return 1;
            }
            if (cfg.replicate_target != std::string(cache->get_replicate_target()))
            {
                conn->write_buf = "cannot change replication while running\n";
                return 1;
            }
        }
    }

    // ─── ONLY WHAT THE DOCUMENT NAMES ───────────────────────────────────────
    //
    // Every field in runtime_config has a default, and this used to apply all
    // of them unconditionally — so a document that left a field out cleared it.
    // Measured, against a runtime with a port, a log path, two limits and a
    // complete TLS set:
    //
    //     socketley import c '{"name":"c"}'
    //     exit 0, no output
    //     ... and port, log_file, max_connections, idle_timeout, tls,
    //         cert_path and key_path were all gone.
    //
    // A runtime configured to speak TLS answered in cleartext afterwards, and
    // the command that did it reported success.  The whole tls_config_refusal
    // apparatus misses it, because it judges the INCOMING document and that
    // document no longer has any TLS in it to be incomplete.
    //
    // ─── CLEARING IS STILL POSSIBLE, AND IS NOW SAID OUT LOUD ───────────────
    //
    // Emptying a field was the documented escape hatch — dump, delete the
    // lines, import — and it stays available: `"tls": false`, `"cert_path": ""`.
    // What changes is that it has to be written rather than implied.  The
    // ordinary round trip is unaffected, because `show` emits every field.
    const auto has = [&cfg](const char* key) { return cfg.has(key); };

    if (has("port"))              instance->set_port(cfg.port);
    if (has("listen"))            instance->set_listen_path(cfg.listen_path);
    if (has("log_file"))          instance->set_log_file(cfg.log_file);
    if (has("write_file"))        instance->set_write_file(cfg.write_file);
    if (has("bash_output"))       instance->set_bash_output(cfg.bash_output);
    if (has("bash_prefix"))       instance->set_bash_prefix(cfg.bash_prefix);
    if (has("bash_timestamp"))    instance->set_bash_timestamp(cfg.bash_timestamp);
    // ─── The three flags a client does not have, refused here too ───────────
    //
    // create and edit refuse --rate-limit, --max-connections and --idle-timeout
    // on a client, because it accepts no connections and there is nothing for
    // any of them to limit.  import writes the same fields through a different
    // door: it does not go through the flag parser at all, so the refusal did
    // not exist here.  Measured, on a build where create already said no:
    //
    //     socketley show c | jq '.rate_limit = 5' | socketley import c   -> 0
    //     socketley show c                          -> "rate_limit": 5
    //
    // which is the same shape as 4af38f0, where import could give a runtime a
    // name create would have refused.  A validation that only guards one entrance
    // is a validation that is not there.
    //
    // Refused rather than ignored: silently dropping a field the caller wrote
    // makes `show | import` stop being a round trip, and the caller is told
    // nothing.  The whole document is rejected, so nothing half-applies.
    if (type == runtime_client)
    {
        const char* offender = has("rate_limit")      ? "rate_limit"
                             : has("max_connections") ? "max_connections"
                             : has("idle_timeout")    ? "idle_timeout"
                             : nullptr;
        if (offender)
        {
            conn->write_buf = std::string("\"") + offender +
                  "\" does not apply to a client: it accepts no connections, so "
                  "there is nothing to limit or to time out. Remove the field and "
                  "import again.\n";
            return 1;
        }
    }

    if (has("max_connections"))   instance->set_max_connections(cfg.max_connections);
    if (has("rate_limit"))        instance->set_rate_limit(cfg.rate_limit);
    if (has("global_rate_limit")) instance->set_global_rate_limit(cfg.global_rate_limit);
    if (has("idle_timeout"))      instance->set_idle_timeout(cfg.idle_timeout);
    if (has("drain"))             instance->set_drain(cfg.drain);
    if (has("reconnect"))         instance->set_reconnect(cfg.reconnect);
    if (has("tls"))               instance->set_tls(cfg.tls);
    if (has("cert_path"))         instance->set_cert_path(cfg.cert_path);
    if (has("key_path"))          instance->set_key_path(cfg.key_path);
    if (has("ca_path"))           instance->set_ca_path(cfg.ca_path);
    if (has("target"))            instance->set_target(cfg.target);
    if (has("cache_name"))        instance->set_cache_name(cfg.cache_name);
    if (has("group"))             instance->set_group(cfg.group);
    // Carried into this form from the block it replaced.  `show` emits shards,
    // so a round trip that did not read it back would return a sharded proxy
    // with one worker -- reported Up by `ls` and wrong by nothing.  set_shards
    // clamps, so a hand-edited 0 or 900 becomes 1 or 64 rather than a runtime
    // with no worker at all.
    if (has("shards"))            instance->set_shards(cfg.shards);

    // Lua script: reload if changed — and only when the document says which
    // script it wants.  Without the guard, a partial document reads as
    // lua_script="" and detaches the runtime's handler.
    std::string cur_lua(instance->get_lua_script_path());
    if (has("lua_script") && cfg.lua_script != cur_lua)
    {
        if (!cfg.lua_script.empty())
        {
            if (!instance->load_lua_script(cfg.lua_script))
            {
                conn->write_buf = "could not load Lua script: " + cfg.lua_script + "\n";
                // Same reason as the --lua flag's: the parse error or the
                // validator's sentence is on stderr, which is the daemon's log
                // rather than the terminal that asked for this.
                if (!lua_diag::text().empty())
                    conn->write_buf += lua_diag::text() + "\n";
                return 1;
            }
        }
    }

    // Apply type-specific fields
    switch (type)
    {
        case runtime_server:
        {
            auto* srv = static_cast<server_instance*>(instance);
            if (has("mode")) srv->set_mode(static_cast<server_mode>(cfg.mode));
            if (has("udp"))  srv->set_udp(cfg.udp);
            if (!cfg.cache_name.empty())
                srv->set_runtime_manager(&m_manager);
            if (!cfg.master_pw.empty())
                srv->set_master_pw(cfg.master_pw);
            if (cfg.master_forward)
                srv->set_master_forward(true);

            // The list is replaced only when the document names it.  Clearing
            // it on a document that never mentioned upstreams is the same
            // silent loss as the common fields above, and the loudest version
            // of it: a server whose upstream leg simply stops existing.
            if (!has("upstreams")) break;
            srv->clear_upstream_targets();
            for (const auto& u : cfg.upstreams)
            {
                // Reported rather than dropped.  This is a document a person
                // edited, and the list was cleared a line ago — silently
                // storing fewer upstreams than the document names is the
                // half-applied import this command already refuses elsewhere.
                if (!srv->add_upstream_target(u))
                {
                    conn->write_buf = "invalid upstream address: " + u +
                                      " (the port must be a number between 1 and 65535)\n";
                    return 1;
                }
            }
            break;
        }
        case runtime_client:
        {
            auto* cli = static_cast<client_instance*>(instance);
            if (has("mode")) cli->set_mode(static_cast<client_mode>(cfg.mode));
            if (has("udp"))  cli->set_udp(cfg.udp);
            break;
        }
        case runtime_proxy:
        {
            auto* prx = static_cast<proxy_instance*>(instance);
            if (has("protocol")) prx->set_protocol(static_cast<proxy_protocol>(cfg.protocol));
            if (has("strategy")) prx->set_strategy(static_cast<proxy_strategy>(cfg.strategy));
            if (has("backends"))
            {
                prx->clear_backends();
                for (const auto& b : cfg.backends)
                    prx->add_backend(b);
            }
            prx->set_runtime_manager(&m_manager);
            // The clearing half of the escape hatch: without it a proxy
            // restored from a state file with mesh mTLS paths could never be
            // emptied, and would refuse to start forever.  Each is applied only
            // when the document names it, so emptying is now written as
            // `"mesh_client_ca": ""` rather than by leaving the key out — the
            // gate above judged whatever this is about to produce.
            if (has("mesh_client_ca"))   prx->set_mesh_client_ca(cfg.mesh_client_ca);
            if (has("mesh_client_cert")) prx->set_mesh_client_cert(cfg.mesh_client_cert);
            if (has("mesh_client_key"))  prx->set_mesh_client_key(cfg.mesh_client_key);
            break;
        }
        case runtime_cache:
        {
            auto* cache = static_cast<cache_instance*>(instance);
            if (has("persistent_path"))  cache->set_persistent(cfg.persistent_path);
            if (has("cache_mode"))       cache->set_mode(static_cast<cache_mode>(cfg.cache_mode));
            if (has("resp_forced"))      cache->set_resp_forced(cfg.resp_forced);
            if (has("replicate_target")) cache->set_replicate_target(cfg.replicate_target);
            if (has("max_memory"))       cache->set_max_memory(cfg.max_memory);
            if (has("eviction"))         cache->set_eviction(static_cast<eviction_policy>(cfg.eviction));
            break;
        }
    }

    if (renamed)
        m_persistence->remove_runtime(old_name);
    m_persistence->save_runtime(instance);
    return 0;
}

int daemon_handler::cmd_stats(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2)
    {
        conn->write_buf = "usage: stats <name|pattern>...\n";
        return 1;
    }

    auto names = resolve_names(pa);
    int rc = check_empty_names(names, pa, "runtime not found: ", conn);
    if (rc >= 0) return rc;

    // Take whatever the workers have sent since the last tick, so an
    // out-of-process proxy answers about now rather than about the last health
    // timer.  Costs a non-blocking read per worker and nothing at all when
    // there are none.
    poll_proxy_workers();

    for (const auto& n : names)
    {
        auto* inst = m_manager.get(n);
        if (inst)
        {
            conn->write_buf += inst->get_stats();

            // Say how old these are when they were not read here.
            //
            // Every figure above is identical whichever side the runtime runs
            // on — that is the property the split was built to have — and that
            // is exactly what makes the difference invisible: an in-process
            // runtime's counters are read at this instant, a worker's were
            // pushed up to a quarter of a second ago and drained by the
            // poll_proxy_workers() above.  The values agree; their age does not,
            // and an operator comparing a proxy's byte count against a backend's
            // has no way to know which of the two they are holding.
            //
            // Reported rather than removed: making it live would mean asking the
            // child and waiting for the answer on this thread.  See
            // runtime_instance::worker_stats_age_ms().
            //
            // Only for a runtime that has actually reported.  An in-process one
            // never prints these lines, so nothing that reads `stats` today sees
            // a new field appear.
            if (inst->worker_backed())
            {
                conn->write_buf += "figures:pushed\nfigures_age_ms:";
                conn->write_buf += std::to_string(inst->worker_stats_age_ms());
                conn->write_buf += '\n';
            }

            // Which process this runtime is actually in.
            //
            // The supervisor has called set_pid(child) since the split landed
            // and nothing ever printed it, so the one question an operator has
            // about an out-of-process runtime — where do I look for it, which
            // process do I strace, whose RSS is this — had no answer from the
            // tool that knows it.  `figures:pushed` says the runtime is
            // elsewhere without saying where.
            //
            // Printed from the daemon's own record rather than from
            // get_stats(), because for a worker-backed runtime that string was
            // built in the child and pushed: the child knows its pid and the
            // daemon knows which child it is, and only the daemon's answer is
            // still right after a restart has replaced the process.
            //
            // Emitted only when there is a process to name, so an in-process
            // runtime's output is unchanged.  Managed external runtimes set the
            // same field and get the same line, which is the same question.
            // ─── With shards there is more than one process to name ─────────
            //
            // set_pid() is called by every supervisor against the one
            // placeholder, so `pid:` alone answers with whichever shard was
            // forked last — a true pid for a real process, and the wrong answer
            // to "which process is this runtime in", because there are four and
            // it names one of them arbitrarily.
            //
            // So a sharded runtime gets the count and the whole list, and an
            // unsharded one gets exactly the line it got before: `shards:` is
            // omitted at 1, and `pid:` still prints the single pid.  Nothing
            // that reads `stats` today sees a field appear.
            if (auto it = m_proxy_workers.find(n);
                it != m_proxy_workers.end() && it->second.size() > 1)
            {
                conn->write_buf += "shards:";
                conn->write_buf += std::to_string(it->second.size());
                conn->write_buf += "\nshard_pids:";
                bool first = true;
                for (const auto& sup : it->second)
                {
                    if (!first)
                        conn->write_buf += ',';
                    first = false;
                    conn->write_buf +=
                        std::to_string(static_cast<long long>(sup->pid()));
                }
                conn->write_buf += '\n';
            }
            else if (const pid_t rpid = inst->get_pid(); rpid > 0)
            {
                conn->write_buf += "pid:";
                conn->write_buf += std::to_string(static_cast<long long>(rpid));
                conn->write_buf += '\n';
            }

            conn->write_buf += '\n';
        }
    }
    return 0;
}

int daemon_handler::cmd_reload(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2)
    {
        conn->write_buf = "usage: reload <name|pattern>...\n";
        return 1;
    }

    auto names = resolve_names(pa);
    int rc = check_empty_names(names, pa, "runtime not found: ", conn);
    if (rc >= 0) return rc;

    int refused = 0;
    // What this command actually brought back up; see the wait below.
    std::vector<std::string> restarted;
    for (const auto& n : names)
    {
        auto* inst = m_manager.get(n);
        if (!inst || inst->get_state() != runtime_running)
            continue;
        // reload is a stop followed by a start, so it is a start: refuse
        // before touching the runtime rather than tearing it down and
        // bringing it back up in cleartext.
        if (const std::string msg = instance_tls_refusal(inst); !msg.empty())
        {
            conn->write_buf += std::string(n) + ": " + msg;
            ++refused;
            continue;
        }
        // A reload is a start, so it asks a start's questions -- and refuses
        // before touching the runtime rather than tearing down a working
        // listener to discover it cannot be brought back.
        if (const std::string msg = instance_shards_refusal(inst); !msg.empty())
        {
            conn->write_buf += std::string(n) + ": " + msg;
            ++refused;
            continue;
        }
        m_manager.stop(n, m_loop);

        // ─── The child comes down here, or the reload never reaches it ──────
        //
        // Without this line `reload` did nothing at all to a runtime in a
        // worker, which since 2313c26 is every runtime that did not ask
        // otherwise.  The two calls around it move the PLACEHOLDER's state to
        // stopped and back to running, and reconciliation is what turns a
        // placeholder's state into a live child — so reconciling only at the
        // end sees `running`, the same thing it saw before, and leaves the
        // original child alone.  Measured on the parent commit, a worker-backed
        // server whose script was edited under it:
        //
        //     reload   exit 0   (silence)   ls: Up   — old script still serving
        //
        // The command reported success for a reload that had not happened, and
        // the script the operator had just edited was not running anywhere.
        // With the child taken down while the placeholder says stopped, the
        // reconcile after the loop forks a fresh one that reads the new file:
        //
        //     reload   exit 1   "on_start error: ..."          — the new script
        //     reload   exit 1   "the worker did not accept ..."  ls: Failed
        //
        // Per name rather than once for the whole command, because the start
        // that follows is per name too: batching the stops would take every
        // named runtime down before bringing any back, which is a different
        // command from the one this is.
        reconcile_proxy_workers();

        if (m_manager.start(n, m_loop) && m_persistence)
        {
            m_persistence->set_was_running(n, true);
            restarted.push_back(n);
        }

        // The on_start report is read in the collect pass below, for the reason
        // cmd_start gives at the same point: when the script runs in a worker
        // the reason is a frame that has not been asked for yet.
    }

    // The same sentence a third time: reload is a stop followed by a start, so
    // it is a start, and a start now brings the child back and waits for it.
    //
    // Neither half was here.  A worker-backed runtime reloaded through this
    // command had its placeholder flipped and nothing else: the child came back
    // on the health tick up to two seconds later, and the command returned 0 in
    // the meantime — including for a configuration the child was about to
    // refuse, which `ls` then showed as Failed.  Reconciling here is what
    // cmd_start's own comment gives the reason for, one command along: it is
    // what makes `reload` followed immediately by a request work.
    if (!restarted.empty())
    {
        reconcile_proxy_workers();

        const auto deadline = std::chrono::steady_clock::now() + worker_startup_bound;
        for (const auto& n : restarted)
        {
            std::string wmsg;
            if (await_worker_startup(n, wmsg, deadline) != 0)
            {
                conn->write_buf += wmsg;
                ++refused;
                continue;
            }

            // "reload is a stop followed by a start, so it is a start" — the
            // sentence this command is already written under, applied to the
            // other thing a start answers for.  Leaving it out would put the
            // inconsistency back one command along: the same script and the
            // same raise reported by `start` and not by the command that is a
            // start.
            if (std::string why = on_start_error(n); !why.empty())
            {
                conn->write_buf += "reload " + std::string(n) + ": " + why + "\n"
                                 + "the runtime is running, with whatever on_start "
                                   "established before it raised; fix the script and "
                                   "run `reload-lua " + std::string(n) + "` to re-run it.\n";
                ++refused;
            }
        }
    }

    return refused > 0 ? 1 : 0;
}


int daemon_handler::cmd_reload_lua(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2)
    {
        conn->write_buf = "usage: reload-lua <name|pattern>...\n";
        return 1;
    }

    auto names = resolve_names(pa);
    int rc = check_empty_names(names, pa, "runtime not found: ", conn);
    if (rc >= 0) return rc;

    // A runtime whose script runs in a worker has to be asked, and the answer
    // waited for.  Every reload is sent before any of them is waited on, so
    // reloading N runtimes costs one round trip rather than N of them.
    std::vector<std::tuple<proxy_supervisor*, const void*, std::string>> pending;

    // ─── A reload that did not happen is not a success ──────────────────────
    //
    // The bool from reload_lua_script() was discarded here, so `reload-lua`
    // answered 0 with an empty reply for a script that no longer compiled — and
    // the reason went to stderr, which is the daemon's log rather than the
    // terminal of whoever ran the command.  An operator edited a file, ran
    // this, was told nothing, and went on believing the edit was live.  The
    // previous script stays in force in that case, which is the right
    // behaviour and the worst possible one to be silent about: everything
    // keeps working, and it keeps working the old way.
    //
    // Failures are collected rather than returned at the first: `reload-lua`
    // takes a pattern, and reloading eight runtimes of which two are broken
    // should say which two.  The other six are still reloaded.
    std::string failures;
    auto note_failure = [&failures](std::string_view name, std::string_view why) {
        failures += "reload-lua ";
        failures += name;
        failures += ": ";
        failures += why.empty() ? std::string_view("the script did not load") : why;
        failures += '\n';
    };

    for (const auto& n : names)
    {
        auto* inst = m_manager.get(n);

        // The script lives in the worker, and the daemon's copy of this runtime
        // is a placeholder that compiled the file once and discarded it.  So
        // reloading here would re-read the file into an interpreter that does
        // not serve anything, and would still leave the process that does
        // serving running the old one.
        if (auto it = m_proxy_workers.find(n); it != m_proxy_workers.end() &&
                                               !it->second.empty())
        {
            // Read before the ask, so the answer cannot be missed for having
            // arrived between the two.
            const void* prev = inst ? inst->worker_routes().get() : nullptr;

            // Every shard re-runs the script, because every shard IS running
            // it: reloading one would leave the other three serving the file
            // the operator has just replaced, which is the exact failure this
            // command was given a worker path to avoid.
            for (auto& sup : it->second)
                sup->send_reload();

            // Waited on through shard 0 alone, and that is a statement about
            // the declaration rather than about the reload.  Every shard reads
            // the same file and produces the same `routes` frame into the same
            // placeholder, so waiting for a second one would be waiting for a
            // value already written.  Whether each shard's reload SUCCEEDED is
            // a different question and is asked of all of them — see the error
            // collection at the end of this command.
            pending.emplace_back(it->second.front().get(), prev, n);
            continue;
        }

        // The two preconditions reload_lua_script() returns false on without
        // anything having gone wrong — no script, and a runtime that is not
        // running — are checked here rather than reported.  A stopped runtime
        // loads its script when it is started, so "nothing to reload" is not a
        // failure and must not print like one; only a file that would not load
        // is.  Everything past this point that answers false has written a
        // reason, which is what note_failure carries.
        if (inst && !inst->get_lua_script_path().empty() &&
            inst->get_state() == runtime_running)
        {
            lua_diag::clear();
            if (!inst->reload_lua_script())
                note_failure(n, lua_diag::text());
        }
        // Rebuild HTTP file cache on reload-lua (picks up new/changed files)
        if (inst && inst->get_type() == runtime_server)
        {
            auto* srv = static_cast<server_instance*>(inst);
            if (srv->get_http_cache() && !srv->get_http_dir().empty())
                srv->rebuild_http_cache();
        }
    }

    // ─── The publish waits for the declarations it is meant to carry ────────
    //
    // `reload-lua` is the command that makes "the declaration is published, not
    // configured" true: an operator edits a handler's script, runs this, and
    // expects the gateway in front of it to enforce the new declaration on the
    // very next request.  Returning as soon as the frames were written would
    // publish whatever the daemon happened to be holding -- which is the
    // previous version of exactly the thing being changed -- and the new one
    // would land on the health tick up to two seconds later.  The command would
    // report success for a change that had not taken effect yet, which is the
    // same shape of false success `create` was fixed for.
    //
    // This is the control path.  It waits on the IPC socket already, and the
    // rule against synchronous cross-runtime calls is about the data path,
    // where a request would have to suspend across a round trip.  The bound is
    // the one `create` uses, for the reason given there: one timescale in this
    // file rather than two.  A worker that never answers leaves the declaration
    // it had in force, and the publish below carries that.
    for (auto& [sup, prev, name] : pending)
    {
        if (!sup->await_routes(prev, worker_startup_bound))
            LOG_WARN("reload-lua: a worker did not report its declaration in "
                     "time; the gateway keeps enforcing the previous one");
        // Read after the wait, never before: the child writes reload_err ahead
        // of the routes frame the wait ends on, so by here it has been ingested
        // if it was sent at all.  Empty means the reload loaded.
        //
        // Asked of every shard and not only the one waited on.  `sup` is shard
        // 0 — see where `pending` is filled, and why waiting on one is right for
        // the DECLARATION — but whether a reload succeeded is per process: a
        // file that loads in one and raises in another is unlikely and is
        // exactly the case a report is for.  Reported once, from the first
        // shard that has a reason, because four copies of one diagnostic is not
        // four pieces of information; taken from all of them regardless,
        // because take_ is destructive and a reason left behind would be handed
        // to the next reload as its own answer.
        std::string why = sup->take_reload_error();
        if (auto it = m_proxy_workers.find(name); it != m_proxy_workers.end())
            for (auto& other : it->second)
                if (other.get() != sup)
                    if (std::string w = other->take_reload_error();
                        !w.empty() && why.empty())
                        why = std::move(w);
        if (!why.empty())
            note_failure(name, why);
    }

    // A script is where a runtime's route declaration lives, so reloading one
    // can change what it says it will answer.  Without this the proxies in
    // front of it would go on enforcing the declaration from the previous
    // version of the file — the exact drift publishing exists to prevent, and
    // the worst kind, because the two copies came from the same script.
    //
    // Published even when one of the reloads was refused: a script that would
    // not load left the previous one in force, so the declaration the daemon
    // holds for it is still the one being enforced, and the runtimes that did
    // reload have new ones that have to go out.
    m_manager.publish_endpoints();

    if (!failures.empty())
    {
        // Straight into the reply buffer rather than through cout: the
        // cout_to_reply guard that borrows cout for a command exists only in
        // cmd_create and cmd_edit, so cout from here would land on the daemon's
        // own stdout — which is the very place these messages were already
        // being lost.  A null connection is the boot-time restore, which has no
        // reply channel; that keeps the old destination.
        //
        // Bad input — the file the operator named is the thing that is wrong —
        // so exit 1, per the project's codes.  Success stays silent.
        if (conn) conn->write_buf += failures;
        else      std::cout << failures;
        return 1;
    }
    return 0;
}

int daemon_handler::cmd_add(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2)
    {
        conn->write_buf = "usage: add <path> [--name <name>] [-s]\n";
        return 1;
    }

    std::string exec_path = std::string(pa.args[1]);

    // Validate executable exists and is executable
    if (access(exec_path.c_str(), X_OK) != 0)
    {
        conn->write_buf = "not executable: " + exec_path + "\n";
        return 1;
    }

    // Resolve to absolute path
    {
        std::error_code ec;
        auto canonical = std::filesystem::canonical(exec_path, ec);
        if (!ec)
            exec_path = canonical.string();
        else
            exec_path = std::filesystem::absolute(exec_path).string();
    }

    // Parse flags
    std::string name;
    bool autostart = false;

    for (size_t i = 2; i < pa.count; ++i)
    {
        if ((pa.args[i] == "--name" || pa.args[i] == "-n") && i + 1 < pa.count)
            name = std::string(pa.args[++i]);
        else if (pa.args[i] == "-s")
            autostart = true;
        else
        {
            conn->write_buf = "unknown flag: " + std::string(pa.args[i]) + "\n";
            return 1;
        }
    }

    // Derive name from basename if not given
    if (name.empty())
    {
        auto p = std::filesystem::path(exec_path).stem().string();
        if (p.empty())
        {
            conn->write_buf = "could not derive name from path\n";
            return 1;
        }
        name = p;
    }

    // Check name doesn't already exist
    if (m_manager.get(name))
    {
        conn->write_buf = "runtime already exists: " + name + "\n";
        return 1;
    }

    // Create a server-type placeholder
    if (!m_manager.create(runtime_server, name))
    {
        conn->write_buf = "could not create runtime\n";
        return 2;
    }

    auto* inst = m_manager.get(name);
    if (!inst)
    {
        conn->write_buf = "internal error\n";
        return 2;
    }

    inst->mark_managed(exec_path);
    inst->set_runtime_manager(&m_manager);
    inst->set_event_loop(&m_loop);

    if (autostart)
    {
        if (!m_manager.start(name, m_loop))
        {
            conn->write_buf = "could not start managed runtime\n";
            m_manager.remove(name);
            return 2;
        }
    }

    if (m_persistence)
        m_persistence->save_runtime(inst);

    return 0;
}

int daemon_handler::cmd_attach(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 4)
    {
        conn->write_buf = "usage: attach <type> <name> <port> [--owner <name>]\n";
        return 1;
    }

    runtime_type type;
    if (!parse_runtime_type(pa.args[1], type))
    {
        conn->write_buf = std::string("unknown runtime type: ") + std::string(pa.args[1]) + "\n";
        return 1;
    }

    std::string_view name = pa.args[2];

    // Parse port
    uint16_t port = 0;
    {
        auto sv = pa.args[3];
        auto result = std::from_chars(sv.data(), sv.data() + sv.size(), port);
        if (result.ec != std::errc{} || port == 0)
        {
            conn->write_buf = "invalid port: " + std::string(sv) + "\n";
            return 1;
        }
    }

    // Parse optional flags (need --managed and --pid early for re-attach check)
    pid_t pid = 0;
    std::string owner_name;
    for (size_t i = 4; i < pa.count; ++i)
    {
        if (pa.args[i] == "--pid" && i + 1 < pa.count)
        {
            // Checked, like the port six lines up and unlike this call before
            // it: `--pid abc` left pid at 0 and was silently ignored, so a
            // mistyped pid produced a runtime the daemon could never stop.
            auto sv = pa.args[++i];
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), pid);
            if (e != std::errc{} || p != sv.data() + sv.size() || pid <= 0)
            {
                conn->write_buf = "invalid pid: " + std::string(sv) + "\n";
                return 1;
            }
            if (const std::string msg = attach_pid_refusal(conn->fd, pid); !msg.empty())
            {
                conn->write_buf = msg;
                return 1;
            }
        }
        else if (pa.args[i] == "--managed")
        {
            // Consumed but not stored — re-attach is detected via existing->is_managed()
        }
        else if ((pa.args[i] == "--owner" || pa.args[i] == "-o") && i + 1 < pa.count)
        {
            owner_name = std::string(pa.args[++i]);
        }
    }

    // Check for name collision — allow re-attach of managed runtimes
    if (auto* existing = m_manager.get(name))
    {
        if (existing->is_managed() && existing->get_state() == runtime_running)
        {
            // Re-attach: update port/pid on existing managed runtime
            existing->set_port(port);
            if (pid > 0)
                existing->set_pid(pid);
            if (m_persistence)
                m_persistence->save_runtime(existing);
            return 0;
        }
        conn->write_buf = std::string("runtime already exists: ") + std::string(name) + "\n";
        return 1;
    }

    if (!m_manager.create(type, name))
    {
        conn->write_buf = "internal error: could not create runtime\n";
        return 2;
    }

    auto* inst = m_manager.get(name);
    if (!inst)
    {
        conn->write_buf = "internal error\n";
        return 2;
    }

    inst->set_port(port);
    inst->set_runtime_manager(&m_manager);
    inst->set_event_loop(&m_loop);

    // Apply parsed flags
    if (!owner_name.empty())
        inst->set_owner(owner_name);
    if (pid > 0)
        inst->set_pid(pid);

    // Mark as external — must come before start() so it skips io_uring setup
    inst->mark_external();

    if (!m_manager.start(name, m_loop))
    {
        conn->write_buf = "could not register external runtime\n";
        m_manager.remove(name);
        return 2;
    }

    if (m_persistence)
        m_persistence->save_runtime(inst);

    return 0;
}

void daemon_handler::start_health_timer()
{
    // m_health_pending means a completion is still owed on m_health_req — from
    // a timer that is counting down, or from one teardown() withdrew.  Either
    // way re-arming would hand the kernel a request it is already carrying one
    // for.
    if (m_health_pending || m_torn_down)
        return;
    m_health_req = { this, nullptr, -1, 0, op_timeout };
    m_health_ts = { 2, 0 };  // 2 seconds

    // Nothing re-arms this chain but its own completion, so a submission that
    // never reached the ring ends it — and it takes both of the daemon's
    // periodic duties with it: managed runtimes stop being supervised, and
    // retired instances stop being reaped.  The flag is left clear so a later
    // caller can pick the chain back up, and the loss is said out loud rather
    // than being found later as a leak.
    if (!m_loop.submit_timeout(&m_health_ts, &m_health_req))
    {
        LOG_ERROR("daemon health timer refused: managed runtimes are no longer "
                  "supervised and retired runtimes are no longer reaped");
        return;
    }
    m_health_pending = true;
}

void daemon_handler::publish_endpoints_to_workers(const endpoint_table& tbl)
{
    if (m_proxy_workers.empty())
        return;

    // Encoded once, sent to each: the table is the same for every worker, and
    // building it per child would make a membership change cost more the more
    // proxies are split out.
    std::vector<worker_proto::endpoint_wire> names;
    std::vector<worker_proto::endpoint_wire> groups;
    names.reserve(tbl.name_count());
    for (const auto& [name, ep] : tbl.names())
        names.push_back({name, ep.host, ep.port});
    for (const auto& [group, eps] : tbl.groups())
        for (const auto& ep : eps)
            groups.push_back({group, ep.host, ep.port});

    // The declarations travel with the table.  A proxy in a worker enforces
    // what this frame says and nothing else — it cannot read the daemon's
    // endpoint_table object, which is where these used to stay.
    worker_proto::route_decl_wire name_routes, group_routes;
    for (const auto& [n, rt] : tbl.name_routes())
        if (rt) name_routes.emplace_back(n, rt);
    for (const auto& [g, rt] : tbl.group_routes())
        if (rt) group_routes.emplace_back(g, rt);

    const std::string payload =
        worker_proto::encode_endpoints(names, groups, name_routes, group_routes);
    // Every shard, because every shard resolves its own backends: a table that
    // reached three of four workers leaves the fourth refusing to start on a
    // backend written as a name, which reads from outside as an intermittently
    // broken proxy.
    for (auto& [_, shards] : m_proxy_workers)
        for (auto& sup : shards)
            sup->send_endpoints(payload);
}

// What runtimes there are, as the workers' replicas of the map.
//
// Built here and not in runtime_manager for the reason every other worker-facing
// push is: the manager knows what it holds, this class knows where the sockets
// are, and the sink between them is what keeps the manager from having to know
// there are other processes at all.
//
// The connection count is reported_connection_count(), which is the figure the
// CLI prints and the one socketley.get() already answers with — a live walk for
// a runtime in this process, and the last pushed figure for one in a worker.
// EVENT-LOOP THREAD ONLY, because of that walk; every caller is.
std::string daemon_handler::build_runtime_map_payload()
{
    std::vector<worker_proto::runtime_wire> rts;
    {
        std::shared_lock lock(m_manager.mutex);
        rts.reserve(m_manager.list().size());
        for (const auto& [name, inst] : m_manager.list())
        {
            worker_proto::runtime_wire w;
            w.name        = name;
            w.type        = static_cast<uint8_t>(inst->get_type());
            w.state       = static_cast<uint8_t>(inst->get_state());
            w.port        = inst->get_port();
            w.connections = static_cast<uint64_t>(inst->reported_connection_count());
            w.owner       = std::string(inst->get_owner());
            w.group       = std::string(inst->get_group());
            rts.push_back(std::move(w));
        }
    }
    return worker_proto::encode_runtime_map(rts);
}

void daemon_handler::publish_runtime_map_to_workers()
{
    if (m_proxy_workers.empty())
        return;

    // Encoded once for all of them, like the endpoint table above: the map is
    // the same map whichever child is being told about it.  Each supervisor
    // decides whether it is news — see send_runtime_map, which drops a payload
    // identical to the one that child already has, so an idle daemon's health
    // tick costs one string compare per worker and no frame at all.
    const std::string payload = build_runtime_map_payload();
    for (auto& [_, shards] : m_proxy_workers)
        for (auto& sup : shards)
            sup->send_runtime_map(payload);

    m_last_map_push = std::chrono::steady_clock::now();
}

// What the cluster looks like, for the workers that cannot look.
//
// Built from this daemon's cluster_discovery, which is the only object that has
// any of it and which a worker may not have one of: it publishes into the
// shared directory and claims this node's name there, so a worker running one
// would read as a second daemon to every other member.  See
// shared/cluster_view.h.
//
// An empty view is sent when there is no cluster_discovery — but only once this
// daemon has ever had one.  That is the withdrawal, and it is needed because
// clustering can be restarted under a new name or a new directory: a worker
// left holding the old view would answer the four cluster calls out of a
// cluster this daemon has left.  A daemon that was never clustered sends
// nothing at all, which keeps the ordinary case free of a frame that says
// nothing and keeps those four calls refused out there, which is the honest
// answer for a worker whose daemon is in no cluster.
std::string daemon_handler::build_cluster_view_payload()
{
    // Empty means "there is nothing to say and nothing to withdraw": a daemon
    // that has never been in a cluster.  The callers send no frame at all for
    // it, which is what keeps those four calls refused in its workers — the
    // honest answer, rather than the empty table a successful call returns on a
    // daemon that IS in a cluster and alone in it.
    if (!m_cluster && !m_cluster_view_pushed)
        return {};

    cluster_view view;
    if (m_cluster)
    {
        view.daemon_name = std::string(m_cluster->get_daemon_name());
        view.host        = std::string(m_cluster->get_cluster_addr());
        view.remote      = m_cluster->get_all_daemons();
    }
    return worker_proto::encode_cluster_view(view);
}

void daemon_handler::publish_cluster_view_to_workers()
{
    if (m_proxy_workers.empty())
        return;

    const std::string payload = build_cluster_view_payload();
    if (payload.empty())
        return;

    for (auto& [_, shards] : m_proxy_workers)
        for (auto& sup : shards)
            sup->send_cluster_view(payload);

    m_cluster_view_pushed = true;
}

// ─── A connection count is news, and nothing else announces it ──────────────
//
// Membership changes republish the map through publish_endpoints(), which is
// right for a create or a stop and answers nothing for the field that moves on
// its own.  A client connecting to a runtime in a worker changes that runtime's
// count and moves nothing in the daemon: the figure arrives in a stats frame,
// lands in the placeholder, and until now waited for the two-second health tick
// to reach any other worker.
//
// What that cost was measurable and was the point of the exercise.  The
// daemon's own answer for a worker-backed runtime is as old as the last stats
// frame — 250 ms — and a script in a worker asking about the same runtime was
// reading a figure up to 2 s old.  The parity harness caught it as the one
// field of socketley.get() that differed between the two arms: 0 against 1.
//
// So the counts ride the cadence they arrive on.  Each worker publishes every
// stats_interval_ms, so any worker's frame is a tick of that clock, and this
// pushes the map when one arrives.
//
// ─── COALESCED, AND WHY THAT IS THE WHOLE DESIGN ────────────────────────────
//
// Pushing per arrival is quadratic: N workers publish N frames per interval,
// and each one changes the payload — a count moved — so the per-child dedupe
// cannot drop any of them, and every one of the N arrivals sends to all N
// children.  Sixteen workers is 256 frames per 250 ms.
//
// One round per interval instead, whoever's frame started it: 16 frames per
// 250 ms, four rounds a second, linear in the number of workers.  A delta frame
// carrying only the counts was considered and not built — the full row set at
// this rate is under a kilobyte per worker per round, and a second encoding of
// what a runtime is, kept in step with the first, costs more than it saves.
//
// The price of coalescing is that a figure can wait out the remainder of the
// window before it goes: the daemon is ≤250 ms stale and a worker is ≤500 ms in
// the worst case.  Both are the stats cadence rather than the health tick,
// which is what parity here means; the floor is one constant if it has to come
// down.
void daemon_handler::on_worker_stats(const std::string& name)
{
    // First, and outside the floor below: the placeholder every reader in this
    // process looks at holds the sum over this runtime's shards, and the frame
    // that has just arrived changed one of the terms.  Coalescing this the way
    // the map push is coalesced would answer `stats` from figures one interval
    // old for no saving — the numbers are already in hand and the work is an
    // addition over at most max_shards terms.
    aggregate_worker_stats(name);

    // Half the publish interval, and strictly below it on purpose.  A floor
    // equal to the arrival period is a floor that ordinary jitter trips over:
    // a frame landing a millisecond early is dropped, and the figure it carried
    // then waits for the NEXT one, so the worst case is two intervals rather
    // than one.  Below the period, every arrival gets through and the floor
    // only does what it is for — bounding the rounds when many children report
    // inside one interval.
    const auto now = std::chrono::steady_clock::now();
    if (now - m_last_map_push <
        std::chrono::milliseconds(worker_proto::stats_interval_ms / 2))
        return;

    publish_runtime_map_to_workers();
}

void daemon_handler::publish_to_workers(std::string_view cache_name,
                                        std::string_view channel,
                                        std::string_view message)
{
    if (m_proxy_workers.empty())
        return;

    // Encoded once for all of them.  A PUBLISH on a busy cache is a hot path in
    // a way an endpoint republish is not, and the payload does not depend on
    // which worker it is going to.
    const std::string payload = worker_proto::encode_publish(cache_name, channel, message);
    for (auto& [_, shards] : m_proxy_workers)
    for (auto& sup : shards)
    {
        // Everyone but whoever sent it up.  A worker that published has already
        // run its own subscribers — it cannot wait for a round trip to do that,
        // and it should not have to — so echoing the frame back would run every
        // subscriber in that process a second time for one PUBLISH.
        //
        // The exclusion is per PROCESS and not per runtime, which is what makes
        // it still right with shards: only the one shard that published has
        // already run its own subscribers, and its siblings are separate
        // processes holding separate interpreters that have not.  Excluding the
        // whole shard set would silently stop delivering to N-1 of them.
        if (sup.get() == m_publish_origin)
            continue;
        sup->send_publish(payload);
    }
}

// One runtime, not every worker: this message is addressed to a name, and the
// connections it is meant for belong to that runtime and no other.
//
// But "that runtime" is now every shard of it.  `send` broadcasts to the
// connections a runtime is holding, and with --shards those are spread across N
// processes by the kernel's own choice — so delivering to one shard delivers to
// the fraction of the clients that happened to land there, and reports success
// for the rest.  Which fraction is not even stable between two sends.
//
// So the frame goes to all of them and each broadcasts to what it holds.  True
// if any shard took it: a partial delivery is still worth reporting as one,
// because the alternative is telling the operator nothing was sent when most of
// it was.  A shard that would not take the frame has already logged why.
bool daemon_handler::deliver_to_worker(std::string_view name,
                                       std::string_view message)
{
    auto it = m_proxy_workers.find(std::string(name));
    if (it == m_proxy_workers.end())
        return false;

    bool any = false;
    for (auto& sup : it->second)
        if (sup->send_deliver(message))
            any = true;
    return any;
}

void daemon_handler::on_worker_publish(proxy_supervisor* from,
                                       std::string_view cache_name,
                                       std::string_view channel,
                                       std::string_view message)
{
    // Saved and restored rather than cleared: dispatch_publish() runs Lua, a
    // subscriber may PUBLISH again, and the inner fan-out must not lose the
    // outer one's origin on its way back out.
    proxy_supervisor* const prev = m_publish_origin;
    m_publish_origin = from;
    m_manager.dispatch_publish(cache_name, channel, message);
    m_publish_origin = prev;
}

void daemon_handler::poll_proxy_workers()
{
    // ─── Nothing here may hold into the map across a poll() ─────────────────
    //
    // poll() drains a control socket, and what comes off one reaches back here:
    // a `publish` runs the subscribe callbacks of every runtime in this daemon,
    // a subscriber may call socketley.remove, and that reconciles — which
    // erases from m_proxy_workers.  await_worker_startup() documents the same
    // path and re-takes its iterator for the same reason.
    //
    // A range-for over the map was already resting on that not happening.  It
    // became worth fixing rather than noting when the aggregate below started
    // using the KEY after the drain: a structured binding's `name` is a
    // reference into the node, so an erase during poll() would leave this
    // reading a freed string, not merely a stale iterator.
    //
    // So: the names are copied first, and every element is re-found by name
    // between drains.  One string copy per runtime per tick, against a
    // use-after-free that needs a Lua subscriber and a removal to reach.
    std::vector<std::string> names;
    names.reserve(m_proxy_workers.size());
    for (const auto& [name, _] : m_proxy_workers)
        names.push_back(name);

    for (const auto& name : names)
    {
        size_t k = 0;
        for (;;)
        {
            auto it = m_proxy_workers.find(name);
            if (it == m_proxy_workers.end() || k >= it->second.size())
                break;
            it->second[k]->poll();
            ++k;
        }

        // Once per runtime and after its whole shard set has been drained, not
        // once per shard: the placeholder holds the SUM, so writing it while
        // half the shards still carry figures from the previous interval would
        // publish a total that never existed.  It re-finds the name itself and
        // does nothing when the runtime has gone.
        aggregate_worker_stats(name);
    }
}

// ─── One runtime's figures, out of N processes' ─────────────────────────────
//
// A shard is an implementation detail of a runtime and not a runtime: `ls`
// prints one line, `inspect` prints one record, and the connection count on it
// is what the runtime is serving.  With N workers that is the sum over them,
// which is why apply_stats() stopped writing the placeholder — see the note
// there.
//
// The four lifetime counters add up because each shard has only ever counted
// its own connections, and the active count adds up for the same reason.  The
// timestamp does NOT: it is a moment, and the honest answer to "how old is this
// figure" for a total is the age of its OLDEST part, because that is the last
// instant the whole of it was true.  Taking the newest would let one busy shard
// make three stale siblings look current.
//
// A shard that has not published yet contributes nothing at all rather than
// zeros.  Otherwise every restart — and every `create -s`, for the moments
// between the forks — would report a runtime as having lost the connections its
// unstarted shards have not yet claimed.
void daemon_handler::aggregate_worker_stats(const std::string& name)
{
    auto it = m_proxy_workers.find(name);
    if (it == m_proxy_workers.end())
        return;

    auto* inst = m_manager.get(name);
    if (!inst)
        return;

    uint64_t total_conn = 0, total_msg = 0, in = 0, out = 0, active = 0;
    int64_t  oldest     = 0;
    bool     any        = false;
    std::string detail;

    for (const auto& sup : it->second)
    {
        const auto& s = sup->last_stats();
        if (!s.seen)
            continue;

        any          = true;
        total_conn  += s.total_connections;
        total_msg   += s.total_messages;
        in          += s.bytes_in;
        out         += s.bytes_out;
        active      += s.active_connections;

        if (s.taken_ns != 0 && (oldest == 0 || s.taken_ns < oldest))
            oldest = s.taken_ns;

        // One shard's detail text is passed through unchanged, which is the
        // whole of the unsharded case and keeps `stats` byte-identical to what
        // it printed before this existed.  Several are labelled, because the
        // text is a walk of ONE process's connection tables and concatenating
        // them unlabelled would read as one runtime with the same connection
        // listed several times.
        if (it->second.size() > 1)
        {
            detail += "[shard ";
            detail += std::to_string(&sup - it->second.data());
            detail += "]\n";
        }
        detail += s.detail;
    }

    if (!any)
        return;

    inst->m_stat_total_connections.store(total_conn, std::memory_order_relaxed);
    inst->m_stat_total_messages.store(total_msg, std::memory_order_relaxed);
    inst->m_stat_bytes_in.store(in, std::memory_order_relaxed);
    inst->m_stat_bytes_out.store(out, std::memory_order_relaxed);

    // Where an in-process runtime's would be, so stat_detail_snapshot() — which
    // the metrics endpoint already calls — is answered identically whichever
    // side the runtime is running on, and whether it is one process or four.
    inst->set_worker_stats(std::move(detail), active, oldest);
}

void daemon_handler::reconcile_proxy_workers()
{
    // What the runtime map says should be running out of process, and HOW MANY
    // processes each of them wants.  The count is part of what is being
    // reconciled now, not just the presence: `--shards 4` on a runtime that
    // currently has one worker is three forks, and a restore that brings a
    // four-shard proxy back has to bring back four.
    std::vector<std::pair<std::string, size_t>> wanted;
    {
        std::shared_lock lock(m_manager.mutex);
        for (const auto& [name, inst] : m_manager.list())
        {
            // The supervisor does not care what kind of runtime it is
            // supervising — it forks, hands over a config frame, restarts and
            // reads stats back, and none of that reads the type.  It held a
            // proxy_instance* it never dereferenced until ba86f38.
            if (!inst->is_out_of_process())
                continue;
            if (inst->get_state() == runtime_running)
                wanted.emplace_back(name, static_cast<size_t>(inst->get_shards()));
        }
    }

    // Retire one shard: the whole of what used to happen to the single
    // supervisor for a name, unchanged, and now reached from two places — a
    // runtime that is going away entirely, and one that is merely going from
    // four shards to two.
    //
    // Its own function because getting this wrong is not a visible failure.
    // The erase must NOT destroy: the erase used to run the destructor, and the
    // supervisor's control-socket poll had been cancelled rather than
    // completed, so its completion arrived on a later turn and the loop read
    // the owner token out of an io_request living inside the freed object.
    // Removing or stopping an out-of-process runtime was enough; no traffic was
    // needed.  retire() gives the ring back, drops every pointer to this
    // supervisor while the things holding them are still alive, and hands over
    // the identity to wait on; drain_retired_handlers() destroys it once the
    // loop says nothing more will name it.
    const auto retire_one = [this](std::unique_ptr<proxy_supervisor> sup)
    {
        sup->shutdown();
        // shutdown() reaps only a child that was already gone, and one that has
        // just been asked to unwind its ring never is.  This is the last moment
        // anything knows the pid.
        if (const pid_t p = sup->release_pid(); p > 0)
            m_orphan_workers.push_back({p, std::chrono::steady_clock::now(), false});

        const uint32_t tok = sup->retire();
        m_retired_handlers.push_back({std::move(sup), tok});
    };

    // Children whose runtime has stopped, been removed or renamed — and shards
    // of a runtime that is still wanted with fewer of them than it has.  Taken
    // down before anything is started, so a rename that reuses a port does not
    // have two children bound to it at once.
    for (auto it = m_proxy_workers.begin(); it != m_proxy_workers.end();)
    {
        const auto w = std::find_if(wanted.begin(), wanted.end(),
                                    [&](const auto& p) { return p.first == it->first; });

        if (w == wanted.end())
        {
            for (auto& sup : it->second)
                retire_one(std::move(sup));
            // The region goes with the last shard.  Nothing may read it after
            // this — every process that had it mapped is being torn down — and
            // keeping it would hand a restarted runtime a table still holding
            // the counts of the shards it replaced.
            m_shard_regions.erase(it->first);
            it = m_proxy_workers.erase(it);
            continue;
        }

        // Wanted, but with fewer processes than it currently has.  Reached when
        // a stopped runtime was edited to a smaller --shards and started again;
        // the shrink itself is refused while running, see parse_common_edit_flags.
        //
        // From the back, so the shards that survive keep their index — the
        // index is what `stats` labels a shard's detail text with, and having
        // it renumber underneath a reader for no reason is a worse answer than
        // leaving a gap that cannot occur.
        while (it->second.size() > w->second)
        {
            retire_one(std::move(it->second.back()));
            it->second.pop_back();
        }

        // The surviving shards must stop counting the ones that just went.  A
        // retired shard publishes nothing on its way out — that is the whole
        // point of retiring it — so its last figure would sit in the table
        // being summed forever, and `self.connections()` would report a runtime
        // holding connections that no process has.  Told here, by the one side
        // that knows a shard has gone.
        if (const auto r = m_shard_regions.find(it->first); r != m_shard_regions.end())
            r->second.set_shard_count(static_cast<uint32_t>(w->second));

        ++it;
    }

    // Children that should exist and do not — including the second, third and
    // fourth process of a runtime that already has its first.
    for (const auto& [name, want_count] : wanted)
    {
        auto& shards = m_proxy_workers[name];
        if (shards.size() >= want_count)
            continue;

        auto* inst = m_manager.get(name);
        if (!inst)
        {
            if (shards.empty())
                m_proxy_workers.erase(name);
            continue;
        }

        runtime_config cfg;
        if (m_persistence)
            cfg = m_persistence->read_from_instance(inst);
        else
        {
            if (shards.empty())
                m_proxy_workers.erase(name);
            continue;   // nothing to describe the runtime with
        }

        // The shards forked in this pass, so `start` can be sent to all of them
        // AFTER the endpoint table has been published once — see the note below
        // the spawn for why the table has to arrive before the start, and why
        // publishing it once for N children beats publishing it N times.
        std::vector<proxy_supervisor*> forked;

        // ── The shared table this runtime's shards publish into ─────────────
        //
        // Made before the first fork and kept for the life of the runtime; see
        // m_shard_regions.  A runtime that is not sharded gets none and every
        // reader below is written for that: shard_fd stays -1, the supervisor
        // passes nothing across the exec, and the worker finds no descriptor and
        // does not map anything.
        //
        // A region that cannot be made is not fatal.  memfd_create is old
        // enough to be everywhere this daemon runs, but the failure mode if it
        // is not is the behaviour this tree had yesterday — each shard answers
        // for itself — and taking the runtime down instead would turn a missing
        // optimisation into an outage.  It is logged once, here, so the reason
        // `self.connections()` is answering per-shard is written down somewhere.
        int shard_fd = -1;
        if (want_count > 1)
        {
            auto& region = m_shard_regions[name];
            if (!region.mapped())
            {
                if (!region.create(static_cast<uint32_t>(want_count)))
                    LOG_WARN(("could not create the shared shard table for "
                              + name
                              + "; each shard will answer only for itself").c_str());
            }
            else
            {
                // Growing: the shards that already exist keep their slots and
                // their published figures, and the new ones get slots that were
                // out of range a moment ago.
                region.set_shard_count(static_cast<uint32_t>(want_count));
            }
            shard_fd = region.fd();
        }

        while (shards.size() < want_count)
        {
        auto sup = std::make_unique<proxy_supervisor>(inst, std::string{});

        // Which of N this child is, and where it publishes.  The position in
        // this vector IS the index — reconcile only ever appends here and only
        // ever retires from the back, exactly so that a shard's index does not
        // move underneath a reader — so no counter has to be kept beside it.
        sup->set_shard(static_cast<uint32_t>(shards.size()), shard_fd);

        // The supervisor answers for the runtime it supervises.  Set before the
        // spawn so that a request arriving in the same turn as the start has
        // somewhere to go, and pointed at the placeholder so that
        // publish_sinks() below picks it up instead of the empty local object.
        sup->set_channel(&m_manager.requests());
        sup->set_event_loop(&m_loop);
        sup->set_publish_handler([this](proxy_supervisor* from,
                                        std::string_view c, std::string_view ch,
                                        std::string_view m)
                                 { on_worker_publish(from, c, ch, m); });
        sup->set_deliver_handler([this](std::string_view n, std::string_view m)
                                 { on_worker_deliver(n, m); });
        sup->set_stats_handler([this, name] { on_worker_stats(name); });

        // ─── Only the first shard is the request sink ───────────────────────
        //
        // A cross-runtime request names a runtime and expects ONE answer.  The
        // override is a single pointer because that is the shape of the
        // question, not a limitation to route around: sending `cache get k` to
        // four shards would produce four replies to a channel holding one
        // ticket.
        //
        // Shard 0 rather than a rotation, because a request must be answerable
        // and any shard can answer one — a request is served from the runtime's
        // configuration and its script, both of which every shard has, and not
        // from the connections, which is the one thing they do not share.  The
        // types where that is untrue are exactly the types --shards refuses.
        if (shards.empty())
            inst->set_request_sink_override(sup.get());

        // ─── What this child must know before it reads its config ───────────
        //
        // Handed over before the fork, not published after it.  There is no
        // socket yet, so these only fill the supervisor's caches — and those
        // caches are exactly what spawn() writes ahead of the config frame,
        // which is the frame that makes the worker load its script.
        //
        // Publishing after the spawn, which is what the map used to rely on,
        // puts both frames BEHIND the config: fine for the map, which is read
        // when a callback runs, and not fine for the cluster view, whose
        // bindings are refused or not at the moment the script is loaded.  A
        // script's top level asking socketley.cluster.daemons() was answered by
        // a refusal installed a few microseconds before the view arrived.
        //
        // The map is primed the same way for the smaller version of the same
        // problem: a top-level socketley.list() saw an empty map.
        sup->send_runtime_map(build_runtime_map_payload());
        if (const std::string cv = build_cluster_view_payload(); !cv.empty())
        {
            sup->send_cluster_view(cv);
            m_cluster_view_pushed = true;
        }

        if (!sup->spawn(cfg))
        {
            LOG_ERROR("could not start out-of-process proxy worker");
            // The override must not outlive the supervisor it points at.  Only
            // when this IS the supervisor it points at: with shards, a fork
            // that fails on the third child must not unhook the first, which is
            // alive, serving, and the one answering requests.
            if (shards.empty())
                inst->set_request_sink_override(nullptr);
            inst->mark_failed();

            // Stop adding to a runtime that has just been marked failed rather
            // than trying the remaining shards.  Whatever stopped this fork —
            // memory, a descriptor limit, a process limit — is not going to be
            // any different one line later, and the shards that DID come up are
            // retired by the loop above on the next reconcile, because a
            // `failed` runtime is no longer in `wanted`.
            break;
        }
        // Three frames have to reach this child, in this order: config, the
        // endpoint table, then start.  The first went with spawn(); the other
        // two are sent below, once the whole shard set is in the map — the
        // table's only way to a worker is publish_endpoints(), which reaches
        // one by walking m_proxy_workers, so every shard has to be IN the map
        // before the publish and started after it.
        //
        // The table travels as its own frame rather than riding on `start`,
        // because that is the frame spawn() already re-sends to a restarted
        // child from its cache: one path into the worker, not two.
        //
        // sup is moved into the map, so the start goes through the supervisor
        // itself.  A pointer rather than an iterator: a vector reallocates as
        // shards are appended, so the pointer is taken from the element after
        // the push and the ones collected earlier would dangle if they were
        // element addresses.  They are not — proxy_supervisor is held by
        // unique_ptr, so the OBJECT does not move when the vector grows, only
        // the pointers to the pointers do.
        shards.push_back(std::move(sup));
        forked.push_back(shards.back().get());
        }

        // Once for however many were forked, and before any of them is started.
        //
        // A backend written as a bare runtime name is turned into host:port by
        // resolve_backend(), which runs inside start() — before the listener is
        // bound, and it fails the start outright when there is no table to look
        // the name up in.  A supervisor forked in this loop has an empty
        // endpoint cache, so the send inside spawn() had nothing to send yet.
        //
        // With start sent first, an out-of-process proxy whose backend was a
        // name never came up at all: the worker resolved nothing, refused to
        // bind, and every client got a connection refused on a port `ls` showed
        // as running.  A literal address was unaffected — it needs no table —
        // which is what made this look like a proxy bug rather than an ordering
        // one.
        if (!forked.empty())
        {
            m_manager.publish_endpoints();
            for (auto* s : forked)
                s->send_start();
        }

        // A name whose every fork failed must not be left in the map as an
        // empty vector: `m_proxy_workers.find(name)` succeeding with nothing in
        // it would answer "this runtime has workers" to every site that asks.
        if (shards.empty())
        {
            m_proxy_workers.erase(name);
            // And the region goes with them, for the same reason: a table with
            // no process publishing into it is not a smaller table, it is one
            // whose every reader has gone.
            m_shard_regions.erase(name);
        }
    }
}

std::string daemon_handler::on_start_error(std::string_view name)
{
    if (auto* inst = m_manager.get(name); inst && !inst->last_on_start_error().empty())
        return inst->last_on_start_error();

    // Nothing on the instance means either that on_start ran, or that it ran
    // somewhere else: for a runtime in a worker the placeholder never touches
    // the script, and the reason came up the control socket instead.
    // The first shard that has one.  Taken from every shard and not only the
    // first, because on_start runs in each of them and the one that raised may
    // be any: reading shard 0 alone would report success for a runtime three
    // quarters of whose processes never finished their set-up.
    //
    // Taken from ALL of them even after one is found, because take_ is
    // destructive — leaving a sibling's error in place would hand it to the
    // next command that asked, as the answer to a start it was not about.
    if (auto it = m_proxy_workers.find(std::string(name)); it != m_proxy_workers.end())
    {
        std::string first;
        for (auto& sup : it->second)
            if (std::string e = sup->take_start_error(); !e.empty() && first.empty())
                first = std::move(e);
        return first;
    }

    return {};
}

int daemon_handler::await_worker_startup(std::string_view name, std::string& out,
                                         std::chrono::steady_clock::time_point deadline)
{
    auto it = m_proxy_workers.find(std::string(name));
    if (it == m_proxy_workers.end())
        return 0;   // in-daemon, or never spawned: nothing in another process

    // Whatever is left of the command's budget, never less than zero.  A caller
    // waiting on several children has already spent some of it on the ones
    // ahead of this — which costs nothing when they answered in 20 ms, and is
    // the whole point when one of them did not answer at all.
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - std::chrono::steady_clock::now());
    if (left < std::chrono::milliseconds(0))
        left = std::chrono::milliseconds(0);

    // ─── Every shard, and the worst verdict any of them gave ────────────────
    //
    // A `create -s` on a four-shard proxy that waits only for the first one is
    // a command that returns before three quarters of the runtime exists, and —
    // worse — returns 0 for a configuration the other three are about to
    // refuse.  The refusal that matters is usually the SAME on every shard,
    // because they are handed the same config; the one that is not is the port,
    // and that is exactly the case where waiting for one is silently wrong.
    //
    // Worst-of, in the order refused > pending > serving: a shard that refused
    // is the answer whatever its siblings did, and a shard that never reported
    // outranks a shard that came up.  They share one deadline rather than
    // getting one each, which is what the `deadline` parameter is already for —
    // see the note above it: a caller waiting on several children spends the
    // budget on the ones ahead.
    auto verdict = proxy_supervisor::startup::serving;
    {
        const size_t n = it->second.size();
        for (size_t k = 0; k < n; ++k)
        {
            // Re-found on every turn for the reason the re-take below gives:
            // await_startup() drains the control socket, and a publish coming
            // off it can run a subscriber that removes this very runtime.
            auto sit = m_proxy_workers.find(std::string(name));
            if (sit == m_proxy_workers.end() || k >= sit->second.size())
                break;

            auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(
                           deadline - std::chrono::steady_clock::now());
            if (rem < std::chrono::milliseconds(0))
                rem = std::chrono::milliseconds(0);

            const auto v = sit->second[k]->await_startup(rem);
            if (v == proxy_supervisor::startup::refused)
                verdict = v;
            else if (v == proxy_supervisor::startup::pending &&
                     verdict != proxy_supervisor::startup::refused)
                verdict = v;
        }
    }

    // The iterator is re-taken rather than reused, and that is not tidiness.
    //
    // await_startup() drains the control socket, and what comes off it can reach
    // back into this map: a `publish` runs the subscribe callbacks of every
    // runtime in this daemon, a subscriber may call socketley.remove, and that
    // reconciles — which erases from m_proxy_workers.  `it` then names a node
    // that has been freed, and the two uses below would read it.
    //
    // Older than the map frame this commit adds and not reached by it: the way
    // in is the publish path, which has existed since a cache in a worker could
    // reach a subscriber in the daemon.  Fixed here because auditing what a new
    // frame could reach is what found it.
    it = m_proxy_workers.find(std::string(name));
    if (it == m_proxy_workers.end())
        return 0;   // gone while we waited: nothing left to report on

    switch (verdict)
    {
        case proxy_supervisor::startup::serving:
            // The child is listening, so it is a group member others may be
            // routed to now — and until this runs, deliberately, they have not
            // been told about it.  This is what turns the wait into the
            // announcement rather than leaving it to the health tick two
            // seconds later; a create that returns has already published.
            // take_reachability_change() is consumed here so the tick does not
            // publish a second time for the same transition.
            //
            // Consumed from every shard, and one publish for however many
            // reported it: the table is rebuilt whole, so N calls would send N
            // identical tables — and a flag left unconsumed on a sibling makes
            // the health tick republish for a transition already announced.
            {
                bool moved = false;
                for (auto& sup : it->second)
                    if (sup->take_reachability_change())
                        moved = true;
                if (moved)
                    m_manager.publish_endpoints();
            }
            return 0;

        case proxy_supervisor::startup::refused:
            // Deliberately "did not accept" rather than "refused its script".
            // Two different things reach this verdict -- a worker that exits
            // rather than serve without its script, and one that started and
            // could not bind, resolve its backend or load its TLS pair -- and
            // only the first is a refusal in the narrow sense.  The message has
            // to be true of both, and the child has already written the specific
            // reason: "'path' must start with '/'" names the entry and the rule,
            // which is more than this side knows.  What is added here is the
            // consequence, on the CLI's own stream, because a log line the
            // operator has not gone looking for is not an answer to a command.
            //
            // Exit 1 for both, because both are the configuration that was
            // handed in: a script that will not load, a backend that cannot be
            // resolved, a port already taken.  That is bad input, not a fatal.
            out += "runtime ";
            out += name;
            out += " could not start: the worker did not accept its "
                   "configuration (the reason is in the daemon log)\n";

            // ─── AND IT IS NOT `was_running` ────────────────────────────────
            //
            // cmd_start and cmd_reload both set was_running=true the moment
            // m_manager.start() returns, which is before the child exists --
            // the placeholder is optimistically `running` and the verdict is
            // this frame, arriving later.  Neither cleared it when the verdict
            // came back refused, so a runtime that never served was recorded as
            // one the operator wants brought back, and the next daemon start
            // brought it back.
            //
            // Two writers, and every path that learns a start did not happen
            // comes through this function, so the clear belongs here rather
            // than at each of them -- a third caller is a matter of time and
            // would not know to do it.
            //
            // Only on `refused`, never on `pending`: pending is this side not
            // knowing, and the case below says so at length.  Clearing on a
            // child that is merely slow would leave a listener serving traffic
            // and marked not-to-be-restored, which is the worse of the two
            // wrong answers.
            //
            // What it cost, measured on `--listen unix:` where two claimants
            // for one path cannot both win: a refused server was restored after
            // a daemon restart, took the path from the runtime that owned it,
            // and -- having no --http of its own -- answered 404 to every
            // request, permanently.  22% of runs under load, on this commit and
            // on every commit before it.
            if (m_persistence)
                m_persistence->set_was_running(name, false);
            return 1;

        case proxy_supervisor::startup::pending:
            break;
    }

    // Neither answer inside the bound.  Deliberately NOT reported as a refusal
    // and deliberately not marked failed here: this side does not know which it
    // is, and the two wrong answers available -- "it failed" about a runtime
    // that comes up a moment later, "it worked" about one that never does --
    // are both worse than saying what is actually known.  The supervisor still
    // owns the child, the health tick still settles the state, and `ls` will
    // show whichever it turns out to be.
    out += "runtime ";
    out += name;
    out += " did not report back within 2s of starting; it is still being "
           "supervised -- check `socketley ls` for what it settled on\n";
    return 2;
}

void daemon_handler::reap_orphan_workers()
{
    if (m_orphan_workers.empty())
        return;

    // Long enough for a worker to cancel its ring and close its connections,
    // short enough that a daemon stopping runtimes in a loop does not accumulate
    // them.  A child that is still here after this has not answered SIGTERM and
    // is not going to.
    constexpr auto kill_after = std::chrono::seconds(5);
    const auto     now        = std::chrono::steady_clock::now();

    for (auto it = m_orphan_workers.begin(); it != m_orphan_workers.end();)
    {
        // ECHILD as well as a positive pid: if it is not ours any more there is
        // nothing left to wait for, and keeping the entry would mean signalling
        // a number the kernel is free to hand to somebody else.
        const pid_t r = ::waitpid(it->pid, nullptr, WNOHANG);
        if (r > 0 || (r < 0 && errno == ECHILD))
        {
            it = m_orphan_workers.erase(it);
            continue;
        }

        if (!it->killed && now - it->signalled_at > kill_after)
        {
            const std::string note = "worker " + std::to_string(it->pid) +
                                     " did not exit on SIGTERM; killing it";
            LOG_WARN(note.c_str());
            ::kill(it->pid, SIGKILL);
            it->killed = true;
        }
        ++it;
    }
}

void daemon_handler::drain_retired_handlers()
{
    if (m_retired_handlers.empty())
        return;

    for (auto it = m_retired_handlers.begin(); it != m_retired_handlers.end();)
    {
        // The one question worth asking, and the loop is the only thing that
        // can answer it: is any completion still going to name the storage
        // inside this object.  Not "has it been deregistered" — a deregistered
        // owner's completion is dropped, and dropping one reads the request to
        // decide.
        if (m_loop.token_inflight(it->token) != 0)
        {
            ++it;
            continue;
        }

        // Zero, so nothing in the ring can reach it any more and the erase
        // below is what finally runs the destructor.
        it = m_retired_handlers.erase(it);
    }
}

void daemon_handler::check_managed_health()
{
    reap_orphan_workers();

    // Beside the pid graveyard, and drained the same way for the same reason:
    // both hold something a removal could not finish with, and the tick is a
    // later turn of the loop than the removal was.
    drain_retired_handlers();

    // The children first: liveness, then whatever they have reported.  Both
    // before the managed-runtime sweep below, which can return early.
    bool routes_moved = false;
    for (auto& [worker_name, shards] : m_proxy_workers)
    for (auto& sup : shards)
    {
        // The child's own report, drained before liveness so a runtime that
        // failed to start reaches the state file on the same tick it was heard
        // about.  poll_proxy_workers() below is where the frame is read; this
        // collects what the previous drain decided.
        if (sup->take_state_change() && m_persistence)
        {
            if (auto* inst = m_manager.get(worker_name))
                m_persistence->save_runtime(inst);
        }

        // A declaration that arrived since the last tick.  publish_endpoints()
        // rebuilds the whole table, so one call covers however many sent one.
        if (sup->take_routes_change())
            routes_moved = true;

        // A child that has started listening since the last tick.  Folded into
        // the same republish for the same reason, and it is the backstop rather
        // than the fast path: a `create` announces its own worker as soon as
        // await_worker_startup() sees it serving.  What reaches here is every
        // other way a worker can come up — a restart after a crash above all,
        // where nothing is waiting on the child and the member has been out of
        // its group since the fork.
        if (sup->take_reachability_change())
            routes_moved = true;

        if (sup->check_liveness() && m_persistence)
        {
            // A child that died and was not restarted has moved the runtime to
            // `failed`; that has to reach the state file or a daemon restart
            // would bring back a runtime the operator was told had failed.
            if (auto* inst = m_manager.get(worker_name))
                m_persistence->save_runtime(inst);
        }
    }
    poll_proxy_workers();
    reconcile_proxy_workers();

    if (routes_moved)
        m_manager.publish_endpoints();

    // The workers' replica of the map, refreshed for what no event announces.
    //
    // Membership changes ride publish_endpoints() and arrive at once; two things
    // do not.  A connection count moves with traffic and nothing republishes for
    // it, and a runtime whose worker refused its configuration reaches `failed`
    // through mark_failed(), which is not a transition the manager publishes
    // either.  Both are collected above, so this is the point at which the tick
    // has the freshest answer it is going to have.
    //
    // After reconcile_proxy_workers(), so a child forked on this tick is in
    // m_proxy_workers and gets the map with everything else.  Unconditional
    // because the decision belongs one level down: send_runtime_map() drops a
    // payload the child already has, so a daemon where nothing moved sends
    // nothing.
    publish_runtime_map_to_workers();

    // And what the cluster looks like, on the same tick.
    //
    // That is not a convenience: cluster_discovery scans the shared directory
    // every PUBLISH_INTERVAL_SEC, which is the two seconds this tick already
    // runs at, so a view pushed here is exactly as old as the one a script in
    // the daemon reads off get_all_daemons().  Pushing it more often would
    // resend a snapshot that has not been re-scanned; less often — only when
    // local membership moved — would freeze it, because a remote daemon joining
    // or leaving changes nothing in the local map.
    publish_cluster_view_to_workers();

    std::shared_lock lock(m_manager.mutex);
    for (auto& [name, inst] : m_manager.list())
    {
        if (!inst->is_managed() || inst->get_state() != runtime_running)
            continue;
        pid_t pid = inst->get_pid();
        if (pid <= 0)
            continue;
        int status = 0;
        pid_t ret = waitpid(pid, &status, WNOHANG);
        if (ret <= 0)
            continue;  // still alive or error

        // Process died — stop and restart
        LOG_WARN("managed runtime died, restarting");
        lock.unlock();
        inst->stop(m_loop);   // set state to stopped (no SIGTERM needed, process is dead)
        m_manager.start(name, m_loop);  // fork+exec again
        if (m_persistence)
            m_persistence->save_runtime(inst.get());
        return;  // restart one at a time per health check cycle
    }
}

int daemon_handler::cmd_cluster_dir(ipc_connection* conn)
{
    if (!m_cluster)
    {
        conn->write_buf = cluster_off_reason();
        return 1;
    }

    conn->write_buf = std::string(m_cluster->get_cluster_dir()) + "\n";
    return 0;
}

// The local half of `socketley cluster`.  Everything else that command prints
// it reads off the shared directory, which is exactly the view a node excluded
// from the cluster does not appear in — so the one fact the directory can never
// carry is whether THIS daemon is in it, and why not.
//
// Always exits 0: "clustering is off" is an answer, not a failure to answer.
int daemon_handler::cmd_cluster_status(ipc_connection* conn)
{
    std::string out;

    if (m_cluster)
    {
        out += "cluster:on\n";
        out += "name:"  + std::string(m_cluster->get_daemon_name())  + "\n";
        out += "dir:"   + std::string(m_cluster->get_cluster_dir())  + "\n";
        out += "host:"  + std::string(m_cluster->get_cluster_addr()) + "\n";
        conn->write_buf = std::move(out);
        return 0;
    }

    out += "cluster:off\n";
    out += "name:" + (m_daemon_name.empty() ? std::string("-") : m_daemon_name) + "\n";
    out += "dir:"  + (m_cluster_want_dir.empty() ? std::string("-") : m_cluster_want_dir) + "\n";
    if (!m_cluster_error.empty())
        out += "error:" + m_cluster_error + "\n";

    conn->write_buf = std::move(out);
    return 0;
}

void daemon_handler::stop_cluster()
{
    if (!m_owned_cluster)
        return;

    // Not reset() — quarantined.  cluster_discovery's publish timer is an
    // io_request inside the object, so a timeout still counting down names
    // storage the reset would free, and the loop reads the owner token out of
    // that request when the completion lands.  stop() did not deregister at
    // all, so the token still matched and the completion was dispatched: a
    // virtual call on a freed cluster_discovery, about two seconds after this
    // line.  Pointing `daemon --cluster` at a second directory was enough, and
    // so was renaming a clustered daemon, which restarts discovery through
    // here.
    //
    // The pointers first, so that nothing can reach the object while it waits.
    m_cluster = nullptr;
    m_manager.set_cluster_discovery(nullptr);

    const uint32_t tok = m_owned_cluster->retire();
    m_retired_handlers.push_back({std::move(m_owned_cluster), tok});
}

bool daemon_handler::start_cluster(const std::string& name, const std::string& dir)
{
    stop_cluster();

    m_cluster_want_dir = dir;

    auto cd = std::make_unique<cluster_discovery>(name, dir, socket_path, m_manager);
    cd->set_event_callback([this](const std::vector<cluster_event>& events) {
        m_manager.dispatch_cluster_events(events);

        // A daemon joining or leaving moves nothing in the local map, so
        // nothing else would carry it to a worker before the next tick.  The
        // tick is the backstop; this is the moment the daemon itself learned,
        // and a script out there should not hear about it later than one in
        // here does.
        publish_cluster_view_to_workers();
    });

    if (!cd->start(m_loop))
    {
        m_cluster_error = cd->last_error();
        return false;
    }

    m_owned_cluster = std::move(cd);
    m_cluster = m_owned_cluster.get();
    m_manager.set_cluster_discovery(m_cluster);
    m_cluster_error.clear();
    return true;
}

// The sentence an operator gets from every surface that can be asked about
// clustering after the fact.  A daemon that was never given --cluster and a
// daemon that was given it and could not honour it are two different states,
// and reporting them with one message is how "accepted and not applied" hides.
std::string daemon_handler::cluster_off_reason() const
{
    if (m_cluster_error.empty())
        return "daemon is not in cluster mode (use: daemon --name <n> --cluster <dir>)\n";

    return "cluster mode is off: " + m_cluster_error + "\n"
           "  this daemon is serving normally, but it publishes nothing into "
         + m_cluster_want_dir + " and no peer can see it.\n"
           "  give it a name no live daemon holds, or wait for the holder's "
           "heartbeat to age out, then: daemon --name <n> --cluster "
         + m_cluster_want_dir + "\n";
}

int daemon_handler::cmd_daemon_name(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2)
    {
        if (m_daemon_name.empty())
        {
            conn->write_buf = "no daemon name set\n";
            return 1;
        }
        conn->write_buf = m_daemon_name + "\n";
        return 0;
    }

    std::string new_name(pa.args[1]);

    // Validate name: reject path-unsafe characters
    for (char c : new_name)
    {
        if (c == '/' || c == '\\' || c == '\0')
        {
            conn->write_buf = "invalid daemon name: contains path separator\n";
            return 1;
        }
    }
    if (new_name == "." || new_name == ".." || new_name.empty())
    {
        conn->write_buf = "invalid daemon name\n";
        return 1;
    }

    // If cluster is active, restart it with the new name.
    //
    // A rename that the cluster cannot honour is refused whole: the daemon goes
    // back to the name it had and republishes under it.  It used to keep the
    // new name, with clustering off and its old entry already deleted, so a
    // rejected rename cost the node its membership under a name that was never
    // in dispute.
    if (m_owned_cluster)
    {
        const std::string cluster_dir(m_owned_cluster->get_cluster_dir());
        const std::string old_name = m_daemon_name;

        m_daemon_name = new_name;
        if (start_cluster(new_name, cluster_dir))
            return 0;

        const std::string why = m_cluster_error;
        m_daemon_name = old_name;

        if (start_cluster(old_name, cluster_dir))
        {
            conn->write_buf = "rename refused: " + why + "\n"
                "  the daemon is still \"" + old_name + "\" and still in the cluster.\n";
        }
        else
        {
            conn->write_buf = "rename refused: " + why + "\n"
                "  and \"" + old_name + "\" could not be reclaimed either: "
                + m_cluster_error + "\n"
                "  cluster mode is now off; no peer can see this daemon.\n";
        }
        return 1;
    }

    // Not clustered, so nothing to republish.  Any standing refusal named the
    // old name and stops describing this daemon here; `cluster ls` goes back to
    // the plain "not in cluster mode" until --cluster is issued afresh.
    m_daemon_name = new_name;
    m_cluster_error.clear();
    return 0;
}

int daemon_handler::cmd_daemon_cluster(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2)
    {
        if (!m_cluster)
        {
            conn->write_buf = "cluster not active\n";
            return 1;
        }
        conn->write_buf = std::string(m_cluster->get_cluster_dir()) + "\n";
        return 0;
    }

    if (m_daemon_name.empty())
    {
        conn->write_buf = "--cluster requires --name to be set first\n";
        return 1;
    }

    std::string cluster_dir(pa.args[1]);

    // A flag that cannot be honoured is refused with the reason named, the same
    // way --sqpoll and --tls are, and it is refused loudly enough to survive the
    // exit code: the log says it, and every `socketley cluster` subcommand says
    // it afterwards.  What is never on offer is accepting --cluster and running
    // without it.
    if (!start_cluster(m_daemon_name, cluster_dir))
    {
        conn->write_buf = "cluster mode not enabled: " + m_cluster_error + "\n"
            "  this daemon keeps serving, but it publishes nothing into "
            + cluster_dir + " and no peer can see it.\n";
        return 1;
    }

    return 0;
}

void daemon_handler::set_metrics_port(uint16_t port)
{
    m_metrics_port = port;
}

int daemon_handler::cmd_dashboard(ipc_connection* conn)
{
    if (m_metrics_port == 0)
    {
        conn->write_buf = "metrics endpoint not configured\n"
            "add metrics_port = 9100 to socketley.conf to enable the dashboard\n";
        return 1;
    }

    conn->write_buf = "Dashboard: http://127.0.0.1:" + std::to_string(m_metrics_port) + "/\n";
    return 0;
}

// Frame one command's reply onto the end of the connection's outgoing stream:
// exit code byte, payload, NUL terminator — what ipc_client.cpp reads back.
//
// The payload is copied out of write_buf rather than framed in place.  write_buf
// is scratch that every cmd_* assigns to and that handle_read() clears before
// each command; out_buf is the only thing a write SQE is ever given, and it is
// appended to and never rebuilt.  The copy also drops the insert() this used to
// do to put the exit code in front, which shifted the whole reply.
void daemon_handler::append_response(ipc_connection* conn, int exit_code)
{
    conn->out_buf += static_cast<char>(exit_code);
    conn->out_buf += conn->write_buf;
    conn->out_buf += '\0';
}

// Submit the one write that carries everything append_response() has framed,
// starting from whatever a short write has already got out.
//
// One write outstanding per connection, and no read re-armed until it reports:
// that is what makes the buffer safe, and it is the whole of the fix.  This used
// to submit a write per command, out of the one write_req and the one write_buf.
// A client that put `ls` and `ps` in a single packet therefore had the second
// command clear and rebuild write_buf while the first write was still queued, so
// the kernel sent whatever the reallocated string had become — freed memory as
// often as not.  The one write_req carried both submissions at once, which left
// the two completions indistinguishable and the loop's per-request bookkeeping
// describing only the later of them.  And nothing linked the two SQEs, so the
// kernel was free to put the second reply on the wire first, handing the CLI one
// command's exit code in front of the other's output.
//
// False means the SQE never reached the ring.  Nothing will complete for this
// connection, so the caller must take it down rather than leave a client waiting
// on a reply that was never queued: what ended that wait before was the CLI's own
// five second SO_RCVTIMEO, and it ended it with "failed to connect to daemon" on
// a daemon that is running and healthy.
bool daemon_handler::send_response(ipc_connection* conn)
{
    char* base = conn->out_buf.data() + conn->write_off;
    const uint32_t len = static_cast<uint32_t>(conn->out_buf.size() - conn->write_off);

    conn->write_req.buffer = base;
    conn->write_req.length = len;

    if (!m_loop.submit_write(conn->fd, base, len, &conn->write_req))
    {
        LOG_ERROR("daemon: a CLI reply could not be queued; closing the connection "
                  "rather than leaving the client waiting for it");
        return false;
    }

    conn->write_pending = true;
    return true;
}
