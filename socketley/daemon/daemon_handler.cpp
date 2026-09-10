#include "daemon_handler.h"
#include "flag_handlers.h"
#include "type_manifest.h"
#include "../shared/command_usage.h"
#include "../shared/type_registry.h"
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
#include "../shared/paths.h"
#include "../shared/unix_listener.h"
#include "../shared/endpoint_table.h"
#include "../shared/worker_protocol.h"
#include "../shared/runtime_config_apply.h"
#include "../shared/ipc_framing.h"
#include "../shared/shard_target.h"
#include <sys/resource.h>
#include <sys/socket.h>
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
#include <fstream>
#include <sys/wait.h>
#include <csignal>
#include "../shared/logging.h"

// Two seconds is the backstop for a worker that has wedged, not a budget the
// normal path spends -- a child reports in 17-22 ms -- and it is one budget
// per command rather than per runtime, because every child is forked before
// any is waited on.
namespace
{
constexpr auto worker_startup_bound = std::chrono::milliseconds(2000);
}

std::string daemon_handler::socket_path = "/tmp/socketley.sock";
std::string daemon_handler::daemons_dir;
bool        daemon_handler::system_socket = false;

// A column is as wide as its widest value plus a gap, never narrower than its
// heading: TYPE was a fixed eight and a registered type's name is arbitrary, so
// `mdid_store` ran into PORT and left a row nothing could split into fields.
static int col_width(int base, size_t longest)
{
    return static_cast<int>(std::max(static_cast<size_t>(base), longest + 2));
}

// A daemon whose parent has not reaped it answers kill(pid, 0) and is counted
// live by it, so the state is read as well; over-reporting a daemon that is a
// corpse is the failure this hint exists to prevent, in miniature.
static bool is_zombie(pid_t pid)
{
    std::ifstream f("/proc/" + std::to_string(pid) + "/stat");
    std::string line;
    if (!std::getline(f, line))
        return false;

    // From the last `)`, because a comm field may hold both spaces and parens.
    const size_t close = line.rfind(')');
    if (close == std::string::npos || close + 2 >= line.size())
        return false;
    return line[close + 2] == 'Z';
}

// A second daemon is invisible from inside the first: SOCKETLEY_SOCKET moves
// the socket and the state directory together, so `ls` answers for whichever
// one the environment points at and never says which.
static std::string daemon_hint()
{
    if (daemon_handler::daemons_dir.empty())
        return {};

    int live = 0;
    std::error_code ec;
    for (const auto& e :
         std::filesystem::directory_iterator(daemon_handler::daemons_dir, ec))
    {
        if (e.path().extension() != ".daemon")
            continue;
        const std::string stem = e.path().stem().string();
        long pid = 0;
        const auto* end = stem.data() + stem.size();
        if (std::from_chars(stem.data(), end, pid).ptr != end || pid <= 0)
            continue;
        // The pid decides, not the file: a daemon killed outright leaves its
        // own behind, and EPERM is another user's live daemon.
        if (::kill(static_cast<pid_t>(pid), 0) == 0 || errno == EPERM)
            if (!is_zombie(static_cast<pid_t>(pid)))
                ++live;
    }

    // One daemon is the ordinary case and needs no line about it; the hint is
    // for the day the answer came from a daemon the operator forgot about.
    if (live < 2)
        return {};

    return "\n" + std::to_string(live) + " daemons are running; this is pid " +
           std::to_string(::getpid()) + " on " + daemon_handler::socket_path +
           " -- `socketley daemons` lists them all\n";
}

// Why this runtime's TLS configuration cannot be honoured, repeated wherever a
// runtime goes live because a state file written before the parse gate existed
// would otherwise bring up a cleartext listener `inspect` calls encrypted.
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

// Why this runtime's shard count cannot be honoured, asked of the instance,
// since a scripted server is no longer refused and there is nothing left for
// flag order to change.
static std::string instance_shards_refusal(const runtime_instance* inst)
{
    if (!inst)
        return {};

    return shards_config_refusal(inst->get_type(),
                                 inst->get_shards());
}

// Why a cache's persistence pair cannot be honoured, judged as a set because
// --persistent may be typed on either side of --persistent-interval.
static std::string instance_cache_persist_refusal(const runtime_instance* inst)
{
    if (!inst || inst->get_type() != runtime_cache)
        return {};

    const auto* cache = static_cast<const cache_instance*>(inst);
    if (cache->get_persist_interval() > 0 && cache->get_persistent().empty())
        return "--persistent-interval needs --persistent: the interval says how "
               "often the journal beside that file reaches the disk, and "
               "without the file there is nothing to journal beside\n";
    return {};
}

// Why this server's --mode and the three flags that only mean something in
// some of its answers cannot be honoured together.  The rule itself lives in
// server_instance.h beside the enums it is about, and start() asks the same
// question through config_refusal(), so a state file reaches it too; this
// wrapper exists only so a command can refuse BEFORE storing anything.
static std::string instance_server_mode_refusal(const runtime_instance* inst)
{
    return inst ? inst->config_refusal() : std::string{};
}

// Who is on the other end of this connection, or 0 when the socket cannot say.
static pid_t peer_pid(int conn_fd)
{
    struct ucred cred{};
    socklen_t    len = sizeof(cred);
    if (conn_fd < 0 ||
        ::getsockopt(conn_fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
        return 0;
    return cred.pid;
}

// The pid `attach --pid` names has to belong to the caller, judged from
// SO_PEERCRED against the owner of /proc/<pid>, because the packaged socket is
// group-readable and the daemon would otherwise lend out a privilege it was
// never asked to lend.
static std::string attach_pid_refusal(int conn_fd, pid_t pid)
{
    if (pid <= 0)
        return {};

    struct ucred cred{};
    socklen_t    len = sizeof(cred);
    if (conn_fd < 0 ||
        ::getsockopt(conn_fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
    {
        // No credentials means no way to judge on the path that decides who
        // may be signalled, so refusing is the answer that cannot be wrong in
        // the direction that matters.
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

// Why this runtime's --cpus request cannot be honoured, with the
// text on runtime_instance because the restore path meets the request again on
// a ring created before the state file was read.
static std::string instance_ring_refusal(const runtime_instance* inst,
                                         const event_loop& loop)
{
    if (!inst)
        return {};
    return inst->ring_policy_refusal(loop);
}

// cout is borrowed for the length of a command and given back, because every
// parser reports its refusals there and there is the daemon's stdout -- safe
// on this thread, which is the only one that writes cout.
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
        // channel, which keeps the old behaviour rather than losing the text
        // entirely.
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

// A running runtime shows how long it has been up and every other state shows
// its name, because printing an uptime for a runtime that never came up makes
// a failed one look healthy.
std::string state_column(const runtime_instance* inst)
{
    switch (inst->get_state())
    {
        case runtime_created: return "Created";
        case runtime_running:
        {
            std::string up = format_uptime(inst->get_start_time());
            // Said in the default column and not behind a flag, because the
            // reading it corrects -- a long uptime on a runtime that has lost
            // everything it held -- is the one an operator trusts.
            if (const unsigned r = inst->restart_count(); r > 0)
                up += " (" + std::to_string(r) + (r == 1 ? " restart)" : " restarts)");
            // Said last so it is the end of the line an operator reads, and
            // never instead of the uptime: the process is up, and that is the
            // whole point of the warning.
            if (inst->is_unresponsive())
                up += " NOT RESPONDING";
            return up;
        }
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

    // The map rides publish_endpoints() rather than growing a second list of
    // call sites, because both tables are stale at exactly the same moments;
    // the periodic push carries the connection counts, which move with no
    // event at all.
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
    // worker, given to the manager so socketley.send() gets the route
    // cmd_send() reaches by hand.
    m_manager.set_deliver_sink([this](std::string_view name,
                                      std::string_view message)
                               { return deliver_to_worker(name, message); });

    // And the moment before a runtime leaves the map, so a caller with only
    // the manager cannot free a placeholder out from under its supervisor.
    m_manager.set_worker_release_sink([this] { reconcile_proxy_workers(); });

    // And who answers for one shard, because only this side knows a name is N
    // processes and can register the qualified entries.
    m_manager.set_shard_sink_publisher([this](request_channel& ch)
                                       { publish_shard_sinks(ch); });

    // And a routing verb aimed at a runtime this process does not hold, as a
    // pointer rather than a lambda because the sink is an interface with two
    // contracts.
    m_manager.set_route_sink(this);

    // And a cluster event for the runtimes this process does not hold, which
    // is all of them, because dispatch_cluster_events reaches for a
    // lua_context a placeholder does not have.
    m_manager.set_cluster_event_sink(
        [this](const cluster_ev_wire& w)
        {
            const std::string payload = worker_proto::encode_cluster_event(w);
            for (auto& [name, shards] : m_proxy_workers)
            {
                (void)name;
                // Every shard, because a cluster event is about the cluster
                // and telling only shard 0 would run on_group_change in one of
                // four identical interpreters.
                for (auto& sup : shards)
                    if (sup)
                        sup->send_cluster_event(payload);
            }
        });
}

// Every shard of every sharded runtime under `name#index`, rebuilt wholesale
// so a retired supervisor is not still reachable, with the index being the
// position in the vector -- and meshing N shards needs N(N-1) descriptors at
// once, answered from RLIMIT_NOFILE and said out loud when it refuses.
bool daemon_handler::mesh_fits(size_t shards) const
{
    // The measurement control, so the mesh and the relay differ in the route
    // alone rather than in the build.
    if (const char* off = ::getenv("SOCKETLEY_NO_SHARD_MESH");
        off && *off && *off != '0')
    {
        LOG_INFO("shard mesh disabled by SOCKETLEY_NO_SHARD_MESH; shards relay "
                 "through the daemon");
        return false;
    }

    struct rlimit rl{};
    if (::getrlimit(RLIMIT_NOFILE, &rl) != 0)
        return false;               // cannot tell, so do not spend descriptors

    const uint64_t need   = static_cast<uint64_t>(shards) * (shards - 1);
    const uint64_t budget = (rl.rlim_cur == RLIM_INFINITY)
                          ? need                      // no limit to run into
                          : (static_cast<uint64_t>(rl.rlim_cur) / 2);
    const uint64_t headroom = 256;

    if (need + headroom <= budget)
        return true;

    LOG_WARN(("the shard mesh needs " + std::to_string(need)
              + " descriptors for " + std::to_string(shards)
              + " shards and the open-file limit leaves room for "
              + std::to_string(budget > headroom ? budget - headroom : 0)
              + "; this runtime's shards will relay through the daemon instead")
             .c_str());
    return false;
}

void daemon_handler::publish_shard_sinks(request_channel& ch)
{
    for (auto& [name, shards] : m_proxy_workers)
    {
        if (shards.size() <= 1)
            continue;
        for (size_t i = 0; i < shards.size(); ++i)
            ch.register_sink(shard_target(name, static_cast<uint32_t>(i)),
                             shards[i].get());
    }
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

daemon_handler::socket_state daemon_handler::probe_socket()
{
    int probe = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (probe < 0)
        return socket_state::free;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);
    const bool connected =
        connect(probe, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0;
    const int err = errno;

    // Raw close on purpose: this is a static probe with no event loop anywhere
    // in reach, so no SQE can ever have named this number and there is nothing
    // for close_fd() to hold it against.
    close(probe);

    if (connected)
        return socket_state::ours;

    // EACCES/EPERM is still "do not touch this path" -- the caller's next move
    // on `free` is a setup() that unlinks it, which in a directory with no
    // sticky bit would take the socket from the daemon that owns it.  What it
    // is NOT is a daemon of ours already serving, and answering both with one
    // boolean is what made the second exit 0 in silence.
    if (err == EACCES || err == EPERM)
        return socket_state::foreign;

    return socket_state::free;
}

bool daemon_handler::setup()
{
    unlink(socket_path.c_str());

    // SOCK_CLOEXEC, because without it a worker inherits the socket every CLI
    // command arrives on and answers "is a daemon serving this" for as long as
    // it lives.
    m_listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (m_listen_fd < 0)
        return false;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

    // ─── WHO MAY OPEN THE CONTROL PLANE ─────────────────────────────────────
    // A daemon serving the packaged path shares its socket with its own group
    // at 0660 and every other daemon keeps it at 0600, because connecting is
    // not a small thing to grant -- `create --lua` runs code as the daemon's
    // user -- and there is no window, since a bound socket refuses connect()
    // until listen().
    if (bind(m_listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        // Which path and why, because a daemon that cannot bind exits without
        // serving anything and "already in use" and "permission denied" want
        // opposite things done.
        LOG_ERROR(("ipc socket: " + std::string(addr.sun_path) + " could not be bound: " +
                   std::string(std::strerror(errno))).c_str());
        // Raw close on purpose, because the failure paths never reach the
        // accept at the bottom of this function and the number provably never
        // entered the ring.
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    // 0600 first and unconditionally so the packaged branch only ever widens,
    // and fatal on failure because a daemon serving its control plane at
    // whatever the umask left is not a state to have.
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
        // The group by name and not by whatever this process has, because
        // `sudo socketley daemon` would otherwise hand the socket to group
        // root -- and a refused chown leaves the 0600 it already has, which is
        // narrower rather than wider.
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
            // Only worth saying when the daemon is a dedicated user, because a
            // root daemon with no such group is the container image's
            // arrangement and a warning there is noise on every start.
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

// Arm the accept every CLI connection arrives through, whose only re-arm is
// its own completion, so a refused submission leaves the daemon deaf until the
// health tick picks the chain back up.
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
    // The workers first, every shard of every runtime, because a child left to
    // the destructor is an orphan still bound to its port and the next daemon
    // fails to bind.
    for (auto& [_, shards] : m_proxy_workers)
    for (auto& sup : shards)
    {
        sup->shutdown();
        if (const pid_t p = sup->release_pid(); p > 0)
            m_orphan_workers.push_back({p, std::chrono::steady_clock::now(), false});

        // Retired here too, so "a supervisor is never destroyed while
        // something still holds it" holds on both paths rather than only on
        // the reported one.
        if (sup->retire() != 0) {}
    }
    m_proxy_workers.clear();

    // Wait for the children just told to go, because PR_SET_PDEATHSIG is
    // SIGKILL and exiting while a worker unwinds turns a graceful shutdown
    // into a kill -- bounded shorter than reap_orphan_workers()' own
    // escalation, which handles a worker that will not leave.
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

    // Reaped here for the case teardown() does not end in exit(), or a daemon
    // torn down and set up again carries the previous generation's zombies.
    reap_orphan_workers();

    // Nothing may call the sink once the workers are gone: it would encode a
    // table for an empty map, which is harmless, but the manager outlives this
    // handler and the lambda captures `this`.
    m_manager.set_endpoint_sink(nullptr);
    m_manager.set_publish_sink(nullptr);
    m_manager.set_deliver_sink(nullptr);
    m_manager.set_worker_release_sink(nullptr);
    m_manager.set_route_sink(nullptr);

    // Reap managed children
    {
        std::shared_lock lock(m_manager.mutex);
        for (auto& [name, inst] : m_manager.list())
        {
            if (inst->is_managed() && inst->get_pid() > 0)
                waitpid(inst->get_pid(), nullptr, WNOHANG);
        }
    }

    // The health timer, which nothing below reaches because a timeout hangs
    // off no descriptor, withdrawn once per teardown -- a formality on the
    // daemon's path, written for the destructor's, and it only makes the
    // -ECANCELED arrive now rather than in two seconds.
    if (m_health_pending && !m_torn_down)
    {
        // The answer is ignored on purpose, because false means either the
        // ring is already gone or the submission was refused, and all that is
        // left for the second is to let the timer fire.
        if (!m_loop.submit_timeout_remove(&m_health_req)) {}

        // m_health_pending stays set, because the withdrawn timeout still owes
        // one completion carrying this request and clearing it would let a
        // later arm hand the kernel a request it is already carrying one for.
    }
    m_torn_down = true;

    // Anything a worker was still waiting on is refused rather than dropped,
    // because the nop that would serve it is not coming and silence costs the
    // script its whole deadline.
    for (auto& q : m_map_queue)
    {
        proxy_supervisor::answer_map_request(q.reply_fd, q.ticket, false,
                                             "the daemon is shutting down");
        if (q.reply_fd >= 0)
            ::close(q.reply_fd);
    }
    m_map_queue.clear();

    // Stop cluster discovery before closing IPC, because this is the graceful
    // path the man page calls "file deleted, peers drop it at once" and it has
    // to reach unpublish().
    stop_cluster();

    // After stop_cluster(), which is the last thing that can add to it, and
    // everything here was retired on a path where waiting longer is not on
    // offer.
    m_retired_handlers.clear();

    // Through the loop and not close(), because every one of these numbers has
    // been named by an SQE -- a formality on the daemon's own path, and
    // written this way because teardown() is also the destructor's.
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

    // Connections already handed to close_fd() in handle_read(), whose
    // descriptors are the loop's business now, so only the storage is ours to
    // drop.
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
        case op_nop:
            // The loop coming back once every handler on the stack has
            // unwound, with the address checked anyway because a nop's type
            // says nothing about who asked for it.
            if (req == &m_map_defer_req)
            {
                m_map_defer_armed = false;
                if (!m_torn_down)
                    serve_map_requests();
            }
            break;
        case op_timeout:
            if (req == &m_health_req)
            {
                m_health_pending = false;

                // The withdrawal teardown() submitted, answered, with nothing
                // left to supervise and nothing to re-arm.
                if (m_torn_down)
                    break;

                // The accept chain ends at a refused submission and only
                // something outside it can restart one — this tick is the only
                // thing that runs without a CLI connection to run for.
                if (m_listen_fd >= 0 && !m_accept_armed)
                    start_accept();

                check_managed_health();
                // Release the retired runtimes the ring has finished with,
                // because removal only ever reaps the ones retired before it
                // and the last runtime a daemon removes would keep its whole
                // object.
                m_manager.reap_retired(m_loop);
                start_health_timer();
            }
            break;
        default:
            break;
    }
}

// A write submitted by send_response() has reported, which for a live
// connection re-arms the read and for a parked one is the only thing that can
// say the ring has finished with the buffer.
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

    // A failed send says the reply is not going to be delivered, so this
    // connection goes rather than sitting in m_clients with nothing armed on
    // it.
    if (cqe->res <= 0)
    {
        close_client(it);
        return;
    }

    // send() is entitled to take less than it was given, and the rest used to
    // be dropped, so a CLI reading to the NUL terminator sat out its timeout
    // and reported the daemon unreachable.
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

// Take a client connection down, reached from every path where the daemon can
// no longer finish the exchange, all of which require that it not be left
// waiting for a completion that is never coming.
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

    // The only close here that happens while the ring is live, so close_fd()
    // holds the number until a queued reply write reports -- otherwise the
    // next CLI connection finds somebody else's `ls` output spliced into its
    // own.
    m_loop.close_fd(fd);

    // Whatever fd_inflight() still counts is that queued write pointing at
    // write_req and out_buf inside this connection, so the connection is
    // parked and released by the write's own completion.
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

        // Not "a completion arrived" but "nothing else names this number",
        // asked of the loop rather than assumed, because a client that
        // pipelined two commands once got two writes through one write_req.
        if (m_loop.fd_inflight((*it)->fd) == 0)
            m_closing.erase(it);
        return;
    }
}

void daemon_handler::handle_accept(struct io_uring_cqe* cqe)
{
    // This completion is the accept, spent, cleared before anything can fail
    // so the re-arm and the health tick both see the truth.
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

        // Refused, so this connection never hears from the daemon again, and
        // with nothing queued against the number close_client() closes it
        // outright for an immediate EOF.
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

    // Cannot happen, and checked for what it would mean: a read armed with a
    // write outstanding is the daemon rebuilding a buffer the kernel is still
    // reading.
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
                    static_cast<server_instance*>(inst)->broadcast(line);
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
    // A command is a line unless it begins with the frame marker, and both are
    // handled in one loop because both can arrive in one packet.
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
                // A length past the cap means this stream's framing is wrong
                // and no point in the buffer is provably the start of the next
                // frame.
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
    // The reply guard is held here rather than in each handler, because a
    // per-handler list goes stale the moment somebody adds a command -- which
    // is how four of them came to write to the daemon's own stdout.
    const cout_to_reply reply_guard(conn);

    parsed_args pa;
    pa.parse(line);

    if (pa.count == 0)
    {
        std::cout << "no command\n";
        return 1;
    }

    // parsed_args merges the tail into its last slot, which is right for the
    // three commands whose final argument is free text and wrong for every
    // command that reads a list, so the allowlist is three entries rather than
    // a rule.
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
        case fnv1a("daemon-stop"): return cmd_daemon_stop(conn);
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

// conn is unused and stays anyway, because the dispatcher hands every handler
// the connection and dropping it here would make this signature the odd one
// out.
int daemon_handler::cmd_create([[maybe_unused]] ipc_connection* conn,
                              const parsed_args& pa)
{
    if (pa.count < 3)
    {
        std::cout << command_usage::line("create");
        return 1;
    }

    runtime_type type;
    if (!parse_runtime_type(pa.args[1], type))
    {
        std::cout << "unknown runtime type: " << pa.args[1] << "\n";
        return 1;
    }

    std::string_view name = pa.args[2];

    // The reason and not a guess at it, because this reported "runtime already
    // exists" for a name refused for its characters on a daemon holding
    // nothing.
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
                         "  may not contain '..', and may be at most 128 "
                         "characters.\n";
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

    // Every runtime runs in its own process, with nothing to type, because the
    // flag that bought back the map calls and routing is a flag whose purpose
    // no longer exists -- and with one answer there is no argument order left
    // to get wrong.
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
                default:
                    // A registered type's flags come from its manifest schema.
                    result = type_manifest::parse_registered_flag(instance, pa, i);
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

    // The TLS options are checked as a set once every flag has been seen,
    // which is the first point the question can be answered, and refusing here
    // keeps the runtime from being created at all.
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

    // And the shard count, for the same reason, because --listen may be typed
    // on either side of --shards.
    if (const std::string msg = instance_shards_refusal(instance);
        !msg.empty())
    {
        std::cout << msg;
        m_manager.remove(name);
        return 1;
    }

    // And the cache's persistence pair, whose halves may arrive in either
    // order as well.
    if (const std::string msg = instance_cache_persist_refusal(instance);
        !msg.empty())
    {
        std::cout << msg;
        m_manager.remove(name);
        return 1;
    }

    // And --send-to, --udp and --master-pw against --mode, as one question
    // because they are one answer and --mode may be typed on either side of
    // any of them.
    if (const std::string msg = instance_server_mode_refusal(instance); !msg.empty())
    {
        std::cout << msg;
        m_manager.remove(name);
        return 1;
    }

    // A registered type's required keys, at the point the TLS set is checked
    // and for the same reason, with declared defaults filled in on the way.
    if (const std::string msg = type_manifest::registered_create_refusal(instance);
        !msg.empty())
    {
        std::cout << msg;
        m_manager.remove(name);
        return 1;
    }

    // The script last, because loading snapshots `self` from the instance and
    // because a runtime about to be refused must not have run a line of
    // anybody's script first.
    if (!lua_script.empty() && !instance->load_lua_script(lua_script))
    {
        // The reason and not just the fact, because the parse error or the
        // validator's sentence went to the daemon's log one process away from
        // the terminal that ran the command.
        std::cout << "could not load Lua script: " << lua_script << "\n";
        if (!lua_diag::text().empty())
            std::cout << lua_diag::text() << "\n";
        m_manager.remove(name);
        return 1;
    }

    if (autostart && !instance->get_test_mode())
    {
        std::string refusal;
        if (!m_manager.start(name, m_loop, &refusal))
        {
            std::cout << (refusal.empty() ? "could not start runtime\n" : refusal);
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

        // The answer waits for the process that decides it, because the script
        // runs, the port binds and the TLS pair is checked in the worker --
        // and the runtime is left `failed` rather than removed, so the
        // worker's reason is not the only record of a runtime the operator can
        // no longer ask about.
        std::string wmsg;
        const int   wrc = await_worker_startup(
            name, wmsg, std::chrono::steady_clock::now() + worker_startup_bound);
        if (wrc != 0)
        {
            std::cout << wmsg;
            return wrc;
        }

        // `instance` may not exist any more, because the wait serves map
        // requests inline and a script's own `socketley.remove` frees a
        // placeholder that never reached setup(), so the name is re-resolved
        // rather than cached.
        instance = m_manager.get(name);
        if (!instance)
            return 0;
    }

    // A script whose on_start raised is not a silent success, reported last
    // because nothing above is undone, and as exit 1 because the fault is in
    // the file the operator named.
    if (autostart && !instance->get_test_mode())
    {
        // Two places to ask, because on_start runs wherever the script runs
        // and the worker leg is the ordinary `create -s`.
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
        std::cout << command_usage::line("start");
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

    // Refused before anything is started rather than after, and it stays a
    // refusal because a proxy has no stream for typed input to mean anything
    // on.
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
    // The ones this command actually brought up, collected because a
    // worker-backed runtime's verdict cannot be read until
    // reconcile_proxy_workers() has forked the child.
    std::vector<std::string> started;
    for (const auto& n : names)
    {
        // Allow -i on already-running runtimes (attach without start)
        auto* inst = m_manager.get(n);
        bool already_running = inst && inst->get_state() == runtime_running;

        if (!already_running)
        {
            // Refuse to bring up a listener that would serve cleartext under a
            // configuration promising encryption, reached by runtimes restored
            // from a state file written before TLS was gated.
            if (const std::string msg = instance_tls_refusal(inst); !msg.empty())
            {
                conn->write_buf += std::string(n) + ": " + msg;
                ++failed;
                continue;
            }

            // Reached by a runtime whose shard count came from a hand-written
            // state file, which start() also refuses -- but only this puts the
            // reason on the terminal of whoever typed `start`.
            if (const std::string msg = instance_shards_refusal(inst); !msg.empty())
            {
                conn->write_buf += std::string(n) + ": " + msg;
                ++failed;
                continue;
            }

            // The persistence pair on the same reasoning: only a hand-written
            // state file can hold an interval without a path.
            if (const std::string msg = instance_cache_persist_refusal(inst);
                !msg.empty())
            {
                conn->write_buf += std::string(n) + ": " + msg;
                ++failed;
                continue;
            }

            // And the server's --mode set, named here rather than left to
            // start(): the runtime would refuse there anyway, but this reply
            // carries the runtime's name and start()'s only goes to the log.
            if (const std::string msg = instance_server_mode_refusal(inst);
                !msg.empty())
            {
                conn->write_buf += std::string(n) + ": " + msg;
                ++failed;
                continue;
            }

            std::string refusal;
            if (!m_manager.start(n, m_loop, &refusal))
            {
                conn->write_buf += refusal.empty()
                                       ? "failed to start: " + std::string(n) + "\n"
                                       : refusal;
                ++failed;
                continue;
            }
            if (m_persistence)
                m_persistence->set_was_running(n, true);
            inst = m_manager.get(n);
            started.push_back(n);

            // The runtime is up and its script's set-up is not, counted rather
            // than returned because `start a b c` has to start b and c, with
            // was_running set anyway and the reason read below, where a
            // worker's frame has arrived.
        }

        if (want_interactive && inst)
        {
            // The proxy case was refused above, before anything was started.
            conn->interactive = true;
            conn->interactive_name = n;
            inst->add_interactive_fd(conn->fd);
        }
    }

    // Any runtime just moved into `running` in a worker now needs its child,
    // done here rather than on the health timer so `start` followed
    // immediately by a request works.
    reconcile_proxy_workers();

    // `start` waits for the answer exactly as `create -s` does, because it was
    // reporting success for a start that did not happen -- one child's startup
    // for the whole command, since every child is forked before any is waited
    // on.
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

            // The runtime is up and its script's set-up is not, counted rather
            // than returned, with was_running set anyway because the operator
            // asked for this runtime to be up and it is.
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
        conn->write_buf = command_usage::line("stop");
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
        conn->write_buf = command_usage::line("remove");
        return 1;
    }

    auto names = resolve_names(pa);
    int rc = check_empty_names(names, pa, "runtime not found: ", conn);
    if (rc >= 0) return rc;

    // A caller cannot mean "signal me".  Removing an external runtime SIGTERMs
    // the pid it attached with, which is right for an operator and fatal for
    // the process itself: daemon_detach() sends this command and then waits for
    // the reply, so the signal landed on a program inside its own detach --
    // and daemon_attach() registers that same call with atexit, so it landed
    // on every SDK program that had ever attached, at exit.
    const pid_t asking = peer_pid(conn ? conn->fd : -1);

    for (const auto& n : names)
    {
        auto* inst = m_manager.get(n);
        if (!inst || inst->get_state() != runtime_running)
            continue;
        if (inst->is_external() && asking > 0 && inst->get_pid() == asking)
            continue;   // unregistered below; the state it leaves in is not read
        m_manager.stop(n, m_loop);
    }

    // Before the instances leave the map, because the supervisor holds a
    // pointer to the placeholder it writes stats into and that pointer must be
    // dropped while the object is still there.
    reconcile_proxy_workers();

    for (const auto& n : names)
    {
        // Nothing is held on this side any more, because remove() hands the
        // runtime to the manager's graveyard -- and the list that used to hold
        // it here was emptied by a timeout whose answer nobody read.
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
        // `--format json` is the only spelling there is, so anything else is
        // refused rather than answered in a format the operator did not ask
        // for.
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

    // `-s` with no column named prints only runtime names, as documented,
    // rather than the whole table with the header off.
    if (silent && !col_id && !col_name && !col_type && !col_port &&
        !col_status && !col_conn && !col_owner && !col_created && !col_group)
        col_name = true;

    bool any_col = col_id || col_name || col_type || col_port ||
                   col_status || col_conn || col_owner || col_created || col_group;

    // Checked here rather than at the top because an empty listing is exactly
    // where the wrong daemon looks like an idle one, and the hint below is the
    // only thing that would say otherwise.
    if (runtimes.empty())
    {
        if (!json_format && !any_col && !silent)
            conn->write_buf = daemon_hint();
        return 0;
    }

    if (json_format)
    {
        std::ostringstream out;
        out << "[";
        bool first = true;
        for (const auto& [name, instance] : runtimes)
        {
            if (!first) out << ",";
            first = false;
            const char* state_str = state_to_string(instance->get_state());
            uint16_t port = instance->get_port();
            auto owner = instance->get_owner();
            auto group = instance->get_group();
            // Escaped, all of them, because a group and an owner are arbitrary
            // operator strings -- and where a runtime with no port listens,
            // empty for every other runtime.
            const std::string_view listen_path = instance->get_listen_path();
            out << "{\"id\":\"" << sp_detail::json_escape(instance->get_id())
                << "\",\"name\":\"" << sp_detail::json_escape(name)
                << "\",\"type\":\"" << type_to_string(instance->get_type())
                << "\",\"port\":" << port
                << ",\"listen\":\""
                << (listen_path.empty() ? std::string()
                                        : "unix:" + sp_detail::json_escape(listen_path))
                << "\",\"status\":\"" << state_str
                << "\",\"restarts\":" << instance->restart_count()
                << ",\"connections\":" << instance->reported_connection_count()
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
        size_t w_name = 0, w_type = 0, w_owner = 0, w_status = 0;
        for (const auto& [name, instance] : runtimes)
        {
            w_name  = std::max(w_name, name.size());
            w_type  = std::max(w_type, std::strlen(type_to_string(instance->get_type())));
            w_owner = std::max(w_owner, instance->get_owner().size());
            w_status = std::max(w_status, state_column(instance.get()).size());
        }
        const int cw_name   = col_width(16, w_name);
        const int cw_type   = col_width(8,  w_type);
        const int cw_owner  = col_width(12, w_owner);
        const int cw_status = col_width(20, w_status);

        if (!silent)
            out << std::setw(10) << "ID"
                << std::setw(cw_name) << "NAME"
                << std::setw(cw_type) << "TYPE"
                << std::setw(8)  << "PORT"
                << std::setw(6)  << "CONN"
                << std::setw(cw_owner) << "OWNED BY"
                << std::setw(cw_status) << "STATUS"
                << "CREATED\n";

        for (const auto& [name, instance] : runtimes)
        {
            const std::string status_buf = state_column(instance.get());
            const char* status_str = status_buf.c_str();
            uint16_t port = instance->get_port();
            auto owner = instance->get_owner();
            out << std::setw(10) << instance->get_id()
                << std::setw(cw_name) << name
                << std::setw(cw_type) << type_to_string(instance->get_type())
                << std::setw(8)  << (port > 0 ? std::to_string(port) : "-")
                << std::setw(6)  << instance->reported_connection_count()
                << std::setw(cw_owner) << (owner.empty() ? "-" : std::string(owner))
                << std::setw(cw_status) << status_str
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
            std::string status = state_column(instance.get());
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

    if (!any_col && !silent)
        out << daemon_hint();

    conn->write_buf = out.str();
    return 0;
}

// Bare `ps` lists running runtimes and `-a` widens it, because `failed` is
// exactly the state you go looking for and was the one state this could not
// show.
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
        // `--format json` is the only spelling there is, so anything else is
        // refused rather than answered in a format the operator did not ask
        // for.
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

    // Nothing to list means no output rather than an empty table, with the
    // flags parsed above because `-a` decides what nothing to list means.
    const auto listed = [&](const runtime_instance* inst)
    { return all || inst->get_state() == runtime_running; };

    // As in cmd_ls: `-s` alone is the names-only listing both the man page and
    // the help script promise; a named column keeps it meaning header-off.
    if (silent && !col_id && !col_name && !col_type && !col_port &&
        !col_uptime && !col_conn && !col_owner && !col_created)
        col_name = true;

    bool any_col = col_id || col_name || col_type || col_port ||
                   col_uptime || col_conn || col_owner || col_created;

    if (std::none_of(runtimes.begin(), runtimes.end(),
                     [&](const auto& p) { return listed(p.second.get()); }))
    {
        if (!json_format && !any_col && !silent)
            conn->write_buf = daemon_hint();
        return 0;
    }

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
            // The state is read rather than written as "running", because
            // under -a a literal would be a row for a failed runtime claiming
            // to be up.
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
                << "\",\"restarts\":" << instance->restart_count()
                << ",\"connections\":" << instance->reported_connection_count()
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
        // Over the rows this will print, not every runtime: `ps` without -a
        // leaves the stopped ones out and their names should not widen it.
        size_t w_name = 0, w_type = 0, w_owner = 0, w_status = 0;
        for (const auto& [name, instance] : runtimes)
        {
            if (!listed(instance.get()))
                continue;
            w_name  = std::max(w_name, name.size());
            w_type  = std::max(w_type, std::strlen(type_to_string(instance->get_type())));
            w_owner = std::max(w_owner, instance->get_owner().size());
            w_status = std::max(w_status, state_column(instance.get()).size());
        }
        const int cw_name   = col_width(16, w_name);
        const int cw_type   = col_width(8,  w_type);
        const int cw_owner  = col_width(12, w_owner);
        const int cw_status = col_width(20, w_status);

        if (!silent)
            out << std::setw(10) << "ID"
                << std::setw(cw_name) << "NAME"
                << std::setw(cw_type) << "TYPE"
                << std::setw(8)  << "PORT"
                << std::setw(6)  << "CONN"
                << std::setw(cw_owner) << "OWNED BY"
                << std::setw(cw_status) << "STATUS"
                << "CREATED\n";

        for (const auto& [name, instance] : runtimes)
        {
            if (!listed(instance.get()))
                continue;
            uint16_t port = instance->get_port();
            auto owner = instance->get_owner();
            out << std::setw(10) << instance->get_id()
                << std::setw(cw_name) << name
                << std::setw(cw_type) << type_to_string(instance->get_type())
                << std::setw(8)  << (port > 0 ? std::to_string(port) : "-")
                << std::setw(6)  << instance->reported_connection_count()
                << std::setw(cw_owner) << (owner.empty() ? "-" : std::string(owner))
                << std::setw(cw_status) << state_column(instance.get())
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

    if (!any_col && !silent)
        out << daemon_hint();

    conn->write_buf = out.str();
    return 0;
}

// The one command whose answer is the daemon itself, leading with a literal no
// other program produces by accident and carrying the version and pid, cheap
// enough to run ahead of every CLI command.
int daemon_handler::cmd_ping(ipc_connection* conn)
{
    if (!conn)
        return 0;

    std::ostringstream out;
    out << socketley::daemon_ident_prefix << SOCKETLEY_VERSION
        << ' ' << getpid();

    // And which executable this daemon is, which the version cannot answer,
    // read fresh because the link gains " (deleted)" the moment the file is
    // unlinked -- and last in the reply, because a path may contain spaces.
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
        conn->write_buf = command_usage::line("owner");
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

// One rule and two callers, written as one function because two copies of the
// routing would be two answers to "is a send delivered", which this tree has
// already got wrong in exactly this place.
bool daemon_handler::deliver_to_runtime(std::string_view name,
                                        std::string_view message,
                                        std::string& why,
                                        const proxy_supervisor* exclude)
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

    // The connections are wherever the runtime is, because calling
    // broadcast() on a placeholder succeeded, returned 0, and sent the
    // message nowhere.
    if (instance->is_out_of_process())
    {
        // deliver_to_worker() fans the message out across every shard and
        // answers true if any took it.
        if (!deliver_to_worker(name, message, exclude))
        {
            // With `exclude` set this is a sibling fan-out with no siblings
            // left, so nothing was owed a delivery and it is not an error.
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
                srv->broadcast(message);
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
        std::cout << command_usage::line("send");
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

// The same verb arriving from a worker's script, answered by nothing, with
// what the replica was too old to know said in the log rather than dropped.
void daemon_handler::on_worker_deliver(proxy_supervisor* from,
                                       std::string_view name,
                                       std::string_view message)
{
    // Whether this is a cross-runtime send or a sibling fan-out is derived
    // from the name rather than carried on the wire, because a bit on the
    // frame is a second place for the two sides to disagree.
    const proxy_supervisor* exclude = nullptr;
    if (from)
        if (const auto it = m_proxy_workers.find(std::string(name));
            it != m_proxy_workers.end())
            for (const auto& sup : it->second)
                if (sup.get() == from)
                {
                    exclude = from;
                    break;
                }

    std::string why;
    if (!deliver_to_runtime(name, message, why, exclude))
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
        // Both readings, leading with the typo, which is the rule
        // test_cli_unknown_command.sh states for `socketley <word>` and which
        // this arm was left out of: `socketley stpo c1` answered "runtime not
        // found: stpo" and sent the reader looking for a runtime nobody meant.
        conn->write_buf = "unknown command: " + std::string(name) + "\n"
                        + "  If " + std::string(name) + " is a runtime, it does"
                          " not exist here; `socketley ls` lists them.\n";
        return 1;
    }

    if (instance->get_state() != runtime_running)
    {
        conn->write_buf = "runtime is not running: " + std::string(name) + "\n";
        return 1;
    }

    runtime_type type = instance->get_type();

    // ── Where a cache command runs ──────────────────────────────────────────
    // Every arm below calls the instance directly, which was right while a
    // runtime could live in the daemon and has been wrong since none can: the
    // object here is a placeholder, so `set` wrote a store no client reads,
    // `get` read it back and agreed with itself, and `flush` saved it over the
    // dump the worker's real keys were in.  The text goes to the worker
    // instead, which is what a client on the port sends anyway.
    //
    // `send` is not a cache command and keeps its own path; `memory` is half
    // configuration the daemon owns, so it is finished below rather than here.
    if (type == runtime_cache && instance->is_out_of_process()
        && action != "send" && action != "memory")
        return run_cache_action(conn, name, action, pa.rest_from(2));

    if (type == runtime_cache && instance->is_out_of_process()
        && action == "memory")
    {
        // The cap is what this runtime was configured with and the daemon has
        // it; the bytes in use are the worker's and only the worker knows.
        auto* cache = static_cast<cache_instance*>(instance);
        const std::string cap = std::to_string(cache->get_max_memory());
        const int rc = run_cache_action(conn, name, action, "memory");
        if (rc == 0)
            conn->write_buf = cap + " " + conn->write_buf;
        return rc;
    }

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
            if (ec != std::errc{} || ptr != sv.data() + sv.size() || seconds <= 0)
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
            // deliver_to_runtime(), which is what `socketley send NAME MSG`
            // has always used.  This spelling called broadcast()/lua_send() on
            // the PLACEHOLDER, and every CLI runtime is one -- cmd_create marks
            // them out-of-process -- so its connection table is empty and the
            // message went nowhere, with rc 0.  Two spellings of one verb, one
            // of which worked; deliver_to_runtime says so in its own comment
            // and routes to the worker.
            std::string why;
            if (!deliver_to_runtime(name, pa.rest_from(3), why))
            {
                conn->write_buf = why + "\n";
                return 1;
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
        std::cout << command_usage::line("edit");
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

    // What the runtime's TLS configuration was before this edit, because the
    // flags only mean anything as a set and an incomplete one has to leave no
    // trace.
    const bool        tls_before  = instance->get_tls();
    const std::string cert_before(instance->get_cert_path());
    const std::string key_before(instance->get_key_path());
    const std::string ca_before(instance->get_ca_path());
    // The same rule for the same reason, one set along: --shards and --listen
    // are only meaningful together, and a pair that comes out incompatible has
    // to leave the runtime exactly as it found it.
    const uint32_t    shards_before = instance->get_shards();
    const std::string listen_before(instance->get_listen_path());
    // The proxy's half of the same set, whose backend leg is as much a set as
    // the listener's.
    std::string_view mca_v, mcert_v, mkey_v;
    instance->get_mesh_tls_paths(mca_v, mcert_v, mkey_v);
    const std::string mesh_ca_before(mca_v), mesh_cert_before(mcert_v),
                      mesh_key_before(mkey_v);
    // And the server's, which is four flags deciding one question: --mode says
    // what this runtime is, and --send-to, --udp and --master-pw each mean
    // something only in some of the answers.  `edit` accepts all four, so it
    // can complete an incompatible set that `create` would have refused --
    // measured: a legal master server edited to `--mode inout` kept its
    // password and relayed it to the other connections again.
    server_mode mode_before      = mode_inout;
    uint8_t     send_to_before   = send_to_unset;
    bool        udp_before       = false;
    std::string master_pw_before;
    if (type == runtime_server)
    {
        const auto* srv_b = static_cast<const server_instance*>(instance);
        mode_before      = srv_b->get_mode();
        send_to_before   = srv_b->get_send_to();
        udp_before       = srv_b->is_udp();
        master_pw_before = std::string(srv_b->get_master_pw());
    }

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
                    // There is no parse_cache_edit_flags, so cache flags fall
                    // through here with a message that sends the operator to
                    // `import` rather than reading as a typo.
                    result = -1;
                    break;
                default:
                    // A registered type's fields reach its worker at the next
                    // start, which is when the config frame is built.
                    result = type_manifest::parse_registered_flag(instance, pa, i);
                    break;
            }
        }

        if (result == -1)
        {
            static constexpr uint32_t cache_only[] = {
                fnv1a("--maxmemory"), fnv1a("--eviction"), fnv1a("--persistent"),
                fnv1a("--replicate"), fnv1a("--resp"), fnv1a("--cluster"),
                fnv1a("--persistent-interval"),
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

    // The shard set, checked here because --listen and --shards are both
    // editable and either can complete an incompatible pair, and rolled back
    // the same way.
    if (const std::string msg = instance_shards_refusal(instance); !msg.empty())
    {
        instance->set_shards(shards_before);
        instance->set_listen_path(listen_before);
        std::cout << msg;
        return 1;
    }

    // The server set, rolled back as one because the four flags are one
    // answer: restoring only the flag that was typed would leave the runtime
    // in a state no `create` could have produced.
    if (type == runtime_server)
    {
        const std::string msg = instance_server_mode_refusal(instance);
        if (!msg.empty())
        {
            auto* srv_r = static_cast<server_instance*>(instance);
            srv_r->set_mode(mode_before);
            srv_r->set_send_to(send_to_before);
            srv_r->set_udp(udp_before);
            srv_r->set_master_pw(master_pw_before);
            std::cout << msg;
            return 1;
        }
    }

    if (m_persistence)
        m_persistence->save_runtime(instance);

    // A runtime in a worker keeps its own copy of the configuration, and the
    // object edited above is the daemon's placeholder.  Without this the edit
    // was stored, reported by `show`, answered 0 -- and the process holding the
    // port went on enforcing the value it was spawned with.
    //
    // Sent to every shard, because leaving one on the old limit is a runtime
    // that enforces two.  What arrives is the whole configuration and not a
    // delta; the worker takes the part a live runtime can take.
    if (is_running && m_persistence)
    {
        if (auto it = m_proxy_workers.find(std::string(name));
            it != m_proxy_workers.end() && !it->second.empty())
        {
            const runtime_config cfg = m_persistence->read_from_instance(instance);
            const std::string json = m_persistence->format_json_pretty(cfg);
            for (auto& sup : it->second)
                sup->send_config(json);
        }
    }

    return 0;
}

int daemon_handler::cmd_dump(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2)
    {
        conn->write_buf = command_usage::line("show");
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
        conn->write_buf = command_usage::line("import");
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

    // The listener field is re-read from the document rather than taken from
    // cfg, because parse_json_string cannot tell a missing `unix:` prefix from
    // a field cleared on purpose.
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

    // Judged on the result and not on the document, because an omitted field
    // now leaves the runtime's own value in place -- so reading cfg would pass
    // a TLS cache handed only a replicate_target.
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

    // The shard set merged the same way and before the apply, because import
    // has no rollback and a refusal later would leave the runtime
    // half-changed.
    const uint32_t    eff_shards = merged("shards", cfg.shards,
                                          instance->get_shards());
    const std::string eff_listen = merged("listen", cfg.listen_path,
                                          std::string(instance->get_listen_path()));

    if (const std::string msg = shards_config_refusal(type, eff_shards);
        !msg.empty())
    {
        conn->write_buf = msg;
        return 1;
    }

    // The cache's persistence pair judged on the result as well, because a
    // document may set the interval while clearing or omitting the path.
    if (type == runtime_cache)
    {
        const auto* cache = static_cast<const cache_instance*>(instance);
        const std::string eff_path = merged("persistent_path",
                                            cfg.persistent_path,
                                            std::string(cache->get_persistent()));
        const uint32_t eff_ival = merged("persistent_interval",
                                         cfg.persistent_interval,
                                         cache->get_persist_interval());
        if (eff_ival > 0 && eff_path.empty())
        {
            conn->write_buf =
                "persistent_interval needs persistent_path: the interval says "
                "how often the journal beside that file reaches the disk, and "
                "without the file there is nothing to journal beside\n";
            return 1;
        }
    }

    // A registered type's fields against its schema, here with the other
    // refusals because import has no rollback, so a misspelled key is named
    // before anything is stored.
    if (const std::string msg = type_manifest::extra_refusal(type, cfg.extra);
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
        // Two reasons said apart, because "already taken" for a name with a
        // slash in it sends the operator looking for a runtime that does not
        // exist.
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
        // The listener's other spelling under the same rule, because a running
        // server is bound to the socket node it has and moving it would leave
        // that node for a teardown that never came.
        if (cfg.listen_path != std::string(instance->get_listen_path()))
        {
            conn->write_buf = "cannot change the listen socket while running\n";
            return 1;
        }
        // The same rule as the port above, because applying it to a running
        // proxy would retire workers out from under live connections.
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
            // A running cluster has already published its map, so every client
            // holding it would keep sending keys to ports that had stopped
            // answering.
            if (cfg.cluster != cache->get_cluster())
            {
                conn->write_buf = "cannot change cluster mode while running\n";
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
    // A field the document leaves out keeps its current value rather than
    // being cleared, because applying every default meant `import c
    // '{"name":"c"}'` silently took a runtime's TLS away -- clearing is still
    // possible and now has to be written.
    const auto has = [&cfg](const char* key) { return cfg.has(key); };

    if (has("port"))              instance->set_port(cfg.port);
    if (has("listen"))            instance->set_listen_path(cfg.listen_path);
    if (has("log_file"))          instance->set_log_file(cfg.log_file);
    if (has("write_file"))        instance->set_write_file(cfg.write_file);
    if (has("bash_output"))       instance->set_bash_output(cfg.bash_output);
    if (has("bash_prefix"))       instance->set_bash_prefix(cfg.bash_prefix);
    if (has("bash_timestamp"))    instance->set_bash_timestamp(cfg.bash_timestamp);
    // The three flags a client does not have are refused here too, because
    // import does not go through the flag parser and a validation that guards
    // one entrance is not there.
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
    // Carried into this form from the block it replaced, because `show` emits
    // shards and a round trip that dropped it would return a sharded proxy
    // with one worker.
    if (has("shards"))            instance->set_shards(cfg.shards);

    // Lua script, reloaded if changed and only when the document says which
    // script it wants, or a partial document detaches the runtime's handler.
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
            if (has("send_to") || has("master_forward"))
                srv->set_send_to(cfg.send_to);
            if (has("udp"))  srv->set_udp(cfg.udp);
            if (!cfg.cache_name.empty())
                srv->set_runtime_manager(&m_manager);
            if (!cfg.master_pw.empty())
                srv->set_master_pw(cfg.master_pw);

            // The list is replaced only when the document names it, because
            // clearing it on a document that never mentioned upstreams is a
            // server whose upstream leg stops existing.
            if (!has("upstreams")) break;
            srv->clear_upstream_targets();
            for (const auto& u : cfg.upstreams)
            {
                // Reported rather than dropped, because the list was cleared a
                // line ago and storing fewer upstreams than the document names
                // is a half-applied import.
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
            // The clearing half of the escape hatch, without which a proxy
            // restored with mesh mTLS paths could never be emptied and would
            // refuse to start forever.
            if (has("mesh_client_ca"))   prx->set_mesh_client_ca(cfg.mesh_client_ca);
            if (has("mesh_client_cert")) prx->set_mesh_client_cert(cfg.mesh_client_cert);
            if (has("mesh_client_key"))  prx->set_mesh_client_key(cfg.mesh_client_key);
            break;
        }
        case runtime_cache:
        {
            auto* cache = static_cast<cache_instance*>(instance);
            if (has("persistent_path"))  cache->set_persistent(cfg.persistent_path);
            if (has("persistent_interval"))
                cache->set_persist_interval(cfg.persistent_interval);
            if (has("cache_mode"))       cache->set_mode(static_cast<cache_mode>(cfg.cache_mode));
            if (has("resp_forced"))      cache->set_resp_forced(cfg.resp_forced);
            if (has("cluster"))          cache->set_cluster(cfg.cluster);
            if (has("replicate_target")) cache->set_replicate_target(cfg.replicate_target);
            if (has("max_memory"))       cache->set_max_memory(cfg.max_memory);
            if (has("eviction"))         cache->set_eviction(static_cast<eviction_policy>(cfg.eviction));
            break;
        }
        default:
            // Replaced only when the document names the object, like the
            // upstream and backend lists above.
            if (has("extra"))
                instance->apply_config(cfg.extra);
            break;
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
    // timer.
    poll_proxy_workers();

    for (const auto& n : names)
    {
        auto* inst = m_manager.get(n);
        if (inst)
        {
            conn->write_buf += inst->get_stats();

            // There is no age to print here any more, because the counters are
            // summed out of shared memory at this instant rather than pushed
            // on a timer.

            // Which process this runtime is actually in, printed from the
            // daemon's own record because only that stays right after a
            // restart -- and as a list for a sharded runtime, since `pid:`
            // alone names one of N arbitrarily.
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

        // The child comes down here, per name, or the reconcile after the loop
        // sees the same `running` it saw before and leaves the original child
        // serving the script the operator has just replaced.
        reconcile_proxy_workers();

        std::string refusal;
        if (m_manager.start(n, m_loop, &refusal))
        {
            if (m_persistence)
            {
                m_persistence->set_was_running(n, true);
                restarted.push_back(n);
            }
        }
        // Said out loud, because a reload whose start was refused used to
        // leave the runtime stopped and answer as though it had reloaded.
        else if (!refusal.empty())
        {
            conn->write_buf += refusal;
            ++refused;
        }

        // The on_start report is read in the collect pass below, for the reason
        // cmd_start gives at the same point: when the script runs in a worker
        // the reason is a frame that has not been asked for yet.
    }

    // Reload is a stop followed by a start, so it is a start, and a start now
    // brings the child back and waits for it.
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

            // The same sentence applied to the other thing a start answers
            // for, or the same raise is reported by `start` and not by the
            // command that is a start.
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

    // A runtime whose script runs in a worker has to be asked and the answer
    // waited for, with every reload sent before any is waited on.
    std::vector<std::tuple<proxy_supervisor*, const void*, std::string>> pending;

    // A reload that did not happen is not a success, and failures are
    // collected rather than returned at the first, because `reload-lua` takes
    // a pattern and the previous script stays in force.
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

        // The script lives in the worker and this daemon's copy is a
        // placeholder that compiled the file once and discarded it.
        if (auto it = m_proxy_workers.find(n); it != m_proxy_workers.end() &&
                                               !it->second.empty())
        {
            // Read before the ask, so the answer cannot be missed for having
            // arrived between the two.
            const void* prev = inst ? inst->worker_routes().get() : nullptr;

            // Every shard re-runs the script, because reloading one would
            // leave the others serving the file the operator has just
            // replaced.
            for (auto& sup : it->second)
                sup->send_reload(inst ? inst->get_lua_script_path()
                                      : std::string_view{});

            // Waited on through shard 0 alone, which is a statement about the
            // declaration rather than the reload, since every shard writes the
            // same `routes` frame into the same placeholder.
            //
            // And only for a runtime that HAS a script.  Without one the worker
            // returns from on_reload() before it sends a declaration, so waiting
            // spent the entire deadline on an answer nothing was going to send:
            // measured 2.01s against 0.01s for a runtime carrying a script, with
            // the daemon answering nothing at all meanwhile.  A scriptless
            // runtime declares no routes either way, so there is nothing the
            // publish below could carry that this wait would have improved.
            if (inst && !inst->get_lua_script_path().empty())
                pending.emplace_back(it->second.front().get(), prev, n);
            continue;
        }

        // The two preconditions reload_lua_script() returns false on without
        // anything having gone wrong are checked here rather than reported,
        // because a stopped runtime loads its script when it is started.
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

    // The publish waits for the declarations it is meant to carry, or it
    // publishes the previous version of the thing being changed -- and it is
    // the same ::poll inside a command handler await_worker_startup() uses,
    // with the same consequence for map requests.
    const worker_wait_scope reload_waiting{m_worker_wait_depth};

    // One deadline for the command and not one per runtime: `reload-lua` takes
    // a pattern, and a bound each meant a wedged worker multiplied the whole
    // daemon's blocked time by however many runtimes the pattern named --
    // measured at exactly 2.0 s per runtime, until the CLI's own 5 s deadline
    // cut in and reported the daemon as unreachable.  The restart loop a
    // hundred lines above already shares one, for the same stated reason.
    const auto routes_deadline = std::chrono::steady_clock::now() + worker_startup_bound;

    for (auto& [sup, prev, name] : pending)
    {
        if (!sup->await_routes(prev, routes_deadline))
            LOG_WARN("reload-lua: a worker did not report its declaration in "
                     "time; the gateway keeps enforcing the previous one");
        // Read after the wait and asked of every shard, reported once from the
        // first that has a reason but taken from all of them, because take_ is
        // destructive and a reason left behind becomes the next reload's
        // answer.
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

    // A script is where a route declaration lives, so reloading one can change
    // it, and it is published even when a reload was refused because the
    // runtimes that did reload have new ones.
    m_manager.publish_endpoints();

    if (!failures.empty())
    {
        // Straight into the reply buffer rather than through cout, which for
        // this command is the daemon's own stdout, and exit 1 because the file
        // the operator named is what is wrong.
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
        if (!parse_uint16(sv, port) || port == 0)
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
            // Checked, like the pid above: an unvalidated owner reached `ls`.
            owner_name = std::string(pa.args[++i]);
            if (!runtime_manager::valid_name(owner_name))
            {
                conn->write_buf = "invalid owner: " + owner_name + "\n";
                return 1;
            }
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
    // m_health_pending means a completion is still owed on m_health_req, so
    // re-arming would hand the kernel a request it is already carrying one
    // for.
    if (m_health_pending || m_torn_down)
        return;
    m_health_req = { this, nullptr, -1, 0, op_timeout };
    m_health_ts = { 2, 0 };  // 2 seconds

    // Nothing re-arms this chain but its own completion, so a refused
    // submission stops both of the daemon's periodic duties, and the loss is
    // said out loud rather than found later as a leak.
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
        names.push_back({name, ep.host, ep.port, ep.unix_paths});
    // A member's nodes travel with it, exactly as a name's do, because the
    // table decided who has them and this frame only carries the decision.
    for (const auto& [group, eps] : tbl.groups())
        for (const auto& ep : eps)
            groups.push_back({group, ep.host, ep.port, ep.unix_paths});

    // The declarations travel with the table, because a proxy in a worker
    // enforces what this frame says and cannot read the daemon's
    // endpoint_table object.
    worker_proto::route_decl_wire name_routes, group_routes;
    for (const auto& [n, rt] : tbl.name_routes())
        if (rt) name_routes.emplace_back(n, rt);
    for (const auto& [g, rt] : tbl.group_routes())
        if (rt) group_routes.emplace_back(g, rt);

    const std::string payload =
        worker_proto::encode_endpoints(names, groups, name_routes, group_routes);
    // Every shard, because a table that reached three of four workers leaves
    // the fourth refusing to start on a backend written as a name.
    for (auto& [_, shards] : m_proxy_workers)
        for (auto& sup : shards)
            sup->send_endpoints(payload);
}

// What runtimes there are, as the workers' replicas, built here because the
// manager knows what it holds and this class knows where the sockets are --
// event-loop thread only, because the connection count is a live walk for a
// local runtime.
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
            w.type        = type_to_string(inst->get_type());
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

    // Encoded once for all of them, with each supervisor deciding whether it
    // is news, so an idle daemon's health tick costs one string compare per
    // worker.
    const std::string payload = build_runtime_map_payload();
    for (auto& [_, shards] : m_proxy_workers)
        for (auto& sup : shards)
            sup->send_runtime_map(payload);

    m_last_map_push = std::chrono::steady_clock::now();
}

// A worker sends one control frame per PUBLISH so the daemon can fan it out to
// the other workers and to whatever it is running in-process -- and when there
// is neither, that frame is three copies of the payload on its way to being
// dropped at MAX_BACKLOG.  Measured on a cache with fifty subscribers and
// nothing else running: 0.079 microseconds of worker per delivery against
// 0.063 with the frame suppressed, so a fifth of that worker was building
// frames for nobody.
//
// The answer is the daemon's to give because only it can see the other
// processes, and it is pushed rather than asked for, on the same tick as the
// runtime map: a worker that has never been told sends, so this frame only
// ever narrows what a process does on its own.
void daemon_handler::refresh_publish_interest()
{
    if (m_proxy_workers.empty())
        return;

    // A process without a Lua VM has nobody to give a publish to, so a sibling
    // shard of a cache with no script is not "somebody else" -- and counting
    // it as one sent every publish of a sharded cache through the daemon and
    // back out to N-1 workers that decoded it for nothing.
    bool                            daemon_side = false;
    size_t                          scripted_procs = 0;
    std::unordered_set<std::string> scripted;
    {
        std::shared_lock lock(m_manager.mutex);
        for (const auto& [n, inst] : m_manager.list())
        {
            // The same three tests dispatch_publish() applies, including the
            // out-of-process one: a placeholder loads the runtime's script and
            // so has a Lua VM, and counting it would keep every worker sending
            // to an interpreter that serves nothing.
            if (inst->get_state() == runtime_running && inst->lua() &&
                !inst->is_out_of_process())
                daemon_side = true;

            const auto wit = m_proxy_workers.find(n);
            if (wit != m_proxy_workers.end() && !inst->get_lua_script_path().empty())
            {
                scripted.insert(n);
                scripted_procs += wit->second.size();
            }
        }
    }

    // Per runtime rather than once for all, because a process with the only
    // script has nobody else while every other process has it.
    for (auto& [n, shards] : m_proxy_workers)
    {
        const size_t others   = scripted_procs - (scripted.count(n) ? 1 : 0);
        const bool   interest = daemon_side || others > 0;
        for (auto& sup : shards)
            sup->send_publish_interest(interest);
    }
}

// What the cluster looks like for the workers that cannot look, with an empty
// view sent as a withdrawal only once this daemon has ever had a cluster -- a
// never-clustered one sends nothing, keeping those four calls honestly
// refused.
std::string daemon_handler::build_cluster_view_payload()
{
    // Empty means there is nothing to say and nothing to withdraw, which is a
    // daemon that has never been in a cluster.
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

// A connection count moves with traffic and nothing else announces it, so the
// map rides the stats cadence -- coalesced to one round per interval, because
// pushing per arrival is N frames to N children and sixteen workers would be
// 256 frames per 250 ms.
void daemon_handler::link_peers(proxy_supervisor* from, const std::string& target)
{
    // The measurement control, so the link and the relay differ in the route
    // alone rather than in the build -- the same switch the shard mesh has,
    // for the same reason.
    static const bool disabled = []
    {
        const char* off = ::getenv("SOCKETLEY_NO_PEER_LINKS");
        return off && *off && *off != '0';
    }();
    if (disabled)
        return;

    if (!from || !from->placeholder() || target.empty())
        return;

    const std::string origin(from->placeholder()->get_name());
    if (origin == target)
        return;

    // Here rather than at the two call sites, because a request and a routing
    // frame are two kinds of evidence for the same thing and one window has to
    // cover both.
    if (from->grant_suppressed(target))
        return;

    const auto mine = m_proxy_workers.find(origin);
    const auto theirs = m_proxy_workers.find(target);
    if (mine == m_proxy_workers.end() || theirs == m_proxy_workers.end())
        return;

    // A sharded origin gets one link PER SHARD, and the far side registers each
    // under `origin#k`.  N links under one bare name are N answers to one
    // question, which is why this used to refuse a sharded origin outright --
    // and the refusal cost every shard of every sharded runtime 10.49 us of
    // round trip and 10.75 us of CPU on every crossing, permanently.  The name
    // a worker registers is who is on the other end, and when that end is one
    // shard of N the name says which; the far side picks by conn_ref_shard().
    size_t my_shard = 0;
    bool   mine_found = false;
    for (size_t k = 0; k < mine->second.size(); ++k)
        if (mine->second[k].get() == from) { my_shard = k; mine_found = true; break; }
    if (!mine_found)
        return;   // not one of this name's workers; nothing to name it by

    const std::string back_name =
        mine->second.size() == 1 ? origin
                                 : origin + "#" + std::to_string(my_shard);

    // The answering side may be any number.  front() is shard 0, which is
    // where the daemon's own sink for the bare name points -- see the
    // request_sink_override in reconcile_proxy_workers -- and the worker there
    // answers a crossing the same way whether it arrived over a link or down
    // the control socket.  So this replaces the daemon's leg and changes
    // nothing about which process serves it.
    proxy_supervisor* to = theirs->second.front().get();
    if (!to || to == from)
        return;

    // The far side is asked too, because a target that has just been handed a
    // link is one whose end of this pair is already on its way -- asked under
    // the name it will register, so one shard's grant does not suppress
    // another's.
    if (to->grant_suppressed(back_name))
        return;

    int sv[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0)
    {
        LOG_WARN(("peer links: no socketpair for " + origin + " and " + target
                  + "; their crossings keep relaying").c_str());
        return;
    }

    // A half-delivered pair is not left half-delivered: closing both copies
    // gives whichever end did arrive an immediate EOF, so that worker's link
    // dies and it relays, rather than holding a socket nothing answers on.
    if (!from->grant_peer_link(target, sv[0]) || !to->grant_peer_link(back_name, sv[1]))
    {
        ::close(sv[0]);
        ::close(sv[1]);
        return;
    }

    // The daemon's copies go now: an end it still holds is an end whose peer
    // never sees EOF when the process on the other side of it exits.
    ::close(sv[0]);
    ::close(sv[1]);

    LOG_INFO(("peer links: " + back_name + " and " + target
              + " now cross directly").c_str());
}

void daemon_handler::on_worker_stats(const std::string& name)
{
    // First and outside the floor, because the placeholder holds the sum over
    // this runtime's shards and the frame that just arrived changed one of the
    // terms.
    aggregate_worker_stats(name);

    // Half the publish interval and strictly below it, because a floor equal
    // to the arrival period is one that ordinary jitter trips over.
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

    // Encoded once for all of them, because a PUBLISH on a busy cache is a hot
    // path and the payload does not depend on which worker it goes to.
    const std::string payload = worker_proto::encode_publish(cache_name, channel, message);
    for (auto& [_, shards] : m_proxy_workers)
    for (auto& sup : shards)
    {
        // Everyone but whoever sent it up, excluded per process and not per
        // runtime, because a sibling shard is a separate interpreter that has
        // not run this publish.
        if (sup.get() == m_publish_origin)
            continue;
        sup->send_publish(payload);
    }
}

// One runtime and every shard of it, because the clients are spread across N
// processes by the kernel's own choice, answering true if any shard took it.
bool daemon_handler::deliver_to_worker(std::string_view name,
                                       std::string_view message,
                                       const proxy_supervisor* exclude)
{
    auto it = m_proxy_workers.find(std::string(name));
    if (it == m_proxy_workers.end())
        return false;

    bool any = false;
    for (auto& sup : it->second)
    {
        // Everyone but whoever sent it up and only when somebody did, excluded
        // per process, because excluding the whole shard set would deliver to
        // nobody at all.
        if (exclude && sup.get() == exclude)
            continue;
        if (sup->send_deliver(message))
            any = true;
    }
    return any;
}

void daemon_handler::on_worker_send_ref(proxy_supervisor* from,
                                        const conn_ref& ref,
                                        std::string_view message)
{
    if (!from)
        return;

    // Which runtime the asking shard belongs to, found by walking the map
    // rather than carried on the frame, because a field the worker filled in
    // would be a second answer to disagree with the daemon's.
    for (auto& [name, shards] : m_proxy_workers)
    {
        bool mine = false;
        for (const auto& sup : shards)
            if (sup.get() == from) { mine = true; break; }
        if (!mine)
            continue;

        const uint32_t target = conn_ref_shard(ref);
        if (target >= shards.size())
        {
            // A ref minted by a shard that has since been retired, which is
            // not an error because the connection went with the process.
            LOG_DEBUG("a send named a connection on a shard that is gone");
            return;
        }

        // The asking shard is not a legal target, so a frame that comes back
        // round is a build that has lost send_to_client's own check.
        if (shards[target].get() == from)
        {
            LOG_WARN("a shard asked the daemon to deliver to itself; dropped");
            return;
        }

        if (!shards[target]->send_deliver_ref(ref, message))
            LOG_WARN("could not reach the shard holding a routed connection");
        return;
    }
}

// A connection stays where it is and another runtime answers it, with the
// daemon in the path only because it holds the authoritative answer to where
// `to` is -- and a routed connection lands on shard 0 always, which is a
// limitation stated rather than a placement rule defended.
void daemon_handler::route_dispatch(std::string_view to, std::string_view frm,
                                    worker_proto::route_op op,
                                    const conn_ref& ref,
                                    std::string_view payload)
{
    // In this process and a real server rather than a placeholder standing in
    // for one, asked through local_server(), which is the single test.
    if (auto* srv = route_relay::local_server(&m_manager, to))
    {
        switch (op)
        {
            case worker_proto::route_op::open:
                // The one op that can be refused after it has been accepted at
                // this level, unwound as a `drop` back the way the ask came,
                // which is the same message the origin gets when the target
                // dies.
                if (srv->accept_routed(ref, frm) < 0)
                    route_dispatch(frm, to, worker_proto::route_op::drop, ref, {});
                break;
            case worker_proto::route_op::data:
                srv->deliver_routed(ref, payload);
                break;
            case worker_proto::route_op::close:
                srv->release_routed(ref);
                break;
            case worker_proto::route_op::write:
                if (!srv->write_to_ref(ref, payload))
                    LOG_DEBUG("a routed message named a connection its owner no "
                              "longer has");
                break;
            case worker_proto::route_op::drop:
                srv->drop_route(ref);
                break;
            case worker_proto::route_op::broadcast:
                srv->broadcast(payload);
                break;
            case worker_proto::route_op::forget:
                // Not reachable through post(), because forget() fans out
                // directly, but handled anyway so a worker sending it up is
                // served rather than dropped by a switch that looks complete.
                srv->forget_runtime(frm);
                break;
        }
        return;
    }

    auto it = m_proxy_workers.find(std::string(to));
    if (it == m_proxy_workers.end() || it->second.empty())
    {
        // The runtime went away between the ask and this frame, which for
        // teardown ops is the ordinary case, so debug rather than warn.
        LOG_DEBUG("a routing frame named a runtime the daemon no longer holds");
        return;
    }

    if (!it->second[0]->send_route(to, frm, op, ref, payload))
        LOG_WARN("could not reach the worker holding a routed runtime");
}

void daemon_handler::post(std::string_view to, std::string_view frm,
                          worker_proto::route_op op, const conn_ref& ref,
                          std::string_view payload)
{
    route_dispatch(to, frm, op, ref, payload);
}

bool daemon_handler::open(std::string_view target, const conn_ref& ref,
                          std::string_view origin, std::string& err)
{
    if (!admit(target, err))
        return false;
    route_dispatch(target, origin, worker_proto::route_op::open, ref, {});
    return true;
}

bool daemon_handler::admit(std::string_view target, std::string& err)
{
    // Reached only when the target is not in this process, so the daemon
    // decides from the map -- and the three refusals are worded exactly as the
    // in-process path words them, because a script must not be able to tell
    // which path it took.
    auto* rt = m_manager.get(target);
    if (!rt)
    {
        err = "there is no runtime called \"" + std::string(target) + "\"";
        return false;
    }
    if (rt->get_type() != runtime_server)
    {
        err = "\"" + std::string(target) + "\" is not a server";
        return false;
    }
    if (rt->get_state() != runtime_running)
    {
        err = "\"" + std::string(target) + "\" is not running";
        return false;
    }
    return true;
}

void daemon_handler::forget(std::string_view gone)
{
    // Everyone but the runtime that is leaving, as a fan-out rather than a
    // lookup because a table of who routed to whom would be a third place a
    // route is recorded -- collected first, since release_routed runs a
    // script's on_disconnect.
    std::vector<std::string> local;
    {
        std::shared_lock lock(m_manager.mutex);
        for (const auto& [name, inst] : m_manager.list())
        {
            (void)inst;
            if (name != gone)
                local.push_back(name);
        }
    }
    for (const auto& name : local)
        if (auto* srv = route_relay::local_server(&m_manager, name))
            srv->forget_runtime(gone);

    for (auto& [name, shards] : m_proxy_workers)
    {
        if (name == gone)
            continue;
        // Every shard and not the first, because routing out of a runtime is
        // done by whichever shard holds the connection.
        for (auto& sup : shards)
            if (sup && !sup->send_route(name, gone,
                                        worker_proto::route_op::forget,
                                        conn_ref{}, {}))
                LOG_DEBUG("could not tell a worker that a routed runtime went "
                          "away; it is stopping too");
    }
}

void daemon_handler::on_worker_route(proxy_supervisor* from, std::string_view to,
                                     std::string_view frm,
                                     worker_proto::route_op op,
                                     const conn_ref& ref,
                                     std::string_view payload)
{
    if (!from)
        return;

    // `frm` is checked against what this supervisor stands for rather than
    // trusted, or the target's on_connect reports the wrong origin and
    // owner_send writes into a runtime the connection never came from.
    const auto* ph = from->placeholder();
    if (!ph || ph->get_name() != frm)
    {
        LOG_WARN("a worker sent a routing frame naming a runtime that is not "
                 "its own; dropped");
        return;
    }

    route_dispatch(to, frm, op, ref, payload);

    // The same evidence a carried request gives: this daemon just moved bytes
    // between two processes that could have moved them themselves.  A
    // broadcast is excluded because it names no runtime to be linked to.
    if (op != worker_proto::route_op::broadcast &&
        op != worker_proto::route_op::forget && !to.empty())
        link_peers(from, std::string(to));
}

// socketley.create/.start/.stop/.remove asked by a script in a worker,
// recorded here and served a turn later rather than where they arrive.
void daemon_handler::queue_map_request(uint64_t ticket, int reply_fd,
                                       std::string op, std::string name,
                                       std::string config)
{
    // A daemon on its way down will not come back round, so a parked request
    // would be answered by nothing and the worker would wait out its whole
    // deadline for silence.
    if (m_torn_down)
    {
        proxy_supervisor::answer_map_request(reply_fd, ticket, false,
                                             "the daemon is shutting down");
        if (reply_fd >= 0) ::close(reply_fd);
        return;
    }

    m_map_queue.push_back({ticket, reply_fd, std::move(op), std::move(name),
                           std::move(config)});

    // Inside a wait for a worker, served here rather than deferred, because
    // the loop is not coming back and what it waits for is the script blocked
    // on this answer.
    if (m_worker_wait_depth > 0)
    {
        serve_map_requests();
        return;
    }

    // One nop for the whole queue, not one per request: the completion serves
    // everything waiting, and a second arm would come back to an empty list.
    if (m_map_defer_armed)
        return;

    m_map_defer_req   = { this, nullptr, -1, 0, op_nop };
    m_map_defer_armed = m_loop.submit_nop(&m_map_defer_req);

    if (!m_map_defer_armed)
    {
        // The ring would not take the nop, so the requests are refused rather
        // than served: a false with a reason is recoverable and a freed
        // supervisor is not.
        LOG_ERROR("daemon: could not defer a worker's map request; refusing it");
        for (auto& q : m_map_queue)
        {
            proxy_supervisor::answer_map_request(
                q.reply_fd, q.ticket, false,
                "the daemon could not schedule the request");
            if (q.reply_fd >= 0) ::close(q.reply_fd);
        }
        m_map_queue.clear();
    }
}

void daemon_handler::serve_map_requests()
{
    // Taken by value first, because serving one of these can create a runtime
    // whose script calls straight back and appends to the vector this loop
    // would be holding an iterator into.
    std::vector<pending_map_request> batch;
    batch.swap(m_map_queue);

    for (auto& q : batch)
    {
        std::string err;
        const bool ok = serve_map_request(q.op, q.name, q.config, err);

        proxy_supervisor::answer_map_request(q.reply_fd, q.ticket, ok, err);
        if (q.reply_fd >= 0)
            ::close(q.reply_fd);
    }
}

// One of the four, against the map this process holds.
//
// ─── WHAT THIS IS AND IS NOT A COPY OF ──────────────────────────────────────
// The in-daemon socketley.create/.start/.stop/.remove reached from a different
// direction, parsing nothing because a runtime_config crosses -- and
// duplicating cmd_start's order in three lines each, since sharing it would
// mean inventing an ipc_connection and a parsed_args here.
bool daemon_handler::serve_map_request(const std::string& op,
                                       const std::string& name,
                                       const std::string& config,
                                       std::string& err)
{
    const uint32_t h = fnv1a(op.c_str());

    // ── create ─────────────────────────────────────────────────────────────
    if (h == fnv1a("create"))
    {
        runtime_config    cfg;
        state_persistence parser{std::filesystem::path{}};   // parser only
        if (!parser.parse_json_string(config, cfg))
        {
            err = "the configuration could not be read by the daemon";
            return false;
        }

        // The name on the wire wins over the one in the config, which is what
        // stops a future field deciding it by accident.
        cfg.name = name;

        // Refused before the fallback below it can act, because str_to_type
        // answers runtime_server for a name it cannot resolve and a script's
        // typo must not build a server.
        if (!cfg.type_name.empty() && cfg.type_name != type_to_string(cfg.type))
        {
            err = "\"" + cfg.type_name + "\" is not a runtime type this daemon knows";
            return false;
        }

        // A map-created runtime runs where this handler runs, and a registered
        // type has nothing to run here -- its behaviour is a worker binary.
        if (type_registry::is_registered(cfg.type))
        {
            err = "\"" + cfg.type_name + "\" is a registered type, which a "
                  "script cannot create";
            return false;
        }

        switch (m_manager.try_create(cfg.type, name))
        {
            case runtime_manager::create_result::ok:
                break;
            case runtime_manager::create_result::invalid_name:
                err = "\"" + name + "\" is not a usable runtime name";
                return false;
            case runtime_manager::create_result::name_taken:
                err = "a runtime called \"" + name + "\" already exists";
                return false;
            case runtime_manager::create_result::internal:
                err = "the runtime could not be built";
                return false;
        }

        auto* inst = m_manager.get(name);
        if (!inst)
        {
            err = "the runtime could not be built";
            return false;
        }

        inst->set_runtime_manager(&m_manager);
        inst->set_event_loop(&m_loop);
        inst->set_owner(cfg.owner);

        // The runtime this builds runs in the daemon as it always has,
        // deliberately, because making the same three lines of Lua build a
        // different thing depending on which process ran them is the property
        // this work exists to remove.
        inst->set_lua_created(true);
        inst->set_child_policy(
            cfg.child_policy == 1 ? runtime_instance::child_policy::remove
                                  : runtime_instance::child_policy::stop);

        apply_common_config(*inst, cfg);
        apply_typed_config(*inst, cfg);

        // The script, and the same unwind the in-daemon path takes, because a
        // runtime with no callbacks is indistinguishable from a working one
        // until traffic arrives.
        if (!cfg.lua_script.empty() && !inst->load_lua_script(cfg.lua_script))
        {
            m_manager.remove(name);
            err = "could not load " + cfg.lua_script;
            return false;
        }

        // was_running is how the config carries the table's `start = true`;
        // see the encode side in lua_context.
        std::string refusal;
        if (cfg.was_running && !m_manager.start(name, m_loop, &refusal))
        {
            m_manager.remove(name);
            err = refusal.empty() ? "start = true, and it could not be started"
                                  : refusal;
            return false;
        }

        return true;
    }

    // ── route ──────────────────────────────────────────────────────────────
    // The fifth op is not a map mutation and is on this socket because this
    // socket is what a worker can block on, answered by admit() so an
    // in-daemon script and a worker script cannot drift apart in what they
    // refuse -- and the verdict only, because the open frame itself travels
    // with the connection's other frames, or the first of them overtakes it.
    if (h == fnv1a("route"))
        return admit(name, err);

    // Word for word what the daemon's own bindings answer, because a script
    // must not be able to tell which side of the boundary it is on from the
    // text of a refusal, and these are made against the map itself rather than
    // a replica.
    auto* inst = m_manager.get(name);
    if (!inst)
    {
        err = "there is no runtime called \"" + name + "\"";
        return false;
    }

    // ── start ──────────────────────────────────────────────────────────────
    if (h == fnv1a("start"))
    {
        if (inst->get_state() == runtime_running)
        {
            err = "\"" + name + "\" is already running";
            return false;
        }
        if (inst->get_state() == runtime_failed)
        {
            err = "\"" + name + "\" is failed, and a failed runtime cannot be "
                  "started again — remove it and create it anew";
            return false;
        }

        if (std::string msg = instance_tls_refusal(inst); !msg.empty())
        {
            err = msg;
            return false;
        }
        if (std::string msg = instance_shards_refusal(inst); !msg.empty())
        {
            err = msg;
            return false;
        }

        std::string refusal;
        if (!m_manager.start(name, m_loop, &refusal))
        {
            err = refusal.empty() ? "\"" + name + "\" could not be started"
                                  : refusal;
            return false;
        }
        if (m_persistence)
            m_persistence->set_was_running(name, true);

        // A runtime that lives in a worker is not serving until its child is,
        // and this is the whole reason the call waits at all: reporting the
        // fork rather than the listener is the defect cmd_start was fixed for.
        reconcile_proxy_workers();
        if (inst->is_out_of_process())
        {
            std::string wmsg;
            const auto  deadline =
                std::chrono::steady_clock::now() + worker_startup_bound;
            if (await_worker_startup(name, wmsg, deadline) != 0)
            {
                err = wmsg.empty() ? "the worker did not come up" : wmsg;
                return false;
            }
        }

        // The runtime is up and its script's set-up may not be, reported as a
        // failure exactly as cmd_start reports it.
        if (std::string why = on_start_error(name); !why.empty())
        {
            err = why;
            return false;
        }
        return true;
    }

    // ── stop ───────────────────────────────────────────────────────────────
    if (h == fnv1a("stop"))
    {
        if (inst->get_state() != runtime_running)
        {
            err = "\"" + name + "\" is "
                + std::string(state_json(inst->get_state()))
                + ", not running";
            return false;
        }

        if (!m_manager.stop(name, m_loop))
        {
            err = "\"" + name + "\" could not be stopped";
            return false;
        }
        if (m_persistence)
            m_persistence->set_was_running(name, false);

        // Before returning, for the reason cmd_stop gives: `stop` has to mean
        // the port is free by the time the caller sees the answer.
        reconcile_proxy_workers();
        return true;
    }

    // ── remove ─────────────────────────────────────────────────────────────
    if (h == fnv1a("remove"))
    {
        if (inst->get_state() == runtime_running)
            m_manager.stop(name, m_loop);

        // Before the instance leaves the map, for the reason cmd_remove gives:
        // the supervisor holds a pointer to the placeholder, and that pointer
        // has to be dropped while the object it names is still there.
        reconcile_proxy_workers();

        if (!m_manager.remove(name))
        {
            err = "\"" + name + "\" could not be removed";
            return false;
        }
        if (m_persistence)
            m_persistence->remove_runtime(name);
        return true;
    }

    err = "the daemon does not know the map call \"" + op + "\"";
    return false;
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
    // Nothing may hold into the map across a poll(), because a publish runs
    // subscribe callbacks that may remove a runtime and erase from
    // m_proxy_workers -- so the names are copied and every element re-found
    // between drains.
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

        // Once per runtime after its whole shard set has been drained, because
        // the placeholder holds the sum and writing it half-way would publish
        // a total that never existed.
        aggregate_worker_stats(name);
    }
}

// One runtime's figures out of N processes', which is the fallback for a
// runtime whose memfd region could not be created and still where the detail
// text is assembled -- with a shard that has not published contributing
// nothing rather than zeros.
void daemon_handler::aggregate_worker_stats(const std::string& name)
{
    auto it = m_proxy_workers.find(name);
    if (it == m_proxy_workers.end())
        return;

    auto* inst = m_manager.get(name);
    if (!inst)
        return;

    uint64_t total_conn = 0, total_msg = 0, in = 0, out = 0, active = 0;
    bool     any        = false;
    std::string detail;

    const auto rit = m_shard_regions.find(name);
    const shard_stats::shard_table* region =
        (rit != m_shard_regions.end() && rit->second.mapped()) ? &rit->second : nullptr;

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

        // One shard's detail text passes through unchanged and several are
        // labelled, with each shard's own figures under `shard_` names,
        // because how the work is spread is a question the sum cannot answer.
        const size_t idx = static_cast<size_t>(&sup - it->second.data());
        if (it->second.size() > 1)
        {
            const shard_stats::figures sf =
                region ? region->at(static_cast<uint32_t>(idx))
                       : shard_stats::figures{s.active_connections,
                                              s.total_connections,
                                              s.total_messages,
                                              s.bytes_in, s.bytes_out};
            detail += "[shard ";
            detail += std::to_string(idx);
            detail += "]\nshard_connections:";
            detail += std::to_string(sf.active_connections);
            detail += "\nshard_total_connections:";
            detail += std::to_string(sf.total_connections);
            detail += "\nshard_total_messages:";
            detail += std::to_string(sf.total_messages);
            detail += "\nshard_bytes_in:";
            detail += std::to_string(sf.bytes_in);
            detail += "\nshard_bytes_out:";
            detail += std::to_string(sf.bytes_out);
            detail += '\n';
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
    inst->set_worker_stats(std::move(detail), active);
}

void daemon_handler::reconcile_proxy_workers()
{
    // What the map says should be running out of process and how many
    // processes each wants, because the count is part of what is being
    // reconciled and not just the presence.
    std::vector<std::pair<std::string, size_t>> wanted;
    {
        std::shared_lock lock(m_manager.mutex);
        for (const auto& [name, inst] : m_manager.list())
        {
            // The supervisor does not care what kind of runtime it is
            // supervising, and none of what it does reads the type.
            if (!inst->is_out_of_process())
                continue;
            if (inst->get_state() == runtime_running)
                wanted.emplace_back(name, static_cast<size_t>(inst->get_shards()));
        }
    }

    // Retire one shard without destroying it, because the erase used to run
    // the destructor while a cancelled poll's completion was still on its way
    // -- and runtimes losing their whole shard set are told to forget their
    // routes after the loops, since forget() runs on_disconnect and a script
    // may reconcile again.
    std::vector<std::string> retired_names;

    const auto retire_one = [this](std::unique_ptr<proxy_supervisor> sup)
    {
        sup->shutdown();
        // shutdown() reaps only a child that was already gone, so this is the
        // last moment anything knows the pid.
        if (const pid_t p = sup->release_pid(); p > 0)
            m_orphan_workers.push_back({p, std::chrono::steady_clock::now(), false});

        const uint32_t tok = sup->retire();
        m_retired_handlers.push_back({std::move(sup), tok});
    };

    // Children whose runtime has gone, and surplus shards, taken down before
    // anything is started so a rename that reuses a port does not have two
    // children bound to it.
    for (auto it = m_proxy_workers.begin(); it != m_proxy_workers.end();)
    {
        const auto w = std::find_if(wanted.begin(), wanted.end(),
                                    [&](const auto& p) { return p.first == it->first; });

        // A wanted name whose every child has been reaped is a runtime being
        // started out of `failed`: check_liveness() zeroes the pid of a child
        // it did not restart, and nothing else leaves a full set dead while the
        // placeholder asks to run.  Their entries have to go before the spawn
        // loop below, which counts supervisors and not children and would find
        // the set complete and fork nothing.
        const bool all_reaped =
            w != wanted.end() && !it->second.empty() &&
            std::none_of(it->second.begin(), it->second.end(),
                         [](const auto& sup) { return sup->is_alive(); });

        if (w == wanted.end() || all_reaped)
        {
            // Recorded before the retire, because retire() nulls the
            // supervisor's placeholder pointer and this is a name the map is
            // about to stop holding either way.
            retired_names.push_back(it->first);
            for (auto& sup : it->second)
                retire_one(std::move(sup));
            // The region goes with the last shard, and the placeholder's own
            // duplicated reader is closed first, or the runtime would go on
            // answering `stats` out of a table no process writes any more.
            if (auto* inst = m_manager.get(it->first))
                inst->shard_stats_table().close();
            m_shard_regions.erase(it->first);
            m_shard_client_regions.erase(it->first);
            it = m_proxy_workers.erase(it);
            continue;
        }

        // Wanted with fewer processes than it has, retired from the back so
        // the surviving shards keep the index `stats` labels their detail text
        // with.
        while (it->second.size() > w->second)
        {
            retire_one(std::move(it->second.back()));
            it->second.pop_back();
        }

        // The surviving shards must stop counting the ones that just went,
        // because a retired shard publishes nothing and its last figure would
        // sit in the sum forever.
        if (const auto r = m_shard_regions.find(it->first); r != m_shard_regions.end())
            r->second.set_shard_count(static_cast<uint32_t>(w->second));

        // The client list is sized from the shard count, so a retired shard's
        // block is cleared instead of the region being resized.
        if (const auto c = m_shard_client_regions.find(it->first);
            c != m_shard_client_regions.end())
            for (size_t i = w->second; i < c->second.count(); ++i)
                c->second.clear_block(static_cast<uint32_t>(i));

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

        // The nodes beside this runtime's port, one per shard, decided here
        // because this is the one place that knows both the configuration and
        // this daemon's own socket -- set on the placeholder, since
        // publish_endpoints reads them off it, and each shard's own one put
        // in its frame below.
        //
        // Derived from the daemon socket, so two daemons never name one node,
        // and the directory they go in is 0700: only this user can put
        // anything there, and this user can already reach the port.
        std::vector<std::string> nodes;
        {
            static const std::string dsock =
                socketley_paths::resolve().socket_path.string();

            // The shard count is want_count and not a second get_shards(),
            // because the decision and the number of paths it produces have to
            // come from one read.
            if (socketley::unix_sock::wants_companion(inst->get_type(),
                                                      inst->get_port(),
                                                      inst->get_listen_path(),
                                                      inst->get_tls(),
                                                      inst->is_udp(),
                                                      static_cast<uint32_t>(want_count)))
            {
                nodes = socketley::unix_sock::companion_paths(
                    dsock, name, static_cast<uint32_t>(want_count));

                // Secured here and not in the worker, because publishing a path
                // and binding it are two decisions and only one of them can be
                // the one that fails: a path published into a directory this
                // daemon does not own is a path a stranger can be serving.
                if (!nodes.empty() &&
                    !socketley::unix_sock::secure_node_dir(
                        socketley::unix_sock::node_dir_of(nodes.front())))
                {
                    static bool said = false;
                    if (!said)
                    {
                        said = true;
                        LOG_WARN(("companion nodes are off: "
                                  + socketley::unix_sock::node_dir_of(nodes.front())
                                  + " is not a directory this daemon owns with "
                                    "nothing but owner access").c_str());
                    }
                    nodes.clear();
                }
            }
            inst->set_companion_paths(nodes);
        }

        // The shards forked in this pass, so `start` can be sent to all of
        // them after the endpoint table has been published once.
        std::vector<proxy_supervisor*> forked;

        // The shared table this runtime's shards publish into, made before the
        // first fork and kept for the life of the runtime, and not fatal when
        // it cannot be made -- the fallback is each shard answering for
        // itself.
        int shard_fd   = -1;
        int clients_fd = -1;
        {
            auto& region = m_shard_regions[name];
            if (!region.mapped())
            {
                if (!region.create(static_cast<uint32_t>(want_count)))
                    LOG_WARN(("could not create the shared figures table for "
                              + name
                              + "; its figures will come from the frames it"
                                " pushes instead").c_str());
            }
            else
            {
                // Growing: the shards that already exist keep their slots and
                // their published figures, and the new ones get slots that were
                // out of range a moment ago.
                region.set_shard_count(static_cast<uint32_t>(want_count));
            }
            shard_fd = region.fd();

            // ── And the daemon's own way in ─────────────────────────────────
            // The placeholder gets a reader's mapping of the same region,
            // attached once, so every reader that asks it for figures loads
            // them at the moment it is called.
            if (!inst->shard_stats_table().mapped() && region.mapped())
                if (!inst->shard_stats_table().attach_reader(shard_fd))
                    LOG_WARN(("could not attach to the shared figures table for "
                              + name
                              + "; its figures will come from the frames it"
                                " pushes instead").c_str());
        }
        if (want_count > 1)
        {
            // And the client list, on the same lifetime and the same failure
            // policy: each shard answering self.clients() with its own
            // connections is not an outage.
            auto& creg = m_shard_client_regions[name];
            if (!creg.mapped())
            {
                if (!creg.create(static_cast<uint32_t>(want_count)))
                    LOG_WARN(("could not create the shared client list for "
                              + name
                              + "; each shard will list only its own").c_str());
            }
            else if (creg.count() != want_count)
            {
                // Width is fixed at creation, so a changed shard count needs a
                // new region, which reconcile does not currently produce.
                if (!creg.create(static_cast<uint32_t>(want_count)))
                    LOG_WARN(("could not resize the shared client list for "
                              + name).c_str());
            }
            clients_fd = creg.fd();
        }

        // ── The shard mesh ─────────────────────────────────────────────────
        // N(N-1)/2 socketpairs made here, the only moment both ends can reach
        // both processes, and only for a set being forked whole -- a runtime
        // that grew while running has shards that relay.
        std::vector<std::vector<int>> mesh;
        if (want_count > 1 && shards.empty() && mesh_fits(want_count))
        {
            mesh.assign(want_count, std::vector<int>(want_count, -1));
            bool made = true;
            for (size_t i = 0; i < want_count && made; ++i)
                for (size_t j = i + 1; j < want_count && made; ++j)
                {
                    int sv[2];
                    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0)
                    {
                        LOG_WARN(("could not build the shard mesh for " + name
                                  + "; its shards will relay through the daemon")
                                 .c_str());
                        made = false;
                        break;
                    }
                    mesh[i][j] = sv[0];
                    mesh[j][i] = sv[1];
                }
            if (!made)
            {
                for (auto& row : mesh)
                    for (int fd : row)
                        if (fd >= 0) ::close(fd);
                mesh.clear();
            }
        }

        // Every end the daemon made is closed once the whole set is forked,
        // because a restarted shard cannot be given an end its siblings
        // already hold the other side of.
        struct mesh_closer
        {
            std::vector<std::vector<int>>& m;
            ~mesh_closer()
            {
                for (auto& row : m)
                    for (int fd : row)
                        if (fd >= 0) ::close(fd);
            }
        } mesh_guard{mesh};

        while (shards.size() < want_count)
        {
        // Empty for a built-in, which the supervisor reads as "exec myself";
        // a registered type's worker is the binary its manifest names.
        auto sup = std::make_unique<proxy_supervisor>(
            inst, type_manifest::exec_path(inst->get_type()));

        // Which of N this child is, where the position in this vector is the
        // index, so no counter has to be kept beside it.
        sup->set_shard(static_cast<uint32_t>(shards.size()), shard_fd, clients_fd);

        // Its row of the mesh, which spawn() places and then forgets.
        if (!mesh.empty())
            sup->set_mesh_fds(mesh[shards.size()]);

        // The supervisor answers for the runtime it supervises, set before the
        // spawn so a request arriving in the same turn has somewhere to go.
        sup->set_channel(&m_manager.requests());
        sup->set_event_loop(&m_loop);
        sup->set_publish_handler([this](proxy_supervisor* from,
                                        std::string_view c, std::string_view ch,
                                        std::string_view m)
                                 { on_worker_publish(from, c, ch, m); });
        sup->set_deliver_handler([this](proxy_supervisor* f, std::string_view n,
                                        std::string_view m)
                                 { on_worker_deliver(f, n, m); });
        sup->set_send_ref_handler([this](proxy_supervisor* f, const conn_ref& r,
                                         std::string_view m)
                                  { on_worker_send_ref(f, r, m); });
        sup->set_route_handler([this](proxy_supervisor* f, std::string_view to,
                                      std::string_view frm,
                                      worker_proto::route_op op,
                                      const conn_ref& r, std::string_view pl)
                               { on_worker_route(f, to, frm, op, r, pl); });
        sup->set_stats_handler([this, name] { on_worker_stats(name); });

        // A crossing this worker made to another runtime, which is what tells
        // the daemon the two processes have something to say to each other.
        sup->set_peer_handler([this](proxy_supervisor* from, std::string target)
                              { link_peers(from, target); });

        // The four map calls, recorded here and served a turn later, with
        // `this` outliving every supervisor it is installed on.
        sup->set_map_handler([this](uint64_t ticket, int reply_fd,
                                    std::string op, std::string n,
                                    std::string cfg)
                             { queue_map_request(ticket, reply_fd, std::move(op),
                                                 std::move(n), std::move(cfg)); });

        // Only shard 0 is the request sink, because a cross-runtime request
        // expects one answer and any shard can serve one -- a request is
        // answered from the configuration and the script, which every shard
        // has.
        if (shards.empty())
            inst->set_request_sink_override(sup.get());

        // Handed over before the fork rather than published after it, because
        // these only fill the supervisor's caches and those are what spawn()
        // writes ahead of the config frame that loads the script.
        sup->send_runtime_map(build_runtime_map_payload());
        if (const std::string cv = build_cluster_view_payload(); !cv.empty())
        {
            sup->send_cluster_view(cv);
            m_cluster_view_pushed = true;
        }

        // Its own node out of the set, the one field beside the shard index
        // that differs between the N frames.
        cfg.companion_path = shards.size() < nodes.size() ? nodes[shards.size()]
                                                          : std::string{};

        if (!sup->spawn(cfg))
        {
            LOG_ERROR("could not start out-of-process proxy worker");
            // The override must not outlive the supervisor it points at, and
            // only when this is that supervisor, because a fork failing on the
            // third child must not unhook the first.
            if (shards.empty())
                inst->set_request_sink_override(nullptr);
            inst->mark_failed();

            // Stop adding to a runtime just marked failed, because whatever
            // stopped this fork will not be different one line later and the
            // shards that came up are retired on the next reconcile.
            break;
        }
        // Three frames reach this child in order -- config, endpoint table,
        // start -- with the last two sent once the whole shard set is in the
        // map, and a pointer rather than an iterator because the vector
        // reallocates as shards are appended.
        shards.push_back(std::move(sup));
        forked.push_back(shards.back().get());
        }

        // Once for however many were forked and before any is started, because
        // a backend written as a bare name is resolved inside start() and a
        // proxy forked with an empty endpoint cache never came up at all.
        if (!forked.empty())
        {
            m_manager.publish_endpoints();
            for (auto* s : forked)
                s->send_start();
        }

        // The descriptors have been placed into every child that wanted them,
        // and are dropped so a restart cannot place numbers the guard above is
        // about to close.
        for (auto& sup : shards)
            sup->clear_mesh_fds();

        // A name whose every fork failed must not be left in the map as an
        // empty vector: `m_proxy_workers.find(name)` succeeding with nothing in
        // it would answer "this runtime has workers" to every site that asks.
        if (shards.empty())
        {
            m_proxy_workers.erase(name);
            // And the regions go with them, for the same reason: a table with
            // no process publishing into it is not a smaller table, it is one
            // whose every reader has gone.
            m_shard_regions.erase(name);
            m_shard_client_regions.erase(name);
        }
    }

    // And now the routes, once nothing is iterating the map, covering the
    // departures the stop hook does not reach -- a rename, a shard count
    // reduced to zero, a restore that no longer wants it.
    for (const auto& n : retired_names)
        route_relay::forget(&m_manager, n);

    // Here and not only on the health tick, because a worker forked by a
    // `create -s` must be announced to the workers already running before the
    // command returns: on the tick alone, a cache told there was nobody would
    // go on believing it for up to one tick after somebody arrived, and drop
    // every publish in between.
    refresh_publish_interest();
}

std::string daemon_handler::on_start_error(std::string_view name)
{
    if (auto* inst = m_manager.get(name); inst && !inst->last_on_start_error().empty())
        return inst->last_on_start_error();

    // Nothing on the instance means on_start ran or ran somewhere else, so the
    // first shard that has a reason reports it and every shard is drained,
    // because take_ is destructive.
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

// The reply a port client would have read, turned back into what the CLI
// promises: success is silent, and everything else is printed as it came.
int daemon_handler::run_cache_action(ipc_connection* conn, std::string_view name,
                                     std::string_view action,
                                     std::string_view command)
{
    auto it = m_proxy_workers.find(std::string(name));
    if (it == m_proxy_workers.end() || it->second.empty() || !it->second[0])
    {
        conn->write_buf = "could not reach the worker holding "
                        + std::string(name) + "\n";
        return 2;
    }

    const uint64_t ticket = proxy_supervisor::direct_ticket_bit
                          | ++m_direct_ticket_seq;

    uint8_t     st = 0;
    std::string reply;
    {
        // A ::poll inside a command handler, exactly as await_worker_startup
        // does it and for the reason stated there.
        const worker_wait_scope waiting{m_worker_wait_depth};

        // Marked as exactly one command: the CLI's own framing carries a
        // value with newlines in it, and the cache's line-split path would
        // read everything past the first one as further commands.
        std::string framed("\x01skl-one\n");
        framed.append(command);

        auto* sup = it->second[0].get();
        if (!sup->send_direct(ticket, framed)
            || !sup->await_direct(ticket, std::chrono::milliseconds(5000),
                                  st, reply))
        {
            conn->write_buf = "no answer from the worker holding "
                            + std::string(name) + "\n";
            return 2;
        }
    }

    if (st != static_cast<uint8_t>(request_status::ok))
    {
        conn->write_buf = "the worker holding " + std::string(name)
                        + " refused the command\n";
        return 2;
    }

    while (!reply.empty() && (reply.back() == '\n' || reply.back() == '\r'))
        reply.pop_back();

    // `ok` is the text protocol saying a mutation took, and this CLI does not
    // print that: success is silent.
    if (reply == "ok")
        return 0;

    // The one message the daemon says better, because it names the word that
    // was not understood instead of the fact that something was not.
    if (reply == "failed: unknown command")
    {
        conn->write_buf = "unknown action: " + std::string(action) + "\n";
        return 1;
    }

    conn->write_buf = reply;
    conn->write_buf += '\n';

    // Everything the protocol refuses, kept at exit 1 -- bad input, not a
    // fatal -- and told apart by the prefixes the cache itself uses.
    if (reply.starts_with("usage:") || reply.starts_with("denied:")
        || reply.starts_with("failed:") || reply.starts_with("error:")
        || reply.starts_with("ERR"))
        return 1;

    return 0;
}

int daemon_handler::await_worker_startup(std::string_view name, std::string& out,
                                         std::chrono::steady_clock::time_point deadline)
{
    auto it = m_proxy_workers.find(std::string(name));
    if (it == m_proxy_workers.end())
    {
        // Two unlike things shared this return, and one of them is a failure.
        // An in-daemon runtime has no worker BY DESIGN.  A runtime whose fork
        // failed has none because reconcile_proxy_workers() marked it failed
        // and erased the name -- and answering 0 for that told the operator
        // `start` had worked, with nothing on the terminal, `ls` reading
        // Failed and the state file carrying was_running:true.
        auto* inst = m_manager.get(name);
        if (inst && inst->is_out_of_process() &&
            inst->get_state() == runtime_failed)
        {
            // Not "did not accept its configuration": no worker ever read it.
            out += "runtime ";
            out += name;
            out += " could not start: no worker process was created "
                   "(the reason is in the daemon log)\n";

            // On the same reasoning as the refused branch below: a runtime
            // that never started must not be restored as running.
            if (m_persistence)
                m_persistence->set_was_running(name, false);
            return 1;
        }
        return 0;   // in-daemon: nothing in another process
    }

    // Whatever is left of the command's budget and never less than zero, which
    // costs nothing when the children ahead answered in 20 ms.
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - std::chrono::steady_clock::now());
    if (left < std::chrono::milliseconds(0))
        left = std::chrono::milliseconds(0);

    // Every shard, and the worst verdict any of them gave in the order refused
    // > pending > serving, sharing one deadline so a wedged child cannot
    // multiply the bound.
    auto verdict = proxy_supervisor::startup::serving;
    {
        // Everything below is a ::poll inside a command handler, so nothing
        // the ring owes is dispatched while it runs, which is what tells
        // queue_map_request to serve where requests arrive.
        const worker_wait_scope waiting{m_worker_wait_depth};

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

    // The iterator is re-taken rather than reused, because await_startup()
    // drains the control socket and a publish can reach a subscriber that
    // removes a runtime, which erases from this map.
    it = m_proxy_workers.find(std::string(name));
    if (it == m_proxy_workers.end())
        return 0;   // gone while we waited: nothing left to report on

    switch (verdict)
    {
        case proxy_supervisor::startup::serving:
            // The child is listening, so it becomes a group member here rather
            // than on the health tick, with the flag consumed from every shard
            // and one publish for however many reported it.
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
        {
            // "Did not accept" rather than "refused its script", because two
            // different things reach this verdict and only one is a refusal in
            // the narrow sense -- exit 1 for both, because both are the
            // configuration that was handed in.
            out += "runtime ";
            out += name;
            out += " could not start: the worker did not accept its "
                   "configuration";

            // The child's own reason when it managed to send one, read from
            // the first shard that has one, because a configuration refusal is
            // the same for every shard.
            std::string why;
            if (auto wit = m_proxy_workers.find(std::string(name));
                wit != m_proxy_workers.end())
                for (auto& sup : wit->second)
                    if (why = sup->take_config_error(); !why.empty())
                        break;

            if (!why.empty())
            {
                out += ": ";
                out += why;
                if (out.back() != '\n')
                    out += "\n";
            }
            else
            {
                out += " (the reason is in the daemon log)\n";
            }

            // ─── AND IT IS NOT `was_running` ────────────────────────────────
            // was_running is cleared here, and only on `refused`, because two
            // commands set it before the child exists and a refused runtime
            // restored after a restart took a unix path from the runtime that
            // owned it in 22% of runs.
            if (m_persistence)
                m_persistence->set_was_running(name, false);
            return 1;
        }

        case proxy_supervisor::startup::pending:
            break;
    }

    // Neither answer inside the bound, reported as neither, because this side
    // does not know which it is and both wrong answers are worse than saying
    // what is known.
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
    // short enough that a daemon stopping runtimes in a loop does not
    // accumulate them.
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
        // The one question worth asking, which only the loop can answer: is
        // any completion still going to name the storage inside this object.
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

    // The children first -- liveness, then whatever they have reported -- both
    // before the managed-runtime sweep, which can return early.
    bool routes_moved = false;
    // Names whose child was found dead on this tick; see the fan-out below the
    // loop for why they are collected rather than acted on in place.
    std::vector<std::string> died;

    for (auto& [worker_name, shards] : m_proxy_workers)
    for (auto& sup : shards)
    {
        // The child's own report, drained before liveness so a runtime that
        // failed to start reaches the state file on the same tick it was heard
        // about.
        if (sup->take_state_change() && m_persistence)
        {
            if (auto* inst = m_manager.get(worker_name))
                m_persistence->save_runtime(inst);
        }

        // A declaration that arrived since the last tick, where one publish
        // covers however many sent one because the whole table is rebuilt.
        if (sup->take_routes_change())
            routes_moved = true;

        // A child that has started listening since the last tick, folded into
        // the same republish as the backstop for every way a worker comes up
        // without something waiting on it.
        if (sup->take_reachability_change())
            routes_moved = true;

        // Before liveness, because that call can reap the child and clear the
        // pid this one reads.
        sup->check_wedged();

        if (sup->check_liveness())
        {
            // A child that died and was not restarted has moved the runtime to
            // `failed`; that has to reach the state file or a daemon restart
            // would bring back a runtime the operator was told had failed.
            if (m_persistence)
                if (auto* inst = m_manager.get(worker_name))
                    m_persistence->save_runtime(inst);

            // And every route in or out of it, because a restarted worker
            // comes back with an empty connection table -- collected rather
            // than fanned out here, since forget() runs on_disconnect and a
            // script may remove a runtime from the map this loop walks.
            died.push_back(worker_name);
        }
    }
    for (const auto& n : died)
        route_relay::forget(&m_manager, n);

    poll_proxy_workers();
    reconcile_proxy_workers();

    if (routes_moved)
        m_manager.publish_endpoints();

    // The workers' replica refreshed for what no event announces -- a
    // connection count, and a runtime that reached `failed` through
    // mark_failed() -- unconditionally, because send_runtime_map() drops a
    // payload the child already has.
    publish_runtime_map_to_workers();

    // reconcile_proxy_workers() above has already refreshed the interest for
    // anything it changed; this catches what it cannot see -- a runtime the
    // daemon is running in-process reaching or leaving `running`.
    refresh_publish_interest();

    // And what the cluster looks like on the same tick, which is exactly the
    // cadence cluster_discovery re-scans the shared directory at.
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

        // Process died — stop and restart, unless it is dying faster than it
        // is running.  Without this an `add` runtime whose program exits at
        // once was forked again every two seconds for ever, and `ls` read `Up`
        // the whole time because m_manager.start() sets the state back before
        // the next tick finds the corpse.  The burst is the supervisor's, from
        // the same two constants, because both paths restart a child and owe
        // the operator one answer.
        const auto now = std::chrono::steady_clock::now();
        auto& burst = m_managed_restarts[std::string(name)];
        if (now - burst.last > restart_burst_window)
            burst.count = 0;
        burst.last = now;

        if (++burst.count > restart_burst_limit)
        {
            LOG_ERROR("managed runtime restarted too often, leaving it failed");
            lock.unlock();
            inst->mark_failed();
            if (m_persistence)
            {
                // Or the next daemon start brings back a program that has
                // already proved it cannot stay up.
                m_persistence->set_was_running(name, false);
                m_persistence->save_runtime(inst.get());
            }
            m_managed_restarts.erase(std::string(name));
            return;
        }

        LOG_WARN("managed runtime died, restarting");
        lock.unlock();
        inst->stop(m_loop);   // set state to stopped (no SIGTERM needed, process is dead)
        m_manager.start(name, m_loop);  // fork+exec again
        // The count `stats` prints, which this path never touched: a runtime
        // that had been restarting every two seconds reported 0 restarts.
        inst->note_restart();
        if (m_persistence)
            m_persistence->save_runtime(inst.get());
        return;  // restart one at a time per health check cycle
    }
}

// The same route a SIGTERM takes, because that path already stops every
// runtime, drains the ring and removes this daemon's entry -- a second way out
// would be a second thing to keep correct.
int daemon_handler::cmd_daemon_stop(ipc_connection* conn)
{
    (void)conn;
    ::kill(::getpid(), SIGTERM);
    return 0;
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

// The local half of `socketley cluster`, because the one fact the shared
// directory cannot carry is whether this daemon is in the cluster and why not;
// always exits 0.
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

    // Quarantined rather than reset, because cluster_discovery's publish timer
    // is an io_request inside the object and a reset would free storage a
    // completion still names.
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

        // A daemon joining or leaving moves nothing in the local map, so a
        // script in a worker should not hear about it later than one in here
        // does.
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

// The sentence every surface gives when asked about clustering afterwards,
// because a daemon never given --cluster and one that could not honour it are
// two different states.
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

// One rule for a name that becomes a path component, here because a
// configuration file is a second way in and a second copy of it would drift.
static std::string daemon_name_refusal(const std::string& name)
{
    for (char c : name)
        if (c == '/' || c == '\\' || c == '\0')
            return "invalid daemon name: contains path separator\n";

    if (name == "." || name == ".." || name.empty())
        return "invalid daemon name\n";

    return {};
}

std::string daemon_handler::apply_startup_identity(const std::string& name,
                                                   const std::string& cluster_dir)
{
    if (!name.empty())
    {
        if (std::string why = daemon_name_refusal(name); !why.empty())
            return why;

        m_daemon_name = name;
        m_cluster_error.clear();
    }

    if (cluster_dir.empty())
        return {};

    // Named first for the same reason `daemon-cluster` asks for it: a cluster
    // directory identifies its members by name and this daemon has none yet.
    if (m_daemon_name.empty())
        return "cluster requires a daemon name: set both in the same table\n";

    if (!start_cluster(m_daemon_name, cluster_dir))
        return "cluster mode not enabled: " + m_cluster_error + "\n"
               "  this daemon keeps serving, but it publishes nothing into "
               + cluster_dir + " and no peer can see it.\n";

    return {};
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

    if (std::string why = daemon_name_refusal(new_name); !why.empty())
    {
        conn->write_buf = why;
        return 1;
    }

    // A rename the cluster cannot honour is refused whole, because keeping the
    // new name with clustering off cost the node its membership under a name
    // that was never in dispute.
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

    // Not clustered, so nothing to republish, and any standing refusal named
    // the old name and stops describing this daemon.
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

    // A flag that cannot be honoured is refused with the reason named, loudly
    // enough to survive the exit code, and accepting --cluster while running
    // without it is never on offer.
    if (!start_cluster(m_daemon_name, cluster_dir))
    {
        conn->write_buf = "cluster mode not enabled: " + m_cluster_error + "\n"
            "  this daemon keeps serving, but it publishes nothing into "
            + cluster_dir + " and no peer can see it.\n";
        return 1;
    }

    return 0;
}

void daemon_handler::set_metrics_port(uint16_t port, bool bound)
{
    m_metrics_bound = bound;
    m_metrics_port = port;
}

void daemon_handler::set_config_path(std::string path)
{
    m_config_path = std::move(path);
}

// Named for what the caller means rather than exposing the reconciler itself,
// which is an invariant of this class and not a service it offers.
void daemon_handler::start_restored_workers()
{
    reconcile_proxy_workers();
}

int daemon_handler::cmd_dashboard(ipc_connection* conn)
{
    if (m_metrics_port == 0)
    {
        // Named with the path and the table, because the message that stood
        // here sent the operator to `socketley.conf`, which is not the name of
        // any file this daemon reads, and to a bare assignment, which is a Lua
        // global the reader never looks at.  Following it produced this same
        // message again.
        conn->write_buf =
            "metrics endpoint not configured\n"
            "add this to " +
            (m_config_path.empty() ? std::string("the daemon's config.lua")
                                   : m_config_path) +
            " and restart the daemon:\n"
            "    daemon = { metrics_port = 9100 }\n";
        return 1;
    }

    // Named as this daemon's failure rather than printed as a URL, because the
    // process holding that port is almost always another daemon and its
    // dashboard is the one the operator would have been reading.
    if (!m_metrics_bound)
    {
        conn->write_buf =
            "metrics_port " + std::to_string(m_metrics_port) +
            " is configured but this daemon could not bind it\n"
            "something else holds it; `socketley daemons` lists the daemons "
            "running here\n";
        return 1;
    }

    conn->write_buf = "Dashboard: http://127.0.0.1:" + std::to_string(m_metrics_port) + "/\n";
    return 0;
}

// Frame one command's reply onto the outgoing stream, copied out of write_buf
// because that is scratch every cmd_* assigns to while out_buf is the only
// thing a write SQE is ever given.
void daemon_handler::append_response(ipc_connection* conn, int exit_code)
{
    conn->out_buf += static_cast<char>(exit_code);
    conn->out_buf += conn->write_buf;
    conn->out_buf += '\0';
}

// One write outstanding per connection with no read re-armed until it reports,
// which is what makes the buffer safe -- a write per command let a pipelined
// second command rebuild write_buf under the first, and left the two
// completions indistinguishable.
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
