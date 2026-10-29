#include "daemon_handler.h"
#include "cluster_reconciler.h"
#include "raft_host.h"
#include "flag_handlers.h"
#include "type_manifest.h"
#include "../shared/runtime/command_usage.h"
#include "../shared/util/random_id.h"
#include "../shared/runtime/type_registry.h"
#include "../shared/runtime/stats_text.h"
#include "../shared/loop/event_loop.h"
#include "../shared/runtime/runtime_manager.h"
#include "../shared/runtime/runtime_definitions.h"
#include "../shared/util/time_format.h"
#include "../shared/persist/state_persistence.h"
#include "../shared/net/fast_lo.h"
#include "../cli/runtime_type_parser.h"
#include "../cli/command_hashing.h"
#include "../runtime/cache/cache_instance.h"
#include "../runtime/storage/storage_instance.h"
#include "../runtime/dns/dns_instance.h"
#include "../runtime/sync/sync_instance.h"
#include "../runtime/idp/idp_instance.h"
#include "../runtime/tunnel/tunnel_instance.h"
#include "../runtime/tunnel/tunnel_registry.h"
#include "../runtime/proxy/proxy_auth.h"
#include "../runtime/db/db_instance.h"
#include "../runtime/mqtt/mqtt_command.h"
#include "../shared/util/base64.h"
#include "../runtime/mqtt/mqtt_instance.h"
#include "../runtime/mail/mail_instance.h"
#include "../runtime/mail/mail_command.h"
#include "../runtime/db/db_log.h"
#include "../runtime/db/db_store.h"
#include "../shared/lua/db_call.h"
#include "../runtime/idp/idp_run.h"
#include "../shared/storage/storage_rpc.h"
#include "../shared/net/dns_feed.h"
#include "../shared/runtime/runtime_names.h"
#include "../shared/crypto/cert_keeper.h"
#include "../runtime/dns/dns_zone.h"
#include "../runtime/dns/dns_wire.h"
#include "../shared/util/proc_stat.h"
#include "../shared/ipc/one_command.h"
#include "../shared/util/settings.h"
#include "runtime_schema.h"
#include <sys/stat.h>

static void publish_dns_names(runtime_manager& manager);

// Why `rt`'s names may not stand beside every other runtime's (runtime_names.h), empty when they may; a plan stands
// for the runtime `instead_of`, whose names it would take over.
static std::string names_refusal(runtime_manager& manager, const runtime_instance& rt, std::string_view instead_of = {})
{
    std::shared_lock lock(manager.mutex);
    std::vector<const runtime_instance*> others;
    for (const auto& [name, inst] : manager.list())
        if (instead_of.empty() || name != instead_of)
            others.push_back(inst.get());
    return runtime_names::refusal(rt, others);
}
#include "../runtime/server/server_instance.h"
#include "../runtime/client/client_instance.h"
#include "../runtime/proxy/proxy_instance.h"
#include "../shared/cluster/cluster_discovery.h"
#include "../shared/ipc/daemon_client.h"
#include "../cli/cli.h"
#include "../shared/crypto/tls_context.h"
#include "../shared/persist/paths.h"
#include "../shared/net/unix_listener.h"
#include "../shared/net/endpoint_table.h"
#include "../shared/ipc/worker_protocol.h"
#include <shared_mutex>
#include "../shared/runtime/runtime_config_apply.h"
#include "../shared/ipc/exit_bound.h"
#include "../shared/persist/appending_file.h"
#include "../shared/ipc/ipc_framing.h"
#include "../shared/ipc/shard_target.h"
#include <sys/resource.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "../shared/lua/lua_context.h"
#include "proxy_supervisor.h"

#include <unistd.h>
#include <cerrno>
#include <cstring>
#include "../shared/loop/blocking_write.h"
#include <charconv>
#include <chrono>
#include <optional>
#include <algorithm>
#include <cctype>
#include <grp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "../shared/net/name_resolver.h"
#include <iomanip>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <poll.h>
#include <csignal>
#include "../shared/util/logging.h"
#include "../shared/json/json_escape.h"
#include "../shared/util/number_parse.h"

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
    socketley::proc_stat st;
    return socketley::read_proc_stat(pid, st) && st.state == 'Z';
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
static std::string instance_tls_refusal(const runtime_instance* inst);

// An entrance asked for --tls with no certificate of its own is issued one for the names it routes: its files are
// the ones the entrance keeps, and the proxy, seeing them, asks the CA (see proxy_instance::entrance_certify).
static void entrance_cert_default(runtime_instance* inst)
{
    if (inst && runtime_names::is_entrance(*inst) && inst->get_tls() && inst->get_cert_path().empty() &&
        inst->get_key_path().empty() && inst->get_acme_domains().empty())
    {
        inst->set_cert_path(cert_keeper::entrance_cert_path(inst->get_name()));
        inst->set_key_path(cert_keeper::entrance_key_path(inst->get_name()));
    }
}

// A mail runtime asked for --tls with no certificate of its own takes its dns runtime's entrance's, the one the names
// it serves under are certified in; the entrance a dns runtime not yet made would make is its <dns>-proxy.
static void mail_cert_default(runtime_manager& manager, runtime_instance* inst)
{
    if (!inst || inst->get_type() != runtime_mail || !inst->get_tls() || !inst->get_cert_path().empty() ||
        !inst->get_key_path().empty())
        return;
    const std::string dns(static_cast<mail_instance*>(inst)->get_dns());
    if (dns.empty())
        return;
    std::string entrance = dns + "-proxy";
    if (auto* d = manager.get(dns); d && d->get_type() == runtime_dns)
        entrance = std::string(static_cast<dns_instance*>(d)->get_proxy());
    if (entrance.empty() || entrance == "none")
        return;
    inst->set_cert_path(cert_keeper::entrance_cert_path(entrance));
    inst->set_key_path(cert_keeper::entrance_key_path(entrance));
}

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
    if (!inst)
        return {};
    if (std::string msg = inst->config_refusal(); !msg.empty())
        return msg;
    // A sync whose directory holds the storage it carries to, or lies in it, would carry each object it wrote back
    // into the same storage, without end; the daemon is the one place that knows both directories.
    runtime_manager* mgr = inst->get_runtime_manager();
    if (inst->get_type() != runtime_sync || !mgr)
        return {};
    const auto* sy = static_cast<const sync_instance*>(inst);
    for (const auto& entry : sy->storage_targets())
    {
        sync_target_spec spec;
        std::string why;
        if (!parse_sync_target(entry, spec, why) || spec.runtime.empty())
            continue;
        const runtime_instance* rt = mgr->get(spec.runtime);
        if (!rt || rt->get_type() != runtime_storage)
            continue;
        // Reached by its name the storage is spoken to in plain HTTP at 127.0.0.1, which a TLS port does not answer.
        if (rt->get_tls())
            return "sync: " + spec.runtime + " serves TLS itself, so it is named by its URL, as in https://<its host>:" +
                   std::to_string(rt->get_port()) + "/" + spec.bucket + "\n";
        std::error_code ec;
        const std::string data =
            std::filesystem::weakly_canonical(std::string(static_cast<const storage_instance*>(rt)->get_dir()), ec)
                .string() + "/";
        const std::string mine = std::filesystem::weakly_canonical(std::string(sy->get_dir()), ec).string() + "/";
        if (data.starts_with(mine) || mine.starts_with(data))
            return "sync: --dir " + std::string(sy->get_dir()) + " and the directory of " + spec.runtime +
                   " lie one in the other, so every object carried would be carried again\n";
    }
    return {};
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
std::string state_text(const runtime_instance* inst)
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

// The state, and a marker on a replica the cluster placed here, which `ls` must not show as a runtime an operator made.
std::string state_column(const runtime_instance* inst)
{
    return inst->is_cluster_owned() ? state_text(inst) + " [cluster]" : state_text(inst);
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
    : m_manager(manager), m_loop(loop), m_fio(loop, this), m_alert_out(loop, m_fio, this, "alerts"), m_listen_fd(-1)
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
    // And the wait for a started runtime's workers, so a script's start answers as late as the CLI's does.
    m_manager.set_worker_await_sink([this](std::string_view name) {
        // A worker still exiting holds the fork back, and a script's start cannot be parked as the CLI's is, so it
        // is waited out here within the bound and the fork made at once.
        const std::string held(name);
        for (const auto until = std::chrono::steady_clock::now() + worker_startup_bound;
             m_spawn_waiting.contains(held) && std::chrono::steady_clock::now() < until;)
        {
            if (::poll(nullptr, 0, 10) < 0) {}
            reconcile_proxy_workers();
        }
        if (m_spawn_waiting.contains(held))
            return "runtime " + held + " is not serving yet: its previous worker has not exited; it starts once it has";
        std::string out;
        if (await_worker_startup(name, out, std::chrono::steady_clock::now() + worker_startup_bound) == 0)
            return std::string();
        while (!out.empty() && out.back() == '\n')
            out.pop_back();
        return out.empty() ? "runtime " + std::string(name) + " could not start (the reason is in the daemon log)" : out;
    });

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
            for (auto& entry : m_proxy_workers)
            {
                // Every shard, because a cluster event is about the cluster
                // and telling only shard 0 would run on_group_change in one of
                // four identical interpreters.
                for (auto& sup : entry.second)
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
    if (socketley::settings::flag("SOCKETLEY_NO_SHARD_MESH", false))
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
    // A listener of another user's on a shared /tmp path is no daemon of ours, and exiting 0 on it hid the squatter.
    const bool trusted = connected && socketley::socket_peer_trusted(probe);

    // Raw close on purpose: this is a static probe with no event loop anywhere
    // in reach, so no SQE can ever have named this number and there is nothing
    // for close_fd() to hold it against.
    close(probe);

    if (connected)
        return trusted ? socket_state::ours : socket_state::foreign;

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
            m_orphan_workers.push_back({p, std::chrono::steady_clock::now(), false, std::chrono::seconds(5), {}});

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

    // What the alerts' webhook has not taken stays in its outbox for the next start.
    m_alert_out.stop();
    m_alert_box.retire(m_loop);

    // Nothing is forked from here on, so a reply waiting for a fork is given up, and every exit watch withdrawn.
    finish_deferred_starts(true);
    for (auto& w : m_exit_watches)
    {
        if (w.pidfd < 0)
            continue;
        if (!m_loop.submit_poll_remove(&w.req)) {}
        m_loop.close_fd(w.pidfd);
        w.pidfd = -1;
    }

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
    if (socketley::file_io::owns_type(req->type))
    {
        m_fio.on_cqe(cqe);
        return;
    }

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
            if (m_alert_out.owns(req))
            {
                m_alert_out.on_timer();
                break;
            }
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
                publish_dns_names(m_manager);
                // The backstop for a start whose wait ended without an exit watch firing, the reconcile above having forked.
                finish_deferred_starts(false);
                // Release the retired runtimes the ring has finished with,
                // because removal only ever reaps the ones retired before it
                // and the last runtime a daemon removes would keep its whole
                // object.
                m_manager.reap_retired(m_loop);
                start_health_timer();
            }
            break;
        case op_poll:
            on_exit_watch(req);
            break;
        default:
            break;
    }
}

// The names every runtime is reached by, for a dns runtime with --publish to answer for (dns_feed.h): --domain and
// --acme, and a storage runtime's --domain and --website-domain with the wildcard its buckets are addressed under.
// Rewritten only when they change, which is what moves the feed's time and with it the serial secondaries see.
// The origins of a dns runtime's zones, read from its files once and again only when one changes.
// The settings of `cfg` that name the runtime `name`, which a rename of it would leave naming nothing.
static std::vector<std::string> naming_settings(const runtime_config& cfg, std::string_view name)
{
    std::vector<std::string> out;
    // `<runtime>/<bucket>` names the runtime before its slash; a URL names none.
    const auto names = [&](std::string_view v) { return !v.empty() && v.find("://") == std::string_view::npos &&
                                                       v.substr(0, v.find('/')) == name; };
    if (cfg.cache_name == name)
        out.emplace_back("--cache");
    if (std::find(cfg.backends.begin(), cfg.backends.end(), name) != cfg.backends.end())
        out.emplace_back("--backend");
    for (std::string_view auth = cfg.proxy_auth; !auth.empty();)
        if (const std::string_view m = socketley::take_item(auth, '+'); m == "idp:" + std::string(name))
            out.emplace_back("--auth");
    for (const std::string* idp : {&cfg.storage_idp, &cfg.tunnel_idp, &cfg.db_idp, &cfg.mqtt_idp, &cfg.mail_idp})
        if (*idp == name)
            out.emplace_back("--idp");
    if (cfg.dns_proxy == name)
        out.emplace_back("--proxy");
    if (names(cfg.sync_storage) || names(cfg.mail_storage))
        out.emplace_back("--storage");
    if (cfg.mail_dns == name)
        out.emplace_back("--dns");
    return out;
}

static std::vector<std::string> zone_origins(const runtime_instance& rt)
{
    struct cached { std::optional<socketley::file_stamp> stamp; std::string origin; };
    static std::unordered_map<std::string, cached> cache;
    std::vector<std::string> out;
    for (const auto& path : static_cast<const dns_instance&>(rt).zone_paths())
    {
        const socketley::file_stamp now = socketley::file_stamp::of(path);
        if (!now.exists())
            continue;
        cached& c = cache[path];
        if (c.stamp != now)
        {
            socketley::dns::zone z;
            std::string why;
            c.stamp = now;
            c.origin = socketley::dns::load_zone(path, {}, z, why) ? socketley::dns::to_text(z.origin) : std::string{};
        }
        if (!c.origin.empty())
            out.push_back(c.origin);
    }
    return out;
}

static void publish_dns_names(runtime_manager& manager)
{
    std::vector<std::string> names;
    std::string zones;
    std::vector<std::pair<std::string, std::string>> tables;
    {
        std::shared_lock lock(manager.mutex);
        std::vector<const runtime_instance*> all;
        for (const auto& [name, inst] : manager.list())
        {
            if (!inst)
                continue;
            all.push_back(inst.get());
            for (auto& n : runtime_names::of(*inst, /*with_buckets=*/true))
                names.push_back(std::move(n));
            for (const auto& d : inst->get_acme_domains())
                if (std::string why; dns_feed::valid_name(d, why))
                    names.push_back(runtime_names::normal(d));
        }
        // Every entrance's table, built while the runtimes cannot change under it.
        for (const runtime_instance* r : all)
            if (runtime_names::is_entrance(*r))
                tables.emplace_back(std::string(r->get_name()), runtime_names::entrance_table(*r, all, zone_origins));
        // Each dns runtime's zones, which a mail runtime naming it with --dns takes as its domains, and whose
        // host name, mail.<zone> unless it says another, is then given the dns runtime's addresses.
        std::unordered_map<std::string, std::vector<std::string>> origins;
        for (const runtime_instance* r : all)
            if (r->get_type() == runtime_dns)
                for (const auto& o : zone_origins(*r))
                {
                    origins[std::string(r->get_name())].push_back(o);
                    zones += std::string(r->get_name()) + " " + o + "\n";
                }
        for (const runtime_instance* r : all)
        {
            if (r->get_type() != runtime_mail)
                continue;
            const auto& ml = static_cast<const mail_instance&>(*r);
            const auto it = origins.find(std::string(ml.get_dns()));
            if (ml.get_dns().empty() || it == origins.end() || it->second.empty())
                continue;
            // The name the runtime greets with and its MX names: of its first --mail-domain, else of the zone.
            std::string host(ml.get_hostname());
            if (host.empty())
            {
                const auto own = ml.domains();
                host = "mail." + (own.empty() ? it->second.front() : own.front());
                if (host.back() == '.')
                    host.pop_back();
            }
            if (std::string why; dns_feed::valid_name(host, why))
                names.push_back(runtime_names::normal(host));
            // The host an MTA-STS policy is fetched from is this one too, where the runtime serves it.
            if (ml.get_mta_sts_port())
            {
                auto own = ml.domains();
                if (own.empty())
                    own = it->second;
                for (std::string d : own)
                {
                    if (!d.empty() && d.back() == '.')
                        d.pop_back();
                    if (std::string why; dns_feed::valid_name("mta-sts." + d, why))
                        names.push_back(runtime_names::normal("mta-sts." + d));
                }
            }
        }
    }
    if (!dns_feed::write_zones(zones))
        LOG_WARN(("the zones for mail runtimes could not be written to " + dns_feed::dir()).c_str());
    std::vector<std::string> entrances;
    for (const auto& [entrance, table] : tables)
    {
        entrances.push_back(entrance);
        if (!dns_feed::write_routes(entrance, table))
            LOG_WARN(("the routes of entrance " + entrance + " could not be written").c_str());
    }
    dns_feed::remove_routes_except(entrances);
    static bool warned = false;
    if (!dns_feed::write_names(names) && !warned)
    {
        warned = true;
        LOG_WARN(("the names for dns runtimes could not be written to " + dns_feed::dir()).c_str());
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
        conn->serial = ++m_next_serial;
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

    // A line is held whole until its end, as a frame is up to max_payload: one that never ends is not let grow
    // past that bound either.
    if (SOCKETLEY_UNLIKELY(conn->partial.size() > ipc_frame::max_payload + ipc_frame::header_size) &&
        conn->partial[0] != ipc_frame::marker && conn->partial.find('\n') == std::string::npos)
    {
        LOG_ERROR("daemon: a CLI connection sent a line longer than the limit with no end to it; closing it");
        close_client(it);
        return;
    }

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

            // What was typed while the runtime is down goes nowhere, rather than all at once when it next starts.
            auto* inst = m_manager.get(conn->interactive_name);
            if (!inst || inst->get_state() != runtime_running)
            {
                conn->partial.clear();
                break;
            }

            // ─── The typed line goes where the runtime is ────────────────
            // Every arm below used to call the instance directly, which was
            // right while a runtime could live in the daemon and has been
            // wrong since none can: this object is the placeholder.
            // broadcast() and lua_send() return at their first guard -- both
            // test m_loop, which only setup() assigns and a placeholder's
            // setup() never runs -- so the line was accepted and discarded.
            // The cache was worse than discarding: execute() answered out of
            // the placeholder's own empty store, so `get k` said nil for a key
            // that existed and `set k v` said ok into a store nothing could
            // read.
            //
            // This is the THIRD site of that one defect.  `send` carries the
            // fix and a comment naming it -- "calling broadcast() on a
            // placeholder succeeded, returned 0, and sent the message
            // nowhere" -- and `socketley <cache> <verb>` carries it with a
            // test whose header describes this exact symptom.  Both routes
            // are reused here rather than a third being written.
            if (inst->is_out_of_process())
            {
                if (inst->get_type() == runtime_cache)
                {
                    // The whole line is one command, which is what
                    // run_cache_action frames it as -- a value with a newline
                    // in it would otherwise be read as further commands.  The
                    // answer lands in write_buf, and an interactive session is
                    // a stream rather than a command with a reply, so it goes
                    // straight out and the buffer is left clean for whatever
                    // asks next.
                    const size_t sp = line.find(' ');
                    run_cache_action(conn, conn->interactive_name,
                                     line.substr(0, sp), line);
                    // Never blocking the daemon on a terminal that stopped reading: what does not fit is dropped.
                    if (!conn->write_buf.empty())
                    {
                        if (!socketley::send_all_nowait(conn->fd, conn->write_buf.data(),
                                                        conn->write_buf.size())) {}
                        conn->write_buf.clear();
                    }
                }
                else if (inst->get_type() == runtime_server
                         || inst->get_type() == runtime_client)
                {
                    // Fanned across every shard, which is what a server's
                    // broadcast means and what `send` already does.
                    deliver_to_worker(conn->interactive_name, line);
                }
                continue;
            }

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
                    if (!resp.empty() && !socketley::send_all_nowait(conn->fd, resp.data(), resp.size())) {}
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

    serve_commands(it, false);
}

void daemon_handler::serve_commands(client_map::iterator it, bool queued)
{
    auto* conn = it->second.get();
    const int fd = conn->fd;

    // ─── TWO FRAMINGS ON ONE CONNECTION ─────────────────────────────────────
    // A command is a line unless it begins with the frame marker, and both are
    // handled in one loop because both can arrive in one packet.
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
        // Answered, after whatever is queued ahead of it, once its starts can be waited for.
        if (exit_code == reply_parked)
            return;
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

int daemon_handler::process_command(ipc_connection* conn, std::string& line)
{
    parsed_args pa;
    pa.parse(line);
    ipc_frame::restore_spaces(line);
    return process_parsed(conn, pa);
}

int daemon_handler::process_parsed(ipc_connection* conn, const parsed_args& pa)
{
    // ─── One guard, for every command ───────────────────────────────────────
    // The reply guard is held here rather than in each handler, because a
    // per-handler list goes stale the moment somebody adds a command -- which
    // is how four of them came to write to the daemon's own stdout.
    const cout_to_reply reply_guard(conn);

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

    const int rc = dispatch_command(conn, pa);

    // The names in the list that named nothing -- see resolve_names.  Written
    // through cout so the reply guard puts it after whatever the handler
    // printed, and so it works for a caller with no connection.
    if (!m_unresolved.empty())
    {
        for (const auto& n : m_unresolved)
            std::cout << "runtime not found: " << n << "\n";
        std::cout << "  " << pa.args[0] << " ran for the rest of the list and not for "
                  << (m_unresolved.size() == 1 ? "this name" : "these names")
                  << ".\n"
                     "  `socketley ls` lists what is there.\n";
        m_unresolved.clear();
        if (rc == reply_parked)
        {
            conn->parked_floor = 1;
            return rc;
        }
        return rc == 0 ? 1 : rc;
    }

    return rc;
}

int daemon_handler::dispatch_command(ipc_connection* conn, const parsed_args& pa)
{
    switch (pa.hashes[0])
    {
        case fnv1a("create"):     return cmd_create(conn, pa);
        case fnv1a("plan"):       return cmd_plan(conn, pa);
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
        case fnv1a("restart"):   return cmd_restart(conn, pa);
        case fnv1a("action"):    return cmd_action(conn, pa);
        case fnv1a("stats"):     return cmd_stats(conn, pa);
        case fnv1a("reload"):    return cmd_reload(conn, pa);
        case fnv1a("reload-lua"):return cmd_reload_lua(conn, pa);
        case fnv1a("owner"):     return cmd_owner(conn, pa);
        case fnv1a("attach"):    return cmd_attach(conn, pa);
        case fnv1a("add"):       return cmd_add(conn, pa);
        case fnv1a("daemon-stop"): return cmd_daemon_stop(conn);
        case fnv1a("daemon-stats"): return cmd_daemon_stats(conn);
        case fnv1a("cluster-dir"): return cmd_cluster_dir(conn);
        case fnv1a("cluster-status"): return cmd_cluster_status(conn);
        case fnv1a("raft-status"):    return cmd_raft_status(conn);
        case fnv1a("cluster-create"): return cmd_cluster_create(conn, pa);
        case fnv1a("cluster-remove"): return cmd_cluster_remove(conn, pa);
        case fnv1a("cluster-scale"):  return cmd_cluster_scale(conn, pa);
        case fnv1a("cluster-has"):    return cmd_cluster_has(conn, pa);
        case fnv1a("cluster-placement"): return cmd_cluster_placement(conn);
        case fnv1a("daemon-name"):    return cmd_daemon_name(conn, pa);
        case fnv1a("daemon-cluster"): return cmd_daemon_cluster(conn, pa);
        case fnv1a("dashboard"):     return cmd_dashboard(conn);
        case fnv1a("settings"):      return cmd_settings(conn, pa);
        case fnv1a("ping"):          return cmd_ping(conn);
        case fnv1a("idp-user"):      return cmd_idp_user(conn, pa);
        case fnv1a("db-backup"):     return cmd_db_backup(conn, pa);
        case fnv1a("mqtt-pub"):
        case fnv1a("mqtt-sessions"):
        case fnv1a("mqtt-kick"):
        case fnv1a("mqtt-retained"):
        case fnv1a("mqtt-tap"):      return cmd_mqtt(conn, pa);
        case fnv1a("mail-send"):
        case fnv1a("mail"):          return cmd_mail(conn, pa);
        case fnv1a("db-restore"):    return cmd_db_restore(conn, pa);
        case fnv1a("db-query"):      return cmd_db_query(conn, pa);
        case fnv1a("dnssec"):        return cmd_dnssec(conn, pa);
        case fnv1a("tunnel"):        return cmd_tunnel(conn, pa);
        case fnv1a("startup"):       return cmd_startup(conn, pa);
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
    if (m_cluster_creating)
        instance->set_cluster_owned(true);

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
                case runtime_storage:
                    result = parse_storage_flags(
                        static_cast<storage_instance*>(instance), pa, i, name);
                    break;
                case runtime_dns:
                    result = parse_dns_flags(static_cast<dns_instance*>(instance), pa, i, name);
                    break;
                case runtime_sync:
                    result = parse_sync_flags(static_cast<sync_instance*>(instance), pa, i, name);
                    break;
                case runtime_idp:
                    result = parse_idp_flags(static_cast<idp_instance*>(instance), pa, i, name);
                    break;
                case runtime_db:
                    result = parse_db_flags(static_cast<db_instance*>(instance), pa, i, name);
                    break;
                case runtime_mqtt:
                    result = parse_mqtt_flags(static_cast<mqtt_instance*>(instance), pa, i, name);
                    break;
                case runtime_mail:
                    result = parse_mail_flags(static_cast<mail_instance*>(instance), pa, i, name);
                    break;
                case runtime_tunnel:
                    result = parse_tunnel_flags(static_cast<tunnel_instance*>(instance), pa, i, name);
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
    entrance_cert_default(instance);
    mail_cert_default(m_manager, instance);
    if (const std::string msg = instance_tls_refusal(instance); !msg.empty())
    {
        std::cout << msg;
        m_manager.remove(name);
        return 1;
    }

    // A name belongs to one runtime, checked once every flag is in.
    if (const std::string msg = names_refusal(m_manager, *instance, m_plan_for); !msg.empty())
    {
        std::cout << msg;
        m_manager.remove(name);
        return 1;
    }

    // Checked as a set for the same reason TLS is, and at the same point: the
    // flag that completes the request may be further along the command line.
    if (const std::string msg = instance->ring_policy_refusal(m_loop); !msg.empty())
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

    // A dns runtime comes with its entrance: the proxy every name it publishes is reached through, made here as
    // its child unless it exists already or --proxy none says there is to be none.
    if (type == runtime_dns && !instance->get_test_mode() && !instance->is_lua_created())
        if (const int rc = make_dns_entrance(static_cast<dns_instance*>(instance), autostart); rc != 0)
        {
            m_manager.remove(name);
            return rc;
        }

    std::string start_refusal;

    if (autostart && !instance->get_test_mode())
    {
        std::string refusal;
        if (!m_manager.start(name, m_loop, &refusal))
        {
            // A refusal with a sentence is the operator's to fix, so the
            // runtime stays where `ls` shows it and `edit` can reach it, and
            // the command exits 1 -- bad input, not fatal.  That is the same
            // answer `create -s` already gives a script whose on_start raised:
            // created, named, exit 1, fix it and try again.
            //
            // Without a sentence the start failed for a reason nobody can act
            // on -- a fork that did not happen -- and a half-made runtime is
            // worse than none, which is what this path always did.
            if (!refusal.empty())
            {
                // Carried past the save rather than printed here, because the
                // one save in this function is below and returning left
                // exactly what the --test block further down was written to
                // stop: a runtime that `ls` lists and `start` will bind, with
                // no state file, dropped without a word at the next restart.
                start_refusal = std::move(refusal);
                // Nothing started, so the reconcile and the worker wait below
                // have nothing to wait for.
                autostart = false;
            }
            else
            {
                std::cout << "could not start runtime\n";
                // The entrances it just made go with it, or nothing names them any more.
                const auto entrances = dns_entrance_children(name);
                for (const auto& e : entrances)
                    m_manager.stop(e, m_loop);
                if (!entrances.empty())
                    reconcile_proxy_workers();
                for (const auto& e : entrances)
                {
                    m_manager.remove(e);
                    if (m_persistence)
                        m_persistence->remove_runtime(e);
                }
                m_manager.remove(name);
                return 2;
            }
        }
    }

    if (m_persistence && !instance->get_test_mode() && !instance->is_lua_created())
        m_persistence->save_runtime(instance);

    // After the save, which is what it was carried this far for.
    if (!start_refusal.empty())
    {
        std::cout << start_refusal;
        return 1;
    }

    // After the save, because the supervisor describes the child with the same
    // runtime_config the state file holds and reads it back off the instance.
    if (autostart && !instance->get_test_mode())
    {
        reconcile_proxy_workers();

        // The cluster's reconciliation runs on the Raft tick, so it never waits for a worker: a failure shows as the runtime's state on a later tick.
        if (m_cluster_internal)
            return 0;

        // The answer waits for the process that decides it, because the script
        // runs, the port binds and the TLS pair is checked in the worker --
        // and the runtime is left `failed` rather than removed, so the
        // worker's reason is not the only record of a runtime the operator can
        // no longer ask about.
        const std::string created(name);
        auto verdict = [this, created](std::string& out)
        {
            std::string wmsg;
            const int   wrc = await_worker_startup(
                created, wmsg, std::chrono::steady_clock::now() + worker_startup_bound);
            if (wrc != 0)
            {
                out += wmsg;
                return wrc;
            }

            // The runtime may not exist any more, because the wait serves map
            // requests inline and a script's own `socketley.remove` frees a
            // placeholder that never reached setup(), so the name is re-resolved
            // rather than cached.
            if (!m_manager.get(created))
                return 0;

            // A script whose on_start raised is not a silent success, reported
            // last because nothing above is undone, and as exit 1 because the
            // fault is in the file the operator named; two places to ask,
            // because on_start runs wherever the script runs.
            if (std::string why = on_start_error(created); !why.empty())
            {
                out += "create " + created + ": " + why + "\n"
                       "the runtime is created and running, with whatever "
                       "on_start established before it raised; fix the script "
                       "and run `reload-lua " + created + "` to re-run it.\n";
                return 1;
            }
            return 0;
        };

        // A runtime of this name removed a moment ago may still have its worker, which this one's fork waits for.
        if (conn && m_spawn_waiting.contains(created))
        {
            park_reply(conn, {created}, [verdict](ipc_connection* c) { return verdict(c->write_buf); });
            return reply_parked;
        }
        std::string out;
        const int   rc = verdict(out);
        std::cout << out;
        return rc;
    }

    // ─── A DRY RUN LEAVES NOTHING BEHIND ────────────────────────────────────
    // --test skips the start and the save, and skipping the save was the whole
    // defect: try_create() made the runtime before the first flag was read and
    // nothing took it away, so a dry run held the name until the daemon
    // restarted -- and the real `create` that followed answered "runtime
    // already exists".  Worse, what it left was startable: `start` on it bound
    // the port and served, with no state file, so the daemon's next restart
    // dropped a running runtime with no record that it had been there.
    //
    // Removed rather than never created, because every flag parser writes into
    // an instance and there is nothing to validate against without one -- and
    // this is the form the two refusals above already use.
    if (instance->get_test_mode())
    {
        // What `plan` asks for: the runtime as `show` would write it, before it is gone -- a dns runtime's entrance
        // named as make_dns_entrance names it, which a dry run does not reach.
        if (m_plan_out && m_persistence)
        {
            if (type == runtime_dns)
            {
                auto* dns = static_cast<dns_instance*>(instance);
                const std::string proxy(dns->get_proxy());
                dns->set_proxy(proxy == "none" ? std::string() : proxy.empty() ? std::string(name) + "-proxy" : proxy);
            }
            *m_plan_out = m_persistence->format_json_pretty(m_persistence->read_from_instance(instance));
        }
        m_manager.remove(name);
    }

    return 0;
}

// `plan <type> <name> [flags]`: what `create` would keep of the runtime, as `show` writes it, kept nowhere -- made
// under a name of its own, so a runtime that exists by that name is planned as well.
int daemon_handler::cmd_plan(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 3 || pa.count + 1 >= MAX_ARGS)
    {
        std::cout << "usage: plan <type> <name> [flags]\n";
        return 1;
    }
    const std::string name(pa.args[2]);
    std::string scratch = name + ".plan";
    while (m_manager.get(scratch))
        scratch += '_';
    parsed_args p = pa;
    p.args[0] = "create";
    p.hashes[0] = fnv1a("create");
    p.args[2] = scratch;
    p.hashes[2] = fnv1a(scratch);
    p.args[p.count] = "--test";
    p.hashes[p.count] = fnv1a("--test");
    ++p.count;
    std::string json;
    m_plan_out = &json;
    m_plan_for = name;
    const int rc = cmd_create(conn, p);
    m_plan_out = nullptr;
    m_plan_for.clear();
    if (rc != 0)
        return rc;
    // A value made of the name, as a default path is, is the one the real name gives.
    for (size_t at = json.find(scratch); at != std::string::npos; at = json.find(scratch, at + name.size()))
        json.replace(at, scratch.size(), name);
    std::cout << json;
    return 0;
}

std::vector<std::string> daemon_handler::resolve_names(const parsed_args& pa, size_t start)
{
    std::shared_lock lock(m_manager.mutex);
    auto names = resolve_names_impl(pa.args, pa.count, m_manager.list(), start);

    // ─── A LIST WITH A TYPO IN IT IS NOT A LIST THAT WORKED ─────────────────
    // resolve_names_impl skips an argument that names nothing, so `stop a
    // gibtsnicht` stopped a, said nothing and exited 0 -- and on `remove`, an
    // operator clearing two runtimes and misspelling one had every reason to
    // believe both were gone.  Collected here because this is the one function
    // that turns arguments into names; reported in process_command, which is
    // the one place that also holds the exit code.
    m_unresolved.clear();

    // Nothing resolved at all is check_empty_names' case, which already reports
    // it: recording here too would print the same line twice.
    if (names.empty())
        return names;

    for (size_t i = start; i < pa.count; ++i)
    {
        const std::string_view arg = pa.args[i];
        if (arg.empty() || arg[0] == '-')
            continue;

        // A glob is a query and "no match" is an answer to one, not a typo in
        // it -- `stop 'api*'` on a box with no api runtimes asked a question
        // and got the truth.
        if (arg.find_first_of("*?[") != std::string_view::npos)
            continue;

        if (std::find(names.begin(), names.end(), arg) == names.end())
            m_unresolved.emplace_back(arg);
    }

    return names;
}

int daemon_handler::make_dns_entrance(dns_instance* dns, bool start)
{
    std::string proxy(dns->get_proxy());
    if (proxy == "none")
    {
        dns->set_proxy("");
        return 0;
    }
    if (proxy.empty())
        proxy = std::string(dns->get_name()) + "-proxy";
    const auto drop = [&](const std::string& name)
    {
        m_manager.stop(name, m_loop);
        reconcile_proxy_workers();
        m_manager.remove(name);
        if (m_persistence)
            m_persistence->remove_runtime(name);
    };
    // Made by this create, as the dns runtime's child: stopped with it, started with it, removed with it.
    const auto make = [&](const std::string& name, std::vector<std::string> words, const char* what) -> bool
    {
        if (start)
            words.emplace_back("-s");
        std::string out;
        const int rc = run_internal(words, out, false);
        auto* made = m_manager.get(name);
        if (rc != 0 || !made)
        {
            std::cout << out << what << " '" << name << "' could not be made"
                      << (made ? "" : "; give --proxy another name, --proxy-port another port, or --proxy none") << "\n";
            if (made)
                drop(name);
            return false;
        }
        made->set_owner(dns->get_name());
        made->set_child_policy(runtime_instance::child_policy::stop);
        if (m_persistence)
            m_persistence->save_runtime(made);
        return true;
    };
    bool made_entrance = false;
    if (auto* there = m_manager.get(proxy))
    {
        // One made before, or by hand: taken as it is, provided it is an entrance.
        if (!runtime_names::is_entrance(*there))
        {
            std::cout << "--proxy: '" << proxy << "' is a runtime but no entrance (a proxy speaking HTTP without "
                      << "--backend); name another, or none\n";
            return 1;
        }
    }
    // Five minutes for a runtime's first byte, as a web server in front of sites gives them; two seconds is a mesh's.
    else if (!make(proxy, {"create", "proxy", proxy, "-p", std::to_string(dns->get_proxy_port()), "--tls",
                           "--backend-timeout", "5m"},
                   "the entrance"))
        return 1;
    else
        made_entrance = true;
    // An entrance made on 443 comes with port 80, where a browser typing the bare name arrives and is sent to
    // HTTPS; one taken as it is comes as it is.
    const std::string http = proxy + "-http";
    if (made_entrance && dns->get_proxy_port() == 443 && !m_manager.get(http) &&
        !make(http, {"create", "proxy", http, "-p", "80", "--redirect-https"}, "the redirect to HTTPS"))
    {
        drop(proxy);
        return 1;
    }
    dns->set_proxy(proxy);
    return 0;
}

// The entrances a dns runtime made for itself, which go where it goes.
std::vector<std::string> daemon_handler::dns_entrance_children(std::string_view dns_name) const
{
    std::vector<std::string> out;
    const auto* dns = m_manager.get(dns_name);
    if (!dns || dns->get_type() != runtime_dns)
        return out;
    for (const auto& child : m_manager.get_children(dns_name))
        if (const auto* c = m_manager.get(child); c && runtime_names::is_entrance(*c))
            out.push_back(child);
    return out;
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
    const size_t withheld_start = withhold_cluster_names(names, "start", conn);
    if (names.empty())
        return withheld_start ? 1 : 0;
    // Counted before the entrances join, which start with their dns runtime and are no second name the operator gave.
    const size_t named = names.size();
    // A dns runtime's entrance starts with it.
    for (size_t k = 0, n = names.size(); k < n; ++k)
        for (auto& child : dns_entrance_children(names[k]))
            if (std::find(names.begin(), names.end(), child) == names.end())
                if (const auto* c = m_manager.get(child); c && c->get_state() != runtime_running)
                    names.push_back(std::move(child));

    if (want_interactive && named > 1)
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

        // A dns runtime's entrance joined names after the refusal above and is no stream for typed input either.
        if (want_interactive && inst && inst->get_type() != runtime_proxy)
        {
            // The proxy case was refused above, before anything was started.
            conn->interactive = true;
            conn->interactive_name = n;
            // The daemon's own record of who is attached, which is what
            // close_client() and teardown() read to detach.  It is NOT what
            // delivers: the messages happen in the worker.
            inst->add_interactive_fd(conn->fd);
            grant_interactive_to_workers(n, conn->fd);
        }
    }

    // Any runtime just moved into `running` in a worker now needs its child,
    // done here rather than on the health timer so `start` followed
    // immediately by a request works.
    reconcile_proxy_workers();

    // As in create: the Raft tick does not wait for a worker.
    if (m_cluster_internal)
        return failed > 0 ? 1 : 0;

    // `start` waits for the answer exactly as `create -s` does, because it was
    // reporting success for a start that did not happen -- one child's startup
    // for the whole command, since every child is forked before any is waited
    // on.
    if (!started.empty())
    {
        // A runtime whose last worker has not exited is forked when it has, and the reply waits for that, not the loop.
        if (conn && any_spawn_waiting(started))
        {
            park_reply(conn, started, [this, started, failed](ipc_connection* c)
                       { return failed + await_started(c->write_buf, started, "start") > 0 ? 1 : 0; });
            return reply_parked;
        }
        failed += await_started(conn->write_buf, started, "start");
    }

    return failed > 0 ? 1 : 0;
}

int daemon_handler::await_started(std::string& out, const std::vector<std::string>& names,
                                  std::string_view verb)
{
    int failed = 0;
    const auto deadline = std::chrono::steady_clock::now() + worker_startup_bound;
    for (const auto& n : names)
    {
        std::string wmsg;
        if (await_worker_startup(n, wmsg, deadline) != 0)
        {
            out += wmsg;
            ++failed;
            continue;   // it is not serving; on_start is the smaller news
        }

        // The runtime is up and its script's set-up is not, counted rather
        // than returned, with was_running set anyway because the operator
        // asked for this runtime to be up and it is.
        if (std::string why = on_start_error(n); !why.empty())
        {
            out += std::string(verb) + " " + n + ": " + why + "\n"
                 + "the runtime is running, with whatever on_start "
                   "established before it raised; fix the script and "
                   "run `reload-lua " + n + "` to re-run it.\n";
            ++failed;
        }
    }
    return failed;
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
    const size_t withheld = withhold_cluster_names(names, "stop", conn);

    for (const auto& n : names)
    {
        if (m_manager.stop(n, m_loop) && m_persistence)
            m_persistence->set_was_running(n, false);
    }

    // Takes down the children of everything that just stopped, before the
    // command returns: `stop` has to mean the port is free by the time the CLI
    // exits, whichever side the proxy was running on.
    reconcile_proxy_workers();
    return withheld ? 1 : 0;
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
    const size_t withheld = withhold_cluster_names(names, "remove", conn);
    // A dns runtime's entrance is removed with it -- unless another dns runtime that stays names it too, which
    // then becomes its parent.
    for (size_t k = 0, n = names.size(); k < n; ++k)
        for (auto& child : dns_entrance_children(names[k]))
        {
            if (std::find(names.begin(), names.end(), child) != names.end())
                continue;
            std::string heir;
            {
                std::shared_lock lock(m_manager.mutex);
                for (const auto& [other, rt] : m_manager.list())
                    if (rt->get_type() == runtime_dns &&
                        (static_cast<const dns_instance*>(rt.get())->get_proxy() == child ||
                         std::string(static_cast<const dns_instance*>(rt.get())->get_proxy()) + "-http" == child) &&
                        std::find(names.begin(), names.end(), other) == names.end())
                    {
                        heir = other;
                        break;
                    }
            }
            if (heir.empty())
                names.push_back(std::move(child));
            else if (auto* c = m_manager.get(child))
            {
                c->set_owner(heir);
                if (m_persistence)
                    m_persistence->save_runtime(c);
            }
        }

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
        // Its index describes objects nobody answers for any more, and a job made again under the name starts empty.
        const auto* gone = m_manager.get(n);
        const bool sync_job = gone && gone->get_type() == runtime_sync;
        // A broker's sessions under the state directory go with it; a file of its own naming is the operator's.
        const bool broker_state = gone && ((gone->get_type() == runtime_mqtt &&
                                            static_cast<const mqtt_instance*>(gone)->get_persistent() == "on") ||
                                           gone->get_type() == runtime_mail);
        const runtime_type gone_type = gone ? gone->get_type() : runtime_server;
        if (m_manager.remove(n))
        {
            if (m_persistence)
                m_persistence->remove_runtime(n);
            if (sync_job && ::unlink(sync_index_path(n).c_str()) != 0 && errno != ENOENT)
                LOG_WARN(("sync " + n + ": its index was not removed: " + std::strerror(errno)).c_str());
            if (broker_state)
                m_forget_snapshots[n] = gone_type;
        }
    }

    forget_settled_snapshots();
    return withheld ? 1 : 0;
}

void daemon_handler::forget_settled_snapshots()
{
    for (auto it = m_forget_snapshots.begin(); it != m_forget_snapshots.end();)
    {
        if (predecessor_running(it->first))
        {
            ++it;
            continue;
        }
        if (it->second == runtime_mail)
            mail_forget_state(it->first);
        else
            mqtt_forget_snapshots(it->first);
        it = m_forget_snapshots.erase(it);
    }
}

// The refusal `ls` and `ps` share, because both read a set of column names out
// of a switch and neither had a `default:`: `socketley ls --grp` printed the
// whole table and exited 0, and so did `--format` with its value forgotten.
// The usage comes from command_usage so the columns named here and the ones
// `ls --help` prints cannot be two different lists.
static std::string listing_arg_refusal(const char* verb, std::string_view arg)
{
    std::string out;

    // Not a flag at all: neither verb takes a name, and the operator who typed
    // one wants the command that does.
    if (!arg.empty() && arg.front() != '-')
        out = "unknown argument: " + std::string(arg) + "\n"
              "  " + verb + " lists every runtime and takes no names.\n"
              "  For one: socketley show " + std::string(arg) + "\n";
    else
        out = "unknown flag: " + std::string(arg) + "\n";

    return out + "  " + command_usage::line(verb);
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

            // `--format json` is the only spelling there is, so anything else
            // is refused rather than answered in a format the operator did not
            // ask for -- and a missing value is refused too, where it used to
            // be dropped and the table printed.
            case fnv1a("--format"):
                if (i + 1 >= pa.count)
                {
                    conn->write_buf = "--format requires a value (the only one is json)\n";
                    return 1;
                }
                ++i;
                if (pa.hashes[i] != fnv1a("json"))
                {
                    conn->write_buf = "unknown format: " + std::string(pa.args[i]) +
                                      " (the only one is json)\n";
                    return 1;
                }
                json_format = true;
                break;

            default:
                conn->write_buf = listing_arg_refusal("ls", pa.args[i]);
                return 1;
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
            // The port it will actually bind, not the raw zero an unset -p
            // leaves: a server with no -p serves on 8000 and this column
            // read "-".  See runtime_instance::effective_port().
            uint16_t port = instance->effective_port();
            auto owner = instance->get_owner();
            auto group = instance->get_group();
            // Escaped, all of them, because a group and an owner are arbitrary
            // operator strings -- and where a runtime with no port listens,
            // empty for every other runtime.
            const std::string_view listen_path = instance->get_listen_path();
            out << "{\"id\":\"" << socketley::json::escape(instance->get_id())
                << "\",\"name\":\"" << socketley::json::escape(name)
                << "\",\"type\":\"" << type_to_string(instance->get_type())
                << "\",\"port\":" << port
                << ",\"listen\":\""
                << (listen_path.empty() ? std::string()
                                        : "unix:" + socketley::json::escape(listen_path))
                << "\",\"bind\":\"" << socketley::json::escape(instance->get_bind_address())
                << "\",\"status\":\"" << state_str
                << "\",\"restarts\":" << instance->restart_count()
                << ",\"connections\":" << instance->reported_connection_count()
                << ",\"owner\":\"" << socketley::json::escape(owner)
                << "\",\"group\":\"" << socketley::json::escape(group)
                << "\",\"cluster\":" << (instance->is_cluster_owned() ? "true" : "false")
                << "}";
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
            // The port it will actually bind, not the raw zero an unset -p
            // leaves: a server with no -p serves on 8000 and this column
            // read "-".  See runtime_instance::effective_port().
            uint16_t port = instance->effective_port();
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
            // The port it will actually bind, not the raw zero an unset -p
            // leaves: a server with no -p serves on 8000 and this column
            // read "-".  See runtime_instance::effective_port().
            uint16_t port = instance->effective_port();
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

            // As in cmd_ls, and for the same two reasons.
            case fnv1a("--format"):
                if (i + 1 >= pa.count)
                {
                    conn->write_buf = "--format requires a value (the only one is json)\n";
                    return 1;
                }
                ++i;
                if (pa.hashes[i] != fnv1a("json"))
                {
                    conn->write_buf = "unknown format: " + std::string(pa.args[i]) +
                                      " (the only one is json)\n";
                    return 1;
                }
                json_format = true;
                break;

            default:
                conn->write_buf = listing_arg_refusal("ps", pa.args[i]);
                return 1;
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
            // The port it will actually bind, not the raw zero an unset -p
            // leaves: a server with no -p serves on 8000 and this column
            // read "-".  See runtime_instance::effective_port().
            uint16_t port = instance->effective_port();
            auto owner = instance->get_owner();
            auto group = instance->get_group();
            const bool running = instance->get_state() == runtime_running;
            // The state is read rather than written as "running", because
            // under -a a literal would be a row for a failed runtime claiming
            // to be up.
            const std::string_view listen_path = instance->get_listen_path();
            out << "{\"id\":\"" << socketley::json::escape(instance->get_id())
                << "\",\"name\":\"" << socketley::json::escape(name)
                << "\",\"type\":\"" << type_to_string(instance->get_type())
                << "\",\"port\":" << port
                << ",\"listen\":\""
                << (listen_path.empty() ? std::string()
                                        : "unix:" + socketley::json::escape(listen_path))
                << "\",\"bind\":\"" << socketley::json::escape(instance->get_bind_address())
                << "\",\"status\":\"" << state_json(instance->get_state())
                << "\",\"uptime\":\""
                << (running ? format_uptime(instance->get_start_time()) : std::string())
                << "\",\"restarts\":" << instance->restart_count()
                << ",\"connections\":" << instance->reported_connection_count()
                << ",\"owner\":\"" << socketley::json::escape(owner)
                << "\",\"group\":\"" << socketley::json::escape(group)
                << "\",\"cluster\":" << (instance->is_cluster_owned() ? "true" : "false")
                << "}";
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
            // The port it will actually bind, not the raw zero an unset -p
            // leaves: a server with no -p serves on 8000 and this column
            // read "-".  See runtime_instance::effective_port().
            uint16_t port = instance->effective_port();
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
            // The port it will actually bind, not the raw zero an unset -p
            // leaves: a server with no -p serves on 8000 and this column
            // read "-".  See runtime_instance::effective_port().
            uint16_t port = instance->effective_port();
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
int daemon_handler::cmd_startup(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2 || !conn)
        return 1;
    const std::string name(pa.args[1]);
    std::string out;
    const int rc = await_worker_startup(name, out, std::chrono::steady_clock::now());
    if (rc != 2)
    {
        conn->write_buf = std::move(out);
        return rc;
    }
    // Still starting: the CPU its workers have used, which grows while one reads its files and not while one is wedged.
    uint64_t ticks = 0;
    if (auto it = m_proxy_workers.find(name); it != m_proxy_workers.end())
        for (const auto& sup : it->second)
            if (sup->pid() > 0)
            {
                if (socketley::proc_stat st; socketley::read_proc_stat(sup->pid(), st))
                    ticks += st.utime + st.stime;
            }
    conn->write_buf = "starting " + std::to_string(ticks) + "\n";
    return 2;
}

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
            if (exclude)
                if (const auto it = m_proxy_workers.find(std::string(name));
                    it != m_proxy_workers.end() && it->second.size() <= 1)
                    return true;
            why ="could not reach the worker holding " + std::string(name);
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

bool daemon_handler::ask_worker(ipc_connection* conn, std::string_view runtime, std::string_view payload,
                                std::string& reply, std::chrono::milliseconds bound, size_t shard)
{
    auto it = m_proxy_workers.find(std::string(runtime));
    if (it == m_proxy_workers.end() || it->second.size() <= shard || !it->second[shard])
    {
        conn->write_buf = "could not reach the worker holding " + std::string(runtime) + "\n";
        return false;
    }
    const uint64_t ticket = proxy_supervisor::direct_ticket_bit | ++m_direct_ticket_seq;
    uint8_t st = 0;
    const worker_wait_scope waiting{m_worker_wait_depth};
    auto* sup = it->second[shard].get();
    if (!sup->send_direct(ticket, payload) || !sup->await_direct(ticket, bound, st, reply))
    {
        conn->write_buf = "no answer from the worker holding " + std::string(runtime) + "\n";
        return false;
    }
    if (st != static_cast<uint8_t>(request_status::ok))
    {
        conn->write_buf = "the worker holding " + std::string(runtime) + " refused the command\n";
        return false;
    }
    return true;
}

int daemon_handler::cmd_dnssec(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count != 2)
    {
        conn->write_buf = command_usage::line("dnssec");
        return 1;
    }
    auto* instance = m_manager.get(pa.args[1]);
    if (!instance || instance->get_type() != runtime_dns)
    {
        conn->write_buf = "no dns runtime named " + std::string(pa.args[1]) + "\n";
        return 1;
    }
    const auto* dns = static_cast<const dns_instance*>(instance);
    if (!dns->get_dnssec())
    {
        conn->write_buf = std::string(pa.args[1]) + " signs no zones; edit it with --dnssec first\n";
        return 1;
    }
    std::string why;
    const std::string records = dns->ds_records(why);
    if (records.empty())
    {
        conn->write_buf = "dnssec: " + why + "\n";
        return 1;
    }
    conn->write_buf = records;
    return 0;
}

// A mail runtime's commands: a message to send goes to one shard, which queues it; the queue, a flush and a drop ask
// every shard, since each keeps a spool of its own.
int daemon_handler::cmd_mail(ipc_connection* conn, const parsed_args& pa)
{
    namespace ml = socketley::mail;
    const std::string verb(pa.args[0]);
    if (pa.count < 3)
    {
        conn->write_buf = command_usage::line(verb == "mail-send" ? "send" : "mail");
        return 1;
    }
    const std::string_view name = pa.args[1];
    auto* instance = m_manager.get(name);
    if (!instance || instance->get_type() != runtime_mail)
    {
        conn->write_buf = "no mail runtime named " + std::string(name) + "\n";
        return 1;
    }
    if (instance->get_state() != runtime_running)
    {
        conn->write_buf = std::string(name) + " is not running\n";
        return 1;
    }
    std::string reply;
    if (verb == "mail-send")
    {
        std::string payload;
        if (!socketley::base64::decode(pa.args[2], payload) || !payload.starts_with(ml::command_prefix))
        {
            conn->write_buf = "the message did not arrive whole\n";
            return 1;
        }
        if (!ask_worker(conn, name, payload, reply, std::chrono::seconds(30)))
            return 1;
        conn->write_buf = reply + (reply.ends_with('\n') ? "" : "\n");
        return reply.starts_with("error") ? 1 : 0;
    }
    const std::string_view what = pa.args[2];
    const ml::verb v = what == "queue" ? ml::verb::queue : what == "show" ? ml::verb::show
                     : what == "flush" ? ml::verb::flush : what == "drop" ? ml::verb::drop
                     : what == "dns"   ? ml::verb::dns   : what == "suppressed" ? ml::verb::suppressed
                     : what == "forgive" ? ml::verb::forgive : what == "sieve" ? ml::verb::sieve
                     : what == "unsubscribed" ? ml::verb::unsubscribed
                     : what == "resubscribe" ? ml::verb::resubscribe
                     : what == "learn" ? ml::verb::learn : what == "trace" ? ml::verb::trace
                     : what == "usage" ? ml::verb::usage : what == "export" ? ml::verb::export_box
                     : what == "import" ? ml::verb::import_box : what == "job" ? ml::verb::job : ml::verb::send;
    if (v == ml::verb::send)
    {
        conn->write_buf = command_usage::line("mail");
        return 1;
    }
    const std::string arg = pa.count > 3 ? std::string(pa.args[3]) : std::string();
    const std::string payload = ml::command_text(v, arg);
    // The users' scripts and the unsubscribed are files every shard reads, so the first shard answers for them.
    if (v == ml::verb::sieve || v == ml::verb::unsubscribed || v == ml::verb::resubscribe || v == ml::verb::learn ||
        v == ml::verb::usage || v == ml::verb::export_box || v == ml::verb::import_box || v == ml::verb::job)
    {
        std::string one;
        if (!ask_worker(conn, name, payload, one, std::chrono::seconds(10), 0))
            return 1;
        conn->write_buf = one.empty() || one.ends_with('\n') ? one : one + "\n";
        return one.starts_with("error") ? 1 : 0;
    }
    const size_t shards = std::max<size_t>(1, instance->get_shards());
    std::string all;
    bool found = false;
    for (size_t s = 0; s < shards; ++s)
    {
        std::string one;
        if (!ask_worker(conn, name, payload, one, std::chrono::seconds(10), s))
            return 1;
        if ((v == ml::verb::show || v == ml::verb::drop || v == ml::verb::forgive) && one.starts_with("error"))
            continue;
        found = true;
        if (v == ml::verb::flush || v == ml::verb::drop || v == ml::verb::forgive)
            continue;
        all += one;
        // Every shard's records and suppressed list are the same, and its show is of one message.
        if (v == ml::verb::show || v == ml::verb::dns || v == ml::verb::suppressed)
            break;
    }
    if (!found)
    {
        conn->write_buf = v == ml::verb::forgive ? "error: " + arg + " is not suppressed\n"
                                                 : "error: no message " + arg + " is queued\n";
        return 1;
    }
    conn->write_buf = v == ml::verb::flush || v == ml::verb::drop || v == ml::verb::forgive ? std::string() : all;
    return 0;
}

// A broker's commands: a publish goes to one shard, which hands it to the others; sessions, kicks and taps ask every
// shard, since each holds the sessions of the clients connected to it; retained messages are on all of them alike.
int daemon_handler::cmd_mqtt(ipc_connection* conn, const parsed_args& pa)
{
    namespace mq = socketley::mqtt;
    const std::string verb(pa.args[0]);
    if (pa.count < 2)
    {
        conn->write_buf = command_usage::line(verb);
        return 1;
    }
    const std::string_view name = pa.args[1];
    auto* instance = m_manager.get(name);
    if (!instance || instance->get_type() != runtime_mqtt)
    {
        conn->write_buf = "no mqtt runtime named " + std::string(name) + "\n";
        return 1;
    }
    if (instance->get_state() != runtime_running)
    {
        conn->write_buf = "runtime is not running: " + std::string(name) + "\n";
        return 1;
    }
    const auto it = m_proxy_workers.find(std::string(name));
    const size_t shards = it == m_proxy_workers.end() ? 0 : it->second.size();
    if (shards == 0)
    {
        conn->write_buf = "could not reach the worker holding " + std::string(name) + "\n";
        return 2;
    }
    // One shard's answer, or false with the reason already in the write buffer.
    const auto ask = [&](size_t shard, std::string_view payload, std::string& reply) {
        if (!ask_worker(conn, name, payload, reply, std::chrono::milliseconds(4000), shard))
            return false;
        if (reply.starts_with("error: "))
        {
            conn->write_buf = reply.substr(7) + "\n";
            return false;
        }
        return true;
    };
    // A JSON array of every shard's answer, one element a line.
    const auto merged = [&](std::string_view payload) {
        std::string out = "[";
        bool any = false;
        for (size_t j = 0; j < shards; ++j)
        {
            std::string reply;
            if (!ask(j, payload, reply))
                return false;
            if (reply.size() < 2 || reply.front() != '[' || reply.back() != ']')
            {
                conn->write_buf = "the worker holding " + std::string(name) + " gave no list\n";
                return false;
            }
            std::string_view body(reply);
            body = body.substr(1, body.size() - 2);
            // Each element is an object, cut out at the brace that closes it outside a string.
            size_t depth = 0, from = 0;
            bool in_str = false, esc = false;
            for (size_t k = 0; k < body.size(); ++k)
            {
                const char c = body[k];
                if (in_str)
                {
                    if (esc)
                        esc = false;
                    else if (c == '\\')
                        esc = true;
                    else if (c == '"')
                        in_str = false;
                    continue;
                }
                if (c == '"')
                    in_str = true;
                else if (c == '{' && depth++ == 0)
                    from = k;
                else if (c == '}' && depth > 0 && --depth == 0)
                {
                    out += any ? ",\n" : "\n";
                    any = true;
                    out.append(body.substr(from, k + 1 - from));
                }
            }
        }
        conn->write_buf = out + (any ? "\n]\n" : "]\n");
        return true;
    };

    if (verb == "mqtt-pub")
    {
        // mqtt-pub <rt> [--qos n] [--retain] <topic> [payload...]
        uint8_t qos = 0;
        bool retain = false;
        size_t i = 2;
        for (; i < pa.count; ++i)
        {
            if (pa.args[i] == "--retain")
                retain = true;
            else if (pa.args[i] == "--qos" && i + 1 < pa.count && pa.args[i + 1].size() == 1 &&
                     pa.args[i + 1][0] >= '0' && pa.args[i + 1][0] <= '2')
                qos = static_cast<uint8_t>(pa.args[++i][0] - '0');
            else if (pa.args[i].starts_with("--"))
            {
                conn->write_buf = command_usage::line(verb);
                return 1;
            }
            else
                break;
        }
        if (i >= pa.count)
        {
            conn->write_buf = command_usage::line(verb);
            return 1;
        }
        const std::string_view topic = pa.args[i];
        // The CLI sends the payload in base64, which no space, tab or byte of it can change on the way.
        std::string payload(pa.rest_from(i + 1));
        if (i + 1 < pa.count && pa.args[i + 1] == "--base64")
        {
            payload.clear();
            if (i + 3 < pa.count || (i + 2 < pa.count && !socketley::base64::decode(pa.args[i + 2], payload)))
            {
                conn->write_buf = "--base64 takes one payload in base64\n";
                return 1;
            }
        }
        std::string reply;
        if (!ask(0, mq::command_publish(topic, payload, qos, retain), reply))
            return 1;
        return 0;
    }
    if (verb == "mqtt-sessions")
        return merged(mq::command_text(mq::verb::sessions)) ? 0 : 1;
    if (verb == "mqtt-kick")
    {
        // mqtt-kick <rt> <client> [--end]
        const bool end = pa.count == 4 && pa.args[3] == "--end";
        if (pa.count < 3 || (pa.count == 4 && !end) || pa.count > 4)
        {
            conn->write_buf = command_usage::line(verb);
            return 1;
        }
        const std::string payload = mq::command_text(mq::verb::kick, pa.args[2], end);
        bool kicked = false;
        for (size_t j = 0; j < shards; ++j)
        {
            std::string reply;
            if (!ask_worker(conn, name, payload, reply, std::chrono::milliseconds(4000), j))
                return 2;
            kicked = kicked || reply == "kicked";
        }
        if (!kicked)
        {
            conn->write_buf = "no session of " + std::string(pa.args[2]) + "\n";
            return 1;
        }
        return 0;
    }
    if (verb == "mqtt-retained")
    {
        // mqtt-retained <rt> [filter] | --clear <topic>
        if (pa.count >= 3 && pa.args[2] == "--clear")
        {
            if (pa.count != 4)
            {
                conn->write_buf = command_usage::line(verb);
                return 1;
            }
            std::string reply;
            return ask(0, mq::command_text(mq::verb::clear, pa.args[3]), reply) ? 0 : 1;
        }
        if (pa.count > 3)
        {
            conn->write_buf = command_usage::line(verb);
            return 1;
        }
        std::string reply;
        if (!ask(0, mq::command_text(mq::verb::retained, pa.count == 3 ? pa.args[2] : std::string_view("#")), reply))
            return 1;
        conn->write_buf = reply + "\n";
        return 0;
    }
    if (verb == "mqtt-tap")
    {
        // mqtt-tap <rt> open <filter> | poll <id,...> | close <id,...>, one tap a shard.
        if (pa.count != 4 || (pa.args[2] != "open" && pa.args[2] != "poll" && pa.args[2] != "close"))
        {
            conn->write_buf = "usage: mqtt-tap <mqtt> open <filter> | poll <ids> | close <ids>\n";
            return 1;
        }
        if (pa.args[2] == "open")
        {
            std::string ids;
            for (size_t j = 0; j < shards; ++j)
            {
                std::string reply;
                if (!ask(j, mq::command_text(mq::verb::tap_open, pa.args[3]), reply))
                    return 1;
                ids += (j ? "," : "") + reply;
            }
            conn->write_buf = ids + "\n";
            return 0;
        }
        const bool poll = pa.args[2] == "poll";
        std::vector<std::string_view> ids;
        for (std::string_view rest = pa.args[3];;)
        {
            const size_t comma = rest.find(',');
            ids.push_back(rest.substr(0, comma));
            if (comma == std::string_view::npos)
                break;
            rest.remove_prefix(comma + 1);
        }
        if (ids.size() != shards)
        {
            conn->write_buf = "the tap was opened on another number of shards; open it again\n";
            return 1;
        }
        std::string out;
        for (size_t j = 0; j < shards; ++j)
        {
            std::string reply;
            if (!ask(j, mq::command_text(poll ? mq::verb::tap_poll : mq::verb::tap_close, ids[j]), reply))
                return 1;
            if (poll)
                out += reply;
        }
        conn->write_buf = out;
        return 0;
    }
    conn->write_buf = "unknown command\n";
    return 1;
}

// A backup of a db runtime into a file: started by the worker, which answers its number at once, and asked after by
// that number, so a database of any size never holds the daemon up waiting for it.
// A collection's documents as a query of the db's API finds them, answered as its JSON body, {"docs":[...]}.
int daemon_handler::cmd_db_query(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count != 3 && pa.count != 4)
    {
        conn->write_buf = command_usage::line("db-query");
        return 1;
    }
    const std::string_view name = pa.args[1];
    auto* instance = m_manager.get(name);
    if (!instance || instance->get_type() != runtime_db)
    {
        conn->write_buf = "no db runtime named " + std::string(name) + "\n";
        return 1;
    }
    if (instance->get_state() != runtime_running)
    {
        conn->write_buf = "runtime is not running: " + std::string(name) + "\n";
        return 1;
    }
    std::string payload(socketley::db::call_marker);
    payload += "{\"method\":\"POST\",\"path\":";
    socketley::json::quote_into(payload, "/c/" + std::string(pa.args[2]) + "/_query");
    payload += ",\"body\":" + (pa.count == 4 ? std::string(pa.args[3]) : std::string("{}")) + "}";
    std::string reply;
    if (!ask_worker(conn, name, payload, reply))
        return 2;
    socketley::db::jvalue v;
    const socketley::db::jvalue* status = nullptr;
    const socketley::db::jvalue* body = nullptr;
    if (!socketley::db::json_reader(reply).document(v) || !(status = socketley::db::member(v, "status")) ||
        !(body = socketley::db::member(v, "body")))
    {
        conn->write_buf = "the database's answer could not be read\n";
        return 2;
    }
    if (status->s != "200")
    {
        conn->write_buf = "error: " + status->s + " " + socketley::json::written(*body) + "\n";
        return 1;
    }
    conn->write_buf = socketley::json::written(*body) + "\n";
    return 0;
}

int daemon_handler::cmd_db_backup(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count != 3 && !(pa.count == 4 && pa.args[2] == "--status"))
    {
        conn->write_buf = command_usage::line("db-backup");
        return 1;
    }
    const std::string_view name = pa.args[1];
    auto* instance = m_manager.get(name);
    if (!instance || instance->get_type() != runtime_db)
    {
        conn->write_buf = "no db runtime named " + std::string(name) + "\n";
        return 1;
    }
    if (instance->get_state() != runtime_running)
    {
        conn->write_buf = "runtime is not running: " + std::string(name) + "\n";
        return 1;
    }
    std::string payload(socketley::db::call_marker);
    if (pa.count == 4)
        payload += "{\"backup_status\":" + std::string(pa.args[3]) + "}";
    else
    {
        if (pa.args[2].empty() || pa.args[2].front() != '/')
        {
            conn->write_buf = "the backup is written to an absolute path\n";
            return 1;
        }
        std::string quoted;
        socketley::json::quote_into(quoted, pa.args[2]);
        payload += "{\"backup\":" + quoted + "}";
    }
    std::string reply;
    if (!ask_worker(conn, name, payload, reply))
        return 2;
    socketley::db::jvalue v;
    if (!socketley::db::json_reader(reply).document(v))
    {
        conn->write_buf = "the database's answer could not be read\n";
        return 2;
    }
    const socketley::db::jvalue* status = socketley::db::member(v, "status");
    const socketley::db::jvalue* body = socketley::db::member(v, "body");
    const auto field = [&](std::string_view k) -> std::string {
        const socketley::db::jvalue* f = body ? socketley::db::member(*body, k) : nullptr;
        return !f ? std::string() : f->k == socketley::db::jvalue::kind::boolean ? (f->b ? "true" : "false") : f->s;
    };
    if (!status || (status->s != "200" && status->s != "202"))
    {
        conn->write_buf = field("message") + "\n";
        return 1;
    }
    // Lines the CLI reads: the job's number, then whether it is done and how it ended.
    if (pa.count == 3)
        conn->write_buf = "job " + field("job") + "\n";
    else if (field("done") != "true")
        conn->write_buf = "running\n";
    else if (field("ok") == "true")
        conn->write_buf = "done " + field("documents") + " " + field("file") + "\n";
    else
    {
        conn->write_buf = "failed: " + field("message") + "\n";
        return 2;
    }
    return 0;
}

// A db runtime's documents replaced by a backup's: the runtime stopped, its directory kept aside, the backup put in
// its place, and the runtime started again as it was.
int daemon_handler::cmd_db_restore(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count != 3)
    {
        conn->write_buf = command_usage::line("db-restore");
        return 1;
    }
    const std::string name(pa.args[1]);
    const std::string file(pa.args[2]);
    auto* instance = m_manager.get(name);
    if (!instance || instance->get_type() != runtime_db)
    {
        conn->write_buf = "no db runtime named " + name + "\n";
        return 1;
    }
    // Read whole before anything is touched: a file that is not a backup of a database changes nothing.
    std::string why;
    if (file.empty() || file.front() != '/' ||
        !socketley::db::seglog::scan_file(
            file,
            [&](uint32_t, uint64_t, std::string_view p) {
                std::vector<socketley::db::event> evs;
                return socketley::db::decode_record(p, evs);
            },
            false, why))
    {
        conn->write_buf = (why.empty() ? "the backup is read from an absolute path" : why) + "\n";
        return 1;
    }
    const std::string dir = db_data_dir(name);
    return across_restart(
        conn, "db-restore", name,
        [&]() -> int {
            std::error_code ec;
            const std::string aside = dir + ".before-restore";
            std::filesystem::remove_all(aside, ec);
            if (std::filesystem::exists(dir, ec))
                std::filesystem::rename(dir, aside, ec);
            if (ec)
            {
                conn->write_buf = "the documents could not be moved aside: " + ec.message() + "\n";
                return 2;
            }
            std::filesystem::create_directories(dir, ec);
            std::filesystem::copy_file(file, dir + "/seg-00000001.log", ec);
            if (ec)
            {
                conn->write_buf = "the backup could not be put in place: " + ec.message() + "; the documents before "
                                  "are in " + aside + "\n";
                return 2;
            }
            ::chmod(dir.c_str(), 0700);
            return 0;
        },
        false);
}

// A tunnel edge's agents: an invitation made, the agents listed, or one revoked, the edge's worker reading the file
// again within a second and cutting off an agent no longer in it.
int daemon_handler::cmd_tunnel(ipc_connection* conn, const parsed_args& pa)
{
    namespace tn = socketley::tunnel;
    if (pa.count < 3)
    {
        conn->write_buf = command_usage::line("tunnel");
        return 1;
    }
    const std::string edge(pa.args[1]);
    auto* inst = m_manager.get(edge);
    if (!inst || inst->get_type() != runtime_tunnel ||
        static_cast<tunnel_instance*>(inst)->get_mode() != tunnel_instance::mode::edge)
    {
        conn->write_buf = "no tunnel edge named " + edge + "\n";
        return 1;
    }
    const std::string_view action = pa.args[2];
    std::string why;
    if (action == "list" && pa.count == 3)
    {
        std::vector<tn::agent> agents;
        if (!tn::load_agents(edge, agents, why))
        {
            conn->write_buf = why + "\n";
            return 2;
        }
        std::string out;
        for (const auto& a : agents)
        {
            out += a.name + (a.joined ? "\tjoined\t" : "\tinvited\t");
            for (size_t i = 0; i < a.services.size(); ++i)
            {
                const tn::service& s = a.services[i];
                if (i)
                    out += ',';
                out += s.http ? s.name + (s.auth.empty() ? "" : "=" + s.auth)
                              : s.name + (s.bind.empty() ? "" : ":" + s.bind) + ":" + std::to_string(s.port);
            }
            out += "\n";
        }
        conn->write_buf = out;
        return 0;
    }
    if (action == "revoke" && pa.count == 4)
    {
        const std::string name(pa.args[3]);
        const bool ok = tn::update_agents(edge, [&](std::vector<tn::agent>& agents, std::string& w) {
            const size_t before = agents.size();
            std::erase_if(agents, [&](const tn::agent& a) { return a.name == name; });
            if (agents.size() == before)
            {
                w = "no agent named " + name;
                return false;
            }
            return true;
        }, why);
        conn->write_buf = ok ? std::string() : why + "\n";
        return ok ? 0 : 1;
    }
    if ((action == "invite" || action == "set") && pa.count >= 4)
    {
        const bool invite = action == "invite";
        tn::agent a;
        a.name = std::string(pa.args[3]);
        std::string http, tcp;
        for (size_t i = 4; i < pa.count; ++i)
        {
            if (pa.args[i] == "--http" && i + 1 < pa.count)
                http = std::string(pa.args[++i]);
            else if (pa.args[i] == "--tcp" && i + 1 < pa.count)
                tcp = std::string(pa.args[++i]);
            else
            {
                conn->write_buf = command_usage::line("tunnel");
                return 1;
            }
        }
        if (!tn::valid_name(a.name))
        {
            conn->write_buf = "an agent's name is lower-case letters, digits and -\n";
            return 1;
        }
        if (!tn::parse_services(http, tcp, a.services, why))
        {
            conn->write_buf = why + "\n";
            return 1;
        }
        for (const tn::service& s : a.services)
            for (const std::string_view method : tn::auth_methods(s.auth))
                if (const std::string bad = proxy_auth::spec_error(method); !bad.empty())
                {
                    conn->write_buf = "--http " + s.name + ": " + bad + "\n";
                    return 1;
                }
        // An invitation's secret goes to the agent once, in this answer; the file keeps its hash.
        const std::string secret = invite ? socketley::random_b64url(32) : std::string();
        a.secret_hash = invite ? tn::hash_secret(secret) : std::string();
        const bool ok = (!invite || !secret.empty()) &&
                        tn::update_agents(edge, [&](std::vector<tn::agent>& agents, std::string& w) {
            if (const std::string c = tn::clash(agents, a); !c.empty())
            {
                w = c;
                return false;
            }
            const auto it = std::find_if(agents.begin(), agents.end(), [&](const tn::agent& o) { return o.name == a.name; });
            // `set` changes what an agent offers and keeps its key; invited again, it takes a new secret instead.
            if (!invite)
            {
                if (it == agents.end())
                {
                    w = "no agent named " + a.name + "; invite it first";
                    return false;
                }
                it->services = a.services;
                return true;
            }
            if (it != agents.end())
                agents.erase(it);
            agents.push_back(a);
            return true;
        }, why);
        if (!ok)
        {
            conn->write_buf = (why.empty() ? std::string("no randomness for a secret") : why) + "\n";
            return 1;
        }
        conn->write_buf = invite ? a.name + "." + secret + "\n" : std::string();
        return 0;
    }
    conn->write_buf = command_usage::line("tunnel");
    return 1;
}

// An account of an idp runtime, changed or read in the worker that keeps them, which answers in text.
int daemon_handler::cmd_idp_user(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 3)
    {
        conn->write_buf = "usage: idp-user <idp> add|passwd|set|disable|enable|logout|remove|show|list|import ...\n";
        return 1;
    }
    const std::string_view name = pa.args[1];
    auto* instance = m_manager.get(name);
    if (!instance || instance->get_type() != runtime_idp)
    {
        conn->write_buf = "no idp runtime named " + std::string(name) + "\n";
        return 1;
    }
    if (instance->get_state() != runtime_running)
    {
        conn->write_buf = "runtime is not running: " + std::string(name) + "\n";
        return 1;
    }
    std::string reply;
    if (pa.args[2] == "import")
    {
        // The storage is asked by the daemon and its pages handed to the provider, one wait after the other: the
        // provider asking the storage itself would go through this daemon while it waits on the provider.
        if (pa.count != 4)
        {
            conn->write_buf = "usage: idp-user <idp> import <storage>\n";
            return 1;
        }
        const std::string_view storage = pa.args[3];
        auto* st = m_manager.get(storage);
        if (!st || st->get_type() != runtime_storage || st->get_state() != runtime_running)
        {
            conn->write_buf = "no running storage runtime named " + std::string(storage) + "\n";
            return 1;
        }
        size_t added = 0, kept = 0;
        std::string errors, after;
        for (;;)
        {
            socketley::storage_rpc::request q;
            q.kind = socketley::storage_rpc::op::users;
            q.start_after = after;
            std::string page;
            if (!ask_worker(conn, storage, socketley::storage_rpc::encode(q), page))
                return 2;
            socketley::storage_rpc::reply r;
            if (!socketley::storage_rpc::decode(page, socketley::storage_rpc::op::users, r) || !r.ok)
            {
                conn->write_buf = "the storage " + std::string(storage) + " gave no list of users: " + r.message + "\n";
                return 1;
            }
            if (!ask_worker(conn, name, std::string(socketley::idp::command_marker) + "import-data\n" + page, reply))
                return 2;
            if (reply.starts_with("error: "))
            {
                conn->write_buf = reply;
                return 1;
            }
            const size_t nl = reply.find('\n');
            const std::string counts = reply.substr(0, nl);
            added += std::strtoull(counts.c_str(), nullptr, 10);
            kept += std::strtoull(counts.c_str() + std::min(counts.size(), counts.find(' ') + 1), nullptr, 10);
            if (nl != std::string::npos)
                errors += reply.substr(nl + 1);
            if (!r.truncated || r.objects.empty())
                break;
            after = r.objects.back().key;
        }
        conn->write_buf = std::to_string(added) + " imported, " + std::to_string(kept) + " already here\n" + errors;
        return 0;
    }
    std::string payload(socketley::idp::command_marker);
    for (size_t i = 2; i < pa.count; ++i)
    {
        payload.append(pa.args[i]);
        if (i + 1 < pa.count)
            payload += '\n';
    }
    if (!ask_worker(conn, name, payload, reply))
        return 2;
    conn->write_buf = reply;
    if (!conn->write_buf.empty() && conn->write_buf.back() != '\n')
        conn->write_buf += '\n';
    return reply.starts_with("error: ") ? 1 : 0;
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
    const uint32_t action_hash = fnv1a_lower(action);

    if (type == runtime_cache && instance->is_out_of_process()
        && action_hash != fnv1a("send") && action_hash != fnv1a("memory"))
    {
        // The cache splits a text command at its spaces, and only a value, its last word, is taken as the rest.
        for (size_t i = 3; i < pa.count; ++i)
            if (pa.args[i].find(' ') != std::string_view::npos && (i == 3 || i + 1 < pa.count))
            {
                conn->write_buf = "'" + std::string(pa.args[i]) + "' has a space in it, which the cache's text "
                                  "commands read as two words; only a value, the last argument, may hold one\n";
                return 1;
            }
        return run_cache_action(conn, name, action, pa.rest_from(2));
    }

    if (type == runtime_cache && instance->is_out_of_process()
        && action_hash == fnv1a("memory"))
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
            if (pa.count < 5)
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
// Whether the command carries --restart, which every configuration command takes to mean "stop it if that is what
// this needs, apply, and start it again".
static bool asks_restart(const parsed_args& pa)
{
    for (size_t i = 2; i < pa.count; ++i)
        if (pa.args[i] == "--restart")
            return true;
    return false;
}

int daemon_handler::cmd_edit(ipc_connection* conn,
                             const parsed_args& pa, bool may_restart)
{
    if (may_restart && pa.count >= 3 && asks_restart(pa))
        return across_restart(conn, "edit", pa.args[1], [&] { return cmd_edit(conn, pa, false); }, false);
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

    if (instance->is_cluster_owned() && !m_cluster_internal)
    {
        std::vector<std::string> only{std::string(name)};
        withhold_cluster_names(only, "edit", conn);
        return 1;
    }

    runtime_type type = instance->get_type();
    bool is_running = instance->get_state() == runtime_running;

    // What the runtime's TLS configuration was before this edit, because the
    // flags only mean anything as a set and an incomplete one has to leave no
    // trace.
    // ─── Everything an edit can change, before the first flag is applied ────
    //
    // The parsers apply as they parse, so a refusal on the fourth flag left
    // the first three in the runtime.  Measured:
    //
    //   edit x --max-connections 3 --bogus-flag    -> "unknown flag", exit 1,
    //                                                 max_connections now 3
    //   edit x --rate-limit 9 --max-connections -1 -> "invalid value", exit 1,
    //                                                 rate_limit now 9
    //   edit c --max-connections 3 --maxmemory 100 -> refused, exit 1,
    //                                                 max_connections now 3
    //
    // The operator is told no and has no reason to look.  And it is not even
    // stored: save_runtime() is past every one of those returns, so `show`
    // reported the new value and the next boot read the old one.
    //
    // Three of these fields were already captured here, in three separate
    // blocks, each for its own refusal -- the TLS set, --shards with --listen,
    // and the server's four.  A fourth place needing the same thing is what
    // says it belongs in one.  A field missed from this list stays changed,
    // which is exactly what it did before, so the failure mode is the status
    // quo rather than something worse.
    struct edit_snapshot
    {
        bool        tls{false};
        std::string cert, key, ca;
        std::string mesh_ca, mesh_cert, mesh_key;
        uint32_t    shards{1};
        std::string listen;
        std::string bind;
        uint16_t    port{0};
        uint32_t    max_conns{0}, idle_timeout{0};
        size_t      write_buffer{0}, read_buffer{0};
        double      rate_limit{0.0}, global_rate_limit{0.0};
        std::string group, log_file, write_file;
        bool        bash_output{false}, bash_prefix{false}, bash_timestamp{false};
        server_mode mode{mode_inout};
        uint8_t     send_to{send_to_unset};
        bool        udp{false};
        std::string master_pw, cache_name, http_dir, origins;
        bool        http_cache{false};
        client_mode cmode{client_mode_inout};
        std::string target;
        tunnel_instance::mode tmode{tunnel_instance::mode::edge};
        std::string to, join, offers, forward, idp, idp_audience;
    } before;

    before.tls        = instance->get_tls();
    before.cert       = std::string(instance->get_cert_path());
    before.key        = std::string(instance->get_key_path());
    before.ca         = std::string(instance->get_ca_path());
    {
        std::string_view mca_v, mcert_v, mkey_v;
        instance->get_mesh_tls_paths(mca_v, mcert_v, mkey_v);
        before.mesh_ca   = std::string(mca_v);
        before.mesh_cert = std::string(mcert_v);
        before.mesh_key  = std::string(mkey_v);
    }
    before.shards     = instance->get_shards();
    before.listen     = std::string(instance->get_listen_path());
    before.bind       = std::string(instance->get_bind_address());
    before.port       = instance->get_port();
    before.max_conns  = instance->get_max_connections();
    before.idle_timeout      = instance->get_idle_timeout();
    before.write_buffer      = instance->get_write_buffer();
    before.read_buffer       = instance->get_read_buffer();
    before.rate_limit        = instance->get_rate_limit();
    before.global_rate_limit = instance->get_global_rate_limit();
    before.group      = std::string(instance->get_group());
    before.log_file   = std::string(instance->get_log_file());
    before.write_file = std::string(instance->get_write_file());
    before.bash_output    = instance->get_bash_output();
    before.bash_prefix    = instance->get_bash_prefix();
    before.bash_timestamp = instance->get_bash_timestamp();
    if (type == runtime_server)
    {
        const auto* srv_b = static_cast<const server_instance*>(instance);
        before.mode       = srv_b->get_mode();
        before.send_to    = srv_b->get_send_to();
        before.udp        = srv_b->is_udp();
        before.master_pw  = std::string(srv_b->get_master_pw());
        before.cache_name = std::string(srv_b->get_cache_name());
        before.http_dir   = srv_b->get_http_dir().string();
        before.http_cache = srv_b->get_http_cache();
        before.origins    = std::string(srv_b->get_origins());
    }
    else if (type == runtime_client)
    {
        const auto* cli_b = static_cast<const client_instance*>(instance);
        before.cmode  = cli_b->get_mode();
        before.udp    = cli_b->is_udp();
        before.target = std::string(cli_b->get_target());
    }
    else if (type == runtime_tunnel)
    {
        const auto* tn_b = static_cast<const tunnel_instance*>(instance);
        before.tmode        = tn_b->get_mode();
        before.to           = std::string(tn_b->get_to());
        before.join         = std::string(tn_b->get_join());
        before.offers       = std::string(tn_b->get_offers());
        before.forward      = std::string(tn_b->get_forward());
        before.idp          = std::string(tn_b->get_idp());
        before.idp_audience = std::string(tn_b->get_idp_audience());
    }

    const auto restore_edit = [&]
    {
        instance->set_tls(before.tls);
        instance->set_cert_path(before.cert);
        instance->set_key_path(before.key);
        instance->set_ca_path(before.ca);
        instance->set_shards(before.shards);
        instance->set_listen_path(before.listen);
        instance->set_bind_address(before.bind);
        instance->set_port(before.port);
        instance->set_max_connections(before.max_conns);
        instance->set_idle_timeout(before.idle_timeout);
        instance->set_write_buffer(before.write_buffer);
        instance->set_read_buffer(before.read_buffer);
        instance->set_rate_limit(before.rate_limit);
        instance->set_global_rate_limit(before.global_rate_limit);
        instance->set_group(before.group);
        instance->set_log_file(before.log_file);
        instance->set_write_file(before.write_file);
        instance->set_bash_output(before.bash_output);
        instance->set_bash_prefix(before.bash_prefix);
        instance->set_bash_timestamp(before.bash_timestamp);
        if (type == runtime_proxy)
        {
            auto* prx_r = static_cast<proxy_instance*>(instance);
            prx_r->set_mesh_client_ca(before.mesh_ca);
            prx_r->set_mesh_client_cert(before.mesh_cert);
            prx_r->set_mesh_client_key(before.mesh_key);
        }
        else if (type == runtime_server)
        {
            auto* srv_r = static_cast<server_instance*>(instance);
            srv_r->set_mode(before.mode);
            srv_r->set_send_to(before.send_to);
            srv_r->set_udp(before.udp);
            srv_r->set_master_pw(before.master_pw);
            srv_r->set_cache_name(before.cache_name);
            srv_r->set_http_dir(before.http_dir);
            srv_r->set_http_cache(before.http_cache);
            srv_r->set_origins(before.origins);
        }
        else if (type == runtime_client)
        {
            auto* cli_r = static_cast<client_instance*>(instance);
            cli_r->set_mode(before.cmode);
            cli_r->set_udp(before.udp);
            cli_r->set_target(before.target);
        }
        else if (type == runtime_tunnel)
        {
            auto* tn_r = static_cast<tunnel_instance*>(instance);
            tn_r->set_mode(before.tmode);
            tn_r->set_to(before.to);
            tn_r->set_join(before.join);
            tn_r->set_offers(before.offers);
            tn_r->set_forward(before.forward);
            tn_r->set_idp(before.idp);
            tn_r->set_idp_audience(before.idp_audience);
        }
    };

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
                        static_cast<proxy_instance*>(instance), pa, i, is_running);
                    break;
                case runtime_cache:
                    // There is no parse_cache_edit_flags, so cache flags fall
                    // through here with a message that sends the operator to
                    // `import` rather than reading as a typo.
                    result = -1;
                    break;
                case runtime_storage:
                case runtime_dns:
                case runtime_sync:
                case runtime_idp:
                case runtime_db:
                case runtime_mqtt:
                case runtime_mail:
                    // A storage, DNS, sync, idp, db, mqtt or mail runtime's
                    // own settings are applied by `import`, as a cache's are.
                    result = -1;
                    break;
                case runtime_tunnel:
                    // A tunnel reads its own settings when it starts, so a running one takes them through a restart.
                    if (is_running && runtime_schema::offered(pa.args[i], type))
                    {
                        restore_edit();
                        std::cout << pa.args[i] << " changes a tunnel when it starts: socketley edit " << name << " "
                                  << pa.args[i] << " ... --restart\n";
                        return 1;
                    }
                    result = parse_tunnel_flags(static_cast<tunnel_instance*>(instance), pa, i, name);
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
            // A flag `create` takes for this type and `edit` does not is named as one `import` changes, so the answer
            // does not read as a typo; -s and --test are what create does, not settings.
            const bool own_type = type == runtime_cache || type == runtime_storage || type == runtime_idp ||
                                  type == runtime_db || type == runtime_mqtt || type == runtime_mail;
            if (own_type && pa.hashes[i] != fnv1a("-s") && pa.hashes[i] != fnv1a("--test") &&
                runtime_schema::offered(pa.args[i], type))
            {
                restore_edit();
                // idp, db and mqtt read their own settings once, at start.
                const bool restart = type == runtime_idp || type == runtime_db || type == runtime_mqtt ||
                                     type == runtime_mail;
                std::cout << pa.args[i] << " cannot be changed with `edit`\n"
                          << (type == runtime_cache     ? "  A cache's"
                              : type == runtime_storage ? "  A storage runtime's"
                              : type == runtime_idp     ? "  An idp runtime's"
                              : type == runtime_mqtt    ? "  An mqtt runtime's"
                              : type == runtime_mail    ? "  A mail runtime's"
                                                        : "  A db runtime's")
                          << " own settings are applied by `import`:\n"
                             "    socketley show " << name
                          << " > cfg.json   # edit the field, then\n"
                             "    socketley import " << name << (restart ? " --restart" : "") << " < cfg.json\n";
                return 1;
            }

            restore_edit();
            std::cout << "unknown flag: " << pa.args[i] << "\n";
            return 1;
        }

        // A parser's own refusal -- a value out of range, a flag that does not
        // apply to this type -- which has already printed why.
        if (result > 0)
        {
            restore_edit();
            return result;
        }
    }

    entrance_cert_default(instance);
    mail_cert_default(m_manager, instance);
    if (const std::string msg = instance_tls_refusal(instance); !msg.empty())
    {
        restore_edit();
        std::cout << msg;
        return 1;
    }

    if (const std::string msg = names_refusal(m_manager, *instance); !msg.empty())
    {
        restore_edit();
        std::cout << msg;
        return 1;
    }

    // The shard set, checked here because --listen and --shards are both
    // editable and either can complete an incompatible pair, and rolled back
    // the same way.
    if (const std::string msg = instance_shards_refusal(instance); !msg.empty())
    {
        restore_edit();
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
            restore_edit();
            std::cout << msg;
            return 1;
        }
    }

    if (m_persistence)
        m_persistence->save_runtime(instance);

    if (is_running)
        push_config_to_workers(name, instance);

    return 0;
}

// A runtime in a worker keeps its own copy of the configuration, and the object
// a command edited is the daemon's placeholder.  Without this the change was
// stored, reported by `show`, answered 0 -- and the process holding the port
// went on enforcing the value it was spawned with.
//
// Sent to every shard, because leaving one on the old limit is a runtime that
// enforces two.  What arrives is the whole configuration and not a delta; the
// worker takes the part a live runtime can take.
//
// A function rather than the block it used to be inside cmd_edit, because
// `import` is the other door onto the same fields -- and the one the
// interactive editor goes through -- and it had no push at all: send_config had
// exactly one call site in the tree.
// The operator's terminal to every worker serving this runtime, so what a
// client says reaches the session.  Once per worker and not per message: the
// descriptor is the channel, so notify_interactive() writes to the terminal
// with nothing of the daemon's on the path.
//
// Under --shards N every shard gets it and every shard writes to it, which is
// right -- each has its own clients -- and safe for the same reason -w's shared
// file is: one write per message, atomic at this size.
//
// This is the "attaches without restarting" half.  A session opened on a
// runtime whose worker is forked afterwards is granted in
// reconcile_proxy_workers(), beside send_start(), because the supervisor does
// not exist yet when the interactive block runs.
void daemon_handler::grant_interactive_to_workers(std::string_view name, int fd)
{
    if (fd < 0)
        return;
    auto it = m_proxy_workers.find(std::string(name));
    if (it == m_proxy_workers.end())
        return;
    for (auto& sup : it->second)
        if (sup)
            sup->grant_interactive(fd);
}

void daemon_handler::push_config_to_workers(std::string_view name,
                                            runtime_instance* instance)
{
    if (!m_persistence || !instance)
        return;

    auto it = m_proxy_workers.find(std::string(name));
    if (it == m_proxy_workers.end() || it->second.empty())
        return;

    const runtime_config cfg  = m_persistence->read_from_instance(instance);
    const std::string    json = m_persistence->format_json_pretty(cfg);
    for (auto& sup : it->second)
        sup->send_config(json);
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
        // A smarthost's password is shown as ***, which an import of what this printed puts back as it was.
        cfg.mail_relay = mail_redacted_relay(cfg.mail_relay);
        conn->write_buf += m_persistence->format_json_pretty(cfg);
    }
    return 0;
}

// Stop, apply, start -- in the daemon, as one command.
//
// Three commands are three round trips, and the runtime they travel through is stopped by the first: a dashboard is
// reached through an entrance proxy, so changing that proxy's shard count stopped it and the import and the start
// after it never arrived.  Measured on a live box: the entrance down, its configuration unchanged, and every site
// behind it with it.  `apply` is called rather than inlined because cmd_import has forty ways out, and every one of
// them returns here, to the start below.
int daemon_handler::across_restart(ipc_connection* conn, const char* verb, std::string_view name,
                                   const std::function<int()>& apply, bool always_start, bool interactive)
{
    const std::string was(name);
    std::string id;
    bool running = false;
    if (auto* inst = m_manager.get(was))
    {
        id.assign(inst->get_id());
        running = inst->get_state() == runtime_running;
        // The guard `stop`, `start` and `edit` each carry, here as well: the cluster placed this runtime, so going
        // around three refusals by doing all three at once is not what one command was for -- and the start below is
        // cmd_start, which refuses a cluster runtime, so this would stop it and leave it down.
        if (inst->is_cluster_owned() && !m_cluster_internal)
        {
            std::vector<std::string> only{was};
            withhold_cluster_names(only, verb, conn);
            // With nothing to apply it is a bounce in place, and there is a verb for that which the cluster allows.
            if (!apply)
                conn->write_buf += "  `socketley reload " + was + "` bounces it where it stands.\n";
            return 1;
        }
    }
    else
    {
        conn->write_buf = "runtime not found: " + was + "\n";
        return 1;
    }
    // What the state file says is left alone: a daemon that dies between the stop and the start brings the runtime up
    // again at its next start, where writing "was not running" would leave it down for good.
    if (running)
    {
        m_manager.stop(was, m_loop);
        reconcile_proxy_workers();
    }
    const int rc = apply ? apply() : 0;
    if (!running && !always_start)
        return rc;
    // The name it answers to now, which a document or a flag that renamed it changed; the id does not move.
    std::string now = was;
    if (!m_manager.get(now))
    {
        std::shared_lock lock(m_manager.mutex);
        for (const auto& [n, inst] : m_manager.list())
            if (inst && inst->get_id() == id)
            {
                now = n;
                break;
            }
    }
    // -i is honoured by cmd_start on the connection it arrives on, so it has to be on the line that gets there:
    // without it the daemon never registered the session and the CLI pumped a terminal nobody was listening to.
    const std::string line = "start " + now + (interactive ? " -i" : "");
    parsed_args sp;
    sp.parse(line);
    std::string said = std::move(conn->write_buf);
    conn->write_buf.clear();
    const int src = cmd_start(conn, sp);
    // What the change said comes first, since that is the answer to the command; the start's after it, which it has
    // only when the runtime is not running any more.
    conn->write_buf = said + conn->write_buf;
    // The start waits for a worker whose predecessor has not exited yet, so its answer goes out later -- and a
    // refusal from the change above travels as the floor of that one answer.  Returned as itself, it would be
    // replied to now and the parked verdict would reply again, which is two frames for one command.
    if (src == reply_parked)
    {
        if (rc != 0)
            conn->parked_floor = std::max(conn->parked_floor, rc);
        return src;
    }
    return rc != 0 ? rc : src;
}

int daemon_handler::cmd_restart(ipc_connection* conn, const parsed_args& pa)
{
    if (pa.count < 2)
    {
        conn->write_buf = command_usage::line("restart");
        return 1;
    }
    // -i is restart's own and belongs to the start at the end; everything else is edit's, so the two are separated
    // here and `edit` never sees a flag it would refuse by name.
    bool interactive = false;
    std::string flags;
    for (size_t i = 2; i < pa.count; ++i)
    {
        if (pa.args[i] == "-i")
        {
            interactive = true;
            continue;
        }
        flags += ' ';
        flags += pa.args[i];
    }
    if (flags.empty())
        return across_restart(conn, "restart", pa.args[1], nullptr, true, interactive);
    // The flags are edit's, read by edit's own parser: `restart x --shards 1` is `edit x --shards 1` with the stop
    // and the start around it, and a flag this daemon does not know is refused here by the one parser that knows.
    const std::string line = "edit " + std::string(pa.args[1]) + flags;
    parsed_args ep;
    ep.parse(line);
    return across_restart(conn, "restart", pa.args[1], [&] { return cmd_edit(conn, ep, false); }, true, interactive);
}

// Everything after the name is the document -- minus --restart, which is the caller's own and not part of what is
// being imported, and which a caller may write on either side of it.
static std::string_view import_document(const parsed_args& pa)
{
    size_t first = 2, last = pa.count - 1;
    if (first <= last && pa.args[first] == "--restart")
        ++first;
    if (first <= last && pa.args[last] == "--restart")
        --last;
    if (first > last)
        return {};
    const char* b = pa.args[first].data();
    const char* e = pa.args[last].data() + pa.args[last].size();
    return std::string_view(b, static_cast<size_t>(e - b));
}

int daemon_handler::cmd_import(ipc_connection* conn, const parsed_args& pa, bool may_restart)
{
    if (may_restart && pa.count >= 3 && asks_restart(pa))
        return across_restart(conn, "import", pa.args[1], [&] { return cmd_import(conn, pa, false); }, false);

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

    // The same refusal `edit` gives, because this is the other door to the same configuration: the cluster placed
    // this runtime and declares what it is, so a document written here is undone at the next tick.
    if (instance->is_cluster_owned() && !m_cluster_internal)
    {
        std::vector<std::string> only{std::string(name)};
        withhold_cluster_names(only, "import", conn);
        return 1;
    }

    if (!m_persistence)
    {
        conn->write_buf = "state persistence not available\n";
        return 2;
    }

    std::string json_str(import_document(pa));
    runtime_config cfg;
    const bool named = m_persistence->parse_json_string(json_str, cfg, instance->get_type());
    std::string_view doc = json_str;
    while (!doc.empty() && std::isspace(static_cast<unsigned char>(doc.front()))) doc.remove_prefix(1);
    while (!doc.empty() && std::isspace(static_cast<unsigned char>(doc.back()))) doc.remove_suffix(1);
    // A document without "name" is about the runtime the command names, as edit's flags are.
    if (!doc.starts_with('{') || !doc.ends_with('}') || (!named && cfg.has("name")))
    {
        conn->write_buf = "invalid JSON\n";
        return 1;
    }
    if (!named)
        cfg.name = std::string(name);
    // The *** show writes for a smarthost's password is the password this runtime has.
    if (instance->get_type() == runtime_mail && cfg.mail_relay.find(":***@") != std::string::npos)
    {
        const std::string had(static_cast<const mail_instance*>(instance)->get_relay());
        if (mail_redacted_relay(had) == cfg.mail_relay)
            cfg.mail_relay = had;
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

    // The port re-read raw, for the reason the listen field above is: the
    // parser narrows it.  `cfg.port` is a uint16_t and parse_json_string fills
    // it with `static_cast<uint16_t>(json_get_int(...))`, so 70000 arrives as
    // 4464 and there is nothing left for anyone downstream to refuse -- the
    // runtime is configured for a port nobody asked for and `show` reports it
    // as though it had been typed.  The flag door has always refused the same
    // input: socketley::parse_whole() checks std::errc::result_out_of_range and prints
    // "invalid port number".
    //
    // The typed-extra-digit case is exactly what the interactive editor makes
    // likely, and that editor sends its buffer through here.
    if (cfg.has("port"))
    {
        const std::string raw = m_persistence->raw_field(json_str, "port");
        if (!raw.empty())
        {
            long long value = 0;
            const auto [ptr, ec] = std::from_chars(
                raw.data(), raw.data() + raw.size(), value);
            if (ec != std::errc{} || ptr != raw.data() + raw.size()
                || value < 0 || value > 65535)
            {
                conn->write_buf = "port: \"" + raw + "\" is not a port number "
                                  "(1 to 65535, or 0 for this runtime type's "
                                  "default)\n";
                return 1;
            }
        }
    }

    // The --auth judged as the flag judges it, so a typo is told here and not by every request refused.
    if (cfg.has("auth") && !cfg.proxy_auth.empty())
    {
        if (const std::string bad = proxy_auth::spec_error(cfg.proxy_auth); !bad.empty())
        {
            conn->write_buf = bad + "\n";
            return 1;
        }
    }

    // The address judged as --bind judges it, since a document is the other way in.
    if (cfg.has("bind") && !cfg.bind_address.empty())
    {
        in_addr a{};
        if (::inet_pton(AF_INET, cfg.bind_address.c_str(), &a) != 1)
        {
            conn->write_buf = "bind: \"" + cfg.bind_address + "\" is not an IPv4 address such as 127.0.0.1\n";
            return 1;
        }
        if (a.s_addr == htonl(INADDR_ANY))
            cfg.bind_address.clear();
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
    if (const std::string msg = type_manifest::missing_required_refusal(type, cfg.extra);
        cfg.has("extra") && !msg.empty())
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
        if (m_manager.get(cfg.name))
        {
            conn->write_buf = "rename failed: name already taken\n";
            return 1;
        }
        // What names it by its name would name nothing after, so a rename of a runtime others rely on is refused
        // with them named, rather than leaving them without their idp, storage or backend.
        std::string named_by;
        {
            std::shared_lock lock(m_manager.mutex);
            for (const auto& [other, inst] : m_manager.list())
            {
                if (!inst || other == old_name)
                    continue;
                for (const std::string& flag : naming_settings(m_persistence->read_from_instance(inst.get()), old_name))
                    named_by += "  " + std::string(other) + " " + flag + " " + old_name + "\n";
                // An edge's agents' services that ask visitors to sign in at it.
                std::vector<socketley::tunnel::agent> agents;
                std::string why;
                if (inst->get_type() == runtime_tunnel && socketley::tunnel::load_agents(other, agents, why))
                    for (const auto& a : agents)
                        for (const auto& sv : a.services)
                            for (const std::string_view m : socketley::tunnel::auth_methods(sv.auth))
                                if (m == "idp:" + old_name)
                                    named_by += "  " + std::string(other) + " agent " + a.name + " --http " + sv.name +
                                                "=" + sv.auth + "\n";
            }
        }
        if (!named_by.empty())
        {
            conn->write_buf = "rename refused: these name " + old_name + ", and would name nothing after it:\n" +
                              named_by + "  change them to another first\n";
            return 1;
        }
        // Renamed last, once nothing below can refuse the document, or a refusal left it renamed in memory alone.
        renamed = true;
    }

    // ─── Changes that need a restart ────────────────────────────────────────
    // Each of these asks cfg.has(key) first, because a field the document does
    // not mention is left alone -- the rule the page states for import and the
    // rule the apply below already follows: `if (has("port")) set_port(...)`.
    //
    // Without it these read the parser's DEFAULT as the operator's intent. A
    // partial document -- the shape import exists for -- carries port 0,
    // listen "", tls false, and a runtime running on any port was answered
    // "cannot change port while running" for a change nobody asked for.
    // Measured: {"name":"x","max_connections":42} against a running server on
    // 26978 was refused; the identical document on the same runtime stopped
    // was applied and left the port at 26978.
    if (is_running)
    {
        if (cfg.has("port") && cfg.port != instance->get_port())
        {
            conn->write_buf = "cannot change port while running\n";
            return 1;
        }
        // The listener's other spelling under the same rule, because a running
        // server is bound to the socket node it has and moving it would leave
        // that node for a teardown that never came.
        if (cfg.has("listen") && cfg.listen_path != std::string(instance->get_listen_path()))
        {
            conn->write_buf = "cannot change the listen socket while running\n";
            return 1;
        }
        if (cfg.has("bind") && cfg.bind_address != std::string(instance->get_bind_address()))
        {
            conn->write_buf = "cannot change the bind address while running\n";
            return 1;
        }
        // The same rule as the port above, because applying it to a running
        // proxy would retire workers out from under live connections.
        if (cfg.has("shards") && cfg.shards != instance->get_shards())
        {
            conn->write_buf = "cannot change the shard count while running\n";
            return 1;
        }
        if (cfg.has("tls") && cfg.tls != instance->get_tls())
        {
            conn->write_buf = "cannot change TLS while running\n";
            return 1;
        }
        // What the handshakes trust, and the proxy's backend certificate, are contexts built at start as TLS is.
        if ((cfg.has("ca_path") && cfg.ca_path != instance->get_ca_path()) ||
            (cfg.has("mesh_client_ca") && cfg.mesh_client_ca != inst_mca) ||
            (cfg.has("mesh_client_cert") && cfg.mesh_client_cert != inst_mcert) ||
            (cfg.has("mesh_client_key") && cfg.mesh_client_key != inst_mkey))
        {
            conn->write_buf = "cannot change the CA or a client certificate while running: its handshakes use what it "
                              "started with; import it with --restart\n";
            return 1;
        }
        if (type == runtime_server || type == runtime_client)
        {
            bool cur_udp = instance->is_udp();
            if (cfg.has("udp") && cfg.udp != cur_udp)
            {
                conn->write_buf = "cannot change protocol while running\n";
                return 1;
            }
        }
        if (type == runtime_client)
        {
            if (cfg.has("target") && cfg.target != std::string(instance->get_target()))
            {
                conn->write_buf = "cannot change target while running\n";
                return 1;
            }
        }
        if (type == runtime_proxy)
        {
            auto* prx = static_cast<proxy_instance*>(instance);
            if (cfg.has("protocol") && cfg.protocol != static_cast<uint8_t>(prx->get_protocol()))
            {
                conn->write_buf = "cannot change protocol while running\n";
                return 1;
            }
        }
        if (type == runtime_cache)
        {
            auto* cache = static_cast<cache_instance*>(instance);
            if (cfg.has("resp_forced") && cfg.resp_forced != cache->get_resp_forced())
            {
                conn->write_buf = "cannot change RESP mode while running\n";
                return 1;
            }
            // A running cluster has already published its map, so every client
            // holding it would keep sending keys to ports that had stopped
            // answering.
            if (cfg.has("cluster") && cfg.cluster != cache->get_cluster())
            {
                conn->write_buf = "cannot change cluster mode while running\n";
                return 1;
            }
            // Asked only when the document names it, as every check above is: an edit of one limit leaves it out.
            if (cfg.has("replicate_target") && cfg.replicate_target != std::string(cache->get_replicate_target()))
            {
                conn->write_buf = "cannot change replication while running\n";
                return 1;
            }
        }
        if (type == runtime_storage)
        {
            // The directory is what the worker opened at start, and moving it
            // under a serving runtime would strand every open object.
            auto* stg = static_cast<storage_instance*>(instance);
            if (cfg.has("dir") && cfg.storage_dir != std::string(stg->get_dir()))
            {
                conn->write_buf = "cannot change the storage directory while running\n";
                return 1;
            }
            if (cfg.has("anonymous") && cfg.storage_anonymous != stg->get_anonymous())
            {
                conn->write_buf = "cannot change anonymous access while running\n";
                return 1;
            }
            // The keys the running authenticator holds are those it read at start;
            // the credentials file is re-read by itself, so changing its contents
            // needs no import at all.
            if ((cfg.has("access_key") && cfg.storage_access_key != std::string(stg->get_access_key())) ||
                (cfg.has("secret_key") && cfg.storage_secret_key != std::string(stg->get_secret_key())) ||
                (cfg.has("credentials") && cfg.storage_credentials != std::string(stg->get_credentials_file())))
            {
                conn->write_buf = "cannot change the access key, secret key or credentials file while running; "
                                  "edit the credentials file, which is re-read when it changes, or stop and start\n";
                return 1;
            }
            // The master key the running workers hold is the one they read at start.
            if (cfg.has("sse_key_file") && cfg.storage_sse_key_file != std::string(stg->get_sse_key_file()))
            {
                conn->write_buf = "cannot change the SSE key file while running; stop, import, and start\n";
                return 1;
            }
            // The sync mode is each worker's store's from its start.
            if ((cfg.has("fsync") && cfg.storage_fsync != std::string(stg->get_fsync())) ||
                (cfg.has("fsync_interval") && cfg.storage_fsync_interval_secs != stg->get_fsync_interval_secs()))
            {
                conn->write_buf = "cannot change the sync mode while running; stop, import, and start\n";
                return 1;
            }
            // The website's domains likewise.
            if (cfg.has("website_domain") && cfg.storage_website_domain != std::string(stg->get_website_domain()))
            {
                conn->write_buf = "cannot change the website domain while running; stop, import, and start\n";
                return 1;
            }
            // The domains are parsed into each worker's run at start.
            if (cfg.has("domain") && cfg.storage_domain != std::string(stg->get_domain()))
            {
                conn->write_buf = "cannot change the domain while running; stop, import, and start\n";
                return 1;
            }
            // The targets the running workers deliver to are those they read at start.
            if (cfg.has("notify_targets") && cfg.storage_notify_targets != std::string(stg->get_notify_targets()))
            {
                conn->write_buf = "cannot change the notification targets file while running; stop, import, and start\n";
                return 1;
            }
            if (cfg.has("replication_targets") &&
                cfg.storage_replication_targets != std::string(stg->get_replication_targets()))
            {
                conn->write_buf = "cannot change the replication targets file while running; stop, import, and start\n";
                return 1;
            }
            if (cfg.has("tls_offloaded") && cfg.storage_tls_offloaded != std::string(stg->get_tls_offloaded()))
            {
                conn->write_buf = "cannot change --tls-offloaded while running; stop, import, and start\n";
                return 1;
            }
            if (cfg.has("federation") && cfg.storage_federation != std::string(stg->get_federation_file()))
            {
                conn->write_buf = "cannot change the federation file while running; stop, import, and start\n";
                return 1;
            }
            if (cfg.has("tiers") && cfg.storage_tiers != std::string(stg->get_tiers_file()))
            {
                conn->write_buf = "cannot change the tiers file while running; stop, import, and start\n";
                return 1;
            }
            if (cfg.has("nodes") && cfg.storage_nodes != std::string(stg->get_nodes_file()))
            {
                conn->write_buf = "cannot change the nodes file while running; stop, import, and start\n";
                return 1;
            }
        }
    }

    if (type == runtime_storage && cfg.has("dir") && cfg.storage_dir.empty())
    {
        conn->write_buf = "dir needs a directory: it is where the buckets live\n";
        return 1;
    }

    // ─── ONLY WHAT THE DOCUMENT NAMES ───────────────────────────────────────
    // A field the document leaves out keeps its current value rather than
    // being cleared, because applying every default meant `import c
    // '{"name":"c"}'` silently took a runtime's TLS away -- clearing is still
    // possible and now has to be written.
    const auto has = [&cfg](const char* key) { return cfg.has(key); };

    // The names the document gives, judged before anything is applied: put in place for the question and taken
    // back, so a refusal leaves the runtime as it was.
    {
        const std::string old_domains(instance->get_domains()), old_group(instance->get_group());
        std::string old_stg_domain, old_stg_website;
        auto* stg = type == runtime_storage ? static_cast<storage_instance*>(instance) : nullptr;
        if (stg)
        {
            old_stg_domain = std::string(stg->get_domain());
            old_stg_website = std::string(stg->get_website_domain());
            if (has("domain"))         stg->set_domain(cfg.storage_domain);
            if (has("website_domain")) stg->set_website_domain(cfg.storage_website_domain);
        }
        else if (has("domain"))
            instance->set_domains(cfg.domains);
        if (has("group"))
            instance->set_group(cfg.group);
        const std::string msg = names_refusal(m_manager, *instance);
        instance->set_domains(old_domains);
        instance->set_group(old_group);
        if (stg)
        {
            stg->set_domain(old_stg_domain);
            stg->set_website_domain(old_stg_website);
        }
        if (!msg.empty())
        {
            conn->write_buf = msg;
            return 1;
        }
    }

    // The same absolute-path rule the flag doors apply, because a document is
    // the other way in and a state file written before that rule existed is a
    // third.
    for (const auto& [key, flag, value] :
         { std::tuple<const char*, const char*, const std::string&>
               { "log_file",   "--log", cfg.log_file },
           std::tuple<const char*, const char*, const std::string&>
               { "write_file", "-w",    cfg.write_file } })
    {
        if (!has(key))
            continue;
        if (const std::string why = socketley::appended_path_refusal(flag, value);
            !why.empty())
        {
            conn->write_buf = why;
            return 1;
        }
    }
    // The flags a client does not have are refused here too, because import
    // does not go through the flag parser and a validation that guards one
    // entrance is not there.
    //
    // Five now, not three.  global_rate_limit caps the total across all
    // inbound connections and drain flushes their write queues -- neither is
    // read by any client code, and both were stored and reported by `show`
    // exactly as the first three were.
    if (type == runtime_client)
    {
        const char* offender = has("rate_limit")        ? "rate_limit"
                             : has("max_connections")   ? "max_connections"
                             : has("idle_timeout")      ? "idle_timeout"
                             : has("global_rate_limit") ? "global_rate_limit"
                             : has("drain")             ? "drain"
                             : nullptr;
        if (offender)
        {
            conn->write_buf = std::string("\"") + offender +
                  "\" does not apply to a client: it accepts no connections, so "
                  "there is nothing to limit, to time out or to flush. Remove the "
                  "field and import again.\n";
            return 1;
        }
    }

    // And the other direction, for the one field that describes a connection
    // this runtime MAKES.  reconnect is read in client_instance.cpp and
    // nowhere else, so on the other three it was a stored number with nothing
    // to act on it.
    if (type != runtime_client && has("reconnect") && cfg.reconnect >= 0)
    {
        conn->write_buf =
            "\"reconnect\" applies to a client: it re-dials a connection this "
            "runtime made, and a server, a proxy and a cache take connections "
            "rather than make them. Remove the field and import again.\n";
        return 1;
    }

    if (has("port"))              instance->set_port(cfg.port);
    if (has("listen"))            instance->set_listen_path(cfg.listen_path);
    if (has("bind"))              instance->set_bind_address(cfg.bind_address);
    if (has("domain") && type != runtime_storage) instance->set_domains(cfg.domains);
    if (has("log_file"))          instance->set_log_file(cfg.log_file);
    if (has("write_file"))        instance->set_write_file(cfg.write_file);
    if (has("bash_output"))       instance->set_bash_output(cfg.bash_output);
    if (has("bash_prefix"))       instance->set_bash_prefix(cfg.bash_prefix);
    if (has("bash_timestamp"))    instance->set_bash_timestamp(cfg.bash_timestamp);
    if (has("max_connections"))   instance->set_max_connections(cfg.max_connections);
    if (has("rate_limit"))        instance->set_rate_limit(cfg.rate_limit);
    if (has("global_rate_limit")) instance->set_global_rate_limit(cfg.global_rate_limit);
    if (has("idle_timeout"))      instance->set_idle_timeout(cfg.idle_timeout);
    if (has("write_buffer"))      instance->set_write_buffer(cfg.write_buffer);
    if (has("read_buffer"))       instance->set_read_buffer(cfg.read_buffer);
    if (has("drain"))             instance->set_drain(cfg.drain);
    if (has("reconnect"))         instance->set_reconnect(cfg.reconnect);
    if (has("tls"))               instance->set_tls(cfg.tls);
    if (has("cert_path"))         instance->set_cert_path(cfg.cert_path);
    if (has("key_path"))          instance->set_key_path(cfg.key_path);
    // As the flags take them, which also points TLS at the files the names' certificate is kept in; empty clears them.
    for (const auto& [key, value, email] : {std::tuple{"acme_domains", &cfg.acme_domains, false},
                                            std::tuple{"acme_email", &cfg.acme_email, true}})
    {
        if (!has(key))
            continue;
        if (value->empty())
        {
            if (email)
                instance->set_acme_email("");
            else
                instance->set_acme_domains("");
            continue;
        }
        if (std::string why = apply_acme(instance, *value, email); !why.empty())
        {
            conn->write_buf = why + "\n";
            return 1;
        }
    }
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

    // Its type's own fields by the document's keys, refused whole on an upstream that cannot be.
    if (std::string why; !apply_typed_config(*instance, cfg, /*by_presence=*/true, &why))
    {
        conn->write_buf = std::move(why);
        return 1;
    }
    // A server that reaches a cache and a proxy route through the manager this daemon holds.
    if (type == runtime_server && !cfg.cache_name.empty())
        static_cast<server_instance*>(instance)->set_runtime_manager(&m_manager);
    if (type == runtime_proxy)
        static_cast<proxy_instance*>(instance)->set_runtime_manager(&m_manager);

    if (renamed)
    {
        // A mail runtime's spool, keys and mailboxes' state are files named for it, moved with it.
        const runtime_instance* before = m_manager.get(old_name);
        const bool mail = before && before->get_type() == runtime_mail;
        if (!m_manager.rename(old_name, cfg.name))
        {
            conn->write_buf = "rename failed: name already taken\n";
            return 1;
        }
        if (std::string why; mail && !mail_rename_state(old_name, cfg.name, why))
            LOG_WARN(("mail " + cfg.name + ": its state stayed under " + old_name + ": " + why).c_str());
        instance = m_manager.get(cfg.name);
        // The children it took along name it on disk too.
        for (const auto& child : m_manager.get_children(cfg.name))
            if (auto* c = m_manager.get(child); c && !c->get_test_mode() && !c->is_lua_created())
                m_persistence->save_runtime(c);
        // What a sync carried goes with its name, or the renamed job would carry its whole directory again.
        if (instance && instance->get_type() == runtime_sync &&
            ::rename(sync_index_path(old_name).c_str(), sync_index_path(cfg.name).c_str()) != 0 && errno != ENOENT)
            LOG_WARN(("sync " + cfg.name + ": its index stayed under " + old_name + ": " + std::strerror(errno)).c_str());
        m_persistence->remove_runtime(old_name);
    }
    m_persistence->save_runtime(instance);

    // The same push `edit` does, because this is the same set of fields
    // arriving by the other door -- and the door the interactive editor uses,
    // so `socketley edit NAME` with no flags went through here and told the
    // worker nothing.
    if (instance->get_state() == runtime_running)
        push_config_to_workers(pa.args[1], instance);
    // A running mail runtime takes its limits at once and the rest of its settings at its next start.
    if (instance->get_type() == runtime_mail && instance->get_state() == runtime_running)
        conn->write_buf += cfg.name + ": its ports, domains, relay, keys and mailboxes change at its next start\n";

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
            if (inst->is_cluster_owned())
                conn->write_buf += "cluster:replica\n";

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
        // The rest of a start's questions, as `start` asks them.
        if (const std::string msg = instance_cache_persist_refusal(inst); !msg.empty())
        {
            conn->write_buf += std::string(n) + ": " + msg;
            ++refused;
            continue;
        }
        if (const std::string msg = instance_server_mode_refusal(inst); !msg.empty())
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
        else
        {
            conn->write_buf += refusal.empty() ? "failed to start: " + std::string(n) + "\n" : refusal;
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

        // The old workers were told to go a moment ago, so the new ones are forked as each exits, as for `start`.
        if (conn && any_spawn_waiting(restarted))
        {
            park_reply(conn, restarted, [this, restarted, refused](ipc_connection* c)
                       { return refused + await_started(c->write_buf, restarted, "reload") > 0 ? 1 : 0; });
            return reply_parked;
        }
        refused += await_started(conn->write_buf, restarted, "reload");
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
        if (pa.args[i] == "--name" || pa.args[i] == "-n")
        {
            // A token that is itself a flag is not the value: it is the next
            // flag, typed after one whose value was forgotten -- the rule
            // `daemon --name` applies in cli.cpp for the same reason.  Without
            // this the guard fell through to "unknown flag: --name", which
            // says the flag does not exist rather than that its value is
            // missing, and `--name -s` blamed the name and dropped the -s.
            if (i + 1 >= pa.count || pa.args[i + 1].starts_with('-'))
            {
                conn->write_buf = std::string(pa.args[i]) + " requires a value\n";
                return 1;
            }
            name = std::string(pa.args[++i]);
        }
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

    // Create a server-type placeholder, with the reason told apart from the
    // outcome as cmd_create does: `--name a..b` is bad input and exits 1.
    switch (m_manager.try_create(runtime_server, name))
    {
        case runtime_manager::create_result::ok:
            break;
        case runtime_manager::create_result::invalid_name:
            conn->write_buf = "invalid runtime name: " + name + "\n";
            return 1;
        case runtime_manager::create_result::name_taken:
            conn->write_buf = "runtime already exists: " + name + "\n";
            return 1;
        case runtime_manager::create_result::internal:
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
        if (!socketley::parse_whole(sv, port) || port == 0)
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
        else
        {
            // The branch cmd_add's own loop has and this one did not: an
            // unknown flag, and --pid or --owner typed with nothing after it,
            // fell out of the chain and the command went on to exit 0 -- so
            // `attach server x 80 --pid` made a runtime with pid 0, which is
            // the very thing the --pid check above was added to prevent.
            const bool needs_value = pa.args[i] == "--pid"
                                  || pa.args[i] == "--owner" || pa.args[i] == "-o";
            conn->write_buf = std::string(pa.args[i])
                            + (needs_value ? " requires a value\n"
                                           : " is not an attach flag\n");
            return 1;
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
            if (!owner_name.empty())
                existing->set_owner(owner_name);
            if (m_persistence)
                m_persistence->save_runtime(existing);
            return 0;
        }
        conn->write_buf = std::string("runtime already exists: ") + std::string(name) + "\n";
        return 1;
    }

    // The reason told apart from the outcome, the way cmd_create does it: a
    // name this daemon will not spell is bad input and exits 1, and exiting 2
    // for it told a script the daemon had broken.
    switch (m_manager.try_create(type, name))
    {
        case runtime_manager::create_result::ok:
            break;
        case runtime_manager::create_result::invalid_name:
            conn->write_buf = "invalid runtime name: " + std::string(name) + "\n";
            return 1;
        case runtime_manager::create_result::name_taken:
            conn->write_buf = "runtime already exists: " + std::string(name) + "\n";
            return 1;
        case runtime_manager::create_result::internal:
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
    // Rides the map's pushes, which come at every change the map has and at each health tick.
    publish_runtime_events();
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
        return socketley::settings::flag("SOCKETLEY_NO_PEER_LINKS", false);
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
    if (mine == m_proxy_workers.end() || theirs == m_proxy_workers.end() || theirs->second.empty())
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
        for (const auto& entry : m_manager.list())
            if (entry.first != gone)
                local.push_back(entry.first);
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
        bool parked = false;
        const bool ok = serve_map_request(q.op, q.name, q.config, err, parked);
        if (parked)
        {
            m_deferred_starts.push_back({{q.name}, [this, ticket = q.ticket, reply_fd = q.reply_fd,
                                                    name = q.name](bool abandoned)
            {
                std::string why = "the daemon is shutting down";
                const bool up = !abandoned && map_started(name, why);
                proxy_supervisor::answer_map_request(reply_fd, ticket, up, why);
                if (reply_fd >= 0)
                    ::close(reply_fd);
            }});
            continue;
        }

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
                                       std::string& err, bool& parked)
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
        // this work exists to remove. A sync, an idp, a db and an mqtt broker
        // are the exceptions: their work is done on a worker's own loop, which
        // only a worker turns.
        if (cfg.type == runtime_sync || cfg.type == runtime_idp || cfg.type == runtime_db ||
            cfg.type == runtime_mqtt || cfg.type == runtime_mail || cfg.type == runtime_tunnel)
            inst->mark_out_of_process();
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
        if (m_spawn_waiting.contains(name))
        {
            parked = true;
            return true;
        }
        return map_started(name, err);
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

bool daemon_handler::map_started(const std::string& name, std::string& err)
{
    // Looked up again, since a parked start is answered on a later turn than the one that started it.
    if (auto* inst = m_manager.get(name); inst && inst->is_out_of_process())
    {
        std::string wmsg;
        const auto  deadline = std::chrono::steady_clock::now() + worker_startup_bound;
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

    shard_stats::figures sum;
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

        any  = true;
        sum += s.f;

        // One shard's detail text passes through unchanged and several are
        // labelled, with each shard's own figures under `shard_` names,
        // because how the work is spread is a question the sum cannot answer.
        const size_t idx = static_cast<size_t>(&sup - it->second.data());
        if (it->second.size() > 1)
        {
            const shard_stats::figures sf = region ? region->at(static_cast<uint32_t>(idx)) : s.f;
            detail += "[shard " + std::to_string(idx) + "]\n";
            socketley::stats_text::put(detail, "shard_connections", sf.active_connections);
            socketley::stats_text::put(detail, "shard_total_connections", sf.total_connections);
            socketley::stats_text::put(detail, "shard_total_messages", sf.total_messages);
            socketley::stats_text::put(detail, "shard_bytes_in", sf.bytes_in);
            socketley::stats_text::put(detail, "shard_bytes_out", sf.bytes_out);
        }
        detail += s.detail;
    }

    if (!any)
        return;

    inst->m_stat_total_connections.store(sum.total_connections, std::memory_order_relaxed);
    inst->m_stat_total_messages.store(sum.total_messages, std::memory_order_relaxed);
    inst->m_stat_bytes_in.store(sum.bytes_in, std::memory_order_relaxed);
    inst->m_stat_bytes_out.store(sum.bytes_out, std::memory_order_relaxed);

    // Where an in-process runtime's would be, so stat_detail_snapshot() — which
    // the metrics endpoint already calls — is answered identically whichever
    // side the runtime is running on, and whether it is one process or four.
    inst->set_worker_stats(std::move(detail), sum.active_connections);
}

void daemon_handler::reconcile_proxy_workers()
{
    // Before a worker of a name is forked again, so a broker made again under it never reads the old one's state.
    forget_settled_snapshots();
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
        // Read before shutdown(), which is the last moment the placeholder is
        // certainly this supervisor's runtime.
        const auto* ph = sup->placeholder();
        const bool dumps = ph && ph->get_type() == runtime_cache &&
            !static_cast<const cache_instance*>(ph)->get_persistent().empty();
        const std::string runtime = ph ? std::string(ph->get_name()) : std::string{};
        sup->shutdown();
        // shutdown() reaps only a child that was already gone, so this is the
        // last moment anything knows the pid.
        if (const pid_t p = sup->release_pid(); p > 0)
        {
            m_orphan_workers.push_back({p, std::chrono::steady_clock::now(), false,
                std::chrono::seconds(dumps ? socketley::dump_exit_bound_sec : 5), runtime,
                sup->shard_index()});
            watch_exit(p);
        }
        else
            clear_clients_block(runtime, sup->shard_index());

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

        // A set asked for more shards than it has outlived a stop no reconcile
        // followed, since the count cannot be edited while running, and its
        // survivors map a client list sized for the old count, so it is forked
        // again whole.
        const bool must_grow = w != wanted.end() && !it->second.empty() &&
                               it->second.size() < w->second;

        if (w == wanted.end() || all_reaped || must_grow)
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
            {
                // Exclusively, and not under the shared lock this function
                // takes further up: the metrics thread reads this same region
                // in worker_figures() -> sum() while holding a SHARED lock,
                // and two shared holders exclude nothing.  sum() null-checks
                // the mapping once and then loads from it N times, so an unmap
                // landing in between is a SIGSEGV in the daemon on a thread
                // that was only being asked for a number.
                //
                // get() takes the shared lock itself, so the name is resolved
                // first and the exclusive lock covers the unmap alone -- the
                // mutex is not recursive.
                std::unique_lock stats_lock(m_manager.mutex);
                inst->shard_stats_table().close();
            }
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
        // block is cleared instead of the region being resized -- by
        // clear_clients_block() once its worker has exited, because until then
        // that worker still accepts and closes and is the block's writer.

        ++it;
    }

    // Children that should exist and do not — including the second, third and
    // fourth process of a runtime that already has its first.
    m_spawn_waiting.clear();
    for (const auto& [name, want_count] : wanted)
    {
        auto& shards = m_proxy_workers[name];
        if (shards.size() >= want_count)
            continue;

        // Every runtime type holds its ports, unix paths and files until its process exits, so a retired worker of
        // this runtime still running holds back the fork, which its exit watch or the health tick resumes.
        if (predecessor_running(name))
        {
            m_spawn_waiting.insert(name);
            if (shards.empty())
                m_proxy_workers.erase(name);
            continue;
        }

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
                // Width is fixed at creation, and a set that grows was retired
                // whole above, so no running shard still maps the old region.
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

            // A session that was already open when this child was forked: a
            // `start NAME -i`, whose interactive block runs BEFORE this
            // function makes the worker, and a runtime restarted under a live
            // session, whose old process took its copy of the descriptor away.
            // Either one would come back mute without this.
            for (const auto& [cfd, c] : m_clients)
            {
                if (!c || !c->interactive || c->interactive_name != name)
                    continue;
                for (auto* s : forked)
                    s->grant_interactive(cfd);
            }
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
            // whose every reader has gone.  The placeholder's reader first,
            // under the lock the reap above takes, or it reads a region
            // nobody publishes into and a later start attaches no new one.
            if (auto* inst = m_manager.get(name))
            {
                std::unique_lock stats_lock(m_manager.mutex);
                inst->shard_stats_table().close();
            }
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
        const std::string framed = socketley::one_command(command);

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
        {
            // ─── EVERY SHARD THAT WAS FORKED, WHICH IS NOT EVERY SHARD ──────
            // The loop above asks it->second, the supervisors that exist.  A
            // fork that fails on the third of eight leaves the first two
            // serving, breaks out of the spawn loop and marks the runtime
            // failed -- and all of that was invisible here, because two
            // supervisors answering "serving" is a clean verdict.  `start`
            // returned 0 with nothing on the terminal, `ls` read Failed, and
            // the state file kept was_running:true, so the next daemon start
            // tried the same partial runtime again.
            //
            // The full failure has been reported since the top of this
            // function; this is the half of it that had nobody.
            if (auto* inst = m_manager.get(name))
            {
                const uint32_t want = inst->get_shards();
                if (want > 1 && it->second.size() < want)
                {
                    out += "runtime ";
                    out += name;
                    out += " could not start: only ";
                    out += std::to_string(it->second.size());
                    out += " of ";
                    out += std::to_string(want);
                    out += " shards were started (the reason is in the daemon "
                           "log); the ones that came up are taken down on the "
                           "next reconcile\n";

                    // Same reasoning as the refused branch: a runtime that did
                    // not come up whole must not be restored as running.
                    if (m_persistence)
                        m_persistence->set_was_running(name, false);
                    return 1;
                }
            }

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
        }

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

void daemon_handler::watch_exit(pid_t pid)
{
    // A process already gone, or a kernel without pidfds, is left to the health tick's reap.
    const int fd = static_cast<int>(::syscall(SYS_pidfd_open, pid, 0));
    if (fd < 0)
        return;
    exit_watch& w = m_exit_watches.emplace_back();
    w.pidfd = fd;
    w.req   = { this, nullptr, fd, 0, op_poll };
    if (!m_loop.submit_poll_add(fd, POLLIN, &w.req))
    {
        ::close(fd);
        m_exit_watches.pop_back();
    }
}

void daemon_handler::on_exit_watch(const io_request* req)
{
    const auto w = std::find_if(m_exit_watches.begin(), m_exit_watches.end(),
                                [req](const exit_watch& x) { return &x.req == req; });
    if (w == m_exit_watches.end())
        return;
    if (w->pidfd >= 0)
        m_loop.close_fd(w->pidfd);
    m_exit_watches.erase(w);
    forget_settled_snapshots();
    if (m_torn_down || (m_spawn_waiting.empty() && m_deferred_starts.empty()))
        return;

    // The reconcile reaps the exited worker in predecessor_running() and forks whatever no longer waits.
    reconcile_proxy_workers();
    finish_deferred_starts(false);
}

bool daemon_handler::predecessor_running(const std::string& name)
{
    bool running = false;
    for (auto it = m_orphan_workers.begin(); it != m_orphan_workers.end();)
    {
        if (it->runtime != name)
        {
            ++it;
            continue;
        }
        const pid_t r = ::waitpid(it->pid, nullptr, WNOHANG);
        if (r > 0 || (r < 0 && errno == ECHILD))
        {
            clear_clients_block(it->runtime, it->clients_block);
            it = m_orphan_workers.erase(it);
            continue;
        }
        running = true;
        ++it;
    }
    return running;
}

void daemon_handler::clear_clients_block(const std::string& runtime, uint32_t block)
{
    // Safe because nothing forks the runtime's next worker, which would adopt this block, while this one runs.
    if (const auto c = m_shard_client_regions.find(runtime);
        c != m_shard_client_regions.end() && block < c->second.count())
        c->second.clear_block(block);
}

bool daemon_handler::any_spawn_waiting(const std::vector<std::string>& names) const
{
    return std::any_of(names.begin(), names.end(),
                       [this](const std::string& n) { return m_spawn_waiting.contains(n); });
}

void daemon_handler::finish_deferred_starts(bool abandoned)
{
    // Taken out first, because a finish waits on workers, which serves map requests that may defer more.
    std::vector<deferred_start> ready;
    for (auto it = m_deferred_starts.begin(); it != m_deferred_starts.end();)
    {
        if (abandoned || !any_spawn_waiting(it->names))
        {
            ready.push_back(std::move(*it));
            it = m_deferred_starts.erase(it);
        }
        else
            ++it;
    }
    for (auto& d : ready)
        d.finish(abandoned);
}

void daemon_handler::park_reply(ipc_connection* conn, std::vector<std::string> names,
                                std::function<int(ipc_connection*)> verdict)
{
    const int      fd     = conn->fd;
    const uint64_t serial = conn->serial;
    m_deferred_starts.push_back({std::move(names), [this, fd, serial, verdict = std::move(verdict)](bool abandoned)
    {
        auto it = m_clients.find(fd);
        if (abandoned || it == m_clients.end() || it->second->serial != serial)
            return;
        const int rc = verdict(it->second.get());

        // Found again, since the wait inside the verdict serves map requests that may change the client map.
        it = m_clients.find(fd);
        if (it == m_clients.end() || it->second->serial != serial)
            return;
        ipc_connection* c = it->second.get();
        append_response(c, std::max(rc, c->parked_floor));
        c->parked_floor = 0;
        serve_commands(it, true);
    }});
}

void daemon_handler::reap_orphan_workers()
{
    forget_settled_snapshots();
    if (m_orphan_workers.empty())
        return;

    const auto now = std::chrono::steady_clock::now();

    for (auto it = m_orphan_workers.begin(); it != m_orphan_workers.end();)
    {
        // ECHILD as well as a positive pid: if it is not ours any more there is
        // nothing left to wait for, and keeping the entry would mean signalling
        // a number the kernel is free to hand to somebody else.
        const pid_t r = ::waitpid(it->pid, nullptr, WNOHANG);
        if (r > 0 || (r < 0 && errno == ECHILD))
        {
            clear_clients_block(it->runtime, it->clients_block);
            it = m_orphan_workers.erase(it);
            continue;
        }

        if (!it->killed && now - it->signalled_at > it->grace)
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
        pid_t ret = waitpid(pid, nullptr, WNOHANG);
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
        // A restart refused, an address now taken, is said and the runtime marked failed, not left stopped silently.
        if (std::string refusal; !m_manager.start(name, m_loop, &refusal))  // fork+exec again
        {
            LOG_ERROR(("managed runtime " + std::string(name) + " could not be started again" +
                       (refusal.empty() ? std::string() : ": " + refusal)).c_str());
            inst->mark_failed();
            if (m_persistence)
                m_persistence->save_runtime(inst.get());
            m_managed_restarts.erase(std::string(name));
            return;
        }
        // The count `stats` prints, which this path never touched: a runtime
        // that had been restarting every two seconds reported 0 restarts.
        inst->note_restart();
        if (m_persistence)
            m_persistence->save_runtime(inst.get());
        return;  // restart one at a time per health check cycle
    }
}

// One key:value line per figure, the shape `stats` gives a runtime, so a
// script reads both the same way.
int daemon_handler::cmd_daemon_stats(ipc_connection* conn)
{
    if (!conn)
        return 0;
    const socketley::fast_lo_figures f = socketley::fast_lo_now();
    std::ostringstream out;
    out << "fast_lo:" << f.mode << '\n';
    if (!f.reason.empty())
        out << "fast_lo_reason:" << f.reason << '\n';
    if (f.mode != "off" && f.mode != "unavailable")
    {
        out << "fast_lo_sockets_shortcut:" << f.sockets_shortcut << '\n'
            << "fast_lo_sockets_tcp:" << f.sockets_tcp << '\n'
            << "fast_lo_entered:" << f.entered << '\n'
            << "fast_lo_tainted_bound:" << f.tainted_bound << '\n'
            << "fast_lo_tainted_unanswered:" << f.tainted_unanswered << '\n'
            << "fast_lo_tainted_budget:" << f.tainted_budget << '\n'
            << "fast_lo_tainted_peer_off:" << f.tainted_peer_off << '\n'
            << "fast_lo_held_bytes:" << f.held_bytes << '\n'
            << "fast_lo_budget_bytes:" << f.budget_bytes << '\n'
            << "fast_lo_pair_limit_bytes:" << f.pair_bytes << '\n'
            << "fast_lo_over_budget:" << (f.over_budget ? 1 : 0) << '\n';
    }
    conn->write_buf = out.str();
    return 0;
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

int daemon_handler::cmd_raft_status(ipc_connection* conn)
{
    if (!m_raft)
    {
        conn->write_buf = "raft is not enabled on this daemon (start it with socketley daemon --raft-listen <ip:port> ...)\n";
        return 1;
    }
    int code = 0;
    conn->write_buf = m_raft->status(code);
    return code;
}

void daemon_handler::set_raft(class raft_host* host)
{
    m_raft = host;
    if (!host)
        return;
    m_reconciler = std::make_unique<cluster_reconciler>(*this, m_manager, *host);
    host->set_on_tick([this] { m_reconciler->tick(); });
}

int daemon_handler::run_internal(const std::vector<std::string>& words, std::string& out, bool cluster_owned)
{
    if (words.empty() || words.size() > MAX_ARGS - 1)
    {
        out = "too many arguments\n";
        return 1;
    }
    parsed_args pa;
    for (const std::string& w : words)
    {
        pa.args[pa.count]   = w;
        pa.hashes[pa.count] = fnv1a(w);
        ++pa.count;
    }
    ipc_connection scratch{};
    scratch.fd = -1;
    const bool was_internal = m_cluster_internal;
    const bool was_creating = m_cluster_creating;
    m_cluster_internal = true;
    m_cluster_creating = cluster_owned;
    const int rc = process_parsed(&scratch, pa);
    m_cluster_internal = was_internal;
    m_cluster_creating = was_creating;
    out = std::move(scratch.write_buf);
    return rc;
}

std::string daemon_handler::worker_detail(const std::string& name) const
{
    auto it = m_proxy_workers.find(name);
    if (it == m_proxy_workers.end() || it->second.empty() || !it->second.front() || !it->second.front()->last_stats().seen)
        return {};
    return it->second.front()->last_stats().detail;
}

bool daemon_handler::send_replica_order(const std::string& name, std::string_view payload)
{
    auto it = m_proxy_workers.find(name);
    if (it == m_proxy_workers.end() || it->second.empty() || !it->second.front())
        return false;
    return it->second.front()->send_replica_order(payload);
}

size_t daemon_handler::withhold_cluster_names(std::vector<std::string>& names, const char* verb, ipc_connection* conn) const
{
    if (m_cluster_internal)
        return 0;
    size_t withheld = 0;
    std::erase_if(names, [&](const std::string& n)
    {
        auto* inst = m_manager.get(n);
        if (!inst || !inst->is_cluster_owned())
            return false;
        ++withheld;
        // The cluster runs it, so the way to end it is to tell the cluster, and the way to change it is to declare it again.
        conn->write_buf += n + " is a cluster runtime, placed here by the cluster: `" + verb + "` would be undone at the next tick.\n"
                           "  `socketley cluster remove " + n + "` ends it everywhere; `socketley cluster placement` shows where it runs.\n";
        return true;
    });
    return withheld;
}

namespace {

const char* raft_needed =
    "cluster runtimes need a Raft daemon: start it with socketley daemon --raft-listen <ip:port> "
    "and --raft-init or --raft-join\n";

// Proposes or forwards one command, and says why when it could not go anywhere.
int submit_cluster_command(raft_host& raft, const socketley::cluster::command& c, std::string& out)
{
    namespace cl = socketley::cluster;
    if (const std::string why = cl::refusal(c); !why.empty())
    {
        out = why + "\n";
        return 1;
    }
    if (const std::string why = cl::conflict(raft.cluster(), c); !why.empty())
    {
        out = why + "\n";
        return 1;
    }
    std::string err;
    if (!raft.submit(cl::encode(c), err))
    {
        out = err;
        return 2;
    }
    return 0;
}

}   // namespace

int daemon_handler::cmd_cluster_create(ipc_connection* conn, const parsed_args& pa)
{
    namespace cl = socketley::cluster;
    if (!m_raft)
    {
        conn->write_buf = raft_needed;
        return 1;
    }
    if (pa.count < 3)
    {
        conn->write_buf = "usage: cluster create <type> <name> [flags] [--replicas <n>]\n";
        return 1;
    }

    cl::command c;
    c.op          = cl::op::create;
    c.sp.replicas = 1;
    // Every word arrives quoted (the CLI's quote_arg), so a flag with a space in it is one argument here as on the command line.
    auto word = [&](size_t i, std::string& out) { return cl::unquote_arg(pa.args[i], out); };
    if (!word(1, c.sp.type) || !word(2, c.name))
    {
        conn->write_buf = "a word of the command is not correctly quoted\n";
        return 1;
    }
    for (size_t i = 3; i < pa.count; ++i)
    {
        std::string arg;
        if (!word(i, arg))
        {
            conn->write_buf = "a word of the command is not correctly quoted\n";
            return 1;
        }
        if (arg != "--replicas")
        {
            c.sp.args.push_back(std::move(arg));
            continue;
        }
        uint32_t n = 0;
        std::string count;
        if (i + 1 < pa.count)
            word(i + 1, count);
        const std::string_view v = count;
        const auto [end, ec] = std::from_chars(v.data(), v.data() + v.size(), n);
        if (v.empty() || ec != std::errc{} || end != v.data() + v.size())
        {
            conn->write_buf = "--replicas takes a count\n";
            return 1;
        }
        c.sp.replicas = n;
        ++i;
    }

    if (const std::string why = cl::refusal(c); !why.empty())
    {
        conn->write_buf = why + "\n";
        return 1;
    }
    if (const std::string why = cl::conflict(m_raft->cluster(), c); !why.empty())
    {
        conn->write_buf = why + "\n";
        return 1;
    }
    // A runtime of this name here would keep the replica out, so it is said now and not found at the first tick.
    if (m_manager.get(c.name))
    {
        conn->write_buf = "a local runtime named " + c.name + " exists on this node, and a cluster runtime cannot take its name\n";
        return 1;
    }
    // The flags are run through `create --test` as this node would run them, so a typo is refused here and not on every node at once.
    std::string out;
    std::vector<std::string> dry = {"create", c.sp.type, c.name};
    for (std::string& a : cl::expand_args(c.sp.args, m_raft->node_name(m_raft->self())))
        dry.push_back(std::move(a));
    dry.push_back("--test");
    if (const int rc = run_internal(dry, out, false); rc != 0)
    {
        conn->write_buf = out.empty() ? "the flags were refused\n" : out;
        return rc;
    }
    return submit_cluster_command(*m_raft, c, conn->write_buf);
}

int daemon_handler::cmd_cluster_remove(ipc_connection* conn, const parsed_args& pa)
{
    namespace cl = socketley::cluster;
    if (!m_raft)
    {
        conn->write_buf = raft_needed;
        return 1;
    }
    if (pa.count != 2)
    {
        conn->write_buf = "usage: cluster remove <name>\n";
        return 1;
    }
    cl::command c;
    c.op   = cl::op::remove;
    c.name = std::string(pa.args[1]);
    return submit_cluster_command(*m_raft, c, conn->write_buf);
}

int daemon_handler::cmd_cluster_scale(ipc_connection* conn, const parsed_args& pa)
{
    namespace cl = socketley::cluster;
    if (!m_raft)
    {
        conn->write_buf = raft_needed;
        return 1;
    }
    uint32_t n = 0;
    const std::string_view v = pa.count == 3 ? pa.args[2] : std::string_view{};
    const auto [end, ec] = std::from_chars(v.data(), v.data() + v.size(), n);
    if (pa.count != 3 || v.empty() || ec != std::errc{} || end != v.data() + v.size())
    {
        conn->write_buf = "usage: cluster scale <name> <replicas>\n";
        return 1;
    }
    cl::command c;
    c.op          = cl::op::scale;
    c.name        = std::string(pa.args[1]);
    c.sp.replicas = n;
    return submit_cluster_command(*m_raft, c, conn->write_buf);
}

// Whether this node has applied a runtime, silently, which is what the CLI polls to know its command has taken effect.
int daemon_handler::cmd_cluster_has(ipc_connection* conn, const parsed_args& pa)
{
    if (!m_raft)
    {
        conn->write_buf = raft_needed;
        return 1;
    }
    if (pa.count < 2 || pa.count > 3)
        return 1;
    const auto& specs = m_raft->cluster().specs;
    const auto it = specs.find(std::string(pa.args[1]));
    if (pa.count == 3 && pa.args[2] == "absent")
        return it == specs.end() ? 0 : 1;
    if (it == specs.end())
        return 1;
    if (pa.count == 3)
        return std::to_string(it->second.replicas) == pa.args[2] ? 0 : 1;
    return 0;
}

int daemon_handler::cmd_cluster_placement(ipc_connection* conn)
{
    if (!m_raft)
    {
        conn->write_buf = raft_needed;
        return 1;
    }
    conn->write_buf = m_raft->placement();
    if (m_reconciler && !m_reconciler->report().empty())
    {
        conn->write_buf += "\nreplicas on this node:\n";
        size_t w = 0;
        for (const auto& r : m_reconciler->report())
            w = std::max(w, r.name.size());
        for (const auto& r : m_reconciler->report())
            conn->write_buf += "  " + r.name + std::string(w - r.name.size() + 2, ' ') + r.state
                             + (r.detail.empty() ? "" : "  " + r.detail) + "\n";
    }
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

    // Read before start_cluster(), which opens with stop_cluster() and so
    // unpublishes from whatever this daemon is in now.
    const std::string old_dir = m_owned_cluster
        ? std::string(m_owned_cluster->get_cluster_dir()) : std::string();

    // A flag that cannot be honoured is refused with the reason named, loudly
    // enough to survive the exit code, and accepting --cluster while running
    // without it is never on offer.
    if (!start_cluster(m_daemon_name, cluster_dir))
    {
        const std::string why = m_cluster_error;

        // Put back the way a refused `daemon --name` puts the old name back,
        // and for the sentence that refusal carries: the membership this
        // daemon already held was never in dispute.
        if (!old_dir.empty() && start_cluster(m_daemon_name, old_dir))
        {
            conn->write_buf = "cluster mode not enabled: " + why + "\n"
                "  nothing was published into " + cluster_dir +
                "; this daemon is still a member of " + old_dir + ".\n";
            return 1;
        }

        conn->write_buf = "cluster mode not enabled: " + why + "\n"
            "  this daemon keeps serving, but it publishes nothing into "
            + cluster_dir + " and no peer can see it.\n";
        if (!old_dir.empty())
            conn->write_buf += "  and " + old_dir + " could not be reclaimed "
                               "either: " + m_cluster_error + "\n";
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

// Every SOCKETLEY_* setting as this daemon and what it starts see it: its value and where that came from.
int daemon_handler::cmd_settings(ipc_connection* conn, const parsed_args& pa)
{
    namespace st = socketley::settings;
    bool all = false, json = false;
    for (size_t i = 1; i < pa.count; ++i)
    {
        switch (pa.hashes[i])
        {
            case fnv1a("-a"):
            case fnv1a("--all"):  all  = true; break;
            case fnv1a("-j"):
            case fnv1a("--json"): json = true; break;
            default:
                conn->write_buf = "unknown argument: " + std::string(pa.args[i]) +
                                  "\n  usage: socketley settings [-a|--all] [--json|-j]\n";
                return 1;
        }
    }
    static constexpr const char* audiences[] = {"tuning", "test", "command", "bootstrap", "internal"};
    struct row
    {
        std::string name, value, from;
        const st::setting* s;
    };
    std::vector<row> rows;
    size_t wn = 7, wv = 5;
    for (const st::setting& s : st::table)
    {
        if (!all && s.who != st::audience::tuning)
            continue;
        const char* v = std::getenv(std::string(s.name).c_str());
        row r{st::config_name(s), v && *v ? v : std::string(s.fallback),
              !(v && *v) ? "default" : st::from_file(s).load() ? "config" : "environment", &s};
        wn = std::max(wn, r.name.size());
        wv = std::max(wv, std::min<size_t>(r.value.size(), 40));
        rows.push_back(std::move(r));
    }
    std::string out;
    if (json)
    {
        out = "[";
        for (const row& r : rows)
        {
            out += out.size() > 1 ? "," : "";
            out += "{\"name\":" + socketley::json::quote(r.name) + ",\"env\":" + socketley::json::quote(std::string(r.s->name)) +
                   ",\"value\":" + socketley::json::quote(r.value) + ",\"from\":\"" + r.from + "\",\"for\":\"" +
                   audiences[static_cast<int>(r.s->who)] + "\",\"meaning\":" + socketley::json::quote(std::string(r.s->meaning)) +
                   "}";
        }
        out += "]\n";
    }
    else
    {
        const auto pad = [](std::string t, size_t w) { return t.size() >= w ? t + "  " : t + std::string(w - t.size() + 2, ' '); };
        out = pad("SETTING", wn) + pad("VALUE", wv) + pad("FROM", 11) + (all ? pad("FOR", 9) : std::string()) + "MEANING\n";
        for (const row& r : rows)
        {
            std::string value = r.value.size() > 40 ? r.value.substr(0, 37) + "..." : r.value;
            out += pad(r.name, wn) + pad(value, wv) + pad(r.from, 11) +
                   (all ? pad(audiences[static_cast<int>(r.s->who)], 9) : std::string()) + std::string(r.s->meaning) + "\n";
        }
    }
    conn->write_buf = std::move(out);
    return 0;
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

bool daemon_handler::open_notifications(const std::string& webhook, const std::string& mail, const std::string& events,
                                        const std::string& state_dir, std::string& why)
{
    std::vector<socketley::notify_target> targets;
    m_alert_hook = !webhook.empty();
    m_alert_mail = !mail.empty();
    if (m_alert_mail)
    {
        // A mail runtime that mails every alert to its addresses, mail://<runtime>/<address>[,<address>...].
        std::vector<socketley::notify_target> one;
        if (!socketley::parse_notify_targets("alert-mail " + mail, one, why) || one.empty() ||
            one.front().k != socketley::notify_target::kind::mail)
        {
            why = "daemon.alert_mail is not mail://<runtime>/<address>: " + why;
            return false;
        }
        targets.push_back(std::move(one.front()));
        m_alert_out.set_runtimes(&m_manager, "daemon");
    }
    if (!webhook.empty())
    {
        socketley::notify_target t;
        t.name = "alerts";
        t.k    = socketley::notify_target::kind::webhook;
        if (!socketley::parse_http_url(webhook, t.http, why))
            return false;
        targets.push_back(std::move(t));
    }
    if (!events.empty())
    {
        // Every event is published under socketley/ on the broker, which may be made after the daemon starts: until
        // it runs, what is owed waits in the outbox.
        socketley::notify_target t;
        t.name    = "events";
        t.k       = socketley::notify_target::kind::mqtt;
        t.runtime = events;
        t.topic   = "socketley";
        targets.push_back(std::move(t));
        m_alert_out.set_runtimes(&m_manager, "daemon");
        m_events = true;
    }
    m_alert_out.set_targets(std::move(targets));
    if (!m_alert_box.attach(m_fio))
    {
        why = "the alerts' handoff to the loop cannot be waited for";
        return false;
    }
    // An alert is never staged with a change, so a start has nothing to look for.
    return m_alert_out.open(state_dir, ".notify", 0, [](std::string_view) { return true; }, why);
}

void daemon_handler::send_alert(std::string body)
{
    m_alert_box.post_done([this, b = std::move(body)]() mutable {
        if (m_alert_mail)
            m_alert_out.add("alert-mail", b);
        if (m_alert_hook)
            m_alert_out.add("alerts", std::move(b));
    });
}

void daemon_handler::send_event(std::string sub, std::string json)
{
    m_alert_box.post_done([this, s = std::move(sub), j = std::move(json)]() mutable
                          { m_alert_out.add("events", std::move(j), s, true); });
}

void daemon_handler::publish_runtime_events()
{
    if (!m_events)
        return;
    std::unordered_map<std::string, std::string> now;
    {
        std::shared_lock lock(m_manager.mutex);
        now.reserve(m_manager.list().size());
        for (const auto& [name, inst] : m_manager.list())
            now.emplace(name, "{\"name\":" + socketley::json::quote(name) + ",\"type\":" +
                                  socketley::json::quote(type_to_string(inst->get_type())) + ",\"state\":" +
                                  socketley::json::quote(state_to_string(inst->get_state())) +
                                  ",\"port\":" + std::to_string(inst->get_port()) + "}");
    }
    // Retained, so a subscriber that comes later reads how each runtime stands, and cleared for one that is gone.
    // A refused update leaves the old state recorded, so the next call sends it again.
    auto next = now;
    for (const auto& [name, json] : now)
        if (const auto it = m_event_states.find(name); it == m_event_states.end() || it->second != json)
            if (!m_alert_out.add("events", json, "runtimes/" + name + "/state", true))
            {
                if (it != m_event_states.end())
                    next[name] = it->second;
                else
                    next.erase(name);
            }
    for (const auto& [name, json] : m_event_states)
        if (!now.contains(name) && !m_alert_out.add("events", std::string(), "runtimes/" + name + "/state", true))
            next.emplace(name, json);
    m_event_states = std::move(next);
}
