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
#include "proxy_supervisor.h"

#include <unistd.h>
#include <cstring>
#include <charconv>
#include <sys/socket.h>
#include <sys/stat.h>
#include "../shared/name_resolver.h"
#include <iomanip>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <sys/wait.h>
#include "../shared/logging.h"

std::string daemon_handler::socket_path = "/tmp/socketley.sock";

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
                              inst->get_tls(), inst->get_cert_path(),
                              inst->get_key_path(), inst->get_ca_path(),
                              mesh_ca, mesh_cert, mesh_key,
                              inst->get_replication_target());
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
    m_manager.set_endpoint_sink([this](const endpoint_table& tbl)
                                { publish_endpoints_to_workers(tbl); });

    // And every published message, for the same reason: a worker's subscribers
    // are not reachable by calling into an instance, so the manager hands them
    // over here instead of walking a map it cannot find them in.
    m_manager.set_publish_sink([this](std::string_view cache_name,
                                      std::string_view channel,
                                      std::string_view message)
                               { publish_to_workers(cache_name, channel, message); });
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
    // daemon forks and execs a proxy worker for every runtime created with
    // --out-of-process.  Without the flag the worker inherits it — measured, as
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

    // Allow all users to connect (needed when daemon runs as socketley user via systemd)
    chmod(socket_path.c_str(), 0666);

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
    for (auto& [_, sup] : m_proxy_workers)
        sup->shutdown();
    m_proxy_workers.clear();

    // Nothing may call the sink once the workers are gone: it would encode a
    // table for an empty map, which is harmless, but the manager outlives this
    // handler and the lambda captures `this`.
    m_manager.set_endpoint_sink(nullptr);
    m_manager.set_publish_sink(nullptr);

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

    size_t pos;
    bool queued = false;
    while ((pos = conn->partial.find('\n')) != std::string::npos)
    {
        std::string line = conn->partial.substr(0, pos);
        conn->partial.erase(0, pos + 1);

        if (!line.empty() && line.back() == '\r')
            line.pop_back();

        conn->write_buf.clear();
        int exit_code = process_command(conn, line);
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
    parsed_args pa;
    pa.parse(line);

    if (pa.count == 0)
    {
        std::cout << "no command\n";
        return 1;
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

int daemon_handler::cmd_create(ipc_connection* conn, const parsed_args& pa)
{
    const cout_to_reply reply_guard(conn);

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

    if (!m_manager.create(type, name))
    {
        std::cout << "runtime already exists: " << name << "\n";
        return 1;
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

    // ─── One flag has to be known before the others are read ────────────────
    //
    // --lua is acted on the moment it is parsed, and what it does depends on
    // whether this runtime will live in a worker: an out-of-process placeholder
    // compiles the script and discards it, an in-process runtime loads and runs
    // it (see runtime_instance::load_lua_script).  Flags arrive in whatever
    // order the operator typed them, so `--lua x --out-of-process` would
    // otherwise have executed the script in the daemon before anyone knew it
    // belonged to a worker -- and `--out-of-process --lua x` would not.  A
    // create whose behaviour depends on argument order is a bug waiting for
    // someone to reorder a command line.
    //
    // Scanned rather than reordered: the flag takes no value, so finding it is
    // exact, and marking early is idempotent with the case below that marks it
    // again when the loop reaches it.
    if (type == runtime_proxy)
    {
        for (size_t i = 3; i < pa.count; ++i)
        {
            if (std::string_view(pa.args[i]) == "--out-of-process")
            {
                static_cast<proxy_instance*>(instance)->mark_out_of_process();
                break;
            }
        }
    }

    for (size_t i = 3; i < pa.count; ++i)
    {
        int result = parse_common_flags(instance, pa, i, autostart);
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
        reconcile_proxy_workers();

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
    // daemon's does, so nothing here is about --out-of-process.
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

            if (!m_manager.start(n, m_loop))
            {
                conn->write_buf += "failed to start: " + std::string(n) + "\n";
                ++failed;
                continue;
            }
            if (m_persistence)
                m_persistence->set_was_running(n, true);
            inst = m_manager.get(n);
        }

        if (want_interactive && inst)
        {
            // The proxy case was refused above, before anything was started.
            conn->interactive = true;
            conn->interactive_name = n;
            inst->add_interactive_fd(conn->fd);
        }
    }

    // Any proxy just moved into `running` with --out-of-process now needs its
    // child.  Doing it here rather than waiting for the health timer is what
    // makes `start` followed immediately by a request work.
    reconcile_proxy_workers();

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
        if (pa.hashes[i] == fnv1a("--format") && i + 1 < pa.count)
        {
            if (pa.hashes[i + 1] == fnv1a("json"))
                json_format = true;
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
            out << "{\"id\":\"" << instance->get_id()
                << "\",\"name\":\"" << name
                << "\",\"type\":\"" << type_to_string(instance->get_type())
                << "\",\"port\":" << port
                << ",\"status\":\"" << state_str
                << "\",\"connections\":" << instance->get_connection_count()
                << ",\"owner\":\"" << (owner.empty() ? "" : std::string(owner))
                << "\",\"group\":\"" << (group.empty() ? "" : std::string(group))
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
                << std::setw(6)  << instance->get_connection_count()
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
            if (col_conn)    col(std::to_string(instance->get_connection_count()));
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
        if (pa.hashes[i] == fnv1a("--format") && i + 1 < pa.count)
        {
            if (pa.hashes[i + 1] == fnv1a("json"))
                json_format = true;
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
            out << "{\"id\":\"" << instance->get_id()
                << "\",\"name\":\"" << name
                << "\",\"type\":\"" << type_to_string(instance->get_type())
                << "\",\"port\":" << port
                << ",\"status\":\"" << state_json(instance->get_state())
                << "\",\"uptime\":\""
                << (running ? format_uptime(instance->get_start_time()) : std::string())
                << "\",\"connections\":" << instance->get_connection_count()
                << ",\"owner\":\"" << (owner.empty() ? "" : std::string(owner))
                << "\",\"group\":\"" << (group.empty() ? "" : std::string(group))
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
                << std::setw(6)  << instance->get_connection_count()
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
            if (col_conn)    col(std::to_string(instance->get_connection_count()));
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
        << ' ' << getpid() << '\n';
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

int daemon_handler::cmd_send(const parsed_args& pa)
{
    if (pa.count < 3)
    {
        std::cout << "usage: send <name> <message>\n";
        return 1;
    }

    std::string_view name = pa.args[1];
    std::string_view message = pa.rest_from(2);

    auto* instance = m_manager.get(name);
    if (!instance)
    {
        std::cout << "runtime not found: " << name << "\n";
        return 1;
    }

    if (instance->get_state() != runtime_running)
    {
        std::cout << "runtime is not running: " << name << "\n";
        return 1;
    }

    switch (instance->get_type())
    {
        case runtime_server:
        {
            auto* srv = static_cast<server_instance*>(instance);
            if (srv->get_mode() != mode_in)
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
            std::cout << "send is only supported for server and client runtimes\n";
            return 1;
    }

    return 0;
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

int daemon_handler::cmd_edit(ipc_connection* conn, const parsed_args& pa)
{
    // Same reason as cmd_create: every refusal below, and every one the flag
    // parsers print, went to the daemon's stdout and never to the client.
    const cout_to_reply reply_guard(conn);

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
                    result = -1;
                    break;
            }
        }

        if (result == -1)
        {
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

    bool is_running = instance->get_state() == runtime_running;
    runtime_type type = instance->get_type();

    // Same gate as the create path: a config carrying TLS this build cannot
    // honour is rejected before anything is applied or written back to the
    // state file.  Note the check is on what the incoming JSON *sets* — a
    // config that omits the TLS fields is accepted, which is how an operator
    // clears them from a runtime restored out of an older state file (dump,
    // drop the fields, import).
    //
    // The replication target comes from the same document, not from the live
    // instance: this is the configuration that is about to take effect, and an
    // import is exactly how a cleartext replicating cache would otherwise be
    // handed a certificate one field at a time.  A document that drops
    // replicate_target drops the replication with it (set_replicate_target
    // below is called unconditionally), so the pair being judged here is the
    // pair that will exist afterwards.
    if (const std::string msg = tls_config_refusal(type,
                                                   cfg.tls, cfg.cert_path, cfg.key_path,
                                                   cfg.ca_path, cfg.mesh_client_ca,
                                                   cfg.mesh_client_cert, cfg.mesh_client_key,
                                                   cfg.replicate_target);
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

    // Apply common fields
    instance->set_port(cfg.port);
    instance->set_log_file(cfg.log_file);
    instance->set_write_file(cfg.write_file);
    instance->set_bash_output(cfg.bash_output);
    instance->set_bash_prefix(cfg.bash_prefix);
    instance->set_bash_timestamp(cfg.bash_timestamp);
    instance->set_max_connections(cfg.max_connections);
    instance->set_rate_limit(cfg.rate_limit);
    instance->set_global_rate_limit(cfg.global_rate_limit);
    instance->set_idle_timeout(cfg.idle_timeout);
    instance->set_drain(cfg.drain);
    instance->set_reconnect(cfg.reconnect);
    instance->set_tls(cfg.tls);
    instance->set_cert_path(cfg.cert_path);
    instance->set_key_path(cfg.key_path);
    instance->set_ca_path(cfg.ca_path);
    instance->set_target(cfg.target);
    instance->set_cache_name(cfg.cache_name);
    instance->set_group(cfg.group);

    // Lua script: reload if changed
    std::string cur_lua(instance->get_lua_script_path());
    if (cfg.lua_script != cur_lua)
    {
        if (!cfg.lua_script.empty())
        {
            if (!instance->load_lua_script(cfg.lua_script))
            {
                conn->write_buf = "could not load Lua script: " + cfg.lua_script + "\n";
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
            srv->set_mode(static_cast<server_mode>(cfg.mode));
            srv->set_udp(cfg.udp);
            if (!cfg.cache_name.empty())
                srv->set_runtime_manager(&m_manager);
            if (!cfg.master_pw.empty())
                srv->set_master_pw(cfg.master_pw);
            if (cfg.master_forward)
                srv->set_master_forward(true);
            srv->clear_upstream_targets();
            for (const auto& u : cfg.upstreams)
                srv->add_upstream_target(u);
            break;
        }
        case runtime_client:
        {
            auto* cli = static_cast<client_instance*>(instance);
            cli->set_mode(static_cast<client_mode>(cfg.mode));
            cli->set_udp(cfg.udp);
            break;
        }
        case runtime_proxy:
        {
            auto* prx = static_cast<proxy_instance*>(instance);
            prx->set_protocol(static_cast<proxy_protocol>(cfg.protocol));
            prx->set_strategy(static_cast<proxy_strategy>(cfg.strategy));
            prx->clear_backends();
            for (const auto& b : cfg.backends)
                prx->add_backend(b);
            prx->set_runtime_manager(&m_manager);
            // The gate above guarantees these three are empty, so this is the
            // clearing half of the escape hatch: without it a proxy restored
            // from a state file with mesh mTLS paths could never be emptied,
            // and would refuse to start forever.
            prx->set_mesh_client_ca(cfg.mesh_client_ca);
            prx->set_mesh_client_cert(cfg.mesh_client_cert);
            prx->set_mesh_client_key(cfg.mesh_client_key);
            break;
        }
        case runtime_cache:
        {
            auto* cache = static_cast<cache_instance*>(instance);
            cache->set_persistent(cfg.persistent_path);
            cache->set_mode(static_cast<cache_mode>(cfg.cache_mode));
            cache->set_resp_forced(cfg.resp_forced);
            cache->set_replicate_target(cfg.replicate_target);
            cache->set_max_memory(cfg.max_memory);
            cache->set_eviction(static_cast<eviction_policy>(cfg.eviction));
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
            if (const pid_t rpid = inst->get_pid(); rpid > 0)
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
        m_manager.stop(n, m_loop);
        if (m_manager.start(n, m_loop) && m_persistence)
            m_persistence->set_was_running(n, true);
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

    for (const auto& n : names)
    {
        auto* inst = m_manager.get(n);
        if (inst && !inst->get_lua_script_path().empty())
            inst->reload_lua_script();
        // Rebuild HTTP file cache on reload-lua (picks up new/changed files)
        if (inst && inst->get_type() == runtime_server)
        {
            auto* srv = static_cast<server_instance*>(inst);
            if (srv->get_http_cache() && !srv->get_http_dir().empty())
                srv->rebuild_http_cache();
        }
    }

    // A script is where a runtime's route declaration lives, so reloading one
    // can change what it says it will answer.  Without this the proxies in
    // front of it would go on enforcing the declaration from the previous
    // version of the file — the exact drift publishing exists to prevent, and
    // the worst kind, because the two copies came from the same script.
    m_manager.publish_endpoints();
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
            auto sv = pa.args[++i];
            std::from_chars(sv.data(), sv.data() + sv.size(), pid);
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

    const std::string payload = worker_proto::encode_endpoints(names, groups);
    for (auto& [_, sup] : m_proxy_workers)
        sup->send_endpoints(payload);
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
    for (auto& [_, sup] : m_proxy_workers)
        sup->send_publish(payload);
}

void daemon_handler::poll_proxy_workers()
{
    for (auto& [_, sup] : m_proxy_workers)
        sup->poll();
}

void daemon_handler::reconcile_proxy_workers()
{
    // What the runtime map says should be running out of process.
    std::vector<std::string> wanted;
    {
        std::shared_lock lock(m_manager.mutex);
        for (const auto& [name, inst] : m_manager.list())
        {
            if (inst->get_type() != runtime_proxy || !inst->is_out_of_process())
                continue;
            if (inst->get_state() == runtime_running)
                wanted.push_back(name);
        }
    }

    // Children whose runtime has stopped, been removed or renamed.  Taken down
    // before anything is started, so a rename that reuses a port does not have
    // two children bound to it at once.
    for (auto it = m_proxy_workers.begin(); it != m_proxy_workers.end();)
    {
        const bool still_wanted =
            std::find(wanted.begin(), wanted.end(), it->first) != wanted.end();
        if (still_wanted)
        {
            ++it;
            continue;
        }
        it->second->shutdown();
        it = m_proxy_workers.erase(it);
    }

    // Children that should exist and do not.
    for (const auto& name : wanted)
    {
        if (m_proxy_workers.count(name))
            continue;

        auto* inst = m_manager.get(name);
        if (!inst)
            continue;

        runtime_config cfg;
        if (m_persistence)
            cfg = m_persistence->read_from_instance(inst);
        else
            continue;   // nothing to describe the runtime with

        auto sup = std::make_unique<proxy_supervisor>(inst, std::string{});
        if (!sup->spawn(cfg))
        {
            LOG_ERROR("could not start out-of-process proxy worker");
            inst->mark_failed();
            continue;
        }
        sup->send_start();

        // The child forked after the last publish, so it has no table yet.
        m_proxy_workers.emplace(name, std::move(sup));
        m_manager.publish_endpoints();
    }
}

void daemon_handler::check_managed_health()
{
    // The children first: liveness, then whatever they have reported.  Both
    // before the managed-runtime sweep below, which can return early.
    for (auto& [worker_name, sup] : m_proxy_workers)
    {
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

    m_owned_cluster->stop();
    m_owned_cluster.reset();
    m_cluster = nullptr;
    m_manager.set_cluster_discovery(nullptr);
}

bool daemon_handler::start_cluster(const std::string& name, const std::string& dir)
{
    stop_cluster();

    m_cluster_want_dir = dir;

    auto cd = std::make_unique<cluster_discovery>(name, dir, socket_path, m_manager);
    cd->set_event_callback([this](const std::vector<cluster_event>& events) {
        m_manager.dispatch_cluster_events(events);
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
