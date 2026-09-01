#include "proxy_supervisor.h"

#include "../shared/peer_link.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <poll.h>

#include "../runtime/proxy/proxy_instance.h"
#include "../shared/event_loop.h"
#include "../shared/logging.h"
#include "../shared/runtime_instance.h"
#include "../shared/state_persistence.h"
#include "../shared/shard_target.h"
#include "../shared/worker_protocol.h"

namespace
{

// The descriptor the child finds its control socket on, fixed rather than
// passed in argv so its very first action can be a read.
constexpr int child_control_fd = 3;

// The shared aggregation table for a runtime that has one, at a fixed number
// both sides agree on, whose absence a worker reads as "not sharded" rather
// than as an error.
constexpr int child_shard_fd = 4;

// And the client-list region, at five for the reason four is four.
constexpr int child_clients_fd = 5;

// The map socket, separate from the control socket because a worker has to
// block for these answers, and tested rather than announced so a new worker
// under an old daemon degrades to its old refusals instead of hanging.
constexpr int child_map_fd = 6;

// And the shard mesh, one descriptor per sibling at slot j for shard j, so
// both sides do the same arithmetic and a child that finds none relays through
// the daemon.
// The grant channel, whose only cargo is the end of a link to another
// runtime's process; the control socket cannot carry one, because its reads
// are a standing recv and a recv with no control buffer drops the ancillary
// data a descriptor travels in.
constexpr int child_link_fd = 7;

constexpr int child_mesh_base = 8;

// A child that dies immediately and repeatedly is not fixed by forking it
// again, so after this many restarts inside the window the runtime is left
// `failed`.
constexpr unsigned restart_burst_limit  = 5;
constexpr auto     restart_burst_window = std::chrono::seconds(10);

std::string self_exe()
{
    char buf[4096];
    const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0)
        return {};
    buf[n] = '\0';
    return std::string(buf);
}

} // namespace

proxy_supervisor::proxy_supervisor(runtime_instance* placeholder, std::string exec_path)
    : m_placeholder(placeholder)
    , m_exec_path(std::move(exec_path))
{
    if (m_exec_path.empty())
        m_exec_path = self_exe();
}

proxy_supervisor::~proxy_supervisor()
{
    // A backstop for a supervisor destroyed without ever being retired, since
    // retire() gives up the placeholder and the channel while both are still
    // known to be alive.
    if (m_placeholder)
        m_placeholder->set_request_sink_override(nullptr);
    if (m_channel)
    {
        m_channel->drop_sink(this);
        m_channel->drop_origin(this);
    }
    shutdown();

    // After shutdown(), and giving the registration back is not what makes
    // this safe: a dropped completion still reads the owner token out of
    // m_poll_req, which is a member of the object being freed, so reaching
    // retire() first is what leaves nothing to be found.
    if (m_loop)
        m_loop->deregister_owner(this);
}

void proxy_supervisor::set_event_loop(event_loop* loop)
{
    m_loop = loop;
    if (m_loop)
        m_owner_token = m_loop->register_owner(this);
}

uint32_t proxy_supervisor::retire()
{
    // The three holders the destructor lists, given up at the moment they are
    // all still known to exist, because the destructor now runs whenever the
    // ring finishes and cmd_remove frees the placeholder a few statements
    // after retiring.
    if (m_placeholder)
    {
        m_placeholder->set_request_sink_override(nullptr);
        m_placeholder = nullptr;
    }
    if (m_channel)
    {
        m_channel->drop_sink(this);
        m_channel->drop_origin(this);
        m_channel = nullptr;
    }

    // All three handlers, not just the publish, because a retired supervisor
    // still has whatever its child sent sitting in m_in and ingest() can still
    // walk it.
    m_on_publish = nullptr;
    m_on_deliver = nullptr;
    m_on_send_ref = nullptr;
    m_on_route   = nullptr;
    m_on_stats   = nullptr;

    if (!m_loop)
        return 0;

    // Cancel the arm and let the descriptor go, because an arm nobody asked
    // back never reports and the count would never reach zero.
    close_control();

    event_loop* const loop = m_loop;
    const uint32_t    tok  = m_owner_token;

    // Cleared before the deregistration and never set again, which stops a
    // late arm putting this object back in the ring behind the quarantine's
    // back.
    m_loop        = nullptr;
    m_owner_token = 0;

    loop->deregister_owner(this);
    return tok;
}

void proxy_supervisor::arm_control_poll()
{
    if (!m_loop || m_control_fd < 0 || m_poll_armed)
        return;

    m_poll_mask  = POLLIN | (pending_out() ? POLLOUT : 0u);
    m_poll_req   = { this, nullptr, m_control_fd, 0, op_poll };
    m_poll_armed = m_loop->submit_poll_add(m_control_fd, m_poll_mask, &m_poll_req);

    // Not worth failing the runtime over, since the health tick still drains
    // this socket, but said out loud because that latency is two seconds.
    if (!m_poll_armed)
        LOG_WARN("proxy supervisor: could not arm the control socket; its "
                 "replies now wait for the health tick");
}

void proxy_supervisor::disarm_control_poll()
{
    if (!m_loop)
        return;

    // Cancel first and let the loop drop whatever still reports, or a
    // completion arriving after the close carries a token for an fd that may
    // belong to somebody else.
    if (m_poll_armed)
    {
        if (!m_loop->submit_poll_remove(&m_poll_req)) {}
        m_poll_armed = false;
    }
}

void proxy_supervisor::on_cqe(struct io_uring_cqe* cqe)
{
    // Which of the two descriptors reported, by the address of the request and
    // not the op type, since both are op_poll.
    if (static_cast<io_request*>(io_uring_cqe_get_data(cqe)) == &m_map_poll_req)
    {
        m_map_armed = false;
        poll_map();

        // Only if poll_map() did not close it, because re-arming on a worker's
        // EOF is a poll that reports readable for ever.
        arm_map_poll();
        return;
    }

    // Whatever the result this arm is spent, cleared before the drain so a
    // frame that writes back can re-arm rather than queue behind one that has
    // reported.
    m_poll_armed = false;
    m_poll_mask  = 0;

    // The backlog first, because the socket may have room now and a request
    // waiting in m_out is somebody's answer not yet asked for.
    flush_control();

    // Errors included: a poll that reports POLLHUP or an error is exactly the
    // case where the read below returns 0 and close_control() runs, which is
    // the death path this class already has.
    poll();

    arm_control_poll();
}

// Through the loop and not ::close(), because a descriptor the ring may still
// name is not the caller's to close -- and the immediacy shutdown() needs is
// still met, since the cancel's -ECANCELED lands on the next drain and SIGTERM
// follows on the next line.
void proxy_supervisor::close_control()
{
    // Here rather than at the eight call sites, because the three descriptors
    // have one lifetime between them -- though not the converse, since
    // poll_map() closes on its own EOF and leaves the control socket to report
    // it.
    close_map();
    close_link_chan();

    if (m_control_fd >= 0)
    {
        disarm_control_poll();
        if (m_loop)
            m_loop->close_fd(m_control_fd);
        else
            ::close(m_control_fd);
        m_control_fd = -1;

        // The outbound backlog dies with the socket it was addressed to, or it
        // is written to the next child ahead of that child's own config; m_in
        // deliberately does not go with it, because bytes read before the
        // child went away are complete frames still owed.
        m_out.clear();
        m_out_off = 0;
    }
}

// The same rule for the map socket, shorter because nothing is ever queued for
// it, and m_map_in goes with it since the only thing waiting on a partial
// request is the process that just died.
void proxy_supervisor::close_map()
{
    if (m_map_fd >= 0)
    {
        disarm_map_poll();
        if (m_loop)
            m_loop->close_fd(m_map_fd);
        else
            ::close(m_map_fd);
        m_map_fd = -1;
        m_map_in.clear();
    }
}

// The grant channel goes the way the map socket does, and for the same reason:
// a descriptor left over from a previous child would be written to under a new
// child's number.
void proxy_supervisor::close_link_chan()
{
    if (m_link_chan_fd >= 0)
    {
        // Never armed on the ring -- the daemon only ever writes here -- so
        // this is a close and not a withdrawal.
        ::close(m_link_chan_fd);
        m_link_chan_fd = -1;
    }
}

bool proxy_supervisor::grant_peer_link(std::string_view peer, int fd)
{
    if (m_link_chan_fd < 0)
        return false;
    if (!socketley::peer_link::grant(m_link_chan_fd, peer, fd))
    {
        LOG_WARN(("peer links: could not hand " + std::string(peer)
                  + " to a worker; its crossings keep relaying").c_str());
        return false;
    }
    m_granted[std::string(peer)] = std::chrono::steady_clock::now();
    return true;
}

bool proxy_supervisor::grant_suppressed(std::string_view peer)
{
    // A plain unordered_map, so the key is built rather than looked up
    // through a transparent hash this one line does not justify.
    const auto it = m_granted.find(std::string(peer));
    if (it == m_granted.end())
        return false;

    // Long enough that a burst of relayed crossings produces one grant, short
    // enough that a link which failed to arrive is retried while the operator
    // is still looking at it.
    constexpr auto window = std::chrono::seconds(2);
    if (std::chrono::steady_clock::now() - it->second < window)
        return true;

    m_granted.erase(it);
    return false;
}

void proxy_supervisor::arm_map_poll()
{
    if (!m_loop || m_map_fd < 0 || m_map_armed)
        return;

    m_map_poll_req = { this, nullptr, m_map_fd, 0, op_poll };
    m_map_armed    = m_loop->submit_poll_add(m_map_fd, POLLIN, &m_map_poll_req);

    // Louder than the control socket's equivalent, because there is no health
    // tick behind this one: nothing else drains this descriptor, so a refused
    // arm is not latency, it is a worker blocked until its own deadline.
    if (!m_map_armed)
        LOG_WARN("proxy supervisor: could not arm the map socket; this "
                 "worker's socketley.create/start/stop/remove will time out");
}

void proxy_supervisor::disarm_map_poll()
{
    if (!m_loop)
        return;

    if (m_map_armed)
    {
        if (!m_loop->submit_poll_remove(&m_map_poll_req)) {}
        m_map_armed = false;
    }
}

// Whatever the child has asked for, handed on to be answered later, because
// `socketley.remove` of this worker's own runtime destroys this object inside
// its own completion.
void proxy_supervisor::poll_map()
{
    if (m_map_fd < 0)
        return;

    // MSG_DONTWAIT rather than O_NONBLOCK on the descriptor, because a flag on
    // the file description is shared by every dup of it and the two ends are
    // used in opposite ways.
    char buf[4096];
    for (;;)
    {
        const ssize_t n = ::recv(m_map_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n > 0)
        {
            m_map_in.append(buf, static_cast<size_t>(n));
            continue;
        }
        if (n == 0)
        {
            // The child let go of its end, which happens on every worker exit
            // and is reported by the control socket's own EOF.
            close_map();
            return;
        }
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;
        close_map();
        return;
    }

    worker_proto::frame_type type{};
    uint16_t                 ver   = 0;
    std::string              payload;
    bool                     fatal = false;

    while (worker_proto::take_frame(m_map_in, type, ver, payload, fatal))
    {
        if (type != worker_proto::frame_type::map_req || !m_on_map)
            continue;   // a frame this build cannot serve is skipped, not fatal

        uint64_t    ticket = 0;
        std::string op, name, config;
        if (!worker_proto::decode_map_request(payload, ticket, op, name, config))
            continue;

        // The dup the handler owns and closes, taken here while the descriptor
        // is certainly still open rather than on a later turn when this object
        // may be gone.
        const int reply_fd = ::fcntl(m_map_fd, F_DUPFD_CLOEXEC, 3);
        if (reply_fd < 0)
        {
            // Out of descriptors, and answering on m_map_fd directly is still
            // safe because nothing has been deferred yet.
            answer_map_request(m_map_fd, ticket, false,
                               "the daemon is out of file descriptors");
            continue;
        }

        m_on_map(ticket, reply_fd, std::move(op), std::move(name),
                 std::move(config));
    }

    if (fatal)
    {
        LOG_ERROR("proxy supervisor: malformed map frame from a worker");
        m_map_in.clear();
        close_map();
    }
}

void proxy_supervisor::answer_map_request(int reply_fd, uint64_t ticket,
                                          bool ok, std::string_view err)
{
    if (reply_fd < 0)
        return;

    const std::string frame = worker_proto::frame(
        worker_proto::frame_type::map_rep,
        worker_proto::encode_map_reply(ticket, ok, err));

    // The send completes on its first attempt for any worker behaving as
    // workers behave, and the bound exists for one that writes requests and
    // never reads answers, which would otherwise stop the daemon's loop on its
    // behalf.
    static constexpr int reply_wait_ms = 250;

    size_t off = 0;
    while (off < frame.size())
    {
        const ssize_t n = ::send(reply_fd, frame.data() + off, frame.size() - off,
                                 MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n > 0)
        {
            off += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            struct pollfd pfd{reply_fd, POLLOUT, 0};
            if (::poll(&pfd, 1, reply_wait_ms) > 0 && (pfd.revents & POLLOUT))
                continue;
            LOG_WARN("proxy supervisor: a worker would not take its map reply");
            break;
        }

        // The worker is gone.  There is nobody left to tell.
        break;
    }
}

bool proxy_supervisor::spawn(const runtime_config& cfg)
{
    if (m_exec_path.empty())
    {
        LOG_ERROR("proxy supervisor: could not resolve own executable path");
        return false;
    }

    // The daemon's CPU set wherever this runtime asked for none of its own,
    // because a worker inherits the affinity mask in fact while its loop
    // believes otherwise.
    runtime_config effective = cfg;

    // Which of N this child is, the only field that differs between the N
    // frames, written into m_config_json so a restart replays the same index.
    effective.shard_index = m_shard_index;

    // Set here rather than carried over from the parsed config, because a
    // restart replays m_config_json and the ends this child was given have
    // been closed by then; a stale true would point it at its own descriptors.
    effective.mesh_wired = !m_mesh_fds.empty();

    if (m_loop)
    {
        if (effective.cpus.empty() && !m_loop->cpus().all)
            effective.cpus = m_loop->cpus().to_string();
    }

    // Keep the config so a restart can replay it without going back to disk,
    // which is the daemon's record for the child rather than for the operator.
    {
        state_persistence sp{std::filesystem::path{}};
        m_config_json = sp.format_json_pretty(effective);
    }

    // A fresh socketpair starts with an empty outbound buffer, or the first
    // thing the new child reads is frames addressed to the dead one.
    if (pending_out() != 0)
    {
        LOG_ERROR("proxy supervisor: outbound backlog survived into a new "
                  "worker's socket; dropping it");
        m_out.clear();
        m_out_off = 0;
    }

    int sv[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0)
    {
        LOG_ERROR("proxy supervisor: socketpair failed");
        return false;
    }

    // The control plane's own pair, whose failure is not a failure to spawn:
    // the worker keeps its refusals, which is a working proxy with four fewer
    // script calls.
    int mv[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, mv) < 0)
    {
        LOG_WARN("proxy supervisor: no map socket for this worker; its "
                 "socketley.create/start/stop/remove will be refused");
        mv[0] = mv[1] = -1;
    }

    // The grant channel, SEQPACKET so two grants cannot arrive as one read and
    // leave the second one's descriptor behind.  Its failure is not a failure
    // to spawn: this runtime's crossings relay through the daemon, which is
    // what every crossing did before links existed.
    int lv[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, lv) < 0)
    {
        LOG_WARN("proxy supervisor: no grant channel for this worker; its "
                 "crossings to other runtimes will relay through the daemon");
        lv[0] = lv[1] = -1;
    }

    // Whatever this class was still holding from a previous child, because a
    // leftover map descriptor would be armed on the ring under a new child's
    // number.
    close_map();
    close_link_chan();

    // A new child holds no links, so the record of who it has been introduced
    // to goes with the old one; keeping it would leave a restarted worker
    // relaying for ever, since the grant that would fix it is suppressed.
    m_granted.clear();

    const pid_t child = ::fork();
    if (child < 0)
    {
        ::close(sv[0]);
        ::close(sv[1]);
        if (mv[0] >= 0) ::close(mv[0]);
        if (mv[1] >= 0) ::close(mv[1]);
        if (lv[0] >= 0) ::close(lv[0]);
        if (lv[1] >= 0) ::close(lv[1]);
        LOG_ERROR("proxy supervisor: fork failed");
        return false;
    }

    if (child == 0)
    {
        // ── child ───────────────────────────────────────────────────────────
        // Exactly four descriptors are meant to reach the worker -- /dev/null,
        // the daemon's stdout and stderr, and the control socket -- with the
        // fix at every creation site rather than here, because a descriptor
        // inheritable for a moment is inheritable during exactly this
        // function.
        ::close(sv[0]);
        if (mv[0] >= 0)
            ::close(mv[0]);
        if (lv[0] >= 0)
            ::close(lv[0]);

        // dup2 destroys its destination, so a socketpair that came back
        // holding 4 is moved out of the way before either fixed number is
        // placed.
        if ((m_shard_region_fd >= 0 && sv[1] == child_shard_fd)
            || (m_shard_clients_fd >= 0 && sv[1] == child_clients_fd)
            || (mv[1] >= 0 && sv[1] == child_map_fd)
            || (lv[1] >= 0 && sv[1] == child_link_fd))
        {
            const int moved = ::fcntl(sv[1], F_DUPFD, 16);
            if (moved < 0)
                _exit(127);
            ::close(sv[1]);
            sv[1] = moved;
        }

        // The shared regions, whose MFD_CLOEXEC dup2 clears on the copy,
        // placed by the same three lines and each moved out of the way first
        // because a source sitting on the other's destination would be
        // destroyed by a placement that has not happened yet.
        int region_src  = m_shard_region_fd;
        int clients_src = m_shard_clients_fd;
        if (clients_src >= 0 && region_src == child_clients_fd)
        {
            region_src = ::fcntl(region_src, F_DUPFD, 16);
            if (region_src < 0) _exit(127);
        }
        if (region_src >= 0 && clients_src == child_shard_fd)
        {
            clients_src = ::fcntl(clients_src, F_DUPFD, 16);
            if (clients_src < 0) _exit(127);
        }

        const auto place = [](int src, int dst) {
            if (src < 0) return;
            if (src != dst)
            {
                if (::dup2(src, dst) < 0)
                    _exit(127);
            }
            else
            {
                const int fl = ::fcntl(src, F_GETFD, 0);
                if (fl >= 0)
                    if (::fcntl(src, F_SETFD, fl & ~FD_CLOEXEC) < 0) {}
            }
        };
        place(region_src,  child_shard_fd);
        place(clients_src, child_clients_fd);

        // The grant channel's source is moved with the mesh's rather than
        // after it, because the mesh block is placed first and a source still
        // sitting on one of its destinations would be destroyed by a
        // placement that has not happened yet.
        int link_src = lv[1];
        if (link_src >= 0
            && link_src <= child_mesh_base + static_cast<int>(m_mesh_fds.size()))
        {
            link_src = ::fcntl(link_src, F_DUPFD, 128);
            if (link_src < 0)
                _exit(127);
        }

        // The mesh is a block rather than two descriptors, so every source is
        // moved above the whole destination block first -- one rule instead of
        // a case analysis that grows as N**2.
        for (size_t j = 0; j < m_mesh_fds.size(); ++j)
        {
            if (m_mesh_fds[j] < 0)
                continue;
            if (m_mesh_fds[j] >= child_mesh_base
                && m_mesh_fds[j] < child_mesh_base + static_cast<int>(m_mesh_fds.size()))
            {
                const int moved = ::fcntl(m_mesh_fds[j], F_DUPFD, 128);
                if (moved < 0)
                    _exit(127);
                m_mesh_fds[j] = moved;
            }
        }
        for (size_t j = 0; j < m_mesh_fds.size(); ++j)
            place(m_mesh_fds[j], child_mesh_base + static_cast<int>(j));

        // Below the mesh block and above the map, so neither placement can
        // reach it.
        place(link_src, child_link_fd);

        // The map socket is placed last but one, because a source already on 6
        // belongs to a placement that has happened, and the control socket
        // stays last as the descriptor whose loss cannot be recovered from.
        int map_src = mv[1];
        if (map_src >= 0 && map_src <= child_mesh_base + static_cast<int>(m_mesh_fds.size()))
        {
            map_src = ::fcntl(map_src, F_DUPFD, 128);
            if (map_src < 0)
                _exit(127);
        }
        place(map_src, child_map_fd);

        if (sv[1] != child_control_fd)
        {
            if (::dup2(sv[1], child_control_fd) < 0)
                _exit(127);
            ::close(sv[1]);
        }
        else
        {
            const int fl = ::fcntl(sv[1], F_GETFD, 0);
            if (fl >= 0)
                if (::fcntl(sv[1], F_SETFD, fl & ~FD_CLOEXEC) < 0) {}
        }

        // Its own session, so a Ctrl-C in the terminal that started the daemon
        // does not reach the worker before the daemon has stopped it properly.
        ::setsid();

        const int devnull = ::open("/dev/null", O_RDWR);
        if (devnull >= 0)
        {
            if (::dup2(devnull, STDIN_FILENO) < 0) {}
            if (devnull > 2)
                ::close(devnull);
        }

        const char* path = m_exec_path.c_str();
        ::execl(path, path, "proxy-worker", static_cast<char*>(nullptr));
        _exit(127);
    }

    // ── parent ──────────────────────────────────────────────────────────────
    ::close(sv[1]);
    if (mv[1] >= 0)
        ::close(mv[1]);
    if (lv[1] >= 0)
        ::close(lv[1]);
    m_pid          = child;
    m_control_fd   = sv[0];
    m_map_fd       = mv[0];
    m_link_chan_fd = lv[0];

    // A new child has said nothing yet, or a restart would inherit the
    // previous one's report and await_startup() would answer for a process
    // that no longer exists.
    m_worker_state      = runtime_created;
    m_worker_state_seen = false;

    const int fl = ::fcntl(m_control_fd, F_GETFL, 0);
    if (fl >= 0)
        if (::fcntl(m_control_fd, F_SETFL, fl | O_NONBLOCK) < 0) {}

    if (m_placeholder)
    {
        m_placeholder->set_pid(child);

        // Forked and not listening, lowered on every spawn and not only the
        // first, because a child being replaced re-enters exactly this window.
        m_placeholder->set_endpoint_live(false);
    }

    // The runtime map and the cluster view go before the config frame, because
    // the config frame runs the script and the cluster bindings decide once,
    // while they are built, whether a view exists.
    if (!m_cluster_view.empty())
        if (!write_frame(worker_proto::frame(worker_proto::frame_type::cluster,
                                             m_cluster_view))) {}

    if (!m_runtime_map.empty())
        if (!write_frame(worker_proto::frame(worker_proto::frame_type::runtime_map,
                                             m_runtime_map))) {}

    if (!write_frame(worker_proto::frame(worker_proto::frame_type::config, m_config_json)))
    {
        LOG_ERROR("proxy supervisor: could not send config to worker");
        shutdown();
        return false;
    }

    // After the config and not before it, unlike the two above, because only a
    // proxy is handed an endpoint table and the proxy does not exist until the
    // config has been read.
    if (!m_endpoints.empty())
        if (!write_frame(worker_proto::frame(worker_proto::frame_type::endpoints, m_endpoints))) {}

    // Last, and only on the path that keeps the socket: an arm on a descriptor
    // a failed spawn is about to close is the completion-outliving-its-fd case
    // this file goes to some length to avoid.
    arm_control_poll();
    arm_map_poll();
    return true;
}

// ─── writing to the child ───────────────────────────────────────────────────
// Frames are queued and flushed as the socket takes them, because a dropped
// request frame answered `no such runtime` for a healthy runtime -- 298 of
// 10,000 pipelined `cache set` -- and the cap turns a real refusal into
// `overloaded`.
void proxy_supervisor::flush_control()
{
    while (m_out_off < m_out.size() && m_control_fd >= 0)
    {
        const ssize_t n = ::write(m_control_fd, m_out.data() + m_out_off,
                                  m_out.size() - m_out_off);
        if (n > 0)
        {
            m_out_off += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;                       // the arm below waits for writability

        // Anything else is the child going away, which is close_control()'s
        // business and not a per-frame failure.
        close_control();
        return;
    }

    // Consumed prefix, dropped in one move rather than per write: erase(0, n) in
    // the loop is quadratic in the backlog, and the backlog is exactly the case
    // this exists for.
    if (m_out_off > 0)
    {
        if (m_out_off >= m_out.size())
        {
            m_out.clear();
            m_out_off = 0;
        }
        else if (m_out_off >= 64 * 1024)
        {
            m_out.erase(0, m_out_off);
            m_out_off = 0;
        }
    }

    // A backlog means the next thing worth waking for is writability, re-armed
    // rather than adjusted because the arm is one-shot.
    const unsigned want = POLLIN | (pending_out() ? POLLOUT : 0u);
    if (want != m_poll_mask)
    {
        disarm_control_poll();
        arm_control_poll();
    }
}

bool proxy_supervisor::write_frame(const std::string& framed)
{
    if (m_control_fd < 0)
        return false;

    if (pending_out() + framed.size() > MAX_CONTROL_BACKLOG)
    {
        // Said once per crossing rather than per frame: a wedged child produces
        // one of these per request otherwise.
        if (!m_out_full)
        {
            LOG_WARN("proxy supervisor: control socket backlog full; the child "
                     "is not reading");
            m_out_full = true;
        }
        return false;
    }
    m_out_full = false;

    m_out += framed;
    flush_control();
    return true;
}

bool proxy_supervisor::send_deliver(std::string_view message)
{
    return write_frame(worker_proto::frame(worker_proto::frame_type::deliver,
                                           std::string(message)));
}

void proxy_supervisor::send_start()
{
    if (!write_frame(worker_proto::frame(worker_proto::frame_type::start, {}))) {}
}

void proxy_supervisor::send_stop()
{
    if (!write_frame(worker_proto::frame(worker_proto::frame_type::stop, {}))) {}
}

void proxy_supervisor::send_reload()
{
    // Cleared at the ask rather than at the answer, because a clean reload
    // sends nothing and "no reload_err since the ask" is the only shape
    // success has.
    m_reload_error.clear();
    if (!write_frame(worker_proto::frame(worker_proto::frame_type::reload, {}))) {}
}

std::string proxy_supervisor::take_reload_error()
{
    // Cleared explicitly rather than left to the move, because a moved-from
    // string is unspecified and empty here means the reload loaded.
    std::string out = std::move(m_reload_error);
    m_reload_error.clear();
    return out;
}

std::string proxy_supervisor::take_config_error()
{
    std::string out = std::move(m_config_error);
    m_config_error.clear();
    return out;
}

std::string proxy_supervisor::take_start_error()
{
    // Cleared explicitly for the reason take_reload_error() gives: a moved-from
    // string is valid but unspecified, and this member's whole meaning is
    // "empty means on_start ran".
    std::string out = std::move(m_start_error);
    m_start_error.clear();
    return out;
}

void proxy_supervisor::send_endpoints(const std::string& encoded_payload)
{
    m_endpoints = encoded_payload;
    if (m_control_fd >= 0)
        if (!write_frame(worker_proto::frame(worker_proto::frame_type::endpoints, m_endpoints))) {}
}

void proxy_supervisor::send_runtime_map(const std::string& encoded_payload)
{
    // Nothing has moved since this child was last told, compared as encoded
    // payload on purpose, so there is no second idea of what counts as a
    // change to drift from the first.
    if (encoded_payload == m_runtime_map)
        return;

    // No child to write to, so this is what the next one is handed, which is
    // right both for a supervisor that has not forked and for one whose child
    // is about to be replaced.
    if (m_control_fd < 0)
    {
        m_runtime_map = encoded_payload;
        return;
    }

    // Remembered only once it has been queued, or a payload the child never
    // received would make every later push of the same map look like a
    // duplicate.
    if (write_frame(worker_proto::frame(worker_proto::frame_type::runtime_map,
                                        encoded_payload)))
        m_runtime_map = encoded_payload;
}

void proxy_supervisor::send_cluster_event(const std::string& encoded_payload)
{
    if (encoded_payload.empty())
        return;
    if (!write_frame(worker_proto::frame(
            worker_proto::frame_type::cluster_ev, encoded_payload))) {}
}

void proxy_supervisor::send_cluster_view(const std::string& encoded_payload)
{
    // The same three rules as the map above, of which the middle one is what
    // makes the four cluster calls answerable in a script's top level.
    if (encoded_payload == m_cluster_view)
        return;

    if (m_control_fd < 0)
    {
        m_cluster_view = encoded_payload;
        return;
    }

    if (write_frame(worker_proto::frame(worker_proto::frame_type::cluster,
                                        encoded_payload)))
        m_cluster_view = encoded_payload;
}

void proxy_supervisor::send_publish(const std::string& encoded_payload)
{
    if (m_control_fd < 0)
        return;
    // A dropped frame is a message this worker's subscribers do not see, not
    // retried and not queued, because the alternative is an unbounded backlog
    // for messages whose value was being timely.
    if (!write_frame(worker_proto::frame(worker_proto::frame_type::publish, encoded_payload))) {}
}

void proxy_supervisor::shutdown()
{
    if (m_pid > 0)
    {
        // Ask first, because the worker stops its proxy while it still has a
        // ring to cancel into, which is the only way its connections close
        // cleanly.
        if (m_control_fd >= 0)
            if (!write_frame(worker_proto::frame(worker_proto::frame_type::shutdown, {}))) {}

        // Closing the socket is the backstop: a worker blocked somewhere that
        // never reads the frame still sees EOF and exits.
        close_control();

        ::kill(m_pid, SIGTERM);

        // Reaped here if it has already gone and otherwise by the health
        // timer, because the daemon's event-loop thread does not block on a
        // child.
        if (::waitpid(m_pid, nullptr, WNOHANG) > 0)
            m_pid = 0;

        // The placeholder stops naming a process the moment this supervisor
        // stops owning one, whether or not the reap succeeded.
        if (m_placeholder)
            m_placeholder->set_pid(0);
    }
    close_control();
}

void proxy_supervisor::poll()
{
    if (m_control_fd < 0)
        return;

    char buf[8192];
    for (;;)
    {
        const ssize_t n = ::read(m_control_fd, buf, sizeof(buf));
        if (n > 0)
        {
            m_in.append(buf, static_cast<size_t>(n));
            continue;
        }
        if (n == 0)
        {
            // The child closed its end and is on its way out, though liveness
            // is still decided by waitpid so the policy runs in one place.
            close_control();
            break;
        }
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;
        close_control();
        break;
    }

    ingest(m_in);
}

// Three things end this wait -- serving, refused, timeout -- all read with
// plain syscalls and none of them a waitpid of its own, because
// check_liveness() is the one place that reaps and the one place that applies
// the death policy.
proxy_supervisor::startup
proxy_supervisor::await_startup(std::chrono::milliseconds bound)
{
    const auto deadline = std::chrono::steady_clock::now() + bound;

    for (;;)
    {
        // Whatever is already buffered, before deciding anything, because on
        // the refusal path the frames and the EOF are both sitting in the
        // socket.
        poll();

        // And the map socket, which is what stops this being a deadlock: the
        // child's on_start is where the four map calls are written, so a
        // worker blocked on an answer would face a daemon blocked in this
        // loop.
        poll_map();

        if (m_placeholder && m_placeholder->get_state() == runtime_failed)
            return startup::refused;

        if (m_worker_state_seen && m_worker_state == runtime_running)
            return startup::serving;

        // Reaps, applies the policy, and may mark the placeholder failed or
        // fork a replacement, checked again at the top of the next turn.
        if (check_liveness())
            continue;

        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
            return startup::pending;

        // Sleep on the descriptor rather than the clock, capped so a child
        // killed without closing its end is still noticed within a tick of the
        // cap.
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        int slice = static_cast<int>(std::min<std::chrono::milliseconds::rep>(
            remaining.count(), 20));
        if (slice < 0)
            slice = 0;

        if (m_control_fd >= 0 || m_map_fd >= 0)
        {
            // Both descriptors, because either can end this wait and watching
            // only the control socket cost the full slice on every turn.
            struct pollfd pfds[2];
            nfds_t        n = 0;
            if (m_control_fd >= 0) pfds[n++] = {m_control_fd, POLLIN, 0};
            if (m_map_fd     >= 0) pfds[n++] = {m_map_fd,     POLLIN, 0};
            if (::poll(pfds, n, slice) < 0) {}
        }
        else
        {
            // No socket left to wait on: the child is gone or never had one,
            // and the only thing that can still change is the reap above.
            struct timespec ts{0, static_cast<long>(slice) * 1000000L};
            if (::nanosleep(&ts, nullptr) < 0) {}
        }
    }
}

bool proxy_supervisor::send_direct(uint64_t ticket, std::string_view payload)
{
    if (!m_placeholder)
        return false;

    m_direct_ticket = ticket;
    m_direct_done   = false;
    m_direct_status = 0;
    m_direct_reply.clear();

    // The worker answers a chan_req by handing the payload to its own runtime,
    // so the target is this supervisor's own name and the frame is the one
    // serve_deferred writes.
    return write_frame(worker_proto::frame(
        worker_proto::frame_type::chan_req,
        worker_proto::encode_chan_request(ticket, m_placeholder->get_name(),
                                          payload)));
}

bool proxy_supervisor::await_direct(uint64_t ticket,
                                    std::chrono::milliseconds bound,
                                    uint8_t& status, std::string& reply)
{
    const auto deadline = std::chrono::steady_clock::now() + bound;

    for (;;)
    {
        poll();

        // The map socket too, for the reason await_startup gives: a child
        // blocked on a map answer would face a daemon blocked here.
        poll_map();

        if (m_direct_done && m_direct_ticket == ticket)
        {
            status = m_direct_status;
            reply  = m_direct_reply;
            m_direct_ticket = 0;
            m_direct_done   = false;
            return true;
        }

        // A child that died owes nothing, and waiting out the deadline for a
        // corpse is the difference between a refusal and a hang.
        if (check_liveness())
            continue;
        if (m_control_fd < 0)
            return false;

        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
            return false;

        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        int slice = static_cast<int>(std::min<std::chrono::milliseconds::rep>(
            remaining.count(), 20));
        if (slice < 0)
            slice = 0;

        struct pollfd pfds[2];
        nfds_t        n = 0;
        if (m_control_fd >= 0) pfds[n++] = {m_control_fd, POLLIN, 0};
        if (m_map_fd     >= 0) pfds[n++] = {m_map_fd,     POLLIN, 0};
        if (n && ::poll(pfds, n, slice) < 0) {}
    }
}

// The reload half of the same idea, watching the declaration object the child
// installs rather than the flag beside it, which the health tick consumes --
// and a false here is not an error, because the declaration already held is
// still in force.
bool proxy_supervisor::await_routes(const void* previous,
                                    std::chrono::milliseconds bound)
{
    const auto deadline = std::chrono::steady_clock::now() + bound;

    for (;;)
    {
        poll();

        // The reload path reaches the script's top level again, so it reaches
        // the same four calls; see the note in await_startup().
        poll_map();

        if (m_placeholder && m_placeholder->worker_routes().get() != previous)
            return true;

        // A child that has gone will never answer, checked after the drain so
        // a declaration sitting in the socket of an exited child is still
        // taken.
        if (check_liveness())
            continue;
        if (m_control_fd < 0 || m_pid <= 0)
            return false;

        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
            return false;

        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        int slice = static_cast<int>(std::min<std::chrono::milliseconds::rep>(
            remaining.count(), 20));
        if (slice < 0)
            slice = 0;

        struct pollfd pfds[2];
        nfds_t        n = 0;
        if (m_control_fd >= 0) pfds[n++] = {m_control_fd, POLLIN, 0};
        if (m_map_fd     >= 0) pfds[n++] = {m_map_fd,     POLLIN, 0};
        if (n && ::poll(pfds, n, slice) < 0) {}
    }
}

void proxy_supervisor::ingest(const std::string&)
{
    worker_proto::frame_type type{};
    uint16_t                 ver = 0;
    std::string              payload;
    bool                     fatal = false;

    while (worker_proto::take_frame(m_in, type, ver, payload, fatal))
    {
        // Any frame at all proves the child became a worker, which is the one
        // thing its exit status cannot tell us afterwards.
        m_saw_worker_frame = true;
        m_last_frame_at    = std::chrono::steady_clock::now();

        switch (type)
        {
            case worker_proto::frame_type::stats:
                apply_stats(payload);
                // After the figures are in the placeholder and never before,
                // because the handler rebuilds the runtime map out of what
                // every runtime reports.
                if (m_on_stats)
                    m_on_stats();
                break;

            case worker_proto::frame_type::hello:
                break;

            case worker_proto::frame_type::routes:
            {
                // The declaration this child's script made, kept where
                // publish_endpoints() looks, with a republish asked for
                // because membership has not changed.
                auto rt = std::make_shared<route_table>();
                if (worker_proto::decode_routes(payload, *rt) && m_placeholder)
                {
                    m_placeholder->set_worker_routes(
                        std::shared_ptr<const route_table>(std::move(rt)));
                    m_routes_changed = true;
                }
                else
                {
                    LOG_WARN("worker sent a route declaration this build could "
                             "not read; the gateway in front keeps forwarding");
                }
                break;
            }

            case worker_proto::frame_type::reload_err:
                // Only sent when a reload failed and only between the ask and
                // the routes frame, so this is the answer cmd_reload_lua is
                // holding and it is read back there rather than logged.
                m_reload_error = payload;
                break;

            case worker_proto::frame_type::config_err:
                // Written by a child about to exit rather than serve, kept
                // rather than logged because the point of the frame is the
                // terminal that ran the command.
                m_config_error = payload;
                break;

            case worker_proto::frame_type::start_err:
                // The same shape one command along, sent only when on_start
                // raised and only before the `state` frame, so this is the
                // answer cmd_create is holding.
                m_start_error = payload;
                break;

            case worker_proto::frame_type::publish:
            {
                // The same frame this supervisor writes downward, arriving
                // from the other end, because a cache serving PUBLISH in a
                // worker has no other way to reach a subscriber.
                worker_proto::publish_wire p;
                if (m_on_publish && worker_proto::decode_publish(payload, p))
                    m_on_publish(this, p.cache_name, p.channel, p.message);
                break;
            }

            case worker_proto::frame_type::chan_rep:
            {
                // The answer to a request this supervisor put on the wire,
                // whose ticket is the channel's own, so nothing here has to
                // know what was asked.
                worker_proto::chan_reply_wire r;
                if (!worker_proto::decode_chan_reply(payload, r))
                    break;

                // A ticket the daemon minted for itself is answered into the
                // slot await_direct watches, and never into the channel, whose
                // parked table has no entry for it.
                if (r.ticket == m_direct_ticket && (r.ticket & direct_ticket_bit))
                {
                    m_direct_status = r.status;
                    m_direct_reply.assign(r.payload);
                    m_direct_done   = true;
                    break;
                }

                if (m_channel)
                    m_channel->complete_deferred(
                        r.ticket, static_cast<request_status>(r.status), r.payload);
                break;
            }

            case worker_proto::frame_type::chan_req:
                // A request from the worker's runtime for one it cannot see.
                on_chan_req(payload);
                break;

            case worker_proto::frame_type::deliver_to:
            {
                // `socketley.send` from the worker's script, or the sibling
                // half of a broadcast when the name is its own, routed by the
                // daemon with `this` passed so the sending shard is left out
                // of the fan-out.
                std::string name, message;
                if (m_on_deliver &&
                    worker_proto::decode_deliver_to(payload, name, message))
                    m_on_deliver(this, name, message);
                break;
            }

            case worker_proto::frame_type::send_ref:
            {
                // `self.send(handle, msg)` for a client one of this shard's
                // siblings holds, routed by the daemon, which holds every
                // shard's socket.
                conn_ref    ref{};
                std::string message;
                if (m_on_send_ref &&
                    worker_proto::decode_send_ref(payload, ref, message))
                    m_on_send_ref(this, ref, message);
                break;
            }

            case worker_proto::frame_type::route_up:
            {
                // A routing verb this child performed on a runtime it does not
                // hold, decoded here and resolved by the daemon, which holds
                // the map.
                std::string        to, frm, rp;
                worker_proto::route_op op{};
                conn_ref           ref{};
                if (m_on_route &&
                    worker_proto::decode_route_frame(payload, to, frm, op, ref, rp))
                    m_on_route(this, to, frm, op, ref, rp);
                break;
            }

            case worker_proto::frame_type::state:
                // created/running/stopped are still not adopted because the
                // daemon's record has one writer, but `failed` is: no command
                // causes it and this side cannot observe it, so a client whose
                // TLS cannot work read as Up in a worker and Failed in the
                // daemon -- and every state is remembered either way, which
                // await_startup() needs and writes nothing on.
                if (!payload.empty())
                {
                    m_worker_state =
                        static_cast<runtime_state>(static_cast<uint8_t>(payload[0]));
                    m_worker_state_seen = true;

                    // The one thing only the child can tell us -- the listener
                    // is up -- written through because the endpoint table is
                    // built from it, and raised once per transition so the
                    // caller republishes.
                    if (m_placeholder && m_worker_state == runtime_running &&
                        !m_placeholder->endpoint_live())
                    {
                        m_placeholder->set_endpoint_live(true);
                        m_reachability_changed = true;
                    }
                }

                if (!payload.empty() &&
                    static_cast<runtime_state>(static_cast<uint8_t>(payload[0]))
                        == runtime_failed &&
                    m_placeholder &&
                    m_placeholder->get_state() != runtime_failed)
                {
                    LOG_ERROR("worker reported its runtime failed to start");
                    m_placeholder->mark_failed();
                    m_state_changed = true;   // collected by check_managed_health
                }
                break;

            default:
                break;   // unknown or wrong-direction frame: skipped by length
        }
    }

    if (fatal)
    {
        LOG_ERROR("proxy supervisor: malformed frame from worker, dropping control socket");
        close_control();
        m_in.clear();
    }
}

void proxy_supervisor::apply_stats(const std::string& payload)
{
    worker_proto::stats_wire s;
    if (!worker_proto::decode_stats(payload, s))
    {
        // Not a silent return, because a frame that will not decode makes
        // every later one suspect and the placeholder freezes on its last good
        // report.
        const std::string msg =
            "proxy supervisor: stats frame did not decode ("
            + std::to_string(payload.size())
            + " bytes); worker figures held at last good report";
        LOG_WARN(msg.c_str());
        return;
    }

    // Kept and not applied, because a placeholder stands for N processes and N
    // writers of one field means a reader sees whichever shard published most
    // recently; the sum is aggregate_worker_stats()'s to make, and these
    // figures are only the fallback for a runtime whose region could not be
    // created.
    m_last_stats.total_connections  = s.total_connections;
    m_last_stats.total_messages     = s.total_messages;
    m_last_stats.bytes_in           = s.bytes_in;
    m_last_stats.bytes_out          = s.bytes_out;
    m_last_stats.active_connections = s.active_connections;
    m_last_stats.detail             = std::move(s.detail);
    m_last_stats.seen               = true;
}

// Above lua_deadline::builtin_default_ms, deliberately: a runaway callback is
// already ended by its own deadline, and reporting a wedge the runtime is about
// to resolve is noise.  What is left over is what no deadline covers -- a
// callback whose script set `callback_timeout_ms = 0`, and a loop that is not
// in Lua at all.
static constexpr auto wedge_silence = std::chrono::seconds(15);

// Half a core, sustained across the whole silent window.  A worker with nothing
// to do sits in poll_completions() and spends none.
static constexpr double wedge_cpu_share = 0.5;

// utime + stime out of /proc/<pid>/stat, counted from the last ')' because a
// process name may contain both spaces and parentheses and the fields before it
// cannot be split on whitespace.
static bool read_cpu_ticks(pid_t pid, uint64_t& out)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", static_cast<int>(pid));
    FILE* f = ::fopen(path, "re");
    if (!f)
        return false;

    char buf[4096];
    const size_t n = ::fread(buf, 1, sizeof(buf) - 1, f);
    ::fclose(f);
    if (n == 0)
        return false;
    buf[n] = '\0';

    const char* p = ::strrchr(buf, ')');
    if (!p)
        return false;

    // Field 3 (state) begins after the ')'; utime is 14 and stime 15, so the
    // twelfth and thirteenth values from here.
    unsigned long long utime = 0, stime = 0;
    int matched = 0;
    ++p;
    for (int field = 3; field <= 15 && *p; ++field)
    {
        while (*p == ' ') ++p;
        char* end = nullptr;
        const unsigned long long v = ::strtoull(p, &end, 10);
        if (end == p)
        {
            // The state field is a letter, skipped rather than parsed.
            while (*p && *p != ' ') ++p;
            continue;
        }
        if (field == 14) { utime = v; ++matched; }
        if (field == 15) { stime = v; ++matched; }
        p = end;
    }
    if (matched != 2)
        return false;
    out = utime + stime;
    return true;
}

void proxy_supervisor::check_wedged()
{
    if (m_pid <= 0)
    {
        m_wedged = false;
        return;
    }

    uint64_t ticks = 0;
    if (!read_cpu_ticks(m_pid, ticks))
        return;   // the child is going away; check_liveness owns that

    const auto now = std::chrono::steady_clock::now();

    // The first sample establishes the baseline and accuses nobody, and so does
    // the first tick after a restart, which resets it.
    if (m_last_cpu_at.time_since_epoch().count() == 0)
    {
        m_last_cpu_ticks = ticks;
        m_last_cpu_at    = now;
        return;
    }

    const auto window = now - m_last_cpu_at;
    const double secs = std::chrono::duration<double>(window).count();
    const long   hz   = ::sysconf(_SC_CLK_TCK);
    const double cores = (secs > 0 && hz > 0)
        ? static_cast<double>(ticks - m_last_cpu_ticks) / static_cast<double>(hz) / secs
        : 0.0;

    m_last_cpu_ticks = ticks;
    m_last_cpu_at    = now;

    // A worker that has never spoken has no silence to measure yet; spawn()
    // stamps nothing and await_startup owns that window.
    const bool silent = m_last_frame_at.time_since_epoch().count() != 0
                     && now - m_last_frame_at > wedge_silence;

    const bool wedged = silent && cores >= wedge_cpu_share;
    if (wedged == m_wedged)
        return;

    // On the edge only, because a stuck worker stays stuck and one line an
    // operator can find beats one a second they cannot.
    m_wedged = wedged;
    if (m_placeholder)
        m_placeholder->set_unresponsive(wedged);

    char msg[256];
    if (wedged)
        snprintf(msg, sizeof(msg),
                 "worker pid %d has answered nothing for %llds while spending "
                 "%.2f cores; it is running and not serving",
                 static_cast<int>(m_pid),
                 static_cast<long long>(std::chrono::duration_cast<std::chrono::seconds>(
                     now - m_last_frame_at).count()),
                 cores);
    else
        snprintf(msg, sizeof(msg), "worker pid %d is answering again",
                 static_cast<int>(m_pid));
    LOG_WARN(msg);
}

bool proxy_supervisor::check_liveness()
{
    if (m_pid <= 0)
        return false;

    int   status = 0;
    const pid_t r = ::waitpid(m_pid, &status, WNOHANG);
    if (r <= 0)
        return false;      // still running, or not ours to reap

    m_pid = 0;
    // The placeholder's copy goes with it: `stats` prints this number, and a pid
    // that has been reaped is worse than no pid at all — it is a number the
    // operator will go and look at, and by then it can belong to anything.
    if (m_placeholder)
        m_placeholder->set_pid(0);
    close_control();
    m_in.clear();

    // The binary and the status, because the usual cause is a worker binary
    // that never became a worker and the bare sentence sent operators looking
    // in the configuration path instead.
    {
        char msg[512];
        if (WIFEXITED(status))
            snprintf(msg, sizeof(msg),
                     "worker %s exited unexpectedly with status %d",
                     m_exec_path.c_str(), WEXITSTATUS(status));
        else if (WIFSIGNALED(status))
            snprintf(msg, sizeof(msg),
                     "worker %s was killed by signal %d",
                     m_exec_path.c_str(), WTERMSIG(status));
        else
            snprintf(msg, sizeof(msg), "worker %s exited unexpectedly",
                     m_exec_path.c_str());
        LOG_WARN(msg);
    }

    // A child that died without ever answering a frame never read the config
    // it is about to be blamed for, and the one way to build that binary is to
    // leave `proxy-worker` undispatched.
    if (!m_saw_worker_frame && m_config_error.empty())
        m_config_error = std::string(m_exec_path) +
                         " exited before it answered anything; a custom daemon "
                         "or worker binary must run worker_main() for argv[1] "
                         "== \"proxy-worker\"";

    // The one thing a child can tell us on the way out -- not a crash but a
    // configuration it will never accept -- so the runtime is left `failed`
    // where the operator can see it.
    if (WIFEXITED(status) && WEXITSTATUS(status) == worker_proto::exit_config_refused)
    {
        LOG_ERROR("proxy worker refused its configuration; not restarting it");
        if (m_placeholder)
            m_placeholder->mark_failed();
        return true;
    }

    if (m_policy == death_policy::fail)
    {
        if (m_placeholder)
            m_placeholder->mark_failed();
        return true;
    }

    // Restart, unless it is failing faster than it is serving.
    const auto now = std::chrono::steady_clock::now();
    if (now - m_last_restart > restart_burst_window)
        m_restarts = 0;
    m_last_restart = now;

    if (++m_restarts > restart_burst_limit)
    {
        LOG_ERROR("proxy worker restarted too often, leaving it failed");
        if (m_placeholder)
            m_placeholder->mark_failed();
        return true;
    }

    runtime_config cfg;
    {
        state_persistence sp{std::filesystem::path{}};
        if (!sp.parse_json_string(m_config_json, cfg))
        {
            if (m_placeholder)
                m_placeholder->mark_failed();
            return true;
        }
    }

    if (!spawn(cfg))
    {
        if (m_placeholder)
            m_placeholder->mark_failed();
        return true;
    }

    // The replacement is a different process with an empty store, so the
    // uptime restarts with it and the count is what tells an operator the
    // difference between a cache that has served all day and one that has not.
    if (m_placeholder)
    {
        m_placeholder->note_restart();
        m_placeholder->set_unresponsive(false);
    }
    m_wedged      = false;
    m_last_cpu_at = {};
    m_last_frame_at = {};

    send_start();
    return true;
}

// A write that does not queue means the child is gone or wedged, and saying so
// keeps a ticket from being parked for something that will never answer.
bool proxy_supervisor::serve_deferred(uint64_t ticket, std::string_view target,
                                      std::string_view payload)
{
    if (!m_channel)
        return false;
    // `target` is this supervisor's own runtime by construction — the channel
    // only reaches here through the name this sink is registered under — but it
    // is sent rather than re-derived, so the two sides read the same field.
    return write_frame(worker_proto::frame(
        worker_proto::frame_type::chan_req,
        worker_proto::encode_chan_request(ticket, target, payload)));
}

// ─── the other direction ────────────────────────────────────────────────────

bool proxy_supervisor::send_deliver_ref(const conn_ref& ref,
                                       std::string_view message)
{
    return write_frame(worker_proto::frame(
        worker_proto::frame_type::deliver_ref,
        worker_proto::encode_send_ref(ref, message)));
}

bool proxy_supervisor::send_route(std::string_view to, std::string_view frm,
                                 worker_proto::route_op op, const conn_ref& ref,
                                 std::string_view payload)
{
    return write_frame(worker_proto::frame(
        worker_proto::frame_type::route_down,
        worker_proto::encode_route_frame(to, frm, op, ref, payload)));
}

void proxy_supervisor::on_chan_req(std::string_view payload)
{
    worker_proto::chan_request_wire q;
    if (!worker_proto::decode_chan_request(payload, q))
        return;

    const auto refuse = [&](request_status st)
    {
        if (!write_frame(worker_proto::frame(
                worker_proto::frame_type::chan_rep,
                worker_proto::encode_chan_reply(q.ticket,
                    static_cast<uint8_t>(st), {})))) {}
    };

    // The one cycle this arrangement can produce, cut here as the second lock
    // on a door the worker's own registration already closes.
    if (m_placeholder && q.target == m_placeholder->get_name())
    {
        refuse(request_status::no_target);
        return;
    }

    // The same door one notch finer, because `c#3` is not `c` and a shard
    // naming its own index would go straight back down the socket it came
    // from.
    {
        std::string_view base;
        uint32_t         idx = 0;
        if (m_placeholder && parse_shard_target(q.target, base, idx)
            && base == m_placeholder->get_name() && idx == m_shard_index)
        {
            LOG_WARN("a shard asked the daemon for its own slice; refused");
            refuse(request_status::no_target);
            return;
        }
    }

    if (!m_channel ||
        !m_channel->post(this, q.ticket, q.target, q.payload, request_class::client))
    {
        // Nothing was taken, so no reply is coming and answering here is the
        // whole difference between a refusal and a hang.
        refuse(request_status::no_target);
        return;
    }

    // This crossing was carried, which is the only evidence that exists that
    // the two processes have something to say to each other.  Asked after the
    // post so a target nothing answers for is never linked, and last so a
    // refusal to introduce them cannot cost the request that revealed them.
    if (m_on_peer)
        m_on_peer(this, std::string(q.target));
}

void proxy_supervisor::on_request_reply(uint64_t cookie, request_status st,
                                        std::string_view reply)
{
    if (!write_frame(worker_proto::frame(
            worker_proto::frame_type::chan_rep,
            worker_proto::encode_chan_reply(cookie, static_cast<uint8_t>(st),
                                            reply)))) {}
}
