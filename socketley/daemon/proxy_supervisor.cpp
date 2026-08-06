#include "proxy_supervisor.h"

#include <cerrno>
#include <cstdint>
#include <cstring>
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
#include "../shared/worker_protocol.h"

namespace
{

// The descriptor the child finds its control socket on.  Fixed rather than
// passed in argv so there is nothing to parse and nothing to get wrong: the
// child's very first action can be a read.
constexpr int child_control_fd = 3;

// A child that dies immediately and repeatedly is not going to be fixed by
// forking it again — a bad port, a backend that cannot be resolved, a Lua
// script that throws.  After this many restarts inside the window the runtime
// is left `failed` so the operator sees it rather than watching the daemon
// fork in a loop.
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
    // Three things outlive a supervisor and all three can be holding it: the
    // placeholder keeps it as its sink override, and the channel keeps it as a
    // sink and — since a worker can ask as well as answer — as an origin.  A
    // supervisor dies whenever its runtime is stopped while the runtime itself
    // stays in the map, so this is an ordinary event, not a shutdown-only one.
    //
    // The sink table only holds running runtimes, which is what has kept the
    // override from being dereferenced after the fact so far.  That is a
    // property of another file's filter, not of this one, and it is not worth
    // depending on.
    if (m_placeholder)
        m_placeholder->set_request_sink_override(nullptr);
    if (m_channel)
    {
        m_channel->drop_sink(this);
        m_channel->drop_origin(this);
    }
    shutdown();

    // After shutdown(), which closes the socket and cancels the arm with it.
    // The registration is what makes the loop drop a completion that is still
    // on its way for this handler, so it is given back last.
    if (m_loop)
        m_loop->deregister_owner(this);
}

void proxy_supervisor::set_event_loop(event_loop* loop)
{
    m_loop = loop;
    if (m_loop)
        m_loop->register_owner(this);
}

void proxy_supervisor::arm_control_poll()
{
    if (!m_loop || m_control_fd < 0 || m_poll_armed)
        return;

    m_poll_mask  = POLLIN | (pending_out() ? POLLOUT : 0u);
    m_poll_req   = { this, nullptr, m_control_fd, 0, op_poll };
    m_poll_armed = m_loop->submit_poll_add(m_control_fd, m_poll_mask, &m_poll_req);

    // Not an error worth failing the runtime over: the health tick still drains
    // this socket, so a refused arm costs latency and nothing else.  Said out
    // loud because that latency is two seconds and somebody will measure it.
    if (!m_poll_armed)
        LOG_WARN("proxy supervisor: could not arm the control socket; its "
                 "replies now wait for the health tick");
}

void proxy_supervisor::disarm_control_poll()
{
    if (!m_loop)
        return;

    // Cancel first, then let the loop drop whatever still reports: an armed
    // poll names a descriptor this class is about to close, and a completion
    // that arrives after the close would carry a token for an fd that may
    // already belong to somebody else.
    if (m_poll_armed)
    {
        if (!m_loop->submit_poll_remove(&m_poll_req)) {}
        m_poll_armed = false;
    }
}

void proxy_supervisor::on_cqe(struct io_uring_cqe* /*cqe*/)
{
    // Whatever the result, this arm is spent.  Cleared before the drain so a
    // frame that causes a write back into this socket can re-arm rather than
    // queue behind an arm that has already reported.
    m_poll_armed = false;
    m_poll_mask  = 0;

    // The backlog first: whatever the poll reported, the socket may have room
    // now, and a request waiting in m_out is somebody's answer not yet asked
    // for.  flush_control() re-arms with the mask the backlog calls for.
    flush_control();

    // Errors included: a poll that reports POLLHUP or an error is exactly the
    // case where the read below returns 0 and close_control() runs, which is
    // the death path this class already has.
    poll();

    arm_control_poll();
}

void proxy_supervisor::close_control()
{
    if (m_control_fd >= 0)
    {
        disarm_control_poll();
        ::close(m_control_fd);
        m_control_fd = -1;
    }
}

bool proxy_supervisor::spawn(const runtime_config& cfg)
{
    if (m_exec_path.empty())
    {
        LOG_ERROR("proxy supervisor: could not resolve own executable path");
        return false;
    }

    // Keep the config so a restart can replay it without going back to disk.
    // The state file is the daemon's record for the operator; this is the
    // daemon's record for the child, and they are written at different moments.
    {
        state_persistence sp{std::filesystem::path{}};
        m_config_json = sp.format_json_pretty(cfg);
    }

    int sv[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0)
    {
        LOG_ERROR("proxy supervisor: socketpair failed");
        return false;
    }

    const pid_t child = ::fork();
    if (child < 0)
    {
        ::close(sv[0]);
        ::close(sv[1]);
        LOG_ERROR("proxy supervisor: fork failed");
        return false;
    }

    if (child == 0)
    {
        // ── child ───────────────────────────────────────────────────────────
        //
        // ─── WHAT CROSSES THE EXEC, AND NOTHING ELSE ────────────────────────
        //
        // Exactly four descriptors are meant to reach the worker.  The list is
        // written down because for a long time it was not, and what actually
        // crossed was every socket the daemon had open — read out of a live
        // worker's /proc/<pid>/fd:
        //
        //     fd 5 -> unix .../daemon.sock  SO_ACCEPTCON   the IPC listener
        //     fd 6 -> tcp 0.0.0.0:4CEA      LISTEN         another runtime's port
        //     fd 8 -> unix .../daemon.sock                 an accepted CLI connection
        //
        // none of which this process has any use for, and all of which it then
        // held for its whole life.  The listener made "is a daemon serving this
        // socket" answer yes with no daemon left alive; the port stayed bound
        // by a worker belonging to a different runtime.  The fix is at every
        // creation site rather than here, because a descriptor that is
        // inheritable for even a moment is inheritable during exactly the
        // moment this function runs.
        //
        // The deliberate set:
        //
        //   0  /dev/null, opened below.  The worker must never read the
        //      terminal the daemon was started from.
        //   1  the daemon's stdout, inherited unchanged.
        //   2  the daemon's stderr, inherited unchanged.  1 and 2 are the point
        //      of the exercise: a worker's log lines have to land where the
        //      operator is already looking, so these two are inherited on
        //      purpose and are the reason no blanket close-range runs here.
        //   3  the control socket, dup2'd onto child_control_fd below.
        //
        // The worker's own listening socket is NOT in this set and must not be:
        // it binds its own port after the exec, from the port in the config
        // frame, and nothing is passed with SCM_RIGHTS.  Verified rather than
        // assumed — a worker started with the leak closed still binds and still
        // serves, and its listener is a descriptor number that did not exist
        // before the exec.
        //
        // Nothing here may allocate or take a lock that the parent could have
        // held at fork time.  dup2 clears FD_CLOEXEC on the copy, which is what
        // lets the control socket survive the exec.
        ::close(sv[0]);
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
    m_pid        = child;
    m_control_fd = sv[0];

    const int fl = ::fcntl(m_control_fd, F_GETFL, 0);
    if (fl >= 0)
        if (::fcntl(m_control_fd, F_SETFL, fl | O_NONBLOCK) < 0) {}

    if (m_placeholder)
        m_placeholder->set_pid(child);

    if (!write_frame(worker_proto::frame(worker_proto::frame_type::config, m_config_json)))
    {
        LOG_ERROR("proxy supervisor: could not send config to worker");
        shutdown();
        return false;
    }

    // A child forked after the last publish would otherwise route from an empty
    // table until the next membership change, which for a stable daemon may
    // never come.
    if (!m_endpoints.empty())
        if (!write_frame(worker_proto::frame(worker_proto::frame_type::endpoints, m_endpoints))) {}

    // Last, and only on the path that keeps the socket: an arm on a descriptor
    // a failed spawn is about to close is the completion-outliving-its-fd case
    // this file goes to some length to avoid.
    arm_control_poll();
    return true;
}

// ─── writing to the child ───────────────────────────────────────────────────
//
// This used to write straight at the descriptor and drop the frame on EAGAIN,
// which was defensible while the socket carried stats: the next push supersedes
// the one that did not fit, and blocking the daemon's event-loop thread on a
// process it does not control is not on the table.
//
// It stopped being defensible when requests went on the same socket.  A dropped
// request frame is a false return, the channel reads a false return as "this
// sink cannot take it", and the origin is answered `no such runtime` — for a
// runtime that exists, is healthy, and is answering everything else.  Measured
// before this buffer, with 10,000 pipelined `cache set` through one worker:
// 298 of them answered no such runtime.  The socket held about 270 frames and
// everything past that was a confident lie.
//
// So the frames are queued and flushed as the socket takes them.  The cap is
// what makes it bounded, and reaching it is a real refusal rather than an
// invented one — see serve_deferred, which turns it into `overloaded`.
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

    // A backlog means the next thing worth waking for is writability, not just
    // readability.  Re-armed rather than adjusted: the arm is one-shot.
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

void proxy_supervisor::send_endpoints(const std::string& encoded_payload)
{
    m_endpoints = encoded_payload;
    if (m_control_fd >= 0)
        if (!write_frame(worker_proto::frame(worker_proto::frame_type::endpoints, m_endpoints))) {}
}

void proxy_supervisor::send_publish(const std::string& encoded_payload)
{
    if (m_control_fd < 0)
        return;
    // A dropped frame is a message this worker's subscribers do not see, which
    // is what write_frame() already warns about.  Not retried and not queued:
    // the alternative is the daemon growing an unbounded backlog on behalf of a
    // child that is not reading, for messages whose whole value was being
    // timely.
    if (!write_frame(worker_proto::frame(worker_proto::frame_type::publish, encoded_payload))) {}
}

void proxy_supervisor::shutdown()
{
    if (m_pid > 0)
    {
        // Ask first.  The worker stops its proxy while it still has a ring to
        // cancel into, which is the only way its connections close cleanly.
        if (m_control_fd >= 0)
            if (!write_frame(worker_proto::frame(worker_proto::frame_type::shutdown, {}))) {}

        // Closing the socket is the backstop: a worker blocked somewhere that
        // never reads the frame still sees EOF and exits.
        close_control();

        ::kill(m_pid, SIGTERM);

        // Reaped here if it has already gone; otherwise the health timer's
        // waitpid collects it.  Not waited on: the daemon's event-loop thread
        // does not block on a child.
        if (::waitpid(m_pid, nullptr, WNOHANG) > 0)
            m_pid = 0;

        // The placeholder stops naming a process the moment this supervisor
        // stops owning one, whether or not the reap above succeeded: SIGTERM has
        // been sent and the runtime is on its way out, so `stats` must not go on
        // printing a pid as if the runtime were still there to look at.
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
            // The child closed its end — it is on its way out.  Liveness is
            // still decided by waitpid, not by this, so the policy runs in one
            // place only.
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

void proxy_supervisor::ingest(const std::string&)
{
    worker_proto::frame_type type{};
    uint16_t                 ver = 0;
    std::string              payload;
    bool                     fatal = false;

    while (worker_proto::take_frame(m_in, type, ver, payload, fatal))
    {
        switch (type)
        {
            case worker_proto::frame_type::stats:
                apply_stats(payload);
                break;

            case worker_proto::frame_type::hello:
                break;

            case worker_proto::frame_type::routes:
            {
                // The declaration this child's script made.  Kept on the
                // placeholder, which is where publish_endpoints() looks, and a
                // republish is asked for because membership has not changed —
                // nothing else would carry it out to the proxies in front.
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

            case worker_proto::frame_type::publish:
            {
                // The same frame this supervisor writes downward, arriving from
                // the other end.  A cache serving PUBLISH in a worker has no
                // other way to reach a subscriber: every other runtime and every
                // other worker's socket is held by the daemon.
                worker_proto::publish_wire p;
                if (m_on_publish && worker_proto::decode_publish(payload, p))
                    m_on_publish(this, p.cache_name, p.channel, p.message);
                break;
            }

            case worker_proto::frame_type::chan_rep:
            {
                // The answer to a request this supervisor put on the wire.  The
                // ticket is the channel's own, so nothing here has to know what
                // was asked or what came back.
                worker_proto::chan_reply_wire r;
                if (m_channel && worker_proto::decode_chan_reply(payload, r))
                    m_channel->complete_deferred(
                        r.ticket, static_cast<request_status>(r.status), r.payload);
                break;
            }

            case worker_proto::frame_type::chan_req:
                // A request from the worker's runtime for one it cannot see.
                on_chan_req(payload);
                break;

            case worker_proto::frame_type::state:
                // created / running / stopped are still not acted on, and for
                // the reason that was always given: the daemon's own record is
                // what the CLI is promised, it is set by the command that
                // caused the transition, and letting the child move it too
                // would mean two writers for one value.
                //
                // `failed` is not one of those.  No command causes it and the
                // daemon cannot observe it: start() on an out-of-process
                // runtime stores `running` the moment the child is forked,
                // because that is all this side knows — the port is bound in
                // the worker, the TLS pair is checked in the worker, the script
                // runs in the worker.  When any of that refuses, the child
                // stays alive holding a runtime that will never serve, so
                // check_liveness() never fires either.
                //
                // What that looked like, with a client whose TLS configuration
                // cannot work:
                //
                //     in the daemon    ls: Failed   json: "status":"failed"
                //     in a worker      ls: Up       json: "status":"running"
                //
                // A wrong answer rather than a missing one, to `ls`, to `ps -a`
                // and to every script reading the JSON.
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
        return;
    if (!m_placeholder)
        return;

    m_placeholder->m_stat_total_connections.store(s.total_connections, std::memory_order_relaxed);
    m_placeholder->m_stat_total_messages.store(s.total_messages, std::memory_order_relaxed);
    m_placeholder->m_stat_bytes_in.store(s.bytes_in, std::memory_order_relaxed);
    m_placeholder->m_stat_bytes_out.store(s.bytes_out, std::memory_order_relaxed);

    // The detail text and the connection count are stored where an in-process
    // runtime's would be, so stat_detail_snapshot() — which the metrics
    // endpoint already calls — is answered identically whichever side the
    // proxy is running on.
    //
    // The moment goes with them.  This function runs when the daemon gets round
    // to draining, which is a poor answer to "how old are these": frames wait in
    // the socket for however long nothing polls, and the age was being measured
    // from the wait's end rather than its start.
    m_placeholder->set_worker_stats(s.detail, s.active_connections,
                                    static_cast<int64_t>(s.taken_ns));
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

    LOG_WARN("proxy worker exited unexpectedly");

    // The one thing a child can tell us about itself on the way out: this is not
    // a crash, it is a configuration it will never accept.  Restarting is the
    // right answer to a crash and produces nothing here but five more copies of
    // the same refusal, so the runtime is left `failed` where the operator can
    // see it — and the reason is already in the log, written by the child.
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
    send_start();
    return true;
}

// The request goes out on the control socket the child is already reading.  A
// write that does not queue means the child is gone or wedged; saying so here
// is what keeps a ticket from being parked for something that will never
// answer — the channel then tells the origin `no_target` instead.
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

    // The one cycle this arrangement can produce, cut here.
    //
    // A worker asking for its own name would be posted into the daemon's
    // channel, whose sink for that name is this supervisor, which would put it
    // straight back on the wire to the worker that asked.  The worker registers
    // its own runtime precisely so this does not arise, and this is the second
    // lock on the same door: a worker built by an older binary, or one whose
    // runtime failed to build at all, must not be able to start the two
    // processes handing one request back and forth for ever.
    if (m_placeholder && q.target == m_placeholder->get_name())
    {
        refuse(request_status::no_target);
        return;
    }

    if (!m_channel ||
        !m_channel->post(this, q.ticket, q.target, q.payload, request_class::client))
    {
        // Nothing was taken, so no on_request_reply() is coming and the worker
        // would wait for ever.  Answering here is the whole difference between
        // a refusal and a hang.
        refuse(request_status::no_target);
    }
}

void proxy_supervisor::on_request_reply(uint64_t cookie, request_status st,
                                        std::string_view reply)
{
    if (!write_frame(worker_proto::frame(
            worker_proto::frame_type::chan_rep,
            worker_proto::encode_chan_reply(cookie, static_cast<uint8_t>(st),
                                            reply)))) {}
}
