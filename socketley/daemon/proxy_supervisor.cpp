#include "proxy_supervisor.h"

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
    //
    // A backstop now rather than the real severance: retire() does this while
    // the placeholder is still known to be alive, and nulls both pointers, so
    // on every path that goes through it these two blocks are skipped.  They
    // stay for a supervisor destroyed without ever being retired — one that
    // failed to spawn and is dropped on the spot — which has nothing in the
    // ring and nothing to wait for.
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
    //
    // Giving it back is NOT what makes this safe, and it never was.  A dropped
    // completion is still a completion: the loop reads the owner token out of
    // the io_request to decide whether to drop it, and m_poll_req is a member
    // of this object, so that read lands in the storage the delete below is
    // about to release.  retire() is the call that makes the wait possible, and
    // reaching it first is what leaves nothing here to be found.
    // Destroying a supervisor without it — through m_loop still being set at
    // this point — is the path that used to abort the daemon.
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
    // all still known to exist.  The destructor is no longer that moment: it
    // runs whenever the ring finishes, and cmd_remove frees the placeholder a
    // few statements after retiring the supervisor for it — so a destructor
    // clearing the override then reads a runtime_instance that is gone.
    //
    // Dropping the channel registrations here is the same argument in the other
    // direction.  Between retirement and the free this object still answers to
    // its name in the sink table, with a control socket that is closed and a
    // child that has been signalled; a request routed to it in that window
    // could only fail, and a caller would be told the write failed rather than
    // that the runtime is gone.
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

    // Nothing may be delivered to this object once it is retired, and these are
    // the holders that are not a pointer somebody else keeps — they are
    // std::functions this object owns, capturing the handler that is about to
    // put it in the quarantine.
    //
    // All three, not just the publish.  A retired supervisor still has whatever
    // its child sent before the socket closed sitting in m_in, and ingest() can
    // still walk it: a `deliver_to` would route a send for a runtime that is on
    // its way out, and a stats frame would ask the daemon to rebuild and
    // republish the runtime map on behalf of a child it no longer supervises.
    m_on_publish = nullptr;
    m_on_deliver = nullptr;
    m_on_stats   = nullptr;

    if (!m_loop)
        return 0;

    // Cancel the arm and let the descriptor go.  The whole point of the token
    // below is to wait out what is still in the ring, so submitting the
    // withdrawal before asking is what makes the count able to reach zero at
    // all — an arm nobody asked back never reports.
    close_control();

    event_loop* const loop = m_loop;
    const uint32_t    tok  = m_owner_token;

    // Cleared before the deregistration and never set again.  m_loop is what
    // arm_control_poll() tests, so this is what stops a late poll() or
    // flush_control() from putting this object back in the ring behind the
    // quarantine's back — which would restart the wait the caller has already
    // begun, on a count it has already read.
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

// Through the loop, not ::close(), and the tension in that is worth writing
// down because it looks like a reason not to.
//
// The rule first: a descriptor the ring may still name is not the caller's to
// close.  An SQE carries a descriptor NUMBER that the kernel resolves when it
// consumes the SQE — under SQPOLL on another thread, at a moment nothing here
// observes — so closing between submission and consumption does not withdraw
// the operation, it redirects it onto whatever inherits the number.  This class
// arms exactly one thing on this descriptor, the readability poll above, and
// disarm_control_poll() asks for it back — but a cancel is itself an SQE naming
// the same number, and the poll it cancels is still owed one completion when
// this line runs.  So there was a window here, and the number it hands away is
// the one the NEXT worker's socketpair is most likely to be given.
//
// What it cost is smaller than the proxy's version of the same bug: a poll
// watches, it does not read, so a redirected arm reports somebody else's
// readability rather than putting bytes in the wrong stream, and the completion
// is dropped for a deregistered owner.  Small is not none, and it is the same
// mistake — the one this project has paid for more than once.
//
// The argument against was that shutdown() needs this close to be immediate: it
// is the backstop that makes a worker which never reads its `shutdown` frame
// see EOF and exit.  close_fd() holds the number while the ring still owes
// something for it, so the peer does not see EOF until it lets go.
//
// That argument does not survive being measured against what close_fd()
// actually holds for.  The wait is one turn of the loop, not an open-ended one:
// the poll has just been cancelled, its -ECANCELED lands on the next drain, and
// disarm() closes the descriptor from there.  In the commonest case — this
// being called from inside the poll's own completion, on the read of zero bytes
// that says the child is gone — it is not even a turn, because the loop disarms
// as soon as this handler returns.  And EOF is not the only thing on that path:
// shutdown() sends SIGTERM on the next line, and reap_orphan_workers() escalates
// to SIGKILL five seconds later.  A worker wedged badly enough to need the EOF
// is not going to notice a delay measured in microseconds.
//
// So the ownership rule wins on its own terms, and the immediacy requirement is
// still met.  m_loop may be null for a supervisor that never had one, and there
// is nothing to protect against then.
void proxy_supervisor::close_control()
{
    if (m_control_fd >= 0)
    {
        disarm_control_poll();
        if (m_loop)
            m_loop->close_fd(m_control_fd);
        else
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

    // The daemon's ring policy, wherever this runtime asked for none of its own.
    //
    // Before runtimes moved out of the daemon they ran on its event loop, so
    // `daemon --cpus 0-1` and `daemon --no-sqpoll` were theirs by construction.
    // A worker has a loop of its own and learns nothing it is not told, and both
    // settings then go wrong in a way that leaves no trace:
    //
    //   cpus   — the worker inherits the daemon's affinity mask through fork, so
    //            it is pinned in fact while its loop believes every core is
    //            available.  `stats` reported cpus:max for a runtime that could
    //            only ever run on two, and the SQPOLL thread was placed against
    //            a set that was not the real one.
    //   sqpoll — the worker re-reads SOCKETLEY_SQPOLL out of the environment it
    //            inherited, so a daemon started with --no-sqpoll in a shell that
    //            exports it spawned workers with SQPOLL on, against the only
    //            instruction anybody gave.
    //
    // Only where the runtime is silent.  `create --cpus` is a statement about
    // that runtime and outranks the daemon's default, which is the order that
    // already applied when the two shared a loop.
    runtime_config effective = cfg;
    if (m_loop)
    {
        if (effective.cpus.empty() && !m_loop->cpus().all)
            effective.cpus = m_loop->cpus().to_string();

        // Forwarded even when the answer is "off": off is a decision here, and
        // leaving it unsaid lets an inherited environment variable answer in
        // place of the operator.
        if (!effective.sqpoll_set)
        {
            effective.sqpoll_set = true;
            effective.sqpoll     = m_loop->sqpoll_requested();
        }
    }

    // Keep the config so a restart can replay it without going back to disk.
    // The state file is the daemon's record for the operator; this is the
    // daemon's record for the child, and they are written at different moments.
    {
        state_persistence sp{std::filesystem::path{}};
        m_config_json = sp.format_json_pretty(effective);
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

    // A new child has said nothing yet.  Without this a restart would inherit
    // the previous one's report, and await_startup() would answer for a process
    // that no longer exists — most sharply on the restart path, where the child
    // being replaced is one that had reached `running` before it died.
    m_worker_state      = runtime_created;
    m_worker_state_seen = false;

    const int fl = ::fcntl(m_control_fd, F_GETFL, 0);
    if (fl >= 0)
        if (::fcntl(m_control_fd, F_SETFL, fl | O_NONBLOCK) < 0) {}

    if (m_placeholder)
    {
        m_placeholder->set_pid(child);

        // Forked, not listening.  Everything below this line is a frame on its
        // way to a child that has not run a line of its own yet, and the port
        // is bound at the far end of it — so from here until the child says
        // otherwise this runtime is not a group member anybody may be routed
        // to.  See runtime_instance::endpoint_live().
        //
        // Lowered on every spawn and not only the first, which is what covers
        // the restart path: a child that died and is being replaced re-enters
        // exactly this window, and the endpoint table said it was serving
        // throughout the old one.
        m_placeholder->set_endpoint_live(false);
    }

    // ─── What the child has to know BEFORE it reads its config ──────────────
    //
    // The config frame is what makes the worker load its script, and a script's
    // top level runs inside that load.  Everything the top level can ask about
    // therefore has to be in the worker's hands before the config frame is, and
    // these two are the whole of what that means: the runtime map, which
    // socketley.list() and socketley.get() are answered from, and the cluster
    // view, which the four socketley.cluster.* calls are answered from.
    //
    // The cluster view is the one where the order is load-bearing rather than
    // merely better.  Its bindings are refused unless a view is installed, and
    // that decision is taken once, while the bindings are being built — so a
    // view arriving one frame later than the config leaves the four calls
    // refused for the life of that script, and the refusal says the worker
    // cannot answer when it can.  One stream, delivered in order, so writing
    // them first is all it takes.
    //
    // Both are also re-sent here rather than only on the next tick, which is
    // what covers a RESTARTED child: it has a script to run immediately and
    // nothing else would carry these to it until something moved.
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

    // A child forked after the last publish would otherwise route from an empty
    // table until the next membership change, which for a stable daemon may
    // never come.
    //
    // After the config and not before it, unlike the two above: only a proxy is
    // handed an endpoint table and the proxy does not exist until the config has
    // been read, so a table arriving early is stashed rather than applied — see
    // on_endpoints().  The map and the view go into objects that exist from the
    // worker's construction, which is what lets them go first.
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

void proxy_supervisor::send_reload()
{
    // Cleared here rather than when the answer arrives: a worker that reloaded
    // cleanly sends nothing, so "no reload_err since the ask" is the only shape
    // success has, and a stale message from the previous reload would otherwise
    // be reported as this one's.
    m_reload_error.clear();
    if (!write_frame(worker_proto::frame(worker_proto::frame_type::reload, {}))) {}
}

std::string proxy_supervisor::take_reload_error()
{
    // Cleared explicitly rather than left to the move.  A moved-from string is
    // valid but unspecified, and this member's whole meaning is "empty means the
    // reload loaded" — a second read finding something in it would report the
    // previous reload's failure against a reload that worked.
    std::string out = std::move(m_reload_error);
    m_reload_error.clear();
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
    // Nothing has moved since this child was last told.  The comparison is what
    // makes the health tick's unconditional push free on a quiet daemon, and it
    // is a comparison of the ENCODED payload rather than of anything smarter on
    // purpose: it is exactly "would this frame say anything new", with no second
    // idea of what counts as a change to drift from the first.
    if (encoded_payload == m_runtime_map)
        return;

    // No child to write to, so this is what the next one will be handed: spawn()
    // writes the cache before the config frame.  Reached in two ways and right
    // in both — a supervisor that has not forked yet, and one whose child has
    // died and is about to be replaced.
    if (m_control_fd < 0)
    {
        m_runtime_map = encoded_payload;
        return;
    }

    // Otherwise remembered only once it has been queued, which is what makes the
    // dedupe above safe.  Storing it either way would record a payload this
    // child was never sent — write_frame refuses when the backlog is full,
    // meaning the child has stopped reading — and every later push of the same
    // map would then be dropped as a duplicate of a frame that never went.  On a
    // daemon whose membership is settled that is a replica left stale for good.
    if (write_frame(worker_proto::frame(worker_proto::frame_type::runtime_map,
                                        encoded_payload)))
        m_runtime_map = encoded_payload;
}

void proxy_supervisor::send_cluster_view(const std::string& encoded_payload)
{
    // The same three rules as the map above, and for the same reasons: nothing
    // that this child already holds, a cache rather than a write when there is
    // no child yet, and otherwise remembered only once it has been queued.
    //
    // The middle rule is what makes the four cluster calls answerable at all in
    // a script's top level: the cache is what spawn() writes ahead of the config
    // frame, and the config frame is what runs the script.
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

// ─── Waiting for the child's verdict without pumping the ring ───────────────
//
// Three things can end this wait, and all three are read with plain syscalls:
//
//   serving   the child sent `state` carrying running, which on_start() writes
//             only after m_rt->start() has bound the socket.
//   refused   the placeholder is `failed`.  Two paths reach that and both are
//             somebody else's already: ingest() adopts a `state` frame carrying
//             failed, and check_liveness() adopts the exit status of a child
//             that died -- including exit_config_refused, whose whole purpose is
//             to say "not a crash, a configuration I will never accept".
//   timeout   neither, before the bound.
//
// What is deliberately NOT here is a waitpid of its own.  check_liveness() is
// the one place that reaps and the one place that applies the death policy;
// a second reaper would take the child out from under it, and the pid
// bookkeeping and the restart-burst counter would both be reading a corpse
// somebody else buried.  So this calls check_liveness() and reads the result
// off the placeholder, which keeps one writer for the state and one reaper for
// the child.
//
// A restart during the wait is not an ending.  check_liveness() may fork a
// replacement, which leaves the placeholder `running` and m_worker_state_seen
// false; the loop simply goes round again against the new child, still inside
// the same bound.
proxy_supervisor::startup
proxy_supervisor::await_startup(std::chrono::milliseconds bound)
{
    const auto deadline = std::chrono::steady_clock::now() + bound;

    for (;;)
    {
        // Whatever is already buffered, before deciding anything.  On the
        // refusal path the child has usually exited before this is first
        // called, so the frames and the EOF are both sitting in the socket.
        poll();

        if (m_placeholder && m_placeholder->get_state() == runtime_failed)
            return startup::refused;

        if (m_worker_state_seen && m_worker_state == runtime_running)
            return startup::serving;

        // Reaps, applies the policy, and may mark the placeholder failed or
        // fork a replacement.  Checked again at the top of the next turn.
        if (check_liveness())
            continue;

        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
            return startup::pending;

        // Sleep on the descriptor, not on the clock: the answer arrives as a
        // frame, and a poll that ends on it costs the wait nothing it does not
        // have to spend.  Capped so a child that dies without closing its end
        // -- SIGKILL leaves nothing to read -- is still noticed by the
        // check_liveness() above within a tick of the cap rather than at the
        // deadline.
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        int slice = static_cast<int>(std::min<std::chrono::milliseconds::rep>(
            remaining.count(), 20));
        if (slice < 0)
            slice = 0;

        if (m_control_fd >= 0)
        {
            struct pollfd pfd{m_control_fd, POLLIN, 0};
            if (::poll(&pfd, 1, slice) < 0) {}
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

// The reload half of the same idea, and deliberately the same shape: drain what
// is there, decide, then sleep on the descriptor rather than on the clock.
//
// It watches the declaration object the child's frame installs, rather than the
// m_routes_changed flag beside it: that flag belongs to the health tick, which
// consumes it, so a wait resting on it would end or not end depending on
// whether a timer happened to fire first.  A fresh table is allocated for every
// frame, so the pointer changing means "a declaration arrived" even when the
// script's answer turned out identical to the one before it.
//
// Like await_startup() it does not reap.  check_liveness() is called for the
// same reason -- a child that dies mid-reload must end the wait rather than run
// it to the bound -- and it is still the only place that reaps and the only
// place that writes the state.  A false here is not an error the caller has to
// report: the declaration the daemon already holds is still the one in force,
// and cmd_reload_lua publishes that.
bool proxy_supervisor::await_routes(const void* previous,
                                    std::chrono::milliseconds bound)
{
    const auto deadline = std::chrono::steady_clock::now() + bound;

    for (;;)
    {
        poll();

        if (m_placeholder && m_placeholder->worker_routes().get() != previous)
            return true;

        // A child that has gone is one that will never answer.  Checked after
        // the drain above, so a declaration sitting in the socket of a child
        // that has since exited is still taken.
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

        struct pollfd pfd{m_control_fd, POLLIN, 0};
        if (::poll(&pfd, 1, slice) < 0) {}
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
        switch (type)
        {
            case worker_proto::frame_type::stats:
                apply_stats(payload);
                // After the figures are in the placeholder and never before:
                // the handler rebuilds the runtime map out of what every
                // runtime reports, and this child's row has to be the one that
                // has just arrived rather than the one before it.
                if (m_on_stats)
                    m_on_stats();
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

            case worker_proto::frame_type::reload_err:
                // Only sent when a reload failed, and only between the ask and
                // the routes frame that ends the wait for it — so this is the
                // answer to the reload cmd_reload_lua is holding, and it is
                // read back there rather than logged: the worker has already
                // logged it, and the point of the frame is the other terminal.
                m_reload_error = payload;
                break;

            case worker_proto::frame_type::start_err:
                // The same shape one command along: only sent when on_start
                // raised, and only between the `start` frame and the `state`
                // frame that ends await_startup(), so this is the answer to the
                // start cmd_create is holding.  Read back there rather than
                // logged, because the worker has already logged it and the
                // point of the frame is the operator's terminal.
                m_start_error = payload;
                break;

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

            case worker_proto::frame_type::deliver_to:
            {
                // `socketley.send(name, msg)` from the worker's script, for a
                // name that is not its own runtime.  Routed by the handler,
                // which is the daemon and holds the map; nothing is answered,
                // because nothing is waiting — see the frame's own note.
                std::string name, message;
                if (m_on_deliver &&
                    worker_proto::decode_deliver_to(payload, name, message))
                    m_on_deliver(name, message);
                break;
            }

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
                //
                // Remembered either way, which is not the same as adopted.  The
                // paragraph above is about who owns the placeholder's state; it
                // does not say this side has to forget what the child said.
                // await_startup() needs exactly that memory to tell a child that
                // has bound its socket from one that has not answered yet, and
                // it writes nothing on the strength of it.
                if (!payload.empty())
                {
                    m_worker_state =
                        static_cast<runtime_state>(static_cast<uint8_t>(payload[0]));
                    m_worker_state_seen = true;

                    // The one thing only the child can tell us, and the reason
                    // this frame is worth more than a state the daemon already
                    // owns: the listener is up.  Written through to the
                    // placeholder because the endpoint table is built from it
                    // and this is the fact the group filter needs — which is
                    // not the same as adopting the child's state, the value
                    // the paragraph above says has one owner.
                    //
                    // Raised once per transition so the caller republishes: an
                    // address that has become answerable is only useful to the
                    // gateways once they are told.
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
        return;

    // Kept, not applied.  This used to write the six figures straight into the
    // placeholder, which was right while a placeholder stood for exactly one
    // process.  With --shards it stands for N, and N writers of one field means
    // a reader sees whichever shard published most recently instead of the
    // runtime: four shards serving 25 connections each reported 25.
    //
    // The sum is daemon_handler::aggregate_worker_stats()'s to make, and that
    // is where it belongs rather than here: this object cannot reach its
    // siblings and should not be given a way to, because the map that knows
    // which supervisors serve one name is the daemon's.  The stats handler
    // fires immediately after this returns, so the total is rewritten before
    // anything gets the chance to read a stale one.
    //
    // The moment is kept with the figures for the reason it crosses the wire at
    // all: this runs when the daemon gets round to draining, and measuring the
    // age from there rather than from when the counters were read made a frame
    // that had sat unread for a second look new.
    m_last_stats.total_connections  = s.total_connections;
    m_last_stats.total_messages     = s.total_messages;
    m_last_stats.bytes_in           = s.bytes_in;
    m_last_stats.bytes_out          = s.bytes_out;
    m_last_stats.active_connections = s.active_connections;
    m_last_stats.detail             = std::move(s.detail);
    m_last_stats.taken_ns           = static_cast<int64_t>(s.taken_ns);
    m_last_stats.seen               = true;
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
