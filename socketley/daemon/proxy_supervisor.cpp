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

#include "../runtime/proxy/proxy_instance.h"
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
    shutdown();
}

void proxy_supervisor::close_control()
{
    if (m_control_fd >= 0)
    {
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

    return true;
}

bool proxy_supervisor::write_frame(const std::string& framed)
{
    if (m_control_fd < 0)
        return false;

    size_t off = 0;
    while (off < framed.size())
    {
        const ssize_t n = ::write(m_control_fd, framed.data() + off, framed.size() - off);
        if (n > 0) { off += static_cast<size_t>(n); continue; }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            // The child is not reading.  Blocking here would stall the daemon's
            // event-loop thread on a process it does not control, so the frame
            // is dropped and said out loud.  Config is the one frame that
            // cannot be dropped safely, and spawn() treats a false here as a
            // failed spawn for exactly that reason.
            LOG_WARN("proxy supervisor: control socket full, frame dropped");
            return false;
        }
        return false;
    }
    return true;
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

            case worker_proto::frame_type::state:
                // Reported for the log, not acted on: the daemon's own record
                // of created/running/stopped is what the CLI is promised, and
                // it is set by the command that caused the transition.  Letting
                // the child move it would mean two writers for one value.
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
