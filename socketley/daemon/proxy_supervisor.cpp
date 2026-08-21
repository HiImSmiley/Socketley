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
#include "../shared/shard_target.h"
#include "../shared/worker_protocol.h"

namespace
{

// The descriptor the child finds its control socket on.  Fixed rather than
// passed in argv so there is nothing to parse and nothing to get wrong: the
// child's very first action can be a read.
constexpr int child_control_fd = 3;

// The shared aggregation table, for a runtime that has one.  Four rather than
// three for the reason three is three: a fixed number both sides agree on
// without negotiating, immediately after the control socket, and below anything
// the worker opens for itself.  A child of an unsharded runtime never has this
// descriptor at all, and the worker treats its absence as "not sharded" rather
// than as an error — see proxy_worker's on_config.
constexpr int child_shard_fd = 4;

// And the client-list region; see shard_clients.h.  Five for the reason four is
// four.
constexpr int child_clients_fd = 5;

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
    if (!m_loop)
        return;

    // ── The registration and the ring writer, together and with no early
    //    return between them ────────────────────────────────────────────────
    //
    // A submission carries its owner's token, and one made without a
    // registration has its completion DROPPED rather than delivered — an
    // endpoint that submits before registering never hears back and is deaf
    // for the rest of its life.  That is not hypothetical: it is what the same
    // ordering did in the worker, where register_owner() sat below a
    // create_runtime() that can return null.
    //
    // So both facts are established here, in the one function that is called
    // on every path that gives this object a loop, before spawn() and before
    // any frame is written.  There is no early exit in between to slip past.
    //
    // The writer has no descriptor yet — the child is not forked — and does not
    // need one: it queues, and frame_writer refuses to submit on a negative fd.
    // spawn() hands it the socket, and use_ring()'s flush sends what waited.
    m_owner_token = m_loop->register_owner(this);
    m_writer.use_ring(m_loop, this);
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
    m_on_send_ref = nullptr;
    m_on_stats   = nullptr;

    if (!m_loop)
        return 0;

    // Off the ring before the descriptor goes.  A send still in flight is left
    // to the token count below exactly like the poll is — it was submitted
    // under this owner, so it is one of the things token_inflight() is waiting
    // out — and leave_ring() is what stops a new one being started behind the
    // quarantine's back.
    m_writer.leave_ring();

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

    // POLLIN only.  The write side is on the ring now and a send ends with its
    // own completion, so there is nothing left to want writability for — the
    // mask used to carry POLLOUT whenever a backlog existed, and a backlog is
    // now a send that has not completed yet.
    m_poll_mask  = POLLIN;
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

void proxy_supervisor::on_cqe(struct io_uring_cqe* cqe)
{
    // Two submissions belong to this object now, and they are told apart by
    // the request address rather than by the op type: a type is a shape, and
    // two submissions of the same shape would be indistinguishable the moment
    // a second one exists.
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));

    if (req && m_writer.owns_request(req))
    {
        m_writer.on_send_cqe(cqe->res);

        // A send that failed for a reason that is not going to get better is
        // the child going away, which is close_control()'s business — the same
        // verdict the old ::write reached inline, one turn later.
        if (m_writer.dead())
            close_control();
        return;
    }

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

        // ── The backlog goes with the child it was addressed to ─────────────
        //
        // A supervisor outlives its worker: check_liveness() closes this
        // socket, clears m_in and forks a replacement onto the same object.
        // m_in was cleared there and m_out never was, so whatever the dead
        // child had not taken was still sitting in the buffer when spawn()
        // appended the new child's config — and the new child parsed the dead
        // one's frames first, ahead of its own configuration.
        //
        // That predates this change: the buffer, the clear of m_in beside it
        // and the absence of a clear here are all older than the ring.  It is
        // fixed here rather than left because this is where the descriptor
        // stops being the one those frames were queued for, and because the
        // writer now has to be told the descriptor is gone in any case — see
        // frame_writer::reset() for what an in-flight send does about it.
        m_writer.set_fd(-1);
        m_writer.reset();
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

    // Which of N this child is.  The ONLY field that differs between the N
    // frames one runtime's shards are sent, and the one thing SO_REUSEPORT
    // deliberately does not tell them.  Written into the copy that becomes
    // m_config_json, so a restart replays the same index and the replacement
    // takes the same slot in the shared table.
    effective.shard_index = m_shard_index;

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

        // ─── Two fixed numbers, and the case where one is already taken ─────
        //
        // Both descriptors are placed by dup2, and dup2 destroys whatever was
        // at the destination.  The control socket has always been moved to 3
        // and there is now a second one to place at 4, so the ONE ordering
        // hazard is a socketpair that came back holding 4 already: dup2ing the
        // region onto it would close the control socket, and the child would
        // exec into a process whose only link to the daemon is a memfd.
        //
        // Rare — the daemon holds stdio, its listener and its ring long before
        // any worker is forked — and cheap to make impossible, which is the
        // trade this file makes everywhere else.  Moved out of the way first,
        // then the region, then the control socket, so no placement can undo
        // one that has already happened.
        if ((m_shard_region_fd >= 0 && sv[1] == child_shard_fd)
            || (m_shard_clients_fd >= 0 && sv[1] == child_clients_fd))
        {
            const int moved = ::fcntl(sv[1], F_DUPFD, 16);
            if (moved < 0)
                _exit(127);
            ::close(sv[1]);
            sv[1] = moved;
        }

        // The fifth descriptor, and only for a runtime that has shards.  The
        // memfd is MFD_CLOEXEC in the daemon precisely so that it reaches no
        // child by accident; dup2 clears that flag on the copy, so this is the
        // whole of what makes it reach the ones it should.
        //
        // A failure here is fatal to the child rather than survivable.  The
        // alternative is a shard that serves connections and publishes them
        // nowhere, which is the silent wrong answer this whole mechanism exists
        // to remove — and the supervisor's restart path is the right response.
        //
        // Both regions are placed by the same three lines, because the hazard
        // is the same one: dup2 destroys its destination, and a source that is
        // already sitting on the OTHER region's destination would be destroyed
        // by the placement that has not happened yet.  So each source is moved
        // out of the way first if it collides, and only then are the two placed.
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

    // Before the first write_frame() below.  The writer has been on the ring
    // since set_event_loop(); this is the descriptor it has been waiting for,
    // and anything queued in the meantime goes out on the flush that follows.
    m_writer.set_fd(m_control_fd);

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
// ─── AND WHY THE SEND IS ON THE RING WHILE THE READ IS NOT ──────────────────
//
// Counted, this daemon relaying for a four-shard cache, 240,000 GETs,
// strace -f -qq -c on the daemon process:
//
//     write            359,994      1.500 per GET
//     read               8,373      0.035 per GET  (3,298 EAGAIN)
//     io_uring_enter     1,100      0.005 per GET
//
// The two halves of this socket are not the same problem.  1.500 writes per
// GET is 0.75 crossings times the two hops a crossing makes through the relay,
// and every one of them was its own syscall because a relayed frame is written
// the moment it is routed.  A read is not: one read takes about 43 frames off
// the socket, so the whole read side costs a fortieth of the write side.
//
// The read side is also the half that could not move.  poll() is called from
// await_startup() and await_routes(), which wait on the descriptor with
// ::poll and deliberately do not pump this ring — they run inside a command
// handler that is itself inside a completion being dispatched.  A ring recv
// would make those waits unable to see their own answer without re-entering
// the loop from a position where that is not allowed, and two readers on one
// socket is the alternative.  So the read stays where it is, and the number
// above is the reason that is not a compromise: it is 2.3% of this endpoint's
// blocking syscalls.
//
// What is left of this function is the flush contract frame_writer states at
// use_ring(): the owner submits once per turn.  This owner has no per-turn
// hook — a supervisor is driven by its own completions and by whoever routes a
// frame at it — so it flushes on every write instead, which costs a branch
// while a send is in flight and starts one when none is.  That is the
// coalescing: the frames routed between two completions go out together.
void proxy_supervisor::flush_control()
{
    if (m_control_fd < 0)
        return;

    m_writer.flush();

    // The old inline ::write reached this verdict without a turn; a submission
    // reaches it one completion later.  Checked here as well as in on_cqe so a
    // writer that was already dead when a frame arrived is not left queueing
    // into a socket nobody will take.
    if (m_writer.dead())
        close_control();
}

bool proxy_supervisor::write_frame(const std::string& framed)
{
    if (m_control_fd < 0)
        return false;

    // The cap, the one-per-episode warning and the refusal are frame_writer's
    // now, unchanged in value and in meaning: false still means the child has
    // stopped reading, and serve_deferred still turns that into `overloaded`
    // rather than into a request that vanishes.
    if (!m_writer.write(framed))
        return false;

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

        // ── The frame has to be IN the kernel before we block on the answer ─
        //
        // This wait does not pump the ring — see the note above it — so a send
        // that is only queued in the submission queue would sit there for as
        // long as we wait for the reply to it, which is the deadlock shape:
        // waiting for an answer to a question that was never asked.
        //
        // submit_pending() hands the queue over and dispatches nothing, which
        // is exactly what is safe from here: the child receives the frame
        // because the kernel sends it, and the completion saying how much went
        // is reaped by whoever turns the loop next.
        if (m_loop)
            m_loop->submit_pending();

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

        // Same reason as in await_startup(): this wait does not pump the ring,
        // so the reload frame it is waiting for the answer to has to be handed
        // to the kernel before we block.  Submitting dispatches nothing.
        if (m_loop)
            m_loop->submit_pending();

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
                // `socketley.send(name, msg)` from the worker's script, or —
                // when `name` is the worker's OWN runtime — the sibling half of
                // a broadcast on a sharded one.  Routed by the handler, which
                // is the daemon and holds the map; nothing is answered, because
                // nothing is waiting — see the frame's own note.
                //
                // `this` goes with it so the daemon can leave this shard out
                // when the name is its own: the local delivery already
                // happened out there, and a second copy would reach every one
                // of this shard's clients twice.
                std::string name, message;
                if (m_on_deliver &&
                    worker_proto::decode_deliver_to(payload, name, message))
                    m_on_deliver(this, name, message);
                break;
            }

            case worker_proto::frame_type::send_ref:
            {
                // `self.send(handle, msg)` out there, for a client one of this
                // shard's siblings is holding.  Routed by the handler, which is
                // the daemon and holds every shard's socket.
                conn_ref    ref{};
                std::string message;
                if (m_on_send_ref &&
                    worker_proto::decode_send_ref(payload, ref, message))
                    m_on_send_ref(this, ref, message);
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

bool proxy_supervisor::send_deliver_ref(const conn_ref& ref,
                                       std::string_view message)
{
    return write_frame(worker_proto::frame(
        worker_proto::frame_type::deliver_ref,
        worker_proto::encode_send_ref(ref, message)));
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

    // The same door, one notch finer.
    //
    // A shard-qualified target (`c#3`, see shared/shard_target.h) is how one
    // shard of a runtime reaches another, and the check above cannot see it —
    // `c#3` is not `c`.  A shard naming its OWN index would be posted into the
    // daemon's channel, resolve to this very supervisor, and go straight back
    // down the socket it came from, for ever.
    //
    // The router never produces its own index: cache_instance only crosses when
    // the owner is somebody else.  This is the second lock on that door, the
    // same arrangement on_worker_send_ref makes for a shard asking the daemon
    // to deliver to itself, and for the same reason — a worker built by an
    // older binary must not be able to start two processes handing one request
    // back and forth.
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
