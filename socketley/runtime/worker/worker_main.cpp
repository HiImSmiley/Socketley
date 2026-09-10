#include "worker_main.h"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "../proxy/proxy_instance.h"
#include "../server/server_instance.h"
#include "../client/client_instance.h"
#include "../../shared/request_channel.h"
#include "../../shared/endpoint_table.h"
#include "../../shared/event_loop.h"
#include "../../shared/logging.h"
#include "../../shared/lua_context.h"
#include "../../shared/runtime_config_apply.h"
#include "../../shared/route_relay.h"
#include "../../shared/runtime_factory.h"
#include "../../shared/type_registry.h"
#include "../../shared/runtime_instance.h"
#include "../../shared/runtime_manager.h"
#include "../../shared/state_persistence.h"
#include "../../shared/frame_writer.h"
#include "../../shared/peer_link.h"
#include "../../shared/shard_mesh.h"
#include "../../shared/shard_target.h"
#include "../../shared/worker_protocol.h"

namespace
{

// How often the worker publishes its figures, defined in worker_protocol.h
// because the daemon coalesces its map pushes to the same period -- and the
// shard table's descriptor number, named on both sides on purpose, because the
// number is the whole of the contract between two processes.
constexpr int worker_shard_fd = 4;

// And the client-list region, on the same contract and named on both sides for
// the same reason.
constexpr int worker_clients_fd = 5;

// The control plane, a second socket because this process has to block on the
// answer and the control socket's writes queue for the ring while its reads
// are a standing recv -- absent is not an error but the refusal an older
// daemon's worker has always had.
constexpr int worker_map_fd = 6;

// The grant channel, read here in the constructor rather than at the point of
// use, because by then this process has a ring and an eventfd of its own and
// one of them is sitting on this number.
constexpr int worker_link_fd = 7;

// And the mesh block, which must agree with proxy_supervisor's
// child_mesh_base.  Whether the block is there at all is read from the config
// and never from the descriptors: with no mesh the loop's own eventfd lands on
// this number, and a worker that probed it armed a recv on its own wakeup and
// then closed it.
constexpr int worker_mesh_base = 8;

constexpr auto stats_interval =
    std::chrono::milliseconds(worker_proto::stats_interval_ms);

// A backstop and not a schedule: a worker with nothing to say has no deadline,
// and poll_completions() has no infinite wait, so thirty seconds is 0.03
// wakeups a second against the cost of sleeping through a frame for ever.
constexpr int idle_wait_ms = 30000;

// The longest the loop will wait when it has no notification it can trust,
// kept as a constant so the fallback and the thing it replaces are visibly the
// same number.
constexpr int ctl_fallback_ms = 20;

// How long a map call may hold this worker's loop, above the daemon's own 2000
// ms bound because timing out cancels nothing -- the create still happens and
// the script is told false for something that succeeded.
constexpr int map_wait_ms = 5000;

// SIGTERM asked for and not yet acted on, caught rather than ignored so the
// shutdown frame and the signal take one path out -- with the default
// disposition the worker died mid-unwind and on_stop never ran.
volatile sig_atomic_t g_term_requested = 0;

// How long an unwind may take before this process stops waiting for itself,
// five seconds because that is already the supervisor's escalation -- what the
// alarm changes is who enforces it when the daemon is what died.
constexpr unsigned worker_term_grace_sec = 5;

extern "C" void worker_on_term(int)
{
    g_term_requested = 1;

    // The flag only ends a worker that reaches the top of its loop, so a
    // wedged one keeps its share of the listening socket, and alarm(2) is
    // async-signal-safe with a default action that terminates.
    ::alarm(worker_term_grace_sec);
}

// ─── Whose worker is this ───────────────────────────────────────────────────
// The creator of my control socket must still be my parent, proved by
// SO_PEERCRED against getppid() at startup and again before the bind, with
// PR_SET_PDEATHSIG holding the rule for the rest of the worker's life -- and
// the signal is SIGKILL because a SIGSTOPped shard runs no handler, made safe
// by clearing it at the one point this process has decided to exit.
pid_t control_socket_creator(int fd)
{
    struct ucred cr{};
    socklen_t    len = sizeof(cr);
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &len) < 0)
        return -1;
    return static_cast<pid_t>(cr.pid);
}

bool claim_current_daemon(int control_fd)
{
    const pid_t creator = control_socket_creator(control_fd);
    if (creator <= 0)
        return false;
    return ::getppid() == creator;
}

// The worker's writer and the shard mesh's links share one bounded-backlog
// writer, because two of them is two places to get the EAGAIN case wrong.
using control_writer = frame_writer;

// Every runtime this process does not hold, as the mirror of
// proxy_supervisor's sink: the request goes out on the control socket, the
// daemon resolves the name, and the answer comes back as a chan_rep.
class remote_sink : public request_sink
{
public:
    explicit remote_sink(control_writer* w) : m_w(w) {}

    void serve_request(std::string_view, std::string& out) override
    {
        // Unreachable because serves_inline() is false, and an answer invented
        // here would be worse than none.
        out.clear();
    }

    bool serves_inline() const override { return false; }

    bool serve_deferred(uint64_t ticket, std::string_view target,
                        std::string_view payload) override
    {
        // The name travels with the request because this process cannot
        // resolve it, and false means the backlog is full, so the channel
        // answers the origin rather than parking a ticket nothing will
        // complete.
        return m_w->write(
            worker_proto::frame(worker_proto::frame_type::chan_req,
                worker_proto::encode_chan_request(ticket, target, payload)));
    }

private:
    control_writer* m_w;
};

// Arming the control fd on this worker's own ring makes the wait end when the
// frame arrives, which took a cross-process `cache set` from 20.00 ms to the
// cost of the command.
class worker : public io_handler, public route_relay::sink,
               public request_origin
{
public:
    explicit worker(int control_fd)
        : m_fd(control_fd), m_writer(control_fd), m_remote(&m_writer)
    {
        // Before the first frame is read, because a runtime_map frame can be
        // the first and writing to that map here would build a runtime that
        // exists in this process alone.
        m_manager.mark_replica();

        // The map sink is installed in the constructor rather than in
        // on_config(), because lua_context decides at binding time whether the
        // four calls are refused and the script's table is built during the
        // config frame's load.
        // Taken here for the reason stated at worker_link_fd: this is the last
        // moment the number can only be what the daemon placed.
        if (::fcntl(worker_link_fd, F_GETFD, 0) >= 0)
            m_link_chan_fd = worker_link_fd;

        if (::fcntl(worker_map_fd, F_GETFD, 0) >= 0)
        {
            m_map_fd = worker_map_fd;
            m_manager.set_map_sink(
                [this](std::string_view op, std::string_view name,
                       std::string_view config, std::string& err) -> bool
                {
                    if (!map_request(op, name, config, err))
                        return false;

                    // A script that stops its own runtime runs on_stop()'s
                    // body here, because the daemon has stopped the
                    // placeholder and this process's object has not -- so the
                    // next line armed a timer that can never fire and was
                    // answered with a live id.
                    if (m_rt && name == m_rt->get_name() &&
                        (op == "stop" || op == "remove"))
                        on_stop();

                    return true;
                });

            // And routing, under the same condition and for the same
            // binding-time reason, because its verbs are frames on the control
            // socket and `open` starts with a question the map socket alone
            // can answer.
            m_manager.set_route_sink(this);
        }
    }

    // The control socket's recv and the control writer's send, told apart by
    // the request address rather than the op type, because two submissions of
    // the same shape are otherwise indistinguishable.
    void on_cqe(struct io_uring_cqe* cqe) override
    {
        auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
        if (!req)
            return;

        if (m_writer.owns_request(req))
        {
            m_writer.on_send_cqe(cqe->res);
            return;
        }

        if (req != &m_ctl_req)
            return;

        // A recv and not a readiness notification, so the bytes are already
        // here and the read that used to follow the poll is what this
        // replaces.
        m_ctl_armed = false;

        const int res = cqe->res;
        if (res > 0)
        {
            m_in.append(m_ctl_buf, static_cast<size_t>(res));
            return;
        }

        if (res == 0)
        {
            m_ctl_eof = true;                 // the daemon closed
            return;
        }

        // Nothing arrived and nothing is wrong: re-armed at the end of the
        // turn, and the wait before it is clamped because m_ctl_armed is false.
        if (res == -EAGAIN || res == -EWOULDBLOCK || res == -EINTR ||
            res == -ECANCELED)
            return;

        // A recv that failed for any other reason is the socket, and the socket
        // is the only thing this worker is reachable through.
        LOG_ERROR("proxy worker: the control socket could not be read");
        m_ctl_eof = true;
    }

    int run()
    {
        // The daemon may die while we are serving, and this makes a write to
        // the closed control socket end the process instead of raising
        // SIGPIPE.
        signal(SIGPIPE, SIG_IGN);

        // Before anything is bound, so the window between the fork and the
        // first frame is covered too.
        {
            struct sigaction sa{};
            sa.sa_handler = worker_on_term;
            sigemptyset(&sa.sa_mask);
            sa.sa_flags = 0;              // no SA_RESTART: a slow poll should
                                          // return so the loop can see the flag
            if (::sigaction(SIGTERM, &sa, nullptr) < 0) {}
        }

        // No ring yet, because io_uring fixes a ring's flags at creation and
        // the config frame is the only thing that tells a worker anything --
        // so on_config() builds the ring.
        set_nonblocking(m_fd);
        send_hello();

        auto last_stats = std::chrono::steady_clock::now();

        // The publish is on-change now rather than a heartbeat, because the
        // counters live in shared memory and an idle worker's turn that
        // delivered no completion cannot have produced anything worth saying
        // -- which gives up only a figure that moves with the clock alone, and
        // every candidate is driven by an SQE in this ring.
        bool stats_dirty = true;

        while (!m_done && !g_term_requested)
        {
            // One drain pass waiting until the next thing this loop owes
            // somebody, because a flat 20 ms was a 50 Hz clock costing 0.13%
            // of a core per idle runtime -- with the fallback constant
            // covering exactly the two states where no arm stands: a
            // submission the ring refused, and an arm whose mask predates what
            // is now being waited for.
            const auto turn_now = std::chrono::steady_clock::now();
            int wait_ms = idle_wait_ms;
            if (stats_dirty)
            {
                const auto since = turn_now - last_stats;
                wait_ms = 0;
                if (since < stats_interval)
                    wait_ms = static_cast<int>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            stats_interval - since).count()) + 1;   // round up:
                                                            // a truncated 0
                                                            // would spin
            }

            // Before the ring exists poll_completions() returns at once
            // whatever timeout it is handed, so the wait comes from a poll on
            // the control socket, which is its own notification.
            if (m_loop.ring_open())
            {
                // The two states the ring cannot end on its own -- no recv
                // standing, or bytes queued with no send standing -- since an
                // in-flight send ends with a completion.
                if (!m_ctl_armed || m_writer.needs_retry())
                    wait_ms = std::min(wait_ms, ctl_fallback_ms);

                // The grant channel too: a refused submission leaves this
                // worker deaf to the link that would end its relaying.
                if (m_link_recv && !m_link_recv->armed())
                    wait_ms = std::min(wait_ms, ctl_fallback_ms);

                // The same two states per link, because a standing recv is
                // ended by a peer's frame and only a submission get_sqe()
                // refused needs a clamp.
                for (const auto& link : m_mesh_links)
                    if (link->needs_wake())
                    {
                        wait_ms = std::min(wait_ms, ctl_fallback_ms);
                        break;
                    }

                // The turn did something exactly when the ring delivered
                // something, taken here rather than inferred from a counter,
                // because a completion that changes nothing visible still ran
                // code in this process.
                if (m_loop.poll_completions(wait_ms) > 0)
                    stats_dirty = true;

                // Dispatched here rather than in on_cqe(), because on_config()
                // is one of these frames and it builds this ring, and the
                // reload and stop handlers reach into the runtime.
                if (!drain_frames())
                    break;
            }
            else
            {
                // No ring yet, so the notification comes from the descriptor
                // itself, which costs nothing measurable in a window before
                // this worker has a runtime, a port or a sibling.
                wait_for_control(wait_ms, m_writer.pending());
                if (!pump_control())
                    break;

                // Unconditionally for the window this branch covers, because
                // there is no runtime to have figures about and the first
                // publish is what says this worker answers for one.
                stats_dirty = true;
            }

            // Whatever the socket would not take last turn, because a reply
            // sitting here is somebody's answer.
            m_writer.flush();
            if (m_writer.dead())
                break;

            // After the drain and not before, because an arm placed while a
            // frame is buffered fires at once and wastes the turn; skipped
            // once the worker has decided to exit.
            if (!m_done)
                arm_control();

            // The same two steps per sibling link, once per turn because a
            // send per frame produces a completion per crossing -- 5,920 ring
            // entries against 61,221 on the control socket -- and
            // unconditional, since a dying link still owes what it has queued.
            for_each_link([](shard_link& link) { link.pump(); });
            if (m_link_recv)
                m_link_recv->pump();

            // Once per turn, because the condition it waits for is a property
            // of this turn and not of any one completion.
            arm_pending_peers();
            reap_retired_peers();

            // And whatever the runtime itself has that no completion returns
            // for, which today is a listener the ring refused to arm.
            if (m_rt)
                m_rt->on_loop_turn();

            // A state the runtime reached on its own, reported as soon as it
            // changes.  send_state() ran on start, stop and config and nowhere
            // else, so a mark_failed() out here was worker-local and the daemon
            // went on printing `Up` -- runtime_instance.cpp names exactly that
            // gap where it calls mark_failed().  One comparison per turn.
            if (m_rt && m_rt->get_state() != m_last_sent_state)
                send_state();

            const auto now = std::chrono::steady_clock::now();
            if (stats_dirty && now - last_stats >= stats_interval)
            {
                // The safety pump is gone with the poll it was watching,
                // because a recv is not a claim about the socket: the bytes
                // are in the completion, and the only way to have no recv
                // standing is a submission the next turn resubmits.

                // Cleared when nothing remains to publish, but never for a
                // frame the writer refused, because the figures are still owed
                // and the flag staying up is what brings this loop back to
                // retry.
                if (push_stats())
                    stats_dirty = false;
                last_stats  = now;
            }

            // This shard's line, once per turn and at the end of it, so every
            // drain's work is counted before the loop comes round -- and every
            // summable counter is stored here rather than at the 34 sites
            // where one moves, because the daemon reads them when it prints.
            if (m_rt && m_rt->shard_stats_table().mapped())
            {
                shard_stats::figures f;
                f.active_connections =
                    static_cast<uint64_t>(m_rt->get_connection_count());
                f.total_connections =
                    m_rt->m_stat_total_connections.load(std::memory_order_relaxed);
                f.total_messages =
                    m_rt->m_stat_total_messages.load(std::memory_order_relaxed);
                f.bytes_in  = m_rt->m_stat_bytes_in.load(std::memory_order_relaxed);
                f.bytes_out = m_rt->m_stat_bytes_out.load(std::memory_order_relaxed);
                m_rt->shard_stats_table().publish(f);
            }
        }

        // Every way out of the loop arrives here, which makes this the one
        // place to give the parent-death kill back, because a check every path
        // has to remember is one a new path will not.
        if (::prctl(PR_SET_PDEATHSIG, 0) < 0) {}

        // Same order the daemon uses: stop the runtime while there is still a
        // ring for teardown() to cancel into, and only then end the ring.
        if (m_rt && m_rt->get_state() == runtime_running)
            m_rt->stop(m_loop);

        // The cancellations stop() just submitted have to be reaped here, or
        // every armed timer stays allocated -- measured at 176 bytes per
        // worker -- and it is bounded at ten milliseconds because the
        // supervisor kills a worker that will not finish anyway.
        for (int i = 0; i < 10; ++i)
            if (m_loop.poll_completions(1) == 0)
                break;

        // The links come off the ring before the ring goes, through die(),
        // which sweeps the crossings each was carrying and answers them
        // `no_target` -- before requests().detach(), which would answer them
        // `dropped` instead.
        for_each_link([](shard_link& link) {
            link.die("this worker is shutting down", /*expected=*/true);
        });

        // Before the ring, like every other owner registration: detach answers
        // whatever is still queued `dropped` and gives the owner token back.
        m_manager.requests().detach();

        // The writer comes off the ring before the ring goes, with a bounded
        // chance for an in-flight send because stop() can still have written a
        // frame, and leave_ring() refuses to guess about one that does not
        // finish.
        for (int i = 0; i < 20 && m_writer.send_in_flight(); ++i)
            m_loop.poll_completions(1);
        m_writer.leave_ring();
        m_writer.flush();

        // A recv, so poll_remove no longer names it, and cancelling by
        // descriptor covers both it and any send leave_ring() gave up on.
        if (m_ctl_armed || m_writer.send_in_flight())
        {
            if (!m_loop.submit_cancel_fd(m_fd)) {}
            m_ctl_armed = false;
        }
        m_loop.deregister_owner(this);
        m_loop.shutdown_ring();

        return m_exit_code;
    }

private:
    static void set_nonblocking(int fd)
    {
        const int fl = fcntl(fd, F_GETFL, 0);
        if (fl >= 0)
            if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {}
    }

    // Block until the control socket has something or will take what is
    // waiting, used only before there is a ring, with POLLOUT asked for only
    // when there is something to send.
    void wait_for_control(int timeout_ms, bool want_write) const
    {
        struct pollfd pfd{m_fd,
                          static_cast<short>(POLLIN | (want_write ? POLLOUT : 0)),
                          0};
        if (::poll(&pfd, 1, timeout_ms) < 0) {}
    }

    // ── The recv that used to be a poll ─────────────────────────────────────
    // A recv rather than a poll plus a read, which took one shard from 50,600
    // write() and 14,984 read() calls to 7 and 9 over 200,000 GETs -- and
    // one-shot rather than multishot, because the re-arm is an SQE and a
    // provided-buffer group on this socket is a trade with no number asking
    // for it.
    void arm_control()
    {
        if (!m_loop.ring_open() || m_ctl_armed)
            return;
        m_ctl_req   = { this, nullptr, m_fd, sizeof(m_ctl_buf), op_read };
        m_ctl_armed = m_loop.submit_read(m_fd, m_ctl_buf, sizeof(m_ctl_buf),
                                         &m_ctl_req);
    }

    void send_hello()
    {
        std::string payload;
        worker_proto::put_u32(payload, static_cast<uint32_t>(::getpid()));
        if (!m_writer.write(worker_proto::frame(worker_proto::frame_type::hello, payload))) {}
    }

    // What the daemon has last been told this runtime's state is.
    runtime_state m_last_sent_state{runtime_created};

    void send_state()
    {
        // Recorded here and not at the call sites, so the per-turn check below
        // and the start/stop/config reports cannot disagree about what the
        // daemon has been told.
        m_last_sent_state = m_rt ? m_rt->get_state() : runtime_created;
        std::string payload;
        payload.push_back(static_cast<char>(static_cast<uint8_t>(m_last_sent_state)));
        if (!m_writer.write(worker_proto::frame(worker_proto::frame_type::state, payload))) {}
    }

    // True when nothing remains to publish, false only for a frame the writer
    // refused, because swallowing that after m_last_pub had been updated
    // recorded a lost frame as delivered.
    bool push_stats()
    {
        // No runtime, so nothing published and nothing changed — and reporting
        // "still owed" here would hold the interval at its floor for a worker
        // that has nothing to say.
        if (!m_rt)
            return true;

        // Built on the event-loop thread, the only one allowed to walk the
        // connection tables, carrying what the daemon cannot compute -- the
        // ring's granted flags and this runtime's own figures -- plus the five
        // counters as the fallback for a worker whose region could not be
        // made.
        worker_proto::stats_wire s;
        s.total_connections  = m_rt->m_stat_total_connections.load(std::memory_order_relaxed);
        s.total_messages     = m_rt->m_stat_total_messages.load(std::memory_order_relaxed);
        s.bytes_in           = m_rt->m_stat_bytes_in.load(std::memory_order_relaxed);
        s.bytes_out          = m_rt->m_stat_bytes_out.load(std::memory_order_relaxed);
        s.active_connections = static_cast<uint64_t>(m_rt->get_connection_count());
        s.detail             = m_rt->stats_ring() + m_rt->stats_lines();

        // The two numbers that make a mesh measurement mean anything, sent
        // unconditionally including by a shard with no links, because the
        // absence of a line made "never connected" indistinguishable from
        // "quiet".
        {
            uint64_t direct = 0, relayed = 0;
            mesh_counts(direct, relayed);
            s.detail += "mesh_links:"   + std::to_string(m_mesh_sinks.size()) + "\n";
            s.detail += "mesh_direct:"  + std::to_string(direct)  + "\n";
            s.detail += "mesh_relayed:" + std::to_string(relayed) + "\n";

            // The same three for other runtimes, separate lines because a
            // sibling crossing and a cross-runtime one are answered by
            // different processes and only one of them has a mesh.
            uint64_t pdirect = 0, prelayed = 0;
            peer_counts(pdirect, prelayed);
            s.detail += "peer_links:"   + std::to_string(m_peer_links.size()) + "\n";
            s.detail += "peer_direct:"  + std::to_string(pdirect)  + "\n";
            s.detail += "peer_relayed:" + std::to_string(prelayed) + "\n";
        }

        // Did anything the daemon can see actually move, which now decides
        // whether there is a publish at all rather than how far it backs off.
        const bool changed =
            !m_have_last
            || s.total_connections  != m_last_pub.total_connections
            || s.total_messages     != m_last_pub.total_messages
            || s.bytes_in           != m_last_pub.bytes_in
            || s.bytes_out          != m_last_pub.bytes_out
            || s.active_connections != m_last_pub.active_connections
            || s.detail             != m_last_pub.detail;

        // Only when it changed, because the daemon's copy already says the
        // last thing that was true -- which is why the heartbeat could be
        // removed rather than slowed.
        if (!changed)
            return true;

        if (!m_writer.write(worker_proto::frame(worker_proto::frame_type::stats,
                                                 worker_proto::encode_stats(s))))
            return false;

        // Committed only once the frame is queued, because recording it first
        // made a refused frame permanent: the next interval compared against
        // figures the daemon never received.
        m_last_pub  = std::move(s);
        m_have_last = true;
        return true;
    }

    // Returns false when the control socket is gone, which is the worker's
    // instruction to exit: a proxy whose supervisor has died has nobody to
    // report to and nobody to stop it.
    worker_proto::stats_wire m_last_pub{};
    bool m_have_last{false};

    // Bytes off the descriptor for the one window with no ring to read them
    // with, which under load is not reached at all.
    bool pump_control()
    {
        char buf[4096];
        for (;;)
        {
            const ssize_t n = ::read(m_fd, buf, sizeof(buf));
            if (n > 0)
            {
                m_in.append(buf, static_cast<size_t>(n));
                continue;
            }
            if (n == 0)
                return false;                       // daemon closed
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;                              // nothing more for now
            return false;
        }
        return drain_frames();
    }

    // Whole frames out of m_in, where false is the instruction to exit, with
    // the EOF test first and stopping before dispatch because acting on a
    // frame from a daemon that has gone would be a new behaviour.
    bool drain_frames()
    {
        if (m_ctl_eof)
            return false;

        worker_proto::frame_type type{};
        uint16_t                 ver = 0;
        std::string              payload;
        bool                     fatal = false;

        while (worker_proto::take_frame(m_in, type, ver, payload, fatal))
            handle(type, payload);

        if (fatal)
        {
            LOG_ERROR("proxy worker: malformed control frame, exiting");
            return false;
        }
        return true;
    }

    void handle(worker_proto::frame_type type, const std::string& payload)
    {
        switch (type)
        {
            case worker_proto::frame_type::config:    on_config(payload);    break;
            case worker_proto::frame_type::deliver_ref: on_deliver_ref(payload); break;
            case worker_proto::frame_type::route_down: on_route_down(payload); break;
            case worker_proto::frame_type::endpoints: on_endpoints(payload); break;
            case worker_proto::frame_type::runtime_map: on_runtime_map(payload); break;
            case worker_proto::frame_type::cluster:   on_cluster_view(payload); break;
            case worker_proto::frame_type::cluster_ev: on_cluster_event(payload); break;
            case worker_proto::frame_type::publish:   on_publish(payload);   break;
            case worker_proto::frame_type::publish_interest:
                // Narrowing only: true is what this process starts with, so a
                // daemon that never sends this leaves the old behaviour intact.
                m_publish_interest = !payload.empty() && payload[0] != '0';
                break;
            case worker_proto::frame_type::chan_req:  on_chan_req(payload);  break;
            case worker_proto::frame_type::chan_rep:  on_chan_rep(payload);  break;
            case worker_proto::frame_type::deliver:   on_deliver(payload);   break;
            case worker_proto::frame_type::start:     on_start();            break;
            case worker_proto::frame_type::stop:      on_stop();             break;
            case worker_proto::frame_type::reload:    on_reload(payload);    break;
            case worker_proto::frame_type::shutdown:  m_done = true;         break;

            // Anything else is a frame this build predates or one that only
            // travels the other way, skipped and not fatal, which is the point
            // of the length in the header.
            default: break;
        }
    }

    void on_config(const std::string& json)
    {
        runtime_config cfg;
        state_persistence sp{std::filesystem::path{}};   // parser only; writes nothing
        if (!sp.parse_json_string(json, cfg))
        {
            LOG_ERROR("proxy worker: could not parse config");
            return;
        }

        // A second config is an `edit` on a runtime that is already serving.
        // Rebuilding here is not on the table -- a port is a bound socket, TLS
        // is a context the open handshakes used, backends are open connections
        // -- so what a live worker takes is the set of limits it reads at the
        // moment it uses them, and the rest keeps waiting for the next start.
        //
        // The frame used to be dropped with a warning, which is why `edit
        // NAME --max-connections 1` answered 0, made `show` report 1, and left
        // the worker holding the port enforcing 10.
        if (m_rt)
        {
            apply_live_config(*m_rt, cfg);
            LOG_INFO("worker: applied an edit to the running runtime "
                     "(connection, rate and idle limits; the rest waits for a restart)");
            return;
        }

        // The ring is built between the parse and the init, which is the only
        // window where the config has been read and nothing has submitted --
        // otherwise `--cpus 0-1` pinned no thread while `stats` reported
        // cpus:0-1.
        if (!cfg.cpus.empty())
        {
            cpu_set_spec spec;
            std::string  err;
            if (parse_cpu_set(cfg.cpus, spec, err))
                m_loop.set_cpus(spec);
            else
                LOG_WARN("proxy worker: unusable --cpus in its config, ignored");
        }
        // Guarded on ring_open() rather than on reaching here once, because a
        // config that built a ring and then failed to build a proxy must not
        // get a second ring from the next frame.
        if (!m_loop.ring_open() && !m_loop.init())
        {
            LOG_ERROR("proxy worker: could not initialise io_uring");
            m_done = true;
            return;
        }

        // Registered with the ring here and not further down, because a
        // submission made without a registration has its completion dropped --
        // for the recv that means the worker is deaf to its daemon for the
        // rest of its life.
        m_loop.register_owner(this);

        // And the frames going the other way go on the ring too, after the
        // registration and not before.
        m_writer.use_ring(&m_loop, this);

        // A type name this binary cannot resolve is refused rather than
        // repaired, because str_to_type falls back to runtime_server and a
        // custom worker must not build a server nobody asked for.
        if (!cfg.type_name.empty() && cfg.type_name != type_to_string(cfg.type))
        {
            const std::string why = "this worker binary has no runtime type "
                                    "called \"" + cfg.type_name + "\"";
            LOG_ERROR(why.c_str());
            if (!m_writer.write(worker_proto::frame(
                    worker_proto::frame_type::config_err, why))) {}
            m_exit_code = worker_proto::exit_config_refused;
            m_done      = true;
            return;
        }

        // The type comes from the frame the daemon sent rather than from this
        // file, so a worker is not a proxy worker any more.
        auto inst = create_runtime(cfg.type, cfg.name);
        if (!inst)
        {
            // A name this process interned off a map but never registered a
            // factory for lands here, which for a custom binary means
            // register_type was not called before run().
            const std::string why = "this worker binary cannot build a \"" +
                                    cfg.type_name + "\" runtime";
            LOG_ERROR(why.c_str());
            if (!m_writer.write(worker_proto::frame(
                    worker_proto::frame_type::config_err, why))) {}
            m_exit_code = worker_proto::exit_config_refused;
            m_done      = true;
            return;
        }
        m_owned = std::move(inst);
        m_rt    = m_owned.get();
        m_proxy = (cfg.type == runtime_proxy)
                    ? static_cast<proxy_instance*>(m_owned.get()) : nullptr;

        m_rt->set_event_loop(&m_loop);
        m_rt->set_id(cfg.id);

        // Both halves from the same file the daemon's restore path uses,
        // because the hand-written list here was missing seventeen fields and
        // reported nothing, every setter it did call having succeeded.
        apply_common_config(*m_rt, cfg);
        apply_typed_config(*m_rt, cfg);

        // Adopted before the script loads, because a top level may call
        // self.connections() and an unattached runtime answers with a fraction
        // -- and tested with looks_like_region() rather than "is fd 4 open",
        // since adopt() takes ownership and a guess closes somebody else's
        // descriptor.
        if (shard_stats::looks_like_region(worker_shard_fd))
        {
            if (!m_rt->shard_stats_table().adopt(worker_shard_fd,
                                                 m_rt->get_shard_index()))
                LOG_WARN("proxy worker: the shared shard table could not be "
                         "mapped; this shard will answer only for itself");
        }

        // And the client list, adopted here with the same guard, because a top
        // level may call self.clients().
        if (cfg.shards > 1 && ::fcntl(worker_clients_fd, F_GETFD, 0) >= 0)
        {
            if (!m_rt->shard_clients_table().adopt(worker_clients_fd,
                                                   m_rt->get_shard_index(),
                                                   cfg.shards))
                LOG_WARN("proxy worker: the shared client list could not be "
                         "mapped; this shard will list only its own clients");

            // Where a message for a sibling's connection goes, which the
            // daemon resolves from the ref itself, so it is one hop to one
            // process.
            m_rt->set_ref_sink(
                [this](const conn_ref& r, std::string_view message)
                {
                    if (!m_writer.write(worker_proto::frame(
                            worker_proto::frame_type::send_ref,
                            worker_proto::encode_send_ref(r, message)))) {}
                });
        }

        // ── The shard mesh ─────────────────────────────────────────────────
        // Built before the channel is attached, because these sinks must be in
        // the table by the first request, with the links themselves attached
        // once the ring exists -- and a child the daemon did not wire relays
        // rather than errors.
        if (cfg.shards > 1 && cfg.mesh_wired)
        {
            const uint32_t me = m_rt->get_shard_index();
            for (uint32_t j = 0; j < cfg.shards; ++j)
            {
                if (j == me)
                    continue;
                const int fd = worker_mesh_base + static_cast<int>(j);
                if (::fcntl(fd, F_GETFD, 0) < 0)
                    continue;
                m_mesh_links.push_back(std::make_unique<shard_link>(
                    fd, j, &m_manager.requests(), &worker_serve_mesh, this));
            }
            if (!m_mesh_links.empty())
                LOG_INFO(("shard mesh: " + std::to_string(m_mesh_links.size())
                          + " direct link(s) to siblings").c_str());
        }

        // ── the channel, both directions ────────────────────────────────────
        // The manager's map is a replica that answers no requests, so the sink
        // table is built by hand from this worker's own runtime, with its own
        // name registered so a request for it is served here rather than
        // routed back through the daemon.

        m_manager.requests().attach(m_loop);
        if (auto* sink = m_rt->as_request_sink())
            m_manager.requests().register_sink(cfg.name, sink);
        m_manager.requests().set_default_sink(&m_remote);

        // `name#j` for every sibling this process has a link to, registered
        // after the default sink, so a sibling with no link is absent and
        // falls through to the daemon.
        for (auto& link : m_mesh_links)
        {
            link->attach(m_loop);
            m_mesh_sinks.push_back(std::make_unique<mesh_sink>(link.get(), &m_remote));
            m_manager.requests().register_sink(
                shard_target(cfg.name, link->peer()), m_mesh_sinks.back().get());
        }

        // ── Links to other runtimes ────────────────────────────────────────
        // After the default sink, like the mesh's, so a peer this worker has
        // not been introduced to is absent from the table and falls through to
        // the daemon -- which is also what tells the daemon to introduce them.
        if (m_link_chan_fd >= 0)
        {
            m_link_recv = std::make_unique<socketley::peer_link::receiver>(
                m_link_chan_fd,
                [this](std::string peer, int fd) {
                    // The one cargo on this channel that is not a peer: an
                    // operator's terminal, so notify_interactive() can reach
                    // it from here.  Before this the descriptor was registered
                    // on the DAEMON's placeholder, whose m_interactive_fds
                    // nothing ever fires -- every message a client sent went
                    // to a list in the wrong process.
                    if (peer == socketley::peer_link::interactive_marker)
                    {
                        if (m_rt)
                            m_rt->add_interactive_fd(fd);
                        else
                            ::close(fd);
                        return;
                    }
                    adopt_peer_link(std::move(peer), fd);
                });
            if (!m_link_recv->attach(m_loop))
                LOG_WARN("peer links: the grant channel could not be armed; "
                         "crossings to other runtimes will relay through the daemon");
        }
        m_rt->set_runtime_manager(&m_manager);

        // ── and a send on its way out ───────────────────────────────────────
        // The mirror of the daemon's deliver sink, answering this worker's own
        // runtime locally rather than through a round trip -- with the sibling
        // fan-out in one place, guarded on the shard count inside
        // fanout_to_siblings() so a one-shard worker writes no frame at all.
        m_rt->set_sibling_sink(
            [this](std::string_view message)
            {
                if (!m_writer.write(worker_proto::frame(
                        worker_proto::frame_type::deliver_to,
                        worker_proto::encode_deliver_to(m_rt->get_name(),
                                                        message)))) {}
            });

        m_manager.set_deliver_sink(
            [this](std::string_view name, std::string_view message) -> bool
            {
                if (m_rt && name == m_rt->get_name())
                {
                    // The local half stays local, because a round trip through
                    // the daemon would make the commonest send in a worker's
                    // script the slowest one.
                    deliver_local(message);

                    // And the half that is not local, which did not exist
                    // while a runtime was one process: `socketley.send` to
                    // one's own name reached a quarter of the clients on four
                    // shards.
                    m_rt->fanout_to_siblings(message);
                    return true;
                }
                return m_writer.write(worker_proto::frame(
                    worker_proto::frame_type::deliver_to,
                    worker_proto::encode_deliver_to(name, message)));
            });

        // ── and a publish on its way out ────────────────────────────────────
        // The mirror of the publish frame this worker receives, out of the
        // process first and the local runtime second, because a subscriber may
        // call back into the manager and a frame already written cannot be
        // affected.
        m_manager.set_publish_sink(
            [this](std::string_view cache_name, std::string_view channel,
                   std::string_view message)
            {
                // Skipped when the daemon has said there is nobody on the
                // other side, because encode_publish() and frame() each copy
                // the whole payload and write() copies it a third time -- and
                // on a busy channel the backlog is full, so all three copies
                // are made on the way to being dropped.
                if (m_publish_interest &&
                    !m_writer.write(worker_proto::frame(
                        worker_proto::frame_type::publish,
                        worker_proto::encode_publish(cache_name, channel, message)))) {}

                // The daemon fans this back out to every worker EXCEPT this
                // one, so delivering here is not a duplicate — it is the only
                // delivery this process gets.
                if (m_rt)
                    m_rt->on_publish_dispatch(cache_name, channel, message);
            });

        // A script that does not load is a configuration this worker cannot
        // serve, so it exits with exit_config_refused rather than relaying
        // with none of the filters, routes or callbacks the operator wrote.
        lua_diag::clear();
        if (!cfg.lua_script.empty() && !m_rt->load_lua_script(cfg.lua_script))
        {
            std::string why = lua_diag::text();
            if (why.empty())
                why = "the script did not load";
            // The reason is deliberately not repeated here, because it is
            // already in this worker's stderr and now travels up the control
            // socket, and a third copy made it appear twice in the daemon's
            // log.
            LOG_ERROR("proxy worker: lua script did not load; refusing to serve "
                      "without it (the script's own error is above)");

            // Up the control socket as well as into the log, written before
            // m_done so the frame is queued while the writer still runs and
            // outlives this process in the socket.
            if (!m_writer.write(worker_proto::frame(
                    worker_proto::frame_type::config_err, why))) {}

            m_exit_code = worker_proto::exit_config_refused;
            m_done      = true;
            return;
        }

        // A table that arrived before the config is held and applied here, and
        // the route declaration goes up once and only when there is something
        // to send.
        if (const auto* lctx = m_rt->lua(); lctx && lctx->has_routes())
        {
            if (!m_writer.write(worker_proto::frame(
                    worker_proto::frame_type::routes,
                    worker_proto::encode_routes(lctx->declared_routes())))) {}
        }

        if (m_pending_endpoints)
        {
            // Only a proxy routes by name, so only a proxy is handed the table.
            if (m_proxy) m_proxy->set_endpoints(std::move(m_pending_endpoints));
            m_pending_endpoints.reset();
        }

        send_state();
    }

    // The daemon's map decoded into the manager, so every reader works out
    // here exactly as it does in the daemon -- with this worker's own runtime
    // present as a replica, because putting the live object in would deliver
    // every PUBLISH to it twice.
    void on_runtime_map(const std::string& payload)
    {
        std::vector<worker_proto::runtime_wire> wire;
        if (!worker_proto::decode_runtime_map(payload, wire))
        {
            LOG_WARN("proxy worker: malformed runtime map, keeping the previous one");
            return;
        }

        std::vector<runtime_manager::replica_entry> entries;
        entries.reserve(wire.size());
        for (const auto& w : wire)
        {
            // The type arrives by name and is interned to a local id, so a
            // registered type this binary cannot build still shows up under
            // its own name -- with a state this build has no name for dropped
            // rather than cast, because a runtime reported as the wrong kind
            // is worse than one not reported.
            runtime_type wtype;
            if (!type_registry::intern(w.type, wtype) ||
                w.state > static_cast<uint8_t>(runtime_failed))
            {
                LOG_WARN("proxy worker: runtime map entry of an unknown kind, skipped");
                continue;
            }

            runtime_manager::replica_entry e;
            e.name        = w.name;
            e.type        = wtype;
            e.state       = static_cast<runtime_state>(w.state);
            e.port        = w.port;
            e.connections = w.connections;
            e.owner       = w.owner;
            e.group       = w.group;
            entries.push_back(std::move(e));
        }

        m_manager.install_replica(entries);

        if (logger::g_level <= log_debug)
        {
            std::string msg = "proxy worker: runtime map replica now holds "
                            + std::to_string(entries.size()) + " runtime(s)";
            LOG_DEBUG(msg.c_str());
        }
    }

    // The cluster view, installed on lua_context because it is a property of
    // the process, held by shared_ptr and never mutated -- and an empty daemon
    // name is a withdrawal that clears it so the four calls refuse again.
    void on_cluster_view(const std::string& payload)
    {
        auto view = std::make_shared<cluster_view>();
        if (!worker_proto::decode_cluster_view(payload, *view))
        {
            LOG_WARN("proxy worker: malformed cluster view, keeping the previous one");
            return;
        }

        if (view->daemon_name.empty())
        {
            lua_context::set_cluster_view(nullptr);
            LOG_DEBUG("proxy worker: cluster view withdrawn");
            return;
        }

        const size_t remote = view->remote.size();
        lua_context::set_cluster_view(std::move(view));

        if (logger::g_level <= log_debug)
        {
            std::string msg = "proxy worker: cluster view installed, "
                            + std::to_string(remote) + " remote daemon(s)";
            LOG_DEBUG(msg.c_str());
        }
    }

    void on_endpoints(const std::string& payload)
    {
        std::vector<worker_proto::endpoint_wire> names, groups;
        worker_proto::route_decl_wire name_routes, group_routes;
        if (!worker_proto::decode_endpoints(payload, names, groups,
                                            name_routes, group_routes))
        {
            LOG_WARN("proxy worker: malformed endpoint table, keeping the previous one");
            return;
        }

        auto tbl = std::make_shared<endpoint_table>();
        for (const auto& e : names)
            tbl->set_name(e.name, runtime_endpoint{e.host, e.port, e.unix_paths});
        for (const auto& e : groups)
            tbl->add_to_group(e.name, runtime_endpoint{e.host, e.port, e.unix_paths});
        for (auto& [n, rt] : name_routes)
            tbl->set_name_routes(n, std::move(rt));
        for (auto& [g, rt] : group_routes)
            tbl->set_group_routes(g, std::move(rt));

        // Immutable from here, exactly as on the daemon side, with the braces
        // load-bearing: without them the `else` bound to the inner `if` and a
        // table arriving before the config was dropped instead of stashed.
        if (!m_rt)
            m_pending_endpoints = std::move(tbl);   // no runtime yet; keep it
        else if (m_proxy)
            m_proxy->set_endpoints(std::move(tbl)); // only a proxy routes by name
        // else: a runtime that does not route.  Nothing to hand it.
    }

    // A publish delivered through the same entry point an in-process dispatch
    // uses and dropped when there is no proxy yet -- and a request from
    // another runtime, whose payload is handed over untouched and whose ticket
    // goes back with the answer, on this turn or a later one.
    static mesh_verdict worker_serve_mesh(void* ctx, shard_link* from,
                                          uint64_t ticket,
                                          std::string_view target,
                                          std::string_view payload,
                                          std::string& reply)
    {
        auto* self = static_cast<worker*>(ctx);
        if (!self || !self->m_rt)
            return mesh_verdict::refused;
        auto* sink = self->m_rt->as_request_sink();
        if (!sink)
            return mesh_verdict::refused;
        if (sink->serves_inline())
        {
            sink->serve_request(payload, reply);
            return mesh_verdict::served;
        }
        return self->defer_request(sink, ticket, from->serial(), target, payload)
             ? mesh_verdict::deferred
             : mesh_verdict::refused;
    }

    // A request the runtime answers on a later turn, parked on this worker's
    // own channel so the answer comes back through on_request_reply() with a
    // cookie naming the socket it goes out on.  False means nothing was taken
    // and the caller answers no_target itself.
    bool defer_request(request_sink* sink, uint64_t wire_ticket,
                       uint64_t link_serial, std::string_view target,
                       std::string_view payload)
    {
        auto& ch = m_manager.requests();
        const uint64_t cookie = m_next_deferred++;
        const uint64_t ticket = ch.park(this, cookie);
        if (ticket == 0)
            return false;
        m_deferred.emplace(cookie, deferred_reply{wire_ticket, link_serial});
        if (sink->serve_deferred(ticket, target, payload))
            return true;
        ch.withdraw(ticket);
        m_deferred.erase(cookie);
        return false;
    }

    // The runtime is done with a request that came in from outside, and the
    // answer leaves the way the request arrived.
    void on_request_reply(uint64_t cookie, request_status st,
                          std::string_view reply) override
    {
        const auto it = m_deferred.find(cookie);
        if (it == m_deferred.end())
            return;
        const deferred_reply to = it->second;
        m_deferred.erase(it);

        if (to.link_serial == 0)
        {
            if (!m_writer.write(worker_proto::frame(
                    worker_proto::frame_type::chan_rep,
                    worker_proto::encode_chan_reply(
                        to.wire_ticket, static_cast<uint8_t>(st), reply)))) {}
            return;
        }

        // A link that went while the answer was in flight answered its
        // asker's tickets as it died, so there is nobody left to tell.
        if (shard_link* link = find_link(to.link_serial))
            link->send_reply(to.wire_ticket, st, reply);
    }

    shard_link* find_link(uint64_t serial)
    {
        shard_link* found = nullptr;
        for_each_link([&](shard_link& link)
        {
            if (link.serial() == serial)
                found = &link;
        });
        return found;
    }

    // Every link this worker holds, siblings and other runtimes alike, so the
    // three places the loop touches them cannot come to disagree about which
    // kinds there are.
    template <typename F>
    void for_each_link(F&& f)
    {
        for (auto& link : m_mesh_links)
            f(*link);
        for (auto& e : m_peer_links)
            if (e.link)
                f(*e.link);
    }

    // One link to another runtime's process, as the daemon handed it over.
    // Registering under the peer's NAME is the whole change: the request
    // channel then finds this sink instead of falling through to the default
    // one, which is the socket to the daemon.
    void adopt_peer_link(std::string peer, int fd)
    {
        if (peer.empty() || fd < 0)
            return;
        if (m_rt && peer == m_rt->get_name())
        {
            // The daemon refuses this too; said here as well because a link to
            // oneself would answer every request by asking itself for it.
            ::close(fd);
            return;
        }

        // One grant at a time per peer.  A worker that never falls quiet keeps
        // relaying, so the daemon keeps offering, and without this every offer
        // would leave behind a link attached to the ring that nothing can free.
        for (const auto& e : m_peer_links)
            if (e.name == peer && !e.live)
            {
                ::close(fd);
                return;
            }

        // An earlier LIVE link to the same peer is left in place and in the
        // table: it is either still carrying, or dead and relaying, and both
        // are answers.  arm_pending_peers() retires it at the moment the new
        // one takes over, which is a moment with nothing in flight.
        peer_entry e;
        e.name = peer;
        e.link = std::make_unique<shard_link>(fd, 0, &m_manager.requests(),
                                              &worker_serve_mesh, this,
                                              "runtime " + peer,
                                              &worker_serve_route);
        if (!e.link->attach(m_loop))
        {
            // Not fatal: an unattached link never carries and the requests
            // keep relaying, which is what was happening anyway.
            LOG_WARN(("peer links: could not arm the link to " + peer
                      + "; crossings keep relaying").c_str());
        }
        e.sink = std::make_unique<mesh_sink>(e.link.get(), &m_remote);
        m_peer_links.push_back(std::move(e));
    }

    // A link is two routes to one runtime, and the moment it starts being used
    // is the moment they both have traffic on them: a request handed to the
    // daemon is ~12 us behind one sent direct, so a `get` posted after the
    // switch can be answered before a `set` posted just before it.
    //
    // So the switch waits for a turn with nothing outstanding anywhere -- no
    // queued request and no parked ticket -- at which point there is nothing
    // for a direct crossing to overtake.  A worker that never falls quiet
    // never switches, and keeps exactly the behaviour it has today.
    void arm_pending_peers()
    {
        if (m_peer_links.empty())
            return;

        bool any = false;
        for (const auto& e : m_peer_links)
            if (!e.live) { any = true; break; }
        if (!any)
            return;

        auto& ch = m_manager.requests();
        if (ch.parked_count() != 0 || ch.pending() != 0)
            return;

        // The names waiting, taken before anything is erased.
        //
        // This was a range-for over m_peer_links with an inner loop erasing
        // from the SAME vector and `e` held across it.  erase() moves the
        // later elements down and destroys the last slot -- and that is always
        // the slot `e` named, because adopt_peer_link() pushes a fresh grant
        // BEHIND the live link it replaces, so the entry being erased is
        // always at the lower index.  The three statements after the inner
        // loop then read and wrote a moved-from entry: the replacement never
        // got live = true, its sink was never registered -- register_sink
        // refuses an empty name -- and the log line printed no runtime at all.
        // Crossings to that peer went on relaying through the daemon for the
        // rest of the worker's life, which is the behaviour a fresh link
        // exists to end.
        std::vector<std::string> pending;
        for (const auto& e : m_peer_links)
            if (!e.live && e.sink)
                pending.push_back(e.name);

        for (const std::string& peer : pending)
        {
            // Found afresh, because the pass below moves the table under
            // itself.  At most two entries share a name -- an older live one
            // and this grant -- since adopt_peer_link() refuses a second grant
            // while a pending one exists.
            size_t keep = m_peer_links.size();
            for (size_t i = 0; i < m_peer_links.size(); ++i)
                if (!m_peer_links[i].live && m_peer_links[i].sink
                    && m_peer_links[i].name == peer)
                {
                    keep = i;
                    break;
                }
            if (keep == m_peer_links.size())
                continue;

            // Any earlier link to the same runtime leaves the table first, or
            // register_sink would replace it while its object still owns the
            // name it was registered under.  By index, with nothing held
            // across the erase.
            for (size_t i = 0; i < m_peer_links.size(); )
            {
                if (i == keep || m_peer_links[i].name != peer)
                {
                    ++i;
                    continue;
                }
                peer_entry& victim = m_peer_links[i];
                if (victim.sink)
                    ch.drop_sink(victim.sink.get());
                if (victim.link)
                    victim.link->die("replaced by a fresh link", /*expected=*/true);
                m_retired_peers.push_back(std::move(victim));
                m_peer_links.erase(m_peer_links.begin()
                                   + static_cast<std::ptrdiff_t>(i));
                // The survivor moved down with everything above the hole, and
                // `i` stays put because the element that slid into this slot
                // has not been looked at yet.
                if (keep > i)
                    --keep;
            }

            peer_entry& e = m_peer_links[keep];
            ch.register_sink(e.name, e.sink.get());
            e.live = true;
            LOG_INFO(("peer links: " + e.name + " is now one socket away").c_str());
        }
    }

    // A link retired by arm_pending_peers() is held until the ring has
    // finished with it, and it used to be held FOR EVER: the vector was
    // pushed to and never read except to sum its counters.  Every peer
    // restart -- and the supervisor's policy is restart -- left behind a
    // 16 KiB read buffer, a shard_link and a mesh_sink, so a cache that fell
    // a thousand times cost its server 16 MiB.
    //
    // owner_inflight() reaching zero without a deregistration is exactly the
    // licence to free the storage, which event_loop.h says in those words.
    // The counters are folded into a running total first, because `stats`
    // reports crossings over the life of the runtime and a freed link's share
    // of them is not less true for the link being gone.
    void reap_retired_peers()
    {
        if (m_retired_peers.empty())
            return;

        // Once the owner table has run out, handlers share an identity and a
        // zero here proves nothing -- so nothing is freed, and the leak is
        // back to what it was rather than becoming a use-after-free.
        if (m_loop.owner_table_full())
            return;

        for (auto it = m_retired_peers.begin(); it != m_retired_peers.end(); )
        {
            if (it->link && m_loop.owner_inflight(it->link.get()) != 0)
            {
                ++it;
                continue;
            }
            if (it->sink)
            {
                m_retired_direct  += it->sink->stat_direct();
                m_retired_relayed += it->sink->stat_relayed();
            }
            it = m_retired_peers.erase(it);
        }
    }

    // A routing frame that came over a link rather than down from the daemon,
    // applied by the same function either way.
    static void worker_serve_route(void* ctx, std::string_view payload)
    {
        auto* self = static_cast<worker*>(ctx);
        if (self)
            self->on_route_down(std::string(payload));
    }

    // A live link to `peer`, or null.  Not gated on the sink table's `live`
    // flag: that gate exists for requests, which have no order between them
    // and therefore need a quiet moment, while a routed connection is pinned
    // to one path for its whole life and needs no moment at all.
    shard_link* live_peer_link(std::string_view peer)
    {
        for (auto& e : m_peer_links)
            if (e.name == peer && e.link && e.link->alive())
                return e.link.get();
        return nullptr;
    }

    // The link to `peer` for a connection this ref names, which for a SHARDED
    // peer is not the same question as "a link to that name".  Each shard of a
    // sharded runtime holds its own link to this process, and the daemon named
    // them `peer#k` because N links under one bare name are N answers to one
    // question.  conn_ref carries the minting shard in the top six bits of its
    // serial, so the ref itself says which one.
    //
    // One pass and no allocation: this runs per frame on a pinned connection,
    // and building the qualified name would put a string on that path.
    shard_link* live_peer_link_for(std::string_view peer, const conn_ref& ref)
    {
        const uint32_t want = conn_ref_shard(ref);
        shard_link* bare = nullptr;
        for (auto& e : m_peer_links)
        {
            if (!e.link || !e.link->alive())
                continue;
            if (e.name.size() > peer.size() + 1 &&
                e.name.compare(0, peer.size(), peer.data(), peer.size()) == 0 &&
                e.name[peer.size()] == '#')
            {
                uint32_t k = 0;
                const char* first = e.name.data() + peer.size() + 1;
                const char* last  = e.name.data() + e.name.size();
                if (std::from_chars(first, last, k).ec == std::errc{} && k == want)
                    return e.link.get();
            }
            else if (!bare && e.name.size() == peer.size() &&
                     e.name.compare(0, peer.size(), peer.data(), peer.size()) == 0)
            {
                // The unsharded peer, and the fallback for a ref whose shard
                // has no link of its own.
                bare = e.link.get();
            }
        }
        return bare;
    }

    // Which way this connection's frames go, decided once and kept.
    //
    // The decision cannot be made per frame: a link is ~12 us faster than the
    // daemon, so a frame sent direct would overtake one sent a moment earlier
    // the long way, and a routed connection is a stream where that is a
    // corruption rather than a reordering.  Pinned per conn_ref, it cannot
    // happen -- and the one permitted change, direct to relay after a link
    // dies, is safe in the direction it goes: the slow path cannot overtake
    // the fast one.
    enum : uint8_t { pin_direct = 1, pin_relay = 2 };

    shard_link* route_path(std::string_view to, const conn_ref& ref)
    {
        const auto it = m_route_pin.find(ref);
        if (it != m_route_pin.end())
            return it->second == pin_direct ? live_peer_link_for(to, ref) : nullptr;

        shard_link* link = live_peer_link_for(to, ref);
        m_route_pin.emplace(ref, link ? pin_direct : pin_relay);
        return link;
    }

    // Crossings by route, told apart from the mesh's because the two answer
    // different questions: one is about shards of this runtime, the other
    // about other runtimes entirely.
    void peer_counts(uint64_t& direct, uint64_t& relayed) const
    {
        direct = relayed = 0;
        for (const auto& e : m_peer_links)
            if (e.sink)
            {
                direct  += e.sink->stat_direct();
                relayed += e.sink->stat_relayed();
            }
        for (const auto& e : m_retired_peers)
            if (e.sink)
            {
                direct  += e.sink->stat_direct();
                relayed += e.sink->stat_relayed();
            }
        // And the ones already freed, whose crossings happened all the same.
        direct  += m_retired_direct;
        relayed += m_retired_relayed;
    }

    // Crossings by route summed over this shard's links, reported because the
    // relay fallback makes a mesh that never connects look exactly like one
    // that made no difference.
    void mesh_counts(uint64_t& direct, uint64_t& relayed) const
    {
        direct = relayed = 0;
        for (const auto& sk : m_mesh_sinks)
        {
            direct  += sk->stat_direct();
            relayed += sk->stat_relayed();
        }
    }

    void on_chan_req(const std::string& payload)
    {
        worker_proto::chan_request_wire q;
        if (!worker_proto::decode_chan_request(payload, q))
            return;   // a frame this build cannot read is skipped, not fatal

        // request_status::no_target when there is nothing to ask, which the
        // daemon cannot know because the placeholder exists whether or not
        // this worker built its runtime.
        uint8_t     st = 1;   // no_target
        std::string reply;
        if (m_rt)
        {
            if (auto* sink = m_rt->as_request_sink())
            {
                // A runtime that answers on a later turn writes its chan_rep
                // from on_request_reply() with the daemon's ticket carried
                // through, so nothing is written here unless it was not even
                // taken.
                if (!sink->serves_inline())
                {
                    if (defer_request(sink, q.ticket, 0, q.target, q.payload))
                        return;
                }
                else
                {
                    sink->serve_request(q.payload, reply);
                    st = 0;       // ok
                }
            }
        }

        if (!m_writer.write(worker_proto::frame(worker_proto::frame_type::chan_rep,
                          worker_proto::encode_chan_reply(q.ticket, st, reply)))) {}
    }

    // The answer to something this worker's runtime asked, whose ticket this
    // process issued, so the two namespaces never meet and neither needs a
    // tag.
    void on_chan_rep(const std::string& payload)
    {
        worker_proto::chan_reply_wire p;
        if (!worker_proto::decode_chan_reply(payload, p))
            return;

        m_manager.requests().complete_deferred(
            p.ticket, static_cast<request_status>(p.status), p.payload);
    }

    // The only place in this process that blocks its own event loop, bounded
    // by map_wait_ms, at the same cost socketley.http() already imposes for a
    // round trip three orders of magnitude longer.
    bool map_request(std::string_view op, std::string_view name,
                     std::string_view config, std::string& err)
    {
        if (m_map_fd < 0)
        {
            err = "this daemon does not serve map calls from a worker";
            return false;
        }

        // Ticketed because frames interleave in one direction too: a reply to a
        // call that already gave up is still in the socket, and reading it as
        // the answer to this one would report another call's verdict.
        const uint64_t ticket = ++m_map_ticket;

        const std::string out = worker_proto::frame(
            worker_proto::frame_type::map_req,
            worker_proto::encode_map_request(ticket, op, name, config));

        const auto deadline = std::chrono::steady_clock::now()
                            + std::chrono::milliseconds(map_wait_ms);

        if (!map_write(out, deadline))
        {
            err = "the daemon could not be reached";
            return false;
        }

        for (;;)
        {
            // Whatever is already buffered, before deciding anything — the same
            // shape proxy_supervisor::await_startup uses, for the same reason:
            // the answer may already be here.
            worker_proto::frame_type type{};
            uint16_t                 ver   = 0;
            std::string              payload;
            bool                     fatal = false;

            while (worker_proto::take_frame(m_map_in, type, ver, payload, fatal))
            {
                if (type != worker_proto::frame_type::map_rep)
                    continue;

                uint64_t    t  = 0;
                bool        ok = false;
                std::string reason;
                if (!worker_proto::decode_map_reply(payload, t, ok, reason))
                    continue;
                if (t != ticket)
                    continue;   // an answer to a call that has already given up

                err = std::move(reason);
                return ok;
            }

            if (fatal)
            {
                LOG_ERROR("proxy worker: malformed map reply; closing the "
                          "control plane");
                close_map();
                err = "the daemon sent an answer this build cannot read";
                return false;
            }

            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline)
            {
                // Said as what it is, because the daemon may still be doing
                // the work and a script told "it failed" would be told
                // something this side cannot know.
                err = "the daemon did not answer within "
                    + std::to_string(map_wait_ms) + " ms";
                return false;
            }

            struct pollfd pfd{m_map_fd, POLLIN, 0};
            const int slice = static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - now).count());
            const int r = ::poll(&pfd, 1, slice);
            if (r < 0)
            {
                if (errno == EINTR)
                    continue;
                close_map();
                err = "the control plane could not be waited on";
                return false;
            }
            if (r == 0)
                continue;       // the deadline is tested at the top

            char          buf[4096];
            const ssize_t n = ::recv(m_map_fd, buf, sizeof(buf), MSG_DONTWAIT);
            if (n > 0)
            {
                m_map_in.append(buf, static_cast<size_t>(n));
                continue;
            }
            if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
                continue;

            // Zero is the daemon letting go and anything else is the socket,
            // so every later call says so at once rather than waiting five
            // seconds.
            close_map();
            err = "the daemon closed the control plane";
            return false;
        }
    }

    // The request out, bounded by the same deadline the wait is, because a
    // full socketpair buffer means the daemon has stopped reading.
    bool map_write(const std::string& frame,
                   std::chrono::steady_clock::time_point deadline)
    {
        size_t off = 0;
        while (off < frame.size())
        {
            const ssize_t n = ::send(m_map_fd, frame.data() + off,
                                     frame.size() - off,
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
                const auto now = std::chrono::steady_clock::now();
                if (now >= deadline)
                    return false;

                struct pollfd pfd{m_map_fd, POLLOUT, 0};
                const int slice = static_cast<int>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        deadline - now).count());
                if (::poll(&pfd, 1, slice) < 0 && errno != EINTR)
                    return false;
                continue;
            }

            close_map();
            return false;
        }
        return true;
    }

    // The control plane is gone, and the sink stays installed so every later
    // call is refused truthfully by the m_map_fd test at the top of
    // map_request().
    void close_map()
    {
        if (m_map_fd >= 0)
        {
            ::close(m_map_fd);
            m_map_fd = -1;
        }
        m_map_in.clear();
    }

    // `socketley send` reaching the process that holds the connections, with
    // the same two calls and the same mode test cmd_send() makes on an
    // in-process runtime.
    void on_deliver(const std::string& message)
    {
        deliver_local(message);
    }

    // The two calls cmd_send() makes, reached from both a `deliver` frame and
    // this worker's own script, in one body so the two cannot disagree about
    // what `send` does to a runtime in `in` mode.
    void deliver_local(std::string_view message)
    {
        if (!m_rt || m_rt->get_state() != runtime_running)
            return;

        switch (m_rt->get_type())
        {
            case runtime_server:
            {
                auto* srv = static_cast<server_instance*>(m_rt);
                if (srv->get_mode() != mode_in)
                    srv->broadcast(message);
                break;
            }
            case runtime_client:
            {
                auto* cli = static_cast<client_instance*>(m_rt);
                if (cli->get_mode() != client_mode_in)
                    cli->lua_send(message);
                break;
            }
            default:
                break;   // send is a server/client verb; cmd_send says so
        }
    }

    // A message for one of this shard's connections sent by a sibling, through
    // write_to_ref(), which already checks that the name is ours, still
    // resolves, and names the connection it was minted for.
    void on_deliver_ref(const std::string& payload)
    {
        if (!m_rt || m_rt->get_state() != runtime_running)
            return;

        conn_ref    ref{};
        std::string message;
        if (!worker_proto::decode_send_ref(payload, ref, message))
        {
            LOG_WARN("proxy worker: malformed deliver_ref frame, dropped");
            return;
        }

        auto* srv = m_rt->as_server();
        if (!srv)
            return;   // only a server has clients named this way
        if (!srv->write_to_ref(ref, message))
            LOG_DEBUG("proxy worker: a sibling's message named a connection "
                      "this shard no longer has");
    }

    // A connection being routed here, or a message for one this runtime routed
    // away coming back, with which of the five it is carried on the frame.
    void on_route_down(const std::string& payload)
    {
        std::string            to, frm, msg;
        worker_proto::route_op op{};
        conn_ref               ref{};
        if (!worker_proto::decode_route_frame(payload, to, frm, op, ref, msg))
        {
            LOG_WARN("proxy worker: malformed route frame, dropped");
            return;
        }

        if (!m_rt || m_rt->get_state() != runtime_running)
            return;

        // Against m_rt's own name and not the manager's map, because the map
        // out here holds a replica of this runtime, which is not the object
        // holding the connections.
        if (to != m_rt->get_name())
        {
            LOG_WARN("proxy worker: a routing frame named another runtime; "
                     "dropped");
            return;
        }

        auto* srv = m_rt->as_server();
        if (!srv)
            return;   // only a server routes or is routed to

        switch (op)
        {
            case worker_proto::route_op::open:
                // Refused here is not refused at the origin, which was told
                // yes from the map, so the unwind travels back as a `drop` --
                // one path, already tested.
                if (srv->accept_routed(ref, frm) < 0)
                    post(frm, to, worker_proto::route_op::drop, ref, {});
                break;
            case worker_proto::route_op::data:
                srv->deliver_routed(ref, msg);
                break;
            case worker_proto::route_op::close:
                srv->release_routed(ref);
                break;
            case worker_proto::route_op::write:
                if (!srv->write_to_ref(ref, msg))
                    LOG_DEBUG("proxy worker: a routed message named a "
                              "connection this runtime no longer has");
                break;
            case worker_proto::route_op::drop:
                srv->drop_route(ref);
                break;
            case worker_proto::route_op::broadcast:
                // Unconditional, with `--mode in` deliberately not consulted,
                // because that flag says whether socketley.send reaches this
                // runtime and not whether a sub-server may answer its clients.
                srv->broadcast(msg);
                break;
            case worker_proto::route_op::forget:
                // `frm` is the runtime that went away rather than one that
                // asked for something, named because it is the kind of
                // difference a reader supplies from the lines above it.
                srv->forget_runtime(frm);
                // And its pins, which neither verb that erases them reaches:
                // forget_route_pin() answers to close and drop, and a peer
                // that went away sends neither.  conn_ref carries the minting
                // runtime in `owner`, so the departed name names them all.
                forget_pins_of(frm);
                break;
        }

        // The other side of forget_route_pin's job: a route ends for both
        // processes, and only one of them sent the frame that ended it.
        forget_route_pin(op, ref);
    }

    // Everything this runtime does to another leaves here as a frame, `open`
    // included, so the pin below is made by the first frame of a connection
    // and every later one follows it.
    void post(std::string_view to, std::string_view frm,
              worker_proto::route_op op, const conn_ref& ref,
              std::string_view payload) override
    {
        const std::string frame =
            worker_proto::encode_route_frame(to, frm, op, ref, payload);

        // A broadcast names no connection, so there is no stream for a faster
        // frame to overtake and no ref to pin the decision to; it keeps the
        // daemon's leg, which is also the only one that reaches a peer this
        // worker has no link to.
        const bool pinnable = ref.valid() &&
                              op != worker_proto::route_op::broadcast;

        if (pinnable)
            if (shard_link* link = route_path(to, ref))
                if (link->send_route(frame))
                {
                    forget_route_pin(op, ref);
                    return;
                }

        // Either no link, or one that gave up holding this very frame -- and
        // the daemon's leg is slower, so a frame that changes route here
        // arrives after the ones that went direct rather than before them.
        if (pinnable)
            m_route_pin[ref] = pin_relay;

        if (!m_writer.write(worker_proto::frame(
                worker_proto::frame_type::route_up, frame))) {}
        forget_route_pin(op, ref);
    }

    // Every pin for connections a departed runtime minted.  Without it the map
    // grew by one entry per routed connection that ended in a `forget` and
    // never shrank.
    void forget_pins_of(std::string_view runtime_id)
    {
        if (runtime_id.empty() || m_route_pin.empty())
            return;
        const uint64_t owner = conn_owner_key(runtime_id);
        for (auto it = m_route_pin.begin(); it != m_route_pin.end(); )
            it = (it->first.owner == owner) ? m_route_pin.erase(it) : std::next(it);
    }

    // A route that has ended takes its pin with it, on whichever side sent the
    // frame that ended it.
    void forget_route_pin(worker_proto::route_op op, const conn_ref& ref)
    {
        if (op == worker_proto::route_op::close || op == worker_proto::route_op::drop)
            m_route_pin.erase(ref);
    }

    // The map's verdict first, up the only descriptor this process may block
    // on, and then the open as a frame on the connection's own path -- not
    // dispatched by the daemon, whose leg into the target is a second socket
    // that the first `data` over a link was seen to overtake.
    bool open(std::string_view target, const conn_ref& ref,
              std::string_view origin, std::string& err) override
    {
        if (!map_request("route", target, {}, err))
            return false;
        post(target, origin, worker_proto::route_op::open, ref, {});
        return true;
    }

    void forget(std::string_view) override
    {
        // Nothing, structurally: this is called from runtime_manager::stop and
        // ::remove, both of which refuse in a replica, and the daemon is what
        // tells everyone.
    }

    // One cluster event as the daemon resolved it, because a script that only
    // reads the snapshot can never see a change it slept through -- and all
    // three callbacks fired nowhere before this frame existed.
    void on_cluster_event(const std::string& payload)
    {
        if (!m_rt || m_rt->get_state() != runtime_running)
            return;

        cluster_ev_wire w;
        if (!worker_proto::decode_cluster_event(payload, w))
        {
            LOG_WARN("proxy worker: malformed cluster event, dropped");
            return;
        }

        if (auto* lua = m_rt->lua())
            lua->dispatch_cluster_event(w);
    }

    void on_publish(const std::string& payload)
    {
        if (!m_rt)
            return;

        worker_proto::publish_wire p;
        if (!worker_proto::decode_publish(payload, p))
        {
            LOG_WARN("proxy worker: malformed publish frame, dropped");
            return;
        }

        m_rt->on_publish_dispatch(p.cache_name, p.channel, p.message);
    }

    void on_start()
    {
        // A worker that has decided to exit must not bind anything on the way
        // out, because start and config arrive together and without the guard
        // it took the port and then exited.
        if (m_done || !m_rt || m_rt->get_state() == runtime_running)
            return;

        // The second ownership check, at the bind, because a bind is what
        // joins the SO_REUSEPORT group and everything since the fork is time
        // the daemon can die in -- refused rather than deferred, since there
        // is nothing left to wait for.
        if (!claim_current_daemon(m_fd))
        {
            LOG_ERROR("proxy worker: the daemon that forked this worker is gone; "
                      "refusing to bind");
            m_done      = true;
            m_exit_code = 2;
            return;
        }

        if (!m_rt->start(m_loop))
            LOG_ERROR("proxy worker: proxy failed to start");

        // A raise in on_start does not stop this runtime serving, but `create
        // -s` is holding the operator's terminal, so the reason is written
        // before send_state(), which ends the daemon's wait.
        if (const std::string& why = m_rt->last_on_start_error(); !why.empty())
        {
            LOG_WARN(("proxy worker: " + why).c_str());
            if (!m_writer.write(worker_proto::frame(
                    worker_proto::frame_type::start_err, why))) {}
        }

        send_state();
    }

    void on_stop()
    {
        if (!m_rt || m_rt->get_state() != runtime_running)
            return;
        m_rt->stop(m_loop);
        send_state();
    }

    // `reload-lua` reached this runtime, and the answer goes back
    // unconditionally -- unlike on_config() -- because an empty frame is what
    // withdraws a declaration the script has removed.
    void on_reload(std::string_view lua_path)
    {
        if (!m_rt)
            return;

        // A path on the frame replaces the one this worker was spawned with.
        // Without it, `socketley edit NAME -r` -- dump, editor, import,
        // reload-lua -- reloaded the script the worker already had, because
        // import changes the path on the PLACEHOLDER and nothing carried it
        // down.  Empty means "keep yours", which is what a plain `reload-lua`
        // sends.
        if (!lua_path.empty() && lua_path != m_rt->get_lua_script_path())
            if (!m_rt->load_lua_script(lua_path))
                LOG_WARN("proxy worker: the new script path did not load; "
                         "the previous script stays in force");

        if (m_rt->get_lua_script_path().empty())
            return;
        // A script that will not compile leaves the previous one in force, so
        // the declaration below is still the right answer, but the reason goes
        // up the control socket too, and the warning no longer claims
        // survival, which is true of only one of the two ways here.
        lua_diag::clear();
        if (!m_rt->reload_lua_script())
        {
            std::string why = lua_diag::text();
            if (why.empty())
                why = "the script did not load";
            LOG_WARN(("proxy worker: reload-lua did not complete: " + why).c_str());
            if (!m_writer.write(worker_proto::frame(
                    worker_proto::frame_type::reload_err, std::move(why)))) {}
        }
        send_routes();
    }

    void send_routes()
    {
        const auto* lctx = m_rt ? m_rt->lua() : nullptr;
        route_table decl;
        if (lctx && lctx->has_routes())
            decl = lctx->declared_routes();
        if (!m_writer.write(worker_proto::frame(
                worker_proto::frame_type::routes,
                worker_proto::encode_routes(decl)))) {}
    }

    int                                    m_fd;
    event_loop                             m_loop;
    // Before m_remote, which holds a pointer to it.
    control_writer                         m_writer;
    std::vector<std::unique_ptr<shard_link>> m_mesh_links;
    std::vector<std::unique_ptr<mesh_sink>>  m_mesh_sinks;

    // ── Links to other runtimes' processes ─────────────────────────────────
    // The same two objects the mesh uses, keyed by a runtime name instead of a
    // shard index, and arriving one at a time on the grant channel rather than
    // all at once at the fork -- two runtimes are created at different
    // moments, and there is no instant at which both processes exist and
    // neither has started.
    struct peer_entry
    {
        std::string                 name;
        std::unique_ptr<shard_link> link;
        std::unique_ptr<mesh_sink>  sink;

        // Whether this link is in the sink table yet.  See arm_pending_peers()
        // for what has to be true first, which is the whole reason a grant and
        // its first use are two separate moments.
        bool                        live{false};
    };
    std::vector<peer_entry> m_peer_links;

    // A replaced link is kept rather than freed: its registration is still on
    // the ring, and a dropped completion reads the owner token out of the
    // object it names.
    std::vector<peer_entry> m_retired_peers;

    // What the retired links carried before they were freed, so `stats` keeps
    // reporting crossings over the life of the runtime.
    uint64_t m_retired_direct{0};
    uint64_t m_retired_relayed{0};

    int m_link_chan_fd{-1};
    std::unique_ptr<socketley::peer_link::receiver> m_link_recv;

    // One entry per routed connection this worker has sent a frame for, gone
    // when the route closes; bounded by the routes that are open, which is
    // what the server's own table is bounded by.
    std::unordered_map<conn_ref, uint8_t, conn_ref_hash> m_route_pin;
    remote_sink                            m_remote;

    // Where a deferred answer goes back out, by the cookie the channel hands
    // back: the control socket when the link serial is 0, else the link it
    // came in on.
    struct deferred_reply
    {
        uint64_t wire_ticket{0};
        uint64_t link_serial{0};
    };
    std::unordered_map<uint64_t, deferred_reply> m_deferred;
    uint64_t                                     m_next_deferred{1};
    // A replica of the daemon's map and a live channel, declared before the
    // runtime so it outlives it: a runtime revokes its origin as it is
    // destroyed and that call needs a channel that is still there.
    runtime_manager                        m_manager;
    std::unique_ptr<runtime_instance>       m_owned;
    // The runtime this worker owns and the same pointer narrowed when it is a
    // proxy, with m_proxy only for the two things only a proxy has.
    runtime_instance*                      m_rt{nullptr};
    proxy_instance*                        m_proxy{nullptr};
    std::shared_ptr<const endpoint_table>  m_pending_endpoints;
    std::string                            m_in;
    io_request                             m_ctl_req{};
    bool                                   m_ctl_armed{false};
    // Where the ring's recv puts the frame, 16 KiB rather than the read loop's
    // 4096 because a recv does not go round again and a short buffer is a
    // second completion and a second turn.
    char                                   m_ctl_buf[16 * 1024];
    // The daemon closed, or the recv failed for a reason that will not get
    // better, set in on_cqe() and acted on by drain_frames().
    bool                                   m_ctl_eof{false};
    bool                                   m_done{false};

    // Whether a publish leaving this process has anywhere to go, which only
    // the daemon can see.  True until told otherwise, because the failure that
    // costs a message is sending too little and the one that costs cycles is
    // sending too much.
    bool                                   m_publish_interest{true};
    int                                    m_exit_code{0};

    // ── The control plane ───────────────────────────────────────────────────
    // -1 when this daemon does not serve map calls, never armed on the ring
    // and never touched from on_cqe, because the whole point is a descriptor
    // the loop does not own.
    int                                    m_map_fd{-1};
    std::string                            m_map_in;
    uint64_t                               m_map_ticket{0};
};

} // namespace

int worker_main(int control_fd)
{
    if (control_fd < 0)
        return 2;

    // Ask the kernel to signal on the parent's death first and only then check
    // the parent, because a daemon that died before the prctl produces no
    // signal and the getppid() check is what catches that window.
    if (::prctl(PR_SET_PDEATHSIG, SIGKILL) < 0) {}

    if (!claim_current_daemon(control_fd))
        return 2;

    // Before the first line this process might log, because a worker reads no
    // configuration file and every LOG_DEBUG out here would otherwise be
    // unreachable.
    inherit_log_level();

    // Before any interpreter exists, because it decides what one is built
    // with: this process has no map of runtimes and says so rather than
    // answering nothing.
    lua_context::set_worker_process(true);
    // The same fact in the bit that survives a SOCKETLEY_NO_LUA build, read by
    // the --shards placement rule, which would otherwise refuse every shard
    // the daemon had just accepted.
    set_worker_process(true);

    worker w(control_fd);
    return w.run();
}
