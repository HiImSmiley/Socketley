#include "proxy_worker.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "proxy_instance.h"
#include "../server/server_instance.h"
#include "../client/client_instance.h"
#include "../../shared/request_channel.h"
#include "../../shared/endpoint_table.h"
#include "../../shared/event_loop.h"
#include "../../shared/logging.h"
#include "../../shared/lua_context.h"
#include "../../shared/runtime_config_apply.h"
#include "../../shared/runtime_factory.h"
#include "../../shared/runtime_instance.h"
#include "../../shared/runtime_manager.h"
#include "../../shared/state_persistence.h"
#include "../../shared/frame_writer.h"
#include "../../shared/shard_mesh.h"
#include "../../shared/shard_target.h"
#include "../../shared/worker_protocol.h"

namespace
{

// How often the worker publishes its figures.  Short enough that `stats` and
// the metrics endpoint are answering about the present, long enough that a busy
// proxy is not spending its event loop building strings: the detail text is
// produced by get_stats(), which walks the connection tables.
//
// The number itself is in worker_protocol.h now, because the daemon needs it
// too: these frames are where the connection counts in the runtime map come
// from, and the daemon coalesces its map pushes to the same period.
// The shared shard table, at the number proxy_supervisor::spawn dup2'd it onto.
// Named twice on purpose — the daemon's constant is in proxy_supervisor.cpp and
// this is the worker's — because the two sides are different processes and the
// number is the whole of the contract between them; a header shared for one
// integer would hide that.  If these ever disagree, the worker finds no
// descriptor and reports that it will answer only for itself, which is the
// loudest a mismatch here can be made without inventing a handshake.
constexpr int worker_shard_fd = 4;

// And the client-list region; see shard_clients.h.  Same contract, same reason
// it is named on both sides rather than shared through a header.
constexpr int worker_clients_fd = 5;

// And the mesh block, which must agree with proxy_supervisor's
// child_mesh_base: slot j is this shard's link to shard j, and the slot at its
// own index is never placed.  Absent is the ordinary case — an unsharded
// runtime, or one the daemon could not mesh — and it means "relay", not
// "error".  See shared/shard_mesh.h.
constexpr int worker_mesh_base = 8;

constexpr auto stats_interval =
    std::chrono::milliseconds(worker_proto::stats_interval_ms);

// ─── The ceiling on a wait that nothing is waiting for ──────────────────────
//
// Once the figures moved into shared memory the worker owes nobody a
// heartbeat: the counters are summed by whoever prints them and the text that
// is still pushed is pushed when it CHANGES.  A worker with an empty ring and
// nothing to say therefore has no deadline at all, and the honest wait is
// "until something happens".
//
// poll_completions() has no such argument — a non-positive timeout means peek
// and return — so the wait is a long finite one instead.  Thirty seconds is
// 0.03 wakeups a second, which is under a thousandth of the 50 Hz this loop
// used to run at and under a hundredth of the 4 Hz that replaced it.
//
// It is a backstop and not a schedule.  Nothing is known to need it: every
// state in which the ring cannot end this wait on its own is enumerated at the
// wait itself and each one clamps to ctl_fallback_ms.  It is here because that
// enumeration is a claim about code that will keep changing, and the cost of
// being wrong about it — a worker that sleeps through a frame for ever — is
// out of proportion to 0.03 wakeups a second.
constexpr int idle_wait_ms = 30000;

// The longest the worker's loop will wait when it has no notification it can
// trust — the two states named at the wait in run().  It is the constant that
// wait used to use unconditionally; keeping it here rather than inlining it is
// so the fallback and the thing it replaces are visibly the same number.
constexpr int ctl_fallback_ms = 20;

// SIGTERM asked for, and not yet acted on.
//
// The supervisor's shutdown() writes a shutdown frame, closes the socket and
// signals, in that order and without waiting — the daemon's event-loop thread
// does not block on a child.  With the default disposition the signal won this
// race: the worker died where it stood, mid-unwind, and everything stop() does
// on the way out was skipped.  What that cost was visible from outside as a Lua
// `on_stop` callback that never ran for a runtime in a worker and always ran
// for one in the daemon, for the same `socketley stop`.
//
// Caught rather than ignored: the flag ends the loop on its next turn, which is
// the same path the shutdown frame takes, so there is one way out and not two.
// A worker that will not unwind is not left running — the supervisor escalates
// to SIGKILL five seconds after the SIGTERM.
volatile sig_atomic_t g_term_requested = 0;

// How long an unwind may take before this process stops waiting for itself.
//
// Five seconds because that is already the bound: reap_orphan_workers()
// escalates a SIGTERM to SIGKILL five seconds later, so a worker that has not
// finished by then is killed today.  What the alarm changes is who enforces it
// — the daemon cannot, when the daemon is what died — and the note above
// claim_current_daemon() is where the reason for needing that lives.
constexpr unsigned worker_term_grace_sec = 5;

extern "C" void worker_on_term(int)
{
    g_term_requested = 1;

    // The flag above is read at the top of run()'s loop, so it only ends a
    // worker that reaches the top of its loop.  One that does not — wedged in a
    // callback, or blocked — keeps its share of the listening socket, and after
    // PR_SET_PDEATHSIG below that is precisely the case this signal is being
    // used to answer: the daemon is gone and there is nobody left to escalate.
    //
    // alarm(2) is async-signal-safe and SIGALRM's default action terminates, so
    // this needs no second handler and cannot itself wedge.  Re-arming on a
    // repeated SIGTERM is deliberate: each ask restarts the grace period, which
    // is what the supervisor's own escalation does.
    ::alarm(worker_term_grace_sec);
}

// ─── Whose worker is this ───────────────────────────────────────────────────
//
// SO_REUSEPORT shares a port between any number of sockets and does not ask
// where they came from.  A worker that outlived the daemon which forked it
// therefore goes on taking its share of the connections arriving at that port,
// served by a build nobody believes is running.  With one worker per runtime
// that shows up as "the proxy is serving the wrong thing"; with --shards N it
// becomes "one request in N+1 is served by the wrong thing", which is the same
// defect made quiet.
//
// The proof of ownership is the kernel's rather than the wire's.  SO_PEERCRED
// on a socketpair reports the pid of the process that CREATED it — the daemon,
// at the instant of the fork — and that is a credential this process cannot
// forge, cannot inherit from anyone else's socket, and a dead daemon cannot
// renew.  So the rule is: the creator of my control socket must still be my
// parent.  A worker whose daemon has gone has been reparented, getppid() stops
// matching, and it refuses to serve.
//
// Checked at two moments, for two different failures:
//
//   * at startup, immediately after the PR_SET_PDEATHSIG in worker_claim(),
//     which is what makes that pair race-free — if the daemon died before the
//     prctl the kernel will never signal us, and this is what notices;
//   * immediately before the listening socket is bound, in on_start().  A fork
//     that has not bound yet is harmless; the instant it binds it is in the
//     REUSEPORT group and taking traffic, so that instant is the one worth
//     gating, and everything between the fork and it is time the daemon can
//     die in.
//
// PR_SET_PDEATHSIG then makes the rule hold for the rest of the worker's life
// instead of only at those two instants.
//
// ─── WHY THE SIGNAL IS SIGKILL, WHICH IT WAS NOT AT FIRST ───────────────────
//
// It was SIGTERM, on the argument that the handler above turns one into a clean
// unwind, so a daemon that crashed would still get on_stop run.  That argument
// is wrong about the only case the guarantee exists FOR, and the test said so:
// freeze one shard with SIGSTOP, SIGKILL its daemon, and fifteen seconds later
// the shard is still there — state T, still bound, still in the REUSEPORT
// group.  A stopped process runs no handler; the SIGTERM just queues behind the
// stop.  The alarm above cannot save it either, because the alarm is armed BY
// the handler that never ran.  Every mechanism that needs the target to execute
// something fails on exactly the target that has stopped executing.  SIGKILL
// asks nothing of it.
//
// What that would cost if nothing else changed is the graceful path: teardown()
// signals its workers and the daemon exits, and a SIGKILL arriving as it goes
// would end them mid-unwind.  So two things make it safe rather than one.  This
// process clears the setting at the single point where it has ALREADY decided
// to exit — see the end of run() — and teardown() waits for the children it
// signalled instead of exiting out from under them.  Between them the kill can
// only reach a worker that was never told to go, which is the case it is for.
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

// The worker's writer to the daemon is shared/frame_writer.h; the shard mesh
// needs the same bounded-backlog behaviour for its links to siblings, and one
// drop policy is what keeps the two from disagreeing about EAGAIN.  Lifted out
// of this file whole: a bounded-backlog writer with a drop policy has two
// places to get the EAGAIN case wrong if there are two of it, and the second is
// always found months later.
using control_writer = frame_writer;

// Every runtime this process does not hold.
//
// The worker's own channel can serve exactly one name — the runtime in this
// process — and until now that was the whole of its world: `server --cache c`
// in a worker found no manager at all, so post_cache_request() returned before
// posting anything and the client waited for an answer nobody was ever going to
// write. Not an error, not a refusal. Silence, until the socket timed out.
//
// This is the mirror of proxy_supervisor's sink. Same wire, same ticket
// discipline, opposite direction: the request goes out on the control socket,
// the daemon looks the name up in the map only it holds, and the answer comes
// back as a chan_rep. The asking runtime cannot tell — which is the property
// the whole channel exists to provide, now finally true in both directions.
class remote_sink : public request_sink
{
public:
    explicit remote_sink(control_writer* w) : m_w(w) {}

    void serve_request(std::string_view, std::string& out) override
    {
        // Unreachable: serves_inline() is false. If the channel ever calls it,
        // an answer invented here would be worse than none.
        out.clear();
    }

    bool serves_inline() const override { return false; }

    bool serve_deferred(uint64_t ticket, std::string_view target,
                        std::string_view payload) override
    {
        // The name travels with the request rather than being resolved here,
        // because this process cannot resolve it. A false return means the
        // backlog is full — the daemon has stopped reading entirely — and the
        // channel then answers the origin rather than parking a ticket nothing
        // will complete.
        return m_w->write(
            worker_proto::frame(worker_proto::frame_type::chan_req,
                worker_proto::encode_chan_request(ticket, target, payload)));
    }

private:
    control_writer* m_w;
};

// The worker's half of the same problem the supervisor has.
//
// Its loop waits on the ring for 20 ms and then drains the control socket, so a
// request arriving from the daemon waited up to a full timeout before anything
// looked at it.  With the daemon side armed that was the whole remaining cost:
// a cross-process `cache set` measured 20.00 ms — the timeout, to the
// hundredth — against 0.09 ms for the same command in the daemon.
//
// Arming the fd on this worker's own ring makes the wait end when the frame
// arrives.  Everything else about the loop is unchanged: pump_control() still
// runs every turn, so a missed arm costs latency, never a frame.
class worker : public io_handler
{
public:
    explicit worker(int control_fd)
        : m_fd(control_fd), m_writer(control_fd), m_remote(&m_writer)
    {
        // Before the first frame is read, because a runtime_map frame can be the
        // first frame: the manager's map is the daemon's, copied, and writing to
        // it here would build a runtime that exists in this process and nowhere
        // else.  See runtime_manager::mark_replica().
        m_manager.mark_replica();
    }

    // ── The two things this worker has on the ring for itself ───────────────
    //
    // Its runtime's completions never arrive here: the runtime registers as its
    // own owner.  What lands here is the control socket's recv and the control
    // writer's send, and they are told apart by the request address rather than
    // by the op type — a type is a shape, and two submissions of the same shape
    // would be indistinguishable the moment a second one exists.
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

        // A recv, not a readiness notification.  The bytes are already here;
        // the read that used to follow the poll is what this replaces.
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
        // The daemon may die while we are serving.  Without this the worker
        // keeps forwarding traffic for a proxy nobody is supervising any more;
        // with it, a write to the closed control socket ends the process
        // instead of raising SIGPIPE.
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

        // No ring yet.  io_uring fixes a ring's flags when the ring is created
        // and offers no way to change them afterwards, so whatever is going to
        // decide this worker's ring — SQPOLL, a CPU set — has to have arrived
        // before init() runs.  The only thing that ever tells a worker anything
        // is its config frame, and this used to init() several hundred
        // microseconds before the first byte of that frame was read: a
        // per-runtime ring setting could be parsed, stored, and would then be
        // silently ignored, because set_sqpoll()/set_cpus() on an open ring are
        // no-ops by contract.  on_config() builds the ring now.
        set_nonblocking(m_fd);
        send_hello();

        auto last_stats = std::chrono::steady_clock::now();

        // ─── THE PUBLISH WAS THE LAST THING AN IDLE WORKER PAID FOR ─────────
        //
        // With the 20 ms poll gone, 93% of what an idle runtime cost was a 4 Hz
        // publish: measured, 395.8 us/s per idle runtime of the 425 that
        // remained.  Four frames a second, every one of them carrying the same
        // numbers as the last, for a runtime with nothing connected to it.
        //
        // It was a heartbeat and not a report.  lib_ready.sh's ready_conns used
        // to wait until `now - figures_age_ms >= start` — until a sample existed
        // that was TAKEN after the caller asked — and it asked that of runtimes
        // whose value was already what it wanted.  So the frame had to keep
        // arriving even when it said nothing, and on-change publishing was not
        // available.
        //
        // The counters are in shared memory now, stored once per turn at the
        // bottom of this loop and summed by whoever prints them, so there is no
        // sample to be after anything: the answer is computed when the question
        // is asked.  That removes the heartbeat's only reader, and the frame
        // becomes what it always should have been — the part of `stats` that is
        // NOT a summable counter, sent when it changes.
        //
        // Which leaves the wakeup.  Nothing in this worker's address space can
        // change while this worker is not running, so a turn in which the ring
        // delivered no completion is a turn in which nothing can have become
        // worth saying.  `stats_dirty` is that observation: the publish deadline
        // exists only after a turn that did something, and an idle worker has no
        // deadline and does not wake.
        //
        // WHAT THIS GIVES UP, stated because it is real: a figure that moves
        // with the passage of time alone and without any completion would go
        // unpublished until the next completion.  Every candidate was looked for
        // and each one is driven by a timer that is itself an SQE in this ring —
        // the Lua tick, health checks, key expiry, backend deadlines — so each
        // arrives as a completion and marks the turn.  A future figure that is
        // computed from the clock at read time would not, and would need to say
        // so here.
        bool stats_dirty = true;

        while (!m_done && !g_term_requested)
        {
            // One drain pass of the ring, waiting until the next thing this
            // loop actually owes somebody.  run() is not usable here: it owns
            // the thread until the ring stops, and the control socket has to be
            // serviced between completions.
            //
            // ─── WHY THE TIMEOUT IS A DEADLINE AND NOT A CONSTANT ───────────
            //
            // This was a flat 20 ms, with the reasoning that a short wait keeps
            // an idle worker from spinning.  It does — and it replaces the spin
            // with a fixed 50 Hz clock that runs whether or not anything is
            // happening.  Measured on an idle runtime: 50.0 context switches a
            // second, 0.13% of a core, per runtime, for a process with nothing
            // to do.  At a hundred idle runtimes that is a core and a third of
            // wakeups against an empty ring.
            //
            // Nothing in the loop below is periodic except the stats publish.
            // pump_control() is answered by the poll armed on the control
            // socket, which ends the ring's wait the moment a frame arrives;
            // the runtime's own timers — the Lua tick, health checks, backend
            // deadlines — are timeouts in this same ring and complete into this
            // same drain.  So the honest timeout is the time left until the
            // next publish, and an idle worker then wakes at the publish rate
            // rather than at fifty hertz.
            //
            // A worker with work is unaffected: io_uring_wait_cqe_timeout()
            // returns on the first completion, so a longer ceiling adds nothing
            // to a wait that ends early anyway.
            //
            // ─── THE STATES IN WHICH THE ARM DOES NOT COVER THIS WAIT ───────
            //
            // A long wait is only as good as the notification standing in the
            // ring.  Every state in which an idle worker has none, found by
            // walking every assignment to m_ctl_armed and every early return
            // out of arm_control():
            //
            //   (a) There is no ring yet.  arm_control() returns at once while
            //       ring_open() is false, from the fork until on_config()
            //       builds the ring.  Covered by the else branch below, which
            //       waits on the descriptor itself — the complete notification
            //       for that state, and the reason this branch needs no
            //       fallback.
            //
            //   (b) The submission did not reach the ring.  submit_poll_add()
            //       answers false when get_sqe() has nothing to give, and the
            //       flag is then false with nothing outstanding.  The same
            //       state follows a completion that cleared the flag after
            //       arm_control() had already run for the turn — the drain in
            //       the publish branch below does exactly that.
            //
            //   (c) The arm is standing but blind to what is being waited for.
            //       Its mask is fixed when it is placed, so an arm made while
            //       the write queue was empty carries no POLLOUT, and the
            //       daemon starting to read again does not end the wait.
            //
            //   (d) m_done — arm_control() is skipped once the worker has
            //       decided to leave.  Not a wait state: m_done is the loop's
            //       own condition, so there is no next wait to be uncovered.
            //
            // (b) and (c) fall back to the old constant, which is what that
            // constant was always doing for them.  Neither can be true of an
            // idle worker: it is armed and has nothing queued, so the fallback
            // costs nothing in the case this change is about.
            //
            // What is NOT on this list, and was checked: a frame arriving
            // between the drain's last EAGAIN and the arm reaching the kernel.
            // A poll_add is level-triggered on submit, so it completes at once
            // against a descriptor that is already readable, and no wakeup is
            // lost there.
            //
            // (e) There is no deadline at all.  Nothing has happened since the
            //     last publish, so there is nothing to publish and no clock to
            //     wait for; the wait is idle_wait_ms, which is a backstop and
            //     not a schedule.  See the constant.
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

            // Before the ring exists poll_completions() returns at once no
            // matter what timeout it is handed, so the wait has to come from
            // somewhere else or this loop is a spinning core for as long as the
            // config takes to arrive.  Waiting on the control socket is the
            // right place for it anyway: the frame is the only thing that can
            // happen to a worker in that window — and poll() on the fd is its
            // own notification, so this branch needs no fallback, only the
            // POLLOUT the arm would have carried.
            if (m_loop.ring_open())
            {
                // The two states the ring cannot end on its own: no recv
                // standing (a submission get_sqe() refused), and bytes queued
                // with no send standing for the same reason.  An in-flight send
                // needs no clamp — it ends with a completion.
                if (!m_ctl_armed || m_writer.needs_retry())
                    wait_ms = std::min(wait_ms, ctl_fallback_ms);

                // The same two states, per mesh link.  A link whose recv is
                // standing and whose writer is idle needs nothing: a sibling's
                // frame ends the wait by itself, which is the whole reason the
                // links are on the ring.  What has to be clamped is a
                // submission get_sqe() refused, because nothing in the ring
                // will come back to retry it.
                for (const auto& link : m_mesh_links)
                    if (link->needs_wake())
                    {
                        wait_ms = std::min(wait_ms, ctl_fallback_ms);
                        break;
                    }

                // The turn did something exactly when the ring delivered
                // something.  This is the whole of the activity test and it is
                // taken HERE rather than inferred later from a counter that
                // moved: a completion that changes nothing a reader can see —
                // an accept immediately refused, a cancelled read — still ran
                // code in this process, and the publish below is what decides
                // whether it produced anything worth sending.
                if (m_loop.poll_completions(wait_ms) > 0)
                    stats_dirty = true;

                // The bytes are in m_in, put there by the recv completion.
                // Dispatching them here rather than in on_cqe() is deliberate
                // and is not a detail: on_config() is one of these frames and
                // it BUILDS this ring, and the reload and stop handlers reach
                // into the runtime.  Every one of them ran on a loop turn
                // before the read moved onto the ring, and they still do.
                if (!drain_frames())
                    break;
            }
            else
            {
                // No ring yet, so the notification has to come from the
                // descriptor itself.  This is the whole of what is left of the
                // old pattern, and it costs nothing that can be measured: a
                // worker is in this state from the fork until its config
                // arrives, which is before it has a runtime, a port, or a
                // sibling to cross to.
                wait_for_control(wait_ms, m_writer.pending());
                if (!pump_control())
                    break;

                // Unconditionally, for the window this branch covers: from the
                // fork until on_config() builds the ring there is no runtime to
                // have figures about, and the first publish is what tells the
                // daemon this worker is answering for one.
                stats_dirty = true;
            }

            // Whatever the socket would not take last turn.  A reply sitting
            // here is somebody's answer, so it goes before anything else this
            // turn does.
            m_writer.flush();
            if (m_writer.dead())
                break;

            // After the drain, not before: an arm placed while a frame is
            // already buffered fires at once and the turn is wasted.  Skipped
            // once the worker has decided to exit, so nothing is outstanding
            // against the fd on the way down.
            if (!m_done)
                arm_control();

            // ── And the same two steps for every link to a sibling ──────────
            //
            // Beside m_writer.flush() and arm_control() rather than inside
            // shard_link::on_cqe(), and that placement is the measurement, not
            // a tidiness preference: a send submitted per frame produces a
            // completion per crossing, and a completion arriving alone ends the
            // ring's wait — so the loop spends a turn and an io_uring_enter
            // learning that a send it needed no answer to has finished.  On the
            // control socket, which is this same code, that was 5,920 ring
            // entries against 61,221.  Once per turn, every crossing this turn
            // answered leaves in one send.
            //
            // Unconditional, including while m_done: a link that is on its way
            // out still owes its sibling whatever it has queued, and pump() is
            // a no-op on a dead one.
            for (auto& link : m_mesh_links)
                link->pump();

            const auto now = std::chrono::steady_clock::now();
            if (stats_dirty && now - last_stats >= stats_interval)
            {
                // ─── THE SAFETY PUMP THAT USED TO BE HERE, AND WHY IT IS NOT ─
                //
                // A read once per interval, whatever the arm said, plus two
                // extra ring drains and a warning around it.  All of it existed
                // because the arm was a POLL: a readiness notification is a
                // claim about the socket that the loop then had to act on, and
                // "armed and unfired means not readable" was an invariant this
                // process could be wrong about without anything saying so.
                //
                // A recv is not a claim.  The bytes are IN the completion, so
                // there is no second step to skip and nothing to be stale about
                // — a frame that arrives is either delivered by the standing
                // recv or there is no standing recv, and that second case is
                // visible directly in m_ctl_armed and is retried at the top of
                // every turn with the wait clamped to ctl_fallback_ms.
                //
                // So the pump is gone with the invariant it was watching, and
                // with it the last read() on this path.  What replaced its
                // guarantee is not an interval — it is that arm_control() runs
                // on every turn and the only way to have no recv standing is a
                // submission the ring refused, which the next turn resubmits.

                // Cleared when nothing remains to publish.  push_stats()
                // answers "was any of this new", and a turn whose work produced
                // nothing a reader can see is a turn with nothing left to
                // publish — asking again in 250 ms would only rebuild the same
                // string and compare it against itself.  The next completion
                // sets the flag again.
                //
                // NOT cleared for a frame the writer refused: the figures are
                // still owed, and the flag staying up is what brings this loop
                // back at the publish rate to retry — an idle worker with a
                // clear flag waits idle_wait_ms, which for a runtime that has
                // gone quiet after a burst is a report the daemon never gets.
                if (push_stats())
                    stats_dirty = false;
                last_stats  = now;
            }

            // ── This shard's line, once per turn ────────────────────────────
            //
            // The END of the turn and not the top of it, because that is what
            // makes this one site instead of several: every drain this turn
            // performs is above this line — the main one, the one after
            // pump_control, and the one inside the stats block — so whatever
            // any of them accepted or reaped is counted before the loop comes
            // round again.
            //
            // Once per turn rather than at every place a connection count
            // moves.  A count changes in accept and in teardown, and those are
            // 34 call sites across four runtimes with nothing in common but
            // the loop that dispatched them; putting the publish where every
            // path already passes is the rule this tree states about the
            // half-close hold, applied before rather than after the fourth fix.
            //
            // NOT on the 250 ms stats timer, which is the other thing already
            // here and is the wrong clock: a script that is told a client
            // connected and asks how many there are would be answered from a
            // sibling's quarter-second-old figure.  A turn is microseconds.
            //
            // ─── AND NOT ONLY THE CONNECTION COUNT ──────────────────────────
            //
            // Every figure `stats` prints that is a summable counter is stored
            // here, because this is the clock they all belong on for the same
            // reason: the daemon reads them when it prints, so whatever they say
            // when this turn ends is what the next question is answered with.
            // Four extra relaxed stores into a line this turn is already
            // writing.
            //
            // mapped() is now true for every worker-backed runtime and not only
            // for a sharded one — a region is made for each of them, see
            // reconcile_proxy_workers().  For one shard the "sum" is one slot,
            // which is the same number by a longer route and is what makes the
            // sharded and unsharded cases one path.
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

        // ─── Past this line the guarantee has already done its job ──────────
        //
        // Every way out of the loop above arrives here: the shutdown frame, the
        // SIGTERM flag, an EOF on the control socket, a dead writer.  That is
        // what makes this the one place to give the parent-death kill back —
        // this process is leaving, and the only thing PR_SET_PDEATHSIG could
        // still do is interrupt the leaving.
        //
        // Putting it here rather than at each exit is the same rule this tree
        // states about close_pair() and the half-close hold: a check every path
        // has to remember is one a new path will not.  There are four ways out
        // of that loop today and the unwind below is common to all four.
        //
        // What it costs to be wrong in the safe direction is nothing: a worker
        // that clears this and then wedges during teardown is reaped by the
        // daemon's own escalation, which is alive on every path that gets here
        // deliberately.
        if (::prctl(PR_SET_PDEATHSIG, 0) < 0) {}

        // Same order the daemon uses on its way down: stop the runtime while
        // there is still a ring for teardown() to cancel into, and only then
        // end the ring.  Reversing these two is what turned a clean shutdown
        // into a segfault the last time it was got wrong.
        if (m_rt && m_rt->get_state() == runtime_running)
            m_rt->stop(m_loop);

        // ── The links come off the ring before the ring goes ───────────────
        //
        // Each of them holds a standing recv, may hold an in-flight send, and
        // owns a registration of its own.  die() is the one function that ends
        // a link and it does all three — it sweeps the crossings the link was
        // carrying and answers them `no_target`, so a sibling's request that
        // was in flight when this shard was told to stop is answered rather
        // than left to a deadline that does not exist, and it closes the
        // descriptor through the loop so the number outlives the cancel.
        //
        // Before requests().detach() for the same reason detach() is before the
        // ring: the sweep completes tickets through the channel, and a detached
        // channel answers them `dropped` instead.
        for (auto& link : m_mesh_links)
            link->die("this shard is shutting down", /*expected=*/true);

        // Before the ring, like every other owner registration: detach answers
        // whatever is still queued `dropped` and gives the owner token back.
        m_manager.requests().detach();

        // ── The writer comes off the ring before the ring goes ──────────────
        //
        // stop() above can still have written a frame — a Lua on_stop that
        // sends, a final state — and on the ring that frame is a submission
        // rather than bytes on the wire.  So the in-flight send is given a
        // bounded chance to complete, and then the writer goes back to the
        // descriptor for whatever is left.  Bounded, and short: this is a
        // socketpair whose peer is the daemon, and a worker that will not
        // finish unwinding is killed by the supervisor five seconds from the
        // SIGTERM regardless.
        //
        // leave_ring() is what refuses to guess: see its note on why a send
        // that is still in flight when the drains run out ends the writer
        // rather than being rewritten.
        for (int i = 0; i < 20 && m_writer.send_in_flight(); ++i)
            m_loop.poll_completions(1);
        m_writer.leave_ring();
        m_writer.flush();

        // A recv, so poll_remove no longer names it.  Cancelling by descriptor
        // covers the recv and any send that outlived the drain above, which is
        // the case leave_ring() has just given up on.
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

    // Block until the control socket has something, or will take what is
    // waiting to go out, or the timeout runs out.  Only used before there is a
    // ring; afterwards the ring's own wait covers it, and the control socket is
    // drained between completions.
    //
    // POLLOUT is not decoration.  This is the only wait a worker has before its
    // config arrives, and it is also the wait that holds while the hello frame
    // is going out; with the timeout no longer a flat 20 ms, a queue that the
    // socket would not take would otherwise sit until the deadline rather than
    // until the socket drained.  Asked for only when there is something to
    // send, so an idle worker is not woken by a socket that is merely writable.
    void wait_for_control(int timeout_ms, bool want_write) const
    {
        struct pollfd pfd{m_fd,
                          static_cast<short>(POLLIN | (want_write ? POLLOUT : 0)),
                          0};
        if (::poll(&pfd, 1, timeout_ms) < 0) {}
    }

    // ── The recv that used to be a poll ─────────────────────────────────────
    //
    // This was submit_poll_add(POLLIN), and the bytes were then taken by a
    // ::read() in the loop.  Two things for one arrival, one of them a
    // syscall — the epoll pattern, on the one path in this tree that still had
    // it.  What that cost is countable and was counted: on a four-shard cache,
    // one shard over 200,000 GETs made 50,600 write() and 14,984 read() calls
    // against 5,920 io_uring_enter, where the same run on one shard makes 7 and
    // 9.  Every one of them is a crossing to a sibling.
    //
    // No POLLOUT half any more: the send is on the ring too, and it ends with
    // its own completion rather than with a readiness report somebody has to
    // act on.
    //
    // ── AND WHY THIS IS ONE-SHOT AND NOT MULTISHOT ──────────────────────────
    //
    // A multishot recv would take the re-arm away as well.  The re-arm is an
    // SQE, which under SQPOLL is a store and no syscall at all — it is not on
    // the axis this change is about, and the counting below says so: entries
    // per GET did not rise when the reads and writes moved onto them.
    //
    // What it would cost is a provided-buffer group on the one socket in this
    // process whose frames may not be lost: an ENOBUFS fallback path, a buffer
    // that has to be handed back on every exit from the completion handler, and
    // a second shape of "a frame arrived".  That is a trade worth making
    // against a measured number and not against an expected one, and there is
    // no number here asking for it.
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

    void send_state()
    {
        std::string payload;
        payload.push_back(static_cast<char>(
            m_rt ? static_cast<uint8_t>(m_rt->get_state())
                    : static_cast<uint8_t>(runtime_created)));
        if (!m_writer.write(worker_proto::frame(worker_proto::frame_type::state, payload))) {}
    }

    // True when nothing remains to publish — either the frame was queued or
    // there was nothing to say.  False only for a frame the writer REFUSED,
    // which the caller must keep its dirty flag armed for: the refusal used to
    // be swallowed here after m_last_pub had already been updated, so the lost
    // frame was recorded as delivered and was never resent until a counter
    // happened to move again — for a cache that went idle after a burst, never.
    // The daemon then held the previous report indefinitely, with nothing in
    // any log but frame_writer's one backlog warning.
    bool push_stats()
    {
        // No runtime, so nothing published and nothing changed — and reporting
        // "still owed" here would hold the interval at its floor for a worker
        // that has nothing to say.
        if (!m_rt)
            return true;

        // On the event-loop thread, which is the only thread allowed to walk
        // the proxy's connection tables.  Everything that leaves this process
        // is a copy taken here.
        //
        // ─── WHAT IS IN THIS FRAME AND WHAT IS NOT ──────────────────────────
        //
        // Not the prefix of `stats`.  name, port and the five counters are
        // written by the daemon out of the shared table at the moment it
        // prints — see runtime_instance::stats_prefix() — so sending them here
        // would be a second answer to a question that already has one, and the
        // one that is older.
        //
        // What is here is everything the daemon CANNOT compute: the ring's
        // granted flags and this runtime's own type-specific figures, each of
        // them a walk of tables that exist only in this process.
        //
        // The five counters still travel, and this is the one place they are
        // duplicated.  They are the fallback for a worker whose daemon could
        // not create a memfd region — logged at the daemon, see
        // reconcile_proxy_workers() — where without them `stats` would report a
        // runtime with no figures at all.  They are also what makes the change
        // test below cover a counter moving, which is what keeps that fallback
        // fed.
        worker_proto::stats_wire s;
        s.total_connections  = m_rt->m_stat_total_connections.load(std::memory_order_relaxed);
        s.total_messages     = m_rt->m_stat_total_messages.load(std::memory_order_relaxed);
        s.bytes_in           = m_rt->m_stat_bytes_in.load(std::memory_order_relaxed);
        s.bytes_out          = m_rt->m_stat_bytes_out.load(std::memory_order_relaxed);
        s.active_connections = static_cast<uint64_t>(m_rt->get_connection_count());
        s.detail             = m_rt->stats_ring() + m_rt->stats_extra();

        // The two numbers that make a mesh measurement mean anything.
        //
        // The relay fallback is what keeps a broken mesh from being an outage,
        // and it is also what would let one go unnoticed: a mesh that never
        // connects reports the same throughput as one that did not help.  These
        // say which happened.  Appended to the detail the worker already sends
        // rather than added to the frame, because the frame is a contract
        // between two builds and this is a figure.
        // Unconditionally, including the shard that has no links at all.
        //
        // These used to be inside `if (!m_mesh_sinks.empty())`, which made the
        // ABSENCE of a line the signal for "this shard never connected" -- the
        // one state the counters exist to expose, reported by silence.  Every
        // reader that sums the lines, including this tree's own test, read a
        // missing shard as a zero and could not tell it from a quiet one.
        //
        // mesh_links is here for the same reason: 0 says so out loud, where a
        // reader would otherwise have to infer it from two counters that are
        // also 0 on a mesh that is merely idle.
        {
            uint64_t direct = 0, relayed = 0;
            mesh_counts(direct, relayed);
            s.detail += "mesh_links:"   + std::to_string(m_mesh_sinks.size()) + "\n";
            s.detail += "mesh_direct:"  + std::to_string(direct)  + "\n";
            s.detail += "mesh_relayed:" + std::to_string(relayed) + "\n";
        }

        // Did anything the daemon can see actually move?
        //
        // This used to decide how far the publish backed off.  It now decides
        // whether there is a publish at all: an idle worker that was woken by
        // something which changed nothing sends no frame, and a worker that is
        // idle in the ordinary sense is not woken and does not reach here.
        // There is nothing left in this struct that changes by itself — the
        // timestamp that did is gone with the age it was for.
        const bool changed =
            !m_have_last
            || s.total_connections  != m_last_pub.total_connections
            || s.total_messages     != m_last_pub.total_messages
            || s.bytes_in           != m_last_pub.bytes_in
            || s.bytes_out          != m_last_pub.bytes_out
            || s.active_connections != m_last_pub.active_connections
            || s.detail             != m_last_pub.detail;

        // Only when it changed.  The daemon's copy is a copy of the last thing
        // that was true, and re-sending it says nothing that its own record does
        // not already say — which is exactly why the heartbeat could be removed
        // and not merely slowed down.
        if (!changed)
            return true;

        if (!m_writer.write(worker_proto::frame(worker_proto::frame_type::stats,
                                                 worker_proto::encode_stats(s))))
            return false;

        // Committed only once the frame is actually queued.  Recording it
        // before the write is what made a refused frame permanent: the next
        // interval compared against figures the daemon never received, found
        // them equal, and had nothing left to resend.
        m_last_pub  = std::move(s);
        m_have_last = true;
        return true;
    }

    // Returns false when the control socket is gone, which is the worker's
    // instruction to exit: a proxy whose supervisor has died has nobody to
    // report to and nobody to stop it.
    worker_proto::stats_wire m_last_pub{};
    bool m_have_last{false};

    // Bytes off the descriptor, for the one window in which there is no ring to
    // read them with: from the fork until on_config() builds it.  Under load
    // this is not reached at all — the recv completion fills m_in and
    // drain_frames() below is what runs.
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

    // Whole frames out of m_in, dispatched.  False is the worker's instruction
    // to exit: the socket is gone, or what came off it was not a frame.
    //
    // The EOF test is first and stops before dispatch, which is what the read
    // loop above did — a zero-length read returned false without parsing what
    // an earlier pass had appended.  Kept rather than improved: a worker that
    // acts on a frame from a daemon that has already gone is a new behaviour,
    // and this change is not the place to introduce one.
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
            case worker_proto::frame_type::endpoints: on_endpoints(payload); break;
            case worker_proto::frame_type::runtime_map: on_runtime_map(payload); break;
            case worker_proto::frame_type::cluster:   on_cluster_view(payload); break;
            case worker_proto::frame_type::publish:   on_publish(payload);   break;
            case worker_proto::frame_type::chan_req:  on_chan_req(payload);  break;
            case worker_proto::frame_type::chan_rep:  on_chan_rep(payload);  break;
            case worker_proto::frame_type::deliver:   on_deliver(payload);   break;
            case worker_proto::frame_type::start:     on_start();            break;
            case worker_proto::frame_type::stop:      on_stop();             break;
            case worker_proto::frame_type::reload:    on_reload();           break;
            case worker_proto::frame_type::shutdown:  m_done = true;         break;

            // Anything else is either a frame this build predates or one that
            // only travels the other way.  Skipped, not fatal — that is the
            // whole point of the length in the header.
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

        // A second config for a proxy that is already up would have to rebuild
        // it, and the daemon does not send one: a change of backends is a stop
        // and a start.  Saying so is better than half-applying it.
        if (m_rt)
        {
            LOG_WARN("proxy worker: ignoring config for an already-configured worker");
            return;
        }

        // The ring, at the first and only moment where both halves hold: the
        // config has been parsed, so anything in it that shapes a ring can be
        // applied, and nothing has submitted yet, so applying it is still
        // allowed.  Any set_sqpoll()/set_cpus() this worker is ever given goes
        // between the parse above and the init below — that gap is the whole
        // point of building the ring here instead of in run().
        //
        // This is where a worker's --cpus and --sqpoll are finally honoured.
        // They were parsed, stored, persisted and reported, and then applied to
        // nothing: the ring was built from whatever environment the daemon was
        // launched with, so `create proxy p --cpus 0-1` pinned
        // no thread anywhere while `stats` reported cpus:0-1.  Nothing said so
        // — this is the shape of confidently-wrong the rest of this file is
        // written against.
        //
        // It has to happen here and nowhere else: io_uring fixes a ring's flags
        // when the ring is created, so set_sqpoll()/set_cpus() on an open ring
        // are no-ops by contract.  Between the parse above and the init below is
        // the only window that exists.
        //
        if (!cfg.cpus.empty())
        {
            cpu_set_spec spec;
            std::string  err;
            if (parse_cpu_set(cfg.cpus, spec, err))
                m_loop.set_cpus(spec);
            else
                LOG_WARN("proxy worker: unusable --cpus in its config, ignored");
        }
        if (cfg.sqpoll_set)
            m_loop.set_sqpoll(cfg.sqpoll);
        //
        // Guarded on ring_open() rather than on reaching here once: a config
        // that got as far as the ring and then failed to build a proxy leaves
        // m_rt null, and a second config frame must not build a second ring
        // over the first.
        if (!m_loop.ring_open() && !m_loop.init())
        {
            LOG_ERROR("proxy worker: could not initialise io_uring");
            m_done = true;
            return;
        }

        // ── Registered with the ring here, and not further down ─────────────
        //
        // The control socket's recv and the control writer's send are this
        // handler's own submissions, and a submission carries its owner's
        // token: made without a registration it is not merely unowned, its
        // completion is DROPPED.  For the recv that means the arm never
        // completes, m_ctl_armed never clears, and the worker is deaf to its
        // daemon for the rest of its life.
        //
        // Everything below this line can fail and return without building a
        // runtime — create_runtime() does, for a type this build does not have
        // — and that exit used to be survivable because the loop read the
        // socket once per stats interval whatever the arm said.  That read is
        // gone with the poll it was covering for, so the registration moves to
        // where the ring is, which is the fact it actually depends on.
        //
        // register_owner() is idempotent by contract, so a second config frame
        // reaching here costs nothing and strands nothing.
        m_loop.register_owner(this);

        // And the frames going the other way go on the ring too — after the
        // registration and not before, for the reason just stated.  Whatever
        // the hello frame left queued goes out from here on the ring.
        m_writer.use_ring(&m_loop, this);

        // The type comes from the frame the daemon sent, not from this file.
        // Everything below is either a setter every runtime has or is guarded
        // on the cast, so a worker is not a proxy worker any more.
        auto inst = create_runtime(cfg.type, cfg.name);
        if (!inst)
        {
            LOG_ERROR("proxy worker: could not create proxy instance");
            return;
        }
        m_owned = std::move(inst);
        m_rt    = m_owned.get();
        m_proxy = (cfg.type == runtime_proxy)
                    ? static_cast<proxy_instance*>(m_owned.get()) : nullptr;

        m_rt->set_event_loop(&m_loop);
        m_rt->set_id(cfg.id);

        // Both halves, from the same file the daemon's restore path uses.
        // This was a hand-written list here, and it was missing seventeen
        // fields: a worker built a runtime the operator had not asked for and
        // reported nothing, because there is nothing to report — every setter
        // it did call succeeded.  See runtime_config_apply.h.
        apply_common_config(*m_rt, cfg);
        apply_typed_config(*m_rt, cfg);

        // ── This shard's line in the table its siblings share ───────────────
        //
        // Before the script is loaded, which is the constraint that decides
        // where this goes: a script's top level runs inside load_lua_script()
        // below and may call self.connections(), and a runtime that is not
        // attached yet answers that with its own count — a fraction, silently,
        // exactly the defect this exists to remove.
        //
        // The descriptor is at a fixed number the supervisor dup2'd it onto, or
        // it is not there at all.  Absent is no longer the ordinary case — a
        // region is made for every worker-backed runtime now, one shard or
        // eight — but it is still not an error: it is a worker forked by a
        // daemon that could not make one, which falls back to the figures in
        // the stats frame.  fcntl is the cheapest way to ask whether a
        // descriptor exists without disturbing it.
        //
        // No test on cfg.shards.  A one-shard runtime publishes into slot 0 of
        // a one-slot table and the daemon sums one slot, which is the same
        // number by a longer route and is the point: there is one path for the
        // figures and not a sharded one beside an unsharded one.
        //
        // looks_like_region() and not fcntl(F_GETFD).  "Is fd 4 open" was a
        // sufficient test while `shards > 1` stood in front of it, because that
        // was the daemon saying it had placed one; with the region made for
        // every worker-backed runtime there is no such signal left, and fd 4 is
        // open in any process that has opened four things.  adopt() takes
        // ownership of what it is handed, so a guess here CLOSES somebody
        // else's descriptor — which is exactly what happened to a worker
        // spawned outside the supervisor.  See the note on looks_like_region().
        if (shard_stats::looks_like_region(worker_shard_fd))
        {
            if (!m_rt->shard_stats_table().adopt(worker_shard_fd,
                                                 m_rt->get_shard_index()))
                LOG_WARN("proxy worker: the shared shard table could not be "
                         "mapped; this shard will answer only for itself");
        }

        // And the client list.  Adopted here for the same reason and with the
        // same guard: a script's top level may call self.clients(), and a
        // runtime that is not attached yet answers with its own connections.
        if (cfg.shards > 1 && ::fcntl(worker_clients_fd, F_GETFD, 0) >= 0)
        {
            if (!m_rt->shard_clients_table().adopt(worker_clients_fd,
                                                   m_rt->get_shard_index(),
                                                   cfg.shards))
                LOG_WARN("proxy worker: the shared client list could not be "
                         "mapped; this shard will list only its own clients");

            // Where a message for a sibling's connection goes.  The daemon
            // reads the shard out of the ref itself, so this is one hop to one
            // process and not an offer to all of them.
            m_rt->set_ref_sink(
                [this](const conn_ref& r, std::string_view message)
                {
                    if (!m_writer.write(worker_proto::frame(
                            worker_proto::frame_type::send_ref,
                            worker_proto::encode_send_ref(r, message)))) {}
                });
        }

        // ── The shard mesh ─────────────────────────────────────────────────
        //
        // Built after the channel is attached below?  No — before it, because
        // the sinks registered here have to be in the table by the time the
        // first request is posted, and the config frame that reaches this point
        // is followed by `start`.  The links themselves are armed on the ring,
        // which exists from register_owner() a few lines down, so attach() is
        // deferred until then.
        //
        // A descriptor that is not there is not an error: it is an unsharded
        // runtime, a daemon that could not build the mesh, or a shard that was
        // restarted and cannot inherit one.  All three relay.
        if (cfg.shards > 1)
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
        //
        // A runtime asks through its manager, and a worker had none: every
        // `cache` command a server in a worker was given died at the
        // `if (!mgr) return;` in post_cache_request(), unanswered.  The map was
        // empty on purpose then — this process holds one runtime and the manager
        // was here for the channel — and it is not any more: the daemon pushes a
        // replica of it, and the sink table below is still built by hand from
        // this worker's own runtime, because a replica answers no requests.
        //
        // Its own name is registered so a request for it is served here rather
        // than making a round trip through the daemon, which would route it
        // back to this very worker.
        // The ring, the owner registration and the writer are already up — see
        // the block right after m_loop.init(), and the note there for why they
        // cannot wait for a runtime that may never be built.

        m_manager.requests().attach(m_loop);
        if (auto* sink = m_rt->as_request_sink())
            m_manager.requests().register_sink(cfg.name, sink);
        m_manager.requests().set_default_sink(&m_remote);

        // `name#j` for every sibling this process has a link to.  Registered
        // AFTER the default sink and under the qualified name, so the lookup
        // that used to miss and fall through to the daemon now resolves here —
        // and a sibling with no link is simply absent from the table, which is
        // the miss that still falls through.  See shared/shard_mesh.h.
        for (auto& link : m_mesh_links)
        {
            link->attach(m_loop);
            m_mesh_sinks.push_back(std::make_unique<mesh_sink>(link.get(), &m_remote));
            m_manager.requests().register_sink(
                shard_target(cfg.name, link->peer()), m_mesh_sinks.back().get());
        }
        m_rt->set_runtime_manager(&m_manager);

        // ── and a send on its way out ───────────────────────────────────────
        //
        // The mirror of the daemon's own deliver sink, which is what
        // socketley.send reaches for a runtime whose connections are in another
        // process.  In a worker EVERY other runtime is in another process, and
        // the daemon is the only one that knows where — so the message goes up
        // and is routed there, by the same code that routes a `send` typed at
        // the CLI.
        //
        // Its own runtime is answered here rather than on the wire.  The round
        // trip would work — the daemon would route the name straight back to
        // this socket — but it would make the commonest send in a worker's
        // script the slowest one, and it would be delivered a turn of two event
        // loops later than the call that asked for it.
        // ── The other shards of this runtime, for anything that fans out ────
        //
        // One place, because two callers need it and they must not be able to
        // disagree about what "everybody" means: `self.broadcast`, through
        // runtime_instance::broadcast_all, and `socketley.send` addressed to
        // this worker's own runtime, just below.
        //
        // The frame is the ordinary deliver_to naming this runtime's own name.
        // The daemon reads that as the sibling fan-out and leaves this shard
        // out of it — see on_worker_deliver — so nothing new goes on the wire.
        //
        // Guarded on the shard count inside fanout_to_siblings(), not here: a
        // one-shard worker must write no frame at all rather than one the
        // daemon fans out to nobody and then logs as undeliverable.
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
                    // The local half stays local, for the reason it always
                    // did: a round trip through the daemon would work and
                    // would make the commonest send in a worker's script the
                    // slowest one.
                    deliver_local(message);

                    // And the half that is NOT local, which did not exist
                    // while a runtime was one process.  `socketley.send` to
                    // one's own name reached this shard's clients and stopped
                    // — a quarter of them on four shards, reported as sent.
                    m_rt->fanout_to_siblings(message);
                    return true;
                }
                return m_writer.write(worker_proto::frame(
                    worker_proto::frame_type::deliver_to,
                    worker_proto::encode_deliver_to(name, message)));
            });

        // ── and a publish on its way out ────────────────────────────────────
        //
        // The mirror of the frame this worker already receives.  A cache calls
        // mgr->dispatch_publish(), which in the daemon writes the message to
        // every worker and then runs every in-process subscriber.  In a worker
        // that same call found a manager with an empty map and no sink, so a
        // PUBLISH served by a cache out here reached nobody at all — not the
        // subscribers in the daemon, not the ones in other workers, and not the
        // one in this process either, because this runtime is not in this map.
        //
        // Out of the process first and the local runtime second, in that order
        // and for the reason the daemon's copy gives: a subscriber may call
        // straight back into the manager, and a frame already written to a
        // socket cannot be affected by what it does.
        m_manager.set_publish_sink(
            [this](std::string_view cache_name, std::string_view channel,
                   std::string_view message)
            {
                if (!m_writer.write(worker_proto::frame(
                        worker_proto::frame_type::publish,
                        worker_proto::encode_publish(cache_name, channel, message)))) {}

                // The daemon fans this back out to every worker EXCEPT this
                // one, so delivering here is not a duplicate — it is the only
                // delivery this process gets.
                if (m_rt)
                    m_rt->on_publish_dispatch(cache_name, channel, message);
            });

        // A script that does not load is a configuration this worker cannot
        // serve, not a warning to carry on past.
        //
        // It used to be one: the proxy started anyway, relaying with none of the
        // filters, routes or callbacks the operator wrote, and the only trace
        // was a WARN in the daemon's log.  The in-process path has never allowed
        // that — `create --lua` refuses outright and exits 1 — so a proxy could
        // be rejected by the daemon and silently accepted, gutted, by the same
        // binary one flag later.
        //
        // Exiting is how a worker says so.  The supervisor already treats a dead
        // child as the runtime's problem; exit_config_refused tells it not to
        // fork a sixth copy of the same refusal.
        // Sent after the load below, not before: there is no declaration until
        // the script's top level has run.
        if (!cfg.lua_script.empty() && !m_rt->load_lua_script(cfg.lua_script))
        {
            LOG_ERROR("proxy worker: lua script did not load; refusing to serve "
                      "without it (the script's own error is above)");
            m_exit_code = worker_proto::exit_config_refused;
            m_done      = true;
            return;
        }

        // A table that arrived before the config is not lost: it is held and
        // applied here.  The daemon publishes on every membership change, and
        // nothing orders those against the config frame.
        // What this runtime says it will answer, up to the daemon, which is the
        // only process that can publish it to whoever routes here.  Sent once
        // and only when there is something to send: a runtime that declares
        // nothing leaves the gateway forwarding exactly as it did before route
        // declarations existed, and an empty frame would say the same thing at
        // the cost of a round of publishing.
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

    // What runtimes the daemon has, arriving as a table rather than as a
    // question this process would have to ask.
    //
    // The whole of the worker's half: decode, hand it to the manager, and every
    // reader of the map — socketley.list(), socketley.get(), and anything else
    // that goes through mgr->get() — works out here exactly as it does in the
    // daemon, with no idea that what it found is a copy.  That is the point of
    // putting the replica in the map instead of answering the two calls
    // specially: there is one place that knows, and it is not the Lua layer.
    //
    // Not stashed when there is no runtime yet, unlike the endpoint table.  The
    // table has to be held because only a proxy can be handed one and the proxy
    // does not exist before the config frame; the map goes into the manager,
    // which exists from construction.
    //
    // ─── This worker's OWN runtime is in here, and as a replica ─────────────
    //
    // It has to be in the map at all, because socketley.list() called from a
    // runtime includes that runtime everywhere else: a worker that left itself
    // out would answer three where the daemon answers four, which is a wrong
    // answer rather than a missing feature.
    //
    // It is the replica and not m_rt, and that is the load-bearing half.
    // Putting the live object in the map would deliver every PUBLISH to it
    // twice: dispatch_publish() walks the map and skips only what is out of
    // process, and this worker's publish sink ALSO calls
    // m_rt->on_publish_dispatch() by hand — because that call is the only
    // delivery this process gets for a message it published itself.  A replica
    // is out of process by construction and has no interpreter, so the walk
    // skips it twice over and the hand-written delivery stays the only one.
    //
    // What it costs is that socketley.get(self.name).connections is the
    // daemon's copy of this worker's own figure, up to a push interval old,
    // while self.connections() is exact.  Two calls, two answers, and the
    // second one is the one a script asking about itself should be using.
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
            // A type or a state this build has no name for comes from a daemon
            // newer than this worker — the case the version in every frame
            // header exists for.  The entry is dropped rather than cast to
            // whatever the number happens to land on: a runtime reported as the
            // wrong kind is worse than one not reported at all, and the next
            // upgrade of this binary makes it appear.
            if (w.type > static_cast<uint8_t>(runtime_cache) ||
                w.state > static_cast<uint8_t>(runtime_failed))
            {
                LOG_WARN("proxy worker: runtime map entry of an unknown kind, skipped");
                continue;
            }

            runtime_manager::replica_entry e;
            e.name        = w.name;
            e.type        = static_cast<runtime_type>(w.type);
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

    // What the cluster looks like, as the daemon last scanned it.
    //
    // Installed on lua_context rather than on this runtime, because it is a
    // property of the PROCESS: every interpreter in this worker is looking at
    // the same cluster, and there is exactly one worker per runtime anyway.
    // Held by shared_ptr and never mutated after publication, so a cluster call
    // that is mid-iteration keeps the view it started with instead of watching
    // daemons appear underneath it — the same arrangement the endpoint table
    // uses, for the same reason.
    //
    // An empty daemon name is a WITHDRAWAL, not a cluster of one with no name:
    // it is what the daemon sends when it no longer has a cluster_discovery, and
    // taking it as a view would leave the four cluster calls answering out of a
    // cluster this daemon has left.  Cleared, so they refuse again.
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
            tbl->set_name(e.name, runtime_endpoint{e.host, e.port});
        for (const auto& e : groups)
            tbl->add_to_group(e.name, runtime_endpoint{e.host, e.port});
        for (auto& [n, rt] : name_routes)
            tbl->set_name_routes(n, std::move(rt));
        for (auto& [g, rt] : group_routes)
            tbl->set_group_routes(g, std::move(rt));

        // Immutable from here, exactly as on the daemon side: a request that is
        // already resolving keeps the table it started with.
        // Three cases, and the braces are load-bearing.  Written without them
        // the `else` bound to the inner `if` and a table arriving before the
        // config frame was dropped instead of stashed — -Wdangling-else caught
        // it, which is the whole reason that warning is not tolerated here.
        if (!m_rt)
            m_pending_endpoints = std::move(tbl);   // no runtime yet; keep it
        else if (m_proxy)
            m_proxy->set_endpoints(std::move(tbl)); // only a proxy routes by name
        // else: a runtime that does not route.  Nothing to hand it.
    }

    // A cache somewhere in the daemon published, and this proxy's script asked to
    // hear about it.  Delivered through the same entry point an in-process
    // runtime's dispatch goes through, so a subscribe callback cannot tell which
    // side of the boundary it is running on.
    //
    // Dropped when there is no proxy yet: a publish that arrives before the
    // config frame has nowhere to go, and holding it the way a pending endpoint
    // table is held would be storing an event to replay at a subscriber that did
    // not exist when it happened.
    // A request another runtime made of this one, arriving over the control
    // socket instead of over this runtime's own port.
    //
    // The payload is whatever would have reached that port and is handed to the
    // runtime untouched — nothing here parses a command, which is why this wire
    // was chosen over the target's own protocol.  The ticket is the channel's,
    // and it goes back with the answer so the daemon can pair them without
    // understanding either.
    // What a mesh link hands a sibling's request to.
    //
    // The same two lines on_chan_req() runs for a request that came the long
    // way round, deliberately: a key served over a direct link and the same key
    // served through the daemon must not be able to differ.  A free function
    // because shard_link knows nothing about runtimes and should not.
    static bool worker_serve_mesh(void* ctx, std::string_view /*target*/,
                                  std::string_view payload, std::string& reply)
    {
        auto* self = static_cast<worker*>(ctx);
        if (!self || !self->m_rt)
            return false;
        auto* sink = self->m_rt->as_request_sink();
        if (!sink)
            return false;
        sink->serve_request(payload, reply);
        return true;
    }

    // Crossings by route, summed over this shard's links.
    //
    // Reported because the relay fallback makes a mesh that never connects look
    // exactly like one that made no difference: same throughput, same green
    // tests.  Without these two numbers the benchmark cannot tell them apart.
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

        // request_status::no_target if there is nothing to ask.  The daemon
        // cannot know that from its side: the placeholder exists whether or not
        // this worker ever built its runtime.
        uint8_t     st = 1;   // no_target
        std::string reply;
        if (m_rt)
        {
            if (auto* sink = m_rt->as_request_sink())
            {
                sink->serve_request(q.payload, reply);
                st = 0;       // ok
            }
        }

        if (!m_writer.write(worker_proto::frame(worker_proto::frame_type::chan_rep,
                          worker_proto::encode_chan_reply(q.ticket, st, reply)))) {}
    }

    // The answer to something this worker's runtime asked of a runtime it
    // cannot see.  The ticket is one this process issued, so it can only ever
    // match a request parked here — a chan_rep the other way carries the
    // daemon's ticket and is read by the daemon, never by this.  The two
    // namespaces never meet, which is why neither needs a tag.
    void on_chan_rep(const std::string& payload)
    {
        worker_proto::chan_reply_wire p;
        if (!worker_proto::decode_chan_reply(payload, p))
            return;

        m_manager.requests().complete_deferred(
            p.ticket, static_cast<request_status>(p.status), p.payload);
    }

    // `socketley send` reaching the process that holds the connections.
    //
    // The same two calls cmd_send() makes on an in-process runtime, and the same
    // mode test: a server in `in` mode and a client in `in` mode both read only,
    // so a broadcast to one is a message with nowhere to go.
    void on_deliver(const std::string& message)
    {
        deliver_local(message);
    }

    // The two calls cmd_send() makes on an in-process runtime, against the one
    // runtime this process holds.
    //
    // Reached from two directions now.  A `deliver` frame is the daemon routing
    // somebody else's send here, and a `socketley.send(self, ...)` from this
    // worker's own script is the same delivery with no wire between the ask and
    // the answer — so it is short-circuited in the deliver sink rather than sent
    // up for the daemon to send straight back down.  One body, because the two
    // must not be able to disagree about what `send` does to a runtime in `in`
    // mode.
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
                    srv->lua_broadcast(message);
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

    // A message for one of THIS shard's connections, sent by a sibling.
    //
    // write_to_ref() is the same function a routed-in message from another
    // runtime lands in, and it already checks the three things that matter:
    // that the name is ours to resolve, that it still resolves, and that what
    // it resolves to is the connection it named when it was minted.  A ref for
    // a client that has since gone answers false and the message is dropped —
    // which is conn_identity.h's whole promise, and the reason nothing here has
    // to guess.
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
        // out.  start and config arrive together — the supervisor sends both
        // before the first drain — so a refusal in on_config() is followed by
        // this in the same batch, and without the guard the worker took the port,
        // reported "proxy failed to start", and exited: a listener opened and
        // closed for a configuration it had already refused.
        if (m_done || !m_rt || m_rt->get_state() == runtime_running)
            return;

        // The second of the two checks the note above claim_current_daemon()
        // describes, and the one it exists for: start() is what binds, and a
        // bind is what joins the SO_REUSEPORT group.  Everything between the
        // fork and this line — the config frame, the script's top level, the
        // ring being built — is time in which the daemon can die, and a worker
        // that binds afterwards is the stale shard that goes on serving 1/N of
        // the traffic from a build nobody thinks is running.
        //
        // Refused rather than deferred: there is no daemon left to tell, and a
        // worker that cannot name its owner has nothing to wait for.
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

        // A raise in on_start does not stop this runtime serving and is not
        // meant to — start() says why — but `create -s` is still holding the
        // operator's terminal, and out here its script's set-up is the one
        // thing that side cannot observe.  Written before send_state(), which
        // is what ends the daemon's wait, for the reason the reload path gives
        // at the same point: an answer that arrives after the wait has ended is
        // an answer nobody reads.
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

    // `reload-lua` reached this runtime.  The script runs here and nowhere else,
    // so the daemon cannot re-read it on this runtime's behalf; it can only ask,
    // which is what this frame is.
    //
    // The answer goes back unconditionally, which is where this differs from
    // on_config() above.  A fresh child has no predecessor and the daemon holds
    // nothing to clear, so sending nothing there means "no declaration".  After a
    // reload the daemon may be holding the *previous* version of this script's
    // declaration, and a script that has deleted a route -- or its whole `routes`
    // table -- has to be able to withdraw it.  An empty frame is what withdraws
    // it: publish_endpoints() drops a declaration with nothing in it, so the
    // gateway goes back to forwarding rather than being left enforcing a rule the
    // handler has removed.  Silently, in that case, because nothing but `stats`
    // reports what the gate holds.
    void on_reload()
    {
        if (!m_rt || m_rt->get_lua_script_path().empty())
            return;
        // A script that will not compile leaves the previous one in force --
        // reload_lua_script()'s own contract -- so the declaration read below is
        // still the one being enforced in that case, and still the right answer.
        //
        // But it is not the answer the operator asked for, and the WARN below
        // is in a log they are not reading.  The reason goes up the control
        // socket as well, so `reload-lua` can refuse rather than reporting
        // success for an edit that did not take effect.  Written before the
        // routes frame, which is what ends the daemon's wait.
        //
        // The WARN no longer claims the previous script survived, because that
        // is only true of one of the two ways to reach it.  A script that will
        // not compile leaves the previous one running; a script that compiled
        // and then raised in on_start IS the one in force, with whatever set-up
        // it managed before it failed.  The reason distinguishes them.
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
    remote_sink                            m_remote;
    // A replica of the daemon's map, and a live channel.  See the wiring in
    // on_config() and the runtime_map frame that fills the map in.
    //
    // The map was empty on purpose until that frame existed, and everything that
    // looked a name up in it got the truth for a process holding one runtime:
    // nothing.  What that cost was the twelve management calls a worker refuses,
    // all of which reach for this object.
    //
    // Declared before the runtime so it outlives it: a runtime revokes its
    // origin as it is destroyed, and that call needs a channel that is still
    // there — the same ordering runtime_manager itself documents, and the same
    // UBSan report if it is got wrong.
    runtime_manager                        m_manager;
    std::unique_ptr<runtime_instance>       m_owned;
    // The runtime this worker owns, and the same pointer narrowed when it
    // happens to be a proxy.  Everything generic goes through m_rt; m_proxy is
    // for the two things only a proxy has — its own config applier and the
    // endpoint table it routes with.
    runtime_instance*                      m_rt{nullptr};
    proxy_instance*                        m_proxy{nullptr};
    std::shared_ptr<const endpoint_table>  m_pending_endpoints;
    std::string                            m_in;
    io_request                             m_ctl_req{};
    bool                                   m_ctl_armed{false};
    // Where the ring's recv puts the frame.  Read only from on_cqe(), and only
    // for the length the completion reports; the recv that owns it is the one
    // named by m_ctl_req and there is never more than one.
    //
    // 4096 was what the ::read() loop used, and that loop went round again.  A
    // recv does not, so a short buffer is a second completion and a second
    // turn.  16 KiB holds the largest frame this socket carries under load —
    // a chan_req or a chan_rep with a batch of cache commands in it — and
    // costs one page more per worker.
    char                                   m_ctl_buf[16 * 1024];
    // The daemon closed, or the recv failed for a reason that is not going to
    // get better.  Set in on_cqe(), acted on by drain_frames().
    bool                                   m_ctl_eof{false};
    bool                                   m_done{false};
    int                                    m_exit_code{0};
};

} // namespace

int proxy_worker_main(int control_fd)
{
    if (control_fd < 0)
        return 2;

    // ─── Before anything else this process could go on to do ────────────────
    //
    // The order of these two is the whole of what makes them race-free, and it
    // is the reverse of the intuitive one.  Ask the kernel to signal us on our
    // parent's death FIRST, then ask whether that parent is still there: a
    // daemon that died before the prctl will never produce the signal, and the
    // getppid() check is what catches exactly that window.  Doing it the other
    // way round leaves the window open instead of closing it.
    //
    // See the note above claim_current_daemon() for why a worker has to be able
    // to prove this at all, and why the signal is SIGTERM.
    if (::prctl(PR_SET_PDEATHSIG, SIGKILL) < 0) {}

    if (!claim_current_daemon(control_fd))
        return 2;

    // Before the first line this process might want to log.  A worker reads no
    // configuration file, so without this its level is the built-in default and
    // every LOG_DEBUG out here — including the ones in the runtime it is about
    // to build — is unreachable however the daemon was configured.
    inherit_log_level();

    // Before any interpreter exists, because it decides what one is built with.
    // This process holds one runtime and no map of runtimes, so the cross-runtime
    // half of the Lua management API has nothing here to answer from and says so
    // instead of answering nothing.
    lua_context::set_worker_process(true);
    // The same fact, in the bit that survives a SOCKETLEY_NO_LUA build.  Read by
    // the --shards placement rule, which would otherwise refuse every shard of a
    // runtime the daemon had just accepted -- see shards_config_refusal.
    set_worker_process(true);

    worker w(control_fd);
    return w.run();
}
