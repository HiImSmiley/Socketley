#include "proxy_worker.h"

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
#include "../../shared/worker_protocol.h"

namespace
{

// How often the worker publishes its figures.  Short enough that `stats` and
// the metrics endpoint are answering about the present, long enough that a busy
// proxy is not spending its event loop building strings: the detail text is
// produced by get_stats(), which walks the connection tables.
constexpr auto stats_interval = std::chrono::milliseconds(250);

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

extern "C" void worker_on_term(int) { g_term_requested = 1; }

// Frames on their way to the daemon, and what happens when it is not reading.
//
// This was a straight write that dropped the frame on EAGAIN, which was right
// while the socket carried stats: the next push supersedes the one that did not
// fit. It is wrong for a request or a reply. A dropped chan_req is answered
// `no such runtime` by the asking side — for a target that exists — and a
// dropped chan_rep is an answer that never comes, so the origin waits until its
// client gives up.
//
// Queued and flushed as the socket takes them, with a cap so a daemon that has
// stopped reading cannot grow this process without limit.
class control_writer
{
public:
    static constexpr size_t MAX_BACKLOG = 4u << 20;

    explicit control_writer(int fd) : m_fd(fd) {}

    bool write(std::string_view framed)
    {
        if (pending() + framed.size() > MAX_BACKLOG)
        {
            if (!m_full)
            {
                LOG_WARN("proxy worker: control backlog full; the daemon is not reading");
                m_full = true;
            }
            return false;
        }
        m_full = false;
        m_out.append(framed);
        flush();
        return true;
    }

    void flush()
    {
        while (m_off < m_out.size())
        {
            const ssize_t n = ::write(m_fd, m_out.data() + m_off, m_out.size() - m_off);
            if (n > 0) { m_off += static_cast<size_t>(n); continue; }
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                break;
            m_dead = true;          // the daemon is gone; run() ends on the read side
            return;
        }

        // Compacted in one move: erasing the written prefix on every pass is
        // quadratic in exactly the backlog this exists to hold.
        if (m_off >= m_out.size())      { m_out.clear(); m_off = 0; }
        else if (m_off >= 64 * 1024)    { m_out.erase(0, m_off); m_off = 0; }
    }

    size_t pending() const { return m_out.size() - m_off; }
    bool   dead()    const { return m_dead; }

private:
    int         m_fd;
    std::string m_out;
    size_t      m_off{0};
    bool        m_full{false};
    bool        m_dead{false};
};

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
        : m_fd(control_fd), m_writer(control_fd), m_remote(&m_writer) {}

    void on_cqe(struct io_uring_cqe* /*cqe*/) override
    {
        // Nothing to do but stop waiting.  The frame is drained by the
        // pump_control() the main loop already runs on every turn, and re-armed
        // there too — doing either here would give this socket two readers.
        m_ctl_armed = false;
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

        while (!m_done && !g_term_requested)
        {
            // One drain pass of the ring, with a short wait so an idle worker
            // is not spinning.  run() is not usable here: it owns the thread
            // until the ring stops, and the control socket has to be serviced
            // between completions.
            //
            // Before the ring exists poll_completions() returns at once no
            // matter what timeout it is handed, so the wait has to come from
            // somewhere else or this loop is a spinning core for as long as the
            // config takes to arrive.  Waiting on the control socket is the
            // right place for it anyway: the frame is the only thing that can
            // happen to a worker in that window.
            if (m_loop.ring_open())
                m_loop.poll_completions(20);
            else
                wait_for_control(20);

            if (!pump_control())
                break;

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

            const auto now = std::chrono::steady_clock::now();
            if (now - last_stats >= stats_interval)
            {
                push_stats();
                last_stats = now;
            }
        }

        // Same order the daemon uses on its way down: stop the runtime while
        // there is still a ring for teardown() to cancel into, and only then
        // end the ring.  Reversing these two is what turned a clean shutdown
        // into a segfault the last time it was got wrong.
        if (m_rt && m_rt->get_state() == runtime_running)
            m_rt->stop(m_loop);

        // Before the ring, like every other owner registration: detach answers
        // whatever is still queued `dropped` and gives the owner token back.
        m_manager.requests().detach();
        if (m_ctl_armed)
        {
            if (!m_loop.submit_poll_remove(&m_ctl_req)) {}
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

    // Block until the control socket has something or the timeout runs out.
    // Only used before there is a ring; afterwards the ring's own wait covers
    // it, and the control socket is drained between completions.
    void wait_for_control(int timeout_ms) const
    {
        struct pollfd pfd{m_fd, POLLIN, 0};
        if (::poll(&pfd, 1, timeout_ms) < 0) {}
    }

    // Make the ring's wait end when a frame arrives instead of when the timeout
    // does.  One-shot: the fd outlives every arm here, but a multishot poll on
    // it would still be reporting after shutdown_ring() and there is nothing to
    // gain from it — one SQE per exchange against a socket that carries one
    // frame at a time.
    void arm_control()
    {
        if (!m_loop.ring_open() || m_ctl_armed)
            return;
        // POLLOUT only while something is waiting to go out, so an idle worker
        // is not woken by a socket that is merely writable.
        const unsigned mask = POLLIN | (m_writer.pending() ? POLLOUT : 0u);
        m_ctl_req   = { this, nullptr, m_fd, 0, op_poll };
        m_ctl_armed = m_loop.submit_poll_add(m_fd, mask, &m_ctl_req);
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

    void push_stats()
    {
        if (!m_rt)
            return;

        // On the event-loop thread, which is the only thread allowed to walk
        // the proxy's connection tables.  Everything that leaves this process
        // is a copy taken here.
        worker_proto::stats_wire s;
        s.total_connections  = m_rt->m_stat_total_connections.load(std::memory_order_relaxed);
        s.total_messages     = m_rt->m_stat_total_messages.load(std::memory_order_relaxed);
        s.bytes_in           = m_rt->m_stat_bytes_in.load(std::memory_order_relaxed);
        s.bytes_out          = m_rt->m_stat_bytes_out.load(std::memory_order_relaxed);
        s.active_connections = static_cast<uint64_t>(m_rt->get_connection_count());
        s.detail             = m_rt->get_stats();

        // Stamped here, after the reads and before the write, because this is
        // the moment the figures describe.  The daemon cannot recover it: what
        // it can observe is when the frame came off the socket, which is later
        // by however long nothing drained — up to a health tick, not up to a
        // publish interval.  A frame that waits does not become newer.
        s.taken_ns = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                .count());

        if (!m_writer.write(worker_proto::frame(worker_proto::frame_type::stats,
                                                 worker_proto::encode_stats(s)))) {}
    }

    // Returns false when the control socket is gone, which is the worker's
    // instruction to exit: a proxy whose supervisor has died has nobody to
    // report to and nobody to stop it.
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
            case worker_proto::frame_type::endpoints: on_endpoints(payload); break;
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

        // ── the channel, both directions ────────────────────────────────────
        //
        // A runtime asks through its manager, and a worker had none: every
        // `cache` command a server in a worker was given died at the
        // `if (!mgr) return;` in post_cache_request(), unanswered.  The map
        // stays empty on purpose — this process holds one runtime and the
        // manager is here for the channel — and every call site that looks a
        // name up in it already handles not finding one, which in a worker is
        // the truth rather than a failure.
        //
        // Its own name is registered so a request for it is served here rather
        // than making a round trip through the daemon, which would route it
        // back to this very worker.
        // The ring exists from here, so the control socket can be armed on it.
        m_loop.register_owner(this);

        m_manager.requests().attach(m_loop);
        if (auto* sink = m_rt->as_request_sink())
            m_manager.requests().register_sink(cfg.name, sink);
        m_manager.requests().set_default_sink(&m_remote);
        m_rt->set_runtime_manager(&m_manager);

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
        if (!m_rt->start(m_loop))
            LOG_ERROR("proxy worker: proxy failed to start");
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
        // still the one being enforced either way, and still the right answer.
        if (!m_rt->reload_lua_script())
            LOG_WARN("proxy worker: reload-lua could not load the script; the "
                     "previous one is still in force");
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
    remote_sink                            m_remote;
    // Empty map, live channel.  See the wiring in on_config().  Declared before
    // the runtime so it outlives it: a runtime revokes its origin as it is
    // destroyed, and that call needs a channel that is still there — the same
    // ordering runtime_manager itself documents, and the same UBSan report if
    // it is got wrong.
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
    bool                                   m_done{false};
    int                                    m_exit_code{0};
};

} // namespace

int proxy_worker_main(int control_fd)
{
    if (control_fd < 0)
        return 2;

    // Before any interpreter exists, because it decides what one is built with.
    // This process holds one runtime and no map of runtimes, so the cross-runtime
    // half of the Lua management API has nothing here to answer from and says so
    // instead of answering nothing.
    lua_context::set_worker_process(true);

    worker w(control_fd);
    return w.run();
}
