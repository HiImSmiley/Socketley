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
#include "../../shared/endpoint_table.h"
#include "../../shared/event_loop.h"
#include "../../shared/logging.h"
#include "../../shared/lua_context.h"
#include "../../shared/runtime_config_apply.h"
#include "../../shared/runtime_factory.h"
#include "../../shared/runtime_instance.h"
#include "../../shared/state_persistence.h"
#include "../../shared/worker_protocol.h"

namespace
{

// How often the worker publishes its figures.  Short enough that `stats` and
// the metrics endpoint are answering about the present, long enough that a busy
// proxy is not spending its event loop building strings: the detail text is
// produced by get_stats(), which walks the connection tables.
constexpr auto stats_interval = std::chrono::milliseconds(250);

bool write_all(int fd, std::string_view buf)
{
    size_t off = 0;
    while (off < buf.size())
    {
        const ssize_t n = ::write(fd, buf.data() + off, buf.size() - off);
        if (n > 0) { off += static_cast<size_t>(n); continue; }
        if (n < 0 && (errno == EINTR))
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            // The daemon is not draining us.  Dropping the frame is right for
            // stats — the next one supersedes it anyway — and the caller treats
            // a false return as "not sent", never as "connection lost".
            return false;
        }
        return false;
    }
    return true;
}

class worker
{
public:
    explicit worker(int control_fd) : m_fd(control_fd) {}

    int run()
    {
        // The daemon may die while we are serving.  Without this the worker
        // keeps forwarding traffic for a proxy nobody is supervising any more;
        // with it, a write to the closed control socket ends the process
        // instead of raising SIGPIPE.
        signal(SIGPIPE, SIG_IGN);

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

        while (!m_done)
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
        if (m_proxy && m_proxy->get_state() == runtime_running)
            m_proxy->stop(m_loop);
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

    void send_hello()
    {
        std::string payload;
        worker_proto::put_u32(payload, static_cast<uint32_t>(::getpid()));
        if (!write_all(m_fd, worker_proto::frame(worker_proto::frame_type::hello, payload))) {}
    }

    void send_state()
    {
        std::string payload;
        payload.push_back(static_cast<char>(
            m_proxy ? static_cast<uint8_t>(m_proxy->get_state())
                    : static_cast<uint8_t>(runtime_created)));
        if (!write_all(m_fd, worker_proto::frame(worker_proto::frame_type::state, payload))) {}
    }

    void push_stats()
    {
        if (!m_proxy)
            return;

        // On the event-loop thread, which is the only thread allowed to walk
        // the proxy's connection tables.  Everything that leaves this process
        // is a copy taken here.
        worker_proto::stats_wire s;
        s.total_connections  = m_proxy->m_stat_total_connections.load(std::memory_order_relaxed);
        s.total_messages     = m_proxy->m_stat_total_messages.load(std::memory_order_relaxed);
        s.bytes_in           = m_proxy->m_stat_bytes_in.load(std::memory_order_relaxed);
        s.bytes_out          = m_proxy->m_stat_bytes_out.load(std::memory_order_relaxed);
        s.active_connections = static_cast<uint64_t>(m_proxy->get_connection_count());
        s.detail             = m_proxy->get_stats();

        if (!write_all(m_fd, worker_proto::frame(worker_proto::frame_type::stats,
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
            case worker_proto::frame_type::start:     on_start();            break;
            case worker_proto::frame_type::stop:      on_stop();             break;
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
        if (m_proxy)
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
        // Nothing is passed today, so the ring lands on the same environment
        // the daemon was launched with, exactly as before.
        //
        // Guarded on ring_open() rather than on reaching here once: a config
        // that got as far as the ring and then failed to build a proxy leaves
        // m_proxy null, and a second config frame must not build a second ring
        // over the first.
        if (!m_loop.ring_open() && !m_loop.init())
        {
            LOG_ERROR("proxy worker: could not initialise io_uring");
            m_done = true;
            return;
        }

        auto inst = create_runtime(runtime_proxy, cfg.name);
        if (!inst)
        {
            LOG_ERROR("proxy worker: could not create proxy instance");
            return;
        }
        m_owned = std::move(inst);
        m_proxy = static_cast<proxy_instance*>(m_owned.get());

        m_proxy->set_event_loop(&m_loop);
        m_proxy->set_id(cfg.id);
        if (cfg.port > 0)               m_proxy->set_port(cfg.port);
        if (!cfg.group.empty())         m_proxy->set_group(cfg.group);
        if (!cfg.log_file.empty())      m_proxy->set_log_file(cfg.log_file);
        if (!cfg.write_file.empty())    m_proxy->set_write_file(cfg.write_file);
        if (cfg.bash_output)            m_proxy->set_bash_output(true);
        if (cfg.bash_prefix)            m_proxy->set_bash_prefix(true);
        if (cfg.bash_timestamp)         m_proxy->set_bash_timestamp(true);
        if (cfg.max_connections > 0)    m_proxy->set_max_connections(cfg.max_connections);
        if (cfg.rate_limit > 0.0)       m_proxy->set_rate_limit(cfg.rate_limit);
        if (cfg.global_rate_limit > 0.0)m_proxy->set_global_rate_limit(cfg.global_rate_limit);
        if (cfg.idle_timeout > 0)       m_proxy->set_idle_timeout(cfg.idle_timeout);
        if (cfg.drain)                  m_proxy->set_drain(true);
        if (cfg.tls)                    m_proxy->set_tls(true);
        if (!cfg.cert_path.empty())     m_proxy->set_cert_path(cfg.cert_path);
        if (!cfg.key_path.empty())      m_proxy->set_key_path(cfg.key_path);
        if (!cfg.ca_path.empty())       m_proxy->set_ca_path(cfg.ca_path);
        if (!cfg.target.empty())        m_proxy->set_target(cfg.target);

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
        if (!cfg.lua_script.empty() && !m_proxy->load_lua_script(cfg.lua_script))
        {
            LOG_ERROR("proxy worker: lua script did not load; refusing to serve "
                      "without it (the script's own error is above)");
            m_exit_code = worker_proto::exit_config_refused;
            m_done      = true;
            return;
        }

        apply_proxy_config(*m_proxy, cfg);

        // A table that arrived before the config is not lost: it is held and
        // applied here.  The daemon publishes on every membership change, and
        // nothing orders those against the config frame.
        if (m_pending_endpoints)
        {
            m_proxy->set_endpoints(std::move(m_pending_endpoints));
            m_pending_endpoints.reset();
        }

        send_state();
    }

    void on_endpoints(const std::string& payload)
    {
        std::vector<worker_proto::endpoint_wire> names, groups;
        if (!worker_proto::decode_endpoints(payload, names, groups))
        {
            LOG_WARN("proxy worker: malformed endpoint table, keeping the previous one");
            return;
        }

        auto tbl = std::make_shared<endpoint_table>();
        for (const auto& e : names)
            tbl->set_name(e.name, runtime_endpoint{e.host, e.port});
        for (const auto& e : groups)
            tbl->add_to_group(e.name, runtime_endpoint{e.host, e.port});

        // Immutable from here, exactly as on the daemon side: a request that is
        // already resolving keeps the table it started with.
        if (m_proxy)
            m_proxy->set_endpoints(std::move(tbl));
        else
            m_pending_endpoints = std::move(tbl);
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
    void on_publish(const std::string& payload)
    {
        if (!m_proxy)
            return;

        worker_proto::publish_wire p;
        if (!worker_proto::decode_publish(payload, p))
        {
            LOG_WARN("proxy worker: malformed publish frame, dropped");
            return;
        }

        m_proxy->on_publish_dispatch(p.cache_name, p.channel, p.message);
    }

    void on_start()
    {
        // A worker that has decided to exit must not bind anything on the way
        // out.  start and config arrive together — the supervisor sends both
        // before the first drain — so a refusal in on_config() is followed by
        // this in the same batch, and without the guard the worker took the port,
        // reported "proxy failed to start", and exited: a listener opened and
        // closed for a configuration it had already refused.
        if (m_done || !m_proxy || m_proxy->get_state() == runtime_running)
            return;
        if (!m_proxy->start(m_loop))
            LOG_ERROR("proxy worker: proxy failed to start");
        send_state();
    }

    void on_stop()
    {
        if (!m_proxy || m_proxy->get_state() != runtime_running)
            return;
        m_proxy->stop(m_loop);
        send_state();
    }

    int                                    m_fd;
    event_loop                             m_loop;
    std::unique_ptr<runtime_instance>       m_owned;
    proxy_instance*                        m_proxy{nullptr};
    std::shared_ptr<const endpoint_table>  m_pending_endpoints;
    std::string                            m_in;
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
