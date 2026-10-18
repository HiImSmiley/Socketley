#pragma once
#include <string>
#include <string_view>
#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include "../http/route_table.h"
#include "../loop/write_queue.h"
#include <chrono>
#include <sstream>
#include <utility>
#include <vector>
#include <algorithm>
#include <functional>
#include <mutex>
#include <sys/types.h>

#ifndef SOCKETLEY_NO_LUA
#include <sol/sol.hpp>
#endif
#include "../loop/liburing_version.h"   // must precede <liburing.h>; see that file
#include <liburing.h>
#include "runtime_definitions.h"
#include "../ipc/shard_stats.h"
#include "../ipc/shard_clients.h"
#include "../loop/event_loop_definitions.h"
#include "../persist/appending_file.h"

class event_loop;
class lua_context;
class runtime_manager;
class endpoint_table;
class request_sink;
class server_instance;

class runtime_instance : public io_handler
{
public:
    runtime_instance(runtime_type type, std::string_view name);
    ~runtime_instance() override;

    bool start(event_loop& loop);
    bool stop(event_loop& loop);

    void on_cqe(struct io_uring_cqe* cqe) override = 0;
    virtual bool setup(event_loop& loop) = 0;
    virtual void teardown(event_loop& loop) = 0;

    runtime_state get_state() const;
    runtime_type get_type() const;

    // True once start() has entered setup(), never cleared, because the kernel
    // may hold the address of an io_request inside this object long after
    // stop() ran.
    bool has_armed_io() const;

    // What the last invoke_on_start() raised, kept on the runtime rather than
    // in lua_diag, and cleared at the top of every attempt, because a start
    // may not fail on a raise but may still say.
    const std::string& last_on_start_error() const;

    std::string_view get_name() const;
    void set_name(std::string_view name);
    std::string_view get_id() const;
    void set_id(std::string_view id);

    std::chrono::system_clock::time_point get_created_time() const;
    std::chrono::system_clock::time_point get_start_time() const;

    // A worker the supervisor replaced, which start() never sees: the uptime
    // becomes the new child's or `ls` reports a life the process did not have,
    // and the count is the only sign left that a store was lost.
    void     note_restart();
    unsigned restart_count() const { return m_restarts.load(std::memory_order_relaxed); }

    // A live worker that has stopped answering, decided by the supervisor and
    // held here because `ls` reads instances and not supervisors.
    void set_unresponsive(bool v) { m_unresponsive = v; }
    bool is_unresponsive() const  { return m_unresponsive; }

    void set_port(uint16_t port);
    uint16_t get_port() const;

    // Where this runtime listens when that is not a port, empty for the
    // ordinary TCP case, kept here because the things that ask a runtime where
    // it listens do not know its type.
    void set_listen_path(std::string_view path);
    std::string_view get_listen_path() const;

    // The IPv4 address a port listener binds, as `-p address:port` names it, empty for every address.
    void set_bind_address(std::string_view address);
    std::string_view get_bind_address() const;
    // The address bind() is given in network order, INADDR_ANY for none.
    uint32_t bind_in_addr() const;

    // The node this runtime also answers on, beside its port.  Set by the
    // daemon, empty for a runtime that has only one way in -- which is every
    // runtime with TLS, with no port, or already listening on a path.
    void set_companion_path(std::string_view path);
    std::string_view get_companion_path() const;

    // Every node of this runtime, one per shard, held by the daemon's
    // placeholder to publish; a worker holds only its own one, above.
    void set_companion_paths(std::vector<std::string> paths);
    const std::vector<std::string>& get_companion_paths() const;

    void set_log_file(std::string_view path);
    std::string_view get_log_file() const;

    void set_write_file(std::string_view path);
    std::string_view get_write_file() const;

    void set_test_mode(bool enabled);
    bool get_test_mode() const;

    void set_target(std::string_view target);
    std::string_view get_target() const;

    void set_cache_name(std::string_view name);
    std::string_view get_cache_name() const;

    // Bash output settings
    void set_bash_output(bool enabled);
    void set_bash_prefix(bool enabled);
    void set_bash_timestamp(bool enabled);
    bool get_bash_output() const;
    bool get_bash_prefix() const;
    bool get_bash_timestamp() const;

    // Connection count, event-loop thread only and meaningful only in the
    // process holding the connections, since it walks this object's tables.
    virtual size_t get_connection_count() const { return 0; }

    // What to print, decided once here rather than at each call site, because
    // a placeholder's tables are empty and its figures arrive in a pushed
    // frame.
    size_t reported_connection_count() const
    {
        if (!worker_backed())
            return get_connection_count();
        // Summed out of the shared table at this instant, with the load below
        // the fallback for a runtime whose memfd could not be made.
        if (m_shard_stats.mapped())
            return static_cast<size_t>(m_shard_stats.sum_active());
        return static_cast<size_t>(m_stat_active_connections.load(std::memory_order_relaxed));
    }

    // Max connections
    // Re-read the limits a runtime copies out of its configuration at setup.
    //
    // The hot paths compare against a cached copy rather than calling a virtual
    // getter per accept and per message, which made every setter a lie for a
    // runtime that was already running: `edit NAME --max-connections 1` reached
    // the worker, set the field, and the accept path went on reading the value
    // from before.  A type that caches overrides this; one that does not needs
    // nothing.
    virtual void refresh_cached_limits() {}

    void set_max_connections(uint32_t max);
    uint32_t get_max_connections() const;

    // Rate limiting (messages per second, 0 = unlimited)
    void set_rate_limit(double rate);
    double get_rate_limit() const;

    // Global rate limiting (across all connections, messages per second, 0 = unlimited)
    void set_global_rate_limit(double rate);
    double get_global_rate_limit() const;

    // Idle connection timeout (seconds, 0 = disabled)
    void set_idle_timeout(uint32_t seconds);
    uint32_t get_idle_timeout() const;

    // ─── How much may be owed to one connection ─────────────────────────────
    // The write queue's bound, per connection, which was two compile-time
    // constants and therefore the same for a runtime serving four large
    // transfers and one serving ten thousand small ones.  The arithmetic is
    // what makes it a knob: 8 MiB times ten thousand connections is 80 GB, and
    // a box with 11 GiB serves about a thousand before it is the memory and
    // not the code that decides.
    //
    // One value and not two: the watermark is half the bound, which is the
    // ratio the constants had, so a caller has one number to reason about
    // rather than a pair that can be set inconsistently.
    void set_write_buffer(size_t bytes);
    size_t get_write_buffer() const;
    // The bound, past which the connection is closed because it is not going
    // to catch up.
    size_t write_buffer_bytes() const { return m_write_buffer; }
    // And the point where a producer is told to pace and a reader is stopped,
    // with room left to absorb what is already in flight.
    //
    // Divided by the number of live connections rather than fixed at half the
    // bound, because what has to fit in cache is the TOTAL in flight and not one
    // stream's share of it: half of 8 MiB is right for a few large transfers and
    // wrong by an order of magnitude for sixty-four of them.  Clamped to the
    // configured half at the top, so a runtime told to keep little keeps little,
    // and to one message at the bottom.
    size_t write_watermark_bytes() const { return m_write_watermark; }

    // What this runtime owes across all its connections right now, which is the
    // quantity that has to fit in cache -- 0 from a type that has not been
    // measured yet, which reads as "nothing is backed up" and keeps that type on
    // the behaviour it had.
    virtual size_t total_queued_bytes() const { return 0; }

    // Recomputed once per loop turn, from the one place in worker_main that runs
    // every turn for every runtime type -- so no accept or close path has to
    // remember, and a value one turn stale paces on the previous turn's numbers,
    // which is microseconds old and never unsafe: the bound that closes a
    // connection is not this number.
    // `now` is the caller's, because the worker reads the clock once a turn.
    void refresh_pacing_watermark(std::chrono::steady_clock::time_point now)
    {
        // Sticky for a while after the budget is exceeded, because the total is
        // sampled once a turn and the queues drain between turns: tested on the
        // instant, a runtime at 64 streams reads "not backed up" most turns and
        // goes straight back to the deep point, which measured +3 per cent where
        // the same streams paced throughout are worth +18.

        // The SUM is sampled on an interval; the two lines below it are not.
        //
        // total_queued_bytes() walks every connection this runtime holds, and
        // each step is a pointer into a separate allocation -- a cache miss per
        // connection.  Measured on a server doing one ping-pong per loop turn,
        // with every other connection idle and holding nothing at all:
        //
        //     open      p50 round trip     worker CPU per request
        //     1001          26.3 us              26.7 us
        //     3001          56.7 us              96.7 us
        //     5001         124.9 us             193.3 us
        //
        // and a profile at 5001 put 81.72% of the worker inside this one call.
        // The answer it was computing five thousand times a second was zero.
        //
        // Sampling is safe in the way the walk's own comment already argued:
        // the value feeds a hold that lasts fifty milliseconds, so an interval
        // well under that cannot change which side of the budget a runtime
        // spends its time on -- and "the bound that closes a connection is not
        // this number", the per-connection watermark still applies every turn.
        if (now >= m_pacing_sample_due)
        {
            m_pacing_sample_due = now + std::chrono::milliseconds(2);
            if (total_queued_bytes() >= socketley::write_pacing_budget)
                m_pacing_hold_until = now + std::chrono::milliseconds(50);
        }

        // Expiry stays per turn: a runtime that has drained must stop pacing on
        // the turn its hold runs out, not on the next sample.
        m_pacing_backed_up = now < m_pacing_hold_until;
        m_write_watermark = pacing_watermark_for(get_connection_count(),
                                                 m_pacing_backed_up);
    }

    // The same sticky state the watermark was just derived from, for a runtime
    // that has to act on the fact and not only on the number it produced.
    bool pacing_backed_up() const { return m_pacing_backed_up; }

    // ─── And how much may be accumulated FROM one connection ────────────────
    // The inbound twin, which was MAX_PARTIAL_SIZE -- a constexpr repeated in
    // all four runtimes at 1 MiB -- with the cache's RESP bulk cap sitting at
    // 512 KB beside it.  Those two were already exactly 2:1, so the halving is
    // named here rather than introduced: the accumulation bound is the buffer,
    // and the largest single value inside it is half, which leaves room for
    // the framing around it.
    void set_read_buffer(size_t bytes);
    size_t get_read_buffer() const;
    size_t read_buffer_bytes() const { return m_read_buffer; }
    // Half, and as an int because the RESP decoders compare a parsed int
    // against it; clamped so a very large buffer cannot make it negative.
    int read_bulk_limit() const
    {
        const size_t half = m_read_buffer / 2;
        return half > static_cast<size_t>(INT32_MAX) ? INT32_MAX : static_cast<int>(half);
    }

    // Graceful shutdown
    void set_drain(bool enabled);
    bool get_drain() const;

    // Reconnect (client only)
    void set_reconnect(int max_attempts);
    int get_reconnect() const;

    // TLS
    void set_tls(bool enabled);
    bool get_tls() const;
    void set_cert_path(std::string_view path);
    std::string_view get_cert_path() const;
    void set_key_path(std::string_view path);
    std::string_view get_key_path() const;
    void set_ca_path(std::string_view path);
    std::string_view get_ca_path() const;
    // --acme: the names its certificate is issued for, comma-separated as given, and the account's contact.
    void set_acme_domains(std::string_view comma_list);
    const std::vector<std::string>& get_acme_domains() const { return m_acme_domains; }
    void set_acme_email(std::string_view email) { m_acme_email = email; }
    // --domain: the names this runtime is reached by, comma-separated as given, which a dns runtime with --publish
    // answers for. A storage runtime keeps its own, which also names its buckets' virtual hosts.
    void set_domains(std::string_view comma_list) { m_domains = comma_list; }
    std::string_view get_domains() const { return m_domains; }
    std::string_view get_acme_email() const { return m_acme_email; }

    // get_stats() and get_connection_count() read this instance's live
    // connection tables and are therefore event-loop thread only, while the
    // four counters below are atomics readable from anywhere.
    virtual std::string get_stats() const;

    // The three pieces get_stats() is made of, so that a runtime living in
    // another process can be printed from the two ends that know each part.
    //
    // ─── WHY THIS IS SPLIT AT ALL ───────────────────────────────────────────
    // The worker publishes stats_ring() + stats_lines() and the daemon puts
    // stats_prefix() in front, so `stats` is byte-identical on both sides and
    // the split says which process stated which figure.
    std::string stats_prefix() const;
    std::string stats_ring() const;
    virtual std::string stats_lines() const { return {}; }

    // The daemon's order to a cluster cache replica about its part, which no other runtime takes.
    virtual void on_replica_order(std::string_view /*payload*/) {}

    // Atomic for the DAEMON's copy of these, not the worker's.
    //
    // Both processes hold a runtime_instance and they use these four
    // differently.  In a worker the loop thread increments them and the same
    // loop thread reads them for its stats push -- one thread, so the lock
    // prefix on every fetch_add buys nothing.  In the daemon the main thread
    // stores the figures a worker reported (daemon_handler.cpp, in the
    // aggregation) while the metrics endpoint reads them from a thread of its
    // own -- metrics_endpoint.cpp calls enable_offthread_stats() and means it.
    // That reader is what the type is for.
    //
    // Measured before assuming it mattered: removing the message counter from
    // the server's per-message path entirely -- the upper bound on any change
    // here -- is +2.8 per cent at pipeline depth 400, with the arms
    // overlapping.  Worth knowing, because `lock xadd` against 197 cycles a
    // message looks arithmetically like ten.
    //
    // If it ever is worth it, the change is not to drop `atomic`: exactly one
    // thread WRITES in either process, so `store(load(relaxed) + 1, relaxed)`
    // is a plain add with no lock and stays correct for the reader.
    std::atomic<uint64_t> m_stat_total_connections{0};
    std::atomic<uint64_t> m_stat_total_messages{0};
    std::atomic<uint64_t> m_stat_bytes_in{0};
    std::atomic<uint64_t> m_stat_bytes_out{0};

    // That plain add, for a counter only the calling thread ever writes.
    static void stat_add(std::atomic<uint64_t>& counter, uint64_t n)
    {
        counter.store(counter.load(std::memory_order_relaxed) + n,
                      std::memory_order_relaxed);
    }

    // The figures to report whichever process holds them, computed when the
    // question is asked -- out of this object's atomics, or summed over the
    // shared table -- so there is no age to declare and any thread may call
    // it.
    shard_stats::figures worker_figures() const
    {
        // Mapped in the daemon for every worker-backed runtime and in a worker
        // for every sharded one, with worker_backed() keeping a worker reading
        // its own counters, since its `stats` text is labelled as one shard's.
        if (worker_backed() && m_shard_stats.mapped())
            return m_shard_stats.sum();

        // No region, so the four counters are this object's own atomics, and
        // active_connections is the published count because this runs on a
        // thread that may not walk a runtime's containers.
        return counted_figures(m_stat_active_connections.load(std::memory_order_relaxed));
    }

    // This object's four counters, with the active count the caller vouches for.
    shard_stats::figures counted_figures(uint64_t active) const
    {
        shard_stats::figures f;
        f.active_connections = active;
        f.total_connections  = m_stat_total_connections.load(std::memory_order_relaxed);
        f.total_messages     = m_stat_total_messages.load(std::memory_order_relaxed);
        f.bytes_in           = m_stat_bytes_in.load(std::memory_order_relaxed);
        f.bytes_out          = m_stat_bytes_out.load(std::memory_order_relaxed);
        return f;
    }

    // ── Off-thread view ─────────────────────────────────────────────────────
    // What a reader off the event-loop thread gets instead, because the
    // manager's mutex guards the runtime map and says nothing about what is
    // inside a runtime being rehashed underneath a walk.
    std::atomic<uint64_t> m_stat_active_connections{0};

    // Refresh both, event-loop thread only, with the get_stats() string built
    // before the lock so the lock covers a move and nobody waits on string
    // construction.
    //
    // Nothing at all for a runtime whose figures are its worker's.  Both of
    // these were written for an in-process runtime and neither is true of a
    // placeholder: get_connection_count() walks containers that are empty
    // here, and get_stats() for a worker-backed runtime is
    //
    //     stats_prefix() + stat_detail_snapshot()
    //
    // -- so storing its result back into m_stat_detail prepends a whole prefix
    // block to the text on every health tick.  While a worker is pushing,
    // set_worker_stats() overwrites it and nothing shows; once it stops
    // pushing, nothing does.  Measured with the metrics endpoint on, a stopped
    // runtime's `stats` text: 235 bytes, then 865, then 1495 over 24 seconds,
    // by then thirteen name: blocks stacked on top of each other.
    void publish_offthread_stats()
    {
        if (worker_backed())
            return;

        m_stat_active_connections.store(static_cast<uint64_t>(get_connection_count()),
                                        std::memory_order_relaxed);
        std::string detail = get_stats();
        std::lock_guard<std::mutex> lock(m_stat_detail_mutex);
        m_stat_detail = std::move(detail);
    }

    // The last published get_stats() text, empty until the first publish,
    // which callers already treat as no detail.
    std::string stat_detail_snapshot() const
    {
        std::lock_guard<std::mutex> lock(m_stat_detail_mutex);
        return m_stat_detail;
    }

    // What a worker still pushes: the part of `stats` that is not a summable
    // counter, and only when it changes, since the counters live in a shared
    // table the daemon sums at print time.
    void set_worker_stats(std::string detail, uint64_t active)
    {
        m_stat_active_connections.store(active, std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> lock(m_stat_detail_mutex);
            m_stat_detail = std::move(detail);
        }

        // Published after the detail it promises, with a release so a reader
        // that sees the flag also sees the text.
        m_worker_backed.store(true, std::memory_order_release);
    }

    // True once a worker has reported at least once, an atomic rather than
    // something under m_stat_detail_mutex because an in-process proxy reads it
    // on its own accept path.
    bool worker_backed() const
    {
        return m_worker_backed.load(std::memory_order_acquire);
    }

    // Straight to `failed`, for a supervisor that has decided a child is not
    // coming back, and not a transition any runtime makes to itself.
    void mark_failed() { store_state(runtime_failed); }

    // The state of a runtime living in another process, for replicas only,
    // because the daemon's own placeholder owns that value and sets it from
    // the command that caused the transition.
    void set_replicated_state(runtime_state s)
    { m_state.store(s, std::memory_order_release); }

    // Lua hot-reload
    bool reload_lua_script();
    std::string_view get_lua_script_path() const;

    // Interactive mode observer fds
    void add_interactive_fd(int fd);
    void remove_interactive_fd(int fd);
    void notify_interactive(std::string_view msg) const;

    // UDP mode (virtual, implemented by server/client)
    virtual bool is_udp() const { return false; }

    // Group tagging (for dynamic proxy backend discovery)
    void set_group(std::string_view group);
    std::string_view get_group() const;

    // Ownership system
    bool set_owner(std::string_view owner_name);
    std::string_view get_owner() const;
    void set_lua_created(bool v);
    bool is_lua_created() const;
    // A replica the cluster placed here, which its reconciliation owns and no state file may resurrect after a restart.
    void set_cluster_owned(bool v) { m_cluster_owned = v; }
    bool is_cluster_owned() const { return m_cluster_owned; }

    // External (attach) mode — runtime is managed by another process
    void mark_external();
    bool is_external() const;
    void set_pid(pid_t pid);
    pid_t get_pid() const;

    // The process each shard runs in, 0 where none does, kept for the metrics thread to read while the loop changes it.
    void set_shard_pid(uint32_t shard, pid_t pid);
    std::vector<pid_t> shard_pids() const;

    // Managed external — daemon owns fork+exec lifecycle
    void mark_managed(std::string exec_path);
    bool is_managed() const;
    std::string_view get_exec_path() const;

    // Is the server behind this name one I may call into, asked as one
    // question because a worker's replica of a server answers `runtime_server`
    // truthfully and the cast would then run server_instance's code over a
    // much smaller object.
    virtual server_instance* as_server() { return nullptr; }

    // Why this runtime's own configuration cannot be honoured, asked by
    // start() so that every route to a live runtime is covered by one answer
    // -- a command line, a state file the boot restore reads, a script's
    // `socketley.create` and an `import` all end here, and a check written in
    // any one of them is a check the other three walk past.
    virtual std::string config_refusal() const { return {}; }

    // Every address this runtime binds when it starts, and nothing at all for
    // one that binds none -- a client, an attached process, a server that is
    // only its owner's.  A set rather than one address because a clustered
    // cache holds a port per shard.
    //
    // Asked by the manager, which is the only place that can see two runtimes
    // claiming one address: SO_REUSEPORT is set so that --shards can share a
    // port, and it makes the kernel accept the second binder rather than
    // refuse it.  The spelling is "tcp:PORT", "udp:PORT" or "unix:PATH", and
    // it only has to be consistent between two instances -- nothing parses it
    // back.
    virtual void listen_addresses(std::vector<std::string>& /*out*/) const {}

    // The port this runtime will actually bind, which is not always the one it
    // was configured with: an unset -p means the type's default, and every
    // listing surface printed the raw zero -- "-" in `ps`, "port": 0 in `ps
    // --json` and in `stats` -- for a server that was serving on 8000.  An
    // operator could not learn from any command which port their runtime was
    // on.  Zero here means it binds no port at all.
    //
    // The same answer listen_addresses() is built from, so the number `ps`
    // prints and the number the address check refuses on cannot drift apart.
    // NOT what `show` prints: that document goes back into `import`, and
    // writing 8000 into it would pin a runtime that was deliberately left to
    // its default.
    virtual uint16_t effective_port() const { return 0; }

    // Out of process -- a placeholder for a runtime in a worker this daemon
    // supervises -- distinct from external/managed, and it changes only that
    // start()/stop() must not touch the ring.
    void mark_out_of_process();
    bool is_out_of_process() const;

    // How many worker processes serve this one runtime, a declaration and
    // never inferred, kept on the placeholder because it is configuration that
    // `inspect`, the state file and was_running all read.
    void     set_shards(uint32_t n);
    uint32_t get_shards() const;

    // Which of those processes this one is, 0 for every runtime that is not
    // sharded and for the daemon's placeholder, set from the config frame and
    // from nowhere else.
    void     set_shard_index(uint32_t i);
    uint32_t get_shard_index() const;

    // What every shard of this runtime is publishing about itself, mapped only
    // in a worker whose daemon handed it a region and unmapped everywhere
    // else.
    shard_stats::shard_table& shard_stats_table() { return m_shard_stats; }

    // And which connections each shard is holding, by name, unmapped for every
    // unsharded runtime and every runtime in the daemon.
    shard_clients::client_table& shard_clients_table() { return m_shard_clients; }

    // A message for a connection this process does not own, set only in a
    // worker, answering nothing because the in-process path answers "queued"
    // rather than "delivered".
    using ref_sink = std::function<void(const conn_ref&, std::string_view)>;
    void set_ref_sink(ref_sink s) { m_ref_sink = std::move(s); }
    bool has_ref_sink() const { return static_cast<bool>(m_ref_sink); }
    void send_to_ref(const conn_ref& r, std::string_view msg)
    { if (m_ref_sink) m_ref_sink(r, msg); }

    // Fan-out to this runtime's clients in other processes, which blocks on
    // nothing and is guarded on the shard count so a one-shard worker writes
    // no frame at all.
    using sibling_sink = std::function<void(std::string_view message)>;
    void set_sibling_sink(sibling_sink s) { m_sibling_sink = std::move(s); }

    // What a broadcast did, which used to be nothing anyone could ask.  A
    // client whose queue is full is dropped by the broadcast the same way it
    // was dropped by a send, and that was equally silent.
    //
    // These count THIS shard's connections, deliberately: a sharded runtime
    // runs this script once per shard, and the connections a script can
    // actually throttle are its own.  That is the opposite case from
    // shard_connection_count(), where the question is "how many clients does
    // my runtime have" and only the global answer is true.
    struct fanout_count
    {
        uint32_t taken{0};        // queued for a connection of this shard
        uint32_t backlogged{0};   // dropped because its queue was already full
    };

    // Every client of this runtime and not of this process, local first so a
    // script that broadcasts and then reads its own state sees a consistent
    // one.
    fanout_count broadcast_all(std::string_view msg)
    {
        const fanout_count c = broadcast(msg);
        fanout_to_siblings(msg);
        return c;
    }

    // The message on its way to this runtime's other shards, separate from
    // broadcast_all() because `socketley.send` to this runtime's own name
    // needs the second half without the first.
    void fanout_to_siblings(std::string_view msg)
    {
        if (m_shards > 1 && m_sibling_sink)
            m_sibling_sink(msg);
    }

    // How many connections this runtime has counting its sibling shards,
    // publishing our own count first so a script told a client connected sees
    // that client in the answer.
    uint64_t shard_connection_count()
    {
        const uint64_t mine = static_cast<uint64_t>(get_connection_count());
        if (!m_shard_stats.mapped())
            return mine;
        m_shard_stats.publish_active(mine);
        return m_shard_stats.sum_active();
    }

    // ── Ring policy ─────────────────────────────────────────────────────────
    // What this runtime's I/O was asked to run on, a request and not a result,
    // with asked-for and not-asked-for separate states so a plain `create` is
    // not read as an explicit unrestricted set.
    void set_cpus(const cpu_set_spec& cpus);
    const cpu_set_spec& get_cpus() const;
    bool has_cpus_request() const;

    // Why this runtime's request cannot be honoured on `loop`'s ring, naming
    // the daemon setting that would satisfy it, asked by both `create` and
    // start() because the request outlives the daemon that accepted it.
    std::string ring_policy_refusal(const event_loop& loop) const;

    enum class child_policy { stop, remove };
    void set_child_policy(child_policy p);
    child_policy get_child_policy() const;

    // Runtime manager / event loop (base class — used by Lua management API)
    void set_runtime_manager(runtime_manager* mgr);
    void set_event_loop(event_loop* loop);
    runtime_manager* get_runtime_manager() const;
    event_loop* get_event_loop() const;

    // A new name/group to endpoint snapshot pushed by the manager on every
    // membership change, ignored by default because only the proxy forwards to
    // other runtimes.
    // One call per turn of the loop this runtime is on, for the work that has
    // no completion to hang off: a submission the ring refused leaves a
    // listener unarmed, and nothing else would come back to try again.
    virtual void on_loop_turn() {}

    virtual void set_endpoints(std::shared_ptr<const endpoint_table>) {}

    // A registered type's own fields as an ordered string bag, no-ops for the
    // built-ins, whose fields are named columns in runtime_config.
    virtual void capture_config(std::vector<std::pair<std::string, std::string>>&) const {}
    virtual void apply_config(const std::vector<std::pair<std::string, std::string>>&) {}

    // What answers requests addressed to this runtime's name, which only a
    // cache does, overridden for an out-of-process runtime to the supervisor
    // holding the control socket, since the placeholder's store is empty.
    virtual request_sink* as_request_sink()
    { return m_sink_override; }
    // The daemon's override when there is one, else the runtime itself.
    request_sink* sink_or(request_sink* self) { return m_sink_override ? m_sink_override : self; }

    // What a runtime in a worker says it will answer, sent up and kept here
    // because the declaration is produced by running the script and the
    // placeholder has no interpreter.
    void set_worker_routes(std::shared_ptr<const route_table> rt);
    const std::shared_ptr<const route_table>& worker_routes() const;

    // Is there something listening on this runtime's port yet, answered by the
    // supervisor for an out-of-process runtime -- false from the fork, true
    // when the child reports serving -- and applied to group membership only,
    // never to the by-name entry.
    bool endpoint_live() const { return m_endpoint_live; }
    void set_endpoint_live(bool live) { m_endpoint_live = live; }

    void set_request_sink_override(request_sink* s) { m_sink_override = s; }

    // The mesh client-certificate paths, a virtual because the TLS gate runs
    // in shared code that must not know what a proxy is.
    virtual void get_mesh_tls_paths(std::string_view& ca, std::string_view& cert,
                                    std::string_view& key) const
    {
        ca = {}; cert = {}; key = {};
    }

    // The replication target, asked by the same gate and for the same reason,
    // empty for every role but the cache.
    virtual std::string_view get_replication_target() const { return {}; }

    // Lua integration
    bool load_lua_script(std::string_view path);
    lua_context* lua() const { return m_lua.get(); }

    // A C++ event callback, invoked instead of the Lua one for that event,
    // with set_tick_interval() controlling the tick period when Lua is not in
    // use.
    void set_on_start          (std::function<void()>                         cb);
    void set_on_stop           (std::function<void()>                         cb);
    void set_on_connect        (std::function<void(int fd)>                   cb);
    void set_on_disconnect     (std::function<void(int fd)>                   cb);
    void set_on_client_message (std::function<void(int fd, std::string_view)> cb);
    void set_on_message        (std::function<void(std::string_view)>         cb);
    void set_on_tick           (std::function<void(double dt_ms)>             cb);
    void set_on_auth           (std::function<bool(int fd)>                  cb);
    void set_tick_interval     (uint32_t ms);   // tick period in ms; 0 = use Lua value (default)

    // Cross-runtime pub/sub dispatch (called by runtime_manager on publish)
    virtual void on_publish_dispatch(std::string_view cache_name, std::string_view channel, std::string_view message);

    // Whether the message was written or queued, false for a runtime with no
    // outward connection of its own.
    virtual bool lua_send(std::string_view /*msg*/) { return false; }
    // Answers what it did; see fanout_count.  A runtime with no connection
    // table of its own did nothing, which is what {} says.
    virtual fanout_count broadcast(std::string_view /*msg*/) { return {}; }
    // Whether the bytes reached a connection, which the base holds none of, so
    // the honest answer here is no.
    virtual bool send_to(int /*client_id*/, std::string_view /*msg*/) { return false; }

    // Virtual methods for Lua cache access (overridden by cache_instance)
    // Which of the three modes this cache is in.  Every mutating call below
    // refuses in `readonly` by answering exactly what it answers when there was
    // nothing to do -- false for nine of them, "" for the two pops -- so a
    // script could not tell the two apart, while a client on the wire got
    // "denied: readonly mode".  Empty for a runtime that is not a cache.
    // A script's callback is about to wait for an answer from another runtime:
    // a runtime that answers a peer through a connection keeps it open until the
    // answer has been used, and says with `ctx` what to let go of afterwards
    // (see lua_suspender::set_await_ended).  Zero, the default, holds nothing.
    virtual void hold_answering_connection(uint64_t& ctx) { ctx = 0; }

    virtual std::string_view lua_cache_mode() const { return {}; }

    // The second question of exactly that kind, for the second reason a call
    // below answers nothing: under --shards this script runs in all N
    // processes and each one acts only on the keys it owns, so "false" from
    // self.set means "a sibling did it" as often as it means "refused".
    // True for every key on a runtime that is one process, which is what makes
    // a script written against it read the same on either.
    virtual bool lua_cache_owns(std::string_view /*key*/) { return true; }

    virtual std::string lua_cache_get(std::string_view /*key*/) { return ""; }

    // The question lua_cache_get() cannot answer.  It returns "" both for a key
    // that is not there and for one holding an empty string, so a script had no
    // way to tell them apart -- and the project's own example leans on the
    // ambiguity: examples/cache/cache-integration-handler.lua:27 reads
    // `if self.get("config:timeout") == ""` to mean "not set yet".
    //
    // Answered by adding the missing question rather than by changing what
    // get() returns.  Making it nil would be correct and would break that
    // example and every script written the same way, and an empty string is a
    // value a cache is entitled to hold -- EXISTS is what Redis offers for
    // exactly this and the wire protocol here has had it all along.
    virtual bool lua_cache_exists(std::string_view /*key*/) { return false; }
    virtual bool lua_cache_set(std::string_view /*key*/, std::string_view /*value*/) { return false; }
    virtual bool lua_cache_del(std::string_view /*key*/) { return false; }

    // Lists
    virtual bool lua_cache_lpush(std::string_view /*key*/, std::string_view /*val*/) { return false; }
    virtual bool lua_cache_rpush(std::string_view /*key*/, std::string_view /*val*/) { return false; }
    virtual std::string lua_cache_lpop(std::string_view /*key*/) { return ""; }
    virtual std::string lua_cache_rpop(std::string_view /*key*/) { return ""; }
    virtual int lua_cache_llen(std::string_view /*key*/) { return 0; }

    // Sets
    virtual int lua_cache_sadd(std::string_view /*key*/, std::string_view /*member*/) { return -1; }
    virtual bool lua_cache_srem(std::string_view /*key*/, std::string_view /*member*/) { return false; }
    virtual bool lua_cache_sismember(std::string_view /*key*/, std::string_view /*member*/) { return false; }
    virtual int lua_cache_scard(std::string_view /*key*/) { return 0; }

    // Hashes
    virtual bool lua_cache_hset(std::string_view /*key*/, std::string_view /*field*/, std::string_view /*val*/) { return false; }
    virtual std::string lua_cache_hget(std::string_view /*key*/, std::string_view /*field*/) { return ""; }
    // The same question about a hash field, for the same reason.
    virtual bool lua_cache_hexists(std::string_view /*key*/, std::string_view /*field*/) { return false; }
    virtual bool lua_cache_hdel(std::string_view /*key*/, std::string_view /*field*/) { return false; }
    virtual int lua_cache_hlen(std::string_view /*key*/) { return 0; }

    // TTL
    virtual bool lua_cache_expire(std::string_view /*key*/, int /*seconds*/) { return false; }
    virtual int64_t lua_cache_ttl(std::string_view /*key*/) { return -2; }
    virtual bool lua_cache_persist(std::string_view /*key*/) { return false; }

    // Pub/Sub
    virtual int lua_cache_publish(std::string_view /*channel*/, std::string_view /*message*/) { return 0; }

protected:
    // on_start answers whether it ran without raising, because it is the one
    // callback here that runs inside a command rather than on traffic.
    bool invoke_on_start();
    void invoke_on_stop();
    void invoke_on_message(std::string_view msg);
    void invoke_on_connect(int client_id);
    void invoke_on_disconnect(int client_id);
    bool invoke_on_auth(int client_id);
    void invoke_on_send(std::string_view msg);
    void invoke_on_client_message(int client_id, std::string_view msg);
    // The write queue for this connection has drained back under the
    // backpressure watermark.  Dispatched a loop turn after the completion
    // that emptied it, not on that completion's stack -- see the server's
    // on_loop_turn().
    void invoke_on_writable(int client_id);
    // Asked before a crossing is recorded at all, so a server whose script has
    // no on_writable queues nothing and walks no list.
    bool wants_on_writable() const;

    // One chunk of a request body, with how much is still owed after it.  The
    // script is handed the bytes and the runtime keeps none of them.
    void invoke_on_http_body(int client_id, std::string_view chunk, size_t remaining);
    // The same callback with `remaining` as nil, for a chunked body where how
    // much is still owed is not knowable.  A separate entry rather than a
    // sentinel number, because any number a script compared against would be a
    // wrong answer about the end of the body.
    void invoke_on_http_body_unknown(int client_id, std::string_view chunk);
    // Asked before the headers are done, because it decides whether the body
    // is streamed at all -- and therefore whether it may exceed the bound.
    bool wants_on_http_body() const;

    // The upstream side of on_writable.  Its own callback because an upstream
    // id and a client id are different spaces.
    void invoke_on_upstream_writable(int conn_id);
    bool wants_on_upstream_writable() const;

public:
#ifndef SOCKETLEY_NO_LUA
    // ─── A call a script makes that cannot answer yet ───────────────────────
    // Post `cmd` to whatever this runtime is linked to and leave the handler on
    // `th` waiting for the reply.  nullptr means it was posted and the binding
    // must yield; anything else is the reason it was not, answered to the
    // script inline as `nil, reason` so an await always returns.
    //
    // A literal and not a std::string: the caller is a lua_CFunction, where a
    // raise unwinds with longjmp and runs no destructor.
    virtual const char* begin_cache_await(lua_State* /*th*/, std::string_view /*cmd*/)
    { return "this runtime has no cache linked"; }
#endif
protected:

    // Global rate limit check (token bucket, shared across all connections)
    bool check_global_rate_limit();

    // Bash output helper
    void print_bash_message(std::string_view msg) const;

    // The same message to the file -w named, which is the file half of what
    // print_bash_message does to stdout -- and which had never been written:
    // the path was parsed by four flag doors, carried to the worker,
    // persisted, and reported by `show`, and nothing anywhere opened it.
    void write_received_message(std::string_view msg);

private:
    // -w and --log, which want the same three things: no file for a runtime
    // that never writes, an append rather than a truncate on restart, and one
    // complaint for a bad path rather than one per line.  See appending_file.h
    // for why that is one class and not two copies.
    socketley::appending_file m_write_out;
    socketley::appending_file m_state_log;

    // Every transition goes through here, because --log has to see all of them
    // and twelve stores in start()/stop() plus mark_failed() is twelve places
    // to forget one.  set_replicated_state() deliberately does not: a replica
    // is a copy of somebody else's runtime and would log a transition it did
    // not make.
    void store_state(runtime_state s);

    // One line into the --log file for the state given, also called by
    // set_log_file() so the file opens with where the runtime stood.
    void append_state_line(runtime_state s);

    // Guards m_stat_detail only and is held for a single move, its own lock so
    // publishing never takes the runtime map exclusively on the event-loop
    // thread.
    mutable std::mutex m_stat_detail_mutex;
    std::string m_stat_detail;
    std::atomic<bool> m_worker_backed{false};

    std::string m_name;
    std::string m_id;
    runtime_type m_type;
    std::atomic<runtime_state> m_state;
    bool m_armed_io = false;
    // See last_on_start_error().  Empty unless the most recent on_start raised.
    std::string m_on_start_error;
    uint16_t m_port = 0;
    std::string m_listen_path;
    std::string m_bind_address;
    std::string m_companion_path;
    std::vector<std::string> m_companion_paths;
    bool m_test_mode = false;
    std::string m_log_file;
    std::string m_write_file;
    std::string m_target;
    std::string m_cache_name;
    std::unique_ptr<lua_context> m_lua;

    std::chrono::system_clock::time_point m_created_time;
    std::chrono::system_clock::time_point m_start_time;

    // Not persisted: a daemon that restarts did not witness these, and a count
    // restored from a file would claim it had.
    // Counted by the daemon's loop and read by the metrics thread.
    std::atomic<unsigned> m_restarts{0};
    bool     m_unresponsive{false};

    // Bash output settings
    bool m_bash_output = false;
    bool m_bash_prefix = false;
    bool m_bash_timestamp = false;

    // Resource limits
    uint32_t m_max_connections = 0;
    double m_rate_limit = 0.0;
    double m_global_rate_limit = 0.0;
    double m_global_tokens = 0.0;
    std::chrono::steady_clock::time_point m_global_last{};
    uint32_t m_idle_timeout = 0;
    // Defaulted to what the constants were, so a runtime nobody configures
    // behaves exactly as before.
    size_t m_write_buffer = socketley::write_queue_max_bytes;
    // Half the bound until the first loop turn refines it, which is what this
    // was before it could vary at all.
    size_t m_write_watermark = socketley::write_queue_max_bytes / 2;
    // Until when the divided pacing point stays in force; see refresh above.
    std::chrono::steady_clock::time_point m_pacing_hold_until{};
    // When the O(connections) sum may next be paid for.  Value-initialised, so
    // the first turn of a runtime's life always samples.
    std::chrono::steady_clock::time_point m_pacing_sample_due{};
    bool m_pacing_backed_up{false};

    // Dividing by the connection count alone was the wrong rule and measured so:
    // at 8 streams it paced a producer four times as often for no benefit, since
    // the queues never filled -- 4,412 responses a second against 5,463, nine
    // interleaved passes -- while at 16 it was worth +33 per cent, because there
    // they do fill and 64 MB in flight is out of a 16 MiB L3.
    //
    // So the divisor is applied only when this runtime is ACTUALLY holding more
    // than fits: under the budget every connection keeps the depth it had, and
    // over it they share the budget.
    size_t pacing_watermark_for(size_t live, bool backed_up) const
    {
        const size_t hi = m_write_buffer / 2;
        if (live <= 1 || !backed_up)
            return hi;
        size_t w = socketley::write_pacing_budget / live;
        if (w > hi) w = hi;
        if (w < socketley::write_pacing_floor) w = socketley::write_pacing_floor;
        return w;
    }
    // Defaulted to what MAX_PARTIAL_SIZE was, so an unconfigured runtime
    // accepts exactly what it accepted before -- and its bulk cap lands on
    // 512 KB, which is exactly what RESP_MAX_BULK_LEN was.
    size_t m_read_buffer = 1u * 1024 * 1024;

    // Graceful shutdown
    bool m_drain = false;

    // Reconnect
    int m_reconnect = -1; // -1 = disabled, 0 = infinite, >0 = max attempts

    // TLS
    bool m_tls = false;
    std::string m_cert_path;
    std::string m_key_path;
    std::string m_ca_path;
    std::vector<std::string> m_acme_domains;
    std::string m_acme_email;
    std::string m_domains;

    // Lua script path for hot-reload
    std::string m_lua_script_path;

    // C++ event callbacks
    std::function<void()>                        m_cb_on_start;
    std::function<void()>                        m_cb_on_stop;
    std::function<void(int)>                     m_cb_on_connect;
    std::function<void(int)>                     m_cb_on_disconnect;
    std::function<void(int, std::string_view)>   m_cb_on_client_message;
    std::function<void(std::string_view)>        m_cb_on_message;
    std::function<void(double)>                  m_cb_on_tick;
    std::function<bool(int)>                     m_cb_on_auth;
    uint32_t                                     m_cb_tick_ms = 0;

    // Interactive mode observer fds (IPC sockets)
    std::vector<int> m_interactive_fds;

    // Group tag
    std::string m_group;

    // Ownership
    std::string m_owner;
    bool m_lua_created = false;
    bool m_cluster_owned = false;
    bool m_external = false;
    bool m_managed = false;
    bool m_out_of_process = false;

    // One and not zero, so every reader can multiply or loop by it without
    // first asking whether it was set.
    uint32_t m_shards = 1;

    // 0 unless a config frame said otherwise; see set_shard_index().
    uint32_t m_shard_index = 0;

    // Empty unless this process is one shard of several; see shard_stats.h.
    shard_stats::shard_table m_shard_stats;

    // Set only in a worker, and only used above one shard; see set_sibling_sink.
    sibling_sink m_sibling_sink;

    // Which connections each shard of this runtime holds; see shard_clients.h.
    shard_clients::client_table m_shard_clients;

    // See set_ref_sink.  Empty everywhere but in a worker.
    ref_sink m_ref_sink;

    std::shared_ptr<const route_table> m_worker_routes;

    // See endpoint_live(), true by default because a runtime that binds in
    // this process is listening by the time anything can ask.
    bool m_endpoint_live{true};
    std::string m_exec_path;
    pid_t m_pid = 0;           // PID of external process (used by stop() to send SIGTERM)
    std::array<std::atomic<pid_t>, max_shards> m_shard_pids{};
    child_policy m_child_policy = child_policy::stop;

    // Ring policy as requested, meaningful only when the matching _set flag is
    // true.
    cpu_set_spec m_cpus{};
    bool m_cpus_set = false;

    // Runtime manager / event loop (base class)
    runtime_manager* m_runtime_manager = nullptr;
    request_sink*    m_sink_override = nullptr;
    event_loop* m_event_loop = nullptr;

    // Tick timer
    struct tick_handler : io_handler {
        runtime_instance* rt{nullptr};
        // Kept so the handler can take itself out of the loop's owner table in
        // its own last completion, which deregistering earlier would have
        // dropped.
        event_loop* loop{nullptr};
        io_request req{};
        struct __kernel_timespec ts{};
        std::chrono::steady_clock::time_point last{};
        void on_cqe(struct io_uring_cqe* cqe) override;
    };
    tick_handler* m_tick{nullptr};
    void start_tick_timer();
    void fire_tick(int res);
};
