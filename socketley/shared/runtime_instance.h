#pragma once
#include <string>
#include <string_view>
#include <atomic>
#include <cstdint>
#include <memory>
#include "route_table.h"
#include <chrono>
#include <sstream>
#include <vector>
#include <algorithm>
#include <functional>
#include <mutex>
#include <sys/types.h>

#ifndef SOCKETLEY_NO_LUA
#include <sol/sol.hpp>
#endif
#include "liburing_version.h"   // must precede <liburing.h>; see that file
#include <liburing.h>
#include "runtime_definitions.h"
#include "event_loop_definitions.h"

class event_loop;
class lua_context;
class runtime_manager;
class endpoint_table;
class request_sink;

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

    // True once start() has entered setup(), i.e. once this instance may have
    // handed the kernel the address of an io_request that lives inside it — its
    // own accept/timer requests, or the ones embedded in every connection
    // struct it owns.  Never cleared: stop() closes the fds and nulls the owner
    // pointers, but a completion for this object can still be sitting in the
    // ring afterwards, and the kernel keeps the address either way.
    // runtime_manager reads this to decide whether an instance that has just
    // left the map has to be retired or can be destroyed on the spot.
    bool has_armed_io() const;

    std::string_view get_name() const;
    void set_name(std::string_view name);
    std::string_view get_id() const;
    void set_id(std::string_view id);

    std::chrono::system_clock::time_point get_created_time() const;
    std::chrono::system_clock::time_point get_start_time() const;

    void set_port(uint16_t port);
    uint16_t get_port() const;

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

    // Connection count (virtual, implemented per runtime type)
    virtual size_t get_connection_count() const { return 0; }

    // Max connections
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

    // Stats
    //
    // get_stats() and get_connection_count() both read this instance's live
    // connection tables — a server walks m_upstreams and m_active_fds, a cache
    // walks m_clients — and the event-loop thread mutates those with no
    // synchronisation whatsoever.  Both are therefore EVENT-LOOP THREAD ONLY.
    // The four counters below are atomics and may be read from anywhere.
    virtual std::string get_stats() const;
    std::atomic<uint64_t> m_stat_total_connections{0};
    std::atomic<uint64_t> m_stat_total_messages{0};
    std::atomic<uint64_t> m_stat_bytes_in{0};
    std::atomic<uint64_t> m_stat_bytes_out{0};

    // ── Off-thread view ─────────────────────────────────────────────────────
    // What a reader that is not on the event-loop thread gets instead.
    //
    // The metrics endpoint runs on its own std::thread and used to call
    // get_connection_count() — and get_stats() — from there, holding only
    // runtime_manager::mutex.  That mutex guards the runtime *map*; it says
    // nothing about what is inside a runtime.  Reading an unordered_map while
    // another thread rehashes it is undefined, not merely stale: the walk
    // follows bucket pointers that are being rewritten underneath it.
    //
    // So the figures are published instead.  The event-loop thread writes them
    // through publish_offthread_stats(); everyone else reads them here.  They
    // are as old as the last publish and no older, which is the price of not
    // reading a container that is being rewritten.
    std::atomic<uint64_t> m_stat_active_connections{0};

    // Refresh both.  EVENT-LOOP THREAD ONLY — it makes exactly the
    // unsynchronised reads this exists to keep off other threads.
    //
    // The get_stats() string is built before the lock is taken, so the only
    // thing the lock covers is a move: a reader can never be made to wait on
    // string construction, and the event-loop thread can never be made to wait
    // on more than one string copy.
    void publish_offthread_stats()
    {
        m_stat_active_connections.store(static_cast<uint64_t>(get_connection_count()),
                                        std::memory_order_relaxed);
        std::string detail = get_stats();
        std::lock_guard<std::mutex> lock(m_stat_detail_mutex);
        m_stat_detail = std::move(detail);
    }

    // The last published get_stats() text.  Empty until the first publish, which
    // is the same thing an instance with nothing to say returns, and callers
    // already treat an empty result as "no detail".
    std::string stat_detail_snapshot() const
    {
        std::lock_guard<std::mutex> lock(m_stat_detail_mutex);
        return m_stat_detail;
    }

    // ── Figures pushed from a worker process ────────────────────────────────
    // When a runtime runs in its own process the daemon keeps a placeholder
    // instance for it — the thing that holds its name, port and state — and the
    // placeholder has no connections of its own to count.  Its figures arrive
    // over the control socket instead and land here.
    //
    // They land in exactly the fields an off-thread reader already uses, and
    // that is the point: the metrics endpoint reads m_stat_active_connections
    // and stat_detail_snapshot() and needs no idea that the runtime is not in
    // this address space.  A worker is the off-thread reader's case with the
    // boundary made physical, so it reuses the answer rather than inventing a
    // second one.
    // `taken_ns` is the worker's steady-clock reading at the instant it read the
    // counters, which travels with them; 0 from a sender that does not stamp.
    void set_worker_stats(std::string detail, uint64_t active, int64_t taken_ns)
    {
        m_stat_active_connections.store(active, std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> lock(m_stat_detail_mutex);
            m_stat_detail = std::move(detail);
        }

        // The worker's moment, not this one.  This line used to read steady_ns()
        // — the instant the frame came off the socket — which is the same thing
        // only when the daemon drains the moment the child writes.  It does not:
        // it drains when a command asks or when the two-second health tick comes
        // round, so a frame can sit unread for a second and more, and stamping
        // it here declared it new.  Unstamped is the pre-upgrade worker, whose
        // figures are still worth having; the read moment is then the closest
        // honest answer available and it is a lower bound on the true age.
        m_worker_stats_ns.store(taken_ns > 0 ? taken_ns : steady_ns(),
                                std::memory_order_relaxed);

        // Published after the detail it promises, with a release so a reader
        // that sees the flag also sees the text.  Setting it first would let
        // the first `stats` after a worker starts print nothing at all.
        m_worker_backed.store(true, std::memory_order_release);
    }

    // How old these figures are, in milliseconds, or -1 when none has arrived.
    //
    // ─── WHY THIS IS REPORTED RATHER THAN REMOVED ───────────────────────────
    //
    // A worker's figures are pushed, not read.  Making them live would mean the
    // daemon asking the child a question and waiting for the answer, on the
    // event-loop thread, with a process it does not control on the other end —
    // which is the synchronous cross-runtime call this design already answered
    // no to everywhere else.  The child publishes every 250ms and the daemon
    // drains the socket before any command that prints them, so the number is
    // recent; what it is not is instantaneous, and the difference is invisible
    // in every figure the CLI prints.  So it is stated.
    //
    // Not folded into the pushed detail text: that text is built by the worker
    // and would then be reporting its own age at the moment it was written,
    // which is always zero.  Age is the interval between two moments — the
    // worker's read of its own counters and this read of them — and the first
    // of the two therefore has to cross the socket as a value, because the
    // daemon has no way to reconstruct it.  See stats_wire::taken_ns.
    //
    // What a large number means is a worker that has not published: stopped,
    // wedged, or gone with the daemon not yet having noticed.  That is the
    // reading this field exists to make possible, so nothing here bounds it.
    long long worker_stats_age_ms() const
    {
        const int64_t at = m_worker_stats_ns.load(std::memory_order_relaxed);
        if (at == 0)
            return -1;
        // Clamped, because the two moments are read on two processes' clocks:
        // CLOCK_MONOTONIC is the same clock on both, but the frame is written
        // before it is read only in the order the two syscalls happen, and a
        // negative age is a number no operator can use.
        const int64_t d = steady_ns() - at;
        return d <= 0 ? 0 : static_cast<long long>(d / 1'000'000);
    }

    // True once a worker has reported at least once.  Read by the placeholder's
    // get_stats()/get_connection_count() to answer from the pushed figures
    // rather than from its own empty containers.
    //
    // An atomic rather than something under m_stat_detail_mutex: this is read
    // by get_connection_count(), which an in-process proxy calls on its own
    // accept path, and putting a lock acquisition there would make every
    // connection pay for a branch that is false in every in-process daemon.
    bool worker_backed() const
    {
        return m_worker_backed.load(std::memory_order_acquire);
    }

    // Straight to `failed`, for a supervisor that has decided a child is not
    // coming back.  Not a transition any runtime makes to itself.
    void mark_failed() { m_state.store(runtime_failed, std::memory_order_release); }

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
    void set_owner(std::string_view owner_name);
    std::string_view get_owner() const;
    void set_lua_created(bool v);
    bool is_lua_created() const;

    // External (attach) mode — runtime is managed by another process
    void mark_external();
    bool is_external() const;
    void set_pid(pid_t pid);
    pid_t get_pid() const;

    // Managed external — daemon owns fork+exec lifecycle
    void mark_managed(std::string exec_path);
    bool is_managed() const;
    std::string_view get_exec_path() const;

    // Out-of-process — this instance is a placeholder for a runtime living in a
    // worker process the daemon supervises.  Distinct from external/managed on
    // purpose: those describe a foreign program the daemon merely starts and
    // signals, whereas this one is the same binary on the other end of a
    // control socket, and it is persisted, inspected and cascaded exactly like
    // an in-process runtime.  Overloading `external` for it would have made
    // `inspect` and the state file start describing it as something it is not.
    //
    // What it changes here is only that start()/stop() must not touch the ring:
    // the port is bound in the worker, and the placeholder owns no I/O at all.
    void mark_out_of_process();
    bool is_out_of_process() const;

    // ── Ring policy ─────────────────────────────────────────────────────────
    // What this runtime's I/O was asked to run as: which CPUs, and whether its
    // ring carries a submission poller.
    //
    // A request, not a result.  A ring's flags are fixed when the ring is
    // created, and a runtime does not create one — the process it lives in
    // does, before any runtime configuration has been read.  So these say what
    // was asked for; the loop says what was granted, and `stats` prints the
    // loop's answer.  cmd_create refuses a request the runtime's loop cannot
    // meet rather than storing one that will never come true.
    //
    // Both survive the split unchanged: when a runtime owns its own process the
    // same two values become that process's ring parameters, and the check
    // moves from "does the daemon's ring match" to "build the worker's ring
    // like this".
    //
    // Asked-for and not-asked-for are separate states, and the separation is
    // load-bearing rather than tidy.  Without it "no flag given" is stored as
    // the default value of the flag, so a plain `create` on a daemon whose ring
    // does carry a poller reads as an explicit --no-sqpoll and is refused —
    // a user who never typed a ring flag being lectured about one.  A request
    // that was never made is not a request to keep the default; it is no
    // request, and nothing is checked against it.
    void set_cpus(const cpu_set_spec& cpus);
    const cpu_set_spec& get_cpus() const;
    bool has_cpus_request() const;
    void set_sqpoll(bool on);
    bool get_sqpoll() const;
    bool has_sqpoll_request() const;

    // Why this runtime's request cannot be honoured on `loop`'s ring, or an
    // empty string when it can.  Newline-terminated, and it names the daemon
    // setting that would satisfy the request rather than only saying no.
    //
    // Asked in two places, which is the point of it being one function.
    // `create` asks so a refusal reaches the client that typed the flag; start()
    // asks because the request outlives the daemon that accepted it — the state
    // file carries it, and a ring is created before any of it is read, so the
    // ring a restored runtime meets is not necessarily the ring its request was
    // checked against.  Two copies of this text would drift, and the half that
    // drifted would be the one nobody reads until a restart.
    std::string ring_policy_refusal(const event_loop& loop) const;

    enum class child_policy { stop, remove };
    void set_child_policy(child_policy p);
    child_policy get_child_policy() const;

    // Runtime manager / event loop (base class — used by Lua management API)
    void set_runtime_manager(runtime_manager* mgr);
    void set_event_loop(event_loop* loop);
    runtime_manager* get_runtime_manager() const;
    event_loop* get_event_loop() const;

    // A new name/group → endpoint snapshot, pushed by the manager whenever
    // membership changes.  Ignored by default: only the proxy forwards to other
    // runtimes, and this is the whole of what it needs to know about them — a
    // host and a port, which is what would arrive over a socket if this runtime
    // lived in its own process.  See shared/endpoint_table.h.
    virtual void set_endpoints(std::shared_ptr<const endpoint_table>) {}

    // Whether this runtime can answer requests other runtimes address to its
    // name, and through what.  Null by default: only a cache can, and it is the
    // manager — not the asking runtime — that puts the answer in the request
    // channel's table, on the same membership changes that republish the
    // endpoints.  See shared/request_channel.h.
    // What answers requests addressed to this runtime's name.  A cache returns
    // itself; everything else has nothing to answer with.
    //
    // The override is for a runtime that is not in this process.  Its
    // placeholder here has the name and the port but an empty store, so
    // answering from it would be confidently wrong — the same failure
    // get_stats() had until 338341f.  The daemon sets this to the supervisor
    // that holds the control socket to the worker, and the channel then reaches
    // the real runtime without anything on the asking side changing.
    virtual request_sink* as_request_sink()
    { return m_sink_override; }

    // What a runtime in a worker says it will answer.
    //
    // The declaration is produced by running the script, and a worker's script
    // runs in the worker — the placeholder only checks that the file parses, so
    // it has no interpreter and lua() is null.  publish_endpoints() reads the
    // declaration from lua(), found nothing, and published none: a gateway in
    // front of such a runtime forwarded every method instead of refusing the
    // undeclared ones with a 405.  The worker sends its table up and it is kept
    // here, where publish_endpoints() looks first.
    void set_worker_routes(std::shared_ptr<const route_table> rt);
    const std::shared_ptr<const route_table>& worker_routes() const;

    void set_request_sink_override(request_sink* s) { m_sink_override = s; }

    // The mesh client-certificate paths, for the one role that has them.
    //
    // The TLS gate in start() has to see the *whole* configuration — half a
    // client-certificate pair is refused, and a client CA without --tls is
    // refused — and it runs here, in shared code that must not know what a
    // proxy is.  A virtual keeps the knowledge on the side that has it; the
    // views point into the instance and are valid for as long as it is.
    virtual void get_mesh_tls_paths(std::string_view& ca, std::string_view& cert,
                                    std::string_view& key) const
    {
        ca = {}; cert = {}; key = {};
    }

    // The replication target, for the one role that has one.
    //
    // Same reasoning as get_mesh_tls_paths above, and the same gate asks it: a
    // cache that terminates TLS on its listener and replicates out of it in
    // cleartext is refused, and the check belongs in tls_config_refusal with
    // every other "may this configuration take effect?" question rather than
    // in a place the restore path can walk around.  Empty for every role that
    // does not replicate, which is all of them but the cache.
    virtual std::string_view get_replication_target() const { return {}; }

    // Lua integration
    bool load_lua_script(std::string_view path);
    lua_context* lua() const { return m_lua.get(); }

    // ── C++ event callbacks (alternative to Lua) ─────────────────────────────
    // If set, the C++ callback is invoked *instead of* the Lua callback for that event.
    // Use set_tick_interval() to control the tick period when not using Lua.
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

    // Virtual methods for Lua actions (overridden by specific runtimes)
    virtual void lua_send(std::string_view /*msg*/) {}
    virtual void lua_broadcast(std::string_view /*msg*/) {}
    virtual void lua_send_to(int /*client_id*/, std::string_view /*msg*/) {}

    // Virtual methods for Lua cache access (overridden by cache_instance)
    virtual std::string lua_cache_get(std::string_view /*key*/) { return ""; }
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
    virtual bool lua_cache_hdel(std::string_view /*key*/, std::string_view /*field*/) { return false; }
    virtual int lua_cache_hlen(std::string_view /*key*/) { return 0; }

    // TTL
    virtual bool lua_cache_expire(std::string_view /*key*/, int /*seconds*/) { return false; }
    virtual int64_t lua_cache_ttl(std::string_view /*key*/) { return -2; }
    virtual bool lua_cache_persist(std::string_view /*key*/) { return false; }

    // Pub/Sub
    virtual int lua_cache_publish(std::string_view /*channel*/, std::string_view /*message*/) { return 0; }

protected:
    // Invoke Lua callbacks safely
    void invoke_on_start();
    void invoke_on_stop();
    void invoke_on_message(std::string_view msg);
    void invoke_on_connect(int client_id);
    void invoke_on_disconnect(int client_id);
    bool invoke_on_auth(int client_id);
    void invoke_on_send(std::string_view msg);
    void invoke_on_client_message(int client_id, std::string_view msg);

    // Global rate limit check (token bucket, shared across all connections)
    bool check_global_rate_limit();

    // Bash output helper
    void print_bash_message(std::string_view msg) const;

private:
    // Guards m_stat_detail only, and is held for a single move or copy.  Its own
    // lock rather than the manager's, so publishing never has to take the
    // runtime map exclusively on the event-loop thread.
    mutable std::mutex m_stat_detail_mutex;
    std::string m_stat_detail;
    std::atomic<bool> m_worker_backed{false};

    // When the worker read the figures it last pushed, on the monotonic clock,
    // or 0 for never.  Its clock, not this process's: see set_worker_stats().
    // Monotonic and not wall-clock: this is an interval, and a wall clock that
    // steps — ntp, a suspend — would report a figure as hours old or as arriving
    // from the future.  Outside m_stat_detail_mutex on purpose, so that reading
    // the age never has to wait behind a detail-string copy.
    std::atomic<int64_t> m_worker_stats_ns{0};

    static int64_t steady_ns()
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }

    std::string m_name;
    std::string m_id;
    runtime_type m_type;
    std::atomic<runtime_state> m_state;
    bool m_armed_io = false;
    uint16_t m_port = 0;
    bool m_test_mode = false;
    std::string m_log_file;
    std::string m_write_file;
    std::string m_target;
    std::string m_cache_name;
    std::unique_ptr<lua_context> m_lua;

    std::chrono::system_clock::time_point m_created_time;
    std::chrono::system_clock::time_point m_start_time;

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

    // Graceful shutdown
    bool m_drain = false;

    // Reconnect
    int m_reconnect = -1; // -1 = disabled, 0 = infinite, >0 = max attempts

    // TLS
    bool m_tls = false;
    std::string m_cert_path;
    std::string m_key_path;
    std::string m_ca_path;

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
    bool m_external = false;
    bool m_managed = false;
    bool m_out_of_process = false;
    std::shared_ptr<const route_table> m_worker_routes;
    std::string m_exec_path;
    pid_t m_pid = 0;           // PID of external process (used by stop() to send SIGTERM)
    child_policy m_child_policy = child_policy::stop;

    // Ring policy, as requested.  The values are only meaningful when the
    // matching _set flag is true; until then nothing was asked for.
    cpu_set_spec m_cpus{};
    bool m_cpus_set = false;
    bool m_sqpoll = false;
    bool m_sqpoll_set = false;

    // Runtime manager / event loop (base class)
    runtime_manager* m_runtime_manager = nullptr;
    request_sink*    m_sink_override = nullptr;
    event_loop* m_event_loop = nullptr;

    // Tick timer
    struct tick_handler : io_handler {
        runtime_instance* rt{nullptr};
        // Kept so the handler can take itself out of the loop's owner table in
        // its own last completion.  Deregistering any earlier would have that
        // completion dropped, and the handler would then never free itself.
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
