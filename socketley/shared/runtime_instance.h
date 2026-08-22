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
#include "shard_stats.h"
#include "shard_clients.h"
#include "event_loop_definitions.h"

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

    // True once start() has entered setup(), i.e. once this instance may have
    // handed the kernel the address of an io_request that lives inside it — its
    // own accept/timer requests, or the ones embedded in every connection
    // struct it owns.  Never cleared: stop() closes the fds and nulls the owner
    // pointers, but a completion for this object can still be sitting in the
    // ring afterwards, and the kernel keeps the address either way.
    // runtime_manager reads this to decide whether an instance that has just
    // left the map has to be retired or can be destroyed on the spot.
    bool has_armed_io() const;

    // What the last invoke_on_start() raised, empty when it did not raise.
    //
    // start() does not fail on a raise and must not: the runtime is listening by
    // the time on_start runs, and turning a script's error into `failed` would
    // take a live listener down over a callback the rest of this tree reports
    // and carries on from.  But "the command may not fail" and "the command may
    // not say" are different sentences, and only the first one is true — so the
    // reason is kept here for whoever asked for the start to read.
    //
    // Not lua_diag: that buffer belongs to whoever is about to read it, and a
    // nested socketley.create from inside on_start clears it and writes its own
    // load diagnostics into it.  This is attached to the runtime whose on_start
    // it was, which is the thing the caller has to name in the message.
    //
    // Cleared at the top of every invoke_on_start(), so it always describes the
    // most recent attempt and a runtime that starts cleanly reports nothing.
    const std::string& last_on_start_error() const;

    std::string_view get_name() const;
    void set_name(std::string_view name);
    std::string_view get_id() const;
    void set_id(std::string_view id);

    std::chrono::system_clock::time_point get_created_time() const;
    std::chrono::system_clock::time_point get_start_time() const;

    void set_port(uint16_t port);
    uint16_t get_port() const;

    // Where this runtime listens, when that is not a port.
    //
    // `--listen unix:/run/app.sock` on a server: the listener is an AF_UNIX
    // socket at this path and the port stays 0.  Empty means the ordinary
    // case, a TCP listener on get_port().  The two are alternatives and never
    // both — whoever accepts the flag refuses the combination, rather than
    // leaving this object to decide which of them wins.
    //
    // Kept here rather than on server_instance because the things that ask a
    // runtime where it listens do not know its type: the endpoint table (a
    // proxy reaching a server by runtime name has to be handed a path instead
    // of a port), `ls`, `show`, and the state file.
    void set_listen_path(std::string_view path);
    std::string_view get_listen_path() const;

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
    //
    // EVENT-LOOP THREAD ONLY, and only meaningful for a runtime whose
    // connections are in this process: it walks this object's tables.  Anything
    // reporting a figure to a user wants reported_connection_count() instead.
    virtual size_t get_connection_count() const { return 0; }

    // What to print.  The same question asked in a way that survives the
    // runtime living in a worker process, where this object is a placeholder
    // whose tables are empty and whose figures arrive in a pushed frame.
    //
    // Every other counter on a `stats` line is an atomic that frame stores
    // into, so they stayed right while this one did not -- `stats` and `ls`
    // reported 0 connections for a server with clients, beside a
    // total_connections that was counting them.  Reading the live tables is
    // correct exactly when there is no worker, which is what this decides once
    // instead of at each call site.
    size_t reported_connection_count() const
    {
        if (!worker_backed())
            return get_connection_count();
        // Summed out of the shared table at this instant.  See worker_figures()
        // for why there is no age to print beside it any more; the load below is
        // the pre-region fallback, for a runtime whose memfd could not be made.
        if (m_shard_stats.mapped())
            return static_cast<size_t>(m_shard_stats.sum_active());
        return static_cast<size_t>(m_stat_active_connections.load(std::memory_order_relaxed));
    }

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

    // The three pieces get_stats() is made of, so that a runtime living in
    // another process can be printed from the two ends that know each part.
    //
    // ─── WHY THIS IS SPLIT AT ALL ───────────────────────────────────────────
    //
    // Every figure in the prefix is a counter the daemon can now read at the
    // instant it prints — they are summed out of shared memory, see
    // worker_figures().  Everything after it is not: the ring's granted flags,
    // a cache's key count, a proxy's healthy backends are facts about the
    // worker's own address space, and the only process that can state them is
    // the worker.
    //
    // So the worker publishes stats_ring() + stats_extra() and the daemon puts
    // stats_prefix() in front of it.  An in-process runtime concatenates the
    // same three in the same order, which is what keeps `stats` byte-identical
    // on both sides — and what makes the seam a place where a stale number
    // cannot hide, because the two halves are produced by different processes
    // at different moments and the split says which is which.
    std::string stats_prefix() const;
    std::string stats_ring() const;
    virtual std::string stats_extra() const { return {}; }

    std::atomic<uint64_t> m_stat_total_connections{0};
    std::atomic<uint64_t> m_stat_total_messages{0};
    std::atomic<uint64_t> m_stat_bytes_in{0};
    std::atomic<uint64_t> m_stat_bytes_out{0};

    // ── The figures to REPORT, whichever process is holding them ────────────
    //
    // For a runtime in this process these are the four atomics above and the
    // live connection count, and this costs what reading them costs.
    //
    // For a runtime in a worker they are a sum over the shared table — one
    // cache line per shard, no lock, no round trip and no wait — and they are
    // read HERE, at the moment somebody asks, rather than taken from a frame
    // the worker pushed on a timer.  That is the whole of why the timer is
    // gone: an answer that is computed when the question is asked has no age to
    // report, so `figures:pushed` and `figures_age_ms` have nothing left to
    // say.
    //
    // Called on any thread.  The metrics endpoint has its own std::thread and
    // is one of the callers this exists for: summing atomics out of a shared
    // mapping is exactly as safe there as reading this object's own.
    shard_stats::figures worker_figures() const
    {
        // Mapped in the daemon for every worker-backed runtime, and in a worker
        // for every sharded one.  The worker_backed() test is what keeps a
        // worker reading its OWN counters here: its `stats` text is one shard's
        // and is labelled as one shard's, and summing the runtime into it would
        // report every shard's total under each shard's heading.
        if (worker_backed() && m_shard_stats.mapped())
            return m_shard_stats.sum();

        // No region: the four counters are this object's own atomics, which for
        // a worker-backed placeholder is where the frame path still writes
        // them.  active_connections is the PUBLISHED count and not
        // get_connection_count() — this runs on the metrics endpoint's thread,
        // which may not walk a runtime's containers.
        shard_stats::figures f;
        f.active_connections = m_stat_active_connections.load(std::memory_order_relaxed);
        f.total_connections  = m_stat_total_connections.load(std::memory_order_relaxed);
        f.total_messages     = m_stat_total_messages.load(std::memory_order_relaxed);
        f.bytes_in           = m_stat_bytes_in.load(std::memory_order_relaxed);
        f.bytes_out          = m_stat_bytes_out.load(std::memory_order_relaxed);
        return f;
    }

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

    // ── What a worker pushes, and what it no longer has to ──────────────────
    //
    // When a runtime runs in its own process the daemon keeps a placeholder
    // instance for it — the thing that holds its name, port and state — and the
    // placeholder has no connections of its own to count.
    //
    // ─── WHAT USED TO ARRIVE HERE, AND WHY IT DOES NOT ──────────────────────
    //
    // Every figure, four times a second, whether or not any of them had moved,
    // together with the moment they were read so that `stats` could print how
    // stale they were.  That timer was the last periodic thing an idle worker
    // did, and it is gone: the counters live in a shared table the worker
    // stores into once per loop turn and the daemon sums when it prints, so
    // there is no interval left between the reading and the printing and
    // nothing to report an age for.  See worker_figures().
    //
    // What still crosses the socket is the part of `stats` that is NOT a
    // summable counter — a cache's key count, a proxy's healthy backends, the
    // ring's granted flags — and it crosses only when it has changed, which for
    // an idle runtime is never.  `active` is still carried with it because a
    // region that could not be created is a case the daemon must survive: see
    // the fallback in worker_figures().
    //
    // The text lands in exactly the field an off-thread reader already uses,
    // and that is the point: the metrics endpoint reads stat_detail_snapshot()
    // and needs no idea that the runtime is not in this address space.
    void set_worker_stats(std::string detail, uint64_t active)
    {
        m_stat_active_connections.store(active, std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> lock(m_stat_detail_mutex);
            m_stat_detail = std::move(detail);
        }

        // Published after the detail it promises, with a release so a reader
        // that sees the flag also sees the text.  Setting it first would let
        // the first `stats` after a worker starts print nothing at all.
        m_worker_backed.store(true, std::memory_order_release);
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

    // The state of a runtime that lives in ANOTHER process, copied from what
    // that process last said it was.
    //
    // For replicas only — the copies a worker keeps of the daemon's map, see
    // runtime_manager::install_replica.  The daemon's own placeholder for an
    // out-of-process runtime must NOT use this and does not: the daemon owns
    // that value, sets it from the command that caused the transition, and
    // proxy_supervisor::ingest() is explicit that a `state` frame is remembered
    // rather than adopted precisely so there is one writer for it.  Here there
    // is still one writer — the daemon — and this is the other end of the wire
    // it writes down, not a second opinion about the same runtime.
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

    // ── "Is the server behind this name one I may call into?" ───────────────
    //
    // Nine places resolve a name through the runtime manager and then reach for
    // server_instance's own methods — routing a connection, releasing one,
    // writing to one the origin still owns.  All nine asked the same two-part
    // question: get_type() == runtime_server, then static_cast.
    //
    // That pairing is safe exactly while every instance of type `server` is a
    // server_instance, and it stopped being.  A worker holds REPLICAS of the
    // daemon's map — records of runtimes in other processes, carrying a type and
    // five other fields and none of the storage — and a replica of a server
    // answers `runtime_server` truthfully.  The cast then produces a pointer to
    // an object that is not one, and write_to_ref() is not virtual: it would run
    // server_instance's code over a much smaller object.
    //
    // So the type test and the cast become one question that cannot be answered
    // wrongly.  Null is "not in this process, or not a server", which is what
    // every one of those nine sites already treats as "do nothing".
    //
    // Nothing in the daemon changes: a placeholder for an out-of-process server
    // IS a server_instance and still answers itself here, exactly as the cast
    // did.  Whether calling into a placeholder is the right thing is a separate
    // question this does not touch.
    virtual server_instance* as_server() { return nullptr; }

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

    // ── How many worker processes serve this one runtime ────────────────────
    //
    // One by default, which is what every runtime in this tree was before
    // --shards existed and is still what one gets unless it asks otherwise.
    // More than one means N processes share the listening socket through
    // SO_REUSEPORT and the kernel gives each incoming connection to one of
    // them — the only way a single runtime uses more than the single core its
    // event loop runs on.
    //
    // A DECLARATION, never inferred.  Sharding is correct exactly when nothing
    // is shared between connections, and nothing can detect that: not the
    // configuration, and not the script, because a Lua table at file scope is
    // indistinguishable from one that happens never to be read twice.  So the
    // operator asks for it and owns the consequence — and the types where the
    // consequence is certainly wrong refuse the flag outright rather than let
    // the declaration be made at all.  See parse_common_flags.
    //
    // Kept on the placeholder rather than inside the supervisor because it is
    // configuration and is read as configuration: `inspect` prints it, the
    // state file carries it, and was_running has to bring a runtime back with
    // the shard count it had rather than merely bring it back.
    void     set_shards(uint32_t n);
    uint32_t get_shards() const;

    // ── Which of those processes THIS one is ────────────────────────────────
    //
    // 0..get_shards()-1, and 0 for every runtime that is not sharded — which is
    // the same answer a one-shard runtime gives, correctly: it is shard 0 of 1.
    //
    // The daemon's placeholder is not any shard and reads 0 too.  Nothing in
    // the daemon may use this to mean "the first shard"; the daemon addresses
    // shards through m_proxy_workers, where the position in the vector IS the
    // index and is the thing that was sent.
    //
    // Set from the config frame in a worker and from nowhere else.  There is no
    // flag for it and there must not be: an operator naming a shard index would
    // be naming one of N processes the kernel deliberately makes
    // indistinguishable.
    void     set_shard_index(uint32_t i);
    uint32_t get_shard_index() const;

    // ── What every shard of this runtime is publishing about itself ─────────
    //
    // Mapped in a worker whose daemon handed it a region — see shard_stats.h —
    // and unmapped everywhere else, which is every unsharded runtime and every
    // runtime in the daemon.  `mapped()` false is the ordinary case and every
    // reader below is written for it.
    shard_stats::shard_table& shard_stats_table() { return m_shard_stats; }

    // And which connections each shard is holding, by name; see
    // shard_clients.h.  Unmapped for every unsharded runtime and every runtime
    // in the daemon, which is what every reader below is written for.
    shard_clients::client_table& shard_clients_table() { return m_shard_clients; }

    // ── A message for a connection this process does not own ────────────────
    //
    // `self.send(id, msg)` where `id` names a client of a SIBLING shard.  Set
    // only in a worker; the daemon reads the conn_ref's own shard tag and hands
    // the message to exactly that worker, so this is one hop and not a search.
    //
    // Nothing is returned, for the reason worker_protocol.h gives above
    // encode_send_ref: the in-process path answers "queued", not "delivered",
    // and an answer here would have to be a promise the local path does not
    // make -- at the price of a round trip inside a Lua callback.
    using ref_sink = std::function<void(const conn_ref&, std::string_view)>;
    void set_ref_sink(ref_sink s) { m_ref_sink = std::move(s); }
    bool has_ref_sink() const { return static_cast<bool>(m_ref_sink); }
    void send_to_ref(const conn_ref& r, std::string_view msg)
    { if (m_ref_sink) m_ref_sink(r, msg); }

    // ── Reaching the clients this runtime has in OTHER processes ────────────
    //
    // The third of the three shapes a sharded runtime needs — fan-out — and the
    // one that costs least, because nothing is owed a reply.  The caller never
    // blocks: the message is written to the supervisor's socket and the call
    // returns, exactly as a publish already does.
    //
    // Empty for every runtime in the daemon and for every unsharded one, and
    // the guard below is on the SHARD COUNT rather than on the sink, so a
    // one-shard worker writes no frame at all rather than one the daemon has to
    // fan out to nobody.
    using sibling_sink = std::function<void(std::string_view message)>;
    void set_sibling_sink(sibling_sink s) { m_sibling_sink = std::move(s); }

    // Every client of this RUNTIME, not of this process.
    //
    // `self.broadcast` used to be lua_broadcast() alone, which is this
    // process's connection table — so on four shards it reached a quarter of
    // the clients and reported nothing.  Here rather than inside each runtime's
    // lua_broadcast() override, because it is the same decision for all four
    // and four copies of it is how one of them comes to be missing the fan-out.
    //
    // Local first, siblings second, and the order is deliberate: the local
    // delivery is synchronous and cannot fail halfway, so a script that
    // broadcasts and then reads its own state sees a consistent one.
    void broadcast_all(std::string_view msg)
    {
        lua_broadcast(msg);
        fanout_to_siblings(msg);
    }

    // The message on its way to this runtime's other shards, and a no-op
    // everywhere else.  Separate from broadcast_all() because `socketley.send`
    // addressed to this runtime's own name needs the second half without the
    // first — the worker has already delivered locally by then.
    void fanout_to_siblings(std::string_view msg)
    {
        if (m_shards > 1 && m_sibling_sink)
            m_sibling_sink(msg);
    }

    // How many connections THIS RUNTIME has, counting the ones its sibling
    // shards are holding.
    //
    // This is what a script means by `self.connections()`.  Unsharded, or in
    // the daemon, it is exactly get_connection_count() and costs the same.
    // Sharded, it is this shard's own count published into its slot and then a
    // sum over N slots — N loads out of shared memory, no round trip, and no
    // way for a shard that has stopped running to delay it.
    //
    // Publishing our own count first rather than trusting the last periodic
    // publish is what makes the commonest case right: a script that has just
    // been told a client connected asks how many there are, and the answer has
    // to include that client.
    uint64_t shard_connection_count()
    {
        const uint64_t mine = static_cast<uint64_t>(get_connection_count());
        if (!m_shard_stats.mapped())
            return mine;
        m_shard_stats.publish_active(mine);
        return m_shard_stats.sum_active();
    }

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

    // ── Is there something listening on this runtime's port yet? ────────────
    //
    // `running` answers that for a runtime that binds in this process, because
    // start() binds the listener before it returns and the state is set after.
    // It does not answer it for one that binds in a worker: start() there
    // stores `running` the moment the child is FORKED, since that is all this
    // side knows — the port is bound in the worker, and the daemon hears about
    // it in a `state` frame some milliseconds later.
    //
    // publish_endpoints() adds a runtime to its group on `running`, meaning "a
    // member that is merely configured has nothing listening".  For an
    // out-of-process member that reading was wrong, and the gap was not
    // academic: the address went into every other gateway's table while nothing
    // was accepting on it, a saturated gateway spent its next few thousand
    // requests being refused there, and five refusals opened the group circuit
    // breaker — which then excluded the new member for the whole circuit
    // timeout, thirty seconds by default.  Measured at 28k req/s: a member that
    // joined served nothing for the entire window.
    //
    // So the group filter asks this instead, and the supervisor is what answers
    // it: false from the fork, true when the child reports that it is serving.
    // True by default and never lowered for a runtime that binds here, which is
    // what keeps in-daemon behaviour exactly as it was.
    //
    // Deliberately NOT applied to the by-name entry above it.  That one is
    // unfiltered on purpose — a backend written as a bare runtime name is
    // resolved inside the target's own start(), before anything has bound — and
    // filtering it is what broke out-of-process proxies with a named backend
    // once already.  This is about group membership, which is a promise made to
    // somebody else.
    bool endpoint_live() const { return m_endpoint_live; }
    void set_endpoint_live(bool live) { m_endpoint_live = live; }

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
    // Whether the message was written or queued.  A runtime with no outward
    // connection of its own — a server, a cache — has nowhere to send it, and
    // saying so is better than the silent nothing this used to be.
    virtual bool lua_send(std::string_view /*msg*/) { return false; }
    virtual void lua_broadcast(std::string_view /*msg*/) {}
    // Whether the bytes reached a connection.  The base holds none, so the
    // honest answer here is no: a client or cache runtime handed a client_id
    // is being asked for something it does not have, and that used to be a
    // silent nothing.
    virtual bool lua_send_to(int /*client_id*/, std::string_view /*msg*/) { return false; }

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
    //
    // on_start answers whether it ran without raising, because it is the one
    // callback in this list that runs inside a command rather than on traffic:
    // `start`, `create -s` and — since it began re-running scripts' set-up —
    // `reload-lua`.  reload_lua_script() is the caller that acts on it; start()
    // ignores it deliberately, for the reason written there.
    bool invoke_on_start();
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

    std::string m_name;
    std::string m_id;
    runtime_type m_type;
    std::atomic<runtime_state> m_state;
    bool m_armed_io = false;
    // See last_on_start_error().  Empty unless the most recent on_start raised.
    std::string m_on_start_error;
    uint16_t m_port = 0;
    std::string m_listen_path;
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

    // One, and not zero, so that every reader can multiply or loop by it
    // without first asking whether it was ever set.  See set_shards().
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

    // See endpoint_live().  True by default: a runtime that binds in this
    // process is listening by the time anything can ask.
    bool m_endpoint_live{true};
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
