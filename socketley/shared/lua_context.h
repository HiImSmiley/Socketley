#pragma once

#include <string>
#include <string_view>

// ─── What the script said, on its way to the person who asked ───────────────
//
// Every Lua diagnostic in this tree is written to stderr, and stderr is the
// daemon's log.  A CLI command's reply channel is std::cout: daemon_handler
// borrows cout for the length of a command and hands whatever was printed back
// as the reply (see cout_to_reply).  stderr is not borrowed, and cannot be —
// the metrics endpoint has a thread of its own and logs there, so swapping a
// process-wide streambuf for an ostringstream would be a data race between two
// threads at the moment something has already gone wrong.
//
// So the load-time diagnostics are collected as well as printed, into a buffer
// belonging to the calling thread, and the commands that load or reload a
// script read it back and put the reason on the terminal of whoever typed the
// command.  The log keeps its copy: this is a tee, not a redirect.
//
// Load time only, deliberately.  A callback's error happens on traffic, with no
// command in flight to carry it anywhere; those keep going to the log alone.
namespace lua_diag
{
    // Begin one load, discarding whatever the previous one left behind.
    void clear();

    // Everything that load reported, newline separated, empty if it was silent.
    // Only meaningful immediately after the call that failed.
    const std::string& text();

    // Record one line.  Called from lua_context and runtime_instance's
    // compile-only paths; nothing else should need it.
    void record(std::string_view line);
}

#ifndef SOCKETLEY_NO_LUA

#include <sol/sol.hpp>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "route_table.h"

class runtime_instance;

// Lua context for a runtime - manages state and bindings
class lua_context
{
public:
    lua_context();
    ~lua_context();

    // Load and execute a Lua script, registering callbacks
    bool load_script(std::string_view path, runtime_instance* owner);

    // Compile a script without running a line of it, and say whether it parses.
    //
    // For an out-of-process runtime the script belongs to the worker, and the
    // daemon's placeholder must not execute it -- see
    // runtime_instance::load_lua_script.  But refusing to run it is not a
    // reason to stop looking at it: a syntax error is the one thing `create`
    // could always report immediately, and turning that into "the worker
    // exited, the runtime is failed" would be a worse message for what is
    // usually a typo.  So the placeholder compiles and discards.
    //
    // Static and owning its own state: it registers no bindings and takes no
    // runtime, precisely so that nothing a script does at its top level can
    // reach anything.  A chunk that compiles is not a chunk that is safe to
    // run -- that judgement stays with the worker, which is where it runs.
    static bool script_compiles(std::string_view path, std::string& err);

    // Get the Lua state (for callback invocation)
    sol::state& state() { return m_lua; }

    // Update self.state to reflect current runtime state
    void update_self_state(const char* state_str);

    // Callback bitmask constants
    enum : uint32_t {
        CB_ON_START              = 1u << 0,
        CB_ON_STOP               = 1u << 1,
        CB_ON_MESSAGE            = 1u << 2,
        CB_ON_SEND               = 1u << 3,
        CB_ON_CONNECT            = 1u << 4,
        CB_ON_DISCONNECT         = 1u << 5,
        CB_ON_ROUTE              = 1u << 6,
        CB_ON_MASTER_AUTH        = 1u << 7,
        CB_ON_CLIENT_MESSAGE     = 1u << 8,
        CB_ON_TICK               = 1u << 9,
        CB_ON_MISS               = 1u << 10,
        CB_ON_WRITE              = 1u << 11,
        CB_ON_DELETE             = 1u << 12,
        CB_ON_EXPIRE             = 1u << 13,
        CB_ON_AUTH               = 1u << 14,
        CB_ON_WEBSOCKET          = 1u << 15,
        CB_ON_PROXY_REQUEST      = 1u << 16,
        CB_ON_PROXY_RESPONSE     = 1u << 17,
        CB_ON_CLUSTER_JOIN       = 1u << 18,
        CB_ON_CLUSTER_LEAVE      = 1u << 19,
        CB_ON_GROUP_CHANGE       = 1u << 20,
        CB_ON_UPSTREAM           = 1u << 21,
        CB_ON_UPSTREAM_CONNECT   = 1u << 22,
        CB_ON_UPSTREAM_DISCONNECT = 1u << 23,
        CB_ON_HTTP_REQUEST       = 1u << 24,
        CB_FILTERS               = 1u << 25,
        CB_ROUTES                = 1u << 26,
    };

    // Check if context has valid callbacks (bitmask lookup)
    bool has_on_start()              const { return m_callback_mask & CB_ON_START; }
    bool has_on_stop()               const { return m_callback_mask & CB_ON_STOP; }
    bool has_on_message()            const { return m_callback_mask & CB_ON_MESSAGE; }
    bool has_on_send()               const { return m_callback_mask & CB_ON_SEND; }
    bool has_on_connect()            const { return m_callback_mask & CB_ON_CONNECT; }
    bool has_on_disconnect()         const { return m_callback_mask & CB_ON_DISCONNECT; }
    bool has_on_route()              const { return m_callback_mask & CB_ON_ROUTE; }
    bool has_on_master_auth()        const { return m_callback_mask & CB_ON_MASTER_AUTH; }
    bool has_on_client_message()     const { return m_callback_mask & CB_ON_CLIENT_MESSAGE; }
    bool has_on_tick()               const { return m_callback_mask & CB_ON_TICK; }
    bool has_on_miss()               const { return m_callback_mask & CB_ON_MISS; }
    bool has_on_write()              const { return m_callback_mask & CB_ON_WRITE; }
    bool has_on_delete()             const { return m_callback_mask & CB_ON_DELETE; }
    bool has_on_expire()             const { return m_callback_mask & CB_ON_EXPIRE; }
    bool has_on_auth()               const { return m_callback_mask & CB_ON_AUTH; }
    bool has_on_websocket()          const { return m_callback_mask & CB_ON_WEBSOCKET; }
    bool has_on_proxy_request()      const { return m_callback_mask & CB_ON_PROXY_REQUEST; }
    bool has_on_proxy_response()     const { return m_callback_mask & CB_ON_PROXY_RESPONSE; }
    bool has_on_cluster_join()       const { return m_callback_mask & CB_ON_CLUSTER_JOIN; }
    bool has_on_cluster_leave()      const { return m_callback_mask & CB_ON_CLUSTER_LEAVE; }
    bool has_on_group_change()       const { return m_callback_mask & CB_ON_GROUP_CHANGE; }
    bool has_on_upstream()           const { return m_callback_mask & CB_ON_UPSTREAM; }
    bool has_on_upstream_connect()   const { return m_callback_mask & CB_ON_UPSTREAM_CONNECT; }
    bool has_on_upstream_disconnect() const { return m_callback_mask & CB_ON_UPSTREAM_DISCONNECT; }
    bool has_on_http_request()       const { return m_callback_mask & CB_ON_HTTP_REQUEST; }
    // Whether the script declared a non-empty `filters` chain.  Asked once per
    // request on the proxy's route path, so it is a mask bit like every other
    // callback here rather than a vector emptiness test.
    bool has_filters()               const { return m_callback_mask & CB_FILTERS; }
    // Whether the script declared a non-empty `routes` table.  Asked by the
    // daemon when it publishes the endpoint snapshot, not on any request path.
    bool has_routes()                const { return m_callback_mask & CB_ROUTES; }

    // Get callbacks
    sol::protected_function& on_start() { return m_on_start; }
    sol::protected_function& on_stop() { return m_on_stop; }
    sol::protected_function& on_message() { return m_on_message; }
    sol::protected_function& on_send() { return m_on_send; }
    sol::protected_function& on_connect() { return m_on_connect; }
    sol::protected_function& on_disconnect() { return m_on_disconnect; }
    // protected_function, like filters() and unlike every other callback here.
    // See m_on_route below for why.
    sol::protected_function& on_route() { return m_on_route; }
    sol::protected_function& on_master_auth() { return m_on_master_auth; }
    sol::protected_function& on_client_message() { return m_on_client_message; }
    sol::protected_function& on_tick() { return m_on_tick; }
    sol::protected_function& on_miss()      { return m_on_miss; }
    sol::protected_function& on_write()     { return m_on_write; }
    sol::protected_function& on_delete_cb() { return m_on_delete; }  // avoid clash with std::delete
    sol::protected_function& on_expire()    { return m_on_expire; }
    sol::protected_function& on_auth()        { return m_on_auth; }
    sol::protected_function& on_websocket()   { return m_on_websocket; }
    sol::protected_function& on_proxy_request()  { return m_on_proxy_request; }
    sol::protected_function& on_proxy_response() { return m_on_proxy_response; }
    sol::protected_function& on_cluster_join()   { return m_on_cluster_join; }
    sol::protected_function& on_cluster_leave()  { return m_on_cluster_leave; }
    sol::protected_function& on_group_change()   { return m_on_group_change; }
    sol::protected_function& on_upstream()           { return m_on_upstream; }
    sol::protected_function& on_upstream_connect()   { return m_on_upstream_connect; }
    sol::protected_function& on_upstream_disconnect() { return m_on_upstream_disconnect; }
    sol::function& on_http_request()       { return m_on_http_request; }
    // The chain, in the order the script listed it.  Only valid to read when
    // has_filters() is true; empty otherwise.
    const std::vector<sol::protected_function>& filters() const { return m_filters; }

    // What this script says it will answer.  Read by runtime_manager when it
    // builds the snapshot every proxy is handed, and by nothing else — a route
    // declaration is data about this runtime, not a callback into it, which is
    // the whole reason it can cross a process boundary later.  Empty unless
    // has_routes().
    const route_table& declared_routes() const { return m_routes; }

    uint32_t get_tick_ms() const { return m_tick_ms; }

    // Cross-runtime pub/sub dispatch (called from runtime_instance)
    void dispatch_publish(std::string_view cache_name, std::string_view channel, std::string_view message);

    // ── "This process holds no runtime manager, and never will" ──────────────
    //
    // A worker process runs one runtime and nothing else.  There is no map of
    // runtimes in it to list, create in, or send to, and there cannot be: the
    // map lives in the daemon, one process away, and the answer to "may a
    // runtime make a synchronous call into another one" was already settled as
    // no — that is why `server --cache` is an async continuation and not a
    // blocking lookup.  A management call from here has no honest answer.
    //
    // A process fact rather than a per-instance one, because that is what it is.
    // Set once, before anything is created; every lua_context built afterwards
    // sees it.
    static void set_worker_process(bool on);
    static bool in_worker_process();

private:
    void register_bindings(runtime_instance* owner);
    // Overwrite the cross-runtime calls with a refusal that names them.  Only
    // called when in_worker_process().
    void refuse_cross_runtime_api(sol::table& sk, sol::table& cluster_tbl);
    void register_server_table(runtime_instance* owner, sol::table& self);
    void register_client_table(runtime_instance* owner, sol::table& self);
    void register_cache_table(runtime_instance* owner, sol::table& self);
    void register_proxy_table(runtime_instance* owner, sol::table& self);

    sol::state m_lua;
    sol::protected_function m_on_start;
    sol::protected_function m_on_stop;
    sol::protected_function m_on_message;
    sol::protected_function m_on_send;
    sol::protected_function m_on_connect;
    sol::protected_function m_on_disconnect;

    // protected_function, for the same reason m_filters below is one.  Every
    // callback still declared sol::function is invoked inside a try/catch that
    // catches sol::error; that only works because sol2's panic handler happens
    // to throw one, and whether the throw can unwind out of the interpreter at
    // all depends on how LuaJIT was built — so the catch is a bet, not a
    // guarantee.  A protected call does not make the bet: the error comes back
    // as a value.
    //
    // The bet is not hypothetical and it is not only about exotic toolchains:
    // it loses in this repository's own Sanitize configuration.  Measured, one
    // script per row, the callback raising after logging a marker so that
    // "did it run" and "was the error reported" are separate questions:
    //
    //                       marker logged   error logged (Release / Sanitize)
    //     on_auth  (catch)       yes                 yes    /    NO
    //     filters  (protected)   yes                 yes    /    yes
    //
    // The same daemon, the same log file, the same std::cerr — so the message
    // is not being lost on the way out, the catch simply never runs.  Every
    // `catch (const sol::error&)` diagnostic in this tree is therefore dead
    // under the sanitizer build, which is the build the nightly job uses to
    // find regressions.  The three callbacks below were moved across because a
    // silent auth hook and a silent proxy hook are the two places where losing
    // the message costs the most; the rest are recorded as a finding.
    //
    // on_route is the callback that decides where a request goes, and the
    // routing path already has a defined answer for "no usable index came back"
    // — round-robin.  An error is that same non-answer, so it has to arrive in a
    // form the C++ side can act on rather than as an unwind through the accept
    // path.  It is also the callback most likely to raise: on a TCP proxy it is
    // called with no arguments, so the ordinary `hash(path) % n` errors on the
    // very first request.
    sol::protected_function m_on_route;

    // An auth hook that raises must deny AND say so; a hook whose error is
    // swallowed is indistinguishable from one that considered the request and
    // refused it, which is the whole defect this callback was just fixed for.
    sol::protected_function m_on_master_auth;
    sol::protected_function m_on_client_message;
    sol::protected_function m_on_tick;
    sol::protected_function m_on_miss;
    sol::protected_function m_on_write;
    sol::protected_function m_on_delete;
    sol::protected_function m_on_expire;
    // The callback that decides whether a client is served at all, so a
    // failure has to arrive as a value for the same reason on_master_auth's
    // does — and a test now pins that its error is reported, which under the
    // try/catch it was not in the Sanitize build.
    sol::protected_function m_on_auth;
    sol::protected_function m_on_websocket;
    // Both refuse on error, so the error has to arrive as a value: a refusal
    // nobody can explain is barely better than the admission it replaced.
    sol::protected_function m_on_proxy_request;
    sol::protected_function m_on_proxy_response;
    sol::protected_function m_on_cluster_join;
    sol::protected_function m_on_cluster_leave;
    sol::protected_function m_on_group_change;
    sol::protected_function m_on_upstream;
    sol::protected_function m_on_upstream_connect;
    sol::protected_function m_on_upstream_disconnect;
    sol::function m_on_http_request;

    // The `filters` chain.  A vector and not a single sol::function because the
    // whole point of it is order: each entry is asked in turn and the first one
    // with an answer ends the request.  Collected once at load time, so nothing
    // walks the Lua global table per request.
    //
    // protected_function and not function, unlike every callback above: a filter
    // is where authentication lives, and an error raised inside one has to come
    // back as a value this side can act on — the request is refused — rather
    // than as an unwind whose behaviour depends on how LuaJIT was built.
    std::vector<sol::protected_function> m_filters;

    // The `routes` declaration, converted out of Lua once at load time.  A
    // plain C++ table and not a sol::table: it is published to other runtimes,
    // and anything that has to survive being sent somewhere cannot be a
    // reference into this Lua state.
    route_table m_routes;

    uint32_t m_tick_ms{0};
    uint32_t m_callback_mask{0};

    // See set_worker_process().  Written once at process start, before any
    // interpreter exists, and read-only afterwards — so it needs no atomic and
    // no lock, and a plain bool is what it means.
    static bool s_worker_process;

    // Timer lifetime guard — set to false in destructor; timers check before firing
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};

    // Active timers — tracked so we can clear sol::function refs before Lua state closes
    std::vector<void*> m_active_timers;

public:
    void unregister_timer(void* t);
private:

    // Cross-runtime pub/sub: key = cache_name + '\0' + channel
    std::unordered_map<std::string, std::vector<sol::protected_function>> m_subscriptions;

    // Timer cancellation: ID → timer* mapping
    int m_next_timer_id{0};
    std::unordered_map<int, void*> m_timer_map;

    // Timer pool to avoid per-timer heap allocation
    std::vector<void*> m_timer_pool;
public:
    void* timer_pool_acquire();
    void timer_pool_release(void* t);
private:
};

#else // SOCKETLEY_NO_LUA

#include <string>
#include <string_view>
#include <cstdint>

#include "route_table.h"

class runtime_instance;

// No-op stub — same public interface, no LuaJIT required
class lua_context
{
public:
    lua_context() = default;
    ~lua_context() = default;

    bool load_script(std::string_view, runtime_instance*) { return true; }
    // Without Lua there is no chunk to compile, so nothing can fail to.
    static bool script_compiles(std::string_view, std::string&) { return true; }
    void update_self_state(const char*) {}

    bool has_on_start()          const { return false; }
    bool has_on_stop()           const { return false; }
    bool has_on_message()        const { return false; }
    bool has_on_send()           const { return false; }
    bool has_on_connect()        const { return false; }
    bool has_on_disconnect()     const { return false; }
    bool has_on_route()          const { return false; }
    bool has_on_master_auth()    const { return false; }
    bool has_on_client_message() const { return false; }
    bool has_on_tick()           const { return false; }
    bool has_on_miss()           const { return false; }
    bool has_on_write()          const { return false; }
    bool has_on_delete()         const { return false; }
    bool has_on_expire()         const { return false; }
    bool has_on_auth()           const { return false; }
    bool has_on_websocket()      const { return false; }
    bool has_on_proxy_request()  const { return false; }
    bool has_on_proxy_response() const { return false; }
    bool has_on_cluster_join()   const { return false; }
    bool has_on_cluster_leave()  const { return false; }
    bool has_on_group_change()   const { return false; }
    bool has_on_upstream()           const { return false; }
    bool has_on_upstream_connect()   const { return false; }
    bool has_on_upstream_disconnect() const { return false; }
    bool has_on_http_request()       const { return false; }
    bool has_filters()               const { return false; }
    bool has_routes()                const { return false; }
    // A reference to one empty table for every caller: without Lua there is no
    // script to declare a route, so there is nothing to own per instance.
    const route_table& declared_routes() const
    {
        static const route_table empty;
        return empty;
    }
    uint32_t get_tick_ms()       const { return 0; }
    void dispatch_publish(std::string_view, std::string_view, std::string_view) {}
    // The worker calls this before it builds anything; without Lua there is no
    // management API to refuse, so it records nothing.
    static void set_worker_process(bool) {}
    static bool in_worker_process() { return false; }
    // on_*() callbacks omitted — only called when has_*() returns true,
    // and guarded by #ifndef SOCKETLEY_NO_LUA at each call site.
};

#endif // SOCKETLEY_NO_LUA
