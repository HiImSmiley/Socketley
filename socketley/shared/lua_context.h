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
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "route_table.h"

class runtime_instance;

// ─── How long one Lua callback may hold the event-loop thread ───────────────
//
// Nothing used to bound a script at all.  `while true do end` in any callback —
// or at a script's top level, which runs synchronously inside the `create`
// command — freezes the single thread that serves every runtime in this daemon:
// all traffic, the metrics endpoint, the IPC socket.  Measured on the parent
// commit, one server spinning and a second server doing nothing:
//
//     stats <the other runtime>   -> no answer, exit 2 after 5s
//     traffic to the other runtime -> not served
//     daemon                       -> 80% of a core, recoverable only by SIGKILL
//
// The mechanism is a count hook.  lua_sethook(L, h, LUA_MASKCOUNT, N) fires h
// every N VM instructions; h reads a clock and, if this invocation has outrun
// its deadline, raises a Lua error, which unwinds the callback exactly the way
// any other script error does — the tree already knows how to report those.
//
// The trigger is an instruction count because that is the only thing LuaJIT will
// call back on.  The *test* is wall-clock time, because instructions do not map
// to time: a callback blocked in socketley.http executes almost no bytecode and
// still holds the loop for as long as it likes.  An instruction budget on its
// own would punish a tight numeric loop and wave the sleeping one through.
//
// Not a supervisor thread (nothing can safely interrupt LuaJIT from outside),
// and not a runtime kill (heavier than failing the one callback, and the
// callback failure path already exists and already reports).
namespace lua_deadline
{
    // ─── The number ─────────────────────────────────────────────────────────
    //
    // Ten seconds, which is not a new scale: it is PROXY_HEADER_TIMEOUT_SEC,
    // and it was chosen there for the same shape of question — "far outside
    // anything a working participant does, and far inside how long something
    // broken would like to hold the connection".  A callback is the same
    // trade: no legitimate handler in this tree spends a second, and the
    // cost of being wrong in the other direction is a working script that
    // starts failing, which is worse than no bound at all.
    //
    // It is also the number socketley.http forces.  That call blocks the event
    // loop by design and defaults to a 5000ms timeout, and it is sanctioned for
    // on_start / on_stop / low-frequency on_tick — so a callback that makes one
    // ordinary HTTP request must fit inside the deadline with room to spare, or
    // the deadline breaks the documented use of the one blocking primitive this
    // tree ships.  10000 leaves that request its full 5000 and a second one
    // after it.  Anything at or under 5000 would silently clip the default.
    //
    // The two are not merely numerically compatible: socketley.http asks
    // remaining_ms() and clamps its own wait to what is left of the callback's
    // budget, so there is one budget rather than two that happen to agree.  The
    // hook cannot fire *inside* http in any case — a count hook counts VM
    // instructions and a blocking C call executes none — so there is no way for
    // this to interrupt a half-read socket.
    inline constexpr uint32_t builtin_default_ms = 10000;

    // The process-wide default, in milliseconds; 0 means the mechanism is off
    // and no hook is installed at all.  Read once from SOCKETLEY_LUA_TIMEOUT_MS.
    //
    // ─── Where it is configurable, and why there ────────────────────────────
    //
    // Two knobs, for the two people who have a reason to touch it.
    //
    // The script says `callback_timeout_ms = N` at its top level, next to
    // `tick_ms`, which is the same shape of declaration for the same reason:
    // how long a callback legitimately needs is a property of the code in that
    // file, and the person who knows it is the person editing it.  It travels
    // with the script through reload-lua, export and import without a new
    // persisted field on every runtime.
    //
    // The operator sets SOCKETLEY_LUA_TIMEOUT_MS in the daemon's environment,
    // alongside SOCKETLEY_CACHE_TTL_SWEEP_MS and SOCKETLEY_SQPOLL_IDLE_MS,
    // which are the tuning knobs of exactly this kind.  It moves the default
    // for every script that never mentioned the subject, and 0 switches the
    // mechanism off outright — which is what a new safety mechanism owes
    // whoever is running it in production when it turns out to misfire.
    //
    // Not a CLI flag.  A flag would have to be parsed, persisted, exported,
    // imported, shown by `inspect` and accepted by `edit`, and it would let
    // somebody who has not read the script overrule a bound its author set
    // deliberately.  The two knobs above already cover both people.
    uint32_t default_ms();

    // Put the count hook on a state, or take it off when limit_ms is 0.
    //
    // Public because lua_context is not the only interpreter in the daemon: it
    // reads its own configuration file with a bare sol::state before any runtime
    // exists (see daemon.cpp), and a config file is a script like any other.
    //
    // Every interpreter in the DAEMON is bounded.  The one in the CLI process is
    // not, deliberately — see cli_config.cpp.
    void install(lua_State* L, uint32_t limit_ms);

    // Arm the deadline for one callback invocation.
    //
    // Nesting is deliberate and only the outermost scope arms.  A callback that
    // reaches a second interpreter — socketley.publish running a subscriber that
    // belongs to another runtime — is one stretch of time the event loop is held
    // for, and that is the thing being bounded, so the inner call spends the
    // outer call's budget rather than being handed a fresh one.
    class scope
    {
    public:
        // `what` names the callback for the diagnostic; it must outlive the
        // scope, which every call site satisfies by passing a literal.
        // `limit_ms` of 0 leaves the deadline unarmed.
        scope(const char* what, uint32_t limit_ms) noexcept;
        ~scope() noexcept;
        scope(const scope&)            = delete;
        scope& operator=(const scope&) = delete;

    private:
        bool m_outermost;
    };

    // Milliseconds left in the armed invocation; -1 when nothing is armed or
    // the mechanism is off.  socketley.http asks, so that its own wait lives
    // inside the callback's budget instead of beside it.
    long remaining_ms() noexcept;
}

// One callback, with the deadline armed for exactly the length of the call.
//
// Returned by every on_*() accessor below instead of the bare sol::function, so
// that arming is not something 40 call sites in five files each have to
// remember — and so that the next callback added to this class gets the bound
// by writing its accessor the same way the others are written.
template <class F>
class lua_guarded_call
{
public:
    lua_guarded_call(F& fn, const char* what, uint32_t limit_ms) noexcept
        : m_fn(fn), m_scope(what, limit_ms) {}

    // decltype(auto) rather than auto: sol's call operator returns a result
    // object that owns a slice of the Lua stack and pops it when it dies.  The
    // returned expression is a prvalue of that type, so C++17 constructs it
    // straight into the caller's object — no move, no second pop.
    template <class... A>
    decltype(auto) operator()(A&&... a) const { return m_fn(std::forward<A>(a)...); }

private:
    F&                   m_fn;
    lua_deadline::scope  m_scope;
};

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

    // Sever every armed timer from this context without destroying it.  Called
    // when a runtime stops: a stopped runtime must execute no script, and its
    // set_interval timers otherwise keep firing until the context is destroyed
    // by `remove`.  Idempotent — a second call has nothing left to sever.
    void cancel_timers();

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

    // Get callbacks.
    //
    // Each returns a handle that arms the invocation deadline for the length of
    // the call and disarms it afterwards, then forwards to the function.  Call
    // sites are unchanged — `lua->on_message()(msg)` still reads the same — and
    // no call site can forget the bound, which is the point of putting it here
    // rather than at each of the forty places that invoke one of these.
    //
    // The handle forwards and nothing else.  It does not look at the result and
    // must not start: 07baee7..b868bb5 made every one of these a protected call
    // whose caller checks valid() before reading anything, and a failed call
    // still has a value at index 0 — the error object.  b868bb5 records what
    // that costs when the order is wrong: on_miss reads index 0 and writes it
    // into the cache, so a read-before-check would have stored a Lua error
    // message as the fetched value and served it as a hit for ever.
    //
    // guarded_protected almost everywhere, because after that sweep almost
    // every callback here is a sol::protected_function.  on_http_request is the
    // one still declared sol::function, so it is the one still `guarded`.
    using guarded           = lua_guarded_call<sol::function>;
    using guarded_protected = lua_guarded_call<sol::protected_function>;

    guarded_protected on_start()      { return {m_on_start,      "on_start",      m_deadline_ms}; }
    guarded_protected on_stop()       { return {m_on_stop,       "on_stop",       m_deadline_ms}; }
    guarded_protected on_message()    { return {m_on_message,    "on_message",    m_deadline_ms}; }
    guarded_protected on_send()       { return {m_on_send,       "on_send",       m_deadline_ms}; }
    guarded_protected on_connect()    { return {m_on_connect,    "on_connect",    m_deadline_ms}; }
    guarded_protected on_disconnect() { return {m_on_disconnect, "on_disconnect", m_deadline_ms}; }
    // on_route and on_master_auth were protected before the sweep — see
    // m_on_route below for the reasoning that the sweep then generalised.
    guarded_protected on_route()       { return {m_on_route,       "on_route",       m_deadline_ms}; }
    guarded_protected on_master_auth() { return {m_on_master_auth, "on_master_auth", m_deadline_ms}; }
    guarded_protected on_client_message() { return {m_on_client_message, "on_client_message", m_deadline_ms}; }
    guarded_protected on_tick()       { return {m_on_tick,       "on_tick",       m_deadline_ms}; }
    guarded_protected on_miss()       { return {m_on_miss,       "on_miss",       m_deadline_ms}; }
    guarded_protected on_write()      { return {m_on_write,      "on_write",      m_deadline_ms}; }
    guarded_protected on_delete_cb()  { return {m_on_delete,     "on_delete",     m_deadline_ms}; }  // avoid clash with std::delete
    guarded_protected on_expire()     { return {m_on_expire,     "on_expire",     m_deadline_ms}; }
    // The callback that decides whether a client is served at all.  A deadline
    // raised in here IS such a failure, and it reaches invoke_on_auth's
    // !valid() branch — reported, and fail-closed — rather than vanishing.
    guarded_protected on_auth()       { return {m_on_auth,       "on_auth",       m_deadline_ms}; }
    guarded_protected on_websocket()  { return {m_on_websocket,  "on_websocket",  m_deadline_ms}; }
    guarded_protected on_proxy_request()  { return {m_on_proxy_request,  "on_proxy_request",  m_deadline_ms}; }
    guarded_protected on_proxy_response() { return {m_on_proxy_response, "on_proxy_response", m_deadline_ms}; }
    guarded_protected on_cluster_join()  { return {m_on_cluster_join,  "on_cluster_join",  m_deadline_ms}; }
    guarded_protected on_cluster_leave() { return {m_on_cluster_leave, "on_cluster_leave", m_deadline_ms}; }
    guarded_protected on_group_change()  { return {m_on_group_change,  "on_group_change",  m_deadline_ms}; }
    guarded_protected on_upstream()            { return {m_on_upstream,            "on_upstream",            m_deadline_ms}; }
    guarded_protected on_upstream_connect()    { return {m_on_upstream_connect,    "on_upstream_connect",    m_deadline_ms}; }
    guarded_protected on_upstream_disconnect() { return {m_on_upstream_disconnect, "on_upstream_disconnect", m_deadline_ms}; }
    guarded on_http_request()        { return {m_on_http_request,        "on_http_request",        m_deadline_ms}; }
    // The chain, in the order the script listed it.  Only valid to read when
    // has_filters() is true; empty otherwise.
    //
    // The one accessor that hands back the functions themselves rather than a
    // guarded handle, because the chain is walked and the whole walk is what a
    // request costs: the caller arms one lua_deadline::scope around the loop
    // (see proxy_instance) so ten filters share one request's budget instead of
    // being handed ten.
    const std::vector<sol::protected_function>& filters() const { return m_filters; }

    // What one invocation of a callback on this script may spend, in ms; 0 when
    // the deadline is off.  Read by the filter chain, which arms its own scope.
    uint32_t callback_timeout_ms() const { return m_deadline_ms; }

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
    // Put the count hook on this state, or take it off when m_deadline_ms is 0.
    // Called once at construction and again after the script's top level has
    // run, because that is when a `callback_timeout_ms` global becomes readable.
    void install_deadline_hook();

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

    // What one callback invocation on this script may spend, in milliseconds;
    // 0 = unbounded, and then no hook is installed and LuaJIT keeps its JIT.
    //
    // Starts at the process default so that the top-level chunk — which runs
    // inside `create`, before the script has had a chance to say anything — is
    // bounded too; a top level that never returns must refuse the create rather
    // than half-build a runtime.  Replaced by the script's own
    // `callback_timeout_ms` global, if it declared one, once the chunk has run.
    uint32_t m_deadline_ms{lua_deadline::default_ms()};

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
    void cancel_timers() {}

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
