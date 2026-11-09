#pragma once

#include <cstdint>
#include <string>
#include <string_view>

// Load-time Lua diagnostics are collected into a per-thread buffer as well as
// printed, so the command that loaded the script can put the reason on the
// terminal -- a tee and not a redirect, and load time only, because a
// callback's error has no command in flight to carry it.
namespace lua_diag
{
    // Begin one load, discarding whatever the previous one left behind.
    void clear();

    // Everything that load reported, newline separated, and only meaningful
    // immediately after the call that failed.
    const std::string& text();

    // Record one line, called from lua_context and runtime_instance's
    // compile-only paths and nothing else.
    void record(std::string_view line);

    // ─── Which runtime's script said it ─────────────────────────────────────
    // The prefix every Lua diagnostic carries, "[lua <name>]", because the
    // script name in an error is a file and a file is not a runtime -- one
    // handler is shared across a set of servers in examples/.
    std::string tag(std::string_view runtime_name);
}

// ─── The tick floor, in one place ───────────────────────────────────────────
// runtime_instance's floor is the last word on `tick_ms` because it also
// clamps the C++ SDK path, and the Lua path refuses a value below it rather
// than raising it, so a mistake is found while editing the file.
namespace lua_tick
{
    // The shortest interval on_tick may be armed at.
    inline constexpr uint32_t floor_ms = 10;

    // What a script that declares on_tick and no tick_ms gets, and what a
    // runtime with no script at all ticks at.
    inline constexpr uint32_t default_ms = 100;
}

#ifndef SOCKETLEY_NO_LUA

#include <sol/sol.hpp>
#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../http/route_table.h"
#include "../cluster/cluster_view.h"

class runtime_instance;

// Held by pointer and not by value: lua_suspend.h needs lua_deadline and
// lua_diag from this file, so including it here would be a cycle.  A call site
// that starts a callback includes shared/lua/lua_suspend.h itself.
class lua_suspender;
class lua_storage_client;
class lua_db_client;
class lua_mqtt_client;
class lua_mail_client;
class lua_http_client;

namespace deadline_slot { struct slot; }

// How long one Lua callback may hold the event-loop thread, watched from
// outside the thread rather than by a hook inside it: a worker publishes the
// invocation in a line the daemon reads every 100 ms, and only a callback
// found past its budget gets an instruction hook, put there by a signal --
// so no hook runs in normal operation and the trace compiler stays on.
namespace lua_deadline
{
    // ─── The number ─────────────────────────────────────────────────────────
    // Ten seconds, the same number PROXY_HEADER_TIMEOUT_SEC was chosen for,
    // and the one that leaves socketley.http its documented 5000 ms with room
    // for a second request inside one shared budget.
    inline constexpr uint32_t builtin_default_ms = 10000;

    // The process-wide default in milliseconds, 0 meaning nothing is armed or
    // written at all, set by the script's `callback_timeout_ms` or by
    // SOCKETLEY_LUA_TIMEOUT_MS -- and not by a CLI flag, which would let
    // somebody who has not read the script overrule a bound its author set.
    uint32_t default_ms();

    // Hand this thread's callbacks to the daemon's watch through `line`, called
    // once by a worker before any interpreter exists; a thread that never calls
    // it watches itself with a timer per invocation instead.
    void watch(deadline_slot::slot* line) noexcept;

    // Whether this thread's callbacks are watched by the daemon, which is what
    // can end one that a compiled trace keeps away from any hook.
    bool watched() noexcept;

    // Open the deadline for one callback invocation, dated from the start of
    // the loop turn it runs in, and mark that this thread is inside one, with
    // only the outermost scope opening it, because a nested interpreter is the
    // same stretch of time the event loop is held for.
    class scope
    {
    public:
        // `L` is the state the callback runs on, any thread of it, for the stop
        // hook to be put on; `what` and `runtime` name the callback and its
        // runtime for the diagnostic and must outlive the scope, because the
        // hook formats them with fprintf where no destructor may run;
        // `limit_ms` of 0 leaves the deadline unarmed without stopping the
        // scope counting.
        scope(lua_State* L, const char* what, uint32_t limit_ms, const char* runtime = nullptr) noexcept;
        ~scope() noexcept;
        scope(const scope&)            = delete;
        scope& operator=(const scope&) = delete;

    private:
        lua_State* m_L;
        // The state a nested scope on another interpreter took over from, put back when it ends.
        lua_State* m_outer_L{nullptr};
        bool       m_outermost;
        bool       m_first_frame;
    };

    // Milliseconds left in the armed invocation, -1 when nothing is armed,
    // asked by socketley.http so its wait lives inside the callback's budget.
    long remaining_ms() noexcept;

    // True while a Lua callback is somewhere on this thread's stack, asked
    // before a runtime_instance is freed outright, and not the same question
    // as remaining_ms() >= 0.
    bool in_callback() noexcept;

    // Raises the deadline error on L once the armed invocation is past its
    // deadline, for C code that runs long without executing a VM instruction.
    void check(lua_State* L);
}

// One callback with the deadline armed for exactly the length of the call,
// returned by every on_*() accessor so no call site has to remember the bound.
template <class F>
class lua_guarded_call
{
public:
    lua_guarded_call(F& fn, const char* what, uint32_t limit_ms,
                     const char* runtime = nullptr) noexcept
        : m_fn(fn), m_scope(fn.lua_state(), what, limit_ms, runtime) {}

    // decltype(auto) rather than auto, because sol's result owns a slice of
    // the Lua stack and C++17 then constructs it straight into the caller's
    // object.
    template <class... A>
    decltype(auto) operator()(A&&... a) const { return m_fn(std::forward<A>(a)...); }

private:
    F&                   m_fn;
    lua_deadline::scope  m_scope;
};

namespace lua_diag
{
    // Writes "<tag> <hook> error: <message><then>" to stderr for a callback that raised.
    void report_raise(const sol::protected_function_result& r, std::string_view owner, std::string_view hook,
                      std::string_view then);

    // True when `r` raised, which is then reported; what a raise means is the caller's to decide.
    inline bool raised(const sol::protected_function_result& r, std::string_view owner, std::string_view hook,
                       std::string_view then = {})
    {
        if (__builtin_expect(r.valid(), 1))
            return false;
        report_raise(r, owner, hook, then);
        return true;
    }
}

// Lua context for a runtime - manages state and bindings
class lua_context
{
public:
    lua_context();
    ~lua_context();

    // Load and execute a Lua script, registering callbacks
    bool load_script(std::string_view path, runtime_instance* owner);

    // Compile a script without running a line of it, for the placeholder of an
    // out-of-process runtime, in a static state that registers no bindings so
    // nothing a top level does can reach anything.
    static bool script_compiles(std::string_view path, std::string& err);

    // Get the Lua state (for callback invocation)
    sol::state& state() { return m_lua; }

    // The runtime this interpreter belongs to, for a diagnostic's prefix,
    // empty before load_script has run.
    const std::string& owner_name() const { return m_owner_name; }

    // The callbacks of this runtime that stopped on an await, and the threads
    // they stopped on.
    lua_suspender& suspender() { return *m_suspend; }
    const lua_suspender& suspender() const { return *m_suspend; }

    // Update self.state to reflect current runtime state
    void update_self_state(const char* state_str);

    // Sever every armed timer from this context without destroying it, because
    // a stopped runtime must execute no script; idempotent.
    void cancel_timers();

    // End every subscription this context holds, the other half of
    // cancel_timers() and called from the same place, safe from inside a
    // delivery and idempotent.
    void cancel_subscriptions();

    // Both severances raise this latch, and while it is up the two calls that
    // schedule work refuse and say so, because stop() returns to a script that
    // would otherwise arm them again; start() lowers it before on_start.
    bool registrations_severed() const { return m_severed; }
    void allow_registrations() { m_severed = false; }

    // Callback bitmask constants
    enum : uint64_t {
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
        CB_ON_WRITABLE           = 1u << 27,
        CB_ON_HTTP_BODY          = 1u << 28,
        CB_ON_UPSTREAM_WRITABLE  = 1u << 29,
        // A storage runtime's: a request that has passed authentication and
        // has not begun, and an object that has just been committed.
        CB_ON_REQUEST            = 1u << 30,
        CB_ON_PUT                = 1u << 31,
        // An mqtt runtime's: a message or a subscription on its way in, either of which the script may refuse.
        CB_ON_PUBLISH            = 1ull << 32,
        CB_ON_SUBSCRIBE          = 1ull << 33,
        // A mail runtime's: a recipient on its way in, which the script may take or refuse.
        CB_ON_RCPT               = 1ull << 34,
        // Every complete line of one read as one string, in place of on_message and on_client_message.
        CB_ON_MESSAGES           = 1ull << 35,
        CB_ON_CLIENT_MESSAGES    = 1ull << 36,
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
    // The batch forms, which win over the per-line ones when a script defines both.
    bool has_on_messages()           const { return m_callback_mask & CB_ON_MESSAGES; }
    bool has_on_client_messages()    const { return m_callback_mask & CB_ON_CLIENT_MESSAGES; }
    // A connection's write queue has come back down under the watermark, so a
    // producer that stopped because self.pending() was high can go on.
    bool has_on_writable()           const { return m_callback_mask & CB_ON_WRITABLE; }
    // Defining it is the opt-in: a request body is streamed to it instead of
    // being gathered whole, which is why there is no flag for this.
    bool has_on_http_body()          const { return m_callback_mask & CB_ON_HTTP_BODY; }
    // An upstream's write queue has come back under the watermark.  Its own
    // callback and not on_writable, because an upstream id and a client id are
    // different spaces and one function taking both would have to be told which.
    bool has_on_upstream_writable()   const { return m_callback_mask & CB_ON_UPSTREAM_WRITABLE; }
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
    bool has_on_request()            const { return m_callback_mask & CB_ON_REQUEST; }
    bool has_on_put()                const { return m_callback_mask & CB_ON_PUT; }
    bool has_on_publish()            const { return m_callback_mask & CB_ON_PUBLISH; }
    bool has_on_subscribe()          const { return m_callback_mask & CB_ON_SUBSCRIBE; }
    bool has_on_rcpt()               const { return m_callback_mask & CB_ON_RCPT; }
    // Whether the script declared a non-empty `filters` chain, a mask bit
    // because it is asked once per request on the proxy's route path.
    bool has_filters()               const { return m_callback_mask & CB_FILTERS; }
    // Whether the script declared a non-empty `routes` table, asked when the
    // daemon publishes the endpoint snapshot and on no request path.
    bool has_routes()                const { return m_callback_mask & CB_ROUTES; }

    // Each accessor returns a handle that arms the deadline and forwards,
    // looking at the result and never reading it, because a failed protected
    // call still has the error object at index 0 -- which on_miss would
    // otherwise store as the fetched value.
    using guarded_protected = lua_guarded_call<sol::protected_function>;

    guarded_protected on_start()      { return {m_on_start,      "on_start",      m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_stop()       { return {m_on_stop,       "on_stop",       m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_message()    { return {m_on_message,    "on_message",    m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_send()       { return {m_on_send,       "on_send",       m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_connect()    { return {m_on_connect,    "on_connect",    m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_disconnect() { return {m_on_disconnect, "on_disconnect", m_deadline_ms, m_owner_name.c_str()}; }
    // on_route and on_master_auth were protected before the sweep — see
    // m_on_route below for the reasoning that the sweep then generalised.
    guarded_protected on_route()       { return {m_on_route,       "on_route",       m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_master_auth() { return {m_on_master_auth, "on_master_auth", m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_client_message() { return {m_on_client_message, "on_client_message", m_deadline_ms, m_owner_name.c_str()}; }

    // ─── The same two, for the coroutine path ───────────────────────────────
    // Handed over raw because a suspendable invocation arms a deadline around
    // each RESUME, and the guarded wrapper arms one around a call that returns
    // exactly once.
    sol::protected_function& raw_on_message()        { return m_on_message; }
    sol::protected_function& raw_on_client_message() { return m_on_client_message; }
    sol::protected_function& raw_on_messages()        { return m_on_messages; }
    sol::protected_function& raw_on_client_messages() { return m_on_client_messages; }
    guarded_protected on_writable()   { return {m_on_writable,   "on_writable",   m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_http_body()  { return {m_on_http_body,  "on_http_body",  m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_upstream_writable() { return {m_on_upstream_writable, "on_upstream_writable", m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_tick()       { return {m_on_tick,       "on_tick",       m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_miss()       { return {m_on_miss,       "on_miss",       m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_write()      { return {m_on_write,      "on_write",      m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_delete_cb()  { return {m_on_delete,     "on_delete",     m_deadline_ms, m_owner_name.c_str()}; }  // avoid clash with std::delete
    guarded_protected on_expire()     { return {m_on_expire,     "on_expire",     m_deadline_ms, m_owner_name.c_str()}; }
    // The callback that decides whether a client is served at all, so a raised
    // deadline reaches invoke_on_auth's !valid() branch and fails closed
    // rather than vanishing.
    guarded_protected on_auth()       { return {m_on_auth,       "on_auth",       m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_websocket()  { return {m_on_websocket,  "on_websocket",  m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_proxy_request()  { return {m_on_proxy_request,  "on_proxy_request",  m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_proxy_response() { return {m_on_proxy_response, "on_proxy_response", m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_cluster_join()  { return {m_on_cluster_join,  "on_cluster_join",  m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_cluster_leave() { return {m_on_cluster_leave, "on_cluster_leave", m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_group_change()  { return {m_on_group_change,  "on_group_change",  m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_upstream()            { return {m_on_upstream,            "on_upstream",            m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_upstream_connect()    { return {m_on_upstream_connect,    "on_upstream_connect",    m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_upstream_disconnect() { return {m_on_upstream_disconnect, "on_upstream_disconnect", m_deadline_ms, m_owner_name.c_str()}; }
    // A handler that raises has not declined; see m_on_http_request below.
    guarded_protected on_http_request()        { return {m_on_http_request,        "on_http_request",        m_deadline_ms, m_owner_name.c_str()}; }
    guarded_protected on_put()                 { return {m_on_put,                 "on_put",                 m_deadline_ms, m_owner_name.c_str()}; }
    // Handed over raw like on_message, because a storage runtime runs these on
    // a coroutine so that a hook which asks another runtime something can stop.
    sol::protected_function& raw_on_request()  { return m_on_request; }
    sol::protected_function& raw_on_put()      { return m_on_put; }
    sol::protected_function& raw_on_delete()   { return m_on_delete; }
    // An mqtt runtime's deciding hooks, run on a coroutine for the same reason.
    sol::protected_function& raw_on_auth()      { return m_on_auth; }
    sol::protected_function& raw_on_publish()   { return m_on_publish; }
    sol::protected_function& raw_on_subscribe() { return m_on_subscribe; }
    sol::protected_function& raw_on_rcpt()      { return m_on_rcpt; }
    sol::protected_function& raw_on_connect()   { return m_on_connect; }
    sol::protected_function& raw_on_disconnect() { return m_on_disconnect; }
    // The chain in the order the script listed it, handed back raw because the
    // caller arms one scope around the whole walk so ten filters share one
    // request's budget.
    const std::vector<sol::protected_function>& filters() const { return m_filters; }

    // What one invocation of a callback on this script may spend in ms, 0 when
    // the deadline is off, read by the filter chain.
    uint32_t callback_timeout_ms() const { return m_deadline_ms; }

    // What this script says it will answer, read by runtime_manager when it
    // builds the snapshot and by nothing else, because a declaration is data
    // rather than a callback.
    const route_table& declared_routes() const { return m_routes; }

    uint32_t get_tick_ms() const { return m_tick_ms; }

    // Cross-runtime pub/sub dispatch (called from runtime_instance)
    void dispatch_publish(std::string_view cache_name, std::string_view channel, std::string_view message);

    // This process holds no runtime manager and never will, a process fact set
    // once before anything is created, because a management call from a worker
    // has no honest answer.
    static void set_worker_process(bool on);
    static bool in_worker_process();

    // The cluster as seen by a process that cannot run discovery: set by the
    // worker when the daemon pushes a view, held by shared_ptr and swapped
    // wholesale, and while it is null the four cluster calls stay refused
    // rather than answering an empty table.
    void dispatch_cluster_event(const cluster_ev_wire& ev);

    static void set_cluster_view(cluster_view_ptr view);
    static cluster_view_ptr cluster_view_snapshot();

private:
    // Open LuaJIT's jit library wherever a runaway compiled trace can still be
    // ended, once, from the point where m_deadline_ms is final.
    void open_compiler();

    void register_bindings(runtime_instance* owner);

    // One load-time refusal into the daemon's log, naming this runtime, and
    // into the buffer the asking command reads back, which does not repeat the
    // name the operator just typed.
    void load_diag(const std::string& msg) const;

    // Overwrite the cross-runtime calls with a refusal that names them, called
    // only when in_worker_process().
    void refuse_cross_runtime_api(sol::table& sk, sol::table& cluster_tbl,
                                  runtime_instance* owner);
    void register_server_table(runtime_instance* owner, sol::table& self);
    void register_client_table(runtime_instance* owner, sol::table& self);
    void register_cache_table(runtime_instance* owner, sol::table& self);
    void register_proxy_table(runtime_instance* owner, sol::table& self);

    // The runtime this interpreter belongs to, by name, as a copy rather than
    // a pointer because timers and subscription fan-out report after the
    // context has been severed from its runtime.
    std::string m_owner_name;

    sol::state m_lua;

    // After m_lua, because a suspended thread belongs to that state and the
    // suspender's destructor unrefs it.
    std::unique_ptr<lua_suspender> m_suspend;
    sol::protected_function m_on_start;
    sol::protected_function m_on_stop;
    sol::protected_function m_on_message;
    sol::protected_function m_on_send;
    sol::protected_function m_on_connect;
    sol::protected_function m_on_disconnect;

    // protected_function, because a try/catch on sol::error is a bet on the
    // panic handler throwing and unwinding, and that bet loses in this
    // repository's Sanitize build -- and on_route in particular has to answer
    // as a value the routing path can act on.
    sol::protected_function m_on_route;

    // An auth hook that raises must deny AND say so; a hook whose error is
    // swallowed is indistinguishable from one that considered the request and
    // refused it, which is the whole defect this callback was just fixed for.
    sol::protected_function m_on_master_auth;
    sol::protected_function m_on_client_message;
    sol::protected_function m_on_messages;
    sol::protected_function m_on_client_messages;
    sol::protected_function m_on_writable;
    sol::protected_function m_on_http_body;
    sol::protected_function m_on_upstream_writable;
    sol::protected_function m_on_tick;
    sol::protected_function m_on_miss;
    sol::protected_function m_on_write;
    sol::protected_function m_on_delete;
    sol::protected_function m_on_expire;
    // The callback that decides whether a client is served at all, so a
    // failure has to arrive as a value rather than as an unwind the Sanitize
    // build swallows.
    sol::protected_function m_on_auth;
    sol::protected_function m_on_publish;
    sol::protected_function m_on_subscribe;
    sol::protected_function m_on_rcpt;
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
    // The last one across, because returning nil is documented as declining
    // and answering a raise the same way made a broken handler
    // indistinguishable from one that declined; the call site now answers 500
    // and says why.
    sol::protected_function m_on_http_request;

    // A storage runtime's hooks.  on_request decides whether a request goes on,
    // so it too has to arrive as a value -- a raise is a refusal, and says so.
    sol::protected_function m_on_request;
    sol::protected_function m_on_put;

    // What socketley.storage waits on, made when the bindings are and freed with
    // this context, which is after cancel_timers() has let go of its requests.
    std::unique_ptr<lua_storage_client> m_storage_client;
    // And what socketley.db waits on, alike.
    std::unique_ptr<lua_db_client> m_db_client;
    std::unique_ptr<lua_mqtt_client> m_mqtt_client;
    std::unique_ptr<lua_mail_client> m_mail_client;
    // And socketley.http's exchanges on the loop, for a callback that waits on one.
    std::unique_ptr<lua_http_client> m_http_client;

    // The `filters` chain as a vector because order is the whole point,
    // collected once at load time, and protected because a filter is where
    // authentication lives.
    std::vector<sol::protected_function> m_filters;

    // The `routes` declaration converted out of Lua once at load time, as a
    // plain C++ table because anything sent to another runtime cannot be a
    // reference into this state.
    route_table m_routes;

    uint32_t m_tick_ms{0};
    uint64_t m_callback_mask{0};

    // What one callback invocation may spend in ms, starting at the process
    // default so the top-level chunk is bounded too, and replaced by the
    // script's own `callback_timeout_ms` once the chunk has run.
    uint32_t m_deadline_ms{lua_deadline::default_ms()};

    // See set_worker_process(): written once at process start and read-only
    // afterwards, so a plain bool is what it means.
    static bool s_worker_process;

    // See set_cluster_view(): null in the daemon and in a worker whose daemon
    // has not published one.
    static cluster_view_ptr s_cluster_view;

    // Timer lifetime guard — set to false in destructor; timers check before firing
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};

    // Active timers — tracked so we can clear sol::function refs before Lua state closes
    std::vector<void*> m_active_timers;

public:
    void unregister_timer(void* t);
private:

    // One registration made by socketley.subscribe, with an id because
    // unsubscribe(cache_name, channel) cannot express dropping one of two
    // subscriptions to the same channel; ids start at 1.
    struct subscription
    {
        int                     id{0};
        sol::protected_function fn;
        // Marked by unsubscribe() while a dispatch is walking this channel and
        // compacted out when the outermost dispatch returns.
        bool                    dead{false};
    };

    // Cross-runtime pub/sub: key = cache_name + '\0' + channel
    std::unordered_map<std::string, std::vector<subscription>> m_subscriptions;

    // id to key, so unsubscribe() is one lookup rather than a walk, and a
    // stale id names nothing because ids are never reused.
    std::unordered_map<int, std::string> m_subscription_keys;
    int m_next_subscription_id{0};

    // Subscriptions made while a dispatch is in flight, applied when it ends,
    // because the vector being walked may not move.
    std::vector<std::pair<std::string, subscription>> m_pending_subscriptions;

    // How many dispatch_publish frames this context has on the stack, not a
    // bool because a subscriber may publish and a publish may come back here.
    unsigned m_dispatch_depth{0};

    // See registrations_severed(): raised by either severance and lowered by
    // start(), false here because reload_lua_script() builds a context on a
    // runtime that never stopped.
    bool m_severed{false};

    // Whether unsubscribe() marked anything while m_dispatch_depth was nonzero.
    bool m_subscriptions_dirty{false};

    // Apply the deferred insertions and remove the marked entries, when the
    // last dispatch frame unwinds or directly from unsubscribe().
    void settle_subscriptions();

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

#include "../http/route_table.h"
#include "../cluster/cluster_view.h"

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
    void cancel_subscriptions() {}
    bool registrations_severed() const { return false; }
    void allow_registrations() {}

    bool has_on_start()          const { return false; }
    bool has_on_stop()           const { return false; }
    bool has_on_message()        const { return false; }
    bool has_on_send()           const { return false; }
    bool has_on_connect()        const { return false; }
    bool has_on_disconnect()     const { return false; }
    bool has_on_route()          const { return false; }
    bool has_on_master_auth()    const { return false; }
    bool has_on_client_message() const { return false; }
    bool has_on_messages()       const { return false; }
    bool has_on_client_messages() const { return false; }
    bool has_on_writable()       const { return false; }
    bool has_on_http_body()      const { return false; }
    bool has_on_upstream_writable() const { return false; }
    bool has_on_tick()           const { return false; }
    bool has_on_miss()           const { return false; }
    bool has_on_write()          const { return false; }
    bool has_on_delete()         const { return false; }
    bool has_on_expire()         const { return false; }
    bool has_on_auth()           const { return false; }
    bool has_on_publish()        const { return false; }
    bool has_on_subscribe()      const { return false; }
    bool has_on_rcpt()           const { return false; }
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
    bool has_on_request()            const { return false; }
    bool has_on_put()                const { return false; }
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
    void dispatch_cluster_event(const cluster_ev_wire&) {}
    static void set_cluster_view(cluster_view_ptr) {}
    static cluster_view_ptr cluster_view_snapshot() { return {}; }
    static bool in_worker_process() { return false; }
    // on_*() callbacks omitted — only called when has_*() returns true,
    // and guarded by #ifndef SOCKETLEY_NO_LUA at each call site.
};

#endif // SOCKETLEY_NO_LUA
