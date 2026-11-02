#include "lua_context.h"
#include "../crypto/tls_context.h"
#include <strings.h>
#include "../net/resolve_cache.h"
#include "../http/http_framing.h"
#include "lua_json.h"
#include "../loop/coarse_clock.h"
#include "lua_suspend.h"
#include "lua_storage_api.h"
#include "lua_db_api.h"
#include "lua_mqtt_api.h"
#include "lua_mail_api.h"
#include "../../runtime/mqtt/mqtt_lua_table.h"
#include "../util/settings.h"

// Outside the SOCKETLEY_NO_LUA guard: the no-Lua SDK compiles this file too,
// and the callers that read a load failure back are not conditional on Lua.
namespace lua_diag
{
    // Thread-local, which is what makes this safe where a cerr swap is not,
    // because a CLI command runs on the daemon's own thread and each worker
    // has its own.
    static thread_local std::string s_text;

    void clear() { s_text.clear(); }
    const std::string& text() { return s_text; }

    void record(std::string_view line)
    {
        if (!s_text.empty()) s_text += '\n';
        s_text += line;
    }

    // The empty name is not an error case, because the daemon's configuration
    // file and the SOCKETLEY_LUA_TIMEOUT_MS parse belong to no runtime.
    std::string tag(std::string_view runtime_name)
    {
        std::string out("[lua");
        if (!runtime_name.empty())
        {
            out += ' ';
            out += runtime_name;
        }
        out += ']';
        return out;
    }
}

#ifndef SOCKETLEY_NO_LUA

void lua_diag::report_raise(const sol::protected_function_result& r, std::string_view owner, std::string_view hook,
                            std::string_view then)
{
    const sol::error e = r;
    std::cerr << tag(owner) << ' ' << hook << " error: " << e.what() << then << '\n';
}

#include "../runtime/runtime_instance.h"
#include "../runtime/runtime_definitions.h"
#include "../runtime/runtime_manager.h"
#include "../persist/state_persistence.h"
#include "../util/logging.h"
#include "../cluster/cluster_discovery.h"
#include "../loop/event_loop.h"
#include "../../runtime/server/server_instance.h"
#include "../../runtime/client/client_instance.h"
#include "../../runtime/proxy/proxy_instance.h"
#include "../../cli/command_hashing.h"
#include "../../cli/runtime_type_parser.h"
#include <iostream>
#include <algorithm>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <cerrno>
#include <charconv>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <system_error>
#include <thread>
#include <climits>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#ifndef SOCKETLEY_NO_HTTPS
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#endif

// ─── The callback deadline ──────────────────────────────────────────────────
// See lua_context.h for what this is and why it has this shape; what lives
// here is the state it is enforced through.
namespace lua_deadline
{
// How many VM instructions between hook calls, which is noise beside the
// interpreter itself -- the real cost of having a hook at all is the hooked
// dispatch path and the jit library it forbids, not this number.
static constexpr int hook_count = 10000;

// ── Which clock a callback budget is measured on ────────────────────────────
// The coarse one, because this is read on the hot path: every outermost
// callback invocation arms a deadline, so a server whose script answers each
// message reads the clock twice per message.  See shared/loop/coarse_clock.h for
// the numbers and for when it is the wrong clock.
using socketley::coarse_now;

// ── The armed invocation ────────────────────────────────────────────────────
// Thread-local and not per-interpreter, because the deadline protects one
// event loop, which makes nesting across interpreters work out on its own.
static thread_local unsigned                              t_depth{0};
static thread_local std::chrono::steady_clock::time_point t_deadline{};
static thread_local const char*                           t_what{nullptr};
// Which runtime's script the armed invocation belongs to, set and cleared
// beside t_what so the pairing cannot be got half right.
static thread_local const char*                           t_runtime{nullptr};
static thread_local uint32_t                              t_limit_ms{0};
// Whether this invocation has already been reported, because the hook raises
// every time it fires past the deadline and a script that pcalls its own
// runaway would otherwise fill the log.
static thread_local bool                                  t_reported{false};
// How many callback invocations are on this thread's stack, counted whether or
// not the deadline is armed, which t_depth deliberately does not answer.
static thread_local unsigned                              t_frames{0};

uint32_t default_ms()
{
    // Read once, because a parse per lua_context would run at every create for
    // nothing.
    static const uint32_t value = [] () -> uint32_t {
        const char* e = socketley::settings::text("SOCKETLEY_LUA_TIMEOUT_MS");
        if (!e || !*e)
            return builtin_default_ms;

        // Anything that is not a non-negative number is a typo in an
        // operator's unit file, and 0 is meaningful because it turns the
        // deadline off.
        char*     end = nullptr;
        long long v   = std::strtoll(e, &end, 10);
        if (end == e || *end != '\0' || v < 0 || v > 3600000)
        {
            std::cerr << "[lua] SOCKETLEY_LUA_TIMEOUT_MS=\"" << e
                      << "\" is not a millisecond count in 0..3600000; using "
                      << builtin_default_ms << std::endl;
            return builtin_default_ms;
        }
        return static_cast<uint32_t>(v);
    }();
    return value;
}

scope::scope(const char* what, uint32_t limit_ms, const char* runtime) noexcept
    : m_outermost(t_depth == 0 && limit_ms != 0)
    , m_first_frame(t_frames == 0)
{
    // Unconditional and reset at the boundary rather than decremented, because
    // stuck above zero here means nothing is ever freed on the spot again.
    ++t_frames;

    if (m_outermost)
    {
        t_deadline = coarse_now() + std::chrono::milliseconds(limit_ms);
        t_what     = what;
        t_runtime  = runtime;
        t_limit_ms = limit_ms;
        t_reported = false;
    }
    // Counted even when this scope did not arm, so an inner scope can never
    // disarm the outer one's deadline, while a scope constructed with the
    // deadline off neither arms nor counts.
    if (t_depth != 0 || m_outermost)
        ++t_depth;
}

scope::~scope() noexcept
{
    // The outermost scope resets rather than decrements, because a leaked
    // depth would leave the deadline armed and already expired for every
    // innocent callback after it.
    if (m_outermost)
    {
        t_depth    = 0;
        t_what     = nullptr;
        t_runtime  = nullptr;
        t_limit_ms = 0;
    }
    else if (t_depth != 0)
    {
        --t_depth;
    }

    // Same rule and reason on the frame count: the outermost frame knows the
    // stack is about to be empty and says so outright.
    if (m_first_frame)      t_frames = 0;
    else if (t_frames != 0) --t_frames;
}

bool in_callback() noexcept
{
    return t_frames != 0;
}

long remaining_ms() noexcept
{
    if (t_depth == 0)
        return -1;
    // The same clock the deadline was armed on, or the two would disagree by
    // however far apart they happen to be.
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                    t_deadline - coarse_now()).count();
    if (left < 0)          return 0;
    if (left > INT_MAX)    return INT_MAX;
    return static_cast<long>(left);
}

// The hook reports before it raises, and this line stays only for the path
// with nothing else -- a script that pcalls its own slow work -- with no C++
// object alive at the raise and the deadline deliberately left expired so a
// `while true do pcall(spin) end` still ends.
void check(lua_State* L)
{
    if (t_depth == 0)
        return;
    if (coarse_now() < t_deadline)
        return;

    const char*    what = t_what ? t_what : "a callback";
    const unsigned ms   = t_limit_ms;

    if (!t_reported)
    {
        t_reported = true;
        // Two formats rather than one built with lua_diag::tag(), because that
        // returns a std::string and nothing here may allocate when luaL_error
        // unwinds.
        if (t_runtime && *t_runtime)
            std::fprintf(stderr,
                         "[lua %s] %s hit its %ums deadline and was stopped\n",
                         t_runtime, what, ms);
        else
            std::fprintf(stderr, "[lua] %s hit its %ums deadline and was stopped\n",
                         what, ms);
        std::fflush(stderr);
    }

    // `what` carries the noun, so this reads as a sentence for a callback, for
    // the script's top level and for the daemon's configuration file alike.
    luaL_error(L, "%s exceeded the %ums deadline", what, ms);
}

static void hook(lua_State* L, lua_Debug*)
{
    check(L);
}

void install(lua_State* L, uint32_t limit_ms)
{
    if (limit_ms == 0)
    {
        // Off means off, down to not paying for it: with no count hook LuaJIT
        // compiles again.
        lua_sethook(L, nullptr, 0, 0);
        return;
    }
    lua_sethook(L, hook, LUA_MASKCOUNT, hook_count);
}

}  // namespace lua_deadline

void lua_context::install_deadline_hook()
{
    lua_deadline::install(m_lua.lua_state(), m_deadline_ms);
}

// The trace compiler is opened exactly when no hook is installed, because a
// compiled trace calls no hook back and the two are one decision -- and once
// only, from the point where m_deadline_ms is final, since there is no
// supported way back.
void lua_context::enable_jit_if_unbounded()
{
    if (m_deadline_ms != 0)
        return;

    // luaopen_jit is a module opener and leaves its table on the stack, so the
    // top is restored rather than a count popped, which is LuaJIT's to change.
    lua_State* L  = m_lua.lua_state();
    const int  top = lua_gettop(L);
    luaopen_jit(L);
    lua_settop(L, top);
}

lua_context::lua_context()
{
    // `jit` is left out deliberately, at a measured 5.2-5.5x on compute-shaped
    // scripts, because with the compiler on a runaway callback can no longer
    // be interrupted -- and neither sol::lib::jit nor luaJIT_setmode is a
    // narrower way in.
    m_lua.open_libraries(sol::lib::base, sol::lib::string, sol::lib::table,
                         sol::lib::math, sol::lib::os, sol::lib::io,
                         sol::lib::package);

    m_suspend = std::make_unique<lua_suspender>();

    // This is not a sandbox and says so: `io`, `package` and `base` are open,
    // so a Lua handler runs with the daemon's full privileges, and what stays
    // removed is only what one call can do to the whole process by accident --
    // os.exit ends the daemon.
    m_lua["os"]["exit"] = sol::nil;

    // os.setlocale is process-wide, so one script turns every other script's
    // JSON into something no parser accepts, and it is removed rather than
    // wrapped because nothing here needs to change how a number is spelled.
    m_lua["os"]["setlocale"] = sol::nil;

    install_deadline_hook();
}

// ─── lua_timer: heap-allocated one-shot / repeating timer via op_timeout ───
struct lua_timer : io_handler
{
    std::shared_ptr<bool> alive;
    sol::protected_function fn;
    event_loop*           loop{};
    lua_context*          ctx{};
    struct __kernel_timespec ts{};
    io_request            req{};
    bool                  repeat{false};
    bool                  cancelled{false};
    // True for exactly as long as `fn` is on the stack below, read by
    // sever_timer(), which must not replace a callable that is executing.
    bool                  dispatching{false};
    int                   timer_id{0};

    void on_cqe(struct io_uring_cqe* cqe) override
    {
        if (!*alive || cqe->res == -ECANCELED || cancelled)
        {
            // Out of the loop's owner table first: this object is about to be
            // pooled or freed, and a token left behind would let a later
            // completion be dispatched into whoever takes its place.
            if (loop) loop->deregister_owner(this);
            if (ctx) { ctx->unregister_timer(this); ctx->timer_pool_release(this); }
            else delete this;
            return;
        }
        // A timer body is a callback invocation like any other, spending the
        // budget of the context that registered it, with the scope bracketing
        // the call and nothing else.
        {
            lua_deadline::scope guard("a socketley.set_timeout/set_interval callback",
                                      ctx ? ctx->callback_timeout_ms() : 0u,
                                      ctx ? ctx->owner_name().c_str() : nullptr);
            // The flag brackets the call and nothing else, so sever_timer()
            // can tell that the timer it is asked to sever is the one
            // executing.
            dispatching = true;
            sol::protected_function_result tr = fn();
            dispatching = false;
            lua_diag::raised(tr, ctx ? std::string_view(ctx->owner_name()) : std::string_view{}, "timer");
        }
        if (repeat && *alive && !cancelled)
            loop->submit_timeout(&ts, &req);
        else
        {
            // Out of the loop's owner table first: this object is about to be
            // pooled or freed, and a token left behind would let a later
            // completion be dispatched into whoever takes its place.
            if (loop) loop->deregister_owner(this);
            if (ctx) { ctx->unregister_timer(this); ctx->timer_pool_release(this); }
            else delete this;
        }
    }
};

// ─── Severing one timer from its context ───────────────────────────────────
// The order is the reasoning -- function, then ctx, and never
// deregister_owner, which on_cqe does in the right place -- and the withdrawal
// at the end is what clear_timeout and clear_interval were missing, guarded on
// ring_open() because ~lua_context reaches this after shutdown_ring().
static void sever_timer(lua_timer* t)
{
    // Unless it is the callback doing the severing, in which case replacing
    // `fn` frees the object sol is still reading members of; skipping the
    // assignment costs nothing because on_cqe deletes the timer the moment it
    // returns.
    if (!t->dispatching)
        t->fn = sol::nil;

    t->ctx       = nullptr;
    t->cancelled = true;
    t->repeat    = false;

    if (t->loop && t->loop->ring_open())
        if (!t->loop->submit_timeout_remove(&t->req)) {}
}

lua_context::~lua_context()
{
    // An active timer outlives this context and is severed rather than freed,
    // `ctx` included -- leaving it pointing here made a reload's next tick
    // call two methods on freed memory -- while deregister_owner() is
    // deliberately left to on_cqe.
    cancel_timers();

    // Free all pooled timers, which are safe to delete outright because a
    // timer only reaches the pool from inside its own reported completion.
    for (auto* t : m_timer_pool)
        delete static_cast<lua_timer*>(t);
    m_timer_pool.clear();

    *m_alive = false;
}

void lua_context::unregister_timer(void* t)
{
    auto* timer = static_cast<lua_timer*>(t);
    if (timer->timer_id > 0)
        m_timer_map.erase(timer->timer_id);

    auto it = std::find(m_active_timers.begin(), m_active_timers.end(), t);
    if (it != m_active_timers.end())
    {
        *it = m_active_timers.back();
        m_active_timers.pop_back();
    }
}

void* lua_context::timer_pool_acquire()
{
    if (!m_timer_pool.empty())
    {
        auto* t = m_timer_pool.back();
        m_timer_pool.pop_back();
        return t;
    }
    return new lua_timer{};
}

// How many spent lua_timers this context keeps to hand back out, bounded at 64
// so the memory a script can hold this way is a function of its steady state
// rather than its peak.
static constexpr size_t timer_pool_max = 64;

void lua_context::timer_pool_release(void* t)
{
    auto* timer = static_cast<lua_timer*>(t);

    // Freed rather than pooled once the pool is full, safe in exactly the way
    // the pooling is, because this is only reached from inside the timer's own
    // reported completion.
    if (m_timer_pool.size() >= timer_pool_max)
    {
        delete timer;
        return;
    }

    timer->fn = sol::nil;
    timer->cancelled = false;
    timer->dispatching = false;
    timer->timer_id = 0;
    m_timer_pool.push_back(t);
}

// One load-time refusal, into the daemon's log and into the buffer the asking
// command reads back, which every `return false` in load_script and the two
// validators goes through.
void lua_context::load_diag(const std::string& msg) const
{
    std::cerr << lua_diag::tag(m_owner_name) << ' ' << msg << std::endl;
    lua_diag::record(msg);
}

// The same line from the management API, recorded as well as printed because a
// script's top level runs synchronously inside `create` and cmd_create reads
// the buffer back.
static void api_diag(runtime_instance* owner, const std::string& msg)
{
    std::cerr << lua_diag::tag(owner ? owner->get_name() : std::string_view{})
              << ' ' << msg << std::endl;
    lua_diag::record(msg);
}

// One return contract for everything a script asks for -- `true`, or `false,
// "<reason>"` -- which is Lua's own shape, changes behaviour only for a call
// in a function's last argument position, and is a variant of tuples rather
// than sol::variadic_results, whose vector cost 114 ns against sol2's whole
// marshalling layer's 15.
using api_yes_t   = std::tuple<bool>;
using api_why_t   = std::tuple<bool, std::string>;
using api_count_t = std::tuple<size_t>;
using api_str_t   = std::tuple<std::string>;
using api_obj_t   = std::tuple<sol::object>;
using api_result  = std::variant<api_yes_t, api_why_t, api_count_t,
                                 api_str_t, api_obj_t>;

static api_result api_yes()
{
    return api_yes_t{ true };
}

// The refusal, deliberately not logged, because these are control flow --
// stopping something already stopped is how an idempotent teardown is written
// -- while api_diag belongs to construction, which an operator has to see.
static api_result api_why(std::string why)
{
    return api_why_t{ false, std::move(why) };
}

// A count, for the two calls whose interesting answer is how many rather than
// whether.
static api_result api_count(size_t n)
{
    return api_count_t{ n };
}

// `"name"` — quoted, so an empty name or one carrying a space is visible in the
// sentence rather than vanishing into it.
static std::string q(std::string_view s)
{
    std::string out;
    out.reserve(s.size() + 2);
    out += '"';
    out += s;
    out += '"';
    return out;
}

bool lua_context::script_compiles(std::string_view path, std::string& err)
{
    lua_diag::clear();

    // Its own state with nothing registered on it, and load_file leaves the
    // chunk unexecuted, so no top-level line runs and none could reach
    // anything if it did.
    sol::state probe;
    sol::load_result chunk = probe.load_file(std::string(path));
    if (chunk.valid())
        return true;

    sol::error e = chunk;
    err = e.what();
    lua_diag::record(std::string("script error: ") + err);
    return false;
}

bool lua_context::load_script(std::string_view path, runtime_instance* owner)
{
    lua_diag::clear();
    register_bindings(owner);

    // Set package.path so require() resolves modules relative to the script's directory
    {
        std::string script_dir(path);
        auto slash = script_dir.rfind('/');
        if (slash != std::string::npos)
            script_dir.resize(slash);
        else
            script_dir = ".";

        sol::optional<std::string> current_path = m_lua["package"]["path"].get<sol::optional<std::string>>();
        std::string new_path = script_dir + "/?.lua;" + script_dir + "/?/init.lua";
        if (current_path && !current_path->empty())
        {
            new_path += ';';
            new_path += *current_path;
        }
        m_lua["package"]["path"] = new_path;
    }

    // The top-level chunk is bounded too, because it runs synchronously inside
    // `create` and used to freeze the daemon before the runtime existed --
    // against the process default, since the script's own global is set by
    // this very chunk.
    auto result = [&] {
        lua_deadline::scope guard("the script's top level", lua_deadline::default_ms(),
                                  m_owner_name.c_str());
        return m_lua.safe_script_file(std::string(path), sol::script_pass_on_error);
    }();
    if (!result.valid())
    {
        sol::error err = result;
        load_diag(std::string("script error: ") + err.what());
        return false;
    }

    // What this script asked for now that its top level has run, probed as a
    // sol::object first because the checked read cannot tell an absent key
    // from a present unreadable one, which need different answers.
    {
        sol::object cto = m_lua["callback_timeout_ms"];
        if (cto.valid() && cto != sol::nil)
        {
            const bool is_num = cto.get_type() == sol::type::number;
            const double ms = is_num ? cto.as<double>() : -1.0;
            if (!is_num || ms != std::floor(ms) || ms < 0.0 || ms > 4294967295.0)
            {
                load_diag("`callback_timeout_ms` must be a millisecond count of "
                          "0 or more (0 disables the callback deadline for this "
                          "script)");
                return false;
            }
            m_deadline_ms = static_cast<uint32_t>(ms);
            install_deadline_hook();
        }
    }

    // m_deadline_ms is final here in both branches, which is what makes this
    // the place to decide about the compiler, and it is outside the block so a
    // script that declares nothing is decided too.
    enable_jit_if_unbounded();

    m_on_start = m_lua["on_start"];
    m_on_stop = m_lua["on_stop"];
    m_on_message = m_lua["on_message"];
    m_on_send = m_lua["on_send"];
    m_on_connect = m_lua["on_connect"];
    m_on_disconnect = m_lua["on_disconnect"];
    m_on_route = m_lua["on_route"];
    m_on_master_auth = m_lua["on_master_auth"];
    m_on_client_message = m_lua["on_client_message"];
    m_on_writable       = m_lua["on_writable"];
    m_on_http_body      = m_lua["on_http_body"];
    m_on_upstream_writable = m_lua["on_upstream_writable"];
    m_on_tick = m_lua["on_tick"];
    // A tick_ms below the floor is refused rather than substituted, absent
    // still means 100, and the read is a double with an integrality test
    // because every Lua number is a double and the two builds do not agree
    // about conversions.
    if (m_on_tick.valid()) {
        sol::object t = m_lua["tick_ms"];
        if (!t.valid() || t == sol::nil)
        {
            m_tick_ms = lua_tick::default_ms;
        }
        else if (t.get_type() != sol::type::number ||
                 t.as<double>() != std::floor(t.as<double>()) ||
                 t.as<double>() < static_cast<double>(lua_tick::floor_ms) ||
                 t.as<double>() > 86400000.0)
        {
            load_diag("`tick_ms` must be a whole number of milliseconds, "
                      + std::to_string(lua_tick::floor_ms)
                      + " or more — the shortest interval on_tick can be armed at");
            return false;
        }
        else
        {
            m_tick_ms = static_cast<uint32_t>(t.as<double>());
        }
    }
    m_on_miss   = m_lua["on_miss"];
    m_on_write  = m_lua["on_write"];
    m_on_delete = m_lua["on_delete"];
    m_on_expire = m_lua["on_expire"];
    m_on_auth       = m_lua["on_auth"];
    m_on_websocket  = m_lua["on_websocket"];
    m_on_proxy_request  = m_lua["on_proxy_request"];
    m_on_proxy_response = m_lua["on_proxy_response"];
    m_on_cluster_join   = m_lua["on_cluster_join"];
    m_on_cluster_leave  = m_lua["on_cluster_leave"];
    m_on_group_change   = m_lua["on_group_change"];
    m_on_upstream           = m_lua["on_upstream"];
    m_on_upstream_connect   = m_lua["on_upstream_connect"];
    m_on_upstream_disconnect = m_lua["on_upstream_disconnect"];
    m_on_http_request       = m_lua["on_http_request"];
    m_on_request            = m_lua["on_request"];
    m_on_put                = m_lua["on_put"];
    m_on_publish            = m_lua["on_publish"];
    m_on_subscribe          = m_lua["on_subscribe"];
    m_on_rcpt               = m_lua["on_rcpt"];

    // Build callback bitmask for O(1) has_on_*() checks
    m_callback_mask = 0;
    if (m_on_start.valid())              m_callback_mask |= CB_ON_START;
    if (m_on_stop.valid())               m_callback_mask |= CB_ON_STOP;
    if (m_on_message.valid())            m_callback_mask |= CB_ON_MESSAGE;
    if (m_on_send.valid())               m_callback_mask |= CB_ON_SEND;
    if (m_on_connect.valid())            m_callback_mask |= CB_ON_CONNECT;
    if (m_on_disconnect.valid())         m_callback_mask |= CB_ON_DISCONNECT;
    if (m_on_route.valid())              m_callback_mask |= CB_ON_ROUTE;
    if (m_on_master_auth.valid())        m_callback_mask |= CB_ON_MASTER_AUTH;
    if (m_on_client_message.valid())     m_callback_mask |= CB_ON_CLIENT_MESSAGE;
    if (m_on_writable.valid())           m_callback_mask |= CB_ON_WRITABLE;
    if (m_on_http_body.valid())          m_callback_mask |= CB_ON_HTTP_BODY;
    if (m_on_upstream_writable.valid())  m_callback_mask |= CB_ON_UPSTREAM_WRITABLE;
    if (m_on_tick.valid())               m_callback_mask |= CB_ON_TICK;
    if (m_on_miss.valid())               m_callback_mask |= CB_ON_MISS;
    if (m_on_write.valid())              m_callback_mask |= CB_ON_WRITE;
    if (m_on_delete.valid())             m_callback_mask |= CB_ON_DELETE;
    if (m_on_expire.valid())             m_callback_mask |= CB_ON_EXPIRE;
    if (m_on_auth.valid())               m_callback_mask |= CB_ON_AUTH;
    if (m_on_websocket.valid())          m_callback_mask |= CB_ON_WEBSOCKET;
    if (m_on_proxy_request.valid())      m_callback_mask |= CB_ON_PROXY_REQUEST;
    if (m_on_proxy_response.valid())     m_callback_mask |= CB_ON_PROXY_RESPONSE;
    if (m_on_cluster_join.valid())       m_callback_mask |= CB_ON_CLUSTER_JOIN;
    if (m_on_cluster_leave.valid())      m_callback_mask |= CB_ON_CLUSTER_LEAVE;
    if (m_on_group_change.valid())       m_callback_mask |= CB_ON_GROUP_CHANGE;
    if (m_on_upstream.valid())           m_callback_mask |= CB_ON_UPSTREAM;
    if (m_on_upstream_connect.valid())   m_callback_mask |= CB_ON_UPSTREAM_CONNECT;
    if (m_on_upstream_disconnect.valid()) m_callback_mask |= CB_ON_UPSTREAM_DISCONNECT;
    if (m_on_http_request.valid())       m_callback_mask |= CB_ON_HTTP_REQUEST;
    if (m_on_request.valid())            m_callback_mask |= CB_ON_REQUEST;
    if (m_on_put.valid())                m_callback_mask |= CB_ON_PUT;
    if (m_on_publish.valid())            m_callback_mask |= CB_ON_PUBLISH;
    if (m_on_subscribe.valid())          m_callback_mask |= CB_ON_SUBSCRIBE;
    if (m_on_rcpt.valid())               m_callback_mask |= CB_ON_RCPT;

    // The filter chain, where a malformed entry refuses the script rather than
    // being skipped, because a quietly dropped filter is a runtime that admits
    // everyone while looking like one that does not.
    m_filters.clear();
    {
        sol::object fobj = m_lua["filters"];
        if (fobj.valid() && fobj != sol::nil)
        {
            if (!fobj.is<sol::table>())
            {
                load_diag("`filters` must be a table of functions");
                return false;
            }
            sol::table ft = fobj.as<sol::table>();
            // The array part only, and stopping at the first hole: a chain with
            // a gap in it has an order nobody can state, which is the one thing
            // a chain has to have.
            for (size_t i = 1;; ++i)
            {
                sol::object entry = ft[i];
                if (!entry.valid() || entry == sol::nil)
                    break;
                if (!entry.is<sol::function>())
                {
                    load_diag("filters[" + std::to_string(i) + "] is not a function");
                    return false;
                }
                m_filters.push_back(entry.as<sol::protected_function>());
            }
            if (m_filters.empty())
            {
                // `filters = { auth = f }` reads like a registration and is
                // silently nothing, while an empty table is a legitimate way
                // to say no filters.
                bool any = false;
                ft.for_each([&](sol::object, sol::object) { any = true; });
                if (any)
                {
                    load_diag("`filters` has no entry at index 1 — a chain is "
                              "an ordered array, not a keyed table");
                    return false;
                }
            }
        }
    }
    if (!m_filters.empty()) m_callback_mask |= CB_FILTERS;

    // The route declaration, an array of { path, methods }, where a malformed
    // entry refuses the script because a dropped declaration fails open and
    // neither side can see that the published routes are not the written ones.
    m_routes.clear();
    {
        sol::object robj = m_lua["routes"];
        if (robj.valid() && robj != sol::nil)
        {
            if (!robj.is<sol::table>())
            {
                load_diag("`routes` must be a table of { path, methods } entries");
                return false;
            }
            sol::table rt = robj.as<sol::table>();
            for (size_t i = 1;; ++i)
            {
                sol::object entry = rt[i];
                if (!entry.valid() || entry == sol::nil)
                    break;
                if (!entry.is<sol::table>())
                {
                    load_diag("routes[" + std::to_string(i) + "] is not a table");
                    return false;
                }
                sol::table e = entry.as<sol::table>();

                sol::optional<std::string> path = e["path"].get<sol::optional<std::string>>();
                if (!path)
                {
                    load_diag("routes[" + std::to_string(i) + "] has no `path`");
                    return false;
                }

                // A single string is accepted where a table of one is meant,
                // because `methods = "POST"` is what everyone writes first.
                std::vector<std::string> methods;
                sol::object mobj = e["methods"];
                if (mobj.valid() && mobj.is<std::string>())
                {
                    methods.push_back(mobj.as<std::string>());
                }
                else if (mobj.valid() && mobj.is<sol::table>())
                {
                    sol::table mt = mobj.as<sol::table>();
                    for (size_t j = 1;; ++j)
                    {
                        sol::object m = mt[j];
                        if (!m.valid() || m == sol::nil)
                            break;
                        if (!m.is<std::string>())
                        {
                            load_diag("routes[" + std::to_string(i) + "].methods["
                                      + std::to_string(j) + "] is not a string");
                            return false;
                        }
                        methods.push_back(m.as<std::string>());
                    }
                }
                else
                {
                    load_diag("routes[" + std::to_string(i) + "] (" + *path
                              + ") has no `methods` list — a route that named no method "
                                "would refuse every request at the edge");
                    return false;
                }

                const char* why = nullptr;
                switch (m_routes.add(*path, methods))
                {
                    case route_table::add_result::ok:         break;
                    case route_table::add_result::bad_path:
                        why = "`path` must start with '/' and carry no space, query or fragment";
                        break;
                    case route_table::add_result::bad_method:
                        why = "`methods` must be a non-empty list of method tokens";
                        break;
                    case route_table::add_result::too_many:
                        why = "too many routes or methods for one declaration";
                        break;
                    case route_table::add_result::duplicate:
                        why = "this path is declared twice — the second would be ignored";
                        break;
                }
                if (why)
                {
                    load_diag("routes[" + std::to_string(i) + "] (" + *path + "): " + why);
                    return false;
                }
            }

            if (m_routes.empty())
            {
                // Same trap as `filters`: a keyed table reads like a
                // declaration and is silently nothing, while an empty table
                // means declare nothing.
                bool any = false;
                rt.for_each([&](sol::object, sol::object) { any = true; });
                if (any)
                {
                    load_diag("`routes` has no entry at index 1 — it is an array "
                              "of { path = ..., methods = { ... } }, not a keyed table");
                    return false;
                }
            }
        }
    }
    if (!m_routes.empty()) m_callback_mask |= CB_ROUTES;

    return true;
}

void lua_context::dispatch_publish(std::string_view cache_name, std::string_view channel, std::string_view message)
{
    thread_local std::string key_buf;
    key_buf.clear();
    key_buf.reserve(cache_name.size() + 1 + channel.size());
    key_buf.append(cache_name);
    key_buf.push_back('\0');
    key_buf.append(channel);
    auto it = m_subscriptions.find(key_buf);
    if (it == m_subscriptions.end()) return;

    // ─── Nothing may move under this loop ───────────────────────────────────
    // Both directions are deferred rather than guarded against, because a
    // subscriber may subscribe or unsubscribe from inside a handler, which
    // makes the vector immutable for the whole dispatch and settles what a new
    // registration receives.
    auto&        subs = it->second;
    const size_t n    = subs.size();

    // One scope for the whole fan-out, because a publish made from inside
    // another callback spends the publisher's budget, which does not return
    // until the last subscriber has run.
    ++m_dispatch_depth;
    {
        lua_deadline::scope guard("a socketley.subscribe callback", m_deadline_ms,
                                  m_owner_name.c_str());
        for (size_t i = 0; i < n; ++i)
        {
            if (subs[i].dead) continue;
            sol::protected_function_result r = subs[i].fn(channel, message);
            lua_diag::raised(r, m_owner_name, "subscribe callback");
        }
    }
    if (--m_dispatch_depth == 0)
        settle_subscriptions();
}

// Called at the moment it is safe to move the vectors dispatch_publish walks,
// which is when the last of its frames has unwound.
void lua_context::settle_subscriptions()
{
    for (auto& [key, sub] : m_pending_subscriptions)
        m_subscriptions[key].push_back(std::move(sub));
    m_pending_subscriptions.clear();

    if (!m_subscriptions_dirty)
        return;

    for (auto it = m_subscriptions.begin(); it != m_subscriptions.end(); )
    {
        auto& v = it->second;
        v.erase(std::remove_if(v.begin(), v.end(),
                               [](const subscription& s) { return s.dead; }),
                v.end());
        // A channel nobody listens to comes out of the map rather than staying
        // an empty vector a lookup answers on every publish.
        if (v.empty()) it = m_subscriptions.erase(it);
        else           ++it;
    }
    m_subscriptions_dirty = false;
}

// End every subscription this context holds while leaving it alive, because a
// stopped runtime must execute no script, deferred exactly as unsubscribe() is
// since `socketley.stop(self.name)` from a subscriber holds a reference into
// the map below.
void lua_context::cancel_subscriptions()
{
    // Up before anything is torn down and until start() lowers it, because
    // severing what is armed does not stop the calling script arming more.
    m_severed = true;

    // Nothing is walking the pending queue, so these go outright: settling
    // them would install subscribers on a runtime that has gone.
    m_pending_subscriptions.clear();
    m_subscription_keys.clear();

    if (m_dispatch_depth != 0)
    {
        for (auto& [key, v] : m_subscriptions)
            for (auto& s : v)
                s.dead = true;
        m_subscriptions_dirty = true;
        return;
    }

    m_subscriptions.clear();
    m_subscriptions_dirty = false;
}

// Sever every armed timer while leaving the context alive, split out of the
// destructor so `stop` can reach it, clearing both containers because what is
// left would name timers this context has given away.
void lua_context::cancel_timers()
{
    // The same latch, raised by both severances because they are called
    // together and answer the same sentence.
    m_severed = true;

    for (auto* p : m_active_timers)
        sever_timer(static_cast<lua_timer*>(p));
    m_active_timers.clear();

    // The timer ids too, because every one has just been handed to its own
    // completion and a surviving lookup would find a pointer with nothing left
    // to say.
    m_timer_map.clear();

    // A handler stopped on an await is let go rather than answered here: this
    // is the path a runtime takes when it must execute no more script, and
    // resuming one would run the rest of a callback against a runtime that is
    // already coming down.  Everywhere else an await ends in an answer.
    if (m_suspend)
        m_suspend->forget_all();

    // And the storage calls it was owed answers to, for the same reason.
    if (m_storage_client)
        m_storage_client->cancel();
    if (m_db_client)
        m_db_client->cancel();
    if (m_mqtt_client)
        m_mqtt_client->cancel();
    if (m_mail_client)
        m_mail_client->cancel();
}

void lua_context::update_self_state(const char* state_str)
{
    sol::optional<sol::table> self = m_lua["self"].get<sol::optional<sol::table>>();
    if (self)
        (*self)["state"] = state_str;
}

// ---------------------------------------------------------------------------
// socketley.http is a synchronous client that verifies the chain and the host
// name, still blocks the event-loop thread, and is bounded by one deadline
// clamped to what is left of the callback's budget, name resolution included.
// ---------------------------------------------------------------------------

using http_clock = std::chrono::steady_clock;

// The first address of host:port, asked on a thread of its own and waited for until `deadline`: getaddrinfo() has no
// bound of its own, and a resolver that does not answer held the loop through its every retry. The thread finishes on
// its own when the wait gave up, into state it shares, so nothing is left pointing at this frame.
static bool resolve_within(const std::string& host, const char* port, http_clock::time_point deadline,
                           socketley::resolve_cache::entry& out, std::string& why)
{
    struct state
    {
        std::mutex mu;
        std::condition_variable cv;
        bool done{false};
        int rc{EAI_FAIL};
        socketley::resolve_cache::entry peer{};
        bool fits{true};
    };
    // Threads left behind by lookups that were given up on, capped so a script calling a dead resolver in a loop
    // cannot pile them up.
    static std::atomic<int> outstanding{0};
    if (outstanding.fetch_add(1, std::memory_order_relaxed) >= 8)
    {
        outstanding.fetch_sub(1, std::memory_order_relaxed);
        why = "DNS resolution failed for: " + host + " (eight lookups already waiting on the resolver)";
        return false;
    }
    auto st = std::make_shared<state>();
    try
    {
        std::thread([st, host, port = std::string(port)] {
            struct addrinfo hints{}, *addrs = nullptr;
            hints.ai_family   = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            const int rc = getaddrinfo(host.c_str(), port.c_str(), &hints, &addrs);
            std::lock_guard<std::mutex> lk(st->mu);
            st->rc = rc == 0 && !addrs ? EAI_FAIL : rc;
            // The first entry, its length checked before the copy, since it decides how much is written.
            if (rc == 0 && addrs)
            {
                st->fits = addrs->ai_addrlen <= sizeof(st->peer.addr);
                if (st->fits)
                {
                    std::memcpy(&st->peer.addr, addrs->ai_addr, addrs->ai_addrlen);
                    st->peer.len    = addrs->ai_addrlen;
                    st->peer.family = addrs->ai_family;
                }
            }
            if (addrs)
                freeaddrinfo(addrs);
            st->done = true;
            st->cv.notify_one();
            outstanding.fetch_sub(1, std::memory_order_relaxed);
        }).detach();
    }
    catch (const std::system_error&)
    {
        outstanding.fetch_sub(1, std::memory_order_relaxed);
        why = "DNS resolution failed for: " + host + " (no thread to ask on)";
        return false;
    }
    std::unique_lock<std::mutex> lk(st->mu);
    if (!st->cv.wait_until(lk, deadline, [&] { return st->done; }))
    {
        why = "DNS resolution for " + host + " took longer than the request's deadline";
        return false;
    }
    if (st->rc != 0)
    {
        why = "DNS resolution failed for: " + host;
        return false;
    }
    if (!st->fits)
    {
        why = "DNS returned an address too large for: " + host;
        return false;
    }
    out = st->peer;
    return true;
}


// How long a resolved address is reused before asking again.  A ceiling and
// not a promise: a connect that fails drops the entry at once, so this only
// decides how long an endpoint that moved WITHOUT refusing stays wrong -- the
// case where something else answers on the old address.  libcurl's own DNS
// cache defaults to the same minute.
inline constexpr std::chrono::milliseconds http_resolve_default{60000};

// Read once, because neither the environment nor this process's mind changes
// under it, and 0 is a real answer: it disables the cache, which is also the
// A/B switch -- one binary, one workload, only the reuse differing.
static std::chrono::milliseconds http_resolve_lifetime()
{
    static const std::chrono::milliseconds ms = [] {
        const char* e = socketley::settings::text("SOCKETLEY_DNS_CACHE_MS");
        if (!e || !*e)
            return http_resolve_default;
        char* end = nullptr;
        const long v = std::strtol(e, &end, 10);
        if (end == e || *end != '\0' || v < 0)
            return http_resolve_default;
        return std::chrono::milliseconds{v};
    }();
    return ms;
}

// Milliseconds left before `deadline`, never negative.
static int http_ms_left(http_clock::time_point deadline)
{
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - http_clock::now()).count();
    if (left <= 0)       return 0;
    if (left > INT_MAX)  return INT_MAX;
    return static_cast<int>(left);
}

// Wait for `fd` to become ready for `events` or for the deadline, answering 1
// ready, 0 out of time, -1 failed.
static int http_wait(int fd, short events, http_clock::time_point deadline)
{
    for (;;)
    {
        int left = http_ms_left(deadline);
        if (left <= 0)
            return 0;

        struct pollfd p{};
        p.fd     = fd;
        p.events = events;

        int r = ::poll(&p, 1, left);
        if (r > 0)  return 1;
        if (r == 0) return 0;
        if (errno == EINTR)
            continue;      // a signal is not a timeout; the deadline decides
        return -1;
    }
}

// Ceiling on what one response may accumulate, because a hostile endpoint
// could otherwise grow this string until the allocator gave up and took the
// daemon with it.
static constexpr size_t http_max_response = 8u * 1024u * 1024u;

#ifndef SOCKETLEY_NO_HTTPS
// Drain OpenSSL's thread-local error queue into readable text, or the reason
// is lost and a stale entry is later reported as the cause of an unrelated
// failure.
static std::string ssl_error_text()
{
    std::string out;
    char buf[256];
    for (unsigned long e = ERR_get_error(); e != 0; e = ERR_get_error())
    {
        ERR_error_string_n(e, buf, sizeof(buf));
        if (!out.empty())
            out += "; ";
        out += buf;
    }
    return out;
}
#endif

static sol::table socketley_http_call(sol::state& lua, sol::table opts)
{
    sol::table result = lua.create_table();
    result["ok"]     = false;
    result["status"] = 0;
    result["body"]   = std::string{};
    result["error"]  = std::string{};

    // A pointer key: gcc folds sol2's literal-key getters of two lengths into one and warns of a bound none crosses.
    sol::optional<std::string> url_opt = opts.get<sol::optional<std::string>>(static_cast<const char*>("url"));
    if (!url_opt || url_opt->empty()) { result["error"] = "url required"; return result; }

    // ─── The three optional keys, checked ───────────────────────────────────
    // Checked reads rather than a converting optional, because whether a
    // conversion throws is a property of the build, and a `timeout_ms` that
    // was written down and unreadable is reported through result.error rather
    // than silently defaulted.
    std::string url = *url_opt;

    std::string method = "GET";
    if (sol::object o = opts["method"]; o.valid() && o != sol::nil)
    {
        if (o.get_type() != sol::type::string)
        {
            result["error"] = "method must be a string";
            return result;
        }
        method = o.as<std::string>();
    }

    // Asked case-insensitively, because nothing here upper-cases `method`.
    const bool is_head = (method.size() == 4 &&
                          strncasecmp(method.c_str(), "HEAD", 4) == 0);

    std::string body;
    if (sol::object o = opts["body"]; o.valid() && o != sol::nil)
    {
        if (o.get_type() != sol::type::string)
        {
            result["error"] = "body must be a string";
            return result;
        }
        body = o.as<std::string>();
    }

    int timeout_ms = 5000;
    if (sol::object o = opts["timeout_ms"]; o.valid() && o != sol::nil)
    {
        const double d = (o.get_type() == sol::type::number) ? o.as<double>() : -1.0;
        if (o.get_type() != sol::type::number || d != std::floor(d) ||
            d < 1.0 || d > 3600000.0)
        {
            result["error"] = "timeout_ms must be a whole number of "
                              "milliseconds in 1..3600000";
            return result;
        }
        timeout_ms = static_cast<int>(d);
    }

    // The fourth of the optional keys, checked here with the other three and
    // not at the point of use.  A converting optional cannot tell "not given"
    // from "given as the wrong thing", so headers = "Content-Type: text/plain"
    // -- a string where the man page documents a table -- was dropped in
    // silence and the request went without it.
    //
    // Before the socket, the resolver and the TLS context, because a refusal
    // down there has three things to unwind and this one has none.
    sol::optional<sol::table> hdrs;
    if (sol::object o = opts["headers"]; o.valid() && o != sol::nil)
    {
        if (o.get_type() != sol::type::table)
        {
            result["error"] = "headers must be a table of string keys and "
                              "string values";
            return result;
        }
        hdrs = o.as<sol::table>();
    }

    // Inside the callback's budget and not beside it, with remaining_ms() of
    // -1 leaving timeout_ms as the script wrote it.
    {
        const long budget = lua_deadline::remaining_ms();
        if (budget == 0)
        {
            // Named rather than reported as a connect timeout: the request has
            // not been attempted, and "timed out" would send whoever reads it
            // to look at the wrong host.
            result["error"] = "no time left in this callback's deadline "
                              "(callback_timeout_ms) to make the request";
            return result;
        }
        if (budget > 0 && budget < timeout_ms)
            timeout_ms = static_cast<int>(budget);
    }

    // One deadline for the whole exchange, taken before anything can block, so
    // the total hold is timeout_ms plus the resolver rather than timeout_ms
    // per operation.
    const auto deadline = http_clock::now() + std::chrono::milliseconds(timeout_ms);

    // Parse scheme
    bool is_https = false;
    if (url.rfind("https://", 0) == 0)      { is_https = true;  url = url.substr(8); }
    else if (url.rfind("http://", 0) == 0)  {                   url = url.substr(7); }
    else { result["error"] = "unsupported scheme (use http:// or https://)"; return result; }

#ifdef SOCKETLEY_NO_HTTPS
    if (is_https) {
        // What is missing is a build, so that is what this says -- the wording
        // it replaced handed the caller a shell running with the daemon's
        // privileges.
        result["error"] = "HTTPS not supported in this build (compiled with "
                          "SOCKETLEY_NO_HTTPS); use http://, or rebuild with "
                          "TLS support";
        return result;
    }
#endif

    // The last colon is not the port separator, because an IPv6 literal is
    // full of them, so two forms come out of this: `host` without brackets for
    // the resolver and the verifier, and `host_header` with them.
    int port = is_https ? 443 : 80;
    std::string host, host_header, path;
    {
        auto slash = url.find('/');
        std::string authority = (slash != std::string::npos) ? url.substr(0, slash) : url;
        path = (slash != std::string::npos) ? url.substr(slash) : "/";

        std::string_view port_str;
        if (!authority.empty() && authority.front() == '[')
        {
            auto rbracket = authority.find(']');
            if (rbracket == std::string::npos) {
                result["error"] = "malformed url: '[' with no matching ']'";
                return result;
            }
            host = authority.substr(1, rbracket - 1);
            if (rbracket + 1 < authority.size())
            {
                if (authority[rbracket + 1] != ':') {
                    result["error"] = "malformed url: expected ':port' after ']'";
                    return result;
                }
                port_str = std::string_view(authority).substr(rbracket + 2);
            }
        }
        else
        {
            auto colon = authority.rfind(':');
            // Exactly one colon is a port, and more than one without brackets
            // is an IPv6 literal that must not be silently cut in half.
            if (colon != std::string::npos && authority.find(':') == colon)
            {
                host     = authority.substr(0, colon);
                port_str = std::string_view(authority).substr(colon + 1);
            }
            else
                host = authority;
        }

        if (host.empty()) { result["error"] = "url has no host"; return result; }

        if (!port_str.empty())
        {
            // A port that does not parse used to leave the default in place and
            // quietly talk to the wrong service.
            int parsed = 0;
            auto [ptr, ec] = std::from_chars(port_str.data(),
                                             port_str.data() + port_str.size(), parsed);
            if (ec != std::errc{} || ptr != port_str.data() + port_str.size() ||
                parsed < 1 || parsed > 65535)
            {
                result["error"] = "invalid port in url: " + std::string(port_str);
                return result;
            }
            port = parsed;
        }

        host_header = (host.find(':') != std::string::npos) ? "[" + host + "]" : host;
    }

    char port_buf[8];
    auto port_res = std::to_chars(port_buf, port_buf + sizeof(port_buf), port);
    *port_res.ptr = '\0';

    // Resolved once per host:port and then reused, because this call used to
    // ask on every request -- the one resolver in this tree with no bound at
    // all, on the thread the event loop runs on, and the note above this
    // function admits neither the deadline nor the callback budget reaches it.
    //
    // thread_local rather than a file-scope object: nothing here takes a lock,
    // and a cache two threads could reach would be a race rather than a
    // saving.  One Lua VM runs on one thread, so this is one cache per VM.
    thread_local socketley::resolve_cache dns_cache(http_resolve_lifetime());
    const bool reuse = http_resolve_lifetime().count() > 0;

    std::string dns_key;
    dns_key.reserve(host.size() + 8);
    dns_key.append(host);
    dns_key.push_back(':');
    dns_key.append(port_buf);

    socketley::resolve_cache::entry peer;
    if (!reuse || !dns_cache.get(dns_key, peer))
    {
        std::string why;
        if (!resolve_within(host, port_buf, deadline, peer, why)) {
            result["error"] = why;
            return result;
        }
        if (reuse)
            dns_cache.put(dns_key, peer);
    }

    // Non-blocking socket plus poll() and not SO_SNDTIMEO, which does not
    // bound connect() on Linux at all, and the socket stays non-blocking so
    // every later wait goes through the same deadline.
    int sock = ::socket(peer.family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sock < 0) { result["error"] = "socket() failed"; return result; }

    if (::connect(sock, reinterpret_cast<const sockaddr*>(&peer.addr), peer.len) != 0)
    {
        if (errno != EINPROGRESS)
        {
            // An address that will not take a connection is not one to keep,
            // so the next call asks again instead of waiting out the lifetime.
            dns_cache.drop(dns_key);
            ::close(sock);
            result["error"] = std::string("connect() failed: ") + std::strerror(errno);
            return result;
        }

        int ready  = http_wait(sock, POLLOUT, deadline);
        int so_err = 0;
        if (ready == 1)
        {
            // Writable only means the attempt finished, and a refused
            // connection reports readiness while hiding ECONNREFUSED in
            // SO_ERROR.
            socklen_t so_len = sizeof(so_err);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &so_len) != 0)
                so_err = errno;
        }
        if (ready != 1 || so_err != 0)
        {
            // Including the timeout: a cached address that stopped answering
            // is exactly the endpoint that moved, which is what this drops for.
            dns_cache.drop(dns_key);
            ::close(sock);
            result["error"] = (ready == 0)
                ? std::string("connect timed out after ") + std::to_string(timeout_ms) + "ms"
                : std::string("connect() failed: ") + std::strerror(so_err ? so_err : errno);
            return result;
        }
    }

    // A method, a path or a header the script made from what someone sent it would otherwise write lines of their
    // choosing into the request; one that cannot go out as given is refused, not sent altered.
    bool fields_ok = http_field_name_ok(method) && !path.empty() &&
                     path.find_first_of(std::string_view(" \r\n\0", 4)) == std::string_view::npos;
    if (hdrs)
        (*hdrs).for_each([&](sol::object k, sol::object v) {
            if (!k.is<std::string>() || !v.is<std::string>() ||
                !http_field_name_ok(k.as<std::string>()) || !http_field_value_ok(v.as<std::string>()))
                fields_ok = false;
        });
    if (!fields_ok)
    {
        ::close(sock);
        result["error"] = std::string("the method, the path or a header holds what cannot go out as one line");
        return result;
    }

    // Build HTTP/1.0 request
    std::string req;
    req.reserve(256 + body.size());
    req.append(method);
    req.append(" ");
    req.append(path);
    req.append(" HTTP/1.0\r\n");
    req.append("Host: ");
    req.append(host_header);
    req.append("\r\n");
    if (!body.empty())
    {
        char cl_buf[24];
        auto cl_res = std::to_chars(cl_buf, cl_buf + sizeof(cl_buf), body.size());
        req.append("Content-Length: ");
        req.append(cl_buf, static_cast<size_t>(cl_res.ptr - cl_buf));
        req.append("\r\n");
    }
    if (hdrs) {
        (*hdrs).for_each([&](sol::object k, sol::object v) {
            if (k.is<std::string>() && v.is<std::string>())
            {
                req.append(k.as<std::string>());
                req.append(": ");
                req.append(v.as<std::string>());
                req.append("\r\n");
            }
        });
    }
    req.append("Connection: close\r\n\r\n");
    req.append(body);

    // Both directions are poll-driven against the shared deadline, because
    // socket timeouts restart on every byte and a peer sending one a second
    // never times out.
    std::string response;
    std::string xfer_err;

    // The framing decision is http_framing.h's, which the proxy already reads
    // its backends with and which fuzz_http_response drives.  The first
    // version of this was a parser of its own written here -- it missed
    // "Content-Length : 5", took the first of two that disagree where RFC 9112
    // Section 6.3 says the message is unrecoverable, and framed no chunked
    // body at all.  Every one of those is a question this header had already
    // answered.
    //
    // A HEAD reply quotes the length its GET would have had and sends no body,
    // and nothing on the wire says so -- the scanner learns 204 and 304 from
    // the status line and cannot learn this -- so it is set here.  It is only
    // ever set, never cleared, so a 204 answer to a HEAD agrees with itself.
    http_response_framing frame{};
    frame.no_body = is_head;

#ifndef SOCKETLEY_NO_HTTPS
    if (is_https) {
        // Built once per process and kept: a fresh context per call read and parsed the whole system CA store
        // every time, on the loop. What a call changes lives on its SSL, not here.
        static SSL_CTX* shared_ctx = nullptr;
        if (!shared_ctx)
        {
            std::string why;
            SSL_CTX* made = tls_context::make_client_ctx({}, why);
            if (!made) {
                ::close(sock);
                result["error"] = "no system CA store available: " + why;
                return result;
            }
#if defined(SSL_OP_IGNORE_UNEXPECTED_EOF)
            // HTTP/1.0 with Connection: close, tolerating the missing close_notify
            // a great many servers omit, at the cost that TLS can no longer tell a
            // truncated response from a complete one -- which is why the framing
            // below counts the Content-Length down instead, and why a response
            // that declared no length remains unjudgeable here.
            SSL_CTX_set_options(made, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif
            shared_ctx = made;
        }
        SSL_CTX* ctx = shared_ctx;

        SSL* ssl = SSL_new(ctx);
        if (!ssl) { ::close(sock); result["error"] = "SSL_new failed"; return result; }
        SSL_set_fd(ssl, sock);

        // SSL_VERIFY_PEER and the host pin are both needed, because a
        // certificate for a domain the attacker owns is entirely valid.
        if (!tls_context::pin_peer_name(ssl, host)) {
            // Refuse rather than continue unpinned: a connection that verifies
            // the chain and not the name looks identical to a good one.
            std::string why = ssl_error_text();
            SSL_free(ssl); ::close(sock);
            result["error"] = "failed to pin expected certificate name for " + host
                            + (why.empty() ? "" : ": " + why);
            return result;
        }

        // Handshake bounded by the shared deadline, with the non-blocking
        // socket giving WANT_READ/WANT_WRITE back to poll() instead of
        // sleeping inside read().
        std::string tls_err;
        for (;;) {
            ERR_clear_error();
            int hr = SSL_connect(ssl);
            if (hr == 1)
                break;
            int e = SSL_get_error(ssl, hr);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                if (http_wait(sock, (e == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT, deadline) != 1) {
                    tls_err = "TLS handshake timed out"; break;
                }
                continue;
            }
            // The verify result carries the half of the diagnosis that never
            // reaches the error queue, so report whichever one has something.
            tls_err = "TLS handshake failed";
            long verify = SSL_get_verify_result(ssl);
            if (verify != X509_V_OK) {
                tls_err += ": certificate rejected: ";
                tls_err += X509_verify_cert_error_string(verify);
            }
            std::string why = ssl_error_text();
            if (!why.empty()) { tls_err += ": "; tls_err += why; }
            break;
        }
        if (!tls_err.empty()) {
            SSL_free(ssl); ::close(sock);
            result["error"] = tls_err;
            return result;
        }

        {
            size_t sent = 0;
            while (sent < req.size()) {
                ERR_clear_error();
                int w = SSL_write(ssl, req.data() + sent, static_cast<int>(req.size() - sent));
                if (w > 0) { sent += static_cast<size_t>(w); continue; }
                int e = SSL_get_error(ssl, w);
                if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                    if (http_wait(sock, (e == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT, deadline) != 1) {
                        xfer_err = "send timed out"; break;
                    }
                    continue;
                }
                xfer_err = "SSL_write failed";
                { std::string why = ssl_error_text(); if (!why.empty()) xfer_err += ": " + why; }
                break;
            }
        }
        if (xfer_err.empty()) {
            char buf[4096];
            for (;;) {
                ERR_clear_error();
                int n = SSL_read(ssl, buf, sizeof(buf));
                if (n > 0) {
                    if (response.size() + static_cast<size_t>(n) > http_max_response) {
                        xfer_err = "response exceeds 8MB limit"; break;
                    }
                    response.append(buf, static_cast<size_t>(n));
                    http_response_scan_chunk(frame, std::string_view(buf, static_cast<size_t>(n)));
                    // A response whose length this header cannot establish --
                    // a transfer coding other than chunked, or two lengths that
                    // disagree -- is never complete here, which leaves the old
                    // rule of reading until the peer closes.
                    if (http_response_frame_complete(frame))
                        break;
                    continue;
                }
                int e = SSL_get_error(ssl, n);
                if (e == SSL_ERROR_ZERO_RETURN)
                    break;                      // close_notify: response complete
                if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                    if (http_wait(sock, (e == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT, deadline) != 1) {
                        xfer_err = "response timed out"; break;
                    }
                    continue;
                }
                if (e == SSL_ERROR_SYSCALL && ERR_peek_error() == 0 && !response.empty())
                    break;                      // peer closed without close_notify
                xfer_err = "SSL_read failed";
                { std::string why = ssl_error_text(); if (!why.empty()) xfer_err += ": " + why; }
                break;
            }
        }

        // One attempt only, because waiting for the peer's close_notify would
        // spend the deadline on a connection being closed either way.
        if (SSL_shutdown(ssl) < 0) {}
        ERR_clear_error();
        SSL_free(ssl);
        ::close(sock);
    } else
#endif
    {
        {
            size_t s_total = 0;
            while (s_total < req.size()) {
                // MSG_NOSIGNAL for the same reason event_loop uses it: writing
                // to a peer that already closed must not raise SIGPIPE.
                ssize_t w = ::send(sock, req.data() + s_total, req.size() - s_total, MSG_NOSIGNAL);
                if (w > 0) { s_total += static_cast<size_t>(w); continue; }
                if (w < 0 && errno == EINTR) continue;
                if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    if (http_wait(sock, POLLOUT, deadline) != 1) { xfer_err = "send timed out"; break; }
                    continue;
                }
                xfer_err = std::string("send() failed: ") + std::strerror(errno);
                break;
            }
        }
        if (xfer_err.empty()) {
            char buf[4096];
            for (;;) {
                ssize_t n = ::recv(sock, buf, sizeof(buf), 0);
                if (n > 0) {
                    if (response.size() + static_cast<size_t>(n) > http_max_response) {
                        xfer_err = "response exceeds 8MB limit"; break;
                    }
                    response.append(buf, static_cast<size_t>(n));
                    http_response_scan_chunk(frame, std::string_view(buf, static_cast<size_t>(n)));
                    // A response whose length this header cannot establish --
                    // a transfer coding other than chunked, or two lengths that
                    // disagree -- is never complete here, which leaves the old
                    // rule of reading until the peer closes.
                    if (http_response_frame_complete(frame))
                        break;
                    continue;
                }
                if (n == 0) break;              // peer closed — end of an HTTP/1.0 response
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if (http_wait(sock, POLLIN, deadline) != 1) { xfer_err = "response timed out"; break; }
                    continue;
                }
                xfer_err = std::string("recv() failed: ") + std::strerror(errno);
                break;
            }
        }
        ::close(sock);
    }

    // Both read loops have two exits and only one of them means the answer is
    // whole: a peer that named a length and closed before reaching it ends the
    // loop exactly as the length running out does.  It is reported rather than
    // handed back as a short body because nothing else in the answer would say
    // so -- the close that ended it is the same close that frames a correct
    // HTTP/1.0 response, and over TLS the close_notify that would have told
    // the two apart is one SSL_OP_IGNORE_UNEXPECTED_EOF accepts the absence of
    // on purpose.  Only a declared length can be fallen short of, which is the
    // whole of the condition: http_scan_header_lines refuses a header block
    // carrying a transfer coding beside its Content-Length, and
    // http_response_frame_complete() already answers yes for a HEAD or a 204
    // that quotes one and sends nothing.
    if (xfer_err.empty() && frame.has_content_length &&
        !http_response_frame_complete(frame))
    {
        xfer_err = "the response stopped " + std::to_string(frame.body_remaining)
                 + " bytes short of its Content-Length";
    }

    if (!xfer_err.empty()) { result["error"] = xfer_err; return result; }

    // Parse HTTP status line: "HTTP/1.x NNN Reason"
    int status = 0;
    auto sp1 = response.find(' ');
    if (sp1 != std::string::npos) {
        auto sp2 = response.find(' ', sp1 + 1);
        {
            auto ss = response.substr(sp1 + 1, sp2 - sp1 - 1);
            std::from_chars(ss.data(), ss.data() + ss.size(), status);
        }
    }
    // A reason, where there was none.  `status` stays 0 when the answer is not
    // an HTTP response -- an empty read, a peer that speaks something else, a
    // TLS-only port -- and the table then said ok=false with `error` still the
    // empty string it was created with, so a script asking why got nothing.
    // Every other failure here names itself.
    if (status == 0)
    {
        result["error"] = response.empty()
            ? "the peer closed without sending anything"
            : "the peer's answer is not an HTTP response (it begins \""
              + response.substr(0, std::min<size_t>(response.size(), 32)) + "\")";
        return result;
    }

    auto body_start = response.find("\r\n\r\n");
    std::string body_out = (body_start != std::string::npos) ? response.substr(body_start + 4) : "";
    // The body is what the head says it is: none for a 204 or a 304, and no byte past a Content-Length that came in
    // the same read.
    if (frame.no_body)
        body_out.clear();
    else if (!frame.chunked && body_start != std::string::npos)
    {
        const std::string_view head(response.data(), body_start);
        for (size_t at = head.find("\r\n"); at != std::string_view::npos;)
        {
            const size_t end = head.find("\r\n", at + 2);
            const std::string_view line = head.substr(at + 2, end == std::string_view::npos ? std::string_view::npos : end - at - 2);
            at = end;
            size_t len = 0;
            if (header_name_equals(line, "content-length", 14) &&
                http_whole_decimal(http_trim_ows(line.substr(line.find(':') + 1)), len) && len < body_out.size())
                body_out.resize(len);
        }
    }

    // A chunked answer is handed over as its payload, because the chunk sizes
    // are framing and a script decoding JSON would otherwise read them as the
    // first bytes of the document.
    if (frame.chunked && !frame.no_body && frame.headers_parsed)
    {
        http_chunked_decoder dec{};
        std::string_view in(body_out);
        std::string payload;
        chunk_step step;
        std::string_view piece;
        while ((step = http_chunked_next(dec, in, piece)) == chunk_step::payload)
            payload.append(piece.data(), piece.size());
        if (step != chunk_step::done)
        {
            result["error"] = "the chunked response ended before its last chunk";
            return result;
        }
        body_out.swap(payload);
    }

    result["status"] = status;
    result["body"]   = std::move(body_out);
    result["ok"]     = (status >= 200 && status < 300);
    return result;
}

// The JSON pair lives in lua_json.h now — see the header for why it had to
// leave this file (it was unreachable from any test).
using socketley::lua_json::json_encode_value;
using socketley::lua_json::json_decode_value;
using socketley::lua_json::json_max_depth;


namespace
{

// What a worker cannot answer, raised rather than returned and split into
// three families -- read, mutate, carry a connection -- because a refusal that
// names the wrong missing thing sends its reader to wait for the wrong
// delivery.
std::string worker_refusal(const std::string& call,
                           const char* mistaken_for =
                               "a successful call on a daemon with nothing in it")
{
    return call +
           "() is refused in a worker process: this call reaches for the "
           "runtime map, which lives in the daemon, and answering from here "
           "would return nothing — indistinguishable from " + mistaken_for +
           ". The daemon pushes a cluster view to its workers; this one has "
           "none, so either this daemon is in no cluster, or it joined one "
           "after this script was loaded. Reload the runtime to pick it up.";
}

// The four that change the map would each act on this process's private copy,
// and they travel now, so this message is reached only by a worker with
// nowhere to send them -- an older daemon, or one whose socketpair could not
// be created.
std::string worker_mutation_refusal(const std::string& call)
{
    return call +
           "() is refused by this worker: the call CHANGES the runtime map, "
           "the map lives in the daemon, and this worker was forked without a "
           "control plane to ask over — an older daemon, or one that could not "
           "create the socket. Answering it here would act on this process's "
           "own copy of the map: a runtime built inside this worker that the "
           "daemon never hears about, or a start and a stop that flip a "
           "placeholder and bind nothing. Restart the daemon: a current one "
           "serves these four for every worker it forks.";
}

// pipe and route move a connection rather than read a map, so what was missing
// was never SCM_RIGHTS -- conn_transfer.h and conn_identity.h are in the tree
// with a test -- but a channel between two runtimes to carry it.
std::string worker_transfer_refusal(const std::string& call, const char* moves,
                                    const std::string& way_out)
{
    return call + "() is refused in a worker process: " + moves +
           ", and a connection cannot be handed to another process the way a "
           "name or a port can — the descriptor has to be passed with "
           "SCM_RIGHTS, or its bytes relayed under a reference that means the "
           "same thing at both ends, and there is no channel between two "
           "runtimes to carry either. The mechanism for both is in the tree "
           "and tested; nothing is wired to it yet. So this one is not waiting "
           "on the runtime map and will not come back with it. " + way_out;
}

// pipe has two branches and only one crosses anything, so the way out names
// self.pipe(a, b), which is the same operation on the same tables.
std::string worker_pipe_refusal()
{
    return worker_transfer_refusal(
        "socketley.pipe",
        "a pipe hands an open file descriptor from one runtime to another",
        "To pair two connections of this same server, call self.pipe(fd_a, "
        "fd_b), which stays in this process and is not refused; to route a "
        "connection to another runtime, restart the daemon — a current one "
        "gives every worker the channel this needs.");
}

// self.route() always names another runtime, and route_client() writes into
// the target's maps while keeping the socket here, which is conn_transfer.h's
// RELAY shape rather than its HANDOVER shape.
std::string worker_route_refusal()
{
    return worker_transfer_refusal(
        "self.route",
        "routing hands a live client to another runtime, which answers it "
        "while this server keeps the socket and relays the bytes",
        "Restart the daemon; a current one gives every worker the channel "
        "this needs. unroute(), get_route() "
        "and owner_send() are not refused here: they read this runtime's own "
        "tables, which in a worker are empty because nothing was ever routed "
        "in, and that is the truth rather than a substitute for it.");
}

// Built by a Lua factory so a script sees Lua's own error() at the call site,
// shared by the two tables that have something to refuse, and invalid when the
// interpreter could not build it.
sol::function refusal_factory(sol::state& lua)
{
    auto factory = lua.safe_script(
        "return function(msg) return function() error(msg, 2) end end",
        sol::script_pass_on_error);
    if (!factory.valid())
        return sol::function();
    return factory;
}

}  // namespace

void lua_context::set_worker_process(bool on) { s_worker_process = on; }
bool lua_context::in_worker_process() { return s_worker_process; }

bool lua_context::s_worker_process = false;

void lua_context::dispatch_cluster_event(const cluster_ev_wire& ev)
{
    // Lifted out of runtime_manager::dispatch_cluster_events and handed the
    // resolved list, so this function has no idea which process it is in --
    // which is what lets both run it.
    switch (static_cast<cluster_event::type_t>(ev.kind))
    {
        case cluster_event::daemon_join:
            if (has_on_cluster_join())
            {
                sol::table dt = m_lua.create_table();
                dt["name"] = ev.daemon_name;
                if (!ev.host.empty())
                    dt["host"] = ev.host;
                sol::protected_function_result r = on_cluster_join()(dt);
                lua_diag::raised(r, m_owner_name, "on_cluster_join");
            }
            break;

        case cluster_event::daemon_leave:
            if (has_on_cluster_leave())
            {
                sol::table dt = m_lua.create_table();
                dt["name"] = ev.daemon_name;
                sol::protected_function_result r = on_cluster_leave()(dt);
                lua_diag::raised(r, m_owner_name, "on_cluster_leave");
            }
            break;

        case cluster_event::group_change:
            if (has_on_group_change())
            {
                sol::table members = m_lua.create_table();
                int mi = 1;
                for (const auto& m : ev.members)
                {
                    sol::table t = m_lua.create_table();
                    t["daemon"] = m.daemon;
                    t["host"]   = m.host;
                    t["port"]   = m.port;
                    members[mi++] = t;
                }
                sol::protected_function_result r =
                    on_group_change()(ev.group_name, members);
                lua_diag::raised(r, m_owner_name, "on_group_change");
            }
            break;
    }
}

void lua_context::set_cluster_view(cluster_view_ptr view)
{
    s_cluster_view = std::move(view);
}
cluster_view_ptr lua_context::cluster_view_snapshot() { return s_cluster_view; }

cluster_view_ptr lua_context::s_cluster_view;

// Replace the cross-runtime half of the management API with a Lua error()
// saying why it is not there, which every callback already catches and prints
// with the callback's name attached.
void lua_context::refuse_cross_runtime_api(sol::table& sk, sol::table& cluster_tbl,
                                           runtime_instance* owner)
{
    sol::function make = refusal_factory(m_lua);
    if (!make.valid())
    {
        // Cannot happen with a working interpreter, and if it does the honest
        // thing is to say so rather than leave the old bindings in place while
        // believing they are gone.
        std::cerr << lua_diag::tag(m_owner_name)
                  << " could not install the out-of-process refusals; the "
                     "cross-runtime management API is left bound and will "
                     "answer nothing" << std::endl;
        return;
    }

    // Grouped by what is missing rather than by which table they sit on,
    // because one sentence for eight names was telling three of the four
    // groups the wrong reason.

    // READ, empty now that the worker is handed the runtime map, kept as a
    // group so a reader finding two families knows the third was emptied on
    // purpose.

    // MUTATE, refused only while this process has no sink to ask through,
    // tested once while the bindings are built because worker_main installs
    // the sink in its constructor.
    const runtime_manager* mgr = owner ? owner->get_runtime_manager() : nullptr;
    if (!mgr || !mgr->has_map_sink())
    {
        for (const char* call : {"create", "start", "stop", "remove"})
        {
            sol::function f = make(worker_mutation_refusal(std::string("socketley.") + call));
            sk[call] = f;
        }
    }

    // CARRY A CONNECTION, no longer permanent: the same test as the mutators
    // against a different sink, since route_client() needed a way to name
    // another runtime's connection rather than SCM_RIGHTS.
    if (!mgr || !mgr->route_sink())
        sk["pipe"] = make(worker_pipe_refusal());

    // ASK THE CLUSTER, refused only while this process has no view, because
    // with none the answer would be an empty table -- which is what a
    // successful call returns on a daemon alone in its cluster.
    if (!lua_context::cluster_view_snapshot())
    {
        for (const char* call : {"daemons", "runtimes", "group", "stats"})
        {
            sol::function f = make(worker_refusal(std::string("socketley.cluster.") + call));
            cluster_tbl[call] = f;
        }
    }
}

void lua_context::register_bindings(runtime_instance* owner)
{
    // Which runtime every diagnostic from this interpreter belongs to, first,
    // because load_diag is called from everything below.
    m_owner_name = std::string(owner->get_name());
    m_suspend->attach(&m_lua, m_owner_name);

    // Register socketley.log() and management API
    sol::table sk = m_lua.create_table();

    // socketley.log goes through the daemon's logger, so script output gains a
    // clock and a level and an operator who set `warn` can finally ask for
    // less.
    sk["log"] = [owner](std::string_view msg) {
        std::string line = lua_diag::tag(owner->get_name());
        line += ' ';
        line += msg;
        LOG_INFO(line.c_str());
    };

    // The config table is judged before anything is built -- unknown keys
    // included, since it is read by the same build on the same machine --
    // because a child on a port nobody chose is invisible from the script,
    // from `ls` and from the runtime itself.
    sk["create"] = [owner](std::string type_str, std::string name,
                           sol::object config) -> api_result {
        auto* mgr = owner->get_runtime_manager();
        auto* loop = owner->get_event_loop();
        if (!mgr || !loop)
            return api_why("this runtime has no runtime manager");

        const std::string where = "socketley.create(\"" + type_str + "\", \"" + name + "\")";
        // Logged and returned, because a top-level create runs inside the
        // `create` command and cmd_create reads the buffer back to the
        // operator's terminal.
        auto refuse = [&](const std::string& why) {
            api_diag(owner, where + ": " + why);
            return api_why(why);
        };

        runtime_type type;
        if (!parse_runtime_type(type_str, type))
            return refuse("`" + type_str + "` is not a runtime type "
                          "(server, client, proxy, cache)");

        const bool has_config = config.valid() &&
                                config.get_type() != sol::type::lua_nil &&
                                config.get_type() != sol::type::none;
        if (has_config && config.get_type() != sol::type::table)
            return refuse("the third argument is a config table "
                          "{ port = ..., config = ... }");

        // Everything the table asked for, read and judged here, applied below.
        uint16_t    cfg_port       = 0;
        bool        have_port      = false;
        std::string cfg_script;
        std::string cfg_target;    bool have_target = false;
        server_mode cfg_mode       = mode_inout;
        bool        have_mode      = false;
        std::string cfg_http;
        bool        cfg_http_cache = false;
        std::string cfg_group;
        bool        cfg_remove_with_parent = false;
        bool        cfg_start      = false;

        if (has_config)
        {
            sol::table t = config.as<sol::table>();

            // The closed set, walked first so an unknown key is reported as
            // itself rather than as whatever it failed to be.
            static constexpr std::string_view known[] = {
                "port", "config", "lua", "target", "mode", "http",
                "http_cache", "group", "on_parent_stop", "start"
            };
            std::string bad_key;
            t.for_each([&](sol::object k, sol::object) {
                if (!bad_key.empty()) return;
                if (k.get_type() != sol::type::string)
                {
                    bad_key = "<a key that is not a name>";
                    return;
                }
                const std::string key = k.as<std::string>();
                for (std::string_view ok : known)
                    if (key == ok) return;
                bad_key = key;
            });
            if (!bad_key.empty())
                return refuse("`" + bad_key + "` is not a config key — one of "
                              "port, config/lua, target, mode, http, http_cache, "
                              "group, on_parent_stop, start");

            // A key that is not there must read as absent rather than throw,
            // so every read is taken as a sol::object first and type-checked
            // here instead of by a conversion whose behaviour follows NDEBUG.
            sol::object o_port = t["port"];
            if (o_port.valid() && o_port != sol::nil)
            {
                const double d = (o_port.get_type() == sol::type::number)
                               ? o_port.as<double>() : -1.0;
                if (o_port.get_type() != sol::type::number ||
                    d != std::floor(d) || d < 0.0 || d > 65535.0)
                    return refuse("`port` must be a whole number in 0..65535 "
                                  "(0 means no port) — the CLI's own -p has "
                                  "refused anything else since it was written");
                cfg_port  = static_cast<uint16_t>(d);
                have_port = true;
            }

            // `config` and `lua` are two spellings of one key; naming both is
            // a script asking for two different scripts.
            sol::object o_cfg = t["config"];
            sol::object o_lua = t["lua"];
            if (o_cfg.valid() && o_cfg != sol::nil && o_lua.valid() && o_lua != sol::nil)
                return refuse("`config` and `lua` are the same key spelled two "
                              "ways; name one");
            sol::object o_script = (o_cfg.valid() && o_cfg != sol::nil) ? o_cfg : o_lua;
            if (o_script.valid() && o_script != sol::nil)
            {
                if (o_script.get_type() != sol::type::string)
                    return refuse("`config` must be the path to a Lua script");
                cfg_script = o_script.as<std::string>();
            }

            sol::object o_target = t["target"];
            if (o_target.valid() && o_target != sol::nil)
            {
                if (o_target.get_type() != sol::type::string)
                    return refuse("`target` must be a host:port string");
                cfg_target  = o_target.as<std::string>();
                have_target = true;
            }

            sol::object o_mode = t["mode"];
            if (o_mode.valid() && o_mode != sol::nil)
            {
                if (o_mode.get_type() != sol::type::string)
                    return refuse("`mode` must be one of in, out, inout, master");
                // Only a server has modes, and `mode` on anything else used to
                // be dropped without a word — a value accepted and ignored,
                // which is the same defect as a value accepted and altered.
                if (type != runtime_server)
                    return refuse("`mode` applies to a server; a " + type_str
                                  + " has none");
                const std::string m = o_mode.as<std::string>();
                switch (fnv1a(m))
                {
                    case fnv1a("in"):     cfg_mode = mode_in;     break;
                    case fnv1a("out"):    cfg_mode = mode_out;    break;
                    case fnv1a("inout"):  cfg_mode = mode_inout;  break;
                    case fnv1a("master"): cfg_mode = mode_master; break;
                    default:
                        return refuse("`mode = \"" + m + "\"` is not a mode — "
                                      "one of in, out, inout, master");
                }
                have_mode = true;
            }

            sol::object o_http = t["http"];
            if (o_http.valid() && o_http != sol::nil)
            {
                if (type != runtime_server)
                    return refuse("`http` applies to a server; a " + type_str
                                  + " serves no files");
                if (o_http.get_type() != sol::type::string)
                    return refuse("`http` must be a directory to serve");
                cfg_http = o_http.as<std::string>();
            }

            sol::object o_hcache = t["http_cache"];
            if (o_hcache.valid() && o_hcache != sol::nil)
            {
                if (type != runtime_server)
                    return refuse("`http_cache` applies to a server; a "
                                  + type_str + " serves no files");
                if (o_hcache.get_type() != sol::type::boolean)
                    return refuse("`http_cache` must be true or false");
                cfg_http_cache = o_hcache.as<bool>();
            }

            sol::object o_group = t["group"];
            if (o_group.valid() && o_group != sol::nil)
            {
                if (o_group.get_type() != sol::type::string)
                    return refuse("`group` must be a group name");
                cfg_group = o_group.as<std::string>();
            }

            sol::object o_ops = t["on_parent_stop"];
            if (o_ops.valid() && o_ops != sol::nil)
            {
                if (o_ops.get_type() != sol::type::string)
                    return refuse("`on_parent_stop` must be \"remove\" or \"stop\"");
                // "stop" and not "keep", because that is what the enum, the
                // `owner` command and the man page call it, and a second name
                // for one bit costs the same here as anywhere.
                const std::string p = o_ops.as<std::string>();
                if (fnv1a(p) == fnv1a("remove"))
                    cfg_remove_with_parent = true;
                else if (fnv1a(p) != fnv1a("stop"))
                    return refuse("`on_parent_stop = \"" + p + "\"` is not a "
                                  "policy — \"remove\" (goes with the parent) "
                                  "or \"stop\" (outlives it, stopped)");
            }

            sol::object o_start = t["start"];
            if (o_start.valid() && o_start != sol::nil)
            {
                if (o_start.get_type() != sol::type::boolean)
                    return refuse("`start` must be true or false");
                cfg_start = o_start.as<bool>();
            }
        }

        // The seam is exactly here: everything above is the table, refused
        // where the mistake was made, and what crosses is a runtime_config,
        // which is the same struct a config frame and a state file carry.
        if (mgr->has_map_sink())
        {
            runtime_config c;
            c.name        = name;
            c.type        = type;
            c.owner       = owner->get_name();
            c.child_policy = cfg_remove_with_parent ? 1 : 0;

            // `start = true` travels as was_running, which is the field that
            // already means "this runtime is meant to be up" everywhere else.
            c.was_running = cfg_start;

            if (have_port)          c.port       = cfg_port;
            if (have_target)        c.target     = cfg_target;
            if (!cfg_group.empty()) c.group      = cfg_group;
            if (!cfg_script.empty())c.lua_script = cfg_script;
            if (type == runtime_server)
            {
                if (have_mode)           c.mode       = static_cast<uint8_t>(cfg_mode);
                if (!cfg_http.empty())   c.http_dir   = cfg_http;
                if (cfg_http_cache)      c.http_cache = true;
            }

            state_persistence codec{std::filesystem::path{}};   // codec only
            std::string       err;
            if (!mgr->map_mutate("create", name, codec.format_json_pretty(c), err))
                return refuse(err.empty() ? std::string("the daemon refused the "
                                                        "create and said nothing")
                                          : err);

            // The replica, corrected on the spot, or the next line of the same
            // script reads a map without this runtime in it.
            runtime_manager::replica_entry re;
            re.name  = name;
            re.type  = type;
            re.state = cfg_start ? runtime_running : runtime_created;
            re.port  = have_port ? static_cast<uint16_t>(cfg_port) : 0;
            re.owner = std::string(owner->get_name());
            re.group = cfg_group;
            mgr->replica_note("create", name, re);
            return api_yes();
        }

        // Nothing above this line built anything, so nothing above it has to
        // undo anything.
        if (!mgr->create(type, name))
            return refuse("a runtime called \"" + name + "\" already exists");

        auto* inst = mgr->get(name);
        if (!inst) return refuse("the runtime could not be built");

        inst->set_runtime_manager(mgr);
        inst->set_event_loop(loop);
        inst->set_owner(owner->get_name());
        inst->set_lua_created(true);

        if (have_port) inst->set_port(cfg_port);
        if (have_target) inst->set_target(cfg_target);
        if (!cfg_group.empty()) inst->set_group(cfg_group);
        if (cfg_remove_with_parent)
            inst->set_child_policy(runtime_instance::child_policy::remove);
        // as_server() and not static_cast, because a replica answers
        // runtime_server truthfully and is a bare runtime_instance underneath
        // -- unreachable today only because socketley.create is refused in a
        // worker, which is the coupling a reader who changes that refusal has
        // to find.
        if (type == runtime_server)
        {
            auto* srv = inst->as_server();
            // Null means the manager handed back something that calls itself a
            // server and is not one, so the half-built runtime goes with the
            // refusal.
            if (!srv)
            {
                mgr->remove(name);
                return refuse("the runtime could not be built as a server");
            }
            if (have_mode) srv->set_mode(cfg_mode);
            if (!cfg_http.empty()) srv->set_http_dir(cfg_http);
            if (cfg_http_cache) srv->set_http_cache(true);
        }

        // The two that can only fail after the runtime exists remove what they
        // built, exactly as cmd_create does, without repeating a reason the
        // child's own load has already written under the child's name.
        if (!cfg_script.empty() && !inst->load_lua_script(cfg_script))
        {
            mgr->remove(name);
            return refuse("could not load " + cfg_script);
        }

        if (cfg_start && !mgr->start(name, *loop))
        {
            mgr->remove(name);
            return refuse("start = true, and it could not be started"
                          + (have_port ? " on port " + std::to_string(cfg_port)
                                       : std::string{}));
        }
        // Its workers forked and serving before the answer, as for the CLI's start, so the port answers once the
        // script hears yes.
        if (cfg_start)
        {
            mgr->release_workers();
            if (std::string why = mgr->await_workers(name); !why.empty())
                return api_why(why);
        }

        return api_yes();
    };

    // Two of the four reasons a start fails can be asked about from here in
    // O(1) before anything is attempted, so they are named, and the ring check
    // runs first because runtime_instance::start stores `failed` on that path.
    sk["start"] = [owner](std::string name) -> api_result {
        auto* mgr = owner->get_runtime_manager();
        auto* loop = owner->get_event_loop();
        if (!mgr || !loop)
            return api_why("this runtime has no runtime manager");

        // In a worker, asked of the daemon and asked first, because every
        // check below reads a replica that can be a snapshot behind and `loop`
        // is this worker's ring rather than the runtime's.
        if (mgr->has_map_sink())
        {
            std::string err;
            if (mgr->map_mutate("start", name, {}, err))
            {
                runtime_manager::replica_entry re;
                re.state = runtime_running;
                mgr->replica_note("start", name, re);
                return api_yes();
            }
            return api_why(err.empty() ? q(name) + " could not be started" : err);
        }

        auto* inst = mgr->get(name);
        if (!inst)
            return api_why("there is no runtime called " + q(name));

        switch (inst->get_state())
        {
            case runtime_running:
                return api_why(q(name) + " is already running");
            case runtime_failed:
                return api_why(q(name) + " is failed, and a failed runtime "
                                         "cannot be started again — remove it "
                                         "and create it anew");
            default: break;
        }

        if (const std::string msg = inst->ring_policy_refusal(*loop); !msg.empty())
            return api_why(msg);

        // Its workers forked and serving before the answer, as for the CLI's start, rather than at the next tick.
        if (mgr->start(name, *loop))
        {
            mgr->release_workers();
            if (std::string why = mgr->await_workers(name); !why.empty())
                return api_why(why);
            return api_yes();
        }

        return api_why(q(name) + " could not be started; it is "
                    + state_to_string(inst->get_state())
                    + " now, and the reason is in the daemon's log");
    };

    // socketley.stop(name) → true | false, reason
    sk["stop"] = [owner](std::string name) -> api_result {
        auto* mgr = owner->get_runtime_manager();
        auto* loop = owner->get_event_loop();
        if (!mgr || !loop)
            return api_why("this runtime has no runtime manager");

        // In a worker, asked of the daemon before the replica, and the one of
        // the four where waiting is load-bearing: the daemon takes the workers
        // down before it answers, so a script can rebind the port.
        if (mgr->has_map_sink())
        {
            std::string err;
            if (mgr->map_mutate("stop", name, {}, err))
            {
                runtime_manager::replica_entry re;
                re.state = runtime_stopped;
                mgr->replica_note("stop", name, re);
                return api_yes();
            }
            return api_why(err.empty() ? q(name) + " could not be stopped" : err);
        }

        auto* inst = mgr->get(name);
        if (!inst)
            return api_why("there is no runtime called " + q(name));
        if (inst->get_state() != runtime_running)
            return api_why(q(name) + " is "
                           + state_to_string(inst->get_state()) + ", not running");

        if (mgr->stop(name, *loop))
        {
            // The workers taken down before the answer, as the daemon does for
            // a worker's script, or they serve the port until the next health
            // tick and a start in between keeps them with their old config.
            mgr->release_workers();
            return api_yes();
        }
        return api_why(q(name) + " could not be stopped; the reason is in "
                                 "the daemon's log");
    };

    // socketley.remove(name) → true | false, reason
    sk["remove"] = [owner](std::string name) -> api_result {
        auto* mgr = owner->get_runtime_manager();
        auto* loop = owner->get_event_loop();
        if (!mgr || !loop)
            return api_why("this runtime has no runtime manager");
        // In a worker, asked of the daemon before the replica, because the
        // stop below would be a write to that replica.
        if (mgr->has_map_sink())
        {
            std::string err;
            if (mgr->map_mutate("remove", name, {}, err))
            {
                mgr->replica_note("remove", name, {});
                return api_yes();
            }
            return api_why(err.empty() ? q(name) + " could not be removed" : err);
        }

        auto* inst = mgr->get(name);
        if (!inst)
            return api_why("there is no runtime called " + q(name));

        if (inst->get_state() == runtime_running)
            mgr->stop(name, *loop);
        // Before the instance leaves the map, because a worker's supervisor
        // holds a pointer to the placeholder that has to be dropped while the
        // object is still there.
        mgr->release_workers();
        if (mgr->remove(name))
            return api_yes();
        // Unreachable while the lookup above succeeds and nothing else runs on
        // this thread in between — said anyway, because a bare false is what
        // this whole change exists to stop returning.
        return api_why(q(name) + " could not be removed");
    };

    // The connections are wherever the runtime is, so calling broadcast()
    // on a placeholder succeeds, returns true and delivers nothing.
    sk["send"] = [owner](std::string_view name,
                         std::string_view msg) -> api_result {
        auto* mgr = owner->get_runtime_manager();
        if (!mgr)
            return api_why("this runtime has no runtime manager");
        auto* inst = mgr->get(name);
        if (!inst)
            return api_why("there is no runtime called " + q(name));
        if (inst->get_state() != runtime_running)
            return api_why(q(name) + " is " + state_to_string(inst->get_state())
                           + ", not running; nothing is connected to it");
        if (inst->is_out_of_process())
        {
            if (mgr->deliver_out_of_process(name, msg))
                return api_yes();
            // Named as the transport it is, taken for every peer when the
            // caller is itself in a worker, where `true` means the message
            // reached the daemon rather than the process holding the
            // connections.
            return api_why(q(name) + " runs in another process, and the "
                                     "message could not be handed to it");
        }
        if (inst->get_type() == runtime_server)
        {
            // What the broadcast did, because self.broadcast was given this
            // contract at the other door under a comment saying why: checking
            // at one and not the other teaches a script author the check is
            // not there.
            const auto c = inst->broadcast(msg);
            // Nobody connected is ordinary; every client dropped is not.
            if (c.taken == 0 && c.backlogged > 0)
                return api_why(q(name) + " dropped the message for all "
                               + std::to_string(c.backlogged)
                               + " of its connections, which are behind on "
                                 "their writes");
            return api_yes();
        }
        // Whether the message was written or queued: a client that is not
        // connected, is --mode in, or has a full write queue answers no to all
        // three and was reported here as a delivery.
        if (!inst->lua_send(msg))
            return api_why(q(name) + " had no connection to write or queue "
                                     "the message on");
        return api_yes();
    };

    // socketley.list() → table of names
    sk["list"] = [owner, this]() -> sol::table {
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return m_lua.create_table();
        std::shared_lock lock(mgr->mutex);
        auto& list = mgr->list();
        sol::table result = m_lua.create_table(static_cast<int>(list.size()), 0);
        int i = 1;
        for (const auto& [name, _] : list)
            result[i++] = name;
        return result;
    };

    // reported_connection_count() and not get_connection_count(), because
    // `name` is some other runtime, whose connections this object does not
    // hold.
    sk["get"] = [owner, this](std::string name) -> sol::object {
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return sol::nil;
        auto* inst = mgr->get(name);
        if (!inst) return sol::nil;
        sol::table info = m_lua.create_table();
        info["name"] = std::string(inst->get_name());
        info["type"] = type_to_string(inst->get_type());
        info["state"] = state_to_string(inst->get_state());
        info["port"] = inst->get_port();
        info["connections"] = inst->reported_connection_count();
        auto ow = inst->get_owner();
        info["owner"] = ow.empty() ? sol::object(sol::nil) : sol::make_object(m_lua, std::string(ow));
        return info;
    };

    sk["http"] = [this](sol::table opts) -> sol::table {
        return socketley_http_call(m_lua, opts);
    };

    // socketley.set_timeout(ms, fn) → timer_id
    //
    // ─── What 0 means, and why it stays 0 ───────────────────────────────────
    // 0 is a refusal and never an id, said in the log because a callback that
    // never runs otherwise leaves no record, and not a nil, which would break
    // `clear_timeout(id)`.
    sk["set_timeout"] = [this, owner](int ms, sol::protected_function fn) -> int {
        // A third refusal and the same 0: the runtime is down and this call
        // would schedule work for it.
        if (m_severed)
        {
            std::cerr << lua_diag::tag(owner->get_name())
                      << " set_timeout(" << ms << ") armed nothing: this "
                         "runtime has been stopped" << std::endl;
            return 0;
        }
        auto* loop = owner->get_event_loop();
        if (!loop || ms <= 0)
        {
            std::cerr << lua_diag::tag(owner->get_name())
                      << " set_timeout(" << ms << ") armed nothing: "
                      << (loop ? "the delay must be greater than 0"
                               : "this runtime has no event loop")
                      << std::endl;
            return 0;
        }
        auto* t  = static_cast<lua_timer*>(timer_pool_acquire());
        t->alive  = m_alive;
        t->fn     = std::move(fn);
        t->loop   = loop;
        t->ctx    = this;
        t->ts     = { (long long)ms / 1000, ((long long)ms % 1000) * 1'000'000LL };
        t->req    = { t, nullptr, -1, 0, op_timeout };
        t->repeat = false;
        t->cancelled = false;
        int id = ++m_next_timer_id;
        t->timer_id = id;
        m_active_timers.push_back(t);
        m_timer_map[id] = t;
        loop->submit_timeout(&t->ts, &t->req);
        return id;
    };

    // socketley.set_interval(ms, fn) → timer_id
    //
    // 0 on refusal, said out loud; see set_timeout above for the whole of it.
    sk["set_interval"] = [this, owner](int ms, sol::protected_function fn) -> int {
        // See set_timeout above; this is the one the measurement came from, at
        // 41 ticks in two seconds on a stopped runtime.
        if (m_severed)
        {
            std::cerr << lua_diag::tag(owner->get_name())
                      << " set_interval(" << ms << ") armed nothing: this "
                         "runtime has been stopped" << std::endl;
            return 0;
        }
        auto* loop = owner->get_event_loop();
        if (!loop || ms <= 0)
        {
            std::cerr << lua_diag::tag(owner->get_name())
                      << " set_interval(" << ms << ") armed nothing: "
                      << (loop ? "the period must be greater than 0"
                               : "this runtime has no event loop")
                      << std::endl;
            return 0;
        }
        auto* t  = static_cast<lua_timer*>(timer_pool_acquire());
        t->alive  = m_alive;
        t->fn     = std::move(fn);
        t->loop   = loop;
        t->ctx    = this;
        t->ts     = { (long long)ms / 1000, ((long long)ms % 1000) * 1'000'000LL };
        t->req    = { t, nullptr, -1, 0, op_timeout };
        t->repeat = true;
        t->cancelled = false;
        int id = ++m_next_timer_id;
        t->timer_id = id;
        m_active_timers.push_back(t);
        m_timer_map[id] = t;
        loop->submit_timeout(&t->ts, &t->req);
        return id;
    };

    // ─── Cancelling a timer withdraws it ────────────────────────────────────
    // sever_timer() rather than two assignments, which stopped the callback
    // and left the timeout armed and the closure referenced, reusing the one
    // place that knows the load-bearing order -- unregister_timer() first,
    // because it finds the entry by timer_id.
    auto cancel_timer_by_id = [this](int id) {
        auto it = m_timer_map.find(id);
        if (it == m_timer_map.end()) return;   // already fired, or never issued
        auto* t = static_cast<lua_timer*>(it->second);
        unregister_timer(t);
        sever_timer(t);
    };

    // socketley.clear_timeout(id) — cancel a pending timeout
    sk["clear_timeout"] = cancel_timer_by_id;

    // socketley.clear_interval(id) — cancel a repeating interval
    sk["clear_interval"] = cancel_timer_by_id;

    // json_encode refuses with false and a reason rather than raising,
    // following this file's return contract, where both refusals used to crash
    // the whole daemon.
    sk["json_encode"] = [](sol::object val)
                        -> api_result {
        std::string out;
        out.reserve(256);
        std::vector<const void*> path;
        std::string err;
        if (!json_encode_value(out, val, 0, path, err))
            return api_why("socketley.json_encode(): " + err);

        return api_str_t{ std::move(out) };
    };

    // json_decode's depth refusal matters most because this call is pointed at
    // request bodies, and nil would be indistinguishable from a document that
    // really decoded to nil.
    sk["json_decode"] = [this](std::string_view str)
                        -> api_result {
        const char* p = str.data();
        const char* end = p + str.size();
        auto st = socketley::lua_json::json_status::ok;
        sol::object v = json_decode_value(m_lua, p, end, 0, st);
        if (st == socketley::lua_json::json_status::too_deep)
            return api_why("socketley.json_decode(): the document is nested "
                           "deeper than " + std::to_string(json_max_depth) +
                           " levels");
        if (st != socketley::lua_json::json_status::ok)
            return api_why("socketley.json_decode(): not a JSON document, at "
                           "byte " + std::to_string(
                               static_cast<size_t>(p - str.data())));

        // Trailing bytes are a failure too, caught here because
        // json_decode_value stops at the end of the first complete value and
        // says nothing about what follows.
        socketley::lua_json::json_skip_ws(p, end);
        if (p != end)
            return api_why("socketley.json_decode(): " +
                           std::to_string(static_cast<size_t>(end - p)) +
                           " byte(s) of trailing data after the document");

        return api_obj_t{ std::move(v) };
    };

    // The id is what socketley.unsubscribe takes, following the timers, and is
    // the only identity that can express dropping one of two handlers on one
    // channel.
    sk["subscribe"] = [this](std::string cache_name, std::string channel,
                             sol::protected_function fn) -> int {
        // The key joins the two with a NUL, which a runtime's name never holds, so a name that does is no cache.
        if (cache_name.find('\0') != std::string::npos)
        {
            std::cerr << lua_diag::tag(owner_name()) << " subscribe(): a cache's name holds no NUL" << std::endl;
            return 0;
        }
        // 0, which is never an id: the runtime is down and a registration made
        // now would outlive the stop that was supposed to end them all.
        if (m_severed)
        {
            std::cerr << lua_diag::tag(owner_name())
                      << " subscribe(" << cache_name << ", " << channel
                      << ") registered nothing: this runtime has been stopped"
                      << std::endl;
            return 0;
        }
        const int   id  = ++m_next_subscription_id;
        std::string key = cache_name + '\0' + channel;
        m_subscription_keys.emplace(id, key);

        subscription sub;
        sub.id = id;
        sub.fn = std::move(fn);

        // Parked rather than appended while a dispatch is walking, so a
        // handler that subscribes does not receive the message it is handling.
        if (m_dispatch_depth > 0)
            m_pending_subscriptions.emplace_back(std::move(key), std::move(sub));
        else
            m_subscriptions[std::move(key)].push_back(std::move(sub));
        return id;
    };

    // True when it removed a live registration and false when the id names
    // none, which unlike a cleared timeout is always the script asking about
    // something that does not exist.
    sk["unsubscribe"] = [this](int id) -> bool {
        auto ki = m_subscription_keys.find(id);
        if (ki == m_subscription_keys.end())
            return false;

        // One that has not reached the map yet — subscribed and unsubscribed
        // inside the same dispatch — is simply dropped from the queue.
        for (auto pit = m_pending_subscriptions.begin();
             pit != m_pending_subscriptions.end(); ++pit)
        {
            if (pit->second.id != id) continue;
            m_pending_subscriptions.erase(pit);
            m_subscription_keys.erase(ki);
            return true;
        }

        if (auto si = m_subscriptions.find(ki->second); si != m_subscriptions.end())
        {
            for (auto& s : si->second)
                if (s.id == id) { s.dead = true; break; }
        }
        m_subscription_keys.erase(ki);
        m_subscriptions_dirty = true;

        // Marked and taken out now, unless a dispatch is walking this entry's
        // vector, since a handler unsubscribing itself is the ordinary
        // one-shot subscriber.
        if (m_dispatch_depth == 0)
            settle_subscriptions();
        return true;
    };

    // Two operations and the argument count is which: four is a pipe within
    // one runtime, three is route_client() across two, because the
    // cross-runtime branch has no destination descriptor and used to read the
    // fourth argument not at all.
    sk["pipe"] = [owner](std::string src_name, int src_fd,
                         std::string dst_name,
                         sol::optional<int> dst_fd) -> api_result {
        auto* mgr = owner->get_runtime_manager();
        if (!mgr)
            return api_why("this runtime has no runtime manager");

        const std::string where = "socketley.pipe(\"" + src_name + "\", "
                                + std::to_string(src_fd) + ", \"" + dst_name + "\""
                                + (dst_fd ? ", " + std::to_string(*dst_fd) : "")
                                + ")";
        auto refuse = [&](const std::string& why) {
            api_diag(owner, where + ": " + why);
            return api_why(why);
        };

        if (src_name == dst_name)
        {
            // A pipe pairs two connections of one server, so naming a third
            // runtime twice must not fall through to the cross-runtime branch
            // and route a runtime to itself.
            if (src_name != owner->get_name())
                return refuse("a pipe joins two connections of one server, and "
                              "only that server holds them — call it from \""
                              + src_name + "\"'s own script");
            if (!dst_fd)
                return refuse("a pipe joins two connections: the fourth "
                              "argument is the second one");
            if (owner->get_type() != runtime_server)
                return refuse("only a server has connections to pipe");
            if (!static_cast<server_instance*>(owner)->pipe(src_fd, *dst_fd))
                return refuse("one of those is not an open connection of this "
                              "server");
            return api_yes();
        }

        if (dst_fd)
            return refuse("a pipe across two runtimes routes the connection to "
                          "\"" + dst_name + "\" and lets it decide which of its "
                          "own connections answers — there is no destination "
                          "descriptor to honour, so drop the fourth argument");

        auto* src_rt = mgr->get(src_name);
        if (!src_rt) return refuse("there is no runtime called \"" + src_name + "\"");
        if (src_rt->get_type() != runtime_server)
            return refuse("\"" + src_name + "\" is not a server");

        // The destination is not checked here when there is a route sink,
        // because this process's map is a replica pushed on a timer and
        // whoever holds the map answers in the map's own words.
        if (!mgr->route_sink())
        {
            auto* dst_rt = mgr->get(dst_name);
            if (!dst_rt) return refuse("there is no runtime called \"" + dst_name + "\"");
            if (dst_rt->get_type() != runtime_server)
                return refuse("both ends must be servers");
        }

        // as_server() and not static_cast, sharper here because `src_rt` is an
        // arbitrary name out of a map whose rows are replicas in a worker --
        // and `owner` is asked first, because it is the only resolution that
        // cannot be one.
        server_instance* src_srv = nullptr;
        if (src_name == owner->get_name())
            src_srv = owner->as_server();
        else
            src_srv = src_rt->as_server();
        if (!src_srv)
            return refuse("\"" + src_name + "\" says it is a server but this "
                          "process holds no server object for it — it lives "
                          "somewhere else");
        // route_client refuses several different things and now says which, in
        // the daemon's own words for a target in another process.
        std::string why;
        if (src_srv->route_client(src_fd, dst_name, &why))
            return api_yes();
        return refuse("connection " + std::to_string(src_fd) + " could not be "
                      "routed to " + q(dst_name) + ": "
                      + (why.empty() ? std::string("it was refused and no "
                                                   "reason was given") : why));
    };

    // The cluster half of the answer is resolved once here rather than four
    // times, from cluster_discovery in the daemon and from a pushed view in a
    // worker, where `ok` false means neither source and an empty table is the
    // honest answer.
    struct cluster_source
    {
        std::string                daemon_name;
        std::string                host;
        std::vector<remote_daemon> remote;
        bool                       ok = false;
    };
    auto resolve_cluster = [](runtime_manager* mgr) -> cluster_source {
        cluster_source src;
        if (!mgr) return src;
        if (auto* cd = mgr->get_cluster_discovery())
        {
            src.daemon_name = std::string(cd->get_daemon_name());
            src.host        = std::string(cd->get_cluster_addr());
            src.remote      = cd->get_all_daemons();
            src.ok          = true;
            return src;
        }
        if (auto view = lua_context::cluster_view_snapshot())
        {
            src.daemon_name = view->daemon_name;
            src.host        = view->host;
            src.remote      = view->remote;
            src.ok          = true;
        }
        return src;
    };

    sol::table cluster_tbl = m_lua.create_table();

    // socketley.cluster.daemons() → array of {name, host, runtimes}
    cluster_tbl["daemons"] = [owner, this, resolve_cluster]() -> sol::table {
        sol::table result = m_lua.create_table();
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return result;
        const cluster_source src = resolve_cluster(mgr);
        if (!src.ok) return result;

        int i = 1;
        // The local daemon entry, whose `runtimes` is the whole local map,
        // because a snapshot missing the worker's own row reports a daemon
        // smaller than it is.
        {
            sol::table d = m_lua.create_table();
            d["name"] = src.daemon_name;
            d["host"] = src.host;
            size_t count = 0;
            {
                std::shared_lock lock(mgr->mutex);
                count = mgr->list().size();
            }
            d["runtimes"] = static_cast<int>(count);
            result[i++] = d;
        }
        // Remote daemons
        for (const auto& rd : src.remote)
        {
            sol::table d = m_lua.create_table();
            d["name"] = rd.name;
            d["host"] = rd.host;
            d["runtimes"] = static_cast<int>(rd.runtimes.size());
            result[i++] = d;
        }
        return result;
    };

    // socketley.cluster.runtimes() → array of {daemon, name, type, port, group, state, connections}
    cluster_tbl["runtimes"] = [owner, this, resolve_cluster]() -> sol::table {
        sol::table result = m_lua.create_table();
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return result;
        const cluster_source src = resolve_cluster(mgr);
        if (!src.ok) return result;

        int i = 1;
        // Local runtimes, the row that decides whether a name-and-port
        // snapshot is enough, because it reads get_group() as well as the six
        // fields socketley.get() wants.
        {
            std::shared_lock lock(mgr->mutex);
            for (const auto& [name, inst] : mgr->list())
            {
                sol::table r = m_lua.create_table();
                r["daemon"] = src.daemon_name;
                r["name"] = std::string(name);
                r["type"] = type_to_string(inst->get_type());
                r["port"] = inst->get_port();
                r["group"] = std::string(inst->get_group());
                r["state"] = state_to_string(inst->get_state());
                r["connections"] = static_cast<int>(inst->reported_connection_count());
                result[i++] = r;
            }
        }
        // Remote runtimes
        for (const auto& rd : src.remote)
        {
            for (const auto& rt : rd.runtimes)
            {
                sol::table r = m_lua.create_table();
                r["daemon"] = rt.daemon_name;
                r["name"] = rt.name;
                r["type"] = rt.type;
                r["port"] = rt.port;
                r["group"] = rt.group;
                r["state"] = rt.state;
                r["connections"] = static_cast<int>(rt.connections);
                result[i++] = r;
            }
        }
        return result;
    };

    // socketley.cluster.group(name) → array of {daemon, host, port, connections}
    cluster_tbl["group"] = [owner, this, resolve_cluster](std::string group_name) -> sol::table {
        sol::table result = m_lua.create_table();
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return result;
        const cluster_source src = resolve_cluster(mgr);
        if (!src.ok) return result;

        int i = 1;
        // Local group members
        {
            std::shared_lock lock(mgr->mutex);
            for (const auto& [_, inst] : mgr->list())
            {
                if (inst->get_group() == group_name &&
                    inst->get_state() == runtime_running &&
                    inst->get_port() > 0)
                {
                    sol::table m = m_lua.create_table();
                    m["daemon"] = src.daemon_name;
                    // The advertised address and not 127.0.0.1, which a worker
                    // cannot derive and which no other node could reach.
                    m["host"] = src.host;
                    m["port"] = inst->get_port();
                    // The figure a least-connections choice is made on, which
                    // read 0 for a local member in a worker and so was always
                    // picked.
                    m["connections"] = static_cast<int>(inst->reported_connection_count());
                    result[i++] = m;
                }
            }
        }
        // Remote group members
        for (const auto& rd : src.remote)
        {
            for (const auto& rt : rd.runtimes)
            {
                if (rt.group == group_name && rt.state == "running" && rt.port > 0)
                {
                    sol::table m = m_lua.create_table();
                    m["daemon"] = rt.daemon_name;
                    m["host"] = rt.host;
                    m["port"] = rt.port;
                    m["connections"] = static_cast<int>(rt.connections);
                    result[i++] = m;
                }
            }
        }
        return result;
    };

    // socketley.cluster.stats() → {daemons, runtimes, running, groups={name=count}}
    cluster_tbl["stats"] = [owner, this, resolve_cluster]() -> sol::table {
        sol::table result = m_lua.create_table();
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return result;
        const cluster_source src = resolve_cluster(mgr);
        if (!src.ok) return result;

        int daemon_count = 1;  // include local
        int rt_total = 0;
        int rt_running = 0;
        std::unordered_map<std::string, int> groups;

        // Local runtimes
        {
            std::shared_lock lock(mgr->mutex);
            for (const auto& [_, inst] : mgr->list())
            {
                ++rt_total;
                if (inst->get_state() == runtime_running) ++rt_running;
                auto g = inst->get_group();
                if (!g.empty()) ++groups[std::string(g)];
            }
        }

        // Remote daemons
        for (const auto& rd : src.remote)
        {
            ++daemon_count;
            for (const auto& rt : rd.runtimes)
            {
                ++rt_total;
                if (rt.state == "running") ++rt_running;
                if (!rt.group.empty()) ++groups[rt.group];
            }
        }

        result["daemons"] = daemon_count;
        result["runtimes"] = rt_total;
        result["running"] = rt_running;

        sol::table grp_tbl = m_lua.create_table();
        for (const auto& [name, count] : groups)
            grp_tbl[name] = count;
        result["groups"] = grp_tbl;

        return result;
    };

    // socketley.storage in every runtime that has a script, because what it
    // needs is the request channel and every runtime has one.
    if (!m_storage_client)
        m_storage_client = std::make_unique<lua_storage_client>(*this, *owner);
    m_storage_client->install(m_lua, sk);
    if (!m_db_client)
        m_db_client = std::make_unique<lua_db_client>(*this, *owner);
    m_db_client->install(m_lua, sk);
    if (!m_mqtt_client)
        m_mqtt_client = std::make_unique<lua_mqtt_client>(*this, *owner);
    m_mqtt_client->install(m_lua, sk);
    if (!m_mail_client)
        m_mail_client = std::make_unique<lua_mail_client>(*this, *owner);
    m_mail_client->install(m_lua, sk);

    // Last and over the top of the bindings above, so the two builds differ in
    // one place and the list of what is refused is readable in one place.
    if (in_worker_process())
        refuse_cross_runtime_api(sk, cluster_tbl, owner);

    sk["cluster"] = cluster_tbl;

    m_lua["socketley"] = sk;

    // Register "self" table with runtime properties and actions
    sol::table self = m_lua.create_table();
    self["name"] = std::string(owner->get_name());
    self["port"] = owner->get_port();
    self["type"] = type_to_string(owner->get_type());
    self["state"] = state_to_string(owner->get_state());

    // Register type-specific action methods
    switch (owner->get_type())
    {
        case runtime_server:
            register_server_table(owner, self);
            break;
        case runtime_client:
            register_client_table(owner, self);
            break;
        case runtime_cache:
            register_cache_table(owner, self);
            break;
        case runtime_proxy:
            register_proxy_table(owner, self);
            break;
        case runtime_mqtt:
            socketley::mqtt::register_lua_table(owner, m_lua, self);
            break;
        case runtime_storage:
        case runtime_dns:
        case runtime_sync:
        case runtime_idp:
        case runtime_db:
        case runtime_mail:
        case runtime_tunnel:
        case runtime_metrics:
            // No verbs of their own yet.
            break;
    }

    m_lua["self"] = self;

    // Also register type-specific alias (server/client/cache/proxy) pointing to same table
    m_lua[type_to_string(owner->get_type())] = self;
}

// self.cache(command) -- the first call a script can make whose answer is not
// there yet.  Bound as a raw lua_CFunction and not through sol, because sol's
// wrappers return a value and this one has to yield: the answer arrives later,
// as this call's own return value, when the linked cache replies.
//
// Everything before the yield is POD on purpose.  luaL_checklstring raises by
// longjmp, which runs no destructor, so nothing here may own memory.
static int lua_await_cache(lua_State* L)
{
    auto* owner = static_cast<runtime_instance*>(lua_touserdata(L, lua_upvalueindex(1)));
    size_t n = 0;
    const char* cmd = luaL_checklstring(L, 1, &n);

    const char* why = owner ? owner->begin_cache_await(L, std::string_view(cmd, n))
                            : "this runtime is gone";
    if (why)
    {
        // Answered inline rather than raised: a script that asks a runtime with
        // no cache linked has made a mistake worth seeing, and one whose cache
        // is merely busy has not -- and `nil, reason` is the one shape that
        // reads the same for both.
        lua_pushnil(L);
        lua_pushstring(L, why);
        return 2;
    }
    return lua_yield(L, 0);
}

void lua_context::register_server_table(runtime_instance* owner, sol::table& self)
{
    // Pushed by hand because sol has no form for a function that yields; the
    // runtime travels as an upvalue, which is how the C function finds it
    // again without a global.
    {
        lua_State* L = m_lua.lua_state();
        self.push(L);
        lua_pushlightuserdata(L, owner);
        lua_pushcclosure(L, &lua_await_cache, 1);
        lua_setfield(L, -2, "cache");
        lua_pop(L, 1);
    }

    // broadcast_all() and not broadcast(), which is this process's
    // connection table and under --shards reaches a quarter of the clients
    // while reporting success.
    // Two values, because a broadcast that dropped a third of its recipients
    // for backlog used to look exactly like one that reached everybody.  Both
    // count this shard's connections -- see fanout_count for why that is the
    // right scope here and the wrong one for shard_connection_count().
    self["broadcast"] = [owner](std::string_view msg) {
        const auto c = owner->broadcast_all(msg);
        return std::make_tuple(static_cast<long>(c.taken),
                               static_cast<long>(c.backlogged));
    };
    // The same contract at the other door, because checking at one and not the
    // other teaches a script author that the check exists.
    self["send"] = [owner, this](int client_id,
                                 std::string_view msg) -> api_result {
        if (owner->is_udp())
            return api_why("a UDP server has no connection to send to; use "
                           "self.broadcast");
        if (owner->send_to(client_id, msg))
            return api_yes();
        // A fifth way, and the only one the script can do something about:
        // this runtime closed the connection because the producer outran the
        // socket.  Named apart from the other four, because "it may have
        // closed" reads as the peer's doing and the answer to this one is to
        // pace rather than to give up.
        if (static_cast<server_instance*>(owner)->closed_for_backlog(client_id))
            return api_why("connection " + std::to_string(client_id) + " on "
                           + q(m_owner_name) + " was closed because more was "
                             "queued for it than it could take -- self.pending("
                           + std::to_string(client_id) + ") is what to watch "
                             "before sending the next one");

        // Four ways this used to be a silent no-op: an id that is not a
        // connection, one already closing, a routed-in handle whose origin is
        // gone, and an origin that has stopped.
        return api_why("there is no open connection " + std::to_string(client_id)
                       + " on " + q(m_owner_name)
                       + " — it may have closed, or it may never have been one");
    };
    // How much this connection still owes the socket.  A producer with a large
    // body loops self.send(), and until now nothing told it when it was going
    // faster than the wire -- the queue filled, the runtime closed the
    // connection, and the message that did it was answered true.
    //
    // nil and not -1 for an id that is not a connection of this runtime, so a
    // caller cannot read "unknown" as "empty".
    self["pending"] = [owner](int client_id) -> sol::optional<long> {
        const long n = static_cast<server_instance*>(owner)->pending_bytes(client_id);
        if (n < 0) return sol::nullopt;
        return n;
    };
    // The number on_writable is defined against, so pacing does not mean
    // hardcoding it.  A producer that stops below this never crosses the
    // watermark and is never called back -- it would wait for an event it
    // prevented -- so this and the callback have to name one value.
    //
    // A CALL and not a field, on the same reasoning the cache's mode() gives:
    // --write-buffer is editable, and a number written into this table when
    // the script was loaded goes stale the moment it is edited.  Measured as a
    // field: `edit x --write-buffer 512K` moved the runtime's bound and the
    // script went on reading 4194304 until the runtime was restarted.
    self["watermark"] = [owner]() -> long {
        return static_cast<long>(owner->write_watermark_bytes());
    };

    // ─── A response written here rather than returned ───────────────────────
    // on_http_request has to return a complete body, so a generated response had
    // to fit in memory: a FILE of any size was already served by the splice path
    // and a generated one of any size was not expressible.  These three put a
    // script on the same side of the bound its reads already have, and they pace
    // through self.pending()/on_writable exactly as any other producer does --
    // a stream without backpressure is only a slower way to run out of memory.
    //
    //     self.respond_stream(id, 200, {["Content-Type"] = "text/csv"})
    //     ... self.send_chunk(id, row) ...
    //     self.end_response(id)
    self["respond_stream"] = [owner, this](int client_id, sol::optional<int> status,
                                           sol::optional<sol::table> headers) -> api_result {
        std::vector<std::pair<std::string, std::string>> hdrs;
        if (headers)
            for (const auto& kv : *headers)
            {
                // Skipped rather than refused: a header table with a number in
                // it is a script's slip, and dropping the pair leaves a valid
                // response where refusing the call would leave none.
                if (!kv.first.is<std::string>() || !kv.second.is<std::string>())
                    continue;
                hdrs.emplace_back(kv.first.as<std::string>(), kv.second.as<std::string>());
            }
        if (static_cast<server_instance*>(owner)->begin_chunked_response(
                client_id, status.value_or(200), hdrs))
            return api_yes();
        return api_why("cannot start a response on connection " + std::to_string(client_id)
                       + " of " + q(m_owner_name)
                       + " -- it may have closed, or a response may already have been"
                         " started on it");
    };
    self["send_chunk"] = [owner, this](int client_id, std::string_view data) -> api_result {
        if (static_cast<server_instance*>(owner)->send_response_chunk(client_id, data))
            return api_yes();
        // The three reasons named together, because only one of them is
        // recoverable and a script has to be able to tell which it met.
        return api_why("chunk refused on connection " + std::to_string(client_id)
                       + " of " + q(m_owner_name)
                       + " -- no response has been started on it, the request was a"
                         " HEAD and has no body, or more was queued for it than it"
                         " could take; self.pending(" + std::to_string(client_id)
                       + ") is what to watch before the next one");
    };
    self["end_response"] = [owner, this](int client_id) -> api_result {
        if (static_cast<server_instance*>(owner)->finish_chunked_response(client_id))
            return api_yes();
        return api_why("no response was open on connection " + std::to_string(client_id)
                       + " of " + q(m_owner_name));
    };

    // shard_connection_count() and not get_connection_count(), because under
    // --shards a script asking how many clients its runtime has was answered
    // with how many this process had.
    self["connections"] = [owner]() -> size_t {
        return static_cast<size_t>(owner->shard_connection_count());
    };
    self["protocol"] = owner->is_udp() ? "udp" : "tcp";

    // Client routing
    self["route"] = [owner](int client_id, std::string target) -> bool {
        return static_cast<server_instance*>(owner)->route_client(client_id, target);
    };
    self["unroute"] = [owner](int client_id) -> bool {
        return static_cast<server_instance*>(owner)->unroute_client(client_id);
    };
    self["get_route"] = [owner, this](int client_id) -> sol::object {
        auto route = static_cast<server_instance*>(owner)->get_client_route(client_id);
        if (route.empty()) return sol::nil;
        return sol::make_object(m_lua, std::string(route));
    };

    // Owner-targeted sending (sub-server → owner's clients)
    self["owner_send"] = [owner](int client_id, std::string_view msg) -> bool {
        return static_cast<server_instance*>(owner)->owner_send(client_id, msg);
    };
    self["owner_broadcast"] = [owner](std::string_view msg) -> bool {
        return static_cast<server_instance*>(owner)->owner_broadcast(msg);
    };

    // Connection control
    self["disconnect"] = [owner, this](
                                       int client_id) -> api_result {
        if (static_cast<server_instance*>(owner)->disconnect(client_id))
            return api_yes();
        return api_why("there is no open connection " + std::to_string(client_id)
                       + " on " + q(m_owner_name) + " to disconnect");
    };
    self["peer_ip"] = [owner](int client_id) -> std::string {
        return static_cast<server_instance*>(owner)->peer_ip(client_id);
    };
    self["ws_headers"] = [owner, this](int client_id) -> sol::object {
        auto h = static_cast<server_instance*>(owner)->ws_headers(client_id);
        if (!h.is_websocket) return sol::nil;
        sol::table t = m_lua.create_table();
        if (!h.cookie.empty())   t["cookie"]        = h.cookie;
        if (!h.origin.empty())   t["origin"]        = h.origin;
        if (!h.protocol.empty()) t["protocol"]      = h.protocol;
        if (!h.auth.empty())     t["authorization"] = h.auth;
        return t;
    };

    // Client enumeration
    self["clients"] = [owner, this]() -> sol::table {
        auto ids = static_cast<server_instance*>(owner)->clients();
        sol::table t = m_lua.create_table(static_cast<int>(ids.size()), 0);
        for (int i = 0; i < (int)ids.size(); ++i) t[i + 1] = ids[i];
        return t;
    };

    // A list with a hole in it is not a shorter list, so a non-integer entry
    // refuses the call rather than being dropped -- which is exactly what an
    // id that came back from json_decode as a string would be.
    self["multicast"] = [owner](sol::table ids,
                                std::string_view msg) -> api_result {
        std::vector<int> fds;
        for (size_t i = 1;; ++i)
        {
            sol::object v = ids[i];
            if (!v.valid() || v == sol::nil) break;
            if (v.get_type() != sol::type::number)
                return api_why("multicast list entry " + std::to_string(i)
                               + " is not a client id");
            const double d = v.as<double>();
            // A whole number an int holds, since a cast of one it does not is undefined.
            if (d != std::floor(d) || !(d >= INT_MIN && d <= INT_MAX))
                return api_why("multicast list entry " + std::to_string(i)
                               + " is not a whole number");
            fds.push_back(static_cast<int>(d));
        }
        if (fds.empty())
        {
            bool any = false;
            ids.for_each([&](sol::object, sol::object) { any = true; });
            if (any)
                return api_why("the multicast list has no entry at index 1 — "
                               "it is an array of client ids, not a keyed table");
        }
        else
        {
            size_t stray = 0;
            ids.for_each([&](sol::object k, sol::object)
            {
                if (!stray && k.get_type() == sol::type::number && k.as<double>() > static_cast<double>(fds.size()))
                    stray = fds.size() + 1;
            });
            if (stray)
                return api_why("the multicast list has no entry at index " + std::to_string(stray)
                               + " but has entries after it");
        }
        // The count, not a bool: every id was well formed, and how many still
        // name an open connection is the thing worth knowing.
        return api_count(static_cast<server_instance*>(owner)->multicast(fds, msg));
    };

    // Per-connection metadata: nil value deletes the key
    self["set_data"] = [owner, this](int id, std::string key,
                                     sol::optional<sol::object> val) -> api_result {
        // An empty key is a key nothing can read back, so storing under it is
        // a write that cannot be observed.
        if (key.empty())
            return api_why("the metadata key is empty");
        // The type is judged here and not by a sol::optional<std::string>,
        // whose failed check is indistinguishable from an absent argument, so
        // storing a number deleted the key and answered true.
        const bool has_val = val && val->valid()
                             && val->get_type() != sol::type::lua_nil
                             && val->get_type() != sol::type::none;
        // The same rule the empty KEY gets three lines up, for the same
        // reason: get_data() answers nil for an empty value, so storing one is
        // a write that cannot be observed -- it reads back exactly as "never
        // set" does, and the call answered true.
        if (has_val && val->get_type() == sol::type::string
            && val->as<std::string>().empty())
            return api_why("the metadata value is empty, and get_data cannot "
                           "tell that from a key that was never set; pass nil "
                           "to delete the key");
        if (has_val && val->get_type() != sol::type::string)
            return api_why("the metadata value is a "
                           + std::string(lua_typename(
                                 m_lua.lua_state(),
                                 static_cast<int>(val->get_type())))
                           + "; a string is stored and nil deletes the key");
        auto* srv = static_cast<server_instance*>(owner);
        const bool ok = has_val ? srv->set_data(id, key, val->as<std::string>())
                                : srv->del_data(id, key);
        if (ok) return api_yes();
        return api_why("there is no open connection " + std::to_string(id)
                       + " on " + q(m_owner_name) + " to carry metadata");
    };
    self["get_data"] = [owner, this](int id, std::string key) -> sol::object {
        auto v = static_cast<server_instance*>(owner)->get_data(id, key);
        if (v.empty()) return sol::nil;
        return sol::make_object(m_lua, v);
    };

    // Upstream actions
    self["upstream_send"] = [owner](int conn_id,
                                    std::string_view msg) -> api_result {
        auto* srv = static_cast<server_instance*>(owner);
        if (srv->upstream_send(conn_id, msg))
            return api_yes();
        // A second reason, and the one this used to answer with the first: an
        // upstream whose queue reached the bound has `closing` set and
        // `connected` still true, so "is not connected" was false AND every
        // later send answered true for ever while nothing left the process.
        if (srv->upstream_closed_for_backlog(conn_id))
            return api_why("upstream " + std::to_string(conn_id)
                           + " was closed because more was queued for it than it "
                             "could take -- self.upstream_pending("
                           + std::to_string(conn_id)
                           + ") is what to watch before sending the next one");
        return api_why("upstream " + std::to_string(conn_id)
                       + " is not connected — self.upstreams() lists the ones "
                         "that are");
    };
    // Two numbers, like the client-facing broadcast's and for the same reason:
    // a fan-out that dropped half its targets used to be indistinguishable
    // from one that reached all of them.
    self["upstream_broadcast"] = [owner](std::string_view msg) {
        const auto c = static_cast<server_instance*>(owner)->upstream_broadcast(msg);
        return std::make_tuple(static_cast<long>(c.taken),
                               static_cast<long>(c.backlogged));
    };
    // The upstream side of self.pending(), as its own call because an upstream
    // id and a client id are different spaces: nil for an id that is not one of
    // this runtime's upstreams, so a caller cannot read "unknown" as "empty".
    self["upstream_pending"] = [owner](int conn_id) -> sol::optional<long> {
        const long n = static_cast<server_instance*>(owner)->upstream_pending(conn_id);
        if (n < 0) return sol::nullopt;
        return n;
    };
    self["upstreams"] = [owner, this]() -> sol::table {
        auto ids = static_cast<server_instance*>(owner)->upstreams();
        sol::table t = m_lua.create_table(static_cast<int>(ids.size()), 0);
        for (int i = 0; i < (int)ids.size(); ++i) t[i + 1] = ids[i];
        return t;
    };

    // An empty group name is refused at all three doors rather than at none,
    // because no client can be reached by it.
    self["join_group"] = [owner, this](int fd,
                                       std::string group) -> api_result {
        if (group.empty()) return api_why("the group name is empty");
        if (static_cast<server_instance*>(owner)->join_group(fd, group))
            return api_yes();
        return api_why("there is no open connection " + std::to_string(fd)
                       + " on " + q(m_owner_name) + " to put in a group");
    };
    self["leave_group"] = [owner, this](int fd,
                                        std::string group) -> api_result {
        if (group.empty()) return api_why("the group name is empty");
        if (static_cast<server_instance*>(owner)->leave_group(fd, group))
            return api_yes();
        return api_why("there is no open connection " + std::to_string(fd)
                       + " on " + q(m_owner_name));
    };
    // The count, for the reason group_send gives: a group that exists and is
    // empty is what a misspelled name looks like once its last real member has
    // left, and a bool cannot tell that from a group that is full.
    self["group_send"] = [owner](std::string group,
                                 std::string_view msg) -> api_result {
        if (group.empty()) return api_why("the group name is empty");
        return api_count(static_cast<server_instance*>(owner)->group_send(group, msg));
    };

    // Zero-copy pipe pairing
    self["pipe"] = [owner, this](int fd_a,
                                 int fd_b) -> api_result {
        if (fd_a == fd_b)
            return api_why("a pipe joins two connections, and those are one");
        if (static_cast<server_instance*>(owner)->pipe(fd_a, fd_b))
            return api_yes();
        return api_why("one of " + std::to_string(fd_a) + " and "
                       + std::to_string(fd_b) + " is not an open connection on "
                       + q(m_owner_name));
    };
    self["unpipe"] = [owner](int fd) -> api_result {
        if (static_cast<server_instance*>(owner)->unpipe(fd))
            return api_yes();
        return api_why("connection " + std::to_string(fd) + " is not piped");
    };

    // self.route() escaped the socketley.* refusals only because it is spelled
    // self., and it is grouped with socketley.pipe rather than the reads --
    // while unroute(), get_route() and owner_send() answer from this runtime's
    // own empty tables, where false is the truth.
    // ─── AND WHAT IT IS NOW ────────────────────────────────────────────────
    // The channel exists now and the test is the sink rather than the process,
    // with the paragraphs above left standing as the record of one call
    // refused for three stated reasons, two of them wrong.
    const runtime_manager* rmgr = owner ? owner->get_runtime_manager() : nullptr;
    if (in_worker_process() && (!rmgr || !rmgr->route_sink()))
    {
        sol::function make = refusal_factory(m_lua);
        if (make.valid())
        {
            sol::function f = make(worker_route_refusal());
            self["route"] = f;
        }
        else
        {
            std::cerr << lua_diag::tag(m_owner_name)
                      << " could not install the out-of-process refusal for "
                         "self.route; it is left bound and will answer false"
                      << std::endl;
        }
    }
}

void lua_context::register_client_table(runtime_instance* owner, sol::table& self)
{
    // Same contract as the server's mutators, and the same three silent
    // no-ops behind it: a client that has not connected yet, one whose server
    // has dropped it, and one created --mode in, which does not send at all.
    self["send"] = [owner, this](
                                 std::string_view msg) -> api_result {
        if (owner->lua_send(msg))
            return api_yes();
        // A fourth reason, named apart from the three above for the same
        // cause as on the server: the sentence for a missing connection is
        // the wrong one for a connection that is merely behind, and only one
        // of the two is something a script can act on.
        if (static_cast<client_instance*>(owner)->write_backlogged())
            return api_why(q(m_owner_name) + " has more queued for its server "
                           "than it could take -- self.pending() is what to "
                           "watch before sending the next one");
        return api_why(q(m_owner_name) + " is not connected to its server, "
                       "or was created --mode in and does not send");
    };
    // As on the server, minus the id: this runtime has one connection.
    self["pending"] = [owner]() -> long {
        return static_cast<client_instance*>(owner)->pending_bytes();
    };
    self["watermark"] = [owner]() -> long {
        return static_cast<long>(owner->write_watermark_bytes());
    };
    // One runtime's connections and not one process's; see the note on the
    // server's copy of this binding, in register_server_table above.
    self["connections"] = [owner]() -> size_t {
        return static_cast<size_t>(owner->shard_connection_count());
    };
    self["protocol"] = owner->is_udp() ? "udp" : "tcp";
}

void lua_context::register_cache_table(runtime_instance* owner, sol::table& self)
{
    // Which mode this cache is in, as a CALL and not a field: --mode is
    // editable, and a field written when the table was built would go stale the
    // way self.state did.  It is how a script tells a refusal from a call that
    // had nothing to do, since every mutating entry below answers the same for
    // both.
    self["cache_mode"] = [owner]() -> std::string {
        return std::string(owner->lua_cache_mode());
    };

    // Whether THIS process is the one that holds `key`.  Under --shards the
    // script below runs in all N of them and each acts only on the slice it
    // owns, so every mutating entry in this table answers a foreign key the
    // same way it answers a refusal -- and this is how a script tells the two
    // apart, exactly as cache_mode() does for the readonly case.  Always true
    // on a cache that is one process, so a script reads the same on either.
    self["owns"] = [owner](std::string key) -> bool {
        return owner->lua_cache_owns(key);
    };

    // Strings
    self["get"] = [owner](std::string key) -> std::string {
        return owner->lua_cache_get(key);
    };
    self["set"] = [owner](std::string key, std::string value) -> bool {
        return owner->lua_cache_set(key, value);
    };
    self["del"] = [owner](std::string key) -> bool {
        return owner->lua_cache_del(key);
    };
    // self.get() answers "" for a key that is not there AND for one holding an
    // empty string, which no script can tell apart -- see lua_cache_exists in
    // runtime_instance.h for why the answer is this binding rather than a
    // change to get().
    self["exists"] = [owner](std::string key) -> bool {
        return owner->lua_cache_exists(key);
    };

    // Lists
    self["lpush"] = [owner](std::string key, std::string val) -> bool {
        return owner->lua_cache_lpush(key, val);
    };
    self["rpush"] = [owner](std::string key, std::string val) -> bool {
        return owner->lua_cache_rpush(key, val);
    };
    self["lpop"] = [owner](std::string key) -> std::string {
        return owner->lua_cache_lpop(key);
    };
    self["rpop"] = [owner](std::string key) -> std::string {
        return owner->lua_cache_rpop(key);
    };
    self["llen"] = [owner](std::string key) -> int {
        return owner->lua_cache_llen(key);
    };

    // Sets
    // sol::optional, so a refusal is nil rather than -1.  In Lua every number
    // is true, so `if self.sadd(k, m) then` was taken on a readonly cache that
    // had added nothing -- the one value in this whole table where the refusal
    // was TRUTHY.  1 and 0 still mean added and already-present, as they do
    // over the wire.
    self["sadd"] = [owner](std::string key,
                           std::string member) -> sol::optional<int> {
        const int added = owner->lua_cache_sadd(key, member);
        if (added < 0)
            return sol::nullopt;
        return added;
    };
    self["srem"] = [owner](std::string key, std::string member) -> bool {
        return owner->lua_cache_srem(key, member);
    };
    self["sismember"] = [owner](std::string key, std::string member) -> bool {
        return owner->lua_cache_sismember(key, member);
    };
    self["scard"] = [owner](std::string key) -> int {
        return owner->lua_cache_scard(key);
    };

    // Hashes
    self["hset"] = [owner](std::string key, std::string field, std::string val) -> bool {
        return owner->lua_cache_hset(key, field, val);
    };
    self["hget"] = [owner](std::string key, std::string field) -> std::string {
        return owner->lua_cache_hget(key, field);
    };
    self["hexists"] = [owner](std::string key, std::string field) -> bool {
        return owner->lua_cache_hexists(key, field);
    };
    self["hdel"] = [owner](std::string key, std::string field) -> bool {
        return owner->lua_cache_hdel(key, field);
    };
    self["hlen"] = [owner](std::string key) -> int {
        return owner->lua_cache_hlen(key);
    };

    // TTL
    self["expire"] = [owner](std::string key, int seconds) -> bool {
        return owner->lua_cache_expire(key, seconds);
    };
    self["ttl"] = [owner](std::string key) -> int {
        return owner->lua_cache_ttl(key);
    };
    self["persist"] = [owner](std::string key) -> bool {
        return owner->lua_cache_persist(key);
    };

    // Pub/Sub
    self["publish"] = [owner](std::string channel, std::string message) -> int {
        return owner->lua_cache_publish(channel, message);
    };

    // One runtime's connections and not one process's; see the note on the
    // server's copy of this binding, in register_server_table above.
    self["connections"] = [owner]() -> size_t {
        return static_cast<size_t>(owner->shard_connection_count());
    };
}

void lua_context::register_proxy_table(runtime_instance* owner, sol::table& self)
{
    auto* proxy = static_cast<proxy_instance*>(owner);

    // One runtime's connections and not one process's; see the note on the
    // server's copy of this binding, in register_server_table above.
    self["connections"] = [owner]() -> size_t {
        return static_cast<size_t>(owner->shard_connection_count());
    };
    self["protocol"] = proxy->get_protocol() == protocol_http ? "http" : "tcp";
    self["peer_ip"] = [proxy](int client_id) -> std::string {
        return proxy->peer_ip(client_id);
    };
    self["close_client"] = [proxy](
                                   int client_id) -> api_result {
        if (proxy->close_client(client_id))
            return api_yes();
        // Both halves of a proxied pair are ints, and handing this the backend
        // half is the mistake a script makes; it used to do nothing at all.
        return api_why("there is no open client connection "
                       + std::to_string(client_id)
                       + " on this proxy — self.clients() lists the ones "
                         "there are");
    };
    self["clients"] = [proxy, this]() -> sol::table {
        auto ids = proxy->clients();
        sol::table t = m_lua.create_table(static_cast<int>(ids.size()), 0);
        for (int i = 0; i < (int)ids.size(); ++i) t[i + 1] = ids[i];
        return t;
    };
    self["backends"] = [proxy, this]() -> sol::table {
        auto addrs = proxy->backends();
        sol::table t = m_lua.create_table(static_cast<int>(addrs.size()), 0);
        for (int i = 0; i < (int)addrs.size(); ++i) t[i + 1] = addrs[i];
        return t;
    };
    self["backend_health"] = [proxy, this]() -> sol::table {
        auto health = proxy->backend_health_report();
        sol::table t = m_lua.create_table(0, static_cast<int>(health.size()));
        for (const auto& [idx, state] : health)
            t[idx + 1] = state;
        return t;
    };
    self["stats"] = [proxy, this]() -> sol::table {
        sol::table t = m_lua.create_table(0, 6);
        // The same figure self.connections() answers, because two members of
        // one API disagreeing about one number is worse than either answer
        // alone.
        t["connections"] = static_cast<size_t>(proxy->shard_connection_count());
        // worker_figures(), not the four atomics: for a runtime in a worker
        // these are summed out of the shared table at this instant, which is
        // what makes a script's answer the same one `stats` prints.
        const shard_stats::figures f = proxy->worker_figures();
        t["bytes_in"] = f.bytes_in;
        t["bytes_out"] = f.bytes_out;
        t["total_connections"] = f.total_connections;
        t["total_messages"] = f.total_messages;
        auto addrs = proxy->backends();
        t["backend_count"] = addrs.size();
        return t;
    };
}

#endif // SOCKETLEY_NO_LUA
