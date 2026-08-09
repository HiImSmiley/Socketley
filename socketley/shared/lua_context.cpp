#include "lua_context.h"
#include "lua_json.h"

// Outside the SOCKETLEY_NO_LUA guard: the no-Lua SDK compiles this file too,
// and the callers that read a load failure back are not conditional on Lua.
namespace lua_diag
{
    // Thread-local, which is what makes this safe where a cerr swap is not.
    // A CLI command runs on the daemon's own thread and each worker has its
    // own; nothing here is shared and nothing needs a lock.
    static thread_local std::string s_text;

    void clear() { s_text.clear(); }
    const std::string& text() { return s_text; }

    void record(std::string_view line)
    {
        if (!s_text.empty()) s_text += '\n';
        s_text += line;
    }

    // See the declaration.  The empty name is not an error case — the daemon's
    // own configuration file and the SOCKETLEY_LUA_TIMEOUT_MS parse are Lua
    // diagnostics belonging to no runtime, and "[lua]" is what they mean.
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

#include "runtime_instance.h"
#include "runtime_definitions.h"
#include "runtime_manager.h"
#include "logging.h"
#include "cluster_discovery.h"
#include "event_loop.h"
#include "../runtime/server/server_instance.h"
#include "../runtime/proxy/proxy_instance.h"
#include "../cli/command_hashing.h"
#include "../cli/runtime_type_parser.h"
#include <iostream>
#include <algorithm>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <cerrno>
#include <charconv>
#include <chrono>
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
//
// See lua_context.h for what this is and why it has this shape.  What lives
// here is the state it is enforced through.
namespace lua_deadline
{
// How many VM instructions between hook calls.
//
// The hook's whole body on the ordinary path is one clock read and one
// comparison — steady_clock::now() is a vDSO read on this platform, about 20ns
// — so at this count it costs on the order of 20ns per 10,000 instructions,
// which is noise beside the interpreter itself.  It is also 100,000 times finer
// than the smallest deadline anyone would set, so the granularity of the check
// is never what decides when a runaway is caught.
//
// The real cost of having a hook at all is elsewhere and is not tunable by this
// number: LuaJIT drops the state to the interpreter while a count or line hook
// is installed, because a compiled trace does not call back out.  That is the
// price of being able to interrupt a `while true do end` at all — a trace with
// no hook in it cannot be stopped from inside — and it is why installing
// nothing when the deadline is off is worth the branch.
static constexpr int hook_count = 10000;

// ── The armed invocation ────────────────────────────────────────────────────
//
// Thread-local, not per-interpreter.  The daemon serves every runtime from one
// thread and each worker has one of its own, so this is per event loop, which
// is the resource the deadline exists to protect.  Nesting across interpreters
// then works out to the right thing on its own: a publish that runs another
// runtime's subscriber spends the budget of the callback that published.
static thread_local unsigned                              t_depth{0};
static thread_local std::chrono::steady_clock::time_point t_deadline{};
static thread_local const char*                           t_what{nullptr};
// Which runtime's script the armed invocation belongs to; null for the two
// that belong to none.  Set and cleared beside t_what, which makes the pairing
// impossible to get half right.
static thread_local const char*                           t_runtime{nullptr};
static thread_local uint32_t                              t_limit_ms{0};
// Whether this invocation has already been reported.  The hook raises every
// time it fires past the deadline, but says so once: a script that wraps its
// own runaway in pcall() swallows the first error and is raised in again a few
// thousand instructions later, and that must stop the script without also
// filling the log with one line per raise.
static thread_local bool                                  t_reported{false};
// How many callback invocations are on this thread's stack, counted whether or
// not the deadline is armed.  t_depth cannot answer that question: it stays 0
// when the mechanism is off, deliberately, because remaining_ms() has to keep
// answering -1 so socketley.http keeps the timeout the script asked for.  See
// in_callback() in the header for who asks and why the difference matters.
static thread_local unsigned                              t_frames{0};

uint32_t default_ms()
{
    // Read once.  A getenv per lua_context would be a syscall-free but still
    // pointless string parse on a path that runs at every create.
    static const uint32_t value = [] () -> uint32_t {
        const char* e = std::getenv("SOCKETLEY_LUA_TIMEOUT_MS");
        if (!e || !*e)
            return builtin_default_ms;

        // Anything that is not a number is a typo in an operator's unit file,
        // and silently falling back to the default would hide it.  Anything
        // negative is the same.  0 is meaningful: it turns the deadline off.
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
    // Unconditional, and reset at the boundary rather than decremented, for the
    // reason the destructor gives about t_depth: a path that skips an inner
    // destructor must not leave this stuck above zero.  Stuck here is quieter
    // than a stuck deadline and worse — nothing would ever be freed on the spot
    // again, and a create/remove churn would grow the graveyard until the health
    // timer's two-second sweep became the only thing draining it.
    ++t_frames;

    if (m_outermost)
    {
        t_deadline = std::chrono::steady_clock::now()
                   + std::chrono::milliseconds(limit_ms);
        t_what     = what;
        t_runtime  = runtime;
        t_limit_ms = limit_ms;
        t_reported = false;
    }
    // Counted even when this scope did not arm, so that the matching destructor
    // does not have to decide anything and an inner scope can never disarm the
    // outer one's deadline.  A scope constructed while the deadline is off does
    // not arm and does not count: t_depth stays 0, remaining_ms() stays -1, and
    // socketley.http keeps the timeout the script asked for.
    if (t_depth != 0 || m_outermost)
        ++t_depth;
}

scope::~scope() noexcept
{
    // The outermost scope resets rather than decrements, and that is the one
    // thing in here that has to be true no matter what happened inside it.  A
    // leaked depth would leave the deadline armed and already expired after the
    // callback that armed it had returned — so the NEXT callback, an innocent
    // one, would be stopped on its first hook fire, and so would every callback
    // after that.  Decrementing makes that outcome reachable from any path that
    // skips an inner destructor; resetting at the boundary does not.
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

    // Same rule, same reason, on the frame count.  The outermost frame is the
    // one that knows the stack is about to be empty of callbacks, so it says so
    // outright instead of trusting that every inner scope was unwound.
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
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                    t_deadline - std::chrono::steady_clock::now()).count();
    if (left < 0)          return 0;
    if (left > INT_MAX)    return INT_MAX;
    return static_cast<long>(left);
}

// The hook.  Runs on the hot path of every script, so the ordinary return is
// two loads and a compare.
//
// ─── It reports before it raises, and that is still worth a line ────────────
//
// This used to be the only report there was.  Every callback was invoked inside
// a `catch (const sol::error&)`, and that catch only ever fired because sol2's
// panic handler happens to throw and the throw happens to unwind out of the
// interpreter — which it does not in the Sanitize build, so the diagnostic was
// dead in exactly the configuration the nightly job uses.
//
// 07baee7..b868bb5 removed every one of those catches and made the calls
// protected, so a deadline now arrives at the call site as an invalid result
// and IS reported there, in both builds, with the script and line attached —
// which this line cannot know.  That is the primary report now, and it is the
// one to read.
//
// This line stays because one path still has nothing else.  A script that
// wraps its own slow work in pcall() — `local ok = pcall(fetch_all)` is an
// ordinary thing to write — catches the deadline error itself, and the call
// site never sees a failure to report; without this the runtime would simply
// stop making progress with nothing in the log to say why.
//
// It used to be two.  on_http_request was the one callback the sweep did not
// reach — still a sol::function, its call site checking nothing at all — so a
// deadline there was invisible unless it was written here.  It is a protected
// call now and its call site reports like the rest.
//
// So it is deliberately short, and deliberately not a copy of the error text:
// this line is the event, the call site's line is the diagnosis.
//
// No C++ object with a destructor is alive at the raise: lua_error unwinds by
// whatever means LuaJIT was built for, and a std::string here would be the one
// allocation that leaks when that turns out to be longjmp.
//
// The deadline is NOT pushed forward after it fires, and that is deliberate.
// Leaving it expired means the hook raises again on the next few thousand
// instructions, which is what closes the obvious way around this: a script that
// writes `while true do pcall(spin) end` swallows the raise inside pcall, and
// the only thing that ends it is the next raise landing on the outer loop
// instead.  The hook count is a global countdown rather than a per-frame one,
// so it lands there within a few thousand fires — a fraction of a second — and
// the invocation ends.  A grace period after each fire would give the protected
// frame all of it and the outer loop none, and never end.
static void hook(lua_State* L, lua_Debug*)
{
    if (t_depth == 0)
        return;
    if (std::chrono::steady_clock::now() < t_deadline)
        return;

    const char*    what = t_what ? t_what : "a callback";
    const unsigned ms   = t_limit_ms;

    if (!t_reported)
    {
        t_reported = true;
        // Two formats rather than one built with lua_diag::tag(): that returns
        // a std::string, and the paragraph above is about what may be alive
        // when luaL_error unwinds by whatever means LuaJIT was built for.
        // Nothing here allocates.
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

void install(lua_State* L, uint32_t limit_ms)
{
    if (limit_ms == 0)
    {
        // Off means off, down to not paying for it: with no count hook LuaJIT
        // compiles again.  An operator who has measured the hook and decided
        // against it gets the interpreter they had before this existed.
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

lua_context::lua_context()
{
    m_lua.open_libraries(sol::lib::base, sol::lib::string, sol::lib::table,
                         sol::lib::math, sol::lib::os, sol::lib::io,
                         sol::lib::package);

    // ─── THIS IS NOT A SANDBOX, AND SAYING SO IS THE POINT ──────────────────
    //
    // What used to be here removed five names — os.execute, os.remove,
    // os.rename, os.tmpname, os.exit — under the heading "dangerous os
    // functions".  Four of those five bought nothing.  `io` is open, so
    // io.popen("...") is a shell and io.open(path, "w") truncates any file this
    // uid can write; `package` is open, so package.loadlib maps arbitrary
    // native code; `base` is open, so load/loadstring/dofile/loadfile compile
    // anything a handler can produce.  Removing os.execute while io.popen sits
    // beside it does not deny a capability, it hides where the capability is.
    //
    // That is worse than leaving it alone.  A script author who sees os.remove
    // come back nil concludes the daemon protects its files, and it does not.
    // Anyone deciding whether to accept a handler from a colleague was reading
    // a boundary that was never enforced anywhere.
    //
    // And the capability is not one to take away.  Handlers legitimately read
    // and write files — a logging pipeline appends, a config-driven handler
    // reads its table off disk — so closing `io` would break supported use for
    // the sake of a fence with a gate next to it.
    //
    // THE HONEST STATEMENT, which the man page now carries in these words: a
    // Lua handler runs with the daemon's full privileges.  Treat a handler the
    // way you would treat a program you are about to run as that user, because
    // that is what it is.  What keeps an untrusted local user from supplying
    // one is the permission on the IPC socket — see daemon_handler::setup() —
    // not anything in this interpreter.
    //
    // ─── WHAT IS STILL REMOVED, AND ON WHAT GROUNDS ─────────────────────────
    //
    // Two names, and the test is not "could a script misuse this" — every name
    // here fails that test.  It is: does ONE call damage the process that every
    // other runtime shares, in a way no other single call does?  That is a
    // guard against an accident in a handler that is trusted, which is a real
    // thing to want and is not a security claim.
    //
    // os.exit() ends the daemon.  A handler is very often a standalone script
    // that grew into one, and standalone scripts end with os.exit; copied in as
    // written it takes down every runtime in the process, from inside a
    // callback, with no error anywhere.  Yes, a determined script can reach the
    // same end through io.popen and a signal — that is the point of the
    // paragraphs above — but it cannot reach it by accident.
    m_lua["os"]["exit"] = sol::nil;

    // ─── os.setlocale, which reaches further than any name yet named ─────────
    //
    // It is the one that damages every other runtime in the daemon without the
    // script doing anything else at all.
    //
    // setlocale(LC_ALL, ...) is process-wide, and this daemon serves every
    // runtime from one process.  Two of its own primitives read the C locale:
    // socketley.json_encode formats numbers with "%.14g" and json_decode parses
    // them with std::stod, both of which take the decimal separator from
    // LC_NUMERIC.  Measured, with a de_DE.UTF-8 locale available:
    //
    //     before                snprintf("%.14g", 1.5) -> "1.5"
    //     os.setlocale("de_DE.UTF-8")
    //     after                 snprintf("%.14g", 1.5) -> "1,5"
    //                           strtod("1.5")          -> 1.0
    //
    // So one line in one script turns every other script's JSON into something
    // no JSON parser accepts, and makes every number it decodes truncate at the
    // decimal point — silently, with no error anywhere, and for as long as the
    // daemon lives.  A cache holding "1,5" does not become "1.5" again when the
    // script that did it is removed.
    //
    // Removed rather than wrapped, for the same reason as os.exit above and
    // because there is nothing to wrap it down to: the legitimate uses of a
    // locale are reads, and os.date, os.time and os.clock — which stay — are
    // the reads.  Nothing a script in this tree does needs to CHANGE the
    // process's idea of how a number is spelled.
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
    // True for exactly as long as `fn` is on the stack below.  Read by
    // sever_timer(), which must not replace a callable that is executing; see
    // the note there.
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
        // A timer body is a callback invocation like any other — it runs on the
        // event-loop thread, from a completion, and holds it for as long as it
        // runs.  The budget comes from the context that registered it, so a
        // script that set callback_timeout_ms gets the same answer here as in
        // on_message.  A timer whose context has already been severed (ctx null:
        // see the destructor) has nothing left to run, and fn is nil by then.
        //
        // The scope brackets the call and nothing else: a deadline that expires
        // in here comes back as an invalid result, and b62d58d's branch below
        // is already the right place for it to be reported.
        {
            lua_deadline::scope guard("a socketley.set_timeout/set_interval callback",
                                      ctx ? ctx->callback_timeout_ms() : 0u,
                                      ctx ? ctx->owner_name().c_str() : nullptr);
            // The flag brackets the call and nothing else.  A callback may
            // cancel its own timer — clear_interval(id) from inside the
            // interval is the one-shot shape — and sever_timer() has to be able
            // to tell that this is the timer it is being asked to sever.
            dispatching = true;
            sol::protected_function_result tr = fn();
            dispatching = false;
            if (SOCKETLEY_UNLIKELY(!tr.valid()))
            {
                sol::error e = tr;
                fprintf(stderr, "%s timer error: %s\n",
                        lua_diag::tag(ctx ? std::string_view(ctx->owner_name())
                                          : std::string_view{}).c_str(), e.what());
            }
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
//
// c1f45ba built this in ~lua_context and 1928eb4/ebb6897 generalised it to
// cancel_timers(); it is one function now because clear_timeout and
// clear_interval need exactly it and used to perform a weaker thing instead.
//
// The order is the reasoning, and it is written out at cancel_timers():
//
//   * the sol::function goes first, so a completion already in flight cannot
//     call into Lua.  It is also what releases the closure's registry
//     reference — until it does, the callback and everything it captured are
//     reachable from C++ and no collectgarbage() can free them.  The one
//     exception is a timer severed from inside its own callback; see below.
//   * `ctx` goes second, so lua_timer::on_cqe takes its terminal `delete this`
//     path rather than calling two methods on a context that has either
//     already given this timer away or is about to be destroyed.
//   * deregister_owner is deliberately NOT called here.  event_loop.h: a
//     handler that frees itself from inside its own on_cqe must deregister
//     THERE, because deregistering while its last completion is in flight has
//     that completion dropped and the callback that would have freed it never
//     runs.  on_cqe already does it in the right place.
//
// The withdrawal at the end is the part clear_timeout/clear_interval were
// missing.  They set `cancelled` and `repeat` and stopped, which is enough to
// keep the callback from running — the existing tests pin that — but the
// timeout stayed armed, so the lua_timer, its closure and its owner
// registration all stayed alive until it expired on its own.  Cancelling a
// one-hour interval kept every one of them for the hour.
//
// Guarded on ring_open() rather than merely on a non-null loop: ~lua_context
// reaches this at process teardown, by which time shutdown_ring() has been
// called, and a submission then is a submission into a ring that is gone.
static void sever_timer(lua_timer* t)
{
    // ─── Unless it is the callback doing the severing ───────────────────────
    //
    // `clear_interval(id)` from inside that interval's own callback is how a
    // one-shot subscriber to time is written, and `socketley.stop(self.name)`
    // from a timer reaches cancel_timers() the same way.  In both, `fn` is the
    // function currently executing, and sol's call reads members of the object
    // it was invoked through after lua_pcall returns — so replacing it here
    // took the daemon down with a SIGSEGV on that very tick.  Measured on this
    // branch before the flag existed: three ticks, "IV cleared", then nothing.
    //
    // Skipping the assignment costs nothing.  `ctx` and the two flags below are
    // still cleared, so lua_timer::on_cqe takes its terminal branch the moment
    // the callback returns and deletes the timer there — and ~lua_timer
    // releases the reference at that point, a few instructions later than this
    // line would have.
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
    // An active timer outlives this context, and has to.  Its io_request lives
    // inside the lua_timer, which is its own heap allocation and its own
    // io_handler — so the storage the ring is still reading is NOT the storage
    // being freed here, and there is nothing to defer or quarantine the way
    // daemon_handler defers a retired proxy_supervisor.  What this destructor
    // owes the timer is severance, and it used to perform only half of it.
    //
    // It nilled the sol::function, which is why a completion could not call into
    // a closed Lua state.  It left `ctx` pointing here — and lua_timer::on_cqe
    // reaches through that pointer on every path it has, to unregister_timer()
    // and timer_pool_release(), both of them methods on this object.  So a
    // `reload-lua`, or a second load_lua_script(), on any script that called
    // set_interval left a live registration naming a timer that would call two
    // methods on freed memory the next time it fired.  Under ASan that is an
    // abort one tick after the reload; without it, the replacement context is
    // allocated at exactly this size immediately afterwards, so the stale
    // completion edits the new context's timer tables about as often as it
    // touches an unmapped page.
    //
    // deregister_owner() is deliberately NOT called here, and that is not an
    // omission.  event_loop.h: a handler that frees itself from inside its own
    // on_cqe must deregister THERE and not earlier, because deregistering while
    // its last completion is in flight has that completion dropped, and the
    // callback that would have freed the handler never runs.  on_cqe already
    // does it in the right place, and the `else delete this` beside it is the
    // terminal path a null ctx selects — which is what this severance is handing
    // the timer to.  runtime_instance does the identical thing to its tick timer
    // (`m_tick->rt = nullptr` in reload_lua_script), for the identical reason.
    cancel_timers();

    // Free all pooled timers.  These are safe to delete outright: a timer only
    // reaches the pool from inside its own on_cqe, after that completion has
    // reported, so the ring owes them nothing.
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

// How many spent lua_timers this context keeps to hand back out.
//
// The pool exists so that a script arming a timer per message does not allocate
// one per message, and a handful of slots buys all of that.  It had no bound,
// and a pool without one is not a pool: a script that arms two thousand
// timeouts at once — a fan-out, a retry sweep, a batch of deadlines — leaves
// two thousand lua_timers in this vector after they fire, and they stay for the
// life of the context because nothing ever shrinks it.  Retention at the
// high-water mark is a strange thing to pay for a cache of empty objects.
//
// 64 because the concurrency this is worth optimising for is a script's steady
// state, not its worst burst, and past that the allocator is the right thing to
// be using.  A lua_timer is small, so the cap is about the shape rather than
// the bytes: a bound that exists is what makes the memory a script can hold
// this way a function of its steady state instead of its peak.
static constexpr size_t timer_pool_max = 64;

void lua_context::timer_pool_release(void* t)
{
    auto* timer = static_cast<lua_timer*>(t);

    // Freed rather than pooled once the pool is full.  Safe in exactly the way
    // the pooling is: this is only ever reached from inside the timer's own
    // on_cqe, after that completion has been reported and after
    // deregister_owner, so the ring owes this object nothing — which is why the
    // branch beside this call site can already write `delete this`.
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

static const char* state_to_string(runtime_state s)
{
    switch (s)
    {
        case runtime_created: return "created";
        case runtime_running: return "running";
        case runtime_stopped: return "stopped";
        case runtime_failed:  return "failed";
    }
    return "unknown";
}

// One load-time refusal: into the daemon's log, and into the buffer the command
// that asked for this load reads back.  Every `return false` in load_script and
// in the two declaration validators goes through here, because every one of
// them is a sentence written for the person editing the script — and until now
// not one of them could reach them.
//
// See the declaration for why only one of the two halves carries the name.
void lua_context::load_diag(const std::string& msg) const
{
    std::cerr << lua_diag::tag(m_owner_name) << ' ' << msg << std::endl;
    lua_diag::record(msg);
}

// The same line, from the management API rather than from a load.
//
// It records as well as prints for a reason that is easy to miss: a script's
// TOP LEVEL runs synchronously inside `create`, and a top-level
// socketley.create() is the ordinary way an orchestration script builds its
// children — so there genuinely is a command in flight to carry the reason to,
// and cmd_create already reads the buffer back.  When there is no such command
// the buffer costs a string nobody reads and is cleared by the next load.
static void api_diag(runtime_instance* owner, const std::string& msg)
{
    std::cerr << lua_diag::tag(owner ? owner->get_name() : std::string_view{})
              << ' ' << msg << std::endl;
    lua_diag::record(msg);
}

// ─── ONE RETURN CONTRACT FOR EVERYTHING A SCRIPT ASKS FOR ───────────────────
//
// `true` when it happened; `false, "<reason>"` when it did not.
//
// 7b951e3 fixed the calls that took a value, altered it and reported success.
// This is the same defect one step along: the call answers, and the answer
// carries nothing.  `socketley.start("web")` returned a bare `false` for a
// runtime that does not exist, for one that is already running, for one whose
// port another process holds, and for one whose --cpus cannot be met by this
// daemon's ring.  Four situations, four different things to do about them, one
// answer — so a script that wants to be idempotent has to guess, and a script
// that wants to report has nothing to report.
//
// ─── WHY TWO RETURNS, AND EXACTLY WHAT IT BREAKS ────────────────────────────
//
// `false, "reason"` is what Lua itself does — io.open, os.remove, and pcall —
// so it is the shape a script author already knows, and `assert(socketley.start(n))`
// starts printing the reason with no change to anything.
//
// It is also nearly free to adopt, because Lua truncates a multiple-return call
// to one value in every context but two.  UNCHANGED: assignment
// (`local ok = f()`), `if not f() then`, `and`/`or`, concatenation, tostring,
// comparison, and any argument position that is not the last.  CHANGED, and
// this is the whole list:
//
//     print(socketley.stop(n))     -- "false   <reason>", was "false"
//     { socketley.start(n) }       -- a two-element table, was one
//     g(socketley.start(n))        -- g receives two arguments, was one
//
// Only the third can alter behaviour rather than output, and it needs the call
// to be the LAST argument of a function that also reads its second parameter.
// Nothing in examples/ or test/ is written that way — checked, every call site
// of the six — and where it does occur the fix is a pair of parentheses.
//
// Success returns ONE value, not `true, nil`, which is why this is
// sol::variadic_results rather than std::tuple: `print(socketley.start(n))` on
// the ordinary path still prints "true", and a script collecting answers in a
// table does not get a hole punched in it.
static sol::variadic_results api_yes(lua_State* L)
{
    sol::variadic_results r;
    r.push_back({ L, sol::in_place_type<bool>, true });
    return r;
}

// The refusal.  NOT logged, and that is the deliberate difference from
// api_diag above.
//
// api_diag belongs to `create`, which is construction: its failures are
// configuration mistakes, they can happen at a script's top level with a CLI
// command in flight, and the operator is the one who has to see them.  These
// are control flow.  `socketley.stop(name)` on something already stopped is how
// an idempotent teardown is written, and a daemon that printed a line every
// time would be punishing a script for being careful.  The caller is handed the
// reason; what to do with it is the caller's business.
static sol::variadic_results api_why(lua_State* L, std::string why)
{
    sol::variadic_results r;
    r.push_back({ L, sol::in_place_type<bool>, false });
    r.push_back({ L, sol::in_place_type<std::string>, std::move(why) });
    return r;
}

// A count, for the two calls whose interesting answer is "how many" rather than
// "did it".  See self.group_send and self.multicast.
static sol::variadic_results api_count(lua_State* L, size_t n)
{
    sol::variadic_results r;
    r.push_back({ L, sol::in_place_type<size_t>, n });
    return r;
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

    // Its own state, with nothing registered on it.  load_file compiles the
    // chunk and leaves it on the stack unexecuted, so no top-level line runs
    // and there is nothing for a top-level line to reach even if one did.
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

    // The top-level chunk is bounded too, and it is the one place the bound
    // changes what a *command* does rather than what a connection sees.  This
    // runs synchronously inside `create`: a script whose top level does not
    // return used to freeze the daemon before the runtime existed, with the
    // operator's terminal blocked on a create that would never answer.  It is
    // safe_script_file, so an expiry comes back as an invalid result and lands
    // in load_diag — the create is refused, with a reason, and nothing is
    // half-built.
    //
    // The process default and not the script's own `callback_timeout_ms`: the
    // global is set BY this chunk, so at this point there is nothing to read.
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

    // What this script asked for, now that its top level has run.  Same shape
    // as tick_ms directly below: a global, read once, clamped.
    //
    // 0 is meaningful and means "no deadline on my callbacks" — a script that
    // genuinely blocks for minutes has to be able to say so, and saying so in
    // the file is the visible way to do it.  A negative or non-integer value is
    // a mistake in a file somebody is editing right now, so it is named rather
    // than rounded into something plausible.
    //
    // TWO READS, AND BOTH FORMS ARE DELIBERATE.
    //
    // `.get<sol::optional<int>>()` is the checked read 091e6d9 replaced every
    // bare `sol::optional<T> x = tbl[k]` in this tree with.  The bare form runs
    // an unconditional conversion, and sol2's safety checks follow NDEBUG — on
    // in every Debug and Sanitize build, off in Release — so what it does with
    // a value it cannot convert is a property of the build rather than of the
    // code.  091e6d9 has the case that cost a daemon: an ABSENT key read as
    // sol::optional<std::string> inside socketley.create's binding, throwing
    // across the Lua C boundary into std::terminate.
    //
    // Honestly: the bare form was tried here and did NOT misbehave.  Measured,
    // Sanitize, `callback_timeout_ms = "soon"` through `create --lua`: it
    // answered nullopt and the diagnostic below fired, the same as the checked
    // form.  The guard above is why — sol::object first, so the key is known to
    // be present, which is the case 091e6d9 was about.  So this is not a crash
    // being fixed; it is the one read in this file that would otherwise be
    // spelled differently from every other read in the file, resting on a
    // measurement of which type pairs sol2 happens to throw on.  That is not a
    // thing to rest on, and the checked form costs nothing.
    //
    // The sol::object probe stays because the checked read cannot tell the two
    // failures apart — absent and present-but-wrong both answer nullopt, and
    // they need different answers.  Absent means "no opinion, use the daemon's
    // default"; present and unreadable is a typo somebody wants told about.
    {
        sol::object cto = m_lua["callback_timeout_ms"];
        if (cto.valid() && cto != sol::nil)
        {
            sol::optional<int> ms =
                m_lua["callback_timeout_ms"].get<sol::optional<int>>();
            if (!ms || *ms < 0)
            {
                load_diag("`callback_timeout_ms` must be a millisecond count of "
                          "0 or more (0 disables the callback deadline for this "
                          "script)");
                return false;
            }
            m_deadline_ms = static_cast<uint32_t>(*ms);
            install_deadline_hook();
        }
    }

    m_on_start = m_lua["on_start"];
    m_on_stop = m_lua["on_stop"];
    m_on_message = m_lua["on_message"];
    m_on_send = m_lua["on_send"];
    m_on_connect = m_lua["on_connect"];
    m_on_disconnect = m_lua["on_disconnect"];
    m_on_route = m_lua["on_route"];
    m_on_master_auth = m_lua["on_master_auth"];
    m_on_client_message = m_lua["on_client_message"];
    m_on_tick = m_lua["on_tick"];
    // ─── tick_ms, against one floor rather than two ─────────────────────────
    //
    // See lua_tick in the header for which of the two rules this file used to
    // hold survived and why.  What changed here is that a value below the floor
    // is now REFUSED instead of being turned into a different number: this line
    // read `(tms && *tms >= 10) ? *tms : 100`, so `tick_ms = 5` was not a
    // clamp, it was a substitution — the script asked for 5 and got 100, twenty
    // times slower, with the same silence a script that asked for nothing gets.
    //
    // Absent still means 100.  A script that declares on_tick and no interval
    // has expressed no opinion, and a default is the right answer to that;
    // there is nothing for anybody to be surprised by later.  The refusal is
    // only for a value that was written down and could not be honoured.
    //
    // The read is a double with an integrality test rather than
    // `get<sol::optional<int>>()`, and that is not decoration.  Every Lua
    // number is a double, so `tick_ms = 12.5` is an ordinary thing to type;
    // asking sol for an int leaves what happens to the half up to a conversion
    // this file does not own, and the two builds do not agree about conversions
    // — that is the whole subject of the note at callback_timeout_ms above.
    // Asking for the number and judging it here has one answer in every build.
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

    // The filter chain.  `filters` is an array of functions run in order before
    // a proxy chooses a backend; see proxy_instance::run_request_filters.
    //
    // A malformed entry refuses the script rather than being skipped.  The chain
    // is where authentication lives, so "the third filter was a typo and was
    // quietly dropped" is a runtime that admits everyone while looking exactly
    // like one that does not.  A script that cannot be loaded is visible at the
    // moment the operator writes it; a hole in the chain is not.
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
                // silently nothing: the array part is empty, so the chain never
                // runs.  An empty table is a legitimate way to say "no filters"
                // and is left alone.
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

    // The route declaration.  `routes` is an array of { path, methods }, and it
    // states what this runtime will answer — see shared/route_table.h for why
    // it lives here rather than in the proxy that enforces it.
    //
    //   routes = {
    //       { path = "/endpoint/login", methods = { "POST", "GET" } },
    //       { path = "/static/*",       methods = { "GET" } },
    //   }
    //
    // A malformed entry refuses the script, as a malformed filter does.  The
    // failure mode is the opposite one — a dropped declaration fails open, and
    // the gateway simply forwards what it would have refused — but it is still
    // a runtime whose published routes are not the ones written in the file,
    // and the operator has no way to see that from either side.  A script that
    // will not load is visible at the moment it is written.
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

                // A single string is accepted where a table of one is meant.
                // `methods = "POST"` is what everyone writes first, and the
                // alternative to reading it is a script that loads with the
                // route silently dropped.
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
                // declaration and is silently nothing, because the array part
                // is what is walked.  An empty table means "declare nothing"
                // and is left alone.
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
    //
    // A subscriber is a script, and a script may call straight back into this
    // API: socketley.subscribe and socketley.unsubscribe are both bound in the
    // very VM these run in.  This was a range-for over the vector, which holds
    // an iterator into it — so one subscribe on this same channel from inside a
    // handler reallocated the buffer and the loop went on walking the freed
    // one.  Latent only because there was no unsubscribe to make the other half
    // of it reachable.
    //
    // Both directions are therefore deferred rather than guarded against.
    // subscribe() parks a new registration in m_pending_subscriptions and
    // unsubscribe() marks its entry dead; settle_subscriptions() applies both
    // when the last frame here unwinds.  The vector is then immutable for the
    // whole dispatch, which is what makes the plain index below correct — and
    // it costs nothing on the ordinary path, where no subscriber touches
    // either call.
    //
    // Deferring the insertion also settles a question that would otherwise be
    // decided by std::vector's growth policy: a subscription registered while a
    // message is being delivered does not receive that message.
    auto&        subs = it->second;
    const size_t n    = subs.size();

    // One scope for the whole fan-out, not one per subscriber.  A publish is
    // usually made from inside another callback, and lua_deadline::scope nests
    // outermost-wins, so in that case this arms nothing and the subscribers
    // spend the publisher's budget — which is right, because the publisher's
    // callback does not return until the last subscriber has run.  When the
    // publish comes from somewhere with no callback armed, this is the outermost
    // scope and the whole fan-out shares one budget.
    ++m_dispatch_depth;
    {
        lua_deadline::scope guard("a socketley.subscribe callback", m_deadline_ms,
                                  m_owner_name.c_str());
        for (size_t i = 0; i < n; ++i)
        {
            if (subs[i].dead) continue;
            sol::protected_function_result r = subs[i].fn(channel, message);
            if (SOCKETLEY_UNLIKELY(!r.valid()))
            {
                sol::error e = r;
                fprintf(stderr, "%s subscribe callback error: %s\n",
                        lua_diag::tag(m_owner_name).c_str(), e.what());
            }
        }
    }
    if (--m_dispatch_depth == 0)
        settle_subscriptions();
}

// See the declaration.  Called at the moment it is safe to move the vectors
// dispatch_publish walks — which is when the last of its frames has unwound, or
// immediately when there were none.
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
        // as an empty vector: dispatch_publish finds by key, and a key that is
        // present answers the lookup and then does nothing, on every publish,
        // for the life of the context.
        if (v.empty()) it = m_subscriptions.erase(it);
        else           ++it;
    }
    m_subscriptions_dirty = false;
}

// End every subscription this context holds, leaving the context itself alive.
//
// The other half of cancel_timers(), and it exists for the sentence that one is
// written under: a stopped runtime must execute no script.  ebb6897 severed the
// timers at `stop` and left this standing, so a registration went on living as
// long as the interpreter did — and only `remove` destroys that — which meant a
// PUBLISH on the linked cache was delivered to a runtime `ls` reported as
// Stopped.  Measured on the parent commit, the handler even read self.state as
// "stopped" and ran anyway.  The bill is the same one: socketley.subscribe
// callbacks call self.send, and self.send from a stopped runtime delivers to
// clients of a runtime the operator has taken down.
//
// ─── Deferred while a dispatch is walking, exactly as unsubscribe() is ──────
//
// This is not a theoretical ordering.  `socketley.stop(self.name)` from inside a
// subscriber reaches here through runtime_instance::stop(), and the frame it
// reaches here from is holding `auto& subs = it->second` — a reference into the
// very map below.  Clearing it there would free the vector being walked, which
// is the same shape sever_timer() has to dodge one call along when a timer
// cancels itself.  So the marking path is the one unsubscribe() already built:
// entries are marked dead, m_subscriptions_dirty is set, and the outermost
// dispatch frame calls settle_subscriptions() on its way out.  Marking dead is
// enough for the delivery in progress too — dispatch_publish skips a dead entry
// on every iteration, so the handlers after this one in the same fan-out do not
// run either.
//
// The ids go in both paths.  They name registrations this context no longer
// has, so a later socketley.unsubscribe(id) answering true for one of them
// would be answering for something that is already gone; false is the truth,
// and it is what the id's contract says.
void lua_context::cancel_subscriptions()
{
    // Up before anything is torn down, and it stays up until start() lowers it.
    // See registrations_severed(): severing what is armed does not stop the
    // script that called socketley.stop from arming more the moment stop()
    // returns to it.
    m_severed = true;

    // Nothing is walking the pending queue — dispatch_publish reads the map —
    // so these go outright whether or not a dispatch is in flight.  They are
    // registrations made during this dispatch, which is to say made by a script
    // that is being stopped, and settling them afterwards would install
    // subscribers on a runtime that has gone.
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

// Sever every armed timer from this context, leaving the context itself alive.
//
// Split out of ~lua_context so that stopping a runtime can reach it.  A stopped
// runtime must execute no script, and its intervals used to go on firing at
// full rate for as long as the daemon lived — the context is only destroyed by
// `remove`, so `stop` left every set_interval running.  That is not untidy, it
// is wrong in a way a script can act on: self.send from such a timer reaches
// clients of a runtime the operator has taken down.
//
// The severance is exactly what the destructor performed, and the reasoning is
// written out at sever_timer() above.  The only difference is that this object
// survives, which is why both containers are cleared: what is left in them
// would name timers this context has already given away.
void lua_context::cancel_timers()
{
    // The same latch, raised by both severances rather than by one of them:
    // they are called together from stop() and they answer the same sentence,
    // and a script that re-arms afterwards re-arms whichever it likes.  The
    // destructor reaches this too, where it costs nothing — the context is
    // going, so nothing will read it again.
    m_severed = true;

    for (auto* p : m_active_timers)
        sever_timer(static_cast<lua_timer*>(p));
    m_active_timers.clear();

    // The timer ids too.  They name timers this context no longer owns — every
    // one of them has just been handed to its own completion — so a lookup that
    // survived into the destructor's remaining work would find a pointer with
    // nothing left to say.
    m_timer_map.clear();
}

void lua_context::update_self_state(const char* state_str)
{
    sol::optional<sol::table> self = m_lua["self"].get<sol::optional<sol::table>>();
    if (self)
        (*self)["state"] = state_str;
}

// ---------------------------------------------------------------------------
// socketley.http(opts) — synchronous HTTP/HTTPS client for Lua scripts
// opts = { url, method="GET", body="", headers={}, timeout_ms=5000 }
// Returns { ok=bool, status=int, body=string, error=string }
//
// HTTPS now verifies the chain against the system trust store *and* that the
// certificate was issued for the host in the URL. It used to do neither
// (SSL_VERIFY_NONE): that bought encryption against somebody recording the
// wire and nothing whatsoever against somebody sitting on it. Any self-signed
// certificate was accepted, so a script fetching config, polling a health
// endpoint or posting a webhook could be answered by whoever got in the middle
// — with no error, no log line, and a `result.ok` of true.
//
// STILL BLOCKS THE EVENT-LOOP THREAD. This runs on the single thread that
// serves every runtime in the daemon, so a slow host still stalls all of them.
// Making it asynchronous means driving the socket from event_loop and
// suspending the Lua callback across the round trip, which is a different
// change in a different file. What is fixed here is that the block is now
// *bounded*: DNS aside, connect, handshake, send and receive share one deadline
// of timeout_ms enforced with poll(). Before, connect() ignored timeout_ms
// entirely and sat in the kernel's SYN retry schedule for over two minutes,
// and the socket timeouts restarted on every byte, so a server trickling one
// byte at a time held the whole daemon for as long as it cared to.
//
// Residual: getaddrinfo() is still unbounded and is not counted against the
// deadline until it returns — the resolver has no per-call timeout, and giving
// it one means resolving off-thread, which is the same asynchronous rework.
// It is also the one part of this call the callback deadline cannot reach: a
// count hook counts VM instructions and the resolver executes none.
//
// AND IT LIVES INSIDE THE CALLBACK'S BUDGET. There are now two bounds on how
// long the event loop may be held, and two bounds that merely happen to be
// compatible is a bug waiting for the day somebody changes one of them. So
// timeout_ms is clamped to what is left of the invocation deadline (see
// lua_deadline in lua_context.h) and there is one budget: whatever a callback
// spends here, it spends out of the ten seconds it has in total, and a script
// that wants a thirty-second fetch says `callback_timeout_ms = 31000` and gets
// it. Nothing here can be interrupted mid-socket by the hook — no bytecode runs
// between these poll() calls — so the clamp is the only way the two interact,
// and it interacts by returning an ordinary `ok = false, error = "..."` result
// that a script can see and handle.
//
// Keep to on_start/on_stop or low-frequency on_tick callbacks regardless.
// ---------------------------------------------------------------------------

using http_clock = std::chrono::steady_clock;

// Milliseconds left before `deadline`, never negative.
static int http_ms_left(http_clock::time_point deadline)
{
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - http_clock::now()).count();
    if (left <= 0)       return 0;
    if (left > INT_MAX)  return INT_MAX;
    return static_cast<int>(left);
}

// Wait for `fd` to become ready for `events`, or for the deadline to pass.
// Returns 1 = ready, 0 = out of time, -1 = poll failed.
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

// Ceiling on what one response may accumulate in daemon memory. The old loop
// appended until the peer stopped sending, so a hostile or broken endpoint
// could grow this string until the allocator gave up — on a box with no swap
// that takes the daemon down, not just the script.
static constexpr size_t http_max_response = 8u * 1024u * 1024u;

#ifndef SOCKETLEY_NO_HTTPS
// Drain OpenSSL's thread-local error queue into readable text.
//
// Every TLS failure here reported the bare string "TLS handshake failed". The
// reason — expired certificate, unknown CA, name mismatch, a plain-HTTP server
// on port 443 — was on that queue and nobody popped it. Leaving it there is a
// second bug: the queue persists, so a stale entry gets drained later and
// reported as the cause of an unrelated request's failure.
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

    sol::optional<std::string> url_opt = opts["url"].get<sol::optional<std::string>>();
    if (!url_opt || url_opt->empty()) { result["error"] = "url required"; return result; }

    // ─── The three optional keys, checked ───────────────────────────────────
    //
    // These were the last `sol::optional<T> x = tbl[k]` reads in this file, the
    // form 091e6d9 replaced everywhere else after one of them took the daemon
    // down: the converting constructor runs an unconditional conversion, sol2's
    // safety checks follow NDEBUG, and a key that is absent or of another type
    // throws across the Lua C boundary into std::terminate.  Honestly: this
    // pair does not throw today, measured — `socketley.http{url=...}` with no
    // `method` is what every test in the tree calls and it answers "GET" in
    // both builds.  It is replaced anyway for the reason written at
    // callback_timeout_ms: whether a conversion throws is a property of the
    // build, and that is not a thing to rest on when the checked form costs
    // nothing.
    //
    // And the second half is this file's own subject.  `timeout_ms = "soon"`
    // read as nullopt and became 5000 — a value written down, discarded, and
    // the request made anyway on a number nobody chose.  A wrong value is
    // reported through `result.error`, which is the channel this call already
    // has and the one a script can act on; a *missing* value keeps its default,
    // because saying nothing is not a mistake.
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

    // Inside the callback's budget, not beside it.  remaining_ms() is -1 when
    // no deadline is armed — a call from somewhere that is not a callback, or a
    // script that set callback_timeout_ms = 0 — and then timeout_ms stands as
    // the script wrote it, which is exactly the behaviour that existed before.
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

    // One deadline for the whole exchange, taken before anything can block.
    // Every wait below measures against this, so the total time this call can
    // hold the event-loop thread is timeout_ms plus the resolver, rather than
    // timeout_ms per operation with no ceiling on the number of operations.
    const auto deadline = http_clock::now() + std::chrono::milliseconds(timeout_ms);

    // Parse scheme
    bool is_https = false;
    if (url.rfind("https://", 0) == 0)      { is_https = true;  url = url.substr(8); }
    else if (url.rfind("http://", 0) == 0)  {                   url = url.substr(7); }
    else { result["error"] = "unsupported scheme (use http:// or https://)"; return result; }

#ifdef SOCKETLEY_NO_HTTPS
    if (is_https) {
        // The wording here used to be `use io.popen("curl -s https://...")`.
        // A diagnostic that hands the caller a shell is the wrong answer twice
        // over: it turns one runtime's missing TLS into an arbitrary command
        // executed with the daemon's privileges, and it teaches that as the
        // normal way to fetch a URL, in the one message a script author is
        // guaranteed to read at the moment they are looking for a workaround.
        // What is actually missing is a build, so that is what it says.
        result["error"] = "HTTPS not supported in this build (compiled with "
                          "SOCKETLEY_NO_HTTPS); use http://, or rebuild with "
                          "TLS support";
        return result;
    }
#endif

    // Parse host:port/path.
    //
    // The last colon is not the port separator: an IPv6 literal is full of
    // colons. rfind(':') turned "[::1]:8443" into host "[::1]" — brackets and
    // all, which no resolver and no certificate ever matches — and bare "::1"
    // into host "::" with port 1. Either way the address never resolved, so
    // the IP-literal branch of the certificate check below was unreachable
    // from here.
    //
    // Two forms of the host come out of this: `host`, without brackets, which
    // is what getaddrinfo(), SNI and the certificate verifier all expect, and
    // `host_header`, which keeps them, because an unbracketed IPv6 address in
    // a Host header cannot be told from host:port.
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
            // Exactly one colon is a port. More than one and no brackets is an
            // unbracketed IPv6 literal — not strictly a legal URL, but it must
            // not be silently cut in half either.
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

    // DNS resolve
    struct addrinfo hints{}, *addrs = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_buf[8];
    auto port_res = std::to_chars(port_buf, port_buf + sizeof(port_buf), port);
    *port_res.ptr = '\0';
    if (getaddrinfo(host.c_str(), port_buf, &hints, &addrs) != 0 || !addrs) {
        result["error"] = "DNS resolution failed for: " + host;
        return result;
    }

    // Connect.
    //
    // Non-blocking socket plus poll(), not a blocking connect() with
    // SO_SNDTIMEO: that option does not bound connect() on Linux at all. A host
    // that drops the SYN — a firewall blackholing the port is the usual way —
    // left this parked in the kernel's retry schedule for well over two
    // minutes, on the thread every other runtime needs, no matter what
    // timeout_ms said. The socket stays non-blocking for the rest of the call
    // so every later wait goes through the same deadline.
    int sock = ::socket(addrs->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sock < 0) { freeaddrinfo(addrs); result["error"] = "socket() failed"; return result; }

    if (::connect(sock, addrs->ai_addr, addrs->ai_addrlen) != 0)
    {
        if (errno != EINPROGRESS)
        {
            freeaddrinfo(addrs); ::close(sock);
            result["error"] = std::string("connect() failed: ") + std::strerror(errno);
            return result;
        }

        int ready  = http_wait(sock, POLLOUT, deadline);
        int so_err = 0;
        if (ready == 1)
        {
            // Writable only means the attempt finished, not that it succeeded:
            // a refused connection reports readiness and hides ECONNREFUSED in
            // SO_ERROR, which is how a failed connect turns into a mysterious
            // empty response if nobody looks.
            socklen_t so_len = sizeof(so_err);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &so_len) != 0)
                so_err = errno;
        }
        if (ready != 1 || so_err != 0)
        {
            freeaddrinfo(addrs); ::close(sock);
            result["error"] = (ready == 0)
                ? std::string("connect timed out after ") + std::to_string(timeout_ms) + "ms"
                : std::string("connect() failed: ") + std::strerror(so_err ? so_err : errno);
            return result;
        }
    }
    freeaddrinfo(addrs);

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
    sol::optional<sol::table> hdrs = opts["headers"].get<sol::optional<sol::table>>();
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

    // Send + receive. Both directions are poll-driven against the shared
    // deadline: the socket timeouts this used to rely on restart on every byte
    // that arrives, so a peer sending one byte per second never "times out"
    // while holding the thread forever.
    std::string response;
    std::string xfer_err;

#ifndef SOCKETLEY_NO_HTTPS
    if (is_https) {
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { ::close(sock); result["error"] = "SSL_CTX_new failed"; return result; }

        // ── Verification ──
        // SSL_VERIFY_PEER fails the handshake on a chain no trusted CA signed;
        // the host pin below fails it when the chain is trusted but was issued
        // to somebody else. Both are needed: a certificate for a domain the
        // attacker owns is entirely valid, and without the name check it
        // impersonates any host this script fetches.
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            std::string why = ssl_error_text();
            SSL_CTX_free(ctx); ::close(sock);
            result["error"] = "no system CA store available" + (why.empty() ? "" : ": " + why);
            return result;
        }
#if defined(SSL_OP_IGNORE_UNEXPECTED_EOF)
        // HTTP/1.0 with "Connection: close": a great many servers just drop the
        // TCP connection instead of sending close_notify. OpenSSL 3.0 calls
        // that a protocol error by default, which would turn a complete
        // response into "SSL_read failed" for a large slice of the internet.
        // The cost is that a truncated response is indistinguishable from a
        // complete one — the same exposure the plaintext path has always had,
        // and the reason a caller should check status and body rather than
        // trust length.
        SSL_CTX_set_options(ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif

        SSL* ssl = SSL_new(ctx);
        if (!ssl) { SSL_CTX_free(ctx); ::close(sock); result["error"] = "SSL_new failed"; return result; }
        SSL_set_fd(ssl, sock);

        // An address literal is matched against the certificate's iPAddress SAN
        // and must not be sent as SNI (RFC 6066 permits host names there only).
        unsigned char ip_probe[16];
        const bool host_is_ip = inet_pton(AF_INET,  host.c_str(), ip_probe) == 1 ||
                                inet_pton(AF_INET6, host.c_str(), ip_probe) == 1;
        bool pinned;
        if (host_is_ip) {
            pinned = X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), host.c_str()) == 1;
        } else {
            SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            pinned = SSL_set1_host(ssl, host.c_str()) == 1 &&
                     SSL_set_tlsext_host_name(ssl, host.c_str()) == 1;
        }
        if (!pinned) {
            // Refuse rather than continue unpinned: a connection that verifies
            // the chain and not the name looks identical to a good one.
            std::string why = ssl_error_text();
            SSL_free(ssl); SSL_CTX_free(ctx); ::close(sock);
            result["error"] = "failed to pin expected certificate name for " + host
                            + (why.empty() ? "" : ": " + why);
            return result;
        }

        // Handshake, bounded by the shared deadline. The socket is
        // non-blocking, so OpenSSL hands back WANT_READ/WANT_WRITE instead of
        // sleeping inside read(), and poll() decides how long we are willing to
        // wait for the peer's next record.
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
            SSL_free(ssl); SSL_CTX_free(ctx); ::close(sock);
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

        // One attempt only: on a non-blocking socket SSL_shutdown normally
        // wants another round trip, and we are closing the connection either
        // way — waiting for the peer's close_notify would spend the deadline we
        // just spent enforcing on nothing.
        if (SSL_shutdown(ssl) < 0) {}
        ERR_clear_error();
        SSL_free(ssl); SSL_CTX_free(ctx);
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
    auto body_start = response.find("\r\n\r\n");
    result["status"] = status;
    result["body"]   = (body_start != std::string::npos) ? response.substr(body_start + 4) : "";
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

// ── What a worker cannot answer, said in the way this tree says it ──────────
//
// Named, with the reason and the way out, like tls_config_refusal — and for the
// same reason.  Every one of these calls used to return a false, a nil or an
// empty table from inside a worker, which is exactly what a *successful* call
// on an empty daemon returns.  A script could not tell "there are no other
// runtimes" from "this call cannot see any runtimes from here", so it carried
// on routing, sending and creating against nothing, and the operator was told
// nothing at all.
//
// Raised rather than returned, because the return value is the thing that
// cannot carry it: `if socketley.create(...) then` is how these are written and
// a false is what it already handles.
//
// `call` is the fully-qualified name as a script writes it, so the message
// names what was typed.  `mistaken_for` completes the sentence, because the lie
// differs by call: an empty list reads as a daemon with nothing in it, while a
// false from self.route() reads as a target that is not there.
std::string worker_refusal(const std::string& call,
                           const char* mistaken_for =
                               "a successful call on a daemon with nothing in it")
{
    return call +
           "() is refused in a worker process: this call reaches for the "
           "runtime map, which lives in the daemon, and answering from here "
           "would return nothing — indistinguishable from " + mistaken_for +
           ". Create this runtime with --daemon-process, or move the call to "
           "one that has it.";
}

// The raise itself.  Built by a Lua factory so that what a script sees is Lua's
// own error() at the call site rather than a C++ exception thrown through
// LuaJIT's frames — which is what lets every callback in this tree catch it and
// print it with the callback's name attached.
//
// Shared by the two tables that have something to refuse, so both fail the same
// way.  Comes back invalid if the interpreter could not build it; callers say so
// rather than quietly leaving a working binding in place.
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

// Replace the cross-runtime half of the management API with something that says
// why it is not there.
//
// The raise is built by a Lua factory and is therefore Lua's own error(): no C++
// exception is thrown through LuaJIT's frames to produce it.  What a script sees
// is an ordinary runtime error at the call site, which every callback in this
// tree already catches and prints with the callback's name attached — so a
// refusal in on_proxy_request reads as
//
//   [lua] on_proxy_request error: lua: error: px.lua:7: socketley.list() is
//   refused in an out-of-process proxy worker: ...
//
// and a refusal at the top level fails the script load, which the worker treats
// as a configuration it cannot serve.
void lua_context::refuse_cross_runtime_api(sol::table& sk, sol::table& cluster_tbl)
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

    // Everything that reaches for the runtime map, and nothing that does not.
    // socketley.log, .http, .json_*, the timers and .subscribe/.unsubscribe all
    // work in a worker exactly as they do in the daemon, and .subscribe in
    // particular is delivered to now — see runtime_manager::set_publish_sink.
    for (const char* call : {"create", "start", "stop", "remove", "send", "list",
                             "get", "pipe"})
    {
        sol::function f = make(worker_refusal(std::string("socketley.") + call));
        sk[call] = f;
    }

    // The cluster view is the runtime map plus what discovery has heard, and a
    // worker has neither.
    for (const char* call : {"daemons", "runtimes", "group", "stats"})
    {
        sol::function f = make(worker_refusal(std::string("socketley.cluster.") + call));
        cluster_tbl[call] = f;
    }
}

void lua_context::register_bindings(runtime_instance* owner)
{
    // Which runtime every diagnostic from this interpreter belongs to.  First,
    // because load_diag is called from the validators below this point and from
    // load_script, which calls this function before it does anything else.
    m_owner_name = std::string(owner->get_name());

    // Register socketley.log() and management API
    sol::table sk = m_lua.create_table();

    // ─── socketley.log, through the daemon's own logger ─────────────────────
    //
    // It wrote straight to std::cerr, which made it the one stream in this
    // process with no timestamp, no level and no way to turn it down.  A script
    // logging per message is a script whose operator cannot ask for less
    // without editing the script — and `log_level` in the daemon's
    // configuration file exists precisely so that asking for less is a setting.
    //
    // At `info`, which is the default, nothing that used to appear stops
    // appearing; it gains a clock and a level. At `warn`, script chatter goes
    // quiet, which is what an operator who set `warn` asked for and could not
    // previously get. That is the judgement: this is output, not diagnosis —
    // the failures a script must never lose are the callback errors below,
    // and those are ERROR and survive every level but silence.
    sk["log"] = [owner](std::string msg) {
        std::string line = lua_diag::tag(owner->get_name());
        line += ' ';
        line += msg;
        LOG_INFO(line.c_str());
    };

    // socketley.create(type, name, config_table) → bool
    //
    // ─── THE TABLE IS JUDGED BEFORE ANYTHING IS BUILT ───────────────────────
    //
    // Every read below used to be "if it is there and I can convert it, apply
    // it", with no branch for a value that was there and wrong.  That is one
    // decision repeated eight times, and it is the wrong one every time:
    //
    //     port = 70000        cast to uint16_t -> a server on 4464
    //     mode = "mater"      the switch's default: -> an inout server
    //     on_parent_stop="keeep"  compared only against "remove" -> keep
    //     prot = 8080         read by nothing -> a server on port 0
    //
    // and in all four the call answered `true`.  A script cannot see any of it:
    // socketley.get(name).port answers 4464 as confidently as it would answer
    // 8080, and the operator finds out from a client that cannot connect.
    //
    // The refusal policy is not invented here.  `filters` and `routes`, two
    // hundred lines up this file, refuse the WHOLE script for exactly this
    // class of mistake, and their validators say why: a hole in a chain is not
    // visible, so the load fails rather than half-working.  A child runtime on
    // a port nobody chose is the same shape — invisible from the script, from
    // `ls`, and from the runtime itself, which is running perfectly well.
    //
    // UNKNOWN KEYS ARE REFUSED TOO, and that is the one line here worth
    // arguing.  The case against is forward compatibility: a script written for
    // a later socketley, naming a key this one has never heard of, stops
    // loading instead of degrading.  The case for is that this table is not a
    // wire format — it is read by the daemon the script is running inside, of
    // the same build, on the same machine — so there is no version skew to
    // absorb, and the failure it prevents is the commonest one there is.
    // `prot = 8080` is a typo somebody will make; a server on port 0 is what
    // they get for it, and nothing anywhere says the word `prot`. Refused, with
    // the key named.
    //
    // The order matters as much as the checks: everything is judged BEFORE
    // mgr->create, so a refusal leaves no runtime behind at all.  The two that
    // cannot be — the script, which needs an instance to load into, and the
    // start, which needs one to bind — remove what they built, which is what
    // cmd_create does for the identical two failures on the CLI side.
    // sol::object and not sol::optional<sol::table> for the third parameter:
    // the optional answers nullopt for a value that is present and not a table,
    // which is indistinguishable from no third argument at all — so
    // socketley.create("server", "s", 8080) built a portless server and
    // reported success.  An object says which of the two it was.
    sk["create"] = [owner](sol::this_state L, std::string type_str, std::string name,
                           sol::object config) -> sol::variadic_results {
        auto* mgr = owner->get_runtime_manager();
        auto* loop = owner->get_event_loop();
        if (!mgr || !loop)
            return api_why(L, "this runtime has no runtime manager");

        const std::string where = "socketley.create(\"" + type_str + "\", \"" + name + "\")";
        // Logged AND returned, which makes this the one call in the family that
        // does both — and both callers are real.  api_why alone would serve the
        // script; api_diag alone is what a TOP-LEVEL create needs, because that
        // one runs inside the `create` command and the operator who typed
        // `create --lua x.lua` is the person who wrote the mistake.  cmd_create
        // reads the buffer back to their terminal.
        auto refuse = [&](const std::string& why) {
            api_diag(owner, where + ": " + why);
            return api_why(L, why);
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

            // ─── A key that is not there must read as absent, not throw ─────
            //
            // `sol::optional<T> x = tbl[k]` looks like it says "if present",
            // and it does not.  The optional's converting constructor runs an
            // unconditional conversion, and with sol2's safety checks on — they
            // follow NDEBUG, so they are ON in every Debug and Sanitize build
            // and off in Release — a key that is absent or of another type
            // throws.  The throw is raised inside a lambda that sol2 called
            // across the Lua C boundary, so it unwinds into std::terminate:
            //
            //     socketley.create("server","made",{port=P,start=true})
            //     Release   -> the runtime is created and started
            //     Sanitize  -> terminate called without an active exception
            //                  (the whole daemon, and every runtime in it)
            //
            // gdb put it at this line: the config above has no `lua` key, and
            // reading the one that is not there is what ended the process.
            //
            // Every read below is therefore taken as a sol::object first, which
            // asks the Lua stack what is there without converting anything, and
            // is then type-checked by this code rather than by a conversion
            // whose behaviour is a property of the build.
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
                // "stop" and not "keep": child_policy::stop is what the enum
                // calls it, what the `owner` command prints, and what the man
                // page documents.  A second name for one bit is the thing the
                // --out-of-process/--in-daemon note in flag_handlers warns
                // about, and it costs the same here.
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
        if (type == runtime_server)
        {
            auto* srv = static_cast<server_instance*>(inst);
            if (have_mode) srv->set_mode(cfg_mode);
            if (!cfg_http.empty()) srv->set_http_dir(cfg_http);
            if (cfg_http_cache) srv->set_http_cache(true);
        }

        // ─── The two that can only fail after the runtime exists ────────────
        //
        // Both returns were discarded.  A child whose script would not compile
        // was created, registered and answered `true` with not one callback on
        // it — a server that accepts connections and does nothing with them,
        // which is indistinguishable from a working one until traffic arrives.
        // A `start = true` that could not bind answered `true` for a runtime
        // that never listened.
        //
        // Removed rather than left `failed`, because that is what cmd_create
        // does for the same two failures: a script that will not load and a
        // start that will not bind both take `m_manager.remove(name)` on the
        // way out.  The one place this tree leaves a refusal standing is the
        // out-of-process create, where the reason lives in another process and
        // a `failed` row is the only record — not this path, where the reason
        // is on the line above.  A Lua-created child is always in-daemon, so
        // there is no supervisor holding a pointer to it and no release_workers
        // to do first, which is why this is a plain remove.
        //
        // The reason is not repeated here on purpose: the child's own load has
        // already written it, named for the CHILD, to both the log and the
        // buffer a top-level create reads back.  Saying it again under the
        // parent's name would put one failure on the operator's terminal twice
        // under two different runtime names.
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

        return api_yes(L);
    };

    // socketley.start(name) → bool
    // ─── THE DIAGNOSIS IS MADE HERE, FROM WHAT THIS SIDE CAN KNOW ───────────
    //
    // runtime_manager::start answers a bool, and the reasons behind it are
    // spread through runtime_instance::start: a state that cannot be started, a
    // ring policy this loop cannot meet, a TLS pair that is not a pair, a bind
    // that failed.  Two of those four can be asked about from here, exactly and
    // in O(1), BEFORE anything is attempted — so they are, and they are named.
    //
    // The other two cannot, and this deliberately does not pretend otherwise.
    // setup() is where a held port is discovered and it reports to the daemon's
    // log; a second diagnosis invented here would be a guess wearing the
    // clothes of a fact.  What is said instead is true and is the part a script
    // can act on: the attempt was made, it failed, and this is the state the
    // runtime is in now.
    //
    // The ring check runs before the attempt rather than after it for a reason
    // beyond tidiness: runtime_instance::start stores `failed` on that path, so
    // a call that could have been refused would otherwise leave the runtime
    // unstartable for the rest of the daemon's life.
    sk["start"] = [owner](sol::this_state L, std::string name) -> sol::variadic_results {
        auto* mgr = owner->get_runtime_manager();
        auto* loop = owner->get_event_loop();
        if (!mgr || !loop)
            return api_why(L, "this runtime has no runtime manager");

        auto* inst = mgr->get(name);
        if (!inst)
            return api_why(L, "there is no runtime called " + q(name));

        switch (inst->get_state())
        {
            case runtime_running:
                return api_why(L, q(name) + " is already running");
            case runtime_failed:
                return api_why(L, q(name) + " is failed, and a failed runtime "
                                            "cannot be started again — remove it "
                                            "and create it anew");
            default: break;
        }

        if (const std::string msg = inst->ring_policy_refusal(*loop); !msg.empty())
            return api_why(L, msg);

        if (mgr->start(name, *loop))
            return api_yes(L);

        return api_why(L, q(name) + " could not be started; it is "
                       + state_to_string(inst->get_state())
                       + " now, and the reason is in the daemon's log");
    };

    // socketley.stop(name) → true | false, reason
    sk["stop"] = [owner](sol::this_state L, std::string name) -> sol::variadic_results {
        auto* mgr = owner->get_runtime_manager();
        auto* loop = owner->get_event_loop();
        if (!mgr || !loop)
            return api_why(L, "this runtime has no runtime manager");

        auto* inst = mgr->get(name);
        if (!inst)
            return api_why(L, "there is no runtime called " + q(name));
        if (inst->get_state() != runtime_running)
            return api_why(L, q(name) + " is "
                              + state_to_string(inst->get_state()) + ", not running");

        if (mgr->stop(name, *loop))
            return api_yes(L);
        return api_why(L, q(name) + " could not be stopped; the reason is in "
                                    "the daemon's log");
    };

    // socketley.remove(name) → true | false, reason
    sk["remove"] = [owner](sol::this_state L, std::string name) -> sol::variadic_results {
        auto* mgr = owner->get_runtime_manager();
        auto* loop = owner->get_event_loop();
        if (!mgr || !loop)
            return api_why(L, "this runtime has no runtime manager");
        auto* inst = mgr->get(name);
        if (!inst)
            return api_why(L, "there is no runtime called " + q(name));
        if (inst->get_state() == runtime_running)
            mgr->stop(name, *loop);
        // Before the instance leaves the map, and for the reason cmd_remove()
        // gives at the same point in the same order: a worker's supervisor
        // holds a pointer to the placeholder, and that pointer has to be
        // dropped while the object it names is still there.
        mgr->release_workers();
        if (mgr->remove(name))
            return api_yes(L);
        // Unreachable while the lookup above succeeds and nothing else runs on
        // this thread in between — said anyway, because a bare false is what
        // this whole change exists to stop returning.
        return api_why(L, q(name) + " could not be removed");
    };

    // socketley.send(name, msg) → bool
    //
    // The connections are wherever the runtime is — the same sentence cmd_send()
    // is written under, and for the same reason.  Calling lua_broadcast() on a
    // placeholder reaches an object that has the name, the port and the state
    // and not one connection: it succeeds, it returns true, and the message
    // goes nowhere.  That was fixed for the CLI when the deliver frame was
    // added and left standing here, so since 2313c26 made the worker the
    // default it was the ordinary case for a script.
    sk["send"] = [owner](sol::this_state L, std::string name,
                         std::string msg) -> sol::variadic_results {
        auto* mgr = owner->get_runtime_manager();
        if (!mgr)
            return api_why(L, "this runtime has no runtime manager");
        auto* inst = mgr->get(name);
        if (!inst)
            return api_why(L, "there is no runtime called " + q(name));
        if (inst->get_state() != runtime_running)
            return api_why(L, q(name) + " is " + state_to_string(inst->get_state())
                              + ", not running; nothing is connected to it");
        if (inst->is_out_of_process())
        {
            if (mgr->deliver_out_of_process(name, msg))
                return api_yes(L);
            // Named as the transport it is.  A script told only `false` would
            // look at its own runtime for a fault that is in the pipe to
            // somebody else's process.
            return api_why(L, q(name) + " runs in a worker process, and the "
                                        "message could not be handed to it");
        }
        if (inst->get_type() == runtime_server)
            inst->lua_broadcast(msg);
        else
            inst->lua_send(msg);
        return api_yes(L);
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

    // socketley.get(name) → table {name, type, state, port, connections, owner} or nil
    //
    // reported_connection_count(), not get_connection_count(): `name` is some
    // OTHER runtime, and since 2313c26 another runtime is normally one in a
    // worker process, whose connections this object does not hold.  The three
    // calls in this file that ask about another runtime are the three that had
    // to change; every self.connections() below asks its own object in its own
    // process and is right to walk the tables.
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
    //
    // A refusal, and only a refusal.  The ids come from `++m_next_timer_id` on
    // a counter that starts at 0, so a timer that was armed always has an id of
    // 1 or more and there is no value a script has to disambiguate — `if
    // socketley.set_timeout(ms, f) == 0 then` is a complete test.
    //
    // What it does not say is WHICH refusal, and both are worth a line in the
    // log rather than a silent nothing: a runtime with no event loop is not a
    // runtime that can schedule anything, and `ms <= 0` is a script asking for
    // a timer that would never be armed.  Neither can happen in a working
    // script, so the cost of saying so is nothing and the cost of not saying so
    // is a callback that never runs with no record of why.
    //
    // Not changed to a nil return, which was the alternative.  0 is already
    // unambiguous, and a nil would break `local id = set_timeout(...)` followed
    // by `clear_timeout(id)` — clear_timeout takes an int, so the failure would
    // move from a callback that never fires to a type error at a line that has
    // nothing wrong with it.
    sk["set_timeout"] = [this, owner](int ms, sol::protected_function fn) -> int {
        // A third refusal, and the same 0.  See registrations_severed(): the
        // runtime is down and this call would schedule work for it.
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
        // See set_timeout above.  This is the one the measurement came from: 41
        // ticks in two seconds on a runtime that had been stopped.
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
    //
    // Both of these were two assignments — `cancelled = true; repeat = false;`
    // — and nothing else.  That stops the callback, which is all the existing
    // tests ask for, and it leaves everything else exactly where it was: the
    // timeout stays armed in the ring, the lua_timer keeps its storage and its
    // owner registration, and the sol::protected_function keeps a registry
    // reference to the closure and to every upvalue it captured.  Cancelling a
    // one-hour interval held all of that for the hour.  Measured on the parent,
    // 100 cleared timeouts each capturing a 32 KB string, collectgarbage()
    // called after the clear: the Lua heap did not move.
    //
    // sever_timer() is what cancel_timers() already does to every timer at stop
    // and at teardown, so this is that mechanism reused rather than a second
    // one — which matters, because the order it performs those four steps in is
    // load-bearing and there should be exactly one place that knows it.
    //
    // unregister_timer() first, and not after: it finds the map entry by
    // t->timer_id, and it is what takes this timer out of m_timer_map and
    // m_active_timers so that neither goes on naming a timer this context has
    // handed to its own completion.
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

    // socketley.json_encode(value) → JSON string, or false + why
    //
    // The refusal follows this file's return contract rather than raising: a
    // string is truthy and false is not, so `local s = socketley.json_encode(t)`
    // reads the same, and `if not s then` is how the two callers that care
    // already test everything else here.  Both refusals used to be a crash of
    // the whole daemon — see json_max_depth.
    sk["json_encode"] = [](sol::this_state L, sol::object val)
                        -> sol::variadic_results {
        std::string out;
        out.reserve(256);
        std::vector<const void*> path;
        std::string err;
        if (!json_encode_value(out, val, 0, path, err))
            return api_why(L, "socketley.json_encode(): " + err);

        sol::variadic_results r;
        r.push_back({ L, sol::in_place_type<std::string>, std::move(out) });
        return r;
    };

    // socketley.json_decode(str) → Lua value, or false + why
    //
    // The depth refusal is the one that matters here: this call is written to be
    // pointed at a request body, so the nesting is chosen by whoever sent it.
    // Answering nil would be indistinguishable from a document that really did
    // decode to nil, which is the ambiguity this file's whole return contract
    // exists to remove.
    sk["json_decode"] = [this](sol::this_state L, std::string str)
                        -> sol::variadic_results {
        const char* p = str.data();
        const char* end = p + str.size();
        auto st = socketley::lua_json::json_status::ok;
        sol::object v = json_decode_value(m_lua, p, end, 0, st);
        if (st == socketley::lua_json::json_status::too_deep)
            return api_why(L, "socketley.json_decode(): the document is nested "
                              "deeper than " + std::to_string(json_max_depth) +
                              " levels");
        if (st != socketley::lua_json::json_status::ok)
            return api_why(L, "socketley.json_decode(): not a JSON document, at "
                              "byte " + std::to_string(
                                  static_cast<size_t>(p - str.data())));

        // Trailing bytes are a failure too, and this is where they are caught:
        // json_decode_value stops at the end of the first complete value and
        // says nothing about what follows.  Without this, `{"a":1} DROP TABLE`
        // decoded to {a=1} and the rest went unmentioned — the caller cannot
        // notice what it is never told, and a body with something appended to it
        // is exactly the case worth noticing.
        socketley::lua_json::json_skip_ws(p, end);
        if (p != end)
            return api_why(L, "socketley.json_decode(): " +
                              std::to_string(static_cast<size_t>(end - p)) +
                              " byte(s) of trailing data after the document");

        sol::variadic_results r;
        r.push_back({ L, std::move(v) });
        return r;
    };

    // socketley.subscribe(cache_name, channel, fn) → subscription_id
    //
    // The id is new, and it is what socketley.unsubscribe takes.  Returning one
    // rather than answering unsubscribe(cache_name, channel) follows the timers
    // — set_timeout hands back an integer that clear_timeout takes — and is the
    // only identity that can express the case the counterpart exists for: two
    // handlers on one channel, of which the script wants to drop one.
    sk["subscribe"] = [this](std::string cache_name, std::string channel,
                             sol::protected_function fn) -> int {
        // 0, which is never an id — see the note above on where ids start.  The
        // runtime is down and a registration made now would outlive the stop
        // that was supposed to end them all; see registrations_severed().
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

        // Parked rather than appended when a dispatch is walking a vector; see
        // dispatch_publish.  A handler that subscribes does not thereby receive
        // the message it is handling.
        if (m_dispatch_depth > 0)
            m_pending_subscriptions.emplace_back(std::move(key), std::move(sub));
        else
            m_subscriptions[std::move(key)].push_back(std::move(sub));
        return id;
    };

    // socketley.unsubscribe(subscription_id) → bool
    //
    // True when it removed a live registration, false when the id names none —
    // an id that was never issued, or one already unsubscribed.  The timers
    // return nothing from clear_timeout because cancelling a timeout that has
    // already fired is an ordinary thing to do and says nothing about the
    // script; a subscription has no such state.  It is live until this call, so
    // false means the script asked about something that does not exist, and
    // that is worth being able to see.
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

        // Marked now, taken out now — unless a dispatch is walking the vector
        // this entry is in, in which case the walk finishes first.  A handler
        // unsubscribing itself is the ordinary way to write a one-shot
        // subscriber, so this is not an exotic path.
        if (m_dispatch_depth == 0)
            settle_subscriptions();
        return true;
    };

    // socketley.pipe(src_name, src_fd, dst_name[, dst_fd])
    //
    // ─── TWO OPERATIONS, AND THE ARGUMENT COUNT IS WHICH ────────────────────
    //
    // This was one four-argument call that did two unrelated things, and told
    // you it had done the one you asked for either way.
    //
    // Inside one runtime it is a pipe: lua_pipe writes each connection's
    // descriptor into the other's `pipe_peer_fd`, and bytes arriving on one go
    // straight out of the other.  Both descriptors are needed and both are
    // used.
    //
    // Across two runtimes it is not a pipe and cannot be.  `pipe_peer_fd` is an
    // index into ONE server's connection table, so there is no pairing to make;
    // what the branch actually does is route_client(src_fd, dst_name), which
    // hands the connection to the destination RUNTIME and lets that runtime
    // decide what to do with it.  There is no destination descriptor in that at
    // all — and the fourth argument was read by nothing:
    //
    //     socketley.pipe("a", 3, "b", 7)  ->  true, and 7 was never looked at
    //
    // A script that went to the trouble of obtaining descriptor 7 from `b` was
    // told it had joined 3 to 7.  It had not; it had given the connection to
    // `b`, which delivered it wherever its own script says.
    //
    // So the fourth argument is optional now and the count states the request.
    // Four is the pipe and requires one runtime; three is the route and
    // requires two.  Asking for the combination that does not exist is refused
    // by name rather than served as the other one.
    sk["pipe"] = [owner](sol::this_state L, std::string src_name, int src_fd,
                         std::string dst_name,
                         sol::optional<int> dst_fd) -> sol::variadic_results {
        auto* mgr = owner->get_runtime_manager();
        if (!mgr)
            return api_why(L, "this runtime has no runtime manager");

        const std::string where = "socketley.pipe(\"" + src_name + "\", "
                                + std::to_string(src_fd) + ", \"" + dst_name + "\""
                                + (dst_fd ? ", " + std::to_string(*dst_fd) : "")
                                + ")";
        auto refuse = [&](const std::string& why) {
            api_diag(owner, where + ": " + why);
            return api_why(L, why);
        };

        if (src_name == dst_name)
        {
            // A pipe pairs two connections of one server, and only that
            // server's own object holds them.  Naming a third runtime twice
            // used to fall through to the cross-runtime branch and route a
            // runtime to itself.
            if (src_name != owner->get_name())
                return refuse("a pipe joins two connections of one server, and "
                              "only that server holds them — call it from \""
                              + src_name + "\"'s own script");
            if (!dst_fd)
                return refuse("a pipe joins two connections: the fourth "
                              "argument is the second one");
            if (owner->get_type() != runtime_server)
                return refuse("only a server has connections to pipe");
            if (!static_cast<server_instance*>(owner)->lua_pipe(src_fd, *dst_fd))
                return refuse("one of those is not an open connection of this "
                              "server");
            return api_yes(L);
        }

        if (dst_fd)
            return refuse("a pipe across two runtimes routes the connection to "
                          "\"" + dst_name + "\" and lets it decide which of its "
                          "own connections answers — there is no destination "
                          "descriptor to honour, so drop the fourth argument");

        auto* src_rt = mgr->get(src_name);
        auto* dst_rt = mgr->get(dst_name);
        if (!src_rt) return refuse("there is no runtime called \"" + src_name + "\"");
        if (!dst_rt) return refuse("there is no runtime called \"" + dst_name + "\"");
        if (src_rt->get_type() != runtime_server || dst_rt->get_type() != runtime_server)
            return refuse("both ends must be servers");
        auto* src_srv = static_cast<server_instance*>(src_rt);
        if (src_srv->route_client(src_fd, dst_name))
            return api_yes(L);
        // route_client refuses three different things, and the bare false told
        // them apart no better than it told any of them from success.
        return refuse("connection " + std::to_string(src_fd) + " could not be "
                      "routed to " + q(dst_name) + " — it is not an open "
                      "connection of " + q(src_name) + ", or it was itself "
                      "routed in from another runtime, or " + q(dst_name)
                      + " refused it");
    };

    // ─── socketley.cluster.* — cluster introspection API ───
    sol::table cluster_tbl = m_lua.create_table();

    // socketley.cluster.daemons() → array of {name, host, runtimes}
    cluster_tbl["daemons"] = [owner, this]() -> sol::table {
        sol::table result = m_lua.create_table();
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return result;
        auto* cd = mgr->get_cluster_discovery();
        if (!cd) return result;

        int i = 1;
        // Local daemon entry
        {
            sol::table d = m_lua.create_table();
            d["name"] = std::string(cd->get_daemon_name());
            d["host"] = std::string(cd->get_cluster_addr());
            size_t count = 0;
            {
                std::shared_lock lock(mgr->mutex);
                count = mgr->list().size();
            }
            d["runtimes"] = static_cast<int>(count);
            result[i++] = d;
        }
        // Remote daemons
        auto daemons = cd->get_all_daemons();
        for (const auto& rd : daemons)
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
    cluster_tbl["runtimes"] = [owner, this]() -> sol::table {
        sol::table result = m_lua.create_table();
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return result;
        auto* cd = mgr->get_cluster_discovery();
        if (!cd) return result;

        int i = 1;
        // Local runtimes
        {
            std::shared_lock lock(mgr->mutex);
            for (const auto& [name, inst] : mgr->list())
            {
                sol::table r = m_lua.create_table();
                r["daemon"] = std::string(cd->get_daemon_name());
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
        auto daemons = cd->get_all_daemons();
        for (const auto& rd : daemons)
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
    cluster_tbl["group"] = [owner, this](std::string group_name) -> sol::table {
        sol::table result = m_lua.create_table();
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return result;
        auto* cd = mgr->get_cluster_discovery();
        if (!cd) return result;

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
                    m["daemon"] = std::string(cd->get_daemon_name());
                    m["host"] = std::string(cd->get_cluster_addr());
                    m["port"] = inst->get_port();
                    // The figure a least-connections choice is made on.  A local
                    // member in a worker reported 0 here beside a remote
                    // member's true count, so every such choice picked the
                    // local one, however busy it was.
                    m["connections"] = static_cast<int>(inst->reported_connection_count());
                    result[i++] = m;
                }
            }
        }
        // Remote group members
        auto daemons = cd->get_all_daemons();
        for (const auto& rd : daemons)
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
    cluster_tbl["stats"] = [owner, this]() -> sol::table {
        sol::table result = m_lua.create_table();
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return result;
        auto* cd = mgr->get_cluster_discovery();
        if (!cd) return result;

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
        auto daemons = cd->get_all_daemons();
        for (const auto& rd : daemons)
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

    // Last, and over the top of the bindings above: a worker gets the same table
    // with the calls it cannot honour replaced by a refusal that names them.
    // Done here rather than by not binding them at all, so the two builds differ
    // in one place and the list of what is refused is readable in one place.
    if (in_worker_process())
        refuse_cross_runtime_api(sk, cluster_tbl);

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
    }

    m_lua["self"] = self;

    // Also register type-specific alias (server/client/cache/proxy) pointing to same table
    m_lua[type_to_string(owner->get_type())] = self;
}

void lua_context::register_server_table(runtime_instance* owner, sol::table& self)
{
    self["broadcast"] = [owner](std::string msg) {
        owner->lua_broadcast(msg);
    };
    // ─── THE SAME CONTRACT AT THE OTHER DOOR ────────────────────────────────
    //
    // socketley.create refuses a port it cannot honour.  Every mutator below
    // used to take whatever it was given and, when it could not honour it, do
    // nothing and say nothing.  Checking at one door and not the other is worse
    // than checking at neither, because it teaches a script author that the
    // check exists.
    //
    // So these answer the way the management family answers: `true`, or
    // `false, "<reason>"`.  Nothing that exists can be reading a value that
    // changed, because every one of them returned NOTHING before — the only
    // scripts affected are the ones that now have an answer where they had
    // silence.
    self["send"] = [owner, this](sol::this_state L, int client_id,
                                 std::string msg) -> sol::variadic_results {
        if (owner->is_udp())
            return api_why(L, "a UDP server has no connection to send to; use "
                              "self.broadcast");
        if (owner->lua_send_to(client_id, msg))
            return api_yes(L);
        // Four ways this used to be a silent no-op: an id that is not a
        // connection, one already closing, a routed-in handle whose origin is
        // gone, and an origin that has stopped.
        return api_why(L, "there is no open connection " + std::to_string(client_id)
                          + " on " + q(m_owner_name)
                          + " — it may have closed, or it may never have been one");
    };
    self["connections"] = [owner]() -> size_t {
        return owner->get_connection_count();
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
    self["owner_send"] = [owner](int client_id, std::string msg) -> bool {
        return static_cast<server_instance*>(owner)->owner_send(client_id, msg);
    };
    self["owner_broadcast"] = [owner](std::string msg) -> bool {
        return static_cast<server_instance*>(owner)->owner_broadcast(msg);
    };

    // Connection control
    self["disconnect"] = [owner, this](sol::this_state L,
                                       int client_id) -> sol::variadic_results {
        if (static_cast<server_instance*>(owner)->lua_disconnect(client_id))
            return api_yes(L);
        return api_why(L, "there is no open connection " + std::to_string(client_id)
                          + " on " + q(m_owner_name) + " to disconnect");
    };
    self["peer_ip"] = [owner](int client_id) -> std::string {
        return static_cast<server_instance*>(owner)->lua_peer_ip(client_id);
    };
    self["ws_headers"] = [owner, this](int client_id) -> sol::object {
        auto h = static_cast<server_instance*>(owner)->lua_ws_headers(client_id);
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
        auto ids = static_cast<server_instance*>(owner)->lua_clients();
        sol::table t = m_lua.create_table(static_cast<int>(ids.size()), 0);
        for (int i = 0; i < (int)ids.size(); ++i) t[i + 1] = ids[i];
        return t;
    };

    // Targeted multicast to a subset of clients
    // ─── A LIST WITH A HOLE IN IT IS NOT A SHORTER LIST ─────────────────────
    //
    // `if (v.is<int>()) fds.push_back(...)` dropped every entry that was not an
    // integer and sent to whatever was left.  `self.multicast({1, "2", 3}, m)`
    // therefore reached two of the three clients the script named and reported
    // nothing — and the entry it skipped is exactly the one whose id came back
    // from json_decode as a string, which is how this happens in practice.
    //
    // Refused, for the reason the `filters` validator gives in this same file: a
    // hole in a list is not visible from the outside, so the call fails rather
    // than half-works.  The array part only, stopping at the first gap, exactly
    // as `filters` and `routes` are read — and a keyed table, which reaches
    // nobody at all, is named rather than treated as an empty list.
    self["multicast"] = [owner](sol::this_state L, sol::table ids,
                                std::string msg) -> sol::variadic_results {
        std::vector<int> fds;
        for (size_t i = 1;; ++i)
        {
            sol::object v = ids[i];
            if (!v.valid() || v == sol::nil) break;
            if (v.get_type() != sol::type::number)
                return api_why(L, "multicast list entry " + std::to_string(i)
                                  + " is not a client id");
            const double d = v.as<double>();
            if (d != std::floor(d))
                return api_why(L, "multicast list entry " + std::to_string(i)
                                  + " is not a whole number");
            fds.push_back(static_cast<int>(d));
        }
        if (fds.empty())
        {
            bool any = false;
            ids.for_each([&](sol::object, sol::object) { any = true; });
            if (any)
                return api_why(L, "the multicast list has no entry at index 1 — "
                                  "it is an array of client ids, not a keyed table");
        }
        // The count, not a bool: every id was well formed, and how many still
        // name an open connection is the thing worth knowing.
        return api_count(L,
            static_cast<server_instance*>(owner)->lua_multicast(fds, msg));
    };

    // Per-connection metadata: nil value deletes the key
    self["set_data"] = [owner, this](sol::this_state L, int id, std::string key,
                                     sol::optional<std::string> val) -> sol::variadic_results {
        // An empty key is a key nothing can read back — get_data("") answers nil
        // whether it was ever set or not — so storing under it is a write that
        // cannot be observed.  It is also what a missing table field looks like
        // after `..`.
        if (key.empty())
            return api_why(L, "the metadata key is empty");
        auto* srv = static_cast<server_instance*>(owner);
        const bool ok = val ? srv->lua_set_data(id, key, *val)
                            : srv->lua_del_data(id, key);
        if (ok) return api_yes(L);
        return api_why(L, "there is no open connection " + std::to_string(id)
                          + " on " + q(m_owner_name) + " to carry metadata");
    };
    self["get_data"] = [owner, this](int id, std::string key) -> sol::object {
        auto v = static_cast<server_instance*>(owner)->lua_get_data(id, key);
        if (v.empty()) return sol::nil;
        return sol::make_object(m_lua, v);
    };

    // Upstream actions
    self["upstream_send"] = [owner](sol::this_state L, int conn_id,
                                    std::string msg) -> sol::variadic_results {
        if (static_cast<server_instance*>(owner)->lua_upstream_send(conn_id, msg))
            return api_yes(L);
        return api_why(L, "upstream " + std::to_string(conn_id)
                          + " is not connected — self.upstreams() lists the ones "
                            "that are");
    };
    self["upstream_broadcast"] = [owner](std::string msg) {
        static_cast<server_instance*>(owner)->lua_upstream_broadcast(msg);
    };
    self["upstreams"] = [owner, this]() -> sol::table {
        auto ids = static_cast<server_instance*>(owner)->lua_upstreams();
        sol::table t = m_lua.create_table(static_cast<int>(ids.size()), 0);
        for (int i = 0; i < (int)ids.size(); ++i) t[i + 1] = ids[i];
        return t;
    };

    // Multicast groups
    // An empty group name is refused at all three doors rather than at none:
    // it is a name no client can be reached by, and it is what a missing table
    // field looks like after `..`.
    self["join_group"] = [owner, this](sol::this_state L, int fd,
                                       std::string group) -> sol::variadic_results {
        if (group.empty()) return api_why(L, "the group name is empty");
        if (static_cast<server_instance*>(owner)->lua_join_group(fd, group))
            return api_yes(L);
        return api_why(L, "there is no open connection " + std::to_string(fd)
                          + " on " + q(m_owner_name) + " to put in a group");
    };
    self["leave_group"] = [owner, this](sol::this_state L, int fd,
                                        std::string group) -> sol::variadic_results {
        if (group.empty()) return api_why(L, "the group name is empty");
        if (static_cast<server_instance*>(owner)->lua_leave_group(fd, group))
            return api_yes(L);
        return api_why(L, "there is no open connection " + std::to_string(fd)
                          + " on " + q(m_owner_name));
    };
    // The count, for the reason lua_group_send gives: a group that exists and is
    // empty is what a misspelled name looks like once its last real member has
    // left, and a bool cannot tell that from a group that is full.
    self["group_send"] = [owner](sol::this_state L, std::string group,
                                 std::string msg) -> sol::variadic_results {
        if (group.empty()) return api_why(L, "the group name is empty");
        return api_count(L,
            static_cast<server_instance*>(owner)->lua_group_send(group, msg));
    };

    // Zero-copy pipe pairing
    self["pipe"] = [owner, this](sol::this_state L, int fd_a,
                                 int fd_b) -> sol::variadic_results {
        if (fd_a == fd_b)
            return api_why(L, "a pipe joins two connections, and those are one");
        if (static_cast<server_instance*>(owner)->lua_pipe(fd_a, fd_b))
            return api_yes(L);
        return api_why(L, "one of " + std::to_string(fd_a) + " and "
                          + std::to_string(fd_b) + " is not an open connection on "
                          + q(m_owner_name));
    };
    self["unpipe"] = [owner](sol::this_state L, int fd) -> sol::variadic_results {
        if (static_cast<server_instance*>(owner)->lua_unpipe(fd))
            return api_yes(L);
        return api_why(L, "connection " + std::to_string(fd) + " is not piped");
    };

    // ── Last, and over the top of the binding above ─────────────────────────
    //
    // self.route() names another runtime, so it looks that name up in the
    // runtime map exactly as the socketley.* calls do — and a worker holds no
    // such map, only its own runtime.  It escaped their refusal for one reason:
    // it is spelled self. rather than socketley., and the refusal was installed
    // per table rather than per what a call reaches for.
    //
    // Left alone it answered a bare false, which is also what it answers for a
    // target that does not exist.  A script could not tell a runtime that is
    // absent from one that is merely in another process, and the accepted-but-
    // not-applied call is the shape this tree refuses everywhere else.
    //
    // What this does NOT say is how routing a connection between processes
    // should eventually work.  It says only that it cannot happen in a worker
    // today, which is true and is all that is known: when a connection can be
    // handed to another process, this is the binding that stops being refused,
    // and nothing here decides what that mechanism looks like.
    //
    // Only route().  unroute(), get_route() and owner_send() answer from this
    // runtime's own tables, and in a worker those are empty because nothing was
    // ever routed — so their false is the truth rather than a substitute for
    // it, and refusing them would replace a correct answer with an error.
    if (in_worker_process())
    {
        sol::function make = refusal_factory(m_lua);
        if (make.valid())
        {
            sol::function f = make(
                worker_refusal("self.route", "a target that does not exist"));
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
    self["send"] = [owner, this](sol::this_state L,
                                 std::string msg) -> sol::variadic_results {
        if (owner->lua_send(msg))
            return api_yes(L);
        return api_why(L, q(m_owner_name) + " is not connected to its server, "
                          "or was created --mode in and does not send");
    };
    self["connections"] = [owner]() -> size_t {
        return owner->get_connection_count();
    };
    self["protocol"] = owner->is_udp() ? "udp" : "tcp";
}

void lua_context::register_cache_table(runtime_instance* owner, sol::table& self)
{
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
    self["sadd"] = [owner](std::string key, std::string member) -> int {
        return owner->lua_cache_sadd(key, member);
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

    self["connections"] = [owner]() -> size_t {
        return owner->get_connection_count();
    };
}

void lua_context::register_proxy_table(runtime_instance* owner, sol::table& self)
{
    auto* proxy = static_cast<proxy_instance*>(owner);

    self["connections"] = [owner]() -> size_t {
        return owner->get_connection_count();
    };
    self["protocol"] = proxy->get_protocol() == protocol_http ? "http" : "tcp";
    self["peer_ip"] = [proxy](int client_id) -> std::string {
        return proxy->lua_peer_ip(client_id);
    };
    self["close_client"] = [proxy](sol::this_state L,
                                   int client_id) -> sol::variadic_results {
        if (proxy->lua_close_client(client_id))
            return api_yes(L);
        // Both halves of a proxied pair are ints, and handing this the backend
        // half is the mistake a script makes; it used to do nothing at all.
        return api_why(L, "there is no open client connection "
                          + std::to_string(client_id)
                          + " on this proxy — self.clients() lists the ones "
                            "there are");
    };
    self["clients"] = [proxy, this]() -> sol::table {
        auto ids = proxy->lua_clients();
        sol::table t = m_lua.create_table(static_cast<int>(ids.size()), 0);
        for (int i = 0; i < (int)ids.size(); ++i) t[i + 1] = ids[i];
        return t;
    };
    self["backends"] = [proxy, this]() -> sol::table {
        auto addrs = proxy->lua_backends();
        sol::table t = m_lua.create_table(static_cast<int>(addrs.size()), 0);
        for (int i = 0; i < (int)addrs.size(); ++i) t[i + 1] = addrs[i];
        return t;
    };
    self["backend_health"] = [proxy, this]() -> sol::table {
        auto health = proxy->lua_backend_health();
        sol::table t = m_lua.create_table(0, static_cast<int>(health.size()));
        for (const auto& [idx, state] : health)
            t[idx + 1] = state;
        return t;
    };
    self["stats"] = [proxy, this]() -> sol::table {
        sol::table t = m_lua.create_table(0, 6);
        t["connections"] = proxy->get_connection_count();
        t["bytes_in"] = proxy->m_stat_bytes_in.load(std::memory_order_relaxed);
        t["bytes_out"] = proxy->m_stat_bytes_out.load(std::memory_order_relaxed);
        t["total_connections"] = proxy->m_stat_total_connections.load(std::memory_order_relaxed);
        t["total_messages"] = proxy->m_stat_total_messages.load(std::memory_order_relaxed);
        auto addrs = proxy->lua_backends();
        t["backend_count"] = addrs.size();
        return t;
    };
}

#endif // SOCKETLEY_NO_LUA
