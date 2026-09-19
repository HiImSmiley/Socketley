#pragma once
// A callback that stopped in the middle, and the answer it is stopped for.
//
// Every Lua callback ran to the end in one go, so a script could only answer
// from what it already held: asking anything of another runtime meant blocking
// the event loop for every runtime in the daemon, which is what socketley.http
// does and why the manual tells scripts to use it only in on_start.  A callback
// run on a coroutine can stop instead, and the daemon goes on serving while it
// waits.
//
// Two measured facts decide everything here.  A thread a handler stopped on has
// to be kept off the collector until it is resumed.  And a thread that is still
// suspended must never be handed to another handler -- reusing one does not
// fail, it feeds the new handler's arguments into the old handler's pending
// await, which then answers with a value nobody asked for.

#ifndef SOCKETLEY_NO_LUA

#include <sol/sol.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <iostream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "lua_context.h"

// One runtime's suspended callbacks.  Lives beside the Lua state because a
// thread belongs to the state that made it, and dies with it.
class lua_suspender
{
public:
    // An invocation and not an await: a handler that waits three times keeps
    // one of these, so a reply can only ever reach the handler that asked.
    using id_t = uint32_t;

    // What one invocation did.
    enum class outcome : uint8_t
    {
        finished,   // ran to the end; nothing is owed
        suspended,  // stopped on an await; exactly one settle is owed
        failed      // raised, and it has been reported
    };

    // How many invocations of one runtime may be waiting at once.  The same
    // number request_channel bounds its parked tickets by, for the same reason:
    // a target that never answers must not be able to grow this.
    static constexpr size_t max_suspended = 4096;

    // Threads kept for reuse.  A fresh coroutine per call measured 0.524 us
    // against 0.161 for a plain protected call, and a pooled one 0.158 -- so
    // the pool is what makes running every callback this way free.
    static constexpr size_t max_pooled = 64;

    lua_suspender() = default;

    lua_suspender(const lua_suspender&)            = delete;
    lua_suspender& operator=(const lua_suspender&) = delete;

    ~lua_suspender() { forget_all(); }

    // The state whose threads these are, and the name diagnostics carry.  Set
    // once, after the script has loaded.
    void attach(sol::state* lua, std::string_view owner_name)
    {
        m_lua = lua;
        m_owner_name.assign(owner_name);
    }

    bool attached() const { return m_lua != nullptr; }

    // ─── Running a callback so that it MAY stop ─────────────────────────────
    // Answers what became of it.  `out_id` is set only for `suspended`, and is
    // then the handle every later settle names.
    template <class... A>
    outcome start(sol::protected_function& fn, const char* what,
                  uint32_t exec_ms, id_t& out_id, A&&... args)
    {
        out_id = 0;
        if (!m_lua || !fn.valid())
            return outcome::failed;

        if (m_live.size() >= max_suspended)
        {
            // Refused here rather than at the await, because a handler stopped
            // by a full table would have run half its work first.
            report_overflow(what);
            return outcome::failed;
        }

        const auto [th, ref] = acquire();
        if (!th)
            return outcome::failed;

        fn.push(th);
        (sol::stack::push(th, std::forward<A>(args)), ...);

        const id_t id = enrol(th, ref, what, exec_ms);
        const outcome o = step(id, static_cast<int>(sizeof...(A)));
        if (o == outcome::suspended)
            out_id = id;
        return o;
    }

    // ─── What an awaiting binding needs ─────────────────────────────────────
    // Which invocation is running on this thread, 0 when the caller is not on
    // one of ours -- which is how a binding tells "inside a callback that may
    // wait" from "inside the script's top level".
    id_t running_on(lua_State* th) const
    {
        const auto it = m_by_thread.find(th);
        return it == m_by_thread.end() ? 0 : it->second;
    }

    // Note that this invocation has posted something and is about to yield, so
    // the deadline dates from the await rather than from the callback's start.
    //
    // `ctx` means nothing here.  It is handed straight back to the runtime when
    // the await ends, which is how a server can hold the connection its handler
    // is answering open for a reply the script has not produced yet.
    void note_await(id_t id, uint32_t wait_ms, uint64_t ctx = 0)
    {
        record* r = find(id);
        if (!r)
            return;
        r->awaits++;
        r->awaiting = true;
        r->ctx      = ctx;
        r->wait_ms  = wait_ms;
        r->armed    = std::chrono::steady_clock::now();
    }

    // Told once per await, after the handler has run on, so whatever the
    // runtime was holding for that answer is let go only once the answer has
    // been used.
    void set_await_ended(std::function<void(uint64_t)> h) { m_await_ended = std::move(h); }

    // ─── Giving an invocation its answer ────────────────────────────────────
    // An unknown id is a reply that arrived after its handler was let go, and
    // is ignored rather than reported: the settle that already happened is the
    // one that counted.
    void settle_value(id_t id, std::string_view value)
    {
        record* r = find(id);
        if (!r)
            return;
        sol::stack::push(r->th, value);
        step(id, 1);
    }

    // Every await ends in exactly one settle, including the ones whose answer
    // never came.  A script therefore never has to bound its own wait, which is
    // the whole point: `local v, err = self.cache(...)` always returns.
    void settle_nil(id_t id, std::string_view reason)
    {
        record* r = find(id);
        if (!r)
            return;
        lua_pushnil(r->th);
        sol::stack::push(r->th, reason);
        step(id, 2);
    }

    // ─── The bound ──────────────────────────────────────────────────────────
    // Give up on anything that has waited past its budget.  An await nothing
    // ever settles is the unbounded wait one level up, so this is not optional
    // -- request_channel promises exactly one reply, and a parked ticket across
    // a process boundary is where that promise waits on somebody else.
    size_t expire(std::chrono::steady_clock::time_point now)
    {
        m_expired.clear();
        for (const auto& [id, r] : m_live)
        {
            if (r.wait_ms == 0)
                continue;   // running rather than waiting: the count hook bounds it
            if (now - r.armed >= std::chrono::milliseconds(r.wait_ms))
                m_expired.push_back(id);
        }

        // Collected before settling, because settling runs the script and the
        // script may start or finish invocations under the iterator.
        m_stat_expired += m_expired.size();
        for (const id_t id : m_expired)
            settle_nil(id, "timeout");
        return m_expired.size();
    }

    // Whether the sweep has anything to come back for.
    bool idle() const { return m_live.empty(); }

    size_t suspended_count() const { return m_live.size(); }
    uint64_t stat_started()   const { return m_stat_started; }
    uint64_t stat_suspended() const { return m_stat_suspended; }
    uint64_t stat_expired()   const { return m_stat_expired; }
    uint64_t stat_refused()   const { return m_stat_refused; }

    // ─── Teardown ───────────────────────────────────────────────────────────
    // Let every stopped handler go WITHOUT resuming it.  Used when the runtime
    // itself is going away, where running more script would reach a half torn
    // down instance; everywhere else the answer is settle_nil, so the script
    // sees a failure rather than silence.
    void forget_all()
    {
        if (!m_lua)
        {
            m_live.clear();
            m_by_thread.clear();
            return;
        }
        lua_State* L = m_lua->lua_state();
        for (auto& [id, r] : m_live)
        {
            (void)id;
            // Let go of what the runtime held for it, even here: the handler is
            // not being resumed, but the hold is still a hold.
            if (r.awaiting && m_await_ended)
                m_await_ended(r.ctx);
            if (r.ref != LUA_NOREF)
                luaL_unref(L, LUA_REGISTRYINDEX, r.ref);
        }
        m_live.clear();
        m_by_thread.clear();
        for (const int ref : m_pool)
            luaL_unref(L, LUA_REGISTRYINDEX, ref);
        m_pool.clear();
    }

private:
    struct record
    {
        lua_State*  th{nullptr};
        int         ref{LUA_NOREF};
        const char* what{nullptr};   // a literal from the call site, so it outlives this
        uint32_t    exec_ms{0};      // what one resume may hold the loop for
        uint32_t    wait_ms{0};      // how long this await may go unanswered; 0 = running
        uint32_t    awaits{0};
        bool        awaiting{false}; // an answer is outstanding for this one
        uint64_t    ctx{0};          // the call site's, opaque here
        std::chrono::steady_clock::time_point armed{};
    };

    record* find(id_t id)
    {
        const auto it = m_live.find(id);
        return it == m_live.end() ? nullptr : &it->second;
    }

    // A thread to run one invocation on, from the pool when there is one.  The
    // pool only ever holds threads that RAN OUT, never ones that stopped.
    std::pair<lua_State*, int> acquire()
    {
        lua_State* L = m_lua->lua_state();
        while (!m_pool.empty())
        {
            const int ref = m_pool.back();
            m_pool.pop_back();
            lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
            lua_State* th = lua_tothread(L, -1);
            lua_pop(L, 1);
            if (th)
            {
                lua_settop(th, 0);
                return {th, ref};
            }
            luaL_unref(L, LUA_REGISTRYINDEX, ref);   // the registry lost it
        }

        lua_State* th = lua_newthread(L);
        return {th, luaL_ref(L, LUA_REGISTRYINDEX)};   // the ref pops the thread
    }

    // The chokepoint the whole file exists for: a thread goes back only when
    // lua_resume said it was done.
    void release(lua_State* th, int ref, bool completed)
    {
        lua_State* L = m_lua->lua_state();
        if (!completed || m_pool.size() >= max_pooled)
        {
            if (ref != LUA_NOREF)
                luaL_unref(L, LUA_REGISTRYINDEX, ref);
            (void)th;
            return;
        }
        lua_settop(th, 0);
        m_pool.push_back(ref);
    }

    id_t enrol(lua_State* th, int ref, const char* what, uint32_t exec_ms)
    {
        const id_t id = next_id();
        record r;
        r.th      = th;
        r.ref     = ref;
        r.what    = what;
        r.exec_ms = exec_ms;
        r.armed   = std::chrono::steady_clock::now();
        m_live.emplace(id, r);
        m_by_thread[th] = id;
        ++m_stat_started;
        return id;
    }

    id_t next_id()
    {
        // Zero is "not on one of ours", so it is never handed out.
        do {
            if (++m_seq == 0)
                m_seq = 1;
        } while (m_live.find(m_seq) != m_live.end());
        return m_seq;
    }

    // One resume, and the bookkeeping that follows from what it answered.
    outcome step(id_t id, int nargs)
    {
        record* r = find(id);
        if (!r)
            return outcome::failed;

        lua_State*  th      = r->th;
        const int   ref     = r->ref;
        const char* what    = r->what;
        const uint32_t exec = r->exec_ms;

        // Read before the resume and released after it: the resume may start a
        // NEW await on the same invocation, and it is the old one that ends
        // here.
        const bool     had_await = r->awaiting;
        const uint64_t ended_ctx = r->ctx;

        // Cleared before the resume so that a handler which returns without
        // awaiting again is not expired by the budget of the await it just
        // finished; note_await sets it if the handler stops once more.
        r->wait_ms  = 0;
        r->awaiting = false;

        int rc;
        {
            lua_deadline::scope guard(what, exec, m_owner_name.c_str());
            // Three arguments and not two: sol's 5.1 compatibility layer
            // defines lua_resume with the 5.4 signature and drops the caller.
            rc = lua_resume(th, nullptr, nargs);
        }

        // After the resume, so a handler answering the peer that half-closed
        // still finds the connection its runtime was holding open for it.
        if (had_await && m_await_ended)
            m_await_ended(ended_ctx);

        if (rc == LUA_YIELD)
        {
            ++m_stat_suspended;
            return outcome::suspended;
        }

        // Read before the record goes, because the error object is on the
        // thread's stack and release() clears it.
        std::string err;
        if (rc != 0)
        {
            const char* msg = lua_tostring(th, -1);
            err.assign(msg ? msg : "(no message)");
        }

        m_by_thread.erase(th);
        m_live.erase(id);
        release(th, ref, rc == 0);

        if (rc != 0)
        {
            std::cerr << lua_diag::tag(m_owner_name) << ' ' << (what ? what : "callback")
                      << " error: " << err << std::endl;
            return outcome::failed;
        }
        return outcome::finished;
    }

    void report_overflow(const char* what)
    {
        ++m_stat_refused;
        if (m_stat_refused == 1)
            std::cerr << lua_diag::tag(m_owner_name) << ' ' << (what ? what : "callback")
                      << " not run: " << max_suspended
                      << " callbacks are already waiting on this runtime" << std::endl;
    }

    sol::state* m_lua{nullptr};
    std::string m_owner_name;

    std::unordered_map<id_t, record>      m_live;
    std::unordered_map<lua_State*, id_t>  m_by_thread;
    std::vector<int>                      m_pool;
    std::vector<id_t>                     m_expired;
    std::function<void(uint64_t)>         m_await_ended;

    id_t  m_seq{0};

    uint64_t m_stat_started{0};
    uint64_t m_stat_suspended{0};
    uint64_t m_stat_expired{0};
    uint64_t m_stat_refused{0};
};

#endif // SOCKETLEY_NO_LUA
