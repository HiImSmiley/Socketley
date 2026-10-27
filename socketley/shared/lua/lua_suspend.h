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
// Three measured facts decide everything here.
//
// A thread a handler stopped on has to be kept off the collector until it is
// resumed.
//
// A thread that is still suspended must never be handed to another handler --
// reusing one does not fail, it feeds the new handler's arguments into the old
// handler's pending await, which then answers with a value nobody asked for.
//
// And an invocation that does not stop must be charged NOTHING for the
// possibility that it might.  The first version of this file enrolled every
// invocation in two hash tables and took it back out again, which cost 0.078 us
// per callback: an echo server with a script went from 2,471,474 messages a
// second to 1,777,358, a 29 per cent loss, while the same server with no script
// was unchanged at 5.6M.  So the tables below are populated by the AWAIT and
// not by the call, and a handler that never waits touches a vector and nothing
// else.

#ifndef SOCKETLEY_NO_LUA

#include <sol/sol.hpp>

#include <algorithm>
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
#include "../loop/coarse_clock.h"

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
    // the pool is what makes running every callback this way affordable at all.
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
        m_frames.reserve(8);
        m_pool.reserve(max_pooled);
    }

    bool attached() const { return m_lua != nullptr; }

    // ─── Running a callback so that it MAY stop ─────────────────────────────
    // Answers what became of it.  `out_id` is set only for `suspended`, and is
    // then the handle every later settle names.
    //
    // The whole hot path is here: take a thread off the pool, push a frame,
    // resume.  Nothing is allocated and nothing is hashed unless the handler
    // actually stops.
    template <class... A>
    outcome start(sol::protected_function& fn, const char* what,
                  uint32_t exec_ms, id_t& out_id, A&&... args)
    {
        out_id = 0;

        // Taken before anything can return, so a handler set for this call is
        // never left over for the next one.
        result_fn mine = std::move(m_next_result);
        m_next_result  = nullptr;

        if (!m_lua || !fn.valid())
        {
            if (mine)
                mine(nullptr, 0, "the callback is not defined");
            return outcome::failed;
        }

        const auto [th, ref] = acquire();
        if (SOCKETLEY_UNLIKELY(!th))
        {
            if (mine)
                mine(nullptr, 0, "no coroutine could be made for the callback");
            return outcome::failed;
        }
        if (SOCKETLEY_UNLIKELY(static_cast<bool>(mine)))
            m_results[th] = std::move(mine);

        m_frames.push_back(frame{th, ref, what, exec_ms, 0});

        // The registry by hand rather than fn.push(th).  sol's push compares
        // the target state with the reference's own, and a coroutine is a
        // different lua_State, so it takes the slow arm: push there, then
        // lua_xmove across.  A thread shares its parent's registry, so one
        // rawgeti on the thread is the same value with neither step -- measured
        // at 1.95 per cent of the worker in lua_xmove alone.
        lua_rawgeti(th, LUA_REGISTRYINDEX, fn.registry_index());
        (sol::stack::push(th, std::forward<A>(args)), ...);

        ++m_stat_started;
        return run(static_cast<int>(sizeof...(A)), out_id);
    }

    // ─── What an awaiting binding needs ─────────────────────────────────────
    // The handle for the invocation running on this thread, allocating it here
    // because this is the first moment anybody needs one.  0 means the caller
    // is not inside a callback that may wait -- the script's top level, or one
    // of the callbacks still invoked the old way -- or that too many handlers
    // are already stopped.
    id_t enrol_await(lua_State* th)
    {
        for (auto it = m_frames.rbegin(); it != m_frames.rend(); ++it)
        {
            if (it->th != th)
                continue;
            if (it->id == 0)
            {
                if (SOCKETLEY_UNLIKELY(m_live.size() >= max_suspended))
                {
                    report_overflow(it->what);
                    return 0;
                }
                const id_t id = next_id();
                record r;
                r.th      = th;
                r.ref     = it->ref;
                r.what    = it->what;
                r.exec_ms = it->exec_ms;
                r.armed   = socketley::coarse_now();
                m_live.emplace(id, r);
                it->id = id;
            }
            return it->id;
        }
        return 0;
    }

    // Which await of its invocation the last note_await() made, for the settle of its answer to name.
    uint32_t await_seq(id_t id)
    {
        const record* r = find(id);
        return r ? r->awaits : 0;
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
        r->armed    = socketley::coarse_now();
    }

    // Told once per await, after the handler has run on, so whatever the
    // runtime was holding for that answer is let go only once the answer has
    // been used.
    void set_await_ended(std::function<void(uint64_t)> h) { m_await_ended = std::move(h); }

    // ─── Giving an invocation its answer ────────────────────────────────────
    // An unknown id is a reply that arrived after its handler was let go, and
    // is ignored rather than reported: the settle that already happened is the
    // one that counted.
    //
    // `seq`, when given, is what await_seq() said when the await was made: a reply for an earlier await of the same
    // invocation, one that was given up on and came anyway, is then not taken as the answer to the one waiting now.
    void settle_value(id_t id, std::string_view value, uint32_t seq = 0)
    {
        record* r = find(id);
        if (!r || (seq && r->awaits != seq))
            return;
        sol::stack::push(r->th, value);
        resume(id, 1);
    }

    // The same with any number of values, pushed by `push` onto the thread the
    // handler stopped on and counted by what it returns -- for an answer that is
    // a table, or several results, rather than the one string settle_value takes.
    template <class Push>
    void settle_with(id_t id, Push&& push, uint32_t seq = 0)
    {
        record* r = find(id);
        if (!r || (seq && r->awaits != seq))
            return;
        const int n = push(r->th);
        resume(id, n);
    }

    // ─── Getting what a callback returned ───────────────────────────────────
    // A callback run for its answer rather than for its effects -- one that
    // decides whether a request goes on -- asks to be told what it returned
    // when it finishes, which for a callback that waits is after a later
    // resume.  `results` are on the thread's stack for the call and no longer,
    // and `error` is null unless the callback raised or was given up on; it is
    // called exactly once per start() it was set for, except when the runtime
    // lets every waiting callback go, which is the runtime coming down.
    using result_fn = std::function<void(lua_State* results, int count, const char* error)>;
    void set_next_result(result_fn fn) { m_next_result = std::move(fn); }

    // Every await ends in exactly one settle, including the ones whose answer
    // never came.  A script therefore never has to bound its own wait, which is
    // the whole point: `local v, err = self.cache(...)` always returns.
    void settle_nil(id_t id, std::string_view reason, uint32_t seq = 0)
    {
        record* r = find(id);
        if (!r || (seq && r->awaits != seq))
            return;
        lua_pushnil(r->th);
        sol::stack::push(r->th, reason);
        resume(id, 2);
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
        m_results.clear();
        m_next_result = nullptr;
        if (!m_lua)
        {
            m_live.clear();
            m_frames.clear();
            m_pool.clear();
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
            // A resumed invocation's frame holds the same reference and lets it go below, after its resume.
            const bool running = std::any_of(m_frames.begin(), m_frames.end(),
                                             [&](const frame& f) { return f.ref == r.ref; });
            if (r.ref != LUA_NOREF && !running)
                luaL_unref(L, LUA_REGISTRYINDEX, r.ref);
        }
        m_live.clear();
        // A frame still running is let go once its resume has returned, not under it.
        for (const frame& f : m_frames)
            if (f.ref != LUA_NOREF)
                m_orphaned.push_back(f.ref);
        m_frames.clear();
        for (const auto& p : m_pool)
            luaL_unref(L, LUA_REGISTRYINDEX, p.ref);
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

    // One invocation currently on the stack.  A vector and not a map because
    // this is the hot path: a callback that runs straight through pushes one of
    // these and pops it, and nothing is hashed.  Depth is 1 except where one
    // callback's own work reaches another runtime's callbacks.
    struct frame
    {
        lua_State*  th{nullptr};
        int         ref{LUA_NOREF};
        const char* what{nullptr};
        uint32_t    exec_ms{0};
        id_t        id{0};           // 0 until an await needs a handle
    };

    // The thread and the registry reference that holds it, kept together so the
    // hot path never reads the registry back -- lua_rawgeti plus lua_tothread
    // plus lua_pop, per call, for a pointer we already had.
    struct pooled
    {
        lua_State* th{nullptr};
        int        ref{LUA_NOREF};
    };

    record* find(id_t id)
    {
        const auto it = m_live.find(id);
        return it == m_live.end() ? nullptr : &it->second;
    }

    std::pair<lua_State*, int> acquire()
    {
        if (SOCKETLEY_LIKELY(!m_pool.empty()))
        {
            const pooled p = m_pool.back();
            m_pool.pop_back();
            // No lua_settop here: release() clears the stack BEFORE pooling,
            // which it has to do anyway so a pooled thread holds nothing alive,
            // and a fresh one from lua_newthread is empty already.  Clearing
            // again on the way out was the same call twice per invocation.
            return {p.th, p.ref};
        }
        lua_State* L = m_lua->lua_state();
        lua_State* th = lua_newthread(L);
        return {th, luaL_ref(L, LUA_REGISTRYINDEX)};   // the ref pops the thread
    }

    // The chokepoint the whole file exists for: a thread goes back only when
    // lua_resume said it was done.
    void release(lua_State* th, int ref, bool completed)
    {
        if (SOCKETLEY_UNLIKELY(!completed || m_pool.size() >= max_pooled))
        {
            if (ref != LUA_NOREF)
                luaL_unref(m_lua->lua_state(), LUA_REGISTRYINDEX, ref);
            return;
        }
        lua_settop(th, 0);
        m_pool.push_back(pooled{th, ref});
    }

    id_t next_id()
    {
        // Zero is "no handle yet", so it is never handed out.
        do {
            if (++m_seq == 0)
                m_seq = 1;
        } while (m_live.find(m_seq) != m_live.end());
        return m_seq;
    }

    // Put the stopped invocation back on the stack and carry on from its await.
    void resume(id_t id, int nargs)
    {
        record* r = find(id);
        if (!r)
            return;

        // Read before the resume and released after it: the resume may start a
        // NEW await on the same invocation, and it is the old one that ends
        // here.
        const bool     had_await = r->awaiting;
        const uint64_t ended_ctx = r->ctx;
        r->awaiting = false;
        r->wait_ms  = 0;

        m_frames.push_back(frame{r->th, r->ref, r->what, r->exec_ms, id});
        id_t ignored = 0;
        run(nargs, ignored);

        // After the resume, so a handler answering the peer that half-closed
        // still finds the connection its runtime was holding open for it.
        if (had_await && m_await_ended)
            m_await_ended(ended_ctx);
    }

    // One resume of whatever frame is on top, and the bookkeeping that follows
    // from what it answered.
    outcome run(int nargs, id_t& out_id)
    {
        // By value: the resume can push frames of its own and move the vector.
        const frame started = m_frames.back();

        int rc;
        {
            lua_deadline::scope guard(started.what, started.exec_ms,
                                      m_owner_name.c_str());
            // Three arguments and not two: sol's 5.1 compatibility layer
            // defines lua_resume with the 5.4 signature and drops the caller.
            ++m_resuming;
            rc = lua_resume(started.th, nullptr, nargs);
            --m_resuming;
        }

        // A script that stopped its own runtime ran forget_all() under this
        // resume, which let the frame go with everything else.
        if (SOCKETLEY_UNLIKELY(m_frames.empty()))
        {
            // Only the outermost resume releases, since a frame below this one may still be running.
            if (m_resuming == 0)
            {
                for (const int ref : m_orphaned)
                    luaL_unref(m_lua->lua_state(), LUA_REGISTRYINDEX, ref);
                m_orphaned.clear();
            }
            return outcome::failed;
        }

        const frame done = m_frames.back();   // an await may have given it an id
        m_frames.pop_back();

        if (rc == LUA_YIELD)
        {
            if (SOCKETLEY_UNLIKELY(done.id == 0))
            {
                // The script called coroutine.yield() itself, so nothing is
                // going to resume it.  Reported and let go rather than pooled:
                // a suspended thread handed to the next handler answers its
                // await with the wrong value.
                std::cerr << lua_diag::tag(m_owner_name) << ' '
                          << (done.what ? done.what : "callback")
                          << " yielded without waiting for anything; it will not resume"
                          << std::endl;
                give_result(done.th, 1,
                            "yielded without waiting for anything");
                release(done.th, done.ref, false);
                return outcome::failed;
            }
            ++m_stat_suspended;
            out_id = done.id;
            return outcome::suspended;
        }

        // Read before the record goes, because the error object is on the
        // thread's stack and release() clears it.
        std::string err;
        if (SOCKETLEY_UNLIKELY(rc != 0))
        {
            const char* msg = lua_tostring(done.th, -1);
            err.assign(msg ? msg : "(no message)");
        }

        if (SOCKETLEY_UNLIKELY(!m_results.empty()))
            give_result(done.th, rc, rc == 0 ? nullptr : err.c_str());

        if (done.id != 0)
            m_live.erase(done.id);
        release(done.th, done.ref, rc == 0);

        if (SOCKETLEY_UNLIKELY(rc != 0))
        {
            std::cerr << lua_diag::tag(m_owner_name) << ' '
                      << (done.what ? done.what : "callback")
                      << " error: " << err << std::endl;
            return outcome::failed;
        }
        return outcome::finished;
    }

    // The handler registered for this thread, if there is one, told how the
    // callback ended; `rc` 0 means it returned and its values are on the stack.
    void give_result(lua_State* th, int rc, const char* error)
    {
        const auto it = m_results.find(th);
        if (it == m_results.end())
            return;
        result_fn fn = std::move(it->second);
        m_results.erase(it);
        fn(th, rc == 0 ? lua_gettop(th) : 0, error);
    }

    void report_overflow(const char* what)
    {
        ++m_stat_refused;
        if (m_stat_refused == 1)
            std::cerr << lua_diag::tag(m_owner_name) << ' ' << (what ? what : "callback")
                      << " could not wait: " << max_suspended
                      << " callbacks are already waiting on this runtime" << std::endl;
    }

    sol::state* m_lua{nullptr};
    std::string m_owner_name;

    std::vector<frame>               m_frames;

    // The registry references of frames forget_all() let go while they ran, released after their resume.

    std::vector<int> m_orphaned;
    // Resumes under way, nested when a handler's script starts another.
    uint32_t m_resuming{0};
    std::vector<pooled>              m_pool;
    std::unordered_map<id_t, record> m_live;
    std::vector<id_t>                m_expired;
    std::function<void(uint64_t)>    m_await_ended;

    id_t  m_seq{0};

    result_fn                              m_next_result;
    std::unordered_map<lua_State*, result_fn> m_results;

    uint64_t m_stat_started{0};
    uint64_t m_stat_suspended{0};
    uint64_t m_stat_expired{0};
    uint64_t m_stat_refused{0};
};

#endif // SOCKETLEY_NO_LUA
