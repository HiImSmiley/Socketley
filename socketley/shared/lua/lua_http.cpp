#ifndef SOCKETLEY_NO_LUA

#include "lua_http.h"

#include <algorithm>
#include <cmath>
#include <strings.h>
#include <unordered_map>

#include "lua_context.h"
#include "lua_suspend.h"
#include "../http/http_framing.h"
#include "../http/outbound_http.h"
#include "../loop/file_io.h"
#include "../loop/hash_pool.h"
#include "../runtime/runtime_instance.h"

sol::table lua_http_blocking(sol::state& lua, const sol::table& opts);

bool read_lua_http_options(const sol::table& opts, lua_http_options& out, std::string& why)
{
    // A pointer key: gcc folds sol2's literal-key getters of two lengths into one and warns of a bound none crosses.
    sol::optional<std::string> url = opts.get<sol::optional<std::string>>(static_cast<const char*>("url"));
    if (!url || url->empty())
    {
        why = "url required";
        return false;
    }
    out.url = std::move(*url);
    // Checked reads rather than converting ones, so a key written down and unreadable is reported, not defaulted.
    if (sol::object o = opts["method"]; o.valid() && o != sol::nil)
    {
        if (o.get_type() != sol::type::string)
        {
            why = "method must be a string";
            return false;
        }
        out.method = o.as<std::string>();
    }
    if (sol::object o = opts["body"]; o.valid() && o != sol::nil)
    {
        if (o.get_type() != sol::type::string)
        {
            why = "body must be a string";
            return false;
        }
        out.body = o.as<std::string>();
    }
    if (sol::object o = opts["timeout_ms"]; o.valid() && o != sol::nil)
    {
        const double d = o.get_type() == sol::type::number ? o.as<double>() : -1.0;
        if (o.get_type() != sol::type::number || d != std::floor(d) || d < 1.0 || d > 3600000.0)
        {
            why = "timeout_ms must be a whole number of milliseconds in 1..3600000";
            return false;
        }
        out.timeout_ms = static_cast<int>(d);
    }
    if (sol::object o = opts["headers"]; o.valid() && o != sol::nil)
    {
        bool strings = o.get_type() == sol::type::table;
        if (strings)
            o.as<sol::table>().for_each([&](sol::object k, sol::object v) {
                if (k.get_type() != sol::type::string || v.get_type() != sol::type::string)
                    strings = false;
                else
                    out.headers.emplace_back(k.as<std::string>(), v.as<std::string>());
            });
        if (!strings)
        {
            why = "headers must be a table of string keys and string values";
            return false;
        }
    }
    return true;
}

// The exchanges of one runtime's script on its loop, each on a connection of its own, ended by their own deadline.
class lua_http_client::ring final : public io_handler
{
public:
    using done_fn = std::function<void(socketley::http_answer)>;

    // Exchanges of one runtime at once, past which a call is refused rather than queued.
    static constexpr size_t max_calls = 256;

    ring(event_loop& loop, std::string what) : m_loop(loop), m_fio(loop, this), m_what(std::move(what))
    {
        reap(loop);
        if (!m_pool.attach(m_fio))
            m_pool.stop();
    }

    ~ring() override
    {
        m_loop.deregister_owner(this);
    }

    void on_cqe(struct io_uring_cqe* cqe) override
    {
        auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
        if (req && socketley::file_io::owns_type(req->type))
            m_fio.on_cqe(cqe);
    }

    size_t calls() const { return m_calls.size(); }

    // `done` hears the exchange's end exactly once, never from in here.
    void start(socketley::http_target target, socketley::http_request req, int timeout_ms, done_fn done)
    {
        const uint64_t key = m_next++;
        call& c = m_calls[key];
        c.peer = std::make_unique<socketley::http_peer>(m_loop, m_fio, m_pool, std::move(target), std::string{},
                                                        m_what);
        c.done = std::move(done);
        c.timeout_ms = timeout_ms;
        c.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        arm(c.deadline);
        m_starting = true;
        c.peer->exchange(std::move(req), [this, key](socketley::http_answer a) { finished(key, std::move(a)); });
        m_starting = false;
    }

    // Every exchange ended without its answer.
    void cancel()
    {
        for (auto& [key, c] : m_calls)
        {
            c.done = nullptr;
            c.peer->stop();
            m_spent.push_back(std::move(c.peer));
        }
        m_calls.clear();
        m_early.clear();
    }

    // Let go by its client: freed now when the ring owes it nothing, and by a later ring's reap otherwise.
    void retire()
    {
        cancel();
        m_retired = true;
        m_pool.retire(m_loop);
        if (m_loop.owner_inflight(this) == 0)
            delete this;
        else
            graveyard().push_back(this);
    }

private:
    struct call
    {
        std::unique_ptr<socketley::http_peer> peer;
        done_fn done;
        int timeout_ms{0};
        std::chrono::steady_clock::time_point deadline{};
    };

    static std::vector<ring*>& graveyard()
    {
        // Never destroyed, so a ring still owed a completion at exit is not freed under the ring.
        static auto* g = new std::vector<ring*>();
        return *g;
    }

    static void reap(event_loop& loop)
    {
        auto& g = graveyard();
        std::erase_if(g, [&](ring* r) {
            if (&r->m_loop != &loop || loop.owner_inflight(r) != 0)
                return false;
            delete r;
            return true;
        });
    }

    void finished(uint64_t key, socketley::http_answer a)
    {
        const auto it = m_calls.find(key);
        if (it == m_calls.end())
            return;
        // The peer is on the stack that called here, so it is freed on a later tick.
        m_spent.push_back(std::move(it->second.peer));
        done_fn done = std::move(it->second.done);
        m_calls.erase(it);
        // An exchange that ended before start() returned is answered on the next tick, after its caller has yielded.
        if (m_starting)
        {
            m_early.emplace_back(std::move(done), std::move(a));
            arm(std::chrono::steady_clock::now());
            return;
        }
        if (done)
            done(std::move(a));
    }

    void arm(std::chrono::steady_clock::time_point at)
    {
        if (m_armed && m_tick_at <= at)
            return;
        const auto now = std::chrono::steady_clock::now();
        // Woken at least once a second while anything is open, for the peers' own stall bound.
        at = std::min(at, now + std::chrono::seconds(1));
        if (!m_fio.after(std::max(at - now, std::chrono::steady_clock::duration::zero()), [this](int64_t) { tick(); }))
            return;
        m_armed = true;
        m_tick_at = at;
    }

    void tick()
    {
        m_armed = false;
        reap(m_loop);
        if (m_retired)
            return;
        // Under no peer's frame here, so the ones that finished can go.
        m_spent.clear();
        const auto now = std::chrono::steady_clock::now();
        auto early = std::move(m_early);
        m_early.clear();
        for (auto& [done, a] : early)
            if (done)
                done(std::move(a));
        // By key, since a peer's tick may end its exchange and the answer run a script that starts another.
        std::vector<uint64_t> keys;
        keys.reserve(m_calls.size());
        for (const auto& [key, c] : m_calls)
            keys.push_back(key);
        for (const uint64_t key : keys)
        {
            const auto it = m_calls.find(key);
            if (it == m_calls.end())
                continue;
            if (now < it->second.deadline)
            {
                it->second.peer->tick(now);
                continue;
            }
            socketley::http_answer a;
            a.failure = "timed out after " + std::to_string(it->second.timeout_ms) + "ms";
            // A stopped peer tells nobody, so the answer is given here.
            it->second.peer->stop();
            m_spent.push_back(std::move(it->second.peer));
            done_fn done = std::move(it->second.done);
            m_calls.erase(it);
            if (done)
                done(std::move(a));
        }
        if (m_retired)
            return;
        for (const auto& [key, c] : m_calls)
            arm(c.deadline);
        if (!m_spent.empty() || !m_early.empty())
            arm(now + std::chrono::milliseconds(m_early.empty() ? 1000 : 0));
    }

    event_loop& m_loop;
    socketley::file_io m_fio;
    // One thread for the names the loop's resolver cannot answer, started at the first such name.
    socketley::hash_pool m_pool{1};
    std::string m_what;
    std::unordered_map<uint64_t, call> m_calls;
    uint64_t m_next{1};
    std::vector<std::unique_ptr<socketley::http_peer>> m_spent;
    std::vector<std::pair<done_fn, socketley::http_answer>> m_early;
    std::chrono::steady_clock::time_point m_tick_at{};
    bool m_armed{false};
    bool m_starting{false};
    bool m_retired{false};
};

lua_http_client::lua_http_client(lua_context& ctx, runtime_instance& owner) : m_ctx(ctx), m_owner(owner)
{
}

lua_http_client::~lua_http_client()
{
    if (m_ring)
        m_ring->retire();
}

void lua_http_client::install(sol::table& sk)
{
    lua_State* L = m_ctx.state().lua_state();
    sk.push();
    lua_pushlightuserdata(L, this);
    lua_pushcclosure(L, &thunk, 1);
    lua_setfield(L, -2, "http");
    lua_pop(L, 1);
}

void lua_http_client::cancel()
{
    if (m_ring)
        m_ring->cancel();
}

namespace
{

// What socketley.http answers, as the blocking call does.
int push_answer(lua_State* th, const socketley::http_answer& a)
{
    lua_createtable(th, 0, 4);
    lua_pushboolean(th, a.status >= 200 && a.status < 300);
    lua_setfield(th, -2, "ok");
    lua_pushinteger(th, a.status);
    lua_setfield(th, -2, "status");
    // No part of an answer that did not come whole.
    const std::string_view body = a.status ? std::string_view(a.body) : std::string_view();
    lua_pushlstring(th, body.data(), body.size());
    lua_setfield(th, -2, "body");
    const std::string& why = a.status ? std::string() : a.failure;
    lua_pushlstring(th, why.data(), why.size());
    lua_setfield(th, -2, "error");
    return 1;
}

}   // namespace

int lua_http_client::thunk(lua_State* L)
{
    auto* client = static_cast<lua_http_client*>(lua_touserdata(L, lua_upvalueindex(1)));
    luaL_checktype(L, 1, LUA_TTABLE);
    return client ? client->call(L) : 0;
}

int lua_http_client::call(lua_State* L)
{
    const mode m = begin(L);
    if (m == mode::wait)
        // Nothing is left on this frame that a longjmp would skip.
        return lua_yield(L, 0);
    if (m == mode::refused)
    {
        socketley::http_answer a;
        a.failure = m_error;
        return push_answer(L, a);
    }
    sol::table result = lua_http_blocking(m_ctx.state(), sol::table(L, 1));
    result.push(L);
    return 1;
}


lua_http_client::mode lua_http_client::begin(lua_State* L)
{
    event_loop* loop = m_owner.get_event_loop();
    // A stopped runtime's on_stop, and every callback that cannot wait, make the call the blocking way.
    if (!loop || m_ctx.registrations_severed())
        return mode::blocking;
    const lua_suspender::id_t id = m_ctx.suspender().enrol_await(L);
    if (id == 0)
        return mode::blocking;
    // Anything the blocking call would refuse is left to it, which refuses before it makes a connection.
    lua_http_options o;
    socketley::http_target target;
    std::string why;
    if (!read_lua_http_options(sol::table(L, 1), o, why) || !socketley::parse_http_url(o.url, target, why))
        return mode::blocking;
#ifdef SOCKETLEY_NO_HTTPS
    if (target.tls)
        return mode::blocking;
#endif
    bool fields_ok = http_field_name_ok(o.method) &&
                     target.path.find_first_of(std::string_view(" \r\n\0", 4)) == std::string::npos;
    for (const auto& [k, v] : o.headers)
        fields_ok = fields_ok && http_field_name_ok(k) && http_field_value_ok(v);
    if (!fields_ok)
        return mode::blocking;

    socketley::http_request req;
    req.head = o.method + " " + target.path + " HTTP/1.1\r\nHost: " + target.authority() + "\r\n";
    if (!o.body.empty())
        req.head += "Content-Length: " + std::to_string(o.body.size()) + "\r\n";
    for (const auto& [k, v] : o.headers)
        req.head += k + ": " + v + "\r\n";
    req.head += "Connection: close\r\n\r\n";
    req.body = std::move(o.body);
    req.head_only = o.method.size() == 4 && strncasecmp(o.method.c_str(), "HEAD", 4) == 0;
    // The ring's own deadline ends the exchange first; the peer's bounds are only a backstop past it.
    req.answer_secs = o.timeout_ms / 1000 + 2;
    req.max_answer = 8u * 1024u * 1024u;

    if (!m_ring)
        m_ring = new ring(*loop, "lua " + std::string(m_owner.get_name()) + ": socketley.http");
    if (m_ring->calls() >= ring::max_calls)
    {
        m_error = "too many socketley.http calls are already waiting on this runtime";
        return mode::refused;
    }
    // The connection whose handler waits is kept open for the answer, as for socketley.db's.
    uint64_t held = 0;
    m_owner.hold_answering_connection(held);
    m_ctx.suspender().note_await(id, 0, held);
    const uint32_t seq = m_ctx.suspender().await_seq(id);
    lua_suspender* sus = &m_ctx.suspender();
    m_ring->start(std::move(target), std::move(req), o.timeout_ms, [sus, id, seq](socketley::http_answer a) {
        sus->settle_with(id, [&](lua_State* th) { return push_answer(th, a); }, seq);
    });
    return mode::wait;
}

#endif // SOCKETLEY_NO_LUA
