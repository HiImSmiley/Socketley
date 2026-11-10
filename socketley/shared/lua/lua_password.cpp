#ifndef SOCKETLEY_NO_LUA

#include "lua_password.h"

#include <memory>
#include <vector>

#include "lua_context.h"
#include "lua_suspend.h"
#include "../crypto/password_hash.h"
#include "../loop/event_loop.h"
#include "../loop/file_io.h"
#include "../loop/hash_pool.h"
#include "../runtime/runtime_instance.h"

// The thread the hashes are made on and the loop's end of it, freed only once the ring owes it nothing.
class lua_password_client::lane final : public io_handler
{
public:
    // Hashes of one runtime under way at once, past which a call is made on the spot.
    static constexpr size_t max_jobs = 64;

    explicit lane(event_loop& loop) : m_loop(loop), m_fio(loop, this)
    {
        reap(loop);
        m_pool.name("lua password");
        if (!m_pool.attach(m_fio))
            m_pool.stop();
    }

    ~lane() override { m_loop.deregister_owner(this); }

    void on_cqe(struct io_uring_cqe* cqe) override
    {
        auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
        if (req && socketley::file_io::owns_type(req->type))
            m_fio.on_cqe(cqe);
    }

    // Whether a job given now goes to the thread, so its answer comes on a later turn and never under the call.
    bool takes() const { return m_pool.enabled() && m_jobs < max_jobs && !m_retired; }

    // `work` on the thread, then `done` on the loop unless the lane was cancelled meanwhile.
    void submit(std::function<void()> work, std::function<void()> done)
    {
        ++m_jobs;
        const uint64_t epoch = m_epoch;
        m_pool.submit(0, std::move(work), [this, epoch, done = std::move(done)] {
            --m_jobs;
            if (epoch == m_epoch && !m_retired)
                done();
        });
    }

    void cancel() { ++m_epoch; }

    // Let go by its client: freed now when the ring owes it nothing, and by a later lane's reap otherwise.
    void retire()
    {
        m_retired = true;
        m_pool.retire(m_loop);
        if (m_loop.owner_inflight(this) == 0)
            delete this;
        else
            graveyard().push_back(this);
    }

private:
    static std::vector<lane*>& graveyard()
    {
        // Never destroyed, so a lane still owed a completion at exit is not freed under the ring.
        static auto* g = new std::vector<lane*>();
        return *g;
    }

    static void reap(event_loop& loop)
    {
        std::erase_if(graveyard(), [&](lane* l) {
            if (&l->m_loop != &loop || loop.owner_inflight(l) != 0)
                return false;
            delete l;
            return true;
        });
    }

    event_loop& m_loop;
    socketley::file_io m_fio;
    socketley::hash_pool m_pool{1};
    size_t m_jobs{0};
    uint64_t m_epoch{0};
    bool m_retired{false};
};

lua_password_client::lua_password_client(lua_context& ctx, runtime_instance& owner) : m_ctx(ctx), m_owner(owner)
{
}

lua_password_client::~lua_password_client()
{
    if (m_lane)
        m_lane->retire();
}

void lua_password_client::install(sol::table& sk)
{
    lua_State* L = m_ctx.state().lua_state();
    sk.push();
    lua_pushlightuserdata(L, this);
    lua_pushcclosure(L, &hash_thunk, 1);
    lua_setfield(L, -2, "password_hash");
    lua_pushlightuserdata(L, this);
    lua_pushcclosure(L, &verify_thunk, 1);
    lua_setfield(L, -2, "password_verify");
    lua_pop(L, 1);
}

void lua_password_client::cancel()
{
    if (m_lane)
        m_lane->cancel();
}

int lua_password_client::hash_thunk(lua_State* L)
{
    auto* c = static_cast<lua_password_client*>(lua_touserdata(L, lua_upvalueindex(1)));
    return c ? c->call(L, false) : 0;
}

int lua_password_client::verify_thunk(lua_State* L)
{
    auto* c = static_cast<lua_password_client*>(lua_touserdata(L, lua_upvalueindex(1)));
    return c ? c->call(L, true) : 0;
}

namespace
{

// What either call answers: a hash or nil and why, a boolean for a verify.
int push_result(lua_State* L, bool verify, const std::string& hash, bool matches)
{
    if (verify)
    {
        lua_pushboolean(L, matches);
        return 1;
    }
    if (hash.empty())
    {
        lua_pushnil(L);
        lua_pushliteral(L, "no random bytes could be drawn for a salt");
        return 2;
    }
    lua_pushlstring(L, hash.data(), hash.size());
    return 1;
}

}   // namespace

int lua_password_client::call(lua_State* L, bool verify)
{
    // The arguments are copied before anything can yield, since the frame that waits holds nothing with a destructor.
    std::string first, second;
    {
        size_t n = 0;
        const char* a = luaL_checklstring(L, 1, &n);
        first.assign(a, n);
        if (verify)
        {
            const char* b = luaL_checklstring(L, 2, &n);
            second.assign(b, n);
        }
    }

    event_loop* loop = m_owner.get_event_loop();
    lua_suspender::id_t id = 0;
    if (loop && !m_ctx.registrations_severed())
    {
        if (!m_lane)
            m_lane = new lane(*loop);
        if (m_lane->takes())
            id = m_ctx.suspender().enrol_await(L);
    }
    if (id == 0)
    {
        // A callback that cannot wait, or no thread to wait on: made here, holding the loop for its tens of ms.
        std::string hash;
        bool matches = false;
        if (verify)
            matches = socketley::crypto::password_matches(first, second);
        else
            hash = socketley::crypto::password_hash(first);
        return push_result(L, verify, hash, matches);
    }

    // The connection whose handler waits is kept open for the answer, as for socketley.db's.
    uint64_t held = 0;
    m_owner.hold_answering_connection(held);
    lua_suspender& sus = m_ctx.suspender();
    sus.note_await(id, 0, held);
    const uint32_t seq = sus.await_seq(id);
    auto out = std::make_shared<std::pair<std::string, bool>>();
    lua_suspender* sp = &sus;
    m_lane->submit(
        [out, verify, a = std::move(first), b = std::move(second)] {
            if (verify)
                out->second = socketley::crypto::password_matches(a, b);
            else
                out->first = socketley::crypto::password_hash(a);
        },
        [sp, id, seq, out, verify] {
            sp->settle_with(id, [&](lua_State* th) { return push_result(th, verify, out->first, out->second); }, seq);
        });
    return lua_yield(L, 0);
}

#endif // SOCKETLEY_NO_LUA
