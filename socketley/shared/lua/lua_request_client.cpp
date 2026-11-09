#ifndef SOCKETLEY_NO_LUA

#include "lua_request_client.h"

#include <iostream>

#include "lua_context.h"
#include "lua_suspend.h"
#include "../runtime/runtime_instance.h"
#include "../runtime/runtime_manager.h"

lua_request_client::lua_request_client(lua_context& ctx, runtime_instance& owner, const char* name, const char* word)
    : m_ctx(ctx), m_owner(owner), m_name(name), m_word(word), m_callback_what(std::string(name) + " callback")
{
}

lua_request_client::~lua_request_client()
{
    cancel();
}

void lua_request_client::install_table(sol::state& lua, sol::table& sk, const char* field,
                                       std::span<const function> fns)
{
    lua_State* L = lua.lua_state();
    sol::table t = lua.create_table();
    t.push();
    for (const function& f : fns)
    {
        lua_pushlightuserdata(L, this);
        lua_pushinteger(L, static_cast<lua_Integer>(f.tag));
        lua_pushcclosure(L, &thunk, 2);
        lua_setfield(L, -2, f.name);
    }
    lua_pop(L, 1);
    sk[field] = t;
}

int lua_request_client::thunk(lua_State* L)
{
    auto* client = static_cast<lua_request_client*>(lua_touserdata(L, lua_upvalueindex(1)));
    const int tag = static_cast<int>(lua_tointeger(L, lua_upvalueindex(2)));
    return client ? client->call(L, tag) : 0;
}

void lua_request_client::cancel()
{
    if (auto* mgr = m_owner.get_runtime_manager())
        mgr->requests().drop_origin(this);
    lua_State* L = m_ctx.state().lua_state();
    for (auto& [cookie, p] : m_pending)
        if (p.ref != LUA_NOREF)
            luaL_unref(L, LUA_REGISTRYINDEX, p.ref);
    m_pending.clear();
}

int lua_request_client::call(lua_State* L, int tag)
{
    const mode m = m_ctx.registrations_severed() ? refuse("this runtime has been stopped, so it makes no more calls")
                                                 : begin(L, tag);
    if (m == mode::refused)
    {
        lua_pushnil(L);
        lua_pushlstring(L, m_error.data(), m_error.size());
        return 2;
    }
    if (m == mode::callback)
    {
        lua_pushboolean(L, 1);
        return 1;
    }
    // Nothing is left on this frame that a longjmp would skip.
    return lua_yield(L, 0);
}

lua_request_client::mode lua_request_client::refuse(std::string why)
{
    m_error = std::move(why);
    return mode::refused;
}

lua_request_client::mode lua_request_client::send(lua_State* L, int tag, std::string_view target, std::string payload)
{
    auto* mgr = m_owner.get_runtime_manager();
    if (!mgr)
        return refuse("this runtime has no runtime manager");
    if (m_pending.size() >= max_pending)
        return refuse(std::string("too many ") + m_word + " calls are already waiting on this runtime");
    const int nargs = lua_gettop(L);
    const bool has_cb = nargs >= 1 && lua_type(L, nargs) == LUA_TFUNCTION;
    pending p;
    p.tag = tag;
    if (has_cb)
    {
        lua_pushvalue(L, nargs);
        p.ref = luaL_ref(L, LUA_REGISTRYINDEX);
    }
    else
    {
        // The handle is made here, when a call has to wait, because most callbacks never do; 0 is one that could
        // not stop.
        p.await = m_ctx.suspender().enrol_await(L);
        if (p.await == 0)
            return refuse(waits_name(tag) + " waits for an answer, so without a callback it may only be called from "
                          "one that can wait (on_message, on_client_message, or a storage runtime's on_request, "
                          "on_put and on_delete); pass a function as the last argument anywhere else");
    }
    const uint64_t cookie = m_next++;
    if (!mgr->requests().post(this, cookie, target, std::move(payload), request_class::client))
    {
        if (p.ref != LUA_NOREF)
            luaL_unref(L, LUA_REGISTRYINDEX, p.ref);
        return refuse("the request channel is full");
    }
    if (!has_cb)
    {
        // The connection whose handler waits is kept open for the answer, as it is for a linked cache's, so a
        // client that has sent its line and shut its writing side still gets the reply.
        uint64_t held = 0;
        m_owner.hold_answering_connection(held);
        m_ctx.suspender().note_await(p.await, 0, held);
        p.seq = m_ctx.suspender().await_seq(p.await);
    }
    m_pending.emplace(cookie, p);
    return has_cb ? mode::callback : mode::wait;
}

void lua_request_client::on_request_reply(uint64_t cookie, request_status st, std::string_view reply)
{
    const auto it = m_pending.find(cookie);
    if (it == m_pending.end())
        return;
    const pending p = it->second;
    m_pending.erase(it);
    if (p.await != 0)
    {
        m_ctx.suspender().settle_with(p.await, [&](lua_State* th) { return push_values(th, p.tag, st, reply); }, p.seq);
        return;
    }
    lua_State* L = m_ctx.state().lua_state();
    lua_deadline::scope guard(L, m_callback_what.c_str(), m_ctx.callback_timeout_ms(), m_ctx.owner_name().c_str());
    lua_rawgeti(L, LUA_REGISTRYINDEX, p.ref);
    luaL_unref(L, LUA_REGISTRYINDEX, p.ref);
    const int n = push_values(L, p.tag, st, reply);
    if (lua_pcall(L, n, 0, 0) != 0)
    {
        const char* msg = lua_tostring(L, -1);
        std::cerr << lua_diag::tag(m_ctx.owner_name()) << " a " << m_name << " callback raised: "
                  << (msg ? msg : "(no message)") << std::endl;
        lua_pop(L, 1);
    }
}

#endif // SOCKETLEY_NO_LUA
