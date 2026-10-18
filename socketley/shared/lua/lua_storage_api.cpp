#ifndef SOCKETLEY_NO_LUA

#include "lua_storage_api.h"

#include <iostream>

#include "lua_context.h"
#include "lua_suspend.h"
#include "../runtime/runtime_instance.h"
#include "../runtime/runtime_manager.h"

using storage_rpc::op;

namespace
{

// The shapes a script may pass, written where the error message can name them.
const char* usage(op kind)
{
    switch (kind)
    {
        case op::put:
            return "socketley.storage.put(runtime, bucket, key, data [, {content_type=, metadata={}}] [, callback])";
        case op::get:
            return "socketley.storage.get(runtime, bucket, key [, callback])";
        case op::head:
            return "socketley.storage.head(runtime, bucket, key [, callback])";
        case op::del:
            return "socketley.storage.delete(runtime, bucket, key [, callback])";
        case op::list:
            return "socketley.storage.list(runtime, bucket [, prefix] [, {delimiter=, max_keys=, start_after=}] [, callback])";
        case op::users:
            break;   // the identity provider's, which no script is given
    }
    return "";
}

bool string_at(lua_State* L, int idx, std::string& out)
{
    if (lua_type(L, idx) != LUA_TSTRING)
        return false;
    size_t n = 0;
    const char* p = lua_tolstring(L, idx, &n);
    out.assign(p, n);
    return true;
}

// A value a script may write for a string: a string, or a number, which is
// spelled the way Lua spells it.
bool text_at(lua_State* L, int idx, std::string& out)
{
    const int t = lua_type(L, idx);
    if (t != LUA_TSTRING && t != LUA_TNUMBER)
        return false;
    size_t n = 0;
    const char* p = lua_tolstring(L, idx, &n);
    out.assign(p, n);
    return true;
}

std::string lower(std::string s)
{
    for (char& c : s)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    return s;
}

// The put's options table.  Unknown keys are refused, because a misspelt
// `content_type` that stores the object as binary is a defect nobody sees.
bool parse_put_options(lua_State* L, int idx, storage_rpc::request& r, std::string& err)
{
    lua_pushnil(L);
    while (lua_next(L, idx) != 0)
    {
        std::string key;
        if (lua_type(L, -2) != LUA_TSTRING)
        {
            err = "the options table has a key that is not a string";
            lua_pop(L, 2);
            return false;
        }
        size_t kn = 0;
        const char* kp = lua_tolstring(L, -2, &kn);
        key.assign(kp, kn);

        if (key == "content_type")
        {
            if (!string_at(L, lua_gettop(L), r.content_type))
            {
                err = "content_type must be a string";
                lua_pop(L, 2);
                return false;
            }
        }
        else if (key == "metadata")
        {
            if (lua_type(L, -1) != LUA_TTABLE)
            {
                err = "metadata must be a table of names and values";
                lua_pop(L, 2);
                return false;
            }
            const int inner = lua_gettop(L);
            lua_pushnil(L);
            while (lua_next(L, inner) != 0)
            {
                std::string name, value;
                if (lua_type(L, -2) != LUA_TSTRING ||
                    !text_at(L, lua_gettop(L), value))
                {
                    err = "metadata takes string names and string or number values";
                    lua_pop(L, 4);
                    return false;
                }
                size_t nn = 0;
                const char* np = lua_tolstring(L, -2, &nn);
                name.assign(np, nn);
                r.metadata.emplace_back(lower(std::move(name)), std::move(value));
                lua_pop(L, 1);
            }
        }
        else
        {
            err = "unknown option '" + key + "' (content_type and metadata are the ones a put takes)";
            lua_pop(L, 2);
            return false;
        }
        lua_pop(L, 1);
    }
    return true;
}

bool parse_list_options(lua_State* L, int idx, storage_rpc::request& r, std::string& err)
{
    lua_pushnil(L);
    while (lua_next(L, idx) != 0)
    {
        if (lua_type(L, -2) != LUA_TSTRING)
        {
            err = "the options table has a key that is not a string";
            lua_pop(L, 2);
            return false;
        }
        size_t kn = 0;
        const char* kp = lua_tolstring(L, -2, &kn);
        const std::string key(kp, kn);
        if (key == "delimiter")
        {
            if (!string_at(L, lua_gettop(L), r.delimiter))
            {
                err = "delimiter must be a string";
                lua_pop(L, 2);
                return false;
            }
        }
        else if (key == "start_after")
        {
            if (!string_at(L, lua_gettop(L), r.start_after))
            {
                err = "start_after must be a string";
                lua_pop(L, 2);
                return false;
            }
        }
        else if (key == "max_keys")
        {
            const lua_Number n = lua_tonumber(L, -1);
            if (lua_type(L, -1) != LUA_TNUMBER || n < 1 || n > storage_rpc::max_list ||
                n != static_cast<lua_Number>(static_cast<uint32_t>(n)))
            {
                err = "max_keys must be a whole number from 1 to " + std::to_string(storage_rpc::max_list);
                lua_pop(L, 2);
                return false;
            }
            r.max_keys = static_cast<uint32_t>(n);
        }
        else
        {
            err = "unknown option '" + key + "' (delimiter, max_keys and start_after are the ones a list takes)";
            lua_pop(L, 2);
            return false;
        }
        lua_pop(L, 1);
    }
    return true;
}

void set_string(lua_State* L, const char* field, const std::string& v)
{
    lua_pushlstring(L, v.data(), v.size());
    lua_setfield(L, -2, field);
}

void set_number(lua_State* L, const char* field, double v)
{
    lua_pushnumber(L, v);
    lua_setfield(L, -2, field);
}

void push_info(lua_State* L, const storage_rpc::object_info& i, bool with_key, bool with_metadata)
{
    lua_createtable(L, 0, 6);
    if (with_key)
        set_string(L, "key", i.key);
    set_number(L, "size", static_cast<double>(i.size));
    set_string(L, "etag", i.etag);
    set_string(L, "content_type", i.content_type);
    set_number(L, "mtime_ms", static_cast<double>(i.mtime_ms));
    if (with_metadata)
    {
        lua_createtable(L, 0, static_cast<int>(i.metadata.size()));
        for (const auto& [k, v] : i.metadata)
        {
            lua_pushlstring(L, k.data(), k.size());
            lua_pushlstring(L, v.data(), v.size());
            lua_rawset(L, -3);
        }
        lua_setfield(L, -2, "metadata");
    }
}

// The C function every one of the five is.  It is a lua_CFunction and not a sol
// binding because sol has no form for a function that yields, and it returns
// through call() so that the frame that yields owns nothing.
int storage_thunk(lua_State* L)
{
    auto* client = static_cast<lua_storage_client*>(lua_touserdata(L, lua_upvalueindex(1)));
    const int kind = static_cast<int>(lua_tointeger(L, lua_upvalueindex(2)));
    if (!client)
        return 0;
    return client->call(L, static_cast<op>(kind));
}

} // namespace

lua_storage_client::lua_storage_client(lua_context& ctx, runtime_instance& owner)
    : m_ctx(ctx), m_owner(owner)
{
}

lua_storage_client::~lua_storage_client()
{
    cancel();
}

void lua_storage_client::install(sol::state& lua, sol::table& sk)
{
    lua_State* L = lua.lua_state();
    sol::table st = lua.create_table();
    st.push();
    static constexpr std::pair<const char*, op> fns[] = {
        {"put", op::put}, {"get", op::get}, {"head", op::head}, {"delete", op::del}, {"list", op::list},
    };
    for (const auto& [name, kind] : fns)
    {
        lua_pushlightuserdata(L, this);
        lua_pushinteger(L, static_cast<lua_Integer>(kind));
        lua_pushcclosure(L, &storage_thunk, 2);
        lua_setfield(L, -2, name);
    }
    lua_pop(L, 1);
    sk["storage"] = st;
}

void lua_storage_client::cancel()
{
    if (auto* mgr = m_owner.get_runtime_manager())
        mgr->requests().drop_origin(this);
    drop_refs();
    m_pending.clear();
}

void lua_storage_client::drop_refs()
{
    lua_State* L = m_ctx.state().lua_state();
    for (auto& [cookie, p] : m_pending)
        if (p.ref != LUA_NOREF)
        {
            luaL_unref(L, LUA_REGISTRYINDEX, p.ref);
            p.ref = LUA_NOREF;
        }
}

int lua_storage_client::call(lua_State* L, op kind)
{
    const mode m = begin(L, kind);
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

lua_storage_client::mode lua_storage_client::begin(lua_State* L, op kind)
{
    const auto refuse = [&](std::string msg)
    {
        m_error = std::move(msg);
        return mode::refused;
    };

    if (m_ctx.registrations_severed())
        return refuse("this runtime has been stopped, so it makes no more calls");

    const int nargs = lua_gettop(L);
    const bool has_cb = nargs >= 1 && lua_type(L, nargs) == LUA_TFUNCTION;
    const int logical = has_cb ? nargs - 1 : nargs;

    storage_rpc::request rq;
    rq.kind = kind;
    std::string target;

    const auto shape = [&] { return refuse(std::string("usage: ") + usage(kind)); };

    if (logical < 2 || !string_at(L, 1, target) || target.empty() ||
        !string_at(L, 2, rq.bucket) || rq.bucket.empty())
        return shape();

    switch (kind)
    {
        case op::put:
        {
            if (logical < 4 || logical > 5 || !string_at(L, 3, rq.key) || rq.key.empty() ||
                !string_at(L, 4, rq.data))
                return shape();
            if (rq.data.size() > storage_rpc::max_value)
                return refuse("the object is " + std::to_string(rq.data.size()) + " bytes, and a script may move at most " +
                              std::to_string(storage_rpc::max_value) + " -- put larger ones over the S3 port");
            if (logical == 5)
            {
                if (lua_type(L, 5) != LUA_TTABLE)
                    return shape();
                std::string err;
                if (!parse_put_options(L, 5, rq, err))
                    return refuse(err);
            }
            break;
        }
        case op::get:
        case op::head:
        case op::del:
            if (logical != 3 || !string_at(L, 3, rq.key) || rq.key.empty())
                return shape();
            break;
        case op::list:
        {
            if (logical > 4)
                return shape();
            int opts = 0;
            for (int i = 3; i <= logical; ++i)
            {
                const int t = lua_type(L, i);
                if (t == LUA_TSTRING && i == 3)
                    string_at(L, i, rq.prefix);
                else if (t == LUA_TNIL && i == 3)
                    continue;
                else if (t == LUA_TTABLE && opts == 0 && i == logical)
                    opts = i;
                else
                    return shape();
            }
            if (opts)
            {
                std::string err;
                if (!parse_list_options(L, opts, rq, err))
                    return refuse(err);
            }
            break;
        }
        case op::users:
            return shape();   // the identity provider's, which no script is given
    }

    auto* mgr = m_owner.get_runtime_manager();
    if (!mgr)
        return refuse("this runtime has no runtime manager");
    if (m_pending.size() >= max_pending)
        return refuse("too many storage calls are already waiting on this runtime");

    pending p;
    p.kind = kind;
    if (has_cb)
    {
        lua_pushvalue(L, nargs);
        p.ref = luaL_ref(L, LUA_REGISTRYINDEX);
    }
    else
    {
        // The handle is made here, when a call has to wait, because most
        // callbacks never do; 0 is a callback that could not stop.
        auto& sus = m_ctx.suspender();
        p.await = sus.enrol_await(L);
        if (p.await == 0)
            return refuse(std::string(storage_rpc::op_name(kind)) + " waits for an answer, so without a "
                          "callback it may only be called from one that can wait (on_message, "
                          "on_client_message, or a storage runtime's on_request, on_put and on_delete); "
                          "pass a function as the last argument anywhere else");
    }

    const uint64_t cookie = m_next++;
    if (!mgr->requests().post(this, cookie, target, storage_rpc::encode(rq), request_class::client))
    {
        if (p.ref != LUA_NOREF)
            luaL_unref(L, LUA_REGISTRYINDEX, p.ref);
        return refuse("the request channel is full");
    }

    if (!has_cb)
    {
        // The connection whose handler is waiting is kept open for the answer, as
        // it is for a linked cache's, so a client that has sent its line and shut
        // its writing side still gets the reply.
        uint64_t held = 0;
        m_owner.hold_answering_connection(held);
        m_ctx.suspender().note_await(p.await, 0, held);
    }
    m_pending.emplace(cookie, std::move(p));
    return has_cb ? mode::callback : mode::wait;
}

int lua_storage_client::push_values(lua_State* L, op kind, request_status st,
                                    const storage_rpc::reply* r)
{
    if (st != request_status::ok || !r)
    {
        lua_pushnil(L);
        const char* why = st != request_status::ok ? request_status_text(st) : "the reply could not be read";
        lua_pushstring(L, why);
        return 2;
    }
    if (!r->ok)
    {
        lua_pushnil(L);
        lua_pushlstring(L, r->code.data(), r->code.size());
        lua_pushlstring(L, r->message.data(), r->message.size());
        return 3;
    }
    switch (kind)
    {
        case op::put:
        case op::head:
            push_info(L, r->info, false, true);
            return 1;
        case op::get:
            lua_pushlstring(L, r->data.data(), r->data.size());
            push_info(L, r->info, false, true);
            return 2;
        case op::del:
            lua_pushboolean(L, 1);
            return 1;
        case op::users:
            lua_pushnil(L);   // the identity provider's, which no script is given
            return 1;
        case op::list:
        {
            lua_createtable(L, 0, 4);
            lua_createtable(L, static_cast<int>(r->objects.size()), 0);
            int i = 1;
            for (const auto& o : r->objects)
            {
                push_info(L, o, true, false);
                lua_rawseti(L, -2, i++);
            }
            lua_setfield(L, -2, "objects");
            lua_createtable(L, static_cast<int>(r->prefixes.size()), 0);
            i = 1;
            for (const auto& p : r->prefixes)
            {
                lua_pushlstring(L, p.data(), p.size());
                lua_rawseti(L, -2, i++);
            }
            lua_setfield(L, -2, "prefixes");
            lua_pushboolean(L, r->truncated ? 1 : 0);
            lua_setfield(L, -2, "truncated");
            if (r->truncated)
                set_string(L, "next", r->next);
            return 1;
        }
    }
    return 0;
}

void lua_storage_client::on_request_reply(uint64_t cookie, request_status st, std::string_view reply)
{
    const auto it = m_pending.find(cookie);
    if (it == m_pending.end())
        return;
    pending p = std::move(it->second);
    m_pending.erase(it);

    storage_rpc::reply r;
    bool decoded = false;
    if (st == request_status::ok)
        decoded = storage_rpc::decode(reply, p.kind, r);

    if (p.await != 0)
    {
        m_ctx.suspender().settle_with(p.await, [&](lua_State* th)
        {
            return push_values(th, p.kind, st, decoded ? &r : nullptr);
        });
        return;
    }

    lua_State* L = m_ctx.state().lua_state();
    lua_deadline::scope guard("socketley.storage callback", m_ctx.callback_timeout_ms(),
                              m_ctx.owner_name().c_str());
    lua_rawgeti(L, LUA_REGISTRYINDEX, p.ref);
    luaL_unref(L, LUA_REGISTRYINDEX, p.ref);
    const int n = push_values(L, p.kind, st, decoded ? &r : nullptr);
    if (lua_pcall(L, n, 0, 0) != 0)
    {
        const char* msg = lua_tostring(L, -1);
        std::cerr << lua_diag::tag(m_ctx.owner_name()) << " a socketley.storage callback raised: "
                  << (msg ? msg : "(no message)") << std::endl;
        lua_pop(L, 1);
    }
}

#endif // SOCKETLEY_NO_LUA
