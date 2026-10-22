#ifndef SOCKETLEY_NO_LUA

#include "lua_storage_api.h"

#include "lua_context.h"

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
        case op::put_begin:
        case op::put_more:
        case op::make_bucket:
        case op::get_range:
        case op::abort:
            break;   // the identity provider's and the mail runtime's, which no script is given
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


} // namespace

void push_object_info(lua_State* L, const storage_rpc::object_info& i, bool with_key, bool with_metadata)
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

lua_storage_client::lua_storage_client(lua_context& ctx, runtime_instance& owner)
    : lua_request_client(ctx, owner, "socketley.storage", "storage")
{
}

void lua_storage_client::install(sol::state& lua, sol::table& sk)
{
    static constexpr function fns[] = {
        {"put", int(op::put)}, {"get", int(op::get)}, {"head", int(op::head)}, {"delete", int(op::del)},
        {"list", int(op::list)},
    };
    install_table(lua, sk, "storage", fns);
}

std::string lua_storage_client::waits_name(int tag) const
{
    return storage_rpc::op_name(static_cast<op>(tag));
}

lua_storage_client::mode lua_storage_client::begin(lua_State* L, int tag)
{
    const op kind = static_cast<op>(tag);
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
        case op::put_begin:
        case op::put_more:
        case op::make_bucket:
        case op::get_range:
        case op::abort:
            return shape();   // the identity provider's and the mail runtime's, which no script is given
    }

    return send(L, tag, target, storage_rpc::encode(rq));
}

int lua_storage_client::push_values(lua_State* L, int tag, request_status st, std::string_view reply)
{
    const op kind = static_cast<op>(tag);
    storage_rpc::reply decoded;
    const storage_rpc::reply* r = st == request_status::ok && storage_rpc::decode(reply, kind, decoded) ? &decoded
                                                                                                          : nullptr;
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
            push_object_info(L, r->info, false, true);
            return 1;
        case op::get:
            lua_pushlstring(L, r->data.data(), r->data.size());
            push_object_info(L, r->info, false, true);
            return 2;
        case op::del:
            lua_pushboolean(L, 1);
            return 1;
        case op::users:
            lua_pushnil(L);   // the identity provider's, which no script is given
            return 1;
        case op::put_begin:
        case op::put_more:
        case op::make_bucket:
        case op::get_range:
        case op::abort:
            // The mail runtime's, which no script asks.
            lua_pushnil(L);
            return 1;
        case op::list:
        {
            lua_createtable(L, 0, 4);
            lua_createtable(L, static_cast<int>(r->objects.size()), 0);
            int i = 1;
            for (const auto& o : r->objects)
            {
                push_object_info(L, o, true, false);
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

#endif // SOCKETLEY_NO_LUA
