#ifndef SOCKETLEY_NO_LUA

#include "lua_mail_api.h"

#include "lua_context.h"
#include "../../runtime/mail/mail_command.h"

namespace
{

constexpr const char* send_usage =
    "usage: socketley.mail.send(runtime, {to=, cc=, bcc=, from=, reply_to=, subject=, text=, html=, headers={}, "
    "attachments={{name=, type=, data=}}, raw=} [, callback])";

bool field_string(lua_State* L, int t, const char* name, std::string& out)
{
    lua_getfield(L, t, name);
    const int type = lua_type(L, -1);
    bool ok = type == LUA_TNIL;
    if (type == LUA_TSTRING || type == LUA_TNUMBER)
    {
        size_t n = 0;
        const char* p = lua_tolstring(L, -1, &n);
        out.assign(p, n);
        ok = true;
    }
    lua_pop(L, 1);
    return ok;
}

// The string on top of the stack whole, false for one with a NUL, which would cut an address short unseen.
bool whole_string(lua_State* L, std::vector<std::string>& out)
{
    size_t n = 0;
    const char* p = lua_tolstring(L, -1, &n);
    if (std::string_view(p, n).find('\0') != std::string_view::npos)
        return false;
    out.emplace_back(p, n);
    return true;
}

// A string, or a list of strings.
bool field_list(lua_State* L, int t, const char* name, std::vector<std::string>& out)
{
    lua_getfield(L, t, name);
    bool ok = true;
    if (lua_type(L, -1) == LUA_TSTRING)
        ok = whole_string(L, out);
    else if (lua_type(L, -1) == LUA_TTABLE)
    {
        const int n = static_cast<int>(lua_objlen(L, -1));
        for (int i = 1; i <= n && ok; ++i)
        {
            lua_rawgeti(L, -1, i);
            ok = lua_type(L, -1) == LUA_TSTRING && whole_string(L, out);
            lua_pop(L, 1);
        }
    }
    else
        ok = lua_type(L, -1) == LUA_TNIL;
    lua_pop(L, 1);
    return ok;
}

}   // namespace

lua_mail_client::lua_mail_client(lua_context& ctx, runtime_instance& owner)
    : lua_request_client(ctx, owner, "socketley.mail", "mail")
{
}

void lua_mail_client::install(sol::state& lua, sol::table& sk)
{
    static constexpr function fns[] = {{"send", 0}};
    install_table(lua, sk, "mail", fns);
}

lua_mail_client::mode lua_mail_client::begin(lua_State* L, int)
{
    const int nargs = lua_gettop(L);
    const bool has_cb = nargs >= 1 && lua_type(L, nargs) == LUA_TFUNCTION;
    const int logical = has_cb ? nargs - 1 : nargs;
    if (logical != 2 || lua_type(L, 1) != LUA_TSTRING || lua_type(L, 2) != LUA_TTABLE)
        return refuse(send_usage);
    const std::string target = lua_tostring(L, 1);
    if (target.empty())
        return refuse(send_usage);
    socketley::mail::compose c;
    if (!field_list(L, 2, "to", c.to) || !field_list(L, 2, "cc", c.cc) || !field_list(L, 2, "bcc", c.bcc) ||
        !field_string(L, 2, "from", c.from) || !field_string(L, 2, "reply_to", c.reply_to) ||
        !field_string(L, 2, "subject", c.subject) || !field_string(L, 2, "text", c.text) ||
        !field_string(L, 2, "html", c.html) || !field_list(L, 2, "headers", c.headers) ||
        !field_string(L, 2, "raw", c.raw))
        return refuse(send_usage);
    lua_getfield(L, 2, "attachments");
    if (lua_type(L, -1) == LUA_TTABLE)
    {
        const int n = static_cast<int>(lua_objlen(L, -1));
        for (int i = 1; i <= n; ++i)
        {
            lua_rawgeti(L, -1, i);
            socketley::mail::attachment a;
            const bool ok = lua_type(L, -1) == LUA_TTABLE && field_string(L, lua_gettop(L), "name", a.name) &&
                            field_string(L, lua_gettop(L), "type", a.type) &&
                            field_string(L, lua_gettop(L), "data", a.data);
            lua_pop(L, 1);
            if (!ok)
            {
                lua_pop(L, 1);
                return refuse(send_usage);
            }
            c.attachments.push_back(std::move(a));
        }
    }
    lua_pop(L, 1);
    if (c.to.empty() && c.cc.empty() && c.bcc.empty())
        return refuse("socketley.mail.send: the message names no recipient, as to=");
    return send(L, 0, target, socketley::mail::command_send(c));
}

int lua_mail_client::push_values(lua_State* L, int, request_status st, std::string_view reply)
{
    if (st != request_status::ok)
    {
        lua_pushnil(L);
        lua_pushstring(L, st == request_status::no_target ? "no runtime of that name answers socketley.mail"
                                                         : request_status_text(st));
        return 2;
    }
    if (reply.starts_with("queued "))
    {
        reply.remove_prefix(7);
        lua_pushlstring(L, reply.data(), reply.size());
        return 1;
    }
    if (reply.starts_with("error: "))
        reply.remove_prefix(7);
    lua_pushnil(L);
    lua_pushlstring(L, reply.data(), reply.size());
    return 2;
}

#endif // SOCKETLEY_NO_LUA
