#include "mail_lua.h"

#include <iostream>

#include "mail_compose.h"
#include "mail_instance.h"

#ifndef SOCKETLEY_NO_LUA
#include "../../shared/lua/lua_context.h"
#include "../../shared/lua/lua_suspend.h"
#endif

namespace socketley::mail
{

#ifndef SOCKETLEY_NO_LUA

bool mail_lua::wants_rcpt() const
{
    const lua_context* lua = m_owner.lua();
    return lua && lua->has_on_rcpt();
}

void mail_lua::rcpt(const std::string& to, const std::string& from, const std::string& peer, const std::string& user,
                    bool fallback, std::function<void(account)> done)
{
    lua_context* lua = m_owner.lua();
    if (!lua || !lua->has_on_rcpt())
    {
        done(fallback ? account::yes : account::no);
        return;
    }
    sol::state& L = lua->state();
    sol::table t = L.create_table(0, 5);
    t["to"] = to;
    t["from"] = from;
    t["peer"] = peer;
    t["user"] = user;
    const std::string owner(m_owner.get_name());
    auto& sus = lua->suspender();
    sus.set_next_result([done, fallback, owner](lua_State* th, int n, const char* error) {
        if (error)
        {
            // A script that broke decides nothing: the sender is told to try again, not that the address is wrong.
            std::cerr << lua_diag::tag(owner) << " on_rcpt " << error << " -- answered 451\n";
            done(account::unreachable);
            return;
        }
        if (n >= 1 && lua_type(th, 1) == LUA_TBOOLEAN)
            done(lua_toboolean(th, 1) != 0 ? account::yes : account::no);
        else
            done(fallback ? account::yes : account::no);
    });
    lua_suspender::id_t id = 0;
    sus.start(lua->raw_on_rcpt(), "on_rcpt", lua->callback_timeout_ms(), id, t, fallback);
}

void mail_lua::message(const spool_entry& e)
{
    lua_context* lua = m_owner.lua();
    if (!lua || !lua->has_on_message())
        return;
    sol::state& L = lua->state();
    sol::table t = L.create_table(0, 8);
    t["id"] = e.id;
    t["from"] = e.from;
    sol::table to = L.create_table(static_cast<int>(e.rcpts.size()), 0);
    for (size_t i = 0; i < e.rcpts.size(); ++i)
        to[i + 1] = e.rcpts[i].addr;
    t["to"] = to;
    t["size"] = e.body_len;
    t["peer"] = e.peer;
    t["user"] = e.user;
    // A message small enough to be kept in memory is handed whole, its subject read out of it.
    if (e.body)
    {
        t["message"] = *e.body;
        t["subject"] = header_value(header_block(*e.body), "Subject");
    }
    lua_suspender::id_t id = 0;
    lua->suspender().start(lua->raw_on_message(), "on_message", lua->callback_timeout_ms(), id, t);
}

#else

bool mail_lua::wants_rcpt() const
{
    return false;
}

void mail_lua::rcpt(const std::string&, const std::string&, const std::string&, const std::string&, bool fallback,
                    std::function<void(account)> done)
{
    done(fallback ? account::yes : account::no);
}

void mail_lua::message(const spool_entry&) {}

#endif

}   // namespace socketley::mail
