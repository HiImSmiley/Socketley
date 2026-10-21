#pragma once
// socketley.mail.send(runtime, {to=, subject=, text=, ...} [, callback]): a message written and queued by a mail
// runtime of this daemon, from any runtime that has a script, answered with its queue id once it is on the disk.
#ifndef SOCKETLEY_NO_LUA

#include <cstdint>
#include <string>

#include "lua_request_client.h"

class lua_mail_client : public lua_request_client
{
public:
    lua_mail_client(lua_context& ctx, runtime_instance& owner);

    // Adds `mail` to the `socketley` table being built.
    void install(sol::state& lua, sol::table& sk);

private:
    mode        begin(lua_State* L, int tag) override;
    int         push_values(lua_State* L, int tag, request_status st, std::string_view reply) override;
    std::string waits_name(int) const override { return "socketley.mail"; }
};

#endif // SOCKETLEY_NO_LUA
