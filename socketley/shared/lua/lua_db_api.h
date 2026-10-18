#pragma once
// socketley.db: a script reads and writes the documents of a db runtime it names, and goes on serving while it waits.
//
// The call travels on the request channel as socketley.storage's does, and is answered once the change is on the
// database's disk. Inside a callback that can stop it yields and returns the answer; anywhere else the last argument
// is a function called with it. A script is the operator's own code and reaches every collection, as a key does.
#ifndef SOCKETLEY_NO_LUA

#include <cstdint>
#include <string>

#include "lua_request_client.h"

class lua_db_client : public lua_request_client
{
public:
    enum class verb : uint8_t { get, put, insert, patch, del, query, tx };

    lua_db_client(lua_context& ctx, runtime_instance& owner);

    // Adds `db` to the `socketley` table being built.
    void install(sol::state& lua, sol::table& sk);

private:
    mode        begin(lua_State* L, int tag) override;
    int         push_values(lua_State* L, int tag, request_status st, std::string_view reply) override;
    std::string waits_name(int) const override { return "socketley.db"; }
};

#endif // SOCKETLEY_NO_LUA
