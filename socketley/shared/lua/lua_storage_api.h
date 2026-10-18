#pragma once
// socketley.storage: a script asks a storage runtime -- one it names, in this
// daemon or across a peer link -- to put, get, head, delete or list, and goes on
// serving while it waits.
//
// The request travels on the request channel exactly as another runtime's
// command does, addressed by name and carrying storage_rpc's payload, and the
// answer arrives on a later turn.  What the script does with the wait depends
// on where it asked from: inside a callback that can stop (on_message,
// on_client_message and the storage runtime's own hooks) the call yields and
// returns the answer, and anywhere else -- an on_tick, a cache's on_write, a
// proxy's filter -- the last argument is a function that is called with it.
#ifndef SOCKETLEY_NO_LUA

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

#include <sol/sol.hpp>

#include "lua_request_client.h"
#include "../storage/storage_rpc.h"

namespace storage_rpc = socketley::storage_rpc;

// An object's facts as the Lua table socketley.storage answers with and on_put is given, pushed on L.
void push_object_info(lua_State* L, const storage_rpc::object_info& i, bool with_key, bool with_metadata);

class lua_storage_client : public lua_request_client
{
public:
    lua_storage_client(lua_context& ctx, runtime_instance& owner);

    // Adds `storage` to the `socketley` table being built.
    void install(sol::state& lua, sol::table& sk);

private:
    mode        begin(lua_State* L, int tag) override;
    int         push_values(lua_State* L, int tag, request_status st, std::string_view reply) override;
    std::string waits_name(int tag) const override;
};

#endif // SOCKETLEY_NO_LUA
