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

#include "../ipc/request_channel.h"
#include "../storage/storage_rpc.h"

class lua_context;
class runtime_instance;

namespace storage_rpc = socketley::storage_rpc;

class lua_storage_client : public request_origin
{
public:
    // How many calls of one runtime may be waiting for an answer.
    static constexpr size_t max_pending = 1024;

    lua_storage_client(lua_context& ctx, runtime_instance& owner);
    ~lua_storage_client() override;

    lua_storage_client(const lua_storage_client&)            = delete;
    lua_storage_client& operator=(const lua_storage_client&) = delete;

    // Adds `storage` to the `socketley` table being built.
    void install(sol::state& lua, sol::table& sk);

    // Lets go of everything waiting: the runtime this belongs to is stopping
    // and must execute no more script.  A later call works again.
    void cancel();

    // The body of the five functions; what it answers is the number of Lua
    // results, or the yield.
    int call(lua_State* L, storage_rpc::op kind);

    void on_request_reply(uint64_t cookie, request_status st, std::string_view reply) override;

private:
    enum class mode { refused, callback, wait };

    struct pending
    {
        storage_rpc::op         kind{storage_rpc::op::get};
        uint32_t                await{0};
        // The callback, as a registry reference on the state and not on the
        // coroutine the call was made from, which is pooled and reused once the
        // caller has finished.
        int                     ref{LUA_NOREF};
    };

    mode begin(lua_State* L, storage_rpc::op kind);
    void drop_refs();
    int  push_values(lua_State* L, storage_rpc::op kind, request_status st,
                     const storage_rpc::reply* r);

    lua_context&      m_ctx;
    runtime_instance& m_owner;
    std::unordered_map<uint64_t, pending> m_pending;
    uint64_t          m_next{1};
    // What begin() says when it refuses, a member so that the frame that yields
    // holds nothing with a destructor.
    std::string       m_error;
};

#endif // SOCKETLEY_NO_LUA
