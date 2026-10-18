#pragma once
// socketley.db: a script reads and writes the documents of a db runtime it names, and goes on serving while it waits.
//
// The call travels on the request channel as socketley.storage's does, and is answered once the change is on the
// database's disk. Inside a callback that can stop it yields and returns the answer; anywhere else the last argument
// is a function called with it. A script is the operator's own code and reaches every collection, as a key does.
#ifndef SOCKETLEY_NO_LUA

#include <cstdint>
#include <string>
#include <unordered_map>

#include <sol/sol.hpp>

#include "../ipc/request_channel.h"

class lua_context;
class runtime_instance;

class lua_db_client : public request_origin
{
public:
    // How many calls of one runtime may be waiting for an answer.
    static constexpr size_t max_pending = 1024;

    enum class verb : uint8_t { get, put, insert, patch, del, query, tx };

    lua_db_client(lua_context& ctx, runtime_instance& owner);
    ~lua_db_client() override;

    lua_db_client(const lua_db_client&)            = delete;
    lua_db_client& operator=(const lua_db_client&) = delete;

    // Adds `db` to the `socketley` table being built.
    void install(sol::state& lua, sol::table& sk);

    // Lets go of everything waiting: the runtime is stopping and must execute no more script.
    void cancel();

    // The body of every function; the number of Lua results, or the yield.
    int call(lua_State* L, verb v);

    void on_request_reply(uint64_t cookie, request_status st, std::string_view reply) override;

private:
    enum class mode { refused, callback, wait };

    struct pending
    {
        uint32_t await{0};
        int      ref{LUA_NOREF};
    };

    mode begin(lua_State* L, verb v);
    int  push_values(lua_State* L, request_status st, std::string_view reply);

    lua_context&      m_ctx;
    runtime_instance& m_owner;
    std::unordered_map<uint64_t, pending> m_pending;
    uint64_t          m_next{1};
    // What begin() says when it refuses, a member so that the frame that yields holds nothing with a destructor.
    std::string       m_error;
};

#endif // SOCKETLEY_NO_LUA
