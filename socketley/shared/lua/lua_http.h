#pragma once
// socketley.http as a callback that can wait calls it: the exchange runs on the loop and the callback stops until it
// ends, while the runtime goes on serving; anywhere else the call is still the blocking one.
#ifndef SOCKETLEY_NO_LUA

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <sol/sol.hpp>

class lua_context;
class runtime_instance;

// What a script asked socketley.http for, read and checked once for both ways of making the call.
struct lua_http_options
{
    std::string url;
    std::string method{"GET"};
    std::string body;
    std::vector<std::pair<std::string, std::string>> headers;
    int timeout_ms{5000};
};

// False with `why` for a key that is present and of the wrong type or out of range.
bool read_lua_http_options(const sol::table& opts, lua_http_options& out, std::string& why);

class lua_http_client
{
public:
    lua_http_client(lua_context& ctx, runtime_instance& owner);
    ~lua_http_client();

    lua_http_client(const lua_http_client&)            = delete;
    lua_http_client& operator=(const lua_http_client&) = delete;

    // Sets socketley.http, a C function because sol has no form for one that yields.
    void install(sol::table& sk);

    // Ends every exchange without answering it: the runtime is stopping and must execute no more script.
    void cancel();

private:
    class ring;
    enum class mode { wait, blocking, refused };

    static int thunk(lua_State* L);
    int call(lua_State* L);
    // Starts the exchange the coroutine on `L` waits for, or says it is made the blocking way or refused.
    mode begin(lua_State* L);

    lua_context&          m_ctx;
    runtime_instance&     m_owner;
    // The loop's side, made at the first call that waits and outliving this object while the ring owes it anything.
    ring*                 m_ring{nullptr};
    // What begin() says when it refuses, a member so that the frame that yields holds nothing with a destructor.
    std::string           m_error;
};

#endif // SOCKETLEY_NO_LUA
