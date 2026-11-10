#pragma once
// socketley.password_hash(password) and socketley.password_verify(hash, password): scrypt as the idp and storage
// runtimes keep a password, made on a thread of its own while a callback that can wait waits for it, since one hash
// holds a core for tens of milliseconds; anywhere else it is made on the spot.
#ifndef SOCKETLEY_NO_LUA

#include <sol/sol.hpp>

#include <string>

class lua_context;
class runtime_instance;

class lua_password_client
{
public:
    lua_password_client(lua_context& ctx, runtime_instance& owner);
    ~lua_password_client();

    lua_password_client(const lua_password_client&)            = delete;
    lua_password_client& operator=(const lua_password_client&) = delete;

    // Sets socketley.password_hash and socketley.password_verify.
    void install(sol::table& sk);

    // Lets every hash under way go unanswered: the runtime is stopping and must execute no more script.
    void cancel();

private:
    class lane;

    static int hash_thunk(lua_State* L);
    static int verify_thunk(lua_State* L);
    int call(lua_State* L, bool verify);

    lua_context&      m_ctx;
    runtime_instance& m_owner;
    // The loop's side, made at the first call that waits and outliving this object while the ring owes it anything.
    lane*             m_lane{nullptr};
};

#endif // SOCKETLEY_NO_LUA
