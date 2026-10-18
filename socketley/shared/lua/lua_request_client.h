#pragma once
// A table of socketley functions that post to another runtime on the request channel and answer the script either
// by yielding until the reply comes or through a callback passed last, which socketley.db and socketley.storage are.
#ifndef SOCKETLEY_NO_LUA

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

#include <sol/sol.hpp>

#include "../ipc/request_channel.h"

class lua_context;
class runtime_instance;

class lua_request_client : public request_origin
{
public:
    // How many calls of one runtime may be waiting for an answer.
    static constexpr size_t max_pending = 1024;

    lua_request_client(const lua_request_client&)            = delete;
    lua_request_client& operator=(const lua_request_client&) = delete;

    // Lets go of everything waiting: the runtime is stopping and must execute no more script; a later call works
    // again.
    void cancel();

    void on_request_reply(uint64_t cookie, request_status st, std::string_view reply) final;

protected:
    enum class mode { refused, callback, wait };

    struct function
    {
        const char* name;
        int         tag;
    };

    // `name` is what scripts call it, "socketley.db", and `word` what its refusals call one call, "db".
    lua_request_client(lua_context& ctx, runtime_instance& owner, const char* name, const char* word);
    ~lua_request_client() override;

    // Sets socketley.<field> to a table of `fns`, each a C function that yields, which sol has no form for.
    void install_table(sol::state& lua, sol::table& sk, const char* field, std::span<const function> fns);

    // Reads a call's arguments and ends in send() or refuse().
    virtual mode begin(lua_State* L, int tag) = 0;
    // Pushes what the reply answers the script with, and says how many values.
    virtual int push_values(lua_State* L, int tag, request_status st, std::string_view reply) = 0;
    // What the refusal to wait outside a callback that can names, "socketley.db" or a storage verb.
    virtual std::string waits_name(int tag) const = 0;

    mode refuse(std::string why);
    // Posts `payload` to `target` and keeps what its reply goes to: the callback passed last, or the coroutine that
    // waits.
    mode send(lua_State* L, int tag, std::string_view target, std::string payload);

    lua_context&      m_ctx;
    runtime_instance& m_owner;

private:
    struct pending
    {
        int      tag{0};
        uint32_t await{0};
        // A registry reference on the state and not on the coroutine the call came from, which is pooled and reused
        // once the caller has finished.
        int      ref{LUA_NOREF};
    };

    static int thunk(lua_State* L);
    int call(lua_State* L, int tag);

    const char*                           m_name;
    const char*                           m_word;
    std::string                           m_callback_what;
    std::unordered_map<uint64_t, pending> m_pending;
    uint64_t                              m_next{1};
    // What begin() says when it refuses, a member so that the frame that yields holds nothing with a destructor.
    std::string                           m_error;
};

#endif // SOCKETLEY_NO_LUA
