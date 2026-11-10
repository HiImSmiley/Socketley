#pragma once
// Lua pages: a .lua file under a site's root answering its own request, as a .php file does under PHP, and the
// reply a Lua HTTP handler's returned table asks for, which a page and a server's on_http_request share.
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../util/transparent_string.h"

class lua_context;

namespace socketley::lua_pages
{

// The version of each page compiled into one Lua state, whose compiled factories live in that state's registry so
// a state that is replaced takes them with it.
struct cache
{
    struct version
    {
        dev_t   dev{};
        ino_t   ino{};
        off_t   size{};
        int64_t sec{};
        long    nsec{};
        // The site's generation it was last found current at.
        uint64_t seen{0};
    };
    const lua_context* ctx{nullptr};
    std::unordered_map<std::string, version, string_hash, std::equal_to<>> compiled;
    // And of each template render() compiled, kept in the registry beside the pages.
    std::unordered_map<std::string, version, string_hash, std::equal_to<>> templates;
    // The root include() reads beneath, its owner's own descriptor, so a release swapped in is the one a page that
    // waited reads after it.
    const int* root{nullptr};
    // What its owner says of the files under the root: a number that changes whenever any of them may have, so a
    // file found current at it is current still and is not asked of the disk again; 0 when it cannot say.
    uint64_t site_gen{0};
};

}   // namespace socketley::lua_pages

#ifndef SOCKETLEY_NO_LUA
#include "lua_context.h"

namespace socketley::lua_pages
{

// What a page is handed of its request, as on_http_request's req table has it.
struct request
{
    std::string_view method, path, query, body, version;
    std::vector<std::pair<std::string_view, std::string_view>> headers;
    int client_id{-1};
};

// What it answers with, for the runtime to write: a header given a list of values is a line each.
struct reply
{
    int status{200};
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
};

// The page a site path names, relative to the root: a .lua file, for a path no segment of which starts with '_',
// which are the files pages include and never a request's.
bool page_name(std::string_view site_path, std::string& rel);

// Whether any segment of `site_path` starts with '_', which no request may name.
bool hidden_to_requests(std::string_view site_path);

enum class outcome
{
    not_a_page,   // no regular file at `rel` beneath the root: the caller's static answer
    started,      // `done` has the page's reply, or will: a 500 for one that did not compile or raised
};

// Called once with a page's reply: before run() returns for a page that did not wait, later for one that waited on
// another runtime or on socketley.http, and never for one its runtime stopped under.
using done_fn = std::function<void(reply)>;

// The reply a Lua HTTP handler's returned value asks for into `out`, true when there is one -- a 500 for a table this
// end cannot read included -- and false when the value declines, which only nil does quietly.
bool reply_from_lua(lua_context& ctx, std::string_view owner, std::string_view hook, const sol::object& result,
                    reply& out);

// Runs the page at `rel` beneath `root_fd` for `req` on a coroutine, so it may wait, opened with RESOLVE_BENEATH and
// compiled again only when its file changed.
outcome run(lua_context& ctx, cache& c, int root_fd, const std::string& rel, const request& req,
            std::string_view owner, done_fn done);

}   // namespace socketley::lua_pages
#endif
