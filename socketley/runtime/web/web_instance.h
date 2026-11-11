#pragma once
// The web runtime: a site of files, served over HTTP to browsers and nothing else -- GET and HEAD, the files under its
// --root as they lie, the addresses a static site generator writes, and the caching that lets a new build show at once.
//
// It speaks plain HTTP on its port and is reached through the entrance proxy, which terminates TLS and HTTP/2 for it as
// for every other name. It takes no WebSocket: a page that talks to its server is a server's --http. With --lua-pages a
// .lua file under --root answers its own address, and with --backend fastcgi://... a .php file, run by php-fpm.
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "../../shared/runtime/runtime_instance.h"
#include "shared/runtime/retired_runs.h"

namespace socketley::web
{
class web_run;
}

// A request answered by the program that embeds this runtime; `answer` is called once, now or on a later turn.
struct web_handler_request
{
    std::string method, path, query, headers, body;
};
using web_answer = std::function<void(int status, std::vector<std::pair<std::string, std::string>> fields, std::string body)>;
using web_handler = std::function<void(const web_handler_request&, web_answer)>;

class web_instance : public runtime_instance
{
public:
    // The path and what lies under it go to `h` before any file does.
    void add_handler(std::string prefix, web_handler h) { m_handlers.emplace_back(std::move(prefix), std::move(h)); }
    const web_handler* handler_for(std::string_view path) const
    {
        for (const auto& [prefix, h] : m_handlers)
            if (path == prefix || prefix == "/" || (path.starts_with(prefix) && path[prefix.size()] == '/'))
                return &h;
        return nullptr;
    }
    bool has_handlers() const { return !m_handlers.empty(); }

    explicit web_instance(std::string_view name);
    ~web_instance() override;

    // The directory whose files are the site (--root), absolute.
    void set_root(std::string_view p) { m_root = std::string(p); }
    std::string_view get_root() const { return m_root; }
    // The file a directory's address is answered with (--index), index.html unless given.
    void set_index(std::string_view n) { m_index = std::string(n); }
    std::string_view get_index() const { return m_index; }
    // The page an address nothing answers is given instead, with 200, as a single-page app routes (--fallback).
    void set_fallback(std::string_view p) { m_fallback = std::string(p); }
    std::string_view get_fallback() const { return m_fallback; }
    // The FastCGI server a .php file under --root is run by (--backend fastcgi://unix:/path or fastcgi://a.b.c.d:port).
    void set_backend(std::string_view b) { m_backend = std::string(b); }
    std::string_view get_backend() const { return m_backend; }
    // --root as that server sees it, when it is another path (a container), as a FastCGI proxy's --fastcgi-root.
    void set_fastcgi_root(std::string_view d) { m_fastcgi_root = std::string(d); }
    std::string_view get_fastcgi_root() const { return m_fastcgi_root; }
    // A .lua file under --root is run as a page rather than served (--lua-pages).
    void set_lua_pages(bool on) { m_lua_pages = on; }
    bool get_lua_pages() const { return m_lua_pages; }

    std::string config_refusal() const override;
    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;
    void on_loop_turn() override;
    bool runs_drained() override;
    size_t get_connection_count() const override;
    std::string stats_lines() const override;
    void listen_addresses(std::vector<std::string>& out) const override;
    uint16_t effective_port() const override;

private:
    std::vector<std::pair<std::string, web_handler>> m_handlers;
    std::string m_root;
    std::string m_index{"index.html"};
    std::string m_fallback;
    bool m_lua_pages{false};
    std::string m_backend;
    std::string m_fastcgi_root;

    std::unique_ptr<socketley::web::web_run> m_run;
    // Runs stopped but still owed completions by the ring.
    socketley::retired_runs<socketley::web::web_run> m_graveyard;
};
