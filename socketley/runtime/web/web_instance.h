#pragma once
// The web runtime: a site of files, served over HTTP to browsers and nothing else -- GET and HEAD, the files under its
// --root as they lie, the addresses a static site generator writes, and the caching that lets a new build show at once.
//
// It speaks plain HTTP on its port and is reached through the entrance proxy, which terminates TLS and HTTP/2 for it as
// for every other name. It runs no script and takes no WebSocket: a page that talks to its server is a server's --http.
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

class web_instance : public runtime_instance
{
public:
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

    std::string config_refusal() const override;
    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;
    void on_loop_turn() override;
    size_t get_connection_count() const override;
    std::string stats_lines() const override;
    void listen_addresses(std::vector<std::string>& out) const override;
    uint16_t effective_port() const override;

private:
    std::string m_root;
    std::string m_index{"index.html"};
    std::string m_fallback;

    std::unique_ptr<socketley::web::web_run> m_run;
    // Runs stopped but still owed completions by the ring.
    socketley::retired_runs<socketley::web::web_run> m_graveyard;
};
