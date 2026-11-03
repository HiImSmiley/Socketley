#pragma once
// The mcp runtime's running half: its listener and connections, the HTTP of Streamable HTTP on them, who asks by
// their key, and the backend that answers with what the script declared and the daemon's own tools.
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <time.h>

#include "mcp_protocol.h"
#include "../../shared/http/conn_server.h"
#include "../../shared/loop/event_loop.h"
#include "../../shared/loop/event_loop_definitions.h"

class mcp_instance;

namespace socketley::mcp
{

class mcp_run : public io_handler, public socketley::http::conn_hooks, public backend
{
public:
    mcp_run(mcp_instance& owner, event_loop& loop);
    ~mcp_run() override;

    bool start(std::string& why);
    void stop();
    void on_loop_turn();
    void on_cqe(struct io_uring_cqe* cqe) override;
    bool drained() const;
    size_t conn_count() const { return m_http.size(); }
    std::string stats() const;

    const std::vector<tool_def>& tools() const override { return m_tools; }
    const std::vector<resource_def>& resources() const override { return m_resources; }
    const std::vector<prompt_def>& prompts() const override { return m_prompts; }
    bool call_tool(const tool_def& t, const json::jvalue& args, const caller& who, tool_result& out,
                   std::string& why) override;
    bool read_resource(const resource_def& r, const caller& who, std::string& contents, std::string& why) override;
    bool get_prompt(const prompt_def& p, const json::jvalue& args, const caller& who, std::string& messages,
                    std::string& description, std::string& why) override;

private:
    struct key
    {
        std::string name;
        bool admin{false};
    };

    std::shared_ptr<socketley::http::server_conn> make_conn() override;
    void serve(const std::shared_ptr<socketley::http::server_conn>& c) override;
    void accepted(const std::shared_ptr<socketley::http::server_conn>& c) override;
    void answer(const std::shared_ptr<socketley::http::server_conn>& c, int status, std::string_view body,
                std::string_view extra = {});
    // The keys file read again when it changed; false with `why` while it cannot be read.
    bool reload_keys(std::string& why);
    // What the script declared and the daemon's tools, as the lists the protocol shows.
    void collect();
    bool daemon_tool(const tool_def& t, const json::jvalue& args, const caller& who, tool_result& out);
    void arm_tick();

    mcp_instance& m_owner;
    event_loop& m_loop;
    socketley::http::conn_server m_http;
    server_info m_info;
    std::vector<tool_def> m_tools;
    std::vector<resource_def> m_resources;
    std::vector<prompt_def> m_prompts;
    size_t m_declared_seen{SIZE_MAX};
    std::unordered_map<std::string, key> m_keys;
    int64_t m_keys_mtime{-1};
    std::string m_keys_error;
    std::vector<std::string> m_origins;
    bool m_any_origin{false};
    uint64_t m_refused{0};
    io_request m_tick_req{};
    __kernel_timespec m_tick_ts{};
    bool m_tick_armed{false};
    bool m_stopped{false};
};

}   // namespace socketley::mcp
