#pragma once
// The mcp runtime: a Model Context Protocol server over Streamable HTTP, whose tools, resources and prompts a script
// declares with mcp.tool, mcp.resource and mcp.prompt, and which may also offer the daemon's own runtimes as tools.
//
// It speaks plain HTTP on its port and is reached through the entrance proxy, which terminates TLS for it as for every
// other name; a key of --keys says who asks, and one marked admin may call what changes the daemon.
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "mcp_protocol.h"
#include "../../shared/runtime/runtime_instance.h"
#include "shared/runtime/retired_runs.h"

namespace socketley::mcp
{
class mcp_run;

// What a script declared, each with the function that does it.
struct lua_tool
{
    tool_def def;
    std::function<bool(const json::jvalue&, const caller&, tool_result&, std::string&)> call;
};
struct lua_resource
{
    resource_def def;
    std::function<bool(const caller&, std::string&, std::string&)> read;
};
struct lua_prompt
{
    prompt_def def;
    std::function<bool(const json::jvalue&, const caller&, std::string&, std::string&, std::string&)> get;
};
struct declared
{
    // Added to by every declaration and every new reading of the script, so a run knows its lists are old.
    uint64_t gen{0};
    std::vector<lua_tool> tools;
    std::vector<lua_resource> resources;
    std::vector<lua_prompt> prompts;
};
}   // namespace socketley::mcp

class mcp_instance : public runtime_instance
{
public:
    explicit mcp_instance(std::string_view name);
    ~mcp_instance() override;

    // The file of keys (--keys), one `name secret [admin]` a line, read again when it changes.
    void set_keys_path(std::string_view p) { m_keys = std::string(p); }
    std::string_view get_keys_path() const { return m_keys; }
    // Asked by anyone, with no key (--anonymous): for a port only this machine reaches.
    void set_anonymous(bool on) { m_anonymous = on; }
    bool get_anonymous() const { return m_anonymous; }
    // The web origins a browser may call it from (--origins), comma-separated; * for any.
    void set_origins(std::string_view list) { m_origins = std::string(list); }
    std::string_view get_origins() const { return m_origins; }
    // The daemon's runtimes offered as tools (--tools daemon): listing and reading them for every key, starting and
    // stopping them for an admin's.
    void set_tools(std::string_view t) { m_tools = std::string(t); }
    std::string_view get_tools() const { return m_tools; }
    // What a client is told the server is for (--instructions).
    void set_instructions(std::string_view t) { m_instructions = std::string(t); }
    std::string_view get_instructions() const { return m_instructions; }

    // Filled by the script's mcp.tool, mcp.resource and mcp.prompt, and emptied when the script is read again.
    socketley::mcp::declared& declared() { return m_declared; }
    socketley::mcp::mcp_run* run() const { return m_run.get(); }

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
    std::string m_keys;
    bool m_anonymous{false};
    std::string m_origins;
    std::string m_tools{"none"};
    std::string m_instructions;
    socketley::mcp::declared m_declared;

    std::unique_ptr<socketley::mcp::mcp_run> m_run;
    // Runs stopped but still owed completions by the ring.
    socketley::retired_runs<socketley::mcp::mcp_run> m_graveyard;
};
