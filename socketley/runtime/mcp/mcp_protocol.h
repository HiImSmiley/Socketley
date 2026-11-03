#pragma once
// The Model Context Protocol as an mcp runtime speaks it over Streamable HTTP: one JSON-RPC message a POST, answered
// as the 2026-07-28 revision has it, stateless, its version and the client's capabilities in every request, and as
// 2025-11-25 and the two before it have it for a client that opens with initialize.
//
// What a tool, a resource or a prompt does is the backend's; this file checks a message, routes it and writes the
// answer, and holds no state between two of them.
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "../../shared/json/json_doc.h"

namespace socketley::mcp
{

inline constexpr std::string_view latest_version = "2026-07-28";
// The revisions a client that opens with initialize may ask for, newest first.
inline constexpr std::string_view legacy_versions[] = {"2025-11-25", "2025-06-18", "2025-03-26"};
// The version a request without the header is taken to be, as 2025-11-25 has it.
inline constexpr std::string_view unstated_version = "2025-03-26";

struct tool_def
{
    std::string name, title, description;
    // JSON Schema text: input an object schema, output empty for none.
    std::string input_schema{"{\"type\":\"object\"}"}, output_schema;
    bool read_only{false}, destructive{true}, idempotent{false}, open_world{true};
    // Called by a key that may administer alone.
    bool admin_only{false};
};

struct resource_def
{
    std::string uri, name, title, description, mime_type;
    uint64_t ttl_ms{0};
};

struct prompt_arg
{
    std::string name, description;
    bool required{false};
};

struct prompt_def
{
    std::string name, title, description;
    std::vector<prompt_arg> args;
};

// Who asked: the key's name, empty for none, and whether it may administer.
struct caller
{
    std::string name;
    bool admin{false};
    // The account's id, which never changes, for one signed in through --idp; empty for a key.
    std::string sub;
};

// A tool's answer: a JSON array of content blocks, a JSON value of structured output or empty, and whether the tool
// failed, which is a result the model reads and not a JSON-RPC error.
struct tool_result
{
    std::string content{"[]"};
    std::string structured;
    bool is_error{false};
};

class backend
{
public:
    virtual ~backend() = default;
    virtual const std::vector<tool_def>& tools() const = 0;
    virtual const std::vector<resource_def>& resources() const = 0;
    virtual const std::vector<prompt_def>& prompts() const = 0;
    // False with `why` for a failure of the server's own, which is a JSON-RPC error; a tool that ran and failed sets
    // out.is_error instead.
    virtual bool call_tool(const tool_def& t, const json::jvalue& args, const caller& who, tool_result& out,
                           std::string& why) = 0;
    // The contents array of the resource; false with `why` when it cannot be read.
    virtual bool read_resource(const resource_def& r, const caller& who, std::string& contents, std::string& why) = 0;
    // The messages array and a description; false with `why` when the prompt cannot be made.
    virtual bool get_prompt(const prompt_def& p, const json::jvalue& args, const caller& who, std::string& messages,
                            std::string& description, std::string& why) = 0;
};

struct server_info
{
    std::string name, title, version, instructions;
};

// The headers a message is checked against; empty for one not sent.
struct headers
{
    std::string protocol_version;
    std::string method;
    std::string name;
};

struct reply
{
    int status{200};
    // The JSON to send, empty for a notification answered 202 with nothing.
    std::string body;
};

reply handle(backend& b, const server_info& info, const headers& h, std::string_view body, const caller& who);

// Counted by handle(), for stats.
struct counters
{
    uint64_t requests{0}, tool_calls{0}, tool_errors{0}, errors{0}, legacy{0};
};
counters& stats();

}   // namespace socketley::mcp
