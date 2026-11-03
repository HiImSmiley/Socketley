#include "mcp_protocol.h"

#include <algorithm>
#include <optional>

#include "../../shared/json/json_escape.h"

namespace socketley::mcp
{

namespace
{

namespace js = socketley::json;

constexpr int parse_error = -32700, invalid_request = -32600, method_not_found = -32601, invalid_params = -32602,
              internal_error = -32603, header_mismatch = -32020, unsupported_version = -32022;
// How long a client may keep a list or a resource it was given, as the revision asks every list to say.
constexpr uint64_t list_ttl_ms = 60000;

bool is_legacy(std::string_view v)
{
    return std::find(std::begin(legacy_versions), std::end(legacy_versions), v) != std::end(legacy_versions);
}

std::string supported_json()
{
    std::string o = "[";
    o += js::quote(latest_version);
    for (const auto v : legacy_versions)
        o += "," + js::quote(v);
    return o + "]";
}

struct message
{
    std::string id{"null"};
    bool has_id{false};
    std::string method;
    js::jvalue params;
    bool legacy{false};
};

reply error_reply(const message& m, int code, std::string_view text, std::string_view data = {}, int status = 200)
{
    ++stats().errors;
    reply r;
    r.status = status;
    r.body = "{\"jsonrpc\":\"2.0\",\"id\":" + m.id + ",\"error\":{\"code\":" + std::to_string(code) +
             ",\"message\":" + js::quote(text);
    if (!data.empty())
        r.body += ",\"data\":" + std::string(data);
    r.body += "}}";
    return r;
}

std::string server_info_json(const server_info& info)
{
    std::string o = "{\"name\":" + js::quote(info.name) + ",\"version\":" + js::quote(info.version);
    if (!info.title.empty())
        o += ",\"title\":" + js::quote(info.title);
    return o + "}";
}

// A result: what the method gave, with the fields every result of the revision carries.
reply result_reply(const message& m, const server_info& info, std::string_view fields)
{
    reply r;
    r.body = "{\"jsonrpc\":\"2.0\",\"id\":" + m.id + ",\"result\":{\"resultType\":\"complete\"";
    if (!fields.empty())
        r.body += "," + std::string(fields);
    if (!m.legacy)
        r.body += ",\"_meta\":{\"io.modelcontextprotocol/serverInfo\":" + server_info_json(info) + "}";
    r.body += "}}";
    return r;
}

std::string capabilities_json(backend& b)
{
    std::string o = "{";
    const auto add = [&](std::string_view name) {
        o += o.size() > 1 ? "," : "";
        o += "\"" + std::string(name) + "\":{}";
    };
    if (!b.tools().empty() || (b.resources().empty() && b.prompts().empty()))
        add("tools");
    if (!b.resources().empty())
        add("resources");
    if (!b.prompts().empty())
        add("prompts");
    return o + "}";
}

std::string cache_fields(bool per_caller)
{
    return ",\"ttlMs\":" + std::to_string(list_ttl_ms) + ",\"cacheScope\":" + (per_caller ? "\"private\"" : "\"public\"");
}

std::string tool_json(const tool_def& t)
{
    std::string o = "{\"name\":" + js::quote(t.name);
    if (!t.title.empty())
        o += ",\"title\":" + js::quote(t.title);
    if (!t.description.empty())
        o += ",\"description\":" + js::quote(t.description);
    o += ",\"inputSchema\":" + t.input_schema;
    if (!t.output_schema.empty())
        o += ",\"outputSchema\":" + t.output_schema;
    o += std::string(",\"annotations\":{\"readOnlyHint\":") + (t.read_only ? "true" : "false") +
         ",\"destructiveHint\":" + (t.destructive ? "true" : "false") + ",\"idempotentHint\":" +
         (t.idempotent ? "true" : "false") + ",\"openWorldHint\":" + (t.open_world ? "true" : "false") + "}";
    return o + "}";
}

const js::jvalue* object_member(const js::jvalue& v, std::string_view name)
{
    const js::jvalue* m = v.k == js::jvalue::kind::object ? js::member(v, name) : nullptr;
    return m && m->k == js::jvalue::kind::object ? m : nullptr;
}

// A tool's end as the answer to `m`.
reply tool_reply(const message& m, const server_info& info, bool ok, const tool_result& out, const std::string& why)
{
    if (!ok)
        return error_reply(m, internal_error, why.empty() ? "the tool could not be run" : why);
    if (out.is_error)
        ++stats().tool_errors;
    std::string f = "\"content\":" + out.content;
    if (!out.structured.empty())
        f += ",\"structuredContent\":" + out.structured;
    if (out.is_error)
        f += ",\"isError\":true";
    return result_reply(m, info, f);
}

// The answer, or none when a tool was started and `later` hears its answer.
std::optional<reply> dispatch(backend& b, const server_info& info, const message& m, const caller& who,
                              const std::function<void(reply)>& later)
{
    const std::string_view method = m.method;
    if (method == "initialize")
    {
        // The version asked for when this server speaks it, the newest it speaks before 2026 otherwise.
        std::string_view asked = js::string_of(m.params, "protocolVersion");
        const std::string_view answer = is_legacy(asked) ? asked : legacy_versions[0];
        std::string f = "\"protocolVersion\":" + js::quote(answer) + ",\"capabilities\":" + capabilities_json(b) +
                        ",\"serverInfo\":" + server_info_json(info);
        if (!info.instructions.empty())
            f += ",\"instructions\":" + js::quote(info.instructions);
        return result_reply(m, info, f);
    }
    if (method == "ping" || method == "logging/setLevel")
        return result_reply(m, info, {});
    if (method == "server/discover")
    {
        std::string f = "\"supportedVersions\":" + supported_json() + ",\"capabilities\":" + capabilities_json(b);
        if (!info.instructions.empty())
            f += ",\"instructions\":" + js::quote(info.instructions);
        return result_reply(m, info, f + cache_fields(false));
    }
    if (method == "tools/list")
    {
        // A key that may not administer is not shown what it may not call, so the list is its own.
        bool per_caller = false;
        std::string f = "\"tools\":[";
        bool first = true;
        for (const tool_def& t : b.tools())
        {
            per_caller = per_caller || t.admin_only;
            if (t.admin_only && !who.admin)
                continue;
            f += first ? "" : ",";
            first = false;
            f += tool_json(t);
        }
        return result_reply(m, info, f + "]" + cache_fields(per_caller));
    }
    if (method == "tools/call")
    {
        const std::string_view name = js::string_of(m.params, "name");
        const auto& tools = b.tools();
        const auto it = std::find_if(tools.begin(), tools.end(), [&](const tool_def& t) { return t.name == name; });
        if (it == tools.end() || (it->admin_only && !who.admin))
            return error_reply(m, invalid_params, "Unknown tool: " + std::string(name));
        static const js::jvalue no_args = [] { js::jvalue v; v.k = js::jvalue::kind::object; return v; }();
        const js::jvalue* args = object_member(m.params, "arguments");
        if (const js::jvalue* given = js::member(m.params, "arguments"); given && !args &&
                                                                          given->k != js::jvalue::kind::null)
            return error_reply(m, invalid_params, "arguments is an object");
        ++stats().tool_calls;
        b.call_tool(*it, args ? *args : no_args, who,
                    [m, info, later](bool ok, tool_result out, std::string why) { later(tool_reply(m, info, ok, out, why)); });
        return std::nullopt;
    }
    if (method == "resources/list")
    {
        std::string f = "\"resources\":[";
        bool first = true;
        for (const resource_def& r : b.resources())
        {
            f += first ? "{" : ",{";
            first = false;
            f += "\"uri\":" + js::quote(r.uri) + ",\"name\":" + js::quote(r.name.empty() ? r.uri : r.name);
            if (!r.title.empty())
                f += ",\"title\":" + js::quote(r.title);
            if (!r.description.empty())
                f += ",\"description\":" + js::quote(r.description);
            if (!r.mime_type.empty())
                f += ",\"mimeType\":" + js::quote(r.mime_type);
            f += "}";
        }
        return result_reply(m, info, f + "]" + cache_fields(false));
    }
    if (method == "resources/templates/list")
        return result_reply(m, info, "\"resourceTemplates\":[]" + cache_fields(false));
    if (method == "resources/read")
    {
        const std::string_view uri = js::string_of(m.params, "uri");
        const auto& rs = b.resources();
        const auto it = std::find_if(rs.begin(), rs.end(), [&](const resource_def& r) { return r.uri == uri; });
        if (it == rs.end())
            return error_reply(m, invalid_params, "Resource not found", "{\"uri\":" + js::quote(uri) + "}");
        std::string contents, why;
        if (!b.read_resource(*it, who, contents, why))
            return error_reply(m, internal_error, why.empty() ? "the resource could not be read" : why);
        // A resource read per caller may say something of that caller, so a cache keeps it to them.
        return result_reply(m, info, "\"contents\":" + contents + ",\"ttlMs\":" + std::to_string(it->ttl_ms) +
                                         ",\"cacheScope\":\"private\"");
    }
    if (method == "prompts/list")
    {
        std::string f = "\"prompts\":[";
        bool first = true;
        for (const prompt_def& p : b.prompts())
        {
            f += first ? "{" : ",{";
            first = false;
            f += "\"name\":" + js::quote(p.name);
            if (!p.title.empty())
                f += ",\"title\":" + js::quote(p.title);
            if (!p.description.empty())
                f += ",\"description\":" + js::quote(p.description);
            if (!p.args.empty())
            {
                f += ",\"arguments\":[";
                for (size_t i = 0; i < p.args.size(); ++i)
                {
                    f += (i ? ",{" : "{") + std::string("\"name\":") + js::quote(p.args[i].name);
                    if (!p.args[i].description.empty())
                        f += ",\"description\":" + js::quote(p.args[i].description);
                    f += std::string(",\"required\":") + (p.args[i].required ? "true" : "false") + "}";
                }
                f += "]";
            }
            f += "}";
        }
        return result_reply(m, info, f + "]" + cache_fields(false));
    }
    if (method == "prompts/get")
    {
        const std::string_view name = js::string_of(m.params, "name");
        const auto& ps = b.prompts();
        const auto it = std::find_if(ps.begin(), ps.end(), [&](const prompt_def& p) { return p.name == name; });
        if (it == ps.end())
            return error_reply(m, invalid_params, "Unknown prompt: " + std::string(name));
        static const js::jvalue no_args = [] { js::jvalue v; v.k = js::jvalue::kind::object; return v; }();
        const js::jvalue* args = object_member(m.params, "arguments");
        for (const prompt_arg& a : it->args)
            if (a.required && (!args || js::string_of(*args, a.name).empty()))
                return error_reply(m, invalid_params, "Missing required argument: " + a.name);
        std::string messages, description, why;
        if (!b.get_prompt(*it, args ? *args : no_args, who, messages, description, why))
            return error_reply(m, internal_error, why.empty() ? "the prompt could not be made" : why);
        std::string f;
        if (!description.empty())
            f = "\"description\":" + js::quote(description) + ",";
        return result_reply(m, info, f + "\"messages\":" + messages);
    }
    // A method the revision has and this server does not, or one no revision has, answered 404 on HTTP as 2026 asks.
    return error_reply(m, method_not_found, "Method not found: " + m.method, {}, m.legacy ? 200 : 404);
}

}   // namespace

counters& stats()
{
    static counters c;
    return c;
}

static std::optional<reply> handle_or_start(backend& b, const server_info& info, const headers& h,
                                            std::string_view body, const caller& who,
                                            const std::function<void(reply)>& later)
{
    ++stats().requests;
    message m;
    // A batch, which no revision since 2025-06-18 has, is no request rather than no JSON.
    const size_t first = body.find_first_not_of(" \t\r\n");
    if (first != std::string_view::npos && body[first] == '[')
        return error_reply(m, invalid_request, "Invalid Request: one JSON-RPC message a request", {}, 400);
    js::jvalue doc;
    if (!js::json_reader(body).document(doc))
        return error_reply(m, parse_error, "Parse error", {}, 400);
    if (doc.k != js::jvalue::kind::object)
        return error_reply(m, invalid_request, "Invalid Request: one JSON-RPC message a request", {}, 400);
    if (const js::jvalue* id = js::member(doc, "id");
        id && (id->k == js::jvalue::kind::string || id->k == js::jvalue::kind::number))
    {
        m.id = js::written(*id);
        m.has_id = true;
    }
    const js::jvalue* method = js::member(doc, "method");
    if (js::string_of(doc, "jsonrpc") != "2.0" || !method || method->k != js::jvalue::kind::string)
    {
        // A response a client sent, which no request of this server asked for, is taken and dropped.
        if (!method && (js::member(doc, "result") || js::member(doc, "error")))
            return reply{202, {}};
        return error_reply(m, invalid_request, "Invalid Request", {}, 400);
    }
    m.method = method->s;
    if (const js::jvalue* p = js::member(doc, "params"))
    {
        if (p->k != js::jvalue::kind::object && p->k != js::jvalue::kind::null)
            return error_reply(m, invalid_params, "params is an object");
        if (p->k == js::jvalue::kind::object)
            m.params = *p;
    }
    if (m.params.k != js::jvalue::kind::object)
        m.params.k = js::jvalue::kind::object;

    // The revision a request is of: initialize opens the ones before 2026, as does a request with no header, which
    // 2025-11-25 takes to be 2025-03-26.
    const std::string_view version = h.protocol_version;
    if (m.method == "initialize" || version.empty() || is_legacy(version))
        m.legacy = true;
    else if (version != latest_version)
        return error_reply(m, unsupported_version, "Unsupported protocol version: " + std::string(version),
                           "{\"supported\":" + supported_json() + ",\"requested\":" + js::quote(version) + "}", 400);
    if (m.legacy)
        ++stats().legacy;
    else
    {
        const js::jvalue* meta = object_member(m.params, "_meta");
        const std::string_view in_body = meta ? js::string_of(*meta, "io.modelcontextprotocol/protocolVersion") : "";
        if (in_body != version)
            return error_reply(m, header_mismatch, "MCP-Protocol-Version and the request's protocolVersion differ", {},
                               400);
        if (!meta || !object_member(*meta, "io.modelcontextprotocol/clientCapabilities"))
            return error_reply(m, invalid_params, "the request has no clientCapabilities in its _meta");
        if (m.has_id && h.method != m.method)
            return error_reply(m, header_mismatch, "Mcp-Method and the request's method differ", {}, 400);
        const bool named = m.method == "tools/call" || m.method == "prompts/get" || m.method == "resources/read";
        if (named && h.name != js::string_of(m.params, m.method == "resources/read" ? "uri" : "name"))
            return error_reply(m, header_mismatch, "Mcp-Name and the request's name differ", {}, 400);
    }
    // A notification, a cancellation or the end of initialize among them, wants no answer.
    if (!m.has_id)
        return reply{202, {}};
    return dispatch(b, info, m, who, later);
}

void handle(backend& b, const server_info& info, const headers& h, std::string_view body, const caller& who,
            std::function<void(reply)> answer)
{
    if (std::optional<reply> r = handle_or_start(b, info, h, body, who, answer))
        answer(std::move(*r));
}

reply handle(backend& b, const server_info& info, const headers& h, std::string_view body, const caller& who)
{
    reply out;
    handle(b, info, h, body, who, [&](reply r) { out = std::move(r); });
    return out;
}

}   // namespace socketley::mcp
