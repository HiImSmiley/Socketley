#include "mcp_instance.h"

#ifndef SOCKETLEY_NO_LUA
#include "mcp_lua_table.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/lua/lua_context.h"
#include "../../shared/lua/lua_json.h"
#include "../../shared/lua/lua_suspend.h"
#include "../../shared/util/logging.h"

namespace socketley::mcp
{

namespace
{

namespace js = socketley::json;

// Where the script's functions are kept, in its own state, so nothing outside it holds a reference a new reading of
// the script would leave pointing at a state that is gone.
const std::string handlers_key{"__mcp_handlers"}, tools_key{"tools"}, resources_key{"resources"},
    prompts_key{"prompts"};

const std::string no_arguments = R"({"type":"object","additionalProperties":false})";

// A Lua value as JSON text: a string as given, a table encoded.
bool json_of(const sol::object& o, std::string& out, std::string& why)
{
    out.clear();
    if (o.get_type() == sol::type::string)
    {
        out = o.as<std::string>();
        js::jvalue v;
        if (!js::json_reader(out).document(v))
        {
            why = "is no JSON";
            return false;
        }
        return true;
    }
    std::vector<const void*> path;
    return socketley::lua_json::json_encode_value(out, o, 0, path, why);
}

// A schema, from a table or a JSON string; `object` asks that it is an object schema, as an input is.
bool schema_of(const sol::object& o, bool object, std::string& out, std::string& why)
{
    if (!o.valid() || o.get_type() == sol::type::lua_nil)
    {
        out.clear();
        return true;
    }
    if (!json_of(o, out, why))
        return false;
    js::jvalue v;
    if (!js::json_reader(out).document(v) || v.k != js::jvalue::kind::object)
    {
        why = "is no JSON Schema object";
        return false;
    }
    if (object && js::string_of(v, "type") != "object")
    {
        why = "has no \"type\": \"object\"";
        return false;
    }
    return true;
}

sol::table caller_table(sol::state_view L, const caller& who)
{
    sol::table t = L.create_table(0, 3);
    t["name"] = who.name;
    t["admin"] = who.admin;
    if (!who.sub.empty())
        t["sub"] = who.sub;
    return t;
}

sol::object lua_of(sol::state& L, const js::jvalue& v)
{
    const std::string text = js::written(v);
    const char* p = text.data();
    auto st = socketley::lua_json::json_status::ok;
    sol::object o = socketley::lua_json::json_decode_value(L, p, text.data() + text.size(), 0, st);
    return st == socketley::lua_json::json_status::ok ? o : sol::make_object(L, sol::lua_nil);
}

std::string text_block(std::string_view s)
{
    return "[{\"type\":\"text\",\"text\":" + js::quote(s) + "}]";
}

// What a tool's handler returned, as its result: a string, or a table of text, content, structured and error.
bool tool_answer(const sol::object& v, tool_result& out, std::string& why)
{
    out.content = "[]";
    if (v.get_type() == sol::type::string || v.get_type() == sol::type::number)
    {
        out.content = text_block(v.as<std::string>());
        return true;
    }
    if (v.get_type() != sol::type::table)
        return true;
    const sol::table t = v.as<sol::table>();
    const sol::object content = t[std::string("content")], text = t[std::string("text")],
                      structured = t[std::string("structured")];
    std::string err;
    if (structured.valid() && structured.get_type() != sol::type::lua_nil && !json_of(structured, out.structured, err))
    {
        why = "the tool's structured " + err;
        return false;
    }
    if (content.valid() && content.get_type() == sol::type::table)
    {
        if (!json_of(content, out.content, err))
        {
            why = "the tool's content " + err;
            return false;
        }
    }
    else if (text.valid() && text.get_type() != sol::type::lua_nil)
        out.content = text_block(text.as<std::string>());
    else if (!out.structured.empty())
        out.content = text_block(out.structured);
    else if (!json_of(v, out.structured, err))
    {
        why = "the tool's answer " + err;
        return false;
    }
    else
        out.content = text_block(out.structured);
    out.is_error = t.get_or("error", false);
    return true;
}

// The function the script gave under `kind` and `name`, in the state that now runs it.
sol::protected_function handler(mcp_instance* rt, const std::string& kind, const std::string& name, std::string& why)
{
    lua_context* ctx = rt->lua();
    if (!ctx)
    {
        why = "the script is not loaded";
        return {};
    }
    sol::optional<sol::protected_function> fn = ctx->state()[handlers_key][kind][name];
    if (!fn)
    {
        why = "the script no longer has it";
        return {};
    }
    return *fn;
}

std::string raised_text(const sol::protected_function_result& r)
{
    sol::error e = r;
    return e.what();
}

bool string_field(const sol::table& t, const char* key, std::string& out)
{
    sol::optional<std::string> v = t[key];
    if (v)
        out = *v;
    return static_cast<bool>(v);
}

}   // namespace

void register_lua_table(runtime_instance* owner, sol::state& lua, sol::table& self)
{
    auto* rt = static_cast<mcp_instance*>(owner);
    // What an earlier reading of the script declared goes with it.
    {
        auto& d = rt->declared();
        const uint64_t gen = d.gen + 1;
        d = declared{};
        d.gen = gen;
    }
    sol::table handlers = lua.create_table();
    handlers[tools_key] = lua.create_table();
    handlers[resources_key] = lua.create_table();
    handlers[prompts_key] = lua.create_table();
    lua[handlers_key] = handlers;

    // mcp.tool{ name=, description=, input=, output=, read_only=, destructive=, idempotent=, open_world=, admin=,
    // handler=function(args, who) }
    self["tool"] = [rt](sol::table def, sol::this_state ts) -> std::tuple<sol::object, sol::object> {
        sol::state_view L(ts);
        // Said in the log as well as answered, since a script seldom looks at what a declaration returns.
        const auto fail = [&](const std::string& what) {
            LOG_ERROR(("mcp " + std::string(rt->get_name()) + ": " + what).c_str());
            return std::make_tuple(sol::make_object(L, sol::lua_nil), sol::make_object(L, what));
        };
        lua_tool t;
        if (!string_field(def, "name", t.def.name) || t.def.name.empty())
            return fail("mcp.tool needs a name");
        string_field(def, "title", t.def.title);
        string_field(def, "description", t.def.description);
        std::string why;
        if (!schema_of(def[std::string("input")], true, t.def.input_schema, why))
            return fail("mcp.tool " + t.def.name + ": input " + why);
        if (t.def.input_schema.empty())
            t.def.input_schema = no_arguments;
        if (!schema_of(def[std::string("output")], false, t.def.output_schema, why))
            return fail("mcp.tool " + t.def.name + ": output " + why);
        t.def.read_only = def.get_or("read_only", false);
        t.def.destructive = def.get_or("destructive", !t.def.read_only);
        t.def.idempotent = def.get_or("idempotent", t.def.read_only);
        t.def.open_world = def.get_or("open_world", true);
        t.def.admin_only = def.get_or("admin", false);
        sol::optional<sol::protected_function> fn = def[std::string("handler")];
        if (!fn)
            return fail("mcp.tool " + t.def.name + " needs a handler function");
        L[handlers_key][tools_key][t.def.name] = *fn;
        const std::string name = t.def.name;
        t.call = [rt, name](const js::jvalue& args, const caller& who, tool_done done) {
            std::string why;
            sol::protected_function f = handler(rt, tools_key, name, why);
            if (!f.valid())
            {
                done(false, {}, why);
                return;
            }
            lua_context* ctx = rt->lua();
            sol::state& S = ctx->state();
            // On a coroutine, so a handler that waits on socketley.http or socketley.db lets the runtime go on serving.
            auto& sus = ctx->suspender();
            sus.set_next_result([done](lua_State* th, int n, const char* error) {
                tool_result out;
                // A tool that raised has failed, which is the model's to read; the suspender has told the operator.
                if (error)
                {
                    out.content = text_block(std::string("the tool raised: ") + error);
                    out.is_error = true;
                    done(true, std::move(out), {});
                    return;
                }
                std::string why;
                const sol::object v = n >= 1 ? sol::stack::get<sol::object>(th, 1) : sol::object(sol::lua_nil);
                const bool ok = tool_answer(v, out, why);
                done(ok, std::move(out), std::move(why));
            });
            lua_suspender::id_t id = 0;
            sus.start(f, "mcp tool", ctx->callback_timeout_ms(), id, lua_of(S, args), caller_table(S, who));
        };
        auto& tools = rt->declared().tools;
        std::erase_if(tools, [&](const lua_tool& x) { return x.def.name == name; });
        tools.push_back(std::move(t));
        ++rt->declared().gen;
        return std::make_tuple(sol::make_object(L, true), sol::make_object(L, sol::lua_nil));
    };

    // mcp.resource{ uri=, name=, title=, description=, mime=, ttl_ms=, read=function(who) }
    self["resource"] = [rt](sol::table def, sol::this_state ts) -> std::tuple<sol::object, sol::object> {
        sol::state_view L(ts);
        // Said in the log as well as answered, since a script seldom looks at what a declaration returns.
        const auto fail = [&](const std::string& what) {
            LOG_ERROR(("mcp " + std::string(rt->get_name()) + ": " + what).c_str());
            return std::make_tuple(sol::make_object(L, sol::lua_nil), sol::make_object(L, what));
        };
        lua_resource r;
        if (!string_field(def, "uri", r.def.uri) || r.def.uri.empty())
            return fail("mcp.resource needs a uri");
        string_field(def, "name", r.def.name);
        string_field(def, "title", r.def.title);
        string_field(def, "description", r.def.description);
        string_field(def, "mime", r.def.mime_type);
        r.def.ttl_ms = def.get_or<uint64_t>("ttl_ms", 0);
        sol::optional<sol::protected_function> fn = def[std::string("read")];
        if (!fn)
            return fail("mcp.resource " + r.def.uri + " needs a read function");
        L[handlers_key][resources_key][r.def.uri] = *fn;
        const std::string uri = r.def.uri, mime = r.def.mime_type;
        r.read = [rt, uri, mime](const caller& who, std::string& contents, std::string& why) {
            sol::protected_function f = handler(rt, resources_key, uri, why);
            if (!f.valid())
                return false;
            sol::state& S = rt->lua()->state();
            // Kept for the deadline's message, which may be written from the hook where nothing may allocate.
            const std::string who_name(rt->get_name());
            sol::protected_function_result res;
            {
                lua_deadline::scope bound(S.lua_state(), "mcp resource", lua_deadline::default_ms(), who_name.c_str());
                res = f(caller_table(S, who));
            }
            if (lua_diag::raised(res, rt->get_name(), "mcp resource " + uri))
            {
                why = "the resource raised: " + raised_text(res);
                return false;
            }
            const sol::object v = res.get<sol::object>(0);
            std::string head = "[{\"uri\":" + js::quote(uri);
            std::string type = mime;
            if (v.get_type() == sol::type::table)
            {
                const sol::table t = v.as<sol::table>();
                string_field(t, "mime", type);
                if (!type.empty())
                    head += ",\"mimeType\":" + js::quote(type);
                if (sol::optional<std::string> blob = t[std::string("blob")])
                    contents = head + ",\"blob\":" + js::quote(*blob) + "}]";
                else
                    contents = head + ",\"text\":" + js::quote(t.get_or<std::string>("text", "")) + "}]";
                return true;
            }
            if (!type.empty())
                head += ",\"mimeType\":" + js::quote(type);
            contents = head + ",\"text\":" + js::quote(v.get_type() == sol::type::lua_nil ? std::string() : v.as<std::string>()) + "}]";
            return true;
        };
        auto& rs = rt->declared().resources;
        std::erase_if(rs, [&](const lua_resource& x) { return x.def.uri == uri; });
        rs.push_back(std::move(r));
        ++rt->declared().gen;
        return std::make_tuple(sol::make_object(L, true), sol::make_object(L, sol::lua_nil));
    };

    // mcp.prompt{ name=, title=, description=, arguments={ {name=, description=, required=} }, get=function(args, who) }
    self["prompt"] = [rt](sol::table def, sol::this_state ts) -> std::tuple<sol::object, sol::object> {
        sol::state_view L(ts);
        // Said in the log as well as answered, since a script seldom looks at what a declaration returns.
        const auto fail = [&](const std::string& what) {
            LOG_ERROR(("mcp " + std::string(rt->get_name()) + ": " + what).c_str());
            return std::make_tuple(sol::make_object(L, sol::lua_nil), sol::make_object(L, what));
        };
        lua_prompt p;
        if (!string_field(def, "name", p.def.name) || p.def.name.empty())
            return fail("mcp.prompt needs a name");
        string_field(def, "title", p.def.title);
        string_field(def, "description", p.def.description);
        if (sol::optional<sol::table> args = def[std::string("arguments")])
            for (size_t i = 1; i <= args->size(); ++i)
            {
                sol::optional<sol::table> a = (*args)[i];
                prompt_arg pa;
                if (!a || !string_field(*a, "name", pa.name) || pa.name.empty())
                    return fail("mcp.prompt " + p.def.name + ": each argument needs a name");
                string_field(*a, "description", pa.description);
                pa.required = a->get_or("required", false);
                p.def.args.push_back(std::move(pa));
            }
        sol::optional<sol::protected_function> fn = def[std::string("get")];
        if (!fn)
            return fail("mcp.prompt " + p.def.name + " needs a get function");
        L[handlers_key][prompts_key][p.def.name] = *fn;
        const std::string name = p.def.name;
        p.get = [rt, name](const js::jvalue& args, const caller& who, std::string& messages, std::string& description,
                           std::string& why) {
            sol::protected_function f = handler(rt, prompts_key, name, why);
            if (!f.valid())
                return false;
            sol::state& S = rt->lua()->state();
            // Kept for the deadline's message, which may be written from the hook where nothing may allocate.
            const std::string who_name(rt->get_name());
            sol::protected_function_result res;
            {
                lua_deadline::scope bound(S.lua_state(), "mcp prompt", lua_deadline::default_ms(), who_name.c_str());
                res = f(lua_of(S, args), caller_table(S, who));
            }
            if (lua_diag::raised(res, rt->get_name(), "mcp prompt " + name))
            {
                why = "the prompt raised: " + raised_text(res);
                return false;
            }
            const sol::object v = res.get<sol::object>(0);
            const auto message = [](std::string_view role, std::string_view text) {
                return "{\"role\":" + js::quote(role) + ",\"content\":{\"type\":\"text\",\"text\":" + js::quote(text) + "}}";
            };
            if (v.get_type() != sol::type::table)
            {
                messages = "[" + message("user", v.get_type() == sol::type::lua_nil ? std::string() : v.as<std::string>()) + "]";
                return true;
            }
            const sol::table t = v.as<sol::table>();
            string_field(t, "description", description);
            messages = "[";
            if (sol::optional<sol::table> ms = t[std::string("messages")])
                for (size_t i = 1; i <= ms->size(); ++i)
                {
                    sol::optional<sol::table> m = (*ms)[i];
                    if (!m)
                        continue;
                    const std::string role = m->get_or<std::string>("role", "user");
                    if (role != "user" && role != "assistant")
                    {
                        why = "a prompt message's role is user or assistant";
                        return false;
                    }
                    messages += (messages.size() > 1 ? "," : "") + message(role, m->get_or<std::string>("text", ""));
                }
            messages += "]";
            return true;
        };
        auto& ps = rt->declared().prompts;
        std::erase_if(ps, [&](const lua_prompt& x) { return x.def.name == name; });
        ps.push_back(std::move(p));
        ++rt->declared().gen;
        return std::make_tuple(sol::make_object(L, true), sol::make_object(L, sol::lua_nil));
    };
}

}   // namespace socketley::mcp

#endif   // SOCKETLEY_NO_LUA
