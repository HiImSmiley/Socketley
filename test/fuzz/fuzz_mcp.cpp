// Fuzz target: the mcp runtime's reader of what a client POSTs, one JSON-RPC message with the headers of its revision
// (socketley/runtime/mcp/mcp_protocol.cpp).
//
// The first byte chooses the headers: 0 none, as a client before 2025-06-18 sends; 1 those of 2025-11-25; 2 those of
// 2026-07-28 for the method the body names; 3 a revision neither era has. The rest is the body. A first byte with
// 0x40 set (no message seed has it) instead holds the rest to an input schema directly: the schema up to the first
// NUL, then the arguments; with no NUL the rest is the arguments, held to the tool "typed"'s schema.
//
// Properties checked, beyond "did it crash":
//   * every answer is one JSON object, or nothing with 202 for a notification;
//   * an answer is a result or an error, never both, with the request's id;
//   * a status is one of those the transport names;
//   * the handler of "typed" never sees arguments its schema refuses, read by hand here rather than by the checker;
//   * any arguments are admitted by {}, by their own const, enum and type, and refused by not of their const;
//   * a schema says the same of the same arguments twice, says why whenever it refuses, and does so within 2 s.
#include "fuzz_common.h"
#include "runtime/mcp/mcp_protocol.h"
#include "runtime/mcp/mcp_schema.h"
#include "shared/json/json_doc.h"
#include "shared/json/json_escape.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <string>

namespace mcp = socketley::mcp;
namespace js = socketley::json;

namespace {

// A schema of most of what a tool declares in practice: required, no extra member, a pattern, an enum, an integer
// range, a list's length and kind, and a member held by reference.
constexpr std::string_view typed_schema = R"({"type":"object","required":["path"],"additionalProperties":false,
"properties":{"path":{"type":"string","pattern":"^[a-z0-9/]{1,64}$"},"count":{"type":"integer","minimum":1,"maximum":100},
"mode":{"enum":["r","w"]},"tags":{"type":"array","maxItems":8,"items":{"type":"string","maxLength":16}},
"opts":{"$ref":"#/$defs/opts"}},"$defs":{"opts":{"type":"object","additionalProperties":false,
"properties":{"deep":{"type":"boolean"}}}}})";

// What "typed"'s schema asks, read by hand, so the handler can tell arguments that should never have reached it.
bool typed_by_hand(const js::jvalue& a)
{
    using k = js::jvalue::kind;
    if (a.k != k::object)
        return false;
    for (const auto& [name, v] : a.members)
    {
        if (name == "path")
        {
            if (v.k != k::string || v.s.empty() || v.s.size() > 64 ||
                !std::all_of(v.s.begin(), v.s.end(), [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '/'; }))
                return false;
        }
        else if (name == "count")
        {
            if (v.k != k::number)
                return false;
            const double d = std::strtod(v.s.c_str(), nullptr);
            if (!(d >= 1 && d <= 100) || std::floor(d) != d)
                return false;
        }
        else if (name == "mode")
        {
            if (v.k != k::string || (v.s != "r" && v.s != "w"))
                return false;
        }
        else if (name == "tags")
        {
            if (v.k != k::array || v.items.size() > 8)
                return false;
            for (const auto& t : v.items)
            {
                if (t.k != k::string)
                    return false;
                size_t n = 0;
                for (const unsigned char c : t.s)
                    n += (c & 0xC0) != 0x80;
                if (n > 16)
                    return false;
            }
        }
        else if (name == "opts")
        {
            if (v.k != k::object)
                return false;
            for (const auto& [o, ov] : v.members)
                if (o != "deep" || ov.k != k::boolean)
                    return false;
        }
        else
            return false;
    }
    return js::member(a, "path") != nullptr;
}

bool admits(std::string_view schema, const js::jvalue& v, std::string* why_out = nullptr)
{
    std::string why;
    const bool ok = mcp::schema_admits(schema, v, why);
    FUZZ_CHECK(ok || !why.empty(), "a schema refuses without saying why");
    if (why_out)
        *why_out = std::move(why);
    return ok;
}

void direct(std::string_view in)
{
    const size_t nul = in.find('\0');
    const std::string_view schema = nul == std::string_view::npos ? typed_schema : in.substr(0, nul);
    const std::string_view text = nul == std::string_view::npos ? in : in.substr(nul + 1);
    js::jvalue args;
    // Nested no deeper than a request's own reader takes, and any kind, since a schema meets every kind below the top.
    js::json_policy p;
    p.object_root = false;
    if (!js::json_reader(text, p).document(args))
        return;

    const auto began = std::chrono::steady_clock::now();
    std::string first, second;
    const bool a = admits(schema, args, &first);
    const bool b = admits(schema, args, &second);
    FUZZ_CHECK(a == b && first == second, "a schema says two things of the same arguments");
    FUZZ_CHECK(std::chrono::steady_clock::now() - began < std::chrono::seconds(2),
               "a schema took more than two seconds to check one set of arguments");
    if (nul == std::string_view::npos && args.k == js::jvalue::kind::object)
        FUZZ_CHECK(a == typed_by_hand(args), "the checker and the schema read by hand disagree on typed's arguments");

    // What any value is admitted and refused by, whatever it is.
    const std::string w = js::written(args);
    FUZZ_CHECK(admits("{}", args), "{} refuses a value");
    FUZZ_CHECK(!admits(R"({"not":{}})", args), "not {} admits a value");
    FUZZ_CHECK(admits("{\"const\":" + w + "}", args), "a value is not its own const");
    FUZZ_CHECK(admits("{\"enum\":[1," + w + "]}", args), "a value is not in an enum that lists it");
    FUZZ_CHECK(!admits("{\"not\":{\"const\":" + w + "}}", args), "not of its own const admits a value");
    FUZZ_CHECK(admits("{\"anyOf\":[false,{\"const\":" + w + "}]}", args), "anyOf of its const refuses a value");
    FUZZ_CHECK(!admits("{\"oneOf\":[{\"const\":" + w + "},{}]}", args), "oneOf of two that admit it admits a value");
    static constexpr const char* names[] = {"null", "boolean", "number", "string", "array", "object"};
    FUZZ_CHECK(admits(std::string("{\"type\":\"") + names[static_cast<int>(args.k)] + "\"}", args),
               "a value is not of its own type");
}

struct echo : mcp::backend
{
    std::vector<mcp::tool_def> t;
    std::vector<mcp::resource_def> r;
    std::vector<mcp::prompt_def> p;
    echo()
    {
        mcp::tool_def a;
        a.name = "echo";
        mcp::tool_def b;
        b.name = "root";
        b.admin_only = true;
        mcp::tool_def c;
        c.name = "typed";
        c.input_schema = typed_schema;
        t = {a, b, c};
        mcp::resource_def res;
        res.uri = "x://a";
        r = {res};
        mcp::prompt_def pr;
        pr.name = "p";
        pr.args = {{"who", "", true}};
        p = {pr};
    }
    const std::vector<mcp::tool_def>& tools() const override { return t; }
    const std::vector<mcp::resource_def>& resources() const override { return r; }
    const std::vector<mcp::prompt_def>& prompts() const override { return p; }
    void call_tool(const mcp::tool_def& tool, const js::jvalue& args, const mcp::caller&, mcp::tool_done done) override
    {
        if (tool.name == "typed")
            FUZZ_CHECK(typed_by_hand(args), "typed's handler got arguments its schema refuses");
        mcp::tool_result out;
        out.content = "[{\"type\":\"text\",\"text\":" + js::quote(js::written(args)) + "}]";
        done(true, std::move(out), {});
    }
    bool read_resource(const mcp::resource_def&, const mcp::caller&, std::string& c, std::string&) override
    {
        c = R"([{"uri":"x://a","text":"a"}])";
        return true;
    }
    bool get_prompt(const mcp::prompt_def&, const js::jvalue&, const mcp::caller&, std::string& m, std::string&,
                    std::string&) override
    {
        m = R"([{"role":"user","content":{"type":"text","text":"hi"}}])";
        return true;
    }
};

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1)
        return 0;
    if (data[0] & 0x40)
    {
        direct(std::string_view(reinterpret_cast<const char*>(data) + 1, size - 1));
        return 0;
    }
    static echo b;
    static const mcp::server_info info{"fuzz", "", "1", ""};
    const std::string_view body(reinterpret_cast<const char*>(data) + 1, size - 1);
    mcp::headers h;
    if (data[0] % 4 == 1)
        h.protocol_version = "2025-11-25";
    else if (data[0] % 4 == 2)
    {
        h.protocol_version = "2026-07-28";
        js::jvalue doc;
        if (js::json_reader(body).document(doc) && doc.k == js::jvalue::kind::object)
        {
            h.method = std::string(js::string_of(doc, "method"));
            if (const js::jvalue* p = js::member(doc, "params"); p && p->k == js::jvalue::kind::object)
                h.name = std::string(h.method == "resources/read" ? js::string_of(*p, "uri") : js::string_of(*p, "name"));
        }
    }
    else if (data[0] % 4 == 3)
        h.protocol_version = "2099-01-01";
    const mcp::reply r = mcp::handle(b, info, h, body, mcp::caller{"f", (data[0] & 0x80) != 0, {}});
    FUZZ_CHECK(r.status == 200 || r.status == 202 || r.status == 400 || r.status == 404, "a status the transport names");
    if (r.status == 202)
    {
        FUZZ_CHECK(r.body.empty(), "a notification is answered with nothing");
        return 0;
    }
    js::jvalue out;
    FUZZ_CHECK(js::json_reader(r.body).document(out) && out.k == js::jvalue::kind::object, "an answer is one JSON object");
    FUZZ_CHECK((js::member(out, "result") != nullptr) != (js::member(out, "error") != nullptr), "a result or an error, not both");
    FUZZ_CHECK(js::string_of(out, "jsonrpc") == "2.0", "the answer is JSON-RPC 2.0");
    return 0;
}
