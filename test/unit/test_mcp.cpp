// The mcp runtime's protocol without a socket: each revision's checks of a message, the methods of both, what a key
// that may not administer is shown and let call, and the JSON-RPC errors the revisions name.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <string>

#include "runtime/mcp/mcp_protocol.h"
#include "shared/json/json_doc.h"
#include "shared/json/json_escape.h"

using namespace socketley::mcp;
namespace js = socketley::json;

namespace
{

struct fake : backend
{
    std::vector<tool_def> t;
    std::vector<resource_def> r;
    std::vector<prompt_def> p;
    std::string last_args;
    fake()
    {
        tool_def echo;
        echo.name = "echo";
        echo.description = "says it back";
        echo.input_schema = R"({"type":"object","properties":{"text":{"type":"string"}},"required":["text"]})";
        echo.read_only = true;
        tool_def boom;
        boom.name = "boom";
        tool_def stop;
        stop.name = "stop";
        stop.admin_only = true;
        t = {echo, boom, stop};
        resource_def res;
        res.uri = "test://a";
        res.name = "a";
        res.mime_type = "text/plain";
        res.ttl_ms = 5000;
        r = {res};
        prompt_def pr;
        pr.name = "greet";
        pr.args = {{"who", "whom to greet", true}};
        p = {pr};
    }
    const std::vector<tool_def>& tools() const override { return t; }
    const std::vector<resource_def>& resources() const override { return r; }
    const std::vector<prompt_def>& prompts() const override { return p; }
    bool call_tool(const tool_def& d, const js::jvalue& args, const caller&, tool_result& out, std::string&) override
    {
        last_args = js::written(args);
        if (d.name == "boom")
        {
            out.content = R"([{"type":"text","text":"it failed"}])";
            out.is_error = true;
            return true;
        }
        out.content = "[{\"type\":\"text\",\"text\":" + js::quote(js::string_of(args, "text")) + "}]";
        return true;
    }
    bool read_resource(const resource_def&, const caller&, std::string& contents, std::string&) override
    {
        contents = R"([{"uri":"test://a","mimeType":"text/plain","text":"hello"}])";
        return true;
    }
    bool get_prompt(const prompt_def&, const js::jvalue& args, const caller&, std::string& messages, std::string& d,
                    std::string&) override
    {
        d = "a greeting";
        messages = "[{\"role\":\"user\",\"content\":{\"type\":\"text\",\"text\":" +
                   js::quote("Greet " + std::string(js::string_of(args, "who"))) + "}}]";
        return true;
    }
};

const server_info info{"shop", "Shop", "1.0", "Ask about orders."};

const std::string meta = R"("_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}})";

headers modern(std::string method, std::string name = {})
{
    return headers{"2026-07-28", std::move(method), std::move(name)};
}

js::jvalue parsed(const reply& r)
{
    js::jvalue v;
    REQUIRE(js::json_reader(r.body).document(v));
    return v;
}

const js::jvalue& result_of(const js::jvalue& v)
{
    const js::jvalue* r = js::member(v, "result");
    REQUIRE(r);
    return *r;
}

int64_t error_code(const reply& r)
{
    js::jvalue v = parsed(r);
    const js::jvalue* e = js::member(v, "error");
    REQUIRE(e);
    return js::int_of(*e, "code");
}

}   // namespace

TEST_CASE("server/discover says the revisions, the capabilities and the server, with how long it may be kept")
{
    fake b;
    const reply r = handle(b, info, modern("server/discover"),
                           R"({"jsonrpc":"2.0","id":1,"method":"server/discover","params":{)" + meta + "}}", {});
    CHECK(r.status == 200);
    const js::jvalue v = parsed(r);
    const js::jvalue& res = result_of(v);
    CHECK(js::string_of(res, "resultType") == "complete");
    CHECK(js::written(*js::member(res, "supportedVersions")) == R"(["2026-07-28","2025-11-25","2025-06-18","2025-03-26"])");
    CHECK(js::member(*js::member(res, "capabilities"), "tools"));
    CHECK(js::member(*js::member(res, "capabilities"), "resources"));
    CHECK(js::member(*js::member(res, "capabilities"), "prompts"));
    CHECK(js::string_of(res, "instructions") == "Ask about orders.");
    CHECK(js::int_of(res, "ttlMs") == 60000);
    CHECK(js::string_of(res, "cacheScope") == "public");
    CHECK(js::string_of(*js::member(*js::member(res, "_meta"), "io.modelcontextprotocol/serverInfo"), "name") == "shop");
}

TEST_CASE("a 2026 request is checked against its headers")
{
    fake b;
    const std::string list = R"({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{)" + meta + "}}";
    CHECK(handle(b, info, modern("tools/list"), list, {}).status == 200);
    SUBCASE("a version neither era has")
    {
        const reply r = handle(b, info, headers{"2099-01-01", "tools/list", {}}, list, {});
        CHECK(r.status == 400);
        CHECK(error_code(r) == -32022);
        CHECK(r.body.find("\"requested\":\"2099-01-01\"") != std::string::npos);
    }
    SUBCASE("a header the body does not say")
    {
        const std::string other = R"({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25","io.modelcontextprotocol/clientCapabilities":{}}}})";
        CHECK(error_code(handle(b, info, modern("tools/list"), other, {})) == -32020);
    }
    SUBCASE("no client capabilities")
    {
        const std::string bare = R"({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}})";
        CHECK(error_code(handle(b, info, modern("tools/list"), bare, {})) == -32602);
    }
    SUBCASE("an Mcp-Method that is another method")
    {
        const reply r = handle(b, info, modern("prompts/list"), list, {});
        CHECK(r.status == 400);
        CHECK(error_code(r) == -32020);
    }
    SUBCASE("an Mcp-Name that is another tool")
    {
        const std::string call = R"({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"x"},)" + meta + "}}";
        CHECK(error_code(handle(b, info, modern("tools/call", "boom"), call, {})) == -32020);
        CHECK(handle(b, info, modern("tools/call", "echo"), call, {}).status == 200);
    }
}

TEST_CASE("tools are listed in their order, called with their arguments, and a failure is the model's to read")
{
    fake b;
    const reply l = handle(b, info, modern("tools/list"),
                           R"({"jsonrpc":"2.0","id":"a","method":"tools/list","params":{)" + meta + "}}", {});
    const js::jvalue v = parsed(l);
    CHECK(js::written(*js::member(v, "id")) == "\"a\"");
    const js::jvalue& tools = *js::member(result_of(v), "tools");
    REQUIRE(tools.items.size() == 2);
    CHECK(js::string_of(tools.items[0], "name") == "echo");
    CHECK(js::string_of(tools.items[1], "name") == "boom");
    CHECK(js::string_of(*js::member(tools.items[0], "inputSchema"), "type") == "object");
    CHECK(js::member(*js::member(tools.items[0], "annotations"), "readOnlyHint")->b);
    // Whose list it is depends on who asks, so a cache keeps it to them.
    CHECK(js::string_of(result_of(v), "cacheScope") == "private");

    const std::string call = R"({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"},)" + meta + "}}";
    const js::jvalue c = parsed(handle(b, info, modern("tools/call", "echo"), call, {}));
    CHECK(js::written(*js::member(result_of(c), "content")) == R"([{"type":"text","text":"hi"}])");
    CHECK(!js::member(result_of(c), "isError"));
    CHECK(b.last_args == R"({"text":"hi"})");

    const std::string boom = R"({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"boom",)" + meta + "}}";
    const reply br = handle(b, info, modern("tools/call", "boom"), boom, {});
    CHECK(br.status == 200);
    CHECK(js::member(result_of(parsed(br)), "isError")->b);
    CHECK(b.last_args == "{}");

    const std::string none = R"({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"nope",)" + meta + "}}";
    const reply nr = handle(b, info, modern("tools/call", "nope"), none, {});
    CHECK(error_code(nr) == -32602);
    CHECK(nr.body.find("Unknown tool: nope") != std::string::npos);
}

TEST_CASE("a tool for administrators is shown to and called by an administrator alone")
{
    fake b;
    const std::string call = R"({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"stop",)" + meta + "}}";
    CHECK(error_code(handle(b, info, modern("tools/call", "stop"), call, caller{"ops", false, {}})) == -32602);
    CHECK(handle(b, info, modern("tools/call", "stop"), call, caller{"root", true, {}}).status == 200);
    const js::jvalue v = parsed(handle(b, info, modern("tools/list"),
                                       R"({"jsonrpc":"2.0","id":8,"method":"tools/list","params":{)" + meta + "}}",
                                       caller{"root", true, {}}));
    CHECK(js::member(result_of(v), "tools")->items.size() == 3);
}

TEST_CASE("resources and prompts")
{
    fake b;
    const js::jvalue l = parsed(handle(b, info, modern("resources/list"),
                                       R"({"jsonrpc":"2.0","id":9,"method":"resources/list","params":{)" + meta + "}}", {}));
    CHECK(js::string_of(js::member(result_of(l), "resources")->items.at(0), "uri") == "test://a");
    const std::string read = R"({"jsonrpc":"2.0","id":10,"method":"resources/read","params":{"uri":"test://a",)" + meta + "}}";
    const js::jvalue rd = parsed(handle(b, info, modern("resources/read", "test://a"), read, {}));
    CHECK(js::string_of(js::member(result_of(rd), "contents")->items.at(0), "text") == "hello");
    CHECK(js::int_of(result_of(rd), "ttlMs") == 5000);
    const std::string missing = R"({"jsonrpc":"2.0","id":11,"method":"resources/read","params":{"uri":"test://z",)" + meta + "}}";
    const reply mr = handle(b, info, modern("resources/read", "test://z"), missing, {});
    CHECK(error_code(mr) == -32602);
    CHECK(mr.body.find("\"data\":{\"uri\":\"test://z\"}") != std::string::npos);

    const std::string get = R"({"jsonrpc":"2.0","id":12,"method":"prompts/get","params":{"name":"greet","arguments":{"who":"Ann"},)" + meta + "}}";
    const js::jvalue g = parsed(handle(b, info, modern("prompts/get", "greet"), get, {}));
    CHECK(js::string_of(result_of(g), "description") == "a greeting");
    CHECK(js::string_of(*js::member(js::member(result_of(g), "messages")->items.at(0), "content"), "text") == "Greet Ann");
    const std::string lacking = R"({"jsonrpc":"2.0","id":13,"method":"prompts/get","params":{"name":"greet",)" + meta + "}}";
    CHECK(error_code(handle(b, info, modern("prompts/get", "greet"), lacking, {})) == -32602);
}

TEST_CASE("a client of 2025-11-25 opens with initialize and is answered as that revision has it")
{
    fake b;
    const reply r = handle(b, info, headers{},
                           R"({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c","version":"1"}}})",
                           {});
    CHECK(r.status == 200);
    const js::jvalue doc = parsed(r);
    const js::jvalue& res = result_of(doc);
    CHECK(js::string_of(res, "protocolVersion") == "2025-11-25");
    CHECK(js::string_of(*js::member(res, "serverInfo"), "name") == "shop");
    CHECK(js::string_of(res, "instructions") == "Ask about orders.");
    // A version this server does not have is answered with the newest of the era it has.
    const js::jvalue old = result_of(parsed(handle(b, info, headers{},
        R"({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}})", {})));
    CHECK(js::string_of(old, "protocolVersion") == "2025-11-25");
    // The notification that ends it, and a ping, as the era has them.
    CHECK(handle(b, info, headers{"2025-11-25", {}, {}}, R"({"jsonrpc":"2.0","method":"notifications/initialized"})", {}).status == 202);
    CHECK(handle(b, info, headers{"2025-11-25", {}, {}}, R"({"jsonrpc":"2.0","id":1,"method":"ping"})", {}).status == 200);
    // Its requests carry no _meta and no Mcp- headers.
    const js::jvalue c = parsed(handle(b, info, headers{"2025-11-25", {}, {}},
        R"({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"old"}}})", {}));
    CHECK(js::written(*js::member(result_of(c), "content")) == R"([{"type":"text","text":"old"}])");
    CHECK(!js::member(result_of(c), "_meta"));
}

TEST_CASE("what is no message is refused")
{
    fake b;
    CHECK(handle(b, info, modern("x"), "{nope", {}).status == 400);
    CHECK(error_code(handle(b, info, modern("x"), "{nope", {})) == -32700);
    CHECK(error_code(handle(b, info, modern("x"), "[1,2]", {})) == -32600);
    CHECK(error_code(handle(b, info, modern("x"), R"({"jsonrpc":"1.0","id":1,"method":"x"})", {})) == -32600);
    const reply nf = handle(b, info, modern("nope/nope"),
                            R"({"jsonrpc":"2.0","id":1,"method":"nope/nope","params":{)" + meta + "}}", {});
    CHECK(nf.status == 404);
    CHECK(error_code(nf) == -32601);
    // A response the client sent is taken and dropped.
    CHECK(handle(b, info, modern("x"), R"({"jsonrpc":"2.0","id":1,"result":{}})", {}).status == 202);
}
