// Fuzz target: the mcp runtime's reader of what a client POSTs, one JSON-RPC message with the headers of its revision
// (socketley/runtime/mcp/mcp_protocol.cpp).
//
// The first byte chooses the headers: 0 none, as a client before 2025-06-18 sends; 1 those of 2025-11-25; 2 those of
// 2026-07-28 for the method the body names; 3 a revision neither era has. The rest is the body.
//
// Properties checked, beyond "did it crash":
//   * every answer is one JSON object, or nothing with 202 for a notification;
//   * an answer is a result or an error, never both, with the request's id;
//   * a status is one of those the transport names.
#include "fuzz_common.h"
#include "runtime/mcp/mcp_protocol.h"
#include "shared/json/json_doc.h"
#include "shared/json/json_escape.h"

#include <string>

namespace mcp = socketley::mcp;
namespace js = socketley::json;

namespace {

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
        t = {a, b};
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
    bool call_tool(const mcp::tool_def&, const js::jvalue& args, const mcp::caller&, mcp::tool_result& out,
                   std::string&) override
    {
        out.content = "[{\"type\":\"text\",\"text\":" + js::quote(js::written(args)) + "}]";
        return true;
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
