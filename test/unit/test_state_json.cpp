#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
// The state file's reader as `import` and every start use it: what a document's keys say, read in one walk.
#include "doctest.h"
#include "thread_cpu.h"

#include <chrono>
#include <filesystem>
#include <string>

#include "shared/persist/state_persistence.h"

namespace
{
const state_persistence& parser()
{
    static const state_persistence p{std::filesystem::path{}};
    return p;
}

// A proxy's document with `n` backends, the largest list a state file holds.
std::string proxy_with_backends(size_t n)
{
    std::string j = "{\"name\":\"p\",\"type\":\"proxy\",\"port\":8080,\"strategy\":\"random\",\"backends\":[";
    for (size_t i = 0; i < n; ++i)
    {
        if (i)
            j += ',';
        j += "\"10." + std::to_string((i >> 16) & 255) + "." + std::to_string((i >> 8) & 255) + "." +
             std::to_string(i & 255) + ":8080\"";
    }
    j += "],\"max_connections\":7}";
    return j;
}
}   // namespace

TEST_CASE("state json: a document is read in time linear in its size, whatever it holds")
{
    // Every getter walked the whole document from its start for its own key: about sixty walks of a proxy's.
    const std::string small = proxy_with_backends(1000);
    const std::string big = proxy_with_backends(400000);
    runtime_config a, b;
    auto start = thread_cpu_now();
    REQUIRE(parser().parse_json_string(small, a));
    const auto took_small = thread_cpu_now() - start;
    start = thread_cpu_now();
    REQUIRE(parser().parse_json_string(big, b));
    const auto took_big = thread_cpu_now() - start;
    MESSAGE("document of " << small.size() << " bytes: " << std::chrono::duration<double>(took_small).count() * 1e3
                           << " ms; of " << big.size() << " bytes: "
                           << std::chrono::duration<double>(took_big).count() * 1e3 << " ms");
    CHECK(b.backends.size() == 400000);
    CHECK(b.max_connections == 7);
    CHECK(took_big < std::chrono::milliseconds(150 * build_cpu_factor));
}

TEST_CASE("state json: import refuses a document it would read as something else than it says")
{
    const auto refused = [](std::string_view doc, runtime_type type) {
        return parser().import_refusal(std::string(doc), type);
    };
    // What each was read as before: the field's default, applied, and the import answered 0.
    CHECK(refused(R"({"max_connections":-1})", runtime_server).find("max_connections") != std::string::npos);
    CHECK(refused(R"({"tls":"yes"})", runtime_proxy).find("\"tls\"") != std::string::npos);
    CHECK(refused(R"({"rate_limit":"5/s"})", runtime_server).find("rate_limit") != std::string::npos);
    CHECK(refused(R"({"port":70000})", runtime_server).find("port") != std::string::npos);
    CHECK(refused(R"({"imap":70143})", runtime_mail).find("imap") != std::string::npos);
    CHECK(refused(R"({"keepalive_max":65536})", runtime_mqtt).find("keepalive_max") != std::string::npos);
    CHECK(refused(R"({"fsync_interval":4294967296})", runtime_storage).find("fsync_interval") != std::string::npos);
    CHECK(refused(R"({"health_interval":-5})", runtime_proxy).find("health_interval") != std::string::npos);
    CHECK(refused(R"({"strategy":"randon"})", runtime_proxy).find("strategy") != std::string::npos);
    CHECK(refused(R"({"mode":"agnet"})", runtime_tunnel).find("mode") != std::string::npos);
    CHECK(refused(R"({"mode":"both"})", runtime_sync).find("mode") != std::string::npos);
    CHECK(refused(R"({"send_to":"sender,everyone"})", runtime_server).find("send_to") != std::string::npos);
    CHECK(refused(R"({"backends":"127.0.0.1:1"})", runtime_proxy).find("backends") != std::string::npos);
    CHECK(refused(R"({"backends":["127.0.0.1:1", 7]})", runtime_proxy).find("backends") != std::string::npos);
    CHECK(refused(R"({"cert_path":null})", runtime_server).find("cert_path") != std::string::npos);
    CHECK(refused(R"({"extra":{"k":1}})", runtime_server).find("extra") != std::string::npos);
    CHECK(refused(R"({"connections":0})", runtime_client).find("connections") != std::string::npos);
    CHECK(refused(R"({"connections":65536})", runtime_client).find("connections") != std::string::npos);
    // What the reader walked around: a missing comma, a stray word, something after the object.
    CHECK(refused(R"({"tls": true "port": 5})", runtime_server).find("not JSON") != std::string::npos);
    CHECK(refused(R"({"max_connections":7, x "idle_timeout":3})", runtime_server).find("not JSON") != std::string::npos);
    CHECK(refused(R"({"max_connections":7}{"tls":true})", runtime_server).find("not JSON") != std::string::npos);
    CHECK(refused(R"({"backends":["a",]})", runtime_proxy).find("not JSON") != std::string::npos);
    CHECK(refused(R"({"name":"a\q"})", runtime_server).find("not JSON") != std::string::npos);
    CHECK(refused(R"({"max_connections":07})", runtime_server).find("not JSON") != std::string::npos);
    // A typo, a key named twice, and another type's document.
    CHECK(refused(R"({"max_conections":5})", runtime_server).find("max_conections") != std::string::npos);
    CHECK(refused(R"({"idle_timeout":5,"idle_timeout":9})", runtime_server).find("twice") != std::string::npos);
    CHECK(refused(R"({"type":"server","strategy":"random"})", runtime_proxy).find("type") != std::string::npos);
    CHECK(refused(R"({"strategy":"random"})", runtime_server).find("strategy") != std::string::npos);
    // And what was always taken still is: a partial document, quoted numbers, an empty enum, the type it is.
    CHECK(refused(R"({"max_connections":7,"rate_limit":"2.5","tls":false})", runtime_server).empty());
    CHECK(refused(R"({"name":"p","type":"proxy","strategy":"lua","backends":[]})", runtime_proxy).empty());
    CHECK(refused(R"({"send_to":"","mode":"master"})", runtime_server).empty());
    CHECK(refused(R"({"mode":"agent","offer":"web=127.0.0.1:80"})", runtime_tunnel).empty());
    CHECK(refused("{}", runtime_cache).empty());
    CHECK(refused(" {\n \"extra\" : { } , \"backends\":[ ] ,\"rate_limit\":-1.5e-3}\n", runtime_proxy)
              .find("not JSON") == std::string::npos);
}

TEST_CASE("state json: the document show prints for every type is one import takes")
{
    // Every key it writes is one the type reads, at a value the field takes: `show | import` is the round trip.
    for (int t = 0; t < 15; ++t)
    {
        runtime_config cfg;
        cfg.name = "x";
        cfg.type = static_cast<runtime_type>(t);
        cfg.port = 65535;
        cfg.max_connections = 4294967295u;
        cfg.rate_limit = 1e300;
        cfg.reconnect = 0;
        cfg.tls = true;
        cfg.congestion = "reno";
        cfg.domains = "a.test";
        cfg.shards = 4;
        const std::string shown = parser().format_json_pretty(cfg);
        INFO(shown);
        CHECK(parser().import_refusal(shown, cfg.type).empty());
    }
}

TEST_CASE("state json: what the reader takes is unchanged by reading it in one walk")
{
    // Keys inside values and nested objects are not the document's own, the first of two names wins, and a string
    // the document never ends is read to the end.
    runtime_config c;
    REQUIRE(parser().parse_json_string(
        R"({"name":"a","note":"\"port\": 9","extra":{"port":"8","domain":"x"},"port":7,"name":"b"})", c,
        runtime_server));
    CHECK(c.name == "a");
    CHECK(c.port == 7);
    CHECK(c.domains.empty());
    REQUIRE(c.extra.size() == 2);
    CHECK(c.extra[0] == std::pair<std::string, std::string>{"port", "8"});
    runtime_config t;
    CHECK(parser().parse_json_string(R"({"name":"t","log_file":"/a\"b","port":5,"bind":"x)", t, runtime_server));
    CHECK(t.log_file == "/a\"b");
    CHECK(t.port == 5);
    CHECK(t.bind_address == "x");
}
