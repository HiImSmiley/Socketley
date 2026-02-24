// SDK compile test: engine headers + high-level wrapper classes (links libsocketley_sdk.a)
#include <optional>
#include "socketley/server.h"
#include "socketley/client.h"
#include "socketley/proxy.h"
#include "socketley/cache.h"

int main()
{
    // Verify wrapper classes compile, config chains, and callback registration.
    // Does NOT call run() — this is a compile/link test only.

    // Server wrapper
    {
        socketley::server srv(9000);
        srv.max_connections(100)
           .rate_limit(1000)
           .idle_timeout(30)
           .drain()
           .group("web")
           .tick_interval(1000);

        srv.on_start([]{ })
           .on_stop([]{ })
           .on_connect([](int) { })
           .on_disconnect([](int) { })
           .on_message([](int, std::string_view) { })
           .on_tick([](double) { })
           .on_auth([](int) -> bool { return true; })
           .on_websocket([](int, const server_instance::ws_headers_result&) { });

        // Verify escape hatches compile
        (void)srv.instance();
        (void)srv.manager();
        (void)srv.loop();
    }

    // Client wrapper
    {
        socketley::client cli("127.0.0.1", 9000);
        cli.reconnect(5)
           .tick_interval(2000);

        cli.on_start([]{ })
           .on_stop([]{ })
           .on_connect([](int) { })
           .on_disconnect([](int) { })
           .on_message([](std::string_view) { })
           .on_tick([](double) { });

        (void)cli.instance();
    }

    // Proxy wrapper
    {
        socketley::proxy px(8080);
        px.backend("127.0.0.1:9000")
          .protocol(protocol_tcp)
          .strategy(strategy_round_robin)
          .max_connections(500)
          .idle_timeout(60);

        px.on_start([]{ })
          .on_stop([]{ })
          .on_connect([](int) { })
          .on_disconnect([](int) { })
          .on_tick([](double) { })
          .tick_interval(500)
          .on_proxy_request([](int, std::string_view) -> std::optional<std::string> { return std::nullopt; })
          .on_proxy_response([](int, std::string_view) -> std::optional<std::string> { return "modified"; });

        (void)px.instance();
    }

    // Cache wrapper
    {
        socketley::cache c(6379);
        c.persistent("/tmp/test.dat")
         .max_memory(1024 * 1024)
         .eviction(evict_allkeys_lru)
         .resp()
         .mode(cache_mode_admin)
         .max_connections(200)
         .idle_timeout(120);

        c.on_start([]{ })
         .on_stop([]{ });

        (void)c.instance();
    }

    return 0;
}
