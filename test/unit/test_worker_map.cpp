#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "../../socketley/shared/runtime/runtime_manager.h"
#include "../../socketley/shared/loop/event_loop.h"
#include "../../socketley/shared/ipc/worker_protocol.h"

#include <string>
#include <vector>

// The runtime map, as a worker sees it.
//
// A worker process holds one runtime and no map, and that is why twelve
// management calls are refused out there.  The daemon pushes what it has; this
// covers the two halves of receiving it — the frame, and what the manager does
// with the frame's contents — and the guards that stop a replica being mistaken
// for the real thing.
//
// What is NOT covered here: the wiring. Whether the daemon builds the frame at
// the right moments and whether the worker hands it to install_replica() is a
// question about two processes, and these tests have one.

namespace {

worker_proto::runtime_wire wire(std::string name, std::string type, uint8_t state,
                                uint16_t port, uint64_t conns, std::string owner,
                                std::string group = {})
{
    worker_proto::runtime_wire w;
    w.name = std::move(name);
    w.type = std::move(type);
    w.state = state;
    w.port = port;
    w.connections = conns;
    w.owner = std::move(owner);
    w.group = std::move(group);
    return w;
}

runtime_manager::replica_entry entry(std::string name, runtime_type type,
                                     runtime_state state, uint16_t port,
                                     uint64_t conns, std::string owner = {},
                                     std::string group = {})
{
    runtime_manager::replica_entry e;
    e.name = std::move(name);
    e.type = type;
    e.state = state;
    e.port = port;
    e.connections = conns;
    e.owner = std::move(owner);
    e.group = std::move(group);
    return e;
}

} // namespace

TEST_CASE("runtime map survives the wire unchanged")
{
    std::vector<worker_proto::runtime_wire> in;
    in.push_back(wire("api", "server", 1 /*running*/, 8080, 42, "", "web"));
    in.push_back(wire("kv", "cache", 0 /*created*/, 0, 0, "api"));
    // A name with a space in it, because every string on this wire is
    // length-prefixed and nothing has to be escaped.  A port at the top of the
    // range and a count above 2^32, because both fields have been the wrong
    // width in a protocol before.
    in.push_back(wire("a name", "proxy", 3 /*failed*/, 65535,
                      5'000'000'000ULL, "a parent", "a group"));

    const std::string payload = worker_proto::encode_runtime_map(in);

    std::vector<worker_proto::runtime_wire> out;
    REQUIRE(worker_proto::decode_runtime_map(payload, out));
    REQUIRE(out.size() == in.size());
    for (size_t i = 0; i < in.size(); ++i)
    {
        CHECK(out[i].name        == in[i].name);
        CHECK(out[i].type        == in[i].type);
        CHECK(out[i].state       == in[i].state);
        CHECK(out[i].port        == in[i].port);
        CHECK(out[i].connections == in[i].connections);
        CHECK(out[i].owner       == in[i].owner);
        CHECK(out[i].group       == in[i].group);
    }
}

TEST_CASE("an empty map is a map, not a failure")
{
    // The daemon has runtimes but this is still worth telling a worker: it is
    // how the last one being removed reaches the replica.
    const std::string payload = worker_proto::encode_runtime_map({});
    std::vector<worker_proto::runtime_wire> out;
    out.push_back(wire("stale", "server", 1, 1, 1, ""));
    REQUIRE(worker_proto::decode_runtime_map(payload, out));
    CHECK(out.empty());
}

TEST_CASE("a truncated map is refused rather than half-read")
{
    std::vector<worker_proto::runtime_wire> in;
    in.push_back(wire("api", "server", 1, 8080, 1, "parent"));
    const std::string payload = worker_proto::encode_runtime_map(in);

    // Every prefix short of the whole thing.  A decoder that reads past the end
    // of one field and into the next would pass some of these.
    for (size_t n = 0; n < payload.size(); ++n)
    {
        std::vector<worker_proto::runtime_wire> out;
        CHECK_FALSE(worker_proto::decode_runtime_map(
            std::string_view(payload.data(), n), out));
    }
    std::vector<worker_proto::runtime_wire> out;
    CHECK(worker_proto::decode_runtime_map(payload, out));
}

TEST_CASE("a replica answers what socketley.get is built from")
{
    runtime_manager mgr;
    mgr.mark_replica();

    mgr.install_replica({ entry("api", runtime_server, runtime_running, 8080, 7,
                                {}, "web"),
                          entry("kv", runtime_cache, runtime_created, 0, 0, "api") });

    // list(), which is the whole of socketley.list().
    {
        std::shared_lock lock(mgr.mutex);
        CHECK(mgr.list().size() == 2);
    }

    // get(), which is the whole of socketley.get() but the type name.
    auto* api = mgr.get("api");
    REQUIRE(api != nullptr);
    CHECK(api->get_name() == "api");
    CHECK(api->get_type() == runtime_server);
    CHECK(api->get_state() == runtime_running);
    CHECK(api->get_port() == 8080);
    CHECK(api->reported_connection_count() == 7);
    CHECK(api->get_owner().empty());
    // Not one of socketley.get()'s fields, and the reason the row carries it:
    // socketley.cluster.group(name) is about nothing else.
    CHECK(api->get_group() == "web");

    auto* kv = mgr.get("kv");
    REQUIRE(kv != nullptr);
    CHECK(kv->get_type() == runtime_cache);
    CHECK(kv->get_state() == runtime_created);
    CHECK(kv->get_owner() == "api");

    CHECK(mgr.get("nothing") == nullptr);
}

TEST_CASE("a replica is not something to act on")
{
    runtime_manager mgr;
    mgr.mark_replica();
    mgr.install_replica({ entry("api", runtime_server, runtime_running, 8080, 0) });

    auto* api = mgr.get("api");
    REQUIRE(api != nullptr);

    // socketley.send and cmd_send both branch on this to reach the process that
    // holds the connections.  A replica that answered false here would have
    // them broadcast into an object with no connections and report success.
    CHECK(api->is_out_of_process());

    // And the nine sites that reach for server_instance's own methods ask this.
    // A replica of a server reports `runtime_server` truthfully — the cast that
    // used to follow that test is what this replaces.
    CHECK(api->as_server() == nullptr);

    // Nothing is armed, so nothing in a ring can be naming this storage: the
    // manager may free a dropped replica on the spot.
    CHECK_FALSE(api->has_armed_io());
}

TEST_CASE("the worker's own runtime is in the map, and is a replica too")
{
    // The daemon sends every runtime it has, including the one this worker
    // holds, because socketley.list() called from a runtime includes that
    // runtime everywhere else — a worker that left itself out would answer one
    // short of the daemon.
    //
    // And it arrives as a replica like every other row, which is what keeps a
    // PUBLISH from being delivered to this worker's runtime twice: the map walk
    // in dispatch_publish() skips what is out of process, and the worker's
    // publish sink delivers to its own runtime by hand.
    runtime_manager mgr;
    mgr.mark_replica();
    mgr.install_replica({ entry("me", runtime_server, runtime_running, 8080, 2),
                          entry("peer", runtime_server, runtime_running, 8081, 0) });

    auto* self = mgr.get("me");
    REQUIRE(self != nullptr);
    CHECK(self->is_out_of_process());
    CHECK(self->lua() == nullptr);
    {
        std::shared_lock lock(mgr.mutex);
        CHECK(mgr.list().size() == 2);
    }
}

TEST_CASE("the second snapshot updates in place")
{
    runtime_manager mgr;
    mgr.mark_replica();
    mgr.install_replica({ entry("api", runtime_server, runtime_created, 8080, 0) });

    runtime_instance* first = mgr.get("api");
    REQUIRE(first != nullptr);

    mgr.install_replica({ entry("api", runtime_server, runtime_running, 8080, 3) });

    // The same object, so a pointer a caller took out of get() a statement ago
    // still names the runtime it asked about.
    CHECK(mgr.get("api") == first);
    CHECK(first->get_state() == runtime_running);
    CHECK(first->reported_connection_count() == 3);
}

TEST_CASE("a name the daemon no longer has leaves the replica")
{
    runtime_manager mgr;
    mgr.mark_replica();
    mgr.install_replica({ entry("api", runtime_server, runtime_running, 8080, 0),
                          entry("kv", runtime_cache, runtime_running, 6379, 0) });
    {
        std::shared_lock lock(mgr.mutex);
        REQUIRE(mgr.list().size() == 2);
    }

    mgr.install_replica({ entry("api", runtime_server, runtime_running, 8080, 0) });

    CHECK(mgr.get("kv") == nullptr);
    CHECK(mgr.get("api") != nullptr);
    {
        std::shared_lock lock(mgr.mutex);
        CHECK(mgr.list().size() == 1);
    }

    // And the last one going.
    mgr.install_replica({});
    CHECK(mgr.get("api") == nullptr);
}

TEST_CASE("a name reused for another type is rebuilt, not re-tagged")
{
    // remove + create between two pushes.  get_type() is fixed at construction,
    // so keeping the object would report a cache as the server it used to be.
    runtime_manager mgr;
    mgr.mark_replica();
    mgr.install_replica({ entry("x", runtime_server, runtime_running, 8080, 0) });
    REQUIRE(mgr.get("x")->get_type() == runtime_server);

    mgr.install_replica({ entry("x", runtime_cache, runtime_running, 6379, 0) });
    REQUIRE(mgr.get("x") != nullptr);
    CHECK(mgr.get("x")->get_type() == runtime_cache);
    CHECK(mgr.get("x")->get_port() == 6379);
}

TEST_CASE("a replica map refuses to be written")
{
    // Every one of these would build or move something in this process alone.
    // They are unreachable from the Lua bindings, which route to the remote_*
    // calls in a replica; the refusal is what makes a call site that has not
    // been taught the difference fail visibly instead of quietly.
    runtime_manager mgr;
    mgr.mark_replica();
    mgr.install_replica({ entry("api", runtime_server, runtime_running, 8080, 0) });

    event_loop loop;   // never initialised: none of these may reach it

    CHECK_FALSE(mgr.create(runtime_server, "made"));
    CHECK(mgr.get("made") == nullptr);

    CHECK_FALSE(mgr.start("api", loop));
    CHECK_FALSE(mgr.stop("api", loop));
    CHECK_FALSE(mgr.rename("api", "api2"));
    CHECK_FALSE(mgr.remove("api"));

    // Untouched by all five.
    REQUIRE(mgr.get("api") != nullptr);
    CHECK(mgr.get("api")->get_state() == runtime_running);
    CHECK(mgr.get("api2") == nullptr);
}

TEST_CASE("a replica never republishes the endpoint table")
{
    // The destructive one.  publish_endpoints() REBUILDS that table out of the
    // local map and pushes it everywhere, so in a worker it would overwrite the
    // authoritative table the daemon sent — with a copy that is missing every
    // remote cluster member, because a worker has no cluster_discovery to fold
    // them in from.  A proxy's @group routing would quietly lose every member on
    // another node.
    //
    // Observed through the endpoint sink, which is the last thing
    // publish_endpoints() does and the only part of it visible from here.
    runtime_manager daemon_side;
    bool daemon_published = false;
    daemon_side.set_endpoint_sink([&](const endpoint_table&) { daemon_published = true; });
    daemon_side.publish_endpoints();
    // The control: without this the check below passes on a build where
    // publishing was broken for everybody.
    CHECK(daemon_published);

    runtime_manager replica;
    bool replica_published = false;
    replica.set_endpoint_sink([&](const endpoint_table&) { replica_published = true; });
    replica.mark_replica();
    replica.install_replica({ entry("api", runtime_server, runtime_running, 8080, 0) });
    replica.publish_endpoints();
    CHECK_FALSE(replica_published);
}

TEST_CASE("a manager that was never marked is still the daemon's")
{
    // The guard is opt-in, so an unmarked manager — every one in the daemon —
    // behaves exactly as it did.  Without this the test above would pass on a
    // build where the flag was stuck on.
    runtime_manager mgr;
    CHECK_FALSE(mgr.is_replica());
    CHECK(mgr.create(runtime_server, "made"));
    REQUIRE(mgr.get("made") != nullptr);
    CHECK(mgr.get("made")->get_type() == runtime_server);
    CHECK(mgr.remove("made"));
}

TEST_CASE("a publish frame built in place is the frame built in three steps")
{
    const std::string big(70000, 'm');
    for (auto [c, ch, m] : { std::tuple<std::string_view, std::string_view, std::string_view>{ "cache", "news", "hello" },
                             { "", "", "" },
                             { "c", "ch with space\n", big } })
    {
        std::string in_place;
        worker_proto::append_publish_frame(in_place, c, ch, m);
        const std::string built = worker_proto::frame(worker_proto::frame_type::publish,
                                                      worker_proto::encode_publish(c, ch, m));
        CHECK(in_place == built);
        CHECK(in_place.size() == worker_proto::publish_frame_size(c, ch, m));
    }
}

TEST_CASE("a delta survives the wire with its rows and its departures")
{
    const auto out = worker_proto::encode_runtime_map_delta(
        { wire("api", "server", 1, 8080, 4, "", "web"), wire("kv", "cache", 0, 6379, 0, "api") }, { "gone", "old" });

    std::vector<worker_proto::runtime_wire> up;
    std::vector<std::string> removed;
    REQUIRE(worker_proto::decode_runtime_map_delta(out, up, removed));
    REQUIRE(up.size() == 2);
    CHECK(up[0] == wire("api", "server", 1, 8080, 4, "", "web"));
    CHECK(up[1] == wire("kv", "cache", 0, 6379, 0, "api"));
    CHECK(removed == std::vector<std::string>{ "gone", "old" });

    // A delta cut short is refused whole, never applied in part.
    CHECK_FALSE(worker_proto::decode_runtime_map_delta(std::string_view(out).substr(0, out.size() - 2), up, removed));
}

TEST_CASE("a delta moves only its rows and keeps every other object")
{
    runtime_manager mgr;
    mgr.mark_replica();
    mgr.install_replica({ entry("api", runtime_server, runtime_running, 8080, 1),
                          entry("kv", runtime_cache, runtime_running, 6379, 0),
                          entry("old", runtime_server, runtime_running, 8081, 0) });
    runtime_instance* api = mgr.get("api");
    runtime_instance* kv  = mgr.get("kv");

    REQUIRE(mgr.apply_replica_delta({ entry("kv", runtime_cache, runtime_stopped, 6379, 0),
                                      entry("new", runtime_client, runtime_running, 0, 1) },
                                    { "old" }));

    CHECK(mgr.get("api") == api);
    CHECK(api->get_state() == runtime_running);
    CHECK(api->reported_connection_count() == 1);
    CHECK(mgr.get("kv") == kv);
    CHECK(kv->get_state() == runtime_stopped);
    REQUIRE(mgr.get("new") != nullptr);
    CHECK(mgr.get("new")->get_type() == runtime_client);
    CHECK(mgr.get("old") == nullptr);
    {
        std::shared_lock lock(mgr.mutex);
        CHECK(mgr.list().size() == 3);
    }

    // A departure of a name this replica never had is nothing to do.
    CHECK(mgr.apply_replica_delta({}, { "never" }));
}

TEST_CASE("a snapshot of many runtimes keeps them all and drops the one left out")
{
    std::vector<runtime_manager::replica_entry> all;
    for (int i = 0; i < 300; ++i)
        all.push_back(entry("c" + std::to_string(i), runtime_client, runtime_running, 0, 1));
    runtime_manager mgr;
    mgr.mark_replica();
    REQUIRE(mgr.install_replica(all));

    all.erase(all.begin() + 150);
    REQUIRE(mgr.install_replica(all));
    CHECK(mgr.get("c150") == nullptr);
    CHECK(mgr.get("c149") != nullptr);
    CHECK(mgr.get("c299") != nullptr);
    std::shared_lock lock(mgr.mutex);
    CHECK(mgr.list().size() == 299);
}

TEST_CASE("a replica with a fill is filled at its first read, and once")
{
    runtime_manager mgr;
    mgr.mark_replica();
    int fills = 0;
    mgr.set_replica_fill([&] {
        ++fills;
        mgr.install_replica({ entry("api", runtime_server, runtime_running, 8080, 0),
                              entry("kv", runtime_cache, runtime_running, 0, 0) });
    });
    CHECK(mgr.replica_unfilled());
    CHECK(fills == 0);

    // A delta onto nothing is refused by the worker, which asks this before applying one.
    REQUIRE(mgr.get("api") != nullptr);
    CHECK(fills == 1);
    CHECK_FALSE(mgr.replica_unfilled());
    {
        std::shared_lock lock(mgr.mutex);
        CHECK(mgr.list().size() == 2);
    }
    CHECK(mgr.get_children("api").empty());
    CHECK(fills == 1);

    // Owed again, it fills at the next read and not before.
    mgr.replica_owe();
    CHECK(mgr.replica_unfilled());
    CHECK(fills == 1);
    CHECK(mgr.get("kv") != nullptr);
    CHECK(fills == 2);
}

TEST_CASE("a replica is filled by a read that holds the lock, before it is taken")
{
    runtime_manager mgr;
    mgr.mark_replica();
    int fills = 0;
    mgr.set_replica_fill([&] {
        ++fills;
        mgr.install_replica({ entry("api", runtime_server, runtime_running, 8080, 0) });
    });
    std::shared_lock lock(mgr.mutex);
    CHECK(fills == 1);
    CHECK(mgr.list().size() == 1);
}

TEST_CASE("the manager's own walks do not fill a replica")
{
    runtime_manager mgr;
    mgr.mark_replica();
    int fills = 0;
    mgr.set_replica_fill([&] { ++fills; });
    mgr.dispatch_publish("cache", "channel", "message");
    mgr.publish_endpoints();
    CHECK(mgr.retired_count() == 0);
    CHECK(fills == 0);
    CHECK(mgr.replica_unfilled());
}

TEST_CASE("a fill that fails leaves the replica owed and the read still answered, and the next read does not ask again at once")
{
    runtime_manager mgr;
    mgr.mark_replica();
    int fills = 0;
    mgr.set_replica_fill([&] { ++fills; });
    CHECK(mgr.get("api") == nullptr);
    CHECK(mgr.get("api") == nullptr);
    // A second apart, so a daemon slow to answer costs one wait and not one per read.
    CHECK(fills == 1);
    CHECK(mgr.replica_unfilled());
}

TEST_CASE("a manager with no fill is never owed")
{
    runtime_manager mgr;
    mgr.mark_replica();
    CHECK_FALSE(mgr.replica_unfilled());
    mgr.replica_owe();
    CHECK_FALSE(mgr.replica_unfilled());
}

TEST_CASE("a push carries its generation in front of the map")
{
    const std::string body = worker_proto::encode_runtime_map({ wire("api", "server", 1, 8080, 0, "") });
    const std::string payload = worker_proto::with_generation(42, body);
    uint64_t gen = 0;
    std::string_view rest;
    REQUIRE(worker_proto::split_generation(payload, gen, rest));
    CHECK(gen == 42);
    CHECK(rest == body);
    std::vector<worker_proto::runtime_wire> out;
    REQUIRE(worker_proto::decode_runtime_map(rest, out));
    CHECK(out.size() == 1);
    CHECK_FALSE(worker_proto::split_generation(std::string_view(payload.data(), 7), gen, rest));
}
