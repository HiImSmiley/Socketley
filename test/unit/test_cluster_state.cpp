#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "../../socketley/shared/byte_codec.h"
#include "../../socketley/shared/cluster_state.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

// The replicated desired state and the placement that writes it: what a command may say, what applying it does, what a snapshot keeps, and where the planner puts replicas.

namespace cl = socketley::cluster;

namespace {

struct prng
{
    uint64_t s;

    uint64_t next()
    {
        uint64_t z = (s += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }
    uint64_t below(uint64_t n) { return n ? next() % n : 0; }
};

cl::command declare(const std::string& name, uint32_t replicas, const std::string& type = "server",
                   const std::string& args = "-p 8080")
{
    cl::command c;
    c.op   = cl::op::create;
    c.name = name;
    c.sp   = cl::spec{type, args, replicas};
    return c;
}

cl::command drop(const std::string& name)
{
    cl::command c;
    c.op   = cl::op::remove;
    c.name = name;
    return c;
}

cl::command resize(const std::string& name, uint32_t replicas)
{
    cl::command c;
    c.op          = cl::op::scale;
    c.name        = name;
    c.sp.replicas = replicas;
    return c;
}

cl::command place(const std::string& name, cl::node_id n, bool on = true)
{
    cl::command c;
    c.op   = on ? cl::op::assign : cl::op::unassign;
    c.name = name;
    c.node = n;
    return c;
}

void apply_all(cl::state& s, const std::vector<cl::command>& v)
{
    for (const cl::command& c : v)
        s.apply(c);
}

// The invariants the state machine keeps whatever it is fed.
void check_invariants(const cl::state& s)
{
    for (const auto& [name, sp] : s.specs)
    {
        CHECK(s.owners.count(name) == 1);
        CHECK(cl::refusal(cl::command{cl::op::create, name, sp, 0}).empty());
    }
    for (const auto& [name, held] : s.owners)
    {
        CHECK(s.specs.count(name) == 1);
        CHECK(held.count(0) == 0);
    }
}

// A random walk over every operator command and the assignments a planner would make, from one seed.
std::vector<cl::command> random_history(uint64_t seed, size_t steps)
{
    prng r{seed};
    std::vector<cl::command> out;
    cl::state shadow;
    const std::vector<std::string> names = {"api", "web", "edge", "job", "a.b-c_d"};
    std::vector<cl::node_id> live = {11, 22, 33};
    for (size_t i = 0; i < steps; ++i)
    {
        const std::string& n = names[r.below(names.size())];
        cl::command c;
        switch (r.below(6))
        {
        case 0: c = declare(n, 1 + static_cast<uint32_t>(r.below(4)), r.below(2) ? "server" : "proxy"); break;
        case 1: c = drop(n); break;
        case 2: c = resize(n, 1 + static_cast<uint32_t>(r.below(5))); break;
        case 3:
            if (r.below(2) && live.size() > 1)
                live.erase(live.begin() + static_cast<long>(r.below(live.size())));
            else
                live.push_back(11 * (1 + r.below(6)));
            std::sort(live.begin(), live.end());
            live.erase(std::unique(live.begin(), live.end()), live.end());
            for (const cl::command& p : cl::plan(shadow, live))
            {
                shadow.apply(p);
                out.push_back(p);
            }
            continue;
        default: c = place(n, 11 * (1 + r.below(6)), r.below(3) != 0); break;
        }
        shadow.apply(c);
        out.push_back(c);
    }
    return out;
}

}   // namespace

// ─── commands ───

TEST_CASE("every command survives a round trip and nothing else decodes")
{
    const std::vector<cl::command> all = {declare("api", 2), drop("api"), resize("api", 3), place("api", 77),
                                          place("api", 77, false)};
    for (const cl::command& c : all)
    {
        const std::string bytes = cl::encode(c);
        CHECK(cl::is_command(bytes));
        cl::command back;
        REQUIRE(cl::decode(bytes, back));
        CHECK(back == c);
        // A torn frame is never taken for a shorter command.
        for (size_t cut = 0; cut < bytes.size(); ++cut)
        {
            cl::command t;
            CHECK_FALSE(cl::decode(std::string_view(bytes).substr(0, cut), t));
        }
        cl::command t;
        CHECK_FALSE(cl::decode(bytes + std::string(1, '\0'), t));
    }
}

TEST_CASE("a command the operator may not give is refused, and decode refuses it too")
{
    struct row { cl::command c; const char* needle; };
    const std::vector<row> rows = {
        {declare("", 1), "invalid runtime name"},
        {declare(".hidden", 1), "invalid runtime name"},
        {declare("a..b", 1), "invalid runtime name"},
        {declare("-flag", 1), "invalid runtime name"},
        {declare("sp ace", 1), "invalid runtime name"},
        {declare(std::string(129, 'x'), 1), "invalid runtime name"},
        {declare("db", 1, "cache"), "cache"},
        {declare("db", 1, "nonsense"), "only a server"},
        {declare("api", 0), "replicas must be"},
        {declare("api", cl::max_replicas + 1), "replicas must be"},
        {resize("api", 0), "replicas must be"},
        {declare("api", 1, "server", "-p 80 --test"), "--test"},
        {declare("api", 1, "server", "-p 80\n-p 81"), "control character"},
        {declare("api", 1, "server", std::string(cl::max_args + 1, 'x')), "longer than"},
        {place("api", 0), "node 0"},
    };
    for (const row& r : rows)
    {
        const std::string why = cl::refusal(r.c);
        INFO(r.needle);
        CHECK(why.find(r.needle) != std::string::npos);
        // A node never applies what another would have refused, so the bytes are refused on receipt as well.
        cl::command back;
        CHECK_FALSE(cl::decode(cl::encode(r.c), back));
    }
}

TEST_CASE("{node} becomes the executing node's name, made safe for a command line")
{
    CHECK(cl::expand_args("--listen unix:/run/{node}.sock", "n1") == "--listen unix:/run/n1.sock");
    CHECK(cl::expand_args("{node} {node}", "a b") == "a_b a_b");
    CHECK(cl::expand_args("-p 80", "n1") == "-p 80");
    CHECK(cl::expand_args("{nod", "n1") == "{nod");
    CHECK(cl::expand_args("x{node}", "a;b\n") == "xa_b_");
}

// ─── the state machine ───

TEST_CASE("apply: create, scale, assign and remove")
{
    cl::state s;
    CHECK(s.apply(declare("api", 2)));
    CHECK_FALSE(s.apply(declare("api", 5)));
    CHECK(s.specs.at("api").replicas == 2);
    CHECK(s.missing("api") == 2);

    CHECK(s.apply(place("api", 1)));
    CHECK_FALSE(s.apply(place("api", 1)));
    CHECK(s.apply(place("api", 2)));
    // The replicas are full, so a racing plan's assignment loses.
    CHECK_FALSE(s.apply(place("api", 3)));
    CHECK(s.placed("api") == 2);
    CHECK(s.missing("api") == 0);
    CHECK(s.load(1) == 1);

    CHECK_FALSE(s.apply(place("ghost", 1)));
    CHECK(s.apply(place("api", 1, false)));
    CHECK_FALSE(s.apply(place("api", 1, false)));

    CHECK(s.apply(resize("api", 3)));
    CHECK_FALSE(s.apply(resize("api", 3)));
    CHECK_FALSE(s.apply(resize("ghost", 3)));

    CHECK(s.apply(drop("api")));
    CHECK_FALSE(s.apply(drop("api")));
    CHECK(s == cl::state{});
}

TEST_CASE("conflict names a command that would change nothing")
{
    cl::state s;
    s.apply(declare("api", 2));
    CHECK(cl::conflict(s, declare("api", 1)).find("already exists") != std::string::npos);
    CHECK(cl::conflict(s, declare("web", 1)).empty());
    CHECK(cl::conflict(s, drop("ghost")).find("not found") != std::string::npos);
    CHECK(cl::conflict(s, drop("api")).empty());
    CHECK(cl::conflict(s, resize("api", 2)).find("already has 2") != std::string::npos);
    CHECK(cl::conflict(s, resize("api", 3)).empty());
}

TEST_CASE("two states that applied the same history are equal, and keep the invariants")
{
    for (uint64_t seed = 1; seed <= 200; ++seed)
    {
        const std::vector<cl::command> h = random_history(seed, 120);
        cl::state a, b;
        apply_all(a, h);
        apply_all(b, h);
        CHECK(a == b);
        check_invariants(a);
    }
}

// ─── snapshots ───

TEST_CASE("a snapshot round-trips, and replaying the log from it gives the state the whole log gives")
{
    for (uint64_t seed = 1; seed <= 100; ++seed)
    {
        const std::vector<cl::command> h = random_history(seed, 80);
        cl::state whole;
        apply_all(whole, h);

        // Compaction may cut the log anywhere, and the node that restarts from that cut must agree with the one that never did.
        for (size_t cut : {size_t{0}, h.size() / 3, h.size() / 2, h.size() - 1, h.size()})
        {
            cl::state head;
            apply_all(head, std::vector<cl::command>(h.begin(), h.begin() + static_cast<long>(cut)));
            const std::string bytes = cl::encode(head);
            cl::state restored;
            REQUIRE(cl::decode(bytes, restored));
            CHECK(restored == head);
            CHECK(cl::encode(restored) == bytes);
            apply_all(restored, std::vector<cl::command>(h.begin() + static_cast<long>(cut), h.end()));
            CHECK(restored == whole);
        }
    }
}

TEST_CASE("a snapshot that is not exactly what encode wrote is refused")
{
    cl::state s;
    s.apply(declare("api", 2, "server", "-p 80"));
    s.apply(place("api", 5));
    s.apply(declare("web", 1, "proxy", "--backend 127.0.0.1:1"));
    const std::string bytes = cl::encode(s);

    cl::state t;
    REQUIRE(cl::decode(bytes, t));
    for (size_t cut = 0; cut < bytes.size(); ++cut)
        CHECK_FALSE(cl::decode(std::string_view(bytes).substr(0, cut), t));
    CHECK_FALSE(cl::decode(bytes + "x", t));

    std::string wrong_version = bytes;
    wrong_version[1] = 9;
    CHECK_FALSE(cl::decode(wrong_version, t));

    // A name that would be refused as a command is refused inside a snapshot.
    cl::state bad;
    bad.specs["a b"]  = cl::spec{"server", "", 1};
    bad.owners["a b"] = {};
    CHECK_FALSE(cl::decode(cl::encode(bad), t));

    // Node 0 is not a node, and a node held twice is not a set.
    cl::state zero;
    zero.specs["x"]  = cl::spec{"server", "", 2};
    zero.owners["x"] = {0};
    CHECK_FALSE(cl::decode(cl::encode(zero), t));
    CHECK(cl::decode(cl::encode(cl::state{}), t));
    CHECK(t == cl::state{});

    // One state has one encoding, so owners and runtimes written out of order or twice are not a state.
    auto raw = [](const std::vector<std::pair<std::string, std::vector<uint64_t>>>& rows)
    {
        socketley::bytes::writer w;
        w.u8('S');
        w.u8(1);
        w.u32(static_cast<uint32_t>(rows.size()));
        for (const auto& [name, owners] : rows)
        {
            w.bytes(name);
            w.bytes("server");
            w.bytes("");
            w.u32(3);
            w.ids(owners);
        }
        return w.take();
    };
    CHECK(cl::decode(raw({{"a", {1, 2}}, {"b", {}}}), t));
    CHECK_FALSE(cl::decode(raw({{"a", {2, 1}}}), t));
    CHECK_FALSE(cl::decode(raw({{"a", {1, 1}}}), t));
    CHECK_FALSE(cl::decode(raw({{"b", {}}, {"a", {}}}), t));
    CHECK_FALSE(cl::decode(raw({{"a", {}}, {"a", {}}}), t));
}

// ─── placement ───

TEST_CASE("placement puts the replicas of one runtime on distinct nodes, spread by count")
{
    cl::state s;
    apply_all(s, {declare("a", 2), declare("b", 2), declare("c", 2)});
    const std::vector<cl::node_id> live = {30, 10, 20};
    apply_all(s, cl::plan(s, live));
    check_invariants(s);
    for (const auto& [name, held] : s.owners)
        CHECK(held.size() == 2);
    // Six replicas over three nodes is two each: the spread is by how many a node holds.
    for (cl::node_id n : live)
        CHECK(s.load(n) == 2);
    CHECK(cl::plan(s, live).empty());
}

TEST_CASE("placement is a function of the state and the set of live nodes, not of the order they are listed")
{
    for (uint64_t seed = 1; seed <= 100; ++seed)
    {
        prng r{seed};
        cl::state s;
        for (uint32_t i = 0; i < 6; ++i)
            s.apply(declare("r" + std::to_string(i), 1 + static_cast<uint32_t>(r.below(3))));
        std::vector<cl::node_id> live = {5, 6, 7, 8, 9};
        const std::vector<cl::command> first = cl::plan(s, live);
        for (int shuffle = 0; shuffle < 5; ++shuffle)
        {
            for (size_t i = live.size(); i > 1; --i)
                std::swap(live[i - 1], live[r.below(i)]);
            CHECK(cl::plan(s, live) == first);
        }
        std::vector<cl::node_id> dup = live;
        dup.insert(dup.end(), live.begin(), live.end());
        CHECK(cl::plan(s, dup) == first);
    }
}

TEST_CASE("a replica whose node is gone moves to a live node that does not already hold the runtime")
{
    cl::state s;
    apply_all(s, {declare("api", 2)});
    apply_all(s, cl::plan(s, {1, 2, 3}));
    REQUIRE(s.placed("api") == 2);
    const std::set<cl::node_id> before = s.owners.at("api");
    REQUIRE(before == std::set<cl::node_id>{1, 2});

    // Node 2 dies: its replica moves to the one node that holds nothing, and the survivor stays where it is.
    apply_all(s, cl::plan(s, {1, 3}));
    CHECK(s.owners.at("api") == std::set<cl::node_id>{1, 3});
    CHECK(cl::plan(s, {1, 3}).empty());

    // Node 2 comes back and takes nothing: what moved away stays away.
    CHECK(cl::plan(s, {1, 2, 3}).empty());
}

TEST_CASE("more replicas than nodes runs what fits and reports the rest")
{
    cl::state s;
    apply_all(s, {declare("api", 3)});
    apply_all(s, cl::plan(s, {1, 2}));
    CHECK(s.placed("api") == 2);
    CHECK(s.missing("api") == 1);
    // A third node arrives and the shortfall is filled, and nothing else moves.
    apply_all(s, cl::plan(s, {1, 2, 3}));
    CHECK(s.missing("api") == 0);
    CHECK(s.owners.at("api").count(1) == 1);
    CHECK(s.owners.at("api").count(2) == 1);
    // With no node at all nothing is assigned, and nothing is invented.
    cl::state empty;
    apply_all(empty, {declare("api", 1)});
    CHECK(cl::plan(empty, {}).empty());
}

TEST_CASE("scaling down takes the replica from the most loaded node")
{
    cl::state s;
    apply_all(s, {declare("busy", 3), declare("api", 3)});
    apply_all(s, cl::plan(s, {1, 2, 3}));
    apply_all(s, {declare("extra", 1)});
    apply_all(s, cl::plan(s, {1, 2, 3}));
    // Node 1 holds three, the others two.
    REQUIRE(s.load(1) == 3);
    apply_all(s, {resize("api", 2)});
    apply_all(s, cl::plan(s, {1, 2, 3}));
    CHECK(s.placed("api") == 2);
    CHECK(s.owners.at("api").count(1) == 0);
    CHECK(cl::plan(s, {1, 2, 3}).empty());
}

TEST_CASE("a node that is no longer a member holds nothing after the next plan")
{
    cl::state s;
    apply_all(s, {declare("a", 1), declare("b", 1)});
    apply_all(s, {place("a", 99), place("b", 1)});
    apply_all(s, cl::plan(s, {1, 2}));
    check_invariants(s);
    CHECK(s.owners.at("a") == std::set<cl::node_id>{2});
    CHECK(s.owners.at("b") == std::set<cl::node_id>{1});
}

TEST_CASE("planning to convergence: nothing is left on a dead node, nothing over its replicas, and a second plan is empty")
{
    for (uint64_t seed = 1; seed <= 300; ++seed)
    {
        prng r{seed};
        cl::state s;
        std::vector<cl::node_id> live;
        for (cl::node_id n = 1; n <= 5; ++n)
            live.push_back(n);
        for (int step = 0; step < 40; ++step)
        {
            switch (r.below(4))
            {
            case 0: s.apply(declare("r" + std::to_string(r.below(6)), 1 + static_cast<uint32_t>(r.below(4)))); break;
            case 1: s.apply(drop("r" + std::to_string(r.below(6)))); break;
            case 2: s.apply(resize("r" + std::to_string(r.below(6)), 1 + static_cast<uint32_t>(r.below(4)))); break;
            default:
                if (r.below(2) && live.size() > 1)
                    live.erase(live.begin() + static_cast<long>(r.below(live.size())));
                else if (live.size() < 5)
                    live.push_back(1 + r.below(5));
                std::sort(live.begin(), live.end());
                live.erase(std::unique(live.begin(), live.end()), live.end());
                break;
            }
            apply_all(s, cl::plan(s, live));
            check_invariants(s);
            const std::set<cl::node_id> alive(live.begin(), live.end());
            for (const auto& [name, held] : s.owners)
            {
                for (cl::node_id n : held)
                    CHECK(alive.count(n) == 1);
                CHECK(held.size() == std::min<size_t>(s.specs.at(name).replicas, alive.size()));
            }
            CHECK(cl::plan(s, live).empty());
        }
    }
}
