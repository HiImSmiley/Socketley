#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "../../socketley/shared/byte_codec.h"
#include "../../socketley/shared/cluster_state.h"
#include "../../socketley/shared/replica_role.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

// The replicated desired state and the placement that writes it: what a command may say, what applying it does, what
// a snapshot keeps, and where the planner puts replicas.

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
                   const std::vector<std::string>& args = {"-p", "8080"})
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

cl::command promote(const std::string& name, cl::node_id n, uint64_t incarnation, uint64_t epoch)
{
    cl::command c;
    c.op          = cl::op::promote;
    c.name        = name;
    c.node        = n;
    c.incarnation = incarnation;
    c.epoch       = epoch;
    return c;
}

// A cache as an operator declares it.
cl::command cache(const std::string& name, uint32_t replicas)
{
    return declare(name, replicas, "cache", {"-p", "6300"});
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
    // Only a cache has a primary, it is one of the owners, and a runtime nobody leads has no incarnation either.
    for (const auto& [name, lead] : s.primaries)
    {
        REQUIRE(s.specs.count(name) == 1);
        CHECK(s.specs.at(name).type == "cache");
        if (lead.node != 0)
        {
            CHECK(s.owners.at(name).count(lead.node) == 1);
            CHECK(lead.incarnation != 0);
            CHECK(lead.epoch != 0);
        }
        else
        {
            CHECK(lead.incarnation == 0);
        }
    }
    for (const auto& [name, sp] : s.specs)
        CHECK((s.primaries.count(name) == 1) == (sp.type == "cache"));
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
                                          place("api", 77, false), cache("db", 3), promote("db", 77, 0x1234567890ull, 4)};
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
        {declare("db", 1, "cache", {"--maxmemory", "1M"}), "needs -p"},
        {declare("db", 1, "cache", {"-p"}), "needs -p"},
        {declare("db", 1, "cache", {"-p", "80", "--replicate", "1.2.3.4:5"}), "the cluster's to set"},
        {declare("db", 1, "cache", {"-p", "80", "--cluster-replica", "7"}), "the cluster's to set"},
        {declare("db", 1, "cache", {"-p", "80", "--listen", "unix:/x"}), "unix socket"},
        {declare("db", 1, "cache", {"-p", "80", "--shards", "2"}), "sharded"},
        {declare("db", 1, "nonsense"), "only a server"},
        {promote("db", 0, 7, 1), "node 0"},
        {promote("db", 3, 0, 1), "incarnation 0"},
        {promote("db", 3, 7, 0), "epoch 0"},
        {declare("api", 0), "replicas must be"},
        {declare("api", cl::max_replicas + 1), "replicas must be"},
        {resize("api", 0), "replicas must be"},
        {declare("api", 1, "server", {"-p", "80", "--test"}), "--test"},
        {declare("api", 1, "server", {"-p", "80\n81"}), "control character"},
        {declare("api", 1, "server", {std::string(cl::max_args + 1, 'x')}), "longer than"},
        {declare("api", 1, "server", std::vector<std::string>(cl::max_arg_count + 1, "-x")), "more than"},
        {declare("api", 1, "server", {"-p", ""}), "empty"},
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

TEST_CASE("a flag with a space in it is one argument through the command codec, the snapshot, and the command line")
{
    const std::vector<std::string> args = {"--http", "/srv/my www", "--listen", "unix:/run/a b.sock", "50%", "ünï"};
    cl::command c = declare("api", 2, "server", args);
    cl::command back;
    REQUIRE(cl::decode(cl::encode(c), back));
    CHECK(back.sp.args == args);

    cl::state s;
    s.apply(c);
    cl::state t;
    REQUIRE(cl::decode(cl::encode(s), t));
    CHECK(t.specs.at("api").args == args);

    // On the command line each word is quoted, so a space never splits it and no word is empty.
    for (const std::string& a : args)
    {
        const std::string word = cl::quote_arg(a);
        CHECK(word.find_first_of(" \t\n") == std::string::npos);
        std::string round;
        REQUIRE(cl::unquote_arg(word, round));
        CHECK(round == a);
    }
    std::string sink;
    CHECK(cl::quote_arg("a\tb\nc") == "a%09b%0Ac");
    CHECK_FALSE(cl::unquote_arg("100%", sink));
    CHECK_FALSE(cl::unquote_arg("a%2", sink));
    CHECK_FALSE(cl::unquote_arg("a%zz", sink));
    CHECK(cl::unquote_arg("a%20b", sink));
    CHECK(sink == "a b");
}

TEST_CASE("{node} becomes the executing node's name, made safe for a command line")
{
    CHECK(cl::expand_args("--listen unix:/run/{node}.sock", "n1") == "--listen unix:/run/n1.sock");
    CHECK(cl::expand_args("{node} {node}", "a b") == "a_b a_b");
    CHECK(cl::expand_args("-p", "n1") == "-p");
    CHECK(cl::expand_args(std::vector<std::string>{"--http", "/srv/{node} www"}, "n1")
          == std::vector<std::string>{"--http", "/srv/n1 www"});
    CHECK(cl::expand_args("{nod", "n1") == "{nod");
    CHECK(cl::expand_args("x{node}", "a;b\n") == "xa_b_");
}

TEST_CASE("two nodes whose names make one {node} label are one name")
{
    const std::map<cl::node_id, std::string> names = {{1, "a"}, {2, "b c"}, {3, "d"}};
    // The same name held by another node, and one that only becomes it once made safe for a command line.
    CHECK(cl::label_holder(names, 9, "a") == 1);
    CHECK(cl::label_holder(names, 9, "b_c") == 2);
    CHECK(cl::label_holder(names, 9, "b?c") == 2);
    // A node is not its own duplicate, so a restart under the same name is fine, and a name nobody holds is free.
    CHECK(cl::label_holder(names, 2, "b c") == 0);
    CHECK(cl::label_holder(names, 9, "b-c") == 0);
    CHECK(cl::label_holder({}, 9, "a") == 0);
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
    s.apply(declare("api", 2, "server", {"-p", "80"}));
    s.apply(place("api", 5));
    s.apply(declare("web", 1, "proxy", {"--backend", "127.0.0.1:1"}));
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
    bad.specs["a b"]  = cl::spec{"server", {}, 1};
    bad.owners["a b"] = {};
    CHECK_FALSE(cl::decode(cl::encode(bad), t));

    // Node 0 is not a node, and a node held twice is not a set.
    cl::state zero;
    zero.specs["x"]  = cl::spec{"server", {}, 2};
    zero.owners["x"] = {0};
    CHECK_FALSE(cl::decode(cl::encode(zero), t));
    CHECK(cl::decode(cl::encode(cl::state{}), t));
    CHECK(t == cl::state{});

    // One state has one encoding, so owners and runtimes written out of order or twice are not a state.
    auto raw = [](const std::vector<std::pair<std::string, std::vector<uint64_t>>>& rows)
    {
        socketley::bytes::writer w;
        w.u8('S');
        w.u8(2);
        w.u32(static_cast<uint32_t>(rows.size()));
        for (const auto& [name, owners] : rows)
        {
            w.bytes(name);
            w.bytes("server");
            w.bytes("");
            w.u32(3);
            w.ids(owners);
            w.u64(0);
            w.u64(0);
            w.u64(0);
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

// ─── the worker's half of a cache replica ───

namespace {

cl::replica_order ordered(cl::replica_mode m, uint64_t inc, uint64_t epoch, uint32_t valid_ms, const std::string& target = {})
{
    return cl::replica_order{m, inc, epoch, valid_ms, target};
}

}   // namespace

TEST_CASE("an order round-trips, and one that contradicts itself or is torn is refused")
{
    for (const cl::replica_order& o : {ordered(cl::replica_mode::fenced, 7, 0, 0), ordered(cl::replica_mode::primary, 7, 3, 2999),
                                       ordered(cl::replica_mode::follower, 7, 3, 2999, "10.0.0.2:6301")})
    {
        const std::string bytes = cl::encode(o);
        cl::replica_order back;
        REQUIRE(cl::decode(bytes, back));
        CHECK(back == o);
        for (size_t cut = 0; cut < bytes.size(); ++cut)
            CHECK_FALSE(cl::decode(std::string_view(bytes).substr(0, cut), back));
        CHECK_FALSE(cl::decode(bytes + "x", back));
    }
    cl::replica_order back;
    // A follower has somebody to follow and a primary has nobody.
    CHECK_FALSE(cl::decode(cl::encode(ordered(cl::replica_mode::follower, 7, 3, 1000)), back));
    CHECK_FALSE(cl::decode(cl::encode(ordered(cl::replica_mode::primary, 7, 3, 1000, "10.0.0.2:6301")), back));
    std::string wrong_mode = cl::encode(ordered(cl::replica_mode::primary, 7, 3, 1000));
    wrong_mode[1] = 9;
    CHECK_FALSE(cl::decode(wrong_mode, back));
}

TEST_CASE("a replica is fenced until it is told, and fences itself when the daemon stops telling it")
{
    cl::replica_role role(7);
    CHECK(role.mode(0) == cl::replica_mode::fenced);
    CHECK(role.mode(1000) == cl::replica_mode::fenced);

    const auto lead = ordered(cl::replica_mode::primary, 7, 1, 3000);
    CHECK(role.order(lead, 1000).mode == cl::replica_mode::primary);
    CHECK(role.mode(3999) == cl::replica_mode::primary);
    // The order stands for what the lease had left when it was sent, and not a millisecond longer.
    CHECK(role.mode(4000) == cl::replica_mode::fenced);
    CHECK(role.left_ms(3000) == 1000);
    CHECK(role.left_ms(4000) == 0);

    // Each tick renews it, so a daemon that is running never lets it lapse, and one that is not does.
    for (uint64_t t = 1100; t < 6000; t += 100)
        role.order(ordered(cl::replica_mode::primary, 7, 1, 3000), t);
    CHECK(role.mode(5900 + 2999) == cl::replica_mode::primary);
    CHECK(role.mode(5900 + 3000) == cl::replica_mode::fenced);

    // A renewal with no time left is a fence, and so is a fenced order.
    CHECK(role.order(ordered(cl::replica_mode::primary, 7, 1, 0), 7000).mode == cl::replica_mode::fenced);
    CHECK(role.order(lead, 7100).mode == cl::replica_mode::primary);
    CHECK(role.order(ordered(cl::replica_mode::fenced, 7, 1, 3000), 7200).mode == cl::replica_mode::fenced);
    CHECK(role.mode(7201) == cl::replica_mode::fenced);
}

TEST_CASE("an order for another incarnation reaches nobody and fences the one it finds")
{
    cl::replica_role role(7);
    role.order(ordered(cl::replica_mode::primary, 7, 1, 3000), 1000);
    REQUIRE(role.mode(1001) == cl::replica_mode::primary);
    CHECK(role.order(ordered(cl::replica_mode::primary, 8, 2, 3000), 1002).mode == cl::replica_mode::fenced);
    CHECK(role.mode(1003) == cl::replica_mode::fenced);
    CHECK(role.epoch() == 1);
}

TEST_CASE("a follower's copy is nothing while a dump arrives, and is the primary's epoch and offset once it ends")
{
    cl::replica_role f(7);
    auto follow = ordered(cl::replica_mode::follower, 7, 4, 3000, "10.0.0.2:6301");
    auto e = f.order(follow, 1000);
    CHECK(e.mode == cl::replica_mode::follower);
    CHECK(e.retarget);
    CHECK(f.epoch() == 0);
    CHECK(f.offset() == 0);

    f.sync_started();
    CHECK(f.syncing());
    f.sync_done(900);
    CHECK_FALSE(f.syncing());
    CHECK(f.epoch() == 4);
    CHECK(f.offset() == 900);
    for (int i = 0; i < 25; ++i)
        f.record();
    CHECK(f.offset() == 925);

    // The same order again is not a reason to dial again, and a different primary or a newer epoch is.
    CHECK_FALSE(f.order(follow, 1100).retarget);
    CHECK(f.order(ordered(cl::replica_mode::follower, 7, 4, 3000, "10.0.0.3:6301"), 1200).retarget);
    CHECK(f.order(ordered(cl::replica_mode::follower, 7, 5, 3000, "10.0.0.3:6301"), 1300).retarget);
    CHECK_FALSE(f.order(ordered(cl::replica_mode::follower, 7, 5, 3000, "10.0.0.3:6301"), 1400).retarget);
    // A spell without a lease is not a reason to sync again: the link stood through it, and the same order after it changes nothing.
    CHECK(f.order(ordered(cl::replica_mode::fenced, 7, 5, 0), 1250).mode == cl::replica_mode::fenced);
    CHECK(f.following());
    CHECK_FALSE(f.order(ordered(cl::replica_mode::follower, 7, 5, 3000, "10.0.0.3:6301"), 1260).retarget);
    // A copy is still the old primary's until the new dump lands, and empty while it is landing.
    CHECK(f.epoch() == 4);
    CHECK(f.offset() == 925);
    f.sync_started();
    CHECK(f.epoch() == 0);
    CHECK(f.offset() == 0);
    f.sync_done(31);
    CHECK(f.epoch() == 5);
    CHECK(f.offset() == 31);
}

TEST_CASE("a follower promoted keeps the offset it had reached and leads from it in the new epoch")
{
    cl::replica_role r(7);
    r.order(ordered(cl::replica_mode::follower, 7, 4, 3000, "10.0.0.2:6301"), 1000);
    r.sync_started();
    r.sync_done(900);
    for (int i = 0; i < 25; ++i)
        r.record();
    CHECK(r.order(ordered(cl::replica_mode::primary, 7, 5, 3000), 2000).mode == cl::replica_mode::primary);
    CHECK(r.epoch() == 5);
    CHECK(r.offset() == 925);
    r.record();
    CHECK(r.offset() == 926);

    // And a primary demoted keeps what it wrote until the primary that replaced it sends a dump, so a copy that
    // outranks nothing is not mistaken for one that does.
    CHECK(r.order(ordered(cl::replica_mode::follower, 7, 6, 3000, "10.0.0.3:6301"), 3000).retarget);
    CHECK(r.epoch() == 5);
    CHECK(r.offset() == 926);
}

TEST_CASE("a fresh replica promoted into the first epoch leads an empty copy")
{
    cl::replica_role r(7);
    CHECK(r.order(ordered(cl::replica_mode::primary, 7, 1, 3000), 1000).mode == cl::replica_mode::primary);
    CHECK(r.epoch() == 1);
    CHECK(r.offset() == 0);
}

TEST_CASE("the report lines survive the stats text they travel in, and a text that lacks one says nothing")
{
    cl::replica_role r(0xFFFFFFFFFFFFFFF1ull);
    r.order(ordered(cl::replica_mode::primary, 0xFFFFFFFFFFFFFFF1ull, 12, 3000), 1000);
    for (int i = 0; i < 5; ++i)
        r.record();
    const std::string lines = cl::report_lines(r, 1500);
    const std::string stats = "keys:3\nmode:1\n" + lines + "followers:2\n";
    const auto rep = cl::parse_report(stats, "db");
    REQUIRE(rep.has_value());
    CHECK(rep->name == "db");
    CHECK(rep->incarnation == 0xFFFFFFFFFFFFFFF1ull);
    CHECK(rep->epoch == 12);
    CHECK(rep->offset == 5);
    CHECK(rep->primary);
    // Fenced by lapse, it says so.
    CHECK_FALSE(cl::parse_report("x:1\n" + cl::report_lines(r, 9000), "db")->primary);

    CHECK_FALSE(cl::parse_report("keys:3\n", "db").has_value());
    CHECK_FALSE(cl::parse_report("cluster_incarnation:7\ncluster_epoch:1\ncluster_offset:2\n", "db").has_value());
    CHECK_FALSE(cl::parse_report("cluster_incarnation:0\ncluster_epoch:1\ncluster_offset:2\ncluster_role:fenced\n", "db").has_value());
    CHECK_FALSE(cl::parse_report("cluster_incarnation:7x\ncluster_epoch:1\ncluster_offset:2\ncluster_role:fenced\n", "db").has_value());
}

// ─── a cache and its primary ───

TEST_CASE("a cache has a primary record from the moment it is declared, and no other type has one")
{
    cl::state s;
    apply_all(s, {declare("api", 2), cache("db", 3)});
    CHECK(s.primaries.count("db") == 1);
    CHECK(s.primaries.count("api") == 0);
    CHECK(s.primaries.at("db") == cl::primary_record{});
    check_invariants(s);
    CHECK(s.apply(drop("db")));
    CHECK(s.primaries.empty());
}

TEST_CASE("a promotion names the next epoch and a node that holds a replica, and the second of two racing plans loses")
{
    cl::state s;
    apply_all(s, {cache("db", 3), place("db", 1), place("db", 2), place("db", 3)});

    // A node that holds no replica, a stale epoch and a skipped one change nothing.
    CHECK_FALSE(s.apply(promote("db", 9, 100, 1)));
    CHECK_FALSE(s.apply(promote("db", 1, 100, 2)));
    CHECK_FALSE(s.apply(promote("ghost", 1, 100, 1)));
    CHECK(s.primaries.at("db") == cl::primary_record{});

    CHECK(s.apply(promote("db", 1, 100, 1)));
    CHECK(s.primaries.at("db") == cl::primary_record{1, 100, 1});
    // Two leaders that both saw epoch 1 propose epoch 2 for different replicas: the first applied wins on every node alike.
    CHECK(s.apply(promote("db", 2, 200, 2)));
    CHECK_FALSE(s.apply(promote("db", 3, 300, 2)));
    CHECK(s.primaries.at("db") == cl::primary_record{2, 200, 2});
    // A repeat of the applied promotion is not a second promotion.
    CHECK_FALSE(s.apply(promote("db", 2, 200, 2)));
    check_invariants(s);
}

TEST_CASE("a primary that loses its replica leads nothing, and the next promotion is still above its epoch")
{
    cl::state s;
    apply_all(s, {cache("db", 2), place("db", 1), place("db", 2), promote("db", 1, 100, 1)});
    // The follower's departure leaves the primary alone.
    CHECK(s.apply(place("db", 2, false)));
    CHECK(s.primaries.at("db") == cl::primary_record{1, 100, 1});
    // The primary's own does not.
    CHECK(s.apply(place("db", 1, false)));
    CHECK(s.primaries.at("db") == cl::primary_record{0, 0, 1});
    check_invariants(s);
    apply_all(s, {place("db", 2), promote("db", 2, 200, 1)});
    CHECK(s.primaries.at("db") == cl::primary_record{0, 0, 1});
    CHECK(s.apply(promote("db", 2, 200, 2)));
    CHECK(s.primaries.at("db") == cl::primary_record{2, 200, 2});
}

TEST_CASE("a snapshot keeps the primary, and refuses a primary that is not one of the owners")
{
    cl::state s;
    apply_all(s, {cache("db", 2), place("db", 4), place("db", 5), promote("db", 5, 0xABCDEF0123ull, 1)});
    const std::string bytes = cl::encode(s);
    cl::state t;
    REQUIRE(cl::decode(bytes, t));
    CHECK(t == s);
    CHECK(cl::encode(t) == bytes);
    for (size_t cut = 0; cut < bytes.size(); ++cut)
        CHECK_FALSE(cl::decode(std::string_view(bytes).substr(0, cut), t));

    cl::state stranger = s;
    stranger.primaries["db"] = cl::primary_record{6, 1, 1};
    CHECK_FALSE(cl::decode(cl::encode(stranger), t));
    cl::state nameless = s;
    nameless.primaries["db"] = cl::primary_record{4, 0, 1};
    CHECK_FALSE(cl::decode(cl::encode(nameless), t));
    cl::state epochless = s;
    epochless.primaries["db"] = cl::primary_record{4, 1, 0};
    CHECK_FALSE(cl::decode(cl::encode(epochless), t));
    cl::state ghost = s;
    ghost.primaries["db"] = cl::primary_record{0, 9, 3};
    CHECK_FALSE(cl::decode(cl::encode(ghost), t));
    // A server that is somebody's primary is not a state.
    cl::state sv;
    apply_all(sv, {declare("api", 1), place("api", 4)});
    REQUIRE(cl::decode(cl::encode(sv), t));
    sv.primaries["api"] = cl::primary_record{4, 1, 1};
    CHECK_FALSE(cl::decode(cl::encode(sv), t));
}

TEST_CASE("the most up-to-date copy is the highest epoch, then the highest offset, then the lowest node")
{
    using c = cl::candidate;
    CHECK_FALSE(cl::best_candidate({}).has_value());
    // The offset decides among copies of one primary's stream.
    CHECK(cl::best_candidate({c{1, 10, 3, 500}, c{2, 20, 3, 900}, c{3, 30, 3, 700}})->node == 2);
    // An epoch outranks any offset: offsets of two epochs are not on one scale, and a copy of the newer stream is the newer.
    CHECK(cl::best_candidate({c{1, 10, 3, 9000}, c{2, 20, 4, 5}})->node == 2);
    // A copy that is empty comes last, and a tie is the lowest node.
    CHECK(cl::best_candidate({c{1, 10, 0, 0}, c{2, 20, 2, 1}})->node == 2);
    CHECK(cl::best_candidate({c{5, 10, 2, 40}, c{3, 20, 2, 40}, c{4, 30, 2, 40}})->node == 3);
    // The order they are listed in decides nothing.
    CHECK(cl::best_candidate({c{4, 30, 2, 40}, c{3, 20, 2, 40}, c{5, 10, 2, 40}})->node == 3);
    CHECK(cl::best_candidate({c{2, 20, 2, 41}, c{3, 20, 2, 40}})->incarnation == 20);
}

TEST_CASE("followers dial the primary on its own -p, at the host its node is reached at")
{
    CHECK(cl::replica_address({"-p", "6301", "--maxmemory", "1M"}, "10.0.0.7") == "10.0.0.7:6301");
    CHECK(cl::replica_address({"--maxmemory", "1M", "-p", "6302"}, "127.0.0.1") == "127.0.0.1:6302");
    CHECK(cl::replica_address({"--maxmemory", "1M"}, "127.0.0.1").empty());
    CHECK(cl::replica_address({"-p"}, "127.0.0.1").empty());
    CHECK(cl::replica_address(cl::expand_args(std::vector<std::string>{"-p", "630{node}"}, "3"), "127.0.0.1") == "127.0.0.1:6303");
}

TEST_CASE("scaling a cache down never takes its primary")
{
    for (cl::node_id lead : {cl::node_id{1}, cl::node_id{2}, cl::node_id{3}})
    {
        cl::state s;
        apply_all(s, {cache("db", 3)});
        apply_all(s, cl::plan(s, {1, 2, 3}));
        REQUIRE(s.placed("db") == 3);
        REQUIRE(s.apply(promote("db", lead, 50 + lead, 1)));
        // Node 3 would give the replica up on load, and the highest id on a tie: the primary is the exception, wherever it is.
        REQUIRE(s.apply(resize("db", 1)));
        apply_all(s, cl::plan(s, {1, 2, 3}));
        CHECK(s.owners.at("db") == std::set<cl::node_id>{lead});
        CHECK(s.primaries.at("db").node == lead);
        check_invariants(s);
    }
}

TEST_CASE("a random history of caches, promotions and moves keeps the invariants and replays to the same state")
{
    for (uint64_t seed = 1; seed <= 200; ++seed)
    {
        prng r{seed};
        cl::state a, b;
        std::vector<cl::command> history;
        std::vector<cl::node_id> live = {1, 2, 3, 4};
        for (int step = 0; step < 100; ++step)
        {
            const std::string name = "c" + std::to_string(r.below(3));
            cl::command c;
            switch (r.below(6))
            {
            case 0: c = cache(name, 1 + static_cast<uint32_t>(r.below(3))); break;
            case 1: c = drop(name); break;
            case 2: c = resize(name, 1 + static_cast<uint32_t>(r.below(4))); break;
            case 3: c = promote(name, 1 + r.below(4), 1 + r.below(5), a.primaries.count(name) ? a.primaries.at(name).epoch + 1 : 1); break;
            case 4: c = place(name, 1 + r.below(4), r.below(2) != 0); break;
            default:
                for (const cl::command& p : cl::plan(a, live))
                {
                    a.apply(p);
                    history.push_back(p);
                }
                check_invariants(a);
                continue;
            }
            a.apply(c);
            history.push_back(c);
            check_invariants(a);
        }
        apply_all(b, history);
        CHECK(a == b);
        cl::state t;
        REQUIRE(cl::decode(cl::encode(a), t));
        CHECK(t == a);
    }
}
