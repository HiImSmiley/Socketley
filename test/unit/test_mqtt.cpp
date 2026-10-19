#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "runtime/mqtt/mqtt_auth.h"
#include "runtime/mqtt/mqtt_broker.h"
#include "runtime/mqtt/mqtt_codec.h"
#include "runtime/mqtt/mqtt_routes.h"
#include "runtime/mqtt/mqtt_topics.h"

#include <map>
#include <set>
#include <string>
#include <vector>

using namespace socketley::mqtt;

namespace
{

// ── A transport and hooks the tests drive by hand ───────────────────────────

struct fake_io : broker_io
{
    std::map<uint64_t, std::string> out;
    std::set<uint64_t> closed;
    std::map<uint64_t, size_t> held;
    int64_t now{1'000'000};

    void send(uint64_t conn, std::string_view bytes) override { out[conn].append(bytes); }
    size_t backlog(uint64_t conn) const override
    {
        const auto it = held.find(conn);
        return it == held.end() ? 0 : it->second;
    }
    void close(uint64_t conn) override { closed.insert(conn); }
    int64_t now_ms() const override { return now; }
};

struct fake_hooks : broker_hooks
{
    uint8_t answer{reason::success};
    bool defer{false};
    std::vector<std::function<void(auth_answer)>> waiting;
    std::vector<std::string> accepted_topics;
    acl_rules acl;
    bool script_publish{false};
    std::function<publish_verdict(const message&)> verdict;
    std::vector<std::string> disconnects;

    void authenticate(const auth_ask& ask, std::function<void(auth_answer)> done) override
    {
        auth_answer a{answer, ask.username.value_or(ask.cert_cn)};
        if (defer)
            waiting.push_back([done, a](auth_answer) { done(a); });
        else
            done(a);
    }
    bool may_write(std::string_view u, std::string_view c, std::string_view t) override { return acl.may_write(u, c, t); }
    bool may_read(std::string_view u, std::string_view c, std::string_view t) override { return acl.may_read(u, c, t); }
    bool may_subscribe(std::string_view u, std::string_view c, std::string_view f) override
    {
        return acl.may_subscribe(u, c, f);
    }
    bool hooks_publish() const override { return script_publish; }
    void on_publish(const client_info&, const message_ptr& m, std::function<void(publish_verdict)> done) override
    {
        done(verdict ? verdict(*m) : publish_verdict{});
    }
    void on_disconnect(const client_info& c, std::string_view why) override
    {
        disconnects.push_back(c.client_id + ":" + std::string(why));
    }
    void accepted(const message_ptr& m) override { accepted_topics.push_back(m->topic); }
};

// What a test client reads back: every packet the broker wrote to it since the last look.
struct got
{
    std::vector<frame> frames;
    std::string bytes;
};

struct rig
{
    fake_io io;
    fake_hooks hooks;
    broker_config cfg;
    std::unique_ptr<broker> b;
    uint64_t next{1};

    explicit rig(broker_config c = {})
    {
        c.sys_interval_s = 0;
        cfg = c;
        b = std::make_unique<broker>(cfg, io, hooks);
    }

    uint64_t open() { const uint64_t id = next++; b->connected(id, {"127.0.0.1:1", "", false, false}); return id; }

    void send(uint64_t c, const std::string& bytes) { b->input(c, bytes); }

    // The packets written to `c` since the last call, parsed.
    std::vector<std::string> packets(uint64_t c)
    {
        std::vector<std::string> list;
        std::string& buf = io.out[c];
        size_t at = 0;
        while (at < buf.size())
        {
            frame f;
            const auto st = take_frame(std::string_view(buf).substr(at), 0, f);
            REQUIRE(st == frame_status::ok);
            list.emplace_back(buf.substr(at, f.size));
            at += f.size;
        }
        buf.clear();
        return list;
    }

    uint64_t connect(std::string id, uint8_t level = level_311, bool clean = true, uint32_t expiry = 0,
                     std::optional<will_message> will = {}, uint16_t keepalive = 60)
    {
        const uint64_t c = open();
        connect_packet p;
        p.level       = level;
        p.client_id   = std::move(id);
        p.clean_start = clean;
        p.keepalive   = keepalive;
        p.will        = std::move(will);
        if (level == level_5 && expiry)
            p.props.session_expiry = expiry;
        std::string out;
        write_connect(out, p);
        send(c, out);
        return c;
    }
};

frame frame_of(const std::string& bytes)
{
    frame f;
    REQUIRE(take_frame(bytes, 0, f) == frame_status::ok);
    return f;
}

connack_packet connack_of(const std::string& bytes, uint8_t level)
{
    connack_packet a;
    refusal err;
    REQUIRE(read_connack(frame_of(bytes), level, a, err));
    return a;
}

publish_packet publish_of(const std::string& bytes, uint8_t level)
{
    publish_packet p;
    refusal err;
    REQUIRE(read_publish(frame_of(bytes), level, p, err));
    return p;
}

std::string pub(const std::string& topic, const std::string& payload, uint8_t qos = 0, uint16_t id = 0,
                bool retain = false, uint8_t level = level_311, properties props = {})
{
    publish_packet p;
    p.topic     = topic;
    p.payload   = payload;
    p.qos       = qos;
    p.packet_id = id;
    p.retain    = retain;
    p.props     = std::move(props);
    std::string out;
    write_publish(out, level, p);
    return out;
}

std::string sub(const std::string& filter, uint8_t qos, uint16_t id = 1, uint8_t level = level_311,
                uint8_t retain_handling = 0, bool no_local = false, uint32_t sub_id = 0)
{
    subscribe_packet p;
    p.packet_id = id;
    subscription s;
    s.filter          = filter;
    s.qos             = qos;
    s.retain_handling = retain_handling;
    s.no_local        = no_local;
    p.entries.push_back(s);
    if (sub_id)
        p.props.subscription_ids.push_back(sub_id);
    std::string out;
    write_subscribe(out, level, p);
    return out;
}

std::string ack(packet_type t, uint16_t id, uint8_t level = level_311)
{
    ack_packet a;
    a.type = t;
    a.packet_id = id;
    std::string out;
    write_ack(out, level, a);
    return out;
}

packet_type type_of(const std::string& bytes) { return frame_of(bytes).type; }

}   // namespace

// ── Codec ───────────────────────────────────────────────────────────────────

TEST_CASE("a CONNECT of 3.1.1 and of 5.0 reads back what was written, will and properties included")
{
    for (const uint8_t level : {level_31, level_311, level_5})
    {
        connect_packet p;
        p.level       = level;
        p.clean_start = false;
        p.keepalive   = 30;
        p.client_id   = "dev-1";
        p.username    = "alice";
        p.password    = std::string("s\0cret", 6);
        will_message w;
        w.topic   = "devices/dev-1/state";
        w.payload = "offline";
        w.qos     = 1;
        w.retain  = true;
        if (level == level_5)
        {
            w.props.will_delay = 5;
            p.props.session_expiry  = 3600;
            p.props.receive_maximum = 10;
            p.props.user.emplace_back("k", "v");
        }
        p.will = w;
        std::string bytes;
        write_connect(bytes, p);
        connect_packet q;
        refusal err;
        REQUIRE(read_connect(frame_of(bytes), q, err));
        CHECK(q.level == level);
        CHECK(q.client_id == "dev-1");
        CHECK(*q.username == "alice");
        CHECK(*q.password == std::string("s\0cret", 6));
        CHECK(q.keepalive == 30);
        CHECK_FALSE(q.clean_start);
        REQUIRE(q.will);
        CHECK(q.will->topic == "devices/dev-1/state");
        CHECK(q.will->qos == 1);
        CHECK(q.will->retain);
        if (level == level_5)
        {
            CHECK(*q.props.session_expiry == 3600);
            CHECK(*q.props.receive_maximum == 10);
            CHECK(*q.will->props.will_delay == 5);
            CHECK(q.props.user.size() == 1);
        }
    }
}

TEST_CASE("the reader refuses what the specification says a receiver must refuse")
{
    refusal err;
    // A Remaining Length of five bytes.
    frame f;
    CHECK(take_frame(std::string("\x30\xFF\xFF\xFF\xFF\x01", 6), 0, f) == frame_status::malformed);
    // Packet type 0.
    CHECK(take_frame(std::string("\x00\x00", 2), 0, f) == frame_status::malformed);
    // Larger than the limit, refused from its header alone.
    CHECK(take_frame(std::string("\x30\xFF\x7F", 3), 1000, f) == frame_status::too_large);
    CHECK(take_frame(std::string("\x30\x05", 2), 0, f) == frame_status::incomplete);

    // A QoS 3 PUBLISH, and a QoS 0 one marked as a repeat.
    publish_packet p;
    std::string q3 = pub("a", "x");
    q3[0] = static_cast<char>(0x36);
    CHECK_FALSE(read_publish(frame_of(q3), level_311, p, err));
    std::string dup0 = pub("a", "x");
    dup0[0] = static_cast<char>(0x38);
    CHECK_FALSE(read_publish(frame_of(dup0), level_311, p, err));
    // A publish to a wildcard.
    CHECK_FALSE(read_publish(frame_of(pub("a/+", "x")), level_311, p, err));
    CHECK(err.code == reason::topic_name_invalid);
    // A SUBSCRIBE whose reserved bits are not 0010.
    std::string s = sub("a", 0);
    s[0] = static_cast<char>(0x80);
    subscribe_packet sp;
    CHECK_FALSE(read_subscribe(frame_of(s), level_311, sp, err));
    // A topic that is not UTF-8.
    CHECK_FALSE(read_publish(frame_of(pub(std::string("a\xC0\x80", 3), "x")), level_311, p, err));
    // A property given twice, and one a packet may not carry.
    properties twice;
    twice.content_type = "a";
    std::string bytes = pub("t", "x", 0, 0, false, level_5, twice);
    publish_packet ok5;
    CHECK(read_publish(frame_of(bytes), level_5, ok5, err));
    // Content type 0x03 given twice, by hand: topic "t", properties "a" and "b".
    const std::string dupprop("\x30\x0C\x00\x01t\x08\x03\x00\x01" "a\x03\x00\x01" "b", 14);
    CHECK_FALSE(read_publish(frame_of(dupprop), level_5, ok5, err));
}

TEST_CASE("topic names and filters follow the rules for levels and wildcards")
{
    CHECK(valid_topic("a/b"));
    CHECK(valid_topic("a//b"));
    CHECK(valid_topic("/"));
    CHECK_FALSE(valid_topic(""));
    CHECK_FALSE(valid_topic("a/+"));
    CHECK_FALSE(valid_topic("a/#"));
    CHECK(valid_filter("#"));
    CHECK(valid_filter("+/a/#"));
    CHECK(valid_filter("a/+/+"));
    CHECK_FALSE(valid_filter("a/#/b"));
    CHECK_FALSE(valid_filter("a#"));
    CHECK_FALSE(valid_filter("a/b+"));
    CHECK(valid_filter("$share/g/a/#"));
    CHECK_FALSE(valid_filter("$share/g"));
    CHECK_FALSE(valid_filter("$share//a"));
    CHECK_FALSE(valid_filter("$share/g+/a"));
    std::string_view g, inner;
    REQUIRE(split_shared("$share/workers/jobs/#", g, inner));
    CHECK(g == "workers");
    CHECK(inner == "jobs/#");
    CHECK(valid_utf8("\xC3\xA9"));
    CHECK_FALSE(valid_utf8(std::string("a\0b", 3)));
    CHECK_FALSE(valid_utf8("\xED\xA0\x80"));
    CHECK_FALSE(valid_utf8("\xC0\xAF"));
}

TEST_CASE("the subscription tree matches as the specification says, '$' topics apart")
{
    subscription_tree t;
    std::vector<std::string> names = {"#", "a/#", "a/+", "a/b", "+/b", "+", "$SYS/#", "a/b/#"};
    for (size_t i = 0; i < names.size(); ++i)
        t.add(names[i], {}, i, {});
    const auto who = [&](std::string_view topic) {
        std::set<std::string> out;
        t.match(topic, [&](uint64_t s, const sub_options&) { out.insert(names[s]); },
                [](std::string_view, uint64_t, const sub_options&) {});
        return out;
    };
    CHECK(who("a/b") == std::set<std::string>{"#", "a/#", "a/+", "a/b", "+/b", "a/b/#"});
    CHECK(who("a") == std::set<std::string>{"#", "a/#", "+"});
    CHECK(who("a/c/d") == std::set<std::string>{"#", "a/#"});
    CHECK(who("$SYS/x") == std::set<std::string>{"$SYS/#"});
    CHECK(t.any_match("x/b"));
    CHECK(t.remove("a/b/#", {}, 7));
    CHECK_FALSE(t.remove("a/b/#", {}, 7));
    CHECK(who("a/b").size() == 5);
    CHECK(t.size() == names.size() - 1);
}

TEST_CASE("a shared group hands each message to one member, round them, preferring those connected")
{
    subscription_tree t;
    t.add("jobs/#", "w", 1, {});
    t.add("jobs/#", "w", 2, {});
    t.add("jobs/#", "w", 3, {});
    std::vector<uint64_t> got;
    for (int i = 0; i < 6; ++i)
        t.match("jobs/x", [](uint64_t, const sub_options&) {},
                [&](std::string_view key, uint64_t s, const sub_options&) {
                    CHECK(key == "$share/w/jobs/#");
                    got.push_back(s);
                });
    CHECK(got == std::vector<uint64_t>{1, 2, 3, 1, 2, 3});
    got.clear();
    for (int i = 0; i < 4; ++i)
        t.match("jobs/x", [](uint64_t, const sub_options&) {},
                [&](std::string_view, uint64_t s, const sub_options&) { got.push_back(s); },
                [](uint64_t s) { return s != 2; });
    CHECK(std::find(got.begin(), got.end(), 2) == got.end());
}

TEST_CASE("the retained tree finds what a filter matches")
{
    retained_tree<std::string> r;
    r.set("a/b", std::make_shared<std::string>("1"));
    r.set("a/c/d", std::make_shared<std::string>("2"));
    r.set("a", std::make_shared<std::string>("3"));
    r.set("$SYS/x", std::make_shared<std::string>("4"));
    const auto found = [&](std::string_view f) {
        std::set<std::string> out;
        r.match(f, [&](const std::shared_ptr<std::string>& v) { out.insert(*v); });
        return out;
    };
    CHECK(found("#") == std::set<std::string>{"1", "2", "3"});
    CHECK(found("a/#") == std::set<std::string>{"1", "2", "3"});
    CHECK(found("a/+") == std::set<std::string>{"1"});
    CHECK(found("+/+/d") == std::set<std::string>{"2"});
    CHECK(found("$SYS/#") == std::set<std::string>{"4"});
    r.set("a/b", nullptr);
    CHECK(r.size() == 3);
    CHECK(found("a/+").empty());
}

TEST_CASE("the ACL grants by user and pattern, and a deny wins")
{
    acl_rules a;
    std::string why;
    REQUIRE(a.parse("topic read public/#\n"
                    "user alice\n"
                    "topic readwrite alice/#\n"
                    "topic deny alice/secret/#\n"
                    "pattern readwrite devices/%c/#\n"
                    "pattern read users/%u/inbox\n",
                    why));
    CHECK(a.may_read("", "x", "public/news"));
    CHECK_FALSE(a.may_write("", "x", "public/news"));
    CHECK(a.may_write("alice", "c1", "alice/x"));
    CHECK_FALSE(a.may_write("alice", "c1", "alice/secret/k"));
    CHECK_FALSE(a.may_read("alice", "c1", "public/news"));
    CHECK(a.may_write("bob", "dev7", "devices/dev7/temp"));
    CHECK_FALSE(a.may_write("bob", "dev7", "devices/dev8/temp"));
    CHECK(a.may_read("bob", "c", "users/bob/inbox"));
    CHECK(a.may_subscribe("alice", "c1", "alice/#"));
    CHECK(a.may_subscribe("alice", "c1", "alice/+/x"));
    CHECK_FALSE(a.may_subscribe("alice", "c1", "alice/secret/#"));
    CHECK_FALSE(a.may_subscribe("alice", "c1", "#"));
    // A name holding a separator cannot widen a pattern.
    CHECK_FALSE(a.may_write("bob", "a/b", "devices/a/b/x"));
    CHECK_FALSE(a.parse("topic sometimes a/b\n", why));
    CHECK_FALSE(a.parse("topic read a/#/b\n", why));
    CHECK(filter_covers("a/#", "a/b/c"));
    CHECK(filter_covers("a/+", "a/+"));
    CHECK_FALSE(filter_covers("a/+", "a/#"));
    CHECK(filter_covers("#", "a"));
    CHECK_FALSE(filter_covers("#", "$SYS/x"));
    CHECK(topic_matches("a/#", "a"));
    CHECK_FALSE(topic_matches("+/x", "$SYS/x"));
}

TEST_CASE("the users file takes only hashes")
{
    user_table u;
    std::string why;
    CHECK(u.parse("# comment\nalice:$scrypt$ln=14,r=8,p=1$abc$def\n", why));
    CHECK(u.hash_of("alice") != nullptr);
    CHECK(u.hash_of("bob") == nullptr);
    CHECK_FALSE(u.parse("alice:plaintext\n", why));
    CHECK_FALSE(u.parse("nocolon\n", why));
}

// ── The broker ──────────────────────────────────────────────────────────────

TEST_CASE("a client connects, subscribes and gets what another publishes, at the lower QoS")
{
    rig r;
    const uint64_t a = r.connect("a");
    const uint64_t b = r.connect("b");
    auto pa = r.packets(a);
    REQUIRE(pa.size() == 1);
    CHECK(connack_of(pa[0], level_311).reason == 0);
    CHECK_FALSE(connack_of(pa[0], level_311).session_present);
    r.packets(b);
    r.send(a, sub("t/#", 1));
    pa = r.packets(a);
    REQUIRE(pa.size() == 1);
    CHECK(type_of(pa[0]) == packet_type::suback);
    r.send(b, pub("t/x", "hello", 2, 7));
    const auto pb = r.packets(b);
    REQUIRE(pb.size() == 1);
    CHECK(type_of(pb[0]) == packet_type::pubrec);
    pa = r.packets(a);
    REQUIRE(pa.size() == 1);
    const auto got = publish_of(pa[0], level_311);
    CHECK(got.topic == "t/x");
    CHECK(got.payload == "hello");
    CHECK(got.qos == 1);
    CHECK(got.packet_id != 0);
    CHECK(r.hooks.accepted_topics == std::vector<std::string>{"t/x"});
}

TEST_CASE("QoS 2 towards the broker is delivered once, however often it is sent before PUBREL")
{
    rig r;
    const uint64_t a = r.connect("a");
    const uint64_t b = r.connect("b");
    r.send(a, sub("q", 2));
    r.packets(a);
    r.packets(b);
    r.send(b, pub("q", "once", 2, 9));
    r.send(b, pub("q", "once", 2, 9));
    auto pb = r.packets(b);
    REQUIRE(pb.size() == 2);
    CHECK(type_of(pb[0]) == packet_type::pubrec);
    CHECK(type_of(pb[1]) == packet_type::pubrec);
    r.send(b, ack(packet_type::pubrel, 9));
    pb = r.packets(b);
    REQUIRE(pb.size() == 1);
    CHECK(type_of(pb[0]) == packet_type::pubcomp);
    auto pa = r.packets(a);
    REQUIRE(pa.size() == 1);
    const auto m = publish_of(pa[0], level_311);
    CHECK(m.qos == 2);
    // The subscriber's half: PUBREC, then PUBREL from the broker, then PUBCOMP.
    r.send(a, ack(packet_type::pubrec, m.packet_id));
    pa = r.packets(a);
    REQUIRE(pa.size() == 1);
    CHECK(type_of(pa[0]) == packet_type::pubrel);
    r.send(a, ack(packet_type::pubcomp, m.packet_id));
    CHECK(r.b->inflight_count() == 0);
}

TEST_CASE("a session that is kept gets what it missed, and what was unanswered again marked as a repeat")
{
    rig r;
    uint64_t a = r.connect("keep", level_311, false);
    r.send(a, sub("news", 1));
    r.packets(a);
    const uint64_t p = r.connect("pub");
    r.send(p, pub("news", "1", 1, 1));
    const auto first = r.packets(a);
    REQUIRE(first.size() == 1);
    const uint16_t unanswered = publish_of(first[0], level_311).packet_id;
    r.b->disconnected(a);
    r.send(p, pub("news", "2", 1, 2));
    r.send(p, pub("news", "3", 0));
    a = r.connect("keep", level_311, false);
    const auto back = r.packets(a);
    REQUIRE(back.size() == 3);
    CHECK(connack_of(back[0], level_311).session_present);
    const auto again = publish_of(back[1], level_311);
    CHECK(again.dup);
    CHECK(again.packet_id == unanswered);
    CHECK(again.payload == "1");
    CHECK(publish_of(back[2], level_311).payload == "2");
}

TEST_CASE("a second connection with the same client identifier takes the session over")
{
    rig r;
    const uint64_t a = r.connect("same", level_5, false, 3600);
    r.packets(a);
    const uint64_t b = r.connect("same", level_5, false, 3600);
    auto pa = r.packets(a);
    REQUIRE(pa.size() == 1);
    CHECK(type_of(pa[0]) == packet_type::disconnect);
    CHECK(r.io.closed.contains(a));
    auto pb = r.packets(b);
    REQUIRE(pb.size() == 1);
    CHECK(connack_of(pb[0], level_5).session_present);
    CHECK(r.b->stats().takeovers == 1);
    // The old connection's end, when it comes, changes nothing for the new one.
    r.b->disconnected(a);
    CHECK(r.b->connected_count() == 1);
}

TEST_CASE("a will is sent when a connection breaks, not after a DISCONNECT, and after its delay")
{
    rig r;
    const uint64_t watcher = r.connect("w", level_5);
    r.send(watcher, sub("wills/#", 0, 1, level_5));
    r.packets(watcher);
    will_message w;
    w.topic = "wills/a";
    w.payload = "gone";
    const uint64_t a = r.connect("a", level_311, true, 0, w);
    r.b->disconnected(a);
    auto pw = r.packets(watcher);
    REQUIRE(pw.size() == 1);
    CHECK(publish_of(pw[0], level_5).payload == "gone");

    const uint64_t b = r.connect("b", level_311, true, 0, w);
    disconnect_packet d;
    std::string bytes;
    write_disconnect(bytes, level_311, d);
    r.send(b, bytes);
    r.b->disconnected(b);
    CHECK(r.packets(watcher).empty());

    will_message late = w;
    late.props.will_delay = 5;
    const uint64_t c = r.connect("c", level_5, false, 60, late);
    r.b->disconnected(c);
    r.io.now += 4000;
    r.b->tick();
    CHECK(r.packets(watcher).empty());
    r.io.now += 2000;
    r.b->tick();
    CHECK(r.packets(watcher).size() == 1);

    // A connection back to the session within the delay keeps the will from being sent.
    const uint64_t d1 = r.connect("d", level_5, false, 60, late);
    r.b->disconnected(d1);
    r.io.now += 1000;
    r.connect("d", level_5, false, 60);
    r.io.now += 10000;
    r.b->tick();
    CHECK(r.packets(watcher).empty());
}

TEST_CASE("retained messages reach new subscribers as Retain Handling says")
{
    rig r;
    const uint64_t p = r.connect("p", level_5);
    r.send(p, pub("state/1", "on", 0, 0, true, level_5));
    r.send(p, pub("state/2", "off", 0, 0, true, level_5));
    CHECK(r.b->retained_count() == 2);
    const uint64_t s = r.connect("s", level_5);
    r.packets(s);
    r.send(s, sub("state/+", 1, 1, level_5));
    auto got = r.packets(s);
    REQUIRE(got.size() == 3);
    CHECK(type_of(got[0]) == packet_type::suback);
    CHECK(publish_of(got[1], level_5).retain);
    // Retain Handling 1: none for a subscription that already existed.
    r.send(s, sub("state/+", 1, 2, level_5, 1));
    CHECK(r.packets(s).size() == 1);
    // Retain Handling 2: none at all.
    r.send(s, sub("state/#", 1, 3, level_5, 2));
    CHECK(r.packets(s).size() == 1);
    // An empty retained payload clears it.
    r.send(p, pub("state/1", "", 0, 0, true, level_5));
    CHECK(r.b->retained_count() == 1);
}

TEST_CASE("overlapping subscriptions deliver once at the highest QoS, carrying every identifier")
{
    rig r;
    const uint64_t s = r.connect("s", level_5);
    r.send(s, sub("a/#", 0, 1, level_5, 0, false, 11));
    r.send(s, sub("a/+", 1, 2, level_5, 0, false, 22));
    r.packets(s);
    const uint64_t p = r.connect("p", level_5);
    r.send(p, pub("a/b", "x", 2, 1, false, level_5));
    const auto got = r.packets(s);
    REQUIRE(got.size() == 1);
    const auto m = publish_of(got[0], level_5);
    CHECK(m.qos == 1);
    CHECK(std::set<uint32_t>(m.props.subscription_ids.begin(), m.props.subscription_ids.end()) ==
          std::set<uint32_t>{11, 22});
}

TEST_CASE("No Local keeps a client's own messages from it")
{
    rig r;
    const uint64_t s = r.connect("s", level_5);
    r.send(s, sub("echo", 0, 1, level_5, 0, true));
    r.packets(s);
    r.send(s, pub("echo", "mine", 0, 0, false, level_5));
    CHECK(r.packets(s).empty());
    // And on a shared subscription it is a protocol error.
    r.send(s, sub("$share/g/echo", 0, 2, level_5, 0, true));
    CHECK(r.io.closed.contains(s));
}

TEST_CASE("a client's Receive Maximum holds the rest back until it answers")
{
    rig r;
    const uint64_t s = r.open();
    connect_packet c;
    c.level = level_5;
    c.client_id = "slow";
    c.props.receive_maximum = 2;
    std::string bytes;
    write_connect(bytes, c);
    r.send(s, bytes);
    r.send(s, sub("m", 1, 1, level_5));
    r.packets(s);
    const uint64_t p = r.connect("p", level_5);
    for (int i = 0; i < 5; ++i)
        r.send(p, pub("m", std::to_string(i), 1, static_cast<uint16_t>(i + 1), false, level_5));
    auto got = r.packets(s);
    REQUIRE(got.size() == 2);
    r.send(s, ack(packet_type::puback, publish_of(got[0], level_5).packet_id, level_5));
    got = r.packets(s);
    REQUIRE(got.size() == 1);
    CHECK(publish_of(got[0], level_5).payload == "2");
}

TEST_CASE("an offline session keeps up to its limit and drops the oldest past it")
{
    broker_config cfg;
    cfg.session_queue = 3;
    rig r(cfg);
    uint64_t s = r.connect("q", level_311, false);
    r.send(s, sub("m", 1));
    r.b->disconnected(s);
    const uint64_t p = r.connect("p");
    for (int i = 0; i < 5; ++i)
        r.send(p, pub("m", std::to_string(i), 1, static_cast<uint16_t>(i + 1)));
    CHECK(r.b->stats().dropped_queue == 2);
    s = r.connect("q", level_311, false);
    const auto got = r.packets(s);
    REQUIRE(got.size() == 4);
    CHECK(publish_of(got[1], level_311).payload == "2");
}

TEST_CASE("QoS 0 to a client that does not read is dropped and counted")
{
    rig r;
    const uint64_t s = r.connect("s");
    r.send(s, sub("m", 0));
    r.packets(s);
    r.io.held[s] = r.cfg.write_limit + 1;
    const uint64_t p = r.connect("p");
    r.send(p, pub("m", "x"));
    CHECK(r.packets(s).empty());
    CHECK(r.b->stats().dropped_slow == 1);
}

TEST_CASE("a message past its expiry is not delivered, and one waiting is told what is left")
{
    rig r;
    uint64_t s = r.connect("s", level_5, false, 600);
    r.send(s, sub("m", 1, 1, level_5));
    r.b->disconnected(s);
    const uint64_t p = r.connect("p", level_5);
    properties e;
    e.message_expiry = 10;
    r.send(p, pub("m", "soon", 1, 1, false, level_5, e));
    properties e2;
    e2.message_expiry = 100;
    r.send(p, pub("m", "later", 1, 2, false, level_5, e2));
    r.io.now += 20000;
    s = r.connect("s", level_5, false, 600);
    const auto got = r.packets(s);
    REQUIRE(got.size() == 2);
    const auto m = publish_of(got[1], level_5);
    CHECK(m.payload == "later");
    CHECK(*m.props.message_expiry == 80);
}

TEST_CASE("a session ends after its expiry, and a clean start ends it at once")
{
    rig r;
    const uint64_t s = r.connect("s", level_5, false, 30);
    r.b->disconnected(s);
    CHECK(r.b->session_count() == 1);
    r.io.now += 31000;
    r.b->tick();
    CHECK(r.b->session_count() == 0);
    CHECK(r.b->stats().sessions_expired == 1);
    const uint64_t a = r.connect("a", level_311, false);
    r.send(a, sub("x", 0));
    r.b->disconnected(a);
    const uint64_t b = r.connect("a", level_311, true);
    CHECK_FALSE(connack_of(r.packets(b)[0], level_311).session_present);
    CHECK(r.b->subscription_count() == 0);
}

TEST_CASE("keep alive and the CONNECT deadline close what goes quiet")
{
    rig r;
    const uint64_t s = r.connect("s", level_311, true, 0, {}, 10);
    r.io.now += 14000;
    r.b->tick();
    CHECK_FALSE(r.io.closed.contains(s));
    r.io.now += 2000;
    r.b->tick();
    CHECK(r.io.closed.contains(s));
    const uint64_t q = r.open();
    r.io.now += r.cfg.connect_timeout_ms + 1;
    r.b->tick();
    CHECK(r.io.closed.contains(q));
}

TEST_CASE("CONNECT is refused for what it cannot be, in each version's own codes")
{
    rig r;
    r.hooks.answer = reason::bad_user_or_password;
    const uint64_t a = r.connect("a", level_311);
    CHECK(connack_of(r.packets(a)[0], level_311).reason == 4);
    const uint64_t b = r.connect("b", level_5);
    CHECK(connack_of(r.packets(b)[0], level_5).reason == reason::bad_user_or_password);
    r.hooks.answer = reason::success;
    // 3.1.1 with no identifier and a kept session.
    const uint64_t c = r.connect("", level_311, false);
    CHECK(connack_of(r.packets(c)[0], level_311).reason == 2);
    // 5.0 with no identifier is given one.
    const uint64_t d = r.connect("", level_5, true);
    const auto ack5 = connack_of(r.packets(d)[0], level_5);
    CHECK(ack5.reason == 0);
    REQUIRE(ack5.props.assigned_client_id);
    CHECK(ack5.props.assigned_client_id->starts_with("auto-"));
    // A packet before CONNECT closes the connection.
    const uint64_t e = r.open();
    r.send(e, sub("x", 0));
    CHECK(r.io.closed.contains(e));
}

TEST_CASE("an answer that comes later holds the connection's packets until it does")
{
    rig r;
    r.hooks.defer = true;
    const uint64_t a = r.open();
    connect_packet c;
    c.client_id = "late";
    std::string bytes;
    write_connect(bytes, c);
    r.send(a, bytes + sub("x", 0));
    CHECK(r.packets(a).empty());
    REQUIRE(r.hooks.waiting.size() == 1);
    r.hooks.waiting[0]({});
    const auto got = r.packets(a);
    REQUIRE(got.size() == 2);
    CHECK(type_of(got[0]) == packet_type::connack);
    CHECK(type_of(got[1]) == packet_type::suback);
}

TEST_CASE("the ACL and a script decide what is published and subscribed")
{
    rig r;
    std::string why;
    REQUIRE(r.hooks.acl.parse("user u\ntopic readwrite ok/#\n", why));
    r.hooks.answer = reason::success;
    const uint64_t s = r.open();
    connect_packet c;
    c.level = level_5;
    c.client_id = "c";
    c.username = "u";
    std::string bytes;
    write_connect(bytes, c);
    r.send(s, bytes);
    r.send(s, sub("no/#", 1, 1, level_5));
    auto got = r.packets(s);
    REQUIRE(got.size() == 2);
    suback_packet sa;
    refusal err;
    REQUIRE(read_suback(frame_of(got[1]), level_5, sa, err));
    CHECK(sa.reasons.at(0) == reason::not_authorized);
    r.send(s, pub("no/x", "x", 1, 5, false, level_5));
    got = r.packets(s);
    ack_packet pa;
    REQUIRE(read_ack(frame_of(got[0]), level_5, pa, err));
    CHECK(pa.reason == reason::not_authorized);
    r.hooks.script_publish = true;
    r.hooks.verdict = [](const message& m) {
        publish_verdict v;
        v.allow = m.payload != "bad";
        return v;
    };
    r.send(s, pub("ok/x", "bad", 1, 6, false, level_5));
    got = r.packets(s);
    REQUIRE(read_ack(frame_of(got[0]), level_5, pa, err));
    CHECK(pa.reason == reason::not_authorized);
}

TEST_CASE("topic aliases from a 5.0 client are kept per connection")
{
    rig r;
    const uint64_t s = r.connect("s", level_5);
    r.send(s, sub("long/topic/name", 0, 1, level_5));
    r.packets(s);
    const uint64_t p = r.connect("p", level_5);
    properties set;
    set.topic_alias = 3;
    r.send(p, pub("long/topic/name", "1", 0, 0, false, level_5, set));
    r.send(p, pub("", "2", 0, 0, false, level_5, set));
    const auto got = r.packets(s);
    REQUIRE(got.size() == 2);
    CHECK(publish_of(got[1], level_5).topic == "long/topic/name");
    properties bad;
    bad.topic_alias = 200;
    r.send(p, pub("x", "3", 0, 0, false, level_5, bad));
    CHECK(r.io.closed.contains(p));
}

TEST_CASE("a snapshot brings sessions, queues, unanswered messages and retained ones back")
{
    std::string snap;
    {
        rig r;
        const uint64_t s = r.connect("s", level_5, false, 3600);
        r.send(s, sub("m/#", 1, 1, level_5));
        const uint64_t p = r.connect("p", level_5);
        r.send(p, pub("m/1", "a", 1, 1, true, level_5));
        r.send(p, pub("m/2", "b", 1, 2, false, level_5));
        r.packets(s);
        r.b->disconnected(s);
        r.send(p, pub("m/3", "c", 1, 3, false, level_5));
        snap = r.b->snapshot();
    }
    rig r;
    std::string why;
    REQUIRE(r.b->restore(snap, why));
    CHECK(r.b->retained_count() == 1);
    CHECK(r.b->session_count() == 1);
    const uint64_t s = r.connect("s", level_5, false, 3600);
    const auto got = r.packets(s);
    REQUIRE(got.size() == 4);
    CHECK(connack_of(got[0], level_5).session_present);
    CHECK(publish_of(got[1], level_5).dup);
    CHECK(publish_of(got[3], level_5).payload == "c");
    CHECK_FALSE(r.b->restore("garbage", why));
}

TEST_CASE("a session given up by one broker is taken in by another")
{
    rig one, two;
    uint64_t s = one.connect("roam", level_5, false, 3600);
    one.send(s, sub("r", 1, 1, level_5));
    one.b->disconnected(s);
    const uint64_t p = one.connect("p", level_5);
    one.send(p, pub("r", "kept", 1, 1, false, level_5));
    const std::string bytes = one.b->surrender("roam", false);
    REQUIRE_FALSE(bytes.empty());
    CHECK(one.b->session_count() == 1);
    two.b->adopt(bytes);
    s = two.connect("roam", level_5, false, 3600);
    const auto got = two.packets(s);
    REQUIRE(got.size() == 2);
    CHECK(connack_of(got[0], level_5).session_present);
    CHECK(publish_of(got[1], level_5).payload == "kept");
    CHECK(one.b->surrender("nobody", false).empty());
}

TEST_CASE("a packet larger than the broker takes ends the connection")
{
    broker_config cfg;
    cfg.max_packet = 64;
    rig r(cfg);
    const uint64_t s = r.connect("s", level_5);
    r.packets(s);
    r.send(s, pub("t", std::string(100, 'x'), 0, 0, false, level_5));
    CHECK(r.io.closed.contains(s));
}

TEST_CASE("the operator can kick a client and clear a retained message")
{
    rig r;
    const uint64_t s = r.connect("k", level_5, false, 60);
    r.packets(s);
    CHECK(r.b->kick("k", true));
    CHECK(r.io.closed.contains(s));
    CHECK(r.b->session_count() == 0);
    CHECK_FALSE(r.b->kick("nobody", false));
    message m;
    m.topic = "x";
    m.payload = "1";
    m.retain = true;
    r.b->publish(m);
    CHECK(r.b->clear_retained("x"));
    CHECK_FALSE(r.b->clear_retained("x"));
}

TEST_CASE("a first byte that is no CONNECT closes the connection before a whole packet arrives")
{
    rig r;
    r.b->connected(1, {"peer", "", false, false});
    r.b->input(1, "GE");
    CHECK(r.io.closed.contains(1));
    r.b->connected(2, {"peer", "", false, false});
    r.b->input(2, std::string_view("\x10", 1));
    CHECK_FALSE(r.io.closed.contains(2));
}

TEST_CASE("topic rules read their targets and refuse what is none, naming the line")
{
    route_table t;
    std::string why;
    CHECK(t.parse("# rules\nsensor/+/temp cache://kv/stream/t-%1\nalarm/# cache://kv/channel/a  # c\n"
                  "dev/+/s db://fleet/devices/%1\nlog/# storage://raw/logs/%Y/\nchat/# server://chat\n"
                  "fwd/# mqtt://core/x/%t\n",
                  why));
    REQUIRE(t.routes().size() == 6);
    CHECK(t.routes()[0].kind == target_kind::cache_stream);
    CHECK(t.routes()[3].name == "logs");
    CHECK(t.routes()[3].detail == "%Y/");
    CHECK_FALSE(t.parse("a/# cache://kv/stack/x\n", why));
    CHECK(why.starts_with("line 1: "));
    CHECK_FALSE(t.parse("ok/# server://s\na/#/b server://s\n", why));
    CHECK(why.starts_with("line 2: "));
    CHECK_FALSE(t.parse("a/+ db://f/c/%2\n", why));
    CHECK_FALSE(t.parse("a/b nowhere\n", why));
}

TEST_CASE("a rule's request sent again goes back before every later one, and a snapshot keeps those in flight")
{
    const std::string text = "a/# mqtt://core/b/%t\n";
    route_table t;
    std::string why;
    REQUIRE(t.parse(text, why));
    message m;
    for (int i = 1; i <= 4; ++i)
    {
        m.topic = "a/" + std::to_string(i);
        t.offer(m, 0, 0);
    }
    route& r = t.routes()[0];
    REQUIRE(r.queue.size() == 4);
    // Two sent, as the pump does it.
    route_request first = std::move(r.queue.front());
    r.queue.pop_front();
    route_request second = std::move(r.queue.front());
    r.queue.pop_front();
    const auto topics = [](const route_table& rt) {
        std::vector<std::string> out;
        for (const auto& q : rt.routes()[0].queue)
            out.push_back(q.bytes.substr(q.bytes.find("b/a/"), 5));
        return out;
    };
    route_table copy;
    REQUIRE(copy.parse(text, why));
    copy.load(t.save({{&second, &first}}));
    CHECK(topics(copy) == std::vector<std::string>{"b/a/1", "b/a/2", "b/a/3", "b/a/4"});
    // Both fail, answered in the order they were sent: each goes back to where it stood.
    r.put_back(std::move(first));
    r.put_back(std::move(second));
    CHECK(topics(t) == std::vector<std::string>{"b/a/1", "b/a/2", "b/a/3", "b/a/4"});
    m.topic = "a/5";
    t.offer(m, 0, 0);
    CHECK(topics(t).back() == "b/a/5");
}

TEST_CASE("a target's answer says delivered, refused or worth another try")
{
    std::string why;
    CHECK(judge_reply(target_kind::db, R"({"status":201,"body":{}})", why) == reply_verdict::delivered);
    CHECK(judge_reply(target_kind::db, R"({"status":409,"body":{}})", why) == reply_verdict::refused);
    CHECK(judge_reply(target_kind::db, R"({"status":503,"body":{}})", why) == reply_verdict::retry);
    CHECK(judge_reply(target_kind::cache_stream, "1-0", why) == reply_verdict::delivered);
    CHECK(judge_reply(target_kind::cache_stream, "error: wrong type", why) == reply_verdict::refused);
    CHECK(judge_reply(target_kind::mqtt, "ok", why) == reply_verdict::delivered);
}

TEST_CASE("a PUBLISH written from its parts is byte for byte the one written from a packet")
{
    publish_packet p;
    p.qos = 1;
    p.retain = true;
    p.dup = true;
    p.packet_id = 513;
    p.topic = "a/b/c";
    p.payload = std::string(300, 'x');
    p.props.payload_format = 1;
    p.props.message_expiry = 42;
    p.props.content_type = "text/plain";
    p.props.response_topic = "r/t";
    p.props.correlation_data = "corr";
    p.props.subscription_ids = {7, 300};
    p.props.user = {{"k", "v"}, {"k", "w"}};
    std::string props;
    put_prop_byte(props, 0x01, 1);
    put_prop_u32(props, 0x02, 42);
    put_prop_str(props, 0x03, "text/plain");
    put_prop_str(props, 0x08, "r/t");
    put_prop_str(props, 0x09, "corr");
    put_prop_varint(props, 0x0B, 7);
    put_prop_varint(props, 0x0B, 300);
    put_prop_pair(props, 0x26, "k", "v");
    put_prop_pair(props, 0x26, "k", "w");
    publish_parts q{p.qos, p.retain, p.dup, p.packet_id, p.topic, p.payload, props};
    for (const uint8_t level : {level_311, level_5})
    {
        std::string a, b;
        write_publish(a, level, p);
        write_publish_parts(b, level, q);
        CHECK(a == b);
        CHECK(publish_parts_size(level, q) == b.size());
        std::string head;
        write_publish_head(head, level, q);
        CHECK(head + p.payload == b);
    }
}

TEST_CASE("the window of unanswered messages finds, frees and wraps its identifiers")
{
    id_window<int> w;
    CHECK(w.add(10) == 1);
    CHECK(w.add(20) == 2);
    CHECK(w.add(30) == 3);
    REQUIRE(w.find(2));
    CHECK(*w.find(2) == 20);
    CHECK_FALSE(w.find(4));
    CHECK_FALSE(w.find(0));
    // Answered out of turn: the middle one goes, the others stay where they were.
    CHECK(w.erase(2));
    CHECK_FALSE(w.erase(2));
    CHECK_FALSE(w.find(2));
    CHECK(*w.find(3) == 30);
    CHECK(w.size() == 2);
    std::vector<uint16_t> ids;
    w.each([&](uint16_t id, const int&) { ids.push_back(id); });
    CHECK(ids == std::vector<uint16_t>{1, 3});
    CHECK(w.erase(1));
    CHECK(w.erase(3));
    CHECK(w.empty());
    CHECK(w.add(40) == 4);

    // Past 65535 the identifiers start again at 1, never at 0.
    id_window<int> wrap;
    wrap.set_next_id(65534);
    CHECK(wrap.add(1) == 65534);
    CHECK(wrap.add(2) == 65535);
    CHECK(wrap.add(3) == 1);
    CHECK(*wrap.find(65535) == 2);
    CHECK(*wrap.find(1) == 3);
    CHECK(wrap.erase(65534));
    CHECK(*wrap.find(1) == 3);

    // One never answered holds every identifier after it, and once all 65535 are spanned none is free.
    id_window<int> full;
    for (int i = 0; i < 65535; ++i)
        full.add(i);
    CHECK(full.full());
    for (uint32_t id = 2; id <= 65535; ++id)
        full.erase(static_cast<uint16_t>(id));
    CHECK(full.size() == 1);
    CHECK(full.full());
    CHECK(full.erase(1));
    CHECK_FALSE(full.full());
    CHECK(full.empty());

    // A snapshot's identifiers come back in the order they were sent, with the gaps of those answered.
    id_window<int> back;
    CHECK(back.restore(65530, 1));
    CHECK(back.restore(65533, 2));
    CHECK(back.restore(4, 3));
    CHECK_FALSE(back.restore(4, 9));
    CHECK(back.size() == 3);
    CHECK_FALSE(back.find(65531));
    CHECK(*back.find(4) == 3);
    CHECK(back.add(5) == 5);
}

TEST_CASE("the subscription tree takes its wildcard levels away with their last subscription, and long topics")
{
    subscription_tree t;
    CHECK(t.add("a/+/#", "", 1, {}));
    CHECK(t.add("a/+", "", 2, {}));
    std::vector<uint64_t> got;
    const auto plain = [&](uint64_t s, const sub_options&) { got.push_back(s); };
    const auto none = [](std::string_view, uint64_t, const sub_options&) {};
    t.match("a/x/y", plain, none);
    CHECK(got == std::vector<uint64_t>{1});
    CHECK(t.remove("a/+/#", "", 1));
    CHECK_FALSE(t.remove("a/+/#", "", 1));
    got.clear();
    t.match("a/x/y", plain, none);
    CHECK(got.empty());
    t.match("a/x", plain, none);
    CHECK(got == std::vector<uint64_t>{2});
    CHECK(t.remove("a/+", "", 2));
    CHECK(t.size() == 0);
    CHECK_FALSE(t.any_match("a/x"));

    std::string deep = "d";
    for (int i = 0; i < 40; ++i)
        deep += "/l" + std::to_string(i);
    CHECK(t.add(deep, "", 3, {}));
    CHECK(t.add("d/+/l1/#", "", 4, {}));
    got.clear();
    t.match(deep, plain, none);
    std::sort(got.begin(), got.end());
    CHECK(got == std::vector<uint64_t>{3, 4});
    CHECK(topic_levels(deep).view().size() == 41);
}
