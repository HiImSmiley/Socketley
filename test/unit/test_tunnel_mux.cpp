#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "shared/net/tunnel_mux.h"

#include <algorithm>
#include <string>
#include <vector>

using namespace socketley::tunnel;

namespace
{

// Every event as a line, so two runs can be compared whole.
struct recorder : events
{
    std::vector<std::string> log;
    std::string data;
    session* self{nullptr};
    std::string* out{nullptr};
    // What a handler does on an open: nothing, refuse, or answer at once.
    enum { keep, refuse, echo } on_open_do{keep};

    void on_hello(const fields& f) override
    {
        std::string l = "hello";
        for (const auto& [k, v] : f)
            l += " " + k + "=" + v;
        log.push_back(l);
    }
    void on_open(uint32_t s, std::string_view t, std::string_view peer) override
    {
        log.push_back("open " + std::to_string(s) + " " + std::string(t) + " " + std::string(peer));
        if (on_open_do == refuse)
            self->reset(s, reset_code::refused, *out);
        else if (on_open_do == echo)
            self->send(s, "hi", *out);
    }
    void on_data(uint32_t s, std::string_view b) override
    {
        log.push_back("data " + std::to_string(s) + " " + std::to_string(b.size()));
        data.append(b);
    }
    void on_close(uint32_t s) override { log.push_back("close " + std::to_string(s)); }
    void on_reset(uint32_t s, reset_code c) override
    {
        log.push_back("reset " + std::to_string(s) + " " + std::to_string(static_cast<int>(c)));
    }
    void on_window(uint32_t s) override { log.push_back("window " + std::to_string(s)); }
    void on_pong(std::string_view t) override { log.push_back("pong " + std::string(t)); }
    void on_goaway(std::string_view w) override { log.push_back("goaway " + std::string(w)); }
    void on_datagram(uint32_t f, std::string_view svc, std::string_view b) override
    {
        log.push_back("datagram " + std::to_string(f) + " " + std::string(svc) + " " + std::string(b));
    }
};

// Two ends of one connection, each one's output fed to the other.
struct pair_of
{
    recorder ra, rb;
    session a{true, ra}, b{false, rb};
    std::string a_out, b_out;
    pair_of()
    {
        ra.self = &a;
        ra.out = &a_out;
        rb.self = &b;
        rb.out = &b_out;
        a.hello({{"agent", "pi"}}, a_out);
        b.hello({{"edge", "t"}}, b_out);
        REQUIRE(pump());
    }
    // Until neither side has anything left to say.
    bool pump()
    {
        for (int i = 0; i < 64 && (!a_out.empty() || !b_out.empty()); ++i)
        {
            std::string x;
            x.swap(a_out);
            if (!b.feed(x, b_out))
                return false;
            std::string y;
            y.swap(b_out);
            if (!a.feed(y, a_out))
                return false;
        }
        return true;
    }
};

std::string frame(frame_type t, uint32_t stream, std::string_view payload)
{
    std::string out;
    const uint32_t n = static_cast<uint32_t>(payload.size());
    for (int sh = 24; sh >= 0; sh -= 8)
        out.push_back(static_cast<char>((n >> sh) & 0xff));
    out.push_back(static_cast<char>(t));
    for (int sh = 24; sh >= 0; sh -= 8)
        out.push_back(static_cast<char>((stream >> sh) & 0xff));
    out.append(payload);
    return out;
}

std::string hello_frame() { return frame(frame_type::hello, 0, std::string(1, static_cast<char>(version))); }

}   // namespace

TEST_CASE("both sides say hello, and a stream carries bytes both ways until both close it")
{
    pair_of p;
    CHECK(p.ra.log == std::vector<std::string>{"hello edge=t"});
    CHECK(p.rb.log == std::vector<std::string>{"hello agent=pi"});

    const uint32_t s = p.a.open("pi", "203.0.113.7:50000", p.a_out);
    CHECK(s == 1);
    REQUIRE(p.pump());
    CHECK(p.rb.log.back() == "open 1 pi 203.0.113.7:50000");
    CHECK(p.a.send(s, "GET / HTTP/1.1\r\n\r\n", p.a_out) == 18);
    CHECK(p.b.send(s, "HTTP/1.1 200 OK\r\n\r\n", p.b_out) == 19);
    REQUIRE(p.pump());
    CHECK(p.rb.data == "GET / HTTP/1.1\r\n\r\n");
    CHECK(p.ra.data == "HTTP/1.1 200 OK\r\n\r\n");

    p.a.close(s, p.a_out);
    REQUIRE(p.pump());
    CHECK(p.rb.log.back() == "close 1");
    CHECK(p.a.is_open(s));
    CHECK(p.a.send(s, "more", p.a_out) == 0);
    CHECK(p.b.send(s, "still", p.b_out) == 5);
    p.b.close(s, p.b_out);
    REQUIRE(p.pump());
    CHECK_FALSE(p.a.is_open(s));
    CHECK_FALSE(p.b.is_open(s));
    CHECK(p.ra.data.ends_with("still"));

    // The accepting side opens even streams.
    const uint32_t e = p.b.open("ssh", "", p.b_out);
    CHECK(e == 2);
    REQUIRE(p.pump());
    CHECK(p.ra.log.back() == "open 2 ssh ");
}

TEST_CASE("a stream sends no more than its credit, and the reader's consumption gives it more")
{
    pair_of p;
    const uint32_t s = p.a.open("pi", "", p.a_out);
    REQUIRE(p.pump());
    const std::string big(initial_window + 1000, 'x');
    CHECK(p.a.send(s, big, p.a_out) == initial_window);
    CHECK(p.a.credit(s) == 0);
    CHECK(p.a.send(s, "y", p.a_out) == 0);
    REQUIRE(p.pump());
    CHECK(p.rb.data.size() == initial_window);
    // Frames are cut at the payload limit.
    CHECK(std::count(p.rb.log.begin(), p.rb.log.end(), "data 1 " + std::to_string(max_payload)) == 4);

    // Less than half handed on gives nothing back yet.
    p.b.consumed(s, initial_window / 2 - 1, p.b_out);
    CHECK(p.b_out.empty());
    p.b.consumed(s, 1, p.b_out);
    REQUIRE(p.pump());
    CHECK(p.ra.log.back() == "window 1");
    CHECK(p.a.credit(s) == initial_window / 2);
    // Never more back than was taken, however much the caller says it consumed.
    p.b.consumed(s, 10 * initial_window, p.b_out);
    REQUIRE(p.pump());
    CHECK(p.a.credit(s) == initial_window);
}

TEST_CASE("resets, refusals, the stream limit, pings and goaway")
{
    pair_of p;
    p.rb.on_open_do = recorder::refuse;
    const uint32_t s = p.a.open("nope", "", p.a_out);
    REQUIRE(p.pump());
    CHECK(p.ra.log.back() == "reset 1 1");
    CHECK_FALSE(p.a.is_open(s));
    // Data still on its way for a stream reset is dropped, not an error.
    std::string late = frame(frame_type::data, 1, "late");
    CHECK(p.b.feed(late, p.b_out));

    p.a.ping("12345678", p.a_out);
    REQUIRE(p.pump());
    CHECK(p.ra.log.back() == "pong 12345678");

    recorder r;
    session small(false, r, 1);
    std::string out;
    REQUIRE(small.feed(hello_frame(), out));
    CHECK(small.feed(frame(frame_type::open, 1, std::string("\0\2pi", 4)), out));
    CHECK(small.feed(frame(frame_type::open, 3, std::string("\0\2pi", 4)), out));
    CHECK(small.stream_count() == 1);
    CHECK(out == frame(frame_type::reset, 3, std::string(1, static_cast<char>(reset_code::limit))));

    p.b.goaway("restarting", p.b_out);
    REQUIRE(p.pump());
    CHECK(p.ra.log.back() == "goaway restarting");
    CHECK(p.a.open("pi", "", p.a_out) == 0);
}

TEST_CASE("a datagram goes either way named by its flow and service, outside every stream's credit")
{
    pair_of p;
    CHECK(p.a.datagram(7, "mc", "ping", p.a_out));
    CHECK(p.b.datagram(7, "mc", std::string("pong\0x", 6), p.b_out));
    REQUIRE(p.pump());
    CHECK(p.rb.log.back() == "datagram 7 mc ping");
    CHECK(p.ra.log.back() == std::string("datagram 7 mc pong\0x", 20));
    // A stream that used its credit up holds back no datagram.
    const uint32_t s = p.a.open("pi", "", p.a_out);
    CHECK(p.a.send(s, std::string(initial_window, 'x'), p.a_out) == initial_window);
    CHECK(p.a.credit(s) == 0);
    CHECK(p.a.datagram(8, "mc", "still", p.a_out));
    REQUIRE(p.pump());
    CHECK(p.rb.log.back() == "datagram 8 mc still");
    // What no frame can name is not sent.
    CHECK_FALSE(p.a.datagram(0, "mc", "x", p.a_out));
    CHECK_FALSE(p.a.datagram(1, "", "x", p.a_out));
    CHECK_FALSE(p.a.datagram(1, "mc", std::string(max_payload, 'x'), p.a_out));
}

TEST_CASE("a far side that breaks the protocol ends the session")
{
    const auto broken = [](const std::string& bytes, bool dialled = false) {
        recorder r;
        session s(dialled, r);
        std::string out;
        const bool ok = s.feed(bytes, out);
        return ok ? std::string() : s.error();
    };
    const std::string h = hello_frame();
    CHECK(broken(frame(frame_type::data, 1, "x")) == "a frame before the hello");
    CHECK(broken(h + h).starts_with("a hello where none belongs"));
    CHECK(broken(frame(frame_type::hello, 0, std::string(1, '\2'))) == "a hello of version 2");
    CHECK(broken(frame(frame_type::hello, 0, std::string("\1\0\5ab", 5))) == "a hello cut short");
    CHECK(broken(h + frame(frame_type::open, 2, std::string("\0\2pi", 4))).starts_with("an open of stream 2"));
    CHECK(broken(h + frame(frame_type::open, 1, std::string("\0\2pi", 4)) + frame(frame_type::open, 1, std::string("\0\2pi", 4)))
              .starts_with("an open of stream 1"));
    CHECK(broken(h + frame(frame_type::open, 1, std::string("\0\0", 2))) == "an open with no target");
    CHECK(broken(h + frame(frame_type::data, 5, "x")).starts_with("data for stream 5"));
    std::string flood = h + frame(frame_type::open, 1, std::string("\0\2pi", 4));
    for (uint32_t sent = 0; sent <= initial_window; sent += max_payload)
        flood += frame(frame_type::data, 1, std::string(max_payload, 'x'));
    CHECK(broken(flood).starts_with("data on stream 1 past the credit"));
    CHECK(broken(h + frame(frame_type::open, 1, std::string("\0\2pi", 4)) + frame(frame_type::close, 1, "") +
                 frame(frame_type::data, 1, "x"))
              .starts_with("data on stream 1 after its close"));
    std::string header = frame(frame_type::data, 1, "");
    header[0] = '\x01';   // a length of 16 MiB
    CHECK(broken(h + header).starts_with("a frame of 16777216 bytes"));
    CHECK(broken(h + frame(static_cast<frame_type>(42), 0, "")) == "a frame of unknown type 42");
    CHECK(broken(h + frame(frame_type::ping, 0, "short")) == "a ping of 5 bytes");
    CHECK(broken(h + frame(frame_type::datagram, 0, std::string("\0\2mcx", 5))) == "a datagram with no flow or no service");
    CHECK(broken(h + frame(frame_type::datagram, 3, std::string("\0\0x", 3))) == "a datagram with no flow or no service");
    CHECK(broken(h + frame(frame_type::datagram, 3, std::string("\0\x09mc", 4))) == "a datagram with no flow or no service");
    // Credit that would pass 2^31.
    {
        recorder r;
        session s(true, r);
        std::string out;
        REQUIRE(s.feed(h, out));
        const uint32_t id = s.open("pi", "", out);
        CHECK_FALSE(s.feed(frame(frame_type::window, id, std::string("\x7f\xff\xff\xff", 4)), out));
        CHECK(s.error().starts_with("credit past 2^31"));
    }
}

TEST_CASE("the same bytes give the same events however they are cut")
{
    // One conversation, recorded whole.
    std::string wire = hello_frame();
    wire += frame(frame_type::open, 1, std::string("\0\2pi", 4) + "peer");
    wire += frame(frame_type::data, 1, "hello there");
    wire += frame(frame_type::ping, 0, "abcdefgh");
    wire += frame(frame_type::close, 1, "");
    wire += frame(frame_type::goaway, 0, "bye");
    recorder whole;
    session s1(false, whole);
    std::string out1;
    REQUIRE(s1.feed(wire, out1));
    for (size_t cut = 0; cut <= wire.size(); ++cut)
    {
        recorder r;
        session s(false, r);
        std::string out;
        REQUIRE(s.feed(std::string_view(wire).substr(0, cut), out));
        REQUIRE(s.feed(std::string_view(wire).substr(cut), out));
        CHECK(r.log == whole.log);
        CHECK(out == out1);
        CHECK(s.buffered() == 0);
    }
    recorder bytewise;
    session s2(false, bytewise);
    std::string out2;
    for (char c : wire)
        REQUIRE(s2.feed(std::string_view(&c, 1), out2));
    CHECK(bytewise.log == whole.log);
}

// ─── The edge's agents file ─────────────────────────────────────────────────

#include "runtime/tunnel/tunnel_registry.h"

TEST_CASE("the agents file is read as written, and refuses what it cannot be")
{
    const std::string hash(64, 'a');
    std::vector<agent> agents;
    std::string why;
    REQUIRE(parse_agents("# a comment\nagent pi joined " + hash + " http:web=idp:auth,tcp:mc:25565\n\nagent nas invited " +
                             hash + " http:files  # trailing\n",
                         agents, why));
    REQUIRE(agents.size() == 2);
    CHECK(agents[0].name == "pi");
    CHECK(agents[0].joined);
    CHECK(agents[0].services.size() == 2);
    CHECK(agents[0].services[1].name == "mc");
    CHECK(agents[0].services[1].port == 25565);
    CHECK(agents[0].services[0].auth == "idp:auth");
    CHECK(agents[1].services[0].auth.empty());
    CHECK(agents[0].services[1].bind.empty());
    CHECK_FALSE(agents[1].joined);
    std::vector<agent> again;
    REQUIRE(parse_agents(render_agents(agents), again, why));
    CHECK(render_agents(again) == render_agents(agents));

    // A TCP service on one address alone keeps it, the port after it.
    REQUIRE(parse_agents("agent pi joined " + hash + " tcp:ssh:127.0.0.1:2201\n", agents, why));
    CHECK(agents[0].services[0].name == "ssh");
    CHECK(agents[0].services[0].bind == "127.0.0.1");
    CHECK(agents[0].services[0].port == 2201);
    CHECK(render_agents(agents).find(" tcp:ssh:127.0.0.1:2201\n") != std::string::npos);

    const auto refused = [&](const std::string& text) {
        std::vector<agent> out;
        std::string w;
        return !parse_agents(text, out, w);
    };
    CHECK(refused("agent Pi joined " + hash + " http:web\n"));
    CHECK(refused("agent pi joined short http:web\n"));
    CHECK(refused("agent pi maybe " + hash + " http:web\n"));
    CHECK(refused("agent pi joined " + hash + " ftp:web\n"));
    CHECK(refused("agent pi joined " + hash + " tcp:mc:0\n"));
    CHECK(refused("agent pi joined " + hash + " tcp:mc:70000\n"));
    CHECK(refused("agent pi joined " + hash + " tcp:mc:localhost:25565\n"));
    CHECK(refused("agent pi joined " + hash + " tcp:mc:1.2.3:25565\n"));
    CHECK(refused("agent pi joined " + hash + " http:web,http:web\n"));
    CHECK(refused("agent pi joined " + hash + " http:web=\n"));
    CHECK(refused("agent pi joined " + hash + " http:Web=idp:auth\n"));
    // An auth with an empty method, a comment, or a byte that is no printable character.
    CHECK(refused("agent pi joined " + hash + " http:web=+idp:auth\n"));
    CHECK(refused("agent pi joined " + hash + " http:web=idp:auth+\n"));
    CHECK(refused("agent pi joined " + hash + " http:web=idp:a++bearer:/f\n"));
    CHECK(refused("agent pi joined " + hash + " http:web=idp:a\x01b\n"));
    // A # given as a service's auth, as a join's header may carry, would start a comment in the file.
    std::vector<service> hashed;
    std::string w;
    CHECK_FALSE(parse_services("web=idp:a#x", "", "", hashed, w));
    // A name or a port another agent has.
    CHECK(refused("agent pi joined " + hash + " http:web\nagent nas joined " + hash + " http:web\n"));
    CHECK(refused("agent pi joined " + hash + " tcp:a:2000\nagent nas joined " + hash + " tcp:b:2000\n"));
    CHECK(refused("agent pi joined " + hash + " udp:a:2000\nagent nas joined " + hash + " udp:b:2000\n"));
    // A TCP and a UDP port of one number are two ports.
    CHECK_FALSE(refused("agent pi joined " + hash + " tcp:a:2000\nagent nas joined " + hash + " udp:b:2000\n"));
}

TEST_CASE("services, credentials and names")
{
    std::vector<service> s;
    std::string why;
    REQUIRE(parse_services("web, files=bearer:/etc/tokens", "mc:25565", "bedrock:127.0.0.1:19132", s, why));
    CHECK(s.size() == 4);
    CHECK((s[0].auth.empty() && s[1].name == "files" && s[1].auth == "bearer:/etc/tokens"));
    CHECK((!s[2].udp && s[3].udp && s[3].port == 19132 && s[3].bind == "127.0.0.1"));
    CHECK_FALSE(parse_services("files=", "", "", s, why));
    CHECK_FALSE(parse_services("", "", "", s, why));
    CHECK_FALSE(parse_services("Web", "", "", s, why));
    CHECK_FALSE(parse_services("", "mc", "", s, why));
    CHECK_FALSE(parse_services("", "", "bedrock", s, why));
    CHECK(valid_name("a-1"));
    CHECK_FALSE(valid_name("-a"));
    CHECK_FALSE(valid_name(std::string(64, 'a')));
    std::string name, secret;
    CHECK(split_credential("pi." + std::string(43, 'x'), name, secret));
    CHECK((name == "pi" && secret.size() == 43));
    CHECK_FALSE(split_credential("pi.short", name, secret));
    CHECK_FALSE(split_credential("nodot", name, secret));
    CHECK(hash_secret("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}
