#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "../../socketley/shared/ipc/request_channel.h"
#include "../../socketley/shared/loop/event_loop.h"
#include "../../socketley/shared/ipc/worker_protocol.h"

#include <string>
#include <vector>

// A request that cannot be answered on this thread.
//
// The channel has always been able to serve a target in this process: the sink
// reads its own memory and fills the reply before it returns.  A target on the
// other side of a socket cannot, and the only ways to pretend otherwise are to
// block the event loop or to make the answer up.  So a sink may now say it
// cannot answer inline; the channel parks the request against a ticket and the
// sink completes it later.
//
// What these tests hold down is that the asking side cannot tell the two apart.
// An origin posts, and on some later turn its on_request_reply() runs with the
// cookie it posted — whichever path the request took.

namespace {

struct recording_origin : request_origin
{
    struct reply { uint64_t cookie; request_status st; std::string payload; };
    std::vector<reply> replies;

    void on_request_reply(uint64_t cookie, request_status st,
                          std::string_view payload) override
    {
        replies.push_back({cookie, st, std::string(payload)});
    }
};

// Answers immediately, as every sink in the tree does today.
struct inline_sink : request_sink
{
    std::string answer{"+PONG\r\n"};
    int calls{0};
    void serve_request(std::string_view, std::string& out) override
    {
        ++calls;
        out += answer;
    }
};

// Takes the request and answers on a later turn — the shape a socket-backed
// sink has.
struct deferred_sink : request_sink
{
    bool accept{true};
    std::vector<uint64_t>    tickets;
    std::vector<std::string> payloads;
    std::vector<std::string> targets;

    void serve_request(std::string_view, std::string& out) override
    {
        // Never reached for this sink; if the channel ever calls it, the reply
        // is wrong in a way the assertions below will see.
        out += "INLINE-WAS-CALLED";
    }
    bool serves_inline() const override { return false; }
    bool serve_deferred(uint64_t ticket, std::string_view target,
                        std::string_view payload) override
    {
        if (!accept)
            return false;
        tickets.push_back(ticket);
        targets.emplace_back(target);
        payloads.emplace_back(payload);
        return true;
    }
};

// Drive the loop until the channel's wakeup has been delivered and the drain
// has run.  The drain is private and reached only through the ring, which is
// deliberate — this exercises the same path the daemon takes.
void pump(event_loop& loop, int rounds = 8)
{
    for (int i = 0; i < rounds; i++)
        loop.poll_completions(1);
}

}   // namespace

TEST_CASE("a sink that answers inline is unchanged")
{
    event_loop loop;
    REQUIRE(loop.init());
    request_channel ch;
    ch.attach(loop);

    inline_sink sink;
    recording_origin origin;
    ch.register_sink("cache", &sink);

    REQUIRE(ch.post(&origin, 7, "cache", "PING", request_class::client));
    pump(loop);

    REQUIRE(origin.replies.size() == 1);
    CHECK(origin.replies[0].cookie == 7);
    CHECK(origin.replies[0].st == request_status::ok);
    CHECK(origin.replies[0].payload == "+PONG\r\n");
    CHECK(sink.calls == 1);
    CHECK(ch.parked_count() == 0);

    ch.detach();
    loop.shutdown_ring();
}

TEST_CASE("a deferred sink answers nothing until it says so")
{
    event_loop loop;
    REQUIRE(loop.init());
    request_channel ch;
    ch.attach(loop);

    deferred_sink sink;
    recording_origin origin;
    ch.register_sink("remote", &sink);

    REQUIRE(ch.post(&origin, 42, "remote", "GET k", request_class::client));
    pump(loop);

    // The half that matters: the drain has run, the sink has the request, and
    // the origin has heard nothing.  Without the parking this would either be
    // an answer the sink never gave or a stalled loop.
    REQUIRE(sink.tickets.size() == 1);
    CHECK(sink.payloads[0] == "GET k");
    CHECK(sink.targets[0] == "remote");   // the name reaches the sink, not just the bytes
    CHECK(origin.replies.empty());
    CHECK(ch.parked_count() == 1);

    ch.complete_deferred(sink.tickets[0], request_status::ok, "$1\r\nv\r\n");

    REQUIRE(origin.replies.size() == 1);
    CHECK(origin.replies[0].cookie == 42);          // the cookie it posted with
    CHECK(origin.replies[0].st == request_status::ok);
    CHECK(origin.replies[0].payload == "$1\r\nv\r\n");
    CHECK(ch.parked_count() == 0);

    // Answering the same ticket twice is absorbed, not doubled.
    ch.complete_deferred(sink.tickets[0], request_status::ok, "again");
    CHECK(origin.replies.size() == 1);

    ch.detach();
    loop.shutdown_ring();
}

TEST_CASE("order is kept across the deferred path")
{
    event_loop loop;
    REQUIRE(loop.init());
    request_channel ch;
    ch.attach(loop);

    deferred_sink sink;
    recording_origin origin;
    ch.register_sink("remote", &sink);

    for (uint64_t i = 0; i < 4; i++)
        REQUIRE(ch.post(&origin, i, "remote", "q" + std::to_string(i),
                        request_class::client));
    pump(loop);
    REQUIRE(sink.tickets.size() == 4);

    // Completed in the order the sink was given them, which is the order they
    // were posted — the channel promises replies to one origin come back in
    // posting order, and the deferred path must not be the exception.
    for (size_t i = 0; i < 4; i++)
        ch.complete_deferred(sink.tickets[i], request_status::ok,
                             "r" + std::to_string(i));

    REQUIRE(origin.replies.size() == 4);
    for (size_t i = 0; i < 4; i++)
    {
        CHECK(origin.replies[i].cookie == i);
        CHECK(origin.replies[i].payload == "r" + std::to_string(i));
    }

    ch.detach();
    loop.shutdown_ring();
}

TEST_CASE("a sink that will not take the request answers no_target")
{
    event_loop loop;
    REQUIRE(loop.init());
    request_channel ch;
    ch.attach(loop);

    deferred_sink sink;
    sink.accept = false;
    recording_origin origin;
    ch.register_sink("remote", &sink);

    REQUIRE(ch.post(&origin, 5, "remote", "GET k", request_class::client));
    pump(loop);

    // Refused outright: nothing is parked, because nothing is ever going to
    // complete it, and the origin is told so rather than left waiting.
    REQUIRE(origin.replies.size() == 1);
    CHECK(origin.replies[0].st == request_status::no_target);
    CHECK(ch.parked_count() == 0);

    ch.detach();
    loop.shutdown_ring();
}

TEST_CASE("an origin that goes away takes its parked requests with it")
{
    event_loop loop;
    REQUIRE(loop.init());
    request_channel ch;
    ch.attach(loop);

    deferred_sink sink;
    recording_origin origin;
    ch.register_sink("remote", &sink);

    REQUIRE(ch.post(&origin, 9, "remote", "GET k", request_class::client));
    pump(loop);
    REQUIRE(ch.parked_count() == 1);

    // The runtime that asked is removed while the answer is in flight.  This is
    // the case that decides whether the parked table can grow without bound:
    // the ticket must go with the origin, and a late answer must not reach into
    // storage the manager has retired.
    ch.drop_origin(&origin);
    CHECK(ch.parked_count() == 0);

    ch.complete_deferred(sink.tickets[0], request_status::ok, "too late");
    CHECK(origin.replies.empty());

    ch.detach();
    loop.shutdown_ring();
}

// ─── the fallback, and why a worker needs one ───────────────────────────────
//
// The daemon holds every runtime, so a name it does not know does not exist.
// A worker holds one, so a name it does not know is the ordinary case: the
// whole rest of the daemon.  Without a fallback `server --cache c` inside a
// worker resolved to nothing on every request — and not to an error, because
// the runtime never even reached the channel.  The client simply waited.

TEST_CASE("an unknown name goes to the default sink, with the name")
{
    event_loop loop;
    REQUIRE(loop.init());
    request_channel ch;
    ch.attach(loop);

    deferred_sink fallback;
    recording_origin origin;
    ch.set_default_sink(&fallback);          // and nothing registered by name

    REQUIRE(ch.post(&origin, 3, "somewhere-else", "GET k", request_class::client));
    pump(loop);

    // The name has to survive: the fallback is registered under no name at all
    // and forwards for every one of them, so it cannot infer which it is
    // holding.  This is what the sink signature carries the target for.
    REQUIRE(fallback.tickets.size() == 1);
    CHECK(fallback.targets[0] == "somewhere-else");
    CHECK(fallback.payloads[0] == "GET k");
    CHECK(origin.replies.empty());

    ch.complete_deferred(fallback.tickets[0], request_status::ok, "v");
    REQUIRE(origin.replies.size() == 1);
    CHECK(origin.replies[0].cookie == 3);
    CHECK(origin.replies[0].payload == "v");

    ch.detach();
    loop.shutdown_ring();
}

TEST_CASE("a registered name is served here rather than sent to the fallback")
{
    event_loop loop;
    REQUIRE(loop.init());
    request_channel ch;
    ch.attach(loop);

    inline_sink      mine;
    deferred_sink    fallback;
    recording_origin origin;
    ch.register_sink("mine", &mine);
    ch.set_default_sink(&fallback);

    REQUIRE(ch.post(&origin, 1, "mine", "PING", request_class::client));
    pump(loop);

    // Not a preference — a termination condition.  In a worker the fallback is
    // the control socket to the daemon, and the daemon's sink for this worker's
    // own name is the supervisor that would put the request straight back on
    // that socket.  The table entry is what stops the two processes handing one
    // request to each other for ever.
    CHECK(mine.calls == 1);
    CHECK(fallback.tickets.empty());
    REQUIRE(origin.replies.size() == 1);
    CHECK(origin.replies[0].payload == "+PONG\r\n");

    ch.detach();
    loop.shutdown_ring();
}

TEST_CASE("dropping a sink drops it as the fallback too")
{
    event_loop loop;
    REQUIRE(loop.init());
    request_channel ch;
    ch.attach(loop);

    deferred_sink    fallback;
    recording_origin origin;
    ch.set_default_sink(&fallback);
    REQUIRE(ch.default_sink() == &fallback);

    // Otherwise every unknown name would keep pointing at storage the caller
    // has just withdrawn, which is worse than the no_target it replaces.
    ch.drop_sink(&fallback);
    CHECK(ch.default_sink() == nullptr);

    REQUIRE(ch.post(&origin, 1, "gone", "GET k", request_class::client));
    pump(loop);
    REQUIRE(origin.replies.size() == 1);
    CHECK(origin.replies[0].st == request_status::no_target);
    CHECK(fallback.tickets.empty());

    ch.detach();
    loop.shutdown_ring();
}

// ─── the wire a socket-backed sink would use ────────────────────────────────
//
// Deliberately not the target's own client protocol.  The cache's text replies
// are not self-delimiting — ten commands answer over several lines ending in
// `end\n` — so a client could only find the end of one by knowing which command
// produced it.  RESP would be self-delimiting but cannot be produced faithfully:
// process_command() splits positionally and `SET k hello world` stores
// "hello world", so building arrays needs an arity table per command.  A
// length-prefixed frame needs neither: the payload passes through untouched and
// the ticket pairs answer with question.

TEST_CASE("a channel request survives the frame")
{
    using namespace worker_proto;
    const std::string payload = "GET k\nSET a hello world\n";
    auto f = encode_chan_request(4242, "cachename", payload);

    chan_request_wire q;
    REQUIRE(decode_chan_request(f, q));
    CHECK(q.ticket == 4242);
    CHECK(q.target == "cachename");
    // Verbatim, spaces and newlines intact: nothing on this wire parses cache
    // commands, which is the entire reason it was chosen.
    CHECK(q.payload == payload);
}

TEST_CASE("a channel reply survives the frame")
{
    using namespace worker_proto;
    auto g = encode_chan_reply(4242, static_cast<uint8_t>(request_status::ok),
                               "$5\r\nhello\r\n");
    chan_reply_wire p;
    REQUIRE(decode_chan_reply(g, p));
    CHECK(p.ticket == 4242);
    CHECK(p.status == static_cast<uint8_t>(request_status::ok));
    CHECK(p.payload == "$5\r\nhello\r\n");
}

TEST_CASE("a truncated frame is refused rather than read past")
{
    using namespace worker_proto;
    auto f = encode_chan_request(1, "cache", "GET k");
    for (size_t cut : {size_t(0), size_t(3), size_t(7), f.size() - 1})
    {
        chan_request_wire q;
        CHECK_FALSE(decode_chan_request(std::string_view(f).substr(0, cut), q));
    }
}
