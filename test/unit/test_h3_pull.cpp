#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

// The endpoint's own structs are its translation unit's, so the cases below are compiled with it: they make the
// connection and the stream by hand, with no socket, no QUIC and no ring, and drive pull() with a host that does what
// the entrance does inside a take.
#include "shared/http/h3_endpoint.cpp"

#ifdef SOCKETLEY_HTTP3

#include <memory>
#include <string>

namespace
{

using namespace socketley::h3;

// A host whose first take lets go of the stream (gone(), as the entrance's close_pair does) and then has its
// connection dropped, as the flush the entrance asks for there does when it finds the connection dead.
struct letting_go_host final : host
{
    endpoint* ep{nullptr};
    std::shared_ptr<conn> hc;
    bool did{false};
    // What the stream says its connection is, read right after the drop, while pull() still holds the stream.
    const conn* owner_after_drop{reinterpret_cast<const conn*>(1)};
    size_t takes{0};

    uint64_t make_stream(stream&) override { return 1; }
    void start_stream(stream&, socketley::mux::request&, int) override {}
    bool can_take(stream&) override { return true; }
    void take(stream& st, const char*, size_t) override
    {
        ++takes;
        if (did)
            return;
        did = true;
        gone(st);
        ep->drop(hc);
        owner_after_drop = st.owner;
    }
    void write_done(stream&) override {}
    void stream_gone(stream&) override {}
    void count(event) override {}
};

}   // namespace

TEST_CASE("a stream let go of inside a take names no connection once that connection is dropped in the same take")
{
    letting_go_host h;
    endpoint ep;
    ep.h = &h;
    h.ep = &ep;

    auto hc = std::make_shared<conn>();
    hc->ep = &ep;
    ep.conns.push_back(hc);
    ep.per_address[hc->addr] = 1;
    auto owned = std::make_unique<stream>();
    stream* st = owned.get();
    st->sid = 0;
    st->owner = hc.get();
    st->opened = true;
    hc->streams[0] = std::move(owned);
    h.hc = hc;

    // Kept here past the drop, so the connection the stream still named is not freed under pull() even when the
    // stream keeps naming it -- the check below is the defect, not a read of freed memory.
    const std::shared_ptr<conn> kept = hc;
    hc.reset();

    pull(*st, std::string(3 * pull_slice, 'x'));

    CHECK(h.did);
    // One slice taken, and nothing of the stream read past the drop but its window given back to nobody.
    CHECK(h.takes == 1);
    CHECK(h.owner_after_drop == nullptr);
    CHECK(ep.doomed.empty());
    CHECK(kept->dead);
    CHECK(kept->streams.empty());
    CHECK(ep.conns.empty());
}

TEST_CASE("a stream let go of inside a take, its connection still open, gives the rest back to that connection")
{
    // The ordinary path the doomed list was made for: gone() inside a take with the connection staying.
    struct host_gone_only final : host
    {
        size_t takes{0};
        uint64_t make_stream(stream&) override { return 1; }
        void start_stream(stream&, socketley::mux::request&, int) override {}
        bool can_take(stream&) override { return true; }
        void take(stream& st, const char*, size_t) override
        {
            if (++takes == 1)
                gone(st);
        }
        void write_done(stream&) override {}
        void stream_gone(stream&) override {}
        void count(event) override {}
    } h;
    endpoint ep;
    ep.h = &h;

    auto hc = std::make_shared<conn>();
    hc->ep = &ep;
    ep.conns.push_back(hc);
    auto owned = std::make_unique<stream>();
    stream* st = owned.get();
    st->sid = 4;
    st->owner = hc.get();
    st->opened = true;
    hc->streams[4] = std::move(owned);

    pull(*st, std::string(2 * pull_slice, 'y'));

    CHECK(h.takes == 1);
    CHECK(hc->streams.empty());
    CHECK(ep.doomed.empty());
    CHECK_FALSE(hc->dead);
}

#else

TEST_CASE("HTTP/3 is not built in")
{
    CHECK(true);
}

#endif
