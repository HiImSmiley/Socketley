// Fuzz target: the tunnel's multiplexing (socketley/shared/net/tunnel_mux.h), which an edge runs on every byte an
// agent or a person sends once they have upgraded, and an agent on every byte the edge sends.
//
// The first input byte picks the side (bit 0: the one that dialled) and how the rest is cut (the next byte the
// size of each piece, 0 for whole).
//
// Properties checked, beyond "did it crash":
//   * a session that refused the bytes says why, and refuses everything after;
//   * what it holds of a frame not yet whole is never more than one frame's header and payload;
//   * it never holds more streams than its limit, nor credit past 2^31;
//   * the same bytes give the same events and the same answer whether fed whole, cut, or a byte at a time.
//
// WHAT THIS TARGET DOES NOT COVER: the sockets each stream is carried to (tunnel_run.cpp), and the upgrade before it.

#include "fuzz_common.h"
#include "shared/net/tunnel_mux.h"

#include <string>
#include <vector>

namespace
{

namespace tn = socketley::tunnel;

constexpr uint32_t max_streams = 8;

// Every event as a line, and an answer to some of them, so the output depends on what was read.
struct reactor : tn::events
{
    tn::session* s{nullptr};
    std::string* out{nullptr};
    std::string log;
    std::vector<uint32_t> streams;

    void on_hello(const tn::fields& f) override { log += "hello " + std::to_string(f.size()) + "\n"; }
    void on_open(uint32_t id, std::string_view t, std::string_view p) override
    {
        log += "open " + std::to_string(id) + " " + std::string(t) + " " + std::to_string(p.size()) + "\n";
        streams.push_back(id);
        if (t.size() % 3 == 0)
            s->reset(id, tn::reset_code::refused, *out);
        else
            s->send(id, t, *out);
    }
    void on_data(uint32_t id, std::string_view b) override
    {
        log += "data " + std::to_string(id) + " " + std::to_string(b.size()) + "\n";
        s->consumed(id, b.size(), *out);
        if (!b.empty() && b[0] == 'c')
            s->close(id, *out);
    }
    void on_close(uint32_t id) override { log += "close " + std::to_string(id) + "\n"; }
    void on_reset(uint32_t id, tn::reset_code c) override
    {
        log += "reset " + std::to_string(id) + " " + std::to_string(static_cast<int>(c)) + "\n";
    }
    void on_window(uint32_t id) override { log += "window " + std::to_string(id) + "\n"; }
    void on_pong(std::string_view) override { log += "pong\n"; }
    void on_goaway(std::string_view w) override { log += "goaway " + std::to_string(w.size()) + "\n"; }
    void on_datagram(uint32_t f, std::string_view svc, std::string_view b) override
    {
        log += "datagram " + std::to_string(f) + " " + std::string(svc) + " " + std::to_string(b.size()) + "\n";
    }
};

struct run
{
    reactor r;
    tn::session s;
    std::string out;
    bool ok{true};
    explicit run(bool dialled) : s(dialled, r, max_streams)
    {
        r.s = &s;
        r.out = &out;
    }
    void feed(std::string_view bytes)
    {
        if (!ok)
        {
            FUZZ_CHECK(!s.feed(bytes, out), "a session that refused the bytes took more after");
            return;
        }
        ok = s.feed(bytes, out);
        if (!ok)
            FUZZ_CHECK(!s.error().empty(), "a session refused the bytes without saying why");
        FUZZ_CHECK(s.buffered() < tn::header_size + tn::max_payload, "more held than one frame");
        FUZZ_CHECK(s.stream_count() <= max_streams, "more streams than the limit");
        for (const uint32_t id : r.streams)
            FUZZ_CHECK(s.credit(id) <= 0x7fffffffu, "credit past 2^31");
    }
};

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    data = ::fuzz::never_null(data);
    ::fuzz::set_current(data, size);
    if (size < 2 || size > 512 * 1024)
        return 0;
    const bool dialled = data[0] & 1;
    const size_t piece = data[1];
    const std::string_view bytes(reinterpret_cast<const char*>(data) + 2, size - 2);

    run whole(dialled);
    whole.feed(bytes);

    run cut(dialled);
    if (piece == 0)
        cut.feed(bytes);
    else
        for (size_t at = 0; at < bytes.size(); at += piece)
            cut.feed(bytes.substr(at, piece));
    FUZZ_CHECK(cut.ok == whole.ok, "the same bytes were refused cut and taken whole, or the other way");
    if (whole.ok)
    {
        FUZZ_CHECK(cut.r.log == whole.r.log, "the same bytes gave other events when cut");
        FUZZ_CHECK(cut.out == whole.out, "the same bytes gave another answer when cut");
    }

    if (bytes.size() <= 4096)
    {
        run bytewise(dialled);
        for (const char c : bytes)
            bytewise.feed(std::string_view(&c, 1));
        FUZZ_CHECK(bytewise.ok == whole.ok, "fed a byte at a time the bytes were judged otherwise");
        if (whole.ok)
            FUZZ_CHECK(bytewise.r.log == whole.r.log && bytewise.out == whole.out,
                       "fed a byte at a time the bytes gave other events or another answer");
    }
    return 0;
}
