// Fuzz target: an HTTP/2 connection as the entrance and the storage read one (socketley/shared/http/h2_driver.h,
// h2_session.h, h2_frame.h, mux_head.cpp, hpack.cpp).
//
// Reachable by anyone who can open a connection to an entrance with TLS or to a storage runtime, before any sign-in:
// every byte after the preface is the client's. The reader, the flow control, the flood counters and the turn that
// frames answers are the runtimes' own; the host under them is this file's, a stream that answers as the input says
// and reads its body at once.
//
// An input is: one byte of how the host behaves, one byte of how the bytes are cut into reads, then the client's
// bytes. Bit 0 of the first byte puts the preface and an empty SETTINGS before them, so a mutation spends itself on
// frames rather than on the 24 bytes every connection begins with.
//
// What must hold, beside no report from the sanitizers:
//
//   * No more streams are open than the session allows, and none is made after the connection was told to go.
//   * What is kept between reads is less than one frame, and a header block being gathered stays under its bound.
//   * This side never has more to receive than its windows say, on the connection or on a stream, and never sends
//     more DATA than the windows the client gave: 65535 and every WINDOW_UPDATE of the connection it sent.
//   * Everything written is whole frames no longer than the client's MAX_FRAME_SIZE allows, of types a server sends,
//     and DATA only on a stream the client opened.
//   * What the client's frames make this side queue of its own (acks, resets, updates, GOAWAY) is bounded by how
//     many frames it sent, so a peer that does not read cannot grow the queue faster than it writes.
//   * Nothing of a stream is written after a GOAWAY for an error: the connection is over (RFC 9113 5.4.1), and the
//     storage went on sending a file behind one.

#include <algorithm>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "fuzz_common.h"

#include "../../socketley/shared/http/h2_driver.h"

namespace
{

namespace h2 = socketley::h2;
namespace mux = socketley::mux;

struct node
{
    std::unique_ptr<h2::stream> h2s{new h2::stream};
    bool gone{false};
};
using handle = std::shared_ptr<node>;
using session = h2::session<handle>;

struct host
{
    session& s;
    uint8_t how;
    bool erred{false};
    bool closed{false};
    size_t made_after_error{0};
    std::unordered_set<uint32_t> opened;

    host(session& of, uint8_t behaves) : s(of), how(behaves) {}

    bool gone() const { return closed; }
    void close_now() { closed = true; }
    void want_more() {}
    void conn_error(uint32_t code)
    {
        erred = true;
        s.goaway_sent = true;
        h2::put_goaway(s.ctl, s.last_sid, code);
        if (code != h2::NO_ERROR)
        {
            s.close_when_flushed = true;
            s.dying = true;
        }
    }
    // As both runtimes do: the stream leaves the session, and what it held of the connection's window comes back.
    void stream_gone(const handle& h)
    {
        if (h->gone)
            return;
        h->gone = true;
        h2::stream& st = *h->h2s;
        if (!s.dying)
            h2::give_back(s, static_cast<uint32_t>(st.rx_bytes));
        s.streams.erase(st.sid);
    }
    handle make(uint32_t)
    {
        if (erred)
            ++made_after_error;
        // A host that cannot make a stream, now and then.
        if ((how & 0x80) && (opened.size() % 5) == 4)
            return nullptr;
        return std::make_shared<node>();
    }
    void start(const handle& h, mux::request& mr, int answer_status)
    {
        h2::stream& st = *h->h2s;
        opened.insert(st.sid);
        // The head a runtime's own parser reads: a request line, fields, an empty line, and nothing a field's value
        // could have ended a line with.
        if (answer_status == 0)
        {
            FUZZ_CHECK(mr.line.size() >= 4 && mr.line.ends_with("\r\n\r\n"), "a head that does not end in an empty line");
            FUZZ_CHECK(mr.line.find("\r\n\r\n") == mr.line.size() - 4, "a head with an empty line inside it");
            FUZZ_CHECK(mr.line.find('\0') == std::string::npos, "a head with a NUL in it");
            const std::string_view first(mr.line.data(), mr.line.find("\r\n"));
            FUZZ_CHECK(std::count(first.begin(), first.end(), ' ') == 2 && first.ends_with(" HTTP/1.1"),
                       "a request line that is not three words");
            for (size_t at = 0; at < mr.line.size(); ++at)
                if (mr.line[at] == '\n')
                    FUZZ_CHECK(at > 0 && mr.line[at - 1] == '\r', "a head with a bare LF");
                else if (mr.line[at] == '\r')
                    FUZZ_CHECK(at + 1 < mr.line.size() && mr.line[at + 1] == '\n', "a head with a lone CR");
        }
        // The answer, as a runtime's HTTP/1.1 writer makes it: none yet, one with a length, or one in chunks.
        std::string answer;
        switch (answer_status ? 1 : (how >> 1) & 3)
        {
            case 0: return;
            case 1: answer = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: keep-alive\r\nContent-Length: 5\r\n\r\nhello"; break;
            case 2: answer = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n" + std::string("4000\r\n") +
                             std::string(0x4000, 'x') + "\r\n0\r\n\r\n"; break;
            case 3: answer = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"; break;
        }
        h2::frame_answer(s, st, std::move(answer));
        st.end_pending = true;
        h2::enqueue(s, st);
    }
    // The body is read as it comes, and the windows given back by halves, as a runtime's pull does.
    void body(const handle& h, std::string_view d)
    {
        h2::stream& st = *h->h2s;
        st.rx_unacked += static_cast<uint32_t>(d.size());
        if (!st.remote_closed && st.rx_unacked >= h2::stream_window / 2)
        {
            h2::put_window_update(s.ctl, st.sid, st.rx_unacked);
            st.recv_avail += st.rx_unacked;
            st.rx_unacked = 0;
        }
        h2::give_back(s, static_cast<uint32_t>(d.size()));
    }
    void body_end(const handle&) {}
    void count(h2::event) {}
};

// The client's frames as far as they can be told from its bytes: how many, and what its connection's
// WINDOW_UPDATEs add up to, which bounds what this side may send whether or not each was taken.
struct sent
{
    uint64_t frames{0};
    uint64_t credit{h2::default_window};
    uint32_t max_frame{h2::default_frame};
};

sent survey(std::string_view in)
{
    sent out;
    while (in.size() >= h2::head_len)
    {
        const h2::frame_head h = h2::parse_head(in.data());
        ++out.frames;
        if (in.size() < h2::head_len + h.len)
            break;
        const std::string_view pl = in.substr(h2::head_len, h.len);
        if (h.type == h2::WINDOW_UPDATE && h.sid == 0 && h.len == 4)
            out.credit += h2::rd32(pl.data()) & 0x7fffffffu;
        if (h.type == h2::SETTINGS)
            for (size_t i = 0; i + 6 <= pl.size(); i += 6)
                if ((static_cast<uint8_t>(pl[i]) << 8 | static_cast<uint8_t>(pl[i + 1])) == h2::MAX_FRAME_SIZE)
                    out.max_frame = std::max(out.max_frame, std::min<uint32_t>(h2::rd32(pl.data() + i + 2), 64 * 1024));
        in.remove_prefix(h2::head_len + h.len);
    }
    // A cut may fall anywhere, and a frame it splits is counted once more.
    ++out.frames;
    return out;
}

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz::current_data() = data;
    fuzz::current_size() = size;
    if (size < 2 || size > (256u << 10))
        return 0;
    const uint8_t how = data[0];
    const size_t cut = 1 + data[1] * 37u;
    std::string in;
    if (how & 1)
    {
        in.assign(h2::preface);
        h2::put_settings(in, {});
    }
    in.append(reinterpret_cast<const char*>(data) + 2, size - 2);
    const bool spoke = std::string_view(in).starts_with(h2::preface);
    const sent client = survey(spoke ? std::string_view(in).substr(h2::preface.size()) : std::string_view());

    session s;
    s.max_live = (how & 0x40) ? 8 : h2::max_streams;
    s.began = s.window_start = std::chrono::steady_clock::now();
    host h(s, how);
    std::string frag, wire;
    uint64_t own = 0;

    const auto turn = [&] {
        own += s.ctl.size();
        // The wire takes everything, so a turn is held back by the client's windows alone.
        h2::drain(s, wire, 0, s.out_high, [](const handle&) {}, [&](const handle& st) { h.stream_gone(st); },
                  [](const handle&) {});
    };

    for (size_t at = 0; at < in.size() && !h.closed; at += cut)
    {
        const size_t n = std::min(cut, in.size() - at);
        const bool read = h2::feed(s, frag, in.data() + at, n, 32 * 1024, h);
        FUZZ_CHECK(frag.size() < h2::preface.size() + h2::head_len + h2::default_frame + cut,
                   "more kept between reads than a frame and a read");
        FUZZ_CHECK(s.cont_buf.size() <= h2::block_max + h2::default_frame, "a header block gathered past its bound");
        FUZZ_CHECK(s.streams.size() <= s.max_live, "more streams open than the session allows");
        FUZZ_CHECK(s.recv_avail >= 0, "the connection took more than its window");
        for (const auto& [sid, st] : s.streams)
        {
            FUZZ_CHECK(st->h2s->recv_avail >= 0, "a stream took more than its window");
            FUZZ_CHECK(st->h2s->send_win <= h2::max_window, "a stream's window past 2^31-1");
        }
        FUZZ_CHECK(s.send_win <= h2::max_window, "the connection's window past 2^31-1");
        if (read)
            for (int i = 0; i < 4; ++i)
                turn();
    }
    for (int i = 0; i < 8 && !h.closed; ++i)
        turn();
    FUZZ_CHECK(h.made_after_error == 0, "a stream made after the connection was told to go");

    // Whole frames a server sends, DATA within the client's windows and on its streams alone.
    uint64_t data_out = 0;
    bool over = false;
    for (std::string_view w = wire; !w.empty();)
    {
        FUZZ_CHECK(w.size() >= h2::head_len, "a frame written with no whole head");
        const h2::frame_head f = h2::parse_head(w.data());
        FUZZ_CHECK(w.size() >= h2::head_len + f.len, "a frame written shorter than its length");
        FUZZ_CHECK(f.len <= client.max_frame, "a frame written longer than the client takes");
        FUZZ_CHECK(f.type == h2::DATA || f.type == h2::HEADERS || f.type == h2::CONTINUATION || f.type == h2::RST_STREAM ||
                       f.type == h2::SETTINGS || f.type == h2::PING || f.type == h2::GOAWAY || f.type == h2::WINDOW_UPDATE,
                   "a frame written of a type no server sends");
        if (f.type == h2::DATA || f.type == h2::HEADERS || f.type == h2::CONTINUATION)
            FUZZ_CHECK(h.opened.count(f.sid) == 1, "an answer on a stream the client never opened");
        if (f.type == h2::DATA)
            data_out += f.len;
        if (f.type == h2::DATA || f.type == h2::HEADERS || f.type == h2::CONTINUATION)
            FUZZ_CHECK(!over, "a stream's frame written after a GOAWAY for an error");
        if (f.type == h2::GOAWAY && f.len >= 8 && h2::rd32(w.data() + h2::head_len + 4) != h2::NO_ERROR)
            over = true;
        w.remove_prefix(h2::head_len + f.len);
    }
    FUZZ_CHECK(data_out <= client.credit, "more DATA sent than the windows the client gave");
    // A reset, an ack or an update is at most 17 bytes, a GOAWAY as many, and one frame of the client draws one.
    FUZZ_CHECK(own <= 64 + client.frames * 2 * (h2::head_len + 8), "more queued of this side's own than the client's frames drew");
    return 0;
}
