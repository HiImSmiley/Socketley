// HTTP/2, RFC 9113, for the storage runtime. A connection that negotiates it by ALPN, or opens with its preface in
// the clear, reads frames from then on; each request is a stream, and each stream is a conn of its own with no
// socket. Its head is decoded by HPACK and written back as the HTTP/1.1 head parse_head() already reads, its body's
// DATA is handed to its phase as a recv's bytes would be, and what it writes -- an HTTP/1.1 answer, whoever built it
// -- is read back into HEADERS and DATA here. So every operation runs as it does over HTTP/1.1, and only these edges
// know the difference.
//
// Flow control follows the put: a stream's window is given back only as its phase takes the bytes, so a disk that
// cannot keep up stops the client, as a full socket buffer does for HTTP/1.1. Going out, a stream's bytes are framed
// as the peer's windows allow, a frame per stream in turn, and a stream is told its write is done -- which asks it for
// the next piece of a file -- when its bytes have gone into the connection's queue, which is held under a bound.
#include "storage_run.h"
#include "storage_instance.h"

#include <algorithm>
#include <charconv>
#include <deque>
#include <unordered_map>

#include "../../shared/h2_frame.h"
#include "../../shared/hpack.h"
#include "../../shared/logging.h"

namespace socketley::storage
{

namespace
{

// What a stream may send before its window is given back, which is what a browser's upload has in flight on it.
constexpr uint32_t stream_window   = 4u << 20;
// The connection's, across its streams: several uploads at once each keep their window full.
constexpr uint32_t conn_window     = 32u << 20;
constexpr uint32_t max_streams     = 128;
constexpr size_t   header_list_max = 64 * 1024;
// A header block gathered over CONTINUATIONs: past this, or past this many frames, it is a flood.
constexpr size_t   block_max       = header_list_max + 16 * 1024;
constexpr int      continuations_max = 64;
// What waits in the connection's queue before more frames are put in it.
constexpr size_t   out_high        = 256 * 1024;
// What one turn hands a stream's phase.
constexpr size_t   pull_slice      = 64 * 1024;
// Seconds a TLS connection that chose HTTP/2 has to send its preface.
constexpr long     preface_secs    = 10;
// Control frames the peer may make this side answer, and streams it may reset, in each ten seconds.
constexpr uint32_t pings_max       = 200;
constexpr uint32_t settings_max    = 200;
constexpr uint32_t resets_max      = 400;
constexpr uint32_t empty_data_max  = 1000;
constexpr size_t   max_head        = 32 * 1024;
// A session left with frames it cannot send, as an HTTP/1.1 answer that cannot be written is.
constexpr long     write_stall_secs = 120;

}   // namespace

struct h2_stream
{
    uint32_t sid{0};
    // DATA received and not yet handed to the phase, and how far it has been.
    std::string rx;
    size_t      rx_off{0};
    // What this side may still receive on the stream, and what was taken and not yet given back.
    int64_t     recv_avail{stream_window};
    uint32_t    rx_unacked{0};
    bool        remote_closed{false};
    // A body with no content-length is handed over as chunked framing, which the phases read.
    bool        synth_chunked{false};
    bool        chunk_end_given{false};
    bool        has_cl{false};
    uint64_t    cl{0};
    uint64_t    data_in{0};

    // Going out: HEADERS already framed, which no window holds, then the body's bytes waiting for windows.
    std::string hdr;
    std::string tx;
    size_t      tx_off{0};
    int64_t     send_win{h2::default_window};
    enum class out_state : uint8_t { head, body, dechunk } os{out_state::head};
    std::string head_acc;
    http_chunked_decoder dechunk;
    std::string dechunk_in;
    bool        end_pending{false};
    bool        local_closed{false};
    // RST_STREAM was sent or received, so none is sent again.
    bool        reset{false};
    bool        queued{false};

    size_t tx_left() const { return tx.size() - tx_off; }
};

struct h2_session
{
    bool     preface_ok{false};
    bool     got_settings{false};
    uint32_t peer_init_win{h2::default_window};
    uint32_t peer_max_frame{h2::default_frame};
    hpack::decoder dec{4096};
    int64_t  send_win{h2::default_window};
    int64_t  recv_avail{conn_window};
    uint32_t recv_unacked{0};
    uint32_t last_sid{0};
    bool     goaway_sent{false};
    bool     peer_goaway{false};
    bool     close_when_flushed{false};
    bool     dying{false};
    bool     first_block{true};
    // A header block being gathered over CONTINUATIONs.
    uint32_t cont_sid{0};
    std::string cont_buf;
    bool     cont_end_stream{false};
    bool     cont_trailers{false};
    // The block's stream named itself as its dependency, and is reset once the block is read.
    bool     cont_refuse{false};
    int      cont_frames{0};

    std::unordered_map<uint32_t, std::shared_ptr<conn>> streams;
    // Streams with something to send, in turn.
    std::deque<uint32_t> rr;
    // Frames of the connection's own, sent before any stream's.
    std::string ctl;

    std::chrono::steady_clock::time_point began{};
    std::chrono::steady_clock::time_point window_start{};
    uint32_t pings{0}, settings{0}, resets{0}, empty_data{0}, strays{0};
};

void h2_session_free::operator()(h2_session* s) const { delete s; }
void h2_stream_free::operator()(h2_stream* s) const { delete s; }

namespace
{

size_t unsent(const conn& c)
{
    return (c.wbuf.size() - c.woff) + (c.wq.size() - c.wq_off);
}

void enqueue(h2_session& s, h2_stream& st)
{
    if (st.queued)
        return;
    st.queued = true;
    s.rr.push_back(st.sid);
}

// The flood counters start again every ten seconds.
void tick_window(h2_session& s)
{
    const auto now = std::chrono::steady_clock::now();
    if (now - s.window_start > std::chrono::seconds(10))
    {
        s.window_start = now;
        s.pings = s.settings = s.resets = s.empty_data = s.strays = 0;
    }
}

bool lower_token(std::string_view n)
{
    if (n.empty())
        return false;
    for (const char ch : n)
        if ((ch >= 'A' && ch <= 'Z') || static_cast<uint8_t>(ch) <= 0x20 || ch == ':' || ch == 0x7f)
            return false;
    return true;
}

bool clean_value(std::string_view v)
{
    for (const char ch : v)
        if (ch == '\0' || ch == '\r' || ch == '\n')
            return false;
    return v.empty() || (v.front() != ' ' && v.front() != '\t' && v.back() != ' ' && v.back() != '\t');
}

}   // namespace

// ─── The session ────────────────────────────────────────────────────────────

void storage_run::h2_start(const std::shared_ptr<conn>& c)
{
    c->ph = phase::h2;
    c->h2.reset(new h2_session);
    h2_session& s = *c->h2;
    s.began = s.window_start = std::chrono::steady_clock::now();
    // The settings this side reads by, and the connection's window opened past the 64 KiB it starts with.
    h2::put_settings(s.ctl, {{h2::MAX_CONCURRENT_STREAMS, max_streams},
                             {h2::INITIAL_WINDOW_SIZE, stream_window},
                             {h2::MAX_HEADER_LIST_SIZE, static_cast<uint32_t>(header_list_max)},
                             {h2::ENABLE_PUSH, 0}});
    h2::put_window_update(s.ctl, 0, conn_window - h2::default_window);
    ++m_c.h2_conns;
    h2_schedule(c);
}

bool storage_run::h2_preface_in(const std::shared_ptr<conn>& c, const char* p, size_t n)
{
    const std::string_view pre = h2::preface;
    const size_t have = c->in.size();
    const size_t look = std::min(pre.size(), have + n);
    for (size_t i = 0; i < look; ++i)
    {
        const char ch = i < have ? c->in[i] : p[i - have];
        if (ch != pre[i])
        {
            // A client that began HTTP/2's request line and then got it wrong speaks neither; it is not answered.
            if (i >= 14)
            {
                close_conn(c);
                return true;
            }
            return false;
        }
    }
    if (have + n < pre.size())
    {
        c->in.append(p, n);
        arm_read(c);
        return true;
    }
    const size_t used = pre.size() - have;
    c->in.clear();
    h2_start(c);
    c->h2->preface_ok = true;
    if (n > used)
        h2_in(c, p + used, n - used);
    else
        arm_read(c);
    return true;
}

void storage_run::h2_goaway(const std::shared_ptr<conn>& c, uint32_t code, bool now)
{
    if (!c->h2 || c->dead)
        return;
    h2_session& s = *c->h2;
    if (!s.goaway_sent)
        ++m_c.h2_goaways;
    s.goaway_sent = true;
    if (!now)
    {
        h2::put_goaway(s.ctl, s.last_sid, code);
        if (code != h2::NO_ERROR)
        {
            s.close_when_flushed = true;
            s.dying = true;
        }
        h2_schedule(c);
        return;
    }
    // The runtime stops: one try at the socket, without waiting, as a TLS alert is sent.
    if (c->wr_pending || c->fd < 0)
        return;
    std::string g;
    h2::put_goaway(g, s.last_sid, code);
    if (c->ssl)
    {
        c->wq += g;
        if (!tls_encrypt(c))
            return;
        g.assign(c->wbuf, c->woff, std::string::npos);
    }
    else if (c->woff < c->wbuf.size())
        return;
    const ssize_t sent = ::send(c->fd, g.data(), g.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
    if (sent < 0) {}
}

void storage_run::h2_parent_gone(const std::shared_ptr<conn>& c)
{
    h2_session& s = *c->h2;
    s.dying = true;
    std::vector<std::shared_ptr<conn>> all;
    all.reserve(s.streams.size());
    for (auto& [sid, sc] : s.streams)
        all.push_back(sc);
    for (auto& sc : all)
    {
        close_conn(sc);
        sc->h2_parent = nullptr;
    }
    s.streams.clear();
    s.rr.clear();
}

void storage_run::h2_sweep(const std::shared_ptr<conn>& c, std::chrono::steady_clock::time_point now)
{
    h2_session& s = *c->h2;
    if (!s.preface_ok)
    {
        if (now - s.began > std::chrono::seconds(preface_secs))
        {
            ++m_c.timeouts;
            close_conn(c);
        }
        return;
    }
    const auto quiet = std::chrono::duration_cast<std::chrono::seconds>(now - c->last_progress).count();
    if (s.close_when_flushed && quiet > write_stall_secs)
    {
        close_conn(c);
        return;
    }
    // A session with no stream open is idle, and goes as an idle HTTP/1.1 connection does, telling the client.
    const uint32_t idle = m_owner.get_idle_timeout();
    if (s.streams.empty() && idle > 0 && quiet > static_cast<long>(idle))
    {
        ++m_c.timeouts;
        h2_goaway(c, h2::NO_ERROR, false);
        s.close_when_flushed = true;
        if (unsent(*c) == 0 && !c->wr_pending)
            close_conn(c);
    }
}

// ─── Frames in ──────────────────────────────────────────────────────────────

void storage_run::h2_in(const std::shared_ptr<conn>& c, const char* p, size_t n)
{
    h2_session& s = *c->h2;
    if (s.dying)
        return;
    c->in.append(p, n);
    size_t at = 0;
    auto conn_error = [&](uint32_t code)
    {
        c->in.clear();
        at = 0;
        h2_goaway(c, code, false);
    };
    // A stream's own error ends it alone.
    auto stream_error = [&](uint32_t sid, uint32_t code)
    {
        h2::put_rst(s.ctl, sid, code);
        ++m_c.h2_resets_out;
        if (auto it = s.streams.find(sid); it != s.streams.end())
        {
            auto sc = it->second;
            sc->h2s->reset = true;
            close_conn(sc);
        }
    };

    if (!s.preface_ok)
    {
        const std::string_view pre = h2::preface;
        const size_t look = std::min(pre.size(), c->in.size());
        if (c->in.compare(0, look, pre.substr(0, look)) != 0)
        {
            close_conn(c);
            return;
        }
        if (c->in.size() < pre.size())
        {
            arm_read(c);
            return;
        }
        s.preface_ok = true;
        at = pre.size();
    }

    while (!c->dead && !s.dying && c->in.size() - at >= h2::head_len)
    {
        const h2::frame_head h = h2::parse_head(c->in.data() + at);
        if (h.len > h2::default_frame)
        {
            conn_error(h2::FRAME_SIZE_ERROR);
            break;
        }
        if (c->in.size() - at < h2::head_len + h.len)
            break;
        std::string_view pl(c->in.data() + at + h2::head_len, h.len);
        at += h2::head_len + h.len;
        tick_window(s);

        // The first frame is the client's SETTINGS; between HEADERS and its END_HEADERS only CONTINUATION.
        if (!s.got_settings && (h.type != h2::SETTINGS || (h.flags & h2::ACK)))
        {
            conn_error(h2::PROTOCOL_ERROR);
            break;
        }
        if (s.cont_sid && (h.type != h2::CONTINUATION || h.sid != s.cont_sid))
        {
            conn_error(h2::PROTOCOL_ERROR);
            break;
        }

        switch (h.type)
        {
            case h2::DATA:
            {
                if (h.sid == 0)
                {
                    conn_error(h2::PROTOCOL_ERROR);
                    break;
                }
                if (h.sid > s.last_sid)
                {
                    conn_error(h2::PROTOCOL_ERROR);
                    break;
                }
                if (static_cast<int64_t>(h.len) > s.recv_avail)
                {
                    conn_error(h2::FLOW_CONTROL_ERROR);
                    break;
                }
                s.recv_avail -= h.len;
                auto it = s.streams.find(h.sid);
                if (it == s.streams.end() || it->second->h2s->remote_closed)
                {
                    // The bytes are the connection's again, and DATA on a closed stream is STREAM_CLOSED (RFC 9113
                    // 5.1); the answers to a peer that keeps sending such are bounded like its resets.
                    s.recv_unacked += h.len;
                    if (++s.strays <= resets_max)
                        stream_error(h.sid, h2::STREAM_CLOSED);
                    break;
                }
                auto sc = it->second;
                h2_stream& st = *sc->h2s;
                if (static_cast<int64_t>(h.len) > st.recv_avail)
                {
                    s.recv_unacked += h.len;
                    stream_error(h.sid, h2::FLOW_CONTROL_ERROR);
                    break;
                }
                st.recv_avail -= h.len;
                if (!h2::unpad(h, pl))
                {
                    conn_error(h2::PROTOCOL_ERROR);
                    break;
                }
                // Padding is given back at once; the payload when the phase takes it.
                const uint32_t pad = h.len - static_cast<uint32_t>(pl.size());
                s.recv_unacked += pad;
                st.rx_unacked  += pad;
                if (pl.empty() && !(h.flags & h2::END_STREAM) && ++s.empty_data > empty_data_max)
                {
                    conn_error(h2::ENHANCE_YOUR_CALM);
                    break;
                }
                st.data_in += pl.size();
                if (st.has_cl && st.data_in > st.cl)
                {
                    s.recv_unacked += static_cast<uint32_t>(pl.size());
                    stream_error(h.sid, h2::PROTOCOL_ERROR);
                    break;
                }
                if (st.rx_off == st.rx.size())
                {
                    st.rx.clear();
                    st.rx_off = 0;
                }
                st.rx.append(pl);
                if (h.flags & h2::END_STREAM)
                {
                    st.remote_closed = true;
                    if (st.has_cl && st.data_in != st.cl)
                    {
                        stream_error(h.sid, h2::PROTOCOL_ERROR);
                        break;
                    }
                }
                sc->last_progress = std::chrono::steady_clock::now();
                h2_pull(sc);
                break;
            }
            case h2::HEADERS:
            {
                if (h.sid == 0 || !(h.sid & 1))
                {
                    conn_error(h2::PROTOCOL_ERROR);
                    break;
                }
                // A stream may not depend on itself (RFC 9113 5.3.1), which is its own error; the block is still
                // decoded, so the table stays in step.
                bool self_dependent = false;
                if (h.flags & h2::PRIORITY_F)
                {
                    const size_t at_dep = (h.flags & h2::PADDED) ? 1 : 0;
                    self_dependent = pl.size() >= at_dep + 4 && (h2::rd32(pl.data() + at_dep) & 0x7fffffffu) == h.sid;
                }
                if (!h2::unpad(h, pl))
                {
                    conn_error(h2::PROTOCOL_ERROR);
                    break;
                }
                bool trailers = false;
                if (h.sid <= s.last_sid)
                {
                    auto it = s.streams.find(h.sid);
                    // Trailers end the stream they follow; HEADERS on a stream that is closed is an error.
                    if (it == s.streams.end() || it->second->h2s->remote_closed)
                    {
                        conn_error(h2::STREAM_CLOSED);
                        break;
                    }
                    if (!(h.flags & h2::END_STREAM))
                    {
                        conn_error(h2::PROTOCOL_ERROR);
                        break;
                    }
                    trailers = true;
                }
                s.cont_sid        = h.sid;
                s.cont_buf.assign(pl);
                s.cont_end_stream = h.flags & h2::END_STREAM;
                s.cont_trailers   = trailers;
                s.cont_frames     = 0;
                s.cont_refuse     = self_dependent;
                if (h.flags & h2::END_HEADERS)
                {
                    const uint32_t sid = s.cont_sid;
                    s.cont_sid = 0;
                    if (!h2_headers(c, sid))
                        conn_error(h2::COMPRESSION_ERROR);
                }
                break;
            }
            case h2::CONTINUATION:
            {
                if (!s.cont_sid)
                {
                    conn_error(h2::PROTOCOL_ERROR);
                    break;
                }
                s.cont_buf.append(pl);
                if (s.cont_buf.size() > block_max || ++s.cont_frames > continuations_max)
                {
                    conn_error(h2::ENHANCE_YOUR_CALM);
                    break;
                }
                if (h.flags & h2::END_HEADERS)
                {
                    const uint32_t sid = s.cont_sid;
                    s.cont_sid = 0;
                    if (!h2_headers(c, sid))
                        conn_error(h2::COMPRESSION_ERROR);
                }
                break;
            }
            case h2::PRIORITY:
                if (h.sid == 0)
                    conn_error(h2::PROTOCOL_ERROR);
                else if (h.len != 5)
                    stream_error(h.sid, h2::FRAME_SIZE_ERROR);
                else if ((h2::rd32(pl.data()) & 0x7fffffffu) == h.sid)
                    stream_error(h.sid, h2::PROTOCOL_ERROR);
                break;
            case h2::RST_STREAM:
            {
                if (h.sid == 0 || h.sid > s.last_sid)
                {
                    conn_error(h2::PROTOCOL_ERROR);
                    break;
                }
                if (h.len != 4)
                {
                    conn_error(h2::FRAME_SIZE_ERROR);
                    break;
                }
                ++m_c.h2_resets_in;
                // Streams opened and reset at once cost this side their work and the client nothing.
                if (++s.resets > resets_max)
                {
                    conn_error(h2::ENHANCE_YOUR_CALM);
                    break;
                }
                if (auto it = s.streams.find(h.sid); it != s.streams.end())
                {
                    auto sc = it->second;
                    sc->h2s->reset = true;
                    close_conn(sc);
                }
                break;
            }
            case h2::SETTINGS:
            {
                if (h.sid != 0)
                {
                    conn_error(h2::PROTOCOL_ERROR);
                    break;
                }
                if (h.flags & h2::ACK)
                {
                    if (h.len != 0)
                        conn_error(h2::FRAME_SIZE_ERROR);
                    break;
                }
                if (h.len % 6)
                {
                    conn_error(h2::FRAME_SIZE_ERROR);
                    break;
                }
                if (++s.settings > settings_max)
                {
                    conn_error(h2::ENHANCE_YOUR_CALM);
                    break;
                }
                bool bad = false;
                for (size_t i = 0; i + 6 <= pl.size() && !bad; i += 6)
                {
                    const uint16_t id = static_cast<uint16_t>(static_cast<uint8_t>(pl[i]) << 8 | static_cast<uint8_t>(pl[i + 1]));
                    const uint32_t v = h2::rd32(pl.data() + i + 2);
                    if (id == h2::ENABLE_PUSH && v > 1)
                        bad = true, conn_error(h2::PROTOCOL_ERROR);
                    else if (id == h2::INITIAL_WINDOW_SIZE)
                    {
                        if (v > h2::max_window)
                        {
                            bad = true;
                            conn_error(h2::FLOW_CONTROL_ERROR);
                            break;
                        }
                        // Every open stream's window moves by the difference, and may go below zero.
                        const int64_t delta = static_cast<int64_t>(v) - s.peer_init_win;
                        s.peer_init_win = v;
                        for (auto& [sid, sc] : s.streams)
                        {
                            sc->h2s->send_win += delta;
                            if (sc->h2s->send_win > h2::max_window)
                            {
                                bad = true;
                                conn_error(h2::FLOW_CONTROL_ERROR);
                                break;
                            }
                            if (delta > 0 && sc->h2s->tx_left())
                                enqueue(s, *sc->h2s);
                        }
                    }
                    else if (id == h2::MAX_FRAME_SIZE)
                    {
                        if (v < h2::default_frame || v > 16777215)
                            bad = true, conn_error(h2::PROTOCOL_ERROR);
                        else
                            s.peer_max_frame = std::min<uint32_t>(v, 64 * 1024);
                    }
                }
                if (bad)
                    break;
                s.got_settings = true;
                h2::put_settings_ack(s.ctl);
                break;
            }
            case h2::PING:
                if (h.sid != 0)
                    conn_error(h2::PROTOCOL_ERROR);
                else if (h.len != 8)
                    conn_error(h2::FRAME_SIZE_ERROR);
                else if (!(h.flags & h2::ACK))
                {
                    if (++s.pings > pings_max)
                        conn_error(h2::ENHANCE_YOUR_CALM);
                    else
                        h2::put_ping_ack(s.ctl, pl);
                }
                break;
            case h2::GOAWAY:
                if (h.sid != 0)
                    conn_error(h2::PROTOCOL_ERROR);
                else
                    s.peer_goaway = true;
                break;
            case h2::WINDOW_UPDATE:
            {
                if (h.len != 4)
                {
                    conn_error(h2::FRAME_SIZE_ERROR);
                    break;
                }
                const uint32_t inc = h2::rd32(pl.data()) & 0x7fffffffu;
                if (h.sid == 0)
                {
                    if (inc == 0 || s.send_win + inc > h2::max_window)
                    {
                        conn_error(inc == 0 ? h2::PROTOCOL_ERROR : h2::FLOW_CONTROL_ERROR);
                        break;
                    }
                    s.send_win += inc;
                    for (auto& [sid, sc] : s.streams)
                        if (sc->h2s->tx_left() && sc->h2s->send_win > 0)
                            enqueue(s, *sc->h2s);
                    break;
                }
                if (h.sid > s.last_sid)
                {
                    conn_error(h2::PROTOCOL_ERROR);
                    break;
                }
                auto it = s.streams.find(h.sid);
                if (it == s.streams.end())
                    break;
                h2_stream& st = *it->second->h2s;
                if (inc == 0 || st.send_win + inc > h2::max_window)
                {
                    stream_error(h.sid, inc == 0 ? h2::PROTOCOL_ERROR : h2::FLOW_CONTROL_ERROR);
                    break;
                }
                st.send_win += inc;
                if (st.tx_left())
                    enqueue(s, st);
                break;
            }
            case h2::PUSH_PROMISE:
                conn_error(h2::PROTOCOL_ERROR);
                break;
            default:
                // Frames of a kind not known are ignored, as RFC 9113 asks.
                break;
        }
    }
    if (c->dead)
        return;
    if (at)
        c->in.erase(0, std::min(at, c->in.size()));
    h2_schedule(c);
    if (!c->dead && !c->ssl)
        arm_read(c);
}

// A complete header block: a new stream's request, or trailers, which are read only so the table stays in step.
// False for a block HPACK cannot read, after which the connection cannot go on.
bool storage_run::h2_headers(const std::shared_ptr<conn>& c, uint32_t sid)
{
    h2_session& s = *c->h2;
    std::vector<hpack::header> fields;
    const auto res = s.dec.decode(s.cont_buf, fields, header_list_max);
    std::string().swap(s.cont_buf);
    if (res == hpack::decoder::result::error)
        return false;

    if (s.cont_trailers)
    {
        auto it = s.streams.find(sid);
        if (it == s.streams.end())
            return true;
        auto sc = it->second;
        h2_stream& st = *sc->h2s;
        st.remote_closed = true;
        if (st.has_cl && st.data_in != st.cl)
        {
            h2::put_rst(s.ctl, sid, h2::PROTOCOL_ERROR);
            ++m_c.h2_resets_out;
            st.reset = true;
            close_conn(sc);
            return true;
        }
        h2_pull(sc);
        return true;
    }

    s.last_sid = sid;
    auto refuse = [&](uint32_t code)
    {
        h2::put_rst(s.ctl, sid, code);
        ++m_c.h2_resets_out;
    };
    if (s.cont_refuse)
    {
        refuse(h2::PROTOCOL_ERROR);
        return true;
    }
    // A client told to go away, or one at its limit, has the stream refused, which it may try again elsewhere.
    if (s.goaway_sent || s.streams.size() >= max_streams)
    {
        ++m_c.h2_refused;
        refuse(h2::REFUSED_STREAM);
        return true;
    }
    // A list too long for this side is answered, as HTTP/1.1's would be.
    std::string answer_status;
    if (res == hpack::decoder::result::too_large)
        answer_status = "431";

    // The request as an HTTP/1.1 head, which parse_head() reads; RFC 9113 8.2 and 8.3 say what a request may hold.
    std::string_view method, scheme, path, authority;
    bool regular = false, bad = false;
    std::string head, cookies;
    bool has_cl = false, has_host = false;
    uint64_t cl = 0;
    for (const auto& f : fields)
    {
        if (!f.name.empty() && f.name[0] == ':')
        {
            std::string_view* slot = f.name == ":method" ? &method : f.name == ":scheme" ? &scheme
                                   : f.name == ":path" ? &path : f.name == ":authority" ? &authority : nullptr;
            if (!slot || regular || !slot->empty() || f.value.empty())
            {
                bad = true;
                break;
            }
            *slot = f.value;
            continue;
        }
        regular = true;
        if (!lower_token(f.name) || !clean_value(f.value) || f.name == "connection" || f.name == "keep-alive" ||
            f.name == "proxy-connection" || f.name == "transfer-encoding" || f.name == "upgrade" ||
            (f.name == "te" && f.value != "trailers"))
        {
            bad = true;
            break;
        }
        if (f.name == "cookie")
        {
            cookies += cookies.empty() ? "" : "; ";
            cookies += f.value;
            continue;
        }
        if (f.name == "content-length")
        {
            const auto r = std::from_chars(f.value.data(), f.value.data() + f.value.size(), cl);
            if (r.ec != std::errc{} || r.ptr != f.value.data() + f.value.size() || has_cl)
            {
                bad = true;
                break;
            }
            has_cl = true;
        }
        has_host = has_host || f.name == "host";
        head += f.name;
        head += ": ";
        head += f.value;
        head += "\r\n";
    }
    if (!bad && answer_status.empty() && (method.empty() || method == "CONNECT" || scheme.empty() || path.empty()))
        bad = true;
    if (bad)
    {
        refuse(h2::PROTOCOL_ERROR);
        return true;
    }
    if (s.cont_end_stream && has_cl && cl != 0)
    {
        refuse(h2::PROTOCOL_ERROR);
        return true;
    }

    auto sc = std::make_shared<conn>();
    sc->run       = this;
    sc->id        = m_next_id++;
    sc->h2_parent = c.get();
    sc->h2s.reset(new h2_stream);
    sc->accepted  = c->accepted;
    sc->last_progress = sc->request_began = std::chrono::steady_clock::now();
    sc->ip        = c->ip;
    sc->ip_known  = c->ip_known;
    sc->any_request = true;
    h2_stream& st = *sc->h2s;
    st.sid           = sid;
    st.send_win      = s.peer_init_win;
    st.remote_closed = s.cont_end_stream;
    st.has_cl        = has_cl;
    st.cl            = cl;
    st.synth_chunked = !s.cont_end_stream && !has_cl;
    m_streams[sc->id] = sc;
    s.streams[sid]    = sc;
    ++m_c.h2_streams;

    std::string line;
    line.reserve(head.size() + path.size() + authority.size() + cookies.size() + 64);
    line += method;
    line += ' ';
    line += path;
    line += " HTTP/1.1\r\n";
    if (!has_host && !authority.empty())
    {
        line += "host: ";
        line += authority;
        line += "\r\n";
    }
    line += head;
    if (!cookies.empty())
    {
        line += "cookie: ";
        line += cookies;
        line += "\r\n";
    }
    if (st.synth_chunked)
        line += "transfer-encoding: chunked\r\n";
    line += "\r\n";
    if (line.size() > max_head)
        answer_status = "431";
    if (!answer_status.empty())
    {
        new_request_id(sc->req.request_id);
        response r;
        r.status = 431;
        sc->ph = phase::respond;
        send_response(sc, std::move(r));
        return true;
    }
    if (!parse_head(sc, line))
        return true;
    sc->req.version = "HTTP/2.0";
    ++m_c.requests;
    runtime_instance::stat_add(m_owner.m_stat_total_messages, 1);
    dispatch(sc);
    return true;
}

// ─── A stream's body in ─────────────────────────────────────────────────────

void storage_run::h2_pull(const std::shared_ptr<conn>& c)
{
    if (c->pulling || c->dead || !c->h2_parent)
        return;
    conn* parent = c->h2_parent;
    h2_session& s = *parent->h2;
    h2_stream& st = *c->h2s;
    c->pulling = true;
    uint64_t given = 0;
    auto open = [&] { return !c->dead && c->ph != phase::respond && c->ph != phase::hook_wait && c->park_off >= c->park.size(); };
    while (open() && st.rx_off < st.rx.size())
    {
        const size_t n = std::min(pull_slice, st.rx.size() - st.rx_off);
        const size_t from = st.rx_off;
        st.rx_off += n;
        given += n;
        if (st.synth_chunked)
        {
            char hex[20];
            const auto r = std::to_chars(hex, hex + sizeof hex, n, 16);
            std::string framed;
            framed.reserve(n + 32);
            framed.append(hex, r.ptr);
            framed += "\r\n";
            framed.append(st.rx, from, n);
            framed += "\r\n";
            plain_in(c, framed.data(), framed.size());
        }
        else
            plain_in(c, st.rx.data() + from, n);
    }
    if (st.synth_chunked && st.remote_closed && !st.chunk_end_given && st.rx_off >= st.rx.size() && open())
    {
        st.chunk_end_given = true;
        static const char end[] = "0\r\n\r\n";
        plain_in(c, end, sizeof end - 1);
    }
    c->pulling = false;
    if (st.rx_off == st.rx.size())
    {
        st.rx.clear();
        st.rx_off = 0;
    }
    else if (st.rx_off > (1u << 20) && st.rx_off * 2 > st.rx.size())
    {
        st.rx.erase(0, st.rx_off);
        st.rx_off = 0;
    }
    if (!given || s.dying)
        return;
    // What the phase took is given back, in increments of half a window so the updates are few.
    st.rx_unacked  += static_cast<uint32_t>(given);
    s.recv_unacked += static_cast<uint32_t>(given);
    if (!st.remote_closed && !c->dead && st.rx_unacked >= stream_window / 2)
    {
        h2::put_window_update(s.ctl, st.sid, st.rx_unacked);
        st.recv_avail += st.rx_unacked;
        st.rx_unacked = 0;
    }
    if (s.recv_unacked >= conn_window / 2)
    {
        h2::put_window_update(s.ctl, 0, s.recv_unacked);
        s.recv_avail += s.recv_unacked;
        s.recv_unacked = 0;
    }
    if (auto p = find(parent->id))
        h2_schedule(p);
}

// ─── A stream's answer out ──────────────────────────────────────────────────

void storage_run::h2_stream_out(const std::shared_ptr<conn>& c, std::string data)
{
    if (!c->h2_parent)
        return;
    conn* parent = c->h2_parent;
    h2_session& s = *parent->h2;
    h2_stream& st = *c->h2s;
    if (st.reset || st.local_closed)
        return;
    std::string_view rest = data;
    while (!rest.empty())
    {
        if (st.os == h2_stream::out_state::head)
        {
            // The answer's head, which this runtime wrote, so its form is known: a status line and its fields.
            st.head_acc.append(rest);
            rest = {};
            const size_t end = st.head_acc.find("\r\n\r\n");
            if (end == std::string::npos)
                break;
            const std::string_view head(st.head_acc.data(), end + 2);
            const std::string after = st.head_acc.substr(end + 4);
            std::string block;
            if (s.first_block)
            {
                // The table this side's blocks could use is set to nothing, so the peer's needs no tracking.
                block += '\x20';
                s.first_block = false;
            }
            const size_t sp = head.find(' ');
            const std::string_view status = sp == std::string_view::npos ? "500" : head.substr(sp + 1, 3);
            hpack::encode(block, ":status", status);
            bool chunked = false;
            size_t at = head.find("\r\n") + 2;
            while (at < head.size())
            {
                const size_t eol = head.find("\r\n", at);
                const std::string_view l = head.substr(at, eol - at);
                at = eol + 2;
                const size_t colon = l.find(':');
                if (colon == std::string_view::npos)
                    continue;
                std::string name(l.substr(0, colon));
                for (char& ch : name)
                    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
                std::string_view value = l.substr(colon + 1);
                while (!value.empty() && value.front() == ' ')
                    value.remove_prefix(1);
                if (name == "transfer-encoding")
                {
                    chunked = value.find("chunked") != std::string_view::npos;
                    continue;
                }
                if (name == "connection" || name == "keep-alive" || name == "proxy-connection" || name == "upgrade")
                    continue;
                hpack::encode(block, name, value);
            }
            const bool interim = status.size() == 3 && status[0] == '1';
            h2::put_header_block(st.hdr, st.sid, block, false, s.peer_max_frame);
            st.head_acc.clear();
            if (!interim)
                st.os = chunked ? h2_stream::out_state::dechunk : h2_stream::out_state::body;
            if (!after.empty())
            {
                data = after;
                rest = data;
            }
            continue;
        }
        if (st.os == h2_stream::out_state::body)
        {
            if (st.tx_off == st.tx.size())
            {
                st.tx.clear();
                st.tx_off = 0;
            }
            st.tx.append(rest);
            rest = {};
            break;
        }
        // A chunked answer's framing is HTTP/1.1's, and DATA frames carry what is inside it.
        st.dechunk_in.append(rest);
        rest = {};
        std::string_view view = st.dechunk_in;
        for (;;)
        {
            std::string_view out;
            const chunk_step k = http_chunked_next(st.dechunk, view, out);
            if (k == chunk_step::payload)
            {
                st.tx.append(out);
                continue;
            }
            break;
        }
        st.dechunk_in.erase(0, st.dechunk_in.size() - view.size());
    }
    c->last_progress = std::chrono::steady_clock::now();
    enqueue(s, st);
    if (auto p = find(parent->id))
        h2_schedule(p);
}

void storage_run::h2_stream_end(const std::shared_ptr<conn>& c)
{
    if (c->file_fd >= 0)
    {
        m_loop.close_fd(c->file_fd);
        c->file_fd = -1;
    }
    c->dec.reset();
    c->sel.reset();
    zip_end(*c);
    c->ph = phase::respond;
    if (!c->h2_parent)
    {
        close_conn(c);
        return;
    }
    h2_session& s = *c->h2_parent->h2;
    h2_stream& st = *c->h2s;
    st.end_pending = true;
    enqueue(s, st);
    if (auto p = find(c->h2_parent->id))
        h2_schedule(p);
}

void storage_run::h2_stream_gone(const std::shared_ptr<conn>& c)
{
    conn* parent = c->h2_parent;
    if (!parent || !parent->h2)
        return;
    h2_session& s = *parent->h2;
    h2_stream& st = *c->h2s;
    if (!s.dying)
    {
        // Ended before its answer did, or with its request's body still coming: the client is told.
        if (!st.reset && (!st.local_closed || !st.remote_closed))
        {
            h2::put_rst(s.ctl, st.sid, st.local_closed ? h2::NO_ERROR : h2::CANCEL);
            ++m_c.h2_resets_out;
            st.reset = true;
        }
        // What it received and its phase never took is the connection's again.
        s.recv_unacked += static_cast<uint32_t>(st.rx.size() - st.rx_off);
        if (s.recv_unacked >= conn_window / 2)
        {
            h2::put_window_update(s.ctl, 0, s.recv_unacked);
            s.recv_avail += s.recv_unacked;
            s.recv_unacked = 0;
        }
    }
    s.streams.erase(st.sid);
    std::string().swap(st.rx);
    std::string().swap(st.tx);
    if (!s.dying)
        if (auto p = find(parent->id))
            h2_schedule(p);
}

// Frames into the connection's queue: its own first, then a frame of each stream with something to send, in turn,
// while the windows and the queue's bound allow.
void storage_run::h2_schedule(const std::shared_ptr<conn>& c)
{
    if (c->dead || !c->h2)
        return;
    h2_session& s = *c->h2;
    std::string out = std::move(s.ctl);
    s.ctl.clear();
    const size_t before = unsent(*c);
    std::vector<std::shared_ptr<conn>> ended;
    while (!s.rr.empty() && before + out.size() < out_high)
    {
        const uint32_t sid = s.rr.front();
        s.rr.pop_front();
        auto it = s.streams.find(sid);
        if (it == s.streams.end())
            continue;
        auto sc = it->second;
        h2_stream& st = *sc->h2s;
        st.queued = false;
        if (st.reset || st.local_closed)
            continue;
        if (!st.hdr.empty())
        {
            out += st.hdr;
            st.hdr.clear();
        }
        const int64_t win = std::min(st.send_win, s.send_win);
        if (st.tx_left() && win > 0)
        {
            const size_t n = std::min<size_t>({st.tx_left(), static_cast<size_t>(win), s.peer_max_frame});
            const bool last = st.end_pending && n == st.tx_left();
            h2::put_data(out, sid, std::string_view(st.tx).substr(st.tx_off, n), last);
            st.tx_off  += n;
            st.send_win -= static_cast<int64_t>(n);
            s.send_win  -= static_cast<int64_t>(n);
            sc->last_progress = std::chrono::steady_clock::now();
            if (last)
                st.local_closed = true;
        }
        if (!st.tx_left())
        {
            st.tx.clear();
            st.tx_off = 0;
            if (st.end_pending && !st.local_closed)
            {
                h2::put_data(out, sid, {}, true);
                st.local_closed = true;
            }
        }
        if (st.local_closed)
        {
            ended.push_back(sc);
            continue;
        }
        // More of it goes in the next turn, unless a window holds it until an update comes.
        if (st.tx_left() && st.send_win > 0 && s.send_win > 0)
            enqueue(s, st);
    }
    if (!out.empty())
        queue_write(c, std::move(out));
    for (auto& sc : ended)
        close_conn(sc);
}

void storage_run::h2_written(const std::shared_ptr<conn>& c)
{
    h2_session& s = *c->h2;
    if (c->woff < c->wbuf.size() || c->wq_off < c->wq.size() || (c->ssl && tls_context::has_pending_out(c->ssl)))
    {
        pump_write(c);
        if (c->dead)
            return;
    }
    else
    {
        c->wbuf.clear();
        c->woff = 0;
    }
    // Each stream whose answer has left its own queue goes on: the next piece of its file, or its end.
    std::vector<std::shared_ptr<conn>> due;
    for (auto& [sid, sc] : s.streams)
        if (!sc->dead && sc->after_write != conn::after_kind::none && sc->h2s->hdr.empty() && !sc->h2s->tx_left() &&
            sc->h2s->os != h2_stream::out_state::head)
            due.push_back(sc);
    for (auto& sc : due)
    {
        if (sc->dead || c->dead)
            continue;
        const conn::after_kind next = sc->after_write;
        sc->after_write = conn::after_kind::none;
        if (next == conn::after_kind::finish)
            finish_request(sc);
        else if (next == conn::after_kind::pump)
            file_pump(sc);
    }
    if (c->dead)
        return;
    h2_schedule(c);
    if (!c->dead && s.close_when_flushed && !c->wr_pending && unsent(*c) == 0)
        close_conn(c);
}

}   // namespace socketley::storage
