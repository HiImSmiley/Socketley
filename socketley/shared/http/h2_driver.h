#pragma once
// The parts of driving an HTTP/2 connection that no host takes part in: the answer an HTTP/1.1 writer produced read
// back into HEADERS and DATA, the connection-level frames that only move windows and counters, and the turn that
// puts frames into the wire's queue. What is left to a runtime is the five things only it can do -- open a stream,
// hand a stream's body to whatever reads it, close one, stamp progress, and write bytes to a socket.
//
// Here with the frame codec (h2_frame.h), HPACK (hpack.h), the head contract (mux_head.h) and the session's state
// (h2_session.h) because none of it is one runtime's: the storage speaks HTTP/2 today, and an entrance proxy has
// the same frames to read before it can route a stream by its `:authority`.
//
// Templates on the host's per-stream handle rather than an interface, because this is walked once per frame and a
// virtual call per frame is a cost the hot path does not have to carry.
#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>

#include "h2_frame.h"
#include "h2_session.h"
#include "hpack.h"
#include "http_framing.h"
#include "mux_head.h"

namespace socketley::h2
{

// How a host's per-stream handle gives up the stream's own state: both runtimes that speak this hang an `h2s` off
// what they keep per stream, so that is the default and a host keeping it elsewhere overloads this.
template <class S>
inline stream& state_of(const S& h) { return *h->h2s; }

// What a frame asks of the connection once it has been read: nothing, an error that ends the connection, or one
// that ends a single stream.
struct outcome
{
    enum class what : uint8_t { taken, conn_error, stream_error };
    what     kind{what::taken};
    uint32_t code{NO_ERROR};
    uint32_t sid{0};

    static outcome taken() { return {}; }
    static outcome conn(uint32_t code) { return {what::conn_error, code, 0}; }
    static outcome strm(uint32_t sid, uint32_t code) { return {what::stream_error, code, sid}; }
};

// The peer's SETTINGS: every open stream's window moves with INITIAL_WINDOW_SIZE, and the ack is queued when the
// whole payload was good -- a half-applied SETTINGS is not acknowledged.
template <class S>
outcome settings_in(session<S>& s, std::string_view pl)
{
    for (size_t i = 0; i + 6 <= pl.size(); i += 6)
    {
        const uint16_t id = static_cast<uint16_t>(static_cast<uint8_t>(pl[i]) << 8 | static_cast<uint8_t>(pl[i + 1]));
        const uint32_t v  = rd32(pl.data() + i + 2);
        if (id == ENABLE_PUSH && v > 1)
            return outcome::conn(PROTOCOL_ERROR);
        if (id == INITIAL_WINDOW_SIZE)
        {
            if (v > max_window)
                return outcome::conn(FLOW_CONTROL_ERROR);
            // Every open stream's window moves by the difference, and may go below zero.
            const int64_t delta = static_cast<int64_t>(v) - s.peer_init_win;
            s.peer_init_win = v;
            for (auto& [sid, h] : s.streams)
            {
                stream& st = state_of(h);
                st.send_win += delta;
                if (st.send_win > max_window)
                    return outcome::conn(FLOW_CONTROL_ERROR);
                if (delta > 0 && st.tx_left())
                    enqueue(s, st);
            }
        }
        else if (id == MAX_FRAME_SIZE)
        {
            if (v < default_frame || v > 16777215)
                return outcome::conn(PROTOCOL_ERROR);
            s.peer_max_frame = std::min<uint32_t>(v, 64 * 1024);
        }
    }
    s.got_settings = true;
    put_settings_ack(s.ctl);
    return outcome::taken();
}

// A WINDOW_UPDATE on the connection or on one stream; one for a stream this side has already forgotten is ignored,
// as RFC 9113 6.9 allows for a stream that has closed.
template <class S>
outcome window_update_in(session<S>& s, const frame_head& h, std::string_view pl)
{
    const uint32_t inc = rd32(pl.data()) & 0x7fffffffu;
    if (h.sid == 0)
    {
        if (inc == 0)
            return outcome::conn(PROTOCOL_ERROR);
        if (s.send_win + inc > max_window)
            return outcome::conn(FLOW_CONTROL_ERROR);
        s.send_win += inc;
        for (auto& [sid, hnd] : s.streams)
        {
            stream& st = state_of(hnd);
            if (st.tx_left() && st.send_win > 0)
                enqueue(s, st);
        }
        return outcome::taken();
    }
    if (h.sid > s.last_sid)
        return outcome::conn(PROTOCOL_ERROR);
    auto it = s.streams.find(h.sid);
    if (it == s.streams.end())
        return outcome::taken();
    stream& st = state_of(it->second);
    if (inc == 0)
        return outcome::strm(h.sid, PROTOCOL_ERROR);
    if (st.send_win + inc > max_window)
        return outcome::strm(h.sid, FLOW_CONTROL_ERROR);
    st.send_win += inc;
    if (st.tx_left())
        enqueue(s, st);
    return outcome::taken();
}

// The HTTP/1.1 answer a host handed over, read back into this stream's HEADERS and the bytes its DATA will carry.
// Whoever built the answer does not know it is on an HTTP/2 stream, so its form is HTTP/1.1's throughout: a status
// line and its fields, then a body framed by Content-Length or by chunks.
template <class S>
void frame_answer(session<S>& s, stream& st, std::string data)
{
    std::string_view rest = data;
    while (!rest.empty())
    {
        if (st.os == stream::out_state::head)
        {
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
            mux::response mr;
            mux::response_head(head, mr);
            hpack::encode(block, ":status", mr.status);
            for (const auto& [name, value] : mr.fields)
                hpack::encode(block, name, value);
            const bool interim = mr.interim, chunked = mr.chunked;
            put_header_block(st.hdr, st.sid, block, false, s.peer_max_frame);
            st.head_acc.clear();
            if (!interim)
                st.os = chunked ? stream::out_state::dechunk : stream::out_state::body;
            if (!after.empty())
            {
                data = after;
                rest = data;
            }
            continue;
        }
        if (st.os == stream::out_state::body)
        {
            // A piece of a file is taken as it was handed over, when nothing is waiting before it.
            if (st.tx_off == st.tx.size())
            {
                st.tx_off = 0;
                if (rest.data() == data.data() && rest.size() == data.size())
                    st.tx = std::move(data);
                else
                    st.tx.assign(rest);
            }
            else
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
}

// What a stream received and its reader never took is the connection's again, and the update is sent once it is
// worth a frame -- the same bound the stream's own give-back uses.
template <class S>
void give_back(session<S>& s, uint32_t bytes)
{
    s.recv_unacked += bytes;
    if (s.recv_unacked >= conn_window / 2)
    {
        put_window_update(s.ctl, 0, s.recv_unacked);
        s.recv_avail += s.recv_unacked;
        s.recv_unacked = 0;
    }
}

// One turn of frames into `out`: the connection's own first, then a frame of each stream with something to send, in
// turn, while the peer's windows and the queue's bound allow. `unsent_now` is what the wire has not taken yet, so a
// queue already at `out_high` adds nothing.
//
// `wrote` is called with the handle of a stream whose DATA went in, `ended` with one whose last frame did, and
// `idle` with one that has nothing left to send -- which is where a host asks whether something waits on that.
template <class S, class Wrote, class Ended, class Idle>
void drain(session<S>& s, std::string& out, size_t unsent_now, size_t out_high, Wrote&& wrote, Ended&& ended,
           Idle&& idle)
{
    const size_t start = out.size();
    out += s.ctl;
    s.ctl.clear();
    while (!s.rr.empty() && unsent_now + (out.size() - start) < out_high)
    {
        const uint32_t sid = s.rr.front();
        s.rr.pop_front();
        auto it = s.streams.find(sid);
        if (it == s.streams.end())
            continue;
        S h = it->second;
        stream& st = state_of(h);
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
            put_data(out, sid, std::string_view(st.tx).substr(st.tx_off, n), last);
            st.tx_off   += n;
            st.send_win -= static_cast<int64_t>(n);
            s.send_win  -= static_cast<int64_t>(n);
            wrote(h);
            if (last)
                st.local_closed = true;
        }
        if (!st.tx_left())
        {
            st.tx.clear();
            st.tx_off = 0;
            if (st.end_pending && !st.local_closed)
            {
                put_data(out, sid, {}, true);
                st.local_closed = true;
            }
        }
        if (st.local_closed)
        {
            ended(h);
            continue;
        }
        if (!st.tx_left() && st.hdr.empty() && st.os != stream::out_state::head)
            idle(h);
        // More of it goes in the next turn, unless a window holds it until an update comes.
        if (st.tx_left() && st.send_win > 0 && s.send_win > 0)
            enqueue(s, st);
    }
}

// What a runtime answers while its frames are being read.  A host is a type with these members, taken by reference
// and called directly, so nothing here is a virtual call:
//
//   bool gone()                       the connection is going; stop reading
//   void close_now()                  a peer that is not speaking HTTP/2 at all, so it is not answered
//   void want_more()                  ask the transport for the rest of a frame
//   void conn_error(uint32_t code)     GOAWAY with that code; feed() discards the rest of the bytes
//   void stream_gone(const S& h)      let go of what was kept for a stream the protocol has ended
//   S    make(uint32_t sid)            the handle for a new stream, falsy when it cannot be made
//   void start(const S& h, mux::request& r, int answer_status)   route that stream, or answer it that status
//   void body(const S& h, std::string_view d)        DATA's payload to whatever reads the stream
//   void body_end(const S& h)                        END_STREAM with nothing left to add
//   void count(event e)                              the runtime's own counters
//
// Making a stream and starting it are two calls because the stream's own state has to be set between them: an
// answer a host produces inside start() is framed at once, and a stream that did not know its number yet would
// frame it onto stream 0.  `start` is given a status instead of a route when the head cannot be served as it
// stands -- a list too long for this side is answered 431, as HTTP/1.1's would be -- and the stream is made either
// way, because the answer has to go somewhere.
enum class event : uint8_t { stream_opened, stream_refused, reset_in, reset_out };

// An RST_STREAM a peer's frame has drawn: past resets_max in a window the connection ends instead, since a peer that
// never reads would otherwise grow the wire's queue by one reset per frame it sends.
template <class S, class Host>
void put_reset(session<S>& s, uint32_t sid, uint32_t code, Host& host)
{
    if (++s.resets_out > resets_max)
    {
        host.conn_error(ENHANCE_YOUR_CALM);
        return;
    }
    put_rst(s.ctl, sid, code);
    host.count(event::reset_out);
}

// A stream's own error ends it alone: the peer is told with an RST_STREAM, the stream is marked so none is sent
// again, and the host lets go of whatever it kept for it.
template <class S, class Host>
void reset_stream(session<S>& s, uint32_t sid, uint32_t code, Host& host)
{
    put_reset(s, sid, code, host);
    if (auto it = s.streams.find(sid); it != s.streams.end())
    {
        // The handle is copied out of the map first: stream_gone() is what ends the stream, and ending it erases
        // this entry -- so a reference into the map would name a handle already destroyed.  The code this was
        // lifted from took the copy for the same reason, and taking a reference instead is a use-after-free the
        // sanitizer found on the first streamed GET that was abandoned mid-read.
        S h = it->second;
        state_of(h).reset = true;
        host.stream_gone(h);
    }
}

// A complete header block: a new stream's request, or trailers, which are read only so the table stays in step.
// False for a block HPACK cannot read, after which the connection cannot go on.
template <class S, class Host>
bool headers_in(session<S>& s, uint32_t sid, size_t max_head_bytes, Host& host)
{
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
        S h = it->second;
        stream& st = state_of(h);
        st.remote_closed = true;
        if (st.has_cl && st.data_in != st.cl)
        {
            reset_stream(s, sid, PROTOCOL_ERROR, host);
            return true;
        }
        host.body_end(h);
        return true;
    }

    s.last_sid = sid;
    auto refuse = [&](uint32_t code) { put_reset(s, sid, code, host); };
    if (s.cont_refuse)
    {
        refuse(PROTOCOL_ERROR);
        return true;
    }
    // A client told to go away, or one at its limit, has the stream refused, which it may try again elsewhere.
    if (s.goaway_sent || s.streams.size() >= s.max_live)
    {
        host.count(event::stream_refused);
        refuse(REFUSED_STREAM);
        return true;
    }
    // A list too long for this side is answered, as HTTP/1.1's would be.
    int answer_status = res == hpack::decoder::result::too_large ? 431 : 0;

    std::vector<std::pair<std::string, std::string>> list;
    list.reserve(fields.size());
    for (auto& f : fields)
        list.emplace_back(std::move(f.name), std::move(f.value));
    mux::request mr;
    const mux::verdict v = mux::request_head(list, s.cont_end_stream, max_head_bytes, mr);
    if (v == mux::verdict::malformed && answer_status == 0)
    {
        refuse(PROTOCOL_ERROR);
        return true;
    }
    if (v == mux::verdict::too_large)
        answer_status = 431;

    S h = host.make(sid);
    if (!h)
        return true;
    stream& st = state_of(h);
    st.sid           = sid;
    st.send_win      = s.peer_init_win;
    st.remote_closed = s.cont_end_stream;
    st.has_cl        = mr.has_cl;
    st.cl            = mr.cl;
    st.synth_chunked = mr.synth_chunked;
    s.streams[sid]   = h;
    host.count(event::stream_opened);
    host.start(h, mr, answer_status);
    return true;
}

// Frames out of `p`/`n`, with `frag` holding the one frame cut off by the end of them for the next call.  Reading
// stops the moment the host says the connection is going, and the bytes after a connection error are discarded
// rather than read, which is what GOAWAY means.
//
// False when it stopped before reading any frame -- a session already going, a peer that is not speaking HTTP/2, or
// a preface still arriving -- in which case the caller must not finish the turn: close_now() and want_more() have
// already said what happens next, and arming a second read over the first is not idempotent.
template <class S, class Host>
bool feed(session<S>& s, std::string& frag, const char* p, size_t n, size_t max_head_bytes, Host& host)
{
    if (s.dying)
        return false;
    // Frames are read where the bytes arrived; only a frame cut off by the end of them is kept for the next.
    std::string held;
    std::string_view buf(p, n);
    if (!frag.empty())
    {
        frag.append(p, n);
        held.swap(frag);
        buf = held;
    }
    size_t at = 0;
    auto conn_error = [&](uint32_t code)
    {
        buf = {};
        at  = 0;
        host.conn_error(code);
    };

    if (!s.preface_ok)
    {
        const std::string_view pre = preface;
        const size_t look = std::min(pre.size(), buf.size());
        if (buf.substr(0, look) != pre.substr(0, look))
        {
            host.close_now();
            return false;
        }
        if (buf.size() < pre.size())
        {
            frag.assign(buf);
            host.want_more();
            return false;
        }
        s.preface_ok = true;
        at = pre.size();
    }

    while (!host.gone() && !s.dying && buf.size() - at >= head_len)
    {
        const frame_head h = parse_head(buf.data() + at);
        if (h.len > default_frame)
        {
            conn_error(FRAME_SIZE_ERROR);
            break;
        }
        if (buf.size() - at < head_len + h.len)
            break;
        std::string_view pl(buf.data() + at + head_len, h.len);
        at += head_len + h.len;
        tick_window(s);

        // The first frame is the client's SETTINGS; between HEADERS and its END_HEADERS only CONTINUATION.
        if (!s.got_settings && (h.type != SETTINGS || (h.flags & ACK)))
        {
            conn_error(PROTOCOL_ERROR);
            break;
        }
        if (s.cont_sid && (h.type != CONTINUATION || h.sid != s.cont_sid))
        {
            conn_error(PROTOCOL_ERROR);
            break;
        }

        switch (h.type)
        {
            case DATA:
            {
                if (h.sid == 0 || h.sid > s.last_sid)
                {
                    conn_error(PROTOCOL_ERROR);
                    break;
                }
                if (static_cast<int64_t>(h.len) > s.recv_avail)
                {
                    conn_error(FLOW_CONTROL_ERROR);
                    break;
                }
                s.recv_avail -= h.len;
                auto it = s.streams.find(h.sid);
                if (it == s.streams.end() || state_of(it->second).remote_closed)
                {
                    // The bytes are the connection's again, and DATA on a closed stream is STREAM_CLOSED (RFC 9113
                    // 5.1); the answers to a peer that keeps sending such are bounded like its resets.
                    s.recv_unacked += h.len;
                    if (++s.strays <= resets_max)
                        reset_stream(s, h.sid, STREAM_CLOSED, host);
                    break;
                }
                S hnd = it->second;
                stream& st = state_of(hnd);
                if (static_cast<int64_t>(h.len) > st.recv_avail)
                {
                    s.recv_unacked += h.len;
                    reset_stream(s, h.sid, FLOW_CONTROL_ERROR, host);
                    break;
                }
                st.recv_avail -= h.len;
                if (!unpad(h, pl))
                {
                    conn_error(PROTOCOL_ERROR);
                    break;
                }
                // Padding is given back at once; the payload when the reader takes it.
                const uint32_t pad = h.len - static_cast<uint32_t>(pl.size());
                s.recv_unacked += pad;
                st.rx_unacked  += pad;
                if (pl.empty() && !(h.flags & END_STREAM) && ++s.empty_data > empty_data_max)
                {
                    conn_error(ENHANCE_YOUR_CALM);
                    break;
                }
                st.data_in += pl.size();
                if (st.has_cl && st.data_in > st.cl)
                {
                    s.recv_unacked += static_cast<uint32_t>(pl.size());
                    reset_stream(s, h.sid, PROTOCOL_ERROR, host);
                    break;
                }
                if (h.flags & END_STREAM)
                {
                    st.remote_closed = true;
                    if (st.has_cl && st.data_in != st.cl)
                    {
                        s.recv_unacked += static_cast<uint32_t>(pl.size());
                        reset_stream(s, h.sid, PROTOCOL_ERROR, host);
                        break;
                    }
                }
                host.body(hnd, pl);
                break;
            }
            case HEADERS:
            {
                if (h.sid == 0 || !(h.sid & 1))
                {
                    conn_error(PROTOCOL_ERROR);
                    break;
                }
                // A stream may not depend on itself (RFC 9113 5.3.1), which is its own error; the block is still
                // decoded, so the table stays in step.
                bool self_dependent = false;
                if (h.flags & PRIORITY_F)
                {
                    const size_t at_dep = (h.flags & PADDED) ? 1 : 0;
                    self_dependent = pl.size() >= at_dep + 4 && (rd32(pl.data() + at_dep) & 0x7fffffffu) == h.sid;
                }
                if (!unpad(h, pl))
                {
                    conn_error(PROTOCOL_ERROR);
                    break;
                }
                bool trailers = false;
                if (h.sid <= s.last_sid)
                {
                    auto it = s.streams.find(h.sid);
                    // Trailers end the stream they follow; HEADERS on a stream that is closed is an error.
                    if (it == s.streams.end() || state_of(it->second).remote_closed)
                    {
                        conn_error(STREAM_CLOSED);
                        break;
                    }
                    if (!(h.flags & END_STREAM))
                    {
                        conn_error(PROTOCOL_ERROR);
                        break;
                    }
                    trailers = true;
                }
                s.cont_sid        = h.sid;
                s.cont_buf.assign(pl);
                s.cont_end_stream = h.flags & END_STREAM;
                s.cont_trailers   = trailers;
                s.cont_frames     = 0;
                s.cont_refuse     = self_dependent;
                if (h.flags & END_HEADERS)
                {
                    const uint32_t sid = s.cont_sid;
                    s.cont_sid = 0;
                    if (!headers_in(s, sid, max_head_bytes, host))
                        conn_error(COMPRESSION_ERROR);
                }
                break;
            }
            case CONTINUATION:
            {
                if (!s.cont_sid)
                {
                    conn_error(PROTOCOL_ERROR);
                    break;
                }
                s.cont_buf.append(pl);
                if (s.cont_buf.size() > block_max || ++s.cont_frames > continuations_max)
                {
                    conn_error(ENHANCE_YOUR_CALM);
                    break;
                }
                if (h.flags & END_HEADERS)
                {
                    const uint32_t sid = s.cont_sid;
                    s.cont_sid = 0;
                    if (!headers_in(s, sid, max_head_bytes, host))
                        conn_error(COMPRESSION_ERROR);
                }
                break;
            }
            case PRIORITY:
                if (h.sid == 0)
                    conn_error(PROTOCOL_ERROR);
                else if (h.len != 5)
                    reset_stream(s, h.sid, FRAME_SIZE_ERROR, host);
                else if ((rd32(pl.data()) & 0x7fffffffu) == h.sid)
                    reset_stream(s, h.sid, PROTOCOL_ERROR, host);
                break;
            case RST_STREAM:
            {
                if (h.sid == 0 || h.sid > s.last_sid)
                {
                    conn_error(PROTOCOL_ERROR);
                    break;
                }
                if (h.len != 4)
                {
                    conn_error(FRAME_SIZE_ERROR);
                    break;
                }
                host.count(event::reset_in);
                // Streams opened and reset at once cost this side their work and the client nothing.
                if (++s.resets > resets_max)
                {
                    conn_error(ENHANCE_YOUR_CALM);
                    break;
                }
                if (auto it = s.streams.find(h.sid); it != s.streams.end())
                {
                    // Copied out of the map first, for the reason given in reset_stream().
                    S hnd = it->second;
                    state_of(hnd).reset = true;
                    host.stream_gone(hnd);
                }
                break;
            }
            case SETTINGS:
            {
                if (h.sid != 0)
                {
                    conn_error(PROTOCOL_ERROR);
                    break;
                }
                if (h.flags & ACK)
                {
                    if (h.len != 0)
                        conn_error(FRAME_SIZE_ERROR);
                    break;
                }
                if (h.len % 6)
                {
                    conn_error(FRAME_SIZE_ERROR);
                    break;
                }
                if (++s.settings > settings_max)
                {
                    conn_error(ENHANCE_YOUR_CALM);
                    break;
                }
                if (const auto r = settings_in(s, pl); r.kind == outcome::what::conn_error)
                    conn_error(r.code);
                break;
            }
            case PING:
                if (h.sid != 0)
                    conn_error(PROTOCOL_ERROR);
                else if (h.len != 8)
                    conn_error(FRAME_SIZE_ERROR);
                else if (!(h.flags & ACK))
                {
                    if (++s.pings > pings_max)
                        conn_error(ENHANCE_YOUR_CALM);
                    else
                        put_ping_ack(s.ctl, pl);
                }
                break;
            case GOAWAY:
                if (h.sid != 0)
                    conn_error(PROTOCOL_ERROR);
                else
                    s.peer_goaway = true;
                break;
            case WINDOW_UPDATE:
            {
                if (h.len != 4)
                {
                    conn_error(FRAME_SIZE_ERROR);
                    break;
                }
                const auto r = window_update_in(s, h, pl);
                if (r.kind == outcome::what::conn_error)
                    conn_error(r.code);
                else if (r.kind == outcome::what::stream_error)
                    reset_stream(s, r.sid, r.code, host);
                break;
            }
            case PUSH_PROMISE:
                conn_error(PROTOCOL_ERROR);
                break;
            default:
                // Frames of a kind not known are ignored, as RFC 9113 asks.
                break;
        }
    }
    if (host.gone())
        return true;
    if (!s.dying && at < buf.size())
        frag.assign(buf.substr(at));
    return true;
}

}   // namespace socketley::h2
