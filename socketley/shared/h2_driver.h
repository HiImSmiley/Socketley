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

}   // namespace socketley::h2
