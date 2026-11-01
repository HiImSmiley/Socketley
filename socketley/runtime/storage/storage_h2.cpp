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

#include "../../shared/http/h2_driver.h"
#include "../../shared/http/h2_frame.h"
#include "../../shared/http/h2_session.h"
#include "../../shared/http/hpack.h"
#include "../../shared/util/logging.h"
#include "../../shared/http/mux_head.h"

namespace socketley::storage
{

namespace
{

// The protocol's own limits and flood bounds are shared with every runtime that speaks HTTP/2; named here so the
// body below reads as it did, rather than carrying a qualifier on each of eleven constants.
using h2::block_max;
using h2::conn_window;
using h2::continuations_max;
using h2::empty_data_max;
using h2::header_list_max;
using h2::max_head;
using h2::max_streams;
using h2::pings_max;
using h2::resets_max;
using h2::settings_max;
using h2::stream_window;

// What one turn hands a stream's phase.
constexpr size_t   pull_slice      = 64 * 1024;
// Seconds a TLS connection that chose HTTP/2 has to send its preface.
constexpr long     preface_secs    = 10;
// A session left with frames it cannot send, as an HTTP/1.1 answer that cannot be written is.
constexpr long     write_stall_secs = 120;

}   // namespace

// The state is h2::stream's and h2::session's; these names stay because storage_run.h holds them as opaque types
// with deleters of their own, and a conn is what this runtime hangs off a stream id.
struct h2_stream : h2::stream {};
struct h2_session : h2::session<std::shared_ptr<conn>> {};

void h2_session_free::operator()(h2_session* s) const { delete s; }
void h2_stream_free::operator()(h2_stream* s) const { delete s; }

namespace
{

using h2::enqueue;
using h2::tick_window;

size_t unsent(const conn& c)
{
    return (c.wbuf.size() - c.woff) + (c.wq.size() - c.wq_off);
}

}   // namespace

// ─── The session ────────────────────────────────────────────────────────────

void storage_run::h2_start(const std::shared_ptr<conn>& c)
{
    c->ph = phase::h2;
    c->h2.reset(new h2_session);
    h2_session& s = *c->h2;
    h2::fit_to_path(s, c->fd);
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
    // A stream here is a conn of its own with no socket, so what the shared reader asks of this runtime is what an
    // HTTP/1.1 connection already does: make one, start it, hand it its body, let it go.
    struct host
    {
        storage_run* run;
        const std::shared_ptr<conn>& c;

        bool gone() const { return c->dead; }
        void close_now() { run->close_conn(c); }
        void want_more() { run->arm_read(c); }
        void conn_error(uint32_t code) { run->h2_goaway(c, code, false); }
        void stream_gone(const std::shared_ptr<conn>& sc) { run->close_conn(sc); }
        void body(const std::shared_ptr<conn>& sc, std::string_view d)
        {
            sc->last_progress = std::chrono::steady_clock::now();
            run->h2_pull(sc, d);
        }
        void body_end(const std::shared_ptr<conn>& sc) { run->h2_pull(sc, {}); }
        std::shared_ptr<conn> make(uint32_t) { return run->h2_make_stream(c); }
        void start(const std::shared_ptr<conn>& sc, mux::request& mr, int answer_status)
        {
            run->h2_start_stream(sc, mr, answer_status);
        }
        void count(h2::event e)
        {
            switch (e)
            {
                case h2::event::stream_opened:  ++run->m_c.h2_streams;    break;
                case h2::event::stream_refused: ++run->m_c.h2_refused;    break;
                case h2::event::reset_in:       ++run->m_c.h2_resets_in;  break;
                case h2::event::reset_out:      ++run->m_c.h2_resets_out; break;
            }
        }
    } h{this, c};

    if (!h2::feed(*c->h2, c->in, p, n, max_head, h))
        return;
    if (c->dead)
        return;
    h2_schedule(c);
    if (!c->dead && !c->ssl)
        arm_read(c);
}

// A stream of this connection, before it knows its number: the shared reader sets that and the rest of the stream's
// state, because an answer produced inside h2_start_stream is framed at once.
std::shared_ptr<conn> storage_run::h2_make_stream(const std::shared_ptr<conn>& c)
{
    auto sc = std::make_shared<conn>();
    sc->run       = this;
    sc->id        = m_next_id++;
    sc->h2_parent = c.get();
    sc->h2s.reset(new h2_stream);
    sc->accepted  = c->accepted;
    sc->last_progress = sc->request_began = std::chrono::steady_clock::now();
    sc->ip        = c->ip;
    sc->ip_known  = c->ip_known && !c->ip_forwarded;
    sc->via_offloader = c->via_offloader;
    sc->any_request = true;
    m_streams[sc->id] = sc;
    return sc;
}

// The request as the HTTP/1.1 head parse_head() reads, or the status its head earned instead.
void storage_run::h2_start_stream(const std::shared_ptr<conn>& sc, mux::request& mr, int answer_status)
{
    if (answer_status != 0)
    {
        new_request_id(sc->req.request_id);
        response r;
        r.status = answer_status;
        sc->ph = phase::respond;
        send_response(sc, std::move(r));
        return;
    }
    if (!parse_head(sc, mr.line))
        return;
    sc->req.version = "HTTP/2.0";
    ++m_c.requests;
    runtime_instance::stat_add(m_owner.m_stat_total_messages, 1);
    dispatch(sc);
}

// ─── A stream's body in ─────────────────────────────────────────────────────

void storage_run::h2_pull(const std::shared_ptr<conn>& c, std::string_view fresh)
{
    if (c->dead || !c->h2_parent)
        return;
    conn* parent = c->h2_parent;
    h2_session& s = *parent->h2;
    h2_stream& st = *c->h2s;
    // Called again from inside the phase, by its arm_read(): what just came is held, and the outer call goes on.
    if (c->pulling)
    {
        if (!fresh.empty())
        {
            st.rxq.emplace_back(fresh);
            st.rx_bytes += fresh.size();
        }
        return;
    }
    c->pulling = true;
    uint64_t given = 0;
    auto open = [&] { return !c->dead && c->ph != phase::respond && c->ph != phase::hook_wait && c->park_off >= c->park.size(); };
    auto give = [&](const char* d, size_t n)
    {
        given += n;
        if (!st.synth_chunked)
        {
            plain_in(c, d, n);
            return;
        }
        char hex[20];
        const auto r = std::to_chars(hex, hex + sizeof hex, n, 16);
        std::string framed;
        framed.reserve(n + 32);
        framed.append(hex, r.ptr);
        framed += "\r\n";
        framed.append(d, n);
        framed += "\r\n";
        plain_in(c, framed.data(), framed.size());
    };
    // What was held goes first, in order; then what just came, straight from the frame when nothing is held.
    while (open() && !st.rxq.empty())
    {
        std::string front = std::move(st.rxq.front());
        st.rxq.pop_front();
        size_t at = std::exchange(st.rx_head, 0);
        while (at < front.size() && open())
        {
            const size_t n = std::min(pull_slice, front.size() - at);
            st.rx_bytes -= n;
            at += n;
            give(front.data() + at - n, n);
        }
        if (at < front.size())
        {
            st.rx_head = at;
            st.rxq.push_front(std::move(front));
        }
    }
    while (!fresh.empty())
    {
        if (!open() || !st.rxq.empty())
        {
            st.rxq.emplace_back(fresh);
            st.rx_bytes += fresh.size();
            break;
        }
        const size_t n = std::min(pull_slice, fresh.size());
        const char* d = fresh.data();
        fresh.remove_prefix(n);
        give(d, n);
    }
    if (st.synth_chunked && st.remote_closed && !st.chunk_end_given && st.rxq.empty() && open())
    {
        st.chunk_end_given = true;
        static const char end[] = "0\r\n\r\n";
        plain_in(c, end, sizeof end - 1);
    }
    c->pulling = false;
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
    h2::frame_answer(s, st, std::move(data));
    c->last_progress = std::chrono::steady_clock::now();
    // An answer handed over whole -- send_response's -- ends the stream with its last DATA frame rather than an empty
    // one sent a turn later; a chunked one ends with its last chunk, which cannot be seen coming.
    if (c->after_write == conn::after_kind::finish && st.os == h2_stream::out_state::body)
        st.end_pending = true;
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
        h2::give_back(s, static_cast<uint32_t>(st.rx_bytes));
    }
    s.streams.erase(st.sid);
    st.rxq.clear();
    st.rx_bytes = 0;
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
    // Frames go straight into the connection's queue, which the record layer or the kernel takes from. What it has
    // taken is let go of once it is half the queue, so the queue does not grow -- and get copied whole as it grows --
    // by everything the connection ever sent while several streams keep it from ever running empty.
    if (c->wq_off > 0 && c->wq_off * 2 >= c->wq.size())
    {
        c->wq.erase(0, c->wq_off);
        c->wq_off = 0;
    }
    std::string& out = c->wq;
    const size_t start = out.size();
    std::vector<std::shared_ptr<conn>> ended;
    h2::drain(s, out, unsent(*c), s.out_high,
              [](const std::shared_ptr<conn>& sc) { sc->last_progress = std::chrono::steady_clock::now(); },
              [&](const std::shared_ptr<conn>& sc) { ended.push_back(sc); },
              // A stream with nothing left to send is asked for its next piece only if it is waiting to be asked.
              [&](const std::shared_ptr<conn>& sc)
              {
                  if (sc->after_write != conn::after_kind::none)
                      m_h2_due.push_back(sc);
              });
    if (out.size() > start)
        pump_write(c);
    for (auto& sc : ended)
        close_conn(sc);
}

// A stream whose bytes have all left its own queue is told its write is done, as HTTP/1.1's write completion tells a
// connection: the next piece of its file is read, or its answer ends.
void storage_run::h2_go_on(const std::shared_ptr<conn>& sc)
{
    if (sc->dead || sc->after_write == conn::after_kind::none)
        return;
    if (sc->h3s)
    {
        if (!h3_stream_drained(*sc))
            return;
    }
    else if (!sc->h2s || !sc->h2s->hdr.empty() || sc->h2s->tx_left() || sc->h2s->os == h2_stream::out_state::head)
        return;
    const conn::after_kind next = sc->after_write;
    sc->after_write = conn::after_kind::none;
    if (next == conn::after_kind::finish)
        finish_request(sc);
    else if (next == conn::after_kind::pump)
        file_pump(sc);
}

void storage_run::h2_turn()
{
    std::vector<std::weak_ptr<conn>> due;
    due.swap(m_h2_due);
    for (auto& w : due)
        if (auto sc = w.lock())
            h2_go_on(sc);
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
        due.push_back(sc);
    for (auto& sc : due)
        if (!c->dead)
            h2_go_on(sc);
    if (c->dead)
        return;
    h2_schedule(c);
    if (!c->dead && s.close_when_flushed && !c->wr_pending && unsent(*c) == 0)
        close_conn(c);
}

}   // namespace socketley::storage
