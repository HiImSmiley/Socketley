// HTTP/2 at the entrance, RFC 9113. A client that negotiates it by ALPN reads frames from then on, and each stream
// it opens becomes a connection of its own: the request on it is written back as the HTTP/1.1 head
// parse_http_request_line() already reads, so the table, the entrance's checks, the filters, the backend pool and
// the retries all run as they do over HTTP/1.1, and only the two edges here know the difference.
//
// A stream's connection has a descriptor of its own, unconnected, so that it has a slot in m_client_slots, an
// exchange, and a lifetime like every other client -- nothing above has to learn a second kind of identity. The
// descriptor carries no bytes: a read on it is never armed, a write never submitted, and the two direct-send paths
// that would use it already treat a refused send() as "queue it instead".
//
// Why the entrance has to read frames at all rather than relay them: a browser coalesces names onto one connection
// when the certificate and the address agree, which is exactly an entrance's case, so a connection routed once by
// its SNI would answer a request for one name out of another name's backend. The `:authority` of each stream is the
// only thing that can be routed, and reading it means reading frames.
#include "proxy_instance.h"

#include <charconv>
#include <chrono>
#include <cstdlib>
#include <sys/socket.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "../../shared/http/h2_driver.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/settings.h"

namespace h2  = socketley::h2;
namespace mux = socketley::mux;

// The state is h2::stream's and h2::session's; the names stay because proxy_instance.h holds them as opaque types
// with deleters of their own, and a stream's connection is what this runtime hangs off a stream id.
struct proxy_h2_stream : socketley::h2::stream
{
    // A pull running inside the parse its own arm_read asked for: what arrives then is held, and the outer pull
    // goes on, as the storage's `pulling` does for the same re-entrance.
    bool pulling{false};
};

struct proxy_h2_conn : socketley::h2::session<proxy_client_connection*>
{
    // A frame cut off by the end of a read waits here for the next one.
    std::string frag;
    // A stream that ends from inside a turn asks for another one; the turn it is in sets this instead of nesting,
    // because the queue the inner turn would fill is the one the outer turn is filling.
    bool in_turn{false};
    bool turn_again{false};
};

void proxy_h2_conn_free::operator()(proxy_h2_conn* s) const { delete s; }
void proxy_h2_stream_free::operator()(proxy_h2_stream* s) const { delete s; }

namespace
{

// What waits in the connection's queue before more frames are put in it.
constexpr size_t h2_out_high = 1024 * 1024;
// What the wire may leave untaken before the session is given up: the DATA bound keeps an honest peer near
// h2_out_high, so past this the queue is frames a peer that does not read keeps drawing.
constexpr size_t h2_out_max = 4 * h2_out_high;

// Streams a client may have open here at once, which is a memory bound and not a protocol one: each is a client
// connection of its own, so eight of them cost eight structs and eight descriptors. Eight is already more in flight
// than the six TCP connections a browser would have opened for HTTP/1.1, and the win it is after -- one handshake,
// one congestion window, compressed heads -- does not need more.
constexpr uint32_t h2_max_live = 8;

}   // namespace

// ─── The session ────────────────────────────────────────────────────────────

bool proxy_instance::h2_offered() const
{
    // get_tls() and not m_tls, because the one caller asks while the context it is about to hold is still being
    // built -- reading m_tls there answered no for every listener, which is a whole protocol switched off by the
    // order of two lines.
    if (!m_entrance || m_protocol != protocol_http || !get_tls())
        return false;
    return socketley::settings::flag("SOCKETLEY_PROXY_HTTP2", true);
}

bool proxy_instance::h2_idle(const proxy_client_connection* conn) const
{
    return !conn->h2 || conn->h2->streams.empty();
}

void proxy_instance::h2_begin(proxy_client_connection* conn)
{
    conn->h2.reset(new proxy_h2_conn);
    proxy_h2_conn& s = *conn->h2;
    s.max_live = h2_max_live;
    s.began = s.window_start = std::chrono::steady_clock::now();
    // The settings this side reads by, and the connection's window opened past the 64 KiB it starts with.
    h2::put_settings(s.ctl, {{h2::MAX_CONCURRENT_STREAMS, s.max_live},
                             {h2::INITIAL_WINDOW_SIZE, h2::stream_window},
                             {h2::MAX_HEADER_LIST_SIZE,
                              static_cast<uint32_t>(proxy_client_connection::MAX_HEADER_SIZE)},
                             {h2::ENABLE_PUSH, 0}});
    h2::put_window_update(s.ctl, 0, h2::conn_window - h2::default_window);
    ++m_h2.conns;
    h2_schedule(conn);
}

void proxy_instance::h2_goaway(proxy_client_connection* conn, uint32_t code)
{
    if (!conn->h2 || conn->closing)
        return;
    proxy_h2_conn& s = *conn->h2;
    if (!s.goaway_sent)
        ++m_h2.goaways;
    s.goaway_sent = true;
    h2::put_goaway(s.ctl, s.last_sid, code);
    if (code != h2::NO_ERROR)
    {
        s.close_when_flushed = true;
        s.dying = true;
    }
    h2_schedule(conn);
}

void proxy_instance::h2_parent_gone(proxy_client_connection* conn)
{
    proxy_h2_conn& s = *conn->h2;
    s.dying = true;
    std::vector<proxy_client_connection*> all;
    all.reserve(s.streams.size());
    for (auto& [sid, child] : s.streams)
        all.push_back(child);
    s.streams.clear();
    s.rr.clear();
    // The parent is cleared on each before it is closed, so a child's own release does not reach back into a
    // session whose state is already going.
    for (auto* child : all)
    {
        child->h2_parent = nullptr;
        if (child->fd >= 0)
        {
            child->closing = true;
            close_pair(child->fd, child->ex.backend_fd, close_reason::force);
        }
    }
}

// ─── Frames in ──────────────────────────────────────────────────────────────

void proxy_instance::h2_in(proxy_client_connection* conn, const char* p, size_t n)
{
    // A stream here is a client connection of its own, so what the shared reader asks of this runtime is what an
    // accepted socket already gets: make one, start it, hand it its body, let it go.
    struct host
    {
        proxy_instance* px;
        proxy_client_connection* c;

        bool gone() const { return c->closing || c->fd < 0; }
        void close_now() { c->closing = true; }
        void want_more() {}
        void conn_error(uint32_t code) { px->h2_goaway(c, code); }
        void stream_gone(proxy_client_connection* child)
        {
            if (child->fd < 0)
                return;
            child->closing = true;
            px->close_pair(child->fd, child->ex.backend_fd, close_reason::force);
        }
        void body(proxy_client_connection* child, std::string_view d)
        {
            proxy_h2_stream& st = *child->h2s;
            st.rxq.emplace_back(d);
            st.rx_bytes += d.size();
            child->last_activity = std::chrono::steady_clock::now();
            px->h2_child_pull(child);
        }
        void body_end(proxy_client_connection* child) { px->h2_child_pull(child); }
        proxy_client_connection* make(uint32_t) { return px->h2_make_stream(c); }
        void start(proxy_client_connection* child, mux::request& mr, int answer_status)
        {
            px->h2_start_stream(child, mr, answer_status);
        }
        void count(h2::event e)
        {
            switch (e)
            {
                case h2::event::stream_opened:  ++px->m_h2.streams;    break;
                case h2::event::stream_refused: ++px->m_h2.refused;    break;
                case h2::event::reset_in:       ++px->m_h2.resets_in;  break;
                case h2::event::reset_out:      ++px->m_h2.resets_out; break;
            }
        }
    } h{this, conn};

    if (!h2::feed(*conn->h2, conn->h2->frag, p, n, proxy_client_connection::MAX_HEADER_SIZE, h))
        return;
    if (conn->closing || conn->fd < 0)
        return;
    h2_schedule(conn);
}

// A stream of this connection, before it knows its number: the shared reader sets that and the rest of the stream's
// state, because an answer produced inside h2_start_stream is framed at once.
proxy_client_connection* proxy_instance::h2_make_stream(proxy_client_connection* parent)
{
    // A descriptor of its own, unconnected, so the slot and the lifetime are a client's and nothing above has to
    // know this one carries no bytes.
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0 || fd >= MAX_FDS)
    {
        if (fd >= 0)
            close_tracked(fd);
        return nullptr;
    }
    auto owned = client_pool_acquire(fd);
    if (!owned)
    {
        close_tracked(fd);
        return nullptr;
    }
    proxy_client_connection* child = owned.get();
    child->h2s.reset(new proxy_h2_stream);
    child->h2_parent = parent;
    child->last_activity = std::chrono::steady_clock::now();
    // The address the request came from is the session's, read when it was accepted, since this socket has no peer.
    child->peer_addr = parent->peer_addr;
    m_client_slots[fd] = owned.release();
    m_client_count++;
    m_conn_idx[fd].side = conn_client;
    m_conn_idx[fd].client = child;
    return child;
}

// The request as the HTTP/1.1 head parse_http_request_line() reads, or the status its head earned instead.
void proxy_instance::h2_start_stream(proxy_client_connection* child, mux::request& mr, int answer_status)
{
    if (answer_status == 431)
    {
        send_error(child, "431 Request Header Fields Too Large", "Header Too Large\n");
        return;
    }
        child->partial = mr.line;
    drive_client_request(child, child->fd, false);
}

// ─── A stream's body in ─────────────────────────────────────────────────────

// A stream's reads come from its DATA frames: what they brought and the parser above has not taken yet, handed over
// as a recv's bytes would be, and with a body of no stated length framed as chunks the way the head says.
bool proxy_instance::h2_child_pull(proxy_client_connection* child)
{
    proxy_client_connection* parent = child->h2_parent;
    if (!parent || !parent->h2 || !child->h2s || child->closing)
        return true;
    proxy_h2_conn& s = *parent->h2;
    proxy_h2_stream& st = *child->h2s;
    // Called again from inside the parse, by its own arm_read: what is held stays held and the outer call goes on.
    if (st.pulling)
        return true;
    st.pulling = true;

    uint64_t given = 0;
    auto give = [&](std::string_view d)
    {
        // An empty DATA frame carries nothing, and as a chunk it would read as the last one.
        if (d.empty())
            return;
        given += d.size();
        if (!st.synth_chunked)
        {
            child->partial.append(d);
            return;
        }
        char hex[20];
        const auto r = std::to_chars(hex, hex + sizeof hex, d.size(), 16);
        child->partial.append(hex, r.ptr);
        child->partial += "\r\n";
        child->partial.append(d);
        child->partial += "\r\n";
    };

    while (!st.rxq.empty() && child->partial.size() < read_buffer_bytes())
    {
        std::string front = std::move(st.rxq.front());
        st.rxq.pop_front();
        const size_t at = std::exchange(st.rx_head, 0);
        st.rx_bytes -= front.size() - at;
        give(std::string_view(front).substr(at));
    }
    bool fed = given > 0;
    if (st.synth_chunked && st.remote_closed && !st.chunk_end_given && st.rxq.empty())
    {
        st.chunk_end_given = true;
        child->partial += "0\r\n\r\n";
        fed = true;
    }

    if (given > 0)
    {
        // What the parser took is given back, in increments of half a window so the updates are few.
        st.rx_unacked += static_cast<uint32_t>(given);
        if (!st.remote_closed && st.rx_unacked >= h2::stream_window / 2)
        {
            h2::put_window_update(s.ctl, st.sid, st.rx_unacked);
            st.recv_avail += st.rx_unacked;
            st.rx_unacked = 0;
        }
        h2::give_back(s, static_cast<uint32_t>(given));
    }
    // Only when there was something to give.  An arm_read with an empty queue means the parser wants bytes that
    // have not arrived yet, and driving it again on nothing is a loop: drive -> arm_read -> pull -> drive, which is
    // what this did until the log showed the same line twenty-five times in one millisecond.  The next DATA frame
    // is what wakes it, through host.body.
    const proxy_h2_stream* const held = child->h2s.get();
    if (fed && !child->closing && child->fd >= 0)
        drive_client_request(child, child->fd, false);
    // Held across the drive as well, so a read armed from inside the parse finds the pull already running; a drive
    // that ended the stream freed st, and nothing is left to clear.
    if (child->h2s.get() == held)
        st.pulling = false;
    if (!parent->closing)
        h2_schedule(parent);
    return true;
}

// ─── A stream's answer out ──────────────────────────────────────────────────

// A stream's answer is not written to a socket: it is read back into this stream's HEADERS and DATA and framed onto
// the connection its session belongs to.
bool proxy_instance::h2_child_flush(proxy_client_connection* child)
{
    proxy_client_connection* parent = child->h2_parent;
    if (!parent || !parent->h2 || !child->h2s)
    {
        child->write_queue.clear();
        return true;
    }
    proxy_h2_conn& s = *parent->h2;
    proxy_h2_stream& st = *child->h2s;
    if (st.reset || st.local_closed || s.dying)
    {
        child->write_queue.clear();
        return true;
    }
    while (!child->write_queue.empty())
    {
        auto chunk = child->write_queue.take_front();
        h2::frame_answer(s, st, std::string(chunk.data(), chunk.size()));
        chunk.clear();
    }
    child->last_activity = std::chrono::steady_clock::now();
    h2::enqueue(s, st);
    h2_schedule(parent);
    return true;
}

size_t proxy_instance::stream_answer_held(const proxy_client_connection* conn) const
{
    if (conn->h3s)
        return static_cast<size_t>(conn->h3s->held());
    if (!conn->h2s)
        return 0;
    const proxy_h2_stream& st = *conn->h2s;
    return st.tx_left() + st.hdr.size() + st.head_acc.size() + st.dechunk_in.size();
}

// The answer is over, which on a stream is END_STREAM and not a half-closed socket.
void proxy_instance::h2_child_end(proxy_client_connection* child)
{
    proxy_client_connection* parent = child->h2_parent;
    if (!parent || !parent->h2 || !child->h2s)
        return;
    proxy_h2_conn& s = *parent->h2;
    proxy_h2_stream& st = *child->h2s;
    if (st.reset || st.local_closed)
        return;
    st.end_pending = true;
    h2::enqueue(s, st);
    h2_schedule(parent);
}

void proxy_instance::h2_stream_gone(proxy_client_connection* child)
{
    proxy_client_connection* parent = child->h2_parent;
    child->h2_parent = nullptr;
    if (!parent || !parent->h2 || !child->h2s)
    {
        child->h2s.reset();
        return;
    }
    proxy_h2_conn& s = *parent->h2;
    proxy_h2_stream& st = *child->h2s;
    if (!s.dying)
    {
        // An answer that was framed whole ends with END_STREAM and not a reset.  A proxy closing a connection is
        // how HTTP/1.1 says an answer ended (RFC 9112 6.3), and a client may throw away an answer it was reset out
        // of.  Measured on the live entrance before this: every completed request left one h2_resets_out, nine
        // streams and six resets, which is this line and not the clients.
        const bool answered = st.os != h2::stream::out_state::head && st.hdr.empty() && !st.tx_left();
        if (!st.reset && !st.local_closed && answered)
        {
            h2::put_data(s.ctl, st.sid, {}, true);
            st.local_closed = true;
        }
        // Ended before its answer did, or with its request's body still coming: the client is told.
        else if (!st.reset && (!st.local_closed || !st.remote_closed))
        {
            h2::put_rst(s.ctl, st.sid, st.local_closed ? h2::NO_ERROR : h2::CANCEL);
            ++m_h2.resets_out;
            st.reset = true;
        }
        // What it received and the parser above never took is the connection's again.
        h2::give_back(s, static_cast<uint32_t>(st.rx_bytes));
    }
    s.streams.erase(st.sid);
    child->h2s.reset();
    if (!s.dying && !parent->closing)
        h2_schedule(parent);
}

// ─── The turn ───────────────────────────────────────────────────────────────

void proxy_instance::h2_wrote(proxy_client_connection* conn)
{
    if (!conn->h2 || conn->closing || conn->fd < 0 || conn->h2->rr.empty() ||
        conn->write_queue.bytes() >= h2_out_high)
        return;
    h2_schedule(conn);
}

void proxy_instance::h2_schedule(proxy_client_connection* conn)
{
    if (!conn->h2 || conn->closing || conn->fd < 0)
        return;
    proxy_h2_conn& s = *conn->h2;
    // A stream ending inside the turn asks for another one; that becomes the next turn rather than a deeper one.
    if (s.in_turn)
    {
        s.turn_again = true;
        return;
    }
    s.in_turn = true;
    do
    {
        s.turn_again = false;
        std::string out;
        std::vector<proxy_client_connection*> ended;
        // By descriptor, since a stream that ends in this turn is gone before its backend could be read again.
        std::vector<int> wrote;
        h2::drain(s, out, conn->write_queue.bytes(), h2_out_high,
                  [&](proxy_client_connection* child)
                  {
                      child->last_activity = std::chrono::steady_clock::now();
                      wrote.push_back(child->fd);
                  },
                  [&](proxy_client_connection* child) { ended.push_back(child); },
                  [](proxy_client_connection*) {});
        if (!out.empty())
        {
            conn->write_queue.emplace(std::move(out));
            if (conn->write_queue.bytes() > h2_out_max)
            {
                // The rest would never be read, and shutting the socket ends the write in flight with it.
                conn->write_queue.clear();
                conn->closing = true;
                ::shutdown(conn->fd, SHUT_RDWR);
            }
            else if (!conn->write_pending && !flush_client_write_queue(conn))
                conn->closing = true;
        }
        // Whose last frame has gone: the stream's connection goes with it, which is also what frees its descriptor.
        for (auto* child : ended)
            if (child->fd >= 0)
            {
                child->closing = true;
                close_pair(child->fd, child->ex.backend_fd);
            }
        // A stream whose answer the wire has taken below the pacing point has its backend read again.
        for (const int fd : wrote)
            if (fd >= 0 && fd < MAX_FDS && m_conn_idx[fd].side == conn_client &&
                m_conn_idx[fd].client->h2_parent == conn)
                resume_stream_backend(m_conn_idx[fd].client);
    } while (s.turn_again && !conn->closing && conn->fd >= 0);
    s.in_turn = false;

    if (s.close_when_flushed && !conn->write_pending && conn->write_queue.empty())
        conn->closing = true;
}
