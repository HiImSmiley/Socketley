// HTTP/3 at the entrance, RFC 9114 over QUIC: a UDP socket on the listener's port, whose QUIC, TLS and HTTP/3 are
// shared/http/h3_endpoint.cpp's. What is here is what only this runtime can say about a stream, and it is the same answer
// it gives for HTTP/2: a stream becomes a connection of its own, so the request on it is routed by its `:authority`
// through the table, the entrance's checks, the filters, the backend pool and the retries, and only the two edges
// know the difference.
//
// A stream's reads come from its own body rather than from a socket, and its answer is handed to h3::answer rather
// than written to one -- the same two diversions HTTP/2 needs, at the same two chokepoints. Everything else about a
// stream's connection, down to its descriptor and its exchange, is what an accepted socket gets.
//
// A browser learns of HTTP/3 from the Alt-Svc header every answer over TCP carries, and goes on over TCP when UDP
// does not reach.
#include "proxy_instance.h"

#if SOCKETLEY_HTTP3

#include <charconv>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>

#include "../../shared/http/h3_endpoint.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/settings.h"

namespace
{

// Streams a client may have open at once, for the same reason HTTP/2 bounds them here: each is a client connection
// of its own, so each costs a struct and a descriptor.
constexpr uint64_t h3_max_live = 8;

}   // namespace

// What the shared endpoint asks of this runtime. A stream's connection is found by the descriptor the stream
// carries as its key, through the same slot table every other client is in.
class proxy_h3_host final : public socketley::h3::host
{
public:
    explicit proxy_h3_host(proxy_instance& px) : m_px(px) {}

    uint64_t make_stream(socketley::h3::stream& st) override { return m_px.h3_make_stream(st); }
    void start_stream(socketley::h3::stream& st, socketley::mux::request& r, int answer_status) override
    {
        m_px.h3_start_stream(st, r, answer_status);
    }
    bool can_take(socketley::h3::stream& st) override { return m_px.h3_can_take(st); }
    void take(socketley::h3::stream& st, const char* d, size_t n) override { m_px.h3_take(st, d, n); }
    void write_done(socketley::h3::stream& st) override { m_px.h3_write_done(st); }
    void stream_gone(socketley::h3::stream& st) override { m_px.h3_host_stream_gone(st); }
    void count(socketley::h3::event e) override { m_px.h3_count(e); }

private:
    proxy_instance& m_px;
};

// ─── The endpoint ───────────────────────────────────────────────────────────

bool proxy_instance::h3_offered() const
{
    // The same three things h2 needs, since a stream is routed by its authority either way; and one more, because
    // HTTP/3 means a UDP socket of its own on the same port.
    if (!h2_offered())
        return false;
    return socketley::settings::flag("SOCKETLEY_PROXY_HTTP3", true);
}

bool proxy_instance::h3_open(uint16_t port)
{
    socketley::h3::options o;
    o.owner      = this;
    o.port       = port;
    o.advertise  = port;
    o.cert       = get_cert_path();
    o.key        = get_key_path();
    o.ca         = m_mesh.client_ca;
    o.max_head   = proxy_client_connection::MAX_HEADER_SIZE;
    o.max_streams = h3_max_live;
    m_h3_host = std::make_unique<proxy_h3_host>(*this);
    std::string err;
    m_h3 = socketley::h3::open(o, *m_h3_host, *m_loop, err);
    if (!m_h3)
    {
        // An entrance without HTTP/3 still serves; only a browser's try over UDP is wasted, and it falls back.
        LOG_WARN(("proxy: HTTP/3 not offered -- " + err).c_str());
        m_h3_host.reset();
        return false;
    }
    m_alt_svc = socketley::h3::alt_svc(*m_h3);
    return true;
}

bool proxy_instance::h3_owns(const io_request* req) const
{
    return m_h3 && socketley::h3::owns(*m_h3, req);
}

void proxy_instance::h3_cqe(io_request* req, int res) { socketley::h3::completion(*m_h3, req, res); }
void proxy_instance::h3_flush() { if (m_h3) socketley::h3::flush(*m_h3); }
void proxy_instance::h3_stop() { if (m_h3) socketley::h3::stop(*m_h3); }

void proxy_instance::h3_count(socketley::h3::event e)
{
    switch (e)
    {
        case socketley::h3::event::conn_opened:   ++m_h3t.conns;     break;
        case socketley::h3::event::stream_opened: ++m_h3t.streams;   break;
        case socketley::h3::event::retry_sent:    ++m_h3t.retries;   break;
        case socketley::h3::event::forwarded:     ++m_h3t.forwarded; break;
    }
}

// ─── A stream's request in ──────────────────────────────────────────────────

// A stream of this connection: a client connection of its own, with a descriptor that is real but unconnected, for
// the reasons given in proxy_h2.cpp.  Its descriptor is the key the endpoint carries, so it is found through the
// same slot table as every other client.
uint64_t proxy_instance::h3_make_stream(socketley::h3::stream& st)
{
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0 || fd >= MAX_FDS)
    {
        if (fd >= 0)
            close_tracked(fd);
        return 0;
    }
    auto owned = client_pool_acquire(fd);
    if (!owned)
    {
        close_tracked(fd);
        return 0;
    }
    proxy_client_connection* child = owned.get();
    child->h3s = &st;
    child->last_activity = std::chrono::steady_clock::now();
    // The address the request came from is the connection's; this socket has no peer at all to ask.
    child->peer_addr = socketley::h3::peer_text_of(st);
    if (const size_t colon = child->peer_addr.rfind(':'); colon != std::string::npos)
        child->peer_addr.erase(colon);
    m_client_slots[fd] = owned.release();
    m_client_count++;
    m_conn_idx[fd].side = conn_client;
    m_conn_idx[fd].client = child;
    return static_cast<uint64_t>(fd);
}

// The descriptor a stream's key names, or nullptr when its connection has already gone.
proxy_client_connection* proxy_instance::h3_child(const socketley::h3::stream& st) const
{
    const auto fd = static_cast<int>(st.user);
    if (fd <= 0 || fd >= MAX_FDS)
        return nullptr;
    auto* c = m_client_slots[fd];
    return c && c->h3s == &st ? c : nullptr;
}

void proxy_instance::h3_start_stream(socketley::h3::stream& st, socketley::mux::request& mr, int answer_status)
{
    auto* child = h3_child(st);
    if (!child || child->closing)
        return;
    if (answer_status == 431)
    {
        send_error(child, "431 Request Header Fields Too Large", "Header Too Large\n");
        return;
    }
    child->partial = mr.line;
    drive_client_request(child, child->fd, false);
}

// ─── A stream's body in ─────────────────────────────────────────────────────

bool proxy_instance::h3_can_take(socketley::h3::stream& st)
{
    auto* child = h3_child(st);
    return child && !child->closing && child->partial.size() < read_buffer_bytes();
}

void proxy_instance::h3_take(socketley::h3::stream& st, const char* d, size_t n)
{
    auto* child = h3_child(st);
    if (!child || child->closing)
        return;
    child->partial.append(d, n);
    child->last_activity = std::chrono::steady_clock::now();
    if (child->fd >= 0)
        drive_client_request(child, child->fd, false);
}

// A stream's reads come from its own body: what its DATA brought and the parser above has not taken yet.
bool proxy_instance::h3_child_pull(proxy_client_connection* child)
{
    if (child->h3s)
        socketley::h3::pull(*child->h3s, {});
    return true;
}

// ─── A stream's answer out ──────────────────────────────────────────────────

// A stream's answer is not written to a socket: it is read back into HTTP/3's fields and DATA.
bool proxy_instance::h3_child_flush(proxy_client_connection* child)
{
    if (!child->h3s)
    {
        child->write_queue.clear();
        return true;
    }
    while (!child->write_queue.empty())
    {
        auto chunk = child->write_queue.take_front();
        // Not the last piece on its own account: a stream's end is said by h3_child_end, which is where this proxy
        // decides an answer is over.
        socketley::h3::answer(*child->h3s, std::string(chunk.data(), chunk.size()), false);
        chunk.clear();
    }
    child->last_activity = std::chrono::steady_clock::now();
    h3_flush();
    return true;
}

// The answer is over, which on a stream is its end and not a half-closed socket.
void proxy_instance::h3_child_end(proxy_client_connection* child)
{
    if (!child->h3s)
        return;
    if (!socketley::h3::answer_end(*child->h3s))
    {
        // It could not be ended -- no head was ever framed -- so the stream goes instead.
        h3_child_gone(child);
        return;
    }
    h3_flush();
}

// This runtime is letting go of a stream's connection: the stream is ended toward the client.
void proxy_instance::h3_child_gone(proxy_client_connection* child)
{
    if (socketley::h3::stream* st = child->h3s)
    {
        child->h3s = nullptr;
        // A connection closing after its answer is how HTTP/1.1 says the answer ended -- RFC 9112 6.3 -- and on a
        // stream that is END_STREAM.  answer_end refuses when no head was ever framed, which is a request nothing
        // answered, and then the stream is reset as a cancelled one.
        if (socketley::h3::answer_end(*st))
            socketley::h3::release(*st);
        else
            socketley::h3::gone(*st);
        h3_flush();
    }
}

// And the other direction: QUIC is done with the stream, so its connection goes.
void proxy_instance::h3_host_stream_gone(socketley::h3::stream& st)
{
    auto* child = h3_child(st);
    if (!child)
        return;
    child->h3s = nullptr;
    if (child->fd >= 0)
    {
        child->closing = true;
        close_pair(child->fd, child->ex.backend_fd, close_reason::force);
    }
}

// A stream whose bytes nghttp3 has all taken may have room again for its backend's answer; it is resumed after the
// endpoint's walk, since a refused arm closes the stream the walk is on.
void proxy_instance::h3_write_done(socketley::h3::stream& st)
{
    auto* child = h3_child(st);
    if (!child || child->closing || child->ex.backend_fd < 0 || child->ex.backend_fd >= MAX_FDS)
        return;
    const auto& be = m_conn_idx[child->ex.backend_fd];
    if (be.side == conn_backend && !be.backend->read_pending && !client_backpressured(be.backend))
        m_h3_resume.push_back(child->fd);
}

#else

bool proxy_instance::h3_offered() const { return false; }
bool proxy_instance::h3_open(uint16_t) { return false; }
bool proxy_instance::h3_owns(const io_request*) const { return false; }
void proxy_instance::h3_cqe(io_request*, int) {}
void proxy_instance::h3_flush() {}
void proxy_instance::h3_stop() {}
bool proxy_instance::h3_child_pull(proxy_client_connection*) { return true; }
bool proxy_instance::h3_child_flush(proxy_client_connection* child) { child->write_queue.clear(); return true; }
void proxy_instance::h3_child_end(proxy_client_connection*) {}
void proxy_instance::h3_child_gone(proxy_client_connection*) {}

#endif
