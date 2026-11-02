// HTTP/3 for a storage runtime with --tls: a UDP socket on the TCP listener's port, whose QUIC, TLS and HTTP/3 are
// shared/http/h3_endpoint.cpp's. What is left here is what only this runtime can say about a stream: each request is a
// stream, and each stream a conn with no socket, exactly as for HTTP/2 -- its head is written back as the HTTP/1.1
// head parse_head() reads, its body handed to its phase as a recv's bytes would be, and its answer read back into
// HTTP/3's fields and DATA. Every operation runs as it does over HTTP/1.1.
//
// A body in is given back to the window only as its phase takes it, which is can_take() below. A body out is held
// until the peer acknowledges it, since QUIC may send it again; a stream is told its write is done -- and asked for
// the next piece of a file -- once nghttp3 has taken all it was handed. A browser learns of HTTP/3 from the Alt-Svc
// header every answer over TCP carries, and goes on over TCP when UDP does not reach.
#include "storage_run.h"
#include "storage_instance.h"

#if SOCKETLEY_HTTP3

#include <charconv>
#include <cstdlib>
#include <cstring>

#include "../../shared/http/h3_endpoint.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/number_parse.h"
#include "../../shared/util/settings.h"

namespace socketley::storage
{

namespace
{

constexpr size_t max_head = 32 * 1024;

}   // namespace

// What the shared endpoint asks of this runtime. A stream's conn is found by the id the stream carries, not by a
// pointer: a stream the endpoint still holds can outlive its conn by an operation in flight, and a miss there is a
// miss rather than a read of something freed.
class storage_h3_host final : public h3::host
{
public:
    explicit storage_h3_host(storage_run& run) : m_run(run) {}

    uint64_t make_stream(h3::stream& st) override { return m_run.h3_make_stream(st); }
    void start_stream(h3::stream& st, mux::request& r, int answer_status) override
    {
        m_run.h3_start_stream(st, r, answer_status);
    }
    bool can_take(h3::stream& st) override { return m_run.h3_can_take(st); }
    void take(h3::stream& st, const char* d, size_t n) override { m_run.h3_take(st, d, n); }
    void write_done(h3::stream& st) override { m_run.h3_write_done(st); }
    void stream_gone(h3::stream& st) override { m_run.h3_host_stream_gone(st); }
    void count(h3::event e) override { m_run.h3_count(e); }
    void sent(size_t n) override { m_run.h3_sent(n); }
    uint32_t shards() const override { return m_run.h3_shards(); }

private:
    storage_run& m_run;
};

// ─── The endpoint ───────────────────────────────────────────────────────────

bool storage_run::h3_open(uint16_t port, uint16_t advertise, uint32_t shard, uint32_t shards, const std::string& cert,
                          const std::string& key, const std::string& ca)
{
    h3::options o;
    o.owner     = this;
    o.port      = port;
    o.advertise = advertise;
    o.shard     = shard;
    o.shards    = std::max<uint32_t>(shards, 1);
    o.cert      = cert;
    o.key       = key;
    o.ca        = ca;
    o.max_head  = max_head;
    // This runtime's own dials, which the endpoint's defaults otherwise answer for.
    if (const char* cc = settings::text("SOCKETLEY_STORAGE_HTTP3_CC"); cc && *cc)
        o.cc = cc;
    if (const auto v = settings::number<size_t>("SOCKETLEY_STORAGE_HTTP3_RETRY_AFTER"))
        o.retry_after = *v;
    m_h3_host = std::make_unique<storage_h3_host>(*this);
    std::string err;
    m_h3 = h3::open(o, *m_h3_host, m_loop, err);
    if (!m_h3)
    {
        LOG_WARN(("storage: HTTP/3 not offered -- " + err).c_str());
        m_h3_host.reset();
        return false;
    }
    m_alt_svc = h3::alt_svc(*m_h3);
    return true;
}

bool storage_run::h3_owns(io_request* req) const { return (m_h3 && h3::owns(*m_h3, req)) || h3::owns_retired(req); }
// A completion of an endpoint a restart replaced goes to it, kept until its last is in.
void storage_run::h3_cqe(io_request* req, int res)
{
    if (m_h3 && h3::owns(*m_h3, req))
        h3::completion(*m_h3, req, res);
    else
        h3::completion_retired(req, res);
}
void storage_run::h3_flush_dirty() { if (m_h3) h3::flush(*m_h3); }
size_t storage_run::h3_open_conns() const { return m_h3 ? h3::open_conns(*m_h3) : 0; }
void storage_run::h3_stop() { if (m_h3) h3::stop(*m_h3); }
uint32_t storage_run::h3_shards() const { return std::max<uint32_t>(m_owner.get_shards(), 1); }

void storage_run::h3_count(h3::event e)
{
    switch (e)
    {
        case h3::event::conn_opened:   ++m_c.h3_conns;     break;
        case h3::event::stream_opened: ++m_c.h3_streams;   break;
        case h3::event::retry_sent:    ++m_c.h3_retries;   break;
        case h3::event::forwarded:     ++m_c.h3_forwarded; break;
    }
}

void storage_run::h3_sent(size_t n)
{
    runtime_instance::stat_add(m_owner.m_stat_bytes_out, static_cast<uint64_t>(n));
    m_c.bytes_out += static_cast<uint64_t>(n);
}

// ─── A stream's request in ──────────────────────────────────────────────────

// A stream of this connection, before it knows its head: its conn is this runtime's, and the id is what the
// endpoint carries so that it can be found again.
uint64_t storage_run::h3_make_stream(h3::stream& st)
{
    auto sc = std::make_shared<conn>();
    sc->run       = this;
    sc->id        = m_next_id++;
    sc->h3s       = &st;
    sc->quic_ssl  = h3::tls_of(st);
    sc->accepted  = sc->last_progress = sc->request_began = std::chrono::steady_clock::now();
    // Known only when the stream says whose it is, or the default address would be taken as the client's.
    if (const sockaddr_storage* a = h3::peer_of(st))
    {
        sc->ip = client_ip_from(reinterpret_cast<const sockaddr*>(a));
        sc->ip_known = true;
    }
    sc->peer      = h3::peer_text_of(st);
    sc->any_request = true;
    m_streams[sc->id] = sc;
    return sc->id;
}

// The request as the HTTP/1.1 head parse_head() reads, or the status its head earned instead.
void storage_run::h3_start_stream(h3::stream& st, mux::request& mr, int answer_status)
{
    auto sc = find(st.user);
    if (!sc || sc->dead)
        return;
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
    sc->req.version = "HTTP/3";
    ++m_c.requests;
    runtime_instance::stat_add(m_owner.m_stat_total_messages, 1);
    dispatch(sc);
}

// ─── A stream's body in ─────────────────────────────────────────────────────

bool storage_run::h3_can_take(h3::stream& st)
{
    auto sc = find(st.user);
    if (!sc || sc->dead)
        return false;
    return sc->ph != phase::respond && sc->ph != phase::hook_wait && sc->park_off >= sc->park.size();
}

void storage_run::h3_take(h3::stream& st, const char* d, size_t n)
{
    if (auto sc = find(st.user); sc && !sc->dead)
    {
        sc->last_progress = std::chrono::steady_clock::now();
        plain_in(sc, d, n);
    }
}

void storage_run::h3_pull(const std::shared_ptr<conn>& c, std::string_view fresh)
{
    if (c->h3s)
        h3::pull(*c->h3s, fresh);
}

// ─── A stream's answer out ──────────────────────────────────────────────────

void storage_run::h3_stream_out(const std::shared_ptr<conn>& c, std::string data)
{
    if (!c->h3s)
        return;
    c->last_progress = std::chrono::steady_clock::now();
    // An answer handed over whole -- send_response's, whose end is already decided -- carries the stream's end with
    // its last bytes, in the same packet, instead of in one of its own a turn later; finish_request still follows
    // for the rest. A chunked one ends with its last chunk, which the stream cannot see coming.
    h3::answer(*c->h3s, std::move(data), c->after_write == conn::after_kind::finish);
}

void storage_run::h3_stream_end(const std::shared_ptr<conn>& c)
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
    if (!c->h3s || !h3::answer_end(*c->h3s))
        close_conn(c);
}

// A stream whose bytes nghttp3 has all taken is told its write is done, which asks it for the next piece of its
// file or ends its answer; the turn it is told in is the one the endpoint is finishing.
void storage_run::h3_write_done(h3::stream& st)
{
    auto sc = find(st.user);
    if (sc && !sc->dead && sc->after_write != conn::after_kind::none)
        m_h2_due.push_back(sc);
}

// QUIC and HTTP/3 are done with the stream: its conn goes, and the stream's own state is the endpoint's to let go.
void storage_run::h3_host_stream_gone(h3::stream& st)
{
    auto sc = find(st.user);
    if (!sc)
        return;
    // The session goes with the connection; a conn kept a little longer by an operation in flight must not reach it.
    sc->quic_ssl = nullptr;
    sc->h3s = nullptr;
    close_conn(sc);
}

void storage_run::h3_stream_gone(const std::shared_ptr<conn>& c)
{
    if (h3::stream* st = c->h3s)
    {
        c->h3s = nullptr;
        c->quic_ssl = nullptr;
        h3::gone(*st);
    }
}

bool storage_run::h3_stream_drained(const conn& c) const
{
    return c.h3s && c.h3s->drained();
}

}   // namespace socketley::storage

#else

namespace socketley::storage
{

bool storage_run::h3_open(uint16_t, uint16_t, uint32_t, uint32_t, const std::string&, const std::string&,
                          const std::string&)
{
    return false;
}
bool storage_run::h3_owns(io_request*) const { return false; }
void storage_run::h3_cqe(io_request*, int) {}
void storage_run::h3_pull(const std::shared_ptr<conn>&, std::string_view) {}
void storage_run::h3_stream_out(const std::shared_ptr<conn>&, std::string) {}
void storage_run::h3_stream_end(const std::shared_ptr<conn>&) {}
void storage_run::h3_stream_gone(const std::shared_ptr<conn>&) {}
bool storage_run::h3_stream_drained(const conn&) const { return true; }
void storage_run::h3_flush_dirty() {}
void storage_run::h3_stop() {}
size_t storage_run::h3_open_conns() const { return 0; }

}   // namespace socketley::storage

#endif
