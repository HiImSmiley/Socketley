#include "mqtt_run.h"

#include <algorithm>
#include <utility>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <iterator>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/x509.h>
#include <unistd.h>

#include "mqtt_command.h"
#include "mqtt_instance.h"
#include "mqtt_lua.h"
#include "../idp/idp_session.h"
#include "../storage/password_hash.h"
#include "../../shared/crypto/tls_context.h"
#include "../../shared/http/ws_protocol.h"
#include "../../shared/ipc/route_relay.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/net/socket_tuning.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/persist/replaced_file.h"
#include "../../shared/runtime/runtime_manager.h"
#include "../../shared/runtime/stats_text.h"
#include "../../shared/util/ascii.h"
#include "../../shared/util/byte_codec.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/text_list.h"
#include "../../shared/util/version.h"
#include "../../shared/util/wall_clock.h"

namespace socketley::mqtt
{

namespace
{

// The buffer group the broker's reads take their buffers from, one per runtime type on a loop.
constexpr uint16_t ring_group = 6;
constexpr uint32_t ring_bufs = 1024;
constexpr uint32_t ring_buf_bytes = 4096;
constexpr int64_t close_grace_ms = 5000;
constexpr int64_t handshake_ms = 10000;
constexpr size_t tap_limit = 10000;
constexpr uint32_t snapshot_magic = 0x4E524D51;   // "QMRN"

// The listener is IPv4, so its peers are.
std::string peer_text(const sockaddr_in& a)
{
    char host[INET_ADDRSTRLEN] = {};
    ::inet_ntop(AF_INET, &a.sin_addr, host, sizeof host);
    return std::string(host) + ":" + std::to_string(ntohs(a.sin_port));
}

// The common name a verified client certificate carries, empty without one.
std::string peer_common_name(SSL* ssl)
{
    X509* cert = SSL_get1_peer_certificate(ssl);
    if (!cert)
        return {};
    std::string out;
    if (SSL_get_verify_result(ssl) == X509_V_OK)
    {
        char cn[256] = {};
        if (X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, cn, sizeof cn) > 0)
            out = cn;
    }
    X509_free(cert);
    return out;
}

// A header's value from an HTTP request head, its name compared without case; empty when absent.
std::string_view header_value(std::string_view head, std::string_view name)
{
    std::string_view rest = head;
    socketley::take_item(rest, '\n');
    while (!rest.empty())
    {
        std::string_view line = socketley::take_item(rest, '\n');
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        const size_t colon = line.find(':');
        if (colon == std::string_view::npos)
            continue;
        if (!socketley::ascii::iequals(line.substr(0, colon), name))
            continue;
        std::string_view v = line.substr(colon + 1);
        while (!v.empty() && (v.front() == ' ' || v.front() == '\t'))
            v.remove_prefix(1);
        while (!v.empty() && (v.back() == ' ' || v.back() == '\t'))
            v.remove_suffix(1);
        return v;
    }
    return {};
}

bool list_has(std::string_view list, std::string_view word)
{
    while (!list.empty())
    {
        std::string_view one = socketley::take_item(list);
        while (!one.empty() && one.front() == ' ')
            one.remove_prefix(1);
        while (!one.empty() && one.back() == ' ')
            one.remove_suffix(1);
        if (socketley::ascii::iequals(one, word))
            return true;
    }
    return false;
}

std::string message_line(const message& m)
{
    std::string out = "{\"topic\":";
    socketley::json::quote_into(out, m.topic);
    out += ",\"payload\":";
    payload_json(out, m.payload);
    out += ",\"qos\":" + std::to_string(m.qos);
    out += m.retain ? ",\"retain\":true" : ",\"retain\":false";
    out += ",\"client\":";
    socketley::json::quote_into(out, m.from_client);
    out += "}";
    return out;
}

}   // namespace

mqtt_run::mqtt_run(mqtt_instance& owner, event_loop& loop)
    : m_owner(owner), m_loop(loop), m_fio(loop, this), m_pool(2), m_alive(std::make_shared<bool>(true))
{
}

mqtt_run::~mqtt_run()
{
    *m_alive = false;
    m_pool.stop();
    for (auto& [id, c] : m_conns)
        if (c->ssl)
            tls_context::free_ssl(c->ssl);
    for (auto& c : m_closing)
        if (c->ssl)
            tls_context::free_ssl(c->ssl);
    m_loop.deregister_owner(this);
}

// Keep alive, expiry and wills are counted in seconds, so the coarse clock serves, at a fraction of the cost.
int64_t mqtt_run::now_ms() const
{
    return wall::now_ms_coarse();
}

// ── Starting and stopping ───────────────────────────────────────────────────

bool mqtt_run::start(std::string& why)
{
    m_loop.register_owner(this);
    if (!m_pool.attach(m_fio))
        m_pool.stop();

    broker_config cfg;
    cfg.max_packet         = m_owner.get_max_packet();
    cfg.session_expiry_max = m_owner.get_session_expiry();
    cfg.session_queue      = m_owner.get_session_queue();
    cfg.retained_max_bytes = m_owner.get_retained_max();
    cfg.max_sessions       = m_owner.get_max_sessions();
    cfg.keepalive_max      = m_owner.get_keepalive_max();
    cfg.write_limit        = m_owner.get_write_buffer() ? m_owner.get_write_buffer() : (4u << 20);
    m_read_hold            = cfg.write_limit * 2 + cfg.max_packet;
    cfg.version            = SOCKETLEY_VERSION;
    cfg.sys_interval_s     = 10;
    // A shard of several publishes its own figures under its number, and every shard keeps them all.
    cfg.sharded            = m_owner.get_shards() > 1;
    if (cfg.sharded)
        cfg.sys_prefix = "shard/" + std::to_string(m_owner.get_shard_index()) + "/";
    m_broker = std::make_unique<broker>(cfg, *this, *this);

    if (m_owner.get_tls())
    {
        m_tls = std::make_unique<tls_context>();
        if (!m_tls->init_server(m_owner.get_cert_path(), m_owner.get_key_path(), m_owner.get_ca_path()))
        {
            why = "the certificate, key or client CA could not be loaded";
            return false;
        }
    }
    if (!m_owner.get_idp().empty())
    {
        m_idp = std::make_unique<socketley::idp::session_verifier>();
        m_idp->configure(m_owner.get_idp(), m_owner.get_idp_audience());
    }
    m_users.set_path(std::string(m_owner.get_users()));
    m_acl.set_path(std::string(m_owner.get_acl()));
    m_routes = std::make_unique<route_table>();
    if (const std::string path(m_owner.get_routes()); !path.empty())
    {
        std::string text;
        if (!socketley::read_file(path, text, {.max_bytes = 4u << 20}, &why))
            return false;
        if (!m_routes->parse(text, why))
        {
            why = path + ": " + why;
            return false;
        }
        // A webhook rule's connection, kept from one message to the next and asked for its host now.
        m_route_peers.resize(m_routes->routes().size());
        m_route_posting.resize(m_routes->routes().size());
        for (size_t i = 0; i < m_routes->routes().size(); ++i)
        {
            const route& r = m_routes->routes()[i];
            socketley::http_target t;
            std::string bad;
            if (r.kind != target_kind::webhook || !socketley::parse_http_url(r.name, t, bad))
                continue;
            m_route_peers[i] = std::make_unique<socketley::http_peer>(
                m_loop, m_fio, m_pool, t, std::string{},
                "mqtt " + std::string(m_owner.get_name()) + ": the webhook of " + r.text);
            m_route_peers[i]->prime();
        }
    }
    std::string file_why;
    if (!m_users.refresh([](user_table& t, std::string_view text, std::string& w) { return t.parse(text, w); },
                         file_why) ||
        !m_acl.refresh([](acl_rules& t, std::string_view text, std::string& w) { return t.parse(text, w); },
                       file_why))
    {
        why = file_why;
        return false;
    }

    const std::string snap = m_owner.snapshot_path();
    if (!snap.empty())
    {
        std::error_code ec;
        std::filesystem::create_directories(std::filesystem::path(snap).parent_path(), ec);
        std::string bytes;
        if (!socketley::read_file(snap, bytes, {.missing_ok = true}, &why))
            return false;
        if (!bytes.empty())
        {
            socketley::bytes::reader r(bytes);
            uint32_t magic = 0;
            std::string_view core, routes;
            if (!r.u32(magic) || magic != snapshot_magic || !r.view(core, bytes.size()) ||
                !r.view(routes, bytes.size()))
            {
                why = snap + " is no snapshot of an mqtt runtime";
                return false;
            }
            if (!m_broker->restore(core, why))
            {
                why = snap + ": " + why;
                return false;
            }
            m_routes->load(routes);
        }
        why.clear();
    }

    m_ring      = m_loop.setup_buf_ring(ring_group, ring_bufs, ring_buf_bytes);
    m_multishot = m_ring && m_loop.recv_multishot_enabled();

    if (!open_listener(m_tcp, m_owner.effective_port(), false, why))
        return false;
    if (m_owner.get_ws_port() && !open_listener(m_ws, m_owner.get_ws_port(), true, why))
        return false;
    m_lua = std::make_unique<mqtt_lua>(m_owner);
    arm_accept(m_tcp);
    if (m_ws.fd >= 0)
        arm_accept(m_ws);
    m_next_persist_ms = now_ms() + static_cast<int64_t>(m_owner.get_persist_interval()) * 1000;
    shards_start();
    arm_tick();
    LOG_INFO(("mqtt " + std::string(m_owner.get_name()) + ": serving MQTT on " +
              std::to_string(m_owner.effective_port()) + (m_tls ? " over TLS" : "") +
              (m_ws.fd >= 0 ? ", WebSocket on " + std::to_string(m_owner.get_ws_port()) : std::string()) + ", " +
              std::to_string(m_broker->session_count()) + " session(s) and " +
              std::to_string(m_broker->retained_count()) + " retained message(s) kept, " +
              std::to_string(m_routes->routes().size()) + " topic rule(s)")
                 .c_str());
    return true;
}

bool mqtt_run::open_listener(listener& l, uint16_t port, bool ws, std::string& why)
{
    l.ws = ws;
    l.fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (l.fd < 0)
    {
        why = std::string("no socket: ") + std::strerror(errno);
        return false;
    }
    int one = 1;
    ::setsockopt(l.fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    // Every shard binds the port, and the kernel spreads the connections over them.
    if (m_owner.get_shards() > 1)
        ::setsockopt(l.fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
    sockaddr_in a{};
    a.sin_family      = AF_INET;
    a.sin_addr.s_addr = m_owner.bind_in_addr();
    a.sin_port        = htons(port);
    if (::bind(l.fd, reinterpret_cast<sockaddr*>(&a), sizeof a) < 0 || ::listen(l.fd, 4096) < 0)
    {
        why = "port " + std::to_string(port) + " could not be bound: " + std::strerror(errno);
        ::close(l.fd);
        l.fd = -1;
        return false;
    }
    return true;
}

void mqtt_run::stop()
{
    if (m_stopped)
        return;
    m_stopped = true;
    // What the other shards are still owed goes before this one stops listening for their answers.
    send_shards();
    for (listener* l : {&m_tcp, &m_ws})
        if (l->fd >= 0)
        {
            ::shutdown(l->fd, SHUT_RDWR);
            m_loop.close_fd(l->fd);
            l->fd = -1;
        }
    if (auto* mgr = m_owner.get_runtime_manager())
        mgr->requests().drop_origin(this);
    // A webhook's request in flight goes back to the head of its queue, so the snapshot keeps it.
    for (size_t i = 0; i < m_route_peers.size(); ++i)
        if (m_route_peers[i])
        {
            m_route_peers[i]->stop();
            if (m_route_posting[i] && m_routes)
            {
                m_routes->routes()[i].put_back(std::move(*m_route_posting[i]));
                m_route_posting[i].reset();
                if (m_routes->routes()[i].inflight)
                    --m_routes->routes()[i].inflight;
            }
        }
    if (m_routes)
        m_routes->cut_batches(now_ms(), m_owner.get_shard_index(), true);
    // A broker that keeps its state writes it while the sessions still have their connections, so their wills are
    // sent by the next start if they do not come back; one that keeps nothing sends them now.
    const bool keeps = !m_owner.snapshot_path().empty();
    // A snapshot the pool is still writing would land after this last one and put an older state back.
    m_pool.stop();
    if (keeps && m_broker)
        persist(true);
    std::vector<conn*> all;
    for (auto& [id, c] : m_conns)
        all.push_back(c.get());
    for (conn* c : all)
    {
        if (keeps)
            c->told_broker = false;
        close_conn(*c);
    }
    *m_alive = false;
}

bool mqtt_run::drained() const
{
    return m_loop.owner_drained(this);
}

// ── Accepting ───────────────────────────────────────────────────────────────

void mqtt_run::arm_accept(listener& l)
{
    if (m_stopped || l.fd < 0 || l.pending)
        return;
    l.req       = io_request{};
    l.req.owner = this;
    l.req.fd    = l.fd;
    l.req.type  = event_loop::supports_multishot_accept() ? op_multishot_accept : op_accept;
    l.pending   = l.req.type == op_multishot_accept ? m_loop.submit_multishot_accept(l.fd, &l.req)
                                                    : m_loop.submit_accept(l.fd, nullptr, nullptr, &l.req);
}

void mqtt_run::accept_done(listener& l, struct io_uring_cqe* cqe)
{
    if (!(cqe->flags & IORING_CQE_F_MORE))
        l.pending = false;
    const int fd = cqe->res;
    if (fd >= 0)
    {
        if (m_stopped || m_owner.connections_full(m_conns.size(), m_owner.get_max_connections()))
            m_loop.close_fd(fd);
        else
        {
            auto c = std::make_unique<conn>();
            c->id = m_next_id++;
            c->fd = fd;
            socklen_t len = sizeof c->peer;
            if (::getpeername(fd, reinterpret_cast<sockaddr*>(&c->peer), &len) < 0) {}
            int one = 1;
            ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
            c->fitted = socket_tuning::fit_to_path(fd);
            c->ws = l.ws;
            c->closing_ms = now_ms();
            if (m_tls)
                c->ssl = m_tls->create_ssl_server();
            conn* raw = c.get();
            m_conns.emplace(raw->id, std::move(c));
            runtime_instance::stat_add(m_owner.m_stat_total_connections, 1);
            m_owner.m_stat_active_connections.store(m_conns.size(), std::memory_order_relaxed);
            if (m_tls && !raw->ssl)
            {
                close_conn(*raw);
            }
            else
            {
                if (!raw->ssl && !raw->ws)
                {
                    raw->told_broker = true;
                    m_broker->connected(raw->id, {peer_text(raw->peer), "", false, false});
                }
                arm_read(*raw);
            }
        }
    }
    // Out of descriptors, the next accept fails the same way at once: it waits a tenth of a second instead.
    if (fd == -EMFILE || fd == -ENFILE)
    {
        m_accept_paused_until_ms = now_ms() + 100;
        return;
    }
    if (!l.pending && !m_stopped && fd != -ECANCELED)
        arm_accept(l);
}

// ── Reading ─────────────────────────────────────────────────────────────────

mqtt_run::conn* mqtt_run::conn_of(io_request* req)
{
    auto* raw = reinterpret_cast<conn*>(req->buffer);
    if (const auto it = m_conns.find(raw->id); it != m_conns.end() && it->second.get() == raw)
        return raw;
    for (const auto& c : m_closing)
        if (c.get() == raw)
            return raw;
    return nullptr;
}

mqtt_run::conn* mqtt_run::find(uint64_t id)
{
    return const_cast<conn*>(std::as_const(*this).find(id));
}

const mqtt_run::conn* mqtt_run::find(uint64_t id) const
{
    // The broker asks after one connection several times a delivery: what it owes, then the bytes for it.
    if (m_last_conn && m_last_conn->id == id)
        return m_last_conn;
    const auto it = m_conns.find(id);
    if (it == m_conns.end())
        return nullptr;
    m_last_conn = it->second.get();
    return m_last_conn;
}

void mqtt_run::arm_read(conn& c)
{
    if (c.dead || c.rd_pending || c.fd < 0 || c.paused || c.write_held)
        return;
    c.rd        = io_request{};
    c.rd.owner  = this;
    c.rd.buffer = reinterpret_cast<char*>(&c);
    c.rd.fd     = c.fd;
    c.rearm     = false;
    // Asked of the loop each time, because a kernel that refuses the flag turns it off after start.
    if (m_multishot && m_loop.recv_multishot_enabled())
    {
        c.rd.type      = op_recv_multishot;
        c.rd.buf_group = static_cast<uint8_t>(ring_group);
        c.rd_pending   = m_loop.submit_recv_multishot(c.fd, ring_group, &c.rd);
    }
    else
    {
        if (!c.rbuf)
            c.rbuf = std::make_unique<char[]>(ring_buf_bytes);
        c.rd.type    = op_read;
        c.rd_pending = m_loop.submit_read(c.fd, c.rbuf.get(), ring_buf_bytes, &c.rd);
    }
    // The ring had no room: asked again on the next turn.
    if (!c.rd_pending)
        c.rearm = true;
}

void mqtt_run::read_done(conn& c, struct io_uring_cqe* cqe)
{
    const int res = cqe->res;
    // A provided-buffer read is what the loop re-arms a refused multishot as, and it ends like one without F_MORE.
    if (c.rd.type == op_recv_multishot || c.rd.type == op_read_provided)
    {
        const bool more = cqe->flags & IORING_CQE_F_MORE;
        const bool was_withdrawing = c.withdrawing;
        if (!more)
        {
            c.rd_pending = false;
            c.withdrawing = false;
        }
        if (res > 0)
        {
            m_loop.for_each_cqe_buf(ring_group, cqe, [&](const char* p, uint32_t n) {
                if (!c.dead)
                    bytes_in(c, p, n);
            });
        }
        else if (cqe->flags & IORING_CQE_F_BUFFER)
            m_loop.return_cqe_buf(cqe, &c.rd);
        if (c.dead)
        {
            if (!c.rd_pending && !c.wr_pending)
                std::erase_if(m_closing, [&](const std::unique_ptr<conn>& x) { return x.get() == &c; });
            return;
        }
        if (res == -ENOBUFS)
        {
            if (!more)
                c.rearm = true;
            return;
        }
        // Taken back by withdraw_read(), and armed again here when the connection went on before it came back.
        if (res == -ECANCELED && !more && was_withdrawing)
        {
            arm_read(c);
            return;
        }
        if (res <= 0)
        {
            close_conn(c);
            return;
        }
        if (!more)
            arm_read(c);
        else if (c.paused || c.write_held)
            withdraw_read(c);
        return;
    }
    c.rd_pending = false;
    if (c.dead)
    {
        if (!c.wr_pending)
            std::erase_if(m_closing, [&](const std::unique_ptr<conn>& x) { return x.get() == &c; });
        return;
    }
    if (res <= 0)
    {
        close_conn(c);
        return;
    }
    bytes_in(c, c.rbuf.get(), static_cast<size_t>(res));
    if (!c.dead)
        arm_read(c);
}

void mqtt_run::bytes_in(conn& c, const char* p, size_t n)
{
    runtime_instance::stat_add(m_owner.m_stat_bytes_in, n);
    if (c.ssl)
        tls_in(c, p, n);
    else
        plain_in(c, p, n);
    // The replies, pongs and acks to what was just read are queued by now, so a peer leaving them unread is held here.
    if (!c.dead && c.unsent() > m_read_hold)
        c.write_held = true;
}

void mqtt_run::tls_in(conn& c, const char* p, size_t n)
{
    if (tls_context::bio_write_in(c.ssl, p, static_cast<int>(n)) < 0)
    {
        close_conn(c);
        return;
    }
    if (!c.handshaken)
    {
        const int r = tls_context::do_handshake(c.ssl);
        queue_tls_out(c);
        flush(c);
        if (r < 0)
        {
            ++m_tls_failures;
            close_conn(c);
            return;
        }
        if (r == 0)
            return;
        c.handshaken = true;
        if (!c.ws)
        {
            c.told_broker = true;
            m_broker->connected(c.id, {peer_text(c.peer), peer_common_name(c.ssl), true, false});
        }
    }
    char buf[16384];
    while (!c.dead)
    {
        const int r = tls_context::ssl_read(c.ssl, buf, sizeof buf);
        if (r > 0)
        {
            plain_in(c, buf, static_cast<size_t>(r));
            continue;
        }
        if (r < 0)
            close_conn(c);
        break;
    }
    if (!c.dead && tls_context::has_pending_out(c.ssl))
    {
        queue_tls_out(c);
        flush(c);
    }
}

void mqtt_run::plain_in(conn& c, const char* p, size_t n)
{
    if (!c.ws)
    {
        m_broker->input(c.id, std::string_view(p, n));
        return;
    }
    c.ws_in.append(p, n);
    if (!c.ws_open)
        ws_handshake(c);
    else
        ws_frames(c);
}

void mqtt_run::ws_handshake(conn& c)
{
    const size_t end = c.ws_in.find("\r\n\r\n");
    if (end == std::string::npos)
    {
        if (c.ws_in.size() > 16384)
        {
            ++m_ws_refused;
            close_conn(c);
        }
        return;
    }
    const std::string_view head(c.ws_in.data(), end + 2);
    const std::string_view key = header_value(head, "sec-websocket-key");
    const std::string_view protocols = header_value(head, "sec-websocket-protocol");
    const bool good = head.starts_with("GET ") && list_has(header_value(head, "upgrade"), "websocket") &&
                      list_has(header_value(head, "connection"), "upgrade") &&
                      header_value(head, "sec-websocket-version") == "13" && !key.empty();
    // A client offering subprotocols is given mqtt or refused; one offering none is taken as it is.
    std::string chosen;
    if (!protocols.empty())
    {
        if (list_has(protocols, "mqtt"))
            chosen = "mqtt";
        else if (list_has(protocols, "mqttv3.1"))
            chosen = "mqttv3.1";
    }
    if (!good || (!protocols.empty() && chosen.empty()))
    {
        ++m_ws_refused;
        raw_out(c, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        close(c.id);
        return;
    }
    std::string resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                       "Sec-WebSocket-Accept: ";
    ws_accept_key_into(resp, key);
    resp += "\r\n";
    if (!chosen.empty())
        resp += "Sec-WebSocket-Protocol: " + chosen + "\r\n";
    resp += "\r\n";
    raw_out(c, resp);
    c.ws_in.erase(0, end + 4);
    c.ws_open = true;
    c.told_broker = true;
    m_broker->connected(c.id, {peer_text(c.peer), c.ssl ? peer_common_name(c.ssl) : std::string(), c.ssl != nullptr,
                               true});
    ws_frames(c);
}

void mqtt_run::ws_frames(conn& c)
{
    size_t at = 0;
    while (!c.dead && at < c.ws_in.size())
    {
        ws_frame_view f;
        const ws_parse r = ws_parse_frame_inplace(c.ws_in.data() + at, c.ws_in.size() - at, f);
        if (r == ws_parse::incomplete)
            break;
        if (r == ws_parse::invalid || !f.masked)
        {
            ++m_ws_refused;
            close_conn(c);
            return;
        }
        at += f.consumed;
        switch (f.opcode)
        {
            case WS_OP_CONT:
            case WS_OP_TEXT:
            case WS_OP_BINARY:
                // MQTT's own framing is what counts: a packet may span frames and a frame hold several.
                m_broker->input(c.id, std::string_view(f.payload_ptr, f.payload_len));
                break;
            case WS_OP_PING:
            {
                std::string pong;
                ws_frame_pong_into(pong, std::string_view(f.payload_ptr, f.payload_len));
                // Ahead of the queued frames where they can be overtaken, which RFC 6455 5.4 allows a control frame.
                if (c.fitted && !c.ssl)
                    urgent_out(c, pong);
                else
                    raw_out(c, pong);
                break;
            }
            case WS_OP_CLOSE:
            {
                std::string bye;
                ws_frame_close_into(bye);
                raw_out(c, bye);
                close(c.id);
                c.ws_in.clear();
                return;
            }
            default:
                break;
        }
    }
    if (c.dead)
        return;
    c.ws_in.erase(0, at);
    // What is left is one frame unfinished; one longer than a few of the largest packets the broker takes is no
    // MQTT client's, and is refused before it is all held.
    if (c.ws_in.size() > static_cast<size_t>(m_owner.get_max_packet()) * 4 + 14)
    {
        ++m_ws_refused;
        close_conn(c);
    }
}

// ── Writing ─────────────────────────────────────────────────────────────────

void mqtt_run::send(uint64_t id, std::string_view bytes)
{
    conn* c = find(id);
    if (!c || c->dead)
        return;
    if (c->ws)
    {
        std::string frame;
        ws_frame_binary_into(frame, bytes);
        raw_out(*c, frame);
        return;
    }
    raw_out(*c, bytes);
}

void mqtt_run::send_control(uint64_t id, std::string_view bytes)
{
    conn* c = find(id);
    if (!c || c->dead)
        return;
    // TLS has made records of what was queued already, in their order; only the clear can be overtaken.
    if (c->ssl || !c->fitted)
    {
        send(id, bytes);
        return;
    }
    if (c->ws)
    {
        std::string frame;
        ws_frame_binary_into(frame, bytes);
        urgent_out(*c, frame);
    }
    else
        urgent_out(*c, bytes);
}

void mqtt_run::urgent_out(conn& c, std::string_view framed)
{
    c.urgent.append(framed);
    c.owed += framed.size();
    flush(c);
}

void mqtt_run::raw_out(conn& c, std::string_view bytes)
{
    if (c.dead)
        return;
    if (c.ssl)
    {
        size_t off = 0;
        while (off < bytes.size())
        {
            const int w = tls_context::ssl_write(c.ssl, bytes.data() + off,
                                                 static_cast<int>(std::min<size_t>(bytes.size() - off, 1u << 20)));
            if (w <= 0)
                break;
            off += static_cast<size_t>(w);
        }
        queue_tls_out(c);
    }
    else
        queue_owned(c, bytes);
    flush(c);
}

void mqtt_run::queue_owned(conn& c, std::string_view bytes)
{
    if (bytes.empty())
        return;
    c.owed += bytes.size();
    // A fitted connection's chunks stay a batch long, so a write can stop between them.
    if (!c.queue.empty() && c.queue.back().owns() && (!c.fitted || c.queue.back().size() < fitted_batch))
        c.queue.back().append(bytes);
    else
    {
        std::string b = std::move(c.spare);
        b.assign(bytes);
        c.queue.emplace_back(std::move(b));
    }
}

void mqtt_run::queue_tls_out(conn& c)
{
    m_tls_out.clear();
    tls_context::take_out(c.ssl, m_tls_out);
    queue_owned(c, m_tls_out);
}

void mqtt_run::send_parts(uint64_t id, std::string_view head, const std::shared_ptr<const std::string>& owner,
                          std::string_view body)
{
    conn* c = find(id);
    if (!c || c->dead)
        return;
    // TLS encrypts every byte into a record anyway, so a slice saves it nothing.
    if (c->ssl)
    {
        broker_io::send_parts(id, head, owner, body);
        return;
    }
    if (c->ws)
    {
        char frame[14];
        const int n = ws_write_header(frame, static_cast<uint8_t>(0x80 | WS_OP_BINARY), head.size() + body.size());
        queue_owned(*c, std::string_view(frame, static_cast<size_t>(n)));
    }
    queue_owned(*c, head);
    if (!body.empty())
    {
        const auto off = static_cast<uint32_t>(body.data() - owner->data());
        c->queue.emplace_back(owner, off, static_cast<uint32_t>(body.size()));
        c->owed += body.size();
    }
    flush(*c);
}

void mqtt_run::pause_reading(uint64_t id, bool paused)
{
    conn* c = find(id);
    if (!c || c->dead || c->paused == paused)
        return;
    c->paused = paused;
    if (paused)
        withdraw_read(*c);
    else
        arm_read(*c);
}

void mqtt_run::withdraw_read(conn& c)
{
    // A single read ends by itself and is not armed again; one the ring would not take back is asked at its next.
    if (c.rd_pending && c.rd.type == op_recv_multishot && !c.withdrawing)
        c.withdrawing = m_loop.submit_cancel_request(&c.rd);
}

size_t mqtt_run::backlog(uint64_t id) const
{
    const conn* c = find(id);
    return c ? c->unsent() : 0;
}

void mqtt_run::flush(conn& c)
{
    if (c.dead || c.wr_pending)
        return;
    if (c.sending_at >= c.sending.size())
    {
        c.sending.clear();
        c.sending_at = 0;
        c.sent = 0;
        if (c.queue.empty() && c.urgent.empty())
        {
            if (c.closing)
                m_close_soon.push_back(c.id);
            return;
        }
        if (!c.urgent.empty())
        {
            c.sending.emplace_back(std::move(c.urgent));
            c.urgent.clear();
        }
        if (!c.fitted)
        {
            if (c.sending.empty())
                c.sending.swap(c.queue);
            else
            {
                std::move(c.queue.begin(), c.queue.end(), std::back_inserter(c.sending));
                c.queue.clear();
            }
        }
        else
        {
            // A batch at a time, so whatever is made urgent meanwhile waits behind one batch and not the backlog.
            size_t took = 0, n = 0;
            while (n < c.queue.size() && (n == 0 || took < fitted_batch))
                took += c.queue[n++].size();
            std::move(c.queue.begin(), c.queue.begin() + static_cast<std::ptrdiff_t>(n), std::back_inserter(c.sending));
            c.queue.erase(c.queue.begin(), c.queue.begin() + static_cast<std::ptrdiff_t>(n));
        }
    }
    c.wr        = io_request{};
    c.wr.owner  = this;
    c.wr.buffer = reinterpret_cast<char*>(&c);
    c.wr.fd     = c.fd;
    const size_t left = c.sending.size() - c.sending_at;
    if (left == 1)
    {
        const std::string_view b = c.sending[c.sending_at].view().substr(c.sent);
        c.wr.type    = op_write;
        // All of it, since a write capped at 1 MiB sent a subscriber 1 MiB a turn while the turn queued far more.
        c.wr_pending = m_loop.submit_write(c.fd, b.data(), static_cast<uint32_t>(std::min<size_t>(b.size(), UINT32_MAX)),
                                           &c.wr);
    }
    else
    {
        c.iov.clear();
        for (size_t i = c.sending_at; i < c.sending.size() && c.iov.size() < 128; ++i)
        {
            const std::string_view b = c.sending[i].view().substr(i == c.sending_at ? c.sent : 0);
            c.iov.push_back({const_cast<char*>(b.data()), b.size()});
        }
        c.wr.type    = op_writev;
        c.wr_pending = m_loop.submit_writev(c.fd, c.iov.data(), static_cast<uint32_t>(c.iov.size()), &c.wr);
    }
    // The ring had no room; a turn later it may.
    c.reflush = !c.wr_pending;
}

void mqtt_run::write_done(conn& c, int res)
{
    c.wr_pending = false;
    if (c.dead)
    {
        if (!c.rd_pending)
            std::erase_if(m_closing, [&](const std::unique_ptr<conn>& x) { return x.get() == &c; });
        return;
    }
    if (res <= 0)
    {
        close_conn(c);
        return;
    }
    auto done = static_cast<size_t>(res);
    c.owed -= std::min(c.owed, done);
    while (done && c.sending_at < c.sending.size())
    {
        const size_t rest = c.sending[c.sending_at].size() - c.sent;
        if (done < rest)
        {
            c.sent += done;
            break;
        }
        done -= rest;
        // Let go at once, so a payload's message is freed as soon as its last subscriber has it; its own room is
        // kept for the next, since a capped one was grown again from nothing on every batch (0.65 at 4 KiB).
        socketley::write_chunk& sent = c.sending[c.sending_at++];
        if (sent.owns())
        {
            std::string room = sent.take_owned();
            if (room.capacity() > c.spare.capacity())
            {
                room.clear();
                c.spare.swap(room);
            }
        }
        sent = socketley::write_chunk{};
        c.sent = 0;
    }
    runtime_instance::stat_add(m_owner.m_stat_bytes_out, static_cast<uint64_t>(res));
    if (c.unsent() == 0 && c.told_broker && !c.closing)
        m_broker->drained(c.id);
    // Read again once the peer has taken half of what held it, so a slow reader is not withdrawn and armed every write.
    if (c.write_held && c.unsent() <= m_read_hold / 2)
    {
        c.write_held = false;
        arm_read(c);
    }
    flush(c);
}

void mqtt_run::close(uint64_t id)
{
    conn* c = find(id);
    if (!c || c->dead)
        return;
    if (!c->closing)
    {
        c->closing    = true;
        c->closing_ms = now_ms();
    }
    m_close_soon.push_back(id);
}

void mqtt_run::close_conn(conn& c)
{
    if (c.dead)
        return;
    c.dead = true;
    const uint64_t id = c.id;
    if (c.fd >= 0)
    {
        ::shutdown(c.fd, SHUT_RDWR);
        m_loop.close_fd(c.fd);
        c.fd = -1;
    }
    if (c.ssl)
    {
        tls_context::free_ssl(c.ssl);
        c.ssl = nullptr;
    }
    // Freed by settle() and never here, since a completion handler up the stack may still hold `c`.
    const auto it = m_conns.find(id);
    if (it != m_conns.end())
    {
        if (m_last_conn == it->second.get())
            m_last_conn = nullptr;
        m_closing.push_back(std::move(it->second));
        m_conns.erase(it);
    }
    m_owner.m_stat_active_connections.store(m_conns.size(), std::memory_order_relaxed);
    if (c.told_broker && m_broker)
    {
        c.told_broker = false;
        m_broker->disconnected(id);
    }
}

void mqtt_run::settle()
{
    if (m_in_settle)
        return;
    m_in_settle = true;
    const int64_t now = now_ms();
    for (int rounds = 0; rounds < 4 && !m_close_soon.empty(); ++rounds)
    {
        std::vector<uint64_t> ids;
        ids.swap(m_close_soon);
        std::sort(ids.begin(), ids.end());
        ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
        for (const uint64_t id : ids)
        {
            conn* c = find(id);
            if (!c || c->dead)
                continue;
            if (c->unsent() == 0 || now - c->closing_ms >= close_grace_ms)
                close_conn(*c);
        }
    }
    std::erase_if(m_closing, [](const std::unique_ptr<conn>& c) { return !c->rd_pending && !c->wr_pending; });
    m_in_settle = false;
}

// ── The ring ────────────────────────────────────────────────────────────────

void mqtt_run::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req)
        return;
    if (file_io::owns_type(req->type))
        m_fio.on_cqe(cqe);
    else if (req == &m_tick_req)
    {
        m_tick_armed = false;
        if (!m_stopped)
            tick();
    }
    else if (req == &m_tcp.req)
        accept_done(m_tcp, cqe);
    else if (req == &m_ws.req)
        accept_done(m_ws, cqe);
    else if (conn* c = conn_of(req))
    {
        if (req == &c->rd)
            read_done(*c, cqe);
        else if (req == &c->wr)
            write_done(*c, cqe->res);
    }
    else if (cqe->flags & IORING_CQE_F_BUFFER)
        m_loop.return_cqe_buf(cqe, req);
    settle();
}

void mqtt_run::on_loop_turn()
{
    if (m_stopped)
        return;
    if (now_ms() >= m_accept_paused_until_ms)
    {
        if (!m_tcp.pending)
            arm_accept(m_tcp);
        if (m_ws.fd >= 0 && !m_ws.pending)
            arm_accept(m_ws);
    }
    for (auto& [id, c] : m_conns)
    {
        if (c->rearm && !c->dead)
            arm_read(*c);
        if (c->reflush && !c->dead)
            flush(*c);
    }
    pump_routes();
    send_shards();
    settle();
}

void mqtt_run::arm_tick()
{
    if (m_tick_armed || m_stopped)
        return;
    m_tick_req       = io_request{};
    m_tick_req.owner = this;
    m_tick_req.type  = op_timeout;
    m_tick_ts        = {1, 0};
    m_tick_armed     = m_loop.submit_timeout(&m_tick_ts, &m_tick_req);
}

void mqtt_run::tick()
{
    const int64_t now = now_ms();
    m_broker->tick();
    // A TLS handshake or a WebSocket upgrade that never finishes is let go like a CONNECT that never comes.
    std::vector<conn*> late;
    for (auto& [id, c] : m_conns)
        if (!c->told_broker && !c->closing && now - c->closing_ms > handshake_ms)
            late.push_back(c.get());
    for (conn* c : late)
        close_conn(*c);
    if (now >= m_next_files_ms)
    {
        // Each tick, so a file changed is taken within two seconds as documented, not three.
        m_next_files_ms = now + 1000;
        refresh_files();
    }
    if (m_routes)
        m_routes->cut_batches(now, m_owner.get_shard_index(), false);
    // A webhook's exchange that stalled ends, and its connection kept too long goes.
    const auto steady = std::chrono::steady_clock::now();
    for (auto& p : m_route_peers)
        if (p)
            p->tick(steady);
    if (now >= m_next_persist_ms)
    {
        m_next_persist_ms = now + static_cast<int64_t>(m_owner.get_persist_interval()) * 1000;
        persist(false);
    }
    reap_taps(now);
    sweep_claims(now);
    tls_context::report_inbound_failures();
    pump_routes();
    arm_tick();
}

void mqtt_run::refresh_files()
{
    std::string why;
    if (!m_users.refresh([](user_table& t, std::string_view text, std::string& w) { return t.parse(text, w); }, why))
        LOG_WARN(("mqtt " + std::string(m_owner.get_name()) + ": " + why + "; the users read before are kept").c_str());
    why.clear();
    if (!m_acl.refresh([](acl_rules& t, std::string_view text, std::string& w) { return t.parse(text, w); }, why))
        LOG_WARN(("mqtt " + std::string(m_owner.get_name()) + ": " + why + "; the rules read before are kept").c_str());
}

// ── The snapshot ────────────────────────────────────────────────────────────

void mqtt_run::persist(bool now_and_wait)
{
    const std::string path = m_owner.snapshot_path();
    if (path.empty() || !m_broker)
        return;
    const bool dirty = m_broker->take_dirty() || m_routes_dirty;
    if (!dirty && !now_and_wait)
        return;
    if (m_persist_busy && !now_and_wait)
    {
        // Still writing the last one: this change waits for the next turn of the interval.
        m_routes_dirty = true;
        return;
    }
    m_routes_dirty = false;
    // Taken now, written to bytes where the file is written: the retained messages are shared, not copied, here.
    auto parts = std::make_shared<broker::snapshot_parts>(m_broker->snapshot_now());
    // What is in flight is kept in its place, so a restart sends it again rather than losing it.
    std::vector<std::vector<const route_request*>> flying;
    if (m_routes && !m_route_asks.empty())
    {
        flying.resize(m_routes->routes().size());
        for (const auto& [cookie, ask] : m_route_asks)
            if (ask.index < flying.size())
                flying[ask.index].push_back(&ask.request);
    }
    if (m_routes)
    {
        flying.resize(m_routes->routes().size());
        for (size_t i = 0; i < m_route_posting.size() && i < flying.size(); ++i)
            if (m_route_posting[i])
                flying[i].push_back(&*m_route_posting[i]);
    }
    auto routes = std::make_shared<const std::string>(m_routes ? m_routes->save(flying) : std::string());
    // The magic, the broker's snapshot as one length-prefixed piece written in place, and the routes'.
    const auto encode = [parts, routes] {
        std::string data(8, '\0');
        socketley::bytes::store32(data.data(), snapshot_magic);
        broker::write_snapshot(*parts, data);
        socketley::bytes::store32(data.data() + 4, static_cast<uint32_t>(data.size() - 8));
        socketley::bytes::append32(data, static_cast<uint32_t>(routes->size()));
        data.append(*routes);
        return data;
    };
    if (now_and_wait || !m_pool.enabled())
    {
        std::string why;
        if (!socketley::replace_file(path, encode(), socketley::durability::data, &why))
            LOG_ERROR(("mqtt " + std::string(m_owner.get_name()) + ": the snapshot could not be written: " + why)
                          .c_str());
        else
            ++m_persists;
        return;
    }
    m_persist_busy = true;
    auto result = std::make_shared<std::string>();
    auto ok = std::make_shared<bool>(false);
    m_pool.submit(0,
                  [path, encode, result, ok] {
                      *ok = socketley::replace_file(path, encode(), socketley::durability::data, result.get());
                  },
                  [this, alive = m_alive, result, ok] {
                      if (!*alive)
                          return;
                      m_persist_busy = false;
                      if (*ok)
                      {
                          ++m_persists;
                          if (m_persist_failed)
                              LOG_INFO(("mqtt " + std::string(m_owner.get_name()) + ": the snapshot is written again")
                                           .c_str());
                          m_persist_failed = false;
                      }
                      else if (!m_persist_failed)
                      {
                          m_persist_failed = true;
                          LOG_ERROR(("mqtt " + std::string(m_owner.get_name()) +
                                     ": the snapshot could not be written: " + *result)
                                        .c_str());
                      }
                  });
}

// ── Who connects, and what they may do ──────────────────────────────────────

void mqtt_run::authenticate(const auth_ask& ask, std::function<void(auth_answer)> done)
{
    // An accepted client's session is first taken from whichever shard holds it.
    auto accept = [this, ask, done = std::move(done)](auth_answer a) {
        if (a.code != reason::success)
        {
            ++m_auth_refused;
            done(std::move(a));
            return;
        }
        claim(ask, std::move(a), done);
    };
    // The script's word last, given the credentials' verdict.
    auto finish = [this, ask, accept](bool verified, uint8_t code, std::string username) {
        if (m_lua && m_lua->wants_auth())
        {
            // Only a script letting in whom the credentials refused makes the name the client gave its user.
            const std::string named = ask.username ? *ask.username : std::string();
            m_lua->auth(ask, verified, code == reason::success, username,
                        [code, username, named, accept](bool allow) {
                            if (!allow)
                                accept({code == reason::success ? reason::not_authorized : code, username});
                            else
                                accept({reason::success, code == reason::success ? username : named});
                        });
            return;
        }
        accept({code, username});
    };
    if (!ask.cert_cn.empty())
    {
        finish(true, reason::success, ask.cert_cn);
        return;
    }
    if (ask.password)
    {
        const std::string* hash = ask.username ? m_users.value().hash_of(*ask.username) : nullptr;
        if (hash)
        {
            // scrypt costs tens of milliseconds, which the loop does not spend.
            auto matched = std::make_shared<bool>(false);
            m_pool.submit(1,
                          [h = *hash, pw = *ask.password, matched] {
                              *matched = socketley::storage::password_matches(h, pw);
                          },
                          [this, alive = m_alive, matched, user = *ask.username, finish]() mutable {
                              if (!*alive)
                                  return;
                              finish(*matched, *matched ? reason::success : reason::bad_user_or_password,
                                     *matched ? user : std::string());
                          });
            return;
        }
        if (m_idp)
        {
            socketley::idp::session_verifier::who who;
            if (m_idp->check_bearer(*ask.password, who) &&
                (!ask.username || ask.username->empty() || *ask.username == who.username || *ask.username == who.sub))
            {
                finish(true, reason::success, who.username.empty() ? who.sub : who.username);
                return;
            }
        }
        finish(false, reason::bad_user_or_password, {});
        return;
    }
    if (m_owner.get_anonymous())
    {
        finish(false, reason::success, {});
        return;
    }
    finish(false, reason::bad_user_or_password, {});
}

bool mqtt_run::may_write(std::string_view user, std::string_view client, std::string_view topic)
{
    return m_acl.value().may_write(user, client, topic);
}

bool mqtt_run::may_read(std::string_view user, std::string_view client, std::string_view topic)
{
    return m_acl.value().may_read(user, client, topic);
}

bool mqtt_run::may_subscribe(std::string_view user, std::string_view client, std::string_view filter)
{
    return m_acl.value().may_subscribe(user, client, filter);
}

bool mqtt_run::hooks_publish() const
{
    return m_lua && m_lua->wants_publish();
}

void mqtt_run::on_publish(const client_info& c, const message_ptr& m, std::function<void(publish_verdict)> done)
{
    m_lua->publish(c, m, std::move(done));
}

bool mqtt_run::hooks_subscribe() const
{
    return m_lua && m_lua->wants_subscribe();
}

void mqtt_run::on_subscribe(const client_info& c, const std::string& filter, uint8_t qos,
                            std::function<void(bool)> done)
{
    m_lua->subscribe(c, filter, qos, std::move(done));
}

void mqtt_run::on_connected(const client_info& c)
{
    if (m_lua)
        m_lua->connected(c);
}

void mqtt_run::on_disconnect(const client_info& c, std::string_view why)
{
    if (m_lua)
        m_lua->disconnected(c, why);
}

void mqtt_run::accepted(const message_ptr& m)
{
    runtime_instance::stat_add(m_owner.m_stat_total_messages, 1);
    if (m_routes && !m_routes->empty())
    {
        m_routes->offer(*m, now_ms(), m_owner.get_shard_index());
        m_routes_dirty = true;
    }
    tap_message(*m);
    share_message(m);
}

void mqtt_run::retained_changed(const std::string& topic, const message_ptr& now)
{
    share_retained(topic, now);
}

// ── Topic rules ─────────────────────────────────────────────────────────────

void mqtt_run::pump_routes()
{
    if (!m_routes || m_routes->empty() || m_stopped)
        return;
    auto* mgr = m_owner.get_runtime_manager();
    if (!mgr)
        return;
    const int64_t now = now_ms();
    auto& routes = m_routes->routes();
    for (size_t i = 0; i < routes.size(); ++i)
    {
        route& r = routes[i];
        if (now < r.retry_at_ms)
            continue;
        while (!r.queue.empty() && r.inflight < route_table::window)
        {
            // One at a time, so a webhook is told in the order the messages came.
            if (r.kind == target_kind::webhook)
            {
                if (r.inflight == 0)
                    post_route(i);
                break;
            }
            if (r.kind == target_kind::server)
            {
                if (!route_relay::broadcast(mgr, r.runtime, m_owner.get_name(), r.queue.front().bytes))
                {
                    r.back_off(now);
                    r.last_error = "no server called " + r.runtime + " is running";
                    break;
                }
                r.queue.pop_front();
                ++r.delivered;
                r.backoff_ms = 0;
                m_routes_dirty = true;
                continue;
            }
            const uint64_t cookie = m_next_cookie++;
            route_request q = std::move(r.queue.front());
            r.queue.pop_front();
            if (!mgr->requests().post(this, cookie, r.runtime, q.bytes, request_class::background))
            {
                r.queue.push_front(std::move(q));
                r.back_off(now);
                break;
            }
            ++r.inflight;
            m_route_asks.emplace(cookie, route_ask{i, std::move(q)});
        }
    }
}

void mqtt_run::post_route(size_t i)
{
    route& r = m_routes->routes()[i];
    socketley::http_peer* peer = i < m_route_peers.size() ? m_route_peers[i].get() : nullptr;
    if (!peer || peer->busy() || r.queue.empty())
        return;
    m_route_posting[i] = std::move(r.queue.front());
    r.queue.pop_front();
    ++r.inflight;
    const socketley::http_target& t = peer->target();
    socketley::http_request rq;
    rq.head = "POST " + (t.path.empty() ? std::string("/") : t.path) + " HTTP/1.1\r\nHost: " + t.authority() +
              "\r\nContent-Type: application/json\r\nContent-Length: " +
              std::to_string(m_route_posting[i]->bytes.size()) +
              "\r\nConnection: keep-alive\r\nUser-Agent: socketley-mqtt\r\n\r\n";
    rq.body = m_route_posting[i]->bytes;
    peer->exchange(std::move(rq), [this, i](socketley::http_answer a)
    {
        if (!m_routes || i >= m_routes->routes().size() || !m_route_posting[i])
            return;
        route& r = m_routes->routes()[i];
        if (r.inflight)
            --r.inflight;
        std::string why;
        const reply_verdict v = judge_reply(target_kind::webhook, std::to_string(a.status), why);
        if (a.status == 0 && !a.failure.empty())
            why = "the webhook did not answer: " + a.failure;
        switch (v)
        {
            case reply_verdict::delivered:
                ++r.delivered;
                r.backoff_ms = 0;
                break;
            case reply_verdict::refused:
                ++r.failed;
                if (r.last_error != why)
                    LOG_WARN(("mqtt " + std::string(m_owner.get_name()) + ": " + r.text + " refused a message: " + why)
                                 .c_str());
                r.last_error = why;
                break;
            case reply_verdict::retry:
                r.put_back(std::move(*m_route_posting[i]));
                r.back_off(now_ms());
                r.last_error = why;
                break;
        }
        m_route_posting[i].reset();
        m_routes_dirty = true;
        if (!m_stopped)
            pump_routes();
    });
}

void mqtt_run::on_request_reply(uint64_t cookie, request_status st, std::string_view reply)
{
    if (m_claim_cookies.contains(cookie))
    {
        claim_reply(cookie, st, reply);
        return;
    }
    if (dump_reply(cookie, st, reply))
        return;
    if (shard_receipt(cookie, st, reply))
        return;
    const auto it = m_route_asks.find(cookie);
    if (it == m_route_asks.end())
        return;
    route_ask ask = std::move(it->second);
    m_route_asks.erase(it);
    if (!m_routes || ask.index >= m_routes->routes().size())
        return;
    route& r = m_routes->routes()[ask.index];
    if (r.inflight)
        --r.inflight;
    std::string why;
    const reply_verdict v = st == request_status::ok ? judge_reply(r.kind, reply, why) : reply_verdict::retry;
    if (st != request_status::ok)
        why = std::string("the target did not answer: ") + request_status_text(st);
    switch (v)
    {
        case reply_verdict::delivered:
            ++r.delivered;
            r.backoff_ms = 0;
            break;
        case reply_verdict::refused:
            ++r.failed;
            if (r.last_error != why)
                LOG_WARN(("mqtt " + std::string(m_owner.get_name()) + ": " + r.text + " refused a message: " + why)
                             .c_str());
            r.last_error = why;
            break;
        case reply_verdict::retry:
        {
            r.put_back(std::move(ask.request));
            r.back_off(now_ms());
            r.last_error = why;
            break;
        }
    }
    m_routes_dirty = true;
    pump_routes();
}

// ── Taps: what `socketley mqtt-sub` reads ───────────────────────────────────

void mqtt_run::tap_message(const message& m)
{
    if (m_taps.empty())
        return;
    for (auto& [id, t] : m_taps)
    {
        if (!topic_matches(t.filter, m.topic))
            continue;
        if (t.lines.size() >= tap_limit)
        {
            t.lines.pop_front();
            ++t.dropped;
        }
        t.lines.push_back(message_line(m));
    }
}

void mqtt_run::reap_taps(int64_t now)
{
    std::erase_if(m_taps, [&](const auto& kv) { return now - kv.second.polled_ms > 10000; });
}

// ── Commands ────────────────────────────────────────────────────────────────

std::string mqtt_run::sessions_json()
{
    std::string out = "[";
    bool first = true;
    for (const auto& s : m_broker->sessions())
    {
        if (!first)
            out += ",";
        first = false;
        out += "{\"client\":";
        socketley::json::quote_into(out, s.client_id);
        out += ",\"user\":";
        socketley::json::quote_into(out, s.username);
        out += s.connected ? ",\"connected\":true" : ",\"connected\":false";
        out += ",\"version\":\"";
        out += s.level == level_5 ? "5.0" : s.level == level_311 ? "3.1.1" : "3.1";
        out += "\",\"peer\":";
        socketley::json::quote_into(out, s.peer);
        out += ",\"subscriptions\":[";
        for (size_t i = 0; i < s.filters.size(); ++i)
        {
            if (i)
                out += ",";
            socketley::json::quote_into(out, s.filters[i]);
        }
        out += "],\"queued\":" + std::to_string(s.queued) + ",\"inflight\":" + std::to_string(s.inflight) +
               ",\"expires_in\":" + std::to_string(s.expires_in) + ",\"shard\":" +
               std::to_string(m_owner.get_shard_index()) + "}";
    }
    out += "]";
    return out;
}

std::string mqtt_run::retained_json(std::string_view filter)
{
    std::string out = "[";
    bool first = true;
    m_broker->retained_each(filter, [&](const message_ptr& m) {
        if (!first)
            out += ",";
        first = false;
        out += message_line(*m);
    });
    out += "]";
    return out;
}

void mqtt_run::command(uint64_t ticket, std::string_view payload)
{
    auto* mgr = m_owner.get_runtime_manager();
    if (!mgr)
        return;
    const auto answer = [&](std::string_view text) {
        mgr->requests().complete_deferred(ticket, request_status::ok, text);
    };
    socketley::bytes::reader r(payload);
    uint8_t v = 0;
    if (!r.marker(command_prefix) || !r.u8(v))
    {
        answer("error: no mqtt command");
        return;
    }
    switch (static_cast<verb>(v))
    {
        case verb::publish:
        {
            message m;
            bool retain = false;
            if (!r.bytes(m.topic, 65535) || !r.bytes(m.payload, m_owner.get_max_packet()) || !r.u8(m.qos) ||
                m.qos > 2 || !r.flag(retain))
            {
                answer("error: the publish is cut off");
                return;
            }
            m.retain = retain;
            if (uint8_t hops = 0; r.u8(hops))
                m.hops = hops;
            if (!valid_topic(m.topic) || m.topic.front() == '$')
            {
                answer("error: " + m.topic + " is not a topic a message can be published to");
                return;
            }
            m_broker->publish(std::move(m));
            answer("ok");
            return;
        }
        default:
            break;
    }
    std::string arg;
    bool flag = false;
    if (!r.bytes(arg, 65535) || !r.flag(flag))
    {
        answer("error: the command is cut off");
        return;
    }
    switch (static_cast<verb>(v))
    {
        case verb::sessions:
            answer(sessions_json());
            return;
        case verb::kick:
            answer(m_broker->kick(arg, flag) ? std::string("kicked") : "error: no session of " + arg);
            return;
        case verb::retained:
            answer(retained_json(arg));
            return;
        case verb::clear:
            answer(m_broker->clear_retained(arg) ? std::string("cleared") : "error: nothing retained on " + arg);
            return;
        case verb::tap_open:
        {
            if (!valid_filter(arg) || arg.starts_with("$share/"))
            {
                answer("error: " + arg + " is not a topic filter");
                return;
            }
            const uint64_t id = m_next_tap++;
            tap& t = m_taps[id];
            t.filter = arg;
            t.polled_ms = now_ms();
            answer(std::to_string(id));
            return;
        }
        case verb::tap_poll:
        {
            uint64_t id = 0;
            if (const auto [end, ec] = std::from_chars(arg.data(), arg.data() + arg.size(), id);
                ec != std::errc{} || end != arg.data() + arg.size())
                id = 0;
            const auto it = m_taps.find(id);
            if (it == m_taps.end())
            {
                answer("error: no such tap");
                return;
            }
            it->second.polled_ms = now_ms();
            std::string out;
            if (it->second.dropped)
            {
                out += "{\"dropped\":" + std::to_string(it->second.dropped) + "}\n";
                it->second.dropped = 0;
            }
            for (auto& l : it->second.lines)
            {
                out += l;
                out += '\n';
            }
            it->second.lines.clear();
            answer(out);
            return;
        }
        case verb::tap_close:
        {
            uint64_t id = 0;
            if (const auto [end, ec] = std::from_chars(arg.data(), arg.data() + arg.size(), id);
                ec != std::errc{} || end != arg.data() + arg.size())
                id = 0;
            m_taps.erase(id);
            answer("closed");
            return;
        }
        default:
            answer("error: no such mqtt command");
            return;
    }
}

// ── Stats ───────────────────────────────────────────────────────────────────

std::string mqtt_run::stats() const
{
    namespace st = socketley::stats_text;
    const broker& b = *m_broker;
    const broker_stats& s = b.stats();
    std::string out;
    st::put(out, "sessions", b.session_count());
    st::put(out, "sessions_connected", b.connected_count());
    st::put(out, "subscriptions", b.subscription_count());
    st::put(out, "retained", b.retained_count());
    st::put(out, "retained_bytes", b.retained_bytes());
    st::put(out, "queued", b.queued_count());
    st::put(out, "inflight", b.inflight_count());
    st::put(out, "received_qos0", s.received[0]);
    st::put(out, "received_qos1", s.received[1]);
    st::put(out, "received_qos2", s.received[2]);
    st::put(out, "sent_qos0", s.sent[0]);
    st::put(out, "sent_qos1", s.sent[1]);
    st::put(out, "sent_qos2", s.sent[2]);
    st::put(out, "dropped_slow", s.dropped_slow);
    st::put(out, "dropped_queue", s.dropped_queue);
    st::put(out, "dropped_expired", s.dropped_expired);
    st::put(out, "dropped_too_large", s.dropped_too_large);
    st::put(out, "dropped_denied", s.dropped_denied);
    st::put(out, "denied_publish", s.denied_publish);
    st::put(out, "denied_subscribe", s.denied_subscribe);
    st::put(out, "connects", s.connects);
    st::put(out, "connects_refused", s.connects_refused);
    st::put(out, "auth_refused", m_auth_refused);
    st::put(out, "takeovers", s.takeovers);
    st::put(out, "takeovers_refused", s.takeovers_refused);
    st::put(out, "wills_sent", s.wills_sent);
    st::put(out, "sessions_expired", s.sessions_expired);
    st::put(out, "sessions_evicted", s.sessions_evicted);
    st::put(out, "protocol_errors", s.protocol_errors);
    st::put(out, "retained_refused", s.retained_refused);
    st::put(out, "tls_failures", m_tls_failures);
    st::put(out, "websocket_refused", m_ws_refused);
    st::put(out, "snapshots", m_persists);
    st::put(out, "snapshot_failing", m_persist_failed);
    // A change that waits for its snapshot, or whose snapshot is still being written, is what a crash would lose.
    st::put(out, "snapshot_unsaved",
            !m_owner.snapshot_path().empty() && m_broker && (m_broker->dirty() || m_routes_dirty || m_persist_busy));
    if (m_routes)
        for (size_t i = 0; i < m_routes->routes().size(); ++i)
        {
            const route& r = m_routes->routes()[i];
            const std::string p = "rule_" + std::to_string(i) + "_";
            st::put(out, p + "target", r.text);
            st::put(out, p + "delivered", r.delivered);
            st::put(out, p + "failed", r.failed);
            st::put(out, p + "dropped", r.dropped);
            st::put(out, p + "queued", r.queue.size() + r.inflight + (r.batch.empty() ? 0 : 1));
            if (!r.last_error.empty())
                st::put(out, p + "error", r.last_error);
        }
    shard_stats(out);
    return out;
}

}   // namespace socketley::mqtt
