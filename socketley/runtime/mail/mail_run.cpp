#include "mail_run.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <unistd.h>

#include "mail_delivery.h"
#include "mail_compose.h"
#include "mail_instance.h"
#include "mail_mailbox.h"
#include "mail_verify.h"
#include "../idp/idp_session.h"
#include "../storage/password_hash.h"
#include "../../shared/crypto/tls_context.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/net/dns_feed.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/persist/replaced_file.h"
#include "../../shared/runtime/runtime_manager.h"
#include "../../shared/runtime/stats_text.h"
#include "../../shared/util/ascii.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/text_list.h"
#include "../../shared/util/wall_clock.h"

namespace socketley::mail
{

namespace
{

// The buffer group the runtime's reads take their buffers from, one per runtime type on a loop.
constexpr uint16_t ring_group = 7;
constexpr uint32_t ring_bufs = 1024;
constexpr uint32_t ring_buf_bytes = 4096;
constexpr int64_t close_grace_ms = 5000;
constexpr int64_t handshake_ms = 30000;
// RFC 5321 4.5.3.2.7 has a server wait five minutes for the next command, RFC 3501 5.4 an IMAP one thirty.
constexpr int64_t idle_ms = 300000;
constexpr int64_t imap_idle_ms = 31 * 60000;
// A wrong password is answered after this, so guessing one costs a client a second a try.
constexpr auto auth_delay = std::chrono::seconds(1);

std::string peer_ip(const sockaddr_in& a)
{
    char host[INET_ADDRSTRLEN] = {};
    ::inet_ntop(AF_INET, &a.sin_addr, host, sizeof host);
    return host;
}

// This machine's own programs, which may relay and sign in without TLS; 127.0.0.1 and not all of 127/8, so a test can
// be a stranger from 127.0.0.2.
bool loopback(const sockaddr_in& a)
{
    return ntohl(a.sin_addr.s_addr) == INADDR_LOOPBACK;
}

}   // namespace

mail_run::mail_run(mail_instance& owner, event_loop& loop)
    : m_owner(owner), m_loop(loop), m_fio(loop, this), m_pool(2), m_checks(4), m_spool(loop, m_fio),
      m_alive(std::make_shared<bool>(true))
{
}

mail_run::~mail_run()
{
    *m_alive = false;
    m_pool.stop();
    m_checks.stop();
    m_delivery.reset();
    m_mailboxes.reset();
    for (auto& [id, c] : m_conns)
        if (c->ssl)
            tls_context::free_ssl(c->ssl);
    for (auto& c : m_closing)
        if (c->ssl)
            tls_context::free_ssl(c->ssl);
    m_loop.deregister_owner(this);
}

uint32_t mail_run::shard() const
{
    return m_owner.get_shard_index();
}

bool mail_run::is_local_domain(std::string_view d) const
{
    for (const auto& x : m_domains)
        if (x == d)
            return true;
    return false;
}

route_to mail_run::route(const address& a, bool from_null) const
{
    std::string domain = a.domain;
    // The postmaster with no domain is the first domain's.
    if (domain.empty())
    {
        if (m_domains.empty())
            return {};
        domain = m_domains.front();
    }
    if (!is_local_domain(domain))
        return {route_to::remote, a.text()};
    if (m_owner.get_no_reply() && socketley::ascii::iequals(a.local, "no-reply"))
        return from_null ? route_to{route_to::sink, {}} : route_to{};
    if (const auto* t = m_aliases.value().find(a.local, domain))
    {
        const std::string& first = t->front();
        return first.find('@') == std::string::npos ? route_to{route_to::mailbox, first}
                                                     : route_to{route_to::remote, first};
    }
    // A user's own address, which the mailboxes say is one or is not.
    if (m_mailboxes && m_mailboxes->enabled() && !m_owner.get_idp().empty())
        return {route_to::mailbox, a.local};
    return {};
}

bool mail_run::suppressed(std::string_view addr) const
{
    std::string a(addr);
    socketley::ascii::lower_in_place(a);
    return m_suppressed.count(a) > 0;
}

void mail_run::suppress(std::string addr)
{
    socketley::ascii::lower_in_place(addr);
    if (addr.empty() || addr.find('@') == std::string::npos || m_suppressed.count(addr))
        return;
    // What another shard added since is kept beside this one.
    load_suppressed(true);
    m_suppressed.insert(addr);
    ++m_suppressions;
    save_suppressed();
}

void mail_run::load_suppressed(bool merge)
{
    const std::string path = mail_suppressed_path(m_owner.get_name());
    const auto stamp = socketley::file_stamp::of(path);
    if (!merge && m_suppressed_stamp && *m_suppressed_stamp == stamp)
        return;
    m_suppressed_stamp = stamp;
    std::string text;
    if (!socketley::read_file(path, text, {.missing_ok = true}, nullptr))
        return;
    std::unordered_set<std::string> got;
    std::string_view rest = text;
    while (!rest.empty())
        if (std::string_view one = socketley::take_item(rest, '\n'); !one.empty())
            got.emplace(one);
    if (merge)
        m_suppressed.insert(got.begin(), got.end());
    else
        m_suppressed = std::move(got);
}

void mail_run::save_suppressed()
{
    std::string text;
    for (const auto& a : m_suppressed)
        text += a + "\n";
    std::string why;
    const std::string path = mail_suppressed_path(m_owner.get_name());
    const bool ok = socketley::replace_file(path, text, socketley::durability::data, &why);
    m_suppressed_stamp = socketley::file_stamp::of(path);
    if (!ok)
        LOG_WARN(("mail " + std::string(m_owner.get_name()) + ": the suppressed addresses could not be kept: " + why)
                     .c_str());
}

void mail_run::bounce_taken(std::string_view message)
{
    ++m_bounces_taken;
    // A delivery status report names each recipient, then what was done with it (RFC 3464 2.3).
    std::string_view rest = message;
    std::string recipient;
    while (!rest.empty())
    {
        const size_t nl = rest.find('\n');
        std::string_view line = rest.substr(0, nl);
        rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        const size_t colon = line.find(':');
        if (colon == std::string_view::npos)
            continue;
        const std::string_view name = line.substr(0, colon);
        std::string_view value = line.substr(colon + 1);
        while (!value.empty() && value.front() == ' ')
            value.remove_prefix(1);
        if (socketley::ascii::iequals(name, "Final-Recipient"))
        {
            const size_t semi = value.find(';');
            recipient = std::string(semi == std::string_view::npos ? value : value.substr(semi + 1));
            while (!recipient.empty() && recipient.front() == ' ')
                recipient.erase(0, 1);
        }
        else if (socketley::ascii::iequals(name, "Action") && !recipient.empty())
        {
            if (socketley::ascii::iequals(value.substr(0, 6), "failed"))
                suppress(recipient);
            recipient.clear();
        }
    }
}

// ── Starting and stopping ───────────────────────────────────────────────────

bool mail_run::start(std::string& why)
{
    m_loop.register_owner(this);
    if (!m_pool.attach(m_fio))
        m_pool.stop();
    if (!m_checks.attach(m_fio))
        m_checks.stop();
    m_state_dir = mail_state_dir(m_owner.get_name(), m_owner.get_shard_index(), m_owner.get_shards());
    std::error_code ec;
    std::filesystem::create_directories(m_state_dir, ec);
    if (::chmod(m_state_dir.c_str(), 0700) != 0) {}
    if (!m_spool.open(m_state_dir + "/spool", false, why))
        return false;
    m_domains = m_owner.domains();
    m_hostname = m_owner.greeting_name();
    refresh_domains();
    load_suppressed(false);
    if (m_owner.get_tls())
    {
        m_tls = std::make_unique<tls_context>();
        if (!m_tls->init_server(m_owner.get_cert_path(), m_owner.get_key_path(), m_owner.get_ca_path()))
        {
            why = "the certificate or key could not be loaded";
            return false;
        }
    }
    if (!m_owner.get_idp().empty())
    {
        m_idp = std::make_unique<socketley::idp::session_verifier>();
        m_idp->configure(m_owner.get_idp());
    }
    m_users.set_path(std::string(m_owner.get_users()));
    m_aliases.set_path(std::string(m_owner.get_aliases()));
    std::string file_why;
    if (!m_users.refresh([](user_table& t, std::string_view text, std::string& w) { return t.parse(text, w); },
                         file_why) ||
        !m_aliases.refresh([](alias_table& t, std::string_view text, std::string& w) { return t.parse(text, w); },
                           file_why))
    {
        why = file_why;
        return false;
    }
    m_mailboxes = std::make_unique<mailboxes>(*this);
    if (!m_mailboxes->configure(why))
        return false;
    if (const std::string path(m_owner.get_notify_targets()); !path.empty())
    {
        std::vector<socketley::notify_target> targets;
        if (!socketley::load_notify_targets(path, targets, why))
            return false;
        for (const auto& t : targets)
            m_notify_names.push_back(t.name);
        m_notify = std::make_unique<socketley::notifier>(m_loop, m_fio, this, "mail " + std::string(m_owner.get_name()));
        m_notify->set_targets(std::move(targets));
        m_notify->set_runtimes(m_owner.get_runtime_manager(), std::string(m_owner.get_name()));
        if (!m_notify->open(m_state_dir, ".notify", m_owner.get_shard_index(), [](std::string_view) { return true; },
                            why))
            return false;
        m_mailboxes->on_stored = [this](const mailboxes::stored_info& s) {
            std::string j = "{\"event\":\"mail.received\",\"id\":";
            socketley::json::quote_into(j, s.id);
            j += ",\"mailbox\":";
            socketley::json::quote_into(j, s.user);
            j += ",\"folder\":";
            socketley::json::quote_into(j, s.folder);
            j += ",\"key\":";
            socketley::json::quote_into(j, s.key);
            j += ",\"from\":";
            socketley::json::quote_into(j, s.from);
            j += ",\"subject\":";
            socketley::json::quote_into(j, s.subject);
            j += ",\"size\":" + std::to_string(s.size) + "}";
            for (const auto& n : m_notify_names)
                m_notify->add(n, j, "mail/" + s.user);
        };
    }
    m_ring = m_loop.setup_buf_ring(ring_group, ring_bufs, ring_buf_bytes);
    m_multishot = m_ring && m_loop.recv_multishot_enabled();
    if (!open_listener(m_smtp, m_owner.effective_port(), port_kind::smtp, why))
        return false;
    if (m_owner.get_submission_port() &&
        !open_listener(m_sub, m_owner.get_submission_port(), port_kind::submission, why))
        return false;
    if (m_owner.get_submissions_port() &&
        !open_listener(m_subs, m_owner.get_submissions_port(), port_kind::submissions, why))
        return false;
    // IMAP on the first shard alone, whose index of each folder's UIDs is then the one there is.
    if (m_mailboxes && m_mailboxes->enabled() && m_owner.get_shard_index() == 0)
    {
        m_imap = std::make_unique<imap_store>(*this);
        if (m_owner.get_imap_port() && !open_listener(m_imap_l, m_owner.get_imap_port(), port_kind::imap, why))
            return false;
        if (m_owner.get_imaps_port() && !open_listener(m_imaps_l, m_owner.get_imaps_port(), port_kind::imaps, why))
            return false;
    }
    m_delivery = std::make_unique<delivery>(*this);
    if (!m_delivery->start(why))
        return false;
    for (listener* l : {&m_smtp, &m_sub, &m_subs, &m_imap_l, &m_imaps_l})
        if (l->fd >= 0)
            arm_accept(*l);
    publish_records();
    arm_tick();
    LOG_INFO(("mail " + std::string(m_owner.get_name()) + ": serving SMTP on " +
              std::to_string(m_owner.effective_port()) +
              (m_sub.fd >= 0 ? ", submission on " + std::to_string(m_owner.get_submission_port()) : std::string()) +
              (m_subs.fd >= 0 ? ", submission over TLS on " + std::to_string(m_owner.get_submissions_port())
                              : std::string()) +
              " as " + m_hostname + ", " + std::to_string(m_spool.entries().size()) + " message(s) queued")
                 .c_str());
    return true;
}

bool mail_run::open_listener(listener& l, uint16_t port, port_kind kind, std::string& why)
{
    l.kind = kind;
    l.fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (l.fd < 0)
    {
        why = std::string("no socket: ") + std::strerror(errno);
        return false;
    }
    int one = 1;
    ::setsockopt(l.fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    // Every shard binds the ports, and the kernel spreads the connections over them.
    if (m_owner.get_shards() > 1)
        ::setsockopt(l.fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = m_owner.bind_in_addr();
    a.sin_port = htons(port);
    if (::bind(l.fd, reinterpret_cast<sockaddr*>(&a), sizeof a) < 0 || ::listen(l.fd, 4096) < 0)
    {
        why = "port " + std::to_string(port) + " could not be bound: " + std::strerror(errno);
        ::close(l.fd);
        l.fd = -1;
        return false;
    }
    return true;
}

void mail_run::stop()
{
    if (m_stopped)
        return;
    m_stopped = true;
    for (listener* l : {&m_smtp, &m_sub, &m_subs, &m_imap_l, &m_imaps_l})
        if (l->fd >= 0)
        {
            ::shutdown(l->fd, SHUT_RDWR);
            m_loop.close_fd(l->fd);
            l->fd = -1;
        }
    if (auto* mgr = m_owner.get_runtime_manager())
        mgr->requests().drop_origin(this);
    if (m_delivery)
        m_delivery->stop();
    if (m_notify)
        m_notify->stop();
    if (m_imap)
        m_imap->flush_now();
    std::vector<conn*> all;
    for (auto& [id, c] : m_conns)
        all.push_back(c.get());
    for (conn* c : all)
        close_conn(*c);
    m_pool.stop();
    m_checks.stop();
    m_spool.close();
    *m_alive = false;
}

bool mail_run::drained() const
{
    return m_loop.owner_drained(this) && (!m_delivery || m_delivery->drained());
}

// ── Accepting ───────────────────────────────────────────────────────────────

void mail_run::arm_accept(listener& l)
{
    if (m_stopped || l.fd < 0 || l.pending)
        return;
    l.req = io_request{};
    l.req.owner = this;
    l.req.fd = l.fd;
    l.req.type = event_loop::supports_multishot_accept() ? op_multishot_accept : op_accept;
    l.pending = l.req.type == op_multishot_accept ? m_loop.submit_multishot_accept(l.fd, &l.req)
                                                  : m_loop.submit_accept(l.fd, nullptr, nullptr, &l.req);
}

void mail_run::accept_done(listener& l, struct io_uring_cqe* cqe)
{
    if (!(cqe->flags & IORING_CQE_F_MORE))
        l.pending = false;
    const int fd = cqe->res;
    if (fd >= 0)
    {
        const size_t limit = m_owner.get_max_connections();
        if (m_stopped || (limit && m_conns.size() >= limit))
            m_loop.close_fd(fd);
        else
        {
            auto c = std::make_unique<conn>();
            c->run = this;
            c->id = m_next_id++;
            c->fd = fd;
            c->kind = l.kind;
            socklen_t len = sizeof c->peer;
            if (::getpeername(fd, reinterpret_cast<sockaddr*>(&c->peer), &len) < 0) {}
            int one = 1;
            ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
            c->closing_ms = c->heard_ms = wall::now_ms_coarse();
            conn* raw = c.get();
            m_conns.emplace(raw->id, std::move(c));
            runtime_instance::stat_add(m_owner.m_stat_total_connections, 1);
            m_owner.m_stat_active_connections.store(m_conns.size(), std::memory_order_relaxed);
            // A port that speaks TLS from the first byte begins with the handshake, any other with the greeting.
            if (l.kind == port_kind::submissions || l.kind == port_kind::imaps)
            {
                raw->ssl = m_tls ? m_tls->create_ssl_server() : nullptr;
                if (!raw->ssl)
                {
                    close_conn(*raw);
                    raw = nullptr;
                }
            }
            else
                begin_session(*raw);
            if (raw && !raw->dead)
                arm_read(*raw);
        }
    }
    if (!l.pending && !m_stopped && fd != -ECANCELED)
        arm_accept(l);
}

smtp_config mail_run::session_config(const conn& c) const
{
    smtp_config cfg;
    cfg.hostname = m_hostname;
    cfg.max_size = m_owner.get_max_size();
    cfg.max_rcpt = m_owner.get_max_recipients();
    cfg.tls_offered = m_tls != nullptr && c.kind != port_kind::submissions;
    cfg.tls_active = c.ssl != nullptr && c.handshaken;
    const bool signs_in = !m_owner.get_users().empty() || m_idp != nullptr;
    cfg.auth_offered = signs_in;
    // A loopback peer is this machine, whose own programs need no TLS to sign in.
    cfg.auth_in_clear = loopback(c.peer);
    cfg.auth_required = c.kind != port_kind::smtp;
    cfg.tls_required = c.kind == port_kind::submission && m_tls != nullptr && !loopback(c.peer);
    return cfg;
}

void mail_run::begin_session(conn& c)
{
    c.in_input = true;
    if (c.kind == port_kind::imap || c.kind == port_kind::imaps)
    {
        imap_config cfg;
        cfg.hostname = m_hostname;
        cfg.tls_offered = m_tls != nullptr && c.kind == port_kind::imap;
        cfg.tls_active = c.ssl != nullptr && c.handshaken;
        cfg.login_in_clear = loopback(c.peer);
        cfg.max_append = m_owner.get_max_size();
        c.imap = std::make_unique<imap_session>(cfg, c, *m_imap);
        c.imap->greet();
    }
    else
    {
        c.smtp = std::make_unique<smtp_session>(session_config(c), c);
        c.smtp->greet();
    }
    c.in_input = false;
    flush(c);
}

// ── Reading ─────────────────────────────────────────────────────────────────

mail_run::conn* mail_run::conn_of(io_request* req)
{
    auto* raw = reinterpret_cast<conn*>(req->buffer);
    if (const auto it = m_conns.find(raw->id); it != m_conns.end() && it->second.get() == raw)
        return raw;
    for (const auto& c : m_closing)
        if (c.get() == raw)
            return raw;
    return nullptr;
}

mail_run::conn* mail_run::find(uint64_t id)
{
    const auto it = m_conns.find(id);
    return it == m_conns.end() ? nullptr : it->second.get();
}

void mail_run::arm_read(conn& c)
{
    if (c.dead || c.rd_pending || c.fd < 0)
        return;
    c.rd = io_request{};
    c.rd.owner = this;
    c.rd.buffer = reinterpret_cast<char*>(&c);
    c.rd.fd = c.fd;
    c.rearm = false;
    if (m_multishot)
    {
        c.rd.type = op_recv_multishot;
        c.rd.buf_group = static_cast<uint8_t>(ring_group);
        c.rd_pending = m_loop.submit_recv_multishot(c.fd, ring_group, &c.rd);
    }
    else
    {
        if (!c.rbuf)
            c.rbuf = std::make_unique<char[]>(ring_buf_bytes);
        c.rd.type = op_read;
        c.rd_pending = m_loop.submit_read(c.fd, c.rbuf.get(), ring_buf_bytes, &c.rd);
    }
    if (!c.rd_pending)
        c.rearm = true;
}

void mail_run::read_done(conn& c, struct io_uring_cqe* cqe)
{
    const int res = cqe->res;
    if (c.rd.type == op_recv_multishot)
    {
        const bool more = cqe->flags & IORING_CQE_F_MORE;
        if (!more)
            c.rd_pending = false;
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
            return;
        if (res == -ENOBUFS)
        {
            if (!more)
                c.rearm = true;
            return;
        }
        if (res <= 0)
        {
            close_conn(c);
            return;
        }
        if (!more)
            arm_read(c);
        return;
    }
    c.rd_pending = false;
    if (c.dead)
        return;
    if (res <= 0)
    {
        close_conn(c);
        return;
    }
    bytes_in(c, c.rbuf.get(), static_cast<size_t>(res));
    if (!c.dead)
        arm_read(c);
}

void mail_run::bytes_in(conn& c, const char* p, size_t n)
{
    runtime_instance::stat_add(m_owner.m_stat_bytes_in, n);
    c.heard_ms = wall::now_ms_coarse();
    if (c.ssl)
        tls_in(c, p, n);
    else
        plain_in(c, p, n);
}

void mail_run::tls_in(conn& c, const char* p, size_t n)
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
        if (c.upgrading)
        {
            c.upgrading = false;
            ++m_starttls;
            c.in_input = true;
            if (c.imap)
                c.imap->tls_started();
            else
                c.smtp->tls_started();
            c.in_input = false;
            flush(c);
        }
        else
            begin_session(c);
        if (c.dead)
            return;
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

void mail_run::plain_in(conn& c, const char* p, size_t n)
{
    if (!c.smtp && !c.imap)
        return;
    c.in_input = true;
    if (c.imap)
        c.imap->input(std::string_view(p, n));
    else
        c.smtp->input(std::string_view(p, n));
    c.in_input = false;
    if (!c.dead)
        flush(c);
}

// ── Writing ─────────────────────────────────────────────────────────────────

void mail_run::out(conn& c, std::string_view bytes)
{
    if (c.dead)
        return;
    if (c.ssl && c.handshaken && !c.upgrading)
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
    // Replies said while input is taken go in one write once all of it is, as pipelining wants them.
    if (!c.in_input)
        flush(c);
}

void mail_run::queue_owned(conn& c, std::string_view bytes)
{
    if (bytes.empty())
        return;
    c.owed += bytes.size();
    if (!c.queue.empty() && c.queue.back().owns())
        c.queue.back().append(bytes);
    else
    {
        std::string b = std::move(c.spare);
        b.assign(bytes);
        c.queue.emplace_back(std::move(b));
    }
}

void mail_run::queue_tls_out(conn& c)
{
    m_tls_out.clear();
    tls_context::take_out(c.ssl, m_tls_out);
    queue_owned(c, m_tls_out);
}

void mail_run::flush(conn& c)
{
    if (c.dead || c.wr_pending)
        return;
    if (c.sending_at >= c.sending.size())
    {
        c.sending.clear();
        c.sending_at = 0;
        c.sent = 0;
        if (c.queue.empty())
        {
            if (c.closing)
                m_close_soon.push_back(c.id);
            return;
        }
        c.sending.swap(c.queue);
    }
    c.wr = io_request{};
    c.wr.owner = this;
    c.wr.buffer = reinterpret_cast<char*>(&c);
    c.wr.fd = c.fd;
    const size_t left = c.sending.size() - c.sending_at;
    if (left == 1)
    {
        const std::string_view b = c.sending[c.sending_at].view().substr(c.sent);
        c.wr.type = op_write;
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
        c.wr.type = op_writev;
        c.wr_pending = m_loop.submit_writev(c.fd, c.iov.data(), static_cast<uint32_t>(c.iov.size()), &c.wr);
    }
    c.reflush = !c.wr_pending;
}

void mail_run::write_done(conn& c, int res)
{
    c.wr_pending = false;
    if (c.dead)
        return;
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
    flush(c);
}

void mail_run::close_soon(conn& c)
{
    if (c.dead)
        return;
    if (!c.closing)
    {
        c.closing = true;
        c.closing_ms = wall::now_ms_coarse();
    }
    m_close_soon.push_back(c.id);
}

void mail_run::close_conn(conn& c)
{
    if (c.dead)
        return;
    c.dead = true;
    if (c.smtp)
        c.smtp->gone();
    if (c.imap)
        c.imap->gone();
    if (c.writer)
    {
        m_spool.abort(c.writer);
        c.writer = 0;
    }
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
    const auto it = m_conns.find(c.id);
    if (it != m_conns.end())
    {
        m_closing.push_back(std::move(it->second));
        m_conns.erase(it);
    }
    m_owner.m_stat_active_connections.store(m_conns.size(), std::memory_order_relaxed);
}

void mail_run::settle()
{
    if (m_in_settle)
        return;
    m_in_settle = true;
    const int64_t now = wall::now_ms_coarse();
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
            if (c->owed == 0 || now - c->closing_ms >= close_grace_ms)
                close_conn(*c);
        }
    }
    std::erase_if(m_closing, [](const std::unique_ptr<conn>& c) { return !c->rd_pending && !c->wr_pending; });
    m_in_settle = false;
}

// ── The session's hooks ─────────────────────────────────────────────────────

void mail_run::conn::reply(std::string_view bytes)
{
    run->out(*this, bytes);
}

void mail_run::conn::start_tls()
{
    // The 220 goes in the clear, and everything after it is the handshake's.
    run->flush(*this);
    ssl = run->m_tls ? run->m_tls->create_ssl_server() : nullptr;
    if (!ssl)
    {
        run->close_conn(*this);
        return;
    }
    handshaken = false;
    upgrading = true;
    closing_ms = wall::now_ms_coarse();
}

void mail_run::conn::authenticate(std::string_view, std::string user, std::string secret,
                                  std::function<void(bool, std::string)> done)
{
    mail_run& r = *run;
    // A wrong answer waits a second before it is said.
    auto finish = [&r, alive = r.m_alive, done](bool ok, std::string name) {
        if (!*alive)
            return;
        if (ok)
        {
            ++r.m_auth_ok;
            done(true, std::move(name));
            return;
        }
        ++r.m_auth_failed;
        if (!r.m_fio.after(auth_delay, [alive, done](int64_t) {
                if (*alive)
                    done(false, {});
            }))
            done(false, {});
    };
    if (const std::string* hash = r.m_users.value().hash_of(user))
    {
        // scrypt costs tens of milliseconds, which the loop does not spend.
        auto matched = std::make_shared<bool>(false);
        r.m_pool.submit(1, [h = *hash, pw = std::move(secret), matched] {
                            *matched = socketley::storage::password_matches(h, pw);
                        },
                        [matched, user, finish] { finish(*matched, user); });
        return;
    }
    if (r.m_idp)
    {
        socketley::idp::session_verifier::who who;
        if (r.m_idp->check_bearer(secret, who) && (user == who.username || user == who.sub || user == who.email))
        {
            idp_user = true;
            user_email = who.email;
            finish(true, who.username.empty() ? who.sub : who.username);
            return;
        }
        // A password, which only the idp runtime can check, on its own threads.
        const uint64_t me = id;
        r.m_mailboxes->verify(user, secret, [&r, me, finish](bool ok, std::string name, std::string email) {
            if (conn* c = r.find(me); c && ok)
            {
                c->idp_user = true;
                c->user_email = std::move(email);
            }
            finish(ok, std::move(name));
        });
        return;
    }
    finish(false, {});
}

void mail_run::conn::mail_from(const address& from, std::function<void(rcpt_verdict)> done)
{
    // A user of the idp runtime sends as their own address, its username at a domain of this runtime or the email
    // their account names, as Postfix's reject_sender_login_mismatch has it.
    if (idp_user && !from.empty())
    {
        const std::string user = smtp->user();
        const bool own = (run->is_local_domain(from.domain) && socketley::ascii::iequals(from.local, user)) ||
                         (!user_email.empty() && socketley::ascii::iequals(from.text(), user_email));
        if (!own)
        {
            done({553, "Sender address not owned by " + user});
            return;
        }
    }
    done({250, ""});
}

void mail_run::conn::rcpt_to(const address& to, std::function<void(rcpt_verdict)> done)
{
    mail_run& r = *run;
    const route_to where = r.route(to, smtp->sender().empty());
    switch (where.k)
    {
        case route_to::mailbox:
        {
            if (!r.m_mailboxes || !r.m_mailboxes->enabled())
            {
                ++r.m_refused_rcpt;
                done({550, "No mailbox is kept here"});
                return;
            }
            r.m_mailboxes->find(where.target, [&r, done](bool found, std::string, std::string) {
                if (!found)
                    ++r.m_refused_rcpt;
                done(found ? rcpt_verdict{250, ""} : rcpt_verdict{550, "No such user here"});
            });
            return;
        }
        case route_to::sink:
            done({250, ""});
            return;
        case route_to::remote:
            // Mail for elsewhere is taken from a signed-in user, from this machine, or for an alias of a local
            // address; from anyone else it is relaying, which a mail server open to it is soon a spammer's.
            if (!smtp->user().empty() || loopback(peer) || r.is_local_domain(to.domain))
            {
                done({250, ""});
                return;
            }
            ++r.m_refused_relay;
            done({554, "Relay access denied"});
            return;
        case route_to::none:
            break;
    }
    ++r.m_refused_rcpt;
    if (r.m_owner.get_no_reply() && socketley::ascii::iequals(to.local, "no-reply") && r.is_local_domain(to.domain))
        done({550, "This address takes no mail"});
    else
        done({550, "No such user here"});
}

bool mail_run::conn::data_begin()
{
    mail_run& r = *run;
    auto e = std::make_shared<spool_entry>();
    e->id = new_spool_id(r.shard());
    e->from = smtp->sender().text();
    for (const auto& a : smtp->recipients())
        e->rcpts.push_back({a.text(), rcpt_state::waiting, {}});
    e->user = smtp->user();
    e->peer = peer_ip(peer);
    e->helo = smtp->helo();
    e->at_ms = wall::now_ms_coarse();
    const std::string head =
        r.received_line(*this, e->id, smtp->recipients().size() == 1 ? smtp->recipients().front().text() : "");
    entry = e;
    writer = r.m_spool.begin(std::move(e), head);
    return writer != 0;
}

void mail_run::conn::data_bytes(std::string_view piece)
{
    if (writer)
        run->m_spool.append(writer, piece);
}

void mail_run::conn::data_end(std::function<void(rcpt_verdict)> done)
{
    mail_run& r = *run;
    const uint64_t w = writer;
    writer = 0;
    entry_ptr e = std::move(entry);
    // Mail from elsewhere is checked before it is taken: from a user signed in, or this machine, it is not.
    const bool check = kind == port_kind::smtp && smtp->user().empty() && !loopback(peer);
    const std::string ip = peer_ip(peer), helo = smtp->helo();
    r.m_spool.finish(w, [&r, alive = r.m_alive, e, done, check, ip, helo](bool ok) {
        if (!*alive)
            return;
        if (!ok)
        {
            ++r.m_spool_failed;
            done({451, "The message could not be written, try again later"});
            return;
        }
        if (!check)
        {
            done({250, "OK queued as " + e->id});
            r.accepted(e);
            return;
        }
        auto result = std::make_shared<inbound_result>();
        const std::string path = r.m_spool.file_of(e->id);
        r.m_checks.submit(r.m_checks.next_lane(),
                          [e, result, ip, helo, path] {
                              std::string whole;
                              std::string_view msg;
                              if (e->body)
                                  msg = *e->body;
                              else
                              {
                                  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
                                  whole.resize(e->body_len);
                                  size_t got = 0;
                                  while (fd >= 0 && got < whole.size())
                                  {
                                      const ssize_t n = ::pread(fd, whole.data() + got, whole.size() - got,
                                                                static_cast<off_t>(e->body_off + got));
                                      if (n <= 0)
                                          break;
                                      got += static_cast<size_t>(n);
                                  }
                                  if (fd >= 0)
                                      ::close(fd);
                                  whole.resize(got);
                                  msg = whole;
                              }
                              auto resolver = system_check_resolver();
                              *result = check_inbound(msg, ip, helo, e->from, *resolver, wall::now_ms() / 1000);
                          },
                          [&r, alive, e, done, result] {
                              if (!*alive)
                                  return;
                              ++r.m_checked;
                              if (result->reject())
                              {
                                  // DMARC says its domain's own mail never comes so: it is refused, not kept.
                                  ++r.m_dmarc_rejected;
                                  r.m_spool.forget_written(e->id);
                                  done({550, "Message refused: DMARC policy of " + result->from_domain + " is reject"});
                                  return;
                              }
                              if (result->quarantine())
                                  ++r.m_quarantined;
                              r.m_spool.note_auth(*e, result->header(), result->quarantine() ? "Junk" : "");
                              done({250, "OK queued as " + e->id});
                              r.accepted(e);
                          });
    });
}

void mail_run::conn::data_abort()
{
    if (writer)
    {
        run->m_spool.abort(writer);
        writer = 0;
    }
    entry.reset();
    ++run->m_too_big;
}

void mail_run::conn::close()
{
    run->close_soon(*this);
}

void mail_run::conn::login(std::string user, std::string password, std::function<void(bool, std::string)> done)
{
    authenticate("IMAP", std::move(user), std::move(password), std::move(done));
}

std::string mail_run::received_line(const conn& c, const std::string& id, const std::string& rcpt) const
{
    const bool tls = c.ssl && c.handshaken;
    const bool auth = c.smtp && !c.smtp->user().empty();
    std::string with = c.smtp && c.smtp->esmtp() ? "ESMTP" : "SMTP";
    if (tls)
        with += "S";
    if (auth)
        with += "A";
    std::string out = "Received: from " + (c.smtp ? c.smtp->helo() : std::string()) + " (" + peer_ip(c.peer) +
                      ")\r\n\tby " + m_hostname + " (socketley) with " + with + " id " + id;
    if (!rcpt.empty())
        out += "\r\n\tfor <" + rcpt + ">";
    out += "; " + rfc5322_date(wall::now_ms()) + "\r\n";
    return out;
}

void mail_run::accepted(const entry_ptr& e)
{
    ++m_received;
    runtime_instance::stat_add(m_owner.m_stat_total_messages, 1);
    if (m_delivery)
        m_delivery->queued(e);
}

void mail_run::queue_message(const std::string& from, const std::vector<std::string>& rcpts, std::string body,
                             bool bounce, std::string user, std::function<void(bool, std::string)> done)
{
    auto e = std::make_shared<spool_entry>();
    e->id = new_spool_id(shard());
    e->from = from;
    for (const auto& a : rcpts)
        e->rcpts.push_back({a, rcpt_state::waiting, {}});
    e->user = std::move(user);
    e->peer = "local";
    e->helo = m_hostname;
    e->at_ms = wall::now_ms_coarse();
    e->bounce = bounce;
    const uint64_t w = m_spool.begin(e, {});
    m_spool.append(w, body);
    m_spool.finish(w, [this, alive = m_alive, e, done](bool ok) {
        if (!*alive)
            return;
        if (ok)
            accepted(e);
        if (done)
            done(ok, e->id);
    });
}

// ── The ring ────────────────────────────────────────────────────────────────

void mail_run::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req)
        return;
    if (m_notify && m_notify->owns(req))
        m_notify->on_timer();
    else if (file_io::owns_type(req->type))
        m_fio.on_cqe(cqe);
    else if (req == &m_tick_req)
    {
        m_tick_armed = false;
        if (!m_stopped)
            tick();
    }
    else if (req == &m_smtp.req)
        accept_done(m_smtp, cqe);
    else if (req == &m_sub.req)
        accept_done(m_sub, cqe);
    else if (req == &m_subs.req)
        accept_done(m_subs, cqe);
    else if (req == &m_imap_l.req)
        accept_done(m_imap_l, cqe);
    else if (req == &m_imaps_l.req)
        accept_done(m_imaps_l, cqe);
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

void mail_run::on_loop_turn()
{
    if (m_stopped)
        return;
    for (listener* l : {&m_smtp, &m_sub, &m_subs, &m_imap_l, &m_imaps_l})
        if (l->fd >= 0 && !l->pending)
            arm_accept(*l);
    for (auto& [id, c] : m_conns)
    {
        if (c->rearm && !c->dead)
            arm_read(*c);
        if (c->reflush && !c->dead)
            flush(*c);
    }
    if (m_delivery)
        m_delivery->on_loop_turn();
    settle();
}

void mail_run::arm_tick()
{
    if (m_tick_armed || m_stopped)
        return;
    m_tick_req = io_request{};
    m_tick_req.owner = this;
    m_tick_req.type = op_timeout;
    m_tick_ts = {1, 0};
    m_tick_armed = m_loop.submit_timeout(&m_tick_ts, &m_tick_req);
}

void mail_run::tick()
{
    const int64_t now = wall::now_ms_coarse();
    std::vector<conn*> late;
    for (auto& [id, c] : m_conns)
    {
        const bool shaking = c->ssl && !c->handshaken;
        const int64_t quiet = c->imap ? imap_idle_ms : idle_ms;
        if (!c->closing && ((shaking && now - c->closing_ms > handshake_ms) || now - c->heard_ms > quiet))
            late.push_back(c.get());
        else if (c->imap && c->imap->idling())
        {
            c->in_input = true;
            c->imap->poll();
            c->in_input = false;
            flush(*c);
        }
    }
    for (conn* c : late)
    {
        if (c->imap && !(c->ssl && !c->handshaken))
        {
            out(*c, "* BYE " + m_hostname + " idle too long\r\n");
            close_soon(*c);
        }
        else if (c->smtp && !(c->ssl && !c->handshaken))
        {
            out(*c, "421 4.4.2 " + m_hostname + " idle too long, closing\r\n");
            close_soon(*c);
        }
        else
            close_conn(*c);
    }
    if (now >= m_next_files_ms)
    {
        m_next_files_ms = now + 1000;
        refresh_files();
        refresh_domains();
        load_suppressed(false);
    }
    if (m_delivery)
        m_delivery->tick(now);
    if (m_imap)
        m_imap->tick(now);
    tls_context::report_inbound_failures();
    settle();
    arm_tick();
}

void mail_run::refresh_files()
{
    std::string why;
    if (!m_users.refresh([](user_table& t, std::string_view text, std::string& w) { return t.parse(text, w); }, why))
        LOG_WARN(("mail " + std::string(m_owner.get_name()) + ": " + why + "; the users read before are kept").c_str());
    why.clear();
    if (!m_aliases.refresh([](alias_table& t, std::string_view text, std::string& w) { return t.parse(text, w); },
                           why))
        LOG_WARN(("mail " + std::string(m_owner.get_name()) + ": " + why + "; the aliases read before are kept")
                     .c_str());
}

void mail_run::refresh_domains()
{
    if (m_owner.get_dns().empty() || !m_owner.get_mail_domains().empty())
        return;
    std::vector<std::string> now;
    for (auto& [rt, origin] : dns_feed::read_zones())
        if (rt == m_owner.get_dns())
        {
            std::string d = origin;
            if (!d.empty() && d.back() == '.')
                d.pop_back();
            socketley::ascii::lower_in_place(d);
            if (!d.empty())
                now.push_back(std::move(d));
        }
    if (now == m_domains)
        return;
    m_domains = std::move(now);
    m_owner.set_resolved_domains(m_domains);
    m_hostname = m_owner.greeting_name();
    std::string list;
    for (const auto& d : m_domains)
        list += (list.empty() ? "" : ", ") + d;
    LOG_INFO(("mail " + std::string(m_owner.get_name()) + ": the zones of " + std::string(m_owner.get_dns()) +
              " are its domains: " + (list.empty() ? std::string("none") : list))
                 .c_str());
    publish_records();
}

std::string mail_run::records_text() const
{
    std::string out;
    const std::string dkim = m_delivery ? m_delivery->dkim_record() : std::string();
    const std::string sel = m_delivery ? m_delivery->dkim_selector() : std::string("skl");
    // Mail for elsewhere through a smarthost leaves from its addresses, which SPF cannot name here, so it only softfails.
    const std::string spf = m_owner.get_relay().empty() ? "v=spf1 mx -all" : "v=spf1 mx ~all";
    for (const auto& d : m_domains)
    {
        out += d + ". 300 IN MX 10 " + m_hostname + ".\n";
        out += d + ". 300 IN TXT \"" + spf + "\"\n";
        if (!dkim.empty())
            out += sel + "._domainkey." + d + ". 300 IN TXT \"" + dkim + "\"\n";
        out += "_dmarc." + d + ". 300 IN TXT \"v=DMARC1; p=quarantine; adkim=r; aspf=r\"\n";
    }
    return out;
}

void mail_run::publish_records()
{
    // One shard writes them, since every shard's are the same.
    if (m_owner.get_dns().empty() || m_owner.get_shard_index() != 0)
        return;
    const std::string text = records_text();
    if (text == m_published)
        return;
    if (dns_feed::write_records(m_owner.get_name(), text))
        m_published = text;
    else
        LOG_WARN(("mail " + std::string(m_owner.get_name()) + ": its records could not be written for " +
                  std::string(m_owner.get_dns()))
                     .c_str());
}

// ── Requests ────────────────────────────────────────────────────────────────

void mail_run::expect_reply(uint64_t cookie, std::function<void(request_status, std::string_view)> cb)
{
    m_replies[cookie] = std::move(cb);
}

void mail_run::ask(const std::string& target, std::string payload,
                   std::function<void(request_status, std::string_view)> cb)
{
    auto* mgr = m_owner.get_runtime_manager();
    const uint64_t cookie = next_cookie();
    expect_reply(cookie, cb);
    if (!mgr || m_stopped || !mgr->requests().post(this, cookie, target, payload, request_class::background))
    {
        m_replies.erase(cookie);
        cb(request_status::no_target, {});
    }
}

void mail_run::on_request_reply(uint64_t cookie, request_status st, std::string_view reply)
{
    const auto it = m_replies.find(cookie);
    if (it == m_replies.end())
        return;
    auto cb = std::move(it->second);
    m_replies.erase(it);
    cb(st, reply);
}

std::string mail_run::queue_text(std::string_view filter) const
{
    std::string out;
    for (const auto& [id, e] : m_spool.entries())
    {
        if (!filter.empty() && id.find(filter) == std::string::npos && e->from.find(filter) == std::string::npos)
            continue;
        out += id + "\t" + std::to_string(e->body_len) + "\t" + (e->from.empty() ? "<>" : e->from) + "\t" +
               std::to_string(e->waiting()) + "/" + std::to_string(e->rcpts.size()) + " waiting\t" +
               std::to_string(e->attempts) + " tries\n";
    }
    return out;
}

std::string mail_run::show_text(const std::string& id) const
{
    const entry_ptr e = m_spool.find(id);
    if (!e)
        return "error: no message " + id + " is queued";
    std::string out = "id: " + e->id + "\nfrom: " + (e->from.empty() ? "<>" : e->from) + "\nsize: " +
                      std::to_string(e->body_len) + "\nreceived: " + rfc5322_date(e->at_ms) + "\npeer: " + e->peer +
                      "\n";
    if (!e->user.empty())
        out += "user: " + e->user + "\n";
    out += "tries: " + std::to_string(e->attempts) + "\n";
    if (e->next_ms)
        out += "next: " + rfc5322_date(e->next_ms) + "\n";
    for (const auto& r : e->rcpts)
        out += "rcpt: " + r.addr + "\t" +
               (r.state == rcpt_state::waiting ? "waiting" : r.state == rcpt_state::delivered ? "delivered" : "failed") +
               (r.why.empty() ? std::string() : "\t" + r.why) + "\n";
    return out;
}

void mail_run::command(uint64_t ticket, std::string_view payload)
{
    auto* mgr = m_owner.get_runtime_manager();
    if (!mgr)
        return;
    const auto answer = [mgr, ticket](std::string_view text) {
        mgr->requests().complete_deferred(ticket, request_status::ok, text);
    };
    socketley::bytes::reader r(payload);
    uint8_t v = 0;
    if (!r.marker(command_prefix) || !r.u8(v))
    {
        answer("error: no mail command");
        return;
    }
    if (static_cast<verb>(v) == verb::send)
    {
        send_command(ticket, r);
        return;
    }
    std::string arg;
    if (!r.bytes(arg, 4096))
    {
        answer("error: the command is cut off");
        return;
    }
    switch (static_cast<verb>(v))
    {
        case verb::queue:
            answer(queue_text(arg));
            return;
        case verb::show:
            answer(show_text(arg));
            return;
        case verb::dns:
            answer(records_text());
            return;
        case verb::suppressed:
        {
            std::vector<std::string> all(m_suppressed.begin(), m_suppressed.end());
            std::sort(all.begin(), all.end());
            std::string out;
            for (const auto& a : all)
                out += a + "\n";
            answer(out);
            return;
        }
        case verb::forgive:
        {
            std::string a = arg;
            socketley::ascii::lower_in_place(a);
            load_suppressed(false);
            if (!m_suppressed.erase(a))
            {
                answer("error: " + arg + " is not suppressed");
                return;
            }
            save_suppressed();
            answer("ok");
            return;
        }
        case verb::flush:
            if (m_delivery)
                m_delivery->flush(arg);
            answer("ok");
            return;
        case verb::drop:
        {
            const entry_ptr e = m_spool.find(arg);
            if (!e)
            {
                answer("error: no message " + arg + " is queued");
                return;
            }
            if (m_delivery)
                m_delivery->forget(arg);
            m_spool.remove(arg);
            answer("ok");
            return;
        }
        default:
            answer("error: no such mail command");
            return;
    }
}

void mail_run::send_command(uint64_t ticket, socketley::bytes::reader& r)
{
    auto* mgr = m_owner.get_runtime_manager();
    const auto answer = [mgr, ticket](std::string_view text) {
        mgr->requests().complete_deferred(ticket, request_status::ok, text);
    };
    compose c;
    if (!decode_send(r, c, m_owner.get_max_size()))
    {
        answer("error: the message is cut off or larger than --max-size");
        return;
    }
    std::string body, from, why;
    std::vector<std::string> rcpts;
    if (!m_delivery->compose_message(c, from, rcpts, body, why))
    {
        answer("error: " + why);
        return;
    }
    queue_message(from, rcpts, std::move(body), false, "local", [answer](bool ok, std::string id) {
        answer(ok ? "queued " + id : "error: the message could not be written to the spool");
    });
}

std::string mail_run::stats() const
{
    std::string out;
    using socketley::stats_text::put;
    put(out, "mail_received", m_received);
    put(out, "mail_queued", m_spool.entries().size());
    put(out, "mail_queued_bytes", m_spool.bytes());
    put(out, "mail_refused_recipients", m_refused_rcpt);
    put(out, "mail_refused_relay", m_refused_relay);
    put(out, "mail_too_big", m_too_big);
    put(out, "mail_spool_failures", m_spool_failed + m_spool.write_failures());
    put(out, "mail_bounces_taken", m_bounces_taken);
    put(out, "mail_suppressed", m_suppressed.size());
    if (m_imap)
    {
        size_t imap = 0;
        for (const auto& [id, c] : m_conns)
            imap += c->imap != nullptr;
        put(out, "imap_connections", imap);
        put(out, "imap_reads", m_imap->gets());
        put(out, "imap_cache_hits", m_imap->cache_hits());
    }
    if (m_mailboxes && m_mailboxes->enabled())
    {
        put(out, "mail_stored", m_mailboxes->stored());
        put(out, "mail_store_failures", m_mailboxes->store_failures());
    }
    put(out, "mail_checked", m_checked);
    put(out, "mail_dmarc_rejected", m_dmarc_rejected);
    put(out, "mail_quarantined", m_quarantined);
    put(out, "auth_ok", m_auth_ok);
    put(out, "auth_failed", m_auth_failed);
    put(out, "starttls", m_starttls);
    put(out, "tls_failures", m_tls_failures);
    if (m_delivery)
        m_delivery->stats(out);
    return out;
}

}   // namespace socketley::mail
