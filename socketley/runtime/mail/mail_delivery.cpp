#include "mail_delivery.h"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <ctime>
#include <random>
#include <set>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <resolv.h>
#include <sys/socket.h>
#include <unistd.h>

#include "mail_arc.h"
#include "mail_compose.h"
#include "mail_instance.h"
#include "mail_mailbox.h"
#include "mail_mime.h"
#include "jmap_session.h"
#include "mail_rspamd.h"
#include "mail_srs.h"
#include "mail_verify.h"
#include "mail_run.h"
#include "../dns/dns_wire.h"
#include "../../shared/crypto/tls_context.h"
#include "../../shared/http/https_client.h"
#include "../../shared/loop/blocking_write.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/net/dns_client.h"
#include "../../shared/runtime/stats_text.h"
#include "../../shared/util/ascii.h"
#include "../../shared/util/base64.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/random_id.h"
#include "../../shared/util/settings.h"
#include "../../shared/util/wall_clock.h"

namespace socketley::mail
{

namespace
{

// Connections to one domain, grown from four to twenty while it takes mail, as Postfix's slow start does.
constexpr uint32_t per_route_max = 20;
constexpr size_t all_routes = 128;
constexpr uint32_t read_bytes = 16384;
constexpr uint32_t body_chunk = 256u << 10;
constexpr int64_t command_ms = 300000;
// RFC 5321 4.5.3.2.6: the reply to the end of the data is waited for ten minutes.
constexpr int64_t final_ms = 600000;
constexpr int64_t idle_close_ms = 5000;
// An exchanger's name looked up again after an hour.
constexpr int64_t lookup_ms = 3600000;

std::string lower(std::string_view s)
{
    std::string out(s);
    socketley::ascii::lower_in_place(out);
    return out;
}

std::string domain_of(std::string_view addr)
{
    const size_t at = addr.rfind('@');
    return at == std::string_view::npos ? std::string() : lower(addr.substr(at + 1));
}

// MX or TXT records out of an answer the system's resolver gave, for a lookup the loop's resolver could not make.
bool parse_answer(const uint8_t* msg, size_t len, uint16_t type, std::vector<dns_client::record>& out, bool& nx)
{
    nx = false;
    if (len < dns::header_len)
        return false;
    if ((msg[3] & 0x0F) == dns::rcode::NXDOMAIN)
    {
        nx = true;
        return true;
    }
    uint8_t name[dns::max_name];
    size_t next = 0;
    size_t at = dns::header_len;
    for (uint16_t q = dns::rd16(msg + 4); q > 0; --q)
    {
        if (dns::read_name(msg, len, at, name, next) == 0)
            return false;
        at = next + 4;
    }
    for (uint16_t an = dns::rd16(msg + 6); an > 0; --an)
    {
        if (dns::read_name(msg, len, at, name, next) == 0 || next + 10 > len)
            return false;
        const uint16_t t = dns::rd16(msg + next);
        const uint16_t rdlen = dns::rd16(msg + next + 8);
        const uint8_t* rd = msg + next + 10;
        if (next + 10 + rdlen > len)
            return false;
        if (t == type && type == dns::type::MX && rdlen > 2)
        {
            uint8_t ex[dns::max_name];
            size_t after = 0;
            const size_t el = dns::read_name(msg, len, next + 12, ex, after);
            if (el)
                out.push_back({dns::rd16(rd), dns::to_text(std::string_view(reinterpret_cast<char*>(ex), el))});
        }
        else if (t == type && type == dns::type::TXT)
        {
            std::string text;
            for (size_t i = 0; i < rdlen;)
            {
                const size_t n = rd[i];
                if (i + 1 + n > rdlen)
                    break;
                text.append(reinterpret_cast<const char*>(rd + i + 1), n);
                i += 1 + n;
            }
            out.push_back({0, std::move(text)});
        }
        at = next + 10 + rdlen;
    }
    return true;
}

// Lines that begin with a dot have one more put ahead (RFC 5321 4.5.2), `bol` saying whether a line begins here.
void stuff(std::string_view in, std::string& out, bool& bol)
{
    out.reserve(out.size() + in.size() + in.size() / 64 + 4);
    size_t at = 0;
    while (at < in.size())
    {
        if (bol && in[at] == '.')
            out += '.';
        const size_t nl = in.find('\n', at);
        if (nl == std::string_view::npos)
        {
            out.append(in.substr(at));
            bol = false;
            return;
        }
        out.append(in.substr(at, nl + 1 - at));
        at = nl + 1;
        bol = true;
    }
}

}   // namespace

struct delivery::out_conn
{
    enum class st : uint8_t { resolving, connecting, handshake, greeting, ehlo, helo, starttls, auth, ready, transaction,
                              body, dot, rset, quit };
    uint64_t id{0};
    std::string route;
    int fd{-1};
    uint64_t gen{0};
    SSL* ssl{nullptr};
    bool handshaken{false};
    bool after_starttls{false};
    bool verified{false};
    st state{st::resolving};
    // Where it connects: each exchanger in turn, and each address of the one being tried.
    size_t host_at{0};
    std::string host;
    std::vector<endpoint> addrs;
    size_t addr_at{0};
    bool resolved{false};
    // What the other side said it does.
    bool pipelining{false}, starttls{false}, eightbit{false}, utf8{false}, auth_plain{false}, auth_login{false},
        chunking{false}, dsn{false}, requiretls{false};
    // Where AUTH LOGIN is: the username sent, then the password.
    uint8_t login_step{0};
    uint64_t size_max{0};
    // The recipients it takes in one transaction, as its LIMITS said (RFC 9422); 0 where it said none.
    uint32_t rcpt_max{0};
    std::string in;
    int reply_code{0};
    std::string reply_text;
    // What goes out, each piece held by the write in flight too, so a connection closed under it frees nothing.
    std::deque<std::shared_ptr<const std::string>> outq;
    size_t out_off{0};
    bool writing{false};
    // The message it carries, the commands not yet sent where there is no pipelining, and what each reply answers.
    std::unique_ptr<item> cur;
    std::deque<std::string> unsent;
    std::deque<char> expect;
    std::vector<int> rcpt_code;
    std::vector<std::string> rcpt_text;
    size_t rcpt_seen{0};
    uint32_t rcpt_ok{0};
    int mail_code{0};
    std::string mail_text;
    uint64_t body_off{0};
    bool bol{true};
    bool reading{false};
    bool signature_sent{false};
    // The exchanger's TLSA records, asked for the host at `tlsa_for`: DANE applies where there are any, and they
    // authenticate where one is usable; and what the domain's MTA-STS policy asks.
    size_t tlsa_for{SIZE_MAX};
    bool dane{false};
    std::vector<tls_policy::tlsa> tlsa;
    tls_policy::sts_mode sts{tls_policy::sts_mode::none};
    // The body goes in BDAT chunks: those whose answer is still to come, whether the last went, and what refused one.
    bool bdat{false};
    uint32_t bdat_out{0};
    bool bdat_last{false};
    int bdat_code{0};
    std::string bdat_text;
    int64_t deadline_ms{0};
    int64_t idle_ms{0};
    std::string last_error;
};

delivery::delivery(mail_run& run)
    : m_run(run), m_loop(run.loop()), m_io(run.loop(), this), m_alive(std::make_shared<bool>(true))
{
}

delivery::~delivery()
{
    *m_alive = false;
    for (auto& [id, c] : m_conns)
    {
        if (c->ssl)
            tls_context::free_ssl(c->ssl);
        if (c->fd >= 0)
            ::close(c->fd);
    }
    m_loop.deregister_owner(this);
}

bool delivery::start(std::string& why)
{
    m_loop.register_owner(this);
    mail_instance& o = m_run.owner();
    m_selector = std::string(o.get_dkim_selector());
    m_mx_port = settings::number<uint16_t>("SOCKETLEY_MAIL_MX_PORT").value_or(25);
    m_tls = std::make_unique<tls_context>();
    const char* ca = settings::text("SOCKETLEY_MAIL_TLS_CA");
    if (!m_tls->init_client(ca ? std::string_view(ca) : std::string_view{}))
        m_tls.reset();
    // DANE checks a certificate against TLSA records rather than a CA, which the context must be readied for.
    m_dane = m_tls && SSL_CTX_dane_enable(m_tls->native()) > 0;
    m_sts_path = m_run.state_dir() + "/mta-sts";
    {
        std::string text;
        if (socketley::read_file(m_sts_path, text))
        {
            std::string_view rest = text;
            while (!rest.empty())
            {
                const size_t nl = rest.find('\n');
                std::string domain;
                tls_policy::sts p;
                if (tls_policy::from_cache_line(rest.substr(0, nl), domain, p))
                    m_sts[domain] = std::move(p);
                rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
            }
        }
    }
    if (const std::string_view url = o.get_relay(); !url.empty())
    {
        std::string_view rest = url;
        if (rest.starts_with("smtps://"))
        {
            m_relay_tls = true;
            rest.remove_prefix(8);
            m_relay_port = 465;
        }
        else if (rest.starts_with("smtp://"))
        {
            rest.remove_prefix(7);
            m_relay_port = 587;
        }
        else
        {
            why = "--relay must be smtp:// or smtps://, not " + std::string(url);
            return false;
        }
        // Credentials end at the last '@' before the host, and are percent-decoded as a URL's userinfo is.
        const auto decoded = [](std::string_view v) {
            std::string out;
            for (size_t i = 0; i < v.size(); ++i)
            {
                const auto hex = [](char ch) { return std::isxdigit(static_cast<unsigned char>(ch)) != 0; };
                if (v[i] == '%' && i + 2 < v.size() && hex(v[i + 1]) && hex(v[i + 2]))
                {
                    out += static_cast<char>(std::stoi(std::string(v.substr(i + 1, 2)), nullptr, 16));
                    i += 2;
                }
                else
                    out += v[i];
            }
            return out;
        };
        if (const size_t at = rest.rfind('@'); at != std::string_view::npos)
        {
            const std::string_view cred = rest.substr(0, at);
            const size_t colon = cred.find(':');
            m_relay_user = decoded(cred.substr(0, colon));
            m_relay_pass = colon == std::string_view::npos ? std::string() : decoded(cred.substr(colon + 1));
            rest = rest.substr(at + 1);
        }
        if (const size_t slash = rest.find('/'); slash != std::string_view::npos)
            rest = rest.substr(0, slash);
        if (const size_t colon = rest.rfind(':'); colon != std::string_view::npos && rest.front() != '[')
        {
            const std::string_view port = rest.substr(colon + 1);
            unsigned value = 0;
            const auto r = std::from_chars(port.data(), port.data() + port.size(), value);
            m_relay_port = r.ec == std::errc() && r.ptr == port.data() + port.size() && value <= 65535
                               ? static_cast<uint16_t>(value) : 0;
            rest = rest.substr(0, colon);
        }
        m_relay_host = std::string(rest);
        if (m_relay_host.empty() || m_relay_port == 0)
        {
            why = "--relay names no host and port: " + std::string(url);
            return false;
        }
        m_relay = true;
    }
    // A key of the runtime's own, made at its first start and shared by its shards, signs the mail its domains send;
    // an Ed25519 one under <selector>-ed signs it too, and --dkim-next's pair is made to be published first.
    m_key = dkim::load_or_make(mail_key_path(o.get_name(), m_selector), why);
    m_ed_key = m_key ? dkim::load_or_make(mail_key_path(o.get_name(), m_selector + "-ed"), why, true) : nullptr;
    if (!m_key || !m_ed_key)
        return false;
    m_next_selector = std::string(o.get_dkim_next());
    if (!m_next_selector.empty() && m_next_selector != m_selector)
    {
        m_next_key = dkim::load_or_make(mail_key_path(o.get_name(), m_next_selector), why);
        m_next_ed_key = m_next_key ? dkim::load_or_make(mail_key_path(o.get_name(), m_next_selector + "-ed"), why, true)
                                   : nullptr;
        if (!m_next_key || !m_next_ed_key)
            return false;
    }
    const int64_t now = wall::now_ms_coarse();
    for (const auto& [id, e] : m_run.queue().entries())
        schedule(e, std::max(now, e->next_ms));
    return true;
}

void delivery::stop()
{
    m_stopped = true;
    std::vector<uint64_t> ids;
    for (auto& [id, c] : m_conns)
        ids.push_back(id);
    for (const uint64_t id : ids)
        if (const auto it = m_conns.find(id); it != m_conns.end())
            conn_close(*it->second);
}

bool delivery::drained() const
{
    return m_loop.owner_drained(this);
}

void delivery::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (req && file_io::owns_type(req->type))
        m_io.on_cqe(cqe);
}

void delivery::schedule(const entry_ptr& e, int64_t at)
{
    if (const auto it = m_due_at.find(e->id); it != m_due_at.end())
        m_due.erase(it->second);
    m_due_at[e->id] = m_due.emplace(at, e->id);
}

void delivery::queued(const entry_ptr& e)
{
    if (!m_stopped)
        dispatch(e);
}

void delivery::flush(std::string_view id)
{
    const int64_t now = wall::now_ms_coarse();
    for (const auto& [k, e] : m_run.queue().entries())
        if (id.empty() || k == id)
            schedule(e, now);
    tick(now);
}

void delivery::forget(const std::string& id)
{
    if (const auto it = m_due_at.find(id); it != m_due_at.end())
    {
        m_due.erase(it->second);
        m_due_at.erase(it);
    }
    m_signed.erase(id);
    m_pending_targets.erase(id);
    m_target_count.erase(id);
}

void delivery::on_loop_turn()
{
    // Only the routes the global limit held back are tried again, once a connection is free.
    if (m_stopped || m_starved.empty() || m_conns.size() >= all_routes)
        return;
    std::vector<std::string> keys;
    keys.reserve(m_starved.size());
    for (const auto& [key, _] : m_starved)
        keys.push_back(key);
    m_starved.clear();
    for (const auto& k : keys)
        if (const auto it = m_routes.find(k); it != m_routes.end())
            pump(it->second);
}

void delivery::tick(int64_t now)
{
    if (m_stopped)
        return;
    while (!m_due.empty() && m_due.begin()->first <= now)
    {
        const std::string id = m_due.begin()->second;
        m_due.erase(m_due.begin());
        m_due_at.erase(id);
        if (const entry_ptr e = m_run.queue().find(id))
            dispatch(e);
    }
    for (auto it = m_held.begin(); it != m_held.end();)
    {
        const auto r = m_routes.find(*it);
        if (r != m_routes.end() && now < r->second.held_until)
        {
            ++it;
            continue;
        }
        it = m_held.erase(it);
        if (r != m_routes.end())
            pump(r->second);
    }
    std::vector<uint64_t> late, idle;
    for (auto& [id, c] : m_conns)
    {
        if (c->state == out_conn::st::ready && now - c->idle_ms > idle_close_ms)
            idle.push_back(id);
        else if (c->deadline_ms && now > c->deadline_ms && c->state != out_conn::st::resolving)
            late.push_back(id);
    }
    for (const uint64_t id : idle)
        if (const auto it = m_conns.find(id); it != m_conns.end())
        {
            it->second->state = out_conn::st::quit;
            it->second->expect.push_back('Q');
            it->second->deadline_ms = now + 10000;
            conn_send(*it->second, "QUIT\r\n");
        }
    for (const uint64_t id : late)
        if (const auto it = m_conns.find(id); it != m_conns.end())
        {
            out_conn& c = *it->second;
            if (c.state == out_conn::st::quit)
                conn_close(c);
            else
                conn_fail(c, "451 4.4.2 no answer from " + c.host + " in time", early_move(c));
        }
}

// ── What goes where ─────────────────────────────────────────────────────────

void delivery::dispatch(const entry_ptr& e)
{
    if (m_out[e->id] > 0)
        return;
    std::map<std::string, item> by_route;
    std::vector<uint32_t>& pending = m_pending_targets[e->id];
    pending.assign(e->rcpts.size(), 0);
    std::vector<uint32_t>& counts = m_target_count[e->id];
    counts.assign(e->rcpts.size(), 1);
    std::vector<target> local;
    for (size_t i = 0; i < e->rcpts.size(); ++i)
    {
        if (e->rcpts[i].state != rcpt_state::waiting)
            continue;
        address a;
        if (!parse_address(e->rcpts[i].addr, a) && !parse_path("<" + e->rcpts[i].addr + ">", a, false, true))
        {
            m_run.queue().mark(*e, i, rcpt_state::failed, "553 5.1.3 the address cannot be read");
            continue;
        }
        std::vector<std::string> targets;
        if (m_run.is_local_domain(a.domain) || a.domain.empty())
        {
            const route_to r = m_run.route(a, e->from.empty());
            if (r.k == route_to::none)
            {
                // A recipient the script took is the script's: on_message had the message.
                if (m_run.script_takes())
                    m_run.queue().mark(*e, i, rcpt_state::delivered, "taken by the script");
                else
                    m_run.queue().mark(*e, i, rcpt_state::failed, "550 5.1.1 no such user here");
                continue;
            }
            if (r.k == route_to::sink)
            {
                // A bounce to no-reply@: whom it says failed is not mailed again.
                const uint32_t want = static_cast<uint32_t>(std::min<uint64_t>(e->body_len, 256u << 10));
                const bool own = e->bounce && e->peer == "local";
                m_run.queue().read(e, 0, want, [this, to = e->rcpts[i].addr, own, alive = m_alive](bool ok,
                                                                                                   std::string_view b) {
                    if (*alive && ok)
                        m_run.bounce_taken(b, to, own);
                });
                m_run.queue().mark(*e, i, rcpt_state::delivered, "taken as a bounce");
                continue;
            }
            const std::string dom = a.domain.empty() ? (m_run.domains().empty() ? "" : m_run.domains().front())
                                                     : a.domain;
            // An alias's targets in one of this runtime's domains are followed here, a few aliases deep, to the
            // mailboxes they name, rather than sent out to come back.
            const auto expand = [&](const auto& self, const std::string& t, int depth) -> void {
                address ta;
                if (t.find('@') != std::string::npos && parse_address(t, ta) && m_run.is_local_domain(ta.domain))
                {
                    if (const auto* more = m_run.aliases().find(ta.local, ta.domain); more && depth < 8)
                    {
                        for (const auto& x : *more)
                            self(self, x, depth + 1);
                        return;
                    }
                    if (const route_to rt = m_run.route(ta, e->from.empty()); rt.k == route_to::mailbox)
                    {
                        if (std::find(targets.begin(), targets.end(), rt.target) == targets.end())
                            targets.push_back(rt.target);
                        return;
                    }
                }
                if (std::find(targets.begin(), targets.end(), t) == targets.end())
                    targets.push_back(t);
            };
            if (const auto* t = m_run.aliases().find(a.local, dom))
                for (const auto& x : *t)
                    expand(expand, x, 1);
            else
                targets.push_back(r.target);
        }
        else
            targets.push_back(a.text());
        counts[i] = static_cast<uint32_t>(targets.size());
        const spool_rcpt& rc = e->rcpts[i];
        const auto over = [&rc](const std::string& t) {
            if (std::find(rc.targets_done.begin(), rc.targets_done.end(), t) != rc.targets_done.end())
                return true;
            for (const auto& f : rc.targets_failed)
                if (f.size() > t.size() && f.starts_with(t) && f.compare(t.size(), 2, ": ") == 0)
                    return true;
            return false;
        };
        for (const auto& t : targets)
        {
            // A target an earlier try took, or refused for good, is not sent to again.
            if (targets.size() > 1 && over(t))
                continue;
            if (address ta; t.find('@') != std::string::npos && parse_address(t, ta) && m_run.is_local_domain(ta.domain))
            {
                // An address of this runtime that is no mailbox, or an alias loop: no one here, and not sent out.
                const std::string why = "550 5.1.1 " + t + " is no mailbox here";
                if (targets.size() > 1)
                    m_run.queue().target_over(*e, i, t, false, why);
                else
                    m_run.queue().mark(*e, i, rcpt_state::failed, why);
                continue;
            }
            if (t.find('@') != std::string::npos && m_run.suppressed(t))
            {
                const std::string why = "550 5.1.1 " + t + " bounced before and is not sent to again; `socketley mail " +
                                        std::string(m_run.owner().get_name()) + " forgive " + t + "` lets it";
                if (targets.size() > 1)
                    m_run.queue().target_over(*e, i, t, false, why);
                else
                    m_run.queue().mark(*e, i, rcpt_state::failed, why);
                continue;
            }
            ++pending[i];
            if (t.find('@') == std::string::npos)
            {
                local.push_back({i, t});
                continue;
            }
            const std::string key = m_relay ? std::string() : domain_of(t);
            item& it = by_route[key];
            it.e = e;
            it.to.push_back({i, t});
        }
    }
    // A recipient whose every target is over is decided by them now.
    for (size_t i = 0; i < e->rcpts.size(); ++i)
        if (e->rcpts[i].state == rcpt_state::waiting && pending[i] == 0 &&
            (!e->rcpts[i].targets_done.empty() || !e->rcpts[i].targets_failed.empty()))
            targets_settled(*e, i);
    m_out[e->id] = static_cast<uint32_t>(by_route.size() + local.size());
    if (m_out[e->id] == 0)
    {
        attempt_over(e);
        return;
    }
    for (const auto& t : local)
        deliver_local(e, t);
    if (by_route.empty())
        return;
    sign_then(e, [this, e, by_route = std::move(by_route), alive = m_alive](bool ok) mutable {
        if (!*alive || m_stopped)
            return;
        for (auto& [key, it] : by_route)
        {
            if (!ok)
            {
                // A message that could not be read to be signed waits, rather than going out unsigned.
                for (size_t t = 0; t < it.to.size(); ++t)
                    result(it, t, 451, "451 4.3.0 the message could not be read from the spool to be signed", true);
                if (--m_out[it.e->id] == 0)
                    attempt_over(it.e);
                continue;
            }
            route& r = m_routes[key];
            r.key = key;
            r.waiting.push_back(std::move(it));
            pump(r);
        }
    });
}

void delivery::deliver_local(const entry_ptr& e, const target& t)
{
    auto it = std::make_shared<item>();
    it->e = e;
    it->to.push_back(t);
    const auto settle = [this, it](int code, const std::string& text) {
        result(*it, 0, code, text, code / 100 == 4, 1);
        if (--m_out[it->e->id] == 0)
            attempt_over(it->e);
    };
    mailboxes* boxes = m_run.boxes();
    if (!boxes || !boxes->enabled())
    {
        settle(550, "550 5.1.1 the mailbox " + t.addr + " is kept nowhere: this runtime has no --storage");
        return;
    }
    boxes->find(t.addr, [this, it, settle, alive = m_alive](account a, std::string user, std::string email) {
        if (!*alive)
            return;
        if (a == account::unreachable)
        {
            settle(451, "451 4.3.0 the accounts cannot be checked now");
            return;
        }
        if (a == account::no)
        {
            settle(550, "550 5.1.1 no mailbox " + it->to[0].addr + " here");
            return;
        }
        const spool_entry& e = *it->e;
        // A mailbox at its bound takes no more, as Dovecot's default refuses it (RFC 3463 5.2.2).
        if (const uint64_t q = m_run.boxes()->quota_of(user); q && m_run.imap() && m_run.imap()->usage(user) + e.body_len > q)
        {
            ++m_over_quota;
            settle(552, "552 5.2.2 the mailbox of " + it->to[0].addr + " is full");
            return;
        }
        // What a reader of the mailbox is told of the message's way: who it came from, to whom, and what was checked.
        // Delivered-To names the address it came for where that is the user's at one of these domains.
        std::string to = user + (m_run.domains().empty() ? std::string() : "@" + m_run.domains().front());
        if (const size_t ri = it->to[0].rcpt; ri < e.rcpts.size())
            if (address ra; parse_address(e.rcpts[ri].addr, ra) && m_run.is_local_domain(ra.domain) &&
                            socketley::ascii::iequals(ra.local, user))
                to = ra.text();
        std::string head = "Return-Path: <" + e.from + ">\r\nDelivered-To: " + to + "\r\n";
        if (!e.auth.empty())
            head += "Authentication-Results: " + m_run.hostname() + "; " + e.auth + "\r\n";
        // Taken, by a filter or as it is, the message is one a VacationResponse answers.
        const std::string own = email.empty() ? to : email;
        const auto taken = [this, it, user, own, settle](int code, const std::string& text) {
            if (code / 100 == 2)
                jmap_vacation(it->e, user, own);
            settle(code, text);
        };
        const auto plain = [this, it, user, taken, alive](std::string head) {
            m_run.boxes()->deliver(it->e, user, it->e->folder.empty() ? "INBOX" : it->e->folder, std::move(head),
                                   [taken, alive](int code, std::string text) {
                                       if (*alive)
                                           taken(code, text);
                                   });
        };
        // The user's Sieve script decides where it goes, where they have one active; it is looked for off the loop,
        // as a change of it is read and compiled there.
        if (sieve_store* f = m_run.filters())
        {
            auto script = std::make_shared<std::shared_ptr<const sieve::script>>();
            m_run.pool().submit(0, [f, user, script] { *script = f->active(user); },
                                [this, it, user, email, head = std::move(head), script, taken, plain, alive] {
                                    if (!*alive)
                                        return;
                                    if (*script)
                                        filter(it, user, email, head, *script, taken);
                                    else
                                        plain(head);
                                });
            return;
        }
        plain(std::move(head));
    });
}

namespace
{

// imap4flags' system flags as the letters a key carries them by, as Maildir names them.
uint8_t flag_bits(const std::vector<std::string>& flags)
{
    uint8_t out = 0;
    for (const auto& f : flags)
    {
        using socketley::ascii::iequals;
        out |= iequals(f, "\\Seen") ? 1 : iequals(f, "\\Answered") ? 2 : iequals(f, "\\Flagged") ? 4
             : iequals(f, "\\Deleted") ? 8 : iequals(f, "\\Draft") ? 16 : 0;
    }
    return out;
}

// A folder fileinto may name: printable, no step out of the user's mailboxes.
bool folder_ok(std::string_view f)
{
    if (f.empty() || f.size() > 200 || f.front() == '/' || f.back() == '/' || f.find("//") != std::string_view::npos)
        return false;
    for (size_t at = 0; at <= f.size();)
    {
        const size_t slash = std::min(f.find('/', at), f.size());
        const std::string_view part = f.substr(at, slash - at);
        if (part == "." || part == ".." || part.starts_with("."))
            return false;
        at = slash + 1;
    }
    for (const char c : f)
        if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f || c == '\\')
            return false;
    return true;
}

}   // namespace

void delivery::filter(const std::shared_ptr<item>& it, const std::string& user, const std::string& email,
                      std::string head, std::shared_ptr<const sieve::script> script,
                      std::function<void(int, const std::string&)> settle)
{
    const entry_ptr e = it->e;
    const std::string own = email.empty() && !m_run.domains().empty() ? user + "@" + m_run.domains().front() : email;
    auto go = [this, it, user, own, head = std::move(head), script, settle](std::shared_ptr<const std::string> bytes) {
        const entry_ptr e = it->e;
        sieve::context ctx;
        for (const auto& d : m_run.domains())
            ctx.own.push_back(user + "@" + d);
        if (!own.empty())
            ctx.own.push_back(own);
        ctx.now_s = wall::now_ms() / 1000;
        std::tm tm{};
        const time_t now = static_cast<time_t>(ctx.now_s);
        if (::localtime_r(&now, &tm))
            ctx.zone_min = static_cast<int32_t>(tm.tm_gmtoff / 60);
        const std::string to = it->to[0].rcpt < e->rcpts.size() ? e->rcpts[it->to[0].rcpt].addr : own;
        ctx.host = m_run.hostname();
        ctx.domain = m_run.domains().empty() ? std::string() : m_run.domains().front();
        ctx.remote_ip = e->peer;
        // What Rspamd scored it, as this host's checks wrote it, for spamtest (RFC 5235).
        if (const size_t at = e->auth.find("x-spam="); at != std::string::npos)
        {
            spam_verdict v;
            const size_t s = e->auth.find("score=", at), q = e->auth.find("required=", at);
            if (s != std::string::npos && q != std::string::npos)
            {
                v.scored = true;
                v.score = std::strtod(e->auth.c_str() + s + 6, nullptr);
                v.required = std::strtod(e->auth.c_str() + q + 9, nullptr);
                ctx.spam = v.level();
                ctx.spam_percent = v.percent();
            }
        }
        // The folders the index knows, read here on the loop, so the run's question is answered from a copy.
        if (imap_store* imap = m_run.imap())
        {
            const std::vector<std::string> known = imap->folder_names(user);
            auto names = std::make_shared<const std::set<std::string>>(known.begin(), known.end());
            ctx.mailbox_exists = [names](std::string_view f) {
                return socketley::ascii::iequals(f, "INBOX") || names->count(std::string(f)) > 0;
            };
        }
        if (sieve_store* store = m_run.filters())
            ctx.seen = [store, user, now = ctx.now_s](std::string_view key) { return store->seen(user, key, now); };
        auto out = std::make_shared<sieve::outcome>();
        // A run is bounded by its step budget, and spent on a thread rather than the loop.
        m_run.pool().submit(
            m_run.cpu_lane(),
            [script, bytes, out, ctx = std::move(ctx), to, from = e->from] {
                sieve::message m{*bytes, from, to};
                *out = script->run(m, ctx);
            },
            [this, it, user, own, head, bytes, out, settle, alive = m_alive] {
                if (*alive)
                    apply(it, user, own, head, *bytes, *out, settle);
            });
    };
    if (e->body)
    {
        go(e->body);
        return;
    }
    // A message not kept in memory is read whole, as --max-size bounds it, so size and body see all of it.
    const uint32_t want = static_cast<uint32_t>(std::min<uint64_t>(e->body_len, UINT32_MAX));
    m_run.queue().read(e, 0, want, [go, settle, alive = m_alive](bool ok, std::string_view b) {
        if (!*alive)
            return;
        if (!ok)
        {
            settle(451, "451 4.3.0 the message could not be read from the spool");
            return;
        }
        go(std::make_shared<const std::string>(b));
    });
}

void delivery::apply(const std::shared_ptr<item>& it, const std::string& user, const std::string& own,
                     const std::string& head, std::string_view bytes, const sieve::outcome& out,
                     std::function<void(int, const std::string&)> settle)
{
    const entry_ptr e = it->e;
    if (!out.error.empty())
        LOG_WARN(("mail: the Sieve script of " + user + " failed, and the message is kept: " + out.error).c_str());
    struct put_to
    {
        std::string folder;
        uint8_t flags{0};
    };
    std::vector<put_to> puts;
    std::vector<std::string> redirects;
    std::vector<sieve::notification> notes;
    std::optional<sieve::vacation> vac;
    std::string rejected;
    bool reject = false;
    const std::string inbox = e->folder.empty() ? "INBOX" : e->folder;
    // A folder fileinto names without :create is filed into only where it is there (RFC 5490 3.2); the index knows.
    std::set<std::string> there;
    if (imap_store* imap = m_run.imap())
        for (auto& n : imap->folder_names(user))
            there.insert(std::move(n));
    for (const auto& a : out.actions)
    {
        switch (a.k)
        {
            case sieve::action::kind::keep:
            case sieve::action::kind::fileinto:
            {
                std::string folder = a.k == sieve::action::kind::keep ? inbox : a.arg;
                if (!folder_ok(folder))
                    folder = inbox;
                // INBOX is one name whatever its case (RFC 3501 5.1), and the one IMAP lists.
                if (socketley::ascii::iequals(std::string_view(folder).substr(0, 5), "inbox") &&
                    (folder.size() == 5 || folder[5] == '/'))
                    folder.replace(0, 5, "INBOX");
                if (a.k == sieve::action::kind::fileinto && !a.create && m_run.imap() && folder != "INBOX" &&
                    !there.count(folder))
                {
                    LOG_INFO(("mail: " + user + "'s filter files into " + folder +
                              ", which is not there and not :create'd, so into INBOX")
                                 .c_str());
                    folder = inbox;
                }
                // Two actions into one folder are one copy, its flags those of both.
                auto f = std::find_if(puts.begin(), puts.end(), [&](const put_to& p) { return p.folder == folder; });
                if (f == puts.end())
                    puts.push_back({std::move(folder), flag_bits(a.flags)});
                else
                    f->flags |= flag_bits(a.flags);
                break;
            }
            case sieve::action::kind::redirect:
                redirects.push_back(a.arg);
                break;
            case sieve::action::kind::reject:
                reject = true;
                rejected = a.arg;
                break;
            case sieve::action::kind::vacation:
                vac = a.v;
                break;
            case sieve::action::kind::notify:
                if (a.n)
                    notes.push_back(*a.n);
                break;
            case sieve::action::kind::discard:
                break;
        }
    }
    // What duplicate saw is kept once the actions are taken, off the loop.
    if (sieve_store* store = m_run.filters(); store && !out.seen.empty())
        m_run.pool().submit(0, [store, user, seen = out.seen, now = wall::now_ms() / 1000] {
            for (const auto& [key, seconds] : seen)
                store->keep_seen(user, key, seconds, now);
        }, [] {});
    if (reject)
    {
        // A message the user's filter refuses goes back to its sender as a failure (RFC 5429 2.1).
        ++m_sieve_rejected;
        settle(550, "550 5.7.1 refused by the filter of " + own + ": " + rejected.substr(0, 300));
        return;
    }
    const std::string_view headers = header_block(bytes);
    // Whether this sender was answered is asked of the memory off the loop, which may read and write a file.
    if (sieve_store* store = m_run.filters(); vac && !e->bounce && store)
    {
        auto fresh = std::make_shared<bool>(false);
        m_run.pool().submit(0,
                            [store, user, v = *vac, fresh, now = wall::now_ms() / 1000] {
                                *fresh = !store->answered(user, v.handle, v.to, v.seconds, now);
                            },
                            [this, own, v = *vac, fresh, msgid = std::string(header_value(headers, "Message-ID")),
                             alive = m_alive] {
                                if (*alive && *fresh)
                                    vacation(own, v, msgid);
                            });
    }
    for (const auto& n : notes)
        notify(own, n, headers);
    // A message that came back to the user it was sent on from is not sent on again.
    const bool looped = headers.find("Delivered-To: " + own + "\r\n") != std::string_view::npos;
    if (!redirects.empty() && looped)
    {
        LOG_WARN(("mail: a message " + own + "'s filter sent on came back, and is kept rather than sent again").c_str());
        redirects.clear();
        if (puts.empty())
            puts.push_back({inbox, 0});
    }
    // Sent on once the copies kept are in, so a retry of them sends nothing twice and a refusal sends nothing on.
    const std::string edited = out.header ? *out.header : std::string();
    const auto then = [this, e, own, redirects, settle, edited, kept = !puts.empty()](int code, const std::string& text) {
        if (redirects.empty() || code / 100 != 2)
        {
            settle(code, text);
            return;
        }
        redirect(e, own, redirects, edited, [own, settle, kept, code, text](bool ok) {
            if (ok || kept)
            {
                if (!ok)
                    LOG_WARN(("mail: a message " + own + "'s filter sends on could not be read, and is not sent on")
                                 .c_str());
                settle(code, text);
                return;
            }
            settle(451, "451 4.3.0 the message could not be read from the spool to send it on");
        });
    };
    if (puts.empty())
    {
        then(250, "250 2.0.0 " + std::string(redirects.empty() ? "discarded" : "sent on") + " by the filter");
        return;
    }
    // Every copy in, or the first refusal of one: the message is delivered once all of them are.
    auto left = std::make_shared<size_t>(puts.size());
    auto worst = std::make_shared<std::pair<int, std::string>>(250, "250 2.0.0 filed");
    for (const auto& p : puts)
        m_run.boxes()->deliver(e, user, p.folder, head,
                               [left, worst, then, alive = m_alive](int code, std::string text) {
                                   if (!*alive)
                                       return;
                                   if (code / 100 != 2 && worst->first / 100 == 2)
                                       *worst = {code, std::move(text)};
                                   if (--*left == 0)
                                       then(worst->first, worst->second);
                               },
                               p.flags, edited);
}

void delivery::redirect(const entry_ptr& e, const std::string& own, std::vector<std::string> to,
                        const std::string& header, std::function<void(bool)> done)
{
    // Sent from the user's own address, so a bounce comes to them and SPF is this runtime's to pass; with the header
    // editheader left, where it changed it.
    const auto send = [this, own, header, to = std::move(to), done, requiretls = e->requiretls](std::string_view whole) {
        const std::string_view block = header_block(whole);
        const std::string message = header.empty() || block.size() >= whole.size()
                                        ? std::string(whole)
                                        : header + std::string(whole.substr(block.size()));
        for (const auto& t : to)
        {
            ++m_sieve_redirected;
            // What had to go over checked TLS still does, forwarded (RFC 8689 4.3).
            m_run.queue_message(own, {t}, "Delivered-To: " + own + "\r\n" + message, false, {},
                                [](bool, std::string) {}, requiretls);
        }
        done(true);
    };
    if (e->body)
    {
        send(*e->body);
        return;
    }
    m_run.queue().read(e, 0, static_cast<uint32_t>(std::min<uint64_t>(e->body_len, UINT32_MAX)),
                       [send, done, alive = m_alive](bool ok, std::string_view b) {
                           if (!*alive)
                               return;
                           if (ok)
                               send(b);
                           else
                               done(false);
                       });
}

void delivery::jmap_vacation(const entry_ptr& e, const std::string& user, const std::string& own)
{
    imap_store* store = m_run.imap();
    sieve_store* memory = m_run.filters();
    // Spam is answered by nobody, which would tell its sender the address is read.
    if (!store || !memory || e->bounce || e->from.empty() || e->folder == "Junk" ||
        e->auth.find("x-spam=yes") != std::string::npos)
        return;
    const std::string* kept = store->meta(user, {}, std::string(jmap_session::vacation_entry));
    socketley::json::jvalue v;
    if (!kept || !socketley::json::json_reader(*kept).document(v))
        return;
    const auto* on = socketley::json::member(v, "isEnabled");
    if (!on || on->k != socketley::json::jvalue::kind::boolean || !on->b)
        return;
    // Between fromDate and toDate, where they are set (RFC 8621 8).
    const int64_t now_ms = wall::now_ms();
    const auto at = [](std::string_view t) -> int64_t {
        std::tm tm{};
        const std::string s(t);
        return ::strptime(s.c_str(), "%Y-%m-%dT%H:%M:%S", &tm) ? static_cast<int64_t>(::timegm(&tm)) * 1000 : -1;
    };
    if (const std::string_view f = socketley::json::string_of(v, "fromDate"); !f.empty() && at(f) > now_ms)
        return;
    if (const std::string_view t = socketley::json::string_of(v, "toDate"); !t.empty() && at(t) >= 0 && at(t) <= now_ms)
        return;
    // Nothing that answers by itself, comes from a list or is a bounce is answered (RFC 3834 2).
    const auto answer = [this, user, own, v, from = e->from, alive = m_alive](std::string_view whole) {
        if (!*alive)
            return;
        const std::string_view head = header_block(whole);
        const std::string auto_sub = header_value(head, "Auto-Submitted");
        std::string precedence = header_value(head, "Precedence");
        socketley::ascii::lower_in_place(precedence);
        std::string local = from.substr(0, from.find('@'));
        socketley::ascii::lower_in_place(local);
        if ((!auto_sub.empty() && !socketley::ascii::iequals(auto_sub, "no")) || precedence == "bulk" ||
            precedence == "list" || precedence == "junk" || !header_value(head, "List-Id").empty() ||
            local == "mailer-daemon" || local.starts_with("owner-") || local.ends_with("-request") ||
            socketley::ascii::iequals(from, own))
            return;
        sieve::vacation r;
        r.handle = "jmap";
        r.seconds = 7 * 86400;
        r.to = from;
        r.from = own;
        const std::string_view subject = socketley::json::string_of(v, "subject");
        r.subject = subject.empty() ? "Re: " + mime::decode_words(header_value(head, "Subject")) : std::string(subject);
        r.reason = std::string(socketley::json::string_of(v, "textBody"));
        if (r.reason.empty())
            r.reason = std::string(socketley::json::string_of(v, "htmlBody"));
        if (r.reason.empty())
            return;
        sieve_store* memory = m_run.filters();
        auto fresh = std::make_shared<bool>(false);
        m_run.pool().submit(0,
                            [memory, user, r, fresh, now = wall::now_ms() / 1000] {
                                *fresh = !memory->answered(user, r.handle, r.to, r.seconds, now);
                            },
                            [this, own, r, fresh, msgid = header_value(head, "Message-ID"), alive = m_alive] {
                                if (*alive && *fresh)
                                    vacation(own, r, msgid);
                            });
    };
    if (e->body)
    {
        answer(*e->body);
        return;
    }
    const uint32_t want = static_cast<uint32_t>(std::min<uint64_t>(e->body_len, 64u << 10));
    m_run.queue().read(e, 0, want, [answer](bool ok, std::string_view b) {
        if (ok)
            answer(b);
    });
}

void delivery::vacation(const std::string& own, const sieve::vacation& v, std::string_view msgid)
{
    const std::string from = v.from.empty() ? own : v.from;
    std::string msg = "From: " + from + "\r\nTo: " + v.to + "\r\nSubject: " + encode_header_value("Subject", v.subject) +
                      "\r\nDate: " + rfc5322_date(wall::now_ms()) +
                      "\r\nMessage-ID: <" + socketley::random_hex(12) + "@" + m_run.hostname() + ">\r\n";
    if (!msgid.empty())
        msg += "In-Reply-To: " + std::string(msgid) + "\r\nReferences: " + std::string(msgid) + "\r\n";
    msg += "Auto-Submitted: auto-replied (vacation)\r\nMIME-Version: 1.0\r\n";
    if (v.mime)
        msg += crlf_lines(v.reason);
    else
        msg += "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" +
               quoted_printable(v.reason);
    ++m_sieve_vacations;
    // From the null sender, so nothing answers it in turn (RFC 5230 5.1).
    m_run.queue_message("", {v.to}, std::move(msg), true, {}, [](bool, std::string) {});
}

void delivery::notify(const std::string& own, const sieve::notification& n, std::string_view headers)
{
    std::vector<std::string> to;
    std::string subject, body;
    if (!sieve::parse_mailto(n.method, to, subject, body))
        return;
    // The subject the URI names, or the script's message, or what the mail said (RFC 5436 2.7).
    const std::string about = std::string(header_value(headers, "Subject")).substr(0, 200);
    const std::string from = std::string(header_value(headers, "From")).substr(0, 200);
    if (subject.empty())
        subject = !n.message.empty() ? n.message : "[SIEVE] New mail" + (about.empty() ? "" : ": " + about);
    if (body.empty())
        body = (n.message.empty() ? "New mail" : n.message) + "\nFrom: " + from + "\nSubject: " + about + "\n";
    std::string msg = "From: " + (n.from.empty() ? own : n.from) + "\r\nTo: ";
    for (size_t i = 0; i < to.size(); ++i)
        msg += (i ? ", " : "") + to[i];
    msg += "\r\nSubject: " + encode_header_value("Subject", subject) + "\r\nDate: " + rfc5322_date(wall::now_ms()) +
           "\r\nMessage-ID: <" + socketley::random_hex(12) + "@" + m_run.hostname() + ">\r\n" +
           "Auto-Submitted: auto-notified\r\nImportance: " +
           (n.importance == "1" ? "high" : n.importance == "3" ? "low" : "normal") +
           "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n"
           "Content-Transfer-Encoding: quoted-printable\r\n\r\n" +
           quoted_printable(body);
    ++m_sieve_notified;
    // From the null sender, so nothing answers it in turn and a failed one makes no bounce.
    m_run.queue_message("", to, std::move(msg), true, {}, [](bool, std::string) {});
}

void delivery::tls_told(const out_conn& c, bool success, const char* failure)
{
    // Told only of a domain whose policy asked for TLS, the sessions RFC 8460 counts.
    if (!m_run.owner().get_reports() || m_relay || (!c.dane && c.sts == tls_policy::sts_mode::none))
        return;
    std::vector<std::string> lines;
    std::string type = "tlsa";
    if (!c.dane)
    {
        type = "sts";
        if (const tls_policy::sts* p = sts_for(c.route))
        {
            lines.push_back("version: STSv1");
            lines.push_back(std::string("mode: ") + (p->mode == tls_policy::sts_mode::enforce ? "enforce" : "testing"));
            for (const auto& m : p->mx)
                lines.push_back("mx: " + m);
        }
    }
    m_run.report_book().tls(c.route, type, lines, c.host, success, failure, "", "");
}

void delivery::fail_waiting(route& r, int code, const std::string& text, bool temporary)
{
    while (!r.waiting.empty())
    {
        item it = std::move(r.waiting.front());
        r.waiting.pop_front();
        for (size_t t = 0; t < it.to.size(); ++t)
            result(it, t, code, text, temporary);
        if (--m_out[it.e->id] == 0)
            attempt_over(it.e);
    }
}

void delivery::pump(route& r)
{
    if (m_stopped || r.waiting.empty())
        return;
    const int64_t now = wall::now_ms_coarse();
    // A domain found dead is asked again after ten minutes, a live one's exchangers after an hour.
    static const int64_t dead_ms = settings::number<int64_t>("SOCKETLEY_MAIL_DEAD_DOMAIN_MS").value_or(600000);
    if (!r.looked || now - r.looked_ms > (r.dead.empty() ? lookup_ms : dead_ms))
    {
        // Live exchangers serve while they are asked again; a dead answer does not.
        if (!r.dead.empty())
            r.looked = false;
        if (!r.looking)
            lookup(r);
        if (!r.looked)
            return;
    }
    if (!r.dead.empty())
    {
        fail_waiting(r, std::atoi(r.dead.c_str()), r.dead, false);
        return;
    }
    if (!m_relay)
    {
        if (r.sts_state == 2 && now - r.sts_ms > lookup_ms)
            r.sts_state = 0;
        // A policy's record asked or its fetch out is waited for, never asked again meanwhile.
        if (r.sts_state == 0)
            sts_check(r);
        if (r.sts_state != 2)
            return;
        // Under an enforced policy only the exchangers it names are tried, and with none of them nothing is sent.
        if (const tls_policy::sts* p = sts_for(r.key); p && p->mode == tls_policy::sts_mode::enforce)
        {
            if (!r.sts_filtered)
            {
                r.sts_filtered = true;
                std::erase_if(r.hosts, [p](const std::string& h) { return !tls_policy::mx_matches(*p, h); });
            }
            if (r.hosts.empty())
            {
                fail_waiting(r, 451, "451 4.7.0 no exchanger of " + r.key + " is one its MTA-STS policy names", true);
                return;
            }
        }
    }
    if (now < r.held_until)
    {
        m_held.insert(r.key);
        return;
    }
    // A connection that waits for work takes the next message first.
    std::vector<uint64_t> idle;
    for (auto& [id, c] : m_conns)
        if (c->route == r.key && c->state == out_conn::st::ready)
            idle.push_back(id);
    for (const uint64_t id : idle)
        if (const auto it = m_conns.find(id); it != m_conns.end() && !r.waiting.empty())
            conn_next(*it->second);
    // As many connections as messages wait, up to the route's limit and the runtime's.
    while (!r.waiting.empty() && r.active < r.limit && r.active < r.waiting.size())
    {
        if (m_conns.size() >= all_routes)
        {
            m_starved[r.key] = true;
            return;
        }
        open_conn(r);
    }
}

void delivery::lookup(route& r)
{
    if (m_relay)
    {
        r.hosts = {m_relay_host};
        r.looked = true;
        r.looked_ms = wall::now_ms_coarse();
        return;
    }
    std::vector<dns_client::record> recs;
    bool nx = false, secure = false;
    const dns_client::state st = dns_client::here().ask_records(r.key, dns::type::MX, recs, nx, &secure);
    r.mx_secure = st == dns_client::state::ready && secure;
    r.sts_filtered = false;
    if (st == dns_client::state::pending)
    {
        r.looking = true;
        poll_lookups(&r.key);
        return;
    }
    const auto take = [this](route& rt, std::vector<dns_client::record> rs, bool no_domain) {
        rt.looking = false;
        rt.looked = true;
        rt.looked_ms = wall::now_ms_coarse();
        ++m_lookups;
        rt.hosts.clear();
        rt.dead.clear();
        if (no_domain)
        {
            rt.dead = "550 5.1.2 the domain " + rt.key + " does not exist";
            return;
        }
        if (rs.empty())
        {
            // No MX: the domain's own address is its exchanger (RFC 5321 5.1).
            rt.hosts.push_back(rt.key);
            return;
        }
        // Exchangers of one preference are tried in an order of chance, so the load spreads (RFC 5321 5.1).
        static thread_local std::minstd_rand rng(static_cast<uint32_t>(wall::now_ms() ^ ::getpid()));
        std::shuffle(rs.begin(), rs.end(), rng);
        std::stable_sort(rs.begin(), rs.end(), [](const auto& a, const auto& b) { return a.pref < b.pref; });
        if (rs.size() == 1 && (rs[0].text.empty() || rs[0].text == "."))
        {
            rt.dead = "556 5.1.10 the domain " + rt.key + " says it takes no mail";
            return;
        }
        for (auto& x : rs)
        {
            std::string h = x.text;
            if (!h.empty() && h.back() == '.')
                h.pop_back();
            rt.hosts.push_back(std::move(h));
        }
    };
    if (st == dns_client::state::ready)
    {
        take(r, std::move(recs), nx);
        return;
    }
    // What the loop's resolver cannot say, the system's resolver asks on a thread.
    r.looking = true;
    auto out = std::make_shared<std::vector<dns_client::record>>();
    auto no = std::make_shared<bool>(false);
    auto ok = std::make_shared<bool>(false);
    const std::string key = r.key;
    m_run.pool().submit(0,
                        [key, out, no, ok] {
                            // The system's resolver, at the nameservers a test points the loop's at too.
                            uint8_t buf[8192];
                            bool nx = false, answered = false;
                            const int n = system_query(key, T_MX, buf, sizeof buf, nx, answered);
                            if (n < 0)
                            {
                                *no = nx;
                                *ok = answered;
                                return;
                            }
                            *ok = parse_answer(buf, static_cast<size_t>(n), dns::type::MX, *out, *no);
                        },
                        [this, key, out, no, ok, take, alive = m_alive] {
                            if (!*alive)
                                return;
                            route& rt = m_routes[key];
                            if (!*ok)
                            {
                                // An answer that did not come is no answer that there is no MX: the mail waits.
                                rt.looking = false;
                                rt.looked = false;
                                fail_waiting(rt, 451, "451 4.4.3 the exchangers of " + key + " could not be looked up",
                                             true);
                                return;
                            }
                            take(rt, std::move(*out), *no);
                            pump(rt);
                        });
}

void delivery::sts_check(route& r)
{
    r.sts_state = 1;
    std::vector<dns_client::record> recs;
    bool nx = false;
    const dns_client::state st = dns_client::here().ask_records("_mta-sts." + r.key, dns::type::TXT, recs, nx);
    if (st == dns_client::state::pending)
    {
        poll_lookups(&r.key);
        return;
    }
    if (st == dns_client::state::unsure)
    {
        // A record that could not be read says nothing: a cached policy still counts, and it is asked again soon.
        r.sts_state = 2;
        r.sts_ms = wall::now_ms_coarse() - lookup_ms + 300000;
        return;
    }
    // One record says the policy's id; none or two say there is none to fetch, and a cached one still counts.
    std::string id;
    int found = 0;
    for (const auto& rec : recs)
    {
        std::string i;
        if (tls_policy::sts_record_id(rec.text, i))
        {
            id = std::move(i);
            ++found;
        }
    }
    const auto it = m_sts.find(r.key);
    const bool cached = it != m_sts.end() && it->second.expires_s > wall::now_ms() / 1000;
    if (found != 1 || (cached && it->second.id == id))
    {
        r.sts_state = 2;
        r.sts_ms = wall::now_ms_coarse();
        return;
    }
    r.sts_state = 3;
    sts_fetch(r.key, id);
}

void delivery::sts_fetch(const std::string& domain, const std::string& id)
{
    struct fetched
    {
        bool ok{false};
        tls_policy::sts p;
        int64_t max_age{0};
        std::string why;
    };
    auto out = std::make_shared<fetched>();
    const char* ca = settings::text("SOCKETLEY_MAIL_STS_CA");
    const char* to = settings::text("SOCKETLEY_MAIL_STS_CONNECT");
    m_run.pool().submit(
        0,
        [domain, out, ca = std::string(ca ? ca : ""), to = std::string(to ? to : "")] {
            // The policy is fetched over HTTPS with a certificate for mta-sts.<domain>, and no redirect is followed.
            https_client::client cl;
            if (!cl.init(out->why, ca))
                return;
            if (!to.empty())
                cl.connect_to(to);
            // The name is the recipient domain's to point anywhere, so it is dialled only where it is public.
            cl.public_only(true);
            https_client::reply rep;
            if (!cl.request("GET", "https://mta-sts." + domain + "/.well-known/mta-sts.txt", {}, {}, rep, out->why, 10,
                            65536))
                return;
            if (rep.status != 200)
            {
                out->why = "the policy was answered " + std::to_string(rep.status);
                return;
            }
            if (!lower(rep.header("content-type")).starts_with("text/plain"))
            {
                out->why = "the policy is not text/plain";
                return;
            }
            if (rep.body.size() > 65536)
            {
                out->why = "the policy is larger than 64 KiB";
                return;
            }
            out->ok = tls_policy::parse_sts(rep.body, out->p, out->max_age, out->why);
        },
        [this, domain, id, out, alive = m_alive] {
            if (!*alive)
                return;
            ++m_sts_fetched;
            if (out->ok)
            {
                out->p.id = id;
                out->p.expires_s = wall::now_ms() / 1000 + out->max_age;
                m_sts[domain] = std::move(out->p);
                sts_save();
            }
            else
            {
                LOG_WARN(("mail: the MTA-STS policy of " + domain + " could not be fetched: " + out->why +
                          (m_sts.count(domain) ? "; the one fetched before counts until it expires" : ""))
                             .c_str());
                if (m_run.owner().get_reports())
                    m_run.report_book().tls(domain, "sts", {}, "", false, "sts-policy-fetch-error", "", "");
            }
            route& r = m_routes[domain];
            r.sts_state = 2;
            r.sts_ms = wall::now_ms_coarse();
            // The exchangers looked up again, so a new policy is applied to the whole list.
            r.looked = false;
            r.sts_filtered = false;
            pump(r);
        });
}

const tls_policy::sts* delivery::sts_for(const std::string& domain) const
{
    const auto it = m_sts.find(domain);
    if (it == m_sts.end() || it->second.mode == tls_policy::sts_mode::none ||
        it->second.expires_s <= wall::now_ms() / 1000)
        return nullptr;
    return &it->second;
}

void delivery::sts_save()
{
    std::string text;
    for (const auto& [domain, p] : m_sts)
        if (p.expires_s > wall::now_ms() / 1000)
            text += tls_policy::cache_line(domain, p);
    // A cache: written whole and moved into place, and a crash loses at most the last fetch.
    const std::string tmp = m_sts_path + ".tmp";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    const bool ok = fd >= 0 && socketley::write_all(fd, text.data(), text.size());
    if (fd >= 0)
        ::close(fd);
    if (!ok || ::rename(tmp.c_str(), m_sts_path.c_str()) != 0)
        ::unlink(tmp.c_str());
}

void delivery::poll_lookups(const std::string* key, uint64_t conn)
{
    // A lookup newly out is looked at again soon; one asked again because its answer has not come waits longer.
    if (key && m_wait_routes.insert(*key).second)
        m_poll_ms = 2;
    if (conn && m_wait_conns.insert(conn).second)
        m_poll_ms = 2;
    if (m_polling || (m_wait_routes.empty() && m_wait_conns.empty()))
        return;
    m_polling = m_io.after(std::chrono::milliseconds(m_poll_ms), [this, alive = m_alive](int64_t) {
        if (!*alive)
            return;
        // Held while the lookups are asked again, so each one still out does not set a timer of its own.
        bool answered = false;
        const std::vector<std::string> routes(m_wait_routes.begin(), m_wait_routes.end());
        for (const auto& key : routes)
        {
            const auto it = m_routes.find(key);
            route* r = it == m_routes.end() ? nullptr : &it->second;
            // Off the list before the route is pumped, which may put it back for its MTA-STS lookup.
            if (r && r->looking && !m_relay)
            {
                r->looked = false;
                lookup(*r);
                if (!r->looked)
                    continue;
                m_wait_routes.erase(key);
                pump(*r);
            }
            else if (r && r->sts_state == 1)
            {
                sts_check(*r);
                if (r->sts_state == 1)
                    continue;
                m_wait_routes.erase(key);
                pump(*r);
            }
            else
                m_wait_routes.erase(key);
            answered = true;
        }
        const std::vector<uint64_t> ids(m_wait_conns.begin(), m_wait_conns.end());
        for (const uint64_t id : ids)
        {
            const auto it = m_conns.find(id);
            if (it != m_conns.end() && it->second->state == out_conn::st::resolving)
            {
                conn_connect(*it->second);
                // conn_connect may have closed it.
                if (const auto again = m_conns.find(id); again != m_conns.end() && again->second->state == out_conn::st::resolving)
                    continue;
            }
            m_wait_conns.erase(id);
            answered = true;
        }
        m_poll_ms = answered ? 2 : std::min<int64_t>(m_poll_ms * 2, 32);
        m_polling = false;
        poll_lookups();
    });
}

void delivery::sign_then(const entry_ptr& e, std::function<void(bool)> go)
{
    if (!m_key || m_signed.count(e->id) || e->body_len > m_run.owner().get_max_size() + (1u << 20))
    {
        go(true);
        return;
    }
    auto& waiting = m_signing[e->id];
    waiting.push_back(std::move(go));
    if (waiting.size() > 1)
        return;
    auto j = std::make_shared<sign_job>();
    j->e = e;
    // A message held in memory is signed at once, as its bytes cost nothing more; only one read back waits its turn.
    if (e->body)
    {
        ++m_signs_out;
        ++m_signs_held;
        j->kept = e->body;
        j->in_memory = true;
        sign_read(j);
        return;
    }
    m_signs_waiting.push_back(std::move(j));
    sign_next();
}

void delivery::sign_next()
{
    // A queue read back at a start is signed a few messages at a time, not every one read into memory at once.
    while (m_signs_out - m_signs_held < 8 && !m_signs_waiting.empty())
    {
        auto j = std::move(m_signs_waiting.front());
        m_signs_waiting.pop_front();
        ++m_signs_out;
        if (j->e->body)
            j->kept = j->e->body;
        else
            j->data.reserve(j->e->body_len);
        sign_read(j);
    }
}

void delivery::sign_read(const std::shared_ptr<sign_job>& j)
{
    // The message whole, from memory as it is or read back a piece at a time, each piece at once or later.
    j->looping = true;
    while (!j->kept && !j->failed && j->data.size() < j->e->body_len)
    {
        j->waiting = true;
        m_run.queue().read(j->e, j->data.size(), body_chunk, [this, j, alive = m_alive](bool ok, std::string_view b) {
            if (!*alive)
                return;
            if (!ok || b.empty())
                j->failed = true;
            else
                j->data.append(b);
            j->waiting = false;
            if (!j->looping)
                sign_read(j);
        });
        if (j->waiting)
        {
            j->looping = false;
            return;
        }
    }
    j->looping = false;
    const std::string id = j->e->id;
    const auto done = [this, id, in_memory = j->in_memory](bool ok) {
        --m_signs_out;
        if (in_memory)
            --m_signs_held;
        auto gos = std::move(m_signing[id]);
        m_signing.erase(id);
        for (auto& g : gos)
            g(ok);
        sign_next();
    };
    if (j->failed)
    {
        // Not read back, it is not sent unsigned: it waits for the next try.
        done(false);
        return;
    }
    const std::string_view whole = j->kept ? std::string_view(*j->kept) : std::string_view(j->data);
    const std::string dom = signing_domain(header_value(header_block(whole), "From"));
    // Mail from elsewhere that was checked here and is sent on, as an alias does, is sealed by ARC (RFC 8617), so the
    // next hop can know what it was as it came; other mail not from one of its domains goes unsigned.
    const bool forwarded = dom.empty() && !j->e->auth.empty() && !m_run.domains().empty();
    if (dom.empty() && !forwarded)
    {
        m_signed[id];
        done(true);
        return;
    }
    auto sig = std::make_shared<std::string>();
    m_run.pool().submit(m_run.cpu_lane(),
                        [j, sig, dom, forwarded, sel = m_selector, key = m_key, ed = m_ed_key,
                         authserv = m_run.hostname(), seal_domain = m_run.domains().front()] {
                            const std::string_view w = j->kept ? std::string_view(*j->kept) : std::string_view(j->data);
                            const int64_t now = wall::now_ms() / 1000;
                            if (forwarded)
                            {
                                // What the chain was as it came, as this host's checks wrote it.
                                const std::string& auth = j->e->auth;
                                const std::string cv = auth.find("arc=pass") != std::string::npos ? "pass" : "fail";
                                *sig = arc::seal(w, authserv, auth, seal_domain, sel, key.get(), now, cv);
                                return;
                            }
                            // The body is hashed once for both signatures.
                            const std::string bh = dkim::body_hash(w);
                            *sig = dkim::sign(w, dom, sel, key.get(), now, "DKIM-Signature", {}, bh) +
                                   dkim::sign(w, dom, sel + "-ed", ed.get(), now, "DKIM-Signature", {}, bh);
                        },
                        [this, id, sig, done, alive = m_alive] {
                            if (!*alive)
                                return;
                            m_signed[id] = std::move(*sig);
                            done(true);
                        });
}

std::string delivery::signing_domain(std::string_view from_header) const
{
    address a;
    if (!parse_mailbox(from_header, a))
        return {};
    for (const auto& d : m_run.domains())
        if (a.domain == d || (a.domain.size() > d.size() && a.domain.ends_with("." + d)))
            return d;
    return {};
}

std::vector<std::pair<std::string, std::string>> delivery::dkim_records() const
{
    std::vector<std::pair<std::string, std::string>> out;
    for (const auto& [sel, key] : {std::pair{m_selector, m_key}, {m_selector + "-ed", m_ed_key},
                                   {m_next_selector, m_next_key}, {m_next_selector + "-ed", m_next_ed_key}})
        if (key)
            out.emplace_back(sel, dkim::public_record(key.get()));
    return out;
}

// ── Results ─────────────────────────────────────────────────────────────────

void delivery::result(const item& it, size_t t, int code, const std::string& said, bool temporary, uint8_t report)
{
    const size_t i = it.to[t].rcpt;
    spool_entry& e = *it.e;
    if (i >= e.rcpts.size() || e.rcpts[i].state != rcpt_state::waiting)
        return;
    // A remote reply's lines are one line here, as the log, the report and `show` take them.
    std::string text = said;
    for (char& ch : text)
        if (ch == '\n' || ch == '\r')
            ch = ' ';
    const auto count = m_target_count.find(e.id);
    const uint32_t targets = count != m_target_count.end() && i < count->second.size() ? count->second[i] : 1;
    if (code / 100 == 2 && report && (e.rcpts[i].notify & notify_success))
        e.rcpts[i].report = std::max(e.rcpts[i].report, report);
    if (targets > 1)
    {
        // Each target an alias made is over on its own, and the recipient once they all are.
        if (code / 100 == 2)
        {
            ++m_delivered;
            m_run.queue().target_over(e, i, it.to[t].addr, true, {});
        }
        else if (temporary)
        {
            ++m_deferred;
            e.rcpts[i].why = it.to[t].addr + ": " + text;
        }
        else
        {
            ++m_failed;
            m_run.queue().target_over(e, i, it.to[t].addr, false, text);
        }
        if (e.rcpts[i].targets_done.size() + e.rcpts[i].targets_failed.size() >= targets)
            targets_settled(e, i);
        return;
    }
    if (code / 100 == 2)
    {
        ++m_delivered;
        m_run.queue().mark(e, i, rcpt_state::delivered, text);
        return;
    }
    if (temporary)
    {
        ++m_deferred;
        e.rcpts[i].why = text;
        return;
    }
    ++m_failed;
    m_run.queue().mark(e, i, rcpt_state::failed, (it.to[t].addr != e.rcpts[i].addr ? it.to[t].addr + ": " : "") + text);
}

void delivery::targets_settled(spool_entry& e, size_t i)
{
    const spool_rcpt& r = e.rcpts[i];
    if (r.targets_failed.empty())
    {
        m_run.queue().mark(e, i, rcpt_state::delivered,
                           "250 2.0.0 delivered to its " + std::to_string(r.targets_done.size()) + " targets");
        return;
    }
    std::string why;
    for (const auto& f : r.targets_failed)
        why += (why.empty() ? "" : "; ") + f;
    m_run.queue().mark(e, i, rcpt_state::failed, why);
}

void delivery::attempt_over(const entry_ptr& e)
{
    m_out.erase(e->id);
    if (e->waiting() == 0)
    {
        finished(e);
        return;
    }
    const int64_t now = wall::now_ms_coarse();
    if (now - e->at_ms > static_cast<int64_t>(m_run.owner().get_queue_lifetime()) * 1000 / queue_scale())
    {
        for (size_t i = 0; i < e->rcpts.size(); ++i)
            if (e->rcpts[i].state == rcpt_state::waiting)
                m_run.queue().mark(*e, i, rcpt_state::failed,
                                   "550 5.4.7 given up after " + std::to_string(e->attempts + 1) + " tries: " +
                                       (e->rcpts[i].why.empty() ? std::string("no answer") : e->rcpts[i].why));
        finished(e);
        return;
    }
    // A sender who asked to hear of a delay is told once, after delay_notice of trying.
    static const int64_t notice = settings::number<int64_t>("SOCKETLEY_MAIL_DELAY_NOTICE_MS").value_or(4 * 3600000);
    if (!e->delay_told && !e->bounce && !e->from.empty() && now - e->at_ms >= notice)
    {
        bool asked = false;
        for (const auto& r : e->rcpts)
            asked = asked || (r.state == rcpt_state::waiting && (r.notify & notify_delay));
        if (asked)
        {
            m_run.queue().delay_told(*e);
            report(e, report_kind::delay);
        }
    }
    // What failed for good is told now, not once the recipients still waiting are over, as Postfix tells it.
    if (!e->bounce && !e->from.empty())
    {
        bool tell = false;
        for (const auto& r : e->rcpts)
            tell = tell || (r.state == rcpt_state::failed && !r.told && reported(r, false));
        if (tell)
            report(e, report_kind::partial);
    }
    constexpr size_t n = std::size(retry_delays);
    const uint32_t delay = retry_delays[std::min<size_t>(e->attempts, n - 1)];
    m_run.queue().retry(*e, e->attempts + 1, now + static_cast<int64_t>(delay) * 1000 / queue_scale());
    schedule(e, e->next_ms);
}

int64_t delivery::queue_scale()
{
    // A test aid: the retries and the queue lifetime run this many times faster.
    static const int64_t scale = std::max<int64_t>(1, settings::number<int64_t>("SOCKETLEY_MAIL_QUEUE_SCALE").value_or(1));
    return scale;
}

void delivery::finished(const entry_ptr& e)
{
    bool told = false;
    for (const auto& r : e->rcpts)
        told = told || (!r.told && reported(r, false));
    m_signed.erase(e->id);
    m_pending_targets.erase(e->id);
    m_target_count.erase(e->id);
    if (told && !e->bounce && !e->from.empty())
    {
        report(e, report_kind::final);
        return;
    }
    m_run.queue().remove(e->id);
}

bool delivery::reported(const spool_rcpt& r, bool delay)
{
    if (delay)
        return r.state == rcpt_state::waiting && (r.notify & notify_delay);
    // A failure is told unless NOTIFY said otherwise; a success only where it asked and was not passed on.
    if (r.state == rcpt_state::failed)
        return r.notify == 0 || (r.notify & notify_failure);
    return r.state == rcpt_state::delivered && r.report;
}

void delivery::report(const entry_ptr& e, report_kind kind)
{
    const bool delay = kind == report_kind::delay;
    // The whole message under RET=FULL, up to a few mebibytes; its header otherwise, as RET=HDRS or no RET says, and
    // always for REQUIRETLS mail, whose notice goes back with no such requirement.
    const bool full = e->ret == 1 && !e->requiretls && e->body_len <= (4u << 20);
    const uint32_t want = static_cast<uint32_t>(full ? e->body_len : std::min<uint64_t>(e->body_len, 65536));
    m_run.queue().read(e, 0, want, [this, e, kind, delay, full, alive = m_alive](bool ok, std::string_view got) {
        if (!*alive)
            return;
        const std::string host = m_run.hostname();
        const std::string b = "=_skl_" + socketley::random_hex(12);
        const int64_t now = wall::now_ms();
        std::string text, status;
        bool failed = false;
        // A value a sender gave is put into a header only as one line of printable text.
        const auto clean = [](std::string_view v) {
            std::string out;
            for (const unsigned char ch : v.substr(0, 1000))
                out += ch < 0x20 || ch == 0x7f ? ' ' : static_cast<char>(ch);
            return out;
        };
        std::vector<size_t> included;
        for (size_t ri = 0; ri < e->rcpts.size(); ++ri)
        {
            const spool_rcpt& r = e->rcpts[ri];
            if (!reported(r, delay) || (!delay && r.told) || (kind == report_kind::partial && r.state != rcpt_state::failed))
                continue;
            included.push_back(ri);
            std::string action, code;
            if (delay)
            {
                action = "delayed";
                code = "4.0.0";
                text += "<" + r.addr + ">: still being tried" + (r.why.empty() ? "" : ": " + r.why) + "\r\n";
            }
            else if (r.state == rcpt_state::failed)
            {
                failed = true;
                action = "failed";
                code = "5.0.0";
                for (size_t i = 0; i + 4 < r.why.size(); ++i)
                    if (r.why[i] == '5' && r.why[i + 1] == '.' && std::isdigit(static_cast<unsigned char>(r.why[i + 2])))
                    {
                        code = r.why.substr(i, r.why.find(' ', i) - i);
                        break;
                    }
                text += "<" + r.addr + ">: " + r.why + "\r\n";
            }
            else
            {
                action = r.report == 1 ? "delivered" : "relayed";
                code = "2.0.0";
                text += "<" + r.addr + ">: " + (r.report == 1 ? "delivered to the mailbox" :
                                                "handed to a server that sends no delivery reports") + "\r\n";
            }
            status += "\r\n";
            if (!r.orcpt.empty())
            {
                const size_t semi = r.orcpt.find(';');
                std::string plain;
                if (semi != std::string::npos && xtext_decode(std::string_view(r.orcpt).substr(semi + 1), plain))
                    status += "Original-Recipient: " + clean(r.orcpt.substr(0, semi)) + "; " + clean(plain) + "\r\n";
            }
            status += "Final-Recipient: rfc822; " + clean(r.addr) + "\r\nAction: " + action + "\r\nStatus: " + code +
                      "\r\n";
            if (!r.why.empty() && action != "delivered")
                status += "Diagnostic-Code: smtp; " + clean(r.why) + "\r\n";
            if (delay)
                status += "Will-Retry-Until: " +
                          rfc5322_date(e->at_ms + static_cast<int64_t>(m_run.owner().get_queue_lifetime()) * 1000) +
                          "\r\n";
        }
        const std::string subject = delay ? "Delayed Mail (still being retried)" : failed ?
                                    "Undelivered Mail Returned to Sender" : "Successful Mail Delivery Report";
        const std::string said = delay ? "Your message has not been delivered yet to the recipients below; it is "
                                         "still being tried, and nothing needs to be done:" :
                                 failed ? "Your message could not be delivered to one or more of its recipients:" :
                                          "Your message was delivered to the recipients below:";
        std::string envid;
        if (!e->envid.empty() && xtext_decode(e->envid, envid))
            envid = "Original-Envelope-Id: " + clean(envid) + "\r\n";
        else
            envid.clear();
        const std::string enclosed = !ok ? std::string() : full ? std::string(got) : std::string(header_block(got));
        std::string msg = "From: Mail Delivery System <MAILER-DAEMON@" + host + ">\r\nTo: <" + e->from +
                          ">\r\nSubject: " + subject + "\r\nDate: " + rfc5322_date(now) + "\r\nMessage-ID: <" + e->id +
                          (delay ? ".delay@" : ".report@") + host +
                          ">\r\nAuto-Submitted: auto-replied\r\nMIME-Version: 1.0\r\n"
                          "Content-Type: multipart/report; report-type=delivery-status; boundary=\"" + b +
                          "\"\r\n\r\n--" + b + "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nThis is the mail system at " +
                          host + ".\r\n\r\n" + said + "\r\n\r\n" + text + "\r\n--" + b +
                          "\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; " + host + "\r\n" + envid +
                          "Arrival-Date: " + rfc5322_date(e->at_ms) + "\r\n" + status + "\r\n--" + b +
                          (full ? "\r\nContent-Type: message/rfc822\r\n\r\n" : "\r\nContent-Type: text/rfc822-headers\r\n\r\n") +
                          enclosed + "\r\n--" + b + "--\r\n";
        if (failed)
            ++m_bounced;
        else
            ++m_reports;
        if (included.empty())
        {
            if (kind == report_kind::final)
                m_run.queue().remove(e->id);
            return;
        }
        m_run.queue_message("", {e->from}, std::move(msg), true, {},
                            [this, e, kind, included, alive](bool ok, std::string) {
            if (!*alive || kind == report_kind::delay)
                return;
            if (ok)
            {
                for (const size_t ri : included)
                    m_run.queue().told(*e, ri);
                if (kind == report_kind::final)
                    m_run.queue().remove(e->id);
                return;
            }
            if (kind == report_kind::partial)
                return;
            // A report the spool would not take is made again later, and the message kept until it is.
            LOG_WARN(("mail: the report on " + e->id + " could not be queued, and is tried again").c_str());
            const int64_t next = wall::now_ms_coarse() + 300000;
            m_run.queue().retry(*e, e->attempts, next);
            schedule(e, next);
        });
    });
}

bool delivery::compose_message(const compose& c, std::string& from, std::vector<std::string>& rcpts,
                               std::string& body, std::string& why)
{
    address a;
    std::string name;
    if (!c.from.empty())
    {
        if (!parse_mailbox(c.from, a, &name) || a.domain.empty())
        {
            why = c.from + " is not an address to send from";
            return false;
        }
    }
    else if (m_run.owner().get_no_reply() && !m_run.domains().empty())
        parse_address("no-reply@" + m_run.domains().front(), a);
    else
    {
        why = "say who it is from with --from, or make the runtime with --no-reply to send from no-reply@";
        return false;
    }
    composed out;
    const std::string msgid = socketley::random_hex(12) + "@" + m_run.hostname();
    if (!mail::compose_message(c, a, name, msgid, wall::now_ms(), out, why))
        return false;
    from = std::move(out.from);
    rcpts = std::move(out.rcpts);
    body = std::move(out.message);
    if (body.size() > m_run.owner().get_max_size())
    {
        why = "the message is larger than --max-size";
        return false;
    }
    return true;
}

void delivery::stats(std::string& out) const
{
    using socketley::stats_text::put;
    put(out, "mail_delivered", m_delivered);
    put(out, "mail_deferred", m_deferred);
    put(out, "mail_failed", m_failed);
    put(out, "mail_bounced", m_bounced);
    put(out, "mail_reports", m_reports);
    put(out, "mail_sieve_rejected", m_sieve_rejected);
    put(out, "mail_over_quota", m_over_quota);
    put(out, "mail_sieve_redirected", m_sieve_redirected);
    put(out, "mail_sieve_vacations", m_sieve_vacations);
    put(out, "mail_sieve_notified", m_sieve_notified);
    put(out, "mail_out_connections", m_conns.size());
    put(out, "mail_out_connects", m_connects);
    put(out, "mail_out_tls", m_tls_sessions);
    put(out, "mail_out_transactions", m_transactions);
    put(out, "mail_mx_lookups", m_lookups);
    put(out, "mail_out_dane_verified", m_dane_verified);
    put(out, "mail_out_sts_verified", m_sts_verified);
    put(out, "mail_out_tls_refused", m_tls_refused);
    put(out, "mail_sts_fetched", m_sts_fetched);
    put(out, "mail_sts_testing_failures", m_sts_testing_failed);
}

// ── One connection ──────────────────────────────────────────────────────────

void delivery::open_conn(route& r)
{
    auto c = std::make_unique<out_conn>();
    c->id = m_next_conn++;
    c->route = r.key;
    c->cur = std::make_unique<item>(std::move(r.waiting.front()));
    r.waiting.pop_front();
    ++r.active;
    out_conn& raw = *c;
    m_conns.emplace(raw.id, std::move(c));
    raw.host = r.hosts.empty() ? r.key : r.hosts.front();
    if (const tls_policy::sts* p = m_relay ? nullptr : sts_for(r.key))
        raw.sts = p->mode;
    conn_connect(raw);
}

void delivery::conn_connect(out_conn& c)
{
    route& r = m_routes[c.route];
    const uint16_t port = m_relay ? m_relay_port : m_mx_port;
    for (;;)
    {
        if (!c.resolved)
        {
            if (c.host_at >= r.hosts.size())
            {
                conn_fail(c, c.last_error.empty() ? "451 4.4.1 no exchanger of " + r.key + " could be reached"
                                                  : c.last_error,
                          move_on::none);
                return;
            }
            c.host = r.hosts[c.host_at];
            // An exchanger of a domain whose MX records DNSSEC signed has its TLSA records asked first (RFC 7672).
            // An answer is kept five minutes for the next connection to the same exchanger.
            if (!m_relay && r.mx_secure && c.tlsa_for != c.host_at)
                if (const auto held = m_tlsa_kept.find(c.host);
                    held != m_tlsa_kept.end() && held->second.until_ms > wall::now_ms_coarse())
                {
                    c.tlsa_for = c.host_at;
                    c.dane = held->second.dane;
                    c.tlsa = held->second.tlsa;
                }
            if (!m_relay && r.mx_secure && c.tlsa_for != c.host_at)
            {
                std::vector<dns_client::record> recs;
                bool nx = false, secure = false;
                const dns_client::state ts =
                    dns_client::here().ask_records("_" + std::to_string(m_mx_port) + "._tcp." + c.host, dns::type::TLSA, recs, nx, &secure);
                if (ts == dns_client::state::pending)
                {
                    c.state = out_conn::st::resolving;
                    poll_lookups(nullptr, c.id);
                    return;
                }
                if (ts == dns_client::state::unsure)
                {
                    // Records that may be there but could not be read are no licence to send without them.
                    c.last_error = "451 4.7.5 the TLSA records of " + c.host + " could not be looked up";
                    ++c.host_at;
                    continue;
                }
                c.tlsa_for = c.host_at;
                c.dane = secure && !nx && !recs.empty();
                c.tlsa.clear();
                for (const auto& rec : recs)
                {
                    tls_policy::tlsa t;
                    if (tls_policy::parse_tlsa(rec.text, t) && tls_policy::usable(t))
                        c.tlsa.push_back(std::move(t));
                }
                if (m_tlsa_kept.size() > 4096)
                    m_tlsa_kept.clear();
                m_tlsa_kept[c.host] = {wall::now_ms_coarse() + 300000, c.dane, c.tlsa};
            }
            else if (!r.mx_secure)
            {
                c.dane = false;
                c.tlsa.clear();
            }
            std::vector<endpoint> found;
            // An exchanger an MX record named is an absolute name, asked with no search domain after it.
            unsigned char lit[16];
            const bool literal = ::inet_pton(AF_INET, c.host.c_str(), lit) == 1 || ::inet_pton(AF_INET6, c.host.c_str(), lit) == 1;
            const dns_client::state st =
                dns_client::here().ask(m_relay || literal || c.host.ends_with('.') ? c.host : c.host + ".", AF_UNSPEC, found);
            if (st == dns_client::state::pending)
            {
                c.state = out_conn::st::resolving;
                poll_lookups(nullptr, c.id);
                return;
            }
            if (st == dns_client::state::unsure)
            {
                // The system's resolver, on a thread, for what the loop's cannot say.
                c.state = out_conn::st::resolving;
                c.deadline_ms = 0;
                auto got = std::make_shared<std::vector<endpoint>>();
                const uint64_t id = c.id, gen = c.gen;
                m_run.pool().submit(0, [host = c.host, got] { *got = socketley::resolve_all(host, nullptr, AF_UNSPEC); },
                                    [this, id, gen, got, alive = m_alive] {
                                        if (!*alive)
                                            return;
                                        const auto it = m_conns.find(id);
                                        if (it == m_conns.end() || it->second->gen != gen)
                                            return;
                                        out_conn& c = *it->second;
                                        c.addrs = std::move(*got);
                                        c.addr_at = 0;
                                        c.resolved = true;
                                        if (c.addrs.empty())
                                        {
                                            c.last_error = "451 4.4.4 " + c.host + " has no address";
                                            ++c.host_at;
                                            c.resolved = false;
                                        }
                                        conn_connect(c);
                                    });
                c.state = out_conn::st::connecting;
                c.deadline_ms = wall::now_ms_coarse() + 60000;
                return;
            }
            c.addrs = std::move(found);
            c.addr_at = 0;
            c.resolved = true;
            if (c.addrs.empty())
            {
                c.last_error = "451 4.4.4 " + c.host + " has no address";
                ++c.host_at;
                c.resolved = false;
                continue;
            }
        }
        if (c.addr_at >= c.addrs.size())
        {
            ++c.host_at;
            c.resolved = false;
            continue;
        }
        break;
    }
    endpoint ep = c.addrs[c.addr_at];
    if (ep.addr.ss_family == AF_INET)
        reinterpret_cast<sockaddr_in*>(&ep.addr)->sin_port = htons(port);
    else
        reinterpret_cast<sockaddr_in6*>(&ep.addr)->sin6_port = htons(port);
    c.fd = ::socket(ep.addr.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (c.fd < 0)
    {
        conn_fail(c, "451 4.3.0 no socket could be made", move_on::none);
        return;
    }
    const int one = 1;
    if (::setsockopt(c.fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) < 0) {}
    c.state = out_conn::st::connecting;
    c.deadline_ms = wall::now_ms_coarse() + 30000;
    ++c.gen;
    ++m_connects;
    const uint64_t id = c.id, gen = c.gen;
    if (!m_io.connect(c.fd, reinterpret_cast<const sockaddr*>(&ep.addr), ep.len,
                      [this, id, gen, alive = m_alive](int64_t res) {
                          if (!*alive)
                              return;
                          const auto it = m_conns.find(id);
                          if (it != m_conns.end() && it->second->gen == gen)
                              conn_connected(*it->second, res);
                      }))
        conn_fail(c, "451 4.3.0 the ring is full", move_on::none);
}

void delivery::conn_connected(out_conn& c, int64_t res)
{
    if (res < 0)
    {
        if (route& r = m_routes[c.route]; r.limit > 1)
            r.limit /= 2;
        c.last_error = "451 4.4.1 " + c.host + " refused the connection: " + std::strerror(static_cast<int>(-res));
        ::close(c.fd);
        c.fd = -1;
        ++c.addr_at;
        conn_connect(c);
        return;
    }
    c.deadline_ms = wall::now_ms_coarse() + command_ms;
    if (m_relay && m_relay_tls)
    {
        c.ssl = m_tls ? m_tls->create_ssl_client(c.host) : nullptr;
        if (!c.ssl)
        {
            conn_fail(c, "451 4.7.0 no TLS session could be made for " + c.host, move_on::none);
            return;
        }
        c.state = out_conn::st::handshake;
        tls_context::do_handshake(c.ssl);
        std::string hello;
        tls_context::take_out(c.ssl, hello);
        c.outq.push_back(std::make_shared<const std::string>(std::move(hello)));
        conn_write(c);
    }
    else
        c.state = out_conn::st::greeting;
    conn_receive(c);
}

void delivery::conn_receive(out_conn& c)
{
    std::shared_ptr<char[]> buf(new char[read_bytes]);
    const uint64_t id = c.id, gen = c.gen;
    if (!m_io.pread(c.fd, buf.get(), read_bytes, file_io::at_stream, [this, id, gen, buf, alive = m_alive](int64_t res) {
            if (!*alive)
                return;
            const auto it = m_conns.find(id);
            if (it == m_conns.end() || it->second->gen != gen)
                return;
            out_conn& c = *it->second;
            if (res <= 0)
            {
                if (c.state == out_conn::st::quit)
                    conn_close(c);
                else
                    conn_fail(c, "451 4.4.2 " + c.host + " closed the connection", early_move(c));
                return;
            }
            conn_got(c, buf.get(), static_cast<size_t>(res));
            if (m_conns.count(id) && m_conns[id]->gen == gen)
                conn_receive(*m_conns[id]);
        }))
        conn_fail(c, "451 4.3.0 the ring is full", move_on::none);
}

void delivery::conn_got(out_conn& c, const char* p, size_t n)
{
    const uint64_t id = c.id, gen = c.gen;
    const auto live = [&] {
        const auto it = m_conns.find(id);
        return it != m_conns.end() && it->second->gen == gen;
    };
    if (c.ssl)
    {
        if (tls_context::bio_write_in(c.ssl, p, static_cast<int>(n)) < 0)
        {
            conn_fail(c, "451 4.7.0 the TLS record layer took no more", early_move(c));
            return;
        }
        if (!c.handshaken)
        {
            const int r = tls_context::do_handshake(c.ssl);
            std::string out;
            tls_context::take_out(c.ssl, out);
            if (!out.empty())
            {
                c.outq.push_back(std::make_shared<const std::string>(std::move(out)));
                conn_write(c);
            }
            if (r < 0)
            {
                const long v = SSL_get_verify_result(c.ssl);
                tls_told(c, false, c.dane ? "validation-failure" : v != X509_V_OK ? "certificate-not-trusted"
                                                                                   : "validation-failure");
                conn_fail(c, "451 4.7.5 the TLS handshake with " + c.host + " failed" +
                                 (v != X509_V_OK ? std::string(": ") + X509_verify_cert_error_string(v) +
                                                   (c.dane ? ", against its TLSA records" : "")
                                                 : std::string()),
                          m_relay ? move_on::none : move_on::host);
                return;
            }
            if (r == 0)
                return;
            c.handshaken = true;
            c.verified = SSL_get_verify_result(c.ssl) == X509_V_OK;
            ++m_tls_sessions;
            tls_told(c, c.verified, c.verified ? "" : "certificate-host-mismatch");
            if (c.verified && c.dane && !c.tlsa.empty())
                ++m_dane_verified;
            else if (c.verified && c.sts == tls_policy::sts_mode::enforce)
                ++m_sts_verified;
            else if (!c.verified && c.sts == tls_policy::sts_mode::testing)
            {
                // A policy in testing mode is told of, never acted on.
                ++m_sts_testing_failed;
                LOG_WARN(("mail: " + c.host + " would fail the MTA-STS policy of " + c.route + ": " +
                          X509_verify_cert_error_string(SSL_get_verify_result(c.ssl)))
                             .c_str());
            }
            if (c.after_starttls)
            {
                // The conversation starts over inside TLS (RFC 3207 4.2).
                c.state = out_conn::st::ehlo;
                c.pipelining = c.starttls = c.eightbit = c.utf8 = c.auth_plain = c.chunking = c.dsn = false;
                c.requiretls = false;
                c.rcpt_max = 0;
                c.expect.push_back('E');
                conn_send(c, "EHLO " + m_run.hostname() + "\r\n");
            }
            else
                c.state = out_conn::st::greeting;
        }
        char buf[16384];
        for (;;)
        {
            const int r = tls_context::ssl_read(c.ssl, buf, sizeof buf);
            if (r <= 0)
            {
                if (r < 0)
                {
                    conn_fail(c, "451 4.7.0 TLS failed on the connection to " + c.host, early_move(c));
                    return;
                }
                break;
            }
            c.in.append(buf, static_cast<size_t>(r));
        }
    }
    else
        c.in.append(p, n);
    // A reply longer than any server sends is no reply: what it said is not held without bound.
    if (c.in.size() > (64u << 10) && c.in.find('\n') == std::string::npos)
    {
        conn_fail(c, "451 4.4.2 " + c.host + " sent a line longer than 64 KiB", move_on::none);
        return;
    }
    size_t at = 0;
    while (live())
    {
        const size_t nl = c.in.find('\n', at);
        if (nl == std::string::npos)
            break;
        std::string_view line(c.in.data() + at, nl - at);
        at = nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (line.size() < 3 || !std::isdigit(static_cast<unsigned char>(line[0])))
            continue;
        const int code = std::atoi(std::string(line.substr(0, 3)).c_str());
        const bool more = line.size() > 3 && line[3] == '-';
        if (!c.reply_text.empty())
            c.reply_text += '\n';
        c.reply_text += std::string(line.substr(std::min<size_t>(line.size(), 4)));
        if (c.reply_text.size() > (64u << 10))
        {
            conn_fail(c, "451 4.4.2 " + c.host + " sent a reply longer than 64 KiB", move_on::none);
            return;
        }
        if (more)
            continue;
        std::string text = std::move(c.reply_text);
        c.reply_text.clear();
        conn_reply(c, code, std::move(text));
    }
    if (live())
        c.in.erase(0, at);
}

void delivery::conn_send(out_conn& c, std::string bytes)
{
    if (c.ssl && c.handshaken)
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
        std::string out;
        tls_context::take_out(c.ssl, out);
        c.outq.push_back(std::make_shared<const std::string>(std::move(out)));
        if (off < bytes.size())
        {
            // What TLS would not take is no message cut short: the connection fails, after the caller is done with it.
            const uint64_t id = c.id, gen = c.gen;
            if (!m_io.after(std::chrono::milliseconds(0), [this, id, gen, alive = m_alive](int64_t) {
                    if (!*alive)
                        return;
                    const auto it = m_conns.find(id);
                    if (it != m_conns.end() && it->second->gen == gen)
                        conn_fail(*it->second, "451 4.7.0 TLS took no more on the connection to " + it->second->host,
                                  move_on::none);
                })) {}
            return;
        }
    }
    else
        c.outq.push_back(std::make_shared<const std::string>(std::move(bytes)));
    conn_write(c);
}

void delivery::conn_write(out_conn& c)
{
    while (!c.writing && !c.outq.empty() && c.outq.front()->size() == c.out_off)
    {
        c.outq.pop_front();
        c.out_off = 0;
    }
    if (c.writing || c.outq.empty() || c.fd < 0)
    {
        // What the body has sent is gone: the next piece of it is read.
        if (!c.writing && c.outq.empty() && c.state == out_conn::st::body && !c.reading)
            conn_body(c);
        return;
    }
    c.writing = true;
    std::shared_ptr<const std::string> b = c.outq.front();
    const uint64_t id = c.id, gen = c.gen;
    if (!m_io.pwrite(c.fd, b->data() + c.out_off, static_cast<uint32_t>(b->size() - c.out_off), file_io::at_stream,
                     [this, id, gen, b, alive = m_alive](int64_t res) {
                         if (!*alive)
                             return;
                         const auto it = m_conns.find(id);
                         if (it == m_conns.end() || it->second->gen != gen)
                             return;
                         out_conn& c = *it->second;
                         c.writing = false;
                         if (res <= 0)
                         {
                             conn_fail(c, "451 4.4.2 the connection to " + c.host + " broke", early_move(c));
                             return;
                         }
                         c.out_off += static_cast<size_t>(res);
                         conn_write(c);
                     }))
    {
        c.writing = false;
        conn_fail(c, "451 4.3.0 the ring is full", move_on::none);
    }
}

void delivery::conn_reply(out_conn& c, int code, std::string text)
{
    using st = out_conn::st;
    const bool ok = code / 100 == 2;
    c.deadline_ms = wall::now_ms_coarse() + command_ms;
    const std::string said = std::to_string(code) + " " + text;
    if (code == 421)
    {
        // A server that says it is busy is given a rest from new connections (RFC 5321 4.2.3).
        static const int64_t hold_first_ms = settings::number<int64_t>("SOCKETLEY_MAIL_BUSY_HOLD_MS").value_or(30000);
        route& r = m_routes[c.route];
        r.hold_ms = std::min<int64_t>(r.hold_ms ? r.hold_ms * 2 : hold_first_ms, 900000);
        r.held_until = wall::now_ms_coarse() + r.hold_ms;
        r.limit = 1;
        m_held.insert(r.key);
    }
    switch (c.state)
    {
        case st::greeting:
            if (code != 220)
            {
                // A refusal at the door keeps its class: the next exchanger is tried, and a 5xx from the last is final.
                conn_fail(c, (code / 100 == 5 ? "554 5.4.0 " : "451 4.4.0 ") + c.host + " greeted with " + said,
                          move_on::host);
                return;
            }
            c.state = st::ehlo;
            c.expect.push_back('E');
            conn_send(c, "EHLO " + m_run.hostname() + "\r\n");
            return;
        case st::ehlo:
        case st::helo:
        {
            if (!c.expect.empty())
                c.expect.pop_front();
            if (!ok)
            {
                if (c.state == st::ehlo)
                {
                    c.state = st::helo;
                    c.expect.push_back('E');
                    conn_send(c, "HELO " + m_run.hostname() + "\r\n");
                    return;
                }
                conn_fail(c, (code / 100 == 5 ? "554 5.4.0 " : "451 4.4.0 ") + c.host + " refused HELO: " + said,
                          move_on::host);
                return;
            }
            if (c.state == st::ehlo)
            {
                std::string_view rest = text;
                while (!rest.empty())
                {
                    const size_t nl = rest.find('\n');
                    std::string line = lower(rest.substr(0, nl));
                    rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
                    if (line == "pipelining")
                        c.pipelining = true;
                    else if (line == "starttls")
                        c.starttls = true;
                    else if (line == "8bitmime")
                        c.eightbit = true;
                    else if (line == "smtputf8")
                        c.utf8 = true;
                    else if (line == "chunking")
                        c.chunking = true;
                    else if (line == "dsn")
                        c.dsn = true;
                    else if (line == "requiretls")
                        c.requiretls = true;
                    else if (line.starts_with("size"))
                        c.size_max = static_cast<uint64_t>(std::atoll(line.c_str() + 4));
                    else if (line.starts_with("limits ") && line.find("rcptmax=") != std::string::npos)
                        c.rcpt_max = static_cast<uint32_t>(
                            std::clamp<long long>(std::atoll(line.c_str() + line.find("rcptmax=") + 8), 0, 100000));
                    else if (line.starts_with("auth ") || line.starts_with("auth="))
                    {
                        // The mechanisms are words of the line, not parts of others such as XPLAIN.
                        std::string_view words = std::string_view(line).substr(5);
                        while (!words.empty())
                        {
                            const size_t sp = words.find(' ');
                            const std::string_view w = words.substr(0, sp);
                            c.auth_plain = c.auth_plain || w == "plain";
                            c.auth_login = c.auth_login || w == "login";
                            words = sp == std::string_view::npos ? std::string_view{} : words.substr(sp + 1);
                        }
                    }
                }
            }
            const bool loopback = c.host == "localhost" || c.host.starts_with("127.") || c.host == "::1";
            if (!c.ssl && c.starttls && m_tls)
            {
                c.state = st::starttls;
                conn_send(c, "STARTTLS\r\n");
                return;
            }
            if (!c.ssl && (c.dane || c.sts == tls_policy::sts_mode::enforce))
            {
                // Its domain says its mail goes over TLS, so it is not sent in the clear (RFC 7672 2.2, RFC 8461 5).
                ++m_tls_refused;
                tls_told(c, false, "starttls-not-supported");
                conn_fail(c, "451 4.7.5 " + c.host + " offers no STARTTLS, which " +
                                 (c.dane ? "its TLSA records" : "the MTA-STS policy of " + c.route) + " require",
                          move_on::host);
                return;
            }
            if (m_relay && !m_relay_user.empty())
            {
                if (!c.ssl && !loopback)
                {
                    conn_fail(c, "451 4.7.0 the relay " + c.host + " offers no TLS, and its password is not sent "
                                 "in the clear", move_on::none);
                    return;
                }
                if (!c.auth_plain && !c.auth_login)
                {
                    conn_fail(c, "451 4.7.0 the relay " + c.host + " offers neither AUTH PLAIN nor LOGIN", move_on::none);
                    return;
                }
                c.state = st::auth;
                if (!c.auth_plain)
                {
                    c.login_step = 1;
                    conn_send(c, "AUTH LOGIN\r\n");
                    return;
                }
                std::string plain;
                plain += '\0';
                plain += m_relay_user;
                plain += '\0';
                plain += m_relay_pass;
                conn_send(c, "AUTH PLAIN " + socketley::base64::encode(plain) + "\r\n");
                return;
            }
            c.state = st::ready;
            conn_next(c);
            return;
        }
        case st::starttls:
            if (code != 220)
            {
                if (c.dane || c.sts == tls_policy::sts_mode::enforce)
                {
                    ++m_tls_refused;
                    tls_told(c, false, "starttls-not-supported");
                    conn_fail(c, "451 4.7.5 " + c.host + " refused STARTTLS: " + said, move_on::host);
                    return;
                }
                // Refused: the mail goes in the clear, as it would to a server that never offered TLS.
                c.starttls = false;
                c.state = st::ehlo;
                conn_reply(c, 250, "");
                return;
            }
            c.ssl = m_tls->create_ssl_client(c.host);
            if (!c.ssl)
            {
                conn_fail(c, "451 4.7.0 no TLS session could be made for " + c.host, move_on::none);
                return;
            }
            // An exchanger's certificate is checked against its TLSA records where there are usable ones, against
            // the CAs and its name under an enforced MTA-STS policy, and not at all otherwise: TLS against an
            // eavesdropper, as every MTA speaks it.  A smarthost's is checked always.
            if (!m_relay)
            {
                if (c.dane && !c.tlsa.empty())
                {
                    bool added = m_dane && SSL_dane_enable(c.ssl, c.host.c_str()) > 0;
                    for (const auto& t : c.tlsa)
                        added = added && SSL_dane_tlsa_add(c.ssl, t.usage, t.selector, t.mtype,
                                                           reinterpret_cast<const unsigned char*>(t.data.data()),
                                                           t.data.size()) > 0;
                    if (!added)
                    {
                        tls_told(c, false, "tlsa-invalid");
                        conn_fail(c, "451 4.7.5 the TLSA records of " + c.host + " could not be used", move_on::host);
                        return;
                    }
                }
                else if (c.sts != tls_policy::sts_mode::enforce)
                    SSL_set_verify(c.ssl, SSL_VERIFY_NONE, nullptr);
            }
            c.after_starttls = true;
            c.state = st::handshake;
            {
                tls_context::do_handshake(c.ssl);
                std::string hello;
                tls_context::take_out(c.ssl, hello);
                c.outq.push_back(std::make_shared<const std::string>(std::move(hello)));
                conn_write(c);
            }
            return;
        case st::auth:
            if (code == 334 && (c.login_step == 1 || c.login_step == 2))
            {
                conn_send(c, socketley::base64::encode(c.login_step == 1 ? m_relay_user : m_relay_pass) + "\r\n");
                ++c.login_step;
                return;
            }
            if (code != 235)
            {
                // Mail waits for credentials a relay refused, as Postfix's soft bounce has it: they may be fixed.
                conn_fail(c, "454 4.7.0 the relay " + c.host + " refused the credentials: " + said, move_on::none);
                return;
            }
            c.state = st::ready;
            conn_next(c);
            return;
        case st::transaction:
        {
            if (c.expect.empty())
                return;
            const char what = c.expect.front();
            c.expect.pop_front();
            if (what == 'M')
            {
                c.mail_code = code;
                c.mail_text = said;
                // A refused MAIL ends the transaction: without pipelining nothing more of it is sent.
                if (!ok && !c.pipelining)
                {
                    c.unsent.clear();
                    conn_end_item(c, code, said);
                    return;
                }
            }
            else if (what == 'R')
            {
                if (c.rcpt_seen < c.rcpt_code.size())
                {
                    c.rcpt_code[c.rcpt_seen] = code;
                    c.rcpt_text[c.rcpt_seen] = said;
                    c.rcpt_ok += ok;
                }
                ++c.rcpt_seen;
            }
            else if (what == 'D')
            {
                if (code == 354 && c.mail_code / 100 == 2 && c.rcpt_ok > 0)
                {
                    c.state = st::body;
                    c.body_off = 0;
                    c.bol = true;
                    c.signature_sent = false;
                    conn_body(c);
                    return;
                }
                // A server that waits for the data though it took no recipient is sent an empty message's end, or
                // what comes next would be read as the data (RFC 2920 3.1); each recipient keeps its own answer.
                if (code == 354)
                {
                    c.state = st::dot;
                    c.deadline_ms = wall::now_ms_coarse() + final_ms;
                    conn_send(c, ".\r\n");
                    return;
                }
                // Nobody took it: each recipient is told what its own command was answered.
                conn_end_item(c, c.mail_code / 100 != 2 ? c.mail_code : code,
                              c.mail_code / 100 != 2 ? c.mail_text : said);
                return;
            }
            // With BDAT, the body goes once every recipient is answered, if one was taken.
            if (c.bdat && c.expect.empty() && c.unsent.empty())
            {
                if (c.mail_code / 100 == 2 && c.rcpt_ok > 0)
                {
                    c.state = st::body;
                    c.body_off = 0;
                    c.signature_sent = false;
                    conn_body(c);
                }
                else
                    conn_end_item(c, c.mail_code / 100 != 2 ? c.mail_code : c.rcpt_code.empty() ? 554 : c.rcpt_code[0],
                                  c.mail_code / 100 != 2 ? c.mail_text : c.rcpt_text.empty() ? "" : c.rcpt_text[0]);
                return;
            }
            // Without pipelining, the next command goes once this one is answered.
            if (!c.unsent.empty() && c.expect.empty())
            {
                std::string next = std::move(c.unsent.front());
                c.unsent.pop_front();
                c.expect.push_back(next.starts_with("DATA") ? 'D' : 'R');
                conn_send(c, std::move(next));
            }
            return;
        }
        case st::body:
        case st::dot:
            if (c.bdat)
            {
                // Each chunk is answered; the first refusal is the message's, and the last answer ends it.
                if (c.bdat_out)
                    --c.bdat_out;
                if (!ok && !c.bdat_code)
                {
                    c.bdat_code = code;
                    c.bdat_text = said;
                }
                if (c.bdat_out || !(c.bdat_last || c.bdat_code))
                {
                    if (c.bdat_code == 0 && c.state == st::body && c.outq.empty() && !c.reading)
                        conn_body(c);
                    return;
                }
                c.deadline_ms = 0;
                if (c.bdat_code)
                {
                    // A chunk refused before the last leaves a transaction for RSET to clear.
                    if (!c.bdat_last)
                        c.state = st::transaction;
                    conn_end_item(c, c.bdat_code, c.bdat_text);
                    return;
                }
                conn_end_item(c, code, said);
                return;
            }
            if (c.state == st::body)
                return;
            c.deadline_ms = 0;
            conn_end_item(c, code, said);
            return;
        case st::rset:
            c.state = st::ready;
            conn_next(c);
            return;
        case st::quit:
            conn_close(c);
            return;
        default:
            return;
    }
}

void delivery::conn_next(out_conn& c)
{
    if (!c.cur)
    {
        route& r = m_routes[c.route];
        if (r.waiting.empty())
        {
            c.state = out_conn::st::ready;
            c.idle_ms = wall::now_ms_coarse();
            c.deadline_ms = 0;
            return;
        }
        c.cur = std::make_unique<item>(std::move(r.waiting.front()));
        r.waiting.pop_front();
    }
    conn_begin(c);
}

void delivery::conn_begin(out_conn& c)
{
    item& it = *c.cur;
    const spool_entry& e = *it.e;
    if (c.rcpt_max && it.to.size() > c.rcpt_max)
    {
        // The recipients past the server's limit go in a transaction of their own, next.
        item rest{it.e, std::vector<target>(it.to.begin() + c.rcpt_max, it.to.end())};
        it.to.resize(c.rcpt_max);
        ++m_out[e.id];
        m_routes[c.route].waiting.push_front(std::move(rest));
    }
    const auto sig = m_signed.find(e.id);
    const uint64_t size = e.body_len + (sig == m_signed.end() ? 0 : sig->second.size());
    if (c.size_max && size > c.size_max)
    {
        conn_end_item(c, 552, "552 5.3.4 the message is larger than " + c.host + " takes");
        return;
    }
    // REQUIRETLS mail goes only over TLS whose certificate DANE or MTA-STS vouched for, to a server that keeps the
    // requirement on (RFC 8689 4.2.1); a smarthost's is checked always.
    const bool vouched = c.ssl && c.handshaken && c.verified &&
                         (m_relay || (c.dane && !c.tlsa.empty()) || c.sts == tls_policy::sts_mode::enforce);
    if (e.requiretls && (!vouched || !c.requiretls))
    {
        conn_end_item(c, 550, "550 5.7.10 REQUIRETLS: " + c.host +
                                  (vouched ? " does not offer REQUIRETLS" : " was not reached over TLS DANE or MTA-STS vouched for"));
        return;
    }
    ++m_transactions;
    c.state = out_conn::st::transaction;
    c.rcpt_code.assign(it.to.size(), 0);
    c.rcpt_text.assign(it.to.size(), {});
    c.rcpt_seen = 0;
    c.rcpt_ok = 0;
    c.mail_code = 0;
    c.expect.clear();
    c.unsent.clear();
    bool utf8 = false;
    for (const unsigned char ch : e.from)
        utf8 = utf8 || ch >= 0x80;
    for (const auto& t : it.to)
        for (const unsigned char ch : t.addr)
            utf8 = utf8 || ch >= 0x80;
    // no-reply mail goes out under a tag of the domain it goes to, which a bounce of it must come back with.
    std::string sender = e.from;
    if (address na; m_run.owner().get_no_reply() && parse_address(e.from, na) &&
                    socketley::ascii::iequals(na.local, "no-reply") && m_run.is_local_domain(na.domain) && !it.to.empty())
        sender = "no-reply+" + m_run.verp_token(domain_of(it.to.front().addr)) + "@" + na.domain;
    // Mail from elsewhere sent on goes from an SRS address of ours, so SPF at the far end judges this host.
    else if (!e.auth.empty() && !e.from.empty() && !m_run.domains().empty() && !m_run.is_local_domain(domain_of(e.from)))
        sender = srs::forward(e.from, m_run.domains().front(), m_run.secret(), wall::now_ms() / 86400000);
    std::string mail = "MAIL FROM:<" + sender + ">";
    if (c.size_max)
        mail += " SIZE=" + std::to_string(size);
    if (c.eightbit)
        mail += " BODY=8BITMIME";
    if (utf8 && c.utf8)
        mail += " SMTPUTF8";
    // What the sender asked to be told goes on to a server that tells it (RFC 3461 6.2).
    if (c.dsn && e.ret)
        mail += e.ret == 1 ? " RET=FULL" : " RET=HDRS";
    if (c.dsn && !e.envid.empty())
        mail += " ENVID=" + e.envid;
    if (e.requiretls)
        mail += " REQUIRETLS";
    mail += "\r\n";
    std::vector<std::string> cmds;
    cmds.push_back(std::move(mail));
    for (const auto& t : it.to)
    {
        std::string rcpt = "RCPT TO:<" + t.addr + ">";
        if (c.dsn && t.rcpt < e.rcpts.size())
        {
            const spool_rcpt& r = e.rcpts[t.rcpt];
            if (r.notify)
            {
                std::string n;
                for (const auto& [bit, word] : {std::pair{notify_never, "NEVER"}, {notify_success, "SUCCESS"},
                                                {notify_failure, "FAILURE"}, {notify_delay, "DELAY"}})
                    if (r.notify & bit)
                        n += (n.empty() ? "" : ",") + std::string(word);
                rcpt += " NOTIFY=" + n;
            }
            // An address an alias rewrote keeps the one the sender gave.
            if (!r.orcpt.empty())
                rcpt += " ORCPT=" + r.orcpt;
            else if (t.addr != r.addr)
                rcpt += " ORCPT=rfc822;" + xtext_encode(r.addr);
        }
        cmds.push_back(rcpt + "\r\n");
    }
    // BDAT where it is offered with PIPELINING: the body goes as it is, with nothing to stuff.
    c.bdat = c.chunking && c.pipelining;
    c.bdat_out = 0;
    c.bdat_last = false;
    c.bdat_code = 0;
    c.bdat_text.clear();
    if (!c.bdat)
        cmds.push_back("DATA\r\n");
    if (c.pipelining)
    {
        std::string all;
        for (size_t i = 0; i < cmds.size(); ++i)
        {
            all += cmds[i];
            c.expect.push_back(i == 0 ? 'M' : i + 1 == cmds.size() && !c.bdat ? 'D' : 'R');
        }
        conn_send(c, std::move(all));
        return;
    }
    c.expect.push_back('M');
    for (size_t i = 1; i < cmds.size(); ++i)
        c.unsent.push_back(std::move(cmds[i]));
    conn_send(c, std::move(cmds[0]));
}

void delivery::conn_body(out_conn& c)
{
    if (!c.cur || c.reading)
        return;
    const entry_ptr e = c.cur->e;
    if (c.bdat)
    {
        conn_chunk(c);
        return;
    }
    if (!c.signature_sent)
    {
        c.signature_sent = true;
        if (const auto sig = m_signed.find(e->id); sig != m_signed.end() && !sig->second.empty())
        {
            conn_send(c, sig->second);
            return;
        }
    }
    if (c.body_off >= e->body_len)
    {
        std::string end = c.bol ? "" : "\r\n";
        end += ".\r\n";
        c.state = out_conn::st::dot;
        c.deadline_ms = wall::now_ms_coarse() + final_ms;
        conn_send(c, std::move(end));
        return;
    }
    c.reading = true;
    const uint64_t id = c.id, gen = c.gen;
    m_run.queue().read(e, c.body_off, body_chunk, [this, id, gen, alive = m_alive](bool ok, std::string_view b) {
        if (!*alive)
            return;
        const auto it = m_conns.find(id);
        if (it == m_conns.end() || it->second->gen != gen)
            return;
        out_conn& c = *it->second;
        c.reading = false;
        if (!ok || b.empty())
        {
            conn_fail(c, "451 4.3.0 the message could not be read from the spool", move_on::none);
            return;
        }
        c.body_off += b.size();
        std::string out;
        stuff(b, out, c.bol);
        c.deadline_ms = wall::now_ms_coarse() + command_ms;
        conn_send(c, std::move(out));
    });
}

void delivery::conn_chunk(out_conn& c)
{
    if (c.bdat_last || c.bdat_code)
        return;
    const entry_ptr e = c.cur->e;
    std::string sig;
    if (!c.signature_sent)
    {
        c.signature_sent = true;
        if (const auto it = m_signed.find(e->id); it != m_signed.end())
            sig = it->second;
    }
    const auto send = [this](out_conn& c, std::string sig, std::string_view b, bool last) {
        std::string out = "BDAT " + std::to_string(sig.size() + b.size()) + (last ? " LAST\r\n" : "\r\n");
        out.reserve(out.size() + sig.size() + b.size());
        out += sig;
        out.append(b);
        ++c.bdat_out;
        c.bdat_last = last;
        if (last)
        {
            c.state = out_conn::st::dot;
            c.deadline_ms = wall::now_ms_coarse() + final_ms;
        }
        else
            c.deadline_ms = wall::now_ms_coarse() + command_ms;
        conn_send(c, std::move(out));
    };
    if (c.body_off >= e->body_len)
    {
        send(c, std::move(sig), {}, true);
        return;
    }
    c.reading = true;
    const uint64_t id = c.id, gen = c.gen;
    m_run.queue().read(e, c.body_off, body_chunk,
                       [this, id, gen, send, sig = std::move(sig), alive = m_alive](bool ok, std::string_view b) mutable {
                           if (!*alive)
                               return;
                           const auto it = m_conns.find(id);
                           if (it == m_conns.end() || it->second->gen != gen)
                               return;
                           out_conn& c = *it->second;
                           c.reading = false;
                           // A chunk refused while this one was read ended the message.
                           if (!c.cur || c.state != out_conn::st::body || c.bdat_code)
                               return;
                           if (!ok || b.empty())
                           {
                               conn_fail(c, "451 4.3.0 the message could not be read from the spool", move_on::none);
                               return;
                           }
                           c.body_off += b.size();
                           send(c, std::move(sig), b, c.body_off >= c.cur->e->body_len);
                       });
}

void delivery::conn_end_item(out_conn& c, int code, const std::string& text)
{
    if (!c.cur)
        return;
    std::unique_ptr<item> it = std::move(c.cur);
    const bool data_answered = c.state == out_conn::st::dot;
    for (size_t t = 0; t < it->to.size(); ++t)
    {
        int rc = code;
        std::string rt = text;
        // A recipient its RCPT refused keeps that answer, whatever the end of the data was answered; under a refused
        // MAIL the RCPTs were answered for want of one, and MAIL's answer is every recipient's.
        if (c.mail_code / 100 != 2 && c.mail_code)
        {
            rc = c.mail_code;
            rt = c.mail_text;
        }
        else if (t < c.rcpt_code.size() && c.rcpt_code[t] && c.rcpt_code[t] / 100 != 2)
        {
            rc = c.rcpt_code[t];
            rt = c.rcpt_text[t];
        }
        result(*it, t, rc, rt.empty() ? std::to_string(rc) : rt, rc / 100 == 4 || rc == 0, c.dsn ? 0 : 2);
    }
    // A domain that takes its mail is given more connections, up to the most.
    if (data_answered && code / 100 == 2 && c.rcpt_ok > 0)
    {
        route& r = m_routes[c.route];
        r.hold_ms = 0;
        if (r.limit < per_route_max)
            ++r.limit;
    }
    if (--m_out[it->e->id] == 0)
        attempt_over(it->e);
    if (!data_answered && c.state == out_conn::st::transaction)
    {
        // What the refused transaction left is cleared before the next one.
        c.state = out_conn::st::rset;
        conn_send(c, "RSET\r\n");
        return;
    }
    c.state = out_conn::st::ready;
    conn_next(c);
}

delivery::move_on delivery::early_move(const out_conn& c)
{
    return c.state <= out_conn::st::greeting ? move_on::address
         : c.state < out_conn::st::ready     ? move_on::host
                                             : move_on::none;
}

void delivery::conn_fail(out_conn& c, const std::string& why, move_on next)
{
    c.last_error = why;
    // Before a transaction began the message is no one's yet: the next address or exchanger is tried with it.
    if (next != move_on::none && c.state < out_conn::st::ready && !m_stopped)
    {
        if (c.ssl)
        {
            tls_context::free_ssl(c.ssl);
            c.ssl = nullptr;
        }
        if (c.fd >= 0)
        {
            ::shutdown(c.fd, SHUT_RDWR);
            m_loop.close_fd(c.fd);
            c.fd = -1;
        }
        c.handshaken = c.after_starttls = c.verified = false;
        c.pipelining = c.starttls = c.eightbit = c.utf8 = c.auth_plain = c.auth_login = c.chunking = c.dsn = false;
        c.size_max = 0;
        c.rcpt_max = 0;
        c.requiretls = false;
        c.login_step = 0;
        c.in.clear();
        c.reply_text.clear();
        c.outq.clear();
        c.out_off = 0;
        c.writing = false;
        c.expect.clear();
        ++c.gen;
        if (next == move_on::host)
        {
            ++c.host_at;
            c.resolved = false;
        }
        else
            ++c.addr_at;
        conn_connect(c);
        return;
    }
    if (c.cur)
    {
        std::unique_ptr<item> it = std::move(c.cur);
        const bool permanent = why.size() > 0 && why[0] == '5';
        for (size_t t = 0; t < it->to.size(); ++t)
            result(*it, t, permanent ? 550 : 451, why, !permanent);
        if (--m_out[it->e->id] == 0)
            attempt_over(it->e);
    }
    conn_close(c);
}

void delivery::conn_close(out_conn& c)
{
    const uint64_t id = c.id;
    const std::string key = c.route;
    if (c.cur)
    {
        // A message still on the connection is put back for the next.
        m_routes[key].waiting.push_front(std::move(*c.cur));
        c.cur.reset();
    }
    if (c.ssl)
    {
        tls_context::free_ssl(c.ssl);
        c.ssl = nullptr;
    }
    if (c.fd >= 0)
    {
        ::shutdown(c.fd, SHUT_RDWR);
        m_loop.close_fd(c.fd);
        c.fd = -1;
    }
    auto& r = m_routes[key];
    if (r.active)
        --r.active;
    m_conns.erase(id);
    if (!m_stopped)
        pump(r);
}

}   // namespace socketley::mail
