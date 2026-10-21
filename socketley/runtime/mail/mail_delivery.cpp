#include "mail_delivery.h"

#include <algorithm>
#include <cerrno>
#include <cstring>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <resolv.h>
#include <sys/socket.h>
#include <unistd.h>

#include "mail_compose.h"
#include "mail_instance.h"
#include "mail_run.h"
#include "../dns/dns_wire.h"
#include "../../shared/crypto/tls_context.h"
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

constexpr uint32_t per_route = 4;
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
    bool pipelining{false}, starttls{false}, eightbit{false}, utf8{false}, auth_plain{false};
    uint64_t size_max{0};
    std::string in;
    int reply_code{0};
    std::string reply_text;
    std::deque<std::string> outq;
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
    if (!m_tls->init_client())
        m_tls.reset();
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
        if (const size_t slash = rest.find('/'); slash != std::string_view::npos)
            rest = rest.substr(0, slash);
        if (const size_t at = rest.rfind('@'); at != std::string_view::npos)
        {
            const std::string_view cred = rest.substr(0, at);
            const size_t colon = cred.find(':');
            m_relay_user = std::string(cred.substr(0, colon));
            m_relay_pass = colon == std::string_view::npos ? std::string() : std::string(cred.substr(colon + 1));
            rest = rest.substr(at + 1);
        }
        if (const size_t colon = rest.rfind(':'); colon != std::string_view::npos && rest.front() != '[')
        {
            const std::string port(rest.substr(colon + 1));
            m_relay_port = static_cast<uint16_t>(std::atoi(port.c_str()));
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
    // A key of the runtime's own, made at its first start, signs the mail its domains send.
    if (!m_run.domains().empty())
    {
        m_key = dkim::load_or_make(m_run.state_dir() + "/dkim." + m_selector + ".key", why);
        if (!m_key)
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
    for (auto it = m_due.begin(); it != m_due.end();)
        it = it->second == e->id ? m_due.erase(it) : std::next(it);
    m_due.emplace(at, e->id);
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
    for (auto it = m_due.begin(); it != m_due.end();)
        it = it->second == id ? m_due.erase(it) : std::next(it);
    m_signed.erase(id);
    m_pending_targets.erase(id);
}

void delivery::on_loop_turn()
{
    if (m_stopped)
        return;
    std::vector<std::string> keys;
    for (auto& [key, r] : m_routes)
        if (!r.waiting.empty())
            keys.push_back(key);
    for (const auto& k : keys)
        pump(m_routes[k]);
}

void delivery::tick(int64_t now)
{
    if (m_stopped)
        return;
    while (!m_due.empty() && m_due.begin()->first <= now)
    {
        const std::string id = m_due.begin()->second;
        m_due.erase(m_due.begin());
        if (const entry_ptr e = m_run.queue().find(id))
            dispatch(e);
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
                conn_fail(c, "no answer from " + c.host + " in time", c.state <= out_conn::st::greeting);
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
                m_run.queue().mark(*e, i, rcpt_state::failed, "550 5.1.1 no such user here");
                continue;
            }
            if (r.k == route_to::sink)
            {
                m_run.queue().mark(*e, i, rcpt_state::delivered, "taken as a bounce");
                continue;
            }
            const std::string dom = a.domain.empty() ? (m_run.domains().empty() ? "" : m_run.domains().front())
                                                     : a.domain;
            if (const auto* t = m_run.aliases().find(a.local, dom))
                targets = *t;
            else
                targets.push_back(r.target);
        }
        else
            targets.push_back(a.text());
        for (const auto& t : targets)
        {
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
    sign_then(e, [this, e, by_route = std::move(by_route), alive = m_alive]() mutable {
        if (!*alive || m_stopped)
            return;
        for (auto& [key, it] : by_route)
        {
            route& r = m_routes[key];
            r.key = key;
            r.waiting.push_back(std::move(it));
            pump(r);
        }
    });
}

void delivery::deliver_local(const entry_ptr& e, const target& t)
{
    // A mailbox named by an alias, which needs the mailboxes of --storage.
    item it;
    it.e = e;
    it.to.push_back(t);
    result(it, 0, 550, "550 5.1.1 the mailbox " + t.addr + " is kept nowhere: this runtime has no --storage", false);
    if (--m_out[e->id] == 0)
        attempt_over(e);
}

void delivery::pump(route& r)
{
    if (m_stopped || r.waiting.empty())
        return;
    if (!r.dead.empty())
    {
        while (!r.waiting.empty())
        {
            item it = std::move(r.waiting.front());
            r.waiting.pop_front();
            for (size_t t = 0; t < it.to.size(); ++t)
                result(it, t, 550, r.dead, false);
            if (--m_out[it.e->id] == 0)
                attempt_over(it.e);
        }
        return;
    }
    const int64_t now = wall::now_ms_coarse();
    if (!r.looked || now - r.looked_ms > lookup_ms)
    {
        lookup(r);
        if (!r.looked)
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
    // As many connections as messages wait, up to the limits.
    while (!r.waiting.empty() && r.active < per_route && m_conns.size() < all_routes && r.active < r.waiting.size())
        open_conn(r);
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
    bool nx = false;
    const dns_client::state st = dns_client::here().ask_records(r.key, dns::type::MX, recs, nx);
    if (st == dns_client::state::pending)
    {
        r.looking = true;
        poll_lookups();
        return;
    }
    const auto take = [this](route& rt, std::vector<dns_client::record> rs, bool no_domain) {
        rt.looking = false;
        rt.looked = true;
        rt.looked_ms = wall::now_ms_coarse();
        ++m_lookups;
        rt.hosts.clear();
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
        std::sort(rs.begin(), rs.end(), [](const auto& a, const auto& b) { return a.pref < b.pref; });
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
                            uint8_t buf[8192];
                            const int n = ::res_query(key.c_str(), C_IN, T_MX, buf, sizeof buf);
                            if (n < 0)
                            {
                                *no = h_errno == HOST_NOT_FOUND;
                                *ok = *no || h_errno == NO_DATA;
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
                                rt.looking = false;
                                rt.looked = true;
                                rt.looked_ms = wall::now_ms_coarse() - lookup_ms + 60000;
                                rt.hosts = {key};
                            }
                            else
                                take(rt, std::move(*out), *no);
                            pump(rt);
                        });
}

void delivery::poll_lookups()
{
    if (m_polling)
        return;
    bool any = false;
    for (auto& [k, r] : m_routes)
        any = any || (r.looking && !m_relay);
    for (auto& [id, c] : m_conns)
        any = any || c->state == out_conn::st::resolving;
    if (!any)
        return;
    m_polling = m_io.after(std::chrono::milliseconds(2), [this, alive = m_alive](int64_t) {
        if (!*alive)
            return;
        m_polling = false;
        for (auto& [k, r] : m_routes)
            if (r.looking && !m_relay)
            {
                r.looked = false;
                lookup(r);
                if (r.looked)
                    pump(r);
            }
        std::vector<uint64_t> ids;
        for (auto& [id, c] : m_conns)
            if (c->state == out_conn::st::resolving)
                ids.push_back(id);
        for (const uint64_t id : ids)
            if (const auto it = m_conns.find(id); it != m_conns.end())
                conn_connect(*it->second);
        poll_lookups();
    });
}

void delivery::sign_then(const entry_ptr& e, std::function<void()> go)
{
    if (!m_key || m_signed.count(e->id) || e->body_len > m_run.owner().get_max_size() + (1u << 20))
    {
        go();
        return;
    }
    auto& waiting = m_signing[e->id];
    waiting.push_back(std::move(go));
    if (waiting.size() > 1)
        return;
    auto j = std::make_shared<sign_job>();
    j->e = e;
    j->data.reserve(e->body_len);
    sign_read(j);
}

void delivery::sign_read(const std::shared_ptr<sign_job>& j)
{
    // The message whole, from memory or read back a piece at a time, whether each piece comes at once or later.
    j->looping = true;
    while (!j->failed && j->data.size() < j->e->body_len)
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
    const std::string dom = j->failed ? std::string() : signing_domain(header_value(header_block(j->data), "From"));
    if (dom.empty())
    {
        // Mail not from one of its domains, or not read back, goes unsigned.
        m_signed[id];
        auto gos = std::move(m_signing[id]);
        m_signing.erase(id);
        for (auto& g : gos)
            g();
        return;
    }
    auto sig = std::make_shared<std::string>();
    m_run.pool().submit(1, [j, sig, dom, sel = m_selector, key = m_key] {
                            *sig = dkim::sign(j->data, dom, sel, key.get(), wall::now_ms() / 1000);
                        },
                        [this, id, sig, alive = m_alive] {
                            if (!*alive)
                                return;
                            m_signed[id] = std::move(*sig);
                            auto gos = std::move(m_signing[id]);
                            m_signing.erase(id);
                            for (auto& g : gos)
                                g();
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

std::string delivery::dkim_record() const
{
    return m_key ? dkim::public_record(m_key.get()) : std::string();
}

// ── Results ─────────────────────────────────────────────────────────────────

void delivery::result(const item& it, size_t t, int code, const std::string& text, bool temporary)
{
    const size_t i = it.to[t].rcpt;
    spool_entry& e = *it.e;
    if (i >= e.rcpts.size() || e.rcpts[i].state != rcpt_state::waiting)
        return;
    if (code / 100 == 2)
    {
        auto& pending = m_pending_targets[e.id];
        if (i < pending.size() && pending[i] > 0 && --pending[i] > 0)
            return;
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

void delivery::attempt_over(const entry_ptr& e)
{
    m_out.erase(e->id);
    if (e->waiting() == 0)
    {
        finished(e);
        return;
    }
    const int64_t now = wall::now_ms_coarse();
    if (now - e->at_ms > static_cast<int64_t>(m_run.owner().get_queue_lifetime()) * 1000)
    {
        for (size_t i = 0; i < e->rcpts.size(); ++i)
            if (e->rcpts[i].state == rcpt_state::waiting)
                m_run.queue().mark(*e, i, rcpt_state::failed,
                                   "given up after " + std::to_string(e->attempts + 1) + " tries: " +
                                       (e->rcpts[i].why.empty() ? std::string("no answer") : e->rcpts[i].why));
        finished(e);
        return;
    }
    constexpr size_t n = std::size(retry_delays);
    const uint32_t delay = retry_delays[std::min<size_t>(e->attempts, n - 1)];
    m_run.queue().retry(*e, e->attempts + 1, now + static_cast<int64_t>(delay) * 1000);
    schedule(e, e->next_ms);
}

void delivery::finished(const entry_ptr& e)
{
    bool failed = false;
    for (const auto& r : e->rcpts)
        failed = failed || r.state == rcpt_state::failed;
    m_signed.erase(e->id);
    m_pending_targets.erase(e->id);
    if (failed && !e->bounce && !e->from.empty())
    {
        bounce(e);
        return;
    }
    m_run.queue().remove(e->id);
}

void delivery::bounce(const entry_ptr& e)
{
    const uint32_t want = static_cast<uint32_t>(std::min<uint64_t>(e->body_len, 65536));
    m_run.queue().read(e, 0, want, [this, e, alive = m_alive](bool ok, std::string_view head) {
        if (!*alive)
            return;
        const std::string headers(ok ? header_block(head) : std::string_view{});
        const std::string host = m_run.hostname();
        const std::string b = "=_skl_" + socketley::random_hex(12);
        const int64_t now = wall::now_ms();
        std::string text, status;
        for (const auto& r : e->rcpts)
        {
            if (r.state != rcpt_state::failed)
                continue;
            text += "<" + r.addr + ">: " + r.why + "\r\n";
            std::string code = "5.0.0";
            for (size_t i = 0; i + 4 < r.why.size(); ++i)
                if (r.why[i] == '5' && r.why[i + 1] == '.' && std::isdigit(static_cast<unsigned char>(r.why[i + 2])))
                {
                    const size_t sp = r.why.find(' ', i);
                    code = r.why.substr(i, sp - i);
                    break;
                }
            status += "\r\nFinal-Recipient: rfc822; " + r.addr + "\r\nAction: failed\r\nStatus: " + code +
                      "\r\nDiagnostic-Code: smtp; " + r.why + "\r\n";
        }
        std::string msg = "From: Mail Delivery System <MAILER-DAEMON@" + host + ">\r\nTo: <" + e->from +
                          ">\r\nSubject: Undelivered Mail Returned to Sender\r\nDate: " + rfc5322_date(now) +
                          "\r\nMessage-ID: <" + e->id + ".bounce@" + host +
                          ">\r\nAuto-Submitted: auto-replied\r\nMIME-Version: 1.0\r\n"
                          "Content-Type: multipart/report; report-type=delivery-status; boundary=\"" + b +
                          "\"\r\n\r\n--" + b +
                          "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nThis is the mail system at " + host +
                          ".\r\n\r\nYour message could not be delivered to one or more of its recipients:\r\n\r\n" +
                          text + "\r\n--" + b + "\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; " +
                          host + "\r\nArrival-Date: " + rfc5322_date(e->at_ms) + "\r\n" + status + "\r\n--" + b +
                          "\r\nContent-Type: text/rfc822-headers\r\n\r\n" + headers + "\r\n--" + b + "--\r\n";
        ++m_bounced;
        const std::string id = e->id;
        m_run.queue_message("", {e->from}, std::move(msg), true, {}, [this, id, alive](bool, std::string) {
            if (*alive)
                m_run.queue().remove(id);
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
    put(out, "mail_out_connections", m_conns.size());
    put(out, "mail_out_connects", m_connects);
    put(out, "mail_out_tls", m_tls_sessions);
    put(out, "mail_out_transactions", m_transactions);
    put(out, "mail_mx_lookups", m_lookups);
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
                conn_fail(c, c.last_error.empty() ? "no exchanger of " + r.key + " could be reached" : c.last_error,
                          false);
                return;
            }
            c.host = r.hosts[c.host_at];
            std::vector<endpoint> found;
            const dns_client::state st = dns_client::here().ask(c.host, AF_UNSPEC, found);
            if (st == dns_client::state::pending)
            {
                c.state = out_conn::st::resolving;
                poll_lookups();
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
        conn_fail(c, "451 4.3.0 no socket could be made", false);
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
        conn_fail(c, "451 4.3.0 the ring is full", false);
}

void delivery::conn_connected(out_conn& c, int64_t res)
{
    if (res < 0)
    {
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
            conn_fail(c, "451 4.7.0 no TLS session could be made for " + c.host, false);
            return;
        }
        c.state = out_conn::st::handshake;
        tls_context::do_handshake(c.ssl);
        std::string hello;
        tls_context::take_out(c.ssl, hello);
        c.outq.push_back(std::move(hello));
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
                    conn_fail(c, "451 4.4.2 " + c.host + " closed the connection", c.state <= out_conn::st::greeting);
                return;
            }
            conn_got(c, buf.get(), static_cast<size_t>(res));
            if (m_conns.count(id) && m_conns[id]->gen == gen)
                conn_receive(*m_conns[id]);
        }))
        conn_fail(c, "451 4.3.0 the ring is full", false);
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
            conn_fail(c, "451 4.7.0 the TLS record layer took no more", false);
            return;
        }
        if (!c.handshaken)
        {
            const int r = tls_context::do_handshake(c.ssl);
            std::string out;
            tls_context::take_out(c.ssl, out);
            if (!out.empty())
            {
                c.outq.push_back(std::move(out));
                conn_write(c);
            }
            if (r < 0)
            {
                conn_fail(c, "451 4.7.0 the TLS handshake with " + c.host + " failed", !c.after_starttls);
                return;
            }
            if (r == 0)
                return;
            c.handshaken = true;
            c.verified = SSL_get_verify_result(c.ssl) == X509_V_OK;
            ++m_tls_sessions;
            if (c.after_starttls)
            {
                // The conversation starts over inside TLS (RFC 3207 4.2).
                c.state = out_conn::st::ehlo;
                c.pipelining = c.starttls = c.eightbit = c.utf8 = c.auth_plain = false;
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
                    conn_fail(c, "451 4.7.0 TLS failed on the connection to " + c.host, false);
                    return;
                }
                break;
            }
            c.in.append(buf, static_cast<size_t>(r));
        }
    }
    else
        c.in.append(p, n);
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
        c.outq.push_back(std::move(out));
    }
    else
        c.outq.push_back(std::move(bytes));
    conn_write(c);
}

void delivery::conn_write(out_conn& c)
{
    while (!c.writing && !c.outq.empty() && c.outq.front().size() == c.out_off)
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
    const std::string& b = c.outq.front();
    const uint64_t id = c.id, gen = c.gen;
    if (!m_io.pwrite(c.fd, b.data() + c.out_off, static_cast<uint32_t>(b.size() - c.out_off), file_io::at_stream,
                     [this, id, gen, alive = m_alive](int64_t res) {
                         if (!*alive)
                             return;
                         const auto it = m_conns.find(id);
                         if (it == m_conns.end() || it->second->gen != gen)
                             return;
                         out_conn& c = *it->second;
                         c.writing = false;
                         if (res <= 0)
                         {
                             conn_fail(c, "451 4.4.2 the connection to " + c.host + " broke", false);
                             return;
                         }
                         c.out_off += static_cast<size_t>(res);
                         conn_write(c);
                     }))
    {
        c.writing = false;
        conn_fail(c, "451 4.3.0 the ring is full", false);
    }
}

void delivery::conn_reply(out_conn& c, int code, std::string text)
{
    using st = out_conn::st;
    const bool ok = code / 100 == 2;
    c.deadline_ms = wall::now_ms_coarse() + command_ms;
    const std::string said = std::to_string(code) + " " + text;
    switch (c.state)
    {
        case st::greeting:
            if (code != 220)
            {
                conn_fail(c, "451 4.4.0 " + c.host + " greeted with " + said, true);
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
                conn_fail(c, "451 4.4.0 " + c.host + " refused HELO: " + said, true);
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
                    else if (line.starts_with("size"))
                        c.size_max = static_cast<uint64_t>(std::atoll(line.c_str() + 4));
                    else if (line.starts_with("auth ") || line.starts_with("auth="))
                        c.auth_plain = line.find("plain") != std::string::npos;
                }
            }
            const bool loopback = c.host == "localhost" || c.host.starts_with("127.") || c.host == "::1";
            if (!c.ssl && c.starttls && m_tls)
            {
                c.state = st::starttls;
                conn_send(c, "STARTTLS\r\n");
                return;
            }
            if (m_relay && !m_relay_user.empty())
            {
                if (!c.ssl && !loopback)
                {
                    conn_fail(c, "451 4.7.0 the relay " + c.host + " offers no TLS, and its password is not sent "
                                 "in the clear", false);
                    return;
                }
                c.state = st::auth;
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
                // Refused: the mail goes in the clear, as it would to a server that never offered TLS.
                c.starttls = false;
                c.state = st::ehlo;
                conn_reply(c, 250, "");
                return;
            }
            c.ssl = m_tls->create_ssl_client(c.host);
            if (!c.ssl)
            {
                conn_fail(c, "451 4.7.0 no TLS session could be made for " + c.host, false);
                return;
            }
            // An exchanger's certificate is not checked: TLS against an eavesdropper, as every MTA speaks it unless
            // DANE or MTA-STS say more; a smarthost's is.
            if (!m_relay)
                SSL_set_verify(c.ssl, SSL_VERIFY_NONE, nullptr);
            c.after_starttls = true;
            c.state = st::handshake;
            {
                tls_context::do_handshake(c.ssl);
                std::string hello;
                tls_context::take_out(c.ssl, hello);
                c.outq.push_back(std::move(hello));
                conn_write(c);
            }
            return;
        case st::auth:
            if (code != 235)
            {
                conn_fail(c, "530 5.7.8 the relay " + c.host + " refused the credentials: " + said, false);
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
                // Nobody took it: each recipient is told what its own command was answered.
                conn_end_item(c, c.mail_code / 100 != 2 ? c.mail_code : code,
                              c.mail_code / 100 != 2 ? c.mail_text : said);
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
        case st::dot:
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
    const auto sig = m_signed.find(e.id);
    const uint64_t size = e.body_len + (sig == m_signed.end() ? 0 : sig->second.size());
    if (c.size_max && size > c.size_max)
    {
        conn_end_item(c, 552, "552 5.3.4 the message is larger than " + c.host + " takes");
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
    std::string mail = "MAIL FROM:<" + e.from + ">";
    if (c.size_max)
        mail += " SIZE=" + std::to_string(size);
    if (c.eightbit)
        mail += " BODY=8BITMIME";
    if (utf8 && c.utf8)
        mail += " SMTPUTF8";
    mail += "\r\n";
    std::vector<std::string> cmds;
    cmds.push_back(std::move(mail));
    for (const auto& t : it.to)
        cmds.push_back("RCPT TO:<" + t.addr + ">\r\n");
    cmds.push_back("DATA\r\n");
    if (c.pipelining)
    {
        std::string all;
        for (size_t i = 0; i < cmds.size(); ++i)
        {
            all += cmds[i];
            c.expect.push_back(i == 0 ? 'M' : i + 1 == cmds.size() ? 'D' : 'R');
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
            conn_fail(c, "451 4.3.0 the message could not be read from the spool", false);
            return;
        }
        c.body_off += b.size();
        std::string out;
        stuff(b, out, c.bol);
        c.deadline_ms = wall::now_ms_coarse() + command_ms;
        conn_send(c, std::move(out));
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
        // A recipient its RCPT refused keeps that answer, whatever the end of the data was answered.
        if (t < c.rcpt_code.size() && c.rcpt_code[t] && c.rcpt_code[t] / 100 != 2)
        {
            rc = c.rcpt_code[t];
            rt = c.rcpt_text[t];
        }
        result(*it, t, rc, rt.empty() ? std::to_string(rc) : rt, rc / 100 == 4 || rc == 0);
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

void delivery::conn_fail(out_conn& c, const std::string& why, bool next_address)
{
    c.last_error = why;
    if (next_address && c.state <= out_conn::st::greeting)
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
        c.handshaken = c.after_starttls = false;
        c.in.clear();
        c.reply_text.clear();
        c.outq.clear();
        c.out_off = 0;
        c.writing = false;
        c.expect.clear();
        ++c.gen;
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
