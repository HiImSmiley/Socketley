#include "tunnel_run.h"
#include "tunnel_instance.h"
#include "../../shared/net/socket_tuning.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <filesystem>

#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../idp/idp_session.h"
#include "../proxy/proxy_auth.h"
#include "../../shared/http/cookie.h"
#include "../../shared/http/request_head.h"
#include "../../shared/persist/replaced_file.h"
#include "../../shared/net/endpoint.h"
#include "../../shared/net/peer_address.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/util/ascii.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/random_id.h"
#include "../../shared/util/text_list.h"
#include "../../shared/util/wall_clock.h"

namespace socketley::tunnel
{

namespace
{

constexpr size_t max_front = 1024;
constexpr size_t max_legs = 4096;
constexpr size_t max_head = 16 * 1024;
constexpr int64_t ping_every = 15;
constexpr int64_t silent_limit = 45;
constexpr int64_t max_backoff = 30;
// A share holds two hours unless asked for less or more, a day at most, and each person and the edge hold only so many.
constexpr int64_t share_default_s = 2 * 3600;
constexpr int64_t share_max_s = 24 * 3600;
constexpr size_t shares_per_person = 3;
constexpr size_t shares_per_edge = 32;
// A UDP flow is forgotten after a minute of silence, a service or an agent holds so many at once, and a datagram is
// dropped rather than queued behind more than this, which a game would rather lose than wait for.
constexpr int64_t flow_idle_s = 60;
constexpr size_t max_flows = 1024;
constexpr size_t udp_queue_limit = 256 * 1024;
// What one receive takes: any datagram at an edge's port, and at an agent's flow what a home service answers with.
constexpr size_t edge_udp_buf = 65536;
constexpr size_t flow_udp_buf = 9216;

// A UDP socket bound to `on`, or connected to it, armed by the caller; null with `why`.
std::unique_ptr<udp_port> open_udp(const endpoint& on, bool connect_to, size_t buf, std::string& why)
{
    const int fd = ::socket(on.addr.ss_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    const sockaddr* a = reinterpret_cast<const sockaddr*>(&on.addr);
    if (fd < 0 || (connect_to ? ::connect(fd, a, on.len) : ::bind(fd, a, on.len)) < 0)
    {
        why = std::strerror(errno);
        if (fd >= 0)
            ::close(fd);
        return nullptr;
    }
    auto p = std::make_unique<udp_port>();
    p->fd = fd;
    p->buf.resize(buf);
    return p;
}

std::string peer_text(const sockaddr_storage& a)
{
    char buf[INET6_ADDRSTRLEN] = {};
    if (a.ss_family == AF_INET)
    {
        const auto* v = reinterpret_cast<const sockaddr_in*>(&a);
        ::inet_ntop(AF_INET, &v->sin_addr, buf, sizeof buf);
        return std::string(buf) + ":" + std::to_string(ntohs(v->sin_port));
    }
    if (a.ss_family == AF_INET6)
    {
        const auto* v = reinterpret_cast<const sockaddr_in6*>(&a);
        ::inet_ntop(AF_INET6, &v->sin6_addr, buf, sizeof buf);
        return "[" + std::string(buf) + "]:" + std::to_string(ntohs(v->sin6_port));
    }
    return "local";
}

// Who a request came from: behind the entrance, a hop on this machine, the client the entrance heard it from.
std::string client_of(const sockaddr_storage& peer, std::string_view head)
{
    int fields = 0;
    const std::string_view xff = http_last_forwarded_hop(http_request_field(head, "x-forwarded-for", fields));
    return is_loopback(peer) && fields == 1 && !xff.empty() ? std::string(xff) : peer_text(peer);
}

// `host:port` with a literal address or localhost, as --forward and --offer name their targets.
bool target_endpoint(std::string_view target, endpoint& out)
{
    const size_t colon = target.rfind(':');
    if (colon == std::string_view::npos || colon == 0)
        return false;
    uint32_t port = 0;
    const std::string_view p = target.substr(colon + 1);
    const auto [end, ec] = std::from_chars(p.data(), p.data() + p.size(), port);
    if (ec != std::errc{} || end != p.data() + p.size() || port == 0 || port > 65535)
        return false;
    std::string host(target.substr(0, colon));
    if (host.size() > 2 && host.front() == '[' && host.back() == ']')
        host = host.substr(1, host.size() - 2);
    if (host == "localhost")
        host = "127.0.0.1";
    return literal_endpoint(host, static_cast<uint16_t>(port), out);
}

// The value of an HTTP header in a head, empty when it is absent.
std::string_view header_of(std::string_view head, std::string_view name)
{
    for (size_t pos = head.find("\r\n"); pos != std::string_view::npos && pos + 2 < head.size();)
    {
        const size_t start = pos + 2;
        const size_t end = head.find("\r\n", start);
        const std::string_view line = head.substr(start, end == std::string_view::npos ? end : end - start);
        if (line.size() > name.size() && line[name.size()] == ':' &&
            std::equal(name.begin(), name.end(), line.begin(),
                       [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) ==
                                                   std::tolower(static_cast<unsigned char>(b)); }))
            return trim_blanks(line.substr(name.size() + 1));
        pos = end;
    }
    return {};
}

// A visitor's request head as the agent, another machine, is given it: without the idp's cookies, which sign in
// wherever the idp is trusted, and without the Authorization the edge's auth took when it has one.
std::string forwarded_head(std::string_view head, bool drop_authorization)
{
    size_t pos = head.find("\r\n");
    if (pos == std::string_view::npos)
        return std::string(head);
    pos += 2;
    std::string out(head.substr(0, pos));
    while (pos < head.size())
    {
        const size_t nl = head.find("\r\n", pos);
        if (nl == std::string_view::npos)
            break;
        const std::string_view field = head.substr(pos, nl - pos);
        pos = nl + 2;
        const size_t colon = field.find(':');
        const std::string_view name = field.substr(0, colon);
        if (drop_authorization && ascii::iequals(name, "authorization"))
            continue;
        if (colon != std::string_view::npos && ascii::iequals(name, "cookie"))
        {
            const std::string kept = http::without_cookies(field.substr(colon + 1), {socketley::idp::session_cookie_name,
                                                                                     socketley::idp::known_cookie_name});
            if (!kept.empty())
                out.append("Cookie: ").append(kept).append("\r\n");
            continue;
        }
        out.append(field).append("\r\n");
    }
    return out;
}

struct front_conn : http::server_conn
{
    std::shared_ptr<link> l;
};

struct upstream_conn : http::server_conn
{
    std::shared_ptr<link> l;
    SSL* ssl{nullptr};
    bool handshaken{false};
    std::string head;
    ~upstream_conn() override
    {
        if (ssl)
            SSL_free(ssl);
    }
};

}   // namespace

// ─── Links ──────────────────────────────────────────────────────────────────

link::link(tunnel_run& r, kind kd, std::string w, const std::shared_ptr<http::server_conn>& t)
    : run(r), k(kd), who(std::move(w)), s(kd == kind::edge, *this), transport(t), last_heard(wall::now_sec())
{
    if (t && t->fd >= 0 && socket_tuning::fit_to_path(t->fd))
        out_high = 256 * 1024;
}

std::shared_ptr<leg> link::leg_of(uint32_t stream)
{
    const auto it = legs.find(stream);
    return it == legs.end() ? nullptr : it->second;
}

void link::on_hello(const fields&) {}

void link::on_open(uint32_t stream, std::string_view target, std::string_view peer)
{
    // A person names a --forward target, and the edge names one of the agent's offers; an agent opens nothing.
    if (k == kind::agent)
    {
        s.reset(stream, reset_code::refused, out);
        return;
    }
    run.dial_leg(*this, stream, target, peer);
}

void link::on_data(uint32_t stream, std::string_view bytes)
{
    const auto g = leg_of(stream);
    if (!g || g->dead)
        return;
    if (g->await_101)
        run.upgrade_answered(g, bytes);
    g->out.append(bytes);
    g->unacked += bytes.size();
    run.m_c.bytes_out += bytes.size();
    g->srv->flush(g);
}

void link::on_close(uint32_t stream)
{
    if (const auto g = leg_of(stream))
    {
        g->far_closed = true;
        run.leg_done_writing(g);
    }
}

void link::on_reset(uint32_t stream, reset_code)
{
    if (const auto g = leg_of(stream))
        g->srv->close_conn(g);
}

void link::on_window(uint32_t stream)
{
    if (const auto g = leg_of(stream); g && g->waiting && !g->dead)
        g->srv->resume(g);
}

void link::on_pong(std::string_view) {}

void link::on_datagram(uint32_t flow, std::string_view service, std::string_view bytes)
{
    // An agent's datagram answers a visitor, the edge's is for an offer here, and a person carries no UDP.
    if (k == kind::agent)
        run.udp_from_agent(*this, flow, service, bytes);
    else if (k == kind::edge)
        run.udp_from_edge(*this, flow, service, bytes);
}

void link::on_goaway(std::string_view) {}

// ─── Legs ───────────────────────────────────────────────────────────────────

leg_hooks::leg_hooks(tunnel_run& r, std::string a, service sv)
    : run(r), agent(std::move(a)), svc(std::move(sv)), srv(r.m_loop, &r, r.m_owner, *this, max_legs)
{
    if (svc.http)
        for (const std::string_view method : auth_methods(svc.auth))
        {
            auth.push_back(std::make_unique<proxy_auth>());
            auth.back()->configure(method, r.m_owner.get_name());
        }
}

leg_hooks::~leg_hooks() = default;

std::shared_ptr<http::server_conn> leg_hooks::make_conn()
{
    auto g = std::make_shared<leg>();
    g->srv = &srv;
    // A dialler's legs carry what a target answers, which is no request to read.
    g->gated = !agent.empty() && svc.http;
    return g;
}

void leg_hooks::serve(const std::shared_ptr<http::server_conn>& c)
{
    const auto g = std::static_pointer_cast<leg>(c);
    if (g->gated)
        run.gate(*this, g);
    else
        run.pump(*g);
}

void leg_hooks::accepted(const std::shared_ptr<http::server_conn>& c)
{
    // An HTTP service's stream is opened by the first request let through, a TCP service's at once.
    const auto g = std::static_pointer_cast<leg>(c);
    if (!g->gated && !run.visitor(*this, g))
        srv.close_conn(g);
}

bool leg_hooks::written(const std::shared_ptr<http::server_conn>& c)
{
    const auto g = std::static_pointer_cast<leg>(c);
    if (g->l && g->unacked)
    {
        // The link's round trip, which tells a window that limits the stream from a reader that does.
        const auto t = g->l->transport.lock();
        const uint32_t rtt = t ? socket_tuning::rtt_us(t->fd) : 0;
        const auto now = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        g->l->s.consumed(g->stream, g->unacked, g->l->out, static_cast<uint64_t>(now), rtt);
        g->unacked = 0;
        run.flush_link(*g->l);
    }
    run.leg_done_writing(g);
    return false;
}

void leg_hooks::closing(const std::shared_ptr<http::server_conn>& c)
{
    auto& g = static_cast<leg&>(*c);
    link* l = g.l;
    if (!l)
        return;
    g.l = nullptr;
    l->s.reset(g.stream, g.why, l->out);
    l->legs.erase(g.stream);
    run.flush_link(*l);
}

bool leg_hooks::read_ended(const std::shared_ptr<http::server_conn>& c)
{
    const auto g = std::static_pointer_cast<leg>(c);
    // What was read before the end goes first, and the close after it once it has.
    g->near_closed = true;
    if (g->gated)
    {
        // A visitor no request of which went on has nothing to wait for, unless its refusal is still being written.
        if (!g->l)
            return g->refused || !g->refusal.empty();
        run.gate(*this, g);
    }
    else
        run.pump(*g);
    run.leg_done_writing(g);
    return true;
}

void leg_hooks::connected(const std::shared_ptr<http::server_conn>& c, int res)
{
    if (res < 0)
        static_cast<leg&>(*c).why = reset_code::unreachable;
}

void tunnel_run::pump(leg& g)
{
    if (!g.l || !g.l->s.is_open(g.stream))
    {
        g.in.clear();
        g.cleared = 0;
        return;
    }
    const size_t limit = g.gated ? g.cleared : g.in.size();
    const size_t backlog = link_backlog(*g.l);
    const size_t room = backlog < g.l->out_high ? g.l->out_high - backlog : 0;
    const size_t n = g.l->s.send(g.stream, std::string_view(g.in).substr(0, std::min(limit, room)), g.l->out);
    g.in.erase(0, n);
    if (g.gated)
        g.cleared -= n;
    m_c.bytes_in += n;
    // A stream out of credit stops its socket being read until the far side gives more, and one out of room until
    // the transport has written what is before it.
    g.waiting = g.gated ? g.cleared != 0 || !g.refusal.empty() : !g.in.empty();
    if (n == room && n < limit && !g.parked)
    {
        g.parked = true;
        g.l->parked.push_back(g.stream);
    }
    flush_link(*g.l);
    if (g.near_closed && (g.gated ? g.cleared == 0 : g.in.empty()))
    {
        g.l->s.close(g.stream, g.l->out);
        flush_link(*g.l);
    }
}

void tunnel_run::leg_done_writing(const std::shared_ptr<leg>& g)
{
    if (g->dead || g->cn_pending || g->unsent() != 0)
        return;
    // The refusal goes once the far side has answered everything before it, or at once when nothing went there.
    if (!g->refusal.empty() && (g->far_closed || !g->l))
    {
        g->out += g->refusal;
        g->refusal.clear();
        g->refused = true;
        g->srv->flush(g);
        return;
    }
    if (g->refused)
    {
        g->srv->close_conn(g);
        return;
    }
    if (g->far_closed && !g->shut && g->fd >= 0)
    {
        ::shutdown(g->fd, SHUT_WR);
        g->shut = true;
    }
    if (g->far_closed && g->near_closed && g->l)
        g->srv->close_conn(g);
}

void tunnel_run::dial_leg(link& l, uint32_t stream, std::string_view target, std::string_view peer)
{
    std::string addr;
    if (l.k == link::kind::person)
    {
        // Asked again at every stream, so a sign-in the idp took back since opens nothing, and a demoted admin no agent.
        const bool holds = person_holds(l);
        // Only a target the edge names, so a signed-in person reaches what it allows and nothing else.
        if (holds && std::find(m_forward.begin(), m_forward.end(), target) != m_forward.end())
            addr = std::string(target);
        // An admin may name an agent's TCP service, `pi/ssh`, carried as a visitor of the port this edge serves it on.
        else if (const size_t slash = target.find('/'); holds && l.admin && slash != std::string_view::npos)
            for (const agent& a : m_agents)
                if (a.joined && a.name == target.substr(0, slash))
                    for (const service& s : a.services)
                        if (const auto served = m_listeners.find(s.name); !s.http && s.name == target.substr(slash + 1) &&
                                                                          served != m_listeners.end() &&
                                                                          served->second->agent == a.name)
                            addr = (s.bind.empty() || s.bind == "0.0.0.0" ? std::string("127.0.0.1") : s.bind) + ":" +
                                   std::to_string(s.port);
    }
    else if (const auto it = m_offers.find(std::string(target)); it != m_offers.end())
        addr = it->second;
    endpoint ep;
    leg_hooks& dialler = m_edge ? *m_dial : *m_local;
    std::string why;
    std::shared_ptr<http::server_conn> c;
    // A TCP visitor reaches a service on this machine from 127.0.0.2, not as its own programs' 127.0.0.1, while the
    // entrance's HTTP hop ("local") stays 127.0.0.1 so that a service still takes X-Forwarded-For from it.
    const bool stranger = l.k == link::kind::edge && peer != "local";
    if (!addr.empty() && target_endpoint(addr, ep))
        c = dialler.srv.dial(ep.addr, ep.len, why,
                             stranger && ep.addr.ss_family == AF_INET && is_loopback(ep.addr) ? htonl(INADDR_LOOPBACK + 1)
                                                                                                : 0u);
    if (!c)
    {
        ++m_c.refused;
        l.s.reset(stream, addr.empty() ? reset_code::refused : reset_code::unreachable, l.out);
        flush_link(l);
        return;
    }
    auto g = std::static_pointer_cast<leg>(c);
    g->l = &l;
    g->stream = stream;
    l.legs[stream] = g;
    ++m_c.streams;
}

// ─── The run ────────────────────────────────────────────────────────────────

tunnel_run::tunnel_run(tunnel_instance& owner, event_loop& loop) : m_owner(owner), m_loop(loop) {}

tunnel_run::~tunnel_run()
{
    m_loop.deregister_owner(this);
}

bool tunnel_run::start(std::string& why)
{
    m_loop.register_owner(this);
    m_edge = m_owner.get_mode() == tunnel_instance::mode::edge;
    const bool ok = m_edge ? start_edge(why) : start_agent(why);
    if (ok)
        arm_tick();
    return ok;
}

void tunnel_run::stop()
{
    if (m_stopped)
        return;
    m_stopped = true;
    if (m_front)
        m_front->srv.stop();
    for (auto& [name, h] : m_listeners)
        h->srv.stop();
    if (m_dial)
        m_dial->srv.stop();
    if (m_up)
        m_up->srv.stop();
    if (m_local)
        m_local->srv.stop();
    for (auto& [name, u] : m_udp)
        retire_udp(std::move(u.port));
    m_udp.clear();
    for (auto& [id, f] : m_flows)
        retire_udp(std::move(f.port));
    m_flows.clear();
}

bool tunnel_run::drained() const
{
    return m_loop.owner_drained(this);
}

void tunnel_run::on_loop_turn()
{
    if (m_front)
        m_front->srv.on_loop_turn();
    for (auto& [name, h] : m_listeners)
        h->srv.on_loop_turn();
}

void tunnel_run::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req)
        return;
    if (req == &m_tick_req)
    {
        m_tick_armed = false;
        tick();
        return;
    }
    // The tunnel's own receives on UDP sockets, which no connection server here arms.
    if (req->type == op_recvmsg && req->owner == this)
    {
        on_udp(*reinterpret_cast<udp_port*>(req->buffer), cqe->res);
        return;
    }
    if ((m_front && m_front->srv.on_cqe(req, cqe)) || (m_dial && m_dial->srv.on_cqe(req, cqe)) ||
        (m_up && m_up->srv.on_cqe(req, cqe)) || (m_local && m_local->srv.on_cqe(req, cqe)))
        return;
    for (auto& [name, h] : m_listeners)
        if (h->srv.on_cqe(req, cqe))
            return;
    for (auto& h : m_retired)
        if (h->srv.on_cqe(req, cqe))
            return;
}

void tunnel_run::arm_tick()
{
    if (m_tick_armed || m_stopped)
        return;
    m_tick_req = io_request{};
    m_tick_req.owner = this;
    m_tick_req.type = op_timeout;
    m_tick_ts = {1, 0};
    m_tick_armed = m_loop.submit_timeout(&m_tick_ts, &m_tick_req);
}

void tunnel_run::tick()
{
    if (m_stopped)
        return;
    const int64_t now = wall::now_sec();
    // The links gathered first, since a ping or a close below changes the connections they are found among.
    std::vector<std::shared_ptr<link>> links;
    http::conn_server& transports = m_edge ? m_front->srv : m_up->srv;
    transports.for_each([&](const std::shared_ptr<http::server_conn>& c) {
        if (auto& l = m_edge ? static_cast<front_conn&>(*c).l : static_cast<upstream_conn&>(*c).l)
            links.push_back(l);
    });
    // Every link pinged while it is quiet, and one that answers nothing for long given up.
    for (const auto& l : links)
    {
        // A person's link ends with the sign-in it was opened by: signed out everywhere, disabled, reset or removed.
        if (m_edge && l->k == link::kind::person && !l->ending && !person_holds(*l))
        {
            LOG_INFO(("tunnel " + std::string(m_owner.get_name()) + ": the sign-in of \"" + l->who +
                      "\" no longer holds, and its link is closed").c_str());
            end_link(*l, "the sign-in no longer holds");
            continue;
        }
        if (now - l->last_heard > silent_limit)
        {
            if (auto t = l->transport.lock())
                transports.close_conn(t);
            continue;
        }
        if (now - l->last_ping >= ping_every)
        {
            l->last_ping = now;
            l->s.ping("tunnel..", l->out);
            flush_link(*l);
        }
    }
    if (m_edge)
    {
        // A share past its time ends with its link, which tells the person why; gathered first, as a close ends the
        // share and so changes the map.
        std::vector<std::shared_ptr<link>> due;
        for (auto& [name, sh] : m_shares)
            if (auto l = sh.l.lock(); l && now >= sh.until)
                due.push_back(std::move(l));
        for (const auto& l : due)
            if (!l->ending)
                end_link(*l, "the share's time is up");
        reload_agents();
        m_front->srv.sweep(now, 30);
    }
    else if (m_up->srv.empty() && now >= m_next_dial)
        dial_edge();
    tend_udp(now);
    arm_tick();
}

size_t tunnel_run::link_backlog(const link& l) const
{
    const auto t = l.transport.lock();
    return l.out.size() + (t ? t->unsent() : 0);
}

void tunnel_run::link_drained(link& l)
{
    std::vector<uint32_t> streams;
    streams.swap(l.parked);
    for (const uint32_t stream : streams)
    {
        const auto it = l.legs.find(stream);
        if (it == l.legs.end())
            continue;
        const std::shared_ptr<leg> g = it->second;
        g->parked = false;
        if (g->waiting && !g->dead)
            g->srv->resume(g);
    }
}

void tunnel_run::flush_link(link& l)
{
    if (l.out.empty())
        return;
    const auto t = l.transport.lock();
    if (!t || t->dead)
    {
        l.out.clear();
        return;
    }
    // The frames handed over whole when nothing waits before them, rather than copied behind nothing.
    const auto hand_over = [&](std::string& to) {
        if (to.empty())
            to.swap(l.out);
        else
            to.append(l.out);
        l.out.clear();
    };
    if (m_edge)
    {
        hand_over(t->out);
        m_front->srv.flush(t);
        return;
    }
    auto& u = static_cast<upstream_conn&>(*t);
    if (u.ssl)
    {
        size_t at = 0;
        while (at < l.out.size())
        {
            const int n = tls_context::ssl_write(u.ssl, l.out.data() + at,
                                                 static_cast<int>(std::min<size_t>(l.out.size() - at, 1 << 16)));
            if (n <= 0)
                break;
            at += static_cast<size_t>(n);
        }
        l.out.erase(0, at);
        tls_context::take_out(u.ssl, u.out);
    }
    else
        hand_over(u.out);
    m_up->srv.flush(t);
}

void tunnel_run::end_link(link& l, std::string_view why)
{
    const auto t = l.transport.lock();
    if (!t)
        return;
    l.ending = true;
    t->keep_alive = false;
    l.s.goaway(why, l.out);
    flush_link(l);
}

void tunnel_run::drop_link(link& l)
{
    std::vector<std::shared_ptr<leg>> legs;
    legs.reserve(l.legs.size());
    for (auto& [id, g] : l.legs)
        legs.push_back(g);
    l.legs.clear();
    for (auto& g : legs)
    {
        g->l = nullptr;
        g->srv->close_conn(g);
    }
    if (l.k == link::kind::agent)
        if (const auto it = m_agent_links.find(l.who); it != m_agent_links.end() && it->second.lock().get() == &l)
            m_agent_links.erase(it);
    if (!l.share.empty())
        end_share(l.share);
}

size_t tunnel_run::conn_count() const
{
    size_t n = 0;
    if (m_front)
        n += m_front->srv.size();
    for (const auto& [name, h] : m_listeners)
        n += h->srv.size();
    if (m_local)
        n += m_local->srv.size();
    return n;
}

std::string tunnel_run::stats() const
{
    size_t links = 0;
    if (m_front)
        m_front->srv.for_each([&](const std::shared_ptr<http::server_conn>& c) {
            links += static_cast<front_conn&>(*c).l ? 1 : 0;
        });
    if (m_up)
        links += m_up->srv.empty() ? 0 : 1;
    // The agents expected linked and those that are, so an alert can say one is gone.
    const size_t joined = static_cast<size_t>(std::count_if(m_agents.begin(), m_agents.end(),
                                                            [](const agent& a) { return a.joined; }));
    size_t connected = 0;
    for (const auto& [who, weak] : m_agent_links)
        connected += !who.starts_with("share:") && !weak.expired();
    return std::string("mode:") + (m_edge ? "edge" : "agent") + "\nlinks:" + std::to_string(links) +
           "\nagents:" + std::to_string(m_agents.size()) + "\nagents_joined:" + std::to_string(joined) +
           "\nagents_connected:" + std::to_string(connected) + "\nlinks_made:" + std::to_string(m_c.links) +
           "\nstreams:" + std::to_string(m_c.streams) + "\nrefused:" + std::to_string(m_c.refused) +
           "\njoined:" + std::to_string(m_c.joined) + "\nvisitors_refused:" + std::to_string(m_c.visitors_refused) +
           "\nshares:" + std::to_string(m_shares.size()) + "\nshared:" + std::to_string(m_c.shared) +
           "\nflows:" + std::to_string(flow_count()) + "\ndatagrams:" + std::to_string(m_c.datagrams) +
           "\ndatagrams_dropped:" + std::to_string(m_c.datagrams_dropped) +
           "\nbytes_in:" + std::to_string(m_c.bytes_in) + "\nbytes_out:" + std::to_string(m_c.bytes_out) + "\n";
}

// ─── UDP ────────────────────────────────────────────────────────────────────

bool tunnel_run::arm_udp(udp_port& p)
{
    p.iov = iovec{p.buf.data(), p.buf.size()};
    p.msg = msghdr{};
    p.msg.msg_name = &p.from;
    p.msg.msg_namelen = sizeof p.from;
    p.msg.msg_iov = &p.iov;
    p.msg.msg_iovlen = 1;
    p.req = io_request{this, reinterpret_cast<char*>(&p), p.fd, 0, op_recvmsg};
    p.pending = m_loop.submit_recvmsg(p.fd, &p.msg, &p.req);
    return p.pending;
}

void tunnel_run::on_udp(udp_port& p, int res)
{
    p.pending = false;
    if (p.dying)
    {
        const auto it = std::find_if(m_udp_dying.begin(), m_udp_dying.end(), [&](const auto& d) { return d.get() == &p; });
        if (it != m_udp_dying.end())
        {
            ::close(p.fd);
            m_udp_dying.erase(it);
        }
        return;
    }
    // A datagram cut to the buffer is not the one that was sent, and is dropped as a full socket drops one.
    if (res > 0 && !(p.msg.msg_flags & MSG_TRUNC) && p.got)
        p.got(p, std::string_view(p.buf.data(), static_cast<size_t>(res)));
    else if (res > 0)
        ++m_c.datagrams_dropped;
    if (!p.dying && !m_stopped)
        arm_udp(p);
}

void tunnel_run::retire_udp(std::unique_ptr<udp_port> p)
{
    if (!p)
        return;
    p->got = nullptr;
    if (!p->pending)
    {
        ::close(p->fd);
        return;
    }
    p->dying = true;
    if (!m_loop.submit_cancel_request(&p->req)) {}
    m_udp_dying.push_back(std::move(p));
}

void tunnel_run::send_datagram(link& l, uint32_t flow, std::string_view service, std::string_view bytes)
{
    const auto t = l.transport.lock();
    const size_t queued = l.out.size() + (t ? t->out.size() + (t->sending.size() - t->sent) : 0);
    if (!t || t->dead || queued > udp_queue_limit || !l.s.datagram(flow, service, bytes, l.out))
    {
        ++m_c.datagrams_dropped;
        return;
    }
    ++m_c.datagrams;
    m_c.bytes_in += bytes.size();
    flush_link(l);
}

void tunnel_run::udp_visitor(const std::string& service, const udp_port& p, std::string_view bytes)
{
    const auto it = m_udp.find(service);
    if (it == m_udp.end())
        return;
    udp_service& u = it->second;
    const int64_t now = wall::now_sec();
    std::string key(reinterpret_cast<const char*>(&p.from), p.msg.msg_namelen);
    uint32_t flow = 0;
    if (const auto f = u.by_peer.find(key); f != u.by_peer.end())
    {
        flow = f->second;
        u.flows[flow].last = now;
    }
    else
    {
        if (u.flows.size() >= max_flows)
        {
            ++m_c.datagrams_dropped;
            return;
        }
        flow = m_next_flow++;
        if (m_next_flow == 0)
            m_next_flow = 1;
        u.flows[flow] = udp_flow{p.from, p.msg.msg_namelen, now, key};
        u.by_peer.emplace(std::move(key), flow);
    }
    const auto a = m_agent_links.find(u.agent);
    const auto l = a == m_agent_links.end() ? nullptr : a->second.lock();
    if (!l)
    {
        // Nobody to carry it to: the agent is not connected.
        ++m_c.datagrams_dropped;
        return;
    }
    send_datagram(*l, flow, service, bytes);
}

void tunnel_run::udp_from_agent(link& l, uint32_t flow, std::string_view service, std::string_view bytes)
{
    // Only into a service of this agent's own, and only to a visitor that sent it something.
    const auto it = m_udp.find(std::string(service));
    if (it == m_udp.end() || it->second.agent != l.who || !it->second.port)
        return;
    const auto f = it->second.flows.find(flow);
    if (f == it->second.flows.end())
        return;
    f->second.last = wall::now_sec();
    m_c.bytes_out += bytes.size();
    if (::sendto(it->second.port->fd, bytes.data(), bytes.size(), MSG_DONTWAIT,
                 reinterpret_cast<const sockaddr*>(&f->second.peer), f->second.len) < 0)
        ++m_c.datagrams_dropped;
}

void tunnel_run::udp_from_edge(link&, uint32_t flow, std::string_view service, std::string_view bytes)
{
    auto it = m_flows.find(flow);
    if (it == m_flows.end())
    {
        // A new flow gets a socket of its own to the offer the service names, so its answers are told apart.
        const auto o = m_offers.find(std::string(service));
        endpoint ep;
        std::string why;
        auto p = o == m_offers.end() || m_flows.size() >= max_flows || !target_endpoint(o->second, ep)
                     ? nullptr
                     : open_udp(ep, true, flow_udp_buf, why);
        if (!p)
        {
            ++m_c.datagrams_dropped;
            return;
        }
        const std::string svc(service);
        p->got = [this, flow, svc](udp_port&, std::string_view answer) {
            if (const auto f = m_flows.find(flow); f != m_flows.end())
                f->second.last = wall::now_sec();
            if (link* e = edge_link())
                send_datagram(*e, flow, svc, answer);
        };
        if (!arm_udp(*p))
        {
            retire_udp(std::move(p));
            ++m_c.datagrams_dropped;
            return;
        }
        it = m_flows.emplace(flow, agent_flow{std::move(p), svc, 0}).first;
    }
    if (it->second.service != service)
        return;
    it->second.last = wall::now_sec();
    m_c.bytes_out += bytes.size();
    if (::send(it->second.port->fd, bytes.data(), bytes.size(), MSG_DONTWAIT) < 0)
        ++m_c.datagrams_dropped;
}

void tunnel_run::reload_udp()
{
    // A service gone, moved to another port or another agent takes its port and its flows with it.
    for (auto it = m_udp.begin(); it != m_udp.end();)
    {
        bool kept = false;
        for (const agent& a : m_agents)
            for (const service& s : a.services)
                kept = kept || (!s.http && s.udp && s.name == it->first && a.name == it->second.agent &&
                                s.port == it->second.svc.port && s.bind == it->second.svc.bind);
        if (kept)
        {
            ++it;
            continue;
        }
        retire_udp(std::move(it->second.port));
        it = m_udp.erase(it);
    }
    for (const agent& a : m_agents)
        for (const service& s : a.services)
        {
            if (s.http || !s.udp || m_udp.contains(s.name))
                continue;
            endpoint on;
            if (!literal_endpoint(s.bind.empty() ? "0.0.0.0" : s.bind, s.port, on))
                continue;
            std::string why;
            auto p = open_udp(on, false, edge_udp_buf, why);
            if (!p)
            {
                LOG_WARN(("tunnel " + std::string(m_owner.get_name()) + ": the UDP service " + s.name + " of " + a.name +
                          " cannot be served: " + why).c_str());
                continue;
            }
            const std::string name = s.name;
            p->got = [this, name](udp_port& port, std::string_view bytes) { udp_visitor(name, port, bytes); };
            arm_udp(*p);
            m_udp.emplace(s.name, udp_service{a.name, s, std::move(p), {}, {}});
        }
}

void tunnel_run::tend_udp(int64_t now)
{
    for (auto& [name, u] : m_udp)
    {
        for (auto f = u.flows.begin(); f != u.flows.end();)
        {
            if (now - f->second.last <= flow_idle_s)
            {
                ++f;
                continue;
            }
            u.by_peer.erase(f->second.key);
            f = u.flows.erase(f);
        }
        if (u.port && !u.port->pending)
            arm_udp(*u.port);
    }
    for (auto f = m_flows.begin(); f != m_flows.end();)
    {
        if (now - f->second.last <= flow_idle_s)
        {
            if (f->second.port && !f->second.port->pending)
                arm_udp(*f->second.port);
            ++f;
            continue;
        }
        retire_udp(std::move(f->second.port));
        f = m_flows.erase(f);
    }
}

link* tunnel_run::edge_link()
{
    link* out = nullptr;
    if (m_up)
        m_up->srv.for_each([&](const std::shared_ptr<http::server_conn>& c) {
            if (auto& l = static_cast<upstream_conn&>(*c).l; l && !out)
                out = l.get();
        });
    return out;
}

size_t tunnel_run::flow_count() const
{
    size_t n = m_flows.size();
    for (const auto& [name, u] : m_udp)
        n += u.flows.size();
    return n;
}

// ─── The edge ───────────────────────────────────────────────────────────────

front_hooks::front_hooks(tunnel_run& r) : run(r), srv(r.m_loop, &r, r.m_owner, *this, max_front) {}

std::shared_ptr<http::server_conn> front_hooks::make_conn()
{
    return std::make_shared<front_conn>();
}

void front_hooks::serve(const std::shared_ptr<http::server_conn>& c)
{
    auto& f = static_cast<front_conn&>(*c);
    if (!f.l)
    {
        run.front_request(c);
        return;
    }
    std::shared_ptr<link> l = f.l;
    l->last_heard = wall::now_sec();
    if (!l->s.feed(c->in, l->out))
    {
        LOG_INFO(("tunnel " + std::string(run.m_owner.get_name()) + ": " + l->who + " broke the protocol: " +
                  l->s.error()).c_str());
        c->in.clear();
        srv.close_conn(c);
        return;
    }
    c->in.clear();
    run.flush_link(*l);
}

bool front_hooks::written(const std::shared_ptr<http::server_conn>& c)
{
    if (const auto& l = static_cast<front_conn&>(*c).l; l && !l->parked.empty())
        run.link_drained(*l);
    return false;
}

bool front_hooks::keeps_open(const http::server_conn& c) const
{
    const auto& l = static_cast<const front_conn&>(c).l;
    return l && !l->ending;
}

void front_hooks::closing(const std::shared_ptr<http::server_conn>& c)
{
    auto& f = static_cast<front_conn&>(*c);
    if (!f.l)
        return;
    std::shared_ptr<link> l = std::move(f.l);
    run.drop_link(*l);
}

bool tunnel_run::start_edge(std::string& why)
{
    std::string_view list = m_owner.get_forward();
    while (!list.empty())
        if (const std::string_view f = trim_blanks(take_item(list)); !f.empty())
            m_forward.emplace_back(f);
    if (!m_owner.get_idp().empty())
    {
        m_idp = std::make_unique<socketley::idp::session_verifier>();
        const std::string_view audience = m_owner.get_idp_audience();
        m_idp->configure(m_owner.get_idp(), audience.empty() ? socketley::idp::cli_client : audience);
    }
    m_front = std::make_unique<front_hooks>(*this);
    m_dial = std::make_unique<leg_hooks>(*this, std::string(), service{});
    // Behind the entrance by default, which is where an agent's key travels in the clear.
    const std::string bind = m_owner.get_bind_address().empty() ? "127.0.0.1" : std::string(m_owner.get_bind_address());
    in_addr a{};
    if (::inet_pton(AF_INET, bind.c_str(), &a) != 1)
    {
        why = "--bind must be an IPv4 address: " + bind;
        return false;
    }
    if (!m_front->srv.listen_tcp(a.s_addr, m_owner.get_port(), false, why))
        return false;
    m_front->srv.start_accepting();
    // Shares of a worker before this one ended with its links.
    write_shares();
    reload_agents();
    return true;
}

void tunnel_run::reload_agents()
{
    struct stat st{};
    const std::string path = agents_path(m_owner.get_name());
    const int64_t mtime = ::stat(path.c_str(), &st) == 0 ? st.st_mtim.tv_sec * 1000000000LL + st.st_mtim.tv_nsec : 0;
    if (mtime == m_agents_mtime)
        return;
    std::vector<agent> agents;
    std::string why;
    if (!load_agents(m_owner.get_name(), agents, why))
    {
        LOG_WARN(("tunnel " + std::string(m_owner.get_name()) + ": " + why + "; the agents read before are kept").c_str());
        m_agents_mtime = mtime;
        return;
    }
    m_agents_mtime = mtime;
    // A service gone, moved, or asking its visitors for another auth takes its listener with it.
    for (auto it = m_listeners.begin(); it != m_listeners.end();)
    {
        bool kept = m_shares.contains(it->first);
        for (const agent& a : agents)
            for (const service& s : a.services)
                kept = kept || (a.name == it->second->agent && s.name == it->first && s.http == it->second->svc.http &&
                                s.udp == it->second->svc.udp &&
                                s.port == it->second->svc.port && s.bind == it->second->svc.bind &&
                                s.auth == it->second->svc.auth);
        if (kept)
        {
            ++it;
            continue;
        }
        it->second->srv.stop();
        m_retired.push_back(std::move(it->second));
        it = m_listeners.erase(it);
    }
    for (const agent& a : agents)
        for (const service& s : a.services)
        {
            // A UDP service has a port of its own kind, which reload_udp keeps.
            if (m_listeners.contains(s.name) || (!s.http && s.udp))
                continue;
            // A method the edge cannot take serves nothing rather than let every visitor through, as an unread one would.
            std::string bad;
            for (const std::string_view method : s.http ? auth_methods(s.auth) : std::vector<std::string_view>{})
                if (bad.empty())
                    bad = proxy_auth::spec_error(method);
            if (!bad.empty())
            {
                LOG_WARN(("tunnel " + std::string(m_owner.get_name()) + ": the service " + s.name + " of " + a.name +
                          " is not served: " + bad).c_str());
                continue;
            }
            auto h = std::make_unique<leg_hooks>(*this, a.name, s);
            std::string err;
            in_addr on{htonl(INADDR_ANY)};
            if (!s.bind.empty() && ::inet_pton(AF_INET, s.bind.c_str(), &on) != 1)
                on.s_addr = htonl(INADDR_LOOPBACK);
            const std::string sock = s.http ? service_socket(m_owner.get_name(), s.name) : std::string();
            if (s.http)
                err = service_socket_refusal(m_owner.get_name(), sock);
            const bool ok = err.empty() && (s.http ? h->srv.listen_unix(sock, err)
                                                   : h->srv.listen_tcp(on.s_addr, s.port, false, err));
            if (!ok)
            {
                LOG_WARN(("tunnel " + std::string(m_owner.get_name()) + ": the service " + s.name + " of " + a.name +
                          " cannot be served: " + err).c_str());
                continue;
            }
            h->srv.start_accepting();
            m_listeners.emplace(s.name, std::move(h));
        }
    // An agent revoked, or invited again under a new secret, is cut off at once.
    std::vector<std::shared_ptr<http::server_conn>> cut;
    for (const auto& [name, weak] : m_agent_links)
    {
        const auto l = weak.lock();
        if (!l)
            continue;
        const auto it = std::find_if(agents.begin(), agents.end(), [&](const agent& a) { return a.name == name; });
        const bool still = it != agents.end() && it->joined &&
                           std::find_if(m_agents.begin(), m_agents.end(), [&](const agent& o) {
                               return o.name == name && o.secret_hash == it->secret_hash;
                           }) != m_agents.end();
        if (!still)
            if (auto t = l->transport.lock())
                cut.push_back(t);
    }
    m_agents = std::move(agents);
    for (auto& t : cut)
        m_front->srv.close_conn(t);
    reload_udp();
}

void tunnel_run::refuse_front(const std::shared_ptr<http::server_conn>& c, int status, std::string_view why)
{
    ++m_c.refused;
    answer_front(c, status, why);
}

void tunnel_run::answer_front(const std::shared_ptr<http::server_conn>& c, int status, std::string_view text)
{
    const std::string body = std::string(text) + "\n";
    const char* reason = status == 200   ? " OK"
                         : status == 401 ? " Unauthorized"
                         : status == 403 ? " Forbidden"
                         : status == 404 ? " Not Found"
                         : status == 409 ? " Conflict"
                                         : " Bad Request";
    c->out += "HTTP/1.1 " + std::to_string(status) + reason + "\r\nContent-Type: text/plain\r\nContent-Length: " +
              std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
    c->keep_alive = false;
    c->in.clear();
}

// A signed-in admin of the edge's idp adds an agent, answered with the invitation its CLI joins with at once.
void tunnel_run::note_refused(const std::string& name, const std::string& from)
{
    const int64_t now = wall::now_sec_coarse();
    if (m_refused.size() > 256)
        m_refused.clear();
    // By address, not port, since each dial comes from a port of its own: a.b.c.d:port, [v6]:port, or a bare address.
    std::string_view host = from;
    if (host.starts_with('['))
        host = host.substr(0, host.find(']') + 1);
    else if (std::count(host.begin(), host.end(), ':') == 1)
        host = host.substr(0, host.find(':'));
    auto& [said, since] = m_refused["\"" + name + "\" refused from " + std::string(host)];
    if (said != 0 && now - said < 60)
    {
        ++since;
        return;
    }
    std::string line = "tunnel " + std::string(m_owner.get_name()) + ": agent \"" + name + "\" refused from " + from;
    if (since)
        line += ", and " + std::to_string(since) + " time(s) more since it was last said";
    LOG_INFO(line.c_str());
    said = now;
    since = 0;
}

void tunnel_run::join_by_person(const std::shared_ptr<http::server_conn>& c, std::string_view head)
{
    const std::string_view auth = header_of(head, "authorization");
    socketley::idp::session_verifier::who who;
    if (!m_idp || !auth.starts_with("Bearer ") || !m_idp->check_bearer(trim_blanks(auth.substr(7)), who))
    {
        refuse_front(c, 401, "the access token is not one this edge takes");
        return;
    }
    if (!who.admin)
    {
        refuse_front(c, 403, "only an admin of this edge's idp adds agents");
        return;
    }
    agent a;
    a.name = std::string(trim_blanks(header_of(head, "tunnel-agent")));
    std::string why;
    if (!valid_name(a.name))
    {
        refuse_front(c, 400, "an agent's name is lower-case letters, digits and -");
        return;
    }
    if (!parse_services(header_of(head, "tunnel-http"), header_of(head, "tunnel-tcp"), header_of(head, "tunnel-udp"),
                        a.services, why))
    {
        refuse_front(c, 400, why);
        return;
    }
    // A service a person adds asks its visitors to sign in at the edge's idp, until the edge's owner says otherwise.
    for (service& s : a.services)
    {
        if (s.http && s.auth.empty())
            s.auth = "idp:" + std::string(m_owner.get_idp());
        for (const std::string_view method : s.http ? auth_methods(s.auth) : std::vector<std::string_view>{})
            if (const std::string bad = proxy_auth::spec_error(method); !bad.empty())
            {
                refuse_front(c, 400, s.name + ": " + bad);
                return;
            }
    }
    const std::string secret = random_b64url(32);
    a.secret_hash = hash_secret(secret);
    // An agent of that name that has joined is replaced only when asked, as for a machine flashed anew; one invited is.
    const bool replace = trim_blanks(header_of(head, "tunnel-replace")) == "yes";
    const bool ok = !secret.empty() && update_agents(m_owner.get_name(), [&](std::vector<agent>& agents, std::string& w) {
        if (const std::string clashed = clash(agents, a); !clashed.empty())
        {
            w = clashed;
            return false;
        }
        if (!replace && std::any_of(agents.begin(), agents.end(), [&](const agent& o) { return o.name == a.name && o.joined; }))
        {
            w = "an agent named " + a.name + " is joined already; --replace takes its place";
            return false;
        }
        std::erase_if(agents, [&](const agent& o) { return o.name == a.name; });
        agents.push_back(a);
        return true;
    }, why);
    if (!ok)
    {
        refuse_front(c, 409, why.empty() ? std::string("no randomness for a secret") : why);
        return;
    }
    LOG_INFO(("tunnel " + std::string(m_owner.get_name()) + ": \"" + who.username + "\" added agent \"" + a.name +
              "\" from " + client_of(c->peer, head)).c_str());
    m_agents_mtime = -1;
    reload_agents();
    answer_front(c, 200, a.name + "." + secret);
}

void tunnel_run::front_request(const std::shared_ptr<http::server_conn>& c)
{
    const size_t end = c->in.find("\r\n\r\n");
    if (end == std::string::npos)
    {
        if (c->in.size() > max_head)
            refuse_front(c, 400, "the request head is too long");
        return;
    }
    const std::string head = c->in.substr(0, end + 2);
    c->in.erase(0, end + 4);
    const std::string_view line = std::string_view(head).substr(0, head.find("\r\n"));
    // Where a person signs in, for a CLI given only the edge's address.
    if (line.starts_with("GET /.tunnel/idp "))
    {
        const std::string issuer = m_idp ? m_idp->issuer() : std::string();
        if (issuer.empty())
            refuse_front(c, 404, "this edge takes no sign-in");
        else
            answer_front(c, 200, issuer);
        return;
    }
    if (line.starts_with("POST /.tunnel/join "))
    {
        join_by_person(c, head);
        return;
    }
    if (!line.starts_with("GET /.tunnel ") || header_of(head, "upgrade") != upgrade_token)
    {
        refuse_front(c, 404, "this is a socketley tunnel edge: agents and people upgrade at /.tunnel");
        return;
    }
    const std::string_view auth = header_of(head, "authorization");
    const size_t sp = auth.find(' ');
    const std::string_view scheme = auth.substr(0, sp);
    const std::string_view cred = sp == std::string_view::npos ? std::string_view() : trim_blanks(auth.substr(sp + 1));
    std::string name, secret;
    if (scheme == "Tunnel" && split_credential(cred, name, secret))
    {
        const auto it = std::find_if(m_agents.begin(), m_agents.end(), [&](const agent& a) { return a.name == name; });
        if (it == m_agents.end() || !it->joined || it->secret_hash != hash_secret(secret))
        {
            note_refused(name, client_of(c->peer, head));
            refuse_front(c, 401, "this agent's key is not one the edge holds");
            return;
        }
        upgraded(c, link::kind::agent, name, {});
        return;
    }
    if (scheme == "Tunnel-Join" && split_credential(cred, name, secret))
    {
        // The invitation exchanged for a key of the agent's own, which only it and the edge's hash of it know.
        const std::string key = random_b64url(32);
        std::string why;
        const bool ok = !key.empty() && update_agents(m_owner.get_name(), [&](std::vector<agent>& agents, std::string& w) {
            const auto a = std::find_if(agents.begin(), agents.end(), [&](const agent& x) { return x.name == name; });
            if (a == agents.end() || a->joined || a->secret_hash != hash_secret(secret))
            {
                w = "the invitation is not one the edge gave, or was used";
                return false;
            }
            a->joined = true;
            a->secret_hash = hash_secret(key);
            return true;
        }, why);
        if (!ok)
        {
            refuse_front(c, 401, why);
            return;
        }
        ++m_c.joined;
        LOG_INFO(("tunnel " + std::string(m_owner.get_name()) + ": agent \"" + name + "\" joined from " +
                  client_of(c->peer, head)).c_str());
        m_agents_mtime = -1;
        reload_agents();
        upgraded(c, link::kind::agent, name, "Tunnel-Key: " + name + "." + key + "\r\n");
        return;
    }
    if (scheme == "Bearer" && m_idp)
    {
        socketley::idp::session_verifier::who who;
        if (!m_idp->check_bearer(cred, who))
        {
            refuse_front(c, 401, "the access token is not one this edge takes");
            return;
        }
        // A share asked for with the upgrade, so its name comes back in the answer and the protocol stays as it is.
        const std::string_view share = header_of(head, "tunnel-share");
        std::string name;
        if (!share.empty())
        {
            int64_t seconds = share_default_s;
            if (const std::string_view f = header_of(head, "tunnel-share-for"); !f.empty())
            {
                const auto [end, ec] = std::from_chars(f.data(), f.data() + f.size(), seconds);
                if (ec != std::errc{} || end != f.data() + f.size() || seconds < 60 || seconds > share_max_s)
                {
                    refuse_front(c, 400, "a share holds from a minute to a day");
                    return;
                }
            }
            if (share != "public" && share != "signed-in")
            {
                refuse_front(c, 400, "a share is public or signed-in");
                return;
            }
            int status = 0;
            std::string why;
            name = begin_share(who.sub, who.username, who.admin, share == "public", seconds, status, why);
            if (name.empty())
            {
                refuse_front(c, status, why);
                return;
            }
            LOG_INFO(("tunnel " + std::string(m_owner.get_name()) + ": \"" + who.username + "\" shares " + name +
                      (share == "public" ? " with everyone" : " with those signed in") + " from " +
                      client_of(c->peer, head)).c_str());
        }
        else
            LOG_INFO(("tunnel " + std::string(m_owner.get_name()) + ": \"" + who.username + "\" connected from " +
                      client_of(c->peer, head)).c_str());
        upgraded(c, link::kind::person, who.username, name.empty() ? std::string() : "Tunnel-Share: " + name + "\r\n",
                 who.sub, who.issued_ms, who.admin);
        if (!name.empty())
        {
            // The link gone already, in the upgrade, takes its share with it.
            const auto& l = static_cast<front_conn&>(*c).l;
            if (!l || c->dead)
            {
                end_share(name);
                return;
            }
            l->share = name;
            m_shares[name].l = l;
            m_agent_links["share:" + name] = l;
        }
        return;
    }
    refuse_front(c, 401, "an agent's key, an invitation, or an access token is required");
}

void tunnel_run::upgraded(const std::shared_ptr<http::server_conn>& c, link::kind k, std::string who,
                          std::string_view extra_headers, std::string sub, int64_t signed_in_ms, bool admin)
{
    auto& f = static_cast<front_conn&>(*c);
    c->out += "HTTP/1.1 101 Switching Protocols\r\nUpgrade: " + std::string(upgrade_token) +
              "\r\nConnection: Upgrade\r\n" + std::string(extra_headers) + "\r\n";
    f.l = std::make_shared<link>(*this, k, std::move(who), c);
    f.l->admin = admin;
    f.l->sub = std::move(sub);
    f.l->signed_in_ms = signed_in_ms;
    ++m_c.links;
    f.l->s.hello({{"edge", std::string(m_owner.get_name())}}, f.l->out);
    if (k == link::kind::agent)
    {
        // A second connection of the same agent takes over; the first is told and closed.
        if (const auto old = m_agent_links[f.l->who].lock())
            if (auto t = old->transport.lock(); t && t != c)
            {
                old->s.goaway("another connection of this agent took over", old->out);
                flush_link(*old);
                m_front->srv.close_conn(t);
            }
        m_agent_links[f.l->who] = f.l;
    }
    std::shared_ptr<link> l = f.l;
    if (!c->in.empty() && !l->s.feed(c->in, l->out))
    {
        c->in.clear();
        m_front->srv.close_conn(c);
        return;
    }
    c->in.clear();
    flush_link(*l);
}

bool tunnel_run::person_holds(link& l)
{
    bool admin = false;
    if (!m_idp || !m_idp->holds(l.sub, l.signed_in_ms, admin))
        return false;
    l.admin = admin;
    return true;
}

std::string tunnel_run::begin_share(const std::string& sub, const std::string& who, bool admin, bool open,
                                    int64_t seconds, int& status, std::string& why)
{
    if (!admin)
    {
        status = 403;
        why = "sharing is for admins of the edge's idp";
        return {};
    }
    const size_t mine = static_cast<size_t>(
        std::count_if(m_shares.begin(), m_shares.end(), [&](const auto& e) { return e.second.sub == sub; }));
    if (mine >= shares_per_person || m_shares.size() >= shares_per_edge)
    {
        status = 429;
        why = mine >= shares_per_person ? "you share " + std::to_string(mine) + " already; end one first"
                                        : "the edge shares as many as it holds; try again later";
        return {};
    }
    // Six letters and digits nobody chose, so a name is neither guessed nor one an agent's service has.
    std::string name;
    for (int tries = 0; tries < 16 && name.empty(); ++tries)
    {
        for (const char ch : random_b64url(32))
            if (name.size() < 6 && ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')))
                name += ch;
        const bool taken = name.size() < 6 || m_listeners.contains(name) ||
                           std::any_of(m_agents.begin(), m_agents.end(), [&](const agent& a) {
                               return std::any_of(a.services.begin(), a.services.end(),
                                                  [&](const service& sv) { return sv.name == name; });
                           });
        if (taken)
            name.clear();
    }
    service sv{true, false, name, 0, {}, open ? std::string() : "idp:" + std::string(m_owner.get_idp())};
    std::string err = name.empty() ? "no free name was found" : open ? std::string() : proxy_auth::spec_error(sv.auth);
    const std::string sock = name.empty() ? std::string() : service_socket(m_owner.get_name(), name);
    if (err.empty())
        err = service_socket_refusal(m_owner.get_name(), sock);
    auto h = err.empty() ? std::make_unique<leg_hooks>(*this, "share:" + name, sv) : nullptr;
    if (h && !h->srv.listen_unix(sock, err))
        h.reset();
    if (!h)
    {
        LOG_WARN(("tunnel " + std::string(m_owner.get_name()) + ": a share cannot be served: " + err).c_str());
        status = 503;
        why = "the edge cannot serve a share now";
        return {};
    }
    h->srv.start_accepting();
    m_listeners.emplace(name, std::move(h));
    m_shares[name] = share_entry{sub, who, wall::now_sec() + seconds, {}, open};
    ++m_c.shared;
    write_shares();
    return name;
}

void tunnel_run::end_share(const std::string& name)
{
    if (!m_shares.erase(name))
        return;
    m_agent_links.erase("share:" + name);
    if (const auto it = m_listeners.find(name); it != m_listeners.end())
    {
        it->second->srv.stop();
        m_retired.push_back(std::move(it->second));
        m_listeners.erase(it);
    }
    write_shares();
}

void tunnel_run::write_shares()
{
    std::vector<share> list;
    for (const auto& [name, sh] : m_shares)
        list.push_back(share{service{true, false, name, 0, {}, sh.open ? std::string() : "idp:" + std::string(m_owner.get_idp())},
                             sh.who, sh.until});
    if (std::string why; !save_shares(m_owner.get_name(), list, why))
        LOG_WARN(("tunnel " + std::string(m_owner.get_name()) + ": " + why).c_str());
}

bool tunnel_run::visitor(leg_hooks& h, const std::shared_ptr<leg>& g)
{
    if (h.agent.empty())
        return true;
    const auto it = m_agent_links.find(h.agent);
    const auto l = it == m_agent_links.end() ? nullptr : it->second.lock();
    const uint32_t stream = l ? l->s.open(h.svc.name, peer_text(g->peer), l->out) : 0;
    if (!stream)
    {
        // Nobody to carry it to: the agent is not connected.
        ++m_c.refused;
        return false;
    }
    g->l = l.get();
    g->stream = stream;
    l->legs[stream] = g;
    ++m_c.streams;
    flush_link(*l);
    return true;
}

void tunnel_run::refuse_visitor(const std::shared_ptr<leg>& g, std::string_view status, std::string_view body,
                                std::string_view headers)
{
    ++m_c.visitors_refused;
    g->refusal = "HTTP/1.1 " + std::string(status) + "\r\nContent-Type: text/plain\r\nContent-Length: " +
                 std::to_string(body.size()) + "\r\nConnection: close\r\n" + std::string(headers) + "\r\n" +
                 std::string(body);
    // Nothing after what already passed goes on, and the stream ends behind it so the far side answers and closes.
    g->in.resize(g->cleared);
    g->near_closed = true;
    g->waiting = true;
    pump(*g);
    leg_done_writing(g);
}

void tunnel_run::upgrade_answered(const std::shared_ptr<leg>& g, std::string_view bytes)
{
    constexpr std::string_view switched = "HTTP/1.1 101";
    g->answer.append(bytes.substr(0, switched.size() - g->answer.size()));
    if (g->answer.size() < switched.size() && switched.starts_with(g->answer))
        return;
    g->await_101 = false;
    if (g->answer == switched)
        return;
    // Refused the upgrade: the visitor's connection ends with this answer, so no request after it goes on unasked.
    g->raw = false;
    g->in.clear();
    g->cleared = 0;
    g->near_closed = true;
    pump(*g);
}

void tunnel_run::gate(leg_hooks& h, const std::shared_ptr<leg>& g)
{
    while (!g->refused && g->refusal.empty() && g->cleared < g->in.size())
    {
        std::string_view rest = std::string_view(g->in).substr(g->cleared);
        if (g->raw)
        {
            g->cleared = g->in.size();
            break;
        }
        if (g->body_left)
        {
            const size_t k = std::min(g->body_left, rest.size());
            g->cleared += k;
            g->body_left -= k;
            continue;
        }
        if (g->chunked)
        {
            std::string_view piece;
            const size_t before = rest.size();
            const chunk_step step = http_chunked_next(g->chunks, rest, piece);
            g->cleared += before - rest.size();
            if (step == chunk_step::done)
                g->chunked = false;
            else if (step == chunk_step::bad)
                refuse_visitor(g, "400 Bad Request", "Bad Request\n", {});
            else if (step == chunk_step::need_more)
                break;
            continue;
        }
        // A request's head, asked of the auth whole before any byte of it goes on.
        const size_t end = rest.find("\r\n\r\n");
        if (end == std::string_view::npos)
        {
            if (rest.size() > max_head)
                refuse_visitor(g, "431 Request Header Fields Too Large", "Request Header Fields Too Large\n", {});
            break;
        }
        const std::string_view head = rest.substr(0, end + 2);
        const size_t line_end = head.find("\r\n");
        const std::string_view line = head.substr(0, line_end);
        const size_t sp1 = line.find(' ');
        const size_t sp2 = sp1 == std::string_view::npos ? sp1 : line.find(' ', sp1 + 1);
        const http_request_framing_scan scan = http_scan_request_headers(head.substr(line_end + 2));
        if (end + 4 > max_head || !http_eol_framing_ok(head, true) || sp2 == std::string_view::npos ||
            !scan.ok)
        {
            refuse_visitor(g, "400 Bad Request", "Bad Request\n", {});
            break;
        }
        const std::string_view target = line.substr(sp1 + 1, sp2 - sp1 - 1);
        int host_fields = 0;
        const std::string_view host = http_request_field(head, "host", host_fields);
        // The entrance on this machine is the only one that reaches a service's socket, and it is believed; refused
        // by every method, a browser is sent to sign in where one of them would send it.
        proxy_auth::request_verdict v;
        v.pass = h.auth.empty();
        for (const auto& a : h.auth)
        {
            proxy_auth::request_verdict one = a->decide(head, "127.0.0.1", false, line.substr(0, sp1),
                                                        target.substr(0, target.find('?')),
                                                        host_fields == 1 ? host : std::string_view());
            if (one.pass || v.status.empty() || one.status.starts_with("302"))
                v = std::move(one);
            if (v.pass)
                break;
        }
        if (!v.pass)
        {
            refuse_visitor(g, v.status, v.body, v.headers);
            break;
        }
        if (!g->l && !visitor(h, g))
        {
            refuse_visitor(g, "502 Bad Gateway", "The machine serving this is not connected.\n", {});
            break;
        }
        int upgrade_fields = 0;
        g->raw = !http_request_field(head, "upgrade", upgrade_fields).empty();
        // The head rewritten last, as every view above is into the bytes it replaces.
        const std::string fresh = forwarded_head(head, !h.auth.empty());
        g->in.replace(g->cleared, end + 2, fresh);
        g->cleared += fresh.size() + 2;
        g->await_101 = g->raw;
        g->answer.clear();
        g->chunked = scan.chunked;
        g->chunks = http_chunked_decoder{};
        g->body_left = scan.chunked ? 0 : scan.content_length;
    }
    pump(*g);
}

// ─── The agent ──────────────────────────────────────────────────────────────

upstream_hooks::upstream_hooks(tunnel_run& r) : run(r), srv(r.m_loop, &r, r.m_owner, *this, 4) {}

std::shared_ptr<http::server_conn> upstream_hooks::make_conn()
{
    return std::make_shared<upstream_conn>();
}

void upstream_hooks::connected(const std::shared_ptr<http::server_conn>& c, int res)
{
    if (res < 0)
    {
        LOG_INFO(("tunnel " + std::string(run.m_owner.get_name()) + ": " + run.m_host + " could not be reached: " +
                  std::strerror(-res)).c_str());
        return;
    }
    auto& u = static_cast<upstream_conn&>(*c);
    const std::string request = "GET /.tunnel HTTP/1.1\r\nHost: " + run.m_path_host + "\r\nUpgrade: " +
                                std::string(upgrade_token) + "\r\nConnection: Upgrade\r\nAuthorization: " +
                                (run.m_joining ? "Tunnel-Join " : "Tunnel ") + run.m_credential + "\r\n\r\n";
    if (run.m_scheme == "https")
    {
        u.ssl = run.m_tls.create_ssl_client(run.m_host);
        if (!u.ssl)
        {
            srv.close_conn(c);
            return;
        }
        tls_context::do_handshake(u.ssl);
        u.head = request;   // held until the handshake is done
        tls_context::take_out(u.ssl, u.out);
        return;
    }
    u.out += request;
}

void upstream_hooks::serve(const std::shared_ptr<http::server_conn>& c)
{
    auto& u = static_cast<upstream_conn&>(*c);
    std::string plain;
    if (!u.ssl)
    {
        plain.swap(c->in);
        run.from_edge(c, std::move(plain));
        return;
    }
    if (tls_context::bio_write_in(u.ssl, c->in.data(), static_cast<int>(c->in.size())) < 0)
    {
        c->in.clear();
        srv.close_conn(c);
        return;
    }
    c->in.clear();
    if (!u.handshaken)
    {
        const int h = tls_context::do_handshake(u.ssl);
        if (h < 0)
        {
            LOG_INFO(("tunnel " + std::string(run.m_owner.get_name()) + ": the TLS handshake with " + run.m_host +
                      " failed").c_str());
            srv.close_conn(c);
            return;
        }
        if (h == 1)
        {
            u.handshaken = true;
            const std::string request = std::move(u.head);
            u.head.clear();
            if (tls_context::ssl_write(u.ssl, request.data(), static_cast<int>(request.size())) <= 0)
            {
                srv.close_conn(c);
                return;
            }
        }
    }
    char buf[16384];
    bool closed = false;
    while (u.handshaken)
    {
        const int n = tls_context::ssl_read(u.ssl, buf, sizeof buf);
        if (n > 0)
            plain.append(buf, static_cast<size_t>(n));
        else
        {
            closed = n < 0;
            break;
        }
    }
    tls_context::take_out(u.ssl, u.out);
    if (!plain.empty())
        run.from_edge(c, std::move(plain));
    if (closed && !c->dead)
        srv.close_conn(c);
}

bool upstream_hooks::written(const std::shared_ptr<http::server_conn>& c)
{
    if (const auto& l = static_cast<upstream_conn&>(*c).l; l && !l->parked.empty())
        run.link_drained(*l);
    return false;
}

void upstream_hooks::closing(const std::shared_ptr<http::server_conn>& c)
{
    auto& u = static_cast<upstream_conn&>(*c);
    if (u.l)
    {
        std::shared_ptr<link> l = std::move(u.l);
        run.drop_link(*l);
    }
    run.edge_gone();
}

bool tunnel_run::start_agent(std::string& why)
{
    const std::string_view to = m_owner.get_to();
    m_scheme = to.starts_with("https://") ? "https" : "http";
    std::string_view rest = to.substr(m_scheme.size() + 3);
    rest = rest.substr(0, rest.find('/'));
    m_path_host = std::string(rest);
    const size_t colon = rest.rfind(':');
    uint32_t port = m_scheme == "https" ? 443 : 80;
    if (colon != std::string_view::npos && rest.find(']') == std::string_view::npos)
    {
        const std::string_view p = rest.substr(colon + 1);
        if (std::from_chars(p.data(), p.data() + p.size(), port).ec != std::errc{} || port == 0 || port > 65535)
        {
            why = "--to has no port that is one: " + std::string(to);
            return false;
        }
        rest = rest.substr(0, colon);
    }
    m_host = std::string(rest);
    m_port = static_cast<uint16_t>(port);
    if (m_scheme == "https" && !m_tls.init_client())
    {
        why = "no TLS client could be made";
        return false;
    }
    std::string_view list = m_owner.get_offers();
    while (!list.empty())
    {
        const std::string_view o = trim_blanks(take_item(list));
        const size_t eq = o.find('=');
        if (eq != std::string_view::npos)
            m_offers.emplace(std::string(o.substr(0, eq)), std::string(o.substr(eq + 1)));
    }
    // The key it was given when it joined, or the invitation it joins with.
    std::string key;
    if (read_file(agent_key_path(m_owner.get_name()), key, {.missing_ok = true}, nullptr) && !key.empty())
    {
        m_credential = std::string(trim_blanks(key.substr(0, key.find('\n'))));
        m_joining = false;
    }
    else if (!m_owner.get_join().empty())
    {
        m_credential = std::string(m_owner.get_join());
        m_joining = true;
    }
    else
    {
        why = "neither a key from an earlier join nor --join";
        return false;
    }
    m_up = std::make_unique<upstream_hooks>(*this);
    m_local = std::make_unique<leg_hooks>(*this, std::string(), service{});
    dial_edge();
    return true;
}

void tunnel_run::dial_edge()
{
    if (m_stopped || !m_up->srv.empty())
        return;
    std::vector<async_resolver::address> addrs;
    endpoint ep;
    if (!literal_endpoint(m_host == "localhost" ? std::string("127.0.0.1") : m_host, m_port, ep))
    {
        // Asked again at the next tick until the resolver has an answer.
        const auto st = m_resolver.lookup(m_host, AF_UNSPEC, addrs);
        if (st == async_resolver::state::pending)
            return;
        if (st == async_resolver::state::failed || addrs.empty())
        {
            LOG_INFO(("tunnel " + std::string(m_owner.get_name()) + ": " + m_host + " does not resolve").c_str());
            edge_gone();
            return;
        }
        ep = addrs.front();
        async_resolver::set_port(ep, m_port);
    }
    std::string why;
    if (!m_up->srv.dial(ep.addr, ep.len, why))
    {
        LOG_INFO(("tunnel " + std::string(m_owner.get_name()) + ": " + m_host + ": " + why).c_str());
        edge_gone();
    }
}

void tunnel_run::from_edge(const std::shared_ptr<http::server_conn>& c, std::string plain)
{
    auto& u = static_cast<upstream_conn&>(*c);
    if (!u.l)
    {
        u.head += plain;
        const size_t end = u.head.find("\r\n\r\n");
        if (end == std::string::npos)
        {
            if (u.head.size() > max_head)
                m_up->srv.close_conn(c);
            return;
        }
        const std::string head = u.head.substr(0, end + 2);
        std::string rest = u.head.substr(end + 4);
        u.head.clear();
        if (!head.starts_with("HTTP/1.1 101"))
        {
            const std::string line = head.substr(0, head.find("\r\n"));
            LOG_WARN(("tunnel " + std::string(m_owner.get_name()) + ": the edge refused: " + line + " " +
                      rest.substr(0, 200)).c_str());
            m_up->srv.close_conn(c);
            return;
        }
        // A join's answer carries the key every later connection uses.
        if (m_joining)
        {
            const std::string_view key = header_of(head, "tunnel-key");
            std::string name, secret;
            if (!split_credential(key, name, secret))
            {
                m_up->srv.close_conn(c);
                return;
            }
            const std::string path = agent_key_path(m_owner.get_name());
            std::error_code ec;
            std::filesystem::create_directories(std::filesystem::path(path).parent_path(), ec);
            if (!socketley::replace_file(path, std::string(key) + "\n", socketley::durability::data, nullptr, 0600))
                LOG_ERROR(("tunnel " + std::string(m_owner.get_name()) + ": the key could not be kept in " + path +
                           "; the next connection cannot join again").c_str());
            m_credential = std::string(key);
            m_joining = false;
            LOG_INFO(("tunnel " + std::string(m_owner.get_name()) + ": joined " + m_host).c_str());
        }
        u.l = std::make_shared<link>(*this, link::kind::edge, m_host, c);
        ++m_c.links;
        m_backoff = 1;
        std::string names;
        for (const auto& [name, addr] : m_offers)
            names += (names.empty() ? "" : ",") + name;
        u.l->s.hello({{"agent", std::string(m_owner.get_name())}, {"offers", names}}, u.l->out);
        plain = std::move(rest);
    }
    std::shared_ptr<link> l = u.l;
    l->last_heard = wall::now_sec();
    if (!plain.empty() && !l->s.feed(plain, l->out))
    {
        LOG_INFO(("tunnel " + std::string(m_owner.get_name()) + ": the edge broke the protocol: " + l->s.error()).c_str());
        m_up->srv.close_conn(c);
        return;
    }
    flush_link(*l);
}

void tunnel_run::edge_gone()
{
    if (m_stopped)
        return;
    // The flows were the edge's to name, and a new link names them again from nothing.
    for (auto& [id, f] : m_flows)
        retire_udp(std::move(f.port));
    m_flows.clear();
    // Tried again after a pause that doubles to half a minute, spread so a fleet does not come back at once.
    m_next_dial = wall::now_sec() + m_backoff + static_cast<int64_t>(random_u64() % 2);
    m_backoff = std::min(m_backoff * 2, max_backoff);
}

}   // namespace socketley::tunnel
