// `socketley tunnel connect` and `tunnel ssh`: a signed-in person's stream to a --forward target of a tunnel edge,
// carried between stdin and stdout, as ssh's ProxyCommand wants it; `tunnel share` a port of this machine at a name the
// edge gives; `tunnel join` makes this machine an agent of an edge its admin signs in at; `tunnel <edge> ...` goes to
// the daemon.  Errors of connect, ssh and share go to stderr, unlike every other command, because stdout carries the
// stream, or the share's address alone.
#include "cli.h"

#include <cctype>
#include <chrono>
#include <charconv>
#include <ctime>
#include <map>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "../shared/loop/blocking_write.h"
#include "../shared/net/read_buffer.h"
#include "../shared/net/socket_tuning.h"
#include "../shared/util/duration_parse.h"
#include "../shared/persist/paths.h"
#include "../shared/util/ascii.h"
#include "../shared/util/text_list.h"
#include "../shared/net/peer_address.h"
#include "../shared/net/public_suffix.h"
#include "../shared/net/tunnel_mux.h"
#include "../runtime/idp/idp_logic.h"

namespace
{

namespace tn = socketley::tunnel;

// The edge's connection, TLS when it is https, read and written whole.
struct conn
{
    int fd{-1};
    SSL_CTX* ctx{nullptr};
    SSL* ssl{nullptr};

    ~conn()
    {
        if (ssl)
            SSL_free(ssl);
        if (ctx)
            SSL_CTX_free(ctx);
        if (fd >= 0)
            ::close(fd);
    }
    bool write(std::string_view s)
    {
        if (!ssl)
            return socketley::write_all(fd, s.data(), s.size());
        while (!s.empty())
        {
            const int n = SSL_write(ssl, s.data(), static_cast<int>(std::min<size_t>(s.size(), 1 << 16)));
            if (n <= 0)
                return false;
            s.remove_prefix(static_cast<size_t>(n));
        }
        return true;
    }
    // Bytes read, 0 at the end, -1 for an error.
    ssize_t read(char* buf, size_t len)
    {
        if (!ssl)
        {
            for (;;)
            {
                const ssize_t n = ::read(fd, buf, len);
                if (n < 0 && errno == EINTR)
                    continue;
                return n;
            }
        }
        const int n = SSL_read(ssl, buf, static_cast<int>(len));
        if (n > 0)
            return n;
        return SSL_get_error(ssl, n) == SSL_ERROR_ZERO_RETURN ? 0 : -1;
    }
    // Whether OpenSSL holds bytes poll() cannot see: with read-ahead, records already off the socket.
    bool pending() const { return ssl && SSL_has_pending(ssl) == 1; }
};

bool dial(conn& c, const std::string& host, const std::string& port, bool tls, std::string& err)
{
    addrinfo hints{}, *res = nullptr;
    hints.ai_socktype = SOCK_STREAM;
    if (::getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res)
    {
        err = host + " does not resolve";
        return false;
    }
    for (addrinfo* a = res; a; a = a->ai_next)
    {
        c.fd = ::socket(a->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (c.fd >= 0 && ::connect(c.fd, a->ai_addr, a->ai_addrlen) == 0)
            break;
        if (c.fd >= 0)
            ::close(c.fd);
        c.fd = -1;
    }
    ::freeaddrinfo(res);
    if (c.fd < 0)
    {
        err = host + ":" + port + " could not be reached: " + std::strerror(errno);
        return false;
    }
    if (!tls)
        return true;
    c.ctx = SSL_CTX_new(TLS_client_method());
    if (!c.ctx || SSL_CTX_set_default_verify_paths(c.ctx) != 1)
    {
        err = "no TLS client could be made";
        return false;
    }
    SSL_CTX_set_verify(c.ctx, SSL_VERIFY_PEER, nullptr);
    c.ssl = SSL_new(c.ctx);
    // A record in one recv rather than its header and its body in two.
    SSL_set_read_ahead(c.ssl, 1);
    SSL_set_fd(c.ssl, c.fd);
    SSL_set_tlsext_host_name(c.ssl, host.c_str());
    SSL_set1_host(c.ssl, host.c_str());
    if (SSL_connect(c.ssl) != 1)
    {
        char buf[256];
        ERR_error_string_n(ERR_get_error(), buf, sizeof buf);
        err = "the TLS handshake with " + host + " failed: " + buf;
        return false;
    }
    return true;
}

// Credit back for `n` bytes delivered, with the time and the link's round trip that let the window grow, as an edge's
// and an agent's do; without them it stayed at its first 256 KiB.
void give_credit(tn::session& s, uint32_t id, size_t n, std::string& out, int link_fd)
{
    const auto now = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s.consumed(id, n, out, static_cast<uint64_t>(now), socket_tuning::rtt_us(link_fd));
}

// What the edge says on the stream, written to stdout, and whether it has finished.
struct pipe_events : tn::events
{
    tn::session* s{nullptr};
    std::string* out{nullptr};
    int link_fd{-1};
    uint32_t stream{0};
    bool far_closed{false};
    bool gone{false};
    std::string why;

    void on_hello(const tn::fields&) override {}
    void on_open(uint32_t id, std::string_view, std::string_view) override { s->reset(id, tn::reset_code::refused, *out); }
    void on_data(uint32_t id, std::string_view bytes) override
    {
        if (id != stream)
            return;
        if (!socketley::write_all(1, bytes.data(), bytes.size()))
        {
            gone = true;
            return;
        }
        give_credit(*s, id, bytes.size(), *out, link_fd);
    }
    void on_close(uint32_t id) override { far_closed = far_closed || id == stream; }
    void on_reset(uint32_t id, tn::reset_code code) override
    {
        if (id != stream)
            return;
        gone = true;
        why = code == tn::reset_code::refused     ? "the edge does not forward to that target"
              : code == tn::reset_code::unreachable ? "the edge could not reach that target"
                                                    : "the stream was cut";
    }
    void on_window(uint32_t) override {}
    void on_pong(std::string_view) override {}
    void on_goaway(std::string_view) override {}
};

// An edge's address taken apart: https unless it says http, its host and port, and `host[:port]` for a Host field.
struct edge_address
{
    bool tls{true};
    std::string authority, host, port;
};

constexpr const char* plain_refusal =
    "an edge is reached over http:// only on this machine, as the sign-in and the invitation go in clear; use https://";

edge_address parse_edge(std::string rest)
{
    edge_address a;
    a.tls = !rest.starts_with("http://");
    if (rest.starts_with("https://"))
        rest = rest.substr(8);
    else if (rest.starts_with("http://"))
        rest = rest.substr(7);
    a.authority = rest.substr(0, rest.find('/'));
    a.host = a.authority;
    a.port = a.tls ? "443" : "80";
    if (const size_t colon = a.authority.rfind(':'); colon != std::string::npos && a.authority.find(']') == std::string::npos)
    {
        a.host = a.authority.substr(0, colon);
        a.port = a.authority.substr(colon + 1);
    }
    return a;
}

// One request to the edge outside a tunnel, its status and its body read to the end of the connection.
bool ask_edge(const edge_address& a, const std::string& request, int& status, std::string& body, std::string& err)
{
    conn c;
    if (!dial(c, a.host, a.port, a.tls, err))
        return false;
    if (!c.write(request))
    {
        err = "the edge closed the connection";
        return false;
    }
    std::string got;
    char buf[16384];
    for (ssize_t n; (n = c.read(buf, sizeof buf)) > 0 && got.size() < 65536;)
        got.append(buf, static_cast<size_t>(n));
    const size_t end = got.find("\r\n\r\n");
    if (!got.starts_with("HTTP/1.") || got.size() < 12 || end == std::string::npos)
    {
        err = "the edge gave no answer";
        return false;
    }
    status = std::atoi(got.c_str() + 9);
    body = got.substr(end + 4);
    while (!body.empty() && (body.back() == '\n' || body.back() == '\r'))
        body.pop_back();
    return true;
}

// Whether an idp an edge names is beside it, auth.example.com for edge.example.com, or the same address.
bool beside_edge(std::string_view edge_host, std::string_view issuer)
{
    std::string_view h = issuer.substr(issuer.find("://") == std::string_view::npos ? 0 : issuer.find("://") + 3);
    h = h.substr(0, h.find('/'));
    if (const size_t colon = h.rfind(':'); colon != std::string_view::npos && h.find(']') == std::string_view::npos)
        h = h.substr(0, colon);
    if (h == edge_host)
        return true;
    // One registrable domain and not one parent label, which made evil.duckdns.org beside home.duckdns.org.
    return socketley::public_suffix::system_list().same_owner(h, edge_host);
}

// The idp the edge takes sign-ins of, asked of the edge itself when none was given; a sign-in kept here goes only to an
// idp beside the edge, since an edge could name any idp to be handed its token.
bool idp_of(const edge_address& a, std::string& idp, std::string& err)
{
    if (!idp.empty())
        return true;
    int status = 0;
    if (!ask_edge(a, "GET /.tunnel/idp HTTP/1.1\r\nHost: " + a.authority + "\r\nConnection: close\r\n\r\n", status, idp,
                  err))
        return false;
    if (status != 200 || idp.empty())
    {
        err = "the edge names no idp to sign in at: " + socketley::ascii::printable(idp);
        return false;
    }
    if (!beside_edge(a.host, idp))
    {
        const std::string named = socketley::ascii::printable(idp);
        err = "the edge names " + named + " as its idp, which is not beside " + a.host + "; give --idp " + named +
              " to sign in there anyway";
        idp.clear();
        return false;
    }
    return true;
}

// The edge's answer to an upgrade with `token` and `headers`: 0 with the connection upgraded, the 101's head in `head`
// and what came after it in `leftover`, else the exit status with the reason said on stderr.
int open_link(const edge_address& ea, const std::string& token, const std::string& headers, conn& c, std::string& head,
              std::string& leftover)
{
    std::string err;
    if (!dial(c, ea.host, ea.port, ea.tls, err))
    {
        std::cerr << err << "\n";
        return 2;
    }
    if (!c.write("GET /.tunnel HTTP/1.1\r\nHost: " + ea.authority + "\r\nUpgrade: " + std::string(tn::upgrade_token) +
                 "\r\nConnection: Upgrade\r\nAuthorization: Bearer " + token + "\r\n" + headers + "\r\n"))
    {
        std::cerr << "the edge closed the connection\n";
        return 2;
    }
    std::string got;
    char buf[16384];
    while (got.find("\r\n\r\n") == std::string::npos)
    {
        const ssize_t n = c.read(buf, sizeof buf);
        if (n <= 0 || got.size() > 16384)
        {
            std::cerr << "the edge gave no answer\n";
            return 2;
        }
        got.append(buf, static_cast<size_t>(n));
    }
    const size_t end = got.find("\r\n\r\n");
    if (!got.starts_with("HTTP/1.1 101"))
    {
        std::cerr << "the edge refused: " << socketley::ascii::printable(std::string_view(got).substr(end + 4, 300));
        return 1;
    }
    head = got.substr(0, end + 2);
    leftover = got.substr(end + 4);
    return 0;
}

// The domain an edge's services are named in, `.example.com` for edge.example.com, as the edge's own routes name them;
// empty for an address or an edge named as a whole domain, which have no name beside them.
std::string beside_edge(const edge_address& ea)
{
    in6_addr literal{};
    const bool named = ::inet_pton(AF_INET, ea.host.c_str(), &literal) != 1 && ea.host.find(':') == std::string::npos;
    const size_t first_dot = named ? ea.host.find('.') : std::string::npos;
    const bool beside = first_dot != std::string::npos && ea.host.find('.', first_dot + 1) != std::string::npos;
    return beside ? ea.host.substr(first_dot) : std::string();
}

int connect_main(const std::string& edge, const std::string& target, std::string idp)
{
    std::string err, token;
    const edge_address ea = parse_edge(edge);
    if (!ea.tls && !socketley::authority_is_this_machine(ea.authority))
    {
        std::cerr << plain_refusal << "\n";
        return 1;
    }
    if (!idp_of(ea, idp, err) || !cli_access_token(idp, token, err))
    {
        std::cerr << err << "\n";
        return 1;
    }
    conn c;
    std::string head, leftover;
    if (const int rc = open_link(ea, token, {}, c, head, leftover); rc != 0)
        return rc;
    // The edge's side and stdin's, each read in what its traffic asks for (shared/net/read_buffer.h).
    socketley::read_buffer<16384> rb, lb;
    pipe_events ev;
    tn::session s(true, ev);
    std::string out;
    ev.s = &s;
    ev.out = &out;
    ev.link_fd = c.fd;
    s.hello({{"person", std::string(socketley::idp::cli_client)}}, out);
    ev.stream = s.open(target, {}, out);
    if (!leftover.empty() && !s.feed(leftover, out))
    {
        std::cerr << "the edge broke the protocol: " << s.error() << "\n";
        return 2;
    }
    bool stdin_open = true;
    while (!ev.gone && !(ev.far_closed && !stdin_open))
    {
        if (!out.empty())
        {
            if (!c.write(out))
            {
                std::cerr << "the edge closed the connection\n";
                return 2;
            }
            out.clear();
        }
        // Stdin is read only while the stream has credit for what it brings.
        const bool want_stdin = stdin_open && s.credit(ev.stream) > 0;
        pollfd p[2] = {{c.fd, POLLIN, 0}, {0, static_cast<short>(want_stdin ? POLLIN : 0), 0}};
        if (!c.pending() && ::poll(p, want_stdin ? 2 : 1, -1) < 0 && errno != EINTR)
            return 2;
        if (c.pending() || (p[0].revents & (POLLIN | POLLHUP | POLLERR)))
        {
            const ssize_t n = c.read(rb.data(), rb.size());
            if (n <= 0)
            {
                if (!ev.far_closed)
                    std::cerr << "the edge closed the connection\n";
                return ev.far_closed ? 0 : 2;
            }
            const bool fed = s.feed(std::string_view(rb.data(), static_cast<size_t>(n)), out);
            rb.took(static_cast<size_t>(n));
            if (!fed)
            {
                std::cerr << "the edge broke the protocol: " << s.error() << "\n";
                return 2;
            }
        }
        if (want_stdin && (p[1].revents & (POLLIN | POLLHUP)))
        {
            const size_t room = std::min<size_t>(lb.size(), s.credit(ev.stream));
            const ssize_t n = ::read(0, lb.data(), room);
            if (n > 0)
            {
                s.send(ev.stream, std::string_view(lb.data(), static_cast<size_t>(n)), out);
                lb.took(static_cast<size_t>(n));
            }
            else if (n == 0 || (n < 0 && errno != EINTR))
            {
                stdin_open = false;
                s.close(ev.stream, out);
            }
        }
    }
    if (!out.empty())
        c.write(out);
    if (!ev.why.empty())
    {
        std::cerr << ev.why << "\n";
        return 1;
    }
    return 0;
}

// A visitor's stream and its connection to the shared port.
struct share_leg
{
    int fd{-1};
    bool connecting{true};
    // The visitor's bytes not yet written to the port, held no longer than the stream's window.
    std::string to_port;
    // The visitor sends no more, so the port's write half is shut once to_port is written.
    bool far_closed{false};
    bool wr_shut{false};
    // The port sends no more.
    bool rd_closed{false};
};

// What the edge asks of a share: a stream for each visitor, to the one port it shares.
struct share_events : tn::events
{
    tn::session* s{nullptr};
    std::string* out{nullptr};
    std::string name;
    sockaddr_storage port{};
    socklen_t port_len{0};
    std::map<uint32_t, share_leg> legs;
    bool gone{false};
    std::string why;

    void on_hello(const tn::fields&) override {}
    void on_open(uint32_t id, std::string_view svc, std::string_view) override
    {
        // Only the share's own name is carried, and only to the port it shares.
        const int fd = svc == name ? ::socket(port.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) : -1;
        if (fd < 0)
        {
            s->reset(id, tn::reset_code::refused, *out);
            return;
        }
        if (::connect(fd, reinterpret_cast<const sockaddr*>(&port), port_len) < 0 && errno != EINPROGRESS)
        {
            ::close(fd);
            s->reset(id, tn::reset_code::unreachable, *out);
            return;
        }
        legs[id].fd = fd;
    }
    void on_data(uint32_t id, std::string_view bytes) override
    {
        if (const auto it = legs.find(id); it != legs.end())
            it->second.to_port.append(bytes);
    }
    void on_close(uint32_t id) override
    {
        if (const auto it = legs.find(id); it != legs.end())
            it->second.far_closed = true;
    }
    void on_reset(uint32_t id, tn::reset_code) override { drop(id); }
    void on_window(uint32_t) override {}
    void on_pong(std::string_view) override {}
    void on_goaway(std::string_view w) override
    {
        gone = true;
        why = std::string(w);
    }
    void drop(uint32_t id)
    {
        if (const auto it = legs.find(id); it != legs.end())
        {
            ::close(it->second.fd);
            legs.erase(it);
        }
    }
    // The stream cut and its connection closed, for a port that failed under it.
    void cut(uint32_t id, tn::reset_code code)
    {
        s->reset(id, code, *out);
        drop(id);
    }
};

// `<port>`, `<address>:<port>` or `localhost:<port>` as the address a share connects visitors to; false for a name,
// which would make the share depend on what this machine's resolver says.
bool share_port(std::string_view t, sockaddr_storage& out, socklen_t& len)
{
    std::string host = "127.0.0.1";
    std::string_view p = t;
    if (const size_t colon = t.rfind(':'); colon != std::string_view::npos)
    {
        host = std::string(t.substr(0, colon));
        p = t.substr(colon + 1);
    }
    if (host == "localhost")
        host = "127.0.0.1";
    if (host.size() > 2 && host.front() == '[' && host.back() == ']')
        host = host.substr(1, host.size() - 2);
    uint32_t port = 0;
    const auto [end, ec] = std::from_chars(p.data(), p.data() + p.size(), port);
    if (ec != std::errc{} || end != p.data() + p.size() || port == 0 || port > 65535)
        return false;
    out = {};
    if (auto* v4 = reinterpret_cast<sockaddr_in*>(&out); ::inet_pton(AF_INET, host.c_str(), &v4->sin_addr) == 1)
    {
        v4->sin_family = AF_INET;
        v4->sin_port = htons(static_cast<uint16_t>(port));
        len = sizeof(sockaddr_in);
        return true;
    }
    if (auto* v6 = reinterpret_cast<sockaddr_in6*>(&out); ::inet_pton(AF_INET6, host.c_str(), &v6->sin6_addr) == 1)
    {
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(static_cast<uint16_t>(port));
        len = sizeof(sockaddr_in6);
        return true;
    }
    return false;
}

// `tunnel share <edge> <port> [--public] [--for <duration>]`: a port of this machine reached at a name the edge gives,
// by its idp's signed-in people or with --public by everyone, until this ends or the time is up.
int share_main(const std::string& edge, const std::string& target, bool open, uint64_t seconds, std::string idp)
{
    std::string err, token;
    const edge_address ea = parse_edge(edge);
    if (!ea.tls && !socketley::authority_is_this_machine(ea.authority))
    {
        std::cerr << plain_refusal << "\n";
        return 1;
    }
    share_events ev;
    if (!share_port(target, ev.port, ev.port_len))
    {
        std::cerr << "a share takes a port, or an address and a port: " << target << "\n";
        return 1;
    }
    if (!idp_of(ea, idp, err) || !cli_access_token(idp, token, err))
    {
        std::cerr << err << "\n";
        return 1;
    }
    conn c;
    std::string head, leftover;
    if (const int rc = open_link(ea, token,
                                 "Tunnel-Share: " + std::string(open ? "public" : "signed-in") + "\r\nTunnel-Share-For: " +
                                     std::to_string(seconds) + "\r\n",
                                 c, head, leftover);
        rc != 0)
        return rc;
    // The name the edge chose, read off its answer.
    for (std::string_view rest = head; !rest.empty();)
    {
        std::string_view line = socketley::take_item(rest, '\n');
        if (line.ends_with('\r'))
            line.remove_suffix(1);
        if (line.size() > 14 && socketley::ascii::iequals(line.substr(0, 14), "tunnel-share: "))
            ev.name = std::string(socketley::trim_blanks(line.substr(14)));
    }
    if (ev.name.empty())
    {
        std::cerr << "the edge took the link but gave the share no name; it may be older than this command\n";
        return 2;
    }
    const std::string beside = beside_edge(ea);
    // An edge reached by its address has no domain to name the share in, so the name alone is said.
    std::cout << (beside.empty() ? ev.name : "https://" + ev.name + beside + "/") << std::endl;
    const time_t until = ::time(nullptr) + static_cast<time_t>(seconds);
    char at[32];
    std::strftime(at, sizeof at, "%H:%M", std::localtime(&until));
    std::cerr << "shared with " << (open ? "everyone" : "those signed in at " + idp) << " until " << at
              << " or Ctrl+C\n";

    tn::session s(true, ev);
    std::string out;
    ev.s = &s;
    ev.out = &out;
    s.hello({{"person", std::string(socketley::idp::cli_client)}}, out);
    if (!leftover.empty() && !s.feed(leftover, out))
    {
        std::cerr << "the edge broke the protocol: " << s.error() << "\n";
        return 2;
    }
    // The edge's side and the ports', each read in what its traffic asks for (shared/net/read_buffer.h).
    socketley::read_buffer<16384> rb, lb;
    std::vector<pollfd> p;
    std::vector<uint32_t> ids;
    while (!ev.gone)
    {
        if (!out.empty())
        {
            if (!c.write(out))
            {
                std::cerr << "the edge closed the connection\n";
                return 2;
            }
            out.clear();
        }
        p.assign(1, pollfd{c.fd, POLLIN, 0});
        ids.assign(1, 0);
        for (const auto& [id, g] : ev.legs)
        {
            // A port is read only while the stream has credit for what it brings, and written while it owes bytes.
            const short want = static_cast<short>((g.connecting || !g.to_port.empty() ? POLLOUT : 0) |
                                                  (!g.connecting && !g.rd_closed && s.credit(id) > 0 ? POLLIN : 0));
            p.push_back(pollfd{g.fd, want, 0});
            ids.push_back(id);
        }
        if (!c.pending() && ::poll(p.data(), p.size(), -1) < 0 && errno != EINTR)
            return 2;
        if (c.pending() || (p[0].revents & (POLLIN | POLLHUP | POLLERR)))
        {
            const ssize_t n = c.read(rb.data(), rb.size());
            if (n <= 0)
            {
                std::cerr << "the edge closed the connection\n";
                return 2;
            }
            const bool fed = s.feed(std::string_view(rb.data(), static_cast<size_t>(n)), out);
            rb.took(static_cast<size_t>(n));
            if (!fed)
            {
                std::cerr << "the edge broke the protocol: " << s.error() << "\n";
                return 2;
            }
        }
        for (size_t i = 1; i < p.size(); ++i)
        {
            // Found again, as what the edge said above may have reset the stream.
            const auto it = ev.legs.find(ids[i]);
            if (it == ev.legs.end() || it->second.fd != p[i].fd)
                continue;
            const uint32_t id = ids[i];
            share_leg& g = it->second;
            const short r = p[i].revents;
            if (g.connecting && (r & (POLLOUT | POLLERR | POLLHUP)))
            {
                int e = 0;
                socklen_t el = sizeof e;
                if (::getsockopt(g.fd, SOL_SOCKET, SO_ERROR, &e, &el) < 0 || e != 0)
                {
                    ev.cut(id, tn::reset_code::unreachable);
                    continue;
                }
                g.connecting = false;
            }
            if (g.connecting)
                continue;
            if ((r & (POLLOUT | POLLERR | POLLHUP)) && !g.to_port.empty())
            {
                const ssize_t n = ::send(g.fd, g.to_port.data(), g.to_port.size(), MSG_NOSIGNAL);
                if (n < 0 && errno != EAGAIN && errno != EINTR)
                {
                    ev.cut(id, tn::reset_code::gone);
                    continue;
                }
                if (n > 0)
                {
                    g.to_port.erase(0, static_cast<size_t>(n));
                    give_credit(s, id, static_cast<size_t>(n), out, c.fd);
                }
            }
            if (g.far_closed && g.to_port.empty() && !g.wr_shut)
            {
                ::shutdown(g.fd, SHUT_WR);
                g.wr_shut = true;
            }
            if ((r & (POLLIN | POLLHUP | POLLERR)) && !g.rd_closed && s.credit(id) > 0)
            {
                const ssize_t n = ::recv(g.fd, lb.data(), std::min<size_t>(lb.size(), s.credit(id)), 0);
                if (n > 0)
                {
                    s.send(id, std::string_view(lb.data(), static_cast<size_t>(n)), out);
                    lb.took(static_cast<size_t>(n));
                }
                else if (n == 0)
                {
                    s.close(id, out);
                    g.rd_closed = true;
                }
                else if (errno != EAGAIN && errno != EINTR)
                {
                    ev.cut(id, tn::reset_code::gone);
                    continue;
                }
            }
            // Both ways ended: the stream is done on both sides and its connection goes.
            if (g.rd_closed && g.wr_shut)
                ev.drop(id);
        }
    }
    if (!out.empty())
        c.write(out);
    std::cerr << "the share ended: " << ev.why << "\n";
    return 0;
}

// This machine's name as an agent's: its host name, lower case, anything but letters and digits made a -.
std::string host_agent_name()
{
    char h[256] = {};
    std::string n;
    if (::gethostname(h, sizeof h - 1) == 0)
        for (const char* p = h; *p && *p != '.'; ++p)
            n += std::isalnum(static_cast<unsigned char>(*p)) ? static_cast<char>(std::tolower(static_cast<unsigned char>(*p))) : '-';
    while (!n.empty() && n.front() == '-')
        n.erase(0, 1);
    n = n.substr(0, 63);
    while (!n.empty() && n.back() == '-')
        n.pop_back();
    return n.empty() ? std::string("agent") : n;
}

// `tunnel join <edge> --http <name>=<host>:<port> --tcp <name>:<port>=<host>:<port>`: an admin of the edge's idp,
// signed in here, adds this machine as an agent, and the agent runtime is made with the invitation the edge answers.
int join_main(int argc, char** argv)
{
    std::string edge, name, http, tcp, udp, offers, idp;
    bool replace = false;
    const auto usage = [] {
        std::cout << "usage: socketley tunnel join <edge address> [--name <agent>] [--http <service>=<host>:<port>,...] "
                     "[--tcp <service>:<edge port>=<host>:<port>,...] [--udp <service>:<edge port>=<host>:<port>,...] "
                     "[--replace] [--idp <idp address>]\n";
        return 1;
    };
    for (int i = 3; i < argc; ++i)
    {
        const std::string_view a = argv[i];
        if ((a == "--http" || a == "--tcp" || a == "--udp") && i + 1 < argc)
        {
            // Each offer names the service the edge serves and where it is reached on this machine.
            std::string_view list = argv[++i];
            while (!list.empty())
            {
                const std::string_view item = socketley::trim_blanks(socketley::take_item(list));
                const size_t eq = item.find('=');
                if (eq == std::string_view::npos || eq == 0 || eq + 1 == item.size())
                    return usage();
                const std::string_view svc = item.substr(0, eq), there = item.substr(eq + 1);
                std::string& names = a == "--http" ? http : a == "--tcp" ? tcp : udp;
                names += (names.empty() ? "" : ",") + std::string(svc);
                offers += (offers.empty() ? "" : ",") + std::string(svc.substr(0, svc.find(':'))) + "=" + std::string(there);
            }
        }
        else if (a == "--name" && i + 1 < argc)
            name = argv[++i];
        else if (a == "--idp" && i + 1 < argc)
            idp = argv[++i];
        else if (a == "--replace")
            replace = true;
        else if (edge.empty() && !a.starts_with("--"))
            edge = a;
        else
            return usage();
    }
    if (edge.empty() || offers.empty())
        return usage();
    // An address without a scheme is the https one, as the agent runtime's --to wants it.
    if (!edge.starts_with("https://") && !edge.starts_with("http://"))
        edge = "https://" + edge;
    if (name.empty())
        name = host_agent_name();
    // Asked before the edge is, in the system daemon's state as well where this CLI reaches that daemon.
    const socketley_paths paths = socketley_paths::resolve();
    std::error_code ec;
    if (std::filesystem::exists(paths.state_dir / (name + ".json"), ec) ||
        (paths.system_mode && std::filesystem::exists(std::filesystem::path("/var/lib/socketley/runtimes") / (name + ".json"), ec)))
    {
        std::cout << "a runtime named " << name << " is here already; socketley remove " << name
                  << " first, or join with --name\n";
        return 1;
    }

    const edge_address ea = parse_edge(edge);
    if (!ea.tls && !socketley::authority_is_this_machine(ea.authority))
    {
        std::cout << plain_refusal << "\n";
        return 1;
    }
    std::string err, token;
    if (!idp_of(ea, idp, err))
    {
        std::cout << err << "\n";
        return 2;
    }
    // A sign-in kept here is used; else one for this join alone, kept nowhere, since an admin's would outlive it.
    if (!cli_access_token(idp, token, err))
        if (const int rc = cli_sign_in_once(idp, token); rc != 0)
            return rc;
    int status = 0;
    std::string invitation;
    if (!ask_edge(ea, "POST /.tunnel/join HTTP/1.1\r\nHost: " + ea.authority + "\r\nAuthorization: Bearer " + token +
                          "\r\nTunnel-Agent: " + name + "\r\nTunnel-Http: " + http + "\r\nTunnel-Tcp: " + tcp +
                          "\r\nTunnel-Udp: " + udp +
                          (replace ? "\r\nTunnel-Replace: yes" : "") + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                  status, invitation, err))
    {
        std::cout << err << "\n";
        return 2;
    }
    if (status != 200)
    {
        std::cout << "the edge refused: " << socketley::ascii::printable(invitation) << "\n";
        return 1;
    }
    std::vector<std::string> words = {"socketley", "create", "tunnel", name, "--mode", "agent", "--to", edge,
                                      "--join", invitation, "--offer", offers, "-s"};
    std::vector<char*> create_argv;
    for (auto& w : words)
        create_argv.push_back(w.data());
    create_argv.push_back(nullptr);
    // The edge holds the agent as invited until it joins, so the same join once the runtime can be made takes its place.
    if (const int rc = cli_dispatch(static_cast<int>(words.size()), create_argv.data()); rc != 0)
    {
        std::cout << "the edge holds " << name << " as invited; run this join again once its runtime can be made here\n";
        return rc;
    }
    // Where each service is now, named beside the edge as the edge names it.
    const std::string beside = beside_edge(ea);
    const std::string machine = beside.empty() ? ea.host : beside.substr(1);
    std::string_view h = http, c = tcp;
    while (!h.empty())
        std::cout << "https://" << socketley::take_item(h) << beside << "\n";
    while (!c.empty())
    {
        const std::string_view s = socketley::take_item(c);
        std::cout << machine << s.substr(s.rfind(':')) << "\n";
    }
    for (std::string_view u = udp; !u.empty();)
    {
        const std::string_view s = socketley::take_item(u);
        std::cout << machine << s.substr(s.rfind(':')) << "/udp\n";
    }
    return 0;
}

}   // namespace

int cli_tunnel(int argc, char** argv)
{
    const std::string_view what = argc > 2 ? argv[2] : "";
    if (what == "join")
        return join_main(argc, argv);
    if (what == "share")
    {
        std::string edge, target, idp;
        bool open = false, bad = false;
        uint64_t seconds = 2 * 3600;
        for (int i = 3; i < argc; ++i)
        {
            const std::string_view a = argv[i];
            if (a == "--public")
                open = true;
            else if (a == "--idp" && i + 1 < argc)
                idp = argv[++i];
            else if (a == "--for" && i + 1 < argc)
                bad = bad || parse_duration_seconds(argv[++i], 24 * 3600, seconds) != duration_parse::ok || seconds < 60;
            else if (edge.empty())
                edge = a;
            else if (target.empty())
                target = a;
            else
                bad = true;
        }
        if (bad || edge.empty() || target.empty())
        {
            std::cout << "usage: socketley tunnel share <edge address> <port>|<address>:<port> [--public] "
                         "[--for <1m to 24h>] [--idp <idp address>]\n";
            return 1;
        }
        return share_main(edge, target, open, seconds, idp);
    }
    if (what != "connect" && what != "ssh")
        return cli_forward(argc, argv);
    std::string edge, target, idp, agent;
    bool extra = false;
    for (int i = 3; i < argc; ++i)
    {
        const std::string_view a = argv[i];
        if (a == "--idp" && i + 1 < argc)
            idp = argv[++i];
        else if (a == "--agent" && i + 1 < argc && what == "ssh")
            agent = argv[++i];
        else if (edge.empty())
            edge = a;
        else if (target.empty() && what == "connect")
            target = a;
        else
            extra = true;
    }
    // An agent's TCP service `ssh` for --agent, else the edge's own machine.
    if (what == "ssh")
        target = agent.empty() ? std::string("127.0.0.1:22") : agent + "/ssh";
    // Said on stderr, since stdout is the stream itself.
    if (extra || edge.empty() || target.empty())
    {
        std::cerr << "usage: socketley tunnel connect <edge address> <host>:<port>|<agent>/<service> [--idp <idp address>]\n"
                     "       socketley tunnel ssh <edge address> [--agent <agent>] [--idp <idp address>]\n";
        return 1;
    }
    return connect_main(edge, target, idp);
}
