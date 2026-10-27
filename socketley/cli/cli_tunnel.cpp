// `socketley tunnel connect` and `tunnel ssh`: a signed-in person's stream to a --forward target of a tunnel edge,
// carried between stdin and stdout, as ssh's ProxyCommand wants it; `tunnel <edge> ...` goes to the daemon.  Errors
// go to stderr here, unlike every other command, because stdout carries the stream.
#include "cli.h"

#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>

#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "../shared/loop/blocking_write.h"
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
    bool pending() const { return ssl && SSL_pending(ssl) > 0; }
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

// What the edge says on the stream, written to stdout, and whether it has finished.
struct pipe_events : tn::events
{
    tn::session* s{nullptr};
    std::string* out{nullptr};
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
        s->consumed(id, bytes.size(), *out);
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

int connect_main(const std::string& edge, const std::string& target, const std::string& idp)
{
    std::string err, token;
    if (!cli_access_token(idp, token, err))
    {
        std::cerr << err << "\n";
        return 1;
    }
    std::string rest = edge;
    const bool tls = !rest.starts_with("http://");
    if (rest.starts_with("https://"))
        rest = rest.substr(8);
    else if (rest.starts_with("http://"))
        rest = rest.substr(7);
    rest = rest.substr(0, rest.find('/'));
    std::string host = rest, port = tls ? "443" : "80";
    if (const size_t colon = rest.rfind(':'); colon != std::string::npos && rest.find(']') == std::string::npos)
    {
        host = rest.substr(0, colon);
        port = rest.substr(colon + 1);
    }
    conn c;
    if (!dial(c, host, port, tls, err))
    {
        std::cerr << err << "\n";
        return 2;
    }
    if (!c.write("GET /.tunnel HTTP/1.1\r\nHost: " + rest + "\r\nUpgrade: " + std::string(tn::upgrade_token) +
                 "\r\nConnection: Upgrade\r\nAuthorization: Bearer " + token + "\r\n\r\n"))
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
        std::cerr << "the edge refused: " << got.substr(end + 4, 300);
        return 1;
    }
    std::string leftover = got.substr(end + 4);

    pipe_events ev;
    tn::session s(true, ev);
    std::string out;
    ev.s = &s;
    ev.out = &out;
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
            const ssize_t n = c.read(buf, sizeof buf);
            if (n <= 0)
            {
                if (!ev.far_closed)
                    std::cerr << "the edge closed the connection\n";
                return ev.far_closed ? 0 : 2;
            }
            if (!s.feed(std::string_view(buf, static_cast<size_t>(n)), out))
            {
                std::cerr << "the edge broke the protocol: " << s.error() << "\n";
                return 2;
            }
        }
        if (want_stdin && (p[1].revents & (POLLIN | POLLHUP)))
        {
            const size_t room = std::min<size_t>(sizeof buf, s.credit(ev.stream));
            const ssize_t n = ::read(0, buf, room);
            if (n > 0)
                s.send(ev.stream, std::string_view(buf, static_cast<size_t>(n)), out);
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

}   // namespace

int cli_tunnel(int argc, char** argv)
{
    const std::string_view what = argc > 2 ? argv[2] : "";
    if (what != "connect" && what != "ssh")
        return cli_forward(argc, argv);
    std::string edge, target, idp;
    bool extra = false;
    for (int i = 3; i < argc; ++i)
    {
        const std::string_view a = argv[i];
        if (a == "--idp" && i + 1 < argc)
            idp = argv[++i];
        else if (edge.empty())
            edge = a;
        else if (target.empty() && what == "connect")
            target = a;
        else
            extra = true;
    }
    if (what == "ssh")
        target = "127.0.0.1:22";
    // Said on stderr, since stdout is the stream itself.
    if (extra || edge.empty() || target.empty() || idp.empty())
    {
        std::cerr << "usage: socketley tunnel connect <edge address> <host>:<port> --idp <idp address>\n"
                     "       socketley tunnel ssh <edge address> --idp <idp address>\n";
        return 1;
    }
    return connect_main(edge, target, idp);
}
