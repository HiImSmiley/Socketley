// `socketley tunnel connect` and `tunnel ssh`: a signed-in person's stream to a --forward target of a tunnel edge,
// carried between stdin and stdout, as ssh's ProxyCommand wants it; `tunnel join` makes this machine an agent of an
// edge its admin signs in at; `tunnel <edge> ...` goes to the daemon.  Errors of connect and ssh go to stderr, unlike
// every other command, because stdout carries the stream.
#include "cli.h"

#include <cctype>
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
#include "../shared/persist/paths.h"
#include "../shared/util/text_list.h"
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

// An edge's address taken apart: https unless it says http, its host and port, and `host[:port]` for a Host field.
struct edge_address
{
    bool tls{true};
    std::string authority, host, port;
};

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

// The idp the edge takes sign-ins of, asked of the edge itself when none was given.
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
        err = "the edge names no idp to sign in at: " + idp;
        return false;
    }
    return true;
}

int connect_main(const std::string& edge, const std::string& target, std::string idp)
{
    std::string err, token;
    const edge_address ea = parse_edge(edge);
    if (!idp_of(ea, idp, err) || !cli_access_token(idp, token, err))
    {
        std::cerr << err << "\n";
        return 1;
    }
    const std::string& rest = ea.authority;
    conn c;
    if (!dial(c, ea.host, ea.port, ea.tls, err))
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
    std::string edge, name, http, tcp, offers;
    const auto usage = [] {
        std::cout << "usage: socketley tunnel join <edge address> [--name <agent>] [--http <service>=<host>:<port>,...] "
                     "[--tcp <service>:<edge port>=<host>:<port>,...]\n";
        return 1;
    };
    for (int i = 3; i < argc; ++i)
    {
        const std::string_view a = argv[i];
        if ((a == "--http" || a == "--tcp") && i + 1 < argc)
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
                std::string& names = a == "--http" ? http : tcp;
                names += (names.empty() ? "" : ",") + std::string(svc);
                offers += (offers.empty() ? "" : ",") + std::string(svc.substr(0, svc.find(':'))) + "=" + std::string(there);
            }
        }
        else if (a == "--name" && i + 1 < argc)
            name = argv[++i];
        else if (edge.empty() && !a.starts_with("--"))
            edge = a;
        else
            return usage();
    }
    if (edge.empty() || offers.empty())
        return usage();
    if (name.empty())
        name = host_agent_name();
    // Asked before the edge is, since the edge replaces an agent of that name and the one here would lose its key.
    if (std::error_code ec; std::filesystem::exists(socketley_paths::resolve().state_dir / (name + ".json"), ec))
    {
        std::cout << "a runtime named " << name << " is here already; socketley remove " << name
                  << " first, or join with --name\n";
        return 1;
    }

    const edge_address ea = parse_edge(edge);
    std::string idp, err, token;
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
                          "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                  status, invitation, err))
    {
        std::cout << err << "\n";
        return 2;
    }
    if (status != 200)
    {
        std::cout << "the edge refused: " << invitation << "\n";
        return 1;
    }
    std::vector<std::string> words = {"socketley", "create", "tunnel", name, "--mode", "agent", "--to", edge,
                                      "--join", invitation, "--offer", offers, "-s"};
    std::vector<char*> create_argv;
    for (auto& w : words)
        create_argv.push_back(w.data());
    create_argv.push_back(nullptr);
    if (const int rc = cli_dispatch(static_cast<int>(words.size()), create_argv.data()); rc != 0)
        return rc;
    // Where each service is now, named beside the edge as the edge names it; an address has no name to be beside.
    in6_addr literal{};
    const bool named = ::inet_pton(AF_INET, ea.host.c_str(), &literal) != 1 && ea.host.find(':') == std::string::npos;
    const size_t dot = named ? ea.host.find('.') : std::string::npos;
    const std::string beside = dot == std::string::npos ? std::string() : ea.host.substr(dot);
    const std::string machine = dot == std::string::npos ? ea.host : ea.host.substr(dot + 1);
    std::string_view h = http, c = tcp;
    while (!h.empty())
        std::cout << "https://" << socketley::take_item(h) << beside << "\n";
    while (!c.empty())
    {
        const std::string_view s = socketley::take_item(c);
        std::cout << machine << s.substr(s.find(':')) << "\n";
    }
    return 0;
}

}   // namespace

int cli_tunnel(int argc, char** argv)
{
    const std::string_view what = argc > 2 ? argv[2] : "";
    if (what == "join")
        return join_main(argc, argv);
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
