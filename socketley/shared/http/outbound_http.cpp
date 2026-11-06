#include "outbound_http.h"
#include "../util/settings.h"
#include "../net/file_send.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <cstring>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <poll.h>

#include "http_framing.h"
#include "../net/async_resolver.h"
#include "../net/dns_client.h"
#include "../util/logging.h"
#include "../util/ascii.h"
#include "../util/text_list.h"

namespace socketley
{

namespace
{

// The most of an answer that is kept, which is a status, its headers and a small XML document.
constexpr size_t answer_cap = 1u << 20;
// The most plaintext handed to the record layer at once.
constexpr size_t tls_piece = 1u << 20;
// A file body over this moves a TLS connection's send key to the kernel and goes by sendfile, as a server's file does.
constexpr uint64_t kernel_tls_min = 256u << 10;

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

// The value of header `lower` in a head of CRLF-ended lines, empty when it has none.
std::string_view head_value(std::string_view head, std::string_view lower)
{
    size_t pos = head.find("\r\n");
    while (pos != std::string_view::npos && pos + 2 < head.size())
    {
        const size_t start = pos + 2;
        const size_t end   = head.find("\r\n", start);
        const std::string_view line = head.substr(start, end == std::string_view::npos ? std::string_view::npos : end - start);
        const size_t colon = line.find(':');
        if (colon != std::string_view::npos && ascii::iequals(trim(line.substr(0, colon)), lower))
            return trim(line.substr(colon + 1));
        pos = end;
    }
    return {};
}

// A whole status line's code, 0 for anything else.
int status_of(std::string_view head)
{
    if (!head.starts_with("HTTP/1.") || head.size() < 12 || head[8] != ' ')
        return 0;
    int status = 0;
    const auto res = std::from_chars(head.data() + 9, head.data() + 12, status);
    return res.ec == std::errc{} && res.ptr == head.data() + 12 ? status : 0;
}

}   // namespace

std::vector<target_line> split_target_lines(std::string_view text)
{
    std::vector<target_line> out;
    size_t line_no = 0;
    while (!text.empty())
    {
        std::string_view line = trim(take_item(text, '\n'));
        ++line_no;
        target_line t;
        t.line_no = line_no;
        while (!line.empty() && line.front() != '#')
        {
            const size_t sp = line.find_first_of(" \t");
            t.fields.push_back(line.substr(0, sp));
            line = sp == std::string_view::npos ? std::string_view{} : trim(line.substr(sp));
        }
        if (!t.fields.empty())
            out.push_back(std::move(t));
    }
    return out;
}

bool read_targets_file(const std::string& path, std::string_view what, std::string& out, std::string& why)
{
    out.clear();
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        why = "cannot read the " + std::string(what) + " file " + path + ": " + std::strerror(errno);
        return false;
    }
    // Whole or refused: a file read in part would configure only what came before the break.
    char buf[4096];
    for (;;)
    {
        const ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
        {
            why = "cannot read the " + std::string(what) + " file " + path + ": " + std::strerror(errno);
            ::close(fd);
            return false;
        }
        if (n == 0)
            break;
        out.append(buf, static_cast<size_t>(n));
        if (out.size() > (1u << 20))
        {
            why = "the " + std::string(what) + " file " + path + " is larger than 1 MiB";
            ::close(fd);
            return false;
        }
    }
    ::close(fd);
    return true;
}

bool valid_target_name(std::string_view name)
{
    if (name.empty())
        return false;
    for (const char ch : name)
        if (!(std::isalnum(static_cast<unsigned char>(ch)) || ch == '-' || ch == '_' || ch == '.'))
            return false;
    return true;
}

std::vector<http_endpoint> resolve_http_host(const std::string& host, uint16_t port, const std::string& hosts_file)
{
    std::vector<http_endpoint> out;
    if (!hosts_file.empty())
    {
        std::string text;
        if (const int fd = ::open(hosts_file.c_str(), O_RDONLY | O_CLOEXEC); fd >= 0)
        {
            char buf[4096];
            ssize_t n;
            while ((n = ::read(fd, buf, sizeof(buf))) > 0 && text.size() < (1u << 20))
                text.append(buf, static_cast<size_t>(n));
            ::close(fd);
        }
        std::string_view rest = text;
        while (!rest.empty())
        {
            std::string_view line = trim(take_item(rest, '\n'));
            const size_t sp = line.find_first_of(" \t");
            if (sp == std::string_view::npos || line.substr(0, sp) != host)
                continue;
            http_endpoint e;
            if (literal_endpoint(std::string(trim(line.substr(sp))), port, e))
                out.push_back(e);
        }
        if (!out.empty())
            return out;
    }
    return socketley::resolve_all(host, std::to_string(port).c_str(), AF_UNSPEC);
}

std::string_view http_answer::header(std::string_view lower) const
{
    return head_value(head, lower);
}

// ─── The peer ───────────────────────────────────────────────────────────────

http_peer::http_peer(event_loop& loop, file_io& io, hash_pool& resolver, http_target target, std::string hosts_file,
                     std::string what)
    : m_loop(loop), m_io(io), m_resolver(resolver), m_target(std::move(target)), m_hosts_file(std::move(hosts_file)),
      m_what(std::move(what))
{
    if (m_target.tls)
    {
        m_tls = std::make_unique<tls_context>();
        if (!m_tls->init_client(m_target.ca_file))
        {
            LOG_ERROR((m_what + " has no TLS context, so nothing is sent to it").c_str());
            m_tls.reset();
        }
    }
    http_endpoint e;
    m_literal = literal_endpoint(m_target.host, m_target.port, e);
    if (m_literal)
        m_addrs.push_back(e);
}

http_peer::~http_peer()
{
    *m_alive = false;
    if (m_ssl)
        tls_context::free_ssl(m_ssl);
    for (const int fd : {m_pipe_rd, m_pipe_wr})
        if (fd >= 0)
            ::close(fd);
    // A kept connection a stop did not close, which nothing in the ring names any more.
    if (m_fd >= 0)
        ::close(m_fd);
}

void http_peer::prime()
{
    if (!m_literal && !resolve()) {}
}

bool http_peer::resolve()
{
    const auto now = std::chrono::steady_clock::now();
    if (m_literal || m_stopped)
        return false;
    if (m_resolving)
        return true;
    if (m_resolved_at != std::chrono::steady_clock::time_point{} &&
        now - m_resolved_at < std::chrono::milliseconds(resolve_floor_ms))
        return false;
    // The test aid's hosts file is read where it always was, before the system's resolver and on its thread.
    if (m_hosts_file.empty())
    {
        m_resolving = true;
        m_ask_wait  = std::chrono::milliseconds(0);
        if (ask_loop())
            return true;
        m_resolving = false;
    }
    if (!m_resolver.enabled())
        return false;
    m_resolving = true;
    ask_thread();
    return true;
}

bool http_peer::ask_loop()
{
    std::vector<endpoint> out;
    switch (dns_client::here().ask(m_target.host, AF_UNSPEC, out))
    {
        case dns_client::state::ready:
            for (endpoint& e : out)
                async_resolver::set_port(e, m_target.port);
            resolved(std::move(out));
            return true;
        case dns_client::state::unsure:
            return false;
        case dns_client::state::pending:
            break;
    }
    // From 2 ms up to 50: a nearby resolver answers within the first few, one far away within a few of the last.
    m_ask_wait = std::min(m_ask_wait.count() ? m_ask_wait * 2 : std::chrono::milliseconds(2),
                          std::chrono::milliseconds(50));
    auto alive = m_alive;
    return m_io.after(m_ask_wait, [this, alive](int64_t)
    {
        if (!*alive || !m_resolving || m_stopped)
            return;
        if (!ask_loop())
        {
            if (m_resolver.enabled())
                ask_thread();
            else
                resolved({});
        }
    });
}

void http_peer::ask_thread()
{
    auto out = std::make_shared<std::vector<http_endpoint>>();
    auto alive = m_alive;
    m_resolver.submit(0,
        [out, host = m_target.host, port = m_target.port, hosts = m_hosts_file]()
        { *out = resolve_http_host(host, port, hosts); },
        [this, alive, out]()
        {
            if (*alive)
                resolved(std::move(*out));
        });
}

void http_peer::resolved(std::vector<http_endpoint> addrs)
{
    m_resolving   = false;
    m_resolved_at = std::chrono::steady_clock::now();
    ++m_resolves;
    if (m_stopped)
        return;
    // An exchange waiting for the host's first addresses is the one that goes on or ends here.
    const bool waiting = m_busy && m_fd < 0 && m_addrs.empty();
    if (addrs.empty())
    {
        LOG_WARN((m_what + " names host " + m_target.host +
                  ", which does not resolve; what is for it waits and it is asked again").c_str());
        // A host known before keeps its addresses, since a resolver that does not answer says nothing about them.
        if (waiting)
            finish(false, "the host does not resolve");
        return;
    }
    m_addrs = std::move(addrs);
    m_cur   = 0;
    if (waiting)
        connect();
}

void http_peer::exchange(http_request req, std::function<void(http_answer)> done)
{
    const auto now = std::chrono::steady_clock::now();
    m_req          = std::move(req);
    m_done         = std::move(done);
    m_busy         = true;
    m_handshaken   = false;
    m_head_given   = false;
    m_source_done  = false;
    m_head_out.clear();
    m_tls_rest.clear();
    m_tls_rest_off = 0;
    m_file_sent    = 0;
    m_in_pipe      = 0;
    m_file_kernel  = false;
    m_file_by_source = false;
    m_sent         = false;
    m_write_failed = false;
    m_eof          = false;
    m_in.clear();
    m_head_end = std::string::npos;
    m_deadline = now + std::chrono::seconds(stall_secs);
    if (m_stopped || (m_target.tls && !m_tls))
    {
        finish(false, "there is no TLS context for the host");
        return;
    }
    // The connection the last exchange kept goes on at once, its TLS session with it, unless the host closed it since
    // or it is as old as the addresses it was made to.
    if (m_fd >= 0)
    {
        if (now - m_connected_at < std::chrono::seconds(resolve_every_secs) && still_open())
        {
            ++m_reuses;
            m_handshaken = m_ssl != nullptr;
            advance();
            return;
        }
        close_socket();
    }
    // A host with no address yet waits for the resolver, which goes on with the exchange when it answers.
    if (m_addrs.empty())
    {
        if (!resolve())
            finish(false, "the host cannot be resolved");
        return;
    }
    // A host is asked again now and then while it is used, without holding up this exchange.
    if (!m_literal && now - m_resolved_at > std::chrono::seconds(resolve_every_secs))
        if (!resolve()) {}
    connect();
}

void http_peer::connect()
{
    const http_endpoint& ep = m_addrs[m_cur % m_addrs.size()];
    // Blocking, so a write the kernel cannot take whole waits in the ring for room rather than failing with EAGAIN.
    m_fd = ::socket(ep.addr.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    m_sock_flags = -1;
    if (m_fd < 0)
    {
        finish(false, "no socket could be made");
        return;
    }
    // A request's last segment goes at once, not after the host's delayed acknowledgement of the one before.
    const int one = 1;
    if (::setsockopt(m_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) {}
    ++m_connects;
    m_connected_at = std::chrono::steady_clock::now();
    const uint64_t gen = m_gen;
    auto alive = m_alive;
    if (!m_io.connect(m_fd, reinterpret_cast<const struct sockaddr*>(&ep.addr), ep.len,
                      [this, alive, gen](int64_t res)
                      {
                          if (*alive && m_gen == gen)
                              connected(res);
                      }))
        finish(false, "the ring is full");
}

void http_peer::connected(int64_t res)
{
    if (res < 0)
    {
        // The host's next address is tried at once, and once every one has refused, its name is asked again.
        close_socket();
        if (++m_cur < m_addrs.size())
        {
            connect();
            return;
        }
        m_cur = 0;
        if (!resolve()) {}
        finish(false, "every address refused the connection");
        return;
    }
    m_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(stall_secs);
    if (m_target.tls)
    {
        m_ssl = m_tls->create_ssl_client(m_target.host);
        if (!m_ssl)
        {
            finish(false, "no TLS session could be made");
            return;
        }
    }
    advance();
}

void http_peer::advance()
{
    if (m_ssl && !m_handshaken)
    {
        const int h = tls_context::do_handshake(m_ssl);
        if (h < 0)
        {
            // The verify result says why a certificate was refused, which the handshake's own failure does not.
            std::string why = "the TLS handshake failed";
            if (const long v = SSL_get_verify_result(m_ssl); v != X509_V_OK)
                why += std::string(": certificate rejected: ") + X509_verify_cert_error_string(v);
            finish(false, std::move(why));
            return;
        }
        m_handshaken = h == 1;
        if (flush_cipher())
            return;
        if (!m_handshaken)
        {
            receive();
            return;
        }
    }
    if (!m_sent && !m_write_failed)
    {
        std::string plain;
        if (!m_head_given)
        {
            m_head_given = true;
            plain        = std::move(m_req.head);
            plain += m_req.body;
            m_req.body.clear();
            // Without TLS the head waits for the body's first piece, so the host gets both in one write.
            if (m_req.source && !m_source_done && !m_ssl && m_req.file_fd < 0)
            {
                m_head_out = std::move(plain);
                plain.clear();
            }
        }
        // Over TLS a file goes by sendfile once the connection's send key is the kernel's, which a body this size moves.
        if (plain.empty() && m_req.file_fd >= 0 && m_ssl && !m_file_kernel && !m_file_by_source)
        {
            static const bool kernel_tls = socketley::settings::flag("SOCKETLEY_KERNEL_TLS", true);
            m_file_kernel = kernel_tls && m_req.file_len > kernel_tls_min && tls_context::allow_kernel_tls(m_ssl, m_fd) &&
                            tls_context::start_kernel_tls(m_ssl) == tls_context::kernel_switch::on;
            m_file_by_source = !m_file_kernel;
            if (m_file_by_source && !m_req.source)
            {
                finish(false, "a body from a file goes over TLS only through the kernel's, which this one cannot");
                return;
            }
        }
        if (plain.empty() && m_req.file_fd >= 0 && !m_file_by_source &&
            (m_file_sent < m_req.file_len || m_in_pipe > 0))
        {
            // What OpenSSL holds before the switch goes first, and nothing in the clear reaches a socket it encrypts for.
            if (m_ssl && !tls_context::kernel_ready(m_ssl))
            {
                if (!flush_cipher() && !m_write_failed)
                    finish(false, "the kernel took no send key");
                return;
            }
            file_body();
            return;
        }
        // A file body that is all sent leaves the pipe empty, for the next request's.
        if (m_req.file_fd >= 0)
            m_pipe_dirty = false;
        if (plain.empty() && m_req.source && !m_source_done && (m_req.file_fd < 0 || m_file_by_source))
        {
            const uint64_t gen = m_gen;
            auto alive = m_alive;
            // A copy is called, since a source that answers at once can reach finish(), which clears m_req and with it
            // the function still running.
            const auto source = m_req.source;
            source([this, alive, gen](bool ok, std::string_view piece)
            {
                if (!*alive || m_gen != gen)
                    return;
                if (!ok)
                {
                    finish(false, "the body could not be read");
                    return;
                }
                if (piece.empty())
                {
                    m_source_done = true;
                    if (!m_head_out.empty())
                    {
                        send(std::make_shared<std::string>(std::exchange(m_head_out, {})), 0);
                        return;
                    }
                }
                else if (!m_ssl)
                {
                    auto bytes = std::make_shared<std::string>(std::exchange(m_head_out, {}));
                    bytes->append(piece);
                    send(std::move(bytes), 0);
                    return;
                }
                else
                {
                    for (size_t off = 0; off < piece.size();)
                    {
                        const int n = tls_context::ssl_write(m_ssl, piece.data() + off,
                                                             static_cast<int>(std::min(piece.size() - off, tls_piece)));
                        if (n <= 0)
                        {
                            finish(false, "the record layer took no more");
                            return;
                        }
                        off += static_cast<size_t>(n);
                    }
                    // Sent before the next piece is asked for, so the body goes as it is read and never waits whole
                    // in the record layer; the write's completion asks for the next.
                    if (flush_cipher())
                        return;
                }
                advance();
            });
            return;
        }
        // Sent once a turn finds nothing left to write, as a body from a source is asked for after its head.
        const bool nothing_more = plain.empty() && m_tls_rest_off >= m_tls_rest.size();
        if (!plain.empty() && !m_ssl)
        {
            send(std::make_shared<std::string>(std::move(plain)), 0);
            return;
        }
        if (!plain.empty())
        {
            m_tls_rest     = std::move(plain);
            m_tls_rest_off = 0;
        }
        // As much as the record layer's buffer takes, and the rest after each flush, whose completion comes back here.
        while (m_ssl && m_tls_rest_off < m_tls_rest.size())
        {
            const int n = tls_context::ssl_write(m_ssl, m_tls_rest.data() + m_tls_rest_off,
                                                 static_cast<int>(std::min(m_tls_rest.size() - m_tls_rest_off, tls_piece)));
            if (n == 0 && flush_cipher())
                return;
            if (n <= 0)
            {
                finish(false, "the record layer took no more");
                return;
            }
            m_tls_rest_off += static_cast<size_t>(n);
        }
        m_tls_rest.clear();
        m_tls_rest_off = 0;
        if (nothing_more)
            m_sent = true;
    }
    if (m_ssl && !m_write_failed && flush_cipher())
        return;
    if (!m_sent && !m_write_failed)
    {
        advance();
        return;
    }
    // The bytes the kernel still holds for the host, and the host's own work on them, are waited for by the request.
    if (m_sent)
        m_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(m_req.answer_secs);
    receive();
}

bool http_peer::flush_cipher()
{
    std::string cipher;
    while (tls_context::take_out(m_ssl, cipher) == 0)
    {
        // A mark in the stream: the send key going to the kernel, or a record of its own type sent here.
        const auto step = tls_context::kernel_step(m_ssl);
        if (step == tls_context::kernel_step_result::failed)
        {
            m_write_failed = true;
            receive();
            return true;
        }
        if (step == tls_context::kernel_step_result::wait)
        {
            const uint64_t gen = m_gen;
            auto alive = m_alive;
            if (!m_io.poll(m_fd, POLLOUT, [this, alive, gen](int64_t res)
                {
                    if (!*alive || m_gen != gen)
                        return;
                    if (res < 0 || (res & (POLLERR | POLLHUP)) != 0)
                    {
                        m_write_failed = true;
                        receive();
                        return;
                    }
                    advance();
                }))
                finish(false, "the ring is full");
            return true;
        }
        if (step == tls_context::kernel_step_result::idle || !tls_context::has_pending_out(m_ssl))
            return false;
    }
    send(std::make_shared<std::string>(std::move(cipher)), 0);
    return true;
}

void http_peer::drop_pipe()
{
    for (int* fd : {&m_pipe_rd, &m_pipe_wr})
        if (*fd >= 0)
        {
            m_loop.close_fd(*fd);
            *fd = -1;
        }
    m_pipe_dirty = false;
}

// A file body by sendfile from the loop, where a splice through the ring was an io-wq hand-off a step; a window out of
// the page cache, and what is still in the pipe from one, go by the pipe, which the ring reads without holding the loop.
void http_peer::file_body()
{
    if (m_in_pipe > 0 ||
        socketley::file_send::cold(m_req.file_fd, m_req.file_off + m_file_sent, m_req.file_len - m_file_sent))
    {
        splice_body();
        return;
    }
    uint64_t off = m_req.file_off + m_file_sent, left = m_req.file_len - m_file_sent, sent = 0;
    const auto b = socketley::file_send::send(m_fd, m_sock_flags, m_req.file_fd, off, left, sent);
    m_file_sent += sent;
    if (sent > 0)
        m_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(stall_secs);
    if (b == socketley::file_send::burst::failed)
    {
        // A host that answered before it had the whole body, and closed, may have left its answer.
        m_write_failed = true;
        receive();
        return;
    }
    if (b == socketley::file_send::burst::done)
    {
        advance();
        return;
    }
    const uint64_t gen = m_gen;
    auto alive = m_alive;
    if (!m_io.poll(m_fd, POLLOUT, [this, alive, gen](int64_t res)
        {
            if (!*alive || m_gen != gen)
                return;
            if (res < 0 || (res & (POLLERR | POLLHUP)) != 0)
            {
                m_write_failed = true;
                receive();
                return;
            }
            file_body();
        }))
        finish(false, "the ring is full");
}

void http_peer::splice_body()
{
    if (m_pipe_rd < 0)
    {
        int p[2];
        if (::pipe2(p, O_CLOEXEC) < 0)
        {
            finish(false, "no pipe could be made for the body");
            return;
        }
        m_pipe_rd = p[0];
        m_pipe_wr = p[1];
        // A megabyte a step where the system allows it, which a larger body takes in fewer steps.
        if (::fcntl(m_pipe_wr, F_SETPIPE_SZ, 1 << 20) < 0) {}
        const int size = ::fcntl(m_pipe_wr, F_GETPIPE_SZ);
        m_pipe_size = size > 0 ? static_cast<uint32_t>(size) : 65536;
    }
    m_pipe_dirty = true;
    const uint64_t gen = m_gen;
    auto alive = m_alive;
    // What is in the pipe goes to the socket first, and the file fills it again once it is empty.
    if (m_in_pipe > 0)
    {
        if (!m_io.splice(m_pipe_rd, file_io::at_stream, m_fd, m_in_pipe, [this, alive, gen](int64_t res)
            {
                if (!*alive || m_gen != gen)
                    return;
                if (res <= 0)
                {
                    // A host that answered before it had the whole body, and closed, may have left its answer.
                    m_write_failed = true;
                    drop_pipe();
                    receive();
                    return;
                }
                m_in_pipe -= static_cast<uint32_t>(std::min<int64_t>(res, m_in_pipe));
                m_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(stall_secs);
                advance();
            }))
            finish(false, "the ring is full");
        return;
    }
    const uint32_t n = static_cast<uint32_t>(std::min<uint64_t>(m_pipe_size, m_req.file_len - m_file_sent));
    if (!m_io.splice(m_req.file_fd, m_req.file_off + m_file_sent, m_pipe_wr, n, [this, alive, gen](int64_t res)
        {
            if (!*alive || m_gen != gen)
                return;
            if (res <= 0)
            {
                finish(false, "the body could not be read");
                return;
            }
            m_file_sent += static_cast<uint64_t>(res);
            m_in_pipe   += static_cast<uint32_t>(res);
            splice_body();
        }))
        finish(false, "the ring is full");
}

void http_peer::send(std::shared_ptr<std::string> bytes, size_t off)
{
    const uint64_t gen = m_gen;
    auto alive = m_alive;
    if (!m_io.pwrite(m_fd, bytes->data() + off, static_cast<uint32_t>(bytes->size() - off), file_io::at_stream,
                     [this, alive, gen, bytes, off](int64_t res)
        {
            if (!*alive || m_gen != gen)
                return;
            if (res <= 0)
            {
                // A host that answered before it had the whole body, and closed, may have left its answer to be read.
                m_write_failed = true;
                receive();
                return;
            }
            m_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(stall_secs);
            const size_t next = off + static_cast<size_t>(res);
            if (next < bytes->size())
            {
                send(bytes, next);
                return;
            }
            advance();
        }))
        finish(false, "the ring is full");
}

void http_peer::receive()
{
    // A buffer held by the read's completion, so a read the end of an exchange left in the ring writes nowhere shared;
    // the last one again when nothing holds it, so a stream is not a fresh allocation every read.
    const uint32_t want = m_read.next();
    if (!m_rbuf || m_rbuf.use_count() > 1 || m_rbuf_size != want)
    {
        m_rbuf = std::shared_ptr<char[]>(new char[want]);
        m_rbuf_size = want;
    }
    std::shared_ptr<char[]> buf = m_rbuf;
    const uint64_t gen = m_gen;
    auto alive = m_alive;
    if (!m_io.pread(m_fd, buf.get(), want, file_io::at_stream, [this, alive, gen, buf](int64_t res)
        {
            if (!*alive || m_gen != gen)
                return;
            // The host closed after answering, which is how an answer to a Connection: close request ends.
            if (res <= 0)
            {
                m_eof = true;
                finish(true);
                return;
            }
            m_read.took(static_cast<size_t>(res));
            got(buf.get(), static_cast<size_t>(res));
        }))
        finish(false, "the ring is full");
}

void http_peer::got(const char* p, size_t n)
{
    m_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(stall_secs);
    if (!m_ssl)
        m_in.append(p, n);
    else
    {
        if (tls_context::bio_write_in(m_ssl, p, static_cast<int>(n)) < 0)
        {
            finish(false, "the record layer took no more");
            return;
        }
        if (!m_handshaken)
        {
            advance();
            return;
        }
        char buf[16384];
        for (;;)
        {
            const int r = tls_context::ssl_read(m_ssl, buf, sizeof(buf));
            if (r <= 0)
                break;
            m_in.append(buf, static_cast<size_t>(r));
        }
    }
    // Past the cap is no answer this client reads, and not a truncated one handed on as whole; asked first, since the
    // read that crosses it can be the one that completes it.
    if (const size_t cap = m_req.max_answer ? m_req.max_answer : answer_cap; m_in.size() > cap)
    {
        finish(false, "the answer is larger than " + std::to_string(cap >> 10) + " KiB");
        return;
    }
    if (answer_complete())
    {
        finish(true);
        return;
    }
    if (m_ssl && !m_sent && !m_write_failed)
    {
        advance();
        return;
    }
    receive();
}

bool http_peer::answer_complete(bool framed) const
{
    if (m_head_end == std::string::npos)
        m_head_end = m_in.find("\r\n\r\n");
    const size_t end = m_head_end;
    if (end == std::string::npos)
        return false;
    if (m_req.head_only && !framed)
        return status_of(m_in) != 0;
    const std::string_view head(m_in.data(), end + 2);
    const std::string_view body = std::string_view(m_in).substr(end + 4);
    const int status = status_of(head);
    if (status == 204 || status == 304)
        return true;
    if (http_list_has_token(head_value(head, "transfer-encoding"), "chunked", 7))
    {
        // A chunked body ends with an empty line, so a buffer that does not is not decoded again just to learn so.
        if (!m_in.ends_with("\r\n\r\n"))
            return false;
        http_chunked_decoder d;
        std::string_view in = body, out;
        for (;;)
        {
            const chunk_step s = http_chunked_next(d, in, out);
            if (s == chunk_step::done || s == chunk_step::bad)
                return true;
            if (s == chunk_step::need_more)
                return false;
        }
    }
    size_t length = 0;
    if (const std::string_view cl = head_value(head, "content-length"); http_whole_decimal(cl, length))
        return body.size() >= length;
    return false;
}

bool http_peer::keepable() const
{
    if (m_eof || m_write_failed || !m_sent || m_stopped || !answer_complete(true) || !m_in.starts_with("HTTP/1.1 "))
        return false;
    const size_t end = m_in.find("\r\n\r\n");
    const std::string_view head(m_in.data(), end + 2);
    if (http_list_has_token(head_value(head, "connection"), "close", 5))
        return false;
    // Bytes past the answer would be read as the next one's, so only an answer that ends where the bytes do is kept.
    size_t length = 0;
    if (http_list_has_token(head_value(head, "transfer-encoding"), "chunked", 7))
    {
        http_chunked_decoder d;
        std::string_view in = std::string_view(m_in).substr(end + 4), out;
        chunk_step s;
        while ((s = http_chunked_next(d, in, out)) == chunk_step::payload) {}
        return s == chunk_step::done && in.empty();
    }
    if (http_whole_decimal(head_value(head, "content-length"), length))
        return m_in.size() == end + 4 + length;
    const int status = status_of(head);
    return (status == 204 || status == 304) && m_in.size() == end + 4;
}

bool http_peer::still_open()
{
    char buf[16384];
    for (;;)
    {
        const ssize_t r = ::recv(m_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (r < 0)
            return errno == EAGAIN || errno == EWOULDBLOCK;
        // Closed, or bytes nobody asked for on a plain connection.
        if (r == 0 || !m_ssl || tls_context::bio_write_in(m_ssl, buf, static_cast<int>(r)) < 0)
            return false;
        // A record after the answer is a session ticket or a close; an application byte would be no answer's.
        char app[1];
        if (tls_context::ssl_read(m_ssl, app, sizeof(app)) > 0 || (SSL_get_shutdown(m_ssl) & SSL_RECEIVED_SHUTDOWN))
            return false;
    }
}

void http_peer::finish(bool answered, std::string why)
{
    ++m_gen;
    m_busy = false;
    if (m_pipe_dirty)
        drop_pipe();
    if (answered && keepable())
        m_idle_since = std::chrono::steady_clock::now();
    else
        close_socket();
    http_answer a;
    if (const size_t end = m_in.find("\r\n\r\n"); answered && end != std::string::npos && status_of(m_in) != 0)
    {
        a.status = status_of(m_in);
        a.head   = m_in.substr(0, end + 2);
        std::string_view body = std::string_view(m_in).substr(end + 4);
        size_t length = 0;
        // An answer to HEAD, a 204 and a 304 have no body whatever their head says of one (RFC 9112 6.3).
        if (m_req.head_only || a.status == 204 || a.status == 304)
        {
        }
        else if (http_list_has_token(a.header("transfer-encoding"), "chunked", 7))
        {
            http_chunked_decoder d;
            std::string_view out;
            for (;;)
            {
                const chunk_step s = http_chunked_next(d, body, out);
                if (s == chunk_step::payload)
                {
                    a.body.append(out);
                    continue;
                }
                // An answer whose framing breaks off is no answer.
                if (s != chunk_step::done)
                    a.status = 0;
                break;
            }
        }
        else if (http_whole_decimal(a.header("content-length"), length))
        {
            if (body.size() < length && !m_req.head_only)
            {
                a.status = 0;
                if (why.empty())
                    why = "the answer stopped " + std::to_string(length - body.size()) +
                          " bytes short of its Content-Length";
            }
            a.body = std::string(body.substr(0, length));
        }
        else
            a.body = std::string(body);
    }
    // Bytes that do not begin like an answer are named by their start, since a host that speaks something else is not
    // one that closed early.
    if (a.status == 0 && why.empty() && answered && !m_in.empty() && !m_in.starts_with("HTTP/"))
        why = "the answer is not an HTTP response (it begins \"" + m_in.substr(0, std::min<size_t>(m_in.size(), 32)) +
              "\")";
    if (a.status == 0)
        a.failure = !why.empty() ? std::move(why) : answered ? "the host closed before a whole answer" : "no answer";
    auto done = std::move(m_done);
    m_done = nullptr;
    m_req  = http_request{};
    m_in.clear();
    m_head_end = std::string::npos;
    if (done && !m_stopped)
        done(std::move(a));
}

void http_peer::close_socket()
{
    // A body the kernel encrypted can still be in its hands, which a FIN now would throw away.
    const bool kernel_tls = m_ssl && tls_context::kernel_sends(m_ssl);
    if (m_ssl)
    {
        // Kept, from a finished handshake only, so the next dial past keep_idle_secs resumes rather than starting over.
        if (m_tls)
            m_tls->remember_session(m_target.host, m_ssl);
        tls_context::free_ssl(m_ssl);
        m_ssl = nullptr;
    }
    if (m_fd >= 0)
    {
        m_loop.close_fd_orderly(m_fd, kernel_tls);
        m_fd = -1;
    }
}

void http_peer::tick(std::chrono::steady_clock::time_point now)
{
    if (m_busy && now >= m_deadline)
        finish(false, "nothing moved for " + std::to_string(stall_secs) + "s");
    else if (!m_busy && m_fd >= 0 && now - m_idle_since >= std::chrono::seconds(keep_idle_secs))
        close_socket();
}

void http_peer::stop()
{
    m_stopped = true;
    if (m_busy)
        finish(false, "the runtime stopped");
    close_socket();
    drop_pipe();
}

}   // namespace socketley
