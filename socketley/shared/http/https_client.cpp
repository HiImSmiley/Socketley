#include "../net/read_buffer.h"
#include "https_client.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "http_framing.h"
#include "../crypto/tls_context.h"

namespace https_client
{

namespace
{

bool fail(std::string& err, std::string why)
{
    err = std::move(why);
    return false;
}

// `whole` is the far end closing the stream itself, which alone ends a body that names no length.
bool parse(const std::string& raw, bool whole, bool head, reply& out, std::string& err)
{
    const size_t end = raw.find("\r\n\r\n");
    if (end == std::string::npos || raw.size() < 12)
        return fail(err, "no HTTP answer");
    out.status = std::atoi(raw.c_str() + 9);
    size_t pos = raw.find("\r\n") + 2;
    while (pos < end)
    {
        const size_t eol = raw.find("\r\n", pos);
        const std::string line = raw.substr(pos, eol - pos);
        if (const size_t colon = line.find(':'); colon != std::string::npos)
        {
            size_t v = colon + 1;
            while (v < line.size() && line[v] == ' ')
                ++v;
            out.headers.emplace_back(line.substr(0, colon), line.substr(v));
        }
        pos = eol + 2;
    }
    std::string body = raw.substr(end + 4);
    // An answer to HEAD, a 204 and a 304 carry no body whatever their headers say.
    if (head || out.status == 204 || out.status == 304)
    {
        out.body.clear();
        return true;
    }
    const std::string length = out.header("content-length");
    if (strncasecmp(out.header("transfer-encoding").c_str(), "chunked", 7) == 0)
    {
        std::string plain;
        http_chunked_decoder dechunk;
        std::string_view in(body), piece;
        chunk_step step;
        while ((step = http_chunked_next(dechunk, in, piece)) == chunk_step::payload)
            plain.append(piece);
        if (step == chunk_step::bad)
            return fail(err, "the answer's chunks are not chunked framing");
        if (step != chunk_step::done)
            return fail(err, "the answer ended before its last chunk");
        body = std::move(plain);
    }
    else if (!length.empty())
    {
        // Digits and nothing else, or "12abc" would cut the body to 12 and "abc" would give an empty one as whole.
        size_t want = 0;
        const auto [end, ec] = std::from_chars(length.data(), length.data() + length.size(), want);
        if (ec != std::errc() || end != length.data() + length.size())
            return fail(err, "the answer's Content-Length is no number: " + length);
        if (body.size() < want)
            return fail(err, "the answer ended " + std::to_string(want - body.size()) + " bytes short of its length");
        body.resize(want);
    }
    else if (!whole)
        return fail(err, "the connection broke before the answer ended");
    out.body = std::move(body);
    return true;
}

}   // namespace

std::string reply::header(std::string_view name) const
{
    for (const auto& [k, v] : headers)
        if (k.size() == name.size() && strncasecmp(k.data(), name.data(), k.size()) == 0)
            return v;
    return {};
}

client::~client()
{
    if (m_ctx)
        SSL_CTX_free(m_ctx);
}

bool client::init(std::string& err, const std::string& ca_file, std::string user_agent)
{
    m_agent = std::move(user_agent);
    std::string why;
    m_ctx = tls_context::shared_client_ctx(ca_file, why);
    return m_ctx || fail(err, why);
}

namespace
{

// Whether `sa` is an address anyone may reach: not loopback, private, link-local, shared, unspecified or multicast.
bool public_address(const sockaddr* sa)
{
    if (sa->sa_family == AF_INET)
    {
        const auto a = ntohl(reinterpret_cast<const sockaddr_in*>(sa)->sin_addr.s_addr);
        const auto in = [a](uint32_t net, int bits) { return (a >> (32 - bits)) == (net >> (32 - bits)); };
        return !(in(0x00000000, 8) || in(0x0A000000, 8) || in(0x7F000000, 8) || in(0xA9FE0000, 16) ||
                 in(0xAC100000, 12) || in(0xC0A80000, 16) || in(0x64400000, 10) || in(0xE0000000, 3));
    }
    if (sa->sa_family == AF_INET6)
    {
        const auto& a = reinterpret_cast<const sockaddr_in6*>(sa)->sin6_addr;
        if (IN6_IS_ADDR_V4MAPPED(&a))
        {
            sockaddr_in v4{};
            v4.sin_family = AF_INET;
            std::memcpy(&v4.sin_addr, a.s6_addr + 12, 4);
            return public_address(reinterpret_cast<const sockaddr*>(&v4));
        }
        return !(IN6_IS_ADDR_UNSPECIFIED(&a) || IN6_IS_ADDR_LOOPBACK(&a) || IN6_IS_ADDR_LINKLOCAL(&a) ||
                 IN6_IS_ADDR_MULTICAST(&a) || (a.s6_addr[0] & 0xFE) == 0xFC);
    }
    return false;
}

}   // namespace

int client::dial(const std::string& url, std::string& path, std::string& hostport, SSL*& ssl, std::string& err,
                 int timeout_s)
{
    ssl = nullptr;
    std::string_view u = url;
    const bool tls = u.starts_with("https://");
    if (!tls && !u.starts_with("http://"))
    {
        err = "not an http or https URL: " + url;
        return -1;
    }
    u.remove_prefix(tls ? 8 : 7);
    const size_t slash = u.find('/');
    hostport.assign(u.substr(0, slash));
    path = slash == std::string_view::npos ? std::string("/") : std::string(u.substr(slash));
    std::string host = hostport, port = tls ? "443" : "80";
    // An IPv6 host is bracketed, and its brackets are no part of the address.
    if (hostport.starts_with('['))
    {
        const size_t close = hostport.find(']');
        if (close == std::string::npos)
        {
            err = "an IPv6 host is written in brackets: " + url;
            return -1;
        }
        host = hostport.substr(1, close - 1);
        if (close + 1 < hostport.size())
        {
            if (hostport[close + 1] != ':')
            {
                err = "after an IPv6 host in brackets comes its port: " + url;
                return -1;
            }
            port = hostport.substr(close + 2);
        }
    }
    else if (const size_t colon = hostport.rfind(':'); colon != std::string::npos)
    {
        host = hostport.substr(0, colon);
        port = hostport.substr(colon + 1);
    }
    std::string dial_host = host, dial_port = port;
    if (const size_t colon = m_connect.rfind(':'); colon != std::string::npos)
    {
        dial_host = m_connect.substr(0, colon);
        dial_port = m_connect.substr(colon + 1);
    }
    addrinfo hints{}, *res = nullptr;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(dial_host.c_str(), dial_port.c_str(), &hints, &res) != 0 || !res)
    {
        err = "cannot resolve " + host;
        return -1;
    }
    int fd = -1;
    bool refused = false;
    for (addrinfo* a = res; a && fd < 0; a = a->ai_next)
    {
        if (m_public_only && m_connect.empty() && !public_address(a->ai_addr))
        {
            refused = true;
            continue;
        }
        fd = ::socket(a->ai_family, a->ai_socktype | SOCK_CLOEXEC, a->ai_protocol);
        if (fd < 0)
            continue;
        timeval tv{timeout_s, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (::connect(fd, a->ai_addr, a->ai_addrlen) != 0)
        {
            ::close(fd);
            fd = -1;
        }
    }
    freeaddrinfo(res);
    if (fd < 0)
    {
        err = refused ? host + " names no public address" : "cannot connect to " + hostport;
        return -1;
    }
    if (tls)
    {
        ssl = SSL_new(m_ctx);
        // A record in one recv rather than its header and its body in two; every read here blocks, so nothing waits on
        // a poll() for bytes OpenSSL already holds.
        if (ssl)
            SSL_set_read_ahead(ssl, 1);
        if (!ssl || SSL_set_fd(ssl, fd) != 1 || !tls_context::pin_peer_name(ssl, host))
        {
            err = "TLS to " + hostport + " could not be set up to check the name " + host;
            if (ssl)
                SSL_free(ssl);
            ssl = nullptr;
            ::close(fd);
            return -1;
        }
        if (SSL_connect(ssl) != 1)
        {
            const unsigned long e = ERR_get_error();
            const char* why = e ? ERR_reason_error_string(e) : nullptr;
            err = "TLS to " + hostport + " failed: " + (why ? why : "the handshake did not complete");
            SSL_free(ssl);
            ssl = nullptr;
            ::close(fd);
            return -1;
        }
    }
    return fd;
}

namespace
{

bool put_all(int fd, SSL* ssl, const std::string& s)
{
    if (ssl)
        return SSL_write(ssl, s.data(), static_cast<int>(s.size())) == static_cast<int>(s.size());
    size_t at = 0;
    while (at < s.size())
    {
        const ssize_t n = ::send(fd, s.data() + at, s.size() - at, MSG_NOSIGNAL);
        if (n <= 0)
            return false;
        at += static_cast<size_t>(n);
    }
    return true;
}

}   // namespace

bool client::request(std::string_view method, const std::string& url, std::string_view type, std::string_view body,
                     reply& out, std::string& err, int timeout_s, size_t max_bytes,
                     const std::vector<std::pair<std::string, std::string>>& headers)
{
    // One deadline for the whole exchange, so a server that drips a byte a second cannot hold it longer.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_s);
    std::string path, hostport;
    SSL* ssl = nullptr;
    const int fd = dial(url, path, hostport, ssl, err, timeout_s);
    if (fd < 0)
        return false;
    std::string req = std::string(method) + " " + path + " HTTP/1.1\r\nHost: " + hostport + "\r\nUser-Agent: " +
                      m_agent + "\r\nAccept: */*\r\nConnection: close\r\n";
    if (!type.empty())
        req += "Content-Type: " + std::string(type) + "\r\n";
    // A header whose name or value would end the line is left out, not let split the request.
    for (const auto& [k, v] : headers)
        if (k.find_first_of("\r\n:") == std::string::npos && v.find_first_of("\r\n") == std::string::npos)
            req += k + ": " + v + "\r\n";
    req += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
    req += body;
    bool ok = put_all(fd, ssl, req);
    if (!ok)
        err = "sending to " + hostport + " failed";
    std::string raw;
    bool whole = false;
    // 16 KiB a read, growing while an answer streams (shared/net/read_buffer.h), sized before each read.
    socketley::read_buffer<16384> rb;
    size_t last = 0;
    while (ok)
    {
        if (last)
            rb.took(last);
        last = 0;
        const auto left = std::chrono::duration_cast<std::chrono::microseconds>(deadline - std::chrono::steady_clock::now());
        if (left.count() <= 0)
        {
            err = hostport + " did not answer within " + std::to_string(timeout_s) + "s";
            ok = false;
            break;
        }
        timeval tv{static_cast<time_t>(left.count() / 1000000), static_cast<suseconds_t>(left.count() % 1000000)};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        const int n = ssl ? SSL_read(ssl, rb.data(), static_cast<int>(rb.size()))
                          : static_cast<int>(::recv(fd, rb.data(), rb.size(), 0));
        if (n > 0)
        {
            last = static_cast<size_t>(n);
            raw.append(rb.data(), static_cast<size_t>(n));
            // The head is allowed its own 16 KiB beside the body's bound.
            if (max_bytes && raw.size() > max_bytes + (16u << 10))
            {
                err = hostport + " answered more than " + std::to_string(max_bytes) + " bytes";
                ok = false;
                break;
            }
            continue;
        }
        if (!ssl && n < 0 && errno == EINTR)
            continue;
        whole = ssl ? SSL_get_error(ssl, n) == SSL_ERROR_ZERO_RETURN : n == 0;
        break;
    }
    if (ssl)
        SSL_free(ssl);
    ::close(fd);
    ERR_clear_error();
    return ok && parse(raw, whole, method == "HEAD", out, err);
}

bool client::stream(const std::string& url, const std::vector<std::pair<std::string, std::string>>& headers,
                    const std::function<bool(int status)>& on_status, const std::function<bool(std::string_view)>& on_data,
                    std::string& err, int idle_s)
{
    std::string path, hostport;
    SSL* ssl = nullptr;
    const int fd = dial(url, path, hostport, ssl, err, idle_s);
    if (fd < 0)
        return false;
    std::string req = "GET " + path + " HTTP/1.1\r\nHost: " + hostport + "\r\nUser-Agent: " + m_agent +
                      "\r\nAccept: text/event-stream\r\nConnection: close\r\n";
    for (const auto& [k, v] : headers)
        req += k + ": " + v + "\r\n";
    req += "\r\n";
    bool ok = put_all(fd, ssl, req);
    if (!ok)
        err = "sending to " + hostport + " failed";
    std::string raw;
    bool head_done = false, chunked = false, closed = false;
    // A chunked body's state, across reads.
    http_chunked_decoder dechunk;
    socketley::read_buffer<16384> rb;
    size_t last = 0;
    while (ok)
    {
        if (last)
            rb.took(last);
        last = 0;
        const int n = ssl ? SSL_read(ssl, rb.data(), static_cast<int>(rb.size()))
                          : static_cast<int>(::recv(fd, rb.data(), rb.size(), 0));
        if (n > 0)
            last = static_cast<size_t>(n);
        char* const buf = rb.data();
        if (n <= 0)
        {
            const bool timed_out = ssl ? (SSL_get_error(ssl, n) == SSL_ERROR_WANT_READ ||
                                          (SSL_get_error(ssl, n) == SSL_ERROR_SYSCALL && (errno == EAGAIN || errno == EWOULDBLOCK)))
                                       : n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR);
            if (timed_out)
            {
                ERR_clear_error();
                if (!on_data({}))
                    break;
                continue;
            }
            closed = ssl ? SSL_get_error(ssl, n) == SSL_ERROR_ZERO_RETURN || n == 0 : n == 0;
            if (!closed)
                err = "the stream from " + hostport + " broke";
            break;
        }
        raw.append(buf, static_cast<size_t>(n));
        if (!head_done)
        {
            const size_t end = raw.find("\r\n\r\n");
            if (end == std::string::npos)
            {
                if (raw.size() > 65536)
                {
                    err = "no HTTP answer from " + hostport;
                    break;
                }
                continue;
            }
            reply h;
            parse(raw.substr(0, end + 4), true, true, h, err);
            head_done = true;
            chunked = strncasecmp(h.header("transfer-encoding").c_str(), "chunked", 7) == 0;
            raw.erase(0, end + 4);
            if (!on_status(h.status))
                break;
        }
        std::string plain;
        if (!chunked)
            plain.swap(raw);
        else
        {
            std::string_view in(raw), piece;
            chunk_step step;
            while ((step = http_chunked_next(dechunk, in, piece)) == chunk_step::payload)
                plain.append(piece);
            raw.erase(0, raw.size() - in.size());
            if (step == chunk_step::done)
            {
                closed = true;
                ok = false;
            }
            else if (step == chunk_step::bad)
            {
                err = "the stream from " + hostport + " is not chunked framing";
                ok = false;
            }
        }
        if (!plain.empty() && !on_data(plain))
            break;
    }
    if (ssl)
        SSL_free(ssl);
    ::close(fd);
    ERR_clear_error();
    return closed;
}

}   // namespace https_client
