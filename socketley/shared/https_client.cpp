#include "https_client.h"

#include <netdb.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>

#include "tls_context.h"

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
        size_t p = 0;
        bool last = false;
        while (p < body.size())
        {
            const size_t eol = body.find("\r\n", p);
            if (eol == std::string::npos)
                break;
            const size_t n = std::strtoul(body.c_str() + p, nullptr, 16);
            if (n == 0)
            {
                last = true;
                break;
            }
            // Compared without the sum, which a chunk size near 2^64 would wrap.
            if (n > body.size() - (eol + 2))
                break;
            plain.append(body, eol + 2, n);
            p = eol + 2 + n + 2;
        }
        if (!last)
            return fail(err, "the answer ended before its last chunk");
        body = std::move(plain);
    }
    else if (!length.empty())
    {
        const size_t want = std::strtoull(length.c_str(), nullptr, 10);
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
    m_ctx = SSL_CTX_new(TLS_client_method());
    if (!m_ctx)
        return fail(err, "no TLS context");
    SSL_CTX_set_min_proto_version(m_ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER, nullptr);
    const bool ok = !ca_file.empty() ? SSL_CTX_load_verify_locations(m_ctx, ca_file.c_str(), nullptr) == 1
                                     : tls_context::load_system_roots(m_ctx) == 1;
    return ok || fail(err, "the trust roots could not be loaded" + (ca_file.empty() ? std::string() : ": " + ca_file));
}

bool client::request(std::string_view method, const std::string& url, std::string_view type, std::string_view body,
                     reply& out, std::string& err, int timeout_s)
{
    std::string_view u = url;
    const bool tls = u.starts_with("https://");
    if (!tls && !u.starts_with("http://"))
        return fail(err, "not an http or https URL: " + url);
    u.remove_prefix(tls ? 8 : 7);
    const size_t slash = u.find('/');
    std::string hostport(u.substr(0, slash)), path(slash == std::string_view::npos ? "/" : u.substr(slash));
    std::string host = hostport, port = tls ? "443" : "80";
    // An IPv6 host is bracketed, and its brackets are no part of the address.
    if (hostport.starts_with('['))
    {
        const size_t close = hostport.find(']');
        if (close == std::string::npos)
            return fail(err, "an IPv6 host is written in brackets: " + url);
        host = hostport.substr(1, close - 1);
        if (close + 1 < hostport.size())
        {
            if (hostport[close + 1] != ':')
                return fail(err, "after an IPv6 host in brackets comes its port: " + url);
            port = hostport.substr(close + 2);
        }
    }
    else if (const size_t colon = hostport.rfind(':'); colon != std::string::npos)
    {
        host = hostport.substr(0, colon);
        port = hostport.substr(colon + 1);
    }
    addrinfo hints{}, *res = nullptr;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res)
        return fail(err, "cannot resolve " + host);
    int fd = -1;
    for (addrinfo* a = res; a && fd < 0; a = a->ai_next)
    {
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
        return fail(err, "cannot connect to " + hostport);
    SSL* ssl = nullptr;
    bool ok = true;
    if (tls)
    {
        ssl = SSL_new(m_ctx);
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, host.c_str());
        SSL_set1_host(ssl, host.c_str());
        ok = SSL_connect(ssl) == 1;
        if (!ok)
        {
            const unsigned long e = ERR_get_error();
            const char* why = e ? ERR_reason_error_string(e) : nullptr;
            err = "TLS to " + hostport + " failed: " + (why ? why : "the handshake did not complete");
        }
    }
    const auto put = [&](const std::string& s) {
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
    };
    if (ok)
    {
        std::string req = std::string(method) + " " + path + " HTTP/1.1\r\nHost: " + hostport + "\r\nUser-Agent: " +
                          m_agent + "\r\nAccept: */*\r\nConnection: close\r\n";
        if (!type.empty())
            req += "Content-Type: " + std::string(type) + "\r\n";
        req += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
        req += body;
        ok = put(req);
        if (!ok)
            err = "sending to " + hostport + " failed";
    }
    std::string raw;
    bool whole = false;
    while (ok)
    {
        char buf[16384];
        const int n = ssl ? SSL_read(ssl, buf, sizeof buf) : static_cast<int>(::recv(fd, buf, sizeof buf, 0));
        if (n > 0)
        {
            raw.append(buf, static_cast<size_t>(n));
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

}   // namespace https_client
