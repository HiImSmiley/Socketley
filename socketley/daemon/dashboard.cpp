#include "dashboard.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <set>

#include "runtime_schema.h"
#include "../cli/ipc_client.h"
#include "../runtime/proxy/proxy_auth.h"
#include "../runtime/storage/json_doc.h"
#include "../shared/blocking_write.h"
#include "../shared/logging.h"

namespace socketley::storage
{
std::string_view storage_ui_style();
std::string storage_ui_kit();
}

namespace dashboard
{

namespace
{

#include "dashboard_page.inc"

constexpr int64_t session_seconds = 12 * 3600;

std::string json_quote(std::string_view v)
{
    std::string o = "\"";
    for (unsigned char c : v)
    {
        if (c == '"' || c == '\\')
            o += '\\', o += static_cast<char>(c);
        else if (c < 0x20)
        {
            char b[8];
            std::snprintf(b, sizeof b, "\\u%04x", c);
            o += b;
        }
        else
            o += static_cast<char>(c);
    }
    return o + "\"";
}

std::string lower(std::string_view s)
{
    std::string o(s);
    std::transform(o.begin(), o.end(), o.begin(), [](unsigned char c) { return std::tolower(c); });
    return o;
}

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

bool local(std::string_view ip)
{
    return ip.empty() || ip.starts_with("127.") || ip == "::1" || ip.starts_with("::ffff:127.");
}

// The page with the storage interface's look, which it shares rather than copies.
const std::string& page()
{
    static const std::string p = [] {
        std::string s(dashboard_page);
        const std::string mark = "/*STYLE*/";
        if (const size_t at = s.find(mark); at != std::string::npos)
            s.replace(at, mark.size(), socketley::storage::storage_ui_style());
        const std::string kit = "/*KIT*/";
        if (const size_t at = s.find(kit); at != std::string::npos)
            s.replace(at, kit.size(), socketley::storage::storage_ui_kit());
        return s;
    }();
    return p;
}

// The commands the page may send; anything else is the CLI's alone.
const std::set<std::string_view> verbs = {"create", "edit", "import", "start", "stop", "remove", "reload",
                                          "reload-lua", "show", "stats", "ls", "ps"};

}   // namespace

std::string_view request::header(std::string_view name) const
{
    const auto it = headers.find(std::string(name));
    return it == headers.end() ? std::string_view{} : std::string_view(it->second);
}

std::string request::client() const
{
    if (!local(peer))
        return peer;
    std::string_view xff = header("x-forwarded-for");
    if (const size_t comma = xff.rfind(','); comma != std::string_view::npos)
        xff.remove_prefix(comma + 1);
    xff = trim(xff);
    return xff.empty() ? (peer.empty() ? std::string("local") : peer) : std::string(xff);
}

bool read_request(int fd, request& r, size_t max_body)
{
    std::string in;
    size_t end;
    char buf[8192];
    while ((end = in.find("\r\n\r\n")) == std::string::npos)
    {
        if (in.size() > 16384)
            return false;
        const ssize_t n = ::read(fd, buf, sizeof buf);
        if (n <= 0)
            return false;
        in.append(buf, static_cast<size_t>(n));
    }
    const std::string_view head(in.data(), end);
    const size_t line_end = head.find("\r\n");
    const std::string_view line = head.substr(0, line_end);
    const size_t sp1 = line.find(' '), sp2 = line.rfind(' ');
    if (sp1 == std::string_view::npos || sp2 == sp1)
        return false;
    r.method.assign(line.substr(0, sp1));
    std::string_view target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    if (const size_t q = target.find('?'); q != std::string_view::npos)
    {
        r.query.assign(target.substr(q + 1));
        target = target.substr(0, q);
    }
    r.path.assign(target);
    for (size_t p = line_end == std::string_view::npos ? head.size() : line_end + 2; p < head.size();)
    {
        size_t nl = head.find("\r\n", p);
        if (nl == std::string_view::npos)
            nl = head.size();
        const std::string_view h = head.substr(p, nl - p);
        p = nl + 2;
        const size_t colon = h.find(':');
        if (colon == std::string_view::npos)
            continue;
        std::string name = lower(h.substr(0, colon));
        // A field sent twice is refused rather than one of them taken.
        if (r.headers.count(name))
            return false;
        r.headers.emplace(std::move(name), std::string(trim(h.substr(colon + 1))));
    }
    if (!r.header("transfer-encoding").empty())
        return false;
    const std::string_view cl = r.header("content-length");
    const size_t want = cl.empty() ? 0 : std::strtoull(std::string(cl).c_str(), nullptr, 10);
    if (want > max_body)
        return false;
    r.body = in.substr(end + 4);
    while (r.body.size() < want)
    {
        const ssize_t n = ::read(fd, buf, sizeof buf);
        if (n <= 0)
            return false;
        r.body.append(buf, static_cast<size_t>(n));
    }
    r.body.resize(want);
    return true;
}

void send(int fd, int status, std::string_view type, std::string_view body, std::string_view extra_headers)
{
    const char* reason = status == 200 ? "OK" : status == 204 ? "No Content" : status == 400 ? "Bad Request"
                       : status == 401 ? "Unauthorized" : status == 403 ? "Forbidden" : status == 404 ? "Not Found"
                       : status == 405 ? "Method Not Allowed" : status == 413 ? "Payload Too Large"
                       : status == 429 ? "Too Many Requests" : status == 502 ? "Bad Gateway" : "Error";
    std::string out = "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\n";
    if (!type.empty())
        out += "Content-Type: " + std::string(type) + "\r\n";
    out += "X-Frame-Options: DENY\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n"
           "Cache-Control: no-store\r\nConnection: close\r\n";
    out += extra_headers;
    out += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
    out += body;
    socketley::write_all(fd, out.data(), out.size());
}

server::server(std::string credentials) : m_credentials(std::move(credentials))
{
    unsigned char k[32];
    if (RAND_bytes(k, sizeof k) == 1)
        m_key.assign(reinterpret_cast<char*>(k), sizeof k);
    if (configured())
    {
        m_auth = std::make_unique<proxy_auth>();
        m_auth->configure("basic:" + m_credentials, "dashboard");
    }
}

server::~server() = default;

std::string server::seal(std::string_view user, int64_t expires) const
{
    const std::string msg = std::string(user) + "." + std::to_string(expires);
    unsigned char mac[32];
    unsigned int n = 0;
    HMAC(EVP_sha256(), m_key.data(), static_cast<int>(m_key.size()), reinterpret_cast<const unsigned char*>(msg.data()),
         msg.size(), mac, &n);
    static constexpr char hex[] = "0123456789abcdef";
    std::string out = msg + ".";
    for (unsigned i = 0; i < n; ++i)
        out += {hex[mac[i] >> 4], hex[mac[i] & 15]};
    return out;
}

std::string server::session_of(const request& r) const
{
    if (!configured() || m_key.size() != 32)
        return {};
    std::string_view cookies = r.header("cookie");
    std::string_view v;
    for (size_t p = 0; p < cookies.size();)
    {
        size_t semi = cookies.find(';', p);
        if (semi == std::string_view::npos)
            semi = cookies.size();
        const std::string_view c = trim(cookies.substr(p, semi - p));
        if (c.starts_with("skl_dash="))
            v = c.substr(9);
        p = semi + 1;
    }
    const size_t d2 = v.rfind('.'), d1 = d2 == std::string_view::npos ? d2 : v.rfind('.', d2 - 1);
    if (d1 == std::string_view::npos || d1 == 0)
        return {};
    const std::string user(v.substr(0, d1));
    const int64_t expires = std::strtoll(std::string(v.substr(d1 + 1, d2 - d1 - 1)).c_str(), nullptr, 10);
    if (expires < static_cast<int64_t>(std::time(nullptr)))
        return {};
    const std::string want = seal(user, expires);
    if (want.size() != v.size() || CRYPTO_memcmp(want.data(), v.data(), v.size()) != 0)
        return {};
    return user;
}

bool server::handle(int fd, const request& r)
{
    if (r.path == "/" || r.path == "/dashboard")
    {
        send(fd, 200, "text/html; charset=utf-8", page(),
             "Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' "
             "'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'\r\n");
        return true;
    }
    if (r.path == "/api/session")
    {
        session(fd, r);
        return true;
    }
    if (r.path == "/api/schema")
    {
        if (!may_read(r))
            send(fd, 401, "text/plain; charset=utf-8", "Sign in first.\n");
        else
            send(fd, 200, "application/json", runtime_schema::json());
        return true;
    }
    if (r.path == "/api/run")
    {
        run(fd, r);
        return true;
    }
    return false;
}

void server::session(int fd, const request& r)
{
    if (r.method == "GET")
    {
        const std::string who = session_of(r);
        send(fd, 200, "application/json",
             "{\"configured\":" + std::string(configured() ? "true" : "false") + ",\"user\":" +
                 (who.empty() ? std::string("null") : json_quote(who)) + "}");
        return;
    }
    const bool https = r.header("x-forwarded-proto") == "https";
    if (r.method == "DELETE")
    {
        send(fd, 204, {}, {}, std::string("Set-Cookie: skl_dash=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict") +
                                  (https ? "; Secure" : "") + "\r\n");
        return;
    }
    if (r.method != "POST")
    {
        send(fd, 405, "text/plain; charset=utf-8", "Signed in with POST, asked with GET, out with DELETE.\n");
        return;
    }
    if (!configured())
    {
        send(fd, 403, "text/plain; charset=utf-8",
             "Signing in needs daemon.dashboard_credentials in the daemon's configuration.\n");
        return;
    }
    int64_t retry = 0;
    const std::string_view authorization = r.header("authorization");
    const auto v = m_auth->check(authorization, r.client(), retry);
    if (v == proxy_auth::verdict::barred)
    {
        send(fd, 429, "text/plain; charset=utf-8", "Too many failed sign-ins from this address; try again later.\n",
             "Retry-After: " + std::to_string(retry) + "\r\n");
        return;
    }
    if (v != proxy_auth::verdict::pass)
    {
        send(fd, 401, "text/plain; charset=utf-8", "That access key and secret are no admin's.\n");
        return;
    }
    // The access key, which the check just took from the same field.
    std::string pair;
    {
        const std::string_view b64 = trim(authorization.substr(authorization.find(' ') + 1));
        std::string out(b64.size(), '\0');
        const int n = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                                      reinterpret_cast<const unsigned char*>(b64.data()), static_cast<int>(b64.size()));
        if (n > 0)
            pair.assign(out.data(), static_cast<size_t>(n));
    }
    const std::string user = pair.substr(0, pair.find(':'));
    const int64_t expires = static_cast<int64_t>(std::time(nullptr)) + session_seconds;
    LOG_INFO(("dashboard: " + user + " signed in from " + r.client()).c_str());
    send(fd, 200, "application/json", "{\"user\":" + json_quote(user) + "}",
         "Set-Cookie: skl_dash=" + seal(user, expires) + "; Path=/; Max-Age=" + std::to_string(session_seconds) +
             "; HttpOnly; SameSite=Strict" + (https ? "; Secure" : "") + "\r\n");
}

void server::run(int fd, const request& r)
{
    if (r.method != "POST")
    {
        send(fd, 405, "text/plain; charset=utf-8", "A command is sent with POST.\n");
        return;
    }
    if (!configured())
    {
        send(fd, 403, "text/plain; charset=utf-8",
             "Changing anything needs daemon.dashboard_credentials in the daemon's configuration.\n");
        return;
    }
    const std::string who = session_of(r);
    if (who.empty())
    {
        send(fd, 401, "text/plain; charset=utf-8", "Sign in first.\n");
        return;
    }
    // Only the page sends it, since no other site's request can carry it.
    if (r.header("x-socketley-dashboard") != "1")
    {
        send(fd, 403, "text/plain; charset=utf-8", "A command comes from the dashboard's own page.\n");
        return;
    }
    socketley::storage::jvalue doc;
    const socketley::storage::jvalue* args = nullptr;
    if (socketley::storage::json_reader(r.body).document(doc))
        for (const auto& [k, v] : doc.members)
            if (k == "args" && v.k == socketley::storage::jvalue::kind::array)
                args = &v;
    if (!args || args->items.empty())
    {
        send(fd, 400, "text/plain; charset=utf-8", "The body is {\"args\": [the command's words]}.\n");
        return;
    }
    std::string command;
    for (size_t i = 0; i < args->items.size(); ++i)
    {
        const auto& a = args->items[i];
        if (a.k != socketley::storage::jvalue::kind::string || a.s.empty() ||
            a.s.find_first_of("\r\n\0", 0, 3) != std::string::npos)
        {
            send(fd, 400, "text/plain; charset=utf-8", "Each word is a string of one line.\n");
            return;
        }
        if (i == 0 && !verbs.count(a.s))
        {
            send(fd, 403, "text/plain; charset=utf-8", "The dashboard does not send " + a.s + ".\n");
            return;
        }
        // Words are split at spaces, but for an import's document, which is the rest of the line.
        const bool document = args->items[0].s == "import" && i == 2;
        if (!document && a.s.find_first_of(" \t") != std::string::npos)
        {
            send(fd, 400, "text/plain; charset=utf-8", "\"" + a.s + "\" holds a space, which no word may.\n");
            return;
        }
        command += (i ? " " : "") + a.s;
    }
    std::string out;
    const int rc = ipc_send(command, out);
    if (args->items[0].s != "show" && args->items[0].s != "stats" && args->items[0].s != "ls" &&
        args->items[0].s != "ps")
        LOG_INFO(("dashboard: " + who + " ran " + command.substr(0, 200) + " (" + std::to_string(rc) + ")").c_str());
    if (rc == ipc_unreachable || rc == ipc_no_answer)
    {
        send(fd, 502, "text/plain; charset=utf-8",
             rc == ipc_no_answer ? "The daemon is still at it; look again in a moment.\n"
                                 : "The daemon's control socket did not answer.\n");
        return;
    }
    send(fd, 200, "application/json", "{\"code\":" + std::to_string(rc) + ",\"out\":" + json_quote(out) + "}");
}

}   // namespace dashboard
