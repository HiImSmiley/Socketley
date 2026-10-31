// A proxy whose backends are application servers spoken to by FastCGI (fastcgi://unix:/run/php/php-fpm.sock): which
// request goes to a script under --root, how the HTTP/1.1 request the rest of the proxy writes becomes records, and
// how the records read back become the HTTP/1.1 answer it relays -- so pools, deadlines, retries, the breaker and
// HTTP/2 and /3 clients all work on such a backend as on any other.
//
// A script is only ever a regular file ending in .php that lies beneath --root, found by openat2(RESOLVE_BENEATH):
// a path whose .php segment does not exist goes to the index script and not to php-fpm, so an upload.jpg asked for as
// /upload.jpg/x.php is never handed to the interpreter, whatever cgi.fix_pathinfo says.

#include "proxy_instance.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <linux/openat2.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../../shared/http/fastcgi.h"
#include "../../shared/http/status.h"
#include "../../shared/http/url.h"
#include "../../shared/net/peer_address.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/wall_clock.h"

namespace fcgi = socketley::fastcgi;

namespace
{

// The biggest request body buffered whole, which a chunked one is since PHP reads CONTENT_LENGTH bytes or none.
constexpr size_t chunked_body_max = 64ull << 20;
constexpr size_t head_max = 64 * 1024;

bool iequal(std::string_view a, std::string_view b)
{
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    return true;
}

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t'))
        s.remove_suffix(1);
    return s;
}

// A hop's own fields, which describe the connection to the proxy and none of the request a script answers.
bool hop_field(std::string_view name)
{
    return iequal(name, "connection") || iequal(name, "keep-alive") || iequal(name, "te") ||
           iequal(name, "transfer-encoding") || iequal(name, "upgrade") || iequal(name, "expect") ||
           iequal(name, "proxy-connection");
}

struct parsed_head
{
    std::string_view method, target, version;
    std::vector<std::pair<std::string_view, std::string_view>> fields;
    bool chunked{false};
    bool has_length{false};
    uint64_t length{0};
};

bool parse_head(std::string_view head, parsed_head& out)
{
    const size_t eol = head.find("\r\n");
    if (eol == std::string_view::npos)
        return false;
    const std::string_view line = head.substr(0, eol);
    const size_t a = line.find(' ');
    const size_t b = a == std::string_view::npos ? a : line.find(' ', a + 1);
    if (b == std::string_view::npos)
        return false;
    out.method = line.substr(0, a);
    out.target = line.substr(a + 1, b - a - 1);
    out.version = line.substr(b + 1);
    for (std::string_view rest = head.substr(eol + 2); !rest.empty();)
    {
        const size_t e = rest.find("\r\n");
        const std::string_view f = rest.substr(0, e);
        rest = e == std::string_view::npos ? std::string_view{} : rest.substr(e + 2);
        if (f.empty())
            break;
        const size_t colon = f.find(':');
        if (colon == std::string_view::npos || colon == 0)
            return false;
        const std::string_view name = f.substr(0, colon), value = trim(f.substr(colon + 1));
        if (iequal(name, "transfer-encoding"))
        {
            const size_t comma = value.rfind(',');
            out.chunked = iequal(trim(comma == std::string_view::npos ? value : value.substr(comma + 1)), "chunked");
        }
        else if (iequal(name, "content-length"))
        {
            uint64_t n = 0;
            for (const char c : value)
            {
                if (c < '0' || c > '9' || n > (UINT64_MAX - 9) / 10)
                    return false;
                n = n * 10 + static_cast<uint64_t>(c - '0');
            }
            out.has_length = !value.empty();
            out.length = n;
        }
        out.fields.emplace_back(name, value);
    }
    return true;
}

std::string_view field_of(const parsed_head& h, std::string_view name)
{
    for (const auto& [n, v] : h.fields)
        if (iequal(n, name))
            return v;
    return {};
}

void append_chunk(std::string& out, std::string_view data)
{
    if (data.empty())
        return;
    char hex[20];
    const int n = std::snprintf(hex, sizeof hex, "%zx\r\n", data.size());
    out.append(hex, static_cast<size_t>(n));
    out.append(data);
    out += "\r\n";
}

}   // namespace

void proxy_instance::set_root(std::string_view dir)
{
    m_fcgi_root = std::string(dir);
    while (m_fcgi_root.size() > 1 && m_fcgi_root.back() == '/')
        m_fcgi_root.pop_back();
}

void proxy_instance::set_fastcgi_root(std::string_view dir)
{
    m_fcgi_remote_root = std::string(dir);
    while (m_fcgi_remote_root.size() > 1 && m_fcgi_remote_root.back() == '/')
        m_fcgi_remote_root.pop_back();
}

void proxy_instance::set_index(std::string_view name)
{
    m_fcgi_index = name.empty() ? std::string("index.php") : std::string(name);
}

bool proxy_instance::open_fcgi_root()
{
    if (m_fcgi_root_fd >= 0)
        ::close(m_fcgi_root_fd);
    m_fcgi_root_fd = ::open(m_fcgi_root.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (m_fcgi_root_fd < 0)
    {
        LOG_ERROR(("proxy " + std::string(get_name()) + ": --root " + m_fcgi_root + " cannot be opened: " +
                   std::strerror(errno)).c_str());
        return false;
    }
    char real[PATH_MAX];
    m_fcgi_root_real = ::realpath(m_fcgi_root.c_str(), real) ? std::string(real) : std::string();
    if (m_fcgi_root_real == "/")
        m_fcgi_root_real.clear();
    return true;
}

// Whether `rel`, a path under --root without its leading slash, is a regular file beneath it; `dir` says a directory.
bool proxy_instance::fcgi_regular(std::string_view rel, bool& dir) const
{
    dir = false;
    if (m_fcgi_root_fd < 0)
        return false;
    const std::string path = rel.empty() ? std::string(".") : std::string(rel);
    struct open_how how{};
    how.flags = static_cast<uint64_t>(O_PATH | O_CLOEXEC);
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
    long r = ::syscall(__NR_openat2, m_fcgi_root_fd, path.c_str(), &how, sizeof how);
    // An absolute link is refused by RESOLVE_BENEATH wherever it points, so it is followed and kept when it stays in.
    if (r < 0 && errno == EXDEV && !m_fcgi_root_real.empty())
    {
        char real[PATH_MAX];
        if (!::realpath((m_fcgi_root + "/" + path).c_str(), real) ||
            !std::string_view(real).starts_with(m_fcgi_root_real + "/"))
            return false;
        r = ::open(real, O_PATH | O_CLOEXEC);
    }
    if (r < 0)
        return false;
    struct stat st{};
    const bool ok = ::fstat(static_cast<int>(r), &st) == 0;
    ::close(static_cast<int>(r));
    dir = ok && S_ISDIR(st.st_mode);
    return ok && S_ISREG(st.st_mode);
}

bool proxy_instance::route_fastcgi(proxy_client_connection* conn, std::string_view path)
{
    conn->ex.fcgi_script.clear();
    conn->ex.fcgi_filename.clear();
    conn->ex.fcgi_path_info.clear();
    if (const size_t q = path.find('?'); q != std::string_view::npos)
        path = path.substr(0, q);
    std::string decoded;
    if (!socketley::http::percent_decode(path, decoded, false) || decoded.empty() || decoded[0] != '/' ||
        decoded.find('\0') != std::string::npos)
    {
        send_error(conn, "400 Bad Request", "Bad Request\n");
        return false;
    }
    // No segment that walks up, and none hidden but .well-known: .env, .git and .htaccess are a site's secrets.
    for (size_t at = 0; at < decoded.size();)
    {
        const size_t end = std::min(decoded.find('/', at + 1), decoded.size());
        const std::string_view seg = std::string_view(decoded).substr(at + 1, end - at - 1);
        if (seg == ".." || (seg.starts_with('.') && seg != ".well-known" && !seg.empty()))
        {
            send_error(conn, "404 Not Found", "Not Found\n");
            return false;
        }
        at = end;
    }
    const std::string_view rel = std::string_view(decoded).substr(1);
    const auto take = [&](std::string script, std::string path_info) {
        conn->ex.fcgi_filename = (m_fcgi_remote_root.empty() ? m_fcgi_root : m_fcgi_remote_root) + script;
        conn->ex.fcgi_script = std::move(script);
        conn->ex.fcgi_path_info = std::move(path_info);
        return true;
    };
    // The first segment ending in .php, when it is a script; anything after it is PATH_INFO.
    for (size_t at = 0;;)
    {
        const size_t slash = rel.find('/', at);
        const std::string_view upto = rel.substr(0, slash);
        if (upto.ends_with(".php"))
        {
            bool dir = false;
            if (fcgi_regular(upto, dir))
                return take("/" + std::string(upto),
                            slash == std::string_view::npos ? std::string() : std::string(rel.substr(slash)));
            break;
        }
        if (slash == std::string_view::npos)
            break;
        at = slash + 1;
    }
    bool dir = false;
    const bool file = fcgi_regular(rel, dir);
    if (dir)
    {
        std::string index = std::string(rel);
        if (!index.empty() && index.back() != '/')
            index += '/';
        index += m_fcgi_index;
        bool d2 = false;
        if (fcgi_regular(index, d2))
            return take("/" + index, {});
    }
    // An existing file that is no script is the site's own, which only the root may serve and never the interpreter.
    if (file)
    {
        send_error(conn, "404 Not Found", "Not Found\n");
        return false;
    }
    // Nothing at the path: the index script answers it, as a front controller does every route it was not given.
    bool d3 = false;
    if (fcgi_regular(m_fcgi_index, d3))
        return take("/" + m_fcgi_index, {});
    send_error(conn, "404 Not Found", "Not Found\n");
    return false;
}

bool proxy_instance::fastcgi_encode(proxy_client_connection* conn, fcgi_leg& leg, std::string_view in, std::string& out)
{
    const auto params = [&](uint64_t length, bool has_body) {
        parsed_head h;
        if (!parse_head(leg.head, h))
            return false;
        fcgi::request_info r;
        r.method = h.method;
        r.target = h.target;
        const size_t q = h.target.find('?');
        r.path = h.target.substr(0, q);
        r.query = q == std::string_view::npos ? std::string_view{} : h.target.substr(q + 1);
        r.protocol = h.version;
        r.script_name = conn->ex.fcgi_script;
        r.script_filename = conn->ex.fcgi_filename;
        r.path_info = conn->ex.fcgi_path_info;
        r.document_root = m_fcgi_remote_root.empty() ? std::string_view(m_fcgi_root) : std::string_view(m_fcgi_remote_root);
        std::string_view host = field_of(h, "host");
        if (const size_t colon = host.rfind(':'); colon != std::string_view::npos && host.find(']') == std::string_view::npos)
            host = host.substr(0, colon);
        r.server_name = host;
        const std::string port = std::to_string(get_port());
        r.server_port = port;
        r.remote_addr = conn->peer_addr;
        // TLS this proxy ended, or that an entrance in front of it ended and said so over the loopback.
        r.https = conn->tls() != nullptr ||
                  (socketley::is_loopback(conn->peer_addr) && iequal(field_of(h, "x-forwarded-proto"), "https"));
        for (const auto& [n, v] : h.fields)
            if (!hop_field(n))
                r.headers.emplace_back(n, v);
        r.content_length = length;
        r.has_body = has_body;
        fcgi::append_params(out, fcgi::cgi_params(r));
        return true;
    };
    while (!in.empty() || leg.out == fcgi_leg::out_phase::head)
    {
        switch (leg.out)
        {
        case fcgi_leg::out_phase::head:
        {
            const size_t before = leg.head.size();
            leg.head.append(in);
            const size_t end = leg.head.find("\r\n\r\n");
            if (end == std::string::npos)
                return leg.head.size() <= head_max;
            in = in.substr(end + 4 - before);
            leg.head.resize(end + 4);
            parsed_head h;
            if (!parse_head(leg.head, h))
                return false;
            leg.head_request = iequal(h.method, "HEAD");
            fcgi::append_begin(out, true);
            if (h.chunked)
            {
                leg.out = fcgi_leg::out_phase::body_chunked;
                continue;
            }
            if (!params(h.length, h.has_length))
                return false;
            if (h.length == 0)
            {
                fcgi::append_stdin(out, {});
                leg.out = fcgi_leg::out_phase::done;
                return true;
            }
            leg.body_left = static_cast<size_t>(h.length);
            leg.out = fcgi_leg::out_phase::body_length;
            continue;
        }
        case fcgi_leg::out_phase::body_length:
        {
            const size_t n = std::min(in.size(), leg.body_left);
            fcgi::append_stdin(out, in.substr(0, n));
            leg.body_left -= n;
            in.remove_prefix(n);
            if (leg.body_left == 0)
            {
                fcgi::append_stdin(out, {});
                leg.out = fcgi_leg::out_phase::done;
            }
            continue;
        }
        case fcgi_leg::out_phase::body_chunked:
        {
            std::string_view piece;
            switch (http_chunked_next(leg.chunk, in, piece))
            {
            case chunk_step::payload:
                if (leg.body.size() + piece.size() > chunked_body_max)
                    return false;
                leg.body.append(piece);
                continue;
            case chunk_step::need_more:
                return true;
            case chunk_step::bad:
                return false;
            case chunk_step::done:
                if (!params(leg.body.size(), true))
                    return false;
                fcgi::append_stdin(out, leg.body);
                fcgi::append_stdin(out, {});
                leg.body.clear();
                leg.body.shrink_to_fit();
                leg.out = fcgi_leg::out_phase::done;
                continue;
            }
            return false;
        }
        case fcgi_leg::out_phase::done:
            // A request is written whole before the next is taken, and nothing else reaches this leg.
            return in.empty();
        }
    }
    return true;
}

bool proxy_instance::fastcgi_decode(proxy_backend_connection* conn, std::string_view in, std::string& out)
{
    fcgi_leg& leg = *conn->fcgi;
    const auto broken = [&](const char* why) {
        LOG_WARN(("proxy " + std::string(get_name()) + ": the application server " + why +
                  "; the answer is given up").c_str());
        // Nothing of an answer has gone out, so the client is told the gateway failed rather than left with half.
        if (!leg.cgi_done)
            out = "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n"
                  "Connection: close\r\n\r\nBad Gateway\n";
        conn->closing = true;
        return false;
    };
    const auto body = [&](std::string_view data) {
        if (leg.bodiless)
            return;
        if (leg.chunked)
            append_chunk(out, data);
        else
            out.append(data);
    };
    std::string_view buf = in;
    if (!leg.raw.empty())
    {
        leg.raw.append(in);
        buf = leg.raw;
    }
    size_t done = 0;
    for (;;)
    {
        fcgi::record r;
        size_t used = 0;
        const fcgi::take t = fcgi::next_record(buf.substr(done), r, used);
        if (t == fcgi::take::need_more)
            break;
        if (t == fcgi::take::bad)
            return broken("sent bytes that are not FastCGI records");
        done += used;
        switch (r.type)
        {
        case fcgi::record_type::stdout_data:
        {
            if (leg.cgi_done)
            {
                body(r.content);
                break;
            }
            leg.cgi.append(r.content);
            fcgi::cgi_head h;
            size_t len = 0;
            const fcgi::head_result hr = fcgi::parse_cgi_head(leg.cgi, len, h);
            if (hr == fcgi::head_result::need_more)
                break;
            if (hr == fcgi::head_result::bad)
                return broken("answered with a CGI head that is not one");
            leg.cgi_done = true;
            out += "HTTP/1.1 " + std::to_string(h.status) + " " +
                   (h.reason.empty() ? std::string(socketley::http::status_text(h.status)) : h.reason) + "\r\n";
            for (const auto& [n, v] : h.fields)
                if (!iequal(n, "connection") && !iequal(n, "keep-alive") && !iequal(n, "transfer-encoding"))
                    out += n + ": " + v + "\r\n";
            leg.bodiless = leg.head_request || h.status == 204 || h.status == 304 || h.status < 200;
            leg.chunked = !leg.bodiless && !h.has_length;
            if (leg.chunked)
                out += "Transfer-Encoding: chunked\r\n";
            out += "\r\n";
            body(std::string_view(leg.cgi).substr(len));
            leg.cgi.clear();
            break;
        }
        case fcgi::record_type::stderr_data:
        {
            leg.err.append(r.content);
            const int64_t minute = socketley::wall::now_sec() / 60;
            if (minute != m_fcgi_err_minute)
            {
                m_fcgi_err_minute = minute;
                m_fcgi_err_lines = 0;
            }
            for (size_t nl; (nl = leg.err.find('\n')) != std::string::npos || leg.err.size() > 4096;)
            {
                const size_t cut = nl == std::string::npos ? leg.err.size() : nl;
                if (m_fcgi_err_lines++ < 20)
                    LOG_WARN(("proxy " + std::string(get_name()) + ": " +
                              leg.err.substr(0, std::min<size_t>(cut, 1024))).c_str());
                leg.err.erase(0, nl == std::string::npos ? cut : cut + 1);
            }
            break;
        }
        case fcgi::record_type::end_request:
        {
            uint32_t app = 0;
            uint8_t proto = 0;
            if (!fcgi::parse_end_request(r.content, app, proto) || proto != 0)
                return broken("refused the request (it is busy or does not take this role)");
            if (!leg.cgi_done)
                return broken("ended the request without a CGI head");
            if (leg.chunked)
                out += "0\r\n\r\n";
            if (!leg.err.empty() && m_fcgi_err_lines++ < 20)
                LOG_WARN(("proxy " + std::string(get_name()) + ": " + leg.err.substr(0, 1024)).c_str());
            // The next request on this connection begins clean.
            *conn->fcgi = fcgi_leg{};
            return buf.size() == done || broken("sent records after the end of the request");
        }
        default:
            break;
        }
    }
    if (leg.raw.empty())
        leg.raw.assign(buf.substr(done));
    else
        leg.raw.erase(0, done);
    return true;
}
