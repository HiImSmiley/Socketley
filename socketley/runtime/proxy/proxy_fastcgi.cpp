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
#include <iterator>
#include <memory>
#include <poll.h>
#include <linux/openat2.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/uio.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <utility>

#include "../../shared/http/conditional.h"
#include "../../shared/http/fastcgi.h"
#include "../../shared/http/mime.h"
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

// A file a site keeps beside its pages and never means to hand out: a script's source by another name, an editor's or
// a deploy's leftover copy, a dump or an include -- each a classic way a database password reaches the public.
bool private_name(std::string_view rel)
{
    const size_t slash = rel.rfind('/');
    const std::string_view name = slash == std::string_view::npos ? rel : rel.substr(slash + 1);
    if (name.ends_with('~'))
        return true;
    std::string lower(name);
    for (char& c : lower)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (lower.find(".php.") != std::string::npos)
        return true;
    const size_t dot = lower.rfind('.');
    if (dot == std::string::npos)
        return false;
    const std::string_view ext = std::string_view(lower).substr(dot + 1);
    static constexpr std::string_view never[] = {"bak", "old", "orig", "save", "swp", "swo", "tmp", "inc", "sql",
                                                 "ini", "log", "phtml", "phar", "phps", "php3", "php4", "php5",
                                                 "php7", "php8", "dist"};
    return std::find(std::begin(never), std::end(never), ext) != std::end(never);
}

// The largest read of a served file, and so the most of it this proxy holds per connection above the write queue.
constexpr uint32_t file_window = 256 * 1024;
// Kept whole up to this size and this total, the server runtime's own figures: below it one write of bytes in memory
// costs less than any splice, whose every operation is a hand-off to an io-wq worker (event_loop.h, at
// submit_splice).
constexpr uint64_t keep_max_file = 256 * 1024;
constexpr size_t keep_max_total = 64u << 20;
// Above it a file on a plain connection is sent by sendfile from the loop, as much as one call takes up to this much
// before the loop turns, into a send buffer asked for at this size (the kernel doubles it, to tcp_wmem's 4 MiB here,
// which is as far as nginx's autotuned sockets grow).
constexpr uint64_t sendfile_burst = 4u << 20;
constexpr int file_sndbuf = 2 << 20;
// Large files whose descriptors are kept open at once, a bound on the descriptors this costs.
constexpr size_t max_open_files = 256;

}   // namespace

void proxy_instance::set_root(std::string_view dir)
{
    std::string root(dir);
    while (root.size() > 1 && root.back() == '/')
        root.pop_back();
    if (m_fcgi_root_fd < 0 || root == m_fcgi_root)
    {
        m_fcgi_root = std::move(root);
        return;
    }
    // A serving proxy moves to the new root once it is open, so the descriptor and the name never disagree.
    m_kept.clear();
    m_kept_bytes = 0;
    m_open.clear();
    std::string before = std::exchange(m_fcgi_root, std::move(root));
    if (!open_fcgi_root())
    {
        m_fcgi_root = std::move(before);
        if (!open_fcgi_root()) {}
    }
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

// `rel`, a path under --root without its leading slash, opened beneath it with `flags`, and its stat; -1 if it is not.
int proxy_instance::fcgi_open(std::string_view rel, int flags, struct stat& st) const
{
    if (m_fcgi_root_fd < 0)
        return -1;
    const std::string path = rel.empty() ? std::string(".") : std::string(rel);
    struct open_how how{};
    how.flags = static_cast<uint64_t>(flags | O_CLOEXEC);
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
    long r = ::syscall(__NR_openat2, m_fcgi_root_fd, path.c_str(), &how, sizeof how);
    // An absolute link is refused by RESOLVE_BENEATH wherever it points, so it is followed and kept when it stays in.
    if (r < 0 && errno == EXDEV && !m_fcgi_root_real.empty())
    {
        char real[PATH_MAX];
        if (!::realpath((m_fcgi_root + "/" + path).c_str(), real) ||
            !std::string_view(real).starts_with(m_fcgi_root_real + "/"))
            return -1;
        r = ::open(real, flags | O_CLOEXEC);
    }
    if (r < 0)
        return -1;
    if (::fstat(static_cast<int>(r), &st) != 0)
    {
        ::close(static_cast<int>(r));
        return -1;
    }
    return static_cast<int>(r);
}

// Whether `rel` is a regular file beneath --root; `dir` says a directory.
bool proxy_instance::fcgi_regular(std::string_view rel, bool& dir) const
{
    struct stat st{};
    const int fd = fcgi_open(rel, O_PATH, st);
    dir = false;
    if (fd < 0)
        return false;
    ::close(fd);
    dir = S_ISDIR(st.st_mode);
    return S_ISREG(st.st_mode);
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
    if (SOCKETLEY_LIKELY(!m_kept.empty()) && fcgi_serve_kept(conn, rel))
        return false;
    if (!m_open.empty() && fcgi_serve_open(conn, rel))
        return false;
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
    // An existing file that is no script is the site's own, served from here and never handed to the interpreter.
    if (file)
    {
        struct stat st{};
        const int ffd = m_files && !private_name(rel) ? fcgi_open(rel, O_RDONLY, st) : -1;
        if (ffd < 0 || !S_ISREG(st.st_mode))
        {
            if (ffd >= 0)
                ::close(ffd);
            send_error(conn, "404 Not Found", "Not Found\n");
            return false;
        }
        auto src = std::make_shared<fcgi_fd>(ffd);
        // A large file's descriptor is kept for the requests after this one; a small one is kept as bytes instead.
        if (static_cast<uint64_t>(st.st_size) > keep_max_file && !rel.empty())
        {
            if (m_open.size() >= max_open_files)
                m_open.clear();
            m_open[std::string(rel)] = fcgi_open_entry{st.st_dev, st.st_ino, st.st_size, st.st_mtim, src};
        }
        fcgi_serve_file(conn, std::move(src), st, rel);
        return false;
    }
    // Nothing at the path: the index script answers it, as a front controller does every route it was not given.
    bool d3 = false;
    if (fcgi_regular(m_fcgi_index, d3))
        return take("/" + m_fcgi_index, {});
    send_error(conn, "404 Not Found", "Not Found\n");
    return false;
}

// A kept file still the one on disk, answered from memory; false sends the request down the path that opens it.  The
// statx follows links where the open beneath --root would not, which is safe because what it decides is only whether
// these bytes are still that file's: a path that now leads elsewhere names another inode, and is opened afresh.
bool proxy_instance::fcgi_serve_kept(proxy_client_connection* conn, std::string_view rel)
{
    const auto it = m_kept.find(rel);
    if (it == m_kept.end())
        return false;
    struct statx sx{};
    const unsigned want = STATX_TYPE | STATX_INO | STATX_MTIME | STATX_SIZE;
    const std::string path(rel);
    const fcgi_kept& k = it->second;
    if (::statx(m_fcgi_root_fd, path.c_str(), 0, want, &sx) != 0 || (sx.stx_mask & want) != want ||
        !S_ISREG(sx.stx_mode) || makedev(sx.stx_dev_major, sx.stx_dev_minor) != k.dev ||
        static_cast<ino_t>(sx.stx_ino) != k.ino || static_cast<off_t>(sx.stx_size) != k.size ||
        sx.stx_mtime.tv_sec != k.mtime.tv_sec || sx.stx_mtime.tv_nsec != k.mtime.tv_nsec)
    {
        m_kept_bytes -= it->second.body->size();
        m_kept.erase(it);
        return false;
    }
    struct stat st{};
    st.st_size = k.size;
    st.st_mtim = k.mtime;
    fcgi_serve_file(conn, nullptr, st, rel, k.body);
    return true;
}

// A kept descriptor still the file under its name, answered from it; false opens the file afresh, for the reason
// fcgi_serve_kept gives.
bool proxy_instance::fcgi_serve_open(proxy_client_connection* conn, std::string_view rel)
{
    const auto it = m_open.find(rel);
    if (it == m_open.end())
        return false;
    struct statx sx{};
    const unsigned want = STATX_TYPE | STATX_INO | STATX_MTIME | STATX_SIZE;
    const std::string path(rel);
    const fcgi_open_entry& o = it->second;
    if (::statx(m_fcgi_root_fd, path.c_str(), 0, want, &sx) != 0 || (sx.stx_mask & want) != want ||
        !S_ISREG(sx.stx_mode) || makedev(sx.stx_dev_major, sx.stx_dev_minor) != o.dev ||
        static_cast<ino_t>(sx.stx_ino) != o.ino || static_cast<off_t>(sx.stx_size) != o.size ||
        sx.stx_mtime.tv_sec != o.mtime.tv_sec || sx.stx_mtime.tv_nsec != o.mtime.tv_nsec)
    {
        m_open.erase(it);
        return false;
    }
    struct stat st{};
    st.st_size = o.size;
    st.st_mtim = o.mtime;
    fcgi_serve_file(conn, o.src, st, rel);
    return true;
}

// The answer for a file of the site's own: its preconditions (RFC 9110 13), a single range (14), and then its bytes
// a window at a time as the client takes them; under keep-alive, so a page's assets share the connection its page came
// on.
void proxy_instance::fcgi_serve_file(proxy_client_connection* conn, std::shared_ptr<fcgi_fd> src, const struct stat& st,
                                     std::string_view rel, std::shared_ptr<const std::string> kept)
{
    auto f = std::make_shared<fcgi_file>();
    f->fd = src ? src->fd : -1;
    f->src = std::move(src);
    const size_t end = conn->partial.find("\r\n\r\n");
    parsed_head h;
    if (end == std::string::npos || !parse_head(std::string_view(conn->partial).substr(0, end + 4), h))
    {
        send_error(conn, "400 Bad Request", "Bad Request\n");
        return;
    }
    const bool head_only = h.method == "HEAD";
    if (!head_only && h.method != "GET")
    {
        send_error(conn, "405 Method Not Allowed", "Method Not Allowed\n", true, "Allow: GET, HEAD\r\n");
        return;
    }

    const auto size = static_cast<uint64_t>(st.st_size);
    const int64_t mtime = static_cast<int64_t>(st.st_mtim.tv_sec);
    char tag[64];
    const int tn = std::snprintf(tag, sizeof tag, "%llx-%lx-%llx", static_cast<unsigned long long>(st.st_mtim.tv_sec),
                                 static_cast<unsigned long>(st.st_mtim.tv_nsec), static_cast<unsigned long long>(size));
    const std::string etag(tag, tn > 0 ? static_cast<size_t>(tn) : 0);
    const std::string modified = socketley::http::http_date_of(mtime);
    const auto pre = socketley::http::evaluate({field_of(h, "if-match"), field_of(h, "if-unmodified-since"),
                                                field_of(h, "if-none-match"), field_of(h, "if-modified-since")},
                                               etag, mtime);
    if (pre == socketley::http::precondition::failed)
    {
        send_error(conn, "412 Precondition Failed", "Precondition Failed\n");
        return;
    }

    std::string_view status = "200 OK";
    uint64_t first = 0, length = size;
    std::string range_field;
    if (pre == socketley::http::precondition::not_modified)
        status = "304 Not Modified";
    else if (const std::string_view range = field_of(h, "range"); !head_only && !range.empty())
    {
        // A range of a file that has changed since the client's copy is no part of that copy (13.1.5).
        const std::string_view if_range = field_of(h, "if-range");
        if (if_range.empty() || if_range == "\"" + etag + "\"" || if_range == modified)
        {
            const http_range r = http_parse_range(range, static_cast<size_t>(size));
            if (r.unsatisfiable)
            {
                status = "416 Range Not Satisfiable";
                length = 0;
                range_field = "Content-Range: bytes */" + std::to_string(size) + "\r\n";
            }
            else if (r.usable)
            {
                status = "206 Partial Content";
                first = r.first;
                length = static_cast<uint64_t>(r.last - r.first + 1);
                range_field = "Content-Range: bytes " + std::to_string(r.first) + "-" + std::to_string(r.last) + "/" +
                              std::to_string(size) + "\r\n";
            }
        }
    }
    // A body after a request this answers without reading leaves no boundary to find the next request at; and the
    // client's own word on the connection is read here, since rewrite_http_request, which reads it for a backend's
    // answer, is never reached.
    bool asked_close = false, asked_keep = false;
    for (const auto& [n, v] : h.fields)
        if (iequal(n, "connection"))
        {
            asked_close = asked_close || http_list_has_token(v, "close", 5);
            asked_keep = asked_keep || http_list_has_token(v, "keep-alive", 10);
        }
    const bool http10 = h.version == "HTTP/1.0";
    if (conn->ex.declared_body_len > 0 || conn->ex.declared_body_chunked || asked_close || (http10 && !asked_keep))
        conn->ex.client_conn_close = true;

    std::string out;
    out.reserve(320);
    out += "HTTP/1.1 ";
    out += status;
    out += "\r\n";
    if (status.starts_with("416"))
        out += range_field + "Content-Length: 0\r\n";
    else if (!status.starts_with("304"))
    {
        out += "Content-Type: ";
        out += socketley::http::content_type_of(rel);
        out += "\r\nContent-Length: " + std::to_string(length) + "\r\n" + range_field + "Accept-Ranges: bytes\r\n";
        out += "X-Content-Type-Options: nosniff\r\n";
    }
    out += "ETag: \"" + etag + "\"\r\nLast-Modified: " + modified + "\r\n";
    if (conn->ex.client_conn_close)
        out += "Connection: close\r\n";
    else if (http10)
        out += "Connection: keep-alive\r\n";
    out += "\r\n";

    ++m_files_served;
    if (pre == socketley::http::precondition::not_modified)
        ++m_files_not_modified;
    conn->partial.erase(0, end + 4);
    conn->ex.response_started = true;
    const bool body = !head_only && (status.starts_with("200") || status.starts_with("206"));
    if (!kept)
    {
        f->off = first;
        f->left = body ? length : 0;
        // A whole small file asked for by a GET is read once and kept, while there is room for it.
        if (status.starts_with("200") && body && size > 0 && size <= keep_max_file &&
            m_kept_bytes + size <= keep_max_total && !rel.empty())
        {
            f->keep_as = std::string(rel);
            f->keep_stat = st;
        }
        // TLS and a stream frame what they send, so only a plain connection takes the bytes straight from the file.
        else if (f->left > 0 && conn->ssl == nullptr && conn->h2_parent == nullptr && conn->h3s == nullptr)
        {
            f->sendfile = true;
            // The listener's 256 KiB would have each burst stop and wait for room several times a file.
            if (f->left > keep_max_file && !conn->fcgi_sndbuf)
            {
                conn->fcgi_sndbuf = true;
                if (::setsockopt(conn->fd, SOL_SOCKET, SO_SNDBUF, &file_sndbuf, sizeof file_sndbuf) < 0) {}
            }
        }
    }
    // A file sent by sendfile has its head sent here and now, held for the first of its bytes (MSG_MORE), so the
    // file follows in this same turn and not one completion later; what the socket does not take is queued.
    if (f->sendfile && !conn->write_pending && conn->write_queue.empty())
    {
        const ssize_t n = ::send(conn->fd, out.data(), out.size(), MSG_DONTWAIT | MSG_NOSIGNAL | MSG_MORE);
        if (n < 0 && errno != EAGAIN)
        {
            close_pair(conn->fd, conn->ex.backend_fd);
            return;
        }
        if (n > 0)
        {
            stat_add(m_stat_bytes_out, static_cast<uint64_t>(n));
            out.erase(0, static_cast<size_t>(n));
        }
    }
    if (!out.empty())
        conn->write_queue.push(std::move(out));
    // A kept file's bytes go behind its head in the same write, a slice of the one copy every request shares.
    if (kept && body && length > 0)
        conn->write_queue.push(socketley::write_chunk(kept, static_cast<uint32_t>(first), static_cast<uint32_t>(length)));
    if (!conn->write_pending && !conn->write_queue.empty() && !flush_client_write_queue(conn))
    {
        close_pair(conn->fd, conn->ex.backend_fd);
        return;
    }
    // The next request is read as this answer goes out, as it is behind a backend's, since this returns past the
    // re-arm at the end of drive_client_request.
    if (!conn->closing && !conn->read_pending && !arm_read(conn->fd, conn))
    {
        close_pair(conn->fd, conn->ex.backend_fd);
        return;
    }
    conn->file = std::move(f);
    fcgi_file_next(conn, true);
}

// The next window of the file, once what the client holds is below the pacing point; at its end the exchange is over,
// after the write that carries the last of it, so a pipelined request is never parsed from inside this one's answer --
// which is also why `inline_call`, the call from the request itself, ends it at once only when nothing follows it.
void proxy_instance::fcgi_file_next(proxy_client_connection* conn, bool inline_call)
{
    fcgi_file& f = *conn->file;
    if (f.reading || conn->closing || !m_loop)
        return;
    const bool stream = conn->h2_parent != nullptr || conn->h3s != nullptr;
    if (f.left == 0)
    {
        if (!stream && (conn->write_pending || !conn->write_queue.empty()))
            return;
        conn->file.reset();
        reset_client_for_next_request(conn);
        return;
    }
    const int fd = conn->fd;
    const uint32_t gen = conn->generation;
    // A burst whose last byte is not in the page cache would hold the loop on the disk, so that window is read through
    // the ring instead, which also has the kernel read ahead of it.
    char probe = 0;
    iovec pv{&probe, 1};
    const bool cold = f.sendfile &&
                      ::preadv2(f.fd, &pv, 1, static_cast<off_t>(f.off + std::min(f.left, sendfile_burst) - 1), RWF_NOWAIT) < 0 &&
                      errno == EAGAIN;
    if (f.sendfile && !cold)
    {
        // The head goes out first, through the write queue, and nothing else writes to the socket until the file has.
        if (conn->write_pending || !conn->write_queue.empty())
            return;
        // sendfile on the loop thread, the way nginx sends a file, where an io_uring splice is a hand-off to an io-wq
        // worker per operation; non-blocking for the call alone, since the ring's own writes need the socket blocking,
        // and nothing of the ring runs on it meanwhile (SINGLE_ISSUER, DEFER_TASKRUN).
        if (conn->fcgi_sock_flags < 0)
            conn->fcgi_sock_flags = ::fcntl(fd, F_GETFL);
        const int flags = conn->fcgi_sock_flags;
        bool failed = flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0;
        for (uint64_t budget = sendfile_burst; !failed && f.left > 0 && budget > 0;)
        {
            auto off = static_cast<off_t>(f.off);
            const ssize_t n = ::sendfile(fd, f.fd, &off, static_cast<size_t>(std::min(f.left, budget)));
            if (n > 0)
            {
                f.off += static_cast<uint64_t>(n);
                f.left -= static_cast<uint64_t>(n);
                budget -= std::min<uint64_t>(budget, static_cast<uint64_t>(n));
                stat_add(m_stat_bytes_out, static_cast<uint64_t>(n));
                continue;
            }
            // A file that shrank under the length already on the wire, or a client gone, ends the connection.
            failed = n == 0 || errno != EAGAIN;
            break;
        }
        if (flags >= 0 && ::fcntl(fd, F_SETFL, flags) < 0)
            failed = true;
        if (failed)
        {
            conn->file.reset();
            close_pair(fd, conn->ex.backend_fd);
            return;
        }
        if (f.left == 0 && (!inline_call || conn->partial.empty()))
        {
            conn->file.reset();
            reset_client_for_next_request(conn);
            return;
        }
        // Room on the socket, or the next turn when the burst ran out, says when to go on.
        f.reading = true;
        std::shared_ptr<fcgi_file> keep = conn->file;
        if (!m_files->io.poll(fd, POLLOUT, [this, fd, gen, keep](int64_t res) { fcgi_file_polled(fd, gen, keep, res); }))
        {
            f.reading = false;
            close_pair(fd, conn->ex.backend_fd);
        }
        return;
    }
    size_t held = conn->write_queue.bytes();
    if (stream)
        held += stream_answer_held(conn);
    if (held >= write_watermark_bytes())
        return;
    const auto n = static_cast<uint32_t>(std::min<uint64_t>(f.left, file_window));
    f.buf.resize(n);
    f.reading = true;
    std::shared_ptr<fcgi_file> keep = conn->file;
    if (!m_files->io.pread(f.fd, f.buf.data(), n, f.off,
                           [this, fd, gen, keep](int64_t res) { fcgi_file_read(fd, gen, keep, res); }))
    {
        f.reading = false;
        close_pair(conn->fd, conn->ex.backend_fd);
    }
}

void proxy_instance::fcgi_file_read(int fd, uint32_t gen, const std::shared_ptr<fcgi_file>& f, int64_t res)
{
    f->reading = false;
    if (!m_loop || fd < 0 || fd >= MAX_FDS || m_conn_idx[fd].side != conn_client)
        return;
    proxy_client_connection* conn = m_conn_idx[fd].client;
    if (conn->generation != gen || conn->file != f || conn->closing)
        return;
    // The length is on the wire already, so a file that shrank or failed under the read ends the connection.
    if (res <= 0)
    {
        conn->file.reset();
        close_pair(fd, conn->ex.backend_fd);
        return;
    }
    const auto got = static_cast<uint64_t>(std::min<int64_t>(res, static_cast<int64_t>(f->left)));
    f->buf.resize(static_cast<size_t>(got));
    f->off += got;
    f->left -= got;
    if (!f->keep_as.empty() && f->off == static_cast<uint64_t>(f->keep_stat.st_size) && f->left == 0 &&
        m_kept_bytes + f->buf.size() <= keep_max_total)
    {
        auto body = std::make_shared<const std::string>(std::move(f->buf));
        // Two connections may read the same file at once, and the second one's copy replaces the first's.
        auto [it, fresh] = m_kept.try_emplace(std::move(f->keep_as));
        if (!fresh)
            m_kept_bytes -= it->second.body->size();
        it->second = fcgi_kept{f->keep_stat.st_dev, f->keep_stat.st_ino, f->keep_stat.st_size, f->keep_stat.st_mtim, body};
        m_kept_bytes += body->size();
        conn->write_queue.push(socketley::write_chunk(std::move(body)));
    }
    else
        conn->write_queue.push(std::move(f->buf));
    f->buf = std::string();
    if (!conn->write_pending && !flush_client_write_queue(conn))
    {
        close_pair(fd, conn->ex.backend_fd);
        return;
    }
    fcgi_file_next(conn);
}

void proxy_instance::fcgi_file_polled(int fd, uint32_t gen, const std::shared_ptr<fcgi_file>& f, int64_t res)
{
    f->reading = false;
    if (!m_loop || fd < 0 || fd >= MAX_FDS || m_conn_idx[fd].side != conn_client)
        return;
    proxy_client_connection* conn = m_conn_idx[fd].client;
    if (conn->generation != gen || conn->file != f || conn->closing)
        return;
    if (res < 0 || (res & (POLLERR | POLLHUP)) != 0)
    {
        conn->file.reset();
        close_pair(fd, conn->ex.backend_fd);
        return;
    }
    fcgi_file_next(conn);
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
            // An application server never answers 100 Continue, so a client that asked to be told waited its own
            // timeout for every upload; this proxy is the origin it asked, and tells it.
            if ((h.chunked || h.length > 0) && iequal(field_of(h, "expect"), "100-continue") && !conn->h2_parent &&
                !conn->h3s && !conn->closing)
            {
                conn->write_queue.push(std::string("HTTP/1.1 100 Continue\r\n\r\n"));
                if (!conn->write_pending && !flush_client_write_queue(conn))
                    return false;
            }
            // Without FCGI_KEEP_CONN, so php-fpm's worker is free the moment it has answered: a kept connection holds it,
            // and with more of them than workers the rest wait in its backlog for a worker that never comes free.
            fcgi::append_begin(out, false);
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
            // nginx's internal redirect names a location this proxy does not have, and the script's empty body as a 200 would
            // be a download that silently came back empty.
            if (!h.accel_redirect.empty())
                return broken("named a file by X-Accel-Redirect, which is nginx's (readfile() hands a file out here)");
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
