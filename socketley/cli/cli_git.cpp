// `socketley git-sync`: one repository kept in a storage runtime's library, run by that runtime once a day and when
// asked (git_mirrors.h). It fetches into a bare clone of its own, and when a ref moved it writes the branch's files
// under <name>/ -- what changed since the last run, or all of them and nothing else the first time -- and a git
// bundle of the refs under _backups/<name>/, then thins those out. Everything goes through the runtime's S3 API with
// temporary credentials of the user the repository is kept for, so that user's rights, quotas and versioning apply
// as to any upload. Blocking on purpose: it is its own process.
//
//   socketley git-sync --url URL --branch NAME|* --work DIR --endpoint HOST:PORT [--tls] --bucket B --name N
//                      [--keep DAYS,WEEKS,MONTHS]
//   environment: SOCKETLEY_GIT_ACCESS_KEY, SOCKETLEY_GIT_SECRET, SOCKETLEY_GIT_SESSION_TOKEN, SOCKETLEY_GIT_TOKEN
//
// <work>/state.json says how the last run ended; <work>/repo.git is the clone; <work>/lock is held while one runs.
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "../shared/http_framing.h"
#include "../shared/s3_sigv4.h"
#include "../shared/git_names.h"

extern char** environ;

namespace
{

// ─── git ────────────────────────────────────────────────────────────────────

// The environment git runs in: never a prompt, and a token, when there is one, as the header GitHub takes it in,
// so it is on no command line.
std::vector<std::string> git_env()
{
    std::vector<std::string> env;
    for (char** e = environ; *e; ++e)
    {
        const std::string_view v(*e);
        if (!v.starts_with("SOCKETLEY_GIT_") && !v.starts_with("GIT_CONFIG_"))
            env.emplace_back(v);
    }
    env.emplace_back("GIT_TERMINAL_PROMPT=0");
    env.emplace_back("GIT_ASKPASS=/bin/false");
    if (const char* t = std::getenv("SOCKETLEY_GIT_TOKEN"); t && *t)
    {
        const std::string pair = std::string("x-access-token:") + t;
        std::string b64(4 * ((pair.size() + 2) / 3) + 1, '\0');
        b64.resize(static_cast<size_t>(EVP_EncodeBlock(reinterpret_cast<unsigned char*>(b64.data()),
                                                       reinterpret_cast<const unsigned char*>(pair.data()),
                                                       static_cast<int>(pair.size()))));
        env.emplace_back("GIT_CONFIG_COUNT=1");
        env.emplace_back("GIT_CONFIG_KEY_0=http.extraHeader");
        env.emplace_back("GIT_CONFIG_VALUE_0=Authorization: Basic " + b64);
    }
    return env;
}

struct child
{
    pid_t pid{-1};
    int in{-1}, out{-1};
};

// git with `args`, its stdin and stdout pipes to this process, its stderr this process's (the log).
child git_start(const std::vector<std::string>& args, bool want_stdin)
{
    child c;
    int ip[2] = {-1, -1}, op[2] = {-1, -1};
    if ((want_stdin && ::pipe2(ip, O_CLOEXEC) != 0) || ::pipe2(op, O_CLOEXEC) != 0)
        return c;
    std::vector<std::string> a = {"git"};
    a.insert(a.end(), args.begin(), args.end());
    std::vector<char*> argv;
    for (auto& s : a)
        argv.push_back(s.data());
    argv.push_back(nullptr);
    std::vector<std::string> env = git_env();
    std::vector<char*> envp;
    for (auto& s : env)
        envp.push_back(s.data());
    envp.push_back(nullptr);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    if (want_stdin)
        posix_spawn_file_actions_adddup2(&fa, ip[0], 0);
    else
        posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_adddup2(&fa, op[1], 1);
    // git gets the default SIGPIPE back, which this process ignores so a git that left reads as an error.
    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    sigset_t pipe_only;
    sigemptyset(&pipe_only);
    sigaddset(&pipe_only, SIGPIPE);
    posix_spawnattr_setsigdefault(&at, &pipe_only);
    posix_spawnattr_setflags(&at, POSIX_SPAWN_SETSIGDEF);
    const int rc = ::posix_spawnp(&c.pid, "git", &fa, &at, argv.data(), envp.data());
    posix_spawnattr_destroy(&at);
    posix_spawn_file_actions_destroy(&fa);
    if (want_stdin)
        ::close(ip[0]);
    ::close(op[1]);
    if (rc != 0)
    {
        c.pid = -1;
        if (want_stdin)
            ::close(ip[1]);
        ::close(op[0]);
        return c;
    }
    c.in = want_stdin ? ip[1] : -1;
    c.out = op[0];
    return c;
}

int git_wait(child& c)
{
    if (c.in >= 0)
        ::close(c.in);
    if (c.out >= 0)
        ::close(c.out);
    int status = 0;
    if (c.pid > 0 && ::waitpid(c.pid, &status, 0) < 0)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// git with `args`; its stdout into `out`; true for exit status 0.
bool git(const std::vector<std::string>& args, std::string* out = nullptr)
{
    child c = git_start(args, false);
    if (c.pid < 0)
        return false;
    char buf[65536];
    for (ssize_t n; (n = ::read(c.out, buf, sizeof buf)) > 0;)
        if (out)
            out->append(buf, static_cast<size_t>(n));
    return git_wait(c) == 0;
}

bool read_full(int fd, char* p, size_t n)
{
    while (n > 0)
    {
        const ssize_t r = ::read(fd, p, n);
        if (r <= 0)
            return false;
        p += r;
        n -= static_cast<size_t>(r);
    }
    return true;
}

// ─── the runtime's S3 API ───────────────────────────────────────────────────

std::string uri_encode(std::string_view s, bool keep_slash)
{
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s)
    {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
            c == '.' || c == '~' || (keep_slash && c == '/'))
            out += static_cast<char>(c);
        else
        {
            out += '%';
            out += hex[c >> 4];
            out += hex[c & 15];
        }
    }
    return out;
}

struct reply
{
    int status{0};
    std::string body;
};

class s3_client
{
public:
    s3_client(std::string host, std::string port, bool tls, std::string ca = {})
        : m_host(std::move(host)), m_port(std::move(port)), m_ca(std::move(ca)), m_tls(tls)
    {
        const char* k = std::getenv("SOCKETLEY_GIT_ACCESS_KEY");
        const char* s = std::getenv("SOCKETLEY_GIT_SECRET");
        const char* t = std::getenv("SOCKETLEY_GIT_SESSION_TOKEN");
        m_key = k ? k : "";
        m_secret = s ? s : "";
        m_token = t ? t : "";
    }
    ~s3_client() { drop(); }

    // One request; the body, when there is one, comes from `body` in pieces, `length` bytes in all.
    // `copy` names an object the new one is copied from, as x-amz-copy-source does.
    bool request(std::string_view method, const std::string& path, const std::string& query, reply& r,
                 uint64_t length = 0, const std::function<bool(const std::function<bool(const char*, size_t)>&)>& body = {},
                 const std::string& copy = {})
    {
        for (int attempt = 0; attempt < 2; ++attempt)
        {
            if (!connected() && !connect())
                continue;
            if (send_head(method, path, query, length, copy) && (!body || body([&](const char* p, size_t n) { return send(p, n); })) &&
                read_reply(r, method == "HEAD"))
                return true;
            drop();
            // A body comes from a pipe and cannot be sent twice.
            if (body)
                return false;
        }
        return false;
    }

    std::string m_error;

private:
    bool connected() const { return m_fd >= 0; }
    bool connect()
    {
        addrinfo hints{}, *ai = nullptr;
        hints.ai_socktype = SOCK_STREAM;
        if (::getaddrinfo(m_host.c_str(), m_port.c_str(), &hints, &ai) != 0 || !ai)
        {
            m_error = "the runtime at " + m_host + ":" + m_port + " is no address";
            return false;
        }
        m_fd = ::socket(ai->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
        const bool ok = m_fd >= 0 && ::connect(m_fd, ai->ai_addr, ai->ai_addrlen) == 0;
        ::freeaddrinfo(ai);
        if (!ok)
        {
            m_error = "the runtime at " + m_host + ":" + m_port + " does not answer";
            drop();
            return false;
        }
        if (m_tls)
        {
            // Its own listener, trusted by the certificate the runtime named, so a process that took the port first
            // is not handed the session's credentials.
            if (!m_ctx)
            {
                m_ctx = SSL_CTX_new(TLS_client_method());
                if (m_ctx && !m_ca.empty())
                {
                    if (SSL_CTX_load_verify_locations(m_ctx, m_ca.c_str(), nullptr) != 1)
                    {
                        m_error = "the runtime's certificate " + m_ca + " cannot be read";
                        drop();
                        return false;
                    }
                    X509_STORE_set_flags(SSL_CTX_get_cert_store(m_ctx), X509_V_FLAG_PARTIAL_CHAIN);
                    SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER, nullptr);
                }
            }
            m_ssl = m_ctx ? SSL_new(m_ctx) : nullptr;
            if (!m_ssl || SSL_set_fd(m_ssl, m_fd) != 1 || SSL_connect(m_ssl) != 1)
            {
                ERR_clear_error();
                m_error = "TLS to the runtime failed";
                drop();
                return false;
            }
        }
        m_in.clear();
        return true;
    }
    void drop()
    {
        if (m_ssl)
        {
            SSL_free(m_ssl);
            m_ssl = nullptr;
        }
        if (m_fd >= 0)
            ::close(m_fd);
        m_fd = -1;
    }
    bool send(const char* p, size_t n)
    {
        while (n > 0)
        {
            const ssize_t w = m_ssl ? SSL_write(m_ssl, p, static_cast<int>(std::min<size_t>(n, 1 << 30)))
                                    : ::send(m_fd, p, n, MSG_NOSIGNAL);
            if (w <= 0)
                return false;
            p += w;
            n -= static_cast<size_t>(w);
        }
        return true;
    }
    bool fill()
    {
        char buf[65536];
        const ssize_t n = m_ssl ? SSL_read(m_ssl, buf, sizeof buf) : ::recv(m_fd, buf, sizeof buf, 0);
        if (n <= 0)
            return false;
        m_in.append(buf, static_cast<size_t>(n));
        return true;
    }
    bool send_head(std::string_view method, const std::string& path, const std::string& query, uint64_t length,
                   const std::string& copy)
    {
        char date[17];
        const std::time_t now = std::time(nullptr);
        std::tm tm{};
        ::gmtime_r(&now, &tm);
        std::strftime(date, sizeof date, "%Y%m%dT%H%M%SZ", &tm);
        const std::string host = m_host.find(':') != std::string::npos ? "[" + m_host + "]:" + m_port : m_host + ":" + m_port;
        std::vector<std::pair<std::string, std::string>> h = {
            {"host", host}, {"x-amz-content-sha256", "UNSIGNED-PAYLOAD"}, {"x-amz-date", date}};
        if (!m_token.empty())
            h.emplace_back("x-amz-security-token", m_token);
        if (!copy.empty())
            h.emplace_back("x-amz-copy-source", copy);
        std::vector<socketley::s3::header_field> fields;
        for (const auto& [n, v] : h)
            fields.push_back({n, v});
        socketley::s3::sign_input in;
        in.method = method;
        in.raw_path = path;
        in.raw_query = query;
        in.headers = fields;
        in.payload_hash = "UNSIGNED-PAYLOAD";
        in.access_key = m_key;
        in.secret = m_secret;
        in.region = "us-east-1";
        in.amz_date = date;
        std::string head = std::string(method) + " " + path + (query.empty() ? "" : "?" + query) + " HTTP/1.1\r\n";
        for (const auto& [n, v] : h)
            head += n + ": " + v + "\r\n";
        if (length || method == "PUT" || method == "POST")
            head += "content-length: " + std::to_string(length) + "\r\n";
        head += "authorization: " + socketley::s3::sign(in) + "\r\nconnection: keep-alive\r\n\r\n";
        return send(head.data(), head.size());
    }
    bool read_reply(reply& r, bool head_only)
    {
        size_t end;
        while ((end = m_in.find("\r\n\r\n")) == std::string::npos)
            if (m_in.size() > 65536 || !fill())
                return false;
        const std::string head = m_in.substr(0, end);
        m_in.erase(0, end + 4);
        r.status = head.size() > 12 ? std::atoi(head.c_str() + 9) : 0;
        r.body.clear();
        std::string lower(head);
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return std::tolower(c); });
        const bool close = lower.find("\r\nconnection: close") != std::string::npos;
        if (head_only || r.status == 204 || r.status == 304)
        {
            if (close)
                drop();
            return true;
        }
        if (lower.find("\r\ntransfer-encoding: chunked") != std::string::npos)
        {
            http_chunked_decoder dechunk;
            for (;;)
            {
                std::string_view in(m_in), piece;
                chunk_step step;
                while ((step = http_chunked_next(dechunk, in, piece)) == chunk_step::payload)
                    r.body.append(piece);
                m_in.erase(0, m_in.size() - in.size());
                if (step == chunk_step::done)
                    break;
                if (step == chunk_step::bad || !fill())
                    return false;
            }
        }
        else
        {
            const size_t cl = lower.find("\r\ncontent-length:");
            const size_t n = cl == std::string::npos ? 0 : std::strtoull(lower.c_str() + cl + 17, nullptr, 10);
            while (m_in.size() < n)
                if (!fill())
                    return false;
            r.body = m_in.substr(0, n);
            m_in.erase(0, n);
        }
        if (close)
            drop();
        return true;
    }

    std::string m_host, m_port, m_ca, m_key, m_secret, m_token, m_in;
    bool m_tls{false};
    int m_fd{-1};
    SSL_CTX* m_ctx{nullptr};
    SSL* m_ssl{nullptr};
};

// Every <tag>…</tag> value in an XML answer.
std::vector<std::string> xml_values(std::string_view xml, std::string_view tag)
{
    std::vector<std::string> out;
    const std::string open = "<" + std::string(tag) + ">", close = "</" + std::string(tag) + ">";
    for (size_t p = 0; (p = xml.find(open, p)) != std::string_view::npos;)
    {
        p += open.size();
        const size_t e = xml.find(close, p);
        if (e == std::string_view::npos)
            break;
        std::string v(xml.substr(p, e - p));
        // The five entities S3 escapes keys with.
        for (const auto& [ent, ch] : std::initializer_list<std::pair<std::string_view, char>>{
                 {"&lt;", '<'}, {"&gt;", '>'}, {"&quot;", '"'}, {"&apos;", '\''}, {"&amp;", '&'}})
            for (size_t q = 0; (q = v.find(ent, q)) != std::string::npos; ++q)
                v.replace(q, ent.size(), 1, ch);
        out.push_back(std::move(v));
        p = e + close.size();
    }
    return out;
}

// ─── the run ────────────────────────────────────────────────────────────────

struct options
{
    std::string url, branch = "main", work, host, port, bucket, name, ca;
    // A library the repository was written to before, which what it still holds of it is taken from.
    std::string move_from;
    bool tls{false};
    int keep_days{14}, keep_weeks{8}, keep_months{12};
};

std::string json_str(std::string_view v)
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

class run
{
public:
    explicit run(options o) : m_o(std::move(o)), m_s3(m_o.host, m_o.port, m_o.tls, m_o.ca) {}

    int go()
    {
        const std::string repo = m_o.work + "/repo.git";
        std::error_code ec;
        std::filesystem::create_directories(m_o.work, ec);
        const int lock = ::open((m_o.work + "/lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (lock < 0)
        {
            std::cerr << "git-sync: " << m_o.work << "/lock cannot be opened: " << std::strerror(errno) << "\n";
            return 2;
        }
        if (::flock(lock, LOCK_EX | LOCK_NB) != 0)
        {
            std::cerr << "git-sync: a run of this repository is under way already\n";
            return 3;
        }
        const int rc = body(repo);
        save(rc == 0);
        return rc;
    }

private:
    int fail(std::string why)
    {
        m_error = std::move(why);
        std::cerr << "git-sync: " << m_error << "\n";
        return 2;
    }

    int body(const std::string& repo)
    {
        read_state();
        if (!std::filesystem::exists(repo + "/HEAD") && !git({"init", "--quiet", "--bare", repo}))
            return fail("git init failed (is git installed?)");
        // The branch asked for, or every branch; tags with either, and what is gone upstream goes here too.
        const std::string spec = m_o.branch == "*" ? "+refs/heads/*:refs/heads/*"
                                                   : "+refs/heads/" + m_o.branch + ":refs/heads/" + m_o.branch;
        if (!git({"-C", repo, "fetch", "--quiet", "--prune", "--no-auto-gc", "--tags", "--force", m_o.url, spec}))
            return fail("fetching " + m_o.url + (m_o.branch == "*" ? "" : " (branch " + m_o.branch + ")") +
                        " failed; see the log");
        // What the files are taken from: the branch, or with every branch the remote's own default.
        std::string shown = m_o.branch;
        if (shown == "*")
        {
            std::string out;
            if (git({"ls-remote", "--symref", m_o.url, "HEAD"}, &out) && out.starts_with("ref: refs/heads/"))
                shown = out.substr(16, out.find_first_of("\t\n", 16) - 16);
        }
        std::string commit;
        if (!git({"-C", repo, "rev-parse", "--verify", "--quiet", "refs/heads/" + shown + "^{commit}"}, &commit))
            return fail("the remote has no branch " + shown);
        commit.resize(commit.find_first_of("\n") == std::string::npos ? commit.size() : commit.find('\n'));
        m_commit = commit;
        std::string refs;
        git({"-C", repo, "for-each-ref", "--format=%(objectname) %(refname)"}, &refs);
        m_changed = refs != m_refs || m_last_commit.empty();
        m_refs = refs;
        if (!m_changed)
            return move_old();

        if (!ensure_bucket())
            return 2;
        if (const int rc = sync_tree(repo, commit); rc != 0)
            return rc;
        m_last_commit = commit;
        // HEAD names the branch shown, so a bundle cloned checks it out.
        if (!git({"-C", repo, "symbolic-ref", "HEAD", "refs/heads/" + shown}))
            return fail("HEAD could not be set to " + shown);
        if (const int rc = backup(repo, commit); rc != 0)
            return rc;
        thin();
        return move_old();
    }

    // What the library the repository was written to before still holds of it, once its tree is whole in the new
    // one: its backups are copied over, its files go, and so does the library once nothing else is left in it.
    int move_old()
    {
        if (m_o.move_from.empty() || m_o.move_from == m_o.bucket)
            return 0;
        // Gone already, or not this user's to clear: nothing is left to take, and the run is not failed for it.
        reply head;
        if (!m_s3.request("HEAD", "/" + uri_encode(m_o.move_from, false), "", head))
            return fail(m_s3.m_error);
        if (head.status != 200)
        {
            std::cerr << "git-sync: the library " << m_o.move_from << " is left as it is (" << head.status << ")\n";
            return 0;
        }
        std::vector<std::string> keys;
        if (!list(m_o.move_from, "_backups/" + m_o.name + "/", keys))
            return fail("the library " + m_o.move_from + " cannot be listed");
        for (const std::string& k : keys)
        {
            reply r;
            if (!m_s3.request("PUT", object_path(k), "", r, 0, {}, object_path(m_o.move_from, k)) || r.status != 200)
                return fail("the backup " + k + " could not be taken from " + m_o.move_from +
                            (r.status ? " (" + std::to_string(r.status) + ")" : std::string()));
            if (!del(m_o.move_from, k))
                return fail("the backup " + k + " could not be removed from " + m_o.move_from);
        }
        if (!list(m_o.move_from, m_o.name + "/", keys))
            return fail("the library " + m_o.move_from + " cannot be listed");
        for (const std::string& k : keys)
            if (!del(m_o.move_from, k))
                return fail(k + " could not be removed from " + m_o.move_from);
        std::cerr << "git-sync: " << keys.size() << " file(s) of " << m_o.name << " removed from " << m_o.move_from << "\n";
        // A library that holds what other repositories wrote is refused, and kept.
        reply r;
        if (list(m_o.move_from, "", keys) && keys.empty() &&
            m_s3.request("DELETE", "/" + uri_encode(m_o.move_from, false), "", r) && r.status == 204)
            std::cerr << "git-sync: the library " << m_o.move_from << " was empty and is gone\n";
        return 0;
    }

    bool ensure_bucket()
    {
        reply r;
        if (!m_s3.request("HEAD", "/" + uri_encode(m_o.bucket, false), "", r))
            return fail(m_s3.m_error), false;
        if (r.status == 200)
            return true;
        if (r.status == 404 && m_s3.request("PUT", "/" + uri_encode(m_o.bucket, false), "", r) && r.status == 200)
            return true;
        fail("the library " + m_o.bucket + " cannot be written by this user (" + std::to_string(r.status) + ")");
        return false;
    }

    std::string object_path(std::string_view key) const { return object_path(m_o.bucket, key); }
    static std::string object_path(std::string_view bucket, std::string_view key)
    {
        return "/" + uri_encode(bucket, false) + "/" + uri_encode(key, true);
    }

    bool del(const std::string& key) { return del(m_o.bucket, key); }
    bool del(const std::string& bucket, const std::string& key)
    {
        reply r;
        return m_s3.request("DELETE", object_path(bucket, key), "", r) &&
               (r.status == 204 || r.status == 200 || r.status == 404);
    }

    // Every key under `prefix`, false when a page could not be had, since a part of the list read as the whole
    // would leave behind what the rest held.
    bool list(const std::string& prefix, std::vector<std::string>& keys) { return list(m_o.bucket, prefix, keys); }
    bool list(const std::string& bucket, const std::string& prefix, std::vector<std::string>& keys)
    {
        keys.clear();
        std::string token;
        for (int pages = 0; pages < 10000; ++pages)
        {
            std::string q = "list-type=2";
            if (!token.empty())
                q += "&continuation-token=" + uri_encode(token, false);
            q += "&prefix=" + uri_encode(prefix, false);
            reply r;
            if (!m_s3.request("GET", "/" + uri_encode(bucket, false), q, r) || r.status != 200)
                return false;
            for (auto& k : xml_values(r.body, "Key"))
                keys.push_back(std::move(k));
            const auto next = xml_values(r.body, "NextContinuationToken");
            if (next.empty())
                return true;
            token = next.front();
        }
        return false;
    }

    // The branch's files under <name>/: what changed since the commit written last, or the whole tree and nothing
    // else the first time. Links and submodules are no files and are left out.
    int sync_tree(const std::string& repo, const std::string& commit)
    {
        struct entry { std::string sha, path; };
        std::vector<entry> put;
        std::vector<std::string> gone;
        const std::string root = m_o.name + "/";
        bool whole = m_last_commit.empty();
        if (!whole)
        {
            std::string diff;
            if (!git({"-C", repo, "diff-tree", "-r", "-z", "--no-renames", "--raw", m_last_commit, commit}, &diff))
                whole = true;   // the commit written last is gone upstream (a force push)
            else
                for (size_t p = 0; p < diff.size();)
                {
                    // ":<old mode> <new mode> <old sha> <new sha> <status>\0<path>\0"
                    const size_t z = diff.find('\0', p);
                    if (z == std::string::npos || diff[p] != ':')
                        break;
                    const std::string meta = diff.substr(p + 1, z - p - 1);
                    const size_t z2 = diff.find('\0', z + 1);
                    const std::string path = diff.substr(z + 1, (z2 == std::string::npos ? diff.size() : z2) - z - 1);
                    p = z2 == std::string::npos ? diff.size() : z2 + 1;
                    std::istringstream f(meta);
                    std::string om, nm, os, ns, st;
                    f >> om >> nm >> os >> ns >> st;
                    if (!git_names::safe_path(path))
                        continue;
                    if (st == "D" || (nm != "100644" && nm != "100755"))
                    {
                        if (om == "100644" || om == "100755")
                            gone.push_back(root + path);
                        if (st == "D")
                            continue;
                    }
                    if (nm == "100644" || nm == "100755")
                        put.push_back({ns, root + path});
                }
        }
        if (whole)
        {
            std::string tree;
            if (!git({"-C", repo, "ls-tree", "-r", "-z", "--full-tree", commit}, &tree))
                return fail("the tree of " + commit + " cannot be read");
            std::set<std::string> keep;
            for (size_t p = 0; p < tree.size();)
            {
                // "<mode> <type> <sha>\t<path>\0"
                const size_t z = std::min(tree.find('\0', p), tree.size());
                const std::string line = tree.substr(p, z - p);
                p = z + 1;
                const size_t tab = line.find('\t');
                if (tab == std::string::npos || line.size() < 52)
                    continue;
                const std::string mode = line.substr(0, 6), path = line.substr(tab + 1);
                if ((mode != "100644" && mode != "100755") || !git_names::safe_path(path))
                    continue;
                put.push_back({line.substr(12, 40), root + path});
                keep.insert(root + path);
            }
            // What is under <name>/ and not in the tree went with an earlier run of another branch or repository.
            std::vector<std::string> there;
            if (!list(root, there))
                return fail("listing " + root + " in the library failed");
            for (const std::string& k : there)
                if (!keep.count(k))
                    gone.push_back(k);
        }
        if (!upload_blobs(repo, put))
            return 2;
        for (const std::string& k : gone)
            if (!del(k))
                return fail("removing " + k + " failed");
        m_files = put.size();
        std::cerr << "git-sync: " << put.size() << " file(s) written, " << gone.size() << " removed, at " << commit
                  << "\n";
        return 0;
    }

    // Each blob read from one `git cat-file --batch` and put as it comes, never whole in memory.
    template <class E>
    bool upload_blobs(const std::string& repo, const std::vector<E>& put)
    {
        if (put.empty())
            return true;
        child c = git_start({"-C", repo, "cat-file", "--batch"}, true);
        if (c.pid < 0)
            return fail("git cat-file could not be started"), false;
        std::string pending;
        bool ok = true;
        for (const E& e : put)
        {
            const std::string ask = e.sha + "\n";
            if (::write(c.in, ask.data(), ask.size()) != static_cast<ssize_t>(ask.size()))
            {
                ok = false;
                break;
            }
            // "<sha> blob <size>\n" and then the bytes and a newline.
            std::string head;
            char ch;
            while (::read(c.out, &ch, 1) == 1 && ch != '\n')
                head += ch;
            const size_t sp = head.rfind(' ');
            if (head.find(" blob ") == std::string::npos || sp == std::string::npos)
            {
                ok = false;
                fail("git cat-file said " + head);
                break;
            }
            uint64_t left = std::strtoull(head.c_str() + sp + 1, nullptr, 10);
            reply r;
            const bool sent = m_s3.request("PUT", object_path(e.path), "", r, left,
                                           [&](const std::function<bool(const char*, size_t)>& out) {
                                               char buf[65536];
                                               while (left > 0)
                                               {
                                                   const size_t n = static_cast<size_t>(std::min<uint64_t>(left, sizeof buf));
                                                   if (!read_full(c.out, buf, n) || !out(buf, n))
                                                       return false;
                                                   left -= n;
                                               }
                                               return true;
                                           });
            char nl;
            if (!sent || left != 0 || !read_full(c.out, &nl, 1) || r.status != 200)
            {
                ok = false;
                fail("writing " + e.path + " failed" + (r.status ? " (" + std::to_string(r.status) + ")" : ""));
                break;
            }
        }
        ::close(c.in);
        c.in = -1;
        // An aborted run leaves git with nobody reading.
        if (!ok)
            ::kill(c.pid, SIGTERM);
        git_wait(c);
        return ok;
    }

    // A bundle of the refs fetched, full history, under _backups/<name>/<date>_<time>_<short commit>.bundle.
    int backup(const std::string& repo, const std::string& commit)
    {
        const std::string file = m_o.work + "/backup.bundle";
        std::vector<std::string> args = {"-C", repo, "bundle", "create", "--quiet", file, "HEAD"};
        if (m_o.branch == "*")
            args.push_back("--all");
        else
        {
            args.push_back("refs/heads/" + m_o.branch);
            args.push_back("--tags");
        }
        if (!git(args))
            return fail("git bundle failed");
        struct stat st{};
        const int fd = ::open(file.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0 || ::fstat(fd, &st) != 0)
            return fail("the bundle cannot be read");
        char when[32];
        const std::time_t now = std::time(nullptr);
        std::tm tm{};
        ::gmtime_r(&now, &tm);
        std::strftime(when, sizeof when, "%Y-%m-%d_%H%M%S", &tm);
        const std::string key = "_backups/" + m_o.name + "/" + when + "_" + commit.substr(0, 10) + ".bundle";
        uint64_t left = static_cast<uint64_t>(st.st_size);
        reply r;
        const bool sent = m_s3.request("PUT", object_path(key), "", r, left,
                                       [&](const std::function<bool(const char*, size_t)>& out) {
                                           char buf[65536];
                                           while (left > 0)
                                           {
                                               const ssize_t n = ::read(fd, buf, std::min<uint64_t>(left, sizeof buf));
                                               if (n <= 0 || !out(buf, static_cast<size_t>(n)))
                                                   return false;
                                               left -= static_cast<uint64_t>(n);
                                           }
                                           return true;
                                       });
        ::close(fd);
        ::unlink(file.c_str());
        if (!sent || r.status != 200)
            return fail("writing the backup failed" + (r.status ? " (" + std::to_string(r.status) + ")" : std::string()));
        m_backup = key;
        std::cerr << "git-sync: backup " << key << "\n";
        return 0;
    }

    // Every backup of the last day, and before it the newest of each of the last keep_days days, keep_weeks weeks and
    // keep_months months, by the time in its name; the rest go. The last day is kept whole because a force push
    // rewrites what the newest bundle holds.
    void thin()
    {
        const std::string prefix = "_backups/" + m_o.name + "/";
        std::vector<std::string> keys;
        // A list in part would thin by what it lacks, so none is thinned this time.
        if (!list(prefix, keys))
            return;
        std::sort(keys.rbegin(), keys.rend());
        const std::time_t now = std::time(nullptr);
        std::set<std::string> days, weeks, months, keep;
        for (const std::string& k : keys)
        {
            const std::string base = k.substr(prefix.size());
            std::tm tm{};
            if (base.size() < 17 || !::strptime(base.substr(0, 17).c_str(), "%Y-%m-%d_%H%M%S", &tm))
            {
                keep.insert(k);   // not one of ours
                continue;
            }
            const std::time_t t = ::timegm(&tm);
            const int64_t age = (now - t) / 86400;
            if (now - t < 86400)
            {
                keep.insert(k);
                days.insert(base.substr(0, 10));
                continue;
            }
            char w[16], m[16];
            std::strftime(w, sizeof w, "%G-%V", &tm);
            std::strftime(m, sizeof m, "%Y-%m", &tm);
            bool k_ = false;
            if (age < m_o.keep_days && days.insert(base.substr(0, 10)).second)
                k_ = true;
            if (age < 7 * int64_t(m_o.keep_weeks) && weeks.insert(w).second)
                k_ = true;
            if (age < 31 * int64_t(m_o.keep_months) && months.insert(m).second)
                k_ = true;
            if (k_ || keep.empty())
                keep.insert(k);
        }
        for (const std::string& k : keys)
            if (!keep.count(k) && del(k))
                std::cerr << "git-sync: backup " << k << " thinned out\n";
    }

    void read_state()
    {
        std::ifstream f(m_o.work + "/written");
        std::getline(f, m_last_commit);
        std::stringstream rest;
        rest << f.rdbuf();
        m_refs = rest.str();
    }

    void save(bool ok)
    {
        if (ok)
        {
            std::ofstream w(m_o.work + "/written.tmp");
            w << m_last_commit << "\n" << m_refs;
            w.close();
            std::filesystem::rename(m_o.work + "/written.tmp", m_o.work + "/written");
        }
        std::ofstream s(m_o.work + "/state.json.tmp");
        s << "{\"ok\":" << (ok ? "true" : "false") << ",\"at\":" << std::time(nullptr)
          << ",\"commit\":" << json_str(m_commit) << ",\"changed\":" << (m_changed ? "true" : "false")
          << ",\"files\":" << m_files << ",\"backup\":" << json_str(m_backup) << ",\"error\":" << json_str(m_error)
          << "}\n";
        s.close();
        std::error_code ec;
        std::filesystem::rename(m_o.work + "/state.json.tmp", m_o.work + "/state.json", ec);
    }

    options m_o;
    s3_client m_s3;
    std::string m_last_commit, m_refs, m_commit, m_backup, m_error;
    bool m_changed{false};
    size_t m_files{0};
};

}   // namespace

int git_sync_main(int argc, char** argv)
{
    // A git that exits while it is written to is a failed write, recorded, and not the end of this process.
    ::signal(SIGPIPE, SIG_IGN);
    options o;
    for (int i = 2; i < argc; ++i)
    {
        const std::string_view a = argv[i];
        auto value = [&](std::string& out) {
            if (i + 1 >= argc)
                return false;
            out = argv[++i];
            return true;
        };
        std::string v;
        bool ok = true;
        if (a == "--url")
            ok = value(o.url);
        else if (a == "--branch")
            ok = value(o.branch);
        else if (a == "--work")
            ok = value(o.work);
        else if (a == "--bucket")
            ok = value(o.bucket);
        else if (a == "--name")
            ok = value(o.name);
        else if (a == "--tls")
            o.tls = true;
        else if (a == "--ca")
            ok = value(o.ca);
        else if (a == "--move-from")
            ok = value(o.move_from);
        else if (a == "--endpoint" && (ok = value(v)))
        {
            const size_t c = v.rfind(':');
            ok = c != std::string::npos && c > 0;
            if (ok)
            {
                o.host = v.substr(0, c);
                o.port = v.substr(c + 1);
                if (o.host.front() == '[' && o.host.back() == ']')
                    o.host = o.host.substr(1, o.host.size() - 2);
            }
        }
        else if (a == "--keep" && (ok = value(v)))
            ok = std::sscanf(v.c_str(), "%d,%d,%d", &o.keep_days, &o.keep_weeks, &o.keep_months) == 3;
        else
            ok = false;
        if (!ok)
        {
            std::cout << "git-sync: unknown or incomplete option " << a << "\n";
            return 1;
        }
    }
    std::string why;
    if (o.work.empty() || o.host.empty() || o.bucket.empty() || !git_names::valid_url(o.url, why) ||
        !git_names::valid_branch(o.branch, why) || !git_names::valid_name(o.name, why))
    {
        std::cout << "usage: socketley git-sync --url URL --branch NAME|* --work DIR --endpoint HOST:PORT [--tls [--ca FILE]] "
                     "--bucket B --name N [--keep DAYS,WEEKS,MONTHS] [--move-from LIBRARY]"
                  << (why.empty() ? "" : "\n" + why) << "\n";
        return 1;
    }
    // The token goes in a header with every request, so only over https, where nobody on the way reads it.
    if (const char* t = std::getenv("SOCKETLEY_GIT_TOKEN"); t && *t && !o.url.starts_with("https://"))
    {
        std::cout << "a GitHub token is sent only over https://, and " << o.url << " is not\n";
        return 1;
    }
    return run(std::move(o)).go();
}
