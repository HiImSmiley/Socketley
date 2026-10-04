#include "cert_keeper.h"

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>

#if __has_include(<openssl/ssl.h>)
#define SOCKETLEY_CERT_KEEPER_TLS 1
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#else
#define SOCKETLEY_CERT_KEEPER_TLS 0
#endif

#include "logging.h"
#include "paths.h"
#include "tls_context.h"

extern char** environ;

namespace cert_keeper
{

namespace
{

using clock = std::chrono::steady_clock;

constexpr auto watch_every  = std::chrono::seconds(2);
constexpr auto renew_every  = std::chrono::seconds(60);
// A certificate with less than this left is renewed, as Let's Encrypt advises for its 90 days.
constexpr int64_t renew_before_s = 30 * 86400;
constexpr auto backoff_first = std::chrono::seconds(60);
constexpr auto backoff_most  = std::chrono::hours(6);

struct file_sig
{
    int64_t mtime_ns{0};
    int64_t size{-1};
    uint64_t ino{0};
    bool operator==(const file_sig&) const = default;
};

file_sig sig_of(const std::string& path)
{
    struct stat sb{};
    if (::stat(path.c_str(), &sb) != 0)
        return {};
    return {static_cast<int64_t>(sb.st_mtim.tv_sec) * 1000000000 + sb.st_mtim.tv_nsec, static_cast<int64_t>(sb.st_size),
            static_cast<uint64_t>(sb.st_ino)};
}

struct watched
{
    tls_context* ctx{nullptr};
    std::string cert, key;
    file_sig cert_sig, key_sig;
    // The pair last refused, so a broken file is reported once and not every few seconds.
    file_sig bad_cert, bad_key;
};

struct acme_state
{
    std::vector<std::string> domains;
    std::string email, cert, key, log;
    bool tls_alpn{false};
    pid_t pid{-1};
    clock::time_point next_try{};
    clock::duration backoff{backoff_first};
};

std::vector<watched> g_watched;
std::vector<acme_state> g_acme;
clock::time_point g_next_watch{};
clock::time_point g_next_renew{};

std::string acme_root()
{
    static const std::string root = (socketley_paths::resolve().state_dir / ".acme").string();
    return root;
}

std::string domain_dir(std::string_view domain)
{
    // A name is a path component here, and one with a slash or leading dot is none a CA would issue for.
    std::string d(domain);
    std::replace(d.begin(), d.end(), '/', '_');
    if (!d.empty() && d.front() == '.')
        d.front() = '_';
    return acme_root() + "/" + d;
}

bool write_file(const std::string& path, std::string_view data, mode_t mode)
{
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(path).parent_path(), ec);
    const std::string tmp = path + ".tmp." + std::to_string(::getpid());
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0)
        return false;
    bool ok = ::write(fd, data.data(), data.size()) == static_cast<ssize_t>(data.size());
    ok = ::fsync(fd) == 0 && ok;
    ok = ::close(fd) == 0 && ok;
    if (!ok || ::rename(tmp.c_str(), path.c_str()) != 0)
    {
        ::unlink(tmp.c_str());
        return false;
    }
    return true;
}

// Seconds the certificate in `path` has left, and whether it is its own issuer; false when it cannot be read.
bool cert_left(const std::string& path, int64_t& left_s, bool& self_signed)
{
#if SOCKETLEY_CERT_KEEPER_TLS
    BIO* b = BIO_new_file(path.c_str(), "r");
    X509* x = b ? PEM_read_bio_X509(b, nullptr, nullptr, nullptr) : nullptr;
    if (b)
        BIO_free(b);
    ERR_clear_error();
    if (!x)
        return false;
    int days = 0, secs = 0;
    const bool ok = ASN1_TIME_diff(&days, &secs, nullptr, X509_get0_notAfter(x)) == 1;
    left_s = static_cast<int64_t>(days) * 86400 + secs;
    self_signed = X509_check_issued(x, x) == X509_V_OK;
    X509_free(x);
    return ok;
#else
    (void)path;
    left_s = 0;
    self_signed = false;
    return false;
#endif
}

std::string last_line(const std::string& path)
{
    std::ifstream f(path);
    std::string line, last;
    while (std::getline(f, line))
        if (!line.empty())
            last = line;
    return last;
}

void spawn_issue(acme_state& a)
{
    std::string names;
    for (const std::string& d : a.domains)
        names += (names.empty() ? "" : ",") + d;
    std::vector<std::string> args = {"socketley", "acme", "issue", "--domains", names, "--cert", a.cert, "--key", a.key};
    if (!a.email.empty())
        args.insert(args.end(), {"--email", a.email});
    if (a.tls_alpn)
        args.insert(args.end(), {"--challenge", "tls-alpn-01"});
    std::vector<char*> argv;
    for (std::string& s : args)
        argv.push_back(s.data());
    argv.push_back(nullptr);
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t attr;
    posix_spawn_file_actions_init(&fa);
    posix_spawnattr_init(&attr);
    posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 1, a.log.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    posix_spawn_file_actions_adddup2(&fa, 1, 2);
    posix_spawn_file_actions_addclosefrom_np(&fa, 3);
    sigset_t def, none;
    sigemptyset(&def);
    sigaddset(&def, SIGPIPE);
    sigemptyset(&none);
    posix_spawnattr_setsigdefault(&attr, &def);
    posix_spawnattr_setsigmask(&attr, &none);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK);
    pid_t pid = -1;
    const int rc = ::posix_spawn(&pid, "/proc/self/exe", &fa, &attr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&attr);
    if (rc != 0)
    {
        LOG_ERROR(("acme: `socketley acme issue` could not be started: " + std::string(std::strerror(rc))).c_str());
        a.next_try = clock::now() + a.backoff;
        a.backoff = std::min<clock::duration>(a.backoff * 2, backoff_most);
        return;
    }
    a.pid = pid;
}

void look_after(acme_state& a, clock::time_point now)
{
    if (a.pid > 0)
    {
        int status = 0;
        const pid_t r = ::waitpid(a.pid, &status, WNOHANG);
        if (r == 0)
            return;
        a.pid = -1;
        if (r == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
            LOG_ERROR(("acme: issuing for " + a.domains.front() + " failed, tried again in " +
                       std::to_string(std::chrono::duration_cast<std::chrono::seconds>(a.backoff).count()) + "s: " +
                       last_line(a.log)).c_str());
            a.next_try = now + a.backoff;
            a.backoff = std::min<clock::duration>(a.backoff * 2, backoff_most);
            return;
        }
        // Issued: the files are taken up at the next look, which is now.
        a.backoff = backoff_first;
        g_next_watch = now;
        return;
    }
    if (now < a.next_try)
        return;
    int64_t left = 0;
    bool self_signed = true;
    if (cert_left(a.cert, left, self_signed) && !self_signed && left > renew_before_s)
        return;
    spawn_issue(a);
}

}   // namespace

void watch(tls_context* ctx, std::string_view cert_path, std::string_view key_path)
{
    unwatch(ctx);
    watched w;
    w.ctx = ctx;
    w.cert.assign(cert_path);
    w.key.assign(key_path);
    w.cert_sig = sig_of(w.cert);
    w.key_sig = sig_of(w.key);
    g_watched.push_back(std::move(w));
}

void unwatch(tls_context* ctx)
{
    std::erase_if(g_watched, [ctx](const watched& w) { return w.ctx == ctx; });
}

bool prepare_acme(const std::vector<std::string>& domains, std::string_view email, std::string_view cert_path,
                  std::string_view key_path, bool on_443, std::string& err)
{
    if (domains.empty())
        return true;
    acme_state a;
    a.tls_alpn = on_443;
    a.domains = domains;
    a.email.assign(email);
    a.cert.assign(cert_path);
    a.key.assign(key_path);
    a.log = a.cert + ".log";
    std::erase_if(g_acme, [&](const acme_state& o) { return o.cert == a.cert; });
    int64_t left = 0;
    bool self_signed = false;
    if (!cert_left(a.cert, left, self_signed) && !write_self_signed(domains, 7, a.cert, a.key))
    {
        err = "acme: a placeholder certificate could not be written to " + a.cert;
        return false;
    }
    g_acme.push_back(std::move(a));
    g_next_renew = clock::now();
    return true;
}

void tick()
{
    if (g_watched.empty() && g_acme.empty())
        return;
    const clock::time_point now = clock::now();
    if (!g_acme.empty() && now >= g_next_renew)
    {
        // A child that is running is looked at every turn of this, so its end is seen within the renew step.
        bool running = false;
        for (acme_state& a : g_acme)
        {
            look_after(a, now);
            running = running || a.pid > 0;
        }
        g_next_renew = now + (running ? std::chrono::seconds(1) : renew_every);
    }
    if (now < g_next_watch)
        return;
    g_next_watch = now + watch_every;
    for (watched& w : g_watched)
    {
        const file_sig c = sig_of(w.cert), k = sig_of(w.key);
        if (c == w.cert_sig && k == w.key_sig)
            continue;
        if (w.ctx->reload_cert(w.cert, w.key))
        {
            w.cert_sig = c;
            w.key_sig = k;
            LOG_INFO(("tls: took up the replaced certificate " + w.cert).c_str());
        }
        else if (!(c == w.bad_cert && k == w.bad_key))
        {
            // A pair caught between its two renames matches at the next look; one that never does is said once.
            w.bad_cert = c;
            w.bad_key = k;
            LOG_WARN(("tls: " + w.cert + " and " + w.key + " changed and do not load as a pair; keeping the old ones")
                         .c_str());
        }
    }
}

std::string challenge_dir()
{
    return acme_root() + "/challenges";
}

std::string challenge_answer(std::string_view token)
{
    if (token.empty() || token.size() > 256)
        return {};
    for (char ch : token)
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_'))
            return {};
    std::ifstream f(challenge_dir() + "/" + std::string(token));
    if (!f)
        return {};
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::string tls_alpn_path(std::string_view name)
{
    return challenge_dir() + "/tls-alpn-" + domain_dir(name).substr(acme_root().size() + 1) + ".pem";
}

std::string tls_alpn_answer(std::string_view name)
{
    if (name.empty() || name.size() > 253)
        return {};
    std::ifstream f(tls_alpn_path(name));
    if (!f)
        return {};
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::string acme_cert_path(std::string_view domain)
{
    return domain_dir(domain) + "/fullchain.pem";
}

std::string acme_key_path(std::string_view domain)
{
    return domain_dir(domain) + "/key.pem";
}

bool write_self_signed(const std::vector<std::string>& domains, int days, std::string_view cert_path,
                       std::string_view key_path)
{
#if SOCKETLEY_CERT_KEEPER_TLS
    if (domains.empty())
        return false;
    EVP_PKEY* key = EVP_EC_gen("P-256");
    X509* x = X509_new();
    bool ok = key && x;
    if (ok)
    {
        X509_set_version(x, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x), static_cast<long>(std::time(nullptr)));
        X509_gmtime_adj(X509_getm_notBefore(x), -3600);
        X509_gmtime_adj(X509_getm_notAfter(x), static_cast<long>(days) * 86400);
        X509_set_pubkey(x, key);
        X509_NAME* name = X509_get_subject_name(x);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(domains.front().c_str()),
                                   -1, -1, 0);
        X509_set_issuer_name(x, name);
        std::string san;
        for (const std::string& d : domains)
            san += (san.empty() ? "DNS:" : ",DNS:") + d;
        X509V3_CTX v3;
        X509V3_set_ctx(&v3, x, x, nullptr, nullptr, 0);
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &v3, NID_subject_alt_name, san.c_str());
        ok = ext && X509_add_ext(x, ext, -1) == 1;
        if (ext)
            X509_EXTENSION_free(ext);
        ok = ok && X509_sign(x, key, EVP_sha256()) > 0;
    }
    std::string cert_pem, key_pem;
    if (ok)
    {
        BIO* cb = BIO_new(BIO_s_mem());
        BIO* kb = BIO_new(BIO_s_mem());
        ok = cb && kb && PEM_write_bio_X509(cb, x) == 1 &&
             PEM_write_bio_PrivateKey(kb, key, nullptr, nullptr, 0, nullptr, nullptr) == 1;
        char* p = nullptr;
        if (ok)
        {
            const long cn = BIO_get_mem_data(cb, &p);
            cert_pem.assign(p, static_cast<size_t>(cn));
            const long kn = BIO_get_mem_data(kb, &p);
            key_pem.assign(p, static_cast<size_t>(kn));
        }
        if (cb) BIO_free(cb);
        if (kb) BIO_free(kb);
    }
    if (x) X509_free(x);
    if (key) EVP_PKEY_free(key);
    ERR_clear_error();
    // The key first, so a certificate on disk always has its key there before it.
    return ok && write_file(std::string(key_path), key_pem, 0600) && write_file(std::string(cert_path), cert_pem, 0644);
#else
    (void)domains;
    (void)days;
    (void)cert_path;
    (void)key_path;
    return false;
#endif
}

}   // namespace cert_keeper
