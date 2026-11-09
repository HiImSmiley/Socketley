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
#include <limits>
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

#include "../util/logging.h"
#include "../util/settings.h"
#include "../persist/paths.h"
#include "tls_context.h"
#include "../persist/replaced_file.h"
#include "../persist/file_stamp.h"

extern char** environ;

namespace cert_keeper
{

bool read_cert(const std::string& path, cert_facts& c)
{
#if SOCKETLEY_CERT_KEEPER_TLS
    BIO* b = BIO_new_file(path.c_str(), "r");
    X509* x = b ? PEM_read_bio_X509(b, nullptr, nullptr, nullptr) : nullptr;
    if (b)
        BIO_free(b);
    ERR_clear_error();
    if (!x)
        return false;
    c = cert_facts{};
    if (auto* gens = static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(x, NID_subject_alt_name, nullptr, nullptr)))
    {
        for (int i = 0; i < sk_GENERAL_NAME_num(gens); ++i)
            if (const GENERAL_NAME* g = sk_GENERAL_NAME_value(gens, i); g->type == GEN_DNS)
                c.names.emplace_back(reinterpret_cast<const char*>(ASN1_STRING_get0_data(g->d.dNSName)),
                                     static_cast<size_t>(ASN1_STRING_length(g->d.dNSName)));
        GENERAL_NAMES_free(gens);
    }
    int days = 0, secs = 0;
    c.expiry_known = ASN1_TIME_diff(&days, &secs, nullptr, X509_get0_notAfter(x)) == 1;
    c.expires_in = static_cast<int64_t>(days) * 86400 + secs;
    char issuer[256] = {};
    X509_NAME_get_text_by_NID(X509_get_issuer_name(x), NID_organizationName, issuer, sizeof issuer);
    if (!issuer[0])
        X509_NAME_get_text_by_NID(X509_get_issuer_name(x), NID_commonName, issuer, sizeof issuer);
    c.issuer = issuer;
    c.self_signed = X509_check_issued(x, x) == X509_V_OK;
    X509_free(x);
    ERR_clear_error();
    return true;
#else
    (void)path;
    c = cert_facts{};
    return false;
#endif
}

namespace
{

using clock = std::chrono::steady_clock;

constexpr auto watch_every  = std::chrono::seconds(2);
constexpr auto renew_every  = std::chrono::seconds(60);
// A certificate with less than this left is renewed, as Let's Encrypt advises for its 90 days.
constexpr int64_t renew_before_s = 30 * 86400;
constexpr auto backoff_first = std::chrono::seconds(60);
// How long a certificate issued without a wildcard whose zone was not delegated yet waits to ask again.
constexpr auto partial_again = std::chrono::hours(6);
constexpr auto backoff_most  = std::chrono::hours(6);

using file_sig = socketley::file_stamp;

file_sig sig_of(const std::string& path)
{
    return socketley::file_stamp::of(path);
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
    std::vector<std::string> domains, dns_zones;
    std::string email, cert, key, log;
    // The names the child now running asks for, written beside the certificate when it succeeds.
    std::string issuing;
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
    return socketley::replace_file(path, data, socketley::durability::data, nullptr, mode);
}

// Seconds the certificate in `path` has left, and whether it is its own issuer; false when it cannot be read.
bool cert_left(const std::string& path, int64_t& left_s, bool& self_signed)
{
    cert_facts c;
    if (!read_cert(path, c))
        return false;
    left_s = c.expires_in;
    self_signed = c.self_signed;
    return c.expiry_known;
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

// The names a certificate is for, sorted, a line each: what is written beside it once issued.
std::string names_of(const acme_state& a)
{
    std::vector<std::string> d = a.domains;
    std::sort(d.begin(), d.end());
    std::string out;
    for (const std::string& n : d)
        out += n + "\n";
    return out;
}

void spawn_issue(acme_state& a)
{
    std::string names;
    for (const std::string& d : a.domains)
        names += (names.empty() ? "" : ",") + d;
    std::vector<std::string> args = {"socketley", "acme", "issue", "--domains", names, "--cert", a.cert, "--key", a.key};
    if (!a.email.empty())
        args.insert(args.end(), {"--email", a.email});
    // A name in a zone this daemon serves goes over DNS-01, which needs no port open, as does every wildcard, which
    // `acme issue` picks by itself; anything else over the listener on 443.
    std::string zones;
    for (const std::string& z : a.dns_zones)
        zones += (zones.empty() ? "" : ",") + z;
    if (!zones.empty())
        args.insert(args.end(), {"--dns-zones", zones});
    const bool wildcard = std::any_of(a.domains.begin(), a.domains.end(), [](const std::string& d) { return d.starts_with("*."); });
    if (a.tls_alpn && (!wildcard || !zones.empty()))
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
    a.issuing = names_of(a);
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
        // 3 is issued without the wildcards of a zone not yet delegated here, asked again after a while.
        const bool partial = r != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 3;
        if (!partial && (r == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0))
        {
            LOG_ERROR(("acme: issuing for " + a.domains.front() + " failed, tried again in " +
                       std::to_string(std::chrono::duration_cast<std::chrono::seconds>(a.backoff).count()) + "s: " +
                       last_line(a.log)).c_str());
            a.next_try = now + a.backoff;
            a.backoff = std::min<clock::duration>(a.backoff * 2, backoff_most);
            return;
        }
        // Issued: the files are taken up at the next look, which is now.
        write_file(a.cert + ".names", a.issuing, 0644);
        a.backoff = backoff_first;
        g_next_watch = now;
        // Names asked for while it ran are asked for now, not at the next renewal look or six hours later.
        if (a.issuing == names_of(a))
        {
            if (partial)
                a.next_try = now + partial_again;
            return;
        }
    }
    if (now < a.next_try)
        return;
    int64_t left = 0;
    bool self_signed = true;
    if (cert_left(a.cert, left, self_signed) && !self_signed && left > renew_before_s)
    {
        // Issued for the names asked for now, or issued before the names were written beside it.
        std::ifstream f(a.cert + ".names");
        std::stringstream was;
        was << f.rdbuf();
        struct stat partial{};
        if ((!f || was.str() == names_of(a)) && ::stat((a.cert + ".partial").c_str(), &partial) != 0)
            return;
    }
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

bool reserved_name(std::string_view name)
{
    if (socketley::settings::text("SOCKETLEY_ACME_DIRECTORY"))
        return false;
    std::string n;
    for (const char c : name)
        n += (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    while (n.ends_with('.'))
        n.pop_back();
    static constexpr std::string_view reserved[] = {"example", "example.com", "example.net", "example.org", "test",
                                                    "invalid", "localhost", "local", "internal", "home.arpa", "alt"};
    return std::any_of(std::begin(reserved), std::end(reserved), [&](std::string_view r) {
        return n == r || (n.size() > r.size() && n.ends_with(r) && n[n.size() - r.size() - 1] == '.');
    });
}

bool prepare_acme(const std::vector<std::string>& in, std::string_view email, std::string_view cert_path,
                  std::string_view key_path, bool on_443, std::string& err, const std::vector<std::string>& dns_zones)
{
    // No names is no certificate to keep, and reading one would initialise OpenSSL in every runtime that has no TLS.
    if (in.empty())
        return true;

    // Asked of a public CA, a reserved name only sends a request out of a test or a lab that comes back refused.
    std::vector<std::string> domains;
    for (const std::string& d : in)
        if (!reserved_name(d))
            domains.push_back(d);
    if (domains.size() < in.size())
        LOG_INFO(("acme: " + std::to_string(in.size() - domains.size()) +
                  " reserved name(s) not asked for, which no public CA issues; a self-signed certificate stands in")
                     .c_str());
    if (domains.empty())
    {
        // A week's stand-in from before is replaced, since nothing is going to issue the one it stood in for.
        int64_t left = 0;
        bool self_signed = false;
        const bool keep = cert_left(std::string(cert_path), left, self_signed) && (!self_signed || left > 30 * 86400);
        if (!keep && !write_self_signed(in, 365, cert_path, key_path))
        {
            err = "acme: a self-signed certificate could not be written to " + std::string(cert_path);
            return false;
        }
        return true;
    }
    acme_state a;
    a.tls_alpn = on_443;
    a.domains = domains;
    a.dns_zones = dns_zones;
    a.email.assign(email);
    a.cert.assign(cert_path);
    a.key.assign(key_path);
    a.log = a.cert + ".log";
    // A child still issuing for the names before is waited for, and the new names asked for after it.
    for (const acme_state& o : g_acme)
        if (o.cert == a.cert && o.pid > 0)
        {
            a.pid = o.pid;
            a.issuing = o.issuing;
        }
    int64_t left = 0;
    bool self_signed = false;
    // Refused before the old entry goes, so a child it still waits for is not left with nothing to reap it.
    if (!cert_left(a.cert, left, self_signed) && !write_self_signed(domains, 7, a.cert, a.key))
    {
        err = "acme: a placeholder certificate could not be written to " + a.cert;
        return false;
    }
    std::erase_if(g_acme, [&](const acme_state& o) { return o.cert == a.cert; });
    g_acme.push_back(std::move(a));
    g_next_renew = clock::now();
    return true;
}

int due_in_ms()
{
    if (g_watched.empty() && g_acme.empty())
        return -1;
    clock::time_point next = g_watched.empty() ? clock::time_point::max() : g_next_watch;
    if (!g_acme.empty())
        next = std::min(next, g_next_renew);
    const clock::time_point now = clock::now();
    if (next <= now)
        return 0;
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(next - now).count() + 1;
    return static_cast<int>(std::min<int64_t>(ms, std::numeric_limits<int>::max()));
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

std::string entrance_cert_path(std::string_view runtime)
{
    return domain_dir("entrance-" + std::string(runtime)) + "/fullchain.pem";
}

std::string entrance_key_path(std::string_view runtime)
{
    return domain_dir("entrance-" + std::string(runtime)) + "/key.pem";
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
