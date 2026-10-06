// `socketley acme issue`: a certificate from an ACME CA (RFC 8555), Let's Encrypt unless told otherwise, proven over
// HTTP-01 by the challenge files every socketley HTTP runtime serves. A runtime with --acme runs it as a child of its
// worker; an operator may run it by hand, as certbot is run. Blocking on purpose: it is its own process.
#include <fcntl.h>
#include <netdb.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "../shared/cert_keeper.h"
#include "../runtime/storage/json_doc.h"

namespace
{

using socketley::storage::jvalue;
using socketley::storage::json_reader;

constexpr std::string_view lets_encrypt = "https://acme-v02.api.letsencrypt.org/directory";
constexpr int poll_seconds = 90;

std::string b64url(std::string_view in)
{
    static constexpr char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    size_t i = 0;
    for (; i + 2 < in.size(); i += 3)
    {
        const uint32_t v = (uint8_t(in[i]) << 16) | (uint8_t(in[i + 1]) << 8) | uint8_t(in[i + 2]);
        out += tbl[v >> 18];
        out += tbl[(v >> 12) & 63];
        out += tbl[(v >> 6) & 63];
        out += tbl[v & 63];
    }
    if (i + 1 == in.size())
    {
        const uint32_t v = uint8_t(in[i]) << 16;
        out += tbl[v >> 18];
        out += tbl[(v >> 12) & 63];
    }
    else if (i + 2 == in.size())
    {
        const uint32_t v = (uint8_t(in[i]) << 16) | (uint8_t(in[i + 1]) << 8);
        out += tbl[v >> 18];
        out += tbl[(v >> 12) & 63];
        out += tbl[(v >> 6) & 63];
    }
    return out;
}

std::string sha256(std::string_view in)
{
    unsigned char d[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(in.data()), in.size(), d);
    return std::string(reinterpret_cast<const char*>(d), sizeof d);
}

std::string jstr(std::string_view v)
{
    std::string o = "\"";
    for (char ch : v)
    {
        if (ch == '"' || ch == '\\')
            o += '\\';
        o += ch;
    }
    return o + "\"";
}

const jvalue* member(const jvalue& o, std::string_view n)
{
    for (const auto& [k, v] : o.members)
        if (k == n)
            return &v;
    return nullptr;
}

std::string str(const jvalue& o, std::string_view n)
{
    const jvalue* v = member(o, n);
    return v && v->k == jvalue::kind::string ? v->s : std::string{};
}

// ─── HTTPS, one request per connection ──────────────────────────────────────

struct reply
{
    int status{0};
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    std::string header(std::string_view name) const
    {
        for (const auto& [k, v] : headers)
            if (k.size() == name.size() && strncasecmp(k.data(), name.data(), k.size()) == 0)
                return v;
        return {};
    }
};

class https
{
public:
    bool init(std::string& err)
    {
        m_ctx = SSL_CTX_new(TLS_client_method());
        if (!m_ctx)
            return fail(err, "no TLS context");
        SSL_CTX_set_min_proto_version(m_ctx, TLS1_2_VERSION);
        SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER, nullptr);
        // A test CA's root, as Pebble's is, or the system's roots for a public one.
        const char* ca = std::getenv("SOCKETLEY_ACME_CA");
        const bool ok = ca && *ca ? SSL_CTX_load_verify_locations(m_ctx, ca, nullptr) == 1
                                  : SSL_CTX_set_default_verify_paths(m_ctx) == 1;
        return ok || fail(err, std::string("the CA's trust roots could not be loaded") + (ca && *ca ? std::string(": ") + ca : ""));
    }
    ~https()
    {
        if (m_ctx)
            SSL_CTX_free(m_ctx);
    }

    bool request(std::string_view method, const std::string& url, std::string_view type, std::string_view body, reply& out,
                 std::string& err)
    {
        std::string_view u = url;
        if (!u.starts_with("https://"))
            return fail(err, "not an https URL: " + url);
        u.remove_prefix(8);
        const size_t slash = u.find('/');
        std::string hostport(u.substr(0, slash)), path(slash == std::string_view::npos ? "/" : u.substr(slash));
        std::string host = hostport, port = "443";
        if (const size_t colon = hostport.rfind(':'); colon != std::string::npos && hostport.find(']') == std::string::npos)
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
            timeval tv{30, 0};
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
        SSL* ssl = SSL_new(m_ctx);
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, host.c_str());
        SSL_set1_host(ssl, host.c_str());
        bool ok = SSL_connect(ssl) == 1;
        if (!ok)
        {
            const unsigned long e = ERR_get_error();
            const char* why = e ? ERR_reason_error_string(e) : nullptr;
            err = "TLS to " + hostport + " failed: " + (why ? why : "the handshake did not complete");
        }
        std::string req;
        if (ok)
        {
            req = std::string(method) + " " + path + " HTTP/1.1\r\nHost: " + hostport +
                  "\r\nUser-Agent: socketley-acme\r\nAccept: */*\r\nConnection: close\r\n";
            if (!type.empty())
                req += "Content-Type: " + std::string(type) + "\r\n";
            req += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
            req += body;
            ok = SSL_write(ssl, req.data(), static_cast<int>(req.size())) == static_cast<int>(req.size());
            if (!ok)
                err = "sending to " + hostport + " failed";
        }
        std::string raw;
        while (ok)
        {
            char buf[16384];
            const int n = SSL_read(ssl, buf, sizeof buf);
            if (n <= 0)
                break;
            raw.append(buf, static_cast<size_t>(n));
        }
        SSL_free(ssl);
        ::close(fd);
        ERR_clear_error();
        return ok && parse(raw, out, err);
    }

private:
    static bool fail(std::string& err, std::string why)
    {
        err = std::move(why);
        return false;
    }
    static bool parse(const std::string& raw, reply& out, std::string& err)
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
        if (strncasecmp(out.header("transfer-encoding").c_str(), "chunked", 7) == 0)
        {
            std::string plain;
            size_t p = 0;
            while (p < body.size())
            {
                const size_t eol = body.find("\r\n", p);
                if (eol == std::string::npos)
                    break;
                const size_t n = std::strtoul(body.c_str() + p, nullptr, 16);
                if (n == 0)
                    break;
                plain.append(body, eol + 2, n);
                p = eol + 2 + n + 2;
            }
            body = std::move(plain);
        }
        out.body = std::move(body);
        return true;
    }
    SSL_CTX* m_ctx{nullptr};
};

// ─── Keys and signatures ────────────────────────────────────────────────────

EVP_PKEY* load_or_make_key(const std::string& path, std::string& err)
{
    if (BIO* b = BIO_new_file(path.c_str(), "r"))
    {
        EVP_PKEY* k = PEM_read_bio_PrivateKey(b, nullptr, nullptr, nullptr);
        BIO_free(b);
        if (k)
            return k;
        err = "the account key " + path + " does not load";
        return nullptr;
    }
    ERR_clear_error();
    EVP_PKEY* k = EVP_EC_gen("P-256");
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(path).parent_path(), ec);
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    FILE* f = fd >= 0 ? fdopen(fd, "w") : nullptr;
    const bool ok = k && f && PEM_write_PrivateKey(f, k, nullptr, nullptr, 0, nullptr, nullptr) == 1;
    if (f)
        fclose(f);
    else if (fd >= 0)
        ::close(fd);
    if (!ok)
    {
        err = "the account key " + path + " could not be written";
        if (k)
            EVP_PKEY_free(k);
        return nullptr;
    }
    return k;
}

std::string pem_of_key(EVP_PKEY* k)
{
    BIO* b = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(b, k, nullptr, nullptr, 0, nullptr, nullptr);
    char* p = nullptr;
    const long n = BIO_get_mem_data(b, &p);
    std::string s(p, static_cast<size_t>(n));
    BIO_free(b);
    return s;
}

// The account key's public half as RFC 7638 orders it, which is also the input to its thumbprint.
std::string jwk_of(EVP_PKEY* k)
{
    BIGNUM *x = nullptr, *y = nullptr;
    EVP_PKEY_get_bn_param(k, "qx", &x);
    EVP_PKEY_get_bn_param(k, "qy", &y);
    std::string xs(32, '\0'), ys(32, '\0');
    if (x)
        BN_bn2binpad(x, reinterpret_cast<unsigned char*>(xs.data()), 32);
    if (y)
        BN_bn2binpad(y, reinterpret_cast<unsigned char*>(ys.data()), 32);
    BN_free(x);
    BN_free(y);
    return "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + b64url(xs) + "\",\"y\":\"" + b64url(ys) + "\"}";
}

// ES256 over `input`, as JWS has it: r and s, 32 bytes each, and not DER.
std::string es256(EVP_PKEY* k, std::string_view input)
{
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    size_t n = 0;
    std::string der;
    if (EVP_DigestSignInit(md, nullptr, EVP_sha256(), nullptr, k) == 1 &&
        EVP_DigestSign(md, nullptr, &n, reinterpret_cast<const unsigned char*>(input.data()), input.size()) == 1)
    {
        der.resize(n);
        if (EVP_DigestSign(md, reinterpret_cast<unsigned char*>(der.data()), &n,
                           reinterpret_cast<const unsigned char*>(input.data()), input.size()) == 1)
            der.resize(n);
        else
            der.clear();
    }
    EVP_MD_CTX_free(md);
    const unsigned char* p = reinterpret_cast<const unsigned char*>(der.data());
    ECDSA_SIG* sig = der.empty() ? nullptr : d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der.size()));
    std::string raw(64, '\0');
    if (sig)
    {
        BN_bn2binpad(ECDSA_SIG_get0_r(sig), reinterpret_cast<unsigned char*>(raw.data()), 32);
        BN_bn2binpad(ECDSA_SIG_get0_s(sig), reinterpret_cast<unsigned char*>(raw.data()) + 32, 32);
        ECDSA_SIG_free(sig);
    }
    return raw;
}

std::string csr_der(EVP_PKEY* k, const std::vector<std::string>& names)
{
    X509_REQ* req = X509_REQ_new();
    X509_REQ_set_version(req, 0);
    X509_NAME* n = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(names.front().c_str()), -1, -1, 0);
    X509_REQ_set_pubkey(req, k);
    std::string san;
    for (const std::string& d : names)
        san += (san.empty() ? "DNS:" : ",DNS:") + d;
    STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null();
    X509_EXTENSION* e = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, san.c_str());
    sk_X509_EXTENSION_push(exts, e);
    X509_REQ_add_extensions(req, exts);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    std::string out;
    if (X509_REQ_sign(req, k, EVP_sha256()) > 0)
    {
        const int len = i2d_X509_REQ(req, nullptr);
        out.resize(static_cast<size_t>(len));
        unsigned char* p = reinterpret_cast<unsigned char*>(out.data());
        i2d_X509_REQ(req, &p);
    }
    X509_REQ_free(req);
    return out;
}

// The certificate TLS-ALPN-01 asks to be shown for `name` (RFC 8737): self-signed, the name its only SAN, and the
// key authorization's SHA-256 in the critical acmeIdentifier extension; PEM, certificate then key.
std::string alpn_cert(const std::string& name, const std::string& key_auth)
{
    EVP_PKEY* k = EVP_EC_gen("P-256");
    X509* x = X509_new();
    std::string pem;
    if (k && x)
    {
        X509_set_version(x, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
        X509_gmtime_adj(X509_getm_notBefore(x), -3600);
        X509_gmtime_adj(X509_getm_notAfter(x), 7 * 86400);
        X509_set_pubkey(x, k);
        X509_NAME* n = X509_get_subject_name(x);
        X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(name.c_str()), -1, -1, 0);
        X509_set_issuer_name(x, n);
        X509_EXTENSION* san = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, ("DNS:" + name).c_str());
        const std::string digest = sha256(key_auth);
        ASN1_OCTET_STRING* inner = ASN1_OCTET_STRING_new();
        ASN1_OCTET_STRING_set(inner, reinterpret_cast<const unsigned char*>(digest.data()), static_cast<int>(digest.size()));
        unsigned char* der = nullptr;
        const int der_len = i2d_ASN1_OCTET_STRING(inner, &der);
        ASN1_OCTET_STRING* value = ASN1_OCTET_STRING_new();
        ASN1_OCTET_STRING_set(value, der, der_len);
        ASN1_OBJECT* oid = OBJ_txt2obj("1.3.6.1.5.5.7.1.31", 1);
        X509_EXTENSION* id = X509_EXTENSION_create_by_OBJ(nullptr, oid, 1, value);
        const bool ok = san && id && X509_add_ext(x, san, -1) == 1 && X509_add_ext(x, id, -1) == 1 &&
                        X509_sign(x, k, EVP_sha256()) > 0;
        if (ok)
        {
            BIO* b = BIO_new(BIO_s_mem());
            PEM_write_bio_X509(b, x);
            PEM_write_bio_PrivateKey(b, k, nullptr, nullptr, 0, nullptr, nullptr);
            char* p = nullptr;
            const long len = BIO_get_mem_data(b, &p);
            pem.assign(p, static_cast<size_t>(len));
            BIO_free(b);
        }
        if (san) X509_EXTENSION_free(san);
        if (id) X509_EXTENSION_free(id);
        ASN1_OBJECT_free(oid);
        ASN1_OCTET_STRING_free(value);
        ASN1_OCTET_STRING_free(inner);
        OPENSSL_free(der);
    }
    if (x) X509_free(x);
    if (k) EVP_PKEY_free(k);
    ERR_clear_error();
    return pem;
}

bool write_atomic(const std::string& path, const std::string& data, mode_t mode)
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

// ─── The protocol ───────────────────────────────────────────────────────────

class client
{
public:
    client(https& h, EVP_PKEY* account) : m_h(h), m_key(account), m_jwk(jwk_of(account)) {}

    bool directory(const std::string& url, std::string& err)
    {
        reply r;
        jvalue d;
        if (!m_h.request("GET", url, {}, {}, r, err))
            return false;
        if (r.status != 200 || !json_reader(r.body).document(d))
        {
            err = "the directory " + url + " answered " + std::to_string(r.status);
            return false;
        }
        m_new_nonce = str(d, "newNonce");
        m_new_account = str(d, "newAccount");
        m_new_order = str(d, "newOrder");
        if (m_new_nonce.empty() || m_new_account.empty() || m_new_order.empty())
        {
            err = "the directory " + url + " names no newNonce, newAccount or newOrder";
            return false;
        }
        return true;
    }

    std::string thumbprint() const { return b64url(sha256(m_jwk)); }

    // A signed POST, with a fresh nonce whenever the CA says the last one was bad.
    bool post(const std::string& url, const std::string& payload, reply& r, std::string& err, bool use_jwk = false)
    {
        for (int attempt = 0; attempt < 4; ++attempt)
        {
            if (m_nonce.empty())
            {
                reply n;
                if (!m_h.request("HEAD", m_new_nonce, {}, {}, n, err))
                    return false;
                m_nonce = n.header("replay-nonce");
            }
            std::string prot = "{\"alg\":\"ES256\",\"nonce\":" + jstr(m_nonce) + ",\"url\":" + jstr(url) + ",";
            prot += use_jwk ? "\"jwk\":" + m_jwk + "}" : "\"kid\":" + jstr(m_kid) + "}";
            const std::string p64 = b64url(prot), b64 = b64url(payload);
            const std::string body = "{\"protected\":" + jstr(p64) + ",\"payload\":" + jstr(b64) + ",\"signature\":" +
                                     jstr(b64url(es256(m_key, p64 + "." + b64))) + "}";
            m_nonce.clear();
            r = reply{};
            if (!m_h.request("POST", url, "application/jose+json", body, r, err))
                return false;
            m_nonce = r.header("replay-nonce");
            if (r.status == 400 && r.body.find("urn:ietf:params:acme:error:badNonce") != std::string::npos)
                continue;
            if (r.status >= 400)
            {
                jvalue e;
                err = "the CA refused " + url + " with " + std::to_string(r.status);
                if (json_reader(r.body).document(e))
                    err += ": " + str(e, "type") + " " + str(e, "detail");
                return false;
            }
            return true;
        }
        err = "the CA kept refusing its own nonces";
        return false;
    }

    bool account(const std::string& email, std::string& err)
    {
        std::string payload = "{\"termsOfServiceAgreed\":true";
        if (!email.empty())
            payload += ",\"contact\":[" + jstr("mailto:" + email) + "]";
        payload += "}";
        reply r;
        if (!post(m_new_account, payload, r, err, true))
            return false;
        m_kid = r.header("location");
        if (m_kid.empty())
        {
            err = "the CA gave the account no URL";
            return false;
        }
        return true;
    }

    bool get(const std::string& url, reply& r, jvalue& doc, std::string& err)
    {
        if (!post(url, "", r, err))
            return false;
        if (!json_reader(r.body).document(doc))
        {
            std::string head = r.body.substr(0, 120);
            std::ranges::replace_if(head, [](unsigned char ch) { return ch < 0x20 || ch > 0x7e; }, '.');
            err = url + " answered " + std::to_string(r.status) + " with something that is not JSON: '" + head + "'";
            return false;
        }
        return true;
    }

    std::string new_order() const { return m_new_order; }

private:
    https& m_h;
    EVP_PKEY* m_key;
    std::string m_jwk, m_kid, m_nonce, m_new_nonce, m_new_account, m_new_order;
};

// Asks `url` until its status is no longer pending or processing; true when it is `want`.
bool poll(client& c, const std::string& url, std::string_view want, jvalue& doc, std::string& err)
{
    for (int i = 0; i < poll_seconds; ++i)
    {
        reply r;
        if (!c.get(url, r, doc, err))
            return false;
        const std::string st = str(doc, "status");
        if (st == want)
            return true;
        if (st != "pending" && st != "processing")
        {
            err = url + " is " + st;
            if (const jvalue* e = member(doc, "error"))
                err += ": " + str(*e, "detail");
            if (const jvalue* chs = member(doc, "challenges"))
                for (const jvalue& ch : chs->items)
                    if (const jvalue* e = member(ch, "error"))
                        err += ": " + str(*e, "detail");
            return false;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    err = url + " did not become " + std::string(want) + " in " + std::to_string(poll_seconds) + "s";
    return false;
}

int issue(int argc, char** argv)
{
    std::vector<std::string> names;
    std::string cert, key, email, challenge = "http-01";
    std::string dir = std::getenv("SOCKETLEY_ACME_DIRECTORY") && *std::getenv("SOCKETLEY_ACME_DIRECTORY")
                          ? std::getenv("SOCKETLEY_ACME_DIRECTORY")
                          : std::string(lets_encrypt);
    for (int i = 3; i < argc; ++i)
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
        if (a == "--domains" && (ok = value(v)))
        {
            for (size_t p = 0; p <= v.size();)
            {
                const size_t comma = std::min(v.find(',', p), v.size());
                if (comma > p)
                    names.push_back(v.substr(p, comma - p));
                p = comma + 1;
            }
        }
        else if (a == "--cert")
            ok = value(cert);
        else if (a == "--key")
            ok = value(key);
        else if (a == "--email")
            ok = value(email);
        else if (a == "--directory")
            ok = value(dir);
        else if (a == "--challenge")
            ok = value(challenge) && (challenge == "http-01" || challenge == "tls-alpn-01");
        else
            ok = false;
        if (!ok)
        {
            std::cout << "acme issue: unknown or incomplete option " << a << "\n";
            return 1;
        }
    }
    if (names.empty())
    {
        std::cout << "usage: socketley acme issue --domains name[,name...] [--cert file] [--key file] [--email addr] "
                     "[--directory url] [--challenge http-01|tls-alpn-01]\n";
        return 1;
    }
    if (cert.empty())
        cert = cert_keeper::acme_cert_path(names.front());
    if (key.empty())
        key = cert_keeper::acme_key_path(names.front());
    const std::string challenges = cert_keeper::challenge_dir();
    const std::string account_path = std::filesystem::path(challenges).parent_path().string() + "/account-" +
                                     b64url(sha256(dir)).substr(0, 12) + ".key";
    std::error_code ec;
    std::filesystem::create_directories(challenges, ec);

    // One issuance per account at a time, so two runtimes renewing at once do not race for the account's key.
    const int lock = ::open((account_path + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock >= 0 && ::flock(lock, LOCK_EX) != 0) {}

    std::string err;
    https h;
    EVP_PKEY* account = h.init(err) ? load_or_make_key(account_path, err) : nullptr;
    if (!account)
    {
        std::cout << "acme: " << err << "\n";
        return 2;
    }
    client c(h, account);
    std::vector<std::string> written;
    auto done = [&](int rc) {
        for (const std::string& f : written)
            ::unlink(f.c_str());
        EVP_PKEY_free(account);
        if (lock >= 0)
            ::close(lock);
        if (rc != 0)
            std::cout << "acme: " << err << "\n";
        return rc;
    };
    if (!c.directory(dir, err) || !c.account(email, err))
        return done(2);

    std::string ids;
    for (const std::string& n : names)
        ids += (ids.empty() ? "" : ",") + std::string("{\"type\":\"dns\",\"value\":") + jstr(n) + "}";
    reply r;
    jvalue order;
    if (!c.post(c.new_order(), "{\"identifiers\":[" + ids + "]}", r, err) || !json_reader(r.body).document(order))
        return done(2);
    const std::string order_url = r.header("location");
    const std::string thumb = c.thumbprint();

    // Every authorization's HTTP-01 answer is put where the runtimes serve it, and then the CA is told to look.
    if (const jvalue* authz = member(order, "authorizations"))
        for (const jvalue& au : authz->items)
        {
            jvalue a;
            if (!c.get(au.s, r, a, err))
                return done(2);
            if (str(a, "status") == "valid")
                continue;
            std::string token, url;
            if (const jvalue* chs = member(a, "challenges"))
                for (const jvalue& ch : chs->items)
                    if (str(ch, "type") == challenge)
                    {
                        token = str(ch, "token");
                        url = str(ch, "url");
                    }
            const std::string ident = member(a, "identifier") ? str(*member(a, "identifier"), "value") : std::string{};
            if (token.empty() || token.find('/') != std::string::npos || ident.empty())
            {
                err = "the CA offered no " + challenge + " challenge for " + (ident.empty() ? au.s : ident);
                return done(2);
            }
            // HTTP-01's answer is served as a file over HTTP, TLS-ALPN-01's as a certificate on the TLS listener.
            const bool alpn = challenge == "tls-alpn-01";
            const std::string file = alpn ? cert_keeper::tls_alpn_path(ident) : challenges + "/" + token;
            const std::string answer = alpn ? alpn_cert(ident, token + "." + thumb) : token + "." + thumb;
            if (answer.empty() || !write_atomic(file, answer, alpn ? 0600 : 0644))
            {
                err = "the challenge could not be written to " + file;
                return done(2);
            }
            written.push_back(file);
            jvalue ignored;
            if (!c.post(url, "{}", r, err) || !poll(c, au.s, "valid", ignored, err))
                return done(2);
        }

    EVP_PKEY* cert_key = EVP_EC_gen("P-256");
    const std::string csr = cert_key ? csr_der(cert_key, names) : std::string{};
    if (csr.empty())
    {
        err = "no certificate request could be made";
        if (cert_key)
            EVP_PKEY_free(cert_key);
        return done(2);
    }
    jvalue fin;
    if (!c.post(str(order, "finalize"), "{\"csr\":" + jstr(b64url(csr)) + "}", r, err) ||
        !poll(c, order_url, "valid", fin, err))
    {
        EVP_PKEY_free(cert_key);
        return done(2);
    }
    reply chain;
    if (!c.post(str(fin, "certificate"), "", chain, err) || chain.body.find("-----BEGIN CERTIFICATE-----") == std::string::npos)
    {
        if (err.empty())
            err = "the CA's certificate is not PEM";
        EVP_PKEY_free(cert_key);
        return done(2);
    }
    // The key before the chain, so a runtime that sees the new certificate finds its key already there.
    const bool ok = write_atomic(key, pem_of_key(cert_key), 0600) && write_atomic(cert, chain.body, 0644);
    EVP_PKEY_free(cert_key);
    if (!ok)
    {
        err = "the certificate could not be written to " + cert + " and " + key;
        return done(2);
    }
    return done(0);
}

}   // namespace

int acme_main(int argc, char** argv)
{
    if (argc >= 3 && std::string_view(argv[2]) == "issue")
        return issue(argc, argv);
    std::cout << "usage: socketley acme issue --domains name[,name...] [--cert file] [--key file] [--email addr] "
                 "[--directory url] [--challenge http-01|tls-alpn-01]\n";
    return 1;
}
