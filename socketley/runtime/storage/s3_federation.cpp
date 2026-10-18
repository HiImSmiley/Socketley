#include "s3_federation.h"
#include "../../shared/util/logging.h"
#include "../../shared/crypto/tls_context.h"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstring>

#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "../../shared/json/json_doc.h"
#include "outbound_http.h"
#include "s3_names.h"
#include "../../shared/util/base64.h"

using socketley::json::jvalue;
using socketley::json::json_reader;

namespace socketley::storage
{

namespace
{

std::string_view trim_ws(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t'))
        s.remove_suffix(1);
    return s;
}

// The string member `name`, empty when it is absent, false when it is there and not a string.
bool string_member(const jvalue& o, std::string_view name, std::string& out)
{
    out.clear();
    const jvalue* v = member(o, name);
    if (!v)
        return true;
    if (v->k != jvalue::kind::string)
        return false;
    out = v->s;
    return true;
}

// ---- JWS ----

enum class alg_family : uint8_t { rsa, pss, ec };

struct alg_spec
{
    std::string_view name;
    alg_family       family;
    const char*      md;
    // An EC algorithm's curve and the bytes of each of r and s.
    std::string_view crv;
    size_t           coord;
};

// The algorithms a token may be signed with: no "none", and no HMAC, whose key would be the public one.
constexpr alg_spec algs[] = {
    {"RS256", alg_family::rsa, "SHA256", {}, 0},
    {"RS384", alg_family::rsa, "SHA384", {}, 0},
    {"RS512", alg_family::rsa, "SHA512", {}, 0},
    {"PS256", alg_family::pss, "SHA256", {}, 0},
    {"ES256", alg_family::ec, "SHA256", "P-256", 32},
    {"ES384", alg_family::ec, "SHA384", "P-384", 48},
};

const alg_spec* find_alg(std::string_view name)
{
    for (const alg_spec& a : algs)
        if (a.name == name)
            return &a;
    return nullptr;
}

std::string_view kty_of(const alg_spec& a)
{
    return a.family == alg_family::ec ? "EC" : "RSA";
}

// Whether key `k` may verify a signature by `a`.
bool key_fits(const jwk& k, const alg_spec& a)
{
    if (k.kty != kty_of(a) || (!k.alg.empty() && k.alg != a.name))
        return false;
    return a.family != alg_family::ec || k.crv == a.crv;
}

const unsigned char* bytes(std::string_view s)
{
    return reinterpret_cast<const unsigned char*>(s.data());
}

struct pkey_ctx_free
{
    void operator()(EVP_PKEY_CTX* c) const { EVP_PKEY_CTX_free(c); }
};
struct param_bld_free
{
    void operator()(OSSL_PARAM_BLD* b) const { OSSL_PARAM_BLD_free(b); }
};
struct params_free
{
    void operator()(OSSL_PARAM* p) const { OSSL_PARAM_free(p); }
};
struct bn_free
{
    void operator()(BIGNUM* b) const { BN_free(b); }
};
struct md_ctx_free
{
    void operator()(EVP_MD_CTX* c) const { EVP_MD_CTX_free(c); }
};

// A public key of type `type` built from `params`, null when OpenSSL takes no such key or it fails its public check.
EVP_PKEY* key_from(const char* type, OSSL_PARAM_BLD* bld)
{
    std::unique_ptr<OSSL_PARAM, params_free> params(OSSL_PARAM_BLD_to_param(bld));
    std::unique_ptr<EVP_PKEY_CTX, pkey_ctx_free> ctx(EVP_PKEY_CTX_new_from_name(nullptr, type, nullptr));
    EVP_PKEY* key = nullptr;
    if (!params || !ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1 ||
        EVP_PKEY_fromdata(ctx.get(), &key, EVP_PKEY_PUBLIC_KEY, params.get()) != 1)
        return nullptr;
    std::unique_ptr<EVP_PKEY_CTX, pkey_ctx_free> check(EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr));
    if (!check || EVP_PKEY_public_check(check.get()) != 1)
    {
        EVP_PKEY_free(key);
        return nullptr;
    }
    return key;
}

EVP_PKEY* rsa_key(std::string_view n, std::string_view e)
{
    std::unique_ptr<BIGNUM, bn_free> bn_n(BN_bin2bn(bytes(n), static_cast<int>(n.size()), nullptr));
    std::unique_ptr<BIGNUM, bn_free> bn_e(BN_bin2bn(bytes(e), static_cast<int>(e.size()), nullptr));
    std::unique_ptr<OSSL_PARAM_BLD, param_bld_free> bld(OSSL_PARAM_BLD_new());
    if (!bn_n || !bn_e || !bld || OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_N, bn_n.get()) != 1 ||
        OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_E, bn_e.get()) != 1)
        return nullptr;
    EVP_PKEY* key = key_from("RSA", bld.get());
    // A key below 2048 bits is one RFC 7518 forbids for RS and PS.
    if (key && EVP_PKEY_get_bits(key) < 2048)
    {
        EVP_PKEY_free(key);
        return nullptr;
    }
    return key;
}

EVP_PKEY* ec_key(std::string_view crv, std::string_view x, std::string_view y)
{
    const char* group = crv == "P-256" ? "prime256v1" : "secp384r1";
    // The uncompressed point, 0x04 and the two coordinates.
    std::string point;
    point.reserve(1 + x.size() + y.size());
    point.push_back('\x04');
    point.append(x);
    point.append(y);
    std::unique_ptr<OSSL_PARAM_BLD, param_bld_free> bld(OSSL_PARAM_BLD_new());
    if (!bld || OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, group, 0) != 1 ||
        OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, point.data(), point.size()) != 1)
        return nullptr;
    return key_from("EC", bld.get());
}

// One member of a JWK Set as a key verified with here, false for one skipped.
bool parse_jwk(const jvalue& v, jwk& out)
{
    std::string use, n, e, x, y;
    if (v.k != jvalue::kind::object || !string_member(v, "kty", out.kty) || !string_member(v, "kid", out.kid) ||
        !string_member(v, "alg", out.alg) || !string_member(v, "use", use) || (!use.empty() && use != "sig"))
        return false;
    // A key whose key_ops are given is used only for what they name.
    if (const jvalue* ops = member(v, "key_ops"))
    {
        if (ops->k != jvalue::kind::array ||
            std::none_of(ops->items.begin(), ops->items.end(),
                         [](const jvalue& o) { return o.k == jvalue::kind::string && o.s == "verify"; }))
            return false;
    }
    if (!out.alg.empty())
    {
        const alg_spec* a = find_alg(out.alg);
        if (!a || kty_of(*a) != out.kty)
            return false;
    }
    EVP_PKEY* key = nullptr;
    if (out.kty == "RSA")
    {
        std::string raw_n, raw_e;
        if (!string_member(v, "n", n) || !string_member(v, "e", e) || !base64url::decode(n, raw_n) ||
            !base64url::decode(e, raw_e) || raw_n.empty() || raw_e.empty() || raw_e.size() > 8 ||
            raw_n.size() > 2048)
            return false;
        key = rsa_key(raw_n, raw_e);
    }
    else if (out.kty == "EC")
    {
        if (!string_member(v, "crv", out.crv) || (out.crv != "P-256" && out.crv != "P-384"))
            return false;
        const size_t coord = out.crv == "P-256" ? 32 : 48;
        std::string rx, ry;
        if (!string_member(v, "x", x) || !string_member(v, "y", y) || !base64url::decode(x, rx) ||
            !base64url::decode(y, ry) || rx.size() != coord || ry.size() != coord)
            return false;
        if (!out.alg.empty() && find_alg(out.alg)->crv != out.crv)
            return false;
        key = ec_key(out.crv, rx, ry);
    }
    if (!key)
        return false;
    out.key.reset(key);
    return true;
}

// The key of `keys` that verifies a token by `a` naming `kid`, null when there is no one key it can be.
const jwk* pick_key(const jwks_keys& keys, const alg_spec& a, const std::string* kid)
{
    const jwk* only = nullptr;
    size_t fitting = 0;
    for (const jwk& k : keys.keys)
    {
        if (!key_fits(k, a))
            continue;
        if (kid && !k.kid.empty() && k.kid == *kid)
            return &k;
        ++fitting;
        only = &k;
    }
    // A token or a key without a kid takes the key that is the only one of its type.
    if (fitting != 1 || (kid && !only->kid.empty()))
        return nullptr;
    return only;
}

bool verify_signature(const alg_spec& a, EVP_PKEY* key, std::string_view input, std::string_view sig)
{
    std::string der;
    if (a.family == alg_family::ec)
    {
        if (!jws_ecdsa_to_der(sig, a.coord, der))
            return false;
        sig = der;
    }
    std::unique_ptr<EVP_MD_CTX, md_ctx_free> ctx(EVP_MD_CTX_new());
    EVP_PKEY_CTX* pctx = nullptr;
    if (!ctx || EVP_DigestVerifyInit_ex(ctx.get(), &pctx, a.md, nullptr, nullptr, key, nullptr) != 1)
        return false;
    if (a.family == alg_family::rsa && EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0)
        return false;
    // RFC 7518: PSS with MGF1 of the same hash and a salt as long as the hash.
    if (a.family == alg_family::pss && (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
                                        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0))
        return false;
    const int rc = EVP_DigestVerify(ctx.get(), bytes(sig), sig.size(), bytes(input), input.size());
    ERR_clear_error();
    return rc == 1;
}

// A NumericDate, whole seconds of a fractional one.
bool numeric_date(const jvalue& v, int64_t& out)
{
    if (v.k != jvalue::kind::number)
        return false;
    double d = 0;
    const auto res = std::from_chars(v.s.data(), v.s.data() + v.s.size(), d);
    if (res.ec != std::errc{} || res.ptr != v.s.data() + v.s.size() || !std::isfinite(d) || d < 0 || d > 1e13)
        return false;
    out = static_cast<int64_t>(d);
    return true;
}

// The names in a claim: a comma-separated string or an array of strings, trimmed, without repeats.
bool claim_names(const jvalue& v, std::vector<std::string>& out)
{
    auto add = [&out](std::string_view name)
    {
        name = trim_ws(name);
        if (!name.empty() && std::find(out.begin(), out.end(), name) == out.end())
            out.emplace_back(name);
    };
    auto split = [&add](std::string_view s)
    {
        while (!s.empty())
        {
            const size_t comma = s.find(',');
            add(s.substr(0, comma));
            s = comma == std::string_view::npos ? std::string_view{} : s.substr(comma + 1);
        }
    };
    if (v.k == jvalue::kind::string)
        split(v.s);
    else if (v.k == jvalue::kind::array)
    {
        for (const jvalue& item : v.items)
        {
            if (item.k != jvalue::kind::string)
                return false;
            split(item.s);
        }
    }
    else
        return false;
    return out.size() <= 64;
}

// ---- BER ----

void ber_length(std::string& out, size_t n)
{
    if (n < 0x80)
    {
        out.push_back(static_cast<char>(n));
        return;
    }
    char buf[sizeof(size_t)];
    size_t k = 0;
    while (n)
    {
        buf[k++] = static_cast<char>(n & 0xFF);
        n >>= 8;
    }
    out.push_back(static_cast<char>(0x80 | k));
    while (k)
        out.push_back(buf[--k]);
}

void ber_tlv(std::string& out, uint8_t tag, std::string_view value)
{
    out.push_back(static_cast<char>(tag));
    ber_length(out, value.size());
    out.append(value);
}

// A non-negative INTEGER's contents, the fewest bytes with the sign bit clear.
std::string ber_uint(uint32_t v)
{
    std::string out;
    do
    {
        out.insert(out.begin(), static_cast<char>(v & 0xFF));
        v >>= 8;
    } while (v);
    if (static_cast<uint8_t>(out.front()) & 0x80)
        out.insert(out.begin(), '\0');
    return out;
}

// One element at the front of `in`, taken off it; false for one not whole, not definite or of a high tag number.
bool ber_take(std::string_view& in, uint8_t& tag, std::string_view& content)
{
    if (in.size() < 2)
        return false;
    tag = static_cast<uint8_t>(in[0]);
    if ((tag & 0x1F) == 0x1F)
        return false;
    size_t len = static_cast<uint8_t>(in[1]);
    size_t at  = 2;
    if (len & 0x80)
    {
        const size_t n = len & 0x7F;
        if (n == 0 || n > 4 || in.size() < 2 + n)
            return false;
        len = 0;
        for (size_t i = 0; i < n; ++i)
            len = (len << 8) | static_cast<uint8_t>(in[2 + i]);
        at += n;
    }
    if (in.size() - at < len)
        return false;
    content = in.substr(at, len);
    in.remove_prefix(at + len);
    return true;
}

// An INTEGER or ENUMERATED's contents as a value from 0 to INT32_MAX.
bool ber_read_uint(std::string_view c, int32_t& out)
{
    if (c.empty() || c.size() > 5 || (static_cast<uint8_t>(c[0]) & 0x80))
        return false;
    int64_t v = 0;
    for (char ch : c)
        v = (v << 8) | static_cast<uint8_t>(ch);
    if (v > INT32_MAX)
        return false;
    out = static_cast<int32_t>(v);
    return true;
}

// ---- the LDAP connection ----

// One blocking exchange with an LDAP server, plain or TLS, every wait bounded by one deadline.
class ldap_link
{
public:
    ldap_link(std::chrono::steady_clock::time_point deadline, int timeout_ms)
        : m_deadline(deadline), m_timeout_ms(timeout_ms)
    {
    }
    ~ldap_link()
    {
        if (m_ssl)
            SSL_free(m_ssl);
        if (m_ctx)
            SSL_CTX_free(m_ctx);
        if (m_fd >= 0)
            ::close(m_fd);
    }
    ldap_link(const ldap_link&)            = delete;
    ldap_link& operator=(const ldap_link&) = delete;

    bool connect(const federation_ldap& cfg, std::string& why)
    {
        struct addrinfo hints{};
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags    = AI_NUMERICSERV;
        struct addrinfo* res = nullptr;
        const std::string port = std::to_string(cfg.port);
        if (const int rc = ::getaddrinfo(cfg.host.c_str(), port.c_str(), &hints, &res); rc != 0)
        {
            why = "cannot resolve the LDAP host " + cfg.host + ": " + ::gai_strerror(rc);
            return false;
        }
        why = "the LDAP host " + cfg.host + " has no address";
        for (struct addrinfo* ai = res; ai && m_fd < 0; ai = ai->ai_next)
        {
            const int fd = ::socket(ai->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (fd < 0)
            {
                why = std::string("cannot open a socket: ") + std::strerror(errno);
                continue;
            }
            m_fd = fd;
            int err = 0;
            if (::connect(fd, ai->ai_addr, ai->ai_addrlen) != 0)
            {
                err = errno;
                if (err == EINPROGRESS && wait(POLLOUT, why))
                {
                    socklen_t len = sizeof err;
                    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0)
                        err = errno;
                }
                else if (err == EINPROGRESS)
                    err = ETIMEDOUT;
            }
            if (err != 0)
            {
                why = "cannot connect to the LDAP server " + cfg.host + ":" + port + ": " + std::strerror(err);
                ::close(fd);
                m_fd = -1;
            }
        }
        ::freeaddrinfo(res);
        if (m_fd < 0)
            return false;
        why.clear();
        return !cfg.tls || handshake(cfg, why);
    }

    bool send_all(std::string_view data, std::string& why)
    {
        while (!data.empty())
        {
            if (m_ssl)
            {
                size_t n = 0;
                const int rc = SSL_write_ex(m_ssl, data.data(), data.size(), &n);
                if (rc == 1)
                {
                    data.remove_prefix(n);
                    continue;
                }
                if (!ssl_wait(rc, why))
                    return false;
                continue;
            }
            const ssize_t n = ::send(m_fd, data.data(), data.size(), MSG_NOSIGNAL);
            if (n > 0)
            {
                data.remove_prefix(static_cast<size_t>(n));
                continue;
            }
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            {
                if (!wait(POLLOUT, why))
                    return false;
                continue;
            }
            why = std::string("cannot write to the LDAP server: ") + std::strerror(errno);
            return false;
        }
        return true;
    }

    // The next whole LDAP message the server sends.
    bool read_message(std::string& msg, std::string& why)
    {
        for (;;)
        {
            size_t total = 0;
            const int framed = ldap_message_size(m_in, total);
            if (framed < 0)
            {
                why = "the LDAP server's answer is not an LDAP message";
                return false;
            }
            if (framed > 0)
            {
                msg = m_in.substr(0, total);
                m_in.erase(0, total);
                return true;
            }
            char buf[4096];
            if (m_ssl)
            {
                size_t n = 0;
                const int rc = SSL_read_ex(m_ssl, buf, sizeof buf, &n);
                if (rc == 1)
                {
                    m_in.append(buf, n);
                    continue;
                }
                if (SSL_get_error(m_ssl, rc) == SSL_ERROR_ZERO_RETURN)
                {
                    why = "the LDAP server closed the connection without answering";
                    return false;
                }
                if (!ssl_wait(rc, why))
                    return false;
                continue;
            }
            const ssize_t n = ::recv(m_fd, buf, sizeof buf, 0);
            if (n > 0)
            {
                m_in.append(buf, static_cast<size_t>(n));
                continue;
            }
            if (n == 0)
            {
                why = "the LDAP server closed the connection without answering";
                return false;
            }
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                if (!wait(POLLIN, why))
                    return false;
                continue;
            }
            why = std::string("cannot read from the LDAP server: ") + std::strerror(errno);
            return false;
        }
    }

private:
    bool handshake(const federation_ldap& cfg, std::string& why)
    {
        m_ctx = tls_context::make_client_ctx(cfg.ca_file, why);
        if (!m_ctx)
            return false;
        m_ssl = SSL_new(m_ctx);
        if (!m_ssl || SSL_set_fd(m_ssl, m_fd) != 1)
        {
            why = "cannot make a TLS connection";
            return false;
        }
        if (!tls_context::pin_peer_name(m_ssl, cfg.host))
        {
            why = "cannot pin the LDAP server's name " + cfg.host;
            return false;
        }
        for (;;)
        {
            const int rc = SSL_connect(m_ssl);
            if (rc == 1)
                return true;
            const int e = SSL_get_error(m_ssl, rc);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
            {
                const long vr = SSL_get_verify_result(m_ssl);
                why = "the TLS handshake with the LDAP server " + cfg.host + " failed";
                if (vr != X509_V_OK)
                    why += std::string(": ") + X509_verify_cert_error_string(vr);
                ERR_clear_error();
                return false;
            }
            if (!wait(e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, why))
                return false;
        }
    }

    // After a TLS call returned `rc`, waits for what it wants; false for an error or the deadline.
    bool ssl_wait(int rc, std::string& why)
    {
        const int e = SSL_get_error(m_ssl, rc);
        if (e == SSL_ERROR_WANT_READ)
            return wait(POLLIN, why);
        if (e == SSL_ERROR_WANT_WRITE)
            return wait(POLLOUT, why);
        ERR_clear_error();
        why = "the TLS connection to the LDAP server failed";
        return false;
    }

    bool wait(short events, std::string& why)
    {
        for (;;)
        {
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                m_deadline - std::chrono::steady_clock::now()).count();
            if (left <= 0)
                break;
            struct pollfd p{m_fd, events, 0};
            const int rc = ::poll(&p, 1, static_cast<int>(left));
            if (rc > 0)
                return true;
            if (rc < 0 && errno != EINTR)
            {
                why = std::string("cannot wait for the LDAP server: ") + std::strerror(errno);
                return false;
            }
        }
        why = "the LDAP server did not answer within " + std::to_string(m_timeout_ms) + " ms";
        return false;
    }

    std::chrono::steady_clock::time_point m_deadline;
    int         m_timeout_ms;
    int         m_fd{-1};
    SSL_CTX*    m_ctx{nullptr};
    SSL*        m_ssl{nullptr};
    std::string m_in;
};

bool parse_ldap_url(std::string_view url, federation_ldap& l, std::string& why)
{
    std::string_view rest;
    l.tls = url.starts_with("ldaps://");
    if (l.tls || url.starts_with("ldap://"))
        rest = url.substr(l.tls ? 8 : 7);
    else
    {
        why = "an LDAP URL is ldap://host[:port] or ldaps://host[:port]";
        return false;
    }
    if (rest.ends_with('/'))
        rest.remove_suffix(1);
    if (rest.find_first_of("/?#@") != std::string_view::npos)
    {
        why = "an LDAP URL names a host and a port and nothing else";
        return false;
    }
    std::string_view host = rest, port;
    if (rest.starts_with('['))
    {
        const size_t close = rest.find(']');
        if (close == std::string_view::npos || (close + 1 < rest.size() && rest[close + 1] != ':'))
        {
            why = "an IPv6 LDAP host is [address] or [address]:port";
            return false;
        }
        host = rest.substr(1, close - 1);
        if (close + 1 < rest.size())
            port = rest.substr(close + 2);
    }
    else if (const size_t colon = rest.rfind(':'); colon != std::string_view::npos)
    {
        host = rest.substr(0, colon);
        port = rest.substr(colon + 1);
        if (host.find(':') != std::string_view::npos)
        {
            why = "an IPv6 LDAP host goes in brackets";
            return false;
        }
    }
    l.port = l.tls ? 636 : 389;
    if (!port.empty() || rest.ends_with(':'))
    {
        unsigned v = 0;
        const auto res = std::from_chars(port.data(), port.data() + port.size(), v);
        if (res.ec != std::errc{} || res.ptr != port.data() + port.size() || v == 0 || v > 65535)
        {
            why = "an LDAP URL's port is 1 to 65535";
            return false;
        }
        l.port = static_cast<uint16_t>(v);
    }
    if (host.empty())
    {
        why = "an LDAP URL names a host";
        return false;
    }
    l.host = std::string(host);
    return true;
}

}   // namespace

// ---- the provider file ----

bool federation_user_name(std::string_view id)
{
    if (id.empty() || id.size() > 128)
        return false;
    for (unsigned char c : id)
        if (c <= ' ' || c >= 0x7f || c == '/' || c == ':' || c == '*' || c == '?' || c == ',' || c == '=' ||
            c == '[' || c == ']' || c == '"' || c == '<' || c == '>' || c == '&')
            return false;
    return true;
}

bool parse_federation(std::string_view text, federation_config& out, std::string& why, std::string_view dir)
{
    out = federation_config{};
    bool any_oidc = false, any_ldap = false, claim_set = false;
    auto path_in = [dir](std::string_view p)
    {
        if (p.starts_with('/') || dir.empty())
            return std::string(p);
        return std::string(dir) + "/" + std::string(p);
    };
    for (const target_line& line : split_target_lines(text))
    {
        const auto& f = line.fields;
        const std::string where = "line " + std::to_string(line.line_no) + ": ";
        auto once = [&](std::string& slot, std::string value, bool taken) -> bool
        {
            if (taken)
            {
                why = where + "`" + std::string(f[0]) + " " + std::string(f[1]) + "` is given twice";
                return false;
            }
            slot = std::move(value);
            return true;
        };
        if (f[0] == "oidc")
        {
            any_oidc = true;
            if (f.size() != 3)
            {
                why = where + "an oidc line is `oidc issuer|client|jwks|claim <value>`";
                return false;
            }
            if (f[1] == "issuer")
            {
                if (!once(out.oidc.issuer, std::string(f[2]), !out.oidc.issuer.empty()))
                    return false;
            }
            else if (f[1] == "client")
            {
                if (std::find(out.oidc.clients.begin(), out.oidc.clients.end(), f[2]) != out.oidc.clients.end())
                {
                    why = where + "the client " + std::string(f[2]) + " is given twice";
                    return false;
                }
                out.oidc.clients.emplace_back(f[2]);
            }
            else if (f[1] == "jwks")
            {
                if (!once(out.oidc.jwks_path, path_in(f[2]), !out.oidc.jwks_path.empty()))
                    return false;
            }
            else if (f[1] == "claim")
            {
                if (f[2].size() > 256)
                {
                    why = where + "a claim's name is at most 256 bytes";
                    return false;
                }
                if (!once(out.oidc.claim, std::string(f[2]), claim_set))
                    return false;
                claim_set = true;
            }
            else
            {
                why = where + "an oidc line is `oidc issuer|client|jwks|claim <value>`";
                return false;
            }
        }
        else if (f[0] == "ldap")
        {
            any_ldap = true;
            if (f.size() >= 3 && f[1] == "url")
            {
                if (f.size() > 4 || (f.size() == 4 && !f[3].starts_with("ca=")))
                {
                    why = where + "an ldap url line is `ldap url <ldap://host[:port]|ldaps://host[:port]> [ca=<file>]`";
                    return false;
                }
                if (out.ldap.enabled())
                {
                    why = where + "`ldap url` is given twice";
                    return false;
                }
                if (std::string err; !parse_ldap_url(f[2], out.ldap, err))
                {
                    why = where + err;
                    return false;
                }
                if (f.size() == 4)
                {
                    if (!out.ldap.tls || f[3].size() == 3)
                    {
                        why = where + "ca=<file> is for an ldaps:// server";
                        return false;
                    }
                    out.ldap.ca_file = path_in(f[3].substr(3));
                }
            }
            else if (f.size() >= 3 && f[1] == "dn")
            {
                // The template runs to the end of the line, as a DN may hold spaces.
                const auto tpl_len = static_cast<size_t>(f.back().data() + f.back().size() - f[2].data());
                const std::string_view tpl(f[2].data(), tpl_len);
                const size_t at = tpl.find("%s");
                if (at == std::string_view::npos || tpl.find('%', at + 2) != std::string_view::npos ||
                    tpl.substr(0, at).find('%') != std::string_view::npos || tpl.size() > 1024)
                {
                    why = where + "an ldap dn line is `ldap dn <template>` with one %s where the username goes";
                    return false;
                }
                if (!once(out.ldap.dn_template, std::string(tpl), !out.ldap.dn_template.empty()))
                    return false;
            }
            else if (f.size() == 4 && f[1] == "user")
            {
                if (f[2].size() > 256 || (f[3] != "=" && !federation_user_name(f[3])))
                {
                    why = where + "an ldap user line is `ldap user <ldap username|*> <user|=>`, a user as the "
                                  "credentials file names it";
                    return false;
                }
                for (const federation_ldap_map& m : out.ldap.users)
                    if (m.ldap_user == f[2])
                    {
                        why = where + "the LDAP user " + std::string(f[2]) + " is mapped twice";
                        return false;
                    }
                out.ldap.users.push_back({std::string(f[2]), std::string(f[3])});
            }
            else
            {
                why = where + "an ldap line is `ldap url <url> [ca=<file>]`, `ldap dn <template>` or "
                              "`ldap user <ldap username|*> <user|=>`";
                return false;
            }
        }
        else if (f[0] == "role")
        {
            if (f.size() != 3 || f[1].size() > 2048 || !federation_user_name(f[2]))
            {
                why = where + "a role line is `role <arn> <user>`, a user as the credentials file names it";
                return false;
            }
            for (const federation_role& r : out.roles)
                if (r.arn == f[1])
                {
                    why = where + "the role " + std::string(f[1]) + " is mapped twice";
                    return false;
                }
            out.roles.push_back({std::string(f[1]), std::string(f[2])});
        }
        else
        {
            why = where + "a line begins with oidc, ldap or role";
            return false;
        }
    }
    if (any_oidc && (out.oidc.issuer.empty() || out.oidc.clients.empty() || out.oidc.jwks_path.empty()))
    {
        why = "an OIDC provider needs `oidc issuer`, `oidc client` and `oidc jwks`";
        return false;
    }
    if (any_ldap && (!out.ldap.enabled() || out.ldap.dn_template.empty() || out.ldap.users.empty()))
    {
        why = "an LDAP provider needs `ldap url`, `ldap dn` and at least one `ldap user`";
        return false;
    }
    if (!out.roles.empty() && !any_oidc)
    {
        why = "role lines map web identities, and no OIDC provider is configured";
        return false;
    }
    if (!any_oidc && !any_ldap)
    {
        why = "the file configures no OIDC and no LDAP provider";
        return false;
    }
    return true;
}

bool load_federation(const std::string& path, federation_config& out, std::string& why)
{
    std::string text;
    if (!read_targets_file(path, "federation", text, why))
        return false;
    const size_t slash = path.rfind('/');
    const std::string dir = slash == std::string::npos ? std::string(".") : path.substr(0, slash ? slash : 1);
    if (!parse_federation(text, out, why, dir))
    {
        why = path + ": " + why;
        return false;
    }
    // A bind carries the user's password, which ldap:// sends in the clear to anything but this machine.
    if (out.ldap.enabled() && !out.ldap.tls && out.ldap.host != "localhost" && out.ldap.host != "127.0.0.1" &&
        out.ldap.host != "::1")
        LOG_WARN(("storage: " + path + " binds to " + out.ldap.host +
                  " over ldap://, which sends every password in the clear; ldaps:// does not").c_str());
    return true;
}

// ---- OIDC ----

void evp_pkey_free::operator()(EVP_PKEY* k) const
{
    EVP_PKEY_free(k);
}


bool jws_ecdsa_to_der(std::string_view raw, size_t coord, std::string& der)
{
    der.clear();
    if (coord == 0 || raw.size() != 2 * coord)
        return false;
    BIGNUM* r = BN_bin2bn(bytes(raw), static_cast<int>(coord), nullptr);
    BIGNUM* s = BN_bin2bn(bytes(raw.substr(coord)), static_cast<int>(coord), nullptr);
    ECDSA_SIG* sig = ECDSA_SIG_new();
    if (!r || !s || !sig || ECDSA_SIG_set0(sig, r, s) != 1)
    {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(sig);
        return false;
    }
    const int len = i2d_ECDSA_SIG(sig, nullptr);
    if (len > 0)
    {
        der.resize(static_cast<size_t>(len));
        auto* p = reinterpret_cast<unsigned char*>(der.data());
        if (i2d_ECDSA_SIG(sig, &p) != len)
            der.clear();
    }
    ECDSA_SIG_free(sig);
    return !der.empty();
}

bool parse_jwks(std::string_view json, jwks_keys& out, std::string& why)
{
    out = jwks_keys{};
    jvalue doc;
    json_reader reader(json);
    const jvalue* keys = nullptr;
    if (!reader.document(doc) || !(keys = member(doc, "keys")) || keys->k != jvalue::kind::array)
    {
        why = "a JWK Set is a JSON object with a keys array";
        return false;
    }
    if (keys->items.size() > 100)
    {
        why = "a JWK Set holds at most 100 keys";
        return false;
    }
    for (const jvalue& v : keys->items)
    {
        jwk k;
        if (parse_jwk(v, k))
            out.keys.push_back(std::move(k));
        else
            ++out.skipped;
    }
    ERR_clear_error();
    if (out.keys.empty())
    {
        why = "the JWK Set has no RSA key of 2048 bits or more and no EC P-256 or P-384 key to verify signatures with";
        return false;
    }
    return true;
}

const jwks_keys* jwks_file::current(std::string& why)
{
    struct stat st{};
    if (::stat(m_path.c_str(), &st) != 0)
    {
        if (m_loaded)
            return &m_keys;
        why = "cannot read the JWKS file " + m_path + ": " + std::strerror(errno);
        return nullptr;
    }
    const stamp now{static_cast<int64_t>(st.st_mtim.tv_sec) * 1'000'000'000 + st.st_mtim.tv_nsec,
                    static_cast<uint64_t>(st.st_size), static_cast<uint64_t>(st.st_ino)};
    if ((m_loaded && now == m_good) || (m_have_bad && now == m_bad))
    {
        if (m_loaded)
            return &m_keys;
        why = "the JWKS file " + m_path + " has no key to verify with";
        return nullptr;
    }
    std::string text;
    jwks_keys fresh;
    const bool read = read_targets_file(m_path, "JWKS", text, why);
    if (!read || !parse_jwks(text, fresh, why))
    {
        m_bad      = now;
        m_have_bad = true;
        if (m_loaded)
        {
            why.clear();
            return &m_keys;
        }
        if (read)
            why = "the JWKS file " + m_path + ": " + why;
        return nullptr;
    }
    m_keys     = std::move(fresh);
    m_good     = now;
    m_loaded   = true;
    m_have_bad = false;
    return &m_keys;
}

bool oidc_verify(const federation_oidc& cfg, const jwks_keys& keys, std::string_view token, int64_t now,
                 oidc_identity& out, std::string& why)
{
    out = oidc_identity{};
    if (token.size() > jwt_max_bytes)
    {
        why = "the token is longer than " + std::to_string(jwt_max_bytes) + " bytes";
        return false;
    }
    const size_t d1 = token.find('.');
    const size_t d2 = d1 == std::string_view::npos ? d1 : token.find('.', d1 + 1);
    if (d2 == std::string_view::npos || token.find('.', d2 + 1) != std::string_view::npos)
    {
        why = "the token is not a JWS of three parts";
        return false;
    }
    std::string head_text, body_text, sig;
    jvalue head, body;
    if (!base64url::decode(token.substr(0, d1), head_text) ||
        !base64url::decode(token.substr(d1 + 1, d2 - d1 - 1), body_text) ||
        !base64url::decode(token.substr(d2 + 1), sig))
    {
        why = "the token is not base64url";
        return false;
    }
    json_reader head_reader(head_text);
    json_reader body_reader(body_text);
    if (!head_reader.document(head) || !body_reader.document(body))
    {
        why = "the token's header or claims are not a JSON object";
        return false;
    }
    std::string alg, kid;
    if (!string_member(head, "alg", alg) || !string_member(head, "kid", kid))
    {
        why = "the token's alg or kid is not a string";
        return false;
    }
    const alg_spec* a = find_alg(alg);
    if (!a)
    {
        why = "the token's alg \"" + alg + "\" is not one of RS256, RS384, RS512, PS256, ES256 and ES384";
        return false;
    }
    // An extension the token says must be understood is one this verifier does not.
    if (member(head, "crit"))
    {
        why = "the token names critical header parameters";
        return false;
    }
    const bool has_kid = member(head, "kid") != nullptr;
    const jwk* key = pick_key(keys, *a, has_kid ? &kid : nullptr);
    if (!key)
    {
        why = has_kid ? "no key of the JWK Set has kid \"" + kid + "\" for " + alg
                      : "the token names no kid, and the JWK Set has not exactly one key for " + alg;
        return false;
    }
    if (!verify_signature(*a, key->key.get(), token.substr(0, d2), sig))
    {
        why = "the token's signature does not verify";
        return false;
    }

    if (!string_member(body, "iss", out.issuer) || out.issuer != cfg.issuer)
    {
        why = "the token's issuer is not " + cfg.issuer;
        return false;
    }
    const jvalue* aud = member(body, "aud");
    auto client = [&cfg](const jvalue& v)
    {
        return v.k == jvalue::kind::string &&
               std::find(cfg.clients.begin(), cfg.clients.end(), v.s) != cfg.clients.end();
    };
    if (aud && aud->k == jvalue::kind::string && client(*aud))
        out.audience = aud->s;
    else if (aud && aud->k == jvalue::kind::array)
    {
        const auto it = std::find_if(aud->items.begin(), aud->items.end(), client);
        if (it != aud->items.end())
            out.audience = it->s;
    }
    if (out.audience.empty())
    {
        why = "the token's audience names no client of this runtime";
        return false;
    }
    if (!string_member(body, "sub", out.subject))
    {
        why = "the token's sub is not a string";
        return false;
    }
    const jvalue* exp = member(body, "exp");
    if (!exp || !numeric_date(*exp, out.expires))
    {
        why = "the token has no exp";
        return false;
    }
    int64_t t = 0;
    const jvalue* nbf = member(body, "nbf");
    if (nbf && (!numeric_date(*nbf, t) || now + oidc_leeway_secs < t))
    {
        why = "the token is not valid yet";
        return false;
    }
    const jvalue* iat = member(body, "iat");
    if (iat && (!numeric_date(*iat, t) || now + oidc_leeway_secs < t))
    {
        why = "the token was issued in the future";
        return false;
    }
    if (const jvalue* names = member(body, cfg.claim); names && !claim_names(*names, out.policies))
    {
        why = "the token's " + cfg.claim + " claim is not a string or an array of strings, of 64 names at most";
        return false;
    }
    if (now >= out.expires + oidc_leeway_secs)
    {
        out.expired = true;
        why = "the token has expired";
        return false;
    }
    return true;
}

bool oidc_verifier::verify(std::string_view token, int64_t now, oidc_identity& out, std::string& why)
{
    out = oidc_identity{};
    const jwks_keys* keys = m_jwks.current(why);
    return keys && oidc_verify(m_cfg, *keys, token, now, out, why);
}

bool federation_web_user(const federation_config& cfg, const oidc_identity& id, std::string_view role_arn,
                         const federation_user_known& known, std::string& user, std::string& why)
{
    user.clear();
    for (const federation_role& r : cfg.roles)
    {
        if (role_arn.empty() || r.arn != role_arn)
            continue;
        if (!known(r.user))
        {
            why = "the role " + r.arn + " maps to " + r.user + ", which is no user";
            return false;
        }
        user = r.user;
        return true;
    }
    if (id.policies.empty())
    {
        why = "the token's " + cfg.oidc.claim + " claim names no user, and no role line maps the RoleArn";
        return false;
    }
    for (const std::string& name : id.policies)
        if (!federation_user_name(name) || !known(name))
        {
            why = "the token's " + cfg.oidc.claim + " claim names " + name + ", which is no user";
            return false;
        }
    // A session signs as one user, and taking the rights of several at once is not something it can do.
    if (id.policies.size() > 1)
    {
        why = "the token's " + cfg.oidc.claim + " claim names " + std::to_string(id.policies.size()) +
              " users, and a session takes the rights of one";
        return false;
    }
    user = id.policies.front();
    return true;
}

// ---- LDAP ----

std::string ldap_escape_dn_value(std::string_view value)
{
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i)
    {
        const auto c = static_cast<unsigned char>(value[i]);
        const bool edge_space = c == ' ' && (i == 0 || i + 1 == value.size());
        if (c < 0x20 || c == 0x7f)
        {
            out += '\\';
            out += hex[c >> 4];
            out += hex[c & 15];
        }
        else if (edge_space || (c == '#' && i == 0) || c == '"' || c == '+' || c == ',' || c == ';' || c == '<' ||
                 c == '>' || c == '\\' || c == '=')
        {
            out += '\\';
            out += static_cast<char>(c);
        }
        else
            out += static_cast<char>(c);
    }
    return out;
}

std::string ldap_bind_dn(std::string_view dn_template, std::string_view username)
{
    const size_t at = dn_template.find("%s");
    if (at == std::string_view::npos)
        return std::string(dn_template);
    std::string dn(dn_template.substr(0, at));
    dn += ldap_escape_dn_value(username);
    dn += dn_template.substr(at + 2);
    return dn;
}

std::string ldap_bind_request(int32_t msg_id, std::string_view dn, std::string_view password)
{
    std::string op;
    ber_tlv(op, 0x02, ber_uint(3));
    ber_tlv(op, 0x04, dn);
    // AuthenticationChoice simple, [0] primitive.
    ber_tlv(op, 0x80, password);
    std::string msg;
    ber_tlv(msg, 0x02, ber_uint(static_cast<uint32_t>(msg_id)));
    // BindRequest, [APPLICATION 0] constructed.
    ber_tlv(msg, 0x60, op);
    std::string out;
    ber_tlv(out, 0x30, msg);
    return out;
}

std::string ldap_unbind_request(int32_t msg_id)
{
    std::string msg;
    ber_tlv(msg, 0x02, ber_uint(static_cast<uint32_t>(msg_id)));
    // UnbindRequest, [APPLICATION 2] primitive and empty.
    ber_tlv(msg, 0x42, {});
    std::string out;
    ber_tlv(out, 0x30, msg);
    return out;
}

int ldap_message_size(std::string_view in, size_t& total)
{
    total = 0;
    if (in.empty())
        return 0;
    if (static_cast<uint8_t>(in[0]) != 0x30)
        return -1;
    if (in.size() < 2)
        return 0;
    size_t len = static_cast<uint8_t>(in[1]);
    size_t head = 2;
    if (len & 0x80)
    {
        const size_t n = len & 0x7F;
        if (n == 0 || n > 4)
            return -1;
        if (in.size() < 2 + n)
            return 0;
        len = 0;
        for (size_t i = 0; i < n; ++i)
            len = (len << 8) | static_cast<uint8_t>(in[2 + i]);
        head += n;
    }
    if (len > ldap_message_max)
        return -1;
    total = head + len;
    return in.size() >= total ? 1 : 0;
}

bool ldap_parse_bind_response(std::string_view msg, int32_t msg_id, ldap_bind_result& out, std::string& why)
{
    out = ldap_bind_result{};
    std::string_view in = msg, body, id_c, op, code_c, matched, diag;
    uint8_t tag = 0;
    int32_t id = 0;
    if (!ber_take(in, tag, body) || tag != 0x30 || !in.empty())
    {
        why = "the LDAP answer is not one whole message";
        return false;
    }
    if (!ber_take(body, tag, id_c) || tag != 0x02 || !ber_read_uint(id_c, id) || !ber_take(body, tag, op))
    {
        why = "the LDAP answer has no message id or operation";
        return false;
    }
    // A Notice of Disconnection (an ExtendedResponse of message 0) is the server ending the session.
    const bool notice = id == 0 && tag == 0x78;
    if (!notice && tag != 0x61)
    {
        why = "the LDAP answer is not a BindResponse";
        return false;
    }
    if (!notice && id != msg_id)
    {
        why = "the LDAP answer is to message " + std::to_string(id) + ", not " + std::to_string(msg_id);
        return false;
    }
    int32_t code = 0;
    if (!ber_take(op, tag, code_c) || tag != 0x0a || !ber_read_uint(code_c, code) || !ber_take(op, tag, matched) ||
        tag != 0x04 || !ber_take(op, tag, diag) || tag != 0x04)
    {
        why = "the LDAP answer's result is malformed";
        return false;
    }
    for (char c : diag.substr(0, 256))
        out.diagnostic.push_back(c >= ' ' && c < 0x7f ? c : '?');
    if (notice)
    {
        why = "the LDAP server ended the session (result " + std::to_string(code) + ")";
        return false;
    }
    out.code = code;
    return true;
}

bool ldap_simple_bind(const federation_ldap& cfg, std::string_view username, std::string_view password,
                      ldap_bind_result& out, std::string& why)
{
    out = ldap_bind_result{};
    if (!cfg.enabled() || cfg.dn_template.empty())
    {
        why = "no LDAP server is configured";
        return false;
    }
    auto control = [](char c) { return static_cast<unsigned char>(c) < 0x20 || c == 0x7f; };
    if (username.empty() || username.size() > 256 || std::any_of(username.begin(), username.end(), control))
    {
        why = "an LDAP username is 1 to 256 bytes without control characters";
        return false;
    }
    // RFC 4513 5.1.2: a bind with a name and no password is unauthenticated and succeeds for anyone.
    if (password.empty() || password.size() > 4096)
    {
        why = "an LDAP password is 1 to 4096 bytes";
        return false;
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(cfg.timeout_ms);
    ERR_clear_error();
    bool ok = false;
    {
        ldap_link link(deadline, cfg.timeout_ms);
        std::string msg;
        const std::string request = ldap_bind_request(1, ldap_bind_dn(cfg.dn_template, username), password);
        ok = link.connect(cfg, why) && link.send_all(request, why) && link.read_message(msg, why) &&
             ldap_parse_bind_response(msg, 1, out, why);
        // The unbind is a courtesy whose failure changes nothing.
        std::string ignored;
        if (ok && out.bound() && !link.send_all(ldap_unbind_request(2), ignored))
            ignored.clear();
    }
    ERR_clear_error();
    return ok;
}

bool federation_ldap_user(const federation_config& cfg, std::string_view ldap_user,
                          const federation_user_known& known, std::string& user, std::string& why)
{
    user.clear();
    const federation_ldap_map* hit = nullptr;
    for (const federation_ldap_map& m : cfg.ldap.users)
    {
        if (m.ldap_user == ldap_user)
        {
            hit = &m;
            break;
        }
        if (m.ldap_user == "*")
            hit = &m;
    }
    if (!hit)
    {
        why = "no ldap user line maps " + std::string(ldap_user);
        return false;
    }
    const std::string target = hit->user == "=" ? std::string(ldap_user) : hit->user;
    if (!federation_user_name(target) || !known(target))
    {
        why = "the LDAP user " + std::string(ldap_user) + " maps to " + target + ", which is no user";
        return false;
    }
    user = target;
    return true;
}

}   // namespace socketley::storage
