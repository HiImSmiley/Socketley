// `socketley acme issue`: a certificate from an ACME CA (RFC 8555), Let's Encrypt unless told otherwise, proven over
// HTTP-01 by the challenge files every socketley HTTP runtime serves, over TLS-ALPN-01 by a TLS listener, or over
// DNS-01 by the TXT records a dns runtime serves from the feed (dns_feed.h) -- the one way to a wildcard. A runtime with --acme runs it as a child of its
// worker; an operator may run it by hand, as certbot is run. Blocking on purpose: it is its own process.
#include <fcntl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
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
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "../shared/crypto/cert_keeper.h"
#include "../shared/http/https_client.h"
#include "../shared/crypto/jws.h"
#include "../shared/net/dns_feed.h"
#include "../shared/crypto/tls_context.h"
#include "../shared/json/json_doc.h"
#include "../shared/json/json_escape.h"
#include "../shared/persist/replaced_file.h"
#include "../shared/util/base64.h"
#include "../shared/util/random_id.h"

namespace
{

using socketley::json::jvalue;
using socketley::json::json_reader;
using socketley::jws::es256;
using socketley::jws::jwk_of;
using socketley::jws::sha256;

constexpr std::string_view lets_encrypt = "https://acme-v02.api.letsencrypt.org/directory";
constexpr int poll_seconds = 90;

std::string str(const jvalue& o, std::string_view n)
{
    const jvalue* v = member(o, n);
    return v && v->k == jvalue::kind::string ? v->s : std::string{};
}

// ─── HTTPS, one request per connection ──────────────────────────────────────

// The ACME server's, trusting a test CA's root when SOCKETLEY_ACME_CA names one, as Pebble's is.
class https : public https_client::client
{
public:
    bool init(std::string& err)
    {
        const char* ca = std::getenv("SOCKETLEY_ACME_CA");
        return client::init(err, ca && *ca ? ca : "", "socketley-acme");
    }
};
using reply = https_client::reply;

// ─── Keys and signatures ────────────────────────────────────────────────────

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

// Seconds a secondary of a zone is given to take a change up before it is asked: SOCKETLEY_ACME_DNS_WAIT, 10 by default.
int dns_wait_seconds()
{
    int wait = 10;
    if (const char* w = std::getenv("SOCKETLEY_ACME_DNS_WAIT"); w && *w)
        wait = std::clamp(std::atoi(w), 1, 3600);
    return wait;
}

// One question to `host`:`port` over UDP, its answer raw; empty when none came. `recurse` sets RD.
std::string dns_ask(const std::string& host, const std::string& port, const std::string& qname, uint16_t qtype,
                    bool recurse)
{
    unsigned char id[2];
    if (RAND_bytes(id, sizeof id) != 1)
        return {};
    std::string q = {static_cast<char>(id[0]), static_cast<char>(id[1]), static_cast<char>(recurse ? 1 : 0), 0,
                     0, 1, 0, 0, 0, 0, 0, 0};
    for (size_t p = 0; p <= qname.size();)
    {
        const size_t dot = std::min(qname.find('.', p), qname.size());
        if (dot > p)
        {
            q += static_cast<char>(dot - p);
            q.append(qname, p, dot - p);
        }
        p = dot + 1;
    }
    q += {'\0', static_cast<char>(qtype >> 8), static_cast<char>(qtype & 0xff), '\0', '\1'};

    std::string answer;
    addrinfo hints{}, *ai = nullptr;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    if (::getaddrinfo(host.c_str(), port.c_str(), &hints, &ai) != 0 || !ai)
        return {};
    const int fd = ::socket(ai->ai_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    for (int attempt = 0; fd >= 0 && attempt < 3 && answer.empty(); ++attempt)
    {
        if (::sendto(fd, q.data(), q.size(), 0, ai->ai_addr, ai->ai_addrlen) < 0)
            break;
        pollfd pfd{fd, POLLIN, 0};
        while (::poll(&pfd, 1, 3000) > 0)
        {
            char buf[1500];
            const ssize_t n = ::recv(fd, buf, sizeof buf, 0);
            if (n < 12)
                break;
            if (buf[0] == q[0] && buf[1] == q[1])
            {
                answer.assign(buf, static_cast<size_t>(n));
                break;
            }
        }
    }
    if (fd >= 0)
        ::close(fd);
    ::freeaddrinfo(ai);
    return answer;
}

// The name at `off` in a DNS message, compression followed; `off` moves past it. False for a malformed one.
bool dns_name(const std::string& m, size_t& off, std::string& out)
{
    out.clear();
    size_t at = off;
    bool jumped = false;
    for (int hops = 0; hops < 64; ++hops)
    {
        if (at >= m.size())
            return false;
        const auto len = static_cast<unsigned char>(m[at]);
        if (len == 0)
        {
            if (!jumped)
                off = at + 1;
            return true;
        }
        if ((len & 0xc0) == 0xc0)
        {
            if (at + 1 >= m.size())
                return false;
            if (!jumped)
                off = at + 2;
            jumped = true;
            at = (static_cast<size_t>(len & 0x3f) << 8) | static_cast<unsigned char>(m[at + 1]);
            continue;
        }
        if (at + 1 + len > m.size())
            return false;
        if (!out.empty())
            out += '.';
        out.append(m, at + 1, len);
        at += 1 + len;
    }
    return false;
}

// The NS names an answer holds.
std::vector<std::string> dns_ns_names(const std::string& m)
{
    std::vector<std::string> out;
    if (m.size() < 12)
        return out;
    const unsigned qd = (static_cast<unsigned char>(m[4]) << 8) | static_cast<unsigned char>(m[5]);
    const unsigned an = (static_cast<unsigned char>(m[6]) << 8) | static_cast<unsigned char>(m[7]);
    size_t off = 12;
    std::string name;
    for (unsigned i = 0; i < qd; ++i)
        if (!dns_name(m, off, name) || (off += 4) > m.size())
            return out;
    for (unsigned i = 0; i < an; ++i)
    {
        if (!dns_name(m, off, name) || off + 10 > m.size())
            return out;
        const unsigned type = (static_cast<unsigned char>(m[off]) << 8) | static_cast<unsigned char>(m[off + 1]);
        const size_t rdlen = (static_cast<unsigned char>(m[off + 8]) << 8) | static_cast<unsigned char>(m[off + 9]);
        off += 10;
        size_t rd = off;
        if (type == 2 && dns_name(m, rd, name))
            out.push_back(name);
        off += rdlen;
    }
    return out;
}

// Whether the world's DNS asks this daemon's dns runtimes about `zone`, and every server of the zone answers what
// they serve: a TXT record that exists nowhere else is put in the feed, SOCKETLEY_ACME_DNS_WAIT seconds are given to
// the zone's secondaries, and it is asked for through the resolver SOCKETLEY_ACME_DNS_PROBE names ("off" for no
// question) or else the first of /etc/resolv.conf, and then of each name server of the zone, by its IPv4 addresses.
// A CA asks any of them, so a secondary that has not caught up fails the validation as surely as no delegation, and
// every failed validation counts against the CA's limits; `why` says which it was.
bool zone_delegated(const std::string& zone, std::string& why)
{
    const char* env = std::getenv("SOCKETLEY_ACME_DNS_PROBE");
    if (env && std::string_view(env) == "off")
        return true;
    std::string host, port = "53";
    if (env && *env)
    {
        host = env;
        // "127.0.0.1:5353" and "[::1]:5353"; a bare IPv6 address has more than one colon.
        if (host.front() == '[' && host.find("]:") != std::string::npos)
        {
            port = host.substr(host.find("]:") + 2);
            host = host.substr(1, host.find(']') - 1);
        }
        else if (host.find(':') == host.rfind(':') && host.find(':') != std::string::npos)
        {
            port = host.substr(host.find(':') + 1);
            host.resize(host.find(':'));
        }
    }
    else
    {
        std::ifstream rc("/etc/resolv.conf");
        for (std::string line; host.empty() && std::getline(rc, line);)
            if (line.starts_with("nameserver"))
            {
                const size_t a = line.find_first_not_of(" \t", 10);
                if (a != std::string::npos)
                    host = line.substr(a, line.find_first_of(" \t%", a) - a);
            }
    }
    if (host.empty())
    {
        why = "there is no resolver to ask";
        return false;
    }

    const std::string id = socketley::random_hex(8), value = socketley::random_hex(16);
    if (id.empty() || value.empty())
        return false;
    const std::string label = "probe-" + id;
    std::string path;
    if (!dns_feed::write_challenge(label + "." + zone, value, label, path))
    {
        why = "the probe could not be written to " + dns_feed::dir();
        return false;
    }
    // A dns runtime looks at the feed once a second; its secondaries are told and take the change up after.
    std::this_thread::sleep_for(std::chrono::milliseconds(std::max(1500, dns_wait_seconds() * 1000)));

    const std::string qname = "_acme-challenge." + label + "." + zone;
    bool ok = dns_ask(host, port, qname, 16, true).find(value) != std::string::npos;
    if (!ok)
        why = "the world's DNS does not ask this daemon about it yet";
    for (const std::string& ns : ok ? dns_ns_names(dns_ask(host, port, zone, 2, true)) : std::vector<std::string>{})
    {
        addrinfo hints{}, *ai = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        // A server whose address cannot be found here is one the CA could not find either.
        if (::getaddrinfo(ns.c_str(), "53", &hints, &ai) != 0)
            continue;
        for (addrinfo* a = ai; a && ok; a = a->ai_next)
        {
            char ip[INET_ADDRSTRLEN];
            if (!::inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(a->ai_addr)->sin_addr, ip, sizeof ip))
                continue;
            if (dns_ask(ip, "53", qname, 16, false).find(value) == std::string::npos)
            {
                ok = false;
                why = ns + " (" + ip + ") had not taken the change up after " + std::to_string(dns_wait_seconds()) +
                      " s (SOCKETLEY_ACME_DNS_WAIT)";
            }
        }
        ::freeaddrinfo(ai);
    }
    ::unlink(path.c_str());
    return ok;
}

// Whether the certificate in `path` is a CA's, has more than thirty days left, and is good for every one of `names`,
// a name one label below a wildcard it has included.
bool cert_covers(const std::string& path, const std::vector<std::string>& names)
{
    BIO* b = BIO_new_file(path.c_str(), "r");
    X509* x = b ? PEM_read_bio_X509(b, nullptr, nullptr, nullptr) : nullptr;
    if (b)
        BIO_free(b);
    ERR_clear_error();
    if (!x)
        return false;
    int days = 0, secs = 0;
    bool ok = X509_check_issued(x, x) != X509_V_OK &&
              ASN1_TIME_diff(&days, &secs, nullptr, X509_get0_notAfter(x)) == 1 && days > 30;
    std::vector<std::string> sans;
    if (auto* gens = static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(x, NID_subject_alt_name, nullptr, nullptr)))
    {
        for (int i = 0; i < sk_GENERAL_NAME_num(gens); ++i)
            if (const GENERAL_NAME* g = sk_GENERAL_NAME_value(gens, i); g->type == GEN_DNS)
                sans.emplace_back(reinterpret_cast<const char*>(ASN1_STRING_get0_data(g->d.dNSName)),
                                  static_cast<size_t>(ASN1_STRING_length(g->d.dNSName)));
        GENERAL_NAMES_free(gens);
    }
    X509_free(x);
    for (const std::string& n : names)
    {
        const size_t dot = n.find('.');
        ok = ok && (std::find(sans.begin(), sans.end(), n) != sans.end() ||
                    (!n.starts_with("*.") && dot != std::string::npos &&
                     std::find(sans.begin(), sans.end(), "*" + n.substr(dot)) != sans.end()));
    }
    return ok;
}

// `data` whole in a file beside `path`, whose name it answers, empty when the disk would not take it.
std::string stage(const std::string& path, const std::string& data, mode_t mode)
{
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(path).parent_path(), ec);
    const std::string tmp = path + ".tmp." + std::to_string(::getpid());
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0)
        return {};
    bool ok = ::write(fd, data.data(), data.size()) == static_cast<ssize_t>(data.size());
    ok = ::fsync(fd) == 0 && ok;
    ok = ::close(fd) == 0 && ok;
    if (!ok)
    {
        ::unlink(tmp.c_str());
        return {};
    }
    return tmp;
}

bool write_atomic(const std::string& path, const std::string& data, mode_t mode)
{
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(path).parent_path(), ec);
    return socketley::replace_file(path, data, socketley::durability::data, nullptr, mode);
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

    std::string thumbprint() const { return socketley::base64url::encode(sha256(m_jwk)); }

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
            std::string prot = "{\"alg\":\"ES256\",\"nonce\":" + socketley::json::quote(m_nonce) + ",\"url\":" + socketley::json::quote(url) + ",";
            prot += use_jwk ? "\"jwk\":" + m_jwk + "}" : "\"kid\":" + socketley::json::quote(m_kid) + "}";
            const std::string p64 = socketley::base64url::encode(prot), b64 = socketley::base64url::encode(payload);
            const std::string body = "{\"protected\":" + socketley::json::quote(p64) + ",\"payload\":" + socketley::json::quote(b64) + ",\"signature\":" +
                                     socketley::json::quote(socketley::base64url::encode(es256(m_key, p64 + "." + b64))) + "}";
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
            payload += ",\"contact\":[" + socketley::json::quote("mailto:" + email) + "]";
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
    std::vector<std::string> names, dns_zones;
    std::string cert, key, email, challenge;
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
            ok = value(challenge) && (challenge == "http-01" || challenge == "tls-alpn-01" || challenge == "dns-01");
        // The zones a dns runtime of this daemon serves: a name in one is proven over DNS-01 whatever --challenge
        // says, which needs no port open, and --challenge is left for the others.
        else if (a == "--dns-zones" && (ok = value(v)))
        {
            for (size_t p = 0; p <= v.size();)
            {
                const size_t comma = std::min(v.find(',', p), v.size());
                if (comma > p)
                    dns_zones.push_back(v.substr(p, comma - p));
                p = comma + 1;
            }
        }
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
                     "[--directory url] [--challenge http-01|tls-alpn-01|dns-01] [--dns-zones zone[,zone...]]\n";
        return 1;
    }
    // A wildcard is proven by DNS alone (RFC 8555 8.4); SOCKETLEY_ACME_CHALLENGE picks one for every name, for a
    // host whose port 80 is closed.
    const bool wildcard = std::any_of(names.begin(), names.end(), [](const std::string& n) { return n.starts_with("*."); });
    if (challenge.empty())
    {
        const char* env = std::getenv("SOCKETLEY_ACME_CHALLENGE");
        challenge = wildcard && dns_zones.empty() ? "dns-01" : env && *env ? env : "http-01";
    }
    // Whether `n` (with or without "*.") is proven over DNS-01: every name when that is the challenge, and the
    // names in the zones --dns-zones gives.
    const auto by_dns = [&](std::string_view n)
    {
        if (n.starts_with("*."))
            n.remove_prefix(2);
        if (challenge == "dns-01")
            return true;
        for (const std::string& z : dns_zones)
            if (n.size() >= z.size() && n.substr(n.size() - z.size()) == z &&
                (n.size() == z.size() || n[n.size() - z.size() - 1] == '.'))
                return true;
        return false;
    };
    if (challenge != "http-01" && challenge != "tls-alpn-01" && challenge != "dns-01")
    {
        std::cout << "acme issue: the challenge is http-01, tls-alpn-01 or dns-01, not " << challenge << "\n";
        return 1;
    }
    for (const std::string& n : names)
        if (n.starts_with("*.") && !by_dns(n))
        {
            std::cout << "acme issue: a wildcard is proven over dns-01 only, and " << n << " is in none of --dns-zones\n";
            return 1;
        }
    if (cert.empty())
        cert = cert_keeper::acme_cert_path(names.front());
    if (key.empty())
        key = cert_keeper::acme_key_path(names.front());

    // A zone the world's DNS does not ask this daemon about proves nothing over DNS-01: its wildcards wait, and its
    // other names are proven like any outside the zones. Issued so is partial, said with exit status 3 and a file
    // beside the certificate, and tried again later.
    bool partial = false;
    if (challenge != "dns-01")
        std::erase_if(dns_zones, [&](const std::string& z) {
            std::string why;
            if (zone_delegated(z, why))
                return false;
            std::cout << "acme issue: " << z << ": " << why << "; its names are proven over " << challenge
                      << " and its wildcard waits\n";
            return true;
        });
    std::erase_if(names, [&](const std::string& n) {
        const bool waits = n.starts_with("*.") && !by_dns(n);
        partial = partial || waits;
        return waits;
    });
    // A name one label below a wildcard asked for is in it already.
    const std::vector<std::string> asked = names;
    std::erase_if(names, [&](const std::string& n) {
        const size_t dot = n.find('.');
        return !n.starts_with("*.") && dot != std::string::npos &&
               std::find(asked.begin(), asked.end(), "*" + n.substr(dot)) != asked.end();
    });
    const auto finish = [&](int rc) {
        if (rc == 0 && partial)
        {
            write_atomic(cert + ".partial", "", 0644);
            return 3;
        }
        if (rc == 0)
            ::unlink((cert + ".partial").c_str());
        return rc;
    };
    if (names.empty())
    {
        std::cout << "acme issue: no name can be proven now\n";
        return 2;
    }
    // Asked again for what the certificate already holds, the CA is not troubled.
    if (cert_covers(cert, names))
        return finish(0);
    const std::string challenges = cert_keeper::challenge_dir();
    const std::string account_path = std::filesystem::path(challenges).parent_path().string() + "/account-" +
                                     socketley::base64url::encode(sha256(dir)).substr(0, 12) + ".key";
    std::error_code ec;
    std::filesystem::create_directories(challenges, ec);

    // One issuance per account at a time, so two runtimes renewing at once do not race for the account's key.
    const int lock = ::open((account_path + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock >= 0 && ::flock(lock, LOCK_EX) != 0) {}

    std::string err;
    https h;
    EVP_PKEY* account = h.init(err) ? socketley::jws::load_or_make_key(account_path, "the account key", err) : nullptr;
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
        ids += (ids.empty() ? "" : ",") + std::string("{\"type\":\"dns\",\"value\":") + socketley::json::quote(n) + "}";
    reply r;
    jvalue order;
    if (!c.post(c.new_order(), "{\"identifiers\":[" + ids + "]}", r, err) || !json_reader(r.body).document(order))
        return done(2);
    const std::string order_url = r.header("location");
    const std::string thumb = c.thumbprint();

    // Every authorization's answer is put where the runtimes serve it, and then the CA is told to look -- for DNS-01
    // after every answer is out and has had time to reach the secondaries, since a CA asks any of the zone's servers.
    struct pending_check { std::string authz, url; };
    std::vector<pending_check> dns_checks;
    if (const jvalue* authz = member(order, "authorizations"))
        for (const jvalue& au : authz->items)
        {
            jvalue a;
            if (!c.get(au.s, r, a, err))
                return done(2);
            if (str(a, "status") == "valid")
                continue;
            std::string token, url;
            const std::string ident = member(a, "identifier") ? str(*member(a, "identifier"), "value") : std::string{};
            const std::string challenge_here = by_dns(ident) ? "dns-01" : challenge;
            if (const jvalue* chs = member(a, "challenges"))
                for (const jvalue& ch : chs->items)
                    if (str(ch, "type") == challenge_here)
                    {
                        token = str(ch, "token");
                        url = str(ch, "url");
                    }
            if (token.empty() || token.find('/') != std::string::npos || ident.empty())
            {
                err = "the CA offered no " + challenge_here + " challenge for " + (ident.empty() ? au.s : ident);
                return done(2);
            }
            if (challenge_here == "dns-01")
            {
                // The TXT record of _acme-challenge.<name> (RFC 8555 8.4), the name without a wildcard's "*.".
                std::string path;
                if (!dns_feed::write_challenge(ident, socketley::base64url::encode(sha256(token + "." + thumb)), token, path))
                {
                    err = "the DNS-01 answer for " + ident + " could not be written to " + dns_feed::dir();
                    return done(2);
                }
                written.push_back(path);
                dns_checks.push_back({au.s, url});
                continue;
            }
            // HTTP-01's answer is served as a file over HTTP, TLS-ALPN-01's as a certificate on the TLS listener.
            const bool alpn = challenge_here == "tls-alpn-01";
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

    if (!dns_checks.empty())
    {
        // A dns runtime takes the feed up within a second; SOCKETLEY_ACME_DNS_WAIT gives secondaries their time.
        const int wait = dns_wait_seconds();
        std::this_thread::sleep_for(std::chrono::seconds(wait));
        for (const pending_check& pc : dns_checks)
        {
            jvalue ignored;
            if (!c.post(pc.url, "{}", r, err) || !poll(c, pc.authz, "valid", ignored, err))
                return done(2);
        }
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
    if (!c.post(str(order, "finalize"), "{\"csr\":" + socketley::json::quote(socketley::base64url::encode(csr)) + "}", r, err) ||
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
    // Both written out before either is put in place, so a disk that takes one and not the other leaves the old pair;
    // then the key before the chain, so a runtime that sees the new certificate finds its key already there.
    const std::string key_tmp = stage(key, pem_of_key(cert_key), 0600);
    const std::string cert_tmp = key_tmp.empty() ? std::string() : stage(cert, chain.body, 0644);
    const bool ok = !cert_tmp.empty() && ::rename(key_tmp.c_str(), key.c_str()) == 0 &&
                    ::rename(cert_tmp.c_str(), cert.c_str()) == 0;
    if (!ok)
    {
        if (!key_tmp.empty())
            ::unlink(key_tmp.c_str());
        if (!cert_tmp.empty())
            ::unlink(cert_tmp.c_str());
    }
    EVP_PKEY_free(cert_key);
    if (!ok)
    {
        err = "the certificate could not be written to " + cert + " and " + key;
        return done(2);
    }
    return finish(done(0));
}

}   // namespace

int acme_main(int argc, char** argv)
{
    if (argc >= 3 && std::string_view(argv[2]) == "issue")
        return issue(argc, argv);
    std::cout << "usage: socketley acme issue --domains name[,name...] [--cert file] [--key file] [--email addr] "
                 "[--directory url] [--challenge http-01|tls-alpn-01|dns-01] [--dns-zones zone[,zone...]]\n";
    return 1;
}
