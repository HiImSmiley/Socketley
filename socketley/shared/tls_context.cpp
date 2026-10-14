#include "tls_context.h"

#include <unistd.h>

// Conditionally compile TLS support only if OpenSSL is available
#if __has_include(<openssl/ssl.h>)
#define SOCKETLEY_HAS_TLS 1
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <arpa/inet.h>
#else
#define SOCKETLEY_HAS_TLS 0
#endif

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <atomic>
#include <mutex>
#include <new>
#include <vector>

#include "cert_keeper.h"
#include "logging.h"

#if SOCKETLEY_HAS_TLS
namespace
{

// Every connection's write side: the records SSL writes, kept in one string that take_out hands over whole, where a
// memory BIO copied them in, zeroed its growth and copied them out again in pieces.
struct out_bio
{
    std::string buf;
    size_t      off = 0;
};

int out_write(BIO* b, const char* data, size_t len, size_t* written)
{
    BIO_clear_retry_flags(b);
    static_cast<out_bio*>(BIO_get_data(b))->buf.append(data, len);
    *written = len;
    return 1;
}

int out_read(BIO* b, char* data, size_t len, size_t* read)
{
    BIO_clear_retry_flags(b);
    auto* o = static_cast<out_bio*>(BIO_get_data(b));
    const size_t n = std::min(len, o->buf.size() - o->off);
    *read = n;
    if (n == 0)
    {
        // Empty is "ask again", as a memory BIO with an EOF return of -1 says it.
        BIO_set_retry_read(b);
        return 0;
    }
    std::memcpy(data, o->buf.data() + o->off, n);
    o->off += n;
    if (o->off == o->buf.size())
    {
        o->buf.clear();
        o->off = 0;
    }
    return 1;
}

long out_ctrl(BIO* b, int cmd, long, void*)
{
    const auto* o = static_cast<const out_bio*>(BIO_get_data(b));
    switch (cmd)
    {
        case BIO_CTRL_PENDING: return static_cast<long>(o->buf.size() - o->off);
        case BIO_CTRL_FLUSH:   return 1;
        default:               return 0;
    }
}

int out_create(BIO* b)
{
    auto* o = new (std::nothrow) out_bio;
    BIO_set_data(b, o);
    BIO_set_init(b, o != nullptr);
    return o != nullptr;
}

int out_destroy(BIO* b)
{
    delete static_cast<out_bio*>(BIO_get_data(b));
    BIO_set_data(b, nullptr);
    return 1;
}

int out_type()
{
    static const int type = BIO_get_new_index() | BIO_TYPE_SOURCE_SINK;
    return type;
}

const BIO_METHOD* out_method()
{
    static BIO_METHOD* const m = []
    {
        BIO_METHOD* x = BIO_meth_new(out_type(), "socketley records");
        if (x && (!BIO_meth_set_write_ex(x, out_write) || !BIO_meth_set_read_ex(x, out_read) ||
                  !BIO_meth_set_ctrl(x, out_ctrl) || !BIO_meth_set_create(x, out_create) ||
                  !BIO_meth_set_destroy(x, out_destroy)))
        {
            BIO_meth_free(x);
            x = nullptr;
        }
        return x;
    }();
    return m;
}

out_bio* out_of(const SSL* ssl)
{
    BIO* wbio = ssl ? SSL_get_wbio(ssl) : nullptr;
    return wbio && BIO_method_type(wbio) == out_type() ? static_cast<out_bio*>(BIO_get_data(wbio)) : nullptr;
}

}   // namespace
#endif

// The TLS configuration gate, next to the OpenSSL wrapper because whoever
// wires up the next role will be reading this file.

std::string tls_not_implemented_error(std::string_view option)
{
    std::string msg(option);
    msg += ": TLS transport is not implemented for this runtime -- a server "
           "runtime's own listener, a cache runtime's own listener, a client "
           "runtime's outbound socket and a proxy runtime (both legs) perform "
           "a handshake, and nothing else does, so this would run in cleartext "
           "on an endpoint reported as encrypted\n";
    return msg;
}

std::string tls_config_refusal(runtime_type type,
                               bool tls,
                               bool udp,
                               std::string_view cert_path,
                               std::string_view key_path,
                               std::string_view ca_path,
                               std::string_view mesh_client_ca,
                               std::string_view mesh_client_cert,
                               std::string_view mesh_client_key,
                               std::string_view cache_replicate_target)
{
    const bool anything_asked = tls || !cert_path.empty() || !key_path.empty() ||
                                !ca_path.empty() || !mesh_client_ca.empty() ||
                                !mesh_client_cert.empty() || !mesh_client_key.empty();
    if (!anything_asked)
        return {};   // no TLS asked for, nothing to refuse

    // A datagram socket has no handshake to put TLS on, asked once here rather
    // than in each setup(), which a placeholder never runs -- so the same
    // configuration was refused in the daemon and accepted out of process.
    if (tls && udp)
        return "--tls on a UDP socket would need DTLS, which is not implemented\n"
               "  drop --udp to dial over TLS, or drop --tls to send datagrams\n";

    if (!tls_role_has_handshake(type))
    {
        // Order matters only for the message: name the flag the operator most
        // likely typed.
        if (tls)                        return tls_not_implemented_error("--tls");
        if (!cert_path.empty())         return tls_not_implemented_error("--cert");
        if (!key_path.empty())          return tls_not_implemented_error("--key");
        if (!ca_path.empty())           return tls_not_implemented_error("--ca");
        if (!mesh_client_ca.empty())    return tls_not_implemented_error("--client-ca");
        if (!mesh_client_cert.empty())  return tls_not_implemented_error("--client-cert");
        return tls_not_implemented_error("--client-key");
    }

#if !SOCKETLEY_HAS_TLS
    return "--tls: this binary was built without the OpenSSL development "
           "headers, so it has no record layer to speak TLS with\n";
#else
    // A client runtime is handled before the listener rules because it has no
    // listener, and --tls alone is complete: create_ssl_client pins the host
    // from -t and verifies against the system store.
    if (type == runtime_client)
    {
        // The mesh options configure a proxy, and the certificate a client
        // presents is --cert/--key below.
        if (!mesh_client_ca.empty())
            return "--client-ca: verifies the certificates clients present, and a "
                   "client runtime has no listener for one to arrive on -- it "
                   "would be stored and reported and authenticate nobody\n";
        if (!mesh_client_cert.empty() || !mesh_client_key.empty())
        {
            std::string msg(!mesh_client_cert.empty() ? "--client-cert" : "--client-key");
            msg += ": configures a proxy's backend leg, and a client runtime has "
                   "only its own -- use --cert and --key, which are the "
                   "certificate this client presents when the peer asks for one\n";
            return msg;
        }

        // A certificate or a trust store with no --tls is an operator who
        // believes the dial is encrypted and has not turned it on: it would be
        // stored, reported, and used to verify a handshake that never happens.
        if (!tls)
        {
            std::string msg(!cert_path.empty() ? "--cert"
                          : !key_path.empty()  ? "--key"
                                               : "--ca");
            msg += ": needs --tls as well -- on its own it configures a "
                   "certificate for a connection that would still be dialled in "
                   "cleartext\n";
            return msg;
        }

        // The certificate this client presents is a pair, and half of one
        // loads nothing, so the dial would present nothing after the flags
        // said it was configured.
        if (cert_path.empty() != key_path.empty())
            return cert_path.empty()
                ? std::string("--key: needs --cert <file> as well -- a key with no "
                              "certificate presents nothing\n")
                : std::string("--cert: needs --key <file> as well -- a certificate "
                              "with no key presents nothing\n");

        return {};
    }

    // The mesh client-certificate options describe a backend leg, which
    // neither a server nor a cache has, so this catches a state file or an
    // imported document that carries them.
    if ((type == runtime_server || type == runtime_cache || type == runtime_storage) &&
        (!mesh_client_ca.empty() || !mesh_client_cert.empty() || !mesh_client_key.empty()))
    {
        std::string msg(!mesh_client_ca.empty()   ? "--client-ca"
                      : !mesh_client_cert.empty() ? "--client-cert"
                                                  : "--client-key");
        msg += ": configures a proxy's backend leg, and a ";
        msg += type == runtime_server ? "server" : type == runtime_cache ? "cache" : "storage";
        msg += " runtime has none -- it would be stored and reported and dial "
               "nothing\n";
        return msg;
    }

    // Half a listener configuration is refused rather than half-honoured in
    // both directions, with --ca the exception on a proxy, where it is the
    // backend leg's trust store.
    const bool ca_is_listener_option = (type != runtime_proxy);
    if (!tls && (!cert_path.empty() || !key_path.empty() ||
                 (ca_is_listener_option && !ca_path.empty())))
    {
        std::string msg(!cert_path.empty() ? "--cert"
                      : !key_path.empty()  ? "--key"
                                           : "--ca");
        msg += ": needs --tls as well -- on its own it configures a "
               "certificate for a listener that would still accept cleartext\n";
        return msg;
    }
    if (tls && cert_path.empty())
        return "--tls: a TLS listener needs --cert <file> and --key <file>\n";
    if (tls && key_path.empty())
        return "--tls: a TLS listener needs --key <file> to go with --cert\n";

    // A cache that encrypts its port and replicates out of it puts the
    // identical data on the wire in the clear, so the configuration is refused
    // here and the leader half at handle_replicate_request().
    if (type == runtime_cache && tls && !cache_replicate_target.empty())
        return "--replicate: a cache's replication link is not encrypted -- it "
               "dials its leader in cleartext and would stream this cache's "
               "whole dataset off a port --tls says is encrypted.  Refusing "
               "rather than encrypting one half: drop --replicate, or drop "
               "--tls and be honestly cleartext\n";

    if (type != runtime_proxy)
        return {};

    // --client-ca verifies certificates presented by clients, which only a
    // listener that speaks TLS can ask for.
    if (!mesh_client_ca.empty() && !tls)
        return "--client-ca: verifies the certificates clients present, which "
               "needs --tls --cert --key on this proxy's own listener -- on a "
               "cleartext port it would authenticate nobody\n";

    // A client certificate is a pair, and half of one leaves the backend leg
    // presenting nothing after the flags said it was configured.
    if (mesh_client_cert.empty() != mesh_client_key.empty())
        return mesh_client_cert.empty()
            ? std::string("--client-key: needs --client-cert <file> as well -- a "
                          "key with no certificate presents nothing\n")
            : std::string("--client-cert: needs --client-key <file> as well -- a "
                          "certificate with no key presents nothing\n");

    return {};
#endif
}

tls_context::tls_context() = default;

tls_context::~tls_context()
{
    cert_keeper::unwatch(this);
#if SOCKETLEY_HAS_TLS
    if (m_saved_session)
        SSL_SESSION_free(m_saved_session);
    if (m_ctx)
        SSL_CTX_free(m_ctx);
#endif
}

#if SOCKETLEY_HAS_TLS
static const char* ssl_error_name(int err)
{
    switch (err)
    {
        case SSL_ERROR_NONE:             return "SSL_ERROR_NONE";
        case SSL_ERROR_ZERO_RETURN:      return "SSL_ERROR_ZERO_RETURN";
        case SSL_ERROR_WANT_READ:        return "SSL_ERROR_WANT_READ";
        case SSL_ERROR_WANT_WRITE:       return "SSL_ERROR_WANT_WRITE";
        case SSL_ERROR_WANT_X509_LOOKUP: return "SSL_ERROR_WANT_X509_LOOKUP";
        case SSL_ERROR_SYSCALL:          return "SSL_ERROR_SYSCALL";
        case SSL_ERROR_SSL:              return "SSL_ERROR_SSL";
        default:                         return "SSL_ERROR_(unknown)";
    }
}

// What OpenSSL queued, the queue emptied, because it is per-thread and persistent and an entry left behind is
// reported as the cause of an unrelated failure: every error in full, and the first one's reason alone.
struct ssl_failure
{
    std::string detail, brief;
};
static ssl_failure take_ssl_failure(int ssl_err = SSL_ERROR_NONE)
{
    ssl_failure f;
    char buf[256];
    for (unsigned long e = ERR_get_error(); e != 0; e = ERR_get_error())
    {
        if (f.brief.empty())
        {
            const char* r = ERR_reason_error_string(e);
            f.brief = r ? r : "unknown";
        }
        ERR_error_string_n(e, buf, sizeof(buf));
        if (!f.detail.empty())
            f.detail += "; ";
        f.detail += buf;
    }
    if (!f.detail.empty())
        return f;
    // An empty queue is itself information: SSL_ERROR_SYSCALL with nothing queued means the transport broke under
    // OpenSSL rather than the protocol.
    f.detail = "no OpenSSL error queued";
    if (ssl_err != SSL_ERROR_NONE)
        f.detail += std::string(" (") + ssl_error_name(ssl_err) + ")";
    if (ssl_err == SSL_ERROR_SYSCALL)
        f.detail += std::string(" (transport: ") + std::strerror(errno) + ")";
    f.brief = ssl_err == SSL_ERROR_SYSCALL ? "closed before the handshake finished" : f.detail;
    return f;
}

static void log_ssl_errors(const char* what, int ssl_err = SSL_ERROR_NONE)
{
    LOG_ERROR((std::string("tls: ") + what + ": " + take_ssl_failure(ssl_err).detail).c_str());
}

namespace
{
// Handshakes strangers failed, counted by reason and told once a minute, since anyone may open a port and most who
// fail are scanners; each one in full only at debug.
struct inbound_failures
{
    std::mutex mu;
    std::map<std::string, uint64_t> by_reason;
    uint64_t total{0};
    std::chrono::steady_clock::time_point since{};
    // Whether total is above zero, read without the lock by the report every loop turn runs.
    std::atomic<bool> any{false};
};
inbound_failures& inbound()
{
    static inbound_failures f;
    return f;
}
// A minute, or SOCKETLEY_TLS_FAILURE_REPORT_SECS for a test that cannot wait one.
std::chrono::seconds inbound_report_every()
{
    static const std::chrono::seconds every = []
    {
        const char* e = std::getenv("SOCKETLEY_TLS_FAILURE_REPORT_SECS");
        const long v = e ? std::strtol(e, nullptr, 10) : 0;
        return std::chrono::seconds(v > 0 && v <= 3600 ? v : 60);
    }();
    return every;
}
constexpr size_t inbound_reasons_max = 16;

void note_inbound_failure(const std::string& brief)
{
    {
        auto& f = inbound();
        std::lock_guard<std::mutex> lk(f.mu);
        if (f.total == 0)
            f.since = std::chrono::steady_clock::now();
        ++f.total;
        f.any.store(true, std::memory_order_relaxed);
        if (f.by_reason.size() < inbound_reasons_max || f.by_reason.count(brief))
            ++f.by_reason[brief];
        else
            ++f.by_reason["other"];
    }
    tls_context::report_inbound_failures();
}
}   // namespace

// Apply SSL_CTX options common to server and client, once, which every
// per-connection SSL object inherits.
static void apply_ctx_performance_options(SSL_CTX* ctx)
{

    // Session tickets for stateless resumption, with SSL_OP_NO_TICKET cleared
    // explicitly although it is off by default; init_server sets it again.
    long opts = SSL_CTX_get_options(ctx);
    opts &= ~SSL_OP_NO_TICKET;

    // No kernel TLS here, because KTLS needs a socket BIO and this wrapper
    // gives every connection a memory BIO pair so OpenSSL is a codec and
    // io_uring moves every byte.

    // Prefer server cipher order for better security/performance control
    opts |= SSL_OP_CIPHER_SERVER_PREFERENCE;

    // Disable renegotiation to prevent mid-connection handshakes (perf + security)
#if defined(SSL_OP_NO_RENEGOTIATION)
    opts |= SSL_OP_NO_RENEGOTIATION;
#endif

    SSL_CTX_set_options(ctx, opts);

    // SSL_MODE_RELEASE_BUFFERS frees read buffers between reads, and
    // ACCEPT_MOVING_WRITE_BUFFER allows the retry io_uring's short writes
    // require.
    long mode = SSL_MODE_RELEASE_BUFFERS | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;

    // SSL_MODE_AUTO_RETRY: retry internal reads/writes automatically on
    // renegotiation, simplifying the caller's error handling loop.
    mode |= SSL_MODE_AUTO_RETRY;

    SSL_CTX_set_mode(ctx, mode);

    // 16 KB records, the TLS maximum, which amortises the record header and
    // still splits automatically on partial writes.
    SSL_CTX_set_max_send_fragment(ctx, 16384);
}
#endif

#if SOCKETLEY_HAS_TLS
namespace
{

// The protocol name a CA's TLS-ALPN-01 validation offers, length-prefixed as ALPN carries it.
constexpr unsigned char acme_tls_alpn[] = {10, 'a', 'c', 'm', 'e', '-', 't', 'l', 's', '/', '1'};

int acme_ex_index()
{
    static const int idx = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    return idx;
}

// A CA asking for acme-tls/1 by a name whose challenge certificate is on disk is shown that one, on that handshake.
int acme_client_hello(SSL* ssl, int* /*alert*/, void* /*arg*/)
{
    const unsigned char* alpn = nullptr;
    size_t alpn_len = 0;
    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_application_layer_protocol_negotiation, &alpn, &alpn_len) != 1 ||
        alpn_len < 2)
        return SSL_CLIENT_HELLO_SUCCESS;
    bool offered = false;
    for (size_t p = 2; p < alpn_len && !offered;)
    {
        const size_t n = alpn[p];
        offered = n == sizeof acme_tls_alpn - 1 && p + 1 + n <= alpn_len &&
                  std::memcmp(alpn + p, acme_tls_alpn, sizeof acme_tls_alpn) == 0;
        p += 1 + n;
    }
    const unsigned char* sni = nullptr;
    size_t sni_len = 0;
    if (!offered || SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &sni, &sni_len) != 1 || sni_len < 5)
        return SSL_CLIENT_HELLO_SUCCESS;
    // server_name_list: a two-byte length, then a type byte and a two-byte length before the name.
    const size_t name_len = (size_t(sni[3]) << 8) | sni[4];
    if (sni[2] != 0 || 5 + name_len > sni_len)
        return SSL_CLIENT_HELLO_SUCCESS;
    const std::string name(reinterpret_cast<const char*>(sni + 5), name_len);
    const std::string pem = cert_keeper::tls_alpn_answer(name);
    if (pem.empty())
        return SSL_CLIENT_HELLO_SUCCESS;
    BIO* b = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    X509* x = b ? PEM_read_bio_X509(b, nullptr, nullptr, nullptr) : nullptr;
    EVP_PKEY* k = b ? PEM_read_bio_PrivateKey(b, nullptr, nullptr, nullptr) : nullptr;
    if (x && k && SSL_use_cert_and_key(ssl, x, k, nullptr, 1) == 1)
        SSL_set_ex_data(ssl, acme_ex_index(), reinterpret_cast<void*>(1));
    if (x) X509_free(x);
    if (k) EVP_PKEY_free(k);
    if (b) BIO_free(b);
    ERR_clear_error();
    return SSL_CLIENT_HELLO_SUCCESS;
}

// A handshake given the challenge certificate speaks acme-tls/1. Every other one negotiates "h2" when the context
// offers it and the client lists it, and no protocol otherwise, as before. The client's list is walked here rather
// than by SSL_select_next_proto, whose overread (CVE-2024-5535) the OpenSSL in use may still have.
int acme_alpn_select(SSL* ssl, const unsigned char** out, unsigned char* outlen, const unsigned char* in,
                     unsigned int inlen, void* arg)
{
    if (SSL_get_ex_data(ssl, acme_ex_index()))
    {
        *out = acme_tls_alpn + 1;
        *outlen = sizeof acme_tls_alpn - 1;
        return SSL_TLSEXT_ERR_OK;
    }
    if (!arg)
        return SSL_TLSEXT_ERR_NOACK;
    for (unsigned int p = 0; p < inlen;)
    {
        const unsigned int n = in[p];
        if (n == 0 || p + 1 + n > inlen)
            break;
        if (n == 2 && in[p + 1] == 'h' && in[p + 2] == '2')
        {
            *out = in + p + 1;
            *outlen = 2;
            return SSL_TLSEXT_ERR_OK;
        }
        p += 1 + n;
    }
    return SSL_TLSEXT_ERR_NOACK;
}

}   // namespace
#endif

bool tls_context::init_server(std::string_view cert_path, std::string_view key_path,
                              std::string_view client_ca)
{
#if SOCKETLEY_HAS_TLS
    m_ctx = SSL_CTX_new(TLS_server_method());
    if (!m_ctx)
    {
        LOG_ERROR("tls: failed to create SSL context");
        log_ssl_errors("SSL_CTX_new");
        return false;
    }
    SSL_CTX_set_min_proto_version(m_ctx, TLS1_2_VERSION);

    // Server-side session cache, so a returning client resumes without the key
    // exchange.
    SSL_CTX_set_session_cache_mode(m_ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_sess_set_cache_size(m_ctx, 20480);

    // Session timeout: 5 minutes. Balances memory vs resumption hit rate.
    SSL_CTX_set_timeout(m_ctx, 300);

    // Apply common performance options (tickets, modes, fragment size)
    apply_ctx_performance_options(m_ctx);
    // TLS 1.2 is offered with Mozilla's intermediate suites alone, ECDHE and AEAD; TLS 1.3's are all of that already.
    SSL_CTX_set_cipher_list(m_ctx, "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                                   "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
                                   "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305");
    // Resumption from the session cache rather than from tickets, whose key lives as long as the process and would
    // open every TLS 1.2 session it ever sealed to whoever learns it.
    SSL_CTX_set_options(m_ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_client_hello_cb(m_ctx, acme_client_hello, nullptr);
    SSL_CTX_set_alpn_select_cb(m_ctx, acme_alpn_select, nullptr);

    // The chain, so a client is sent the intermediates a CA's certificate needs as well as the leaf.
    if (SSL_CTX_use_certificate_chain_file(m_ctx, std::string(cert_path).c_str()) <= 0)
    {
        LOG_ERROR((std::string("tls: failed to load certificate: ") + std::string(cert_path)).c_str());
        log_ssl_errors("certificate load");
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(m_ctx, std::string(key_path).c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        LOG_ERROR((std::string("tls: failed to load private key: ") + std::string(key_path)).c_str());
        log_ssl_errors("private key load");
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        return false;
    }

    if (!SSL_CTX_check_private_key(m_ctx))
    {
        LOG_ERROR("tls: private key does not match certificate");
        log_ssl_errors("private key check");
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        return false;
    }

    // mTLS: require client certificates if CA file is provided
    if (!client_ca.empty())
    {
        if (SSL_CTX_load_verify_locations(m_ctx, std::string(client_ca).c_str(), nullptr) <= 0)
        {
            LOG_ERROR((std::string("tls: failed to load client CA: ") + std::string(client_ca)).c_str());
            log_ssl_errors("client CA load");
            SSL_CTX_free(m_ctx);
            m_ctx = nullptr;
            return false;
        }
        SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    }

    cert_keeper::watch(this, cert_path, key_path);
    return true;
#else
    LOG_ERROR("tls: OpenSSL not available -- rebuild with OpenSSL development headers");
    return false;
#endif
}

bool tls_context::reload_cert(std::string_view cert_path, std::string_view key_path)
{
#if SOCKETLEY_HAS_TLS
    if (!m_ctx)
        return false;
    // Read whole and checked against each other before the context is touched, so a file half written is no change.
    BIO* cb = BIO_new_file(std::string(cert_path).c_str(), "r");
    BIO* kb = BIO_new_file(std::string(key_path).c_str(), "r");
    X509* leaf = cb ? PEM_read_bio_X509(cb, nullptr, nullptr, nullptr) : nullptr;
    STACK_OF(X509)* chain = sk_X509_new_null();
    while (leaf && chain)
    {
        X509* more = PEM_read_bio_X509(cb, nullptr, nullptr, nullptr);
        if (!more)
            break;
        sk_X509_push(chain, more);
    }
    ERR_clear_error();
    EVP_PKEY* key = kb ? PEM_read_bio_PrivateKey(kb, nullptr, nullptr, nullptr) : nullptr;
    // A handshake already begun keeps what it was given; SSL_new copies the context's certificate.
    const bool ok = leaf && key && chain && X509_check_private_key(leaf, key) == 1 &&
                    SSL_CTX_use_cert_and_key(m_ctx, leaf, key, chain, 1) == 1;
    ERR_clear_error();
    if (cb) BIO_free(cb);
    if (kb) BIO_free(kb);
    if (leaf) X509_free(leaf);
    if (key) EVP_PKEY_free(key);
    if (chain) sk_X509_pop_free(chain, X509_free);
    return ok;
#else
    (void)cert_path;
    (void)key_path;
    return false;
#endif
}

bool tls_context::init_client(std::string_view ca_path,
                              std::string_view client_cert,
                              std::string_view client_key)
{
#if SOCKETLEY_HAS_TLS
    m_ctx = SSL_CTX_new(TLS_client_method());
    if (!m_ctx)
    {
        LOG_ERROR("tls: failed to create SSL context");
        log_ssl_errors("SSL_CTX_new");
        return false;
    }
    SSL_CTX_set_min_proto_version(m_ctx, TLS1_2_VERSION);

    // No internal cache on a client, because OpenSSL never reads one: a
    // ClientHello offers the session the application put on the SSL and
    // nothing else, so SSL_SESS_CACHE_CLIENT only filed sessions where no
    // lookup ever went.  Resumption is remember_session() and the
    // SSL_set_session() in create_ssl_client(), which are that lookup.
    SSL_CTX_set_session_cache_mode(m_ctx, SSL_SESS_CACHE_OFF);

    // Apply common performance options (tickets, modes, fragment size)
    apply_ctx_performance_options(m_ctx);

    if (!ca_path.empty())
    {
        if (SSL_CTX_load_verify_locations(m_ctx, std::string(ca_path).c_str(), nullptr) <= 0)
        {
            LOG_ERROR((std::string("tls: failed to load CA file: ") + std::string(ca_path)).c_str());
            log_ssl_errors("CA file load");
            SSL_CTX_free(m_ctx);
            m_ctx = nullptr;
            return false;
        }
        SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER, nullptr);
    }
    else
    {
        load_system_roots(m_ctx);
        SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER, nullptr);
    }

    // mTLS client certificate (for connecting to backends that require client auth)
    if (!client_cert.empty() && !client_key.empty())
    {
        if (SSL_CTX_use_certificate_file(m_ctx, std::string(client_cert).c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            LOG_ERROR((std::string("tls: failed to load client certificate: ") + std::string(client_cert)).c_str());
            log_ssl_errors("client certificate load");
            SSL_CTX_free(m_ctx);
            m_ctx = nullptr;
            return false;
        }
        if (SSL_CTX_use_PrivateKey_file(m_ctx, std::string(client_key).c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            LOG_ERROR((std::string("tls: failed to load client key: ") + std::string(client_key)).c_str());
            log_ssl_errors("client key load");
            SSL_CTX_free(m_ctx);
            m_ctx = nullptr;
            return false;
        }
    }

    return true;
#else
    LOG_ERROR("tls: OpenSSL not available -- rebuild with OpenSSL development headers");
    return false;
#endif
}

SSL* tls_context::create_ssl() const
{
#if SOCKETLEY_HAS_TLS
    if (!m_ctx)
        return nullptr;

    SSL* ssl = SSL_new(m_ctx);
    if (!ssl)
    {
        log_ssl_errors("SSL_new");
        return nullptr;
    }

    // Memory BIO pair and not a socket BIO, so OpenSSL only encodes and
    // decodes and every byte on the wire is carried by an io_uring submission.
    const BIO_METHOD* records = out_method();
    BIO* rbio = BIO_new(BIO_s_mem());
    BIO* wbio = records ? BIO_new(records) : nullptr;
    if (!rbio || !wbio)
    {
        // Never hand SSL_set_bio a half-allocated pair, because which side it
        // takes ownership of when the other is NULL has changed between
        // OpenSSL releases.
        if (rbio) BIO_free(rbio);
        if (wbio) BIO_free(wbio);
        SSL_free(ssl);
        log_ssl_errors("BIO allocation");
        return nullptr;
    }

    BIO_set_nbio(rbio, 1);

    // SSL_free() frees both BIOs from here on; do not free them separately.
    SSL_set_bio(ssl, rbio, wbio);

    // What BIO_read returns from an empty memory BIO: -1 with the retry flag
    // means ask again, where 0 would be read as a closed connection.
    BIO_set_mem_eof_return(rbio, -1);

    return ssl;
#else
    return nullptr;
#endif
}

SSL* tls_context::create_ssl_server() const
{
#if SOCKETLEY_HAS_TLS
    SSL* ssl = create_ssl();
    if (ssl) SSL_set_accept_state(ssl);
    return ssl;
#else
    return nullptr;
#endif
}

SSL* tls_context::create_ssl_client(std::string_view expected_hostname) const
{
#if SOCKETLEY_HAS_TLS
    // SSL_VERIFY_PEER proves only that some trusted CA signed the chain, so
    // the name is pinned per connection before the handshake and arrives as an
    // argument rather than a skippable setter.
    if (expected_hostname.empty())
    {
        LOG_ERROR("tls: refusing client connection: no expected peer name given");
        return nullptr;
    }

    SSL* ssl = create_ssl();
    if (!ssl)
        return nullptr;

    const std::string name(expected_hostname);

    // An address literal is checked against the iPAddress SAN and never sent
    // as SNI, probed with inet_pton so no failed parse leaves a reason on the
    // error queue.
    unsigned char ip_probe[16];
    const bool is_ip = inet_pton(AF_INET,  name.c_str(), ip_probe) == 1 ||
                       inet_pton(AF_INET6, name.c_str(), ip_probe) == 1;

    bool pinned;
    if (is_ip)
    {
        // No SSL_set1_ip_asc convenience wrapper exists the way SSL_set1_host
        // does; go through the connection's verify param directly.
        pinned = X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), name.c_str()) == 1;
    }
    else
    {
        // Reject partial-label wildcards ("w*.example.com"): still issuable,
        // never what an operator writing a backend address meant.
        SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        pinned = SSL_set1_host(ssl, name.c_str()) == 1 &&
                 SSL_set_tlsext_host_name(ssl, name.c_str()) == 1;
    }

    if (!pinned)
    {
        // Fail rather than return a connection that would verify the chain and
        // not the name: a half-verified SSL here is the exact outcome this
        // function exists to prevent, and it would look identical to a good one.
        LOG_ERROR((std::string("tls: failed to pin expected peer name: ") + std::string(name)).c_str());
        log_ssl_errors("peer name setup");
        SSL_free(ssl);   // frees both memory BIOs with it
        return nullptr;
    }

    // The session kept from the last connection to this same peer, offered
    // only on a name match: what the server answers decides whether it is
    // honoured, and a full handshake is the cost of a miss.
    if (m_saved_session && m_saved_peer == name)
    {
        ERR_clear_error();
        if (SSL_set_session(ssl, m_saved_session) != 1)
            log_ssl_errors("session resumption");   // dials on, one handshake dearer
    }

    SSL_set_connect_state(ssl);
    return ssl;
#else
    (void)expected_hostname;
    return nullptr;
#endif
}

void tls_context::remember_session(std::string_view peer_name, SSL* ssl)
{
#if SOCKETLEY_HAS_TLS
    // A handshake that never finished verified nobody, so its session is not offered again.
    if (!ssl || peer_name.empty() || !SSL_is_init_finished(ssl))
        return;

    // A COPY and not a reference to the live one: freeing an SSL whose peer
    // never exchanged close_notify marks that session not_resumable, and the
    // next dial would then send a ClientHello with no PSK in it and say
    // nothing about why.
    SSL_SESSION* live = SSL_get0_session(ssl);
    if (!live)
        return;
    SSL_SESSION* sess = SSL_SESSION_dup(live);
    if (!sess)
    {
        log_ssl_errors("session copy");
        return;
    }

    // What OpenSSL has already marked unusable is not worth keeping.  This is
    // not a check that the TLS 1.3 ticket has arrived -- a session id alone
    // makes it answer true -- and a session without one costs exactly the full
    // handshake it would have cost anyway.
    if (!SSL_SESSION_is_resumable(sess))
    {
        SSL_SESSION_free(sess);
        return;
    }

    if (m_saved_session)
        SSL_SESSION_free(m_saved_session);
    m_saved_session = sess;
    m_saved_peer.assign(peer_name);
#else
    (void)peer_name;
    (void)ssl;
#endif
}

void tls_context::report_inbound_failures()
{
#if SOCKETLEY_HAS_TLS
    std::string line;
    {
        auto& f = inbound();
        if (!f.any.load(std::memory_order_relaxed))
            return;
        std::lock_guard<std::mutex> lk(f.mu);
        const auto now = std::chrono::steady_clock::now();
        if (f.total == 0 || now - f.since < inbound_report_every())
            return;
        std::vector<std::pair<std::string, uint64_t>> top(f.by_reason.begin(), f.by_reason.end());
        std::sort(top.begin(), top.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
        const auto secs = std::chrono::duration_cast<std::chrono::seconds>(now - f.since).count();
        line = "tls: " + std::to_string(f.total) + (f.total == 1 ? " inbound handshake" : " inbound handshakes") +
               " failed in the last " + std::to_string(secs) + " s, a client that does not speak TLS here or a " +
               "scanner most often:";
        for (size_t i = 0; i < top.size() && i < 3; ++i)
            line += (i ? ", " : " ") + top[i].first + " (" + std::to_string(top[i].second) + ")";
        f.by_reason.clear();
        f.total = 0;
        f.any.store(false, std::memory_order_relaxed);
    }
    LOG_INFO(line.c_str());
#endif
}

int tls_context::do_handshake(SSL* ssl)
{
#if SOCKETLEY_HAS_TLS
    ERR_clear_error();   // so whatever we drain below belongs to this call
    int ret = SSL_do_handshake(ssl);
    if (ret == 1)
        return 1;

    int err = SSL_get_error(ssl, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        return 0;

    // A rejected certificate reaches here as a generic protocol error, so the
    // verify result is reported too or an operator is left guessing.
    const long verify = SSL_get_verify_result(ssl);
    const std::string rejected = verify != X509_V_OK
        ? std::string("peer certificate rejected: ") + X509_verify_cert_error_string(verify) + "; " : std::string();
    const ssl_failure f = take_ssl_failure(err);
    // One a stranger failed against a listener of ours is counted; one this side began is ours to fix and said now.
    if (SSL_is_server(ssl))
    {
        LOG_DEBUG(("tls: inbound handshake failed: " + rejected + f.detail).c_str());
        note_inbound_failure(verify != X509_V_OK ? std::string("client certificate rejected") : f.brief);
        return -1;
    }
    LOG_WARN(("tls: handshake failed: " + rejected + f.detail).c_str());
    return -1;
#else
    return -1;
#endif
}

int tls_context::ssl_read(SSL* ssl, char* buf, int len)
{
#if SOCKETLEY_HAS_TLS
    ERR_clear_error();
    int ret = SSL_read(ssl, buf, len);
    if (ret > 0)
        return ret;

    int err = SSL_get_error(ssl, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        return 0;

    if (err == SSL_ERROR_ZERO_RETURN)
    {
        // close_notify is an orderly shutdown and not a failure, but the queue
        // is still emptied so a leftover entry is not blamed on the next
        // connection.
        ERR_clear_error();
        return -1;
    }

    // A peer that went away mid-record is the peer's business on a listener, and ours on a connection we made.
    const ssl_failure f = take_ssl_failure(err);
    if (SSL_is_server(ssl))
        LOG_DEBUG(("tls: read failed: " + f.detail).c_str());
    else
        LOG_WARN(("tls: read failed: " + f.detail).c_str());
    return -1;
#else
    return -1;
#endif
}

int tls_context::ssl_write(SSL* ssl, const char* buf, int len)
{
#if SOCKETLEY_HAS_TLS
    // Outbound half of the buffer cap, reported as 0 rather than an error
    // because the contract for 0 is that the caller retries the same buffer
    // once it has flushed.
    BIO* wbio = SSL_get_wbio(ssl);
    if (wbio && BIO_ctrl_pending(wbio) >= max_bio_buffered)
        return 0;

    ERR_clear_error();
    int ret = SSL_write(ssl, buf, len);
    if (ret > 0)
        return ret;

    int err = SSL_get_error(ssl, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        return 0;

    const ssl_failure f = take_ssl_failure(err);
    if (SSL_is_server(ssl))
        LOG_DEBUG(("tls: write failed: " + f.detail).c_str());
    else
        LOG_WARN(("tls: write failed: " + f.detail).c_str());
    return -1;
#else
    return -1;
#endif
}

int tls_context::bio_read_out(SSL* ssl, char* buf, int len)
{
#if SOCKETLEY_HAS_TLS
    BIO* wbio = SSL_get_wbio(ssl);
    if (!wbio)
        return -1;

    int ret = BIO_read(wbio, buf, len);
    if (ret > 0)
        return ret;
    if (BIO_should_retry(wbio))
        return 0;
    return -1;
#else
    return -1;
#endif
}

int tls_context::bio_write_in(SSL* ssl, const char* buf, int len)
{
#if SOCKETLEY_HAS_TLS
    BIO* rbio = SSL_get_rbio(ssl);
    if (!rbio)
        return -1;
    if (len <= 0)
        return 0;

    // Inbound buffer cap, because SSL consumes a record only once it is whole
    // and a peer that never finishes one would allocate without limit; 512 KB
    // is far above any legitimate need, so this is fatal rather than
    // backpressure.
    const long buffered = static_cast<long>(BIO_ctrl_pending(rbio));
    if (buffered + static_cast<long>(len) > max_bio_buffered)
    {
        LOG_WARN(("tls: inbound buffer limit exceeded (" + std::to_string(buffered) + " + " + std::to_string(len) +
                  " > " + std::to_string(max_bio_buffered) + " bytes unconsumed) -- dropping connection").c_str());
        return -1;
    }

    int ret = BIO_write(rbio, buf, len);
    if (ret > 0)
        return ret;
    if (BIO_should_retry(rbio))
        return 0;
    return -1;
#else
    return -1;
#endif
}

int tls_context::load_system_roots(SSL_CTX* ctx)
{
#if SOCKETLEY_HAS_TLS
    int ok = SSL_CTX_set_default_verify_paths(ctx) == 1 ? 1 : 0;
    // Debian and Ubuntu, Fedora and RHEL, openSUSE, Alpine and Arch: SSL_CERT_FILE and SSL_CERT_DIR still win, since
    // the default above reads them first.
    static const char* const bundles[] = {"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                                          "/etc/ssl/ca-bundle.pem", "/etc/ssl/cert.pem"};
    for (const char* f : bundles)
        if (::access(f, R_OK) == 0 && SSL_CTX_load_verify_locations(ctx, f, nullptr) == 1)
        {
            ok = 1;
            break;
        }
    ERR_clear_error();
    return ok;
#else
    (void)ctx;
    return 0;
#endif
}

void tls_context::enable_h2(bool on)
{
#if SOCKETLEY_HAS_TLS
    if (m_ctx)
        SSL_CTX_set_alpn_select_cb(m_ctx, acme_alpn_select, on ? reinterpret_cast<void*>(1) : nullptr);
#else
    (void)on;
#endif
}

bool tls_context::negotiated_h2(SSL* ssl)
{
#if SOCKETLEY_HAS_TLS
    const unsigned char* p = nullptr;
    unsigned int n = 0;
    SSL_get0_alpn_selected(ssl, &p, &n);
    return n == 2 && p[0] == 'h' && p[1] == '2';
#else
    (void)ssl;
    return false;
#endif
}

size_t tls_context::take_out(SSL* ssl, std::string& out, size_t max)
{
#if SOCKETLEY_HAS_TLS
    out_bio* o = out_of(ssl);
    if (!o)
        return 0;
    const size_t n = std::min(max, o->buf.size() - o->off);
    if (n == 0)
        return 0;
    if (out.empty() && o->off == 0 && n == o->buf.size())
    {
        // The whole of it, by the string itself; the BIO keeps the empty one it was given.
        out.swap(o->buf);
        o->buf.clear();
        return n;
    }
    out.append(o->buf, o->off, n);
    o->off += n;
    if (o->off == o->buf.size())
    {
        o->buf.clear();
        o->off = 0;
    }
    return n;
#else
    (void)ssl;
    (void)out;
    (void)max;
    return 0;
#endif
}

void tls_context::reserve_out(SSL* ssl, size_t n)
{
#if SOCKETLEY_HAS_TLS
    if (out_bio* o = out_of(ssl))
        o->buf.reserve(o->buf.size() + n);
#else
    (void)ssl;
    (void)n;
#endif
}

bool tls_context::has_pending_out(SSL* ssl)
{
#if SOCKETLEY_HAS_TLS
    BIO* wbio = SSL_get_wbio(ssl);
    return wbio && BIO_ctrl_pending(wbio) > 0;
#else
    return false;
#endif
}

bool tls_context::peer_name_matches(SSL* ssl, std::string_view name)
{
#if SOCKETLEY_HAS_TLS
    if (!ssl || name.empty() || SSL_get_verify_result(ssl) != X509_V_OK)
        return false;
    X509* cert = SSL_get1_peer_certificate(ssl);
    if (!cert)
        return false;
    const std::string n(name);
    unsigned char ip_probe[16];
    const bool is_ip = inet_pton(AF_INET,  n.c_str(), ip_probe) == 1 ||
                       inet_pton(AF_INET6, n.c_str(), ip_probe) == 1;
    const bool ok = is_ip ? X509_check_ip_asc(cert, n.c_str(), 0) == 1
                          : X509_check_host(cert, n.c_str(), n.size(),
                                            X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS, nullptr) == 1;
    X509_free(cert);
    return ok;
#else
    (void)ssl;
    (void)name;
    return false;
#endif
}

const char* tls_context::server_name(const SSL* ssl)
{
    return ssl ? SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name) : nullptr;
}

void tls_context::free_ssl(SSL* ssl)
{
#if SOCKETLEY_HAS_TLS
    if (ssl)
        SSL_free(ssl);
#endif
}
