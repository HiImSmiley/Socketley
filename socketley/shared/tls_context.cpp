#include "tls_context.h"

// Conditionally compile TLS support only if OpenSSL is available
#if __has_include(<openssl/ssl.h>)
#define SOCKETLEY_HAS_TLS 1
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <arpa/inet.h>
#else
#define SOCKETLEY_HAS_TLS 0
#endif

#include <cerrno>
#include <cstring>
#include <iostream>

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
    if ((type == runtime_server || type == runtime_cache) &&
        (!mesh_client_ca.empty() || !mesh_client_cert.empty() || !mesh_client_key.empty()))
    {
        std::string msg(!mesh_client_ca.empty()   ? "--client-ca"
                      : !mesh_client_cert.empty() ? "--client-cert"
                                                  : "--client-key");
        msg += ": configures a proxy's backend leg, and a ";
        msg += type == runtime_server ? "server" : "cache";
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
#if SOCKETLEY_HAS_TLS
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

// Drain OpenSSL's error queue to stderr, because the queue is per-thread and
// persistent, so an entry left behind is reported as the cause of an unrelated
// failure.
static void log_ssl_errors(const char* what, int ssl_err = SSL_ERROR_NONE)
{
    char buf[256];
    bool any = false;
    for (unsigned long e = ERR_get_error(); e != 0; e = ERR_get_error())
    {
        ERR_error_string_n(e, buf, sizeof(buf));
        std::cerr << "[tls] " << what << ": " << buf << "\n";
        any = true;
    }
    if (any)
        return;

    // An empty queue is itself information: SSL_ERROR_SYSCALL with nothing
    // queued means the transport broke under OpenSSL rather than the protocol.
    std::cerr << "[tls] " << what << ": no OpenSSL error queued";
    if (ssl_err != SSL_ERROR_NONE)
        std::cerr << " (" << ssl_error_name(ssl_err) << ")";
    if (ssl_err == SSL_ERROR_SYSCALL)
        std::cerr << " (transport: " << std::strerror(errno) << ")";
    std::cerr << "\n";
}

// Apply SSL_CTX options common to server and client, once, which every
// per-connection SSL object inherits.
static void apply_ctx_performance_options(SSL_CTX* ctx)
{
    // Session tickets for stateless resumption, with SSL_OP_NO_TICKET cleared
    // explicitly although it is off by default.
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

bool tls_context::init_server(std::string_view cert_path, std::string_view key_path,
                              std::string_view client_ca)
{
#if SOCKETLEY_HAS_TLS
    m_ctx = SSL_CTX_new(TLS_server_method());
    if (!m_ctx)
    {
        std::cerr << "[tls] failed to create SSL context\n";
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

    if (SSL_CTX_use_certificate_file(m_ctx, std::string(cert_path).c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "[tls] failed to load certificate: " << cert_path << "\n";
        log_ssl_errors("certificate load");
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(m_ctx, std::string(key_path).c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "[tls] failed to load private key: " << key_path << "\n";
        log_ssl_errors("private key load");
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        return false;
    }

    if (!SSL_CTX_check_private_key(m_ctx))
    {
        std::cerr << "[tls] private key does not match certificate\n";
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
            std::cerr << "[tls] failed to load client CA: " << client_ca << "\n";
            log_ssl_errors("client CA load");
            SSL_CTX_free(m_ctx);
            m_ctx = nullptr;
            return false;
        }
        SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    }

    return true;
#else
    std::cerr << "[tls] OpenSSL not available -- rebuild with OpenSSL development headers\n";
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
        std::cerr << "[tls] failed to create SSL context\n";
        log_ssl_errors("SSL_CTX_new");
        return false;
    }
    SSL_CTX_set_min_proto_version(m_ctx, TLS1_2_VERSION);

    // ── Client-side session caching ──
    // Enable client-side session cache so reconnections to the same server can
    // resume the previous session (avoids full handshake).
    SSL_CTX_set_session_cache_mode(m_ctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_cache_size(m_ctx, 1024);

    // Apply common performance options (tickets, modes, fragment size)
    apply_ctx_performance_options(m_ctx);

    if (!ca_path.empty())
    {
        if (SSL_CTX_load_verify_locations(m_ctx, std::string(ca_path).c_str(), nullptr) <= 0)
        {
            std::cerr << "[tls] failed to load CA file: " << ca_path << "\n";
            log_ssl_errors("CA file load");
            SSL_CTX_free(m_ctx);
            m_ctx = nullptr;
            return false;
        }
        SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER, nullptr);
    }
    else
    {
        SSL_CTX_set_default_verify_paths(m_ctx);
        SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER, nullptr);
    }

    // mTLS client certificate (for connecting to backends that require client auth)
    if (!client_cert.empty() && !client_key.empty())
    {
        if (SSL_CTX_use_certificate_file(m_ctx, std::string(client_cert).c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            std::cerr << "[tls] failed to load client certificate: " << client_cert << "\n";
            log_ssl_errors("client certificate load");
            SSL_CTX_free(m_ctx);
            m_ctx = nullptr;
            return false;
        }
        if (SSL_CTX_use_PrivateKey_file(m_ctx, std::string(client_key).c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            std::cerr << "[tls] failed to load client key: " << client_key << "\n";
            log_ssl_errors("client key load");
            SSL_CTX_free(m_ctx);
            m_ctx = nullptr;
            return false;
        }
    }

    return true;
#else
    std::cerr << "[tls] OpenSSL not available -- rebuild with OpenSSL development headers\n";
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
    BIO* rbio = BIO_new(BIO_s_mem());
    BIO* wbio = BIO_new(BIO_s_mem());
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
    BIO_set_nbio(wbio, 1);

    // SSL_free() frees both BIOs from here on; do not free them separately.
    SSL_set_bio(ssl, rbio, wbio);

    // What BIO_read returns from an empty memory BIO: -1 with the retry flag
    // means ask again, where 0 would be read as a closed connection.
    BIO_set_mem_eof_return(rbio, -1);
    BIO_set_mem_eof_return(wbio, -1);

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
        std::cerr << "[tls] refusing client connection: no expected peer name given\n";
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
        std::cerr << "[tls] failed to pin expected peer name: " << name << "\n";
        log_ssl_errors("peer name setup");
        SSL_free(ssl);   // frees both memory BIOs with it
        return nullptr;
    }

    SSL_set_connect_state(ssl);
    return ssl;
#else
    (void)expected_hostname;
    return nullptr;
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
    long verify = SSL_get_verify_result(ssl);
    if (verify != X509_V_OK)
        std::cerr << "[tls] handshake failed: peer certificate rejected: "
                  << X509_verify_cert_error_string(verify) << "\n";
    log_ssl_errors("handshake failed", err);
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

    log_ssl_errors("read failed", err);
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

    log_ssl_errors("write failed", err);
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
        std::cerr << "[tls] inbound buffer limit exceeded (" << buffered << " + " << len
                  << " > " << max_bio_buffered << " bytes unconsumed) -- dropping connection\n";
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

bool tls_context::has_pending_out(SSL* ssl)
{
#if SOCKETLEY_HAS_TLS
    BIO* wbio = SSL_get_wbio(ssl);
    return wbio && BIO_ctrl_pending(wbio) > 0;
#else
    return false;
#endif
}

void tls_context::free_ssl(SSL* ssl)
{
#if SOCKETLEY_HAS_TLS
    if (ssl)
        SSL_free(ssl);
#endif
}
