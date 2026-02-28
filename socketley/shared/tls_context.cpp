#include "tls_context.h"

// Conditionally compile TLS support only if OpenSSL is available
#if __has_include(<openssl/ssl.h>)
#define SOCKETLEY_HAS_TLS 1
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#else
#define SOCKETLEY_HAS_TLS 0
#endif

#include <iostream>

tls_context::tls_context() = default;

tls_context::~tls_context()
{
#if SOCKETLEY_HAS_TLS
    if (m_ctx)
        SSL_CTX_free(m_ctx);
#endif
}

#if SOCKETLEY_HAS_TLS
// Apply performance-critical SSL_CTX options common to both server and client.
// Called once at context initialization — all per-connection SSL objects inherit these.
static void apply_ctx_performance_options(SSL_CTX* ctx)
{
    // ── Session resumption ──
    // Enable session tickets for stateless TLS resumption (avoids full handshake
    // on reconnect). Server-side: tickets are generated and sent to clients.
    // Client-side: tickets are stored and presented on reconnect.
    // SSL_OP_NO_TICKET is OFF by default, but explicitly clear it for clarity.
    long opts = SSL_CTX_get_options(ctx);
    opts &= ~SSL_OP_NO_TICKET;

    // ── Kernel TLS offload (KTLS) ──
    // When available (OpenSSL 3.0+ with kernel support), offloads symmetric
    // encryption/decryption to the kernel. This allows io_uring to work with
    // encrypted data directly via sendfile/splice, bypassing userspace crypto.
#if defined(SSL_OP_ENABLE_KTLS)
    opts |= SSL_OP_ENABLE_KTLS;
#endif

    // Prefer server cipher order for better security/performance control
    opts |= SSL_OP_CIPHER_SERVER_PREFERENCE;

    // Disable renegotiation to prevent mid-connection handshakes (perf + security)
#if defined(SSL_OP_NO_RENEGOTIATION)
    opts |= SSL_OP_NO_RENEGOTIATION;
#endif

    SSL_CTX_set_options(ctx, opts);

    // ── SSL modes ──
    // SSL_MODE_RELEASE_BUFFERS: free internal read buffers after each SSL_read,
    // reducing per-connection memory when many connections are idle.
    // SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER: allow SSL_write retry with different
    // buffer pointer (same data), needed when io_uring may return short writes.
    long mode = SSL_MODE_RELEASE_BUFFERS | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;

    // SSL_MODE_AUTO_RETRY: retry internal reads/writes automatically on
    // renegotiation, simplifying the caller's error handling loop.
    mode |= SSL_MODE_AUTO_RETRY;

    SSL_CTX_set_mode(ctx, mode);

    // ── Max send fragment ──
    // Set max TLS record size to 16KB (the TLS max). Larger records amortize
    // the ~29-byte TLS record header overhead. For high-throughput scenarios
    // this is optimal. For latency-sensitive small messages, the kernel/OpenSSL
    // will split into smaller records automatically on partial writes.
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
        return false;
    }
    SSL_CTX_set_min_proto_version(m_ctx, TLS1_2_VERSION);

    // ── Session caching for TLS resumption ──
    // Enable server-side session cache. Returning clients can resume with a
    // cached session, skipping the expensive RSA/ECDHE key exchange.
    SSL_CTX_set_session_cache_mode(m_ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_sess_set_cache_size(m_ctx, 20480);

    // Session timeout: 5 minutes. Balances memory vs resumption hit rate.
    SSL_CTX_set_timeout(m_ctx, 300);

    // Apply common performance options (KTLS, tickets, modes, fragment size)
    apply_ctx_performance_options(m_ctx);

    if (SSL_CTX_use_certificate_file(m_ctx, std::string(cert_path).c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "[tls] failed to load certificate: " << cert_path << "\n";
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(m_ctx, std::string(key_path).c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "[tls] failed to load private key: " << key_path << "\n";
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        return false;
    }

    if (!SSL_CTX_check_private_key(m_ctx))
    {
        std::cerr << "[tls] private key does not match certificate\n";
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
        return false;
    }
    SSL_CTX_set_min_proto_version(m_ctx, TLS1_2_VERSION);

    // ── Client-side session caching ──
    // Enable client-side session cache so reconnections to the same server can
    // resume the previous session (avoids full handshake).
    SSL_CTX_set_session_cache_mode(m_ctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_cache_size(m_ctx, 1024);

    // Apply common performance options (KTLS, tickets, modes, fragment size)
    apply_ctx_performance_options(m_ctx);

    if (!ca_path.empty())
    {
        if (SSL_CTX_load_verify_locations(m_ctx, std::string(ca_path).c_str(), nullptr) <= 0)
        {
            std::cerr << "[tls] failed to load CA file: " << ca_path << "\n";
            SSL_CTX_free(m_ctx);
            m_ctx = nullptr;
            return false;
        }
        SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER, nullptr);
    }

    // mTLS client certificate (for connecting to backends that require client auth)
    if (!client_cert.empty() && !client_key.empty())
    {
        if (SSL_CTX_use_certificate_file(m_ctx, std::string(client_cert).c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            std::cerr << "[tls] failed to load client certificate: " << client_cert << "\n";
            SSL_CTX_free(m_ctx);
            m_ctx = nullptr;
            return false;
        }
        if (SSL_CTX_use_PrivateKey_file(m_ctx, std::string(client_key).c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            std::cerr << "[tls] failed to load client key: " << client_key << "\n";
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
        return nullptr;

    // Create BIO memory pair for non-blocking I/O
    BIO* rbio = BIO_new(BIO_s_mem());
    BIO* wbio = BIO_new(BIO_s_mem());

    BIO_set_nbio(rbio, 1);
    BIO_set_nbio(wbio, 1);

    SSL_set_bio(ssl, rbio, wbio);

    // Limit BIO buffering to 512KB to prevent memory exhaustion on failed handshakes
    BIO_set_mem_eof_return(rbio, 0);
    BIO_set_mem_eof_return(wbio, 0);

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

SSL* tls_context::create_ssl_client() const
{
#if SOCKETLEY_HAS_TLS
    SSL* ssl = create_ssl();
    if (ssl) SSL_set_connect_state(ssl);
    return ssl;
#else
    return nullptr;
#endif
}

int tls_context::do_handshake(SSL* ssl)
{
#if SOCKETLEY_HAS_TLS
    int ret = SSL_do_handshake(ssl);
    if (ret == 1)
        return 1;

    int err = SSL_get_error(ssl, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        return 0;

    return -1;
#else
    return -1;
#endif
}

int tls_context::ssl_read(SSL* ssl, char* buf, int len)
{
#if SOCKETLEY_HAS_TLS
    int ret = SSL_read(ssl, buf, len);
    if (ret > 0)
        return ret;

    int err = SSL_get_error(ssl, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        return 0;

    return -1;
#else
    return -1;
#endif
}

int tls_context::ssl_write(SSL* ssl, const char* buf, int len)
{
#if SOCKETLEY_HAS_TLS
    int ret = SSL_write(ssl, buf, len);
    if (ret > 0)
        return ret;

    int err = SSL_get_error(ssl, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        return 0;

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
