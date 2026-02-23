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

bool tls_context::init_server(std::string_view cert_path, std::string_view key_path)
{
#if SOCKETLEY_HAS_TLS
    m_ctx = SSL_CTX_new(TLS_server_method());
    if (!m_ctx)
    {
        std::cerr << "[tls] failed to create SSL context\n";
        return false;
    }
    SSL_CTX_set_min_proto_version(m_ctx, TLS1_2_VERSION);

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

    return true;
#else
    std::cerr << "[tls] OpenSSL not available — rebuild with OpenSSL development headers\n";
    return false;
#endif
}

bool tls_context::init_client(std::string_view ca_path)
{
#if SOCKETLEY_HAS_TLS
    m_ctx = SSL_CTX_new(TLS_client_method());
    if (!m_ctx)
    {
        std::cerr << "[tls] failed to create SSL context\n";
        return false;
    }
    SSL_CTX_set_min_proto_version(m_ctx, TLS1_2_VERSION);

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

    return true;
#else
    std::cerr << "[tls] OpenSSL not available — rebuild with OpenSSL development headers\n";
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
