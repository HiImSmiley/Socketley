#pragma once
#include <string>
#include <string_view>

// Forward declare OpenSSL types to avoid pulling in headers everywhere
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;

// TLS context wrapper for server/client runtimes
// Uses OpenSSL BIO memory pairs for non-blocking integration with io_uring
class tls_context
{
public:
    tls_context();
    ~tls_context();

    // Initialize as server (accept connections)
    // If client_ca is non-empty, enables mTLS (mutual TLS): clients must present a valid cert
    bool init_server(std::string_view cert_path, std::string_view key_path,
                     std::string_view client_ca = {});

    // Initialize as client (connect to server)
    // If client_cert/client_key are non-empty, presents a client certificate (for mTLS)
    bool init_client(std::string_view ca_path = {},
                     std::string_view client_cert = {},
                     std::string_view client_key = {});

    // Create a new SSL connection from this context (use create_ssl_server/client instead)
    SSL* create_ssl() const;

    // Create SSL in server mode (calls SSL_set_accept_state)
    SSL* create_ssl_server() const;
    // Create SSL in client mode (calls SSL_set_connect_state)
    SSL* create_ssl_client() const;

    // Accept a TLS handshake on an SSL object
    // Returns: 1 = complete, 0 = want more data, -1 = error
    static int do_handshake(SSL* ssl);

    // Read decrypted data from SSL
    // Returns bytes read, 0 = want more data, -1 = error/closed
    static int ssl_read(SSL* ssl, char* buf, int len);

    // Write data to SSL (encrypts)
    // Returns bytes written, 0 = want more data, -1 = error
    static int ssl_write(SSL* ssl, const char* buf, int len);

    // Read encrypted data from SSL's output BIO (to send via io_uring)
    static int bio_read_out(SSL* ssl, char* buf, int len);

    // Write encrypted data into SSL's input BIO (received from io_uring)
    static int bio_write_in(SSL* ssl, const char* buf, int len);

    // Check if SSL needs to write (has pending encrypted output)
    static bool has_pending_out(SSL* ssl);

    // Free an SSL connection
    static void free_ssl(SSL* ssl);

    bool is_initialized() const { return m_ctx != nullptr; }

private:
    SSL_CTX* m_ctx = nullptr;
};
