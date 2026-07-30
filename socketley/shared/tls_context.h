#pragma once
#include <string>
#include <string_view>

// Forward declare OpenSSL types to avoid pulling in headers everywhere
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;

// ─── TLS transport is not implemented ───
//
// The tls_context below is a complete OpenSSL wrapper, but nothing constructs
// one.  No runtime feeds socket bytes through it and no runtime performs a
// handshake, so a runtime "configured with TLS" listened in cleartext while
// inspect reported it as encrypted, and a proxy pointed at an HTTPS backend
// sent a plaintext request line.  The first of those is the dangerous one: an
// operator who asks for encryption and is told they have it has no way to
// notice they do not.
//
// So the flags fail closed.  Every TLS option is refused at the point it is
// given and again before a runtime starts, and stays refused until some
// runtime actually drives the handshake.  A flag that errors out is a bad
// afternoon; a flag that silently serves cleartext is a breach.
//
// Returns the name of the first TLS option set in the given configuration, or
// nullptr if none is.  The returned pointer is a string literal.
const char* tls_requested_option(bool tls,
                                 std::string_view cert_path,
                                 std::string_view key_path,
                                 std::string_view ca_path,
                                 std::string_view mesh_client_ca = {},
                                 std::string_view mesh_client_cert = {},
                                 std::string_view mesh_client_key = {});

// The refusal text for `option`, newline-terminated.  Used both on stdout
// (create/edit) and in the IPC response buffer (start/import) so the wording a
// user sees is the same wherever they hit the wall.
std::string tls_not_implemented_error(std::string_view option);

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

    // Create SSL in server mode (calls SSL_set_accept_state)
    SSL* create_ssl_server() const;

    // Create SSL in client mode (calls SSL_set_connect_state).
    //
    // `expected_hostname` is the name the peer's certificate has to be valid
    // for -- the host the caller meant to reach, never a name read back out of
    // the certificate.  It is a required argument rather than an optional
    // setter on purpose: SSL_VERIFY_PEER only proves the chain was signed by a
    // trusted CA, so a certificate legitimately issued for any other host in
    // the world passes it.  A caller who forgets an optional set_hostname()
    // ends up with a connection that looks verified and is not; a caller who
    // forgets this argument does not compile.
    //
    // Pass the literal address for an IP-addressed peer ("10.0.0.7"): it is
    // matched against the certificate's iPAddress SAN, and SNI is suppressed,
    // because RFC 6066 allows host names there only.
    //
    // Returns nullptr if the name is empty or cannot be installed -- there is
    // deliberately no path to a client SSL without name checking.
    SSL* create_ssl_client(std::string_view expected_hostname) const;

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
    // Returns bytes read, 0 = nothing pending, -1 = error
    static int bio_read_out(SSL* ssl, char* buf, int len);

    // Write encrypted data into SSL's input BIO (received from io_uring)
    // Returns bytes written, 0 = nothing to do, -1 = error.
    // -1 includes the peer having more than max_bio_buffered bytes unconsumed
    // in this connection's input BIO, and is fatal for the connection: the
    // caller must free_ssl() and close the socket rather than retry.
    static int bio_write_in(SSL* ssl, const char* buf, int len);

    // Check if SSL needs to write (has pending encrypted output)
    static bool has_pending_out(SSL* ssl);

    // Free an SSL connection
    static void free_ssl(SSL* ssl);

    bool is_initialized() const { return m_ctx != nullptr; }

    // Ceiling on the bytes one connection may have buffered in either memory
    // BIO.  A memory BIO grows to hold whatever is written to it and OpenSSL
    // bounds it nowhere, so without this a peer that never completes a
    // handshake is an unmetered allocator inside a daemon that otherwise caps
    // its connections.  Enforced in bio_write_in (inbound, fatal) and ssl_write
    // (outbound, backpressure).
    static constexpr long max_bio_buffered = 512 * 1024;

private:
    // Not public: an SSL built here has no expected peer name attached, which
    // is precisely the mistake create_ssl_client exists to make impossible.
    SSL* create_ssl() const;

    SSL_CTX* m_ctx = nullptr;
};
