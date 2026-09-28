#pragma once
#include <string>
#include <string_view>
#include <cstdint>

#include "runtime_definitions.h"

// Forward declare OpenSSL types to avoid pulling in headers everywhere
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
typedef struct ssl_session_st SSL_SESSION;

// There is deliberately no way back to tls_conn_none: "give up and carry on in
// cleartext" is the one outcome a TLS transport must never produce.
enum tls_conn_state : uint8_t {
    tls_conn_none      = 0,  // plaintext connection, ssl == nullptr
    tls_conn_handshake = 1,  // records crossing, no application data yet
    tls_conn_ready     = 2   // handshake complete, application data flowing
};

// How long a peer may sit in tls_conn_handshake before the runtime stops
// counting it as a client.  It is not the idle timeout and does not wait for
// one: a quiet connection that DID handshake is legitimate on a daemon built
// for long-living ones, while a peer that has sent nothing the record layer
// accepts has not become a client at all.
//
// Measured before it was written.  A server with --max-connections 2 and two
// TCP connections that send zero bytes refused every real client -- control arm
// ok, loaded arm refused, ok again once the two were gone -- and nothing in the
// tree reclaimed the slots, because the idle sweep is not armed unless
// --idle-timeout is set.
//
// Half a minute rather than seconds, because it is also the sweep's tick and a
// deadline shorter than the tick cannot be honoured anyway.
inline constexpr uint32_t tls_handshake_deadline_secs = 30;

// The one question every place a TLS configuration takes effect asks,
// including the refusal of a TLS cache with --replicate, whose replication
// writes raw bytes around the record layer.
std::string tls_config_refusal(runtime_type type,
                               bool tls,
                               bool udp,
                               std::string_view cert_path,
                               std::string_view key_path,
                               std::string_view ca_path,
                               std::string_view mesh_client_ca = {},
                               std::string_view mesh_client_cert = {},
                               std::string_view mesh_client_key = {},
                               std::string_view cache_replicate_target = {});

// Kept although every type now has a handshake: the next role added to the enum
// starts out without one, and would otherwise silently store flags it cannot honour.
std::string tls_not_implemented_error(std::string_view option);

// The single place that knows, so the flag handler and the start gate cannot
// drift; a function rather than `true` because a fifth type starts out false.
inline bool tls_role_has_handshake(runtime_type type)
{
    return type == runtime_server || type == runtime_proxy ||
           type == runtime_client || type == runtime_cache;
}

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

    // `expected_hostname` is required rather than a setter, because
    // SSL_VERIFY_PEER proves only that some trusted CA signed it.  It is also
    // what decides whether the session kept by remember_session is offered.
    SSL* create_ssl_client(std::string_view expected_hostname) const;

    // Keep this connection's session so the next dial to the same peer resumes
    // it.  Called where the connection ends rather than where it is
    // established, because under TLS 1.3 the ticket that makes a session
    // resumable arrives after the handshake.
    void remember_session(std::string_view peer_name, SSL* ssl);

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

    // Returns bytes written, 0 nothing to do, -1 fatal -- including the peer
    // exceeding max_bio_buffered, where the caller must close rather than retry.
    static int bio_write_in(SSL* ssl, const char* buf, int len);

    // Check if SSL needs to write (has pending encrypted output)
    static bool has_pending_out(SSL* ssl);

    // Free an SSL connection
    static void free_ssl(SSL* ssl);

    // Whether the certificate the peer presented names `name` (a DNS name or an
    // IP address), for a server that learns whom to expect only from what the
    // peer says after the handshake.
    static bool peer_name_matches(SSL* ssl, std::string_view name);

    bool is_initialized() const { return m_ctx != nullptr; }

    // OpenSSL bounds a memory BIO nowhere, so without this a peer that never
    // completes a handshake is an unmetered allocator.
    static constexpr long max_bio_buffered = 512 * 1024;

private:
    // Not public: an SSL built here has no expected peer name attached, which
    // is precisely the mistake create_ssl_client exists to make impossible.
    SSL* create_ssl() const;

    SSL_CTX* m_ctx = nullptr;

    // One session and the name it was taken from.  A resumed handshake carries
    // no certificate, so nothing re-checks the name create_ssl_client pins --
    // which makes the name the key, and a session from any other peer one this
    // context must never offer.
    SSL_SESSION* m_saved_session = nullptr;
    std::string  m_saved_peer;
};
