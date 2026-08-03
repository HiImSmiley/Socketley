#pragma once
#include <string>
#include <string_view>
#include <cstdint>

#include "runtime_definitions.h"

// Forward declare OpenSSL types to avoid pulling in headers everywhere
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;

// Where a TLS connection is in its handshake.  A plaintext connection is
// tls_conn_none and has no SSL at all; there is deliberately no way back from
// tls_conn_handshake to tls_conn_none, because "give up and carry on in
// cleartext" is the one outcome a TLS transport must never produce.
//
// Lives here rather than beside one runtime's connection struct: the server's
// listener and the proxy's two legs run the same state machine over the same
// memory BIO pair, and a second spelling of it would be a second thing to keep
// in step.
enum tls_conn_state : uint8_t {
    tls_conn_none      = 0,  // plaintext connection, ssl == nullptr
    tls_conn_handshake = 1,  // records crossing, no application data yet
    tls_conn_ready     = 2   // handshake complete, application data flowing
};

// ─── What this build can honour ───
//
// Every runtime type has a handshake behind it now:
//
//   * a **server runtime's own listener** — accept, handshake and record layer
//     driven by io_uring completions through the memory BIO pair below; see
//     server_instance's tls_feed/tls_flush.
//   * a **proxy runtime**, on either leg.  Its listening port terminates TLS
//     exactly as a server's does, and its backend leg dials one — verifying
//     the chain and the endpoint's name, and presenting a client certificate
//     when the mesh options ask for it.
//   * a **client runtime's outbound socket** — the same dial as the proxy's
//     backend leg, with the same verification: create_ssl_client pins the host
//     from `-t` before the ClientHello and there is no way to switch that off.
//   * a **cache runtime's own listener** — the server's design over the cache's
//     connection struct: memory BIO pair, ciphertext moved by the same
//     io_uring submissions, RESP and the line protocol reading the decrypted
//     stream exactly as they always did.  See cache_instance's
//     tls_feed/tls_flush.
//
// What a cache still cannot do over TLS is *replicate*, and that is the one
// asymmetry left in here.  Replication is not a listener: a follower dials its
// leader from connect_to_master(), and on the leader a promoted follower gets
// a second writer that submits raw bytes straight at the descriptor, around
// the record layer that owns it.  Neither of those speaks TLS, so a cache that
// terminated TLS on its port and went on replicating would put the whole
// dataset — dump and live command stream — in the clear, out of a runtime the
// operator configured for encryption and `inspect` reports as encrypted.
//
// That is the same dangerous shape the flags used to have, so it fails closed
// the same way: a TLS cache carrying --replicate is refused here, and a TLS
// cache asked to become a leader by a REPLICATE command is refused at the
// command.  Half an encrypted cache is worse than an honestly cleartext one.
//
// tls_config_refusal is the single question every place a TLS configuration is
// about to take effect asks — flag parsing, `edit`, `import`, and the last
// gate before a runtime is started.  It returns the refusal text,
// newline-terminated, or an empty string when the configuration is one this
// build can honour.  A half-written configuration is refused too, on every
// role that has one: --tls with no certificate on a *listener*, a certificate
// with no --tls, half a client-certificate pair, or a client CA for a listener
// that is not encrypted.  Each of those describes something that could only
// run in cleartext or verify nothing.
//
// A client runtime is the one role where --tls on its own is complete: it has
// no listener to present a certificate on, and the trust store it verifies the
// peer against defaults to the system one.  --cert/--key there are the
// certificate it *presents*, for a peer that asks for mutual TLS.
//
// `cache_replicate_target` is the cache's --replicate address, empty for every
// other role and for a cache that does not replicate.  It is a parameter
// rather than a check made at the cache because this function is the one place
// that answers "may this configuration take effect?", and a rule enforced
// anywhere else is a rule the restore path can walk around.
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

// The refusal text for `option`, newline-terminated.  Used both on stdout
// (create/edit) and in the IPC response buffer (start/import) so the wording a
// user sees is the same wherever they hit the wall.
//
// Kept although every runtime_type now answers true to tls_role_has_handshake
// below: this is the text for "the role holding this flag drives no
// handshake", and the next role added to the enum starts out being exactly
// that.  Deleting it would mean the next one silently stores flags it cannot
// honour, which is the failure this whole file is built against.
std::string tls_not_implemented_error(std::string_view option);

// Whether a runtime of this type performs a handshake at all.  The single
// place that knows, so that a flag handler asking "may I store this?" and the
// start gate asking "may this come up?" cannot drift apart.
//
// All four types do, as of the cache listener.  It stays a function rather
// than becoming `true` at every call site because the question is about a
// role, not about this moment: a fifth runtime type is added to the enum
// before anybody writes its record layer, and it has to answer false in the
// meantime.
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
