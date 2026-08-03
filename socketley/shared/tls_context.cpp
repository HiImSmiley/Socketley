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

// ─── TLS configuration gate ───
// See the header for what this build honours and what it still refuses.  It
// deliberately lives next to the OpenSSL wrapper: whoever wires up the next
// role — a server runtime's upstream leg, a cache's replication link — will be
// reading this file, and narrowing the gate is part of that work.

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

    // A datagram socket has no handshake to put TLS on; that would be DTLS, and
    // there is none here.
    //
    // The rule lived in server_instance::setup() and client_instance::setup(),
    // written out twice, and a placeholder for a runtime in a worker never runs
    // either — start() returns as soon as the child is forked, because binding
    // and dialling happen over there.  So `create client x --udp --tls -s` was
    // refused and unwound in the daemon and accepted out of process, where the
    // worker discovered it a moment later and the runtime was left `failed`
    // instead of never existing.  Two answers to one impossible configuration,
    // decided by where it was going to run.
    //
    // It is a question about two flags. It needs no socket, so it belongs with
    // the other questions about flags, and it is asked once.
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
    // ── a client runtime: one leg, and it dials ──
    //
    // Handled before the listener rules below because it has no listener at
    // all, and every one of them would ask this configuration for something it
    // has no place to put.  --tls on its own is the complete configuration
    // here: create_ssl_client pins the host from -t and verifies the chain
    // against the system store, and neither of those is optional.
    if (type == runtime_client)
    {
        // The mesh options configure a proxy: --client-ca verifies certificates
        // presented by clients, which needs a listener, and
        // --client-cert/--client-key name a second leg this role does not have.
        // The certificate a client presents is --cert/--key, below.
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

        // The certificate this client presents is a pair.  Half of one loads
        // nothing, so the dial would present nothing at all and a peer
        // requiring mutual TLS would refuse it -- after the flags said it was
        // configured.
        if (cert_path.empty() != key_path.empty())
            return cert_path.empty()
                ? std::string("--key: needs --cert <file> as well -- a key with no "
                              "certificate presents nothing\n")
                : std::string("--cert: needs --key <file> as well -- a certificate "
                              "with no key presents nothing\n");

        return {};
    }

    // The mesh client-certificate options describe a *backend* leg, and
    // neither a server nor a cache runtime has one: it would store them,
    // report them and dial nothing.  (The flag handlers do not offer them on
    // either at all; this catches a state file or an imported document that
    // carries them.)
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

    // ── the listener half, identical for both roles ──
    //
    // A listener that terminates TLS needs something to terminate it with.
    // Half a configuration is refused rather than half-honoured, in both
    // directions: --tls without a key pair could only ever fall back to
    // cleartext, and a certificate without --tls is an operator who believes
    // the port is encrypted and has not turned it on.
    //
    // --ca is the exception on a proxy, and only there: it is that role's
    // trust store for the *backend* leg (see below), not a listener option.
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

    // ── a cache that encrypts its port and replicates out of it ──
    //
    // The listener above is honoured; the replication link is not encrypted by
    // anything and cannot be, so the two together describe a cache that
    // encrypts what clients send it and then puts the identical data on the
    // wire in the clear.
    //
    // Two separate cleartext paths, neither of which is the listener:
    //
    //   * this cache as a *follower* — connect_to_master() opens the socket
    //     itself, sends "replicate\n" with a bare write(2) and reads the
    //     leader's whole dump back.  No session, no verification, and no name
    //     to verify against: --replicate is parsed with inet_pton, so the
    //     target is always an address literal and there is no trust store on a
    //     cache to check a chain against — its --ca is the *client* CA for its
    //     own listener, exactly as a server's is.
    //   * this cache as a *leader* — a promoted follower is written to by
    //     follower_conn, which submits raw bytes straight at the descriptor
    //     around the record layer that owns it.  That second writer is
    //     deliberate and load-bearing (see handle_replicate_request), and it is
    //     what makes "encrypted for clients, cleartext for replicas" the
    //     default outcome rather than a corner case.
    //
    // So the configuration is refused rather than half-honoured.  The leader
    // half cannot be caught here at all — a cache becomes a leader when a
    // client sends REPLICATE, long after any configuration was validated — so
    // that one is refused at the command, in handle_replicate_request().  This
    // covers the half that *is* configuration.
    if (type == runtime_cache && tls && !cache_replicate_target.empty())
        return "--replicate: a cache's replication link is not encrypted -- it "
               "dials its leader in cleartext and would stream this cache's "
               "whole dataset off a port --tls says is encrypted.  Refusing "
               "rather than encrypting one half: drop --replicate, or drop "
               "--tls and be honestly cleartext\n";

    if (type != runtime_proxy)
        return {};

    // ── the proxy's own options ──
    //
    // --client-ca verifies certificates presented *by clients*, which only a
    // listener that speaks TLS can ask any client for.  On a cleartext port it
    // would authenticate nobody while inspect reported mutual TLS.
    if (!mesh_client_ca.empty() && !tls)
        return "--client-ca: verifies the certificates clients present, which "
               "needs --tls --cert --key on this proxy's own listener -- on a "
               "cleartext port it would authenticate nobody\n";

    // A client certificate is a pair.  Half of one loads nothing, so the
    // backend leg would connect without presenting anything at all and a
    // backend requiring mutual TLS would refuse it — after the flags said it
    // was configured.
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

// Drain OpenSSL's error queue to stderr, one line per queued reason.
//
// Every failure below used to report a bare "handshake failed" / "failed to
// load certificate".  The half of the message that matters -- expired cert,
// unknown CA, no shared cipher, a client speaking plain HTTP at a TLS port,
// wrong passphrase on the key file -- was already sitting on OpenSSL's
// thread-local error queue and nobody popped it, so an operator got a symptom
// and no cause.  Draining is not optional bookkeeping either: the queue is
// per-thread and persistent, so an entry left behind resurfaces later and is
// reported as the diagnosis for some unrelated connection's failure.
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

    // ── No kernel TLS here, by design ──
    // SSL_OP_ENABLE_KTLS used to be set on this line. It could never do
    // anything: KTLS requires the SSL object to sit on a socket BIO so OpenSSL
    // can hand the kernel the file descriptor and the traffic keys, and this
    // wrapper deliberately gives every connection a memory BIO pair instead
    // (see create_ssl). That choice is the whole point of the design -- with
    // memory BIOs OpenSSL is a codec and nothing else, every network byte is
    // still moved by an io_uring submission, and there is exactly one place in
    // the daemon that talks to sockets. A socket BIO would take reads and
    // writes back into OpenSSL's own blocking syscalls, behind the event
    // loop's back. So the option was a no-op that advertised an optimisation
    // the transport is not built for: don't put it back without moving off
    // memory BIOs first.

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
        log_ssl_errors("SSL_CTX_new");
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

    // Memory BIO pair, not a socket BIO: OpenSSL only ever encodes and decodes
    // here, and every byte on the wire is carried by an io_uring submission.
    // See apply_ctx_performance_options for what that costs us (KTLS) and why
    // it is worth it.
    BIO* rbio = BIO_new(BIO_s_mem());
    BIO* wbio = BIO_new(BIO_s_mem());
    if (!rbio || !wbio)
    {
        // Never hand SSL_set_bio a half-allocated pair. Which side it takes
        // ownership of when the other is NULL has changed between OpenSSL
        // releases, so the survivor either leaks or gets freed twice -- and the
        // one situation that makes BIO_new fail is the situation where leaking
        // matters. Refuse the connection instead; the caller sees nullptr and
        // drops the socket.
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

    // What this actually does: decide what BIO_read returns from an *empty*
    // memory BIO. -1 plus the retry flag means "nothing yet, ask again", which
    // is what an empty buffer means in a non-blocking design; 0 would mean EOF,
    // and OpenSSL would read a drained buffer as a closed connection -- which
    // it did, on the value that was here. A peer that really has gone is
    // signalled by the caller tearing the connection down after its io_uring
    // read returns 0; it is never inferred from this buffer being empty.
    //
    // What it does not do: limit anything. The comment that stood here claimed
    // it capped buffering at 512KB. It never has -- BIO_set_mem_eof_return has
    // no size argument and no relation to the buffer's growth -- so the daemon
    // carried a documented protection that did not exist. The real cap is
    // max_bio_buffered, enforced in bio_write_in and ssl_write below.
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
    // ── Hostname verification ──
    // init_client sets SSL_VERIFY_PEER, which proves only that some trusted CA
    // signed the chain. It says nothing about *who* the chain was issued to, so
    // a certificate for any unrelated host -- one anybody can buy for a domain
    // they own -- satisfied it, and a peer that redirected the connection to
    // itself was accepted as the intended backend. The name has to be pinned
    // per connection, before the handshake, which is why it arrives here as an
    // argument instead of a setter someone can skip.
    if (expected_hostname.empty())
    {
        std::cerr << "[tls] refusing client connection: no expected peer name given\n";
        return nullptr;
    }

    SSL* ssl = create_ssl();
    if (!ssl)
        return nullptr;

    const std::string name(expected_hostname);

    // An address literal has to be checked against the certificate's iPAddress
    // SAN, and must not be sent as SNI at all (RFC 6066 allows host names
    // there only; some servers reject the handshake outright when it is). The
    // probe is inet_pton rather than just trying the IP form first, because a
    // failed parse in there pushes a reason onto the error queue that would
    // then be drained and reported as the cause of an unrelated failure.
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

    // A rejected certificate reaches here as a generic protocol error. The
    // useful half of the diagnosis -- expired, self-signed, name mismatch -- is
    // in the verify result and is not on the error queue at all, so report both
    // or an operator is left guessing which of the two went wrong.
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
        // close_notify: an orderly shutdown by the peer, not a failure. Still
        // empty the queue -- a leftover entry would be blamed on the next
        // connection that does fail.
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
    // Outbound half of the buffer cap. SSL_write appends ciphertext to the
    // write BIO whether or not anyone is draining it, so a peer that stops
    // reading would otherwise let a fast producer buffer without limit -- the
    // same unbounded growth as the inbound side, just driven from our end.
    // Report 0 ("want more data") rather than an error: the contract for 0 is
    // that the caller retries this same buffer once it has flushed, which is
    // exactly the right answer to backpressure, and the connection survives.
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

    // ── Inbound buffer cap ──
    // A memory BIO grows to hold whatever is written into it; nothing in
    // OpenSSL bounds it, and BIO_set_mem_eof_return -- which the comment in
    // create_ssl used to claim did -- has nothing to do with size. Handshake
    // records are the cheap way to abuse that: SSL only consumes a record once
    // it is whole, so a peer that sends a few hundred bytes at a time and never
    // finishes leaves every byte of it sitting here. One connection, no
    // authentication needed, unlimited allocation, inside a daemon that goes to
    // the trouble of capping connection counts everywhere else.
    //
    // 512KB is far above any legitimate need: a TLS record maxes out at 16KB
    // and a large certificate chain is a few tens of KB, so a connection that
    // reaches this is either broken or hostile. Either way it does not recover
    // by being fed more, so this is fatal rather than backpressure -- the
    // caller's contract for -1 is free_ssl() plus close, and nothing is
    // allocated here to leak on the way out.
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
