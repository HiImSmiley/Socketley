#pragma once
#include <string>
#include <string_view>
#include <unordered_map>
#include <memory>
#include <vector>
#include <queue>
#include <random>
#include <optional>
#include <functional>
#include <netinet/in.h>
#include <sys/uio.h>

#include "../../shared/runtime_instance.h"
#include "../../shared/route_table.h"
#include "../../shared/write_queue.h"
#include "../../shared/event_loop_definitions.h"
#include "../../shared/tls_context.h"
#include "../../shared/trace.h"
#include "../../shared/invariants.h"
#include "../../shared/http_framing.h"

class runtime_manager;

enum proxy_protocol : uint8_t { protocol_http = 0, protocol_tcp = 1 };
enum proxy_strategy : uint8_t { strategy_round_robin = 0, strategy_random = 1, strategy_lua = 2 };
enum conn_side : uint8_t { conn_none = 0, conn_client, conn_backend };

// What the bytes received from a client so far amount to.  This used to be a
// bool where false meant "need more data", which left the smuggling check no
// way to say "this request is malformed".  It signalled a rejection by
// returning false — so the connection went back and asked for more bytes, and
// no quantity of further bytes could ever make the request acceptable.  The
// client got a 431 once the header limit was hit, or nothing at all until the
// idle timeout, instead of being told its request was refused.
enum class http_request_parse : uint8_t
{
    need_more,  // header block not complete yet — read again
    complete,   // request line and header block parsed; safe to forward
    invalid,    // ambiguous or self-contradictory framing — 400, never forward
};

struct backend_info
{
    std::string address;
    std::string resolved_host;
    uint16_t resolved_port = 0;
    bool is_group = false;
    bool has_cached_addr = false;
    // Whether this backend is reached over TLS.  Two things turn it on, and
    // both are explicit: an `https://` address turns it on for this backend
    // alone, and the backend-TLS options (--ca, --client-cert/--client-key)
    // turn it on for every backend at once — none of them means anything
    // against a cleartext peer, so honouring them without encrypting would be
    // the fail-open half of this flag.
    bool tls = false;
    // A backend reached over AF_UNIX, from `--backend unix:/path/to.sock`.
    //
    // A sidecar proxy and the process it fronts are on one host, and loopback
    // TCP charges that pair for a full stack — sequence numbers, checksums,
    // windows, a three-way handshake — on a connection that never sees a wire.
    // Measured as a strict 64-byte ping-pong between two processes, unpinned:
    // TCP 17.93us against UNIX 9.83us.
    //
    // resolved_host carries the path and resolved_port stays 0, which is what
    // the two of them together mean everywhere else: "not an endpoint on the
    // network".  Everything that writes a `host:port` — the Host header rewrite
    // above all — already refuses on port 0 and goes on refusing.  The
    // connection pool is the one place that wants a key rather than an address,
    // and (path, 0) serves as one because resolve_backend refuses a path that is
    // not absolute: a leading '/' is something no hostname and no dotted quad
    // can produce, so a unix key cannot collide with a TCP key whatever the
    // port.
    bool is_unix = false;
    std::string unix_path;
    struct sockaddr_in cached_addr{};
};

struct resolved_backend
{
    std::string host;
    uint16_t port = 0;
    // Deliberately no `tls` here.  A group's members have no address of their
    // own to carry an https:// scheme, so the only thing that can encrypt the
    // leg to one is the backend-TLS options — which apply to every backend at
    // once.  proxy_instance::conn_backend_tls answers it from there rather
    // than from a copy that would have to be kept in step.
};

// 64KB read buffer for high-throughput TCP forwarding.
// The bottleneck is often the number of read syscalls — larger buffers
// amortize the per-syscall overhead across more data.
static constexpr size_t PROXY_READ_BUF_SIZE = 65536;

// How long a client may take to finish the header block of a request once it
// has started sending one.  Deliberately not a flag and deliberately not tied
// to --idle-timeout: an operator who has never heard of either still gets this,
// and --idle-timeout's default of 0 ("never") must not be able to switch off a
// bound on half-finished requests.  Ten seconds is far outside anything a
// working client does — a header block is one or two segments — and far inside
// how long an attacker would like to hold the connection.  It bounds only the
// gap between the first byte of a request and its terminating blank line;
// neither an idle keep-alive connection between requests nor a slow body is
// measured against it.
static constexpr int PROXY_HEADER_TIMEOUT_SEC = 10;

struct alignas(64) proxy_client_connection
{
    static constexpr size_t MAX_WRITE_BATCH = 16;
    static constexpr size_t MAX_PARTIAL_SIZE = 1 * 1024 * 1024;
    static constexpr size_t MAX_HEADER_SIZE = 16384;

    // === HOT fields (CQE dispatch) — first 2 cache lines ===
    int fd;
    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};
    bool zc_notif_pending{false};
    bool splice_active{false};
    bool splice_in_pending{false};
    bool splice_out_pending{false};
    bool header_parsed{false};
    bool response_started{false};
    bool client_conn_close{false};  // client sent Connection: close
    int backend_fd{-1};
    uint32_t write_batch_count{0};
    io_request read_req;
    io_request write_req;

    // === TLS session (listener leg) ===
    // Non-null only on a proxy configured with --tls.  OpenSSL never sees this
    // socket: the session is fed ciphertext a read completion delivered and
    // drained of ciphertext a write submission carries, so nothing the kernel
    // holds ever names it or its memory BIOs — every byte is copied into or
    // out of a buffer this struct owns before any SQE is built.  That is what
    // makes the session safe to free the moment the struct is released, unlike
    // the write batch beside it.
    //
    // Plaintext goes into `partial`, where the HTTP path already looks for it;
    // TCP mode takes it from there and forwards it.
    SSL* ssl{nullptr};
    tls_conn_state tls_state{tls_conn_none};
    // The peer's close_notify, remembered rather than acted on.  The read that
    // carries it can carry the last request ahead of it, and marking the
    // connection closing before that request is parsed answers it with a
    // dropped connection.
    bool tls_peer_closed{false};

    // === WARM fields ===
    io_request splice_in_req;
    io_request splice_out_req;
    std::string partial;
    socketley::byte_counted_queue<std::string> write_queue;
    std::string write_batch[MAX_WRITE_BATCH];
    struct iovec write_iovs[MAX_WRITE_BATCH];

    // === COLD fields ===
    int pipe_to_backend[2]{-1, -1};
    std::string method;
    std::string path;
    std::string version;

    // How the request whose header block was just parsed frames its own body.
    // Written by parse_http_request_line, read once by rewrite_http_request.
    size_t declared_body_len{0};
    bool declared_body_chunked{false};

    // How much of the current request's body has still to be forwarded, and
    // whether that number means anything.
    //
    // Everything past the header terminator used to be forwarded verbatim, and
    // "everything" is whatever the client chose to put there: a second request
    // pipelined behind the first went to the backend without passing a single
    // one of the checks in parse_http_request_line, which only ever looks at the
    // first message in the buffer.  Putting the payload second was therefore
    // enough to bypass the CL+TE rejection, the duplicate-Content-Length
    // rejection and the whole of the framing scan.  Only the body a request
    // actually declared may follow it; the rest stays buffered and is parsed as
    // a request of its own.
    //
    // body_unbounded is the one case where no such number exists: a chunked
    // request, which this proxy forwards byte for byte and never de-chunks (see
    // rewrite_http_request).  Its body streams on as before.
    size_t body_remaining{0};
    bool body_unbounded{false};

    // Request headers a filter set on the request now being parsed, applied by
    // rewrite_http_request on the way out.  Per request and not per connection:
    // cleared between requests on a keep-alive socket, or the second request
    // would carry the first one's identity.  Empty — and never touched — on a
    // proxy whose script declares no chain.
    std::vector<std::pair<std::string, std::string>> filter_headers;

    // Names a filter asked to be taken *off* the request, lowercased, applied
    // by the same loop in rewrite_http_request that applies the ones above.
    // Same lifetime rules and the same ban list: a filter that could remove
    // Content-Length or Transfer-Encoding would change how the message is
    // framed, and a proxy that frames a request differently from its backend
    // is the whole of request smuggling.
    std::vector<std::string> filter_removed_headers;

    std::chrono::steady_clock::time_point last_activity{};
    int retries_remaining{0};
    size_t backend_idx{0};
    std::string saved_request;

    // Group routing (@groupname) picks a member per connection, so backend_idx
    // does not identify the target — it still points at the group entry, whose
    // resolved_host/resolved_port are deliberately left unset.  These carry the
    // endpoint that was actually selected.
    // The client sent FIN while the backend connect was still in flight; its
    // buffered payload still has to go out before this pair is torn down.
    // Bumped on every reuse from the pool; stamped into io_requests so late
    // completions from the previous occupant can be recognised and dropped.
    uint32_t generation{0};
    // One re-attempt when a connect completion turns out to reference a
    // descriptor that is no longer valid.  That is an internal inconsistency,
    // not a refusal by the backend, and it must not cost the client its
    // connection.  Bounded so a persistent problem still surfaces.
    bool connect_reattempted{false};
    // The client has shut its write side.  It will send nothing more; it is
    // still reading, and whatever it already asked for still has somewhere to
    // go.  Set on the EOF completion and nowhere else, on both the copy path
    // and the splice path.
    bool client_eof{false};
    // …and that half-close has been passed on to the backend socket with
    // shutdown(SHUT_WR).  TCP mode only: there is no framing to tell a backend
    // where the request ended, so the FIN is the only thing that can, and a
    // backend waiting for one will not answer until it arrives.
    //
    // A flag rather than "just call shutdown again": the call has to happen
    // exactly once, at the moment the last byte the client sent has actually
    // reached the socket, and every path that could reach that moment asks
    // forward_client_half_close() rather than deciding for itself.
    bool backend_half_closed{false};
    bool backend_from_group{false};
    std::string backend_host;
    uint16_t backend_port{0};

    // Rate limiting (token bucket), per connection.  Same three fields and the
    // same names the server and the cache carry, so the three are recognisably
    // one mechanism.  rl_max of 0 means no limit and is the common case, which
    // is why the check is written to leave on that first.
    double rl_tokens{0.0};
    double rl_max{0.0};
    std::chrono::steady_clock::time_point rl_last{};

    // Async connect state.
    //
    // There is deliberately no copy of the connect target here.  ::connect()
    // has taken the address by the time this state is set, and what waits for
    // the handshake is a poll on the socket, which names none.  The field that
    // stood here was assigned once and read nowhere.
    bool connect_pending{false};
    int connect_fd{-1};
    io_request connect_req;

    // While the backend handshake is in flight the client socket has nothing
    // armed on it — in TCP mode deliberately, so that unread bytes stay in the
    // kernel and TCP flow control keeps applying.  That left no way at all to
    // notice a client that died in the meantime: the pair was held, with a
    // 64KB struct and a backend socket, until the connect finished and the
    // first read or splice finally reported the corpse.  A client that connects,
    // dumps a payload and resets is therefore free to make the proxy hold
    // arbitrarily many of those at once.  This poll watches for POLLERR/POLLHUP
    // only, which means "reset, or shut down in both directions" and nothing
    // else — a clean close or a half-close leaves it silent, so a client that
    // legitimately stops writing while it waits for its answer is untouched.
    // It reads nothing, so the flow-control argument above still holds.
    bool abort_watch_pending{false};
    io_request abort_req;

    // A request has been handed to the backend and not one byte of the answer
    // has come back yet.  Nothing else bounded that wait: a backend that accepts
    // the connection and then stops answering fails no check anywhere — a TCP
    // health probe connects to it happily, a request that never completes is
    // never recorded as an error, so the breaker never opens, and the request
    // simply stays open.  Measured: one still unanswered after 100 s, and under
    // load the surviving backends looked perfect while throughput fell 99.7%,
    // because every client connection that touched the stalled backend was
    // consumed one by one.  See mesh_config::backend_timeout.
    bool awaiting_response{false};
    std::chrono::steady_clock::time_point response_deadline{};

    // Bytes of a request have arrived and its header block is not finished yet.
    // Holding for the terminating blank line is the correct framing behaviour —
    // acting on half a header block is what request smuggling is made of — but
    // holding is only safe if something ends the hold.  The 16 KiB limit does
    // not: it is a limit on bytes, and a client that sends a request line and
    // then stops sends no further bytes to be counted.  --idle-timeout does
    // not either, because it defaults to 0, meaning never.  So the wait was
    // bounded by nothing at all, and one connection per socket the attacker can
    // open is the whole of slowloris.  See PROXY_HEADER_TIMEOUT_SEC.
    bool awaiting_headers{false};
    std::chrono::steady_clock::time_point header_deadline{};

    SKL_TRACE_FIELD(tr)
    SKL_INV_FIELD(pr)

    // 64KB read buffer — at the END to keep hot fields in first cache lines
    alignas(64) char read_buf[PROXY_READ_BUF_SIZE];

    // The session, for a struct that never reached its release path — one
    // retired with completions outstanding when the runtime stopped, and freed
    // with the instance instead.  Safe here for the same reason it is safe
    // anywhere: no submission ever named it.
    ~proxy_client_connection() { tls_context::free_ssl(ssl); }
    proxy_client_connection() = default;
    proxy_client_connection(const proxy_client_connection&) = delete;
    proxy_client_connection& operator=(const proxy_client_connection&) = delete;

    void reset(int new_fd);
};

struct alignas(64) proxy_backend_connection
{
    static constexpr size_t MAX_WRITE_BATCH = 16;
    static constexpr size_t MAX_PARTIAL_SIZE = 1 * 1024 * 1024;

    // === HOT fields (CQE dispatch) — first 2 cache lines ===
    int fd;
    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};
    bool zc_notif_pending{false};
    bool splice_active{false};
    bool splice_in_pending{false};
    bool splice_out_pending{false};
    // The response is finished and this connection is on its way to the pool,
    // but the read that was armed on it has been cancelled and its completion
    // is still owed.  Nothing may touch the fd until that completion lands.
    bool pool_draining{false};
    // Application bytes came off this backend socket and went to the client.
    // The plain fact behind "did the backend answer", stated so a --protocol
    // tcp proxy can ask it: response_started, which HTTP uses for the same
    // purpose, is never set outside HTTP mode.  See the circuit breaker in
    // handle_backend_read.
    bool sent_to_client{false};
    int client_fd;
    uint32_t write_batch_count{0};
    // Bumped on every reuse from the struct pool and stamped into read_req.
    // Backend structs and backend fds are both pooled, so a completion that
    // outlives its connection is indistinguishable from the next occupant's
    // own — same struct address, same fd number, valid owner — and acting on
    // it appends one backend's bytes to a different client's response.
    uint32_t generation{0};
    io_request read_req;
    io_request write_req;

    // === TLS session (backend leg) ===
    // Non-null only on a connection to a backend this proxy reaches over TLS.
    // Same design as the client side above — OpenSSL is a codec and the ring
    // moves every byte — with the roles reversed: this end is the client, so
    // the session is created with the endpoint's name pinned to it and the
    // chain is verified against the configured trust store before one byte of
    // the request goes out.
    //
    // A connection carrying one of these is never pooled; see
    // backend_pool_eligible.
    SSL* ssl{nullptr};
    tls_conn_state tls_state{tls_conn_none};
    bool tls_peer_closed{false};

    // === WARM fields ===
    io_request splice_in_req;
    io_request splice_out_req;
    // Where the record layer puts the plaintext it has decrypted, on the way
    // to the client.  Unused on a cleartext backend connection, which forwards
    // straight out of the read buffer.
    std::string partial;
    socketley::byte_counted_queue<std::string> write_queue;
    std::string write_batch[MAX_WRITE_BATCH];
    struct iovec write_iovs[MAX_WRITE_BATCH];

    // === COLD fields ===
    int pipe_to_client[2]{-1, -1};

    // HTTP response tracking for connection pooling.  The whole of it lives in
    // http_framing.h now — the scan, the completeness predicate and
    // the state below — so that it can be reached without a daemon, a socket or
    // an event loop.  test/fuzz/fuzz_http_response.cpp drives exactly this
    // struct through exactly the function handle_backend_read calls.
    //
    // Being one object rather than nine loose members also means reset() clears
    // it with a single assignment, so a field added here cannot be forgotten
    // there and leak from one response into the next.
    http_response_framing http_frame;

    // Set while pool_draining when the cancelled read turns out to have
    // delivered something other than the cancellation: data past the end of
    // the response, an EOF, or an error.  Any of those leaves the stream at an
    // offset the next request cannot start from, so the fd is closed instead
    // of pooled — but only once the read has actually finished owing us a
    // completion, which is why the verdict has to be remembered.
    bool pool_abandoned{false};
    // The client is detached the moment draining starts and is free to be
    // routed somewhere else before the cancellation lands, so the pool this
    // connection belongs to cannot be read off it later.  The endpoint goes
    // with the index for the reason given on pooled_backend: with a group
    // backend the index names a set, not a socket's peer.
    size_t pool_backend_idx{0};
    std::string pool_host;
    uint16_t pool_port{0};

    SKL_TRACE_FIELD(tr)
    SKL_INV_FIELD(pr)

    // 64KB read buffer — at the END to keep hot fields in first cache lines
    alignas(64) char read_buf[PROXY_READ_BUF_SIZE];

    // See proxy_client_connection's destructor.
    ~proxy_backend_connection() { tls_context::free_ssl(ssl); }
    proxy_backend_connection() = default;
    proxy_backend_connection(const proxy_backend_connection&) = delete;
    proxy_backend_connection& operator=(const proxy_backend_connection&) = delete;

    void reset(int new_fd);
};

struct proxy_conn_entry
{
    conn_side side = conn_none;
    union {
        proxy_client_connection* client;
        proxy_backend_connection* backend;
    };
};

// Health check state per backend
struct backend_health
{
    bool healthy{true};
    int consecutive_failures{0};
    std::chrono::steady_clock::time_point last_check{};
};

// Circuit breaker per backend
struct circuit_breaker
{
    enum state : uint8_t { closed = 0, open = 1, half_open = 2 };
    state current{closed};
    int error_count{0};
    std::chrono::steady_clock::time_point opened_at{};

    // Half-open means "one request finds out whether the backend is back".
    // Availability alone could not express that: it answered yes to every
    // selection, so the whole rotation poured into a backend that had just been
    // taken out of it, and each timeout transition cost a burst of requests
    // rather than the single probe the design intends.  The timestamp bounds it
    // — a probe whose answer never arrives (the client went away first) must not
    // block the backend out of rotation for good.
    bool probe_in_flight{false};
    std::chrono::steady_clock::time_point probe_started{};
};

// Service mesh configuration
struct mesh_config
{
    // Health checks
    enum health_type : uint8_t { health_none = 0, health_tcp = 1, health_http = 2 };
    health_type health_check{health_none};
    int health_interval{5};      // seconds
    std::string health_path{"/health"};
    int health_threshold{3};     // consecutive failures to mark unhealthy

    // Circuit breaker
    int circuit_threshold{5};    // errors to open circuit
    int circuit_timeout{30};     // seconds before half-open

    // How long a backend may take to produce the first byte of a response
    // before the request is given up on and the backend charged for it.  On by
    // default, because the failure it covers — accepts, never answers — is
    // invisible to everything else the proxy has: no error is ever recorded, so
    // no breaker opens, and a TCP health check connects to such a backend just
    // fine.  An operator who has not heard of this flag is the one who needs it,
    // which is why --sidecar (health_tcp + circuit + retry) inherits it too.
    //
    // It measures time to the *first* byte, not the whole response, so a slow
    // or streaming body is never cut short once the backend has started
    // answering.  0 disables it and restores the old unbounded wait.
    int backend_timeout{2};      // seconds, 0 = disabled

    // Retries
    int retry_count{0};          // 0 = disabled
    bool retry_all{false};       // retry non-idempotent methods too

    // mTLS
    std::string client_ca;       // server-side: CA to verify client certs
    std::string client_cert;     // proxy-side: client cert for backend mTLS
    std::string client_key;      // proxy-side: client key for backend mTLS
};

// One probe of one backend.
//
// Allocated per sweep and never reused.  The 500 ms deadline that gives up on a
// probe cancels nothing — the connect, write or read it was waiting on is still
// owed a completion — so a shared probe meant the next sweep overwrote the
// address the previous connect was reading, and reassigned the string a write
// was still sending from.  What came back was a health verdict for an operation
// that belonged to the sweep before it, and a backend marked unhealthy on that
// evidence is taken out of rotation for every client.
struct async_health_check
{
    // Ciphertext in, on a probe whose backend leg is TLS.  Deliberately larger
    // than `buf`: a server's first flight is a certificate chain, and reading
    // one a quarter of a kilobyte at a time costs a completion per quarter
    // kilobyte.  Nothing is allocated for it on a cleartext probe.
    static constexpr size_t TLS_READ_SIZE = 4096;

    int fd{-1};
    size_t backend_idx{0};
    // connecting → (tls_writing ⇄ tls_reading)* → writing → reading.
    // The two tls_ phases exist only on an encrypted leg and only until the
    // handshake finishes; the request and its answer then run through the same
    // writing/reading pair a cleartext probe uses, one record layer lower.
    enum phase : uint8_t { idle, connecting, tls_writing, tls_reading,
                           writing, reading, done };
    phase current{idle};
    // Whether the ring still owes this probe a completion.  `current` cannot
    // answer that: the deadline moves a probe to `done` while its operation is
    // still in flight.
    bool op_pending{false};
    io_request req;
    // The connect target, kept apart from the response buffer it used to share.
    // sockaddr_storage rather than sockaddr_in because a backend is not
    // necessarily on an IP address — see backend_connect_addr, which is what
    // fills this — and addr_len beside it because the two families do not agree
    // about how much of it the kernel is to read.
    struct sockaddr_storage addr{};
    socklen_t addr_len{0};
    char buf[256];
    // How much of `buf` holds decrypted response bytes.  A status line can
    // arrive split across two records, and a verdict read off the first of them
    // would call a healthy backend dead for answering in two pieces.
    uint16_t plain_len{0};
    std::string write_buf;
    // How much of write_buf has reached the wire.  A short write is ordinary
    // and was previously treated as a completed one: mid-handshake that is a
    // record stream with a hole in it, and mid-request a truncated GET.
    size_t write_off{0};

    // ── the record layer, when this backend is reached over TLS ──
    //
    // The same memory BIO pair the data path uses — see start_backend_tls —
    // driven one completion at a time by this probe's own operations.  No SQE
    // ever names the SSL or its BIOs: ciphertext is copied into cipher_in and
    // out into write_buf before anything is submitted, and both of those belong
    // to this struct.  That is what makes the session safe to release exactly
    // when the struct is, which is what the destructor below does — and why it
    // is a destructor rather than a call in drop_health_check().  A probe with
    // an operation still in flight is not released there at all; it is handed
    // to retire(), which holds this same object until the completion lands.
    // One free reachable from both paths, and it cannot be forgotten on either.
    SSL* ssl{nullptr};
    tls_conn_state tls_state{tls_conn_none};
    std::string cipher_in;

    ~async_health_check() { tls_context::free_ssl(ssl); }
};

// Connection pool entry for backend reuse
struct pooled_backend
{
    int fd;
    size_t backend_idx;             // which backend_info this connects to
    // Where this socket actually goes.  The index alone does not say it: a
    // group entry stands for every member of the group at once, so a socket
    // filed under it would be handed to the next request routed to *any*
    // member — a connection to one runtime carrying another's request.  The
    // pool key is the endpoint, and the index only picks the shelf.
    std::string host;
    uint16_t port;
    std::chrono::steady_clock::time_point idle_since;

    // ── the session, for a socket that has one ──
    //
    // A TLS backend socket is nothing without its record layer.  The transport
    // here is a memory BIO pair rather than SSL_set_fd, so every sequence
    // number, every key schedule and every byte OpenSSL has read but not yet
    // handed over lives inside this object and nowhere else — pooling the
    // descriptor and building a fresh SSL for the next borrower would put a
    // brand new record layer on a stream already several records in, which is
    // not reuse at all.  So the session travels with the descriptor, and the
    // pool owns both: whoever closes the fd frees this.
    //
    // Null for a cleartext socket, which is what nearly every entry is.
    SSL* ssl{nullptr};
    // Which tls_context created `ssl`.
    //
    // The endpoint above answers three of the four things a TLS connection
    // carries beyond an address — the SNI name sent, the name the certificate
    // was verified against, and the peer — because start_backend_tls derives
    // all three from exactly this host, through exactly the same
    // backend_endpoint_of call that fills it in.  The fourth is the client
    // certificate presented and the trust store the chain was checked against,
    // and those belong to the context rather than to the connection: one per
    // proxy instance, built in start() from --client-cert/--client-key/--ca.
    //
    // teardown() empties this pool before start() can build a new context, so
    // an entry outliving its context should be impossible.  It is compared
    // anyway, for the reason backend_pool_eligible gives about the endpoint
    // key: a checked fact costs a pointer compare, and an argument about
    // lifetimes costs whatever the next change to start() costs.
    const tls_context* tls_owner{nullptr};
};

class proxy_instance : public runtime_instance
{
public:
    using proxy_hook = std::function<std::optional<std::string>(int client_fd, std::string_view data)>;

    proxy_instance(std::string_view name);
    ~proxy_instance() override;

    void add_backend(std::string_view addr);
    void clear_backends();
    void set_protocol(proxy_protocol p);
    void set_strategy(proxy_strategy s);
    void set_runtime_manager(runtime_manager* mgr);

    // The manager's name/group → endpoint snapshot.  This is the only thing the
    // proxy needs to know about the other runtimes in the daemon, and it
    // arrives as data rather than as a pointer it may dereference — see
    // shared/endpoint_table.h for what that buys.
    void set_endpoints(std::shared_ptr<const endpoint_table> tbl) override;

    // The proxy is the one role with a backend leg, so it is the one role that
    // has these.  See runtime_instance for why the TLS gate asks this way.
    void get_mesh_tls_paths(std::string_view& ca, std::string_view& cert,
                            std::string_view& key) const override;

    proxy_protocol get_protocol() const;
    proxy_strategy get_strategy() const;
    const std::vector<backend_info>& get_backends() const;
    const mesh_config& get_mesh_config() const;

    // Service mesh configuration
    void set_health_check(mesh_config::health_type type);
    void set_health_interval(int seconds);
    void set_health_path(std::string_view path);
    void set_health_threshold(int threshold);
    void set_circuit_threshold(int threshold);
    void set_circuit_timeout(int seconds);
    void set_backend_timeout(int seconds);
    void set_retry_count(int count);
    void set_retry_all(bool val);
    void set_mesh_client_ca(std::string_view path);
    void set_mesh_client_cert(std::string_view path);
    void set_mesh_client_key(std::string_view path);

    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;

    size_t get_connection_count() const override;

    // C++ proxy intercept hooks
    void set_on_proxy_request(proxy_hook cb);
    void set_on_proxy_response(proxy_hook cb);

    // Stats
    std::string get_stats() const override;

    // Lua API
    std::string lua_peer_ip(int client_fd);
    bool lua_close_client(int client_fd);
    std::vector<std::string> lua_backends() const;
    std::vector<std::pair<int, std::string>> lua_backend_health() const;
    std::vector<int> lua_clients() const;

private:
    void handle_accept(struct io_uring_cqe* cqe);
    void handle_client_read(struct io_uring_cqe* cqe, io_request* req);
    void handle_backend_read(struct io_uring_cqe* cqe, io_request* req);
    void handle_client_write(struct io_uring_cqe* cqe, io_request* req);
    void handle_backend_write(struct io_uring_cqe* cqe, io_request* req);
    void handle_splice(struct io_uring_cqe* cqe, io_request* req);
    void handle_connect(struct io_uring_cqe* cqe, io_request* req);
    // The abort watch armed in connect_to_backend has reported.  Tears the pair
    // down when the client is really gone, and does nothing at all otherwise —
    // including when the report is only the withdrawal that put an end to it.
    void handle_client_abort(struct io_uring_cqe* cqe, io_request* req);
    void handle_health_cqe(struct io_uring_cqe* cqe, io_request* req);

    // One pass over whatever is buffered on an HTTP client connection: parse a
    // request if a whole header block is there, forward the part of a body that
    // belongs to it, and re-arm the client read.
    //
    // Called from handle_client_read when bytes arrive, and — this is why it is
    // a function rather than a block inside that handler — from
    // reset_client_for_next_request, because a request pipelined behind the one
    // just answered is already in the buffer and no further read will arrive to
    // notice it: the client is waiting for its answer, not sending.
    void drive_client_request(proxy_client_connection* conn, int fd);

    // Puts a bound on a request held back behind the exchange in flight, so that
    // a response this proxy cannot frame cannot strand one for ever.
    void bound_pipelined_hold(proxy_client_connection* conn);

    // ── the protocol switch ─────────────────────────────────────────────────
    //
    // Whether this client connection has stopped being a sequence of HTTP
    // exchanges, because the backend answered 101 Switching Protocols on it.
    //
    // Asked of the backend's response-framing state rather than remembered on
    // the client.  The 101 is only ever seen in one place — the response scan,
    // which reads every status code for the pool's sake already — so there is
    // one fact and no copy of it to keep in step.  A tunnel is by construction
    // never detached and never pooled, so the pair stays a pair for as long as
    // the switch means anything, and a client with no backend answers false
    // without needing to.
    bool conn_tunnelled(const proxy_client_connection* conn) const;

    // The handover, run once, on the completion that carried the 101 and after
    // it has been forwarded.  See the definition: what it has to do is unpick
    // the two things the request path set up on the assumption that an answer
    // to a request was coming back.
    void begin_tunnel(proxy_client_connection* cconn);

    // Returns http_request_parse::invalid for a request that must never reach a
    // backend, which is a verdict the old bool return could not express at all.
    http_request_parse parse_http_request_line(proxy_client_connection* conn);
    std::string rewrite_http_request(proxy_client_connection* conn,
                                     std::string_view new_path);

    // ── The path as the backend will see it ─────────────────────────────────
    //
    // An HTTP gateway answers on /<name>/… and forwards the remainder, so there
    // are two paths in every request and a script is entitled to either.  This
    // is the one place the transformation is written: the forwarding site and
    // on_route's third argument both read it, so the two cannot drift.
    //
    // A path that does not carry this proxy's prefix comes back unchanged.  A
    // TCP proxy has no path at all, and inventing a strip for a string that has
    // not been through the prefix check would be worse than saying nothing.
    std::string_view backend_path(std::string_view client_path) const;

    // ── Filter chain ────────────────────────────────────────────────────────
    //
    // The `filters` array a Lua script declares, run in order on a parsed
    // request *before* a backend is chosen for it.  Each filter either says
    // nothing — carry on — or returns the answer, in which case this request is
    // answered here and no backend is ever selected, resolved or connected to.
    // That ordering is the whole feature: a filter that ran after the connect
    // would already have cost the thing it exists to prevent, so the call sits
    // above select_and_resolve_backend in drive_client_request and nowhere else.
    //
    // Returns true when the request has been answered and the caller must
    // return immediately without forwarding anything.  The answer goes out
    // through the same tail every other self-answered response uses, so the
    // connection is torn down by the paths that already exist — see
    // queue_final_response.
    //
    // Guarded by lua()->has_filters() at the call site: a proxy with no chain
    // does not reach this function at all.
    bool run_request_filters(proxy_client_connection* conn);

    // ── Declared routes ─────────────────────────────────────────────────────
    //
    // What this proxy's backends say they will answer, folded out of the
    // published snapshot whenever that snapshot changes and never on a request.
    // Empty on a proxy none of whose backends declares anything — which is
    // every proxy that existed before this — and an empty table is checked with
    // one `empty()` test on the request path.
    //
    // One rule folds several backends into one table, and route_table::
    // merge_alternative gives it: nothing may be refused that either of them
    // might have served.  A single backend that declares nothing therefore
    // leaves this empty.
    void rebuild_route_view();

    // The gate.  Returns true when this request has been answered here and the
    // caller must return at once; false means "no declaration covers this, or
    // it covers it and allows it" — carry on and forward.
    //
    // Runs on the path the *backend* will see (this proxy's prefix already
    // stripped), because that is the path the declaration is written in: it
    // lives in the handler's script and can only speak about the handler's own
    // paths.
    //
    // Above the filter chain and far above backend selection: this is the
    // cheapest refusal there is — two string comparisons against a table
    // already in hand — and everything it prevents (a Lua call, an endpoint
    // resolution, a pooled socket, a connect, a round trip, the handler's own
    // work) begins after it.  Anything it answers goes out through
    // queue_final_response like every other response this proxy writes itself.
    bool enforce_declared_route(proxy_client_connection* conn, std::string_view path);

    // Whether the request whose header block is buffered on this connection
    // carries a given field name.  Used only by the OPTIONS branch above, to
    // tell a CORS preflight from a plain OPTIONS.
    static bool request_has_header(const proxy_client_connection* conn,
                                   const char* lower_name, size_t len);

    // The tail shared by every response this proxy writes itself: queue it,
    // mark the connection closing, flush what can be flushed, and half-close
    // the read direction so the teardown actually happens (see send_error for
    // why the last one is not optional).  One copy, because a second exit from
    // the answered-here path is how a descriptor leaks.
    void queue_final_response(proxy_client_connection* conn, std::string&& response);

    bool resolve_backend(backend_info& b);
    const backend_info* select_and_resolve_backend(proxy_client_connection* conn);
    // A false return means "no backend connection was established", which
    // covers two very different things.  If the backend refused us, that belongs
    // in the circuit breaker; if we simply ran out of room in the submission
    // ring or a slot table, it does not — blaming the backend for our own
    // resource limit trips the breaker and takes a healthy backend out of
    // rotation for everybody.  When *resource_failure comes back true, the
    // backend said nothing at all and must not be charged for it.
    bool connect_to_backend(proxy_client_connection* conn, const backend_info* target,
                            bool* resource_failure = nullptr);
    // Every descriptor this runtime gives back to the kernel goes through here:
    // client sockets, backend sockets, the listener, the connect socket, the
    // splice pipes.  This is the runtime the crossed-delivery bug was measured
    // on — a close does not withdraw an SQE that already carries the number, it
    // only frees the number for the next accept, and the queued splice then
    // writes into that connection instead.  event_loop::close_fd holds the
    // number until nothing in the ring still names it, which is the general
    // form of what close_pair does for one specific splice.
    //
    // m_retired_loop and not m_loop: descriptors are still closed after
    // teardown has cleared m_loop, and that is exactly when the ring is most
    // likely to be holding something.
    void close_tracked(int fd);

    // close_reason::force is a caller stating that no answer can arrive on this
    // pair any more -- the runtime is stopping, the backend is gone, the client
    // aborted.  5 of the 86 calls say it; the other 81 leave the default, and
    // the default is checked.
    //
    // It does not change what close_pair does.  The answer-owed invariant is an
    // assertion, not a gate: holding here was tried and could not work, because
    // by the time this function runs a polite half-close and a connection torn
    // out from under its client are the same pair.  So `force` withdraws a
    // claim rather than a guard, and a path added later inherits the check
    // instead of having to remember it.
    enum class close_reason { normal, force };
    void close_pair(int client_fd, int backend_fd,
                    close_reason reason = close_reason::normal);
    inline void close_pair_close_backend(int backend_fd,
                                          proxy_backend_connection* bconn,
                                          proxy_client_connection* cconn);
    void reset_client_for_next_request(proxy_client_connection* cconn);
    // TCP mode: take the hold on a client that has shut its write side, and
    // pass that half-close on to the backend.  See the definitions.
    bool hold_tcp_half_close(proxy_client_connection* conn);
    void forward_client_half_close(proxy_client_connection* conn);
    void detach_and_pool_backend(proxy_client_connection* cconn, int backend_fd);
    // Consumes the completion of the read that detach_and_pool_backend
    // cancelled, and releases the fd and the struct once it is the last one.
    void finish_pool_drain(proxy_backend_connection* bconn,
                           struct io_uring_cqe* cqe, io_request* req);
    void setup_splice_pipes(proxy_client_connection* conn, proxy_backend_connection* bconn);
    void start_splice_forwarding(proxy_client_connection* conn, proxy_backend_connection* bconn);
    // Waits for the socket end of a splice pipeline to have something, and only
    // then lets the splice go in.  See the definition for what arming the splice
    // directly costs — it is a kernel thread per idle connection and, on the
    // backend leg, a resubmit loop with no bound.
    bool arm_splice_in_poll(int src_fd, io_request* req);

    // Connection pool: reuse idle backend connections
    // Both take the endpoint as well as the index: a pooled socket goes back
    // only to the peer it was opened to.  See pooled_backend.
    //
    // `want_tls` is part of the key rather than a preference.  An encrypted
    // socket handed to a request that will write a plaintext request into it
    // sends that request as a TLS record nobody can read, and a cleartext
    // socket handed to a TLS request sends the ClientHello of a handshake the
    // peer already finished — so the two never mix, and asking makes that a
    // checked fact instead of a consequence of how the backends happen to be
    // configured.  On success `out_ssl` receives the session that belongs to
    // the returned descriptor: non-null exactly when want_tls, and the caller
    // owns it from that moment.
    int acquire_pooled_backend(size_t backend_idx, std::string_view host, uint16_t port,
                               bool want_tls, SSL** out_ssl);
    // `bconn` is the connection being given up.  release_to_pool takes its
    // session with the descriptor when it files one, and leaves it alone when
    // it closes one — so backend_pool_release, which runs after every call
    // here, frees exactly the sessions that were not pooled.
    void release_to_pool(int backend_fd, size_t backend_idx,
                         std::string_view host, uint16_t port,
                         proxy_backend_connection* bconn);
    // Give up a pooled entry: the descriptor and, if it has one, the session.
    // Every path that stops holding an entry goes through here — the stale
    // sweep, the probe's three refusals, the full-pool eviction, teardown —
    // because a session freed anywhere else is a session leaked everywhere
    // else.  `reset` sends a TCP reset rather than a graceful close; see the
    // definition for when that is the right signal.
    void discard_pooled(pooled_backend& pb, bool reset);
    // Ask a pooled TLS socket whether anything is waiting on it that the next
    // borrower must not inherit.  See the definition — this is the whole of
    // the TLS half of ed07f12's argument.
    //
    // Returns true when the socket may be reused.  A false answer has already
    // discarded the entry.
    bool probe_pooled_tls(pooled_backend& pb);
    // Start the periodic sweep if it is not already running.  Idempotent; see
    // the definition for why it is armed on demand rather than always.
    void arm_idle_sweep();
    // Close what the pool holds to endpoints the published membership no longer
    // lists, and forget the breakers that described them.  Membership is the
    // only thing that can make a pooled socket unreachable while it is still
    // healthy, so this runs where membership arrives and nowhere else.
    void drop_departed_endpoints();
    // Resolve the group members whose advertised address is a NAME.
    //
    // A cluster member advertises gethostname(2), so an @group backend routes to
    // hostnames, and the address a request needs is not in m_backends at all —
    // it is built per request from the membership snapshot.  The idle sweep
    // walks m_backends and therefore never sees one.
    //
    // This is the group's equivalent of what setup() does for a configured
    // backend: resolve where the address ARRIVES, which for a group member is
    // the membership snapshot, not the request.  Runs from set_endpoints() and
    // as a retry from the idle sweep; never from the request path.
    void resolve_group_hosts();

#ifdef SOCKETLEY_INVARIANTS
    // Debug-only: see invariants.h.  Asserts over the pair, never over one half.
    void inv_check_pair(int fd, const char* where);
    // Invariant (3), charged to the connection this completion named.  `res` and
    // `type` are the completion's, read before the dispatch that may free the
    // request they came from.
    void inv_check_progress(int fd, int res, uint8_t type, const char* where);
    // Everything about one half that a caller could observe, folded into one
    // number.  Two of these, because the two halves keep different books.
    static uint64_t inv_digest(const proxy_client_connection* c);
    static uint64_t inv_digest(const proxy_backend_connection* b);
    // Every pair the runtime still holds, not just the one a completion named.
    // A completion names one connection, and when its handler tears that
    // connection down the per-completion check finds an empty slot and says
    // nothing — while the half that was stranded is the *other* one, sitting at
    // a descriptor no completion will ever mention again.  That is the shape of
    // every defect this invariant was written for, so without a sweep the check
    // cannot see its own subject.
    void inv_sweep_all(const char* where);
    // Completions between sweeps.  A sweep walks the whole descriptor space, so
    // it is amortised rather than run per completion; small enough that a pair
    // stranded during a load run is reported while the run is still going.
    static constexpr uint32_t INV_SWEEP_EVERY = 4096;
    uint32_t m_inv_sweep_countdown{0};
#endif

    // Append "Host: <backend>:<port>\r\n" for the endpoint this connection was
    // actually routed to.  Returns false when no usable endpoint is known, in
    // which case the caller must leave the client's own Host header alone.
    bool append_backend_host_header(std::string& out, const proxy_client_connection* conn) const;

    void forward_to_backend(proxy_client_connection* conn, std::string_view data);
    void forward_to_client(proxy_backend_connection* conn, std::string_view data);

    // Mark both sides of a pair whose response an on_proxy_response hook
    // refused.  Both, because handle_backend_read — the caller that acts on
    // this — is gated on the backend's flag, and the client has nothing of its
    // own in flight to notice one.  See the note above the definition.
    void refuse_response(proxy_backend_connection* bconn,
                         proxy_client_connection* cconn);
    void send_error(proxy_client_connection* conn, std::string_view status, std::string_view body);
    // The one answer for "this request will never reach a backend", and the one
    // place that decides which status says so.
    //
    // `ours` is the flag connect_to_backend already computes for the circuit
    // breaker — see the note on that function — spent a second time, on the
    // client rather than on the breaker.  502 is the backend's answer: it
    // refused, it was unreachable, or its handshake could not be started.  503
    // is this proxy running short of something local before the backend was
    // ever asked; the backend is healthy and the request would very likely
    // succeed on the next attempt.  The difference is the difference between
    // "stop asking this backend" and "try again shortly", and a client that
    // gets the wrong one either hammers a dead backend or throws away a request
    // that would have worked.
    //
    // Returns false when there is no answer to give, which is a decision and not
    // a failure: TCP mode has no status line, a connection already closing has
    // been answered, and one whose response has started cannot have a status
    // line written behind bytes already on the wire — that would put it at an
    // offset the client cannot read as the start of a message.
    bool answer_gateway_failure(proxy_client_connection* conn, bool ours);
    // The three conditions in that last paragraph, on their own, because they
    // are not the gateway statuses' rule — they are the rule for *any* status
    // this proxy writes on its own account, and there is now more than one
    // caller.  Kept as one function rather than repeated at each site: the
    // response_started half in particular is the whole reason a truncated
    // response is left truncated rather than made unreadable, and a second copy
    // of it is a second chance to leave it out.
    bool client_answerable(const proxy_client_connection* conn) const;
    // A connection whose buffered request has passed MAX_PARTIAL_SIZE.  Sibling
    // of the 431 the header block gets: same shape, same reason, one size class
    // up.  Returns what client_answerable said, so the caller can see whether
    // the close it is about to do is the whole of what this client got.
    bool answer_request_too_large(proxy_client_connection* conn);
    // Re-arm the listener, falling back to the backoff timer when the
    // submission does not reach the ring.  Without that the proxy stops
    // accepting connections silently — there is no completion to report it.
    void rearm_accept();
    void schedule_accept_backoff();

    // Both report whether the submission reached the ring; see the
    // definitions for why a caller must not ignore that.
    bool flush_client_write_queue(proxy_client_connection* conn);
    bool flush_backend_write_queue(proxy_backend_connection* conn);

    // ── TLS record layer ────────────────────────────────────────────────────
    //
    // One implementation for both legs: a client connection this proxy
    // terminates TLS for and a backend connection it dials over TLS run the
    // same state machine, and the two structs carry the same four things it
    // needs (a descriptor, a write request, a write queue of plaintext and a
    // `partial` to decrypt into).  A second copy of it would be a second thing
    // to keep in step with server_instance, which is where the design comes
    // from.
    //
    // OpenSSL does no I/O in either.  tls_feed takes the ciphertext a read
    // completion delivered and leaves plaintext in conn->partial; tls_flush
    // takes queued plaintext and whatever the record layer owes on its own
    // account — a handshake flight, an alert, a session ticket — and puts it
    // on the wire as one ordinary write submission.
    template <typename Conn> void tls_feed(Conn* conn, const char* data, size_t len);
    // False means the submission did not reach the ring, exactly as the two
    // flush functions above report it.
    template <typename Conn> bool tls_flush(Conn* conn);
    // A TLS connection can owe the wire bytes with an empty write queue.
    // Asking only about the queue is how a handshake stalls one round short of
    // finishing, and how an alert is dropped on the way to a teardown.
    template <typename Conn> static bool tls_owes_output(const Conn* conn);

    // Give a backend connection a TLS session and start its handshake.  False
    // means no session could be created or the first flight did not reach the
    // ring — the caller must give the socket up rather than carry on in
    // cleartext, which is the whole point of the flag.
    bool start_backend_tls(proxy_client_connection* cconn, proxy_backend_connection* bconn);
    // Whether this connection's backend leg is encrypted.
    bool conn_backend_tls(const proxy_client_connection* conn) const;

    // Socket tuning: set optimal buffer sizes and options
    void tune_socket(int fd);

    // Service mesh
    bool is_backend_available(size_t idx) const;
    // Claim the single half-open probe when this selection is the one that
    // gets it; a no-op for a backend whose circuit is closed.
    void note_backend_selected(size_t idx);
    void health_check_sweep();
    void record_backend_error(size_t backend_idx);
    void record_backend_success(size_t backend_idx);

    // The same three, for an endpoint reached through an @group backend.  Such
    // an endpoint has no index to be charged: membership is published by the
    // manager and changes while the proxy runs, and one backend_idx stands for
    // the whole group at once.  So a group member's failures went nowhere and
    // nothing could take it out of rotation — a member that refused every
    // connection, or accepted and never answered, kept its full share of the
    // traffic for as long as it was in the group.
    void record_group_error(std::string_view host, uint16_t port);
    void record_group_success(std::string_view host, uint16_t port);
    bool group_endpoint_available(std::string_view host, uint16_t port);
    void note_group_selected(std::string_view host, uint16_t port);
    // Charge whichever breaker describes this connection's backend.  Reading
    // backend_idx unconditionally is how a healthy backend listed alongside a
    // group ended up carrying a group member's failures.
    void note_backend_failure(proxy_client_connection* conn);
    void note_backend_success(proxy_client_connection* conn);

    bool try_retry(proxy_client_connection* conn);

    // Start / stop the wait for a backend's first response byte.  Arming also
    // starts the sweep below if it is not already running; a group-routed
    // connection is timed just the same and is charged to the member it
    // reached — see record_group_error.
    void arm_response_deadline(proxy_client_connection* conn);
    void clear_response_deadline(proxy_client_connection* conn);
    // Start the wait for the rest of a request's header block.  Idempotent: the
    // deadline is set once per request and not pushed forward by later bytes,
    // or a client dribbling one byte at a time would renew it for ever — which
    // is the shape of the attack, not an accident of it.
    void arm_header_deadline(proxy_client_connection* conn);
    // Give up on every deadline that has passed: a backend that never answered
    // is charged so the existing breaker opens and the request is retried
    // elsewhere or answered 504; a client that never finished its header block
    // gets 408 and its connection closed.  Both live on this one sweep because
    // an armed io_uring timeout hangs off no descriptor and cannot be
    // cancelled — a second chain would be a second thing to get wrong at
    // teardown, for a check that costs one comparison on a loop that already
    // walks every client.
    void response_deadline_sweep();
    // Idempotent, and armed on demand for the same reason as the idle sweep: a
    // proxy with nothing outstanding must not keep a timer chain alive, because
    // an io_uring timeout hangs off no descriptor and cannot be cancelled.
    void arm_response_deadline_sweep();

    proxy_protocol m_protocol = protocol_http;
    proxy_strategy m_strategy = strategy_round_robin;
    std::vector<backend_info> m_backends;
    std::string m_prefix;  // pre-built "/<name>/" to avoid repeated allocation

    // The last snapshot the manager published.  Immutable, shared with every
    // other runtime holding the same one, and read on the connection path with
    // no lock — which is the point.  Null until the first publish, which the
    // manager does before it starts anything.
    std::shared_ptr<const endpoint_table> m_endpoints;

    // What that snapshot says this proxy's own backends will answer, merged
    // once per publication by rebuild_route_view().  A copy rather than a
    // pointer into the snapshot because it is a *union* over several backends
    // and so belongs to no single one of them; it is written only on the
    // publish path and read only on the request path, both on the event-loop
    // thread — the same discipline as m_endpoints above.
    route_table m_routes;

    // ─── Retired I/O ───────────────────────────────────────────────────────
    //
    // One rule, applied everywhere: nothing io_uring may still be reading from
    // or writing into is freed, reused or re-armed.  It is retired instead —
    // moved out of the running state into m_retired, which owns the memory and
    // leaves the io_requests inside it pointing at this instance, so the
    // completion that is still owed lands in absorb_retired() instead of on
    // whatever has taken the object's place.
    //
    // A stop/start cycle used to get this wrong in several places at once.
    // teardown() nulled the request owners and left the connection structs
    // alive precisely because the kernel still held their addresses, and then
    // setup() deleted them — an armed POLLOUT on a connect socket, a splice
    // waiting on a pipe or a health-check read outlives that gap easily, and
    // the event loop reads req->owner straight out of the freed struct.
    struct retired_op
    {
        // Released as soon as the last request below has completed; anything
        // that never completes is held until the instance itself is destroyed,
        // which the manager already delays past the last completion.
        std::shared_ptr<void> storage;
        io_request* waiting[6]{};
        uint8_t count{0};
    };
    std::vector<retired_op> m_retired;
    // The loop stays reachable after m_loop is cleared: a retired read may
    // still be holding a provided buffer that has to go back to the ring.
    event_loop* m_retired_loop{nullptr};

    // Retire `storage`, waiting for the `count` requests in `owed` whose
    // completions the ring still owes us.  With nothing owed the object is
    // released here and now.
    void retire(std::shared_ptr<void> storage, io_request* const* owed, size_t count);
    // Consume a completion that belongs to a retired object.  True means the
    // request was one of those, and the caller must not look at it again.
    bool absorb_retired(io_request* req, struct io_uring_cqe* cqe);

    // A timeout and the request that carries it, allocated per run.
    //
    // io_uring keeps both addresses for the life of the operation, and an
    // interval timer is nearly always in flight when a runtime stops.  Timeouts
    // are attached to no descriptor, so neither shutdown() nor submit_cancel_fd
    // reaches them.  Re-arming the same request on restart therefore leaves two
    // self-perpetuating chains driving one piece of state — for the health check
    // that means two sweeps running one state machine; a fresh object per run
    // keeps the old completion recognisable.
    struct timer_op
    {
        io_request req{};
        struct __kernel_timespec ts{};
    };

    // The accept request together with the address the kernel fills in through
    // it.  Same reasoning as timer_op: a stale accept completion landing on a
    // re-armed request arms the listener twice.
    struct accept_op
    {
        io_request req{};
        sockaddr_in addr{};
        socklen_t addrlen{sizeof(sockaddr_in)};
    };

    int m_listen_fd = -1;
    std::unique_ptr<accept_op> m_accept;
    event_loop* m_loop = nullptr;
    bool m_multishot_active = false;

    // EMFILE/ENFILE accept backoff
    std::unique_ptr<timer_op> m_accept_backoff_timer;

    // Idle connection sweep timer.  It reaps idle clients when an idle timeout
    // is configured, and evicts stale pooled backend sockets always — which is
    // why it is armed on demand rather than only from setup(), and why whether
    // it is currently armed has to be tracked: teardown() may only claim a
    // completion is owed for it while one really is.
    std::unique_ptr<timer_op> m_idle_sweep_timer;
    bool m_idle_sweep_armed{false};
    bool m_idle_sweep_warned{false};

    // Backend response deadline sweep.  Runs at a fraction of the deadline so
    // the overshoot stays small, and only while at least one request is
    // actually outstanding — see arm_response_deadline_sweep().
    static constexpr long RESPONSE_SWEEP_NSEC = 250000000L;   // 250 ms
    std::unique_ptr<timer_op> m_response_sweep_timer;
    bool m_response_sweep_armed{false};
    bool m_response_sweep_warned{false};

#ifdef SOCKETLEY_TRACE
    // Every live proxy on this process, so one instance's periodic sweep can
    // report on all of them.  The stall being chased shows up on a *member*
    // proxy while only the gateway has a timer running, and the two are
    // different instances sharing one loop.
    static void trace_register(proxy_instance* p);
    static void trace_unregister(proxy_instance* p);
    static void trace_splice_sweep();
#endif

    static constexpr int MAX_FDS = 65536;
    std::unique_ptr<proxy_client_connection> m_client_slots[MAX_FDS];
    std::unique_ptr<proxy_backend_connection> m_backend_slots[MAX_FDS];
    size_t m_client_count{0};
    size_t m_backend_count{0};

    proxy_conn_entry m_conn_idx[MAX_FDS]{};
    backend_info m_scratch_backend{};

    size_t m_rr_index = 0;
    std::mt19937 m_rng{std::random_device{}()};

    // Provided buffer ring — 64KB buffers for high throughput
    static constexpr uint16_t BUF_GROUP_ID = 2;
    static constexpr uint32_t BUF_COUNT = 512;
    static constexpr uint32_t BUF_SIZE = PROXY_READ_BUF_SIZE;
    bool m_use_provided_bufs{false};
    bool m_recv_multishot{false};
    bool m_send_zc{false};
    // The kernel can do IORING_OP_SPLICE.  Says nothing about whether this
    // proxy uses it — see m_splice_enabled and splice_opt_in().
    bool m_splice_supported{false};
    // …and it is switched on for this instance.  Off by default; see
    // splice_opt_in() for the measurements that decided that.
    bool m_splice_enabled{false};

    // Connection pool for backend reuse (avoids connect() per request)
    static constexpr size_t MAX_POOL_PER_BACKEND = 32;
    static constexpr int POOL_IDLE_TIMEOUT_SEC = 60;
    std::vector<std::vector<pooled_backend>> m_backend_pool; // per-backend pool
    // A backend was found to have written on a pooled socket — see the probe in
    // acquire_pooled_backend().  Reported once per instance: the condition is a
    // property of the backend rather than of one connection, so it repeats on
    // every socket that backend has.
    bool m_pool_unbidden_warned{false};
    // The same finding on an encrypted socket, and a separate flag because it
    // is a separate diagnosis: there the bytes are the evidence, here the bytes
    // are routine and what OpenSSL made of them is the evidence.  An operator
    // reading one of these needs to know which question was answered.
    bool m_pool_tls_unbidden_warned{false};

    // ─── TLS ───────────────────────────────────────────────────────────────
    //
    // Both are built in setup() and dropped there on the next start, so
    // `reload` — a stop followed by a start — is how a renewed certificate is
    // installed.  A context that outlived the file would go on serving or
    // trusting the expired one.  Sessions handed out by a previous context
    // keep it alive through their own reference.
    //
    // Null means cleartext on that leg, and nothing but a refused start can
    // make a configured leg null: a listener that came up unencrypted under
    // --tls is the failure this whole path exists to prevent.
    std::unique_ptr<tls_context> m_tls;          // this proxy's own listener
    std::unique_ptr<tls_context> m_backend_tls;  // the leg to the backends

    // The backend-TLS options were given, so every backend is reached over
    // TLS — including a group's members, which have no address of their own to
    // carry a scheme.  Kept apart from the per-backend flag because that is
    // the question a group-routed connection has to ask.
    bool m_backend_tls_all{false};

    // Service mesh
    mesh_config m_mesh{};
    std::vector<backend_health> m_backend_health;
    std::vector<circuit_breaker> m_circuit_breakers;

    // Breakers for endpoints behind an @group backend, keyed by "host:port".
    // A map rather than a vector because the set is the group's membership,
    // which the proxy does not own and which changes under it.  An entry
    // appears only when an endpoint fails and is erased again when it is
    // healthy, so steady membership churn leaves nothing behind and a group
    // that works costs one empty-map test per request.
    struct endpoint_key_hash
    {
        using is_transparent = void;
        size_t operator()(std::string_view s) const noexcept
        {
            return std::hash<std::string_view>{}(s);
        }
    };
    std::unordered_map<std::string, circuit_breaker, endpoint_key_hash,
                       std::equal_to<>> m_group_breakers;

    // Addresses for group members advertised by name.  Keyed by the host as the
    // snapshot spells it; the port is the member's and is applied at selection,
    // so one entry serves a host that appears in several groups or on several
    // ports.  Kept to the size of the membership rather than of its history —
    // pruned in resolve_group_hosts(), the same discipline as m_group_breakers.
    std::unordered_map<std::string, in_addr> m_group_addr;
    // Some member did not resolve, so the idle sweep has a reason to run and to
    // keep running.  Set by resolve_group_hosts(), cleared by it too.
    bool m_group_unresolved = false;
    std::unique_ptr<timer_op> m_health_check_timer;

    // Async health checks.  One probe object per backend per sweep, held by
    // pointer so the address the ring was given never moves and a probe the
    // deadline gave up on can be retired instead of overwritten.
    std::vector<std::unique_ptr<async_health_check>> m_health_checks;
    bool m_health_checks_pending{false};
    std::unique_ptr<timer_op> m_health_timeout_timer;
    // Give up on a probe: retire it if the ring still owes it a completion,
    // release it otherwise, and leave the slot empty for the next sweep.
    void drop_health_check(size_t idx);
    // The probe's three submissions, in one place each because every step of it
    // now has two spellings — one per leg — and the difference is confined to
    // these.  All three report whether the submission reached the ring; a
    // caller that ignores that leaves a probe waiting for a completion that
    // cannot come, and the slot stays occupied until the next sweep drops it.
    bool health_submit_write(async_health_check* hc);
    bool health_submit_read(async_health_check* hc);
    // One turn of an encrypted probe: whatever the session now owes the wire
    // goes out, and when it owes nothing the peer speaks next.  Picks the
    // phase from tls_state, so the same function drives the handshake and the
    // request that follows it.
    bool health_tls_arm(async_health_check* hc);
    // Inbound ciphertext from cipher_in into the read BIO.  False is fatal for
    // the probe by contract, exactly as it is for a connection.
    bool health_tls_feed(async_health_check* hc, int len);

    // C++ proxy intercept hooks
    proxy_hook m_cb_on_proxy_request;
    proxy_hook m_cb_on_proxy_response;

    // Connection struct pools — reuse allocations to avoid malloc/free per connect/disconnect
    static constexpr size_t CONN_POOL_INIT = 32;
    std::vector<std::unique_ptr<proxy_client_connection>> m_client_pool;
    std::vector<std::unique_ptr<proxy_backend_connection>> m_backend_struct_pool;

    std::unique_ptr<proxy_client_connection> client_pool_acquire(int fd);
    // Hand a connection struct back for reuse — or retire it, when the ring
    // still owes it a completion.  The pool gives structs straight to the next
    // connection, so this is the one place that has to decide, and every close
    // path goes through it.
    void client_pool_release(std::unique_ptr<proxy_client_connection> conn);
    std::unique_ptr<proxy_backend_connection> backend_pool_acquire(int fd);
    void backend_pool_release(std::unique_ptr<proxy_backend_connection> conn);

    // Cached config to avoid virtual calls on hot path
    uint32_t m_idle_timeout_cached{0};
    uint32_t m_max_conns_cached{0};
    // --rate-limit, read once at setup like the two above.  Read at all, which
    // it was not: this proxy stored the value, reported it from `show`, and
    // never looked at it again.  See the check in handle_client_read.
    double m_rate_limit_cached{0.0};

    // Peak connections high-water mark
    size_t m_peak_connections{0};

    // Max backends for fixed-size array in select_and_resolve_backend
    // Reused availability list for random selection over healthy backends.
    // Held here rather than on the stack so the number of backends is not
    // silently bounded by a frame-sized array; reserved in setup().
    std::vector<size_t> m_avail_scratch;
};
