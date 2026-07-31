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
#include "../../shared/write_queue.h"
#include "../../shared/event_loop_definitions.h"
#include "../../shared/trace.h"
#include "http_response_framing.h"

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
    struct sockaddr_in cached_addr{};
};

struct resolved_backend
{
    std::string host;
    uint16_t port = 0;
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
    bool client_eof{false};
    bool backend_from_group{false};
    std::string backend_host;
    uint16_t backend_port{0};

    // Async connect state
    bool connect_pending{false};
    int connect_fd{-1};
    io_request connect_req;
    struct sockaddr_in connect_addr{};

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

    // 64KB read buffer — at the END to keep hot fields in first cache lines
    alignas(64) char read_buf[PROXY_READ_BUF_SIZE];

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

    // === WARM fields ===
    io_request splice_in_req;
    io_request splice_out_req;
    std::string partial;
    socketley::byte_counted_queue<std::string> write_queue;
    std::string write_batch[MAX_WRITE_BATCH];
    struct iovec write_iovs[MAX_WRITE_BATCH];

    // === COLD fields ===
    int pipe_to_client[2]{-1, -1};

    // HTTP response tracking for connection pooling.  The whole of it lives in
    // http_response_framing.h now — the scan, the completeness predicate and
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

    // 64KB read buffer — at the END to keep hot fields in first cache lines
    alignas(64) char read_buf[PROXY_READ_BUF_SIZE];

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
    int fd{-1};
    size_t backend_idx{0};
    enum phase : uint8_t { idle, connecting, writing, reading, done };
    phase current{idle};
    // Whether the ring still owes this probe a completion.  `current` cannot
    // answer that: the deadline moves a probe to `done` while its operation is
    // still in flight.
    bool op_pending{false};
    io_request req;
    // The connect target, kept apart from the response buffer it used to share.
    struct sockaddr_in addr{};
    char buf[256];
    std::string write_buf;
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
    void lua_close_client(int client_fd);
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

    // Returns http_request_parse::invalid for a request that must never reach a
    // backend, which is a verdict the old bool return could not express at all.
    http_request_parse parse_http_request_line(proxy_client_connection* conn);
    std::string rewrite_http_request(proxy_client_connection* conn,
                                     std::string_view new_path);

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

    void close_pair(int client_fd, int backend_fd);
    inline void close_pair_close_backend(int backend_fd,
                                          proxy_backend_connection* bconn,
                                          proxy_client_connection* cconn);
    void reset_client_for_next_request(proxy_client_connection* cconn);
    void detach_and_pool_backend(proxy_client_connection* cconn, int backend_fd);
    // Consumes the completion of the read that detach_and_pool_backend
    // cancelled, and releases the fd and the struct once it is the last one.
    void finish_pool_drain(proxy_backend_connection* bconn,
                           struct io_uring_cqe* cqe, io_request* req);
    void setup_splice_pipes(proxy_client_connection* conn, proxy_backend_connection* bconn);
    void start_splice_forwarding(proxy_client_connection* conn, proxy_backend_connection* bconn);

    // Connection pool: reuse idle backend connections
    // Both take the endpoint as well as the index: a pooled socket goes back
    // only to the peer it was opened to.  See pooled_backend.
    int acquire_pooled_backend(size_t backend_idx, std::string_view host, uint16_t port);
    void release_to_pool(int backend_fd, size_t backend_idx,
                         std::string_view host, uint16_t port);
    // Start the periodic sweep if it is not already running.  Idempotent; see
    // the definition for why it is armed on demand rather than always.
    void arm_idle_sweep();
    // Close what the pool holds to endpoints the published membership no longer
    // lists, and forget the breakers that described them.  Membership is the
    // only thing that can make a pooled socket unreachable while it is still
    // healthy, so this runs where membership arrives and nowhere else.
    void drop_departed_endpoints();

#ifdef SOCKETLEY_INVARIANTS
    // Debug-only: see invariants.h.  Asserts over the pair, never over one half.
    void inv_check_pair(int fd, const char* where);
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
    void send_error(proxy_client_connection* conn, std::string_view status, std::string_view body);
    // Re-arm the listener, falling back to the backoff timer when the
    // submission does not reach the ring.  Without that the proxy stops
    // accepting connections silently — there is no completion to report it.
    void rearm_accept();
    void schedule_accept_backoff();

    // Both report whether the submission reached the ring; see the
    // definitions for why a caller must not ignore that.
    bool flush_client_write_queue(proxy_client_connection* conn);
    bool flush_backend_write_queue(proxy_backend_connection* conn);

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
    bool m_splice_supported{false};

    // Connection pool for backend reuse (avoids connect() per request)
    static constexpr size_t MAX_POOL_PER_BACKEND = 32;
    static constexpr int POOL_IDLE_TIMEOUT_SEC = 60;
    std::vector<std::vector<pooled_backend>> m_backend_pool; // per-backend pool

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

    // Peak connections high-water mark
    size_t m_peak_connections{0};

    // Max backends for fixed-size array in select_and_resolve_backend
    // Reused availability list for random selection over healthy backends.
    // Held here rather than on the stack so the number of backends is not
    // silently bounded by a frame-sized array; reserved in setup().
    std::vector<size_t> m_avail_scratch;
};
