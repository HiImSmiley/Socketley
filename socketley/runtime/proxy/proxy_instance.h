#pragma once
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
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

struct runtime_endpoint;

class runtime_manager;

enum proxy_protocol : uint8_t { protocol_http = 0, protocol_tcp = 1 };
enum proxy_strategy : uint8_t { strategy_round_robin = 0, strategy_random = 1, strategy_lua = 2 };
enum conn_side : uint8_t { conn_none = 0, conn_client, conn_backend };

// What the bytes received so far amount to, as three states rather than a
// bool, because false meaning "need more data" left the smuggling check no way
// to say a request is malformed.
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
    // Whether this backend is reached over TLS, turned on by an https://
    // address for one backend or by the backend-TLS options for all of them,
    // because honouring those against a cleartext peer would be the fail-open
    // half of the flag.
    bool tls = false;
    // A backend reached over AF_UNIX, measured at 9.83 us against loopback
    // TCP's 17.93, carried as (path, 0) -- which cannot collide with a TCP key
    // because resolve_backend refuses a path that is not absolute.
    bool is_unix = false;
    std::string unix_path;
    struct sockaddr_in cached_addr{};

    // The table's node list this backend was resolved against, empty when it
    // took none, so a republish can tell a change from a repeat.
    std::vector<std::string> node_paths;
    // A sharded runtime's nodes, one unix backend each, chosen among per
    // request from node_next; empty for a backend with one address.
    std::vector<backend_info> nodes;
    size_t node_next = 0;
};

struct resolved_backend
{
    std::string host;
    uint16_t port = 0;
    // Deliberately no `tls` here, because a group's members carry no scheme of
    // their own and only the backend-TLS options can encrypt the leg to one.
};

// 64 KB read buffer, because the bottleneck is the number of read syscalls and
// a larger buffer amortises each one over more data.
static constexpr size_t PROXY_READ_BUF_SIZE = 65536;

// How long a client may take to finish a header block once it has started one,
// deliberately not a flag and not tied to --idle-timeout, whose default of 0
// must not switch it off.
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

    // Non-null only with --tls, on a memory BIO pair nothing the kernel names,
    // which is what makes the session safe to free the moment the struct is
    // released.
    SSL* ssl{nullptr};
    tls_conn_state tls_state{tls_conn_none};
    // The peer's close_notify, remembered rather than acted on, because the
    // read that carries it can carry the last request ahead of it.
    bool tls_peer_closed{false};

    // === WARM fields ===
    io_request splice_in_req;
    io_request splice_out_req;
    std::string partial;
    // write_chunk rather than std::string, because a TCP relay lends the ring
    // buffer a read arrived in to the write instead of copying it.
    socketley::byte_counted_queue<socketley::write_chunk> write_queue;
    socketley::write_chunk write_batch[MAX_WRITE_BATCH];
    struct iovec write_iovs[MAX_WRITE_BATCH];

    // === COLD fields ===
    int pipe_to_backend[2]{-1, -1};
    std::string method;
    std::string path;
    std::string version;

    // How the request whose header block was just parsed frames its own body,
    // written by parse_http_request_line and read once by
    // rewrite_http_request.
    size_t declared_body_len{0};
    bool declared_body_chunked{false};

    // How much of the current request's body is still to be forwarded, because
    // forwarding everything past the header terminator sent a pipelined second
    // request to the backend without passing a single framing check -- with
    // body_unbounded the chunked case, which streams on.
    size_t body_remaining{0};
    bool body_unbounded{false};

    // Request headers a filter set on the request now being parsed, per
    // request rather than per connection, or the second request on a
    // keep-alive socket would carry the first one's identity.
    std::vector<std::pair<std::string, std::string>> filter_headers;

    // Names a filter asked to remove, under the same lifetime rules and the
    // same ban list, because a filter that could remove Content-Length would
    // change how the message is framed.
    std::vector<std::string> filter_removed_headers;

    std::chrono::steady_clock::time_point last_activity{};
    int retries_remaining{0};
    size_t backend_idx{0};
    std::string saved_request;

    // Bumped on every reuse from the pool and stamped into io_requests, so
    // late completions from the previous occupant can be recognised and
    // dropped.
    uint32_t generation{0};
    // One re-attempt when a connect completion references a descriptor that is
    // no longer valid, which is an internal inconsistency rather than a
    // refusal, bounded so a persistent problem surfaces.
    bool connect_reattempted{false};
    // The client has shut its write side and is still reading, set on the EOF
    // completion and nowhere else, on both the copy and the splice path.
    bool client_eof{false};
    // And that half-close has been passed on with shutdown(SHUT_WR), a flag
    // because the call has to happen exactly once and every path asks
    // forward_client_half_close() rather than deciding for itself.
    bool backend_half_closed{false};
    bool backend_from_group{false};
    std::string backend_host;
    uint16_t backend_port{0};

    // Rate limiting per connection, with the same three fields and names the
    // server and the cache carry, and rl_max of 0 the common case the check
    // leaves on first.
    double rl_tokens{0.0};
    double rl_max{0.0};
    std::chrono::steady_clock::time_point rl_last{};

    // Async connect state, with deliberately no copy of the target:
    // ::connect() has taken the address and what waits is a poll on the
    // socket, which names none.
    bool connect_pending{false};
    int connect_fd{-1};
    io_request connect_req;

    // A watch for POLLERR/POLLHUP only while the backend handshake is in
    // flight, because a client that dies then was noticed by nothing and let
    // one attacker hold arbitrarily many pairs -- and it reads nothing, so
    // flow control still applies.
    bool abort_watch_pending{false};
    io_request abort_req;

    // A request handed to the backend with no answer yet, which nothing else
    // bounded: a backend that accepts and stops answering fails no check, and
    // under load throughput fell 99.7% while the survivors looked perfect.
    bool awaiting_response{false};
    std::chrono::steady_clock::time_point response_deadline{};

    // Bytes of a request have arrived and its header block is unfinished,
    // which the 16 KiB limit does not bound because a client that stops sends
    // no further bytes to count.
    bool awaiting_headers{false};
    std::chrono::steady_clock::time_point header_deadline{};

    SKL_TRACE_FIELD(tr)
    SKL_INV_FIELD(pr)

    // 64KB read buffer — at the END to keep hot fields in first cache lines
    alignas(64) char read_buf[PROXY_READ_BUF_SIZE];

    // The session, for a struct that never reached its release path, safe here
    // because no submission ever named it.
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
    bool splice_active{false};
    bool splice_in_pending{false};
    bool splice_out_pending{false};
    // The response is finished and this connection is on its way to the pool
    // with a cancelled read still owed, so nothing may touch the fd until that
    // completion lands.
    bool pool_draining{false};
    // Application bytes came off this backend socket and went to the client,
    // stated so a TCP proxy can ask it, since response_started is never set
    // outside HTTP mode.
    bool sent_to_client{false};
    int client_fd;
    uint32_t write_batch_count{0};
    // Bumped on every reuse and stamped into read_req, because structs and fds
    // are both pooled and a completion that outlives its connection is
    // otherwise indistinguishable from the next occupant's.
    uint32_t generation{0};
    io_request read_req;
    io_request write_req;

    // Non-null only on a TLS backend, the same design as the client side with
    // the roles reversed, and a connection carrying one is never pooled.
    SSL* ssl{nullptr};
    tls_conn_state tls_state{tls_conn_none};
    bool tls_peer_closed{false};

    // === WARM fields ===
    io_request splice_in_req;
    io_request splice_out_req;
    // Where the record layer puts decrypted plaintext on the way to the
    // client, unused on a cleartext backend, which forwards straight out of
    // the read buffer.
    std::string partial;
    // See proxy_client_connection::write_queue.
    socketley::byte_counted_queue<socketley::write_chunk> write_queue;
    socketley::write_chunk write_batch[MAX_WRITE_BATCH];
    struct iovec write_iovs[MAX_WRITE_BATCH];

    // === COLD fields ===
    int pipe_to_client[2]{-1, -1};

    // HTTP response tracking whose whole implementation lives in
    // http_framing.h, as one object so reset() clears it with a single
    // assignment and a field added here cannot leak into the next response.
    http_response_framing http_frame;

    // Set while pool_draining when the cancelled read delivered something
    // other than the cancellation, which leaves the stream at an offset the
    // next request cannot start from.
    bool pool_abandoned{false};
    // The client is detached the moment draining starts, so the pool this
    // connection belongs to cannot be read off it later, with the endpoint
    // kept because a group index names a set.
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

    // Half-open means one request finds out whether the backend is back, which
    // availability alone could not express, and the timestamp bounds a probe
    // whose answer never arrives.
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

    // How long a backend may take to produce the first byte, on by default
    // because the failure it covers is invisible to everything else, measuring
    // time to the first byte so a streaming body is never cut short.
    int backend_timeout{2};      // seconds, 0 = disabled

    // Retries
    int retry_count{0};          // 0 = disabled
    bool retry_all{false};       // retry non-idempotent methods too

    // mTLS
    std::string client_ca;       // server-side: CA to verify client certs
    std::string client_cert;     // proxy-side: client cert for backend mTLS
    std::string client_key;      // proxy-side: client key for backend mTLS
};

// One probe of one backend, allocated per sweep and never reused, because the
// 500 ms deadline cancels nothing and a shared probe let the next sweep
// overwrite what the previous connect was reading.
struct async_health_check
{
    // Ciphertext in on a TLS probe, deliberately larger than `buf` because a
    // server's first flight is a certificate chain, and allocated only on an
    // encrypted leg.
    static constexpr size_t TLS_READ_SIZE = 4096;

    int fd{-1};
    size_t backend_idx{0};
    // connecting to (tls_writing / tls_reading)* to writing to reading, with
    // the tls_ phases only on an encrypted leg and only until the handshake
    // finishes.
    enum phase : uint8_t { idle, connecting, tls_writing, tls_reading,
                           writing, reading, done };
    phase current{idle};
    // Whether the ring still owes this probe a completion, which `current`
    // cannot answer because the deadline moves a probe to `done` while its
    // operation is in flight.
    bool op_pending{false};
    io_request req;
    // The connect target kept apart from the response buffer, as
    // sockaddr_storage because a backend is not necessarily on an IP address,
    // with addr_len beside it.
    struct sockaddr_storage addr{};
    socklen_t addr_len{0};
    char buf[256];
    // How much of `buf` holds decrypted response bytes, because a status line
    // split across two records would otherwise call a healthy backend dead.
    uint16_t plain_len{0};
    std::string write_buf;
    // How much of write_buf has reached the wire, because a short write
    // treated as complete is a record stream with a hole in it or a truncated
    // GET.
    size_t write_off{0};

    // The same memory BIO pair the data path uses, driven by this probe's own
    // operations, released by the destructor so the one free is reachable from
    // both the drop and the retire path.
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
    // Where this socket actually goes, because a group entry stands for every
    // member at once and a socket filed under it would carry another runtime's
    // request.
    std::string host;
    uint16_t port;
    std::chrono::steady_clock::time_point idle_since;

    // The session travels with the descriptor and the pool owns both, because
    // every sequence number and key schedule lives inside it and a fresh SSL
    // on a stream several records in is not reuse at all.
    SSL* ssl{nullptr};
    // Which tls_context created `ssl`, because the client certificate and
    // trust store belong to the context rather than the connection, and it is
    // compared anyway since a checked fact costs a pointer compare.
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

    // The manager's name/group to endpoint snapshot, which is all the proxy
    // needs to know about other runtimes and arrives as data rather than as a
    // pointer.
    void set_endpoints(std::shared_ptr<const endpoint_table> tbl) override;

    // The proxy is the one role with a backend leg, so it is the one role that
    // has these.
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
    std::string stats_lines() const override;

    // Lua API
    std::string peer_ip(int client_fd);
    bool close_client(int client_fd);
    std::vector<std::string> backends() const;
    std::vector<std::pair<int, std::string>> backend_health_report() const;
    std::vector<int> clients() const;

private:
    void handle_accept(struct io_uring_cqe* cqe);
    void handle_client_read(struct io_uring_cqe* cqe, io_request* req);
    void handle_backend_read(struct io_uring_cqe* cqe, io_request* req);
    void handle_client_write(struct io_uring_cqe* cqe, io_request* req);
    void handle_backend_write(struct io_uring_cqe* cqe, io_request* req);
    void handle_splice(struct io_uring_cqe* cqe, io_request* req);
    void handle_connect(struct io_uring_cqe* cqe, io_request* req);
    // The abort watch armed in connect_to_backend has reported, tearing the
    // pair down when the client is really gone and doing nothing otherwise.
    void handle_client_abort(struct io_uring_cqe* cqe, io_request* req);
    void handle_health_cqe(struct io_uring_cqe* cqe, io_request* req);

    // One pass over whatever is buffered on an HTTP client connection, called
    // from handle_client_read and from reset_client_for_next_request, because
    // a pipelined request is already in the buffer and no further read will
    // arrive.
    void drive_client_request(proxy_client_connection* conn, int fd);

    // Puts a bound on a request held back behind the exchange in flight, so that
    // a response this proxy cannot frame cannot strand one for ever.
    void bound_pipelined_hold(proxy_client_connection* conn);

    // ── the protocol switch ─────────────────────────────────────────────────
    // Whether this connection has stopped being a sequence of HTTP exchanges,
    // asked of the backend's framing state rather than remembered on the
    // client, so there is one fact and no copy to keep in step.
    bool conn_tunnelled(const proxy_client_connection* conn) const;

    // The handover, run once on the completion that carried the 101 and after
    // it has been forwarded.
    void begin_tunnel(proxy_client_connection* cconn);

    // Returns http_request_parse::invalid for a request that must never reach a
    // backend, which is a verdict the old bool return could not express at all.
    http_request_parse parse_http_request_line(proxy_client_connection* conn);
    std::string rewrite_http_request(proxy_client_connection* conn,
                                     std::string_view new_path);

    // The path as the backend will see it, written in one place so the
    // forwarding site and on_route's third argument cannot drift, and
    // unchanged for a path that does not carry this proxy's prefix.
    std::string_view backend_path(std::string_view client_path) const;

    // ── Filter chain ────────────────────────────────────────────────────────
    // The `filters` chain, run before a backend is chosen so a filter that
    // refuses has cost nothing, returning true when the request has been
    // answered and the caller must return at once.
    bool run_request_filters(proxy_client_connection* conn);

    // ── Declared routes ─────────────────────────────────────────────────────
    // What this proxy's backends say they will answer, folded out of the
    // published snapshot whenever it changes, where merge_alternative's rule
    // means a single backend that declares nothing leaves this empty.
    void rebuild_route_view();

    // The gate, run on the path the backend will see and above both the filter
    // chain and backend selection, because it is the cheapest refusal there is
    // and everything it prevents begins after it.
    bool enforce_declared_route(proxy_client_connection* conn, std::string_view path);

    // Whether the buffered request carries a given field name, used only by
    // the OPTIONS branch to tell a CORS preflight from a plain OPTIONS.
    static bool request_has_header(const proxy_client_connection* conn,
                                   const char* lower_name, size_t len);

    // The tail shared by every response this proxy writes itself, in one copy
    // because a second exit from the answered-here path is how a descriptor
    // leaks.
    void queue_final_response(proxy_client_connection* conn, std::string&& response);

    bool resolve_backend(backend_info& b);
    bool configure_node_backends(backend_info& b, const std::vector<std::string>& paths,
                                 std::string_view where);
    // The nodes the table publishes for this backend now, or nullptr.
    const std::vector<std::string>* published_nodes(const backend_info& b) const;
    // Re-resolve every backend whose published nodes changed.
    void follow_published_nodes();
    // The backend a selection lands on: the entry, or one of its nodes.
    const backend_info* pick_node(proxy_client_connection* conn, size_t idx,
                                  const std::string* exclude_path = nullptr);
    // `exclude_host` names an endpoint this selection may not return -- the
    // one a retry has just given up on.  A group member and a shard node are
    // both addressed by host and port rather than by index, so excluding one
    // is the only way to ask for "another".
    const backend_info* select_and_resolve_backend(proxy_client_connection* conn,
                                                   const std::string* exclude_host = nullptr,
                                                   uint16_t exclude_port = 0);
    // A false return covers two different things, so *resource_failure says
    // when the backend said nothing at all -- blaming it for our own resource
    // limit trips the breaker on a healthy backend.
    bool connect_to_backend(proxy_client_connection* conn, const backend_info* target,
                            bool* resource_failure = nullptr);
    // Every descriptor this runtime gives back goes through here, on the
    // runtime the crossed-delivery bug was measured on, through m_retired_loop
    // because descriptors are closed after teardown has cleared m_loop.
    void close_tracked(int fd);

    // close_reason::force is a caller stating no answer can arrive on this
    // pair, withdrawing a claim rather than a guard, so a path added later
    // inherits the assertion instead of having to remember it.
    enum class close_reason { normal, force };
    void close_pair(int client_fd, int backend_fd,
                    close_reason reason = close_reason::normal);
    inline void close_pair_close_backend(int backend_fd,
                                          proxy_backend_connection* bconn,
                                          proxy_client_connection* cconn);
    void reset_client_for_next_request(proxy_client_connection* cconn);
    // TCP mode: take the hold on a client that has shut its write side and
    // pass that half-close on to the backend.
    bool hold_tcp_half_close(proxy_client_connection* conn);
    void forward_client_half_close(proxy_client_connection* conn);
    void detach_and_pool_backend(proxy_client_connection* cconn, int backend_fd);
    // Consumes the completion of the read that detach_and_pool_backend
    // cancelled, and releases the fd and the struct once it is the last one.
    void finish_pool_drain(proxy_backend_connection* bconn,
                           struct io_uring_cqe* cqe, io_request* req);
    void setup_splice_pipes(proxy_client_connection* conn, proxy_backend_connection* bconn);
    void start_splice_forwarding(proxy_client_connection* conn, proxy_backend_connection* bconn);
    // Waits for the socket end of a splice pipeline to have something before
    // letting the splice in, because arming it directly costs a kernel thread
    // per idle connection.
    bool arm_splice_in_poll(int src_fd, io_request* req);

    // Both take the endpoint as well as the index, and `want_tls` is part of
    // the key rather than a preference, because an encrypted socket handed a
    // plaintext request sends it as an unreadable record.
    int acquire_pooled_backend(size_t backend_idx, std::string_view host, uint16_t port,
                               bool want_tls, SSL** out_ssl);
    // `bconn` is the connection being given up, whose session release_to_pool
    // takes with the descriptor when it files one and leaves alone when it
    // closes one.
    void release_to_pool(int backend_fd, size_t backend_idx,
                         std::string_view host, uint16_t port,
                         proxy_backend_connection* bconn);
    // Give up a pooled entry and its session, through the one function every
    // path uses, because a session freed anywhere else is a session leaked
    // everywhere else.
    void discard_pooled(pooled_backend& pb, bool reset);
    // Ask a pooled TLS socket whether anything is waiting on it the next
    // borrower must not inherit, returning true when it may be reused and
    // having already discarded it otherwise.
    bool probe_pooled_tls(pooled_backend& pb);
    // Start the periodic sweep if it is not already running; idempotent.
    void arm_idle_sweep();
    // Close what the pool holds to endpoints the published membership no
    // longer lists, which runs where membership arrives because that is the
    // only thing that unreaches a healthy socket.
    void drop_departed_endpoints();
    // Resolve the group members whose advertised address is a name, where the
    // address arrives -- the membership snapshot -- rather than on the request
    // path the idle sweep never sees.
    void resolve_group_hosts();
    // The one place a member's nodes are chosen over its port, appended to
    // `out` because a sharded member is N dial targets.
    void member_dial(const runtime_endpoint& ep, std::vector<resolved_backend>& out) const;
    void announce_group_nodes();

#ifdef SOCKETLEY_INVARIANTS
    // Debug-only: see invariants.h.  Asserts over the pair, never over one half.
    void inv_check_pair(int fd, const char* where);
    // Invariant (3) charged to the connection this completion named, with
    // `res` and `type` read before the dispatch that may free the request.
    void inv_check_progress(int fd, int res, uint8_t type, const char* where);
    // Everything about one half a caller could observe folded into one number,
    // two of them because the two halves keep different books.
    static uint64_t inv_digest(const proxy_client_connection* c);
    static uint64_t inv_digest(const proxy_backend_connection* b);
    // Every pair the runtime still holds and not just the one a completion
    // named, because the stranded half is the other one, at a descriptor no
    // completion will mention again.
    void inv_sweep_all(const char* where);
    // Completions between sweeps, amortised because a sweep walks the whole
    // descriptor space, and small enough that a stranded pair is reported
    // while the run is going.
    static constexpr uint32_t INV_SWEEP_EVERY = 4096;
    uint32_t m_inv_sweep_countdown{0};
#endif

    // Append a Host header for the endpoint this connection was routed to,
    // false when no usable endpoint is known, in which case the client's own
    // header is left alone.
    bool append_backend_host_header(std::string& out, const proxy_client_connection* conn) const;

    // True when the ring buffer `lent_buf` names (-1 for none) was queued in
    // place, after which the queue entry gives it back and the caller must
    // not.
    bool forward_to_backend(proxy_client_connection* conn, std::string_view data,
                            int lent_buf = -1);
    bool forward_to_client(proxy_backend_connection* conn, std::string_view data,
                           int lent_buf = -1);

    // Mark both sides of a pair whose response an on_proxy_response hook
    // refused, because handle_backend_read is gated on the backend's flag and
    // the client has nothing of its own in flight.
    void refuse_response(proxy_backend_connection* bconn,
                         proxy_client_connection* cconn);
    void send_error(proxy_client_connection* conn, std::string_view status, std::string_view body);
    // The one answer for a request that will never reach a backend, where 502
    // is the backend's answer and 503 is this proxy running short locally --
    // and false is a decision rather than a failure, for TCP mode and for a
    // response already started.
    bool answer_gateway_failure(proxy_client_connection* conn, bool ours);
    // The three conditions on their own, because they are the rule for any
    // status this proxy writes on its own account and there is now more than
    // one caller.
    bool client_answerable(const proxy_client_connection* conn) const;
    // A connection whose buffered request has passed MAX_PARTIAL_SIZE, sibling
    // of the header block's 431, returning what client_answerable said.
    bool answer_request_too_large(proxy_client_connection* conn);
    // Re-arm the listener, falling back to the backoff timer when the
    // submission does not reach the ring, or the proxy stops accepting
    // silently.
    void rearm_accept();
    void schedule_accept_backoff();

    // Both report whether the submission reached the ring; see the
    // definitions for why a caller must not ignore that.
    bool flush_client_write_queue(proxy_client_connection* conn);
    bool flush_backend_write_queue(proxy_backend_connection* conn);

    // ── TLS record layer ────────────────────────────────────────────────────
    // One implementation for both legs, because a terminated client connection
    // and a dialled backend run the same state machine over the same four
    // things -- and OpenSSL does no I/O in either.
    template <typename Conn> void tls_feed(Conn* conn, const char* data, size_t len);
    // False means the submission did not reach the ring, exactly as the two
    // flush functions above report it.
    template <typename Conn> bool tls_flush(Conn* conn);
    // A TLS connection can owe the wire bytes with an empty write queue, which
    // is how a handshake stalls one round short and how an alert is dropped on
    // the way to a teardown.
    template <typename Conn> static bool tls_owes_output(const Conn* conn);

    // Give a backend connection a TLS session and start its handshake, where
    // false means the caller must give the socket up rather than carry on in
    // cleartext.
    bool start_backend_tls(proxy_client_connection* cconn, proxy_backend_connection* bconn);
    // Whether this connection's backend leg is encrypted.
    bool conn_backend_tls(const proxy_client_connection* conn) const;

    // Socket tuning: set optimal buffer sizes and options
    void tune_socket(int fd);

    // Service mesh
    bool is_backend_available(size_t idx);
    // Claim the single half-open probe when this selection is the one that
    // gets it; a no-op for a backend whose circuit is closed.
    void note_backend_selected(size_t idx);
    void health_check_sweep();
    void record_backend_error(size_t backend_idx);
    void record_backend_success(size_t backend_idx);

    // The same three for an endpoint behind an @group backend, which has no
    // index to be charged, so a member that refused every connection kept its
    // full share of the traffic.
    void record_group_error(std::string_view host, uint16_t port);
    void record_group_success(std::string_view host, uint16_t port);
    bool group_endpoint_available(std::string_view host, uint16_t port);
    void note_group_selected(std::string_view host, uint16_t port);
    // Charge whichever breaker describes this connection's backend, because
    // reading backend_idx unconditionally made a healthy backend carry a group
    // member's failures.
    void note_backend_failure(proxy_client_connection* conn);
    void note_backend_success(proxy_client_connection* conn);

    bool try_retry(proxy_client_connection* conn);

    // Start and stop the wait for a backend's first response byte, with arming
    // also starting the sweep, and a group-routed connection charged to the
    // member it reached.
    void arm_response_deadline(proxy_client_connection* conn);
    void clear_response_deadline(proxy_client_connection* conn);
    // Start the wait for the rest of a request's header block, idempotent so a
    // client dribbling one byte at a time cannot renew it for ever.
    void arm_header_deadline(proxy_client_connection* conn);
    // Give up on every deadline that has passed, both on one sweep because an
    // armed timeout hangs off no descriptor and a second chain would be a
    // second thing to get wrong at teardown.
    void response_deadline_sweep();
    // Idempotent, and armed on demand for the same reason as the idle sweep: a
    // proxy with nothing outstanding must not keep a timer chain alive, because
    // an io_uring timeout hangs off no descriptor and cannot be cancelled.
    void arm_response_deadline_sweep();

    proxy_protocol m_protocol = protocol_http;
    proxy_strategy m_strategy = strategy_round_robin;
    std::vector<backend_info> m_backends;
    std::string m_prefix;  // pre-built "/<name>/" to avoid repeated allocation

    // The last snapshot the manager published, immutable and shared and read
    // on the connection path with no lock, null until the first publish.
    std::shared_ptr<const endpoint_table> m_endpoints;

    // What that snapshot says this proxy's backends will answer, merged once
    // per publication, as a copy because it is a union over several backends
    // and belongs to no single one.
    route_table m_routes;

    // ─── Retired I/O ───────────────────────────────────────────────────────
    // One rule everywhere: nothing io_uring may still be reading from is
    // freed, reused or re-armed, but retired into m_retired with its
    // io_requests still pointing here, so the completion lands in
    // absorb_retired().
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

    // Retire `storage`, waiting for the `count` requests in `owed`, releasing
    // it here and now when nothing is owed.
    void retire(std::shared_ptr<void> storage, io_request* const* owed, size_t count);
    // Consume a completion belonging to a retired object, where true means the
    // caller must not look at the request again.
    bool absorb_retired(io_request* req, struct io_uring_cqe* cqe);

    // A timeout and its request allocated per run, because a timer is nearly
    // always in flight when a runtime stops and reaches no shutdown or cancel,
    // so re-arming would leave two sweeps running one state machine.
    struct timer_op
    {
        io_request req{};
        struct __kernel_timespec ts{};
    };

    // The accept request together with the address the kernel fills in, on the
    // same reasoning as timer_op: a stale accept completion arms the listener
    // twice.
    struct accept_op
    {
        io_request req{};
        sockaddr_in addr{};
        socklen_t addrlen{sizeof(sockaddr_in)};
    };

    int m_listen_fd = -1;
    // The path the current listener actually bound, deliberately not
    // get_listen_path(), because the configuration may have been edited
    // between start and stop.
    std::string m_bound_listen_path;
    std::unique_ptr<accept_op> m_accept;
    event_loop* m_loop = nullptr;
    bool m_multishot_active = false;

    // EMFILE/ENFILE accept backoff
    std::unique_ptr<timer_op> m_accept_backoff_timer;

    // Idle connection sweep timer, armed on demand because it evicts stale
    // pooled sockets always, with its armed state tracked so teardown only
    // claims a completion that is really owed.
    std::unique_ptr<timer_op> m_idle_sweep_timer;
    bool m_idle_sweep_armed{false};
    bool m_idle_sweep_warned{false};

    // Backend response deadline sweep, run at a fraction of the deadline and
    // only while at least one request is outstanding.
    static constexpr long RESPONSE_SWEEP_NSEC = 250000000L;   // 250 ms
    std::unique_ptr<timer_op> m_response_sweep_timer;
    bool m_response_sweep_armed{false};
    bool m_response_sweep_warned{false};

#ifdef SOCKETLEY_TRACE
    // Every live proxy on this process, so one instance's sweep can report on
    // all of them, because the stall shows up on a member proxy while only the
    // gateway has a timer running.
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
    // Decoupled from PROXY_READ_BUF_SIZE deliberately, because that also sizes
    // a per-connection buffer and tying the ring to it makes any buffer-size
    // experiment two experiments at once.
    static constexpr uint32_t BUF_SIZE = 65536;
    // At most this many ring buffers on loan to write queues at once, counted
    // per process rather than per instance because the group is one ring per
    // loop and there is one loop per process, so an instance's own count
    // bounds nothing the ring can run out of.
    static constexpr uint32_t RING_BORROW_LIMIT = BUF_COUNT / 4;
    // Below this the copy is not measurable and the 64 KiB a loan pins is.
    static constexpr size_t RING_BORROW_MIN_BYTES = 4096;
    inline static uint32_t s_ring_bufs_lent{0};
    static void give_back_ring_buf(void* loop, uint16_t id);
    // Queue `data` on loan from ring buffer `lent_buf` while the bound allows
    // and as a copy otherwise, true when it was lent.
    bool lend_or_copy(socketley::byte_counted_queue<socketley::write_chunk>& q,
                      std::string_view data, int lent_buf);
    // The buffer id when this read's bytes may be lent to the write queue, and
    // -1 when they must be copied: not the ring's, not a TCP relay, or too few
    // to be worth a whole buffer.
    int lendable_buf(bool is_provided, uint16_t buf_id, size_t len) const
    {
        return (is_provided && m_protocol == protocol_tcp && len >= RING_BORROW_MIN_BYTES)
                   ? static_cast<int>(buf_id) : -1;
    }
    bool m_use_provided_bufs{false};
    bool m_recv_multishot{false};
    // The kernel can do IORING_OP_SPLICE, which says nothing about whether
    // this proxy uses it.
    bool m_splice_supported{false};
    // And it is switched on for this instance, off by default.
    bool m_splice_enabled{false};

    // Connection pool for backend reuse (avoids connect() per request)
    static constexpr size_t MAX_POOL_PER_BACKEND = 32;
    static constexpr int POOL_IDLE_TIMEOUT_SEC = 60;
    std::vector<std::vector<pooled_backend>> m_backend_pool; // per-backend pool
    // A backend was found to have written on a pooled socket, reported once
    // per instance because the condition is a property of the backend rather
    // than of one connection.
    bool m_pool_unbidden_warned{false};
    // The same finding on an encrypted socket, as a separate flag because
    // there the bytes are routine and what OpenSSL made of them is the
    // evidence.
    bool m_pool_tls_unbidden_warned{false};

    // ─── TLS ───────────────────────────────────────────────────────────────
    // Both contexts are built in setup() and dropped on the next start, so
    // `reload` installs a renewed certificate, and null means cleartext on
    // that leg -- which only a refused start can produce for a configured one.
    std::unique_ptr<tls_context> m_tls;          // this proxy's own listener
    std::unique_ptr<tls_context> m_backend_tls;  // the leg to the backends

    // The backend-TLS options were given, so every backend is reached over TLS
    // including a group's members, kept apart from the per-backend flag
    // because that is what a group-routed connection asks.
    bool m_backend_tls_all{false};
    // Set once setup() has resolved every backend, so a table arriving
    // before that is stashed for setup() rather than resolved against twice.
    bool m_backends_resolved{false};

    // Service mesh
    mesh_config m_mesh{};
    std::vector<backend_health> m_backend_health;
    std::vector<circuit_breaker> m_circuit_breakers;

    // Breakers for endpoints behind an @group backend, as a map because the
    // set is membership the proxy does not own, with entries appearing only on
    // failure so a group that works costs one empty-map test.
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

    // Addresses for group members advertised by name, keyed by host with the
    // port applied at selection, pruned to the size of the membership rather
    // than of its history.
    std::unordered_map<std::string, in_addr> m_group_addr;
    // Nodes already announced in the log, so a republish does not repeat them.
    std::unordered_set<std::string> m_group_nodes_said;
    // Some member did not resolve, so the idle sweep has a reason to run and
    // to keep running.
    bool m_group_unresolved = false;
    std::unique_ptr<timer_op> m_health_check_timer;

    // Async health checks, one probe per backend per sweep held by pointer so
    // the address the ring was given never moves.
    std::vector<std::unique_ptr<async_health_check>> m_health_checks;
    bool m_health_checks_pending{false};
    std::unique_ptr<timer_op> m_health_timeout_timer;
    // Give up on a probe: retire it if the ring still owes it a completion,
    // release it otherwise, and leave the slot empty for the next sweep.
    void drop_health_check(size_t idx);
    // The probe's three submissions in one place each, all reporting whether
    // the submission reached the ring, because a caller that ignores that
    // leaves a probe waiting for a completion that cannot come.
    bool health_submit_write(async_health_check* hc);
    bool health_submit_read(async_health_check* hc);
    // One turn of an encrypted probe, picking the phase from tls_state so the
    // same function drives the handshake and the request that follows it.
    bool health_tls_arm(async_health_check* hc);
    // Inbound ciphertext from cipher_in into the read BIO, where false is
    // fatal for the probe by contract.
    bool health_tls_feed(async_health_check* hc, int len);

    // C++ proxy intercept hooks
    proxy_hook m_cb_on_proxy_request;
    proxy_hook m_cb_on_proxy_response;

    // Connection struct pools — reuse allocations to avoid malloc/free per connect/disconnect
    static constexpr size_t CONN_POOL_INIT = 32;
    std::vector<std::unique_ptr<proxy_client_connection>> m_client_pool;
    std::vector<std::unique_ptr<proxy_backend_connection>> m_backend_struct_pool;

    std::unique_ptr<proxy_client_connection> client_pool_acquire(int fd);
    // Hand a connection struct back for reuse or retire it when the ring still
    // owes a completion, in the one place every close path goes through.
    void client_pool_release(std::unique_ptr<proxy_client_connection> conn);
    std::unique_ptr<proxy_backend_connection> backend_pool_acquire(int fd);
    void backend_pool_release(std::unique_ptr<proxy_backend_connection> conn);

    // Cached config to avoid virtual calls on hot path
public:
    void refresh_cached_limits() override
    {
        m_idle_timeout_cached = get_idle_timeout();
        m_max_conns_cached    = get_max_connections();
        m_rate_limit_cached   = get_rate_limit();
    }

private:
    uint32_t m_idle_timeout_cached{0};
    uint32_t m_max_conns_cached{0};
    // --rate-limit read once at setup, and read at all, which it was not: this
    // proxy stored the value, reported it from `show`, and never looked at it
    // again.
    double m_rate_limit_cached{0.0};

    // Peak connections high-water mark
    size_t m_peak_connections{0};

    // The reused availability list for random selection over healthy backends,
    // held here rather than on the stack so the backend count is not bounded
    // by a frame-sized array.
    std::vector<size_t> m_avail_scratch;
};
