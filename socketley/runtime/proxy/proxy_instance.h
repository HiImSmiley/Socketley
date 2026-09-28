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
#include "../../shared/sockmap_relay.h"
#include "../../shared/fast_lo.h"

struct runtime_endpoint;

class runtime_manager;

// The port a proxy listens on when none was configured.  Named once because
// setup() and listen_addresses() have to answer with the same number.
inline constexpr uint16_t proxy_default_port = 8080;

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
// How much of a request a retry can resend: past it the body has gone to one
// backend and cannot be sent again whole.
static constexpr size_t RETRY_KEEP_BYTES = 64 * 1024;

// How long a client may take to finish a header block once it has started one,
// deliberately not a flag and not tied to --idle-timeout, whose default of 0
// must not switch it off.
// In shared/http_framing.h now, because the server asks the same question and
// answered it differently -- which is to say not at all.
static constexpr int PROXY_HEADER_TIMEOUT_SEC = http_header_deadline_secs;
// A client answered and closed on is read away for at most this long and
// this much, the server's bounds for the same drain.
static constexpr int      PROXY_DRAIN_LIMIT_SEC   = 10;
static constexpr uint32_t PROXY_DRAIN_LIMIT_BYTES = 64u << 20;

struct alignas(64) proxy_client_connection
{
    static constexpr size_t MAX_WRITE_BATCH = 16;
    static constexpr size_t MAX_PARTIAL_SIZE = 1 * 1024 * 1024;
    static constexpr size_t MAX_HEADER_SIZE = 16384;

    // === HOT fields (CQE dispatch) — first 2 cache lines ===
    int fd{-1};
    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};
    // Consecutive reads that drained the socket, which is what earns multishot.
    uint8_t drained_reads{0};
    // A multishot read taken back because the backend it feeds is over the
    // pacing point: set when the cancel is submitted, cleared by the -ECANCELED
    // that ends it or by any other completion that ends it first.  The backend
    // half of this is proxy_backend_connection::recv_withdrawing.
    bool recv_withdrawing{false};
    bool splice_active{false};
    bool splice_in_pending{false};
    bool splice_out_pending{false};
    // This pair's bytes move inside the kernel, so no read or splice is armed
    // and only the abort poll watches the socket.
    bool sockmap_active{false};
    // The client half-closed on a kernel-relayed pair, so the sweep may pass
    // the FIN on once the backend has sent everything the client sent.
    bool sockmap_client_eof{false};
    // The backend half-closed on a kernel-relayed pair, its mirror.
    bool sockmap_backend_eof{false};
    bool header_parsed{false};
    bool response_started{false};
    bool client_conn_close{false};  // client sent Connection: close
    // Our FIN is out, sent before the armed read comes back so the client is not the one to close.
    bool wr_shutdown{false};
    // Answered on our own account with the request possibly still arriving,
    // so it is read away after our FIN until EOF, the byte bound, or
    // header_deadline, which the answer no longer needs.
    bool drain_on_close{false};
    int backend_fd{-1};
    uint32_t write_batch_count{0};
    uint32_t drained_bytes{0};
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
    // When the handshake began, which the deadline reads instead of
    // last_activity.  last_activity is refreshed on every read -- but only when
    // --idle-timeout is set, so the deadline silently changed meaning with a
    // flag that has nothing to do with it: measured, a peer dribbling one byte
    // every twenty seconds inside an unfinished record held its slot for ever
    // WITH --idle-timeout and lost it in 63 seconds without.  Flat, like the
    // client's, because a handshake is bounded by round trips and not by data.
    std::chrono::steady_clock::time_point handshake_since{};


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
    // body_unbounded the chunked case, walked by req_chunk to its last chunk.
    size_t body_remaining{0};
    bool body_unbounded{false};
    http_chunked_decoder req_chunk{};

    // The client's address as X-Forwarded-For names it, looked up on the
    // connection's first request and kept for the rest.
    std::string peer_addr;

    // Request headers a filter set on the request now being parsed, per
    // request rather than per connection, or the second request on a
    // keep-alive socket would carry the first one's identity.
    std::vector<std::pair<std::string, std::string>> filter_headers;

    // Names a filter asked to remove, under the same lifetime rules and the
    // same ban list, because a filter that could remove Content-Length would
    // change how the message is framed.
    std::vector<std::string> filter_removed_headers;

    // Each direction's counters when this pair entered the kernel relay, which
    // the FIN drain, the backlog bound and the teardown byte count read against.
    socketley::sockmap_relay::direction_base sockmap_up{};
    socketley::sockmap_relay::direction_base sockmap_down{};
    // Bytes relayed both ways at the last sweep, so a kernel-relayed pair that
    // moved bytes counts as active for --idle-timeout.
    uint64_t sockmap_seen{0};

    std::chrono::steady_clock::time_point last_activity{};
    int retries_remaining{0};
    size_t backend_idx{0};
    std::string saved_request;
    // The backend kept idle for this connection's next request, or -1; see
    // proxy_instance::park_backend.
    int parked_backend_fd{-1};
    // An exchange on this connection has finished and it stayed open, which
    // is the evidence park_backend waits for.
    bool kept_alive{false};
    // The request in saved_request went whole onto a socket taken from
    // parking, so an answer that never starts may be asked for again.
    bool reissue_ok{false};

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

    // Inline and built by make_connection, so these pages are touched by the
    // reads that use them and an idle connection never pays for them.
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
    int fd{-1};
    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};
    // Consecutive reads that drained the socket, which is what earns multishot.
    uint8_t drained_reads{0};
    // Sends refused for memory in a row, which sets how long the next one waits.
    uint8_t send_retries{0};
    bool splice_active{false};
    bool splice_in_pending{false};
    bool splice_out_pending{false};
    // See the client side: this backend's bytes move inside the kernel.
    bool sockmap_active{false};
    // A poll for POLLERR|POLLHUP|POLLRDHUP on the backend of a kernel-relayed
    // pair, the mirror of the client's abort watch, because with no armed read
    // nothing else reports the backend's reset or half-close.
    bool abort_watch_pending{false};
    // The response is finished and this connection is on its way to the pool
    // with a cancelled read still owed, so nothing may touch the fd until that
    // completion lands.
    bool pool_draining{false};
    // A multishot read taken back because the client it feeds is over the
    // pacing point: set when the cancel is submitted, cleared by the
    // -ECANCELED that ends it or by any other completion that ends it first.
    bool recv_withdrawing{false};
    // Application bytes came off this backend socket and went to the client,
    // stated so a TCP proxy can ask it, since response_started is never set
    // outside HTTP mode.
    bool sent_to_client{false};
    // The backend has shut its write side, so its read is not armed again and
    // the pair lives on for what the client still sends.
    bool backend_eof{false};
    // Idle between two requests of the client in parked_for, with client_fd
    // -1 and only its read armed, so any completion means it is unusable.
    bool parked{false};
    int client_fd{-1};
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
    // The backend abort watch's request, see abort_watch_pending.
    io_request abort_req;
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
    // The client a parked connection is kept for, -1 otherwise.
    int parked_for{-1};
    // Taken from parking or the pool for the exchange now on it, so the
    // stream carries earlier answers and its first bytes are checked.
    bool reused{false};
    // The loop turn it was parked in and when, the second also carried into
    // the pool by release_to_pool so its age survives the move.
    uint64_t park_turn{0};
    std::chrono::steady_clock::time_point idle_since{};

    SKL_TRACE_FIELD(tr)
    SKL_INV_FIELD(pr)

    // See proxy_client_connection::read_buf.
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
    int fd{-1};
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

    // What setup() will bind, answered without binding it; see the base class.
    void listen_addresses(std::vector<std::string>& out) const override;
    uint16_t effective_port() const override;

    size_t get_connection_count() const override;
    // What this proxy owes across both legs, which is what decides the pacing
    // point; without it the base answers 0 and the point never moves.
    size_t total_queued_bytes() const override;

    // Once a turn, immediately after refresh_pacing_watermark() has settled the
    // two numbers this reads.
    void on_loop_turn() override;
    void withdraw_armed_backend_reads();
    void withdraw_armed_client_reads();
    void finish_client_recv_withdraw(proxy_client_connection* conn,
                                     struct io_uring_cqe* cqe, io_request* req);
    bool backend_backpressured(const proxy_client_connection* conn) const;
    bool client_read_armable(const proxy_client_connection* conn) const;
    bool backend_read_armable(const proxy_backend_connection* conn) const;
    void finish_recv_withdraw(proxy_backend_connection* conn,
                              struct io_uring_cqe* cqe, io_request* req);
    bool client_backpressured(const proxy_backend_connection* conn) const;

    // Arming a read goes through here and nowhere else, so the question that
    // decides multishot is asked in one place rather than at twenty call sites.
    // poll_first only where the read just completed left the socket empty.
    bool arm_read(int fd, proxy_client_connection* conn, bool poll_first = false);
    bool arm_read(int fd, proxy_backend_connection* conn, bool poll_first = false);
    bool earned_multishot(uint8_t drained_reads) const;
    void decline_armed_read(proxy_client_connection* conn);
    void decline_armed_read(proxy_backend_connection* conn);

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
    // A backend socket is non-blocking for its connect, so a send the kernel
    // refuses under TCP memory pressure comes back as -EAGAIN instead of
    // waiting; this waits in its place and offers the same batch again.
    bool defer_backend_send(proxy_backend_connection* conn);
    void retry_backend_send(proxy_backend_connection* conn, int res);
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
    void drive_client_request(proxy_client_connection* conn, int fd, bool poll_first = false);

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
    // Writes into `result` rather than returning a string, so the buffer the
    // caller passes keeps its capacity from one request to the next.
    void rewrite_http_request(proxy_client_connection* conn,
                              std::string_view new_path, std::string& result);

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
    void queue_final_response(proxy_client_connection* conn, std::string&& response,
                              bool drain = true);

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
    void shutdown_client_write(proxy_client_connection* conn);
    bool continue_drain(proxy_client_connection* conn, int fd, size_t bytes);
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
    // And the same for a backend that has shut its write side first.
    bool hold_backend_half_close(proxy_backend_connection* bconn);
    void forward_backend_half_close(proxy_client_connection* cconn);
    bool tcp_pair_done(const proxy_client_connection* c,
                       const proxy_backend_connection* b) const;
    void detach_and_pool_backend(proxy_client_connection* cconn, int backend_fd);
    // Keeping a finished backend for its client's next request, which HAProxy
    // calls `http-reuse safe`: true when it was kept and the caller must
    // return, with the client already reset for that request.
    bool park_backend(proxy_client_connection* cconn, proxy_backend_connection* bconn);
    // The parked backend reattached for the request being routed, false when
    // there is none or the request goes to another endpoint.
    bool take_parked_backend(proxy_client_connection* conn);
    // The client's parked backend handed to the shared pool by the road
    // detach_and_pool_backend takes, for a client going away or routed
    // elsewhere.
    void release_parked_backend(proxy_client_connection* cconn);
    proxy_backend_connection* parked_backend_of(proxy_client_connection* cconn);
    void drop_parked_backend(proxy_backend_connection* bconn);
    void unpark(proxy_backend_connection* bconn);
    // A completion on a parked backend, which is an EOF, an error or bytes
    // nobody asked for, and is never charged to the backend.
    void finish_parked_read(proxy_backend_connection* bconn,
                            struct io_uring_cqe* cqe, io_request* req);
    void warn_pool_unbidden();
    // Sends an idempotent request again on a fresh connection when the socket
    // it was taken from parking for closed before a byte of the answer, true
    // when the client has been dealt with and the caller must return.
    bool reissue_unanswered(proxy_client_connection* cconn, proxy_backend_connection* bconn);
    // An answer on a reused socket that cannot be an HTTP response, sent again
    // on a fresh connection or refused 502; false when there is no client
    // waiting on it and the ordinary path goes on.
    bool refuse_desynced_answer(proxy_backend_connection* bconn, int bfd);
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

    // Move a plain TCP pair into the kernel relay, false when it cannot (not
    // enabled, TLS, a hook, or the load failed) so the caller uses the copy
    // path.  Returns true once the pair is entering, including the deferred
    // case where saved bytes are still draining to the backend.
    bool try_enter_sockmap(proxy_client_connection* conn, proxy_backend_connection* bconn);
    // The actual map insertion and abort-poll arming, once the backend queue is
    // empty; false leaves the pair on the copy path.
    bool enter_sockmap_now(proxy_client_connection* conn, proxy_backend_connection* bconn);
    // Take a pair back out of the kernel path and drop it from m_sockmap_pairs;
    // reads are not re-armed because teardown or the copy path follows.
    void leave_sockmap(proxy_client_connection* conn);
    // Arm the backend's POLLERR|POLLHUP|POLLRDHUP watch, the mirror of the
    // client's, false on refusal.
    bool arm_backend_abort(proxy_backend_connection* bconn);
    // Pass on a kernel-relayed pair's held FIN(s) once each direction has
    // drained, and tear the pair down once both FINs are through.
    void sockmap_try_advance(proxy_client_connection* conn, proxy_backend_connection* bconn);
    // Walk the kernel-relayed pairs from the 250 ms sweep: pass on a held FIN
    // once its direction has drained, and pull a pair off the kernel path when
    // its backlog passes the copy path's write bound so backpressure applies.
    void sockmap_backlog_sweep();
    // Charge a kernel-relayed pair's bytes, read from TCP_INFO, to the byte
    // counters the redirect never touched, once at teardown.
    void sockmap_account_at_close(int client_fd, int backend_fd);
    // The backend side of op_poll_abort on a kernel-relayed pair.
    void handle_backend_abort(struct io_uring_cqe* cqe, io_request* req);

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
                           int lent_buf = -1, bool last = false);
    bool send_final_and_fin(proxy_client_connection* cconn, std::string_view data);

    // Mark both sides of a pair whose response an on_proxy_response hook
    // refused, because handle_backend_read is gated on the backend's flag and
    // the client has nothing of its own in flight.
    void refuse_response(proxy_backend_connection* bconn,
                         proxy_client_connection* cconn);
    void send_error(proxy_client_connection* conn, std::string_view status, std::string_view body,
                    bool drain = true);
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
    // Hands what write_batch holds to the ring, false when nothing reached it.
    template <typename Conn> bool submit_write_batch(Conn* conn);
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
    // Backends parked on a client, a subset of m_backend_count, capped at
    // MAX_POOL_PER_BACKEND so idle clients hold no more idle backend sockets
    // than the pool itself would.
    size_t m_parked_count{0};
    // Loop turns seen, so a socket parked this turn can be told apart.
    uint64_t m_turn{0};

    proxy_conn_entry m_conn_idx[MAX_FDS]{};
    backend_info m_scratch_backend{};

    size_t m_rr_index = 0;
    std::mt19937 m_rng{std::random_device{}()};

    // Provided buffer ring, 4 MiB like the cache's and the server's, because a
    // ring turns through every buffer and is resident in full once it has.
    static constexpr uint16_t BUF_GROUP_ID = 2;
    static constexpr uint32_t BUF_COUNT = 64;
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
    // What of `out` the socket took at once, sent directly when nothing is
    // queued ahead of it; 0 when it must go through the queue.
    template <typename Conn> size_t send_now(Conn* c, std::string_view out);
    // The buffer id when this read's bytes may be lent to the write queue, and
    // -1 when they must be copied: not the ring's, not a TCP relay, or too few
    // to be worth a whole buffer.
    int lendable_buf(bool is_provided, uint16_t buf_id, size_t len) const
    {
        return (is_provided && m_protocol == protocol_tcp && len >= RING_BORROW_MIN_BYTES)
                   ? static_cast<int>(buf_id) : -1;
    }
    bool m_use_provided_bufs{false};
    // Which arm the NEXT read is submitted with, recomputed once a turn by
    // on_loop_turn(); an already-armed multishot recv keeps its own.
    bool m_recv_multishot{false};
    // Whether this kernel and this buffer ring could do it at all, which is a
    // different question from whether this turn wants it.
    bool m_recv_multishot_supported{false};
    // SOCKETLEY_RECV_MULTISHOT=1 pins the arm on for a measurement; unset is
    // the rule.  There is no `never` here because =0 is answered by the loop,
    // for every runtime at once.
    enum class multishot_arm : uint8_t { adaptive, always };
    multishot_arm m_multishot_arm{multishot_arm::adaptive};
    // Where a multishot recv starts paying for itself, measured on this box at
    // 8 KiB bodies as the median of the per-pass differences against a
    // single-shot arm of the same binary.  Positive is single-shot ahead:
    //
    //      connections      difference        range
    //              128           +7.70%   +6.7 .. +12.7
    //              256           +7.70%   +3.7 ..  +8.5
    //              512           +6.01%   +3.1 ..  +9.9
    //              640           -6.84%  -12.0 ..  +3.9    <- crosses zero
    //              768          -15.01%  -18.6 ..  +0.1
    //
    // 768 is the first count where the answer is not in doubt, which is the
    // rule this threshold was set by the first time as well.
    //
    // IT MOVED.  Set at 1024 on the first measurement, where the crossover read
    // 768 and 896 read -12.9%; re-measured after the withdrawal commits it is
    // between 512 and 768, so 1024 had drifted a full step above the point it
    // was chosen to sit just past.  Between the two the proxy was picking
    // single-shot where multishot is 15% faster.  A number measured once is a
    // number for that day: this one is worth re-taking after anything that
    // touches on_loop_turn or the read path.
    //
    // NOT the buffer ring.  BUF_COUNT was 512 when this was measured and the
    // crossover sat just above it, which looked like a mechanism and was not:
    // at 768 connections multishot leads by 11.96%, 15.01% and 15.89% with
    // the ring at 256, 512 and 1024, and
    // at 384 connections single-shot still leads with a ring of 256.  The
    // crossover does not track the ring, so this stays a measured number rather
    // than a derived one.
    //
    // The count is not the whole rule: the queue depth is the second condition,
    // and it is worth something only because withdraw_armed_backend_reads()
    // exists.  Gated on pacing_backed_up() ALONE it was measured to change
    // nothing at all -- 1,200 clients that ask for a 1 MiB body and stop reading
    // put the gate on for 96.5% of turns and had it pick single-shot on 99% of
    // them, and the hold was 949 and 1014 MB against 943 and 1046 with the arm
    // pinned on.  The fleet was already armed during the ramp, before any queue
    // existed, and an armed multishot recv keeps its arm; deciding the next read
    // differently reaches none of them.
    //
    // What the two conditions together are worth, and what the count alone was.
    // Clients that ask for a 1 MiB body and then stop reading, three arms in one
    // run, three passes each, interleaved, worker RSS above its own baseline:
    //
    //      clients   pinned on   this rule   pinned off
    //           16       34 MB       26 MB           --
    //           64       97 MB       54 MB           --
    //          128      165 MB       69 MB           --
    //         1200     1016 MB      449 MB       351 MB
    //
    // Below the threshold the rule IS the off arm, which is why that column is
    // empty there.  At 1200 it was 1007 MB before the withdrawal existed -- the
    // count had picked multishot and nothing could decline it -- and 449 after,
    // against a 351 MB floor.  The 100 MB above the floor is the ramp: the
    // withdrawal acts a turn late and cannot un-queue what already arrived.
    //
    // It is not free, and the price is on the other side of the same condition:
    // 1,200 connections with 1 MiB bodies and clients that DO read cost 7.5%
    // against the arm pinned on, because a total over the pacing budget cannot
    // tell a slow peer from a busy one.  At 8 KiB bodies the same comparison is
    // -0.50%, since 1,200 of those never reach the budget at all.  Two narrower
    // shapes were measured and refused: withdrawing without gating the arm holds
    // 760 MB, because the connection is re-armed multishot and reads ahead
    // again; making the single-shot arm sticky per connection instead holds
    // 542 MB and costs 11.1%, because a connection that crossed the watermark
    // once never goes back.
    // NOT per connection.  The withdrawal asks client_backpressured() about one
    // connection while the arm reads this count, which looks like the two halves
    // disagreeing -- so the arm was made to ask the same per-connection question
    // and the gate on the total was dropped.  That is 5.40% faster at 1,200
    // connections and 1 MiB bodies with clients that read (seven passes, range
    // 2.71..7.89, worker at 1.00 cores in both arms, client at 0.25), and it
    // costs the property this rule exists for.  Held against the arm pinned on,
    // one run each, same day, same box:
    //
    //      what the arm asks              upload hold   slow-client hold
    //      the total (this rule)                 42%          70%
    //      the connection                        74% FAIL     80%
    //      the connection, under 1/4 point       57%          85%
    //      the connection, under 1/16 point      58%          93% FAIL
    //
    // The bounds there are 60% and 88%, from the two tests that measure them.
    // Margin at the arm does not buy the bound back, and 1/16 is worse than 1/4
    // on the second row: the depth at arm time says little about what an armed
    // recv goes on to deliver, because it keeps delivering until the cancel
    // lands and the cancel is a turn late.  The gate on the total is a brake on
    // the whole fleet the moment the proxy is over budget, which is earlier and
    // broader than any question about one connection.  The two halves were not
    // disagreeing: what they owe each other is that the withdrawal must not take
    // back a read nothing re-arms, which is liveness and not a shared threshold.
    static constexpr size_t MULTISHOT_MIN_CLIENTS = 768;
    // Consecutive draining reads after which a TCP relay's connection is armed
    // multishot below that count, see earned_multishot().
    static constexpr uint8_t MULTISHOT_DRAINED_READS = 8;
    // The kernel can do IORING_OP_SPLICE, which says nothing about whether
    // this proxy uses it.
    bool m_splice_supported{false};
    // And it is switched on for this instance, off by default.
    bool m_splice_enabled{false};

    // The in-kernel TCP relay, off by default and shared by every pair on this
    // instance; null until SOCKETLEY_PROXY_SOCKMAP asks for it and it loads.
    std::unique_ptr<socketley::sockmap_relay> m_sockmap;
    bool m_sockmap_enabled{false};
    bool m_sockmap_warned{false};
    // Pairs the kernel is relaying, one client fd each, walked by the 250 ms
    // sweep for backlog and half-close because these legs have no armed read.
    std::vector<int> m_sockmap_pairs;

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
    std::unique_ptr<proxy_backend_connection> backend_pool_acquire(
        int fd, const proxy_client_connection* cconn);
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
