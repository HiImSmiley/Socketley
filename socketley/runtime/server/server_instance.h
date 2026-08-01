#pragma once
#include <string>
#include <string_view>
#include <unordered_map>
#include <memory>
#include <queue>
#include <vector>
#include <netinet/in.h>
#include <sys/uio.h>
#include <unistd.h>
#include <cstdlib>
#include <filesystem>

#include "../../shared/runtime_instance.h"
#include "../../shared/write_queue.h"
#include "../../shared/event_loop_definitions.h"
#include "../../shared/request_channel.h"
#include "../../shared/tls_context.h"
#include <linux/time_types.h>

class runtime_manager;

// tls_conn_state lives in shared/tls_context.h, included above: the proxy runs
// the same state machine on both of its legs, and a second spelling of it
// would be a second thing to keep in step.

enum proto_state : uint8_t {
    proto_unknown     = 0,
    proto_tcp         = 1,  // newline-delimited text
    proto_http        = 2,  // HTTP request (not WS upgrade)
    proto_ws_upgrading = 3,
    proto_ws          = 4,  // active WebSocket
    proto_resp        = 5   // RESP2 wire protocol
};

struct alignas(64) server_connection
{
    static constexpr size_t MAX_WRITE_BATCH = 32;
    static constexpr size_t MAX_PARTIAL_SIZE = 1 * 1024 * 1024;
    static constexpr size_t READ_BUF_SIZE = 16384;  // 16KB read buffer

    // === HOT fields (CQE dispatch path) — first 2 cache lines ===
    int fd{-1};
    int fixed_idx{-1};       // io_uring fixed file table index (-1 = not registered)
    // Identity of the connection currently living in this struct.  Structs are
    // pooled and file descriptor numbers are reissued, so "same address, same
    // fd" is not the same connection; every request this connection submits
    // carries this stamp and the dispatcher compares before acting on it.
    uint32_t generation{0};
    bool direct_fd{false};   // true if fd came from direct-accept (fixed file index)
    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};
    bool zc_notif_pending{false};
    proto_state proto{proto_unknown};
    bool routed{false};
    bool file_read_pending{false};
    bool http_keep_alive{false};
    uint32_t active_idx{0};  // index in m_active_fds for O(1) removal
    uint32_t write_batch_count{0};

    // === TLS session ===
    // Non-null only on a listener configured with --tls.  OpenSSL never sees
    // this socket: the session is fed ciphertext a read completion delivered
    // and drained of ciphertext that a write submission carries, so nothing
    // the kernel holds ever names it or its memory BIOs — every byte is copied
    // into or out of a buffer this struct owns before any SQE is built.
    //
    // Who may free this: this struct, and nothing else.  It is released in
    // pool_release() on the way back to the pool, in reset() as a second line
    // of defence for a struct coming back out, and in ~server_connection for
    // one that reaches neither because the runtime stopped with its
    // completions still outstanding.  Because no completion can name the
    // session, freeing it never has to wait on the ring — unlike the write
    // batch and the file buffer beside it.
    SSL* ssl{nullptr};
    tls_conn_state tls_state{tls_conn_none};
    // The peer's close_notify, remembered rather than acted on.  The read that
    // carries it can carry the last request ahead of it, and marking the
    // connection closing before that request is parsed answers it with a
    // dropped connection; handle_read applies this once the parse is done.
    bool tls_peer_closed{false};

    io_request read_req;
    io_request write_req;

    // === WARM fields (message processing path) ===
    std::string partial;
    socketley::byte_counted_queue<std::shared_ptr<const std::string>> write_queue;

    // writev batch: holds refs alive until CQE completes
    std::shared_ptr<const std::string> write_batch[MAX_WRITE_BATCH];
    struct iovec write_iovs[MAX_WRITE_BATCH];

    // === COLD fields (rarely accessed per-CQE) ===

    // Async file read state (HTTP static file serving)
    io_request file_read_req;
    int file_fd{-1};
    char* file_buf{nullptr};
    size_t file_size{0};
    std::string file_content_type;
    bool file_is_html{false};

    // Splice state for zero-copy file serving (non-HTML only)
    io_request splice_in_req;
    io_request splice_out_req;
    int splice_file_fd{-1};
    size_t splice_remaining{0};
    uint32_t splice_pipe_pending{0};
    // Headers are queued and the file→pipe splice starts once they are on the
    // wire; this says the transfer is owed, not that an op is armed.
    bool splice_pending{false};
    // These two say an op is armed.  splice_remaining and splice_pending are
    // transfer bookkeeping that splice_cleanup zeroes, so guarding a close with
    // them proved nothing: the cleanup made the guard true and the connection
    // was freed with a splice still running against its fd and its requests.
    bool splice_in_pending{false};
    bool splice_out_pending{false};

    // WebSocket handshake headers (non-empty only for ws_active connections)
    std::string ws_cookie;
    std::string ws_origin;
    std::string ws_protocol;  // Sec-WebSocket-Protocol
    std::string ws_auth;      // Authorization

    // Rate limiting (token bucket)
    double rl_tokens{0.0};
    double rl_max{0.0};
    std::chrono::steady_clock::time_point rl_last{};

    // Master auth attempt tracking
    uint8_t auth_failures{0};

    // Cache requests this connection has asked for and not been answered yet.
    //
    // A count and not a queue: the request channel answers one origin in the
    // order it posted, so a reply is written the moment it arrives and the wire
    // order is the request order without anything having to be held.  What this
    // is for is the cap — a client pipelining `cache` commands can post them far
    // faster than the channel drains, and an unbounded backlog is a
    // memory-exhaustion path reachable from one socket.
    //
    // Nothing in flight points into this struct: the channel copies the payload
    // and carries a cookie, so the connection can be closed and pooled with
    // requests still queued, and the stale reply is dropped by the generation
    // check in on_request_reply().
    uint32_t cache_pending{0};

    // WebSocket fragment reassembly (zero-alloc, in-place compaction in partial)
    size_t ws_frag_len{0};
    uint8_t ws_frag_opcode{0};

    // Idle connection tracking
    std::chrono::steady_clock::time_point last_activity{};

    // Pipe pairing: fd of peer connection for zero-copy forwarding (-1 = not piped)
    int pipe_peer_fd{-1};

    // Per-connection metadata (freed automatically on disconnect)
    std::unordered_map<std::string, std::string> meta;

    // Multicast group memberships (cleaned up on disconnect)
    std::vector<std::string> groups;

    // 16KB read buffer — at the very end to keep hot fields in first cache lines
    char read_buf[READ_BUF_SIZE];

    // What a struct owns that no container releases for it.
    //
    // Normally pool_release() does this, and every connection reaches it — but
    // only by way of a completion.  A connection with a file read still in
    // flight is put on the retired list, and if the runtime stops before that
    // completion lands the loop drops it rather than dispatching it, so
    // reap_retired() never runs and pool_release() never happens.  The struct is
    // then freed with the instance, and the file's whole contents go with it:
    // one malloc the size of the file served, per connection, held until the
    // process exits.  The descriptors are the same story a level down.
    //
    // Reached only when the instance itself is going away, which runtime_manager
    // does only once the ring owes it nothing — so no submission can still name
    // either descriptor and a plain close is right, exactly as it is in reset().
    ~server_connection()
    {
        free(file_buf);
        if (file_fd >= 0)        close(file_fd);
        if (splice_file_fd >= 0) close(splice_file_fd);
        // The session, for a struct that never reached pool_release() — a
        // retired connection whose completion was dropped when the runtime
        // stopped.  Safe here for the same reason it is safe anywhere: no
        // submission ever named it.
        tls_context::free_ssl(ssl);
    }

    server_connection() = default;
    server_connection(const server_connection&) = delete;
    server_connection& operator=(const server_connection&) = delete;

    // Connection pool support: reset to initial state for reuse
    void reset(int new_fd)
    {
        fd = new_fd;
        fixed_idx = -1;
        direct_fd = false;
        // pool_release() already did this; repeated here because a struct
        // leaving the pool must not carry the previous connection's session
        // under any circumstances, and this is the last point at which that
        // can still be true.
        tls_context::free_ssl(ssl);
        ssl = nullptr;
        tls_state = tls_conn_none;
        tls_peer_closed = false;
        read_req = {};
        write_req = {};
        write_queue.clear();
        for (uint32_t i = 0; i < write_batch_count; i++) write_batch[i].reset();
        write_batch_count = 0;
        read_pending = false;
        write_pending = false;
        closing = false;
        zc_notif_pending = false;
        if (file_fd >= 0) { close(file_fd); file_fd = -1; }
        if (file_buf) { free(file_buf); file_buf = nullptr; }
        file_read_req = {};
        file_size = 0;
        file_content_type.clear();
        file_is_html = false;
        file_read_pending = false;
        splice_in_req = {};
        splice_out_req = {};
        if (splice_file_fd >= 0) { close(splice_file_fd); splice_file_fd = -1; }
        splice_remaining = 0;
        splice_pipe_pending = 0;
        splice_pending = false;
        splice_in_pending = false;
        splice_out_pending = false;
        http_keep_alive = false;
        proto = proto_unknown;
        routed = false;
        ws_cookie.clear();
        ws_origin.clear();
        ws_protocol.clear();
        ws_auth.clear();
        rl_tokens = 0.0;
        rl_max = 0.0;
        auth_failures = 0;
        cache_pending = 0;
        ws_frag_len = 0;
        ws_frag_opcode = 0;
        pipe_peer_fd = -1;
        partial.clear();
        meta.clear();
        groups.clear();
    }
};

struct http_request
{
    std::string_view method;
    std::string_view path;
    std::string_view version;
    std::string_view body;
    std::string_view query;  // everything after '?'
    std::vector<std::pair<std::string_view, std::string_view>> headers;
    int client_id{-1};
};

enum server_mode : uint8_t
{
    mode_inout  = 0,
    mode_in     = 1,
    mode_out    = 2,
    mode_master = 3
};

struct upstream_target
{
    std::string address;        // "host:port" as specified by user
    std::string resolved_host;
    uint16_t resolved_port{0};
};

struct upstream_connection
{
    static constexpr size_t MAX_WRITE_BATCH = 32;
    static constexpr size_t MAX_PARTIAL_SIZE = 1 * 1024 * 1024;
    static constexpr size_t READ_BUF_SIZE = 16384;  // 16KB read buffer

    int conn_id;                  // 1-based Lua-facing ID (stable across reconnects)
    int fd{-1};
    // Same purpose as server_connection::generation: an upstream socket's fd
    // number can be reissued to an accepted client, and the client index is
    // consulted first, so the completion needs to say which one it belongs to.
    uint32_t generation{0};
    upstream_target target;
    io_request read_req;
    io_request write_req;
    char read_buf[READ_BUF_SIZE];
    std::string partial;
    socketley::byte_counted_queue<std::shared_ptr<const std::string>> write_queue;
    std::shared_ptr<const std::string> write_batch[MAX_WRITE_BATCH];
    struct iovec write_iovs[MAX_WRITE_BATCH];
    uint32_t write_batch_count{0};
    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};
    bool connected{false};
    int reconnect_attempt{0};
    io_request timeout_req{};
    struct __kernel_timespec timeout_ts{};
    // A reconnect timer is not attached to an fd, so nothing a stop does can
    // cancel it; it stays armed on this struct for up to 30 seconds.
    bool timeout_pending{false};

    // Resolved endpoint, kept across reconnects.  upstream_try_connect runs on
    // the event loop thread, so every name lookup it performs stalls every other
    // connection this runtime is serving — and a flapping upstream retries on a
    // timer, so that was once per attempt.
    struct sockaddr_in cached_addr{};
    bool has_cached_addr{false};
};

class server_instance : public runtime_instance, public request_origin
{
public:
    server_instance(std::string_view name);
    ~server_instance() override;

    void set_mode(server_mode mode);
    server_mode get_mode() const;

    void set_udp(bool udp);
    bool is_udp() const override;

    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;

    size_t get_connection_count() const override;

    // Lua actions
    void lua_broadcast(std::string_view msg) override;
    void lua_send_to(int client_id, std::string_view msg) override;
    void        lua_disconnect(int client_fd);
    std::string lua_peer_ip(int client_fd);

    // Lua client enumeration + multicast
    std::vector<int> lua_clients() const;
    void lua_multicast(const std::vector<int>& fds, std::string_view msg);

    // Lua per-connection metadata
    void        lua_set_data(int fd, std::string_view key, std::string_view val);
    void        lua_del_data(int fd, std::string_view key);
    std::string lua_get_data(int fd, std::string_view key) const;

    // Multicast groups
    void lua_join_group(int fd, std::string_view group);
    void lua_leave_group(int fd, std::string_view group);
    void lua_group_send(std::string_view group, std::string_view msg);

    // Zero-copy pipe pairing (data forwarded directly, bypasses Lua callbacks)
    void lua_pipe(int fd_a, int fd_b);
    void lua_unpipe(int fd);

    struct ws_headers_result {
        bool is_websocket{false};
        std::string cookie, origin, protocol, auth;
    };
    ws_headers_result lua_ws_headers(int client_fd) const;

    // C++ WebSocket callback
    void set_on_websocket(std::function<void(int fd, const ws_headers_result&)> cb);

    // Stats
    std::string get_stats() const override;

    // Client routing
    bool route_client(int client_fd, std::string_view target_name);
    bool unroute_client(int client_fd);
    std::string_view get_client_route(int client_fd) const;
    void process_forwarded_message(int client_fd, std::string_view msg, std::string_view parent_name);
    void remove_forwarded_client(int client_fd);
    void send_to_client(int client_fd, std::string_view msg);

    // Owner-targeted sending (sub-server → owner's clients)
    bool owner_send(int client_fd, std::string_view msg);
    bool owner_broadcast(std::string_view msg);

    // Master mode
    void set_master_pw(std::string_view pw);
    std::string_view get_master_pw() const;
    void set_master_forward(bool fwd);
    bool get_master_forward() const;
    int get_master_fd() const;

    // HTTP static file serving
    void set_http_dir(std::string_view path);
    const std::filesystem::path& get_http_dir() const;
    void set_http_cache(bool enabled);
    bool get_http_cache() const;
    void rebuild_http_cache();

    // Upstream connections
    void add_upstream_target(std::string_view addr);
    void clear_upstream_targets();
    const std::vector<upstream_target>& get_upstream_targets() const;

    // Lua upstream actions
    void lua_upstream_send(int conn_id, std::string_view msg);
    void lua_upstream_broadcast(std::string_view msg);
    std::vector<int> lua_upstreams() const;

    // ── request_origin ──────────────────────────────────────────────────────
    // An answer from the linked cache, one turn of the event loop after the
    // command that asked for it.  The cookie names the connection that asked
    // and the identity it had at the time; a client that has gone since — or a
    // struct the pool has already handed to somebody else — fails that compare
    // and the answer is dropped rather than written into a stranger's stream.
    void on_request_reply(uint64_t cookie, request_status st,
                          std::string_view reply) override;

private:
    // Ask the linked cache something on behalf of `conn`.  `silent` is the
    // auto-store: it wants no answer and is not charged to the connection,
    // because the client never asked for it.
    void post_cache_request(server_connection* conn, std::string_view payload, bool silent);

    // How many unanswered cache requests one connection may have.  Well above
    // what a single 16 KB read can hold in `cache get k` lines, so ordinary
    // pipelining never meets it; a client that keeps going past it is closed,
    // which is the same answer this runtime already gives a client that outruns
    // its own write queue.  Refusing in place is not an option — the refusal
    // would overtake the answers already queued ahead of it, and a client that
    // cannot tell which answer belongs to which question has no protocol left.
    static constexpr uint32_t MAX_CACHE_PENDING = 4096;

    // ── the --cache auto-store ──────────────────────────────────────────────
    // Every message a linked server receives is written to the cache under an
    // incrementing key.  That used to be one m_store.set() through a pointer to
    // the cache object; it is a request now, and a request per message is the
    // wrong granularity: one 16 KB read is two thousand messages, and posting
    // two thousand entries for it fills the channel's queue faster than a turn
    // of the loop can drain it.  Measured on a 200 000 message burst, that was
    // 88% of the writes dropped.
    //
    // So the lines are accumulated here and posted together — the channel
    // carries a command stream, which is what would go over the cache's socket
    // anyway.  One entry per read instead of one per message, and the loss goes
    // away because the queue is nowhere near its cap.
    //
    // Flushed at every point where the batch could otherwise be stranded: the
    // end of a read, the end of a datagram, a stop, and immediately before any
    // command the client is waiting on — that last one so a client which sends
    // a message and then asks the cache for it by key sees its own write.
    std::string m_cache_store_batch;
    // Flush at this size rather than only at the end of a read, so a single
    // enormous read cannot build an unbounded batch.
    static constexpr size_t CACHE_STORE_BATCH_BYTES = 32 * 1024;
    void flush_cache_store();

    void handle_accept(struct io_uring_cqe* cqe);
    void handle_read(struct io_uring_cqe* cqe, io_request* req);
    void handle_write(struct io_uring_cqe* cqe, io_request* req);
    void handle_file_read(struct io_uring_cqe* cqe, io_request* req);
    void handle_splice_in(struct io_uring_cqe* cqe, server_connection* conn);
    void handle_splice_out(struct io_uring_cqe* cqe, server_connection* conn);
    void splice_cleanup(server_connection* conn);
    void invoke_on_websocket(int fd);

    // Every descriptor this runtime gives back to the kernel goes through here
    // — sockets, listeners, the files an HTTP response is served out of, the
    // splice pipes.  A close does not withdraw an SQE that already carries the
    // number; it only frees the number for the next accept to take, and the
    // queued operation then lands on that connection instead.  See
    // event_loop::close_fd, which holds the number until nothing in the ring
    // still names it.
    //
    // m_ring_loop and not m_loop, for the same reason release_fixed_slot uses
    // it: descriptors are still closed after teardown has cleared m_loop, and
    // that is exactly when the ring is most likely to be holding something.
    void close_tracked(int fd);

    // Is anything the kernel is holding still naming this struct?  Every close
    // path asks this one question now.  Each used to assemble its own list of
    // flags, and the lists disagreed: the zero-copy notification was missing
    // from two of them and the splice ops were tracked by nothing at all.
    bool conn_ops_pending(const server_connection* conn) const;
    // The single teardown for a client connection.  Only legal when
    // conn_ops_pending() is false.
    void close_conn(server_connection* conn, bool notify_disconnect = true);
    // Hand a connection struct back: to the pool when the ring is done with it,
    // to the retired list when it is not.
    void release_conn(std::unique_ptr<server_connection> conn);
    // Completions for retired connections and upstreams: recognised by the
    // address the kernel hands back, since they are no longer in any index.
    bool reap_retired(struct io_uring_cqe* cqe, io_request* req);
    // Give a provided buffer back to its group when we drop the completion that
    // carried it.  The group is shared by every server runtime on this loop, so
    // dropping one silently starves the others.
    void return_provided_buf(struct io_uring_cqe* cqe);
    void arm_udp_recv();

#ifdef SOCKETLEY_INVARIANTS
    // Debug-only: see invariants.h.  Asserts that a connection the runtime still
    // has indexed still has something that will wake it.
    void inv_check_reachable(int fd, const char* where);
#endif

    std::function<void(int, const ws_headers_result&)> m_cb_on_websocket;
    void serve_http(server_connection* conn, std::string_view path);
    void handle_http_request(server_connection* conn, const http_request& req, size_t total_consumed);

    // Upstream helpers
    bool upstream_try_connect(upstream_connection* uc);
    void upstream_schedule_reconnect(upstream_connection* uc);
    void upstream_disconnect(upstream_connection* uc);
    void handle_upstream_read(struct io_uring_cqe* cqe, upstream_connection* uc);
    void handle_upstream_write(struct io_uring_cqe* cqe, upstream_connection* uc);
    void upstream_send(upstream_connection* uc, const std::shared_ptr<const std::string>& msg);
    void upstream_flush_write_queue(upstream_connection* uc);
    void invoke_on_upstream(int conn_id, std::string_view data);
    void invoke_on_upstream_connect(int conn_id);
    void invoke_on_upstream_disconnect(int conn_id);

    void process_message(server_connection* sender, std::string_view msg);
    void broadcast(const std::shared_ptr<const std::string>& msg, int exclude_fd);
    void remove_active_fd(int fd);
    // `even_when_closing` is for an answer that was already promised.  A
    // connection normally stops accepting output the moment it is marked
    // closing — the conversation is over and anything produced after that is
    // computed and thrown away — but a cache reply was asked for before the
    // client half-closed, and its socket is still open precisely because that
    // answer is owed.  Nothing else may set it.
    void send_to(server_connection* conn, const std::shared_ptr<const std::string>& msg,
                 bool even_when_closing = false);
    void flush_write_queue(server_connection* conn);

    // ── TLS record layer ────────────────────────────────────────────────────
    // OpenSSL does no I/O here.  These two move bytes between a connection's
    // memory BIO pair and the buffers io_uring reads into and writes out of,
    // so the handshake happens one completion at a time and nothing blocks the
    // event loop.  Everything above them — protocol detection, WebSocket,
    // HTTP, RESP, Lua — sees the same plaintext it always did.

    // Ciphertext a read completion delivered, in.  Drives the handshake while
    // one is running and appends whatever plaintext comes out to conn->partial.
    // Marks the connection closing on anything terminal (a failed handshake, a
    // buffer cap exceeded, a broken record); a peer's orderly close_notify
    // lands in tls_peer_closed instead, so the request it arrived with is
    // still answered.  There is no path from here back to plaintext.
    void tls_feed(server_connection* conn, const char* data, size_t len);

    // Plaintext queue → SSL → one write submission of ciphertext, and the only
    // thing that puts handshake records or alerts on the wire.  Submits at most
    // one write, exactly as the cleartext path does; the rest waits for that
    // completion.
    void tls_flush(server_connection* conn);

    // Has this connection bytes to send that the ring has not been given?  For
    // a TLS connection the write queue is only half the answer — a handshake
    // record or a session ticket sits in the write BIO with the queue empty.
    bool conn_has_output(const server_connection* conn) const;

    // The listener's TLS context, or null when this server serves cleartext.
    // Rebuilt by setup() on every start so that `reload` is how a renewed
    // certificate is installed; sessions already handed out hold their own
    // reference to the old SSL_CTX and are unaffected.
    std::unique_ptr<tls_context> m_tls;
    void submit_conn_read(server_connection* conn);
    void release_fixed_slot(server_connection* conn);

    // UDP helpers
    void handle_udp_read(struct io_uring_cqe* cqe);
    void udp_broadcast(std::string_view msg, const struct sockaddr_in* exclude);
    int find_or_add_peer(const struct sockaddr_in& addr);

    server_mode m_mode;
    bool m_udp{false};
    uint32_t m_idle_timeout_cached{0};  // cached at setup() to avoid virtual call per CQE
    uint32_t m_max_conns_cached{0};
    double m_rate_limit_cached{0.0};

    // Master mode
    int m_master_fd{-1};
    bool m_master_forward{false};
    std::string m_master_pw;
    int m_listen_fd;
    struct sockaddr_in m_accept_addr;
    socklen_t m_accept_addrlen;
    // The request the current accept chain was armed with, and the ones earlier
    // chains were armed with that the ring has not finished naming.
    //
    // One per chain rather than one per instance, because a stop does not end
    // the chain it belongs to: teardown() closes the listener and close_fd()
    // submits a cancel, both of which make the accept report, but reporting only
    // puts a CQE in the ring — and nothing reaps the ring between a stop and the
    // start that follows it.  See setup() for what arming a second submission on
    // an occupied request costs.
    //
    // A spent request is not freed when it is replaced.  Its completion is
    // dropped rather than dispatched — stop() deregistered the owner — but the
    // loop reads the request in order to drop it, so the storage has to outlive
    // the ring's interest in it.  setup() releases them once owner_inflight()
    // says nothing is left.
    std::unique_ptr<io_request> m_accept_req;
    std::vector<std::unique_ptr<io_request>> m_accept_spent;
    event_loop* m_loop;
    // The same loop, kept across teardown.  A completion that arrives while we
    // are stopped may carry a provided buffer or a fixed-file slot that has to
    // go back, and m_loop is null exactly then.  Never used to submit.
    event_loop* m_ring_loop{nullptr};

    // EMFILE/ENFILE accept backoff
    io_request m_accept_backoff_req{};
    struct __kernel_timespec m_accept_backoff_ts{};

    // Idle connection sweep timer
    io_request m_idle_sweep_req{};
    struct __kernel_timespec m_idle_sweep_ts{};

    // An armed request stays armed across a stop: a timeout is attached to no
    // fd, so neither shutdown() nor a cancel reaches it, and it completes when
    // it completes.  Arming a second one at the next start() is what gave a
    // restarted server two sweep chains, then three.  These say "occupied";
    // nothing re-arms an occupied request, and the completion is what frees it.
    bool m_accept_armed{false};
    bool m_accept_backoff_armed{false};
    bool m_idle_sweep_armed{false};
    bool m_udp_recv_armed{false};

    std::unordered_map<int, std::unique_ptr<server_connection>> m_clients;
    // O(1) fd→conn lookup for CQE dispatch (non-owning, m_clients owns)
    static constexpr int MAX_FDS = 8192;
    server_connection* m_conn_idx[MAX_FDS]{};

    // Active fd tracking for O(1) broadcast iteration (no map overhead)
    std::vector<int> m_active_fds;

    bool m_multishot_active{false};

    uint64_t m_message_counter = 0;

    // Client routing: fd → target runtime name
    std::unordered_map<int, std::string> m_routes;
    // Forwarded clients: fd → source (parent) runtime name
    std::unordered_map<int, std::string> m_forwarded_clients;

    // Stats
    uint32_t m_stat_peak_connections{0};

    // Connection pool: pre-allocated connections for reuse (avoids malloc per accept)
    static constexpr size_t CONN_POOL_INIT = 64;
    std::vector<std::unique_ptr<server_connection>> m_conn_pool;

    // Connections and upstreams the kernel has not finished with.  They are not
    // freed and not reused; they sit here until their completions arrive, and
    // each completion that lands is what tells us one more of them is free.
    // Freeing them at the next start() instead — which is what this code used to
    // do — is how a completion came to be read out of memory that had already
    // been handed to somebody else.
    std::vector<std::unique_ptr<server_connection>> m_conn_retired;
    std::vector<std::unique_ptr<upstream_connection>> m_upstream_retired;

    // Acquire a connection from the pool (or allocate if empty)
    std::unique_ptr<server_connection> pool_acquire(int fd);
    // Return a connection to the pool for reuse
    void pool_release(std::unique_ptr<server_connection> conn);

    // Provided buffer ring
    static constexpr uint16_t BUF_GROUP_ID = 1;
    static constexpr uint32_t BUF_COUNT = 1024;
    static constexpr uint32_t BUF_SIZE = 16384;
    bool m_use_provided_bufs{false};
    bool m_recv_multishot{false};
    bool m_send_zc{false};
    bool m_direct_accept{false};

    // UDP mode
    static constexpr size_t MAX_UDP_PEERS = 10000;
    struct udp_peer { struct sockaddr_in addr; };
    int m_udp_fd{-1};
    // Everything one recvmsg names: the request, the msghdr the kernel walks,
    // the buffer it writes the datagram into and the sockaddr it writes the
    // sender into.  Held apart from the instance and replaced per run, for the
    // reason given for the accept request above: a stop deregisters this owner,
    // so the completion that would lower m_udp_recv_armed is dropped rather
    // than dispatched, and a start that follows before the ring is reaped would
    // otherwise either arm a second recvmsg into the same buffer or — with the
    // flag still standing — arm nothing at all and never receive again.
    struct udp_recv_state
    {
        io_request         req{};
        struct msghdr      msg{};
        struct iovec       iov{};
        struct sockaddr_in addr{};
        char               buf[65536];
    };
    std::unique_ptr<udp_recv_state> m_udp_recv;
    std::vector<std::unique_ptr<udp_recv_state>> m_udp_recv_spent;
    std::vector<udp_peer> m_udp_peers;
    std::unordered_map<uint64_t, int> m_udp_peer_idx;  // packed IP+port → index in m_udp_peers

    // Per-IP auth failure tracking
    struct auth_ip_record {
        uint32_t failures{0};
        std::chrono::steady_clock::time_point last_failure{};
    };
    std::unordered_map<uint32_t, auth_ip_record> m_auth_ip_failures;

    // HTTP static file serving
    std::filesystem::path m_http_dir;
    std::filesystem::path m_http_base;  // canonical resolved path (set at setup/rebuild time)
    bool m_http_cache_enabled{false};
    struct cached_file { std::shared_ptr<const std::string> response; };
    std::unordered_map<std::string, cached_file> m_http_cache;

    // Splice pipe for zero-copy file serving (shared across connections, one at a time)
    int m_splice_pipe[2]{-1, -1};
    bool m_splice_busy{false};

    // Multicast groups: group_name → list of fds in that group
    std::unordered_map<std::string, std::vector<int>> m_groups;
    void remove_from_all_groups(int fd);

    // Upstream connections
    std::vector<upstream_target> m_upstream_targets;
    std::unordered_map<int, std::unique_ptr<upstream_connection>> m_upstreams;     // conn_id → upstream
    std::unordered_map<int, upstream_connection*> m_upstream_by_fd;                // fd → upstream (CQE dispatch)
    int m_next_upstream_id{1};
};
