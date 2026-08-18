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

#include "../../shared/conn_identity.h"
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
    // The half of this connection's conn_ref that varies.  `generation` above
    // is the *loop's* stamp — 32 bits, process-wide, and it wraps, all of which
    // is fine for deciding whether a completion still belongs to its submitter
    // and none of which is fine for a name another process holds.  This one is
    // 64 bits, per runtime, and never repeats.  See conn_identity.h.
    uint64_t ref_serial{0};
    bool direct_fd{false};   // true if fd came from direct-accept (fixed file index)
    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};
    bool zc_notif_pending{false};
    proto_state proto{proto_unknown};
    bool routed{false};
    bool file_read_pending{false};
    bool http_keep_alive{false};
    bool wr_shutdown{false};   // our FIN is already on the wire (shutdown SHUT_WR)
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

    // Relay traffic that arrived before this connection said what it speaks.
    //
    // A connection joins the relay set the moment it is accepted, but nothing
    // is known about its protocol until its first read has been classified —
    // and a client whose opening move is an HTTP request or a WebSocket
    // upgrade is waiting for the response to it.  Writing relay bytes in the
    // meantime does not merely deliver them early, it puts them *in front of*
    // that response: the client reads "hello tcp 7" where the "HTTP/1.1 101"
    // it is parsing for should be, and the handshake is corrupted.
    //
    // So they are held here and released by relay_hold_flush() once the
    // protocol is settled — behind whatever the classifying read queued, and
    // through the framing that protocol uses.  Held rather than dropped
    // because the client is entitled to them: an inout server relays every
    // client's messages to every other client, and this connection goes on
    // receiving exactly this traffic for the rest of its life.
    //
    // Or by the deadline, for a connection that has said nothing at all.  See
    // RELAY_HOLD_DEADLINE_MS and `spoke` below for why those two are the same
    // release and not two policies.
    socketley::byte_counted_queue<std::shared_ptr<const std::string>> relay_hold;

    // When this hold started — set as it goes from empty to non-empty, and
    // meaningless while it is empty.  The deadline is measured from the first
    // message held rather than from the accept, because until there is traffic
    // to hold there is nothing for a deadline to be late for.
    std::chrono::steady_clock::time_point relay_hold_since{};

    // Has this client ever sent a byte of application data?
    //
    // Sticky, and it is the whole of what separates a listener from a client
    // mid-request.  Both are unclassified, and the relay owes them opposite
    // things: a connection that has sent something is waiting for an answer to
    // it, so relay bytes released early land in front of that answer and this
    // is the defect all over again; a connection that has sent nothing has no
    // answer outstanding for anything to land in front of, so releasing its
    // hold cannot reorder anything.  Only the second kind has a deadline.
    //
    // Set where inbound bytes reach `partial`, so a TLS connection counts as
    // having spoken when its plaintext arrives and not when its handshake
    // records do — a client is not "waiting for an answer" to a ClientHello
    // that OpenSSL answers by itself.
    bool spoke{false};

    // Has this connection ever been an HTTP request/response connection?
    //
    // Sticky, because `proto` is not: it is reset to proto_unknown after every
    // keep-alive response so the classifier can run again on the next request,
    // and a connection that forgot it was HTTP would rejoin the relay set in
    // every gap between two requests.  Set where proto_http is decided, and
    // deliberately NOT set for a WebSocket, which arrives over the same HTTP
    // and is a relay target for the rest of its life.
    //
    // What it excludes is exactly the relay — the unsolicited traffic this
    // connection never asked for.  Its own responses, and anything a script
    // addresses to it by client_id, are unaffected.
    bool http_seen{false};

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
        // Cleared, not carried.  pool_acquire() mints a fresh one straight
        // after; leaving the previous connection's serial in a struct being
        // handed to a new client is the whole defect one level up.
        ref_serial = 0;
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
        // The previous occupant's unclassified relay traffic must not be
        // handed to this one.  pool_release() already did it; repeated here for
        // the same reason the TLS session above is.
        relay_hold.clear();
        relay_hold_since = {};
        // A struct that carried a client which had spoken would otherwise hand
        // the next one a permanent exemption from the deadline: it would be a
        // listener the relay believed was mid-request, and it would be held for
        // as long as it stayed connected — which is the behaviour the deadline
        // exists to end, reintroduced through the pool.
        spoke = false;
        // And a struct that carried an HTTP client would hand the next one a
        // permanent exclusion from the relay — the more visible half of the same
        // mistake: a client that never spoke HTTP, silently receiving nothing
        // for as long as it stayed connected.
        http_seen = false;
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

    // See runtime_instance::as_server().  The whole of the override: this class
    // is what the question is asking for, and a class that is not says nothing.
    server_instance* as_server() override { return this; }

    void set_mode(server_mode mode);
    server_mode get_mode() const;

    void set_udp(bool udp);
    bool is_udp() const override;

    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;

private:
    // The two listeners setup() chooses between.  Each opens m_listen_fd, binds
    // it and puts it in the listen state, or leaves it -1 and returns false.
    // Everything after that point in setup() — the buffer ring, the accept
    // chain, the connection tables — is the same for both, which is the whole
    // reason they are two functions and not two copies of setup().
    bool setup_tcp_listener(uint16_t port);
    bool setup_unix_listener(const std::string& path);

public:

    size_t get_connection_count() const override;

    // Lua actions
    void lua_broadcast(std::string_view msg) override;
    bool lua_send_to(int client_id, std::string_view msg) override;
    bool        lua_disconnect(int client_fd);
    std::string lua_peer_ip(int client_fd);

    // Lua client enumeration + multicast
    std::vector<int> lua_clients() const;
    size_t lua_multicast(const std::vector<int>& fds, std::string_view msg);

    // Lua per-connection metadata
    bool        lua_set_data(int fd, std::string_view key, std::string_view val);
    bool        lua_del_data(int fd, std::string_view key);
    std::string lua_get_data(int fd, std::string_view key) const;

    // Multicast groups
    bool lua_join_group(int fd, std::string_view group);
    bool lua_leave_group(int fd, std::string_view group);
    size_t lua_group_send(std::string_view group, std::string_view msg);

    // Zero-copy pipe pairing (data forwarded directly, bypasses Lua callbacks)
    bool lua_pipe(int fd_a, int fd_b);
    bool lua_unpipe(int fd);

    struct ws_headers_result {
        bool is_websocket{false};
        std::string cookie, origin, protocol, auth;
    };
    ws_headers_result lua_ws_headers(int client_fd) const;

    // C++ WebSocket callback
    void set_on_websocket(std::function<void(int fd, const ws_headers_result&)> cb);

    // Stats
    std::string get_stats() const override;

    // ── Client routing ──────────────────────────────────────────────────────
    //
    // The Lua-facing half.  `client_id` is whatever Lua was handed for this
    // connection: a descriptor for one of this runtime's own clients, or a
    // handle out of conn_identity.h's reserved range for one that was routed
    // here from elsewhere.  Nothing above this line ever sees a conn_ref, and
    // nothing below it ever sees a descriptor belonging to another process.
    bool route_client(int client_id, std::string_view target_name);
    bool unroute_client(int client_id);
    std::string_view get_client_route(int client_id) const;
    bool send_to_client(int client_id, std::string_view msg);

    // Owner-targeted sending (sub-server → the connection that was routed here)
    //
    // owner_send used to take a descriptor number from a sub-server's Lua and
    // write it straight into the owner's connection table, with no check that
    // the number still named the connection the sub-server was talking about.
    // It resolves a handle now, and a handle whose connection has gone resolves
    // to nothing.
    bool owner_send(int client_id, std::string_view msg);
    bool owner_broadcast(std::string_view msg);

    // ── The cross-runtime interface ─────────────────────────────────────────
    //
    // Everything one runtime does to another's connection goes through these
    // four, and every one of them takes a conn_ref.  That is the property the
    // process split needs: none of them can be called with a number that only
    // means something in the caller's address space, so the in-process form and
    // the form that arrives over a socket are the same call with the same
    // arguments.
    //
    // Called on the *receiving* runtime.  Mints a local handle for a connection
    // that lives in `origin_name` and tells this runtime's script about it.
    // Returns the handle, or -1 if the ref is not usable.
    int accept_routed(const conn_ref& ref, std::string_view origin_name);

    // Called on the receiving runtime: the connection is gone.
    void release_routed(const conn_ref& ref);

    // Called on the *owning* runtime by a receiver that is shutting down: stop
    // routing this connection, it has nowhere to go.  The connection itself is
    // untouched and goes back to being served here.
    void drop_route(const conn_ref& ref);

    // Called on the receiving runtime: bytes arrived from it.
    void deliver_routed(const conn_ref& ref, std::string_view msg);

    // Called on the *owning* runtime: write to one of my connections, named the
    // way a stranger is allowed to name it.  False when the ref names nothing
    // here any more, which is the case that used to write into whichever
    // connection had inherited the descriptor number.
    bool write_to_ref(const conn_ref& ref, std::string_view msg);

    // The name of one of this runtime's own connections, for a caller that is
    // about to hand it to another runtime.  Invalid for a descriptor this
    // runtime does not hold.
    conn_ref ref_for_fd(int fd) const;

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
    // False when the address named a port that cannot work; nothing is stored
    // in that case.  See the definition for which spellings are refused and
    // why a bare host is not one of them.
    [[nodiscard]] bool add_upstream_target(std::string_view addr);
    void clear_upstream_targets();
    const std::vector<upstream_target>& get_upstream_targets() const;

    // Lua upstream actions
    bool lua_upstream_send(int conn_id, std::string_view msg);
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

    // ── Relay traffic held across classification ────────────────────────────
    // What one connection may accumulate while it is still unclassified,
    // before the oldest held message is dropped to make room.
    //
    // This is not a transient.  A client that has sent half a request and
    // paused holds until the rest of it arrives, which is its own decision and
    // may be a long one, and a server with many such connections pays this per
    // connection.  The figure is sized for the window it exists to cover —
    // accept to the read that classifies, normally a single turn of the event
    // loop — and deliberately not for a backlog: 64 KB is four full 16 KB
    // reads' worth of relayed lines, far more than that window can produce, and
    // 1/128th of the 8 MB a connection's own write queue may hold, so a
    // connection waiting to be classified cannot cost more than an active
    // client already may.
    //
    // Overflow drops the oldest.  The three alternatives are all worse:
    // growing is the memory-exhaustion path this bound exists to close;
    // disconnecting punishes a client that has done nothing but stay quiet;
    // and blocking would let one silent listener stall every client that is
    // talking, which is a far worse failure than a listener missing the start
    // of a conversation it has not joined yet.
    static constexpr size_t RELAY_HOLD_MAX_BYTES = 64 * 1024;

    // How long relay traffic is held for a connection that has said nothing.
    //
    // Holding until classification and only until classification has one
    // consequence that is worse than the defect it fixes: a connection that
    // never sends is never classified, so a pure listener — connect, stay
    // quiet, read what everybody else broadcasts — would receive no relay
    // traffic at all, ever.  That is a legitimate client of an inout server,
    // whose whole job is to relay every client's messages to every other
    // client, and it worked before the hold existed.  So the hold has a
    // deadline, and on it the connection is treated as raw and flushed through
    // the ordinary path.
    //
    // Only for a connection that has not spoken.  See `spoke`: a client
    // mid-request is waiting for an answer, and releasing its hold on a timer
    // would put relay bytes in front of that answer — the original defect,
    // moved from fast clients to slow ones.  Such a connection holds until it
    // is classified however long that takes, exactly as before.
    //
    // 250 ms, bounded from both sides:
    //
    //   * It must not expire before a client that intends to speak has been
    //     heard, because a listener is what this classifies it as, permanently.
    //     The gap it has to clear is connect-to-first-byte for a client that
    //     writes its request immediately — under a millisecond on loopback or a
    //     LAN, and 250 ms still covers a full round trip on an intercontinental
    //     link.  The clock also starts at the first held message rather than at
    //     the accept, so an idle server never runs it at all: a slow client is
    //     only ever at risk while other clients are actively broadcasting.
    //
    //   * It must not be long enough to read as a stall.  A listener's added
    //     latency is 250 ms once, on its first relayed message; every message
    //     after that goes straight out, because the deadline classifies the
    //     connection rather than merely emptying its queue.  That is under the
    //     ~300 ms at which a delay becomes visible in interactive traffic, and
    //     two orders of magnitude below the 30 s idle sweep, which is the only
    //     other timer that would otherwise have touched such a connection.
    static constexpr uint32_t RELAY_HOLD_DEADLINE_MS = 250;

    // Is this connection still waiting to be classified?  Both states mean the
    // same thing to the relay — nothing has been decided about what the client
    // speaks, so nothing unsolicited may be written to it.  proto_ws_upgrading
    // counts because it is the middle of a handshake and not the end of one:
    // headers can span several reads, and the 101 has not been queued yet.
    static bool proto_unsettled(const server_connection* conn)
    {
        return conn->proto == proto_unknown || conn->proto == proto_ws_upgrading;
    }

    // May the relay write to this connection at all?
    //
    // The question the ordering defects on this connection kept being asked one
    // window at a time, answered once instead.  An HTTP connection is never a
    // relay target, at any point in its life:
    //
    //   * While a request is in flight — which it is from the four bytes that
    //     settle the protocol until the last byte of the body — a relayed line
    //     goes into the write queue ahead of the response, and the client, which
    //     is parsing for a status line, reads that line instead.
    //
    //   * Between two keep-alive requests the client is not reading.  When it
    //     next does, having sent another request, it parses whatever was left on
    //     the connection as that response's status line.  The corruption is not
    //     avoided by waiting, only deferred.
    //
    //   * HTTP frames bodies by Content-Length and responses by their order
    //     against requests.  A server-initiated line has no place in either.
    //     There is no delay, no hold and no ordering that makes one well formed.
    //
    // So this is a membership question rather than a timing one, and it is
    // stated here rather than left implicit in a guard at one call site.  A
    // WebSocket is not covered: it arrives over the same HTTP, and once upgraded
    // it has framing for server-initiated messages, which is the whole point of
    // it and the supported way for a browser to receive relay traffic.
    //
    // RESP is the same protocol shape and therefore the same answer.  A RESP
    // client sends a command and reads the next value on the stream as its
    // reply — RESP2 correlates replies to commands by their order and by
    // nothing else, exactly as HTTP does — so an unsolicited value is consumed
    // as the answer to whatever that client asked next.  Two further reasons it
    // cannot be made well formed by delaying it:
    //
    //   * What broadcast() writes is not a RESP value at all.  It is the
    //     message text with a newline, so the client reads a plain letter where
    //     a type byte belongs; a real RESP client answers that with a protocol
    //     error and drops the connection.
    //
    //   * Encoding it as one would not rescue it.  The only channel RESP2 has
    //     for a server-initiated value is pub/sub, which the client must enter
    //     with SUBSCRIBE and which this runtime does not implement — the RESP
    //     branch of handle_read joins argv with spaces and hands the result to
    //     process_message like any other line.
    //
    // No sticky companion to http_seen is needed for it.  http_seen exists
    // because `proto` does not survive a keep-alive gap; every one of those
    // resets is on an HTTP response path, and proto_resp is never reset — a
    // connection that speaks RESP speaks it until it closes.  If that ever
    // stops being true, this needs a resp_seen for the same reason HTTP needed
    // http_seen.
    static bool relay_targetable(const server_connection* conn)
    {
        return !conn->http_seen && conn->proto != proto_resp;
    }

    // May the deadline release this connection's hold?
    //
    // Three conditions, and each one is a different way of asking whether
    // anything is owed to this client that relay bytes could arrive in front
    // of.  It must still be unclassified (a classified one has no hold left to
    // release); it must never have spoken (see `spoke`); and its TLS handshake,
    // if it has one, must be finished — a session still exchanging records has
    // no keys to encrypt with, so flushing into it would queue plaintext behind
    // a handshake and then deliver it in front of the first real response.
    static bool relay_deadline_applies(const server_connection* conn)
    {
        return proto_unsettled(conn) && !conn->spoke
               && conn->tls_state != tls_conn_handshake;
    }

    // Hold one relayed message for a connection that has no protocol yet.
    void relay_hold_push(server_connection* conn,
                         const std::shared_ptr<const std::string>& msg);

    // Release what was held, once the protocol is known.  Called from the one
    // point every path through handle_read reaches, so a connection cannot be
    // classified without its held traffic going out behind the response to the
    // very read that classified it.
    void relay_hold_flush(server_connection* conn);

    // Arm the deadline timer if it is not already counting.  One timer for the
    // whole instance rather than one per connection: a per-connection timeout
    // would need an io_request, an armed flag and a withdrawal on every close
    // path, for a deadline that is the same length for every connection and is
    // only ever waited on by connections that are doing nothing.
    void relay_deadline_arm(uint32_t after_ms);

    // Everything whose deadline has passed, and re-arm for the oldest that is
    // left.  Arming for the full deadline each time would make the worst-case
    // wait twice the constant, for a connection whose hold began just after the
    // previous arming; re-arming for the remainder is what keeps the bound the
    // number that is written down.
    void relay_deadline_sweep();

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

    // Sends our FIN once the response is fully on the wire.  See the definition
    // for why it is shutdown() and not close(), and why only completions call it.
    void maybe_shutdown_write(server_connection* conn);

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
    // The socket node this run's listener is actually bound to, when it is an
    // AF_UNIX one.  Deliberately not get_listen_path(): teardown() has to
    // remove the node THIS bind created, and a runtime edited between its start
    // and its stop would otherwise unlink a path it never bound.  Empty for a
    // TCP listener, which is what says there is nothing to unlink.
    std::string m_bound_listen_path;
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

    // Relay-hold deadline timer.  Armed on demand — by the first message held
    // for a connection that qualifies — and re-armed by its own completion for
    // as long as anything is still waiting, so a server with no listeners never
    // puts it in the ring at all.
    io_request m_relay_deadline_req{};
    struct __kernel_timespec m_relay_deadline_ts{};

    // An armed request stays armed across a stop: a timeout is attached to no
    // fd, so neither shutdown() nor a cancel reaches it, and it completes when
    // it completes.  Arming a second one at the next start() is what gave a
    // restarted server two sweep chains, then three.  These say "occupied";
    // nothing re-arms an occupied request, and the completion is what frees it.
    bool m_accept_armed{false};
    bool m_accept_backoff_armed{false};
    bool m_idle_sweep_armed{false};
    bool m_relay_deadline_armed{false};
    bool m_udp_recv_armed{false};

    std::unordered_map<int, std::unique_ptr<server_connection>> m_clients;
    // O(1) fd→conn lookup for CQE dispatch (non-owning, m_clients owns)
    static constexpr int MAX_FDS = 8192;
    server_connection* m_conn_idx[MAX_FDS]{};

    // Active fd tracking for O(1) broadcast iteration (no map overhead)
    std::vector<int> m_active_fds;

    bool m_multishot_active{false};

    uint64_t m_message_counter = 0;

    // ── Cross-runtime routing ───────────────────────────────────────────────
    //
    // Both of these used to be keyed by a file descriptor number, and the
    // sub-server's copy was keyed by the *parent's* descriptor number — a value
    // that means nothing in the sub-server's own address space and less than
    // nothing once the two are in different processes.  See conn_identity.h for
    // the three properties of a descriptor that made that unworkable.
    //
    // What this runtime owns and has routed away: our own connection's serial →
    // the runtime it went to.  Keyed by serial rather than fd so that a
    // descriptor reissued to a new client is not silently still routed.
    std::unordered_map<uint64_t, std::string> m_routes;

    // Our serials back to the descriptor that currently carries them.  This is
    // the only place a conn_ref becomes an fd again, it is private to the
    // runtime that minted the ref, and the entry is removed the moment the
    // connection closes — which is what makes a stale ref resolve to nothing
    // instead of to whoever inherited the number.
    std::unordered_map<uint64_t, int> m_conn_by_serial;

    // What another runtime has routed *to* us.  The connection lives elsewhere;
    // all we hold is its name and a local handle to show Lua.
    struct forwarded_client
    {
        conn_ref    ref;
        std::string origin;      // runtime name that owns the connection
    };
    std::unordered_map<int, forwarded_client> m_forwarded;
    std::unordered_map<conn_ref, int, conn_ref_hash> m_forwarded_by_ref;
    int m_next_handle{conn_handle_base};
    int alloc_handle();

    // Mints the serial half of this runtime's conn_refs.  Per instance, seeded
    // from the monotonic clock, never restarting at a value a peer could still
    // be holding from a previous lifetime.
    conn_serial_source m_serials;

    // conn_owner_key(get_id()), computed once.  get_id() is set after
    // construction, so this is filled lazily on first use rather than in the
    // constructor — a ref minted before the daemon has assigned an id would
    // carry owner 0 and be invalid by construction.
    mutable uint64_t m_owner_key{0};
    uint64_t owner_key() const;

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

    // A directory descriptor on m_http_base, so a request can be opened
    // relative to it with openat2(RESOLVE_BENEATH) instead of canonicalising
    // the path first.  See serve_http's disk mode for what that replaces and
    // what it costs.  -1 when there is no --http dir or the open failed, in
    // which case the old path is taken.
    int m_http_root_fd{-1};
    void open_http_root();
    bool m_http_cache_enabled{false};
    // Both variants are prebuilt.  A cache hit has to stay a refcount bump —
    // that is the whole point of this map — and the response's own Connection
    // header has to match what the client asked for, so the choice cannot be
    // made by rewriting the string at serve time.
    struct cached_file
    {
        std::shared_ptr<const std::string> response;        // Connection: keep-alive
        std::shared_ptr<const std::string> response_close;  // Connection: close
    };
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
