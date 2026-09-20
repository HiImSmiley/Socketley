#pragma once
#include <atomic>
#include <memory>
#include <string>
#include <string_view>
#include <queue>
#include <vector>
#include <netinet/in.h>
#include <linux/time_types.h>

#include "../../shared/runtime_instance.h"
#include "../../shared/write_queue.h"
#include "../../shared/event_loop_definitions.h"
#include "../../shared/tls_context.h"

// Everything the ring can name for one run, with a lifetime of its own because
// a stop deregisters the owner and the flags saying a request is occupied are
// never lowered while the kernel is still using the buffers.
struct client_tcp_connection
{
    int fd{-1};
    io_request read_req;
    io_request write_req;
    char read_buf[4096];
    std::string write_buf;
    // How much of write_buf the kernel has already taken, because resuming
    // from the right offset is what keeps the next message from being appended
    // to half of this one.
    size_t write_off{0};
    std::string partial;

    static constexpr size_t MAX_PARTIAL_SIZE = 1 * 1024 * 1024;

    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};

    // The reconnect timer, here because it is storage the ring can name that
    // outlives the stop which armed it and hangs off no descriptor a teardown
    // could close.
    io_request timeout_req{};
    struct __kernel_timespec timeout_ts{};

    // The handshake deadline's own clock, beside the reconnect one and never
    // sharing it: this one fires while m_connected is true, which is exactly
    // the state the reconnect clock's guard treats as "stale, do nothing".
    io_request hs_req{};
    struct __kernel_timespec hs_ts{};
    bool hs_armed{false};

    // Non-null only with --tls, on a memory BIO pair so every byte on the wire
    // is still moved by io_uring -- and nothing the ring can name lives inside
    // the SSL, which is what makes it safe to free with a write in flight.
    SSL* ssl{nullptr};
    tls_conn_state tls_state{tls_conn_none};
    // The peer sent close_notify, recorded rather than acted on so plaintext
    // that arrived ahead of it in the same read is still delivered.
    bool tls_peer_closed{false};

    ~client_tcp_connection() { tls_context::free_ssl(ssl); }
    client_tcp_connection() = default;
    client_tcp_connection(const client_tcp_connection&) = delete;
    client_tcp_connection& operator=(const client_tcp_connection&) = delete;
};

enum client_mode : uint8_t
{
    client_mode_inout = 0,
    client_mode_in    = 1,
    client_mode_out   = 2
};

class client_instance : public runtime_instance
{
public:
    client_instance(std::string_view name);
    ~client_instance() override;

    void set_mode(client_mode mode);
    client_mode get_mode() const;

    void set_udp(bool udp);
    bool is_udp() const override;

    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;

    size_t get_connection_count() const override;

    // One line, dial_attempts, which is what total_connections stopped being
    // when it started counting connections.
    std::string stats_lines() const override;

    // Lua actions
    bool lua_send(std::string_view msg) override;

    // The two questions a producer needs, as on the server -- without an id,
    // because a client has one connection and naming it would be a fiction.
    long pending_bytes() const;
    // Whether the last refusal was the queue and not the connection.  Guarded
    // on being connected, so a latch left up by a stall is not blamed for a
    // disconnection that happened underneath it.
    bool write_backlogged() const;

    // The drain crossing is already detected twice in the write paths; this is
    // where the script is told about it, off those stacks.
    void on_loop_turn() override;

private:
    void handle_read(struct io_uring_cqe* cqe);
    void handle_write(struct io_uring_cqe* cqe);
    // Takes the request as well as the completion, because two clocks share
    // op_timeout and state cannot tell them apart.
    void handle_timeout(struct io_uring_cqe* cqe, io_request* req);
    // A dial that connected is not a connection: the TCP half succeeded and
    // the peer may never finish the handshake, in which case nothing is ever
    // lost and --reconnect is never reached.
    void arm_handshake_deadline();

    void process_message(std::string_view msg);
    // Returns whether the reconnect clock is actually armed, since a caller
    // that ignores it claims a client will dial again when nothing will make
    // it.
    [[nodiscard]] bool schedule_reconnect();

    bool try_connect();
    // The one place a read is armed, and only when one is not already armed.
    void arm_read();
    // The one place a write is armed, recording the descriptor so a completion
    // for a socket since lost is spotted.
    void arm_write(const char* data, uint32_t len);
    // Take the next queued message once the write request comes free.
    void flush_queued_write();
    // Lose the socket and start the reconnect clock, in one place, because
    // every path that gets here used to do the same five things in its own
    // copy.
    void drop_connection();
    // The other half of that clock: reset the backoff and the attempt count,
    // from the first completion that carries bytes and not from a connect()
    // that answered EINPROGRESS.
    void note_established();
    // Count this socket in total_connections, once, and only once the kernel
    // has a peer to name for it -- a dial is an intention and the server
    // counts at an accept() that really happened.
    void note_connected();
    // Every descriptor this runtime gives back goes through here, because it
    // reuses one read and one write request across reconnects and the number
    // really does come straight back.
    void close_tracked(int fd);
    // Account for a completion that is not ours to act on any more.
    void settle_stale(struct io_uring_cqe* cqe, io_request* req);
    // Hand a provided buffer back when a completion carrying it is dropped,
    // because every client runtime on this loop shares the group.
    void return_provided_buf(struct io_uring_cqe* cqe);

    // ── TLS record layer ────────────────────────────────────────────────────
    // OpenSSL does no I/O in either of these: tls_feed hands the record layer
    // what a read delivered and tls_flush puts what the session owes on the
    // wire as one ordinary write, deliberately identical in shape to the
    // server's and the proxy's.
    void tls_feed(const char* data, size_t len);
    void tls_flush();
    // Give this connection a session and put the ClientHello on the wire,
    // where false means the caller must give the socket up rather than carry
    // on in cleartext.
    bool start_tls();
    // Release the session wherever the socket is lost, so a reconnect starts a
    // fresh handshake rather than resuming one the peer never saw the first
    // half of.
    void tls_release();

    client_mode m_mode;
    bool m_udp{false};
    // The current run's I/O state and the ones earlier runs left behind, kept
    // because the loop reads the request inside a spent struct to drop its
    // completion and setup() releases them once owner_inflight() says nothing
    // is left.
    std::unique_ptr<client_tcp_connection> m_conn;
    std::vector<std::unique_ptr<client_tcp_connection>> m_conn_spent;
    // Which socket the requests in flight belong to, because both requests are
    // reused and a closed descriptor number comes straight back from the
    // kernel on the next connect.
    uint32_t m_conn_generation{0};
    event_loop* m_loop;
    // The same loop kept across teardown, so buffers carried by late
    // completions go back, and never used to submit -- m_loop being null is
    // what says submitting is not allowed.
    event_loop* m_ring_loop{nullptr};
    bool m_connected;

    // Write queue (prevents silent message loss when write_pending)
    // How large a coalesced entry may grow, the same 64 KB the other runtimes
    // use.  This runtime has no writev batching at all -- flush() takes one
    // entry and arms one write for it -- so coalescing is what stands in for
    // it: a client that is behind sends its backlog in one write instead of
    // one per message.
    static constexpr size_t WRITE_COALESCE_LIMIT = 64 * 1024;

    socketley::byte_counted_queue<std::string> m_write_queue;
    // Latches the "not draining" report, because one line per dropped message
    // would bury the first, which is the only one that says anything new.
    bool m_write_queue_full{false};
    // Armed at the soft watermark by lua_send, cleared by the crossing back
    // down, which is the moment on_writable is owed.  Separate from the latch
    // above: that one is raised only at the hard cap, and a producer told to
    // pace has to hear about the crossing it actually stopped at.
    bool m_drain_wanted{false};
    // Set by the crossing, consumed on the next loop turn.  Not called from
    // the crossing itself, because a script's on_writable sends and the write
    // path still holds its own state -- the server's dispatch gives the long
    // form of this reasoning.
    bool m_drain_due{false};

    // Reconnect state, whose request and timespec live in m_conn because they
    // are storage the ring can name.
    int m_reconnect_attempt{0};
    bool m_reconnect_pending{false};

    // Whether the socket now held has already been counted, lowered at every
    // dial, so a reconnect counts a connection and a re-dial of the same dead
    // target counts none.
    bool m_conn_counted{false};
    // Every dial this client has made, where total_connections used to be, so
    // the churn a flapping target produces still has a name of its own.
    std::atomic<uint64_t> m_stat_dial_attempts{0};

    // DNS cache (avoids getaddrinfo on every reconnect)
    struct sockaddr_in m_cached_addr{};
    bool m_has_cached_addr{false};
    std::string m_cached_host;
    uint16_t m_cached_port{0};

    // ─── TLS ────────────────────────────────────────────────────────────────
    // Null when this client dials in cleartext, rebuilt on every start so
    // `reload` installs a renewed certificate, with existing sessions holding
    // their own reference to the old SSL_CTX.
    std::unique_ptr<tls_context> m_tls;
    // The name the peer's certificate has to be valid for, recorded in
    // try_connect while the target is being parsed, because that is the only
    // place it is known.
    std::string m_tls_peer_name;

    // Sized for the one connection a client has: 65536 x 8 measured 42 M msg/s
    // against 4096 x 64's 24.9 M in the same 256 KB, because four large
    // buffers stay in cache where sixty-four small ones do not.
    static constexpr uint16_t BUF_GROUP_ID = 4;
    static constexpr uint32_t BUF_COUNT = 8;
    static constexpr uint32_t BUF_SIZE = 65536;
    bool m_use_provided_bufs{false};
};
