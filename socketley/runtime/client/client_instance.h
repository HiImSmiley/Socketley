#pragma once
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

// Everything the ring can name for one run of this runtime: the two requests it
// reuses, the buffers the kernel reads out of and writes into, and the reconnect
// timer.  It is one struct with a lifetime of its own — not a member of the
// instance — because a stop does not end what the ring is carrying.
//
// stop() deregisters the owner, and from that moment the loop drops this
// instance's completions rather than dispatching them: on_cqe does not run,
// settle_stale() does not run, and the flags that say a request is occupied are
// never lowered.  They must not simply be cleared either — the kernel really is
// still writing into read_buf and reading out of write_buf.  So a run that finds
// them still standing takes a fresh struct and leaves the old one to the ring;
// see client_instance::setup().
struct client_tcp_connection
{
    int fd{-1};
    io_request read_req;
    io_request write_req;
    char read_buf[4096];
    std::string write_buf;
    // How much of write_buf the kernel has already taken. A write that returns
    // short is ordinary, and resuming from the right offset is what keeps the
    // remainder from being dropped and the next message from being appended to
    // half of this one.
    size_t write_off{0};
    std::string partial;

    static constexpr size_t MAX_PARTIAL_SIZE = 1 * 1024 * 1024;

    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};

    // The reconnect timer.  It lives here rather than on the instance because it
    // is the same kind of thing as the two requests above — storage the ring can
    // name that outlives the stop which armed it — and because it hangs off no
    // descriptor, so nothing a teardown closes can reach it.  Withdrawing it
    // makes it report at once; it is still owed exactly one completion either
    // way, and that completion is dropped if the runtime has stopped.
    io_request timeout_req{};
    struct __kernel_timespec timeout_ts{};

    // === TLS session ===
    // Non-null only on a client configured with --tls.  OpenSSL never sees the
    // socket: the session sits on a memory BIO pair, ciphertext reaches it from
    // read_buf and leaves it into write_buf, and every byte on the wire is
    // still moved by an io_uring submission — the same design the server's
    // listener and the proxy's backend leg use, with this end as the client.
    //
    // Nothing the ring can name lives inside the SSL, which is what makes the
    // session safe to free the moment the connection is lost even with a write
    // still in flight: the kernel is reading out of write_buf, which this
    // struct owns.
    SSL* ssl{nullptr};
    tls_conn_state tls_state{tls_conn_none};
    // The peer sent close_notify.  Recorded rather than acted on, so the
    // plaintext that arrived ahead of it in the same read is still delivered.
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

    // Lua actions
    bool lua_send(std::string_view msg) override;

private:
    void handle_read(struct io_uring_cqe* cqe);
    void handle_write(struct io_uring_cqe* cqe);
    void handle_timeout(struct io_uring_cqe* cqe);

    void process_message(std::string_view msg);
    void send_to_server(std::string_view msg);
    // Returns whether the reconnect clock is actually armed.  A caller that
    // ignores it is claiming a client will dial again when nothing will make
    // it.
    [[nodiscard]] bool schedule_reconnect();
    bool try_connect();
    // The one place a read is armed, and only when one is not already armed.
    void arm_read();
    // The one place a write is armed.  The request records the descriptor it was
    // armed for, which is how a completion for a socket since lost is spotted.
    void arm_write(const char* data, uint32_t len);
    // Take the next queued message once the write request comes free.
    void flush_queued_write();
    // Lose the socket and start the reconnect clock.  Every path that gets here
    // does the same five things; they used to do them each in their own copy.
    void drop_connection();
    // Every descriptor this runtime gives back to the kernel goes through here.
    // A close does not withdraw an SQE that already carries the number, and this
    // runtime reuses one read request and one write request across reconnects,
    // so the number really does come straight back — see event_loop::close_fd.
    // m_ring_loop and not m_loop: sockets are dropped after teardown has cleared
    // m_loop, which is when the ring is most likely to still hold something.
    void close_tracked(int fd);
    // Account for a completion that is not ours to act on any more.
    void settle_stale(struct io_uring_cqe* cqe, io_request* req);
    // Hand a provided buffer back when we drop the completion carrying it.  The
    // group has 64 buffers and every client runtime on this loop shares it, so
    // a runtime that keeps dropping them starves all of them.
    void return_provided_buf(struct io_uring_cqe* cqe);

    // ── TLS record layer ────────────────────────────────────────────────────
    //
    // OpenSSL does no I/O in either of these.  The handshake is advanced one
    // completion at a time: tls_feed hands the record layer the ciphertext a
    // read delivered and leaves whatever plaintext came out in m_conn->partial,
    // and tls_flush takes queued plaintext plus whatever the session owes on
    // its own account — a handshake flight, an alert, a session ticket — and
    // puts it on the wire as one ordinary write submission.  Everything above
    // them, the line framing and the Lua callbacks, sees the same plaintext it
    // always did.
    //
    // The design is server_instance's and proxy_instance's; a third spelling of
    // it would be a third thing to keep in step, so the shape is deliberately
    // identical and only the buffers differ — this runtime has one write
    // request and one write buffer, not a batch.
    void tls_feed(const char* data, size_t len);
    void tls_flush();
    // Give this connection a session and put the ClientHello on the wire.
    // False means no session could be created — no peer name to verify
    // against, or OpenSSL refused — and the caller must give the socket up
    // rather than carry on in cleartext, which is the whole point of the flag.
    bool start_tls();
    // Release the session.  Called wherever the socket is lost, so that a
    // reconnect starts a fresh handshake rather than resuming one against a
    // peer that never saw the first half of it.
    void tls_release();

    client_mode m_mode;
    bool m_udp{false};
    // The current run's I/O state, and the ones earlier runs left behind with
    // something still in the ring.  A spent struct is not freed when it is
    // replaced: the loop reads the request inside it in order to drop its
    // completion, and the kernel may still be writing into its read buffer, so
    // it has to outlive the ring's interest in it.  setup() releases them once
    // owner_inflight() says nothing is left.  See client_tcp_connection.
    std::unique_ptr<client_tcp_connection> m_conn;
    std::vector<std::unique_ptr<client_tcp_connection>> m_conn_spent;
    // Which socket the requests in flight belong to.  There is one read request
    // and one write request on this instance and both are reused, and a closed
    // descriptor number comes straight back from the kernel on the next
    // connect — so neither the address nor the fd tells a completion for the
    // socket we have now from one for the socket we had before.  This does.
    uint32_t m_conn_generation{0};
    event_loop* m_loop;
    // The same loop, kept across teardown: completions still arrive while the
    // runtime is stopped and the buffers they carry have to go back. Never used
    // to submit — m_loop being null is what says submitting is not allowed.
    event_loop* m_ring_loop{nullptr};
    bool m_connected;

    // Write queue (prevents silent message loss when write_pending)
    socketley::byte_counted_queue<std::string> m_write_queue;
    // Latches the "not draining" report. A stuck peer drops every message that
    // follows, and one line per dropped message would bury the first — which is
    // the only one that says anything new.
    bool m_write_queue_full{false};

    // Reconnect state.  The request and the timespec live in m_conn — see
    // there — because they are storage the ring can name.
    int m_reconnect_attempt{0};
    bool m_reconnect_pending{false};

    // DNS cache (avoids getaddrinfo on every reconnect)
    struct sockaddr_in m_cached_addr{};
    bool m_has_cached_addr{false};
    std::string m_cached_host;
    uint16_t m_cached_port{0};

    // ─── TLS ────────────────────────────────────────────────────────────────
    // Null when this client dials in cleartext.  Rebuilt by setup() on every
    // start, so `reload` is how a renewed certificate is installed — sessions
    // already handed out hold their own reference to the old SSL_CTX and are
    // unaffected.  Exactly the server's arrangement.
    std::unique_ptr<tls_context> m_tls;
    // The name the peer's certificate has to be valid for: the host side of
    // `-t`, as the operator wrote it, resolved to nothing and read back from no
    // certificate.  Recorded in try_connect while the target is being parsed,
    // because that is the only place it is known, and handed to
    // create_ssl_client — which refuses to build a session without one.
    std::string m_tls_peer_name;

    // Provided buffer ring
    static constexpr uint16_t BUF_GROUP_ID = 4;
    static constexpr uint32_t BUF_COUNT = 64;
    static constexpr uint32_t BUF_SIZE = 4096;
    bool m_use_provided_bufs{false};
};
