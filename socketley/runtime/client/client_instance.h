#pragma once
#include "../../shared/net/async_resolver.h"
#include <atomic>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <netinet/in.h>
#include <linux/time_types.h>

#include "../../shared/runtime/runtime_instance.h"
#include "../../shared/loop/write_queue.h"
#include "../../shared/loop/line_framing.h"
#include "../../shared/loop/event_loop_definitions.h"
#include "../../shared/crypto/tls_context.h"
#include "../../shared/net/direct_send.h"

// Everything the ring can name for one connection, with a lifetime of its own
// because a stop deregisters the owner and the flags saying a request is
// occupied are never lowered while the kernel is still using the buffers.
//
// One per slot of --connections, and every request in it carries the struct
// in its buffer field, which is how a completion finds its connection.
struct client_tcp_connection
{
    int fd{-1};
    // Which socket the requests in flight belong to, because the requests are
    // reused and a closed descriptor number comes straight back from the
    // kernel on the next connect.
    uint32_t generation{0};
    // The connection id less one, which is this struct's index in m_slots.
    uint32_t slot{0};
    // Its place in m_conn_spent once retired with completions still owed.
    uint32_t spent_at{UINT32_MAX};
    int reconnect_attempt{0};

    bool connected{false};
    // Whether the socket now held has already been counted, lowered at every
    // dial, so a reconnect counts a connection and a re-dial of the same dead
    // target counts none.
    bool counted{false};
    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};
    bool reconnect_pending{false};
    // This slot's dial is waiting for the target's name.
    bool resolving{false};
    // This slot will never dial again: its --reconnect limit, or a timer the
    // ring refused.
    bool gave_up{false};
    // Latches the "not draining" report, because one line per dropped message
    // would bury the first, which is the only one that says anything new.
    bool queue_full{false};
    // Armed at the soft watermark by a send, cleared by the crossing back
    // down, which is the moment on_writable is owed.
    bool drain_wanted{false};
    // Set by the crossing, consumed on the next loop turn, off the write
    // path's stack.
    bool drain_due{false};
    bool hs_armed{false};
    // The peer sent close_notify, recorded rather than acted on so plaintext
    // that arrived ahead of it in the same read is still delivered.
    bool tls_peer_closed{false};
    tls_conn_state tls_state{tls_conn_none};

    io_request read_req;
    io_request write_req;
    // The reconnect timer, here because it is storage the ring can name that
    // outlives the stop which armed it and hangs off no descriptor a teardown
    // could close.
    io_request timeout_req{};
    // The handshake deadline's own clock, beside the reconnect one and never
    // sharing it: this one fires while `connected` is true, which is exactly
    // the state the reconnect clock's guard treats as "stale, do nothing".
    io_request hs_req{};
    struct __kernel_timespec timeout_ts{};
    struct __kernel_timespec hs_ts{};

    // Non-null only with --tls, on a memory BIO pair so every byte on the wire
    // is still moved by io_uring -- and nothing the ring can name lives inside
    // the SSL, which is what makes it safe to free with a write in flight.
    SSL* ssl{nullptr};

    std::string write_buf;
    // How much of write_buf the kernel has already taken, because resuming
    // from the right offset is what keeps the next message from being appended
    // to half of this one.
    size_t write_off{0};
    std::string partial;
    socketley::byte_counted_queue<std::string> write_queue;

    // The plain read's buffer, made on first use, because with provided
    // buffers a connection never reads into its own.
    std::unique_ptr<char[]> read_buf;
    static constexpr uint32_t READ_BUF_SIZE = 4096;

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

    // --connections: how many connections this runtime holds to its target,
    // opened or closed on the spot when it is running.
    void set_connections(uint32_t n);
    uint32_t get_connections() const { return m_connections; }
    static constexpr uint32_t max_connections_held = 65535;

    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;

    size_t get_connection_count() const override;
    // Every connection's queue, so many connections pace against one budget as a server's clients do.
    size_t total_queued_bytes() const override;

    // One line, dial_attempts, which is what total_connections stopped being
    // when it started counting connections.
    std::string stats_lines() const override;

    // `socketley send` and socketley.send(): the one connection, or with
    // --connections the next connected one in turn.
    bool lua_send(std::string_view msg) override;

    // What self.send(msg [, id]) answered, each with a sentence of its own in
    // the binding.
    enum class send_answer : uint8_t { sent, backlogged, not_connected, no_current, no_such_id };
    // id 0 is "no id given": the connection whose callback is running.
    send_answer script_send(std::string_view msg, int id);

    // Bytes queued and not on the wire: for id, that connection, or -1 when
    // there is none; without one, the connection whose callback is running,
    // or the sum outside every callback.
    long pending_bytes() const;
    long pending_bytes_of(int id) const;

    // script_send() when it can only end on the queue behind a write in
    // flight, and false, having done nothing, everywhere else.
    bool send_if_queued(std::string_view msg, int id);

    // Bytes a script's self.send copies through FFI while a callback for one connection runs, which become that
    // connection's queue when the callback ends or before anything else reads or writes the queue: a C call a line
    // was a third of a producer's core.  cap is 0 when there is no such connection, which sends the script to C.
    struct ffi_stage
    {
        unsigned char* p;
        double len;
        double cap;
    };
    ffi_stage* ffi_stage_area();

    // The drain crossing is already detected twice in the write paths; this is
    // where the script is told about it, off those stacks.
    void on_loop_turn() override;

private:
    using conn_t = client_tcp_connection;

    // The connection a completion names, carried in the request's buffer
    // field as file_io carries its op.
    static conn_t* conn_of(io_request* req) { return reinterpret_cast<conn_t*>(req->buffer); }
    // Whether conn is the one its slot holds now, and not one a stop, a
    // restart or a shrink left behind.
    bool is_current(const conn_t* conn) const
    {
        return conn->slot < m_slots.size() && m_slots[conn->slot].get() == conn;
    }
    // The slot a script names by id, null when it names none.
    conn_t* slot_of_id(int id) const
    {
        return id >= 1 && static_cast<size_t>(id) <= m_slots.size() ? m_slots[static_cast<size_t>(id) - 1].get()
                                                                     : nullptr;
    }

    // Marks the connection a callback runs for, for as long as it runs, so a
    // send without an id goes back where the callback came from.
    struct current_scope
    {
        client_instance& c;
        int saved;
        current_scope(client_instance& ci, const conn_t* conn) : c(ci), saved(ci.m_cur)
        {
            ci.stage_close();
            ci.m_cur = static_cast<int>(conn->slot);
            ci.stage_open(conn);
        }
        ~current_scope()
        {
            c.stage_close();
            c.m_cur = saved;
        }
        current_scope(const current_scope&) = delete;
        current_scope& operator=(const current_scope&) = delete;
    };
    // The id a callback passes, its slot plus one.
    static int id_of(const conn_t* conn) { return static_cast<int>(conn->slot) + 1; }

    void handle_read(conn_t* conn, struct io_uring_cqe* cqe);
    void handle_write(conn_t* conn, struct io_uring_cqe* cqe);
    // Takes the request as well as the completion, because two clocks share
    // op_timeout and state cannot tell them apart.
    void handle_timeout(conn_t* conn, struct io_uring_cqe* cqe, io_request* req);
    // A dial that connected is not a connection: the TCP half succeeded and
    // the peer may never finish the handshake, in which case nothing is ever
    // lost and --reconnect is never reached.
    void arm_handshake_deadline(conn_t* conn);

    void process_message(std::string_view msg, int id);
    // One read's plaintext into lines: in place for a provided buffer, through
    // partial for read_buf, and after the record layer for TLS.
    void read_in_place(conn_t* conn, char* data, size_t len);
    void read_through_partial(conn_t* conn, const char* data, size_t len);
    void read_tls(conn_t* conn, const char* data, size_t len);
    void deliver_partial(conn_t* conn, size_t scanned);
    // Every complete line to process_message until a callback loses the
    // socket, which returns socketley::line_framing_stopped.
    size_t deliver_lines(conn_t* conn, const char* data, size_t len, size_t search_from);
    // Whether a read's lines go to on_read or on_messages in one call rather than one by one.
    bool batches_lines() const;
    // deliver_lines() for on_read and on_messages: everything up to the last newline in one call.
    size_t deliver_chunk(conn_t* conn, const char* data, size_t len, size_t search_from);
    bool still_reading(const conn_t* conn, uint32_t slot, uint32_t generation, int fd) const;
    // Returns whether the reconnect clock is actually armed, since a caller
    // that ignores it claims a client will dial again when nothing will make
    // it.
    [[nodiscard]] bool schedule_reconnect(conn_t* conn);

    bool try_connect(conn_t* conn, bool at_start = false);
    // The one place a read is armed, and only when one is not already armed;
    // poll_first says the read just completed left the socket empty.
    void arm_read(conn_t* conn, bool poll_first = false);
    // The plain read into the connection's own buffer, made here on first use.
    bool submit_plain_read(conn_t* conn, bool poll_first);
    // The one place a write is armed, recording the descriptor so a completion
    // for a socket since lost is spotted.
    void arm_write(conn_t* conn, const char* data, uint32_t len);
    // Take the next queued message once the write request comes free.
    void flush_queued_write(conn_t* conn);
    // Lose the socket and start the reconnect clock, in one place, because
    // every path that gets here used to do the same five things in its own
    // copy.
    void drop_connection(conn_t* conn);
    // The two halves of `connected`, in one place each, because the count of
    // connections up is kept and not walked.
    void mark_dialled(conn_t* conn);
    void mark_down(conn_t* conn);
    // A slot that will never dial again, and the runtime failed once every
    // slot has.
    void give_up(conn_t* conn);
    // The other half of that clock: reset the backoff and the attempt count,
    // from the first completion that carries bytes and not from a connect()
    // that answered EINPROGRESS.
    void note_established(conn_t* conn);
    // Count this socket in total_connections, once, and only once the kernel
    // has a peer to name for it -- a dial is an intention and the server
    // counts at an accept() that really happened.
    void note_connected(conn_t* conn);
    // Every descriptor this runtime gives back goes through here, because it
    // reuses one read and one write request across reconnects and the number
    // really does come straight back.
    void close_tracked(int fd);
    // Account for a completion that is not ours to act on any more.
    void settle_stale(conn_t* conn, struct io_uring_cqe* cqe, io_request* req);
    // Hand a provided buffer back when a completion carrying it is dropped,
    // because every client runtime on this loop shares the group.
    void return_provided_buf(struct io_uring_cqe* cqe);
    // A struct the ring still owes completions, kept until it owes none.
    void retire(std::unique_ptr<conn_t> conn);
    void keep_spent(std::unique_ptr<conn_t> conn);
    void drop_spent(conn_t* conn);
    static bool owes_completions(const conn_t* conn)
    {
        return conn->read_pending || conn->write_pending || conn->reconnect_pending || conn->hs_armed;
    }
    // Give a running slot up for good, for a shrink: the socket, the session,
    // both clocks and the queue.
    void close_slot(conn_t* conn);
    // A new slot, dialled now when the runtime is running.
    void open_slot();
    // The slot a send without an id goes to, null with a reason when there is
    // none.
    conn_t* current_or_only(send_answer& why) const;
    // One message onto one connection, the body every send shares.
    bool write_one(conn_t* conn, std::string_view msg);
    // One message onto the queue behind a write in flight, raising
    // drain_wanted at the watermark.
    void enqueue_line(conn_t* conn, std::string_view msg);
    void enqueue_datagram(conn_t* conn, std::string_view msg);

    // ── TLS record layer ────────────────────────────────────────────────────
    // OpenSSL does no I/O in either of these: tls_feed hands the record layer
    // what a read delivered and tls_flush puts what the session owes on the
    // wire as one ordinary write, deliberately identical in shape to the
    // server's and the proxy's.
    void tls_feed(conn_t* conn, const char* data, size_t len);
    void tls_flush(conn_t* conn);
    // Give this connection a session and put the ClientHello on the wire,
    // where false means the caller must give the socket up rather than carry
    // on in cleartext.
    bool start_tls(conn_t* conn);
    // Release the session wherever the socket is lost, so a reconnect starts a
    // fresh handshake rather than resuming one the peer never saw the first
    // half of.
    void tls_release(conn_t* conn);

    client_mode m_mode;
    bool m_udp{false};
    // How many connections were asked for; m_slots follows it while running.
    uint32_t m_connections{1};
    // The slots, id N at index N-1, and the structs earlier runs or a shrink
    // left behind, kept because the loop reads the request inside a spent
    // struct to drop its completion.
    std::vector<std::unique_ptr<conn_t>> m_slots;
    std::vector<std::unique_ptr<conn_t>> m_conn_spent;
    // Where each line of the read on_read is looking at ends, kept for its capacity.
    socketley::line_ends m_line_ends;
    // True while on_read runs, so a delivery under it leaves m_line_ends alone.
    bool m_viewing = false;
    // Slots with `connected` up, kept so the count is never a walk.
    size_t m_up{0};
    size_t m_gave_up{0};
    // The slot whose callback is running, -1 outside all of them.
    int m_cur{-1};
    // Where the next `socketley send` starts looking.
    uint32_t m_rr{0};
    // Some slot dialled and is not yet counted, or owes on_writable.
    bool m_count_due{false};
    bool m_drain_any{false};
    event_loop* m_loop;
    // The same loop kept across teardown, so buffers carried by late
    // completions go back, and never used to submit -- m_loop being null is
    // what says submitting is not allowed.
    event_loop* m_ring_loop{nullptr};

    // How large a coalesced entry may grow, 1 MiB where the other runtimes use
    // 64 KB, because this runtime has no writev batching at all -- flush()
    // takes one entry and arms one write for it -- so a client that is behind
    // pays the cost of a send once per entry and not once per message.
    static constexpr size_t WRITE_COALESCE_LIMIT = 1024 * 1024;

    // Whether a line may go by sendmsg() and skip the ring: only the turn's one write, so a producer sending in a loop
    // queues and coalesces instead of paying a syscall per line.
    socketley::direct_send_gate m_direct_gate;

    // Every dial this client has made, where total_connections used to be, so
    // the churn a flapping target produces still has a name of its own.
    std::atomic<uint64_t> m_stat_dial_attempts{0};

    // DNS cache (avoids getaddrinfo on every reconnect)
    struct sockaddr_in m_cached_addr{};
    bool m_has_cached_addr{false};
    // A reconnect looks the target's name up off the loop, and while the answer is out the dial is retried every tenth of a second.
    socketley::async_resolver m_resolver;
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

    // Sized for the one connection a client has.  Measured, 64-byte lines, a
    // blaster filling the socket: 4096 x 64 carried 24.9 M msg/s in 256 KB and
    // 65536 x 8 carried 42.3 M in 512 KB, because a few large buffers stay in
    // cache where sixty-four small ones do not.
    //
    // 65536 x 4 measured 42.5 M in 256 KB -- the same, for half the memory --
    // and 8 was taken because at most one buffer was ever in flight, which made
    // the other seven margin.  The multishot arm took that premise away: the
    // kernel fills the next buffer while this one is being parsed, so several
    // are in flight and the margin is working set.
    //
    // Measured again under it, two binaries differing in this constant alone,
    // arms interleaved and the order rotated: 4 against 8 came out [0.986,
    // 1.027] once a pass where the 8 arm dropped to 2.03 G/s is set aside,
    // against a noise floor of [0.968, 1.026] from running 8 against itself.
    // The same as before, in other words, so 8 stays -- there is no throughput
    // reason to move and the reason to hold is the one that changed: whether
    // four is enough headroom before ENOBUFS sends this client down the plain
    // read path is not something the throughput figure would show.
    static constexpr uint16_t BUF_GROUP_ID = 4;
    static constexpr uint32_t BUF_COUNT = 8;
    static constexpr uint32_t BUF_SIZE = 65536;
    // With --connections every connection may hold a buffer in the same turn,
    // so the pool is one per connection, the server's size at most, in 1 MB
    // until each buffer is down to a page.
    static constexpr uint32_t MULTI_BUF_SIZE = 16384;
    static constexpr uint32_t MULTI_BUF_MIN = 4096;
    static constexpr uint32_t MULTI_BUF_POOL = 1024 * 1024;
    static constexpr uint32_t MULTI_BUF_MAX = 4096;
    // A sixteenth of a buffer free before it, where a batch reader's leftover line is put rather than the read copied behind it.
    static constexpr uint32_t BUF_HEADROOM_SHARE = 16;
    bool m_use_provided_bufs{false};
    // The stage of ffi_stage_area(), open for the connection in m_stage_slot at m_stage_gen, or for none at -1.
    static constexpr size_t STAGE_BYTES = 65536;
    std::unique_ptr<unsigned char[]> m_stage_buf;
    ffi_stage m_stage{};
    int m_stage_slot{-1};
    uint32_t m_stage_gen{0};
    void stage_open(const conn_t* conn);
    // The staged bytes into their connection's queue, the stage left open with what room the queue leaves.
    void stage_flush();
    void stage_close();

    // The kernel re-arming the recv instead of this client doing it per
    // message; off wherever the ring or SOCKETLEY_RECV_MULTISHOT says so.
    bool m_recv_multishot{false};
};
