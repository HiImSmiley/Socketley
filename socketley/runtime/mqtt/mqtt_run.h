#pragma once
// The broker on its sockets: listeners for MQTT and for MQTT over WebSocket, TLS in memory buffers, reads from a
// buffer ring so a connection that says nothing holds no read buffer of its own, and the second tick that drives
// keep alive, wills, expiry, the files read again and the snapshot.
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <openssl/ssl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "mqtt_auth.h"
#include "mqtt_broker.h"
#include "mqtt_routes.h"
#include "../../shared/http/outbound_http.h"
#include "../../shared/ipc/request_channel.h"
#include "../../shared/loop/event_loop.h"
#include "../../shared/loop/file_io.h"
#include "../../shared/loop/hash_pool.h"
#include "../../shared/loop/write_queue.h"

class mqtt_instance;
class tls_context;

namespace socketley::idp
{
class session_verifier;
}

namespace socketley::mqtt
{

class mqtt_lua;

class mqtt_run : public io_handler, public broker_io, public broker_hooks, public request_origin
{
public:
    mqtt_run(mqtt_instance& owner, event_loop& loop);
    ~mqtt_run() override;

    bool start(std::string& why);
    void stop();
    bool drained() const;
    void on_loop_turn();
    void on_cqe(struct io_uring_cqe* cqe) override;

    // A command of the CLI, a script or a notification, answered through the channel.
    void command(uint64_t ticket, std::string_view payload);
    // Another shard's request.
    void shard_request(uint64_t ticket, std::string_view payload);

    size_t conn_count() const { return m_conns.size(); }
    std::string stats() const;
    broker& core() { return *m_broker; }
    mqtt_instance& owner() { return m_owner; }

    // ── broker_io ───────────────────────────────────────────────────────────
    void send(uint64_t conn, std::string_view bytes) override;
    void send_control(uint64_t conn, std::string_view bytes) override;
    void send_parts(uint64_t conn, std::string_view head, const std::shared_ptr<const std::string>& owner,
                    std::string_view body) override;
    size_t backlog(uint64_t conn) const override;
    void close(uint64_t conn) override;
    int64_t now_ms() const override;
    void pause_reading(uint64_t conn, bool paused) override;

    // ── broker_hooks ────────────────────────────────────────────────────────
    void authenticate(const auth_ask& ask, std::function<void(auth_answer)> done) override;
    bool may_write(std::string_view user, std::string_view client, std::string_view topic) override;
    bool may_read(std::string_view user, std::string_view client, std::string_view topic) override;
    bool reads_checked() const override { return m_acl.value().loaded(); }
    bool may_subscribe(std::string_view user, std::string_view client, std::string_view filter) override;
    bool hooks_publish() const override;
    void on_publish(const client_info& c, const message_ptr& m, std::function<void(publish_verdict)> done) override;
    bool hooks_subscribe() const override;
    void on_subscribe(const client_info& c, const std::string& filter, uint8_t qos,
                      std::function<void(bool)> done) override;
    void on_connected(const client_info& c) override;
    void on_disconnect(const client_info& c, std::string_view why) override;
    void accepted(const message_ptr& m) override;
    void retained_changed(const std::string& topic, const message_ptr& now) override;
    bool shared_here(std::string_view key) override;
    bool publish_room(uint8_t qos, uint64_t sent_to) const override;
    uint64_t shards_reached() const override { return m_reached; }
    bool heard_elsewhere(std::string_view topic) override;
    void filter_added(const std::string& filter) override;
    void filter_removed(const std::string& filter) override;
    void session_held(const std::string& client_id, const std::string& user, uint64_t stamp) override;
    void session_ended(const std::string& client_id) override;

    // ── request_origin ──────────────────────────────────────────────────────
    void on_request_reply(uint64_t cookie, request_status st, std::string_view reply) override;

private:
    // The most a fitted connection's write takes, and its chunks hold: a client's PINGRESP waits behind no more.
    static constexpr size_t fitted_batch = 64 * 1024;
    struct conn
    {
        uint64_t id{0};
        int fd{-1};
        sockaddr_in peer{};
        io_request rd{}, wr{};
        bool rd_pending{false}, wr_pending{false}, dead{false};
        // The ring had no buffer to give, or no room for a write, so it is asked again on a later turn.
        bool rearm{false};
        bool reflush{false};
        // The broker holds its next packet, so it is not read until it may go on; a multishot read is being taken back.
        bool paused{false};
        bool withdrawing{false};
        // Owed more than m_read_hold: a peer that does not read what it is sent is not read either until it has.
        bool write_held{false};
        // A read buffer of its own, only where the buffer ring cannot be used.
        std::unique_ptr<char[]> rbuf;
        // Bytes not yet gone, oldest first: the ones queued since the last write, and the ones the ring is sending
        // now, which stay where they are until it has. A large payload is a slice of the message every subscriber
        // sends from, as a cache's subscribers send a PUBLISH from one segment.
        std::vector<socketley::write_chunk> queue;
        std::vector<socketley::write_chunk> sending;
        size_t sending_at{0};
        size_t sent{0};
        size_t owed{0};
        std::vector<iovec> iov;
        // The room of a sent chunk of its own, taken by the next one, as out and sending traded theirs before.
        std::string spare;
        // The broker asked it closed once what it owes has gone; the time it asked, for a peer that never reads.
        bool closing{false};
        int64_t closing_ms{0};
        SSL* ssl{nullptr};
        bool handshaken{false};
        // WebSocket: the upgrade request until it is whole, then frames.
        bool ws{false};
        bool ws_open{false};
        std::string ws_in;
        bool told_broker{false};
        // On a path with a round trip: a write takes at most a batch, and the kernel holds little unsent, so what
        // `urgent` holds -- a PINGRESP, an acknowledgement -- goes ahead of the PUBLISHes still queued.
        bool fitted{false};
        std::string urgent;
        size_t unsent() const { return owed; }
    };
    struct listener
    {
        int fd{-1};
        io_request req{};
        bool pending{false};
        bool ws{false};
    };
    struct tap
    {
        std::string filter;
        std::deque<std::string> lines;
        int64_t polled_ms{0};
        uint64_t dropped{0};
    };

    bool open_listener(listener& l, uint16_t port, bool ws, std::string& why);
    void arm_accept(listener& l);
    void accept_done(listener& l, struct io_uring_cqe* cqe);
    conn* conn_of(io_request* req);
    conn* find(uint64_t id);
    const conn* find(uint64_t id) const;
    void arm_read(conn& c);
    void withdraw_read(conn& c);
    void read_done(conn& c, struct io_uring_cqe* cqe);
    void bytes_in(conn& c, const char* p, size_t n);
    void tls_in(conn& c, const char* p, size_t n);
    void plain_in(conn& c, const char* p, size_t n);
    void ws_handshake(conn& c);
    void ws_frames(conn& c);
    void raw_out(conn& c, std::string_view bytes);
    // Bytes already framed, sent ahead of what is queued on a fitted clear connection.
    void urgent_out(conn& c, std::string_view framed);
    // Bytes of the connection's own at the end of what it owes.
    static void queue_owned(conn& c, std::string_view bytes);
    // What OpenSSL has encrypted, moved to the end of what the connection owes.
    void queue_tls_out(conn& c);
    std::string m_tls_out;
    void flush(conn& c);
    void write_done(conn& c, int res);
    void close_conn(conn& c);
    void settle();
    void arm_tick();
    void tick();
    void refresh_files();
    void persist(bool now_and_wait);
    void reap_taps(int64_t now);
    void tap_message(const message& m);
    std::string sessions_json();
    std::string retained_json(std::string_view filter);
    void pump_routes();

    // ── Shards ──────────────────────────────────────────────────────────────
    bool sharded() const;
    void shards_start();
    void share_message(const message_ptr& m);
    void share_retained(const std::string& topic, const message_ptr& now);
    void share_interest(uint8_t verb, const std::vector<std::string>& filters);
    bool post_shard(uint32_t to, std::string payload, uint64_t cookie);
    // A batch posted to a shard and not yet receipted: where its frames are in the queue, and the number of the
    // first.
    struct shard_batch
    {
        uint64_t cookie{0};
        size_t   at{0};
        size_t   size{0};
        uint64_t first{0};
    };
    // What waits here for one shard from `head` on, and before it what is posted to it and not yet receipted, kept
    // in place for a resend.
    struct shard_queue
    {
        std::string pending;
        size_t      head{0};
        size_t      flying{0};
        int64_t     failing_since{0};
        int64_t     retry_at{0};
        // When a receipt last came, or the first batch since the last went out.
        int64_t     heard_ms{0};
        // The number of the frame at `head`, counted from this shard's start.
        uint64_t    seq{0};
        // The batches posted and not yet receipted, in the order they went.
        std::deque<shard_batch> sent;
        size_t waiting() const { return pending.size() - head; }
    };
    // A word owed only a receipt, kept for the next batch; false when it is dropped instead.
    bool queue_shard(uint32_t to, std::string_view frame, bool droppable);
    // A message for another shard, dropped where queue_shard() drops a delivery.
    bool queue_deliver(uint32_t to, uint8_t qos, std::string_view body, const std::vector<std::string>& groups);
    void send_shard(uint32_t to);
    void send_shards();
    bool unreachable(const shard_queue& q) const;
    // Handed batches and answered none of them for a while, as a shard that is stopped does.
    bool stalled(const shard_queue& q) const;
    // True when the cookie was a batch's, whatever its answer.
    bool shard_receipt(uint64_t cookie, request_status st, std::string_view reply);
    // One word from another shard, alone or out of a batch; `reply` is what a question is answered with.
    void shard_frame(std::string_view payload, std::string& reply);
    // Asks every other shard to give up the session of a client about to connect here, then answers `done`.
    void claim(const auth_ask& ask, auth_answer a, std::function<void(auth_answer)> done);
    void claim_reply(uint64_t cookie, request_status st, std::string_view reply);
    // An answer to what a starting shard asked another for; false when the cookie is no such question.
    bool dump_reply(uint64_t cookie, request_status st, std::string_view reply);
    void finish_claim(uint64_t id);
    // Another shard let a connection in to `client_id`: the one here is ended or refused if it is the one to give way.
    void settle(const std::string& client_id, uint64_t stamp, const std::string& user);
    void shard_stats(std::string& out) const;
    void sweep_claims(int64_t now);

    mqtt_instance& m_owner;
    event_loop& m_loop;
    file_io m_fio;
    hash_pool m_pool;
    std::unique_ptr<broker> m_broker;
    std::unique_ptr<tls_context> m_tls;
    std::unique_ptr<socketley::idp::session_verifier> m_idp;
    std::unique_ptr<mqtt_lua> m_lua;
    std::unique_ptr<route_table> m_routes;

    listener m_tcp, m_ws;
    std::unordered_map<uint64_t, std::unique_ptr<conn>> m_conns;
    // The connection find() last answered with, which only close_conn() takes out of the table.
    mutable const conn* m_last_conn{nullptr};
    std::vector<std::unique_ptr<conn>> m_closing;
    std::vector<uint64_t> m_close_soon;
    uint64_t m_next_id{1};
    bool m_ring{false};
    bool m_multishot{false};
    bool m_stopped{false};
    bool m_in_settle{false};

    io_request m_tick_req{};
    __kernel_timespec m_tick_ts{};
    bool m_tick_armed{false};
    int64_t m_next_files_ms{0};
    // An accept refused with EMFILE waits a moment before the next, rather than spinning on the same failure.
    int64_t m_accept_paused_until_ms{0};
    int64_t m_next_persist_ms{0};
    bool m_persist_busy{false};
    bool m_persist_failed{false};
    uint64_t m_persists{0};

    watched<user_table> m_users;
    watched<acl_rules> m_acl;

    std::unordered_map<uint64_t, tap> m_taps;
    uint64_t m_next_tap{1};

    uint64_t m_auth_refused{0};
    uint64_t m_tls_failures{0};
    uint64_t m_ws_refused{0};
    // Twice what deliveries stop at and a packet over, so only replies to a peer's own input can pass it.
    size_t m_read_hold{0};
    std::shared_ptr<bool> m_alive;

    // Requests the topic rules have in flight, by cookie.
    struct route_ask
    {
        size_t        index{0};
        route_request request;
    };
    std::unordered_map<uint64_t, route_ask> m_route_asks;
    // Each webhook rule's connection, null for a rule of any other kind, and the one request it has in flight, kept so
    // a snapshot holds it in its place.
    std::vector<std::unique_ptr<socketley::http_peer>> m_route_peers;
    std::vector<std::optional<route_request>>         m_route_posting;
    void post_route(size_t i);
    uint64_t m_next_cookie{1};
    bool m_routes_dirty{false};

    // What the other shards subscribe to, one tree each, and the shared groups among it.
    struct peer
    {
        std::unordered_map<std::string, size_t> held;
        // The clients it holds a session of, so a clean start asks only the shards that may have one to end.
        std::unordered_set<std::string> clients;
        bool known{false};
        // The start its batches are numbered from, and the number of the next frame owed from it.
        uint64_t epoch{0};
        uint64_t next{0};
    };
    std::vector<peer> m_peers;
    // What every other shard subscribes to, in one tree whose sessions are the shards, so a message is matched once
    // for all of them.
    subscription_tree m_remote;
    // A filter a shard took up or let go, counted per shard; and all of one shard's let go.
    void peer_filter(uint32_t from, const std::string& filter, bool add);
    void forget_peer(uint32_t from);
    std::vector<shard_queue> m_squeue;
    // The shard each batch not yet receipted went to, by cookie.
    std::unordered_map<uint64_t, uint32_t> m_shard_batches;
    // Each retained topic's last change by its stamp, for as long as an older one could still be on its way.
    std::unordered_map<std::string, uint64_t> m_retained_stamps;
    uint64_t m_shard_dropped{0};
    uint64_t m_shard_resent{0};
    // The shared groups this message's delivery chose another shard for, filled while it is routed here.
    std::vector<std::vector<std::string>> m_assign;
    // What share_message() works in, kept from one message to the next.
    std::vector<std::vector<std::string>> m_sharing;
    std::vector<uint8_t> m_plain;
    // The shards the last message shared was handed to.
    uint64_t m_reached{0};
    std::unordered_map<std::string, uint64_t> m_group_turn;
    // A CONNECT waiting for the other shards to give its session up.
    struct pending_claim
    {
        auth_ask    ask;
        auth_answer answer;
        std::function<void(auth_answer)> done;
        uint64_t    stamp{0};
        size_t      waiting{0};
        // Some shard was not asked, as for a clean start of a client no shard is known to hold.
        bool        skipped{false};
        bool        lost{false};
        // Another shard holds the session under another user, so this connection may not have it.
        bool        refused{false};
        std::string session;
        int64_t     started_ms{0};
    };
    std::unordered_map<uint64_t, pending_claim> m_claims;
    std::unordered_map<uint64_t, uint64_t> m_claim_cookies;
    // Questions a starting shard asked, by cookie: of which shard, and whether for its retained messages.
    std::unordered_map<uint64_t, std::pair<uint32_t, bool>> m_dump_asks;
    // When to ask again for the retained messages a starting shard did not get, 0 when it is not owed.
    int64_t m_retained_ask_ms{0};
    void ask_retained();
    uint64_t m_next_claim{1};
    // Cookies of shard requests whose answer is only a receipt.
    uint64_t m_shard_cookie_base{1ull << 62};
    // What this shard's batches are numbered under, new at each start so a peer counts them again.
    uint64_t m_shard_epoch{0};
    uint64_t m_shard_forwarded{0};
    uint64_t m_shard_received{0};
    uint64_t m_shard_unreached{0};
    uint64_t m_claims_made{0};
    uint64_t m_claim_asks{0};
    uint64_t m_claims_lost{0};
    uint64_t m_claims_refused{0};
    uint64_t m_sessions_moved{0};
};

}   // namespace socketley::mqtt
