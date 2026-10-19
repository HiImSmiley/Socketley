#pragma once
// The broker on its sockets: listeners for MQTT and for MQTT over WebSocket, TLS in memory buffers, reads from a
// buffer ring so a connection that says nothing holds no read buffer of its own, and the second tick that drives
// keep alive, wills, expiry, the files read again and the snapshot.
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <openssl/ssl.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "mqtt_auth.h"
#include "mqtt_broker.h"
#include "mqtt_routes.h"
#include "../../shared/ipc/request_channel.h"
#include "../../shared/loop/event_loop.h"
#include "../../shared/loop/file_io.h"
#include "../../shared/loop/hash_pool.h"

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
    size_t backlog(uint64_t conn) const override;
    void close(uint64_t conn) override;
    int64_t now_ms() const override;

    // ── broker_hooks ────────────────────────────────────────────────────────
    void authenticate(const auth_ask& ask, std::function<void(auth_answer)> done) override;
    bool may_write(std::string_view user, std::string_view client, std::string_view topic) override;
    bool may_read(std::string_view user, std::string_view client, std::string_view topic) override;
    bool reads_checked() const override { return !m_acl.value().empty(); }
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
    void filter_added(const std::string& filter) override;
    void filter_removed(const std::string& filter) override;

    // ── request_origin ──────────────────────────────────────────────────────
    void on_request_reply(uint64_t cookie, request_status st, std::string_view reply) override;

private:
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
        // A read buffer of its own, only where the buffer ring cannot be used.
        std::unique_ptr<char[]> rbuf;
        // Bytes not yet gone, and the ones the ring is sending now.
        std::string out;
        std::string sending;
        size_t sent{0};
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
        size_t unsent() const { return sending.size() - sent + out.size(); }
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
    void read_done(conn& c, struct io_uring_cqe* cqe);
    void bytes_in(conn& c, const char* p, size_t n);
    void tls_in(conn& c, const char* p, size_t n);
    void plain_in(conn& c, const char* p, size_t n);
    void ws_handshake(conn& c);
    void ws_frames(conn& c);
    void raw_out(conn& c, std::string_view bytes);
    void flush(conn& c);
    void write_done(conn& c, int res);
    void close_conn(conn& c);
    void settle();
    void arm_tick();
    void tick();
    void refresh_files(bool first);
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
    void post_shard(uint32_t to, std::string payload, uint64_t cookie);
    // Asks every other shard to give up the session of a client about to connect here, then answers `done`.
    void claim(const auth_ask& ask, auth_answer a, std::function<void(auth_answer)> done);
    void claim_reply(uint64_t cookie, request_status st, std::string_view reply);
    // An answer to what a starting shard asked another for; false when the cookie is no such question.
    bool dump_reply(uint64_t cookie, request_status st, std::string_view reply);
    void finish_claim(uint64_t id);
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
    std::shared_ptr<bool> m_alive;

    // Requests the topic rules have in flight, by cookie.
    struct route_ask
    {
        size_t        index{0};
        route_request request;
    };
    std::unordered_map<uint64_t, route_ask> m_route_asks;
    uint64_t m_next_cookie{1};
    bool m_routes_dirty{false};

    // What the other shards subscribe to, one tree each, and the shared groups among it.
    struct peer
    {
        std::unique_ptr<subscription_tree> filters;
        std::unordered_map<std::string, size_t> held;
        bool known{false};
    };
    std::vector<peer> m_peers;
    // The shared groups this message's delivery chose another shard for, filled while it is routed here.
    std::vector<std::vector<std::string>> m_assign;
    std::unordered_map<std::string, uint64_t> m_group_turn;
    // A CONNECT waiting for the other shards to give its session up.
    struct pending_claim
    {
        auth_ask    ask;
        auth_answer answer;
        std::function<void(auth_answer)> done;
        uint64_t    stamp{0};
        size_t      waiting{0};
        bool        lost{false};
        std::string session;
        int64_t     started_ms{0};
    };
    std::unordered_map<uint64_t, pending_claim> m_claims;
    std::unordered_map<uint64_t, uint64_t> m_claim_cookies;
    // Questions a starting shard asked, by cookie: of which shard, and whether for its retained messages.
    std::unordered_map<uint64_t, std::pair<uint32_t, bool>> m_dump_asks;
    uint64_t m_next_claim{1};
    // Cookies of shard requests whose answer is only a receipt.
    uint64_t m_shard_cookie_base{1ull << 62};
    uint64_t m_shard_forwarded{0};
    uint64_t m_shard_received{0};
    uint64_t m_shard_unreached{0};
    uint64_t m_claims_made{0};
    uint64_t m_claims_lost{0};
    uint64_t m_sessions_moved{0};
};

}   // namespace socketley::mqtt
