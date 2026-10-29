#pragma once
// The broker without its sockets: bytes and the clock go in, bytes for each connection come out, and everything
// MQTT promises between them is kept here -- sessions that outlive a connection, QoS 1 and 2 with their packet
// identifiers, retained messages, wills, expiry and the limits that keep one slow client from costing the rest.
//
// What it cannot decide alone it asks: whether a client may connect, what a script says of a publish or a
// subscription, and what is done with a message once it is accepted (the topic rules and the other shards). An
// answer may come at once or on a later turn; until it comes, the connection that asked reads nothing more, so its
// packets are taken in the order it sent them.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "mqtt_codec.h"
#include "mqtt_topics.h"

namespace socketley::mqtt
{

// A message as it is routed: what a PUBLISH carried and the properties that travel with it.
struct message
{
    std::string topic;
    std::string payload;
    uint8_t     qos{0};
    bool        retain{false};
    std::optional<uint8_t>     payload_format;
    std::optional<std::string> content_type;
    std::optional<std::string> response_topic;
    std::optional<std::string> correlation_data;
    std::vector<std::pair<std::string, std::string>> user;
    // Wall-clock milliseconds after which it is not delivered, 0 for never.
    int64_t     expires_ms{0};
    // The client identifier of whoever published it, empty when it came from inside, for No Local.
    std::string from_client;
    // How many mqtt:// topic rules passed it on to get here, so rules that point at each other stop.
    uint8_t     hops{0};
};
using message_ptr = std::shared_ptr<const message>;

// A message as bytes, for the snapshot and for the shard it is handed to.
std::string message_bytes(const message& m);
bool message_from(std::string_view in, message& m);

struct broker_config
{
    uint32_t max_packet{256u << 10};
    // The longest a session lasts after its connection goes, in seconds; 0xFFFFFFFF for no limit.
    uint32_t session_expiry_max{86400};
    size_t   session_queue{1000};
    size_t   retained_max_bytes{64u << 20};
    size_t   max_sessions{100000};
    // The longest keep alive accepted, in seconds; a client asking more, or none, is held to it. 0 for no limit.
    uint16_t keepalive_max{1200};
    // How many QoS 1 and 2 messages a client may have unanswered towards the broker.
    uint16_t receive_maximum{1024};
    uint16_t topic_alias_maximum{64};
    // Bytes owed to one connection past which QoS 0 messages are dropped and QoS 1 and 2 wait.
    size_t   write_limit{4u << 20};
    int64_t  connect_timeout_ms{10000};
    // Retained $SYS/broker/... topics, refreshed this often; 0 for none.
    uint32_t sys_interval_s{10};
    // Where they go below $SYS/broker/, "shard/<i>/" for one shard of several.
    std::string sys_prefix;
    std::string version;
    // One shard of several, whose publishers may wait for room on the way to the others; asked for nowhere else.
    bool sharded{false};
};

// A session's waiting messages, read from a head index: it holds nothing until one waits, and little after.
template <class T>
class fifo
{
public:
    bool empty() const { return m_head == m_items.size(); }
    size_t size() const { return m_items.size() - m_head; }
    T& front() { return m_items[m_head]; }
    void push_back(T v) { m_items.push_back(std::move(v)); }
    void push_front(T v)
    {
        if (m_head)
            m_items[--m_head] = std::move(v);
        else
            m_items.insert(m_items.begin(), std::move(v));
    }
    void pop_front()
    {
        // What it held is let go at once, a message shared with other sessions included.
        m_items[m_head++] = T{};
        if (m_head == m_items.size())
            clear();
        else if (m_head >= 32 && m_head * 2 >= m_items.size())
        {
            m_items.erase(m_items.begin(), m_items.begin() + static_cast<std::ptrdiff_t>(m_head));
            m_head = 0;
        }
    }
    // Emptied, its room kept only while that is small.
    void clear()
    {
        if (m_items.capacity() > 4)
            std::vector<T>().swap(m_items);
        else
            m_items.clear();
        m_head = 0;
    }
    template <class Pred>
    size_t remove_if(Pred p)
    {
        const auto kept = std::remove_if(m_items.begin() + static_cast<std::ptrdiff_t>(m_head), m_items.end(), p);
        const auto n = static_cast<size_t>(m_items.end() - kept);
        m_items.erase(kept, m_items.end());
        if (empty())
            clear();
        return n;
    }
    auto begin() const { return m_items.begin() + static_cast<std::ptrdiff_t>(m_head); }
    auto end() const { return m_items.end(); }

private:
    std::vector<T> m_items;
    size_t         m_head{0};
};

// What a session sent and the client has not answered, by packet identifier. Identifiers are given in turn and
// mostly answered in turn, so the entries are a ring from the oldest, found by their distance from it rather than
// searched for, and one answered out of turn is marked and leaves when those before it have.
template <class T>
class id_window
{
public:
    size_t size() const { return m_live; }
    bool empty() const { return m_live == 0; }
    // All 65535 identifiers lie between the oldest unanswered and the next, so none is free.
    bool full() const { return m_slots.size() - m_head >= 65535; }
    uint16_t next_id() const { return m_next; }
    void set_next_id(uint16_t id)
    {
        if (m_slots.size() == m_head)
            m_next = id ? id : 1;
    }

    T* find(uint16_t id)
    {
        slot* sl = slot_of(id);
        return sl ? &sl->value : nullptr;
    }
    // The next identifier given to `v`; full() must be false.
    uint16_t add(T v)
    {
        const uint16_t id = m_next;
        push(id, std::move(v), true);
        return id;
    }
    // One read back from a snapshot, in the order they were sent; false when it cannot follow the last.
    bool restore(uint16_t id, T v)
    {
        if (id == 0)
            return false;
        if (m_slots.size() > m_head)
        {
            const uint16_t back = m_slots.back().id;
            const size_t d = distance(back, id);
            if (d == 0 || d + (m_slots.size() - m_head) > 65535)
                return false;
            for (uint16_t gap = after(back); gap != id; gap = after(gap))
                push(gap, T{}, false);
        }
        push(id, std::move(v), true);
        return true;
    }
    bool erase(uint16_t id)
    {
        slot* sl = slot_of(id);
        if (!sl)
            return false;
        sl->live  = false;
        sl->value = T{};
        --m_live;
        while (m_head < m_slots.size() && !m_slots[m_head].live)
            ++m_head;
        if (m_head == m_slots.size())
            reset();
        else if (m_head >= 32 && m_head * 2 >= m_slots.size())
        {
            m_slots.erase(m_slots.begin(), m_slots.begin() + static_cast<std::ptrdiff_t>(m_head));
            m_head = 0;
        }
        return true;
    }
    // Each unanswered one, oldest first.
    template <class F>
    void each(F&& fn) const
    {
        for (size_t i = m_head; i < m_slots.size(); ++i)
            if (m_slots[i].live)
                fn(m_slots[i].id, m_slots[i].value);
    }
    void clear()
    {
        reset();
        m_live = 0;
    }

private:
    struct slot
    {
        uint16_t id{0};
        bool     live{false};
        T        value{};
    };
    static size_t distance(uint16_t from, uint16_t to) { return (size_t(to) + 65535 - from) % 65535; }
    static uint16_t after(uint16_t id) { return id == 65535 ? 1 : static_cast<uint16_t>(id + 1); }
    slot* slot_of(uint16_t id)
    {
        const size_t n = m_slots.size() - m_head;
        if (n == 0 || id == 0)
            return nullptr;
        const size_t d = distance(m_slots[m_head].id, id);
        if (d >= n)
            return nullptr;
        slot& sl = m_slots[m_head + d];
        return sl.live && sl.id == id ? &sl : nullptr;
    }
    void push(uint16_t id, T v, bool live)
    {
        m_slots.push_back({id, live, std::move(v)});
        m_live += live;
        m_next = after(id);
    }
    // Emptied, its room kept only while that is small, as a fifo's is.
    void reset()
    {
        if (m_slots.capacity() > 8)
            std::vector<slot>().swap(m_slots);
        else
            m_slots.clear();
        m_head = 0;
    }

    std::vector<slot> m_slots;
    size_t   m_head{0};
    size_t   m_live{0};
    uint16_t m_next{1};
};

// What a connection looks like from outside, as the transport saw it.
struct conn_info
{
    std::string peer;
    // The common name of a client certificate the TLS layer verified, empty without one.
    std::string cert_cn;
    bool        tls{false};
    bool        websocket{false};
};

// Who a hook is asked about.
struct client_info
{
    uint64_t    conn{0};
    std::string client_id;
    std::string username;
    std::string peer;
    uint8_t     level{level_311};
};

struct auth_ask
{
    uint64_t    conn{0};
    std::string client_id;
    bool        clean_start{true};
    std::optional<std::string> username;
    std::optional<std::string> password;
    std::string cert_cn;
    std::string peer;
    uint8_t     level{level_311};
};

struct auth_answer
{
    // success, or the reason the CONNACK refuses with.
    uint8_t     code{reason::not_authorized};
    // The name the client is known by from here on: its user name, a certificate's CN or a token's account.
    std::string username;
};

struct publish_verdict
{
    bool allow{true};
    // A replacement for the message, its topic and payload changed by a script.
    message_ptr replace;
};

class broker_io
{
public:
    virtual ~broker_io() = default;
    virtual void send(uint64_t conn, std::string_view bytes) = 0;
    // A packet whose body is a slice of bytes `owner` keeps alive and other connections send too; a transport that
    // cannot send a slice sends the two together.
    virtual void send_parts(uint64_t conn, std::string_view head, const std::shared_ptr<const std::string>& owner,
                            std::string_view body)
    {
        (void)owner;
        std::string all;
        all.reserve(head.size() + body.size());
        all.append(head);
        all.append(body);
        send(conn, all);
    }
    // Bytes handed to send() for this connection and not yet gone.
    virtual size_t backlog(uint64_t conn) const = 0;
    // Ends a connection once what was sent has gone; disconnected() follows.
    virtual void close(uint64_t conn) = 0;
    virtual int64_t now_ms() const = 0;
    // Stops reading a connection, or goes on, so the bytes of a publisher that is held wait in its socket.
    virtual void pause_reading(uint64_t /*conn*/, bool /*paused*/) {}
};

class broker_hooks
{
public:
    virtual ~broker_hooks() = default;
    virtual void authenticate(const auth_ask& ask, std::function<void(auth_answer)> done) = 0;
    virtual bool may_write(std::string_view user, std::string_view client, std::string_view topic) = 0;
    virtual bool may_read(std::string_view user, std::string_view client, std::string_view topic) = 0;
    // Whether may_read can say no at all, asked once a message rather than once a subscriber.
    virtual bool reads_checked() const { return true; }
    virtual bool may_subscribe(std::string_view user, std::string_view client, std::string_view filter) = 0;
    // Whether a script wants to see publishes and subscriptions; without one they take no turn.
    virtual bool hooks_publish() const { return false; }
    virtual void on_publish(const client_info&, const message_ptr&, std::function<void(publish_verdict)> done)
    {
        done({});
    }
    virtual bool hooks_subscribe() const { return false; }
    virtual void on_subscribe(const client_info&, const std::string& /*filter*/, uint8_t /*qos*/,
                              std::function<void(bool)> done)
    {
        done(true);
    }
    // A client's CONNECT was accepted.
    virtual void on_connected(const client_info&) {}
    virtual void on_disconnect(const client_info&, std::string_view /*why*/) {}
    // A message the broker accepted from a client or from inside, for the topic rules and the other shards; not
    // called for one that arrived from another shard.
    virtual void accepted(const message_ptr&) {}
    // A retained message set or cleared, for the other shards.
    virtual void retained_changed(const std::string& /*topic*/, const message_ptr& /*now*/) {}
    // Whether this shard delivers a message to the shared group `key` ($share/<group>/<filter>) it has members of;
    // false when another shard with members was chosen.
    virtual bool shared_here(std::string_view /*key*/) { return true; }
    // Whether the way to the other shards can take another message at `qos` from a publisher whose last one went to
    // the shards in `sent_to`; while it cannot, the publisher is held, and room() lets it go on.
    virtual bool publish_room(uint8_t /*qos*/, uint64_t /*sent_to*/) const { return true; }
    // The shards the message just routed was handed to, one bit each.
    virtual uint64_t shards_reached() const { return 0; }
    // Whether a subscriber elsewhere would hear the topic, for the reason code a 5.0 publisher is answered with.
    virtual bool heard_elsewhere(std::string_view /*topic*/) { return false; }
    // A filter some session here subscribes to now and none did before, and the last one gone, for the shards that
    // send only where someone listens.
    virtual void filter_added(const std::string& /*filter*/) {}
    virtual void filter_removed(const std::string& /*filter*/) {}
};

struct broker_stats
{
    uint64_t connects{0};
    uint64_t connects_refused{0};
    uint64_t received[3]{};
    uint64_t sent[3]{};
    uint64_t dropped_slow{0};
    uint64_t dropped_queue{0};
    uint64_t dropped_expired{0};
    uint64_t dropped_too_large{0};
    uint64_t dropped_denied{0};
    uint64_t denied_publish{0};
    uint64_t denied_subscribe{0};
    uint64_t wills_sent{0};
    uint64_t sessions_expired{0};
    uint64_t sessions_evicted{0};
    uint64_t protocol_errors{0};
    uint64_t retained_refused{0};
    uint64_t takeovers{0};
    uint64_t takeovers_refused{0};
};

class broker
{
public:
    broker(broker_config cfg, broker_io& io, broker_hooks& hooks);
    ~broker();
    broker(const broker&)            = delete;
    broker& operator=(const broker&) = delete;

    // ── From the transport ──────────────────────────────────────────────────

    void connected(uint64_t conn, conn_info info);
    // Bytes read off the connection.
    void input(uint64_t conn, std::string_view bytes);
    // What a connection was owed has gone, so held QoS 1 and 2 messages may follow.
    void drained(uint64_t conn);
    // The connection is gone, whatever ended it.
    void disconnected(uint64_t conn);
    // Keep alive, deadlines, wills and expiry; called about once a second.
    void tick();

    // ── From inside ─────────────────────────────────────────────────────────

    // A message published by the operator, a script or a topic rule; `notify` false for one that came from another
    // shard, which is not handed to accepted() again.
    void publish(message m, bool notify = true);
    // A message another shard accepted, delivered to the subscribers here, and to the shared groups among `groups`
    // that shard chose this one for.
    void deliver_remote(const message_ptr& m, const std::vector<std::string>& groups);
    // Every filter subscribed to here, shared ones as $share/<group>/<filter>.
    std::vector<std::string> filters() const;
    // A retained message another shard set or cleared.
    void apply_retained(const std::string& topic, message_ptr m);
    // There may be room again: the publishers held for it that have some go on.
    void room();
    // A client disconnected by name, its session ended too when `end_session`; false when there is none.
    bool kick(std::string_view client_id, bool end_session);
    // The retained message of `topic` cleared, false when there was none.
    bool clear_retained(std::string_view topic);

    // ── Looking ─────────────────────────────────────────────────────────────

    struct session_view
    {
        std::string client_id;
        std::string username;
        bool        connected{false};
        uint8_t     level{0};
        size_t      subscriptions{0};
        size_t      queued{0};
        size_t      inflight{0};
        std::vector<std::string> filters;
        // Seconds until the session ends, for one with no connection; -1 for never.
        int64_t     expires_in{-1};
        std::string peer;
    };
    std::vector<session_view> sessions() const;
    void retained_each(std::string_view filter, const std::function<void(const message_ptr&)>& f) const;

    const broker_stats& stats() const { return m_stats; }
    size_t session_count() const { return m_sessions.size(); }
    size_t connected_count() const;
    size_t subscription_count() const { return m_subs.size(); }
    size_t retained_count() const { return m_retained.size(); }
    size_t retained_bytes() const { return m_retained_bytes; }
    size_t queued_count() const;
    size_t inflight_count() const;
    // Whether any subscription here matches, for a peer that sends only where someone listens.
    bool listens(std::string_view topic) const { return m_subs.any_match(topic); }
    // Whether some session here subscribes to exactly this filter, a shared one as $share/<group>/<filter>.
    bool has_filter(std::string_view filter) const { return m_filter_refs.contains(std::string(filter)); }

    // ── Persistence ─────────────────────────────────────────────────────────

    // Sessions, subscriptions, queues, unanswered messages and retained messages as bytes.
    std::string snapshot() const;
    // What a snapshot held, taken in at start; false with `why` when the bytes are not one.
    bool restore(std::string_view bytes, std::string& why);
    // Whether anything a snapshot holds changed since the last call.
    bool take_dirty();
    // The same, left as it is.
    bool dirty() const { return m_dirty; }

    // ── Moving sessions between shards ──────────────────────────────────────

    // The session of `client_id` given up as bytes for another shard where a connection to it has just arrived, the
    // one here closed as taken over; empty when there is none, or when `clean` ends it here.
    std::string surrender(std::string_view client_id, bool clean);
    // Whether `client_id` names a session not yet expired that was made under a user other than `username`.
    bool held_by_another(std::string_view client_id, std::string_view username) const;
    // A session another shard gave up, taken in for the connection about to resume it.
    void adopt(std::string_view bytes);

private:
    struct queued
    {
        message_ptr           msg;
        uint8_t               qos{0};
        bool                  retain_flag{false};
        std::vector<uint32_t> sub_ids;
    };
    struct inflight
    {
        enum class state : uint8_t { await_puback, await_pubrec, await_pubcomp };
        uint64_t seq{0};
        state    st{state::await_puback};
        queued   item;
    };
    struct session
    {
        uint64_t    key{0};
        std::string client_id;
        std::string username;
        // Whom it is counted against in m_owned: its user, or for a client with none its address.
        std::string owner;
        uint8_t     level{level_311};
        uint64_t    conn{0};
        std::map<std::string, sub_options> subs;
        fifo<queued> queue;
        id_window<inflight> out;
        std::set<uint16_t> incoming_qos2;
        uint64_t    next_seq{1};
        uint32_t    expiry{0};
        int64_t     gone_ms{0};
        std::unique_ptr<message> will;
        uint32_t    will_delay{0};
        int64_t     will_due_ms{0};
        // The client's own limits, from its CONNECT.
        uint16_t    receive_max{65535};
        uint32_t    max_packet{0};
        bool        problem_info{true};
        std::string peer;
        // Which message's subscribers it was last gathered for, and where, so overlapping filters fold into one.
        uint64_t    route_stamp{0};
        size_t      route_slot{0};
    };
    struct connection
    {
        uint64_t    id{0};
        conn_info   info;
        enum class phase : uint8_t { awaiting_connect, authenticating, open, closing } ph{phase::awaiting_connect};
        uint8_t     level{level_311};
        std::string in;
        // Where what is not yet handled of `in` begins, so a publisher held again and again is not moved each time.
        size_t      in_at{0};
        bool        busy{false};
        // Inside process(), so an answer that comes at once does not start a second walk over the same bytes.
        bool        processing{false};
        int64_t     opened_ms{0};
        int64_t     last_rx_ms{0};
        uint16_t    keepalive{0};
        session*    s{nullptr};
        // The topics a client's aliases stand for, alias 1 first, as long as the highest it has set.
        std::vector<std::string> aliases;
        uint32_t    incoming_pending{0};
        bool        sent_disconnect{false};
        // Set when the connection ends without a will: a DISCONNECT 0x00, or a takeover that keeps the session.
        bool        no_will{false};
        // Its next PUBLISH, at held_qos, waits for room on the way to the other shards.
        bool        held{false};
        uint8_t     held_qos{0};
        // The shards its last message was handed to.
        uint64_t    sent_to{0};
        uint64_t    generation{0};
        // The CONNECT while it is being answered; nothing once the connection is open.
        std::unique_ptr<connect_packet> pending;
    };

    connection* conn_of(uint64_t id);
    session* session_of_key(uint64_t key);
    // Whether a session left by its connection has outlived its expiry, whether or not the sweep has ended it yet.
    bool lapsed(const session& s, int64_t now) const;
    // A full table's room for one more: the session away longest of whoever holds the most, two or more, ended.
    bool make_room();
    // A session counted against its owner as it is made.
    void own(session& s);

    static constexpr size_t shared_payload_bytes = 8192;
    // Room the writing of each PUBLISH reuses, so a subscriber's copy costs no allocation once warm.
    std::string m_props_scratch;
    std::string m_out_scratch;
    void send_ack(connection& c, packet_type type, uint16_t id, uint8_t code);
    void process(connection& c);
    // The whole packets at the front of `in` handled, until one must wait; how many bytes they took.
    size_t consume(connection& c, std::string_view in);
    bool handle(connection& c, const frame& f);
    void protocol_failure(connection& c, uint8_t code, const std::string& why);
    void refuse_connect(connection& c, uint8_t level, uint8_t code);
    void disconnect_with(connection& c, uint8_t code, const std::string& why = {});

    bool on_connect(connection& c, const frame& f);
    void finish_connect(uint64_t conn, uint64_t generation, auth_answer a);
    bool on_publish(connection& c, const frame& f);
    void finish_publish(uint64_t conn, uint64_t generation, uint8_t qos, uint16_t id, uint8_t level,
                        publish_verdict v, message_ptr m);
    bool on_ack(connection& c, const frame& f);
    // A SUBSCRIBE whose filters are granted one after the other, a script's answer awaited between them.
    struct subscribe_state
    {
        subscribe_packet     p;
        std::vector<uint8_t> codes;
        // Whether each granted filter was new to the session, which Retain Handling 1 asks.
        std::vector<bool>    fresh;
    };
    bool on_subscribe(connection& c, const frame& f);
    void subscribe_step(uint64_t conn, uint64_t generation, std::shared_ptr<subscribe_state> st, size_t i,
                        bool script_said_yes);
    bool on_unsubscribe(connection& c, const frame& f);
    bool on_disconnect(connection& c, const frame& f);

    // The message delivered to everyone whose subscription matches; `groups`, when given, are the only shared groups
    // delivered to, as another shard chose them.
    void route(const message_ptr& m, bool notify, const std::vector<std::string>* groups = nullptr);
    // One subscriber of the message being routed, all its matching subscriptions folded in.
    struct route_target
    {
        session*              s{nullptr};
        uint8_t               qos{0};
        bool                  retain{false};
        std::vector<uint32_t> ids;
    };
    std::vector<route_target> m_route_scratch;
    uint64_t m_route_stamp{0};
    bool     m_routing{false};
    void filter_ref(const std::string& filter, bool add);
    // Whether the message was routed; false for one the retained store refused, which the publisher is told of.
    bool store_retained(const message_ptr& m, bool notify);
    void deliver(session& s, const message_ptr& m, uint8_t qos, bool retain_flag, std::vector<uint32_t> sub_ids);
    void send_retained(session& s, const std::string& filter, const sub_options& o);
    // QoS 1 and 2 messages written as far as the client's Receive Maximum and the write limit allow.
    void pump(session& s);
    // A QoS 1 or 2 message written now and held until it is answered; one too large for the client is dropped.
    void send_queued(session& s, connection& c, queued q);
    // False when the message is larger than the client takes, which counts as delivered.
    bool write_publish_to(session& s, connection& c, uint16_t id, const queued& q, bool dup);
    void send_packet(connection& c, std::string_view bytes);
    client_info info_of(const connection& c) const;
    void resend(session& s, connection& c);
    bool expired(const message& m) const;

    void end_session(session& s, bool publish_will);
    void fire_will(session& s);
    void detach(connection& c, std::string_view why);
    // A live connection to `s` ended because another connection, here or on another shard, takes the session.
    void take_over(session& s, bool clean);
    void sweep_sessions(int64_t now);
    void publish_sys(int64_t now);
    void mark() { m_dirty = true; }

    std::string encode_session(const session& s) const;
    bool decode_session(std::string_view in, session& s, std::vector<std::pair<std::string, sub_options>>& subs,
                        std::string& why);
    void install_session(std::unique_ptr<session> s, const std::vector<std::pair<std::string, sub_options>>& subs);

    broker_config m_cfg;
    broker_io& m_io;
    broker_hooks& m_hooks;

    std::unordered_map<uint64_t, std::unique_ptr<connection>> m_conns;
    // The connection conn_of() last answered with, which only disconnected() takes out of the table.
    connection* m_last_conn{nullptr};
    std::vector<uint64_t> m_held;
    std::unordered_map<std::string, std::unique_ptr<session>> m_sessions;
    // How many sessions each owner holds, so one filling the table is the one that gives way.
    std::unordered_map<std::string, size_t> m_owned;
    std::unordered_map<uint64_t, session*> m_by_key;
    uint64_t m_next_key{1};
    uint64_t m_next_generation{1};

    subscription_tree m_subs;
    retained_tree<const message> m_retained;
    size_t m_retained_bytes{0};

    broker_stats m_stats;
    int64_t m_started_ms{0};
    int64_t m_next_sys_ms{0};
    int64_t m_next_sweep_ms{0};
    bool m_dirty{false};
    // Sessions with a will waiting for its delay.
    std::set<std::pair<int64_t, uint64_t>> m_wills_due;
    // How many sessions subscribe to each filter.
    std::unordered_map<std::string, size_t> m_filter_refs;
};

}   // namespace socketley::mqtt
