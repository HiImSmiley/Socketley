#include "mqtt_broker.h"

#include <algorithm>
#include <random>

namespace socketley::mqtt
{

namespace
{

constexpr uint32_t never = 0xFFFFFFFFu;

uint8_t level_code(uint8_t level, uint8_t v5_code, uint8_t v3_code)
{
    return level == level_5 ? v5_code : v3_code;
}

std::string random_client_id()
{
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    static constexpr char digits[] = "0123456789abcdef";
    std::string id = "auto-";
    for (int i = 0; i < 16; ++i)
        id += digits[rng() & 15];
    return id;
}

message message_of(const will_message& w, std::string_view client, int64_t now)
{
    message m;
    m.topic          = w.topic;
    m.payload        = w.payload;
    m.qos            = w.qos;
    m.retain         = w.retain;
    m.payload_format = w.props.payload_format;
    m.content_type   = w.props.content_type;
    m.response_topic = w.props.response_topic;
    m.correlation_data = w.props.correlation_data;
    m.user           = w.props.user;
    if (w.props.message_expiry)
        m.expires_ms = now + static_cast<int64_t>(*w.props.message_expiry) * 1000;
    m.from_client = std::string(client);
    return m;
}

}   // namespace

broker::broker(broker_config cfg, broker_io& io, broker_hooks& hooks)
    : m_cfg(std::move(cfg)), m_io(io), m_hooks(hooks)
{
    m_started_ms  = m_io.now_ms();
    m_next_sys_ms = m_started_ms;
}

broker::~broker() = default;

broker::connection* broker::conn_of(uint64_t id)
{
    // A delivery asks after the same connection from deliver, pump and the writer in turn.
    if (m_last_conn && m_last_conn->id == id)
        return m_last_conn;
    const auto it = m_conns.find(id);
    if (it == m_conns.end())
        return nullptr;
    m_last_conn = it->second.get();
    return m_last_conn;
}

broker::session* broker::session_of_key(uint64_t key)
{
    const auto it = m_by_key.find(key);
    return it == m_by_key.end() ? nullptr : it->second;
}

client_info broker::info_of(const connection& c) const
{
    client_info i;
    i.conn  = c.id;
    i.peer  = c.info.peer;
    i.level = c.level;
    if (c.s)
    {
        i.client_id = c.s->client_id;
        i.username  = c.s->username;
    }
    else if (c.pending)
    {
        i.client_id = c.pending->client_id;
        if (c.pending->username)
            i.username = *c.pending->username;
    }
    return i;
}

size_t broker::connected_count() const
{
    size_t n = 0;
    for (const auto& [k, s] : m_sessions)
        if (s->conn)
            ++n;
    return n;
}

size_t broker::queued_count() const
{
    size_t n = 0;
    for (const auto& [k, s] : m_sessions)
        n += s->queue.size();
    return n;
}

size_t broker::inflight_count() const
{
    size_t n = 0;
    for (const auto& [k, s] : m_sessions)
        n += s->out.size();
    return n;
}

bool broker::take_dirty()
{
    const bool d = m_dirty;
    m_dirty = false;
    return d;
}

bool broker::expired(const message& m) const
{
    return m.expires_ms && m.expires_ms <= m_io.now_ms();
}

void broker::send_packet(connection& c, std::string_view bytes)
{
    m_io.send(c.id, bytes);
}

void broker::send_ack(connection& c, packet_type type, uint16_t id, uint8_t code)
{
    // The one most sent, four bytes, written without a packet built for it.
    if (c.level < level_5 || code == reason::success)
    {
        const char b[4] = {static_cast<char>((static_cast<uint8_t>(type) << 4) |
                                             (type == packet_type::pubrel ? 0x02 : 0x00)),
                           2, static_cast<char>(id >> 8), static_cast<char>(id & 0xFF)};
        send_packet(c, std::string_view(b, sizeof b));
        return;
    }
    ack_packet a;
    a.type      = type;
    a.packet_id = id;
    a.reason    = code;
    std::string out;
    write_ack(out, c.level, a);
    send_packet(c, out);
}

// ── The transport's side ────────────────────────────────────────────────────

void broker::connected(uint64_t conn, conn_info info)
{
    auto c = std::make_unique<connection>();
    c->id         = conn;
    c->info       = std::move(info);
    c->opened_ms  = m_io.now_ms();
    c->last_rx_ms = c->opened_ms;
    c->generation = m_next_generation++;
    m_conns[conn] = std::move(c);
}

void broker::input(uint64_t conn, std::string_view bytes)
{
    connection* c = conn_of(conn);
    if (!c || c->ph == connection::phase::closing)
        return;
    // The common case, nothing kept from before: the packets are read where they arrived, and only what is left
    // of one at the end is copied.
    if (c->in.empty() && !c->busy && !c->processing)
    {
        c->processing = true;
        const size_t used = consume(*c, bytes);
        c->processing = false;
        if (c->ph != connection::phase::closing && used < bytes.size())
            c->in.assign(bytes.substr(used));
        return;
    }
    c->in.append(bytes);
    // What a script holds a connection up on is bounded: past this a client that will not wait is let go.
    if (c->in.size() - c->in_at > static_cast<size_t>(m_cfg.max_packet) * 4 + (16u << 20))
    {
        protocol_failure(*c, reason::quota_exceeded, "sent far more than is taken while it waits");
        return;
    }
    if (!c->busy && !c->processing)
        process(*c);
}

void broker::drained(uint64_t conn)
{
    if (connection* c = conn_of(conn); c && c->s && c->ph == connection::phase::open)
        pump(*c->s);
}

void broker::disconnected(uint64_t conn)
{
    const auto it = m_conns.find(conn);
    if (it == m_conns.end())
        return;
    detach(*it->second, it->second->sent_disconnect ? "disconnected by the broker" : "connection closed");
    if (m_last_conn == it->second.get())
        m_last_conn = nullptr;
    m_conns.erase(it);
}

void broker::process(connection& c)
{
    c.processing = true;
    c.in_at += consume(c, std::string_view(c.in).substr(c.in_at));
    // The handled front goes once it is half of what is kept, not on every call, which moved the rest each time.
    if (c.in_at >= c.in.size())
    {
        c.in.clear();
        c.in_at = 0;
    }
    else if (c.in_at > c.in.size() / 2)
    {
        c.in.erase(0, c.in_at);
        c.in_at = 0;
    }
    c.processing = false;
}

size_t broker::consume(connection& c, std::string_view in)
{
    // One clock read for all the packets that came together.
    const int64_t now = m_io.now_ms();
    size_t at = 0;
    while (!c.busy && c.ph != connection::phase::closing)
    {
        const std::string_view rest = in.substr(at);
        // The first byte already says whether a CONNECT is coming, so an HTTP request or noise is not waited out.
        if (c.ph == connection::phase::awaiting_connect && !rest.empty() &&
            static_cast<uint8_t>(rest[0]) != (static_cast<uint8_t>(packet_type::connect) << 4))
        {
            c.ph = connection::phase::closing;
            m_io.close(c.id);
            break;
        }
        frame f;
        const frame_status st = take_frame(rest, m_cfg.max_packet, f);
        if (st == frame_status::incomplete)
            break;
        if (st == frame_status::malformed)
        {
            protocol_failure(c, reason::malformed, "the bytes are no MQTT packet");
            break;
        }
        if (st == frame_status::too_large)
        {
            protocol_failure(c, reason::packet_too_large, "a packet larger than the broker takes");
            break;
        }
        c.last_rx_ms = now;
        // A publisher is held while the other shards cannot take more, its bytes waiting in its socket rather than its
        // messages being dropped on the way.
        const uint8_t qos = static_cast<uint8_t>((f.flags >> 1) & 3);
        if (m_cfg.sharded && f.type == packet_type::publish && c.ph == connection::phase::open &&
            !m_hooks.publish_room(qos, c.sent_to))
        {
            c.held_qos = qos;
            if (!c.held)
            {
                c.held = true;
                m_held.push_back(c.id);
                m_io.pause_reading(c.id, true);
            }
            break;
        }
        // The handler copies what it keeps, so the bytes may go once it returns.
        at += f.size;
        if (!handle(c, f))
            break;
    }
    return at;
}

bool broker::handle(connection& c, const frame& f)
{
    if (c.ph == connection::phase::awaiting_connect && f.type != packet_type::connect)
    {
        protocol_failure(c, reason::protocol_error, "the first packet is not CONNECT");
        return false;
    }
    refusal err;
    switch (f.type)
    {
        case packet_type::connect:     return on_connect(c, f);
        case packet_type::publish:     return on_publish(c, f);
        case packet_type::puback:
        case packet_type::pubrec:
        case packet_type::pubrel:
        case packet_type::pubcomp:     return on_ack(c, f);
        case packet_type::subscribe:   return on_subscribe(c, f);
        case packet_type::unsubscribe: return on_unsubscribe(c, f);
        case packet_type::pingreq:
        {
            if (!read_empty(f, err))
            {
                protocol_failure(c, err.code, err.why);
                return false;
            }
            std::string out;
            write_pingresp(out);
            send_packet(c, out);
            return true;
        }
        case packet_type::disconnect:  return on_disconnect(c, f);
        case packet_type::auth:
            protocol_failure(c, c.level == level_5 ? reason::protocol_error : reason::malformed,
                             "extended authentication is not offered");
            return false;
        default:
            protocol_failure(c, reason::protocol_error,
                             std::string("a client does not send ") + packet_name(f.type));
            return false;
    }
}

void broker::refuse_connect(connection& c, uint8_t level, uint8_t code)
{
    ++m_stats.connects_refused;
    connack_packet a;
    a.reason = code;
    std::string out;
    write_connack(out, level, a);
    send_packet(c, out);
    c.ph = connection::phase::closing;
    m_io.close(c.id);
}

void broker::protocol_failure(connection& c, uint8_t code, const std::string& why)
{
    ++m_stats.protocol_errors;
    if (c.ph == connection::phase::open && c.level == level_5)
    {
        disconnect_with(c, code, why);
        return;
    }
    c.ph = connection::phase::closing;
    m_io.close(c.id);
}

void broker::disconnect_with(connection& c, uint8_t code, const std::string& why)
{
    if (c.ph == connection::phase::closing)
        return;
    if (c.level == level_5 && c.ph == connection::phase::open)
    {
        disconnect_packet d;
        d.reason = code;
        if (!why.empty() && (!c.s || c.s->problem_info))
            d.props.reason_string = why;
        std::string out;
        write_disconnect(out, c.level, d);
        send_packet(c, out);
        c.sent_disconnect = true;
    }
    c.ph = connection::phase::closing;
    m_io.close(c.id);
}

// ── CONNECT ─────────────────────────────────────────────────────────────────

bool broker::on_connect(connection& c, const frame& f)
{
    if (c.ph != connection::phase::awaiting_connect)
    {
        protocol_failure(c, reason::protocol_error, "a second CONNECT");
        return false;
    }
    connect_packet p;
    refusal err;
    const auto refuse = [&](uint8_t level, uint8_t code) {
        refuse_connect(c, level, code);
        return false;
    };
    if (!read_connect(f, p, err))
    {
        if (err.code == reason::unsupported_version)
            return refuse(p.level == level_5 ? level_5 : level_311, reason::unsupported_version);
        if (err.code == reason::client_id_invalid)
            return refuse(p.level, reason::client_id_invalid);
        if (p.level == level_5)
            return refuse(level_5, err.code);
        c.ph = connection::phase::closing;
        m_io.close(c.id);
        return false;
    }
    c.level = p.level;
    if (p.props.auth_method)
        return refuse(p.level, reason::bad_auth_method);
    if (p.client_id.empty())
    {
        if (p.level == level_31 || (p.level == level_311 && !p.clean_start))
            return refuse(p.level, reason::client_id_invalid);
        p.client_id = random_client_id();
        p.props.assigned_client_id = p.client_id;
    }
    c.pending = std::make_unique<connect_packet>(std::move(p));
    c.ph      = connection::phase::authenticating;
    c.busy    = true;

    auth_ask ask;
    ask.conn      = c.id;
    ask.client_id = c.pending->client_id;
    ask.clean_start = c.pending->clean_start;
    ask.username  = c.pending->username;
    ask.password  = c.pending->password;
    ask.cert_cn   = c.info.cert_cn;
    ask.peer      = c.info.peer;
    ask.level     = c.level;
    const uint64_t id = c.id, gen = c.generation;
    m_hooks.authenticate(ask, [this, id, gen](auth_answer a) { finish_connect(id, gen, std::move(a)); });
    return true;
}

void broker::take_over(session& s, bool clean)
{
    connection* old = s.conn ? conn_of(s.conn) : nullptr;
    if (!old)
        return;
    ++m_stats.takeovers;
    // The old connection's will is sent unless the session goes on and its delay has not passed.
    if (s.will && (s.will_delay == 0 || clean))
        fire_will(s);
    else
        s.will.reset();
    old->no_will = true;
    disconnect_with(*old, reason::session_taken_over, "another connection took the session over");
    // The session stays for the connection taking it; the old one only lets go of it.
    const client_info info = info_of(*old);
    old->s  = nullptr;
    s.conn    = 0;
    s.gone_ms = m_io.now_ms();
    mark();
    m_hooks.on_disconnect(info, "taken over");
}

bool broker::lapsed(const session& s, int64_t now) const
{
    return !s.conn && s.expiry != never && now - s.gone_ms >= static_cast<int64_t>(s.expiry) * 1000;
}

bool broker::held_by_another(std::string_view client_id, std::string_view username) const
{
    const auto it = m_sessions.find(std::string(client_id));
    return it != m_sessions.end() && !lapsed(*it->second, m_io.now_ms()) && it->second->username != username;
}

void broker::finish_connect(uint64_t conn, uint64_t generation, auth_answer a)
{
    connection* c = conn_of(conn);
    if (!c || c->generation != generation || c->ph != connection::phase::authenticating)
        return;
    if (!c->pending)
        return;
    // Held here until the answer is sent, and gone with it.
    const std::unique_ptr<connect_packet> held = std::move(c->pending);
    connect_packet& p = *held;
    const auto refuse = [&](uint8_t code) {
        c->busy = false;
        refuse_connect(*c, c->level, code);
    };
    if (a.code != reason::success)
    {
        refuse(a.code);
        return;
    }
    const int64_t now = m_io.now_ms();
    auto it = m_sessions.find(p.client_id);
    if (it != m_sessions.end() && lapsed(*it->second, now))
    {
        ++m_stats.sessions_expired;
        end_session(*it->second, true);
        it = m_sessions.find(p.client_id);
    }
    // A session is its user's: another account, or a client with none, may neither end it, take it nor resume it.
    if (it != m_sessions.end() && it->second->username != a.username)
    {
        ++m_stats.takeovers_refused;
        refuse(reason::not_authorized);
        return;
    }
    if (it == m_sessions.end() && m_sessions.size() >= m_cfg.max_sessions)
    {
        refuse(c->level == level_5 ? reason::quota_exceeded : reason::server_unavailable);
        return;
    }
    if (it != m_sessions.end())
    {
        take_over(*it->second, p.clean_start);
        if (p.clean_start)
        {
            // A clean start ends the old session, and a will it still held for its delay goes with it.
            end_session(*it->second, true);
            it = m_sessions.end();
        }
        else
        {
            // A will waiting for its delay is not sent once a connection comes back to the session.
            m_wills_due.erase({it->second->will_due_ms, it->second->key});
            it->second->will.reset();
        }
    }
    const bool present = it != m_sessions.end();
    session* s = nullptr;
    if (present)
        s = it->second.get();
    else
    {
        auto fresh = std::make_unique<session>();
        fresh->key       = m_next_key++;
        fresh->client_id = p.client_id;
        s = fresh.get();
        m_by_key[s->key] = s;
        m_sessions[p.client_id] = std::move(fresh);
    }
    s->username     = a.username;
    s->level        = c->level;
    s->conn         = c->id;
    s->peer         = c->info.peer;
    s->receive_max  = p.props.receive_maximum.value_or(65535);
    s->max_packet   = p.props.maximum_packet_size.value_or(0);
    s->problem_info = p.props.request_problem_info.value_or(1) != 0;

    connack_packet ack;
    ack.session_present = present;
    uint32_t expiry = c->level == level_5 ? p.props.session_expiry.value_or(0) : (p.clean_start ? 0 : never);
    if (m_cfg.session_expiry_max != never && expiry > m_cfg.session_expiry_max)
    {
        expiry = m_cfg.session_expiry_max;
        if (c->level == level_5)
            ack.props.session_expiry = expiry;
    }
    s->expiry = expiry;
    s->will.reset();
    if (p.will)
    {
        s->will       = std::make_unique<message>(message_of(*p.will, s->client_id, now));
        s->will_delay = p.will->props.will_delay.value_or(0);
    }

    uint16_t keepalive = p.keepalive;
    // A 3.1.1 client cannot be told of a server keep alive, so its "none" is kept; one asking more than the
    // maximum is held to it either way.
    if (m_cfg.keepalive_max &&
        (keepalive > m_cfg.keepalive_max || (keepalive == 0 && c->level == level_5)))
    {
        keepalive = m_cfg.keepalive_max;
        if (c->level == level_5)
            ack.props.server_keepalive = keepalive;
    }
    c->keepalive = keepalive;
    c->s         = s;
    c->ph        = connection::phase::open;
    c->busy      = false;

    if (c->level == level_5)
    {
        ack.props.receive_maximum     = m_cfg.receive_maximum;
        ack.props.maximum_packet_size = m_cfg.max_packet;
        ack.props.topic_alias_maximum = m_cfg.topic_alias_maximum;
        if (p.props.assigned_client_id)
            ack.props.assigned_client_id = p.props.assigned_client_id;
    }
    std::string out;
    write_connack(out, c->level, ack);
    send_packet(*c, out);
    ++m_stats.connects;
    mark();
    m_hooks.on_connected(info_of(*c));
    if (present)
        resend(*s, *c);
    pump(*s);
    if (!c->processing && !c->busy)
        process(*c);
}

// ── PUBLISH from a client ───────────────────────────────────────────────────

bool broker::on_publish(connection& c, const frame& f)
{
    if (c.ph != connection::phase::open || !c.s)
    {
        protocol_failure(c, reason::protocol_error, "a PUBLISH before the connection is accepted");
        return false;
    }
    publish_packet p;
    refusal err;
    if (!read_publish(f, c.level, p, err))
    {
        protocol_failure(c, err.code, err.why);
        return false;
    }
    if (c.level == level_5)
    {
        if (!p.props.subscription_ids.empty())
        {
            protocol_failure(c, reason::protocol_error, "a client does not send a subscription identifier");
            return false;
        }
        if (p.props.topic_alias)
        {
            const uint16_t alias = *p.props.topic_alias;
            if (alias == 0 || alias > m_cfg.topic_alias_maximum)
            {
                protocol_failure(c, reason::topic_alias_invalid, "a topic alias past the maximum");
                return false;
            }
            if (p.topic.empty())
            {
                if (alias > c.aliases.size() || c.aliases[alias - 1].empty())
                {
                    protocol_failure(c, reason::protocol_error, "a topic alias that was never set");
                    return false;
                }
                p.topic = c.aliases[alias - 1];
            }
            else
            {
                if (alias > c.aliases.size())
                    c.aliases.resize(alias);
                c.aliases[alias - 1] = p.topic;
            }
        }
        else if (p.topic.empty())
        {
            protocol_failure(c, reason::protocol_error, "a PUBLISH without a topic or an alias");
            return false;
        }
    }
    session& s = *c.s;
    ++m_stats.received[p.qos];
    const auto ack = [&](uint8_t code) {
        if (p.qos == 0)
            return;
        send_ack(c, p.qos == 1 ? packet_type::puback : packet_type::pubrec, p.packet_id, code);
        if (p.qos == 2 && (c.level < level_5 || code < 0x80))
        {
            s.incoming_qos2.insert(p.packet_id);
            mark();
        }
    };
    if (p.qos == 2 && s.incoming_qos2.contains(p.packet_id))
    {
        // A repeat of one already taken: answered again, delivered once.
        ack(reason::success);
        return true;
    }
    if (p.qos > 0 && s.incoming_qos2.size() + c.incoming_pending >= m_cfg.receive_maximum)
    {
        protocol_failure(c, reason::receive_max_exceeded, "more unanswered messages than the Receive Maximum");
        return false;
    }
    if (p.props.payload_format.value_or(0) == 1 && !valid_utf8(p.payload))
    {
        if (p.qos == 0)
        {
            protocol_failure(c, reason::payload_format_invalid, "a payload said to be UTF-8 that is not");
            return false;
        }
        ack(reason::payload_format_invalid);
        return true;
    }
    if (p.topic.front() == '$' || !m_hooks.may_write(s.username, s.client_id, p.topic))
    {
        ++m_stats.denied_publish;
        ack(reason::not_authorized);
        return true;
    }
    auto m = std::make_shared<message>();
    m->topic          = std::move(p.topic);
    m->payload        = std::move(p.payload);
    m->qos            = p.qos;
    m->retain         = p.retain;
    m->payload_format = p.props.payload_format;
    m->content_type   = std::move(p.props.content_type);
    m->response_topic = std::move(p.props.response_topic);
    m->correlation_data = std::move(p.props.correlation_data);
    m->user           = std::move(p.props.user);
    if (p.props.message_expiry)
        m->expires_ms = m_io.now_ms() + static_cast<int64_t>(*p.props.message_expiry) * 1000;
    m->from_client = s.client_id;

    const uint64_t id = c.id, gen = c.generation;
    const uint8_t qos = p.qos, level = c.level;
    const uint16_t packet_id = p.packet_id;
    if (!m_hooks.hooks_publish())
    {
        finish_publish(id, gen, qos, packet_id, level, {}, std::move(m));
        return true;
    }
    c.busy = true;
    ++c.incoming_pending;
    message_ptr held = m;
    m_hooks.on_publish(info_of(c), held, [this, id, gen, qos, packet_id, level, held](publish_verdict v) {
        finish_publish(id, gen, qos, packet_id, level, std::move(v), held);
    });
    return true;
}

void broker::finish_publish(uint64_t conn, uint64_t generation, uint8_t qos, uint16_t id, uint8_t level,
                            publish_verdict v, message_ptr m)
{
    connection* c = conn_of(conn);
    const bool live = c && c->generation == generation;
    if (live && c->busy)
    {
        c->busy = false;
        if (c->incoming_pending)
            --c->incoming_pending;
    }
    uint8_t code = reason::success;
    if (!v.allow)
    {
        ++m_stats.denied_publish;
        code = reason::not_authorized;
    }
    else
    {
        message_ptr out = v.replace ? v.replace : m;
        if (v.replace)
        {
            // A script may rename, never send to a wildcard or to '$'.
            if (!valid_topic(out->topic) || out->topic.front() == '$')
                out = m;
        }
        bool retained_ok = true;
        if (out->retain)
            retained_ok = store_retained(out, true);
        // Only a 5.0 publisher waiting for an answer is told nobody heard it, so only then is it asked.
        const bool heard = !(qos > 0 && level == level_5) || m_subs.any_match(out->topic) ||
                           m_hooks.heard_elsewhere(out->topic);
        route(out, true);
        if (live && m_cfg.sharded)
            c->sent_to = m_hooks.shards_reached();
        if (!retained_ok)
            code = reason::quota_exceeded;
        else if (!heard)
            code = reason::no_matching_subscribers;
    }
    if (!live || c->ph != connection::phase::open)
        return;
    if (qos > 0)
    {
        send_ack(*c, qos == 1 ? packet_type::puback : packet_type::pubrec, id, level == level_5 ? code : reason::success);
        if (qos == 2 && c->s && (level < level_5 || code < 0x80))
        {
            c->s->incoming_qos2.insert(id);
            mark();
        }
    }
    if (!c->processing && !c->busy)
        process(*c);
}

// ── Routing ─────────────────────────────────────────────────────────────────

bool broker::store_retained(const message_ptr& m, bool notify)
{
    const auto old = m_retained.get(m->topic);
    const size_t old_size = old ? old->topic.size() + old->payload.size() : 0;
    // A '$' topic holds the broker's own figures, made again each interval and so no change a snapshot keeps.
    const bool kept = !m->topic.starts_with('$');
    if (m->payload.empty())
    {
        if (old)
        {
            m_retained.set(m->topic, nullptr);
            m_retained_bytes -= old_size;
            if (kept)
                mark();
            if (notify)
                m_hooks.retained_changed(m->topic, nullptr);
        }
        return true;
    }
    const size_t size = m->topic.size() + m->payload.size();
    if (m_retained_bytes - old_size + size > m_cfg.retained_max_bytes)
    {
        ++m_stats.retained_refused;
        return false;
    }
    m_retained.set(m->topic, m);
    m_retained_bytes = m_retained_bytes - old_size + size;
    if (kept)
        mark();
    if (notify)
        m_hooks.retained_changed(m->topic, m);
    return true;
}

void broker::filter_ref(const std::string& filter, bool add)
{
    if (add)
    {
        if (++m_filter_refs[filter] == 1)
            m_hooks.filter_added(filter);
        return;
    }
    const auto it = m_filter_refs.find(filter);
    if (it == m_filter_refs.end())
        return;
    if (--it->second == 0)
    {
        m_filter_refs.erase(it);
        m_hooks.filter_removed(filter);
    }
}

std::vector<std::string> broker::filters() const
{
    std::vector<std::string> out;
    out.reserve(m_filter_refs.size());
    for (const auto& [f, n] : m_filter_refs)
        out.push_back(f);
    return out;
}

void broker::room()
{
    if (m_held.empty())
        return;
    std::vector<uint64_t> held;
    held.swap(m_held);
    for (const uint64_t id : held)
    {
        connection* c = conn_of(id);
        if (!c || !c->held)
            continue;
        if (!m_hooks.publish_room(c->held_qos, c->sent_to))
        {
            m_held.push_back(id);
            continue;
        }
        c->held = false;
        // Its silence while it was held was not its own.
        c->last_rx_ms = m_io.now_ms();
        if (!c->busy && !c->processing)
            process(*c);
        // Read again only once what waited is taken, or a publisher held again at once would pile up its socket here.
        if (connection* again = conn_of(id); again && !again->held)
            m_io.pause_reading(id, false);
    }
}

void broker::deliver_remote(const message_ptr& m, const std::vector<std::string>& groups)
{
    if (m->retain)
        store_retained(m, false);
    route(m, false, &groups);
}

void broker::route(const message_ptr& m, bool notify, const std::vector<std::string>* groups)
{
    // The list is kept from one message to the next; a route begun inside another takes one of its own.
    std::vector<route_target> own;
    std::vector<route_target>& plain = m_routing ? own : m_route_scratch;
    const bool outer = !m_routing;
    m_routing = true;
    plain.clear();
    const uint64_t stamp = ++m_route_stamp;
    std::vector<std::pair<session*, sub_options>> shared;
    m_subs.match(
        m->topic,
        [&](uint64_t key, const sub_options& o) {
            session* s = session_of_key(key);
            if (!s || (o.no_local && s->client_id == m->from_client))
                return;
            if (s->route_stamp != stamp)
            {
                s->route_stamp = stamp;
                s->route_slot  = plain.size();
                plain.push_back({s, 0, false, {}});
            }
            route_target& a = plain[s->route_slot];
            a.qos = std::max(a.qos, std::min(m->qos, o.qos));
            a.retain = a.retain || (o.retain_as_published && m->retain);
            if (o.subscription_id)
                a.ids.push_back(o.subscription_id);
        },
        [&](std::string_view group_key, uint64_t key, const sub_options& o) {
            const bool mine = groups ? std::find(groups->begin(), groups->end(), group_key) != groups->end()
                                     : m_hooks.shared_here(group_key);
            if (mine)
                if (session* s = session_of_key(key))
                    shared.emplace_back(s, o);
        },
        [&](uint64_t key) {
            const session* s = session_of_key(key);
            return s && s->conn;
        });
    const bool checked = m_hooks.reads_checked();
    for (route_target& a : plain)
        if (!checked || m_hooks.may_read(a.s->username, a.s->client_id, m->topic))
            deliver(*a.s, m, a.qos, a.retain, std::move(a.ids));
    for (const auto& [s, o] : shared)
    {
        if (checked && !m_hooks.may_read(s->username, s->client_id, m->topic))
            continue;
        std::vector<uint32_t> ids;
        if (o.subscription_id)
            ids.push_back(o.subscription_id);
        deliver(*s, m, std::min(m->qos, o.qos), false, std::move(ids));
    }
    if (outer)
        m_routing = false;
    if (notify)
        m_hooks.accepted(m);
}

void broker::deliver(session& s, const message_ptr& m, uint8_t qos, bool retain_flag, std::vector<uint32_t> sub_ids)
{
    if (expired(*m))
    {
        ++m_stats.dropped_expired;
        return;
    }
    connection* c = s.conn ? conn_of(s.conn) : nullptr;
    if (c && c->ph != connection::phase::open)
        c = nullptr;
    queued q{m, qos, retain_flag, std::move(sub_ids)};
    if (qos == 0)
    {
        if (!c)
            return;
        if (m_io.backlog(c->id) > m_cfg.write_limit)
        {
            ++m_stats.dropped_slow;
            return;
        }
        if (write_publish_to(s, *c, 0, q, false))
            ++m_stats.sent[0];
        return;
    }
    mark();
    // Nothing waiting before it and room for it: sent now, without a turn through the queue.
    if (c && s.queue.empty() && s.out.size() < s.receive_max && !s.out.full() &&
        m_io.backlog(c->id) <= m_cfg.write_limit)
    {
        send_queued(s, *c, std::move(q));
        return;
    }
    if (s.queue.size() >= m_cfg.session_queue)
    {
        s.queue.pop_front();
        ++m_stats.dropped_queue;
    }
    s.queue.push_back(std::move(q));
    if (c)
        pump(s);
}

void broker::send_queued(session& s, connection& c, queued q)
{
    const uint16_t id = s.out.next_id();
    if (!write_publish_to(s, c, id, q, false))
        return;
    ++m_stats.sent[q.qos];
    inflight f;
    f.seq  = s.next_seq++;
    f.st   = q.qos == 1 ? inflight::state::await_puback : inflight::state::await_pubrec;
    f.item = std::move(q);
    s.out.add(std::move(f));
}

void broker::pump(session& s)
{
    connection* c = s.conn ? conn_of(s.conn) : nullptr;
    if (!c || c->ph != connection::phase::open)
        return;
    while (!s.queue.empty() && s.out.size() < s.receive_max && m_io.backlog(c->id) <= m_cfg.write_limit)
    {
        queued q = std::move(s.queue.front());
        s.queue.pop_front();
        mark();
        if (expired(*q.msg))
        {
            ++m_stats.dropped_expired;
            continue;
        }
        if (s.out.full())
        {
            s.queue.push_front(std::move(q));
            break;
        }
        send_queued(s, *c, std::move(q));
    }
}

bool broker::write_publish_to(session& s, connection& c, uint16_t id, const queued& q, bool dup)
{
    const message& m = *q.msg;
    publish_parts p;
    p.dup       = dup && q.qos > 0;
    p.qos       = q.qos;
    p.retain    = q.retain_flag;
    p.topic     = m.topic;
    p.packet_id = id;
    p.payload   = m.payload;
    if (c.level == level_5)
    {
        // In the order the specification lists them, as put_properties writes a packet's own.
        std::string& pr = m_props_scratch;
        pr.clear();
        if (m.payload_format)
            put_prop_byte(pr, 0x01, *m.payload_format);
        if (m.expires_ms)
        {
            const int64_t left = m.expires_ms - m_io.now_ms();
            put_prop_u32(pr, 0x02, static_cast<uint32_t>(std::max<int64_t>(1, (left + 999) / 1000)));
        }
        if (m.content_type)
            put_prop_str(pr, 0x03, *m.content_type);
        if (m.response_topic)
            put_prop_str(pr, 0x08, *m.response_topic);
        if (m.correlation_data)
            put_prop_str(pr, 0x09, *m.correlation_data);
        for (const uint32_t sid : q.sub_ids)
            put_prop_varint(pr, 0x0B, sid);
        for (const auto& [k, v] : m.user)
            put_prop_pair(pr, 0x26, k, v);
        p.props = pr;
    }
    if (s.max_packet && publish_parts_size(c.level, p) > s.max_packet)
    {
        ++m_stats.dropped_too_large;
        return false;
    }
    std::string& out = m_out_scratch;
    out.clear();
    // A large payload is sent from the message itself by every subscriber, as a cache sends a PUBLISH from one
    // segment; below this a copy costs less than the slice that would carry it.
    if (m.payload.size() >= shared_payload_bytes)
    {
        write_publish_head(out, c.level, p);
        m_io.send_parts(c.id, out, std::shared_ptr<const std::string>(q.msg, &m.payload), m.payload);
        return true;
    }
    write_publish_parts(out, c.level, p);
    send_packet(c, out);
    return true;
}

void broker::resend(session& s, connection& c)
{
    // Oldest first, which is the order they were sent in.
    s.out.each([&](uint16_t id, const inflight& f) {
        if (f.st == inflight::state::await_pubcomp)
            send_ack(c, packet_type::pubrel, id, reason::success);
        else
            write_publish_to(s, c, id, f.item, true);
    });
}

void broker::send_retained(session& s, const std::string& filter, const sub_options& o)
{
    std::vector<message_ptr> found;
    m_retained.match(filter, [&](const std::shared_ptr<const message>& m) { found.push_back(m); });
    for (const auto& m : found)
    {
        if (expired(*m) || !m_hooks.may_read(s.username, s.client_id, m->topic))
            continue;
        std::vector<uint32_t> ids;
        if (o.subscription_id)
            ids.push_back(o.subscription_id);
        deliver(s, m, std::min(m->qos, o.qos), true, std::move(ids));
    }
}

// ── Acknowledgements ────────────────────────────────────────────────────────

bool broker::on_ack(connection& c, const frame& f)
{
    if (c.ph != connection::phase::open || !c.s)
    {
        protocol_failure(c, reason::protocol_error, "an acknowledgement before the connection is accepted");
        return false;
    }
    ack_packet a;
    refusal err;
    if (!read_ack(f, c.level, a, err))
    {
        protocol_failure(c, err.code, err.why);
        return false;
    }
    session& s = *c.s;
    switch (a.type)
    {
        case packet_type::puback:
        {
            const inflight* f = s.out.find(a.packet_id);
            if (f && f->st == inflight::state::await_puback)
            {
                s.out.erase(a.packet_id);
                mark();
                pump(s);
            }
            return true;
        }
        case packet_type::pubrec:
        {
            inflight* f = s.out.find(a.packet_id);
            if (!f || f->st == inflight::state::await_puback)
            {
                send_ack(c, packet_type::pubrel, a.packet_id, reason::packet_id_not_found);
                return true;
            }
            if (a.reason >= 0x80)
            {
                // The client refused it; the exchange ends here and its identifier is free.
                s.out.erase(a.packet_id);
                mark();
                pump(s);
                return true;
            }
            f->st = inflight::state::await_pubcomp;
            mark();
            send_ack(c, packet_type::pubrel, a.packet_id, reason::success);
            return true;
        }
        case packet_type::pubcomp:
        {
            const inflight* f = s.out.find(a.packet_id);
            if (f && f->st == inflight::state::await_pubcomp)
            {
                s.out.erase(a.packet_id);
                mark();
                pump(s);
            }
            return true;
        }
        case packet_type::pubrel:
        {
            uint8_t code = reason::success;
            if (s.incoming_qos2.erase(a.packet_id))
                mark();
            else
                code = reason::packet_id_not_found;
            send_ack(c, packet_type::pubcomp, a.packet_id, code);
            return true;
        }
        default:
            return true;
    }
}

// ── SUBSCRIBE and UNSUBSCRIBE ───────────────────────────────────────────────

bool broker::on_subscribe(connection& c, const frame& f)
{
    if (c.ph != connection::phase::open || !c.s)
    {
        protocol_failure(c, reason::protocol_error, "a SUBSCRIBE before the connection is accepted");
        return false;
    }
    auto st = std::make_shared<subscribe_state>();
    refusal err;
    if (!read_subscribe(f, c.level, st->p, err))
    {
        protocol_failure(c, err.code, err.why);
        return false;
    }
    for (const auto& e : st->p.entries)
    {
        std::string_view group, inner;
        if (split_shared(e.filter, group, inner) && e.no_local)
        {
            protocol_failure(c, reason::protocol_error, "No Local on a shared subscription");
            return false;
        }
    }
    st->fresh.assign(st->p.entries.size(), false);
    c.busy = true;
    subscribe_step(c.id, c.generation, std::move(st), 0, false);
    return true;
}

void broker::subscribe_step(uint64_t conn, uint64_t generation, std::shared_ptr<subscribe_state> st, size_t i,
                            bool script_said_yes)
{
    connection* c = conn_of(conn);
    if (!c || c->generation != generation || c->ph != connection::phase::open || !c->s)
        return;
    session& s = *c->s;
    const subscribe_packet& p = st->p;
    const uint32_t sub_id = p.props.subscription_ids.empty() ? 0 : p.props.subscription_ids.front();
    for (; i < p.entries.size(); ++i, script_said_yes = false)
    {
        const subscription& e = p.entries[i];
        std::string_view group, inner = e.filter;
        const bool is_shared = split_shared(e.filter, group, inner);
        if (!valid_filter(e.filter))
        {
            st->codes.push_back(level_code(c->level, reason::topic_filter_invalid, 0x80));
            continue;
        }
        if (!m_hooks.may_subscribe(s.username, s.client_id, inner))
        {
            ++m_stats.denied_subscribe;
            st->codes.push_back(level_code(c->level, reason::not_authorized, 0x80));
            continue;
        }
        if (m_hooks.hooks_subscribe() && !script_said_yes)
        {
            // The script is asked once per filter; its answer resumes the walk at this entry.
            m_hooks.on_subscribe(info_of(*c), e.filter, e.qos, [this, conn, generation, st, i](bool allow) {
                connection* cc = conn_of(conn);
                if (!cc || cc->generation != generation)
                    return;
                if (!allow)
                {
                    ++m_stats.denied_subscribe;
                    st->codes.push_back(level_code(cc->level, reason::not_authorized, 0x80));
                    subscribe_step(conn, generation, st, i + 1, false);
                    return;
                }
                subscribe_step(conn, generation, st, i, true);
            });
            return;
        }
        sub_options o;
        o.qos                 = e.qos;
        o.no_local            = e.no_local;
        o.retain_as_published = e.retain_as_published;
        o.retain_handling     = e.retain_handling;
        o.subscription_id     = sub_id;
        st->fresh[i] = !s.subs.contains(e.filter);
        if (st->fresh[i])
            filter_ref(e.filter, true);
        s.subs[e.filter] = o;
        m_subs.add(inner, is_shared ? group : std::string_view{}, s.key, o);
        mark();
        st->codes.push_back(e.qos);
    }
    suback_packet ack;
    ack.packet_id = p.packet_id;
    ack.reasons   = st->codes;
    std::string out;
    write_suback(out, c->level, ack);
    send_packet(*c, out);
    // Retained messages after the SUBACK, for every granted plain filter whose Retain Handling asks for them.
    for (size_t k = 0; k < p.entries.size(); ++k)
    {
        const subscription& e = p.entries[k];
        if (ack.reasons[k] >= 0x80 || e.retain_handling == 2 || (e.retain_handling == 1 && !st->fresh[k]))
            continue;
        std::string_view group, inner = e.filter;
        if (split_shared(e.filter, group, inner))
            continue;
        if (const auto it = s.subs.find(e.filter); it != s.subs.end())
            send_retained(s, std::string(inner), it->second);
    }
    c->busy = false;
    if (!c->processing)
        process(*c);
}

bool broker::on_unsubscribe(connection& c, const frame& f)
{
    if (c.ph != connection::phase::open || !c.s)
    {
        protocol_failure(c, reason::protocol_error, "an UNSUBSCRIBE before the connection is accepted");
        return false;
    }
    unsubscribe_packet p;
    refusal err;
    if (!read_unsubscribe(f, c.level, p, err))
    {
        protocol_failure(c, err.code, err.why);
        return false;
    }
    session& s = *c.s;
    suback_packet ack;
    ack.type      = packet_type::unsuback;
    ack.packet_id = p.packet_id;
    for (const auto& filter : p.filters)
    {
        std::string_view group, inner = filter;
        const bool is_shared = split_shared(filter, group, inner);
        const bool had = s.subs.erase(filter) > 0;
        if (had)
        {
            m_subs.remove(inner, is_shared ? group : std::string_view{}, s.key);
            filter_ref(filter, false);
            mark();
        }
        ack.reasons.push_back(had ? reason::success : reason::no_subscription_existed);
    }
    std::string out;
    write_suback(out, c.level, ack);
    send_packet(c, out);
    return true;
}

bool broker::on_disconnect(connection& c, const frame& f)
{
    disconnect_packet d;
    refusal err;
    if (!read_disconnect(f, c.level, d, err))
    {
        protocol_failure(c, err.code, err.why);
        return false;
    }
    if (c.s && d.props.session_expiry)
    {
        if (c.s->expiry == 0 && *d.props.session_expiry != 0)
        {
            protocol_failure(c, reason::protocol_error, "a session expiry set at DISCONNECT that CONNECT had as 0");
            return false;
        }
        uint32_t e = *d.props.session_expiry;
        if (m_cfg.session_expiry_max != never && e > m_cfg.session_expiry_max)
            e = m_cfg.session_expiry_max;
        c.s->expiry = e;
        mark();
    }
    c.no_will = d.reason != reason::disconnect_with_will;
    c.ph = connection::phase::closing;
    m_io.close(c.id);
    return false;
}

// ── Sessions ────────────────────────────────────────────────────────────────

void broker::fire_will(session& s)
{
    m_wills_due.erase({s.will_due_ms, s.key});
    if (!s.will)
        return;
    message m = std::move(*s.will);
    s.will.reset();
    mark();
    if (!valid_topic(m.topic) || m.topic.front() == '$' || !m_hooks.may_write(s.username, s.client_id, m.topic))
        return;
    ++m_stats.wills_sent;
    auto p = std::make_shared<const message>(std::move(m));
    if (p->retain)
        store_retained(p, true);
    route(p, true);
}

void broker::end_session(session& s, bool publish_will)
{
    if (publish_will)
        fire_will(s);
    m_wills_due.erase({s.will_due_ms, s.key});
    for (const auto& [filter, o] : s.subs)
    {
        std::string_view group, inner = filter;
        const bool is_shared = split_shared(filter, group, inner);
        m_subs.remove(inner, is_shared ? group : std::string_view{}, s.key);
        filter_ref(filter, false);
    }
    if (s.conn)
        if (connection* c = conn_of(s.conn))
            c->s = nullptr;
    m_by_key.erase(s.key);
    const std::string id = s.client_id;
    m_sessions.erase(id);
    mark();
}

void broker::detach(connection& c, std::string_view why)
{
    if (!c.s)
        return;
    session& s = *c.s;
    c.s = nullptr;
    if (s.conn != c.id)
        return;
    s.conn    = 0;
    s.gone_ms = m_io.now_ms();
    mark();
    client_info info;
    info.conn      = c.id;
    info.client_id = s.client_id;
    info.username  = s.username;
    info.peer      = c.info.peer;
    info.level     = c.level;
    m_hooks.on_disconnect(info, why);
    if (c.no_will)
        s.will.reset();
    if (s.expiry == 0)
    {
        end_session(s, true);
        return;
    }
    if (s.will)
    {
        const uint64_t delay_s = std::min<uint64_t>(s.will_delay, s.expiry);
        if (delay_s == 0)
            fire_will(s);
        else
        {
            s.will_due_ms = s.gone_ms + static_cast<int64_t>(delay_s) * 1000;
            m_wills_due.insert({s.will_due_ms, s.key});
        }
    }
}

void broker::sweep_sessions(int64_t now)
{
    std::vector<std::string> gone;
    for (auto& [id, s] : m_sessions)
    {
        // Messages that expired while waiting go too, so a long-offline session does not hold them.
        const size_t before = s->queue.size();
        s->queue.remove_if([&](const queued& q) { return q.msg->expires_ms && q.msg->expires_ms <= now; });
        if (s->queue.size() != before)
        {
            m_stats.dropped_expired += before - s->queue.size();
            mark();
        }
        if (lapsed(*s, now))
            gone.push_back(id);
    }
    for (const auto& id : gone)
        if (const auto it = m_sessions.find(id); it != m_sessions.end())
        {
            ++m_stats.sessions_expired;
            end_session(*it->second, true);
        }
    std::vector<std::string> stale;
    m_retained.each([&](const std::shared_ptr<const message>& m) {
        if (m->expires_ms && m->expires_ms <= now)
            stale.push_back(m->topic);
    });
    for (const auto& t : stale)
        if (const auto old = m_retained.get(t))
        {
            m_retained.set(t, nullptr);
            m_retained_bytes -= old->topic.size() + old->payload.size();
            mark();
        }
}

void broker::tick()
{
    const int64_t now = m_io.now_ms();
    std::vector<uint64_t> late, silent;
    for (auto& [id, c] : m_conns)
    {
        if ((c->ph == connection::phase::awaiting_connect || c->ph == connection::phase::authenticating) &&
            now - c->opened_ms > m_cfg.connect_timeout_ms)
            late.push_back(id);
        // A held connection is not read, so its silence is this broker's and not its own.
        else if (c->ph == connection::phase::open && c->keepalive && !c->held &&
                 now - c->last_rx_ms > static_cast<int64_t>(c->keepalive) * 1500)
            silent.push_back(id);
    }
    for (const uint64_t id : late)
        if (connection* c = conn_of(id))
        {
            c->ph = connection::phase::closing;
            m_io.close(id);
        }
    for (const uint64_t id : silent)
        if (connection* c = conn_of(id))
            disconnect_with(*c, reason::keepalive_timeout, "nothing came within one and a half keep alive intervals");
    while (!m_wills_due.empty() && m_wills_due.begin()->first <= now)
    {
        const uint64_t key = m_wills_due.begin()->second;
        m_wills_due.erase(m_wills_due.begin());
        if (session* s = session_of_key(key))
            fire_will(*s);
    }
    if (now >= m_next_sweep_ms)
    {
        m_next_sweep_ms = now + 1000;
        sweep_sessions(now);
    }
    if (m_cfg.sys_interval_s && now >= m_next_sys_ms)
    {
        m_next_sys_ms = now + static_cast<int64_t>(m_cfg.sys_interval_s) * 1000;
        publish_sys(now);
    }
}

void broker::publish_sys(int64_t now)
{
    const auto put = [&](const char* name, const std::string& value) {
        auto m = std::make_shared<message>();
        m->topic   = "$SYS/broker/" + m_cfg.sys_prefix + name;
        m->payload = value;
        m->retain  = true;
        // A shard's own figures go to the others like any retained message, under its own prefix.
        const bool notify = !m_cfg.sys_prefix.empty();
        store_retained(m, notify);
        route(m, notify);
    };
    uint64_t received = m_stats.received[0] + m_stats.received[1] + m_stats.received[2];
    uint64_t sent = m_stats.sent[0] + m_stats.sent[1] + m_stats.sent[2];
    put("version", "socketley " + m_cfg.version);
    put("uptime", std::to_string((now - m_started_ms) / 1000) + " seconds");
    put("clients/connected", std::to_string(connected_count()));
    put("clients/disconnected", std::to_string(m_sessions.size() - connected_count()));
    put("clients/total", std::to_string(m_sessions.size()));
    put("messages/received", std::to_string(received));
    put("messages/sent", std::to_string(sent));
    put("messages/dropped",
        std::to_string(m_stats.dropped_slow + m_stats.dropped_queue + m_stats.dropped_expired +
                       m_stats.dropped_too_large));
    put("subscriptions/count", std::to_string(m_subs.size()));
    put("retained messages/count", std::to_string(m_retained.size()));
}

// ── From inside ─────────────────────────────────────────────────────────────

void broker::publish(message m, bool notify)
{
    if (!valid_topic(m.topic))
        return;
    auto p = std::make_shared<const message>(std::move(m));
    if (p->retain)
        store_retained(p, notify);
    route(p, notify);
}

void broker::apply_retained(const std::string& topic, message_ptr m)
{
    if (!m)
    {
        auto blank = std::make_shared<message>();
        blank->topic = topic;
        store_retained(blank, false);
        return;
    }
    store_retained(m, false);
}

bool broker::kick(std::string_view client_id, bool end)
{
    const auto it = m_sessions.find(std::string(client_id));
    if (it == m_sessions.end())
        return false;
    session& s = *it->second;
    if (s.conn)
        if (connection* c = conn_of(s.conn))
        {
            c->no_will = true;
            disconnect_with(*c, reason::administrative_action, "disconnected by the operator");
            detach(*c, "kicked");
        }
    if (end)
        if (const auto again = m_sessions.find(std::string(client_id)); again != m_sessions.end())
            end_session(*again->second, false);
    return true;
}

bool broker::clear_retained(std::string_view topic)
{
    if (!m_retained.get(topic))
        return false;
    auto blank = std::make_shared<message>();
    blank->topic = std::string(topic);
    store_retained(blank, true);
    return true;
}

std::vector<broker::session_view> broker::sessions() const
{
    std::vector<session_view> out;
    const int64_t now = m_io.now_ms();
    for (const auto& [id, s] : m_sessions)
    {
        session_view v;
        v.client_id     = s->client_id;
        v.username      = s->username;
        v.connected     = s->conn != 0;
        v.level         = s->level;
        v.subscriptions = s->subs.size();
        v.queued        = s->queue.size();
        v.inflight      = s->out.size();
        v.peer          = s->peer;
        for (const auto& [f, o] : s->subs)
            v.filters.push_back(f);
        if (!s->conn && s->expiry != never)
            v.expires_in = std::max<int64_t>(0, (s->gone_ms + static_cast<int64_t>(s->expiry) * 1000 - now) / 1000);
        out.push_back(std::move(v));
    }
    std::sort(out.begin(), out.end(), [](const session_view& a, const session_view& b) {
        return a.client_id < b.client_id;
    });
    return out;
}

void broker::retained_each(std::string_view filter, const std::function<void(const message_ptr&)>& f) const
{
    m_retained.match(filter.empty() ? std::string_view("#") : filter, f);
}

}   // namespace socketley::mqtt
