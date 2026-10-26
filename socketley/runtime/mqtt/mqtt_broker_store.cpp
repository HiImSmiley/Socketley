// The broker's state as bytes: a snapshot of every session and retained message for a restart, and one session for
// the shard a client has just connected to.
#include "mqtt_broker.h"

#include "../../shared/util/byte_codec.h"

namespace socketley::mqtt
{

namespace
{

constexpr uint32_t snapshot_magic   = 0x5354514D;   // "MQTS"
constexpr uint8_t  snapshot_version = 1;
constexpr size_t   cap_field        = 1u << 16;
constexpr size_t   cap_payload      = 1u << 28;
constexpr uint32_t cap_count        = 1u << 24;

void put_opt(bytes::writer& w, const std::optional<std::string>& v)
{
    w.flag(v.has_value());
    if (v)
        w.bytes(*v);
}

bool get_opt(bytes::reader& r, std::optional<std::string>& v, size_t cap)
{
    bool has = false;
    if (!r.flag(has))
        return false;
    if (!has)
    {
        v.reset();
        return true;
    }
    std::string s;
    if (!r.bytes(s, cap))
        return false;
    v = std::move(s);
    return true;
}

void put_message(bytes::writer& w, const message& m)
{
    w.bytes(m.topic);
    w.bytes(m.payload);
    w.u8(m.qos);
    w.flag(m.retain);
    w.flag(m.payload_format.has_value());
    if (m.payload_format)
        w.u8(*m.payload_format);
    put_opt(w, m.content_type);
    put_opt(w, m.response_topic);
    put_opt(w, m.correlation_data);
    w.u32(static_cast<uint32_t>(m.user.size()));
    for (const auto& [k, v] : m.user)
    {
        w.bytes(k);
        w.bytes(v);
    }
    w.u64(static_cast<uint64_t>(m.expires_ms));
    w.bytes(m.from_client);
}

bool get_message(bytes::reader& r, message& m)
{
    uint32_t n = 0;
    uint64_t exp = 0;
    bool has_pf = false;
    if (!r.bytes(m.topic, cap_field) || !r.bytes(m.payload, cap_payload) || !r.u8(m.qos) || m.qos > 2 ||
        !r.flag(m.retain) || !r.flag(has_pf))
        return false;
    if (has_pf)
    {
        uint8_t pf = 0;
        if (!r.u8(pf))
            return false;
        m.payload_format = pf;
    }
    if (!get_opt(r, m.content_type, cap_field) || !get_opt(r, m.response_topic, cap_field) ||
        !get_opt(r, m.correlation_data, cap_field) || !r.u32(n) || n > cap_count)
        return false;
    m.user.clear();
    for (uint32_t i = 0; i < n; ++i)
    {
        std::string k, v;
        if (!r.bytes(k, cap_field) || !r.bytes(v, cap_field))
            return false;
        m.user.emplace_back(std::move(k), std::move(v));
    }
    if (!r.u64(exp) || !r.bytes(m.from_client, cap_field))
        return false;
    m.expires_ms = static_cast<int64_t>(exp);
    return true;
}

void put_ids(bytes::writer& w, const std::vector<uint32_t>& ids)
{
    w.u32(static_cast<uint32_t>(ids.size()));
    for (const uint32_t id : ids)
        w.u32(id);
}

bool get_ids(bytes::reader& r, std::vector<uint32_t>& ids)
{
    uint32_t n = 0;
    if (!r.u32(n) || n > cap_count)
        return false;
    ids.resize(n);
    for (auto& id : ids)
        if (!r.u32(id))
            return false;
    return true;
}

}   // namespace

std::string message_bytes(const message& m)
{
    bytes::writer w;
    put_message(w, m);
    return w.take();
}

bool message_from(std::string_view in, message& m)
{
    bytes::reader r(in);
    return get_message(r, m) && r.left() == 0;
}

std::string broker::encode_session(const session& s) const
{
    bytes::writer w;
    w.bytes(s.client_id);
    w.bytes(s.username);
    w.u8(s.level);
    w.u32(s.expiry);
    // A session connected now counts as gone from this moment, which is when whoever reads this takes it in.
    w.u64(static_cast<uint64_t>(s.conn ? m_io.now_ms() : s.gone_ms));
    w.flag(s.conn != 0);
    w.u32(s.out.next_id());
    w.u64(s.next_seq);
    w.u32(static_cast<uint32_t>(s.subs.size()));
    for (const auto& [filter, o] : s.subs)
    {
        w.bytes(filter);
        w.u8(o.qos);
        w.flag(o.no_local);
        w.flag(o.retain_as_published);
        w.u8(o.retain_handling);
        w.u32(o.subscription_id);
    }
    const auto put_queued = [&](const queued& q) {
        put_message(w, *q.msg);
        w.u8(q.qos);
        w.flag(q.retain_flag);
        put_ids(w, q.sub_ids);
    };
    w.u32(static_cast<uint32_t>(s.queue.size()));
    for (const auto& q : s.queue)
        put_queued(q);
    w.u32(static_cast<uint32_t>(s.out.size()));
    s.out.each([&](uint16_t id, const inflight& f) {
        w.u32(id);
        w.u64(f.seq);
        w.u8(static_cast<uint8_t>(f.st));
        put_queued(f.item);
    });
    w.u32(static_cast<uint32_t>(s.incoming_qos2.size()));
    for (const uint16_t id : s.incoming_qos2)
        w.u32(id);
    w.flag(s.will != nullptr);
    if (s.will)
        put_message(w, *s.will);
    w.u32(s.will_delay);
    w.u32(s.receive_max);
    w.u32(s.max_packet);
    w.flag(s.problem_info);
    return w.take();
}

bool broker::decode_session(std::string_view in, session& s,
                            std::vector<std::pair<std::string, sub_options>>& subs, std::string& why)
{
    bytes::reader r(in);
    uint64_t gone = 0;
    bool was_connected = false;
    uint32_t next_id = 0, n = 0;
    const auto bad = [&](const char* what) {
        why = std::string("a session's ") + what + " is cut off or out of range";
        return false;
    };
    if (!r.bytes(s.client_id, cap_field) || !r.bytes(s.username, cap_field) || !r.u8(s.level) ||
        !r.u32(s.expiry) || !r.u64(gone) || !r.flag(was_connected) || !r.u32(next_id) || next_id > 65535 ||
        !r.u64(s.next_seq) || !r.u32(n) || n > cap_count)
        return bad("head");
    s.gone_ms = static_cast<int64_t>(gone);
    s.conn    = 0;
    subs.clear();
    for (uint32_t i = 0; i < n; ++i)
    {
        std::string filter;
        sub_options o;
        if (!r.bytes(filter, cap_field) || !r.u8(o.qos) || o.qos > 2 || !r.flag(o.no_local) ||
            !r.flag(o.retain_as_published) || !r.u8(o.retain_handling) || o.retain_handling > 2 ||
            !r.u32(o.subscription_id) || !valid_filter(filter))
            return bad("subscription");
        subs.emplace_back(std::move(filter), o);
    }
    const auto get_queued = [&](queued& q) {
        auto m = std::make_shared<message>();
        if (!get_message(r, *m) || !r.u8(q.qos) || q.qos > 2 || !r.flag(q.retain_flag) || !get_ids(r, q.sub_ids))
            return false;
        q.msg = std::move(m);
        return true;
    };
    if (!r.u32(n) || n > cap_count)
        return bad("queue");
    s.queue.clear();
    for (uint32_t i = 0; i < n; ++i)
    {
        queued q;
        if (!get_queued(q))
            return bad("queued message");
        s.queue.push_back(std::move(q));
    }
    if (!r.u32(n) || n > 65535)
        return bad("unanswered messages");
    s.out.clear();
    // Put back in the order they were sent, which a snapshot of an older build did not keep.
    std::vector<std::pair<uint16_t, inflight>> sent;
    for (uint32_t i = 0; i < n; ++i)
    {
        uint32_t id = 0;
        uint8_t st = 0;
        inflight f;
        if (!r.u32(id) || id == 0 || id > 65535 || !r.u64(f.seq) || !r.u8(st) || st > 2 || !get_queued(f.item))
            return bad("unanswered message");
        f.st = static_cast<inflight::state>(st);
        sent.emplace_back(static_cast<uint16_t>(id), std::move(f));
    }
    std::sort(sent.begin(), sent.end(), [](const auto& a, const auto& b) { return a.second.seq < b.second.seq; });
    for (auto& [id, f] : sent)
        if (!s.out.restore(id, std::move(f)))
            return bad("unanswered message");
    s.out.set_next_id(static_cast<uint16_t>(next_id));
    if (!r.u32(n) || n > 65535)
        return bad("QoS 2 identifiers");
    s.incoming_qos2.clear();
    for (uint32_t i = 0; i < n; ++i)
    {
        uint32_t id = 0;
        if (!r.u32(id) || id == 0 || id > 65535)
            return bad("QoS 2 identifier");
        s.incoming_qos2.insert(static_cast<uint16_t>(id));
    }
    bool has_will = false;
    if (!r.flag(has_will))
        return bad("will");
    s.will.reset();
    if (has_will)
    {
        message m;
        if (!get_message(r, m))
            return bad("will");
        s.will = std::make_unique<message>(std::move(m));
    }
    uint32_t receive_max = 0;
    if (!r.u32(s.will_delay) || !r.u32(receive_max) || receive_max == 0 || receive_max > 65535 ||
        !r.u32(s.max_packet) || !r.flag(s.problem_info) || r.left() != 0)
        return bad("limits");
    s.receive_max = static_cast<uint16_t>(receive_max);
    // A will is owed only by a session that was connected when it was written: one already gone sent it or holds it
    // for its delay, which the gone time measures from.
    if (!was_connected && s.will && s.will_delay == 0)
        s.will.reset();
    return true;
}

void broker::install_session(std::unique_ptr<session> s, const std::vector<std::pair<std::string, sub_options>>& subs)
{
    if (const auto old = m_sessions.find(s->client_id); old != m_sessions.end())
        end_session(*old->second, false);
    s->key = m_next_key++;
    for (const auto& [filter, o] : subs)
    {
        std::string_view group, inner = filter;
        const bool is_shared = split_shared(filter, group, inner);
        s->subs[filter] = o;
        m_subs.add(inner, is_shared ? group : std::string_view{}, s->key, o);
        filter_ref(filter, true);
    }
    session* raw = s.get();
    m_by_key[raw->key] = raw;
    m_sessions[raw->client_id] = std::move(s);
    if (raw->will)
    {
        const uint64_t delay_s = std::min<uint64_t>(raw->will_delay, raw->expiry);
        raw->will_due_ms = raw->gone_ms + static_cast<int64_t>(delay_s) * 1000;
        m_wills_due.insert({raw->will_due_ms, raw->key});
    }
    mark();
}

std::string broker::snapshot() const
{
    bytes::writer w;
    w.u32(snapshot_magic);
    w.u8(snapshot_version);
    // The broker's own '$' figures are made again after a start, not read back stale.
    uint32_t n = 0;
    m_retained.each([&](const std::shared_ptr<const message>& m) { n += !m->topic.starts_with('$'); });
    w.u32(n);
    m_retained.each([&](const std::shared_ptr<const message>& m) {
        if (!m->topic.starts_with('$'))
            put_message(w, *m);
    });
    w.u32(static_cast<uint32_t>(m_sessions.size()));
    for (const auto& [id, s] : m_sessions)
        w.bytes(encode_session(*s));
    return w.take();
}

bool broker::restore(std::string_view in, std::string& why)
{
    bytes::reader r(in);
    uint32_t magic = 0, n = 0;
    uint8_t version = 0;
    if (!r.u32(magic) || magic != snapshot_magic || !r.u8(version) || version != snapshot_version)
    {
        why = "the file is no snapshot of an mqtt runtime";
        return false;
    }
    if (!r.u32(n) || n > cap_count)
    {
        why = "the retained messages are cut off";
        return false;
    }
    std::vector<std::shared_ptr<message>> retained;
    for (uint32_t i = 0; i < n; ++i)
    {
        auto m = std::make_shared<message>();
        if (!get_message(r, *m) || !valid_topic(m->topic))
        {
            why = "a retained message is cut off";
            return false;
        }
        // A snapshot written before the '$' figures were left out still holds the last process's.
        if (!m->topic.starts_with('$'))
            retained.push_back(std::move(m));
    }
    if (!r.u32(n) || n > cap_count)
    {
        why = "the sessions are cut off";
        return false;
    }
    std::vector<std::pair<std::unique_ptr<session>, std::vector<std::pair<std::string, sub_options>>>> sessions;
    for (uint32_t i = 0; i < n; ++i)
    {
        std::string_view one;
        if (!r.view(one, cap_payload))
        {
            why = "a session is cut off";
            return false;
        }
        auto s = std::make_unique<session>();
        std::vector<std::pair<std::string, sub_options>> subs;
        if (!decode_session(one, *s, subs, why))
            return false;
        sessions.emplace_back(std::move(s), std::move(subs));
    }
    if (r.left() != 0)
    {
        why = "bytes follow the last session";
        return false;
    }
    // Read whole before anything is taken in, so a broken file changes nothing.
    for (auto& m : retained)
        if (!m->payload.empty())
            store_retained(m, false);
    for (auto& [s, subs] : sessions)
        install_session(std::move(s), subs);
    // Sessions that end at their connection's end ended with the broker that wrote this, wills sent as they would
    // have been.
    std::vector<std::string> ended;
    for (const auto& [id, s] : m_sessions)
        if (s->expiry == 0)
            ended.push_back(id);
    for (const auto& id : ended)
        if (const auto it = m_sessions.find(id); it != m_sessions.end())
            end_session(*it->second, true);
    m_dirty = !ended.empty();
    return true;
}

std::string broker::surrender(std::string_view client_id, bool clean)
{
    const auto it = m_sessions.find(std::string(client_id));
    if (it == m_sessions.end())
        return {};
    session& s = *it->second;
    take_over(s, clean);
    if (clean)
    {
        end_session(s, true);
        return {};
    }
    // A delayed will is not sent: the connection that takes the session is the one that came back to it.
    m_wills_due.erase({s.will_due_ms, s.key});
    s.will.reset();
    std::string bytes = encode_session(s);
    end_session(s, false);
    return bytes;
}

void broker::adopt(std::string_view in)
{
    auto s = std::make_unique<session>();
    std::vector<std::pair<std::string, sub_options>> subs;
    std::string why;
    if (!decode_session(in, *s, subs, why))
        return;
    s->will.reset();
    install_session(std::move(s), subs);
}

}   // namespace socketley::mqtt
