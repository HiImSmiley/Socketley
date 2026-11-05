// The shards of one mqtt runtime as one broker: a session lives on the shard its client is connected to and moves
// there when it connects to another, a message goes to the shards that have a subscriber for it, each shared group
// is served by one shard per message, and the retained messages are the same on every shard.
//
// Every word between shards is a request on the channel to "<name>#<shard>", which the shard mesh carries directly
// and the daemon carries when it cannot; each is answered, a receipt where nothing more is owed.
//
// The words owed only a receipt -- deliveries, retained messages, interest -- wait here for each shard in the order
// made and go as batches, a bounded number of bytes in flight, so neither the channel's table nor the link's backlog is
// ever filled; a batch not receipted goes again with every one after it, and each frame is numbered so the shard takes
// it once and in order. A publisher at QoS 1 or 2 is held while a reachable shard cannot take more; a delivery is
// dropped, and counted, only past a harder bound or to a shard that does not answer, and at QoS 1 or 2 only to one that
// cannot be reached at all.
#include "mqtt_run.h"

#include <algorithm>
#include <chrono>

#include "mqtt_command.h"
#include "mqtt_instance.h"
#include "../../shared/ipc/shard_target.h"
#include "../../shared/runtime/runtime_manager.h"
#include "../../shared/runtime/stats_text.h"
#include "../../shared/util/byte_codec.h"

namespace socketley::mqtt
{

namespace
{

enum class sverb : uint8_t
{
    deliver       = 1,
    retained      = 2,
    interest_add  = 3,
    interest_del  = 4,
    interest_full = 5,
    interest_dump = 6,
    retained_dump = 7,
    claim         = 8,
    batch         = 9,
    client_add    = 10,
    client_del    = 11,
};

// A batch is cut at this, far below the 4 MiB a link's backlog holds before it gives up.
constexpr size_t batch_bytes = 128u << 10;
// What may be posted to one shard and not yet receipted: half of what the link's backlog holds, the rest for what
// else goes over it.
constexpr size_t flying_cap = 2u << 20;
// What may wait here for one shard: past the first a publisher is held, past the second a delivery at QoS 0 is
// dropped.
constexpr size_t hold_bytes = 4u << 20;
constexpr size_t drop_bytes = 8u << 20;
// A shard whose batches fail is asked again this often, and after this long counts as unreachable.
constexpr int64_t resend_ms      = 250;
constexpr int64_t unreachable_ms = 3000;
// A shard that answers none of its batches for this long holds publishers at QoS 0 no longer.
constexpr int64_t stall_ms = 1000;
// How long a retained topic's last change is remembered, to tell an older one crossing a newer from behind.
constexpr int64_t stamp_keep_us = 10'000'000;

constexpr int64_t claim_patience_ms = 3000;

std::string frame_of(sverb v, uint32_t from)
{
    // Written in place rather than moved out of a writer, which GCC 12 reads as a copy past the string's own buffer.
    std::string out(shard_prefix);
    out += static_cast<char>(v);
    socketley::bytes::append32(out, from);
    return out;
}

void put_list(socketley::bytes::writer& w, const std::vector<std::string>& list)
{
    w.u32(static_cast<uint32_t>(list.size()));
    for (const auto& s : list)
        w.bytes(s);
}

bool get_list(socketley::bytes::reader& r, std::vector<std::string>& list)
{
    uint32_t n = 0;
    if (!r.u32(n) || n > (1u << 24) || n > r.left() / 4)
        return false;
    list.resize(n);
    for (auto& s : list)
        if (!r.bytes(s, 1u << 16))
            return false;
    return true;
}

uint64_t claim_stamp(uint32_t shard)
{
    const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
    return (static_cast<uint64_t>(us) << 6) | (shard & 63);
}

}   // namespace

bool mqtt_run::sharded() const
{
    return m_owner.get_shards() > 1;
}

bool mqtt_run::post_shard(uint32_t to, std::string payload, uint64_t cookie)
{
    auto* mgr = m_owner.get_runtime_manager();
    if (mgr && mgr->requests().post(this, cookie, shard_target(m_owner.get_name(), to), payload,
                                    request_class::client))
        return true;
    ++m_shard_unreached;
    return false;
}

bool mqtt_run::queue_shard(uint32_t to, std::string_view frame, bool droppable)
{
    if (to >= m_squeue.size())
        return false;
    shard_queue& q = m_squeue[to];
    if (droppable && (q.waiting() >= drop_bytes || unreachable(q) || stalled(q)))
    {
        ++m_shard_dropped;
        return false;
    }
    socketley::bytes::writer w;
    w.bytes(frame);
    q.pending += w.take();
    if (q.waiting() >= batch_bytes)
        send_shard(to);
    return true;
}

bool mqtt_run::unreachable(const shard_queue& q) const
{
    return q.failing_since && now_ms() - q.failing_since >= unreachable_ms;
}

bool mqtt_run::stalled(const shard_queue& q) const
{
    return q.flying && now_ms() - q.heard_ms >= stall_ms;
}

void mqtt_run::send_shard(uint32_t to)
{
    shard_queue& q = m_squeue[to];
    auto* mgr = m_owner.get_runtime_manager();
    if (!mgr || (q.failing_since && now_ms() < q.retry_at))
        return;
    const uint32_t me = m_owner.get_shard_index();
    while (q.waiting() > 0 && q.flying < flying_cap)
    {
        // Whole frames up to the batch's size, at least one however large.
        const std::string_view rest = std::string_view(q.pending).substr(q.head);
        socketley::bytes::reader r(rest);
        size_t cut = 0;
        uint64_t count = 0;
        std::string_view f;
        while (r.view(f, rest.size()))
        {
            const size_t end = rest.size() - r.left();
            if (cut && end > batch_bytes)
                break;
            cut = end;
            ++count;
        }
        // Numbered by its first frame and the oldest one not yet receipted, so the shard takes each frame once and
        // in the order made whatever is sent again.
        std::string batch = frame_of(sverb::batch, me);
        socketley::bytes::append64(batch, m_shard_epoch);
        socketley::bytes::append64(batch, q.seq);
        const auto oldest = q.sent.empty() ? m_shard_batches.end() : m_shard_batches.find(q.sent.front());
        socketley::bytes::append64(batch, oldest == m_shard_batches.end() ? q.seq : oldest->second.first);
        const size_t head = batch.size();
        batch.append(rest.substr(0, cut));
        const uint64_t cookie = m_shard_cookie_base++;
        if (!mgr->requests().post(this, cookie, shard_target(m_owner.get_name(), to), batch, request_class::client))
            break;
        q.head += cut;
        if (!q.flying)
            q.heard_ms = now_ms();
        q.flying += cut;
        m_shard_batches.emplace(cookie, shard_batch{to, std::move(batch), head, q.seq});
        q.sent.push_back(cookie);
        q.seq += count;
    }
    // The front taken away once half of what is held has gone, not once a batch.
    if (q.head == q.pending.size())
    {
        q.pending.clear();
        q.head = 0;
    }
    else if (q.head > q.pending.size() / 2)
    {
        q.pending.erase(0, q.head);
        q.head = 0;
    }
}

void mqtt_run::send_shards()
{
    if (m_squeue.empty())
        return;
    for (uint32_t j = 0; j < m_squeue.size(); ++j)
        if (m_squeue[j].waiting() > 0)
            send_shard(j);
    // Every turn and not only on a receipt, since a shard that stalls lets publishers at QoS 0 go on by the clock.
    if (m_broker)
        m_broker->room();
}

bool mqtt_run::shard_receipt(uint64_t cookie, request_status st, std::string_view reply)
{
    const auto it = m_shard_batches.find(cookie);
    if (it == m_shard_batches.end())
        return cookie >= (1ull << 62);
    const uint32_t to = it->second.to;
    shard_queue& q = m_squeue[to];
    q.heard_ms = now_ms();
    const auto at = std::find(q.sent.begin(), q.sent.end(), cookie);
    // A shard that missed a frame before this batch took none of it, and says so.
    if (st == request_status::ok && reply.empty())
    {
        q.flying -= std::min(q.flying, it->second.frames.size() - it->second.head);
        m_shard_batches.erase(it);
        if (at != q.sent.end())
            q.sent.erase(at);
        q.failing_since = 0;
    }
    else
    {
        // This batch and every one posted after it go again, in the order they went and before what waits, since a
        // later one may not have been taken either; the shard skips what it already took by its number.
        if (!q.failing_since)
            q.failing_since = now_ms();
        q.retry_at = now_ms() + resend_ms;
        q.seq = it->second.first;
        std::string back;
        for (auto i = at; i != q.sent.end(); ++i)
        {
            const auto b = m_shard_batches.find(*i);
            if (b == m_shard_batches.end())
                continue;
            back.append(std::string_view(b->second.frames).substr(b->second.head));
            q.flying -= std::min(q.flying, b->second.frames.size() - b->second.head);
            m_shard_batches.erase(b);
        }
        q.sent.erase(at, q.sent.end());
        q.pending.insert(q.head, back);
        ++m_shard_resent;
    }
    send_shard(to);
    if (m_broker)
        m_broker->room();
    return true;
}

bool mqtt_run::publish_room(uint8_t qos, uint64_t sent_to) const
{
    for (uint32_t j = 0; j < m_squeue.size(); ++j)
    {
        const shard_queue& q = m_squeue[j];
        if (q.waiting() < hold_bytes || unreachable(q))
            continue;
        // QoS 1 and 2 wait for every shard, since what is answered may go anywhere next and past the second mark
        // would be dropped; QoS 0 may be dropped, so it waits only for a shard its last message went to that is
        // still answering, and the others take it meanwhile.
        if (qos > 0 || (!stalled(q) && (j >= 64 || (sent_to >> j & 1))))
            return false;
    }
    return true;
}

bool mqtt_run::heard_elsewhere(std::string_view topic)
{
    return m_remote.size() && m_remote.any_match(topic);
}

void mqtt_run::peer_filter(uint32_t from, const std::string& filter, bool add)
{
    peer& p = m_peers[from];
    std::string_view group, inner = filter;
    const bool is_shared = split_shared(filter, group, inner);
    if (add)
    {
        if (p.held[filter]++ == 0)
        {
            sub_options o;
            o.qos = 2;
            m_remote.add(inner, is_shared ? group : std::string_view{}, from, o);
        }
        return;
    }
    const auto it = p.held.find(filter);
    if (it == p.held.end())
        return;
    if (--it->second == 0)
    {
        p.held.erase(it);
        m_remote.remove(inner, is_shared ? group : std::string_view{}, from);
    }
}

void mqtt_run::forget_peer(uint32_t from)
{
    peer& p = m_peers[from];
    for (const auto& [filter, count] : p.held)
    {
        std::string_view group, inner = filter;
        const bool is_shared = split_shared(filter, group, inner);
        m_remote.remove(inner, is_shared ? group : std::string_view{}, from);
    }
    p.held.clear();
    p.clients.clear();
}

void mqtt_run::shards_start()
{
    if (!sharded())
        return;
    const uint32_t n = m_owner.get_shards();
    const uint32_t me = m_owner.get_shard_index();
    m_peers.resize(n);
    m_squeue.assign(n, {});
    m_shard_epoch = claim_stamp(me);
    m_assign.assign(n, {});
    m_sharing.assign(n, {});
    // What this shard holds, told whole, so a peer that knew an older picture of it replaces that one.
    const std::vector<std::string> mine = m_broker->filters();
    const std::vector<std::string> clients = m_broker->session_ids();
    for (uint32_t j = 0; j < n; ++j)
    {
        if (j == me)
            continue;
        std::string full = frame_of(sverb::interest_full, me);
        {
            socketley::bytes::writer w;
            put_list(w, mine);
            put_list(w, clients);
            full += w.take();
        }
        queue_shard(j, full, false);
        const uint64_t cookie = m_next_cookie++;
        m_dump_asks[cookie] = {j, false};
        post_shard(j, frame_of(sverb::interest_dump, me), cookie);
    }
    // A shard that starts with nothing retained asks shard 0, which alone writes them, and shard 0 the next one.
    if (m_broker->retained_count() == 0)
        ask_retained();
}

void mqtt_run::ask_retained()
{
    const uint32_t me = m_owner.get_shard_index();
    const uint32_t from = me == 0 ? 1 : 0;
    const uint64_t cookie = m_next_cookie++;
    m_dump_asks[cookie] = {from, true};
    m_retained_ask_ms = 0;
    if (post_shard(from, frame_of(sverb::retained_dump, me), cookie))
        return;
    m_dump_asks.erase(cookie);
    m_retained_ask_ms = now_ms() + resend_ms;
}

bool mqtt_run::dump_reply(uint64_t cookie, request_status st, std::string_view reply)
{
    const auto it = m_dump_asks.find(cookie);
    if (it == m_dump_asks.end())
        return false;
    const auto [from, retained] = it->second;
    m_dump_asks.erase(it);
    // Asked again until answered, since a shard that started first may ask one not yet started.
    if (st != request_status::ok && retained)
        m_retained_ask_ms = now_ms() + resend_ms;
    if (st != request_status::ok || from >= m_peers.size())
        return true;
    socketley::bytes::reader r(reply);
    if (retained)
    {
        uint32_t n = 0;
        if (!r.u32(n))
            return true;
        for (uint32_t i = 0; i < n; ++i)
        {
            std::string_view body;
            auto m = std::make_shared<message>();
            if (!r.view(body, 1u << 28) || !message_from(body, *m))
                return true;
            // A retained value that came live from another shard meanwhile is newer than this snapshot.
            if (!m_retained_stamps.contains(m->topic))
                m_broker->apply_retained(m->topic, m);
        }
        return true;
    }
    std::vector<std::string> list, clients;
    if (!get_list(r, list) || !get_list(r, clients))
        return true;
    forget_peer(from);
    m_peers[from].known = true;
    for (const auto& f : list)
        peer_filter(from, f, true);
    m_peers[from].clients.insert(clients.begin(), clients.end());
    return true;
}

// ── What this shard tells the others ────────────────────────────────────────

void mqtt_run::share_interest(uint8_t v, const std::vector<std::string>& filters)
{
    const uint32_t n = m_owner.get_shards();
    const uint32_t me = m_owner.get_shard_index();
    for (uint32_t j = 0; j < n; ++j)
    {
        if (j == me)
            continue;
        std::string f = frame_of(static_cast<sverb>(v), me);
        socketley::bytes::writer w;
        put_list(w, filters);
        f += w.take();
        queue_shard(j, f, false);
    }
}

void mqtt_run::filter_added(const std::string& filter)
{
    if (sharded() && !m_peers.empty())
        share_interest(static_cast<uint8_t>(sverb::interest_add), {filter});
}

void mqtt_run::filter_removed(const std::string& filter)
{
    if (sharded() && !m_peers.empty())
        share_interest(static_cast<uint8_t>(sverb::interest_del), {filter});
}

bool mqtt_run::shared_here(std::string_view key)
{
    if (!sharded() || m_peers.empty())
        return true;
    const uint32_t me = m_owner.get_shard_index();
    std::vector<uint32_t> candidates{me};
    for (uint32_t j = 0; j < m_peers.size(); ++j)
        if (j != me && m_peers[j].held.contains(std::string(key)))
            candidates.push_back(j);
    if (candidates.size() == 1)
        return true;
    uint64_t& turn = m_group_turn[std::string(key)];
    const uint32_t pick = candidates[turn++ % candidates.size()];
    if (pick == me)
        return true;
    m_assign[pick].push_back(std::string(key));
    return false;
}

void mqtt_run::share_message(const message_ptr& m)
{
    m_reached = 0;
    if (!sharded() || m_peers.empty())
        return;
    const uint32_t n = m_owner.get_shards();
    // The groups decided for another shard while the message was routed here, taken whole and left empty for the next.
    m_sharing.swap(m_assign);
    bool any = std::any_of(m_sharing.begin(), m_sharing.end(), [](const auto& a) { return !a.empty(); });
    m_plain.assign(n, 0);
    if (m_remote.size())
        m_remote.match(
            m->topic,
            [&](uint64_t j, const sub_options&) {
                if (j < n)
                {
                    m_plain[j] = 1;
                    any = true;
                }
            },
            [&](std::string_view key, uint64_t j, const sub_options&) {
                // A group with members here was decided by shared_here(), and one decided while routing stays so.
                if (j >= n || (m_broker && m_broker->has_filter(key)) ||
                    std::any_of(m_sharing.begin(), m_sharing.end(),
                                [&](const auto& a) { return std::find(a.begin(), a.end(), key) != a.end(); }))
                    return;
                m_sharing[j].emplace_back(key);
                any = true;
            });
    if (any)
    {
        const std::string body = message_bytes(*m);
        for (uint32_t j = 0; j < n; ++j)
        {
            if (!m_plain[j] && m_sharing[j].empty())
                continue;
            if (j < 64)
                m_reached |= uint64_t{1} << j;
            if (queue_deliver(j, m->qos, body, m_sharing[j]))
                ++m_shard_forwarded;
        }
    }
    for (auto& a : m_sharing)
        a.clear();
}

bool mqtt_run::queue_deliver(uint32_t to, uint8_t qos, std::string_view body, const std::vector<std::string>& groups)
{
    if (to >= m_squeue.size() || to == m_owner.get_shard_index())
        return false;
    shard_queue& q = m_squeue[to];
    // A shard that has gone quiet still has QoS 1 and 2 kept for it, since their publisher was answered and is held
    // at hold_bytes.
    if (q.waiting() >= drop_bytes || unreachable(q) || (qos == 0 && stalled(q)))
    {
        ++m_shard_dropped;
        return false;
    }
    // The frame queue_shard() would make, written where it waits rather than built and copied there.
    size_t size = shard_prefix.size() + 1 + 4 + 4 + body.size() + 4;
    for (const auto& g : groups)
        size += 4 + g.size();
    std::string& out = q.pending;
    socketley::bytes::append32(out, static_cast<uint32_t>(size));
    out.append(shard_prefix);
    out += static_cast<char>(sverb::deliver);
    socketley::bytes::append32(out, m_owner.get_shard_index());
    socketley::bytes::append32(out, static_cast<uint32_t>(body.size()));
    out.append(body);
    socketley::bytes::append32(out, static_cast<uint32_t>(groups.size()));
    for (const auto& g : groups)
    {
        socketley::bytes::append32(out, static_cast<uint32_t>(g.size()));
        out.append(g);
    }
    if (q.waiting() >= batch_bytes)
        send_shard(to);
    return true;
}

void mqtt_run::share_retained(const std::string& topic, const message_ptr& now)
{
    if (!sharded() || m_peers.empty())
        return;
    const uint32_t n = m_owner.get_shards();
    const uint32_t me = m_owner.get_shard_index();
    // Stamped, so two shards changing one topic at once settle on the later change.
    const uint64_t stamp = claim_stamp(me);
    m_retained_stamps[topic] = stamp;
    std::string body;
    {
        socketley::bytes::writer w;
        w.bytes(topic);
        w.u64(stamp);
        w.flag(now != nullptr);
        if (now)
            w.bytes(message_bytes(*now));
        body = w.take();
    }
    for (uint32_t j = 0; j < n; ++j)
        if (j != me)
            queue_shard(j, frame_of(sverb::retained, me) + body, false);
}

// ── Taking a session over from another shard ────────────────────────────────

void mqtt_run::claim(const auth_ask& ask, auth_answer a, std::function<void(auth_answer)> done)
{
    if (!sharded() || m_peers.empty())
    {
        done(std::move(a));
        return;
    }
    const uint32_t n = m_owner.get_shards();
    const uint32_t me = m_owner.get_shard_index();
    const uint64_t id = m_next_claim++;
    pending_claim& pc = m_claims[id];
    pc.ask        = ask;
    pc.answer     = std::move(a);
    pc.done       = std::move(done);
    pc.stamp      = claim_stamp(me);
    pc.started_ms = now_ms();
    ++m_claims_made;
    for (uint32_t j = 0; j < n; ++j)
    {
        // A clean start has nothing to take and only a session to end, so it asks only a shard that may hold one;
        // one let in meanwhile on another shard is settled by the stamps of the two when each hears of the other.
        if (j == me)
            continue;
        if (ask.clean_start && m_peers[j].known && !m_peers[j].clients.contains(ask.client_id))
        {
            pc.skipped = true;
            continue;
        }
        std::string f = frame_of(sverb::claim, me);
        socketley::bytes::writer w;
        w.bytes(ask.client_id);
        w.flag(ask.clean_start);
        w.u64(pc.stamp);
        w.bytes(pc.answer.username);
        f += w.take();
        const uint64_t cookie = m_next_cookie++;
        auto* mgr = m_owner.get_runtime_manager();
        if (mgr && mgr->requests().post(this, cookie, shard_target(m_owner.get_name(), j), f, request_class::client))
        {
            m_claim_cookies[cookie] = id;
            ++pc.waiting;
            ++m_claim_asks;
        }
        else
            ++m_shard_unreached;
    }
    if (pc.waiting == 0)
        finish_claim(id);
}

void mqtt_run::claim_reply(uint64_t cookie, request_status st, std::string_view reply)
{
    const auto it = m_claim_cookies.find(cookie);
    if (it == m_claim_cookies.end())
        return;
    const uint64_t id = it->second;
    m_claim_cookies.erase(it);
    const auto c = m_claims.find(id);
    if (c == m_claims.end())
        return;
    pending_claim& pc = c->second;
    if (st == request_status::ok)
    {
        socketley::bytes::reader r(reply);
        uint8_t status = 0;
        if (r.u8(status))
        {
            if (status == 2)
                pc.lost = true;
            else if (status == 3)
                pc.refused = true;
            else if (status == 1)
            {
                std::string s;
                if (r.bytes(s, 1u << 28) && pc.session.empty())
                    pc.session = std::move(s);
            }
        }
    }
    if (pc.waiting)
        --pc.waiting;
    if (pc.waiting == 0)
        finish_claim(id);
}

void mqtt_run::finish_claim(uint64_t id)
{
    const auto it = m_claims.find(id);
    if (it == m_claims.end())
        return;
    pending_claim pc = std::move(it->second);
    m_claims.erase(it);
    std::erase_if(m_claim_cookies, [&](const auto& kv) { return kv.second == id; });
    if (pc.refused)
    {
        ++m_claims_refused;
        pc.done({reason::not_authorized, {}});
        return;
    }
    if (pc.lost)
    {
        // A newer connection to the same client on another shard wins; this one is told to come back.
        ++m_claims_lost;
        pc.done({pc.ask.level == level_5 ? reason::session_taken_over : reason::server_unavailable, {}});
        return;
    }
    if (!pc.session.empty())
    {
        m_broker->adopt(pc.session);
        ++m_sessions_moved;
    }
    pc.answer.stamp = pc.stamp;
    pc.answer.asked = !pc.skipped;
    pc.done(std::move(pc.answer));
}

void mqtt_run::session_held(const std::string& client_id, const std::string& user, uint64_t stamp)
{
    if (!sharded() || m_peers.empty())
        return;
    const uint32_t me = m_owner.get_shard_index();
    std::string f = frame_of(sverb::client_add, me);
    socketley::bytes::append32(f, static_cast<uint32_t>(client_id.size()));
    f += client_id;
    socketley::bytes::append64(f, stamp);
    socketley::bytes::append32(f, static_cast<uint32_t>(user.size()));
    f += user;
    for (uint32_t j = 0; j < m_squeue.size(); ++j)
        if (j != me)
            queue_shard(j, f, false);
}

void mqtt_run::session_ended(const std::string& client_id)
{
    if (!sharded() || m_peers.empty())
        return;
    const uint32_t me = m_owner.get_shard_index();
    std::string f = frame_of(sverb::client_del, me);
    socketley::bytes::append32(f, static_cast<uint32_t>(client_id.size()));
    f += client_id;
    for (uint32_t j = 0; j < m_squeue.size(); ++j)
        if (j != me)
            queue_shard(j, f, false);
}

void mqtt_run::settle(const std::string& client_id, uint64_t stamp, const std::string& user)
{
    // Of two connections let in at once the later keeps the client, unless it came under another user without every
    // shard asked, in which case the session stays with the user that had it; an older word of a session that has
    // ended since loses to the one here either way.
    const auto yields = [&](uint64_t mine, const std::string& mine_user, bool asked) {
        return mine_user == user ? mine < stamp : mine > stamp && !asked;
    };
    for (auto& [id, pc] : m_claims)
        if (pc.ask.client_id == client_id && yields(pc.stamp, pc.answer.username, !pc.skipped))
            pc.lost = true;
    uint64_t mine = 0;
    std::string mine_user;
    bool asked = true;
    if (m_broker->session_held_as(client_id, mine, mine_user, asked) && yields(mine, mine_user, asked))
    {
        m_broker->surrender(client_id, true);
        ++m_claims_lost;
    }
}

void mqtt_run::sweep_claims(int64_t now)
{
    if (m_retained_ask_ms && now >= m_retained_ask_ms)
        ask_retained();
    if (!m_retained_stamps.empty())
    {
        const uint64_t us = claim_stamp(0) >> 6;
        std::erase_if(m_retained_stamps, [&](const auto& kv) { return us - (kv.second >> 6) > stamp_keep_us; });
    }
    std::vector<uint64_t> late;
    for (const auto& [id, pc] : m_claims)
        if (now - pc.started_ms > claim_patience_ms)
            late.push_back(id);
    for (const uint64_t id : late)
        finish_claim(id);
}

// ── What the others tell this shard ─────────────────────────────────────────

void mqtt_run::shard_request(uint64_t ticket, std::string_view payload)
{
    auto* mgr = m_owner.get_runtime_manager();
    if (!mgr)
        return;
    std::string reply;
    socketley::bytes::reader r(payload);
    uint8_t v = 0;
    uint32_t from = 0;
    // A batch: its words taken in the order they were made, each once, answered by one receipt.
    if (r.marker(shard_prefix) && r.u8(v) && v == static_cast<uint8_t>(sverb::batch) && r.u32(from))
    {
        uint64_t epoch = 0, first = 0, floor = 0;
        if (!r.u64(epoch) || !r.u64(first) || !r.u64(floor) || from >= m_peers.size())
        {
            mgr->requests().complete_deferred(ticket, request_status::ok, reply);
            return;
        }
        peer& p = m_peers[from];
        // A shard heard from afresh is taken up only from a batch with nothing before it still unreceipted.
        if (p.epoch != epoch && first == floor)
        {
            p.epoch = epoch;
            p.next  = first;
        }
        if (p.epoch != epoch || first > p.next)
        {
            reply = "gap";
            mgr->requests().complete_deferred(ticket, request_status::ok, reply);
            return;
        }
        std::string_view frame;
        for (uint64_t n = first; r.view(frame, payload.size()); ++n)
            if (n >= p.next)
            {
                std::string ignored;
                shard_frame(frame, ignored);
                p.next = n + 1;
            }
        mgr->requests().complete_deferred(ticket, request_status::ok, reply);
        return;
    }
    shard_frame(payload, reply);
    mgr->requests().complete_deferred(ticket, request_status::ok, reply);
}

void mqtt_run::shard_frame(std::string_view payload, std::string& reply)
{
    socketley::bytes::reader r(payload);
    uint8_t v = 0;
    uint32_t from = 0;
    if (!r.marker(shard_prefix) || !r.u8(v) || !r.u32(from) || from >= m_peers.size() ||
        from == m_owner.get_shard_index())
        return;
    ++m_shard_received;
    switch (static_cast<sverb>(v))
    {
        case sverb::deliver:
        {
            std::string_view body;
            std::vector<std::string> groups;
            auto m = std::make_shared<message>();
            if (r.view(body, 1u << 28) && get_list(r, groups) && message_from(body, *m))
            {
                message_ptr held = m;
                // Not tapped here: a tap is open on every shard, and the shard that accepted it tapped it.
                m_broker->deliver_remote(held, groups);
            }
            break;
        }
        case sverb::retained:
        {
            std::string topic;
            bool has = false;
            uint64_t stamp = 0;
            if (r.bytes(topic, 1u << 16) && r.u64(stamp) && r.flag(has))
            {
                uint64_t& seen = m_retained_stamps[topic];
                if (seen > stamp)
                    break;
                seen = stamp;
                if (!has)
                    m_broker->apply_retained(topic, nullptr);
                else
                {
                    std::string_view body;
                    auto m = std::make_shared<message>();
                    if (r.view(body, 1u << 28) && message_from(body, *m))
                        m_broker->apply_retained(topic, m);
                }
            }
            break;
        }
        case sverb::interest_full:
        {
            forget_peer(from);
            m_peers[from].known = true;
            std::vector<std::string> list, clients;
            if (get_list(r, list))
                for (const auto& f : list)
                    peer_filter(from, f, true);
            if (get_list(r, clients))
                m_peers[from].clients.insert(clients.begin(), clients.end());
            break;
        }
        case sverb::client_add:
        {
            std::string client, user;
            uint64_t stamp = 0;
            if (!r.bytes(client, 1u << 16) || !r.u64(stamp) || !r.bytes(user, 1u << 16))
                break;
            settle(client, stamp, user);
            m_peers[from].clients.insert(std::move(client));
            break;
        }
        case sverb::client_del:
        {
            std::string client;
            if (r.bytes(client, 1u << 16))
                m_peers[from].clients.erase(client);
            break;
        }
        case sverb::interest_add:
        case sverb::interest_del:
        {
            std::vector<std::string> list;
            if (get_list(r, list))
                for (const auto& f : list)
                    peer_filter(from, f, static_cast<sverb>(v) == sverb::interest_add);
            break;
        }
        case sverb::interest_dump:
        {
            // Answered with what this shard holds, which the asker takes as a full picture of it.
            socketley::bytes::writer w;
            put_list(w, m_broker->filters());
            put_list(w, m_broker->session_ids());
            reply = w.take();
            break;
        }
        case sverb::retained_dump:
        {
            socketley::bytes::writer w;
            std::vector<message_ptr> all;
            m_broker->retained_each("#", [&](const message_ptr& m) { all.push_back(m); });
            w.u32(static_cast<uint32_t>(all.size()));
            for (const auto& m : all)
                w.bytes(message_bytes(*m));
            reply = w.take();
            break;
        }
        case sverb::claim:
        {
            std::string client;
            bool clean = false;
            uint64_t stamp = 0;
            std::string user;
            if (!r.bytes(client, 1u << 16) || !r.flag(clean) || !r.u64(stamp) || !r.bytes(user, 1u << 16))
                break;
            socketley::bytes::writer w;
            // Refused before anything is given up, so the session's own connection stays.
            if (m_broker->held_by_another(client, user))
            {
                w.u8(3);
                reply = w.take();
                break;
            }
            bool newer_here = false;
            for (auto& [id, pc] : m_claims)
                if (pc.ask.client_id == client)
                {
                    if (pc.stamp > stamp)
                        newer_here = true;
                    else
                        pc.lost = true;
                }
            if (newer_here)
            {
                w.u8(2);
                reply = w.take();
                break;
            }
            std::string bytes = m_broker->surrender(client, clean);
            if (bytes.empty())
                w.u8(0);
            else
            {
                w.u8(1);
                w.bytes(bytes);
                ++m_sessions_moved;
            }
            reply = w.take();
            break;
        }
        default:
            break;
    }
}

void mqtt_run::shard_stats(std::string& out) const
{
    if (!sharded())
        return;
    namespace st = socketley::stats_text;
    size_t known = 0;
    for (const auto& p : m_peers)
        known += p.known;
    st::put(out, "shard_peers_known", known);
    st::put(out, "shard_forwarded", m_shard_forwarded);
    st::put(out, "shard_received", m_shard_received);
    st::put(out, "shard_unreached", m_shard_unreached);
    size_t waiting = 0, flying = 0;
    for (const auto& q : m_squeue)
    {
        waiting += q.waiting();
        flying += q.flying;
    }
    st::put(out, "shard_waiting_bytes", waiting);
    st::put(out, "shard_flying_bytes", flying);
    st::put(out, "shard_dropped", m_shard_dropped);
    st::put(out, "shard_resent", m_shard_resent);
    st::put(out, "session_claims", m_claims_made);
    st::put(out, "session_claim_asks", m_claim_asks);
    st::put(out, "session_claims_lost", m_claims_lost);
    st::put(out, "session_claims_refused", m_claims_refused);
    st::put(out, "sessions_moved", m_sessions_moved);
}

}   // namespace socketley::mqtt
