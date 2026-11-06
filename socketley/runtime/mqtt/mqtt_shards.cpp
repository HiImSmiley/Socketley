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
    forward       = 12,
    adopted       = 13,
    handover      = 14,
    handover_part = 15,
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
// A claim older than this is not answered with its session, which would come after the asker's channel gave the
// answer up; the asker's connection takes the session over by settle() instead, once it is heard of.
constexpr int64_t claim_stale_us = int64_t{request_channel::parked_deadline_secs} * 1'000'000 / 2;
// How long a SUBACK waits for the other shards to know its new filters, before it goes without.
constexpr int64_t ack_patience_ms = 1000;
// How long a shard that gave a session up hands on what still comes for it, far past the moment every other shard
// heard where the session went.
constexpr int64_t forward_keep_ms = 10'000;

// A session past this goes to another shard in pieces of it, each far inside the 8 MiB one frame through the daemon
// holds, so no session is too large to move.
constexpr size_t piece_bytes = 1u << 20;
// The most one session's pieces may add up to.
constexpr uint64_t session_most = 1u << 28;

// What an answer of retained messages keeps free of the way back's room for its count and where the next one starts.
constexpr size_t dump_margin = 128u << 10;

// What a message for another shard carries besides its packet, the client's id and the shared groups among it, as
// far as a packet is held to fit; a batch past it is not sent.
constexpr size_t crossing_margin = 256u << 10;

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

uint32_t mqtt_run::crossing_packet(uint32_t asked) const
{
    // With no mesh a message crosses through the daemon, whose frames hold 8 MiB, so a packet past that is refused
    // as one past --max-packet is, rather than sent and lost on the way.
    auto* mgr = m_owner.get_runtime_manager();
    if (!sharded() || !mgr)
        return asked;
    size_t room = SIZE_MAX;
    for (uint32_t j = 0; j < m_owner.get_shards(); ++j)
        if (j != m_owner.get_shard_index())
            room = std::min(room, mgr->requests().request_room(shard_target(m_owner.get_name(), j)));
    const size_t fits = room > crossing_margin ? room - crossing_margin : 0;
    return static_cast<uint32_t>(std::min<size_t>(asked, std::max<size_t>(fits, 64)));
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
    socketley::bytes::append32(q.pending, static_cast<uint32_t>(frame.size()));
    q.pending.append(frame);
    ++q.queued;
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
        const std::string target = shard_target(m_owner.get_name(), to);
        std::string batch = frame_of(sverb::batch, me);
        batch.reserve(batch.size() + 24 + cut);
        socketley::bytes::append64(batch, m_shard_epoch);
        socketley::bytes::append64(batch, q.seq);
        socketley::bytes::append64(batch, q.sent.empty() ? q.seq : q.sent.front().first);
        // A frame past what the way carries now, which a frame of its own is when it is past a batch, goes as an
        // empty one, keeping its number: sent, it would be refused there and every frame after it held behind it.
        if (count == 1 && batch.size() + cut > mgr->requests().request_room(target))
        {
            socketley::bytes::append32(batch, 0);
            ++m_shard_dropped;
        }
        else
            batch.append(rest.substr(0, cut));
        const uint64_t cookie = m_shard_cookie_base++;
        if (!mgr->requests().post_owned(this, cookie, target, std::move(batch), request_class::client))
            break;
        if (!q.flying)
            q.heard_ms = now_ms();
        q.flying += cut;
        m_shard_batches.emplace(cookie, to);
        q.sent.push_back({cookie, q.head, cut, q.seq});
        q.head += cut;
        q.seq += count;
    }
    // The front taken away once half of what is held has been receipted, not once a batch.
    const size_t done = q.sent.empty() ? q.head : q.sent.front().at;
    if (done == q.pending.size())
    {
        q.pending.clear();
        q.head = 0;
    }
    else if (done > q.pending.size() / 2)
    {
        q.pending.erase(0, done);
        q.head -= done;
        for (auto& b : q.sent)
            b.at -= done;
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
    const uint32_t to = it->second;
    shard_queue& q = m_squeue[to];
    q.heard_ms = now_ms();
    const auto at = std::find_if(q.sent.begin(), q.sent.end(), [&](const shard_batch& b) { return b.cookie == cookie; });
    if (at == q.sent.end())
    {
        m_shard_batches.erase(it);
        return true;
    }
    // A shard that missed a frame before this batch took none of it, and says so; one that took it took every frame
    // before it, so the batches before it are done too.
    if (st == request_status::ok && reply.empty())
    {
        for (auto i = q.sent.begin(); i != std::next(at); ++i)
        {
            q.flying -= std::min(q.flying, i->size);
            m_shard_batches.erase(i->cookie);
        }
        q.sent.erase(q.sent.begin(), std::next(at));
        q.failing_since = 0;
        if (!m_held_acks.empty())
            release_acks();
    }
    else
    {
        // This batch and every one posted after it go again, from where they still are and before what waits, since
        // a later one may not have been taken either; the shard skips what it already took by its number.
        if (!q.failing_since)
            q.failing_since = now_ms();
        q.retry_at = now_ms() + resend_ms;
        q.seq  = at->first;
        q.head = at->at;
        for (auto i = at; i != q.sent.end(); ++i)
        {
            q.flying -= std::min(q.flying, i->size);
            m_shard_batches.erase(i->cookie);
        }
        q.sent.erase(at, q.sent.end());
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
    m_seen.assign(n, {});
    m_moved.clear();
    m_unsaid.clear();
    m_adopted.clear();
    m_unheard.clear();
    // What this shard holds, told whole, so a peer that knew an older picture of it replaces that one.
    const std::vector<std::string> mine = told_filters();
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
    std::string f = frame_of(sverb::retained_dump, me);
    socketley::bytes::append32(f, static_cast<uint32_t>(m_retained_after.size()));
    f += m_retained_after;
    if (post_shard(from, std::move(f), cookie))
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
        // An answer that cannot be read is asked for again, from where the last one ended.
        m_retained_ask_ms = now_ms() + resend_ms;
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
        bool more = false;
        std::string after;
        if (!r.flag(more) || (more && !r.bytes(after, 1u << 16)))
            return true;
        m_retained_ask_ms = 0;
        m_retained_after = std::move(after);
        // An answer the way had no room for any of is asked for again a moment later.
        if (more && n)
            ask_retained();
        else if (more)
            m_retained_ask_ms = now_ms() + resend_ms;
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
    // One whose end was not told yet is still counted by the others.
    if (!sharded() || m_peers.empty() || m_unsaid.erase(filter))
        return;
    share_interest(static_cast<uint8_t>(sverb::interest_add), {filter});
    std::vector<uint64_t>& upto = m_unheard[filter];
    upto.assign(m_squeue.size(), 0);
    for (uint32_t j = 0; j < m_squeue.size(); ++j)
        if (j != m_owner.get_shard_index())
            upto[j] = m_squeue[j].queued;
}

bool mqtt_run::shard_took(uint32_t to, uint64_t upto) const
{
    const shard_queue& q = m_squeue[to];
    return (q.sent.empty() ? q.seq : q.sent.front().first) >= upto || unreachable(q);
}

bool mqtt_run::heard_everywhere(const std::string& filter)
{
    const auto it = m_unheard.find(filter);
    if (it == m_unheard.end())
        return true;
    for (uint32_t j = 0; j < it->second.size(); ++j)
        if (!shard_took(j, it->second[j]))
            return false;
    m_unheard.erase(it);
    return true;
}

bool mqtt_run::filters_heard(const std::vector<std::string>& filters, std::function<void()> ready)
{
    bool heard = true;
    for (const auto& f : filters)
        heard = heard_everywhere(f) && heard;
    if (heard)
        return true;
    ++m_acks_held;
    m_held_acks.push_back({filters, now_ms() + ack_patience_ms, std::move(ready)});
    arm_ack_timer();
    return false;
}

void mqtt_run::release_acks()
{
    const int64_t now = now_ms();
    std::vector<std::function<void()>> go;
    for (size_t i = 0; i < m_held_acks.size();)
    {
        held_ack& h = m_held_acks[i];
        bool all = true;
        for (const auto& f : h.filters)
            all = heard_everywhere(f) && all;
        if (!all && now < h.until)
        {
            ++i;
            continue;
        }
        // Past its patience it goes anyway, counted, since a message published elsewhere may not reach it yet.
        if (!all)
            ++m_acks_late;
        go.push_back(std::move(h.ready));
        m_held_acks.erase(m_held_acks.begin() + static_cast<std::ptrdiff_t>(i));
    }
    // Answered after the walk, since an answer lets the connection's next SUBSCRIBE be held here.
    for (auto& g : go)
        g();
    arm_ack_timer();
}

void mqtt_run::arm_ack_timer()
{
    if (m_ack_armed || m_stopped || m_held_acks.empty())
        return;
    int64_t first = m_held_acks.front().until;
    for (const auto& h : m_held_acks)
        first = std::min(first, h.until);
    const int64_t wait = std::max<int64_t>(first - now_ms(), 1);
    m_ack_req       = io_request{};
    m_ack_req.owner = this;
    m_ack_req.type  = op_timeout;
    m_ack_ts        = {wait / 1000, (wait % 1000) * 1'000'000};
    m_ack_armed     = m_loop.submit_timeout(&m_ack_ts, &m_ack_req);
}

void mqtt_run::filter_removed(const std::string& filter)
{
    if (!sharded() || m_peers.empty())
        return;
    // A session given up lately still takes this filter's messages here, to hand them on.
    if (std::any_of(m_moved.begin(), m_moved.end(), [&](const moved_session& s) { return s.subs.contains(filter); }))
    {
        m_unsaid.insert(filter);
        return;
    }
    share_interest(static_cast<uint8_t>(sverb::interest_del), {filter});
}

std::vector<std::string> mqtt_run::told_filters() const
{
    std::vector<std::string> out = m_broker->filters();
    out.insert(out.end(), m_unsaid.begin(), m_unsaid.end());
    return out;
}

void mqtt_run::drop_moved(size_t i)
{
    moved_session gone = std::move(m_moved[i]);
    m_moved.erase(m_moved.begin() + static_cast<std::ptrdiff_t>(i));
    for (const auto& [filter, o] : gone.subs)
    {
        if (!m_unsaid.contains(filter) ||
            std::any_of(m_moved.begin(), m_moved.end(), [&](const moved_session& s) { return s.subs.contains(filter); }))
            continue;
        m_unsaid.erase(filter);
        share_interest(static_cast<uint8_t>(sverb::interest_del), {filter});
    }
}

void mqtt_run::forward_moved(const message_ptr& m, uint32_t origin, uint64_t epoch, uint64_t seq, uint64_t taken,
                             const std::vector<std::string>* groups)
{
    const int64_t now = now_ms();
    for (const moved_session& s : m_moved)
    {
        if (now >= s.until)
            continue;
        std::vector<std::string> filters;
        bool plain = false;
        for (const auto& [filter, o] : s.subs)
        {
            std::string_view group, inner = filter;
            const bool shared = split_shared(filter, group, inner);
            if (!topic_matches(inner, m->topic))
                continue;
            // A group's message is the session's only where this shard was chosen for the group and has no member
            // of it left.
            if (shared && (m_broker->has_filter(filter) ||
                           (groups ? std::find(groups->begin(), groups->end(), filter) == groups->end()
                                   : std::any_of(m_sharing.begin(), m_sharing.end(), [&](const auto& a) {
                                         return std::find(a.begin(), a.end(), filter) != a.end();
                                     }))))
                continue;
            plain = plain || !shared;
            filters.push_back(filter);
        }
        if (!filters.empty())
            forward_to(s, std::move(filters), plain, m, origin, epoch, seq, taken);
    }
}

void mqtt_run::forward_to(const moved_session& s, std::vector<std::string> filters, bool plain, const message_ptr& m,
                          uint32_t origin, uint64_t epoch, uint64_t seq, uint64_t taken)
{
    if (!deliver_room(s.to, m->qos))
    {
        ++m_shard_dropped;
        return;
    }
    // Whether the shard it went to was handed this message too, as the one that accepted it or directly.
    const bool direct = plain && (s.to == origin || (s.to < 64 && (taken >> s.to & 1)));
    // Handed there after it took the session in, it reached the session there.
    if (direct && origin < s.marks.size() && std::pair{epoch, seq} > s.marks[origin])
    {
        std::erase_if(filters, [](const std::string& f) {
            std::string_view group, inner = f;
            return !split_shared(f, group, inner);
        });
        if (filters.empty())
            return;
    }
    std::string f = frame_of(sverb::forward, m_owner.get_shard_index());
    socketley::bytes::writer w;
    w.bytes(s.client);
    w.u32(origin);
    w.u64(epoch);
    w.u64(seq);
    w.u64(taken);
    w.flag(direct);
    put_list(w, filters);
    w.bytes(message_bytes(*m));
    f += w.take();
    if (queue_shard(s.to, f, false))
        ++m_moved_forwarded;
}

void mqtt_run::take_forward(std::string_view frame)
{
    socketley::bytes::reader r(frame);
    uint8_t v = 0;
    uint32_t from = 0, origin = 0;
    uint64_t epoch = 0, seq = 0, taken = 0;
    bool direct = false;
    std::string client;
    std::vector<std::string> filters;
    std::string_view body;
    auto m = std::make_shared<message>();
    if (!r.marker(shard_prefix) || !r.u8(v) || !r.u32(from) || !r.bytes(client, 1u << 16) || !r.u32(origin) ||
        !r.u64(epoch) || !r.u64(seq) || !r.u64(taken) || !r.flag(direct) || !get_list(r, filters) ||
        !r.view(body, 1u << 28) || !message_from(body, *m))
        return;
    // A session still being claimed here is handed it once it is in.
    bool held = false;
    for (auto& [id, pc] : m_claims)
        if (pc.ask.client_id == client)
        {
            pc.early.emplace_back(frame);
            held = true;
        }
    if (held)
        return;
    // A session that went on from here meanwhile is handed it where it went, as what was routed here would be.
    if (!m_broker->has_session(client))
    {
        bool on = false;
        const message_ptr held_m = m;
        for (const moved_session& s : m_moved)
        {
            if (s.client != client || now_ms() >= s.until)
                continue;
            std::vector<std::string> theirs;
            bool plain = false;
            for (const auto& f : filters)
                if (s.subs.contains(f))
                {
                    std::string_view group, inner = f;
                    plain = plain || !split_shared(f, group, inner);
                    theirs.push_back(f);
                }
            if (!theirs.empty())
                forward_to(s, std::move(theirs), plain, held_m, origin, epoch, seq, taken);
            on = true;
        }
        if (!on)
            ++m_shard_dropped;
        return;
    }
    // A copy handed here directly reached the session by its plain subscriptions, unless it came before the session.
    if (direct)
    {
        const auto a = m_adopted.find(client);
        const bool before = a != m_adopted.end() && origin < a->second.marks.size() &&
                            std::pair{epoch, seq} <= a->second.marks[origin];
        if (!before)
            std::erase_if(filters, [](const std::string& f) {
                std::string_view group, inner = f;
                return !split_shared(f, group, inner);
            });
    }
    if (!filters.empty() && !m_broker->deliver_moved(client, m, filters))
        ++m_shard_dropped;
}

bool mqtt_run::shared_here(std::string_view key)
{
    if (!sharded() || m_peers.empty())
        return true;
    const uint32_t me = m_owner.get_shard_index();
    std::vector<uint32_t>& candidates = m_candidates;
    candidates.assign(1, me);
    for (uint32_t j = 0; j < m_peers.size(); ++j)
        if (j != me && m_peers[j].held.contains(key))
            candidates.push_back(j);
    if (candidates.size() == 1)
        return true;
    auto t = m_group_turn.find(key);
    if (t == m_group_turn.end())
        t = m_group_turn.emplace(std::string(key), 0).first;
    const uint32_t pick = candidates[t->second++ % candidates.size()];
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
    const uint64_t seq = ++m_msg_seq;
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
    // The shards that take it, which each is told, so a shard a session moved to knows a copy came to it directly.
    uint64_t taken = 0;
    if (any)
    {
        for (uint32_t j = 0; j < n && j < 64; ++j)
            if ((m_plain[j] || !m_sharing[j].empty()) && deliver_room(j, m->qos))
                taken |= uint64_t{1} << j;
        const std::string body = message_bytes(*m);
        for (uint32_t j = 0; j < n; ++j)
        {
            if (!m_plain[j] && m_sharing[j].empty())
                continue;
            if (j < 64)
                m_reached |= uint64_t{1} << j;
            if (queue_deliver(j, m->qos, body, m_sharing[j], taken))
                ++m_shard_forwarded;
        }
    }
    if (!m_moved.empty())
        forward_moved(m, m_owner.get_shard_index(), m_shard_epoch, seq, taken, nullptr);
    for (auto& a : m_sharing)
        a.clear();
}

bool mqtt_run::deliver_room(uint32_t to, uint8_t qos) const
{
    if (to >= m_squeue.size() || to == m_owner.get_shard_index())
        return false;
    // A shard that has gone quiet still has QoS 1 and 2 kept for it, since their publisher was answered and is held
    // at hold_bytes.
    const shard_queue& q = m_squeue[to];
    return q.waiting() < drop_bytes && !unreachable(q) && !(qos == 0 && stalled(q));
}

bool mqtt_run::queue_deliver(uint32_t to, uint8_t qos, std::string_view body, const std::vector<std::string>& groups,
                             uint64_t taken)
{
    if (!deliver_room(to, qos))
    {
        if (to < m_squeue.size() && to != m_owner.get_shard_index())
            ++m_shard_dropped;
        return false;
    }
    shard_queue& q = m_squeue[to];
    // The frame queue_shard() would make, written where it waits rather than built and copied there.
    size_t size = shard_prefix.size() + 1 + 4 + 4 + body.size() + 4 + 24;
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
    socketley::bytes::append64(out, m_shard_epoch);
    socketley::bytes::append64(out, m_msg_seq);
    socketley::bytes::append64(out, taken);
    ++q.queued;
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
    // One frame for every shard, each appending it where it waits.
    std::string f = frame_of(sverb::retained, me);
    socketley::bytes::append32(f, static_cast<uint32_t>(topic.size()));
    f += topic;
    socketley::bytes::append64(f, stamp);
    f += static_cast<char>(now != nullptr);
    if (now)
    {
        const std::string body = message_bytes(*now);
        socketley::bytes::append32(f, static_cast<uint32_t>(body.size()));
        f += body;
    }
    for (uint32_t j = 0; j < n; ++j)
        if (j != me)
            queue_shard(j, f, false);
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
    m_pass_on.erase(ask.client_id);
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
            m_claim_cookies[cookie] = {id, j};
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
    {
        // An answer past the claim's patience: the connection was let in without its session, which is taken in now.
        const auto late = m_late_claims.find(cookie);
        if (late == m_late_claims.end())
            return;
        const auto [client, from] = std::move(late->second);
        m_late_claims.erase(late);
        socketley::bytes::reader r(reply);
        uint8_t status = 0;
        std::string bytes;
        if (st == request_status::ok && r.u8(status) && status == 1 && r.bytes(bytes, 1u << 28))
            absorb(client, bytes, from, false);
        return;
    }
    const auto [id, from] = it->second;
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
                pc.lose(from, 0);
            else if (status == 3)
                pc.refused = true;
            else if (status == 4 && pc.session.empty())
            {
                pc.coming      = true;
                pc.coming_from = from;
            }
            else if (status == 1)
            {
                std::string s;
                if (r.bytes(s, 1u << 28) && pc.session.empty())
                {
                    pc.session      = std::move(s);
                    pc.session_from = from;
                }
            }
        }
    }
    if (pc.waiting)
        --pc.waiting;
    // A session coming in pieces is waited for as long as they come, a patience at most apart.
    if (pc.waiting == 0 && !(pc.coming && pc.session.empty()))
        finish_claim(id);
}

uint64_t mqtt_run::claim_awaiting(const std::string& client, uint32_t from) const
{
    for (const auto& [id, pc] : m_claims)
    {
        if (pc.ask.client_id != client || !pc.session.empty())
            continue;
        if (pc.coming && pc.coming_from == from)
            return id;
        // Its pieces may come before the answer that says they do.
        for (const auto& [cookie, to] : m_claim_cookies)
            if (to.first == id && to.second == from)
                return id;
    }
    return 0;
}

void mqtt_run::pass_on(const std::string& client)
{
    const auto it = m_pass_on.find(client);
    if (it == m_pass_on.end())
        return;
    const uint32_t to = it->second.first;
    m_pass_on.erase(it);
    // Whether that connection began clean is for the shard it is on to say, as absorb() does there.
    const std::string bytes = give_up(client, to, false);
    if (bytes.empty())
        return;
    hand_session(to, client, false, bytes);
    ++m_sessions_yielded;
}

void mqtt_run::finish_claim(uint64_t id)
{
    const auto it = m_claims.find(id);
    if (it == m_claims.end())
        return;
    pending_claim pc = std::move(it->second);
    m_claims.erase(it);
    for (auto c = m_claim_cookies.begin(); c != m_claim_cookies.end();)
        if (c->second.first == id)
        {
            m_late_claims[c->first] = {pc.ask.client_id, c->second.second};
            c = m_claim_cookies.erase(c);
        }
        else
            ++c;
    // What was handed on for the session meanwhile goes to it if it is here, whatever became of this connection.
    const auto early = [&] {
        for (const auto& f : pc.early)
            take_forward(f);
    };
    if (pc.refused)
    {
        ++m_claims_refused;
        // A session another shard gave this claim all the same goes back to it.
        if (!pc.session.empty())
        {
            hand_session(pc.session_from, pc.ask.client_id, true, pc.session);
            ++m_sessions_handed_back;
        }
        early();
        pc.done({reason::not_authorized, {}});
        return;
    }
    if (pc.lost)
    {
        // A newer connection to the same client on another shard wins; this one is told to come back, and the session
        // given to it, now or later, goes on to the winner's shard.
        ++m_claims_lost;
        m_pass_on[pc.ask.client_id] = {pc.lost_to, now_ms() + claim_stale_us / 1000};
        if (!pc.session.empty())
        {
            m_broker->adopt(pc.session);
            took_in(pc.ask.client_id);
        }
        early();
        if (!pc.session.empty())
            pass_on(pc.ask.client_id);
        pc.done({pc.ask.level == level_5 ? reason::session_taken_over : reason::server_unavailable, {}});
        return;
    }
    // The client is this shard's now, so what it gave up of it before is handed on no longer.
    for (size_t i = m_moved.size(); i-- > 0;)
        if (m_moved[i].client == pc.ask.client_id)
            drop_moved(i);
    if (!pc.session.empty())
    {
        m_broker->adopt(pc.session);
        ++m_sessions_moved;
        took_in(pc.ask.client_id);
    }
    early();
    pc.answer.stamp = pc.stamp;
    pc.answer.asked = !pc.skipped;
    pc.done(std::move(pc.answer));
}

void mqtt_run::took_in(const std::string& client)
{
    adopted_session& a = m_adopted[client];
    a.marks = m_seen;
    a.marks[m_owner.get_shard_index()] = {m_shard_epoch, m_msg_seq};
    a.until = now_ms() + 2 * forward_keep_ms;
    // Told to the shard it came from, which then hands on only what did not come here after.
    std::string f = frame_of(sverb::adopted, m_owner.get_shard_index());
    socketley::bytes::writer w;
    w.bytes(client);
    w.u32(static_cast<uint32_t>(a.marks.size()));
    for (const auto& [e, s] : a.marks)
    {
        w.u64(e);
        w.u64(s);
    }
    f += w.take();
    for (uint32_t j = 0; j < m_squeue.size(); ++j)
        if (j != m_owner.get_shard_index())
            queue_shard(j, f, false);
}

void mqtt_run::absorb(const std::string& client, std::string_view bytes, uint32_t from, bool back)
{
    // The session a claim here waits for, sent in the batches since the claim's answer could not carry it.
    if (const uint64_t id = back ? 0 : claim_awaiting(client, from))
    {
        pending_claim& pc = m_claims[id];
        pc.session      = std::string(bytes);
        pc.session_from = from;
        pc.coming       = false;
        if (pc.waiting == 0)
            finish_claim(id);
        return;
    }
    switch (m_broker->take_late(bytes))
    {
        case broker::late_take::installed:
        case broker::late_take::merged:
            ++m_sessions_late;
            for (size_t i = m_moved.size(); i-- > 0;)
                if (m_moved[i].client == client)
                    drop_moved(i);
            if (!back)
            {
                took_in(client);
                pass_on(client);
            }
            break;
        case broker::late_take::ended:
            ++m_sessions_late_ended;
            break;
        case broker::late_take::refused:
        {
            if (back)
            {
                ++m_sessions_late_ended;
                break;
            }
            hand_session(from, client, true, bytes);
            ++m_sessions_handed_back;
            break;
        }
    }
}

void mqtt_run::hand_session(uint32_t to, const std::string& client, bool back, std::string_view bytes)
{
    if (bytes.size() <= piece_bytes)
    {
        std::string f = frame_of(sverb::handover, m_owner.get_shard_index());
        socketley::bytes::writer w;
        w.bytes(client);
        w.flag(back);
        w.bytes(bytes);
        f += w.take();
        queue_shard(to, f, false);
        return;
    }
    // Queued at once, so no other frame comes between the pieces.
    for (size_t at = 0; at < bytes.size(); at += piece_bytes)
    {
        std::string f = frame_of(sverb::handover_part, m_owner.get_shard_index());
        socketley::bytes::writer w;
        w.bytes(client);
        w.flag(back);
        w.u64(bytes.size());
        w.u64(at);
        w.bytes(bytes.substr(at, piece_bytes));
        f += w.take();
        queue_shard(to, f, false);
    }
    ++m_sessions_pieced;
}

std::string mqtt_run::give_up(const std::string& client, uint32_t to, bool clean)
{
    // With none here what an earlier give_up still hands on stays, for a second claim right behind the first.
    if (!m_broker->has_session(client))
        return {};
    // Kept as given up before it is, so the filters it ends are told ended only once its messages stop coming.
    std::map<std::string, sub_options> subs;
    if (!clean)
        subs = m_broker->session_subs(client);
    for (size_t i = m_moved.size(); i-- > 0;)
        if (m_moved[i].client == client)
            drop_moved(i);
    if (!subs.empty())
        m_moved.push_back({client, to, std::move(subs), now_ms() + forward_keep_ms, {}});
    m_adopted.erase(client);
    std::string bytes = m_broker->surrender(client, clean).value_or(std::string());
    if (bytes.empty() && !m_moved.empty() && m_moved.back().client == client)
        drop_moved(m_moved.size() - 1);
    return bytes;
}

void mqtt_run::session_held(const std::string& client_id, const std::string& user, uint64_t stamp, bool clean)
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
    f += static_cast<char>(clean);
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

void mqtt_run::settle(const std::string& client_id, uint64_t stamp, const std::string& user, uint32_t from,
                      bool clean)
{
    // Of two connections let in at once the later keeps the client, unless it came under another user without every
    // shard asked, in which case the session stays with the user that had it; an older word of a session that has
    // ended since loses to the one here either way.
    const auto yields = [&](uint64_t mine, const std::string& mine_user, bool asked) {
        return mine_user == user ? mine < stamp : mine > stamp && !asked;
    };
    for (auto& [id, pc] : m_claims)
        if (pc.ask.client_id == client_id && yields(pc.stamp, pc.answer.username, !pc.skipped))
            pc.lose(from, stamp);
    uint64_t mine = 0;
    std::string mine_user;
    bool asked = true;
    if (m_broker->session_held_as(client_id, mine, mine_user, asked) && yields(mine, mine_user, asked))
    {
        // A connection that resumes goes on with the session here, as it would have had its claim been answered.
        // However large, since it goes in pieces where one frame would not carry it.
        if (!clean && mine_user == user)
        {
            const std::string bytes = give_up(client_id, from, false);
            if (!bytes.empty())
            {
                hand_session(from, client_id, false, bytes);
                ++m_sessions_yielded;
            }
        }
        else
            m_broker->surrender(client_id, true);
        ++m_claims_lost;
    }
}

void mqtt_run::sweep_claims(int64_t now)
{
    if (m_retained_ask_ms && now >= m_retained_ask_ms)
        ask_retained();
    for (size_t i = m_moved.size(); i-- > 0;)
        if (now >= m_moved[i].until)
            drop_moved(i);
    std::erase_if(m_adopted, [&](const auto& kv) { return now >= kv.second.until; });
    std::erase_if(m_pass_on, [&](const auto& kv) { return now >= kv.second.second; });
    // A filter let go here is no longer waited on; one still held is, until every shard has it.
    for (auto it = m_unheard.begin(); it != m_unheard.end();)
    {
        const auto next = std::next(it);
        if (!m_broker->has_filter(it->first))
            m_unheard.erase(it);
        else
            heard_everywhere(it->first);
        it = next;
    }
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
            p.part.clear();
            p.part_client.clear();
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
                shard_frame(frame, ignored, 0);
                p.next = n + 1;
            }
        mgr->requests().complete_deferred(ticket, request_status::ok, reply);
        return;
    }
    shard_frame(payload, reply, mgr->requests().reply_room(ticket));
    mgr->requests().complete_deferred(ticket, request_status::ok, reply);
}

void mqtt_run::shard_frame(std::string_view payload, std::string& reply, size_t room)
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
            uint64_t epoch = 0, seq = 0, taken = 0;
            auto m = std::make_shared<message>();
            if (r.view(body, 1u << 28) && get_list(r, groups) && r.u64(epoch) && r.u64(seq) && r.u64(taken) &&
                message_from(body, *m))
            {
                message_ptr held = m;
                // Not tapped here: a tap is open on every shard, and the shard that accepted it tapped it.
                m_broker->deliver_remote(held, groups);
                if (std::pair{epoch, seq} > m_seen[from])
                    m_seen[from] = {epoch, seq};
                if (!m_moved.empty())
                    forward_moved(held, from, epoch, seq, taken, &groups);
            }
            break;
        }
        case sverb::forward:
        {
            take_forward(payload);
            break;
        }
        case sverb::handover:
        {
            std::string client;
            bool back = false;
            std::string_view bytes;
            if (r.bytes(client, 1u << 16) && r.flag(back) && r.view(bytes, session_most))
                absorb(client, bytes, from, back);
            break;
        }
        case sverb::handover_part:
        {
            // The pieces of one session come one after another, in order, so one that does not follow drops them.
            peer& p = m_peers[from];
            std::string client;
            bool back = false;
            uint64_t total = 0, at = 0;
            std::string_view piece;
            if (!r.bytes(client, 1u << 16) || !r.flag(back) || !r.u64(total) || !r.u64(at) ||
                !r.view(piece, piece_bytes) || total > session_most)
                break;
            if (at == 0)
            {
                p.part_client = std::move(client);
                p.part.clear();
            }
            else if (client != p.part_client || at != p.part.size())
            {
                p.part.clear();
                p.part_client.clear();
                break;
            }
            p.part.append(piece);
            if (p.part.size() < total)
            {
                if (const uint64_t id = back ? 0 : claim_awaiting(p.part_client, from))
                    m_claims[id].started_ms = now_ms();
                break;
            }
            std::string whole = std::move(p.part);
            const std::string who = std::move(p.part_client);
            p.part.clear();
            p.part_client.clear();
            if (whole.size() == total)
                absorb(who, whole, from, back);
            break;
        }
        case sverb::adopted:
        {
            std::string client;
            uint32_t n = 0;
            if (!r.bytes(client, 1u << 16) || !r.u32(n) || n != m_peers.size())
                break;
            std::vector<std::pair<uint64_t, uint64_t>> marks(n);
            for (auto& [e, s] : marks)
                if (!r.u64(e) || !r.u64(s))
                    return;
            for (auto& s : m_moved)
                if (s.client == client && s.to == from)
                    s.marks = marks;
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
            bool clean = false;
            if (!r.bytes(client, 1u << 16) || !r.u64(stamp) || !r.bytes(user, 1u << 16) || !r.flag(clean))
                break;
            settle(client, stamp, user, from, clean);
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
            put_list(w, told_filters());
            put_list(w, m_broker->session_ids());
            reply = w.take();
            break;
        }
        case sverb::retained_dump:
        {
            // In the topics' order from after the one asked, as many as the way back carries, and where the next
            // answer starts when more are left.
            std::string after;
            if (!r.bytes(after, 1u << 16))
                break;
            std::vector<message_ptr> all;
            m_broker->retained_each("#", [&](const message_ptr& m) {
                if (m->topic > after)
                    all.push_back(m);
            });
            std::sort(all.begin(), all.end(), [](const message_ptr& a, const message_ptr& b) {
                return a->topic < b->topic;
            });
            // What the way carries at most, past which a message never goes, and what it takes now.
            auto* mgr = m_owner.get_runtime_manager();
            const size_t way = mgr ? mgr->requests().request_room(shard_target(m_owner.get_name(), from)) : 0;
            const size_t most = way > dump_margin ? way - dump_margin : 0;
            const size_t fits = std::min(room, way) > dump_margin ? std::min(room, way) - dump_margin : 0;
            std::string items;
            uint32_t count = 0;
            size_t i = 0;
            for (; i < all.size(); ++i)
            {
                std::string body = message_bytes(*all[i]);
                // One the way can never carry is passed over, so the answers after it still come.
                if (4 + body.size() > most)
                {
                    ++m_shard_dropped;
                    after = all[i]->topic;
                    continue;
                }
                if (items.size() + 4 + body.size() > fits)
                    break;
                socketley::bytes::append32(items, static_cast<uint32_t>(body.size()));
                items += body;
                ++count;
                after = all[i]->topic;
            }
            socketley::bytes::writer w;
            w.u32(count);
            reply = w.take();
            reply += items;
            reply += static_cast<char>(i < all.size());
            if (i < all.size())
            {
                socketley::bytes::append32(reply, static_cast<uint32_t>(after.size()));
                reply += after;
            }
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
                        pc.lose(from, stamp);
                }
            if (newer_here)
            {
                w.u8(2);
                reply = w.take();
                break;
            }
            if (static_cast<int64_t>((claim_stamp(0) >> 6) - (stamp >> 6)) > claim_stale_us)
            {
                w.u8(0);
                reply = w.take();
                break;
            }
            const std::string bytes = give_up(client, from, clean);
            if (bytes.empty())
                w.u8(0);
            else if (5 + bytes.size() <= room)
            {
                w.u8(1);
                w.bytes(bytes);
                ++m_sessions_moved;
            }
            else
            {
                // One the way back cannot carry goes in the batches, and the asker waits for it.
                hand_session(from, client, false, bytes);
                w.u8(4);
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
    st::put(out, "sessions_late", m_sessions_late);
    st::put(out, "sessions_late_ended", m_sessions_late_ended);
    st::put(out, "sessions_handed_back", m_sessions_handed_back);
    st::put(out, "sessions_yielded", m_sessions_yielded);
    st::put(out, "sessions_pieced", m_sessions_pieced);
    st::put(out, "session_forwards", m_moved_forwarded);
    st::put(out, "subacks_held", m_acks_held);
    st::put(out, "subacks_unheard", m_acks_late);
}

}   // namespace socketley::mqtt
