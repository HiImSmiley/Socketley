#include "request_channel.h"
#include "../loop/event_loop.h"
#include "../util/logging.h"

#include <algorithm>

const char* request_status_text(request_status st)
{
    switch (st)
    {
        case request_status::ok:         return "ok";
        case request_status::no_target:  return "no such runtime";
        case request_status::overloaded: return "the runtime is overloaded: its request backlog is full";
        case request_status::dropped:    return "cache request dropped";
    }
    return "unknown";
}

const char* overload_bound_name(overload_bound b)
{
    switch (b)
    {
        case overload_bound::queue:       return "queue";
        case overload_bound::queue_bytes: return "queue_bytes";
        case overload_bound::parked:      return "parked";
        case overload_bound::wakeup:      return "wakeup";
        case overload_bound::way:         return "way";
        case overload_bound::answer_way:  return "answer_way";
        case overload_bound::count_:      break;
    }
    return "unknown";
}

namespace
{

// What a bound is, in the words of the one log line it gets.
std::string overload_bound_text(overload_bound b)
{
    switch (b)
    {
        case overload_bound::queue:
            return "the request queue holds " + std::to_string(request_channel::MAX_PENDING) + " requests";
        case overload_bound::queue_bytes:
            return "the request queue's bytes are at their bound";
        case overload_bound::parked:
            return "the table of requests awaiting an answer is full (" + std::to_string(request_channel::MAX_PARKED) +
                   ", background work " + std::to_string(request_channel::MAX_PARKED_BACKGROUND) + ")";
        case overload_bound::wakeup:
            return "the ring took no wakeup for the queue";
        case overload_bound::way:
            return "the socket the request goes out on is full";
        case overload_bound::answer_way:
            return "the socket the answer goes back on is full";
        case overload_bound::count_:
            break;
    }
    return "unknown";
}

}   // namespace

void request_channel::note_overloaded(overload_bound b)
{
    if (++m_stat_overloaded[static_cast<size_t>(b)] == 1)
        LOG_WARN(("request channel: a request was refused as overloaded because " + overload_bound_text(b) +
                  "; counted as requests_overloaded_" + overload_bound_name(b) + " in stats").c_str());
}

std::string request_channel::bound_stats() const
{
    std::string out;
    for (size_t i = 0; i < static_cast<size_t>(overload_bound::count_); ++i)
        out += std::string("requests_overloaded_") + overload_bound_name(static_cast<overload_bound>(i)) + ":" +
               std::to_string(m_stat_overloaded[i]) + "\n";
    return out + "requests_parked_most:" + std::to_string(m_parked_most) + "\n";
}

request_channel::~request_channel()
{
    // Deliberately does not touch the loop, which has static storage duration
    // in the same translation unit and is destroyed first; detach() is what
    // gives the registration back.
    m_queue.clear();
    m_origins.clear();
    m_sinks.clear();
}

void request_channel::attach(event_loop& loop)
{
    m_loop  = &loop;
    m_wake  = { this, nullptr, -1, 0, op_nop };
    m_sweep = { this, nullptr, -1, 0, op_timeout };

    // A wakeup in flight across a detach never reports, so the flag is cleared
    // from owner_inflight(), except when the owner table is full and zero
    // would mean unknown.
    if (loop.owner_drained(this))
    {
        m_wake_armed  = false;
        m_sweep_armed = false;
    }

    loop.register_owner(this);

    // Anything parked from before is waiting again on a ring that can report.
    arm_park_sweep();
}

void request_channel::arm_park_sweep()
{
    if (!m_loop || m_sweep_armed || m_parked.empty())
        return;

    // Five seconds against a thirty second deadline: the answer is late either
    // way, and a finer tick would walk the table six times for nothing.
    m_sweep_ts.tv_sec  = 5;
    m_sweep_ts.tv_nsec = 0;
    m_sweep_armed = m_loop->submit_timeout(&m_sweep_ts, &m_sweep);
}

template <class Pick>
size_t request_channel::drop_parked(Pick pick)
{
    // Taken out of the member for the walk, since an answer's callback can come back here and refill it.
    std::vector<uint64_t> due;
    due.swap(m_sweep_due);
    due.clear();
    for (const auto& [ticket, p] : m_parked)
        if (pick(p))
            due.push_back(ticket);

    for (const uint64_t ticket : due)
        complete_deferred(ticket, request_status::dropped, {});

    const size_t n = due.size();
    m_stat_parked_dropped += n;
    if (m_sweep_due.empty())
        m_sweep_due.swap(due);
    return n;
}

void request_channel::detach()
{
    // Both halves, and for a long time only the first: the queue was drained
    // here and the parked table was not, so a request that had already reached
    // its target was the one kind this never answered.
    drop_parked([](const parked_request&) { return true; });

    // Everything queued is answered rather than forgotten, because an origin
    // promised a reply that never comes waits for ever.
    while (!m_queue.empty())
    {
        entry e = std::move(m_queue.front());
        m_queue.pop_front();
        m_bytes -= std::min(m_bytes, e.payload.size());
        if (e.origin && origin_live(e.origin))
            e.origin->on_request_reply(e.cookie, request_status::dropped, {});
    }

    if (m_loop)
        m_loop->deregister_owner(this);
    m_loop = nullptr;
    m_sinks.clear();
    m_origins.clear();
}

void request_channel::clear_sinks()
{
    m_sinks.clear();
}

void request_channel::register_sink(std::string_view name, request_sink* sink)
{
    if (!sink || name.empty())
        return;
    m_sinks.insert_or_assign(std::string(name), sink);
}

void request_channel::drop_sink(const request_sink* sink)
{
    // Answered now rather than at the deadline: this is the target genuinely
    // going, and it is the one moment where the answer is known.  NOT done by
    // clear_sinks(), which rebuilds the whole table on every membership change
    // and would drop every request in flight each time.
    const size_t gone = drop_parked(
        [sink](const parked_request& p) { return p.sink == sink; });
    if (gone > 0)
        LOG_WARN(("request channel: " + std::to_string(gone) +
                  " request(s) dropped because the runtime answering them went away").c_str());

    for (auto it = m_sinks.begin(); it != m_sinks.end(); )
    {
        if (it->second == sink)
            it = m_sinks.erase(it);
        else
            ++it;
    }

    // The fallback too, or dropping a sink would leave every unknown name
    // pointing at it.
    if (m_default_sink == sink)
        m_default_sink = nullptr;
}

bool request_channel::origin_live(const request_origin* o) const
{
    return std::find(m_origins.begin(), m_origins.end(), o) != m_origins.end();
}

bool request_channel::kick()
{
    if (m_wake_armed)
        return true;
    if (!m_loop)
        return false;
    if (!m_loop->submit_nop(&m_wake))
        return false;
    m_wake_armed = true;
    m_stat_wakeups++;
    return true;
}

bool request_channel::post(request_origin* origin, uint64_t cookie,
                           std::string_view target, std::string_view payload,
                           request_class cls)
{
    if (!admit(origin, target, payload.size(), cls))
        return false;
    enqueue(origin, cookie, target, std::string(payload), cls);
    return true;
}

bool request_channel::post_owned(request_origin* origin, uint64_t cookie,
                                 std::string_view target, std::string&& payload,
                                 request_class cls)
{
    if (!admit(origin, target, payload.size(), cls))
        return false;
    enqueue(origin, cookie, target, std::move(payload), cls);
    return true;
}

bool request_channel::admit(request_origin* origin, std::string_view target, size_t size, request_class cls)
{
    if (!m_loop || !origin || target.empty())
    {
        m_stat_refused++;
        return false;
    }

    // Background work stops short of the cap so a request somebody is waiting
    // on still has room, counted separately because the two are different
    // events.
    const size_t limit = (cls == request_class::background)
                       ? MAX_PENDING_BACKGROUND : MAX_PENDING;
    const size_t byte_limit = (cls == request_class::background)
                       ? (MAX_PENDING_BYTES / 4) * 3 : MAX_PENDING_CLIENT_BYTES;

    if (m_queue.size() >= limit ||
        (m_bytes + size > byte_limit && (m_bytes != 0 || cls == request_class::background)))
    {
        if (cls == request_class::background)
            m_stat_dropped_bg++;
        else
            m_stat_refused++;
        note_overloaded(m_queue.size() >= limit ? overload_bound::queue : overload_bound::queue_bytes);
        return false;
    }

    // Before the entry goes in, because an entry queued behind a submission
    // that never reached the ring is one nothing will come back for.
    if (!kick())
    {
        if (cls == request_class::background)
            m_stat_dropped_bg++;
        else
            m_stat_refused++;
        note_overloaded(overload_bound::wakeup);
        return false;
    }
    return true;
}

void request_channel::enqueue(request_origin* origin, uint64_t cookie, std::string_view target,
                              std::string&& payload, request_class cls)
{
    if (!origin_live(origin))
        m_origins.push_back(origin);

    entry e;
    e.origin  = origin;
    e.cookie  = cookie;
    e.target.assign(target);
    e.payload = std::move(payload);
    e.cls = cls;
    m_bytes += e.payload.size();
    m_queue.push_back(std::move(e));
    m_stat_posted++;
}

void request_channel::complete_deferred(uint64_t ticket, request_status st,
                                        std::string_view reply)
{
    auto it = m_parked.find(ticket);
    if (it == m_parked.end())
        return;   // answered twice, or withdrawn by drop_origin(); either is fine

    const parked_request p = it->second;
    m_parked.erase(it);

    if (st == request_status::ok)
        m_stat_served++;

    // The same check the inline path makes after the sink has run, for the same
    // reason and with more time for it to have become true: the runtime that
    // asked may have been stopped or removed while the answer was in flight.
    if (p.origin && origin_live(p.origin))
        p.origin->on_request_reply(p.cookie, st, reply);
}

size_t request_channel::reply_room(uint64_t ticket) const
{
    const auto it = m_parked.find(ticket);
    if (it == m_parked.end() || !it->second.origin || !origin_live(it->second.origin))
        return 0;
    return it->second.origin->reply_room(it->second.cookie);
}

size_t request_channel::request_room(std::string_view target) const
{
    const auto it = m_sinks.find(target);
    const request_sink* sink = it == m_sinks.end() ? m_default_sink : it->second;
    return sink ? sink->request_room(target) : SIZE_MAX;
}

uint64_t request_channel::park(request_origin* origin, uint64_t cookie,
                               const request_sink* sink, request_class cls)
{
    // Background work stops short as in post(), or a flood of it fills the table a waiting client parks in.
    const size_t limit = (cls == request_class::background) ? MAX_PARKED_BACKGROUND : MAX_PARKED;
    if (!origin)
        return 0;
    if (m_parked.size() >= limit)
    {
        note_overloaded(overload_bound::parked);
        return 0;
    }
    if (!origin_live(origin))
        m_origins.push_back(origin);
    const uint64_t ticket = m_next_ticket++;
    m_parked.emplace(ticket, parked_request{origin, cookie, sink,
                                            std::chrono::steady_clock::now()});
    m_parked_most = std::max(m_parked_most, m_parked.size());
    arm_park_sweep();
    return ticket;
}

void request_channel::withdraw(uint64_t ticket)
{
    m_parked.erase(ticket);
}

void request_channel::drop_origin(const request_origin* origin)
{
    // Parked requests first, since a ticket whose origin is gone can never be
    // delivered and is the one way this map grows without bound.
    for (auto it = m_parked.begin(); it != m_parked.end(); )
        it = (it->second.origin == origin) ? m_parked.erase(it) : std::next(it);

    for (auto it = m_queue.begin(); it != m_queue.end(); )
    {
        if (it->origin == origin)
        {
            m_bytes -= std::min(m_bytes, it->payload.size());
            it = m_queue.erase(it);
        }
        else
        {
            ++it;
        }
    }

    auto it = std::find(m_origins.begin(), m_origins.end(), origin);
    if (it != m_origins.end())
    {
        *it = m_origins.back();
        m_origins.pop_back();
    }
}

void request_channel::on_cqe(struct io_uring_cqe* cqe)
{
    // Two submissions now, so which one reported has to be asked rather than
    // assumed -- the wakeup's own handling clears a flag, and clearing the
    // wrong one leaves the channel believing a wakeup is owed that is not.
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (req == &m_sweep)
    {
        m_sweep_armed = false;

        const auto now = std::chrono::steady_clock::now();
        const auto limit = std::chrono::seconds(parked_deadline_secs);
        const size_t gone = drop_parked([now, limit](const parked_request& p) {
            return now - p.armed >= limit;
        });
        if (gone > 0)
            LOG_WARN(("request channel: " + std::to_string(gone) +
                      " request(s) given up on after " +
                      std::to_string(parked_deadline_secs) +
                      "s; the runtime they went to took them and did not answer").c_str());

        arm_park_sweep();   // only re-arms while something is still parked
        return;
    }

    // The wakeup, lowered first so a post() from inside a reply callback arms
    // a fresh one.
    m_wake_armed = false;
    drain();
}

void request_channel::drain()
{
    if (m_draining)
        return;
    m_draining = true;

    // Exactly the batch queued when the wakeup was armed, capped so a reply
    // callback that posts again cannot feed the drain itself and a burst
    // cannot hold the loop.
    size_t budget = std::min(m_queue.size(), MAX_DRAIN_BATCH);

    while (budget-- > 0 && !m_queue.empty())
    {
        entry e = std::move(m_queue.front());
        m_queue.pop_front();
        m_bytes -= std::min(m_bytes, e.payload.size());

        request_status st = request_status::no_target;
        std::string    reply;

        // Looked up now and taken out of the table before the call, because
        // serving a request can reach Lua, which can create or remove a
        // runtime and republish this table.
        auto  sit  = m_sinks.find(e.target);
        auto* sink = (sit == m_sinks.end()) ? m_default_sink : sit->second;
        if (sink && !sink->serves_inline())
        {
            // The sink is on the other side of a socket and cannot fill
            // `reply` before returning, so the request parks against a ticket
            // and nothing here waits.
            const uint64_t ticket = park(e.origin, e.cookie, sink, e.cls);
            if (ticket == 0)
            {
                m_stat_deferred_refused++;
                st = request_status::overloaded;
            }
            else if (sink->serve_deferred(ticket, e.target, e.payload))
            {
                m_stat_deferred++;
                continue;          // the reply comes from complete_deferred()
            }
            else
            {
                // It would not even take it, so nothing is going to complete
                // this ticket and it must not stay parked.
                withdraw(ticket);
                st = sink->refusal(e.target, e.payload.size());
                if (st == request_status::no_target)
                    m_stat_no_target++;
                else
                    m_stat_deferred_refused++;
                if (st == request_status::overloaded)
                    note_overloaded(overload_bound::way);
            }
        }
        else if (sink)
        {
            sink->serve_request(e.payload, reply);
            st = request_status::ok;
            m_stat_served++;
        }
        else
        {
            m_stat_no_target++;
        }

        // Re-checked after the sink has run, because Lua can stop or remove
        // the runtime that asked and the pointer taken off the entry would be
        // into retired storage.
        if (e.origin && origin_live(e.origin))
            e.origin->on_request_reply(e.cookie, st, reply);
    }

    m_draining = false;

    // What the batch limit left behind plus anything a callback posted,
    // because a queue left non-empty with nothing armed is a set of origins
    // waiting for replies that are not coming.
    if (!m_queue.empty() && !kick())
    {
        LOG_WARN("request channel: no wakeup could be queued — answering the "
                 "backlog as overloaded rather than leaving it stranded");
        while (!m_queue.empty())
        {
            entry e = std::move(m_queue.front());
            m_queue.pop_front();
            m_bytes -= std::min(m_bytes, e.payload.size());
            note_overloaded(overload_bound::wakeup);
            if (e.origin && origin_live(e.origin))
                e.origin->on_request_reply(e.cookie, request_status::overloaded, {});
        }
    }
}
