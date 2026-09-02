#include "request_channel.h"
#include "event_loop.h"
#include "logging.h"

#include <algorithm>

const char* request_status_text(request_status st)
{
    switch (st)
    {
        case request_status::ok:         return "ok";
        case request_status::no_target:  return "no such runtime";
        case request_status::overloaded: return "cache request queue full";
        case request_status::dropped:    return "cache request dropped";
    }
    return "unknown";
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
    m_loop = &loop;
    m_wake = { this, nullptr, -1, 0, op_nop };

    // A wakeup in flight across a detach never reports, so the flag is cleared
    // from owner_inflight(), except when the owner table is full and zero
    // would mean unknown.
    if (loop.owner_inflight(this) == 0 && !loop.owner_table_full())
        m_wake_armed = false;

    loop.register_owner(this);
}

void request_channel::detach()
{
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
                       ? (MAX_PENDING_BYTES / 4) * 3 : MAX_PENDING_BYTES;

    if (m_queue.size() >= limit || m_bytes + payload.size() > byte_limit)
    {
        if (cls == request_class::background)
            m_stat_dropped_bg++;
        else
            m_stat_refused++;
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
        return false;
    }

    if (!origin_live(origin))
        m_origins.push_back(origin);

    entry e;
    e.origin  = origin;
    e.cookie  = cookie;
    e.target.assign(target);
    e.payload.assign(payload);
    m_bytes += e.payload.size();
    m_queue.push_back(std::move(e));
    m_stat_posted++;
    return true;
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

uint64_t request_channel::park(request_origin* origin, uint64_t cookie)
{
    if (!origin || m_parked.size() >= MAX_PARKED)
        return 0;
    if (!origin_live(origin))
        m_origins.push_back(origin);
    const uint64_t ticket = m_next_ticket++;
    m_parked.emplace(ticket, parked_request{origin, cookie});
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

void request_channel::on_cqe(struct io_uring_cqe* /*cqe*/)
{
    // The one submission this handler ever makes, lowered first so a post()
    // from inside a reply callback arms a fresh wakeup.
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
            const uint64_t ticket = park(e.origin, e.cookie);
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
                m_stat_no_target++;
                st = request_status::no_target;
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
            if (e.origin && origin_live(e.origin))
                e.origin->on_request_reply(e.cookie, request_status::overloaded, {});
        }
    }
}
