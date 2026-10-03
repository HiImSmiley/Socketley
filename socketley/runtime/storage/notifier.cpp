#include "notifier.h"

#include <algorithm>
#include <cstdlib>

#include "../../shared/byte_codec.h"
#include "../../shared/logging.h"

namespace socketley::storage
{

namespace
{

constexpr long tick_ns = 250'000'000;

}   // namespace

bool parse_notify_targets(std::string_view text, std::vector<notify_target>& out, std::string& why)
{
    out.clear();
    for (const target_line& line : split_target_lines(text))
    {
        const auto& fields = line.fields;
        const std::string where = "line " + std::to_string(line.line_no) + ": ";
        if (fields.size() < 2 || fields.size() > 3 || (fields.size() == 3 && !fields[2].starts_with("ca=")))
        {
            why = where + "a target is `name url [ca=file]`";
            return false;
        }
        notify_target t;
        t.name = std::string(fields[0]);
        if (fields.size() == 3)
            t.http.ca_file = std::string(fields[2].substr(3));
        if (!valid_target_name(t.name))
        {
            why = where + "a target's name is letters, digits, '-', '_' and '.'";
            return false;
        }
        if (std::string err; !parse_http_url(fields[1], t.http, err))
        {
            why = where + err;
            return false;
        }
        if (!t.http.ca_file.empty() && !t.http.tls)
        {
            why = where + "ca= is for an https target";
            return false;
        }
        for (const notify_target& o : out)
            if (o.name == t.name)
            {
                why = where + "the target " + t.name + " is named twice";
                return false;
            }
        out.push_back(std::move(t));
    }
    return true;
}

bool load_notify_targets(const std::string& path, std::vector<notify_target>& out, std::string& why)
{
    std::string text;
    if (!read_targets_file(path, "notification targets", text, why))
        return false;
    if (!parse_notify_targets(text, out, why))
    {
        why = path + ": " + why;
        return false;
    }
    return true;
}

// ─── The notifier ───────────────────────────────────────────────────────────

notifier::notifier(event_loop& loop, file_io& io, io_handler* owner)
    : m_loop(loop), m_io(io), m_owner(owner), m_box(loop, io, "event outbox")
{
    if (const char* e = std::getenv("SOCKETLEY_STORAGE_NOTIFY_QUEUE"))
    {
        char* end;
        const long v = std::strtol(e, &end, 10);
        if (end != e && v > 0)
            m_queue_max = static_cast<size_t>(v);
    }
    if (const char* e = std::getenv("SOCKETLEY_STORAGE_NOTIFY_HOSTS"))
        m_hosts_file = e;
}

notifier::~notifier()
{
    *m_alive = false;
}

void notifier::set_targets(std::vector<notify_target> targets)
{
    m_lanes.clear();
    bool names = false;
    for (notify_target& t : targets)
    {
        http_endpoint e;
        names = names || !literal_endpoint(t.http.host, t.http.port, e);
    }
    if (names && !m_resolver.attach(m_io))
        LOG_ERROR("storage: the notification resolver cannot be waited for, so webhooks named by a host are not delivered to");
    for (notify_target& t : targets)
    {
        auto l  = std::make_unique<lane>();
        l->name = t.name;
        l->peer = std::make_unique<http_peer>(m_loop, m_io, m_resolver, std::move(t.http), m_hosts_file,
                                              "the notification target " + t.name);
        // Every name is asked for now, so the first event does not wait for its answer.
        l->peer->prime();
        m_lanes.push_back(std::move(l));
    }
}

bool notifier::has_target(std::string_view name) const
{
    for (const auto& l : m_lanes)
        if (l->name == name)
            return true;
    return false;
}

notifier::lane* notifier::find_lane(std::string_view name)
{
    for (auto& l : m_lanes)
        if (l->name == name)
            return l.get();
    return nullptr;
}

uint64_t notifier::resolves() const
{
    uint64_t n = 0;
    for (const auto& l : m_lanes)
        n += l->peer->resolves();
    return n;
}

uint64_t notifier::connects() const
{
    uint64_t n = 0;
    for (const auto& l : m_lanes)
        n += l->peer->connects();
    return n;
}

uint64_t notifier::reuses() const
{
    uint64_t n = 0;
    for (const auto& l : m_lanes)
        n += l->peer->reuses();
    return n;
}

bool notifier::open(const std::string& dir, uint32_t shard, const outbox::change_made& made, std::string& err)
{
    if (m_lanes.empty())
        return true;
    uint64_t dropped = 0;
    const bool ok = m_box.open(dir, ".notify", shard, made, [&](uint64_t id, std::string_view payload)
    {
        bytes::reader r(payload);
        std::string target, json;
        lane* l = r.bytes(target, 4096) && r.bytes(json, 8u << 20) ? find_lane(target) : nullptr;
        if (!l || m_queued >= m_queue_max)
        {
            ++dropped;
            return false;
        }
        l->q.push_back({id, std::move(json)});
        ++m_queued;
        return true;
    }, err);
    if (!ok)
        return false;
    m_c.dropped += dropped;
    if (dropped)
        LOG_WARN(("storage: " + std::to_string(dropped) +
                  " undelivered event(s) in the outbox name a target that is gone or overflow the queue, and are dropped")
                     .c_str());
    if (m_queued)
    {
        LOG_INFO(("storage: " + std::to_string(m_queued) + " undelivered event(s) are sent again").c_str());
        for (auto& l : m_lanes)
            start(*l);
    }
    return true;
}

bool notifier::add(std::string_view target, std::string json)
{
    lane* l = find_lane(target);
    if (!l || m_stopped || m_queued >= m_queue_max)
    {
        ++m_c.dropped;
        return false;
    }
    bytes::writer w;
    w.bytes(target);
    w.bytes(json);
    const uint64_t id = m_box.add(w.take());
    l->q.push_back({id, std::move(json)});
    ++m_queued;
    start(*l);
    return true;
}

uint64_t notifier::stage(std::string_view check, std::vector<std::pair<std::string, std::string>> events)
{
    std::vector<std::pair<lane*, pending>> kept;
    std::vector<std::string> payloads;
    for (auto& [target, json] : events)
    {
        lane* l = find_lane(target);
        if (!l || m_stopped || m_queued + kept.size() >= m_queue_max)
        {
            ++m_c.dropped;
            continue;
        }
        bytes::writer w;
        w.bytes(target);
        w.bytes(json);
        payloads.push_back(w.take());
        kept.emplace_back(l, pending{0, std::move(json)});
    }
    if (kept.empty())
        return 0;
    std::vector<uint64_t> ids;
    const uint64_t ticket = m_box.stage(check, payloads, ids);
    for (size_t i = 0; i < kept.size(); ++i)
        kept[i].second.id = ids[i];
    m_queued += kept.size();
    m_staged.emplace(ticket, std::move(kept));
    return ticket;
}

void notifier::settle(uint64_t ticket, bool made, std::function<void()> then)
{
    const auto it = m_staged.find(ticket);
    if (it == m_staged.end())
    {
        then();
        return;
    }
    auto events = std::move(it->second);
    m_staged.erase(it);
    if (m_stopped)
    {
        then();
        return;
    }
    for (auto& [l, ev] : events)
    {
        if (!made)
        {
            --m_queued;
            continue;
        }
        l->q.push_back(std::move(ev));
        start(*l);
    }
    m_box.settle(ticket, made, std::move(then));
}

// ─── Deliveries ─────────────────────────────────────────────────────────────

void notifier::arm_timer()
{
    if (m_timer_armed || m_stopped)
        return;
    m_timer_ts  = {0, tick_ns};
    m_timer_req = io_request{};
    m_timer_req.owner = m_owner;
    m_timer_req.type  = op_timeout;
    m_timer_armed = m_loop.submit_timeout(&m_timer_ts, &m_timer_req);
}

void notifier::on_timer()
{
    m_timer_armed = false;
    if (m_stopped)
        return;
    const auto now = std::chrono::steady_clock::now();
    bool waiting = false;
    for (auto& lp : m_lanes)
    {
        lane& l = *lp;
        l.peer->tick(now);
        if (!l.busy && !l.q.empty() && now >= l.next_try)
            start(l);
        waiting = waiting || l.busy || !l.q.empty();
    }
    if (waiting)
        arm_timer();
}

void notifier::start(lane& l)
{
    if (l.busy || l.q.empty() || m_stopped)
        return;
    if (std::chrono::steady_clock::now() < l.next_try)
    {
        arm_timer();
        return;
    }
    const pending& ev = l.q.front();
    const http_target& t = l.peer->target();
    http_request rq;
    rq.head = "POST " + t.path + " HTTP/1.1\r\nHost: " + t.authority() +
              "\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(ev.json.size()) +
              "\r\nConnection: keep-alive\r\nUser-Agent: socketley-storage\r\nX-Socketley-Event-Id: " +
              std::to_string(ev.id) + "\r\n\r\n";
    // A webhook says all it has to say in its status, but its whole answer is read so the connection carries the next.
    rq.body      = ev.json;
    l.busy = true;
    arm_timer();
    auto alive = m_alive;
    lane* lp = &l;
    l.peer->exchange(std::move(rq), [this, alive, lp](http_answer a)
    {
        if (*alive)
            finish(*lp, a.status / 100 == 2);
    });
}

void notifier::finish(lane& l, bool delivered)
{
    l.busy = false;
    if (m_stopped)
        return;
    if (delivered)
    {
        ++m_c.sent;
        m_box.done(l.q.front().id);
        l.q.pop_front();
        --m_queued;
        l.failures = 0;
        l.next_try = {};
        start(l);
        return;
    }
    back_off(l);
}

void notifier::back_off(lane& l)
{
    ++m_c.failed;
    ++l.failures;
    const int64_t pause = std::min(backoff_cap_ms, backoff_first_ms << std::min<uint32_t>(l.failures - 1, 16));
    l.next_try = std::chrono::steady_clock::now() + std::chrono::milliseconds(pause);
    arm_timer();
}

void notifier::stop()
{
    if (m_stopped)
        return;
    m_stopped = true;
    for (auto& l : m_lanes)
        l->peer->stop();
    if (m_timer_armed)
        m_loop.submit_timeout_remove(&m_timer_req);
    // A resolve in progress is waited out here, which the system resolver's own timeout bounds.
    m_resolver.stop();
    if (const int fd = m_resolver.release_wake_fd(); fd >= 0)
        m_loop.close_fd(fd);
    m_box.stop();
}

}   // namespace socketley::storage
