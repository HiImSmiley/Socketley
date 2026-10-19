#include "notifier.h"

#include <algorithm>
#include <cstdlib>

#include "../../runtime/cache/stream_log.h"
#include "../../runtime/mqtt/mqtt_codec.h"
#include "../../runtime/mqtt/mqtt_command.h"
#include "../../shared/util/byte_codec.h"
#include "../../shared/ipc/route_relay.h"
#include "../../shared/runtime/runtime_manager.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/number_parse.h"
#include "../../shared/ipc/one_command.h"
#include "../../shared/util/settings.h"
#include "../../shared/util/text_list.h"

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
        // Another runtime of the daemon: a cache's stream or channel, a server's clients, or a broker's topic.
        const std::string_view url = fields[1];
        if (url.starts_with("mqtt://"))
        {
            std::string_view rest = url.substr(7);
            t.runtime = std::string(take_item(rest, '/'));
            t.topic = std::string(rest);
            t.k = notify_target::kind::mqtt;
            if (t.runtime.empty() || fields.size() == 3 || !socketley::mqtt::valid_topic(t.topic) ||
                t.topic.front() == '$')
            {
                why = where + "a broker target is mqtt://<runtime>/<topic>, the topic without + or #";
                return false;
            }
        }
        else if (url.starts_with("cache://") || url.starts_with("server://"))
        {
            const bool cache = url.starts_with("cache://");
            std::string_view rest = url.substr(cache ? 8 : 9);
            t.runtime = std::string(take_item(rest, '/'));
            if (cache && rest.starts_with("stream/"))
                t.k = notify_target::kind::cache_stream;
            else if (cache && rest.starts_with("channel/"))
                t.k = notify_target::kind::cache_channel;
            else if (!cache && rest.empty())
                t.k = notify_target::kind::server;
            if (cache)
                t.topic = std::string(rest.substr(rest.find('/') + 1));
            if (t.k == notify_target::kind::webhook || t.runtime.empty() || fields.size() == 3 ||
                (cache && (t.topic.empty() || t.topic.find_first_of(" \t") != std::string::npos)))
            {
                why = where + "a runtime target is cache://<runtime>/stream/<key>, cache://<runtime>/channel/<channel>, "
                              "server://<runtime> or mqtt://<runtime>/<topic>";
                return false;
            }
        }
        else if (std::string err; !parse_http_url(fields[1], t.http, err))
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
    if (const auto v = settings::number<size_t>("SOCKETLEY_STORAGE_NOTIFY_QUEUE"))
        m_queue_max = *v;
    if (const char* e = settings::text("SOCKETLEY_STORAGE_NOTIFY_HOSTS"))
        m_hosts_file = e;
}

notifier::~notifier()
{
    *m_alive = false;
    if (m_channel)
        m_channel->drop_origin(this);
}

void notifier::set_targets(std::vector<notify_target> targets)
{
    m_lanes.clear();
    bool names = false;
    for (notify_target& t : targets)
    {
        http_endpoint e;
        names = names || (t.k == notify_target::kind::webhook && !literal_endpoint(t.http.host, t.http.port, e));
    }
    if (names && !m_resolver.attach(m_io))
        LOG_ERROR("storage: the notification resolver cannot be waited for, so webhooks named by a host are not delivered to");
    for (notify_target& t : targets)
    {
        auto l  = std::make_unique<lane>();
        l->name = t.name;
        if (t.k == notify_target::kind::webhook)
        {
            l->peer = std::make_unique<http_peer>(m_loop, m_io, m_resolver, t.http, m_hosts_file,
                                                  "the notification target " + t.name);
            // Every name is asked for now, so the first event does not wait for its answer.
            l->peer->prime();
        }
        l->target = std::move(t);
        m_lanes.push_back(std::move(l));
    }
}

void notifier::set_runtimes(runtime_manager* mgr, std::string self)
{
    m_mgr     = mgr;
    m_channel = mgr ? &mgr->requests() : nullptr;
    m_self    = std::move(self);
}

void notifier::on_request_reply(uint64_t cookie, request_status st, std::string_view reply)
{
    const auto it = m_asked.find(cookie);
    if (it == m_asked.end())
        return;
    lane* l = it->second;
    m_asked.erase(it);
    // A cache answers a command it refused with a line that says so.
    const bool taken = st == request_status::ok && !reply.starts_with("error") && !reply.starts_with("failed") &&
                       !reply.starts_with("denied") && !reply.starts_with("-");
    finish(*l, taken);
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
        n += l->peer ? l->peer->resolves() : 0;
    return n;
}

uint64_t notifier::connects() const
{
    uint64_t n = 0;
    for (const auto& l : m_lanes)
        n += l->peer ? l->peer->connects() : 0;
    return n;
}

uint64_t notifier::reuses() const
{
    uint64_t n = 0;
    for (const auto& l : m_lanes)
        n += l->peer ? l->peer->reuses() : 0;
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
        if (l.peer)
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
    if (!l.peer)
    {
        start_runtime(l, ev);
        return;
    }
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

void notifier::start_runtime(lane& l, const pending& ev)
{
    const notify_target& t = l.target;
    // A server is handed each event for its clients and answers nothing, so handing it over is the delivery, made for
    // the whole queue in one turn rather than one call inside the last.
    if (t.k == notify_target::kind::server)
    {
        while (!l.q.empty() && !m_stopped)
        {
            if (!m_mgr || !route_relay::broadcast(m_mgr, t.runtime, m_self, l.q.front().json))
            {
                back_off(l);
                return;
            }
            delivered(l);
        }
        return;
    }
    l.busy = true;
    arm_timer();
    // A cache takes one command in its text protocol; a stream's entry goes in its exact bytes, since its words are
    // split on spaces.
    std::string cmd(one_command_marker);
    // A broker takes the event as a message at QoS 1, which it answers once its subscribers have it queued.
    if (t.k == notify_target::kind::mqtt)
        cmd = socketley::mqtt::command_publish(t.topic, ev.json, 1, false);
    else if (t.k == notify_target::kind::cache_channel)
        cmd += "publish " + t.topic + " " + ev.json;
    else
    {
        const std::string_view args[] = {"xadd", t.topic, "*", "event", ev.json};
        cmd += "xapply " + t.topic + " ";
        stream_args_encode(cmd, args, std::size(args));
    }
    const uint64_t cookie = ++m_next_cookie;
    m_asked.emplace(cookie, &l);
    if (!m_channel || !m_channel->post(this, cookie, t.runtime, cmd, request_class::client))
    {
        m_asked.erase(cookie);
        finish(l, false);
    }
}

void notifier::finish(lane& l, bool ok)
{
    l.busy = false;
    if (m_stopped)
        return;
    if (ok)
    {
        delivered(l);
        start(l);
        return;
    }
    back_off(l);
}

void notifier::delivered(lane& l)
{
    ++m_c.sent;
    m_box.done(l.q.front().id);
    l.q.pop_front();
    --m_queued;
    l.failures = 0;
    l.next_try = {};
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
    if (m_channel)
        m_channel->drop_origin(this);
    m_channel = nullptr;
    m_asked.clear();
    for (auto& l : m_lanes)
        if (l->peer)
            l->peer->stop();
    if (m_timer_armed)
        m_loop.submit_timeout_remove(&m_timer_req);
    // A resolve in progress is waited out here, which the system resolver's own timeout bounds.
    m_resolver.retire(m_loop);
    m_box.stop();
}

}   // namespace socketley::storage
