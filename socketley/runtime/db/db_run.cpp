#include "db_run.h"
#include "../../shared/loop/turn_clock.h"

#include <algorithm>
#include <tuple>
#include <charconv>
#include <ctime>
#include <chrono>
#include <cstring>
#include <filesystem>

#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "db_instance.h"
#include "../../shared/http/http_framing.h"
#include "../../shared/http/https_client.h"
#include "../../shared/util/logging.h"
#include "../../shared/persist/replaced_file.h"
#include "../../shared/runtime/runtime_manager.h"
#include "../../shared/ipc/shard_target.h"
#include "../../shared/json/json_escape.h"
#include "../../shared/http/url.h"
#include "../../shared/http/status.h"
#include "../../shared/http/request_head.h"
#include "../../shared/util/wall_clock.h"
#include "../../shared/util/text_list.h"
#include "../../shared/crypto/mac.h"
#include "../../shared/loop/eventfd_wake.h"

namespace socketley::db
{

namespace
{

constexpr int64_t idle_secs = 120;
constexpr size_t  max_head  = 16 * 1024;
constexpr size_t  max_body  = 4u << 20;
constexpr size_t  max_conns = 4096;
// What a stream holds unsent before it takes further changes from the history as it drains, not into memory.
constexpr size_t  feed_window = 256u << 10;
// The changes kept for a stream that resumes: while one is open on any shard or closed within resume_secs (a replica
// takes up to a minute to call a silent stream dead, then two seconds to dial again), and else only a few.
constexpr size_t  history_bytes      = 32u << 20;
constexpr size_t  idle_history_bytes = 1u << 20;
constexpr int64_t resume_secs        = 120;
// The common word the shards of a runtime stamp with the last second one held a stream.
constexpr uint32_t feed_seen_word = 0;
// A stream's place when every document of its last change was offered to it.
constexpr size_t  whole_change = SIZE_MAX;

std::string error_body(std::string_view code, std::string_view message)
{
    std::string out = "{\"error\":";
    socketley::json::quote_into(out, code);
    out += ",\"message\":";
    socketley::json::quote_into(out, message);
    out += '}';
    return out;
}

db_run::answer refused(int status, std::string_view code, std::string_view message)
{
    return db_run::answer{status, error_body(code, message), 0, 0};
}

db_run::answer refused(const error& e)
{
    return refused(e.status, e.code, e.message);
}

// The version an If-Match names, "3" or 3; 0 for none or one that is not a version.
uint64_t version_of(std::string_view tag)
{
    if (tag.size() >= 2 && tag.front() == '"' && tag.back() == '"')
        tag = tag.substr(1, tag.size() - 2);
    uint64_t v = 0;
    const auto r = std::from_chars(tag.data(), tag.data() + tag.size(), v);
    return r.ec == std::errc() && r.ptr == tag.data() + tag.size() ? v : 0;
}

const jvalue* string_member(const jvalue& obj, std::string_view name)
{
    const jvalue* m = member(obj, name);
    return m && m->k == jvalue::kind::string ? m : nullptr;
}

}   // namespace


db_run::db_run(db_instance& owner, event_loop& loop)
    : m_owner(owner), m_loop(loop), m_io(loop, this), m_http(loop, this, owner, *this, max_conns)
{
}

db_run::~db_run()
{
    m_replica_stop = true;
    if (m_replica.joinable())
        m_replica.join();
    for (auto& j : m_jobs)
        if (j->th.joinable())
            j->th.join();
    m_loop.deregister_owner(this);
}

bool db_run::start(std::string& why)
{
    schema s;
    if (const std::string path(m_owner.get_schema_path()); !path.empty())
    {
        std::string text;
        if (!read_whole_file(path, text))
        {
            why = path + " cannot be read";
            return false;
        }
        if (!parse_schema(text, s, why))
        {
            why = path + " " + why;
            return false;
        }
        m_schema_stamp = socketley::file_stamp::of(path);
    }
    m_shards = std::max<uint32_t>(1, m_owner.get_shards());
    m_shard = m_owner.get_shard_index();
    m_reader = m_shards > 1 && m_shard > 0;
    // --cache is the runtime's, as --maxmemory is a cache's: each shard caches its share of it, 1 MiB at the least.
    m_store.set_cache_bytes(m_shards > 1 ? std::max<uint64_t>(1u << 20, m_owner.get_cache_bytes() / m_shards)
                                         : m_owner.get_cache_bytes());
    // A shard reading shard 0's log opens it once shard 0 has, and sends shard 0 everything until then.
    if (m_reader)
    {
        // Kept by the store until it opens the log, so a schema read again meanwhile is the one it opens with.
        if (!m_store.set_schema(s, why))
            return false;
    }
    else if (!m_store.open(db_data_dir(m_owner.get_name()), s, why))
        return false;
    m_store.set_max_bytes(m_owner.get_max_bytes());
    m_durable = m_store.seq();
    m_history_from = m_durable + 1;
    m_files_checked = 0;
    reload_files(why);
    if (!why.empty())
        return false;
    m_idp.configure(m_owner.get_idp(), m_owner.get_idp_audience());
    for (std::string_view list = m_owner.get_origins(); !list.empty();)
    {
        const std::string_view one = http_trim_ows(take_item(list));
        if (!one.empty())
            m_origins.emplace_back(one);
    }

    if (!m_http.listen_tcp(m_owner.bind_in_addr(), m_owner.effective_port(), m_shards > 1, why))
        return false;
    m_wake_fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (m_wake_fd < 0)
    {
        why = "no eventfd for work off the loop";
        return false;
    }
    m_loop.register_owner(this);
    m_http.start_accepting();
    arm_wake();
    if (!m_owner.get_backup_dir().empty())
        m_next_backup = wall::now_sec_coarse() + m_owner.get_backup_every();
    if (m_reader)
        try_follow();
    else
        publish_log();
    // Shard 0 alone follows the database it copies; the others read what it writes.
    if (!m_owner.get_replicate().empty() && !m_reader)
    {
        m_replica_seq = m_store.seq();
        m_replica_state = "connecting";
        m_replica = std::thread(&db_run::replica_main, this);
    }
    arm_tick();
    LOG_INFO(("db " + std::string(m_owner.get_name()) + ": " + std::to_string(m_store.documents()) +
              " document(s) in " + std::to_string(m_store.collections()) + " collection(s) at change " +
              std::to_string(m_store.seq()) + ", " + std::to_string(m_keys.size()) + " key(s)" +
              (m_owner.get_idp().empty() ? "" : ", accounts of " + std::string(m_owner.get_idp())) +
              (m_owner.get_replicate().empty() ? "" : ", a replica of " + std::string(m_owner.get_replicate())))
                 .c_str());
    return true;
}

void db_run::stop()
{
    if (m_stopped)
        return;
    m_stopped = true;
    // Answers to what this shard took to another are not wanted once it stops.
    if (auto* mgr = m_owner.get_runtime_manager())
        mgr->requests().drop_origin(this);
    m_crossed.clear();
    m_replica_stop = true;
    if (m_replica.joinable())
        m_replica.join();
    // Work off the loop ends before the files it reads go.
    for (auto& j : m_jobs)
        if (j->th.joinable())
            j->th.join();
    // What was written is on the disk before anything goes, and every answer waiting on it given.
    if (!m_waiting.empty() || !m_unpublished.empty())
    {
        const uint64_t covered = m_store.seq();
        synced(!m_broken && m_store.sync(), covered);
    }
    m_http.stop();
    m_feeds.clear();
    for (auto& j : m_jobs)
        m_store.finish(*j->job);
    m_jobs.clear();
    m_store.close();
    if (m_wake_fd >= 0)
    {
        m_loop.close_fd(m_wake_fd);
        m_wake_fd = -1;
    }
}

bool db_run::drained() const
{
    return m_loop.owner_drained(this);
}

void db_run::on_loop_turn()
{
    if (m_stopped)
        return;
    finish_turn();
    maybe_merge();
    // A merge finished or a segment removed, said to the reading shards.
    publish_log();
    m_http.on_loop_turn();
    if (!m_wake_armed)
        arm_wake();
}

// ─── The disk ───────────────────────────────────────────────────────────────

void db_run::hold(waiter w)
{
    if (w.c)
        w.c->waiting = true;
    m_waiting.push_back(std::move(w));
}

void db_run::finish_turn()
{
    if (m_broken)
    {
        if (!m_waiting.empty())
            synced(false, 0);
        return;
    }
    bool need = !m_unpublished.empty();
    for (const auto& w : m_waiting)
        need = need || w.needs > m_durable;
    if (!need || m_sync_inflight)
        return;
    if (m_store.sealing())
    {
        // The records past the seal are told once it is on the disk, so the loop goes on and looks again.
        if (!m_seal_poll)
            m_seal_poll = m_io.after(std::chrono::milliseconds(1), [this](int64_t) {
                m_seal_poll = false;
                if (!m_stopped)
                    finish_turn();
            });
        if (m_seal_poll)
            return;
        // The ring had no room for the timer: the seal is waited for here, which only blocks the loop for it.
        synced(m_store.sync(), m_store.seq());
        return;
    }
    if (!m_store.flush())
    {
        synced(false, 0);
        return;
    }
    const uint64_t covered = m_store.seq();
    ++m_c.syncs;
    m_sync_inflight = true;
    const bool queued = m_io.fsync(m_store.journal_fd(), true, [this, covered](int64_t res) {
        m_sync_inflight = false;
        // A stop gave every answer itself, after a sync of its own.
        if (m_stopped)
            return;
        synced(res == 0, covered);
        finish_turn();
    });
    if (!queued)
    {
        // The ring had no room: the sync is made here instead, which only blocks the loop for it.
        m_sync_inflight = false;
        synced(m_store.sync(), covered);
    }
}

void db_run::synced(bool ok, uint64_t covered)
{
    if (!ok)
    {
        if (!m_broken)
            LOG_ERROR(("db " + std::string(m_owner.get_name()) +
                       ": the journal could not be written to the disk; nothing more is answered until a restart "
                       "reads back what is there")
                          .c_str());
        m_broken = true;
        m_unpublished.clear();
        std::vector<waiter> all;
        all.swap(m_waiting);
        const std::string body = error_body("not_durable", "the change could not be written to the disk");
        for (auto& w : all)
        {
            if (w.call)
            {
                if (auto* mgr = m_owner.get_runtime_manager())
                    mgr->requests().complete_deferred(w.ticket, request_status::ok,
                                                      "{\"status\":503,\"body\":" + body + "}");
                continue;
            }
            if (w.c->dead)
                continue;
            w.c->keep_alive = false;
            answered(*w.c);
            put_head(w.c->out, *w.c, 503, "application/json", body.size(), {});
            w.c->out += body;
            w.c->waiting = false;
            m_http.flush(w.c);
        }
        return;
    }
    m_durable = std::max(m_durable, covered);
    m_replica_seq = m_durable;
    // Said to the reading shards before anything resting on it is answered.
    publish_log();
    std::vector<waiter> ready;
    std::vector<waiter> rest;
    for (auto& w : m_waiting)
        (w.needs <= m_durable ? ready : rest).push_back(std::move(w));
    m_waiting.swap(rest);
    for (auto& w : ready)
    {
        if (w.call)
        {
            if (auto* mgr = m_owner.get_runtime_manager())
                mgr->requests().complete_deferred(w.ticket, request_status::ok, w.held);
            continue;
        }
        if (w.c->dead)
            continue;
        answered(*w.c);
        w.c->out += w.held;
        if (m_stopped)
            w.c->waiting = false;
        else
            m_http.resume(w.c);
    }
    publish();
}

// ─── Streams of changes ─────────────────────────────────────────────────────

bool db_run::sees(const conn& c, const event& e) const
{
    if (c.replica || c.all)
        return true;
    if (e.coll != c.coll)
        return false;
    if (c.who.kind == principal::key)
        return true;
    const collection_def* def = m_store.get_schema().find(e.coll);
    switch (def ? def->acc : access::priv)
    {
        case access::priv:    return false;
        case access::owner:   return c.who.kind == principal::user && e.owner == c.who.sub;
        case access::shared:  return c.who.kind == principal::user;
        case access::open:
        case access::catalog: return true;
    }
    return false;
}

void db_run::send_event(conn& c, const event& e)
{
    std::string& o = c.out;
    o += "id: " + std::to_string(e.seq) + (e.del ? "\nevent: delete\ndata: " : "\nevent: put\ndata: ");
    o += "{\"collection\":";
    socketley::json::quote_into(o, e.coll);
    o += ",\"id\":";
    socketley::json::quote_into(o, e.id);
    if (!e.owner.empty())
    {
        o += ",\"owner\":";
        socketley::json::quote_into(o, e.owner);
    }
    if (e.del)
        o += ",\"deleted\":true}\n\n";
    else
    {
        o += ",\"version\":" + std::to_string(e.v) + ",\"doc\":";
        o += e.json;
        o += "}\n\n";
    }
    ++m_c.events;
}

bool db_run::feeds_near(int64_t now)
{
    if (std::any_of(m_feeds.begin(), m_feeds.end(), [](const std::shared_ptr<conn>& c) { return !c->dead; }))
    {
        feeds_here(now);
        return true;
    }
    const int64_t seen = std::max<int64_t>(m_feed_seen,
        static_cast<int64_t>(m_owner.shard_stats_table().common_at(feed_seen_word)));
    return seen != 0 && now - seen < resume_secs;
}

void db_run::feeds_here(int64_t now)
{
    if (m_feed_seen == now)
        return;
    m_feed_seen = now;
    if (auto* w = m_owner.shard_stats_table().common_word(feed_seen_word))
        w->store(static_cast<uint64_t>(now), std::memory_order_relaxed);
}

void db_run::trim_history(size_t cap)
{
    while (m_history_bytes > cap && !m_history.empty())
    {
        const event& f = m_history.front();
        m_history_bytes -= f.json.size() + f.coll.size() + f.id.size() + 64;
        m_history_from = f.seq + 1;
        m_history.pop_front();
    }
}

void db_run::publish()
{
    const size_t cap = feeds_near(wall::now_sec_coarse()) ? history_bytes : idle_history_bytes;
    while (!m_unpublished.empty() && m_unpublished.front().seq <= m_durable)
    {
        event e = std::move(m_unpublished.front());
        m_unpublished.pop_front();
        for (size_t i = 0; i < m_feeds.size(); ++i)
        {
            const std::shared_ptr<conn> c = m_feeds[i];
            if (c->dead || !c->dump.empty() || c->behind)
                continue;
            // A stream that has its window unsent takes this change and those after it from the history as it drains.
            if (c->unsent() >= feed_window)
            {
                c->behind = true;
                continue;
            }
            offered(*c, e.seq);
            if (!sees(*c, e))
                continue;
            send_event(*c, e);
            m_http.flush(c);
        }
        m_history_bytes += e.json.size() + e.coll.size() + e.id.size() + 64;
        m_history.push_back(std::move(e));
        trim_history(cap);
    }
    std::erase_if(m_feeds, [](const std::shared_ptr<conn>& c) { return c->dead; });
    tell_feeds();
}

void db_run::open_feed(const std::shared_ptr<conn>& c, const request& rq, std::string coll, bool all, bool replica)
{
    open_feed_at(c, rq, std::move(coll), all, replica);
    // Shard 0 nudges a reader only once it knows of a stream there, so what it wrote before it knew is read now.
    if (m_reader)
    {
        tell_feeds();
        catch_up();
    }
}

void db_run::open_feed_at(const std::shared_ptr<conn>& c, const request& rq, std::string coll, bool all, bool replica)
{
    // Where the stream starts: after the change it names, or now.
    uint64_t since = m_durable;
    bool named = false;
    std::string_view s = rq.last_event_id;
    for (std::string_view q = rq.query; s.empty() && !q.empty();)
    {
        const std::string_view kv = take_item(q, '&');
        if (kv.starts_with("since="))
            s = kv.substr(6);
    }
    if (!s.empty())
    {
        uint64_t v = 0;
        const auto r = std::from_chars(s.data(), s.data() + s.size(), v);
        if (r.ec == std::errc() && r.ptr == s.data() + s.size())
        {
            since = v;
            named = true;
        }
    }
    c->feed = true;
    m_feeds.push_back(c);
    c->all = all;
    c->replica = replica;
    c->coll = std::move(coll);
    c->keep_alive = false;
    c->out += "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\n"
              "X-Accel-Buffering: no\r\nX-Content-Type-Options: nosniff\r\n" +
              cors(rq) + "Connection: close\r\n\r\n";
    // A count the database never reached is a copy of another past: it is told everything again.
    const bool kept = named && since <= m_durable && since + 1 >= m_history_from;
    if (!named || since == m_durable || kept)
    {
        c->at_seq = since;
        c->at_skip = whole_change;
        pump_history(c);
        arm_tick();
        return;
    }
    c->at_seq = m_durable;
    c->at_skip = whole_change;
    c->out += "id: " + std::to_string(m_durable) + "\nevent: reset\ndata: {}\n\n";
    if (!replica)
    {
        // A page told to read again what it shows, and then the changes after it.
        m_http.flush(c);
        arm_tick();
        return;
    }
    c->dump = m_store.everything();
    c->dump_at = 0;
    c->dump_seq = m_store.seq();
    if (!c->dump.empty())
        m_store.pin();
    pump_dump(c);
    arm_tick();
}

void db_run::pump_dump(const std::shared_ptr<conn>& c)
{
    std::string json;
    while (!c->dump.empty() && c->unsent() < (1u << 20))
    {
        if (c->dump_at == c->dump.size())
        {
            c->out += "id: " + std::to_string(c->dump_seq) + "\nevent: synced\ndata: {}\n\n";
            c->dump.clear();
            m_store.unpin();
            // The changes made while the copy went, from the history; a gap there starts the copy again.
            if (c->dump_seq + 1 < m_history_from && c->dump_seq < m_durable)
            {
                c->out += "id: " + std::to_string(m_durable) + "\nevent: reset\ndata: {}\n\n";
                c->dump = m_store.everything();
                c->dump_at = 0;
                c->dump_seq = m_store.seq();
                if (!c->dump.empty())
                    m_store.pin();
                continue;
            }
            c->at_seq = c->dump_seq;
            c->at_skip = whole_change;
            c->behind = true;
            break;
        }
        const auto& it = c->dump[c->dump_at++];
        if (!m_store.body_at(it.from, json))
        {
            m_http.close_conn(c);
            return;
        }
        send_event(*c, event{it.seq, it.coll, it.id, it.owner, it.v, false, json});
    }
    if (c->dump.empty() && c->behind)
    {
        pump_history(c);
        return;
    }
    m_http.flush(c);
}

void db_run::offered(conn& c, uint64_t seq)
{
    if (seq == c.at_seq && c.at_skip != whole_change)
        ++c.at_skip;
    else
    {
        c.at_seq = seq;
        c.at_skip = 1;
    }
}

void db_run::pump_history(const std::shared_ptr<conn>& c)
{
    c->behind = false;
    // The change after the stream's place, or the rest of the one it stopped inside, must still be in the history.
    if (c->at_skip == whole_change ? c->at_seq + 1 < m_history_from : c->at_seq < m_history_from)
    {
        c->at_seq = m_durable;
        c->at_skip = whole_change;
        c->out += "id: " + std::to_string(m_durable) + "\nevent: reset\ndata: {}\n\n";
        if (c->replica)
        {
            c->dump = m_store.everything();
            c->dump_at = 0;
            c->dump_seq = m_store.seq();
            if (!c->dump.empty())
                m_store.pin();
            pump_dump(c);
            return;
        }
        m_http.flush(c);
        return;
    }
    auto it = std::partition_point(m_history.begin(), m_history.end(),
                                   [&](const event& e) { return e.seq < c->at_seq; });
    for (size_t n = 0; it != m_history.end() && it->seq == c->at_seq && n < c->at_skip; ++n)
        ++it;
    for (; it != m_history.end(); ++it)
    {
        if (c->unsent() >= feed_window)
        {
            c->behind = true;
            break;
        }
        offered(*c, it->seq);
        if (sees(*c, *it))
            send_event(*c, *it);
    }
    m_http.flush(c);
}

// ─── Work off the loop ──────────────────────────────────────────────────────

void db_run::arm_wake()
{
    if (m_wake_armed || m_wake_fd < 0 || m_stopped)
        return;
    // Polled and then read here: the ring's read is a socket's recv, which an eventfd answers at once with ENOTSOCK.
    m_wake_req = io_request{};
    m_wake_req.owner = this;
    m_wake_req.fd = m_wake_fd;
    m_wake_req.type = op_poll;
    m_wake_armed = m_loop.submit_poll_add(m_wake_fd, POLLIN, &m_wake_req);
}

void db_run::start_job(std::unique_ptr<copy_job> job, uint64_t ticket)
{
    auto slot = std::make_unique<job_slot>();
    slot->job = std::move(job);
    slot->ticket = ticket;
    job_slot* raw = slot.get();
    const int wake = m_wake_fd;
    raw->th = std::thread([raw, wake] {
        raw->job->run();
        raw->done = true;
        eventfd_bump(wake);
    });
    m_jobs.push_back(std::move(slot));
}

void db_run::jobs_done()
{
    for (auto it = m_jobs.begin(); it != m_jobs.end();)
    {
        job_slot& j = **it;
        if (!j.done)
        {
            ++it;
            continue;
        }
        if (j.th.joinable())
            j.th.join();
        copy_job& job = *j.job;
        m_store.finish(job);
        if (!job.merge)
        {
            if (job.ok)
                ++m_c.backups;
            else
                ++m_c.backup_failures;
            if (j.ticket)
            {
                backup_result& r = m_backups[j.ticket];
                r.done = true;
                r.ok = job.ok;
                r.why = job.why;
                r.documents = job.items.size();
            }
            else if (!job.ok)
                LOG_ERROR(("db " + std::string(m_owner.get_name()) + ": the backup failed: " + job.why).c_str());
            else
            {
                // The newest --backup-keep of this database's backups stay.
                std::vector<std::filesystem::path> ours;
                std::error_code ec;
                const std::string prefix = std::string(m_owner.get_name()) + "-";
                for (const auto& e : std::filesystem::directory_iterator(std::string(m_owner.get_backup_dir()), ec))
                {
                    const std::string n = e.path().filename().string();
                    // Only the exact stamp follows the name, so "shop-eu-..." is not one of shop's.
                    constexpr size_t stamp_len = 16;
                    if (!n.starts_with(prefix) || !n.ends_with(".dbbackup") ||
                        n.size() != prefix.size() + stamp_len + 9)
                        continue;
                    const std::string_view st = std::string_view(n).substr(prefix.size(), stamp_len);
                    bool stamped = st[8] == 'T' && st[15] == 'Z';
                    for (size_t i = 0; i < stamp_len && stamped; ++i)
                        if (i != 8 && i != 15 && (st[i] < '0' || st[i] > '9'))
                            stamped = false;
                    if (stamped)
                        ours.push_back(e.path());
                }
                std::sort(ours.begin(), ours.end());
                const size_t keep = std::max<uint32_t>(1, m_owner.get_backup_keep());
                for (size_t i = 0; i + keep < ours.size(); ++i)
                    std::filesystem::remove(ours[i], ec);
            }
        }
        else if (!job.ok)
            LOG_ERROR(("db " + std::string(m_owner.get_name()) + ": a merge of segments failed: " + job.why).c_str());
        it = m_jobs.erase(it);
    }
}

void db_run::maybe_merge()
{
    if (!m_jobs.empty() || m_reader)
        return;
    if (auto job = m_store.plan_merge())
        start_job(std::move(job), 0);
}

void db_run::scheduled_backup()
{
    if (m_reader || m_owner.get_backup_dir().empty() || wall::now_sec_coarse() < m_next_backup)
        return;
    std::error_code ec;
    std::filesystem::create_directories(std::string(m_owner.get_backup_dir()), ec);
    char stamp[32];
    const time_t t = ::time(nullptr);
    struct tm tmv{};
    gmtime_r(&t, &tmv);
    std::strftime(stamp, sizeof stamp, "%Y%m%dT%H%M%SZ", &tmv);
    const std::string dest =
        std::string(m_owner.get_backup_dir()) + "/" + std::string(m_owner.get_name()) + "-" + stamp + ".dbbackup";
    auto job = m_store.plan_backup(dest);
    if (!job)
        return;   // a merge is running; the next tick tries again
    m_next_backup = wall::now_sec_coarse() + m_owner.get_backup_every();
    start_job(std::move(job), 0);
}

// ─── A replica ──────────────────────────────────────────────────────────────

void db_run::replica_main()
{
    std::string secret;
    if (std::string text; read_whole_file(std::string(m_owner.get_replicate_key()), text))
    {
        secret = std::string(http_trim_ows(text.substr(0, text.find('\n'))));
    }
    https_client::client cl;
    std::string err;
    if (secret.empty() || !cl.init(err))
    {
        std::lock_guard lk(m_replica_mu);
        m_replica_state = secret.empty() ? "the key file " + std::string(m_owner.get_replicate_key()) + " holds no key"
                                         : err;
        return;
    }
    std::string base(m_owner.get_replicate());
    while (!base.empty() && base.back() == '/')
        base.pop_back();
    const auto wake = [this] { eventfd_bump(m_wake_fd); };
    while (!m_replica_stop)
    {
        const std::string url = base + "/_replicate?since=" + std::to_string(m_replica_seq.load());
        std::string buf;
        auto last = std::chrono::steady_clock::now();
        int status = 0;
        err.clear();
        cl.stream(
            url, {{"Authorization", "Bearer " + secret}},
            [&](int st) {
                status = st;
                if (st == 200)
                {
                    m_replica_connected = true;
                    std::lock_guard lk(m_replica_mu);
                    m_replica_state = "following";
                }
                return st == 200;
            },
            [&](std::string_view data) {
                if (m_replica_stop)
                    return false;
                const auto now = std::chrono::steady_clock::now();
                if (data.empty())
                    // The database sends a comment every fifteen seconds; a minute of nothing is a dead stream.
                    return now - last < std::chrono::seconds(60);
                last = now;
                buf.append(data);
                std::vector<event> got;
                bool reset = false;
                uint64_t mark = 0;
                size_t end;
                while ((end = buf.find("\n\n")) != std::string::npos)
                {
                    const std::string block = buf.substr(0, end);
                    buf.erase(0, end + 2);
                    std::string name, payload;
                    uint64_t id = 0;
                    for (std::string_view rest = block; !rest.empty();)
                    {
                        const std::string_view line = take_item(rest, '\n');
                        if (line.starts_with("id: "))
                            std::from_chars(line.data() + 4, line.data() + line.size(), id);
                        else if (line.starts_with("event: "))
                            name = std::string(line.substr(7));
                        else if (line.starts_with("data: "))
                            payload = std::string(line.substr(6));
                    }
                    if (name == "reset")
                    {
                        reset = true;
                        got.clear();
                        mark = 0;
                        continue;
                    }
                    if (name == "synced")
                    {
                        mark = id;
                        continue;
                    }
                    if (name != "put" && name != "delete")
                        continue;
                    jvalue v;
                    if (!json_reader(payload).document(v))
                        continue;
                    event e;
                    e.seq = id;
                    e.del = name == "delete";
                    const jvalue* c = string_member(v, "collection");
                    const jvalue* i = string_member(v, "id");
                    const jvalue* o = string_member(v, "owner");
                    const jvalue* ver = member(v, "version");
                    const jvalue* d = member(v, "doc");
                    if (!c || !i || (!e.del && (!d || !ver)))
                        continue;
                    e.coll = c->s;
                    e.id = i->s;
                    e.owner = o ? o->s : std::string();
                    if (!e.del)
                    {
                        std::from_chars(ver->s.data(), ver->s.data() + ver->s.size(), e.v);
                        json::write_into(e.json, *d);
                    }
                    got.push_back(std::move(e));
                }
                if (!got.empty() || reset || mark)
                {
                    std::lock_guard lk(m_replica_mu);
                    if (reset)
                    {
                        m_replica_in.clear();
                        m_replica_mark = 0;
                        m_replica_reset = true;
                    }
                    for (auto& e : got)
                        m_replica_in.push_back(std::move(e));
                    if (mark)
                        m_replica_mark = std::max(m_replica_mark, mark);
                    wake();
                }
                return true;
            },
            err, 1);
        m_replica_connected = false;
        {
            std::lock_guard lk(m_replica_mu);
            m_replica_state = status && status != 200 ? "refused with " + std::to_string(status)
                              : err.empty()           ? "the stream ended; connecting again"
                                                      : err;
        }
        // A moment between tries, broken off by a stop.
        for (int i = 0; i < 20 && !m_replica_stop; ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void db_run::take_replicated()
{
    std::vector<event> evs;
    bool reset = false;
    uint64_t mark = 0;
    {
        std::lock_guard lk(m_replica_mu);
        evs.swap(m_replica_in);
        reset = m_replica_reset;
        mark = m_replica_mark;
        m_replica_reset = false;
        m_replica_mark = 0;
    }
    if (!reset && evs.empty() && !mark)
        return;
    std::string why;
    if (reset)
    {
        ++m_c.resets;
        // Answers waiting on what is about to go are given first, as they were.
        if (!m_waiting.empty() || !m_unpublished.empty())
            synced(m_store.sync(), m_store.seq());
        // A job running read the log about to go, so it ends and is taken in first.
        for (auto& j : m_jobs)
            if (j->th.joinable())
                j->th.join();
        jobs_done();
        if (!m_store.reset(why))
        {
            LOG_ERROR(("db " + std::string(m_owner.get_name()) + ": the copy could not be emptied: " + why).c_str());
            m_broken = true;
            return;
        }
        m_durable = 0;
        m_replica_seq = 0;
        m_history.clear();
        m_history_bytes = 0;
        m_history_from = 1;
        m_unpublished.clear();
        // Streams of this database, past what it now holds, start over.
        const std::vector<std::shared_ptr<conn>> feeds = m_feeds;
        for (const auto& c : feeds)
            m_http.close_conn(c);
    }
    if (!evs.empty())
    {
        if (!m_store.apply(evs, why))
        {
            LOG_ERROR(("db " + std::string(m_owner.get_name()) + ": a change from " +
                       std::string(m_owner.get_replicate()) + " could not be applied: " + why)
                          .c_str());
            return;
        }
        m_c.replicated += evs.size();
        for (auto& e : evs)
            m_unpublished.push_back(std::move(e));
    }
    if (mark)
        m_store.mark(mark);
    // A change carried here waits for the disk as a write does; finish_turn() syncs it.
    if (m_store.seq() > m_durable)
        hold(waiter{m_store.seq(), nullptr, {}, 0, true});
}

// ─── Stats and files ────────────────────────────────────────────────────────

std::string db_run::stats() const
{
    std::string replica;
    if (!m_owner.get_replicate().empty())
    {
        std::lock_guard lk(const_cast<std::mutex&>(m_replica_mu));
        replica = "\nreplica_of:" + std::string(m_owner.get_replicate()) + "\nreplica_state:" + m_replica_state +
                  "\nreplica_connected:" + (m_replica_connected ? "1" : "0") +
                  "\nreplicated:" + std::to_string(m_c.replicated) + "\nresets:" + std::to_string(m_c.resets);
    }
    const size_t feeds = static_cast<size_t>(
        std::count_if(m_feeds.begin(), m_feeds.end(), [](const std::shared_ptr<conn>& c) { return !c->dead; }));
    return "documents:" + std::to_string(m_store.documents()) + "\ncollections:" + std::to_string(m_store.collections()) +
           "\nbytes:" + std::to_string(m_store.bytes()) + "\nmax_bytes:" + std::to_string(m_owner.get_max_bytes()) +
           "\ndisk_bytes:" + std::to_string(m_store.disk_bytes()) + "\nsegments:" + std::to_string(m_store.segments()) +
           "\nmerges:" + std::to_string(m_store.merges()) + "\ncache_hits:" + std::to_string(m_store.cache_hits()) +
           "\ncache_misses:" + std::to_string(m_store.cache_misses()) +
           "\ncache_limit:" + std::to_string(m_store.cache_limit()) + "\nseq:" + std::to_string(m_store.seq()) +
           "\ndurable:" + std::to_string(m_durable) + "\nkeys:" + std::to_string(m_keys.size()) +
           "\nreads:" + std::to_string(m_c.reads) + "\nfetched:" + std::to_string(m_c.fetched) +
           "\nwrites:" + std::to_string(m_c.writes) +
           "\nqueries:" + std::to_string(m_c.queries) + "\nsyncs:" + std::to_string(m_c.syncs) +
           "\nrefused:" + std::to_string(m_c.refused) + "\nconflicts:" + std::to_string(m_c.conflicts) +
           "\nexpired:" + std::to_string(m_c.expired) + "\nfeeds:" + std::to_string(feeds) +
           "\nhistory_bytes:" + std::to_string(m_history_bytes) +
           "\nevents_sent:" + std::to_string(m_c.events) + "\nbackups:" + std::to_string(m_c.backups) +
           "\nbackup_failures:" + std::to_string(m_c.backup_failures) + "\nscript_calls:" + std::to_string(m_c.calls) +
           (m_shards > 1 ? "\nshard:" + std::to_string(m_shard) + "/" + std::to_string(m_shards) +
                               (m_reader ? std::string("\nrole:reader") + (m_ready ? "" : " (starting)") +
                                               "\ncaught_up:" + std::to_string(m_c.caught_up) +
                                               "\nreopened:" + std::to_string(m_c.reopened)
                                         : std::string("\nrole:writer\nnudges:") + std::to_string(m_c.nudges)) +
                               "\nsent_to_writer:" + std::to_string(m_c.crossed) +
                               "\ntaken_from_readers:" + std::to_string(m_c.crossings_served)
                         : std::string()) +
           replica + (m_broken ? "\nbroken:the journal could not be synced; restart" : "") +
           (m_schema_error.empty() ? std::string() : "\nschema_error:" + m_schema_error) +
           (m_keys_error.empty() ? std::string() : "\nkeys_error:" + m_keys_error) + "\n" + latency_line();
}

std::string db_run::latency_line() const
{
    std::string out;
    m_lat.put(out, "request_latency");
    return out;
}

void db_run::reload_files(std::string& why)
{
    const bool first = m_files_checked == 0;
    const int64_t now = wall::now_sec_coarse();
    if (!first && now == m_files_checked)
        return;
    m_files_checked = now;
    if (const std::string path(m_owner.get_schema_path()); !path.empty())
    {
        if (const socketley::file_stamp mt = socketley::file_stamp::of(path); mt != m_schema_stamp)
        {
            m_schema_stamp = mt;
            std::string text, err;
            schema s;
            if (!read_whole_file(path, text))
                err = path + " cannot be read";
            else if (!parse_schema(text, s, err))
                err = path + " " + err;
            else if (!m_store.set_schema(s, err))
                err = path + ": " + err;
            if (!err.empty())
                LOG_ERROR(("db " + std::string(m_owner.get_name()) + ": " + err + "; the schema before is kept").c_str());
            m_schema_error = err;
        }
    }
    if (const std::string path(m_owner.get_keys_path()); !path.empty())
    {
        if (const socketley::file_stamp mt = socketley::file_stamp::of(path); mt != m_keys_stamp)
        {
            m_keys_stamp = mt;
            std::string text, err;
            std::vector<service_key> keys;
            if (!read_whole_file(path, text))
                err = path + " cannot be read";
            else if (!parse_keys(text, keys, err))
                err = path + " " + err;
            else
                m_keys = std::move(keys);
            if (!err.empty() && first)
                why = err;
            else if (!err.empty())
                LOG_ERROR(("db " + std::string(m_owner.get_name()) + ": " + err + "; the keys before are kept").c_str());
            m_keys_error = err;
        }
    }
}

// ─── Connections ────────────────────────────────────────────────────────────

// Requests in order, one at a time: a write's answer waits for the turn's sync and holds those behind it.
void db_run::serve(const std::shared_ptr<socketley::http::server_conn>& sc)
{
    const auto c = std::static_pointer_cast<conn>(sc);
    while (socketley::http::conn_server::takes_more(*c))
    {
        request rq;
        int refusal = 400;
        c->began_ns = socketley::turn_clock::now_ns();
        const int r = take_request(*c, rq, refusal);
        if (r == 0)
            break;
        if (r < 0)
        {
            c->keep_alive = false;
            respond(c, refusal, error_body("bad_request", "the request could not be read"));
            break;
        }
        runtime_instance::stat_add(m_owner.m_stat_total_messages, 1);
        handle(c, rq);
    }
}

std::shared_ptr<socketley::http::server_conn> db_run::make_conn()
{
    return std::make_shared_for_overwrite<conn>();
}

void db_run::accepted(const std::shared_ptr<socketley::http::server_conn>&)
{
    arm_tick();
}

bool db_run::written(const std::shared_ptr<socketley::http::server_conn>& sc)
{
    // A whole copy being sent, or the history a stream is behind on, goes on as what went before it drains.
    const auto c = std::static_pointer_cast<conn>(sc);
    if (!c->feed)
        return false;
    if (!c->dump.empty())
        pump_dump(c);
    else if (c->behind)
        pump_history(c);
    else
        return false;
    return true;
}

bool db_run::keeps_open(const socketley::http::server_conn& c) const
{
    return static_cast<const conn&>(c).feed;
}

void db_run::closing(const std::shared_ptr<socketley::http::server_conn>& sc)
{
    auto& c = static_cast<conn&>(*sc);
    // A stream that ends may resume, here or at a sibling, from the moment it went.
    if (c.feed)
        feeds_here(wall::now_sec_coarse());
    if (!c.dump.empty())
    {
        c.dump.clear();
        m_store.unpin();
    }
}


void db_run::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req)
        return;
    if (file_io::owns_type(req->type))
    {
        m_io.on_cqe(cqe);
        return;
    }
    if (req == &m_tick_req)
    {
        m_tick_armed = false;
        tick();
        return;
    }
    if (req == &m_wake_req)
    {
        m_wake_armed = false;
        if (m_stopped)
            return;
        if (::read(m_wake_fd, &m_wake_buf, sizeof m_wake_buf) < 0) {}
        jobs_done();
        take_replicated();
        arm_wake();
        return;
    }
    m_http.on_cqe(req, cqe);
}

// Woken for what is due: every second while connections are open, else at the next document to go or backup to
// take, at most a minute ahead; an idle database with neither is woken by nothing.
void db_run::arm_tick()
{
    if (m_tick_armed || m_stopped)
        return;
    int64_t delay = 0;
    const int64_t now = wall::now_sec_coarse();
    const auto due = [&](int64_t at) {
        if (at <= 0)
            return;
        const int64_t d = std::clamp<int64_t>(at - now, 1, 60);
        delay = delay ? std::min(delay, d) : d;
    };
    if (!m_http.empty() || !m_owner.get_replicate().empty())
        delay = 1;
    if (m_owner.get_replicate().empty())
        due(m_store.next_expiry());
    if (!m_owner.get_backup_dir().empty())
        due(m_next_backup);
    if (!delay)
        return;
    m_tick_req = io_request{};
    m_tick_req.owner = this;
    m_tick_req.type = op_timeout;
    m_tick_ts = {delay, 0};
    m_tick_armed = m_loop.submit_timeout(&m_tick_ts, &m_tick_req);
}

void db_run::tick()
{
    if (m_stopped)
        return;
    const int64_t now = wall::now_sec_coarse();
    // A comment now and then, so a stream nothing changes on is not taken for a dead one.
    for (size_t i = 0; i < m_feeds.size(); ++i)
    {
        const std::shared_ptr<conn> c = m_feeds[i];
        if (!c->dead && now - c->last >= 15)
        {
            c->last = now;
            c->out += ": ping\n\n";
            m_http.flush(c);
        }
    }
    std::erase_if(m_feeds, [](const std::shared_ptr<conn>& c) { return c->dead; });
    tell_feeds();
    // Asked every tick, so a quiet stream still stamps the word its siblings read; once none is near, what was kept for
    // one goes.
    if (!feeds_near(now) && m_history_bytes > idle_history_bytes)
        trim_history(idle_history_bytes);
    m_http.sweep(now, idle_secs);
    catch_up();
    // A replica is told of the documents that go by the database it copies, which sends their deletions; a shard
    // reading shard 0's log is told them by it.
    if (m_owner.get_replicate().empty() && !m_broken && !m_reader)
    {
        std::vector<event> evs;
        if (const size_t n = m_store.expire(now, &evs))
        {
            m_c.expired += n;
            for (auto& e : evs)
                m_unpublished.push_back(std::move(e));
            finish_turn();
        }
    }
    scheduled_backup();
    arm_tick();
}

// ─── HTTP ───────────────────────────────────────────────────────────────────

int db_run::take_request(conn& c, request& rq, int& refusal)
{
    socketley::http::request_view v;
    const int r = socketley::http::take_request(c.in, max_head, max_body, v, refusal,
                                                [&rq](std::string_view f, std::string_view value) {
        if (header_name_equals(f, "cookie", 6))
        {
            if (!rq.cookie.empty())
                rq.cookie += "; ";
            rq.cookie.append(value);
        }
        else if (header_name_equals(f, "authorization", 13))
            rq.authorization.assign(value);
        else if (header_name_equals(f, "content-type", 12))
            rq.content_type.assign(value);
        else if (header_name_equals(f, "if-match", 8))
            rq.if_match.assign(value);
        else if (header_name_equals(f, "if-none-match", 13))
            rq.if_none_match.assign(value);
        else if (header_name_equals(f, "last-event-id", 13))
            rq.last_event_id.assign(value);
        else if (header_name_equals(f, "origin", 6))
            rq.origin.assign(value);
        else if (header_name_equals(f, "host", 4))
            rq.host.assign(value);
    });
    if (r <= 0)
        return r;
    rq.method.assign(v.method);
    rq.path.assign(v.path);
    rq.query.assign(v.query);
    rq.body.assign(c.in, v.head_len, v.body_len);
    c.in.erase(0, v.head_len + v.body_len);
    c.keep_alive = !v.close;
    return 1;
}

void db_run::put_head(std::string& o, const conn& c, int status, std::string_view type, size_t length,
                      std::string_view extra, uint64_t version) const
{
    char num[24];
    const auto number = [&](uint64_t v) {
        o.append(num, static_cast<size_t>(std::to_chars(num, num + sizeof num, v).ptr - num));
    };
    o += "HTTP/1.1 ";
    number(static_cast<uint64_t>(status));
    o += ' ';
    o += socketley::http::status_text(status);
    o += "\r\nContent-Type: ";
    o += type;
    o += "\r\nContent-Length: ";
    number(length);
    o += "\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n";
    o += extra;
    if (version)
    {
        o += "ETag: \"";
        number(version);
        o += "\"\r\n";
    }
    if (!c.keep_alive)
        o += "Connection: close\r\n";
    o += "\r\n";
}

void db_run::respond(const std::shared_ptr<conn>& c, int status, std::string_view body, std::string_view extra,
                     uint64_t version, bool head_only)
{
    if (status >= 400)
        ++m_c.refused;
    answered(*c);
    put_head(c->out, *c, status, "application/json", body.size(), extra, version);
    if (!head_only)
        c->out += body;
}

void db_run::answered(const conn& c)
{
    m_lat.observe(c.began_ns, socketley::turn_clock::now_ns());
}

std::string db_run::cors(const request& rq) const
{
    if (rq.origin.empty())
        return {};
    // A named origin is answered with the browser's credentials; `*` lets any page in, but not with them.
    for (const auto& o : m_origins)
        if (o == rq.origin)
            return "Access-Control-Allow-Origin: " + rq.origin +
                   "\r\nAccess-Control-Allow-Credentials: true\r\nAccess-Control-Expose-Headers: ETag\r\nVary: Origin\r\n";
    for (const auto& o : m_origins)
        if (o == "*")
            return "Access-Control-Allow-Origin: *\r\nAccess-Control-Expose-Headers: ETag\r\n";
    return "Vary: Origin\r\n";
}

bool db_run::who_of(const request& rq, principal& who, bool& by_cookie, std::string& refusal)
{
    by_cookie = false;
    if (!rq.authorization.empty())
    {
        std::string_view token;
        if (!http_auth_credentials(rq.authorization, "bearer", token))
        {
            refusal = "Authorization takes Bearer and a key's secret or the provider's access token";
            return false;
        }
        for (const auto& k : m_keys)
            if (crypto::secure_equal(k.secret, token))
            {
                who = principal{principal::key, k.name};
                return true;
            }
        socketley::idp::session_verifier::who w;
        if (m_idp.check_bearer(token, w))
        {
            who = principal{principal::user, w.sub};
            return true;
        }
        refusal = "the bearer token is no key of this database and no access token of its provider";
        return false;
    }
    socketley::idp::session_verifier::who w;
    if (!rq.cookie.empty() && m_idp.check(rq.cookie, w))
    {
        who = principal{principal::user, w.sub};
        by_cookie = true;
        return true;
    }
    who = principal{};
    return true;
}

void db_run::handle(const std::shared_ptr<conn>& c, request& rq)
{
    std::string ignored;
    reload_files(ignored);
    // What shard 0 has made durable is taken in first, so this answer sees every write answered before it.
    catch_up();
    const std::string allow = cors(rq);
    if (rq.method == "OPTIONS")
    {
        // A browser's preflight, answered for an origin this database answers at all.
        respond(c, 204, "",
                allow + (allow.starts_with("Access-Control-Allow-Origin")
                             ? "Access-Control-Allow-Methods: GET, PUT, PATCH, DELETE, POST\r\n"
                               "Access-Control-Allow-Headers: Authorization, Content-Type, If-Match, If-None-Match, Last-Event-ID\r\n"
                               "Access-Control-Max-Age: 600\r\n"
                             : ""));
        return;
    }
    principal who;
    bool by_cookie = false;
    std::string why;
    if (!who_of(rq, who, by_cookie, why))
    {
        respond(c, 401, error_body("bad_credentials", why), allow + "WWW-Authenticate: Bearer\r\n");
        return;
    }
    const bool reads = rq.method == "GET" || rq.method == "HEAD";
    // A browser's cookie goes along with a form another page posts, which can say neither JSON nor this host.
    if (by_cookie && !reads)
    {
        const bool json = rq.content_type.starts_with("application/json") || rq.method == "DELETE";
        const bool same_site = rq.origin.empty() || rq.origin == "https://" + rq.host ||
                               rq.origin == "http://" + rq.host ||
                               std::find(m_origins.begin(), m_origins.end(), rq.origin) != m_origins.end();
        if (!json || !same_site)
        {
            respond(c, json ? 403 : 415,
                    error_body("cross_site", "a write signed in by the cookie is sent as application/json from this "
                                             "host or an origin of --origins"),
                    allow);
            return;
        }
    }
    if (rq.path == "/me")
    {
        if (who.kind == principal::anyone)
            respond(c, 401, error_body("sign_in", "nobody is signed in"), allow);
        else
        {
            std::string body = who.kind == principal::key ? "{\"key\":" : "{\"sub\":";
            socketley::json::quote_into(body, who.sub);
            body += '}';
            respond(c, 200, body, allow);
        }
        return;
    }
    if (rq.path == "/" && reads)
    {
        std::string body = "{\"database\":";
        socketley::json::quote_into(body, m_owner.get_name());
        if (who.kind == principal::key)
        {
            body += ",\"collections\":[";
            bool first = true;
            for (const auto& name : m_store.collection_names())
            {
                body += first ? "" : ",";
                first = false;
                socketley::json::quote_into(body, name);
            }
            body += ']';
        }
        body += '}';
        respond(c, 200, body, allow);
        return;
    }
    // A path with no % is its own spelling, read where it lies.
    std::string unescaped;
    if (rq.path.find('%') != std::string::npos && !socketley::http::percent_decode(rq.path, unescaped, false))
    {
        respond(c, 400, error_body("bad_path", "the path holds a % that spells no byte"), allow);
        return;
    }
    const std::string_view path = unescaped.empty() ? std::string_view(rq.path) : std::string_view(unescaped);
    // Streams of changes: a collection's as its reader may see them, every one's for a key, and a replica's.
    const bool feed = path.ends_with("/_feed") && path.starts_with("/c/");
    if ((path == "/_feed" || path == "/_replicate" || feed) && reads)
    {
        std::string coll;
        if (feed)
        {
            coll = path.substr(3, path.size() - 3 - 6);
            if (!valid_collection(coll))
            {
                respond(c, 400, error_body("bad_collection", "a collection's name is 1 to 64 of a-z 0-9 _ -"), allow);
                return;
            }
            const collection_def* def = m_store.get_schema().find(coll);
            const access acc = def ? def->acc : access::priv;
            if (who.kind == principal::anyone && (acc == access::priv || acc == access::owner || acc == access::shared))
            {
                respond(c, 401, error_body("sign_in", "this collection is read by a signed-in account or a key"), allow);
                return;
            }
            if (who.kind == principal::user && acc == access::priv)
            {
                respond(c, 403, error_body("forbidden", "this collection is reached by a key only"), allow);
                return;
            }
        }
        else if (who.kind != principal::key)
        {
            respond(c, who.kind == principal::anyone ? 401 : 403,
                    error_body("key_only", "every collection's changes are streamed to a key only"), allow);
            return;
        }
        if (m_reader && !m_ready)
        {
            respond(c, 503, error_body("starting", "this shard is still reading the log; try again"), allow);
            return;
        }
        c->who = who;
        open_feed(c, rq, coll, !feed, path == "/_replicate");
        return;
    }
    // A read is tried first without waiting for the disk, so a document it needs from there is brought through the
    // ring while every other connection is answered; past a few tries it waits as a write does.
    std::vector<location> wanted;
    const bool probing = (reads || (rq.method == "POST" && path.ends_with("/_query"))) && c->probes < 3;
    m_store.probe(probing ? &wanted : nullptr, &c->fetched);
    const counters before = m_c;
    answer a = execute(who, rq.method, path, rq.body, rq.if_match, rq.if_none_match);
    m_store.probe(nullptr, nullptr);
    if (probing && !wanted.empty() && !a.forward)
    {
        // The try is not the answer, and is not counted as one.
        m_c = before;
        m_c.fetched += wanted.size();
        fetch_and_retry(c, rq, std::move(wanted));
        return;
    }
    c->fetched.clear();
    c->probes = 0;
    if (a.forward)
    {
        // Answered when shard 0 has, and nothing behind it on this connection meanwhile.
        c->waiting = true;
        if (!cross(a.forward - 1, crossing{who, rq.method, path, rq.body, rq.if_match, rq.if_none_match},
                   crossed{c, 0, rq.method == "HEAD", allow}))
        {
            c->waiting = false;
            respond(c, 503, error_body("shard_unreachable", "shard 0, which writes, could not be asked"), allow);
        }
        return;
    }
    const bool head_only = rq.method == "HEAD";
    if (a.needs <= m_durable)
        respond(c, a.status, a.body, allow, a.version, head_only);
    else
    {
        // Rests on a change not yet on the disk: answered once it is, and nothing behind it read meanwhile.
        if (a.status >= 400)
            ++m_c.refused;
        std::string reply;
        put_head(reply, *c, a.status, "application/json", a.body.size(), allow, a.version);
        if (!head_only)
            reply += a.body;
        hold(waiter{a.needs, c, std::move(reply), 0, false});
    }
    m_spare.swap(a.body);
    // A buffer one large answer grew is not held for the small ones after it.
    if (m_spare.capacity() > (1u << 20))
        std::string().swap(m_spare);
}

void db_run::fetch_and_retry(const std::shared_ptr<conn>& c, const request& rq, std::vector<location> wanted)
{
    struct job
    {
        request rq;
        std::vector<store::fetched_doc> docs;
        size_t left{0};
    };
    auto j = std::make_shared<job>();
    j->rq = rq;
    std::sort(wanted.begin(), wanted.end(), [](const location& a, const location& b) {
        return std::tie(a.seg, a.off) < std::tie(b.seg, b.off);
    });
    wanted.erase(std::unique(wanted.begin(), wanted.end(), [](const location& a, const location& b) {
                     return a.seg == b.seg && a.off == b.off;
                 }), wanted.end());
    // What the tries before brought stays, for a read that needs it again.
    j->docs = std::move(c->fetched);
    c->fetched.clear();
    ++c->probes;
    c->waiting = true;
    const auto done = [this, j, weak = std::weak_ptr<conn>(c)]
    {
        auto cc = weak.lock();
        if (m_stopped || !cc || cc->dead)
            return;
        std::erase_if(j->docs, [](const store::fetched_doc& f) { return f.json.size() != f.at.len; });
        std::sort(j->docs.begin(), j->docs.end(), [](const store::fetched_doc& a, const store::fetched_doc& b) {
            return std::tie(a.at.seg, a.at.off) < std::tie(b.at.seg, b.at.off);
        });
        cc->fetched = std::move(j->docs);
        cc->waiting = false;
        handle(cc, j->rq);
        if (!cc->waiting)
            m_http.resume(cc);
    };
    const size_t had = j->docs.size();
    j->docs.resize(had + wanted.size());
    j->left = wanted.size() + 1;
    for (size_t i = 0; i < wanted.size(); ++i)
    {
        store::fetched_doc& f = j->docs[had + i];
        f.at = wanted[i];
        f.json.resize(f.at.len);
        const int fd = m_store.dup_fd_of(f.at);
        // One that cannot be read through the ring is read in line at the next try.
        if (fd < 0 || !m_io.pread(fd, f.json.data(), f.at.len, f.at.off, [j, &f, fd, done](int64_t res) {
                ::close(fd);
                if (res != static_cast<int64_t>(f.at.len))
                    f.json.clear();
                if (--j->left == 0)
                    done();
            }))
        {
            if (fd >= 0)
                ::close(fd);
            f.json.clear();
            --j->left;
        }
    }
    if (--j->left == 0)
        done();
}

db_run::answer db_run::spare_answer()
{
    answer a;
    a.body.swap(m_spare);
    a.body.clear();
    return a;
}

db_run::answer db_run::execute(const principal& who, std::string_view method, std::string_view path,
                               std::string_view body, std::string_view if_match, std::string_view if_none_match,
                               bool sibling)
{
    if (m_broken)
        return refused(503, "not_durable", "the journal could not be written to the disk; restart the database");
    // A copy answers reads, a query among them, and leaves every write to the database it copies.
    const bool reading = method == "GET" || method == "HEAD" || (method == "POST" && path.ends_with("/_query"));
    if (!m_owner.get_replicate().empty() && !reading)
        return refused(403, "read_only", "this database is a copy of " + std::string(m_owner.get_replicate()) +
                                             "; write there");
    // A shard reading shard 0's log sends it the writes, and every request until the log is open.
    if (m_reader && !sibling && (!reading || !m_ready))
    {
        answer a;
        a.forward = 1;
        return a;
    }
    const auto parse_body = [&](jvalue& out) {
        return json_reader(body).document(out);
    };
    std::vector<write_op> ops;
    error err;
    std::string coll, id;
    bool is_tx = false;
    if (path == "/tx")
    {
        if (method != "POST")
            return refused(405, "method", "a transaction is POSTed");
        is_tx = true;
        jvalue doc;
        const jvalue* list = nullptr;
        if (!parse_body(doc) || !(list = member(doc, "ops")) || list->k != jvalue::kind::array)
            return refused(400, "bad_write", "a transaction is {\"ops\":[...]}");
        for (const auto& o : list->items)
        {
            write_op op;
            const jvalue* kind = string_member(o, "op");
            const jvalue* c = string_member(o, "c");
            const jvalue* i = string_member(o, "id");
            if (!kind || !c)
                return refused(400, "bad_write", "each change names its op and its collection, c");
            op.coll = c->s;
            op.id = i ? i->s : std::string();
            if (kind->s == "put" || kind->s == "insert")
            {
                op.kind = kind->s == "put" ? write_op::put : write_op::insert;
                const jvalue* d = member(o, "doc");
                if (!d)
                    return refused(400, "bad_write", "a put or an insert carries its doc");
                op.body = *d;
            }
            else if (kind->s == "patch")
            {
                op.kind = write_op::patch;
                const jvalue* d = member(o, "changes");
                if (!d)
                    return refused(400, "bad_write", "a patch carries its changes");
                op.body = *d;
            }
            else if (kind->s == "delete")
                op.kind = write_op::del;
            else
                return refused(400, "bad_write", "an op is put, insert, patch or delete");
            if (const jvalue* v = member(o, "if"); v && v->k != jvalue::kind::null)
            {
                const bool text = v->k == jvalue::kind::string || v->k == jvalue::kind::number;
                op.if_v = text ? version_of(v->s) : 0;
                if (!op.if_v && !(text && v->s == "*"))
                    return refused(400, "bad_precondition", "an op's if names a version, 3");
            }
            if (const jvalue* v = member(o, "if_absent"); v && v->k != jvalue::kind::null)
            {
                if (v->k != jvalue::kind::boolean)
                    return refused(400, "bad_precondition", "an op's if_absent is true or false");
                op.if_absent = v->b;
            }
            ops.push_back(std::move(op));
        }
    }
    else
    {
        if (!path.starts_with("/c/"))
            return refused(404, "not_found", "the API is /c/<collection>[/<id>|/_query] and /tx");
        std::string_view rest = path.substr(3);
        const size_t slash = rest.find('/');
        coll = std::string(rest.substr(0, slash));
        id = slash == std::string_view::npos ? std::string() : std::string(rest.substr(slash + 1));
        if (!valid_collection(coll))
            return refused(400, "bad_collection", "a collection's name is 1 to 64 of a-z 0-9 _ -, a letter first");
        if (id == "_query")
        {
            if (method != "POST")
                return refused(405, "method", "a query is POSTed");
            jvalue q;
            query parsed;
            if (!body.empty() && !parse_body(q))
                return refused(400, "bad_query", "a query is a JSON object");
            if (!body.empty() && !store::parse_query(q, parsed, err))
                return refused(err);
            answer a = spare_answer();
            if (!m_store.find(who, coll, parsed, a.body, err, a.needs))
                return refused(err);
            ++m_c.queries;
            return a;
        }
        if (id.empty())
        {
            if (method != "POST")
                return refused(405, "method", "a document is POSTed to its collection, or PUT at its id");
            write_op op;
            op.kind = write_op::insert;
            op.coll = coll;
            if (!parse_body(op.body))
                return refused(400, "bad_document", "a document is a JSON object");
            ops.push_back(std::move(op));
        }
        else if (method == "GET" || method == "HEAD")
        {
            answer a = spare_answer();
            if (!m_store.read(who, coll, id, a.body, err, a.needs, &a.version))
            {
                // An absence rests on the last change too: one not yet on the disk may be its deletion.
                answer r = refused(err);
                r.needs = a.needs;
                return r;
            }
            ++m_c.reads;
            return a;
        }
        else
        {
            write_op op;
            op.coll = coll;
            op.id = id;
            op.if_v = version_of(if_match);
            if (!if_match.empty() && !op.if_v && if_match != "*")
                return refused(400, "bad_precondition", "If-Match names a version, \"3\"");
            if (method == "PUT")
            {
                op.kind = write_op::put;
                op.if_absent = if_none_match == "*";
                if (!parse_body(op.body))
                    return refused(400, "bad_document", "a document is a JSON object");
            }
            else if (method == "PATCH")
            {
                op.kind = write_op::patch;
                if (!parse_body(op.body))
                    return refused(400, "bad_patch", "a patch is a JSON object of set, unset, inc, push and pull");
            }
            else if (method == "DELETE")
                op.kind = write_op::del;
            else
                return refused(405, "method", "a document is read with GET and written with PUT, PATCH and DELETE");
            ops.push_back(std::move(op));
        }
    }

    // The store writes its results into the answer itself.
    answer a = spare_answer();
    if (is_tx)
        a.body = "{\"results\":";
    std::vector<event> evs;
    store::first_change first;
    if (!m_store.write(who, ops, a.body, err, &evs, &first))
    {
        m_spare.swap(a.body);
        if (err.status == 409 || err.status == 412)
            ++m_c.conflicts;
        return refused(err);
    }
    ++m_c.writes;
    a.needs = m_store.seq();
    for (auto& e : evs)
        m_unpublished.push_back(std::move(e));
    if (is_tx)
    {
        a.body += '}';
        return a;
    }
    // One change: its document, or its deletion, not the list a transaction answers.
    a.body.pop_back();
    a.body.erase(0, 1);
    if (ops[0].kind != write_op::del)
    {
        a.version = first.version;
        if (ops[0].kind == write_op::insert || (ops[0].kind == write_op::put && !first.existed))
            a.status = 201;
    }
    return a;
}

void db_run::call(uint64_t ticket, std::string_view json)
{
    ++m_c.calls;
    auto* mgr = m_owner.get_runtime_manager();
    if (!mgr)
        return;
    jvalue req;
    answer a;
    const jvalue* method = nullptr;
    const jvalue* path = nullptr;
    const bool parsed = json_reader(json).document(req);
    // A backup the daemon asks for, into the file it names: started and numbered at once, since it may take long,
    // and asked after by its number.
    if (const jvalue* file = parsed ? string_member(req, "backup") : nullptr)
    {
        if (!file->s.starts_with('/'))
        {
            mgr->requests().complete_deferred(
                ticket, request_status::ok,
                "{\"status\":400,\"body\":" + error_body("bad_path", "the backup's file is an absolute path") + "}");
            return;
        }
        auto job = m_store.plan_backup(file->s);
        if (!job)
        {
            mgr->requests().complete_deferred(
                ticket, request_status::ok,
                "{\"status\":409,\"body\":" +
                    error_body("busy", "a merge or another backup is running; try again") + "}");
            return;
        }
        const uint64_t id = m_next_backup_id++;
        m_backups[id].file = file->s;
        start_job(std::move(job), id);
        mgr->requests().complete_deferred(ticket, request_status::ok,
                                          "{\"status\":202,\"body\":{\"job\":" + std::to_string(id) + "}}");
        return;
    }
    if (const jvalue* id = parsed ? member(req, "backup_status") : nullptr)
    {
        uint64_t n = 0;
        std::from_chars(id->s.data(), id->s.data() + id->s.size(), n);
        const auto it = m_backups.find(n);
        std::string body;
        if (it == m_backups.end())
            body = "{\"status\":404,\"body\":" + error_body("not_found", "no backup of that number") + "}";
        else
        {
            body = "{\"status\":200,\"body\":{\"done\":" + std::string(it->second.done ? "true" : "false") +
                   ",\"ok\":" + (it->second.ok ? "true" : "false") + ",\"documents\":" +
                   std::to_string(it->second.documents) + ",\"file\":";
            socketley::json::quote_into(body, it->second.file);
            body += ",\"message\":";
            socketley::json::quote_into(body, it->second.why);
            body += "}}";
            if (it->second.done)
                m_backups.erase(it);
        }
        mgr->requests().complete_deferred(ticket, request_status::ok, body);
        return;
    }
    if (!parsed || !(method = string_member(req, "method")) || !(path = string_member(req, "path")))
        a = refused(400, "bad_call", "a call is {\"method\":..,\"path\":..[,\"body\":..]}");
    else
    {
        std::string body;
        if (const jvalue* b = member(req, "body"))
            json::write_into(body, *b);
        const jvalue* im = string_member(req, "if_match");
        const jvalue* inm = string_member(req, "if_none_match");
        // A script of this daemon is the operator's own code, as a key is.
        a = execute(principal{principal::key, "script"}, method->s, path->s, body, im ? im->s : std::string_view{},
                    inm ? inm->s : std::string_view{});
    }
    std::string reply = "{\"status\":" + std::to_string(a.status) + ",\"body\":" + (a.body.empty() ? "null" : a.body) + "}";
    if (a.needs > m_durable)
        hold(waiter{a.needs, nullptr, std::move(reply), ticket, true});
    else
        mgr->requests().complete_deferred(ticket, request_status::ok, reply);
}

// ─── Shards ─────────────────────────────────────────────────────────────────

uint64_t db_run::log_word(uint32_t k) const
{
    return m_owner.shard_stats_table().word_at(0, k);
}

void db_run::publish_log()
{
    if (m_shards <= 1 || m_reader)
        return;
    const uint64_t layout = m_store.layout() + 1;
    if (m_durable == m_told_durable && layout == m_told_layout)
        return;
    const bool relaid = layout != m_told_layout;
    m_told_durable = m_durable;
    m_told_layout = layout;
    m_owner.shard_stats_table().publish_words(m_durable, layout);
    // A word to each reading shard that holds a stream, so it hears of the change without waiting for a read or a
    // tick, and to every one when the segments changed, as a starting shard waits for that to open the log; one with
    // no stream reads a change at its next request.  Ordered against the reader's count and its read.
    std::atomic_thread_fence(std::memory_order_seq_cst);
    for (uint32_t j = 1; j < m_shards; ++j)
        if (relaid || m_owner.shard_stats_table().word_at(j, 0) != 0)
            nudge(j);
}

const std::string& db_run::target_of(uint32_t shard)
{
    // The name does not change while the runtime runs, so each shard's address is made once.
    if (m_targets.size() < m_shards)
        for (uint32_t j = static_cast<uint32_t>(m_targets.size()); j < m_shards; ++j)
            m_targets.push_back(shard_target(m_owner.get_name(), j));
    return m_targets[shard];
}

void db_run::tell_feeds()
{
    if (m_shards <= 1 || !m_reader || m_feeds.size() == m_told_feeds)
        return;
    m_told_feeds = m_feeds.size();
    m_owner.shard_stats_table().publish_words(m_told_feeds, 0);
    std::atomic_thread_fence(std::memory_order_seq_cst);
}

// The cookie of a nudge, above every crossing's, names the shard it went to.
static constexpr uint64_t nudge_cookie = uint64_t(1) << 63;

void db_run::nudge(uint32_t j)
{
    if (m_nudge_flying.size() < m_shards)
    {
        m_nudge_flying.resize(m_shards, 0);
        m_nudge_owed.resize(m_shards, 0);
        m_nudge_sent.resize(m_shards);
    }
    // A nudge only says there is more log, so one already on its way says it for this one too; a reply lost on a
    // link that went down is not waited for past a second.
    const auto now = std::chrono::steady_clock::now();
    if (m_nudge_flying[j] && now - m_nudge_sent[j] < std::chrono::seconds(1))
    {
        m_nudge_owed[j] = 1;
        return;
    }
    auto* mgr = m_owner.get_runtime_manager();
    const bool sent = mgr && mgr->requests().post(this, nudge_cookie | j, target_of(j), nudge_marker,
                                                  request_class::background);
    m_nudge_flying[j] = sent;
    m_nudge_owed[j] = !sent;
    m_nudge_sent[j] = now;
    m_c.nudges += sent;
}

void db_run::try_follow()
{
    if (!m_reader || m_ready || m_stopped)
        return;
    // Shard 0 says its log is open by saying how often its segments changed, one at least.
    const uint64_t layout = log_word(1);
    if (!layout)
        return;
    std::string why;
    const schema wanted = m_store.get_schema();
    if (!m_store.follow_open(db_data_dir(m_owner.get_name()), wanted, log_word(0), why))
    {
        // Said once a reason, since it is tried again every second.
        if (why != m_follow_error)
            LOG_WARN(("db " + std::string(m_owner.get_name()) + " shard " + std::to_string(m_shard) +
                      ": shard 0's log could not be read yet: " + why)
                         .c_str());
        m_follow_error = why;
        return;
    }
    m_follow_error.clear();
    m_ready = true;
    m_seen_layout = layout;
    m_durable = m_store.seq();
    m_history.clear();
    m_history_bytes = 0;
    m_history_from = m_durable + 1;
}

void db_run::catch_up()
{
    if (!m_reader)
        return;
    if (!m_ready)
    {
        try_follow();
        return;
    }
    // The durable change before the layout, since shard 0 says the layout first and a merge it says is then not missed.
    const uint64_t durable = log_word(0);
    const uint64_t layout = log_word(1);
    if (layout == m_seen_layout && durable <= m_store.seq())
        return;
    // The changes are made into events only while a stream may want them; past that the history has a gap and is let
    // go, so a resume from inside it is told reset.
    std::vector<event> evs;
    const bool tell = feeds_near(wall::now_sec_coarse());
    if (!m_store.follow(durable, tell ? &evs : nullptr))
    {
        // The log no longer goes on from where this shard stood -- cleared, restored, merged past -- so it is read
        // again whole, and its streams start over as a replica's do after a reset.
        ++m_c.reopened;
        m_ready = false;
        std::vector<std::shared_ptr<conn>> streams = m_feeds;
        for (auto& c : streams)
            m_http.close_conn(c);
        try_follow();
        return;
    }
    if (layout != m_seen_layout)
    {
        m_store.follow_layout();
        m_seen_layout = layout;
    }
    ++m_c.caught_up;
    for (auto& e : evs)
        m_unpublished.push_back(std::move(e));
    m_durable = m_store.seq();
    if (!tell)
    {
        m_history.clear();
        m_history_bytes = 0;
        m_history_from = m_durable + 1;
    }
    publish();
}

void db_run::nudged()
{
    catch_up();
}

bool db_run::cross(uint32_t shard, const crossing& what, crossed then)
{
    auto* mgr = m_owner.get_runtime_manager();
    if (!mgr)
        return false;
    const uint64_t cookie = m_next_cookie++;
    m_crossed.emplace(cookie, std::move(then));
    // The write's body copied once, into the call the channel then keeps.
    if (!mgr->requests().post_owned(this, cookie, target_of(shard), encode_crossing(what)))
    {
        m_crossed.erase(cookie);
        return false;
    }
    ++m_c.crossed;
    return true;
}

void db_run::on_request_reply(uint64_t cookie, request_status st, std::string_view reply)
{
    // A nudge's answer says nothing but that the next may go.
    if (cookie & nudge_cookie)
    {
        const uint32_t j = static_cast<uint32_t>(cookie & ~nudge_cookie);
        if (j < m_nudge_flying.size())
        {
            m_nudge_flying[j] = 0;
            if (m_nudge_owed[j])
                nudge(j);
        }
        return;
    }
    const auto it = m_crossed.find(cookie);
    if (it == m_crossed.end())
        return;
    crossed then = std::move(it->second);
    m_crossed.erase(it);
    int status = 503;
    uint64_t version = 0;
    std::string_view body;
    std::string refusal;
    if (st != request_status::ok || !decode_crossing_reply(reply, status, version, body))
    {
        status = 503;
        version = 0;
        refusal = error_body("shard_unreachable", "shard 0, which writes, did not answer");
        body = refusal;
    }
    deliver(then, status, body, version);
}

void db_run::deliver(const crossed& to, int status, std::string_view body, uint64_t version)
{
    if (to.ticket)
    {
        std::string out = "{\"status\":" + std::to_string(status) + ",\"body\":";
        out += body.empty() ? std::string_view("null") : body;
        out += '}';
        if (auto* mgr = m_owner.get_runtime_manager())
            mgr->requests().complete_deferred(to.ticket, request_status::ok, out);
        return;
    }
    const std::shared_ptr<conn> c = to.c.lock();
    if (!c || c->dead)
        return;
    // Shard 0 answered once the write was on its disk and had said so first, so a read behind it here sees it.
    catch_up();
    respond(c, status, body, to.allow, version, to.head);
    m_http.resume(c);
}

void db_run::cross_call(uint64_t ticket, std::string_view payload)
{
    auto* mgr = m_owner.get_runtime_manager();
    if (!mgr)
        return;
    crossing what;
    if (m_reader || !decode_crossing(payload, what))
    {
        mgr->requests().complete_deferred(
            ticket, request_status::ok,
            encode_crossing_reply(421, 0, error_body("misdirected", "a shard's write is shard 0's to take")));
        return;
    }
    ++m_c.crossings_served;
    answer a = execute(what.who, what.method, what.path, what.body, what.if_match, what.if_none_match, true);
    std::string reply = encode_crossing_reply(a.status, a.version, a.body);
    // The answer's buffer serves the next one, as serve() keeps it.
    m_spare.swap(a.body);
    if (m_spare.capacity() > (1u << 20))
        std::string().swap(m_spare);
    if (a.needs > m_durable)
        hold(waiter{a.needs, nullptr, std::move(reply), ticket, true});
    else
        mgr->requests().complete_deferred(ticket, request_status::ok, reply);
}

}   // namespace socketley::db
