#include "db_run.h"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstring>
#include <filesystem>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "db_instance.h"
#include "../../shared/http_framing.h"
#include "../../shared/https_client.h"
#include "../../shared/logging.h"
#include "../../shared/replaced_file.h"
#include "../../shared/runtime_manager.h"

namespace socketley::db
{

namespace
{

constexpr int64_t idle_secs = 120;
constexpr size_t  max_head  = 16 * 1024;
constexpr size_t  max_body  = 4u << 20;
constexpr size_t  max_conns = 4096;

int64_t now_sec()
{
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

const char* reason(int status)
{
    switch (status)
    {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 409: return "Conflict";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Content Too Large";
        case 415: return "Unsupported Media Type";
        case 431: return "Request Header Fields Too Large";
        case 503: return "Service Unavailable";
        case 507: return "Insufficient Storage";
        default:  return "Error";
    }
}

std::string error_body(std::string_view code, std::string_view message)
{
    std::string out = "{\"error\":";
    write_string(code, out);
    out += ",\"message\":";
    write_string(message, out);
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

// A path's segment with its %XX spelled out; false for a % that spells nothing or a byte no id holds.
bool unescape(std::string_view in, std::string& out)
{
    out.clear();
    for (size_t i = 0; i < in.size(); ++i)
    {
        if (in[i] != '%')
        {
            out += in[i];
            continue;
        }
        unsigned v = 0;
        if (i + 2 >= in.size() || std::from_chars(in.data() + i + 1, in.data() + i + 3, v, 16).ptr != in.data() + i + 3)
            return false;
        out += static_cast<char>(v);
        i += 2;
    }
    return true;
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

int64_t mtime_of(const std::string& path)
{
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0)
        return 0;
    return static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec + static_cast<int64_t>(st.st_size);
}

const jvalue* string_member(const jvalue& obj, std::string_view name)
{
    const jvalue* m = member(obj, name);
    return m && m->k == jvalue::kind::string ? m : nullptr;
}

}   // namespace


db_run::db_run(db_instance& owner, event_loop& loop) : m_owner(owner), m_loop(loop), m_io(loop, this) {}

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
        m_schema_mtime = mtime_of(path);
    }
    m_store.set_cache_bytes(m_owner.get_cache_bytes());
    if (!m_store.open(db_data_dir(m_owner.get_name()), s, why))
        return false;
    m_store.set_max_bytes(m_owner.get_max_bytes());
    m_durable = m_store.seq();
    m_history_from = m_durable + 1;
    m_files_checked = 0;
    reload_files(why);
    if (!why.empty())
        return false;
    m_idp.configure(m_owner.get_idp());
    for (std::string_view list = m_owner.get_origins(); !list.empty();)
    {
        const size_t comma = list.find(',');
        const std::string_view one = http_trim_ows(list.substr(0, comma));
        list = comma == std::string_view::npos ? std::string_view{} : list.substr(comma + 1);
        if (!one.empty())
            m_origins.emplace_back(one);
    }

    const uint16_t port = m_owner.effective_port();
    m_listen_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (m_listen_fd < 0)
    {
        why = std::string("no socket: ") + std::strerror(errno);
        return false;
    }
    int one = 1;
    ::setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = m_owner.bind_in_addr();
    a.sin_port = htons(port);
    if (::bind(m_listen_fd, reinterpret_cast<sockaddr*>(&a), sizeof a) < 0 || ::listen(m_listen_fd, 1024) < 0)
    {
        why = "port " + std::to_string(port) + " could not be bound: " + std::strerror(errno);
        ::close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }
    m_wake_fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (m_wake_fd < 0)
    {
        why = "no eventfd for work off the loop";
        return false;
    }
    m_loop.register_owner(this);
    arm_accept();
    arm_wake();
    if (!m_owner.get_backup_dir().empty())
        m_next_backup = now_sec() + m_owner.get_backup_every();
    if (!m_owner.get_replicate().empty())
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
    if (m_listen_fd >= 0)
    {
        ::shutdown(m_listen_fd, SHUT_RDWR);
        m_loop.close_fd(m_listen_fd);
        m_listen_fd = -1;
    }
    std::vector<std::shared_ptr<conn>> all;
    for (auto& [id, c] : m_conns)
        all.push_back(c);
    for (auto& c : all)
        close_conn(c);
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
    return m_loop.owner_inflight(this) == 0 && !m_loop.owner_table_full();
}

void db_run::on_loop_turn()
{
    if (m_stopped)
        return;
    finish_turn();
    maybe_merge();
    // A listener whose accept the ring had no room for is asked again here, or it would be deaf for good.
    if (!m_accept_pending)
        arm_accept();
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
            w.c->out += head(*w.c, 503, "application/json", body.size(), {});
            w.c->out += body;
            w.c->waiting = false;
            flush(w.c);
        }
        return;
    }
    m_durable = std::max(m_durable, covered);
    m_replica_seq = m_durable;
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
        w.c->out += w.held;
        if (m_stopped)
            w.c->waiting = false;
        else
            resume(w.c);
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
    write_string(e.coll, o);
    o += ",\"id\":";
    write_string(e.id, o);
    if (!e.owner.empty())
    {
        o += ",\"owner\":";
        write_string(e.owner, o);
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

void db_run::publish()
{
    constexpr size_t history_bytes = 32u << 20;
    while (!m_unpublished.empty() && m_unpublished.front().seq <= m_durable)
    {
        event e = std::move(m_unpublished.front());
        m_unpublished.pop_front();
        for (size_t i = 0; i < m_feeds.size(); ++i)
        {
            const std::shared_ptr<conn> c = m_feeds[i];
            if (c->dead || !c->dump.empty() || !sees(*c, e))
                continue;
            send_event(*c, e);
            // A stream that reads slower than changes come is let go; it resumes from the last one it read.
            if (c->out.size() - c->out_off > (16u << 20))
                close_conn(c);
            else
                flush(c);
        }
        m_history_bytes += e.json.size() + e.coll.size() + e.id.size() + 64;
        m_history.push_back(std::move(e));
        while (m_history_bytes > history_bytes && !m_history.empty())
        {
            const event& f = m_history.front();
            m_history_bytes -= f.json.size() + f.coll.size() + f.id.size() + 64;
            m_history_from = f.seq + 1;
            m_history.pop_front();
        }
    }
    std::erase_if(m_feeds, [](const std::shared_ptr<conn>& c) { return c->dead; });
}

void db_run::open_feed(const std::shared_ptr<conn>& c, const request& rq, std::string coll, bool all, bool replica)
{
    // Where the stream starts: after the change it names, or now.
    uint64_t since = m_durable;
    bool named = false;
    std::string_view s = rq.last_event_id;
    for (std::string_view q = rq.query; s.empty() && !q.empty();)
    {
        const size_t amp = q.find('&');
        const std::string_view kv = q.substr(0, amp);
        q = amp == std::string_view::npos ? std::string_view{} : q.substr(amp + 1);
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
    ++m_c.feeds;
    c->out += "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\n"
              "X-Accel-Buffering: no\r\nX-Content-Type-Options: nosniff\r\n" +
              cors(rq) + "Connection: close\r\n\r\n";
    // A count the database never reached is a copy of another past: it is told everything again.
    const bool kept = named && since <= m_durable && since + 1 >= m_history_from;
    if (!named || since == m_durable || kept)
    {
        for (const auto& e : m_history)
            if (e.seq > since && sees(*c, e))
                send_event(*c, e);
        flush(c);
        arm_tick();
        return;
    }
    c->out += "id: " + std::to_string(m_durable) + "\nevent: reset\ndata: {}\n\n";
    if (!replica)
    {
        // A page told to read again what it shows, and then the changes after it.
        flush(c);
        arm_tick();
        return;
    }
    c->dump = m_store.everything();
    c->dump_at = 0;
    c->dump_seq = m_store.seq();
    m_store.pin();
    pump_dump(c);
    arm_tick();
}

void db_run::pump_dump(const std::shared_ptr<conn>& c)
{
    std::string json;
    while (!c->dump.empty() && c->out.size() - c->out_off < (1u << 20))
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
                m_store.pin();
                continue;
            }
            for (const auto& e : m_history)
                if (e.seq > c->dump_seq)
                    send_event(*c, e);
            break;
        }
        const auto& it = c->dump[c->dump_at++];
        if (!m_store.body_at(it.from, json))
        {
            close_conn(c);
            return;
        }
        send_event(*c, event{it.seq, it.coll, it.id, it.owner, it.v, false, json});
    }
    flush(c);
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
        const uint64_t one = 1;
        if (::write(wake, &one, sizeof one) < 0) {}
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
                    if (n.starts_with(prefix) && n.ends_with(".dbbackup"))
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
    if (!m_jobs.empty())
        return;
    if (auto job = m_store.plan_merge())
        start_job(std::move(job), 0);
}

void db_run::scheduled_backup()
{
    if (m_owner.get_backup_dir().empty() || now_sec() < m_next_backup)
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
    m_next_backup = now_sec() + m_owner.get_backup_every();
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
    const auto wake = [this] {
        const uint64_t one = 1;
        if (::write(m_wake_fd, &one, sizeof one) < 0) {}
    };
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
                        const size_t nl = rest.find('\n');
                        const std::string_view line = rest.substr(0, nl);
                        rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
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
                        write_json(*d, e.json);
                    }
                    got.push_back(std::move(e));
                }
                if (!got.empty() || reset || mark)
                {
                    std::lock_guard lk(m_replica_mu);
                    if (reset)
                    {
                        m_replica_in.clear();
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
        if (!m_store.reset(why))
        {
            LOG_ERROR(("db " + std::string(m_owner.get_name()) + ": the copy could not be emptied: " + why).c_str());
            m_broken = true;
            return;
        }
        m_durable = 0;
        m_history.clear();
        m_history_bytes = 0;
        m_history_from = 1;
        m_unpublished.clear();
        // Streams of this database, past what it now holds, start over.
        std::vector<std::shared_ptr<conn>> feeds;
        for (auto& [id, c] : m_conns)
            if (c->feed)
                feeds.push_back(c);
        for (auto& c : feeds)
            close_conn(c);
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
    size_t feeds = 0;
    for (const auto& [id, c] : m_conns)
        feeds += c->feed ? 1 : 0;
    return "documents:" + std::to_string(m_store.documents()) + "\ncollections:" + std::to_string(m_store.collections()) +
           "\nbytes:" + std::to_string(m_store.bytes()) + "\nmax_bytes:" + std::to_string(m_owner.get_max_bytes()) +
           "\ndisk_bytes:" + std::to_string(m_store.disk_bytes()) + "\nsegments:" + std::to_string(m_store.segments()) +
           "\nmerges:" + std::to_string(m_store.merges()) + "\ncache_hits:" + std::to_string(m_store.cache_hits()) +
           "\ncache_misses:" + std::to_string(m_store.cache_misses()) + "\nseq:" + std::to_string(m_store.seq()) +
           "\ndurable:" + std::to_string(m_durable) + "\nkeys:" + std::to_string(m_keys.size()) +
           "\nreads:" + std::to_string(m_c.reads) + "\nwrites:" + std::to_string(m_c.writes) +
           "\nqueries:" + std::to_string(m_c.queries) + "\nsyncs:" + std::to_string(m_c.syncs) +
           "\nrefused:" + std::to_string(m_c.refused) + "\nconflicts:" + std::to_string(m_c.conflicts) +
           "\nexpired:" + std::to_string(m_c.expired) + "\nfeeds:" + std::to_string(feeds) +
           "\nevents_sent:" + std::to_string(m_c.events) + "\nbackups:" + std::to_string(m_c.backups) +
           "\nbackup_failures:" + std::to_string(m_c.backup_failures) + "\nscript_calls:" + std::to_string(m_c.calls) +
           replica + (m_broken ? "\nbroken:the journal could not be synced; restart" : "") +
           (m_schema_error.empty() ? std::string() : "\nschema_error:" + m_schema_error) +
           (m_keys_error.empty() ? std::string() : "\nkeys_error:" + m_keys_error) + "\n";
}

void db_run::reload_files(std::string& why)
{
    const bool first = m_files_checked == 0;
    const int64_t now = now_sec();
    if (!first && now == m_files_checked)
        return;
    m_files_checked = now;
    if (const std::string path(m_owner.get_schema_path()); !path.empty())
    {
        if (const int64_t mt = mtime_of(path); mt != m_schema_mtime)
        {
            m_schema_mtime = mt;
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
        if (const int64_t mt = mtime_of(path); mt != m_keys_mtime)
        {
            m_keys_mtime = mt;
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

void db_run::arm_accept()
{
    if (m_stopped || m_listen_fd < 0 || m_accept_pending)
        return;
    m_accept_req = io_request{};
    m_accept_req.owner = this;
    m_accept_req.fd = m_listen_fd;
    m_accept_req.type = event_loop::supports_multishot_accept() ? op_multishot_accept : op_accept;
    m_accept_pending = m_accept_req.type == op_multishot_accept
                           ? m_loop.submit_multishot_accept(m_listen_fd, &m_accept_req)
                           : m_loop.submit_accept(m_listen_fd, nullptr, nullptr, &m_accept_req);
}

void db_run::accept_done(struct io_uring_cqe* cqe)
{
    if (!(cqe->flags & IORING_CQE_F_MORE))
        m_accept_pending = false;
    const int fd = cqe->res;
    if (fd >= 0)
    {
        const size_t limit = m_owner.get_max_connections() ? m_owner.get_max_connections() : max_conns;
        if (m_stopped || m_conns.size() >= limit)
            m_loop.close_fd(fd);
        else
        {
            auto c = std::make_shared_for_overwrite<conn>();
            c->id = m_next_id++;
            c->fd = fd;
            int one = 1;
            ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
            c->last = now_sec();
            m_conns.emplace(c->id, c);
            runtime_instance::stat_add(m_owner.m_stat_total_connections, 1);
            m_owner.m_stat_active_connections.store(m_conns.size(), std::memory_order_relaxed);
            arm_read(c);
            arm_tick();
        }
    }
    if (!m_accept_pending && !m_stopped && fd != -ECANCELED)
        arm_accept();
}

std::shared_ptr<db_run::conn> db_run::conn_of(io_request* req)
{
    auto* raw = reinterpret_cast<conn*>(req->buffer);
    if (auto it = m_conns.find(raw->id); it != m_conns.end() && it->second.get() == raw)
        return it->second;
    for (const auto& c : m_closing)
        if (c.get() == raw)
            return c;
    return nullptr;
}

void db_run::arm_read(const std::shared_ptr<conn>& c)
{
    if (c->dead || c->rd_pending || c->fd < 0)
        return;
    c->rd = io_request{};
    c->rd.owner = this;
    c->rd.buffer = reinterpret_cast<char*>(c.get());
    c->rd.fd = c->fd;
    c->rd.type = op_read;
    c->rd_pending = m_loop.submit_read(c->fd, c->rbuf, sizeof c->rbuf, &c->rd);
    if (!c->rd_pending)
        close_conn(c);
}

void db_run::read_done(const std::shared_ptr<conn>& c, int res)
{
    c->rd_pending = false;
    if (c->dead)
    {
        if (!c->wr_pending)
            std::erase(m_closing, c);
        return;
    }
    if (res <= 0)
    {
        close_conn(c);
        return;
    }
    c->last = now_sec();
    c->in.append(c->rbuf, static_cast<size_t>(res));
    runtime_instance::stat_add(m_owner.m_stat_bytes_in, static_cast<uint64_t>(res));
    serve(c);
    if (!c->dead && !c->waiting)
        arm_read(c);
}

// Requests in order, one at a time: a write's answer waits for the turn's sync and holds those behind it.
void db_run::serve(const std::shared_ptr<conn>& c)
{
    while (!c->dead && !c->waiting && !c->in.empty())
    {
        request rq;
        int refusal = 400;
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
    flush(c);
}

void db_run::resume(const std::shared_ptr<conn>& c)
{
    c->waiting = false;
    serve(c);
    if (!c->dead && !c->waiting)
        arm_read(c);
}

void db_run::flush(const std::shared_ptr<conn>& c)
{
    if (c->dead || c->wr_pending)
        return;
    if (c->out_off >= c->out.size())
    {
        c->out.clear();
        c->out_off = 0;
        if (!c->keep_alive && !c->waiting && !c->feed)
            close_conn(c);
        return;
    }
    c->wr = io_request{};
    c->wr.owner = this;
    c->wr.buffer = reinterpret_cast<char*>(c.get());
    c->wr.fd = c->fd;
    c->wr.type = op_write;
    const size_t chunk = std::min<size_t>(c->out.size() - c->out_off, 1u << 20);
    c->wr_pending = m_loop.submit_write(c->fd, c->out.data() + c->out_off, static_cast<uint32_t>(chunk), &c->wr);
    if (!c->wr_pending)
        close_conn(c);
}

void db_run::write_done(const std::shared_ptr<conn>& c, int res)
{
    c->wr_pending = false;
    if (c->dead)
    {
        if (!c->rd_pending)
            std::erase(m_closing, c);
        return;
    }
    if (res <= 0)
    {
        close_conn(c);
        return;
    }
    c->out_off += static_cast<size_t>(res);
    c->last = now_sec();
    runtime_instance::stat_add(m_owner.m_stat_bytes_out, static_cast<uint64_t>(res));
    // A stream's buffer is cut behind what went, and a whole copy being sent goes on as it drains.
    if (c->feed && c->out_off == c->out.size())
    {
        c->out.clear();
        c->out_off = 0;
        if (!c->dump.empty())
        {
            pump_dump(c);
            return;
        }
    }
    flush(c);
}

void db_run::close_conn(const std::shared_ptr<conn>& c)
{
    if (c->dead)
        return;
    c->dead = true;
    if (!c->dump.empty())
    {
        c->dump.clear();
        m_store.unpin();
    }
    if (c->fd >= 0)
    {
        ::shutdown(c->fd, SHUT_RDWR);
        m_loop.close_fd(c->fd);
        c->fd = -1;
    }
    m_conns.erase(c->id);
    m_owner.m_stat_active_connections.store(m_conns.size(), std::memory_order_relaxed);
    if (c->rd_pending || c->wr_pending)
        m_closing.push_back(c);
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
    if (req == &m_accept_req)
    {
        accept_done(cqe);
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
    auto c = conn_of(req);
    if (!c)
        return;
    if (req == &c->rd)
        read_done(c, cqe->res);
    else if (req == &c->wr)
        write_done(c, cqe->res);
}

// Woken for what is due: every second while connections are open, else at the next document to go or backup to
// take, at most a minute ahead; an idle database with neither is woken by nothing.
void db_run::arm_tick()
{
    if (m_tick_armed || m_stopped)
        return;
    int64_t delay = 0;
    const int64_t now = now_sec();
    const auto due = [&](int64_t at) {
        if (at <= 0)
            return;
        const int64_t d = std::clamp<int64_t>(at - now, 1, 60);
        delay = delay ? std::min(delay, d) : d;
    };
    if (!m_conns.empty() || !m_owner.get_replicate().empty())
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
    const int64_t now = now_sec();
    // A comment now and then, so a stream nothing changes on is not taken for a dead one.
    for (size_t i = 0; i < m_feeds.size(); ++i)
    {
        const std::shared_ptr<conn> c = m_feeds[i];
        if (!c->dead && now - c->last >= 15)
        {
            c->last = now;
            c->out += ": ping\n\n";
            flush(c);
        }
    }
    std::erase_if(m_feeds, [](const std::shared_ptr<conn>& c) { return c->dead; });
    std::vector<std::shared_ptr<conn>> idle;
    for (auto& [id, c] : m_conns)
        if (!c->feed && now - c->last > idle_secs && !c->waiting && c->out_off >= c->out.size())
            idle.push_back(c);
    for (auto& c : idle)
        close_conn(c);
    // A replica is told of the documents that go by the database it copies, which sends their deletions.
    if (m_owner.get_replicate().empty() && !m_broken)
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
    const size_t end = c.in.find("\r\n\r\n");
    if (end == std::string::npos)
    {
        if (c.in.size() > max_head)
        {
            refusal = 431;
            return -1;
        }
        return 0;
    }
    const std::string_view head(c.in.data(), end + 2);
    if (!http_eol_framing_ok(head, true))
        return -1;
    const size_t line_end = head.find("\r\n");
    const std::string_view line = head.substr(0, line_end);
    const size_t sp1 = line.find(' ');
    const size_t sp2 = sp1 == std::string_view::npos ? sp1 : line.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos)
        return -1;
    rq.method.assign(line.substr(0, sp1));
    const std::string_view target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    const std::string_view version = line.substr(sp2 + 1);
    if (version != "HTTP/1.1" && version != "HTTP/1.0")
        return -1;
    const size_t q = target.find('?');
    rq.path.assign(target.substr(0, q));
    if (q != std::string_view::npos)
        rq.query.assign(target.substr(q + 1));

    const std::string_view fields = head.substr(line_end + 2);
    const http_request_framing_scan scan = http_scan_request_headers(fields);
    if (!scan.ok || scan.transfer_encoding)
    {
        refusal = scan.ok ? 411 : 400;
        return -1;
    }
    bool close = version == "HTTP/1.0";
    size_t pos = 0;
    while (pos < fields.size())
    {
        size_t nl = fields.find("\r\n", pos);
        if (nl == std::string_view::npos)
            nl = fields.size();
        const std::string_view f = fields.substr(pos, nl - pos);
        pos = nl + 2;
        const size_t colon = f.find(':');
        if (colon == std::string_view::npos)
            continue;
        const std::string_view value = http_trim_ows(f.substr(colon + 1));
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
        else if (header_name_equals(f, "connection", 10))
        {
            if (http_list_has_token(value, "close", 5))
                close = true;
            else if (http_list_has_token(value, "keep-alive", 10))
                close = false;
        }
    }
    const size_t body_len = scan.has_content_length ? scan.content_length : 0;
    if (body_len > max_body)
    {
        refusal = 413;
        return -1;
    }
    if (c.in.size() < end + 4 + body_len)
        return 0;
    rq.body.assign(c.in, end + 4, body_len);
    c.in.erase(0, end + 4 + body_len);
    c.keep_alive = !close;
    return 1;
}

std::string db_run::head(const conn& c, int status, std::string_view type, size_t length, std::string_view extra) const
{
    std::string o = "HTTP/1.1 " + std::to_string(status) + " " + reason(status) + "\r\nContent-Type: ";
    o += type;
    o += "\r\nContent-Length: ";
    o += std::to_string(length);
    o += "\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n";
    o += extra;
    if (!c.keep_alive)
        o += "Connection: close\r\n";
    o += "\r\n";
    return o;
}

void db_run::respond(const std::shared_ptr<conn>& c, int status, std::string_view body, std::string_view extra)
{
    if (status >= 400)
        ++m_c.refused;
    c->out += head(*c, status, "application/json", body.size(), extra);
    c->out += body;
}

std::string db_run::cors(const request& rq) const
{
    if (rq.origin.empty())
        return {};
    for (const auto& o : m_origins)
    {
        // A named origin is answered with the browser's credentials; `*` lets any page in, but not with them.
        if (o == rq.origin)
            return "Access-Control-Allow-Origin: " + rq.origin +
                   "\r\nAccess-Control-Allow-Credentials: true\r\nAccess-Control-Expose-Headers: ETag\r\nVary: Origin\r\n";
        if (o == "*")
            return "Access-Control-Allow-Origin: *\r\nAccess-Control-Expose-Headers: ETag\r\n";
    }
    return "Vary: Origin\r\n";
}

bool db_run::who_of(const request& rq, principal& who, bool& by_cookie, std::string& refusal)
{
    by_cookie = false;
    if (!rq.authorization.empty())
    {
        std::string_view a = rq.authorization;
        if (!a.starts_with("Bearer ") && !a.starts_with("bearer "))
        {
            refusal = "Authorization takes Bearer and a key's secret or the provider's access token";
            return false;
        }
        const std::string_view token = http_trim_ows(a.substr(7));
        for (const auto& k : m_keys)
            if (k.secret.size() == token.size() && CRYPTO_memcmp(k.secret.data(), token.data(), token.size()) == 0)
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
            write_string(who.sub, body);
            body += '}';
            respond(c, 200, body, allow);
        }
        return;
    }
    if (rq.path == "/" && reads)
    {
        std::string body = "{\"database\":";
        write_string(m_owner.get_name(), body);
        if (who.kind == principal::key)
        {
            body += ",\"collections\":[";
            bool first = true;
            for (const auto& name : m_store.collection_names())
            {
                body += first ? "" : ",";
                first = false;
                write_string(name, body);
            }
            body += ']';
        }
        body += '}';
        respond(c, 200, body, allow);
        return;
    }
    std::string path;
    if (!unescape(rq.path, path))
    {
        respond(c, 400, error_body("bad_path", "the path holds a % that spells no byte"), allow);
        return;
    }
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
        c->who = who;
        open_feed(c, rq, coll, !feed, path == "/_replicate");
        return;
    }
    answer a = execute(who, rq.method, path, rq.body, rq.if_match, rq.if_none_match);
    std::string extra = allow;
    if (a.version)
        extra += "ETag: \"" + std::to_string(a.version) + "\"\r\n";
    if (rq.method == "HEAD")
        a.body.clear();
    if (a.needs <= m_durable)
    {
        respond(c, a.status, a.body, extra);
        return;
    }
    // Rests on a change not yet on the disk: answered once it is, and nothing behind it read meanwhile.
    if (a.status >= 400)
        ++m_c.refused;
    hold(waiter{a.needs, c, head(*c, a.status, "application/json", a.body.size(), extra) + a.body, 0, false});
}

db_run::answer db_run::execute(const principal& who, std::string_view method, std::string_view path,
                               std::string_view body, std::string_view if_match, std::string_view if_none_match)
{
    if (m_broken)
        return refused(503, "not_durable", "the journal could not be written to the disk; restart the database");
    // A copy answers reads, a query among them, and leaves every write to the database it copies.
    const bool reading = method == "GET" || method == "HEAD" || (method == "POST" && path.ends_with("/_query"));
    if (!m_owner.get_replicate().empty() && !reading)
        return refused(403, "read_only", "this database is a copy of " + std::string(m_owner.get_replicate()) +
                                             "; write there");
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
            if (const jvalue* v = member(o, "if"))
                op.if_v = version_of(v->s);
            if (const jvalue* v = member(o, "if_absent"); v && v->k == jvalue::kind::boolean)
                op.if_absent = v->b;
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
            answer a;
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
            answer a;
            if (!m_store.read(who, coll, id, a.body, err, a.needs))
            {
                // An absence rests on the last change too: one not yet on the disk may be its deletion.
                answer r = refused(err);
                r.needs = a.needs;
                return r;
            }
            if (const doc* d = m_store.get(coll, id))
                a.version = d->v;
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

    const bool existed = !is_tx && ops[0].kind == write_op::put && m_store.get(coll, ops[0].id);
    answer a;
    std::string out;
    std::vector<event> evs;
    if (!m_store.write(who, ops, out, err, &evs))
    {
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
        a.body = "{\"results\":" + out + "}";
        return a;
    }
    // One change: its document, or its deletion, not the list a transaction answers.
    a.body = out.substr(1, out.size() - 2);
    if (ops[0].kind != write_op::del)
    {
        if (const doc* d = m_store.get(coll, ops[0].id))
            a.version = d->v;
        if (ops[0].kind == write_op::insert || (ops[0].kind == write_op::put && !existed))
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
        auto job = file->s.starts_with('/') ? m_store.plan_backup(file->s) : nullptr;
        if (!job)
        {
            mgr->requests().complete_deferred(
                ticket, request_status::ok,
                "{\"status\":409,\"body\":" +
                    error_body("busy", file->s.starts_with('/') ? "a merge or another backup is running; try again"
                                                                : "the backup's file is an absolute path") +
                    "}");
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
            write_string(it->second.file, body);
            body += ",\"message\":";
            write_string(it->second.why, body);
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
            write_json(*b, body);
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

}   // namespace socketley::db
