#include "replicator.h"

#include <algorithm>
#include <cstdlib>
#include <ctime>

#include "body_reader.h"
#include "checksum.h"
#include "s3_names.h"
#include "s3_tagging.h"
#include "../../shared/byte_codec.h"
#include "../../shared/logging.h"
#include "../../shared/s3_sigv4.h"

namespace socketley::storage
{

namespace
{

constexpr long tick_ns = 250'000'000;

// The key m_open counts a version's destinations under.
std::string version_key(std::string_view bucket, std::string_view key, std::string_view version_id)
{
    std::string k;
    k.reserve(bucket.size() + key.size() + version_id.size() + 2);
    k.append(bucket);
    k.push_back('\0');
    k.append(key);
    k.push_back('\0');
    k.append(version_id);
    return k;
}

// The time a signature is dated with, as x-amz-date gives it.
std::string amz_date_now()
{
    const std::time_t now = std::time(nullptr);
    struct tm tm{};
    ::gmtime_r(&now, &tm);
    char buf[17];
    std::strftime(buf, sizeof(buf), "%Y%m%dT%H%M%SZ", &tm);
    return buf;
}

// The text of the first <name> element in a small answer, empty when there is none.
std::string element_text(std::string_view xml, std::string_view name)
{
    const std::string open  = "<" + std::string(name) + ">";
    const std::string close = "</" + std::string(name) + ">";
    const size_t a = xml.find(open);
    if (a == std::string_view::npos)
        return {};
    const size_t b = xml.find(close, a + open.size());
    if (b == std::string_view::npos)
        return {};
    return std::string(xml.substr(a + open.size(), b - a - open.size()));
}

// What an answer that is not a 2xx says, for the log.
std::string describe(const http_answer& a)
{
    if (a.status == 0)
        return a.failure;
    std::string d = "HTTP " + std::to_string(a.status);
    const size_t open = a.body.find("<Code>");
    const size_t close = a.body.find("</Code>");
    if (open != std::string::npos && close != std::string::npos && close > open)
        d += " " + a.body.substr(open + 6, close - open - 6);
    return d;
}

// The headers of an object a client set, which its replica is written with.
bool carried_header(std::string_view name)
{
    static constexpr std::string_view kept[] = {
        "cache-control", "content-disposition", "content-encoding", "content-language", "expires",
        "x-amz-website-redirect-location",
    };
    return name.starts_with("x-amz-meta-") || std::find(std::begin(kept), std::end(kept), name) != std::end(kept);
}

}   // namespace

bool parse_replication_targets(std::string_view text, std::vector<replication_target>& out, std::string& why)
{
    out.clear();
    for (const target_line& line : split_target_lines(text))
    {
        const auto& f = line.fields;
        const std::string where = "line " + std::to_string(line.line_no) + ": ";
        if (f.size() < 5 || f.size() > 6 || (f.size() == 6 && !f[5].starts_with("ca=")))
        {
            why = where + "a target is `name url region access_key secret [ca=file]`";
            return false;
        }
        replication_target t;
        t.name       = std::string(f[0]);
        t.region     = std::string(f[2]);
        t.access_key = std::string(f[3]);
        t.secret     = std::string(f[4]);
        if (f.size() == 6)
            t.http.ca_file = std::string(f[5].substr(3));
        if (!valid_target_name(t.name))
        {
            why = where + "a target's name is letters, digits, '-', '_' and '.'";
            return false;
        }
        if (std::string err; !parse_http_url(f[1], t.http, err))
        {
            why = where + err;
            return false;
        }
        if (!t.http.ca_file.empty() && !t.http.tls)
        {
            why = where + "ca= is for an https target";
            return false;
        }
        if (!valid_target_name(t.region) || t.access_key.size() > 127)
        {
            why = where + "a target's region is letters, digits, '-', '_' and '.', and its access key at most 127 bytes";
            return false;
        }
        for (const replication_target& o : out)
            if (o.name == t.name)
            {
                why = where + "the target " + t.name + " is named twice";
                return false;
            }
        out.push_back(std::move(t));
    }
    return true;
}

bool load_replication_targets(const std::string& path, std::vector<replication_target>& out, std::string& why)
{
    std::string text;
    if (!read_targets_file(path, "replication targets", text, why))
        return false;
    if (!parse_replication_targets(text, out, why))
    {
        why = path + ": " + why;
        return false;
    }
    return true;
}

// ─── The replicator ─────────────────────────────────────────────────────────

struct replicator::job
{
    task        t;
    int         fd{-1};
    object_meta meta;
    size_t      data_off{0};
    // The data key of an encrypted version, which its plaintext is read with.
    std::optional<sse_key> key;
    part_list   parts;
    std::string upload_id;
    size_t      part{0};
    // Each part's ETag and checksum as the destination gave them.
    std::vector<std::pair<std::string, std::string>> done_parts;
    // A body that could not be read, which no retry will read either.
    bool        source_failed{false};
    // What the last step that did not succeed came to, for the log.
    std::string why;
};

replicator::replicator(event_loop& loop, file_io& io, io_handler* owner, object_store& store, hash_pool& hashes,
                       key_opener keys)
    : m_loop(loop), m_io(io), m_owner(owner), m_store(store), m_hashes(hashes), m_keys(std::move(keys)),
      m_box(loop, io, "replication outbox")
{
    if (const char* e = std::getenv("SOCKETLEY_STORAGE_REPLICATION_HOSTS"))
        m_hosts_file = e;
}

replicator::~replicator()
{
    *m_alive = false;
}

void replicator::set_targets(std::vector<replication_target> targets)
{
    m_lanes.clear();
    bool names = false;
    for (const replication_target& t : targets)
    {
        http_endpoint e;
        names = names || !literal_endpoint(t.http.host, t.http.port, e);
    }
    if (names && !m_resolver.attach(m_io))
        LOG_ERROR("storage: the replication resolver cannot be waited for, so targets named by a host are not written to");
    for (replication_target& t : targets)
    {
        auto l  = std::make_unique<lane>();
        l->peer = std::make_unique<http_peer>(m_loop, m_io, m_resolver, t.http, m_hosts_file,
                                              "the replication target " + t.name);
        l->peer->prime();
        l->target = std::move(t);
        m_lanes.push_back(std::move(l));
    }
}

bool replicator::has_target(std::string_view name) const
{
    for (const auto& l : m_lanes)
        if (l->target.name == name)
            return true;
    return false;
}

replicator::lane* replicator::find_lane(std::string_view name)
{
    for (auto& l : m_lanes)
        if (l->target.name == name)
            return l.get();
    return nullptr;
}

bool replicator::open(const std::string& dir, uint32_t shard, const outbox::change_made& made, std::string& err)
{
    if (m_lanes.empty())
        return true;
    uint64_t dropped = 0, again = 0;
    const bool ok = m_box.open(dir, ".replicate", shard, made, [&](uint64_t id, std::string_view payload)
    {
        bytes::reader r(payload);
        uint8_t kind = 0;
        std::string target;
        task t;
        t.id = id;
        if (!r.u8(kind) || !r.bytes(target, 4096) || !r.bytes(t.bucket, 4096) || !r.bytes(t.key, 4096) ||
            !r.bytes(t.version_id, 4096) || !r.bytes(t.dest_bucket, 4096) || !r.bytes(t.storage_class, 4096) ||
            (kind != 'P' && kind != 'M' && kind != 'G') || (kind == 'G' && !r.bytes(t.tags, 64 * 1024)))
        {
            ++dropped;
            return false;
        }
        lane* l = find_lane(target);
        if (!l)
        {
            ++dropped;
            return false;
        }
        t.marker  = kind == 'M';
        t.tagging = kind == 'G';
        if (kind == 'P')
            ++m_open[version_key(t.bucket, t.key, t.version_id)];
        l->q.push_back(std::move(t));
        ++m_pending;
        ++again;
        return true;
    }, err);
    if (!ok)
        return false;
    if (dropped)
        LOG_WARN(("storage: " + std::to_string(dropped) +
                  " replication(s) in the outbox name a target that is gone, and are dropped").c_str());

    // A version answered PENDING whose entry a crash or a failed write took is queued again from what the index says.
    uint64_t swept = 0;
    for (const bucket_info& b : m_store.buckets())
    {
        const auto cfg = m_store.bucket_replication(b.name);
        if (!cfg)
            continue;
        std::vector<std::pair<std::string, object_meta>> found;
        m_store.each_version(b.name, [&](const std::string& key, const object_meta& m)
        {
            if (replication_status_of(m) == replication_pending && has_version(m) && !is_delete_marker(m) &&
                !m_open.contains(version_key(b.name, key, version_of(m).id)))
                found.emplace_back(key, m);
        });
        for (const auto& [key, m] : found)
            if (enqueue(*cfg, b.name, key, version_of(m).id, false, tags_of(m)))
                ++swept;
    }
    if (again || swept)
        LOG_INFO(("storage: " + std::to_string(again) + " replication(s) from the outbox and " + std::to_string(swept) +
                  " pending version(s) are copied again").c_str());
    for (auto& l : m_lanes)
        start(*l);
    return true;
}

replicator::lane* replicator::tasks_for(const replication_config& cfg, const std::string& bucket,
                                       const std::string& key, const std::string& version_id, bool marker,
                                       std::string_view tags, std::vector<task>& out)
{
    out.clear();
    if (m_stopped || version_id.empty())
        return nullptr;
    const auto rules = replication_rules_for(cfg, key, tags, marker);
    lane* l = find_lane(cfg.target);
    if (rules.empty() || !l)
        return nullptr;
    for (const replication_rule* r : rules)
    {
        task t;
        t.marker        = marker;
        t.bucket        = bucket;
        t.key           = key;
        t.version_id    = version_id;
        t.dest_bucket   = r->dest_bucket;
        t.storage_class = r->storage_class;
        out.push_back(std::move(t));
    }
    return l;
}

std::string replicator::encode_task(const lane& l, const task& t)
{
    bytes::writer w;
    w.u8(t.tagging ? 'G' : t.marker ? 'M' : 'P');
    w.bytes(l.target.name);
    w.bytes(t.bucket);
    w.bytes(t.key);
    w.bytes(t.version_id);
    w.bytes(t.dest_bucket);
    w.bytes(t.storage_class);
    if (t.tagging)
        w.bytes(t.tags);
    return w.take();
}

bool replicator::enqueue(const replication_config& cfg, const std::string& bucket, const std::string& key,
                         const std::string& version_id, bool marker, std::string_view tags)
{
    std::vector<task> tasks;
    lane* l = tasks_for(cfg, bucket, key, version_id, marker, tags, tasks);
    if (!l)
    {
        // A version written PENDING that nothing will copy, because the configuration changed or its target is gone.
        if (!marker && !m_stopped && !version_id.empty())
            set_status(bucket, key, version_id, replication_failed, [](bool) {});
        return false;
    }
    if (!marker)
        m_open[version_key(bucket, key, version_id)] += static_cast<uint32_t>(tasks.size());
    for (task& t : tasks)
        push(*l, std::move(t), false);
    return true;
}

bool replicator::enqueue_tags(const replication_config& cfg, const std::string& bucket, const std::string& key,
                             const std::string& version_id, std::string_view tags)
{
    std::vector<task> tasks;
    lane* l = tasks_for(cfg, bucket, key, version_id, false, tags, tasks);
    if (!l)
        return false;
    for (task& t : tasks)
    {
        t.tagging = true;
        t.tags    = std::string(tags);
        push(*l, std::move(t), false);
    }
    return true;
}

uint64_t replicator::stage(std::string_view check, const replication_config& cfg, const std::string& bucket,
                           const std::string& key, const std::string& version_id, bool marker, std::string_view tags)
{
    std::vector<task> tasks;
    lane* l = tasks_for(cfg, bucket, key, version_id, marker, tags, tasks);
    if (!l)
        return 0;
    std::vector<std::string> payloads;
    for (const task& t : tasks)
        payloads.push_back(encode_task(*l, t));
    std::vector<uint64_t> ids;
    const uint64_t ticket = m_box.stage(check, payloads, ids);
    for (size_t i = 0; i < tasks.size(); ++i)
        tasks[i].id = ids[i];
    m_staged.emplace(ticket, staged_copies{l, std::move(tasks)});
    return ticket;
}

void replicator::settle(uint64_t ticket, bool made, std::function<void()> then)
{
    const auto it = m_staged.find(ticket);
    if (it == m_staged.end())
    {
        then();
        return;
    }
    staged_copies sc = std::move(it->second);
    m_staged.erase(it);
    if (m_stopped)
    {
        then();
        return;
    }
    if (made)
    {
        if (!sc.tasks.empty() && !sc.tasks.front().marker)
        {
            const task& t = sc.tasks.front();
            m_open[version_key(t.bucket, t.key, t.version_id)] += static_cast<uint32_t>(sc.tasks.size());
        }
        for (task& t : sc.tasks)
            push(*sc.l, std::move(t), true);
    }
    m_box.settle(ticket, made, std::move(then));
}

void replicator::push(lane& l, task t, bool from_outbox)
{
    if (!from_outbox)
        t.id = m_box.add(encode_task(l, t));
    l.q.push_back(std::move(t));
    ++m_pending;
    start(l);
}

void replicator::arm_timer()
{
    if (m_timer_armed || m_stopped)
        return;
    m_timer_ts  = {0, tick_ns};
    m_timer_req = io_request{};
    m_timer_req.owner = m_owner;
    m_timer_req.type  = op_timeout;
    m_timer_armed = m_loop.submit_timeout(&m_timer_ts, &m_timer_req);
}

void replicator::on_timer()
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
        if (!l.active && !l.q.empty() && now >= l.next_try)
            start(l);
        waiting = waiting || l.active || !l.q.empty();
    }
    if (waiting)
        arm_timer();
}

void replicator::start(lane& l)
{
    if (l.active || l.q.empty() || m_stopped)
        return;
    if (std::chrono::steady_clock::now() < l.next_try)
    {
        arm_timer();
        return;
    }
    auto j = std::make_shared<job>();
    j->t     = l.q.front();
    l.active = j;
    arm_timer();
    if (j->t.tagging)
        run_tags(l, j);
    else if (j->t.marker)
        run_marker(l, j);
    else
        run_put(l, j);
}

void replicator::back_off(lane& l)
{
    ++m_c.retries;
    ++l.failures;
    const int64_t pause = std::min(backoff_cap_ms, backoff_first_ms << std::min<uint32_t>(l.failures - 1, 16));
    l.next_try = std::chrono::steady_clock::now() + std::chrono::milliseconds(pause);
    arm_timer();
}

void replicator::set_status(const std::string& bucket, const std::string& key, const std::string& version_id,
                            std::string_view status, std::function<void(bool)> then)
{
    header_change change;
    change.what  = header_change::kind::replication;
    change.value = std::string(status);
    auto alive = m_alive;
    m_store.change_header(bucket, key, version_id, std::move(change), [alive, then](st s, std::string)
    {
        if (!*alive)
            return;
        // A version or bucket that is gone has no status to write, which is as good as written.
        then(s == st::ok || s == st::no_such_version || s == st::no_such_key || s == st::delete_marker ||
             s == st::no_such_bucket);
    });
}

void replicator::ended(lane& l, outcome o, uint64_t bytes)
{
    std::shared_ptr<job> j = l.active;
    if (!j)
        return;
    if (j->fd >= 0)
    {
        m_loop.close_fd(j->fd);
        j->fd = -1;
    }
    const task& t = j->t;
    // A streak of failures is said once, at its start, and a refusal every time.
    if ((o == outcome::retry && l.failures == 0) || o == outcome::refused)
        LOG_WARN(("storage: copying " + t.bucket + "/" + t.key +
                  (t.tagging ? " (its tags)" : t.marker ? " (a delete marker)" : "") + " to " + l.target.name + ":" +
                  t.dest_bucket + " failed (" + j->why + ")" +
                  (o == outcome::retry        ? "; it is tried again until it is taken"
                   : t.marker || t.tagging    ? "; it is given up"
                                              : "; the version is FAILED"))
                     .c_str());
    if (o == outcome::retry)
    {
        l.active.reset();
        back_off(l);
        return;
    }
    auto retire = [this, &l, j, o, bytes]()
    {
        if (o == outcome::done)
        {
            ++m_c.completed;
            m_c.bytes += bytes;
        }
        else
            ++m_c.failed;
        m_box.done(j->t.id);
        if (!l.q.empty() && l.q.front().id == j->t.id)
            l.q.pop_front();
        --m_pending;
        l.active.reset();
        l.failures = 0;
        l.next_try = {};
        start(l);
    };
    // A delete marker and a tag change have no status of their own to write.
    if (t.marker || t.tagging)
    {
        retire();
        return;
    }
    // The version's status is written once its last destination has it, or at once when one refused it.
    const std::string vk = version_key(t.bucket, t.key, t.version_id);
    uint32_t left = 0;
    if (auto it = m_open.find(vk); it != m_open.end())
    {
        left = it->second > 0 ? it->second - 1 : 0;
        if (left == 0)
            m_open.erase(it);
        else
            it->second = left;
    }
    const std::string_view status = o == outcome::refused ? replication_failed
                                  : left == 0             ? replication_completed
                                                          : std::string_view{};
    if (status.empty())
    {
        retire();
        return;
    }
    auto alive = m_alive;
    lane* lp = &l;
    set_status(t.bucket, t.key, t.version_id, status, [this, alive, lp, j, vk, retire](bool written)
    {
        if (!*alive || lp->active != j)
            return;
        if (written)
        {
            retire();
            return;
        }
        // The copy is made again, since its status is what a restart goes by.
        ++m_open[vk];
        lp->active.reset();
        back_off(*lp);
    });
}

replicator::outcome replicator::judge(const http_answer& a)
{
    if (a.status == 0 || (a.status >= 500 && a.status != 501) || a.status == 408 || a.status == 409 || a.status == 429)
        return outcome::retry;
    return outcome::refused;
}

void replicator::exchange(lane& l, const std::shared_ptr<job>& j, http_request rq,
                          std::function<void(lane&, const std::shared_ptr<job>&, http_answer)> then)
{
    auto alive = m_alive;
    lane* lp = &l;
    rq.answer_secs = answer_secs;
    l.peer->exchange(std::move(rq), [alive, lp, j, then](http_answer a)
    {
        if (!*alive || lp->active != j)
            return;
        if (a.status / 100 != 2)
            j->why = describe(a);
        then(*lp, j, std::move(a));
    });
}

std::string replicator::signed_head(const lane& l, std::string_view method, const std::string& path,
                                    const std::string& query, std::vector<std::pair<std::string, std::string>> headers,
                                    uint64_t length) const
{
    const replication_target& t = l.target;
    const std::string date = amz_date_now();
    headers.emplace_back("host", t.http.authority());
    headers.emplace_back("x-amz-date", date);
    headers.emplace_back("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
    if (method != "DELETE" || length != 0)
        headers.emplace_back("content-length", std::to_string(length));
    std::vector<s3::header_field> fields;
    fields.reserve(headers.size());
    for (const auto& [n, v] : headers)
        fields.push_back({n, v});
    s3::sign_input in;
    in.method       = method;
    in.raw_path     = path;
    in.raw_query    = query;
    in.headers      = fields;
    in.payload_hash = "UNSIGNED-PAYLOAD";
    in.access_key   = t.access_key;
    in.secret       = t.secret;
    in.region       = t.region;
    in.amz_date     = date;
    std::string head(method);
    head += " " + path + (query.empty() ? "" : "?" + query) + " HTTP/1.1\r\n";
    for (const auto& [n, v] : headers)
        head += n + ": " + v + "\r\n";
    head += "authorization: " + s3::sign(in) + "\r\nconnection: close\r\nuser-agent: socketley-storage-replication\r\n\r\n";
    return head;
}

namespace
{

// The path of `key` in `bucket` below a target's own path.
std::string object_path(const http_target& t, std::string_view bucket, std::string_view key)
{
    std::string p = t.path;
    while (!p.empty() && p.back() == '/')
        p.pop_back();
    p += "/";
    p += bucket;
    p += "/";
    url_encode_to(p, key, true);
    return p;
}

}   // namespace

void replicator::run_marker(lane& l, const std::shared_ptr<job>& j)
{
    http_request rq;
    rq.head = signed_head(l, "DELETE", object_path(l.target.http, j->t.dest_bucket, j->t.key), {},
                          {{"x-amz-replication-status", "REPLICA"},
                           {std::string(replica_version_header), j->t.version_id}}, 0);
    exchange(l, j, std::move(rq), [this](lane& lp, const std::shared_ptr<job>&, http_answer a)
    {
        ended(lp, a.status / 100 == 2 ? outcome::done : judge(a), 0);
    });
}

void replicator::run_tags(lane& l, const std::shared_ptr<job>& j)
{
    const std::string query = "tagging=&versionId=" + url_encode(j->t.version_id, false);
    const std::string path  = object_path(l.target.http, j->t.dest_bucket, j->t.key);
    std::vector<std::pair<std::string, std::string>> h{{"x-amz-replication-status", "REPLICA"}};
    http_request rq;
    if (j->t.tags.empty())
        rq.head = signed_head(l, "DELETE", path, query, std::move(h), 0);
    else
    {
        rq.body = tagging_xml(decode_tags(j->t.tags));
        const auto md5 = md5_of(rq.body);
        h.emplace_back("content-md5", base64_encode(std::string_view(reinterpret_cast<const char*>(md5.data()), 16)));
        h.emplace_back("content-type", "application/xml");
        rq.head = signed_head(l, "PUT", path, query, std::move(h), rq.body.size());
    }
    exchange(l, j, std::move(rq), [this](lane& lp, const std::shared_ptr<job>&, http_answer a)
    {
        ended(lp, a.status / 100 == 2 ? outcome::done : judge(a), 0);
    });
}

void replicator::run_put(lane& l, const std::shared_ptr<job>& j)
{
    auto alive = m_alive;
    lane* lp = &l;
    m_store.open_version(j->t.bucket, j->t.key, j->t.version_id, 0, [this, alive, lp, j](open_result o)
    {
        if (!*alive || lp->active != j)
        {
            if (o.fd >= 0)
                m_loop.close_fd(o.fd);
            return;
        }
        opened(*lp, j, std::move(o));
    });
}

void replicator::opened(lane& l, const std::shared_ptr<job>& j, open_result o)
{
    if (o.status != st::ok)
    {
        if (o.fd >= 0)
            m_loop.close_fd(o.fd);
        // A version removed since it was queued has nothing left to copy, and a disk that did not answer is asked again.
        const bool gone = o.delete_marker || o.status == st::no_such_version || o.status == st::no_such_key ||
                          o.status == st::no_such_bucket;
        j->why = std::string("the version could not be opened: ") + status_name(o.status);
        ended(l, gone ? outcome::done : outcome::retry, 0);
        return;
    }
    j->fd       = o.fd;
    j->meta     = std::move(o.meta);
    j->data_off = o.data_off;
    if (is_encrypted(j->meta))
    {
        sse_key k{};
        // An SSE-C version is never written PENDING, and one whose key does not open here cannot be copied.
        if (sse_mode_of(j->meta) == sse_mode::c || !m_keys || !m_keys(j->meta, k))
        {
            j->why = "its data key does not open here";
            ended(l, outcome::refused, 0);
            return;
        }
        j->key = k;
    }
    if (j->meta.parts == 0)
    {
        send_single(l, j);
        return;
    }
    // A multipart version is copied in the same parts, so its replica has the same ETag and composite checksum.
    if (part_list_of(j->meta, j->parts) && j->parts.sizes.size() == j->meta.parts)
    {
        mpu_create(l, j);
        return;
    }
    part_trailer t;
    if (!part_trailer_of(j->meta, t))
    {
        send_single(l, j);
        return;
    }
    auto buf   = std::make_shared<std::string>(t.len, '\0');
    auto alive = m_alive;
    lane* lp   = &l;
    if (!m_io.pread(j->fd, buf->data(), static_cast<uint32_t>(t.len), j->data_off + t.at,
                    [this, alive, lp, j, buf, t](int64_t r)
        {
            if (!*alive || lp->active != j)
                return;
            j->parts = part_list{};
            if (r != static_cast<int64_t>(t.len) || !decode_part_trailer(*buf, j->meta, t, j->parts) ||
                j->parts.sizes.size() != j->meta.parts)
            {
                send_single(*lp, j);
                return;
            }
            mpu_create(*lp, j);
        }))
        ended(l, outcome::retry, 0);
}

http_body_source replicator::body_of(const std::shared_ptr<job>& j, uint64_t first, uint64_t len)
{
    auto reader = body_reader::make(m_io, &m_hashes, m_store.alive_token(), j->fd, j->data_off, j->meta,
                                    j->key ? &*j->key : nullptr, first, len);
    std::weak_ptr<job> weak = j;
    return [reader, weak](http_body_give give)
    {
        auto fail = [weak, give]()
        {
            if (auto jj = weak.lock())
                jj->source_failed = true;
            give(false, {});
        };
        if (!reader)
        {
            fail();
            return;
        }
        reader->next([fail, give](bool ok, std::string_view plain)
        {
            if (!ok)
            {
                fail();
                return;
            }
            give(true, plain);
        });
    };
}

namespace
{

// The headers a replica is written with that its source's metadata gives it.
std::vector<std::pair<std::string, std::string>> replica_headers(const object_meta& m, std::string_view storage_class)
{
    std::vector<std::pair<std::string, std::string>> h;
    h.emplace_back("content-type", m.content_type);
    for (const auto& [n, v] : m.extra)
        if (carried_header(n))
            h.emplace_back(n, v);
    if (const std::string_view tags = tags_of(m); !tags.empty())
    {
        std::string q;
        for (const auto& [k, v] : decode_tags(tags))
        {
            if (!q.empty())
                q += "&";
            url_encode_to(q, k, false);
            q += "=";
            url_encode_to(q, v, false);
        }
        h.emplace_back("x-amz-tagging", std::move(q));
    }
    h.emplace_back("x-amz-replication-status", "REPLICA");
    if (has_version(m))
        h.emplace_back(std::string(replica_version_header), version_of(m).id);
    if (is_encrypted(m))
        h.emplace_back("x-amz-server-side-encryption", "AES256");
    if (!storage_class.empty())
        h.emplace_back("x-amz-storage-class", std::string(storage_class));
    return h;
}

// The object's own checksum in `algo`, empty when it keeps none.
std::string checksum_value(const object_meta& m, checksum_algo algo)
{
    if (algo == checksum_algo::none || m.checksum.algo != algo)
        return {};
    return m.checksum.b64();
}

}   // namespace

void replicator::send_single(lane& l, const std::shared_ptr<job>& j)
{
    const object_meta& m = j->meta;
    auto h = replica_headers(m, j->t.storage_class);
    // The bytes are checked by the destination against the source's own digests, so a copy torn on the way is refused.
    h.emplace_back("content-md5", base64_encode(std::string_view(reinterpret_cast<const char*>(m.md5.data()), 16)));
    const checksum_algo algo = checksum_algo_of(m);
    if (const std::string v = checksum_value(m, algo); !v.empty() && v.find('-') == std::string::npos)
        h.emplace_back(std::string(checksum_header(algo)), v);
    http_request rq;
    rq.head = signed_head(l, "PUT", object_path(l.target.http, j->t.dest_bucket, j->t.key), {}, std::move(h), m.size);
    if (m.size)
        rq.source = body_of(j, 0, m.size);
    exchange(l, j, std::move(rq), [this](lane& lp, const std::shared_ptr<job>& jj, http_answer a)
    {
        if (a.status / 100 == 2)
            ended(lp, outcome::done, jj->meta.size);
        else
            ended(lp, jj->source_failed ? outcome::refused : judge(a), 0);
    });
}

void replicator::mpu_create(lane& l, const std::shared_ptr<job>& j)
{
    const object_meta& m = j->meta;
    auto h = replica_headers(m, j->t.storage_class);
    const checksum_algo algo = checksum_algo_of(m);
    if (const std::string v = checksum_value(m, algo); !v.empty())
    {
        h.emplace_back("x-amz-checksum-algorithm", std::string(checksum_name(algo)));
        h.emplace_back("x-amz-checksum-type", v.find('-') != std::string::npos ? "COMPOSITE" : "FULL_OBJECT");
    }
    http_request rq;
    rq.head = signed_head(l, "POST", object_path(l.target.http, j->t.dest_bucket, j->t.key), "uploads=", std::move(h), 0);
    exchange(l, j, std::move(rq), [this](lane& lp, const std::shared_ptr<job>& jj, http_answer a)
    {
        if (a.status / 100 != 2)
        {
            ended(lp, judge(a), 0);
            return;
        }
        jj->upload_id = element_text(a.body, "UploadId");
        if (jj->upload_id.empty())
        {
            jj->why = "the upload's creation named no UploadId";
            ended(lp, outcome::retry, 0);
            return;
        }
        jj->part = 0;
        jj->done_parts.clear();
        mpu_part(lp, jj);
    });
}

void replicator::mpu_part(lane& l, const std::shared_ptr<job>& j)
{
    if (j->part >= j->parts.sizes.size())
    {
        mpu_complete(l, j);
        return;
    }
    const size_t i = j->part;
    uint64_t first = 0;
    for (size_t k = 0; k < i; ++k)
        first += j->parts.sizes[k];
    const uint64_t len    = j->parts.sizes[i];
    const uint32_t number = j->parts.numbers.size() == j->parts.sizes.size() ? j->parts.numbers[i]
                                                                            : static_cast<uint32_t>(i + 1);
    std::vector<std::pair<std::string, std::string>> h;
    h.emplace_back("x-amz-replication-status", "REPLICA");
    const checksum_algo algo = checksum_algo_of(j->meta);
    if (algo != checksum_algo::none && i < j->parts.checksums.size() && !j->parts.checksums[i].empty())
        h.emplace_back(std::string(checksum_header(algo)), base64_encode(j->parts.checksums[i]));
    const std::string query = "partNumber=" + std::to_string(number) + "&uploadId=" + url_encode(j->upload_id, false);
    http_request rq;
    rq.head = signed_head(l, "PUT", object_path(l.target.http, j->t.dest_bucket, j->t.key), query, std::move(h), len);
    if (len)
        rq.source = body_of(j, first, len);
    exchange(l, j, std::move(rq), [this, number](lane& lp, const std::shared_ptr<job>& jj, http_answer a)
    {
        if (a.status / 100 != 2)
        {
            mpu_abort(lp, jj, jj->source_failed ? outcome::refused : judge(a));
            return;
        }
        const checksum_algo algo = checksum_algo_of(jj->meta);
        std::string ck = algo == checksum_algo::none ? std::string() : std::string(a.header(checksum_header(algo)));
        jj->done_parts.emplace_back(std::to_string(number) + "\n" + std::string(a.header("etag")), std::move(ck));
        ++jj->part;
        mpu_part(lp, jj);
    });
}

void replicator::mpu_complete(lane& l, const std::shared_ptr<job>& j)
{
    const checksum_algo algo = checksum_algo_of(j->meta);
    std::string x = "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">";
    for (const auto& [numbered, ck] : j->done_parts)
    {
        const size_t nl = numbered.find('\n');
        x += "<Part><PartNumber>" + numbered.substr(0, nl) + "</PartNumber><ETag>";
        xml_escape_to(x, numbered.substr(nl + 1));
        x += "</ETag>";
        if (!ck.empty())
        {
            const std::string el = "Checksum" + std::string(checksum_name(algo));
            x += "<" + el + ">";
            xml_escape_to(x, ck);
            x += "</" + el + ">";
        }
        x += "</Part>";
    }
    x += "</CompleteMultipartUpload>";
    std::vector<std::pair<std::string, std::string>> h;
    h.emplace_back("content-type", "application/xml");
    h.emplace_back("x-amz-replication-status", "REPLICA");
    const std::string query = "uploadId=" + url_encode(j->upload_id, false);
    http_request rq;
    rq.head = signed_head(l, "POST", object_path(l.target.http, j->t.dest_bucket, j->t.key), query, std::move(h),
                          x.size());
    rq.body = std::move(x);
    exchange(l, j, std::move(rq), [this](lane& lp, const std::shared_ptr<job>& jj, http_answer a)
    {
        // A completion may be refused inside a 200, as S3 answers one it worked on for a while.
        if (a.status / 100 == 2 && a.body.find("<Error>") == std::string::npos)
        {
            ended(lp, outcome::done, jj->meta.size);
            return;
        }
        if (a.status / 100 == 2)
            jj->why = "the completion was refused inside its 200";
        mpu_abort(lp, jj, a.status / 100 == 2 ? outcome::retry : judge(a));
    });
}

void replicator::mpu_abort(lane& l, const std::shared_ptr<job>& j, outcome o)
{
    const std::string why = j->why;
    const std::string query = "uploadId=" + url_encode(j->upload_id, false);
    http_request rq;
    rq.head = signed_head(l, "DELETE", object_path(l.target.http, j->t.dest_bucket, j->t.key), query,
                          {{"x-amz-replication-status", "REPLICA"}}, 0);
    exchange(l, j, std::move(rq), [this, o, why](lane& lp, const std::shared_ptr<job>& jj, http_answer)
    {
        jj->why = why;
        ended(lp, o, 0);
    });
}

void replicator::stop()
{
    if (m_stopped)
        return;
    m_stopped = true;
    for (auto& l : m_lanes)
    {
        l->peer->stop();
        if (l->active && l->active->fd >= 0)
            m_loop.close_fd(l->active->fd);
        l->active.reset();
    }
    if (m_timer_armed)
        m_loop.submit_timeout_remove(&m_timer_req);
    // A resolve in progress is waited out here, which the system resolver's own timeout bounds.
    m_resolver.stop();
    if (const int fd = m_resolver.release_wake_fd(); fd >= 0)
        m_loop.close_fd(fd);
    m_box.stop();
}

}   // namespace socketley::storage
