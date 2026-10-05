#include "replicator.h"

#include <algorithm>
#include <cstdlib>
#include <ctime>

#include <fcntl.h>
#include <unistd.h>

#include "body_reader.h"
#include "checksum.h"
#include "cluster.h"
#include "s3_names.h"
#include "s3_tagging.h"
#include "../../shared/byte_codec.h"
#include "../../shared/http_framing.h"
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

// The bytes of `s` in hex, and back, empty for text that is not hex.
std::string hex_of(std::string_view s)
{
    return hex(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

std::string unhex(std::string_view h)
{
    std::string out;
    if (h.size() % 2)
        return out;
    const auto digit = [](char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; };
    for (size_t i = 0; i < h.size(); i += 2)
    {
        const int a = digit(h[i]), b = digit(h[i + 1]);
        if (a < 0 || b < 0)
            return {};
        out.push_back(static_cast<char>(a << 4 | b));
    }
    return out;
}

// Writes `text` beside `path` and renames it over, unsynced, for a note a crash may take back to an older one.
bool replace_note(const std::string& path, const std::string& text)
{
    const std::string tmp = path + ".tmp";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    const bool whole = ::write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size());
    ::close(fd);
    return whole && ::rename(tmp.c_str(), path.c_str()) == 0;
}

// The path of `key` in `bucket` below a target's own path.
std::string object_path(const http_target& t, std::string_view bucket, std::string_view key);

// What a change sent to another node is, for the log.
std::string node_change_name(char kind, bool has_version)
{
    switch (kind)
    {
        case 'p': return has_version ? "a version" : "an object";
        case 'm': return "a delete marker";
        case 'g': return "its tags";
        case 'd': return "its removal";
        case 'x': return "a version's removal";
        case 'l': return "a version's lock";
        case 'i': return "a record of the runtime's own";
        case 'q': return "a request for a copy";
        default:  return "the bucket's change";
    }
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
    // The connection of its lane it goes on, and whether it is still in flight there.
    size_t      slot{0};
    bool        live{true};
};

replicator::replicator(event_loop& loop, file_io& io, io_handler* owner, object_store& store, hash_pool& hashes,
                       key_opener keys)
    : m_loop(loop), m_io(io), m_owner(owner), m_store(store), m_hashes(hashes), m_keys(std::move(keys)),
      m_box(loop, io, "replication outbox")
{
    if (const char* e = std::getenv("SOCKETLEY_STORAGE_REPLICATION_HOSTS"))
        m_hosts_file = e;
    if (const char* e = std::getenv("SOCKETLEY_STORAGE_CLUSTER_QUEUE"))
        m_node_queue_max = std::max<size_t>(std::strtoul(e, nullptr, 10), 1);
}

replicator::~replicator()
{
    *m_alive = false;
}

void replicator::set_targets(std::vector<replication_target> targets)
{
    std::erase_if(m_lanes, [](const std::unique_ptr<lane>& l) { return !l->target.node; });
    add_lanes(std::move(targets), false);
}

void replicator::set_nodes(std::vector<replication_target> nodes)
{
    std::erase_if(m_lanes, [](const std::unique_ptr<lane>& l) { return l->target.node; });
    m_nodes = nodes.size();
    add_lanes(std::move(nodes), true);
}

void replicator::add_lanes(std::vector<replication_target> targets, bool nodes)
{
    bool names = false;
    for (const replication_target& t : targets)
    {
        http_endpoint e;
        names = names || !literal_endpoint(t.http.host, t.http.port, e);
    }
    if (names && !m_resolver_attached)
    {
        m_resolver_attached = m_resolver.attach(m_io);
        if (!m_resolver_attached)
            LOG_ERROR("storage: the replication resolver cannot be waited for, so targets named by a host are not "
                      "written to");
    }
    for (replication_target& t : targets)
    {
        t.node = nodes;
        auto l = std::make_unique<lane>();
        l->peers.push_back(new_peer(t));
        l->peers.front()->prime();
        l->target = std::move(t);
        m_lanes.push_back(std::move(l));
    }
}

std::unique_ptr<http_peer> replicator::new_peer(const replication_target& t)
{
    return std::make_unique<http_peer>(m_loop, m_io, m_resolver, t.http, m_hosts_file,
                                       (t.node ? "the cluster node " : "the replication target ") + t.name);
}

size_t replicator::free_slot(lane& l)
{
    for (size_t i = 0; i < l.peers.size(); ++i)
        if (std::none_of(l.active.begin(), l.active.end(), [i](const auto& a) { return a->slot == i; }))
            return i;
    l.peers.push_back(new_peer(l.target));
    return l.peers.size() - 1;
}

bool replicator::has_target(std::string_view name) const
{
    for (const auto& l : m_lanes)
        if (!l->target.node && l->target.name == name)
            return true;
    return false;
}

uint64_t replicator::connects() const
{
    uint64_t n = 0;
    for (const auto& l : m_lanes)
        for (const auto& p : l->peers)
            n += p->connects();
    return n;
}

uint64_t replicator::reuses() const
{
    uint64_t n = 0;
    for (const auto& l : m_lanes)
        for (const auto& p : l->peers)
            n += p->reuses();
    return n;
}

replicator::lane* replicator::find_lane(std::string_view name, bool node)
{
    for (auto& l : m_lanes)
        if (l->target.node == node && l->target.name == name)
            return l.get();
    return nullptr;
}

bool replicator::open(const std::string& dir, uint32_t shard, const outbox::change_made& made, std::string& err)
{
    if (m_lanes.empty())
        return true;
    m_dir   = dir;
    m_shard = shard;
    uint64_t dropped = 0, again = 0;
    const bool ok = m_box.open(dir, ".replicate", shard, made, [&](uint64_t id, std::string_view payload)
    {
        bytes::reader r(payload);
        uint8_t kind = 0;
        std::string target;
        task t;
        t.id = id;
        if (!r.u8(kind) || !r.bytes(target, 4096))
        {
            ++dropped;
            return false;
        }
        const bool node = std::string_view("pmgdxlbsiq").find(static_cast<char>(kind)) != std::string_view::npos;
        const bool read = node ? r.bytes(t.bucket, 4096) && r.bytes(t.key, 4096) && r.bytes(t.version_id, 4096) &&
                                     r.bytes(t.stamp, 4096) && r.bytes(t.tags, max_record_bytes)
                               : r.bytes(t.bucket, 4096) && r.bytes(t.key, 4096) && r.bytes(t.version_id, 4096) &&
                                     r.bytes(t.dest_bucket, 4096) && r.bytes(t.storage_class, 4096) &&
                                     (kind == 'P' || kind == 'M' || kind == 'G') &&
                                     (kind != 'G' || r.bytes(t.tags, 64 * 1024));
        lane* l = read ? find_lane(target, node) : nullptr;
        if (!l)
        {
            ++dropped;
            return false;
        }
        if (node)
        {
            t.node_kind   = static_cast<char>(kind);
            t.dest_bucket = t.bucket;
        }
        t.marker  = kind == 'M';
        t.tagging = kind == 'G';
        if (kind == 'P')
            ++m_open[version_key(t.bucket, t.key, t.version_id)];
        m_node_pending += node ? 1 : 0;
        l->q.push_back(std::move(t));
        ++m_pending;
        ++again;
        return true;
    }, err);
    if (!ok)
        return false;
    if (dropped)
        LOG_WARN(("storage: " + std::to_string(dropped) +
                  " replication(s) in the outbox name a target or a cluster node that is gone, and are dropped").c_str());

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
    {
        if (l->target.node)
            load_seed(*l);
        start(*l);
    }
    // A node is asked for its data's id at the first tick, and every so often after.
    if (m_nodes)
        arm_timer();
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
    lane* l = find_lane(cfg.target, false);
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
    if (t.node_kind)
    {
        w.u8(static_cast<uint8_t>(t.node_kind));
        w.bytes(l.target.name);
        w.bytes(t.bucket);
        w.bytes(t.key);
        w.bytes(t.version_id);
        w.bytes(t.stamp);
        w.bytes(t.tags);
        return w.take();
    }
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

replicator::task replicator::node_task(const cluster_change& c)
{
    task t;
    t.node_kind   = c.kind;
    t.bucket      = c.bucket;
    t.key         = c.key;
    t.version_id  = c.version_id;
    t.dest_bucket = c.bucket;
    t.stamp       = c.stamp;
    t.tags        = c.payload;
    return t;
}

bool replicator::enqueue_nodes(const cluster_change& c)
{
    if (m_stopped || m_nodes == 0)
        return false;
    for (auto& l : m_lanes)
        if (l->target.node)
            push(*l, node_task(c), false);
    return true;
}

bool replicator::enqueue_node(const std::string& name, const cluster_change& c)
{
    lane* l = m_stopped ? nullptr : find_lane(name, true);
    if (!l)
        return false;
    push(*l, node_task(c), false);
    return true;
}

void replicator::find_copy(std::string bucket, std::string key, std::string version_id, std::string etag,
                           std::function<void(std::string node)> found)
{
    m_questions.push_back({std::move(bucket), std::move(key), std::move(version_id), std::move(etag), std::move(found), 0});
    if (!m_asking)
        ask_next();
}

void replicator::ask_next()
{
    std::vector<lane*> nodes;
    for (auto& l : m_lanes)
        if (l->seed)
            nodes.push_back(l.get());
    while (!m_questions.empty() && m_questions.front().next >= nodes.size())
    {
        auto q = std::move(m_questions.front());
        m_questions.pop_front();
        q.found({});
    }
    m_asking = !m_questions.empty() && !m_stopped;
    if (!m_asking)
        return;
    copy_question& q = m_questions.front();
    lane& l = *nodes[q.next++];
    if (!l.seed->asker)
        l.seed->asker = new_peer(l.target);
    http_request rq;
    rq.head = signed_head(l, "HEAD", object_path(l.target.http, q.bucket, q.key),
                          q.version_id.empty() ? std::string() : "versionId=" + url_encode(q.version_id, false), {}, 0);
    rq.head_only   = true;
    rq.answer_secs = 10;
    auto alive = m_alive;
    const std::string name = l.target.name;
    l.seed->asker->exchange(std::move(rq), [this, alive, name](http_answer a)
    {
        if (!*alive || m_questions.empty())
            return;
        copy_question& q = m_questions.front();
        if (a.status == 200 && http_trim_ows(a.header("etag")) == "\"" + q.etag + "\"")
        {
            auto done = std::move(q);
            m_questions.pop_front();
            done.found(name);
        }
        ask_next();
    });
}

uint64_t replicator::stage(std::string_view check, const replication_config* cfg, const std::string& bucket,
                           const std::string& key, const std::string& version_id, bool marker, std::string_view tags,
                           const cluster_change* node, bool* copied)
{
    std::vector<task> tasks;
    lane* l = cfg ? tasks_for(*cfg, bucket, key, version_id, marker, tags, tasks) : nullptr;
    if (copied)
        *copied = l != nullptr;
    std::vector<std::pair<lane*, task>> node_tasks;
    if (node && !m_stopped)
        for (auto& nl : m_lanes)
            if (nl->target.node)
                node_tasks.emplace_back(nl.get(), node_task(*node));
    if (!l && node_tasks.empty())
        return 0;
    std::vector<std::string> payloads;
    if (l)
        for (const task& t : tasks)
            payloads.push_back(encode_task(*l, t));
    for (const auto& [nl, t] : node_tasks)
        payloads.push_back(encode_task(*nl, t));
    std::vector<uint64_t> ids;
    const uint64_t ticket = m_box.stage(check, payloads, ids);
    size_t i = 0;
    if (l)
        for (task& t : tasks)
            t.id = ids[i++];
    for (auto& nt : node_tasks)
        nt.second.id = ids[i++];
    if (!l)
        tasks.clear();
    // The answer of a write waits for as many other nodes as sync asks, each copy telling its ticket when it is taken.
    if (m_sync && !node_tasks.empty())
    {
        m_sync_waits[ticket].need = std::min<uint32_t>(m_sync, static_cast<uint32_t>(node_tasks.size()));
        for (const auto& nt : node_tasks)
            m_sync_copies[nt.second.id] = ticket;
    }
    m_staged.emplace(ticket, staged_copies{l, std::move(tasks), std::move(node_tasks)});
    return ticket;
}

void replicator::synced(uint64_t ticket, std::function<void()> then)
{
    const auto it = m_sync_waits.find(ticket);
    if (it == m_sync_waits.end() || it->second.need == 0 || m_stopped)
    {
        if (it != m_sync_waits.end())
        {
            ++m_c.node_synced;
            m_sync_waits.erase(it);
        }
        then();
        return;
    }
    it->second.then  = std::move(then);
    it->second.until = std::chrono::steady_clock::now() + std::chrono::milliseconds(m_sync_ms);
    arm_timer();
}

void replicator::sync_taken(uint64_t task_id, bool taken)
{
    const auto c = m_sync_copies.find(task_id);
    if (c == m_sync_copies.end())
        return;
    const uint64_t ticket = c->second;
    m_sync_copies.erase(c);
    const auto it = m_sync_waits.find(ticket);
    if (it == m_sync_waits.end() || !taken)
        return;
    if (it->second.need > 0 && --it->second.need == 0)
        sync_answer(ticket, false);
}

void replicator::sync_answer(uint64_t ticket, bool timed_out)
{
    const auto it = m_sync_waits.find(ticket);
    if (it == m_sync_waits.end())
        return;
    // A change whose answer nobody waits for yet is answered at once when its wait begins.
    if (!it->second.then)
    {
        it->second.need = 0;
        return;
    }
    std::function<void()> then = std::move(it->second.then);
    m_sync_waits.erase(it);
    ++(timed_out ? m_c.node_sync_timeouts : m_c.node_synced);
    then();
}

void replicator::settle(uint64_t ticket, bool made, std::function<void()> then)
{
    // A change that was not made waits for no node.
    if (!made)
        if (const auto w = m_sync_waits.find(ticket); w != m_sync_waits.end())
        {
            for (auto c = m_sync_copies.begin(); c != m_sync_copies.end();)
                c = c->second == ticket ? m_sync_copies.erase(c) : std::next(c);
            if (w->second.then)
                sync_answer(ticket, false);
            else
                m_sync_waits.erase(w);
        }
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
        for (auto& [nl, t] : sc.node_tasks)
            push(*nl, std::move(t), true);
    }
    m_box.settle(ticket, made, std::move(then));
}

void replicator::push(lane& l, task t, bool from_outbox)
{
    if (l.seed && l.q.size() >= m_node_queue_max)
        overflow(l);
    if (!from_outbox)
        t.id = m_box.add(encode_task(l, t));
    m_node_pending += t.node_kind ? 1 : 0;
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
    // A write whose nodes did not all take it in time is answered anyway, and its copies go on.
    std::vector<uint64_t> late;
    for (const auto& [ticket, w] : m_sync_waits)
        if (w.then && now >= w.until)
            late.push_back(ticket);
    for (const uint64_t ticket : late)
        sync_answer(ticket, true);
    waiting = std::any_of(m_sync_waits.begin(), m_sync_waits.end(), [](const auto& w) { return bool(w.second.then); });
    for (auto& lp : m_lanes)
    {
        lane& l = *lp;
        for (auto& p : l.peers)
            p->tick(now);
        if (l.seed)
        {
            seeding& sd = *l.seed;
            sd.probe->tick(now);
            if (!sd.asking && now >= sd.next_ask)
                ask_id(l);
            if (sd.confirmed && !sd.done && !sd.saving && l.q.size() < std::min(seed_low, m_node_queue_max / 2))
                seed_more(l);
            waiting = true;
        }
        if (!l.q.empty() && now >= l.next_try)
            start(l);
        waiting = waiting || !l.active.empty() || !l.q.empty();
    }
    if (waiting)
        arm_timer();
}

void replicator::start(lane& l)
{
    if (l.q.empty() || m_stopped || l.active.size() >= lane_width)
        return;
    if (std::chrono::steady_clock::now() < l.next_try)
    {
        arm_timer();
        return;
    }
    // A key's copies go one at a time and in order, and a bucket's change alone, after what is in flight and before
    // what follows it.
    std::vector<std::shared_ptr<job>> started;
    size_t scanned = 0;
    std::string name;
    for (auto it = l.q.begin(); it != l.q.end() && l.active.size() < lane_width && scanned < lane_scan; ++scanned)
    {
        const bool barrier = it->node_kind == 'b' || it->node_kind == 'i';
        if (l.barrier || (barrier && !l.active.empty()))
            break;
        name = version_key(it->bucket, it->key, {});
        if (l.busy.contains(name))
        {
            ++it;
            continue;
        }
        auto j  = std::make_shared<job>();
        j->t    = std::move(*it);
        it      = l.q.erase(it);
        j->slot = free_slot(l);
        l.active.push_back(j);
        l.busy.insert(std::move(name));
        l.barrier = barrier;
        started.push_back(j);
    }
    arm_timer();
    // Started once the queue is no longer walked, since a step that ends at once starts the next copies itself.
    for (const auto& j : started)
        if (j->live)
            run(l, j);
}

void replicator::run(lane& l, const std::shared_ptr<job>& j)
{
    if (j->t.node_kind)
        run_node(l, j);
    else if (j->t.tagging)
        run_tags(l, j);
    else if (j->t.marker)
        run_marker(l, j);
    else
        run_put(l, j);
}

void replicator::land(lane& l, const std::shared_ptr<job>& j)
{
    j->live = false;
    std::erase(l.active, j);
    l.busy.erase(version_key(j->t.bucket, j->t.key, {}));
    l.barrier = false;
}

void replicator::requeue(lane& l, const std::shared_ptr<job>& j)
{
    land(l, j);
    l.q.push_front(std::move(j->t));
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

void replicator::ended(lane& l, const std::shared_ptr<job>& j, outcome o, uint64_t bytes)
{
    if (!j->live)
        return;
    if (j->fd >= 0)
    {
        m_loop.close_fd(j->fd);
        j->fd = -1;
    }
    const task& t = j->t;
    // A streak of failures is said once, at its start, and a refusal every time.
    if (((o == outcome::retry && l.failures == 0) || o == outcome::refused) && t.node_kind)
        LOG_WARN(("storage: sending " + t.bucket + (t.key.empty() ? "" : "/" + t.key) + " (" + node_change_name(t.node_kind, !t.version_id.empty()) +
                  ") to the cluster node " + l.target.name + " failed (" + j->why + ")" +
                  (o == outcome::retry ? "; it is sent again until it is taken" : "; it is given up"))
                     .c_str());
    else if ((o == outcome::retry && l.failures == 0) || o == outcome::refused)
        LOG_WARN(("storage: copying " + t.bucket + "/" + t.key +
                  (t.tagging ? " (its tags)" : t.marker ? " (a delete marker)" : "") + " to " + l.target.name + ":" +
                  t.dest_bucket + " failed (" + j->why + ")" +
                  (o == outcome::retry        ? "; it is tried again until it is taken"
                   : t.marker || t.tagging    ? "; it is given up"
                                              : "; the version is FAILED"))
                     .c_str());
    if (o == outcome::retry)
    {
        requeue(l, j);
        back_off(l);
        return;
    }
    auto retire = [this, &l, j, o, bytes]()
    {
        land(l, j);
        if (j->t.node_kind)
        {
            sync_taken(j->t.id, o == outcome::done);
            ++(o == outcome::done ? m_c.node_sent : m_c.node_failed);
            --m_node_pending;
        }
        else if (o == outcome::done)
        {
            ++m_c.completed;
            m_c.bytes += bytes;
        }
        else
            ++m_c.failed;
        m_box.done(j->t.id);
        --m_pending;
        l.failures = 0;
        l.next_try = {};
        start(l);
    };
    // A delete marker, a tag change and a change sent to another node have no status of their own to write.
    if (t.marker || t.tagging || t.node_kind)
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
        if (!*alive || !j->live)
            return;
        if (written)
        {
            retire();
            return;
        }
        // The copy is made again, since its status is what a restart goes by.
        ++m_open[vk];
        requeue(*lp, j);
        back_off(*lp);
    });
}

replicator::outcome replicator::judge(const http_answer& a)
{
    if (a.status == 0 || (a.status >= 500 && a.status != 501) || a.status == 408 || a.status == 409 || a.status == 429)
        return outcome::retry;
    return outcome::refused;
}

replicator::outcome replicator::judge_node(task& t, const http_answer& a)
{
    const std::string code = element_text(a.body, "Code");
    // The node has the change or a newer one, or nothing a removal, a tag or a lock could change.
    if (a.status == 412 ||
        (a.status == 404 && code != "NoSuchBucket" && t.node_kind != 'p' && t.node_kind != 's' && t.node_kind != 'b'))
        return outcome::done;
    // A bucket that is not made yet, or not emptied yet, waits for the change another lane carries, but not forever.
    if (a.status == 404 || a.status == 409)
    {
        const auto now = std::chrono::steady_clock::now();
        if (t.waiting_since == std::chrono::steady_clock::time_point{})
            t.waiting_since = now;
        return now - t.waiting_since > node_wait_limit ? outcome::refused : outcome::retry;
    }
    // A node that is down, busy, or not given this node's key yet, is sent the change until it takes it.
    if (a.status == 0 || a.status >= 500 || a.status == 403 || a.status == 408 || a.status == 429)
        return outcome::retry;
    return outcome::refused;
}

replicator::outcome replicator::judge_of(task& t, const http_answer& a)
{
    return t.node_kind ? judge_node(t, a) : judge(a);
}

void replicator::exchange(lane& l, const std::shared_ptr<job>& j, http_request rq,
                          std::function<void(lane&, const std::shared_ptr<job>&, http_answer)> then)
{
    auto alive = m_alive;
    lane* lp = &l;
    rq.answer_secs = answer_secs;
    l.peers[j->slot]->exchange(std::move(rq), [alive, lp, j, then](http_answer a)
    {
        if (!*alive || !j->live)
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
    head += "authorization: " + s3::sign(in) + "\r\nconnection: keep-alive\r\nuser-agent: socketley-storage-replication\r\n\r\n";
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
    exchange(l, j, std::move(rq), [this](lane& lp, const std::shared_ptr<job>& jj, http_answer a)
    {
        ended(lp, jj, a.status / 100 == 2 ? outcome::done : judge(a), 0);
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
    exchange(l, j, std::move(rq), [this](lane& lp, const std::shared_ptr<job>& jj, http_answer a)
    {
        ended(lp, jj, a.status / 100 == 2 ? outcome::done : judge(a), 0);
    });
}

http_request replicator::node_record(const lane& l, const task& t) const
{
    http_request rq;
    std::string path = l.target.http.path;
    while (!path.empty() && path.back() == '/')
        path.pop_back();
    path += "/" + t.bucket;
    if (t.node_kind == 'l' || t.node_kind == 'q')
        path = object_path(l.target.http, t.bucket, t.key);
    rq.body = t.tags;
    rq.head = signed_head(l, "POST", path, std::string(cluster_query) + "=",
                          {{"content-type", "application/octet-stream"}}, rq.body.size());
    return rq;
}

void replicator::run_node(lane& l, const std::shared_ptr<job>& j)
{
    const task& t = j->t;
    auto settle = [this](lane& lp, const std::shared_ptr<job>& jj, http_answer a)
    {
        ended(lp, jj, a.status / 100 == 2 ? outcome::done : judge_node(jj->t, a), 0);
    };
    http_request rq;
    const std::string path = object_path(l.target.http, t.bucket, t.key);
    switch (t.node_kind)
    {
        case 'p':
            run_put(l, j);
            return;
        case 's':
        {
            // A node being sent everything is asked first whether it has the version, or the object's bytes.
            rq.head = signed_head(l, "HEAD", path, t.version_id.empty() ? std::string()
                                                                        : "versionId=" + url_encode(t.version_id, false),
                                  {}, 0);
            rq.head_only = true;
            exchange(l, j, std::move(rq), [this](lane& lp, const std::shared_ptr<job>& jj, http_answer a)
            {
                if (a.status == 200)
                {
                    const object_meta* m = jj->t.version_id.empty() ? m_store.find(jj->t.bucket, jj->t.key) : nullptr;
                    if (!jj->t.version_id.empty() || (m && http_trim_ows(a.header("etag")) == "\"" + m->etag() + "\""))
                    {
                        ended(lp, jj, outcome::done, 0);
                        return;
                    }
                }
                if (a.status == 200 || a.status == 404)
                {
                    run_put(lp, jj);
                    return;
                }
                ended(lp, jj, judge_node(jj->t, a), 0);
            });
            return;
        }
        case 'm':
        case 'd':
            rq.head = signed_head(l, "DELETE", path, {}, {{std::string(cluster_stamp_header), t.stamp}}, 0);
            break;
        case 'x':
            rq.head = signed_head(l, "DELETE", path, "versionId=" + url_encode(t.version_id, false), {}, 0);
            break;
        case 'g':
        {
            const std::string query =
                t.version_id.empty() ? std::string("tagging=") : "tagging=&versionId=" + url_encode(t.version_id, false);
            if (t.tags.empty())
                rq.head = signed_head(l, "DELETE", path, query, {}, 0);
            else
            {
                rq.body = tagging_xml(decode_tags(t.tags));
                const auto md5 = md5_of(rq.body);
                rq.head = signed_head(l, "PUT", path, query,
                                      {{"content-md5", base64_encode(std::string_view(
                                                           reinterpret_cast<const char*>(md5.data()), 16))},
                                       {"content-type", "application/xml"}},
                                      rq.body.size());
            }
            break;
        }
        default:
            rq = node_record(l, t);
            break;
    }
    exchange(l, j, std::move(rq), std::move(settle));
}

void replicator::run_put(lane& l, const std::shared_ptr<job>& j)
{
    auto alive = m_alive;
    lane* lp = &l;
    auto then = [this, alive, lp, j](open_result o)
    {
        if (!*alive || !j->live)
        {
            if (o.fd >= 0)
                m_loop.close_fd(o.fd);
            return;
        }
        opened(*lp, j, std::move(o));
    };
    // An object of a bucket that keeps no versions is sent as it is now, which is its newest write.
    if (j->t.version_id.empty())
        m_store.open_object(j->t.bucket, j->t.key, 0, std::move(then));
    else
        m_store.open_version(j->t.bucket, j->t.key, j->t.version_id, 0, std::move(then));
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
        ended(l, j, gone ? outcome::done : outcome::retry, 0);
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
            ended(l, j, outcome::refused, 0);
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
            if (!*alive || !j->live)
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
        ended(l, j, outcome::retry, 0);
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

// The headers another node of the cluster is sent an object with: a replica's, its lock, and its stamp in place of the
// replication status, so the node keeps the version and the time this one gave it.
std::vector<std::pair<std::string, std::string>> node_headers(const object_meta& m)
{
    auto h = replica_headers(m, {});
    std::erase_if(h, [](const auto& e) { return e.first == "x-amz-replication-status" || e.first == replica_version_header; });
    for (const auto& [n, v] : m.extra)
    {
        if (n == retention_extra)
            h.emplace_back(std::string(cluster_retention_header), v);
        else if (n == legal_hold_extra)
            h.emplace_back(std::string(cluster_legal_hold_header), v);
    }
    h.emplace_back(std::string(cluster_stamp_header), cluster_stamp_text({version_of(m), m.mtime_ms}));
    return h;
}

// Whether `len` bytes of `m` go to `target` straight from the file: plain bytes, on a connection without TLS, and
// enough of them to be worth the pipe.
bool spliceable(const http_target& target, const object_meta& m, uint64_t len)
{
    return !target.tls && !is_encrypted(m) && len >= 64 * 1024;
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
    auto h = j->t.node_kind ? node_headers(m) : replica_headers(m, j->t.storage_class);
    // The bytes are checked by the destination against the source's own digests, so a copy torn on the way is refused.
    h.emplace_back("content-md5", base64_encode(std::string_view(reinterpret_cast<const char*>(m.md5.data()), 16)));
    const checksum_algo algo = checksum_algo_of(m);
    if (const std::string v = checksum_value(m, algo); !v.empty() && v.find('-') == std::string::npos)
        h.emplace_back(std::string(checksum_header(algo)), v);
    http_request rq;
    rq.head = signed_head(l, "PUT", object_path(l.target.http, j->t.dest_bucket, j->t.key), {}, std::move(h), m.size);
    if (spliceable(l.target.http, m, m.size))
    {
        rq.file_fd  = j->fd;
        rq.file_off = j->data_off;
        rq.file_len = m.size;
    }
    else if (m.size)
        rq.source = body_of(j, 0, m.size);
    exchange(l, j, std::move(rq), [this](lane& lp, const std::shared_ptr<job>& jj, http_answer a)
    {
        if (a.status / 100 == 2)
            ended(lp, jj, outcome::done, jj->meta.size);
        else
            ended(lp, jj, jj->source_failed ? outcome::refused : judge_of(jj->t, a), 0);
    });
}

void replicator::mpu_create(lane& l, const std::shared_ptr<job>& j)
{
    const object_meta& m = j->meta;
    auto h = j->t.node_kind ? node_headers(m) : replica_headers(m, j->t.storage_class);
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
            ended(lp, jj, judge_of(jj->t, a), 0);
            return;
        }
        jj->upload_id = element_text(a.body, "UploadId");
        if (jj->upload_id.empty())
        {
            jj->why = "the upload's creation named no UploadId";
            ended(lp, jj, outcome::retry, 0);
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
    if (!j->t.node_kind)
        h.emplace_back("x-amz-replication-status", "REPLICA");
    const checksum_algo algo = checksum_algo_of(j->meta);
    if (algo != checksum_algo::none && i < j->parts.checksums.size() && !j->parts.checksums[i].empty())
        h.emplace_back(std::string(checksum_header(algo)), base64_encode(j->parts.checksums[i]));
    const std::string query = "partNumber=" + std::to_string(number) + "&uploadId=" + url_encode(j->upload_id, false);
    http_request rq;
    rq.head = signed_head(l, "PUT", object_path(l.target.http, j->t.dest_bucket, j->t.key), query, std::move(h), len);
    if (spliceable(l.target.http, j->meta, len))
    {
        rq.file_fd  = j->fd;
        rq.file_off = j->data_off + first;
        rq.file_len = len;
    }
    else if (len)
        rq.source = body_of(j, first, len);
    exchange(l, j, std::move(rq), [this, number](lane& lp, const std::shared_ptr<job>& jj, http_answer a)
    {
        if (a.status / 100 != 2)
        {
            mpu_abort(lp, jj, jj->source_failed ? outcome::refused : judge_of(jj->t, a));
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
    if (!j->t.node_kind)
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
            ended(lp, jj, outcome::done, jj->meta.size);
            return;
        }
        if (a.status / 100 == 2)
            jj->why = "the completion was refused inside its 200";
        mpu_abort(lp, jj, a.status / 100 == 2 ? outcome::retry : judge_of(jj->t, a));
    });
}

void replicator::mpu_abort(lane& l, const std::shared_ptr<job>& j, outcome o)
{
    const std::string why = j->why;
    const std::string query = "uploadId=" + url_encode(j->upload_id, false);
    http_request rq;
    std::vector<std::pair<std::string, std::string>> h;
    if (!j->t.node_kind)
        h.emplace_back("x-amz-replication-status", "REPLICA");
    rq.head = signed_head(l, "DELETE", object_path(l.target.http, j->t.dest_bucket, j->t.key), query, std::move(h), 0);
    exchange(l, j, std::move(rq), [this, o, why](lane& lp, const std::shared_ptr<job>& jj, http_answer)
    {
        jj->why = why;
        ended(lp, jj, o, 0);
    });
}

// ─── Sending a node everything ──────────────────────────────────────────────

void replicator::overflow(lane& l)
{
    LOG_WARN(("storage: the cluster node " + l.target.name + " is " + std::to_string(l.q.size()) +
              " changes behind, so they are let go and it is sent everything this shard holds once it answers").c_str());
    for (const task& t : l.q)
    {
        m_box.done(t.id);
        sync_taken(t.id, false);
    }
    m_pending -= l.q.size();
    m_node_pending -= l.q.size();
    l.q.clear();
    ++m_c.node_overflows;
    seeding& sd = *l.seed;
    sd.buckets   = false;
    sd.done      = false;
    sd.keys_done = false;
    sd.confirmed = false;
    sd.next_ask  = {};
    sd.removals.clear();
    sd.bucket.clear();
    sd.key.clear();
    save_seed(l);
}

std::string replicator::seed_path(const lane& l) const
{
    return m_dir + "/.replicate/seed." + std::to_string(m_shard) + "." + l.target.name;
}

void replicator::load_seed(lane& l)
{
    l.seed = std::make_unique<seeding>();
    l.seed->probe = new_peer(l.target);
    std::string text;
    if (std::string why; !read_targets_file(seed_path(l), "seeding", text, why))
        return;
    // Lines of `name value`, the bucket and key in hex, since a key may hold any byte.
    for (const target_line& line : split_target_lines(text))
    {
        if (line.fields.size() != 2)
            continue;
        const std::string_view name = line.fields[0], value = line.fields[1];
        if (name == "id")
            l.seed->id = value == "-" ? std::string() : std::string(value);
        else if (name == "buckets")
            l.seed->buckets = value == "1";
        else if (name == "done")
            l.seed->done = value == "1";
        else if (name == "bucket")
            l.seed->bucket = value == "-" ? std::string() : unhex(value);
        else if (name == "key")
            l.seed->key = value == "-" ? std::string() : unhex(value);
    }
}

void replicator::save_seed(const lane& l)
{
    const seeding& sd = *l.seed;
    const std::string text = "id " + (sd.id.empty() ? std::string("-") : sd.id) + "\nbuckets " + (sd.buckets ? "1" : "0") +
                             "\ndone " + (sd.done ? "1" : "0") + "\nbucket " +
                             (sd.bucket.empty() ? std::string("-") : hex_of(sd.bucket)) + "\nkey " +
                             (sd.key.empty() ? std::string("-") : hex_of(sd.key)) + "\n";
    // A note lost to a crash sends the node again what it already has, which it then refuses as had.
    if (!replace_note(seed_path(l), text))
        LOG_WARN(("storage: how far the cluster node " + l.target.name + " was sent everything could not be noted").c_str());
}

void replicator::ask_id(lane& l)
{
    seeding& sd = *l.seed;
    sd.asking = true;
    std::string path = l.target.http.path;
    while (!path.empty() && path.back() == '/')
        path.pop_back();
    http_request rq;
    rq.head = signed_head(l, "GET", path + "/", std::string(cluster_query) + "=", {}, 0);
    rq.answer_secs = ask_every_secs;
    auto alive = m_alive;
    lane* lp   = &l;
    sd.probe->exchange(std::move(rq), [this, alive, lp](http_answer a)
    {
        if (!*alive || m_stopped)
            return;
        seeding& s = *lp->seed;
        s.asking   = false;
        std::string id = a.body;
        while (!id.empty() && (id.back() == '\n' || id.back() == '\r'))
            id.pop_back();
        const bool ok = a.status == 200 && id.size() == 32 &&
                        id.find_first_not_of("0123456789abcdef") == std::string::npos;
        s.next_ask = std::chrono::steady_clock::now() + std::chrono::seconds(ok ? ask_every_secs : ask_retry_secs);
        if (!ok)
            return;
        // A node whose data this shard never sent everything to, a new one or one that began again empty, is sent it.
        if (id != s.id)
        {
            LOG_INFO(("storage: the cluster node " + lp->target.name + " holds data this shard has not sent all it has "
                      "to, so it is sent everything").c_str());
            s.id        = id;
            s.buckets   = false;
            s.done      = false;
            s.keys_done = false;
            s.removals.clear();
            s.bucket.clear();
            s.key.clear();
            ++m_c.node_seeds;
            save_seed(*lp);
        }
        s.confirmed = true;
    });
}

void replicator::seed_more(lane& l)
{
    seeding& sd = *l.seed;
    // A bucket's change goes before its keys, from shard 0 alone, since every shard has the bucket's documents.
    if (!sd.buckets)
    {
        if (m_shard == 0 && m_seed_first)
            for (std::string& first : m_seed_first())
                push(l, node_task({'i', {}, {}, {}, {}, std::move(first)}), false);
        if (m_shard == 0)
        {
            auto all = m_store.buckets();
            std::sort(all.begin(), all.end(), [](const bucket_info& a, const bucket_info& b) { return a.name < b.name; });
            for (const bucket_info& b : all)
            {
                push(l, node_task({'b', b.name, {}, {}, {}, encode_cluster_record({'c', b.owner, 0, {}, {}})}), false);
                for (auto& [kind, xml] : m_store.bucket_docs_text(b.name))
                    push(l, node_task({'b', b.name, {}, {}, {},
                                       encode_cluster_record({'d', {}, static_cast<uint8_t>(kind), std::move(xml), {}})}),
                         false);
            }
        }
        sd.buckets = true;
    }
    auto all = m_store.buckets();
    std::sort(all.begin(), all.end(), [](const bucket_info& a, const bucket_info& b) { return a.name < b.name; });
    // A batch stays well inside the queue's bound, so a seeding never lets go of itself.
    const size_t batch = std::clamp<size_t>(m_node_queue_max / 4, 1, seed_batch);
    size_t queued = 0;
    for (const bucket_info& b : all)
    {
        if (sd.keys_done)
            break;
        if (b.name < sd.bucket)
            continue;
        const std::string after = b.name == sd.bucket ? sd.key : std::string();
        queued += m_store.keys_after(b.name, after, batch - queued,
                                     [&](const std::string& key, const std::vector<const object_meta*>& versions)
        {
            for (const object_meta* m : versions)
            {
                cluster_change c;
                c.bucket = b.name;
                c.key    = key;
                if (is_delete_marker(*m))
                {
                    c.kind       = 'm';
                    c.version_id = version_of(*m).id;
                    c.stamp      = cluster_stamp_text({version_of(*m), m->mtime_ms});
                }
                else
                {
                    c.kind       = 's';
                    c.version_id = has_version(*m) ? version_of(*m).id : std::string();
                }
                push(l, node_task(c), false);
                ++m_c.node_seeded;
            }
            sd.bucket = b.name;
            sd.key    = key;
        });
        if (queued >= batch)
            break;
    }
    // Last, what this shard removed in the last day, which the node may still hold, a batch at a time.
    if (!sd.keys_done && queued < batch)
    {
        sd.keys_done = true;
        m_store.each_removed([&](const std::string& bucket, const std::string& key, const std::string& id, int64_t when)
        {
            // A removal in a bucket removed since is no node's to make.
            if (!m_store.has_bucket(bucket))
                return;
            cluster_change c;
            c.bucket = bucket;
            c.key    = key;
            if (id.empty())
            {
                c.kind  = 'd';
                c.stamp = cluster_stamp_text({{static_cast<uint64_t>(when) * 1000, "null", false}, when});
            }
            else
            {
                c.kind       = 'x';
                c.version_id = id;
            }
            sd.removals.push_back(std::move(c));
        });
    }
    while (sd.keys_done && queued < batch && !sd.removals.empty())
    {
        push(l, node_task(sd.removals.back()), false);
        sd.removals.pop_back();
        ++queued;
    }
    sd.done   = sd.keys_done && sd.removals.empty();
    sd.saving = true;
    auto alive = m_alive;
    lane* lp   = &l;
    m_box.sync([this, alive, lp]()
    {
        if (!*alive)
            return;
        lp->seed->saving = false;
        save_seed(*lp);
        if (lp->seed->done)
            LOG_INFO(("storage: everything this shard holds is queued for the cluster node " + lp->target.name).c_str());
    });
}

void replicator::stop()
{
    if (m_stopped)
        return;
    m_stopped = true;
    m_sync_waits.clear();
    m_sync_copies.clear();
    for (auto& l : m_lanes)
    {
        for (auto& p : l->peers)
            p->stop();
        if (l->seed)
        {
            l->seed->probe->stop();
            if (l->seed->asker)
                l->seed->asker->stop();
        }
        for (auto& j : l->active)
        {
            if (j->fd >= 0)
                m_loop.close_fd(j->fd);
            j->live = false;
        }
        l->active.clear();
        l->busy.clear();
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
