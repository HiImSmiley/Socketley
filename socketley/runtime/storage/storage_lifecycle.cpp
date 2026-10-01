// Bucket lifecycle: the configuration's operations, and the sweep that expires
// objects and aborts incomplete uploads by its rules.
//
// Each shard sweeps the keys and uploads it owns, removing an object through
// the same owner-side delete a DeleteObject takes, so the unlink is durable and
// journalled exactly as one.  A pass walks the index a page at a time with at
// most a few removals in flight and a pause between steps, so no turn of the
// loop spends long on it however many keys expire.
#include "storage_run.h"

#include <algorithm>

#include "lifecycle.h"
#include "s3_xml.h"
#include "../../shared/logging.h"

namespace socketley::storage
{

namespace
{

// Keys a step walks before it pauses, keys one walk of the index takes, and removals in flight at once.
constexpr size_t   lc_step_budget = 4096;
constexpr size_t   lc_page        = 256;
constexpr uint32_t lc_inflight    = 8;
constexpr long     lc_pause_ns    = 10'000'000;

// What a walk of the index finds due under one rule.
class due_finder final : public list_visitor
{
public:
    due_finder(lifecycle_pass& p, const std::string& bucket, int64_t now_ms, int64_t day_ms)
        : m_p(p), m_bucket(bucket), m_now(now_ms), m_day(day_ms), m_rule(p.cfg->rules[p.rule])
    {
    }

    void object(const std::string& key, const object_meta& meta) override
    {
        ++m_p.scanned;
        if (lifecycle_object_due(m_rule, key, meta, m_now, m_day))
            m_p.due.push_back({m_bucket, key, m_p.cfg, m_p.rule, false});
    }
    void prefix(std::string) override {}
    void truncated(const std::string& resume_at) override
    {
        m_more = true;
        m_p.resume = resume_at;
    }

    bool more() const { return m_more; }

private:
    lifecycle_pass&       m_p;
    const std::string&    m_bucket;
    int64_t               m_now;
    int64_t               m_day;
    const lifecycle_rule& m_rule;
    bool                  m_more{false};
};

}   // namespace

// ─── The configuration ──────────────────────────────────────────────────────

void storage_run::op_put_lifecycle(const std::shared_ptr<conn>& c)
{
    const s3_request& q = c->req;
    if (!m_store.has_bucket(q.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    s3_error err;
    if (!body_md5_ok(q, c->body, err))
    {
        send_error(c, err);
        return;
    }
    auto cfg = std::make_shared<lifecycle_config>();
    if (!parse_lifecycle(c->body, *cfg, err))
    {
        send_error(c, err);
        return;
    }
    std::weak_ptr<conn> weak = c;
    // Every shard parses the same canonical document, so an ID generated here is every shard's.
    m_node.set_doc(bucket_doc::lifecycle, q.bucket, lifecycle_xml(*cfg), [this, weak](st s)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (s != st::ok)
        {
            send_error_st(cc, s);
            return;
        }
        send_response(cc, response{});
    });
}

void storage_run::op_get_lifecycle(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    const auto cfg = m_store.lifecycle(c->req.bucket);
    if (!cfg)
    {
        send_error(c, make_error("NoSuchLifecycleConfiguration"));
        return;
    }
    response r;
    r.headers.emplace_back("Content-Type", "application/xml");
    r.body = lifecycle_xml(*cfg);
    send_response(c, std::move(r));
}

void storage_run::op_delete_lifecycle(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    std::weak_ptr<conn> weak = c;
    m_node.set_doc(bucket_doc::lifecycle, c->req.bucket, {}, [this, weak](st s)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (s != st::ok)
        {
            send_error_st(cc, s);
            return;
        }
        response r;
        r.status = 204;
        send_response(cc, std::move(r));
    });
}

// ─── The sweep ──────────────────────────────────────────────────────────────

void storage_run::lifecycle_changed()
{
    if (m_lc)
        m_lc_again = true;
    else
        m_lc_next = {};
    arm_sweep();
}

void storage_run::lifecycle_tick()
{
    if (m_lc)
    {
        // A pass waiting out its in-flight removals is moved on by their answers, and one between steps by its timer.
        if (!m_lc_timer.armed && m_lc->inflight == 0)
        {
            m_lc->scanned = 0;
            lifecycle_pump();
        }
        return;
    }
    if (m_store.lifecycle_buckets() == 0 || std::chrono::steady_clock::now() < m_lc_next)
        return;
    m_lc = std::make_unique<lifecycle_pass>();
    m_lc->id = ++m_lc_passes;
    for (const bucket_info& b : m_store.buckets())
        if (m_store.lifecycle(b.name))
            m_lc->buckets.push_back(b.name);
    lifecycle_pump();
}

bool storage_run::lifecycle_walk(lifecycle_pass& p)
{
    while (p.bucket < p.buckets.size())
    {
        const std::string& name = p.buckets[p.bucket];
        if (!p.cfg)
        {
            p.cfg          = m_store.lifecycle(name);
            p.uploads_done = false;
            p.rule         = 0;
            p.has_resume   = false;
            if (!p.cfg)
            {
                ++p.bucket;
                continue;
            }
        }
        const int64_t now = static_cast<int64_t>(m_store.now_ms());

        // The uploads first: this shard holds those whose key it owns, and there are few of them.
        if (!p.uploads_done)
        {
            p.uploads_done = true;
            bool any = false;
            for (const lifecycle_rule& r : p.cfg->rules)
                any = any || r.aborts();
            if (any)
                for (const mpu_upload* u : m_mpu.uploads_of(name))
                {
                    ++p.scanned;
                    if (u->state != mpu_state::open)
                        continue;
                    for (size_t i = 0; i < p.cfg->rules.size(); ++i)
                        if (lifecycle_upload_due(p.cfg->rules[i], u->key, u->initiated_ms, now, m_lc_day_ms))
                        {
                            p.due.push_back({name, u->id, p.cfg, i, true});
                            break;
                        }
                }
            return true;
        }

        if (p.rule >= p.cfg->rules.size())
        {
            p.cfg.reset();
            ++p.bucket;
            continue;
        }
        const lifecycle_rule& rule = p.cfg->rules[p.rule];
        auto next_phase = [&p]()
        {
            p.has_resume = false;
            p.resume.clear();
            if (p.versions_phase)
                ++p.rule;
            p.versions_phase = !p.versions_phase;
        };
        if (!p.versions_phase)
        {
            if (!rule.expires())
            {
                next_phase();
                continue;
            }
            list_query q;
            q.prefix     = rule.prefix;
            q.max_keys   = lc_page;
            q.has_resume = p.has_resume;
            q.resume_at  = p.resume;
            due_finder finder(p, name, now, m_lc_day_ms);
            const st s = m_store.list_walk(name, q, finder);
            p.has_resume = s == st::ok && finder.more();
            if (!p.has_resume)
                next_phase();
            return true;
        }
        if (!rule.versions())
        {
            next_phase();
            continue;
        }
        // A version is noncurrent from the moment the one after it was made, and a marker with nothing behind it is spent.
        const std::string more = m_store.walk_versioned_keys(name, rule.prefix, p.has_resume ? p.resume : std::string{},
            lc_page, [&](const std::string& key, const object_meta* latest, const std::vector<object_meta>& versions)
            {
                p.scanned += versions.size() + 1;
                const bool marker_latest = !latest && !versions.empty() && is_delete_marker(versions.front());
                if (marker_latest && versions.size() == 1 && rule.delete_marker == 1)
                    p.due.push_back({name, key, p.cfg, p.rule, false, version_of(versions.front()).id});
                const object_meta* newer = latest;
                for (const object_meta& v : versions)
                {
                    if (newer && !is_delete_marker(v) &&
                        lifecycle_noncurrent_due(rule, key, v, newer->mtime_ms, now, m_lc_day_ms))
                        p.due.push_back({name, key, p.cfg, p.rule, false, version_of(v).id});
                    newer = &v;
                }
            });
        p.has_resume = !more.empty();
        p.resume     = more;
        if (!p.has_resume)
            next_phase();
        return true;
    }
    return false;
}

void storage_run::lifecycle_issue(lifecycle_pass& p)
{
    lifecycle_pass::due_key d = std::move(p.due.front());
    p.due.pop_front();
    const uint64_t id = p.id;

    // The rules that found it must still be the bucket's when it goes, or a change made meanwhile is overruled.
    if (m_store.lifecycle(d.bucket) != d.cfg)
        return;

    if (d.upload)
    {
        const mpu_upload* u = m_mpu.find(d.bucket, d.key);
        if (!u || u->state != mpu_state::open ||
            !lifecycle_upload_due(d.cfg->rules[d.rule], u->key, u->initiated_ms,
                                  static_cast<int64_t>(m_store.now_ms()), m_lc_day_ms))
            return;
        ++p.inflight;
        if (m_mpu.abort(d.bucket, d.key, [this, id]() { lifecycle_done(id); }))
        {
            ++p.aborted;
            ++m_c.lifecycle_aborted;
        }
        else
            --p.inflight;
        return;
    }

    ++p.inflight;
    const std::string bucket = d.bucket;
    const std::string key    = d.key;
    if (!d.version_id.empty())
    {
        // Asked under the key's lane: the rules are still the bucket's and the version is still behind a newer one, or a lone marker.
        auto still = [this, d](const object_meta& m)
        {
            if (m_store.lifecycle(d.bucket) != d.cfg)
                return false;
            const object_meta* marker = m_store.latest_marker(d.bucket, d.key);
            if (is_delete_marker(m))
                return marker == &m && m_store.find(d.bucket, d.key) == nullptr;
            return m_store.find(d.bucket, d.key) != &m;
        };
        m_store.remove_version_local(bucket, key, d.version_id, [this, id, bucket, key](remove_result r)
        {
            if (r.status == st::ok && r.existed)
            {
                ++m_c.lifecycle_expired;
                if (m_lc && m_lc->id == id)
                    ++m_lc->expired;
            }
            else if (r.status != st::ok && r.status != st::no_such_bucket)
                LOG_WARN(("storage: lifecycle could not remove a version of " + bucket + "/" + key + ": " +
                          status_name(r.status)).c_str());
            lifecycle_done(id);
        }, std::move(still));
        return;
    }
    // Asked under the key's lane, so an object written again or retagged after the walk saw it is judged as it is.
    auto still_due = [this, d = std::move(d)](const object_meta& m)
    {
        return m_store.lifecycle(d.bucket) == d.cfg &&
               lifecycle_object_due(d.cfg->rules[d.rule], d.key, m,
                                    static_cast<int64_t>(m_store.now_ms()), m_lc_day_ms);
    };
    m_store.remove_local(bucket, key, [this, id, bucket, key](st s, bool existed)
    {
        if (s == st::ok && existed)
        {
            ++m_c.lifecycle_expired;
            if (m_lc && m_lc->id == id)
                ++m_lc->expired;
            notify_delete(bucket, key);
        }
        else if (s != st::ok && s != st::no_such_bucket)
            LOG_WARN(("storage: lifecycle could not remove " + bucket + "/" + key + ": " + status_name(s)).c_str());
        lifecycle_done(id);
    }, std::move(still_due));
}

void storage_run::lifecycle_done(uint64_t pass_id)
{
    if (!m_lc || m_lc->id != pass_id)
        return;
    --m_lc->inflight;
    lifecycle_pump();
}

void storage_run::lifecycle_pump()
{
    if (!m_lc || m_stopped || m_lc->pumping)
        return;
    lifecycle_pass& p = *m_lc;
    p.pumping = true;
    bool finished = false;
    for (;;)
    {
        while (p.inflight < lc_inflight && !p.due.empty())
            lifecycle_issue(p);
        if (!p.due.empty())
            break;
        if (p.scanned >= lc_step_budget)
        {
            if (!m_lc_timer.armed)
            {
                m_lc_timer.ts  = {0, lc_pause_ns};
                m_lc_timer.req = io_request{};
                m_lc_timer.req.owner = this;
                m_lc_timer.req.type  = op_timeout;
                m_lc_timer.armed = m_loop.submit_timeout(&m_lc_timer.ts, &m_lc_timer.req);
            }
            break;
        }
        if (!lifecycle_walk(p))
        {
            finished = p.inflight == 0;
            break;
        }
    }
    p.pumping = false;
    if (!finished)
        return;

    if (p.expired || p.aborted)
        LOG_INFO(("storage: lifecycle expired " + std::to_string(p.expired) + " object(s) and aborted " +
                  std::to_string(p.aborted) + " incomplete upload(s)").c_str());
    m_lc.reset();
    // A pass an hour at most, and more often only under a test's shortened day.
    const auto every = std::chrono::milliseconds(std::clamp<int64_t>(m_lc_day_ms / 24, 1000, 3600 * 1000));
    m_lc_next = m_lc_again ? std::chrono::steady_clock::time_point{} : std::chrono::steady_clock::now() + every;
    m_lc_again = false;
    arm_sweep();
}

}   // namespace socketley::storage
