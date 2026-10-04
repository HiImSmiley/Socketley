// A bucket's replication over S3: setting, reading and deleting its ReplicationConfiguration, the status a new version
// is written with, and the copies the owner of a key queues for each change it makes.
#include "storage_run.h"

#include "s3_notify.h"
#include "s3_replication.h"
#include "s3_xml.h"

namespace socketley::storage
{

bool replica_request(const s3_request& r)
{
    // A copy is no replica, which a replication writes from the bytes it read itself.
    return http_token_equals(http_trim_ows(r.header("x-amz-replication-status")), "replica", 7) &&
           !r.has_header("x-amz-copy-source");
}

void storage_run::op_put_replication(const std::shared_ptr<conn>& c)
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
    replication_config cfg;
    if (!parse_replication_config(c->body, cfg, err))
    {
        send_error(c, err);
        return;
    }
    if (m_store.bucket_versioning(q.bucket) != versioning::enabled)
    {
        s3_error e = make_error("InvalidRequest");
        e.message  = "Versioning must be 'Enabled' on the bucket to apply a replication configuration";
        send_error(c, e);
        return;
    }
    // The Role names the target the copies are written to with its credentials, which must be one the runtime was given.
    if (!m_repl.has_target(cfg.target))
    {
        s3_error e = make_error("InvalidArgument");
        e.message  = "The Role names no replication target this endpoint was given with --replication-targets";
        send_error(c, e, false, "ArgumentName", cfg.role);
        return;
    }
    std::weak_ptr<conn> weak = c;
    m_node.set_doc(bucket_doc::replication, q.bucket, replication_config_xml(cfg), [this, weak](st s)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (s == st::invalid_bucket_state)
        {
            s3_error e = make_error("InvalidRequest");
            e.message  = "Versioning must be 'Enabled' on the bucket to apply a replication configuration";
            send_error(cc, e);
            return;
        }
        if (s != st::ok)
        {
            send_error_st(cc, s);
            return;
        }
        send_response(cc, response{});
    });
}

void storage_run::op_get_replication(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    const auto cfg = m_store.bucket_replication(c->req.bucket);
    if (!cfg)
    {
        send_error(c, make_error("ReplicationConfigurationNotFoundError"));
        return;
    }
    response r;
    r.headers.emplace_back("Content-Type", "application/xml");
    r.body = replication_config_xml(*cfg);
    send_response(c, std::move(r));
}

void storage_run::op_delete_replication(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    store_doc(c, bucket_doc::replication, c->req.bucket, {}, 204);
}

void storage_run::replication_mark(std::string_view bucket, std::string_view key, object_meta& m, bool sse_c,
                                   bool replica)
{
    set_replication_status(m, {});
    // A copy of a replica is no replica, so the source's version id it carried goes with the status.
    std::erase_if(m.extra, [](const auto& e) { return e.first == replica_version_extra; });
    // A replica is not copied on, which is what keeps two buckets that replicate to each other from doing so forever.
    if (replica)
    {
        set_replication_status(m, replication_replica);
        return;
    }
    const auto cfg = m_store.bucket_replication(bucket);
    if (cfg && !sse_c && !replication_rules_for(*cfg, key, tags_of(m), false).empty())
        set_replication_status(m, replication_pending);
}

void storage_run::replica_source(const s3_request& r, object_meta& m)
{
    const std::string_view id = http_trim_ows(r.header(replica_version_header));
    if (replica_request(r) && valid_version_id(id) && id != "null")
        m.extra.emplace_back(std::string(replica_version_extra), std::string(id));
}

bool storage_run::replicate_change(const change_note& n)
{
    const auto cfg = m_store.bucket_replication(n.bucket);
    if (!cfg || n.who.replica)
        return false;
    // A tag change follows a version that was copied or is on its way, as in S3.
    if (n.event == ev_tagging_put || n.event == ev_tagging_del)
    {
        const object_meta* m = m_store.find_version(n.bucket, n.key, n.version_id);
        const std::string_view status = m ? replication_status_of(*m) : std::string_view{};
        return (status == replication_completed || status == replication_pending) &&
               m_repl.enqueue_tags(*cfg, n.bucket, n.key, n.version_id, n.tags);
    }
    if (n.has_object)
        return n.replication == replication_pending && m_repl.enqueue(*cfg, n.bucket, n.key, n.version_id, false, n.tags);
    // A delete marker a client made is copied, and one a lifecycle rule made is not, as in S3.
    return n.event == ev_marker && m_repl.enqueue(*cfg, n.bucket, n.key, n.version_id, true, {});
}

uint64_t storage_run::stage_copies(const change_note& n, std::string_view check)
{
    const auto cfg = m_store.bucket_replication(n.bucket);
    if (!cfg || n.who.replica)
        return 0;
    if (n.has_object)
        return n.replication == replication_pending
                   ? m_repl.stage(check, *cfg, n.bucket, n.key, n.version_id, false, n.tags)
                   : 0;
    return n.event == ev_marker ? m_repl.stage(check, *cfg, n.bucket, n.key, n.version_id, true, {}) : 0;
}

}   // namespace socketley::storage
