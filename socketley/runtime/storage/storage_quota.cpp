// A bucket's quota over S3: setting, reading and deleting the BucketQuota document `?quota` carries, which only an
// admin may, since a quota bounds what the bucket's owner may store.
#include "storage_run.h"

#include "s3_quota.h"
#include "s3_xml.h"

namespace socketley::storage
{

bool storage_run::quota_admin(const std::shared_ptr<conn>& c)
{
    // No user is the runtime's own key or an anonymous runtime, which may do everything.
    if (!c->user || c->user->admin)
        return true;
    s3_error e = make_error("AccessDenied");
    e.message  = "Only an admin may read or set a bucket's quota.";
    send_error(c, e);
    return false;
}

void storage_run::op_put_quota(const std::shared_ptr<conn>& c)
{
    const s3_request& q = c->req;
    if (!quota_admin(c))
        return;
    if (!m_store.has_bucket(q.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    s3_error err;
    bucket_quota cfg;
    if (!body_md5_ok(q, c->body, err) || !parse_bucket_quota(c->body, cfg, err))
    {
        send_error(c, err);
        return;
    }
    // A document of no bound is no quota, kept as none.
    store_doc(c, bucket_doc::quota, q.bucket, cfg.any() ? bucket_quota_xml(cfg) : std::string{}, 200);
}

void storage_run::op_get_quota(const std::shared_ptr<conn>& c)
{
    if (!quota_admin(c))
        return;
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    const auto cfg = m_store.bucket_quota_of(c->req.bucket);
    if (!cfg)
    {
        send_error(c, make_error("NoSuchBucketQuota"));
        return;
    }
    response r;
    r.headers.emplace_back("Content-Type", "application/xml");
    r.body = bucket_quota_xml(*cfg);
    send_response(c, std::move(r));
}

void storage_run::op_delete_quota(const std::shared_ptr<conn>& c)
{
    if (!quota_admin(c))
        return;
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    store_doc(c, bucket_doc::quota, c->req.bucket, {}, 204);
}

}   // namespace socketley::storage
