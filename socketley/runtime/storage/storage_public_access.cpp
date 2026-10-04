// A bucket's public access block over S3: setting, reading and deleting its PublicAccessBlockConfiguration.
#include "storage_run.h"

#include "s3_public_access.h"
#include "s3_xml.h"

namespace socketley::storage
{

void storage_run::op_put_public_access(const std::shared_ptr<conn>& c)
{
    const s3_request& q = c->req;
    if (!m_store.has_bucket(q.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    s3_error err;
    public_access_block cfg;
    if (!body_md5_ok(q, c->body, err) || !parse_public_access_block(c->body, cfg, err))
    {
        send_error(c, err);
        return;
    }
    store_doc(c, bucket_doc::public_access, q.bucket, public_access_block_xml(cfg), 200);
}

void storage_run::op_get_public_access(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    const auto cfg = m_store.bucket_public_access(c->req.bucket);
    if (!cfg)
    {
        send_error(c, make_error("NoSuchPublicAccessBlockConfiguration"));
        return;
    }
    response r;
    r.headers.emplace_back("Content-Type", "application/xml");
    r.body = public_access_block_xml(*cfg);
    send_response(c, std::move(r));
}

void storage_run::op_delete_public_access(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    store_doc(c, bucket_doc::public_access, c->req.bucket, {}, 204);
}

}   // namespace socketley::storage
