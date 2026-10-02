// An object's tags over S3: setting, reading and removing them.
//
// A change goes to the owner of the key like a put does, and is answered once
// the object's own file says it, so every shard reads the new tags at once.
#include "storage_run.h"

#include "s3_tagging.h"
#include "s3_xml.h"

namespace socketley::storage
{

namespace
{

// The answer to a tag change of the version `id`, which a bucket that keeps none leaves out.
response tagged(int status, const std::string& id)
{
    response r;
    r.status = status;
    if (!id.empty())
        r.headers.emplace_back("x-amz-version-id", id);
    return r;
}

}   // namespace

void storage_run::op_put_object_tagging(const std::shared_ptr<conn>& c)
{
    const s3_request& q = c->req;
    std::string version_id;
    if (!version_param(c, version_id))
        return;
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
    tag_set tags;
    if (!parse_tagging_xml(c->body, tags, err))
    {
        send_error(c, err);
        return;
    }
    std::weak_ptr<conn> weak = c;
    m_store.set_tags(q.bucket, q.key, std::move(version_id), encode_tags(tags), [this, weak](st s, std::string id)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (s != st::ok)
        {
            send_error_st(cc, s);
            return;
        }
        send_response(cc, tagged(200, id));
    }, origin_of(*c));
}

void storage_run::op_put_bucket_tagging(const std::shared_ptr<conn>& c)
{
    const s3_request& q = c->req;
    if (!m_store.has_bucket(q.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    s3_error err;
    tag_set  tags;
    if (!body_md5_ok(q, c->body, err) || !parse_tagging_xml(c->body, tags, err, max_bucket_tags))
    {
        send_error(c, err);
        return;
    }
    // Kept as the set it holds, so GetBucketTagging answers the tags in the order they were given.
    std::weak_ptr<conn> weak = c;
    m_node.set_doc(bucket_doc::tagging, q.bucket, tagging_xml(tags), [this, weak](st s)
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

void storage_run::op_get_bucket_tagging(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    const auto xml = m_store.bucket_tagging(c->req.bucket);
    if (!xml)
    {
        send_error(c, make_error("NoSuchTagSet"));
        return;
    }
    response r;
    r.headers.emplace_back("Content-Type", "application/xml");
    r.body = *xml;
    send_response(c, std::move(r));
}

void storage_run::op_delete_bucket_tagging(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    std::weak_ptr<conn> weak = c;
    m_node.set_doc(bucket_doc::tagging, c->req.bucket, {}, [this, weak](st s)
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

void storage_run::op_get_object_tagging(const std::shared_ptr<conn>& c)
{
    const s3_request& q = c->req;
    std::string version_id;
    if (!version_param(c, version_id))
        return;
    // The owner answers from memory, and any other shard from the object's header.
    std::weak_ptr<conn> weak = c;
    auto answer = [this, weak](st s, const object_meta& m)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (s != st::ok)
        {
            send_error_st(cc, s);
            return;
        }
        const bool named = has_version(m) || m_store.bucket_versioning(cc->req.bucket) != versioning::off;
        response r = tagged(200, named ? version_of(m).id : std::string{});
        r.headers.emplace_back("Content-Type", "application/xml");
        r.body = tagging_xml(decode_tags(tags_of(m)));
        send_response(cc, std::move(r));
    };
    if (version_id.empty())
        m_store.stat_object(q.bucket, q.key, std::move(answer));
    else
        m_store.stat_version(q.bucket, q.key, std::move(version_id), std::move(answer));
}

void storage_run::op_delete_object_tagging(const std::shared_ptr<conn>& c)
{
    const s3_request& q = c->req;
    std::string version_id;
    if (!version_param(c, version_id))
        return;
    if (!m_store.has_bucket(q.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    std::weak_ptr<conn> weak = c;
    m_store.set_tags(q.bucket, q.key, std::move(version_id), {}, [this, weak](st s, std::string id)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (s != st::ok)
        {
            send_error_st(cc, s);
            return;
        }
        send_response(cc, tagged(204, id));
    }, origin_of(*c));
}

}   // namespace socketley::storage
