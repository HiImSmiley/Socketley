// An object's tags over S3: setting, reading and removing them.
//
// A change goes to the owner of the key like a put does, and is answered once
// the object's own file says it, so every shard reads the new tags at once.
#include "storage_run.h"

#include "s3_tagging.h"
#include "s3_xml.h"

namespace socketley::storage
{

void storage_run::op_put_object_tagging(const std::shared_ptr<conn>& c)
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
    tag_set tags;
    if (!parse_tagging_xml(c->body, tags, err))
    {
        send_error(c, err);
        return;
    }
    std::weak_ptr<conn> weak = c;
    m_store.set_tags(q.bucket, q.key, encode_tags(tags), [this, weak](st s)
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

void storage_run::op_get_object_tagging(const std::shared_ptr<conn>& c)
{
    const s3_request& q = c->req;
    // The owner answers from memory, and any other shard from the object's header.
    std::weak_ptr<conn> weak = c;
    m_store.stat_object(q.bucket, q.key, [this, weak](st s, const object_meta& m)
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
        r.headers.emplace_back("Content-Type", "application/xml");
        r.body = tagging_xml(decode_tags(tags_of(m)));
        send_response(cc, std::move(r));
    });
}

void storage_run::op_delete_object_tagging(const std::shared_ptr<conn>& c)
{
    const s3_request& q = c->req;
    if (!m_store.has_bucket(q.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    std::weak_ptr<conn> weak = c;
    m_store.set_tags(q.bucket, q.key, {}, [this, weak](st s)
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

}   // namespace socketley::storage
