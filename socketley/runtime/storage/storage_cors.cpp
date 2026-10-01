// A bucket's CORS rules over S3: setting, reading and removing them, the
// OPTIONS preflight a browser sends first, and the headers of the request it
// sends after.
#include "storage_run.h"

#include "digest.h"
#include "s3_cors.h"
#include "s3_names.h"
#include "s3_xml.h"

namespace socketley::storage
{

void storage_run::op_put_cors(const std::shared_ptr<conn>& c)
{
    const s3_request& q = c->req;
    if (!m_store.has_bucket(q.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    if (const std::string_view md5h = q.header("content-md5"); !md5h.empty())
    {
        std::string raw;
        if (!base64_decode(md5h, raw) || raw.size() != 16)
        {
            send_error(c, make_error("InvalidDigest"));
            return;
        }
        const md5_t got = md5_of(c->body);
        if (std::string_view(reinterpret_cast<const char*>(got.data()), 16) != raw)
        {
            send_error(c, make_error("BadDigest"));
            return;
        }
    }
    cors_config cfg;
    s3_error    err;
    if (!parse_cors_xml(c->body, cfg, err))
    {
        send_error(c, err);
        return;
    }
    std::weak_ptr<conn> weak = c;
    m_node.set_doc(bucket_doc::cors, q.bucket, std::move(cfg.xml), [this, weak](st s)
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

void storage_run::op_get_cors(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    const cors_config* cfg = m_store.bucket_cors(c->req.bucket);
    if (!cfg)
    {
        send_error(c, make_error("NoSuchCORSConfiguration"));
        return;
    }
    response r;
    r.headers.emplace_back("Content-Type", "application/xml");
    r.body = cfg->xml;
    send_response(c, std::move(r));
}

void storage_run::op_delete_cors(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    std::weak_ptr<conn> weak = c;
    m_node.set_doc(bucket_doc::cors, c->req.bucket, {}, [this, weak](st s)
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

void storage_run::op_preflight(const std::shared_ptr<conn>& c)
{
    s3_request& q = c->req;
    // A preflight has no body, and one that sends one anyway is not read for the next request.
    if (q.chunked || q.content_length > 0)
        q.keep_alive = false;
    const bool close = !q.keep_alive;

    if (q.bucket.empty())
    {
        send_error(c, make_error("MethodNotAllowed"), close);
        return;
    }
    const std::string_view origin = q.header("origin");
    const std::string_view method = q.header("access-control-request-method");
    if (origin.empty())
    {
        s3_error e = make_error("BadRequest");
        e.message  = "Insufficient information. Origin request header needed.";
        send_error(c, e, close);
        return;
    }
    if (!cors_method_known(method))
    {
        s3_error e = make_error("BadRequest");
        e.message  = "Invalid Access-Control-Request-Method: " + std::string(method.empty() ? "null" : method);
        send_error(c, e, close);
        return;
    }
    if (!m_store.has_bucket(q.bucket))
    {
        send_error(c, make_error("NoSuchBucket"), close);
        return;
    }
    const cors_config* cfg = m_store.bucket_cors(q.bucket);
    if (!cfg)
    {
        s3_error e = make_error("AccessForbidden");
        e.message  = "CORSResponse: CORS is not enabled for this bucket.";
        send_error(c, e, close, "Method", method);
        return;
    }
    const std::string_view asked = q.header("access-control-request-headers");
    const cors_rule* rule = cors_match(*cfg, origin, method, asked);
    if (!rule)
    {
        send_error(c, make_error("AccessForbidden"), close, "Method", method);
        return;
    }
    c->cors_head.clear();
    cors_render(c->cors_head, *rule, origin, true, asked);
    response r;
    r.close = close;
    send_response(c, std::move(r));
}

void storage_run::cors_actual(const std::shared_ptr<conn>& c)
{
    const s3_request& q = c->req;
    const std::string_view origin = q.header("origin");
    if (origin.empty() || q.bucket.empty())
        return;
    const cors_config* cfg = m_store.bucket_cors(q.bucket);
    if (!cfg)
        return;
    if (const cors_rule* rule = cors_match(*cfg, origin, q.method))
        cors_render(c->cors_head, *rule, origin, false);
}

}   // namespace socketley::storage
