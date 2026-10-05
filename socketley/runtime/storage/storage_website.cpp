// A bucket's website: setting, reading and deleting its WebsiteConfiguration over S3, and serving it to browsers.
#include "storage_run.h"

#include "s3_names.h"
#include "s3_website.h"
#include "s3_xml.h"

namespace socketley::storage
{

void storage_run::op_put_website(const std::shared_ptr<conn>& c)
{
    const s3_request& q = c->req;
    if (!m_store.has_bucket(q.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    s3_error err;
    website_config cfg;
    if (!body_md5_ok(q, c->body, err) || !parse_website_config(c->body, cfg, err))
    {
        send_error(c, err);
        return;
    }
    store_doc(c, bucket_doc::website, q.bucket, website_config_xml(cfg), 200);
}

void storage_run::op_get_website(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    const auto cfg = m_store.bucket_website(c->req.bucket);
    if (!cfg)
    {
        send_error(c, make_error("NoSuchWebsiteConfiguration"));
        return;
    }
    response r;
    r.headers.emplace_back("Content-Type", "application/xml");
    r.body = website_config_xml(*cfg);
    send_response(c, std::move(r));
}

void storage_run::op_delete_website(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    store_doc(c, bucket_doc::website, c->req.bucket, {}, 204);
}

// ─── Serving ────────────────────────────────────────────────────────────────

void storage_run::op_website(const std::shared_ptr<conn>& c)
{
    s3_request& r = c->req;
    // A website reads, so a body sent to it is dropped with the connection.
    if (r.chunked || (r.has_content_length && r.content_length > 0))
        r.keep_alive = false;
    c->website_key = r.key;
    if (r.method != "GET" && r.method != "HEAD")
    {
        website_error_page(c, make_error("MethodNotAllowed"));
        return;
    }
    if (!m_store.has_bucket(r.bucket))
    {
        website_error_page(c, error_for(st::no_such_bucket));
        return;
    }
    const auto cfg = m_store.bucket_website(r.bucket);
    if (!cfg)
    {
        website_error_page(c, make_error("NoSuchWebsiteConfiguration"));
        return;
    }
    const std::string_view scheme = secure(*c) ? "https" : "http";
    if (!cfg->redirect_all_host.empty())
    {
        website_redirect all;
        all.host     = cfg->redirect_all_host;
        all.protocol = cfg->redirect_all_protocol;
        website_redirect_to(c, 301, website_location(all, {}, r.key, scheme, r.host));
        return;
    }
    if (const website_rule* rule = website_rule_for(*cfg, r.key, 0))
    {
        website_redirect_to(c, rule->redirect.code,
                            website_location(rule->redirect, rule->key_prefix.value_or(std::string{}), r.key, scheme,
                                             r.host));
        return;
    }
    // A website serves the latest object whatever the query asks.
    r.query.clear();
    if (r.key.empty() || r.key.back() == '/')
        r.key += cfg->index_suffix;
    if (!website_readable(c))
    {
        send_error(c, make_error("AccessDenied"));
        return;
    }
    op_get_object(c, r.method == "HEAD", false);
}

bool storage_run::website_readable(const std::shared_ptr<conn>& c)
{
    const s3_request& r = c->req;
    // The request is judged as one with no credentials, whatever headers it carries.
    static const std::vector<header_ref> no_headers;
    request_view rv;
    rv.method   = r.method;
    rv.raw_path = r.raw_path;
    rv.host     = r.host;
    rv.headers  = &no_headers;
    rv.bucket   = r.bucket;
    rv.key      = r.key;
    rv.tls      = secure(*c);
    auth_verdict v = m_auth->authorize(rv);
    if ((v.allowed || v.anonymous) && needs_judging(nullptr))
        apply_policy(c, rv, v);
    c->anonymous = v.anonymous;
    return v.allowed;
}

void storage_run::website_failure(const std::shared_ptr<conn>& c, const s3_error& e)
{
    // The error document's own failure is answered with the failure it was to describe.
    if (c->website_status)
    {
        website_error_page(c, c->website_error);
        return;
    }
    const s3_request& r = c->req;
    const auto cfg = m_store.has_bucket(r.bucket) ? m_store.bucket_website(r.bucket) : nullptr;
    if (!cfg || !cfg->redirect_all_host.empty())
    {
        website_error_page(c, e);
        return;
    }
    auto answer = [this](const std::shared_ptr<conn>& cc, const s3_error& err)
    {
        s3_request& q = cc->req;
        const auto conf = m_store.bucket_website(q.bucket);
        if (!conf)
        {
            website_error_page(cc, err);
            return;
        }
        if (const website_rule* rule = website_rule_for(*conf, cc->website_key, err.status))
        {
            website_redirect_to(cc, rule->redirect.code,
                                website_location(rule->redirect, rule->key_prefix.value_or(std::string{}),
                                                 cc->website_key, secure(*cc) ? "https" : "http", q.host));
            return;
        }
        if (conf->error_key.empty())
        {
            website_error_page(cc, err);
            return;
        }
        cc->website_status = err.status;
        cc->website_error  = err;
        q.key = conf->error_key;
        if (!website_readable(cc))
        {
            website_error_page(cc, err);
            return;
        }
        op_get_object(cc, q.method == "HEAD", false);
    };
    // A key without its slash that names a folder with an index document is sent to the folder, where the
    // page's relative links resolve.
    const std::string& key = c->website_key;
    if (e.code == "NoSuchKey" && !key.empty() && key.back() != '/')
    {
        std::weak_ptr<conn> weak = c;
        m_store.stat_object(r.bucket, key + "/" + cfg->index_suffix,
                            [this, weak, e, answer](st s, const object_meta&)
        {
            auto cc = weak.lock();
            if (!cc || cc->dead)
                return;
            if (s != st::ok)
            {
                answer(cc, e);
                return;
            }
            std::string to = "/";
            url_encode_to(to, cc->website_key, true);
            to += "/";
            website_redirect_to(cc, 302, std::move(to));
        });
        return;
    }
    answer(c, e);
}

void storage_run::website_redirect_to(const std::shared_ptr<conn>& c, int status, std::string location)
{
    response r;
    r.status = status;
    r.headers.emplace_back("Location", std::move(location));
    send_response(c, std::move(r));
}

void storage_run::website_error_page(const std::shared_ptr<conn>& c, const s3_error& e)
{
    count_error(*c, e.code);
    response r;
    r.status = e.status;
    r.headers.emplace_back("Content-Type", "text/html; charset=utf-8");
    r.headers.emplace_back("x-amz-error-code", e.code);
    if (c->req.method == "HEAD")
    {
        send_response(c, std::move(r));
        return;
    }
    const std::string title = std::to_string(e.status) + " " + reason_phrase(e.status);
    std::string& b = r.body;
    b = "<html>\n<head><title>";
    b += title;
    b += "</title></head>\n<body>\n<h1>";
    b += title;
    b += "</h1>\n<ul>\n<li>Code: ";
    xml_escape_to(b, e.code);
    b += "</li>\n<li>Message: ";
    xml_escape_to(b, e.message);
    b += "</li>\n<li>RequestId: ";
    xml_escape_to(b, c->req.request_id);
    b += "</li>\n</ul>\n<hr/>\n</body>\n</html>\n";
    send_response(c, std::move(r));
}

}   // namespace socketley::storage
