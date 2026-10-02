// A browser's upload by HTML form, S3's POST Object: the fields in front of the
// file are read, the form's policy and signature are checked, and the upload
// goes on as the PutObject the fields describe, its file streamed like a put's body.
#include "storage_run.h"

#include "s3_names.h"
#include "s3_tagging.h"
#include "s3_xml.h"

namespace socketley::storage
{

namespace
{

// The fields that are a PutObject's headers when a form carries them, by the header's name.
bool header_field(std::string_view name)
{
    static constexpr std::string_view kept[] = {
        "content-type", "cache-control", "content-disposition", "content-encoding", "content-language", "expires",
        "x-amz-storage-class", "x-amz-server-side-encryption", "x-amz-checksum-algorithm",
        "x-amz-website-redirect-location",
    };
    for (std::string_view k : kept)
        if (name == k)
            return true;
    return name.starts_with("x-amz-meta-") || name.starts_with("x-amz-server-side-encryption-") ||
           name.starts_with("x-amz-object-lock-") ||
           (name.starts_with("x-amz-checksum-") && name != "x-amz-checksum-type");
}

}   // namespace

void storage_run::begin_post_form(const std::shared_ptr<conn>& c)
{
    s3_request& r = c->req;
    // The fields are read to a length, which a chunked body does not give.
    if (!r.has_content_length || r.chunked)
    {
        r.keep_alive = false;
        send_error(c, make_error("MissingContentLength"), true);
        return;
    }
    r.form = std::make_unique<post_form>();
    // A client that waits for 100 Continue sends its fields only after it, and is told once.
    if (r.expect_continue)
    {
        queue_write(c, "HTTP/1.1 100 Continue\r\n\r\n");
        r.expect_continue = false;
    }
    c->ph = phase::form_head;
    post_form_more(c);
}

void storage_run::post_form_more(const std::shared_ptr<conn>& c)
{
    s3_request& r = c->req;
    const size_t have = static_cast<size_t>(std::min<uint64_t>(c->in.size(), r.content_length));
    s3_error err;
    switch (scan_post_form(r.header("content-type"), std::string_view(c->in).substr(0, have),
                           have == r.content_length, *r.form, err))
    {
        case form_scan::more:
            arm_read(c);
            return;
        case form_scan::bad:
            deny_request(c, err);
            return;
        case form_scan::ok:
            post_form_ready(c);
            return;
    }
}

void storage_run::post_form_ready(const std::shared_ptr<conn>& c)
{
    s3_request& r = c->req;
    post_form& f = *r.form;
    if (!m_store.has_bucket(r.bucket))
    {
        deny_request(c, make_error("NoSuchBucket"));
        return;
    }
    r.key = post_key(f);
    if (r.key.empty())
    {
        s3_error e = make_error("InvalidArgument");
        e.message = "Bucket POST must contain a field named 'key'.  If it is specified, please check the order of the fields.";
        deny_request(c, e);
        return;
    }

    // A form with a policy is signed in its fields; one without is an anonymous PutObject.
    auth_verdict v;
    auto field = [&](std::string_view n) { const std::string* s = f.field(n); return s ? std::string_view(*s) : std::string_view{}; };
    if (f.field("policy"))
    {
        // A signed form names its key and its signature, in one form or the other.
        const bool v4 = f.field("x-amz-algorithm") != nullptr;
        const char* missing = v4 ? (!f.field("x-amz-credential") ? "X-Amz-Credential"
                                    : !f.field("x-amz-signature") ? "X-Amz-Signature"
                                    : !f.field("x-amz-date") ? "X-Amz-Date" : nullptr)
                                 : (!f.field("awsaccesskeyid") ? "AWSAccessKeyId"
                                    : !f.field("signature") ? "Signature" : nullptr);
        if (missing)
        {
            s3_error e = make_error("InvalidArgument");
            e.message = std::string("Bucket POST must contain a field named '") + missing +
                        "'.  If it is specified, please check the order of the fields.";
            deny_request(c, e);
            return;
        }
        v = m_auth->authorize_post({field("x-amz-algorithm"), field("x-amz-credential"), field("x-amz-date"),
                                    field("policy"), field("x-amz-signature"), field("awsaccesskeyid"),
                                    field("signature")});
        if (s3_error e; v.allowed && !check_post_policy(f, r.bucket, static_cast<int64_t>(m_store.now_ms()), e))
        {
            deny_request(c, e);
            return;
        }
    }
    else
    {
        request_view rv;
        rv.method   = r.method;
        rv.raw_path = r.raw_path;
        rv.host     = r.host;
        rv.headers  = &r.headers;
        rv.bucket   = r.bucket;
        rv.tls      = c->ssl != nullptr;
        v = m_auth->authorize(rv);
    }
    request_view rv;
    rv.method  = r.method;
    rv.headers = &r.headers;
    rv.bucket  = r.bucket;
    rv.key     = r.key;
    rv.tls     = c->ssl != nullptr;
    if (m_store.any_policy() && (v.allowed || v.anonymous))
        apply_policy(c, rv, v);
    if (!v.allowed)
    {
        deny_request(c, v.error.code.empty() ? make_error("AccessDenied") : v.error);
        return;
    }
    c->principal = std::move(v.principal);
    c->anonymous = v.anonymous;

    // The fields become the headers a PutObject would have carried, in place of the form's own.
    std::erase_if(r.headers, [](const header_ref& h) { return h.name == "content-type" || h.name == "content-md5"; });
    for (const auto& [n, value] : f.fields)
        if (header_field(n))
            r.headers.push_back({n, value});
    if (const std::string* acl = f.field("acl"))
        r.headers.push_back({"x-amz-acl", *acl});
    // A form's tags are a Tagging document, where the header's are a query string.
    if (const std::string* doc = f.field("tagging"))
    {
        tag_set tags;
        s3_error e;
        if (!parse_tagging_xml(*doc, tags, e))
        {
            deny_request(c, e);
            return;
        }
        std::string q;
        for (const auto& [k, tv] : tags)
            q += (q.empty() ? "" : "&") + url_encode(k, false) + "=" + url_encode(tv, false);
        r.headers.push_back({"x-amz-tagging", f.held.emplace_back(std::move(q))});
    }

    // What follows the fields is the file, framed by the form's boundary.
    c->in.erase(0, f.file_at);
    r.content_length -= f.file_at;
    c->hook = std::make_shared<form_file_hook>(f.boundary, f.has_range, f.range_min, f.range_max);
    hook_request(c);
}

void storage_run::send_post_result(const std::shared_ptr<conn>& c, const object_meta& m)
{
    const s3_request& r = c->req;
    const post_form& f = *r.form;
    const std::string etag = "\"" + m.etag() + "\"";
    const std::string location = (c->ssl ? "https://" : "http://") + std::string(r.host) + "/" + url_encode(r.bucket) +
                                 "/" + url_encode(r.key);
    response resp;
    resp.headers.emplace_back("ETag", etag);
    if (has_version(m))
        resp.headers.emplace_back("x-amz-version-id", version_of(m).id);
    sse_headers(r, m, resp.headers);

    // A redirect is followed with what was stored; otherwise the status the form asked for, 204 by default.
    const std::string* redirect = f.field("success_action_redirect");
    if (!redirect)
        redirect = f.field("redirect");
    if (redirect && !redirect->empty())
    {
        resp.status = 303;
        resp.headers.emplace_back("Location", *redirect + (redirect->find('?') == std::string::npos ? "?" : "&") +
                                                  "bucket=" + url_encode(r.bucket, false) + "&key=" +
                                                  url_encode(r.key, false) + "&etag=" + url_encode(etag, false));
        send_response(c, std::move(resp));
        return;
    }
    resp.headers.emplace_back("Location", location);
    const std::string* status = f.field("success_action_status");
    resp.status = status && (*status == "200" || *status == "201") ? (*status == "200" ? 200 : 201) : 204;
    if (resp.status == 201)
    {
        resp.headers.emplace_back("Content-Type", "application/xml");
        resp.body = std::string(xml_decl) + "<PostResponse><Location>" + xml_escape(location) + "</Location><Bucket>" +
                    xml_escape(r.bucket) + "</Bucket><Key>" + xml_escape(r.key) + "</Key><ETag>" + xml_escape(etag) +
                    "</ETag></PostResponse>";
    }
    send_response(c, std::move(resp));
}

}   // namespace socketley::storage
