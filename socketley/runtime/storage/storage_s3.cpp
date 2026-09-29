// The S3 operations: routing a parsed request to one of them and answering it.
#include "storage_run.h"

#include <algorithm>
#include <charconv>

#include <openssl/evp.h>

#include "s3_names.h"
#include "s3_xml.h"
#include "storage_instance.h"
#include "../../shared/logging.h"

namespace socketley::storage
{

namespace
{

constexpr uint64_t small_body_limit = 4ull << 20;
constexpr size_t   user_meta_limit  = 2048;

// Standard base64, for Content-MD5.
bool base64_decode(std::string_view in, std::string& out)
{
    out.clear();
    uint32_t acc = 0;
    int bits = 0;
    size_t pad = 0;
    for (char c : in)
    {
        int v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+') v = 62;
        else if (c == '/') v = 63;
        else if (c == '=') { ++pad; continue; }
        else return false;
        if (pad)
            return false;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            out.push_back(static_cast<char>((acc >> bits) & 0xFF));
        }
    }
    return true;
}

// The subresources of the S3 API this runtime does not implement, so a request
// naming one is refused as such and never mistaken for the plain operation.
bool unsupported_subresource(const s3_request& r, bool object)
{
    static constexpr std::string_view names[] = {
        "acl", "tagging", "uploads", "uploadId", "partNumber", "versioning", "versions",
        "versionId", "policy", "policyStatus", "cors", "lifecycle", "website", "notification",
        "object-lock", "retention", "legal-hold", "encryption", "replication", "accelerate",
        "requestPayment", "logging", "analytics", "metrics", "inventory", "ownershipControls",
        "publicAccessBlock", "intelligent-tiering", "attributes", "restore", "select", "torrent",
        "acl", "location-constraint",
    };
    (void)object;
    for (const auto& q : r.query)
        for (std::string_view n : names)
            if (q.first == n)
                return true;
    return false;
}

// One entity tag out of a header, unquoted and without a weak marker.
std::string_view strip_etag(std::string_view e)
{
    e = http_trim_ows(e);
    if (e.starts_with("W/"))
        e.remove_prefix(2);
    if (e.size() >= 2 && e.front() == '"' && e.back() == '"')
        e = e.substr(1, e.size() - 2);
    return e;
}

// Whether a comma-separated If-Match / If-None-Match list names `etag`.
bool etag_list_matches(std::string_view list, std::string_view etag)
{
    while (!list.empty())
    {
        const size_t comma = list.find(',');
        const std::string_view one = strip_etag(list.substr(0, comma));
        if (one == "*" || one == etag)
            return true;
        list = comma == std::string_view::npos ? std::string_view{} : list.substr(comma + 1);
    }
    return false;
}

bool parse_uint(std::string_view s, uint64_t& out)
{
    if (s.empty())
        return false;
    const auto r = std::from_chars(s.data(), s.data() + s.size(), out);
    return r.ec == std::errc{} && r.ptr == s.data() + s.size();
}

}   // namespace

// ─── Routing ────────────────────────────────────────────────────────────────

void storage_run::dispatch(const std::shared_ptr<conn>& c)
{
    s3_request& r = c->req;

    request_view rv;
    rv.method       = r.method;
    rv.raw_path     = r.raw_path;
    rv.raw_query    = r.raw_query;
    rv.host         = r.host;
    rv.payload_hash = r.payload_hash;
    rv.headers      = &r.refs;
    rv.bucket       = r.bucket;
    rv.key          = r.key;
    rv.tls          = false;

    auth_verdict v = m_auth->authorize(rv);
    if (!v.allowed)
    {
        r.keep_alive = false;
        send_error(c, v.error.code.empty() ? make_error("AccessDenied") : v.error, true);
        return;
    }
    c->hook = std::move(v.hook);

    // A client that signs its payload in chunks, talking to a runtime with no
    // decoder for them, would have the framing stored as the object.
    if (!c->hook && (r.payload_hash.starts_with("STREAMING-") ||
                     http_list_has_token(r.header("content-encoding"), "aws-chunked", 11)))
    {
        r.keep_alive = false;
        s3_error e = make_error("NotImplemented");
        e.message = "aws-chunked uploads need the SigV4 authenticator, which this runtime does not have";
        send_error(c, e, true);
        return;
    }
    if (r.has_header("transfer-encoding") && !r.chunked)
    {
        r.keep_alive = false;
        send_error(c, make_error("NotImplemented"), true);
        return;
    }

    const bool service = r.bucket.empty();
    const bool bucket_level = !service && r.key.empty();

    if (r.method == "PUT" && !service && !bucket_level && !r.has_header("x-amz-copy-source") &&
        !unsupported_subresource(r, true))
    {
        op_put_object(c);
        return;
    }

    if (unsupported_subresource(r, !bucket_level))
    {
        // The body of a refused request is dropped with the connection.
        r.keep_alive = false;
        send_error(c, make_error("NotImplemented"), true);
        return;
    }

    collect_body(c, small_body_limit, [this, c]()
    {
        s3_request& q = c->req;
        const bool svc = q.bucket.empty();
        const bool bkt = !svc && q.key.empty();
        const std::string& m = q.method;
        if (svc)
        {
            if (m == "GET")
                op_list_buckets(c);
            else
                send_error(c, make_error("MethodNotAllowed"));
            return;
        }
        if (bkt)
        {
            if (m == "GET")
            {
                if (q.has_query("location"))
                    op_bucket_location(c);
                else
                {
                    const std::string_view lt = q.get_query("list-type");
                    if (q.has_query("list-type") && lt != "2")
                    {
                        s3_error e = make_error("InvalidArgument");
                        e.message = "Invalid Argument";
                        send_error(c, e, false, "ArgumentName", "list-type");
                        return;
                    }
                    op_list_objects(c, lt == "2");
                }
            }
            else if (m == "PUT")
                op_create_bucket(c);
            else if (m == "DELETE")
                op_delete_bucket(c);
            else if (m == "HEAD")
                op_head_bucket(c);
            else if (m == "POST" && q.has_query("delete"))
                op_delete_objects(c);
            else
                send_error(c, make_error("MethodNotAllowed"));
            return;
        }
        if (m == "GET")
            op_get_object(c, false);
        else if (m == "HEAD")
            op_get_object(c, true);
        else if (m == "PUT")
            op_copy_object(c);
        else if (m == "DELETE")
            op_delete_object(c);
        else
            send_error(c, make_error("MethodNotAllowed"));
    });
}

// ─── Buckets ────────────────────────────────────────────────────────────────

void storage_run::op_list_buckets(const std::shared_ptr<conn>& c)
{
    ++m_c.lists;
    response r;
    r.headers.emplace_back("Content-Type", "application/xml");
    r.body = list_buckets_xml(m_store.buckets(), owner_id(), owner_id());
    send_response(c, std::move(r));
}

void storage_run::op_create_bucket(const std::shared_ptr<conn>& c)
{
    std::weak_ptr<conn> weak = c;
    const std::string name = c->req.bucket;
    m_store.create_bucket(name, [this, weak, name](st s)
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
        r.headers.emplace_back("Location", "/" + name);
        send_response(cc, std::move(r));
    });
}

void storage_run::op_delete_bucket(const std::shared_ptr<conn>& c)
{
    std::weak_ptr<conn> weak = c;
    m_store.delete_bucket(c->req.bucket, [this, weak](st s)
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

void storage_run::op_head_bucket(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    response r;
    r.headers.emplace_back("x-amz-bucket-region", "us-east-1");
    send_response(c, std::move(r));
}

void storage_run::op_bucket_location(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    response r;
    r.headers.emplace_back("Content-Type", "application/xml");
    r.body = location_xml();
    send_response(c, std::move(r));
}

// ─── Listing ────────────────────────────────────────────────────────────────

void storage_run::op_list_objects(const std::shared_ptr<conn>& c, bool v2)
{
    const s3_request& q = c->req;
    ++m_c.lists;

    auto bad_arg = [&](std::string_view name, std::string_view msg)
    {
        s3_error e = make_error("InvalidArgument");
        e.message  = std::string(msg);
        send_error(c, e, false, "ArgumentName", name);
    };

    if (!m_store.has_bucket(q.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }

    list_query lq;
    lq.prefix    = std::string(q.get_query("prefix"));
    lq.delimiter = std::string(q.get_query("delimiter"));
    size_t max_keys = 1000;
    if (q.has_query("max-keys"))
    {
        uint64_t v;
        if (!parse_uint(q.get_query("max-keys"), v))
        {
            bad_arg("maxKeys", "Provided max-keys not an integer or within integer range");
            return;
        }
        max_keys = static_cast<size_t>(std::min<uint64_t>(v, 1000));
    }
    lq.max_keys = max_keys;

    bool url_enc = false;
    if (q.has_query("encoding-type"))
    {
        if (q.get_query("encoding-type") != "url")
        {
            bad_arg("encoding-type", "Invalid Encoding Method specified in Request");
            return;
        }
        url_enc = true;
    }

    list_render lr;
    lr.bucket    = q.bucket;
    lr.prefix    = q.get_query("prefix");
    lr.delimiter = q.get_query("delimiter");
    lr.max_keys  = max_keys;
    lr.url_encode_keys = url_enc;
    lr.v2        = v2;
    lr.owner_id  = "socketley";

    std::string token_text, next_token, next_marker;
    if (v2)
    {
        lq.start_after = std::string(q.get_query("start-after"));
        lr.start_after = q.get_query("start-after");
        lr.fetch_owner = q.get_query("fetch-owner") == "true";
        if (q.has_query("continuation-token"))
        {
            lr.continuation_token = q.get_query("continuation-token");
            std::string bound;
            if (lr.continuation_token.empty() || !base64url_decode(lr.continuation_token, bound))
            {
                bad_arg("continuation-token", "The continuation token provided is incorrect");
                return;
            }
            lq.has_resume = true;
            lq.resume_at  = std::move(bound);
        }
    }
    else
    {
        lq.start_after = std::string(q.get_query("marker"));
        lr.marker      = q.get_query("marker");
    }

    list_page page;
    const st s = m_store.list(q.bucket, lq, page);
    if (s != st::ok)
    {
        send_error_st(c, s);
        return;
    }
    if (v2 && page.truncated)
    {
        next_token = base64url_encode(page.resume_at);
        lr.next_token = next_token;
    }
    if (!v2 && page.truncated)
    {
        // The last thing this page returned, which the next request's marker
        // picks up after.
        const std::string* last = nullptr;
        if (!page.objects.empty())
            last = &page.objects.back().key;
        if (!page.prefixes.empty() && (!last || page.prefixes.back() > *last))
            last = &page.prefixes.back();
        if (last)
            next_marker = *last;
        lr.next_marker = next_marker;
    }

    response r;
    r.headers.emplace_back("Content-Type", "application/xml");
    r.body = list_xml(lr, page);
    send_response(c, std::move(r));
}

// ─── DeleteObjects ──────────────────────────────────────────────────────────

void storage_run::op_delete_objects(const std::shared_ptr<conn>& c)
{
    const s3_request& q = c->req;
    if (!m_store.has_bucket(q.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }

    // The digest S3 requires on this call, checked when the client sent one.
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

    delete_request dr;
    if (!parse_delete_request(c->body, dr))
    {
        send_error(c, make_error("MalformedXML"));
        return;
    }

    struct batch
    {
        std::vector<delete_result> results;
        size_t                     pending{0};
        bool                       quiet{false};
    };
    auto b = std::make_shared<batch>();
    b->quiet   = dr.quiet;
    b->pending = dr.keys.size();
    b->results.resize(dr.keys.size());

    std::weak_ptr<conn> weak = c;
    const std::string bucket = q.bucket;
    auto done_one = [this, b, weak]()
    {
        if (--b->pending != 0)
            return;
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        response r;
        r.headers.emplace_back("Content-Type", "application/xml");
        r.body = delete_result_xml(b->results, b->quiet);
        send_response(cc, std::move(r));
    };

    // Every removal is started at once, so their journal records share fsyncs.
    for (size_t i = 0; i < dr.keys.size(); ++i)
    {
        b->results[i].key = dr.keys[i];
        if (dr.keys[i].empty() || dr.keys[i].size() > max_key_bytes)
        {
            b->results[i].ok    = false;
            b->results[i].error = make_error("KeyTooLongError");
            done_one();
            continue;
        }
        ++m_c.deletes;
        m_store.remove(bucket, dr.keys[i], [b, i, done_one](st s, bool)
        {
            if (s != st::ok)
            {
                b->results[i].ok    = false;
                b->results[i].error = error_for(s);
            }
            done_one();
        });
    }
}

// ─── Objects: metadata from headers ─────────────────────────────────────────

bool storage_run::object_meta_from_headers(const std::shared_ptr<conn>& c, object_meta& m, s3_error& err)
{
    const s3_request& q = c->req;
    m = object_meta{};
    m.content_type = std::string(q.header("content-type"));
    if (m.content_type.empty())
        m.content_type = "binary/octet-stream";

    static constexpr std::string_view kept[] = {
        "cache-control", "content-disposition", "content-encoding", "content-language", "expires",
    };
    size_t user = 0;
    for (const auto& [name, value] : q.headers)
    {
        bool take = false;
        for (std::string_view k : kept)
            if (name == k)
                take = true;
        if (name == "content-encoding" && http_list_has_token(value, "aws-chunked", 11))
            take = false;
        if (name.starts_with("x-amz-meta-"))
        {
            take = true;
            user += name.size() - 11 + value.size();
        }
        if (take)
            m.extra.emplace_back(name, value);
    }
    if (user > user_meta_limit)
    {
        err = make_error("MetadataTooLarge");
        return false;
    }
    return true;
}

// ─── PutObject ──────────────────────────────────────────────────────────────

void storage_run::op_put_object(const std::shared_ptr<conn>& c)
{
    s3_request& r = c->req;

    if (!valid_bucket_name(r.bucket))
    {
        r.keep_alive = false;
        send_error_st(c, st::invalid_bucket_name);
        return;
    }

    // The digest the client promises, checked when the body is in.
    if (const std::string_view md5h = r.header("content-md5"); !md5h.empty())
    {
        std::string raw;
        if (!base64_decode(md5h, raw) || raw.size() != 16)
        {
            r.keep_alive = false;
            send_error(c, make_error("InvalidDigest"), true);
            return;
        }
        std::memcpy(c->expected_md5.data(), raw.data(), 16);
        c->has_expected_md5 = true;
    }

    if (!r.has_content_length && !r.chunked)
    {
        r.keep_alive = false;
        send_error(c, make_error("MissingContentLength"), true);
        return;
    }

    object_meta meta;
    s3_error err;
    if (!object_meta_from_headers(c, meta, err))
    {
        r.keep_alive = false;
        send_error(c, err, true);
        return;
    }

    // S3's conditional write: refuse to replace what is there.
    if (r.header("if-none-match") == "*" && m_store.find(r.bucket, r.key))
    {
        r.keep_alive = false;
        send_error(c, make_error("PreconditionFailed"), true);
        return;
    }

    uint64_t expected = r.content_length;
    bool     known    = r.has_content_length && !r.chunked;
    if (c->hook)
        if (auto d = c->hook->decoded_length())
        {
            expected = *d;
            known    = true;
        }
    if (m_active_puts >= m_max_active_puts)
    {
        r.keep_alive = false;
        send_error(c, make_error("SlowDown"), true);
        return;
    }

    st why = st::ok;
    auto op = m_store.begin_put(r.bucket, r.key, std::move(meta), expected, known, why);
    if (!op)
    {
        // The body is not read, so the connection cannot be reused.
        r.keep_alive = false;
        send_error_st(c, why);
        return;
    }
    if (op->failed())
    {
        r.keep_alive = false;
        send_error_st(c, op->status());
        return;
    }
    begin_put_body(c, std::move(op));
}

// ─── CopyObject ─────────────────────────────────────────────────────────────

void storage_run::op_copy_object(const std::shared_ptr<conn>& c)
{
    s3_request& r = c->req;
    const std::string_view src_hdr = r.header("x-amz-copy-source");
    if (src_hdr.empty())
    {
        // A PUT of an object always has a body, and this one was collected small
        // because of a subresource or a copy source that is not there.
        send_error(c, make_error("InvalidRequest"));
        return;
    }

    std::string src;
    std::string_view raw = src_hdr;
    // A version id after the key is not supported and not ignored either.
    if (const size_t q = raw.find("?versionId="); q != std::string_view::npos)
        raw = raw.substr(0, q);
    if (!percent_decode(raw, src, false))
    {
        send_error(c, make_error("InvalidArgument"));
        return;
    }
    std::string_view sv = src;
    if (!sv.empty() && sv.front() == '/')
        sv.remove_prefix(1);
    const size_t slash = sv.find('/');
    if (slash == std::string_view::npos || slash == 0 || slash + 1 >= sv.size())
    {
        s3_error e = make_error("InvalidArgument");
        e.message = "Copy Source must mention the source bucket and key: sourcebucket/sourcekey";
        send_error(c, e, false, "ArgumentName", "x-amz-copy-source");
        return;
    }
    const std::string src_bucket(sv.substr(0, slash));
    const std::string src_key(sv.substr(slash + 1));

    const std::string_view directive = r.header("x-amz-metadata-directive");
    if (!directive.empty() && directive != "COPY" && directive != "REPLACE")
    {
        s3_error e = make_error("InvalidArgument");
        e.message = "Unknown metadata directive.";
        send_error(c, e, false, "ArgumentName", "x-amz-metadata-directive");
        return;
    }
    const bool replace = directive == "REPLACE";

    if (!m_store.has_bucket(src_bucket) || !m_store.has_bucket(r.bucket))
    {
        error_context ctx;
        send_error_st(c, st::no_such_bucket);
        return;
    }
    const object_meta* src_meta = m_store.find(src_bucket, src_key);
    if (!src_meta)
    {
        send_error_st(c, st::no_such_key);
        return;
    }
    if (src_bucket == r.bucket && src_key == r.key && !replace)
    {
        s3_error e = make_error("InvalidRequest");
        e.message = "This copy request is illegal because it is trying to copy an object to itself "
                    "without changing the object's metadata, storage class, website redirect "
                    "location or encryption attributes.";
        send_error(c, e);
        return;
    }

    // The copy source's own conditions, a date counting only when its ETag header is absent.
    const std::string etag    = src_meta->etag();
    const int64_t     mtime_s = src_meta->mtime_ms / 1000;
    bool              refuse  = false;
    if (const auto v = r.header("x-amz-copy-source-if-match"); !v.empty())
        refuse = !etag_list_matches(v, etag);
    else if (const int64_t t = parse_http_date(r.header("x-amz-copy-source-if-unmodified-since")); t >= 0)
        refuse = mtime_s > t;
    if (const auto v = r.header("x-amz-copy-source-if-none-match"); !v.empty())
        refuse = refuse || etag_list_matches(v, etag);
    else if (const int64_t t = parse_http_date(r.header("x-amz-copy-source-if-modified-since")); t >= 0)
        refuse = refuse || mtime_s <= t;
    if (refuse)
    {
        send_error(c, make_error("PreconditionFailed"));
        return;
    }

    object_meta meta;
    if (replace)
    {
        s3_error err;
        if (!object_meta_from_headers(c, meta, err))
        {
            send_error(c, err);
            return;
        }
    }
    else
        meta = *src_meta;

    ++m_c.copies;
    std::weak_ptr<conn> weak = c;
    m_store.copy(src_bucket, src_key, r.bucket, r.key, std::move(meta), [this, weak](put_result p)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (p.status != st::ok)
        {
            send_error_st(cc, p.status);
            return;
        }
        response resp;
        resp.headers.emplace_back("Content-Type", "application/xml");
        resp.body = copy_result_xml(p.meta);
        send_response(cc, std::move(resp));
    });
}

// ─── DeleteObject ───────────────────────────────────────────────────────────

void storage_run::op_delete_object(const std::shared_ptr<conn>& c)
{
    ++m_c.deletes;
    std::weak_ptr<conn> weak = c;
    m_store.remove(c->req.bucket, c->req.key, [this, weak](st s, bool)
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

// ─── GetObject, HeadObject ──────────────────────────────────────────────────

namespace
{

// The headers an object's stored metadata puts on a response, with the
// response-* query overrides a presigned URL may add.
void object_headers(const s3_request& q, const object_meta& m, response& r)
{
    r.headers.emplace_back("Accept-Ranges", "bytes");
    r.headers.emplace_back("ETag", "\"" + m.etag() + "\"");
    r.headers.emplace_back("Last-Modified", http_date(m.mtime_ms));

    struct override_row { std::string_view query; std::string_view header; };
    static constexpr override_row overrides[] = {
        {"response-cache-control", "Cache-Control"},
        {"response-content-disposition", "Content-Disposition"},
        {"response-content-encoding", "Content-Encoding"},
        {"response-content-language", "Content-Language"},
        {"response-content-type", "Content-Type"},
        {"response-expires", "Expires"},
    };
    auto overridden = [&](std::string_view header) -> const std::pair<std::string, std::string>*
    {
        for (const auto& o : overrides)
            if (o.header == header && q.has_query(o.query))
            {
                for (const auto& kv : q.query)
                    if (kv.first == o.query)
                        return &kv;
            }
        return nullptr;
    };

    if (const auto* o = overridden("Content-Type"))
        r.headers.emplace_back("Content-Type", o->second);
    else
        r.headers.emplace_back("Content-Type", m.content_type);

    for (const auto& [n, v] : m.extra)
    {
        if (n.starts_with("x-amz-meta-"))
        {
            r.headers.emplace_back(n, v);
            continue;
        }
        std::string display;
        bool next_upper = true;
        for (char ch : n)
        {
            display.push_back(next_upper ? static_cast<char>(std::toupper(static_cast<unsigned char>(ch))) : ch);
            next_upper = ch == '-';
        }
        if (overridden(display))
            continue;
        r.headers.emplace_back(display, v);
    }
    for (const auto& o : overrides)
        if (o.header != "Content-Type" && q.has_query(o.query))
            for (const auto& kv : q.query)
                if (kv.first == o.query)
                    r.headers.emplace_back(std::string(o.header), kv.second);
    if (m.parts)
        r.headers.emplace_back("x-amz-mp-parts-count", std::to_string(m.parts));
}

enum class cond { proceed, not_modified, precondition_failed };

// RFC 9110 13.2.2 in the order it fixes: If-Match, If-Unmodified-Since,
// If-None-Match, If-Modified-Since.
cond evaluate(const s3_request& q, const object_meta& m)
{
    const std::string etag = m.etag();
    const int64_t mtime_s = m.mtime_ms / 1000;

    const std::string_view im = q.header("if-match");
    if (!im.empty())
    {
        if (!etag_list_matches(im, etag))
            return cond::precondition_failed;
    }
    else if (const std::string_view ius = q.header("if-unmodified-since"); !ius.empty())
    {
        const int64_t t = parse_http_date(ius);
        if (t >= 0 && mtime_s > t)
            return cond::precondition_failed;
    }

    const std::string_view inm = q.header("if-none-match");
    if (!inm.empty())
    {
        if (etag_list_matches(inm, etag))
            return cond::not_modified;
    }
    else if (const std::string_view ims = q.header("if-modified-since"); !ims.empty())
    {
        const int64_t t = parse_http_date(ims);
        if (t >= 0 && mtime_s <= t)
            return cond::not_modified;
    }
    return cond::proceed;
}

}   // namespace

void storage_run::op_get_object(const std::shared_ptr<conn>& c, bool head)
{
    s3_request& q = c->req;
    if (head)
        ++m_c.heads;
    else
        ++m_c.gets;

    if (!m_store.has_bucket(q.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    const object_meta* mem = m_store.find(q.bucket, q.key);
    if (!mem)
    {
        send_error_st(c, st::no_such_key);
        return;
    }

    // Answers a request whose object is known, from a HEAD's memory or a GET's file.
    auto answer = [this, weak = std::weak_ptr<conn>(c), head](const object_meta& m, int fd,
                                                              uint64_t data_off, const std::string& prefetch)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
        {
            if (fd >= 0)
                m_loop.close_fd(fd);
            return;
        }
        const s3_request& rq = cc->req;

        auto close_file = [&] { if (fd >= 0) m_loop.close_fd(fd); };

        response r;
        const cond cd = evaluate(rq, m);
        if (cd == cond::precondition_failed)
        {
            close_file();
            send_error(cc, make_error("PreconditionFailed"));
            return;
        }
        if (cd == cond::not_modified)
        {
            close_file();
            r.status = 304;
            r.head_only = true;
            r.headers.emplace_back("ETag", "\"" + m.etag() + "\"");
            r.headers.emplace_back("Last-Modified", http_date(m.mtime_ms));
            send_response(cc, std::move(r));
            return;
        }

        uint64_t first = 0, len = m.size;
        bool ranged = false;
        if (const std::string_view rh = rq.header("range"); !rh.empty())
        {
            const http_range hr = http_parse_range(rh, static_cast<size_t>(m.size));
            if (hr.unsatisfiable)
            {
                close_file();
                response e;
                e.status = 416;
                e.headers.emplace_back("Content-Type", "application/xml");
                e.headers.emplace_back("Content-Range", "bytes */" + std::to_string(m.size));
                s3_error err = make_error("InvalidRange");
                error_context ctx;
                ctx.bucket = rq.bucket;
                ctx.key = rq.key;
                ctx.request_id = rq.request_id;
                ctx.extra_name = "RangeRequested";
                ctx.extra_value = rh;
                if (head)
                {
                    e.head_only = true;
                    e.has_length_override = true;
                    e.length_override = 0;
                }
                else
                    e.body = error_xml(err, ctx);
                send_response(cc, std::move(e));
                return;
            }
            if (hr.usable)
            {
                first  = hr.first;
                len    = hr.last - hr.first + 1;
                ranged = true;
            }
        }

        object_headers(rq, m, r);
        if (ranged)
        {
            r.status = 206;
            r.headers.emplace_back("Content-Range", "bytes " + std::to_string(first) + "-" +
                                   std::to_string(first + len - 1) + "/" + std::to_string(m.size));
        }

        if (head)
        {
            r.head_only = true;
            r.has_length_override = true;
            r.length_override = len;
            send_response(cc, std::move(r));
            return;
        }

        // A body the header read already brought in is sent from memory in one write.
        if (fd >= 0 && first + len <= prefetch.size())
        {
            close_file();
            r.body = prefetch.substr(static_cast<size_t>(first), static_cast<size_t>(len));
            ++m_c.copied_gets;
            send_response(cc, std::move(r));
            return;
        }
        if (len == 0)
        {
            close_file();
            send_response(cc, std::move(r));
            return;
        }
        send_file(cc, std::move(r), fd, data_off + first, len);
    };

    if (head)
    {
        answer(*mem, -1, 0, std::string{});
        return;
    }

    std::weak_ptr<conn> weak = c;
    // Small objects are read whole with their header, in one read.
    const size_t prefetch = mem->size <= 60000 ? static_cast<size_t>(mem->size) : 0;
    m_store.open_object(q.bucket, q.key, prefetch, [this, weak, answer](open_result o)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
        {
            if (o.fd >= 0)
                m_loop.close_fd(o.fd);
            return;
        }
        if (o.status != st::ok)
        {
            send_error_st(cc, o.status);
            return;
        }
        answer(o.meta, o.fd, o.data_off, o.prefetch);
    });
}

}   // namespace socketley::storage
