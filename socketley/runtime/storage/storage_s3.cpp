// The S3 operations: routing a parsed request to one of them and answering it.
#include "storage_run.h"

#include <algorithm>
#include <charconv>

#include <openssl/evp.h>

#include "s3_cors.h"
#include "s3_names.h"
#include "s3_tagging.h"
#include "s3_xml.h"
#include "storage_instance.h"
#include "../../shared/logging.h"

namespace socketley::storage
{

namespace
{

constexpr uint64_t small_body_limit = 4ull << 20;
constexpr size_t   user_meta_limit  = 2048;

// The subresources of the S3 API this runtime does not implement, so a request
// naming one is refused as such and never mistaken for the plain operation.
bool unsupported_subresource(const s3_request& r, bool object)
{
    static constexpr std::string_view names[] = {
        "acl", "tagging", "website", "notification",
        "object-lock", "retention", "legal-hold", "replication", "accelerate",
        "requestPayment", "logging", "analytics", "metrics", "inventory", "ownershipControls",
        "publicAccessBlock", "intelligent-tiering", "attributes", "restore", "select", "torrent",
        "acl", "location-constraint",
    };
    // CORS and lifecycle rules, a policy and a default encryption belong to a bucket and to nothing else.
    if (object && (r.has_query("cors") || r.has_query("lifecycle") || r.has_query("policy") ||
                   r.has_query("policyStatus") || r.has_query("encryption")))
        return true;
    // A part number outside an upload asks a GET or HEAD for one part of a finished object.
    if (r.has_query("partNumber") && !r.has_query("uploadId") && (!object || (r.method != "GET" && r.method != "HEAD")))
        return true;
    // A bucket's versioning is read and set, its versions listed, and an object's version read, tagged or deleted.
    if (r.has_query("versioning") && (object || (r.method != "GET" && r.method != "PUT")))
        return true;
    if (r.has_query("versions") && (object || r.method != "GET"))
        return true;
    if (r.has_query("versionId") &&
        (!object || r.has_query("uploadId") ||
         (r.method != "GET" && r.method != "HEAD" && r.method != "DELETE" && !r.has_query("tagging"))))
        return true;
    for (const auto& q : r.query)
        for (std::string_view n : names)
            // An object's tags are implemented, and a bucket's are not.
            if (q.first == n && (n != "tagging" || r.key.empty()))
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

// ─── The checksum a request asks for ────────────────────────────────────────

bool parse_checksum_request(const s3_request& r, checksum_request& out, s3_error& err)
{
    out = {};
    auto bad = [&](std::string_view message)
    {
        err = make_error("InvalidRequest");
        err.message = std::string(message);
        return false;
    };
    auto choose = [&](checksum_algo a) -> bool
    {
        if (out.algo != checksum_algo::none && out.algo != a)
            return bad("Expecting a single x-amz-checksum- header. Multiple checksum Types are not allowed.");
        out.algo = a;
        return true;
    };

    for (const auto& [name, value] : r.headers)
    {
        if (!is_checksum_header(name))
            continue;
        const checksum_algo a = checksum_from_header(name);
        if (a == checksum_algo::none)
            return bad("Value for " + std::string(name) + " header is invalid.");
        if (!choose(a))
            return false;
        std::string raw;
        if (!base64_decode(http_trim_ows(value), raw) || raw.size() != checksum_raw_len(a))
            return bad("Value for " + std::string(name) + " header is invalid.");
        out.expected_b64 = std::string(http_trim_ows(value));
    }

    if (const std::string_view alg = r.header("x-amz-sdk-checksum-algorithm"); !alg.empty())
    {
        const checksum_algo a = checksum_from_name(alg);
        if (a == checksum_algo::none)
            return bad("Checksum algorithm provided is unsupported. Please try again with any of the valid types: "
                       "[CRC32, CRC32C, CRC64NVME, SHA1, SHA256]");
        if (!choose(a))
            return false;
    }

    // A checksum that follows the body in a trailer is named ahead of it.
    std::string_view trailers = r.header("x-amz-trailer");
    while (!trailers.empty())
    {
        const size_t comma = trailers.find(',');
        std::string name(http_trim_ows(trailers.substr(0, comma)));
        trailers = comma == std::string_view::npos ? std::string_view{} : trailers.substr(comma + 1);
        for (char& ch : name)
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        if (!is_checksum_header(name))
            continue;
        const checksum_algo a = checksum_from_header(name);
        if (a == checksum_algo::none)
            return bad("Value for " + name + " header is invalid.");
        if (!choose(a))
            return false;
        out.trailer_name = std::move(name);
    }
    return true;
}

bool tagging_from_header(const s3_request& r, object_meta& m, s3_error& err)
{
    if (!r.has_header("x-amz-tagging"))
        return true;
    tag_set tags;
    if (!parse_tagging_header(r.header("x-amz-tagging"), tags, err))
        return false;
    set_tags_extra(m, encode_tags(tags));
    return true;
}

bool body_md5_ok(const s3_request& r, std::string_view body, s3_error& err)
{
    const std::string_view md5h = r.header("content-md5");
    if (md5h.empty())
        return true;
    std::string raw;
    if (!base64_decode(md5h, raw) || raw.size() != 16)
    {
        err = make_error("InvalidDigest");
        return false;
    }
    const md5_t got = md5_of(body);
    if (std::string_view(reinterpret_cast<const char*>(got.data()), 16) != raw)
    {
        err = make_error("BadDigest");
        return false;
    }
    return true;
}

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
    rv.headers      = &r.headers;
    rv.bucket       = r.bucket;
    rv.key          = r.key;
    rv.tls          = c->ssl != nullptr;

    // A bucket whose documents this shard may hold old copies of is served nothing, preflights included.
    if (m_store.any_doubt() && !docs_settled(c))
        return;
    // A browser asks before a cross-origin request, and cannot sign the asking.
    if (r.method == "OPTIONS")
    {
        op_preflight(c);
        return;
    }
    // Every answer to a cross-origin request a rule allows carries the rule, refusals included.
    if (m_store.any_cors())
        cors_actual(c);

    auth_verdict v = m_auth->authorize(rv);
    // A bucket's policy may let in a request that carries no credentials, and may refuse one that does.
    if (m_store.any_policy() && (v.allowed || v.anonymous))
        apply_policy(c, rv, v);
    if (!v.allowed)
    {
        deny_request(c, v.error.code.empty() ? make_error("AccessDenied") : v.error);
        return;
    }
    c->hook = std::move(v.hook);
    c->principal = std::move(v.principal);
    c->anonymous = v.anonymous;

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

    // A script's say comes after authentication and before anything is done.
    hook_request(c);
}

void storage_run::route(const std::shared_ptr<conn>& c)
{
    s3_request& r = c->req;
    const bool service = r.bucket.empty();
    const bool bucket_level = !service && r.key.empty();

    // A part's body streams into the upload like an object's into a file.
    const bool part_request = !service && !bucket_level && r.has_query("uploadId") && r.has_query("partNumber");
    if (r.method == "PUT" && part_request && !r.has_header("x-amz-copy-source") && !r.has_query("tagging") &&
        !unsupported_subresource(r, true))
    {
        op_upload_part(c);
        return;
    }

    if (r.method == "PUT" && !service && !bucket_level && !r.has_header("x-amz-copy-source") &&
        !r.has_query("tagging") && !unsupported_subresource(r, true))
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

    collect_body(c, bucket_level && r.has_query("cors") ? cors_max_bytes : small_body_limit);
}

void storage_run::route_small(const std::shared_ptr<conn>& c)
{
    s3_request& q = c->req;
    const bool svc = q.bucket.empty();
    const bool bkt = !svc && q.key.empty();
    const std::string_view m = q.method;
    if (svc)
    {
        if (m == "GET")
            op_list_buckets(c);
        else
            send_error(c, make_error("MethodNotAllowed"));
        return;
    }
    if (bkt && q.has_query("cors"))
    {
        if (m == "GET")
            op_get_cors(c);
        else if (m == "PUT")
            op_put_cors(c);
        else if (m == "DELETE")
            op_delete_cors(c);
        else
            send_error(c, make_error("MethodNotAllowed"));
        return;
    }
    if (bkt && q.has_query("policyStatus"))
    {
        if (m == "GET")
            op_get_policy_status(c);
        else
            send_error(c, make_error("MethodNotAllowed"));
        return;
    }
    if (bkt && q.has_query("policy"))
    {
        if (m == "GET")
            op_get_policy(c);
        else if (m == "PUT")
            op_put_policy(c);
        else if (m == "DELETE")
            op_delete_policy(c);
        else
            send_error(c, make_error("MethodNotAllowed"));
        return;
    }
    if (bkt && q.has_query("versioning"))
    {
        if (m == "GET")
            op_get_versioning(c);
        else
            op_put_versioning(c);
        return;
    }
    if (bkt && q.has_query("encryption"))
    {
        if (m == "GET")
            op_get_encryption(c);
        else if (m == "PUT")
            op_put_encryption(c);
        else if (m == "DELETE")
            op_delete_encryption(c);
        else
            send_error(c, make_error("MethodNotAllowed"));
        return;
    }
    if (bkt && q.has_query("versions"))
    {
        op_list_versions(c);
        return;
    }
    if (bkt && q.has_query("lifecycle"))
    {
        if (m == "GET")
            op_get_lifecycle(c);
        else if (m == "PUT")
            op_put_lifecycle(c);
        else if (m == "DELETE")
            op_delete_lifecycle(c);
        else
            send_error(c, make_error("MethodNotAllowed"));
        return;
    }
    if (bkt)
    {
        if (m == "GET")
        {
            if (q.has_query("uploads"))
                op_list_uploads(c);
            else if (q.has_query("location"))
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
    if (q.has_query("tagging"))
    {
        if (m == "GET")
            op_get_object_tagging(c);
        else if (m == "PUT")
            op_put_object_tagging(c);
        else if (m == "DELETE")
            op_delete_object_tagging(c);
        else
            send_error(c, make_error("MethodNotAllowed"));
        return;
    }
    const bool upload = q.has_query("uploadId");
    if (m == "GET")
    {
        if (upload)
            op_list_parts(c);
        else
            op_get_object(c, false);
    }
    else if (m == "HEAD")
        op_get_object(c, true);
    else if (m == "PUT")
    {
        if (upload && q.has_query("partNumber"))
            op_upload_part_copy(c);
        else
            op_copy_object(c);
    }
    else if (m == "DELETE")
    {
        if (upload)
            op_abort_multipart(c);
        else
            op_delete_object(c);
    }
    else if (m == "POST" && q.has_query("uploads"))
        op_create_multipart(c);
    else if (m == "POST" && upload)
        op_complete_multipart(c);
    else
        send_error(c, make_error("MethodNotAllowed"));
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
    m_node.create_bucket(name, [this, weak, name](st s)
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
    // An upload that was never completed is something the bucket still holds.
    if (m_mpu.bucket_has_uploads(c->req.bucket))
    {
        send_error_st(c, st::bucket_not_empty);
        return;
    }
    std::weak_ptr<conn> weak = c;
    m_node.delete_bucket(c->req.bucket, [this, weak](st s)
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

    std::string token_text;
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

    // A lone shard holds every key, so the walk of its index is rendered as it goes.
    if (m_store.shards() <= 1)
    {
        list_xml_writer walk(lr);
        if (const st s = m_store.list_walk(q.bucket, lq, walk); s != st::ok)
        {
            send_error_st(c, s);
            return;
        }
        std::string next_token, next_marker;
        if (v2 && walk.is_truncated())
        {
            next_token = base64url_encode(walk.resume_at());
            lr.next_token = next_token;
        }
        if (!v2 && walk.is_truncated())
        {
            if (const std::string* last = walk.last_named())
            {
                next_marker    = *last;
                lr.next_marker = next_marker;
            }
        }
        response r;
        r.headers.emplace_back("Content-Type", "application/xml");
        r.body = walk.finish();
        send_response(c, std::move(r));
        return;
    }

    // Every shard's part of the answer, merged, and the request's own strings
    // are still the views `lr` holds for as long as the connection is.
    std::weak_ptr<conn> weak = c;
    m_node.list(q.bucket, lq, [this, weak, lr, v2](st s, list_page page) mutable
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (s != st::ok)
        {
            send_error_st(cc, s);
            return;
        }
        std::string next_token, next_marker;
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
        send_response(cc, std::move(r));
    });
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
    if (s3_error err; !body_md5_ok(q, c->body, err))
    {
        send_error(c, err);
        return;
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
        std::string                bucket;
        std::weak_ptr<conn>        weak;
    };
    auto b = std::make_shared<batch>();
    b->quiet   = dr.quiet;
    b->pending = dr.keys.size();
    b->results.resize(dr.keys.size());
    b->bucket  = q.bucket;
    b->weak    = c;

    const auto done_one = [this](const std::shared_ptr<batch>& bt)
    {
        if (--bt->pending != 0)
            return;
        auto cc = bt->weak.lock();
        if (!cc || cc->dead)
            return;
        response r;
        r.headers.emplace_back("Content-Type", "application/xml");
        r.body = delete_result_xml(bt->results, bt->quiet);
        send_response(cc, std::move(r));
    };

    // Every removal is started at once, so their journal records share fsyncs.
    for (size_t i = 0; i < dr.keys.size(); ++i)
    {
        delete_result& res = b->results[i];
        res.key        = std::move(dr.keys[i]);
        res.version_id = std::move(dr.versions[i]);
        if (res.key.empty() || res.key.size() > max_key_bytes)
        {
            res.ok    = false;
            res.error = make_error("KeyTooLongError");
            done_one(b);
            continue;
        }
        if (!res.version_id.empty() && !valid_version_id(res.version_id))
        {
            res.ok    = false;
            res.error = make_error("NoSuchVersion");
            done_one(b);
            continue;
        }
        // An entry that names a version is s3:DeleteObjectVersion, which the dispatch could not see in the body.
        if (!res.version_id.empty() && m_store.any_policy() && !policy_allows_version_delete(c, res.key))
        {
            res.ok    = false;
            res.error = make_error("AccessDenied");
            done_one(b);
            continue;
        }
        ++m_c.deletes;
        m_store.remove_version(b->bucket, res.key, res.version_id, [this, b, i, done_one](remove_result rr)
        {
            delete_result& one = b->results[i];
            if (rr.status != st::ok)
            {
                one.ok    = false;
                one.error = error_for(rr.status);
            }
            else
            {
                if (rr.existed)
                    notify_delete(b->bucket, one.key);
                one.delete_marker = rr.marker;
                if (rr.marker)
                    one.marker_version_id = rr.version_id;
            }
            done_one(b);
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
        {
            // The framing is not part of the object, and any other coding is.
            std::string rest;
            std::string_view codings = value;
            while (!codings.empty())
            {
                const size_t comma = codings.find(',');
                const std::string_view one = http_trim_ows(codings.substr(0, comma));
                codings = comma == std::string_view::npos ? std::string_view{} : codings.substr(comma + 1);
                if (one.empty() || http_token_equals(one, "aws-chunked", 11))
                    continue;
                rest += rest.empty() ? "" : ", ";
                rest += one;
            }
            take = false;
            if (!rest.empty())
                m.extra.emplace_back(name, std::move(rest));
        }
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

    object_meta meta;
    s3_error err;
    // Refused before the body is read, and the body is read off after the
    // answer, so a client still sending it hears the refusal and not a reset.
    if (!object_meta_from_headers(c, meta, err) || !tagging_from_header(r, meta, err))
    {
        deny_request(c, err);
        return;
    }

    // S3's conditional write: refuse to replace what is there.  A key another
    // shard owns is not known here, so its owner decides at commit, which is
    // also where two racing creators are told apart.
    const bool create_only = r.header("if-none-match") == "*";
    if (create_only && m_store.owns(r.bucket, r.key) && m_store.find(r.bucket, r.key))
    {
        deny_request(c, make_error("PreconditionFailed"));
        return;
    }

    sse_ask ask;
    sse_seal_spec seal;
    if (!sse_for_write(c, r.bucket, ask, err) ||
        (ask.mode != sse_mode::none && !sse_new_key(ask, false, meta, seal, err)))
    {
        deny_request(c, err);
        return;
    }
    start_put(c, r.key, std::move(meta), {}, checksum_algo::none, create_only, {},
              ask.mode != sse_mode::none ? &seal : nullptr);
}

bool storage_run::body_length(const conn& c, uint64_t& expected)
{
    expected   = c.req.content_length;
    bool known = c.req.has_content_length && !c.req.chunked;
    if (c.hook)
        if (auto d = c.hook->decoded_length())
        {
            expected = *d;
            known    = true;
        }
    return known;
}

// Begins streaming the request's body into a temporary file for `key`, after
// the checks every body that becomes a file has passed; `committer` says where
// the finished file goes when it is not the object namespace, and a checksum
// algorithm is taken whether or not the client named one when `forced_algo` says so.
void storage_run::start_put(const std::shared_ptr<conn>& c, std::string key, object_meta meta,
                            put_op::committer committer, checksum_algo forced_algo, bool create_only,
                            const part_place& place, const sse_seal_spec* seal)
{
    s3_request& r = c->req;

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

    checksum_request ck;
    s3_error         err;
    if (!parse_checksum_request(r, ck, err))
    {
        r.keep_alive = false;
        send_error(c, err, true);
        return;
    }
    if (forced_algo != checksum_algo::none)
    {
        if (ck.algo != checksum_algo::none && ck.algo != forced_algo)
        {
            r.keep_alive = false;
            err = make_error("InvalidRequest");
            err.message = "Checksum Type mismatch occurred, expected checksum Type: " +
                          std::string(checksum_name(forced_algo)) + ", actual checksum Type: " +
                          std::string(checksum_name(ck.algo));
            send_error(c, err, true);
            return;
        }
        ck.algo = forced_algo;
    }
    // A placeholder of the value's length, so the header reserves room for it.
    if (ck.algo != checksum_algo::none)
        meta.extra.emplace_back(std::string(checksum_header(ck.algo)), std::string(checksum_b64_len(ck.algo), 'A'));

    uint64_t expected = 0;
    const bool known  = body_length(*c, expected);
    // Room for the place in the part's header, which the part's owner reads back at its commit.
    if (place.off)
        meta.extra.emplace_back(std::string(mpu_place_extra), encode_place(place.off));
    if (m_store.active_puts() >= m_max_active_puts)
    {
        r.keep_alive = false;
        send_error(c, make_error("SlowDown"), true);
        return;
    }

    st why = st::ok;
    auto op = m_store.begin_put(r.bucket, key, std::move(meta), expected, known, why, !committer && !create_only, seal);
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
    if (ck.algo != checksum_algo::none)
    {
        op->track_checksum(ck.algo, std::move(ck.expected_b64));
        c->ck_trailer = std::move(ck.trailer_name);
    }
    if (committer)
        op->set_committer(std::move(committer));
    op->set_create_only(create_only);
    if (place.off)
        op->place_body(place.path, place.off, place.room);
    if (seal)
        ++m_c.sse_puts;
    begin_put_body(c, std::move(op));
}

// ─── CopyObject ─────────────────────────────────────────────────────────────

bool parse_copy_source(std::string_view header, std::string& bucket, std::string& key, s3_error& err,
                       std::string* version_id)
{
    std::string src;
    std::string_view raw = header;
    // A version id after the key names the version copied, and is refused by a caller that cannot copy one.
    if (const size_t q = raw.find("?versionId="); q != std::string_view::npos)
    {
        const std::string_view id = raw.substr(q + 11);
        if (!version_id || !valid_version_id(id))
        {
            err = make_error("InvalidArgument");
            err.message = "Invalid version id specified";
            return false;
        }
        *version_id = std::string(id);
        raw = raw.substr(0, q);
    }
    if (!percent_decode(raw, src, false))
    {
        err = make_error("InvalidArgument");
        return false;
    }
    std::string_view sv = src;
    if (!sv.empty() && sv.front() == '/')
        sv.remove_prefix(1);
    const size_t slash = sv.find('/');
    if (slash == std::string_view::npos || slash == 0 || slash + 1 >= sv.size())
    {
        err = make_error("InvalidArgument");
        err.message = "Copy Source must mention the source bucket and key: sourcebucket/sourcekey";
        return false;
    }
    bucket = std::string(sv.substr(0, slash));
    key    = std::string(sv.substr(slash + 1));
    return true;
}

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

    std::string src_bucket, src_key, src_version;
    s3_error    copy_err;
    if (!parse_copy_source(src_hdr, src_bucket, src_key, copy_err, &src_version))
    {
        send_error(c, copy_err, false, "ArgumentName", "x-amz-copy-source");
        return;
    }

    const std::string_view directive = r.header("x-amz-metadata-directive");
    if (!directive.empty() && directive != "COPY" && directive != "REPLACE")
    {
        s3_error e = make_error("InvalidArgument");
        e.message = "Unknown metadata directive.";
        send_error(c, e, false, "ArgumentName", "x-amz-metadata-directive");
        return;
    }
    const bool replace = directive == "REPLACE";
    if (const std::string_view td = r.header("x-amz-tagging-directive"); !td.empty() && td != "COPY" && td != "REPLACE")
    {
        s3_error e = make_error("InvalidArgument");
        e.message = "Unknown tagging directive.";
        send_error(c, e, false, "ArgumentName", "x-amz-tagging-directive");
        return;
    }

    if (!m_store.has_bucket(src_bucket) || !m_store.has_bucket(r.bucket))
    {
        error_context ctx;
        send_error_st(c, st::no_such_bucket);
        return;
    }
    // The source may be another shard's, whose header is then read from its file.
    std::weak_ptr<conn> weak = c;
    auto go = [this, weak, src_bucket, src_key, src_version, replace](st s, const object_meta& sm)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        // A delete marker is no object to copy: the latest is no such key, and one named by its id no valid source.
        if (s == st::delete_marker)
        {
            s3_error e = make_error("InvalidRequest");
            e.message = "The source of a copy request may not specifically refer to a delete marker by version id.";
            send_error(cc, e);
            return;
        }
        if (s != st::ok)
        {
            send_error_st(cc, s);
            return;
        }
        op_copy_from(cc, src_bucket, src_key, src_version, replace, sm);
    };
    if (src_version.empty())
        m_store.stat_object(src_bucket, src_key, std::move(go));
    else
        m_store.stat_version(src_bucket, src_key, src_version, std::move(go));
}

void storage_run::op_copy_from(const std::shared_ptr<conn>& c, std::string src_bucket,
                               std::string src_key, std::string src_version, bool replace, const object_meta& src)
{
    s3_request& r = c->req;
    const object_meta* src_meta = &src;
    // What the copy is encrypted with, and the key that opens its source, are refused before anything is read.
    sse_ask dst;
    std::optional<sse_key> src_customer;
    if (s3_error err; !sse_for_write(c, r.bucket, dst, err) || !sse_customer(c, sse_c_copy_prefix, src_customer, err))
    {
        send_error(c, err);
        return;
    }
    if (sse_key probe{}; is_encrypted(src) || src_customer)
    {
        s3_error err;
        const bool opens = is_encrypted(src) ? sse_data_key(src, src_customer, probe, err) : false;
        if (!opens)
        {
            if (!is_encrypted(src))
            {
                err = make_error("InvalidRequest");
                err.message = "The encryption parameters are not applicable to this object.";
            }
            send_error(c, err);
            return;
        }
    }
    // A version copied over its own key is a new latest made of an old one, which S3 allows as it is, and so is a
    // copy that names the encryption it changes to.
    if (src_bucket == r.bucket && src_key == r.key && !replace && src_version.empty() && !dst.named)
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
    // The tags follow their own directive, whatever the metadata's says.
    if (r.header("x-amz-tagging-directive") == "REPLACE")
    {
        set_tags_extra(meta, {});
        if (s3_error err; !tagging_from_header(r, meta, err))
        {
            send_error(c, err);
            return;
        }
    }
    else
        set_tags_extra(meta, tags_of(*src_meta));

    ++m_c.copies;
    std::weak_ptr<conn> weak = c;
    // The version copied, which a source in a bucket that never kept versions has none of.
    const std::string source_id = !src_version.empty() ? src_version
                                : has_version(src) || m_store.bucket_versioning(src_bucket) != versioning::off
                                    ? version_of(src).id : std::string{};
    // Bytes sealed under one key, or to be sealed under another, are opened and sealed again on their way through.
    if (is_encrypted(src) || dst.mode != sse_mode::none)
    {
        copy_sealed(c, std::move(src_bucket), std::move(src_key), std::move(src_version), std::move(meta), src, dst,
                    std::move(src_customer), source_id);
        return;
    }
    m_store.copy(src_bucket, src_key, std::move(src_version), r.bucket, r.key, std::move(meta),
                 [this, weak, source_id](put_result p)
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
        if (!source_id.empty())
            resp.headers.emplace_back("x-amz-copy-source-version-id", source_id);
        if (has_version(p.meta))
            resp.headers.emplace_back("x-amz-version-id", version_of(p.meta).id);
        resp.body = copy_result_xml(p.meta);
        send_response(cc, std::move(resp));
        notify_put(cc->req.bucket, cc->req.key, p.meta);
    });
}

// ─── DeleteObject ───────────────────────────────────────────────────────────

void storage_run::op_delete_object(const std::shared_ptr<conn>& c)
{
    std::string version_id;
    if (!version_param(c, version_id))
        return;
    ++m_c.deletes;
    std::weak_ptr<conn> weak = c;
    m_store.remove_version(c->req.bucket, c->req.key, std::move(version_id),
                           [this, weak, bucket = c->req.bucket, key = c->req.key](remove_result rr)
    {
        // Told whether or not the client is still there to hear the answer: the
        // object is gone either way.
        if (rr.status == st::ok && rr.existed)
            notify_delete(bucket, key);
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (rr.status != st::ok)
        {
            send_error_st(cc, rr.status);
            return;
        }
        response r;
        r.status = 204;
        if (rr.marker)
            r.headers.emplace_back("x-amz-delete-marker", "true");
        if (!rr.version_id.empty())
            r.headers.emplace_back("x-amz-version-id", rr.version_id);
        send_response(cc, std::move(r));
    });
}

// ─── GetObject, HeadObject ──────────────────────────────────────────────────

namespace
{

// The headers an object's stored metadata puts on a response, with the
// response-* query overrides a presigned URL may add; in a `versioned` bucket an
// object written before it was versioned is named as the null version.
void object_headers(const s3_request& q, const object_meta& m, response& r, bool ranged, bool versioned)
{
    if (versioned && !has_version(m))
        r.headers.emplace_back("x-amz-version-id", "null");
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

    // The checksum a client asked to see, which describes the whole object and
    // so is left off an answer that holds only part of it.
    const bool with_checksum = !ranged && http_token_equals(q.header("x-amz-checksum-mode"), "enabled", 7);
    for (const auto& [n, v] : m.extra)
    {
        if (n.starts_with("x-amz-meta-"))
        {
            r.headers.emplace_back(n, v);
            continue;
        }
        // The tags themselves are GetObjectTagging's to tell, and a GET says how many there are.
        if (n == tags_extra)
        {
            r.headers.emplace_back("x-amz-tagging-count", std::to_string(tag_count(v)));
            continue;
        }
        if (is_checksum_header(n))
        {
            if (with_checksum)
                r.headers.emplace_back(n, v);
            continue;
        }
        if (n == part_sizes_extra)
            continue;
        if (n == sse_extra)
        {
            sse_headers(q, m, r.headers);
            continue;
        }
        if (n == version_extra)
        {
            r.headers.emplace_back("x-amz-version-id", version_of(m).id);
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

// The headers of an object's plain answer as the lines they are sent as.
void render_object_headers(const s3_request& q, const object_meta& m, std::string& out, bool versioned)
{
    response r;
    object_headers(q, m, r, false, versioned);
    for (const auto& [k, v] : r.headers)
    {
        out += k;
        out += ": ";
        out += v;
        out += "\r\n";
    }
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

    // One part of the object asked for by its number, which S3 allows instead of a range and never beside one.
    uint32_t part = 0;
    if (q.has_query("partNumber"))
    {
        uint64_t n = 0;
        if (!parse_uint(q.get_query("partNumber"), n) || n < 1 || n > mpu_max_parts)
        {
            s3_error e = make_error("InvalidArgument");
            e.message = "Part number must be an integer between 1 and 10000, inclusive";
            send_error(c, e, false, "ArgumentName", "partNumber");
            return;
        }
        if (q.has_header("range"))
        {
            s3_error e = make_error("InvalidRequest");
            e.message = "Cannot specify both Range header and partNumber query parameter";
            send_error(c, e);
            return;
        }
        part = static_cast<uint32_t>(n);
    }

    std::string version_id;
    if (!version_param(c, version_id))
        return;
    if (!m_store.has_bucket(q.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    // A read names the key it opens with and never an encryption, which only what writes an object chooses.
    if (q.has_header("x-amz-server-side-encryption"))
    {
        s3_error e = make_error("InvalidArgument");
        e.message = "The x-amz-server-side-encryption header is not supported for this operation";
        send_error(c, e);
        return;
    }
    // Answers a request whose object is known, from a HEAD's memory or a GET's file; `clear` says the bytes
    // already in hand are the object's own rather than what its file holds.
    auto answer = [this, head, part](const std::shared_ptr<conn>& cc, const object_meta& m, int fd,
                               uint64_t data_off, const std::string& prefetch, bool clear)
    {
        const s3_request& rq = cc->req;

        auto close_file = [&] { if (fd >= 0) m_loop.close_fd(fd); };

        // An encrypted object is read only with the key its record names, and a clear one with none.
        sse_key key{};
        const bool sealed = is_encrypted(m);
        if (s3_error err; !sse_read_key(cc, m, sse_c_prefix, key, err, !head && !clear))
        {
            close_file();
            send_error(cc, err);
            return;
        }

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
        if (part)
        {
            const part_status ps = part_range(m, part, first, len);
            if (ps != part_status::ok)
            {
                close_file();
                s3_error e = make_error(ps == part_status::out_of_range ? "InvalidPartNumber" : "NotImplemented");
                if (ps == part_status::unknown)
                    e.message = "This object's part sizes were not recorded when it was completed, so it cannot be read by partNumber";
                send_error(cc, e, false, "PartNumberRequested", std::to_string(part));
                return;
            }
            // An empty part has no byte a Content-Range could name.
            ranged = len > 0;
        }
        else if (const std::string_view rh = rq.header("range"); !rh.empty())
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
                count_error(err.code);
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

        object_headers(rq, m, r, ranged, m_store.bucket_versioning(rq.bucket) != versioning::off);
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

        // A body the header read already brought in, or the hot copy, is sent from memory in one write.
        if (sealed && !clear)
        {
            std::string plain;
            if (len > 0 && prefetch.size() >= stored_size(m) && sse_open_body(m, key, prefetch, plain))
            {
                close_file();
                r.body = plain.substr(static_cast<size_t>(first), static_cast<size_t>(len));
                ++m_c.copied_gets;
                ++m_c.sse_gets;
                send_response(cc, std::move(r));
                return;
            }
        }
        else if (!prefetch.empty() && first + len <= prefetch.size())
        {
            close_file();
            r.body_view = std::string_view(prefetch).substr(static_cast<size_t>(first), static_cast<size_t>(len));
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
        if (sealed)
        {
            send_sealed(cc, std::move(r), fd, data_off, m, key, first, len);
            return;
        }
        send_file(cc, std::move(r), fd, data_off + first, len);
    };

    // A version asked for by its id is read where it is, and never from or into a held copy, which is the latest's.
    if (!version_id.empty())
    {
        std::weak_ptr<conn> weak = c;
        if (head)
        {
            m_store.stat_version(q.bucket, q.key, std::move(version_id),
                                 [this, weak, answer](st s, const object_meta& m)
            {
                auto cc = weak.lock();
                if (!cc || cc->dead)
                    return;
                if (s == st::delete_marker)
                    send_delete_marker(cc, m, true);
                else if (s != st::ok)
                    send_error_st(cc, s);
                else
                    answer(cc, m, -1, 0, std::string{}, true);
            });
            return;
        }
        m_store.open_version(q.bucket, q.key, std::move(version_id), object_store::hot_max_object,
                             [this, weak, answer](open_result o)
        {
            auto cc = weak.lock();
            if (!cc || cc->dead)
            {
                if (o.fd >= 0)
                    m_loop.close_fd(o.fd);
                return;
            }
            if (o.status == st::delete_marker)
                send_delete_marker(cc, o.meta, true);
            else if (o.status != st::ok)
                send_error_st(cc, o.status);
            else
                answer(cc, o.meta, o.fd, o.data_off, o.prefetch, false);
        });
        return;
    }

    // A GET of a key held in memory finds the copy, and whose key it is, in one lookup.
    object_store::hot_hit hot;
    const bool held = !head && m_store.hot_find(q.bucket, q.key, hot) && hot.body;
    // Memory holds this shard's keys only, so another shard's key is asked of
    // its file, which is the truth and which any shard can read.
    const bool mine = held ? !hot.foreign : m_store.owns(q.bucket, q.key);
    const object_meta* mem = held ? (hot.foreign ? nullptr : hot.meta) : mine ? m_store.find(q.bucket, q.key) : nullptr;
    if (mine && !mem)
    {
        if (const object_meta* marker = m_store.latest_marker(q.bucket, q.key))
            send_delete_marker(c, *marker, false);
        else
            send_error_st(c, st::no_such_key);
        return;
    }


    if (head)
    {
        if (mem)
        {
            answer(c, *mem, -1, 0, std::string{}, true);
            return;
        }
        std::weak_ptr<conn> weak = c;
        m_store.stat_foreign(q.bucket, q.key, [this, weak, answer](st s, const object_meta& m)
        {
            auto cc = weak.lock();
            if (!cc || cc->dead)
                return;
            if (s == st::no_such_key && is_delete_marker(m))
                send_delete_marker(cc, m, false);
            else if (s != st::ok)
                send_error_st(cc, s);
            else
                answer(cc, m, -1, 0, std::string{}, true);
        });
        return;
    }

    // A hot small object is answered from memory, with no file opened; another
    // shard's for as long as its owner has not said it changed.
    if (held)
    {
        ++m_c.hot_gets;
        // A GET that asks for nothing but the object gets the headers kept with the copy.
        if (q.query.empty() && q.header("range").empty() && q.header("x-amz-checksum-mode").empty() &&
            !q.has_header("x-amz-server-side-encryption-customer-algorithm") && evaluate(q, *hot.meta) == cond::proceed)
        {
            if (hot.head->empty())
            {
                render_object_headers(q, *hot.meta, *hot.head, m_store.bucket_versioning(q.bucket) != versioning::off);
                m_store.hot_charge(hot.head->size());
            }
            response r;
            r.headers_raw = *hot.head;
            r.body_view   = *hot.body;
            ++m_c.copied_gets;
            send_response(c, std::move(r));
            return;
        }
        answer(c, *hot.meta, -1, 0, *hot.body, true);
        return;
    }
    const uint64_t drop_epoch = m_store.hot_epoch();

    // Small objects are read whole with their header, in one read; a key whose
    // size is not known here is read that way too, since the read is short for
    // a small object and only a little long for a large one.
    const size_t prefetch = mem ? (mem->size <= object_store::hot_max_object ? static_cast<size_t>(stored_size(*mem)) : 0)
                                : object_store::hot_max_object;
    std::weak_ptr<conn> weak = c;
    m_store.open_object(q.bucket, q.key, prefetch, [this, weak, answer, mine, drop_epoch, b = q.bucket, k = q.key](open_result o)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
        {
            if (o.fd >= 0)
                m_loop.close_fd(o.fd);
            return;
        }
        if (o.delete_marker)
        {
            send_delete_marker(cc, o.meta, false);
            return;
        }
        if (o.status != st::ok)
        {
            send_error_st(cc, o.status);
            return;
        }
        // An object under the master key is held opened, and one under a client's key is never held at all.
        if (is_encrypted(o.meta))
        {
            sse_key key{};
            std::string plain;
            if (s3_error err; o.meta.size > 0 && o.meta.size <= object_store::hot_max_object &&
                              sse_mode_of(o.meta) == sse_mode::s3 && o.prefetch.size() >= stored_size(o.meta) &&
                              sse_read_key(cc, o.meta, sse_c_prefix, key, err) &&
                              sse_open_body(o.meta, key, o.prefetch, plain))
            {
                if (mine)
                    m_store.hot_put(b, k, o.meta, plain);
                else
                    m_store.hot_put_foreign(b, k, drop_epoch, o.meta, plain);
                answer(cc, o.meta, o.fd, o.data_off, plain, true);
                return;
            }
            answer(cc, o.meta, o.fd, o.data_off, o.prefetch, false);
            return;
        }
        if (o.meta.size > 0 && o.prefetch.size() >= o.meta.size)
        {
            const std::string_view whole = std::string_view(o.prefetch).substr(0, static_cast<size_t>(o.meta.size));
            if (mine)
                m_store.hot_put(b, k, o.meta, whole);
            else
                m_store.hot_put_foreign(b, k, drop_epoch, o.meta, whole);
        }
        answer(cc, o.meta, o.fd, o.data_off, o.prefetch, false);
    });
}

}   // namespace socketley::storage
