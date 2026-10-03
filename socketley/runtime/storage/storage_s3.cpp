// The S3 operations: routing a parsed request to one of them and answering it.
#include "storage_run.h"

#include <algorithm>
#include <charconv>

#include <openssl/evp.h>

#include "lifecycle.h"
#include "s3_cors.h"
#include "s3_names.h"
#include "s3_object_lock.h"
#include "s3_tagging.h"
#include "s3_versioning.h"
#include "s3_vhost.h"
#include "s3_xml_tree.h"
#include "s3_xml.h"
#include "storage_instance.h"
#include "../../shared/logging.h"

namespace socketley::storage
{

namespace
{

constexpr uint64_t small_body_limit = 4ull << 20;
constexpr size_t   user_meta_limit  = 2048;
// A form asking for temporary credentials, read before anyone is known to have sent it.
constexpr uint64_t sts_max_body     = 16 * 1024;

// The subresources of the S3 API this runtime does not implement, so a request
// naming one is refused as such and never mistaken for the plain operation.
bool unsupported_subresource(const s3_request& r, bool object)
{
    static constexpr std::string_view names[] = {
        "acl", "tagging",
        "accelerate",
        "requestPayment", "logging", "analytics", "metrics", "inventory", "ownershipControls",
        "publicAccessBlock", "intelligent-tiering", "attributes", "restore", "select", "torrent",
        "acl", "location-constraint",
    };
    // Every subresource is a query parameter, and most requests have none.
    if (r.query.empty())
        return false;
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
    // A bucket's notification configuration is read and set, and an object has none.
    if (r.has_query("notification") && (object || (r.method != "GET" && r.method != "PUT")))
        return true;
    // A bucket's replication configuration is read, set and deleted, and an object has none.
    if (r.has_query("replication") && (object || (r.method != "GET" && r.method != "PUT" && r.method != "DELETE")))
        return true;
    // And its website configuration and its quota likewise.
    if (r.has_query("website") && (object || (r.method != "GET" && r.method != "PUT" && r.method != "DELETE")))
        return true;
    if (r.has_query("quota") && (object || (r.method != "GET" && r.method != "PUT" && r.method != "DELETE")))
        return true;
    // A bucket's object lock is read and set, and a version's retention and legal hold likewise.
    const bool lock_attr = r.has_query("retention") || r.has_query("legal-hold");
    if ((r.has_query("object-lock") && (object || (r.method != "GET" && r.method != "PUT"))) ||
        (lock_attr && (!object || (r.method != "GET" && r.method != "PUT"))))
        return true;
    if (r.has_query("versionId") &&
        (!object || r.has_query("uploadId") ||
         (r.method != "GET" && r.method != "HEAD" && r.method != "DELETE" && !r.has_query("tagging") && !lock_attr)))
        return true;
    for (const auto& q : r.query)
        for (std::string_view n : names)
            // Tags are an object's and a bucket's, an object's attributes are read, ACLs are read and set as S3 does
            // for a bucket whose ACLs are disabled, and a bucket's ownership controls are read.
            if (q.first == n && ((n != "tagging" && n != "attributes") || (n == "attributes" && r.key.empty()) ||
                                 (n == "attributes" && r.method != "GET")) &&
                (n != "acl" || (r.method != "GET" && r.method != "PUT")) &&
                (n != "ownershipControls" || !r.key.empty() || (r.method != "GET" && r.method != "PUT")))
                return true;
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

bool checksum_algorithm_header(const s3_request& r, checksum_algo& out, s3_error& err)
{
    out = checksum_algo::none;
    const std::string_view name = r.header("x-amz-checksum-algorithm");
    if (name.empty())
        return true;
    out = checksum_from_name(name);
    if (out != checksum_algo::none)
        return true;
    err = make_error("InvalidRequest");
    err.message = "Checksum algorithm provided is unsupported. Please try again with any of the valid types: "
                  "[CRC32, CRC32C, CRC64NVME, SHA1, SHA256]";
    return false;
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
    if (!r.has_header("content-md5"))
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
    // A website is read by browsers, which sign nothing and are judged by the bucket's policy alone.
    if (r.website)
    {
        op_website(c);
        return;
    }
    // A request for temporary credentials is signed over its form, which is read before it is judged.
    if (r.method == "POST" && r.bucket.empty())
    {
        collect_body(c, sts_max_body);
        return;
    }
    // A browser asks before a cross-origin request, and cannot sign the asking.
    if (r.method == "OPTIONS")
    {
        op_preflight(c);
        return;
    }
    // Every answer to a cross-origin request a rule allows carries the rule, refusals included.
    if (m_store.any_cors())
        cors_actual(c);
    // A browser's form is signed in its fields, which are read before anything is decided.
    if (r.method == "POST" && !r.bucket.empty() && r.key.empty() && r.raw_query.empty() &&
        http_token_equals(http_trim_ows(r.header("content-type").substr(0, r.header("content-type").find(';'))),
                          "multipart/form-data", 19))
    {
        begin_post_form(c);
        return;
    }

    auth_verdict v = m_auth->authorize(rv);
    // A policy may let in a request with no credentials, and ownership or a policy may refuse one with them.
    if ((v.allowed || v.anonymous) && needs_judging(v.anonymous ? nullptr : v.user.get()))
        apply_policy(c, rv, v);
    if (!v.allowed)
    {
        deny_request(c, v.error.code.empty() ? make_error("AccessDenied") : v.error);
        return;
    }
    c->hook = std::move(v.hook);
    c->principal = std::move(v.principal);
    c->user      = std::move(v.user);
    c->anonymous = v.anonymous;

    // A client that signs its payload in chunks, talking to a runtime with no
    // decoder for them, would have the framing stored as the object; an empty body has none.
    const bool has_body = r.chunked || (r.has_content_length && r.content_length > 0);
    if (!c->hook && (r.payload_hash.starts_with("STREAMING-") ||
                     (has_body && http_list_has_token(r.header("content-encoding"), "aws-chunked", 11))))
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

    // A write that asks for an ACL other than its owner's full control is refused, as S3 refuses it on a bucket
    // whose ACLs are disabled, and never stored without it.
    // The owner a grant may name is the bucket's, or for a bucket being made the user making it.
    // Only a write carries ACL headers, so a read looks up no owner.
    if ((r.method == "PUT" || r.method == "POST") && !r.has_query("acl"))
    {
        const std::string_view acl_owner = m_store.has_bucket(r.bucket) || !c->user ? owner_of(r.bucket)
                                                                                    : std::string_view(c->user->id);
        if (s3_error e; !acl_headers_ok(r, bucket_level && !r.form, acl_owner, e))
        {
            deny_request(c, e);
            return;
        }
    }
    if (s3_error e; !storage_class_ok(r, e))
    {
        deny_request(c, e);
        return;
    }
    // A form is the PutObject its fields describe, with its file as the body.
    if (r.form)
    {
        op_put_object(c);
        return;
    }

    // A part's body streams into the upload like an object's into a file.
    const bool part_request = !service && !bucket_level && r.has_query("uploadId") && r.has_query("partNumber");
    const bool lock_attr = r.has_query("retention") || r.has_query("legal-hold");
    if (r.method == "PUT" && part_request && !r.has_header("x-amz-copy-source") && !r.has_query("tagging") &&
        !r.has_query("acl") && !lock_attr && !unsupported_subresource(r, true))
    {
        op_upload_part(c);
        return;
    }

    if (r.method == "PUT" && !service && !bucket_level && !r.has_header("x-amz-copy-source") &&
        !r.has_query("tagging") && !r.has_query("acl") && !lock_attr && !unsupported_subresource(r, true))
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
        else if (m == "POST")
            op_sts(c);
        else
            send_error(c, make_error("MethodNotAllowed"));
        return;
    }
    if (q.has_query("acl"))
    {
        if (m == "GET")
            op_get_acl(c);
        else
            op_put_acl(c);
        return;
    }
    if (bkt && q.has_query("ownershipControls"))
    {
        op_ownership_controls(c);
        return;
    }
    if (bkt && q.has_query("tagging"))
    {
        if (m == "GET")
            op_get_bucket_tagging(c);
        else if (m == "PUT")
            op_put_bucket_tagging(c);
        else if (m == "DELETE")
            op_delete_bucket_tagging(c);
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
    if (bkt && q.has_query("notification"))
    {
        if (m == "GET")
            op_get_notification(c);
        else
            op_put_notification(c);
        return;
    }
    if (bkt && q.has_query("website"))
    {
        if (m == "GET")
            op_get_website(c);
        else if (m == "PUT")
            op_put_website(c);
        else
            op_delete_website(c);
        return;
    }
    if (bkt && q.has_query("quota"))
    {
        if (m == "GET")
            op_get_quota(c);
        else if (m == "PUT")
            op_put_quota(c);
        else
            op_delete_quota(c);
        return;
    }
    if (bkt && q.has_query("replication"))
    {
        if (m == "GET")
            op_get_replication(c);
        else if (m == "PUT")
            op_put_replication(c);
        else
            op_delete_replication(c);
        return;
    }
    if (bkt && q.has_query("object-lock"))
    {
        if (m == "GET")
            op_get_object_lock_config(c);
        else
            op_put_object_lock_config(c);
        return;
    }
    if (!bkt && (q.has_query("retention") || q.has_query("legal-hold")))
    {
        if (m == "GET")
            op_get_lock_attr(c, q.has_query("legal-hold"));
        else
            op_put_lock_attr(c, q.has_query("legal-hold"));
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
        else if (q.has_query("attributes"))
            op_get_object(c, true, true);
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
    const s3_request& q = c->req;
    auto bad_arg = [&](std::string_view name, std::string_view msg)
    {
        s3_error e = make_error("InvalidArgument");
        e.message  = std::string(msg);
        send_error(c, e, false, "ArgumentName", name);
    };
    bucket_page page;
    page.prefix = q.get_query("prefix");
    if (q.has_query("max-buckets"))
    {
        uint64_t v;
        if (!parse_uint(q.get_query("max-buckets"), v) || v < 1 || v > 10000)
        {
            bad_arg("max-buckets", "max-buckets must be an integer from 1 to 10000");
            return;
        }
        page.max = static_cast<size_t>(v);
    }
    std::string after;
    if (q.has_query("continuation-token") &&
        (q.get_query("continuation-token").empty() || !base64url_decode(q.get_query("continuation-token"), after)))
    {
        bad_arg("continuation-token", "The continuation token provided is incorrect");
        return;
    }
    page.after = after;
    // A user is shown the buckets it owns, and an admin every bucket.
    const user_identity* u = c->user.get();
    const std::string_view me = u ? std::string_view(u->id) : default_owner;
    std::vector<bucket_info> all = m_store.buckets();
    if (u && !u->admin)
        std::erase_if(all, [me](const bucket_info& b) { return (b.owner.empty() ? default_owner : b.owner) != me; });
    response r;
    r.headers.emplace_back("Content-Type", "application/xml");
    r.body = list_buckets_xml(all, me, display_of(me), page);
    send_response(c, std::move(r));
}

void storage_run::op_create_bucket(const std::shared_ptr<conn>& c)
{
    std::weak_ptr<conn> weak = c;
    const std::string name = c->req.bucket;
    const bool lock = http_token_equals(c->req.header("x-amz-bucket-object-lock-enabled"), "true", 4);
    // The default owner is recorded as no owner at all, as every bucket made before there were users is.
    const std::string me = c->user ? c->user->id : std::string(default_owner);
    m_node.create_bucket(name, me == default_owner ? std::string() : me, [this, weak, name, lock, me](st s)
    {
        auto answer = [this, weak, name, me](st a)
        {
            auto cc = weak.lock();
            if (!cc || cc->dead)
                return;
            if (a == st::bucket_exists && owner_of(name) != me)
            {
                send_error(cc, make_error("BucketAlreadyExists"));
                return;
            }
            if (a != st::ok)
            {
                send_error_st(cc, a);
                return;
            }
            response r;
            // Path style names the bucket's path, as S3 in us-east-1 does, and virtual-hosted style its URL.
            r.headers.emplace_back("Location", cc->req.vhost ? object_url(cc->ssl != nullptr, cc->req.host, true, name, {})
                                                             : "/" + name);
            send_response(cc, std::move(r));
        };
        if (s != st::ok || !lock)
        {
            answer(s);
            return;
        }
        // Versioning first, since object lock is refused on a bucket without it, and a bucket left without the
        // lock it was asked for is not left at all.
        m_node.set_doc(bucket_doc::versioning, name, versioning_xml(versioning::enabled), [this, name, answer](st v)
        {
            auto locked = [this, name, answer](st l)
            {
                if (l == st::ok)
                {
                    answer(st::ok);
                    return;
                }
                m_node.delete_bucket(name, [answer, l](st) { answer(l); });
            };
            if (v != st::ok)
            {
                locked(v);
                return;
            }
            m_node.set_doc(bucket_doc::object_lock, name, lock_config_xml(lock_config{}), std::move(locked));
        });
    });
}

void storage_run::op_delete_bucket(const std::shared_ptr<conn>& c)
{
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

// ─── ACLs and ownership controls ────────────────────────────────────────────

bool storage_run::acl_headers_ok(const s3_request& r, bool bucket, std::string_view owner, s3_error& err) const
{
    if (r.method != "PUT" && r.method != "POST")
        return true;
    const std::string grant = "id=\"" + std::string(owner) + "\"";
    bool ok = true;
    for (const auto& h : r.headers)
    {
        // The two canned ACLs that give the owner full control and nobody else anything, which every object has.
        if (h.name == "x-amz-acl")
            ok = ok && (h.value == "private" || h.value == "bucket-owner-full-control");
        else if (h.name == "x-amz-grant-full-control")
            ok = ok && http_trim_ows(h.value) == grant;
        else if (h.name.starts_with("x-amz-grant-"))
            ok = false;
    }
    if (!ok)
        err = make_error(bucket && r.method == "PUT" ? "InvalidBucketAclWithObjectOwnership" : "AccessControlListNotSupported");
    return ok;
}

bool storage_run::storage_class_ok(const s3_request& r, s3_error& err)
{
    if (r.method != "PUT" && r.method != "POST")
        return true;
    for (const auto& h : r.headers)
    {
        // Every class S3 has is stored as STANDARD, the one this storage has, which keeps at least what was asked.
        if (h.name == "x-amz-storage-class")
        {
            static constexpr std::string_view classes[] = {
                "STANDARD", "REDUCED_REDUNDANCY", "STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER",
                "DEEP_ARCHIVE", "OUTPOSTS", "GLACIER_IR", "SNOW", "EXPRESS_ONEZONE",
            };
            if (std::find(std::begin(classes), std::end(classes), h.value) == std::end(classes))
            {
                err = make_error("InvalidStorageClass");
                return false;
            }
        }
    }
    return true;
}

void storage_run::op_get_acl(const std::shared_ptr<conn>& c)
{
    const s3_request& r = c->req;
    if (!m_store.has_bucket(r.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    auto answer = [this](const std::shared_ptr<conn>& cc, st s)
    {
        if (s != st::ok)
        {
            send_error_st(cc, s == st::delete_marker ? st::no_such_key : s);
            return;
        }
        response resp;
        resp.headers.emplace_back("Content-Type", "application/xml");
        const std::string_view owner = owner_of(cc->req.bucket);
        resp.body = owner_acl_xml(owner, display_of(owner));
        send_response(cc, std::move(resp));
    };
    if (r.key.empty())
    {
        answer(c, st::ok);
        return;
    }
    // The object must be there, as S3 answers NoSuchKey for one that is not.
    std::weak_ptr<conn> weak = c;
    auto then = [weak, answer](st s, const object_meta& m)
    {
        if (auto cc = weak.lock(); cc && !cc->dead)
            answer(cc, s == st::ok && is_delete_marker(m) ? st::no_such_key : s);
    };
    if (const std::string version(r.get_query("versionId")); !version.empty())
        m_store.stat_version(r.bucket, r.key, version, std::move(then));
    else if (m_store.owns(r.bucket, r.key))
        answer(c, m_store.find(r.bucket, r.key) ? st::ok : st::no_such_key);
    else
        m_store.stat_foreign(r.bucket, r.key, std::move(then));
}

void storage_run::op_put_acl(const std::shared_ptr<conn>& c)
{
    const s3_request& r = c->req;
    if (!m_store.has_bucket(r.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    // An ACL is taken when it is the one the object has: by canned name or grant header, or as a document whose
    // every grant is FULL_CONTROL to the owner.
    s3_error err;
    const std::string_view owner = owner_of(r.bucket);
    bool ok = acl_headers_ok(r, false, owner, err);
    if (ok && !c->body.empty())
    {
        xml_node root;
        xml_reader reader(c->body);
        if (!reader.document(root) || root.name != "AccessControlPolicy")
        {
            send_error(c, make_error("MalformedXML"));
            return;
        }
        size_t grants = 0;
        for (const xml_node& list : root.kids)
            if (list.name == "AccessControlList")
                for (const xml_node& g : list.kids)
                {
                    std::string id, permission;
                    bool other = false;
                    for (const xml_node& f : g.kids)
                    {
                        if (f.name == "Permission")
                            permission = f.text;
                        else if (f.name == "Grantee")
                        {
                            for (const xml_node& who : f.kids)
                            {
                                if (who.name == "ID")
                                    id = who.text;
                                else if (who.name != "DisplayName")
                                    other = true;
                            }
                        }
                    }
                    ++grants;
                    ok = ok && !other && id == owner && permission == "FULL_CONTROL";
                }
        ok = ok && grants > 0;
    }
    if (!ok)
    {
        send_error(c, make_error("AccessControlListNotSupported"));
        return;
    }
    auto done = [this](const std::shared_ptr<conn>& cc, st s)
    {
        if (s != st::ok)
        {
            send_error_st(cc, s == st::delete_marker ? st::no_such_key : s);
            return;
        }
        send_response(cc, response{});
    };
    if (r.key.empty())
    {
        done(c, st::ok);
        return;
    }
    std::weak_ptr<conn> weak = c;
    auto then = [weak, done](st s, const object_meta& m)
    {
        if (auto cc = weak.lock(); cc && !cc->dead)
            done(cc, s == st::ok && is_delete_marker(m) ? st::no_such_key : s);
    };
    if (m_store.owns(r.bucket, r.key))
        done(c, m_store.find(r.bucket, r.key) ? st::ok : st::no_such_key);
    else
        m_store.stat_foreign(r.bucket, r.key, std::move(then));
}

void storage_run::op_ownership_controls(const std::shared_ptr<conn>& c)
{
    const s3_request& r = c->req;
    if (!m_store.has_bucket(r.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    if (r.method == "GET")
    {
        response resp;
        resp.headers.emplace_back("Content-Type", "application/xml");
        resp.body = ownership_controls_xml();
        send_response(c, std::move(resp));
        return;
    }
    // Every bucket is BucketOwnerEnforced, which may be set again, and an owner other than the bucket's is not had.
    xml_node root;
    xml_reader reader(c->body);
    if (!reader.document(root) || root.name != "OwnershipControls")
    {
        send_error(c, make_error("MalformedXML"));
        return;
    }
    bool enforced = false, other = false;
    for (const xml_node& rule : root.kids)
        for (const xml_node& f : rule.kids)
            if (f.name == "ObjectOwnership")
                (f.text == "BucketOwnerEnforced" ? enforced : other) = true;
    if (!enforced || other)
    {
        send_error(c, make_error("NotImplemented"));
        return;
    }
    send_response(c, response{});
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
    lr.owner_id   = std::string(owner_of(q.bucket));
    lr.owner_name = display_of(lr.owner_id);

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
        if (!res.version_id.empty() && !policy_allows_version_delete(c, res.key))
        {
            res.ok    = false;
            res.error = make_error("AccessDenied");
            done_one(b);
            continue;
        }
        ++m_c.deletes;
        const bool bypass = !res.version_id.empty() && bypass_allowed(c, res.key);
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
        }, bypass, origin_of(*c));
    }
}

// ─── Objects: metadata from headers ─────────────────────────────────────────

bool storage_run::object_meta_from_headers(const std::shared_ptr<conn>& c, object_meta& m, s3_error& err)
{
    const s3_request& q = c->req;
    m = object_meta{};
    m.content_type = q.header("content-type");
    if (m.content_type.empty())
        m.content_type = "binary/octet-stream";

    static constexpr std::string_view kept[] = {
        "cache-control", "content-disposition", "content-encoding", "content-language", "expires",
        "x-amz-website-redirect-location",
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
    if (!object_meta_from_headers(c, meta, err) || !tagging_from_header(r, meta, err) ||
        (m_store.has_bucket(r.bucket) && !lock_from_headers(c, meta, err)))
    {
        deny_request(c, err);
        return;
    }

    // S3's conditional write.  A key another shard owns is not known here, so its
    // owner decides at commit, which is also where two racing writers are told apart.
    const put_condition cond{std::string(r.header("if-match")), std::string(r.header("if-none-match"))};
    if (cond.any() && m_store.owns(r.bucket, r.key))
        if (const st cs = check_put_condition(cond, m_store.find(r.bucket, r.key)); cs != st::ok)
        {
            deny_request(c, cs == st::no_such_key ? make_error("NoSuchKey") : make_error("PreconditionFailed"));
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
    replication_mark(r.bucket, r.key, meta, ask.mode == sse_mode::c, replica_request(r));
    replica_source(r, meta);
    start_put(c, r.key, std::move(meta), {}, checksum_algo::none, cond, {},
              ask.mode != sse_mode::none ? &seal : nullptr);
}

bool storage_run::body_length(const conn& c, uint64_t& expected)
{
    expected   = c.req.content_length;
    bool known = c.req.has_content_length && !c.req.chunked && (!c.hook || c.hook->length_from_body());
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
                            put_op::committer committer, checksum_algo forced_algo, const put_condition& cond,
                            const part_place& place, const sse_seal_spec* seal)
{
    s3_request& r = c->req;

    // The digest the client promises, checked when the body is in.
    if (const std::string_view md5h = r.header("content-md5"); r.has_header("content-md5"))
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
    // An object sent without a checksum is given S3's default, and a part of an upload with no algorithm keeps the
    // CRC its completion gives the object that default from.
    const bool part_crc = committer && forced_algo == checksum_algo::none;
    if (!committer && ck.algo == checksum_algo::none)
        ck.algo = default_checksum_algo;
    // A placeholder of the value's length, so the header reserves room for it.
    if (ck.algo != checksum_algo::none)
        reserve_checksum(meta, ck.algo);
    if (part_crc)
        meta.extra.emplace_back(std::string(part_crc_extra), std::string(checksum_b64_len(checksum_algo::crc64nvme), 'A'));

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
    auto op = m_store.begin_put(r.bucket, key, std::move(meta), expected, known, why, !committer && !cond.any(), seal);
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
    op->set_cause(r.form ? change_cause::post : change_cause::put);
    op->set_origin(origin_of(*c));
    if (ck.algo != checksum_algo::none)
    {
        op->track_checksum(ck.algo, std::move(ck.expected_b64));
        c->ck_trailer = std::move(ck.trailer_name);
    }
    if (part_crc)
        op->track_part_crc();
    if (committer)
        op->set_committer(std::move(committer));
    op->set_condition(cond);
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
    // The copy's checksum is of its own bytes, in the algorithm the request names or else its source's, as in S3.
    checksum_algo algo = checksum_algo::none;
    if (s3_error err; !sse_for_write(c, r.bucket, dst, err) || !sse_customer(c, sse_c_copy_prefix, src_customer, err) ||
                      !checksum_algorithm_header(r, algo, err))
    {
        send_error(c, err);
        return;
    }
    // A copy that names an algorithm says what it changes, as a copy of an object onto itself to take a checksum does.
    const bool names_checksum = algo != checksum_algo::none;
    if (algo == checksum_algo::none)
        algo = checksum_algo_of(src);
    if (algo == checksum_algo::none)
        algo = default_checksum_algo;
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
    // copy that names the encryption or the checksum algorithm it changes to.
    if (src_bucket == r.bucket && src_key == r.key && !replace && src_version.empty() && !dst.named && !names_checksum)
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
    // A copy is a new version, whose lock is what this request or the bucket's default gives it and never its source's.
    if (s3_error err; !lock_from_headers(c, meta, err))
    {
        send_error(c, err);
        return;
    }
    // And whose replication is its own bucket's.
    replication_mark(r.bucket, r.key, meta, dst.mode == sse_mode::c, false);

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
                    std::move(src_customer), source_id, algo);
        return;
    }
    m_store.copy(src_bucket, src_key, std::move(src_version), r.bucket, r.key, std::move(meta), algo,
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
    }, origin_of(*c));
}

// ─── DeleteObject ───────────────────────────────────────────────────────────

void storage_run::op_delete_object(const std::shared_ptr<conn>& c)
{
    std::string version_id;
    if (!version_param(c, version_id))
        return;
    ++m_c.deletes;
    const bool bypass = !version_id.empty() && bypass_allowed(c, c->req.key);
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
    }, bypass, origin_of(*c));
}

// ─── GetObject, HeadObject ──────────────────────────────────────────────────

namespace
{

// Where a website sends a request for an object stored as a redirect, empty for an object served as itself.
std::string_view website_target(const object_meta& m)
{
    for (const auto& [name, value] : m.extra)
        if (name == "x-amz-website-redirect-location")
            return value;
    return {};
}

// The headers an object's stored metadata puts on a response, with the
// response-* query overrides a presigned URL may add; in a `versioned` bucket an
// object written before it was versioned is named as the null version, and `part`
// is the checksum of the part asked for by number, empty when it was not kept.
void object_headers(const s3_request& q, const object_meta& m, response& r, bool ranged, bool versioned,
                    const std::string* part = nullptr)
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

    // The checksum a client asked to see, of the part it asked for by number or else of the whole object,
    // which an answer holding only a range of it does not get.
    const bool with_checksum = http_token_equals(q.header("x-amz-checksum-mode"), "enabled", 7) &&
                               (part ? !part->empty() : !ranged);
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
        // A value the store would not have written is kept but never shown.
        if (is_checksum_header(n))
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
        if (retention ret; n == retention_extra && retention_from_value(v, ret))
        {
            r.headers.emplace_back("x-amz-object-lock-mode", std::string(lock_mode_name(ret.mode)));
            r.headers.emplace_back("x-amz-object-lock-retain-until-date", iso8601(ret.until_ms));
            continue;
        }
        if (n == legal_hold_extra)
        {
            r.headers.emplace_back("x-amz-object-lock-legal-hold", v);
            continue;
        }
        // What the store keeps for itself about the object's bytes is no header of the object.
        if (n.starts_with("x-socketley-"))
            continue;
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
    if (with_checksum && m.checksum)
    {
        r.headers.emplace_back(checksum_header(m.checksum.algo), part ? *part : m.checksum.b64());
        r.headers.emplace_back("x-amz-checksum-type", m.checksum.type());
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
    const int64_t mtime_s = m.mtime_ms / 1000;

    const std::string_view im = q.header("if-match");
    if (!im.empty())
    {
        if (!etag_list_matches(im, m.etag()))
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
        if (etag_list_matches(inm, m.etag()))
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

// What a GetObjectAttributes request asks for, from x-amz-object-attributes and the part paging headers.
struct attr_query
{
    bool     etag{false};
    bool     checksum{false};
    bool     parts{false};
    bool     storage_class{false};
    bool     size{false};
    uint32_t max_parts{1000};
    uint32_t marker{0};
};

// False with `bad` naming the header when the request is not one S3 would take.
bool parse_attr_query(const s3_request& q, attr_query& a, std::string_view& bad)
{
    std::string_view list = q.header("x-amz-object-attributes");
    bad = "x-amz-object-attributes";
    if (http_trim_ows(list).empty())
        return false;
    while (!list.empty())
    {
        const size_t comma = list.find(',');
        const std::string_view one = http_trim_ows(list.substr(0, comma));
        list = comma == std::string_view::npos ? std::string_view{} : list.substr(comma + 1);
        if (one == "ETag")
            a.etag = true;
        else if (one == "Checksum")
            a.checksum = true;
        else if (one == "ObjectParts")
            a.parts = true;
        else if (one == "StorageClass")
            a.storage_class = true;
        else if (one == "ObjectSize")
            a.size = true;
        else
            return false;
    }
    uint64_t v = 0;
    bad = "x-amz-max-parts";
    if (q.has_header("x-amz-max-parts"))
    {
        if (!parse_uint(q.header("x-amz-max-parts"), v))
            return false;
        a.max_parts = static_cast<uint32_t>(std::min<uint64_t>(v, 1000));
    }
    bad = "x-amz-part-number-marker";
    if (q.has_header("x-amz-part-number-marker"))
    {
        if (!parse_uint(q.header("x-amz-part-number-marker"), v) || v > mpu_max_parts)
            return false;
        a.marker = static_cast<uint32_t>(v);
    }
    return true;
}

// The element a stored checksum is named by in a GetObjectAttributes answer, empty for none.
std::string_view checksum_attribute(checksum_algo a)
{
    switch (a)
    {
        case checksum_algo::crc32:     return "ChecksumCRC32";
        case checksum_algo::crc32c:    return "ChecksumCRC32C";
        case checksum_algo::crc64nvme: return "ChecksumCRC64NVME";
        case checksum_algo::sha1:      return "ChecksumSHA1";
        case checksum_algo::sha256:    return "ChecksumSHA256";
        case checksum_algo::none:      break;
    }
    return {};
}

// The answer to GetObjectAttributes; `l` is the object's part list, or null for a single-part object.
std::string attributes_xml(const object_meta& m, const attr_query& a, const part_list* l)
{
    std::string x(xml_decl);
    x += "<GetObjectAttributesResponse xmlns=\"";
    x += s3_xmlns;
    x += "\">";
    if (a.etag)
        x += "<ETag>" + m.etag() + "</ETag>";
    // A multipart object's checksum is of its parts' checksums, which the -N says.
    if (const std::string_view el = checksum_attribute(m.checksum.algo); a.checksum && !el.empty())
        x += "<Checksum><" + std::string(el) + ">" + xml_escape(m.checksum.b64()) + "</" + std::string(el) +
             "><ChecksumType>" + std::string(m.checksum.type()) + "</ChecksumType></Checksum>";
    if (a.parts && l)
    {
        const checksum_algo algo = checksum_algo_of(m);
        x += "<ObjectParts><PartsCount>" + std::to_string(l->numbers.size()) + "</PartsCount>";
        x += "<PartNumberMarker>" + std::to_string(a.marker) + "</PartNumberMarker>";
        x += "<MaxParts>" + std::to_string(a.max_parts) + "</MaxParts>";
        std::string rows;
        uint32_t shown = 0, last = a.marker;
        bool truncated = false;
        for (size_t i = 0; i < l->numbers.size(); ++i)
        {
            if (l->numbers[i] <= a.marker)
                continue;
            if (shown == a.max_parts)
            {
                truncated = true;
                break;
            }
            ++shown;
            last = l->numbers[i];
            rows += "<Part><PartNumber>" + std::to_string(l->numbers[i]) + "</PartNumber><Size>" +
                    std::to_string(l->sizes[i]) + "</Size>" +
                    (i < l->checksums.size() ? checksum_element(algo, base64_encode(l->checksums[i])) : std::string{}) +
                    "</Part>";
        }
        x += truncated ? "<IsTruncated>true</IsTruncated>" : "<IsTruncated>false</IsTruncated>";
        if (truncated)
            x += "<NextPartNumberMarker>" + std::to_string(last) + "</NextPartNumberMarker>";
        x += rows + "</ObjectParts>";
    }
    if (a.storage_class)
        x += "<StorageClass>STANDARD</StorageClass>";
    if (a.size)
        x += "<ObjectSize>" + std::to_string(m.size) + "</ObjectSize>";
    x += "</GetObjectAttributesResponse>";
    return x;
}

}   // namespace

void storage_run::expiration_header(std::string_view bucket, std::string_view key, const object_meta& m,
                                    std::vector<std::pair<std::string, std::string>>& headers) const
{
    const auto cfg = m_store.lifecycle(bucket);
    int64_t at = 0;
    const lifecycle_rule* rule = nullptr;
    if (cfg && !is_delete_marker(m) && lifecycle_expiry(*cfg, key, m, m_lc_day_ms, at, rule))
        headers.emplace_back("x-amz-expiration", "expiry-date=\"" + http_date(at) + "\", rule-id=\"" + rule->id + "\"");
}

void storage_run::read_part_list(const std::shared_ptr<conn>& c, const object_meta& m, int fd, uint64_t data_off,
                                 bool head,
                                 std::function<void(const object_meta&, int, uint64_t, bool, const part_list&)> then)
{
    std::weak_ptr<conn> weak = c;
    // Reads the list from an open file, whose own header `fm` is what the answer is then given about.
    auto read = [this, weak, then](object_meta fm, int rfd, uint64_t off, bool keep_fd)
    {
        part_trailer t;
        if (!part_trailer_of(fm, t))
        {
            m_loop.close_fd(rfd);
            if (auto cc = weak.lock(); cc && !cc->dead)
                send_error(cc, make_error("InternalError"));
            return;
        }
        auto buf = std::make_shared<std::string>(static_cast<size_t>(t.len), '\0');
        auto meta = std::make_shared<object_meta>(std::move(fm));
        const bool q = m_io.pread(rfd, buf->data(), static_cast<uint32_t>(buf->size()), off + t.at,
            [this, weak, then, buf, meta, rfd, off, keep_fd, t](int64_t res)
            {
                auto cc = weak.lock();
                part_list l;
                const bool ok = res == static_cast<int64_t>(buf->size()) && decode_part_trailer(*buf, *meta, t, l);
                if (!keep_fd || !ok || !cc || cc->dead)
                    m_loop.close_fd(rfd);
                if (!cc || cc->dead)
                    return;
                if (!ok)
                {
                    LOG_WARN(("storage: the part list after the body of \"" + cc->req.key + "\" cannot be read").c_str());
                    send_error(cc, make_error("InternalError"));
                    return;
                }
                then(*meta, keep_fd ? rfd : -1, keep_fd ? off : 0, !keep_fd, l);
            });
        if (!q)
        {
            m_loop.close_fd(rfd);
            if (auto cc = weak.lock(); cc && !cc->dead)
                send_error(cc, make_error("InternalError"));
        }
    };
    if (fd >= 0)
    {
        read(m, fd, data_off, true);
        return;
    }
    // A HEAD has no file open, so the object's is opened for the list and closed again.
    auto opened = [this, weak, read, head](open_result o)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead || o.status != st::ok)
        {
            if (o.fd >= 0)
                m_loop.close_fd(o.fd);
            if (cc && !cc->dead)
                send_error_st(cc, o.status == st::ok ? st::io_error : o.status);
            return;
        }
        read(std::move(o.meta), o.fd, o.data_off, !head);
    };
    const std::string version(c->req.get_query("versionId"));
    if (version.empty())
        m_store.open_object(c->req.bucket, c->req.key, 0, std::move(opened));
    else
        m_store.open_version(c->req.bucket, c->req.key, version, 0, std::move(opened));
}

void storage_run::op_get_object(const std::shared_ptr<conn>& c, bool head, bool attributes)
{
    s3_request& q = c->req;
    if (head)
        ++m_c.heads;
    else
        ++m_c.gets;

    attr_query attrs;
    if (std::string_view bad; attributes && !parse_attr_query(q, attrs, bad))
    {
        s3_error e = make_error("InvalidArgument");
        e.message = "Invalid attribute name specified.";
        send_error(c, e, false, "ArgumentName", bad);
        return;
    }

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
    // already in hand are the object's own rather than what its file holds, and `list` is a part list read
    // after the body, for a partNumber the header alone cannot place.
    // Takes itself as `self` to be given again once a part list is read, so a read that needs none allocates nothing for it.
    const auto again = [this, head, part, attributes, attrs](
                 const auto& self, const std::shared_ptr<conn>& cc, const object_meta& m, int fd, uint64_t data_off,
                 const std::string& prefetch, bool clear, const part_list* list) -> void
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
        // A website's object can stand for a redirect, and its error document is answered with the failure's status.
        if (rq.website)
        {
            if (const std::string_view to = website_target(m); !to.empty() && !cc->website_status)
            {
                close_file();
                website_redirect_to(cc, 301, std::string(to));
                return;
            }
        }
        const cond cd = cc->website_status ? cond::proceed : evaluate(rq, m);
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

        if (attributes)
        {
            // A multipart object's parts are listed from its header, or from after its body once that is read.
            part_list own;
            const part_list* parts = list;
            if (attrs.parts && m.parts && !parts)
            {
                part_trailer t;
                if (part_trailer_of(m, t))
                {
                    read_part_list(cc, m, fd, data_off, true,
                        [weak = std::weak_ptr<conn>(cc), self](
                            const object_meta& m2, int fd2, uint64_t off2, bool clear2, const part_list& l)
                        {
                            if (auto c2 = weak.lock())
                                self(self, c2, m2, fd2, off2, {}, clear2, &l);
                        });
                    return;
                }
                if (part_list_of(m, own))
                    parts = &own;
            }
            close_file();
            r.headers.emplace_back("Content-Type", "application/xml");
            r.headers.emplace_back("Last-Modified", http_date(m.mtime_ms));
            if (has_version(m))
                r.headers.emplace_back("x-amz-version-id", version_of(m).id);
            else if (m_store.bucket_versioning(rq.bucket) != versioning::off)
                r.headers.emplace_back("x-amz-version-id", "null");
            r.body = attributes_xml(m, attrs, m.parts ? parts : nullptr);
            send_response(cc, std::move(r));
            return;
        }

        uint64_t first = 0, len = m.size;
        bool ranged = false;
        std::string part_checksum;
        if (part)
        {
            part_list own;
            const part_status ps = list ? part_range_in(*list, part, first, len) : part_range(m, part, first, len, &own);
            if (const part_list& pl = list ? *list : own; ps == part_status::ok && part <= pl.checksums.size())
                part_checksum = base64_encode(pl.checksums[part - 1]);
            if (ps == part_status::in_trailer)
            {
                // The answer is given again once the list is read, from the file whose list it is.
                read_part_list(cc, m, fd, data_off, head,
                    [weak = std::weak_ptr<conn>(cc), self](
                        const object_meta& m2, int fd2, uint64_t off2, bool clear2, const part_list& l)
                    {
                        if (auto c2 = weak.lock())
                            self(self, c2, m2, fd2, off2, {}, clear2, &l);
                    });
                return;
            }
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
        else if (const std::string_view rh = rq.header("range"); !rh.empty() && !cc->website_status)
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

        object_headers(rq, m, r, ranged, m_store.bucket_versioning(rq.bucket) != versioning::off,
                       part ? &part_checksum : nullptr);
        if (!rq.has_query("versionId"))
            expiration_header(rq.bucket, rq.key, m, r.headers);
        if (cc->website_status)
            r.status = cc->website_status;
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
            // An empty object is opened too, since the chunk that ends its stream is what says it is empty.
            if ((len > 0 || m.size == 0) && prefetch.size() >= stored_size(m))
            {
                close_file();
                if (!sse_open_body(m, key, prefetch, plain))
                {
                    LOG_WARN(("storage: the encrypted object \"" + rq.key + "\" does not open: a chunk is missing, "
                              "cut short or moved").c_str());
                    send_error(cc, make_error("InternalError"));
                    return;
                }
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
    auto answer = [again](const std::shared_ptr<conn>& cc, const object_meta& m, int fd, uint64_t data_off,
                          const std::string& prefetch, bool clear)
    { again(again, cc, m, fd, data_off, prefetch, clear, nullptr); };

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
        // A GET that asks for nothing but the object gets the headers kept with the copy, which do not follow the
        // bucket's lifecycle rules.
        if (q.query.empty() && q.header("range").empty() && q.header("x-amz-checksum-mode").empty() &&
            !m_store.lifecycle(q.bucket) && (!q.website || (!c->website_status && website_target(*hot.meta).empty())) &&
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
