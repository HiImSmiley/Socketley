// Bucket versioning over S3: the configuration's two operations, ListObjectVersions,
// and the answers a request gets that names a version or meets a delete marker.
//
// The configuration is a bucket document like CORS and lifecycle, written by shard 0
// and taken up by every shard before the answer, so each owner decides what its next
// write of a key is from its own copy.
#include "storage_run.h"

#include <charconv>

#include "s3_versioning.h"
#include "s3_xml.h"

namespace socketley::storage
{

namespace
{

struct versions_render
{
    std::string_view bucket;
    std::string_view prefix;
    std::string_view delimiter;
    std::string_view key_marker;
    std::string_view version_marker;
    size_t           max_keys{1000};
    bool             url_encode{false};
    std::string      owner_id;
    std::string      owner_name;
};

void text(std::string& x, const versions_render& r, std::string_view s)
{
    if (r.url_encode)
        url_encode_to(x, s);
    else
        xml_escape_to(x, s);
}

void element(std::string& x, const versions_render& r, std::string_view name, std::string_view value)
{
    x += '<';
    x += name;
    x += '>';
    text(x, r, value);
    x += "</";
    x += name;
    x += '>';
}

std::string versions_xml(const versions_render& r, const version_page& p)
{
    std::string x(xml_decl);
    x += "<ListVersionsResult xmlns=\"";
    x += s3_xmlns;
    x += "\"><Name>";
    xml_escape_to(x, r.bucket);
    x += "</Name>";
    element(x, r, "Prefix", r.prefix);
    element(x, r, "KeyMarker", r.key_marker);
    x += "<VersionIdMarker>";
    xml_escape_to(x, r.version_marker);
    x += "</VersionIdMarker>";
    // What the page returned last, which the next request names to begin after it.
    if (p.truncated && !p.items.empty())
    {
        const version_item& last = p.items.back();
        element(x, r, "NextKeyMarker", last.key);
        if (!last.prefix)
        {
            x += "<NextVersionIdMarker>";
            xml_escape_to(x, version_of(last.meta).id);
            x += "</NextVersionIdMarker>";
        }
    }
    x += "<MaxKeys>";
    append_number(x, r.max_keys);
    x += "</MaxKeys>";
    if (!r.delimiter.empty())
        element(x, r, "Delimiter", r.delimiter);
    if (r.url_encode)
        x += "<EncodingType>url</EncodingType>";
    x += p.truncated ? "<IsTruncated>true</IsTruncated>" : "<IsTruncated>false</IsTruncated>";
    for (const version_item& it : p.items)
    {
        if (it.prefix)
        {
            x += "<CommonPrefixes>";
            element(x, r, "Prefix", it.key);
            x += "</CommonPrefixes>";
            continue;
        }
        const bool marker = is_delete_marker(it.meta);
        x += marker ? "<DeleteMarker>" : "<Version>";
        element(x, r, "Key", it.key);
        x += "<VersionId>";
        xml_escape_to(x, version_of(it.meta).id);
        x += "</VersionId>";
        x += it.latest ? "<IsLatest>true</IsLatest>" : "<IsLatest>false</IsLatest>";
        x += "<LastModified>";
        x += iso8601(it.meta.mtime_ms);
        x += "</LastModified>";
        if (!marker)
        {
            x += "<ETag>";
            x += quoted_etag(it.meta);
            x += "</ETag><Size>";
            append_number(x, it.meta.size);
            x += "</Size><StorageClass>STANDARD</StorageClass>";
        }
        x += "<Owner><ID>";
        xml_escape_to(x, r.owner_id);
        x += "</ID><DisplayName>";
        xml_escape_to(x, r.owner_name);
        x += "</DisplayName></Owner>";
        x += marker ? "</DeleteMarker>" : "</Version>";
    }
    x += "</ListVersionsResult>";
    return x;
}

}   // namespace

bool storage_run::version_param(const std::shared_ptr<conn>& c, std::string& out)
{
    out.clear();
    if (!c->req.has_query("versionId"))
        return true;
    const std::string_view v = c->req.get_query("versionId");
    if (!valid_version_id(v))
    {
        s3_error e = make_error("InvalidArgument");
        e.message = "Invalid version id specified";
        send_error(c, e, false, "ArgumentName", "versionId");
        return false;
    }
    out = std::string(v);
    return true;
}

void storage_run::send_delete_marker(const std::shared_ptr<conn>& c, const object_meta& m, bool by_version)
{
    // A website has no versions to tell of, and a deleted key is one it does not have.
    if (c->req.website)
    {
        send_error(c, make_error("NoSuchKey"));
        return;
    }
    const s3_error err = make_error(by_version ? "MethodNotAllowed" : "NoSuchKey");
    count_error(err.code);
    response r;
    r.status = err.status;
    r.headers.emplace_back("Content-Type", "application/xml");
    r.headers.emplace_back("x-amz-delete-marker", "true");
    r.headers.emplace_back("x-amz-version-id", version_of(m).id);
    if (by_version)
    {
        r.headers.emplace_back("Last-Modified", http_date(m.mtime_ms));
        r.headers.emplace_back("Allow", "DELETE");
    }
    if (c->req.method == "HEAD")
    {
        r.head_only           = true;
        r.has_length_override = true;
        r.length_override     = 0;
    }
    else
    {
        std::string resource = "/" + c->req.bucket + "/" + c->req.key;
        error_context ctx;
        ctx.bucket     = c->req.bucket;
        ctx.key        = c->req.key;
        ctx.resource   = resource;
        ctx.request_id = c->req.request_id;
        r.body = error_xml(err, ctx);
    }
    send_response(c, std::move(r));
}

void storage_run::op_get_versioning(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    response r;
    r.headers.emplace_back("Content-Type", "application/xml");
    r.body = versioning_xml(m_store.bucket_versioning(c->req.bucket));
    send_response(c, std::move(r));
}

void storage_run::op_put_versioning(const std::shared_ptr<conn>& c)
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
    if (q.has_header("x-amz-mfa"))
    {
        err = make_error("NotImplemented");
        err.message = "MFA delete is not supported";
        send_error(c, err);
        return;
    }
    versioning v = versioning::off;
    if (!parse_versioning(c->body, v, err))
    {
        send_error(c, err);
        return;
    }
    // Replication copies versions, so a bucket that replicates keeps them.
    if (v != versioning::enabled && m_store.bucket_replication(q.bucket))
    {
        err = make_error("InvalidBucketState");
        err.message = "A replication configuration is present on this bucket, so the versioning state cannot be changed.";
        send_error(c, err);
        return;
    }
    std::weak_ptr<conn> weak = c;
    m_node.set_doc(bucket_doc::versioning, q.bucket, versioning_xml(v), [this, weak](st s)
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

void storage_run::op_list_versions(const std::shared_ptr<conn>& c)
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

    version_query vq;
    vq.prefix         = std::string(q.get_query("prefix"));
    vq.delimiter      = std::string(q.get_query("delimiter"));
    vq.key_marker     = std::string(q.get_query("key-marker"));
    vq.version_marker = std::string(q.get_query("version-id-marker"));
    if (q.has_query("max-keys"))
    {
        const std::string_view mk = q.get_query("max-keys");
        uint64_t v = 0;
        const auto r = std::from_chars(mk.data(), mk.data() + mk.size(), v);
        if (mk.empty() || r.ec != std::errc{} || r.ptr != mk.data() + mk.size())
        {
            bad_arg("maxKeys", "Provided max-keys not an integer or within integer range");
            return;
        }
        vq.max_keys = static_cast<size_t>(std::min<uint64_t>(v, 1000));
    }
    if (!vq.version_marker.empty() && vq.key_marker.empty())
    {
        bad_arg("version-id-marker", "A version-id marker cannot be specified without a key marker.");
        return;
    }
    if (!vq.version_marker.empty() && !valid_version_id(vq.version_marker))
    {
        bad_arg("version-id-marker", "Invalid version id specified");
        return;
    }
    bool url = false;
    if (q.has_query("encoding-type"))
    {
        if (q.get_query("encoding-type") != "url")
        {
            bad_arg("encoding-type", "Invalid Encoding Method specified in Request");
            return;
        }
        url = true;
    }

    versions_render vr;
    vr.bucket         = q.bucket;
    vr.prefix         = q.get_query("prefix");
    vr.delimiter      = q.get_query("delimiter");
    vr.key_marker     = q.get_query("key-marker");
    vr.version_marker = q.get_query("version-id-marker");
    vr.max_keys       = vq.max_keys;
    vr.url_encode     = url;
    vr.owner_id       = std::string(owner_of(q.bucket));
    vr.owner_name     = display_of(vr.owner_id);
    // The views are into the request, which the connection keeps for as long as it waits.
    std::weak_ptr<conn> weak = c;
    m_node.list_versions(q.bucket, vq, [this, weak, vr](st s, version_page page)
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
        r.body = versions_xml(vr, page);
        send_response(cc, std::move(r));
    });
}

}   // namespace socketley::storage
