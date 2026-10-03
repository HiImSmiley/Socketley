#pragma once
// The XML S3 speaks: errors, listings and the batch-delete exchange, with
// element names and the namespace exactly as S3 writes them.
#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

#include "object_format.h"
#include "object_store.h"
#include "s3_auth.h"
#include "s3_names.h"

namespace socketley::storage
{

inline constexpr std::string_view s3_xmlns = "http://s3.amazonaws.com/doc/2006-03-01/";
inline constexpr std::string_view xml_decl = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

// Whether xml_escape keeps a byte: the ones that would end an element and the
// control characters an XML 1.0 document may not carry at all are changed.
inline bool xml_plain(unsigned char c)
{
    static constexpr auto table = []
    {
        std::array<bool, 256> t{};
        for (int i = 0; i < 256; ++i)
            t[static_cast<size_t>(i)] = !(i == '&' || i == '<' || i == '>' || i == '"' || i == '\'' ||
                                          (i < 0x20 && i != '\t' && i != '\n' && i != '\r'));
        return t;
    }();
    return table[c];
}

// Appended to `out` without a temporary, the bytes it keeps copied in runs.
inline void xml_escape_to(std::string& out, std::string_view in)
{
    size_t run = 0;
    for (size_t i = 0; i < in.size(); ++i)
    {
        const unsigned char c = static_cast<unsigned char>(in[i]);
        if (xml_plain(c))
            continue;
        out.append(in, run, i - run);
        run = i + 1;
        switch (c)
        {
            case '&':  out += "&amp;"; break;
            case '<':  out += "&lt;"; break;
            case '>':  out += "&gt;"; break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default:
            {
                // Not representable in the document; a numeric reference is
                // what S3 sends for these, and clients that decode it get the byte.
                char buf[12];
                std::snprintf(buf, sizeof buf, "&#x%X;", c);
                out += buf;
            }
        }
    }
    out.append(in, run, in.size() - run);
}

inline std::string xml_escape(std::string_view in)
{
    std::string out;
    out.reserve(in.size());
    xml_escape_to(out, in);
    return out;
}

// The catalogue: the status and the standard message of each code the runtime
// answers with.
inline s3_error make_error(std::string_view code)
{
    struct row { std::string_view code; int status; std::string_view message; };
    static constexpr row table[] = {
        {"NoSuchBucket", 404, "The specified bucket does not exist"},
        {"NoSuchKey", 404, "The specified key does not exist."},
        {"NoSuchVersion", 404, "The specified version does not exist."},
        {"NoSuchLifecycleConfiguration", 404, "The lifecycle configuration does not exist"},
        {"NoSuchUpload", 404, "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed."},
        {"BucketAlreadyOwnedByYou", 409, "Your previous request to create the named bucket succeeded and you already own it."},
        {"BucketAlreadyExists", 409, "The requested bucket name is not available. The bucket namespace is shared by all users of the system. Please select a different name and try again."},
        {"BucketNotEmpty", 409, "The bucket you tried to delete is not empty"},
        {"OperationAborted", 409, "A conflicting conditional operation is currently in progress against this resource. Please try again."},
        {"InvalidBucketName", 400, "The specified bucket is not valid."},
        {"InvalidRange", 416, "The requested range is not satisfiable"},
        {"InvalidPartNumber", 416, "The requested partnumber is not satisfiable"},
        {"InvalidArgument", 400, "Invalid Argument"},
        {"InvalidRequest", 400, "Invalid Request"},
        {"InvalidDigest", 400, "The Content-MD5 you specified is not valid."},
        {"BadDigest", 400, "The Content-MD5 or checksum value that you specified did not match what we received."},
        {"EntityTooLarge", 400, "Your proposed upload exceeds the maximum allowed size"},
        {"EntityTooSmall", 400, "Your proposed upload is smaller than the minimum allowed object size."},
        {"InvalidPart", 400, "One or more of the specified parts could not be found.  The part may not have been uploaded, or the specified entity tag may not match the part's entity tag."},
        {"InvalidPartOrder", 400, "The list of parts was not in ascending order. The parts list must be specified in order by part number."},
        {"KeyTooLongError", 400, "Your key is too long"},
        {"MetadataTooLarge", 400, "Your metadata headers exceed the maximum allowed metadata size."},
        {"MalformedXML", 400, "The XML you provided was not well-formed or did not validate against our published schema."},
        {"MissingContentLength", 411, "You must provide the Content-Length HTTP header."},
        {"IncompleteBody", 400, "You did not provide the number of bytes specified by the Content-Length HTTP header."},
        {"PreconditionFailed", 412, "At least one of the pre-conditions you specified did not hold"},
        {"MethodNotAllowed", 405, "The specified method is not allowed against this resource."},
        {"NotImplemented", 501, "A header you provided implies functionality that is not implemented"},
        {"AccessControlListNotSupported", 400, "The bucket does not allow ACLs"},
        {"InvalidStorageClass", 400, "The storage class you specified is not valid"},
        {"MalformedPOSTRequest", 400, "The body of your POST request is not well-formed multipart/form-data."},
        {"MaxPostPreDataLengthExceeded", 400, "Your POST request fields preceding the upload file were too large."},
        {"IncorrectNumberOfFilesInPostRequest", 400, "POST requires exactly one file upload per request."},
        {"InvalidPolicyDocument", 400, "The content of the form does not meet the conditions specified in the policy document."},
        {"InvalidBucketAclWithObjectOwnership", 400, "Bucket cannot have ACLs set with ObjectOwnership's BucketOwnerEnforced setting"},
        {"AccessDenied", 403, "Access Denied"},
        {"AccessForbidden", 403, "CORSResponse: This CORS request is not allowed. This is usually because the evalution of Origin, request method / Access-Control-Request-Method or Access-Control-Request-Headers are not whitelisted by the resource's CORS spec."},
        {"NoSuchCORSConfiguration", 404, "The CORS configuration does not exist"},
        {"NoSuchBucketPolicy", 404, "The bucket policy does not exist"},
        {"NoSuchTagSet", 404, "The TagSet does not exist"},
        {"ObjectLockConfigurationNotFoundError", 404, "Object Lock configuration does not exist for this bucket"},
        {"NoSuchObjectLockConfiguration", 404, "The specified object does not have a ObjectLock configuration"},
        {"InvalidRetentionPeriod", 400, "Default retention period must be a positive integer value."},
        {"InvalidBucketState", 409, "The request is not valid with the current state of the bucket."},
        {"ServerSideEncryptionConfigurationNotFoundError", 404, "The server side encryption configuration was not found"},
        {"ReplicationConfigurationNotFoundError", 404, "The replication configuration was not found"},
        {"InvalidEncryptionAlgorithmError", 400, "The encryption request you specified is not valid. The valid value is AES256."},
        {"MalformedPolicy", 400, "Policies must be valid JSON and the first byte must be '{'"},
        {"BadRequest", 400, "Bad Request"},
        {"InvalidTag", 400, "The tag provided was not a valid tag."},
        {"SignatureDoesNotMatch", 403, "The request signature we calculated does not match the signature you provided. Check your key and signing method."},
        {"InvalidAccessKeyId", 403, "The AWS Access Key Id you provided does not exist in our records."},
        {"RequestTimeout", 400, "Your socket connection to the server was not read from or written to within the timeout period."},
        {"StorageFull", 507, "The storage is full and cannot take more data."},
        {"SlowDown", 503, "Please reduce your request rate."},
        {"InternalError", 500, "We encountered an internal error. Please try again."},
        {"ServiceUnavailable", 503, "Service is unable to handle request."},
    };
    for (const row& r : table)
        if (r.code == code)
            return {std::string(r.code), std::string(r.message), r.status};
    return {std::string(code), std::string(code), 500};
}

// The ways a store result becomes a code.
inline s3_error error_for(st s)
{
    switch (s)
    {
        case st::no_such_bucket:      return make_error("NoSuchBucket");
        case st::no_such_key:         return make_error("NoSuchKey");
        case st::bucket_exists:       return make_error("BucketAlreadyOwnedByYou");
        case st::bucket_not_empty:    return make_error("BucketNotEmpty");
        case st::invalid_bucket_name: return make_error("InvalidBucketName");
        case st::key_too_long:        return make_error("KeyTooLongError");
        case st::metadata_too_large:  return make_error("MetadataTooLarge");
        case st::too_large:           return make_error("EntityTooLarge");
        case st::bad_digest:          return make_error("BadDigest");
        case st::storage_full:        return make_error("StorageFull");
        case st::busy:                return make_error("OperationAborted");
        // A part whose upload was aborted while its body was arriving, which is
        // the only way a cancelled body still has someone to answer.
        case st::cancelled:           return make_error("NoSuchUpload");
        case st::precondition_failed: return make_error("PreconditionFailed");
        case st::no_such_version:     return make_error("NoSuchVersion");
        // A delete marker has no bytes, tags or metadata to act on.
        case st::delete_marker:       return make_error("MethodNotAllowed");
        case st::unavailable:         return make_error("ServiceUnavailable");
        case st::locked:
        {
            s3_error e = make_error("AccessDenied");
            e.message  = "Access Denied because object protected by object lock.";
            return e;
        }
        case st::invalid_bucket_state:
        {
            s3_error e = make_error("InvalidBucketState");
            e.message  = "Object Lock configuration cannot be enabled on existing buckets unless versioning is "
                         "Enabled, and versioning cannot be changed on a bucket with object lock.";
            return e;
        }
        case st::ok:
        case st::io_error:
            break;
    }
    return make_error("InternalError");
}

struct error_context
{
    std::string_view bucket;
    std::string_view key;
    std::string_view resource;
    std::string_view request_id;
    std::string_view extra_name;
    std::string_view extra_value;
};

inline std::string error_xml(const s3_error& e, const error_context& c)
{
    std::string x(xml_decl);
    x += "<Error><Code>" + xml_escape(e.code) + "</Code><Message>" + xml_escape(e.message) + "</Message>";
    if (!c.extra_name.empty())
        x += "<" + std::string(c.extra_name) + ">" + xml_escape(c.extra_value) + "</" +
             std::string(c.extra_name) + ">";
    if (e.code == "NoSuchBucket" || e.code == "BucketNotEmpty" || e.code == "InvalidBucketName" ||
        e.code == "NoSuchCORSConfiguration" || e.code == "NoSuchLifecycleConfiguration" ||
        e.code == "NoSuchBucketPolicy" || e.code == "NoSuchTagSet" || e.code == "ReplicationConfigurationNotFoundError")
        x += "<BucketName>" + xml_escape(c.bucket) + "</BucketName>";
    if (e.code == "NoSuchKey")
        x += "<Key>" + xml_escape(c.key) + "</Key>";
    x += "<Resource>" + xml_escape(c.resource) + "</Resource><RequestId>" + xml_escape(c.request_id) +
         "</RequestId></Error>";
    return x;
}

inline std::string quoted_etag(const object_meta& m) { return "&quot;" + m.etag() + "&quot;"; }

// The ACL of every bucket and object, which S3 gives each when ObjectOwnership is BucketOwnerEnforced.
inline std::string owner_acl_xml(std::string_view owner, std::string_view display_name)
{
    const std::string id =
        "<ID>" + xml_escape(owner) + "</ID><DisplayName>" + xml_escape(display_name) + "</DisplayName>";
    return std::string(xml_decl) + "<AccessControlPolicy xmlns=\"" + std::string(s3_xmlns) + "\"><Owner>" + id +
           "</Owner><AccessControlList><Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
           "xsi:type=\"CanonicalUser\">" + id + "</Grantee><Permission>FULL_CONTROL</Permission></Grant>"
           "</AccessControlList></AccessControlPolicy>";
}

inline std::string ownership_controls_xml()
{
    return std::string(xml_decl) + "<OwnershipControls xmlns=\"" + std::string(s3_xmlns) +
           "\"><Rule><ObjectOwnership>BucketOwnerEnforced</ObjectOwnership></Rule></OwnershipControls>";
}

// What a ListBuckets request asks for: the buckets after `after` whose names begin with `prefix`, `max` of them.
struct bucket_page
{
    std::string_view prefix;
    std::string_view after;
    size_t           max{SIZE_MAX};
};

inline std::string list_buckets_xml(const std::vector<bucket_info>& bs, std::string_view owner_id,
                                    std::string_view owner_name, const bucket_page& page = {})
{
    std::string x(xml_decl);
    x += "<ListAllMyBucketsResult xmlns=\"" + std::string(s3_xmlns) + "\"><Owner><ID>" +
         xml_escape(owner_id) + "</ID><DisplayName>" + xml_escape(owner_name) +
         "</DisplayName></Owner><Buckets>";
    size_t n = 0;
    std::string_view last;
    bool truncated = false;
    for (const bucket_info& b : bs)
    {
        if (!b.name.starts_with(page.prefix) || (!page.after.empty() && b.name <= page.after))
            continue;
        if (n == page.max)
        {
            truncated = true;
            break;
        }
        ++n;
        last = b.name;
        x += "<Bucket><Name>" + xml_escape(b.name) + "</Name><CreationDate>" + iso8601(b.created_ms) +
             "</CreationDate><BucketRegion>us-east-1</BucketRegion></Bucket>";
    }
    x += "</Buckets>";
    if (truncated)
        x += "<ContinuationToken>" + base64url_encode(last) + "</ContinuationToken>";
    if (!page.prefix.empty())
        x += "<Prefix>" + xml_escape(page.prefix) + "</Prefix>";
    x += "</ListAllMyBucketsResult>";
    return x;
}

struct list_render
{
    std::string_view bucket;
    std::string_view prefix;
    std::string_view delimiter;
    std::string_view start_after;
    std::string_view continuation_token;
    std::string_view next_token;
    std::string_view marker;        // V1
    std::string_view next_marker;   // V1
    size_t           max_keys{1000};
    bool             url_encode_keys{false};
    bool             fetch_owner{false};
    bool             v2{true};
    // Held here, since a listing that crosses shards outlives the bucket's own copy.
    std::string      owner_id;
    std::string      owner_name;
};

// The digits of a number appended without a temporary string.
inline void append_number(std::string& out, uint64_t v)
{
    char buf[24];
    const auto r = std::to_chars(buf, buf + sizeof buf, v);
    out.append(buf, static_cast<size_t>(r.ptr - buf));
}

// A key, prefix or marker as the listing spells it.
inline void list_xml_text(std::string& x, const list_render& r, std::string_view s)
{
    // What url_encode leaves is already free of anything the XML escape would change.
    if (r.url_encode_keys)
        url_encode_to(x, s);
    else
        xml_escape_to(x, s);
}

// Everything before the first entry.
inline void list_xml_head(std::string& x, const list_render& r, size_t key_count, bool truncated)
{
    x += xml_decl;
    x += "<ListBucketResult xmlns=\"";
    x += s3_xmlns;
    x += "\"><Name>";
    xml_escape_to(x, r.bucket);
    x += "</Name><Prefix>";
    list_xml_text(x, r, r.prefix);
    x += "</Prefix>";
    if (r.v2)
    {
        if (!r.continuation_token.empty())
        {
            x += "<ContinuationToken>";
            xml_escape_to(x, r.continuation_token);
            x += "</ContinuationToken>";
        }
        if (truncated && !r.next_token.empty())
        {
            x += "<NextContinuationToken>";
            xml_escape_to(x, r.next_token);
            x += "</NextContinuationToken>";
        }
        x += "<KeyCount>";
        append_number(x, key_count);
        x += "</KeyCount>";
    }
    else
    {
        x += "<Marker>";
        list_xml_text(x, r, r.marker);
        x += "</Marker>";
    }
    x += "<MaxKeys>";
    append_number(x, r.max_keys);
    x += "</MaxKeys>";
    if (!r.delimiter.empty())
    {
        x += "<Delimiter>";
        list_xml_text(x, r, r.delimiter);
        x += "</Delimiter>";
    }
    if (r.url_encode_keys)
        x += "<EncodingType>url</EncodingType>";
    x += truncated ? "<IsTruncated>true</IsTruncated>" : "<IsTruncated>false</IsTruncated>";
    if (!r.v2 && truncated && !r.delimiter.empty() && !r.next_marker.empty())
    {
        x += "<NextMarker>";
        list_xml_text(x, r, r.next_marker);
        x += "</NextMarker>";
    }
    if (r.v2 && !r.start_after.empty())
    {
        x += "<StartAfter>";
        list_xml_text(x, r, r.start_after);
        x += "</StartAfter>";
    }
}

// One <Contents> element, written after the key in one place and appended once.
inline void list_xml_object(std::string& x, const list_render& r, const std::string& key,
                            const object_meta& m)
{
    static constexpr char digits[] = "0123456789abcdef";
    const auto lit = [](char* q, std::string_view t)
    {
        std::memcpy(q, t.data(), t.size());
        return q + t.size();
    };
    x += "<Contents><Key>";
    list_xml_text(x, r, key);
    char  buf[320];
    char* q = lit(buf, "</Key><LastModified>");
    q = write_iso8601(q, m.mtime_ms);
    q = lit(q, "</LastModified><ETag>&quot;");
    for (const uint8_t b : m.md5)
    {
        *q++ = digits[b >> 4];
        *q++ = digits[b & 15];
    }
    if (m.parts)
    {
        *q++ = '-';
        q = std::to_chars(q, buf + sizeof buf - 64, static_cast<uint64_t>(m.parts)).ptr;
    }
    q = lit(q, "&quot;</ETag><Size>");
    q = std::to_chars(q, buf + sizeof buf - 64, m.size).ptr;
    q = lit(q, "</Size>");
    if (!r.v2 || r.fetch_owner)
    {
        x.append(buf, static_cast<size_t>(q - buf));
        x += "<Owner><ID>";
        xml_escape_to(x, r.owner_id);
        x += "</ID><DisplayName>";
        xml_escape_to(x, r.owner_name);
        x += "</DisplayName></Owner><StorageClass>STANDARD</StorageClass></Contents>";
        return;
    }
    q = lit(q, "<StorageClass>STANDARD</StorageClass></Contents>");
    x.append(buf, static_cast<size_t>(q - buf));
}

inline void list_xml_prefix(std::string& x, const list_render& r, std::string_view common)
{
    x += "<CommonPrefixes><Prefix>";
    list_xml_text(x, r, common);
    x += "</Prefix></CommonPrefixes>";
}

inline std::string list_xml(const list_render& r, const list_page& p)
{
    // Room for the whole page, so it is written without the string moving.
    size_t room = 1024 + r.prefix.size() + r.marker.size() + r.next_marker.size() + r.start_after.size() +
                  r.continuation_token.size() + r.next_token.size() + r.delimiter.size();
    for (const list_entry& e : p.objects)
        room += e.key.size() + 240 + (r.v2 && !r.fetch_owner ? 0 : 110 + r.owner_id.size() + r.owner_name.size());
    for (const std::string& c : p.prefixes)
        room += c.size() + 48;
    std::string x;
    x.reserve(room);
    list_xml_head(x, r, p.objects.size() + p.prefixes.size(), p.truncated);
    for (const list_entry& e : p.objects)
        list_xml_object(x, r, e.key, e.meta);
    for (const std::string& c : p.prefixes)
        list_xml_prefix(x, r, c);
    x += "</ListBucketResult>";
    return x;
}

// A listing rendered as the walk of the store reports it, without a page in between.
class list_xml_writer final : public list_visitor
{
public:
    explicit list_xml_writer(const list_render& r) : m_r(r) {}

    void object(const std::string& key, const object_meta& meta) override
    {
        list_xml_object(m_objects, m_r, key, meta);
        // The first entry says how big a page of them will be, so the rest are appended without the buffer moving.
        if (m_count == 0)
            m_objects.reserve(std::min<size_t>(m_objects.size() * std::min<size_t>(m_r.max_keys, 1000) + 256, 262144));
        ++m_count;
        m_last_object = &key;
    }
    void prefix(std::string common) override
    {
        list_xml_prefix(m_prefixes, m_r, common);
        ++m_count;
        m_last_prefix = std::move(common);
        m_has_prefix  = true;
    }
    void truncated(const std::string& resume_at) override
    {
        m_truncated = true;
        m_resume_at = resume_at;
    }

    bool               is_truncated() const { return m_truncated; }
    // Where a V2 continuation token points, when the page is cut.
    const std::string& resume_at() const { return m_resume_at; }
    // What a V1 page's marker is: the last of what it named, object or prefix.
    const std::string* last_named() const
    {
        const std::string* last = m_last_object;
        if (m_has_prefix && (!last || m_last_prefix > *last))
            last = &m_last_prefix;
        return last;
    }

    // The document, with the tokens the render has been given by now.
    std::string finish() const
    {
        const list_render& r = m_r;
        std::string x;
        x.reserve(1024 + m_objects.size() + m_prefixes.size() + r.prefix.size() + r.marker.size() +
                  r.next_marker.size() + r.start_after.size() + r.continuation_token.size() +
                  r.next_token.size() + r.delimiter.size());
        list_xml_head(x, r, m_count, m_truncated);
        x += m_objects;
        x += m_prefixes;
        x += "</ListBucketResult>";
        return x;
    }

private:
    const list_render& m_r;
    std::string        m_objects, m_prefixes;
    size_t             m_count{0};
    // The keys live in the store's index and are not touched while the walk runs.
    const std::string* m_last_object{nullptr};
    std::string        m_last_prefix;
    bool               m_has_prefix{false};
    bool               m_truncated{false};
    std::string        m_resume_at;
};

// "Checksum" and the algorithm's name, which is how the XML spells the element.
inline std::string checksum_element(checksum_algo a, std::string_view value_b64)
{
    if (a == checksum_algo::none || value_b64.empty())
        return {};
    const std::string name = "Checksum" + std::string(checksum_name(a));
    return "<" + name + ">" + xml_escape(value_b64) + "</" + name + ">";
}

inline std::string copy_result_xml(const object_meta& m)
{
    std::string x(xml_decl);
    x += "<CopyObjectResult xmlns=\"" + std::string(s3_xmlns) + "\"><LastModified>" +
         iso8601(m.mtime_ms) + "</LastModified><ETag>" + quoted_etag(m) + "</ETag>";
    // A copy's checksum is always of its whole bytes.
    if (m.checksum)
        x += "<ChecksumType>FULL_OBJECT</ChecksumType>" + checksum_element(m.checksum.algo, m.checksum.b64());
    x += "</CopyObjectResult>";
    return x;
}

inline std::string location_xml()
{
    std::string x(xml_decl);
    x += "<LocationConstraint xmlns=\"" + std::string(s3_xmlns) + "\"/>";
    return x;
}

struct delete_result
{
    std::string key;
    bool        ok{true};
    s3_error    error;
    // The version the request named, and the delete marker it removed or made.
    std::string version_id;
    bool        delete_marker{false};
    std::string marker_version_id;
};

inline std::string delete_result_xml(const std::vector<delete_result>& rs, bool quiet)
{
    std::string x(xml_decl);
    x += "<DeleteResult xmlns=\"" + std::string(s3_xmlns) + "\">";
    for (const delete_result& r : rs)
    {
        const std::string version = r.version_id.empty() ? std::string{}
                                                         : "<VersionId>" + xml_escape(r.version_id) + "</VersionId>";
        if (r.ok)
        {
            if (!quiet)
            {
                x += "<Deleted><Key>" + xml_escape(r.key) + "</Key>" + version;
                if (r.delete_marker)
                    x += "<DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>" +
                         xml_escape(r.marker_version_id) + "</DeleteMarkerVersionId>";
                x += "</Deleted>";
            }
        }
        else
            x += "<Error><Key>" + xml_escape(r.key) + "</Key>" + version + "<Code>" + xml_escape(r.error.code) +
                 "</Code><Message>" + xml_escape(r.error.message) + "</Message></Error>";
    }
    x += "</DeleteResult>";
    return x;
}

// ─── Reading a Delete request ───────────────────────────────────────────────
// <Delete><Quiet>true</Quiet><Object><Key>k</Key>[<VersionId/>]</Object>...</Delete>
// A small reader of exactly that shape, which understands the five named
// entities and numeric references and refuses everything it does not expect.

inline bool xml_unescape(std::string_view in, std::string& out)
{
    out.clear();
    for (size_t i = 0; i < in.size(); ++i)
    {
        if (in[i] != '&')
        {
            out.push_back(in[i]);
            continue;
        }
        const size_t semi = in.find(';', i);
        if (semi == std::string_view::npos || semi - i > 10)
            return false;
        const std::string_view ent = in.substr(i + 1, semi - i - 1);
        if (ent == "amp") out.push_back('&');
        else if (ent == "lt") out.push_back('<');
        else if (ent == "gt") out.push_back('>');
        else if (ent == "quot") out.push_back('"');
        else if (ent == "apos") out.push_back('\'');
        else if (ent.size() > 1 && ent[0] == '#')
        {
            uint32_t cp = 0;
            const bool hexform = ent[1] == 'x' || ent[1] == 'X';
            const std::string_view digits = ent.substr(hexform ? 2 : 1);
            if (digits.empty())
                return false;
            for (char c : digits)
            {
                const int d = hexform ? hex_digit(c) : (c >= '0' && c <= '9' ? c - '0' : -1);
                if (d < 0)
                    return false;
                cp = cp * (hexform ? 16 : 10) + static_cast<uint32_t>(d);
                if (cp > 0x10FFFF)
                    return false;
            }
            // UTF-8.
            if (cp < 0x80) out.push_back(static_cast<char>(cp));
            else if (cp < 0x800)
            {
                out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            }
            else if (cp < 0x10000)
            {
                out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            }
            else
            {
                out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
                out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            }
        }
        else
            return false;
        i = semi;
    }
    return true;
}

struct delete_request
{
    std::vector<std::string> keys;
    // Each key's <VersionId>, empty where it named none.
    std::vector<std::string> versions;
    bool                     quiet{false};
};

// False for anything that is not a Delete document with between one and 1000
// objects, each with a key.
inline bool parse_delete_request(std::string_view x, delete_request& out)
{
    out = {};
    size_t pos = 0;
    const auto skip_ws = [&] { while (pos < x.size() && (x[pos] == ' ' || x[pos] == '\t' || x[pos] == '\r' || x[pos] == '\n')) ++pos; };

    // The declaration and any comment before the root.
    skip_ws();
    if (x.substr(pos, 5) == "<?xml")
    {
        const size_t e = x.find("?>", pos);
        if (e == std::string_view::npos)
            return false;
        pos = e + 2;
    }

    struct tag { std::string name; bool closing; bool self_closing; size_t end; };
    const auto next_tag = [&](size_t from, tag& t) -> bool
    {
        size_t lt = x.find('<', from);
        if (lt == std::string_view::npos)
            return false;
        const size_t gt = x.find('>', lt);
        if (gt == std::string_view::npos)
            return false;
        std::string_view inner = x.substr(lt + 1, gt - lt - 1);
        t.closing = !inner.empty() && inner.front() == '/';
        if (t.closing)
            inner.remove_prefix(1);
        t.self_closing = !inner.empty() && inner.back() == '/';
        if (t.self_closing)
            inner.remove_suffix(1);
        // A namespace declaration or attributes are ignored.
        const size_t sp = inner.find_first_of(" \t\r\n");
        if (sp != std::string_view::npos)
            inner = inner.substr(0, sp);
        const size_t colon = inner.find(':');
        if (colon != std::string_view::npos)
            inner.remove_prefix(colon + 1);
        t.name = std::string(inner);
        t.end  = gt + 1;
        return true;
    };

    tag t;
    if (!next_tag(pos, t) || t.closing || t.name != "Delete")
        return false;
    pos = t.end;

    for (;;)
    {
        if (!next_tag(pos, t))
            return false;
        if (t.closing && t.name == "Delete")
            break;
        if (t.closing || t.self_closing)
        {
            pos = t.end;
            continue;
        }
        if (t.name == "Quiet")
        {
            const size_t close = x.find('<', t.end);
            if (close == std::string_view::npos)
                return false;
            const std::string_view v = x.substr(t.end, close - t.end);
            out.quiet = v == "true" || v == "True" || v == "TRUE";
            pos = x.find('>', close);
            if (pos == std::string_view::npos)
                return false;
            ++pos;
        }
        else if (t.name == "Object")
        {
            pos = t.end;
            bool have_key = false;
            std::string key, version;
            for (;;)
            {
                tag u;
                if (!next_tag(pos, u))
                    return false;
                if (u.closing && u.name == "Object")
                {
                    pos = u.end;
                    break;
                }
                if (u.name == "Key" && !u.closing && !u.self_closing)
                {
                    const size_t close = x.find('<', u.end);
                    if (close == std::string_view::npos)
                        return false;
                    if (!xml_unescape(x.substr(u.end, close - u.end), key))
                        return false;
                    have_key = true;
                    const size_t gt = x.find('>', close);
                    if (gt == std::string_view::npos)
                        return false;
                    pos = gt + 1;
                }
                else if (u.name == "Key" && u.self_closing)
                {
                    key.clear();
                    have_key = true;
                    pos = u.end;
                }
                else if (u.name == "VersionId" && !u.closing && !u.self_closing)
                {
                    const size_t close = x.find('<', u.end);
                    if (close == std::string_view::npos || !xml_unescape(x.substr(u.end, close - u.end), version))
                        return false;
                    const size_t gt = x.find('>', close);
                    if (gt == std::string_view::npos)
                        return false;
                    pos = gt + 1;
                }
                else
                    pos = u.end;
            }
            if (!have_key)
                return false;
            out.keys.push_back(std::move(key));
            out.versions.push_back(std::move(version));
            if (out.keys.size() > 1000)
                return false;
        }
        else
            pos = t.end;
    }
    return !out.keys.empty();
}

}   // namespace socketley::storage
