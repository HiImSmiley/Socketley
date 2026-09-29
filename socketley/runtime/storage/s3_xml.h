#pragma once
// The XML S3 speaks: errors, listings and the batch-delete exchange, with
// element names and the namespace exactly as S3 writes them.
#include <cstdint>
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

// The characters that would end an element, and the control characters an XML
// 1.0 document may not carry at all.
inline std::string xml_escape(std::string_view in)
{
    std::string out;
    out.reserve(in.size());
    for (unsigned char c : in)
    {
        switch (c)
        {
            case '&':  out += "&amp;"; break;
            case '<':  out += "&lt;"; break;
            case '>':  out += "&gt;"; break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default:
                if (c < 0x20 && c != '\t' && c != '\n' && c != '\r')
                {
                    // Not representable in the document; a numeric reference is
                    // what S3 sends for these, and clients that decode it get the byte.
                    char buf[12];
                    std::snprintf(buf, sizeof buf, "&#x%X;", c);
                    out += buf;
                }
                else
                    out.push_back(static_cast<char>(c));
        }
    }
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
        {"NoSuchUpload", 404, "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed."},
        {"BucketAlreadyOwnedByYou", 409, "Your previous request to create the named bucket succeeded and you already own it."},
        {"BucketAlreadyExists", 409, "The requested bucket name is not available. The bucket namespace is shared by all users of the system. Please select a different name and try again."},
        {"BucketNotEmpty", 409, "The bucket you tried to delete is not empty"},
        {"OperationAborted", 409, "A conflicting conditional operation is currently in progress against this resource. Please try again."},
        {"InvalidBucketName", 400, "The specified bucket is not valid."},
        {"InvalidRange", 416, "The requested range is not satisfiable"},
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
        {"AccessDenied", 403, "Access Denied"},
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
    if (e.code == "NoSuchBucket" || e.code == "BucketNotEmpty" || e.code == "InvalidBucketName")
        x += "<BucketName>" + xml_escape(c.bucket) + "</BucketName>";
    if (e.code == "NoSuchKey")
        x += "<Key>" + xml_escape(c.key) + "</Key>";
    x += "<Resource>" + xml_escape(c.resource) + "</Resource><RequestId>" + xml_escape(c.request_id) +
         "</RequestId></Error>";
    return x;
}

inline std::string quoted_etag(const object_meta& m) { return "&quot;" + m.etag() + "&quot;"; }

inline std::string list_buckets_xml(const std::vector<bucket_info>& bs, std::string_view owner_id,
                                    std::string_view owner_name)
{
    std::string x(xml_decl);
    x += "<ListAllMyBucketsResult xmlns=\"" + std::string(s3_xmlns) + "\"><Owner><ID>" +
         xml_escape(owner_id) + "</ID><DisplayName>" + xml_escape(owner_name) +
         "</DisplayName></Owner><Buckets>";
    for (const bucket_info& b : bs)
        x += "<Bucket><Name>" + xml_escape(b.name) + "</Name><CreationDate>" + iso8601(b.created_ms) +
             "</CreationDate></Bucket>";
    x += "</Buckets></ListAllMyBucketsResult>";
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
    std::string_view owner_id;
};

inline std::string list_xml(const list_render& r, const list_page& p)
{
    const auto enc = [&](std::string_view s)
    {
        return xml_escape(r.url_encode_keys ? url_encode(s) : std::string(s));
    };
    std::string x(xml_decl);
    x += "<ListBucketResult xmlns=\"" + std::string(s3_xmlns) + "\">";
    x += "<Name>" + xml_escape(r.bucket) + "</Name>";
    x += "<Prefix>" + enc(r.prefix) + "</Prefix>";
    if (r.v2)
    {
        if (!r.continuation_token.empty())
            x += "<ContinuationToken>" + xml_escape(r.continuation_token) + "</ContinuationToken>";
        if (p.truncated && !r.next_token.empty())
            x += "<NextContinuationToken>" + xml_escape(r.next_token) + "</NextContinuationToken>";
        x += "<KeyCount>" + std::to_string(p.objects.size() + p.prefixes.size()) + "</KeyCount>";
    }
    else
        x += "<Marker>" + enc(r.marker) + "</Marker>";
    x += "<MaxKeys>" + std::to_string(r.max_keys) + "</MaxKeys>";
    if (!r.delimiter.empty())
        x += "<Delimiter>" + enc(r.delimiter) + "</Delimiter>";
    if (r.url_encode_keys)
        x += "<EncodingType>url</EncodingType>";
    x += std::string("<IsTruncated>") + (p.truncated ? "true" : "false") + "</IsTruncated>";
    if (!r.v2 && p.truncated && !r.delimiter.empty() && !r.next_marker.empty())
        x += "<NextMarker>" + enc(r.next_marker) + "</NextMarker>";
    if (r.v2 && !r.start_after.empty())
        x += "<StartAfter>" + enc(r.start_after) + "</StartAfter>";
    for (const list_entry& e : p.objects)
    {
        x += "<Contents><Key>" + enc(e.key) + "</Key><LastModified>" + iso8601(e.meta.mtime_ms) +
             "</LastModified><ETag>" + quoted_etag(e.meta) + "</ETag><Size>" +
             std::to_string(e.meta.size) + "</Size>";
        if (!r.v2 || r.fetch_owner)
            x += "<Owner><ID>" + xml_escape(r.owner_id) + "</ID><DisplayName>" +
                 xml_escape(r.owner_id) + "</DisplayName></Owner>";
        x += "<StorageClass>STANDARD</StorageClass></Contents>";
    }
    for (const std::string& c : p.prefixes)
        x += "<CommonPrefixes><Prefix>" + enc(c) + "</Prefix></CommonPrefixes>";
    x += "</ListBucketResult>";
    return x;
}

inline std::string copy_result_xml(const object_meta& m)
{
    std::string x(xml_decl);
    x += "<CopyObjectResult xmlns=\"" + std::string(s3_xmlns) + "\"><LastModified>" +
         iso8601(m.mtime_ms) + "</LastModified><ETag>" + quoted_etag(m) + "</ETag></CopyObjectResult>";
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
};

inline std::string delete_result_xml(const std::vector<delete_result>& rs, bool quiet)
{
    std::string x(xml_decl);
    x += "<DeleteResult xmlns=\"" + std::string(s3_xmlns) + "\">";
    for (const delete_result& r : rs)
    {
        if (r.ok)
        {
            if (!quiet)
                x += "<Deleted><Key>" + xml_escape(r.key) + "</Key></Deleted>";
        }
        else
            x += "<Error><Key>" + xml_escape(r.key) + "</Key><Code>" + xml_escape(r.error.code) +
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
            std::string key;
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
                else
                    pos = u.end;
            }
            if (!have_key)
                return false;
            out.keys.push_back(std::move(key));
            if (out.keys.size() > 1000)
                return false;
        }
        else
            pos = t.end;
    }
    return !out.keys.empty();
}

}   // namespace socketley::storage
