#pragma once
// The XML of the multipart operations: the answers to CreateMultipartUpload,
// CompleteMultipartUpload, ListParts and ListMultipartUploads, and the parsing
// of the part list a client sends to complete an upload.
//
// Element names and the namespace are as S3 writes them.
#include <charconv>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "checksum.h"
#include "s3_names.h"
#include "s3_xml.h"

namespace socketley::storage
{

// One entry of the list CompleteMultipartUpload carries.
struct complete_part
{
    uint32_t    number{0};
    // Unquoted, as the client gave it.
    std::string etag;
    // The checksum the client says the part has, in base64, and which algorithm.
    checksum_algo checksum_algo_{checksum_algo::none};
    std::string   checksum_b64;
};

// False for anything that is not a CompleteMultipartUpload document of parts
// that each have a number and an ETag.
inline bool parse_complete_request(std::string_view x, std::vector<complete_part>& out)
{
    out.clear();
    size_t pos = 0;

    struct tag { std::string name; bool closing; bool self_closing; size_t end; };
    const auto next_tag = [&](size_t from, tag& t) -> bool
    {
        for (;;)
        {
            const size_t lt = x.find('<', from);
            if (lt == std::string_view::npos)
                return false;
            const size_t gt = x.find('>', lt);
            if (gt == std::string_view::npos)
                return false;
            std::string_view inner = x.substr(lt + 1, gt - lt - 1);
            // A declaration or a comment is not an element.
            if (!inner.empty() && (inner.front() == '?' || inner.front() == '!'))
            {
                from = gt + 1;
                continue;
            }
            t.closing = !inner.empty() && inner.front() == '/';
            if (t.closing)
                inner.remove_prefix(1);
            t.self_closing = !inner.empty() && inner.back() == '/';
            if (t.self_closing)
                inner.remove_suffix(1);
            const size_t sp = inner.find_first_of(" \t\r\n");
            if (sp != std::string_view::npos)
                inner = inner.substr(0, sp);
            const size_t colon = inner.find(':');
            if (colon != std::string_view::npos)
                inner.remove_prefix(colon + 1);
            t.name = std::string(inner);
            t.end  = gt + 1;
            return true;
        }
    };

    // The text of an element whose start tag ends at `from`, and where its end tag ends.
    const auto text_of = [&](size_t from, std::string& text, size_t& after) -> bool
    {
        const size_t close = x.find('<', from);
        if (close == std::string_view::npos)
            return false;
        if (!xml_unescape(x.substr(from, close - from), text))
            return false;
        const size_t gt = x.find('>', close);
        if (gt == std::string_view::npos)
            return false;
        after = gt + 1;
        return true;
    };

    tag t;
    if (!next_tag(pos, t) || t.closing || t.name != "CompleteMultipartUpload")
        return false;
    pos = t.end;

    for (;;)
    {
        if (!next_tag(pos, t))
            return false;
        if (t.closing && t.name == "CompleteMultipartUpload")
            break;
        if (t.closing || t.self_closing || t.name != "Part")
        {
            pos = t.end;
            continue;
        }
        pos = t.end;
        complete_part part;
        bool have_number = false, have_etag = false;
        for (;;)
        {
            tag u;
            if (!next_tag(pos, u))
                return false;
            if (u.closing && u.name == "Part")
            {
                pos = u.end;
                break;
            }
            if (u.closing || u.self_closing)
            {
                pos = u.end;
                continue;
            }
            std::string text;
            size_t      after = 0;
            if (!text_of(u.end, text, after))
                return false;
            pos = after;
            if (u.name == "PartNumber")
            {
                uint32_t n = 0;
                const auto r = std::from_chars(text.data(), text.data() + text.size(), n);
                if (text.empty() || r.ec != std::errc{} || r.ptr != text.data() + text.size())
                    return false;
                part.number = n;
                have_number = true;
            }
            else if (u.name == "ETag")
            {
                std::string_view e = text;
                while (!e.empty() && (e.front() == ' ' || e.front() == '\n'))
                    e.remove_prefix(1);
                while (!e.empty() && (e.back() == ' ' || e.back() == '\n'))
                    e.remove_suffix(1);
                if (e.starts_with("W/"))
                    e.remove_prefix(2);
                if (e.size() >= 2 && e.front() == '"' && e.back() == '"')
                    e = e.substr(1, e.size() - 2);
                part.etag = std::string(e);
                have_etag = true;
            }
            else if (u.name.starts_with("Checksum"))
            {
                const checksum_algo a = checksum_from_name(std::string_view(u.name).substr(8));
                if (a != checksum_algo::none)
                {
                    part.checksum_algo_ = a;
                    part.checksum_b64   = text;
                }
            }
        }
        if (!have_number || !have_etag)
            return false;
        out.push_back(std::move(part));
        if (out.size() > 10000)
            return false;
    }
    return true;
}

inline std::string initiate_multipart_xml(std::string_view bucket, std::string_view key, std::string_view upload_id)
{
    std::string x(xml_decl);
    x += "<InitiateMultipartUploadResult xmlns=\"" + std::string(s3_xmlns) + "\"><Bucket>" + xml_escape(bucket) +
         "</Bucket><Key>" + xml_escape(key) + "</Key><UploadId>" + xml_escape(upload_id) +
         "</UploadId></InitiateMultipartUploadResult>";
    return x;
}

// "Checksum" and the algorithm's name, which is how the XML spells the element.
inline std::string checksum_element(checksum_algo a, std::string_view value_b64)
{
    if (a == checksum_algo::none || value_b64.empty())
        return {};
    const std::string name = "Checksum" + std::string(checksum_name(a));
    return "<" + name + ">" + xml_escape(value_b64) + "</" + name + ">";
}

inline std::string complete_multipart_xml(std::string_view location, std::string_view bucket,
                                          std::string_view key, std::string_view etag,
                                          checksum_algo algo, std::string_view checksum_b64)
{
    std::string x(xml_decl);
    x += "<CompleteMultipartUploadResult xmlns=\"" + std::string(s3_xmlns) + "\"><Location>" +
         xml_escape(location) + "</Location><Bucket>" + xml_escape(bucket) + "</Bucket><Key>" + xml_escape(key) +
         "</Key><ETag>&quot;" + xml_escape(etag) + "&quot;</ETag>" + checksum_element(algo, checksum_b64) +
         (algo == checksum_algo::none || checksum_b64.empty() ? ""
          : checksum_b64.find('-') != std::string_view::npos ? "<ChecksumType>COMPOSITE</ChecksumType>"
                                                              : "<ChecksumType>FULL_OBJECT</ChecksumType>") +
         "</CompleteMultipartUploadResult>";
    return x;
}

struct part_row
{
    uint32_t      number{0};
    int64_t       mtime_ms{0};
    std::string   etag;
    uint64_t      size{0};
    checksum_algo algo{checksum_algo::none};
    std::string   checksum_b64;
};

struct list_parts_render
{
    std::string_view bucket;
    std::string_view key;
    std::string_view upload_id;
    std::string_view owner_id;
    uint32_t         part_number_marker{0};
    uint32_t         next_part_number_marker{0};
    uint32_t         max_parts{1000};
    bool             truncated{false};
    checksum_algo    algo{checksum_algo::none};
};

inline std::string list_parts_xml(const list_parts_render& r, const std::vector<part_row>& parts)
{
    std::string x(xml_decl);
    x += "<ListPartsResult xmlns=\"" + std::string(s3_xmlns) + "\"><Bucket>" + xml_escape(r.bucket) +
         "</Bucket><Key>" + xml_escape(r.key) + "</Key><UploadId>" + xml_escape(r.upload_id) + "</UploadId>";
    x += "<PartNumberMarker>" + std::to_string(r.part_number_marker) + "</PartNumberMarker>";
    if (r.truncated)
        x += "<NextPartNumberMarker>" + std::to_string(r.next_part_number_marker) + "</NextPartNumberMarker>";
    x += "<MaxParts>" + std::to_string(r.max_parts) + "</MaxParts>";
    x += std::string("<IsTruncated>") + (r.truncated ? "true" : "false") + "</IsTruncated>";
    for (const part_row& p : parts)
        x += "<Part><PartNumber>" + std::to_string(p.number) + "</PartNumber><LastModified>" + iso8601(p.mtime_ms) +
             "</LastModified><ETag>&quot;" + xml_escape(p.etag) + "&quot;</ETag><Size>" + std::to_string(p.size) +
             "</Size>" + checksum_element(p.algo, p.checksum_b64) + "</Part>";
    x += "<Initiator><ID>" + xml_escape(r.owner_id) + "</ID><DisplayName>" + xml_escape(r.owner_id) +
         "</DisplayName></Initiator><Owner><ID>" + xml_escape(r.owner_id) + "</ID><DisplayName>" +
         xml_escape(r.owner_id) + "</DisplayName></Owner><StorageClass>STANDARD</StorageClass>";
    if (r.algo != checksum_algo::none)
        x += "<ChecksumAlgorithm>" + std::string(checksum_name(r.algo)) + "</ChecksumAlgorithm>";
    x += "</ListPartsResult>";
    return x;
}

struct upload_row
{
    std::string key;
    std::string upload_id;
    int64_t     initiated_ms{0};
};

struct list_uploads_render
{
    std::string_view bucket;
    std::string_view prefix;
    std::string_view delimiter;
    std::string_view key_marker;
    std::string_view upload_id_marker;
    std::string_view next_key_marker;
    std::string_view next_upload_id_marker;
    std::string_view owner_id;
    uint32_t         max_uploads{1000};
    bool             truncated{false};
    bool             url_encode_keys{false};
};

inline std::string list_uploads_xml(const list_uploads_render& r, const std::vector<upload_row>& uploads,
                                    const std::vector<std::string>& prefixes)
{
    const auto enc = [&](std::string_view s)
    {
        return xml_escape(r.url_encode_keys ? url_encode(s) : std::string(s));
    };
    std::string x(xml_decl);
    x += "<ListMultipartUploadsResult xmlns=\"" + std::string(s3_xmlns) + "\"><Bucket>" + xml_escape(r.bucket) +
         "</Bucket><KeyMarker>" + enc(r.key_marker) + "</KeyMarker><UploadIdMarker>" +
         xml_escape(r.upload_id_marker) + "</UploadIdMarker>";
    if (r.truncated)
        x += "<NextKeyMarker>" + enc(r.next_key_marker) + "</NextKeyMarker><NextUploadIdMarker>" +
             xml_escape(r.next_upload_id_marker) + "</NextUploadIdMarker>";
    if (!r.delimiter.empty())
        x += "<Delimiter>" + enc(r.delimiter) + "</Delimiter>";
    x += "<Prefix>" + enc(r.prefix) + "</Prefix>";
    x += "<MaxUploads>" + std::to_string(r.max_uploads) + "</MaxUploads>";
    x += std::string("<IsTruncated>") + (r.truncated ? "true" : "false") + "</IsTruncated>";
    if (r.url_encode_keys)
        x += "<EncodingType>url</EncodingType>";
    for (const upload_row& u : uploads)
        x += "<Upload><Key>" + enc(u.key) + "</Key><UploadId>" + xml_escape(u.upload_id) +
             "</UploadId><Initiator><ID>" + xml_escape(r.owner_id) + "</ID><DisplayName>" + xml_escape(r.owner_id) +
             "</DisplayName></Initiator><Owner><ID>" + xml_escape(r.owner_id) + "</ID><DisplayName>" +
             xml_escape(r.owner_id) + "</DisplayName></Owner><StorageClass>STANDARD</StorageClass><Initiated>" +
             iso8601(u.initiated_ms) + "</Initiated></Upload>";
    for (const std::string& p : prefixes)
        x += "<CommonPrefixes><Prefix>" + enc(p) + "</Prefix></CommonPrefixes>";
    x += "</ListMultipartUploadsResult>";
    return x;
}

}   // namespace socketley::storage
