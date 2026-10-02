// The multipart operations of the S3 API: routing what the parts and the
// upload are asked to do, and answering it.  The uploads themselves are kept by
// the multipart_store.
#include "storage_run.h"

#include <algorithm>
#include <charconv>

#include "s3_multipart_xml.h"
#include "s3_names.h"
#include "s3_xml.h"
#include "storage_instance.h"
#include "../../shared/logging.h"

namespace socketley::storage
{

namespace
{

constexpr uint32_t list_page_max = 1000;

template <class T>
bool parse_number(std::string_view s, T& out)
{
    if (s.empty())
        return false;
    const auto r = std::from_chars(s.data(), s.data() + s.size(), out);
    return r.ec == std::errc{} && r.ptr == s.data() + s.size();
}

bool parse_u32(std::string_view s, uint32_t& out) { return parse_number(s, out); }
bool parse_u64(std::string_view s, uint64_t& out) { return parse_number(s, out); }

}   // namespace

// Asks the shard that owns the upload whether it can take a part, and runs `go`
// with the checksum algorithm the upload has; answers NoSuchUpload itself when it
// cannot.  The body of a part is not read while the owner is being asked.
void storage_run::with_open_upload(const std::shared_ptr<conn>& c, uint32_t number,
                                   std::function<void(checksum_algo, part_place)> go)
{
    const s3_request& r = c->req;
    if (!m_store.has_bucket(r.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    const bool remote = !m_store.owns(r.bucket, r.key);
    if (remote)
        c->ph = phase::hook_wait;
    uint64_t expected = 0;
    const bool known  = number != 0 && body_length(*c, expected);
    std::weak_ptr<conn> weak = c;
    m_node.mpu_begin(r.bucket, r.key, std::string(r.get_query("uploadId")), number, expected, known,
        [this, weak, go = std::move(go)](st s, checksum_algo algo, part_place place)
        {
            auto cc = weak.lock();
            if (!cc || cc->dead)
                return;
            cc->last_progress = std::chrono::steady_clock::now();
            if (s == st::io_error)
            {
                send_error_st(cc, s);
                return;
            }
            if (s != st::ok)
            {
                send_error(cc, make_error("NoSuchUpload"), false, "UploadId", cc->req.get_query("uploadId"));
                return;
            }
            go(algo, std::move(place));
        });
}

bool storage_run::part_number_of(const std::shared_ptr<conn>& c, uint32_t& number)
{
    if (!parse_u32(c->req.get_query("partNumber"), number) || number < 1 || number > mpu_max_parts)
    {
        s3_error e = make_error("InvalidArgument");
        e.message  = "Part number must be an integer between 1 and 10000, inclusive";
        send_error(c, e, false, "ArgumentName", "partNumber");
        return false;
    }
    return true;
}

// ─── CreateMultipartUpload ──────────────────────────────────────────────────

void storage_run::op_create_multipart(const std::shared_ptr<conn>& c)
{
    const s3_request& r = c->req;
    if (!valid_bucket_name(r.bucket) || !m_store.has_bucket(r.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }

    object_meta meta;
    s3_error    err;
    // The tags and the lock are kept with the upload and land on the object its completion makes.
    if (!object_meta_from_headers(c, meta, err) || !tagging_from_header(r, meta, err) ||
        !lock_from_headers(c, meta, err))
    {
        send_error(c, err);
        return;
    }
    // The upload's data key is made now, so every part is sealed under it and the object it completes opens with it.
    sse_ask ask;
    sse_seal_spec seal;
    if (!sse_for_write(c, r.bucket, ask, err) || (ask.mode != sse_mode::none && !sse_new_key(ask, true, meta, seal, err)))
    {
        send_error(c, err);
        return;
    }
    checksum_algo algo = checksum_algo::none;
    if (const std::string_view name = r.header("x-amz-checksum-algorithm"); !name.empty())
    {
        algo = checksum_from_name(name);
        if (algo == checksum_algo::none)
        {
            err = make_error("InvalidRequest");
            err.message = "Checksum algorithm provided is unsupported. Please try again with any of the valid types: "
                          "[CRC32, CRC32C, CRC64NVME, SHA1, SHA256]";
            send_error(c, err);
            return;
        }
    }
    // S3 combines only a CRC into the checksum of the whole object, and CRC64NVME into nothing else.
    const std::string_view type = r.header("x-amz-checksum-type");
    const bool full = type.empty() ? algo == checksum_algo::crc64nvme : type == "FULL_OBJECT";
    if ((!type.empty() && type != "FULL_OBJECT" && type != "COMPOSITE") || (!type.empty() && algo == checksum_algo::none) ||
        (full && !checksum_combinable(algo)) || (!full && algo == checksum_algo::crc64nvme))
    {
        err = make_error("InvalidRequest");
        err.message = "The checksum type " + std::string(type) + " is not supported with the checksum algorithm " +
                      std::string(checksum_name(algo)) + ".";
        send_error(c, err);
        return;
    }
    if (full)
        meta.extra.emplace_back(std::string(checksum_type_extra), "FULL_OBJECT");

    ++m_c.mpu_created;
    std::weak_ptr<conn> weak = c;
    const std::string bucket = r.bucket;
    const std::string key    = r.key;
    object_meta shown;
    if (const std::string* v = sse_value(meta))
        shown.extra.emplace_back(std::string(sse_extra), *v);
    m_node.mpu_create(bucket, key, std::move(meta), algo, [this, weak, bucket, key, shown, algo, full](st s, std::string id)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (s != st::ok)
        {
            send_error_st(cc, s);
            return;
        }
        response resp;
        resp.headers.emplace_back("Content-Type", "application/xml");
        sse_headers(cc->req, shown, resp.headers);
        if (algo != checksum_algo::none)
        {
            resp.headers.emplace_back("x-amz-checksum-algorithm", std::string(checksum_name(algo)));
            resp.headers.emplace_back("x-amz-checksum-type", full ? "FULL_OBJECT" : "COMPOSITE");
        }
        resp.body = initiate_multipart_xml(bucket, key, id);
        send_response(cc, std::move(resp));
    });
}

// ─── UploadPart ─────────────────────────────────────────────────────────────

void storage_run::op_upload_part(const std::shared_ptr<conn>& c)
{
    s3_request& r = c->req;
    // The body has not been read, so an answer given before it is does close the connection.
    const bool keep_alive = r.keep_alive;
    r.keep_alive = false;
    if (!valid_bucket_name(r.bucket))
    {
        send_error_st(c, st::invalid_bucket_name);
        return;
    }
    uint32_t number = 0;
    if (!part_number_of(c, number))
        return;

    std::weak_ptr<conn> weak = c;
    with_open_upload(c, number, [this, weak, number, keep_alive](checksum_algo algo, part_place place)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        s3_request& q = cc->req;
        q.keep_alive = keep_alive;
        const std::string id = std::string(q.get_query("uploadId"));
        // The part's own header names it by upload and number, since it is not an object.
        const std::string part_key = "mpu/" + id + "/" + std::to_string(number);
        object_meta   meta;
        sse_seal_spec seal;
        if (s3_error err; !sse_part_key(cc, place.sse, number, meta, seal, err))
        {
            deny_request(cc, err);
            return;
        }
        ++m_c.mpu_parts;
        start_put(cc, part_key, std::move(meta), m_node.mpu_part_committer(q.bucket, q.key, id, number), algo, {},
                  place, place.sse.empty() ? nullptr : &seal);
    });
}

// ─── UploadPartCopy ─────────────────────────────────────────────────────────

void storage_run::op_upload_part_copy(const std::shared_ptr<conn>& c)
{
    s3_request& r = c->req;
    uint32_t number = 0;
    if (!part_number_of(c, number))
        return;
    std::string src_bucket, src_key, src_version;
    s3_error    err;
    if (!parse_copy_source(r.header("x-amz-copy-source"), src_bucket, src_key, err, &src_version))
    {
        send_error(c, err, false, "ArgumentName", "x-amz-copy-source");
        return;
    }
    if (!m_store.has_bucket(src_bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }

    std::weak_ptr<conn> weak = c;
    with_open_upload(c, 0, [this, weak, number, src_bucket, src_key, src_version](checksum_algo algo, part_place place)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        // The source may be another shard's, whose header is then read from its file.
        auto go = [this, weak, number, src_bucket, src_key, src_version, algo, record = std::move(place.sse)]
            (st s, const object_meta& sm)
            {
                auto c2 = weak.lock();
                if (!c2 || c2->dead)
                    return;
                if (s != st::ok)
                {
                    send_error_st(c2, s);
                    return;
                }
                op_upload_part_copy_from(c2, number, algo, src_bucket, src_key, src_version, sm, record);
            };
        if (src_version.empty())
            m_store.stat_object(src_bucket, src_key, std::move(go));
        else
            m_store.stat_version(src_bucket, src_key, src_version, std::move(go));
    });
}

void storage_run::op_upload_part_copy_from(const std::shared_ptr<conn>& c, uint32_t number, checksum_algo algo,
                                           const std::string& src_bucket, const std::string& src_key,
                                           const std::string& src_version, const object_meta& src_meta,
                                           const std::string& record)
{
    s3_request& r = c->req;
    const object_meta* src = &src_meta;
    const std::string id = std::string(r.get_query("uploadId"));

    // Which bytes of the source: all of them, or the range the header names.
    uint64_t first = 0, len = src->size;
    if (const std::string_view range = r.header("x-amz-copy-source-range"); !range.empty())
    {
        // Only "bytes=first-last" is allowed here, with both ends inside the object.
        uint64_t lo = 0, hi = 0;
        const size_t dash = range.find('-');
        if (!range.starts_with("bytes=") || dash == std::string_view::npos ||
            !parse_u64(range.substr(6, dash - 6), lo) || !parse_u64(range.substr(dash + 1), hi) ||
            lo > hi || hi >= src->size)
        {
            s3_error e = make_error("InvalidArgument");
            e.message  = "The x-amz-copy-source-range value must be of the form bytes=first-last where first and last "
                         "are the zero-based offsets of the first and last bytes to copy";
            send_error(c, e, false, "ArgumentName", "x-amz-copy-source-range");
            return;
        }
        first = lo;
        len   = hi - lo + 1;
    }

    object_meta meta;
    if (algo != checksum_algo::none)
        meta.extra.emplace_back(std::string(checksum_header(algo)), std::string(checksum_b64_len(algo), 'A'));
    // The key that opens the source and the one the part is sealed under, both refused before a byte is read.
    std::optional<sse_key> src_customer;
    sse_seal_spec seal;
    sse_key probe{};
    if (s3_error err; !sse_customer(c, sse_c_copy_prefix, src_customer, err) ||
                      !sse_read_key(c, *src, sse_c_copy_prefix, probe, err) ||
                      !sse_part_key(c, record, number, meta, seal, err))
    {
        send_error(c, err);
        return;
    }
    const std::string part_key = "mpu/" + id + "/" + std::to_string(number);
    st why = st::ok;
    auto op = m_store.begin_put(r.bucket, part_key, std::move(meta), len, true, why, false,
                                record.empty() ? nullptr : &seal);
    if (!op)
    {
        send_error_st(c, why);
        return;
    }
    if (algo != checksum_algo::none)
        op->track_checksum(algo, {});
    op->set_committer(m_node.mpu_part_committer(r.bucket, r.key, id, number));
    ++m_c.mpu_parts;
    ++m_c.copies;
    if (!record.empty())
        ++m_c.sse_puts;

    // The source is read a window at a time into the part, with the put's own staging deciding how fast.
    feed_copy(c, std::move(op), src_bucket, src_key, src_version, std::move(src_customer), first, len,
              [this](const std::shared_ptr<conn>& cc, put_result pr)
    {
        response resp;
        resp.headers.emplace_back("Content-Type", "application/xml");
        sse_headers(cc->req, pr.meta, resp.headers);
        std::string x(xml_decl);
        x += "<CopyPartResult xmlns=\"" + std::string(s3_xmlns) + "\"><LastModified>" + iso8601(pr.meta.mtime_ms) +
             "</LastModified><ETag>" + quoted_etag(pr.meta) + "</ETag>";
        for (const auto& [n, v] : pr.meta.extra)
            if (const checksum_algo a = checksum_from_header(n); a != checksum_algo::none)
                x += checksum_element(a, v);
        x += "</CopyPartResult>";
        resp.body = std::move(x);
        send_response(cc, std::move(resp));
    });
}

// ─── CompleteMultipartUpload ────────────────────────────────────────────────

void storage_run::op_complete_multipart(const std::shared_ptr<conn>& c)
{
    const s3_request& r = c->req;
    if (!m_store.has_bucket(r.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }

    std::vector<complete_part> parts;
    if (!parse_complete_request(c->body, parts))
    {
        send_error(c, make_error("MalformedXML"));
        return;
    }

    // The client's key, which S3 lets a completion leave out, binds an SSE-C object's part list when it is given.
    std::optional<sse_key> customer;
    if (s3_error err; !sse_customer(c, sse_c_prefix, customer, err))
    {
        send_error(c, err);
        return;
    }

    const std::string   bucket = r.bucket;
    const std::string   key    = r.key;
    const std::string   id     = std::string(r.get_query("uploadId"));
    const put_condition cond{std::string(r.header("if-match")), std::string(r.header("if-none-match"))};
    // Refused here when this shard holds the key, so no copy is made only to be refused at its commit.
    if (cond.any() && m_store.owns(bucket, key))
        if (const st cs = check_put_condition(cond, m_store.find(bucket, key)); cs != st::ok)
        {
            send_error(c, cs == st::no_such_key ? make_error("NoSuchKey") : make_error("PreconditionFailed"));
            return;
        }
    std::weak_ptr<conn> weak = c;
    // The object's checksum as the client computed it, which the one made from the parts must be.
    std::string promised;
    for (const auto& h : r.headers)
        if (is_checksum_header(h.name))
            promised = std::string(h.name) + ":" + std::string(h.value);
    auto bind = [this, customer, promised](object_meta& m)
    {
        if (!promised.empty())
        {
            std::string held;
            for (const auto& [n, v] : m.extra)
                if (is_checksum_header(n))
                    held = n + ":" + v;
            // A composite value may be given with or without its -N.
            if (held != promised && held.substr(0, held.rfind('-')) != promised)
            {
                s3_error e = make_error("BadDigest");
                e.message = "The " + promised.substr(0, promised.find(':')) + " you specified did not match the calculated checksum.";
                return e;
            }
        }
        return sse_bind_parts(m, customer);
    };
    m_node.mpu_complete(bucket, key, id, std::move(parts),
        [weak]()
        {
            if (auto cc = weak.lock(); cc && !cc->dead)
                cc->last_progress = std::chrono::steady_clock::now();
        },
        [this, weak, bucket, key, id](complete_result res)
        {
            auto cc = weak.lock();
            if (!cc || cc->dead)
                return;
            if (res.error.code == "NoSuchUpload")
            {
                completed_before(cc, id, std::move(res.error));
                return;
            }
            if (!res.error.code.empty())
            {
                send_error(cc, res.error);
                return;
            }
            ++m_c.mpu_completed;
            ++m_c.puts;
            // A completed upload is a put like any other, whatever shard it was assembled on.
            send_completed(cc, res.meta, res.checksum_b64);
            notify_put(bucket, key, res.meta);
        }, std::move(bind), std::move(cond));
}

void storage_run::send_completed(const std::shared_ptr<conn>& c, const object_meta& m, const std::string& checksum_b64)
{
    const s3_request& r = c->req;
    const checksum_algo algo = [&]
    {
        for (const auto& [n, v] : m.extra)
            if (const checksum_algo a = checksum_from_header(n); a != checksum_algo::none)
                return a;
        return checksum_algo::none;
    }();
    response resp;
    resp.headers.emplace_back("Content-Type", "application/xml");
    if (has_version(m))
        resp.headers.emplace_back("x-amz-version-id", version_of(m).id);
    sse_headers(r, m, resp.headers);
    resp.body = complete_multipart_xml("http://" + std::string(r.host) + "/" + r.bucket + "/" + r.key, r.bucket, r.key,
                                       m.etag(), algo, checksum_b64);
    send_response(c, std::move(resp));
}

void storage_run::completed_before(const std::shared_ptr<conn>& c, const std::string& id, s3_error missing)
{
    // A completion sent again, after an answer that never arrived, finds the object it made and is answered as before.
    auto answer = [this, id, missing = std::move(missing)](const std::shared_ptr<conn>& cc, const object_meta* m) mutable
    {
        const std::string* from = nullptr;
        if (m)
            for (const auto& [n, v] : m->extra)
                if (n == upload_id_extra)
                    from = &v;
        if (from && *from == id)
        {
            std::string checksum;
            for (const auto& [n, v] : m->extra)
                if (checksum_from_header(n) != checksum_algo::none)
                    checksum = v;
            send_completed(cc, *m, checksum);
            return;
        }
        send_error(cc, missing, false, "UploadId", id);
    };
    const s3_request& r = c->req;
    if (m_store.owns(r.bucket, r.key))
    {
        answer(c, m_store.find(r.bucket, r.key));
        return;
    }
    std::weak_ptr<conn> weak = c;
    m_store.stat_foreign(r.bucket, r.key, [weak, answer](st s, const object_meta& m) mutable
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        answer(cc, s == st::ok ? &m : nullptr);
    });
}

// ─── AbortMultipartUpload ───────────────────────────────────────────────────

void storage_run::op_abort_multipart(const std::shared_ptr<conn>& c)
{
    const s3_request& r = c->req;
    if (!m_store.has_bucket(r.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    std::weak_ptr<conn> weak = c;
    const std::string id = std::string(r.get_query("uploadId"));
    m_node.mpu_abort(r.bucket, r.key, id, [this, weak, id](bool found)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (!found)
        {
            send_error(cc, make_error("NoSuchUpload"), false, "UploadId", id);
            return;
        }
        ++m_c.mpu_aborted;
        response resp;
        resp.status = 204;
        send_response(cc, std::move(resp));
    });
}

// ─── ListParts ──────────────────────────────────────────────────────────────

void storage_run::op_list_parts(const std::shared_ptr<conn>& c)
{
    const s3_request& r = c->req;
    if (!m_store.has_bucket(r.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }

    auto bad = [&](std::string_view name, std::string_view msg)
    {
        s3_error e = make_error("InvalidArgument");
        e.message  = std::string(msg);
        send_error(c, e, false, "ArgumentName", name);
    };
    uint32_t max_parts = list_page_max;
    if (r.has_query("max-parts"))
    {
        if (!parse_u32(r.get_query("max-parts"), max_parts))
        {
            bad("max-parts", "Provided max-parts not an integer or within integer range");
            return;
        }
        max_parts = std::min(max_parts, list_page_max);
    }
    uint32_t marker = 0;
    if (r.has_query("part-number-marker") && !parse_u32(r.get_query("part-number-marker"), marker))
    {
        bad("part-number-marker", "Provided part-number-marker not an integer or within integer range");
        return;
    }

    std::weak_ptr<conn> weak = c;
    const std::string id = std::string(r.get_query("uploadId"));
    m_node.mpu_parts(r.bucket, r.key, id, marker, max_parts,
        [this, weak, id, marker, max_parts](parts_page pg)
        {
            auto cc = weak.lock();
            if (!cc || cc->dead)
                return;
            if (pg.status == st::io_error)
            {
                send_error_st(cc, pg.status);
                return;
            }
            if (pg.status != st::ok)
            {
                send_error(cc, make_error("NoSuchUpload"), false, "UploadId", id);
                return;
            }
            list_parts_render lr;
            lr.bucket    = cc->req.bucket;
            lr.key       = pg.key;
            lr.upload_id = pg.id;
            lr.owner_id   = std::string(owner_of(cc->req.bucket));
            lr.owner_name = display_of(lr.owner_id);
            lr.part_number_marker = marker;
            lr.max_parts = max_parts;
            lr.algo      = pg.algo;
            lr.truncated = pg.truncated;
            lr.next_part_number_marker = pg.next_marker;

            response resp;
            resp.headers.emplace_back("Content-Type", "application/xml");
            resp.body = list_parts_xml(lr, pg.rows);
            send_response(cc, std::move(resp));
        });
}

// ─── ListMultipartUploads ───────────────────────────────────────────────────

void storage_run::op_list_uploads(const std::shared_ptr<conn>& c)
{
    const s3_request& r = c->req;
    if (!m_store.has_bucket(r.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    ++m_c.lists;

    uint32_t max_uploads = list_page_max;
    if (r.has_query("max-uploads"))
    {
        if (!parse_u32(r.get_query("max-uploads"), max_uploads))
        {
            s3_error e = make_error("InvalidArgument");
            e.message  = "Provided max-uploads not an integer or within integer range";
            send_error(c, e, false, "ArgumentName", "max-uploads");
            return;
        }
        max_uploads = std::min(max_uploads, list_page_max);
    }
    bool url_enc = false;
    if (r.has_query("encoding-type"))
    {
        if (r.get_query("encoding-type") != "url")
        {
            s3_error e = make_error("InvalidArgument");
            e.message  = "Invalid Encoding Method specified in Request";
            send_error(c, e, false, "ArgumentName", "encoding-type");
            return;
        }
        url_enc = true;
    }

    const std::string prefix    = std::string(r.get_query("prefix"));
    const std::string delimiter = std::string(r.get_query("delimiter"));
    const std::string key_marker = std::string(r.get_query("key-marker"));
    const std::string id_marker  = std::string(r.get_query("upload-id-marker"));

    // Every shard holds the uploads of the keys it owns, so the listing is theirs together.
    std::weak_ptr<conn> weak = c;
    m_node.mpu_list(r.bucket, [this, weak, max_uploads, url_enc, prefix, delimiter, key_marker, id_marker]
                              (st ls, std::vector<wire::upload_stub> all)
    {
    auto cc = weak.lock();
    if (!cc || cc->dead)
        return;
    if (ls != st::ok)
    {
        send_error_st(cc, ls);
        return;
    }
    const s3_request& r = cc->req;
    std::sort(all.begin(), all.end(), [](const wire::upload_stub& a, const wire::upload_stub& b)
    {
        return std::tie(a.key, a.initiated_ms, a.id) < std::tie(b.key, b.initiated_ms, b.id);
    });

    // A marker that is a rolled-up prefix stands for the whole group.
    std::string marker_group;
    if (!delimiter.empty() && key_marker.starts_with(prefix))
    {
        const size_t d = key_marker.find(delimiter, prefix.size());
        if (d != std::string::npos)
            marker_group = key_marker.substr(0, d + delimiter.size());
    }

    std::vector<upload_row>  rows;
    std::vector<std::string> prefixes;
    list_uploads_render lr;
    bool passed_marker = key_marker.empty();
    size_t taken = 0;
    std::string last_key, last_id;
    for (const wire::upload_stub& us : all)
    {
        const wire::upload_stub* u = &us;
        if (!u->key.starts_with(prefix))
            continue;
        if (!passed_marker)
        {
            if (!marker_group.empty())
            {
                if (u->key.starts_with(marker_group))
                    continue;
                if (u->key > key_marker)
                    passed_marker = true;
                else
                    continue;
            }
            else if (u->key < key_marker)
                continue;
            else if (u->key == key_marker)
            {
                if (id_marker.empty())
                    continue;
                if (u->id == id_marker)
                    passed_marker = true;
                continue;
            }
            else
                passed_marker = true;
        }

        std::string group;
        if (!delimiter.empty())
        {
            const size_t d = u->key.find(delimiter, prefix.size());
            if (d != std::string::npos)
                group = u->key.substr(0, d + delimiter.size());
        }
        if (!group.empty())
        {
            if (!prefixes.empty() && prefixes.back() == group)
                continue;
            if (taken == max_uploads)
            {
                lr.truncated = true;
                break;
            }
            prefixes.push_back(group);
            ++taken;
            last_key = group;
            last_id.clear();
            continue;
        }
        if (taken == max_uploads)
        {
            lr.truncated = true;
            break;
        }
        rows.push_back({u->key, u->id, u->initiated_ms});
        ++taken;
        last_key = u->key;
        last_id  = u->id;
    }

    lr.bucket           = r.bucket;
    lr.prefix           = prefix;
    lr.delimiter        = delimiter;
    lr.key_marker       = key_marker;
    lr.upload_id_marker = id_marker;
    lr.next_key_marker  = last_key;
    lr.next_upload_id_marker = last_id;
    lr.owner_id         = std::string(owner_of(cc->req.bucket));
    lr.owner_name       = display_of(lr.owner_id);
    lr.max_uploads      = max_uploads;
    lr.url_encode_keys  = url_enc;

    response resp;
    resp.headers.emplace_back("Content-Type", "application/xml");
    resp.body = list_uploads_xml(lr, rows, prefixes);
    send_response(cc, std::move(resp));
    });
}

// ─── Expiry ─────────────────────────────────────────────────────────────────

void storage_run::reap_uploads()
{
    if (m_mpu_expire_secs == 0)
        return;
    const int64_t now_ms = static_cast<int64_t>(m_store.now_ms());
    const int64_t cutoff = now_ms - static_cast<int64_t>(m_mpu_expire_secs) * 1000;
    if (const size_t n = m_mpu.expire(cutoff))
        LOG_INFO(("storage: " + std::to_string(n) + " multipart upload(s) older than " +
                  std::to_string(m_mpu_expire_secs) + " second(s) aborted").c_str());
}

}   // namespace socketley::storage
