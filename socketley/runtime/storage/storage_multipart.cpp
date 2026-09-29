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

// The upload a request names, when there is one for this bucket and key.
// Answers NoSuchUpload itself and returns null when there is not.
const mpu_upload* storage_run::upload_for(const std::shared_ptr<conn>& c)
{
    const s3_request& r = c->req;
    if (!m_store.has_bucket(r.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return nullptr;
    }
    const mpu_upload* up = m_mpu.find(r.bucket, r.get_query("uploadId"));
    if (!up || up->key != r.key || up->state == mpu_state::removing)
    {
        send_error(c, make_error("NoSuchUpload"), false, "UploadId", r.get_query("uploadId"));
        return nullptr;
    }
    return up;
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
    if (!object_meta_from_headers(c, meta, err))
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

    ++m_c.mpu_created;
    std::weak_ptr<conn> weak = c;
    const std::string bucket = r.bucket;
    const std::string key    = r.key;
    m_mpu.create(bucket, key, std::move(meta), algo, [this, weak, bucket, key](st s, std::string id)
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
    const mpu_upload* up = upload_for(c);
    if (!up)
        return;

    checksum_algo algo = checksum_algo::none;
    if (m_mpu.begin_part(r.bucket, up->id, algo) != st::ok)
    {
        send_error(c, make_error("NoSuchUpload"), true, "UploadId", r.get_query("uploadId"));
        return;
    }
    r.keep_alive = keep_alive;

    // The part's own header names it by upload and number, since it is not an object.
    const std::string part_key = "mpu/" + up->id + "/" + std::to_string(number);
    ++m_c.mpu_parts;
    start_put(c, part_key, object_meta{}, m_mpu.part_committer(r.bucket, up->id, number), algo);
}

// ─── UploadPartCopy ─────────────────────────────────────────────────────────

void storage_run::op_upload_part_copy(const std::shared_ptr<conn>& c)
{
    s3_request& r = c->req;
    uint32_t number = 0;
    if (!part_number_of(c, number))
        return;
    const mpu_upload* up = upload_for(c);
    if (!up)
        return;
    checksum_algo algo = checksum_algo::none;
    if (m_mpu.begin_part(r.bucket, up->id, algo) != st::ok)
    {
        send_error(c, make_error("NoSuchUpload"), false, "UploadId", r.get_query("uploadId"));
        return;
    }

    std::string src_bucket, src_key;
    s3_error    err;
    if (!parse_copy_source(r.header("x-amz-copy-source"), src_bucket, src_key, err))
    {
        send_error(c, err, false, "ArgumentName", "x-amz-copy-source");
        return;
    }
    if (!m_store.has_bucket(src_bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    const object_meta* src = m_store.find(src_bucket, src_key);
    if (!src)
    {
        send_error_st(c, st::no_such_key);
        return;
    }

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
    const std::string part_key = "mpu/" + up->id + "/" + std::to_string(number);
    st why = st::ok;
    auto op = m_store.begin_put(r.bucket, part_key, std::move(meta), len, true, why);
    if (!op)
    {
        send_error_st(c, why);
        return;
    }
    if (algo != checksum_algo::none)
        op->track_checksum(algo, {});
    op->set_committer(m_mpu.part_committer(r.bucket, up->id, number));
    ++m_c.mpu_parts;
    ++m_c.copies;

    // The source is read a piece at a time into the part, with the put's own
    // staging deciding how fast.  The run holds itself until it ends, so it
    // is alive while a read or a wait for the put is owed to it.
    struct copy_run : std::enable_shared_from_this<copy_run>
    {
        storage_run*            run{nullptr};
        std::shared_ptr<put_op> op;
        std::weak_ptr<conn>     owner;
        int         fd{-1};
        uint64_t    off{0};
        uint64_t    left{0};
        std::string buf;
        size_t      buf_off{0};
        bool        reading{false};
        bool        ended{false};
        std::shared_ptr<copy_run> keep;

        void retire()
        {
            ended = true;
            if (fd >= 0)
                run->m_loop.close_fd(fd);
            fd = -1;
            keep.reset();
        }

        void fail(st why)
        {
            if (ended)
                return;
            auto self = shared_from_this();
            op->abort();
            retire();
            if (auto cc = owner.lock(); cc && !cc->dead)
                run->send_error_st(cc, why);
        }

        void answer(put_result pr)
        {
            auto self = shared_from_this();
            retire();
            auto cc = owner.lock();
            if (!cc || cc->dead)
                return;
            if (pr.status != st::ok)
            {
                run->send_error_st(cc, pr.status);
                return;
            }
            response resp;
            resp.headers.emplace_back("Content-Type", "application/xml");
            std::string x(xml_decl);
            x += "<CopyPartResult xmlns=\"" + std::string(s3_xmlns) + "\"><LastModified>" + iso8601(pr.meta.mtime_ms) +
                 "</LastModified><ETag>" + quoted_etag(pr.meta) + "</ETag>";
            for (const auto& [n, v] : pr.meta.extra)
                if (const checksum_algo a = checksum_from_header(n); a != checksum_algo::none)
                    x += checksum_element(a, v);
            x += "</CopyPartResult>";
            resp.body = std::move(x);
            run->send_response(cc, std::move(resp));
        }

        void pump()
        {
            auto self = shared_from_this();
            for (;;)
            {
                if (ended || reading)
                    return;
                auto cc = owner.lock();
                if (!cc || cc->dead)
                {
                    op->abort();
                    retire();
                    return;
                }
                if (op->failed())
                {
                    fail(op->status());
                    return;
                }
                if (buf_off < buf.size())
                {
                    buf_off += op->append(buf.data() + buf_off, buf.size() - buf_off);
                    if (op->failed())
                        continue;
                    if (buf_off < buf.size())
                        return;   // the put's ready callback comes back here
                }
                if (left == 0)
                {
                    // The put answers through the callback, which holds the run until then.
                    op->finish(nullptr, [self](put_result pr) { self->answer(std::move(pr)); });
                    ended = true;
                    return;
                }
                const uint32_t n = static_cast<uint32_t>(std::min<uint64_t>(left, 1u << 20));
                buf.resize(n);
                buf_off = 0;
                reading = true;
                if (!run->m_io.pread(fd, buf.data(), n, off, [self, n](int64_t rn)
                    {
                        self->reading = false;
                        if (rn != static_cast<int64_t>(n))
                        {
                            self->fail(st::io_error);
                            return;
                        }
                        self->off  += n;
                        self->left -= n;
                        self->pump();
                    }))
                {
                    reading = false;
                    fail(st::io_error);
                }
                return;
            }
        }
    };
    auto cr = std::make_shared<copy_run>();
    cr->run   = this;
    cr->op    = std::move(op);
    cr->owner = c;
    cr->left  = len;
    cr->keep  = cr;
    std::weak_ptr<copy_run> weak = cr;
    cr->op->on_ready([weak]()
    {
        if (auto p = weak.lock())
            p->pump();
    });
    cr->op->on_failed([weak](st why)
    {
        if (auto p = weak.lock())
            p->fail(why);
    });

    // The source's file, opened with its header read so the bytes are found.
    m_store.open_object(src_bucket, src_key, 0, [this, weak, first](open_result o)
    {
        auto p = weak.lock();
        if (!p || p->ended)
        {
            if (o.fd >= 0)
                m_loop.close_fd(o.fd);
            return;
        }
        if (o.status != st::ok)
        {
            p->fail(o.status);
            return;
        }
        p->fd  = o.fd;
        p->off = o.data_off + first;
        p->pump();
    });
}

// ─── CompleteMultipartUpload ────────────────────────────────────────────────

void storage_run::op_complete_multipart(const std::shared_ptr<conn>& c)
{
    const s3_request& r = c->req;
    const mpu_upload* up = upload_for(c);
    if (!up)
        return;

    std::vector<complete_part> parts;
    if (!parse_complete_request(c->body, parts))
    {
        send_error(c, make_error("MalformedXML"));
        return;
    }

    const checksum_algo algo = up->algo;
    const std::string   bucket = r.bucket;
    const std::string   key    = r.key;
    const std::string   host   = r.host;
    std::weak_ptr<conn> weak = c;
    m_mpu.complete(bucket, up->id, std::move(parts),
        [weak]()
        {
            if (auto cc = weak.lock(); cc && !cc->dead)
                cc->last_progress = std::chrono::steady_clock::now();
        },
        [this, weak, bucket, key, host, algo](complete_result res)
        {
            auto cc = weak.lock();
            if (!cc || cc->dead)
                return;
            if (!res.error.code.empty())
            {
                send_error(cc, res.error);
                return;
            }
            ++m_c.mpu_completed;
            ++m_c.puts;
            response resp;
            resp.headers.emplace_back("Content-Type", "application/xml");
            resp.body = complete_multipart_xml("http://" + host + "/" + bucket + "/" + key, bucket, key,
                                               res.meta.etag(), algo, res.checksum_b64);
            send_response(cc, std::move(resp));
        });
}

// ─── AbortMultipartUpload ───────────────────────────────────────────────────

void storage_run::op_abort_multipart(const std::shared_ptr<conn>& c)
{
    const mpu_upload* up = upload_for(c);
    if (!up)
        return;
    std::weak_ptr<conn> weak = c;
    if (!m_mpu.abort(c->req.bucket, up->id, [this, weak]()
        {
            auto cc = weak.lock();
            if (!cc || cc->dead)
                return;
            ++m_c.mpu_aborted;
            response resp;
            resp.status = 204;
            send_response(cc, std::move(resp));
        }))
        send_error(c, make_error("NoSuchUpload"), false, "UploadId", c->req.get_query("uploadId"));
}

// ─── ListParts ──────────────────────────────────────────────────────────────

void storage_run::op_list_parts(const std::shared_ptr<conn>& c)
{
    const s3_request& r = c->req;
    const mpu_upload* up = upload_for(c);
    if (!up)
        return;

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

    list_parts_render lr;
    lr.bucket    = r.bucket;
    lr.key       = up->key;
    lr.upload_id = up->id;
    const std::string owner = owner_id();
    lr.owner_id  = owner;
    lr.part_number_marker = marker;
    lr.max_parts = max_parts;
    lr.algo      = up->algo;

    std::vector<part_row> rows;
    for (auto it = up->parts.upper_bound(marker); it != up->parts.end(); ++it)
    {
        if (rows.size() == max_parts)
        {
            lr.truncated = true;
            break;
        }
        const mpu_part& p = it->second;
        rows.push_back({p.number, p.mtime_ms, p.etag(), p.size, up->algo, p.checksum_b64});
        lr.next_part_number_marker = p.number;
    }

    response resp;
    resp.headers.emplace_back("Content-Type", "application/xml");
    resp.body = list_parts_xml(lr, rows);
    send_response(c, std::move(resp));
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

    std::vector<const mpu_upload*> all = m_mpu.uploads_of(r.bucket);
    std::sort(all.begin(), all.end(), [](const mpu_upload* a, const mpu_upload* b)
    {
        return std::tie(a->key, a->initiated_ms, a->id) < std::tie(b->key, b->initiated_ms, b->id);
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
    for (const mpu_upload* u : all)
    {
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
    const std::string owner = owner_id();
    lr.owner_id         = owner;
    lr.max_uploads      = max_uploads;
    lr.url_encode_keys  = url_enc;

    response resp;
    resp.headers.emplace_back("Content-Type", "application/xml");
    resp.body = list_uploads_xml(lr, rows, prefixes);
    send_response(c, std::move(resp));
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
