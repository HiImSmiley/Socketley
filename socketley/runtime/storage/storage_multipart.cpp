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
    // The tags are kept with the upload and land on the object its completion makes.
    if (!object_meta_from_headers(c, meta, err) || !tagging_from_header(r, meta, err))
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
    m_node.mpu_create(bucket, key, std::move(meta), algo, [this, weak, bucket, key](st s, std::string id)
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
        ++m_c.mpu_parts;
        start_put(cc, part_key, object_meta{}, m_node.mpu_part_committer(q.bucket, q.key, id, number), algo, false,
                  place);
    });
}

// ─── UploadPartCopy ─────────────────────────────────────────────────────────

void storage_run::op_upload_part_copy(const std::shared_ptr<conn>& c)
{
    s3_request& r = c->req;
    uint32_t number = 0;
    if (!part_number_of(c, number))
        return;
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

    std::weak_ptr<conn> weak = c;
    with_open_upload(c, 0, [this, weak, number, src_bucket, src_key](checksum_algo algo, part_place)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        // The source may be another shard's, whose header is then read from its file.
        m_store.stat_object(src_bucket, src_key,
            [this, weak, number, src_bucket, src_key, algo](st s, const object_meta& sm)
            {
                auto c2 = weak.lock();
                if (!c2 || c2->dead)
                    return;
                if (s != st::ok)
                {
                    send_error_st(c2, s);
                    return;
                }
                op_upload_part_copy_from(c2, number, algo, src_bucket, src_key, sm);
            });
    });
}

void storage_run::op_upload_part_copy_from(const std::shared_ptr<conn>& c, uint32_t number, checksum_algo algo,
                                           const std::string& src_bucket, const std::string& src_key,
                                           const object_meta& src_meta)
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
    const std::string part_key = "mpu/" + id + "/" + std::to_string(number);
    st why = st::ok;
    auto op = m_store.begin_put(r.bucket, part_key, std::move(meta), len, true, why);
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

    const std::string   bucket = r.bucket;
    const std::string   key    = r.key;
    const std::string   host(r.host);
    const std::string   id     = std::string(r.get_query("uploadId"));
    std::weak_ptr<conn> weak = c;
    m_node.mpu_complete(bucket, key, id, std::move(parts),
        [weak]()
        {
            if (auto cc = weak.lock(); cc && !cc->dead)
                cc->last_progress = std::chrono::steady_clock::now();
        },
        [this, weak, bucket, key, host, id](complete_result res)
        {
            auto cc = weak.lock();
            if (!cc || cc->dead)
                return;
            if (!res.error.code.empty())
            {
                send_error(cc, res.error, false,
                           res.error.code == "NoSuchUpload" ? "UploadId" : std::string_view{},
                           res.error.code == "NoSuchUpload" ? std::string_view(id) : std::string_view{});
                return;
            }
            ++m_c.mpu_completed;
            ++m_c.puts;
            // A completed upload is a put like any other, whatever shard it was assembled on.
            const checksum_algo algo = [&]
            {
                for (const auto& [n, v] : res.meta.extra)
                    if (const checksum_algo a = checksum_from_header(n); a != checksum_algo::none)
                        return a;
                return checksum_algo::none;
            }();
            response resp;
            resp.headers.emplace_back("Content-Type", "application/xml");
            resp.body = complete_multipart_xml("http://" + host + "/" + bucket + "/" + key, bucket, key,
                                               res.meta.etag(), algo, res.checksum_b64);
            send_response(cc, std::move(resp));
            notify_put(bucket, key, res.meta);
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
            const std::string owner = owner_id();
            lr.owner_id  = owner;
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
    const std::string owner = owner_id();
    lr.owner_id         = owner;
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
