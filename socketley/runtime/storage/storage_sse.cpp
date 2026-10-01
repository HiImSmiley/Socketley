// Server-side encryption over S3: what a request asks for and may read, the
// keys an object's record names, the bucket's default, and the paths a body
// takes when its bytes on disk are not its bytes.
#include "storage_run.h"

#include <cstring>

#include "s3_encryption.h"
#include "s3_xml.h"
#include "storage_instance.h"
#include "../../shared/logging.h"

namespace socketley::storage
{

namespace
{

s3_error sse_error(std::string_view code, std::string message)
{
    s3_error e = make_error(code);
    e.message  = std::move(message);
    return e;
}

// The three SSE-C headers under one of the two prefixes, spelled out so a lookup builds no string.
struct customer_names
{
    std::string_view algorithm, key, key_md5;
};

constexpr customer_names own_names{"x-amz-server-side-encryption-customer-algorithm",
                                   "x-amz-server-side-encryption-customer-key",
                                   "x-amz-server-side-encryption-customer-key-md5"};
constexpr customer_names copy_names{"x-amz-copy-source-server-side-encryption-customer-algorithm",
                                    "x-amz-copy-source-server-side-encryption-customer-key",
                                    "x-amz-copy-source-server-side-encryption-customer-key-md5"};

const customer_names& names_of(std::string_view prefix)
{
    return prefix == sse_c_copy_prefix ? copy_names : own_names;
}

}   // namespace

void sse_headers(const s3_request& r, const object_meta& m, std::vector<std::pair<std::string, std::string>>& out,
                 std::string_view prefix)
{
    switch (sse_mode_of(m))
    {
        case sse_mode::none:
            return;
        case sse_mode::s3:
            out.emplace_back("x-amz-server-side-encryption", "AES256");
            return;
        case sse_mode::c:
        {
            out.emplace_back("x-amz-server-side-encryption-customer-algorithm", "AES256");
            const std::string_view md5 = r.header(names_of(prefix).key_md5);
            if (!md5.empty())
                out.emplace_back("x-amz-server-side-encryption-customer-key-MD5", std::string(md5));
            return;
        }
    }
}

void storage_run::set_sse_master(const sse_key& k)
{
    m_master     = k;
    m_master_kid = sse_key_id(k);
    m_has_master = true;
}

// ─── What a request asks for ────────────────────────────────────────────────

bool storage_run::sse_customer(const std::shared_ptr<conn>& c, std::string_view prefix, std::optional<sse_key>& out,
                               s3_error& err)
{
    const s3_request& r = c->req;
    out.reset();
    const customer_names& n = names_of(prefix);
    const std::string_view alg = r.header(n.algorithm);
    const std::string_view key = r.header(n.key);
    const std::string_view md5 = r.header(n.key_md5);
    if (alg.empty() && key.empty() && md5.empty())
        return true;
    // A key sent in the clear is a key given away, as S3 judges it, whatever else the request says.
    if (!c->ssl)
    {
        err = sse_error("InvalidRequest", "Requests specifying Server Side Encryption with Customer provided keys "
                                          "must be made over a secure connection.");
        return false;
    }
    if (alg.empty())
    {
        err = sse_error("InvalidArgument", "Requests specifying Server Side Encryption with Customer provided keys "
                                           "must provide a valid encryption algorithm.");
        return false;
    }
    if (alg != "AES256")
    {
        err = make_error("InvalidEncryptionAlgorithmError");
        return false;
    }
    std::string raw;
    if (key.empty() || !base64_decode(key, raw) || raw.size() != sse_key_bytes)
    {
        err = sse_error("InvalidArgument", "The secret key was invalid for the specified algorithm.");
        return false;
    }
    std::string raw_md5;
    if (md5.empty())
    {
        err = sse_error("InvalidArgument", "Requests specifying Server Side Encryption with Customer provided keys "
                                           "must provide the client calculated MD5 of the secret key.");
        return false;
    }
    const md5_t want = md5_of(raw);
    if (!base64_decode(md5, raw_md5) || raw_md5.size() != want.size() ||
        std::memcmp(raw_md5.data(), want.data(), want.size()) != 0)
    {
        err = sse_error("InvalidArgument", "The calculated MD5 hash of the key did not match the hash that was provided.");
        return false;
    }
    sse_key k{};
    std::memcpy(k.data(), raw.data(), k.size());
    out = k;
    return true;
}

bool storage_run::sse_for_write(const std::shared_ptr<conn>& c, std::string_view bucket, sse_ask& out, s3_error& err)
{
    const s3_request& r = c->req;
    out = sse_ask{};
    if (const std::string_view h = r.header("x-amz-server-side-encryption"); !h.empty())
    {
        out.named = true;
        if (h == "aws:kms" || h == "aws:kms:dsse")
        {
            err = sse_error("NotImplemented", "SSE-KMS is not supported by this runtime; AES256 is");
            return false;
        }
        if (h != "AES256")
        {
            err = sse_error("InvalidArgument", "The encryption method specified is not supported");
            return false;
        }
        out.mode = sse_mode::s3;
    }
    if (r.has_header("x-amz-server-side-encryption-aws-kms-key-id") ||
        r.has_header("x-amz-server-side-encryption-context"))
    {
        err = sse_error("InvalidArgument", "A KMS key or context is only valid with aws:kms, which this runtime "
                                           "does not support");
        return false;
    }
    if (!sse_customer(c, sse_c_prefix, out.customer, err))
        return false;
    if (out.customer)
    {
        if (out.mode == sse_mode::s3)
        {
            err = sse_error("InvalidArgument", "Server Side Encryption with Customer provided key is incompatible "
                                               "with the encryption method specified");
            return false;
        }
        out.mode  = sse_mode::c;
        out.named = true;
    }
    if (out.mode == sse_mode::none && m_store.bucket_encrypts(bucket))
        out.mode = sse_mode::s3;
    if (out.mode == sse_mode::s3 && !m_has_master)
    {
        err = sse_error("NotImplemented", "Server side encryption with AES256 needs a master key, and this runtime "
                                          "was given no --sse-key-file");
        return false;
    }
    return true;
}

bool storage_run::sse_new_key(const sse_ask& ask, bool per_part, object_meta& meta, sse_seal_spec& seal,
                              s3_error& err)
{
    sse_record rec;
    rec.mode     = ask.mode;
    rec.per_part = per_part;
    seal.key         = sse_random_key();
    seal.opaque_etag = ask.mode == sse_mode::c;
    if (ask.mode == sse_mode::s3)
        rec.kid = m_master_kid;
    if ((ask.mode == sse_mode::c && !ask.customer) ||
        !sse_wrap(ask.mode == sse_mode::c ? *ask.customer : m_master, seal.key, rec.wrapped))
    {
        err = sse_error("InternalError", "The object's data key could not be wrapped");
        return false;
    }
    std::erase_if(meta.extra, [](const auto& e) { return e.first == sse_extra; });
    meta.extra.emplace_back(std::string(sse_extra), encode_sse(rec));
    return true;
}

bool storage_run::sse_data_key(const object_meta& m, const std::optional<sse_key>& customer, sse_key& out,
                               s3_error& err) const
{
    sse_record rec;
    const std::string* v = sse_value(m);
    if (!v || !decode_sse(*v, rec))
    {
        err = sse_error("InternalError", "The object's encryption record cannot be read");
        return false;
    }
    if (rec.mode == sse_mode::c)
    {
        if (!customer)
        {
            err = sse_error("InvalidRequest", "The object was stored using a form of Server Side Encryption. The "
                                              "correct parameters must be provided to retrieve the object.");
            return false;
        }
        if (!sse_unwrap(*customer, rec.wrapped, out))
        {
            err = sse_error("AccessDenied", "The SSE-C key provided does not match the key the object was stored with");
            return false;
        }
        return true;
    }
    if (customer)
    {
        err = sse_error("InvalidRequest", "The encryption parameters are not applicable to this object.");
        return false;
    }
    if (!m_has_master)
    {
        err = sse_error("InternalError", "The object is encrypted with AES256 and this runtime has no "
                                         "--sse-key-file to open it");
        return false;
    }
    if (rec.kid != m_master_kid || !sse_unwrap(m_master, rec.wrapped, out))
    {
        err = sse_error("InternalError", "The object was encrypted under another master key than this runtime's "
                                         "--sse-key-file");
        return false;
    }
    return true;
}

bool storage_run::sse_read_key(const std::shared_ptr<conn>& c, const object_meta& m, std::string_view prefix,
                               sse_key& out, s3_error& err, bool need_key)
{
    std::optional<sse_key> customer;
    if (!sse_customer(c, prefix, customer, err))
        return false;
    if (!is_encrypted(m))
    {
        if (!customer)
            return true;
        err = sse_error("InvalidRequest", "The encryption parameters are not applicable to this object.");
        return false;
    }
    // A client's key is checked on every read, its bytes wanted or not, as S3 checks it on a HEAD.
    if (!need_key && !customer && sse_mode_of(m) == sse_mode::s3)
        return true;
    return sse_data_key(m, customer, out, err);
}

bool storage_run::sse_part_key(const std::shared_ptr<conn>& c, const std::string& record, object_meta& meta,
                               sse_seal_spec& seal, s3_error& err)
{
    object_meta upload;
    if (!record.empty())
        upload.extra.emplace_back(std::string(sse_extra), record);
    sse_key key{};
    // An upload stored in the clear takes no key, and is refused one rather than ignoring it.
    if (record.empty())
        return sse_read_key(c, upload, sse_c_prefix, key, err);
    if (!sse_read_key(c, upload, sse_c_prefix, key, err))
        return false;
    seal.key         = key;
    seal.opaque_etag = sse_mode_of(upload) == sse_mode::c;
    // The part's own header says it is sealed, which is what tells its length on disk after a restart.
    meta.extra.emplace_back(std::string(sse_extra), record);
    return true;
}

// ─── A sealed object on its way out ─────────────────────────────────────────

void storage_run::send_sealed(const std::shared_ptr<conn>& c, response head, int fd, uint64_t data_off,
                              const object_meta& m, const sse_key& key, uint64_t first, uint64_t len)
{
    if (c->dead)
    {
        m_loop.close_fd(fd);
        return;
    }
    auto reader = body_reader::make(m_io, &m_hash, m_store.alive_token(), fd, data_off, m, &key, first, len);
    if (!reader)
    {
        m_loop.close_fd(fd);
        LOG_WARN(("storage: the chunks of the encrypted object \"" + c->req.key + "\" cannot be located").c_str());
        send_error(c, make_error("InternalError"));
        return;
    }
    head.close = head.close || !c->req.keep_alive;
    head.head_only = true;
    head.has_length_override = true;
    head.length_override = len;

    c->dec       = std::move(reader);
    c->file_fd   = fd;
    c->file_off  = first;
    c->file_left = len;
    c->ph        = phase::respond;
    c->close_after_write = head.close;
    c->spliced   = false;
    ++m_c.copied_gets;
    ++m_c.sse_gets;
    c->after_write = conn::after_kind::pump;
    queue_write(c, response_head(*c, head));
}

void storage_run::sealed_pump(const std::shared_ptr<conn>& c)
{
    std::weak_ptr<conn> weak = c;
    c->dec->next([this, weak](bool ok, std::string_view plain)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (!ok || plain.empty() || plain.size() > cc->file_left)
        {
            // The headers promised the bytes, so a chunk that does not open can only end the connection.
            LOG_WARN(("storage: the encrypted object \"" + cc->req.key + "\" could not be read whole: a chunk is "
                      "missing or does not open").c_str());
            close_conn(cc);
            return;
        }
        cc->file_off  += plain.size();
        cc->file_left -= plain.size();
        cc->after_write = conn::after_kind::pump;
        queue_write(cc, std::string(plain));
    });
}

// ─── A copy that is not a copy of the bytes ─────────────────────────────────

struct storage_run::copy_feed : std::enable_shared_from_this<copy_feed>
{
    storage_run*                 run{nullptr};
    std::shared_ptr<put_op>      op;
    std::weak_ptr<conn>          owner;
    int                          fd{-1};
    std::shared_ptr<body_reader> src;
    // What of the window the reader holds the put has not taken yet.
    std::string_view             buf;
    bool                         reading{false};
    bool                         ended{false};
    std::shared_ptr<copy_feed>   keep;
    std::function<void(const std::shared_ptr<conn>&, put_result)> done;

    void retire()
    {
        ended = true;
        src.reset();
        if (fd >= 0)
            run->m_loop.close_fd(fd);
        fd = -1;
        keep.reset();
    }

    void fail(const s3_error& e)
    {
        if (ended)
            return;
        auto self = shared_from_this();
        op->abort();
        retire();
        if (auto cc = owner.lock(); cc && !cc->dead)
            run->send_error(cc, e);
    }
    void fail(st why) { fail(error_for(why)); }

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
        done(cc, std::move(pr));
    }

    void pump()
    {
        auto self = shared_from_this();
        for (;;)
        {
            if (ended || reading || !src)
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
            if (!buf.empty())
            {
                buf.remove_prefix(op->append(buf.data(), buf.size()));
                if (op->failed())
                    continue;
                if (!buf.empty())
                    return;   // the put's ready callback comes back here
            }
            reading = true;
            src->next([self](bool ok, std::string_view plain)
            {
                self->reading = false;
                if (self->ended)
                    return;
                if (!ok)
                {
                    self->fail(st::io_error);
                    return;
                }
                if (plain.empty())
                {
                    // The put answers through the callback, which holds the feed until then.
                    self->ended = true;
                    self->op->finish(nullptr, [self](put_result pr) { self->answer(std::move(pr)); });
                    return;
                }
                self->buf = plain;
                self->pump();
            });
            return;
        }
    }
};

void storage_run::feed_copy(const std::shared_ptr<conn>& c, std::shared_ptr<put_op> op, const std::string& src_bucket,
                            const std::string& src_key, const std::string& src_version,
                            std::optional<sse_key> customer, uint64_t first, uint64_t len,
                            std::function<void(const std::shared_ptr<conn>&, put_result)> done)
{
    auto f   = std::make_shared<copy_feed>();
    f->run   = this;
    f->op    = std::move(op);
    f->owner = c;
    f->keep  = f;
    f->done  = std::move(done);
    std::weak_ptr<copy_feed> weak = f;
    f->op->on_ready([weak]()
    {
        if (auto p = weak.lock())
            p->pump();
    });
    f->op->on_failed([weak](st why)
    {
        if (auto p = weak.lock())
            p->fail(why);
    });

    // The source's file, opened with its header read, which is the version whose key and layout are used.
    auto opened = [this, weak, customer, first, len](open_result o)
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
        p->fd = o.fd;
        sse_key key{};
        const bool sealed = is_encrypted(o.meta);
        if (sealed)
        {
            s3_error err;
            if (!sse_data_key(o.meta, customer, key, err))
            {
                p->fail(err);
                return;
            }
            // A source replaced since it was looked at may be shorter than the range, which its chunks cannot give.
            if (first + len > o.meta.size)
            {
                p->fail(st::io_error);
                return;
            }
        }
        p->src = body_reader::make(m_io, &m_hash, m_store.alive_token(), o.fd, o.data_off, o.meta,
                                   sealed ? &key : nullptr, first, len);
        if (!p->src)
        {
            p->fail(st::io_error);
            return;
        }
        p->pump();
    };
    if (src_version.empty())
        m_store.open_object(src_bucket, src_key, 0, std::move(opened));
    else
        m_store.open_version(src_bucket, src_key, src_version, 0, std::move(opened));
}

void storage_run::copy_sealed(const std::shared_ptr<conn>& c, std::string src_bucket, std::string src_key,
                              std::string src_version, object_meta meta, const object_meta& src, const sse_ask& dst,
                              std::optional<sse_key> src_customer, std::string source_id)
{
    s3_request& r = c->req;
    // The copy is one stream of its own, under a key of its own, and a version only its owner gives.
    std::erase_if(meta.extra, [](const auto& e) { return e.first == sse_extra || e.first == part_sizes_extra; });
    clear_version_extra(meta);
    sse_seal_spec seal;
    if (s3_error err; dst.mode != sse_mode::none && !sse_new_key(dst, false, meta, seal, err))
    {
        send_error(c, err);
        return;
    }
    st why = st::ok;
    auto op = m_store.begin_put(r.bucket, r.key, std::move(meta), src.size, true, why, false,
                                dst.mode != sse_mode::none ? &seal : nullptr);
    if (!op)
    {
        send_error_st(c, why);
        return;
    }
    if (dst.mode != sse_mode::none)
        ++m_c.sse_puts;
    feed_copy(c, std::move(op), src_bucket, src_key, src_version, std::move(src_customer), 0, src.size,
              [this, source_id](const std::shared_ptr<conn>& cc, put_result p)
    {
        response resp;
        resp.headers.emplace_back("Content-Type", "application/xml");
        if (!source_id.empty())
            resp.headers.emplace_back("x-amz-copy-source-version-id", source_id);
        if (has_version(p.meta))
            resp.headers.emplace_back("x-amz-version-id", version_of(p.meta).id);
        sse_headers(cc->req, p.meta, resp.headers);
        resp.body = copy_result_xml(p.meta);
        send_response(cc, std::move(resp));
        notify_put(cc->req.bucket, cc->req.key, p.meta);
    });
}

// ─── A bucket's default ─────────────────────────────────────────────────────

void storage_run::op_put_encryption(const std::shared_ptr<conn>& c)
{
    const s3_request& q = c->req;
    if (!m_store.has_bucket(q.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    s3_error err;
    if (!body_md5_ok(q, c->body, err) || !parse_encryption(c->body, err))
    {
        send_error(c, err);
        return;
    }
    // A default nobody could honour would refuse every put the bucket is given.
    if (!m_has_master)
    {
        send_error(c, sse_error("NotImplemented", "Server side encryption with AES256 needs a master key, and this "
                                                  "runtime was given no --sse-key-file"));
        return;
    }
    std::weak_ptr<conn> weak = c;
    m_node.set_doc(bucket_doc::encryption, q.bucket, encryption_xml(), [this, weak](st s)
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

void storage_run::op_get_encryption(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    if (!m_store.bucket_encrypts(c->req.bucket))
    {
        send_error(c, make_error("ServerSideEncryptionConfigurationNotFoundError"));
        return;
    }
    response r;
    r.headers.emplace_back("Content-Type", "application/xml");
    r.body = encryption_xml();
    send_response(c, std::move(r));
}

void storage_run::op_delete_encryption(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    std::weak_ptr<conn> weak = c;
    m_node.set_doc(bucket_doc::encryption, c->req.bucket, {}, [this, weak](st s)
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

}   // namespace socketley::storage
