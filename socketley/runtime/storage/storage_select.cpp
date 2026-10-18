// SelectObjectContent: the object read a window at a time through its reader, sealed, compressed or at a tier as it
// lies, fed to the query, and the records it gives sent as they come in an event stream of HTTP chunks.
#include "storage_run.h"

#include <algorithm>
#include <cstdio>

#include "s3_select.h"
#include "../../shared/util/logging.h"

namespace socketley::storage
{

struct select_job
{
    select_engine engine;
    std::shared_ptr<body_reader> src;
    bool progress{false};
    // The reader gave its last window, and the stream's last chunk is written.
    bool read_all{false};
    bool ended{false};
};

namespace
{

// One HTTP chunk holding `data`.
std::string http_chunk(std::string_view data)
{
    char len[20];
    const int n = std::snprintf(len, sizeof len, "%zx\r\n", data.size());
    std::string out;
    out.reserve(static_cast<size_t>(n) + data.size() + 2);
    out.append(len, static_cast<size_t>(n));
    out.append(data);
    out += "\r\n";
    return out;
}

}   // namespace

void storage_run::op_select(const std::shared_ptr<conn>& c)
{
    const s3_request& q = c->req;
    auto req = std::make_shared<select_request>();
    if (s3_error err; !parse_select_request(c->body, *req, err))
    {
        send_error(c, err);
        return;
    }
    ++m_c.selects;
    std::weak_ptr<conn> weak = c;
    auto opened = [this, weak, req](open_result o)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
        {
            if (o.fd >= 0)
                m_loop.close_fd(o.fd);
            return;
        }
        auto close_file = [&] { if (o.fd >= 0) m_loop.close_fd(o.fd); };
        if (o.delete_marker)
        {
            close_file();
            send_error(cc, make_error(cc->req.has_query("versionId") ? "MethodNotAllowed" : "NoSuchKey"));
            return;
        }
        if (o.status != st::ok)
        {
            close_file();
            send_error_st(cc, o.status);
            return;
        }
        const object_meta& m = o.meta;
        // A select is a read, which the object's own grants answer when its bucket left it to them.
        if (!acl_admits(cc, m))
        {
            close_file();
            send_error(cc, make_error("AccessDenied"));
            return;
        }
        sse_key key{};
        const bool sealed = is_encrypted(m);
        if (s3_error err; !sse_read_key(cc, m, sse_c_prefix, key, err, true))
        {
            close_file();
            send_error(cc, err);
            return;
        }
        auto job = std::make_shared<select_job>();
        job->progress = req->progress;
        if (s3_error err; !job->engine.init(*req, err, m.size))
        {
            close_file();
            send_error(cc, err);
            return;
        }
        const uint64_t first = std::min<uint64_t>(job->engine.first_offset(), m.size);
        const uint64_t len   = m.size - first;
        if (is_tiered(m))
        {
            close_file();
            o.fd = -1;
            job->src = m_tier.reader(m, first, len);
        }
        else
            job->src = body_reader::make(m_io, &m_hash, m_store.alive_token(), o.fd, o.data_off, m,
                                         sealed ? &key : nullptr, first, len);
        if (!job->src)
        {
            close_file();
            LOG_WARN(("storage: the object \"" + cc->req.key + "\" cannot be read for a select").c_str());
            send_error(cc, make_error("InternalError"));
            return;
        }
        response r;
        r.chunked = true;
        r.close   = !cc->req.keep_alive;
        r.headers.emplace_back("Content-Type", "application/octet-stream");
        cc->sel       = std::move(job);
        cc->file_fd   = o.fd;
        cc->file_left = len;
        cc->ph        = phase::respond;
        cc->close_after_write = r.close;
        cc->after_write = conn::after_kind::pump;
        access_log(cc, 200, 0);
        queue_write(cc, response_head(*cc, r));
    };
    const std::string version(q.get_query("versionId"));
    if (version.empty())
        m_store.open_object(q.bucket, q.key, 0, std::move(opened));
    else
        m_store.open_version(q.bucket, q.key, version, 0, std::move(opened));
}

void storage_run::select_pump(const std::shared_ptr<conn>& c)
{
    select_job& j = *c->sel;
    if (j.ended)
    {
        c->sel.reset();
        file_done(c);
        return;
    }
    // The query needs nothing more: what it still holds, its Stats or its error, and the stream's end go in one write.
    if (j.read_all || j.engine.done())
    {
        if (!j.engine.failed())
            j.engine.finish();
        std::string tail;
        if (const std::string out = j.engine.take_output(); !out.empty())
            tail += select_records_event(out);
        if (j.engine.failed())
            tail += select_error_event(j.engine.error().code, j.engine.error().message);
        else
        {
            if (j.progress)
                tail += select_progress_event(j.engine.bytes_scanned(), j.engine.bytes_processed(),
                                              j.engine.bytes_returned());
            tail += select_stats_event(j.engine.bytes_scanned(), j.engine.bytes_processed(),
                                       j.engine.bytes_returned());
            tail += select_end_event();
        }
        m_c.select_scanned += j.engine.bytes_scanned();
        j.ended = true;
        c->after_write = conn::after_kind::pump;
        queue_write(c, http_chunk(tail) + "0\r\n\r\n");
        return;
    }
    std::weak_ptr<conn> weak = c;
    j.src->next([this, weak](bool ok, std::string_view piece)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead || !cc->sel)
            return;
        select_job& sj = *cc->sel;
        // The 200 is sent, so bytes that cannot be read end the stream with an error rather than cut it.
        if (!ok)
        {
            LOG_WARN(("storage: the object \"" + cc->req.key + "\" could not be read whole for a select").c_str());
            sj.ended = true;
            cc->after_write = conn::after_kind::pump;
            queue_write(cc, http_chunk(select_error_event("InternalError", "The object could not be read.")) +
                                "0\r\n\r\n");
            return;
        }
        if (piece.empty())
            sj.read_all = true;
        else
            sj.engine.feed(piece);
        const std::string out = sj.engine.take_output();
        if (out.empty())
        {
            select_pump(cc);
            return;
        }
        cc->after_write = conn::after_kind::pump;
        queue_write(cc, http_chunk(select_records_event(out)));
    });
}

}   // namespace socketley::storage
