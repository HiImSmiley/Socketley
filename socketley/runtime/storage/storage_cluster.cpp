// The cluster: the other nodes this runtime sends its changes to, and the changes another node sends it.
#include "storage_run.h"

#include "cluster.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>

#include <fcntl.h>
#include <unistd.h>

#include "../../shared/logging.h"
#include "../../shared/random_id.h"

namespace socketley::storage
{

bool storage_run::load_cluster_id(std::string& err)
{
    // Made once, by whichever shard comes first, and new whenever the data is: what tells the other nodes to send all.
    const std::string path = m_store.options().dir + "/.cluster-id";
    for (int attempt = 0; attempt < 2; ++attempt)
    {
        if (const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC); fd >= 0)
        {
            char buf[64];
            const ssize_t n = ::read(fd, buf, sizeof buf);
            ::close(fd);
            std::string id(buf, n > 0 ? static_cast<size_t>(n) : 0);
            while (!id.empty() && (id.back() == '\n' || id.back() == '\r'))
                id.pop_back();
            if (id.size() == 32 && id.find_first_not_of("0123456789abcdef") == std::string::npos)
            {
                m_cluster_id = std::move(id);
                return true;
            }
        }
        char hex_id[40];
        std::snprintf(hex_id, sizeof hex_id, "%016llx%016llx\n", static_cast<unsigned long long>(random_u64()),
                      static_cast<unsigned long long>(random_u64()));
        const std::string id = hex_id;
        const std::string tmp = path + ".tmp." + std::to_string(::getpid());
        const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (fd < 0)
            break;
        const bool whole = ::write(fd, id.data(), id.size()) == static_cast<ssize_t>(id.size()) && ::fsync(fd) == 0;
        ::close(fd);
        // The first shard's id stays, and a later one reads it.
        if (!whole || ::link(tmp.c_str(), path.c_str()) < 0)
            if (errno != EEXIST)
            {
                ::unlink(tmp.c_str());
                break;
            }
        ::unlink(tmp.c_str());
    }
    err = "the cluster id of this node's data in " + path + " can be neither read nor made";
    return false;
}

void storage_run::set_cluster(cluster_config cfg)
{
    m_cluster_self = cfg.self;
    m_repl.set_sync(cfg.sync, cfg.sync_ms);
    m_repl.set_nodes(std::move(cfg.peers));
    m_store.set_mirror(true);
    // A bucket's change is in the outbox before its client hears it was made.
    // A node being sent everything gets the IAM document and the share links first.
    m_repl.set_seed_first([this]()
    {
        std::vector<std::string> out = share_records();
        if (std::string iam = iam_record(); !iam.empty())
            out.insert(out.begin(), std::move(iam));
        return out;
    });
    m_node.set_bucket_listener([this](char kind, const std::string& bucket, const std::string& owner, uint8_t doc,
                                      const std::string& xml, std::function<void()> then)
    {
        cluster_change cc;
        cc.kind    = 'b';
        cc.bucket  = bucket;
        cc.payload = encode_cluster_record({kind, owner, doc, xml, {}});
        if (!m_repl.enqueue_nodes(cc))
        {
            then();
            return;
        }
        m_repl.sync(std::move(then));
    });
}

void storage_run::scrub_found(scrubber::finding f)
{
    const std::string what = f.bucket + "/" + f.key + (f.version_id.empty() ? "" : " (version " + f.version_id + ")");
    const bool plain = m_store.bucket_versioning(f.bucket) == versioning::off;
    // Only a version named by its id, or an object of a bucket that keeps no versions, is taken away to be replaced.
    if (!m_repl.has_nodes() || (f.version_id.empty() && !plain))
    {
        LOG_ERROR(("storage: " + what + " does not hold the bytes its header names; restore it from a copy").c_str());
        return;
    }
    LOG_ERROR(("storage: " + what + " does not hold the bytes its header names, so another node that holds it is "
               "asked for it").c_str());
    const md5_t md5 = f.meta.md5;
    const int64_t mtime = f.meta.mtime_ms;
    // Copied first, since the lambda below takes `f` and the order its arguments are made in is the compiler's.
    std::string bucket = f.bucket, key = f.key, version_id = f.version_id, etag = f.meta.etag();
    m_repl.find_copy(std::move(bucket), std::move(key), std::move(version_id), std::move(etag),
                     [this, f = std::move(f), what, md5, mtime](std::string node)
    {
        if (node.empty())
        {
            ++m_c.scrub_unhealed;
            LOG_ERROR(("storage: no other node holds " + what + " whole; restore it from a copy").c_str());
            return;
        }
        // The corrupt copy goes quietly, and only while it is still the one the scrub read.
        m_store.remove_version_local(f.bucket, f.key, f.version_id, [this, f, node, what](remove_result r)
        {
            if (r.status != st::ok || !r.existed)
            {
                LOG_ERROR(("storage: " + what + " could not be taken away to be replaced (" +
                           std::string(status_name(r.status)) + ")").c_str());
                return;
            }
            ++m_c.scrub_heals;
            m_repl.enqueue_node(node, {'q', f.bucket, f.key, f.version_id, {},
                                       encode_cluster_record({'q', m_cluster_self, 0, {}, f.version_id})});
        }, [md5, mtime](const object_meta& m) { return m.md5 == md5 && m.mtime_ms == mtime; }, true,
           change_cause::heal);
    });
}

bool storage_run::cluster_mark(const std::shared_ptr<conn>& c, object_meta& m, s3_error& err)
{
    const s3_request& r = c->req;
    cluster_stamp s;
    if (!parse_cluster_stamp(http_trim_ows(r.header(cluster_stamp_header)), s) || s.tag.marker)
    {
        err = make_error("InvalidRequest");
        err.message = "A write from another node of the cluster names the version and the time it was made with";
        return false;
    }
    // A version waits for this node to hear of the bucket's versioning, which another lane of its node carries.
    if (s.tag.id != "null" && m_store.has_bucket(r.bucket) && m_store.bucket_versioning(r.bucket) == versioning::off)
    {
        err = make_error("SlowDown");
        return false;
    }
    // The write keeps the lock it has at its node, never this bucket's default, and no replication status of its own.
    set_replication_status(m, {});
    clear_lock_extras(m);
    if (const std::string_view v = http_trim_ows(r.header(cluster_retention_header)); !v.empty())
    {
        retention ret;
        if (!retention_from_value(v, ret))
        {
            err = make_error("InvalidRequest");
            return false;
        }
        set_retention_extra(m, ret);
    }
    if (const std::string_view v = http_trim_ows(r.header(cluster_legal_hold_header)); v == "ON" || v == "OFF")
        set_legal_hold_extra(m, v);
    set_cluster_extra(m, s);
    return true;
}

void storage_run::op_cluster(const std::shared_ptr<conn>& c)
{
    const s3_request& q = c->req;
    if (!c->cluster || m_cluster_id.empty())
    {
        send_error(c, make_error("AccessDenied"));
        return;
    }
    if (q.method == "GET")
    {
        app_reply(c, 200, m_cluster_id + "\n", "text/plain");
        return;
    }
    cluster_record rec;
    if (!decode_cluster_record(c->body, rec) || (rec.kind == 'l' || rec.kind == 'q') == q.key.empty() ||
        (rec.kind == 'i' || rec.kind == 'h') != q.bucket.empty() ||
        (rec.kind == 'd' && rec.what >= std::size(all_bucket_docs)) ||
        (rec.kind == 'l' && rec.what != static_cast<uint8_t>(header_change::kind::retention) &&
         rec.what != static_cast<uint8_t>(header_change::kind::legal_hold)))
    {
        send_error(c, make_error("InvalidRequest"));
        return;
    }
    ++m_c.cluster_in;
    std::weak_ptr<conn> weak = c;
    auto answer = [this, weak](st s)
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
    };
    switch (rec.kind)
    {
        case 'c':
            m_node.create_bucket(q.bucket, rec.owner, [answer](st s) { answer(s == st::bucket_exists ? st::ok : s); },
                                 true);
            return;
        case 'r':
            m_node.delete_bucket(q.bucket, [answer](st s) { answer(s == st::no_such_bucket ? st::ok : s); }, true);
            return;
        case 'd':
            m_node.set_doc(static_cast<bucket_doc>(rec.what), q.bucket, std::move(rec.value), answer, true);
            return;
        case 'i':
            answer(iam_take(std::atoll(rec.owner.c_str()), rec.value));
            return;
        case 'h':
            answer(share_take(rec.owner, rec.value));
            return;
        case 'q':
            // Another node lost its copy to a disk, and is sent this one again.
            m_repl.enqueue_node(rec.owner, {'p', q.bucket, q.key, rec.version_id, {}, {}});
            answer(st::ok);
            return;
        default:
        {
            header_change change;
            change.what   = static_cast<header_change::kind>(rec.what);
            change.value  = std::move(rec.value);
            change.bypass = true;
            change.who    = origin_of(*c);
            m_store.change_header(q.bucket, q.key, std::move(rec.version_id), std::move(change),
                                  [answer](st s, std::string) { answer(s); });
            return;
        }
    }
}

}   // namespace socketley::storage
