// The cluster: the other nodes this runtime sends its changes to, and the changes another node sends it.
#include "storage_run.h"

#include "cluster.h"

namespace socketley::storage
{

void storage_run::set_cluster(cluster_config cfg)
{
    m_cluster_self = cfg.self;
    m_repl.set_nodes(std::move(cfg.peers));
    m_store.set_mirror(true);
    // A bucket's change is in the outbox before its client hears it was made.
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
    if (!c->cluster)
    {
        send_error(c, make_error("AccessDenied"));
        return;
    }
    cluster_record rec;
    if (!decode_cluster_record(c->body, rec) || (rec.kind == 'l') == q.key.empty() ||
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
