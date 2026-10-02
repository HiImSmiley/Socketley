// A bucket's event notifications over S3: setting and reading its NotificationConfiguration, and the events the
// owner of a key queues for each change it makes.
#include "storage_run.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "s3_notify.h"
#include "s3_xml.h"

namespace socketley::storage
{

void storage_run::op_put_notification(const std::shared_ptr<conn>& c)
{
    const s3_request& q = c->req;
    if (!m_store.has_bucket(q.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    s3_error err;
    if (!body_md5_ok(q, c->body, err))
    {
        send_error(c, err);
        return;
    }
    notify_config cfg;
    if (!parse_notify_config(c->body, cfg, err))
    {
        send_error(c, err);
        return;
    }
    // A destination is one the runtime was given, unless the request asks for it not to be checked, as S3 lets it.
    if (!http_token_equals(http_trim_ows(q.header("x-amz-skip-destination-validation")), "true", 4))
        for (const notify_rule& r : cfg.rules)
            if (!m_notify.has_target(r.target))
            {
                s3_error e = make_error("InvalidArgument");
                e.message  = "Unable to validate the following destination configurations";
                send_error(c, e, false, "ArgumentName", r.arn);
                return;
            }
    std::weak_ptr<conn> weak = c;
    m_node.set_doc(bucket_doc::notification, q.bucket, cfg.rules.empty() ? std::string() : notify_config_xml(cfg),
                   [this, weak](st s)
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

void storage_run::op_get_notification(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    // A bucket with no configuration answers an empty one, as S3 does.
    const auto cfg = m_store.bucket_notify(c->req.bucket);
    response r;
    r.headers.emplace_back("Content-Type", "application/xml");
    r.body = notify_config_xml(cfg ? *cfg : notify_config{});
    send_response(c, std::move(r));
}

change_origin storage_run::origin_of(const conn& c) const
{
    if (!m_store.bucket_notify(c.req.bucket))
        return {};
    change_origin o;
    o.principal = c.user ? c.user->id : "anonymous";
    struct sockaddr_storage ss{};
    socklen_t len = sizeof(ss);
    if (::getpeername(c.fd, reinterpret_cast<struct sockaddr*>(&ss), &len) < 0)
        return o;
    char host[INET6_ADDRSTRLEN] = {};
    if (ss.ss_family == AF_INET)
        ::inet_ntop(AF_INET, &reinterpret_cast<const struct sockaddr_in*>(&ss)->sin_addr, host, sizeof(host));
    else if (ss.ss_family == AF_INET6)
    {
        const auto& a6 = reinterpret_cast<const struct sockaddr_in6*>(&ss)->sin6_addr;
        // An IPv4 client on a dual-stack socket is named by its IPv4 address, as S3 names it.
        if (IN6_IS_ADDR_V4MAPPED(&a6))
            ::inet_ntop(AF_INET, &a6.s6_addr[12], host, sizeof(host));
        else
            ::inet_ntop(AF_INET6, &a6, host, sizeof(host));
    }
    o.source_ip = host;
    return o;
}

void storage_run::notify_change(change_note n, std::function<void()> answer)
{
    const auto cfg = m_store.bucket_notify(n.bucket);
    bool queued = false;
    if (cfg)
    {
        // Sixteen hex digits that grow with every event of this shard, which owns the key, so a key's events sort by it.
        const uint64_t now_us = m_store.now_ms() * 1000;
        m_notify_seq = std::max(m_notify_seq + 1, now_us);
        char seq[17];
        static constexpr char digits[] = "0123456789ABCDEF";
        for (int i = 15; i >= 0; --i)
            seq[15 - i] = digits[(m_notify_seq >> (4 * i)) & 15];
        seq[16] = 0;

        notify_fields f;
        f.bucket     = n.bucket;
        f.key        = n.key;
        f.owner      = owner_of(n.bucket);
        f.principal  = n.who.principal;
        f.source_ip  = n.who.source_ip;
        f.etag       = n.etag;
        f.version_id = n.version_id;
        f.sequencer  = seq;
        f.size       = n.size;
        f.has_object = n.has_object;
        f.time_ms    = static_cast<int64_t>(m_store.now_ms());
        for (const notify_rule& r : cfg->rules)
        {
            if (!notify_matches(r, n.event, n.key))
                continue;
            f.config_id = r.id;
            queued      = m_notify.add(r.target, notify_event_json(n.event, f)) || queued;
        }
    }
    if (!queued)
    {
        answer();
        return;
    }
    m_notify.sync(std::move(answer));
}

}   // namespace socketley::storage
