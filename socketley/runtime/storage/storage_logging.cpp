// A bucket's server access logging: setting and reading its BucketLoggingStatus over S3, a line in S3's access log
// format for every answer to a request on a logged bucket, and the delivery of those lines as objects in the target
// bucket.
#include "storage_run.h"

#include <arpa/inet.h>
#include <openssl/ssl.h>

#include <algorithm>

#include "s3_logging.h"
#include "s3_names.h"
#include "s3_xml.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/random_id.h"
#include "../../shared/util/settings.h"

namespace socketley::storage
{

namespace
{

// Lines are delivered once this many are held for a destination, or once the oldest is this old.
constexpr size_t access_log_flush_bytes = 1 << 20;

std::chrono::milliseconds access_log_interval()
{
    // SOCKETLEY_STORAGE_LOG_FLUSH_MS shortens the wait for a test, between 100 ms and an hour.
    static const long ms = []
    {
        return settings::number<long>("SOCKETLEY_STORAGE_LOG_FLUSH_MS").value_or(60L * 1000);
    }();
    return std::chrono::milliseconds(ms);
}

void plain(std::string& out, std::string_view v)
{
    out += v.empty() ? std::string_view("-") : v;
    out += ' ';
}

void quoted(std::string& out, std::string_view v)
{
    out += '"';
    if (v.empty())
        out += '-';
    for (char ch : v)
    {
        if (ch == '"' || ch == '\\')
            out += '\\';
        out += ch;
    }
    out += "\" ";
}

void number(std::string& out, uint64_t n, bool dash_for_zero)
{
    if (n == 0 && dash_for_zero)
        out += '-';
    else
        out += std::to_string(n);
    out += ' ';
}

// [06/Feb/2019:00:00:38 +0000], the time a line names.
void log_time(std::string& out, int64_t ms)
{
    static constexpr std::string_view months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    const utc_fields f = utc_of(ms);
    char buf[40];
    const int n = std::snprintf(buf, sizeof buf, "[%02u/%.*s/%04lld:%02u:%02u:%02u +0000] ", f.day,
                                static_cast<int>(months[f.month - 1].size()), months[f.month - 1].data(),
                                static_cast<long long>(f.year), f.hour, f.minute, f.second);
    out.append(buf, static_cast<size_t>(n));
}

// REST.GET.OBJECT and its kin: how the request came, its method, and what it was on.
void operation_of(std::string& out, const s3_request& r)
{
    out += r.website ? "WEBSITE." : "REST.";
    out += r.method;
    out += '.';
    if (!r.key.empty())
        out += r.has_query("partNumber") ? "PART" : r.has_query("uploadId") ? "UPLOAD" : r.has_query("uploads") ? "UPLOADS"
             : r.has_query("tagging") ? "OBJECT_TAGGING" : r.has_query("acl") ? "ACL" : "OBJECT";
    else if (r.method == "POST" && r.has_query("delete"))
        out += "MULTI_OBJECT_DELETE";
    else if (!r.query.empty() && r.query.front().second.empty() && !r.website)
        for (char ch : r.query.front().first)
            out += static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    else
        out += "BUCKET";
    out += ' ';
}

}   // namespace

// ─── Configuration ──────────────────────────────────────────────────────────

void storage_run::op_put_logging(const std::shared_ptr<conn>& c)
{
    const s3_request& q = c->req;
    if (!m_store.has_bucket(q.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    s3_error err;
    logging_config cfg;
    if (!body_md5_ok(q, c->body, err) || !parse_logging_config(c->body, cfg, err))
    {
        send_error(c, err);
        return;
    }
    // The log goes to a bucket that is there and has the logged bucket's owner, as S3 asks one of its own account.
    if (!cfg.target_bucket.empty() && !m_store.has_bucket(cfg.target_bucket))
    {
        send_error(c, make_error("InvalidTargetBucketForLogging"), false, "TargetBucket", cfg.target_bucket);
        return;
    }
    if (!cfg.target_bucket.empty() && owner_of(cfg.target_bucket) != owner_of(q.bucket))
    {
        s3_error e = make_error("InvalidTargetBucketForLogging");
        e.message  = "The owner for the bucket to be logged and the target bucket must be the same.";
        send_error(c, e, false, "TargetBucket", cfg.target_bucket);
        return;
    }
    // Grants are taken where the target bucket takes ACLs, as S3 refuses them for one whose ACLs are disabled.
    if (cfg.grants_given)
    {
        if (bucket_ownership(cfg.target_bucket) == object_ownership::enforced)
        {
            send_error(c, make_error("AccessControlListNotSupported"));
            return;
        }
        if (std::string acl; !logging_acl(cfg, acl, err))
        {
            send_error(c, err);
            return;
        }
    }
    store_doc(c, bucket_doc::logging, q.bucket, cfg.target_bucket.empty() ? std::string{} : logging_config_xml(&cfg),
              200);
}

void storage_run::op_get_logging(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    // A bucket that is not logged answers an empty status, as S3's does.
    const auto cfg = m_store.bucket_logging(c->req.bucket);
    response r;
    r.headers.emplace_back("Content-Type", "application/xml");
    r.body = logging_config_xml(cfg.get());
    send_response(c, std::move(r));
}

// ─── Lines ──────────────────────────────────────────────────────────────────

void storage_run::access_log(const std::shared_ptr<conn>& c, int status, uint64_t bytes, std::string_view op,
                             std::string_view key, std::string_view error)
{
    const s3_request& r = c->req;
    if (!m_store.any_logging() || r.bucket.empty())
        return;
    const auto cfg = m_store.bucket_logging(r.bucket);
    if (!cfg)
        return;

    // The fields of S3's server access log, in its order, "-" for what this runtime does not know.
    std::string& l = m_log_line;
    l.clear();
    const auto now_ms = static_cast<int64_t>(m_store.now_ms());
    plain(l, owner_of(r.bucket));
    plain(l, r.bucket);
    log_time(l, now_ms);
    client_address(*c);
    char ip[INET6_ADDRSTRLEN] = "-";
    if (c->ip.family == 4)
        ::inet_ntop(AF_INET, c->ip.addr, ip, sizeof ip);
    else if (c->ip.family == 6)
        ::inet_ntop(AF_INET6, c->ip.addr, ip, sizeof ip);
    plain(l, ip);
    plain(l, c->anonymous ? std::string_view{} : std::string_view(c->principal));
    plain(l, r.request_id);
    if (op.empty())
        operation_of(l, r);
    else
    {
        l += op;
        l += ' ';
    }
    const std::string_view k = op.empty() ? std::string_view(r.key) : key;
    if (k.empty())
        l += "- ";
    else
    {
        url_encode_to(l, k, true);
        l += ' ';
    }
    l += '"';
    l += r.method;
    l += ' ';
    l += r.raw_path;
    if (!r.raw_query.empty())
    {
        l += '?';
        l += r.raw_query;
    }
    l += ' ';
    l += r.version.empty() ? std::string_view("HTTP/1.1") : r.version;
    l += "\" ";
    number(l, static_cast<uint64_t>(status), false);
    plain(l, op.empty() ? std::string_view(c->error_code) : error);
    number(l, bytes, true);
    number(l, r.method == "PUT" && r.has_content_length ? r.content_length : 0, true);
    number(l, static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - c->request_began).count()), false);
    l += "- ";
    quoted(l, r.header("referer"));
    quoted(l, r.header("user-agent"));
    plain(l, r.header("x-amz-version-id"));
    l += "- ";
    const bool v2_query = r.has_query("AWSAccessKeyId") && r.has_query("Signature");
    const bool by_query = r.raw_query.find("X-Amz-Algorithm=") != std::string_view::npos || v2_query;
    const bool by_header = r.header("authorization").starts_with("AWS4-HMAC-SHA256") ||
                           r.header("authorization").starts_with("AWS ");
    const bool v2 = v2_query || r.header("authorization").starts_with("AWS ");
    plain(l, by_query || by_header ? (v2 ? "SigV2" : "SigV4") : "");
    plain(l, c->tls() ? std::string_view(SSL_get_cipher_name(c->tls())) : std::string_view{});
    plain(l, by_header ? "AuthHeader" : by_query ? "QueryString" : "");
    plain(l, r.host);
    plain(l, c->tls() ? std::string_view(SSL_get_version(c->tls())) : std::string_view{});
    // No access point, and whether an ACL's grant was what admitted the request.
    l += c->by_acl ? "- Yes\n" : "- -\n";

    // Lines for one destination are held together, the date partition's source bucket being part of where they go.
    // The prefix is length-prefixed so none can collide with another, and grants keep a source bucket's lines apart.
    std::string dest = cfg->target_bucket;
    dest += '\n';
    dest += cfg->partitioned ? 'p' : 'n';
    dest += std::to_string(cfg->target_prefix.size());
    dest += '\n';
    dest += cfg->target_prefix;
    if (cfg->partitioned || !cfg->grants.empty())
    {
        dest += '\n';
        dest += r.bucket;
    }
    auto it = m_access_logs.find(dest);
    if (it == m_access_logs.end())
    {
        access_log_buffer b;
        b.target      = cfg->target_bucket;
        b.prefix      = cfg->target_prefix;
        b.partitioned = cfg->partitioned;
        s3_error ignored;
        logging_acl(*cfg, b.acl, ignored);
        if (b.partitioned)
            b.prefix += std::string(owner_of(r.bucket)) + "/us-east-1/" + r.bucket + "/";
        b.since = std::chrono::steady_clock::now();
        it = m_access_logs.emplace(std::move(dest), std::move(b)).first;
        arm_sweep();
    }
    it->second.data += l;
    if (it->second.data.size() >= access_log_flush_bytes)
    {
        access_log_buffer b = std::move(it->second);
        m_access_logs.erase(it);
        deliver_access_log(b.target, std::move(b.prefix), b.partitioned, b.acl, std::move(b.data));
    }
}

// ─── Delivery ───────────────────────────────────────────────────────────────

void storage_run::flush_access_logs(bool all)
{
    const auto now = std::chrono::steady_clock::now();
    for (auto it = m_access_logs.begin(); it != m_access_logs.end();)
    {
        if (!all && now - it->second.since < access_log_interval())
        {
            ++it;
            continue;
        }
        access_log_buffer b = std::move(it->second);
        it = m_access_logs.erase(it);
        deliver_access_log(b.target, std::move(b.prefix), b.partitioned, b.acl, std::move(b.data));
    }
}

bool storage_run::logging_acl(const logging_config& cfg, std::string& out, s3_error& err) const
{
    out.clear();
    if (cfg.grants.empty())
        return true;
    acl_request rq;
    std::string lists[5];
    for (const logging_config::grant& g : cfg.grants)
    {
        const size_t i = g.permission == "READ" ? 0 : g.permission == "WRITE" ? 1 : 4;
        if (!lists[i].empty())
            lists[i] += ", ";
        lists[i] += g.kind + "=\"" + g.value + "\"";
    }
    for (size_t i = 0; i < 5; ++i)
        rq.grant[i] = lists[i];
    const std::string owner(owner_of(cfg.target_bucket));
    acl_list a;
    if (!acl_from_request(rq, false, owner, owner, acl_users(), a, err))
        return false;
    // The owner keeps full control of its log objects beside what the grants give others.
    if (std::none_of(a.grants.begin(), a.grants.end(), [&](const acl_grant& g) { return g.id == owner; }))
        a.grants.insert(a.grants.begin(), acl_grant{acl_grant::who::user, owner, acl_perm::full});
    out = encode_acl(a);
    return true;
}

void storage_run::deliver_access_log(const std::string& target, std::string key, bool partitioned,
                                     const std::string& acl, std::string data)
{
    // The object is named for when it is delivered, after its prefix and its date partition, and made unique.
    const int64_t now_ms = static_cast<int64_t>(m_store.now_ms());
    const utc_fields f = utc_of(now_ms);
    char stamp[64];
    int n = 0;
    if (partitioned)
        n = std::snprintf(stamp, sizeof stamp, "%04lld/%02u/%02u/", static_cast<long long>(f.year), f.month, f.day);
    n += std::snprintf(stamp + n, sizeof stamp - static_cast<size_t>(n), "%04lld-%02u-%02u-%02u-%02u-%02u-",
                       static_cast<long long>(f.year), f.month, f.day, f.hour, f.minute, f.second);
    key.append(stamp, static_cast<size_t>(n));
    const std::string suffix = random_hex(8, true);
    if (suffix.empty())
    {
        LOG_WARN(("storage: access log lines for " + target + " are dropped: no random bytes to name their object")
                     .c_str());
        return;
    }
    key += suffix;

    object_meta meta;
    meta.content_type = "text/plain";
    if (!acl.empty())
        set_object_acl(meta, acl);
    s3_error err;
    const size_t lines = static_cast<size_t>(std::count(data.begin(), data.end(), '\n'));
    auto w = put_whole(target, key, std::move(meta), std::move(data),
                       [this, target, key, lines](st s, const put_result*)
    {
        std::erase_if(m_log_deliveries, [](const std::shared_ptr<whole_put>& d) { return d->done; });
        if (s != st::ok)
            LOG_WARN(("storage: " + std::to_string(lines) + " access log lines for bucket \"" + target +
                      "\" were not delivered as \"" + key + "\": " + error_for(s).code).c_str());
    }, err);
    if (!w)
    {
        LOG_WARN(("storage: " + std::to_string(lines) + " access log lines for bucket \"" + target +
                  "\" were not delivered: " + err.code).c_str());
        return;
    }
    if (!w->done)
        m_log_deliveries.push_back(std::move(w));
}

}   // namespace socketley::storage
