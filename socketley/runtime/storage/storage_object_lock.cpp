// S3 Object Lock over S3: a bucket's ObjectLockConfiguration, a version's retention and legal hold, and the lock a
// write asks for in its headers.
//
// The bucket's configuration is a bucket document like versioning; a version's retention and legal hold live in its
// own header, changed in place by the owner of its key, which is also where a removal is refused.
#include "storage_run.h"

#include "bucket_policy.h"
#include "s3_object_lock.h"
#include "s3_xml.h"

namespace socketley::storage
{

namespace
{

s3_error lock_error(std::string_view code, std::string message)
{
    s3_error e = make_error(code);
    e.message  = std::move(message);
    return e;
}

s3_error missing_lock_config()
{
    return lock_error("InvalidRequest", "Bucket is missing Object Lock Configuration");
}

// Whether the request says what its body's digest is, in a header or in the trailer that follows it; a signed
// SHA-256 of the payload is checked against the body as an MD5 is, and older SDKs send nothing else.
bool integrity_sent(const s3_request& r)
{
    if (r.has_header("content-md5") || r.header("x-amz-trailer").starts_with("x-amz-checksum-"))
        return true;
    if (const std::string_view h = r.header("x-amz-content-sha256");
        h.size() == 64 && std::ranges::all_of(h, [](char ch) { return std::isxdigit(static_cast<unsigned char>(ch)); }))
        return true;
    for (const auto& h : r.headers)
        if (h.name.starts_with("x-amz-checksum-") && checksum_from_header(h.name) != checksum_algo::none)
            return true;
    return false;
}

}   // namespace

bool body_integrity_ok(const s3_request& r, std::string_view body, s3_error& err)
{
    if (!body_md5_ok(r, body, err))
        return false;
    for (const auto& h : r.headers)
    {
        const checksum_algo a = h.name.starts_with("x-amz-checksum-") ? checksum_from_header(h.name)
                                                                      : checksum_algo::none;
        if (a == checksum_algo::none)
            continue;
        checksum_stream s(a);
        s.update(body.data(), body.size());
        if (s.peek_b64() != h.value)
        {
            err = lock_error("BadDigest", "The " + std::string(checksum_name(a)) +
                                              " you specified did not match the calculated checksum.");
            return false;
        }
    }
    if (integrity_sent(r))
        return true;
    err = lock_error("InvalidRequest", "Content-MD5 OR x-amz-checksum- HTTP header is required for this request");
    return false;
}

bool storage_run::bypass_allowed(const std::shared_ptr<conn>& c, std::string_view key)
{
    return http_token_equals(c->req.header("x-amz-bypass-governance-retention"), "true", 4) &&
           policy_allows(c, s3_action::bypass_governance_retention, key);
}

bool storage_run::lock_from_headers(const std::shared_ptr<conn>& c, object_meta& m, s3_error& err)
{
    const s3_request& r = c->req;
    const bool mode = r.has_header("x-amz-object-lock-mode");
    const bool date = r.has_header("x-amz-object-lock-retain-until-date");
    const bool hold = r.has_header("x-amz-object-lock-legal-hold");
    const std::shared_ptr<const lock_config> cfg = m_store.bucket_lock(r.bucket);
    const int64_t now = static_cast<int64_t>(m_store.now_ms());
    clear_lock_extras(m);
    if ((mode || date || hold) && !cfg)
    {
        err = missing_lock_config();
        return false;
    }
    if (mode != date)
    {
        err = lock_error("InvalidArgument",
                         "x-amz-object-lock-retain-until-date and x-amz-object-lock-mode must both be supplied");
        return false;
    }
    if (mode)
    {
        retention want;
        want.mode = lock_mode_of(r.header("x-amz-object-lock-mode"));
        if (want.mode == lock_mode::none)
        {
            err = lock_error("InvalidArgument", "Unknown wormMode directive.");
            return false;
        }
        if (!parse_lock_date(r.header("x-amz-object-lock-retain-until-date"), want.until_ms))
        {
            err = lock_error("InvalidArgument", "The retain until date must be provided in ISO 8601 format");
            return false;
        }
        if (want.until_ms <= now)
        {
            err = lock_error("InvalidArgument", "The retain until date must be in the future!");
            return false;
        }
        if (!policy_allows(c, s3_action::put_object_retention, r.key))
        {
            err = make_error("AccessDenied");
            return false;
        }
        set_retention_extra(m, want);
    }
    else if (cfg && cfg->mode != lock_mode::none)
        set_retention_extra(m, retention{cfg->mode, default_retain_until(*cfg, now)});
    if (hold)
    {
        const std::string_view v = r.header("x-amz-object-lock-legal-hold");
        if (v != "ON" && v != "OFF")
        {
            err = lock_error("InvalidArgument", "Legal Hold must be either of 'ON' or 'OFF'");
            return false;
        }
        if (!policy_allows(c, s3_action::put_object_legal_hold, r.key))
        {
            err = make_error("AccessDenied");
            return false;
        }
        set_legal_hold_extra(m, v);
    }
    // A body that asks to be kept says what it is, as S3 requires, so what is kept is what was sent.
    if ((mode || hold) && !r.form && r.method == "PUT" && !r.has_header("x-amz-copy-source") && !integrity_sent(r))
    {
        err = lock_error("InvalidRequest",
                         "Content-MD5 OR x-amz-checksum- HTTP header is required for Put Object requests with "
                         "Object Lock parameters");
        return false;
    }
    return true;
}

// ─── The bucket's configuration ─────────────────────────────────────────────

void storage_run::op_put_object_lock_config(const std::shared_ptr<conn>& c)
{
    const s3_request& q = c->req;
    if (!m_store.has_bucket(q.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    s3_error    err;
    lock_config cfg;
    if (!body_integrity_ok(q, c->body, err) || !parse_lock_config(c->body, cfg, err))
    {
        send_error(c, err);
        return;
    }
    // Shard 0 refuses it unless versioning is Enabled, in the order of the bucket's other changes.
    store_doc(c, bucket_doc::object_lock, q.bucket, lock_config_xml(cfg), 200);
}

void storage_run::op_get_object_lock_config(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    const std::shared_ptr<const lock_config> cfg = m_store.bucket_lock(c->req.bucket);
    if (!cfg)
    {
        send_error(c, make_error("ObjectLockConfigurationNotFoundError"));
        return;
    }
    response r;
    r.headers.emplace_back("Content-Type", "application/xml");
    r.body = lock_config_xml(*cfg);
    send_response(c, std::move(r));
}

// ─── A version's retention and legal hold ───────────────────────────────────

void storage_run::op_put_lock_attr(const std::shared_ptr<conn>& c, bool legal_hold)
{
    const s3_request& q = c->req;
    std::string version_id;
    if (!version_param(c, version_id))
        return;
    if (!m_store.has_bucket(q.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    if (!m_store.bucket_lock(q.bucket))
    {
        send_error(c, missing_lock_config());
        return;
    }
    s3_error err;
    if (!body_integrity_ok(q, c->body, err))
    {
        send_error(c, err);
        return;
    }
    header_change change;
    if (legal_hold)
    {
        change.what = header_change::kind::legal_hold;
        if (!parse_legal_hold_xml(c->body, change.value, err))
        {
            send_error(c, err);
            return;
        }
    }
    else
    {
        retention want;
        if (!parse_retention_xml(c->body, want, err))
        {
            send_error(c, err);
            return;
        }
        if (want.mode != lock_mode::none && want.until_ms <= static_cast<int64_t>(m_store.now_ms()))
        {
            send_error(c, lock_error("InvalidArgument", "The retain until date must be in the future!"));
            return;
        }
        change.what   = header_change::kind::retention;
        change.value  = retention_value(want);
        change.bypass = bypass_allowed(c, q.key);
    }
    std::weak_ptr<conn> weak = c;
    m_store.change_header(q.bucket, q.key, std::move(version_id), std::move(change), [this, weak](st s, std::string)
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

void storage_run::op_get_lock_attr(const std::shared_ptr<conn>& c, bool legal_hold)
{
    const s3_request& q = c->req;
    std::string version_id;
    if (!version_param(c, version_id))
        return;
    if (!m_store.has_bucket(q.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    if (!m_store.bucket_lock(q.bucket))
    {
        send_error(c, missing_lock_config());
        return;
    }
    // The owner answers from memory, and any other shard from the version's header.
    std::weak_ptr<conn> weak = c;
    auto answer = [this, weak, legal_hold](st s, const object_meta& m)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (s != st::ok)
        {
            send_error_st(cc, s);
            return;
        }
        const retention        ret  = retention_of(m);
        const std::string_view hold = legal_hold_of(m);
        if (legal_hold ? hold.empty() : ret.mode == lock_mode::none)
        {
            send_error(cc, make_error("NoSuchObjectLockConfiguration"));
            return;
        }
        response r;
        r.headers.emplace_back("Content-Type", "application/xml");
        r.body = legal_hold ? legal_hold_xml(hold) : retention_xml(ret);
        send_response(cc, std::move(r));
    };
    if (version_id.empty())
        m_store.stat_object(q.bucket, q.key, std::move(answer));
    else
        m_store.stat_version(q.bucket, q.key, std::move(version_id), std::move(answer));
}

}   // namespace socketley::storage
