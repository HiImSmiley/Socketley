// A bucket's policy over S3: setting, reading and removing it, its status, and
// the judgement of ownership and policy every request is given after it is
// authenticated and before a script's on_request sees it.
#include "storage_run.h"

#include <openssl/ssl.h>

#include "bucket_policy.h"
#include "s3_names.h"
#include "s3_public_access.h"
#include "s3_sigv4_auth.h"
#include "s3_xml.h"

namespace socketley::storage
{

namespace
{

// The condition keys of a request as this runtime parsed it.
class request_context final : public policy_context
{
public:
    request_context(const conn& c, const user_identity* u, bool anonymous, int64_t now_ms)
        : m_c(c), m_u(u), m_anonymous(anonymous), m_now_ms(now_ms) {}

    bool values(std::string_view key, std::vector<std::string>& out) const override
    {
        const s3_request& r = m_c.req;
        auto header = [&](std::string_view name)
        {
            if (!r.has_header(name))
                return false;
            out.emplace_back(r.header(name));
            return true;
        };
        auto query = [&](std::string_view name)
        {
            if (!r.has_query(name))
                return false;
            out.emplace_back(r.get_query(name));
            return true;
        };
        if (key == "aws:referer")
            return header("referer");
        if (key == "aws:useragent")
            return header("user-agent");
        if (key == "aws:securetransport")
            return out.emplace_back(m_c.tls() ? "true" : "false"), true;
        if (key == "aws:currenttime")
            return out.emplace_back(iso8601(m_now_ms)), true;
        if (key == "aws:epochtime")
            return out.emplace_back(std::to_string(m_now_ms / 1000)), true;
        if (key == "aws:username" || key == "aws:userid")
        {
            if (m_anonymous || !m_u)
                return false;
            out.emplace_back(m_u->id);
            return true;
        }
        if (key == "aws:principaltype")
            return out.emplace_back(m_anonymous ? "Anonymous" : "User"), true;
        if (key == "s3:prefix" || key == "s3:delimiter" || key == "s3:max-keys")
            return query(key.substr(3));
        if (key == "s3:versionid")
            return query("versionId");
        if (key == "s3:signatureversion" || key == "s3:authtype")
        {
            const bool by_header = !r.header("authorization").empty();
            const bool v2_query  = r.has_query("AWSAccessKeyId") && r.has_query("Signature");
            const bool by_query  = r.has_query("X-Amz-Algorithm") || v2_query;
            if (m_anonymous || (!by_header && !by_query && !r.form))
                return false;
            // S3 names Signature Version 2 "AWS".
            const bool v2 = v2_query || r.header("authorization").starts_with("AWS ");
            out.emplace_back(key == "s3:signatureversion" ? (v2 ? "AWS" : "AWS4-HMAC-SHA256")
                             : by_header ? "REST-HEADER" : by_query ? "REST-QUERY-STRING" : "POST");
            return true;
        }
        if (key == "s3:tlsversion")
        {
            if (!m_c.tls())
                return false;
            const int v = SSL_version(m_c.tls());
            out.emplace_back(v == TLS1_3_VERSION ? "1.3" : v == TLS1_2_VERSION ? "1.2" : "1.1");
            return true;
        }
        if (key == "s3:requestobjecttagkeys" || key.starts_with("s3:requestobjecttag/"))
        {
            if (!r.has_header("x-amz-tagging"))
                return false;
            const std::string_view want = key.starts_with("s3:requestobjecttag/") ? key.substr(20) : std::string_view{};
            std::vector<std::pair<std::string, std::string>> tags;
            if (!parse_form_pairs(r.header("x-amz-tagging"), tags))
                return false;
            bool found = want.empty();
            for (auto& [k, v] : tags)
            {
                if (want.empty())
                    out.push_back(k);
                else if (k == want)
                {
                    out.push_back(v);
                    found = true;
                }
            }
            return found;
        }
        // s3:x-amz-... and s3:object-lock-... are the request's headers of those names.
        if (key.starts_with("s3:x-amz-"))
            return header(key.substr(3));
        if (key.starts_with("s3:object-lock-"))
            return header("x-amz-" + std::string(key.substr(3)));
        return false;
    }

private:
    // The pairs of an x-amz-tagging header, k=v joined by &, each percent-encoded.
    static bool parse_form_pairs(std::string_view text, std::vector<std::pair<std::string, std::string>>& out)
    {
        while (!text.empty())
        {
            const size_t amp = text.find('&');
            const std::string_view part = text.substr(0, amp);
            text = amp == std::string_view::npos ? std::string_view{} : text.substr(amp + 1);
            const size_t eq = part.find('=');
            std::string k, v;
            if (!percent_decode(part.substr(0, eq), k, true) ||
                !percent_decode(eq == std::string_view::npos ? std::string_view{} : part.substr(eq + 1), v, true))
                return false;
            out.emplace_back(std::move(k), std::move(v));
        }
        return true;
    }

    const conn& m_c;
    const user_identity*     m_u;
    bool                     m_anonymous;
    int64_t                  m_now_ms;
};

}   // namespace

void storage_run::op_put_policy(const std::shared_ptr<conn>& c)
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
    bucket_policy checked;
    if (!bucket_policy::compile(c->body, q.bucket, checked, err))
    {
        send_error(c, err);
        return;
    }
    if (const auto pab = m_store.bucket_public_access(q.bucket); pab && pab->block_public_policy && checked.is_public())
    {
        s3_error e = make_error("AccessDenied");
        e.message  = "Access Denied because public policies are blocked by the BlockPublicPolicy block public access setting.";
        send_error(c, e);
        return;
    }
    store_doc(c, bucket_doc::policy, q.bucket, c->body, 204);
}

void storage_run::op_get_policy(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    const bucket_policy* p = m_store.policy(c->req.bucket);
    if (!p)
    {
        send_error(c, make_error("NoSuchBucketPolicy"));
        return;
    }
    response r;
    r.headers.emplace_back("Content-Type", "application/json");
    r.body = p->text();
    send_response(c, std::move(r));
}

void storage_run::op_delete_policy(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    store_doc(c, bucket_doc::policy, c->req.bucket, {}, 204);
}

void storage_run::op_get_policy_status(const std::shared_ptr<conn>& c)
{
    if (!m_store.has_bucket(c->req.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    const bucket_policy* p = m_store.policy(c->req.bucket);
    if (!p)
    {
        send_error(c, make_error("NoSuchBucketPolicy"));
        return;
    }
    response r;
    r.headers.emplace_back("Content-Type", "application/xml");
    r.body = std::string(xml_decl) + "<PolicyStatus xmlns=\"" + std::string(s3_xmlns) + "\"><IsPublic>" +
             (p->is_public() ? "true" : "false") + "</IsPublic></PolicyStatus>";
    send_response(c, std::move(r));
}

void storage_run::apply_policy(const std::shared_ptr<conn>& c, const request_view& rv, auth_verdict& v)
{
    const s3_request& r = c->req;
    const user_identity* u = v.anonymous ? nullptr : v.user.get();
    // Every user may ask for the list of its own buckets, unless one of its policies denies it.
    if (r.bucket.empty())
    {
        if (!u || u->unrestricted() || r.method != "GET")
            return;
        if (!c->ip_known)
        {
            c->ip       = client_ip_of(c->sock());
            c->ip_known = true;
        }
        const request_context ctx(*c, u, false, static_cast<int64_t>(m_store.now_ms()));
        policy_request pr;
        pr.ctx       = &ctx;
        pr.action    = s3_action::list_all_my_buckets;
        pr.principal = v.principal;
        pr.user      = u->configured ? std::string_view(u->id) : std::string_view{};
        pr.tls       = secure(*c);
        pr.ip        = &c->ip;
        const auto denies = [&pr](const bucket_policy* p) { return p && p->evaluate(pr) == policy_effect::deny; };
        if (denies(u->session_policy.get()) || (u->has_policy && denies(&u->policy)) || denies(u->iam_policy.get()))
        {
            v.allowed = false;
            v.error   = make_error("AccessDenied");
        }
        return;
    }
    const bool restricted = u && !u->unrestricted();
    // A request that only a Deny could refuse is let through without a look when its bucket has none.
    const bool copy_from = r.method == "PUT" && !r.key.empty() && r.has_header("x-amz-copy-source");
    if (!copy_from && !restricted)
    {
        const bucket_policy* p = m_store.policy(r.bucket);
        // Nor an anonymous one a bucket's grants may admit.
        const bool grants = v.anonymous && bucket_ownership(r.bucket) != object_ownership::enforced;
        if ((!p && !grants) || (p && !v.anonymous && !p->has_deny()))
            return;
    }

    // A request that names a version is the version's own action, as S3 judges it, and a replica's write is a
    // replication's.
    s3_action plain = action_of_operation(operation_name(r));
    if (replica_request(r) && (plain == s3_action::put_object || plain == s3_action::abort_multipart_upload))
        plain = s3_action::replicate_object;
    else if (replica_request(r) && plain == s3_action::delete_object && !r.key.empty())
        plain = s3_action::replicate_delete;
    else if (replica_request(r) && (plain == s3_action::put_object_tagging || plain == s3_action::delete_object_tagging))
        plain = s3_action::replicate_tags;
    const s3_action action = r.has_query("versionId") ? version_action(plain) : plain;

    const request_context ctx(*c, u, v.anonymous, static_cast<int64_t>(m_store.now_ms()));
    policy_request pr;
    pr.ctx       = &ctx;
    pr.action    = action;
    pr.bucket    = r.bucket;
    pr.key       = r.key;
    pr.anonymous = v.anonymous;
    pr.principal = v.principal;
    pr.user      = u && u->configured ? std::string_view(u->id) : std::string_view{};
    pr.tls       = secure(*c);
    pr.ip        = &c->ip;
    pr.every_key = action == s3_action::delete_object && r.key.empty();
    pr.sse_sent  = r.has_header("x-amz-server-side-encryption");
    pr.sse       = r.header("x-amz-server-side-encryption");
    // A part, or the completion of an upload, takes the encryption its creation chose and was judged on.
    const std::string_view op = operation_name(r);
    pr.sse_inherited = op == "UploadPart" || op == "UploadPartCopy" || op == "CompleteMultipartUpload";

    auto refuse = [&v](s3_error e)
    {
        v.allowed = false;
        v.error   = std::move(e);
        v.hook.reset();
    };
    // A bucket is a credentials-file user's to make where its own policy does not deny it, a role's and an IAM
    // user's only where their policies allow it, as S3 judges them, and one that is there is answered by the operation.
    if (action == s3_action::create_bucket)
    {
        const policy_effect own = u && u->has_policy ? u->policy.evaluate(pr) : policy_effect::none;
        const policy_effect iam = u && u->iam_policy ? u->iam_policy->evaluate(pr) : policy_effect::none;
        const bool granted_only = u && (u->id.starts_with("role/") || !u->iam_id.empty());
        if (u && (own == policy_effect::deny || iam == policy_effect::deny ||
                  (u->session_policy && u->session_policy->evaluate(pr) != policy_effect::allow) ||
                  (granted_only && own != policy_effect::allow && iam != policy_effect::allow)))
            refuse(make_error("AccessDenied"));
        return;
    }
    // The owner of a bucket and an admin answer to their credentials alone for the bucket's policy, so a policy
    // that shuts everyone out can be removed, and for what no policy names; a session's policy still bounds them.
    const bool policy_op = action == s3_action::put_bucket_policy || action == s3_action::get_bucket_policy ||
                           action == s3_action::delete_bucket_policy || action == s3_action::get_bucket_policy_status;
    if (action == s3_action::none || policy_op)
    {
        if (!restricted || !m_store.has_bucket(r.bucket) ||
            ((u->admin || owner_of(r.bucket) == u->id) && !u->session_policy))
            return;
        if (action == s3_action::none || access_of(c, r.bucket, pr, u) != policy_effect::allow)
            refuse(make_error("AccessDenied"));
        return;
    }

    auto judge = [this, &c, u](std::string_view bucket, const policy_request& q) { return access_of(c, bucket, q, u); };

    policy_effect dest = judge(r.bucket, pr);
    // An object's own grants are read where the object is, so a request its bucket does not admit waits for them.
    if (dest == policy_effect::none && !copy_from)
        if (const uint8_t need = object_acl_need(action);
            need && bucket_ownership(r.bucket) != object_ownership::enforced)
        {
            dest = policy_effect::allow;
            c->acl_need = need;
        }
    // A copy reads its source, which the source bucket's owner and policy have their say on as a GetObject.
    const bool copy = copy_from && action == s3_action::put_object;
    policy_effect src = policy_effect::none;
    std::string sb, sk;
    if (copy)
    {
        std::string sv;
        s3_error    ignored;
        if (parse_copy_source(r.header("x-amz-copy-source"), sb, sk, ignored, &sv))
        {
            policy_request sq = pr;
            // The read of the source is no write, so it carries no encryption of its own.
            sq.sse_sent      = false;
            sq.sse           = {};
            sq.sse_inherited = false;
            sq.action = sv.empty() ? s3_action::get_object : s3_action::get_object_version;
            sq.bucket = sb;
            sq.key    = sk;
            src       = judge(sb, sq);
        }
        else if (u)
            src = policy_effect::allow;
    }

    if (dest == policy_effect::deny || src == policy_effect::deny)
    {
        s3_error e = make_error("AccessDenied");
        const bucket_policy* broken = m_store.policy(dest == policy_effect::deny ? std::string_view(r.bucket)
                                                                                 : std::string_view(sb));
        if (broken && !broken->broken().empty())
            e.message = "The policy stored for this bucket cannot be applied (" + broken->broken() +
                        "), so only the bucket policy operations are served until it is replaced or deleted";
        refuse(std::move(e));
        return;
    }
    // A user that does not own the bucket, is no admin and is let in by no policy is refused.
    if (u && v.allowed && (dest != policy_effect::allow || (copy && src != policy_effect::allow)))
    {
        refuse(make_error("AccessDenied"));
        return;
    }
    // Whether the runtime let the request in before any policy did, which only an anonymous one may lack.
    const bool by_credentials = v.allowed;
    if (!v.allowed && v.anonymous && dest == policy_effect::allow && (!copy || src == policy_effect::allow))
    {
        v.allowed = true;
        v.error   = {};
        v.hook    = unsigned_trailer_hook(rv);
        c->policy_admitted = true;
    }
    if (!v.allowed || !(copy || action_on_object(action)))
        return;
    // A key that is not there is told only to whoever may list the bucket it would be in.
    policy_request lq = pr;
    lq.action    = s3_action::list_bucket;
    lq.bucket    = copy ? std::string_view(sb) : std::string_view(r.bucket);
    lq.key       = {};
    lq.every_key = false;
    lq.sse_sent      = false;
    lq.sse           = {};
    lq.sse_inherited = false;
    const policy_effect list = judge(lq.bucket, lq);
    c->hide_missing = list == policy_effect::deny || ((u || !by_credentials) && list != policy_effect::allow);
}

bool storage_run::docs_settled(const std::shared_ptr<conn>& c)
{
    const s3_request& r = c->req;
    bool settled = r.bucket.empty() || m_store.docs_settled(r.bucket);
    if (settled && r.method == "PUT" && !r.key.empty() && r.has_header("x-amz-copy-source"))
    {
        std::string sb, sk;
        s3_error    ignored;
        if (parse_copy_source(r.header("x-amz-copy-source"), sb, sk, ignored))
            settled = m_store.docs_settled(sb);
    }
    if (settled)
        return true;
    s3_error e = make_error("ServiceUnavailable");
    e.message  = "A change to the configuration of this bucket is being made, so retry the request";
    deny_request(c, e);
    return false;
}

policy_effect storage_run::access_of(const std::shared_ptr<conn>& c, std::string_view bucket, const policy_request& q,
                                     const user_identity* u)
{
    if (const bucket_policy* bound = u ? u->session_policy.get() : nullptr)
    {
        if (bound->needs_ip() && !c->ip_known)
        {
            c->ip       = client_ip_of(c->sock());
            c->ip_known = true;
        }
        // A session's policy bounds everything else: what it does not allow nothing else can.
        const policy_effect e = bound->evaluate(q);
        if (e != policy_effect::allow)
            return e == policy_effect::deny ? policy_effect::deny : policy_effect::none;
    }
    policy_effect own = u && u->has_policy ? u->policy.evaluate(q) : policy_effect::none;
    // The IAM API's policies of a credentials-file user stand beside the file's: either's Deny refuses, either's Allow
    // admits.
    if (const bucket_policy* extra = u ? u->iam_policy.get() : nullptr)
    {
        const policy_effect e = extra->evaluate(q);
        if (e == policy_effect::deny || (e == policy_effect::allow && own == policy_effect::none))
            own = e;
    }
    if (own == policy_effect::deny)
        return policy_effect::deny;
    // An admin, the owner, and anybody at all on a bucket that is not there, which the operation answers for.
    const bool full = u && (u->admin || !m_store.has_bucket(bucket) || owner_of(bucket) == u->id);
    const bucket_policy* p = m_store.policy(bucket);
    policy_effect pol = policy_effect::none;
    // The bucket's policy is asked for its Deny always, and for its Allow only when nothing else lets the request in.
    if (p && (!u || p->has_deny() || (!full && own != policy_effect::allow)))
    {
        if (p->needs_ip() && !c->ip_known)
        {
            c->ip       = client_ip_of(c->sock());
            c->ip_known = true;
        }
        pol = p->evaluate(q);
        // A public policy lets in nobody without credentials while the bucket restricts it.
        if (!u && pol == policy_effect::allow && p->is_public())
            if (const auto pab = m_store.bucket_public_access(bucket); pab && pab->restrict_public_buckets)
                pol = policy_effect::none;
    }
    if (pol == policy_effect::deny)
        return policy_effect::deny;
    if (full || own == policy_effect::allow || pol == policy_effect::allow)
        return policy_effect::allow;
    // A bucket that takes ACLs admits what its ACL grants, a grant to everyone only while it does not ignore those.
    if (const uint8_t need = bucket_acl_need(q.action); need && bucket_ownership(bucket) != object_ownership::enforced)
    {
        const auto kept = m_store.bucket_acl(bucket);
        const acl_list a = kept ? *kept : default_acl(std::string(owner_of(bucket)));
        const auto pab = m_store.bucket_public_access(bucket);
        const std::string_view id = u ? std::string_view(u->id) : std::string_view{};
        if ((acl_grants(a, id, u != nullptr, pab && pab->ignore_public_acls) & need) == need)
        {
            c->by_acl = true;
            return policy_effect::allow;
        }
    }
    return policy_effect::none;
}

bool storage_run::secure(conn& c)
{
    if (c.tls())
        return true;
    if (m_tls_offloaded.empty())
        return false;
    if (!c.ip_known)
    {
        c.ip       = client_ip_of(c.sock());
        c.ip_known = true;
    }
    for (const bucket_policy::cidr& b : m_tls_offloaded)
        if (cidr_holds(b, c.ip))
            return true;
    return false;
}

policy_effect storage_run::iam_access(const std::shared_ptr<conn>& c, const user_identity& u, std::string_view principal,
                                      int action, std::string_view resource)
{
    if (!c->ip_known && ((u.has_policy && u.policy.needs_ip()) || (u.iam_policy && u.iam_policy->needs_ip())))
    {
        c->ip       = client_ip_of(c->sock());
        c->ip_known = true;
    }
    const request_context ctx(*c, &u, false, static_cast<int64_t>(m_store.now_ms()));
    policy_request q;
    q.ctx          = &ctx;
    q.iam_action   = action;
    q.iam_resource = resource;
    q.principal    = principal;
    q.user         = u.configured ? std::string_view(u.id) : std::string_view{};
    q.tls          = secure(*c);
    q.ip           = &c->ip;
    policy_effect own = u.has_policy ? u.policy.evaluate(q) : policy_effect::none;
    // The IAM API's policies of a credentials-file user stand beside the file's, as they do for S3.
    if (const bucket_policy* extra = u.iam_policy.get())
    {
        const policy_effect e = extra->evaluate(q);
        if (e == policy_effect::deny || (e == policy_effect::allow && own == policy_effect::none))
            own = e;
    }
    return own;
}

bool storage_run::policy_allows(const std::shared_ptr<conn>& c, s3_action action, std::string_view key)
{
    const user_identity* u = c->anonymous ? nullptr : c->user.get();
    if (!needs_judging(u))
        return true;
    const request_context ctx(*c, u, c->anonymous, static_cast<int64_t>(m_store.now_ms()));
    policy_request q;
    q.ctx       = &ctx;
    q.action    = action;
    q.bucket    = c->req.bucket;
    q.key       = key;
    q.anonymous = c->anonymous;
    q.principal = c->principal;
    q.user      = u && u->configured ? std::string_view(u->id) : std::string_view{};
    q.tls       = secure(*c);
    q.ip        = &c->ip;
    const policy_effect e = access_of(c, c->req.bucket, q, u);
    if (u)
        return e == policy_effect::allow;
    // A request a policy let in is let do this only by an Allow of it too.
    return e != policy_effect::deny && (!c->policy_admitted || e == policy_effect::allow);
}

bool storage_run::policy_allows_version_delete(const std::shared_ptr<conn>& c, std::string_view key)
{
    return policy_allows(c, s3_action::delete_object_version, key);
}

}   // namespace socketley::storage
