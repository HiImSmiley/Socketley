// A bucket's policy over S3: setting, reading and removing it, its status, and
// the judgement of ownership and policy every request is given after it is
// authenticated and before a script's on_request sees it.
#include "storage_run.h"

#include "bucket_policy.h"
#include "s3_sigv4_auth.h"
#include "s3_xml.h"

namespace socketley::storage
{

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
    std::weak_ptr<conn> weak = c;
    m_node.set_doc(bucket_doc::policy, q.bucket, c->body, [this, weak](st s)
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
    std::weak_ptr<conn> weak = c;
    m_node.set_doc(bucket_doc::policy, c->req.bucket, {}, [this, weak](st s)
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
    // Every user may ask for the list of its own buckets.
    if (r.bucket.empty())
        return;
    const user_identity* u = v.anonymous ? nullptr : v.user.get();
    const bool restricted = u && !u->unrestricted();
    // A request that only a Deny could refuse is let through without a look when its bucket has none.
    const bool copy_from = r.method == "PUT" && !r.key.empty() && r.has_header("x-amz-copy-source");
    if (!copy_from && !restricted)
    {
        const bucket_policy* p = m_store.policy(r.bucket);
        if (!p || (!v.anonymous && !p->has_deny()))
            return;
    }

    // A request that names a version is the version's own action, as S3 judges it.
    const s3_action plain  = action_of_operation(operation_name(r));
    const s3_action action = r.has_query("versionId") ? version_action(plain) : plain;

    policy_request pr;
    pr.action    = action;
    pr.bucket    = r.bucket;
    pr.key       = r.key;
    pr.anonymous = v.anonymous;
    pr.principal = v.principal;
    pr.user      = u && u->configured ? std::string_view(u->id) : std::string_view{};
    pr.tls       = c->ssl != nullptr;
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
    // A bucket is anybody's to make whose own policy does not deny it, and one that is there is answered by the
    // operation.
    if (action == s3_action::create_bucket)
    {
        if (u && u->has_policy && u->policy.evaluate(pr) == policy_effect::deny)
            refuse(make_error("AccessDenied"));
        return;
    }
    // The owner of a bucket and an admin answer to their credentials alone for the bucket's policy, so a policy
    // that shuts everyone out can be removed, and for what no policy names.
    const bool policy_op = action == s3_action::put_bucket_policy || action == s3_action::get_bucket_policy ||
                           action == s3_action::delete_bucket_policy || action == s3_action::get_bucket_policy_status;
    if (action == s3_action::none || policy_op)
    {
        if (!restricted || u->admin || !m_store.has_bucket(r.bucket) || owner_of(r.bucket) == u->id)
            return;
        if (action == s3_action::none || access_of(c, r.bucket, pr, u) != policy_effect::allow)
            refuse(make_error("AccessDenied"));
        return;
    }

    auto judge = [this, &c, u](std::string_view bucket, const policy_request& q) { return access_of(c, bucket, q, u); };

    const policy_effect dest = judge(r.bucket, pr);
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
    const policy_effect own = u && u->has_policy ? u->policy.evaluate(q) : policy_effect::none;
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
            c->ip       = client_ip_of(c->fd);
            c->ip_known = true;
        }
        pol = p->evaluate(q);
    }
    if (pol == policy_effect::deny)
        return policy_effect::deny;
    if (full || own == policy_effect::allow || pol == policy_effect::allow)
        return policy_effect::allow;
    return policy_effect::none;
}

bool storage_run::policy_allows_version_delete(const std::shared_ptr<conn>& c, std::string_view key)
{
    return policy_allows(c, s3_action::delete_object_version, key);
}

}   // namespace socketley::storage
