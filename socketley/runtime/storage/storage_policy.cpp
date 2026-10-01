// A bucket's policy over S3: setting, reading and removing it, its status, and
// the judgement every request to a bucket with one is given after it is
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
    if (r.bucket.empty())
        return;
    // A signed request is already let in, so only a denial can change what it is told.
    const bool copy_from = r.method == "PUT" && !r.key.empty() && r.has_header("x-amz-copy-source");
    if (!copy_from)
    {
        const bucket_policy* p = m_store.policy(r.bucket);
        if (!p || (!v.anonymous && !p->has_deny()))
            return;
    }

    const s3_action action = action_of_operation(operation_name(r));
    // The policy's own operations answer to the credentials alone, so a policy that shuts everyone out can be removed.
    if (action == s3_action::none || action == s3_action::put_bucket_policy || action == s3_action::get_bucket_policy ||
        action == s3_action::delete_bucket_policy || action == s3_action::get_bucket_policy_status)
        return;

    policy_request pr;
    pr.action    = action;
    pr.key       = r.key;
    pr.anonymous = v.anonymous;
    pr.principal = v.principal;
    pr.tls       = c->ssl != nullptr;
    pr.ip        = &c->ip;
    pr.every_key = action == s3_action::delete_object && r.key.empty();

    auto judge = [this, &c](std::string_view bucket, const policy_request& q)
    {
        const bucket_policy* p = m_store.policy(bucket);
        if (!p || (!q.anonymous && !p->has_deny()))
            return policy_effect::none;
        if (p->needs_ip() && !c->ip_known)
        {
            c->ip       = client_ip_of(c->fd);
            c->ip_known = true;
        }
        return p->evaluate(q);
    };

    const policy_effect dest = judge(r.bucket, pr);
    // A copy reads its source, which the source bucket's policy has its say on as a GetObject.
    const bool copy = copy_from && action == s3_action::put_object;
    policy_effect src = policy_effect::none;
    if (copy)
    {
        std::string sb, sk;
        s3_error    ignored;
        if (parse_copy_source(r.header("x-amz-copy-source"), sb, sk, ignored))
        {
            policy_request sq = pr;
            sq.action = s3_action::get_object;
            sq.key    = sk;
            src       = judge(sb, sq);
        }
    }

    if (dest == policy_effect::deny || src == policy_effect::deny)
    {
        v.allowed = false;
        v.error   = make_error("AccessDenied");
        v.hook.reset();
        return;
    }
    if (v.allowed || !v.anonymous)
        return;
    if (dest == policy_effect::allow && (!copy || src == policy_effect::allow))
    {
        v.allowed = true;
        v.error   = {};
        v.hook    = unsigned_trailer_hook(rv);
    }
}

}   // namespace socketley::storage
