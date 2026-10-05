// ACLs and object ownership: a bucket's ownership controls and ACL, an object's owner and grants, the writes that
// set them and the grants that admit a request.
#include "storage_run.h"

#include "s3_acl.h"
#include "s3_public_access.h"
#include "s3_xml.h"

namespace socketley::storage
{

namespace
{

acl_request acl_request_of(const s3_request& r)
{
    acl_request a;
    a.canned   = r.header("x-amz-acl");
    a.grant[0] = r.header("x-amz-grant-read");
    a.grant[1] = r.header("x-amz-grant-write");
    a.grant[2] = r.header("x-amz-grant-read-acp");
    a.grant[3] = r.header("x-amz-grant-write-acp");
    a.grant[4] = r.header("x-amz-grant-full-control");
    return a;
}

// What of an object's own grants a request needs, none for one they say nothing to.
uint8_t object_need(s3_action a)
{
    switch (a)
    {
        case s3_action::get_object:
        case s3_action::get_object_version:     return acl_perm::read;
        case s3_action::get_object_acl:
        case s3_action::get_object_version_acl: return acl_perm::read_acp;
        case s3_action::put_object_acl:
        case s3_action::put_object_version_acl: return acl_perm::write_acp;
        default:                                return 0;
    }
}

}   // namespace

uint8_t bucket_acl_need(s3_action a)
{
    switch (a)
    {
        case s3_action::list_bucket:
        case s3_action::list_bucket_versions:
        case s3_action::list_bucket_multipart_uploads: return acl_perm::read;
        case s3_action::put_object:
        case s3_action::delete_object:
        case s3_action::delete_object_version:
        case s3_action::abort_multipart_upload:        return acl_perm::write;
        case s3_action::get_bucket_acl:                return acl_perm::read_acp;
        case s3_action::put_bucket_acl:                return acl_perm::write_acp;
        default:                                       return 0;
    }
}

uint8_t object_acl_need(s3_action a)
{
    return object_need(a);
}

object_ownership storage_run::bucket_ownership(std::string_view bucket) const
{
    const object_ownership o = m_store.bucket_ownership(bucket);
    if (o != object_ownership::unset)
        return o;
    return m_acls_default ? object_ownership::writer : object_ownership::enforced;
}

acl_resolver storage_run::acl_users() const
{
    acl_resolver r;
    r.has_user = [this](std::string_view id) { return id == default_owner || (m_auth && m_auth->has_user(id)); };
    r.user_of_email = [this](std::string_view e) { return m_auth ? m_auth->user_of_email(e) : std::string(); };
    return r;
}

bool storage_run::acl_headers_ok(const std::shared_ptr<conn>& c, bool bucket, s3_error& err)
{
    const s3_request& r = c->req;
    const acl_request rq = acl_request_of(r);
    const std::string requester = c->user ? c->user->id : std::string();
    if (bucket)
    {
        object_ownership o = object_ownership::unset;
        if (!ownership_of_header(r.header("x-amz-object-ownership"), o))
        {
            err = make_error("InvalidArgument");
            err.message = "Invalid x-amz-object-ownership header";
            return false;
        }
        if (!rq.any())
            return true;
        if (o == object_ownership::unset)
            o = m_acls_default ? object_ownership::writer : object_ownership::enforced;
        const std::string me = requester.empty() ? std::string(default_owner) : requester;
        acl_list a;
        if (!acl_from_request(rq, true, me, me, acl_users(), a, err))
            return false;
        if (o == object_ownership::enforced && !(a == default_acl(me)))
        {
            err = make_error("InvalidBucketAclWithObjectOwnership");
            return false;
        }
        return true;
    }
    if (!rq.any())
        return true;
    const std::string owner(owner_of(r.bucket));
    // ACLs disabled take the owner's full control alone: private from the owner, or that full control by name.
    if (bucket_ownership(r.bucket) == object_ownership::enforced)
    {
        acl_list a;
        s3_error ignored;
        const bool taken = rq.canned == "bucket-owner-full-control" ||
                           (acl_from_request(rq, false, owner, owner, acl_users(), a, ignored) &&
                            a == default_acl(owner) && (rq.canned != "private" || requester.empty() || requester == owner));
        if (!taken)
            err = make_error("AccessControlListNotSupported");
        return taken;
    }
    acl_list a;
    if (!acl_from_request(rq, false, requester.empty() ? owner : requester, owner, acl_users(), a, err))
        return false;
    if (const auto pab = m_store.bucket_public_access(r.bucket); pab && pab->block_public_acls && acl_is_public(a))
    {
        err = make_error("AccessDenied");
        return false;
    }
    return true;
}

bool storage_run::object_acl_stamp(const std::shared_ptr<conn>& c, object_meta& m, s3_error& err)
{
    set_object_acl(m, {});
    const s3_request& r = c->req;
    const object_ownership o = bucket_ownership(r.bucket);
    if (o == object_ownership::enforced)
        return true;
    const std::string bowner(owner_of(r.bucket));
    const acl_request rq = acl_request_of(r);
    // The writer owns what it writes, unless the bucket prefers its owner and the write gave that owner full control.
    std::string writer = c->user && !c->anonymous ? c->user->id : bowner;
    if (o == object_ownership::preferred && rq.canned == "bucket-owner-full-control")
        writer = bowner;
    acl_list a;
    if (!acl_from_request(rq, false, writer, bowner, acl_users(), a, err))
        return false;
    if (!(a == default_acl(bowner)))
        set_object_acl(m, encode_acl(a));
    return true;
}

bool storage_run::acl_admits(const std::shared_ptr<conn>& c, const object_meta& m)
{
    if (!c->acl_need)
        return true;
    const acl_list a = object_acl_of(m, std::string(owner_of(c->req.bucket)));
    const auto pab = m_store.bucket_public_access(c->req.bucket);
    const std::string id = c->user && !c->anonymous ? c->user->id : std::string();
    const bool granted = (acl_grants(a, id, !id.empty(), pab && pab->ignore_public_acls) & c->acl_need) == c->acl_need;
    c->by_acl = c->by_acl || granted;
    return granted;
}

void storage_run::create_bucket_docs(const std::shared_ptr<conn>& c, const std::string& name,
                                     std::function<void(st)> then)
{
    const s3_request& r = c->req;
    object_ownership o = object_ownership::unset;
    if (!ownership_of_header(r.header("x-amz-object-ownership"), o))
        o = object_ownership::unset;
    const std::string me = c->user ? c->user->id : std::string(default_owner);
    acl_list a;
    s3_error ignored;
    std::string acl_text;
    if (acl_from_request(acl_request_of(r), true, me, me, acl_users(), a, ignored) && !(a == default_acl(me)))
        acl_text = encode_acl(a);
    auto set_acl = [this, name, acl_text, then]()
    {
        if (acl_text.empty())
        {
            then(st::ok);
            return;
        }
        m_node.set_doc(bucket_doc::acl, name, acl_text, then);
    };
    if (o == object_ownership::unset)
    {
        set_acl();
        return;
    }
    m_node.set_doc(bucket_doc::ownership, name, ownership_controls_xml(o), [set_acl, then](st s)
    {
        if (s != st::ok)
        {
            then(s);
            return;
        }
        set_acl();
    });
}

// ─── The operations ─────────────────────────────────────────────────────────

void storage_run::op_get_acl(const std::shared_ptr<conn>& c)
{
    const s3_request& r = c->req;
    if (!m_store.has_bucket(r.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    auto display = [this](std::string_view id) { return display_of(id); };
    if (r.key.empty())
    {
        const auto kept = m_store.bucket_acl(r.bucket);
        response resp;
        resp.headers.emplace_back("Content-Type", "application/xml");
        resp.body = acl_xml(kept ? *kept : default_acl(std::string(owner_of(r.bucket))), display);
        send_response(c, std::move(resp));
        return;
    }
    // The object must be there, as S3 answers NoSuchKey for one that is not, and its own grants say who reads them.
    std::weak_ptr<conn> weak = c;
    auto then = [this, weak, display](st s, const object_meta& m)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (s != st::ok || is_delete_marker(m))
        {
            send_error_st(cc, s == st::ok || s == st::delete_marker ? st::no_such_key : s);
            return;
        }
        if (!acl_admits(cc, m))
        {
            send_error(cc, make_error("AccessDenied"));
            return;
        }
        response resp;
        resp.headers.emplace_back("Content-Type", "application/xml");
        resp.body = acl_xml(object_acl_of(m, std::string(owner_of(cc->req.bucket))), display);
        send_response(cc, std::move(resp));
    };
    if (const std::string version(r.get_query("versionId")); !version.empty())
        m_store.stat_version(r.bucket, r.key, version, std::move(then));
    else if (m_store.owns(r.bucket, r.key))
    {
        const object_meta* m = m_store.find(r.bucket, r.key);
        then(m ? st::ok : st::no_such_key, m ? *m : object_meta{});
    }
    else
        m_store.stat_foreign(r.bucket, r.key, std::move(then));
}

void storage_run::op_put_acl(const std::shared_ptr<conn>& c)
{
    const s3_request& r = c->req;
    if (!m_store.has_bucket(r.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    const acl_request rq = acl_request_of(r);
    if (rq.any() && !c->body.empty())
    {
        s3_error e = make_error("UnexpectedContent");
        e.message = "This request does not support content with ACL headers";
        send_error(c, e);
        return;
    }
    const std::string bowner(owner_of(r.bucket));
    const bool enforced = bucket_ownership(r.bucket) == object_ownership::enforced;
    // The ACL asked for of a resource owned by `owner`, refused as S3 refuses it, or null after the refusal is sent.
    auto asked = [this, rq, bowner, enforced](const std::shared_ptr<conn>& cc, const std::string& owner, bool bucket,
                                             acl_list& out) -> bool
    {
        s3_error err;
        const bool ok = rq.any() ? acl_from_request(rq, bucket, owner, bowner, acl_users(), out, err)
                      : !cc->body.empty() ? parse_acl_xml(cc->body, owner, acl_users(), out, err)
                                          : (err = make_error("MissingSecurityHeader"), false);
        if (!ok)
        {
            send_error(cc, err);
            return false;
        }
        // Where ACLs are disabled the owner's full control alone is taken, and private only from the bucket's owner,
        // since from anybody else it would give the writer the control.
        const bool other = cc->user && cc->user->id != bowner;
        if (enforced && rq.canned != "bucket-owner-full-control" &&
            (!(out == default_acl(owner)) || (rq.canned == "private" && other)))
        {
            send_error(cc, make_error("AccessControlListNotSupported"));
            return false;
        }
        if (const auto pab = m_store.bucket_public_access(cc->req.bucket); pab && pab->block_public_acls &&
                                                                         acl_is_public(out))
        {
            send_error(cc, make_error("AccessDenied"));
            return false;
        }
        return true;
    };
    if (r.key.empty())
    {
        acl_list a;
        if (!asked(c, bowner, true, a))
            return;
        store_doc(c, bucket_doc::acl, r.bucket, a == default_acl(bowner) ? std::string() : encode_acl(a), 200);
        return;
    }
    std::weak_ptr<conn> weak = c;
    auto then = [this, weak, asked, bowner, enforced](st s, const object_meta& m)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (s != st::ok || is_delete_marker(m))
        {
            send_error_st(cc, s == st::ok || s == st::delete_marker ? st::no_such_key : s);
            return;
        }
        if (!acl_admits(cc, m))
        {
            send_error(cc, make_error("AccessDenied"));
            return;
        }
        acl_list a;
        if (!asked(cc, object_acl_of(m, bowner).owner, false, a))
            return;
        // Where ACLs are disabled the one ACL taken is the one every object has, so nothing changes.
        if (enforced)
        {
            send_response(cc, response{});
            return;
        }
        header_change change;
        change.what  = header_change::kind::acl;
        change.value = a == default_acl(bowner) ? std::string() : encode_acl(a);
        change.who   = origin_of(*cc);
        std::weak_ptr<conn> w2 = cc;
        m_store.change_header(cc->req.bucket, cc->req.key, std::string(cc->req.get_query("versionId")),
                              std::move(change), [this, w2](st s2, std::string version)
        {
            auto c2 = w2.lock();
            if (!c2 || c2->dead)
                return;
            if (s2 != st::ok)
            {
                send_error_st(c2, s2 == st::delete_marker ? st::no_such_key : s2);
                return;
            }
            response resp;
            if (!version.empty())
                resp.headers.emplace_back("x-amz-version-id", version);
            send_response(c2, std::move(resp));
        });
    };
    if (const std::string version(r.get_query("versionId")); !version.empty())
        m_store.stat_version(r.bucket, r.key, version, std::move(then));
    else if (m_store.owns(r.bucket, r.key))
    {
        const object_meta* m = m_store.find(r.bucket, r.key);
        then(m ? st::ok : st::no_such_key, m ? *m : object_meta{});
    }
    else
        m_store.stat_foreign(r.bucket, r.key, std::move(then));
}

void storage_run::op_ownership_controls(const std::shared_ptr<conn>& c)
{
    const s3_request& r = c->req;
    if (!m_store.has_bucket(r.bucket))
    {
        send_error_st(c, st::no_such_bucket);
        return;
    }
    if (r.method == "GET")
    {
        const object_ownership o = m_store.bucket_ownership(r.bucket);
        // Without --acls a bucket given none is BucketOwnerEnforced, as S3 makes every bucket now.
        if (o == object_ownership::unset && m_acls_default)
        {
            send_error(c, make_error("OwnershipControlsNotFoundError"));
            return;
        }
        response resp;
        resp.headers.emplace_back("Content-Type", "application/xml");
        resp.body = ownership_controls_xml(o == object_ownership::unset ? object_ownership::enforced : o);
        send_response(c, std::move(resp));
        return;
    }
    if (r.method == "DELETE")
    {
        store_doc(c, bucket_doc::ownership, r.bucket, {}, 204);
        return;
    }
    object_ownership o = object_ownership::unset;
    if (s3_error err; !parse_ownership_controls(c->body, o, err))
    {
        send_error(c, err);
        return;
    }
    // ACLs are disabled only on a bucket whose own ACL is its owner's full control.
    if (o == object_ownership::enforced)
        if (const auto a = m_store.bucket_acl(r.bucket); a && !(*a == default_acl(std::string(owner_of(r.bucket)))))
        {
            send_error(c, make_error("InvalidBucketAclWithObjectOwnership"));
            return;
        }
    store_doc(c, bucket_doc::ownership, r.bucket, ownership_controls_xml(o), 200);
}

}   // namespace socketley::storage
