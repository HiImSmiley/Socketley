// STS over the S3 endpoint: GetSessionToken and AssumeRole, which give a user temporary credentials that sign for it,
// and AssumeRoleWithWebIdentity and AssumeRoleWithLDAPIdentity, which give them to an identity an outside provider
// vouches for.
#include "storage_run.h"

#include <algorithm>
#include <chrono>
#include <charconv>

#include "bucket_policy.h"
#include "digest.h"
#include "s3_iam.h"
#include "s3_sts.h"

namespace socketley::storage
{

void storage_run::sts_fail(const std::shared_ptr<conn>& c, int status, std::string_view code, std::string_view message)
{
    count_error(*c, code);
    response resp;
    resp.status = status;
    resp.headers.emplace_back("Content-Type", "text/xml");
    resp.body = sts_error_xml(code, message, c->req.request_id);
    send_response(c, std::move(resp));
}

void storage_run::op_sts(const std::shared_ptr<conn>& c)
{
    const s3_request& r = c->req;
    auto fail = [this, &c](int status, std::string_view code, std::string_view message)
    { sts_fail(c, status, code, message); };

    std::vector<std::pair<std::string, std::string>> fields = r.query;
    if (!parse_form_fields(c->body, fields))
    {
        fail(400, "MalformedInput", "The form does not decode.");
        return;
    }
    auto field = [&fields](std::string_view name) -> const std::string*
    {
        for (const auto& [k, v] : fields)
            if (k == name)
                return &v;
        return nullptr;
    };

    // An outside provider's identity carries no signature of ours, so it is judged before one is looked for.
    if (const std::string* a = field("Action"); a && (*a == "AssumeRoleWithWebIdentity" || *a == "AssumeRoleWithLDAPIdentity"))
    {
        op_sts_federated(c, fields, *a);
        return;
    }
    // The form is what the signature covers, by its hash when the client sent none of its own.
    const std::string body_hash = sha256_hex(c->body);
    if (!r.payload_hash.empty() && r.payload_hash != "UNSIGNED-PAYLOAD" && r.payload_hash != body_hash)
    {
        fail(400, "XAmzContentSHA256Mismatch", "The provided 'x-amz-content-sha256' header does not match what was computed.");
        return;
    }
    request_view rv;
    rv.method          = r.method;
    rv.raw_path        = r.raw_path;
    rv.raw_query       = r.raw_query;
    rv.host            = r.host;
    rv.payload_hash    = r.payload_hash;
    rv.headers         = &r.headers;
    rv.tls             = secure(*c);
    rv.body_sha256_hex = body_hash;
    const std::string_view authz = r.header("authorization");
    rv.service = authz.find("/sts/aws4_request") != std::string_view::npos   ? "sts"
               : authz.find("/iam/aws4_request") != std::string_view::npos ? "iam"
                                                                           : "s3";
    const auth_verdict v = m_auth->authorize(rv);
    if (v.anonymous)
    {
        fail(403, "MissingAuthenticationToken", "Request is missing Authentication Token");
        return;
    }
    if (!v.allowed)
    {
        const bool unknown = v.error.code == "InvalidAccessKeyId";
        fail(v.error.status ? v.error.status : 403, unknown ? "InvalidClientTokenId" : v.error.code,
             unknown ? "The security token included in the request is invalid." : v.error.message);
        return;
    }
    const std::string* action = field("Action");
    // IAM's API shares the endpoint and the form, as one service of the runtime's own.
    if (action && iam_action(*action))
    {
        op_iam(c, fields, *action, v);
        return;
    }
    // Who signed the request, a session included, as STS tells it.
    if (action && *action == "GetCallerIdentity")
    {
        const std::string id = v.user ? v.user->id : std::string{};
        // A user the IAM API made is named by the id and the path it was given, as IAM's own answers name it.
        const bool made = v.user && !v.user->iam_id.empty() && !v.session;
        const std::string arn = id.starts_with("role/") ? "arn:aws:sts:::assumed-role/" + id.substr(5)
                              : "arn:aws:iam::" + std::string(iam_account) + ":user" +
                                    (made ? v.user->iam_path : std::string("/")) + id;
        const std::string& user_id = made ? v.user->iam_id : v.principal;
        response resp;
        resp.headers.emplace_back("Content-Type", "text/xml");
        resp.body = "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">"
                    "<GetCallerIdentityResult><Arn>" + xml_escape(arn) + "</Arn><UserId>" + xml_escape(user_id) +
                    "</UserId><Account></Account></GetCallerIdentityResult><ResponseMetadata><RequestId>" +
                    r.request_id + "</RequestId></ResponseMetadata></GetCallerIdentityResponse>";
        send_response(c, std::move(resp));
        return;
    }
    if (v.session)
    {
        fail(403, "AccessDenied", "Temporary credentials cannot ask for more; sign with the user's own key.");
        return;
    }

    const bool assume = action && *action == "AssumeRole";
    if (!action || (!assume && *action != "GetSessionToken"))
    {
        fail(400, "InvalidAction", "Could not find operation " + (action ? *action : std::string{}) + " for version 2011-06-15");
        return;
    }
    // STS's bounds: an hour by default for a role and twelve for a session, up to twelve and thirty-six.
    int64_t duration = assume ? 3600 : 43200;
    const int64_t longest = assume ? 43200 : 129600;
    if (const std::string* d = field("DurationSeconds"))
    {
        const auto res = std::from_chars(d->data(), d->data() + d->size(), duration);
        if (res.ec != std::errc{} || res.ptr != d->data() + d->size() || duration < 900 || duration > longest)
        {
            fail(400, "ValidationError", "DurationSeconds must be between 900 and " + std::to_string(longest) + ".");
            return;
        }
    }
    std::string role_arn, session_name, policy, role;
    if (assume)
    {
        const std::string* arn  = field("RoleArn");
        const std::string* name = field("RoleSessionName");
        if (!arn || arn->empty() || arn->size() > 2048 || !name || name->size() < 2 || name->size() > 64)
        {
            fail(400, "ValidationError", "AssumeRole needs a RoleArn and a RoleSessionName of 2 to 64 characters.");
            return;
        }
        role_arn     = *arn;
        session_name = *name;
        // A role the IAM API made is assumed only as its trust policy lets, for no longer than it allows; any
        // other ARN is the caller's own session, bounded by its Policy.
        int64_t longest_role = 0;
        const std::string_view rname = iam_role_name_of(*arn);
        const int rc = v.user ? m_auth->role_check(rname, v.user->id, longest_role) : -1;
        if (rc == 0)
        {
            fail(403, "AccessDenied", "User " + v.user->id + " is not authorized to perform sts:AssumeRole on " + *arn);
            return;
        }
        if (rc == 1)
        {
            if (field("DurationSeconds") && duration > longest_role)
            {
                fail(400, "ValidationError", "DurationSeconds exceeds the MaxSessionDuration of the role.");
                return;
            }
            role = std::string(rname);
        }
        if (const std::string* p = field("Policy"))
        {
            bucket_policy checked;
            s3_error err;
            if (p->size() > sts_policy_max)
            {
                fail(400, "PackedPolicyTooLarge", "The session policy is larger than 2048 bytes.");
                return;
            }
            if (!bucket_policy::compile_identity(*p, checked, err))
            {
                fail(400, "MalformedPolicyDocument", err.message);
                return;
            }
            policy = *p;
        }
    }
    else if (field("Policy"))
    {
        fail(400, "InvalidParameterCombination", "GetSessionToken takes no Policy; AssumeRole does.");
        return;
    }

    const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    session_credentials sc;
    if (!m_auth->issue_session(v.principal, now + duration, policy, role, sc))
    {
        fail(403, "AccessDenied", "This runtime's credentials cannot give out temporary ones.");
        return;
    }
    response resp;
    resp.headers.emplace_back("Content-Type", "text/xml");
    resp.body = sts_credentials_xml(*action, sc.access_key, sc.secret, sc.token, sc.expires, role_arn, session_name,
                                    r.request_id);
    send_response(c, std::move(resp));
}

void storage_run::op_sts_federated(const std::shared_ptr<conn>& c,
                                   const std::vector<std::pair<std::string, std::string>>& fields, std::string_view action)
{
    auto field = [&fields](std::string_view name) -> const std::string*
    {
        for (const auto& [k, v] : fields)
            if (k == name)
                return &v;
        return nullptr;
    };
    const bool web = action == "AssumeRoleWithWebIdentity";
    if (!m_auth || (web ? !m_oidc : !m_fed || !m_fed->ldap.enabled()))
    {
        sts_fail(c, 400, "InvalidParameterValue", web ? "This runtime takes no web identities: it has no OIDC provider."
                                                      : "This runtime takes no LDAP identities: it has no directory.");
        return;
    }
    // STS's bounds for a role: an hour by default, up to twelve.
    int64_t duration = 3600;
    if (const std::string* d = field("DurationSeconds"))
    {
        const auto res = std::from_chars(d->data(), d->data() + d->size(), duration);
        if (res.ec != std::errc{} || res.ptr != d->data() + d->size() || duration < 900 || duration > 43200)
        {
            sts_fail(c, 400, "ValidationError", "DurationSeconds must be between 900 and 43200.");
            return;
        }
    }
    std::string policy;
    if (const std::string* p = field("Policy"))
    {
        bucket_policy checked;
        s3_error err;
        if (p->size() > sts_policy_max)
        {
            sts_fail(c, 400, "PackedPolicyTooLarge", "The session policy is larger than 2048 bytes.");
            return;
        }
        if (!bucket_policy::compile_identity(*p, checked, err))
        {
            sts_fail(c, 400, "MalformedPolicyDocument", err.message);
            return;
        }
        policy = *p;
    }
    auto known = [this](std::string_view u) { return m_auth->has_user(u); };

    if (web)
    {
        const std::string* token = field("WebIdentityToken");
        const std::string* arn   = field("RoleArn");
        const std::string* name  = field("RoleSessionName");
        if (!token || token->empty() || !arn || arn->empty() || arn->size() > 2048 || !name || name->size() < 2 ||
            name->size() > 64)
        {
            sts_fail(c, 400, "ValidationError",
                     "AssumeRoleWithWebIdentity needs a WebIdentityToken, a RoleArn and a RoleSessionName of 2 to 64 "
                     "characters.");
            return;
        }
        const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        oidc_identity id;
        std::string why, user;
        if (!m_oidc->verify(*token, now, id, why))
        {
            sts_fail(c, 400, id.expired ? "ExpiredTokenException" : "InvalidIdentityToken",
                     id.expired ? std::string("Token expired") : "The web identity token is not one this runtime takes: " + why);
            return;
        }
        if (!federation_web_user(*m_fed, id, *arn, known, user, why))
        {
            sts_fail(c, 403, "AccessDenied", why);
            return;
        }
        sts_federated_session(c, action, user, *arn, *name, duration, policy);
        return;
    }

    const std::string* username = field("LDAPUsername");
    const std::string* password = field("LDAPPassword");
    if (!username || username->empty() || username->size() > 256 || !password || password->empty())
    {
        sts_fail(c, 400, "ValidationError", "AssumeRoleWithLDAPIdentity needs an LDAPUsername and an LDAPPassword.");
        return;
    }
    if (!m_ldap_attached)
        m_ldap_attached = m_ldap_pool.attach(m_io);
    if (!m_ldap_attached || !m_ldap_pool.enabled())
    {
        sts_fail(c, 503, "ServiceUnavailable", "The directory cannot be asked from this runtime.");
        return;
    }
    // The bind blocks, so it runs on the pool's thread, and its answer finds the connection only if it is still there.
    struct bind_state
    {
        federation_ldap  cfg;
        std::string      user, password, why;
        ldap_bind_result res;
        bool             ok{false};
    };
    auto b      = std::make_shared<bind_state>();
    b->cfg      = m_fed->ldap;
    b->user     = *username;
    b->password = *password;
    std::weak_ptr<conn> weak = c;
    m_ldap_pool.submit(0, [b] { b->ok = ldap_simple_bind(b->cfg, b->user, b->password, b->res, b->why); },
        [this, b, weak, action = std::string(action), duration, policy, known]
    {
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (!b->ok)
        {
            sts_fail(cc, 503, "ServiceUnavailable", "The directory did not answer: " + b->why);
            return;
        }
        if (!b->res.bound())
        {
            sts_fail(cc, 403, "AccessDenied", "The directory refused the credentials.");
            return;
        }
        std::string user, why;
        if (!federation_ldap_user(*m_fed, b->user, known, user, why))
        {
            sts_fail(cc, 403, "AccessDenied", why);
            return;
        }
        sts_federated_session(cc, action, user, {}, {}, duration, policy);
    });
}

void storage_run::sts_federated_session(const std::shared_ptr<conn>& c, std::string_view action, const std::string& user,
                                        const std::string& role_arn, const std::string& session_name, int64_t duration,
                                        const std::string& policy)
{
    // A RoleArn naming a role the IAM API made is assumed as its trust policy lets the mapped user, as AssumeRole does.
    std::string role;
    if (!role_arn.empty())
    {
        int64_t longest_role = 0;
        const std::string_view rname = iam_role_name_of(role_arn);
        const int rc = m_auth->role_check(rname, user, longest_role);
        if (rc == 0)
        {
            sts_fail(c, 403, "AccessDenied", "User " + user + " is not authorized to perform sts:" + std::string(action) +
                                                 " on " + role_arn);
            return;
        }
        if (rc == 1)
        {
            duration = std::min(duration, longest_role);
            role     = std::string(rname);
        }
    }
    const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    session_credentials sc;
    if (!m_auth->issue_session_as(user, now + duration, policy, role, sc))
    {
        sts_fail(c, 403, "AccessDenied", "The user " + user + " has no access key a session can be signed under.");
        return;
    }
    response resp;
    resp.headers.emplace_back("Content-Type", "text/xml");
    resp.body = sts_credentials_xml(action, sc.access_key, sc.secret, sc.token, sc.expires, role_arn, session_name,
                                    c->req.request_id);
    send_response(c, std::move(resp));
}

}   // namespace socketley::storage
