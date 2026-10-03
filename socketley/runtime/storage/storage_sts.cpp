// STS over the S3 endpoint: GetSessionToken and AssumeRole, which give a user temporary credentials that sign for it.
#include "storage_run.h"

#include <chrono>
#include <charconv>

#include "bucket_policy.h"
#include "digest.h"
#include "s3_sts.h"

namespace socketley::storage
{

void storage_run::op_sts(const std::shared_ptr<conn>& c)
{
    const s3_request& r = c->req;
    auto fail = [this, &c](int status, std::string_view code, std::string_view message)
    {
        count_error(code);
        response resp;
        resp.status = status;
        resp.headers.emplace_back("Content-Type", "text/xml");
        resp.body = sts_error_xml(code, message, c->req.request_id);
        send_response(c, std::move(resp));
    };

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
    rv.tls             = c->ssl != nullptr;
    rv.body_sha256_hex = body_hash;
    rv.service = r.header("authorization").find("/sts/aws4_request") != std::string_view::npos ? "sts" : "s3";
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
    if (v.session)
    {
        fail(403, "AccessDenied", "Temporary credentials cannot ask for more; sign with the user's own key.");
        return;
    }

    const std::string* action = field("Action");
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
    std::string role_arn, session_name, policy;
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
    if (!m_auth->issue_session(v.principal, now + duration, policy, sc))
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

}   // namespace socketley::storage
